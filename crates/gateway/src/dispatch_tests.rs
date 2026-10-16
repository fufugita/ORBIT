//! Gateway dispatch tests — GW-04 (no invoke before egress fsync), GW-09
//! (recovery reads durable state), GW-16 (credential reaches one adapter),
//! and the four-gate admission order through the real engine.
//!
//! P0 fixes under test:
//! - P0-1: the egress gate uses an EXTERNAL allowlist; an unadmitted
//!   destination is refused E0307.
//! - P0-3: a re-dispatched decision_id is refused E0701.
//! - P0-5: dispatch uses an injected writer (no competing flock).

use crate::dispatch::{DispatchEngine, DispatchOutcome, DispatchState};
use crate::registry::ProviderRegistry;
use crate::{new_decision_id, new_session_id};
use orbit_adapter::adapters::{
    DeterministicTestV1, canonical_success_result, identity, text_capabilities,
};
use orbit_adapter::conformance::canonical_request;
use orbit_adapter::credential::SecretBytes;
use orbit_adapter::types::{AdapterKind, ProviderRouteBinding, Sha256Digest};
use orbit_egress::{EgressAllowlist, EgressTuple, SpkiPin};
use orbit_ledger::LedgerWriter;
use std::path::PathBuf;
use std::sync::Arc;

use orbit_adapter::types::{ProviderEventKind, ProviderStreamEvent, ProviderUsage, UsageSource};
use orbit_provider_http::{AsyncProviderAdapter, CancelToken};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

struct UsageScript {
    events: Vec<ProviderStreamEvent>,
    calls: Arc<AtomicUsize>,
    capabilities: orbit_adapter::types::ProviderCapabilities,
}

#[async_trait::async_trait]
impl AsyncProviderAdapter for UsageScript {
    fn identity(&self) -> orbit_adapter::types::AdapterIdentity {
        identity(
            AdapterKind::DeterministicTestV1,
            &"i".repeat(64),
            &"p".repeat(64),
        )
    }

    fn capabilities(&self) -> &orbit_adapter::types::ProviderCapabilities {
        &self.capabilities
    }

    fn validate_route(
        &self,
        route: &ProviderRouteBinding,
    ) -> Result<(), orbit_adapter::error::AdapterError> {
        assert_eq!(route.adapter_kind, self.identity().kind);
        Ok(())
    }

    async fn invoke(
        &self,
        _request: &orbit_adapter::types::ProviderRequest,
        _credential: Option<&SecretBytes>,
        _cancel: &CancelToken,
    ) -> Result<orbit_provider_http::AsyncProviderEventStream, orbit_adapter::error::AdapterError>
    {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(Box::pin(futures::stream::iter(
            self.events.clone().into_iter().map(Ok),
        )))
    }
}

fn usage_snapshot(base: u64) -> ProviderUsage {
    ProviderUsage {
        input_tokens: base,
        output_tokens: base + 1,
        cache_read_tokens: base + 2,
        cache_write_tokens: base + 3,
        reasoning_tokens: base + 4,
    }
}

fn usage_events(
    updates: &[ProviderUsage],
    final_usage: Option<ProviderUsage>,
) -> Vec<ProviderStreamEvent> {
    let mut kinds = vec![
        ProviderEventKind::ResponseStarted {
            upstream_request_id: Some("usage-fixture".into()),
        },
        ProviderEventKind::TextDelta {
            bytes: b"exact answer\n".to_vec(),
        },
    ];
    kinds.extend(updates.iter().copied().map(ProviderEventKind::UsageUpdate));
    kinds.push(ProviderEventKind::Finished {
        finish_reason: Some("stop".into()),
        final_usage,
    });
    kinds
        .into_iter()
        .enumerate()
        .map(|(sequence, event)| ProviderStreamEvent {
            sequence: sequence as u64,
            event,
        })
        .collect()
}

// Exercise registry admission, durable egress, the real collector and completion.
// The writer is closed and its private directory removed before assertions return.
async fn dispatch_usage_fixture(
    adapter: Arc<dyn AsyncProviderAdapter>,
    binding: ProviderRouteBinding,
) -> (DispatchOutcome, Vec<ProviderStreamEvent>) {
    use std::os::unix::fs::DirBuilderExt;
    let dir = std::env::temp_dir().join(format!("orbit-gw-usage-{}", new_decision_id().0));
    std::fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
    let tuple = EgressTuple {
        scheme: if binding.endpoint_scheme == orbit_adapter::types::EndpointScheme::HttpLoopback {
            "http"
        } else {
            "https"
        }
        .into(),
        host: binding.endpoint_host.clone(),
        port: binding.endpoint_port,
        path_prefix: "/v1".into(),
        provider_id: binding.provider_id.0.clone(),
        region_id: binding.region_id.0.clone(),
    };
    let mut registry = ProviderRegistry::new();
    registry.register_model(crate::ModelRef("test-model".into()), binding.clone());
    registry.register_async_adapter(binding.adapter_kind, adapter);
    let engine = DispatchEngine::new(
        registry,
        dir.clone(),
        EgressAllowlist::new(vec![tuple.clone()]),
        vec![tuple.clone()],
        vec![],
    );
    let mut writer = LedgerWriter::open(&dir, "usage-writer".into(), "0.1.0").unwrap();
    let session = new_session_id();
    let decision = new_decision_id();
    let mut request = canonical_request(&binding, b"hello");
    request.connect_timeout_ms = 1000;
    request.first_byte_timeout_ms = 1000;
    request.idle_timeout_ms = 1000;
    let cancel = CancelToken::new();
    let mut observed = Vec::new();
    let (outcome, reservation) = tokio::time::timeout(
        Duration::from_secs(4),
        engine.dispatch_async(
            "test-model",
            &session,
            &decision.0,
            &request,
            None,
            &mut writer,
            &cancel,
            Some(&mut |event| observed.push(event.clone())),
        ),
    )
    .await
    .expect("bounded gateway fixture")
    .unwrap();
    writer.close().unwrap();
    let state = engine.recovery_state(&session, &decision.0).unwrap();
    let (records, _) = orbit_ledger::verify_ledger(&dir).unwrap();
    std::fs::remove_dir_all(&dir).unwrap();
    assert_eq!(reservation.decision_id, decision.0);
    assert_eq!(reservation.session_id, session);
    assert_eq!(reservation.destination_digest, tuple.digest());
    assert!(!reservation.intent_digest.is_empty());
    assert_eq!(state, DispatchState::EgressIntentDurable);
    assert_eq!(
        records
            .iter()
            .filter(|record| matches!(
                record.record.event,
                orbit_ledger::event::LedgerEvent::EgressIntent(_)
            ))
            .count(),
        1
    );
    (outcome, observed)
}

fn assert_usage_result(
    outcome: DispatchOutcome,
    usage: ProviderUsage,
    source: UsageSource,
    complete: bool,
) -> Box<orbit_adapter::types::ProviderResult> {
    let DispatchOutcome::Completed(result) = outcome else {
        panic!("expected completed response, got {outcome:?}")
    };
    assert_eq!(
        result.status,
        orbit_adapter::types::ProviderTerminalStatus::Completed
    );
    assert_eq!(result.accounting.usage, usage);
    assert_eq!(result.accounting.usage_source, Some(source));
    assert_eq!(result.accounting.usage_complete, complete);
    assert_eq!(result.accounting.cost_microcents, 0);
    assert_eq!(result.accounting.currency, None);
    assert_eq!(
        result.output,
        orbit_adapter::stream::output_evidence(&result.events).unwrap()
    );
    result
}

async fn scripted_usage_case(
    updates: &[ProviderUsage],
    final_usage: Option<ProviderUsage>,
    usage: ProviderUsage,
    source: UsageSource,
    complete: bool,
) {
    let events = usage_events(updates, final_usage);
    let calls = Arc::new(AtomicUsize::new(0));
    let adapter = UsageScript {
        events: events.clone(),
        calls: calls.clone(),
        capabilities: text_capabilities(),
    };
    let (outcome, observed) = dispatch_usage_fixture(Arc::new(adapter), test_binding()).await;
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let result = assert_usage_result(outcome, usage, source, complete);
    assert_eq!(result.events, events);
    assert_eq!(observed, events);
    assert_eq!(result.output.observed_bytes, 13);
    assert_eq!(result.output.delivered_bytes, 13);
}

#[tokio::test]
async fn gateway_usage_accounting_missing_is_not_final_zero() {
    scripted_usage_case(
        &[],
        None,
        ProviderUsage::default(),
        UsageSource::Missing,
        false,
    )
    .await;
}

#[tokio::test]
async fn gateway_usage_accounting_one_incremental_snapshot_is_incomplete() {
    scripted_usage_case(
        &[usage_snapshot(2)],
        None,
        usage_snapshot(2),
        UsageSource::Incremental,
        false,
    )
    .await;
}

#[tokio::test]
async fn gateway_usage_accounting_latest_snapshot_is_not_summed() {
    scripted_usage_case(
        &[usage_snapshot(2), usage_snapshot(20)],
        None,
        usage_snapshot(20),
        UsageSource::Incremental,
        false,
    )
    .await;
}

#[tokio::test]
async fn gateway_usage_accounting_incremental_zero_is_incomplete() {
    scripted_usage_case(
        &[ProviderUsage::default()],
        None,
        ProviderUsage::default(),
        UsageSource::Incremental,
        false,
    )
    .await;
}

#[tokio::test]
async fn gateway_usage_accounting_explicit_final_zero_is_complete() {
    scripted_usage_case(
        &[],
        Some(ProviderUsage::default()),
        ProviderUsage::default(),
        UsageSource::Final,
        true,
    )
    .await;
}

#[tokio::test]
async fn gateway_usage_accounting_final_zero_overrides_incremental_snapshot() {
    scripted_usage_case(
        &[usage_snapshot(2)],
        Some(ProviderUsage::default()),
        ProviderUsage::default(),
        UsageSource::Final,
        true,
    )
    .await;
}

#[tokio::test]
async fn gateway_usage_accounting_final_snapshot_wins_over_updates() {
    scripted_usage_case(
        &[usage_snapshot(2), usage_snapshot(20)],
        Some(usage_snapshot(40)),
        usage_snapshot(40),
        UsageSource::Final,
        true,
    )
    .await;
}

#[tokio::test]
async fn gateway_usage_accounting_incomplete_stream_is_refused() {
    let mut events = usage_events(&[usage_snapshot(2)], None);
    events.pop();
    let calls = Arc::new(AtomicUsize::new(0));
    let adapter = UsageScript {
        events: events.clone(),
        calls: calls.clone(),
        capabilities: text_capabilities(),
    };
    let (outcome, observed) = dispatch_usage_fixture(Arc::new(adapter), test_binding()).await;
    assert!(matches!(
        outcome,
        DispatchOutcome::AdapterRefused { code: "E0411", .. }
    ));
    assert_eq!(observed, events);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

struct UsageWireServer {
    port: u16,
    task: tokio::task::JoinHandle<()>,
}

impl UsageWireServer {
    async fn new(body: String) -> Self {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let task = tokio::spawn(async move {
            let (mut socket, _) = tokio::time::timeout(Duration::from_secs(2), listener.accept())
                .await
                .unwrap()
                .unwrap();
            let mut raw = Vec::new();
            let header_end = loop {
                let mut chunk = [0u8; 2048];
                let count = socket.read(&mut chunk).await.unwrap();
                assert!(count > 0, "complete request headers");
                raw.extend_from_slice(&chunk[..count]);
                assert!(raw.len() <= 1024 * 1024, "bounded request capture");
                if let Some(end) = raw.windows(4).position(|bytes| bytes == b"\r\n\r\n") {
                    break end + 4;
                }
            };
            let headers = std::str::from_utf8(&raw[..header_end]).unwrap();
            assert!(
                headers.starts_with("POST /v1/"),
                "one admitted provider POST"
            );
            let length = headers
                .lines()
                .find_map(|line| {
                    let (key, value) = line.split_once(':')?;
                    key.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().unwrap())
                })
                .unwrap();
            assert!(header_end + length <= 1024 * 1024);
            while raw.len() < header_end + length {
                let mut chunk = [0u8; 2048];
                let count = socket.read(&mut chunk).await.unwrap();
                assert!(count > 0, "complete request body");
                raw.extend_from_slice(&chunk[..count]);
                assert!(raw.len() <= 1024 * 1024);
            }
            let request: serde_json::Value =
                serde_json::from_slice(&raw[header_end..header_end + length]).unwrap();
            assert_eq!(request["model"], "test-model");
            let headers = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            socket.write_all(headers.as_bytes()).await.unwrap();
            socket.write_all(body.as_bytes()).await.unwrap();
            socket.shutdown().await.unwrap();
            assert!(
                tokio::time::timeout(Duration::from_millis(30), listener.accept())
                    .await
                    .is_err(),
                "no second provider invocation"
            );
        });
        Self { port, task }
    }

    async fn finish(&mut self) {
        tokio::time::timeout(Duration::from_secs(3), &mut self.task)
            .await
            .expect("owned server deadline")
            .expect("owned server completed");
    }
}

impl Drop for UsageWireServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn usage_sse(value: serde_json::Value) -> String {
    format!("data: {value}\n\n")
}

async fn wire_usage_case(
    anthropic: bool,
    body: String,
) -> (DispatchOutcome, Vec<ProviderStreamEvent>) {
    let mut server = UsageWireServer::new(body).await;
    let adapter: Arc<dyn AsyncProviderAdapter> = if anthropic {
        Arc::new(
            orbit_provider_http::AnthropicMessagesV1::new(
                orbit_provider_http::anthropic::anthropic_identity(),
                orbit_provider_http::anthropic::anthropic_capabilities(),
            )
            .unwrap(),
        )
    } else {
        Arc::new(
            orbit_provider_http::OpenAiCompatibleHttpV1::new(
                orbit_provider_http::openai::openai_identity(),
                orbit_provider_http::openai::openai_capabilities(),
                orbit_adapter::types::TlsPinPolicy {
                    webpki: false,
                    spki_sha256: None,
                },
            )
            .unwrap(),
        )
    };
    let identity = adapter.identity();
    let mut binding = test_binding();
    binding.adapter_kind = identity.kind;
    binding.adapter_implementation_digest = identity.implementation_digest;
    binding.adapter_profile_digest = identity.profile_digest;
    binding.endpoint_host = "127.0.0.1".into();
    binding.endpoint_port = server.port;
    binding.endpoint_scheme = orbit_adapter::types::EndpointScheme::HttpLoopback;
    let outcome = dispatch_usage_fixture(adapter, binding).await;
    server.finish().await;
    outcome
}

fn openai_usage_body(usage: Option<serde_json::Value>) -> String {
    let mut body = usage_sse(
        serde_json::json!({"choices":[{"index":0,"delta":{"content":"wire answer"},"finish_reason":null}]}),
    );
    body.push_str(&usage_sse(
        serde_json::json!({"choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}),
    ));
    if let Some(usage) = usage {
        body.push_str(&usage_sse(serde_json::json!({"choices":[],"usage":usage})));
    }
    body.push_str("data: [DONE]\n\n");
    body
}

fn assert_wire_text(
    result: &orbit_adapter::types::ProviderResult,
    observed: &[ProviderStreamEvent],
) {
    assert_eq!(result.events, observed);
    let text: Vec<u8> = result
        .events
        .iter()
        .filter_map(|event| match &event.event {
            ProviderEventKind::TextDelta { bytes } => Some(bytes.as_slice()),
            _ => None,
        })
        .flatten()
        .copied()
        .collect();
    assert_eq!(text, b"wire answer");
}

#[tokio::test]
async fn gateway_wire_usage_accounting_openai_missing_trailer() {
    let (outcome, observed) = wire_usage_case(false, openai_usage_body(None)).await;
    let result = assert_usage_result(
        outcome,
        ProviderUsage::default(),
        UsageSource::Missing,
        false,
    );
    assert_wire_text(&result, &observed);
    assert!(
        !result
            .events
            .iter()
            .any(|event| matches!(event.event, ProviderEventKind::UsageUpdate(_)))
    );
}

#[tokio::test]
async fn gateway_wire_usage_accounting_openai_explicit_final_zero() {
    let (outcome, observed) = wire_usage_case(
        false,
        openai_usage_body(Some(
            serde_json::json!({"prompt_tokens":0,"completion_tokens":0}),
        )),
    )
    .await;
    let result = assert_usage_result(outcome, ProviderUsage::default(), UsageSource::Final, true);
    assert_wire_text(&result, &observed);
}

#[tokio::test]
async fn gateway_wire_usage_accounting_openai_final_categories() {
    let body = openai_usage_body(Some(
        serde_json::json!({"prompt_tokens":20,"completion_tokens":9,"prompt_tokens_details":{"cached_tokens":3},"completion_tokens_details":{"reasoning_tokens":2}}),
    ));
    let (outcome, observed) = wire_usage_case(false, body).await;
    let usage = ProviderUsage {
        input_tokens: 17,
        output_tokens: 9,
        cache_read_tokens: 3,
        cache_write_tokens: 0,
        reasoning_tokens: 2,
    };
    let result = assert_usage_result(outcome, usage, UsageSource::Final, true);
    assert_wire_text(&result, &observed);
}

fn anthropic_usage_body(final_usage: bool, terminal: bool) -> String {
    let values = [
        serde_json::json!({"type":"message_start","message":{"id":"owned-usage","usage":{"input_tokens":17,"output_tokens":0,"cache_read_input_tokens":3,"cache_creation_input_tokens":4}}}),
        serde_json::json!({"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}),
        serde_json::json!({"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"wire answer"}}),
        serde_json::json!({"type":"content_block_stop","index":0}),
    ];
    let mut body: String = values.into_iter().map(usage_sse).collect();
    let mut delta = serde_json::json!({"type":"message_delta","delta":{"stop_reason":"end_turn"}});
    if final_usage {
        delta["usage"] = serde_json::json!({"output_tokens":9});
    }
    body.push_str(&usage_sse(delta));
    if terminal {
        body.push_str(&usage_sse(serde_json::json!({"type":"message_stop"})));
    }
    body
}

#[tokio::test]
async fn gateway_wire_usage_accounting_anthropic_initial_only_is_missing() {
    let (outcome, observed) = wire_usage_case(true, anthropic_usage_body(false, true)).await;
    let result = assert_usage_result(
        outcome,
        ProviderUsage::default(),
        UsageSource::Missing,
        false,
    );
    assert_wire_text(&result, &observed);
}

#[tokio::test]
async fn gateway_wire_usage_accounting_anthropic_final_cache_categories() {
    let (outcome, observed) = wire_usage_case(true, anthropic_usage_body(true, true)).await;
    let usage = ProviderUsage {
        input_tokens: 17,
        output_tokens: 9,
        cache_read_tokens: 3,
        cache_write_tokens: 4,
        reasoning_tokens: 0,
    };
    let result = assert_usage_result(outcome, usage, UsageSource::Final, true);
    assert_wire_text(&result, &observed);
}

#[tokio::test]
async fn gateway_wire_usage_accounting_anthropic_disconnect_is_refused() {
    let (outcome, _) = wire_usage_case(true, anthropic_usage_body(true, false)).await;
    assert!(matches!(
        outcome,
        DispatchOutcome::AdapterRefused { code: "E0411", .. }
    ));
}

#[tokio::test]
async fn gateway_wire_usage_accounting_anthropic_malformed_usage_is_refused() {
    let body = anthropic_usage_body(true, true)
        .replace("\"output_tokens\":9", "\"output_tokens\":\"invalid\"");
    let (outcome, _) = wire_usage_case(true, body).await;
    assert!(matches!(
        outcome,
        DispatchOutcome::AdapterRefused { code: "E0411", .. }
    ));
}

fn test_binding() -> ProviderRouteBinding {
    ProviderRouteBinding {
        provider_id: orbit_adapter::types::ProviderId("test-provider".into()),
        deployment_id: orbit_adapter::types::DeploymentId("test-deploy".into()),
        region_id: orbit_adapter::types::RegionId("test-region".into()),
        adapter_kind: AdapterKind::DeterministicTestV1,
        adapter_implementation_digest: Sha256Digest("i".repeat(64)),
        adapter_profile_digest: Sha256Digest("p".repeat(64)),
        endpoint_digest: Sha256Digest("e".repeat(64)),
        expected_model: "test-model".into(),
        pricing_digest: Sha256Digest("r".repeat(64)),
        endpoint_host: String::from("test-provider"),
        endpoint_port: 443,
        endpoint_scheme: orbit_adapter::types::EndpointScheme::Https,
        endpoint_path: String::new(),
        endpoint_query: None,
    }
}

/// The tuple the binding's egress resolves to (provider_id as host, per the
/// binding's provider id — the real host would come from a signed profile).
/// The SPKI pin the test route expects (a fixed digest — the test adapter
/// never performs real TLS, but the pin must EXIST for the dispatch gate).
fn spki_pin() -> SpkiPin {
    SpkiPin {
        provider_id: "test-provider".into(),
        region_id: "test-region".into(),
        spki_sha256: "expected-test-pin".into(),
    }
}

fn bound_tuple() -> EgressTuple {
    EgressTuple {
        scheme: "https".into(),
        host: "test-provider".into(),
        port: 443,
        path_prefix: "/v1".into(),
        provider_id: "test-provider".into(),
        region_id: "test-region".into(),
    }
}

fn dispatch_endpoint_path(
    path: &str,
    allowed_path: &str,
) -> (Result<DispatchOutcome, crate::DispatchError>, bool) {
    dispatch_endpoint_request(path, allowed_path, |_| {})
}

fn dispatch_endpoint_request(
    path: &str,
    allowed_path: &str,
    alter: fn(&mut ProviderRouteBinding),
) -> (Result<DispatchOutcome, crate::DispatchError>, bool) {
    use orbit_adapter::adapters::{MockHttpV1, MockScript};
    use std::os::unix::fs::DirBuilderExt;
    let dir = std::env::temp_dir().join(format!("orbit-gateway-path-{}", new_decision_id().0));
    std::fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
    let probe = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let adapter = MockHttpV1::with_credential_probe(
        identity(AdapterKind::MockHttpV1, &"i".repeat(64), &"p".repeat(64)),
        text_capabilities(),
        MockScript::Success(canonical_success_result()),
        probe.clone(),
    );
    let mut binding = test_binding();
    binding.adapter_kind = AdapterKind::MockHttpV1;
    binding.endpoint_path = path.into();
    let mut tuple = bound_tuple();
    tuple.path_prefix = allowed_path.into();
    let mut registry = ProviderRegistry::new();
    registry.register_model(crate::ModelRef("test-model".into()), binding.clone());
    registry.register_adapter(AdapterKind::MockHttpV1, Arc::new(adapter));
    let engine = DispatchEngine::new(
        registry,
        dir.clone(),
        EgressAllowlist::new(vec![tuple.clone()]),
        vec![tuple],
        vec![spki_pin()],
    );
    let mut writer = LedgerWriter::open(&dir, "path-writer".into(), "0.1.0").unwrap();
    let mut request = canonical_request(&binding, b"hello");
    alter(&mut request.route);
    let secret = SecretBytes::new(b"synthetic-path-bound-key".to_vec());
    let session = new_session_id();
    let decision = new_decision_id();
    let result = engine
        .dispatch(
            "test-model",
            &session,
            &decision.0,
            &request,
            Some(&secret),
            &mut writer,
        )
        .map(|(outcome, _)| outcome);
    if result.is_err() {
        assert!(matches!(
            engine.recovery_state(&session, &decision.0).unwrap(),
            DispatchState::Reserved
        ));
    }
    writer.close().unwrap();
    std::fs::remove_dir_all(dir).unwrap();
    (result, probe.load(std::sync::atomic::Ordering::SeqCst))
}

#[test]
fn gateway_endpoint_path_custom_base_delivers_only_when_admitted() {
    let (result, received) = dispatch_endpoint_path("/owned/v1", "/owned/v1");
    assert!(
        matches!(result, Ok(DispatchOutcome::Completed(_))),
        "{result:?}"
    );
    assert!(received);
}

#[test]
fn gateway_endpoint_path_default_allowlist_cannot_admit_another_base() {
    let (result, received) = dispatch_endpoint_path("/owned/v1", "/v1");
    assert_eq!(result.unwrap_err().code, "E0307");
    assert!(!received);
}

#[test]
fn gateway_endpoint_path_prefix_confusion_refuses_before_credential_delivery() {
    let (result, received) = dispatch_endpoint_path("/v1admin", "/v1");
    assert_eq!(result.unwrap_err().code, "E0307");
    assert!(!received);
}

#[test]
fn gateway_endpoint_path_noncanonical_paths_refuse_before_credential_delivery() {
    for path in [
        "/v1/../outside",
        "/v1/%2e%2e/outside",
        "/v1?tenant=fixture",
        "/v1#fragment",
        "v1",
        "/v1\\outside",
        "/v1\n",
    ] {
        let (result, received) = dispatch_endpoint_path(path, "/v1");
        assert!(result.is_err(), "ambiguous route path was admitted");
        assert!(!received, "ambiguous route received credentials");
    }
}

fn route_changes() -> [fn(&mut ProviderRouteBinding); 3] {
    [
        |route| route.endpoint_path = "/outside".into(),
        |route| route.endpoint_host = "another.invalid".into(),
        |route| route.endpoint_port = 8443,
    ]
}

#[test]
fn gateway_endpoint_path_sync_request_cannot_change_the_admitted_route() {
    for alter in route_changes() {
        let (result, received) = dispatch_endpoint_request("/v1", "/v1", alter);
        assert_eq!(result.unwrap_err().phase, "capability");
        assert!(!received);
    }
}

#[tokio::test]
async fn gateway_endpoint_path_async_request_cannot_change_the_admitted_route() {
    use std::os::unix::fs::DirBuilderExt;
    for alter in route_changes() {
        let dir = std::env::temp_dir().join(format!("orbit-gateway-route-{}", new_decision_id().0));
        std::fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let adapter = Arc::new(UsageScript {
            events: usage_events(&[], None),
            calls: calls.clone(),
            capabilities: text_capabilities(),
        });
        let binding = test_binding();
        let mut request = canonical_request(&binding, b"hello");
        alter(&mut request.route);
        let mut registry = ProviderRegistry::new();
        registry.register_model(crate::ModelRef("test-model".into()), binding.clone());
        registry.register_async_adapter(binding.adapter_kind, adapter);
        let engine = DispatchEngine::new(
            registry,
            dir.clone(),
            EgressAllowlist::new(vec![bound_tuple()]),
            vec![bound_tuple()],
            vec![spki_pin()],
        );
        let mut writer = LedgerWriter::open(&dir, "route-writer".into(), "0.1.0").unwrap();
        let secret = SecretBytes::new(b"synthetic-path-bound-key".to_vec());
        let session = new_session_id();
        let decision = new_decision_id();
        let mut observed = Vec::new();
        let result = engine
            .dispatch_async(
                "test-model",
                &session,
                &decision.0,
                &request,
                Some(&secret),
                &mut writer,
                &CancelToken::new(),
                Some(&mut |event| observed.push(event.clone())),
            )
            .await;
        assert_eq!(result.unwrap_err().phase, "capability");
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert!(observed.is_empty());
        assert!(matches!(
            engine.recovery_state(&session, &decision.0).unwrap(),
            DispatchState::Reserved
        ));
        writer.close().unwrap();
        std::fs::remove_dir_all(dir).unwrap();
    }
}

/// Build an engine whose egress allowlist CONTAINS the bound tuple (admitted)
/// plus a writer already open on the ledger dir (P0-5: injected, not competing).
fn engine(tag: &str) -> (DispatchEngine, PathBuf, LedgerWriter) {
    let dir = crate::tmpdir(tag);
    let mut registry = ProviderRegistry::new();
    let adapter = DeterministicTestV1::new(
        identity(
            AdapterKind::DeterministicTestV1,
            &"i".repeat(64),
            &"p".repeat(64),
        ),
        text_capabilities(),
        canonical_success_result(),
    );
    registry.register_model(crate::ModelRef("test-model".into()), test_binding());
    registry.register_adapter(AdapterKind::DeterministicTestV1, Arc::new(adapter));
    let allowlist = EgressAllowlist::new(vec![bound_tuple()]);
    let engine = DispatchEngine::new(
        registry,
        dir.clone(),
        allowlist,
        vec![bound_tuple()],
        vec![spki_pin()],
    );
    let writer = LedgerWriter::open(&dir, "test-writer".into(), "0.1.0").unwrap();
    (engine, dir, writer)
}

/// Build an engine whose egress allowlist does NOT contain the bound tuple —
/// dispatch of the bound model must be refused E0307 (P0-1).
fn engine_unadmitted(tag: &str) -> (DispatchEngine, PathBuf, LedgerWriter) {
    let dir = crate::tmpdir(tag);
    let mut registry = ProviderRegistry::new();
    let adapter = DeterministicTestV1::new(
        identity(
            AdapterKind::DeterministicTestV1,
            &"i".repeat(64),
            &"p".repeat(64),
        ),
        text_capabilities(),
        canonical_success_result(),
    );
    registry.register_model(crate::ModelRef("test-model".into()), test_binding());
    registry.register_adapter(AdapterKind::DeterministicTestV1, Arc::new(adapter));
    // Allowlist contains a DIFFERENT tuple — the bound destination is NOT admitted.
    let allowlist = EgressAllowlist::new(vec![]);
    let engine = DispatchEngine::new(registry, dir.clone(), allowlist, vec![], vec![]);
    let writer = LedgerWriter::open(&dir, "test-writer".into(), "0.1.0").unwrap();
    (engine, dir, writer)
}

#[test]
fn gateway_four_gate_admission_order_via_engine() {
    let (engine, dir, _writer) = engine("order");
    // Unknown model → Trust gate denied.
    match engine.resolve("unknown", "s", "d") {
        Err(e) => assert_eq!(e.code, "E0404", "unknown model fails Trust gate"),
        Ok(_) => panic!("unknown model must fail Trust gate"),
    }

    // Known model → resolves to the adapter.
    let (adapter, binding) = engine.resolve("test-model", "s", "d").unwrap();
    assert_eq!(adapter.identity().kind, AdapterKind::DeterministicTestV1);
    assert_eq!(binding.provider_id.0, "test-provider");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn gateway_dispatch_completes_and_writes_egress_intent() {
    let (engine, dir, mut writer) = engine("complete");
    let session = new_session_id();
    let decision = new_decision_id();
    let route = test_binding();
    let request = canonical_request(&route, b"hello");
    let (outcome, reservation) = engine
        .dispatch(
            "test-model",
            &session,
            &decision.0,
            &request,
            None,
            &mut writer,
        )
        .unwrap();

    assert_eq!(reservation.decision_id, decision.0);
    match outcome {
        DispatchOutcome::Completed(r) => {
            assert_eq!(
                r.status,
                orbit_adapter::types::ProviderTerminalStatus::Completed
            );
        }
        other => panic!("expected Completed, got {other:?}"),
    }

    // The egress intent must be durable in the ledger (GW-04).
    writer.close().unwrap();
    let state = engine.recovery_state(&session, &decision.0).unwrap();
    assert!(
        matches!(state, DispatchState::EgressIntentDurable),
        "recovery must see the durable egress intent, got {state:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn gateway_credential_reaches_only_the_admitted_adapter() {
    use orbit_adapter::adapters::MockHttpV1;
    use orbit_adapter::adapters::MockScript;
    let dir = crate::tmpdir("cred");
    let mut registry = ProviderRegistry::new();
    // A credential-aware adapter with a shared receipt probe (P1-3: the test
    // must PROVE delivery, not just that dispatch completed).
    let probe = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let adapter = MockHttpV1::with_credential_probe(
        identity(AdapterKind::MockHttpV1, &"i".repeat(64), &"p".repeat(64)),
        text_capabilities(),
        MockScript::Success(canonical_success_result()),
        probe.clone(),
    );
    // The route must point at MockHttpV1 for the adapter to accept it.
    let mut binding = test_binding();
    binding.adapter_kind = AdapterKind::MockHttpV1;
    registry.register_model(crate::ModelRef("test-model".into()), binding.clone());
    registry.register_adapter(AdapterKind::MockHttpV1, Arc::new(adapter));
    let allowlist = EgressAllowlist::new(vec![bound_tuple()]);
    let engine = DispatchEngine::new(
        registry,
        dir.clone(),
        allowlist,
        vec![bound_tuple()],
        vec![spki_pin()],
    );
    let mut writer = LedgerWriter::open(&dir, "test-writer".into(), "0.1.0").unwrap();

    let session = new_session_id();
    let decision = new_decision_id();
    let request = canonical_request(&binding, b"hello");
    let secret = SecretBytes::new(b"only-admitted-adapter".to_vec());
    let (outcome, _) = engine
        .dispatch(
            "test-model",
            &session,
            &decision.0,
            &request,
            Some(&secret),
            &mut writer,
        )
        .unwrap();
    assert!(
        matches!(outcome, DispatchOutcome::Completed(_)),
        "GW-16: credential must reach the admitted adapter"
    );
    // The credential was DELIVERED to the admitted adapter (P1-3 proof).
    assert!(
        probe.load(std::sync::atomic::Ordering::SeqCst),
        "GW-16: the credential must actually be delivered to the adapter"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn gateway_recovery_returns_reserved_when_no_intent() {
    let (engine, dir, _writer) = engine("reserved");
    let session = new_session_id();
    let decision = new_decision_id();
    // No dispatch happened — recovery must report Reserved.
    let state = engine.recovery_state(&session, &decision.0).unwrap();
    assert_eq!(state, DispatchState::Reserved);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn gateway_egress_allowlist_refuses_unadmitted_destination() {
    // P0-1: the egress gate uses an EXTERNAL allowlist; a destination not in
    // it is refused E0307 even though the model is allowlisted + has a route.
    let (engine, dir, mut writer) = engine_unadmitted("unadmitted");
    let session = new_session_id();
    let decision = new_decision_id();
    let route = test_binding();
    let request = canonical_request(&route, b"hello");
    let r = engine.dispatch(
        "test-model",
        &session,
        &decision.0,
        &request,
        None,
        &mut writer,
    );
    match r {
        Err(e) => {
            assert_eq!(e.code, "E0307", "unadmitted destination must fail egress");
            assert_eq!(e.phase, "egress");
        }
        Ok((outcome, _)) => panic!("unadmitted destination must be refused, got {outcome:?}"),
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn gateway_replayed_decision_id_refused_e0701() {
    // P0-3: a decision_id already dispatched is refused on the second attempt.
    let (engine, dir, mut writer) = engine("replay");
    let session = new_session_id();
    let decision = new_decision_id();
    let route = test_binding();
    let request = canonical_request(&route, b"hello");

    // First dispatch: completed.
    let (outcome, _) = engine
        .dispatch(
            "test-model",
            &session,
            &decision.0,
            &request,
            None,
            &mut writer,
        )
        .unwrap();
    assert!(matches!(outcome, DispatchOutcome::Completed(_)));

    // Replay of the same decision_id → E0701.
    let r2 = engine.dispatch(
        "test-model",
        &session,
        &decision.0,
        &request,
        None,
        &mut writer,
    );
    match r2 {
        Err(e) => {
            assert_eq!(e.code, "E0701", "replayed decision must fail E0701");
        }
        Ok((outcome, _)) => panic!("replayed decision must fail E0701, got {outcome:?}"),
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn gateway_async_dispatch_streams_from_mock_provider() {
    use orbit_mock_provider::server::spawn;
    use orbit_provider_http::openai::{openai_capabilities, openai_identity};
    use orbit_provider_http::{CancelToken, OpenAiCompatibleHttpV1};

    // Start the mock provider (same as the homelab binary).
    let (addr, _state, _h) = spawn().await.expect("mock spawn");
    let dir = crate::tmpdir("async-dispatch");

    // Build the engine with the async adapter registered + egress allowlist.
    let mut registry = ProviderRegistry::new();
    let adapter = OpenAiCompatibleHttpV1::new(
        openai_identity(),
        openai_capabilities(),
        orbit_adapter::types::TlsPinPolicy {
            webpki: false,
            spki_sha256: None,
        },
    )
    .unwrap();
    let mut binding = test_binding();
    binding.adapter_kind = AdapterKind::OpenAiCompatibleHttpV1;
    binding.endpoint_host = "127.0.0.1".into();
    binding.endpoint_port = addr.port();
    binding.endpoint_scheme = orbit_adapter::types::EndpointScheme::HttpLoopback;
    registry.register_model(crate::ModelRef("test-model".into()), binding.clone());
    registry.register_async_adapter(
        AdapterKind::OpenAiCompatibleHttpV1,
        std::sync::Arc::new(adapter),
    );
    // The egress tuple derived from the binding uses the binding's provider_id
    // ("test-provider") + the loopback host/port — the allowlist must match.
    let mock_tuple = orbit_egress::EgressTuple {
        scheme: "http".into(),
        host: "127.0.0.1".into(),
        port: addr.port(),
        path_prefix: "/v1".into(),
        provider_id: "test-provider".into(),
        region_id: "test-region".into(),
    };
    let allowlist = EgressAllowlist::new(vec![mock_tuple.clone()]);
    let engine = DispatchEngine::new(registry, dir.clone(), allowlist, vec![mock_tuple], vec![]);
    let mut writer = LedgerWriter::open(&dir, "test-writer".into(), "0.1.0").unwrap();

    let session = new_session_id();
    let decision = new_decision_id();
    let request = canonical_request(&binding, b"hello");
    let cancel = CancelToken::new();
    let (outcome, reservation) = engine
        .dispatch_async(
            "test-model",
            &session,
            &decision.0,
            &request,
            None,
            &mut writer,
            &cancel,
            None,
        )
        .await
        .unwrap();
    assert_eq!(reservation.decision_id, decision.0);
    match outcome {
        DispatchOutcome::Completed(r) => {
            // The stream produced the mock's "hello world" text.
            let text: String = r
                .events
                .iter()
                .filter_map(|e| match &e.event {
                    orbit_adapter::types::ProviderEventKind::TextDelta { bytes } => {
                        Some(String::from_utf8_lossy(bytes).into_owned())
                    }
                    _ => None,
                })
                .collect();
            assert_eq!(
                text, "hello world",
                "async dispatch streamed the provider text"
            );
            // The final usage is surfaced into ProviderResult.accounting so
            // the CLI can compute real cost from its pricing config.
            assert_eq!(r.accounting.usage.input_tokens, 3);
            assert_eq!(r.accounting.usage.output_tokens, 2);
        }
        other => panic!("async dispatch expected Completed, got {other:?}"),
    }
    let _ = std::fs::remove_dir_all(&dir);
}

fn endpoint_query_binding(
    route: &ProviderRouteBinding,
    query: Option<&str>,
) -> ProviderRouteBinding {
    let mut encoded = serde_json::to_value(route).unwrap();
    match query {
        Some(query) => encoded["endpoint_query"] = query.into(),
        None => {
            encoded.as_object_mut().unwrap().remove("endpoint_query");
        }
    }
    serde_json::from_value(encoded).unwrap()
}

fn endpoint_query_sync_fixture(
    registered: Option<&str>,
    requested: Option<&str>,
) -> (Result<DispatchOutcome, crate::DispatchError>, bool) {
    use orbit_adapter::adapters::{MockHttpV1, MockScript};
    let dir = crate::tmpdir("query-sync");
    let probe = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let adapter = MockHttpV1::with_credential_probe(
        identity(AdapterKind::MockHttpV1, &"i".repeat(64), &"p".repeat(64)),
        text_capabilities(),
        MockScript::Success(canonical_success_result()),
        probe.clone(),
    );
    let mut binding = test_binding();
    binding.adapter_kind = AdapterKind::MockHttpV1;
    binding.endpoint_path = "/v1".into();
    let binding = endpoint_query_binding(&binding, registered);
    let mut request = canonical_request(&binding, b"hello");
    request.route = endpoint_query_binding(&binding, requested);
    let mut registry = ProviderRegistry::new();
    registry.register_model(crate::ModelRef("test-model".into()), binding);
    registry.register_adapter(AdapterKind::MockHttpV1, Arc::new(adapter));
    let engine = DispatchEngine::new(
        registry,
        dir.clone(),
        EgressAllowlist::new(vec![bound_tuple()]),
        vec![bound_tuple()],
        vec![spki_pin()],
    );
    let mut writer = LedgerWriter::open(&dir, "query-writer".into(), "0.1.0").unwrap();
    let session = new_session_id();
    let decision = new_decision_id();
    let secret = SecretBytes::new(b"synthetic-query-bound-key".to_vec());
    let result = engine
        .dispatch(
            "test-model",
            &session,
            &decision.0,
            &request,
            Some(&secret),
            &mut writer,
        )
        .map(|(outcome, _)| outcome);
    if result.is_err() {
        assert_eq!(
            engine.recovery_state(&session, &decision.0).unwrap(),
            DispatchState::Reserved
        );
    }
    writer.close().unwrap();
    std::fs::remove_dir_all(dir).unwrap();
    (result, probe.load(Ordering::SeqCst))
}

struct QueryCredentialProbe {
    inner: UsageScript,
    probe: Arc<std::sync::atomic::AtomicBool>,
}

#[async_trait::async_trait]
impl AsyncProviderAdapter for QueryCredentialProbe {
    fn identity(&self) -> orbit_adapter::types::AdapterIdentity {
        self.inner.identity()
    }
    fn capabilities(&self) -> &orbit_adapter::types::ProviderCapabilities {
        self.inner.capabilities()
    }
    fn validate_route(
        &self,
        route: &ProviderRouteBinding,
    ) -> Result<(), orbit_adapter::error::AdapterError> {
        self.inner.validate_route(route)
    }
    async fn invoke(
        &self,
        request: &orbit_adapter::types::ProviderRequest,
        credential: Option<&SecretBytes>,
        cancel: &CancelToken,
    ) -> Result<orbit_provider_http::AsyncProviderEventStream, orbit_adapter::error::AdapterError>
    {
        self.probe.store(credential.is_some(), Ordering::SeqCst);
        self.inner.invoke(request, credential, cancel).await
    }
}

async fn endpoint_query_async_fixture(
    registered: Option<&str>,
    requested: Option<&str>,
) -> (Result<DispatchOutcome, crate::DispatchError>, bool, usize) {
    let dir = crate::tmpdir("query-async");
    let calls = Arc::new(AtomicUsize::new(0));
    let probe = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let adapter = Arc::new(QueryCredentialProbe {
        inner: UsageScript {
            events: usage_events(&[], None),
            calls: calls.clone(),
            capabilities: text_capabilities(),
        },
        probe: probe.clone(),
    });
    let mut binding = test_binding();
    binding.endpoint_path = "/v1".into();
    let binding = endpoint_query_binding(&binding, registered);
    let mut request = canonical_request(&binding, b"hello");
    request.route = endpoint_query_binding(&binding, requested);
    let mut registry = ProviderRegistry::new();
    registry.register_model(crate::ModelRef("test-model".into()), binding.clone());
    registry.register_async_adapter(binding.adapter_kind, adapter);
    let engine = DispatchEngine::new(
        registry,
        dir.clone(),
        EgressAllowlist::new(vec![bound_tuple()]),
        vec![bound_tuple()],
        vec![spki_pin()],
    );
    let mut writer = LedgerWriter::open(&dir, "query-writer".into(), "0.1.0").unwrap();
    let session = new_session_id();
    let decision = new_decision_id();
    let secret = SecretBytes::new(b"synthetic-query-bound-key".to_vec());
    let mut observed = Vec::new();
    let result = tokio::time::timeout(
        Duration::from_secs(4),
        engine.dispatch_async(
            "test-model",
            &session,
            &decision.0,
            &request,
            Some(&secret),
            &mut writer,
            &CancelToken::new(),
            Some(&mut |event| observed.push(event.clone())),
        ),
    )
    .await
    .expect("bounded query fixture")
    .map(|(outcome, _)| outcome);
    if result.is_err() {
        assert_eq!(
            engine.recovery_state(&session, &decision.0).unwrap(),
            DispatchState::Reserved
        );
        assert!(observed.is_empty());
    }
    writer.close().unwrap();
    std::fs::remove_dir_all(dir).unwrap();
    (
        result,
        probe.load(Ordering::SeqCst),
        calls.load(Ordering::SeqCst),
    )
}

fn endpoint_query_changes() -> [(Option<&'static str>, Option<&'static str>); 5] {
    [
        (Some("scope=one"), Some("scope=two")),
        (Some("scope=one"), None),
        (None, Some("scope=one")),
        (Some("scope=one&other=two"), Some("other=two&scope=one")),
        (Some("scope=a%2Fb"), Some("scope=a/b")),
    ]
}

#[test]
fn gateway_endpoint_query_sync_mismatch_refuses_before_credential() {
    for (registered, requested) in endpoint_query_changes() {
        let (result, received) = endpoint_query_sync_fixture(registered, requested);
        assert_eq!(result.unwrap_err().phase, "capability");
        assert!(!received);
    }
}

#[tokio::test]
async fn gateway_endpoint_query_async_mismatch_refuses_before_credential_and_invoke() {
    for (registered, requested) in endpoint_query_changes() {
        let (result, received, calls) = endpoint_query_async_fixture(registered, requested).await;
        assert_eq!(result.unwrap_err().phase, "capability");
        assert!(!received);
        assert_eq!(calls, 0);
    }
}

#[test]
fn gateway_endpoint_query_sync_exact_match_is_admitted() {
    let (result, received) =
        endpoint_query_sync_fixture(Some("scope=a%2Fb&other=two"), Some("scope=a%2Fb&other=two"));
    assert!(matches!(result, Ok(DispatchOutcome::Completed(_))));
    assert!(received);
}

#[tokio::test]
async fn gateway_endpoint_query_async_exact_match_is_admitted() {
    let (result, received, calls) =
        endpoint_query_async_fixture(Some("scope=a%2Fb&other=two"), Some("scope=a%2Fb&other=two"))
            .await;
    assert!(matches!(result, Ok(DispatchOutcome::Completed(_))));
    assert!(received);
    assert_eq!(calls, 1);
}

#[test]
fn gateway_endpoint_query_sync_ambiguous_values_refuse_before_credential() {
    for query in [
        "",
        "scope=one#fragment",
        "scope=one\n",
        "scope=%GG",
        "scope=one&%73cope=two",
        "api_key=synthetic-query-bound-key",
    ] {
        let (result, received) = endpoint_query_sync_fixture(Some(query), Some(query));
        assert!(result.is_err(), "ambiguous query passed egress validation");
        assert!(!received);
    }
}

#[tokio::test]
async fn gateway_endpoint_query_async_ambiguous_values_refuse_before_credential_and_invoke() {
    for query in [
        "",
        "scope=one#fragment",
        "scope=one\n",
        "scope=%GG",
        "scope=one&%73cope=two",
        "api_key=synthetic-query-bound-key",
    ] {
        let (result, received, calls) =
            endpoint_query_async_fixture(Some(query), Some(query)).await;
        assert!(result.is_err(), "ambiguous query passed egress validation");
        assert!(!received);
        assert_eq!(calls, 0);
    }
}
