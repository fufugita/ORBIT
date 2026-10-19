use orbit_adapter::conformance::canonical_request;
use orbit_adapter::credential::SecretBytes;
use orbit_adapter::error::AdapterError;
use orbit_adapter::types::{
    AdapterIdentity, DeploymentId, EndpointScheme, ProviderCapabilities, ProviderEventKind,
    ProviderId, ProviderRequest, ProviderRouteBinding, ProviderStreamEvent, RegionId, Sha256Digest,
    TlsPinPolicy,
};
use orbit_egress::{EgressAllowlist, EgressTuple};
use orbit_gateway::dispatch::{
    DetailedDispatchOutcome, DispatchEngine, DispatchOutcome, EgressReservation,
};
use orbit_gateway::{ModelRef, ProviderRegistry, new_session_id};
use orbit_ledger::LedgerWriter;
use orbit_provider_http::adapter_trait::{DetailedInvokeFailure, FailureObservation};
use orbit_provider_http::openai::{openai_capabilities, openai_identity};
use orbit_provider_http::{
    AsyncProviderAdapter, AsyncProviderEventStream, CancelToken, OpenAiCompatibleHttpV1,
};
use std::path::PathBuf;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const CANARY: &str = "private-gateway-canary";
const DEADLINE: Duration = Duration::from_secs(8);

struct OwnedDir(PathBuf);
impl OwnedDir {
    fn new() -> Self {
        use std::os::unix::fs::DirBuilderExt;
        let path = std::env::temp_dir().join(format!("orbit-gateway-refusal-{}", new_session_id()));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .unwrap();
        Self(path)
    }
}
impl Drop for OwnedDir {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}

struct Wire {
    port: u16,
    ready: Option<tokio::sync::oneshot::Receiver<()>>,
    task: tokio::task::JoinHandle<Vec<u8>>,
}
impl Wire {
    async fn start(status: u16, body: Vec<u8>, declared: Option<usize>, hold: bool) -> Self {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let port = listener.local_addr().unwrap().port();
        let (ready, received) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            let (mut socket, _) = tokio::time::timeout(DEADLINE, listener.accept())
                .await
                .unwrap()
                .unwrap();
            let mut raw = Vec::new();
            let header_end = loop {
                let mut bytes = [0; 1024];
                let n = tokio::time::timeout(DEADLINE, socket.read(&mut bytes))
                    .await
                    .unwrap()
                    .unwrap();
                assert!(n > 0 && raw.len() + n <= 1_048_576);
                raw.extend_from_slice(&bytes[..n]);
                if let Some(end) = raw.windows(4).position(|bytes| bytes == b"\r\n\r\n") {
                    break end + 4;
                }
                assert!(raw.len() <= 32_768);
            };
            let headers = std::str::from_utf8(&raw[..header_end]).unwrap();
            assert!(headers.starts_with("POST /v1/chat/completions?region=fixture HTTP/1.1\r\n"));
            let length = headers
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().unwrap())
                })
                .unwrap();
            assert!(length <= 1_000_000);
            while raw.len() < header_end + length {
                let mut bytes = [0; 1024];
                let n = tokio::time::timeout(DEADLINE, socket.read(&mut bytes))
                    .await
                    .unwrap()
                    .unwrap();
                assert!(n > 0 && raw.len() + n <= 1_048_576);
                raw.extend_from_slice(&bytes[..n]);
            }
            let capture = raw[header_end..header_end + length].to_vec();
            let redirect = if (300..400).contains(&status) {
                "Location: http://127.0.0.1:1/no-follow\r\n"
            } else {
                ""
            };
            let headers = format!(
                "HTTP/1.1 {status} Fixture\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\n{redirect}Connection: close\r\n\r\n",
                declared.unwrap_or(body.len())
            );
            socket.write_all(headers.as_bytes()).await.unwrap();
            let _ = ready.send(());
            for bytes in body.chunks(2048) {
                if socket.write_all(bytes).await.is_err() {
                    return capture;
                }
            }
            if hold {
                let mut byte = [0];
                let result = tokio::time::timeout(DEADLINE, socket.read(&mut byte)).await;
                assert!(
                    matches!(result, Ok(Ok(0)) | Ok(Err(_))),
                    "gateway must release response"
                );
            }
            let _ = socket.shutdown().await;
            capture
        });
        Self {
            port,
            ready: Some(received),
            task,
        }
    }
    async fn ready(&mut self) {
        tokio::time::timeout(DEADLINE, self.ready.take().unwrap())
            .await
            .unwrap()
            .unwrap();
    }
    async fn finish(&mut self) -> Vec<u8> {
        tokio::time::timeout(DEADLINE, &mut self.task)
            .await
            .unwrap()
            .unwrap()
    }
}
impl Drop for Wire {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn adapter() -> Arc<OpenAiCompatibleHttpV1> {
    Arc::new(
        OpenAiCompatibleHttpV1::new(
            openai_identity(),
            openai_capabilities(),
            TlsPinPolicy {
                webpki: false,
                spki_sha256: None,
            },
        )
        .unwrap(),
    )
}

fn request(port: u16) -> ProviderRequest {
    let identity = openai_identity();
    let route = ProviderRouteBinding {
        provider_id: ProviderId("fixture".into()),
        deployment_id: DeploymentId("fixture".into()),
        region_id: RegionId("fixture".into()),
        adapter_kind: identity.kind,
        adapter_implementation_digest: identity.implementation_digest,
        adapter_profile_digest: identity.profile_digest,
        endpoint_digest: Sha256Digest("e".repeat(64)),
        expected_model: "fixture-model".into(),
        pricing_digest: Sha256Digest("c".repeat(64)),
        endpoint_host: "127.0.0.1".into(),
        endpoint_port: port,
        endpoint_scheme: EndpointScheme::HttpLoopback,
        endpoint_path: String::new(),
        endpoint_query: Some("region=fixture".into()),
    };
    let mut request = canonical_request(&route, CANARY.as_bytes());
    request.connect_timeout_ms = 2_000;
    request.first_byte_timeout_ms = 300;
    request.idle_timeout_ms = 300;
    request
}

fn engine(
    adapter: Arc<dyn AsyncProviderAdapter>,
    route: &ProviderRouteBinding,
    ledger: PathBuf,
) -> DispatchEngine {
    let tuple = EgressTuple {
        scheme: "http".into(),
        host: route.endpoint_host.clone(),
        port: route.endpoint_port,
        path_prefix: "/v1".into(),
        provider_id: route.provider_id.0.clone(),
        region_id: route.region_id.0.clone(),
    };
    let mut registry = ProviderRegistry::new();
    registry.register_model(ModelRef("fixture-model".into()), route.clone());
    registry.register_async_adapter(route.adapter_kind, adapter);
    DispatchEngine::new(
        registry,
        ledger,
        EgressAllowlist::new(vec![tuple.clone()]),
        vec![tuple],
        vec![],
    )
}

async fn detailed(
    adapter: Arc<dyn AsyncProviderAdapter>,
    request: &ProviderRequest,
    outer_decision: &str,
    poison: bool,
) -> (
    DetailedDispatchOutcome,
    EgressReservation,
    Vec<ProviderStreamEvent>,
) {
    let directory = OwnedDir::new();
    let ledger = directory.0.join("ledger");
    let engine = engine(adapter, &request.route, ledger.clone());
    let mut writer = LedgerWriter::open(&ledger, "typed-refusal".into(), "0.2.0").unwrap();
    if poison {
        let segments = ledger.join("segments");
        let held = ledger.join("segments-held");
        std::fs::rename(&segments, &held).unwrap();
        let failure = writer.fsync();
        std::fs::rename(&held, &segments).unwrap();
        assert!(
            failure.is_err(),
            "actual directory-identity refusal poisons writer"
        );
    }
    let mut observed = Vec::new();
    let session = new_session_id();
    let (outcome, reservation) = tokio::time::timeout(
        DEADLINE,
        engine.dispatch_async_detailed(
            "fixture-model",
            &session,
            outer_decision,
            request,
            None,
            &mut writer,
            &CancelToken::new(),
            Some(&mut |event| observed.push(event.clone())),
        ),
    )
    .await
    .unwrap()
    .unwrap();
    if poison {
        assert!(writer.close().is_err());
        assert!(reservation.intent_digest.is_empty());
    } else {
        writer.close().unwrap();
        assert!(!reservation.intent_digest.is_empty());
        let (records, _) = orbit_ledger::verify_ledger(&ledger).unwrap();
        let intents: Vec<_> = records
            .iter()
            .filter_map(|record| match &record.record.event {
                orbit_ledger::event::LedgerEvent::EgressIntent(intent) => Some(intent),
                _ => None,
            })
            .collect();
        assert_eq!(intents.len(), 1);
        assert_eq!(intents[0].decision_id, outer_decision);
        assert_eq!(intents[0].session_id, session);
    }
    assert_eq!(reservation.session_id, session);
    assert_eq!(reservation.decision_id, outer_decision);
    (outcome, reservation, observed)
}

#[tokio::test]
async fn real_complete_http_rejection_survives_durable_gateway_once() {
    for status in [500, 503] {
        let body = format!("{{\"message\":\"{CANARY}\"}}");
        let mut wire = Wire::start(status, body.clone().into_bytes(), None, false).await;
        let adapter = adapter();
        let request = request(wire.port);
        let (outcome, reservation, observed) =
            detailed(adapter.clone(), &request, &request.decision_id.0, false).await;
        let capture = wire.finish().await;
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&capture).unwrap()["messages"][0]["content"],
            CANARY
        );
        let FailureObservation::CompleteHttpRejection(observation) = outcome.observation() else {
            panic!("complete fact must survive")
        };
        assert!(observation.matches_request(&request, &adapter.identity()));
        assert_eq!(observation.decision_id(), reservation.decision_id);
        assert_eq!(observation.status(), status);
        assert_eq!(observation.response_body_bytes(), body.len() as u32);
        assert!(observed.is_empty());
        assert!(!format!("{outcome:?}").contains(CANARY));
        assert!(
            matches!(outcome.outcome(), DispatchOutcome::AdapterRefused { code: "E0408", message } if message.contains(CANARY))
        );
        let (legacy, observation) = outcome.into_parts();
        assert!(matches!(
            observation,
            FailureObservation::CompleteHttpRejection(_)
        ));
        assert!(matches!(
            legacy,
            DispatchOutcome::AdapterRefused { code: "E0408", .. }
        ));
    }
}

#[tokio::test]
async fn outer_decision_mismatch_preserves_legacy_error_but_discards_positive_fact() {
    let mut wire = Wire::start(503, CANARY.as_bytes().to_vec(), None, false).await;
    let request = request(wire.port);
    let (outcome, _, observed) =
        detailed(adapter(), &request, "different-egress-decision", false).await;
    wire.finish().await;
    assert_eq!(outcome.observation(), &FailureObservation::Unknown);
    assert!(observed.is_empty());
    assert!(
        matches!(outcome.into_legacy(), DispatchOutcome::AdapterRefused { code: "E0408", message } if message.contains(CANARY))
    );
}

#[tokio::test]
async fn ambiguous_bodies_successful_headers_and_redirects_remain_unknown_at_gateway() {
    for (status, body, declared, hold) in [
        (503, Vec::new(), Some(100), true),
        (503, b"partial".to_vec(), Some(100), false),
        (503, vec![b'x'; 65_537], None, false),
        (200, Vec::new(), None, false),
        (200, b"data: invalid-json\n\n".to_vec(), None, false),
        (
            200,
            b"data: {\"choices\":[{\"delta\":{\"content\":\"visible prefix\"}}]}\n\n".to_vec(),
            None,
            false,
        ),
        (200, Vec::new(), Some(100), true),
        (101, Vec::new(), None, false),
        (307, Vec::new(), None, false),
    ] {
        let mut wire = Wire::start(status, body, declared, hold).await;
        let request = request(wire.port);
        let (outcome, _, _) = detailed(adapter(), &request, &request.decision_id.0, false).await;
        wire.finish().await;
        assert_eq!(outcome.observation(), &FailureObservation::Unknown);
        assert!(matches!(
            outcome.outcome(),
            DispatchOutcome::AdapterRefused { .. }
        ));
    }
}

#[tokio::test]
async fn cancellation_during_real_error_body_is_unknown_and_preserves_cancelled_observers() {
    let mut wire = Wire::start(503, Vec::new(), Some(100), true).await;
    let request = request(wire.port);
    let directory = OwnedDir::new();
    let ledger = directory.0.join("ledger");
    let engine = engine(adapter(), &request.route, ledger.clone());
    let mut writer = LedgerWriter::open(&ledger, "cancel-body".into(), "0.2.0").unwrap();
    let cancel = CancelToken::new();
    let session = new_session_id();
    let mut observed = Vec::new();
    let (outcome, reservation) = {
        let mut observer = |event: &ProviderStreamEvent| observed.push(event.clone());
        let call = engine.dispatch_async_detailed(
            "fixture-model",
            &session,
            &request.decision_id.0,
            &request,
            None,
            &mut writer,
            &cancel,
            Some(&mut observer),
        );
        tokio::pin!(call);
        tokio::select! {
            result = &mut call => panic!("error body must remain held: {result:?}"),
            () = wire.ready() => {
                cancel.cancel(); tokio::time::timeout(DEADLINE, call).await.unwrap().unwrap()
            }
        }
    };
    wire.finish().await;
    writer.close().unwrap();
    assert!(!reservation.intent_digest.is_empty());
    assert_eq!(outcome.observation(), &FailureObservation::Unknown);
    let DispatchOutcome::Completed(result) = outcome.into_legacy() else {
        panic!("legacy cancellation is a collected partial stream")
    };
    assert_eq!(result.events, observed);
    assert!(
        matches!(&observed.last().unwrap().event, ProviderEventKind::Finished { finish_reason: Some(reason), .. } if reason == "cancelled")
    );
}

#[tokio::test]
async fn real_successful_stream_keeps_all_observers_and_unknown_failure_facts() {
    let body = b"data: {\"choices\":[{\"delta\":{\"content\":\"visible answer\"},\"finish_reason\":null}]}\n\ndata: {\"choices\":[{\"delta\":{},\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":3,\"completion_tokens\":2}}\n\ndata: [DONE]\n\n";
    let mut wire = Wire::start(200, body.to_vec(), None, false).await;
    let request = request(wire.port);
    let (outcome, _, observed) = detailed(adapter(), &request, &request.decision_id.0, false).await;
    wire.finish().await;
    assert_eq!(outcome.observation(), &FailureObservation::Unknown);
    let DispatchOutcome::Completed(result) = outcome.into_legacy() else {
        panic!("completed stream")
    };
    assert_eq!(result.events, observed);
    assert_eq!(result.accounting.usage.input_tokens, 3);
    assert_eq!(result.accounting.usage.output_tokens, 2);
    assert!(observed.iter().any(|event| matches!(&event.event, ProviderEventKind::TextDelta { bytes } if bytes == b"visible answer")));
}

struct LegacyOnly {
    calls: Arc<AtomicUsize>,
    capabilities: ProviderCapabilities,
    success: bool,
}
#[async_trait::async_trait]
impl AsyncProviderAdapter for LegacyOnly {
    fn identity(&self) -> AdapterIdentity {
        openai_identity()
    }
    fn capabilities(&self) -> &ProviderCapabilities {
        &self.capabilities
    }
    fn validate_route(&self, _: &ProviderRouteBinding) -> Result<(), AdapterError> {
        Ok(())
    }
    async fn invoke(
        &self,
        _: &ProviderRequest,
        _: Option<&SecretBytes>,
        _: &CancelToken,
    ) -> Result<AsyncProviderEventStream, AdapterError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if !self.success {
            return Err(AdapterError::CapacityUnavailableExhausted(CANARY.into()));
        }
        Ok(Box::pin(futures::stream::iter([
            Ok(ProviderStreamEvent {
                sequence: 0,
                event: ProviderEventKind::ResponseStarted {
                    upstream_request_id: None,
                },
            }),
            Ok(ProviderStreamEvent {
                sequence: 1,
                event: ProviderEventKind::TextDelta {
                    bytes: CANARY.as_bytes().to_vec(),
                },
            }),
            Ok(ProviderStreamEvent {
                sequence: 2,
                event: ProviderEventKind::Finished {
                    finish_reason: Some("stop".into()),
                    final_usage: None,
                },
            }),
        ])))
    }
}

fn legacy(calls: Arc<AtomicUsize>, success: bool) -> Arc<dyn AsyncProviderAdapter> {
    Arc::new(LegacyOnly {
        calls,
        success,
        capabilities: openai_capabilities(),
    })
}

#[tokio::test]
async fn legacy_only_adapter_is_one_call_and_success_observers_are_unchanged() {
    for success in [false, true] {
        let calls = Arc::new(AtomicUsize::new(0));
        let request = request(1);
        let (outcome, _, observed) = detailed(
            legacy(calls.clone(), success),
            &request,
            &request.decision_id.0,
            false,
        )
        .await;
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(outcome.observation(), &FailureObservation::Unknown);
        assert!(!format!("{outcome:?}").contains(CANARY));
        match outcome.into_legacy() {
            DispatchOutcome::Completed(result) => {
                assert!(success);
                assert_eq!(result.events, observed);
                assert_eq!(observed.len(), 3);
            }
            DispatchOutcome::AdapterRefused { code, message } => {
                assert!(!success);
                assert_eq!(code, "E0408");
                assert!(message.contains(CANARY));
                assert!(observed.is_empty());
            }
            _ => panic!("legacy projection"),
        }
    }
}

#[tokio::test]
async fn non_durable_egress_never_invokes_adapter_or_emits_positive_fact() {
    let calls = Arc::new(AtomicUsize::new(0));
    let request = request(1);
    let (outcome, _, observed) = detailed(
        legacy(calls.clone(), false),
        &request,
        &request.decision_id.0,
        true,
    )
    .await;
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert!(observed.is_empty());
    assert_eq!(outcome.observation(), &FailureObservation::Unknown);
    assert!(matches!(
        outcome.outcome(),
        DispatchOutcome::EgressNotDurable { .. }
    ));
}

#[tokio::test]
async fn legacy_dispatch_wrapper_calls_adapter_once_and_retains_prose_and_observers() {
    for success in [false, true] {
        let directory = OwnedDir::new();
        let ledger = directory.0.join("ledger");
        let calls = Arc::new(AtomicUsize::new(0));
        let request = request(1);
        let engine = engine(
            legacy(calls.clone(), success),
            &request.route,
            ledger.clone(),
        );
        let mut writer = LedgerWriter::open(&ledger, "legacy-wrapper".into(), "0.2.0").unwrap();
        let mut observed = Vec::new();
        let (outcome, _) = engine
            .dispatch_async(
                "fixture-model",
                &new_session_id(),
                &request.decision_id.0,
                &request,
                None,
                &mut writer,
                &CancelToken::new(),
                Some(&mut |event| observed.push(event.clone())),
            )
            .await
            .unwrap();
        writer.close().unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        match outcome {
            DispatchOutcome::Completed(result) => {
                assert!(success);
                assert_eq!(result.events, observed);
            }
            DispatchOutcome::AdapterRefused { code, message } => {
                assert!(!success);
                assert_eq!(code, "E0408");
                assert!(message.contains(CANARY));
            }
            _ => panic!("legacy outcome"),
        }
    }
}

// This adapter can only replay a failure first produced by the real HTTP
// adapter. No test has access to the positive observation constructor.
struct ReplayedFailure {
    failure: Mutex<Option<DetailedInvokeFailure>>,
    identity: AdapterIdentity,
    capabilities: ProviderCapabilities,
    calls: Arc<AtomicUsize>,
}
#[async_trait::async_trait]
impl AsyncProviderAdapter for ReplayedFailure {
    fn identity(&self) -> AdapterIdentity {
        self.identity.clone()
    }
    fn capabilities(&self) -> &ProviderCapabilities {
        &self.capabilities
    }
    fn validate_route(&self, _: &ProviderRouteBinding) -> Result<(), AdapterError> {
        Ok(())
    }
    async fn invoke(
        &self,
        _: &ProviderRequest,
        _: Option<&SecretBytes>,
        _: &CancelToken,
    ) -> Result<AsyncProviderEventStream, AdapterError> {
        panic!("detailed dispatch must not call the legacy override")
    }
    async fn invoke_detailed(
        &self,
        _: &ProviderRequest,
        _: Option<&SecretBytes>,
        _: &CancelToken,
    ) -> Result<AsyncProviderEventStream, DetailedInvokeFailure> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Err(self.failure.lock().unwrap().take().unwrap())
    }
}

#[tokio::test]
async fn gateway_revalidates_real_observations_against_changed_requests_and_selected_identity() {
    for change in 0..7 {
        let mut wire = Wire::start(503, Vec::new(), None, false).await;
        let original = request(wire.port);
        let adapter = adapter();
        let failure = adapter
            .invoke_detailed(&original, None, &CancelToken::new())
            .await
            .err()
            .unwrap();
        wire.finish().await;
        let mut changed = request(wire.port);
        let mut identity = openai_identity();
        match change {
            0 => changed.request_id.0.push('x'),
            1 => changed.decision_id.0.push('x'),
            2 => changed.attempt_id.0.push('x'),
            3 => changed.input = SecretBytes::new(b"different prompt".to_vec()),
            4 => changed.route.endpoint_query = Some("region=other".into()),
            5 => identity.implementation_digest.0.push('x'),
            6 => {
                identity.profile_digest.0.push('x');
                changed.route.adapter_profile_digest = identity.profile_digest.clone();
            }
            _ => unreachable!(),
        }
        let calls = Arc::new(AtomicUsize::new(0));
        let replay = Arc::new(ReplayedFailure {
            failure: Mutex::new(Some(failure)),
            identity,
            capabilities: openai_capabilities(),
            calls: calls.clone(),
        });
        let (outcome, _, observed) =
            detailed(replay, &changed, &changed.decision_id.0, false).await;
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(observed.is_empty());
        assert_eq!(
            outcome.observation(),
            &FailureObservation::Unknown,
            "changed component {change}"
        );
        assert!(matches!(
            outcome.outcome(),
            DispatchOutcome::AdapterRefused { code: "E0408", .. }
        ));
    }
}
