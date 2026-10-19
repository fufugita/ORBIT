use orbit_adapter::conformance::canonical_request;
use orbit_adapter::credential::SecretBytes;
use orbit_adapter::error::AdapterError;
use orbit_adapter::types::{
    AdapterIdentity, DeploymentId, EndpointScheme, ProviderCapabilities, ProviderId,
    ProviderRequest, ProviderRouteBinding, RegionId, Sha256Digest, TlsPinPolicy,
};
use orbit_provider_http::adapter_trait::{
    DetailedInvokeFailure, FailureObservation, RequestFingerprint,
};
use orbit_provider_http::openai::{chat_completions_url, openai_capabilities, openai_identity};
use orbit_provider_http::{
    AsyncProviderAdapter, AsyncProviderEventStream, CancelToken, OpenAiCompatibleHttpV1,
};
use sha2::{Digest, Sha256};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const CANARY: &str = "private-fixture-canary";
const DEADLINE: Duration = Duration::from_secs(6);

struct Capture {
    target: String,
    body: Vec<u8>,
    authorization: Option<String>,
}

struct Fixture {
    port: u16,
    ready: Option<tokio::sync::oneshot::Receiver<()>>,
    task: tokio::task::JoinHandle<Capture>,
}

impl Fixture {
    async fn start(
        status: u16,
        body: Vec<u8>,
        declared: Option<usize>,
        drip: bool,
        hold: bool,
    ) -> Self {
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
            let target = headers.lines().next().unwrap().to_owned();
            let authorization = headers.lines().find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("authorization")
                    .then(|| value.trim().to_owned())
            });
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
            let capture = Capture {
                target,
                body: raw[header_end..header_end + length].to_vec(),
                authorization,
            };
            let redirect = if (300..400).contains(&status) {
                "Location: http://127.0.0.1:1/never-follow\r\n"
            } else {
                ""
            };
            let headers = format!(
                "HTTP/1.1 {status} Fixture\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\n{redirect}Connection: close\r\n\r\n",
                declared.unwrap_or(body.len())
            );
            socket.write_all(headers.as_bytes()).await.unwrap();
            let _ = ready.send(());
            for bytes in body.chunks(if drip { 1 } else { 2048 }) {
                if drip {
                    tokio::time::sleep(Duration::from_millis(75)).await;
                }
                if socket.write_all(bytes).await.is_err() {
                    return capture;
                }
            }
            if hold {
                let mut byte = [0];
                let result = tokio::time::timeout(DEADLINE, socket.read(&mut byte)).await;
                assert!(
                    matches!(result, Ok(Ok(0)) | Ok(Err(_))),
                    "adapter must release held response"
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

    async fn complete(status: u16, body: Vec<u8>) -> Self {
        Self::start(status, body, None, false, false).await
    }
    async fn ready(&mut self) {
        tokio::time::timeout(DEADLINE, self.ready.take().unwrap())
            .await
            .unwrap()
            .unwrap();
    }
    async fn finish(&mut self) -> Capture {
        tokio::time::timeout(DEADLINE, &mut self.task)
            .await
            .unwrap()
            .unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn adapter() -> OpenAiCompatibleHttpV1 {
    OpenAiCompatibleHttpV1::new(
        openai_identity(),
        openai_capabilities(),
        TlsPinPolicy {
            webpki: false,
            spki_sha256: None,
        },
    )
    .unwrap()
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
        endpoint_path: "/exact/base".into(),
        endpoint_query: Some(format!("region=first&canary={CANARY}")),
    };
    let mut request = canonical_request(&route, CANARY.as_bytes());
    request.connect_timeout_ms = 2_000;
    request.first_byte_timeout_ms = 300;
    request.idle_timeout_ms = 300;
    request
}

async fn failure(
    adapter: &dyn AsyncProviderAdapter,
    request: &ProviderRequest,
) -> DetailedInvokeFailure {
    tokio::time::timeout(
        DEADLINE,
        adapter.invoke_detailed(request, None, &CancelToken::new()),
    )
    .await
    .unwrap()
    .err()
    .expect("invoke rejection")
}

fn digest(domain: &[u8], bytes: &[u8]) -> String {
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update(bytes);
    hex::encode(hash.finalize())
}

#[tokio::test]
async fn complete_rejections_bind_captured_wire_bytes_and_preserve_legacy_prose() {
    for status in [400, 429, 500, 503] {
        let body = format!("{{\"error\":{{\"message\":\"{CANARY}\"}}}}").into_bytes();
        let mut fixture = Fixture::complete(status, body.clone()).await;
        let adapter = adapter();
        let request = request(fixture.port);
        let fingerprint = RequestFingerprint::for_request(&request, &adapter.identity()).unwrap();
        let credential = SecretBytes::new(CANARY.as_bytes().to_vec());
        let failure = adapter
            .invoke_detailed(&request, Some(&credential), &CancelToken::new())
            .await
            .err()
            .unwrap();
        let capture = fixture.finish().await;
        let FailureObservation::CompleteHttpRejection(observation) = failure.observation() else {
            panic!("complete rejection")
        };
        assert_eq!(observation.status(), status);
        assert_eq!(observation.response_body_bytes(), body.len() as u32);
        assert_eq!(observation.request_id(), request.request_id.0);
        assert_eq!(observation.decision_id(), request.decision_id.0);
        assert_eq!(observation.attempt_id(), request.attempt_id.0);
        assert_eq!(observation.adapter_identity(), &adapter.identity());
        assert!(observation.matches_request(&request, &adapter.identity()));
        assert_eq!(
            capture.target,
            format!("POST /exact/base/chat/completions?region=first&canary={CANARY} HTTP/1.1")
        );
        assert_eq!(capture.authorization, Some(format!("Bearer {CANARY}")));
        assert_eq!(
            observation.body_digest(),
            digest(b"orbit-http-rejection-body-v1\0", &capture.body)
        );
        assert_eq!(
            observation.route_digest(),
            digest(
                b"orbit-http-rejection-route-v1\0",
                &serde_json::to_vec(&(
                    &request.route,
                    chat_completions_url(&request.route).unwrap()
                ))
                .unwrap()
            )
        );
        assert_eq!(fingerprint.body_digest(), observation.body_digest());
        assert_eq!(fingerprint.route_digest(), observation.route_digest());
        let fingerprint_bytes = serde_json::to_vec(&(
            fingerprint.request_id(),
            fingerprint.decision_id(),
            fingerprint.attempt_id(),
            fingerprint.route_digest(),
            fingerprint.body_digest(),
            fingerprint.adapter_identity(),
        ))
        .unwrap();
        assert_eq!(
            fingerprint.digest(),
            digest(b"orbit-http-request-fingerprint-v1\0", &fingerprint_bytes)
        );
        let expected = serde_json::to_vec(&(
            observation.request_id(),
            observation.decision_id(),
            observation.attempt_id(),
            observation.route_digest(),
            observation.body_digest(),
            observation.adapter_identity(),
            status,
            body.len() as u32,
        ))
        .unwrap();
        assert_eq!(
            observation.observation_digest(),
            digest(b"orbit-http-rejection-observation-v1\0", &expected)
        );
        assert!(failure.error().to_string().contains(CANARY));
        for debug in [
            format!("{failure:?}"),
            format!("{observation:?}"),
            format!("{fingerprint:?}"),
        ] {
            assert!(!debug.contains(CANARY));
            assert!(!debug.contains("127.0.0.1"));
        }
        let expected_error = orbit_provider_http::error::status_error(
            reqwest::StatusCode::from_u16(status).unwrap(),
            String::from_utf8(body).unwrap(),
        )
        .await;
        assert_eq!(failure.into_error(), expected_error);
    }
}

#[tokio::test]
async fn empty_and_exact_limit_complete_bodies_qualify_but_overflow_does_not() {
    for length in [0, 65_536, 65_537] {
        let mut fixture = Fixture::complete(503, vec![b'x'; length]).await;
        let failure = failure(&adapter(), &request(fixture.port)).await;
        fixture.finish().await;
        assert_eq!(failure.error().code(), "E0408");
        match failure.observation() {
            FailureObservation::CompleteHttpRejection(observation) => {
                assert!(length <= 65_536);
                assert_eq!(observation.response_body_bytes(), length as u32);
            }
            FailureObservation::Unknown => assert_eq!(length, 65_537),
        }
    }
}

#[tokio::test]
async fn truncated_body_preserves_status_class_without_a_complete_observation() {
    let mut fixture = Fixture::start(503, b"partial".to_vec(), Some(100), false, false).await;
    let failure = failure(&adapter(), &request(fixture.port)).await;
    fixture.finish().await;
    assert_eq!(failure.error().code(), "E0408");
    assert_eq!(failure.observation(), &FailureObservation::Unknown);
    assert!(!failure.error().to_string().contains("partial"));
}

#[tokio::test]
async fn rejection_deadline_bounds_the_whole_body_even_with_a_slow_drip() {
    for drip in [false, true] {
        let mut fixture = Fixture::start(
            503,
            if drip { vec![b'x'; 64] } else { Vec::new() },
            Some(100),
            drip,
            true,
        )
        .await;
        let mut request = request(fixture.port);
        request.idle_timeout_ms = 300;
        let start = std::time::Instant::now();
        let failure = failure(&adapter(), &request).await;
        assert!(start.elapsed() < Duration::from_secs(3));
        fixture.finish().await;
        assert_eq!(failure.error().code(), "E0409");
        assert_eq!(failure.observation(), &FailureObservation::Unknown);
    }
}

#[tokio::test]
async fn cancellation_of_error_body_retains_the_original_cancelled_stream_contract() {
    let mut fixture = Fixture::start(503, Vec::new(), Some(100), false, true).await;
    let request = request(fixture.port);
    let adapter = adapter();
    let cancel = CancelToken::new();
    let invoke = adapter.invoke_detailed(&request, None, &cancel);
    tokio::pin!(invoke);
    let stream = tokio::select! {
        result = &mut invoke => panic!("body must be held: {:?}", result.err()),
        () = fixture.ready() => { cancel.cancel(); invoke.await.unwrap() }
    };
    let (events, _) = orbit_provider_http::stream::collect_stream(stream, None)
        .await
        .unwrap();
    assert!(
        matches!(&events.last().unwrap().event, orbit_adapter::types::ProviderEventKind::Finished { finish_reason: Some(reason), .. } if reason == "cancelled")
    );
    fixture.finish().await;
}

#[tokio::test]
async fn successful_headers_never_become_rejection_observations() {
    for (body, declared, hold) in [
        (Vec::new(), None, false),
        (b"data: invalid-json\n\n".to_vec(), None, false),
        (Vec::new(), Some(100), true),
    ] {
        let mut fixture = Fixture::start(200, body, declared, false, hold).await;
        let adapter = adapter();
        let request = request(fixture.port);
        let stream = adapter
            .invoke_detailed(&request, None, &CancelToken::new())
            .await
            .expect("successful headers return stream");
        let outcome = tokio::time::timeout(
            DEADLINE,
            orbit_provider_http::stream::collect_stream(stream, None),
        )
        .await
        .unwrap();
        assert!(
            outcome.is_err(),
            "empty, malformed or stalled SSE is incomplete"
        );
        fixture.finish().await;
    }
}

#[tokio::test]
async fn redirects_and_send_failure_remain_unknown() {
    for status in [101, 307] {
        let mut fixture = Fixture::complete(status, Vec::new()).await;
        let failure = failure(&adapter(), &request(fixture.port)).await;
        fixture.finish().await;
        if status == 307 {
            assert_eq!(failure.error().code(), "E0411");
        }
        assert_eq!(failure.observation(), &FailureObservation::Unknown);
    }
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let failure = failure(&adapter(), &request(port)).await;
    assert_eq!(failure.error().code(), "E0410");
    assert_eq!(failure.observation(), &FailureObservation::Unknown);
}

#[tokio::test]
async fn observation_verifier_binds_each_id_route_query_body_and_profile() {
    let mut fixture = Fixture::complete(500, Vec::new()).await;
    let failure = failure(&adapter(), &request(fixture.port)).await;
    fixture.finish().await;
    let FailureObservation::CompleteHttpRejection(observation) = failure.observation() else {
        panic!("complete")
    };
    let original = request(fixture.port);
    assert!(observation.matches_request(&original, &openai_identity()));
    for change in 0..14 {
        let mut changed = request(fixture.port);
        let mut identity = openai_identity();
        match change {
            0 => changed.request_id.0.push('x'),
            1 => changed.decision_id.0.push('x'),
            2 => changed.attempt_id.0.push('x'),
            3 => changed.route.endpoint_path.push('x'),
            4 => changed.route.endpoint_query = Some(format!("canary={CANARY}&region=first")),
            5 => changed.input = SecretBytes::new(b"different prompt".to_vec()),
            6 => changed.route.expected_model.push('x'),
            7 => changed.route.adapter_profile_digest.0.push('x'),
            8 => identity.profile_digest.0.push('x'),
            9 => changed.route.pricing_digest.0.push('x'),
            10 => changed.route.endpoint_digest.0.push('x'),
            11 => changed.route.deployment_id.0.push('x'),
            12 => changed.route.endpoint_port = 1,
            13 => changed.sampling.max_output_tokens += 1,
            _ => unreachable!(),
        }
        assert!(
            !observation.matches_request(&changed, &identity),
            "changed component {change}"
        );
    }
}

#[test]
fn preflight_fingerprint_is_pure_exact_and_does_not_mint_an_observation() {
    let mut request = request(65530);
    let identity = openai_identity();
    let fingerprint = RequestFingerprint::for_request(&request, &identity).unwrap();
    assert_eq!(fingerprint.request_id(), request.request_id.0);
    assert_eq!(fingerprint.decision_id(), request.decision_id.0);
    assert_eq!(fingerprint.attempt_id(), request.attempt_id.0);
    assert_eq!(fingerprint.adapter_identity(), &identity);
    assert_eq!(fingerprint.digest().len(), 64);
    request.request_id.0.clear();
    assert!(RequestFingerprint::for_request(&request, &identity).is_err());
    request.request_id.0 = "x".repeat(257);
    assert!(RequestFingerprint::for_request(&request, &identity).is_err());
    request.request_id.0 = "bad\nidentity".into();
    assert!(RequestFingerprint::for_request(&request, &identity).is_err());
}

#[test]
fn fingerprint_hashes_rendered_transcript_instead_of_unused_fallback_input() {
    let mut request = request(65530);
    request.messages = Some(vec![orbit_adapter::types::ChatMessage {
        role: orbit_adapter::types::ChatRole::User,
        content: "actual transcript".into(),
        blocks: None,
        tool_calls: None,
        tool_call_id: None,
        tool_result: None,
        origin_model: None,
        origin_provider: None,
    }]);
    let fingerprint = RequestFingerprint::for_request(&request, &openai_identity()).unwrap();
    request.input = SecretBytes::new(b"unused fallback changed".to_vec());
    assert_eq!(
        RequestFingerprint::for_request(&request, &openai_identity()).unwrap(),
        fingerprint
    );
    request.messages.as_mut().unwrap()[0].content.push('x');
    assert_ne!(
        RequestFingerprint::for_request(&request, &openai_identity())
            .unwrap()
            .body_digest(),
        fingerprint.body_digest()
    );
}

struct LegacyOnly {
    calls: Arc<AtomicUsize>,
    capabilities: ProviderCapabilities,
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
        Err(AdapterError::CapacityUnavailableExhausted(CANARY.into()))
    }
}

#[tokio::test]
async fn legacy_only_adapter_default_is_one_call_unknown_and_redacted() {
    let calls = Arc::new(AtomicUsize::new(0));
    let adapter = LegacyOnly {
        calls: calls.clone(),
        capabilities: openai_capabilities(),
    };
    let failure = failure(&adapter, &request(1)).await;
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(failure.observation(), &FailureObservation::Unknown);
    assert!(failure.error().to_string().contains(CANARY));
    assert!(!format!("{failure:?}").contains(CANARY));
}

#[tokio::test]
async fn legacy_openai_entry_point_uses_the_same_one_request_error_projection() {
    let body = format!("{{\"message\":\"{CANARY}\"}}");
    let mut fixture = Fixture::complete(503, body.clone().into_bytes()).await;
    let error = adapter()
        .invoke(&request(fixture.port), None, &CancelToken::new())
        .await
        .err()
        .unwrap();
    fixture.finish().await;
    assert_eq!(
        error,
        orbit_provider_http::error::status_error(reqwest::StatusCode::SERVICE_UNAVAILABLE, body)
            .await
    );
}
