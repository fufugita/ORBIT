use futures::StreamExt;
use orbit_adapter::conformance::canonical_request;
use orbit_adapter::error::AdapterError;
use orbit_adapter::types::{
    AdapterIdentity, AdapterKind, DeploymentId, EndpointScheme, ProviderEventKind, ProviderId,
    ProviderRequest, ProviderRouteBinding, ProviderStreamEvent, RegionId, Sha256Digest,
    TlsPinPolicy,
};
use orbit_provider_http::{AsyncProviderAdapter, CancelToken};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot};

const WATCHDOG: Duration = Duration::from_secs(5);
const CANCEL_BUDGET: Duration = Duration::from_secs(1);

/// Independent of the async runtime and the adapter's 15-second timeouts.
/// A stuck runtime cannot make a cancellation regression hang the test runner.
struct Watchdog {
    done: Option<std::sync::mpsc::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Watchdog {
    fn new() -> Self {
        let (done, wait) = std::sync::mpsc::channel();
        let thread = std::thread::spawn(move || {
            if matches!(
                wait.recv_timeout(WATCHDOG),
                Err(std::sync::mpsc::RecvTimeoutError::Timeout)
            ) {
                eprintln!("provider cancellation exceeded independent watchdog");
                std::process::exit(90);
            }
        });
        Self {
            done: Some(done),
            thread: Some(thread),
        }
    }
}

impl Drop for Watchdog {
    fn drop(&mut self) {
        if let Some(done) = self.done.take() {
            let _ = done.send(());
        }
        if let Some(thread) = self.thread.take() {
            thread.join().unwrap();
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum Adapter {
    OpenAi,
    Anthropic,
    Ollama,
}

impl Adapter {
    fn build(self) -> Box<dyn AsyncProviderAdapter> {
        use orbit_provider_http::{AnthropicMessagesV1, OllamaHttpV1, OpenAiCompatibleHttpV1};
        match self {
            Self::OpenAi => Box::new(
                OpenAiCompatibleHttpV1::new(
                    orbit_provider_http::openai::openai_identity(),
                    orbit_provider_http::openai::openai_capabilities(),
                    TlsPinPolicy {
                        webpki: false,
                        spki_sha256: None,
                    },
                )
                .unwrap(),
            ),
            Self::Anthropic => Box::new(
                AnthropicMessagesV1::new(
                    orbit_provider_http::anthropic::anthropic_identity(),
                    orbit_provider_http::anthropic::anthropic_capabilities(),
                )
                .unwrap(),
            ),
            Self::Ollama => Box::new(
                OllamaHttpV1::new(
                    AdapterIdentity {
                        kind: AdapterKind::LocalProcessV1,
                        implementation_digest: Sha256Digest("i".repeat(64)),
                        profile_digest: Sha256Digest("p".repeat(64)),
                    },
                    orbit_provider_http::openai::openai_capabilities(),
                )
                .unwrap(),
            ),
        }
    }

    fn delta(self) -> &'static [u8] {
        match self {
            Self::OpenAi => b"data: {\"choices\":[{\"delta\":{\"content\":\"partial visible\"}}]}\n\n",
            Self::Anthropic => b"data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"partial visible\"}}\n\n",
            Self::Ollama => b"{\"message\":{\"content\":\"partial visible\"},\"done\":false}\n",
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum Stage {
    Headers,
    FirstByte,
    Idle,
    ErrorBody,
    CompleteError,
}

struct Fixture {
    port: u16,
    connections: Arc<AtomicUsize>,
    requests: Arc<AtomicUsize>,
    ready: mpsc::UnboundedReceiver<()>,
    closed: mpsc::UnboundedReceiver<()>,
    stop: oneshot::Sender<()>,
    task: tokio::task::JoinHandle<()>,
}

impl Fixture {
    async fn start(adapter: Adapter, stage: Stage) -> Self {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let port = listener.local_addr().unwrap().port();
        let requests = Arc::new(AtomicUsize::new(0));
        let connection_count = Arc::new(AtomicUsize::new(0));
        let accepted_count = connection_count.clone();
        let captured = requests.clone();
        let (ready_tx, ready) = mpsc::unbounded_channel();
        let (closed_tx, closed) = mpsc::unbounded_channel();
        let (stop, mut stopped) = oneshot::channel();
        let task = tokio::spawn(async move {
            let mut connections = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    _ = &mut stopped => break,
                    accepted = listener.accept() => {
                        let (mut socket, _) = accepted.unwrap();
                        accepted_count.fetch_add(1, Ordering::SeqCst);
                        let captured = captured.clone();
                        let ready_tx = ready_tx.clone();
                        let closed_tx = closed_tx.clone();
                        connections.spawn(async move {
                            let mut request = Vec::new();
                            let header_end = loop {
                                let mut byte = [0u8; 1];
                                assert_eq!(socket.read(&mut byte).await.unwrap(), 1);
                                request.push(byte[0]);
                                assert!(request.len() < 16384, "bounded request headers");
                                if request.ends_with(b"\r\n\r\n") { break request.len(); }
                            };
                            let headers = String::from_utf8(request).unwrap();
                            assert!(headers.starts_with("POST /"));
                            let content_length: usize = headers.lines().find_map(|line| {
                                let (key, value) = line.split_once(':')?;
                                key.eq_ignore_ascii_case("content-length").then(|| value.trim().parse().unwrap())
                            }).unwrap();
                            assert!(header_end < 16384 && content_length < 1024 * 1024);
                            let mut body = vec![0u8; content_length];
                            socket.read_exact(&mut body).await.unwrap();
                            let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
                            assert_eq!(body["model"], "local-model");
                            captured.fetch_add(1, Ordering::SeqCst);
                            let response = match stage {
                                Stage::Headers => Vec::new(),
                                Stage::FirstByte | Stage::Idle => b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: 1000000\r\nConnection: close\r\n\r\n".to_vec(),
                                Stage::ErrorBody => b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 1000000\r\nConnection: close\r\n\r\n{\"error\":{\"message\":\"".to_vec(),
                                Stage::CompleteError => {
                                    let body = b"{\"error\":{\"message\":\"fixture capacity\"}}";
                                    format!("HTTP/1.1 503 Service Unavailable\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).into_bytes().into_iter().chain(body.iter().copied()).collect()
                                }
                            };
                            socket.write_all(&response).await.unwrap();
                            if matches!(stage, Stage::Idle) { socket.write_all(adapter.delta()).await.unwrap(); }
                            socket.flush().await.unwrap();
                            ready_tx.send(()).unwrap();
                            if matches!(stage, Stage::CompleteError) { return; }
                            let mut probe = [0u8; 1];
                            // A cancelled pending request/body must release its socket.
                            let read = socket.read(&mut probe).await;
                            assert!(matches!(read, Ok(0) | Err(_)), "no second request on cancelled connection");
                            let _ = closed_tx.send(());
                        });
                    }
                    joined = connections.join_next(), if !connections.is_empty() => { joined.unwrap().unwrap(); }
                }
            }
            connections.abort_all();
            while let Some(result) = connections.join_next().await {
                if let Err(error) = result {
                    assert!(error.is_cancelled());
                }
            }
        });
        Self {
            port,
            connections: connection_count,
            requests,
            ready,
            closed,
            stop,
            task,
        }
    }

    async fn finish(self) {
        self.stop.send(()).unwrap();
        self.task.await.unwrap();
    }
}

fn request(adapter: &dyn AsyncProviderAdapter, port: u16) -> ProviderRequest {
    let identity = adapter.identity();
    let mut request = canonical_request(
        &ProviderRouteBinding {
            provider_id: ProviderId("fixture".into()),
            deployment_id: DeploymentId("fixture".into()),
            region_id: RegionId("loopback".into()),
            adapter_kind: identity.kind,
            adapter_implementation_digest: identity.implementation_digest,
            adapter_profile_digest: identity.profile_digest,
            endpoint_digest: Sha256Digest("e".repeat(64)),
            expected_model: "local-model".into(),
            pricing_digest: Sha256Digest("r".repeat(64)),
            endpoint_host: "127.0.0.1".into(),
            endpoint_port: port,
            endpoint_scheme: EndpointScheme::HttpLoopback,
            endpoint_path: String::new(),
        },
        b"cancellation fixture",
    );
    request.connect_timeout_ms = 15000;
    request.first_byte_timeout_ms = 15000;
    request.idle_timeout_ms = 15000;
    request
}

async fn collect(
    adapter: Box<dyn AsyncProviderAdapter>,
    request: ProviderRequest,
    cancel: CancelToken,
    observed: mpsc::UnboundedSender<bool>,
) -> Result<Vec<ProviderStreamEvent>, AdapterError> {
    let mut stream = adapter.invoke(&request, None, &cancel).await?;
    let mut events = Vec::new();
    while let Some(event) = stream.next().await {
        let event = event?;
        if matches!(&event.event, ProviderEventKind::ResponseStarted { .. }) {
            let _ = observed.send(false);
        }
        if matches!(&event.event, ProviderEventKind::TextDelta { .. }) {
            let _ = observed.send(true);
        }
        events.push(event);
    }
    Ok(events)
}

async fn cancellation_case(kind: Adapter, stage: Stage) {
    let _watchdog = Watchdog::new();
    let mut fixture = Fixture::start(kind, stage).await;
    let adapter = kind.build();
    let request = request(adapter.as_ref(), fixture.port);
    let cancel = CancelToken::new();
    let (observed_tx, mut observed) = mpsc::unbounded_channel();
    let work = tokio::spawn(collect(adapter, request, cancel.clone(), observed_tx));
    tokio::time::timeout(CANCEL_BUDGET, fixture.ready.recv())
        .await
        .unwrap()
        .unwrap();
    if matches!(stage, Stage::Idle | Stage::FirstByte) {
        let text = tokio::time::timeout(CANCEL_BUDGET, observed.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(!text, "response started before body processing");
        if matches!(stage, Stage::Idle) {
            assert!(tokio::time::timeout(CANCEL_BUDGET, observed.recv())
                .await
                .unwrap()
                .unwrap());
        }
    } else if matches!(stage, Stage::ErrorBody) {
        // Headers and an incomplete body reached the client, which cannot
        // resolve until the body ends or cancellation arrives.
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(!work.is_finished());
    } else {
        // The pending read has no bytes to consume; yielding lets it register.
        tokio::task::yield_now().await;
    }
    cancel.cancel();
    let events = tokio::time::timeout(CANCEL_BUDGET, work)
        .await
        .expect("cancel wait budget")
        .unwrap()
        .unwrap();
    for (index, event) in events.iter().enumerate() {
        assert_eq!(event.sequence, index as u64);
    }
    assert!(matches!(
        events.first().unwrap().event,
        ProviderEventKind::ResponseStarted { .. }
    ));
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(event.event, ProviderEventKind::Finished { .. }))
            .count(),
        1
    );
    assert!(
        matches!(&events.last().unwrap().event, ProviderEventKind::Finished { finish_reason: Some(reason), .. } if reason == "cancelled")
    );
    let text: Vec<u8> = events
        .iter()
        .filter_map(|event| match &event.event {
            ProviderEventKind::TextDelta { bytes } => Some(bytes.as_slice()),
            _ => None,
        })
        .flatten()
        .copied()
        .collect();
    assert_eq!(
        text,
        if matches!(stage, Stage::Idle) {
            b"partial visible".as_slice()
        } else {
            b"".as_slice()
        }
    );
    tokio::time::timeout(CANCEL_BUDGET, fixture.closed.recv())
        .await
        .expect("cancel closes HTTP connection")
        .unwrap();
    assert_eq!(
        fixture.requests.load(Ordering::SeqCst),
        1,
        "cancellation never retries"
    );
    fixture.finish().await;
}

async fn pre_cancel_case(kind: Adapter) {
    let _watchdog = Watchdog::new();
    let fixture = Fixture::start(kind, Stage::Headers).await;
    let adapter = kind.build();
    let request = request(adapter.as_ref(), fixture.port);
    let cancel = CancelToken::new();
    cancel.cancel();
    let (observed, _) = mpsc::unbounded_channel();
    let events = tokio::time::timeout(CANCEL_BUDGET, collect(adapter, request, cancel, observed))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(events.len(), 2);
    assert!(
        matches!(&events[1].event, ProviderEventKind::Finished { finish_reason: Some(reason), .. } if reason == "cancelled")
    );
    tokio::time::sleep(Duration::from_millis(30)).await;
    assert_eq!(
        fixture.requests.load(Ordering::SeqCst),
        0,
        "pre-cancel must not send HTTP"
    );
    assert_eq!(
        fixture.connections.load(Ordering::SeqCst),
        0,
        "pre-cancel must not connect"
    );
    fixture.finish().await;
}

async fn status_case(kind: Adapter) {
    let _watchdog = Watchdog::new();
    let fixture = Fixture::start(kind, Stage::CompleteError).await;
    let adapter = kind.build();
    let request = request(adapter.as_ref(), fixture.port);
    let (observed, _) = mpsc::unbounded_channel();
    let error = collect(adapter, request, CancelToken::new(), observed)
        .await
        .unwrap_err();
    assert!(
        matches!(error, AdapterError::CapacityUnavailableExhausted(ref message) if message.contains("fixture capacity"))
    );
    assert_eq!(fixture.requests.load(Ordering::SeqCst), 1);
    fixture.finish().await;
}

async fn timeout_case(kind: Adapter) {
    let _watchdog = Watchdog::new();
    let fixture = Fixture::start(kind, Stage::FirstByte).await;
    let adapter = kind.build();
    let mut request = request(adapter.as_ref(), fixture.port);
    request.first_byte_timeout_ms = 50;
    let (observed, _) = mpsc::unbounded_channel();
    let error = collect(adapter, request, CancelToken::new(), observed)
        .await
        .unwrap_err();
    assert!(matches!(error, AdapterError::ProviderTimeout(_)));
    assert_eq!(fixture.requests.load(Ordering::SeqCst), 1);
    fixture.finish().await;
}

macro_rules! cases {
    ($headers:ident, $first:ident, $idle:ident, $error:ident, $pre:ident, $status:ident, $timeout:ident, $adapter:ident) => {
        #[tokio::test]
        async fn $headers() {
            cancellation_case(Adapter::$adapter, Stage::Headers).await;
        }
        #[tokio::test]
        async fn $first() {
            cancellation_case(Adapter::$adapter, Stage::FirstByte).await;
        }
        #[tokio::test]
        async fn $idle() {
            cancellation_case(Adapter::$adapter, Stage::Idle).await;
        }
        #[tokio::test]
        async fn $error() {
            cancellation_case(Adapter::$adapter, Stage::ErrorBody).await;
        }
        #[tokio::test]
        async fn $pre() {
            pre_cancel_case(Adapter::$adapter).await;
        }
        #[tokio::test]
        async fn $status() {
            status_case(Adapter::$adapter).await;
        }
        #[tokio::test]
        async fn $timeout() {
            timeout_case(Adapter::$adapter).await;
        }
    };
}

cases!(
    openai_cancel_headers,
    openai_cancel_first_byte,
    openai_cancel_idle,
    openai_cancel_error_body,
    openai_pre_cancel_zero_requests,
    openai_status_classification_preserved,
    openai_timeout_preserved,
    OpenAi
);
cases!(
    anthropic_cancel_headers,
    anthropic_cancel_first_byte,
    anthropic_cancel_idle,
    anthropic_cancel_error_body,
    anthropic_pre_cancel_zero_requests,
    anthropic_status_classification_preserved,
    anthropic_timeout_preserved,
    Anthropic
);
cases!(
    ollama_cancel_headers,
    ollama_cancel_first_byte,
    ollama_cancel_idle,
    ollama_cancel_error_body,
    ollama_pre_cancel_zero_requests,
    ollama_status_classification_preserved,
    ollama_timeout_preserved,
    Ollama
);

#[tokio::test]
async fn all_pending_waiters_are_notified() {
    let _watchdog = Watchdog::new();
    let cancel = CancelToken::new();
    let mut waiters = Vec::new();
    for _ in 0..64 {
        let cancel = cancel.clone();
        waiters.push(tokio::spawn(async move { cancel.cancelled().await }));
    }
    tokio::task::yield_now().await;
    cancel.cancel();
    for waiter in waiters {
        tokio::time::timeout(CANCEL_BUDGET, waiter)
            .await
            .unwrap()
            .unwrap();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn waiter_registration_races_do_not_lose_cancellation() {
    let _watchdog = Watchdog::new();
    for _ in 0..256 {
        let cancel = CancelToken::new();
        let waiter_cancel = cancel.clone();
        let waiter = tokio::spawn(async move { waiter_cancel.cancelled().await });
        std::thread::scope(|scope| {
            scope.spawn(|| cancel.cancel());
        });
        tokio::time::timeout(CANCEL_BUDGET, waiter)
            .await
            .unwrap()
            .unwrap();
    }
}
