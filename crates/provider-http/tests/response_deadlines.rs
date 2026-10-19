use futures::StreamExt;
use orbit_adapter::conformance::canonical_request;
use orbit_adapter::credential::SecretBytes;
use orbit_adapter::error::AdapterError;
use orbit_adapter::types::{
    DeploymentId, EndpointScheme, ProviderEventKind, ProviderId, ProviderRequest,
    ProviderRouteBinding, ProviderStreamEvent, ProviderUsage, RegionId, Sha256Digest, TlsPinPolicy,
};
use orbit_provider_http::{
    AsyncProviderAdapter, CancelToken, OpenAiCompatibleHttpV1,
    openai::{openai_capabilities, openai_identity},
};
use serde_json::{Value, json};
use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const MODEL: &str = "fixture-model";
const PROMPT: &str = "response deadline fixture";
const ANSWER: &str = "response deadline answer";
const KEY: &str = "pr01-fixture-key";
const HEADER_HOLD: Duration = Duration::from_millis(11_250);
const WATCHDOG: Duration = Duration::from_secs(45);
const CALL_BOUND: Duration = Duration::from_secs(35);
const SERVER_BOUND: Duration = Duration::from_secs(40);
const JOIN_BOUND: Duration = Duration::from_secs(4);
const POLL: Duration = Duration::from_millis(5);
const READ_POLL: Duration = Duration::from_millis(20);
const REQUEST_BOUND: Duration = Duration::from_secs(3);
const WRITE_BOUND: Duration = Duration::from_secs(2);
const PEER_BOUND: Duration = Duration::from_secs(3);
const MAX_HEADERS: usize = 16 * 1024;
const MAX_BODY: usize = 1024 * 1024;
const MAX_CAPTURE: usize = 2 * 1024 * 1024;

struct Watchdog {
    done: Option<mpsc::Sender<()>>,
    thread: Option<JoinHandle<()>>,
}

impl Watchdog {
    fn start() -> Self {
        let (done, wait) = mpsc::channel();
        let thread = thread::spawn(move || {
            if matches!(
                wait.recv_timeout(WATCHDOG),
                Err(mpsc::RecvTimeoutError::Timeout)
            ) {
                eprintln!("PR01 fixture exceeded independent 45-second watchdog");
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
            let _ = thread.join();
        }
    }
}

struct DoneSignal(mpsc::Sender<()>);

impl Drop for DoneSignal {
    fn drop(&mut self) {
        let _ = self.0.send(());
    }
}

#[derive(Debug, Default)]
struct Evidence {
    connections: usize,
    post_starts: usize,
    full_requests: usize,
    accepted: Option<Duration>,
    captured: Option<Duration>,
    header_attempt: Option<Duration>,
    first_header_byte: Option<Duration>,
    full_headers: Option<Duration>,
    first_body_byte: Option<Duration>,
    terminal: Option<Duration>,
    peer_closed: Option<Duration>,
    peer_close_kind: Option<String>,
    wire_checked: bool,
    capture_notified: bool,
    unexpected_client_bytes: bool,
    publication_error: Option<String>,
    fixture_errors: Vec<String>,
    listener_poll_barrier: bool,
    owned_socket_closed: bool,
    server_joined: bool,
}

fn elapsed(origin: Instant) -> Duration {
    origin.elapsed()
}

fn retryable_read(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut | io::ErrorKind::Interrupted
    )
}

fn accept_extras(listener: &TcpListener, evidence: &mut Evidence) -> Result<(), String> {
    for _ in 0..8 {
        match listener.accept() {
            Ok((mut extra, _)) => {
                evidence.connections += 1;
                evidence
                    .fixture_errors
                    .push("unexpected additional connection".into());
                extra
                    .set_read_timeout(Some(READ_POLL))
                    .map_err(|error| error.to_string())?;
                let mut prefix = [0u8; 5];
                if let Ok(count) = extra.read(&mut prefix)
                    && prefix[..count].starts_with(b"POST ")
                {
                    evidence.post_starts += 1;
                }
                let _ = extra.shutdown(Shutdown::Both);
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(()),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(format!("listener accept: {error}")),
        }
    }
    Err("additional connection bound exceeded".into())
}

fn read_request_part(
    socket: &mut TcpStream,
    output: &mut [u8],
    listener: &TcpListener,
    stop: &AtomicBool,
    deadline: Instant,
    evidence: &mut Evidence,
) -> Result<(), String> {
    let mut offset = 0;
    while offset < output.len() {
        if stop.load(Ordering::SeqCst) || Instant::now() >= deadline {
            return Err("request capture stopped or exceeded three-second bound".into());
        }
        accept_extras(listener, evidence)?;
        match socket.read(&mut output[offset..]) {
            Ok(0) => return Err("peer closed before full request capture".into()),
            Ok(count) => offset += count,
            Err(error) if retryable_read(&error) => {}
            Err(error) => return Err(format!("request read: {error}")),
        }
    }
    Ok(())
}

fn capture_request(
    socket: &mut TcpStream,
    listener: &TcpListener,
    stop: &AtomicBool,
    origin: Instant,
    port: u16,
    evidence: &mut Evidence,
) -> Result<(), String> {
    let deadline = Instant::now() + REQUEST_BOUND;
    let mut headers = Vec::new();
    while !headers.ends_with(b"\r\n\r\n") {
        if headers.len() == MAX_HEADERS {
            return Err("request headers exceed 16 KiB".into());
        }
        let mut byte = [0u8; 1];
        read_request_part(socket, &mut byte, listener, stop, deadline, evidence)?;
        headers.push(byte[0]);
    }
    let headers = std::str::from_utf8(&headers).map_err(|error| error.to_string())?;
    let mut lines = headers.split("\r\n");
    let line = lines.next().ok_or("request line missing")?;
    if line.starts_with("POST ") {
        evidence.post_starts += 1;
    }
    if line != "POST /v1/chat/completions HTTP/1.1" {
        return Err("unexpected request method/path/version".into());
    }
    let mut length = None;
    let mut authorization = None;
    let mut content_type = None;
    let mut host = None;
    for line in lines.filter(|line| !line.is_empty()) {
        let (name, value) = line.split_once(':').ok_or("malformed request header")?;
        let value = value.trim();
        if name.eq_ignore_ascii_case("content-length") {
            if length
                .replace(value.parse::<usize>().map_err(|error| error.to_string())?)
                .is_some()
            {
                return Err("duplicate content length".into());
            }
        } else if name.eq_ignore_ascii_case("authorization") {
            if authorization.replace(value).is_some() {
                return Err("duplicate authorization".into());
            }
        } else if name.eq_ignore_ascii_case("content-type") {
            if content_type.replace(value).is_some() {
                return Err("duplicate content type".into());
            }
        } else if name.eq_ignore_ascii_case("host") {
            if host.replace(value).is_some() {
                return Err("duplicate host".into());
            }
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            return Err("unexpected transfer encoding".into());
        }
    }
    let length = length.ok_or("content length missing")?;
    if length == 0 || length > MAX_BODY {
        return Err("request body outside one-MiB bound".into());
    }
    let expected_authorization = format!("Bearer {KEY}");
    let expected_host = format!("127.0.0.1:{port}");
    if authorization != Some(expected_authorization.as_str())
        || content_type != Some("application/json")
        || host != Some(expected_host.as_str())
    {
        return Err("fixture credential/content type/host mismatch".into());
    }
    let mut body = vec![0u8; length];
    read_request_part(socket, &mut body, listener, stop, deadline, evidence)?;
    evidence.full_requests += 1;
    evidence.captured = Some(elapsed(origin));
    let body: Value = serde_json::from_slice(&body).map_err(|error| error.to_string())?;
    let expected = json!({
        "model": MODEL, "stream": true, "stream_options": {"include_usage": true},
        "max_tokens": 1024, "temperature": 0.7, "top_p": 0.95,
        "messages": [{"role": "user", "content": PROMPT}],
    });
    if body != expected {
        return Err("exact model/prompt/default request controls mismatch".into());
    }
    evidence.wire_checked = true;
    Ok(())
}

fn observe_peer(
    socket: &TcpStream,
    origin: Instant,
    evidence: &mut Evidence,
) -> Result<(), String> {
    if evidence.peer_closed.is_some() {
        return Ok(());
    }
    let mut bytes = [0u8; 64];
    match socket.peek(&mut bytes) {
        Ok(0) => {
            evidence.peer_closed = Some(elapsed(origin));
            evidence.peer_close_kind = Some("eof".into());
        }
        Ok(count) => {
            if !evidence.unexpected_client_bytes {
                evidence.unexpected_client_bytes = true;
                evidence
                    .fixture_errors
                    .push("bytes follow the sole complete request".into());
                if bytes[..count].starts_with(b"POST ") {
                    evidence.post_starts += 1;
                }
            }
        }
        Err(error) if retryable_read(&error) => {}
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::ConnectionReset
                    | io::ErrorKind::BrokenPipe
                    | io::ErrorKind::NotConnected
                    | io::ErrorKind::ConnectionAborted
            ) =>
        {
            evidence.peer_closed = Some(elapsed(origin));
            evidence.peer_close_kind = Some(format!("{:?}", error.kind()));
        }
        Err(error) => return Err(format!("peer-close observation: {error}")),
    }
    Ok(())
}

fn publish_response(
    socket: &mut TcpStream,
    origin: Instant,
    evidence: &mut Evidence,
) -> io::Result<()> {
    let frame = format!(
        "data: {}\n\n",
        json!({
            "choices": [{"index": 0, "delta": {"content": ANSWER}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 11, "completion_tokens": 7, "total_tokens": 18},
        })
    );
    let terminal = b"data: [DONE]\n\n";
    let headers = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        frame.len() + terminal.len()
    );
    evidence.header_attempt = Some(elapsed(origin));
    socket.write_all(&headers.as_bytes()[..1])?;
    evidence.first_header_byte = Some(elapsed(origin));
    socket.write_all(&headers.as_bytes()[1..])?;
    evidence.full_headers = Some(elapsed(origin));
    socket.write_all(&frame.as_bytes()[..1])?;
    evidence.first_body_byte = Some(elapsed(origin));
    socket.write_all(&frame.as_bytes()[1..])?;
    socket.write_all(terminal)?;
    socket.flush()?;
    evidence.terminal = Some(elapsed(origin));
    Ok(())
}

struct ServerOwner {
    listener: TcpListener,
    port: u16,
    delay: Duration,
    origin: Instant,
    stop: Arc<AtomicBool>,
    registered: Arc<Mutex<Option<TcpStream>>>,
    captured: mpsc::Sender<()>,
    stage_done: mpsc::Sender<()>,
    finish: mpsc::Receiver<()>,
}

fn serve(owner: ServerOwner, evidence: &mut Evidence) -> Result<(), String> {
    let ServerOwner {
        listener,
        port,
        delay,
        origin,
        stop,
        registered,
        captured,
        stage_done,
        finish,
    } = owner;
    let stop = stop.as_ref();
    let mut socket = loop {
        if stop.load(Ordering::SeqCst) || origin.elapsed() >= SERVER_BOUND {
            return Err("listener stopped or exceeded forty-second bound".into());
        }
        match listener.accept() {
            Ok((socket, _)) => {
                evidence.connections += 1;
                evidence.accepted = Some(elapsed(origin));
                break socket;
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => thread::park_timeout(POLL),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(format!("first accept: {error}")),
        }
    };
    *registered.lock().unwrap_or_else(|error| error.into_inner()) =
        Some(socket.try_clone().map_err(|error| error.to_string())?);
    socket
        .set_read_timeout(Some(READ_POLL))
        .map_err(|error| error.to_string())?;
    socket
        .set_write_timeout(Some(WRITE_BOUND))
        .map_err(|error| error.to_string())?;
    capture_request(&mut socket, &listener, stop, origin, port, evidence)?;
    captured
        .send(())
        .map_err(|_| "request-capture consumer disappeared")?;
    let captured = evidence.captured.ok_or("captured timestamp missing")?;
    while origin.elapsed().saturating_sub(captured) < delay {
        if stop.load(Ordering::SeqCst) || origin.elapsed() >= SERVER_BOUND {
            return Err("held-header fixture stopped or exceeded live bound".into());
        }
        accept_extras(&listener, evidence)?;
        observe_peer(&socket, origin, evidence)?;
        thread::park_timeout(POLL);
    }
    if stop.load(Ordering::SeqCst) || origin.elapsed() >= SERVER_BOUND {
        return Err("response publication stopped or exceeded live bound".into());
    }
    if let Err(error) = publish_response(&mut socket, origin, evidence) {
        evidence.publication_error = Some(format!("{:?}: {error}", error.kind()));
    } else {
        let _ = socket.shutdown(Shutdown::Write);
    }
    let peer_deadline = Instant::now() + PEER_BOUND;
    while evidence.peer_closed.is_none() {
        if stop.load(Ordering::SeqCst) || Instant::now() >= peer_deadline {
            return Err("peer close missing within three-second bound".into());
        }
        accept_extras(&listener, evidence)?;
        observe_peer(&socket, origin, evidence)?;
        thread::park_timeout(POLL);
    }
    stage_done
        .send(())
        .map_err(|_| "publication/peer-close consumer disappeared")?;
    loop {
        if stop.load(Ordering::SeqCst) || origin.elapsed() >= SERVER_BOUND {
            return Err("listener barrier stopped or exceeded live bound".into());
        }
        accept_extras(&listener, evidence)?;
        match finish.try_recv() {
            Ok(()) => {
                accept_extras(&listener, evidence)?;
                evidence.listener_poll_barrier = true;
                let _ = socket.shutdown(Shutdown::Both);
                evidence.owned_socket_closed = true;
                return Ok(());
            }
            Err(mpsc::TryRecvError::Empty) => thread::park_timeout(POLL),
            Err(mpsc::TryRecvError::Disconnected) => return Err("finish owner disappeared".into()),
        }
    }
}

struct Fixture {
    port: u16,
    origin: Instant,
    stop: Arc<AtomicBool>,
    registered: Arc<Mutex<Option<TcpStream>>>,
    captured: mpsc::Receiver<()>,
    stage_done: mpsc::Receiver<()>,
    done: mpsc::Receiver<()>,
    finish: mpsc::Sender<()>,
    thread: Option<JoinHandle<Evidence>>,
}

impl Fixture {
    fn start(delay: Duration) -> io::Result<Self> {
        let listener = TcpListener::bind(("127.0.0.1", 0))?;
        listener.set_nonblocking(true)?;
        let port = listener.local_addr()?.port();
        let origin = Instant::now();
        let stop = Arc::new(AtomicBool::new(false));
        let registered = Arc::new(Mutex::new(None));
        let (capture_tx, captured) = mpsc::channel();
        let (stage_tx, stage_done) = mpsc::channel();
        let (done_tx, done) = mpsc::channel();
        let (finish, finish_rx) = mpsc::channel();
        let owner = ServerOwner {
            listener,
            port,
            delay,
            origin,
            stop: stop.clone(),
            registered: registered.clone(),
            captured: capture_tx,
            stage_done: stage_tx,
            finish: finish_rx,
        };
        let thread = thread::spawn(move || {
            let _done = DoneSignal(done_tx);
            let mut evidence = Evidence::default();
            if let Err(error) = serve(owner, &mut evidence) {
                evidence.fixture_errors.push(error);
            }
            evidence
        });
        Ok(Self {
            port,
            origin,
            stop,
            registered,
            captured,
            stage_done,
            done,
            finish,
            thread: Some(thread),
        })
    }

    fn close_registered(&self) {
        if let Some(socket) = self
            .registered
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .take()
        {
            let _ = socket.shutdown(Shutdown::Both);
        }
    }

    fn finish(mut self) -> Evidence {
        let remaining = SERVER_BOUND.saturating_sub(self.origin.elapsed());
        let stage_ready = self.stage_done.recv_timeout(remaining).is_ok();
        let barrier_sent = stage_ready && self.finish.send(()).is_ok();
        if !barrier_sent {
            self.stop.store(true, Ordering::SeqCst);
            self.close_registered();
        }
        if self.done.recv_timeout(JOIN_BOUND).is_err() {
            self.stop.store(true, Ordering::SeqCst);
            self.close_registered();
            eprintln!("PR01 owned server failed bounded cleanup join");
            std::process::exit(91);
        }
        self.close_registered();
        let mut evidence = match self.thread.take().expect("owned server handle").join() {
            Ok(evidence) => evidence,
            Err(_) => Evidence {
                fixture_errors: vec!["owned server panicked".into()],
                ..Evidence::default()
            },
        };
        evidence.server_joined = true;
        evidence.capture_notified = self.captured.try_recv().is_ok();
        if !evidence.capture_notified {
            evidence
                .fixture_errors
                .push("request capture notification missing".into());
        }
        if !stage_ready || !barrier_sent {
            evidence
                .fixture_errors
                .push("publication/peer-close or stop/poll barrier incomplete".into());
        }
        evidence
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        if self.thread.is_none() {
            return;
        }
        self.stop.store(true, Ordering::SeqCst);
        self.close_registered();
        if self.done.recv_timeout(JOIN_BOUND).is_err() {
            eprintln!("PR01 abandoned owned server failed bounded cleanup join");
            std::process::exit(91);
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn request(adapter: &dyn AsyncProviderAdapter, port: u16) -> ProviderRequest {
    let identity = adapter.identity();
    canonical_request(
        &ProviderRouteBinding {
            provider_id: ProviderId("fixture".into()),
            deployment_id: DeploymentId("fixture".into()),
            region_id: RegionId("loopback".into()),
            adapter_kind: identity.kind,
            adapter_implementation_digest: identity.implementation_digest,
            adapter_profile_digest: identity.profile_digest,
            endpoint_digest: Sha256Digest("e".repeat(64)),
            expected_model: MODEL.into(),
            pricing_digest: Sha256Digest("r".repeat(64)),
            endpoint_host: "127.0.0.1".into(),
            endpoint_port: port,
            endpoint_scheme: EndpointScheme::HttpLoopback,
            endpoint_path: String::new(),
            endpoint_query: None,
        },
        PROMPT.as_bytes(),
    )
}

#[derive(Debug, Default)]
struct CallOutcome {
    events: Vec<ProviderStreamEvent>,
    error: Option<AdapterError>,
    fixture_error: Option<String>,
}

async fn collect(
    adapter: &dyn AsyncProviderAdapter,
    request: &ProviderRequest,
    secret: &SecretBytes,
    cancel: &CancelToken,
) -> CallOutcome {
    let mut outcome = CallOutcome::default();
    let mut stream = match adapter.invoke(request, Some(secret), cancel).await {
        Ok(stream) => stream,
        Err(error) => {
            outcome.error = Some(error);
            return outcome;
        }
    };
    let mut captured = 0usize;
    while let Some(event) = stream.next().await {
        match event {
            Ok(event) => {
                let encoded = match serde_json::to_vec(&event) {
                    Ok(encoded) => encoded,
                    Err(error) => {
                        outcome.fixture_error = Some(error.to_string());
                        return outcome;
                    }
                };
                captured = captured.saturating_add(encoded.len());
                if captured > MAX_CAPTURE {
                    outcome.fixture_error = Some("captured stream exceeds two MiB".into());
                    return outcome;
                }
                outcome.events.push(event);
            }
            Err(error) => {
                outcome.error = Some(error);
                return outcome;
            }
        }
    }
    outcome
}

fn millis(value: Option<Duration>) -> Option<u64> {
    value.map(|value| value.as_millis() as u64)
}

async fn actual_defaults_case(delay: Duration) {
    let _watchdog = Watchdog::start();
    let adapter = OpenAiCompatibleHttpV1::new(
        openai_identity(),
        openai_capabilities(),
        TlsPinPolicy {
            webpki: false,
            spki_sha256: None,
        },
    )
    .expect("fixture adapter");
    let fixture = Fixture::start(delay).expect("owned loopback listener");
    let request = request(&adapter, fixture.port);
    let actual_defaults = (
        request.connect_timeout_ms,
        request.first_byte_timeout_ms,
        request.idle_timeout_ms,
    );
    let secret = SecretBytes::new(KEY.as_bytes().to_vec());
    let cancel = CancelToken::new();
    let started = fixture.origin;
    let invoke_started = elapsed(started);
    let outcome =
        match tokio::time::timeout(CALL_BOUND, collect(&adapter, &request, &secret, &cancel)).await
        {
            Ok(outcome) => outcome,
            Err(_) => {
                cancel.cancel();
                CallOutcome {
                    fixture_error: Some(
                        "caller exceeded independent 35-second fixture bound".into(),
                    ),
                    ..CallOutcome::default()
                }
            }
        };
    let client_return = elapsed(started);
    let evidence = tokio::task::spawn_blocking(move || fixture.finish())
        .await
        .expect("owned fixture cleanup task joined");
    eprintln!(
        "PR01_EVIDENCE {}",
        json!({
            "defaults_ms": [actual_defaults.0, actual_defaults.1, actual_defaults.2],
            "scheduled_header_hold_ms": delay.as_millis() as u64,
            "accepted_ms": millis(evidence.accepted), "captured_ms": millis(evidence.captured),
            "header_attempt_ms": millis(evidence.header_attempt),
            "first_header_byte_ms": millis(evidence.first_header_byte),
            "full_headers_ms": millis(evidence.full_headers),
            "first_body_byte_ms": millis(evidence.first_body_byte), "terminal_ms": millis(evidence.terminal),
            "invoke_started_ms": invoke_started.as_millis() as u64,
            "client_return_ms": client_return.as_millis() as u64,
            "peer_closed_ms": millis(evidence.peer_closed), "peer_close_kind": &evidence.peer_close_kind,
            "connections": evidence.connections, "post_starts": evidence.post_starts,
            "full_requests": evidence.full_requests, "wire_checked": evidence.wire_checked,
            "capture_notified": evidence.capture_notified,
            "publication_error": &evidence.publication_error, "fixture_errors": &evidence.fixture_errors,
            "server_joined": evidence.server_joined, "listener_poll_barrier": evidence.listener_poll_barrier,
            "owned_socket_closed": evidence.owned_socket_closed,
            "adapter_error": outcome.error.as_ref().map(|error| format!("{error:?}")),
            "fixture_error": &outcome.fixture_error,
            "events": &outcome.events,
        })
    );
    assert!(
        evidence.fixture_errors.is_empty(),
        "fixture failure after owned cleanup: {evidence:?}"
    );
    assert!(
        evidence.server_joined && evidence.listener_poll_barrier && evidence.owned_socket_closed
    );
    assert_eq!(
        actual_defaults,
        (10_000, 30_000, 90_000),
        "actual canonical defaults unchanged"
    );
    assert_eq!(
        (
            evidence.connections,
            evidence.post_starts,
            evidence.full_requests
        ),
        (1, 1, 1)
    );
    assert!(
        evidence.wire_checked && evidence.capture_notified && !evidence.unexpected_client_bytes
    );
    let captured = evidence.captured.expect("full request capture");
    let header_attempt = evidence
        .header_attempt
        .expect("attempted actual header publication");
    let held = header_attempt
        .checked_sub(captured)
        .expect("monotonic capture/header timestamps");
    assert!(
        held >= delay && held < Duration::from_secs(25),
        "fixture hold outside reviewed margin: {held:?}"
    );
    if delay.is_zero() {
        assert!(held < Duration::from_secs(2), "fast fixture was not prompt");
    } else {
        assert!(
            held > Duration::from_millis(10_000),
            "actual hold must cross existing ten-second boundary"
        );
    }
    let peer_closed = evidence
        .peer_closed
        .expect("observed peer EOF/reset before cleanup");
    let expected_old_disconnect = matches!(&outcome.error, Some(AdapterError::ProviderTimeout(_)))
        && peer_closed < header_attempt;
    assert!(
        evidence.publication_error.is_none() || expected_old_disconnect,
        "server publication failed without an observed earlier typed-timeout disconnect: {evidence:?}"
    );
    assert!(
        outcome.fixture_error.is_none(),
        "caller fixture failure: {outcome:?}"
    );
    assert!(
        outcome.error.is_none(),
        "healthy actual-default response must succeed once; actual adapter outcome: {outcome:?}"
    );
    assert!(
        !cancel.is_cancelled(),
        "positive response was not cancelled"
    );
    let first_header = evidence
        .first_header_byte
        .expect("actual first header byte");
    let full_headers = evidence.full_headers.expect("actual full headers");
    let first_body = evidence.first_body_byte.expect("actual first body byte");
    let terminal = evidence.terminal.expect("actual terminal bytes");
    assert!(
        header_attempt <= first_header
            && first_header <= full_headers
            && full_headers <= first_body
            && first_body <= terminal
            && terminal <= peer_closed
    );
    assert!(terminal.saturating_sub(captured) < Duration::from_secs(25));
    assert!(client_return.saturating_sub(invoke_started) < Duration::from_secs(30));
    let usage = ProviderUsage {
        input_tokens: 11,
        output_tokens: 7,
        cache_read_tokens: 0,
        cache_write_tokens: 0,
        reasoning_tokens: 0,
    };
    assert_eq!(
        outcome.events,
        vec![
            ProviderStreamEvent {
                sequence: 0,
                event: ProviderEventKind::ResponseStarted {
                    upstream_request_id: None
                }
            },
            ProviderStreamEvent {
                sequence: 1,
                event: ProviderEventKind::TextDelta {
                    bytes: ANSWER.as_bytes().to_vec()
                }
            },
            ProviderStreamEvent {
                sequence: 2,
                event: ProviderEventKind::UsageUpdate(usage)
            },
            ProviderStreamEvent {
                sequence: 3,
                event: ProviderEventKind::Finished {
                    finish_reason: Some("stop".into()),
                    final_usage: Some(usage)
                }
            },
        ],
        "exact text, usage, sequence and single non-cancelled terminal"
    );
}

#[tokio::test]
async fn openai_actual_defaults_fast_response_succeeds_once() {
    actual_defaults_case(Duration::ZERO).await;
}

#[tokio::test]
async fn openai_actual_defaults_delayed_headers_succeed_once() {
    actual_defaults_case(HEADER_HOLD).await;
}

mod response_phase_tests {
    use super::*;
    use orbit_adapter::types::{AdapterIdentity, AdapterKind};
    use orbit_provider_http::anthropic::{anthropic_capabilities, anthropic_identity};
    use orbit_provider_http::{AnthropicMessagesV1, OllamaHttpV1};

    #[derive(Clone, Copy, Debug)]
    enum Family {
        OpenAi,
        Anthropic,
        Ollama,
    }

    impl Family {
        fn adapter(self) -> Box<dyn AsyncProviderAdapter> {
            match self {
                Self::OpenAi => Box::new(
                    OpenAiCompatibleHttpV1::new(
                        openai_identity(),
                        openai_capabilities(),
                        TlsPinPolicy {
                            webpki: false,
                            spki_sha256: None,
                        },
                    )
                    .unwrap(),
                ),
                Self::Anthropic => Box::new(
                    AnthropicMessagesV1::new(anthropic_identity(), anthropic_capabilities())
                        .unwrap(),
                ),
                Self::Ollama => Box::new(
                    OllamaHttpV1::new(
                        AdapterIdentity {
                            kind: AdapterKind::LocalProcessV1,
                            implementation_digest: Sha256Digest("o".repeat(64)),
                            profile_digest: Sha256Digest("l".repeat(64)),
                        },
                        openai_capabilities(),
                    )
                    .unwrap(),
                ),
            }
        }
        fn request(self, adapter: &dyn AsyncProviderAdapter, port: u16) -> ProviderRequest {
            let mut request = super::request(adapter, port);
            if matches!(self, Self::Ollama) {
                request.route.endpoint_path = "/api".into();
            }
            request
        }
        fn path(self) -> &'static str {
            match self {
                Self::OpenAi => "/v1/chat/completions",
                Self::Anthropic => "/v1/messages",
                Self::Ollama => "/api/chat",
            }
        }
        fn body(self) -> Value {
            match self {
                Self::OpenAi => {
                    json!({"model":MODEL,"stream":true,"stream_options":{"include_usage":true},
                    "max_tokens":1024,"temperature":0.7,"top_p":0.95,"messages":[{"role":"user","content":PROMPT}]})
                }
                Self::Anthropic => json!({"model":MODEL,"stream":true,"max_tokens":1024,
                    "thinking":{"type":"adaptive"},"messages":[{"role":"user","content":[{"type":"text","text":PROMPT}]}]}),
                Self::Ollama => json!({"model":MODEL,"stream":true,
                    "options":{"num_predict":1024,"temperature":0.7,"top_p":0.95},
                    "messages":[{"role":"user","content":PROMPT}]}),
            }
        }
        fn reason(self) -> &'static str {
            if matches!(self, Self::Anthropic) {
                "end_turn"
            } else {
                "stop"
            }
        }
    }

    fn sse(value: Value) -> Vec<u8> {
        format!("data: {value}\n\n").into_bytes()
    }

    fn response_parts(family: Family, pieces: &[&str]) -> Vec<Vec<u8>> {
        let mut parts = Vec::new();
        for (index, piece) in pieces.iter().enumerate() {
            let bytes = match family {
                Family::OpenAi => sse(json!({"choices":[{"index":0,"delta":{"content":piece},"finish_reason":null}]})),
                Family::Anthropic => {
                    let mut bytes = Vec::new();
                    if index == 0 {
                        bytes.extend(sse(json!({"type":"message_start","message":{"id":"phase-fixture",
                            "role":"assistant","content":[],"usage":{"input_tokens":11,"output_tokens":0}}})));
                        bytes.extend(sse(json!({"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}})));
                    }
                    bytes.extend(sse(json!({"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":piece}})));
                    bytes
                }
                Family::Ollama => format!("{}\n", json!({"model":MODEL,"message":{"role":"assistant","content":piece},"done":false})).into_bytes(),
            };
            parts.push(bytes);
        }
        parts.push(match family {
            Family::OpenAi => {
                let mut bytes = sse(json!({"choices":[{"index":0,"delta":{},"finish_reason":"stop"}],
                    "usage":{"prompt_tokens":11,"completion_tokens":7,"total_tokens":18}}));
                bytes.extend_from_slice(b"data: [DONE]\n\n"); bytes
            }
            Family::Anthropic => {
                let mut bytes = sse(json!({"type":"content_block_stop","index":0}));
                bytes.extend(sse(json!({"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":7}})));
                bytes.extend(sse(json!({"type":"message_stop"}))); bytes
            }
            Family::Ollama => format!("{}\n", json!({"model":MODEL,"message":{"role":"assistant","content":""},
                "done":true,"done_reason":"stop","prompt_eval_count":11,"eval_count":7})).into_bytes(),
        });
        parts
    }

    #[derive(Clone, Copy, Debug)]
    enum Case {
        Headers,
        AbsoluteStart,
        Buffered,
        Idle,
        LongStream,
    }

    struct Plan {
        headers: Duration,
        writes: Vec<(Duration, Vec<u8>)>,
    }
    impl Plan {
        fn for_case(family: Family, case: Case) -> Self {
            let ms = Duration::from_millis;
            match case {
                Case::Headers => Self {
                    headers: ms(300),
                    writes: vec![(ms(300), response_parts(family, &[ANSWER]).concat())],
                },
                Case::AbsoluteStart => Self {
                    headers: ms(600),
                    writes: vec![(ms(1200), response_parts(family, &[ANSWER]).concat())],
                },
                Case::Buffered => Self {
                    headers: Duration::ZERO,
                    writes: vec![(Duration::ZERO, response_parts(family, &[ANSWER]).concat())],
                },
                Case::Idle => {
                    let mut parts = response_parts(family, &[ANSWER]).into_iter();
                    Self {
                        headers: Duration::ZERO,
                        writes: vec![
                            (Duration::ZERO, parts.next().unwrap()),
                            (ms(600), parts.next().unwrap()),
                        ],
                    }
                }
                Case::LongStream => Self {
                    headers: Duration::ZERO,
                    writes: response_parts(family, &["a", "b", "c", "d", "e", "f", "g"])
                        .into_iter()
                        .enumerate()
                        .map(|(index, part)| (ms(index as u64 * 150), part))
                        .collect(),
                },
            }
        }
    }

    #[derive(Debug, Default)]
    struct PhaseEvidence {
        attempts: Vec<Duration>,
        completed: Vec<Duration>,
        all_body_published: bool,
        tls_client_hello: bool,
        tls_record_bytes: usize,
    }

    // Reuse the original Fixture owner/Drop/finish, bounded read and extras/peer
    // helpers; the actual-default fixture and both original cases stay intact.
    fn accept_socket(owner: &ServerOwner, evidence: &mut Evidence) -> Result<TcpStream, String> {
        let socket = loop {
            if owner.stop.load(Ordering::SeqCst) || owner.origin.elapsed() >= SERVER_BOUND {
                return Err("phase accept bound".into());
            }
            match owner.listener.accept() {
                Ok((socket, _)) => {
                    evidence.connections += 1;
                    evidence.accepted = Some(owner.origin.elapsed());
                    break socket;
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    thread::park_timeout(POLL)
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error.to_string()),
            }
        };
        *owner
            .registered
            .lock()
            .unwrap_or_else(|error| error.into_inner()) =
            Some(socket.try_clone().map_err(|error| error.to_string())?);
        socket
            .set_read_timeout(Some(READ_POLL))
            .map_err(|error| error.to_string())?;
        socket
            .set_write_timeout(Some(WRITE_BOUND))
            .map_err(|error| error.to_string())?;
        Ok(socket)
    }

    fn capture_family(
        owner: &ServerOwner,
        socket: &mut TcpStream,
        family: Family,
        evidence: &mut Evidence,
    ) -> Result<(), String> {
        if matches!(family, Family::OpenAi) {
            return capture_request(
                socket,
                &owner.listener,
                &owner.stop,
                owner.origin,
                owner.port,
                evidence,
            );
        }
        let deadline = Instant::now() + REQUEST_BOUND;
        let mut raw = Vec::new();
        while !raw.ends_with(b"\r\n\r\n") {
            if raw.len() == MAX_HEADERS {
                return Err("phase header bound".into());
            }
            let mut byte = [0u8; 1];
            read_request_part(
                socket,
                &mut byte,
                &owner.listener,
                &owner.stop,
                deadline,
                evidence,
            )?;
            raw.push(byte[0]);
        }
        let header_text = std::str::from_utf8(&raw).map_err(|error| error.to_string())?;
        let mut lines = header_text.split("\r\n");
        let first = lines.next().ok_or("phase request line")?;
        if first.starts_with("POST ") {
            evidence.post_starts += 1;
        }
        if first != format!("POST {} HTTP/1.1", family.path()) {
            return Err("phase exact method/path/version".into());
        }
        let mut headers = std::collections::BTreeMap::new();
        for line in lines.filter(|line| !line.is_empty()) {
            let (key, value) = line.split_once(':').ok_or("phase header syntax")?;
            let key = key.to_ascii_lowercase();
            if headers.insert(key, value.trim()).is_some() {
                return Err("phase duplicate header".into());
            }
        }
        let host = format!("127.0.0.1:{}", owner.port);
        if headers.get("host").copied() != Some(host.as_str())
            || headers.get("content-type").copied() != Some("application/json")
            || headers.contains_key("transfer-encoding")
        {
            return Err("phase host/type/length framing".into());
        }
        if matches!(family, Family::Anthropic) {
            if headers.get("x-api-key").copied() != Some(KEY)
                || headers.get("anthropic-version").copied() != Some("2023-06-01")
                || headers.contains_key("authorization")
            {
                return Err("phase Anthropic credential/version".into());
            }
        } else if headers.contains_key("authorization") || headers.contains_key("x-api-key") {
            return Err("phase Ollama credential omission".into());
        }
        let length: usize = headers
            .get("content-length")
            .ok_or("phase missing length")?
            .parse()
            .map_err(|_| "phase invalid length")?;
        if length == 0 || length > MAX_BODY {
            return Err("phase body bound".into());
        }
        let mut body = vec![0; length];
        read_request_part(
            socket,
            &mut body,
            &owner.listener,
            &owner.stop,
            deadline,
            evidence,
        )?;
        evidence.full_requests += 1;
        evidence.captured = Some(owner.origin.elapsed());
        if serde_json::from_slice::<Value>(&body).map_err(|error| error.to_string())?
            != family.body()
        {
            return Err("phase exact canonical body".into());
        }
        evidence.wire_checked = true;
        Ok(())
    }

    fn wait_until(
        owner: &ServerOwner,
        socket: &TcpStream,
        evidence: &mut Evidence,
        at: Duration,
    ) -> Result<(), String> {
        while owner.origin.elapsed() < at {
            if owner.stop.load(Ordering::SeqCst) || owner.origin.elapsed() >= SERVER_BOUND {
                return Err("phase scheduled wait bound".into());
            }
            accept_extras(&owner.listener, evidence)?;
            observe_peer(socket, owner.origin, evidence)?;
            thread::park_timeout(POLL);
        }
        Ok(())
    }

    fn finish_socket(
        owner: &ServerOwner,
        socket: &TcpStream,
        evidence: &mut Evidence,
    ) -> Result<(), String> {
        let peer_deadline = Instant::now() + PEER_BOUND;
        while evidence.peer_closed.is_none() {
            if owner.stop.load(Ordering::SeqCst) || Instant::now() >= peer_deadline {
                return Err("phase peer-close bound".into());
            }
            accept_extras(&owner.listener, evidence)?;
            observe_peer(socket, owner.origin, evidence)?;
            thread::park_timeout(POLL);
        }
        owner
            .stage_done
            .send(())
            .map_err(|_| "phase stage owner disappeared")?;
        loop {
            if owner.stop.load(Ordering::SeqCst) || owner.origin.elapsed() >= SERVER_BOUND {
                return Err("phase final barrier bound".into());
            }
            accept_extras(&owner.listener, evidence)?;
            match owner.finish.try_recv() {
                Ok(()) => {
                    accept_extras(&owner.listener, evidence)?;
                    evidence.listener_poll_barrier = true;
                    let _ = socket.shutdown(Shutdown::Both);
                    evidence.owned_socket_closed = true;
                    return Ok(());
                }
                Err(mpsc::TryRecvError::Empty) => thread::park_timeout(POLL),
                Err(mpsc::TryRecvError::Disconnected) => {
                    return Err("phase finish owner disappeared".into());
                }
            }
        }
    }

    fn serve_phase(
        owner: ServerOwner,
        family: Family,
        plan: Plan,
        trace: &Mutex<PhaseEvidence>,
        evidence: &mut Evidence,
    ) -> Result<(), String> {
        let mut socket = accept_socket(&owner, evidence)?;
        capture_family(&owner, &mut socket, family, evidence)?;
        owner
            .captured
            .send(())
            .map_err(|_| "phase capture owner disappeared")?;
        let captured = evidence.captured.ok_or("phase capture timestamp")?;
        wait_until(&owner, &socket, evidence, captured + plan.headers)?;
        let body_len: usize = plan.writes.iter().map(|(_, bytes)| bytes.len()).sum();
        let content_type = if matches!(family, Family::Ollama) {
            "application/x-ndjson"
        } else {
            "text/event-stream"
        };
        let headers = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nContent-Length: {body_len}\r\nConnection: close\r\n\r\n"
        );
        evidence.header_attempt = Some(owner.origin.elapsed());
        let publication = (|| -> Result<(), String> {
            socket
                .write_all(&headers.as_bytes()[..1])
                .map_err(|error| error.to_string())?;
            evidence.first_header_byte = Some(owner.origin.elapsed());
            socket
                .write_all(&headers.as_bytes()[1..])
                .map_err(|error| error.to_string())?;
            evidence.full_headers = Some(owner.origin.elapsed());
            for (index, (delay, bytes)) in plan.writes.iter().enumerate() {
                wait_until(&owner, &socket, evidence, captured + *delay)?;
                trace.lock().unwrap().attempts.push(owner.origin.elapsed());
                if index == 0 {
                    socket
                        .write_all(&bytes[..1])
                        .map_err(|error| error.to_string())?;
                    evidence.first_body_byte = Some(owner.origin.elapsed());
                    socket
                        .write_all(&bytes[1..])
                        .map_err(|error| error.to_string())?;
                } else {
                    socket.write_all(bytes).map_err(|error| error.to_string())?;
                }
                socket.flush().map_err(|error| error.to_string())?;
                trace.lock().unwrap().completed.push(owner.origin.elapsed());
            }
            evidence.terminal = Some(owner.origin.elapsed());
            trace.lock().unwrap().all_body_published = true;
            Ok(())
        })();
        if let Err(error) = publication {
            evidence.publication_error = Some(error);
        } else {
            let _ = socket.shutdown(Shutdown::Write);
        }
        finish_socket(&owner, &socket, evidence)
    }

    fn serve_tls_stall(
        owner: ServerOwner,
        trace: &Mutex<PhaseEvidence>,
        evidence: &mut Evidence,
    ) -> Result<(), String> {
        let mut socket = accept_socket(&owner, evidence)?;
        let deadline = Instant::now() + REQUEST_BOUND;
        let mut header = [0u8; 5];
        read_request_part(
            &mut socket,
            &mut header,
            &owner.listener,
            &owner.stop,
            deadline,
            evidence,
        )?;
        let length = u16::from_be_bytes([header[3], header[4]]) as usize;
        if header[0] != 0x16 || header[1] != 3 || length == 0 || length > MAX_HEADERS {
            return Err("expected bounded actual TLS handshake record".into());
        }
        let mut hello = vec![0; length];
        read_request_part(
            &mut socket,
            &mut hello,
            &owner.listener,
            &owner.stop,
            deadline,
            evidence,
        )?;
        if hello[0] != 1 {
            return Err("expected actual TLS ClientHello".into());
        }
        {
            let mut trace = trace.lock().unwrap();
            trace.tls_client_hello = true;
            trace.tls_record_bytes = header.len() + hello.len();
        }
        evidence.captured = Some(owner.origin.elapsed());
        evidence.wire_checked = true;
        owner
            .captured
            .send(())
            .map_err(|_| "TLS capture owner disappeared")?;
        // Send no ServerHello/certificate/HTTP byte. This observes a real
        // uncompleted TLS handshake, independent of trust-anchor validation.
        finish_socket(&owner, &socket, evidence)
    }

    fn start_phase(
        family: Family,
        plan: Option<Plan>,
    ) -> io::Result<(Fixture, Arc<Mutex<PhaseEvidence>>)> {
        let listener = TcpListener::bind(("127.0.0.1", 0))?;
        listener.set_nonblocking(true)?;
        let port = listener.local_addr()?.port();
        let origin = Instant::now();
        let stop = Arc::new(AtomicBool::new(false));
        let registered = Arc::new(Mutex::new(None));
        let (capture_tx, captured) = mpsc::channel();
        let (stage_tx, stage_done) = mpsc::channel();
        let (done_tx, done) = mpsc::channel();
        let (finish, finish_rx) = mpsc::channel();
        let owner = ServerOwner {
            listener,
            port,
            delay: Duration::ZERO,
            origin,
            stop: stop.clone(),
            registered: registered.clone(),
            captured: capture_tx,
            stage_done: stage_tx,
            finish: finish_rx,
        };
        let trace = Arc::new(Mutex::new(PhaseEvidence::default()));
        let worker_trace = trace.clone();
        let thread = thread::spawn(move || {
            let _done = DoneSignal(done_tx);
            let mut evidence = Evidence::default();
            let result = match plan {
                Some(plan) => serve_phase(owner, family, plan, &worker_trace, &mut evidence),
                None => serve_tls_stall(owner, &worker_trace, &mut evidence),
            };
            if let Err(error) = result {
                evidence.fixture_errors.push(error);
            }
            evidence
        });
        Ok((
            Fixture {
                port,
                origin,
                stop,
                registered,
                captured,
                stage_done,
                done,
                finish,
                thread: Some(thread),
            },
            trace,
        ))
    }

    async fn collect_buffered(
        adapter: &dyn AsyncProviderAdapter,
        request: &ProviderRequest,
        secret: &SecretBytes,
        cancel: &CancelToken,
        origin: Instant,
        sent: Instant,
        trace: &Mutex<PhaseEvidence>,
    ) -> (CallOutcome, Option<Duration>) {
        let mut outcome = CallOutcome::default();
        let mut stream = match adapter.invoke(request, Some(secret), cancel).await {
            Ok(stream) => stream,
            Err(error) => {
                outcome.error = Some(error);
                return (outcome, None);
            }
        };
        match stream.next().await {
            Some(Ok(event)) if matches!(event.event, ProviderEventKind::ResponseStarted { .. }) => {
                outcome.events.push(event)
            }
            Some(Err(error)) => {
                outcome.error = Some(error);
                return (outcome, None);
            }
            _ => {
                outcome.fixture_error =
                    Some("missing synthetic response-start event before consumer pause".into());
                return (outcome, None);
            }
        }
        let published_by = sent + Duration::from_millis(700);
        while !trace.lock().unwrap().all_body_published {
            if Instant::now() >= published_by {
                outcome.fixture_error =
                    Some("body not fully published before consumer deadline margin".into());
                return (outcome, None);
            }
            tokio::time::sleep(POLL).await;
        }
        // No body-bearing stream poll occurs until well after the existing
        // absolute1000ms response-start deadline. Runtime/transport keep running.
        tokio::time::sleep_until(tokio::time::Instant::from_std(
            sent + Duration::from_millis(1500),
        ))
        .await;
        let resumed = origin.elapsed();
        let mut captured = serde_json::to_vec(&outcome.events[0])
            .expect("serializable response start")
            .len();
        while let Some(event) = stream.next().await {
            match event {
                Ok(event) => {
                    let bytes =
                        serde_json::to_vec(&event).expect("bounded serializable provider event");
                    captured = captured.saturating_add(bytes.len());
                    if captured > MAX_CAPTURE {
                        outcome.fixture_error = Some("buffered event capture bound".into());
                        break;
                    }
                    outcome.events.push(event);
                }
                Err(error) => {
                    outcome.error = Some(error);
                    break;
                }
            }
        }
        (outcome, Some(resumed))
    }

    fn assert_closed(evidence: &Evidence, posts: usize) {
        assert!(
            evidence.fixture_errors.is_empty(),
            "phase fixture failure after cleanup: {evidence:?}"
        );
        assert!(
            evidence.server_joined
                && evidence.listener_poll_barrier
                && evidence.owned_socket_closed
        );
        assert_eq!(
            (
                evidence.connections,
                evidence.post_starts,
                evidence.full_requests
            ),
            (1, posts, posts)
        );
        assert!(
            evidence.wire_checked && evidence.capture_notified && !evidence.unexpected_client_bytes
        );
        assert!(evidence.peer_closed.is_some());
    }

    fn assert_success(family: Family, outcome: &CallOutcome, expected: &str) {
        assert!(
            outcome.fixture_error.is_none() && outcome.error.is_none(),
            "desired phase success: {outcome:?}"
        );
        orbit_adapter::stream::validate_stream(&outcome.events).unwrap();
        let text: Vec<u8> = outcome
            .events
            .iter()
            .flat_map(|event| match &event.event {
                ProviderEventKind::TextDelta { bytes } => bytes.as_slice(),
                _ => &[],
            })
            .copied()
            .collect();
        assert_eq!(text, expected.as_bytes());
        let usage = ProviderUsage {
            input_tokens: 11,
            output_tokens: 7,
            cache_read_tokens: 0,
            cache_write_tokens: 0,
            reasoning_tokens: 0,
        };
        let terminals: Vec<_> = outcome
            .events
            .iter()
            .filter_map(|event| match &event.event {
                ProviderEventKind::Finished {
                    finish_reason,
                    final_usage,
                } => Some((finish_reason.as_deref(), *final_usage)),
                _ => None,
            })
            .collect();
        assert_eq!(terminals, vec![(Some(family.reason()), Some(usage))]);
        assert!(outcome.events.iter().all(|event| matches!(
            &event.event,
            ProviderEventKind::ResponseStarted { .. }
                | ProviderEventKind::TextDelta { .. }
                | ProviderEventKind::UsageUpdate(_)
                | ProviderEventKind::Finished { .. }
        )));
    }

    async fn phase_case(family: Family, case: Case) {
        let _watchdog = Watchdog::start();
        let adapter = family.adapter();
        let (fixture, trace) = start_phase(family, Some(Plan::for_case(family, case))).unwrap();
        let mut request = family.request(adapter.as_ref(), fixture.port);
        request.connect_timeout_ms = if matches!(case, Case::AbsoluteStart | Case::Buffered) {
            2000
        } else {
            100
        };
        request.first_byte_timeout_ms = 1000;
        request.idle_timeout_ms = if matches!(case, Case::Idle) { 250 } else { 400 };
        let secret = SecretBytes::new(KEY.as_bytes().to_vec());
        let cancel = CancelToken::new();
        let origin = fixture.origin;
        let sent = Instant::now();
        let sent_at = origin.elapsed();
        let result = tokio::time::timeout(CALL_BOUND, async {
            if matches!(case, Case::Buffered) {
                collect_buffered(
                    adapter.as_ref(),
                    &request,
                    &secret,
                    &cancel,
                    origin,
                    sent,
                    &trace,
                )
                .await
            } else {
                (
                    collect(adapter.as_ref(), &request, &secret, &cancel).await,
                    None,
                )
            }
        })
        .await;
        let returned = origin.elapsed();
        let (outcome, resumed) = match result {
            Ok(outcome) => outcome,
            Err(_) => {
                cancel.cancel();
                (
                    CallOutcome {
                        fixture_error: Some("phase caller35s bound".into()),
                        ..CallOutcome::default()
                    },
                    None,
                )
            }
        };
        let evidence = tokio::task::spawn_blocking(move || fixture.finish())
            .await
            .expect("phase cleanup joined");
        let trace = trace.lock().unwrap();
        eprintln!(
            "PR01_PHASE {family:?}/{case:?} {:?}",
            json!({"sent_ms":sent_at.as_millis(),"returned_ms":returned.as_millis(),
            "consumer_resumed_ms":millis(resumed),"evidence":format!("{evidence:?}"),"trace":format!("{trace:?}"),"outcome":format!("{outcome:?}")})
        );
        assert_closed(&evidence, 1);
        assert!(
            !cancel.is_cancelled() && outcome.fixture_error.is_none(),
            "phase infrastructure: {outcome:?}"
        );
        let captured = evidence.captured.unwrap();
        let header = evidence.header_attempt.unwrap();
        match case {
            Case::Headers => {
                assert!(header >= captured + Duration::from_millis(300));
                assert!(header - sent_at < Duration::from_millis(900));
                assert!(evidence.publication_error.is_none() && trace.all_body_published);
                assert_success(family, &outcome, ANSWER);
            }
            Case::AbsoluteStart | Case::Buffered | Case::Idle => {
                assert!(
                    matches!(outcome.error, Some(AdapterError::ProviderTimeout(_))),
                    "desired phase timeout: {outcome:?}"
                );
                assert!(
                    !outcome
                        .events
                        .iter()
                        .any(|event| matches!(event.event, ProviderEventKind::Finished { .. }))
                );
                let last_attempt = *trace
                    .attempts
                    .last()
                    .expect("actual scheduled body attempt");
                if matches!(case, Case::AbsoluteStart) {
                    assert!(
                        header >= captured + Duration::from_millis(600)
                            && header - sent_at < Duration::from_millis(900)
                    );
                    assert!(
                        last_attempt >= captured + Duration::from_millis(1200)
                            && returned < last_attempt
                    );
                    assert!(outcome.events.iter().any(|event| matches!(
                        event.event,
                        ProviderEventKind::ResponseStarted { .. }
                    )));
                    assert!(
                        !outcome.events.iter().any(|event| matches!(
                            event.event,
                            ProviderEventKind::TextDelta { .. }
                        ))
                    );
                } else if matches!(case, Case::Buffered) {
                    assert!(trace.all_body_published && evidence.publication_error.is_none());
                    assert!(evidence.terminal.unwrap() - sent_at < Duration::from_millis(700));
                    assert!(resumed.unwrap() - sent_at >= Duration::from_millis(1500));
                    assert!(
                        !outcome.events.iter().any(|event| matches!(
                            event.event,
                            ProviderEventKind::TextDelta { .. }
                        ))
                    );
                } else {
                    assert!(
                        last_attempt >= captured + Duration::from_millis(600)
                            && returned < last_attempt
                    );
                    let text: Vec<u8> = outcome
                        .events
                        .iter()
                        .flat_map(|event| match &event.event {
                            ProviderEventKind::TextDelta { bytes } => bytes.as_slice(),
                            _ => &[],
                        })
                        .copied()
                        .collect();
                    assert_eq!(
                        text,
                        ANSWER.as_bytes(),
                        "real partial output before idle expiry"
                    );
                }
                if evidence.publication_error.is_some() {
                    assert!(evidence.peer_closed.unwrap() < last_attempt);
                }
            }
            Case::LongStream => {
                assert!(evidence.publication_error.is_none() && trace.all_body_published);
                assert_eq!(trace.completed.len(), 8);
                assert!(
                    trace
                        .completed
                        .windows(2)
                        .all(|pair| pair[1] - pair[0] < Duration::from_millis(400)),
                    "every actual body publication gap below idle"
                );
                assert!(
                    evidence.terminal.unwrap() - evidence.first_body_byte.unwrap()
                        > Duration::from_millis(1000),
                    "total stream exceeds idle and response-start windows"
                );
                assert_success(family, &outcome, "abcdefg");
            }
        }
    }

    async fn invalid_zero(family: Family, field: usize) {
        let _watchdog = Watchdog::start();
        let adapter = family.adapter();
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let mut request = family.request(adapter.as_ref(), listener.local_addr().unwrap().port());
        request.connect_timeout_ms = 500;
        request.first_byte_timeout_ms = 500;
        request.idle_timeout_ms = 500;
        match field {
            0 => request.connect_timeout_ms = 0,
            1 => request.first_byte_timeout_ms = 0,
            2 => request.idle_timeout_ms = 0,
            _ => unreachable!(),
        }
        let cancel = CancelToken::new();
        let secret = SecretBytes::new(KEY.as_bytes().to_vec());
        let result =
            tokio::time::timeout(CALL_BOUND, adapter.invoke(&request, Some(&secret), &cancel))
                .await;
        let outcome = match result {
            Ok(Err(error)) => Some(error),
            Ok(Ok(stream)) => {
                drop(stream);
                None
            }
            Err(_) => {
                cancel.cancel();
                None
            }
        };
        tokio::time::sleep(Duration::from_millis(50)).await;
        let mut evidence = Evidence::default();
        let accepted = accept_extras(&listener, &mut evidence);
        drop(listener);
        eprintln!("PR01_ZERO {family:?}/{field} {evidence:?} {outcome:?}");
        assert!(accepted.is_ok() && !cancel.is_cancelled());
        assert_eq!(
            (evidence.connections, evidence.post_starts),
            (0, 0),
            "invalid timeout must fail before any connection/POST"
        );
        assert!(
            matches!(outcome, Some(AdapterError::ProviderConfigurationInvalid(_))),
            "invalid timeout is E0401, never retryable E0409"
        );
    }

    async fn tls_handshake_stall(family: Family) {
        let _watchdog = Watchdog::start();
        let adapter = family.adapter();
        let (fixture, trace) = start_phase(family, None).unwrap();
        let mut request = family.request(adapter.as_ref(), fixture.port);
        request.route.endpoint_scheme = EndpointScheme::Https;
        request.connect_timeout_ms = 200;
        request.first_byte_timeout_ms = 2000;
        request.idle_timeout_ms = 1000;
        let secret = SecretBytes::new(KEY.as_bytes().to_vec());
        let cancel = CancelToken::new();
        let started = Instant::now();
        let outcome = tokio::time::timeout(
            CALL_BOUND,
            collect(adapter.as_ref(), &request, &secret, &cancel),
        )
        .await;
        let runtime = started.elapsed();
        if outcome.is_err() {
            cancel.cancel();
        }
        let evidence = tokio::task::spawn_blocking(move || fixture.finish())
            .await
            .expect("TLS cleanup joined");
        let trace = trace.lock().unwrap();
        eprintln!("PR01_TLS {family:?} {runtime:?} {evidence:?} {trace:?} {outcome:?}");
        assert_closed(&evidence, 0);
        assert!(trace.tls_client_hello && trace.tls_record_bytes > 5);
        assert!(evidence.header_attempt.is_none() && evidence.first_body_byte.is_none());
        assert!(!cancel.is_cancelled());
        let outcome = outcome.expect("TLS caller fixture bound");
        assert!(outcome.fixture_error.is_none() && outcome.events.is_empty());
        assert!(
            matches!(&outcome.error,Some(AdapterError::ProviderTimeout(message)) if message.contains("connect")),
            "actual handshake timeout must retain connect class: {outcome:?}"
        );
        assert!(
            runtime >= Duration::from_millis(100) && runtime < Duration::from_millis(1500),
            "short connect budget, long response budget"
        );
    }

    macro_rules! family_tests {
        ($module:ident,$family:expr) => {
            mod $module {
                use super::*;
                #[tokio::test]
                async fn connected_headers_outlive_connect_budget() {
                    phase_case($family, Case::Headers).await;
                }
                #[tokio::test]
                async fn headers_and_first_body_share_one_deadline() {
                    phase_case($family, Case::AbsoluteStart).await;
                }
                #[tokio::test]
                async fn published_body_polled_after_deadline_times_out() {
                    phase_case($family, Case::Buffered).await;
                }
                #[tokio::test]
                async fn partial_output_idle_gap_times_out() {
                    phase_case($family, Case::Idle).await;
                }
                #[tokio::test]
                async fn long_stream_with_short_gaps_succeeds() {
                    phase_case($family, Case::LongStream).await;
                }
                #[tokio::test]
                async fn zero_connect_fails_before_post() {
                    invalid_zero($family, 0).await;
                }
                #[tokio::test]
                async fn zero_response_fails_before_post() {
                    invalid_zero($family, 1).await;
                }
                #[tokio::test]
                async fn zero_idle_fails_before_post() {
                    invalid_zero($family, 2).await;
                }
            }
        };
    }
    family_tests!(openai, Family::OpenAi);
    family_tests!(anthropic, Family::Anthropic);
    family_tests!(ollama, Family::Ollama);
    #[tokio::test]
    async fn openai_actual_tls_handshake_uses_connect_budget() {
        tls_handshake_stall(Family::OpenAi).await;
    }
    #[tokio::test]
    async fn anthropic_actual_tls_handshake_uses_connect_budget() {
        tls_handshake_stall(Family::Anthropic).await;
    }
}
