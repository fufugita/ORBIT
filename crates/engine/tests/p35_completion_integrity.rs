#![deny(unsafe_code)]

use orbit_adapter::types::{ChatMessage, ChatRole};
use orbit_engine::{PendingToolCall, ToolExecutor, ToolRoundResult, TurnConfig, TurnOptions};
use orbit_frontend_protocol::FrontendEvent;
use orbit_provider_http::CancelToken;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, Instant};

struct Response {
    body: String,
    status: u16,
    pause: bool,
}

struct Fixture {
    url: String,
    requests: Arc<Mutex<Vec<serde_json::Value>>>,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
    watchdog: Option<std::sync::mpsc::Sender<()>>,
}

impl Fixture {
    fn new(responses: Vec<Response>) -> Self {
        let (watchdog, wait) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            if matches!(
                wait.recv_timeout(Duration::from_secs(12)),
                Err(std::sync::mpsc::RecvTimeoutError::Timeout)
            ) {
                eprintln!("completion integrity fixture exceeded independent watchdog");
                std::process::exit(91);
            }
        });
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let requests = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let captured = requests.clone();
        let stopped = stop.clone();
        let thread = std::thread::spawn(move || {
            let mut responses = responses.into_iter();
            while !stopped.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        stream
                            .set_read_timeout(Some(Duration::from_millis(100)))
                            .unwrap();
                        stream
                            .set_write_timeout(Some(Duration::from_secs(2)))
                            .unwrap();
                        let request = read_request(&mut stream);
                        captured.lock().unwrap().push(request);
                        let response = responses.next().expect("unexpected provider retry");
                        let len = if response.pause {
                            1_000_000
                        } else {
                            response.body.len()
                        };
                        write!(stream, "HTTP/1.1 {} Fixture\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", response.status, len, response.body).unwrap();
                        stream.flush().unwrap();
                        while response.pause && !stopped.load(Ordering::SeqCst) {
                            let mut byte = [0];
                            match stream.read(&mut byte) {
                                Ok(0) => break,
                                Ok(_) => (),
                                Err(e)
                                    if matches!(
                                        e.kind(),
                                        std::io::ErrorKind::WouldBlock
                                            | std::io::ErrorKind::TimedOut
                                    ) => {}
                                Err(_) => break,
                            }
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(2))
                    }
                    Err(e) => panic!("fixture accept: {e}"),
                }
            }
        });
        Self {
            url,
            requests,
            stop,
            thread: Some(thread),
            watchdog: Some(watchdog),
        }
    }

    fn calls(&self) -> usize {
        self.requests.lock().unwrap().len()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            thread.join().unwrap();
        }
        if let Some(done) = self.watchdog.take() {
            let _ = done.send(());
        }
    }
}

fn read_request(stream: &mut TcpStream) -> serde_json::Value {
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut header = Vec::new();
    while !header.ends_with(b"\r\n\r\n") {
        assert!(header.len() < 16384 && Instant::now() < deadline);
        let mut byte = [0];
        match stream.read(&mut byte) {
            Ok(1) => header.push(byte[0]),
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            other => panic!("request header: {other:?}"),
        }
    }
    let headers = String::from_utf8(header).unwrap();
    assert!(headers.starts_with("POST /"));
    let len: usize = headers
        .lines()
        .find_map(|l| {
            let (name, value) = l.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse().unwrap())
        })
        .unwrap();
    assert!(len < 1024 * 1024);
    let mut body = vec![0; len];
    stream.read_exact(&mut body).unwrap();
    serde_json::from_slice(&body).unwrap()
}

struct Home(std::path::PathBuf);
impl Home {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("orbit-completion-{}", ulid::Ulid::new()));
        std::fs::create_dir_all(path.join("ledger")).unwrap();
        Self(path)
    }
}
impl Drop for Home {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[derive(Default)]
struct Executor(usize);
impl ToolExecutor for Executor {
    fn execute(&mut self, _calls: &[PendingToolCall], _round: u32) -> Vec<ToolRoundResult> {
        self.0 += 1;
        panic!("incomplete tool call must never execute")
    }
}

fn config(fixture: &Fixture) -> TurnConfig {
    TurnConfig {
        sampling: None,
        effort: None,
        supported_efforts: None,
        provider_id: "fixture".into(),
        gate: fixture.url.clone(),
        model: "local-model".into(),
        kind: orbit_engine::ProviderKind::OpenAiCompatible,
        credential_env: Some("ORBIT_COMPLETION_FIXTURE_UNUSED_TOKEN".into()),
        pricing: None,
        max_output_tokens: 2048,
    }
}

fn sse(text: &str, reason: &str) -> Response {
    Response {
        body: format!(
            "data: {}\n\ndata: [DONE]\n\n",
            serde_json::json!({"choices":[{"delta":{"content":text},"finish_reason":reason}]})
        ),
        status: 200,
        pause: false,
    }
}

fn compaction_case(reason: &str, expected_summary: bool) {
    let fixture = Fixture::new(vec![
        sse("summary candidate", reason),
        sse("ordinary answer", "stop"),
    ]);
    let home = Home::new();
    let mut transcript: Vec<ChatMessage> = (0..12)
        .map(|n| orbit_engine::user_message(format!("history-{n}: {}", "preserve ".repeat(50))))
        .collect();
    let original = transcript.clone();
    let options = TurnOptions {
        window_tokens: Some(500),
        output_reserve_tokens: 0,
        max_attempts: 1,
        ..Default::default()
    };
    let mut events = Vec::new();
    let mut executor = Executor::default();
    let report = orbit_engine::run_turn(
        &home.0,
        &config(&fixture),
        &options,
        "latest prompt",
        &mut transcript,
        &mut executor,
        &CancelToken::new(),
        &mut |event| events.push(event),
    )
    .unwrap();
    assert!(report.ok && !report.interrupted);
    assert_eq!(fixture.calls(), 2);
    assert_eq!(executor.0, 0);
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(event, FrontendEvent::Compacted { .. }))
            .count(),
        usize::from(expected_summary)
    );
    assert!(
        !events
            .iter()
            .any(|event| matches!(event, FrontendEvent::OutputTruncated { .. })),
        "housekeeping events stay private"
    );
    if expected_summary {
        assert!(transcript[0].content.contains("summary candidate"));
        assert!(
            !transcript
                .iter()
                .any(|message| message.content == original[0].content)
        );
        let requests = fixture.requests.lock().unwrap();
        let wire = requests[1]["messages"].as_array().unwrap();
        assert_eq!(wire.len(), 7, "one summary plus the newest six messages");
        assert!(
            wire[0]["content"]
                .as_str()
                .unwrap()
                .contains("summary candidate")
        );
        for (actual, expected) in wire[1..6].iter().zip(&original[7..]) {
            assert_eq!(actual["content"], expected.content);
        }
        assert_eq!(wire[6]["content"], "latest prompt");
    } else {
        assert_eq!(
            &transcript[..original.len()],
            original.as_slice(),
            "incomplete compaction cannot replace history"
        );
        let requests = fixture.requests.lock().unwrap();
        assert!(
            requests[1]["messages"]
                .as_array()
                .unwrap()
                .iter()
                .any(|message| message["content"] == original[0].content)
        );
    }
    assert_eq!(transcript.last().unwrap().content, "ordinary answer");
}

#[test]
fn compaction_rejects_length_summary() {
    compaction_case("length", false);
}
#[test]
fn compaction_rejects_max_tokens_summary() {
    compaction_case("max_tokens", false);
}
#[test]
fn compaction_rejects_cancelled_summary() {
    compaction_case("cancelled", false);
}
#[test]
fn compaction_accepts_completed_summary() {
    compaction_case("stop", true);
}

#[test]
fn cancellation_during_compaction_preserves_history_and_skips_main_request() {
    let fixture = Fixture::new(vec![Response {
        body: "".into(),
        status: 200,
        pause: true,
    }]);
    let home = Home::new();
    let mut transcript: Vec<_> = (0..12)
        .map(|n| orbit_engine::user_message(format!("history-{n}: {}", "preserve ".repeat(50))))
        .collect();
    let original = transcript.clone();
    let cancel = CancelToken::new();
    let calls = fixture.requests.clone();
    let cancelling = cancel.clone();
    let cancel_thread = std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(3);
        while calls.lock().unwrap().is_empty() {
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(2));
        }
        cancelling.cancel();
    });
    let mut events = Vec::new();
    let report = orbit_engine::run_turn(
        &home.0,
        &config(&fixture),
        &TurnOptions {
            window_tokens: Some(500),
            output_reserve_tokens: 0,
            max_attempts: 3,
            ..Default::default()
        },
        "latest prompt",
        &mut transcript,
        &mut Executor::default(),
        &cancel,
        &mut |event| events.push(event),
    )
    .unwrap();
    cancel_thread.join().unwrap();
    assert!(report.interrupted && !report.ok);
    assert_eq!(fixture.calls(), 1);
    assert_eq!(&transcript[..original.len()], original.as_slice());
    assert_eq!(transcript.last().unwrap().content, "latest prompt");
    assert!(
        !events
            .iter()
            .any(|event| matches!(event, FrontendEvent::Compacted { .. }))
    );
}

fn partial_case(thinking: bool) {
    let body = if thinking {
        concat!(
            "data: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":3,\"output_tokens\":0}}}\n\n",
            "data: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"thinking\",\"thinking\":\"\"}}\n\n",
            "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"thinking_delta\",\"thinking\":\"incomplete private thought\"}}\n\n",
            "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"signature_delta\",\"signature\":\"partial-signature\"}}\n\n",
            "data: {\"type\":\"content_block_start\",\"index\":1,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n",
            "data: {\"type\":\"content_block_delta\",\"index\":1,\"delta\":{\"type\":\"text_delta\",\"text\":\"visible partial\"}}\n\n"
        )
    } else {
        concat!(
            "data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"unfinished\",\"type\":\"function\",\"function\":{\"name\":\"Bash\",\"arguments\":\"{\\\"command\\\":\"}}]}}]}\n\n",
            "data: {\"choices\":[{\"delta\":{\"content\":\"visible partial\"}}]}\n\n"
        )
    };
    let fixture = Fixture::new(vec![Response {
        body: body.into(),
        status: 200,
        pause: true,
    }]);
    let home = Home::new();
    let mut config = config(&fixture);
    if thinking {
        config.kind = orbit_engine::ProviderKind::Anthropic;
    }
    let cancel = CancelToken::new();
    let mut transcript = Vec::new();
    let mut executor = Executor::default();
    let mut events = Vec::new();
    let started = Instant::now();
    let report = orbit_engine::run_turn(&home.0, &config, &TurnOptions { max_attempts: 3, ..Default::default() }, "interrupt incomplete data", &mut transcript, &mut executor, &cancel, &mut |event| {
        if matches!(&event, FrontendEvent::TextDelta { text } if text.contains("visible partial")) { cancel.cancel(); }
        events.push(event);
    }).unwrap();
    assert!(started.elapsed() < Duration::from_secs(3));
    assert!(report.interrupted && !report.ok);
    assert_eq!(fixture.calls(), 1);
    assert_eq!(executor.0, 0);
    let partial = transcript.last().unwrap();
    assert_eq!(partial.role, ChatRole::Assistant);
    assert_eq!(partial.content, "visible partial");
    assert!(
        partial.tool_calls.is_none() && partial.blocks.is_none() && partial.origin_model.is_none()
    );
    assert!(
        !events
            .iter()
            .any(|event| matches!(event, FrontendEvent::Retrying { .. }))
    );
}

#[test]
fn cancelled_partial_tool_json_is_never_executed_or_replayed() {
    partial_case(false);
}
#[test]
fn cancelled_partial_thinking_is_never_replayed() {
    partial_case(true);
}

#[test]
fn cancellation_during_retry_backoff_never_sends_another_request() {
    let fixture = Fixture::new(vec![Response {
        body: "{\"error\":{\"message\":\"fixture capacity\"}}".into(),
        status: 503,
        pause: false,
    }]);
    let home = Home::new();
    let cancel = CancelToken::new();
    let mut events = Vec::new();
    let report = orbit_engine::run_turn(
        &home.0,
        &config(&fixture),
        &TurnOptions {
            max_attempts: 3,
            ..Default::default()
        },
        "cancel retry",
        &mut Vec::new(),
        &mut Executor::default(),
        &cancel,
        &mut |event| {
            if matches!(event, FrontendEvent::Retrying { .. }) {
                cancel.cancel();
            }
            events.push(event);
        },
    )
    .unwrap();
    assert!(report.interrupted && !report.ok);
    assert_eq!(fixture.calls(), 1);
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(event, FrontendEvent::Retrying { .. }))
            .count(),
        1
    );
}

#[test]
fn pre_cancelled_turn_has_no_provider_request() {
    let fixture = Fixture::new(Vec::new());
    let home = Home::new();
    let cancel = CancelToken::new();
    cancel.cancel();
    let report = orbit_engine::run_turn(
        &home.0,
        &config(&fixture),
        &TurnOptions {
            max_attempts: 3,
            ..Default::default()
        },
        "already cancelled",
        &mut Vec::new(),
        &mut Executor::default(),
        &cancel,
        &mut |_| {},
    )
    .unwrap();
    assert!(report.interrupted && !report.ok);
    assert_eq!(fixture.calls(), 0);
}
