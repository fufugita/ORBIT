#![cfg(unix)]
#![deny(unsafe_code)]

use orbit_adapter::types::{ChatMessage, ChatRole, ContentBlock, ToolDefinition};
use orbit_engine::{PendingToolCall, ToolExecutor, ToolRoundResult, TurnConfig, TurnOptions};
use orbit_frontend_protocol::FrontendEvent;
use orbit_provider_http::CancelToken;
use serde_json::{Value, json};
use sha2::Digest;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, Instant};

struct Response {
    body: String,
    pause: bool,
}
struct Provider {
    url: String,
    requests: Arc<Mutex<Vec<Value>>>,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
    watchdog: Option<std::sync::mpsc::Sender<()>>,
}
impl Provider {
    fn new(responses: Vec<Response>) -> Self {
        let (watchdog, wait) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            if matches!(
                wait.recv_timeout(Duration::from_secs(15)),
                Err(std::sync::mpsc::RecvTimeoutError::Timeout)
            ) {
                eprintln!("opaque routing fixture exceeded independent watchdog");
                std::process::exit(91);
            }
        });
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let requests = Arc::new(Mutex::new(Vec::new()));
        let captured = requests.clone();
        let stop = Arc::new(AtomicBool::new(false));
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
                        captured.lock().unwrap().push(read_request(&mut stream));
                        let response = responses.next().expect("unexpected provider retry");
                        let length = if response.pause {
                            1_000_000
                        } else {
                            response.body.len()
                        };
                        write!(stream,"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {length}\r\nConnection: close\r\n\r\n{}",response.body).unwrap();
                        stream.flush().unwrap();
                        while response.pause && !stopped.load(Ordering::SeqCst) {
                            let mut byte = [0];
                            match stream.read(&mut byte) {
                                Ok(0) => break,
                                Ok(_) => (),
                                Err(error)
                                    if matches!(
                                        error.kind(),
                                        std::io::ErrorKind::WouldBlock
                                            | std::io::ErrorKind::TimedOut
                                    ) => {}
                                Err(_) => break,
                            }
                        }
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(2))
                    }
                    Err(error) => panic!("provider accept: {error}"),
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
    fn calls(&self) -> Vec<Value> {
        self.requests.lock().unwrap().clone()
    }
    fn config(&self, provider: &str, model: &str) -> TurnConfig {
        TurnConfig {
            provider_id: provider.into(),
            gate: self.url.clone(),
            model: model.into(),
            kind: orbit_engine::ProviderKind::Anthropic,
            credential_env: None,
            pricing: None,
            max_output_tokens: 2048,
            sampling: None,
            effort: None,
            supported_efforts: None,
        }
    }
    fn port(&self) -> u16 {
        url::Url::parse(&self.url).unwrap().port().unwrap()
    }
}
impl Drop for Provider {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            let result = thread.join();
            if !std::thread::panicking() {
                result.unwrap();
            }
        }
        if let Some(done) = self.watchdog.take() {
            let _ = done.send(());
        }
    }
}
fn read_request(stream: &mut TcpStream) -> Value {
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut header = Vec::new();
    while !header.ends_with(b"\r\n\r\n") {
        assert!(header.len() < 16384 && Instant::now() < deadline);
        let mut byte = [0];
        match stream.read(&mut byte) {
            Ok(1) => header.push(byte[0]),
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            other => panic!("request header: {other:?}"),
        }
    }
    let header = String::from_utf8(header).unwrap();
    assert!(
        header.starts_with("POST /v1/messages HTTP/1.1\r\n"),
        "{header}"
    );
    let length: usize = header
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse().unwrap())
        })
        .unwrap();
    assert!(length < 1024 * 1024);
    let mut body = vec![0; length];
    let mut read = 0;
    while read < length {
        assert!(Instant::now() < deadline);
        match stream.read(&mut body[read..]) {
            Ok(0) => panic!("incomplete request body"),
            Ok(count) => read += count,
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            Err(error) => panic!("request body: {error}"),
        }
    }
    serde_json::from_slice(&body).unwrap()
}
struct Home(std::path::PathBuf);
impl Home {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("orbit-opaque-{}", ulid::Ulid::new()));
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::create_dir(path.join("ledger")).unwrap();
        std::fs::set_permissions(path.join("ledger"), std::fs::Permissions::from_mode(0o700))
            .unwrap();
        Self(path)
    }
    fn destinations(&self) -> Vec<(String, u16)> {
        let (records, _) = orbit_ledger::verify_ledger(&self.0.join("ledger")).unwrap();
        records
            .into_iter()
            .filter_map(|record| match record.record.event {
                orbit_ledger::LedgerEvent::EgressIntent(intent) => Some(intent.destinations),
                _ => None,
            })
            .flatten()
            .map(|destination| {
                assert_eq!(destination.host, "127.0.0.1");
                (destination.provider_id, destination.port)
            })
            .collect()
    }
}
impl Drop for Home {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn event(value: Value) -> String {
    format!("data: {value}\n\n")
}
fn message_start() -> String {
    event(json!({"type":"message_start","message":{"usage":{"input_tokens":3,"output_tokens":0}}}))
}
fn thinking_prefix(text: &str, signature: &str) -> String {
    [event(json!({"type":"content_block_start","index":0,"content_block":{"type":"thinking","thinking":""}})),
     event(json!({"type":"content_block_delta","index":0,"delta":{"type":"thinking_delta","thinking":text}})),
     event(json!({"type":"content_block_delta","index":0,"delta":{"type":"signature_delta","signature":signature}})),
     event(json!({"type":"content_block_stop","index":0}))].concat()
}
fn text_events(text: &str) -> String {
    [event(json!({"type":"content_block_start","index":1,"content_block":{"type":"text","text":""}})),
     event(json!({"type":"content_block_delta","index":1,"delta":{"type":"text_delta","text":text}})),
     event(json!({"type":"content_block_stop","index":1}))].concat()
}
fn finish(reason: &str) -> String {
    [event(json!({"type":"message_delta","delta":{"stop_reason":reason},"usage":{"output_tokens":3}})),
     event(json!({"type":"message_stop"}))].concat()
}
fn response(thinking: Option<(&str, &str)>) -> Response {
    Response {
        body: [
            message_start(),
            thinking
                .map(|(text, signature)| thinking_prefix(text, signature))
                .unwrap_or_default(),
            text_events("visible fixture answer"),
            finish("end_turn"),
        ]
        .concat(),
        pause: false,
    }
}
#[derive(Default)]
struct Executor(usize);
impl ToolExecutor for Executor {
    fn execute(&mut self, calls: &[PendingToolCall], _round: u32) -> Vec<ToolRoundResult> {
        self.0 += calls.len();
        calls
            .iter()
            .map(|call| {
                assert_eq!(call.name, "calculator");
                ToolRoundResult {
                    call_id: call.id.clone(),
                    content: "safe tool result".into(),
                }
            })
            .collect()
    }
}
fn options() -> TurnOptions {
    TurnOptions {
        max_attempts: 1,
        ..Default::default()
    }
}
fn run(home: &Home, config: &TurnConfig, transcript: &mut Vec<ChatMessage>, prompt: &str) {
    let mut executor = Executor::default();
    let report = orbit_engine::run_turn(
        &home.0,
        config,
        &options(),
        prompt,
        transcript,
        &mut executor,
        &CancelToken::new(),
        &mut |_| {},
    )
    .unwrap();
    assert!(report.ok && !report.interrupted);
    assert_eq!(executor.0, 0);
}
fn opaque(message: &ChatMessage) -> Value {
    message
        .blocks
        .as_ref()
        .unwrap()
        .iter()
        .find_map(|block| match block {
            ContentBlock::Opaque { json } => Some(serde_json::from_str(json).unwrap()),
            _ => None,
        })
        .unwrap()
}
fn wire_thinking(request: &Value) -> Vec<Value> {
    request["messages"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|message| {
            message["content"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|block| {
                    matches!(
                        block["type"].as_str(),
                        Some("thinking" | "redacted_thinking")
                    )
                })
                .cloned()
        })
        .collect()
}

#[test]
fn opaque_identity_different_model_strips_only_wire_copy() {
    let home = Home::new();
    let provider = Provider::new(vec![
        response(Some(("private fixture a", "fixture-signature-a"))),
        response(None),
    ]);
    let mut transcript = Vec::new();
    run(
        &home,
        &provider.config("provider_a", "model-a"),
        &mut transcript,
        "first",
    );
    assert_eq!(transcript[1].origin_model.as_deref(), Some("model-a"));
    assert_eq!(transcript[1].origin_provider.as_deref(), Some("provider_a"));
    let saved = transcript.clone();
    run(
        &home,
        &provider.config("provider_a", "model-b"),
        &mut transcript,
        "continue",
    );
    let calls = provider.calls();
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[1]["model"], "model-b");
    assert!(wire_thinking(&calls[1]).is_empty());
    assert!(calls[1].to_string().contains("visible fixture answer"));
    assert!(!calls[1].to_string().contains("private fixture a"));
    assert_eq!(&transcript[..saved.len()], saved.as_slice());
    assert_eq!(
        home.destinations(),
        vec![("provider_a".into(), provider.port()); 2]
    );
}

#[test]
fn opaque_identity_same_raw_different_provider_is_foreign() {
    let home = Home::new();
    let a = Provider::new(vec![response(Some((
        "private fixture a",
        "fixture-signature-a",
    )))]);
    let b = Provider::new(vec![response(None)]);
    let mut transcript = Vec::new();
    run(
        &home,
        &a.config("provider_a", "vendor/shared"),
        &mut transcript,
        "first",
    );
    let saved = transcript.clone();
    run(
        &home,
        &b.config("provider_b", "vendor/shared"),
        &mut transcript,
        "continue",
    );
    assert_eq!(a.calls().len(), 1);
    assert_eq!(b.calls().len(), 1);
    assert_eq!(b.calls()[0]["model"], "vendor/shared");
    assert!(wire_thinking(&b.calls()[0]).is_empty());
    assert!(!b.calls()[0].to_string().contains("fixture-signature-a"));
    assert_eq!(&transcript[..saved.len()], saved.as_slice());
    assert_eq!(transcript[1].origin_provider.as_deref(), Some("provider_a"));
    assert_eq!(
        home.destinations(),
        vec![
            ("provider_a".into(), a.port()),
            ("provider_b".into(), b.port())
        ]
    );
}

#[test]
fn opaque_identity_same_pair_retains_exact_thinking_signature() {
    let home = Home::new();
    let provider = Provider::new(vec![
        response(Some(("private same pair", "same-pair-signature"))),
        response(None),
    ]);
    let config = provider.config("provider_a", "vendor/shared");
    let mut transcript = Vec::new();
    run(&home, &config, &mut transcript, "first");
    let saved = transcript.clone();
    let expected = opaque(&transcript[1]);
    run(&home, &config, &mut transcript, "continue");
    assert_eq!(provider.calls().len(), 2);
    assert_eq!(wire_thinking(&provider.calls()[1]), vec![expected]);
    assert!(!provider.calls()[1].to_string().contains("origin_provider"));
    assert!(!provider.calls()[1].to_string().contains("origin_model"));
    assert_eq!(&transcript[..saved.len()], saved.as_slice());
    let plain = transcript.last().unwrap();
    assert!(
        plain.blocks.is_none() && plain.origin_model.is_none() && plain.origin_provider.is_none()
    );
}

#[test]
fn opaque_identity_unproven_legacy_blocks_are_conservatively_stripped() {
    let home = Home::new();
    let provider = Provider::new(vec![response(None)]);
    let legacy: ChatMessage = serde_json::from_value(json!({"role":"assistant","content":"visible legacy",
        "origin_model":"model-a","blocks":[{"type":"opaque","json":"{\"type\":\"thinking\",\"thinking\":\"legacy private\",\"signature\":\"legacy-signature\"}"}]})).unwrap();
    assert!(legacy.origin_provider.is_none());
    assert!(
        serde_json::to_value(&legacy)
            .unwrap()
            .get("origin_provider")
            .is_none()
    );
    let mut missing_model = legacy.clone();
    missing_model.origin_provider = Some("provider_a".into());
    missing_model.origin_model = None;
    let mut transcript = vec![
        orbit_engine::user_message("old"),
        legacy,
        orbit_engine::user_message("other old"),
        missing_model,
    ];
    let saved = transcript.clone();
    run(
        &home,
        &provider.config("provider_a", "model-a"),
        &mut transcript,
        "continue",
    );
    assert_eq!(provider.calls().len(), 1);
    assert!(wire_thinking(&provider.calls()[0]).is_empty());
    assert!(provider.calls()[0].to_string().contains("visible legacy"));
    assert!(!provider.calls()[0].to_string().contains("legacy-signature"));
    assert_eq!(&transcript[..saved.len()], saved.as_slice());
}

fn calculator() -> ToolDefinition {
    let name = "calculator";
    let description = "Fixture calculator";
    let parameters = json!({"type":"object","properties":{"expression":{"type":"string"}},"required":["expression"]});
    let digest = sha2::Sha256::digest(format!("{name}{description}{parameters}").as_bytes());
    ToolDefinition {
        name: name.into(),
        description: description.into(),
        parameters,
        schema_digest: orbit_adapter::types::Sha256Digest(hex::encode(digest)),
    }
}
#[test]
fn opaque_identity_tool_round_preserves_same_pair_then_strips_on_provider_switch() {
    let home = Home::new();
    let tool = Response { body:[message_start(), thinking_prefix("private tool fixture","tool-signature"),
        event(json!({"type":"content_block_start","index":1,"content_block":{"type":"tool_use","id":"fixture-call","name":"calculator","input":{}}})),
        event(json!({"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"{\"expression\":\"1+1\"}"}})),
        event(json!({"type":"content_block_stop","index":1})),finish("tool_use")].concat(),pause:false };
    let a = Provider::new(vec![tool, response(None)]);
    let b = Provider::new(vec![response(None)]);
    let mut transcript = Vec::new();
    let mut executor = Executor::default();
    let options = TurnOptions {
        tools: vec![calculator()],
        user_blocks: Some(vec![
            ContentBlock::Text {
                text: "image and tool fixture".into(),
            },
            ContentBlock::Image {
                data: "iVBORw0KGgo=".into(),
                media_type: "image/png".into(),
            },
        ]),
        ..options()
    };
    let report = orbit_engine::run_turn(
        &home.0,
        &a.config("provider_a", "shared"),
        &options,
        "image and tool fixture",
        &mut transcript,
        &mut executor,
        &CancelToken::new(),
        &mut |_| {},
    )
    .unwrap();
    assert!(report.ok);
    assert_eq!(report.rounds, 2);
    assert_eq!(executor.0, 1);
    let expected = opaque(&transcript[1]);
    assert_eq!(transcript[1].origin_model.as_deref(), Some("shared"));
    assert_eq!(transcript[1].origin_provider.as_deref(), Some("provider_a"));
    assert_eq!(wire_thinking(&a.calls()[1]), vec![expected]);
    let saved = transcript.clone();
    run(
        &home,
        &b.config("provider_b", "shared"),
        &mut transcript,
        "continue",
    );
    let call = &b.calls()[0];
    assert!(wire_thinking(call).is_empty());
    let body = call.to_string();
    assert!(
        body.contains("fixture-call") && body.contains("tool_use") && body.contains("tool_result")
    );
    assert!(body.contains("safe tool result") && body.contains("iVBORw0KGgo="));
    assert!(!body.contains("tool-signature"));
    assert_eq!(&transcript[..saved.len()], saved.as_slice());
    assert_eq!(
        home.destinations(),
        vec![
            ("provider_a".into(), a.port()),
            ("provider_a".into(), a.port()),
            ("provider_b".into(), b.port())
        ]
    );
}

#[test]
fn opaque_identity_cancelled_partial_has_no_provenance_or_replayable_blocks() {
    let home = Home::new();
    let a = Provider::new(vec![Response {
        body: [
            message_start(),
            thinking_prefix("incomplete fixture thought", "partial-signature"),
            text_events("visible partial"),
        ]
        .concat(),
        pause: true,
    }]);
    let b = Provider::new(vec![response(None)]);
    let mut transcript = Vec::new();
    let cancel = CancelToken::new();
    let started = Instant::now();
    let report = orbit_engine::run_turn(
        &home.0,
        &a.config("provider_a", "shared"),
        &options(),
        "cancel fixture",
        &mut transcript,
        &mut Executor::default(),
        &cancel,
        &mut |event| {
            if matches!(&event,FrontendEvent::TextDelta{text} if text.contains("visible partial")) {
                cancel.cancel();
            }
        },
    )
    .unwrap();
    assert!(started.elapsed() < Duration::from_secs(3));
    assert!(report.interrupted && !report.ok);
    let partial = transcript.last().unwrap();
    assert_eq!(partial.role, ChatRole::Assistant);
    assert_eq!(partial.content, "visible partial");
    assert!(
        partial.blocks.is_none()
            && partial.origin_model.is_none()
            && partial.origin_provider.is_none()
    );
    let saved = transcript.clone();
    run(
        &home,
        &b.config("provider_b", "shared"),
        &mut transcript,
        "continue",
    );
    assert_eq!(a.calls().len(), 1);
    assert_eq!(b.calls().len(), 1);
    assert!(wire_thinking(&b.calls()[0]).is_empty());
    assert!(b.calls()[0].to_string().contains("visible partial"));
    assert!(!b.calls()[0].to_string().contains("partial-signature"));
    assert_eq!(&transcript[..saved.len()], saved.as_slice());
}

#[test]
fn direct_dispatch_also_filters_foreign_blocks_without_mutating_the_caller() {
    let home = Home::new();
    let provider = Provider::new(vec![response(None)]);
    let mut foreign = orbit_engine::assistant_message("visible direct history");
    foreign.origin_provider = Some("other_provider".into());
    foreign.origin_model = Some("shared".into());
    foreign.blocks = Some(vec![
        ContentBlock::Opaque {
            json: json!({"type":"redacted_thinking","data":"foreign-redacted-data"}).to_string(),
        },
        ContentBlock::Text {
            text: "kept structured text".into(),
        },
    ]);
    let original = vec![orbit_engine::user_message("old"), foreign];
    let outcome = orbit_engine::dispatch::run_dispatch(
        &home.0,
        &provider.config("provider_a", "shared"),
        "direct",
        Some(original.clone()),
        None,
        CancelToken::new(),
        vec![],
        "opaque-direct",
        "direct-session",
    )
    .unwrap();
    assert_eq!(outcome.output, "visible fixture answer");
    assert_eq!(provider.calls().len(), 1);
    assert!(wire_thinking(&provider.calls()[0]).is_empty());
    assert!(
        provider.calls()[0]
            .to_string()
            .contains("visible direct history")
    );
    assert!(
        !provider.calls()[0]
            .to_string()
            .contains("foreign-redacted-data")
    );
    assert_eq!(original[1].blocks.as_ref().unwrap().len(), 2);
    let mut wire = original.clone();
    assert_eq!(
        orbit_engine::routing::strip_foreign_opaque_blocks_for(&mut wire, "provider_a", "shared"),
        1
    );
    assert_eq!(
        wire[1].blocks,
        Some(vec![ContentBlock::Text {
            text: "kept structured text".into()
        }])
    );
    assert_eq!(
        original[1].origin_provider.as_deref(),
        Some("other_provider")
    );
}
