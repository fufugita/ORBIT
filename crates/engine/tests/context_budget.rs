#![deny(unsafe_code)]

use orbit_adapter::types::{ChatMessage, Sha256Digest, ToolDefinition};
use orbit_engine::{
    PendingToolCall, ProviderKind, ToolExecutor, ToolRoundResult, TurnConfig, TurnOptions,
};
use orbit_frontend_protocol::FrontendEvent;
use orbit_provider_http::CancelToken;
use serde_json::{Value, json};
use sha2::Digest;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::DirBuilderExt;
use std::path::PathBuf;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use std::time::{Duration, Instant};

const MAX_HEADERS: usize = 16 * 1024;
const MAX_BODY: usize = 128 * 1024;
const MAX_REQUESTS: usize = 4;
const PAYLOAD_BYTES: usize = 16 * 1024;
const MODEL: &str = "raw-budget-model/unchanged";
const PROMPT: &str = "continue this exact task";
const ANSWER: &str = "fitting ordinary answer";
const TARGET: &str = "POST /tenant/v1/chat/completions?scope=budget-fixture HTTP/1.1";

struct Home(PathBuf);

impl Home {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("orbit-context-budget-{}", ulid::Ulid::new()));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .unwrap();
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(path.join("ledger"))
            .unwrap();
        Self(path)
    }
}

impl Drop for Home {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct CapturedRequest {
    target: String,
    headers: Vec<(String, String)>,
    body: Value,
}

struct Fixture {
    url: String,
    authority: String,
    requests: Arc<Mutex<Vec<CapturedRequest>>>,
    connections: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<Result<(), &'static str>>>,
    watchdog: Option<std::sync::mpsc::Sender<()>>,
    watchdog_thread: Option<std::thread::JoinHandle<()>>,
}

impl Fixture {
    fn new() -> Self {
        let (watchdog, wait) = std::sync::mpsc::channel();
        let watchdog_thread = std::thread::spawn(move || {
            if matches!(
                wait.recv_timeout(Duration::from_secs(20)),
                Err(std::sync::mpsc::RecvTimeoutError::Timeout)
            ) {
                eprintln!("context budget fixture exceeded independent watchdog");
                std::process::exit(91);
            }
        });
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let authority = listener.local_addr().unwrap().to_string();
        let url = format!("http://{authority}/tenant/v1?scope=budget-fixture");
        let requests = Arc::new(Mutex::new(Vec::new()));
        let captured = requests.clone();
        let connections = Arc::new(AtomicUsize::new(0));
        let accepted = connections.clone();
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = stop.clone();
        let thread = std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(15);
            loop {
                if Instant::now() >= deadline {
                    return Err("owned listener deadline");
                }
                match listener.accept() {
                    Ok((mut socket, _)) => {
                        let count = accepted.fetch_add(1, Ordering::SeqCst) + 1;
                        if count > MAX_REQUESTS {
                            return Err("unexpected provider request count");
                        }
                        socket
                            .set_read_timeout(Some(Duration::from_millis(100)))
                            .map_err(|_| "set bounded read timeout")?;
                        socket
                            .set_write_timeout(Some(Duration::from_secs(2)))
                            .map_err(|_| "set bounded write timeout")?;
                        let request = read_request(&mut socket)?;
                        captured.lock().map_err(|_| "capture lock")?.push(request);
                        let body = format!(
                            "data: {}\n\ndata: [DONE]\n\n",
                            json!({
                                "choices":[{"index":0,"delta":{"content":ANSWER},"finish_reason":"stop"}],
                                "usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}
                            })
                        );
                        write!(socket, "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len())
                            .map_err(|_| "write owned response")?;
                        socket.flush().map_err(|_| "flush owned response")?;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        // Drain already queued connections before acknowledging stop.
                        if stopping.load(Ordering::SeqCst) {
                            break;
                        }
                        std::thread::sleep(Duration::from_millis(2));
                    }
                    Err(_) => return Err("owned listener accept"),
                }
            }
            Ok(())
        });
        Self {
            url,
            authority,
            requests,
            connections,
            stop,
            thread: Some(thread),
            watchdog: Some(watchdog),
            watchdog_thread: Some(watchdog_thread),
        }
    }

    fn finish(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            thread
                .join()
                .expect("owned fixture thread panicked")
                .expect("owned fixture must complete without setup/read/write errors");
        }
        if let Some(done) = self.watchdog.take() {
            let _ = done.send(());
        }
        if let Some(thread) = self.watchdog_thread.take() {
            thread.join().unwrap();
        }
        assert_eq!(
            self.connections.load(Ordering::SeqCst),
            self.requests.lock().unwrap().len(),
            "every accepted connection must have a fully parsed bounded request"
        );
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
        if let Some(done) = self.watchdog.take() {
            let _ = done.send(());
        }
        if let Some(thread) = self.watchdog_thread.take() {
            let _ = thread.join();
        }
    }
}

fn read_exact_until(
    socket: &mut TcpStream,
    bytes: &mut [u8],
    deadline: Instant,
) -> Result<(), &'static str> {
    let mut read = 0;
    while read < bytes.len() {
        if Instant::now() >= deadline {
            return Err("owned request read deadline");
        }
        match socket.read(&mut bytes[read..]) {
            Ok(0) => return Err("incomplete owned request"),
            Ok(count) => read += count,
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            Err(_) => return Err("owned request read"),
        }
    }
    Ok(())
}

fn read_request(socket: &mut TcpStream) -> Result<CapturedRequest, &'static str> {
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut raw = Vec::new();
    while !raw.ends_with(b"\r\n\r\n") {
        if raw.len() >= MAX_HEADERS {
            return Err("owned request header bound");
        }
        let mut byte = [0];
        read_exact_until(socket, &mut byte, deadline)?;
        raw.push(byte[0]);
    }
    let raw = std::str::from_utf8(&raw).map_err(|_| "owned header UTF-8")?;
    let mut lines = raw.lines();
    let target = lines
        .next()
        .ok_or("owned request target missing")?
        .to_owned();
    let headers: Vec<(String, String)> = lines
        .filter(|line| !line.is_empty())
        .map(|line| {
            let (name, value) = line.split_once(':').ok_or("owned header separator")?;
            Ok((name.to_ascii_lowercase(), value.trim().to_owned()))
        })
        .collect::<Result<_, &'static str>>()?;
    if headers.iter().any(|(name, _)| name == "transfer-encoding") {
        return Err("owned fixture expects bounded JSON content length");
    }
    let lengths: Vec<&str> = headers
        .iter()
        .filter_map(|(name, value)| (name == "content-length").then_some(value.as_str()))
        .collect();
    if lengths.len() != 1 {
        return Err("owned request requires one content length");
    }
    let length: usize = lengths[0]
        .parse()
        .map_err(|_| "owned request length invalid")?;
    if length > MAX_BODY {
        return Err("owned request body bound");
    }
    let mut body = vec![0; length];
    read_exact_until(socket, &mut body, deadline)?;
    let body = serde_json::from_slice(&body).map_err(|_| "owned request JSON invalid")?;
    Ok(CapturedRequest {
        target,
        headers,
        body,
    })
}

#[derive(Default)]
struct NoEffects(usize);

impl ToolExecutor for NoEffects {
    fn execute(&mut self, _calls: &[PendingToolCall], _round: u32) -> Vec<ToolRoundResult> {
        self.0 += 1;
        panic!("context budget fixture must not execute tools");
    }
}

fn config(fixture: &Fixture) -> TurnConfig {
    TurnConfig {
        provider_id: "context-budget-fixture".into(),
        gate: fixture.url.clone(),
        model: MODEL.into(),
        kind: ProviderKind::OpenAiCompatible,
        credential_env: None,
        pricing: None,
        max_output_tokens: 16,
        sampling: None,
        effort: None,
        supported_efforts: None,
    }
}

fn tools(description: &str) -> Vec<ToolDefinition> {
    let name = "fixture_lookup";
    let tool_description = "read-only owned fixture";
    let parameters = json!({"type":"object","properties":{"query":{"type":"string",
        "description":description}},"required":["query"],"additionalProperties":false});
    let mut bytes = Vec::new();
    bytes.extend_from_slice(name.as_bytes());
    bytes.extend_from_slice(tool_description.as_bytes());
    bytes.extend_from_slice(&serde_json::to_vec(&parameters).unwrap());
    vec![ToolDefinition {
        name: name.into(),
        description: tool_description.into(),
        parameters,
        schema_digest: Sha256Digest(hex::encode(sha2::Sha256::digest(&bytes))),
    }]
}

fn payload(marker: &str) -> String {
    assert!(marker.len() < PAYLOAD_BYTES);
    format!("{marker}{}", "x".repeat(PAYLOAD_BYTES - marker.len()))
}

fn history() -> Vec<ChatMessage> {
    vec![
        orbit_engine::user_message("earlier user intent"),
        orbit_engine::assistant_message("earlier completed answer"),
    ]
}

fn expected_body(system: Option<&str>, tool_definitions: &[ToolDefinition]) -> Value {
    let mut messages = Vec::new();
    if let Some(system) = system {
        messages.push(json!({"role":"system","content":system}));
    }
    messages.extend([
        json!({"role":"user","content":"earlier user intent"}),
        json!({"role":"assistant","content":"earlier completed answer"}),
        json!({"role":"user","content":PROMPT}),
    ]);
    let mut body = json!({"model":MODEL,"stream":true,"stream_options":{"include_usage":true},
        "max_tokens":16,"messages":messages});
    if !tool_definitions.is_empty() {
        body["tool_choice"] = "auto".into();
        body["tools"] = Value::Array(tool_definitions.iter().map(|tool| json!({"type":"function",
            "function":{"name":tool.name,"description":tool.description,"parameters":tool.parameters}})).collect());
    }
    body
}

fn assert_wire(fixture: &Fixture, expected: &Value) {
    let requests = fixture.requests.lock().unwrap();
    for request in requests.iter() {
        assert_eq!(request.target, TARGET);
        assert!(
            request.body == *expected,
            "actual provider JSON must preserve exact selected system/tools/messages/output"
        );
        for name in ["authorization", "x-api-key"] {
            assert!(
                !request.headers.iter().any(|(key, _)| key == name),
                "unconfigured authentication must not reach the owned provider"
            );
        }
        let hosts: Vec<&str> = request
            .headers
            .iter()
            .filter_map(|(name, value)| (name == "host").then_some(value.as_str()))
            .collect();
        assert!(hosts.len() == 1 && hosts[0] == fixture.authority.as_str());
        assert!(
            request
                .headers
                .iter()
                .any(|(name, value)| name == "content-type" && value == "application/json")
        );
    }
}

fn assert_local_refusal_events(events: &[FrontendEvent], error: &str) {
    let errors: Vec<_> = events
        .iter()
        .filter_map(|event| match event {
            FrontendEvent::Error { message } => Some(message.as_str()),
            _ => None,
        })
        .collect();
    assert_eq!(
        errors.len(),
        1,
        "one local refusal must emit exactly one safe Error"
    );
    assert_eq!(errors[0], error);
    assert!(errors[0].len() <= 512);
    let ended: Vec<_> = events
        .iter()
        .filter_map(|event| match event {
            FrontendEvent::TurnEnded {
                ok,
                interrupted,
                rounds,
                input_tokens,
                output_tokens,
                cost_microcents,
            } => Some((
                *ok,
                *interrupted,
                *rounds,
                *input_tokens,
                *output_tokens,
                *cost_microcents,
            )),
            _ => None,
        })
        .collect();
    assert_eq!(
        ended,
        [(false, false, 0, 0, 0, 0)],
        "one failed terminal event must close the started local lifecycle"
    );
}

fn overflow_case(system: Option<String>, tool_definitions: Vec<ToolDefinition>, marker: &str) {
    let home = Home::new();
    let mut fixture = Fixture::new();
    let mut transcript = history();
    let mut expected_history = transcript.clone();
    expected_history.push(orbit_engine::user_message(PROMPT));
    let expected = expected_body(system.as_deref(), &tool_definitions);
    let options = TurnOptions {
        max_rounds: 1,
        max_attempts: 1,
        window_tokens: Some(128),
        output_reserve_tokens: 0,
        system_directive: system,
        tools: tool_definitions,
        session_id: "context-budget-overflow".into(),
        request_stem: "context-budget-overflow".into(),
        ..Default::default()
    };
    let mut executor = NoEffects::default();
    let mut events = Vec::new();
    let result = orbit_engine::run_turn(
        &home.0,
        &config(&fixture),
        &options,
        PROMPT,
        &mut transcript,
        &mut executor,
        &CancelToken::new(),
        &mut |event| events.push(event),
    );
    fixture.finish();
    // If current code sent the omitted payload, establish its actual wire shape
    // before the semantic refusal assertion. Never dump captured headers/body.
    assert_wire(&fixture, &expected);
    assert!(
        result.is_err(),
        "immutable whole-request overflow was not refused; owned provider connections={}",
        fixture.connections.load(Ordering::SeqCst)
    );
    let error = result.unwrap_err();
    assert!(error.len() <= 512, "budget refusal must be bounded");
    let normalized = error.to_ascii_lowercase();
    assert!(
        normalized.contains("budget")
            || normalized.contains("context")
            || normalized.contains("limit"),
        "local refusal must identify the context budget"
    );
    assert!(!error.contains(&fixture.url) && !error.contains(marker));
    assert_local_refusal_events(&events, &error);
    assert_eq!(
        fixture.connections.load(Ordering::SeqCst),
        0,
        "immutable system/tools cannot be reduced by summary and must cause no provider I/O"
    );
    assert_eq!(executor.0, 0);
    assert!(
        transcript == expected_history,
        "all original typed history and the current user intent must survive refusal"
    );
    assert!(!events.iter().any(|event| matches!(
        event,
        FrontendEvent::TextDelta { .. }
            | FrontendEvent::ToolStarted { .. }
            | FrontendEvent::ToolStartedFull { .. }
            | FrontendEvent::Compacted { .. }
    )));
    assert_eq!(
        std::fs::read_dir(home.0.join("ledger")).unwrap().count(),
        0,
        "known immutable overflow must be refused before ledger creation"
    );
}

#[test]
fn context_budget_large_system_refuses_before_any_post() {
    overflow_case(
        Some(payload("IMMUTABLE-SYSTEM-SENTINEL:")),
        Vec::new(),
        "IMMUTABLE-SYSTEM-SENTINEL",
    );
}

#[test]
fn context_budget_large_tools_refuses_before_any_post() {
    overflow_case(
        None,
        tools(&payload("IMMUTABLE-TOOL-SCHEMA-SENTINEL:")),
        "IMMUTABLE-TOOL-SCHEMA-SENTINEL",
    );
}

#[test]
fn context_budget_small_request_sends_once() {
    let home = Home::new();
    let mut fixture = Fixture::new();
    let mut transcript = history();
    let mut expected_history = transcript.clone();
    expected_history.push(orbit_engine::user_message(PROMPT));
    expected_history.push(orbit_engine::assistant_message(ANSWER));
    let tool_definitions = tools("a short fixture query");
    let expected = expected_body(Some("small system sentinel"), &tool_definitions);
    let options = TurnOptions {
        max_rounds: 1,
        max_attempts: 1,
        window_tokens: Some(100_000),
        output_reserve_tokens: 0,
        system_directive: Some("small system sentinel".into()),
        tools: tool_definitions,
        session_id: "context-budget-fitting".into(),
        request_stem: "context-budget-fitting".into(),
        ..Default::default()
    };
    let mut executor = NoEffects::default();
    let mut events = Vec::new();
    let result = orbit_engine::run_turn(
        &home.0,
        &config(&fixture),
        &options,
        PROMPT,
        &mut transcript,
        &mut executor,
        &CancelToken::new(),
        &mut |event| events.push(event),
    );
    fixture.finish();
    assert_wire(&fixture, &expected);
    let report = result.expect("the fitting ordinary request must complete");
    assert!(report.ok && !report.interrupted);
    assert_eq!(report.rounds, 1);
    assert_eq!(report.final_text, ANSWER);
    assert_eq!(
        fixture.connections.load(Ordering::SeqCst),
        1,
        "fitting request must not cause metadata, summary or retry requests"
    );
    assert_eq!(executor.0, 0);
    assert!(
        transcript == expected_history,
        "fitting request must preserve original history and append one answer"
    );
    assert!(!events.iter().any(|event| matches!(
        event,
        FrontendEvent::Compacting { .. }
            | FrontendEvent::Compacted { .. }
            | FrontendEvent::ToolStarted { .. }
            | FrontendEvent::ToolStartedFull { .. }
    )));
    assert!(
        events
            .iter()
            .any(|event| matches!(event, FrontendEvent::TextDelta { text } if text == ANSWER))
    );
}

fn media_policy_case(strict: bool) {
    use orbit_adapter::types::ContentBlock;
    use orbit_engine::context_budget::{MediaPolicy, SelectedBudget};
    let home = Home::new();
    let mut fixture = Fixture::new();
    let config = config(&fixture);
    let blocks = vec![
        ContentBlock::Text {
            text: PROMPT.into(),
        },
        ContentBlock::Image {
            data: "A".repeat(20_000),
            media_type: "image/png".into(),
        },
    ];
    let mut budget = SelectedBudget::legacy_input(&config, 1000).unwrap();
    if strict {
        budget.policy.media_policy = MediaPolicy::Refuse;
    }
    let options = TurnOptions {
        max_rounds: 1,
        max_attempts: 1,
        selected_budget: Some(budget),
        user_blocks: Some(blocks.clone()),
        session_id: "context-budget-media".into(),
        request_stem: "context-budget-media".into(),
        ..Default::default()
    };
    let mut transcript = history();
    let mut expected = transcript.clone();
    let mut user = orbit_engine::user_message(PROMPT);
    user.blocks = Some(blocks);
    expected.push(user);
    let mut executor = NoEffects::default();
    let mut events = Vec::new();
    let result = orbit_engine::run_turn(
        &home.0,
        &config,
        &options,
        PROMPT,
        &mut transcript,
        &mut executor,
        &CancelToken::new(),
        &mut |event| events.push(event),
    );
    fixture.finish();
    assert_eq!(executor.0, 0);
    if strict {
        let error = result.expect_err("strict media policy must refuse");
        assert!(!error.contains(&fixture.url) && !error.contains(PROMPT));
        assert_local_refusal_events(&events, &error);
        assert_eq!(fixture.connections.load(Ordering::SeqCst), 0);
        assert_eq!(transcript, expected);
        assert_eq!(std::fs::read_dir(home.0.join("ledger")).unwrap().count(), 0);
        assert!(
            !events
                .iter()
                .any(|event| matches!(event, FrontendEvent::TextDelta { .. }))
        );
    } else {
        assert!(result.unwrap().ok);
        expected.push(orbit_engine::assistant_message(ANSWER));
        assert_eq!(transcript, expected);
        assert_eq!(fixture.connections.load(Ordering::SeqCst), 1);
        let mut body = expected_body(None, &[]);
        body["messages"][2]["content"] = json!([
            {"type":"text","text":PROMPT},
            {"type":"image_url","image_url":{"url":format!("data:image/png;base64,{}", "A".repeat(20_000))}}
        ]);
        assert_wire(&fixture, &body);
        assert_eq!(events.iter().filter(|event| matches!(event, FrontendEvent::Status { text } if text.contains("unknown") && text.contains("unverified"))).count(), 1);
    }
}

#[test]
fn context_budget_unknown_media_default_preserves_wire_and_warns_once() {
    media_policy_case(false);
}

#[test]
fn context_budget_unknown_media_strict_refuses_before_any_post() {
    media_policy_case(true);
}

#[test]
fn context_budget_invalid_preparation_emits_one_error_and_terminal_event() {
    let home = Home::new();
    let mut fixture = Fixture::new();
    let mut config = config(&fixture);
    config.gate.push('\n');
    let mut transcript = history();
    let mut expected = transcript.clone();
    expected.push(orbit_engine::user_message(PROMPT));
    let mut executor = NoEffects::default();
    let mut events = Vec::new();
    let result = orbit_engine::run_turn(
        &home.0,
        &config,
        &TurnOptions {
            max_rounds: 1,
            max_attempts: 1,
            ..Default::default()
        },
        PROMPT,
        &mut transcript,
        &mut executor,
        &CancelToken::new(),
        &mut |event| events.push(event),
    );
    fixture.finish();
    let error = result.expect_err("invalid raw endpoint must fail during pure preparation");
    assert!(!error.contains(&fixture.url) && !error.contains(PROMPT));
    assert_eq!(fixture.connections.load(Ordering::SeqCst), 0);
    assert_eq!(executor.0, 0);
    assert_eq!(transcript, expected);
    assert_eq!(std::fs::read_dir(home.0.join("ledger")).unwrap().count(), 0);
    assert_local_refusal_events(&events, &error);
}

fn meter_policy_case(dual: bool) {
    use orbit_engine::context_budget::{BudgetCeilings, SelectedBudget};
    let home = Home::new();
    let mut fixture = Fixture::new();
    let mut config = config(&fixture);
    config.max_output_tokens = 1000;
    let mut budget = SelectedBudget::legacy_input(&config, 100_000).unwrap();
    budget.ceilings = BudgetCeilings {
        input_tokens: dual.then_some(100_000),
        combined_tokens: Some(10_000),
        output_tokens: Some(1000),
    };
    let mut events = Vec::new();
    let mut executor = NoEffects::default();
    let mut transcript = history();
    let report = orbit_engine::run_turn(
        &home.0,
        &config,
        &TurnOptions {
            max_rounds: 1,
            max_attempts: 1,
            selected_budget: Some(budget),
            ..Default::default()
        },
        PROMPT,
        &mut transcript,
        &mut executor,
        &CancelToken::new(),
        &mut |event| events.push(event),
    )
    .unwrap();
    fixture.finish();
    assert!(report.ok);
    assert_eq!(executor.0, 0);
    assert_eq!(fixture.connections.load(Ordering::SeqCst), 1);
    let mut expected = expected_body(None, &[]);
    expected["max_tokens"] = json!(1000);
    assert_wire(&fixture, &expected);
    let usage: Vec<_> = events
        .iter()
        .filter_map(|event| match event {
            FrontendEvent::Usage {
                window_tokens,
                breakdown: Some(breakdown),
                ..
            } => Some((*window_tokens, breakdown.reserve, breakdown.compact_at)),
            _ => None,
        })
        .collect();
    assert_eq!(
        usage,
        [(10_000, 1000, 8000)],
        "the visible threshold must equal input+actual-output reaching90% of the combined ceiling"
    );
}

#[test]
fn context_budget_meter_dual_ceilings_uses_binding_combined_policy() {
    meter_policy_case(true);
}

#[test]
fn context_budget_meter_combined_only_uses_actual_output_at_same_threshold() {
    meter_policy_case(false);
}

#[test]
fn context_budget_typed_compacting_event_uses_selected_window() {
    use orbit_engine::context_budget::SelectedBudget;
    let home = Home::new();
    let mut fixture = Fixture::new();
    let config = config(&fixture);
    let budget = SelectedBudget::legacy_input(&config, 1000).unwrap();
    let mut transcript: Vec<_> = (0..12)
        .map(|n| orbit_engine::user_message(format!("history-{n}: {}", "preserve ".repeat(50))))
        .collect();
    let original = transcript.clone();
    let mut events = Vec::new();
    let mut executor = NoEffects::default();
    let report = orbit_engine::run_turn(
        &home.0,
        &config,
        &TurnOptions {
            max_rounds: 1,
            max_attempts: 1,
            selected_budget: Some(budget),
            window_tokens: None,
            ..Default::default()
        },
        PROMPT,
        &mut transcript,
        &mut executor,
        &CancelToken::new(),
        &mut |event| events.push(event),
    )
    .unwrap();
    fixture.finish();
    assert!(report.ok && !report.interrupted);
    assert_eq!(report.final_text, ANSWER);
    assert_eq!(executor.0, 0);
    assert_eq!(fixture.connections.load(Ordering::SeqCst), 2);
    {
        let requests = fixture.requests.lock().unwrap();
        for request in requests.iter() {
            assert_eq!(request.target, TARGET);
            assert_eq!(request.body["model"], MODEL);
            assert_eq!(request.body["max_tokens"], 16);
            assert!(
                !request
                    .headers
                    .iter()
                    .any(|(name, _)| name == "authorization" || name == "x-api-key")
            );
            assert_eq!(
                request
                    .headers
                    .iter()
                    .filter_map(|(name, value)| (name == "host").then_some(value.as_str()))
                    .collect::<Vec<_>>(),
                [fixture.authority.as_str()]
            );
        }
        assert!(serde_json::to_vec(&requests[0].body).unwrap().len() < 3600);
        assert!(serde_json::to_vec(&requests[1].body).unwrap().len() < 3600);
        assert!(requests[0].body.get("tools").is_none());
        let summary_messages = requests[0].body["messages"].as_array().unwrap();
        assert_eq!(summary_messages.len(), 1);
        assert!(
            summary_messages[0]["content"]
                .as_str()
                .unwrap()
                .starts_with("Summarize this conversation for continuation.")
        );
        assert!(
            !summary_messages[0]["content"]
                .as_str()
                .unwrap()
                .contains(PROMPT)
        );
        let mut candidate_messages = vec![
            json!({"role":"user","content":format!("[context compacted from 7 older messages]\n\n{ANSWER}")}),
        ];
        candidate_messages.extend(
            original[7..]
                .iter()
                .map(|message| json!({"role":"user","content":message.content})),
        );
        candidate_messages.push(json!({"role":"user","content":PROMPT}));
        assert_eq!(
            requests[1].body,
            json!({"model":MODEL,"stream":true,"stream_options":{"include_usage":true},"max_tokens":16,"messages":candidate_messages})
        );
    }
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(event, FrontendEvent::Compacted { .. }))
            .count(),
        1
    );
    let windows: Vec<_> = events
        .iter()
        .filter_map(|event| match event {
            FrontendEvent::Compacting { window_tokens, .. } => Some(*window_tokens),
            _ => None,
        })
        .collect();
    assert_eq!(
        windows,
        [1000],
        "typed selected policy must reach the compacting event without a legacy window"
    );
}
