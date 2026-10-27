#![deny(unsafe_code)]

use orbit_adapter::types::{ChatMessage, Sha256Digest, ToolDefinition};
use orbit_engine::{
    PendingToolCall, ProviderKind, ToolExecutor, ToolRoundResult, TurnConfig, TurnOptions,
};
use orbit_frontend_protocol::FrontendEvent;
use orbit_provider_http::CancelToken;

#[path = "support/compaction_journal.rs"]
pub mod compaction_journal;
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
        billing: None,
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
        first_byte_timeout_ms: None,
        idle_timeout_ms: None,
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
        .map(|n| {
            let mut message =
                orbit_engine::user_message(format!("history-{n}: {}", "preserve ".repeat(50)));
            if n % 2 == 1 {
                message.role = orbit_adapter::types::ChatRole::Assistant;
            }
            message
        })
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
            compaction_config: Some(config.clone()),
            compaction_budget: Some(SelectedBudget::legacy_input(&config, 8192).unwrap()),
            session_id: "budget-event-owner".into(),
            journal: Some(compaction_journal::MemoryJournal::fresh(
                "budget-event-owner",
            )),
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
        assert!((serde_json::to_vec(&requests[0].body).unwrap().len() as u64).div_ceil(4) <= 8192);
        assert!((serde_json::to_vec(&requests[1].body).unwrap().len() as u64).div_ceil(4) <= 1000);
        assert!(requests[0].body.get("tools").is_none());
        let summary_text = requests[0].body["messages"].to_string();
        assert!(summary_text.contains("Summarize this conversation for continuation."));
        assert!(!summary_text.contains(PROMPT));
        let candidate = &transcript[..transcript.len() - 1];
        assert_eq!(
            candidate[0],
            orbit_engine::user_message("[Earlier conversation summary: historical data]")
        );
        assert_eq!(candidate[1], orbit_engine::assistant_message(ANSWER));
        assert!(candidate.len() < original.len() + 1);
        assert_eq!(
            &candidate[candidate.len() - 5..candidate.len() - 1],
            &original[8..]
        );
        assert_eq!(
            candidate.last().unwrap(),
            &orbit_engine::user_message(PROMPT)
        );
        assert!(
            original.iter().any(|old| !candidate.contains(old)),
            "some complete old source must be replaced"
        );
        let candidate_messages: Vec<_> = candidate
            .iter()
            .map(|message| json!({"role":message.role.as_str(),"content":message.content}))
            .collect();
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

mod complete_group_compaction_old_api {
    use super::*;
    use orbit_adapter::types::{ChatRole, ContentBlock, ToolCallMessage};

    const WINDOW: u64 = 2000;
    const SUMMARY_WINDOW: u64 = 12000;
    const CURRENT: &str = "CURRENT-INTENT: continue the newest exact exchange";
    const OLD_VISIBLE: &str = "OLD-VISIBLE-STATE-BEYOND-400: preserve the final chosen task state";
    const OLD_RESULT: &str = "OLD-RESULT-STATE-BEYOND-PREFIX: use the complete recorded result";
    const HIDDEN: &str = "PRIVATE-OPAQUE-REASONING-MUST-NOT-BE-PROJECTED";
    const SYSTEM: &str = "Keep the selected continuation and its exact tool identities.";

    fn tool_result(id: &str, text: String) -> ChatMessage {
        ChatMessage {
            role: ChatRole::Tool,
            content: "display fallback, not the raw result".into(),
            tool_call_id: Some(id.into()),
            tool_result: Some(text),
            tool_calls: None,
            blocks: None,
            origin_model: None,
            origin_provider: None,
        }
    }

    fn call(id: &str, query: &str) -> ToolCallMessage {
        ToolCallMessage {
            id: id.into(),
            name: "fixture_lookup".into(),
            arguments: json!({"query":query}).to_string(),
        }
    }

    fn old_group() -> Vec<ChatMessage> {
        let mut requested = orbit_engine::assistant_message("old tool request");
        requested.tool_calls = Some(vec![call("old-call", "old-query")]);
        let visible = format!("{} {OLD_VISIBLE}", "prior visible decision ö ".repeat(30));
        let mut completed = orbit_engine::assistant_message(visible.clone());
        completed.blocks = Some(vec![
            ContentBlock::Text { text: visible },
            ContentBlock::Opaque {
                json:
                    json!({"type":"thinking","thinking":HIDDEN,"signature":"private-old-signature"})
                        .to_string(),
            },
        ]);
        completed.origin_provider = Some("another-exact-provider".into());
        completed.origin_model = Some("another/raw-model".into());
        vec![
            orbit_engine::user_message("OLD-USER-TASK: inspect the earlier complete exchange"),
            requested,
            tool_result(
                "old-call",
                format!("{} {OLD_RESULT}", "older result λ ".repeat(1000)),
            ),
            completed,
        ]
    }

    fn newest_group() -> Vec<ChatMessage> {
        let mut requested =
            orbit_engine::assistant_message("NEWEST-EXCHANGE: four parallel lookups");
        requested.tool_calls = Some(
            (0..4)
                .map(|i| call(&format!("latest-{i}"), &format!("latest query {i} λ")))
                .collect(),
        );
        requested.blocks = Some(vec![ContentBlock::Text {
            text: requested.content.clone(),
        }]);
        requested.origin_provider = Some("context-budget-fixture".into());
        requested.origin_model = Some(MODEL.into());
        let mut completed =
            orbit_engine::assistant_message("NEWEST-COMPLETED-STATE: retain exact typed blocks");
        completed.blocks=Some(vec![
            ContentBlock::Text {text:completed.content.clone()},
            ContentBlock::Opaque {json:json!({"type":"thinking","thinking":HIDDEN,"signature":"private-latest-signature"}).to_string()},
        ]);
        completed.origin_provider = Some("another-exact-provider".into());
        completed.origin_model = Some("another/raw-model".into());
        let mut messages = vec![
            orbit_engine::user_message("KEEP-NEWEST-USER: complete this authoritative exchange"),
            requested,
        ];
        for i in [2, 0, 3, 1] {
            messages.push(tool_result(
                &format!("latest-{i}"),
                format!("LATEST-RESULT-{i}: Unicode λ and exact recorded output"),
            ));
        }
        messages.push(completed);
        messages
    }

    fn current(blocks: &[ContentBlock]) -> ChatMessage {
        let mut message = orbit_engine::user_message(CURRENT);
        message.blocks = Some(blocks.to_vec());
        message
    }

    fn options(config: &TurnConfig, window: u64) -> TurnOptions {
        let mut summary = config.clone();
        summary.provider_id = "exact-summary-provider".into();
        summary.model = "raw-summary-model/unchanged".into();
        summary.max_output_tokens = 37;
        TurnOptions {
            max_rounds: 1,
            max_attempts: 1,
            session_id: "complete-group-owner".into(),
            request_stem: "complete-group-old-api".into(),
            tools: tools("short exact query"),
            user_blocks: Some(vec![ContentBlock::Text {
                text: CURRENT.into(),
            }]),
            system_directive: Some(SYSTEM.into()),
            selected_budget: Some(
                orbit_engine::context_budget::SelectedBudget::legacy_input(config, window).unwrap(),
            ),
            compaction_budget: Some(
                orbit_engine::context_budget::SelectedBudget::legacy_input(
                    &summary,
                    SUMMARY_WINDOW,
                )
                .unwrap(),
            ),
            compaction_config: Some(summary),
            journal: Some(compaction_journal::MemoryJournal::fresh(
                "complete-group-owner",
            )),
            window_tokens: None,
            ..Default::default()
        }
    }

    fn projected_body(
        config: &TurnConfig,
        messages: &[ChatMessage],
        definitions: &[ToolDefinition],
    ) -> Value {
        let route=serde_json::from_value(json!({
            "provider_id":config.provider_id,"deployment_id":"fixture","region_id":"local",
            "adapter_kind":"OpenAiCompatibleHttpV1","adapter_implementation_digest":"implementation",
            "adapter_profile_digest":"profile","endpoint_digest":"endpoint",
            "expected_model":config.model,"pricing_digest":"pricing",
            "endpoint_host":"127.0.0.1","endpoint_port":80,
            "endpoint_scheme":"HttpLoopback","endpoint_path":""
        })).unwrap();
        let mut request = orbit_adapter::conformance::canonical_request(&route, CURRENT.as_bytes());
        let mut wire = messages.to_vec();
        orbit_engine::routing::strip_foreign_opaque_blocks_for(
            &mut wire,
            &config.provider_id,
            &config.model,
        );
        request.messages = Some(wire);
        request.tools = definitions.to_vec();
        request.sampling = orbit_adapter::types::SamplingParameters {
            temperature_milliunits: 0,
            top_p_millionths: 0,
            max_output_tokens: config.max_output_tokens,
        };
        orbit_provider_http::request::render_request_body(
            orbit_provider_http::request::HttpDialect::OpenAiCompatible,
            orbit_provider_http::request::RequestBodyInput::from(&request),
        )
        .unwrap()
        .as_json()
        .clone()
    }

    fn estimate(body: &Value) -> u64 {
        let bytes = serde_json::to_vec(body).unwrap().len() as u64;
        bytes.div_ceil(4)
    }

    fn with_system(messages: &[ChatMessage]) -> Vec<ChatMessage> {
        let mut system = orbit_engine::user_message(SYSTEM);
        system.role = ChatRole::System;
        std::iter::once(system)
            .chain(messages.iter().cloned())
            .collect()
    }

    fn assert_closed_tools(messages: &[Value]) {
        let mut calls = std::collections::BTreeSet::new();
        let mut results = std::collections::BTreeSet::new();
        for message in messages {
            if let Some(items) = message.get("tool_calls").and_then(Value::as_array) {
                for item in items {
                    let id = item["id"].as_str().expect("retained call ID");
                    assert!(
                        !id.is_empty() && calls.insert(id),
                        "retained call IDs must be unique"
                    );
                }
            }
            if message["role"] == "tool" {
                let id = message["tool_call_id"]
                    .as_str()
                    .expect("retained result ID");
                assert!(
                    calls.contains(id),
                    "a retained result cannot precede or outlive its call"
                );
                assert!(
                    results.insert(id),
                    "each retained result matches exactly once"
                );
            }
        }
        assert_eq!(
            calls, results,
            "every retained call is complete in this fixture"
        );
    }

    fn assert_private(events: &[FrontendEvent]) {
        for event in events {
            if let FrontendEvent::TextDelta { text } = event {
                assert!(!text.contains(HIDDEN));
            }
        }
    }

    #[test]
    fn complete_group_compaction_keeps_fitting_newest_parallel_exchange_and_exact_typed_tail() {
        let home = Home::new();
        let mut fixture = Fixture::new();
        let config = config(&fixture);
        let options = options(&config, WINDOW);
        let newest = newest_group();
        let mut transcript = old_group();
        transcript.extend(newest.clone());
        let original = transcript.clone();
        let intent = current(options.user_blocks.as_ref().unwrap());
        let mut full = original.clone();
        full.push(intent.clone());
        let mut required = newest.clone();
        required.push(intent);
        assert!(
            required.len() > 6,
            "the newest complete group crosses the historical fixed-six cut"
        );
        let full_body = projected_body(&config, &with_system(&full), &options.tools);
        assert!(estimate(&full_body) > WINDOW);
        let mut possible = vec![
            orbit_engine::user_message("[Earlier conversation summary: historical data]"),
            orbit_engine::assistant_message(ANSWER),
        ];
        possible.extend(required.clone());
        let possible_body = projected_body(&config, &with_system(&possible), &options.tools);
        assert!(
            estimate(&possible_body) + 256 < WINDOW,
            "one bounded summary plus the complete newest group demonstrably fits"
        );
        let mut executor = NoEffects::default();
        let mut events = Vec::new();
        let result = orbit_engine::run_turn(
            &home.0,
            &config,
            &options,
            CURRENT,
            &mut transcript,
            &mut executor,
            &CancelToken::new(),
            &mut |event| events.push(event),
        );
        fixture.finish();
        assert_eq!(executor.0, 0);
        let report=result.unwrap_or_else(|error|panic!("a fitting complete newest exchange must compact successfully rather than be blanket-refused; accepted={} parsed={}; error={error}",fixture.connections.load(Ordering::SeqCst),fixture.requests.lock().unwrap().len()));
        assert!(report.ok && !report.interrupted);
        assert_eq!(report.final_text, ANSWER);
        let requests = fixture.requests.lock().unwrap();
        assert_eq!(
            requests.len(),
            2,
            "one fitting older-group summary, then one ordinary continuation"
        );
        let summary = &requests[0].body;
        assert_eq!(summary["model"], "raw-summary-model/unchanged");
        assert_eq!(summary["max_tokens"], 37);
        assert!(summary.get("tools").is_none());
        assert!(summary.get("reasoning_effort").is_none());
        assert!(estimate(summary) <= SUMMARY_WINDOW);
        let summary_text = serde_json::to_string(summary).unwrap();
        assert!(
            summary_text.contains(OLD_VISIBLE) && summary_text.contains(OLD_RESULT),
            "safe older visible task state must survive beyond former 400/200-byte prefixes"
        );
        assert!(
            summary_text.contains("old-call")
                && summary_text.contains("fixture_lookup")
                && summary_text.contains("old-query")
        );
        assert!(
            !summary_text.contains(HIDDEN)
                && !summary_text.contains("private-old-signature")
                && !summary_text.contains("private-latest-signature")
        );
        assert!(!summary_text.contains(CURRENT) && !summary_text.contains("KEEP-NEWEST-USER"));
        let main = &requests[1].body;
        assert_eq!(main["model"], MODEL);
        assert_eq!(main["max_tokens"], 16);
        assert!(main["tools"].is_array());
        assert!(estimate(main) <= WINDOW);
        let main_messages = main["messages"].as_array().unwrap();
        assert_closed_tools(main_messages);
        let expected = projected_body(&config, &required, &options.tools);
        let expected = expected["messages"].as_array().unwrap();
        assert!(main_messages.len() >= expected.len());
        assert_eq!(
            &main_messages[main_messages.len() - expected.len()..],
            expected.as_slice()
        );
        assert!(!serde_json::to_string(main).unwrap().contains(HIDDEN));
        assert_eq!(transcript.last().unwrap().content, ANSWER);
        let retained_end = transcript.len() - 1;
        assert!(retained_end >= required.len());
        assert_eq!(
            &transcript[retained_end - required.len()..retained_end],
            required.as_slice(),
            "retained blocks, raw tool results, IDs and origin fields must remain byte-for-byte equal"
        );
        assert!(!transcript.iter().any(|message| message == &original[0]));
        assert_eq!(
            events
                .iter()
                .filter(|event| matches!(event, FrontendEvent::Compacted { .. }))
                .count(),
            1
        );
        assert_eq!(
            events
                .iter()
                .filter(|event| matches!(event, FrontendEvent::TextDelta { .. }))
                .count(),
            1,
            "summary deltas stay private even when the fixture reply matches ordinary text"
        );
        assert_private(&events);
        for request in requests.iter() {
            assert_eq!(request.target, TARGET);
            assert!(
                !request
                    .headers
                    .iter()
                    .any(|(name, _)| name == "authorization" || name == "x-api-key")
            );
        }
    }

    #[test]
    fn complete_group_already_fits_without_compaction_and_keeps_original_typed_history() {
        let home = Home::new();
        let mut fixture = Fixture::new();
        let config = config(&fixture);
        let options = options(&config, 10000);
        let mut transcript = newest_group();
        let mut expected = transcript.clone();
        expected.push(current(options.user_blocks.as_ref().unwrap()));
        let expected_body = projected_body(&config, &with_system(&expected), &options.tools);
        assert!(estimate(&expected_body) < 9000);
        let mut executor = NoEffects::default();
        let mut events = Vec::new();
        let result = orbit_engine::run_turn(
            &home.0,
            &config,
            &options,
            CURRENT,
            &mut transcript,
            &mut executor,
            &CancelToken::new(),
            &mut |event| events.push(event),
        );
        fixture.finish();
        assert!(result.unwrap().ok);
        assert_eq!(executor.0, 0);
        assert_eq!(&transcript[..expected.len()], expected.as_slice());
        let requests = fixture.requests.lock().unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].body, expected_body);
        assert_closed_tools(requests[0].body["messages"].as_array().unwrap());
        assert!(!events.iter().any(|event| matches!(
            event,
            FrontendEvent::Compacting { .. } | FrontendEvent::Compacted { .. }
        )));
        assert_private(&events);
    }

    fn refusal_control(mut newest: Vec<ChatMessage>, oversized_intent: bool, media: bool) {
        let home = Home::new();
        let mut fixture = Fixture::new();
        let config = config(&fixture);
        let mut options = options(&config, WINDOW);
        let prompt = if oversized_intent {
            "CURRENT-TOO-LARGE ".repeat(1000)
        } else {
            CURRENT.into()
        };
        let mut blocks = vec![ContentBlock::Text {
            text: prompt.clone(),
        }];
        if media {
            blocks.push(ContentBlock::Image {data:"iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=".into(),media_type:"image/png".into()});
            options
                .selected_budget
                .as_mut()
                .unwrap()
                .policy
                .media_policy = orbit_engine::context_budget::MediaPolicy::Refuse;
        }
        options.user_blocks = Some(blocks.clone());
        let mut transcript = old_group();
        transcript.append(&mut newest);
        let mut expected = transcript.clone();
        let mut intent = orbit_engine::user_message(prompt.clone());
        intent.blocks = Some(blocks);
        expected.push(intent);
        let mut executor = NoEffects::default();
        let mut events = Vec::new();
        let result = orbit_engine::run_turn(
            &home.0,
            &config,
            &options,
            &prompt,
            &mut transcript,
            &mut executor,
            &CancelToken::new(),
            &mut |event| events.push(event),
        );
        fixture.finish();
        let error =
            result.expect_err("protected malformed or immutable history must refuse locally");
        assert!(error.len() <= 512 && !error.contains(&fixture.url) && !error.contains(HIDDEN));
        if media {
            let lower = error.to_ascii_lowercase();
            assert!(
                lower.contains("context budget")
                    || (lower.contains("media") && lower.contains("policy")),
                "strict-media control requires a policy refusal, not an incidental image/render error"
            );
        }
        assert_eq!(fixture.connections.load(Ordering::SeqCst), 0);
        assert!(fixture.requests.lock().unwrap().is_empty());
        assert_eq!(executor.0, 0);
        assert_eq!(transcript, expected);
        assert!(!events.iter().any(|event| matches!(
            event,
            FrontendEvent::Compacting { .. }
                | FrontendEvent::Compacted { .. }
                | FrontendEvent::TextDelta { .. }
        )));
    }

    #[test]
    fn complete_group_missing_tool_result_id_refuses_without_post_or_history_repair() {
        let mut group = newest_group();
        group[2].tool_call_id = None;
        refusal_control(group, false, false);
    }

    #[test]
    fn complete_group_duplicate_call_identity_refuses_without_post_or_history_repair() {
        let mut group = newest_group();
        group[1].tool_calls.as_mut().unwrap()[1].id = "latest-0".into();
        refusal_control(group, false, false);
    }

    #[test]
    fn complete_group_unmatched_result_identity_refuses_without_post_or_history_repair() {
        let mut group = newest_group();
        group[2].tool_call_id = Some("unmatched-result".into());
        refusal_control(group, false, false);
    }

    #[test]
    fn complete_group_missing_parallel_result_refuses_without_post_or_history_repair() {
        let mut group = newest_group();
        group.remove(2);
        refusal_control(group, false, false);
    }

    #[test]
    fn complete_group_immutable_current_intent_overflow_refuses_before_summary() {
        refusal_control(newest_group(), true, false);
    }

    #[test]
    fn complete_group_explicit_strict_media_control_refuses_without_dropping_typed_blocks() {
        refusal_control(newest_group(), false, true);
    }

    #[test]
    fn complete_group_missing_journal_refuses_without_provider_effect_or_history_loss() {
        let home = Home::new();
        let mut fixture = Fixture::new();
        let config = config(&fixture);
        let mut options = options(&config, WINDOW);
        options.journal = None;
        let mut transcript = old_group();
        transcript.extend(newest_group());
        let mut expected = transcript.clone();
        expected.push(current(options.user_blocks.as_ref().unwrap()));
        let mut executor = NoEffects::default();
        let mut events = Vec::new();
        let error = orbit_engine::run_turn(
            &home.0,
            &config,
            &options,
            CURRENT,
            &mut transcript,
            &mut executor,
            &CancelToken::new(),
            &mut |e| events.push(e),
        )
        .expect_err("compaction requires an explicit archive/accounting journal");
        fixture.finish();
        assert!(error.len() <= 512);
        assert!(error.to_ascii_lowercase().contains("journal"));
        assert_eq!(fixture.connections.load(Ordering::SeqCst), 0);
        assert!(fixture.requests.lock().unwrap().is_empty());
        assert_eq!(transcript, expected);
        assert_eq!(executor.0, 0);
        assert!(!events.iter().any(|e| matches!(
            e,
            FrontendEvent::Compacting { .. }
                | FrontendEvent::Compacted { .. }
                | FrontendEvent::TextDelta { .. }
        )));
    }

    mod service_old_public_api {
        use super::*;

        const SELECTED_INPUT: u64 = 1000;
        const FULL_TEXT_SENTINEL: &str = "FULL-OLDER-TASK-STATE-AFTER-400-BYTES";
        const CHUNK_A: &str = "WHOLE-GROUP-A-STATE-AT-END";
        const CHUNK_B: &str = "WHOLE-GROUP-B-STATE-AT-END";

        struct Observed {
            bodies: Vec<Value>,
            events: Vec<FrontendEvent>,
        }

        fn append_pair(source: &mut Vec<ChatMessage>, label: &str, bytes: usize, end: &str) {
            source.push(orbit_engine::user_message(format!(
                "{label} user: {} {end}",
                "u".repeat(bytes)
            )));
            source.push(orbit_engine::assistant_message(format!(
                "{label} assistant: {} {end}",
                "a".repeat(bytes)
            )));
        }

        fn append_recent(source: &mut Vec<ChatMessage>) {
            // Three recent completed pairs also leave the current fixed-six path
            // with an exact newest-two-pairs/current-intent suffix on the baseline.
            for index in 0..3 {
                append_pair(
                    source,
                    &format!("recent-{index}"),
                    0,
                    "exact recent state λ",
                );
            }
        }

        fn summary_witness(config: &TurnConfig, source: &[ChatMessage]) -> Value {
            let prompt = format!(
                "Summarize this conversation for continuation. Keep the complete visible task state, decisions and open work. Historical JSON data follows.\n{}",
                serde_json::to_string(source).unwrap()
            );
            projected_body(config, &[orbit_engine::user_message(prompt)], &[])
        }

        fn run_success(source: Vec<ChatMessage>, summary_window: u64) -> Observed {
            let home = Home::new();
            let mut fixture = Fixture::new();
            let config = config(&fixture);
            let mut options = options(&config, SELECTED_INPUT);
            let summary = options.compaction_config.as_ref().unwrap();
            options.compaction_budget = Some(
                orbit_engine::context_budget::SelectedBudget::legacy_input(summary, summary_window)
                    .unwrap(),
            );
            let intent = current(options.user_blocks.as_ref().unwrap());
            let mut original_with_intent = source.clone();
            original_with_intent.push(intent.clone());
            let before = estimate(&projected_body(
                &config,
                &with_system(&original_with_intent),
                &options.tools,
            ));
            assert!(
                before > SELECTED_INPUT,
                "the real whole request must require compaction"
            );
            let mut required = source[source.len() - 4..].to_vec();
            required.push(intent);
            let mut witness = vec![
                orbit_engine::user_message("[Earlier conversation summary: historical data]"),
                orbit_engine::assistant_message(ANSWER),
            ];
            witness.extend(required.clone());
            assert!(
                estimate(&projected_body(
                    &config,
                    &with_system(&witness),
                    &options.tools
                )) + 256
                    < SELECTED_INPUT,
                "a complete required suffix plus bounded summary demonstrably fits",
            );
            let mut transcript = source;
            let mut executor = NoEffects::default();
            let mut events = Vec::new();
            let result = orbit_engine::run_turn(
                &home.0,
                &config,
                &options,
                CURRENT,
                &mut transcript,
                &mut executor,
                &CancelToken::new(),
                &mut |event| events.push(event),
            );
            fixture.finish();
            assert_eq!(executor.0, 0);
            let report = result.unwrap_or_else(|error| panic!(
            "the fitting text-only fixture must complete; accepted={} parsed={}; error={error}",
            fixture.connections.load(Ordering::SeqCst), fixture.requests.lock().unwrap().len(),
        ));
            assert!(report.ok && !report.interrupted);
            assert_eq!(report.final_text, ANSWER);
            let captured = fixture.requests.lock().unwrap();
            assert!(captured.len() >= 2 && captured.len() <= MAX_REQUESTS);
            for (index, request) in captured.iter().enumerate() {
                assert_eq!(request.target, TARGET);
                for name in ["authorization", "x-api-key"] {
                    assert!(!request.headers.iter().any(|(key, _)| key == name));
                }
                let hosts: Vec<_> = request
                    .headers
                    .iter()
                    .filter_map(|(key, value)| (key == "host").then_some(value.as_str()))
                    .collect();
                assert_eq!(hosts, [fixture.authority.as_str()]);
                assert!(
                    request
                        .headers
                        .iter()
                        .any(|(key, value)| key == "content-type" && value == "application/json")
                );
                if index + 1 < captured.len() {
                    assert_eq!(request.body["model"], "raw-summary-model/unchanged");
                    assert_eq!(request.body["max_tokens"], 37);
                    assert!(request.body.get("tools").is_none());
                    assert!(request.body.get("reasoning_effort").is_none());
                    assert!(estimate(&request.body) <= summary_window);
                    assert!(
                        !serde_json::to_string(&request.body["messages"])
                            .unwrap()
                            .contains(CURRENT)
                    );
                }
            }
            let main = &captured.last().unwrap().body;
            assert_eq!(main["model"], MODEL);
            assert_eq!(main["max_tokens"], 16);
            assert!(main["tools"].is_array());
            assert!(estimate(main) <= SELECTED_INPUT);
            let expected = projected_body(&config, &required, &options.tools);
            let expected_messages = expected["messages"].as_array().unwrap();
            let actual_messages = main["messages"].as_array().unwrap();
            assert!(actual_messages.len() >= expected_messages.len());
            assert_eq!(
                &actual_messages[actual_messages.len() - expected_messages.len()..],
                expected_messages.as_slice(),
            );
            let end = transcript.len() - 1;
            assert_eq!(transcript[end].content, ANSWER);
            assert!(end >= required.len());
            assert_eq!(&transcript[end - required.len()..end], required.as_slice());
            let compacted: Vec<_> = events
                .iter()
                .filter_map(|event| match event {
                    FrontendEvent::Compacted { after_tokens, .. } => Some(*after_tokens),
                    _ => None,
                })
                .collect();
            assert_eq!(
                compacted.len(),
                1,
                "the fitting candidate must actually be applied"
            );
            assert!(compacted[0] > 0 && compacted[0] <= SELECTED_INPUT && compacted[0] < before);
            let visible: Vec<_> = events
                .iter()
                .filter_map(|event| match event {
                    FrontendEvent::TextDelta { text } => Some(text.as_str()),
                    _ => None,
                })
                .collect();
            assert_eq!(
                visible,
                [ANSWER],
                "chunk/merge summary deltas remain private"
            );
            assert_eq!(
                events
                    .iter()
                    .filter(|e| matches!(e, FrontendEvent::Usage { .. }))
                    .count(),
                1
            );
            let ended: Vec<_> = events
                .iter()
                .filter_map(|event| match event {
                    FrontendEvent::TurnEnded {
                        ok, interrupted, ..
                    } => Some((*ok, *interrupted)),
                    _ => None,
                })
                .collect();
            assert_eq!(
                ended,
                [(true, false)],
                "only the ordinary turn closes the public lifecycle"
            );
            assert!(
                !events
                    .iter()
                    .any(|e| matches!(e, FrontendEvent::Retrying { .. }))
            );
            assert_private(&events);
            let bodies = captured
                .iter()
                .map(|request| request.body.clone())
                .collect();
            Observed { bodies, events }
        }

        #[test]
        fn service_old_api_summary_receives_complete_plain_task_state_after_400_bytes() {
            let mut source = Vec::new();
            for index in 0..3 {
                append_pair(
                    &mut source,
                    &format!("old-{index}"),
                    1800,
                    FULL_TEXT_SENTINEL,
                );
            }
            append_recent(&mut source);
            let observed = run_success(source, SUMMARY_WINDOW);
            assert_eq!(
                observed.bodies.len(),
                2,
                "one already-fitting full summary then ordinary"
            );
            let summary = serde_json::to_string(&observed.bodies[0]["messages"]).unwrap();
            assert!(
                summary.contains(FULL_TEXT_SENTINEL),
                "the older complete visible task state must not end at the legacy 400-byte digest prefix",
            );
        }

        #[test]
        fn service_old_api_independent_budget_requires_two_whole_chunks_then_merge_and_main() {
            const SUMMARY_INPUT: u64 = 2000;
            let mut older = Vec::new();
            append_pair(&mut older, "group-A", 2400, CHUNK_A);
            append_pair(&mut older, "group-B", 2400, CHUNK_B);
            let witness_config = TurnConfig {
                billing: None,
                provider_id: "exact-summary-provider".into(),
                gate: "http://127.0.0.1:9".into(),
                model: "raw-summary-model/unchanged".into(),
                kind: ProviderKind::OpenAiCompatible,
                credential_env: None,
                pricing: None,
                max_output_tokens: 37,
                sampling: None,
                effort: None,
                supported_efforts: None,
                first_byte_timeout_ms: None,
                idle_timeout_ms: None,
            };
            // The witness uses the actual public body renderer. Its route is pure,
            // not an additional listener/provider call and has no credential input.
            assert!(estimate(&summary_witness(&witness_config, &older)) > SUMMARY_INPUT);
            for group in older.as_chunks::<2>().0 {
                assert!(estimate(&summary_witness(&witness_config, group)) + 256 < SUMMARY_INPUT);
            }
            let mut source = older;
            append_recent(&mut source);
            let observed = run_success(source, SUMMARY_INPUT);
            assert_eq!(
                observed.bodies.len(),
                4,
                "two independently fitting complete-group chunks, one fitting merge, one ordinary POST",
            );
            let a = serde_json::to_string(&observed.bodies[0]["messages"]).unwrap();
            let b = serde_json::to_string(&observed.bodies[1]["messages"]).unwrap();
            assert!(a.contains(CHUNK_A) && !a.contains(CHUNK_B));
            assert!(b.contains(CHUNK_B) && !b.contains(CHUNK_A));
            let merge = serde_json::to_string(&observed.bodies[2]["messages"]).unwrap();
            assert!(
                merge.matches(ANSWER).count() >= 2,
                "the merge receives both complete chunk replies"
            );
            assert!(!merge.contains(CHUNK_A) && !merge.contains(CHUNK_B));
            assert_eq!(
                observed
                    .events
                    .iter()
                    .filter(|e| matches!(e, FrontendEvent::Compacted { .. }))
                    .count(),
                1
            );
        }

        #[test]
        fn service_old_api_short_visible_prefix_fits_one_summary_without_redundant_merge() {
            let mut source = Vec::new();
            for index in 0..12 {
                append_pair(
                    &mut source,
                    &format!("short-old-{index}"),
                    180,
                    "short complete task state",
                );
            }
            append_recent(&mut source);
            let observed = run_success(source, SUMMARY_WINDOW);
            assert_eq!(
                observed.bodies.len(),
                2,
                "a single fitting summary does not need a merge"
            );
            assert!(
                serde_json::to_string(&observed.bodies[0]["messages"])
                    .unwrap()
                    .contains("short complete task state")
            );
        }
    }
}
