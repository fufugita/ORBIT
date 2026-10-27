#![deny(unsafe_code)]

use orbit_adapter::types::{ChatMessage, ChatRole};
use orbit_engine::{PendingToolCall, ToolExecutor, ToolRoundResult, TurnConfig, TurnOptions};
use orbit_frontend_protocol::FrontendEvent;
use orbit_provider_http::CancelToken;

#[path = "support/compaction_journal.rs"]
pub mod compaction_journal;
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
        billing: None,
        sampling: None,
        effort: None,
        supported_efforts: None,
        first_byte_timeout_ms: None,
        idle_timeout_ms: None,
        provider_id: "fixture".into(),
        gate: fixture.url.clone(),
        model: "local-model".into(),
        kind: orbit_engine::ProviderKind::OpenAiCompatible,
        credential_env: None,
        pricing: None,
        max_output_tokens: 2048,
    }
}

fn declared_billing(
    rates: orbit_adapter::types::CostRates,
    basis: orbit_adapter::types::ReasoningCounterBasis,
    policy: orbit_adapter::types::ReasoningRatePolicy,
) -> orbit_adapter::types::BillingQuoteContractV1 {
    use orbit_adapter::types::{
        BillingQuoteContractV1, BillingRatesV1, ModelId, PricingDeclarationState, ProviderId,
    };
    BillingQuoteContractV1::try_new(
        ProviderId("fixture".into()),
        ModelId("local-model".into()),
        PricingDeclarationState::DeclaredV2,
        BillingRatesV1 {
            input_per_million_microdollars: Some(rates.input_per_million_microcents),
            output_per_million_microdollars: Some(rates.output_per_million_microcents),
            cache_read_per_million_microdollars: rates.cache_read_per_million_microcents,
            cache_write_per_million_microdollars: rates.cache_write_per_million_microcents,
            reasoning_per_million_microdollars: rates.reasoning_per_million_microcents,
            request_flat_microdollars: Some(rates.request_flat_microcents),
        },
        basis,
        policy,
    )
    .unwrap()
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

fn compaction_body(messages: &[ChatMessage]) -> serde_json::Value {
    let route = serde_json::from_value(serde_json::json!({
        "provider_id":"fixture", "deployment_id":"fixture", "region_id":"local",
        "adapter_kind":"OpenAiCompatibleHttpV1", "adapter_implementation_digest":"implementation",
        "adapter_profile_digest":"profile", "endpoint_digest":"endpoint",
        "expected_model":"local-model", "pricing_digest":"pricing",
        "endpoint_host":"127.0.0.1", "endpoint_port":80,
        "endpoint_scheme":"HttpLoopback", "endpoint_path":""
    }))
    .unwrap();
    let mut request = orbit_adapter::conformance::canonical_request(&route, b"latest prompt");
    request.messages = Some(messages.to_vec());
    request.sampling = orbit_adapter::types::SamplingParameters {
        temperature_milliunits: 0,
        top_p_millionths: 0,
        max_output_tokens: 2048,
    };
    orbit_provider_http::request::render_request_body(
        orbit_provider_http::request::HttpDialect::OpenAiCompatible,
        orbit_provider_http::request::RequestBodyInput::from(&request),
    )
    .unwrap()
    .as_json()
    .clone()
}

fn compaction_case(summary: &str, reason: &str, expected_summary: bool) {
    let fixture = Fixture::new(vec![sse(summary, reason), sse("ordinary answer", "stop")]);
    let home = Home::new();
    let mut transcript: Vec<ChatMessage> = (0..12)
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
    let mut original_with_prompt = original.clone();
    original_with_prompt.push(orbit_engine::user_message("latest prompt"));
    let original_body = compaction_body(&original_with_prompt);
    assert!(serde_json::to_vec(&original_body).unwrap().len() > 4000);
    let selected = config(&fixture);
    let options = TurnOptions {
        // Legacy callers supply an input-policy ceiling, not a combined
        // provider fact. Keep selected max_tokens=2048 independent of it.
        // These byte bounds exercise the documented byte/4 approximation;
        // they do not claim exact tokenizer/provider capacity knowledge.
        window_tokens: Some(1000),
        session_id: "completion-owner".into(),
        journal: Some(compaction_journal::MemoryJournal::fresh("completion-owner")),
        compaction_config: Some(selected.clone()),
        compaction_budget: Some(
            orbit_engine::context_budget::SelectedBudget::legacy_input(&selected, 8192).unwrap(),
        ),
        output_reserve_tokens: 0,
        max_attempts: 1,
        ..Default::default()
    };
    let mut events = Vec::new();
    let mut executor = Executor::default();
    let result = orbit_engine::run_turn(
        &home.0,
        &selected,
        &options,
        "latest prompt",
        &mut transcript,
        &mut executor,
        &CancelToken::new(),
        &mut |event| events.push(event),
    );
    {
        let requests = fixture.requests.lock().unwrap();
        let summary_body = requests.first().expect("one summary must be attempted");
        assert!((serde_json::to_vec(summary_body).unwrap().len() as u64).div_ceil(4) <= 8192);
        assert_eq!(summary_body["model"], "local-model");
        assert_eq!(summary_body["max_tokens"], 2048);
        assert!(summary_body.get("tools").is_none());
        assert!(summary_body.get("reasoning_effort").is_none());
        let text = summary_body["messages"].to_string();
        assert!(text.contains("Summarize this conversation for continuation."));
        assert!(!text.contains("latest prompt"));
    }
    assert_eq!(
        fixture.calls(),
        if expected_summary { 2 } else { 1 },
        "an unusable summary must never fall through to an oversized ordinary POST"
    );
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
    assert!(
        !events.iter().any(|event| matches!(event,
            FrontendEvent::TextDelta { text } if !summary.is_empty() && text.contains(summary)
        )),
        "housekeeping text stays private"
    );
    if expected_summary {
        let report = result.unwrap();
        assert!(report.ok && !report.interrupted);
        assert_eq!(
            transcript[0],
            orbit_engine::user_message("[Earlier conversation summary: historical data]")
        );
        assert_eq!(transcript[1], orbit_engine::assistant_message(summary));
        assert!(
            original.iter().any(|old| !transcript.contains(old)),
            "some complete old source must be replaced"
        );
        let requests = fixture.requests.lock().unwrap();
        assert_eq!(requests[1]["max_tokens"], 2048);
        assert!((serde_json::to_vec(&requests[1]).unwrap().len() as u64).div_ceil(4) <= 1000);
        let candidate = &transcript[..transcript.len() - 1];
        assert!(candidate.len() < original_with_prompt.len());
        assert_eq!(
            &candidate[candidate.len() - 5..candidate.len() - 1],
            &original[8..]
        );
        assert_eq!(
            candidate.last().unwrap(),
            &orbit_engine::user_message("latest prompt")
        );
        assert_eq!(requests[1], compaction_body(candidate));
        assert_eq!(transcript.last().unwrap().content, "ordinary answer");
    } else {
        let error = result.expect_err("unusable summary must return a local budget error");
        assert!(error.len() <= 512, "local budget error must be bounded");
        let normalized = error.to_ascii_lowercase();
        assert!(
            normalized.contains("context")
                || normalized.contains("budget")
                || normalized.contains("limit")
        );
        assert!(!error.contains(&fixture.url));
        assert!(!error.contains("history-0:") && !error.contains("latest prompt"));
        if !summary.is_empty() {
            assert!(!error.contains(summary));
        }
        assert_eq!(
            transcript, original_with_prompt,
            "unusable compaction must preserve every original message and current intent"
        );
        assert!(
            !events
                .iter()
                .any(|event| matches!(event, FrontendEvent::TextDelta { .. }))
        );
    }
}

#[test]
fn compaction_rejects_length_summary() {
    compaction_case("summary candidate", "length", false);
}
#[test]
fn compaction_rejects_max_tokens_summary() {
    compaction_case("summary candidate", "max_tokens", false);
}
#[test]
fn compaction_rejects_cancelled_summary() {
    compaction_case("summary candidate", "cancelled", false);
}
#[test]
fn compaction_accepts_completed_summary() {
    compaction_case("summary candidate", "stop", true);
}

#[test]
fn compaction_rejects_empty_summary() {
    compaction_case("", "stop", false);
}

#[test]
fn compaction_rejects_whitespace_only_completed_summary() {
    compaction_case(" \n\t", "stop", false);
}

#[test]
fn compaction_rejects_ineffective_completed_summary() {
    let summary = "ineffective ".repeat(550);
    // A completed response can be valid text but fail to reduce the request.
    // The selected output cap remains 2048; the input-only ceiling is 1000.
    // Include the exact retained tail and current intent in this candidate.
    let mut candidate = vec![
        orbit_engine::user_message("[Earlier conversation summary: historical data]"),
        orbit_engine::assistant_message(&summary),
    ];
    candidate.extend((8..12).map(|n| {
        let mut message =
            orbit_engine::user_message(format!("history-{n}: {}", "preserve ".repeat(50)));
        if n % 2 == 1 {
            message.role = ChatRole::Assistant;
        }
        message
    }));
    candidate.push(orbit_engine::user_message("latest prompt"));
    assert!(
        serde_json::to_vec(&compaction_body(&candidate))
            .unwrap()
            .len()
            > 4000
    );
    compaction_case(&summary, "stop", false);
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
    let mut original_with_prompt = original.clone();
    original_with_prompt.push(orbit_engine::user_message("latest prompt"));
    assert!(
        serde_json::to_vec(&compaction_body(&original_with_prompt))
            .unwrap()
            .len()
            > 4000
    );
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
    let selected = config(&fixture);
    let mut events = Vec::new();
    let report = orbit_engine::run_turn(
        &home.0,
        &selected,
        &TurnOptions {
            window_tokens: Some(1000),
            session_id: "completion-owner".into(),
            journal: Some(compaction_journal::MemoryJournal::fresh("completion-owner")),
            compaction_config: Some(selected.clone()),
            compaction_budget: Some(
                orbit_engine::context_budget::SelectedBudget::legacy_input(&selected, 8192)
                    .unwrap(),
            ),
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
    {
        let requests = fixture.requests.lock().unwrap();
        assert!((serde_json::to_vec(&requests[0]).unwrap().len() as u64).div_ceil(4) <= 8192);
        assert_eq!(requests[0]["max_tokens"], 2048);
        assert!(requests[0].get("tools").is_none());
    }
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

#[test]
fn task05_detailed_anthropic_preserves_cache_write_and_full_usage_fields() {
    let body = concat!(
        "data: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":11,\"output_tokens\":0,\"cache_read_input_tokens\":5,\"cache_creation_input_tokens\":3}}}\n\n",
        "data: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n",
        "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"ordinary cached answer\"}}\n\n",
        "data: {\"type\":\"content_block_stop\",\"index\":0}\n\n",
        "data: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":7,\"cache_read_input_tokens\":5,\"cache_creation_input_tokens\":3}}\n\n",
        "data: {\"type\":\"message_stop\"}\n\n"
    );
    let fixture = Fixture::new(vec![Response {
        body: body.into(),
        status: 200,
        pause: false,
    }]);
    let home = Home::new();
    let mut selected = config(&fixture);
    selected.kind = orbit_engine::ProviderKind::Anthropic;
    selected.pricing = Some(orbit_adapter::types::CostRates {
        input_per_million_microcents: 1_000_000,
        output_per_million_microcents: 2_000_000,
        cache_read_per_million_microcents: Some(3_000_000),
        cache_write_per_million_microcents: Some(4_000_000),
        reasoning_per_million_microcents: Some(5_000_000),
        request_flat_microcents: 7,
    });
    selected.billing = Some(declared_billing(
        selected.pricing.unwrap(),
        orbit_adapter::types::ReasoningCounterBasis::IncludedInOutput,
        orbit_adapter::types::ReasoningRatePolicy::OutputRate,
    ));
    let journal = compaction_journal::MemoryJournal::fresh("ordinary-anthropic");
    let options = TurnOptions {
        session_id: "ordinary-anthropic".into(),
        journal: Some(journal.clone()),
        selected_budget: Some(
            orbit_engine::context_budget::SelectedBudget::legacy_input(&selected, 8000).unwrap(),
        ),
        max_attempts: 3,
        ..Default::default()
    };
    let mut source = Vec::new();
    let mut executor = Executor::default();
    let mut events = Vec::new();
    let completion = orbit_engine::run_turn_detailed(
        &home.0,
        &selected,
        &options,
        "cached ordinary task",
        &mut source,
        &mut executor,
        &CancelToken::new(),
        &mut |event| events.push(event),
    );
    assert!(matches!(completion.end, orbit_engine::TurnEnd::Completed));
    assert_eq!(completion.report.cost_microcents, 59);
    assert_eq!(
        (
            completion.report.input_tokens,
            completion.report.output_tokens
        ),
        (11, 7)
    );
    assert_eq!(completion.report.attempts.len(), 1);
    let receipt = &completion.report.attempts[0];
    assert_eq!(
        receipt.usage,
        Some(orbit_adapter::types::ProviderUsage {
            input_tokens: 11,
            output_tokens: 7,
            cache_read_tokens: 5,
            cache_write_tokens: 3,
            reasoning_tokens: 0
        })
    );
    assert_eq!(receipt.totals.cost_microcents, Some(59));
    assert_eq!(receipt.knownness, orbit_engine::AccountingKnownness::Known);
    assert!(receipt.completed);
    assert_eq!(receipt.purpose, orbit_engine::AttemptPurpose::Ordinary);
    assert_eq!(completion.report.accounting.ordinary, receipt.totals);
    assert_eq!(
        completion.report.accounting.housekeeping,
        orbit_engine::AccountingTotals::known_zero()
    );
    assert_eq!(journal.receipts(), completion.report.attempts);
    assert_eq!(executor.0, 0);
    assert_eq!(fixture.calls(), 1);
    assert_eq!(source.last().unwrap().content, "ordinary cached answer");
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(event, FrontendEvent::TurnEnded { .. }))
            .count(),
        1
    );
}

#[test]
fn task05_accepted_http_failure_with_journal_does_not_retry_or_become_known_zero() {
    for status in [429, 503] {
        let fixture = Fixture::new(vec![
            Response {
                body: "{\"error\":{\"message\":\"owned fixture refusal\"}}".into(),
                status,
                pause: false,
            },
            sse("must not retry", "stop"),
        ]);
        let home = Home::new();
        let journal = compaction_journal::MemoryJournal::fresh("ordinary-http-failure");
        let options = TurnOptions {
            session_id: "ordinary-http-failure".into(),
            journal: Some(journal.clone()),
            max_attempts: 3,
            ..Default::default()
        };
        let mut source = Vec::new();
        let mut executor = Executor::default();
        let mut events = Vec::new();
        let completion = orbit_engine::run_turn_detailed(
            &home.0,
            &config(&fixture),
            &options,
            "preserve uncertain ordinary intent",
            &mut source,
            &mut executor,
            &CancelToken::new(),
            &mut |event| events.push(event),
        );
        assert!(matches!(completion.end, orbit_engine::TurnEnd::Failed(_)));
        assert!(!completion.report.ok);
        assert_eq!(completion.report.attempts.len(), 1);
        let receipt = &completion.report.attempts[0];
        assert_eq!(
            receipt.knownness,
            orbit_engine::AccountingKnownness::Uncertain
        );
        assert_eq!(receipt.totals.cost_microcents, None);
        assert!(!receipt.completed);
        assert_eq!(
            completion.report.accounting.knownness,
            orbit_engine::AccountingKnownness::Uncertain
        );
        assert_eq!(
            (
                completion.report.input_tokens,
                completion.report.output_tokens,
                completion.report.cost_microcents
            ),
            (0, 0, 0)
        );
        assert_eq!(journal.receipts(), completion.report.attempts);
        assert_eq!(fixture.calls(), 1);
        assert_eq!(executor.0, 0);
        assert!(source.iter().any(|message| message.role == ChatRole::User
            && message.content == "preserve uncertain ordinary intent"));
        assert!(
            !events
                .iter()
                .any(|event| matches!(event, FrontendEvent::Retrying { .. }))
        );
        assert_eq!(
            events
                .iter()
                .filter(|event| matches!(event, FrontendEvent::TurnEnded { .. }))
                .count(),
            1
        );
        let checkpoint =
            orbit_engine::CompactionJournal::accounting_checkpoint(journal.as_ref()).unwrap();
        assert!(
            checkpoint
                .pending
                .as_ref()
                .is_some_and(|pending| pending.uncertain)
        );
        assert_eq!(checkpoint.totals.ordinary.cost_microcents, None);
    }
}

#[test]
fn task05_valid_ordinary_tool_terminal_is_completed_and_billed_once_before_continuation() {
    struct OneTool(usize);
    impl ToolExecutor for OneTool {
        fn execute(&mut self, calls: &[PendingToolCall], _: u32) -> Vec<ToolRoundResult> {
            self.0 += 1;
            assert_eq!(calls.len(), 1);
            vec![ToolRoundResult {
                call_id: calls[0].id.clone(),
                content: "exact safe tool result".into(),
            }]
        }
    }
    let tool = serde_json::json!({"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"valid-positive-call","type":"function","function":{"name":"inspect","arguments":"{}"}}]},"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":11,"completion_tokens":7,"total_tokens":18}});
    let done = serde_json::json!({"choices":[{"index":0,"delta":{"content":"ordinary completed after tool"},"finish_reason":"stop"}],"usage":{"prompt_tokens":11,"completion_tokens":7,"total_tokens":18}});
    let fixture = Fixture::new(vec![
        Response {
            body: format!("data: {tool}\n\ndata: [DONE]\n\n"),
            status: 200,
            pause: false,
        },
        Response {
            body: format!("data: {done}\n\ndata: [DONE]\n\n"),
            status: 200,
            pause: false,
        },
    ]);
    let home = Home::new();
    let mut selected = config(&fixture);
    selected.pricing = Some(orbit_adapter::types::CostRates {
        input_per_million_microcents: 0,
        output_per_million_microcents: 0,
        cache_read_per_million_microcents: Some(0),
        cache_write_per_million_microcents: Some(0),
        reasoning_per_million_microcents: Some(0),
        request_flat_microcents: 3,
    });
    selected.billing = Some(declared_billing(
        selected.pricing.unwrap(),
        orbit_adapter::types::ReasoningCounterBasis::IncludedInOutput,
        orbit_adapter::types::ReasoningRatePolicy::OutputRate,
    ));
    let journal = compaction_journal::MemoryJournal::fresh("ordinary-tool-positive");
    let options = TurnOptions {
        session_id: "ordinary-tool-positive".into(),
        journal: Some(journal.clone()),
        max_rounds: 3,
        max_attempts: 3,
        tools: vec![orbit_adapter::types::ToolDefinition {
            name: "inspect".into(),
            description: "owned fixture operation".into(),
            parameters: serde_json::json!({"type":"object"}),
            schema_digest: orbit_adapter::types::Sha256Digest("fixture".into()),
        }],
        ..Default::default()
    };
    let mut source = Vec::new();
    let mut executor = OneTool(0);
    let mut events = Vec::new();
    let completion = orbit_engine::run_turn_detailed(
        &home.0,
        &selected,
        &options,
        "complete the exact tool task",
        &mut source,
        &mut executor,
        &CancelToken::new(),
        &mut |event| events.push(event),
    );
    assert!(matches!(completion.end, orbit_engine::TurnEnd::Completed));
    assert_eq!(executor.0, 1);
    assert_eq!(fixture.calls(), 2);
    assert_eq!(
        (
            completion.report.input_tokens,
            completion.report.output_tokens,
            completion.report.cost_microcents
        ),
        (22, 14, 6)
    );
    assert_eq!(completion.report.attempts.len(), 2);
    for receipt in &completion.report.attempts {
        assert_eq!(receipt.purpose, orbit_engine::AttemptPurpose::Ordinary);
        assert_eq!(receipt.knownness, orbit_engine::AccountingKnownness::Known);
        assert!(receipt.completed);
        assert_eq!(receipt.totals.cost_microcents, Some(3));
    }
    assert_eq!(
        completion.report.accounting.ordinary.cost_microcents,
        Some(6)
    );
    assert_eq!(
        completion.report.accounting.housekeeping,
        orbit_engine::AccountingTotals::known_zero()
    );
    assert_eq!(journal.receipts(), completion.report.attempts);
    assert_eq!(
        source.last().unwrap().content,
        "ordinary completed after tool"
    );
    assert!(source.iter().any(|message| message.role == ChatRole::Tool
        && message.tool_call_id.as_deref() == Some("valid-positive-call")
        && message.tool_result.as_deref() == Some("exact safe tool result")));
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(event, FrontendEvent::TurnEnded { .. }))
            .count(),
        1
    );
}

#[test]
fn task05_unmanaged_legacy_retry_retains_uncertain_prefix_and_known_success_once() {
    let done = serde_json::json!({"choices":[{"index":0,"delta":{"content":"completed after bounded legacy retry"},"finish_reason":"stop"}],"usage":{"prompt_tokens":11,"completion_tokens":7,"total_tokens":18}});
    let fixture = Fixture::new(vec![
        Response {
            body: "{\"error\":{\"message\":\"owned fixture capacity\"}}".into(),
            status: 503,
            pause: false,
        },
        Response {
            body: format!("data: {done}\n\ndata: [DONE]\n\n"),
            status: 200,
            pause: false,
        },
    ]);
    let home = Home::new();
    let mut selected = config(&fixture);
    selected.pricing = Some(orbit_adapter::types::CostRates {
        input_per_million_microcents: 0,
        output_per_million_microcents: 0,
        cache_read_per_million_microcents: Some(0),
        cache_write_per_million_microcents: Some(0),
        reasoning_per_million_microcents: Some(0),
        request_flat_microcents: 4,
    });
    selected.billing = Some(declared_billing(
        selected.pricing.unwrap(),
        orbit_adapter::types::ReasoningCounterBasis::IncludedInOutput,
        orbit_adapter::types::ReasoningRatePolicy::OutputRate,
    ));
    let options = TurnOptions {
        session_id: "unmanaged-legacy-retry".into(),
        request_stem: "unmanaged-legacy-retry".into(),
        max_attempts: 2,
        journal: None,
        spend_allowance: None,
        ..Default::default()
    };
    let mut source = Vec::new();
    let mut executor = Executor::default();
    let mut events = Vec::new();
    let completion = orbit_engine::run_turn_detailed(
        &home.0,
        &selected,
        &options,
        "preserve original legacy retry intent",
        &mut source,
        &mut executor,
        &CancelToken::new(),
        &mut |event| events.push(event),
    );
    assert!(matches!(completion.end, orbit_engine::TurnEnd::Completed));
    assert!(completion.report.ok && !completion.report.interrupted);
    assert_eq!(
        completion.report.final_text,
        "completed after bounded legacy retry"
    );
    assert_eq!(fixture.calls(), 2);
    assert_eq!(executor.0, 0);
    assert_eq!(completion.report.attempts.len(), 2);
    let first = &completion.report.attempts[0];
    let second = &completion.report.attempts[1];
    assert_eq!(first.purpose, orbit_engine::AttemptPurpose::Ordinary);
    assert_eq!(
        first.knownness,
        orbit_engine::AccountingKnownness::Uncertain
    );
    assert!(!first.completed);
    assert!(first.usage.is_none());
    assert_eq!(
        (
            first.totals.input_tokens,
            first.totals.output_tokens,
            first.totals.cost_microcents
        ),
        (0, 0, None)
    );
    assert_eq!(second.purpose, orbit_engine::AttemptPurpose::Ordinary);
    assert_eq!(second.knownness, orbit_engine::AccountingKnownness::Known);
    assert!(second.completed);
    assert_eq!(
        second.usage,
        Some(orbit_adapter::types::ProviderUsage {
            input_tokens: 11,
            output_tokens: 7,
            ..Default::default()
        })
    );
    assert_eq!(
        (
            second.totals.input_tokens,
            second.totals.output_tokens,
            second.totals.cost_microcents
        ),
        (11, 7, Some(4))
    );
    assert_eq!(
        completion.report.accounting.knownness,
        orbit_engine::AccountingKnownness::Uncertain
    );
    assert_eq!(
        (
            completion.report.accounting.ordinary.input_tokens,
            completion.report.accounting.ordinary.output_tokens,
            completion.report.accounting.ordinary.cost_microcents
        ),
        (11, 7, None)
    );
    assert_eq!(
        completion.report.accounting.housekeeping,
        orbit_engine::AccountingTotals::known_zero()
    );
    assert_eq!(
        (
            completion.report.input_tokens,
            completion.report.output_tokens,
            completion.report.cost_microcents
        ),
        (11, 7, 4)
    );
    let records = orbit_ledger::verify_ledger(&home.0.join("ledger"))
        .unwrap()
        .0;
    let actual_ids: Vec<_> = records
        .into_iter()
        .filter_map(|record| {
            if let orbit_ledger::LedgerEvent::EgressIntent(event) = record.record.event {
                assert_eq!(event.session_id, options.session_id);
                Some(event.decision_id)
            } else {
                None
            }
        })
        .collect();
    assert_eq!(actual_ids.len(), 2);
    assert_ne!(actual_ids[0], actual_ids[1]);
    assert_eq!(
        actual_ids,
        [first.request_id.clone(), second.request_id.clone()]
    );
    assert_eq!(
        source,
        [
            orbit_engine::user_message("preserve original legacy retry intent"),
            orbit_engine::assistant_message("completed after bounded legacy retry")
        ]
    );
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(event, FrontendEvent::Retrying { .. }))
            .count(),
        1
    );
    let terminal: Vec<_> = events
        .iter()
        .filter_map(|event| {
            if let FrontendEvent::TurnEnded {
                ok,
                interrupted,
                rounds,
                input_tokens,
                output_tokens,
                cost_microcents,
            } = event
            {
                Some((
                    *ok,
                    *interrupted,
                    *rounds,
                    *input_tokens,
                    *output_tokens,
                    *cost_microcents,
                ))
            } else {
                None
            }
        })
        .collect();
    assert_eq!(
        terminal,
        [(true, false, completion.report.rounds, 11, 7, 4)]
    );
}
