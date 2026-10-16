#![deny(unsafe_code)]

use orbit_adapter::types::{ChatMessage, ChatRole};
use orbit_engine::{
    PendingToolCall, ProviderKind, ToolExecutor, ToolRoundResult, TurnConfig, TurnOptions,
};
use orbit_frontend_protocol::FrontendEvent;
use orbit_provider_http::CancelToken;
use serde_json::{Value, json};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, Instant};

struct Reply {
    body: String,
    disconnect: bool,
}

impl Reply {
    fn complete(body: String) -> Self {
        Self {
            body,
            disconnect: false,
        }
    }
}

struct Provider {
    url: String,
    requests: Arc<Mutex<Vec<Value>>>,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
    watchdog: Option<std::sync::mpsc::Sender<()>>,
}

impl Provider {
    fn new(replies: Vec<Reply>) -> Self {
        let (watchdog, receiver) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            if matches!(
                receiver.recv_timeout(Duration::from_secs(18)),
                Err(std::sync::mpsc::RecvTimeoutError::Timeout)
            ) {
                eprintln!("wire integrity fixture exceeded independent watchdog");
                std::process::exit(91);
            }
        });
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let requests = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let captured = requests.clone();
        let stopping = stop.clone();
        let thread = std::thread::spawn(move || {
            let mut replies = replies.into_iter();
            while !stopping.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        stream
                            .set_read_timeout(Some(Duration::from_secs(2)))
                            .unwrap();
                        stream
                            .set_write_timeout(Some(Duration::from_secs(2)))
                            .unwrap();
                        captured.lock().unwrap().push(read_request(&mut stream));
                        let reply = replies.next().unwrap_or_else(|| {
                            Reply::complete(openai_text("unexpected replay", Some("stop"), true))
                        });
                        let length = reply.body.len() + usize::from(reply.disconnect) * 10_000;
                        let _ = write!(
                            stream,
                            "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {length}\r\nConnection: close\r\n\r\n{}",
                            reply.body
                        );
                        let _ = stream.flush();
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(2))
                    }
                    Err(error) => panic!("provider fixture: {error}"),
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

    fn count(&self) -> usize {
        self.requests.lock().unwrap().len()
    }
}

impl Drop for Provider {
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

fn read_request(stream: &mut TcpStream) -> Value {
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut header = Vec::new();
    while !header.ends_with(b"\r\n\r\n") {
        assert!(header.len() < 16_384 && Instant::now() < deadline);
        let mut byte = [0];
        stream.read_exact(&mut byte).unwrap();
        header.push(byte[0]);
    }
    let header = String::from_utf8(header).unwrap();
    assert!(header.starts_with("POST /"));
    let length: usize = header
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse().unwrap())
        })
        .unwrap();
    assert!(length < 1024 * 1024);
    let mut bytes = vec![0; length];
    stream.read_exact(&mut bytes).unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

struct Home(std::path::PathBuf);
impl Home {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("orbit-wire-{}", ulid::Ulid::new()));
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
struct Executor {
    calls: Vec<(String, String)>,
}
impl ToolExecutor for Executor {
    fn execute(&mut self, calls: &[PendingToolCall], _round: u32) -> Vec<ToolRoundResult> {
        calls
            .iter()
            .map(|call| {
                self.calls.push((call.id.clone(), call.name.clone()));
                ToolRoundResult {
                    call_id: call.id.clone(),
                    content: json!({"ok":true,"effect":call.id}).to_string(),
                }
            })
            .collect()
    }
}

fn config(provider: &Provider, kind: ProviderKind) -> TurnConfig {
    TurnConfig {
        provider_id: "fixture".into(),
        gate: provider.url.clone(),
        model: "fixture-model".into(),
        kind,
        credential_env: Some("ORBIT_WIRE_FIXTURE_UNUSED_TOKEN".into()),
        pricing: None,
        max_output_tokens: 2048,
        sampling: None,
        effort: None,
        supported_efforts: None,
    }
}

fn frame(value: Value) -> String {
    format!("data: {value}\n\n")
}
fn openai_text(text: &str, reason: Option<&str>, sentinel: bool) -> String {
    let mut body = frame(json!({"choices":[{"delta":{"content":text},"finish_reason":reason}]}));
    if sentinel {
        body.push_str("data: [DONE]\n\n");
    }
    body
}
fn call(index: usize, id: &str, name: &str, arguments: &str) -> Value {
    json!({"index":index,"id":id,"type":"function","function":{"name":name,"arguments":arguments}})
}
fn openai_calls(calls: Vec<Value>, reason: Option<&str>, sentinel: bool) -> String {
    let mut body =
        frame(json!({"choices":[{"delta":{"content":"visible partial","tool_calls":calls}}]}));
    if let Some(reason) = reason {
        body.push_str(&frame(
            json!({"choices":[{"delta":{},"finish_reason":reason}]}),
        ));
    }
    if sentinel {
        body.push_str("data: [DONE]\n\n");
    }
    body
}

#[test]
fn accounting_native_context_overflow_is_refused_before_effects() {
    let body = [
        json!({"type":"message_start","message":{"id":"message-1","role":"assistant","type":"message","content":[],"usage":{"input_tokens":u64::MAX,"output_tokens":0,"cache_read_input_tokens":1}}}),
        json!({"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}),
        json!({"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"visible partial"}}),
        json!({"type":"content_block_stop","index":0}),
        json!({"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":0}}),
        json!({"type":"message_stop"}),
    ].into_iter().map(frame).collect();
    let provider = Provider::new(vec![Reply::complete(body)]);
    let home = Home::new();
    let mut executor = Executor::default();
    let mut transcript = Vec::new();
    let mut events = Vec::new();
    let result = orbit_engine::run_turn(
        &home.0,
        &config(&provider, ProviderKind::Anthropic),
        &TurnOptions {
            max_attempts: 3,
            ..Default::default()
        },
        "reject overflowing accounting",
        &mut transcript,
        &mut executor,
        &CancelToken::new(),
        &mut |event| events.push(event),
    );
    assert!(result.unwrap_err().contains("accounting overflow"));
    no_effects(&provider, &executor, &transcript, &events);
    assert_eq!(transcript.last().unwrap().content, "visible partial");
}

#[test]
fn accounting_round_overflow_preserves_prior_effects_and_refuses_new_tools() {
    for counter in ["prompt_tokens", "completion_tokens"] {
        let replies = [u64::MAX, 1]
            .into_iter()
            .enumerate()
            .map(|(round, total)| {
                let mut body = openai_calls(
                    vec![call(0, &format!("effect-{round}"), "Effect", "{}")],
                    Some("tool_calls"),
                    false,
                );
                let mut usage = json!({"prompt_tokens":0,"completion_tokens":0});
                usage[counter] = json!(total);
                body.push_str(&frame(json!({"choices":[],"usage":usage})));
                body.push_str("data: [DONE]\n\n");
                Reply::complete(body)
            })
            .collect();
        let provider = Provider::new(replies);
        let home = Home::new();
        let mut executor = Executor::default();
        let mut transcript = Vec::new();
        let mut events = Vec::new();
        let result = orbit_engine::run_turn(
            &home.0,
            &config(&provider, ProviderKind::OpenAiCompatible),
            &TurnOptions {
                max_attempts: 3,
                ..Default::default()
            },
            "stop before new effects if accounting overflows",
            &mut transcript,
            &mut executor,
            &CancelToken::new(),
            &mut |event| events.push(event),
        );
        assert!(
            result.unwrap_err().contains("accounting overflow"),
            "{counter}"
        );
        assert_eq!(provider.count(), 2);
        assert_eq!(executor.calls, vec![("effect-0".into(), "Effect".into())]);
        assert_eq!(
            transcript
                .iter()
                .filter(|m| m.role == ChatRole::Tool)
                .count(),
            1
        );
        assert_eq!(transcript.last().unwrap().content, "visible partial");
        assert!(
            !events
                .iter()
                .any(|e| matches!(e, FrontendEvent::Retrying { .. }))
        );
        assert_eq!(
            events
                .iter()
                .filter(|e| matches!(e, FrontendEvent::CostUpdated { .. }))
                .count(),
            1
        );
    }
}

fn no_effects(
    provider: &Provider,
    executor: &Executor,
    transcript: &[ChatMessage],
    events: &[FrontendEvent],
) {
    assert_eq!(
        provider.count(),
        1,
        "an admitted stream must never be replayed"
    );
    assert!(
        executor.calls.is_empty(),
        "incomplete or invalid calls must have zero effects"
    );
    assert!(
        !events.iter().any(|event| matches!(
            event,
            FrontendEvent::ToolStartedFull { .. } | FrontendEvent::Retrying { .. }
        )),
        "no tool metadata or retry may be emitted"
    );
    assert!(
        !transcript
            .iter()
            .any(|message| message.role == ChatRole::Tool
                || message
                    .tool_calls
                    .as_ref()
                    .is_some_and(|calls| !calls.is_empty())),
        "incomplete work cannot fabricate assistant calls or paired results"
    );
}

#[test]
fn interrupted_openai_partial_transport_is_not_replayed() {
    let provider = Provider::new(vec![Reply {
        body: openai_calls(
            vec![call(0, "effect-1", "Effect", "{\"value\":1}")],
            None,
            false,
        ),
        disconnect: true,
    }]);
    let home = Home::new();
    let mut executor = Executor::default();
    let mut transcript = Vec::new();
    let mut events = Vec::new();
    let result = orbit_engine::run_turn(
        &home.0,
        &config(&provider, ProviderKind::OpenAiCompatible),
        &TurnOptions {
            max_attempts: 3,
            ..Default::default()
        },
        "count the effect once",
        &mut transcript,
        &mut executor,
        &CancelToken::new(),
        &mut |event| events.push(event),
    );
    assert!(
        result.is_err() || result.as_ref().is_ok_and(|report| !report.ok),
        "an interrupted response cannot succeed"
    );
    no_effects(&provider, &executor, &transcript, &events);
    assert_eq!(events.iter().filter(|event| matches!(event, FrontendEvent::TextDelta { text } if text == "visible partial")).count(), 1);
}

#[test]
fn interrupted_openai_admission_without_text_is_not_replayed() {
    let provider = Provider::new(vec![Reply {
        body: String::new(),
        disconnect: true,
    }]);
    let home = Home::new();
    let mut executor = Executor::default();
    let mut transcript = Vec::new();
    let mut events = Vec::new();
    let result = orbit_engine::run_turn(
        &home.0,
        &config(&provider, ProviderKind::OpenAiCompatible),
        &TurnOptions {
            max_attempts: 3,
            ..Default::default()
        },
        "do not replay admission",
        &mut transcript,
        &mut executor,
        &CancelToken::new(),
        &mut |event| events.push(event),
    );
    assert!(result.is_err());
    no_effects(&provider, &executor, &transcript, &events);
}

fn rejected_openai(calls: Vec<Value>, reason: Option<&str>, sentinel: bool, truncated: bool) {
    let provider = Provider::new(vec![Reply::complete(openai_calls(calls, reason, sentinel))]);
    let home = Home::new();
    let mut executor = Executor::default();
    let mut transcript = Vec::new();
    let mut events = Vec::new();
    let result = orbit_engine::run_turn(
        &home.0,
        &config(&provider, ProviderKind::OpenAiCompatible),
        &TurnOptions {
            max_attempts: 3,
            ..Default::default()
        },
        "reject unfinished work",
        &mut transcript,
        &mut executor,
        &CancelToken::new(),
        &mut |event| events.push(event),
    );
    no_effects(&provider, &executor, &transcript, &events);
    assert!(
        result.is_err() || result.as_ref().is_ok_and(|report| !report.ok),
        "incomplete/filtered/truncated responses must not report success"
    );
    if truncated {
        assert!(
            events
                .iter()
                .any(|event| matches!(event, FrontendEvent::OutputTruncated { .. }))
        );
        assert_eq!(transcript.last().unwrap().content, "visible partial");
    }
}

#[test]
fn terminal_policy_openai_negative_reason_overrides_sentinel() {
    for reason in ["length", "max_tokens", "content_filter", "unknown_reason"] {
        rejected_openai(
            vec![call(0, "effect-1", "Effect", "{}")],
            Some(reason),
            true,
            matches!(reason, "length" | "max_tokens"),
        );
    }
}

#[test]
fn terminal_policy_openai_unmarked_eof_is_not_completion() {
    rejected_openai(
        vec![call(0, "effect-1", "Effect", "{}")],
        None,
        false,
        false,
    );
}

#[test]
fn terminal_policy_openai_validates_entire_call_set_before_effects() {
    for invalid in [
        call(1, "", "Effect", "{}"),
        call(1, "effect-2", "", "{}"),
        call(1, "effect-2", "Effect", "{"),
        call(1, "effect-2", "Effect", "[]"),
        call(1, "effect-1", "Effect", "{}"),
    ] {
        rejected_openai(
            vec![call(0, "effect-1", "Effect", "{}"), invalid],
            Some("tool_calls"),
            true,
            false,
        );
    }
}

#[test]
fn terminal_policy_openai_positive_markers_and_tool_pairing() {
    for (reason, sentinel) in [
        (Some("tool_calls"), false),
        (Some("stop"), false),
        (None, true),
        (Some("tool_calls"), true),
    ] {
        let provider = Provider::new(vec![
            Reply::complete(openai_calls(
                vec![call(0, "effect-1", "Effect", "{}")],
                reason,
                sentinel,
            )),
            Reply::complete(openai_text("complete", Some("stop"), true)),
        ]);
        let home = Home::new();
        let mut executor = Executor::default();
        let mut transcript = Vec::new();
        let report = orbit_engine::run_turn(
            &home.0,
            &config(&provider, ProviderKind::OpenAiCompatible),
            &TurnOptions {
                max_attempts: 3,
                ..Default::default()
            },
            "perform effect",
            &mut transcript,
            &mut executor,
            &CancelToken::new(),
            &mut |_| {},
        )
        .unwrap();
        assert!(report.ok && !report.interrupted);
        assert_eq!(report.final_text, "complete");
        assert_eq!(provider.count(), 2);
        assert_eq!(executor.calls, vec![("effect-1".into(), "Effect".into())]);
        let requests = provider.requests.lock().unwrap();
        let messages = requests[1]["messages"].as_array().unwrap();
        let result = messages
            .iter()
            .find(|message| message["role"] == "tool")
            .unwrap();
        assert_eq!(result["tool_call_id"], "effect-1");
        assert_eq!(
            serde_json::from_str::<Value>(result["content"].as_str().unwrap()).unwrap(),
            json!({"ok":true,"effect":"effect-1"})
        );
    }
}

#[test]
fn terminal_policy_openai_positive_text_markers() {
    for (reason, sentinel) in [(Some("stop"), false), (None, true), (Some("stop"), true)] {
        let provider = Provider::new(vec![Reply::complete(openai_text(
            "complete", reason, sentinel,
        ))]);
        let home = Home::new();
        let mut executor = Executor::default();
        let report = orbit_engine::run_turn(
            &home.0,
            &config(&provider, ProviderKind::OpenAiCompatible),
            &TurnOptions::default(),
            "answer",
            &mut Vec::new(),
            &mut executor,
            &CancelToken::new(),
            &mut |_| {},
        )
        .unwrap();
        assert!(report.ok && !report.interrupted);
        assert_eq!(report.final_text, "complete");
        assert_eq!(provider.count(), 1);
        assert!(executor.calls.is_empty());
    }
}

#[test]
fn terminal_policy_anthropic_max_tokens_rejects_complete_json() {
    let body = [json!({"type":"message_start","message":{"id":"message-1","role":"assistant","type":"message","content":[],"usage":{"input_tokens":1,"output_tokens":0}}}),json!({"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"effect-1","name":"Effect","input":{}}}),json!({"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{}"}}),json!({"type":"content_block_stop","index":0}),json!({"type":"message_delta","delta":{"stop_reason":"max_tokens"},"usage":{"output_tokens":1}}),json!({"type":"message_stop"})].into_iter().map(frame).collect::<String>();
    let provider = Provider::new(vec![Reply::complete(body)]);
    let home = Home::new();
    let mut executor = Executor::default();
    let mut transcript = Vec::new();
    let mut events = Vec::new();
    let result = orbit_engine::run_turn(
        &home.0,
        &config(&provider, ProviderKind::Anthropic),
        &TurnOptions {
            max_attempts: 3,
            ..Default::default()
        },
        "reject truncation",
        &mut transcript,
        &mut executor,
        &CancelToken::new(),
        &mut |event| events.push(event),
    );
    no_effects(&provider, &executor, &transcript, &events);
    assert!(result.is_err() || result.is_ok_and(|report| !report.ok));
    assert!(
        events
            .iter()
            .any(|event| matches!(event, FrontendEvent::OutputTruncated { .. }))
    );
}

#[test]
fn terminal_policy_ollama_truncation_rejects_complete_json() {
    let body = format!(
        "{}\n",
        json!({"message":{"role":"assistant","content":"visible partial","tool_calls":[{"function":{"name":"Effect","arguments":{}}}]},"done":true,"done_reason":"length"})
    );
    let provider = Provider::new(vec![Reply::complete(body)]);
    let home = Home::new();
    let mut executor = Executor::default();
    let mut transcript = Vec::new();
    let mut events = Vec::new();
    let result = orbit_engine::run_turn(
        &home.0,
        &config(&provider, ProviderKind::Ollama),
        &TurnOptions {
            max_attempts: 3,
            ..Default::default()
        },
        "reject truncation",
        &mut transcript,
        &mut executor,
        &CancelToken::new(),
        &mut |event| events.push(event),
    );
    no_effects(&provider, &executor, &transcript, &events);
    assert!(result.is_err() || result.is_ok_and(|report| !report.ok));
    assert!(
        events
            .iter()
            .any(|event| matches!(event, FrontendEvent::OutputTruncated { .. }))
    );
}

#[test]
fn ollama_tool_round_preserves_same_name_result_association() {
    let first = format!(
        "{}\n",
        json!({"message":{"role":"assistant","content":"","tool_calls":[{"function":{"index":2,"name":"Effect","arguments":{"value":1}}},{"function":{"index":7,"name":"Effect","arguments":{"value":2}}}]},"done":true,"done_reason":"stop"})
    );
    let last = format!(
        "{}\n",
        json!({"message":{"role":"assistant","content":"complete"},"done":true,"done_reason":"stop"})
    );
    let provider = Provider::new(vec![Reply::complete(first), Reply::complete(last)]);
    let home = Home::new();
    let mut executor = Executor::default();
    let mut transcript = Vec::new();
    let report = orbit_engine::run_turn(
        &home.0,
        &config(&provider, ProviderKind::Ollama),
        &TurnOptions::default(),
        "perform both effects",
        &mut transcript,
        &mut executor,
        &CancelToken::new(),
        &mut |_| {},
    )
    .unwrap();
    assert!(report.ok && !report.interrupted);
    assert_eq!(report.final_text, "complete");
    assert_eq!(provider.count(), 2);
    assert_eq!(executor.calls.len(), 2);
    assert_ne!(executor.calls[0].0, executor.calls[1].0);
    let requests = provider.requests.lock().unwrap();
    let messages = requests[1]["messages"].as_array().unwrap();
    let results: Vec<_> = messages
        .iter()
        .filter(|message| message["role"] == "tool")
        .collect();
    assert_eq!(results.len(), 2);
    for (result, (id, name)) in results.iter().zip(&executor.calls) {
        assert_eq!(result["tool_name"], name.as_str());
        assert_eq!(
            serde_json::from_str::<Value>(result["content"].as_str().unwrap()).unwrap(),
            json!({"ok":true,"effect":id})
        );
    }
}

#[test]
fn interrupted_openai_cancellation_retains_partial_text_without_effects() {
    let provider = Provider::new(vec![Reply::complete(openai_calls(
        vec![call(0, "effect-1", "Effect", "{}")],
        Some("tool_calls"),
        true,
    ))]);
    let home = Home::new();
    let cancel = CancelToken::new();
    let mut executor = Executor::default();
    let mut transcript = Vec::new();
    let mut events = Vec::new();
    let report = orbit_engine::run_turn(
        &home.0,
        &config(&provider, ProviderKind::OpenAiCompatible),
        &TurnOptions {
            max_attempts: 3,
            ..Default::default()
        },
        "cancel work",
        &mut transcript,
        &mut executor,
        &cancel,
        &mut |event| {
            if matches!(&event, FrontendEvent::TextDelta { .. }) {
                cancel.cancel();
            }
            events.push(event);
        },
    )
    .unwrap();
    assert!(report.interrupted && !report.ok);
    no_effects(&provider, &executor, &transcript, &events);
    assert_eq!(transcript.last().unwrap().content, "visible partial");
}
