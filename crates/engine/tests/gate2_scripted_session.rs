//! Gate 2 — one engine, one event stream. A scripted session runs
//! through the engine against the in-process mock provider: round 0
//! produces a fragmented calculator tool call, the executor answers
//! it, round 1 produces the final text. The engine's event stream
//! must contain the rounds, the tool execution and the terminal
//! response, in order — the same events every front-end renders.

#![deny(unsafe_code)]

use orbit_adapter::types::ChatMessage;
use orbit_engine::{PendingToolCall, ToolExecutor, ToolRoundResult};
use orbit_mock_provider::server::spawn;
use sha2::Digest;
use std::sync::mpsc;

fn calc_tool() -> orbit_adapter::types::ToolDefinition {
    let name = "calculator";
    let description = "Evaluate a math expression";
    let parameters = serde_json::json!({
        "type": "object",
        "properties": { "expression": { "type": "string" } },
        "required": ["expression"]
    });
    let mut bytes = Vec::new();
    bytes.extend_from_slice(name.as_bytes());
    bytes.extend_from_slice(description.as_bytes());
    bytes.extend_from_slice(
        serde_json::to_string(&parameters)
            .unwrap_or_default()
            .as_bytes(),
    );
    orbit_adapter::types::ToolDefinition {
        name: name.into(),
        description: description.into(),
        parameters,
        schema_digest: orbit_adapter::types::Sha256Digest(hex::encode(sha2::Sha256::digest(
            &bytes,
        ))),
    }
}

/// Records every FrontendEvent the engine emits.
struct RecordingExecutor {
    seen_calc_call: bool,
}

impl ToolExecutor for RecordingExecutor {
    fn execute(&mut self, calls: &[PendingToolCall], _round: u32) -> Vec<ToolRoundResult> {
        calls
            .iter()
            .map(|c| {
                assert_eq!(c.name, "calculator", "scripted round calls calculator");
                self.seen_calc_call = true;
                ToolRoundResult {
                    call_id: c.id.clone(),
                    content: r#"{"ok":true,"result":14}"#.into(),
                }
            })
            .collect()
    }
}

#[test]
fn gate2_scripted_session_through_engine() {
    // The mock runs on its own thread+runtime; the engine's dispatch
    // builds its own runtime (production callers are sync threads), so
    // the test body must not sit inside a tokio runtime.
    let addr = spawn_mock_on_thread();

    // A real engine home: trust + ledger dirs the dispatch pipeline
    // writes into (the ledger writer creates its own files; the trust
    // root is not required for dispatch itself).
    let dir = std::env::temp_dir().join(format!("orbit-gate2-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("ledger")).expect("mkdir ledger");

    let config = orbit_engine::TurnConfig {
        sampling: None,
        provider_id: "mock".into(),
        gate: format!("http://127.0.0.1:{}", addr.port()),
        model: "test-model".into(),
        kind: orbit_engine::ProviderKind::OpenAiCompatible,
        credential_env: None,
        pricing: None,
        max_output_tokens: 32_000,
    };
    let options = orbit_engine::TurnOptions {
        tools: vec![calc_tool()],
        request_stem: "gate2-test".into(),
        ..Default::default()
    };

    let (tx, rx) = mpsc::channel::<orbit_frontend_protocol::FrontendEvent>();
    let mut events = move |ev: orbit_frontend_protocol::FrontendEvent| {
        let _ = tx.send(ev);
    };

    let mut transcript: Vec<ChatMessage> = Vec::new();
    let mut executor = RecordingExecutor {
        seen_calc_call: false,
    };

    let report = orbit_engine::run_turn(
        &dir,
        &config,
        &options,
        "what is 2*(3+4)?",
        &mut transcript,
        &mut executor,
        &orbit_provider_http::CancelToken::new(),
        &mut events,
    )
    .expect("engine turn");

    assert!(report.ok, "turn must complete: {:?}", report);
    assert!(executor.seen_calc_call, "calculator must have run");
    assert_eq!(report.rounds, 2, "round 0 tool-call + round 1 final");

    // The transcript: user, assistant(tool_calls), tool, assistant.
    assert_eq!(transcript.len(), 4);
    assert!(matches!(
        transcript[0].role,
        orbit_adapter::types::ChatRole::User
    ));
    assert!(
        transcript[1].tool_calls.is_some(),
        "assistant round 0 carries calls"
    );
    assert!(
        transcript[2].tool_call_id.is_some(),
        "tool result carries the call id"
    );
    assert!(matches!(
        transcript[3].role,
        orbit_adapter::types::ChatRole::Assistant
    ));
    assert_eq!(transcript[3].content, "hello world");

    // The event stream: rounds started, tool ran, response finished,
    // turn ended — in order, same events every front-end renders.
    let collected: Vec<_> = rx.try_iter().collect();
    let round_started = collected
        .iter()
        .filter(|e| {
            matches!(
                e,
                orbit_frontend_protocol::FrontendEvent::RoundStarted { .. }
            )
        })
        .count();
    assert_eq!(round_started, 2, "two RoundStarted events");
    assert!(collected.iter().any(|e| matches!(
        e,
        orbit_frontend_protocol::FrontendEvent::TurnEnded { ok: true, .. }
    )));
    assert!(collected.iter().any(|e| matches!(
        e,
        orbit_frontend_protocol::FrontendEvent::ResponseFinished { .. }
    )));

    // The proof surface: each round announces the egress record it wrote
    // BEFORE the request left, and the digest is a real link of the
    // verified chain (not a number the UI made up), in order.
    let egress: Vec<(u64, String)> = collected
        .iter()
        .filter_map(|e| match e {
            orbit_frontend_protocol::FrontendEvent::LedgerAppended {
                record_count,
                head_digest,
                kind,
                ..
            } if kind == "egress" => Some((*record_count, head_digest.clone())),
            _ => None,
        })
        .collect();
    assert_eq!(egress.len(), 2, "one egress record per round: {egress:?}");
    let (records, _head) = orbit_ledger::verify_ledger(&dir.join("ledger")).expect("ledger");
    for (count, digest) in &egress {
        let pos = records
            .iter()
            .position(|r| r.self_hash == *digest)
            .unwrap_or_else(|| panic!("{digest} is not in the ledger"));
        assert!(
            matches!(
                records[pos].record.event,
                orbit_ledger::LedgerEvent::EgressIntent(_)
            ),
            "the announced record is the EgressIntent"
        );
        assert_eq!(
            *count,
            (pos + 1) as u64,
            "the total is the ledger's own count at that point"
        );
    }
    assert!(egress[0].0 < egress[1].0, "the chain only grows");

    // This provider reports usage, and the row says what each round used.
    let summaries: Vec<&str> =
        collected
            .iter()
            .filter_map(|e| match e {
                orbit_frontend_protocol::FrontendEvent::LedgerAppended {
                    kind, summary, ..
                } if kind == "egress" => Some(summary.as_str()),
                _ => None,
            })
            .collect();
    assert_eq!(summaries.len(), 2);
    for row in &summaries {
        assert!(
            row.starts_with("test-model \u{b7} ") && row.contains(" in / "),
            "the egress row names the model and the usage: {row:?}"
        );
    }

    let _ = std::fs::remove_dir_all(&dir);
}

/// Spawn the mock provider on a dedicated thread with its own runtime;
/// returns its bound address.
fn spawn_mock_on_thread() -> std::net::SocketAddr {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::Builder::new()
        .name("mock-provider".into())
        .spawn(move || {
            let rt = tokio::runtime::Runtime::new().expect("mock runtime");
            rt.block_on(async move {
                let (addr, _state, handle) = spawn().await.expect("mock spawn");
                tx.send(addr).expect("send addr");
                let _ = handle.await;
            });
        })
        .expect("spawn mock thread");
    rx.recv().expect("mock address")
}

/// The engine's guard: a turn that never stops calling tools is
/// stopped by max_rounds with a visible reason, not an infinite loop.
#[test]
fn gate2_round_guard_stops_runaway() {
    let addr = spawn_mock_on_thread();
    let dir = std::env::temp_dir().join(format!("orbit-gate2-guard-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("ledger")).expect("mkdir ledger");

    let config = orbit_engine::TurnConfig {
        sampling: None,
        provider_id: "mock".into(),
        gate: format!("http://127.0.0.1:{}", addr.port()),
        model: "test-model".into(),
        kind: orbit_engine::ProviderKind::OpenAiCompatible,
        credential_env: None,
        pricing: None,
        max_output_tokens: 32_000,
    };
    // Advertise the calculator tool: the mock answers EVERY round with
    // a calculator call when tools are present and no tool result is in
    // the history... except our executor DOES append results, and the
    // mock then returns success text. So to force a runaway we would
    // need a mock that never stops. Instead: assert the guard logic on
    // a config with max_rounds = 1 — the turn ends with the guard
    // message after exactly one round.
    let options = orbit_engine::TurnOptions {
        tools: vec![calc_tool()],
        max_rounds: 1,
        request_stem: "gate2-guard".into(),
        ..Default::default()
    };

    let mut transcript: Vec<ChatMessage> = Vec::new();
    let mut executor = RecordingExecutor {
        seen_calc_call: false,
    };
    let mut events = |_ev: orbit_frontend_protocol::FrontendEvent| {};

    let report = orbit_engine::run_turn(
        &dir,
        &config,
        &options,
        "loop forever",
        &mut transcript,
        &mut executor,
        &orbit_provider_http::CancelToken::new(),
        &mut events,
    )
    .expect("engine turn");

    assert!(!report.ok, "guard must stop the turn");
    assert_eq!(report.rounds, 1, "exactly one round before the guard");

    let _ = std::fs::remove_dir_all(&dir);
}
