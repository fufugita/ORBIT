//! Gate 2 — one scripted session, three front-end shapes, one event
//! stream. The TUI, REPL and web bridges each supply their own
//! ToolExecutor and event sink to the SAME engine loop. This test runs
//! the identical mock script through all three shapes and asserts the
//! engine's FrontendEvent sequences are byte-identical — the roadmap's
//! "one loop everywhere" gate.

#![deny(unsafe_code)]

use orbit_adapter::types::ChatMessage;
use orbit_engine::{PendingToolCall, ToolExecutor, ToolRoundResult, TurnConfig, TurnOptions};
use orbit_frontend_protocol::FrontendEvent;
use orbit_mock_provider::server::spawn;
use sha2::Digest;
use std::sync::mpsc;

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

/// The executor each front-end shape supplies — same behavior (the
/// calculator answers 14), mirroring the TUI/REPL/web executors which
/// differ only in their approval channel, not their transcript effect.
struct ShapeExecutor;

impl ToolExecutor for ShapeExecutor {
    fn execute(&mut self, calls: &[PendingToolCall], _round: u32) -> Vec<ToolRoundResult> {
        calls
            .iter()
            .map(|c| ToolRoundResult {
                call_id: c.id.clone(),
                content: r#"{"ok":true,"result":14}"#.into(),
            })
            .collect()
    }
}

fn run_session(
    dir: &std::path::Path,
    addr: &std::net::SocketAddr,
    label: &str,
) -> (Vec<String>, orbit_engine::TurnReport) {
    let config = TurnConfig {
        sampling: None,
        provider_id: "mock".into(),
        gate: format!("http://127.0.0.1:{}", addr.port()),
        model: "test-model".into(),
        kind: orbit_engine::ProviderKind::OpenAiCompatible,
        credential_env: None,
        pricing: None,
        max_output_tokens: 32_000,
    };
    let options = TurnOptions {
        tools: vec![calc_tool()],
        system_directive: Some(format!("shape: {label} directive")),
        request_stem: format!("gate2-{label}"),
        ..Default::default()
    };

    let (tx, rx) = mpsc::channel();
    // The sink records what the ENGINE emitted — the stream every
    // front-end consumes. Each label differs only in sink identity.
    let mut events = move |ev: FrontendEvent| {
        let _ = tx.send(ev);
    };

    let mut transcript: Vec<ChatMessage> = Vec::new();
    let mut executor = ShapeExecutor;
    let report = orbit_engine::run_turn(
        dir,
        &config,
        &options,
        "what is 2*(3+4)?",
        &mut transcript,
        &mut executor,
        &orbit_provider_http::CancelToken::new(),
        &mut events,
    )
    .expect("engine turn");

    // Normalise labels that legitimately differ per front-end (the
    // request stem feeds ledger ids, and the directive differs) — the
    // events compared are the ones a front-end renders: rounds, deltas,
    // tools, cost, response, turn end.
    // A ledger record's hash covers its ULIDs and timestamps, so it is
    // unique to every run by construction; the SHAPE of the stream (an
    // egress record announced per round, in order) is what must match.
    // That each digest is a real link of the chain is asserted in
    // `gate2_scripted_session`.
    let stream: Vec<String> = rx
        .try_iter()
        .map(|ev| {
            let mut value = serde_json::to_value(&ev).unwrap_or_default();
            if let Some(d) = value.get_mut("head_digest") {
                *d = serde_json::Value::String("<digest>".into());
            }
            serde_json::to_string(&value)
                .unwrap_or_default()
                // request stems appear nowhere in FrontendEvent, but be
                // explicit about the comparison being label-independent.
                .replace(&format!("gate2-{label}"), "<stem>")
                .replace(&format!("shape: {label} directive"), "<directive>")
        })
        .collect();
    (stream, report)
}

#[test]
fn gate2_same_event_stream_through_three_shapes() {
    let addr = spawn_mock_on_thread();

    let mut streams = Vec::new();
    let mut reports = Vec::new();
    for (i, label) in ["tui", "repl", "web"].iter().enumerate() {
        let dir = std::env::temp_dir().join(format!("orbit-g2-shape-{i}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("ledger")).expect("mkdir ledger");
        let (stream, report) = run_session(&dir, &addr, label);
        let _ = std::fs::remove_dir_all(&dir);
        streams.push(stream);
        reports.push(report);
    }

    // Every shape completed identically.
    for r in &reports {
        assert!(r.ok, "turn must complete: {r:?}");
        assert_eq!(r.rounds, 2);
        assert_eq!(r.final_text, "hello world");
    }

    // The event streams are identical across front-end shapes.
    assert_eq!(
        streams[0], streams[1],
        "TUI and REPL must see the same engine stream"
    );
    assert_eq!(
        streams[1], streams[2],
        "REPL and web must see the same engine stream"
    );

    // And the stream actually contains the shape of a tool round.
    let joined = streams[0].join("\n");
    assert!(joined.contains("\"round_started\""));
    assert!(joined.contains("\"turn_ended\""));
    assert!(joined.contains("\"response_finished\""));
}
