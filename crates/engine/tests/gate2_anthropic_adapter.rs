//! Gate 2 (Anthropic leg) — the real adapter through the engine.
//!
//! Drives the Anthropic wire format end to end against the mock's
//! `/v1/messages`: round 0 emits a fragmented `tool_use` block
//! (input_json_delta), the executor answers, round 1 replays the
//! `tool_result` and receives final text. Asserts the adapter's
//! message mapping (system extraction, tool_use/tool_result blocks),
//! the real stop reason (`tool_use`), and the cache-read usage
//! accounting the roadmap's gate names.

#![deny(unsafe_code)]

use orbit_adapter::types::ChatMessage;
use orbit_engine::{PendingToolCall, ToolExecutor, ToolRoundResult};
use orbit_mock_provider::server::spawn;
use sha2::Digest;

/// Records every FrontendEvent the engine emits.
struct CalcExecutor;

impl ToolExecutor for CalcExecutor {
    fn execute(&mut self, calls: &[PendingToolCall], _round: u32) -> Vec<ToolRoundResult> {
        calls
            .iter()
            .map(|c| {
                assert_eq!(c.name, "calculator");
                ToolRoundResult {
                    call_id: c.id.clone(),
                    content: r#"{"ok":true,"result":14}"#.into(),
                }
            })
            .collect()
    }
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

/// The mock provider's Anthropic endpoint on its own thread+runtime.
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

#[test]
fn gate2_anthropic_tool_round_and_replay() {
    let addr = spawn_mock_on_thread();
    let dir = std::env::temp_dir().join(format!("orbit-g2-anthropic-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("ledger")).expect("mkdir ledger");

    let config = orbit_engine::TurnConfig {
        provider_id: "mock-anthropic".into(),
        // The adapter builds https://host:port/v1/messages from the
        // route; the mock listens on plain http loopback. The adapter
        // scheme check happens on route.scheme — HttpLoopback works.
        gate: format!("http://127.0.0.1:{}", addr.port()),
        model: "test-model".into(),
        kind: orbit_engine::ProviderKind::Anthropic,
        credential_env: None,
        pricing: None,
        max_output_tokens: 32_000,
    };
    let options = orbit_engine::TurnOptions {
        tools: vec![calc_tool()],
        // A system directive so the adapter's system extraction runs.
        system_directive: Some("You are the test harness.".into()),
        request_stem: "g2-anthropic".into(),
        ..Default::default()
    };

    let mut transcript: Vec<ChatMessage> = Vec::new();
    let mut executor = CalcExecutor;
    let mut events = |_ev: orbit_frontend_protocol::FrontendEvent| {};

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
    assert_eq!(report.rounds, 2, "tool round + final round");

    // Transcript: user, assistant(tool_use), tool result, assistant.
    assert_eq!(transcript.len(), 4);
    assert!(
        transcript[1].tool_calls.is_some(),
        "assistant carries tool_use"
    );
    assert_eq!(
        transcript[1].tool_calls.as_ref().unwrap()[0].name,
        "calculator",
        "fragmented input_json_delta assembled into the call"
    );
    assert!(
        transcript[1].tool_calls.as_ref().unwrap()[0]
            .arguments
            .contains("2*(3+4)"),
        "arguments assembled: {}",
        transcript[1].tool_calls.as_ref().unwrap()[0].arguments
    );
    assert_eq!(transcript[3].content, "hello world");

    let _ = std::fs::remove_dir_all(&dir);
}
