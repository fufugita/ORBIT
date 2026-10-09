//! The engine hands each round's executor the turn's cancel token and
//! takes the previous one back afterwards (stack discipline), so a
//! nested turn — a subagent — cannot clear its parent's Esc.

#![deny(unsafe_code)]

use orbit_adapter::types::ChatMessage;
use orbit_engine::{PendingToolCall, ToolExecutor, ToolRoundResult};
use orbit_mock_provider::server::spawn;
use orbit_provider_http::CancelToken;
use sha2::Digest;

fn calc_tool() -> orbit_adapter::types::ToolDefinition {
    let (name, description) = ("calculator", "Evaluate a math expression");
    let parameters = serde_json::json!({
        "type": "object",
        "properties": { "expression": { "type": "string" } },
        "required": ["expression"]
    });
    let mut bytes = Vec::new();
    bytes.extend_from_slice(name.as_bytes());
    bytes.extend_from_slice(description.as_bytes());
    bytes.extend_from_slice(serde_json::to_string(&parameters).unwrap().as_bytes());
    orbit_adapter::types::ToolDefinition {
        name: name.into(),
        description: description.into(),
        parameters,
        schema_digest: orbit_adapter::types::Sha256Digest(hex::encode(sha2::Sha256::digest(
            &bytes,
        ))),
    }
}

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

/// Keeps a stack of tokens, like an executor's tool context does.
struct StackExecutor {
    stack: Vec<CancelToken>,
    /// A handle on the turn's token, so the test can cancel it from
    /// inside `execute` and see whether the stack's top really is it.
    turn: CancelToken,
    log: Vec<&'static str>,
    top_cancelled_inside: Option<bool>,
}

impl ToolExecutor for StackExecutor {
    fn execute(&mut self, calls: &[PendingToolCall], _round: u32) -> Vec<ToolRoundResult> {
        self.log.push("execute");
        // The current token is the turn's: cancelling the turn shows
        // through the stack's top, and not before.
        assert_eq!(self.stack.last().map(|t| t.is_cancelled()), Some(false));
        self.turn.cancel();
        self.top_cancelled_inside = self.stack.last().map(|t| t.is_cancelled());
        calls
            .iter()
            .map(|c| ToolRoundResult {
                call_id: c.id.clone(),
                content: r#"{"ok":true,"result":14}"#.into(),
            })
            .collect()
    }

    fn begin_cancel_scope(&mut self, token: &CancelToken) {
        self.log.push("begin");
        self.stack.push(token.clone());
    }

    fn end_cancel_scope(&mut self) {
        self.log.push("end");
        self.stack.pop();
    }
}

#[test]
fn the_engine_scopes_the_turn_token_around_each_rounds_tools() {
    let addr = spawn_mock_on_thread();
    let dir = std::env::temp_dir().join(format!("orbit-cancel-hook-{}", std::process::id()));
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
        request_stem: "cancel-hook".into(),
        ..Default::default()
    };

    // The executor starts with a "parent" turn's token already current.
    let parent = CancelToken::new();
    parent.cancel(); // marks it, so a restore is recognisable
    let turn = CancelToken::new();
    let mut executor = StackExecutor {
        stack: vec![parent],
        turn: turn.clone(),
        log: Vec::new(),
        top_cancelled_inside: None,
    };
    let mut transcript: Vec<ChatMessage> = Vec::new();
    let mut events = |_ev: orbit_frontend_protocol::FrontendEvent| {};
    // Round 0 calls the tool; cancelling inside it interrupts the turn
    // at the top of round 1 — which is fine, the hook is what we test.
    let report = orbit_engine::run_turn(
        &dir,
        &config,
        &options,
        "what is 2*(3+4)?",
        &mut transcript,
        &mut executor,
        &turn,
        &mut events,
    )
    .expect("engine turn");

    assert_eq!(
        executor.log,
        ["begin", "execute", "end"],
        "the turn's token is current for the round's tools, then it is not"
    );
    assert_eq!(
        executor.top_cancelled_inside,
        Some(true),
        "the stack's top was the TURN's token during execute"
    );
    assert_eq!(executor.stack.len(), 1, "the scope closed: balanced");
    assert_eq!(
        executor.stack.last().map(|t| t.is_cancelled()),
        Some(true),
        "and the parent's token (marked cancelled) is current again"
    );
    assert!(
        report.interrupted,
        "the cancel inside execute ends the turn"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
