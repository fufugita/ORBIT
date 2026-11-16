//! The engine scopes the turn's cancel token through lifecycle hooks and
//! each round's tools, restoring the previous token afterwards, so a
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
    model: String,
    gate: String,
}

impl ToolExecutor for StackExecutor {
    fn begin_turn(&mut self, config: &orbit_engine::TurnConfig) {
        self.log.push("turn");
        self.model = config.model.clone();
        self.gate = config.gate.clone();
    }

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
        billing: None,
        sampling: None,
        effort: None,
        supported_efforts: None,
        first_byte_timeout_ms: None,
        idle_timeout_ms: None,
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
        model: String::new(),
        gate: String::new(),
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
        ["begin", "turn", "begin", "execute", "end", "end"],
        "the turn token covers the whole operation and the nested tools"
    );
    assert_eq!(executor.model, "test-model", "the turn's own model");
    assert!(
        executor.gate.starts_with("http://127.0.0.1:"),
        "the turn's own gateway: {}",
        executor.gate
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

#[test]
fn prompt_and_failure_hooks_share_the_turn_scope_and_restore_the_parent_without_a_provider() {
    use orbit_engine::hooks::{HandlerRunner, HookEvent, HookOutcome, Hooks};
    use std::sync::{Arc, Mutex};

    struct LifecycleExecutor {
        stack: Arc<Mutex<Vec<CancelToken>>>,
        cancel: CancelToken,
        observed: Arc<Mutex<Vec<(String, bool)>>>,
    }
    impl ToolExecutor for LifecycleExecutor {
        fn execute(&mut self, _: &[PendingToolCall], _: u32) -> Vec<ToolRoundResult> {
            panic!("a blocked prompt must never execute tools");
        }

        fn begin_cancel_scope(&mut self, token: &CancelToken) {
            self.stack.lock().unwrap().push(token.clone());
        }

        fn end_cancel_scope(&mut self) {
            self.stack.lock().unwrap().pop();
        }

        fn hook_handler_runner(&self) -> Option<Arc<HandlerRunner>> {
            let stack = self.stack.clone();
            let cancel = self.cancel.clone();
            let observed = self.observed.clone();
            Some(Arc::new(move |_, payload| {
                let event = payload["hook_event_name"].as_str().unwrap();
                let current = stack.lock().unwrap().last().unwrap().is_cancelled();
                observed.lock().unwrap().push((event.into(), current));
                if event == "UserPromptSubmit" {
                    assert!(!current, "the turn must override the cancelled parent");
                    cancel.cancel();
                    HookOutcome {
                        exit_code: 2,
                        stderr: "blocked before provider dispatch".into(),
                        ..HookOutcome::default()
                    }
                } else {
                    assert!(current, "StopFailure must retain the turn's cancellation");
                    HookOutcome::default()
                }
            }))
        }
    }

    let dir = std::env::temp_dir().join(format!(
        "orbit-cancel-lifecycle-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("settings.toml"),
        "[[hooks]]\nevent = \"UserPromptSubmit\"\nprompt = \"check\"\n\
         [[hooks]]\nevent = \"StopFailure\"\nprompt = \"check\"\n",
    )
    .unwrap();
    let parent = CancelToken::new();
    parent.cancel();
    let stack = Arc::new(Mutex::new(vec![parent]));
    let observed = Arc::new(Mutex::new(Vec::new()));
    let cancel = CancelToken::new();
    let mut executor = LifecycleExecutor {
        stack: stack.clone(),
        cancel: cancel.clone(),
        observed: observed.clone(),
    };
    let _parent_runner = orbit_engine::hooks::handler_runner_scope(Arc::new(|_, _| HookOutcome {
        stdout: "parent runner".into(),
        ..HookOutcome::default()
    }));
    let config = orbit_engine::TurnConfig {
        billing: None,
        sampling: None,
        effort: None,
        supported_efforts: None,
        first_byte_timeout_ms: None,
        idle_timeout_ms: None,
        provider_id: "never-dispatched".into(),
        gate: "invalid://no-provider".into(),
        model: "test-model".into(),
        kind: orbit_engine::ProviderKind::OpenAiCompatible,
        credential_env: None,
        pricing: None,
        max_output_tokens: 1_024,
    };
    let mut transcript = Vec::new();
    let result = orbit_engine::run_turn(
        &dir,
        &config,
        &orbit_engine::TurnOptions::default(),
        "blocked",
        &mut transcript,
        &mut executor,
        &cancel,
        &mut |_| {},
    );
    assert!(
        result
            .unwrap_err()
            .contains("blocked before provider dispatch")
    );
    assert!(transcript.is_empty());
    assert_eq!(
        *observed.lock().unwrap(),
        [
            ("UserPromptSubmit".into(), false),
            ("StopFailure".into(), true)
        ]
    );
    assert_eq!(stack.lock().unwrap().len(), 1);
    assert!(stack.lock().unwrap().last().unwrap().is_cancelled());
    let after = Hooks::load(&dir, false).fire(HookEvent::StopFailure, &serde_json::json!({}));
    assert_eq!(after.len(), 1);
    assert_eq!(after[0].stdout, "parent runner");
    std::fs::remove_dir_all(dir).unwrap();
}
