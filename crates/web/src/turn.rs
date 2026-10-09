//! The turn thread — drives `run_turn` + tool loop for the browser front-end.
//!
//! Same shape as the Go bridge's main loop (go_bridge.rs): wait for actions,
//! run a turn per `prompt`, park on the action channel for approvals, save
//! the session after every turn. Events broadcast to all SSE peers.

use crate::{make_channels, router, BridgeState, WebApprovalChannel};
use orbit_adapter::types::{ChatMessage, ChatRole};
use orbit_cli::tui_worker::TuiTurnConfig;
use std::sync::{mpsc, Arc, Mutex};

/// Server configuration (from `orbit web` flags).
#[derive(Clone)]
pub struct BridgeConfig {
    /// Turn configuration (home, session, model, provider, resume state).
    pub turn: TuiTurnConfig,
    /// Bind address. Loopback by default; non-loopback requires a token.
    pub bind: String,
    /// Port.
    pub port: u16,
    /// Bearer token required when binding non-loopback.
    pub token: Option<String>,
}

/// Run the web bridge until the turn thread exits (browser sends `quit`).
/// Returns the process exit code.
pub fn run_bridge(config: BridgeConfig) -> i32 {
    // Non-loopback binds require a token (docs/browser-harness.md §Security).
    let loopback = config.bind == "127.0.0.1" || config.bind == "localhost" || config.bind == "::1";
    let required_token = if loopback {
        None
    } else {
        Some(config.token.clone().unwrap_or_default())
    };
    let (state, action_rx) = make_channels(required_token);

    // The turn thread: consumes actions, runs turns, broadcasts events.
    let turn_state = state.clone();
    let turn_config = config.turn.clone();
    let action_rx_turn = action_rx.clone();
    let turn_handle = std::thread::Builder::new()
        .name("orbit-web-turn".into())
        .spawn(move || turn_loop(turn_state, turn_config, action_rx_turn))
        .expect("spawn turn thread");

    // Identity first, so the browser status bar is populated on load.
    state.emit(
        "identity",
        serde_json::json!({
            "model": config.turn.model,
            "provider": config.turn.provider_id,
            "session": config.turn.session_id.chars().take(8).collect::<String>(),
            "session_id": config.turn.session_id,
        }),
    );

    let addr = format!("{}:{}", config.bind, config.port);
    println!("orbit-web: http://{addr}");
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    let router = router(state.clone());
    rt.block_on(async move {
        let listener = tokio::net::TcpListener::bind(&addr)
            .await
            .unwrap_or_else(|e| panic!("bind {addr}: {e}"));
        axum::serve(listener, router).await.expect("axum serve");
    });
    let _ = turn_handle.join();
    0
}

/// The protocol wire name of a FrontendEvent (its serde tag) — used as
/// the SSE event kind so the browser sees protocol names verbatim.
fn protocol_kind(ev: &orbit_frontend_protocol::FrontendEvent) -> &'static str {
    use orbit_frontend_protocol::FrontendEvent as E;
    match ev {
        E::TextDelta { .. } => "text_delta",
        E::ResponseFinished { .. } => "response_finished",
        E::ToolStarted { .. } => "tool_started",
        E::ToolFinished { .. } => "tool_finished",
        E::CostUpdated { .. } => "cost_updated",
        E::WorkspaceUpdate(_) => "workspace_update",
        E::ApprovalRequested { .. } => "approval_requested",
        E::ApprovalResolved { .. } => "approval_resolved",
        E::ConnectionChanged(_) => "connection_changed",
        E::Identity(_) => "identity",
        E::Error { .. } => "error",
        E::Status { .. } => "status",
        E::RoundStarted { .. } => "round_started",
        E::TurnEnded { .. } => "turn_ended",
        E::Retrying { .. } => "retrying",
        E::OutputTruncated { .. } => "output_truncated",
        E::Compacting { .. } => "compacting",
        E::Compacted { .. } => "compacted",
        E::ToolStartedFull { .. } => "tool_started_full",
        E::ToolOutput { .. } => "tool_output",
        E::ToolFinishedFull { .. } => "tool_finished_full",
        E::FileChanged { .. } => "file_changed",
        E::SubagentStarted { .. } => "subagent_started",
        E::SubagentProgress { .. } => "subagent_progress",
        E::SubagentFinished { .. } => "subagent_finished",
        E::ToolDenied { .. } => "tool_denied",
        E::ModeChanged { .. } => "mode_changed",
        E::Usage { .. } => "usage",
        E::LedgerAppended { .. } => "ledger_appended",
    }
}

/// The turn loop — same structure as go_bridge's main loop.
fn turn_loop(
    state: BridgeState,
    mut config: TuiTurnConfig,
    action_rx: Arc<Mutex<mpsc::Receiver<serde_json::Value>>>,
) {
    use orbit_cli::tool_runtime::AutoGrants;

    let mut transcript: Vec<ChatMessage> = config.initial_transcript.clone();
    let mut turns = config.initial_turns;
    let mut cum_input = config.initial_input_tokens;
    let mut cum_output = config.initial_output_tokens;
    let mut cum_cost = config.initial_cost_microcents;
    // D8: session-scoped R-grants — one registry for the whole session.
    let mut auto_grants = AutoGrants::new();

    // Restore banner for resumed sessions.
    if !config.initial_transcript.is_empty() {
        state.emit(
            "resumed",
            serde_json::json!({
                "turns": config.initial_turns,
                "input_tokens": cum_input,
                "output_tokens": cum_output,
                "cost_microcents": cum_cost,
            }),
        );
    }

    loop {
        let action = {
            let Ok(guard) = action_rx.lock() else { return };
            match guard.recv() {
                Ok(a) => a,
                Err(_) => return, // all WS peers gone
            }
        };
        match action.get("type").and_then(|t| t.as_str()) {
            Some("prompt") => {
                let text = action
                    .get("text")
                    .and_then(|t| t.as_str())
                    .unwrap_or("")
                    .to_string();
                if text.trim().is_empty() {
                    continue;
                }
                let token = orbit_provider_http::CancelToken::new();
                if let Ok(mut g) = state.cancel_slot.lock() {
                    *g = Some(token.clone());
                }
                let result = run_web_turn(
                    &state,
                    &config,
                    &mut transcript,
                    &text,
                    &action_rx,
                    &token,
                    &mut auto_grants,
                );
                if let Ok(mut g) = state.cancel_slot.lock() {
                    *g = None;
                }
                let (ok, input, output, cost) = match result {
                    Ok(x) => x,
                    Err(e) => {
                        state.emit("error", serde_json::json!({ "message": e }));
                        state.emit("cancelled", serde_json::json!({}));
                        continue;
                    }
                };
                turns = turns.saturating_add(1);
                cum_input = cum_input.saturating_add(input);
                cum_output = cum_output.saturating_add(output);
                cum_cost = cum_cost.saturating_add(cost);
                // MD gate 2: the engine's turn_ended (with the real
                // rounds count) already crossed through the adapter.
                // `cancelled` stays as a browser service nicety.
                if !ok {
                    state.emit("cancelled", serde_json::json!({}));
                }
                // D9: cumulative save, same as the TUI worker.
                let sf = orbit_cli::sessions::SessionFile::from_chat(
                    &config.session_id,
                    &config.model,
                    &config.gate,
                    &config.provider_id,
                    &transcript,
                    turns,
                    cum_input,
                    cum_output,
                    cum_cost,
                );
                if let Err(e) = orbit_cli::sessions::save_session(&config.home, &sf) {
                    state.emit(
                        "error",
                        serde_json::json!({ "message": format!("session not saved: {e}") }),
                    );
                }
            }
            Some("set_model") => {
                let model = action.get("model").and_then(|m| m.as_str()).unwrap_or("");
                if model.is_empty() {
                    continue;
                }
                config.model = model.to_string();
                state.emit("model_changed", serde_json::json!({ "model": model }));
            }
            Some("list_models") => {
                let cfg =
                    orbit_cli::config::ProvidersConfig::load(&config.home).unwrap_or_default();
                let models: Vec<serde_json::Value> = cfg
                    .all_models()
                    .into_iter()
                    .map(|(p, m)| serde_json::json!({ "provider": p, "model": m }))
                    .collect();
                state.emit("models", serde_json::json!({ "models": models }));
            }
            Some("list_sessions") => {
                let list = orbit_cli::sessions::list_sessions(&config.home).unwrap_or_default();
                let sessions: Vec<serde_json::Value> = list
                    .iter()
                    .map(|s| {
                        serde_json::json!({
                            "session_id": s.session_id,
                            "model": s.model,
                            "turns": s.turns,
                            "updated_at": s.updated_at,
                        })
                    })
                    .collect();
                state.emit("sessions", serde_json::json!({ "sessions": sessions }));
            }
            Some("resume") => {
                let id = action.get("id").and_then(|i| i.as_str()).unwrap_or("");
                match orbit_cli::sessions::load_session(&config.home, id) {
                    Ok(s) => {
                        transcript = s.to_transcript();
                        turns = s.turns;
                        config.session_id = s.session_id.clone();
                        config.model = s.model.clone();
                        cum_input = s.input_tokens;
                        cum_output = s.output_tokens;
                        cum_cost = s.cost_microcents;
                        auto_grants = AutoGrants::new(); // D8: new session clears grants
                        state.emit(
                            "transcript",
                            serde_json::json!({
                                // Curated like the TUI's resume path: tool
                                // rounds collapse to a display-safe summary
                                // line, tool-result JSON never renders.
                                "messages": transcript.iter().filter_map(msg_to_json).collect::<Vec<_>>(),
                                "turns": turns,
                                "input_tokens": cum_input,
                                "output_tokens": cum_output,
                                "cost_microcents": cum_cost,
                                "session_id": s.session_id,
                            }),
                        );
                    }
                    Err(e) => {
                        state.emit(
                            "error",
                            serde_json::json!({ "message": format!("cannot resume {id}: {e}") }),
                        );
                    }
                }
            }
            Some("quit") => {
                std::process::exit(0);
            }
            _ => {}
        }
    }
}

/// One user turn: provider rounds + tool loop, events broadcast live.
/// Returns (turn_ok, input_tokens, output_tokens, cost_microcents).
#[allow(clippy::too_many_arguments)]
fn run_web_turn(
    state: &BridgeState,
    config: &TuiTurnConfig,
    transcript: &mut Vec<ChatMessage>,
    prompt: &str,
    action_rx: &Arc<Mutex<mpsc::Receiver<serde_json::Value>>>,
    cancel: &orbit_provider_http::CancelToken,
    auto_grants: &mut orbit_cli::tool_runtime::AutoGrants,
) -> Result<(bool, u64, u64, u64), String> {
    let cfg = orbit_cli::config::ProvidersConfig::load(&config.home).unwrap_or_default();
    let provider = cfg.provider_for_model(&config.model);
    let pricing = cfg.pricing_for_model(&config.model);
    let provider_id = provider
        .map(|p| p.name.as_str())
        .unwrap_or(config.provider_id.as_str())
        .to_string();
    let resolved_gate = provider
        .map(|p| p.url.as_str())
        .unwrap_or(config.gate.as_str())
        .to_string();
    let credential_env = provider.and_then(|p| p.env.as_deref());

    // Phase 2: the loop is the ENGINE's — the web bridge supplies only
    // the event adapter (SSE events, display-safe) and the tool executor
    // (WebApprovalChannel). The old 8-round copy of the loop is gone.
    let turn_config = orbit_cli::engine_turn_config(
        &config.home,
        &provider_id,
        &resolved_gate,
        &config.model,
        credential_env,
        pricing,
    );

    // Event adapter: FrontendEvent → SSE, verbatim (MD gate 2: ONE
    // event stream — the protocol is every front-end's shared
    // vocabulary). The display-safety pipeline stays (CoT strip, glyph
    // sanitize, display gate): the browser never sees raw reasoning or
    // unsafe bytes. Events pass through under their protocol names
    // with their protocol payloads; nothing is renamed.
    let mut cot = orbit_hud_tui::CotStripper::new();
    let mut events = |ev: orbit_frontend_protocol::FrontendEvent| {
        use orbit_frontend_protocol::FrontendEvent as E;
        match ev {
            E::TextDelta { text } => {
                let stripped = cot.push(&text);
                let sanitized = orbit_hud_tui::sanitize_glyphs(&stripped);
                // D7: probe, don't coerce — a rejected chunk emits the
                // chip naming the gate, never the text.
                if !orbit_hud_tui::safe_text_probe(&sanitized) {
                    state.emit("redacted", serde_json::json!({ "kind": "display_gate" }));
                    return;
                }
                state.emit("text_delta", serde_json::json!({ "text": sanitized }));
            }
            other => {
                // Everything else crosses under its protocol name, with
                // its protocol payload (serde tag = "type",
                // snake_case — the same wire form `orbit -p
                // --output-format stream-json` prints).
                let kind = protocol_kind(&other);
                let payload =
                    serde_json::to_value(&other).unwrap_or_else(|_| serde_json::json!({}));
                // The payload carries its own "type"; the SSE event name
                // is the same string.
                state.emit(kind, payload);
            }
        }
    };

    let mut executor = WebToolExecutor {
        home: config.home.clone(),
        session_id: config.session_id.clone(),
        auto_tools: config.auto_tools,
        state: state.clone(),
        action_rx: action_rx.clone(),
        auto_grants: std::mem::take(auto_grants),
        scope: orbit_cli::tool_runtime::PermissionScope::default(),
        tool_cx: orbit_tools::ToolContext::new(
            config.home.clone(),
            config.session_id.clone(),
            std::env::current_dir().unwrap_or_else(|_| std::path::Path::new(".").to_path_buf()),
        ),
    };

    let options = orbit_engine::TurnOptions {
        tools: orbit_cli::tools::tool_definitions(),
        request_stem: "orbit-web".into(),
        session_id: config.session_id.clone(),
        ..Default::default()
    };

    let report = orbit_engine::run_turn(
        &config.home,
        &turn_config,
        &options,
        prompt,
        transcript,
        &mut executor,
        cancel,
        &mut events,
    );

    // Restore the grants into the caller's slot.
    *auto_grants = executor.auto_grants;

    match report {
        Ok(r) => {
            // E10: the attestation scan runs in EVERY front-end — the
            // browser sees an unverified claim event, not silence.
            if let Some(scan) = orbit_engine::automation::scan_attestation(transcript) {
                if scan.claimed_pass && scan.exit_code != 0 {
                    state.emit(
                        "status",
                        serde_json::json!({
                            "text": format!(
                                "UNVERIFIED CLAIM: \"{}\" exited {} at turn time — the claim is not attested",
                                scan.command, scan.exit_code
                            )
                        }),
                    );
                }
            }
            Ok((r.ok, r.input_tokens, r.output_tokens, r.cost_microcents))
        }
        Err(e) => {
            state.emit("error", serde_json::json!({ "message": e }));
            Ok((false, 0, 0, 0))
        }
    }
}

/// The web bridge's tool executor: bridges the engine's `ToolExecutor`
/// trait to the WebApprovalChannel (SSE approval cards) and session grants.
struct WebToolExecutor {
    home: std::path::PathBuf,
    session_id: String,
    auto_tools: bool,
    state: BridgeState,
    action_rx: Arc<Mutex<mpsc::Receiver<serde_json::Value>>>,
    auto_grants: orbit_cli::tool_runtime::AutoGrants,
    /// The session's permission scope (S5).
    scope: orbit_cli::tool_runtime::PermissionScope,
    /// One context per web session (B2).
    tool_cx: orbit_tools::ToolContext,
}

impl orbit_engine::ToolExecutor for WebToolExecutor {
    fn begin_turn(&mut self, config: &orbit_engine::TurnConfig) {
        orbit_cli::tool_runtime::remember_turn_config(&self.tool_cx, config);
    }

    fn execute(
        &mut self,
        calls: &[orbit_engine::PendingToolCall],
        _round: u32,
    ) -> Vec<orbit_engine::ToolRoundResult> {
        let cx = self.tool_cx.clone();
        orbit_cli::tool_runtime::run_until_cancelled(
            &cx,
            calls,
            |call| {
                // MD gate 2: no private tool events — the engine's
                // tool_started_full / tool_finished_full ARE the stream.
                // Per-call ULID decision ids (defect fix: the old
                // `tool-round-{round}-{index}` ids repeated every turn).
                let decision_id = format!("tool-{}-{}", ulid::Ulid::new(), call.index);
                let mut approval_channel = WebApprovalChannel {
                    action_rx: self.action_rx.clone(),
                    state: self.state.clone(),
                };
                let (result, file_change) = orbit_cli::tool_runtime::execute_call(
                    &self.home,
                    &self.session_id,
                    &decision_id,
                    call,
                    self.auto_tools,
                    true,
                    &mut approval_channel,
                    &mut self.auto_grants,
                    &self.scope,
                    &self.tool_cx,
                )
                .unwrap_or_else(|e| {
                    (
                        serde_json::json!({ "ok": false, "error": e }).to_string(),
                        None,
                    )
                });
                // M11: forward the real diff (counts + bounded hunks) to
                // the web frontend's changes feed.
                if let Some(fc) = file_change {
                    self.state.emit(
                        "file_changed",
                        serde_json::json!({
                            "path": fc.path,
                            "added": fc.added,
                            "removed": fc.removed,
                            "checkpoint_id": fc.checkpoint_id,
                            "hunks": fc.hunks,
                        }),
                    );
                }
                // MD gate 2: the engine's tool_finished_full IS the stream.
                orbit_engine::ToolRoundResult {
                    call_id: call.id.clone(),
                    content: result,
                }
            },
            |_| {},
        )
    }

    fn begin_cancel_scope(&mut self, token: &orbit_provider_http::CancelToken) {
        orbit_cli::tool_runtime::begin_cancel_scope(&self.tool_cx, token);
    }

    fn end_cancel_scope(&mut self) {
        self.tool_cx.pop_cancel_check();
    }
}

/// Transcript entry for the `resume` event, curated like the TUI's
/// `session_to_transcript_lines`: user/assistant text passes through
/// display-safe; a tool-call round collapses to one summary line; tool
/// results are dropped entirely (already in the assistant's context).
fn msg_to_json(m: &ChatMessage) -> Option<serde_json::Value> {
    match m.role {
        ChatRole::User | ChatRole::System => Some(serde_json::json!({
            "role": if m.role == ChatRole::User { "user" } else { "system" },
            // H-3: display-safe before it leaves Rust.
            "text": orbit_hud_tui::safe_text(&m.content),
        })),
        ChatRole::Assistant => {
            if let Some(calls) = &m.tool_calls {
                // Tool-calling round: one summary line per round (the TUI
                // emits the first call's name; the content is the model's
                // reasoning, which never renders — CoT defense, H-12).
                calls.first().map(|c| {
                    serde_json::json!({
                        "role": "tool",
                        "text": orbit_hud_tui::safe_text(&format!("[tool] {}", c.name)),
                    })
                })
            } else if !m.content.is_empty() {
                Some(serde_json::json!({
                    "role": "assistant",
                    "text": orbit_hud_tui::safe_text(&m.content),
                }))
            } else {
                None
            }
        }
        ChatRole::Tool => None,
    }
}
