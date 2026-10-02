//! The turn thread — drives `run_turn` + tool loop for the browser front-end.
//!
//! Same shape as the Go bridge's main loop (go_bridge.rs): wait for actions,
//! run a turn per `prompt`, park on the action channel for approvals, save
//! the session after every turn. Events broadcast to all SSE peers.

use crate::{make_channels, router, BridgeState, WebApprovalChannel};
use orbit_adapter::types::{ChatMessage, ChatRole, ProviderEventKind, ProviderStreamEvent};
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
                // Doc protocol: `cancelled` is its own event, fired before
                // `finished` so the client can stamp the turn either way.
                if !ok {
                    state.emit("cancelled", serde_json::json!({}));
                }
                state.emit(
                    "finished",
                    serde_json::json!({
                        "input_tokens": cum_input,
                        "output_tokens": cum_output,
                        "cost_microcents": cum_cost,
                        "turns": turns,
                    }),
                );
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
    let mut input_tokens = 0u64;
    let mut output_tokens = 0u64;
    let mut cost = 0u64;

    // Same bridge as the TUI: CoT stripper (D6) + glyph sanitize + display_safe
    // (H-3). The browser never sees raw reasoning or unsafe bytes.
    let mut cot = orbit_hud_tui::CotStripper::new();
    let mut observer = |ev: &ProviderStreamEvent| {
        if let ProviderEventKind::TextDelta { bytes } = &ev.event {
            let raw = match std::str::from_utf8(bytes) {
                Ok(s) => s.to_string(),
                Err(_) => {
                    state.emit("redacted", serde_json::json!({ "kind": "invalid_utf8" }));
                    return;
                }
            };
            let stripped = cot.push(&raw);
            let sanitized = orbit_hud_tui::sanitize_glyphs(&stripped);
            // D7: probe, don't coerce — a rejected chunk emits the chip
            // naming the gate, never the text.
            if !orbit_hud_tui::safe_text_probe(&sanitized) {
                state.emit("redacted", serde_json::json!({ "kind": "display_gate" }));
                return;
            }
            state.emit("delta", serde_json::json!({ "text": sanitized }));
        }
    };

    let cfg = orbit_cli::config::ProvidersConfig::load(&config.home).unwrap_or_default();
    let provider = cfg.provider_for_model(&config.model);
    let pricing = cfg.pricing_for_model(&config.model);
    let provider_id = provider
        .map(|p| p.name.as_str())
        .unwrap_or(config.provider_id.as_str());
    let resolved_gate = provider.map(|p| p.url.as_str()).unwrap_or(&config.gate);
    let credential_env = provider.and_then(|p| p.env.as_deref());

    transcript.push(ChatMessage {
        role: ChatRole::User,
        content: prompt.to_string(),
        tool_calls: None,
        tool_call_id: None,
        tool_result: None,
    });

    let mut turn_ok = false;
    for round in 0..8u32 {
        let outcome = orbit_cli::run_turn(
            &config.home,
            provider_id,
            resolved_gate,
            &config.model,
            credential_env,
            pricing,
            prompt,
            Some(transcript.clone()),
            Some(&mut observer),
            cancel.clone(),
        );
        let o = match outcome {
            Ok(o) => o,
            Err((code, msg)) => {
                state.emit(
                    "error",
                    serde_json::json!({ "message": format!("{code}: {msg}") }),
                );
                return Ok((false, input_tokens, output_tokens, cost));
            }
        };
        input_tokens += o.input_tokens;
        output_tokens += o.output_tokens;
        cost += o.cost_microcents;
        state.emit(
            "cost",
            serde_json::json!({
                "microcents": cost,
                "input_tokens": input_tokens,
                "output_tokens": output_tokens,
            }),
        );

        if o.tool_calls.is_empty() {
            transcript.push(ChatMessage {
                role: ChatRole::Assistant,
                content: o.output.clone(),
                tool_calls: None,
                tool_call_id: None,
                tool_result: None,
            });
            turn_ok = true;
            break;
        }

        if o.tool_calls.len() > 16 {
            state.emit(
                "error",
                serde_json::json!({ "message": "ORBIT-E0200: provider requested more than 16 tools in one round" }),
            );
            break;
        }

        let assistant_calls: Vec<orbit_adapter::types::ToolCallMessage> = o
            .tool_calls
            .iter()
            .map(|tc| orbit_adapter::types::ToolCallMessage {
                id: tc.id.clone(),
                name: tc.name.clone(),
                arguments: String::from_utf8_lossy(&tc.arguments).into_owned(),
            })
            .collect();
        transcript.push(ChatMessage {
            role: ChatRole::Assistant,
            content: o.output.clone(),
            tool_calls: Some(assistant_calls),
            tool_call_id: None,
            tool_result: None,
        });

        let mut approval_channel = WebApprovalChannel {
            action_rx: action_rx.clone(),
            state: state.clone(),
        };
        for call in &o.tool_calls {
            let args = orbit_cli::tools::parse_arguments(&call.arguments)
                .unwrap_or(serde_json::Value::Null);
            let summary = orbit_cli::tools::safe_call_summary(&call.name, &args);
            state.emit(
                "tool_call_started",
                serde_json::json!({
                    "call_id": call.id,
                    "name": call.name,
                    "summary": summary,
                }),
            );
            let decision_id = format!("tool-round-{round}-{}", call.index);
            let result = orbit_cli::tool_runtime::execute_call(
                &config.home,
                &config.session_id,
                &decision_id,
                call,
                config.auto_tools,
                true,
                &mut approval_channel,
                auto_grants,
            )
            .unwrap_or_else(|e| serde_json::json!({ "ok": false, "error": e }).to_string());
            let ok = result.contains("\"ok\":true");
            state.emit(
                "tool_call_finished",
                serde_json::json!({
                    "call_id": call.id,
                    "name": call.name,
                    "ok": ok,
                }),
            );
            transcript.push(ChatMessage {
                role: ChatRole::Tool,
                content: result.clone(),
                tool_calls: None,
                tool_call_id: Some(call.id.clone()),
                tool_result: Some(result),
            });
        }
    }

    if !turn_ok {
        state.emit(
            "error",
            serde_json::json!({ "message": "ORBIT-E0406: tool loop ended without a final assistant response" }),
        );
    }

    Ok((turn_ok, input_tokens, output_tokens, cost))
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
