//! TUI worker thread — drives `run_turn` + tool execution for the TUI front-end.
//!
//! The worker receives user prompts via `Msg::TextSubmitted` and runs the
//! four-gate pipeline. Stream events flow through the TUI bridge (display_safe
//! + CoT stripping). Tool approvals resolve via the `ApprovalRegistry`.
//!
//! This is the TUI-specific counterpart to the REPL loop — the REPL's inline
//! logic in `cmd_chat` is untouched.

use orbit_adapter::types::{ChatMessage, ChatRole, ProviderEventKind, ProviderStreamEvent};
use orbit_hud_tui::bus::BusSender;
use orbit_hud_tui::msg::Msg;
use orbit_hud_tui::state::TranscriptLine;
use orbit_hud_tui::worker::{CommandSink, WorkerCommand, WorkerCtx};
use orbit_hud_tui::{ApprovalRegistry, ApprovalResponse};
use std::path::PathBuf;
use std::sync::mpsc;

/// The per-turn state the worker needs to run one prompt.
#[derive(Clone)]
pub struct TuiTurnConfig {
    pub home: PathBuf,
    pub session_id: String,
    pub gate: String,
    pub model: String,
    pub provider_id: String,
    pub auto_tools: bool,
    /// Restored session state. Empty/zero for a fresh chat.
    pub initial_transcript: Vec<ChatMessage>,
    pub initial_turns: u64,
    pub initial_input_tokens: u64,
    pub initial_output_tokens: u64,
    pub initial_cost_microcents: u64,
}

/// Build the worker spawner closure for the TUI. The CLI owns `run_turn`;
/// this closure captures the turn config and spawns a thread that drives it.
/// Returns a `CancelHandle` that cancels the turn currently in flight.
pub fn make_spawner(config: TuiTurnConfig) -> orbit_hud_tui::WorkerSpawner {
    Box::new(move |ctx: WorkerCtx, _command_sink: CommandSink| {
        // Shared slot: worker_main installs the CURRENT turn's CancelToken;
        // the handle fires it. None when no turn is running.
        let slot: std::sync::Arc<std::sync::Mutex<Option<orbit_provider_http::CancelToken>>> =
            std::sync::Arc::new(std::sync::Mutex::new(None));
        let handle_slot = slot.clone();
        std::thread::Builder::new()
            .name("orbit-tui-worker".into())
            .spawn(move || worker_main(ctx, config, slot))
            .map(|_| {
                let cancel_handle: orbit_hud_tui::worker::CancelHandle =
                    std::sync::Arc::new(move || {
                        if let Some(token) = handle_slot.lock().ok().and_then(|g| g.clone()) {
                            token.cancel();
                        }
                    });
                cancel_handle
            })
            .map_err(|e| format!("spawn worker: {e}"))
    })
}

/// The worker's event loop — waits for prompts, runs turns, reports results.
/// Each turn gets a fresh CancelToken installed in the shared slot so the
/// TUI's Ctrl+C can abort the in-flight stream.
fn worker_main(
    ctx: WorkerCtx,
    mut config: TuiTurnConfig,
    cancel_slot: std::sync::Arc<std::sync::Mutex<Option<orbit_provider_http::CancelToken>>>,
) {
    let mut transcript: Vec<ChatMessage> = config.initial_transcript.clone();
    let mut turns: u64 = config.initial_turns;
    // D9 (§13.5 rule 5): the session file must carry CUMULATIVE totals —
    // resumed values plus everything this run adds. Tracking them per-turn
    // only (as run_tui_turn does) made every save overwrite the history.
    let mut cum_input: u64 = config.initial_input_tokens;
    let mut cum_output: u64 = config.initial_output_tokens;
    let mut cum_cost: u64 = config.initial_cost_microcents;
    // D8 (§13.5 rule 1): R-grants are SESSION-scoped. Created once here —
    // not per provider round, and not per turn — so `R` means what its
    // label says. Reset on resume and on a new session.
    let mut auto_grants = crate::tool_runtime::AutoGrants::new();

    // Send identity to the TUI so the status bar shows model/provider/session.
    // D18: priced=false makes the status bar show `cost n/a` for models
    // without a pricing entry (never a fake $0.0000).
    let boot_priced = crate::config::ProvidersConfig::load(&config.home)
        .ok()
        .and_then(|cfg| cfg.pricing_for_model(&config.model))
        .is_some();
    ctx.sender.send(Msg::Identity {
        model: config.model.clone(),
        provider: config.provider_id.clone(),
        session_prefix: config.session_id.chars().take(8).collect(),
        session_id: config.session_id.clone(),
        priced: boot_priced,
    });

    // Boot with a resumed session, if any.
    if config.initial_transcript.is_empty() && config.initial_turns == 0 {
        // Fresh chat — nothing to restore.
    } else {
        let lines = session_to_transcript_lines(&config.initial_transcript);
        ctx.sender.send(Msg::TranscriptLoaded {
            lines,
            input_tokens: config.initial_input_tokens,
            output_tokens: config.initial_output_tokens,
            cost_microcents: config.initial_cost_microcents,
            turns: config.initial_turns,
        });
    }
    while let Ok(cmd) = ctx.command_rx.recv() {
        match cmd {
            WorkerCommand::Prompt(prompt) => {
                let token = orbit_provider_http::CancelToken::new();
                if let Ok(mut guard) = cancel_slot.lock() {
                    *guard = Some(token.clone());
                }
                let (_ok, input, output, cost) = match run_tui_turn(
                    &config,
                    &mut transcript,
                    &prompt,
                    &ctx.sender,
                    &ctx.approvals,
                    &token,
                    turns,
                    &mut auto_grants,
                ) {
                    Ok(x) => x,
                    Err(e) => {
                        orbit_hud_tui::emit_error(&ctx.sender, &e);
                        if let Ok(mut guard) = cancel_slot.lock() {
                            *guard = None;
                        }
                        continue;
                    }
                };
                if let Ok(mut guard) = cancel_slot.lock() {
                    *guard = None;
                }
                turns = turns.saturating_add(1);
                // D9: accumulate CUMULATIVE session totals (initial + every
                // turn this run). The save below persists these, and
                // ResponseFinished commits them to the TUI so a later resume
                // shows the full history, not just the last turn.
                cum_input = cum_input.saturating_add(input);
                cum_output = cum_output.saturating_add(output);
                cum_cost = cum_cost.saturating_add(cost);
                // Always emit ResponseFinished — the TUI's turn_in_flight flag
                // and queue drain both depend on it, whether the turn
                // completed, was cancelled by the operator, or errored. The
                // reducer stamps a "cancelled" note when cancel_requested was
                // set.
                orbit_hud_tui::emit_response_finished(&ctx.sender, "", cum_input, cum_output, cum_cost);
                // D9 (§13.5 rule 5): save with CUMULATIVE totals — the
                // resumed baseline plus every turn this run — so a
                // save/resume/save cycle accumulates instead of
                // overwriting, and turns reflects the full count.
                let sf = crate::sessions::SessionFile::from_chat(
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
                if let Err(e) = crate::sessions::save_session(&config.home, &sf) {
                    orbit_hud_tui::emit_error(&ctx.sender, &format!("warning: session not saved: {e}"));
                }
            }
            WorkerCommand::SetModel(model) => {
                if model.is_empty() {
                    continue;
                }
                let old = config.model.clone();
                config.model = model.clone();
                ctx.sender.send(Msg::ModelChanged(model.clone()));
                orbit_hud_tui::emit_status(&ctx.sender, &format!("model → {model} (was {old})"));
            }
            WorkerCommand::ListModels => {
                let cfg = crate::config::ProvidersConfig::load(&config.home).unwrap_or_default();
                let entries = cfg.all_models();
                let text = if entries.is_empty() {
                    "(no providers configured)".into()
                } else {
                    entries
                        .iter()
                        .map(|(p, m)| format!("{p} \t{m}"))
                        .collect::<Vec<_>>()
                        .join("\n")
                };
                ctx.sender.send(Msg::SystemMessage(text));
            }
            WorkerCommand::ListSessions => {
                let text = match crate::sessions::list_sessions(&config.home) {
                    Ok(list) if list.is_empty() => "(no saved sessions)".into(),
                    Ok(list) => list
                        .iter()
                        .map(|s| {
                            format!(
                                "{} \tmodel={} \tturns={} \tupdated={}",
                                s.session_id, s.model, s.turns, s.updated_at
                            )
                        })
                        .collect::<Vec<_>>()
                        .join("\n"),
                    Err(e) => format!("error listing sessions: {e}"),
                };
                ctx.sender.send(Msg::SystemMessage(text));
            }
            WorkerCommand::ResumeSession(id) => {
                match crate::sessions::load_session(&config.home, &id) {
                    Ok(s) => {
                        transcript = s.to_transcript();
                        turns = s.turns;
                        config.session_id = s.session_id.clone();
                        config.model = s.model.clone();
                        let lines = session_to_transcript_lines(&s.transcript);
                        ctx.sender.send(Msg::TranscriptLoaded {
                            lines,
                            input_tokens: s.input_tokens,
                            output_tokens: s.output_tokens,
                            cost_microcents: s.cost_microcents,
                            turns: s.turns,
                        });
                        ctx.sender.send(Msg::Identity {
                            model: s.model.clone(),
                            provider: s.provider.clone(),
                            session_prefix: s.session_id.chars().take(8).collect(),
                            session_id: s.session_id.clone(),
                            // D18: priced stays true unless we know the
                            // resumed model is unpriced.
                            priced: crate::config::ProvidersConfig::load(&config.home)
                                .ok()
                                .and_then(|cfg| cfg.pricing_for_model(&s.model))
                                .is_some(),
                        });
                        // D9: the resumed session's totals become the new
                        // baseline — the next save carries them plus whatever
                        // this run adds.
                        cum_input = s.input_tokens;
                        cum_output = s.output_tokens;
                        cum_cost = s.cost_microcents;
                        // D8: resuming into a different session clears any
                        // R-grants made in the previous one.
                        auto_grants = crate::tool_runtime::AutoGrants::new();
                    }
                    Err(e) => {
                        ctx.sender
                            .send(Msg::SystemMessage(format!("cannot resume {id}: {e}")));
                    }
                }
            }
        }
    }
}

/// Convert a saved session's transcript to TUI display lines. Assistant messages
/// with tool_calls collapse to `Stripped` (same as the streaming path); tool
/// results are dropped (they're already in the assistant's context). User and
/// system messages pass through verbatim.
fn session_to_transcript_lines(msgs: &[ChatMessage]) -> Vec<TranscriptLine> {
    msgs.iter()
        .filter_map(|msg| {
            match msg.role {
                ChatRole::User => Some(TranscriptLine::User { text: msg.content.clone(), time: None }),
                ChatRole::Assistant => {
                    if let Some(calls) = &msg.tool_calls {
                        // Tool-calling round: emit one Stripped line per tool call.
                        // The content (if any) is the model's reasoning, which we
                        // never render (CoT defense, H-12).
                        if calls.is_empty() {
                            // Degenerate: tool_calls array present but empty.
                            None
                        } else {
                            // Emit the first tool call's name only — multiple calls
                            // in one round would require N Stripped lines, but the
                            // streaming path already handles that per-call. For
                            // resume, one summary line is sufficient.
                            Some(TranscriptLine::Stripped {
                                tool_name: calls[0].name.clone(),
                                // Restored sessions carry no argument
                                // summary — the call args aren't in the
                                // display-safe form (they're raw JSON).
                                // The outcome is unknown from the saved
                                // transcript; settled-neutral is honest.
                                summary: String::new(),
                                outcome: Some(orbit_hud_tui::state::ToolOutcome::Ok),
                                meta: String::new(),
                                // Restored calls have no live duration.
                                started_at: None,
                            })
                        }
                    } else if !msg.content.is_empty() {
                        Some(TranscriptLine::Assistant { text: msg.content.clone(), time: None })
                    } else {
                        None
                    }
                }
                ChatRole::System => Some(TranscriptLine::System(msg.content.clone())),
                ChatRole::Tool => {
                    // Tool results are already in the assistant's context; don't
                    // render them as separate transcript lines (matches the
                    // streaming path, which only emits Stripped + finished).
                    None
                }
            }
        })
        .collect()
}

/// A TUI-aware approval channel. Implements the CLI's `ApprovalChannel` trait
/// by posting a request to the bus and parking on a oneshot channel registered
/// in the `ApprovalRegistry`.
pub struct TuiApprovalChannel {
    sender: BusSender,
    approvals: ApprovalRegistry,
}

impl TuiApprovalChannel {
    pub fn new(sender: BusSender, approvals: ApprovalRegistry) -> Self {
        Self { sender, approvals }
    }
}

/// Classify a tool result JSON into a `ToolOutcome` for the transcript card.
/// The denial and block paths in `execute_call` produce `ok:false` results
/// with these exact error strings (crates/cli/src/tool_runtime.rs:243-251);
/// everything else with `ok:true` is a success, and any other `ok:false`
/// means the tool genuinely ran and failed. A refusal must never render as
/// a red `✕ failed` card (§11.5 rule 4, `denied_is_not_failed`).
fn classify_tool_result(result: &str) -> orbit_hud_tui::state::ToolOutcome {
    if result.contains("\"ok\":true") {
        orbit_hud_tui::state::ToolOutcome::Ok
    } else if result.contains("operator denied") {
        orbit_hud_tui::state::ToolOutcome::Denied
    } else if result.contains("non-interactive tool call requires --auto-tools")
        || result.contains("unknown tool (deny-by-default)")
    {
        orbit_hud_tui::state::ToolOutcome::Blocked
    } else {
        orbit_hud_tui::state::ToolOutcome::Failed
    }
}

impl crate::tool_runtime::ApprovalChannel for TuiApprovalChannel {
    fn ask(
        &mut self,
        req: &crate::tool_runtime::ApprovalRequest,
        _auto_tools: bool,
    ) -> crate::tool_runtime::ApprovalVerdict {
        // Register a oneshot channel for this call.
        let (tx, rx) = mpsc::channel();
        self.approvals.register(&req.call_id, tx);
        // Post the request to the bus — the reducer renders an approval card.
        self.sender.send(Msg::ApprovalRequested {
            call_id: req.call_id.clone(),
            tool_name: req.tool_name.clone(),
            summary: req.summary.clone(),
            risk: req.risk.level(),
        });
        // Park until the operator responds (y/n/R). Esc handled as deny.
        match rx.recv() {
            Ok(ApprovalResponse::Allow) => crate::tool_runtime::ApprovalVerdict::AllowOnce,
            Ok(ApprovalResponse::AllowSession) => {
                crate::tool_runtime::ApprovalVerdict::AllowSession
            }
            Ok(ApprovalResponse::Deny) | Err(_) => crate::tool_runtime::ApprovalVerdict::Deny,
        }
    }
}

/// Run one user turn against the gateway, streaming through the TUI bridge.
/// Returns (turn_ok, input_tokens, output_tokens, cost_microcents).
/// `cancel` is the per-turn token the TUI fires on Ctrl+C-mid-stream.
#[allow(clippy::too_many_arguments)]
pub fn run_tui_turn(
    config: &TuiTurnConfig,
    transcript: &mut Vec<ChatMessage>,
    prompt: &str,
    sender: &BusSender,
    approvals: &ApprovalRegistry,
    cancel: &orbit_provider_http::CancelToken,
    // Kept for signature stability; the worker loop owns turn counting and
    // session saving (D9) — the turn itself no longer needs it.
    _turns: u64,
    auto_grants: &mut crate::tool_runtime::AutoGrants,
) -> Result<(bool, u64, u64, u64), String> {
    let mut input_tokens = 0u64;
    let mut output_tokens = 0u64;
    let mut cost = 0u64;

    // Observer: map stream events to TUI messages via the bridge. The CoT
    // stripper is owned by this closure — one per turn — so a `<think>` tag
    // split across deltas is still caught (D6).
    let mut cot = orbit_hud_tui::CotStripper::new();
    let mut observer = |ev: &ProviderStreamEvent| {
        if let ProviderEventKind::TextDelta { bytes } = &ev.event {
            orbit_hud_tui::emit_text(&mut cot, sender, bytes);
        }
    };

    // Resolve provider / pricing from config (same as REPL).
    let cfg = crate::config::ProvidersConfig::load(&config.home).unwrap_or_default();
    let provider = cfg.provider_for_model(&config.model);
    let pricing = cfg.pricing_for_model(&config.model);
    let provider_id = provider
        .map(|p| p.name.as_str())
        .unwrap_or(config.provider_id.as_str());
    let resolved_gate = provider.map(|p| p.url.as_str()).unwrap_or(&config.gate);
    let credential_env = provider.and_then(|p| p.env.as_deref());

    // Build the transcript for this user turn.
    transcript.push(ChatMessage {
        role: ChatRole::User,
        content: prompt.to_string(),
        tool_calls: None,
        tool_call_id: None,
        tool_result: None,
    });

    let mut turn_ok = false;
    // The workspace rail tracks the turn's phases (§6.10):
    // 0 orient → 1 reason → 2 act → 3 verify → 4 respond.
    let mut ws = orbit_hud_tui::state::Workspace::default();
    ws.phase_index = 0;
    orbit_hud_tui::emit_workspace(sender, ws.clone());
    for round in 0..8u32 {
        let outcome = crate::run_turn(
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
                orbit_hud_tui::emit_error(sender, &format!("{code}: {msg}"));
                return Ok((false, input_tokens, output_tokens, cost));
            }
        };
        input_tokens += o.input_tokens;
        output_tokens += o.output_tokens;
        cost += o.cost_microcents;
        // D5: report the TURN's running cost; the committed total is only
        // touched by ResponseFinished (which carries the final number).
        orbit_hud_tui::emit_turn_cost(sender, cost);
        // The model is reasoning (round 0) or responding (later rounds).
        if round == 0 {
            ws.phase_index = 1;
            orbit_hud_tui::emit_workspace(sender, ws.clone());
        }

        if o.tool_calls.is_empty() {
            // Normal text terminal: the respond phase.
            ws.phase_index = 4;
            orbit_hud_tui::emit_workspace(sender, ws.clone());
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
            orbit_hud_tui::emit_error(
                sender,
                "ORBIT-E0200: provider requested more than 16 tools in one round",
            );
            break;
        }

        // Append the assistant tool-call message.
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

        // Tools are running: the act phase.
        ws.phase_index = 2;
        orbit_hud_tui::emit_workspace(sender, ws.clone());
        // Execute each tool call via the TUI approval channel.
        let mut approval_channel = TuiApprovalChannel::new(sender.clone(), approvals.clone());
        for call in &o.tool_calls {
            // Display-safe summary first.
            let args =
                crate::tools::parse_arguments(&call.arguments).unwrap_or(serde_json::Value::Null);
            let summary = crate::tools::safe_call_summary(&call.name, &args);
            orbit_hud_tui::emit_tool_started(sender, &call.name, &summary);

            let decision_id = format!("tool-round-{round}-{}", call.index);
            let result = crate::tool_runtime::execute_call(
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
            // Classify the result into a ToolOutcome: a refusal must render
            // as `⊘ denied by you`, not a red `✕ failed` (§11.5 rule 4).
            // execute_call's denial paths return ok:false with these exact
            // error strings (tool_runtime.rs:243-251), so match on them.
            let outcome = classify_tool_result(&result);
            orbit_hud_tui::emit_tool_finished(sender, &call.name, outcome);
            transcript.push(ChatMessage {
                role: ChatRole::Tool,
                content: result.clone(),
                tool_calls: None,
                tool_call_id: Some(call.id.clone()),
                tool_result: Some(result),
            });
        }
        // The next provider round receives the assistant call + tool results.
    }

    if !turn_ok {
        orbit_hud_tui::emit_error(
            sender,
            "ORBIT-E0406: tool loop ended without a final assistant response",
        );
    }

    Ok((turn_ok, input_tokens, output_tokens, cost))
}
