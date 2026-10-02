//! TUI worker thread — drives `run_turn` + tool execution for the TUI front-end.
//!
//! The worker receives user prompts via `Msg::TextSubmitted` and runs the
//! four-gate pipeline. Stream events flow through the TUI bridge (display_safe
//! + CoT stripping). Tool approvals resolve via the `ApprovalRegistry`.
//!
//! This is the TUI-specific counterpart to the REPL loop — the REPL's inline
//! logic in `cmd_chat` is untouched.

use orbit_adapter::types::{ChatMessage, ChatRole};
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
    // Mods (Claude-Mods parity): loaded once at boot, toggleable at
    // runtime. The directive is rebuilt whenever the enabled set changes.
    let mut mods = crate::mods::load_all(&config.home);
    let mut mods_enabled = crate::mods::initial_enabled(&config.home, &mods);

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
    // Locally-queued commands (mod commands re-enter the Prompt flow).
    let mut pending: Vec<WorkerCommand> = Vec::new();
    loop {
        let cmd = match pending.pop() {
            Some(c) => c,
            None => match ctx.command_rx.recv() {
                Ok(c) => c,
                Err(_) => break,
            },
        };
        match cmd {
            WorkerCommand::PlanPrompt(prompt) => {
                let token = orbit_provider_http::CancelToken::new();
                if let Ok(mut guard) = cancel_slot.lock() {
                    *guard = Some(token.clone());
                }
                let directive = crate::mods::system_directive(&mods, &mods_enabled);
                // Plan directive: read-only posture, produce a plan.
                let plan_directive = format!(
                    "{directive}\n\n## PLAN MODE (read-only)\nYou are in plan mode. Do NOT attempt changes; all tool calls will be denied. Explore the problem, then respond with a concise, numbered implementation plan. End with a line: `PLAN READY`."
                );
                let (_ok, _input, _output, _cost, plan_text) = match run_tui_turn(
                    &config,
                    &mut transcript,
                    &prompt,
                    &ctx.sender,
                    &ctx.approvals,
                    &token,
                    turns,
                    &mut auto_grants,
                    &plan_directive,
                    true,
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
                // The plan is HELD for approval — no counters commit, no
                // session save yet (the plan isn't part of the transcript
                // until approved and executed).
                orbit_hud_tui::emit_response_finished(&ctx.sender, "", 0, 0, 0);
                orbit_hud_tui::emit_plan_ready(&ctx.sender, &plan_text);
            }
            WorkerCommand::Prompt(prompt) => {
                let token = orbit_provider_http::CancelToken::new();
                if let Ok(mut guard) = cancel_slot.lock() {
                    *guard = Some(token.clone());
                }
                let directive = crate::mods::system_directive(&mods, &mods_enabled);
                let (_ok, input, output, cost, _final) = match run_tui_turn(
                    &config,
                    &mut transcript,
                    &prompt,
                    &ctx.sender,
                    &ctx.approvals,
                    &token,
                    turns,
                    &mut auto_grants,
                    &directive,
                    false,
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
                orbit_hud_tui::emit_response_finished(
                    &ctx.sender,
                    "",
                    cum_input,
                    cum_output,
                    cum_cost,
                );
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
                    orbit_hud_tui::emit_error(
                        &ctx.sender,
                        &format!("warning: session not saved: {e}"),
                    );
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
            WorkerCommand::Compact => {
                // Claude Code `/compact`: fold the transcript into a single
                // summary message via the provider, replacing the working
                // transcript. The session FILE keeps the full history; only
                // the in-memory context window shrinks. A no-op on an empty
                // or single-message transcript.
                let worth_compacting = transcript
                    .iter()
                    .filter(|m| matches!(m.role, ChatRole::User | ChatRole::Assistant))
                    .count()
                    >= 2;
                if !worth_compacting {
                    ctx.sender.send(Msg::SystemMessage(
                        "nothing to compact yet (need at least one exchange)".into(),
                    ));
                    continue;
                }
                // Render the transcript as the model's own conversation,
                // dropping tool plumbing (ids/results carry no context value
                // at summary time; the file retains them).
                let mut dump = String::new();
                for m in &transcript {
                    match m.role {
                        ChatRole::User => {
                            dump.push_str("USER: ");
                            dump.push_str(&m.content);
                        }
                        ChatRole::Assistant => {
                            dump.push_str("ASSISTANT: ");
                            dump.push_str(&m.content);
                        }
                        _ => continue,
                    }
                    if let Some(calls) = &m.tool_calls {
                        for c in calls {
                            dump.push_str(&format!(
                                "
  [tool {} {}]",
                                c.name, c.arguments
                            ));
                        }
                    }
                    dump.push('\n');
                }
                let prompt = format!(
                    "Summarize the conversation below for handoff to a fresh context window. Preserve: the user's goal, decisions made, file paths and identifiers mentioned, open questions, and the next step. Reply with the summary only.

{dump}"
                );
                ctx.sender.send(Msg::SystemMessage("compacting…".into()));
                let token = orbit_provider_http::CancelToken::new();
                if let Ok(mut guard) = cancel_slot.lock() {
                    *guard = Some(token.clone());
                }
                let cfg = crate::config::ProvidersConfig::load(&config.home).unwrap_or_default();
                let provider = cfg.provider_for_model(&config.model);
                let pricing = cfg.pricing_for_model(&config.model);
                let provider_id = provider
                    .map(|p| p.name.as_str())
                    .unwrap_or(config.provider_id.as_str());
                let gate = provider
                    .map(|p| p.url.as_str())
                    .unwrap_or(config.gate.as_str());
                let cred = provider.and_then(|p| p.env.as_deref());
                let outcome = crate::run_turn_with_tools(
                    &config.home,
                    provider_id,
                    gate,
                    &config.model,
                    cred,
                    pricing,
                    &prompt,
                    Some(vec![]),
                    None,
                    token.clone(),
                    vec![],
                );
                if let Ok(mut guard) = cancel_slot.lock() {
                    *guard = None;
                }
                match outcome {
                    Ok(o) if !o.output.trim().is_empty() && o.tool_calls.is_empty() => {
                        let before = transcript.len();
                        // Replace the entire transcript with ONE summary
                        // message. The model sees: summary + (next prompt).
                        let summary = format!(
                            "[context compacted from {before} messages]

{}",
                            o.output.trim()
                        );
                        transcript.clear();
                        transcript.push(ChatMessage {
                            role: ChatRole::User,
                            content: summary,
                            tool_calls: None,
                            tool_call_id: None,
                            tool_result: None,
                            blocks: None,
                        });
                        // Usage counts for the compaction request itself.
                        cum_input = cum_input.saturating_add(o.input_tokens);
                        cum_output = cum_output.saturating_add(o.output_tokens);
                        cum_cost = cum_cost.saturating_add(o.cost_microcents);
                        ctx.sender.send(Msg::SystemMessage(format!(
                            "compacted {} messages → 1 (summary {} chars)",
                            before,
                            o.output.trim().chars().count()
                        )));
                        // Persist the compacted state so a resume doesn't
                        // resurrect the full transcript.
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
                            orbit_hud_tui::emit_error(
                                &ctx.sender,
                                &format!("warning: session not saved: {e}"),
                            );
                        }
                    }
                    Ok(_) => {
                        ctx.sender
                            .send(Msg::SystemMessage("compact failed: empty summary".into()));
                    }
                    Err((code, msg)) => {
                        orbit_hud_tui::emit_error(&ctx.sender, &format!("{code}: {msg}"));
                    }
                }
            }
            WorkerCommand::ListInstalledMods => {
                if mods.is_empty() {
                    ctx.sender.send(Msg::SystemMessage(
                        "no mods installed — add $ORBIT_HOME/mods/<name>/instructions.md".into(),
                    ));
                    continue;
                }
                for m in &mods {
                    let state = if mods_enabled.contains(&m.name) {
                        "on"
                    } else {
                        "off"
                    };
                    let cmds = if m.commands.is_empty() {
                        String::new()
                    } else {
                        format!(
                            " · commands: {}",
                            m.commands
                                .keys()
                                .map(|c| format!("/{}:{}", m.name, c))
                                .collect::<Vec<_>>()
                                .join(" ")
                        )
                    };
                    ctx.sender.send(Msg::SystemMessage(format!(
                        "[{state}] {} — {}{cmds}",
                        m.name,
                        if m.description.is_empty() {
                            "(no description)"
                        } else {
                            &m.description
                        }
                    )));
                }
            }
            WorkerCommand::ToggleMod(name) => {
                match crate::mods::toggle(&config.home, &mods, &name) {
                    Ok(now_on) => {
                        if now_on {
                            mods_enabled.push(name.clone());
                        } else {
                            mods_enabled.retain(|n| n != &name);
                        }
                        ctx.sender.send(Msg::SystemMessage(format!(
                            "mod {name}: {}",
                            if now_on { "enabled" } else { "disabled" }
                        )));
                    }
                    Err(e) => {
                        ctx.sender.send(Msg::SystemMessage(e));
                    }
                }
            }
            WorkerCommand::RefreshMods => {
                mods = crate::mods::load_all(&config.home);
                mods_enabled = crate::mods::initial_enabled(&config.home, &mods);
                ctx.sender.send(Msg::SystemMessage(format!(
                    "mods reloaded: {} installed, {} enabled",
                    mods.len(),
                    mods_enabled.len()
                )));
            }
            WorkerCommand::Undo => {
                // Claude Code `/undo`: pop the last user message + every
                // assistant/tool message after it. The session FILE keeps
                // history; only the working context rewinds.
                let last_user = transcript.iter().rposition(|m| m.role == ChatRole::User);
                match last_user {
                    Some(idx) => {
                        let removed: Vec<String> = transcript
                            .split_off(idx)
                            .iter()
                            .filter(|m| m.tool_result.is_none())
                            .map(|m| m.content.clone())
                            .filter(|c| !c.trim().is_empty())
                            .collect();
                        let removed_text = removed.join(" / ");
                        // Persist the rewound state.
                        let sf = crate::sessions::SessionFile::from_chat(
                            &config.session_id,
                            &config.model,
                            &config.gate,
                            &config.provider_id,
                            &transcript,
                            turns.saturating_sub(1),
                            cum_input,
                            cum_output,
                            cum_cost,
                        );
                        match crate::sessions::save_session(&config.home, &sf) {
                            Ok(()) => {
                                ctx.sender.send(Msg::SystemMessage(format!(
                                    "undid last exchange ({})",
                                    if removed_text.is_empty() {
                                        "no text".to_string()
                                    } else {
                                        removed_text
                                    }
                                )));
                            }
                            Err(e) => {
                                orbit_hud_tui::emit_error(
                                    &ctx.sender,
                                    &format!("warning: session not saved: {e}"),
                                );
                            }
                        }
                    }
                    None => {
                        ctx.sender
                            .send(Msg::SystemMessage("nothing to undo".into()));
                    }
                }
            }
            WorkerCommand::Permissions(arg) => {
                let sub = arg.split_whitespace().next().unwrap_or("");
                let tool = arg.split_whitespace().nth(1).unwrap_or("");
                match crate::permissions::PermissionRules::load(&config.home) {
                    Err(e) => {
                        ctx.sender
                            .send(Msg::SystemMessage(format!("permissions.toml: {e}")));
                    }
                    Ok(mut rules) => match (sub, tool) {
                        ("allow", t) if !t.is_empty() => {
                            let msg = rules
                                .allow_tool(&config.home, t)
                                .map(|_| format!("allow rule added: {t}"))
                                .unwrap_or_else(|e| format!("error: {e}"));
                            ctx.sender.send(Msg::SystemMessage(msg));
                        }
                        ("deny", t) if !t.is_empty() => {
                            let msg = rules
                                .deny_tool(&config.home, t)
                                .map(|_| format!("deny rule added: {t}"))
                                .unwrap_or_else(|e| format!("error: {e}"));
                            ctx.sender.send(Msg::SystemMessage(msg));
                        }
                        ("reset", t) if !t.is_empty() => {
                            let msg = rules
                                .reset_tool(&config.home, t)
                                .map(|_| format!("rules cleared: {t}"))
                                .unwrap_or_else(|e| format!("error: {e}"));
                            ctx.sender.send(Msg::SystemMessage(msg));
                        }
                        ("", _) => {
                            let allow: Vec<String> = rules.allow.tools.iter().cloned().collect();
                            let deny: Vec<String> = rules.deny.tools.iter().cloned().collect();
                            ctx.sender.send(Msg::SystemMessage(format!(
                                "allow: [{}] · deny: [{}] · usage: /permissions allow|deny|reset <tool>",
                                allow.join(", "),
                                deny.join(", ")
                            )));
                        }
                        _ => {
                            ctx.sender.send(Msg::SystemMessage(
                                "usage: /permissions [allow|deny|reset <tool>]".into(),
                            ));
                        }
                    },
                }
            }
            WorkerCommand::ModCommand(mod_name, cmd_name) => {
                // A mod command runs its body as a normal prompt turn.
                let body = mods
                    .iter()
                    .find(|m| m.name == mod_name)
                    .and_then(|m| m.commands.get(&cmd_name))
                    .cloned();
                match body {
                    Some(prompt) => {
                        pending.push(WorkerCommand::Prompt(prompt));
                    }
                    None => {
                        ctx.sender.send(Msg::SystemMessage(format!(
                            "no command {cmd_name} in mod {mod_name}"
                        )));
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
                ChatRole::User => Some(TranscriptLine::User {
                    text: msg.content.clone(),
                    time: None,
                }),
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
                        Some(TranscriptLine::Assistant {
                            text: msg.content.clone(),
                            time: None,
                        })
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
    } else if result.contains("operator denied") || result.contains("denied by persistent rule") {
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
///
/// Phase 2: the loop is the ENGINE's (`orbit_engine::run_turn`) — this
/// front-end supplies only the TUI event adapter (FrontendEvent → Msg)
/// and the tool executor (approvals, grants, plan-mode denial). The
/// old 8-round copy of the loop is gone.
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
    mods_directive: &str,
    plan_mode: bool,
) -> Result<(bool, u64, u64, u64, String), String> {
    // Resolve provider / pricing from config (same as REPL).
    let cfg = crate::config::ProvidersConfig::load(&config.home).unwrap_or_default();
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

    let turn_config = crate::engine_turn_config(
        &config.home,
        &provider_id,
        &resolved_gate,
        &config.model,
        credential_env,
        pricing,
    );

    // The workspace rail tracks the turn's phases (§6.10):
    // 0 orient → 1 reason → 2 act → 3 verify → 4 respond.
    let mut ws = orbit_hud_tui::state::Workspace {
        phase_index: 0,
        ..Default::default()
    };
    orbit_hud_tui::emit_workspace(sender, ws.clone());

    // Event adapter: FrontendEvent → TUI Msg. The CoT stripper is owned
    // by this closure — one per turn — so a `<think>` tag split across
    // deltas is still caught (D6).
    let mut cot = orbit_hud_tui::CotStripper::new();
    let mut first_round_seen = false;
    let mut events = |ev: orbit_frontend_protocol::FrontendEvent| {
        use orbit_frontend_protocol::FrontendEvent as E;
        match ev {
            E::TextDelta { text } => {
                orbit_hud_tui::emit_text(&mut cot, sender, text.as_bytes());
            }
            E::RoundStarted { round } => {
                if round == 0 {
                    ws.phase_index = 1; // reason
                    orbit_hud_tui::emit_workspace(sender, ws.clone());
                    first_round_seen = true;
                }
            }
            E::ToolStarted { name, summary } => {
                if !first_round_seen {
                    // Engine events can arrive before the first round
                    // completes; keep the rail honest.
                    ws.phase_index = 2; // act
                    orbit_hud_tui::emit_workspace(sender, ws.clone());
                }
                orbit_hud_tui::emit_tool_started(sender, &name, &summary);
            }
            E::CostUpdated { total_microcents } => {
                // D5: report the TURN's running cost; the committed total
                // is only touched by ResponseFinished.
                orbit_hud_tui::emit_turn_cost(sender, total_microcents);
            }
            E::OutputTruncated { .. } => {
                orbit_hud_tui::emit_status(sender, "reply cut off by the output-token limit");
            }
            E::Retrying {
                attempt,
                retry_in_ms,
                reason,
            } => {
                orbit_hud_tui::emit_status(
                    sender,
                    &format!("retry {attempt} in {retry_in_ms}ms — {reason}"),
                );
            }
            E::Error { message } => {
                orbit_hud_tui::emit_error(sender, &message);
            }
            E::Status { text } => {
                orbit_hud_tui::emit_status(sender, &text);
            }
            E::TurnEnded { .. } => {
                ws.phase_index = 4; // respond
                orbit_hud_tui::emit_workspace(sender, ws.clone());
            }
            _ => {}
        }
    };

    let mut executor = TuiToolExecutor {
        home: config.home.clone(),
        session_id: config.session_id.clone(),
        auto_tools: config.auto_tools,
        plan_mode,
        sender: sender.clone(),
        approvals: approvals.clone(),
        auto_grants: std::mem::take(auto_grants),
    };

    let options = orbit_engine::TurnOptions {
        tools: crate::tools::tool_definitions(),
        system_directive: (!mods_directive.is_empty()).then(|| mods_directive.to_string()),
        request_stem: "orbit-tui".into(),
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

    // Restore the grants into the caller's slot (the executor borrowed
    // them for the turn).
    *auto_grants = executor.auto_grants;

    match report {
        Ok(r) => Ok((
            r.ok,
            r.input_tokens,
            r.output_tokens,
            r.cost_microcents,
            r.final_text,
        )),
        Err(e) => {
            orbit_hud_tui::emit_error(sender, &e);
            Ok((false, 0, 0, 0, String::new()))
        }
    }
}

/// The TUI's tool executor: bridges the engine's `ToolExecutor` trait
/// to the TUI's approval channel, session grants and plan-mode denial.
struct TuiToolExecutor {
    home: std::path::PathBuf,
    session_id: String,
    auto_tools: bool,
    plan_mode: bool,
    sender: BusSender,
    approvals: ApprovalRegistry,
    auto_grants: crate::tool_runtime::AutoGrants,
}

impl orbit_engine::ToolExecutor for TuiToolExecutor {
    fn execute(
        &mut self,
        calls: &[orbit_engine::PendingToolCall],
        _round: u32,
    ) -> Vec<orbit_engine::ToolRoundResult> {
        // Plan mode: read-only tools run (the model researches while
        // planning); everything else is denied with a notice — no
        // prompt, no execution. Read-only classification is
        // backend-authoritative (tools::is_read_only).
        if self.plan_mode {
            let blocked: Vec<&_> = calls
                .iter()
                .filter(|c| !crate::tools::is_read_only(&c.name))
                .collect();
            if !blocked.is_empty() {
                let mut results = Vec::with_capacity(calls.len());
                for call in calls {
                    if crate::tools::is_read_only(&call.name) {
                        results.push(self.run_one(call));
                    } else {
                        let args = crate::tools::parse_arguments(&call.arguments)
                            .unwrap_or(serde_json::Value::Null);
                        let summary = crate::tools::safe_call_summary(&call.name, &args);
                        orbit_hud_tui::emit_tool_started(&self.sender, &call.name, &summary);
                        orbit_hud_tui::emit_tool_finished(
                            &self.sender,
                            &call.name,
                            orbit_hud_tui::state::ToolOutcome::Denied,
                        );
                        results.push(orbit_engine::ToolRoundResult {
                            call_id: call.id.clone(),
                            content: r#"{"ok":false,"error":"plan mode: read-only — this tool is blocked until the plan is approved"}"#.into(),
                        });
                    }
                }
                return results;
            }
        }

        let mut results = Vec::with_capacity(calls.len());
        for c in calls {
            results.push(self.run_one(c));
        }
        results
    }
}

impl TuiToolExecutor {
    fn run_one(&mut self, call: &orbit_engine::PendingToolCall) -> orbit_engine::ToolRoundResult {
        // Display-safe summary first.
        let args =
            crate::tools::parse_arguments(&call.arguments).unwrap_or(serde_json::Value::Null);
        let summary = crate::tools::safe_call_summary(&call.name, &args);
        orbit_hud_tui::emit_tool_started(&self.sender, &call.name, &summary);

        // Per-call ULID decision ids (defect fix: the old
        // `tool-round-{round}-{index}` ids repeated every turn, so
        // ledger records could not be tied to their turn).
        let decision_id = format!("tool-{}-{}", ulid::Ulid::new(), call.index);
        let mut approval_channel =
            TuiApprovalChannel::new(self.sender.clone(), self.approvals.clone());
        let result = crate::tool_runtime::execute_call(
            &self.home,
            &self.session_id,
            &decision_id,
            call,
            self.auto_tools,
            true,
            &mut approval_channel,
            &mut self.auto_grants,
        )
        .unwrap_or_else(|e| serde_json::json!({ "ok": false, "error": e }).to_string());
        // Classify the result into a ToolOutcome: a refusal must render
        // as `⊘ denied by you`, not a red `✕ failed` (§11.5 rule 4).
        let outcome = classify_tool_result(&result);
        orbit_hud_tui::emit_tool_finished(&self.sender, &call.name, outcome);
        orbit_engine::ToolRoundResult {
            call_id: call.id.clone(),
            content: result,
        }
    }
}
