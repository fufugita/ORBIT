//! TUI worker thread — drives `run_turn` + tool execution for the TUI front-end.
//!
//! The worker receives user prompts via `Msg::TextSubmitted` and runs the
//! four-gate pipeline. Stream events flow through the TUI bridge (display_safe
//! + CoT stripping). Tool approvals resolve via the `ApprovalRegistry`.
//!
//! This is the TUI-specific counterpart to the REPL loop — the REPL's inline
//! logic in `cmd_chat` is untouched.

use orbit_adapter::types::{ChatMessage, ChatRole, ContentBlock, EffortSetting};
use orbit_hud_tui::bus::BusSender;
use orbit_hud_tui::model::TranscriptLine;
use orbit_hud_tui::msg::Msg;
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
    /// Selection provenance, independent of the resolved provider wire value.
    pub effort: Option<EffortSetting>,
    pub provider_id: String,
    pub auto_tools: bool,
    /// The session's permission scope (S5): mode + operator lists.
    /// Mutable at runtime via WorkerCommand::SetMode.
    pub scope: crate::tool_runtime::PermissionScope,
    /// Restored session state. Empty/zero for a fresh chat.
    pub initial_transcript: Vec<ChatMessage>,
    pub initial_turns: u64,
    pub initial_input_tokens: u64,
    pub initial_output_tokens: u64,
    pub initial_cost_microcents: u64,
}

fn configured_turn(config: &TuiTurnConfig) -> Result<orbit_engine::TurnConfig, String> {
    let declared = crate::config::ProvidersConfig::load(&config.home)?;
    let mut turn = crate::checked_model_turn(
        &config.home,
        &config.model,
        Some(&config.provider_id),
        declared.provider.is_empty().then_some(config.gate.as_str()),
        true,
    )?;
    if let Some(choice) = &config.effort {
        crate::apply_effort_setting(&config.home, &mut turn, choice)?;
    }
    turn.validate_effort()?;
    Ok(turn)
}

#[allow(clippy::too_many_arguments)]
fn save_controls(
    config: &TuiTurnConfig,
    lease: &crate::sessions::SessionLease,
    transcript: &[ChatMessage],
    turns: u64,
    input: u64,
    output: u64,
    cost: u64,
    sender: &BusSender,
    origin: crate::phase_routing::SelectionOrigin,
) -> bool {
    let sf = crate::sessions::SessionFile::from_chat(
        &config.session_id,
        &config.model,
        &config.gate,
        &config.provider_id,
        transcript,
        turns,
        input,
        output,
        cost,
    )
    .with_effort(config.effort.clone())
    .with_selection_origin(origin);
    if let Err(e) = lease.save(&sf) {
        orbit_hud_tui::emit_error(sender, &format!("settings unchanged: {e}"));
        return false;
    }
    true
}

/// Build the worker spawner closure for the TUI. The CLI owns `run_turn`;
/// this closure captures the turn config and spawns a thread that drives it.
/// Returns a `CancelHandle` that cancels the turn currently in flight.
pub fn make_spawner(config: TuiTurnConfig) -> orbit_hud_tui::WorkerSpawner {
    Box::new(move |ctx, sink| {
        let lease = crate::sessions::SessionLease::acquire(&config.home, &config.session_id, "tui")
            .map_err(|error| error.to_string())?;
        make_spawner_owned(config, lease)(ctx, sink)
    })
}

/// Start with the lease already held before startup state was loaded.
pub fn make_spawner_owned(
    config: TuiTurnConfig,
    lease: crate::sessions::SessionLease,
) -> orbit_hud_tui::WorkerSpawner {
    Box::new(move |ctx: WorkerCtx, _command_sink: CommandSink| {
        if lease.session_id() != config.session_id {
            return Err("TUI session identity differs from its held lease".into());
        }
        // Shared slot: worker_main installs the CURRENT turn's CancelToken;
        // the handle fires it. None when no turn is running.
        let slot: std::sync::Arc<std::sync::Mutex<Option<orbit_provider_http::CancelToken>>> =
            std::sync::Arc::new(std::sync::Mutex::new(None));
        let handle_slot = slot.clone();
        // AskUserQuestion in the TUI renders through the approval card
        // (an operator decision — same interaction shape): the card's
        // summary lists the question + options; y takes option 1, n
        // takes option 2, Esc/R fall back to option 2 (decline-shaped).
        let ask_sender = ctx.sender.clone();
        let ask_approvals = ctx.approvals.clone();
        struct TuiAsk {
            sender: orbit_hud_tui::bus::BusSender,
            approvals: orbit_hud_tui::ApprovalRegistry,
        }
        impl orbit_tools::askuser::AskChannel for TuiAsk {
            fn ask(
                &self,
                questions: &[orbit_tools::askuser::AskQuestion],
            ) -> orbit_tools::askuser::AskAnswer {
                let first = &questions[0];
                let summary = format!(
                    "{} — options: {}",
                    first.question,
                    first.options.join(" / ")
                );
                let call_id = format!("ask-{}", ulid::Ulid::new());
                let (tx, rx) = std::sync::mpsc::channel();
                self.approvals.register(&call_id, tx);
                self.sender
                    .send(orbit_hud_tui::msg::Msg::ApprovalRequested {
                        call_id,
                        tool_name: "AskUserQuestion".into(),
                        summary,
                        risk: 1,
                        working_dir: std::env::current_dir()
                            .map(|d| d.to_string_lossy().into_owned())
                            .unwrap_or_default(),
                    });
                let pick = match rx.recv() {
                    Ok(orbit_hud_tui::ApprovalResponse::Allow)
                    | Ok(orbit_hud_tui::ApprovalResponse::AllowSession) => 0,
                    _ => 1,
                };
                orbit_tools::askuser::AskAnswer {
                    choices: questions
                        .iter()
                        .map(|q| {
                            vec![
                                q.options
                                    .get(pick)
                                    .or_else(|| q.options.first())
                                    .cloned()
                                    .unwrap_or_default(),
                            ]
                        })
                        .collect(),
                }
            }
        }
        orbit_tools::askuser::set_ask_channel(Some(std::sync::Arc::new(TuiAsk {
            sender: ask_sender,
            approvals: ask_approvals,
        })));
        std::thread::Builder::new()
            .name("orbit-tui-worker".into())
            .spawn(move || worker_main_owned(ctx, config, slot, lease))
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

/// The session's tool context: ONE per session (rebuilt on resume), not
/// per turn, so what a Read recorded still lets the next prompt's Edit
/// through (B2: the executor used to build a fresh one every turn). It
/// is wired to the proof surface: every ledger record the session
/// appends is announced to the Activity panel and counted by the chip.
fn session_tool_context(config: &TuiTurnConfig, sender: &BusSender) -> orbit_tools::ToolContext {
    let cx = orbit_tools::ToolContext::new(
        config.home.clone(),
        config.session_id.clone(),
        std::env::current_dir().unwrap_or_else(|_| std::path::Path::new(".").to_path_buf()),
    );
    let ledger_sender = sender.clone();
    cx.set_ledger_sink(Some(std::sync::Arc::new(
        move |n: &orbit_tools::LedgerNote| {
            orbit_hud_tui::emit_activity(
                &ledger_sender,
                n.kind,
                &display_summary(&n.target),
                &n.fact,
                Some(&n.digest),
            );
        },
    )));
    // A subagent the session starts shows in the Agent panels and on its
    // Task card as it works.
    let agent_sender = sender.clone();
    cx.set_ext(crate::tool_runtime::SubagentObserver(std::sync::Arc::new(
        move |u: &crate::tool_runtime::SubagentUpdate| {
            use crate::tool_runtime::SubagentUpdate as U;
            match u {
                U::Started {
                    id,
                    name,
                    model,
                    task,
                } => orbit_hud_tui::emit_subagent_started_with_model(
                    &agent_sender,
                    id,
                    name,
                    task,
                    model,
                ),
                U::Progress { id, action } => orbit_hud_tui::emit_subagent_progress(
                    &agent_sender,
                    id,
                    &display_summary(action),
                ),
                U::Finished { id, ok, report } => {
                    orbit_hud_tui::emit_subagent_finished(&agent_sender, id, report, *ok)
                }
            }
        },
    )));
    cx
}

/// The worker's event loop — waits for prompts, runs turns, reports results.
/// Each turn gets a fresh CancelToken installed in the shared slot so the
/// TUI's Ctrl+C can abort the in-flight stream.
#[cfg(test)]
fn worker_main(
    ctx: WorkerCtx,
    config: TuiTurnConfig,
    cancel_slot: std::sync::Arc<std::sync::Mutex<Option<orbit_provider_http::CancelToken>>>,
) {
    let lease = crate::sessions::SessionLease::acquire(&config.home, &config.session_id, "tui")
        .expect("private test session ownership");
    worker_main_owned(ctx, config, cancel_slot, lease);
}

fn worker_main_owned(
    ctx: WorkerCtx,
    mut config: TuiTurnConfig,
    cancel_slot: std::sync::Arc<std::sync::Mutex<Option<orbit_provider_http::CancelToken>>>,
    mut lease: crate::sessions::SessionLease,
) {
    let mut selection_origin =
        match crate::sessions::read_selection_origin(lease.home(), lease.session_id()) {
            Ok(origin) => origin,
            Err(error) => {
                orbit_hud_tui::emit_error(&ctx.sender, &error);
                return;
            }
        };
    let mut transcript: Vec<ChatMessage> = config.initial_transcript.clone();
    let mut turns: u64 = config.initial_turns;
    let mut tool_cx = session_tool_context(&config, &ctx.sender);
    // The ledger chip's total: the records already in the chain.
    orbit_hud_tui::emit_ledger_appended(
        &ctx.sender,
        orbit_ledger::count_records(&config.home.join("ledger")),
    );
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
    // The SESSION-scoped tool context (B2/E7): read-before-edit map and
    // the turn checkpoint id live here, reset per prompt.
    let mut session_tool_cx = orbit_tools::ToolContext::new(
        config.home.clone(),
        config.session_id.clone(),
        std::env::current_dir().unwrap_or_else(|_| std::path::Path::new(".").to_path_buf()),
    );
    // Mods (Claude-Mods parity): loaded once at boot, toggleable at
    // runtime. The directive is rebuilt whenever the enabled set changes.
    let mut mods = crate::mods::load_all(&config.home);
    let mut mods_enabled = crate::mods::initial_enabled(&config.home, &mods);
    if crate::mods::validation_status(&config.home).is_err() {
        ctx.sender.send(Msg::SystemMessage("Instruction bundles or enabled metadata are malformed or unsafe. Invalid entries remain disabled; run orbit doctor. Stored files are unchanged.".into()));
    }

    // The JSONL transcript (phase 4): one fsynced line per event —
    // the content record that stays on the machine. Opened once;
    // appended by each turn (user prompt, assistant blocks, tool
    // results, notes).
    let mut transcript_log =
        orbit_engine::transcript::Transcript::open(&config.home, &config.session_id).ok();

    // The frozen system prompt (phase 4): built once per session —
    // base instructions, the tool set, the environment snapshot,
    // memory files, mods. Sent as the System message; never
    // re-inserted per request (that broke caching and edited-history
    // replay). Rebuilt only when the enabled mods set changes.
    let built = build_session_prompt(&config.home, &config.model, &mods, &mods_enabled);
    tool_cx.set_ext(MemoryBytes(built.memory_bytes));
    let mut system_prompt = built.text;

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
        session_prefix: short_session_id(&config.session_id),
        session_id: config.session_id.clone(),
        priced: boot_priced,
    });

    // The sandbox is a readiness fact the welcome screen must not hide:
    // measured once, shown as it is.
    orbit_hud_tui::emit_readiness(
        &ctx.sender,
        vec![(
            sandbox_report().confined,
            sandbox_report().readiness.clone(),
        )],
    );

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
                // Plan mode appends its read-only posture to the frozen
                // prompt (the model keeps its context; only the posture
                // changes).
                let plan_directive = format!(
                    "{system_prompt}\n\n## PLAN MODE (read-only)\nYou are in plan mode. Do NOT attempt changes; all tool calls will be denied. Explore the problem, then respond with a concise, numbered implementation plan. End with a line: `PLAN READY`."
                );
                // Take the scope out of config for the turn (borrow
                // rules: config is borrowed immutably by run_tui_turn).
                let mut scope = std::mem::take(&mut config.scope);
                let (_ok, _input, _output, _cost, plan_text) = match run_tui_turn(
                    &config,
                    &mut transcript,
                    &prompt,
                    None,
                    &ctx.sender,
                    &ctx.approvals,
                    &token,
                    turns,
                    &mut auto_grants,
                    &plan_directive,
                    true,
                    &mut scope,
                    &tool_cx,
                ) {
                    Ok(x) => x,
                    Err(e) => {
                        config.scope = scope;
                        orbit_hud_tui::emit_error(&ctx.sender, &e);
                        orbit_hud_tui::emit_response_finished(
                            &ctx.sender,
                            "",
                            cum_input,
                            cum_output,
                            cum_cost,
                        );
                        if let Ok(mut guard) = cancel_slot.lock() {
                            *guard = None;
                        }
                        continue;
                    }
                };
                config.scope = scope;
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
                // E7: a new user prompt opens a new checkpoint turn.
                session_tool_cx.reset_turn_checkpoint();
                let token = orbit_provider_http::CancelToken::new();
                if let Ok(mut guard) = cancel_slot.lock() {
                    *guard = Some(token.clone());
                }
                // @file mentions expand through the Read tool before the
                // turn runs: deny-read, the scanner and the
                // read-before-edit record all apply to a mention, the
                // same as to a Read call. The transcript logs the
                // ORIGINAL prompt (what the operator typed); the
                // expansion is what the model sees.
                let expanded = expand_file_mentions(&prompt, &session_tool_cx);
                let (expanded_prompt, user_blocks) = expanded.into_prompt();
                if let Some(log) = &transcript_log {
                    let _ = log.append(&orbit_engine::transcript::TranscriptEvent::UserPrompt {
                        text: prompt.clone(),
                    });
                }
                let transcript_len_before = transcript.len();
                let directive = system_prompt.clone();
                let mut scope = std::mem::take(&mut config.scope);
                let (_ok, input, output, cost, _final) = match run_tui_turn(
                    &config,
                    &mut transcript,
                    &expanded_prompt,
                    user_blocks,
                    &ctx.sender,
                    &ctx.approvals,
                    &token,
                    turns,
                    &mut auto_grants,
                    &directive,
                    false,
                    &mut scope,
                    &tool_cx,
                ) {
                    Ok(x) => x,
                    Err(e) => {
                        config.scope = scope;
                        orbit_hud_tui::emit_error(&ctx.sender, &e);
                        orbit_hud_tui::emit_response_finished(
                            &ctx.sender,
                            "",
                            cum_input,
                            cum_output,
                            cum_cost,
                        );
                        if let Ok(mut guard) = cancel_slot.lock() {
                            *guard = None;
                        }
                        continue;
                    }
                };
                config.scope = scope;
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
                // E10: the attestation scan runs in EVERY front-end —
                // an unverified claim becomes a visible status, not a
                // silent exit 0.
                if let Some(scan) = orbit_engine::automation::scan_attestation(&transcript)
                    && scan.claimed_pass
                    && scan.exit_code != 0
                {
                    orbit_hud_tui::emit_status(
                        &ctx.sender,
                        &format!(
                            "UNVERIFIED CLAIM: \"{}\" exited {} at turn time — the claim is not attested",
                            scan.command, scan.exit_code
                        ),
                    );
                }
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
                )
                .with_effort(config.effort.clone())
                .with_selection_origin(selection_origin);
                if let Err(e) = lease.save(&sf) {
                    orbit_hud_tui::emit_error(
                        &ctx.sender,
                        &format!("warning: session not saved: {e}"),
                    );
                }
                // The JSONL transcript: assistant blocks + tool results
                // for the turn just finished, in order.
                if let Some(log) = &transcript_log {
                    for m in transcript.iter().skip(transcript_len_before) {
                        match m.role {
                            ChatRole::Assistant => {
                                let calls: Vec<orbit_engine::transcript::ToolCallRecord> = m
                                    .tool_calls
                                    .as_ref()
                                    .map(|tcs| {
                                        tcs.iter()
                                            .map(|tc| orbit_engine::transcript::ToolCallRecord {
                                                id: tc.id.clone(),
                                                name: tc.name.clone(),
                                                arguments: tc.arguments.clone(),
                                            })
                                            .collect()
                                    })
                                    .unwrap_or_default();
                                let _ = log.append(
                                    &orbit_engine::transcript::TranscriptEvent::Assistant {
                                        text: m.content.clone(),
                                        tool_calls: calls,
                                    },
                                );
                            }
                            ChatRole::Tool => {
                                let _ = log.append(
                                    &orbit_engine::transcript::TranscriptEvent::ToolResult {
                                        call_id: m.tool_call_id.clone().unwrap_or_default(),
                                        content: m.tool_result.clone().unwrap_or_default(),
                                    },
                                );
                            }
                            _ => {}
                        }
                    }
                }
            }
            WorkerCommand::SetModel(model) => {
                if model.is_empty() {
                    continue;
                }
                let providers = match crate::config::ProvidersConfig::load(&config.home) {
                    Ok(providers) => providers,
                    Err(error) => {
                        ctx.sender
                            .send(Msg::EffortStatus(format!("Model unchanged:\n{error}")));
                        continue;
                    }
                };
                let selected = match crate::resolve_selected_model(&providers, &model, None, false)
                {
                    Ok(selected) => selected,
                    Err(error) => {
                        ctx.sender
                            .send(Msg::EffortStatus(format!("Model unchanged:\n{error}")));
                        continue;
                    }
                };
                let mut candidate = config.clone();
                candidate.model = selected.raw_model;
                candidate.provider_id = selected.provider_id;
                candidate.gate = selected.url;
                let resolved = match configured_turn(&candidate) {
                    Ok(turn) => turn,
                    Err(e) => {
                        ctx.sender.send(Msg::EffortStatus(format!(
                            "Model unchanged:\n{e}\nUse /effort default before switching."
                        )));
                        continue;
                    }
                };
                if !save_controls(
                    &candidate,
                    &lease,
                    &transcript,
                    turns,
                    cum_input,
                    cum_output,
                    cum_cost,
                    &ctx.sender,
                    crate::phase_routing::SelectionOrigin::Interactive,
                ) {
                    continue;
                }
                selection_origin = crate::phase_routing::SelectionOrigin::Interactive;
                let old = config.model.clone();
                candidate.provider_id = resolved.provider_id;
                candidate.gate = resolved.gate;
                config = candidate;
                let built = build_session_prompt(&config.home, &config.model, &mods, &mods_enabled);
                tool_cx.set_ext(MemoryBytes(built.memory_bytes));
                system_prompt = built.text;
                ctx.sender.send(Msg::ModelChanged(config.model.clone()));
                orbit_hud_tui::emit_status(&ctx.sender, &format!("model → {model} (was {old})"));
            }
            WorkerCommand::Effort(value) => {
                let mut candidate = config.clone();
                if !value.is_empty() {
                    match crate::parse_effort_setting(&value) {
                        Ok(choice) => candidate.effort = Some(choice),
                        Err(e) => {
                            ctx.sender
                                .send(Msg::EffortStatus(format!("Effort unchanged:\n{e}")));
                            continue;
                        }
                    }
                }
                match configured_turn(&candidate) {
                    Ok(turn) => {
                        if !value.is_empty() {
                            if !save_controls(
                                &candidate,
                                &lease,
                                &transcript,
                                turns,
                                cum_input,
                                cum_output,
                                cum_cost,
                                &ctx.sender,
                                selection_origin,
                            ) {
                                continue;
                            }
                            config = candidate;
                        }
                        ctx.sender
                            .send(Msg::EffortStatus(crate::effort_status(&config.home, &turn)));
                    }
                    Err(e) => ctx
                        .sender
                        .send(Msg::EffortStatus(format!("Effort unchanged:\n{e}"))),
                }
            }
            WorkerCommand::Route(argument) => {
                let words: Vec<String> = argument.split_whitespace().map(str::to_owned).collect();
                let base = match configured_turn(&config) {
                    Ok(base) => base,
                    Err(error) => {
                        ctx.sender
                            .send(Msg::SystemMessage(format!("route: {error}")));
                        continue;
                    }
                };
                if words.as_slice() == ["auto"] {
                    let validation = crate::route_command(
                        &config.home,
                        &["status".into()],
                        Some(&base),
                        selection_origin,
                    );
                    if let Err(error) = validation {
                        ctx.sender
                            .send(Msg::SystemMessage(format!("routing unchanged: {error}")));
                        continue;
                    }
                    if save_controls(
                        &config,
                        &lease,
                        &transcript,
                        turns,
                        cum_input,
                        cum_output,
                        cum_cost,
                        &ctx.sender,
                        crate::phase_routing::SelectionOrigin::Default,
                    ) {
                        selection_origin = crate::phase_routing::SelectionOrigin::Default;
                        ctx.sender.send(Msg::Routing(Vec::new()));
                        ctx.sender.send(Msg::SystemMessage(
                            "Automatic routing enabled for this session".into(),
                        ));
                    }
                } else {
                    match crate::route_command(&config.home, &words, Some(&base), selection_origin)
                    {
                        Ok(value) => ctx.sender.send(Msg::SystemMessage(
                            serde_json::to_string_pretty(&value).unwrap_or_default(),
                        )),
                        Err(error) => ctx
                            .sender
                            .send(Msg::SystemMessage(format!("route: {error}"))),
                    }
                }
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
                let target = if id.strip_suffix(".json").unwrap_or(&id) == lease.session_id() {
                    lease.load().map(|saved| (None, saved))
                } else {
                    crate::sessions::SessionLease::acquire_and_load(&config.home, &id, "tui")
                        .map(|(guard, saved)| (Some(guard), saved))
                };
                match target {
                    Ok((candidate_lease, s)) => {
                        let mut candidate = config.clone();
                        candidate.session_id = s.session_id.clone();
                        candidate.model = s.model.clone();
                        candidate.gate = s.gate.clone();
                        candidate.provider_id = s.provider.clone();
                        candidate.effort = s.effort.clone();
                        match configured_turn(&candidate) {
                            Ok(turn) => {
                                candidate.gate = turn.gate;
                                candidate.provider_id = turn.provider_id;
                            }
                            Err(e) => {
                                ctx.sender
                                    .send(Msg::SystemMessage(format!("cannot resume {id}: {e}")));
                                continue;
                            }
                        }
                        let candidate_log = match orbit_engine::transcript::Transcript::open(
                            &config.home,
                            &s.session_id,
                        ) {
                            Ok(log) => log,
                            Err(error) => {
                                ctx.sender.send(Msg::SystemMessage(format!(
                                    "cannot resume {id}: transcript: {error}"
                                )));
                                continue;
                            }
                        };
                        transcript_log = Some(candidate_log);
                        selection_origin = crate::sessions::model_origin(Some(&s));
                        ctx.sender.send(Msg::Routing(Vec::new()));
                        config = candidate;
                        if let Some(candidate_lease) = candidate_lease {
                            lease = candidate_lease;
                        }
                        transcript = s.to_transcript();
                        turns = s.turns;
                        config.session_id = s.session_id.clone();
                        config.model = s.model.clone();
                        tool_cx = session_tool_context(&config, &ctx.sender);
                        session_tool_cx = orbit_tools::ToolContext::new(
                            config.home.clone(),
                            config.session_id.clone(),
                            tool_cx.working_dir.clone(),
                        );
                        let built =
                            build_session_prompt(&config.home, &config.model, &mods, &mods_enabled);
                        tool_cx.set_ext(MemoryBytes(built.memory_bytes));
                        system_prompt = built.text;
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
                            session_prefix: short_session_id(&s.session_id),
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
                let outcome = configured_turn(&config)
                    .and_then(|turn| crate::try_role_turn_config(&config.home, &turn, "compaction"))
                    .map_err(|e| ("ORBIT-E0401", e))
                    .and_then(|turn| {
                        orbit_engine::run_dispatch(
                            &config.home,
                            &turn,
                            &prompt,
                            Some(vec![]),
                            None,
                            token.clone(),
                            vec![],
                            "orbit-compact",
                            &config.session_id,
                        )
                    });
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
                            origin_model: None,
                            origin_provider: None,
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
                        )
                        .with_effort(config.effort.clone())
                        .with_selection_origin(selection_origin);
                        if let Err(e) = lease.save(&sf) {
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
                if crate::mods::validation_status(&config.home).is_err() {
                    ctx.sender.send(Msg::SystemMessage("Instruction bundle validation failed; run orbit doctor. Malformed enabled metadata is preserved and defaults stay disabled.".into()));
                }

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
                        // The frozen prompt rebuilds so the next turn
                        // carries the new mods set (append-only: the
                        // change arrives as a new prompt, never an edit).
                        let built =
                            build_session_prompt(&config.home, &config.model, &mods, &mods_enabled);
                        tool_cx.set_ext(MemoryBytes(built.memory_bytes));
                        system_prompt = built.text;
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
                let built = build_session_prompt(&config.home, &config.model, &mods, &mods_enabled);
                tool_cx.set_ext(MemoryBytes(built.memory_bytes));
                system_prompt = built.text;
                ctx.sender.send(Msg::SystemMessage(format!(
                    "mods reloaded: {} installed, {} enabled",
                    mods.len(),
                    mods_enabled.len()
                )));
            }
            WorkerCommand::Rewind(arg) => {
                // /rewind (phase 4): no argument lists checkpoints;
                // with an id restores every snapshotted file and
                // reports. Conversation restore reuses /undo's
                // transcript pop per checkpoint event.
                let cps =
                    orbit_engine::transcript::Checkpoints::new(&config.home, &config.session_id);
                if arg.trim().is_empty() {
                    let list = cps.list();
                    if list.is_empty() {
                        ctx.sender.send(Msg::SystemMessage(
                            "no checkpoints yet (one opens at each prompt that changes files)"
                                .into(),
                        ));
                    } else {
                        let text = list
                            .iter()
                            .rev()
                            .map(|id| format!("  {id}"))
                            .collect::<Vec<_>>()
                            .join("\n");
                        ctx.sender.send(Msg::SystemMessage(format!(
                            "checkpoints (newest first):\n{text}"
                        )));
                    }
                } else {
                    match cps.restore(arg.trim()) {
                        Ok(files) if !files.is_empty() => {
                            if let Some(log) = &transcript_log {
                                let _ = log.append(
                                    &orbit_engine::transcript::TranscriptEvent::Rewound {
                                        to_checkpoint: arg.trim().to_string(),
                                    },
                                );
                            }
                            ctx.sender.send(Msg::SystemMessage(format!(
                                "restored {} file(s) to checkpoint {}",
                                files.len(),
                                arg.trim()
                            )));
                        }
                        Ok(_) => {
                            ctx.sender.send(Msg::SystemMessage(format!(
                                "checkpoint {} has no file snapshots (nothing was written that turn)",
                                arg.trim()
                            )));
                        }
                        Err(e) => {
                            ctx.sender
                                .send(Msg::SystemMessage(format!("rewind failed: {e}")));
                        }
                    }
                }
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
                        )
                        .with_effort(config.effort.clone())
                        .with_selection_origin(selection_origin);
                        match lease.save(&sf) {
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
            WorkerCommand::SetMode(mode_name) => {
                // S5: runtime mode change. The scope is session state
                // (no env var); the next turn obeys it.
                match orbit_tools::permissions::PermissionMode::from_config(&mode_name) {
                    Some(mode) => {
                        config.scope.mode = mode;
                        orbit_hud_tui::emit_mode_changed(&ctx.sender, &mode_name);
                    }
                    None => {
                        orbit_hud_tui::emit_error(
                            &ctx.sender,
                            &format!(
                                "unknown mode {mode_name} (default, acceptEdits, plan, dontAsk, bypass)"
                            ),
                        );
                    }
                }
            }
            WorkerCommand::Permissions(arg) => {
                let text = crate::tool_runtime::permission_command(
                    &config.home,
                    &config.scope,
                    &tool_cx.working_dir,
                    &arg,
                )
                .unwrap_or_else(|error| format!("permissions: {error}"));
                ctx.sender.send(Msg::SystemMessage(text));
            }
            WorkerCommand::ShellBang(command) => {
                // The shell bang (gate 1): one command through the Bash
                // tool's FULL path — sandbox, permissions, approvals,
                // scanner, ledger — exactly as if the model had called
                // it. The transcript shows the tool line; the composer
                // never blocks (this runs on the worker thread).
                let call = orbit_engine::PendingToolCall {
                    index: 0,
                    id: format!("bang-{}", ulid::Ulid::new()),
                    name: "Bash".into(),
                    arguments: serde_json::json!({ "command": command })
                        .to_string()
                        .into_bytes(),
                };
                let decision_id = format!("bang-{}", ulid::Ulid::new());
                let mut approval_channel =
                    TuiApprovalChannel::new(ctx.sender.clone(), ctx.approvals.clone());
                // The session's context: its ledger sink announces the
                // `!` command's records like any other call's.
                let tool_cx = tool_cx.clone();
                orbit_hud_tui::emit_tool_started(&ctx.sender, &call.id, "Bash", &command);
                tool_cx.set_output_sink(Some(live_output_sink(&ctx.sender, &call.id)));
                let (result, _) = crate::tool_runtime::execute_call(
                    &config.home,
                    &config.session_id,
                    &decision_id,
                    &call,
                    false, // never auto-allow: the bang asks like any Bash call
                    true,
                    &mut approval_channel,
                    &mut auto_grants,
                    &config.scope,
                    &tool_cx,
                )
                .unwrap_or_else(|e| {
                    (
                        serde_json::json!({ "ok": false, "error": e }).to_string(),
                        None,
                    )
                });
                tool_cx.set_output_sink(None);
                let outcome = classify_tool_result(&result);
                let fact = result_fact("Bash", &result);
                orbit_hud_tui::emit_tool_finished(&ctx.sender, &call.id, "Bash", outcome, &fact);
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
                                outcome: Some(orbit_hud_tui::model::ToolOutcome::Ok),
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
    /// The call the last question was about, to fetch its denial note.
    last_call: Option<String>,
}

impl TuiApprovalChannel {
    pub fn new(sender: BusSender, approvals: ApprovalRegistry) -> Self {
        Self {
            sender,
            approvals,
            last_call: None,
        }
    }
}

/// Classify a tool result JSON into a `ToolOutcome` for the transcript card.
/// The denial and block paths in `execute_call` produce `ok:false` results
/// with these exact error strings (crates/cli/src/tool_runtime.rs:243-251);
/// everything else with `ok:true` is a success, and any other `ok:false`
/// means the tool genuinely ran and failed. A refusal must never render as
/// a red `✕ failed` card (§11.5 rule 4, `denied_is_not_failed`).
fn classify_tool_result(result: &str) -> orbit_hud_tui::model::ToolOutcome {
    use orbit_hud_tui::model::ToolOutcome;
    if orbit_tools::result_is_denial(result) {
        // C4: the typed flag — every policy refusal carries it, so the
        // substring lists are gone (they missed new denial sites).
        ToolOutcome::Denied
    } else if result.contains("unknown tool (deny-by-default)") {
        ToolOutcome::Blocked
    } else if result_is_cancelled(result) {
        // The operator's Esc: neither a failure nor a denial.
        ToolOutcome::Cancelled
    } else if !orbit_tools::result_is_error(result) {
        // E4: the typed verdict — the payload's own top-level `ok`, not
        // a substring (a Bash command that prints `"ok":true` and exits
        // 1 is a failure).
        ToolOutcome::Ok
    } else {
        ToolOutcome::Failed
    }
}

/// What the shell sandbox is on this machine, measured once per process
/// (the probe runs a real bubblewrap canary): whether commands are
/// confined, the rows an approval card shows, and the welcome screen's
/// readiness line.
struct SandboxReport {
    confined: bool,
    /// `(label, value)` rows for the approval card — short enough to
    /// fit a card without clipping.
    facts: Vec<(String, String)>,
    /// The welcome screen's READY row.
    readiness: String,
}

fn sandbox_report() -> &'static SandboxReport {
    static REPORT: std::sync::OnceLock<SandboxReport> = std::sync::OnceLock::new();
    REPORT.get_or_init(|| {
        use orbit_tools::sandbox::{SandboxStatus, ShellSandbox};
        match ShellSandbox::probe() {
            SandboxStatus::Confined => SandboxReport {
                confined: true,
                facts: vec![
                    ("sandbox".into(), "confined · no network".into()),
                    (
                        "writes".into(),
                        "this project and a session temp dir only".into(),
                    ),
                ],
                readiness: "sandbox · bubblewrap".into(),
            },
            SandboxStatus::Unavailable(why) => SandboxReport {
                confined: false,
                facts: vec![(
                    "sandbox".into(),
                    "NONE — runs with your full permissions".into(),
                )],
                readiness: format!("sandbox · off ({why}) — every command asks"),
            },
            SandboxStatus::Unsupported => SandboxReport {
                confined: false,
                facts: vec![(
                    "sandbox".into(),
                    "NONE — no sandbox on this platform".into(),
                )],
                readiness: "sandbox · none on this platform — every command asks".into(),
            },
        }
    })
}

/// Set the proof chip's total from the ledger itself. Several writers
/// append (tool calls, provider requests, subagents); announcing each one
/// keeps the chip live, and this keeps it TRUE — it cannot drift from
/// what `orbit ledger verify` would count.
fn resync_ledger_chip(home: &std::path::Path, sender: &BusSender) {
    orbit_hud_tui::emit_ledger_appended(sender, orbit_ledger::count_records(&home.join("ledger")));
}

/// The host part of a gateway URL, for display (`http://127.0.0.1:4001/v1`
/// → `127.0.0.1:4001`).
fn host_of(url: &str) -> String {
    let rest = url.split_once("://").map(|(_, r)| r).unwrap_or(url);
    rest.split('/').next().unwrap_or(rest).to_string()
}

/// Did the operator's interrupt end this call? The Bash tool answers a
/// cancelled run with the typed error `cancelled by user`.
fn result_is_cancelled(result: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(result)
        .ok()
        .and_then(|v| {
            v.get("error")
                .and_then(|e| e.as_str())
                .map(|e| e == "cancelled by user")
        })
        .unwrap_or(false)
}

/// A short, true fact about a tool result for its card — what the
/// result itself says, never a guess. Empty when it has nothing worth a
/// column (the card then shows only the duration).
fn result_fact(tool: &str, result: &str) -> String {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(result) else {
        return String::new();
    };
    let plural = |n: usize, one: &str, many: &str| {
        if n == 1 {
            format!("{n} {one}")
        } else {
            format!("{n} {many}")
        }
    };
    let truncated = v
        .get("truncated")
        .and_then(|t| t.as_bool())
        .unwrap_or(false);
    match tool {
        "Read" => v
            .get("content")
            .and_then(|c| c.as_str())
            .map(|c| {
                let n = c.lines().count();
                if v.get("partial").and_then(|p| p.as_bool()).unwrap_or(false) {
                    format!("{n} lines · partial")
                } else {
                    plural(n, "line", "lines")
                }
            })
            .unwrap_or_default(),
        "Glob" | "Grep" => v
            .get("matches")
            .and_then(|m| m.as_array())
            .map(|m| {
                let (one, many) = if tool == "Glob" {
                    ("file", "files")
                } else {
                    ("match", "matches")
                };
                if truncated {
                    format!("{}+ {many}", m.len())
                } else {
                    plural(m.len(), one, many)
                }
            })
            .unwrap_or_default(),
        "Bash" => {
            if v.get("backgrounded")
                .and_then(|b| b.as_bool())
                .unwrap_or(false)
            {
                "background".to_string()
            } else {
                match v.get("exit_code").and_then(|c| c.as_i64()) {
                    Some(0) | None => String::new(),
                    Some(c) => format!("exit {c}"),
                }
            }
        }
        _ => String::new(),
    }
}

/// The target as the operator should read it: a path under the working
/// directory is shown relative to it, and one under $HOME as `~/…`, so a
/// long absolute prefix never pushes the file name off the card.
fn display_target(kind: &str, target: &str) -> String {
    if !matches!(kind, "Read" | "Write" | "Edit" | "NotebookEdit") {
        return target.to_string();
    }
    display_path(target)
}

/// A call summary (`Edit(/proj/src/a.rs)`) with a file tool's path shown
/// the way the Changes panel shows it: relative to the project. Other
/// summaries (a Bash command line) are shown as recorded.
fn display_summary(summary: &str) -> String {
    for name in ["Read", "Write", "Edit", "NotebookEdit"] {
        if let Some(arg) = summary
            .strip_prefix(name)
            .and_then(|r| r.strip_prefix('('))
            .and_then(|r| r.strip_suffix(')'))
        {
            return format!("{name}({})", display_path(arg));
        }
    }
    summary.to_string()
}

fn display_path(path: &str) -> String {
    if !path.starts_with('/') {
        return path.to_string();
    }
    if let Ok(cwd) = std::env::current_dir()
        && let Some(rest) = path.strip_prefix(cwd.to_string_lossy().as_ref())
        && let Some(rest) = rest.strip_prefix('/')
        && !rest.is_empty()
    {
        return rest.to_string();
    }
    if let Some(home) = std::env::var_os("HOME")
        && let Some(rest) = path.strip_prefix(home.to_string_lossy().as_ref())
        && rest.starts_with('/')
    {
        return format!("~{rest}");
    }
    path.to_string()
}

/// Live command output for the Terminal panel: every line up to a cap,
/// then one honest notice. A runaway command must not flood the UI bus;
/// its full output stays in the call's log file.
fn live_output_sink(sender: &BusSender, call_id: &str) -> orbit_tools::OutputSink {
    const MAX_LIVE_LINES: usize = 3000;
    let sender = sender.clone();
    let call_id = call_id.to_string();
    let seen = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    std::sync::Arc::new(move |line: &str| {
        let n = seen.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if n < MAX_LIVE_LINES {
            orbit_hud_tui::emit_tool_output(&sender, &call_id, line);
        } else if n == MAX_LIVE_LINES {
            orbit_hud_tui::emit_tool_output(
                &sender,
                &call_id,
                "… more output; the full log is kept with the session's outputs",
            );
        }
    })
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
        // The facts the card shows, measured, never assumed: what a Bash
        // command can touch, and (from the request) what an edit changes.
        let mut facts = Vec::new();
        if req.tool_name == "Bash" {
            facts.extend(sandbox_report().facts.iter().cloned());
        }
        let grant = req.grant.as_ref().map(|g| orbit_hud_tui::ApprovalGrant {
            rule: g.rule.clone(),
            can_save: g.can_save,
        });
        orbit_hud_tui::emit_approval_detail(
            &self.sender,
            &req.call_id,
            facts,
            req.preview.clone(),
            grant,
        );
        self.last_call = Some(req.call_id.clone());
        // Post the request to the bus — the reducer renders an approval card.
        self.sender.send(Msg::ApprovalRequested {
            call_id: req.call_id.clone(),
            tool_name: req.tool_name.clone(),
            summary: req.summary.clone(),
            risk: req.risk.level(),
            working_dir: std::env::current_dir()
                .map(|d| d.to_string_lossy().into_owned())
                .unwrap_or_default(),
        });
        // Park until the operator responds (y/s/a/R/n). Esc handled as deny.
        match rx.recv() {
            Ok(ApprovalResponse::Allow) => crate::tool_runtime::ApprovalVerdict::AllowOnce,
            Ok(ApprovalResponse::AllowSession) => {
                crate::tool_runtime::ApprovalVerdict::AllowSession
            }
            Ok(ApprovalResponse::AllowRule) => {
                crate::tool_runtime::ApprovalVerdict::AllowRuleSession
            }
            Ok(ApprovalResponse::AllowRuleAlways) => {
                crate::tool_runtime::ApprovalVerdict::AllowRuleAlways
            }
            Ok(ApprovalResponse::Deny) | Err(_) => crate::tool_runtime::ApprovalVerdict::Deny,
        }
    }

    fn take_note(&mut self) -> Option<String> {
        let call = self.last_call.take()?;
        self.approvals.take_note(&call)
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
    user_blocks: Option<Vec<ContentBlock>>,
    sender: &BusSender,
    approvals: &ApprovalRegistry,
    cancel: &orbit_provider_http::CancelToken,
    // Kept for signature stability; the worker loop owns turn counting and
    // session saving (D9) — the turn itself no longer needs it.
    _turns: u64,
    auto_grants: &mut crate::tool_runtime::AutoGrants,
    mods_directive: &str,
    plan_mode: bool,
    // The session's permission scope (S5), mutable across turns: the
    // worker loop's SetMode command updates config.scope in place —
    // no process env, no per-call reads.
    scope: &mut crate::tool_runtime::PermissionScope,
    // The session's tool context (see `session_tool_context`).
    tool_cx: &orbit_tools::ToolContext,
) -> Result<(bool, u64, u64, u64, String), String> {
    // One checkpoint per prompt (E7): /rewind restores a turn. The context
    // is the session's now, so the turn boundary is marked here.
    tool_cx.reset_turn_checkpoint();
    let base_turn_config = configured_turn(config)?;
    let origin = crate::sessions::read_selection_origin(&config.home, &config.session_id)?;
    let (turn_config, routing_decision) =
        crate::try_phase_turn_config(&config.home, &base_turn_config, prompt, origin)?;
    let resolved_gate = turn_config.gate.clone();
    turn_config.validate_effort()?;
    let compaction_config = crate::try_role_turn_config(&config.home, &turn_config, "compaction")?;
    crate::tool_runtime::remember_effort_setting(
        tool_cx,
        if turn_config.provider_id == base_turn_config.provider_id
            && turn_config.model == base_turn_config.model
        {
            &config.effort
        } else {
            &None
        },
    );
    if let Some(decision) = routing_decision {
        let line = crate::daemon::scan_display(&format!(
            "route {}/{} → {}/{} ({:?})",
            decision.phase.as_str(),
            decision.difficulty.as_str(),
            decision.provider_id,
            decision.raw_model,
            decision.source
        ));
        orbit_hud_tui::emit_status(sender, &line);
        sender.send(Msg::Routing(vec![line]));
    }

    // The workspace rail tracks the turn's phases (§6.10):
    // 0 orient → 1 reason → 2 act → 3 verify → 4 respond.
    let mut ws = orbit_hud_tui::model::Workspace {
        phase_index: 0,
        ..Default::default()
    };
    orbit_hud_tui::emit_workspace(sender, ws.clone());

    // Event adapter: FrontendEvent → TUI Msg. The CoT stripper is owned
    // by this closure — one per turn — so a `<think>` tag split across
    // deltas is still caught (D6).
    let mut cot = orbit_hud_tui::CotStripper::new();
    let mut first_round_seen = false;
    // The size a running compaction started from, for its "before → after".
    let mut compact_from: u64 = 0;
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
            E::Compacting {
                used_tokens,
                window_tokens,
            } => {
                compact_from = used_tokens;
                orbit_hud_tui::emit_compaction(sender, true, used_tokens);
                orbit_hud_tui::emit_activity(
                    sender,
                    "compaction",
                    "compacting context",
                    &format!("{used_tokens} of {window_tokens} tokens"),
                    None,
                );
            }
            E::Compacted {
                summary,
                after_tokens,
            } => {
                orbit_hud_tui::emit_compaction(sender, false, after_tokens);
                let _ = summary;
                orbit_hud_tui::emit_activity(
                    sender,
                    "compaction",
                    "compacted",
                    &format!(
                        "~{} → ~{} tokens",
                        orbit_hud_tui::tokens_short(compact_from),
                        orbit_hud_tui::tokens_short(after_tokens)
                    ),
                    None,
                );
            }
            E::ToolStarted { name, summary } => {
                if !first_round_seen {
                    // Engine events can arrive before the first round
                    // completes; keep the rail honest.
                    ws.phase_index = 2; // act
                    orbit_hud_tui::emit_workspace(sender, ws.clone());
                }
                // No card here: ToolStartedFull carries the call's id and
                // target, and the card is keyed by that id.
                let _ = (name, summary);
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
                orbit_hud_tui::emit_activity(
                    sender,
                    "retry",
                    &format!("attempt {attempt}"),
                    &format!("in {retry_in_ms} ms — {reason}"),
                    None,
                );
                // The failed attempt still wrote its egress record.
                resync_ledger_chip(&config.home, sender);
            }
            E::Error { message } => {
                orbit_hud_tui::emit_error(sender, &message);
                resync_ledger_chip(&config.home, sender);
            }
            E::Status { text } => {
                orbit_hud_tui::emit_status(sender, &text);
            }
            E::TurnEnded { interrupted, .. } => {
                ws.phase_index = 4; // respond
                orbit_hud_tui::emit_workspace(sender, ws.clone());
                resync_ledger_chip(&config.home, sender);
                if interrupted {
                    // The visible cancel: the MD's loop contract says a
                    // cancelled turn keeps the transcript valid — say so.
                    orbit_hud_tui::emit_status(sender, "cancelled");
                }
            }
            // ── The TUI prototype's motion events. Each carries what
            // one panel needs; the HUD layer keeps its own renderers.
            E::ToolStartedFull {
                call_id,
                kind,
                target,
            } => {
                orbit_hud_tui::emit_tool_started(
                    sender,
                    &call_id,
                    &kind,
                    &display_target(&kind, &target),
                );
            }
            E::ToolOutput { call_id, line } => {
                orbit_hud_tui::emit_tool_output(sender, &call_id, &line);
            }
            E::ToolFinishedFull {
                call_id,
                ok,
                result_fact,
            } => {
                // The executor reports each call as it finishes, with the
                // typed outcome (denied / cancelled / failed) and a real
                // fact; the screen keeps the state a card settled in. This
                // is the fallback for calls no executor of ours ran
                // (a subagent's): the engine's verdict settles them.
                let outcome = if ok {
                    orbit_hud_tui::model::ToolOutcome::Ok
                } else {
                    orbit_hud_tui::model::ToolOutcome::Failed
                };
                orbit_hud_tui::emit_tool_finished(sender, &call_id, "", outcome, &result_fact);
                // The result record is on the chain by now.
                resync_ledger_chip(&config.home, sender);
            }
            E::FileChanged {
                path,
                added,
                removed,
                checkpoint_id: _,
                hunks,
            } => {
                orbit_hud_tui::emit_file_changed(
                    sender,
                    &display_path(&path),
                    added,
                    removed,
                    hunks.clone(),
                );
            }
            E::SubagentStarted {
                agent_id,
                name,
                task,
                model: _,
            } => {
                orbit_hud_tui::emit_subagent_started(sender, &agent_id, &name, &task);
            }
            E::SubagentProgress { agent_id, action } => {
                orbit_hud_tui::emit_subagent_progress(sender, &agent_id, &action);
            }
            E::SubagentFinished { agent_id, report } => {
                orbit_hud_tui::emit_subagent_finished(sender, &agent_id, &report, true);
            }
            E::ModeChanged { mode } => {
                orbit_hud_tui::emit_mode_changed(sender, &mode);
            }
            E::Usage {
                used_tokens,
                window_tokens,
                breakdown,
            } => {
                orbit_hud_tui::emit_usage(sender, used_tokens, window_tokens, breakdown);
            }
            E::LedgerAppended {
                record_count,
                head_digest,
                kind,
                summary,
            } => {
                // The row first (it counts one on the chip), then the
                // ledger's own total, which is the authority.
                if !kind.is_empty() {
                    orbit_hud_tui::emit_activity(
                        sender,
                        &kind,
                        &host_of(&resolved_gate),
                        &summary,
                        Some(&head_digest),
                    );
                }
                orbit_hud_tui::emit_ledger_appended(sender, record_count);
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
        scope: std::mem::take(scope),
        tool_cx: tool_cx.clone(),
    };

    let options = orbit_engine::TurnOptions {
        user_blocks,
        tools: crate::tools::session_tool_definitions(&config.home),
        session_id: config.session_id.clone(),
        system_directive: (!mods_directive.is_empty()).then(|| mods_directive.to_string()),
        memory_bytes: tool_cx.ext::<MemoryBytes>().map_or(0, |m| m.0),
        // Resolve the selected provider and raw model's legacy input policy.
        // The engine measures the prepared request and applies the active budget.
        window_tokens: crate::context_window_for_turn(&config.home, &turn_config),
        request_stem: "orbit-tui".into(),
        // The compaction role: a cheap model may summarize while the
        // conversation keeps its own. None = same model summarizes.
        compaction_config: Some(compaction_config),
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

    // Restore the grants and the scope into the caller's slots (the
    // executor borrowed them for the turn; SetMode may have changed
    // the scope mid-turn).
    *auto_grants = executor.auto_grants;
    *scope = executor.scope;

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
    /// The session's permission scope (S5): mode + operator lists,
    /// mutable at runtime via WorkerCommand::SetMode.
    scope: crate::tool_runtime::PermissionScope,
    /// One context per TUI session (B2): read-before-edit survives
    /// across rounds.
    tool_cx: orbit_tools::ToolContext,
}

impl orbit_engine::ToolExecutor for TuiToolExecutor {
    fn begin_turn(&mut self, config: &orbit_engine::TurnConfig) {
        crate::tool_runtime::remember_turn_config(&self.tool_cx, config);
    }

    fn execute(
        &mut self,
        calls: &[orbit_engine::PendingToolCall],
        _round: u32,
    ) -> Vec<orbit_engine::ToolRoundResult> {
        // After Esc the calls that have not started do not run: they are
        // answered "cancelled by user" and their cards settle at once.
        let cx = self.tool_cx.clone();
        let sender = self.sender.clone();
        let on_skip = move |call: &orbit_engine::PendingToolCall| {
            orbit_hud_tui::emit_tool_finished(
                &sender,
                &call.id,
                &call.name,
                orbit_hud_tui::model::ToolOutcome::Cancelled,
                "",
            );
        };
        // Plan mode: read-only tools run (the model researches while
        // planning); everything else is denied with a notice — no
        // prompt, no execution. Read-only classification is
        // backend-authoritative (tools::is_read_only).
        if self.plan_mode && calls.iter().any(|c| !crate::tools::is_read_only(&c.name)) {
            return crate::tool_runtime::run_until_cancelled(
                &cx,
                calls,
                |call| {
                    if crate::tools::is_read_only(&call.name) {
                        self.run_one(call)
                    } else {
                        // The engine announced the call; settle its card.
                        orbit_hud_tui::emit_tool_finished(
                            &self.sender,
                            &call.id,
                            &call.name,
                            orbit_hud_tui::model::ToolOutcome::Denied,
                            "",
                        );
                        orbit_engine::ToolRoundResult {
                            call_id: call.id.clone(),
                            content: r#"{"ok":false,"error":"plan mode: read-only — this tool is blocked until the plan is approved"}"#.into(),
                        }
                    }
                },
                on_skip,
            );
        }
        // The default path: a run of two or more parallel-safe read-only
        // calls runs concurrently (bounded); everything else sequential
        // in the model's order. `run_ro` captures only owned, `Sync`
        // state — no borrow of self, no thread-local.
        let run_ro = self.read_only_runner();
        crate::tool_runtime::run_round_parallel(&cx, calls, |c| self.run_one(c), run_ro, on_skip)
    }

    fn begin_cancel_scope(&mut self, token: &orbit_provider_http::CancelToken) {
        crate::tool_runtime::begin_cancel_scope(&self.tool_cx, token);
    }

    fn end_cancel_scope(&mut self) {
        self.tool_cx.pop_cancel_check();
    }
}

/// One parallel-safe call on a worker thread. Shared state arrives in
/// `st` (all Arc-interior or plain data): the tool context (its
/// read-before-edit map is shared), the bus sender (thread-safe), the
/// approval registry (thread-safe). Two honest limits, by design:
/// - Grants: a scratch `AutoGrants` per worker. The parallel set
///   (Read/Glob/Grep/TaskList) never prompts in default/acceptEdits/
///   plan modes, so there is nothing to remember; if the operator
///   pinned an Ask rule on one, the card still appears and the verdict
///   still governs the call — only an `s`/`a` press from that odd ask
///   is not kept for later calls.
/// - Live output: no output sink. These tools return whole results;
///   the sink is Bash's streaming surface and would interleave.
struct TuiReadOnlyState {
    home: std::path::PathBuf,
    session_id: String,
    auto_tools: bool,
    scope: crate::tool_runtime::PermissionScope,
    tool_cx: orbit_tools::ToolContext,
    sender: orbit_hud_tui::bus::BusSender,
    approvals: orbit_hud_tui::ApprovalRegistry,
}

fn run_read_only_call(
    st: &TuiReadOnlyState,
    call: orbit_engine::PendingToolCall,
) -> orbit_engine::ToolRoundResult {
    let decision_id = format!("tool-{}-{}", ulid::Ulid::new(), call.index);
    let mut approval_channel = TuiApprovalChannel::new(st.sender.clone(), st.approvals.clone());
    let mut scratch_grants = crate::tool_runtime::AutoGrants::new();
    let (result, _) = crate::tool_runtime::execute_call(
        &st.home,
        &st.session_id,
        &decision_id,
        &call,
        st.auto_tools,
        true,
        &mut approval_channel,
        &mut scratch_grants,
        &st.scope,
        &st.tool_cx,
    )
    .unwrap_or_else(|e| {
        (
            serde_json::json!({ "ok": false, "error": e }).to_string(),
            None,
        )
    });
    let outcome = classify_tool_result(&result);
    let fact = result_fact(&call.name, &result);
    orbit_hud_tui::emit_tool_finished(&st.sender, &call.id, &call.name, outcome, &fact);
    orbit_engine::ToolRoundResult {
        call_id: call.id.clone(),
        content: result,
    }
}

impl TuiToolExecutor {
    /// The worker-thread runner for parallel-safe read-only calls: a
    /// closure over owned, `Sync` state only (paths, the session
    /// context, the bus sender, the approval registry). Nothing here
    /// borrows `self`, so the round can hand it to `thread::scope`.
    fn read_only_runner(
        &self,
    ) -> impl Fn(orbit_engine::PendingToolCall) -> orbit_engine::ToolRoundResult + Sync + use<>
    {
        let st = TuiReadOnlyState {
            home: self.home.clone(),
            session_id: self.session_id.clone(),
            auto_tools: self.auto_tools,
            scope: self.scope.clone(),
            tool_cx: self.tool_cx.clone(),
            sender: self.sender.clone(),
            approvals: self.approvals.clone(),
        };
        move |call| run_read_only_call(&st, call)
    }

    fn run_one(&mut self, call: &orbit_engine::PendingToolCall) -> orbit_engine::ToolRoundResult {
        // No start event here: the engine announced this call, with its
        // target, before the round ran, and the card is keyed by the
        // call's id. This function owns the live output and the finish.

        // Per-call ULID decision ids (defect fix: the old
        // `tool-round-{round}-{index}` ids repeated every turn, so
        // ledger records could not be tied to their turn).
        let decision_id = format!("tool-{}-{}", ulid::Ulid::new(), call.index);
        let mut approval_channel =
            TuiApprovalChannel::new(self.sender.clone(), self.approvals.clone());
        // A running command's output lines go to the Terminal panel as
        // they arrive.
        self.tool_cx
            .set_output_sink(Some(live_output_sink(&self.sender, &call.id)));
        let (result, file_change) = crate::tool_runtime::execute_call(
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
        self.tool_cx.set_output_sink(None);
        // The model's task list changed: the Plan panel lists it.
        if matches!(call.name.as_str(), "TaskCreate" | "TaskUpdate")
            && !orbit_tools::result_is_error(&result)
        {
            orbit_hud_tui::emit_tasks(&self.sender, orbit_tools::tasks::snapshot(&self.tool_cx));
        }
        // Classify the result into a ToolOutcome: a refusal must render
        // as `⊘ denied by you`, not a red `✕ failed` (§11.5 rule 4).
        let outcome = classify_tool_result(&result);
        // A true fact for the card: the change's size for a write, else
        // what the result itself says.
        let fact = file_change
            .as_ref()
            .map(|fc| format!("+{} −{}", fc.added, fc.removed))
            .unwrap_or_else(|| result_fact(&call.name, &result));
        orbit_hud_tui::emit_tool_finished(&self.sender, &call.id, &call.name, outcome, &fact);
        // M11: a checkpointed write carries a real diff to the Changes
        // panel — true counts plus bounded hunks, never invented.
        if let Some(fc) = file_change {
            orbit_hud_tui::emit_file_changed(
                &self.sender,
                &display_path(&fc.path),
                fc.added,
                fc.removed,
                fc.hunks,
            );
        }
        orbit_engine::ToolRoundResult {
            call_id: call.id.clone(),
            content: result,
        }
    }
}

/// Build the session's frozen system prompt: the context builder's
/// output (base + tools + env + memory) with the mods directive
/// folded in. Called once at boot and when the enabled mods change.
fn build_session_prompt(
    home: &std::path::Path,
    model: &str,
    mods: &[crate::mods::Mod],
    mods_enabled: &[String],
) -> orbit_engine::context::SystemPrompt {
    let defs = crate::tools::session_tool_definitions(home);
    let tool_names: Vec<&str> = defs.iter().map(|d| d.name.as_str()).collect();
    let mods_directive = crate::mods::system_directive(mods, mods_enabled);
    orbit_engine::context::build_system_prompt(
        home,
        &std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from(".")),
        model,
        &tool_names,
        &mods_directive,
    )
}

/// How many bytes of the session's frozen system prompt are project
/// instructions: kept on the tool context so each turn can tell the engine
/// (and so the Context panel can name them).
struct MemoryBytes(usize);

/// The short id the status line shows: the first eight characters of
/// the id proper, without the `session-` tag every stored id carries.
fn short_session_id(id: &str) -> String {
    id.strip_prefix("session-")
        .unwrap_or(id)
        .chars()
        .take(8)
        .collect()
}

#[cfg(test)]
mod short_session_id_tests {
    use super::short_session_id;

    #[test]
    fn drops_the_session_tag() {
        assert_eq!(short_session_id("session-01J8ZK4QX2M7C9RT"), "01J8ZK4Q");
        assert_eq!(short_session_id("deadbeefcafe"), "deadbeef");
    }
}

#[cfg(test)]
mod session_tests {
    use super::*;

    fn config(home: &std::path::Path) -> TuiTurnConfig {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(home, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        TuiTurnConfig {
            home: home.to_path_buf(),
            session_id: "session-test".into(),
            gate: "http://127.0.0.1:1".into(),
            model: "m".into(),
            effort: None,
            provider_id: "p".into(),
            auto_tools: true,
            scope: Default::default(),
            initial_transcript: Vec::new(),
            initial_turns: 0,
            initial_input_tokens: 0,
            initial_output_tokens: 0,
            initial_cost_microcents: 0,
        }
    }

    #[test]
    fn successful_resume_moves_the_jsonl_writer_before_releasing_old_ownership() {
        use crate::sessions::{SessionFile, SessionLease, SessionLeaseError};
        use orbit_engine::transcript::{Checkpoints, Transcript, TranscriptEvent};
        let home = std::env::temp_dir().join(format!("orbit-p35-log-switch-{}", ulid::Ulid::new()));
        std::fs::create_dir_all(&home).unwrap();
        std::fs::write(
            home.join("providers.toml"),
            "[[provider]]\nname=\"p\"\nurl=\"http://127.0.0.1:1\"\n[[provider.models]]\nid=\"m\"\n",
        )
        .unwrap();
        let initial = config(&home);
        let target = SessionLease::acquire(&home, "target", "fixture").unwrap();
        target
            .save(&SessionFile::from_chat(
                "target",
                "m",
                "http://127.0.0.1:1",
                "p",
                &[],
                0,
                0,
                0,
                0,
            ))
            .unwrap();
        drop(target);
        let restored_file = home.join("restored.txt");
        std::fs::write(&restored_file, "before").unwrap();
        Checkpoints::new(&home, "target")
            .snapshot_file("cp1", &restored_file)
            .unwrap();
        std::fs::write(&restored_file, "after").unwrap();
        let current = SessionLease::acquire(&home, "session-test", "tui").unwrap();
        let (bus, sender) = orbit_hud_tui::bus::Bus::new();
        let (commands, command_rx) = mpsc::channel();
        let worker = std::thread::spawn(move || {
            worker_main_owned(
                WorkerCtx {
                    sender,
                    approvals: ApprovalRegistry::new(),
                    command_rx,
                },
                initial,
                Default::default(),
                current,
            )
        });
        commands
            .send(WorkerCommand::ResumeSession("target".into()))
            .unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
        let mut switched = false;
        while std::time::Instant::now() < deadline {
            if matches!(bus.try_recv(), Some(Msg::Identity { session_id, .. }) if session_id == "target")
            {
                switched = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        let previous = SessionLease::acquire(&home, "session-test", "another-frontend").ok();
        let old_path = home.join("projects/session-test.jsonl");
        let old_bytes = std::fs::read(&old_path).unwrap();
        commands.send(WorkerCommand::Rewind("cp1".into())).unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
        let mut rewound = false;
        while std::time::Instant::now() < deadline {
            if matches!(bus.try_recv(), Some(Msg::SystemMessage(text)) if text.starts_with("restored 1 file"))
            {
                rewound = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        let target_owned = matches!(
            SessionLease::acquire(&home, "target", "other"),
            Err(SessionLeaseError::Busy { .. })
        );
        drop(commands);
        worker.join().unwrap();
        assert!(switched && rewound && previous.is_some() && target_owned);
        assert_eq!(
            std::fs::read(old_path).unwrap(),
            old_bytes,
            "released session's log must stay unchanged"
        );
        assert_eq!(std::fs::read_to_string(restored_file).unwrap(), "before");
        assert!(Transcript::open(&home, "target").unwrap().events().iter().any(|event| matches!(event, TranscriptEvent::Rewound { to_checkpoint } if to_checkpoint == "cp1")));
        drop(previous);
        std::fs::remove_dir_all(home).unwrap();
    }

    #[test]
    fn failed_candidate_jsonl_open_keeps_the_old_session_owned() {
        use crate::sessions::{SessionFile, SessionLease, SessionLeaseError};
        let home =
            std::env::temp_dir().join(format!("orbit-p35-log-refusal-{}", ulid::Ulid::new()));
        std::fs::create_dir_all(&home).unwrap();
        std::fs::write(
            home.join("providers.toml"),
            "[[provider]]\nname=\"p\"\nurl=\"http://127.0.0.1:1\"\n[[provider.models]]\nid=\"m\"\n",
        )
        .unwrap();
        let initial = config(&home);
        let target = SessionLease::acquire(&home, "target", "fixture").unwrap();
        target
            .save(&SessionFile::from_chat(
                "target",
                "m",
                "http://127.0.0.1:1",
                "p",
                &[],
                0,
                0,
                0,
                0,
            ))
            .unwrap();
        drop(target);
        std::fs::create_dir_all(home.join("projects/target.jsonl")).unwrap();
        let current = SessionLease::acquire(&home, "session-test", "tui").unwrap();
        let (bus, sender) = orbit_hud_tui::bus::Bus::new();
        let (commands, command_rx) = mpsc::channel();
        let worker = std::thread::spawn(move || {
            worker_main_owned(
                WorkerCtx {
                    sender,
                    approvals: ApprovalRegistry::new(),
                    command_rx,
                },
                initial,
                Default::default(),
                current,
            )
        });
        commands
            .send(WorkerCommand::ResumeSession("target".into()))
            .unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
        let mut refused = false;
        let mut backend_failure = false;
        while std::time::Instant::now() < deadline {
            match bus.try_recv() {
                Some(Msg::SystemMessage(text))
                    if text.contains("cannot resume target: transcript") =>
                {
                    refused = true;
                    break;
                }
                Some(Msg::BackendError(_)) => backend_failure = true,
                _ => std::thread::sleep(std::time::Duration::from_millis(5)),
            }
        }
        let old_owned = matches!(
            SessionLease::acquire(&home, "session-test", "other"),
            Err(SessionLeaseError::Busy { .. })
        );
        let candidate_released = SessionLease::acquire(&home, "target", "other").is_ok();
        drop(commands);
        worker.join().unwrap();
        assert!(refused && old_owned && candidate_released && !backend_failure);
        std::fs::remove_dir_all(home).unwrap();
    }

    #[test]
    fn busy_resume_keeps_the_current_lease_and_saved_controls() {
        use crate::sessions::{SessionFile, SessionLease, SessionLeaseError};
        use orbit_adapter::types::EffortValue;
        let home = std::env::temp_dir().join(format!("orbit-p35-worker-{}", ulid::Ulid::new()));
        std::fs::create_dir_all(&home).unwrap();
        std::fs::write(
            home.join("providers.toml"),
            r#"
[[provider]]
name = "p"
url = "http://127.0.0.1:1"
[[provider.models]]
id = "m"
supported_efforts = ["low", "high"]
default_effort = "low"
"#,
        )
        .unwrap();
        let initial = config(&home);
        let busy = SessionLease::acquire(&home, "busy", "test").unwrap();
        busy.save(&SessionFile::from_chat(
            "busy",
            "m",
            "http://127.0.0.1:1",
            "p",
            &[],
            9,
            0,
            0,
            0,
        ))
        .unwrap();
        let before = std::fs::read(home.join("sessions/busy.json")).unwrap();
        let current = SessionLease::acquire(&home, "session-test", "tui").unwrap();
        let (bus, sender) = orbit_hud_tui::bus::Bus::new();
        let (commands, command_rx) = mpsc::channel();
        let worker = std::thread::spawn(move || {
            worker_main_owned(
                WorkerCtx {
                    sender,
                    approvals: ApprovalRegistry::new(),
                    command_rx,
                },
                initial,
                Default::default(),
                current,
            )
        });
        commands.send(WorkerCommand::Effort("high".into())).unwrap();
        commands
            .send(WorkerCommand::ResumeSession("busy".into()))
            .unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
        let mut refused = false;
        while std::time::Instant::now() < deadline {
            if let Some(message) = bus.try_recv() {
                match message {
                    Msg::SystemMessage(text) if text.contains("already owned") => {
                        refused = true;
                        break;
                    }
                    Msg::BackendError(error) => {
                        panic!("idle rejection failed a provider turn: {error}")
                    }
                    _ => {}
                }
            } else {
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
        }
        let still_owned = matches!(
            SessionLease::acquire(&home, "session-test", "other"),
            Err(SessionLeaseError::Busy { .. })
        );
        drop(commands);
        worker.join().unwrap();
        assert!(
            refused,
            "busy target must be refused through the worker control path"
        );
        assert!(
            still_owned,
            "a failed switch must retain the original live lease"
        );
        let saved = crate::sessions::load_session(&home, "session-test").unwrap();
        assert_eq!(saved.model, "m");
        assert_eq!(saved.provider, "p");
        assert_eq!(saved.turns, 0);
        assert_eq!(
            saved.effort,
            Some(EffortSetting::Value(EffortValue::Level("high".into())))
        );
        assert_eq!(
            std::fs::read(home.join("sessions/busy.json")).unwrap(),
            before
        );
        assert!(SessionLease::acquire(&home, "session-test", "after").is_ok());
        drop(busy);
        std::fs::remove_dir_all(home).unwrap();
    }

    #[test]
    fn idle_effort_controls_persist_reset_and_reject_incompatible_model_and_resume() {
        use orbit_adapter::types::EffortValue;
        let home = std::env::temp_dir().join(format!("orbit-effort-worker-{}", ulid::Ulid::new()));
        std::fs::create_dir_all(&home).unwrap();
        std::fs::write(
            home.join("providers.toml"),
            r#"
[[provider]]
name = "p"
url = "http://127.0.0.1:1"
[[provider.models]]
id = "m"
supported_efforts = ["low", "high"]
default_effort = "low"
[[provider.models]]
id = "other"
supported_efforts = ["medium"]
default_effort = "medium"
"#,
        )
        .unwrap();
        let bad = crate::sessions::SessionFile::from_chat(
            "bad",
            "other",
            "http://127.0.0.1:1",
            "p",
            &[],
            7,
            0,
            0,
            0,
        )
        .with_effort(Some(EffortSetting::Value(EffortValue::Level(
            "high".into(),
        ))));
        crate::sessions::save_session(&home, &bad).unwrap();
        let (bus, sender) = orbit_hud_tui::bus::Bus::new();
        let (commands, command_rx) = mpsc::channel();
        commands.send(WorkerCommand::Effort("high".into())).unwrap();
        commands
            .send(WorkerCommand::SetModel("other".into()))
            .unwrap();
        commands
            .send(WorkerCommand::ResumeSession("bad".into()))
            .unwrap();
        drop(commands);
        worker_main(
            WorkerCtx {
                sender,
                approvals: ApprovalRegistry::new(),
                command_rx,
            },
            config(&home),
            Default::default(),
        );
        let saved = crate::sessions::load_session(&home, "session-test").unwrap();
        assert_eq!(saved.model, "m");
        assert_eq!(
            saved.effort,
            Some(EffortSetting::Value(EffortValue::Level("high".into())))
        );
        drop(bus);
        let (_, sender) = orbit_hud_tui::bus::Bus::new();
        let (commands, command_rx) = mpsc::channel();
        let mut resumed = config(&home);
        resumed.effort = saved.effort;
        commands
            .send(WorkerCommand::Effort("default".into()))
            .unwrap();
        commands
            .send(WorkerCommand::SetModel("other".into()))
            .unwrap();
        drop(commands);
        worker_main(
            WorkerCtx {
                sender,
                approvals: ApprovalRegistry::new(),
                command_rx,
            },
            resumed,
            Default::default(),
        );
        let saved = crate::sessions::load_session(&home, "session-test").unwrap();
        assert_eq!(saved.model, "other");
        assert_eq!(saved.effort, Some(EffortSetting::Default));
        assert_eq!(
            configured_turn(&TuiTurnConfig {
                model: saved.model,
                effort: saved.effort,
                ..config(&home)
            })
            .unwrap()
            .effort,
            Some(EffortValue::Level("medium".into()))
        );
        let _ = std::fs::remove_dir_all(home);
    }

    #[test]
    fn saved_provider_owns_effort_when_model_ids_overlap() {
        use orbit_adapter::types::EffortValue;
        let home = std::env::temp_dir().join(format!("orbit-effort-owner-{}", ulid::Ulid::new()));
        std::fs::create_dir_all(&home).unwrap();
        std::fs::write(
            home.join("providers.toml"),
            r#"
[[provider]]
name = "first"
url = "http://127.0.0.1:1"
[[provider.models]]
id = "shared"
supported_efforts = ["low", "high"]
default_effort = "low"
[[provider]]
name = "second"
url = "http://127.0.0.1:2"
[[provider.models]]
id = "shared"
supported_efforts = ["medium"]
default_effort = "medium"
"#,
        )
        .unwrap();
        let saved = crate::sessions::SessionFile::from_chat(
            "owner",
            "shared",
            "http://127.0.0.1:2",
            "second",
            &[],
            0,
            0,
            0,
            0,
        )
        .with_effort(Some(EffortSetting::Value(EffortValue::Level(
            "medium".into(),
        ))));
        crate::sessions::save_session(&home, &saved).unwrap();
        let (bus, sender) = orbit_hud_tui::bus::Bus::new();
        let (commands, command_rx) = mpsc::channel();
        commands
            .send(WorkerCommand::ResumeSession("owner".into()))
            .unwrap();
        commands
            .send(WorkerCommand::Effort("default".into()))
            .unwrap();
        drop(commands);
        worker_main(
            WorkerCtx {
                sender,
                approvals: ApprovalRegistry::new(),
                command_rx,
            },
            config(&home),
            Default::default(),
        );
        let after = crate::sessions::load_session(&home, "owner").unwrap();
        assert_eq!(after.provider, "second");
        assert_eq!(after.effort, Some(EffortSetting::Default));
        let turn = configured_turn(&TuiTurnConfig {
            provider_id: after.provider,
            model: after.model,
            effort: after.effort,
            ..config(&home)
        })
        .unwrap();
        assert_eq!(turn.gate, "http://127.0.0.1:2");
        assert_eq!(turn.effort, Some(EffortValue::Level("medium".into())));
        drop(bus);
        let _ = std::fs::remove_dir_all(home);
    }

    #[test]
    fn idle_effort_rejections_do_not_report_a_failed_provider_turn() {
        let home =
            std::env::temp_dir().join(format!("orbit-effort-rejection-{}", ulid::Ulid::new()));
        std::fs::create_dir_all(&home).unwrap();
        std::fs::write(
            home.join("providers.toml"),
            r#"
[[provider]]
name = "p"
url = "http://127.0.0.1:1"
[[provider.models]]
id = "m"
supported_efforts = ["low", "high"]
default_effort = "low"
[[provider.models]]
id = "other"
supported_efforts = ["medium"]
default_effort = "medium"
"#,
        )
        .unwrap();
        let (bus, sender) = orbit_hud_tui::bus::Bus::new();
        let (commands, command_rx) = mpsc::channel();
        for value in ["high", "false", "\"unterminated", "unsupported"] {
            commands.send(WorkerCommand::Effort(value.into())).unwrap();
        }
        commands
            .send(WorkerCommand::SetModel("other".into()))
            .unwrap();
        drop(commands);
        worker_main(
            WorkerCtx {
                sender,
                approvals: ApprovalRegistry::new(),
                command_rx,
            },
            config(&home),
            Default::default(),
        );
        let mut reports = vec![];
        while let Some(message) = bus.try_recv() {
            match message {
                Msg::BackendError(error) => {
                    panic!("idle control emitted a backend failure: {error}")
                }
                Msg::EffortStatus(text) => reports.push(text),
                _ => {}
            }
        }
        assert_eq!(
            reports
                .iter()
                .filter(|s| s.starts_with("Effort unchanged:"))
                .count(),
            3
        );
        assert!(
            reports
                .iter()
                .any(|s| s.contains("reasoning_effort requires a named level"))
        );
        assert!(reports.iter().any(|s| s.starts_with("Model unchanged:")
            && s.contains("Use /effort default before switching.")));
        let saved = crate::sessions::load_session(&home, "session-test").unwrap();
        assert_eq!(saved.model, "m");
        assert_eq!(
            saved.effort,
            Some(crate::parse_effort_setting("high").unwrap())
        );
        let _ = std::fs::remove_dir_all(home);
    }

    #[test]
    fn a_file_tools_path_is_shown_relative_and_a_command_is_left_alone() {
        let cwd = std::env::current_dir().unwrap();
        let inside = format!("Edit({}/src/a.rs)", cwd.display());
        assert_eq!(display_summary(&inside), "Edit(src/a.rs)");
        // Outside the project: shown as it is (never guessed shorter).
        assert_eq!(display_summary("Read(/etc/hosts)"), "Read(/etc/hosts)");
        // A command line is the recorded fact; its paths are not rewritten.
        let cmd = format!("Bash(cat {}/a.txt)", cwd.display());
        assert_eq!(display_summary(&cmd), cmd);
        assert_eq!(display_summary("Glob(**/*.py)"), "Glob(**/*.py)");
    }

    #[test]
    fn host_of_strips_the_scheme_and_path() {
        assert_eq!(host_of("http://127.0.0.1:4001/v1"), "127.0.0.1:4001");
        assert_eq!(host_of("https://api.example.com"), "api.example.com");
        assert_eq!(host_of("localhost:8080/x"), "localhost:8080");
    }

    /// The session's context announces every ledger record it appends to
    /// the UI bus, with the record's hash: what the Activity panel shows.
    #[test]
    fn the_session_context_feeds_the_activity_panel() {
        let home = std::env::temp_dir().join(format!("orbit-sess-ctx-{}", ulid::Ulid::new()));
        std::fs::create_dir_all(&home).unwrap();
        let (bus, sender) = orbit_hud_tui::bus::Bus::new();
        let cx = session_tool_context(&config(&home), &sender);
        let call = orbit_engine::PendingToolCall {
            index: 0,
            id: "c1".into(),
            name: "calculator".into(),
            arguments: br#"{"expression":"1+1"}"#.to_vec(),
        };
        struct Never;
        impl crate::tool_runtime::ApprovalChannel for Never {
            fn ask(
                &mut self,
                _: &crate::tool_runtime::ApprovalRequest,
                _: bool,
            ) -> crate::tool_runtime::ApprovalVerdict {
                panic!("auto-tools: never asked")
            }
        }
        crate::tool_runtime::execute_call(
            &home,
            "session-test",
            "d1",
            &call,
            true,
            false,
            &mut Never,
            &mut crate::tool_runtime::AutoGrants::new(),
            &crate::tool_runtime::PermissionScope::default(),
            &cx,
        )
        .unwrap();
        let mut got = Vec::new();
        while let Some(m) = bus.try_recv() {
            if let orbit_hud_tui::msg::Msg::Activity { kind, digest, .. } = m {
                got.push((kind, digest));
            }
        }
        let kinds: Vec<&str> = got.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(kinds, ["intent", "verdict", "result"]);
        assert!(
            got.iter()
                .all(|(_, d)| d.as_ref().is_some_and(|d| d.len() == 64))
        );
        let _ = std::fs::remove_dir_all(&home);
    }

    /// What a Read recorded in one prompt still lets the next prompt's
    /// Edit through: the context belongs to the session, and each prompt
    /// gets its own checkpoint.
    #[test]
    fn read_before_edit_survives_into_the_next_prompt() {
        let home = std::env::temp_dir().join(format!("orbit-sess-rbe-{}", ulid::Ulid::new()));
        std::fs::create_dir_all(&home).unwrap();
        let (_bus, sender) = orbit_hud_tui::bus::Bus::new();
        let cx = session_tool_context(&config(&home), &sender);
        let file = home.join("a.txt");
        std::fs::write(&file, "hello\n").unwrap();
        // Prompt 1: the model reads the file in full.
        let read = orbit_tools::registry()
            .into_iter()
            .find(|t| t.name() == "Read")
            .unwrap()
            .run(
                &serde_json::json!({ "file_path": file.to_string_lossy() }),
                &cx,
            );
        assert!(!read.is_error, "{}", read.payload);
        let first_checkpoint = cx.turn_checkpoint_id();
        // Prompt 2 (a new turn on the SAME session context): the edit is
        // allowed, and it gets a fresh checkpoint.
        cx.reset_turn_checkpoint();
        let edit = orbit_tools::registry()
            .into_iter()
            .find(|t| t.name() == "Edit")
            .unwrap()
            .run(
                &serde_json::json!({
                    "file_path": file.to_string_lossy(),
                    "old_string": "hello",
                    "new_string": "world"
                }),
                &cx,
            );
        assert!(
            !edit.is_error,
            "an Edit after a Read in an earlier prompt: {}",
            edit.payload
        );
        assert_ne!(
            cx.turn_checkpoint_id(),
            first_checkpoint,
            "one checkpoint per prompt"
        );
        let _ = std::fs::remove_dir_all(&home);
    }
}

#[derive(Debug, Default)]
struct FileMentionExpansion {
    text: String,
    images: Vec<ContentBlock>,
}

impl FileMentionExpansion {
    /// Text remains the routing/display input; structured blocks carry images
    /// only to the provider and persisted conversation, never to the screen.
    fn into_prompt(self) -> (String, Option<Vec<ContentBlock>>) {
        let blocks = if self.images.is_empty() {
            None
        } else {
            let mut blocks = Vec::with_capacity(self.images.len() + 1);
            blocks.push(ContentBlock::Text {
                text: self.text.clone(),
            });
            blocks.extend(self.images);
            Some(blocks)
        };
        (self.text, blocks)
    }
}

const MAX_MENTION_IMAGES: usize = 5;
const MAX_MENTION_IMAGE_DATA: usize = 20 * 1024 * 1024;

/// Expand explicit file mentions through Read so deny-read rules, scanning,
/// size limits and read-before-edit records apply exactly as for a tool read.
///
/// Mentions start at whitespace or an opening punctuation cluster. Bare paths
/// retain internal filename punctuation; trailing sentence punctuation and an
/// unmatched closing bracket end the mention.
/// Use @"quoted paths" (or single quotes) for spaces, embedded @, or ambiguous
/// punctuation. Quotes escape only their delimiter and backslash.
///
/// Failed, denied or malformed mentions retain their exact original spelling.
fn expand_file_mentions(text: &str, tool_cx: &orbit_tools::ToolContext) -> FileMentionExpansion {
    let mut out = String::with_capacity(text.len());
    let mut images = Vec::new();
    let mut image_paths = std::collections::HashSet::new();
    let mut image_data_size = 0usize;
    let mut copied_to = 0;
    let mut search_from = 0;
    while let Some(relative_at) = text[search_from..].find('@') {
        let at = search_from + relative_at;
        search_from = at + 1;
        if !file_mention_start(text, at) {
            continue;
        }
        let (end, path) = file_mention_path(text, at);
        search_from = end;
        let Some(path) = path else {
            continue;
        };
        out.push_str(&text[copied_to..at]);
        let literal = &text[at..end];
        let (expanded, image) = expand_one_mention(&path, literal, tool_cx);
        let mut attached = true;
        if let Some(ContentBlock::Image { data, media_type }) = image {
            let resolved = orbit_tools::resolve_path(tool_cx, &path);
            let identity = std::fs::canonicalize(&resolved).unwrap_or(resolved);
            if !image_paths.contains(&identity) {
                let total = image_data_size.saturating_add(data.len());
                if images.len() < MAX_MENTION_IMAGES && total <= MAX_MENTION_IMAGE_DATA {
                    image_paths.insert(identity);
                    image_data_size = total;
                    images.push(ContentBlock::Image { data, media_type });
                } else {
                    attached = false;
                }
            }
        }
        if attached {
            out.push_str(&expanded);
        } else {
            out.push_str(literal);
            out.push_str(" [image not attached: prompt image limit reached]");
        }
        copied_to = end;
    }
    out.push_str(&text[copied_to..]);
    FileMentionExpansion { text: out, images }
}

fn file_mention_start(text: &str, at: usize) -> bool {
    for c in text[..at].chars().rev() {
        if c.is_whitespace() {
            return true;
        }
        if !matches!(c, '(' | '[' | '{' | '<' | '"' | '\'' | '`') {
            return false;
        }
    }
    true
}

// Return the token's byte end even when it is malformed, so a second @ inside
// a rejected token or an unclosed quoted path cannot become a separate read.
fn file_mention_path(text: &str, at: usize) -> (usize, Option<String>) {
    let tail = &text[at + 1..];
    if let Some(quote @ ('"' | '\'')) = tail.chars().next() {
        let mut path = String::new();
        let mut chars = tail[quote.len_utf8()..].char_indices().peekable();
        while let Some((offset, c)) = chars.next() {
            if c == quote {
                let end = at + 1 + quote.len_utf8() + offset + c.len_utf8();
                let separated = text[end..].chars().next().is_none_or(|next| {
                    next.is_whitespace()
                        || matches!(
                            next,
                            ')' | ']'
                                | '}'
                                | '>'
                                | ','
                                | '.'
                                | ';'
                                | ':'
                                | '!'
                                | '?'
                                | '"'
                                | '\''
                                | '`'
                        )
                });
                return (end, (!path.is_empty() && separated).then_some(path));
            }
            if c.is_control() {
                return (text.len(), None);
            }
            if c == '\\'
                && chars
                    .peek()
                    .is_some_and(|(_, next)| *next == quote || *next == '\\')
            {
                path.push(chars.next().unwrap().1);
            } else {
                path.push(c);
            }
        }
        return (text.len(), None);
    }

    let opening = text[..at].chars().next_back();
    let closing = opening.and_then(|c| match c {
        '(' => Some(')'),
        '[' => Some(']'),
        '{' => Some('}'),
        '<' => Some('>'),
        '"' | '\'' | '`' => Some(c),
        _ => None,
    });
    let mut brackets = Vec::new();
    let mut end = text.len();
    for (offset, c) in tail.char_indices() {
        if c.is_whitespace()
            || (Some(c) == closing && brackets.is_empty())
            || (matches!(c, ')' | ']' | '}' | '>') && brackets.last() != Some(&c))
        {
            end = at + 1 + offset;
            break;
        }
        match c {
            '(' => brackets.push(')'),
            '[' => brackets.push(']'),
            '{' => brackets.push('}'),
            '<' => brackets.push('>'),
            ')' | ']' | '}' | '>' if brackets.last() == Some(&c) => {
                brackets.pop();
            }
            _ => {}
        }
    }
    while text[at + 1..end]
        .chars()
        .next_back()
        .is_some_and(|c| matches!(c, ',' | '.' | ';' | ':' | '!' | '?'))
    {
        end -= 1;
    }
    let path = &text[at + 1..end];
    (
        end,
        (!path.is_empty() && !path.contains('@')).then(|| path.to_string()),
    )
}

/// One mention's expansion: the Read tool's own output, fenced. The
/// tool's payload is JSON (`{"ok":true,"content":"…"}` or a typed
/// denial/error); a denial or an error leaves the mention as-is.
fn expand_one_mention(
    candidate: &str,
    literal: &str,
    tool_cx: &orbit_tools::ToolContext,
) -> (String, Option<ContentBlock>) {
    use orbit_tools::Tool as _;
    let input = serde_json::json!({ "file_path": candidate });
    let result = orbit_tools::ReadTool.run(&input, tool_cx);
    let Ok(v) = serde_json::from_str::<serde_json::Value>(&result.payload) else {
        return (literal.to_string(), None);
    };
    if !v.get("ok").and_then(|b| b.as_bool()).unwrap_or(false) {
        return (literal.to_string(), None);
    }
    let Some(content) = v.get("content").and_then(|c| c.as_str()) else {
        return (literal.to_string(), None);
    };
    let image = v
        .get("image_base64")
        .and_then(|data| data.as_str())
        .zip(v.get("image_media_type").and_then(|media| media.as_str()))
        .map(|(data, media_type)| ContentBlock::Image {
            data: data.to_string(),
            media_type: media_type.to_string(),
        });
    if image.is_some() {
        return (format!("{literal}\n{content}"), image);
    }
    const MAX: usize = 10_000;
    let mut body = content.to_string();
    if body.chars().count() > MAX {
        let cut: String = body.chars().take(MAX).collect();
        let total = body.chars().count();
        body = format!("{cut}\u{2026} (+{total} chars truncated)");
    }
    let lang = std::path::Path::new(candidate)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("");
    (
        format!("{literal}\n```{lang}\n{}\n```", body.trim_end()),
        None,
    )
}

#[cfg(test)]
mod mention_tests {
    use super::*;

    fn cx_in(dir: &std::path::Path) -> orbit_tools::ToolContext {
        orbit_tools::ToolContext::new(dir.to_path_buf(), "mention-test".into(), dir.to_path_buf())
    }

    fn temp_home(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("orbit-mention-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// A mention expands to the file's contents, fenced, with the
    /// mention itself kept as the header.
    #[test]
    fn a_mention_expands_to_the_files_contents() {
        let d = temp_home("expand");
        std::fs::write(d.join("calc.py"), "def add(a, b):\n    return a + b\n").unwrap();
        let cx = cx_in(&d);
        let out = expand_file_mentions("look at @calc.py please", &cx).text;
        assert!(out.contains("@calc.py"), "the mention itself stays: {out}");
        assert!(
            out.contains("```py") && out.contains("return a + b"),
            "the contents are fenced with the language: {out}"
        );
        assert!(out.starts_with("look at "), "text before is untouched");
        assert!(out.ends_with(" please"), "text after is untouched");
    }

    /// A missing file leaves the mention as-is: the model (and the
    /// operator) see the literal @path, never a silent drop.
    #[test]
    fn a_missing_file_leaves_the_mention_untouched() {
        let d = temp_home("missing");
        let cx = cx_in(&d);
        let out = expand_file_mentions("see @nope.txt", &cx).text;
        assert_eq!(out, "see @nope.txt");
    }

    #[test]
    fn a_directory_mention_keeps_its_literal() {
        let d = temp_home("directory");
        std::fs::create_dir_all(d.join("folder with spaces")).unwrap();
        let text = r#"see @"folder with spaces""#;
        let expanded = expand_file_mentions(text, &cx_in(&d));
        assert_eq!(expanded.text, text);
        assert!(expanded.images.is_empty());
    }

    #[test]
    fn text_mentions_inherit_read_secret_redaction() {
        let d = temp_home("scanner");
        let token = "sk-abcdefghijklmnopqrstuvwxyz123456";
        std::fs::write(d.join("notes.txt"), format!("the key is {token} and more")).unwrap();
        let expanded = expand_file_mentions("@notes.txt", &cx_in(&d));
        assert!(expanded.text.contains("[redacted:api token]"));
        assert!(!expanded.text.contains(token));
        assert!(expanded.text.contains("and more"));
    }

    /// The deny-read list holds for mentions: a credential path never
    /// reaches the provider through an @mention — the same refusal the
    /// Read tool gives, surfaced as the untouched mention.
    #[test]
    fn a_deny_read_path_does_not_expand() {
        let d = temp_home("denyread");
        let cx = cx_in(&d);
        let out = expand_file_mentions("read @~/.ssh/id_rsa now", &cx).text;
        assert_eq!(
            out, "read @~/.ssh/id_rsa now",
            "the deny-read path must not expand — the Read tool refused it"
        );
    }

    /// A bare @ and an @ at the end of the text are not mentions.
    #[test]
    fn a_bare_at_is_not_a_mention() {
        let d = temp_home("bare");
        let cx = cx_in(&d);
        assert_eq!(expand_file_mentions("email me@", &cx).text, "email me@");
        assert_eq!(expand_file_mentions("a @ b", &cx).text, "a @ b");
    }

    /// The read-before-edit record: a mention grounds a later Edit the
    /// same way a Read call does — the context is shared.
    #[test]
    fn a_mention_records_the_read_before_edit_hash() {
        let d = temp_home("rbe");
        std::fs::write(d.join("a.txt"), "hello\n").unwrap();
        let cx = cx_in(&d);
        let _ = expand_file_mentions("check @a.txt", &cx);
        assert!(
            cx.was_read(&d.join("a.txt")),
            "the mention recorded the read, so a later Edit is grounded"
        );
    }

    #[test]
    fn email_urls_and_inline_at_signs_never_read_files() {
        let d = temp_home("boundaries");
        std::fs::write(d.join("secret.txt"), "private fixture").unwrap();
        let cx = cx_in(&d);
        for text in [
            "email name@secret.txt",
            "https://example.test/@secret.txt",
            "https://user@secret.txt",
            "https://example.test/(@secret.txt)",
            "mailto:user@secret.txt",
            "name(@secret.txt)",
            "é@secret.txt",
            "@name@secret.txt",
        ] {
            assert_eq!(expand_file_mentions(text, &cx).text, text);
            assert!(!cx.was_read(&d.join("secret.txt")), "{text}");
        }
    }

    #[test]
    fn prose_punctuation_and_balanced_path_brackets_work() {
        let d = temp_home("punctuation");
        std::fs::write(d.join("a.txt"), "ordinary fixture").unwrap();
        std::fs::write(d.join("report(1).txt"), "bracket fixture").unwrap();
        let cx = cx_in(&d);
        for (text, ending) in [
            ("see @a.txt, please", ", please"),
            ("see @a.txt.", "."),
            ("see (@a.txt).", ")."),
            ("see [(@a.txt)], please", ")], please"),
            ("see `@a.txt`!", "`!"),
            ("see @a.txt)", ")"),
        ] {
            let out = expand_file_mentions(text, &cx).text;
            assert!(out.contains("ordinary fixture"), "{text}: {out}");
            assert!(out.ends_with(ending), "{text}: {out}");
        }
        let out = expand_file_mentions("see (@report(1).txt)", &cx).text;
        assert!(out.contains("bracket fixture"));
        assert!(out.ends_with(')'));
    }

    #[test]
    fn quoted_paths_preserve_spaces_punctuation_unicode_and_escaped_characters() {
        let d = temp_home("quotes");
        let cx = cx_in(&d);
        for (name, mention) in [
            ("two words.txt", r#"@"two words.txt""#),
            ("日本語-é.txt", r#"@"日本語-é.txt""#),
            ("report,final!.txt", r#"@"report,final!.txt""#),
            ("quoted\"name.txt", r#"@"quoted\"name.txt""#),
            ("single'name.txt", r#"@'single\'name.txt'"#),
            ("back\\slash.txt", r#"@"back\\slash.txt""#),
            ("literal\\q.txt", r#"@"literal\q.txt""#),
            ("name@host.txt", r#"@"name@host.txt""#),
            ("ends-in-dot.", r#"@"ends-in-dot.""#),
        ] {
            std::fs::write(d.join(name), "quoted fixture").unwrap();
            let text = format!("see ({mention}), please");
            let out = expand_file_mentions(&text, &cx).text;
            assert!(out.contains("quoted fixture"), "{mention}: {out}");
            assert!(out.contains(mention), "literal retained: {out}");
            assert!(out.ends_with("), please"));
            assert!(cx.was_read(&d.join(name)), "{mention}");
        }
    }

    #[test]
    fn failed_or_malformed_quotes_keep_exact_literals_without_inner_reads() {
        let d = temp_home("malformed");
        std::fs::write(d.join("a.txt"), "must not read").unwrap();
        let cx = cx_in(&d);
        for text in [
            r#"see @"missing file.txt", please"#,
            r#"see @'missing file.txt'"#,
            r#"see @"unterminated @a.txt"#,
            r#"see @"a.txt"suffix"#,
            r#"see @"""#,
            "see @\"a\n@a.txt\"",
        ] {
            assert_eq!(expand_file_mentions(text, &cx).text, text);
            assert!(!cx.was_read(&d.join("a.txt")), "{text}");
        }
    }

    #[test]
    fn unicode_bare_mentions_use_byte_boundaries_and_preserve_surrounding_text() {
        let d = temp_home("unicode");
        std::fs::write(d.join("café.txt"), "Unicode fixture").unwrap();
        let cx = cx_in(&d);
        let out = expand_file_mentions("🛰 see @café.txt, then @missing.txt — done", &cx).text;
        assert!(out.starts_with("🛰 see @café.txt\n```txt"));
        assert!(out.ends_with(", then @missing.txt — done"));
        assert!(out.contains("Unicode fixture"));
    }

    fn write_image(path: &std::path::Path) {
        // A tiny deterministic fixture; Read transports image bytes unchanged.
        std::fs::write(path, b"\x89PNG\r\n\x1a\nfixture").unwrap();
    }

    #[test]
    fn an_image_mention_attaches_a_block_without_displaying_base64() {
        let d = temp_home("image");
        write_image(&d.join("screenshot.png"));
        let expanded = expand_file_mentions("inspect @screenshot.png please", &cx_in(&d));
        assert!(expanded.text.contains("[image: screenshot.png,"));
        let [ContentBlock::Image { data, media_type }] = expanded.images.as_slice() else {
            panic!("expected one image");
        };
        assert_eq!(media_type, "image/png");
        assert!(!data.is_empty());
        assert!(!expanded.text.contains(data));
        let (prompt, blocks) = expanded.into_prompt();
        let blocks = blocks.unwrap();
        assert_eq!(blocks[0], ContentBlock::Text { text: prompt });
        assert!(matches!(blocks[1], ContentBlock::Image { .. }));
    }

    #[test]
    fn denied_and_missing_images_remain_literals_and_have_no_blocks() {
        let d = temp_home("denied-image");
        write_image(&d.join("secrets.png"));
        let cx = cx_in(&d);
        for text in [
            "inspect @secrets.png",
            r#"inspect @"secrets.png""#,
            "inspect @missing.png",
        ] {
            let expanded = expand_file_mentions(text, &cx);
            assert_eq!(expanded.text, text);
            assert!(expanded.images.is_empty());
            assert!(expanded.into_prompt().1.is_none());
        }
    }

    #[test]
    fn repeated_image_mentions_and_aliases_share_one_attachment() {
        let d = temp_home("repeat-image");
        write_image(&d.join("capture.png"));
        let expanded =
            expand_file_mentions(r#"@capture.png @./capture.png @"capture.png""#, &cx_in(&d));
        assert_eq!(expanded.images.len(), 1);
        assert_eq!(expanded.text.matches("[image:").count(), 3);
    }

    #[test]
    fn image_count_limit_is_per_prompt_and_reported_in_text() {
        let d = temp_home("image-count");
        let mut mentions = Vec::new();
        for i in 0..=MAX_MENTION_IMAGES {
            let name = format!("capture{i}.png");
            write_image(&d.join(&name));
            mentions.push(format!("@{name}"));
        }
        let expanded = expand_file_mentions(&mentions.join(" "), &cx_in(&d));
        assert_eq!(expanded.images.len(), MAX_MENTION_IMAGES);
        assert!(
            expanded
                .text
                .ends_with(" [image not attached: prompt image limit reached]")
        );
        assert!(
            expanded
                .text
                .contains(&format!("@capture{MAX_MENTION_IMAGES}.png"))
        );
    }

    #[test]
    fn total_encoded_image_size_is_bounded_across_the_prompt() {
        let d = temp_home("image-data-limit");
        let image = vec![0u8; 4 * 1024 * 1024];
        for i in 0..4 {
            std::fs::write(d.join(format!("capture{i}.png")), &image).unwrap();
        }
        let expanded = expand_file_mentions(
            "@capture0.png @capture1.png @capture2.png @capture3.png",
            &cx_in(&d),
        );
        assert_eq!(expanded.images.len(), 3);
        let encoded_bytes: usize = expanded
            .images
            .iter()
            .map(|image| {
                let ContentBlock::Image { data, .. } = image else {
                    panic!("expected image");
                };
                data.len()
            })
            .sum();
        assert!(encoded_bytes <= MAX_MENTION_IMAGE_DATA);
        assert!(
            expanded
                .text
                .ends_with("@capture3.png [image not attached: prompt image limit reached]")
        );
    }

    #[test]
    fn an_oversized_image_preserves_the_literal_without_attachment() {
        let d = temp_home("oversized-image");
        std::fs::write(d.join("huge.png"), vec![0u8; 5 * 1024 * 1024 + 1]).unwrap();
        let expanded = expand_file_mentions("inspect @huge.png", &cx_in(&d));
        assert_eq!(expanded.text, "inspect @huge.png");
        assert!(expanded.images.is_empty());
    }

    #[test]
    fn text_mentions_remain_text_only_and_keep_the_character_limit() {
        let d = temp_home("text-limit");
        std::fs::write(d.join("large.txt"), "é".repeat(10_001)).unwrap();
        let expanded = expand_file_mentions("@large.txt", &cx_in(&d));
        assert!(expanded.text.contains("truncated"));
        assert!(expanded.images.is_empty());
        assert!(expanded.into_prompt().1.is_none());
    }
}
