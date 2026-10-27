//! TUI worker thread — drives `run_turn` + tool execution for the TUI front-end.
//!
//! The worker receives user prompts via `Msg::TextSubmitted` and runs the
//! four-gate pipeline. Stream events flow through the TUI bridge (display_safe
//! + CoT stripping). Tool approvals resolve via the `ApprovalRegistry`.
//!
//! This is the TUI-specific counterpart to the REPL loop — the REPL's inline
//! logic in `cmd_chat` is untouched.

use crate::session_accounting::{
    self, FullCostStatus, NamespaceAccounting, RootOrigin, RootSessionAccounting,
};
#[cfg(test)]
use orbit_adapter::types::EffortSetting;
use orbit_adapter::types::{ChatMessage, ChatRole, ContentBlock};
use orbit_hud_tui::bus::BusSender;
use orbit_hud_tui::model::TranscriptLine;
use orbit_hud_tui::msg::{
    ContextProjection, CostQualification, ManualOutcome, Msg, OrdinaryEnd, OrdinaryPublication,
    ProjectionReason, SessionProjection, SessionsRow as MsgSessionRow,
};
use orbit_hud_tui::worker::{
    CommandSink, ForegroundKind, ForegroundOperation, ManualAction, SessionBinding, WorkerCommand,
    WorkerCtx,
};
use orbit_hud_tui::{ApprovalRegistry, ApprovalResponse};
use std::sync::mpsc;

pub use crate::session_config::SessionTurnConfig as TuiTurnConfig;

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

fn checked_cost(
    accounting: &RootSessionAccounting,
    saved: &crate::sessions::SessionFile,
    reconciled: bool,
) -> CostQualification {
    if !reconciled {
        return CostQualification::Unavailable;
    }
    let Some(anchor) = &saved.accounting_watermark else {
        return CostQualification::Unavailable;
    };
    let Ok(checkpoint) = accounting.namespace().checkpoint_detailed() else {
        return CostQualification::Unavailable;
    };
    if checkpoint.revision().0 != anchor.revision {
        return CostQualification::Unavailable;
    }
    if (checkpoint.pending().is_some()
        || checkpoint.totals().knownness == orbit_engine::AccountingKnownness::Uncertain)
        && anchor.full_cost_status != FullCostStatus::Uncertain
    {
        return CostQualification::Unavailable;
    }
    let revision = anchor.revision;
    match anchor.full_cost_status {
        FullCostStatus::Known => CostQualification::Known { revision },
        FullCostStatus::UnknownLegacy => CostQualification::UnknownHistory { revision },
        FullCostStatus::UnknownUsage => CostQualification::UnknownUsage { revision },
        FullCostStatus::Unpriced => CostQualification::Unpriced { revision },
        FullCostStatus::Uncertain => CostQualification::Uncertain { revision },
    }
}

#[allow(clippy::too_many_arguments)]
fn emit_session_projection(
    sender: &BusSender,
    config: &TuiTurnConfig,
    binding: &SessionBinding,
    transcript: &[ChatMessage],
    turns: u64,
    input: u64,
    output: u64,
    cost: u64,
    qualification: CostQualification,
    reason: ProjectionReason,
    context: ContextProjection,
) {
    sender.send(Msg::SessionProjection(SessionProjection {
        binding: binding.clone(),
        model: config.model.clone(),
        provider: config.provider_id.clone(),
        priced: has_complete_projected_cost(&qualification),
        lines: session_to_transcript_lines(transcript),
        turns,
        input_tokens: input,
        output_tokens: output,
        cost_microcents: cost,
        cost: qualification,
        context,
        reason,
    }));
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ContextProjectionCommand {
    Prompt,
    PlanPrompt,
    Other,
}

fn context_projection_command(command: &WorkerCommand) -> ContextProjectionCommand {
    match command {
        WorkerCommand::Prompt(_) => ContextProjectionCommand::Prompt,
        WorkerCommand::PlanPrompt(_) => ContextProjectionCommand::PlanPrompt,
        _ => ContextProjectionCommand::Other,
    }
}

fn project_context_after_command(
    command: ContextProjectionCommand,
    measured: ContextProjection,
) -> ContextProjection {
    match command {
        ContextProjectionCommand::Prompt | ContextProjectionCommand::PlanPrompt => measured,
        ContextProjectionCommand::Other => ContextProjection::Unavailable,
    }
}

fn project_context_after_foreground_operation(
    operation_kind: ForegroundKind,
    command: ContextProjectionCommand,
    measured: ContextProjection,
) -> ContextProjection {
    match (operation_kind, command) {
        (ForegroundKind::Prompt, ContextProjectionCommand::Prompt)
        | (ForegroundKind::PlanPrompt, ContextProjectionCommand::PlanPrompt) => measured,
        _ => ContextProjection::Unavailable,
    }
}

fn record_latest_usage_window(latest: &mut Option<u64>, window_tokens: u64) {
    *latest = Some(window_tokens);
}

fn measured_context_projection(
    base: (&str, &str),
    effective: (&str, &str),
    latest_usage_window_tokens: Option<u64>,
) -> ContextProjection {
    if base == effective && latest_usage_window_tokens.is_some_and(|window| window > 0) {
        ContextProjection::PreserveMeasured
    } else {
        ContextProjection::Unavailable
    }
}

fn has_complete_projected_cost(qualification: &CostQualification) -> bool {
    matches!(qualification, CostQualification::Known { .. })
}

#[allow(clippy::too_many_arguments)]
fn save_controls(
    config: &TuiTurnConfig,
    lease: &crate::sessions::SessionLease,
    accounting: &RootSessionAccounting,
    transcript: &[ChatMessage],
    turns: u64,
    input: &mut u64,
    output: &mut u64,
    cost: &mut u64,
    sender: &BusSender,
    origin: crate::phase_routing::SelectionOrigin,
    qualification: &mut CostQualification,
) -> bool {
    let mut saved = crate::sessions::SessionFile::from_chat(
        &config.session_id,
        &config.model,
        &config.gate,
        &config.provider_id,
        transcript,
        turns,
        *input,
        *output,
        *cost,
    )
    .with_effort(config.effort.clone())
    .with_selection_origin(origin);
    let result = accounting.persist(lease, &mut saved);
    *qualification = checked_cost(
        accounting,
        &saved,
        result.is_ok()
            || matches!(
                &result,
                Err(session_accounting::AccountingError::Session(_))
            ),
    );
    *input = saved.input_tokens;
    *output = saved.output_tokens;
    *cost = saved.cost_microcents;
    if let Err(error) = result {
        let message = if error.is_publication_uncertain() {
            format!(
                "settings save may have committed; inspect the session before changing settings: {error}"
            )
        } else {
            format!("settings unchanged: {error}")
        };
        orbit_hud_tui::emit_notice(sender, &message);
        return false;
    }
    true
}

fn retain_local_intent(
    transcript: &mut Vec<ChatMessage>,
    prompt: &str,
    blocks: Option<Vec<ContentBlock>>,
) {
    transcript.push(ChatMessage {
        role: ChatRole::User,
        content: prompt.to_owned(),
        tool_calls: None,
        tool_call_id: None,
        tool_result: None,
        blocks,
        origin_model: None,
        origin_provider: None,
    });
}

#[allow(clippy::too_many_arguments)]
fn save_turn(
    config: &TuiTurnConfig,
    lease: &crate::sessions::SessionLease,
    accounting: &RootSessionAccounting,
    transcript: &[ChatMessage],
    turns: u64,
    input: &mut u64,
    output: &mut u64,
    cost: &mut u64,
    origin: crate::phase_routing::SelectionOrigin,
    sender: &BusSender,
    qualification: &mut CostQualification,
    manual: bool,
) -> bool {
    let mut saved = crate::sessions::SessionFile::from_chat(
        &config.session_id,
        &config.model,
        &config.gate,
        &config.provider_id,
        transcript,
        turns,
        *input,
        *output,
        *cost,
    )
    .with_effort(config.effort.clone())
    .with_selection_origin(origin);
    let result = accounting.persist(lease, &mut saved);
    *qualification = checked_cost(
        accounting,
        &saved,
        result.is_ok()
            || matches!(
                &result,
                Err(session_accounting::AccountingError::Session(_))
            ),
    );
    // A failed snapshot publication does not erase charges already in the journal.
    if let Some(anchor) = &saved.accounting_watermark {
        *input = saved.input_tokens;
        *output = saved.output_tokens;
        *cost = saved.cost_microcents;
        if anchor.full_cost_status != FullCostStatus::Known {
            orbit_hud_tui::emit_status(
                sender,
                &format!(
                    "Full session cost is unknown ({:?}); displayed cost is the known priced subtotal",
                    anchor.full_cost_status
                ),
            );
        }
    }
    match result {
        Ok(_) => true,
        Err(error) => {
            let message = if error.is_publication_uncertain() {
                format!(
                    "current prompt save may have committed; inspect the session before retrying: {error}"
                )
            } else {
                format!("current prompt could not be saved: {error}")
            };
            if manual {
                orbit_hud_tui::emit_status(sender, &message);
            } else {
                orbit_hud_tui::emit_notice(sender, &message);
            }
            false
        }
    }
}

/// Project an owning ordinary result without changing its registration or billing.
fn emit_ordinary_result(
    sender: &BusSender,
    operation: Option<&ForegroundOperation>,
    result: Result<&orbit_engine::TurnEnd, &str>,
    saved: bool,
    qualification: &CostQualification,
) {
    let Some(operation) = operation.filter(|operation| operation.kind().is_ordinary()) else {
        return;
    };
    let end = match result {
        Ok(orbit_engine::TurnEnd::Completed) => OrdinaryEnd::Completed,
        Ok(orbit_engine::TurnEnd::Cancelled) => OrdinaryEnd::Cancelled,
        Ok(orbit_engine::TurnEnd::Failed(failure)) => OrdinaryEnd::Failed(failure.message.clone()),
        Err(error) => OrdinaryEnd::Failed(error.to_owned()),
    };
    let publication_qualified = match qualification {
        CostQualification::Known { .. }
        | CostQualification::UnknownHistory { .. }
        | CostQualification::UnknownUsage { .. }
        | CostQualification::Unpriced { .. } => true,
        CostQualification::Uncertain { .. } | CostQualification::Unavailable => false,
    };
    let publication = if saved && publication_qualified {
        OrdinaryPublication::Saved
    } else {
        OrdinaryPublication::BlockedOrUncertain
    };
    orbit_hud_tui::emit_ordinary_turn_ended(sender, operation.clone(), end, publication);
}

/// Build the worker spawner closure for the TUI. The CLI owns `run_turn`;
/// this closure captures the turn config and spawns a thread that drives it.
/// Returns a `CancelHandle` that cancels the turn currently in flight.
pub fn make_spawner(config: TuiTurnConfig) -> orbit_hud_tui::WorkerSpawner {
    Box::new(move |ctx, sink| {
        let workspace = crate::sessions::current_workspace().map_err(|error| error.to_string())?;
        let lease = crate::sessions::SessionLease::acquire_new_or_for_workspace(
            &config.home,
            &config.session_id,
            "tui",
            &workspace,
        )
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
        let workspace = crate::sessions::current_workspace().map_err(|error| error.to_string())?;
        if let Some(saved) = lease.load_optional().map_err(|error| error.to_string())? {
            saved
                .require_workspace(&workspace)
                .map_err(|error| error.to_string())?;
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
    config.home = lease.home().to_path_buf();
    let mut selection_origin =
        match crate::sessions::read_selection_origin(lease.home(), lease.session_id()) {
            Ok(origin) => origin,
            Err(error) => {
                orbit_hud_tui::emit_notice(&ctx.sender, &error);
                return;
            }
        };
    let existing = lease.load_optional();
    let was_saved = matches!(&existing, Ok(Some(_)));
    let mut seed = match existing {
        Ok(Some(saved)) => saved,
        Ok(None) => crate::sessions::SessionFile::from_chat(
            &config.session_id,
            &config.model,
            &config.gate,
            &config.provider_id,
            &config.initial_transcript,
            config.initial_turns,
            config.initial_input_tokens,
            config.initial_output_tokens,
            config.initial_cost_microcents,
        )
        .with_effort(config.effort.clone())
        .with_selection_origin(selection_origin),
        Err(error) => {
            orbit_hud_tui::emit_notice(&ctx.sender, &error.to_string());
            return;
        }
    };
    let workspace = match crate::sessions::current_workspace() {
        Ok(workspace) => workspace,
        Err(error) => {
            orbit_hud_tui::emit_notice(&ctx.sender, &error.to_string());
            return;
        }
    };
    let admission = if was_saved {
        seed.require_workspace(&workspace)
    } else {
        seed.bind_workspace(&workspace)
    };
    if let Err(error) = admission {
        orbit_hud_tui::emit_notice(&ctx.sender, &error.to_string());
        return;
    }
    let mut accounting =
        match session_accounting::prepare_root(&lease, &mut seed, RootOrigin::RestoredOrLegacy) {
            Ok(accounting) => accounting,
            Err(error) => {
                orbit_hud_tui::emit_notice(&ctx.sender, &error.to_string());
                return;
            }
        };
    config.model = seed.model.clone();
    config.gate = seed.gate.clone();
    config.provider_id = seed.provider.clone();
    config.effort = seed.effort.clone();
    config.initial_transcript = seed.to_transcript();
    config.initial_turns = seed.turns;
    config.initial_input_tokens = seed.input_tokens;
    config.initial_output_tokens = seed.output_tokens;
    config.initial_cost_microcents = seed.cost_microcents;
    let mut transcript: Vec<ChatMessage> = config.initial_transcript.clone();
    let mut turns: u64 = config.initial_turns;
    let mut tool_cx = session_tool_context(&config, &ctx.sender);
    tool_cx.working_dir = workspace.clone();
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
        workspace.clone(),
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

    let mut binding = SessionBinding {
        session_id: config.session_id.clone(),
        generation: 1,
    };
    let mut qualification = checked_cost(&accounting, &seed, true);
    orbit_hud_tui::emit_status(
        &ctx.sender,
        &format!("session {}", short_session_id(&config.session_id)),
    );
    emit_session_projection(
        &ctx.sender,
        &config,
        &binding,
        &transcript,
        turns,
        cum_input,
        cum_output,
        cum_cost,
        qualification,
        ProjectionReason::Initial,
        ContextProjection::Unavailable,
    );
    orbit_hud_tui::emit_readiness(
        &ctx.sender,
        vec![(
            sandbox_report().confined,
            sandbox_report().readiness.clone(),
        )],
    );

    // Locally-queued commands (mod commands re-enter the Prompt flow).
    let mut pending: Vec<WorkerCommand> = Vec::new();
    loop {
        let mut cmd = match pending.pop() {
            Some(c) => c,
            None => match ctx.command_rx.recv() {
                Ok(c) => c,
                Err(_) => break,
            },
        };
        let mut foreground = None;
        if let WorkerCommand::Bound { operation, command } = cmd {
            let registration = if operation.source() == &binding {
                operation.start(&command).ok()
            } else {
                None
            };
            let Some(registration) = registration else {
                let _ = operation.finish_unstarted();
                emit_session_projection(
                    &ctx.sender,
                    &config,
                    &binding,
                    &transcript,
                    turns,
                    cum_input,
                    cum_output,
                    cum_cost,
                    qualification,
                    ProjectionReason::Operation { operation },
                    ContextProjection::Unavailable,
                );
                continue;
            };
            cmd = *command;
            foreground = Some((operation, registration));
        }
        // A bound mod intent owns the ordinary prompt it expands to, without
        // releasing ownership or trying to consume its ticket a second time.
        if foreground.is_some()
            && let WorkerCommand::ModCommand(mod_name, cmd_name) = &cmd
            && let Some(body) = mods
                .iter()
                .find(|entry| &entry.name == mod_name)
                .and_then(|entry| entry.commands.get(cmd_name))
                .cloned()
        {
            cmd = WorkerCommand::Prompt(body);
        }
        let project_after = matches!(
            &cmd,
            WorkerCommand::Prompt(_)
                | WorkerCommand::PlanPrompt(_)
                | WorkerCommand::ResumeSession(_)
                | WorkerCommand::SetModel(_)
                | WorkerCommand::Effort(_)
                | WorkerCommand::Undo
        ) || matches!(&cmd, WorkerCommand::Route(value) if value.trim() == "auto");
        let context_projection_command = context_projection_command(&cmd);
        let mut context_projection = ContextProjection::Unavailable;
        let mut projection_reason = ProjectionReason::Refresh;
        let manual_action = match &cmd {
            WorkerCommand::Compact(_) => Some(ManualAction::Compact),
            WorkerCommand::ClearSession(_) => Some(ManualAction::Clear),
            _ => None,
        };
        'command: {
            match cmd {
                WorkerCommand::Bound { .. } => {
                    unreachable!("bound commands are unwrapped before admission")
                }
                WorkerCommand::PlanPrompt(prompt) => {
                    let Some(next_turns) = turns.checked_add(1) else {
                        orbit_hud_tui::emit_error(&ctx.sender, "session turn count overflows");
                        retain_local_intent(&mut transcript, &prompt, None);
                        let saved = save_turn(
                            &config,
                            &lease,
                            &accounting,
                            &transcript,
                            turns,
                            &mut cum_input,
                            &mut cum_output,
                            &mut cum_cost,
                            selection_origin,
                            &ctx.sender,
                            &mut qualification,
                            false,
                        );
                        emit_ordinary_result(
                            &ctx.sender,
                            foreground.as_ref().map(|(operation, _)| operation),
                            Err("session turn count overflows"),
                            saved,
                            &qualification,
                        );
                        orbit_hud_tui::emit_response_finished(
                            &ctx.sender,
                            "",
                            cum_input,
                            cum_output,
                            cum_cost,
                        );
                        break 'command;
                    };
                    let token = orbit_provider_http::CancelToken::new();
                    if let Ok(mut guard) = cancel_slot.lock() {
                        *guard = Some(token.clone());
                    }
                    let plan_directive = format!(
                        "{system_prompt}\n\n## PLAN MODE (read-only)\nYou are in plan mode. Do NOT attempt changes; all tool calls will be denied. Explore the problem, then respond with a concise, numbered implementation plan. End with a line: `PLAN READY`."
                    );
                    let mut scope = std::mem::take(&mut config.scope);
                    let completion = run_tui_turn_inner(
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
                        Some(accounting.namespace()),
                    );
                    config.scope = scope;
                    if let Ok(mut guard) = cancel_slot.lock() {
                        *guard = None;
                    }
                    let usable_plan = match &completion {
                        Ok((completion, measured_context)) => {
                            context_projection = project_context_after_command(
                                context_projection_command,
                                *measured_context,
                            );
                            turns = next_turns;
                            completion.end == orbit_engine::TurnEnd::Completed
                                && completion.report.ok
                                && !completion.report.final_text.trim().is_empty()
                        }
                        Err(error) => {
                            orbit_hud_tui::emit_error(&ctx.sender, error);
                            retain_local_intent(&mut transcript, &prompt, None);
                            false
                        }
                    };
                    let saved = save_turn(
                        &config,
                        &lease,
                        &accounting,
                        &transcript,
                        turns,
                        &mut cum_input,
                        &mut cum_output,
                        &mut cum_cost,
                        selection_origin,
                        &ctx.sender,
                        &mut qualification,
                        false,
                    );
                    emit_ordinary_result(
                        &ctx.sender,
                        foreground.as_ref().map(|(operation, _)| operation),
                        completion
                            .as_ref()
                            .map(|(completion, _)| &completion.end)
                            .map_err(String::as_str),
                        saved,
                        &qualification,
                    );
                    orbit_hud_tui::emit_response_finished(
                        &ctx.sender,
                        "",
                        cum_input,
                        cum_output,
                        cum_cost,
                    );
                    if usable_plan
                        && saved
                        && let Ok((completion, _)) = completion
                    {
                        orbit_hud_tui::emit_plan_ready(&ctx.sender, &completion.report.final_text);
                    }
                }
                WorkerCommand::Prompt(prompt) => {
                    let Some(next_turns) = turns.checked_add(1) else {
                        orbit_hud_tui::emit_error(&ctx.sender, "session turn count overflows");
                        retain_local_intent(&mut transcript, &prompt, None);
                        let saved = save_turn(
                            &config,
                            &lease,
                            &accounting,
                            &transcript,
                            turns,
                            &mut cum_input,
                            &mut cum_output,
                            &mut cum_cost,
                            selection_origin,
                            &ctx.sender,
                            &mut qualification,
                            false,
                        );
                        emit_ordinary_result(
                            &ctx.sender,
                            foreground.as_ref().map(|(operation, _)| operation),
                            Err("session turn count overflows"),
                            saved,
                            &qualification,
                        );
                        orbit_hud_tui::emit_response_finished(
                            &ctx.sender,
                            "",
                            cum_input,
                            cum_output,
                            cum_cost,
                        );
                        break 'command;
                    };
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
                        let _ =
                            log.append(&orbit_engine::transcript::TranscriptEvent::UserPrompt {
                                text: prompt.clone(),
                            });
                    }
                    let transcript_len_before = transcript.len();
                    let directive = system_prompt.clone();
                    let mut scope = std::mem::take(&mut config.scope);
                    let completion = run_tui_turn_inner(
                        &config,
                        &mut transcript,
                        &expanded_prompt,
                        user_blocks.clone(),
                        &ctx.sender,
                        &ctx.approvals,
                        &token,
                        turns,
                        &mut auto_grants,
                        &directive,
                        false,
                        &mut scope,
                        &tool_cx,
                        Some(accounting.namespace()),
                    );
                    config.scope = scope;
                    if let Ok(mut guard) = cancel_slot.lock() {
                        *guard = None;
                    }
                    match &completion {
                        Ok((_, measured_context)) => {
                            turns = next_turns;
                            context_projection = project_context_after_command(
                                context_projection_command,
                                *measured_context,
                            );
                        }
                        Err(error) => {
                            orbit_hud_tui::emit_error(&ctx.sender, error);
                            retain_local_intent(&mut transcript, &expanded_prompt, user_blocks);
                        }
                    }
                    let saved = save_turn(
                        &config,
                        &lease,
                        &accounting,
                        &transcript,
                        turns,
                        &mut cum_input,
                        &mut cum_output,
                        &mut cum_cost,
                        selection_origin,
                        &ctx.sender,
                        &mut qualification,
                        false,
                    );
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
                    emit_ordinary_result(
                        &ctx.sender,
                        foreground.as_ref().map(|(operation, _)| operation),
                        completion
                            .as_ref()
                            .map(|(completion, _)| &completion.end)
                            .map_err(String::as_str),
                        saved,
                        &qualification,
                    );
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
                                                .map(|tc| {
                                                    orbit_engine::transcript::ToolCallRecord {
                                                        id: tc.id.clone(),
                                                        name: tc.name.clone(),
                                                        arguments: tc.arguments.clone(),
                                                    }
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
                        break 'command;
                    }
                    let providers = match crate::config::ProvidersConfig::load(&config.home) {
                        Ok(providers) => providers,
                        Err(error) => {
                            ctx.sender
                                .send(Msg::EffortStatus(format!("Model unchanged:\n{error}")));
                            break 'command;
                        }
                    };
                    let selected =
                        match crate::resolve_selected_model(&providers, &model, None, false) {
                            Ok(selected) => selected,
                            Err(error) => {
                                ctx.sender
                                    .send(Msg::EffortStatus(format!("Model unchanged:\n{error}")));
                                break 'command;
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
                            break 'command;
                        }
                    };
                    if !save_controls(
                        &candidate,
                        &lease,
                        &accounting,
                        &transcript,
                        turns,
                        &mut cum_input,
                        &mut cum_output,
                        &mut cum_cost,
                        &ctx.sender,
                        crate::phase_routing::SelectionOrigin::Interactive,
                        &mut qualification,
                    ) {
                        break 'command;
                    }
                    selection_origin = crate::phase_routing::SelectionOrigin::Interactive;
                    let old = config.model.clone();
                    candidate.provider_id = resolved.provider_id;
                    candidate.gate = resolved.gate;
                    config = candidate;
                    let built =
                        build_session_prompt(&config.home, &config.model, &mods, &mods_enabled);
                    tool_cx.set_ext(MemoryBytes(built.memory_bytes));
                    system_prompt = built.text;
                    ctx.sender.send(Msg::ModelChanged(config.model.clone()));
                    orbit_hud_tui::emit_status(
                        &ctx.sender,
                        &format!("model → {model} (was {old})"),
                    );
                }
                WorkerCommand::Effort(value) => {
                    let mut candidate = config.clone();
                    if !value.is_empty() {
                        match crate::parse_effort_setting(&value) {
                            Ok(choice) => candidate.effort = Some(choice),
                            Err(e) => {
                                ctx.sender
                                    .send(Msg::EffortStatus(format!("Effort unchanged:\n{e}")));
                                break 'command;
                            }
                        }
                    }
                    match configured_turn(&candidate) {
                        Ok(turn) => {
                            if !value.is_empty() {
                                if !save_controls(
                                    &candidate,
                                    &lease,
                                    &accounting,
                                    &transcript,
                                    turns,
                                    &mut cum_input,
                                    &mut cum_output,
                                    &mut cum_cost,
                                    &ctx.sender,
                                    selection_origin,
                                    &mut qualification,
                                ) {
                                    break 'command;
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
                    let words: Vec<String> =
                        argument.split_whitespace().map(str::to_owned).collect();
                    let base = match configured_turn(&config) {
                        Ok(base) => base,
                        Err(error) => {
                            ctx.sender
                                .send(Msg::SystemMessage(format!("route: {error}")));
                            break 'command;
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
                            break 'command;
                        }
                        if save_controls(
                            &config,
                            &lease,
                            &accounting,
                            &transcript,
                            turns,
                            &mut cum_input,
                            &mut cum_output,
                            &mut cum_cost,
                            &ctx.sender,
                            crate::phase_routing::SelectionOrigin::Default,
                            &mut qualification,
                        ) {
                            selection_origin = crate::phase_routing::SelectionOrigin::Default;
                            ctx.sender.send(Msg::Routing(Vec::new()));
                            ctx.sender.send(Msg::SystemMessage(
                                "Automatic routing enabled for this session".into(),
                            ));
                        }
                    } else {
                        match crate::route_command(
                            &config.home,
                            &words,
                            Some(&base),
                            selection_origin,
                        ) {
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
                    match crate::config::ProvidersConfig::load(&config.home) {
                        Ok(cfg) => ctx.sender.send(Msg::ModelsListed(cfg.all_models())),
                        Err(error) => ctx.sender.send(Msg::ModelsListFailed(format!(
                            "Cannot list models: {error}. Repair providers.toml or run orbit setup."
                        ))),
                    };
                }
                WorkerCommand::ListSessions => {
                    let rows = match crate::sessions::list_sessions(&config.home) {
                        Ok(list) => list
                            .iter()
                            .map(|s| MsgSessionRow {
                                id: s.session_id.clone(),
                                model: s.model.clone(),
                                turns: s.turns,
                                updated_at: s.updated_at.clone(),
                                current: s.session_id == binding.session_id,
                            })
                            .collect(),
                        Err(e) => {
                            ctx.sender.send(Msg::SessionsListFailed(format!(
                                "Cannot list sessions: {e}"
                            )));
                            break 'command;
                        }
                    };
                    ctx.sender.send(Msg::SessionsListed(rows));
                }
                WorkerCommand::ResumeSession(id) => {
                    let same_id = id.strip_suffix(".json").unwrap_or(&id) == lease.session_id();
                    let target = if same_id {
                        lease.load().map(|saved| (None, saved))
                    } else {
                        crate::sessions::SessionLease::acquire_for_workspace(
                            &config.home,
                            &id,
                            "tui",
                            &tool_cx.working_dir,
                        )
                        .map(|(guard, saved)| (Some(guard), saved))
                    };
                    match target {
                        Ok((candidate_lease, mut saved)) => {
                            if let Err(error) = saved.require_workspace(&tool_cx.working_dir) {
                                orbit_hud_tui::emit_status(
                                    &ctx.sender,
                                    &format!("resume refused: {error}"),
                                );
                                break 'command;
                            }
                            let mut candidate = config.clone();
                            candidate.session_id = saved.session_id.clone();
                            candidate.model = saved.model.clone();
                            candidate.gate = saved.gate.clone();
                            candidate.provider_id = saved.provider.clone();
                            candidate.effort = saved.effort.clone();
                            let resolved = match configured_turn(&candidate) {
                                Ok(turn) => turn,
                                Err(_) => {
                                    orbit_hud_tui::emit_status(
                                        &ctx.sender,
                                        "resume refused: model configuration unavailable",
                                    );
                                    break 'command;
                                }
                            };
                            candidate.gate = resolved.gate;
                            candidate.provider_id = resolved.provider_id;
                            let candidate_binding = if same_id {
                                binding.clone()
                            } else {
                                let Some(generation) = binding.generation.checked_add(1) else {
                                    orbit_hud_tui::emit_status(
                                        &ctx.sender,
                                        "resume refused: session generation exhausted",
                                    );
                                    break 'command;
                                };
                                SessionBinding {
                                    session_id: candidate.session_id.clone(),
                                    generation,
                                }
                            };
                            let candidate_log = match orbit_engine::transcript::Transcript::open(
                                &config.home,
                                &saved.session_id,
                            ) {
                                Ok(log) => log,
                                Err(_) => {
                                    orbit_hud_tui::emit_status(
                                        &ctx.sender,
                                        "resume refused: transcript unavailable",
                                    );
                                    break 'command;
                                }
                            };
                            let candidate_accounting = match session_accounting::prepare_root(
                                candidate_lease.as_ref().unwrap_or(&lease),
                                &mut saved,
                                RootOrigin::RestoredOrLegacy,
                            ) {
                                Ok(accounting) => accounting,
                                Err(_) => {
                                    if same_id {
                                        qualification = CostQualification::Unavailable;
                                    }
                                    orbit_hud_tui::emit_status(
                                        &ctx.sender,
                                        "resume refused: accounting cannot be verified",
                                    );
                                    break 'command;
                                }
                            };
                            let mut candidate_cx = session_tool_context(&candidate, &ctx.sender);
                            candidate_cx.working_dir = tool_cx.working_dir.clone();
                            let built = build_session_prompt(
                                &config.home,
                                &candidate.model,
                                &mods,
                                &mods_enabled,
                            );
                            candidate_cx.set_ext(MemoryBytes(built.memory_bytes));
                            let candidate_session_cx = orbit_tools::ToolContext::new(
                                candidate.home.clone(),
                                candidate.session_id.clone(),
                                tool_cx.working_dir.clone(),
                            );
                            let previous = binding.clone();
                            qualification = checked_cost(&candidate_accounting, &saved, true);
                            accounting = candidate_accounting;
                            transcript_log = Some(candidate_log);
                            config = candidate;
                            if let Some(candidate_lease) = candidate_lease {
                                lease = candidate_lease;
                            }
                            transcript = saved.to_transcript();
                            turns = saved.turns;
                            cum_input = saved.input_tokens;
                            cum_output = saved.output_tokens;
                            cum_cost = saved.cost_microcents;
                            selection_origin = crate::sessions::model_origin(Some(&saved));
                            system_prompt = built.text;
                            if !same_id {
                                tool_cx = candidate_cx;
                                session_tool_cx = candidate_session_cx;
                                auto_grants = crate::tool_runtime::AutoGrants::new();
                                projection_reason = ProjectionReason::Resume { previous };
                            }
                            binding = candidate_binding;
                        }
                        Err(error) => {
                            if same_id {
                                qualification = CostQualification::Unavailable;
                            }
                            orbit_hud_tui::emit_status(
                                &ctx.sender,
                                &format!("resume refused: {error}"),
                            );
                        }
                    }
                }
                WorkerCommand::Compact(operation) | WorkerCommand::ClearSession(operation) => {
                    if let Err(error) = lease
                        .load()
                        .and_then(|saved| saved.require_workspace(&tool_cx.working_dir))
                    {
                        orbit_hud_tui::emit_status(
                            &ctx.sender,
                            &format!("operation refused: {error}"),
                        );
                        let _ = operation.finish_unstarted();
                        emit_session_projection(
                            &ctx.sender,
                            &config,
                            &binding,
                            &transcript,
                            turns,
                            cum_input,
                            cum_output,
                            cum_cost,
                            qualification,
                            ProjectionReason::Manual {
                                operation,
                                outcome: ManualOutcome::Failed,
                                applied: false,
                            },
                            ContextProjection::PreserveUnchanged,
                        );
                        break 'command;
                    }
                    let expected = manual_action.unwrap_or(ManualAction::Compact);
                    let valid = operation.source() == &binding && operation.action() == expected;
                    let token = orbit_provider_http::CancelToken::new();
                    let registration = if valid {
                        operation
                            .install_cancel(std::sync::Arc::new({
                                let token = token.clone();
                                move || token.cancel()
                            }))
                            .ok()
                    } else {
                        None
                    };
                    if let Some(registration) = registration {
                        if let Ok(mut slot) = cancel_slot.lock() {
                            *slot = Some(token.clone());
                        }
                        let scope_guard = ToolCancelScope::new(&tool_cx, &token);
                        let original_source = serde_json::to_vec(&transcript).ok();
                        let mut applied = false;
                        let outcome;
                        if expected == ManualAction::Compact {
                            let result = compact_manual(
                                &config,
                                &accounting,
                                &mut transcript,
                                &tool_cx,
                                &mods,
                                &mods_enabled,
                                &token,
                                &ctx.sender,
                            );
                            let saved = save_turn(
                                &config,
                                &lease,
                                &accounting,
                                &transcript,
                                turns,
                                &mut cum_input,
                                &mut cum_output,
                                &mut cum_cost,
                                selection_origin,
                                &ctx.sender,
                                &mut qualification,
                                true,
                            );
                            let checkpoint = accounting.namespace().checkpoint_detailed();
                            let uncertain = !matches!(&checkpoint, Ok(cp) if cp.pending().is_none()
                            && cp.totals().knownness != orbit_engine::AccountingKnownness::Uncertain);
                            if !matches!(&checkpoint, Ok(cp) if qualification.revision() == Some(cp.revision().0)
                            && ((cp.pending().is_none() && cp.totals().knownness != orbit_engine::AccountingKnownness::Uncertain)
                                || matches!(qualification, CostQualification::Uncertain { .. })))
                            {
                                qualification = CostQualification::Unavailable;
                            }
                            match result {
                                Ok(completion) => {
                                    applied = completion.applied;
                                    outcome = if !saved || uncertain {
                                        ManualOutcome::Unknown
                                    } else if completion.status
                                        == orbit_engine::CompactionStatus::Cancelled
                                    {
                                        ManualOutcome::Cancelled
                                    } else if completion.applied
                                        || completion.status
                                            == orbit_engine::CompactionStatus::NothingToCompact
                                    {
                                        ManualOutcome::Completed
                                    } else {
                                        ManualOutcome::Failed
                                    };
                                }
                                Err(_) => {
                                    outcome = if !saved || uncertain {
                                        ManualOutcome::Unknown
                                    } else if token.is_cancelled() {
                                        ManualOutcome::Cancelled
                                    } else {
                                        ManualOutcome::Failed
                                    };
                                }
                            }
                        } else {
                            let previous_id = binding.session_id.clone();
                            let clear = stage_clear(
                                &config,
                                &lease,
                                &accounting,
                                &transcript,
                                turns,
                                &mut cum_input,
                                &mut cum_output,
                                &mut cum_cost,
                                selection_origin,
                                &binding,
                                &token,
                            );
                            match clear {
                                Ok(candidate) => {
                                    let mut new_tool_cx =
                                        session_tool_context(&candidate.config, &ctx.sender);
                                    new_tool_cx.working_dir = tool_cx.working_dir.clone();
                                    new_tool_cx.set_ext(MemoryBytes(
                                        tool_cx.ext::<MemoryBytes>().map_or(0, |bytes| bytes.0),
                                    ));
                                    let new_session_cx = orbit_tools::ToolContext::new(
                                        candidate.config.home.clone(),
                                        candidate.config.session_id.clone(),
                                        tool_cx.working_dir.clone(),
                                    );
                                    if token.is_cancelled() {
                                        qualification = CostQualification::Unavailable;
                                        outcome = ManualOutcome::Cancelled;
                                        orbit_hud_tui::emit_status(
                                            &ctx.sender,
                                            &format!(
                                                "clear cancelled; current session retained; candidate {} contains staged files",
                                                candidate.binding.session_id
                                            ),
                                        );
                                    } else {
                                        // All fallible candidate work is complete before this identity swap.
                                        config = candidate.config;
                                        lease = candidate.lease;
                                        accounting = candidate.accounting;
                                        qualification = candidate.cost;
                                        binding = candidate.binding;
                                        transcript_log = Some(candidate.log);
                                        tool_cx = new_tool_cx;
                                        session_tool_cx = new_session_cx;
                                        auto_grants = crate::tool_runtime::AutoGrants::new();
                                        transcript.clear();
                                        turns = 0;
                                        cum_input = 0;
                                        cum_output = 0;
                                        cum_cost = 0;
                                        applied = true;
                                        outcome = ManualOutcome::Completed;
                                        orbit_hud_tui::emit_status(
                                            &ctx.sender,
                                            &format!(
                                                "new session started; previous session {previous_id} retained"
                                            ),
                                        );
                                    }
                                }
                                Err(failure) => {
                                    qualification =
                                        failure.cost.unwrap_or(CostQualification::Unavailable);
                                    outcome = if token.is_cancelled() {
                                        ManualOutcome::Cancelled
                                    } else if failure.uncertain {
                                        ManualOutcome::Unknown
                                    } else {
                                        ManualOutcome::Failed
                                    };
                                    orbit_hud_tui::emit_status(&ctx.sender, &failure.message);
                                }
                            }
                        }
                        drop(scope_guard);
                        if let Ok(mut slot) = cancel_slot.lock() {
                            *slot = None;
                        }
                        drop(registration);
                        let context = if expected == ManualAction::Compact
                            && !applied
                            && original_source.is_some_and(|before| {
                                serde_json::to_vec(&transcript).is_ok_and(|after| after == before)
                            }) {
                            ContextProjection::PreserveUnchanged
                        } else {
                            ContextProjection::Unavailable
                        };
                        emit_session_projection(
                            &ctx.sender,
                            &config,
                            &binding,
                            &transcript,
                            turns,
                            cum_input,
                            cum_output,
                            cum_cost,
                            qualification,
                            ProjectionReason::Manual {
                                operation,
                                outcome,
                                applied,
                            },
                            context,
                        );
                        if expected == ManualAction::Compact {
                            let text = match outcome {
                                ManualOutcome::Completed if applied => "context compacted",
                                ManualOutcome::Completed => "nothing to compact",
                                ManualOutcome::Cancelled => {
                                    "compaction cancelled; history retained"
                                }
                                ManualOutcome::Failed => "compaction refused; history retained",
                                ManualOutcome::Unknown if applied => {
                                    "context applied in memory; inspect the saved outcome before continuing"
                                }
                                ManualOutcome::Unknown => {
                                    "compaction accounting is uncertain; inspect before continuing"
                                }
                            };
                            ctx.sender.send(Msg::SystemMessage(text.into()));
                        }
                    } else {
                        let _ = operation.finish_unstarted();
                        emit_session_projection(
                            &ctx.sender,
                            &config,
                            &binding,
                            &transcript,
                            turns,
                            cum_input,
                            cum_output,
                            cum_cost,
                            qualification,
                            ProjectionReason::Manual {
                                operation,
                                outcome: ManualOutcome::Failed,
                                applied: false,
                            },
                            ContextProjection::Unavailable,
                        );
                    }
                }
                WorkerCommand::ListInstalledMods => {
                    if crate::mods::validation_status(&config.home).is_err() {
                        ctx.sender.send(Msg::SystemMessage("Instruction bundle validation failed; run orbit doctor. Malformed enabled metadata is preserved and defaults stay disabled.".into()));
                    }

                    if mods.is_empty() {
                        ctx.sender.send(Msg::SystemMessage(
                            "no mods installed — add $ORBIT_HOME/mods/<name>/instructions.md"
                                .into(),
                        ));
                        break 'command;
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
                            let built = build_session_prompt(
                                &config.home,
                                &config.model,
                                &mods,
                                &mods_enabled,
                            );
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
                    let built =
                        build_session_prompt(&config.home, &config.model, &mods, &mods_enabled);
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
                    let cps = orbit_engine::transcript::Checkpoints::new(
                        &config.home,
                        &config.session_id,
                    );
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
                    if let Some(index) = transcript
                        .iter()
                        .rposition(|message| message.role == ChatRole::User)
                    {
                        let mut candidate = transcript.clone();
                        let removed: Vec<String> = candidate
                            .split_off(index)
                            .iter()
                            .filter(|message| message.tool_result.is_none())
                            .map(|message| message.content.clone())
                            .filter(|text| !text.trim().is_empty())
                            .collect();
                        let candidate_turns = turns.saturating_sub(1);
                        if save_controls(
                            &config,
                            &lease,
                            &accounting,
                            &candidate,
                            candidate_turns,
                            &mut cum_input,
                            &mut cum_output,
                            &mut cum_cost,
                            &ctx.sender,
                            selection_origin,
                            &mut qualification,
                        ) {
                            transcript = candidate;
                            turns = candidate_turns;
                            let text = removed.join(" / ");
                            ctx.sender.send(Msg::SystemMessage(format!(
                                "undid last exchange ({})",
                                if text.is_empty() { "no text" } else { &text }
                            )));
                        }
                    } else {
                        ctx.sender
                            .send(Msg::SystemMessage("nothing to undo".into()));
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
                            orbit_hud_tui::emit_notice(
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
                    let token = orbit_provider_http::CancelToken::new();
                    if let Ok(mut slot) = cancel_slot.lock() {
                        *slot = Some(token.clone());
                    }
                    let scope_guard = ToolCancelScope::new(&tool_cx, &token);
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
                    orbit_hud_tui::emit_tool_finished(
                        &ctx.sender,
                        &call.id,
                        "Bash",
                        outcome,
                        &fact,
                    );
                    drop(scope_guard);
                    if let Ok(mut slot) = cancel_slot.lock() {
                        *slot = None;
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
        if let Some((operation, registration)) = foreground {
            let mut view = crate::sessions::SessionFile::from_chat(
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
            if accounting.reconcile(&mut view).is_ok() {
                cum_input = view.input_tokens;
                cum_output = view.output_tokens;
                cum_cost = view.cost_microcents;
                qualification = checked_cost(&accounting, &view, true);
            } else {
                qualification = CostQualification::Unavailable;
            }
            drop(registration);
            let operation_context = project_context_after_foreground_operation(
                operation.kind(),
                context_projection_command,
                context_projection,
            );
            emit_session_projection(
                &ctx.sender,
                &config,
                &binding,
                &transcript,
                turns,
                cum_input,
                cum_output,
                cum_cost,
                qualification,
                ProjectionReason::Operation { operation },
                operation_context,
            );
        } else if project_after {
            emit_session_projection(
                &ctx.sender,
                &config,
                &binding,
                &transcript,
                turns,
                cum_input,
                cum_output,
                cum_cost,
                qualification,
                projection_reason,
                context_projection,
            );
        }
    }
}

struct ToolCancelScope(orbit_tools::ToolContext);
impl ToolCancelScope {
    fn new(cx: &orbit_tools::ToolContext, token: &orbit_provider_http::CancelToken) -> Self {
        crate::tool_runtime::begin_cancel_scope(cx, token);
        Self(cx.clone())
    }
}
impl Drop for ToolCancelScope {
    fn drop(&mut self) {
        self.0.pop_cancel_check();
    }
}

#[allow(clippy::too_many_arguments)]
fn compact_manual(
    config: &TuiTurnConfig,
    accounting: &RootSessionAccounting,
    transcript: &mut Vec<ChatMessage>,
    cx: &orbit_tools::ToolContext,
    mods: &[crate::mods::Mod],
    enabled: &[String],
    token: &orbit_provider_http::CancelToken,
    sender: &BusSender,
) -> Result<orbit_engine::ManualCompactionCompletion, &'static str> {
    if token.is_cancelled() {
        return Err("cancelled");
    }
    let turn = configured_turn(config).map_err(|_| "selected model unavailable")?;
    let summary = crate::try_role_turn_config(&config.home, &turn, "compaction")
        .map_err(|_| "summary model unavailable")?;
    let mut options = orbit_engine::TurnOptions {
        session_id: config.session_id.clone(),
        request_stem: format!("orbit-manual-{}", ulid::Ulid::new()),
        max_attempts: 1,
        compaction_config: Some(summary),
        ..Default::default()
    };
    let notices = crate::model_limits::apply_turn_budgets(&config.home, &turn, &mut options)
        .map_err(|_| "context policy unavailable")?;
    accounting
        .namespace()
        .apply_options_detailed(&mut options, None, None)
        .map_err(|_| "accounting admission refused")?;
    if token.is_cancelled() {
        return Err("cancelled");
    }
    let mut definitions = crate::tools::session_tool_definitions_with_context(
        &config.home,
        cx,
        config.scope.allowlist.as_deref(),
    );
    definitions.retain(|definition| {
        !config.scope.disallowlist.contains(&definition.name)
            && config
                .scope
                .allowlist
                .as_ref()
                .is_none_or(|allow| allow.contains(&definition.name))
    });
    let names: Vec<&str> = definitions
        .iter()
        .map(|definition| definition.name.as_str())
        .collect();
    let directive = crate::mods::system_directive(mods, enabled);
    let built = orbit_engine::context::build_system_prompt(
        &config.home,
        &cx.working_dir,
        &config.model,
        &names,
        &directive,
    );
    options.system_directive = Some(built.text);
    options.memory_bytes = built.memory_bytes;
    options.tools = definitions;
    for notice in notices {
        orbit_hud_tui::emit_status(sender, &notice);
    }
    let mut events = |event| match event {
        orbit_frontend_protocol::FrontendEvent::Compacting { used_tokens, .. } => {
            orbit_hud_tui::emit_compaction(sender, true, used_tokens);
        }
        orbit_frontend_protocol::FrontendEvent::Compacted { after_tokens, .. } => {
            orbit_hud_tui::emit_compaction(sender, false, after_tokens);
        }
        // Private summary/reasoning text never becomes an ordinary response.
        _ => {}
    };
    Ok(orbit_engine::compact_context_detailed(
        &config.home,
        &turn,
        &options,
        transcript,
        token,
        &mut events,
    ))
}

struct ClearCandidate {
    config: TuiTurnConfig,
    lease: crate::sessions::SessionLease,
    accounting: RootSessionAccounting,
    binding: SessionBinding,
    cost: CostQualification,
    log: orbit_engine::transcript::Transcript,
}

struct ClearFailure {
    message: String,
    cost: Option<CostQualification>,
    uncertain: bool,
}

fn source_covered(
    saved: &crate::sessions::SessionFile,
    working: &crate::sessions::SessionFile,
) -> bool {
    saved.session_id == working.session_id
        && saved.schema == working.schema
        && saved.workspace == working.workspace
        && saved.model == working.model
        && saved.provider == working.provider
        && saved.gate == working.gate
        && saved.effort == working.effort
        && saved.selection_origin == working.selection_origin
        && saved.turns == working.turns
        && saved.input_tokens == working.input_tokens
        && saved.output_tokens == working.output_tokens
        && saved.cost_microcents == working.cost_microcents
        && saved.accounting_watermark == working.accounting_watermark
        && matches!((serde_json::to_vec(&saved.transcript), serde_json::to_vec(&working.transcript)), (Ok(a), Ok(b)) if a == b)
}

fn fresh_candidate_transcript(
    home: &std::path::Path,
    id: &str,
) -> Result<orbit_engine::transcript::Transcript, &'static str> {
    let directory_path = home.join("projects");
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder
        .create(&directory_path)
        .map_err(|_| "candidate transcript directory unavailable")?;
    let mut directory_options = std::fs::OpenOptions::new();
    directory_options.read(true);
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        directory_options.custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC);
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let directory = directory_options
        .open(&directory_path)
        .map_err(|_| "candidate transcript directory unsafe")?;
    // Transcript::open is create+append; an atomic exclusive reservation must
    // establish absence first, including orphan logs and dangling symlinks.
    let path = directory_path.join(format!("{id}.jsonl"));
    let reservation = options
        .open(&path)
        .map_err(|_| "candidate transcript already exists or is unsafe")?;
    reservation
        .sync_all()
        .map_err(|_| "candidate transcript reservation uncertain")?;
    let log = orbit_engine::transcript::Transcript::open(home, id)
        .map_err(|_| "candidate transcript unavailable")?;
    let current = std::fs::symlink_metadata(&path).map_err(|_| "candidate transcript changed")?;
    let current_directory = std::fs::symlink_metadata(&directory_path)
        .map_err(|_| "candidate transcript directory changed")?;
    if !current.is_file() || current.len() != 0 || !current_directory.is_dir() {
        return Err("candidate transcript changed");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let reserved = reservation
            .metadata()
            .map_err(|_| "candidate transcript reservation unavailable")?;
        let held_directory = directory
            .metadata()
            .map_err(|_| "candidate transcript directory unavailable")?;
        if (current.dev(), current.ino()) != (reserved.dev(), reserved.ino())
            || (current_directory.dev(), current_directory.ino())
                != (held_directory.dev(), held_directory.ino())
            || current.nlink() != 1
            || current.mode() & 0o077 != 0
            || current_directory.mode() & 0o077 != 0
            || current.uid() != held_directory.uid()
        {
            return Err("candidate transcript identity changed or is unsafe");
        }
    }
    directory
        .sync_all()
        .map_err(|_| "candidate transcript directory publication uncertain")?;
    Ok(log)
}

#[allow(clippy::too_many_arguments)]
fn stage_clear(
    config: &TuiTurnConfig,
    lease: &crate::sessions::SessionLease,
    accounting: &RootSessionAccounting,
    transcript: &[ChatMessage],
    turns: u64,
    input: &mut u64,
    output: &mut u64,
    cost: &mut u64,
    origin: crate::phase_routing::SelectionOrigin,
    binding: &SessionBinding,
    token: &orbit_provider_http::CancelToken,
) -> Result<ClearCandidate, ClearFailure> {
    let refuse = |message: &str| ClearFailure {
        message: message.into(),
        cost: None,
        uncertain: false,
    };
    if token.is_cancelled() {
        return Err(refuse("clear cancelled; current session retained"));
    }
    let generation = binding
        .generation
        .checked_add(1)
        .ok_or_else(|| refuse("session generation exhausted"))?;
    let mut source = crate::sessions::SessionFile::from_chat(
        &config.session_id,
        &config.model,
        &config.gate,
        &config.provider_id,
        transcript,
        turns,
        *input,
        *output,
        *cost,
    )
    .with_effort(config.effort.clone())
    .with_selection_origin(origin);
    let saved_workspace = lease
        .load()
        .map_err(|_| refuse("clear refused; saved workspace unavailable"))?;
    saved_workspace
        .require_workspace(
            &crate::sessions::current_workspace()
                .map_err(|_| refuse("clear refused; workspace unavailable"))?,
        )
        .map_err(|_| refuse("clear refused; current session workspace changed"))?;
    source.workspace = saved_workspace.workspace;
    accounting
        .reconcile(&mut source)
        .map_err(|_| refuse("clear refused; current accounting cannot be verified"))?;
    *input = source.input_tokens;
    *output = source.output_tokens;
    *cost = source.cost_microcents;
    let saved = lease
        .load()
        .map_err(|_| refuse("clear refused; current saved history cannot be verified"))?;
    if !source_covered(&saved, &source) {
        accounting.persist(lease, &mut source).map_err(|error| ClearFailure {
            message: "clear refused; current work could not be durably saved; repair storage and retry".into(),
            cost: Some(checked_cost(accounting, &source, matches!(&error, session_accounting::AccountingError::Session(_)))),
            uncertain: true,
        })?;
        let saved = lease
            .load()
            .map_err(|_| refuse("clear refused; saved current work cannot be verified"))?;
        if !source_covered(&saved, &source) {
            return Err(refuse("clear refused; saved current work differs"));
        }
    }
    let source_cost = checked_cost(accounting, &source, true);
    if token.is_cancelled() {
        return Err(ClearFailure {
            message: "clear cancelled; current session retained".into(),
            cost: Some(source_cost),
            uncertain: false,
        });
    }
    let id = orbit_gateway::new_session_id();
    let stage = (|| -> Result<ClearCandidate, &'static str> {
        let candidate_lease = crate::sessions::SessionLease::acquire(lease.home(), &id, "tui")
            .map_err(|_| "candidate ownership unavailable")?;
        if candidate_lease
            .load_optional()
            .map_err(|_| "candidate snapshot unsafe")?
            .is_some()
        {
            return Err("candidate identity already exists");
        }
        let mut candidate_config = config.clone();
        candidate_config.session_id = id.clone();
        candidate_config.initial_transcript.clear();
        candidate_config.initial_turns = 0;
        candidate_config.initial_input_tokens = 0;
        candidate_config.initial_output_tokens = 0;
        candidate_config.initial_cost_microcents = 0;
        let log = fresh_candidate_transcript(lease.home(), &id)?;
        let mut fresh = crate::sessions::SessionFile::from_chat(
            &id,
            &config.model,
            &config.gate,
            &config.provider_id,
            &[],
            0,
            0,
            0,
            0,
        )
        .with_effort(config.effort.clone())
        .with_selection_origin(origin);
        fresh.workspace = saved.workspace.clone();
        fresh
            .require_workspace(
                &crate::sessions::current_workspace().map_err(|_| "workspace unavailable")?,
            )
            .map_err(|_| "current workspace changed")?;
        let candidate_accounting = session_accounting::prepare_root(
            &candidate_lease,
            &mut fresh,
            RootOrigin::FreshCandidate,
        )
        .map_err(|_| "candidate accounting publication failed")?;
        let cost = checked_cost(&candidate_accounting, &fresh, true);
        if !matches!(cost, CostQualification::Known { revision: 0 }) {
            return Err("candidate accounting could not be verified");
        }
        if token.is_cancelled() {
            return Err("cancelled after candidate staging");
        }
        Ok(ClearCandidate {
            config: candidate_config,
            lease: candidate_lease,
            accounting: candidate_accounting,
            binding: SessionBinding {
                session_id: id.clone(),
                generation,
            },
            cost,
            log,
        })
    })();
    stage.map_err(|reason| ClearFailure { message: format!("clear refused; current session retained; candidate {id} may contain staged files ({reason})"),
        cost: Some(source_cost), uncertain: true })
}

fn session_to_transcript_lines(msgs: &[ChatMessage]) -> Vec<TranscriptLine> {
    use orbit_hud_tui::model::ToolOutcome;
    use std::collections::HashMap;

    // Count every saved assistant call and tool result before projecting any
    // line. A result can only settle a unique call with the exact same ID;
    // name/order fallbacks would cross-wire parallel or legacy calls.
    let mut call_counts = HashMap::<&str, usize>::new();
    let mut results_by_id = HashMap::<&str, Vec<&ChatMessage>>::new();
    for msg in msgs {
        if let Some(calls) = &msg.tool_calls {
            for call in calls {
                if !call.id.is_empty() {
                    *call_counts.entry(call.id.as_str()).or_default() += 1;
                }
            }
        }
        if msg.role == ChatRole::Tool
            && let Some(id) = msg.tool_call_id.as_deref().filter(|id| !id.is_empty())
        {
            results_by_id.entry(id).or_default().push(msg);
        }
    }

    let mut lines = Vec::new();
    for msg in msgs {
        match msg.role {
            ChatRole::User => lines.push(TranscriptLine::User {
                text: msg.content.clone(),
                time: None,
            }),
            ChatRole::Assistant => {
                if let Some(calls) = &msg.tool_calls {
                    // Reasoning and raw arguments are never rendered. Each
                    // call gets its own identity-bearing row in source order.
                    for call in calls {
                        let call_count = call_counts.get(call.id.as_str()).copied().unwrap_or(0);
                        let matching = results_by_id.get(call.id.as_str());
                        let result_count = matching.map_or(0, Vec::len);
                        let unique_call = !call.id.is_empty() && call_count == 1;
                        let unambiguous_pair = unique_call && result_count <= 1;
                        let (outcome, meta) = if !unambiguous_pair || result_count != 1 {
                            (ToolOutcome::Unavailable, String::new())
                        } else {
                            classify_saved_tool_result(call.name.as_str(), matching.unwrap()[0])
                        };
                        lines.push(TranscriptLine::Stripped {
                            tool_name: call.name.clone(),
                            call_id: if unambiguous_pair {
                                call.id.clone()
                            } else {
                                String::new()
                            },
                            // Saved arguments are raw JSON and are deliberately
                            // not treated as the bridge's safe display summary.
                            summary: String::new(),
                            outcome: Some(outcome),
                            meta,
                            started_at: None,
                        });
                    }
                } else if !msg.content.is_empty() {
                    lines.push(TranscriptLine::Assistant {
                        text: orbit_hud_tui::bridge::strip_cot(&msg.content),
                        time: None,
                    });
                }
            }
            ChatRole::System => lines.push(TranscriptLine::System(msg.content.clone())),
            ChatRole::Tool => {
                // Tool bodies stay in model context, never in the visible
                // transcript or restored Terminal tape.
            }
        }
    }
    lines
}

fn classify_saved_tool_result(
    tool: &str,
    result: &ChatMessage,
) -> (orbit_hud_tui::model::ToolOutcome, String) {
    use orbit_hud_tui::model::ToolOutcome;

    let unavailable = || (ToolOutcome::Unavailable, String::new());
    let payload = match result.tool_result.as_deref() {
        Some(saved) if saved != result.content => return unavailable(),
        Some(saved) => saved,
        None => result.content.as_str(),
    };
    let Ok(value) = serde_json::from_str::<serde_json::Value>(payload) else {
        return unavailable();
    };
    if !value.is_object() {
        return unavailable();
    }
    let Some(ok) = value.get("ok").and_then(serde_json::Value::as_bool) else {
        return unavailable();
    };
    let denied = match value.get("denied") {
        None => None,
        Some(flag) => match flag.as_bool() {
            Some(flag) => Some(flag),
            None => return unavailable(),
        },
    };
    let error = value.get("error").and_then(serde_json::Value::as_str);
    let blocked = error == Some("unknown tool (deny-by-default)");
    let cancelled = error == Some("cancelled by user");

    let outcome = match (ok, denied) {
        (true, Some(true)) => ToolOutcome::Unavailable,
        (true, _) if blocked || cancelled => ToolOutcome::Unavailable,
        (true, _) => ToolOutcome::Ok,
        (false, Some(true)) if cancelled => ToolOutcome::Unavailable,
        (false, Some(true)) => ToolOutcome::Denied,
        (false, Some(false)) if blocked => ToolOutcome::Unavailable,
        (false, Some(false)) if cancelled => ToolOutcome::Cancelled,
        (false, Some(false)) => ToolOutcome::Failed,
        (false, None) if cancelled => ToolOutcome::Cancelled,
        (false, None) if blocked => ToolOutcome::Blocked,
        (false, None) => ToolOutcome::Failed,
    };

    // Bash's typed process status must agree with the top-level verdict.
    // JSON booleans, floats, null and strings are not integer exit codes.
    if tool == "Bash"
        && let Some(exit_code) = value.get("exit_code")
    {
        let is_zero = exit_code
            .as_i64()
            .map(|code| code == 0)
            .or_else(|| exit_code.as_u64().map(|code| code == 0));
        if is_zero.is_none_or(|is_zero| ok != is_zero) {
            return unavailable();
        }
    }

    // Facts are derived only from a uniquely paired, internally consistent
    // result. Unknown or contradictory records expose no result-derived text.
    // A typed Bash exit code is useful after restore even when it is zero;
    // only the fixed status is shown, never the saved output body.
    let fact = if tool == "Bash"
        && ok
        && value.get("exit_code").and_then(serde_json::Value::as_i64) == Some(0)
    {
        "exit 0".to_string()
    } else if matches!(outcome, ToolOutcome::Ok | ToolOutcome::Failed) {
        result_fact(tool, payload)
    } else {
        String::new()
    };
    (outcome, fact)
}

#[cfg(test)]
mod saved_tool_projection_tests {
    use super::*;
    use orbit_adapter::types::ToolCallMessage;
    use orbit_hud_tui::model::ToolOutcome;

    fn message(role: ChatRole, content: &str) -> ChatMessage {
        ChatMessage {
            role,
            content: content.to_string(),
            blocks: None,
            tool_calls: None,
            tool_call_id: None,
            tool_result: None,
            origin_model: None,
            origin_provider: None,
        }
    }

    fn call(id: &str, name: &str, arguments: &str) -> ToolCallMessage {
        ToolCallMessage {
            id: id.to_string(),
            name: name.to_string(),
            arguments: arguments.to_string(),
        }
    }

    fn assistant(calls: Vec<ToolCallMessage>, reasoning: &str) -> ChatMessage {
        let mut message = message(ChatRole::Assistant, reasoning);
        message.tool_calls = Some(calls);
        message
    }

    fn result(id: &str, payload: &str) -> ChatMessage {
        let mut message = message(ChatRole::Tool, payload);
        message.tool_call_id = Some(id.to_string());
        message.tool_result = Some(payload.to_string());
        message
    }

    fn classify(tool: &str, payload: &str) -> (ToolOutcome, String) {
        classify_saved_tool_result(tool, &result("call", payload))
    }

    fn projected_tools(lines: &[TranscriptLine]) -> Vec<&TranscriptLine> {
        lines
            .iter()
            .filter(|line| matches!(line, TranscriptLine::Stripped { .. }))
            .collect()
    }

    #[test]
    fn calls_keep_order_and_join_only_by_exact_id_without_leaking_saved_bodies() {
        let reasoning = "PRIVATE_REASONING_MARKER";
        let arguments = "PRIVATE_ARGUMENT_MARKER";
        let secret = "PRIVATE_RESULT_BODY_MARKER";
        let lines = session_to_transcript_lines(&[
            assistant(
                vec![
                    call("bash-1", "Bash", arguments),
                    call("glob-1", "Glob", arguments),
                ],
                reasoning,
            ),
            result(
                "glob-1",
                &format!(r#"{{"ok":true,"matches":["a.txt"],"secret":"{secret}"}}"#),
            ),
            result(
                "bash-1",
                &format!(r#"{{"ok":false,"exit_code":3,"output":"{secret}"}}"#),
            ),
        ]);
        let tools = projected_tools(&lines);
        assert_eq!(tools.len(), 2);
        assert!(matches!(
            tools[0],
            TranscriptLine::Stripped {
                tool_name,
                call_id,
                summary,
                outcome: Some(ToolOutcome::Failed),
                meta,
                ..
            } if tool_name == "Bash"
                && call_id == "bash-1"
                && summary.is_empty()
                && meta == "exit 3"
        ));
        assert!(matches!(
            tools[1],
            TranscriptLine::Stripped {
                tool_name,
                call_id,
                outcome: Some(ToolOutcome::Ok),
                meta,
                ..
            } if tool_name == "Glob" && call_id == "glob-1" && meta == "1 file"
        ));
        let visible = format!("{lines:?}");
        assert!(!visible.contains(reasoning));
        assert!(!visible.contains(arguments));
        assert!(!visible.contains(secret));
    }

    #[test]
    fn typed_denial_legacy_block_cancel_and_failure_remain_distinct() {
        assert_eq!(
            classify(
                "Bash",
                r#"{"ok":false,"denied":true,"error":"unknown tool (deny-by-default)"}"#
            )
            .0,
            ToolOutcome::Denied
        );
        assert_eq!(
            classify(
                "Bash",
                r#"{"ok":false,"error":"unknown tool (deny-by-default)"}"#
            )
            .0,
            ToolOutcome::Blocked
        );
        assert_eq!(
            classify(
                "Bash",
                r#"{"ok":false,"denied":false,"error":"unknown tool (deny-by-default)"}"#
            )
            .0,
            ToolOutcome::Unavailable
        );
        assert_eq!(
            classify("Bash", r#"{"ok":false,"error":"cancelled by user"}"#).0,
            ToolOutcome::Cancelled
        );
        assert_eq!(
            classify(
                "Bash",
                r#"{"ok":false,"denied":true,"error":"cancelled by user"}"#
            )
            .0,
            ToolOutcome::Unavailable
        );
        assert_eq!(classify("Bash", r#"{"ok":true}"#).0, ToolOutcome::Ok);
        assert_eq!(
            classify("Bash", r#"{"ok":false,"exit_code":3}"#),
            (ToolOutcome::Failed, "exit 3".to_string())
        );
    }

    #[test]
    fn successful_bash_restore_exposes_only_the_typed_zero_exit_fact() {
        let payload = r#"{"ok":true,"exit_code":0,"output":"PRIVATE_SAVED_OUTPUT"}"#;
        assert_eq!(
            classify("Bash", payload),
            (ToolOutcome::Ok, "exit 0".to_string())
        );
        let without_exit_code = classify("Bash", r#"{"ok":true}"#);
        assert_eq!(without_exit_code, (ToolOutcome::Ok, String::new()));
    }

    #[test]
    fn malformed_or_contradictory_saved_results_are_unavailable() {
        for payload in [
            "not-json",
            "[]",
            r#"{"exit_code":3}"#,
            r#"{"ok":"false"}"#,
            r#"{"ok":false,"denied":"no"}"#,
            r#"{"ok":true,"error":"unknown tool (deny-by-default)"}"#,
            r#"{"ok":true,"error":"cancelled by user"}"#,
            r#"{"ok":false,"exit_code":0}"#,
            r#"{"ok":true,"exit_code":1}"#,
            r#"{"ok":false,"exit_code":true}"#,
            r#"{"ok":false,"exit_code":1.5}"#,
        ] {
            assert_eq!(
                classify("Bash", payload),
                (ToolOutcome::Unavailable, String::new()),
                "payload should be unavailable: {payload}"
            );
        }
    }

    #[test]
    fn legacy_content_only_result_is_supported_but_conflicting_fields_are_not() {
        let mut legacy = result(
            "call",
            r#"{"ok":false,"error":"unknown tool (deny-by-default)"}"#,
        );
        legacy.tool_result = None;
        assert_eq!(
            classify_saved_tool_result("Bash", &legacy).0,
            ToolOutcome::Blocked
        );

        let mut conflicting = result("call", r#"{"ok":true}"#);
        conflicting.tool_result = Some(r#"{"ok":false,"exit_code":4}"#.to_string());
        assert_eq!(
            classify_saved_tool_result("Bash", &conflicting),
            (ToolOutcome::Unavailable, String::new())
        );
    }

    #[test]
    fn ambiguous_missing_and_duplicate_ids_never_settle_or_create_tape_identity() {
        let lines = session_to_transcript_lines(&[
            assistant(
                vec![
                    call("dup", "Bash", "{}"),
                    call("dup", "Bash", "{}"),
                    call("", "Bash", "{}"),
                    call("many-results", "Bash", "{}"),
                    call("no-result", "Bash", "{}"),
                ],
                "PRIVATE_REASONING",
            ),
            result("dup", r#"{"ok":true,"exit_code":0}"#),
            result("many-results", r#"{"ok":true,"exit_code":0}"#),
            result("many-results", r#"{"ok":false,"exit_code":7}"#),
        ]);
        let tools = projected_tools(&lines);
        assert_eq!(tools.len(), 5);
        for line in &tools[..4] {
            assert!(matches!(
                line,
                TranscriptLine::Stripped {
                    outcome: Some(ToolOutcome::Unavailable),
                    call_id,
                    meta,
                    ..
                } if call_id.is_empty() && meta.is_empty()
            ));
        }
        assert!(matches!(
            tools[4],
            TranscriptLine::Stripped {
                outcome: Some(ToolOutcome::Unavailable),
                call_id,
                ..
            } if call_id == "no-result"
        ));
    }
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

/// Compatibility entry point without leased durable accounting.
/// The actual session worker uses the namespace-qualified detailed bridge.
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
    turns: u64,
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
    let (completion, _) = run_tui_turn_inner(
        config,
        transcript,
        prompt,
        user_blocks,
        sender,
        approvals,
        cancel,
        turns,
        auto_grants,
        mods_directive,
        plan_mode,
        scope,
        tool_cx,
        None,
    )?;
    let report = completion.report;
    Ok((
        report.ok,
        report.input_tokens,
        report.output_tokens,
        report.cost_microcents,
        report.final_text,
    ))
}

#[allow(clippy::too_many_arguments)]
fn run_tui_turn_inner(
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
    accounting: Option<&NamespaceAccounting>,
) -> Result<(orbit_engine::TurnCompletion, ContextProjection), String> {
    // One checkpoint per prompt (E7): /rewind restores a turn. The context
    // is the session's now, so the turn boundary is marked here.
    tool_cx.reset_turn_checkpoint();
    let base_turn_config = configured_turn(config)?;
    let origin = crate::sessions::read_selection_origin(&config.home, &config.session_id)?;
    let (turn_config, routing_decision) =
        crate::try_phase_turn_config(&config.home, &base_turn_config, prompt, origin)?;
    let resolved_gate = turn_config.gate.clone();
    turn_config.validate_effort()?;
    let retry_policy = crate::provider_policies::load_for_config(&config.home, &turn_config)
        .map_err(|error| error.to_string())?;
    if retry_policy.is_some() && accounting.is_none() {
        return Err("final-rejection retry requires managed session accounting".into());
    }
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
    let mut latest_usage_window_tokens = None;
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
                record_latest_usage_window(&mut latest_usage_window_tokens, window_tokens);
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

    let mut options = orbit_engine::TurnOptions {
        user_blocks,
        tools: crate::tools::session_tool_definitions(&config.home),
        session_id: config.session_id.clone(),
        system_directive: (!mods_directive.is_empty()).then(|| mods_directive.to_string()),
        memory_bytes: tool_cx.ext::<MemoryBytes>().map_or(0, |m| m.0),
        request_stem: "orbit-tui".into(),
        // The compaction role: a cheap model may summarize while the
        // conversation keeps its own. None = same model summarizes.
        compaction_config: Some(compaction_config),
        ..Default::default()
    };
    // A local budget error must leave session grants and permission scope in
    // the caller's slots so the worker can finish the error without losing them.
    let notices = crate::model_limits::apply_turn_budgets(&config.home, &turn_config, &mut options)
        .map_err(|error| error.to_string())?;
    for notice in notices {
        orbit_hud_tui::emit_status(sender, &notice);
    }

    if let Some(accounting) = accounting {
        accounting
            .apply_options_detailed(&mut options, None, retry_policy.as_ref())
            .map_err(|error| error.to_string())?;
    }

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

    let completion = orbit_engine::turn::run_turn_detailed_with_retry_policy(
        &config.home,
        &turn_config,
        &options,
        prompt,
        transcript,
        &mut executor,
        cancel,
        &mut events,
        retry_policy.as_ref(),
    )
    .into_completion();
    drop(events);
    *auto_grants = executor.auto_grants;
    *scope = executor.scope;
    let context_projection = measured_context_projection(
        (&base_turn_config.model, &base_turn_config.provider_id),
        (&turn_config.model, &turn_config.provider_id),
        latest_usage_window_tokens,
    );
    Ok((completion, context_projection))
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
mod context_projection_tests {
    use super::*;

    #[test]
    fn measured_context_requires_the_latest_nonzero_window_and_exact_identity() {
        assert_eq!(
            measured_context_projection(("m", "p"), ("m", "p"), Some(160_000)),
            ContextProjection::PreserveMeasured
        );
        assert_eq!(
            measured_context_projection(("m", "p"), ("m", "p"), None),
            ContextProjection::Unavailable
        );
        assert_eq!(
            measured_context_projection(("m", "p"), ("m", "p"), Some(0)),
            ContextProjection::Unavailable
        );
        assert_eq!(
            measured_context_projection(("m", "p"), ("routed", "p"), Some(160_000)),
            ContextProjection::Unavailable
        );
        assert_eq!(
            measured_context_projection(("m", "p"), ("m", "routed"), Some(160_000)),
            ContextProjection::Unavailable
        );
    }

    #[test]
    fn the_latest_usage_event_controls_the_context_projection() {
        let mut latest = None;
        record_latest_usage_window(&mut latest, 160_000);
        record_latest_usage_window(&mut latest, 0);
        assert_eq!(
            measured_context_projection(("m", "p"), ("m", "p"), latest),
            ContextProjection::Unavailable
        );

        record_latest_usage_window(&mut latest, 160_000);
        assert_eq!(
            measured_context_projection(("m", "p"), ("m", "p"), latest),
            ContextProjection::PreserveMeasured
        );
    }

    #[test]
    fn only_prompt_commands_can_publish_their_measured_context_sample() {
        for command in [
            WorkerCommand::Prompt("prompt".into()),
            WorkerCommand::PlanPrompt("plan".into()),
        ] {
            let kind = context_projection_command(&command);
            assert_eq!(
                project_context_after_command(kind, ContextProjection::PreserveMeasured),
                ContextProjection::PreserveMeasured
            );
        }

        let same_id_resume = WorkerCommand::ResumeSession("session-current".into());
        let kind = context_projection_command(&same_id_resume);
        assert_eq!(kind, ContextProjectionCommand::Other);
        assert_eq!(
            project_context_after_command(kind, ContextProjection::PreserveMeasured),
            ContextProjection::Unavailable
        );
    }

    #[test]
    fn operation_settlement_preserves_only_the_matching_ordinary_prompt_kind() {
        for (command, operation_kind) in [
            (
                WorkerCommand::Prompt("prompt".into()),
                ForegroundKind::Prompt,
            ),
            (
                WorkerCommand::PlanPrompt("plan".into()),
                ForegroundKind::PlanPrompt,
            ),
        ] {
            let command_kind = context_projection_command(&command);
            assert_eq!(
                project_context_after_foreground_operation(
                    operation_kind,
                    command_kind,
                    ContextProjection::PreserveMeasured,
                ),
                ContextProjection::PreserveMeasured
            );
        }

        for operation_kind in [ForegroundKind::Control, ForegroundKind::Resume] {
            assert_eq!(
                project_context_after_foreground_operation(
                    operation_kind,
                    ContextProjectionCommand::Prompt,
                    ContextProjection::PreserveMeasured,
                ),
                ContextProjection::Unavailable
            );
            assert_eq!(
                project_context_after_foreground_operation(
                    operation_kind,
                    ContextProjectionCommand::PlanPrompt,
                    ContextProjection::PreserveMeasured,
                ),
                ContextProjection::Unavailable
            );
        }
        assert_eq!(
            project_context_after_foreground_operation(
                ForegroundKind::Prompt,
                ContextProjectionCommand::PlanPrompt,
                ContextProjection::PreserveMeasured,
            ),
            ContextProjection::Unavailable
        );
        assert_eq!(
            project_context_after_foreground_operation(
                ForegroundKind::PlanPrompt,
                ContextProjectionCommand::Prompt,
                ContextProjection::PreserveMeasured,
            ),
            ContextProjection::Unavailable
        );
    }
}

#[cfg(test)]
mod projection_price_tests {
    use super::{CostQualification, has_complete_projected_cost};

    #[test]
    fn cost_display_requires_complete_known_session_accounting() {
        assert!(has_complete_projected_cost(&CostQualification::Known {
            revision: 4,
        }));
        for qualification in [
            CostQualification::Unavailable,
            CostQualification::UnknownHistory { revision: 4 },
            CostQualification::UnknownUsage { revision: 4 },
            CostQualification::Unpriced { revision: 4 },
            CostQualification::Uncertain { revision: 4 },
        ] {
            assert!(!has_complete_projected_cost(&qualification));
        }
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
    fn ordinary_end_mapping_preserves_execution_and_publication_matrix() {
        let binding = SessionBinding {
            session_id: "outcome-mapping".into(),
            generation: 1,
        };
        let operation =
            ForegroundOperation::new(binding.clone(), ForegroundKind::Prompt, 1).unwrap();
        let command = WorkerCommand::Prompt("original intent".into());
        let registration = operation.start(&command).unwrap();
        let (bus, sender) = orbit_hud_tui::bus::Bus::new();
        for (engine, expected) in [
            (orbit_engine::TurnEnd::Completed, OrdinaryEnd::Completed),
            (orbit_engine::TurnEnd::Cancelled, OrdinaryEnd::Cancelled),
            (
                orbit_engine::TurnEnd::Failed(orbit_engine::TurnFailure {
                    message: "typed provider failure".into(),
                }),
                OrdinaryEnd::Failed("typed provider failure".into()),
            ),
        ] {
            for saved in [false, true] {
                for (qualification, accounting_usable) in [
                    (CostQualification::Known { revision: 7 }, true),
                    (CostQualification::UnknownHistory { revision: 7 }, true),
                    (CostQualification::UnknownUsage { revision: 7 }, true),
                    (CostQualification::Unpriced { revision: 7 }, true),
                    (CostQualification::Uncertain { revision: 7 }, false),
                    (CostQualification::Unavailable, false),
                ] {
                    emit_ordinary_result(
                        &sender,
                        Some(&operation),
                        Ok(&engine),
                        saved,
                        &qualification,
                    );
                    let Some(Msg::OrdinaryTurnEnded {
                        operation: observed,
                        end,
                        publication,
                    }) = bus.try_recv()
                    else {
                        panic!("exactly one typed ordinary result required");
                    };
                    assert_eq!(observed, operation);
                    assert_eq!(end, expected);
                    let expected_publication = if saved && accounting_usable {
                        OrdinaryPublication::Saved
                    } else {
                        OrdinaryPublication::BlockedOrUncertain
                    };
                    assert_eq!(
                        publication, expected_publication,
                        "saved={saved} qualification={qualification:?}"
                    );
                    assert!(
                        bus.try_recv().is_none(),
                        "mapping cannot emit finish, notice, or projection"
                    );
                }
            }
        }
        emit_ordinary_result(
            &sender,
            Some(&operation),
            Err("setup refusal"),
            true,
            &CostQualification::Known { revision: 7 },
        );
        assert!(matches!(bus.try_recv(), Some(Msg::OrdinaryTurnEnded {
            operation: observed, end: OrdinaryEnd::Failed(reason), publication: OrdinaryPublication::Saved,
        }) if observed == operation && reason == "setup refusal"));
        let control = ForegroundOperation::new(binding, ForegroundKind::Control, 2).unwrap();
        emit_ordinary_result(
            &sender,
            Some(&control),
            Ok(&orbit_engine::TurnEnd::Completed),
            true,
            &CostQualification::Unavailable,
        );
        emit_ordinary_result(
            &sender,
            None,
            Err("unbound error"),
            false,
            &CostQualification::Unavailable,
        );
        assert!(
            bus.try_recv().is_none(),
            "control/unbound paths cannot mint ordinary results"
        );
        drop(registration);
    }

    #[cfg(unix)]
    struct OutcomeHome {
        path: std::path::PathBuf,
        removable: std::cell::Cell<bool>,
        identity: (u64, u64, u32),
    }
    #[cfg(unix)]
    impl OutcomeHome {
        fn new() -> Self {
            use std::os::unix::fs::{DirBuilderExt, MetadataExt};
            let path =
                std::env::temp_dir().join(format!("orbit-outcome-component-{}", ulid::Ulid::new()));
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&path)
                .unwrap();
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(path.join("workspace"))
                .unwrap();
            let info = std::fs::symlink_metadata(&path).unwrap();
            let identity = (info.dev(), info.ino(), info.uid());
            Self {
                path,
                removable: std::cell::Cell::new(true),
                identity,
            }
        }
    }
    #[cfg(unix)]
    impl Drop for OutcomeHome {
        fn drop(&mut self) {
            if self.removable.get() {
                use std::os::unix::fs::MetadataExt;
                let info = std::fs::symlink_metadata(&self.path).unwrap();
                assert!(info.is_dir() && info.mode() & 0o077 == 0);
                assert_eq!((info.dev(), info.ino(), info.uid()), self.identity);
                let mut pending = vec![self.path.clone()];
                let mut entries = 0usize;
                while let Some(path) = pending.pop() {
                    entries += 1;
                    assert!(entries <= 5000, "owned outcome cleanup entry bound");
                    let entry = std::fs::symlink_metadata(&path).unwrap();
                    assert_eq!(entry.uid(), self.identity.2);
                    if entry.is_dir() {
                        for child in std::fs::read_dir(path).unwrap() {
                            pending.push(child.unwrap().path());
                        }
                    } else {
                        assert!(entry.is_file() || entry.file_type().is_symlink());
                    }
                }
                let current = std::fs::symlink_metadata(&self.path).unwrap();
                assert_eq!((current.dev(), current.ino(), current.uid()), self.identity);
                std::fs::remove_dir_all(&self.path).expect("owned outcome fixture cleanup");
            } else {
                eprintln!("owned outcome fixture retained after incomplete snapshot restoration");
            }
        }
    }
    #[cfg(unix)]
    struct OutcomeModeGuard {
        file: std::fs::File,
        mode: u32,
    }
    #[cfg(unix)]
    impl Drop for OutcomeModeGuard {
        fn drop(&mut self) {
            use std::os::unix::fs::PermissionsExt;
            let _ = self
                .file
                .set_permissions(std::fs::Permissions::from_mode(self.mode));
        }
    }

    #[test]
    #[cfg(unix)]
    fn completed_end_with_actual_save_failure_emits_notice_and_blocked_publication() {
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
        let home = OutcomeHome::new();
        let config = config(&home.path);
        let lease =
            crate::sessions::SessionLease::acquire(&home.path, "session-test", "outcome-component")
                .unwrap();
        let mut initial = crate::sessions::SessionFile::from_chat(
            "session-test",
            "m",
            "http://127.0.0.1:1",
            "p",
            &[],
            0,
            0,
            0,
            0,
        )
        .in_workspace(&home.path.join("workspace"))
        .unwrap();
        let accounting =
            session_accounting::prepare_root(&lease, &mut initial, RootOrigin::FreshCandidate)
                .unwrap();
        let before_checkpoint = accounting.namespace().checkpoint().unwrap();
        let path = home.path.join("sessions/session-test.json");
        let before = std::fs::read(&path).unwrap();
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(&path)
            .unwrap();
        let metadata = file.metadata().unwrap();
        assert!(
            metadata.is_file()
                && metadata.uid() == home.identity.2
                && metadata.nlink() == 1
                && metadata.mode() & 0o077 == 0
        );
        let identity = (
            metadata.dev(),
            metadata.ino(),
            metadata.uid(),
            metadata.nlink(),
        );
        let guard = OutcomeModeGuard {
            file,
            mode: metadata.mode() & 0o7777,
        };
        home.removable.set(false);
        guard
            .file
            .set_permissions(std::fs::Permissions::from_mode(guard.mode | 0o040))
            .unwrap();
        let (bus, sender) = orbit_hud_tui::bus::Bus::new();
        let (mut input, mut output, mut cost) = (0, 0, 0);
        let mut qualification = CostQualification::Unavailable;
        let transcript = vec![
            orbit_engine::user_message("component intent"),
            orbit_engine::assistant_message("component completed output"),
        ];
        let saved = save_turn(
            &config,
            &lease,
            &accounting,
            &transcript,
            1,
            &mut input,
            &mut output,
            &mut cost,
            crate::phase_routing::SelectionOrigin::Default,
            &sender,
            &mut qualification,
            false,
        );
        assert!(
            !saved,
            "the real private-file storage fault must reject publication"
        );
        let operation = ForegroundOperation::new(
            SessionBinding {
                session_id: "session-test".into(),
                generation: 1,
            },
            ForegroundKind::Prompt,
            1,
        )
        .unwrap();
        let registration = operation
            .start(&WorkerCommand::Prompt("component intent".into()))
            .unwrap();
        // Completed is a component input, not an observed full-worker engine run.
        emit_ordinary_result(
            &sender,
            Some(&operation),
            Ok(&orbit_engine::TurnEnd::Completed),
            saved,
            &qualification,
        );
        let (mut notices, mut terminal) = (0, 0);
        while let Some(message) = bus.try_recv() {
            match message {
                Msg::BackendNotice(text) => {
                    notices += 1;
                    assert_eq!(
                        text,
                        "current prompt could not be saved: leased session storage could not be verified"
                    );
                }
                Msg::OrdinaryTurnEnded {
                    operation: observed,
                    end,
                    publication,
                } => {
                    terminal += 1;
                    assert_eq!(observed, operation);
                    assert_eq!(end, OrdinaryEnd::Completed);
                    assert_eq!(publication, OrdinaryPublication::BlockedOrUncertain);
                }
                Msg::BackendError(_) | Msg::ResponseFinished { .. } | Msg::SessionProjection(_) => {
                    panic!("component mapping must preserve existing finish/settlement ownership")
                }
                _ => {}
            }
        }
        assert_eq!((notices, terminal), (1, 1));
        assert_eq!((input, output, cost), (0, 0, 0));
        assert_eq!(
            accounting.namespace().checkpoint().unwrap(),
            before_checkpoint
        );
        assert!(matches!(
            crate::sessions::SessionLease::acquire(&home.path, "session-test", "must-stay-owned"),
            Err(crate::sessions::SessionLeaseError::Busy { .. })
        ));
        guard
            .file
            .set_permissions(std::fs::Permissions::from_mode(guard.mode))
            .unwrap();
        let held = guard.file.metadata().unwrap();
        let current = std::fs::symlink_metadata(&path).unwrap();
        assert_eq!((held.dev(), held.ino(), held.uid(), held.nlink()), identity);
        assert_eq!(
            (current.dev(), current.ino(), current.uid(), current.nlink()),
            identity
        );
        assert_eq!(current.mode() & 0o7777, guard.mode);
        assert_eq!(std::fs::read(&path).unwrap(), before);
        // A real nonturn save_controls fault uses the same owned FD, separately.
        guard
            .file
            .set_permissions(std::fs::Permissions::from_mode(guard.mode | 0o040))
            .unwrap();
        assert!(!save_controls(
            &config,
            &lease,
            &accounting,
            &[],
            0,
            &mut input,
            &mut output,
            &mut cost,
            &sender,
            crate::phase_routing::SelectionOrigin::Default,
            &mut qualification
        ));
        assert!(
            matches!(bus.try_recv(), Some(Msg::BackendNotice(text)) if text == "settings unchanged: leased session storage could not be verified")
        );
        assert!(bus.try_recv().is_none());
        guard
            .file
            .set_permissions(std::fs::Permissions::from_mode(guard.mode))
            .unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), before);
        assert_eq!(
            accounting.namespace().checkpoint().unwrap(),
            before_checkpoint
        );
        let current = std::fs::symlink_metadata(&path).unwrap();
        assert_eq!(
            (current.dev(), current.ino(), current.uid(), current.nlink()),
            identity
        );
        assert_eq!(current.mode() & 0o7777, guard.mode);
        home.removable.set(true);
        drop(guard);
        drop(registration);
        let saved_success = save_turn(
            &config,
            &lease,
            &accounting,
            &[],
            0,
            &mut input,
            &mut output,
            &mut cost,
            crate::phase_routing::SelectionOrigin::Default,
            &sender,
            &mut qualification,
            false,
        );
        assert!(
            saved_success,
            "the same actual save must succeed after the owned mode fault is removed"
        );
        let next = ForegroundOperation::new(operation.source().clone(), ForegroundKind::Prompt, 2)
            .unwrap();
        let next_registration = next
            .start(&WorkerCommand::Prompt("saved component control".into()))
            .unwrap();
        emit_ordinary_result(
            &sender,
            Some(&next),
            Ok(&orbit_engine::TurnEnd::Completed),
            saved_success,
            &qualification,
        );
        assert!(matches!(bus.try_recv(), Some(Msg::OrdinaryTurnEnded {
            operation: observed, end: OrdinaryEnd::Completed, publication: OrdinaryPublication::Saved,
        }) if observed == next));
        assert!(
            bus.try_recv().is_none(),
            "successful repair cannot invent a notice or a second result"
        );
        assert_eq!(
            accounting.namespace().checkpoint().unwrap(),
            before_checkpoint
        );
        drop(next_registration);
    }

    #[test]
    #[cfg(unix)]
    fn nonturn_producers_emit_notices_without_ordinary_terminal_result() {
        let home = OutcomeHome::new();
        let initial = config(&home.path);
        let (bus, sender) = orbit_hud_tui::bus::Bus::new();
        let (commands, command_rx) = mpsc::channel();
        commands
            .send(WorkerCommand::SetMode("invalid-outcome-mode".into()))
            .unwrap();
        drop(commands);
        worker_main(
            WorkerCtx {
                sender,
                approvals: ApprovalRegistry::new(),
                command_rx,
            },
            initial,
            Default::default(),
        );
        let mut notices = 0;
        while let Some(message) = bus.try_recv() {
            match message {
                Msg::BackendNotice(text) => {
                    notices += 1;
                    assert!(text.starts_with("unknown mode invalid-outcome-mode"));
                }
                Msg::BackendError(_)
                | Msg::OrdinaryTurnEnded { .. }
                | Msg::ResponseFinished { .. } => {
                    panic!("nonturn producer created ordinary failure or completion")
                }
                _ => {}
            }
        }
        assert_eq!(notices, 1);
    }

    #[cfg(unix)]
    fn startup_private_environment() -> Vec<(std::ffi::OsString, std::ffi::OsString)> {
        use std::os::unix::fs::MetadataExt;
        assert_eq!(
            std::env::var("ORBIT_ACTIVATION_ISOLATED").as_deref(),
            Ok("1")
        );
        assert_eq!(
            std::env::var("ORBIT_ACTIVATION_RUNNER_DEPTH").as_deref(),
            Ok("1")
        );
        let root = std::path::PathBuf::from(std::env::var_os("ORBIT_ACTIVATION_ROOT").unwrap());
        let root_info = std::fs::symlink_metadata(&root).unwrap();
        assert!(root_info.is_dir() && root_info.mode() & 0o077 == 0);
        for path in [
            std::path::PathBuf::from(std::env::var_os("HOME").unwrap()),
            std::path::PathBuf::from(std::env::var_os("TMPDIR").unwrap()),
            std::env::current_dir().unwrap(),
        ] {
            let canonical = std::fs::canonicalize(&path).unwrap();
            let info = std::fs::symlink_metadata(&path).unwrap();
            assert!(
                canonical.starts_with(&root)
                    && info.is_dir()
                    && info.uid() == root_info.uid()
                    && info.mode() & 0o077 == 0
            );
        }
        for (key, current) in [
            ("ORBIT_ACTIVATION_PARENT_MOUNT_FD", "/proc/self/ns/mnt"),
            ("ORBIT_ACTIVATION_PARENT_USER_FD", "/proc/self/ns/user"),
        ] {
            let descriptor: u32 = std::env::var(key).unwrap().parse().unwrap();
            assert!(descriptor < 4096);
            let parent = std::fs::metadata(format!("/proc/self/fd/{descriptor}")).unwrap();
            let own = std::fs::metadata(current).unwrap();
            assert_ne!((parent.dev(), parent.ino()), (own.dev(), own.ino()));
        }
        let mounts = std::fs::read_to_string("/proc/self/mountinfo").unwrap();
        assert!(mounts.lines().any(
            |line| line.split_whitespace().nth(4) == Some("/etc") && line.contains(" - tmpfs ")
        ));
        let marker = std::env::var("ORBIT_ACTIVATION_MANAGED_MARKER").unwrap();
        assert!(
            marker.starts_with("ORBIT_ACTIVATION_MANAGED_")
                && marker.len() <= 128
                && marker
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        );
        assert_eq!(
            std::fs::read_to_string("/etc/orbit/ORBIT.md").unwrap(),
            marker
        );
        let names = [
            "PATH",
            "LANG",
            "LC_ALL",
            "HOME",
            "USER",
            "LOGNAME",
            "TMPDIR",
            "TERM",
            "NO_COLOR",
            "XDG_CONFIG_HOME",
            "XDG_CACHE_HOME",
            "XDG_DATA_HOME",
            "XDG_STATE_HOME",
            "XDG_RUNTIME_DIR",
            "ORBIT_ACTIVATION_ROOT",
            "ORBIT_ACTIVATION_PARENT_MOUNT_FD",
            "ORBIT_ACTIVATION_PARENT_USER_FD",
            "ORBIT_ACTIVATION_MANAGED_MARKER",
            "ORBIT_ACTIVATION_ISOLATED",
            "ORBIT_ACTIVATION_RUNNER_DEPTH",
        ];
        names
            .into_iter()
            .map(|name| (name.into(), std::env::var_os(name).unwrap()))
            .collect()
    }

    #[cfg(unix)]
    struct OutcomeStartupChild {
        child: std::process::Child,
        reaped: bool,
    }
    #[cfg(unix)]
    impl Drop for OutcomeStartupChild {
        fn drop(&mut self) {
            if !self.reaped {
                // This unreaped handle owns this exact child PID. No group or
                // external command is signalled, and the namespace is inherited.
                let _ = self.child.kill();
                let _ = self.child.wait();
            }
        }
    }

    #[cfg(unix)]
    fn record_startup_child_failure(case: &str, stdout: &std::fs::File, stderr: &std::fs::File) {
        use std::os::unix::fs::FileExt;
        let private_root = std::env::var("ORBIT_ACTIVATION_ROOT").unwrap_or_default();
        for (stream, file) in [("stdout", stdout), ("stderr", stderr)] {
            let diagnostic = (|| -> std::io::Result<String> {
                let length = file.metadata()?.len();
                let offset = length.saturating_sub(2048);
                let mut bytes = vec![0u8; (length - offset) as usize];
                let mut read = 0usize;
                while read < bytes.len() {
                    let count = file.read_at(&mut bytes[read..], offset + read as u64)?;
                    if count == 0 {
                        break;
                    }
                    read += count;
                }
                bytes.truncate(read);
                let text = String::from_utf8_lossy(&bytes);
                let redacted = if private_root.is_empty() {
                    text.into_owned()
                } else {
                    text.replace(&private_root, "<private-fixture>")
                };
                Ok(redacted
                    .chars()
                    .flat_map(char::escape_default)
                    .take(4096)
                    .collect())
            })();
            match diagnostic {
                Ok(tail) => {
                    eprintln!("ORBIT_STARTUP_CHILD_FAILURE case={case} stream={stream} tail={tail}")
                }
                Err(_) => eprintln!(
                    "ORBIT_STARTUP_CHILD_FAILURE case={case} stream={stream} tail=<owned-fd-read-failed>"
                ),
            }
        }
    }

    #[cfg(unix)]
    fn startup_case_child(case: &str) {
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
        assert!(matches!(
            case,
            "provenance" | "snapshot" | "cwd" | "workspace" | "accounting"
        ));
        assert!(
            std::env::var_os("ORBIT_TUI_STARTUP_CHILD_CASE").is_none(),
            "startup parent must not recursively run as its ignored child"
        );
        let environment = startup_private_environment();
        let home = OutcomeHome::new();
        home.removable.set(false);
        let executable = std::env::current_exe().unwrap();
        let original = std::fs::symlink_metadata(&executable).unwrap();
        assert!(
            original.is_file()
                && original.uid() == home.identity.2
                && original.nlink() == 1
                && original.mode() & 0o111 != 0
        );
        let stamp = |metadata: &std::fs::Metadata| {
            (
                metadata.dev(),
                metadata.ino(),
                metadata.uid(),
                metadata.mode(),
                metadata.nlink(),
                metadata.len(),
                metadata.mtime(),
                metadata.mtime_nsec(),
                metadata.ctime(),
                metadata.ctime_nsec(),
            )
        };
        let stdout_path = home.path.join("startup-child.stdout");
        let stderr_path = home.path.join("startup-child.stderr");
        let open = |path: &std::path::Path| {
            std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(path)
                .unwrap()
        };
        let stdout = open(&stdout_path);
        let stderr = open(&stderr_path);
        for file in [&stdout, &stderr] {
            let info = file.metadata().unwrap();
            assert!(
                info.is_file()
                    && info.uid() == home.identity.2
                    && info.nlink() == 1
                    && info.mode() & 0o7777 == 0o600
            );
        }
        let mut guard = OutcomeStartupChild {
            child: std::process::Command::new(&executable)
                .args([
                    "--ignored",
                    "--exact",
                    "tui_worker::session_tests::startup_failure_child_dispatch",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env_clear()
                .envs(environment)
                .env("ORBIT_TUI_STARTUP_CHILD_CASE", case)
                .current_dir(std::env::current_dir().unwrap())
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::from(stdout.try_clone().unwrap()))
                .stderr(std::process::Stdio::from(stderr.try_clone().unwrap()))
                .spawn()
                .unwrap(),
            reaped: false,
        };
        let require_child = |passed: bool, reason: &str| {
            if !passed {
                // The enclosing runner removes its fixture root on all exits.
                // Record bounded actual child output before its files vanish.
                record_startup_child_failure(case, &stdout, &stderr);
                panic!("{reason}");
            }
        };
        let within_output_bound = || {
            [&stdout, &stderr].into_iter().all(|file| {
                file.metadata()
                    .map(|info| info.len() <= 64 * 1024)
                    .unwrap_or(false)
            })
        };
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
        let status = loop {
            require_child(
                within_output_bound(),
                "startup child output bound or metadata failure",
            );
            let status = guard.child.try_wait().unwrap_or_else(|_| {
                require_child(false, "startup child wait failed");
                unreachable!()
            });
            if let Some(status) = status {
                guard.reaped = true;
                break status;
            }
            require_child(
                std::time::Instant::now() < deadline,
                "startup child control deadline",
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        };
        require_child(
            status.success(),
            "actual ignored startup child assertions failed",
        );
        require_child(
            within_output_bound(),
            "startup child final output bound or metadata failure",
        );
        let text = std::fs::read_to_string(&stdout_path).unwrap_or_else(|_| {
            require_child(false, "startup child stdout decoding failed");
            unreachable!()
        });
        let marker = format!("ORBIT_STARTUP_BRANCH_ASSERTIONS:{case}");
        require_child(
            text.lines().filter(|line| *line == marker.as_str()).count() == 1,
            "actual startup child assertion marker missing or duplicated",
        );
        require_child(
            text.lines()
                .filter(|line| line.starts_with("test result: ok. 1 passed; 0 failed; 0 ignored;"))
                .count()
                == 1,
            "a zero-test or ignored-only run is not startup branch evidence",
        );
        let current = std::fs::symlink_metadata(&executable).unwrap_or_else(|_| {
            require_child(false, "startup child executable metadata unavailable");
            unreachable!()
        });
        require_child(
            stamp(&current) == stamp(&original),
            "startup child executable identity changed",
        );
        home.removable.set(true);
    }

    #[test]
    #[cfg(unix)]
    #[ignore = "invoked only by the five exact startup parents in a private single-test child"]
    fn startup_failure_child_dispatch() {
        let _ = startup_private_environment();
        let case =
            std::env::var("ORBIT_TUI_STARTUP_CHILD_CASE").expect("exact owned startup child case");
        match case.as_str() {
            "provenance" => startup_provenance_fixture(),
            "snapshot" => startup_snapshot_fixture(),
            "cwd" => startup_workspace_discovery_fixture(),
            "workspace" => startup_workspace_admission_fixture(),
            "accounting" => startup_accounting_preparation_fixture(),
            _ => panic!("unknown startup child case"),
        }
        println!("\nORBIT_STARTUP_BRANCH_ASSERTIONS:{case}");
    }

    #[cfg(unix)]
    struct OutcomeCwdGuard {
        previous: std::path::PathBuf,
        identity: (u64, u64, u32),
        restored: bool,
    }
    #[cfg(unix)]
    impl OutcomeCwdGuard {
        fn enter(home: &OutcomeHome, target: &std::path::Path) -> Self {
            use std::os::unix::fs::MetadataExt;
            let previous = std::env::current_dir().expect("private prior CWD");
            let before = std::fs::symlink_metadata(&previous).unwrap();
            assert!(
                before.is_dir() && before.uid() == home.identity.2 && before.mode() & 0o077 == 0,
                "startup tests require a private owned runner CWD"
            );
            let target_info = std::fs::symlink_metadata(target).unwrap();
            assert!(
                target_info.is_dir()
                    && target_info.uid() == home.identity.2
                    && target_info.mode() & 0o077 == 0
            );
            assert!(
                std::fs::canonicalize(target)
                    .unwrap()
                    .starts_with(&home.path)
            );
            home.removable.set(false);
            std::env::set_current_dir(target).unwrap();
            Self {
                previous,
                identity: (before.dev(), before.ino(), before.uid()),
                restored: false,
            }
        }
        fn restore(&mut self) -> bool {
            use std::os::unix::fs::MetadataExt;
            let result = (|| -> std::io::Result<()> {
                let before = std::fs::symlink_metadata(&self.previous)?;
                if !before.is_dir() || (before.dev(), before.ino(), before.uid()) != self.identity {
                    return Err(std::io::Error::other("private prior CWD identity changed"));
                }
                std::env::set_current_dir(&self.previous)?;
                let current = std::env::current_dir()?;
                let after = std::fs::symlink_metadata(&current)?;
                if current != self.previous
                    || (after.dev(), after.ino(), after.uid()) != self.identity
                {
                    return Err(std::io::Error::other("private prior CWD was not restored"));
                }
                Ok(())
            })();
            self.restored = result.is_ok();
            self.restored
        }
    }
    #[cfg(unix)]
    impl Drop for OutcomeCwdGuard {
        fn drop(&mut self) {
            if !self.restored && !self.restore() {
                eprintln!("owned startup fixture retained after incomplete CWD restoration");
            }
        }
    }

    #[cfg(unix)]
    fn startup_snapshot(
        home: &OutcomeHome,
    ) -> (
        crate::sessions::SessionLease,
        crate::sessions::SessionFile,
        std::path::PathBuf,
    ) {
        let lease =
            crate::sessions::SessionLease::acquire(&home.path, "session-test", "startup-outcome")
                .unwrap();
        let saved = crate::sessions::SessionFile::from_chat(
            "session-test",
            "m",
            "http://127.0.0.1:1",
            "p",
            &[],
            0,
            0,
            0,
            0,
        )
        .in_workspace(&home.path.join("workspace"))
        .unwrap();
        lease.save(&saved).unwrap();
        (lease, saved, home.path.join("sessions/session-test.json"))
    }

    #[cfg(unix)]
    fn rewrite_startup_snapshot(home: &OutcomeHome, path: &std::path::Path, bytes: &[u8]) {
        use std::io::Write;
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
        assert_eq!(path, home.path.join("sessions/session-test.json"));
        assert!(bytes.len() <= 16384);
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(path)
            .unwrap();
        let info = file.metadata().unwrap();
        assert!(
            info.is_file()
                && info.uid() == home.identity.2
                && info.nlink() == 1
                && info.mode() & 0o077 == 0
        );
        let identity = (info.dev(), info.ino(), info.uid(), info.nlink());
        file.set_len(0).unwrap();
        file.write_all(bytes).unwrap();
        file.sync_all().unwrap();
        let after = std::fs::symlink_metadata(path).unwrap();
        assert_eq!(
            (after.dev(), after.ino(), after.uid(), after.nlink()),
            identity
        );
        assert_eq!(std::fs::read(path).unwrap(), bytes);
    }

    #[cfg(unix)]
    fn assert_startup_notice(
        home: &OutcomeHome,
        lease: crate::sessions::SessionLease,
        expected: &str,
    ) {
        let (bus, sender) = orbit_hud_tui::bus::Bus::new();
        let (commands, command_rx) = mpsc::channel();
        drop(commands);
        // EOF prevents a wrong successful startup from waiting for test input.
        // This calls the actual production startup; no stubbed producer or hook.
        worker_main_owned(
            WorkerCtx {
                sender,
                approvals: ApprovalRegistry::new(),
                command_rx,
            },
            config(&home.path),
            Default::default(),
            lease,
        );
        let mut messages = Vec::new();
        while let Some(message) = bus.try_recv() {
            messages.push(message);
        }
        assert_eq!(
            messages.len(),
            1,
            "startup failure must emit exactly its Notice"
        );
        match messages.pop().unwrap() {
            Msg::BackendNotice(text) => assert_eq!(text, expected),
            _ => panic!(
                "startup failure emitted an ordinary error, report, or initialization instead of Notice"
            ),
        }
        let released =
            crate::sessions::SessionLease::acquire(&home.path, "session-test", "startup-returned")
                .expect("the actual returned startup releases its lease");
        drop(released);
    }

    #[test]
    #[cfg(unix)]
    fn startup_provenance_failure_is_notice_without_ordinary_events() {
        startup_case_child("provenance");
    }

    #[cfg(unix)]
    fn startup_provenance_fixture() {
        let home = OutcomeHome::new();
        let (lease, _, path) = startup_snapshot(&home);
        rewrite_startup_snapshot(&home, &path, b"{");
        assert_eq!(
            crate::sessions::read_selection_origin(&home.path, "session-test").unwrap_err(),
            "invalid saved session provenance"
        );
        let before = std::fs::read(&path).unwrap();
        assert_startup_notice(&home, lease, "invalid saved session provenance");
        assert_eq!(std::fs::read(path).unwrap(), before);
    }

    #[test]
    #[cfg(unix)]
    fn startup_snapshot_failure_is_notice_without_ordinary_events() {
        startup_case_child("snapshot");
    }

    #[cfg(unix)]
    fn startup_snapshot_fixture() {
        let home = OutcomeHome::new();
        let (lease, mut saved, path) = startup_snapshot(&home);
        saved.schema = "unsupported-fixture-schema".into();
        rewrite_startup_snapshot(&home, &path, &serde_json::to_vec(&saved).unwrap());
        // Provenance accepts the parsed identity; the next real lease load
        // performs the schema check and reaches the distinct second branch.
        assert!(crate::sessions::read_selection_origin(&home.path, "session-test").is_ok());
        assert!(matches!(lease.load_optional(),
            Err(crate::sessions::SessionLeaseError::InvalidData(reason)) if reason == "unsupported session schema"));
        let before = std::fs::read(&path).unwrap();
        assert_startup_notice(
            &home,
            lease,
            "invalid saved session: unsupported session schema",
        );
        assert_eq!(std::fs::read(path).unwrap(), before);
    }

    #[test]
    #[cfg(unix)]
    fn startup_workspace_discovery_failure_is_notice_without_ordinary_events() {
        startup_case_child("cwd");
    }

    #[cfg(unix)]
    fn startup_workspace_discovery_fixture() {
        let home = OutcomeHome::new();
        let workspace = home.path.join("workspace");
        let lease =
            crate::sessions::SessionLease::acquire(&home.path, "session-test", "startup-workspace")
                .unwrap();
        assert!(crate::sessions::read_selection_origin(&home.path, "session-test").is_ok());
        assert!(lease.load_optional().unwrap().is_none());
        let mut cwd = OutcomeCwdGuard::enter(&home, &workspace);
        let expected = std::fs::symlink_metadata(&workspace).unwrap();
        use std::os::unix::fs::MetadataExt;
        let held = std::fs::symlink_metadata(std::path::Path::new(".")).unwrap();
        assert_eq!(
            (held.dev(), held.ino(), held.uid()),
            (expected.dev(), expected.ino(), expected.uid())
        );
        // Only the exact new empty owned directory is removed, never the
        // runner/operator CWD. This deterministically makes getcwd fail.
        std::fs::remove_dir(&workspace).unwrap();
        assert!(crate::sessions::current_workspace().is_err());
        assert_startup_notice(
            &home,
            lease,
            "invalid saved session: workspace directory is unavailable",
        );
        assert!(cwd.restore(), "private prior CWD restoration");
        home.removable.set(true);
        drop(cwd);
        assert!(
            !home.path.join("sessions/session-test.json").exists(),
            "workspace discovery failure must not create a snapshot"
        );
    }

    #[test]
    #[cfg(unix)]
    fn startup_workspace_admission_failure_is_notice_without_ordinary_events() {
        startup_case_child("workspace");
    }

    #[cfg(unix)]
    fn startup_workspace_admission_fixture() {
        use std::os::unix::fs::DirBuilderExt;
        let home = OutcomeHome::new();
        let (lease, saved, path) = startup_snapshot(&home);
        let actual = home.path.join("current-workspace");
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&actual)
            .unwrap();
        let mut cwd = OutcomeCwdGuard::enter(&home, &actual);
        assert!(crate::sessions::read_selection_origin(&home.path, "session-test").is_ok());
        assert!(lease.load_optional().unwrap().is_some());
        let workspace = crate::sessions::current_workspace().unwrap();
        assert!(saved.require_workspace(&workspace).is_err());
        let before = std::fs::read(&path).unwrap();
        assert_startup_notice(
            &home,
            lease,
            "invalid saved session: session belongs to another workspace; open its original directory to resume",
        );
        assert!(cwd.restore(), "private prior CWD restoration");
        home.removable.set(true);
        drop(cwd);
        assert_eq!(std::fs::read(path).unwrap(), before);
    }

    #[test]
    #[cfg(unix)]
    fn startup_accounting_preparation_failure_is_notice_without_ordinary_events() {
        startup_case_child("accounting");
    }

    #[cfg(unix)]
    fn startup_accounting_preparation_fixture() {
        let home = OutcomeHome::new();
        let (lease, mut saved, path) = startup_snapshot(&home);
        saved.accounting_watermark = Some(session_accounting::SessionAccountingWatermark {
            owner_session_id: "session-test".into(),
            child_id: None,
            revision: 1,
            known_input_tokens: 0,
            known_output_tokens: 0,
            known_ordinary_microcents: 0,
            known_housekeeping_microcents: 0,
            full_cost_status: FullCostStatus::Known,
        });
        lease.save(&saved).unwrap();
        let mut cwd = OutcomeCwdGuard::enter(&home, &home.path.join("workspace"));
        assert!(crate::sessions::read_selection_origin(&home.path, "session-test").is_ok());
        let observed = lease.load_optional().unwrap().unwrap();
        observed
            .require_workspace(&crate::sessions::current_workspace().unwrap())
            .unwrap();
        let journal =
            crate::context_history::context_journal(&home.path, "session-test", None).unwrap();
        assert!(matches!(
            journal.accounting_checkpoint_detailed(),
            Err(orbit_engine::HistoryError::Missing)
        ));
        let before = std::fs::read(&path).unwrap();
        assert_startup_notice(
            &home,
            lease,
            "saved accounting anchor exists but its journal is missing",
        );
        assert!(cwd.restore(), "private prior CWD restoration");
        home.removable.set(true);
        drop(cwd);
        assert_eq!(std::fs::read(path).unwrap(), before);
        assert!(matches!(
            journal.accounting_checkpoint_detailed(),
            Err(orbit_engine::HistoryError::Missing)
        ));
    }

    #[test]
    #[cfg(unix)]
    fn missing_mod_body_settles_without_fabricated_ordinary_report() {
        let home = OutcomeHome::new();
        let initial = config(&home.path);
        let lease =
            crate::sessions::SessionLease::acquire(&home.path, "session-test", "missing-mod")
                .unwrap();
        home.removable.set(false);
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
                lease,
            );
        });
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
        let binding = loop {
            match bus.try_recv() {
                Some(Msg::SessionProjection(view))
                    if matches!(view.reason, ProjectionReason::Initial) =>
                {
                    break view.binding;
                }
                Some(Msg::BackendError(_) | Msg::BackendNotice(_)) => {
                    panic!("missing-mod fixture startup failed")
                }
                _ => {}
            }
            assert!(
                std::time::Instant::now() < deadline,
                "actual initial binding absent"
            );
            std::thread::sleep(std::time::Duration::from_millis(2));
        };
        let operation = ForegroundOperation::new(binding, ForegroundKind::Prompt, 1).unwrap();
        commands
            .send(WorkerCommand::Bound {
                operation: operation.clone(),
                command: Box::new(WorkerCommand::ModCommand(
                    "absent-mod".into(),
                    "absent-command".into(),
                )),
            })
            .unwrap();
        drop(commands);
        worker.join().unwrap();
        home.removable.set(true);
        let (mut diagnostic, mut terminal) = (0, 0);
        while let Some(message) = bus.try_recv() {
            match message {
                Msg::SystemMessage(text)
                    if text == "no command absent-command in mod absent-mod" =>
                {
                    diagnostic += 1
                }
                Msg::SessionProjection(view)
                    if matches!(&view.reason,
                    ProjectionReason::Operation { operation: observed } if observed == &operation) =>
                {
                    terminal += 1
                }
                Msg::BackendError(_)
                | Msg::BackendNotice(_)
                | Msg::OrdinaryTurnEnded { .. }
                | Msg::ResponseFinished { .. } => {
                    panic!("missing body fabricated an ordinary execution")
                }
                _ => {}
            }
        }
        assert_eq!((diagnostic, terminal), (1, 1));
        let retained = crate::sessions::load_session(&home.path, "session-test").unwrap();
        assert!(retained.transcript.is_empty());
        assert_eq!(
            (
                retained.turns,
                retained.input_tokens,
                retained.output_tokens,
                retained.cost_microcents
            ),
            (0, 0, 0, 0)
        );
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
            .save(
                &SessionFile::from_chat("target", "m", "http://127.0.0.1:1", "p", &[], 0, 0, 0, 0)
                    .in_workspace(&crate::sessions::current_workspace().unwrap())
                    .unwrap(),
            )
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
        let mut source = None;
        let mut backend_failure = false;
        while std::time::Instant::now() < deadline {
            match bus.try_recv() {
                Some(Msg::SessionProjection(view)) => match &view.reason {
                    ProjectionReason::Initial => {
                        assert_eq!(view.binding.session_id, "session-test");
                        assert_eq!(view.binding.generation, 1);
                        assert_eq!((view.model.as_str(), view.provider.as_str()), ("m", "p"));
                        assert!(view.lines.is_empty());
                        assert_eq!(
                            (
                                view.turns,
                                view.input_tokens,
                                view.output_tokens,
                                view.cost_microcents
                            ),
                            (0, 0, 0, 0)
                        );
                        assert_eq!(view.cost, CostQualification::UnknownHistory { revision: 0 });
                        assert_eq!(view.context, ContextProjection::Unavailable);
                        source = Some(view.binding);
                    }
                    ProjectionReason::Resume { previous }
                        if view.binding.session_id == "target" =>
                    {
                        let source = source
                            .as_ref()
                            .expect("resume follows the actual Initial view");
                        assert_eq!(previous, source);
                        assert_eq!(
                            source.generation.checked_add(1),
                            Some(view.binding.generation)
                        );
                        assert_eq!((view.model.as_str(), view.provider.as_str()), ("m", "p"));
                        assert!(view.lines.is_empty());
                        assert_eq!(
                            (
                                view.turns,
                                view.input_tokens,
                                view.output_tokens,
                                view.cost_microcents
                            ),
                            (0, 0, 0, 0)
                        );
                        assert_eq!(view.cost, CostQualification::UnknownHistory { revision: 0 });
                        assert_eq!(view.context, ContextProjection::Unavailable);
                        switched = true;
                        break;
                    }
                    _ => {}
                },
                Some(Msg::BackendError(_)) | Some(Msg::BackendNotice(_)) => backend_failure = true,
                _ => std::thread::sleep(std::time::Duration::from_millis(5)),
            }
        }
        let previous = SessionLease::acquire(&home, "session-test", "another-frontend").ok();
        let old_path = home.join("projects/session-test.jsonl");
        let old_bytes = std::fs::read(&old_path).unwrap();
        commands.send(WorkerCommand::Rewind("cp1".into())).unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
        let mut rewound = false;
        while std::time::Instant::now() < deadline {
            match bus.try_recv() {
                Some(Msg::SystemMessage(text)) if text.starts_with("restored 1 file") => {
                    rewound = true;
                    break;
                }
                Some(Msg::BackendError(_)) | Some(Msg::BackendNotice(_)) => backend_failure = true,
                _ => std::thread::sleep(std::time::Duration::from_millis(5)),
            }
        }
        let target_owned = matches!(
            SessionLease::acquire(&home, "target", "other"),
            Err(SessionLeaseError::Busy { .. })
        );
        drop(commands);
        worker.join().unwrap();
        while let Some(message) = bus.try_recv() {
            if matches!(message, Msg::BackendError(_) | Msg::BackendNotice(_)) {
                backend_failure = true;
            }
        }
        assert!(switched && rewound && previous.is_some() && target_owned);
        assert!(
            !backend_failure,
            "resume/rewind controls must not fail a provider turn"
        );
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
            .save(
                &SessionFile::from_chat("target", "m", "http://127.0.0.1:1", "p", &[], 0, 0, 0, 0)
                    .in_workspace(&crate::sessions::current_workspace().unwrap())
                    .unwrap(),
            )
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
        let mut source: Option<SessionProjection> = None;
        let mut refusal_notice = false;
        while std::time::Instant::now() < deadline {
            match bus.try_recv() {
                Some(Msg::SessionProjection(view))
                    if matches!(&view.reason, ProjectionReason::Initial) =>
                {
                    assert_eq!(view.binding.session_id, "session-test");
                    assert_eq!(view.binding.generation, 1);
                    assert_eq!(view.cost, CostQualification::UnknownHistory { revision: 0 });
                    source = Some(view);
                }
                Some(Msg::Status(text)) if text == "resume refused: transcript unavailable" => {
                    refusal_notice = true;
                }
                Some(Msg::SessionProjection(view))
                    if refusal_notice && matches!(&view.reason, ProjectionReason::Refresh) =>
                {
                    let source = source
                        .as_ref()
                        .expect("refusal follows the actual Initial view");
                    assert_eq!(view.binding, source.binding);
                    assert_eq!(
                        (&view.model, &view.provider),
                        (&source.model, &source.provider)
                    );
                    assert_eq!(view.lines, source.lines);
                    assert_eq!(
                        (
                            view.turns,
                            view.input_tokens,
                            view.output_tokens,
                            view.cost_microcents
                        ),
                        (
                            source.turns,
                            source.input_tokens,
                            source.output_tokens,
                            source.cost_microcents
                        )
                    );
                    assert_eq!(view.cost, source.cost);
                    assert_eq!(view.context, ContextProjection::Unavailable);
                    refused = true;
                    break;
                }
                Some(Msg::BackendError(_)) | Some(Msg::BackendNotice(_)) => backend_failure = true,
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
        while let Some(message) = bus.try_recv() {
            if matches!(message, Msg::BackendError(_) | Msg::BackendNotice(_)) {
                backend_failure = true;
            }
        }
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
        busy.save(
            &SessionFile::from_chat("busy", "m", "http://127.0.0.1:1", "p", &[], 9, 0, 0, 0)
                .in_workspace(&crate::sessions::current_workspace().unwrap())
                .unwrap(),
        )
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
        let expected_refusal = format!(
            "resume refused: {}",
            SessionLeaseError::Busy {
                session_id: "busy".into()
            }
        );
        let mut refused = false;
        let mut source: Option<SessionProjection> = None;
        let mut refusal_notice = false;
        while std::time::Instant::now() < deadline {
            if let Some(message) = bus.try_recv() {
                match message {
                    Msg::SessionProjection(view)
                        if matches!(&view.reason, ProjectionReason::Initial) =>
                    {
                        assert_eq!(view.binding.session_id, "session-test");
                        assert_eq!(view.binding.generation, 1);
                        assert_eq!(view.cost, CostQualification::UnknownHistory { revision: 0 });
                        source = Some(view);
                    }
                    Msg::Status(text) if text == expected_refusal => {
                        refusal_notice = true;
                    }
                    Msg::SessionProjection(view)
                        if refusal_notice && matches!(&view.reason, ProjectionReason::Refresh) =>
                    {
                        let source = source
                            .as_ref()
                            .expect("refusal follows the actual Initial view");
                        assert_eq!(view.binding, source.binding);
                        assert_eq!(
                            (&view.model, &view.provider),
                            (&source.model, &source.provider)
                        );
                        assert_eq!(view.lines, source.lines);
                        assert_eq!(
                            (
                                view.turns,
                                view.input_tokens,
                                view.output_tokens,
                                view.cost_microcents
                            ),
                            (
                                source.turns,
                                source.input_tokens,
                                source.output_tokens,
                                source.cost_microcents
                            )
                        );
                        assert_eq!(view.cost, source.cost);
                        assert_eq!(view.context, ContextProjection::Unavailable);
                        refused = true;
                        break;
                    }
                    Msg::BackendError(error) | Msg::BackendNotice(error) => {
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
        while let Some(message) = bus.try_recv() {
            if let Msg::BackendError(error) | Msg::BackendNotice(error) = message {
                panic!("idle rejection failed a provider turn: {error}");
            }
        }
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
        let initial = config(&home);
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
        let bad = bad
            .in_workspace(&crate::sessions::current_workspace().unwrap())
            .unwrap();
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
            initial,
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

    struct TestHome(std::path::PathBuf);

    impl TestHome {
        fn new() -> Self {
            let path =
                std::env::temp_dir().join(format!("orbit-tui-billing-{}", ulid::Ulid::new()));
            std::fs::create_dir(&path).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
            }
            Self(path)
        }
    }

    impl std::ops::Deref for TestHome {
        type Target = std::path::Path;

        fn deref(&self) -> &Self::Target {
            &self.0
        }
    }

    impl Drop for TestHome {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn duplicate_provider_config(first_url: &str, second_url: &str) -> String {
        format!(
            r#"
[[provider]]
name = "first"
url = "{first_url}"
[[provider.models]]
id = "shared-notools"
supported_efforts = ["low", "high"]
default_effort = "low"
[provider.models.billing]
version = 2
input_per_million_microdollars = 1000000
output_per_million_microdollars = 1000000
request_flat_microdollars = 10
reasoning_counter_basis = "included_in_output"
reasoning_rate_policy = "output_rate"
[[provider]]
name = "second"
url = "{second_url}"
[[provider.models]]
id = "shared-notools"
supported_efforts = ["medium"]
default_effort = "medium"
[provider.models.billing]
version = 2
input_per_million_microdollars = 2000000
output_per_million_microdollars = 3000000
request_flat_microdollars = 20
reasoning_counter_basis = "included_in_output"
reasoning_rate_policy = "output_rate"
"#
        )
    }

    struct MockProvider {
        endpoint: String,
        state: orbit_mock_provider::ServerState,
        stop: Option<tokio::sync::oneshot::Sender<()>>,
        thread: Option<std::thread::JoinHandle<()>>,
    }

    impl MockProvider {
        fn start() -> Self {
            let (ready_tx, ready_rx) = std::sync::mpsc::channel();
            let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
            let thread = std::thread::spawn(move || {
                let runtime = tokio::runtime::Runtime::new().unwrap();
                runtime.block_on(async move {
                    let (addr, state, server) = orbit_mock_provider::spawn().await.unwrap();
                    ready_tx.send((addr, state)).unwrap();
                    let _ = stop_rx.await;
                    server.abort();
                });
            });
            let (addr, state) = ready_rx.recv().unwrap();
            Self {
                endpoint: format!("http://{addr}"),
                state,
                stop: Some(stop_tx),
                thread: Some(thread),
            }
        }

        fn request_count(&self) -> u64 {
            use std::sync::atomic::Ordering;
            self.state.requests.load(Ordering::SeqCst)
        }

        fn last_request(&self) -> serde_json::Value {
            self.state.last_body.lock().unwrap().clone().unwrap()
        }
    }

    impl Drop for MockProvider {
        fn drop(&mut self) {
            if let Some(stop) = self.stop.take() {
                let _ = stop.send(());
            }
            if let Some(thread) = self.thread.take() {
                thread.join().unwrap();
            }
        }
    }

    #[test]
    fn saved_provider_owns_effort_and_billing_when_model_ids_overlap() {
        use orbit_adapter::types::EffortValue;
        let mock = MockProvider::start();
        let home = TestHome::new();
        std::fs::write(
            home.join("providers.toml"),
            duplicate_provider_config("http://127.0.0.1:1", &mock.endpoint),
        )
        .unwrap();
        let mut initial = config(&home);
        initial.model = "shared-notools".into();
        initial.provider_id = "first".into();
        initial.gate = "http://127.0.0.1:1".into();
        let saved = crate::sessions::SessionFile::from_chat(
            "owner",
            "shared-notools",
            &mock.endpoint,
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
        let saved = saved
            .in_workspace(&crate::sessions::current_workspace().unwrap())
            .unwrap();
        crate::sessions::save_session(&home, &saved).unwrap();
        let (bus, sender) = orbit_hud_tui::bus::Bus::new();
        let (commands, command_rx) = mpsc::channel();
        commands
            .send(WorkerCommand::ResumeSession("owner".into()))
            .unwrap();
        commands
            .send(WorkerCommand::Effort("default".into()))
            .unwrap();
        commands
            .send(WorkerCommand::Prompt("use the resumed provider".into()))
            .unwrap();
        drop(commands);
        worker_main(
            WorkerCtx {
                sender,
                approvals: ApprovalRegistry::new(),
                command_rx,
            },
            initial,
            Default::default(),
        );
        let after = crate::sessions::load_session(&home, "owner").unwrap();
        assert_eq!(after.provider, "second");
        assert_eq!(after.effort, Some(EffortSetting::Default));
        assert_eq!((after.input_tokens, after.output_tokens), (3, 2));
        assert_eq!(after.cost_microcents, 32);
        assert_eq!(mock.request_count(), 1);
        assert_eq!(mock.last_request()["model"], "shared-notools");
        let turn = configured_turn(&TuiTurnConfig {
            provider_id: after.provider,
            model: after.model,
            effort: after.effort,
            ..config(&home)
        })
        .unwrap();
        assert_eq!(turn.gate, mock.endpoint);
        assert_eq!(turn.effort, Some(EffortValue::Level("medium".into())));
        let billing = turn.billing.as_ref().unwrap();
        assert_eq!(billing.provider_id().0, "second");
        assert_eq!(billing.raw_model_id().0, "shared-notools");
        assert_eq!(
            billing.rates().input_per_million_microdollars,
            Some(2_000_000)
        );
        assert_eq!(billing.rates().request_flat_microdollars, Some(20));
        assert_eq!(
            billing.reasoning_counter_basis(),
            orbit_adapter::types::ReasoningCounterBasis::IncludedInOutput
        );
        assert_eq!(
            billing.reasoning_rate_policy(),
            orbit_adapter::types::ReasoningRatePolicy::OutputRate
        );
        drop(bus);
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
                Msg::BackendError(error) | Msg::BackendNotice(error) => {
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

#[cfg(all(test, unix))]
mod fresh_candidate_transcript_tests {
    use super::fresh_candidate_transcript;
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    struct TempHome(PathBuf);
    impl TempHome {
        fn new() -> Self {
            static SEQUENCE: AtomicU64 = AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "orbit-fresh-candidate-log-{}-{}",
                std::process::id(),
                SEQUENCE.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&path)
                .unwrap();
            Self(path)
        }
        fn projects(&self) -> PathBuf {
            let path = self.0.join("projects");
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&path)
                .unwrap();
            path
        }
    }
    impl Drop for TempHome {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).unwrap();
        }
    }

    #[test]
    fn a_fresh_fixed_candidate_id_creates_one_private_empty_log() {
        let home = TempHome::new();
        let id = "session-fresh-empty";
        let log = fresh_candidate_transcript(&home.0, id).unwrap();
        let expected = home.0.join("projects").join(format!("{id}.jsonl"));
        assert_eq!(log.path(), expected);
        let metadata = std::fs::symlink_metadata(&expected).unwrap();
        assert!(metadata.is_file());
        assert_eq!(metadata.len(), 0);
        assert_eq!(metadata.nlink(), 1);
        assert_eq!(metadata.mode() & 0o777, 0o600);
        assert!(log.events().is_empty());
        assert_eq!(
            std::fs::read_dir(home.0.join("projects")).unwrap().count(),
            1
        );
        drop(log);
    }

    #[test]
    fn an_existing_orphan_log_refuses_and_preserves_its_exact_bytes_and_identity() {
        use std::io::Write;
        let home = TempHome::new();
        let id = "session-existing-orphan";
        let path = home.projects().join(format!("{id}.jsonl"));
        let bytes = b"{\"kind\":\"note\",\"text\":\"orphan marker\"}\n";
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        file.write_all(bytes).unwrap();
        file.sync_all().unwrap();
        let before = std::fs::symlink_metadata(&path).unwrap();
        assert_eq!(
            fresh_candidate_transcript(&home.0, id).err(),
            Some("candidate transcript already exists or is unsafe")
        );
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
        let after = std::fs::symlink_metadata(&path).unwrap();
        assert_eq!(
            (after.dev(), after.ino(), after.nlink(), after.mode()),
            (before.dev(), before.ino(), before.nlink(), before.mode())
        );
        assert_eq!(
            std::fs::read_dir(home.0.join("projects")).unwrap().count(),
            1
        );
    }

    #[test]
    fn a_dangling_candidate_log_symlink_refuses_and_preserves_the_exact_link() {
        let home = TempHome::new();
        let id = "session-dangling-log";
        let path = home.projects().join(format!("{id}.jsonl"));
        let target = home.0.join("uncreated-target");
        std::os::unix::fs::symlink(&target, &path).unwrap();
        let before = std::fs::symlink_metadata(&path).unwrap();
        assert!(before.file_type().is_symlink());
        assert_eq!(
            fresh_candidate_transcript(&home.0, id).err(),
            Some("candidate transcript already exists or is unsafe")
        );
        assert_eq!(std::fs::read_link(&path).unwrap(), target);
        let after = std::fs::symlink_metadata(&path).unwrap();
        assert!(after.file_type().is_symlink());
        assert_eq!(
            (after.dev(), after.ino(), after.mode()),
            (before.dev(), before.ino(), before.mode())
        );
        assert_eq!(
            std::fs::symlink_metadata(&target).unwrap_err().kind(),
            std::io::ErrorKind::NotFound
        );
        assert_eq!(
            std::fs::read_dir(home.0.join("projects")).unwrap().count(),
            1
        );
    }
}
