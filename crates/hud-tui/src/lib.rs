//! ORBIT HUD-TUI — terminal user interface (DR-20).
//!
//! Fourth front-end alongside REPL | JSON | non-TTY | plain. Built on
//! `ratatui` + `crossterm`. The existing REPL is preserved — `cmd_chat`
//! forwards here only when TTY + `--tui` (on by default; `--no-tui` opts out).
//!
//! PR-A: skeleton with event bus, reducer, render, input, coalescer.
//! PR-B: backend bridge + display_safe + CoT stripping + transcript state.
//! PR-C: approval trait injection (in cli crate) + R grants.
//! PR-D: three-pane layout + worker thread that calls `run_turn`.

#![forbid(unsafe_code)]

pub mod approval;
pub mod bridge;
pub mod bus;
mod coalesce;
pub mod format;
pub mod glyphs;
pub mod input;
pub mod msg;
pub mod plain;
pub mod proto;
pub mod render;
mod rich;
pub mod secret_scan;
pub mod selection;
pub mod state;
mod terminal;
pub mod tokens;
pub mod unicode;
pub mod worker;

pub use approval::{ApprovalRegistry, ApprovalResponse};
pub use bridge::{
    emit_activity, emit_approval_detail, emit_compaction, emit_cost, emit_error, emit_file_changed,
    emit_ledger_appended, emit_mode_changed, emit_plan_ready, emit_readiness,
    emit_response_finished, emit_status, emit_subagent_finished, emit_subagent_progress,
    emit_subagent_started, emit_tasks, emit_text, emit_tool_finished, emit_tool_output,
    emit_tool_started, emit_turn_cost, emit_usage, emit_workspace, safe_text, safe_text_probe,
    sanitize_glyphs, strip_cot, terminal_safe, CotStripper,
};
pub use msg::ApprovalGrant;
pub use proto::shell::panes::tokens_short;
pub use state::RedactionKind;
pub use worker::{CommandSink, WorkerCommand, WorkerCtx, WorkerSpawner};

use crossterm::event::{self, Event, KeyEvent};
use input::{KeyAction, KeyParser};
use std::time::{Duration, Instant};

use crate::bus::{Bus, BusSender};
use crate::msg::Msg;
use crate::state::App;
use crate::tokens::Design;

/// The UI tick interval (16 ms ≈ 60 fps cap). Empty frames are forbidden —
/// we only redraw when `app.dirty.is_dirty()`.
const UI_TICK: Duration = Duration::from_millis(16);

/// Entry point — called by `cmd_chat` when TTY + `--tui`.
///
/// `worker_spawner` is provided by the CLI; it spawns the backend thread that
/// calls `run_turn` and feeds `Msg::TextDelta`/`Msg::ResponseFinished`/etc.
/// through the bus. The TUI's event loop drives input + render.
///
/// Returns an exit code (0 for normal quit). Terminal cleanup is guaranteed
/// by `TerminalGuard`'s `Drop` impl, even on panic.
pub fn run(args: &[String], worker_spawner: WorkerSpawner) -> i32 {
    let _ = args;

    // Load the user-customizable theme from $ORBIT_HOME/tui.toml (or default).
    let home = std::env::var("ORBIT_HOME")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::path::PathBuf::from(".orbit"));
    // Design context: palette resolved for the detected colour tier + display
    // capabilities, ONCE at startup (docs/tui/DESIGN.md §3.7). Tiers step
    // down at runtime, never up. Migration notices print once, then drop.
    let raw: crate::tokens::Theme = {
        // The new-schema load; a file written for the old schema parses with
        // deprecation keys intact (both live in one struct).
        let path = home.join("tui.toml");
        std::fs::read_to_string(&path)
            .ok()
            .and_then(|raw| toml::from_str(&raw).ok())
            .unwrap_or_default()
    };
    // Width probe (§11.3): runs BEFORE the alternate screen. The verdict
    // no longer demotes the WHOLE glyph set to ASCII — that turned every
    // pane border into + - | on terminals where one ambiguous glyph (●)
    // renders wide, gutting the design for everyone. Chrome is now pure
    // color (no line glyphs to demote); the verdict only retires the
    // handful of ambiguous-width content glyphs, per-glyph.
    let _probe_wide = terminal::probe_ambiguous_width();
    let design = Design::resolve(&raw, &|k| std::env::var(k).ok());
    for notice in &design.notices {
        eprintln!("orbit-tui: {notice}");
    }

    let mut guard = match terminal::TerminalGuard::enter() {
        Ok(g) => g,
        Err(e) => {
            eprintln!("orbit-tui: cannot enter terminal: {e}");
            return 1;
        }
    };

    let (bus, sender) = Bus::new();
    let approvals = ApprovalRegistry::new();
    let mut app = App::new();
    app.reduced_motion = design.caps.reduced_motion;
    app.bell_on_approval = design.caps.bell_on_approval;
    // Welcome readiness: computed here, never fixture data. Trust root
    // exists; ledger segment count is real; provider · model come from
    // the worker's config via env (the spawner closure runs later, so
    // read the same sources it will).
    app.readiness = crate::state::compute_readiness(&home);
    let mut key_parser = KeyParser::new();

    // Initial size from the terminal.
    if let Ok(size) = crossterm::terminal::size() {
        app.reduce(Msg::Resize(size.0, size.1));
    }

    // Build the worker-command channel — the worker owns the receiver, the
    // event loop holds the sender. Prompts AND /commands flow through this
    // typed channel, keeping the Bus single-consumer (the main loop reducer).
    let (cmd_tx, cmd_rx) = std::sync::mpsc::channel();
    let command_sink = cmd_tx.clone();

    // Spawn the worker thread (owns the backend pipeline). Errors are surfaced
    // via Msg::BackendError to the reducer.
    let spawn_ctx = worker::WorkerCtx {
        sender: sender.clone(),
        approvals: approvals.clone(),
        command_rx: cmd_rx,
    };
    let cancel_handle: worker::CancelHandle = match worker_spawner(spawn_ctx, cmd_tx) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("orbit-tui: worker spawn failed: {e}");
            std::sync::Arc::new(|| {})
        }
    };

    let result = event_loop(
        &mut guard,
        &bus,
        &sender,
        &approvals,
        &mut app,
        &mut key_parser,
        &command_sink,
        &cancel_handle,
        &design,
    );

    // Restore the terminal BEFORE printing anything — raw mode + alternate
    // screen would swallow or garble the message.
    drop(guard);
    match result {
        Ok(outcome) => {
            if let Some(note) = outcome.note {
                eprintln!("orbit-tui: {note}");
            }
            // §8.4: one line to the normal scrollback after the alt screen
            // is restored. Coloured only if colour is allowed (the plain
            // grammar tier prints the same text uncoloured).
            if let Some(st) = outcome.shutdown_stats {
                let cost = format!("${:.4}", st.cost_microcents as f64 / 1_000_000.0);
                println!("✦ ORBIT  session saved · {} turns · {cost}", st.turns);
                println!("         resume with orbit chat --resume {}", st.session_id);
            }
            outcome.exit_code
        }
        Err(e) => {
            eprintln!("orbit-tui: {e}");
            1
        }
    }
}

/// Outcome of the event loop: process exit code plus an optional shutdown
/// note. The note is printed only after the terminal is restored, so it
/// actually lands on the operator's screen (or the script's stderr).
struct LoopOutcome {
    exit_code: i32,
    note: Option<String>,
    /// §8.4 shutdown-line stats: turns, ledger records, cost, session id.
    shutdown_stats: Option<ShutdownStats>,
}

/// The §8.4 shutdown line's data.
#[derive(Debug, Clone)]
struct ShutdownStats {
    turns: u64,
    cost_microcents: u64,
    session_id: String,
}

/// Parse and dispatch a `/command` typed in the composer (REPL parity,
/// DR-21). Local commands reduce immediately; anything needing the worker
/// (model switch, model/session listing, session resume) goes through the
/// typed `CommandSink` and its result comes back as `Msg::SystemMessage` /
/// `Msg::TranscriptLoaded`.
fn handle_slash_command(cmd: &str, sender: &BusSender, command_sink: &CommandSink, app: &mut App) {
    let trimmed = cmd.trim();
    if trimmed.is_empty() {
        return;
    }
    // Newline / section separators (kept out of format strings so no
    // escaped literals lurk in the source).
    const NL: &str = "\n";
    const SEP: &str = "\n---\n\n";

    // Plain quit/exit (REPL parity — no leading slash needed).
    if trimmed == "quit" || trimmed == "exit" {
        app.reduce(Msg::RequestQuit);
        return;
    }

    // The full command may carry an argument (e.g. `/model glm-5.2`).
    let (name, arg) = match trimmed.split_once(char::is_whitespace) {
        Some((n, a)) => (n, a.trim()),
        None => (trimmed, ""),
    };

    match name {
        "/help" => {
            app.reduce(Msg::SystemMessage(
                "commands: exit, /help, /model <M>, /clear, /usage, /models, /sessions, /resume <id>, /cancel, /history, /compact, /undo, /queue, /status, /cost, /export, /mods, /mod <name> — ! <cmd> runs shell — keys: ↑/↓ history, Ctrl+U clear line, Ctrl+W del word, Shift+Enter newline, Tab complete, z y copy transcript"
                    .into(),
            ));
        }
        "/history" => {
            // The composer's own history, mirrored into a system message
            // (the event loop owns the composer; the reducer can't see it).
            let _ = app; // history lives in the composer, shown on ↑/↓
            app.reduce(Msg::SystemMessage(
                "input history: use ↑ / ↓ in the composer".into(),
            ));
        }
        "/clear" => {
            app.reduce(Msg::ClearTranscript);
        }
        "/usage" => {
            let (turns, input, output, cost) = (
                app.total_turns,
                app.total_input_tokens,
                app.total_output_tokens,
                app.total_cost_microcents,
            );
            app.reduce(Msg::SystemMessage(format!(
                "turns {turns} · in {input} · out {output} · ${}.{:06}",
                cost / 1_000_000,
                cost % 1_000_000
            )));
        }
        "/model" => {
            if arg.is_empty() {
                app.reduce(Msg::SystemMessage("usage: /model <model-id>".into()));
            } else {
                let _ = command_sink.send(WorkerCommand::SetModel(arg.to_string()));
            }
        }
        "/models" => {
            let _ = command_sink.send(WorkerCommand::ListModels);
        }
        "/sessions" => {
            let _ = command_sink.send(WorkerCommand::ListSessions);
        }
        "/resume" => {
            if arg.is_empty() {
                app.reduce(Msg::SystemMessage("usage: /resume <session-id>".into()));
            } else {
                let _ = command_sink.send(WorkerCommand::ResumeSession(arg.to_string()));
            }
        }
        "/cancel" => {
            if app.turn_in_flight {
                sender.send(Msg::CancelTurn);
            } else {
                app.reduce(Msg::SystemMessage("no turn in flight".into()));
            }
        }
        "/compact" => {
            let _ = command_sink.send(WorkerCommand::Compact);
        }
        "/undo" => {
            let _ = command_sink.send(WorkerCommand::Undo);
        }
        "/rewind" => {
            let _ = command_sink.send(WorkerCommand::Rewind(arg.to_string()));
        }
        "/permissions" => {
            // Persistent rules live in orbit-cli; route through the worker.
            let _ = command_sink.send(WorkerCommand::Permissions(arg.to_string()));
        }
        "/queue" => {
            // Claude Code parity: show / manage queued prompts.
            if arg == "clear" {
                let n = app.queued.len();
                app.queued.clear();
                app.reduce(Msg::SystemMessage(format!("cleared {n} queued prompt(s)")));
            } else if app.queued.is_empty() {
                app.reduce(Msg::SystemMessage("queue is empty".into()));
            } else {
                let snapshot: Vec<String> = app.queued.clone();
                for (i, q) in snapshot.iter().enumerate() {
                    app.reduce(Msg::SystemMessage(format!("queue[{}]: {}", i + 1, q)));
                }
            }
        }
        "/mods" => {
            if arg == "refresh" {
                let _ = command_sink.send(WorkerCommand::RefreshMods);
            } else {
                let _ = command_sink.send(WorkerCommand::ListInstalledMods);
            }
        }
        "/mod" => {
            if arg.is_empty() {
                app.reduce(Msg::SystemMessage("usage: /mod <name>".into()));
            } else {
                let _ = command_sink.send(WorkerCommand::ToggleMod(arg.to_string()));
            }
        }
        "/status" => {
            // Claude Code parity: a one-glance session summary.
            let conn = match app.connection {
                crate::state::ConnectionState::Online => "online",
                crate::state::ConnectionState::Reconnecting => "reconnecting",
                crate::state::ConnectionState::Offline => "offline",
            };
            let priced = if app.model_priced {
                "priced"
            } else {
                "unpriced"
            };
            app.reduce(Msg::SystemMessage(format!(
                "session {} · {} · model {} · {} · turns {} · in {} · out {} · ${:.4}",
                app.session_id,
                conn,
                app.model,
                priced,
                app.total_turns,
                app.total_input_tokens,
                app.total_output_tokens,
                app.total_cost_microcents as f64 / 1_000_000.0,
            )));
        }
        "/cost" => {
            // Claude Code parity: per-turn + cumulative cost view.
            let turn = app.turn_cost_microcents as f64 / 1_000_000.0;
            let total = app.total_cost_microcents as f64 / 1_000_000.0;
            let avg = if app.total_turns > 0 {
                total / app.total_turns as f64
            } else {
                0.0
            };
            if app.turn_in_flight {
                app.reduce(Msg::SystemMessage(format!(
                    "turn (running): ${turn:.4} · session total: ${total:.4} · avg/turn: ${avg:.4}"
                )));
            } else {
                app.reduce(Msg::SystemMessage(format!(
                    "session total: ${total:.4} · {} turns · avg: ${avg:.4}",
                    app.total_turns
                )));
            }
        }
        "/export" => {
            // Claude Code parity: dump the transcript to a file the operator
            // can keep. Default: markdown next to the session store.
            let home = std::env::var("ORBIT_HOME").unwrap_or_else(|_| ".orbit".to_string());
            let dir = std::path::Path::new(&home).join("exports");
            let _ = std::fs::create_dir_all(&dir);
            let fname = format!("{}.md", app.session_id);
            let path = dir.join(&fname);
            let body = app
                .transcript
                .iter()
                .map(|l| match l {
                    crate::state::TranscriptLine::User { text, .. } => {
                        ["## User", text.as_str(), ""].join(NL)
                    }
                    crate::state::TranscriptLine::Assistant { text, .. } => {
                        ["## Assistant", text.as_str(), ""].join(NL)
                    }
                    crate::state::TranscriptLine::System(t) => ["> ", t.as_str()].join(""),
                    _ => String::new(),
                })
                .collect::<Vec<_>>()
                .join(SEP);
            match std::fs::write(&path, body) {
                Ok(()) => app.reduce(Msg::SystemMessage(format!("exported → {}", path.display()))),
                Err(e) => app.reduce(Msg::SystemMessage(format!("export failed: {e}"))),
            }
        }
        "/quit" | "/exit" => {
            app.reduce(Msg::RequestQuit);
        }
        _ if trimmed.contains(':') && trimmed.starts_with('/') => {
            // Mod-contributed command: /<mod>:<cmd>
            let body = trimmed.trim_start_matches('/');
            match body.split_once(':') {
                Some((mod_name, cmd_name)) if !mod_name.is_empty() && !cmd_name.is_empty() => {
                    let _ = command_sink.send(WorkerCommand::ModCommand(
                        mod_name.to_string(),
                        cmd_name.to_string(),
                    ));
                }
                _ => {
                    app.reduce(Msg::SystemMessage(format!(
                        "unknown command: {trimmed}; try /help"
                    )));
                }
            }
        }
        _ => {
            app.reduce(Msg::SystemMessage(format!(
                "unknown command: {trimmed}; try /help"
            )));
        }
    }
}

/// The main event loop — polls crossterm events and UI ticks, reduces, renders.
/// Returns the process outcome (0 = interactive quit, 128+n = signal death).
#[allow(clippy::too_many_arguments)]
fn event_loop(
    guard: &mut terminal::TerminalGuard,
    bus: &Bus,
    sender: &BusSender,
    approvals: &ApprovalRegistry,
    app: &mut App,
    key_parser: &mut KeyParser,
    command_sink: &CommandSink,
    cancel_handle: &worker::CancelHandle,
    design: &Design,
) -> Result<LoopOutcome, String> {
    let mut last_tick = Instant::now();
    let mut composer = Composer::new();

    loop {
        // Terminal-loss / external termination: NONINTERACTIVE shutdown.
        // After a tab close the PTY is destroyed — nothing can be rendered
        // and no key will ever arrive, so a confirmation modal would orphan
        // the process. Deny pending approvals (releases a parked worker),
        // tear the UI down, and exit with the conventional 128+signum code.
        if let Some(sig) = terminal::take_pending_signal() {
            let denied = approvals.deny_all();
            app.reduce(Msg::SignalShutdown);
            let note = format!(
                "{} — shutting down (denied {denied} pending approval(s))",
                sig.name()
            );
            return Ok(LoopOutcome {
                shutdown_stats: None,
                exit_code: sig.exit_code(),
                note: Some(note),
            });
        }

        while let Some(msg) = bus.try_recv() {
            // A /command from the composer — parse and dispatch locally;
            // anything needing the worker goes through the typed channel.
            if let Msg::SlashCommand(cmd) = msg {
                handle_slash_command(&cmd, sender, command_sink, app);
                continue;
            }
            // Palette execution (§6.13): run the selected command. The
            // reducer already closed the palette; we read the selection
            // BEFORE reduce consumed it — so intercept here.
            if let Msg::PaletteExecute = msg {
                let (label, selected) = {
                    let sel = app.palette.selected;
                    let cmds = crate::state::filtered_commands(&app.palette.query);
                    let label = cmds.get(sel).map(|c| c.label.clone()).unwrap_or_default();
                    (label, sel)
                };
                app.reduce(Msg::PaletteExecute);
                match label.as_str() {
                    "new session" => app.reduce(Msg::KeyAction(KeyAction::NewSession)),
                    "copy transcript" => app.reduce(Msg::EnterCopyMode),
                    "sessions" => app.reduce(Msg::KeyAction(KeyAction::TabSessions)),
                    "activity" => app.reduce(Msg::KeyAction(KeyAction::TabVerbose)),
                    "workspace" => app.reduce(Msg::KeyAction(KeyAction::FocusRight)),
                    "conversation" => app.reduce(Msg::KeyAction(KeyAction::FocusCenter)),
                    "toggle tool detail" => app.reduce(Msg::KeyAction(KeyAction::ToggleToolDetail)),
                    "toggle cost" => app.reduce(Msg::KeyAction(KeyAction::ToggleCost)),
                    "quit" => app.reduce(Msg::RequestQuit),
                    _ => {
                        let _ = selected;
                    }
                }
                continue;
            }
            // Forward prompts to the worker ONLY when the reducer starts a
            // new turn (not when it queues). We detect this by snapshotting
            // turn_in_flight before reduce and checking it flipped to true.
            let was_in_flight = app.turn_in_flight;
            // Plan approval (Claude Code parity): while a plan is pending,
            // y approves (runs the plan as a normal turn), n discards.
            if let Msg::PlanApproved(plan) = msg {
                app.reduce(Msg::PlanApproved(plan.clone()));
                // Run the approved plan as a normal (non-plan) turn.
                app.transcript.push(crate::state::TranscriptLine::User {
                    text: format!("Execute this approved plan:\n{plan}"),
                    time: None,
                });
                let _ = command_sink.send(WorkerCommand::Prompt(format!(
                    "Execute this approved plan:\n{plan}"
                )));
                continue;
            }
            if let Msg::TextSubmitted(text) = msg {
                app.reduce(Msg::TextSubmitted(text.clone()));
                if !was_in_flight && app.turn_in_flight {
                    if app.plan_mode {
                        let _ = command_sink.send(WorkerCommand::PlanPrompt(text));
                    } else {
                        let _ = command_sink.send(WorkerCommand::Prompt(text));
                    }
                }
                continue;
            }
            // Cancel: fire the worker's CancelToken when the operator aborts.
            if let Msg::CancelTurn = msg {
                app.reduce(Msg::CancelTurn);
                (cancel_handle)();
                continue;
            }
            // After a turn ends, drain the queue: pop the next prompt and
            // forward it to the worker (the reducer already marked the new
            // turn in flight via take_next_queued).
            match msg {
                Msg::ResponseFinished {
                    output,
                    input_tokens,
                    output_tokens,
                    cost_microcents,
                } => {
                    app.reduce(Msg::ResponseFinished {
                        output,
                        input_tokens,
                        output_tokens,
                        cost_microcents,
                    });
                    if let Some(next) = app.take_next_queued() {
                        app.transcript.push(crate::state::TranscriptLine::User {
                            text: next.clone(),
                            time: None,
                        });
                        let _ = command_sink.send(WorkerCommand::Prompt(next));
                    }
                    continue;
                }
                Msg::BackendError(err) => {
                    app.reduce(Msg::BackendError(err));
                    if let Some(next) = app.take_next_queued() {
                        app.transcript.push(crate::state::TranscriptLine::User {
                            text: next.clone(),
                            time: None,
                        });
                        let _ = command_sink.send(WorkerCommand::Prompt(next));
                    }
                    continue;
                }
                _ => app.reduce(msg),
            }
        }

        // A finalized selection queued an OSC 52 clipboard write — emit it
        // once (the reducer can't touch stdout) and clear the pending slot.
        if let Some(seq) = app.osc52_pending.take() {
            use std::io::Write as _;
            let mut out = std::io::stdout();
            let _ = out.write_all(seq.as_bytes());
            let _ = out.flush();
        }

        // D17: a pending bell (approval arrived, tui.toml opt-in) — one
        // BEL byte, once, then cleared.
        if app.bell_pending {
            app.bell_pending = false;
            use std::io::Write as _;
            let mut out = std::io::stdout();
            let _ = out.write_all(b"\x07");
            let _ = out.flush();
        }

        // Copy mode: exit alt screen, print transcript, wait for key, re-enter.
        if app.copy_mode {
            app.copy_mode = false;
            app.dirty.clear();
            enter_copy_mode(guard, app)?;
            // After copy mode, force a full redraw.
            app.dirty.set(crate::state::DirtyFlags::LAYOUT);
            continue;
        }

        if app.dirty.is_dirty() {
            guard.draw(app, composer.text(), design)?;
            app.dirty.clear();
        }

        if app.should_quit {
            // Release any worker parked on an approval channel — otherwise
            // the thread is killed at process exit without appending the
            // ToolVerdict/ToolResult to the ledger (H3, fail-closed).
            let denied = approvals.deny_all();
            let note = if denied > 0 {
                Some(format!("denied {denied} pending approval(s)"))
            } else {
                None
            };
            return Ok(LoopOutcome {
                exit_code: 0,
                note,
                shutdown_stats: Some(ShutdownStats {
                    turns: app.total_turns,
                    cost_microcents: app.total_cost_microcents,
                    session_id: app.session_id.clone(),
                }),
            });
        }

        let timeout = UI_TICK
            .checked_sub(last_tick.elapsed())
            .unwrap_or(Duration::ZERO);

        if event::poll(timeout).map_err(|e| format!("poll: {e}"))? {
            match event::read().map_err(|e| format!("read: {e}"))? {
                Event::Key(key) => handle_key(
                    key,
                    sender,
                    &mut composer,
                    key_parser,
                    app,
                    approvals,
                    command_sink,
                ),
                Event::Paste(text) => {
                    // D12: bracketed paste — the whole block lands in the
                    // composer as one edit. Newlines are preserved (the
                    // operator pastes code, logs, heredocs); nothing is
                    // auto-submitted. Sanitize control chars that terminals
                    // can smuggle inside a paste (ESC, CSI leaders) — the
                    // paste is data, never key bindings.
                    //
                    // A paste is unambiguous intent to type: it lands from
                    // ANY focus and ANY mode (Normal, palette open, workspace
                    // pane). Pasting while in Normal mode re-enters Insert
                    // and focuses the composer — silently dropping the paste
                    // (the old behaviour) reads as "paste is broken".
                    let clean: String = text
                        .chars()
                        .filter(|c| !c.is_control() || *c == '\n' || *c == '\r' || *c == '\t')
                        .collect();
                    if !clean.is_empty() {
                        if app.focus != crate::state::Focus::Center {
                            sender.send(Msg::KeyAction(KeyAction::FocusCenter));
                        }
                        if app.input_mode != crate::state::InputMode::Insert {
                            sender.send(Msg::KeyAction(KeyAction::EnterInsert));
                        }
                        composer.push_block(&clean);
                        sender.send(Msg::ComposerChanged);
                        sender.send(Msg::ComposerTextChanged(composer.text().to_string()));
                    }
                }
                Event::Mouse(me) => {
                    handle_mouse(me, sender, app);
                }
                Event::Resize(w, h) => sender.send(Msg::Resize(w, h)),
                _ => {}
            }
        }

        if last_tick.elapsed() >= UI_TICK {
            sender.send(Msg::Tick);
            last_tick = Instant::now();
        }
    }
}

/// Current wall-clock time as HH:MM for the plain grammar's line stamps.
fn hhmm_now() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let (h, m) = ((secs / 3600) % 24, (secs / 60) % 60);
    format!("{h:02}:{m:02}")
}

/// Enter copy mode: temporarily exit the alt screen, print the transcript as
/// plain text (no borders, no panes, no ANSI), wait for any key, then re-enter.
/// The operator can select and copy individual lines with the terminal's
/// native text selection.
fn enter_copy_mode(guard: &mut terminal::TerminalGuard, app: &App) -> Result<(), String> {
    use crossterm::cursor::{Hide, Show};
    use crossterm::event::{
        DisableBracketedPaste, DisableMouseCapture, EnableBracketedPaste, EnableMouseCapture,
    };
    use crossterm::execute;
    use crossterm::terminal::{disable_raw_mode, enable_raw_mode};
    use crossterm::terminal::{EnterAlternateScreen, LeaveAlternateScreen};

    // Exit alt screen + raw mode.
    disable_raw_mode().map_err(|e| format!("disable_raw_mode: {e}"))?;
    execute!(
        std::io::stdout(),
        Show,
        DisableMouseCapture,
        DisableBracketedPaste,
        LeaveAlternateScreen
    )
    .map_err(|e| format!("leave alt screen: {e}"))?;

    // Instructions FIRST — everything below this point is pure transcript
    // text, so a drag-selection captures only message content (no prefixes,
    // no footer, no box art inside the selection region).
    println!();
    println!("  copy mode — select the text below, copy, then press any key");
    println!("  ────────────────────────────────────────────────────────────");
    println!();
    use std::io::Write;
    let _ = std::io::stdout().flush();

    // The shared plain grammar (§11.4): one event per line, words not
    // glyphs, a timestamp on each line. Same module the REPL and non-TTY
    // output use, so the surfaces cannot drift.
    let now = hhmm_now();
    let lines = crate::plain::transcript_lines(app, &now);
    let mut plain = lines.join("\n");
    if !plain.is_empty() {
        plain.push('\n');
    }
    // Nothing after the transcript — selection to end-of-output is clean.
    print!("{plain}");
    let _ = std::io::stdout().flush();

    // Wait for any key.
    let _ = event::read();

    // Re-enter alt screen + raw mode.
    enable_raw_mode().map_err(|e| format!("enable_raw_mode: {e}"))?;
    // Mouse capture (SGR mode): the app owns the mouse so selection can
    // be per-pane (the host terminal's native selection grabs across
    // pane borders — it doesn't know they exist).
    // Bracketed paste must be RE-ENABLED — the copy-mode teardown disabled
    // it, and the host terminal only sends paste sequences while the mode
    // is on. Missing this was the "paste stops working after /copy" bug.
    execute!(
        std::io::stdout(),
        EnterAlternateScreen,
        Hide,
        EnableMouseCapture,
        EnableBracketedPaste
    )
    .map_err(|e| format!("enter alt screen: {e}"))?;

    // Force the terminal to redraw.
    let _ = guard.terminal.clear();

    Ok(())
}
/// `Enter` sends; `Shift+Enter` inserts a newline.
/// Input history (Claude Code QOL): ↑/↓ walk previously-submitted prompts;
/// the in-progress draft is stashed while browsing and restored on ↓-past-end.
#[derive(Debug, Default)]
pub struct Composer {
    text: String,
    history: Vec<String>,
    /// Index into history while browsing (None = not browsing).
    history_pos: Option<usize>,
    /// The draft being edited when ↑ first entered history.
    draft: String,
    /// A draft cleared by Esc/Ctrl+C — restorable by one more Esc.
    cleared_stash: String,
}

impl Composer {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn text(&self) -> &str {
        &self.text
    }
    /// Replace the whole draft (Tab completion writes here).
    pub fn text_mut(&mut self) -> &mut String {
        &mut self.text
    }
    /// Set the draft to an exact string (hint acceptance).
    pub fn set_text(&mut self, s: &str) {
        self.text.clear();
        self.text.push_str(s);
    }
    pub fn push(&mut self, ch: char) {
        self.text.push(ch);
    }
    pub fn pop(&mut self) -> Option<char> {
        self.text.pop()
    }
    pub fn newline(&mut self) {
        self.text.push('\n');
    }
    /// Record the line being submitted into history (dedup vs the previous
    /// entry — resubmitting `r` must not stack duplicates).
    pub fn history_record(&mut self, line: &str) {
        if line.is_empty() {
            return;
        }
        if self.history.last().map(String::as_str) != Some(line) {
            self.history.push(line.to_string());
        }
        self.history_pos = None;
        self.draft.clear();
    }
    /// ↑ — step to the previous (older) history entry. True if the text
    /// changed (a redraw is needed).
    pub fn history_prev(&mut self) -> bool {
        if self.history.is_empty() {
            return false;
        }
        let pos = match self.history_pos {
            None => {
                self.draft = self.text.clone();
                self.history.len() - 1
            }
            Some(0) => return false, // already at the oldest entry
            Some(p) => p - 1,
        };
        self.history_pos = Some(pos);
        self.text = self.history[pos].clone();
        true
    }
    /// ↓ — step to the next (newer) entry; past the end restores the draft.
    pub fn history_next(&mut self) -> bool {
        let Some(mut pos) = self.history_pos else {
            return false;
        };
        if pos + 1 < self.history.len() {
            pos += 1;
            self.history_pos = Some(pos);
            self.text = self.history[pos].clone();
        } else {
            // Past the newest → back to the stashed draft.
            self.history_pos = None;
            self.text = self.draft.clone();
        }
        true
    }
    /// D12: bracketed-paste insertion. The whole block lands as one edit
    /// (one undo unit, one ComposerChanged); CRLF/CR newlines normalize
    /// to LF so pasted Windows text doesn't render stray glyphs.
    pub fn push_block(&mut self, block: &str) {
        if !block.is_empty() {
            self.text
                .push_str(&block.replace("\r\n", "\n").replace('\r', "\n"));
        }
    }
    pub fn backspace_word(&mut self) {
        // Naive: pop until whitespace.
        while let Some(c) = self.text.pop() {
            if c.is_whitespace() {
                break;
            }
        }
    }
    pub fn clear(&mut self) {
        self.text.clear();
    }
    /// Clear but stash the draft — one Esc restores it (undo-clear).
    pub fn clear_stash(&mut self) {
        self.cleared_stash = std::mem::take(&mut self.text);
        self.history_pos = None;
    }
    /// Restore a stashed (just-cleared) draft. None if nothing to restore.
    pub fn take_cleared(&mut self) -> Option<String> {
        let stash = std::mem::take(&mut self.cleared_stash);
        if stash.is_empty() {
            None
        } else {
            self.text = stash.clone();
            Some(stash)
        }
    }
    pub fn take(&mut self) -> String {
        self.history_pos = None;
        self.draft.clear();
        std::mem::take(&mut self.text)
    }
}

/// Slash-command registry for Tab completion + the palette.
/// Slash-command registry with descriptions — drives Tab completion AND
/// the live hint dropdown (Claude Code parity).
pub const SLASH_COMMANDS: &[(&str, &str)] = &[
    ("/help", "list commands and keys"),
    ("/model", "switch the active model"),
    ("/models", "list models from configured providers"),
    ("/clear", "clear the transcript view"),
    ("/usage", "session token/cost usage"),
    ("/sessions", "list saved sessions"),
    ("/resume", "resume a saved session"),
    ("/cancel", "cancel the in-flight turn"),
    ("/history", "input history (use arrow keys)"),
    ("/compact", "summarize + shrink the context window"),
    ("/undo", "rewind the last exchange"),
    ("/rewind", "restore code/conversation to a checkpoint"),
    ("/queue", "show/clear queued prompts"),
    ("/status", "session/model/connection snapshot"),
    ("/cost", "per-turn and cumulative cost"),
    ("/export", "export transcript to markdown"),
    ("/permissions", "view or set persistent tool rules"),
    ("/mods", "list installed mods (or refresh)"),
    ("/mod", "toggle a mod by name"),
    ("/quit", "exit ORBIT"),
    ("/exit", "exit ORBIT"),
];

/// Plain-name list (Tab completion keeps its old shape).
pub const SLASH_NAMES: &[&str] = &[
    "/help",
    "/model",
    "/models",
    "/clear",
    "/usage",
    "/sessions",
    "/resume",
    "/cancel",
    "/history",
    "/compact",
    "/undo",
    "/rewind",
    "/queue",
    "/status",
    "/cost",
    "/export",
    "/permissions",
    "/mods",
    "/mod",
    "/quit",
    "/exit",
];

/// Tab completion for the composer (Claude Code QOL):
/// - A lone `/word` prefix completes against SLASH_COMMANDS.
/// - Otherwise the last word is treated as a file path and completed
///   against the filesystem (relative to cwd).
///
/// Returns the full replacement text, or None when nothing matches.
fn complete_composer(text: &str) -> Option<String> {
    let (head, tail) = match text.rfind(char::is_whitespace) {
        Some(i) => (&text[..=i], &text[i + 1..]),
        None => ("", text),
    };
    // Slash command completion only when the command is the whole input.
    if head.is_empty() && tail.starts_with('/') {
        let matches: Vec<&str> = SLASH_NAMES
            .iter()
            .copied()
            .filter(|c| c.starts_with(tail))
            .collect();
        return match matches.as_slice() {
            [] => None,
            [only] => Some(format!("{only} ")),
            // Multiple: complete to the shared prefix.
            many => {
                let mut prefix = many[0].to_string();
                for c in &many[1..] {
                    let shared = prefix
                        .chars()
                        .zip(c.chars())
                        .take_while(|(a, b)| a == b)
                        .map(|(a, _)| a)
                        .collect::<String>();
                    prefix = shared;
                }
                if prefix.len() > tail.len() {
                    Some(prefix)
                } else {
                    None
                }
            }
        };
    }
    // File-path completion: only when the fragment looks path-y (contains
    // / or . or starts with ~). Avoids hijacking ordinary words.
    if !(tail.contains('/') || tail.starts_with('.') || tail.starts_with('~')) {
        return None;
    }
    let expanded = if let Some(rest) = tail.strip_prefix("~/") {
        let home = std::env::var("HOME").unwrap_or_default();
        format!("{home}/{rest}")
    } else {
        tail.to_string()
    };
    let (dir_part, file_part) = match expanded.rfind('/') {
        Some(i) => (expanded[..=i].to_string(), &expanded[i + 1..]),
        None => (String::from("./"), expanded.as_str()),
    };
    let dir = std::path::Path::new(&dir_part);
    let mut best: Option<String> = None;
    let mut multi = false;
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.starts_with(file_part) {
                let full = if entry.path().is_dir() {
                    format!("{dir_part}{name}/")
                } else {
                    format!("{dir_part}{name}")
                };
                match best.take() {
                    None => best = Some(full),
                    Some(prev) => {
                        let shared: String = prev
                            .chars()
                            .zip(full.chars())
                            .take_while(|(a, b)| a == b)
                            .map(|(a, _)| a)
                            .collect();
                        best = Some(shared);
                        multi = true;
                    }
                }
            }
        }
    }
    // A directory completion (trailing /) is always useful; a bare shared
    // prefix only when it extends the fragment.
    match best {
        Some(b) if b.len() > tail.len() => Some(format!("{head}{b}")),
        Some(b) if b.ends_with('/') => Some(format!("{head}{b}")),
        _ if multi => None,
        _ => None,
    }
}

/// `! <cmd>` shell passthrough (Claude Code QOL): run the command with
/// the shell, capture output, and append it to the transcript as a system
/// block. The TUI stays live — output arrives after the process exits
/// (long runners should be backgrounded by the operator).
fn run_shell_passthrough(cmd: &str, sender: &BusSender) {
    let cmd = cmd.trim();
    if cmd.is_empty() {
        sender.send(Msg::SystemMessage("usage: ! <shell command>".into()));
        return;
    }
    sender.send(Msg::SystemMessage(format!("$ {cmd}")));
    // Run OFF the input thread: the UI stays live while the command
    // works, and the result lands on the bus when it exits. (The old
    // blocking .output() here froze every keypress until it returned.)
    let sender2 = sender.clone();
    let cmd2 = cmd.to_string();
    std::thread::Builder::new()
        .name("orbit-shell-passthrough".into())
        .spawn(move || {
            let out = std::process::Command::new("sh")
                .arg("-c")
                .arg(&cmd2)
                .output();
            match out {
                Ok(o) => {
                    let code = o.status.code().unwrap_or(-1);
                    let stdout = String::from_utf8_lossy(&o.stdout).trim_end().to_string();
                    let stderr = String::from_utf8_lossy(&o.stderr).trim_end().to_string();
                    let mut block = stdout;
                    if !stderr.is_empty() {
                        if !block.is_empty() {
                            block.push_str("  //  ");
                        }
                        block.push_str(&stderr);
                    }
                    if block.is_empty() {
                        block = format!("(no output, exit {code})");
                    }
                    // Cap the block — a `find /` dump must not flood the transcript.
                    const MAX: usize = 4000;
                    let mut display = block;
                    if display.chars().count() > MAX {
                        let cut: String = display.chars().take(MAX).collect();
                        let total = display.chars().count();
                        display = format!("{cut}… (+{} chars)", total - MAX);
                    }
                    sender2.send(Msg::SystemMessage(display));
                    if code != 0 {
                        sender2.send(Msg::SystemMessage(format!("exit {code}")));
                    }
                }
                Err(e) => {
                    sender2.send(Msg::SystemMessage(format!("shell failed: {e}")));
                }
            }
        })
        .ok();
}

/// Expand `@path` mentions in a prompt into inline file contents
/// (Claude Code `@`-mention parity). Each mention becomes:
///   @path
///   ```<lang>
///   <contents, capped at 10_000 chars>
///   ```
/// Paths that don't read leave the mention untouched — the model (and the
/// operator) sees the dangling reference rather than silent nothing.
/// Deny-read list: paths whose contents must NEVER enter a prompt or a
/// provider request, regardless of tool or permission (Claude Code has
/// no such default; ORBIT's credential promise requires one).
pub fn deny_read_reason(path: &str) -> Option<String> {
    let home = std::env::var("HOME").unwrap_or_default();
    let p = path.trim_start_matches(&format!("{home}/"));
    let base = std::path::Path::new(p)
        .file_name()
        .and_then(|f| f.to_str())
        .unwrap_or("");
    let deny_prefixes = [".ssh/", ".aws/", ".gnupg/", ".netrc"];
    let env_like = base.starts_with(".env") || base == "credentials";
    if deny_prefixes.iter().any(|d| p.starts_with(d)) || env_like {
        return Some("credential path is on the deny-read list".into());
    }
    if p.contains("trust/") && p.contains(".orbit") {
        return Some("trust material is never read".into());
    }
    None
}

/// Value-based secret scan of a file's CONTENTS (not its name): refuse
/// expansion when the file carries a private key block or a high-entropy
/// token. Keyword rejection blanked ordinary code; this looks for key
/// SHAPES.
pub fn secret_scan_reason_path(path: &str) -> Option<String> {
    let Ok(body) = std::fs::read_to_string(path) else {
        return None; // unreadable files stay as dangling mentions
    };
    crate::secret_scan::scan_text(&body)
}

fn expand_file_mentions(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find('@') {
        let (before, after) = rest.split_at(at);
        out.push_str(before);
        let candidate: String = after[1..]
            .chars()
            .take_while(|c| !c.is_whitespace() && *c != '@')
            .collect();
        if candidate.is_empty() {
            out.push('@');
            rest = &after[1..];
            continue;
        }
        let path_txt = candidate
            .strip_prefix("~/")
            .map(|r| {
                std::env::var("HOME")
                    .map(|h| format!("{h}/{r}"))
                    .unwrap_or(candidate.clone())
            })
            .unwrap_or_else(|| candidate.clone());
        // Credential guard: the deny-read list every @mention must pass
        // before its bytes enter a prompt. ORBIT's promise is that
        // credentials never reach a provider — the mention itself stays
        // visible (dangling, with the reason) so the operator sees why.
        if let Some(reason) = deny_read_reason(&path_txt) {
            out.push('@');
            out.push_str(&candidate);
            out.push_str(&format!(" [refused: {reason}]"));
        } else if let Some(reason) = secret_scan_reason_path(&path_txt) {
            out.push('@');
            out.push_str(&candidate);
            out.push_str(&format!(" [refused: {reason}]"));
        } else {
            match std::fs::read_to_string(&path_txt) {
                Ok(mut body) => {
                    const MAX: usize = 10_000;
                    if body.chars().count() > MAX {
                        let cut: String = body.chars().take(MAX).collect();
                        let total = body.chars().count();
                        body = format!("{cut}\u{2026} (+{} chars truncated)", total - MAX);
                    }
                    let lang = std::path::Path::new(&path_txt)
                        .extension()
                        .and_then(|e| e.to_str())
                        .unwrap_or("");
                    let mut block = String::new();
                    block.push('@');
                    block.push_str(&candidate);
                    block.push_str("\n```");
                    block.push_str(lang);
                    block.push('\n');
                    block.push_str(body.trim_end());
                    block.push_str("\n```");
                    out.push_str(&block);
                }
                Err(_) => {
                    out.push('@');
                    out.push_str(&candidate);
                }
            }
        }
        let consumed = 1 + candidate.chars().count();
        let skip: usize = after
            .char_indices()
            .nth(consumed)
            .map(|(i, _)| i)
            .unwrap_or(after.len());
        rest = &after[skip..];
    }
    out.push_str(rest);
    out
}

/// True if a character key should go into the composer (not the key parser):
/// - It's a plain character (no Ctrl/Alt modifier)
/// - There's no pending approval (or the char isn't y/n/R, which are approval
///   shortcuts)
fn composer_wants_char(key: &KeyEvent, app: &App) -> bool {
    use crossterm::event::{KeyCode, KeyModifiers};
    if !matches!(key.code, KeyCode::Char(_)) {
        return false;
    }
    if key.modifiers.contains(KeyModifiers::CONTROL) || key.modifiers.contains(KeyModifiers::ALT) {
        return false;
    }
    // If an approval is pending, y/n/R/Esc are approval shortcuts.
    if !app.pending_approvals.is_empty() {
        if let KeyCode::Char(c) = key.code {
            if matches!(c, 'y' | 'Y' | 'n' | 'N' | 'r' | 'R') {
                return false;
            }
        }
    }
    true
}

/// Convert a crossterm key event into a `Msg`, approval response, or composer
/// mutation. Approval responses resolve the first pending approval.
/// Mouse handling (per-pane selection, herdr-style):
///   - Down in a pane's content → anchor a selection there
///   - Drag → extend (clamped to the pane)
///   - Up → finalize + OSC 52 copy
///   - Any click/key clears a Done selection first
///
/// Clicks on borders/gaps hit no pane and are ignored — the borders are
/// the isolation boundary.
fn handle_mouse(me: crossterm::event::MouseEvent, sender: &BusSender, app: &App) {
    use crossterm::event::MouseEventKind;

    let rects = &app.pane_rects;
    let hit = crate::selection::hit_test(
        me.row,
        me.column,
        rects.left.get(),
        rects.center.get().unwrap_or_default(),
        rects.right.get(),
    );

    // Shift+Click: bypass app selection — the host terminal's native
    // selection takes over (the universal terminal convention: Shift
    // suspends mouse reporting for that gesture). This is the escape
    // hatch for whole-screen selection when the operator wants it.
    if me.modifiers.contains(crossterm::event::KeyModifiers::SHIFT) {
        return;
    }

    match me.kind {
        MouseEventKind::Down(crossterm::event::MouseButton::Left) => {
            // A click clears any existing selection.
            sender.send(Msg::SelectionClear);
            // Click-to-focus (herdr-style): a click inside a pane's content
            // focuses that pane first — the pane boundary is the isolation
            // boundary, and the click tells the operator where focus went.
            if let Some((pane, row, col)) = hit {
                sender.send(Msg::KeyAction(crate::input::KeyAction::FocusSet(pane)));
                sender.send(Msg::SelectionAnchor { pane, row, col });
            }
        }
        MouseEventKind::Drag(crossterm::event::MouseButton::Left) => {
            if let Some((pane, row, col)) = hit {
                sender.send(Msg::SelectionExtend { pane, row, col });
            }
        }
        MouseEventKind::Up(crossterm::event::MouseButton::Left) => {
            sender.send(Msg::SelectionFinish);
        }
        // Scroll wheel: per-pane scroll (functional isolation).
        MouseEventKind::ScrollUp => {
            if let Some((pane, _, _)) = hit {
                sender.send(Msg::PaneScroll { pane, delta: -3 });
            }
        }
        MouseEventKind::ScrollDown => {
            if let Some((pane, _, _)) = hit {
                sender.send(Msg::PaneScroll { pane, delta: 3 });
            }
        }
        _ => {}
    }
}

fn handle_key_clears_selection(sender: &BusSender, app: &App) {
    // Any keypress dismisses a finished selection (herdr behaviour).
    if app.selection.is_some() {
        sender.send(Msg::SelectionClear);
    }
}

fn handle_key(
    key: KeyEvent,
    sender: &BusSender,
    composer: &mut Composer,
    key_parser: &mut KeyParser,
    app: &App,
    approvals: &ApprovalRegistry,
    command_sink: &CommandSink,
) {
    // Any keypress dismisses a finished selection (herdr behaviour).
    handle_key_clears_selection(sender, app);
    // §8.3: any key during the splash jumps to the final frame.
    if app.logo_phase == crate::state::LogoPhase::Splash {
        sender.send(Msg::SplashSkip);
    }
    // §6.12: any key dismisses the toast.
    if app.toast.is_some() {
        sender.send(Msg::ToastDismiss);
    }
    // §6.16: any key closes the help overlay (except the toggle itself,
    // which flips it closed anyway).
    if app.help_open {
        sender.send(Msg::HelpToggle);
    }

    // Plan approval keys (Claude Code parity): while a plan is pending,
    // y approves it (the event loop runs it as a normal turn), n
    // discards. Handled before all other input so the operator can't
    // type past the decision point.
    if let Some(plan) = app.pending_plan.clone() {
        match key.code {
            KeyCode::Char('y') | KeyCode::Char('Y') => {
                sender.send(Msg::PlanApproved(plan));
                return;
            }
            KeyCode::Char('n') | KeyCode::Char('N') => {
                sender.send(Msg::PlanDiscarded);
                return;
            }
            _ => {}
        }
    }

    // Command palette (§6.13): when open, ALL keys route to the palette —
    // chars build the query, ↑↓ move, enter executes, esc closes.
    if app.palette.open {
        match key.code {
            KeyCode::Esc => sender.send(Msg::PaletteToggle),
            KeyCode::Up => sender.send(Msg::PaletteMove(false)),
            KeyCode::Down => sender.send(Msg::PaletteMove(true)),
            KeyCode::Enter => sender.send(Msg::PaletteExecute),
            KeyCode::Backspace => sender.send(Msg::PaletteBackspace),
            KeyCode::Char(c) => sender.send(Msg::PaletteChar(c)),
            _ => {}
        }
        return;
    }

    use crossterm::event::{KeyCode, KeyModifiers};

    // Ctrl+C (Claude Code semantics, layered by what's in front of the
    // operator): approvals pending → deny all; turn streaming → cancel it;
    // composer has text → clear the draft (one press, no modal); otherwise
    // a status hint — a second press within 2 s quits. No blocking modal:
    // the operator can always select+copy text from the terminal.
    if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
        if !app.pending_approvals.is_empty() {
            let denied = approvals.deny_all();
            sender.send(Msg::ApprovalsDenied);
            if denied > 0 {
                sender.send(Msg::SystemMessage(format!(
                    "denied {denied} pending approval(s)"
                )));
            }
        } else if app.turn_in_flight && app.tool_state != crate::state::ToolState::AwaitingApproval
        {
            sender.send(Msg::CancelTurn);
        } else if !composer.text().is_empty() {
            composer.clear_stash();
            sender.send(Msg::ComposerChanged);
            sender.send(Msg::ComposerTextChanged(composer.text().to_string()));
            sender.send(Msg::SystemMessage("input cleared (Esc restores)".into()));
        } else {
            sender.send(Msg::CtrlC);
        }
        return;
    }

    // Ctrl+D (EOF) → request quit with confirmation.
    if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('d') {
        sender.send(Msg::RequestQuit);
        return;
    }

    // Ctrl+B → prefix mode (herdr/tmux-style modal dispatch): the next
    // key is a command, not composer text. Esc cancels.
    if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('b') {
        sender.send(Msg::InputModeChanged(crate::state::InputMode::Prefix));
        return;
    }

    // ── Prefix mode: the next key is a command (herdr ClientShellMode::Prefix) ──
    if app.input_mode == crate::state::InputMode::Prefix {
        let return_mode = if app.input_mode == crate::state::InputMode::Copy {
            crate::state::InputMode::Copy
        } else {
            crate::state::InputMode::Insert
        };
        match key.code {
            KeyCode::Esc => {
                sender.send(Msg::InputModeChanged(return_mode));
                return;
            }
            // Prefix commands: pane management (herdr's core).
            KeyCode::Char('z') => {
                sender.send(Msg::InputModeChanged(return_mode));
                sender.send(Msg::ZoomToggle(app.focus));
                return;
            }
            KeyCode::Char('o') => {
                // cycle panes
                sender.send(Msg::InputModeChanged(return_mode));
                sender.send(Msg::KeyAction(KeyAction::FocusNext));
                return;
            }
            KeyCode::Char('1') => {
                sender.send(Msg::InputModeChanged(return_mode));
                sender.send(Msg::KeyAction(KeyAction::FocusLeft));
                return;
            }
            KeyCode::Char('2') => {
                sender.send(Msg::InputModeChanged(return_mode));
                sender.send(Msg::KeyAction(KeyAction::FocusCenter));
                return;
            }
            KeyCode::Char('3') => {
                sender.send(Msg::InputModeChanged(return_mode));
                sender.send(Msg::KeyAction(KeyAction::FocusRight));
                return;
            }
            KeyCode::Char('[') => {
                // enter copy mode (tmux heritage)
                sender.send(Msg::InputModeChanged(crate::state::InputMode::Copy));
                return;
            }
            _ => {
                // Unknown prefix key: cancel back.
                sender.send(Msg::InputModeChanged(return_mode));
                return;
            }
        }
    }

    // ── Copy mode: j/k move, v select, y yank, Esc exits (herdr-style) ──
    if app.input_mode == crate::state::InputMode::Copy {
        match key.code {
            KeyCode::Esc => {
                sender.send(Msg::ExitCopyMode);
                return;
            }
            KeyCode::Char('j') | KeyCode::Down => {
                sender.send(Msg::CopyMove(1));
                return;
            }
            KeyCode::Char('k') | KeyCode::Up => {
                sender.send(Msg::CopyMove(-1));
                return;
            }
            KeyCode::Char('v') => {
                sender.send(Msg::CopySelect);
                return;
            }
            KeyCode::Char('y') => {
                sender.send(Msg::CopyYank);
                return;
            }
            _ => return, // copy mode swallows everything else
        }
    }

    // ── Approval modal captures input (DR-21 L18) ─────────────────────────
    // While an approval is pending the sheet is the ONLY interactive surface:
    // y/n/R answer it, Esc denies, everything else is swallowed. This must
    // run BEFORE the composer branch — focus defaults to Center, so `y`
    // would otherwise be typed into the composer and never reach the modal.
    if !app.pending_approvals.is_empty() {
        let first = &app.pending_approvals[0];
        let call_id = first.call_id.clone();
        let tool_name = first.tool_name.clone();
        if let KeyCode::Char(c) = key.code {
            match c {
                // D3 (§11.5 rule 4): the key handler ONLY resolves the
                // approval through the registry — it never sends
                // ToolCallFinished itself. The line's final state comes
                // from the worker's emit_tool_finished, which fires after
                // the tool actually runs (or is denied). Reporting ok:true
                // before execution would lie to the transcript; ok:false
                // would record an operator denial as a tool error.
                'y' | 'Y' => {
                    approvals.resolve(&call_id, ApprovalResponse::Allow);
                    sender.send(Msg::ApprovalDecision {
                        tool: tool_name,
                        decision: crate::state::ApprovalDecision::Once,
                    });
                    return;
                }
                'n' | 'N' => {
                    approvals.resolve(&call_id, ApprovalResponse::Deny);
                    sender.send(Msg::ApprovalDecision {
                        tool: tool_name,
                        decision: crate::state::ApprovalDecision::Denied,
                    });
                    return;
                }
                // Session grant is `R` only; bare `r` is swallowed by the
                // modal (no accidental session-wide grants). Terminals
                // deliver Shift+R as Char('R') — case is the distinction.
                'R' => {
                    approvals.resolve(&call_id, ApprovalResponse::AllowSession);
                    sender.send(Msg::ApprovalDecision {
                        tool: tool_name,
                        decision: crate::state::ApprovalDecision::Session,
                    });
                    return;
                }
                _ => {}
            }
        }
        if matches!(key.code, KeyCode::Esc) {
            approvals.resolve(&call_id, ApprovalResponse::Deny);
            sender.send(Msg::ApprovalDecision {
                tool: tool_name,
                decision: crate::state::ApprovalDecision::Denied,
            });
        }
        // Any other key is consumed by the modal.
        return;
    }

    // If quit confirmation modal is showing, intercept y/n/Esc.
    if app.quit_confirmation {
        if let KeyCode::Char(c) = key.code {
            match c {
                'y' | 'Y' => {
                    sender.send(Msg::ConfirmQuit);
                    return;
                }
                'n' | 'N' => {
                    sender.send(Msg::CancelQuit);
                    return;
                }
                _ => {}
            }
        }
        if matches!(key.code, KeyCode::Esc) {
            sender.send(Msg::CancelQuit);
            return;
        }
        // Any other key also cancels.
        sender.send(Msg::CancelQuit);
        return;
    }

    // Esc during a running turn cancels it (MD §The agent loop: "Esc
    // cancels the stream and kills each running tool's process group").
    // Priority over the composer Esc semantics — the operator wants the
    // turn stopped, not the draft touched.
    if matches!(key.code, KeyCode::Esc) && app.turn_in_flight {
        sender.send(Msg::CancelTurn);
        return;
    }

    // Modal input toggle (the multiplexer pattern): Esc from an empty
    // composer → NORMAL mode (single-key commands); `i` or Enter in NORMAL
    // → INSERT. The status line shows which mode you're in.
    match key.code {
        KeyCode::Esc if app.input_mode == crate::state::InputMode::Insert => {
            if composer.text.is_empty() {
                // A just-cleared draft can be brought back with Esc once
                // more (undo for the Ctrl+C clear — Claude Code parity).
                if let Some(restored) = composer.take_cleared() {
                    let _ = restored;
                    sender.send(Msg::ComposerChanged);
                    sender.send(Msg::ComposerTextChanged(composer.text().to_string()));
                    return;
                }
                sender.send(Msg::InputModeChanged(crate::state::InputMode::Normal));
                return;
            }
            // Text present: first Esc clears the draft (kept for one more
            // Esc-press as undo); a second Esc drops to NORMAL. Staged so
            // the operator has a beat before the mode flips.
            composer.clear_stash();
            sender.send(Msg::ComposerChanged);
            sender.send(Msg::ComposerTextChanged(composer.text().to_string()));
            return;
        }
        KeyCode::Char('i') | KeyCode::Enter
            if app.input_mode == crate::state::InputMode::Normal =>
        {
            sender.send(Msg::InputModeChanged(crate::state::InputMode::Insert));
            return;
        }
        _ => {}
    }

    // Live slash-hint navigation (Claude Code parity): while the hint
    // dropdown is open, ↑/↓ move the selection and Tab/Enter accept the
    // selected command into the composer.
    if app.slash_hints.open && !app.slash_hints.items.is_empty() {
        let n = app.slash_hints.items.len();
        match key.code {
            KeyCode::Up => {
                let sel = app.slash_hints.selected;
                let next = if sel == 0 { n - 1 } else { sel - 1 };
                sender.send(Msg::SlashHintSelect(next));
                return;
            }
            KeyCode::Down => {
                let sel = app.slash_hints.selected;
                let next = (sel + 1) % n;
                sender.send(Msg::SlashHintSelect(next));
                return;
            }
            KeyCode::Tab => {
                let idx = app.slash_hints.selected.min(n - 1);
                let cmd = app.slash_hints.items[idx].0.clone();
                composer.set_text(&format!("{cmd} "));
                sender.send(Msg::ComposerChanged);
                sender.send(Msg::ComposerTextChanged(composer.text().to_string()));
                return;
            }
            KeyCode::Enter => {
                let idx = app.slash_hints.selected.min(n - 1);
                let cmd = app.slash_hints.items[idx].0.clone();
                composer.set_text(&format!("{cmd} "));
                sender.send(Msg::ComposerChanged);
                sender.send(Msg::ComposerTextChanged(composer.text().to_string()));
                return;
            }
            _ => {}
        }
    }

    // Tab (Claude Code QOL): with the composer focused, INSERT mode, and
    // text present, Tab COMPLETES (slash command or file path) — it only
    // navigates focus when the composer is empty or unfocused.
    if matches!(key.code, KeyCode::Tab)
        && app.focus == crate::state::Focus::Center
        && app.input_mode == crate::state::InputMode::Insert
        && !composer.text().is_empty()
    {
        if let Some(replacement) = complete_composer(composer.text()) {
            *composer.text_mut() = replacement;
            sender.send(Msg::ComposerChanged);
            sender.send(Msg::ComposerTextChanged(composer.text().to_string()));
            return;
        }
        // No completion found — fall through to focus navigation.
    }

    // Shift+Tab (BackTab) cycles plan mode (Claude Code parity): Insert →
    // Plan → Normal. Handled before the global Tab focus nav so BackTab
    // never moves focus.
    if matches!(key.code, KeyCode::BackTab) {
        sender.send(Msg::PlanModeToggle);
        return;
    }

    // Focus navigation is global: Tab/BackTab must reach the key parser even
    // while the center composer is focused. Handle it before composer input.
    if matches!(key.code, KeyCode::Tab) {
        if let Some(action) = key_parser.parse(&key) {
            sender.send(Msg::KeyAction(action));
        }
        return;
    }

    // Shift+Enter inserts a newline (multi-line composer).
    if key.modifiers.contains(KeyModifiers::SHIFT) && key.code == KeyCode::Enter {
        composer.newline();
        sender.send(Msg::ComposerChanged);
        sender.send(Msg::ComposerTextChanged(composer.text().to_string()));
        return;
    }

    // Enter (no shift) sends the composer. A leading `/` (command), `!`
    // (shell passthrough), or bare quit/exit — the event loop parses it.
    if key.code == KeyCode::Enter && !key.modifiers.contains(KeyModifiers::SHIFT) {
        let text = composer.take();
        composer.history_record(text.trim());
        let trimmed = text.trim();
        if !trimmed.is_empty() {
            if trimmed == "quit" || trimmed == "exit" {
                sender.send(Msg::SlashCommand(text));
            } else if let Some(shell_cmd) = trimmed.strip_prefix('!') {
                run_shell_passthrough(shell_cmd, sender);
            } else if trimmed.starts_with('/') {
                sender.send(Msg::SlashCommand(text));
            } else {
                // @file mention expansion (Claude Code QOL): each @path in
                // the prompt is replaced by the file's contents in a fenced
                // block (capped). Missing files leave the mention as-is so
                // the operator sees what failed.
                let expanded = expand_file_mentions(&text);
                sender.send(Msg::TextSubmitted(expanded));
            }
        }
        sender.send(Msg::ComposerChanged);
        sender.send(Msg::ComposerTextChanged(composer.text().to_string()));
        return;
    }

    // Backspace: word-aware with Ctrl.
    if key.code == KeyCode::Backspace {
        if key.modifiers.contains(KeyModifiers::CONTROL) {
            composer.backspace_word();
        } else {
            composer.pop();
        }
        sender.send(Msg::ComposerChanged);
        sender.send(Msg::ComposerTextChanged(composer.text().to_string()));
        return;
    }

    // Input history (Claude Code QOL): ↑/↓ walk previously-submitted
    // prompts while the composer is focused in INSERT mode. The draft is
    // stashed on first ↑ and restored on ↓-past-the-end.
    if app.focus == crate::state::Focus::Center && app.input_mode == crate::state::InputMode::Insert
    {
        match key.code {
            KeyCode::Up if !composer.text().contains('\n') => {
                if composer.history_prev() {
                    sender.send(Msg::ComposerChanged);
                    sender.send(Msg::ComposerTextChanged(composer.text().to_string()));
                }
                return;
            }
            KeyCode::Down if !composer.text().contains('\n') => {
                if composer.history_next() {
                    sender.send(Msg::ComposerChanged);
                    sender.send(Msg::ComposerTextChanged(composer.text().to_string()));
                }
                return;
            }
            _ => {}
        }
    }

    // Ctrl+U: kill to line start (readline QOL).
    if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('u') {
        composer.clear();
        sender.send(Msg::ComposerChanged);
        sender.send(Msg::ComposerTextChanged(composer.text().to_string()));
        return;
    }

    // Plain character input into the composer — when the center pane
    // (conversation) is focused and we're in INSERT mode. In NORMAL mode
    // (Esc from an empty composer), letters route to the command parser —
    // the modal pattern every multiplexer uses (herdr/tmux/vim).
    if app.focus == crate::state::Focus::Center
        && app.input_mode == crate::state::InputMode::Insert
        && composer_wants_char(&key, app)
    {
        if let KeyCode::Char(c) = key.code {
            composer.push(c);
            sender.send(Msg::ComposerChanged);
            sender.send(Msg::ComposerTextChanged(composer.text().to_string()));
            return;
        }
    }

    // Key parser — handles q, Tab, 1/2/3, g+s/g+v/g+n, z+t/z+c, /, Ctrl+C.
    if let Some(action) = key_parser.parse(&key) {
        match action {
            KeyAction::Quit => sender.send(Msg::RequestQuit),
            KeyAction::RerunLast => {
                // D3: `r` in NORMAL mode re-submits the last prompt —
                // the fastest retry loop when iterating on a task. No-op
                // before the first turn of a session.
                if let Some(prompt) = app.last_prompt.clone() {
                    if !prompt.is_empty() {
                        let _ = command_sink.send(WorkerCommand::Prompt(prompt));
                    }
                }
            }
            KeyAction::FocusNext
            | KeyAction::FocusPrev
            | KeyAction::FocusLeft
            | KeyAction::FocusCenter
            | KeyAction::FocusRight
            | KeyAction::FocusSet(_)
            | KeyAction::TabSessions
            | KeyAction::TabVerbose
            | KeyAction::NewSession
            | KeyAction::ToggleToolDetail
            | KeyAction::ToggleCost
            | KeyAction::Unknown => {
                sender.send(Msg::KeyAction(action));
            }
            KeyAction::CommandPalette => {
                // z+y → enter copy mode (yank transcript).
                sender.send(Msg::EnterCopyMode);
            }
            KeyAction::OpenPalette => {
                // ? → the command palette (§6.13).
                sender.send(Msg::PaletteToggle);
            }
            KeyAction::HelpToggle => {
                // ? → the help overlay (§6.16).
                sender.send(Msg::HelpToggle);
            }
            KeyAction::EnterInsert => {
                sender.send(Msg::InputModeChanged(crate::state::InputMode::Insert));
            }
            KeyAction::ZoomToggle => {
                // Z → zoom the focused pane (herdr-style fullscreen).
                sender.send(Msg::ZoomToggle(app.focus));
            }
            KeyAction::ScrollUp(n) => {
                // Scroll acts on the FOCUSED pane (functional isolation).
                sender.send(Msg::PaneScroll {
                    pane: app.focus,
                    delta: -(n as i32),
                });
            }
            KeyAction::ScrollDown(n) => {
                sender.send(Msg::PaneScroll {
                    pane: app.focus,
                    delta: n as i32,
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{App, PendingApproval};
    use crossterm::event::{KeyCode, KeyModifiers};

    fn char_key(c: char) -> KeyEvent {
        KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE)
    }

    #[test]
    fn composer_wants_plain_char_no_approval() {
        let app = App::new();
        assert!(composer_wants_char(&char_key('a'), &app));
        assert!(composer_wants_char(&char_key('g'), &app));
        assert!(composer_wants_char(&char_key('s'), &app));
    }

    #[test]
    fn composer_rejects_ctrl_char() {
        let app = App::new();
        let key = KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL);
        assert!(!composer_wants_char(&key, &app));
    }

    #[test]
    fn composer_rejects_y_n_r_when_approval_pending() {
        let mut app = App::new();
        app.pending_approvals.push(PendingApproval {
            call_id: "c1".into(),
            tool_name: "calculator".into(),
            summary: "calc(expr)".into(),
            risk: 1,
            working_dir: "/tmp".into(),
        });
        assert!(!composer_wants_char(&char_key('y'), &app));
        assert!(!composer_wants_char(&char_key('n'), &app));
        assert!(!composer_wants_char(&char_key('R'), &app));
        // Other letters still go to the composer.
        assert!(composer_wants_char(&char_key('x'), &app));
    }

    #[test]
    fn composer_accepts_y_n_r_when_no_approval() {
        let app = App::new();
        assert!(composer_wants_char(&char_key('y'), &app));
        assert!(composer_wants_char(&char_key('n'), &app));
    }

    #[test]
    fn composer_rejects_non_char_keys() {
        let app = App::new();
        let key = KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE);
        assert!(!composer_wants_char(&key, &app));
    }
}

#[cfg(test)]
mod paste_tests {
    use super::Composer;

    #[test]
    fn paste_block_preserves_newlines_never_submits() {
        let mut c = Composer::new();
        c.push_block("line one\nline two\nline three");
        assert_eq!(c.text(), "line one\nline two\nline three");
    }

    #[test]
    fn paste_block_normalizes_crlf() {
        let mut c = Composer::new();
        c.push_block("windows\r\ntext");
        assert_eq!(c.text(), "windows\ntext");
    }

    #[test]
    fn paste_block_empty_is_noop() {
        let mut c = Composer::new();
        c.push_block("");
        assert_eq!(c.text(), "");
    }

    #[test]
    fn paste_lone_cr_becomes_lf() {
        let mut c = Composer::new();
        c.push_block("old\rmac");
        assert_eq!(c.text(), "old\nmac");
    }
}
