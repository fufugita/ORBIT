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
pub mod render;
mod rich;
pub mod selection;
pub mod state;
mod terminal;
pub mod tokens;
pub mod unicode;
pub mod worker;

pub use approval::{ApprovalRegistry, ApprovalResponse};
pub use state::RedactionKind;
pub use bridge::{
    emit_cost, emit_error, emit_response_finished, emit_status, emit_text, emit_tool_finished,
    emit_tool_started, emit_turn_cost, emit_workspace, safe_text, strip_cot, CotStripper,
};
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
                "commands: exit, /help, /model <M>, /clear, /usage, /models, /sessions, /resume <id>, /cancel"
                    .into(),
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
        "/quit" | "/exit" => {
            app.reduce(Msg::RequestQuit);
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
            if let Msg::TextSubmitted(text) = msg {
                app.reduce(Msg::TextSubmitted(text.clone()));
                if !was_in_flight && app.turn_in_flight {
                    let _ = command_sink.send(WorkerCommand::Prompt(text));
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
                        app.transcript
                            .push(crate::state::TranscriptLine::User(next.clone()));
                        let _ = command_sink.send(WorkerCommand::Prompt(next));
                    }
                    continue;
                }
                Msg::BackendError(err) => {
                    app.reduce(Msg::BackendError(err));
                    if let Some(next) = app.take_next_queued() {
                        app.transcript
                            .push(crate::state::TranscriptLine::User(next.clone()));
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
                Event::Key(key) => {
                    handle_key(key, sender, &mut composer, key_parser, app, approvals, command_sink)
                }
                Event::Paste(text) => {
                    // D12: bracketed paste — the whole block lands in the
                    // composer as one edit. Newlines are preserved (the
                    // operator pastes code, logs, heredocs); nothing is
                    // auto-submitted. Sanitize control chars that terminals
                    // can smuggle inside a paste (ESC, CSI leaders) — the
                    // paste is data, never key bindings.
                    if app.focus == crate::state::Focus::Center
                        && app.input_mode == crate::state::InputMode::Insert
                    {
                        let clean: String = text
                            .chars()
                            .filter(|c| {
                                !c.is_control()
                                    || *c == '\n'
                                    || *c == '\r'
                                    || *c == '\t'
                            })
                            .collect();
                        composer.push_block(&clean);
                        sender.send(Msg::ComposerChanged);
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
    use crossterm::event::{DisableMouseCapture, EnableMouseCapture};
    use crossterm::execute;
    use crossterm::terminal::{disable_raw_mode, enable_raw_mode};
    use crossterm::terminal::{EnterAlternateScreen, LeaveAlternateScreen};

    // Exit alt screen + raw mode.
    disable_raw_mode().map_err(|e| format!("disable_raw_mode: {e}"))?;
    execute!(
        std::io::stdout(),
        Show,
        DisableMouseCapture,
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
    execute!(
        std::io::stdout(),
        EnterAlternateScreen,
        Hide,
        EnableMouseCapture
    )
    .map_err(|e| format!("enter alt screen: {e}"))?;

    // Force the terminal to redraw.
    let _ = guard.terminal.clear();

    Ok(())
}
/// `Enter` sends; `Shift+Enter` inserts a newline.
#[derive(Debug, Default)]
pub struct Composer {
    text: String,
}

impl Composer {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn text(&self) -> &str {
        &self.text
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
    /// D12: bracketed-paste insertion. The whole block lands as one edit
    /// (one undo unit, one ComposerChanged); CRLF/CR newlines normalize
    /// to LF so pasted Windows text doesn't render stray glyphs.
    pub fn push_block(&mut self, block: &str) {
        if !block.is_empty() {
            self.text.push_str(&block.replace("\r\n", "\n").replace('\r', "\n"));
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
    pub fn take(&mut self) -> String {
        std::mem::take(&mut self.text)
    }
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
            if let Some((pane, row, col)) = hit {
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

    // Ctrl+C → deny pending approvals first (D8: the operator's interrupt
    // intent applies to the modal in front of them — releasing the parked
    // worker — not to the whole session). Then cancel the in-flight turn if
    // streaming; otherwise the double-press-to-quit flow.
    if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
        if !app.pending_approvals.is_empty() {
            let denied = approvals.deny_all();
            sender.send(Msg::ApprovalsDenied);
            if denied > 0 {
                sender.send(Msg::SystemMessage(format!(
                    "denied {denied} pending approval(s)"
                )));
            }
        } else if app.turn_in_flight && app.tool_state != crate::state::ToolState::AwaitingApproval {
            sender.send(Msg::CancelTurn);
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
                    return;
                }
                'n' | 'N' => {
                    approvals.resolve(&call_id, ApprovalResponse::Deny);
                    return;
                }
                // Session grant is `R` only; bare `r` is swallowed by the
                // modal (no accidental session-wide grants). Terminals
                // deliver Shift+R as Char('R') — case is the distinction.
                'R' => {
                    approvals.resolve(&call_id, ApprovalResponse::AllowSession);
                    return;
                }
                _ => {}
            }
        }
        if matches!(key.code, KeyCode::Esc) {
            approvals.resolve(&call_id, ApprovalResponse::Deny);
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

    // Modal input toggle (the multiplexer pattern): Esc from an empty
    // composer → NORMAL mode (single-key commands); `i` or Enter in NORMAL
    // → INSERT. The status line shows which mode you're in.
    match key.code {
        KeyCode::Esc if app.input_mode == crate::state::InputMode::Insert => {
            if composer.text.is_empty() {
                sender.send(Msg::InputModeChanged(crate::state::InputMode::Normal));
                return;
            }
            // Text present: Esc clears the composer first (existing feel).
            composer.clear();
            sender.send(Msg::ComposerChanged);
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

    // Focus navigation is global: Tab/BackTab must reach the key parser even
    // while the center composer is focused. Handle it before composer input.
    if matches!(key.code, KeyCode::Tab | KeyCode::BackTab) {
        if let Some(action) = key_parser.parse(&key) {
            sender.send(Msg::KeyAction(action));
        }
        return;
    }

    // Shift+Enter inserts a newline (multi-line composer).
    if key.modifiers.contains(KeyModifiers::SHIFT) && key.code == KeyCode::Enter {
        composer.newline();
        sender.send(Msg::ComposerChanged);
        return;
    }

    // Enter (no shift) sends the composer. A leading `/` (or bare quit/exit)
    // is a command, not a prompt — the event loop parses it.
    if key.code == KeyCode::Enter && !key.modifiers.contains(KeyModifiers::SHIFT) {
        let text = composer.take();
        let trimmed = text.trim();
        if !trimmed.is_empty() {
            if trimmed.starts_with('/') || trimmed == "quit" || trimmed == "exit" {
                sender.send(Msg::SlashCommand(text));
            } else {
                sender.send(Msg::TextSubmitted(text));
            }
        }
        sender.send(Msg::ComposerChanged);
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
