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
pub mod input;
pub mod msg;
mod render;
mod rich;
pub mod state;
mod terminal;
pub mod theme;
pub mod worker;

pub use approval::{ApprovalRegistry, ApprovalResponse};
pub use bridge::{
    emit_cost, emit_error, emit_response_finished, emit_status, emit_text, emit_tool_finished,
    emit_tool_started, safe_text, strip_cot,
};
pub use worker::{WorkerCtx, WorkerSpawner};

use crossterm::event::{self, Event, KeyEvent};
use input::{KeyAction, KeyParser};
use std::time::{Duration, Instant};

use crate::bus::{Bus, BusSender};
use crate::msg::Msg;
use crate::state::App;
use crate::theme::{ResolvedTheme, Theme};

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
    let theme = Theme::load(&home).resolve();

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
    let mut key_parser = KeyParser::new();

    // Initial size from the terminal.
    if let Ok(size) = crossterm::terminal::size() {
        app.reduce(Msg::Resize(size.0, size.1));
    }

    // Build the prompt channel — the worker owns the receiver, the input
    // handler holds the sender. Forwarding user prompts through this channel
    // keeps the Bus single-consumer (the main loop's reducer).
    let (prompt_tx, prompt_rx) = std::sync::mpsc::channel();
    let prompt_forward = prompt_tx.clone();

    // Spawn the worker thread (owns the backend pipeline). Errors are surfaced
    // via Msg::BackendError to the reducer.
    let spawn_ctx = worker::WorkerCtx {
        sender: sender.clone(),
        approvals: approvals.clone(),
        prompt_rx,
    };
    if let Err(e) = worker_spawner(spawn_ctx, prompt_tx) {
        eprintln!("orbit-tui: worker spawn failed: {e}");
    }

    let result = event_loop(
        &mut guard,
        &bus,
        &sender,
        &approvals,
        &mut app,
        &mut key_parser,
        &prompt_forward,
        &theme,
    );

    // Restore the terminal BEFORE printing anything — raw mode + alternate
    // screen would swallow or garble the message.
    drop(guard);
    match result {
        Ok(outcome) => {
            if let Some(note) = outcome.note {
                eprintln!("orbit-tui: {note}");
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
    prompt_forward: &std::sync::mpsc::Sender<String>,
    theme: &ResolvedTheme,
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
                exit_code: sig.exit_code(),
                note: Some(note),
            });
        }

        while let Some(msg) = bus.try_recv() {
            if let Msg::TextSubmitted(ref text) = msg {
                let _ = prompt_forward.send(text.clone());
            }
            app.reduce(msg);
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
            guard.draw(app, composer.text(), theme)?;
            app.dirty.clear();
        }

        if app.should_quit {
            return Ok(LoopOutcome {
                exit_code: 0,
                note: None,
            });
        }

        let timeout = UI_TICK
            .checked_sub(last_tick.elapsed())
            .unwrap_or(Duration::ZERO);

        if event::poll(timeout).map_err(|e| format!("poll: {e}"))? {
            match event::read().map_err(|e| format!("read: {e}"))? {
                Event::Key(key) => {
                    handle_key(key, sender, &mut composer, key_parser, app, approvals)
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

/// Enter copy mode: temporarily exit the alt screen, print the transcript as
/// plain text (no borders, no panes, no ANSI), wait for any key, then re-enter.
/// The operator can select and copy individual lines with the terminal's
/// native text selection.
fn enter_copy_mode(guard: &mut terminal::TerminalGuard, app: &App) -> Result<(), String> {
    use crossterm::cursor::{Hide, Show};
    use crossterm::execute;
    use crossterm::terminal::{disable_raw_mode, enable_raw_mode};
    use crossterm::terminal::{EnterAlternateScreen, LeaveAlternateScreen};

    // Exit alt screen + raw mode.
    disable_raw_mode().map_err(|e| format!("disable_raw_mode: {e}"))?;
    execute!(std::io::stdout(), Show, LeaveAlternateScreen)
        .map_err(|e| format!("leave alt screen: {e}"))?;

    // Print the transcript as plain text.
    println!();
    println!("╭──────────────────────────────────────────────────────────╮");
    println!("│  ORBIT — copy mode (select text, copy, press any key)   │");
    println!("╰──────────────────────────────────────────────────────────╯");
    println!();
    for entry in &app.transcript {
        match entry {
            crate::state::TranscriptLine::User(text) => {
                for line in text.lines() {
                    println!("user> {line}");
                }
            }
            crate::state::TranscriptLine::Assistant(text) => {
                for line in text.lines() {
                    println!("orbit> {line}");
                }
            }
            crate::state::TranscriptLine::Stripped { tool_name } => {
                println!("  [tool: {tool_name}]");
            }
        }
    }
    if !app.in_flight.is_empty() {
        for line in app.in_flight.lines() {
            println!("orbit> {line}");
        }
    }
    println!();
    println!("── press any key to return to ORBIT ──");
    use std::io::Write;
    let _ = std::io::stdout().flush();

    // Wait for any key.
    let _ = event::read();

    // Re-enter alt screen + raw mode.
    enable_raw_mode().map_err(|e| format!("enable_raw_mode: {e}"))?;
    execute!(std::io::stdout(), EnterAlternateScreen, Hide)
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
fn handle_key(
    key: KeyEvent,
    sender: &BusSender,
    composer: &mut Composer,
    key_parser: &mut KeyParser,
    app: &App,
    approvals: &ApprovalRegistry,
) {
    use crossterm::event::{KeyCode, KeyModifiers};

    // Ctrl+C → double-press to quit (not immediate).
    if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
        sender.send(Msg::CtrlC);
        return;
    }

    // Ctrl+D (EOF) → request quit with confirmation.
    if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('d') {
        sender.send(Msg::RequestQuit);
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

    // `c` when center is focused → enter copy mode.
    if app.focus == crate::state::Focus::Center
        && !key.modifiers.contains(KeyModifiers::CONTROL)
        && !key.modifiers.contains(KeyModifiers::ALT)
    {
        if let KeyCode::Char('c') = key.code {
            // Only trigger copy mode if not typing in the composer
            // (i.e., the composer is empty or we're not in typing mode).
            // Actually, `c` should be a composer character when typing.
            // Use Ctrl+C for copy instead? No — Ctrl+C is quit.
            // Use a different key: `y` for "yank" (vim-style copy).
            // Actually, let's use `Ctrl+Shift+C` or just a leader: `z` then `y`.
            // For now, skip — copy mode will be triggered by a leader key.
        }
    }

    // Shift+Enter inserts a newline (multi-line composer).
    if key.modifiers.contains(KeyModifiers::SHIFT) && key.code == KeyCode::Enter {
        composer.newline();
        sender.send(Msg::ComposerChanged);
        return;
    }

    // Enter (no shift) sends the composer.
    if key.code == KeyCode::Enter && !key.modifiers.contains(KeyModifiers::SHIFT) {
        let text = composer.take();
        if !text.trim().is_empty() {
            sender.send(Msg::TextSubmitted(text));
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

    // Plain character input into the composer — ONLY when the center pane
    // (conversation) is focused. On other panes, letters go to the key parser
    // so leader keys (g, z) and shortcuts work instead of typing.
    if app.focus == crate::state::Focus::Center && composer_wants_char(&key, app) {
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
        }
        return;
    }

    // y / n / R are approval shortcuts when an approval is pending.
    if !app.pending_approvals.is_empty() {
        let call_id = app.pending_approvals[0].call_id.clone();
        if let KeyCode::Char(c) = key.code {
            match c {
                'y' | 'Y' => {
                    approvals.resolve(&call_id, ApprovalResponse::Allow);
                    sender.send(Msg::ToolCallFinished {
                        name: app.pending_approvals[0].tool_name.clone(),
                        ok: true,
                    });
                    return;
                }
                'n' | 'N' => {
                    approvals.resolve(&call_id, ApprovalResponse::Deny);
                    sender.send(Msg::ToolCallFinished {
                        name: app.pending_approvals[0].tool_name.clone(),
                        ok: false,
                    });
                    return;
                }
                'r' | 'R' => {
                    approvals.resolve(&call_id, ApprovalResponse::AllowSession);
                    sender.send(Msg::ToolCallFinished {
                        name: app.pending_approvals[0].tool_name.clone(),
                        ok: true,
                    });
                    return;
                }
                _ => {}
            }
        }
        if matches!(key.code, KeyCode::Esc) {
            approvals.resolve(&call_id, ApprovalResponse::Deny);
            sender.send(Msg::ToolCallFinished {
                name: app.pending_approvals[0].tool_name.clone(),
                ok: false,
            });
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
