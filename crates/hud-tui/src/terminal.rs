//! RAII terminal guard — setup/teardown with guaranteed cleanup (DR-20 §1).
//!
//! `TerminalGuard::enter()` enables raw mode, enters the alternate screen,
//! and installs signal handlers for SIGTERM/SIGHUP/SIGINT. The handlers only
//! set `AtomicBool` flags (async-signal-safe); the event loop checks them
//! each tick via `take_pending_signal()`.
//!
//! Signal semantics:
//! - **SIGHUP** (terminal tab/window destroyed): the display surface is GONE —
//!   no confirmation can be rendered. The event loop performs a noninteractive
//!   shutdown: pending approvals are denied, the worker is not kept alive, and
//!   the process exits `128 + 1`. The pre-close "are you sure?" prompt belongs
//!   to the terminal emulator (kitty `confirm_os_window_close`, GNOME
//!   Terminal's close-warning pref) — it must fire BEFORE the PTY is torn down.
//! - **SIGTERM** (`kill`): external termination request; same noninteractive
//!   path, exit `128 + 15`. Unix convention — process managers expect it to die.
//! - **SIGINT via `kill -INT`**: same noninteractive path, exit `128 + 2`.
//!   Keyboard Ctrl+C is distinct: raw mode delivers it as a key event, which
//!   drives the interactive double-press-to-quit flow instead.
//!
//! `Drop` restores the terminal unconditionally — even on panic — so the
//! operator's terminal is never left in a broken state. Write failures on an
//! already-dead PTY are swallowed (`.ok()`): there is nothing left to restore.

use crate::state::App;
use crossterm::cursor::{Hide, Show};
use crossterm::event::{DisableMouseCapture, EnableMouseCapture};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;
use std::io::Stdout;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, LazyLock};

pub type Term = Terminal<CrosstermBackend<Stdout>>;

/// Signal flags set by the signal handler and checked by the event loop.
/// `Arc<AtomicBool>` is required by `signal_hook::flag::register`.
static SIGTERM_FLAG: LazyLock<Arc<AtomicBool>> = LazyLock::new(|| Arc::new(AtomicBool::new(false)));
static SIGHUP_FLAG: LazyLock<Arc<AtomicBool>> = LazyLock::new(|| Arc::new(AtomicBool::new(false)));
static SIGINT_FLAG: LazyLock<Arc<AtomicBool>> = LazyLock::new(|| Arc::new(AtomicBool::new(false)));

/// A terminal-loss / external-termination signal caught since the last poll.
///
/// HUP/TERM/INT all demand **noninteractive** shutdown — the PTY may already
/// be destroyed, so no modal can be shown and no key will ever arrive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShutdownSignal {
    Hangup,
    Terminate,
    Interrupt,
}

impl ShutdownSignal {
    /// Conventional shell exit status for death-by-signal (`128 + signum`).
    pub fn exit_code(self) -> i32 {
        match self {
            ShutdownSignal::Hangup => 128 + 1,
            ShutdownSignal::Terminate => 128 + 15,
            ShutdownSignal::Interrupt => 128 + 2,
        }
    }

    /// Human-readable name for the shutdown trace line.
    pub fn name(self) -> &'static str {
        match self {
            ShutdownSignal::Hangup => "SIGHUP (terminal closed)",
            ShutdownSignal::Terminate => "SIGTERM",
            ShutdownSignal::Interrupt => "SIGINT",
        }
    }
}

/// Return the pending shutdown signal, if any, clearing the flag.
/// Called by the event loop each tick. Only the first caught signal is
/// reported; later ones are irrelevant once shutdown has begun.
pub fn take_pending_signal() -> Option<ShutdownSignal> {
    // Order matters only for exit-code selection; any one triggers shutdown.
    if SIGHUP_FLAG.swap(false, Ordering::Relaxed) {
        return Some(ShutdownSignal::Hangup);
    }
    if SIGTERM_FLAG.swap(false, Ordering::Relaxed) {
        return Some(ShutdownSignal::Terminate);
    }
    if SIGINT_FLAG.swap(false, Ordering::Relaxed) {
        return Some(ShutdownSignal::Interrupt);
    }
    None
}

/// Test hook: force a signal flag as if the handler had run.
#[cfg(test)]
pub(crate) fn force_signal(sig: ShutdownSignal) {
    match sig {
        ShutdownSignal::Hangup => SIGHUP_FLAG.store(true, Ordering::Relaxed),
        ShutdownSignal::Terminate => SIGTERM_FLAG.store(true, Ordering::Relaxed),
        ShutdownSignal::Interrupt => SIGINT_FLAG.store(true, Ordering::Relaxed),
    }
}

/// Owns the terminal; restores it on drop.
pub struct TerminalGuard {
    pub terminal: Term,
}

/// Ambiguous-width probe (§11.3): print ● at column 0, ask the terminal
/// where the cursor is (ESC[6n), check whether it moved one column or two,
/// then erase the line. 100 ms timeout; no answer → assume narrow.
///
/// Runs BEFORE the alternate screen (it must be visible to the terminal,
/// not swallowed by the alt-screen switch). Returns true when ambiguous-
/// width glyphs render wide — the caller selects the ASCII glyph set.
pub fn probe_ambiguous_width() -> bool {
    use std::io::Write;

    // The probe needs raw mode to read the response without a newline.
    if crossterm::terminal::enable_raw_mode().is_err() {
        return false; // not a TTY we can probe — assume narrow
    }
    let wide = {
        let mut out = std::io::stdout();
        // Print ● (U+25CF, ambiguous width) at column 0.
        let _ = write!(out, "\u{25cf}");
        let _ = out.flush();
        // crossterm's cursor::position() sends ESC[6n and reads the reply,
        // but it blocks with NO timeout — a terminal that ignores DSR would
        // hang the probe forever. Run it on a thread and give it the spec's
        // 100 ms budget; no answer in time → assume narrow (§11.3).
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let pos = crossterm::cursor::position();
            let _ = tx.send(pos);
        });
        let wide = rx
            .recv_timeout(std::time::Duration::from_millis(100))
            .ok()
            .and_then(|r| r.ok())
            .map(|(_, col)| col > 1)
            .unwrap_or(false);
        // Erase the line — the probe leaves no trace.
        let _ = write!(out, "\r\x1b[2K");
        let _ = out.flush();
        wide
    };
    let _ = crossterm::terminal::disable_raw_mode();
    wide
}

impl TerminalGuard {
    /// Enter raw mode + alternate screen, hide cursor, install signal handlers.
    pub fn enter() -> Result<Self, String> {
        // NOTE: no locale forcing. Forcing LANG/LC_ALL to en_US.UTF-8 hides
        // non-UTF-8 terminals (H-7 hard downgrade); the glyph set is chosen
        // by locale detection + the width probe instead (§11.3).

        // Install signal handlers — set flags instead of dying mid-render.
        // The event loop converts them into noninteractive shutdown (the
        // modal path is reserved for interactive keys: q / Ctrl+C / Ctrl+D).
        let _ = signal_hook::flag::register(signal_hook::consts::SIGTERM, SIGTERM_FLAG.clone());
        let _ = signal_hook::flag::register(signal_hook::consts::SIGHUP, SIGHUP_FLAG.clone());
        let _ = signal_hook::flag::register(signal_hook::consts::SIGINT, SIGINT_FLAG.clone());

        enable_raw_mode().map_err(|e| format!("enable_raw_mode: {e}"))?;
        let mut stdout = std::io::stdout();
        // Mouse capture (SGR mode): the app owns the mouse so selection is
        // per-pane — the host terminal's native selection grabs rectangular
        // regions across pane borders because it doesn't know the panes
        // exist. Shift+Click bypasses capture for whole-screen selection.
        execute!(stdout, EnterAlternateScreen, Hide, EnableMouseCapture)
            .map_err(|e| format!("enter alt screen: {e}"))?;
        let backend = CrosstermBackend::new(stdout);
        let terminal = Terminal::new(backend).map_err(|e| format!("create terminal: {e}"))?;
        Ok(Self { terminal })
    }

    /// Render the app state to the terminal.
    ///
    /// Pure diff rendering — ratatui emits only changed cells. There is
    /// deliberately no full-repaint path: the live→settled turn transition
    /// is a normal diff (same cells, new gutter style), and forcing a
    /// whole-screen re-emit there caused a visible flash on every turn.
    /// Real Resize events still repaint fully via ratatui's own resize
    /// handling in the event loop.
    pub fn draw(
        &mut self,
        app: &App,
        composer_text: &str,
        design: &crate::tokens::Design,
    ) -> Result<(), String> {
        self.terminal
            .draw(|frame| crate::render::render(frame, app, composer_text, design))
            .map(|_| ())
            .map_err(|e| format!("draw: {e}"))
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        execute!(
            std::io::stdout(),
            Show,
            DisableMouseCapture,
            LeaveAlternateScreen
        )
        .ok();
        disable_raw_mode().ok();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shutdown_signal_exit_codes_follow_128_plus_signum() {
        assert_eq!(ShutdownSignal::Hangup.exit_code(), 129);
        assert_eq!(ShutdownSignal::Terminate.exit_code(), 143);
        assert_eq!(ShutdownSignal::Interrupt.exit_code(), 130);
    }

    #[test]
    fn shutdown_signal_names_are_distinct_and_stable() {
        let names = [
            ShutdownSignal::Hangup.name(),
            ShutdownSignal::Terminate.name(),
            ShutdownSignal::Interrupt.name(),
        ];
        assert_eq!(names, ["SIGHUP (terminal closed)", "SIGTERM", "SIGINT"]);
    }

    #[test]
    fn take_pending_signal_drains_flag_exactly_once() {
        force_signal(ShutdownSignal::Hangup);
        assert_eq!(take_pending_signal(), Some(ShutdownSignal::Hangup));
        // Second poll sees nothing — the flag was consumed.
        assert_eq!(take_pending_signal(), None);
    }

    #[test]
    fn take_pending_signal_reports_each_signal_kind() {
        for sig in [
            ShutdownSignal::Hangup,
            ShutdownSignal::Terminate,
            ShutdownSignal::Interrupt,
        ] {
            force_signal(sig);
            assert_eq!(take_pending_signal(), Some(sig));
            assert_eq!(take_pending_signal(), None);
        }
    }
}
