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
use crate::theme::ResolvedTheme;
use crossterm::cursor::{Hide, Show};
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

impl TerminalGuard {
    /// Enter raw mode + alternate screen, hide cursor, install signal handlers.
    pub fn enter() -> Result<Self, String> {
        // Ensure UTF-8 locale.
        if std::env::var("LANG").unwrap_or_default().is_empty() {
            std::env::set_var("LANG", "en_US.UTF-8");
        }
        if std::env::var("LC_ALL").unwrap_or_default().is_empty() {
            std::env::set_var("LC_ALL", "en_US.UTF-8");
        }

        // Install signal handlers — set flags instead of dying mid-render.
        // The event loop converts them into noninteractive shutdown (the
        // modal path is reserved for interactive keys: q / Ctrl+C / Ctrl+D).
        let _ = signal_hook::flag::register(signal_hook::consts::SIGTERM, SIGTERM_FLAG.clone());
        let _ = signal_hook::flag::register(signal_hook::consts::SIGHUP, SIGHUP_FLAG.clone());
        let _ = signal_hook::flag::register(signal_hook::consts::SIGINT, SIGINT_FLAG.clone());

        enable_raw_mode().map_err(|e| format!("enable_raw_mode: {e}"))?;
        let mut stdout = std::io::stdout();
        execute!(stdout, EnterAlternateScreen, Hide)
            .map_err(|e| format!("enter alt screen: {e}"))?;
        let backend = CrosstermBackend::new(stdout);
        let terminal = Terminal::new(backend).map_err(|e| format!("create terminal: {e}"))?;
        Ok(Self { terminal })
    }

    /// Render the app state to the terminal.
    pub fn draw(
        &mut self,
        app: &App,
        composer_text: &str,
        theme: &ResolvedTheme,
    ) -> Result<(), String> {
        self.terminal
            .draw(|frame| crate::render::render(frame, app, composer_text, theme))
            .map(|_| ())
            .map_err(|e| format!("draw: {e}"))
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        execute!(std::io::stdout(), Show, LeaveAlternateScreen).ok();
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
