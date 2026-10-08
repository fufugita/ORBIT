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
//! ## The terminal watchdog (2026-10-07)
//!
//! A closed PTY master does NOT only deliver SIGHUP: it also makes the input
//! fd permanently readable-with-no-data (`read` returns EOF or EIO
//! instantly, forever). crossterm 0.29's tty read loop has no exit for that
//! case — `event::poll` never returns and the event loop can never reach its
//! signal check. Observed live: three `orbit` processes spinning at 45–99%
//! CPU on deleted PTYs for hours after their terminals closed.
//!
//! [`TerminalWatchdog`] closes the gap. It polls the input fd with
//! `events = 0` (only POLLHUP/POLLERR/POLLNVAL — which the kernel always
//! reports, so it never contends with crossterm for input bytes). When the
//! terminal dies it (a) sets `SIGHUP_FLAG` so a HEALTHY loop exits through
//! its normal shutdown path within one tick, then (b) after a grace period,
//! force-exits `128 + 1` for the wedged case. `_exit` is safe there: the
//! terminal is gone, nothing can be rendered or flushed, and the session
//! file is written per-turn — the most that is lost is the in-flight turn.
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
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, LazyLock};
use std::time::Duration;

pub type Term = Terminal<CrosstermBackend<Stdout>>;

/// Signal flags set by the signal handler and checked by the event loop.
/// `Arc<AtomicBool>` is required by `signal_hook::flag::register`.
static SIGTERM_FLAG: LazyLock<Arc<AtomicBool>> = LazyLock::new(|| Arc::new(AtomicBool::new(false)));
static SIGHUP_FLAG: LazyLock<Arc<AtomicBool>> = LazyLock::new(|| Arc::new(AtomicBool::new(false)));
static SIGINT_FLAG: LazyLock<Arc<AtomicBool>> = LazyLock::new(|| Arc::new(AtomicBool::new(false)));

/// The moment the terminal watchdog detected terminal loss — set when the
/// watchdog first sees POLLHUP/POLLERR on the input fd. `0` = terminal
/// alive (or watchdog not yet run).
///
/// Distinct from [`SIGHUP_FLAG`]: the kernel delivers SIGHUP *to the process*
/// on master close (caught → graceful path), while the watchdog detects
/// *terminal death via the fd* for the case where the signal was missed or
/// the loop can no longer reach its signal check. The watchdog sets BOTH.
static TERMINAL_DEAD_AT: LazyLock<Arc<AtomicU64>> =
    LazyLock::new(|| Arc::new(AtomicU64::new(0)));

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

/// The terminal watchdog: a background thread that detects terminal death
/// when the event loop cannot (see the module doc — crossterm 0.29's tty
/// read loop never returns on a dead PTY, wedging the loop at 100% CPU).
///
/// It polls the input fd with `events = 0`: POLLHUP/POLLERR/POLLNVAL are
/// always reported by the kernel regardless of the requested events, so the
/// watchdog never contends with crossterm for input bytes and costs one
/// syscall per [`WATCHDOG_POLL_MS`]. On terminal death it:
///
/// 1. sets `SIGHUP_FLAG` (a healthy loop exits through its normal
///    noninteractive-shutdown path on the next tick), and
/// 2. records the death time; if the process is still alive
///    [`WATCHDOG_GRACE`] later, force-exits `128 + 1` — the wedged case.
///    Nothing can be rendered or flushed on a dead terminal, and the
///    session file is written per-turn, so `_exit` loses at most the
///    in-flight turn.
///
/// The thread parks in `poll` and exits with the process; it is a daemon
/// by construction (never joined, never blocks shutdown).
pub(crate) struct TerminalWatchdog;

/// The watchdog's poll cadence. Not performance-critical — it exists to
/// catch a case that must not persist, not to react in milliseconds.
const WATCHDOG_POLL_MS: i64 = 500;

/// How long the watchdog waits for the event loop to shut itself down
/// after terminal death before force-exiting. Generous against a slow
/// final render or a busy provider round finishing up.
const WATCHDOG_GRACE: Duration = Duration::from_secs(3);

impl TerminalWatchdog {
    /// Spawn the watchdog for the input fd crossterm reads (stdin — the
    /// guard is only entered when stdin is a TTY; crossterm's `tty_fd()`
    /// uses stdin in exactly that case, so the fds match).
    pub fn spawn() -> Self {
        let stdin = std::io::stdin();
        std::thread::Builder::new()
            .name("orbit-terminal-watchdog".into())
            .spawn(move || Self::run(&stdin))
            .ok();
        Self
    }

    fn run(input: &std::io::Stdin) {
        use rustix::event::{poll, PollFd, PollFlags, Timespec};
        loop {
            let mut fds = [PollFd::new(input, PollFlags::empty())];
            let timeout = Timespec {
                tv_sec: 0,
                tv_nsec: WATCHDOG_POLL_MS * 1_000_000,
            };
            let n = match poll(&mut fds, Some(&timeout)) {
                Ok(n) => n,
                Err(_) => {
                    // A transient poll failure (EINTR-class) — retry. A
                    // permanent one means the fd is unusable; treat that
                    // as terminal death rather than spinning.
                    std::thread::sleep(Duration::from_millis(WATCHDOG_POLL_MS as u64));
                    continue;
                }
            };
            if n == 0 {
                continue;
            }
            let revents = fds[0].revents();
            if revents
                .intersects(PollFlags::HUP | PollFlags::ERR | PollFlags::NVAL)
            {
                Self::terminal_died();
                return;
            }
            // POLLIN-only with events=0 cannot happen (we requested
            // nothing); anything else is unexpected — keep watching.
        }
    }

    fn terminal_died() {
        // (a) The graceful path: a healthy event loop sees SIGHUP on its
        // next tick and runs its normal shutdown (deny approvals, save,
        // exit 129).
        SIGHUP_FLAG.store(true, Ordering::Relaxed);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(1);
        TERMINAL_DEAD_AT.store(now, Ordering::Relaxed);
        // (b) The wedged path: crossterm's read loop never returns on a
        // dead PTY, so the loop above may never run again. Give the
        // process the grace period, then take the conventional exit.
        std::thread::sleep(WATCHDOG_GRACE);
        std::process::exit(ShutdownSignal::Hangup.exit_code());
    }
}

/// Owns the terminal; restores it on drop.
pub struct TerminalGuard {
    /// Whether we enabled mouse capture (§12.4: the prototype does not).
    pub mouse_capture: bool,
    pub terminal: Term,
    /// The terminal-death watchdog (module doc): detects a closed PTY when
    /// the event loop is wedged inside crossterm's read and cannot reach
    /// its signal check. Held so its lifetime reads clearly; the thread
    /// itself parks in poll and exits with the process.
    _watchdog: TerminalWatchdog,
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
        Self::enter_with(true)
    }

    /// `mouse_capture = false` follows §12.4 (the MD's prototype:
    /// mouse capture stays off — the terminal's native selection owns
    /// the mouse).
    pub fn enter_with(mouse_capture: bool) -> Result<Self, String> {
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
        // Bracketed paste (D12): without it, a pasted multi-line block
        // arrives as individual keystrokes — every line's first Enter
        // submits a partial prompt.
        if mouse_capture {
            execute!(
                stdout,
                EnterAlternateScreen,
                Hide,
                EnableMouseCapture,
                crossterm::event::EnableBracketedPaste
            )
            .map_err(|e| format!("enter alt screen: {e}"))?;
        } else {
            execute!(
                stdout,
                EnterAlternateScreen,
                Hide,
                crossterm::event::EnableBracketedPaste
            )
            .map_err(|e| format!("enter alt screen: {e}"))?;
        }
        let backend = CrosstermBackend::new(stdout);
        let terminal = Terminal::new(backend).map_err(|e| format!("create terminal: {e}"))?;
        // The watchdog watches the same fd crossterm reads (stdin — we are
        // only here when stdin is a TTY). Spawned AFTER raw mode + alt
        // screen so a probe failure never leaves a watchdog behind.
        let watchdog = TerminalWatchdog::spawn();
        Ok(Self {
            terminal,
            mouse_capture,
            _watchdog: watchdog,
        })
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
        if self.mouse_capture {
            execute!(
                std::io::stdout(),
                Show,
                DisableMouseCapture,
                crossterm::event::DisableBracketedPaste,
                LeaveAlternateScreen
            )
            .ok();
        } else {
            execute!(
                std::io::stdout(),
                Show,
                crossterm::event::DisableBracketedPaste,
                LeaveAlternateScreen
            )
            .ok();
        }
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

    /// The signal flags are process-global; tests that mutate them must not
    /// interleave (cargo runs tests in parallel threads).
    static SIGNAL_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn take_pending_signal_drains_flag_exactly_once() {
        let _g = SIGNAL_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        force_signal(ShutdownSignal::Hangup);
        assert_eq!(take_pending_signal(), Some(ShutdownSignal::Hangup));
        // Second poll sees nothing — the flag was consumed.
        assert_eq!(take_pending_signal(), None);
    }

    #[test]
    fn take_pending_signal_reports_each_signal_kind() {
        let _g = SIGNAL_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
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
