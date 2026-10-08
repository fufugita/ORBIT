//! The prototype runtime (DR-20): the event loop that owns the
//! keyboard, the bus and the draw. The layout is a pure function of
//! the terminal size (§8) — no user tree, no arrange mode.

use std::time::{Duration, Instant};

use crossterm::event::{self, Event, KeyCode, KeyModifiers};
use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use unicode_width::UnicodeWidthStr;

use super::comps;
use super::core::Token;
use super::scenario::{Activity, LineKind, Scenario, ToolState, TranscriptLine, TurnReport};
use super::screen::{Focus, Screen, WidthClass};
use crate::worker::WorkerCtx;

use crate::bus::{Bus, BusSender};
use crate::worker::CommandSink;
use crate::ApprovalRegistry;
use crate::WorkerCommand;

/// The UI tick: 16 ms. §10.5 — an idle ORBIT draws nothing; the loop
/// still polls so redraws after events are instant.
const UI_TICK: Duration = Duration::from_millis(16);

/// The overlays (§9.19–9.21): one at a time, instant open/close.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Overlay {
    /// The command palette (`/`).
    Palette,
    /// Help (`?`).
    Help,
    /// The quit card (§11.7).
    Quit,
}

/// A toast (§9.13): muted text, optional green ✓, 3 s.
pub struct Toast {
    pub text: String,
    pub ok: bool,
    pub shown_ms: u64,
}

/// The runtime's own state (the App replacement): focus, the star
/// clock, the brand tier.
pub struct Tui {
    pub focus: Focus,
    pub star: super::anim::StarClock,
    pub reduced: bool,
    pub tick_ms: u64,
    pub brand_tier: super::welcome::BrandTier,
}

impl Default for Tui {
    fn default() -> Self {
        Self::new()
    }
}

impl Tui {
    pub fn new() -> Self {
        Tui {
            focus: Focus::Conversation,
            star: super::anim::StarClock::new(),
            reduced: false,
            tick_ms: 0,
            brand_tier: super::welcome::BrandTier::Static,
        }
    }

    fn star_glyph(&self, scenario: &Scenario) -> super::anim::StarGlyph {
        let mut c = self.star;
        c.tick(self.tick_ms, scenario.star_state())
    }
}

/// `orbit chat` → the prototype screen (the MD's target front-end).
pub fn run_proto(args: &[String], worker_spawner: crate::worker::WorkerSpawner) -> i32 {
    let _ = args;
    let home = std::env::var("ORBIT_HOME")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::path::PathBuf::from(".orbit"));

    // tui.toml (Appendix C): colour mode, glyphs, motion, brand,
    // notify, colours, layout.
    let raw: crate::tokens::Theme = {
        let path = home.join("tui.toml");
        std::fs::read_to_string(&path)
            .ok()
            .and_then(|raw| toml::from_str(&raw).ok())
            .unwrap_or_default()
    };
    let reduced = raw.capabilities.reduced;
    // Brand tier (Appendix C): `off` by default; reduced motion caps
    // at `static`.
    let brand_tier = {
        use super::welcome::BrandTier;
        let t = match raw.capabilities.brand.as_str() {
            "anim" => BrandTier::Anim,
            "text" => BrandTier::Text,
            "static" => BrandTier::Static,
            _ => BrandTier::Off,
        };
        if reduced && t == BrandTier::Anim {
            BrandTier::Static
        } else {
            t
        }
    };

    // §12.4: mouse capture stays off (the terminal's native
    // selection owns the mouse).
    let mut guard = match crate::terminal::TerminalGuard::enter_with(false) {
        Ok(g) => g,
        Err(e) => {
            eprintln!("orbit-tui: cannot enter terminal: {e}");
            return 1;
        }
    };

    let (bus, sender) = Bus::new();
    let approvals = ApprovalRegistry::new();
    let mut scenario = Scenario::new();
    scenario.brand_tier = brand_tier;
    scenario.welcome_chips = crate::state::compute_readiness(&home)
        .into_iter()
        .map(|r| (r.ok, r.label))
        .collect();
    // The model name arrives via Msg::Identity; the waiting line
    // needs it before then too.
    scenario.model = std::env::var("ORBIT_ACTIVE_MODEL").unwrap_or_default();

    let mut tui = Tui {
        focus: Focus::Conversation,
        star: super::anim::StarClock::new(),
        reduced,
        tick_ms: 0,
        brand_tier,
    };

    // The composer: text lives here (the event loop owns it).
    let mut composer = String::new();
    let mut overlay: Option<Overlay> = None;
    let mut palette_query = String::new();
    let mut palette_sel = 0usize;
    let mut completion_sel = 0usize;
    let mut toast: Option<Toast> = None;
    // Queued prompts (§11.4): sent while a turn runs, shown as a
    // queued row until their TurnStarted.
    let mut queued: Vec<String> = Vec::new();
    // Composer history (§11.3), newest first.
    let mut history: Vec<String> = Vec::new();
    let mut history_idx: Option<usize> = None;
    // Copy mode is `z y` (§11.2); armed by z.
    let mut pending_leader: Option<char> = None;
    let mut want_copy_mode = false;
    // The Sessions push (§8.2 Medium): Shift-Tab from Conversation.
    let mut sessions_pushed = false;
    // Transcript scroll: rows above the bottom (0 = following).
    let mut scroll_offset: usize = 0;
    // The last sent prompt (§11.3): ⏎ on an empty composer resends
    // it after a failed turn.
    let mut last_prompt: Option<String> = None;

    let (cmd_tx, cmd_rx) = std::sync::mpsc::channel();
    let command_sink = cmd_tx.clone();
    let spawn_ctx = WorkerCtx {
        sender: sender.clone(),
        approvals: approvals.clone(),
        command_rx: cmd_rx,
    };
    // The cancel handle (Esc during a live turn fires it — MD §The
    // agent loop: "Esc cancels the stream and kills each running
    // tool's process group"). A spawn failure falls back to a no-op.
    let cancel_handle: Option<crate::worker::CancelHandle> = worker_spawner(spawn_ctx, cmd_tx).ok();

    // §9.13: the terminal's real cursor is a steady bar at the
    // insertion point while the composer is focused; restored on exit.
    let _ = crossterm::execute!(
        std::io::stdout(),
        crossterm::cursor::SetCursorStyle::SteadyBar
    );
    let guard = &mut guard;
    let mut last_tick = Instant::now();
    let boot_ms = Instant::now();
    let mut last_drawn = String::new();
    let mut overlay_dirty = true;

    loop {
        let timeout = UI_TICK
            .checked_sub(last_tick.elapsed())
            .unwrap_or(Duration::from_millis(0));
        let now_ms = boot_ms.elapsed().as_millis() as u64;
        tui.tick_ms = now_ms;
        // A deleted terminal (closed window, dead PTY) makes poll/read
        // fail with EIO — swallow nothing: treat any input error as
        // "terminal gone" and quit at once (the same rule as SIGHUP).
        // unwrap_or(false) here would busy-loop the EIO at 100% CPU.
        let ev = match event::poll(timeout) {
            Ok(true) => event::read().ok(),
            Ok(false) => None,
            Err(_) => break,
        };
        if let Some(ev) = ev {
            match ev {
                Event::Key(k) => {
                    overlay_dirty = true;
                    if handle_key(
                        k,
                        &mut tui,
                        &mut scenario,
                        &mut composer,
                        cancel_handle.as_ref(),
                        &command_sink,
                        &sender,
                        &approvals,
                        now_ms,
                        &mut overlay,
                        &mut palette_query,
                        &mut palette_sel,
                        &mut completion_sel,
                        &mut toast,
                        &mut queued,
                        &mut history,
                        &mut history_idx,
                        &mut pending_leader,
                        &mut want_copy_mode,
                        &mut sessions_pushed,
                        &mut scroll_offset,
                        &mut last_prompt,
                    ) {
                        break;
                    }
                }
                Event::Resize(w, h) => {
                    let _ = guard.terminal.resize(Rect {
                        x: 0,
                        y: 0,
                        width: w,
                        height: h,
                    });
                    overlay_dirty = true;
                }
                _ => {}
            }
        }
        if want_copy_mode {
            want_copy_mode = false;
            copy_mode(guard, &scenario);
        }
        if last_tick.elapsed() >= UI_TICK {
            last_tick = Instant::now();
            // Signals (SIGHUP/SIGTERM/SIGINT): exit at once — a
            // closed terminal must not leak the process.
            if let Some(sig) = crate::terminal::take_pending_signal() {
                let _ = sig;
                break;
            }
            // Drain the bus into the scenario.
            let msgs_before = scenario.state_version();
            while let Some(msg) = bus.try_recv() {
                apply_msg(msg, &mut scenario, now_ms);
            }
            let bus_dirty = scenario.state_version() != msgs_before;
            // The queue (§11.4): when the turn ends and prompts are
            // queued, the head becomes the next user turn.
            if !scenario.turn_live && !queued.is_empty() {
                let next = queued.remove(0);
                if let Some(pos) = scenario
                    .transcript
                    .iter()
                    .position(|l| l.kind == LineKind::Queued && l.text == next)
                {
                    scenario.transcript[pos].kind = LineKind::User;
                }
                let _ = command_sink.send(WorkerCommand::Prompt(next));
                scenario.turn_started_ms = now_ms;
                scenario.apply("round_started", 0);
            }
            let animating = scenario.is_turning() && !tui.reduced;
            // A pending approval card re-arms on a timer (§9.14) —
            // it must redraw as time passes.
            let card_armed = scenario.approval_pending.is_some()
                && now_ms.saturating_sub(scenario.last_key_ms) < 1500;
            // The breathing caret (§9.13, 0.9 Hz) is always live while
            // the composer holds focus — the idle screen must visibly
            // breathe, not render one dead frame ("frozen" bug). Draw
            // at the caret's pace (~2 changes/s) instead of the 16 ms
            // tick: same animation, a fraction of the redraws.
            let caret_breathes = !tui.reduced
                && tui.focus == Focus::Conversation
                && (now_ms / 550) != (now_ms.saturating_sub(UI_TICK.as_millis() as u64) / 550);
            if animating
                || bus_dirty
                || last_drawn != composer
                || overlay_dirty
                || card_armed
                || caret_breathes
            {
                last_drawn.clone_from(&composer);
                overlay_dirty = false;
                guard
                    .terminal
                    .draw(|f| {
                        draw(
                            f,
                            &tui,
                            &scenario,
                            &composer,
                            overlay,
                            &palette_query,
                            palette_sel,
                            toast.as_ref(),
                            sessions_pushed,
                            scroll_offset,
                        );
                    })
                    .unwrap();
            }
            // Toast expiry (§9.13): 3 s.
            if let Some(t) = &toast {
                if now_ms.saturating_sub(t.shown_ms) >= 3000 {
                    toast = None;
                }
            }
        }
    }

    let _ = guard;
    let _ = crossterm::execute!(
        std::io::stdout(),
        crossterm::cursor::SetCursorStyle::DefaultUserShape
    );
    // M8 / §9.24: one line to the scrollback after the screen closes.
    let session = if scenario.session_id.is_empty() {
        String::new()
    } else {
        format!(
            "\n         resume with orbit chat --resume {}",
            scenario.session_id
        )
    };
    let cost = if scenario.priced {
        format!("${:.4}", scenario.cost_microcents as f64 / 1_000_000.0)
    } else {
        "n/a".into()
    };
    println!(
        "✦ ORBIT  session saved · {} turns · {} in · {} out · {cost}{session}",
        scenario.turns, scenario.input_tokens, scenario.output_tokens
    );
    0
}

/// The keyboard (§11). Returns true to quit.
#[allow(clippy::too_many_arguments)]
fn handle_key(
    k: crossterm::event::KeyEvent,
    tui: &mut Tui,
    scenario: &mut Scenario,
    composer: &mut String,
    cancel_handle: Option<&crate::worker::CancelHandle>,
    command_sink: &CommandSink,
    sender: &BusSender,
    approvals: &ApprovalRegistry,
    now_ms: u64,
    overlay: &mut Option<Overlay>,
    palette_query: &mut String,
    palette_sel: &mut usize,
    completion_sel: &mut usize,
    toast: &mut Option<Toast>,
    queued: &mut Vec<String>,
    history: &mut Vec<String>,
    history_idx: &mut Option<usize>,
    pending_leader: &mut Option<char>,
    want_copy_mode: &mut bool,
    sessions_pushed: &mut bool,
    scroll_offset: &mut usize,
    last_prompt: &mut Option<String>,
) -> bool {
    let prev_key_ms = scenario.last_key_ms;
    scenario.last_key_ms = now_ms;
    // Ctrl+C / Ctrl+D (§11.7): the quit card, from anywhere.
    if k.modifiers.contains(KeyModifiers::CONTROL)
        && (k.code == KeyCode::Char('c') || k.code == KeyCode::Char('d'))
    {
        *overlay = Some(Overlay::Quit);
        return false;
    }
    // Overlays own the keyboard (§9.19–9.21).
    match overlay {
        Some(Overlay::Palette) => match k.code {
            KeyCode::Esc => *overlay = None,
            KeyCode::Up => *palette_sel = palette_sel.saturating_sub(1),
            KeyCode::Down => *palette_sel += 1,
            KeyCode::Enter => {
                let commands: Vec<&'static str> =
                    super::chrome::COMMANDS.iter().map(|(c, _)| *c).collect();
                let _ = commands;
                let matches: Vec<String> = super::chrome::COMMANDS
                    .iter()
                    .filter(|(c, _)| c.contains(palette_query.trim_start_matches('/')))
                    .map(|(c, _)| c.to_string())
                    .collect();
                if let Some(cmd) = matches.get(*palette_sel).cloned() {
                    *overlay = None;
                    palette_query.clear();
                    let mut fs = false;
                    if let Some(o) = run_command(
                        &cmd,
                        scenario,
                        composer,
                        command_sink,
                        sender,
                        now_ms,
                        toast,
                        queued,
                        history,
                        history_idx,
                        &mut fs,
                    ) {
                        *overlay = Some(o);
                    }
                    if fs {
                        tui.focus = Focus::Sessions;
                        *sessions_pushed = true;
                    }
                }
            }
            KeyCode::Char(c) => {
                palette_query.push(c);
                *palette_sel = 0;
            }
            KeyCode::Backspace => {
                palette_query.pop();
                *palette_sel = 0;
            }
            _ => {}
        },
        Some(Overlay::Help) => {
            if matches!(k.code, KeyCode::Esc | KeyCode::Enter | KeyCode::Char('?')) {
                *overlay = None;
            }
        }
        Some(Overlay::Quit) => {
            // §11.7: y quits; n or Esc closes the card.
            match k.code {
                KeyCode::Char('y') | KeyCode::Enter => return true,
                KeyCode::Esc | KeyCode::Char('n') => *overlay = None,
                _ => {}
            }
            return false;
        }
        None => {}
    }
    if overlay.is_some() {
        return false;
    }

    // The approval card (§9.14/§11.5): while a request is pending it
    // owns the keyboard.
    if let Some(call_id) = scenario.approval_call_id.clone() {
        // A decision key does nothing while disabled (§11.5): the
        // arming timer is 1000 ms since the last keypress.
        // The 1000 ms window runs to the PREVIOUS key: this key
        // press itself must not re-arm the card it decides (§9.14).
        let armed_disabled = now_ms.saturating_sub(prev_key_ms) < 1000;
        let response = match k.code {
            KeyCode::Char('y') | KeyCode::Char('Y') if !armed_disabled => {
                Some(crate::ApprovalResponse::Allow)
            }
            KeyCode::Char('R') if !armed_disabled => Some(crate::ApprovalResponse::AllowSession),
            KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc if !armed_disabled => {
                Some(crate::ApprovalResponse::Deny)
            }
            _ => None,
        };
        if let Some(resp) = response {
            let delivered = approvals.resolve(&call_id, resp);
            scenario.approval_queue.remove(0);
            if !delivered {
                // §11.5.3: the worker is gone — drop the request and
                // note it.
                scenario.transcript.push(TranscriptLine {
                    kind: LineKind::System,
                    text: "approval could not be delivered · the turn has ended".into(),
                    ..Default::default()
                });
                scenario.apply("approval_resolved", 0);
            } else if scenario.approval_queue.is_empty() {
                scenario.apply("approval_resolved", 0);
            } else {
                scenario.approval_shown_ms = now_ms;
            }
        }
        return false;
    }

    // Esc while a turn is live (no overlay, no approval card): cancel
    // the turn — MD §The agent loop: "Esc cancels the stream and kills
    // each running tool's process group". Outside a turn Esc keeps its
    // per-context meaning (close completion, defocus…).
    if k.code == KeyCode::Esc && scenario.is_turning() {
        if let Some(cancel) = &cancel_handle {
            cancel();
        }
        return false;
    }

    // z is a leader: z y enters copy mode (§11.2).
    if tui.focus == Focus::Conversation && k.code == KeyCode::Char('z') {
        *pending_leader = Some('z');
        return false;
    }
    if *pending_leader == Some('z') {
        *pending_leader = None;
        if k.code == KeyCode::Char('y') {
            *want_copy_mode = true;
            return false;
        }
    }

    // Focus keys (§11.1).
    match k.code {
        KeyCode::Tab => {
            let class = WidthClass::of(screen_width_hint(), 40);
            if class.single_view() {
                tui.focus = tui.focus.next_view();
            } else {
                tui.focus = tui.focus.next();
                match tui.focus {
                    Focus::Sessions => *sessions_pushed = true,
                    _ => *sessions_pushed = false,
                }
            }
            return false;
        }
        KeyCode::BackTab => {
            // Shift+Tab cycles the permission mode (S5, Claude Code
            // parity): default → acceptEdits → plan → dontAsk →
            // bypass → default. Focus cycling stays on Tab.
            const MODES: [&str; 5] = ["default", "acceptEdits", "plan", "dontAsk", "bypass"];
            let current = scenario
                .permission_mode
                .as_deref()
                .and_then(|m| MODES.iter().position(|c| *c == m))
                .unwrap_or(0);
            let next = MODES[(current + 1) % MODES.len()];
            let _ = command_sink.send(WorkerCommand::SetMode(next.to_string()));
            return false;
        }
        _ => {}
    }

    // The composer only takes keys when the Conversation is focused
    // (§8.5: unfocused composer shows no cursor, hint row blank).
    if tui.focus == Focus::Conversation {
        match k.code {
            KeyCode::Char('?') if composer.is_empty() => {
                *overlay = Some(Overlay::Help);
                return false;
            }
            KeyCode::Char('/') if composer.is_empty() => {
                composer.push('/');
                *completion_sel = 0;
                return false;
            }
            KeyCode::Enter if k.modifiers.contains(KeyModifiers::ALT) => {
                // §11.3: Alt+⏎ inserts a newline.
                composer.push('\n');
            }
            KeyCode::Enter => {
                // The shell bang (gate 1): `!command` runs one command
                // through the Bash tool's full path on the worker
                // thread — the composer stays responsive (the "!
                // sleep 5" gate).
                if composer.starts_with('!') && composer.trim().len() > 1 {
                    let command = composer.trim()[1..].trim().to_string();
                    composer.clear();
                    history.insert(0, format!("!{command}"));
                    *history_idx = None;
                    scenario.transcript.push(TranscriptLine {
                        kind: LineKind::Tool,
                        text: command.clone(),
                        tool_name: "Bash".into(),
                        tool_state: super::scenario::ToolState::Running,
                        ..Default::default()
                    });
                    let _ = command_sink.send(WorkerCommand::ShellBang(command));
                    return false;
                }
                if composer.starts_with('/') && !composer.trim().eq("/") {
                    let text = composer.trim().to_string();
                    composer.clear();
                    let mut fs = false;
                    if let Some(o) = run_command(
                        &text,
                        scenario,
                        composer,
                        command_sink,
                        sender,
                        now_ms,
                        toast,
                        queued,
                        history,
                        history_idx,
                        &mut fs,
                    ) {
                        *overlay = Some(o);
                    }
                    if fs {
                        tui.focus = Focus::Sessions;
                        *sessions_pushed = true;
                    }
                } else if !composer.trim().is_empty() && !composer.starts_with('/') {
                    let text = composer.trim().to_string();
                    composer.clear();
                    history.insert(0, text.clone());
                    *history_idx = None;
                    if scenario.turn_live {
                        queued.push(text.clone());
                        scenario.transcript.push(TranscriptLine {
                            kind: LineKind::Queued,
                            text,
                            ..Default::default()
                        });
                    } else {
                        scenario.transcript.push(TranscriptLine {
                            kind: LineKind::User,
                            text: text.clone(),
                            time: Some(now_hhmm()),
                            ..Default::default()
                        });
                        *last_prompt = Some(text.clone());
                        let _ = command_sink.send(WorkerCommand::Prompt(text.clone()));
                        scenario.turn_started_ms = now_ms;
                        scenario.apply("round_started", 0);
                        if scenario.transcript.len() == 1 {
                            scenario.first_prompt_waiting = true;
                        }
                    }
                } else if composer.is_empty() && scenario.last_failed {
                    // §11.3: an empty ⏎ after a failed turn resends
                    // it, with the toast.
                    if let Some(p) = last_prompt.clone() {
                        scenario.transcript.push(TranscriptLine {
                            kind: LineKind::User,
                            text: p.clone(),
                            time: Some(now_hhmm()),
                            ..Default::default()
                        });
                        let _ = command_sink.send(WorkerCommand::Prompt(p));
                        scenario.turn_started_ms = now_ms;
                        scenario.apply("round_started", 0);
                        *toast = Some(Toast {
                            text: "resent your last prompt".into(),
                            ok: true,
                            shown_ms: now_ms,
                        });
                    }
                }
            }
            KeyCode::Up if history_idx.is_none() && !history.is_empty() => {
                *history_idx = Some(0);
                composer.clear();
                composer.push_str(&history[0]);
            }
            KeyCode::Up => {
                if let Some(i) = *history_idx {
                    if i + 1 < history.len() {
                        *history_idx = Some(i + 1);
                        composer.clear();
                        composer.push_str(&history[i + 1]);
                    }
                }
            }
            KeyCode::Down => {
                if let Some(i) = *history_idx {
                    if i == 0 {
                        *history_idx = None;
                        composer.clear();
                    } else {
                        *history_idx = Some(i - 1);
                        composer.clear();
                        composer.push_str(&history[i - 1]);
                    }
                }
            }
            KeyCode::Backspace => {
                composer.pop();
            }
            KeyCode::Esc => {
                // §11.3: Esc closes the completion list; otherwise
                // nothing (the draft is kept).
                if composer == "/" {
                    composer.clear();
                }
            }
            KeyCode::PageUp => {
                *scroll_offset += 8;
            }
            KeyCode::PageDown => {
                *scroll_offset = scroll_offset.saturating_sub(8);
            }
            KeyCode::End => {
                *scroll_offset = 0;
            }

            _ => {}
        }
        if let KeyCode::Char(c) = k.code {
            if k.modifiers.contains(KeyModifiers::CONTROL) && c == 'w' {
                // Ctrl+W: delete the previous word.
                let trimmed = composer.trim_end_matches(' ');
                if let Some(pos) = trimmed.rfind(' ') {
                    composer.truncate(pos);
                } else {
                    composer.clear();
                }
            } else {
                let ch = if k.modifiers.contains(KeyModifiers::SHIFT) {
                    c.to_uppercase().next().unwrap_or(c)
                } else {
                    c
                };
                composer.push(ch);
            }
        }
        return false;
    }

    // Rail / status focused (§11.2 context 4).
    match k.code {
        KeyCode::Char('1') => tui.focus = Focus::Sessions,
        KeyCode::Char('2') => tui.focus = Focus::Conversation,
        KeyCode::Char('3') => tui.focus = Focus::Workspace,
        KeyCode::Char('/') => *overlay = Some(Overlay::Palette),
        KeyCode::Char('?') => *overlay = Some(Overlay::Help),
        KeyCode::Char('q') => *overlay = Some(Overlay::Quit),
        KeyCode::Esc => tui.focus = Focus::Conversation,
        _ => {}
    }
    false
}

/// The terminal width for focus decisions between draws.
fn screen_width_hint() -> u16 {
    crossterm::terminal::size().map(|(w, _)| w).unwrap_or(100)
}

fn now_hhmm() -> String {
    chrono::Local::now().format("%H:%M").to_string()
}

/// Duration per §7.3: tenths below 10 s, else whole seconds, else m:ss.
pub(crate) fn format_duration(ms: u64) -> (String, f64) {
    let t = (ms + 50) / 100;
    if t < 100 {
        return (format!("{}.{}s", t / 10, t % 10), 0.0);
    }
    let secs = (ms + 500) / 1000;
    if secs < 60 {
        (format!("{secs}s"), 0.0)
    } else {
        (format!("{}m {:02}s", secs / 60, secs % 60), 0.0)
    }
}

/// Copy mode (§9.25): leave the alt screen, print the transcript,
/// wait for a key, return.
fn copy_mode(guard: &mut crate::terminal::TerminalGuard, scenario: &Scenario) {
    let _ = guard.terminal.draw(|_| {});
    let mut stdout = std::io::stdout();
    let _ = crossterm::execute!(stdout, crossterm::terminal::LeaveAlternateScreen);
    // §9.25: one event per line, no box drawing or colour.
    let sid = if scenario.session_id.is_empty() {
        "—".to_string()
    } else {
        scenario.session_id.clone()
    };
    println!("ORBIT transcript · session {sid} · select and copy, then press any key to return");
    for l in &scenario.transcript {
        let t = l.time.clone().unwrap_or_default();
        match l.kind {
            LineKind::User => {
                if t.is_empty() {
                    println!("you: {}", l.text);
                } else {
                    println!("{t} you: {}", l.text);
                }
            }
            LineKind::Model => {
                if t.is_empty() {
                    println!("orbit: {}", l.text);
                } else {
                    println!("{t} orbit: {}", l.text);
                }
            }
            LineKind::Tool => {
                let state = match l.tool_state {
                    ToolState::Done => ": done".to_string(),
                    ToolState::Denied => ": denied by you".into(),
                    ToolState::Failed => ": failed".into(),
                    ToolState::Running => ": running".into(),
                    ToolState::AwaitingYou => ": awaiting you".into(),
                    ToolState::Queued => ": queued".into(),
                    ToolState::Blocked => ": blocked".into(),
                };
                if t.is_empty() {
                    println!("tool {} {}{}", l.tool_name, l.text, state);
                } else {
                    println!("{t} tool {} {}{}", l.tool_name, l.text, state);
                }
            }
            LineKind::System => println!("status: {}", l.text),
            LineKind::Queued => println!("queued: {}", l.text),
        }
    }
    let _ = event::read();
    let _ = crossterm::execute!(stdout, crossterm::terminal::EnterAlternateScreen);
    guard.terminal.clear().ok();
}

/// Run a `/command` or bare `quit`/`exit` (§11.6). TUI-local ones
/// run at once; the rest go to the worker in order.
#[allow(clippy::too_many_arguments)]
fn run_command(
    text: &str,
    scenario: &mut Scenario,
    composer: &mut String,
    command_sink: &CommandSink,
    sender: &BusSender,
    now_ms: u64,
    toast: &mut Option<Toast>,
    queued: &mut Vec<String>,
    history: &mut Vec<String>,
    history_idx: &mut Option<usize>,
    focus_sessions: &mut bool,
) -> Option<Overlay> {
    let _ = (composer, queued, history, history_idx, sender, now_ms);
    if text == "quit" || text == "exit" {
        return Some(Overlay::Quit);
    }
    let (cmd, arg) = match text.split_once(' ') {
        Some((c, a)) => (c, a.trim()),
        None => (text, ""),
    };
    let notice = |s: &mut Scenario, t: String| {
        s.transcript.push(TranscriptLine {
            kind: LineKind::System,
            text: t,
            ..Default::default()
        });
    };
    let open: Option<Overlay> = match cmd {
        "/help" => Some(Overlay::Help),
        "/sessions" => {
            // §11.6: focus the Sessions rail (or view).
            *focus_sessions = true;
            None
        }
        "/usage" => {
            let cost = if scenario.priced {
                format!("${:.4}", scenario.cost_microcents as f64 / 1_000_000.0)
            } else {
                "n/a".into()
            };
            notice(
                scenario,
                format!(
                    "turns {} · in {} · out {} · {cost}",
                    scenario.turns, scenario.input_tokens, scenario.output_tokens
                ),
            );
            None
        }
        "/models" => {
            let _ = command_sink.send(WorkerCommand::ListModels);
            None
        }
        "/model" => {
            if arg.is_empty() {
                notice(scenario, "usage: /model <model-id>".into());
            } else {
                let _ = command_sink.send(WorkerCommand::SetModel(arg.to_string()));
            }
            None
        }
        "/resume" => {
            if arg.is_empty() {
                notice(scenario, "usage: /resume <session-id>".into());
            } else if scenario.turn_live {
                *toast = Some(Toast {
                    text: "wait for this turn to finish first".into(),
                    ok: false,
                    shown_ms: now_ms,
                });
            } else {
                let _ = command_sink.send(WorkerCommand::ResumeSession(arg.to_string()));
            }
            None
        }
        "/clear" => {
            let _ = command_sink.send(WorkerCommand::Compact);
            scenario.transcript.clear();
            notice(
                scenario,
                "conversation cleared · earlier turns are no longer sent to the model".into(),
            );
            None
        }
        "/compact" => {
            let _ = command_sink.send(WorkerCommand::Compact);
            None
        }
        _ => {
            notice(scenario, format!("unknown command: {cmd} · try /help"));
            None
        }
    };
    open
}

/// FrontendEvent-shaped Msgs → the scenario reducer.
fn apply_msg(msg: crate::msg::Msg, scenario: &mut Scenario, now_ms: u64) {
    use crate::msg::Msg;
    match msg {
        Msg::TextDelta(text) => {
            scenario.apply("text_delta", 0);
            scenario.last_data_ms = now_ms;
            match scenario.transcript.last_mut() {
                Some(l) if l.kind == LineKind::Model => l.text.push_str(&text),
                _ => scenario.transcript.push(TranscriptLine {
                    kind: LineKind::Model,
                    text,
                    ..Default::default()
                }),
            }
        }
        Msg::ToolCallStarted { name, summary } => {
            scenario.running.insert(name.clone(), name.clone());
            scenario.apply("tool_started_full", 0);
            scenario.turn_tools += 1;
            // The tool line (§9.8): glyph + name + the display-safe
            // argument (the summary without `name(` … `)`).
            let arg = summary
                .strip_prefix(&format!("{name}("))
                .and_then(|s| s.strip_suffix(')'))
                .unwrap_or(summary.as_str());
            scenario.transcript.push(TranscriptLine {
                kind: LineKind::Tool,
                text: arg.to_string(),
                tool_name: name.clone(),
                tool_state: super::scenario::ToolState::Running,
                ..Default::default()
            });
        }
        Msg::ToolCallFinished { name, outcome } => {
            scenario.running.remove(&name);
            scenario.apply("tool_finished_full", 0);
            for l in scenario.transcript.iter_mut().rev() {
                if l.kind == LineKind::Tool && l.tool_name == name {
                    // §9.8: the final state comes only from the
                    // worker's outcome (never optimistic).
                    let dur = l
                        .started_ms
                        .map(|st| now_ms.saturating_sub(st))
                        .unwrap_or(0);
                    let (ds, _) = format_duration(dur);
                    match outcome {
                        crate::state::ToolOutcome::Ok => {
                            l.tool_state = super::scenario::ToolState::Done;
                            l.meta = format!("done · {ds}");
                        }
                        crate::state::ToolOutcome::Denied => {
                            l.tool_state = super::scenario::ToolState::Denied;
                            l.meta = String::new();
                        }
                        crate::state::ToolOutcome::Failed => {
                            l.tool_state = super::scenario::ToolState::Failed;
                            l.meta = format!("failed · {ds}");
                        }
                        crate::state::ToolOutcome::Blocked => {
                            l.tool_state = super::scenario::ToolState::Blocked;
                            l.meta = "blocked · unknown tool".into();
                        }
                    }
                    break;
                }
            }
        }
        Msg::ApprovalRequested {
            call_id,
            tool_name,
            summary,
            ..
        } => {
            scenario.approval_pending = Some(tool_name.clone());
            scenario.approval_call_id = Some(call_id.clone());
            scenario.approval_queue.push(tool_name.clone());
            scenario.approval_summary = Some(summary.clone());
            scenario.approval_shown_ms = now_ms;
            scenario.apply("approval_requested", 0);
        }
        Msg::ResponseFinished {
            output_tokens,
            input_tokens,
            cost_microcents,
            ..
        } => {
            scenario.turns += 1;
            scenario.input_tokens += input_tokens;
            scenario.output_tokens += output_tokens;
            scenario.cost_microcents += cost_microcents;
            scenario.turn_report = Some(TurnReport {
                duration_ms: now_ms.saturating_sub(scenario.turn_started_ms),
                tools: scenario.turn_tools,
                cost_microcents,
                priced: scenario.priced,
            });
            scenario.apply("turn_ended", 0);
        }
        Msg::SystemMessage(text) => {
            // §11.6: one notice per line (`/models` rows, session
            // lists), `muted`, at the content column.
            for line in text.split('\n') {
                scenario.transcript.push(TranscriptLine {
                    kind: LineKind::System,
                    text: line.to_string(),
                    ..Default::default()
                });
            }
        }
        Msg::Status(text) => {
            scenario.tool_output.push(text.clone());
            scenario.transcript.push(TranscriptLine {
                kind: LineKind::System,
                text,
                ..Default::default()
            });
        }
        Msg::ModeChanged(mode) => {
            // S5: Shift+Tab's next cycle reads this; the toast comes
            // from the reducer.
            scenario.permission_mode = Some(mode);
        }
        Msg::Identity {
            model,
            provider,
            session_prefix,
            session_id,
            priced,
        } => {
            scenario.model = model.clone();
            scenario.model_id = model;
            scenario.provider = provider;
            scenario.session_prefix = session_prefix;
            scenario.session_id = session_id;
            scenario.priced = priced;
        }
        Msg::BackendError(err) => {
            // The turn error card (§9.11): ✕ This turn failed + the
            // gated message + the resend hint.
            scenario.transcript.push(TranscriptLine {
                kind: LineKind::System,
                text: format!("✕ This turn failed · {err}"),
                ..Default::default()
            });
            scenario.transcript.push(TranscriptLine {
                kind: LineKind::System,
                text: "⏎ on an empty composer resends it".into(),
                ..Default::default()
            });
            scenario.apply("turn_failed", 0);
        }
        _ => {}
    }
}

// ── The draw (§8, §9) ─────────────────────────────────────────────

/// The whole screen: headers/switcher, panes, dividers, composer,
/// hint row, status line, overlays.
#[allow(clippy::too_many_arguments)]
pub fn draw(
    f: &mut ratatui::Frame,
    tui: &Tui,
    scenario: &Scenario,
    composer: &str,
    overlay: Option<Overlay>,
    palette_query: &str,
    palette_sel: usize,
    toast: Option<&Toast>,
    sessions_pushed: bool,
    scroll_offset: usize,
) {
    let area = f.area();
    // The size notice (§9.23): below 40 × 10 it is the whole screen.
    if area.width < 40 || area.height < 10 {
        let lines = super::chrome::size_notice_lines(area.width, area.height);
        let star = Line::from(Span::styled(
            "✦",
            Style::default().fg(comps::colour(Token::Magenta)),
        ));
        let mut out = vec![star];
        out.extend(lines);
        f.render_widget(Paragraph::new(out), area);
        return;
    }
    let scr = Screen::resolve(area, sessions_pushed);
    let (_cl, _cw) = scr.conv_column();

    // Row 0: pane headers (§9.1) or the view switcher (§9.2).
    draw_row0(f, &scr, tui, scenario);

    // The panes.
    if let Some(left) = scr.left {
        draw_sessions_rail(f, left, tui.focus == Focus::Sessions, scenario);
    }
    draw_conversation(f, &scr, tui, scenario, composer, scroll_offset);
    if let Some(right) = scr.right {
        draw_workspace_rail(f, right, tui.focus == Focus::Workspace, scenario);
    }

    // The dividers (§8.6): one column of │, row 0 … H−2.
    for (x, y0, y1) in &scr.dividers {
        let r = Rect {
            x: *x,
            y: *y0,
            width: 1,
            height: y1.saturating_sub(*y0) + 1,
        };
        for y in r.y..r.bottom() {
            f.render_widget(
                Paragraph::new(Line::from(Span::styled(
                    "│",
                    Style::default().fg(comps::colour(Token::Rule)),
                ))),
                Rect {
                    x: *x,
                    y,
                    width: 1,
                    height: 1,
                },
            );
        }
    }

    // The approval card (§9.14) replaces the composer while a
    // request is pending; the draft is kept untouched.
    if scenario.approval_pending.is_some() {
        super::view::approval_card(f, &scr, scenario, tui.tick_ms);
    } else {
        draw_composer(f, &scr, tui, scenario, composer, toast);
    }

    // The status line (§9.18).
    draw_status(f, &scr, tui, scenario);

    // The overlays (§9.19–9.21), on top of everything.
    match overlay {
        Some(Overlay::Palette) => {
            let r = super::chrome::palette_area(area);
            let lines = super::chrome::palette_lines(palette_query, palette_sel);
            super::chrome::overlay(f, r, "Commands", lines, Some("esc close · ⏎ run"));
        }
        Some(Overlay::Help) => {
            let r = super::chrome::help_area(area);
            let lines = super::chrome::help_lines();
            super::chrome::overlay(f, r, "Keys", lines, Some("esc close"));
        }
        Some(Overlay::Quit) => {
            let (r, lines) = super::chrome::quit_card(scenario.turn_live, area);
            super::chrome::overlay(f, r, "Quit ORBIT?", lines, None);
        }
        None => {}
    }
}

/// Row 0: the pane headers (§9.1) or the view switcher (§9.2).
fn draw_row0(f: &mut ratatui::Frame, scr: &Screen, tui: &Tui, scenario: &Scenario) {
    let area = scr.header;
    if scr.class.single_view() {
        // §9.2: ` Sessions   Conversation   Workspace n/m ━━━…`
        let active = match tui.focus {
            Focus::Sessions => 0,
            Focus::Conversation => 1,
            Focus::Workspace => 2,
            Focus::Status => 1,
        };
        let mut spans: Vec<Span> = Vec::new();
        for (i, name) in ["Sessions", "Conversation", "Workspace"].iter().enumerate() {
            if i > 0 {
                spans.push(Span::raw("   "));
            }
            if i == active {
                spans.push(Span::styled(
                    *name,
                    Style::default()
                        .fg(comps::colour(Token::Magenta))
                        .add_modifier(Modifier::BOLD),
                ));
            } else if i == 2 && scenario.workspace_empty() {
                spans.push(Span::styled(
                    *name,
                    Style::default().fg(comps::colour(Token::Faint)),
                ));
            } else {
                spans.push(Span::styled(
                    *name,
                    Style::default().fg(comps::colour(Token::Muted)),
                ));
            }
        }
        // n/m: completed/total plan tasks (none today → `0/0` muted).
        spans.push(Span::raw(" "));
        spans.push(Span::styled(
            "0/0",
            Style::default().fg(comps::colour(Token::Muted)),
        ));
        // The heavy rule fills the rest.
        let used: u16 = spans.iter().map(|s| s.width() as u16).sum();
        let rule_w = area.width.saturating_sub(used + 1).saturating_sub(1);
        spans.push(Span::styled(" ".to_string(), Style::default()));
        spans.push(Span::styled(
            "━".repeat(rule_w as usize),
            Style::default().fg(comps::colour(Token::RuleHi)),
        ));
        f.render_widget(Paragraph::new(Line::from(spans)), area);
        return;
    }
    // §9.1: one shared header row, per pane.
    if let Some(left) = scr.left {
        let focused = tui.focus == Focus::Sessions;
        let mut first = true;
        let mut spans = Vec::new();
        for (i, tab) in ["Sessions", "Activity"].iter().enumerate() {
            if i > 0 {
                spans.push(Span::raw("  "));
            }
            let tab_disp = if first {
                format!(" {tab}")
            } else {
                tab.to_string()
            };
            first = false;
            spans.push(Span::styled(
                tab_disp,
                if focused {
                    Style::default()
                        .fg(comps::colour(Token::Magenta))
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default()
                        .fg(comps::colour(Token::Ink))
                        .add_modifier(Modifier::BOLD)
                },
            ));
        }
        let used: u16 = spans.iter().map(|s| s.width() as u16).sum();
        // One air column after the tabs and one before the divider.
        let rule_w = left.w.saturating_sub(used + 2);
        spans.push(Span::raw(" "));
        spans.push(Span::styled(
            (if focused { "━" } else { "─" }).repeat(rule_w as usize),
            Style::default().fg(comps::colour(if focused {
                Token::RuleHi
            } else {
                Token::Rule
            })),
        ));
        f.render_widget(
            Paragraph::new(Line::from(spans)),
            Rect {
                x: left.x,
                y: area.y,
                width: left.w,
                height: 1,
            },
        );
    }
    // Conversation header: title + `n turns` meta.
    {
        let conv = scr.conv;
        let focused = tui.focus == Focus::Conversation;
        let title = if scenario.transcript.is_empty() {
            "New session".to_string()
        } else {
            scenario.session_title()
        };
        let meta = if scenario.turns == 0 {
            String::new()
        } else if scenario.turns == 1 {
            "1 turn".into()
        } else {
            format!("{} turns", scenario.turns)
        };
        let meta_w = meta.len() as u16;
        let title_budget = conv.w.saturating_sub(7 + meta_w).max(3);
        let title = truncate_end(&title, title_budget as usize);
        let title_w = title.width();
        let mut spans = vec![
            Span::raw(" "),
            Span::styled(
                title,
                if focused {
                    Style::default()
                        .fg(comps::colour(Token::Magenta))
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default()
                        .fg(comps::colour(Token::Ink))
                        .add_modifier(Modifier::BOLD)
                },
            ),
        ];
        let used: u16 = 1 + title_w as u16;
        // The rule ends one column short of the divider; the meta
        // rides at its right end behind one air column.
        let reserved = if meta.is_empty() { 1 } else { meta_w + 2 };
        let rule_end = conv.w.saturating_sub(reserved);
        let rule_w = rule_end.saturating_sub(used + 1);
        if rule_w > 0 {
            spans.push(Span::raw(" "));
            spans.push(Span::styled(
                (if focused { "━" } else { "─" }).repeat(rule_w as usize),
                Style::default().fg(comps::colour(if focused {
                    Token::RuleHi
                } else {
                    Token::Rule
                })),
            ));
        }
        if !meta.is_empty() {
            spans.push(Span::raw(" "));
            spans.push(Span::styled(
                meta,
                Style::default().fg(comps::colour(Token::Muted)),
            ));
        }
        f.render_widget(
            Paragraph::new(Line::from(spans)),
            Rect {
                x: conv.x,
                y: area.y,
                width: conv.w,
                height: 1,
            },
        );
    }
    if let Some(right) = scr.right {
        let focused = tui.focus == Focus::Workspace;
        let mut spans = vec![
            Span::raw(" "),
            Span::styled(
                "Workspace",
                if focused {
                    Style::default()
                        .fg(comps::colour(Token::Magenta))
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default()
                        .fg(comps::colour(Token::Ink))
                        .add_modifier(Modifier::BOLD)
                },
            ),
        ];
        let used: u16 = spans.iter().map(|s| s.width() as u16).sum();
        let rule_w = right.w.saturating_sub(used + 1);
        spans.push(Span::raw(" "));
        spans.push(Span::styled(
            (if focused { "━" } else { "─" }).repeat(rule_w as usize),
            Style::default().fg(comps::colour(if focused {
                Token::RuleHi
            } else {
                Token::Rule
            })),
        ));
        f.render_widget(
            Paragraph::new(Line::from(spans)),
            Rect {
                x: right.x,
                y: area.y,
                width: right.w,
                height: 1,
            },
        );
    }
}

/// The Sessions rail (§9.15): groups + rows. Today only the open
/// session exists (§13), so the rail shows TODAY + the open row.
fn draw_sessions_rail(
    f: &mut ratatui::Frame,
    pane: super::screen::Pane,
    focused: bool,
    scenario: &Scenario,
) {
    let x = pane.x;
    let w = pane.w;
    let mut y = pane.y;
    // Section label.
    f.render_widget(
        Paragraph::new(Line::from(Span::styled(
            "TODAY",
            Style::default().fg(comps::colour(Token::Muted)),
        ))),
        Rect {
            x: x + 2,
            y,
            width: (w - 2),
            height: 1,
        },
    );
    y += 2;
    // The open session row (§8.4): ▌/state glyph at x+1, title x+3.
    let title = if scenario.session_title().is_empty() {
        "New session".to_string()
    } else {
        scenario.session_title()
    };
    let fill = if focused {
        comps::colour(Token::Wash)
    } else {
        comps::colour(Token::Surface2)
    };
    let spans = vec![
        Span::styled("▌", Style::default().fg(comps::colour(Token::Magenta))),
        Span::styled(" ", Style::default()),
        Span::styled(
            title,
            Style::default()
                .fg(comps::colour(Token::Ink))
                .add_modifier(Modifier::BOLD),
        ),
    ];
    let line = Line::from(spans);
    let row = Rect {
        x,
        y,
        width: w,
        height: 1,
    };
    f.render_widget(Paragraph::new(line).style(Style::default().bg(fill)), row);
    let _ = spans;
}

/// The Workspace rail (§9.17): the phase stepper + sections. Empty
/// today (§13) → the empty state.
fn draw_workspace_rail(
    f: &mut ratatui::Frame,
    pane: super::screen::Pane,
    focused: bool,
    scenario: &Scenario,
) {
    let x = pane.x;
    let w = pane.w;
    let mut y = pane.y;
    // Empty (§9.17): no stepper yet — nothing is planned, so the rail
    // opens straight on the empty state. EXCEPT while a turn runs: the
    // stepper is the rail's live heartbeat (the star's twin), and a
    // "Nothing planned yet" placeholder during an active turn reads as
    // a dead screen.
    if scenario.tasks.is_empty() && scenario.file_changes.is_empty() && !scenario.is_turning() {
        // Empty state (§9.17).
        f.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled("◌", Style::default().fg(comps::colour(Token::Faint))),
                Span::raw(" "),
                Span::styled(
                    "Nothing planned yet.",
                    Style::default().fg(comps::colour(Token::Ink2)),
                ),
            ])),
            Rect {
                x: x + 2,
                y,
                width: w.saturating_sub(2),
                height: 1,
            },
        );
        y += 2;
        let help =
            "When a task has steps, the plan, findings and verification evidence collect here.";
        f.render_widget(
            Paragraph::new(Line::from(Span::styled(
                help,
                Style::default().fg(comps::colour(Token::Muted)),
            )))
            .wrap(ratatui::widgets::Wrap { trim: false }),
            Rect {
                x: x + 4,
                y,
                width: w.saturating_sub(4),
                height: 4,
            },
        );
        let _ = focused;
        return;
    }
    // The phase stepper (§9.17): 5 nodes, current = phase_index().
    let phases = ["init", "plan", "execute", "verify", "checkpoint"];
    let cur = scenario.phase_index().min(4);
    let mut spans: Vec<Span> = Vec::new();
    for (i, _) in phases.iter().enumerate() {
        if i > 0 {
            spans.push(Span::styled(
                if i <= cur { "━━" } else { "──" },
                Style::default().fg(comps::colour(if i <= cur {
                    Token::Muted
                } else {
                    Token::Rule
                })),
            ));
        }
        let (g, c) = if i < cur {
            ("✓", Token::Muted)
        } else if i == cur {
            ("◉", Token::Cyan)
        } else {
            ("◌", Token::Faint)
        };
        spans.push(Span::styled(g, Style::default().fg(comps::colour(c))));
    }
    spans.push(Span::raw("  "));
    spans.push(Span::styled(
        phases[cur],
        Style::default()
            .fg(comps::colour(Token::Cyan))
            .add_modifier(Modifier::BOLD),
    ));
    // k/5 right-aligned.
    let done = scenario.tasks.iter().filter(|t| t.status == "done").count();
    let k5 = format!("{}/{}", done, scenario.tasks.len());
    let used: u16 = spans.iter().map(|s| s.width() as u16).sum();
    let pad = w.saturating_sub(2 + used + 2 + k5.len() as u16 + 1);
    spans.push(Span::raw(" ".repeat(pad.max(1) as usize)));
    spans.push(Span::styled(
        k5,
        Style::default().fg(comps::colour(Token::Muted)),
    ));
    f.render_widget(
        Paragraph::new(Line::from(spans)),
        Rect {
            x: x + 2,
            y,
            width: w.saturating_sub(2),
            height: 1,
        },
    );
    y += 2;

    // PLAN section: label + count right-aligned, then task rows (§9.17).
    let label = |t: &str| {
        Span::styled(
            t.to_string(),
            Style::default().fg(comps::colour(Token::Muted)),
        )
    };
    if !scenario.tasks.is_empty() {
        let count = format!("{}", scenario.tasks.len());
        let used = 5u16 + count.len() as u16;
        let pad = w.saturating_sub(2 + used + 2);
        f.render_widget(
            Paragraph::new(Line::from(vec![
                label("PLAN"),
                Span::raw(" ".repeat(pad.max(1) as usize)),
                label(&count),
            ])),
            Rect {
                x: x + 2,
                y,
                width: w.saturating_sub(2),
                height: 1,
            },
        );
        y += 1;
        for t in &scenario.tasks {
            if y >= pane.y + pane.h {
                break;
            }
            let active = t.status == "active" || t.status == "running";
            let (g, gc) = if active {
                ("◉", Token::Cyan)
            } else if t.status == "done" {
                ("✓", Token::Ink2)
            } else {
                ("◌", Token::Faint)
            };
            let title_colour = if active { Token::Ink } else { Token::Ink2 };
            let mut spans = vec![
                Span::styled(g, Style::default().fg(comps::colour(gc))),
                Span::raw(" "),
                Span::styled(
                    t.title.clone(),
                    Style::default()
                        .fg(comps::colour(title_colour))
                        .add_modifier(if active {
                            Modifier::BOLD
                        } else {
                            Modifier::empty()
                        }),
                ),
            ];
            if active && !t.status.is_empty() {
                spans.push(Span::styled(
                    format!("  running · {}", t.status),
                    Style::default().fg(comps::colour(Token::Cyan)),
                ));
            }
            f.render_widget(
                Paragraph::new(Line::from(spans)),
                Rect {
                    x: x + 2,
                    y,
                    width: w.saturating_sub(2),
                    height: 1,
                },
            );
            y += 1;
        }
    }
}

/// The conversation column (§8.3/§9.4–9.12): the transcript,
/// bottom-anchored.
fn draw_conversation(
    f: &mut ratatui::Frame,
    scr: &Screen,
    tui: &Tui,
    scenario: &Scenario,
    composer: &str,
    scroll_offset: usize,
) {
    let _ = composer;
    let pane = scr.conv;
    let (cl, cw) = scr.conv_column();
    let view = pane.h as usize;
    let mut lines: Vec<Line> = Vec::new();
    if scenario.transcript.is_empty() {
        // The welcome block (§9.22), placed at 2 + free/3 from the
        // pane top, centred per line.
        let welcome = super::welcome::Welcome {
            tier: tui.brand_tier,
            first_prompt_waiting: scenario.first_prompt_waiting,
        };
        let block = welcome.lines_in(tui.tick_ms, pane.w, &scenario.welcome_chips);
        let free = view.saturating_sub(block.len());
        for _ in 0..(free / 3) {
            lines.push(Line::from(""));
        }
        lines.extend(block);
    } else {
        let body = super::view::transcript_lines(scenario, cl, cw, scr.class);
        // §8.3: the transcript is bottom-anchored — a short one sits
        // against the composer, not at the top of the pane.
        for _ in 0..view.saturating_sub(body.len()) {
            lines.push(Line::from(""));
        }
        lines.extend(body);
    }
    // start = max(0, total − view − offset) (§8.6).
    let total = lines.len();
    let start = total.saturating_sub(view).saturating_sub(scroll_offset);
    let shown: Vec<Line> = lines.into_iter().skip(start).take(view).collect();
    f.render_widget(
        Paragraph::new(shown),
        Rect {
            x: pane.x,
            y: pane.y,
            width: pane.w,
            height: pane.h,
        },
    );
}

/// The composer (§9.13): the surface band, `›` at cl−1, text from
/// cl+1, the hint row below.
fn draw_composer(
    f: &mut ratatui::Frame,
    scr: &Screen,
    tui: &Tui,
    scenario: &Scenario,
    composer: &str,
    toast: Option<&Toast>,
) {
    let (cl, cw) = scr.conv_column();
    let focused = tui.focus == Focus::Conversation;
    // The band spans cl−2 … cl+cw on the input row and the hint row.
    let band_x = cl.saturating_sub(2);
    let band_w = cw + 3;
    let band = Rect {
        x: band_x,
        y: scr.composer.y,
        width: band_w,
        height: 1 + if scr.hint.is_some() { 1 } else { 0 },
    };
    f.render_widget(
        ratatui::widgets::Block::default()
            .style(Style::default().bg(comps::colour(Token::Surface))),
        band,
    );
    // `›` at cl−1; text from cl+1.
    let prompt_colour = if focused {
        Token::Magenta
    } else {
        Token::Faint
    };
    let placeholder = if scenario.turn_live {
        if scr.class == WidthClass::Tight {
            "Add to the queue, or wait"
        } else {
            "Add to the queue, or wait for ORBIT"
        }
    } else {
        "Ask ORBIT, or type / for commands"
    };
    let text_span = if composer.is_empty() {
        Span::styled(
            placeholder,
            Style::default().fg(comps::colour(Token::Faint)),
        )
    } else {
        Span::styled(
            composer.to_string(),
            Style::default().fg(comps::colour(Token::Ink)),
        )
    };
    let spans = vec![
        Span::raw(" "),
        Span::styled("›", Style::default().fg(comps::colour(prompt_colour))),
        Span::raw("  "),
        text_span,
    ];
    f.render_widget(
        Paragraph::new(Line::from(spans)),
        Rect {
            x: band_x,
            y: scr.composer.y,
            width: band_w,
            height: 1,
        },
    );
    // The hint row (§9.13): keycaps + the context hint, toast right.
    if let Some(hint_area) = scr.hint {
        let hint = if focused {
            hint_row(scenario, scr.class, toast)
        } else {
            Line::from("")
        };
        // The hint starts at cl+1, aligned under the composer text.
        let hx = (cl + 1).min(hint_area.right());
        f.render_widget(
            Paragraph::new(hint),
            Rect {
                x: hx,
                y: hint_area.y,
                width: hint_area.right().saturating_sub(hx),
                height: hint_area.height,
            },
        );
    }
}

/// The hint row (§9.13): `⏎ send`, `⇧⏎ newline`, `/ commands`, then
/// the first applicable context hint; toasts end at cl+cw−1.
fn hint_row(scenario: &Scenario, class: WidthClass, toast: Option<&Toast>) -> Line<'static> {
    let key = |k: &str| {
        Span::styled(
            k.to_string(),
            Style::default()
                .fg(comps::colour(Token::Ink))
                .add_modifier(Modifier::BOLD),
        )
    };
    let label = |l: &'static str| {
        Span::styled(
            format!(" {l}"),
            Style::default().fg(comps::colour(Token::Muted)),
        )
    };
    let mut spans = Vec::new();
    if scenario.turn_live {
        spans.push(key("⏎"));
        spans.push(label("queue"));
        spans.push(Span::raw("   "));
        spans.push(key("⇧⏎"));
        spans.push(label("newline"));
    } else {
        spans.push(key("⏎"));
        spans.push(label("send"));
        spans.push(Span::raw("   "));
        spans.push(key("⇧⏎"));
        spans.push(label("newline"));
        spans.push(Span::raw("   "));
        spans.push(key("/"));
        spans.push(label("commands"));
    }
    // The context hint: first that applies.
    if class.single_view() {
        spans.push(Span::raw("   "));
        spans.push(key("tab"));
        spans.push(label("views"));
    } else if class == WidthClass::Medium {
        spans.push(Span::raw("   "));
        spans.push(key("⇧tab"));
        spans.push(label("sessions"));
    }
    if let Some(t) = toast {
        spans.push(Span::raw("   "));
        if t.ok {
            spans.push(Span::styled(
                "✓ ",
                Style::default().fg(comps::colour(Token::Green)),
            ));
        }
        spans.push(Span::styled(
            t.text.clone(),
            Style::default().fg(comps::colour(Token::Muted)),
        ));
    }
    Line::from(spans)
}

/// The status line (§9.18): mark + activity left, the right cluster
/// by level.
fn draw_status(f: &mut ratatui::Frame, scr: &Screen, tui: &Tui, scenario: &Scenario) {
    let area = scr.status;
    let star = tui.star_glyph(scenario);
    let star_colour = comps::colour(match star.colour {
        super::anim::StarColour::Cyan => Token::Cyan,
        super::anim::StarColour::Magenta => Token::Magenta,
        super::anim::StarColour::Amber => Token::Amber,
        super::anim::StarColour::Red => Token::Red,
    });
    // The activity, first match wins (§9.18).
    let elapsed_s = |now: u64, from: u64| {
        let d = now.saturating_sub(from);
        if d >= 1000 {
            format!(" · {}s", d / 1000)
        } else {
            String::new()
        }
    };
    let activity_spans: Vec<Span> = match scenario.activity() {
        Activity::Approval(t) => vec![Span::styled(
            format!("◇ approval needed · {t}"),
            Style::default().fg(comps::colour(Token::Magenta)),
        )],
        Activity::RunningMany(n) => vec![
            Span::styled(
                format!("running {n} tools"),
                Style::default().fg(comps::colour(Token::Cyan)),
            ),
            Span::styled(
                elapsed_s(tui.tick_ms, scenario.turn_started_ms),
                Style::default().fg(comps::colour(Token::Muted)),
            ),
        ],
        Activity::Running(t) => vec![
            Span::styled(
                format!("running {t}"),
                Style::default().fg(comps::colour(Token::Cyan)),
            ),
            Span::styled(
                elapsed_s(tui.tick_ms, scenario.turn_started_ms),
                Style::default().fg(comps::colour(Token::Muted)),
            ),
        ],
        Activity::Streaming => vec![
            Span::styled("streaming", Style::default().fg(comps::colour(Token::Cyan))),
            Span::styled(
                elapsed_s(tui.tick_ms, scenario.turn_started_ms),
                Style::default().fg(comps::colour(Token::Muted)),
            ),
        ],
        Activity::WaitingModel(m) => vec![Span::styled(
            format!("waiting for {m}"),
            Style::default().fg(comps::colour(Token::Cyan)),
        )],
        Activity::Compacting => vec![Span::styled(
            "compacting context",
            Style::default().fg(comps::colour(Token::Amber)),
        )],
        Activity::Done => vec![
            Span::styled("✓", Style::default().fg(comps::colour(Token::Green))),
            Span::styled(" done", Style::default().fg(comps::colour(Token::Ink))),
        ],
        Activity::Failed => vec![Span::styled(
            "✕ failed",
            Style::default().fg(comps::colour(Token::Red)),
        )],
        Activity::Ready => {
            // The M5 turn report: ✓ done · {duration} · {n} tools ·
            // +{cost}, for 2 s or until the next key.
            if let Some(r) = &scenario.turn_report {
                if tui.tick_ms.saturating_sub(scenario.turn_started_ms) < 4000 {
                    let mut spans = vec![
                        Span::styled("✓", Style::default().fg(comps::colour(Token::Green))),
                        Span::styled(" done", Style::default().fg(comps::colour(Token::Ink))),
                        Span::styled(
                            format!(" · {}s", r.duration_ms / 1000),
                            Style::default().fg(comps::colour(Token::Muted)),
                        ),
                    ];
                    if r.tools > 0 {
                        spans.push(Span::styled(
                            format!(" · {} tools", r.tools),
                            Style::default().fg(comps::colour(Token::Muted)),
                        ));
                    }
                    if r.priced {
                        spans.push(Span::styled(
                            format!(" · +${:.4}", r.cost_microcents as f64 / 1_000_000.0),
                            Style::default().fg(comps::colour(Token::Muted)),
                        ));
                    }
                    spans
                } else {
                    vec![Span::styled(
                        "ready",
                        Style::default().fg(comps::colour(Token::Muted)),
                    )]
                }
            } else {
                vec![Span::styled(
                    "ready",
                    Style::default().fg(comps::colour(Token::Muted)),
                )]
            }
        }
    };
    // The mark: glyph + ` ORBIT` (muted bold).
    let mut left = vec![
        Span::raw(" "),
        Span::styled(star.glyph.to_string(), Style::default().fg(star_colour)),
        Span::styled(
            " ORBIT",
            Style::default()
                .fg(comps::colour(Token::Muted))
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("   "),
    ];
    left.extend(activity_spans);
    // The right cluster by level (§9.18). Segments are placed right to
    // left ending at W−2: the row therefore shows, left→right, the
    // model · provider, tokens, cost, the short session id, then
    // `? keys` — exactly as wide_idle.txt reads.
    let level = scr.class.status_level();
    let mut right: Vec<Vec<Span>> = Vec::new();
    // model · provider (the cluster's left-most segment).
    if level <= 1 && !scenario.model_id.is_empty() {
        right.push(vec![
            Span::styled(
                scenario.model_id.clone(),
                Style::default().fg(comps::colour(Token::Ink2)),
            ),
            Span::styled(
                format!(" · {}", scenario.provider),
                Style::default().fg(comps::colour(Token::Muted)),
            ),
        ]);
    }
    if level <= 1 {
        // token slot.
        right.push(vec![Span::styled(
            format!("↓{} ↑{}", scenario.input_tokens, scenario.output_tokens),
            Style::default().fg(comps::colour(Token::Muted)),
        )]);
    }
    if level <= 2 {
        // cost slot.
        if scenario.priced {
            right.push(vec![Span::styled(
                format!("${:.4}", scenario.cost_microcents as f64 / 1_000_000.0),
                Style::default().fg(comps::colour(Token::Ink2)),
            )]);
        } else {
            right.push(vec![Span::styled(
                "cost n/a",
                Style::default().fg(comps::colour(Token::Muted)),
            )]);
        }
    }
    if level == 0 {
        // short session id (§7.3), then `? keys` right-most.
        if !scenario.session_prefix.is_empty() {
            right.push(vec![Span::styled(
                scenario.session_prefix.clone(),
                Style::default().fg(comps::colour(Token::Faint)),
            )]);
        }
        right.push(vec![
            Span::styled(
                "?",
                Style::default()
                    .fg(comps::colour(Token::Ink2))
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(" keys", Style::default().fg(comps::colour(Token::Muted))),
        ]);
    }
    let w = area.width;
    let left_w: u16 = left.iter().map(|s| s.width() as u16).sum();
    let right_w: u16 = right
        .iter()
        .map(|seg| seg.iter().map(|s| s.width() as u16).sum::<u16>())
        .sum::<u16>()
        + (right.len().saturating_sub(1) as u16) * 3;
    let mut status = left;
    if !right.is_empty() && left_w + 3 + right_w <= w {
        let pad = w - left_w - right_w;
        status.push(Span::raw(" ".repeat(pad as usize)));
        for (i, seg) in right.into_iter().enumerate() {
            if i > 0 {
                status.push(Span::raw("   "));
            }
            status.extend(seg);
        }
    }
    f.render_widget(Paragraph::new(Line::from(status)), area);
}

/// End truncation (§7.4): keep the head, append `…`.
fn truncate_end(s: &str, w: usize) -> String {
    if s.width() <= w {
        return s.to_string();
    }
    if w == 0 {
        return String::new();
    }
    let mut end = w.saturating_sub(1);
    while end > 0 && !s[..end].is_char_boundary(end) {
        end -= 1;
    }
    let mut out = s[..end].to_string();
    out.push('…');
    out
}
