//! The prototype runtime (DR-20): the event loop that owns the
//! keyboard, the bus and the draw. The layout is the user's panel tree
//! (presets, arrange mode, saved to `tui.toml`); the screen is a pure
//! function of that tree, the scenario and the tick.

use std::time::{Duration, Instant};

use crossterm::event::{self, Event, KeyCode, KeyModifiers};
use ratatui::layout::Rect;
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;

use super::comps;
use super::core::Token;
use super::scenario::{LineKind, Scenario, ToolState, TranscriptLine, TurnReport};
use super::screen::Focus;
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
    /// The full diff of the Changes panel's selected file (M11).
    Diff,
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
    /// The layout tree, focus and arrange mode (the screen's panels).
    pub app: super::app::App,
    /// Timestamps of interface changes, for the motion between states.
    pub fx: super::shell::Fx,
    /// The colour tier the screen is mapped to.
    pub tier: super::core::Tier,
    /// Rows scrolled up, per panel (reading order): the wheel and
    /// PgUp/PgDn move only the panel they are aimed at.
    pub scrolls: Vec<usize>,
    /// The text selection — bound to one panel, never crossing it.
    pub selection: Option<super::shell::Selection>,
    /// The highlighted row of the `/` command list.
    pub completion_sel: usize,
    /// What the last frame drew as clickable, in drawing order. The mouse
    /// is answered from this and nothing else, so a click can only reach
    /// what is on screen.
    pub hits: Vec<super::shell::hits::Hit>,
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
            app: super::app::App::new(std::path::PathBuf::new(), false),
            fx: super::shell::Fx::default(),
            tier: super::core::Tier::TrueColor,
            scrolls: Vec::new(),
            selection: None,
            completion_sel: 0,
            hits: Vec::new(),
        }
    }

    /// Scroll the focused panel by `delta` rows (positive = back in time).
    pub fn scroll_by(&mut self, delta: isize) {
        let i = self.app.focus;
        if self.scrolls.len() <= i {
            self.scrolls.resize(i + 1, 0);
        }
        self.scrolls[i] = (self.scrolls[i] as isize + delta).max(0) as usize;
    }

    /// Scroll the panel at index `i` (the one under the pointer).
    pub fn scroll_panel(&mut self, i: usize, delta: isize) {
        if self.scrolls.len() <= i {
            self.scrolls.resize(i + 1, 0);
        }
        self.scrolls[i] = (self.scrolls[i] as isize + delta).max(0) as usize;
    }

    /// Follow the newest rows again in the focused panel.
    pub fn scroll_follow(&mut self) {
        if let Some(s) = self.scrolls.get_mut(self.app.focus) {
            *s = 0;
        }
    }

    /// Keep the keyboard mode in step with the focused panel: the
    /// composer takes keys only while a Conversation panel has focus.
    pub fn sync_focus(&mut self) {
        self.focus = if self.app.focused_view() == super::layout::View::Conversation {
            Focus::Conversation
        } else {
            Focus::Workspace
        };
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

    // Mouse capture is ON: the app owns the mouse (click, wheel, per-panel
    // selection). Shift+drag still reaches the terminal's own selection.
    let mut guard = match crate::terminal::TerminalGuard::enter_with(true) {
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
    scenario.welcome_chips = crate::model::compute_readiness(&home)
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
        app: super::app::App::new(home.clone(), reduced),
        fx: super::shell::Fx::default(),
        tier: match raw.capabilities.mode.as_str() {
            "truecolor" => super::core::Tier::TrueColor,
            "256" => super::core::Tier::T256,
            "16" => super::core::Tier::T16,
            "mono" => super::core::Tier::None,
            _ => super::core::Tier::detect(
                std::env::var_os("NO_COLOR").is_some(),
                std::env::var("COLORTERM").ok().as_deref(),
                std::env::var("TERM").ok().as_deref(),
            ),
        },
        scrolls: Vec::new(),
        selection: None,
        completion_sel: 0,
        hits: Vec::new(),
    };
    tui.sync_focus();

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
    // A key a click stands for, handled on the next turn of the loop as
    // if it had been typed.
    let mut injected: Option<Event> = None;
    // The last frame drawn: a selection copies its text from here.
    let mut last_buf: Option<ratatui::buffer::Buffer> = None;

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
        let ev = match injected.take() {
            Some(e) => Some(e),
            None => match event::poll(timeout) {
                Ok(true) => event::read().ok(),
                Ok(false) => None,
                Err(_) => break,
            },
        };
        if let Some(ev) = ev {
            match ev {
                Event::Key(k) => {
                    overlay_dirty = true;
                    let snap_before =
                        super::shell::Snap::of(&tui.app, overlay_code(overlay), palette_sel);
                    let quit = handle_key(
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
                        &mut last_prompt,
                    );
                    let snap_after =
                        super::shell::Snap::of(&tui.app, overlay_code(overlay), palette_sel);
                    tui.fx.observe(&snap_before, &snap_after, now_ms);
                    if quit {
                        break;
                    }
                }
                Event::Mouse(m) => {
                    overlay_dirty = true;
                    let size = guard.terminal.size().unwrap_or_default();
                    let area = Rect::new(0, 0, size.width, size.height);
                    let snap_before =
                        super::shell::Snap::of(&tui.app, overlay_code(overlay), palette_sel);
                    let modal = overlay.is_some() || tui.app.picker.is_some();
                    match handle_mouse(m, &mut tui, area, last_buf.as_ref(), modal) {
                        MouseOutcome::None => {}
                        MouseOutcome::Toast(text) => {
                            toast = Some(Toast {
                                text,
                                ok: true,
                                shown_ms: now_ms,
                            });
                        }
                        MouseOutcome::Key(_) if card_just_appeared(&scenario, now_ms) => {}
                        MouseOutcome::Key(k) => injected = Some(Event::Key(k)),
                        MouseOutcome::File(i) => {
                            // A click selects; a click on the selected file
                            // opens its diff, like ⏎.
                            if click_file(&mut scenario, i) {
                                tui.fx.overlay_ms = now_ms;
                                overlay = Some(Overlay::Diff);
                            }
                        }
                        // A row of the `/` list completes into the composer
                        // (Tab); ⏎ then runs it — a click never runs a
                        // command on its own.
                        MouseOutcome::Slash(i) => {
                            completion_sel = i;
                            injected = Some(Event::Key(crossterm::event::KeyEvent::new(
                                crossterm::event::KeyCode::Tab,
                                crossterm::event::KeyModifiers::NONE,
                            )));
                        }
                        MouseOutcome::Tape(i) => {
                            scenario.pick_tape(i);
                            tui.scroll_follow(); // the other command is read from its end
                        }
                        // The palette is a menu: a click runs the row (⏎).
                        MouseOutcome::Palette(i) => {
                            palette_sel = i;
                            injected = Some(Event::Key(crossterm::event::KeyEvent::new(
                                crossterm::event::KeyCode::Enter,
                                crossterm::event::KeyModifiers::NONE,
                            )));
                        }
                    }
                    let snap_after =
                        super::shell::Snap::of(&tui.app, overlay_code(overlay), palette_sel);
                    tui.fx.observe(&snap_before, &snap_after, now_ms);
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
                if let Some(text) = apply_msg(msg, &mut scenario, now_ms) {
                    // The agent-done toast (§9.13): replaces any current
                    // toast — the newest event wins.
                    toast = Some(Toast {
                        text,
                        ok: true,
                        shown_ms: now_ms,
                    });
                }
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
            // Anything that moves keeps the 16 ms redraw alive: the
            // startup window, a live turn, the first-prompt orbit, a
            // fresh message, a breathing approval card.
            let animating = !tui.reduced
                && (scenario.is_turning()
                    || now_ms < 2200
                    || scenario.first_prompt_waiting
                    || now_ms < scenario.motion_until_ms
                    || tui.fx.active(now_ms)
                    || toast.is_some()
                    || scenario
                        .backoff_until_ms
                        .map(|u| u > now_ms)
                        .unwrap_or(false)
                    || (scenario.approval_pending.is_some()
                        && now_ms.saturating_sub(scenario.approval_shown_ms) < 3200));
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
                tui.completion_sel = completion_sel;
                let mut frame_hits = Vec::new();
                let done = guard
                    .terminal
                    .draw(|f| {
                        frame_hits = draw_with_hits(
                            f,
                            &tui,
                            &scenario,
                            &composer,
                            overlay,
                            &palette_query,
                            palette_sel,
                            toast.as_ref(),
                            sessions_pushed,
                            0,
                        );
                    })
                    .ok();
                let Some(done) = done else {
                    // The terminal is gone (closed window, dead PTY): leave the
                    // loop and let the normal shutdown run — never panic here.
                    break;
                };
                last_buf = Some(done.buffer.clone());
                tui.hits = frame_hits;
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
    // Overlays own the keyboard (§9.19–9.21): the key that closes one
    // is spent — it must not also start arranging.
    let had_overlay = overlay.is_some();
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
                        // The sidebar carries the SESSIONS section.
                        tui.app.sidebar = true;
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
        Some(Overlay::Diff) => {
            // Any key closes the diff: it's a look, not a mode.
            *overlay = None;
        }
        None => {}
    }
    if had_overlay || overlay.is_some() {
        return false;
    }

    // The approval card (§9.14/§11.5): while a request is pending it
    // owns the keyboard.
    if scenario.approval_call_id.is_some() {
        // `?` opens the key help over the card, as the status line says;
        // while a denial's note is being typed it is only a character.
        if k.code == KeyCode::Char('?') && scenario.approval_note.is_none() {
            *overlay = Some(Overlay::Help);
            return false;
        }
        approval_key(k, scenario, approvals, prev_key_ms, now_ms);
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

    // The picker asks what a new or changed panel shows (digits pick).
    if tui.app.picker.is_some() {
        match k.code {
            KeyCode::Esc => {
                tui.app.key(super::app::Key::Esc);
            }
            KeyCode::Char(ch @ '1'..='8') => {
                let i = ch as usize - '1' as usize;
                if tui.app.pick(super::shell::PICKER_VIEWS[i]) {
                    tui.app.save_yours();
                }
            }
            _ => {}
        }
        tui.sync_focus();
        return false;
    }
    // Arrange mode (esc): hjkl move, v/s split, p change, x close,
    // HJKL swap, < > - + size, = even, b sidebar, [ ] layouts, i back.
    if tui.app.arranging {
        let key = match k.code {
            KeyCode::Esc => Some(super::app::Key::Esc),
            KeyCode::Enter => Some(super::app::Key::Enter),
            KeyCode::Tab => Some(super::app::Key::Tab),
            // `y` while arranging: the plain-text transcript view (copy mode).
            KeyCode::Char('y') => {
                *want_copy_mode = true;
                None
            }
            KeyCode::Char(ch) => Some(super::app::Key::Char(ch)),
            _ => None,
        };
        if let Some(key) = key {
            if tui.app.key(key) {
                tui.app.save_yours();
            }
        }
        tui.sync_focus();
        return false;
    }
    // esc on an idle, empty composer starts arranging.
    if k.code == KeyCode::Esc
        && composer.is_empty()
        && !scenario.is_turning()
        && !composer.starts_with('/')
    {
        tui.app.arranging = true;
        return false;
    }

    // A key press clears the selection (the next click starts another).
    tui.selection = None;

    // Scrolling belongs to the focused panel alone.
    match k.code {
        KeyCode::PageUp => {
            tui.scroll_by(8);
            return false;
        }
        KeyCode::PageDown => {
            tui.scroll_by(-8);
            return false;
        }
        KeyCode::End if composer.is_empty() || tui.focus != Focus::Conversation => {
            tui.scroll_follow();
            return false;
        }
        _ => {}
    }

    // `z` zooms the focused panel — except in the Conversation, where it
    // is just a letter (zoom there is `esc` then `z`).
    if k.code == KeyCode::Char('z') && k.modifiers.is_empty() && tui.focus != Focus::Conversation {
        tui.app.zoom = !tui.app.zoom;
        return false;
    }
    let _ = pending_leader;

    // The `/` command list owns Up, Down and Tab while it is open.
    if tui.focus == Focus::Conversation {
        let list = super::chrome::slash_list(composer);
        if !list.is_empty() {
            match k.code {
                KeyCode::Up => {
                    *completion_sel = completion_sel.saturating_sub(1);
                    return false;
                }
                KeyCode::Down => {
                    *completion_sel = (*completion_sel + 1).min(list.len() - 1);
                    return false;
                }
                KeyCode::Tab => {
                    let (cmd, _) = list[(*completion_sel).min(list.len() - 1)];
                    composer.clear();
                    composer.push_str(cmd);
                    composer.push(' ');
                    *completion_sel = 0;
                    return false;
                }
                _ => {}
            }
        }
    }

    // Focus keys (§11.1).
    match k.code {
        KeyCode::Tab => {
            // Tab walks the panels in reading order.
            tui.app.cycle_focus(true);
            tui.sync_focus();
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
            KeyCode::Char(':') if composer.is_empty() => {
                *overlay = Some(Overlay::Palette);
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
                    let mut text = composer.trim().to_string();
                    // A partly typed command runs the highlighted match
                    // (`/he` ⏎ → /help); a complete one, or one with
                    // arguments, runs as typed.
                    let list = super::chrome::slash_list(&text);
                    if !list.is_empty() && !list.iter().any(|(c, _)| *c == text) {
                        text = list[(*completion_sel).min(list.len() - 1)].0.to_string();
                    }
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
                        // The sidebar carries the SESSIONS section.
                        tui.app.sidebar = true;
                        *sessions_pushed = true;
                    }
                } else if !composer.trim().is_empty() && !composer.starts_with('/') {
                    tui.scroll_follow();
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
                *completion_sel = 0;
            }
            KeyCode::Esc => {
                // §11.3: Esc closes the completion list; otherwise
                // nothing (the draft is kept).
                if composer == "/" {
                    composer.clear();
                }
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
                *completion_sel = 0;
            }
        }
        return false;
    }

    // Rail / status focused (§11.2 context 4).
    match k.code {
        KeyCode::Char(ch @ '1'..='9') => {
            let i = ch as usize - '1' as usize;
            if i < tui.app.panel_count() {
                tui.app.focus = i;
                tui.sync_focus();
            }
        }
        // M11: ⏎ on the Changes or Review panel shows the selected file's
        // real diff — the hunks the FileChanged event carried.
        KeyCode::Enter
            if matches!(
                tui.app.focused_view(),
                super::layout::View::Changes | super::layout::View::Review
            ) && !scenario.file_changes.is_empty() =>
        {
            tui.fx.overlay_ms = now_ms;
            *overlay = Some(Overlay::Diff);
        }
        // j/k pick the file, n/p walk the Review panel's hunks.
        KeyCode::Char('j') | KeyCode::Down
            if matches!(
                tui.app.focused_view(),
                super::layout::View::Changes | super::layout::View::Review
            ) =>
        {
            scenario.move_file_selection(1);
        }
        KeyCode::Char('k') | KeyCode::Up
            if matches!(
                tui.app.focused_view(),
                super::layout::View::Changes | super::layout::View::Review
            ) =>
        {
            scenario.move_file_selection(-1);
        }
        KeyCode::Char('n') if tui.app.focused_view() == super::layout::View::Review => {
            scenario.move_hunk_selection(1);
        }
        KeyCode::Char('p') if tui.app.focused_view() == super::layout::View::Review => {
            scenario.move_hunk_selection(-1);
        }
        // The Terminal keeps a tape per command: [ ] pick one.
        KeyCode::Char('[') if tui.app.focused_view() == super::layout::View::Terminal => {
            scenario.move_tape_selection(-1);
            tui.scroll_follow();
        }
        KeyCode::Char(']') if tui.app.focused_view() == super::layout::View::Terminal => {
            scenario.move_tape_selection(1);
            tui.scroll_follow();
        }
        // Panels that only scroll: j/k move a line (PgUp/PgDn a page).
        KeyCode::Char('j') | KeyCode::Down
            if matches!(
                tui.app.focused_view(),
                super::layout::View::Activity | super::layout::View::Terminal
            ) =>
        {
            tui.scroll_by(-1);
        }
        KeyCode::Char('k') | KeyCode::Up
            if matches!(
                tui.app.focused_view(),
                super::layout::View::Activity | super::layout::View::Terminal
            ) =>
        {
            tui.scroll_by(1);
        }
        KeyCode::Char('/') => *overlay = Some(Overlay::Palette),
        KeyCode::Char('?') => *overlay = Some(Overlay::Help),
        KeyCode::Char('q') => *overlay = Some(Overlay::Quit),
        KeyCode::Char('i') => {
            // Back to ORBIT: focus the first Conversation panel.
            if let Some(i) = tui
                .app
                .tree
                .leaves()
                .iter()
                .position(|(_, v)| *v == super::layout::View::Conversation)
            {
                tui.app.focus = i;
                tui.sync_focus();
            }
        }
        KeyCode::Esc => {
            tui.app.arranging = true;
        }
        _ => {}
    }
    false
}

fn now_hhmm() -> String {
    chrono::Local::now().format("%H:%M").to_string()
}

fn now_hhmmss() -> String {
    chrono::Local::now().format("%H:%M:%S").to_string()
}

/// The Context panel's numbers as one line, for `/usage`: what the window
/// is made of (estimates), what is free, and where compaction starts.
fn context_summary(s: &Scenario) -> Option<String> {
    use super::shell::panes::tokens_short as k;
    let bd = s.ctx_breakdown?;
    if s.window_tokens == 0 {
        return None;
    }
    let free = s
        .window_tokens
        .saturating_sub(bd.system + bd.tools + bd.memory + bd.messages);
    Some(format!(
        "context {} of {} · system ~{} · tools ~{} · memory ~{} · messages ~{} · free ~{} · compacts at ~{} of messages",
        k(s.used_tokens),
        k(s.window_tokens),
        k(bd.system),
        k(bd.tools),
        k(bd.memory),
        k(bd.messages),
        k(free),
        k(bd.compact_at),
    ))
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
                    ToolState::Cancelled => ": cancelled".into(),
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
            // List the saved sessions in the transcript and open the
            // sidebar (its SESSIONS section) where there is room.
            let _ = command_sink.send(WorkerCommand::ListSessions);
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
            // The same numbers the Context panel draws.
            if let Some(line) = context_summary(scenario) {
                notice(scenario, line);
            }
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
            scenario.tapes.clear();
            scenario.tape_sel = None;
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

/// Replace the Plan panel's rows. A row whose title or state changed
/// flashes for 450 ms (M17); unchanged rows keep their old stamp.
fn set_plan(scenario: &mut Scenario, rows: Vec<super::panels::TaskRow>, now_ms: u64) {
    let before: Vec<(String, String)> = scenario
        .tasks
        .iter()
        .map(|t| (t.title.clone(), t.status.clone()))
        .collect();
    let old_stamps = std::mem::take(&mut scenario.task_changed_ms);
    scenario.task_changed_ms = rows
        .iter()
        .enumerate()
        .map(|(i, t)| {
            let same = before
                .get(i)
                .map(|(title, st)| *title == t.title && *st == t.status)
                .unwrap_or(false);
            if same {
                old_stamps.get(i).copied().unwrap_or(0)
            } else {
                now_ms
            }
        })
        .collect();
    scenario.tasks = rows;
}

/// FrontendEvent-shaped Msgs → the scenario reducer. Returns a toast
/// to show (the agent-done note, §9.13) — the event loop owns toasts.
fn apply_msg(msg: crate::msg::Msg, scenario: &mut Scenario, now_ms: u64) -> Option<String> {
    use crate::msg::Msg;
    // Every message may start a motion: keep redrawing for a second.
    scenario.motion_until_ms = now_ms + 1000;
    match msg {
        Msg::TextDelta(text) => {
            scenario.apply("text_delta", 0);
            scenario.last_data_ms = now_ms;
            match scenario.transcript.last_mut() {
                Some(l) if l.kind == LineKind::Model => {
                    // Fresh ink: remember when this chunk landed.
                    l.arrivals.push((l.text.chars().count(), now_ms));
                    if l.arrivals.len() > 64 {
                        l.arrivals.remove(0);
                    }
                    l.text.push_str(&text);
                }
                _ => scenario.transcript.push(TranscriptLine {
                    kind: LineKind::Model,
                    text,
                    arrivals: vec![(0, now_ms)],
                    ..Default::default()
                }),
            }
        }
        Msg::ToolCallStarted {
            call_id,
            name,
            summary,
        } => {
            // Lines and the activity row are keyed by the call's id; a
            // front-end that sends none (empty id) falls back to name.
            let key = if call_id.is_empty() {
                name.clone()
            } else {
                call_id.clone()
            };
            scenario.running.insert(key, name.clone());
            scenario.apply("tool_started_full", 0);
            // The tool line (§9.8): glyph + name + the display-safe
            // argument (the summary without `name(` … `)`).
            let arg = summary
                .strip_prefix(&format!("{name}("))
                .and_then(|s| s.strip_suffix(')'))
                .unwrap_or(summary.as_str());
            // One card per call: the card is found by the call's id (or,
            // with no id, by tool and target). The engine announces a
            // call before it runs, so a repeat only fills a missing
            // target.
            if let Some(open) = scenario.transcript.iter_mut().rev().find(|l| {
                l.kind == LineKind::Tool
                    && l.tool_state == super::scenario::ToolState::Running
                    && if call_id.is_empty() {
                        l.tool_name == name && (l.text.is_empty() || l.text == arg)
                    } else {
                        l.call_id == call_id
                    }
            }) {
                if open.text.is_empty() {
                    open.text = arg.to_string();
                }
            } else {
                scenario.turn_tools += 1;
                // The Terminal panel keeps a tape per command: a new Bash
                // call starts its own.
                if name == "Bash" {
                    scenario.start_tape(&call_id);
                }
                scenario.transcript.push(TranscriptLine {
                    kind: LineKind::Tool,
                    text: arg.to_string(),
                    tool_name: name.clone(),
                    call_id: call_id.clone(),
                    tool_state: super::scenario::ToolState::Running,
                    started_ms: Some(now_ms),
                    ..Default::default()
                });
            }
        }
        Msg::ToolOutput { call_id, line } => {
            // Live output of a Bash call, to that call's tape (the
            // Terminal panel). Bounded per tape.
            scenario.push_tape_line(&call_id, line);
        }
        Msg::ToolCallFinished {
            call_id,
            name,
            outcome,
            fact,
        } => {
            let key = if call_id.is_empty() {
                name.clone()
            } else {
                call_id.clone()
            };
            scenario.running.remove(&key);
            scenario.apply("tool_finished_full", 0);
            // By id when there is one; by name (the newest open card of
            // that tool) when there is not.
            let found = scenario.transcript.iter_mut().rev().find(|l| {
                l.kind == LineKind::Tool
                    && if call_id.is_empty() {
                        l.tool_name == name
                    } else {
                        l.call_id == call_id
                    }
            });
            if let Some(l) = found {
                // §9.8: the final state comes only from the worker's
                // outcome (never optimistic), and a settled card keeps
                // the state it settled in.
                let open = matches!(
                    l.tool_state,
                    super::scenario::ToolState::Running
                        | super::scenario::ToolState::Queued
                        | super::scenario::ToolState::AwaitingYou
                );
                if open || call_id.is_empty() {
                    l.finished_ms = Some(now_ms);
                    let dur = l
                        .started_ms
                        .map(|st| now_ms.saturating_sub(st))
                        .unwrap_or(0);
                    let (ds, _) = format_duration(dur);
                    // A true fact about the result leads the meta
                    // (`212 lines · 0.1s`); none → just the duration.
                    let lead = |word: &str| {
                        if fact.is_empty() {
                            format!("{word} · {ds}")
                        } else {
                            format!("{fact} · {ds}")
                        }
                    };
                    match outcome {
                        crate::model::ToolOutcome::Ok => {
                            l.tool_state = super::scenario::ToolState::Done;
                            l.meta = lead("done");
                        }
                        crate::model::ToolOutcome::Denied => {
                            l.tool_state = super::scenario::ToolState::Denied;
                            l.meta = String::new();
                        }
                        crate::model::ToolOutcome::Failed => {
                            l.tool_state = super::scenario::ToolState::Failed;
                            // The card already says "failed": the meta
                            // carries the fact and the time, not the word.
                            l.meta = if fact.is_empty() {
                                ds.clone()
                            } else {
                                format!("{fact} · {ds}")
                            };
                        }
                        crate::model::ToolOutcome::Blocked => {
                            l.tool_state = super::scenario::ToolState::Blocked;
                            l.meta = "blocked · unknown tool".into();
                        }
                        crate::model::ToolOutcome::Cancelled => {
                            l.tool_state = super::scenario::ToolState::Cancelled;
                            l.meta = ds.clone();
                        }
                    }
                }
            }
        }
        Msg::Compaction { running, tokens } => {
            scenario.apply(if running { "compacting" } else { "compacted" }, 0);
            if running {
                scenario.compacting_from = Some(tokens);
            } else if let Some(before) = scenario.compacting_from.take() {
                scenario.compactions.push(super::scenario::CompactionRow {
                    time: now_hhmmss(),
                    before,
                    after: tokens,
                });
                const COMPACTIONS_MAX: usize = 20;
                if scenario.compactions.len() > COMPACTIONS_MAX {
                    scenario.compactions.remove(0);
                }
            }
        }
        Msg::Activity {
            kind,
            target,
            fact,
            digest,
        } => {
            // A ledger-backed row is one more record in the chain: the
            // chip counts it and pulses (M19).
            if digest.is_some() {
                scenario.ledger_count = Some(scenario.ledger_count.unwrap_or(0) + 1);
                scenario.ledger_ms = Some(now_ms);
            }
            scenario.activity.push(super::scenario::ActivityRow {
                time: now_hhmmss(),
                kind,
                target,
                fact,
                digest,
            });
            const ACTIVITY_MAX: usize = 500;
            if scenario.activity.len() > ACTIVITY_MAX {
                let drop = scenario.activity.len() - ACTIVITY_MAX;
                scenario.activity.drain(..drop);
            }
        }
        Msg::Readiness(rows) => {
            // A row replaces an earlier one about the same thing (the
            // first word: "sandbox"), so a repeat never doubles it.
            for (ok, label) in rows {
                let key = label.split_whitespace().next().unwrap_or("").to_string();
                scenario
                    .welcome_chips
                    .retain(|(_, l)| l.split_whitespace().next().unwrap_or("") != key);
                scenario.welcome_chips.push((ok, label));
            }
        }
        Msg::ApprovalDetail {
            call_id,
            facts,
            preview,
            grant,
        } => {
            scenario.approval_facts = facts;
            scenario.approval_preview = preview;
            scenario.approval_grant = grant.map(|g| (call_id, g));
        }
        Msg::ApprovalRequested {
            call_id,
            tool_name,
            summary,
            risk,
            working_dir,
        } => {
            scenario.approval_risk = risk;
            scenario.approval_dir = working_dir;
            // apply() first: it stamps a placeholder name, which the
            // real tool name must replace (the status line read
            // "approval needed · tool").
            scenario.apply("approval_requested", 0);
            scenario.approval_pending = Some(tool_name.clone());
            scenario.approval_call_id = Some(call_id.clone());
            scenario.approval_queue.push(tool_name.clone());
            scenario.approval_summary = Some(summary.clone());
            scenario.approval_shown_ms = now_ms;
            // The call is not running: it waits for the person. Its card
            // says so (◇ needs you) and stops animating — a "running"
            // comet over an open approval was both a lie and a redraw at
            // 60 fps for as long as the person took to answer.
            if let Some(l) = scenario.transcript.iter_mut().rev().find(|l| {
                l.kind == LineKind::Tool
                    && l.call_id == call_id
                    && l.tool_state == super::scenario::ToolState::Running
            }) {
                l.tool_state = super::scenario::ToolState::AwaitingYou;
            }
        }
        Msg::ResponseFinished {
            output_tokens,
            input_tokens,
            cost_microcents,
            ..
        } => {
            // A turn that is over leaves no card "running": a call that
            // never reported (Esc, an error, the round guard) was cut
            // off, and says so.
            for l in scenario.transcript.iter_mut() {
                if l.kind == LineKind::Tool && l.tool_state == super::scenario::ToolState::Running {
                    l.tool_state = super::scenario::ToolState::Cancelled;
                    l.finished_ms = Some(now_ms);
                    l.meta = String::new();
                }
            }
            scenario.running.clear();
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
            scenario.turn_ended_ms = Some(now_ms);
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
        Msg::Status(text) if text.starts_with("┃ ") => {
            // Streamed tool output (no call id): the newest tape.
            scenario.push_tape_line("", text.trim_start_matches("┃ ").to_string());
        }
        Msg::Status(text) if text.starts_with("retry ") => {
            // `retry {n} in {ms}ms — {reason}`: the backoff countdown (M27).
            let ms = text
                .split(" in ")
                .nth(1)
                .and_then(|r| r.split("ms").next())
                .and_then(|n| n.trim().parse::<u64>().ok())
                .unwrap_or(0);
            scenario.backoff_until_ms = Some(now_ms + ms);
            scenario.backoff_total_ms = ms.max(1);
            scenario.transcript.push(TranscriptLine {
                kind: LineKind::System,
                text,
                ..Default::default()
            });
        }
        Msg::Status(text) => {
            scenario.transcript.push(TranscriptLine {
                kind: LineKind::System,
                text,
                ..Default::default()
            });
        }
        Msg::WorkspaceUpdate(ws) => {
            // The worker's workspace carries the reactor phase; its plan
            // is empty today, and an empty plan must not wipe the tasks
            // TasksUpdate filled. A non-empty plan still lists state by
            // state.
            if !ws.plan.is_empty() {
                let rows = ws
                    .plan
                    .iter()
                    .map(|t| super::panels::TaskRow {
                        title: t.title.clone(),
                        status: match t.state {
                            crate::model::TaskState::Done => "done",
                            crate::model::TaskState::Active => "active",
                            _ => "pending",
                        }
                        .to_string(),
                    })
                    .collect();
                set_plan(scenario, rows, now_ms);
            }
        }
        Msg::TasksUpdate(tasks) => {
            // TaskCreate / TaskUpdate: the Plan panel lists the model's
            // own task list.
            let rows = tasks
                .into_iter()
                .map(|(title, status)| super::panels::TaskRow {
                    title,
                    status: match status.as_str() {
                        "done" => "done",
                        "in_progress" => "active",
                        _ => "pending",
                    }
                    .to_string(),
                })
                .collect();
            set_plan(scenario, rows, now_ms);
        }
        Msg::FileChanged {
            path,
            added,
            removed,
            hunks,
        } => {
            // One row per file; later edits to it add to its totals
            // and replace its hunks with the latest change's.
            match scenario.file_changes.iter_mut().find(|f| f.path == path) {
                Some(f) => {
                    f.added += added;
                    f.removed += removed;
                    f.hunks = hunks.clone();
                }
                None => scenario.file_changes.push(super::panels::FileChangeRow {
                    path: path.clone(),
                    added,
                    removed,
                    hunks: hunks.clone(),
                }),
            }
            // The row flashes (M11): note when its file last changed.
            let idx = scenario
                .file_changes
                .iter()
                .position(|f| f.path == path)
                .unwrap_or(0);
            scenario
                .file_changed_ms
                .resize(scenario.file_changes.len(), 0);
            scenario.file_changed_ms[idx] = now_ms;
        }
        Msg::SubagentStarted { id, name, task } => {
            scenario.agents.insert(
                id.clone(),
                super::scenario::Agent {
                    name,
                    task,
                    action: String::new(),
                    report: String::new(),
                    done: false,
                    ok: true,
                    started_ms: now_ms,
                    done_ms: None,
                },
            );
            scenario.agents_running = scenario.agents.values().filter(|a| !a.done).count();
            // M16: attach the subagent to its Task card — the most
            // recent running Task/Agent line — so the card can show a
            // live sub-status of what its agent is doing.
            if let Some(card) = scenario.transcript.iter_mut().rev().find(|l| {
                l.kind == LineKind::Tool
                    && matches!(l.tool_name.as_str(), "Task" | "Agent")
                    && l.tool_state == super::scenario::ToolState::Running
            }) {
                card.agent_id = Some(id);
            }
        }
        Msg::SubagentProgress { id, action } => {
            if let Some(a) = scenario.agents.get_mut(&id) {
                a.action = action.clone();
            }
            // The card's sub-status (M16): what its agent is doing now.
            if let Some(card) = scenario
                .transcript
                .iter_mut()
                .rev()
                .find(|l| l.agent_id.as_deref() == Some(id.as_str()))
            {
                card.meta = action;
            }
        }
        Msg::SubagentFinished { id, report, ok } => {
            let name = scenario.agents.get(&id).map(|a| a.name.clone());
            if let Some(a) = scenario.agents.get_mut(&id) {
                a.report = report;
                a.ok = ok;
                a.done = true;
                a.done_ms = Some(now_ms);
            }
            scenario.agents_running = scenario.agents.values().filter(|a| !a.done).count();
            // The agent-done toast (§9.13): a finished subagent must
            // not pass silently — the operator may be looking away.
            return name.map(|n| format!("agent {n} {}", if ok { "done" } else { "failed" }));
        }
        Msg::Usage {
            used_tokens,
            window_tokens,
            breakdown,
        } => {
            scenario.ctx_breakdown = breakdown;
            let now_ctx = scenario.ctx_eased(now_ms);
            scenario.ctx_from = now_ctx;
            scenario.ctx_to = if window_tokens > 0 {
                (used_tokens as f32 / window_tokens as f32).clamp(0.0, 1.0)
            } else {
                0.0
            };
            scenario.ctx_ms = now_ms;
            scenario.used_tokens = used_tokens;
            scenario.window_tokens = window_tokens;
            scenario.usage_shown_ms = now_ms;
        }
        Msg::LedgerAppended { record_count } => {
            scenario.ledger_count = Some(record_count);
            scenario.ledger_ms = Some(now_ms);
        }
        Msg::ModelChanged(m) => {
            scenario.model = m.clone();
            scenario.model_id = m;
        }
        Msg::ModeChanged(mode) => {
            // S5: Shift+Tab's next cycle reads this; the toast comes
            // from the reducer.
            if scenario.permission_mode.as_deref() != Some(mode.as_str()) {
                scenario.mode_prev = scenario.permission_mode.clone();
                scenario.mode_changed_ms = Some(now_ms);
            }
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
    None
}

// ── The draw (§8, §9) ─────────────────────────────────────────────

/// The whole screen: top bar, the panel tree, status line, overlays.
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
    let _ = draw_with_hits(
        f,
        tui,
        scenario,
        composer,
        overlay,
        palette_query,
        palette_sel,
        toast,
        sessions_pushed,
        scroll_offset,
    );
}

/// `draw`, returning what the frame made clickable (the runtime keeps
/// the last frame's regions to answer the mouse).
#[allow(clippy::too_many_arguments)]
pub fn draw_with_hits(
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
) -> Vec<super::shell::hits::Hit> {
    let _ = sessions_pushed;
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
        return Vec::new();
    }
    use super::shell::overlays::Overlay as Ov;
    let ov = match overlay {
        Some(Overlay::Palette) => Some(Ov::Palette {
            query: palette_query,
            sel: palette_sel,
            sel_prev: tui.fx.sel_prev,
            opened_ms: tui.fx.overlay_ms,
            sel_ms: tui.fx.sel_ms,
        }),
        Some(Overlay::Help) => Some(Ov::Help {
            opened_ms: tui.fx.overlay_ms,
        }),
        Some(Overlay::Quit) => Some(Ov::Quit {
            turn_live: scenario.turn_live,
        }),
        Some(Overlay::Diff) => {
            // The selected file — the row the ⏎ hint promises. No rows,
            // no overlay.
            scenario
                .selected_file()
                .map(|i| &scenario.file_changes[i])
                .map(|f| Ov::Diff {
                    path: f.path.as_str(),
                    added: f.added,
                    removed: f.removed,
                    hunks: &f.hunks,
                    opened_ms: tui.fx.overlay_ms,
                })
        }
        None => None,
    };
    super::shell::draw_with_hits(
        f,
        &super::shell::DrawIn {
            app: &tui.app,
            fx: &tui.fx,
            scenario,
            composer,
            completion_sel: tui.completion_sel,
            now_ms: tui.tick_ms,
            // Colour-effect gating (the spec): shimmer, fades and flashes
            // are COLOUR motion — they switch off under 16 colours or no
            // colour, at the source, instead of running in true colour
            // and being coarsened by the tier map after the fact. This
            // gates only those effects; glyph motion (typing, reveals,
            // stars, comets) works in mono and stays on `reduced`.
            mono: tui.tier >= super::core::Tier::T16,
            reduced: tui.reduced,
            tier: tui.tier,
            scrolls: &tui.scrolls,
            selection: tui.selection,
            scroll_offset,
            brand: tui.brand_tier,
            toast: toast.map(|t| super::shell::ToastIn {
                text: t.text.as_str(),
                ok: t.ok,
                shown_ms: t.shown_ms,
            }),
            overlay: ov,
        },
    )
}

/// A click on changed file `i`. Returns true when it should open that
/// file's diff (it was already the selected one), like ⏎; otherwise it
/// only selects it.
fn click_file(scenario: &mut Scenario, i: usize) -> bool {
    if scenario.selected_file() == Some(i) {
        return true;
    }
    scenario.file_sel = i;
    scenario.hunk_sel = 0;
    false
}

/// An approval card that appeared less than 700 ms ago answers no click:
/// a click aimed at what was under the pointer a moment earlier must not
/// land on a button that has just materialised there and approve a call.
fn card_just_appeared(scenario: &Scenario, now_ms: u64) -> bool {
    scenario.approval_call_id.is_some() && now_ms.saturating_sub(scenario.approval_shown_ms) < 700
}

/// What a mouse event asks the event loop to do beyond updating `Tui`.
#[derive(Debug, PartialEq)]
enum MouseOutcome {
    None,
    /// Text was copied: say so.
    Toast(String),
    /// A clicked hint: press its key through the key handler.
    Key(crossterm::event::KeyEvent),
    /// A click on row `i` of the changed-files list.
    File(usize),
    /// A click on row `i` of the `/` command list.
    Slash(usize),
    /// A click on row `i` of the command palette.
    Palette(usize),
    /// A click on the tab of the Terminal's tape `i`.
    Tape(usize),
}

/// The mouse, with every gesture bound to the panel under the pointer
/// (herdr-style isolation): a click focuses it, or presses what it
/// clicked; the wheel scrolls it alone; a drag selects inside it and is
/// clamped to its content; releasing copies that panel's text — and only
/// that — through OSC 52.
///
/// What a click lands on comes from the regions the LAST FRAME drew
/// (`tui.hits`), so it can only reach what was on screen. A modal (an
/// overlay or the picker) answers only its own controls; a click anywhere
/// else on it closes it. A clicked key hint is the key press itself: it
/// goes through the key handler, with every guard that has.
fn handle_mouse(
    m: crossterm::event::MouseEvent,
    tui: &mut Tui,
    area: Rect,
    last: Option<&ratatui::buffer::Buffer>,
    modal: bool,
) -> MouseOutcome {
    use super::shell::hits::{self, Click};
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers, MouseButton, MouseEventKind};
    let (col, row) = (m.column, m.row);
    let rects = super::shell::panel_rects(area, &tui.app);
    let under = rects
        .iter()
        .find(|(_, r, _)| col >= r.x && col < r.right() && row >= r.y && row < r.bottom());
    match m.kind {
        MouseEventKind::Down(MouseButton::Left) => {
            tui.selection = None;
            let click = hits::at(&tui.hits, col, row);
            if modal {
                return match click {
                    Some(Click::Dismiss) => {
                        MouseOutcome::Key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE))
                    }
                    Some(Click::Key(code, mods)) => MouseOutcome::Key(KeyEvent::new(code, mods)),
                    Some(Click::Palette(i)) => MouseOutcome::Palette(i),
                    _ => MouseOutcome::None,
                };
            }
            // A control belongs to the panel it is drawn in: the key it
            // presses, or the row it picks, must reach THAT panel, not
            // whichever one happened to have focus.
            let focus_under = |tui: &mut Tui| {
                if let Some((i, _, _)) = under {
                    if *i != tui.app.focus {
                        tui.app.focus = *i;
                        tui.sync_focus();
                    }
                }
            };
            match click {
                Some(Click::Key(code, mods)) => {
                    focus_under(tui);
                    return MouseOutcome::Key(KeyEvent::new(code, mods));
                }
                Some(Click::File(i)) => {
                    focus_under(tui);
                    return MouseOutcome::File(i);
                }
                Some(Click::Slash(i)) => {
                    focus_under(tui);
                    return MouseOutcome::Slash(i);
                }
                Some(Click::Tape(i)) => {
                    focus_under(tui);
                    return MouseOutcome::Tape(i);
                }
                Some(Click::Panel(i)) => {
                    if i < tui.app.panel_count() && i != tui.app.focus {
                        tui.app.focus = i;
                        tui.sync_focus();
                    }
                    return MouseOutcome::None;
                }
                Some(Click::Preset(i)) => {
                    use super::layout::Preset;
                    let presets = [
                        Preset::Columns,
                        Preset::Build,
                        Preset::Agents,
                        Preset::Review,
                    ];
                    if let Some(p) = presets.get(i) {
                        tui.app.apply_preset(*p);
                        tui.app.save_yours();
                        tui.sync_focus();
                    }
                    return MouseOutcome::None;
                }
                // Modal-only regions: nothing is open, nothing to do.
                Some(Click::Dismiss | Click::Inert | Click::Palette(_)) => {
                    return MouseOutcome::None;
                }
                // `at` never returns a text span; matched for completeness.
                Some(Click::Text) | None => {}
            }
            if row == 0 {
                return MouseOutcome::None;
            }
            if let Some((i, r, _)) = under {
                if *i != tui.app.focus {
                    tui.app.focus = *i;
                    tui.sync_focus();
                }
                let inner = super::shell::content_rect(*r);
                if col >= inner.x && col < inner.right() && row >= inner.y && row < inner.bottom() {
                    tui.selection = Some(super::shell::Selection {
                        panel: *i,
                        a: (col, row),
                        b: (col, row),
                    });
                }
            }
            MouseOutcome::None
        }
        _ if modal => MouseOutcome::None,
        MouseEventKind::Drag(MouseButton::Left) => {
            if let Some(sel) = &mut tui.selection {
                sel.b = (col, row);
            }
            MouseOutcome::None
        }
        MouseEventKind::Up(MouseButton::Left) => {
            let Some(sel) = tui.selection else {
                return MouseOutcome::None;
            };
            if sel.a == sel.b {
                tui.selection = None;
                return MouseOutcome::None;
            }
            let Some((_, r, _)) = rects.iter().find(|(i, _, _)| *i == sel.panel) else {
                return MouseOutcome::None;
            };
            let Some(buf) = last else {
                return MouseOutcome::None;
            };
            let text = selected_text(buf, &sel, *r, &tui.hits);
            if text.is_empty() {
                return MouseOutcome::None;
            }
            let _ = std::io::Write::write_all(
                &mut std::io::stdout(),
                crate::selection::osc52_sequence(&text).as_bytes(),
            );
            let _ = std::io::Write::flush(&mut std::io::stdout());
            MouseOutcome::Toast(format!("copied {} characters", text.chars().count()))
        }
        MouseEventKind::ScrollUp => {
            if let Some((i, _, _)) = under {
                tui.scroll_panel(*i, 3);
            }
            MouseOutcome::None
        }
        MouseEventKind::ScrollDown => {
            if let Some((i, _, _)) = under {
                tui.scroll_panel(*i, -3);
            }
            MouseOutcome::None
        }
        _ => MouseOutcome::None,
    }
}

/// The text of a selection, read from the drawn frame, inside its panel.
///
/// A row that marked where its words sit (a turn in the Conversation)
/// gives up the rest: the gutter marks and the timestamp are not what
/// anyone selects. What is copied is the text as displayed, markup
/// already turned into style; the other rows are read whole.
fn selected_text(
    buf: &ratatui::buffer::Buffer,
    sel: &super::shell::Selection,
    panel: Rect,
    hits: &[super::shell::hits::Hit],
) -> String {
    let inner = super::shell::content_rect(panel);
    sel.rows(inner)
        .into_iter()
        .map(|(x, y, w)| {
            let (mut from, mut to) = (x, x + w);
            if let Some((sx, ex)) = super::shell::hits::text_span(hits, y as u16, inner) {
                from = from.max(sx as i32);
                to = to.min(ex as i32);
            }
            (from..to.max(from))
                .map(|cx| buf[(cx as u16, y as u16)].symbol().to_string())
                .collect::<String>()
                .trim_end()
                .to_string()
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// The keys of the approval card while a request is pending: `y` once, `s`
/// this session, `a` always, `R` the whole tool, `n` a denial with a note,
/// esc a denial without. The decision keys are disabled for a second after
/// the last keypress so typing cannot answer the card (§9.14).
fn approval_key(
    k: crossterm::event::KeyEvent,
    scenario: &mut Scenario,
    approvals: &ApprovalRegistry,
    prev_key_ms: u64,
    now_ms: u64,
) {
    let Some(call_id) = scenario.approval_call_id.clone() else {
        return;
    };
    // `n` opened the note field: the denial waits for ⏎ (with the
    // note) or esc (without), and nothing else answers the card.
    if let Some(note) = scenario.approval_note.as_mut() {
        let outcome = match k.code {
            KeyCode::Enter => Some(Some(std::mem::take(note))),
            KeyCode::Esc => Some(None),
            KeyCode::Backspace => {
                note.pop();
                None
            }
            KeyCode::Char(c)
                if !k
                    .modifiers
                    .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
            {
                note.push(c);
                None
            }
            _ => None,
        };
        if let Some(note) = outcome {
            scenario.approval_note = None;
            finish_approval(scenario, approvals, &call_id, Answer::Deny(note), now_ms);
        }
        return;
    }
    // A decision key does nothing while disabled (§11.5): the
    // arming timer is 1000 ms since the last keypress.
    // The 1000 ms window runs to the PREVIOUS key: this key
    // press itself must not re-arm the card it decides (§9.14).
    let armed_disabled = now_ms.saturating_sub(prev_key_ms) < 1000;
    // `s` and `a` answer only for the rule the card showed; `a` only
    // where it can be saved.
    let offer = scenario.offered_grant().cloned();
    let answer = if armed_disabled {
        None
    } else {
        match k.code {
            KeyCode::Char('y') | KeyCode::Char('Y') => {
                Some(Answer::Response(crate::ApprovalResponse::Allow))
            }
            KeyCode::Char('s') if offer.is_some() => {
                Some(Answer::Response(crate::ApprovalResponse::AllowRule))
            }
            KeyCode::Char('a') if offer.as_ref().is_some_and(|g| g.can_save) => {
                Some(Answer::Response(crate::ApprovalResponse::AllowRuleAlways))
            }
            // `n` denies, and asks for a word on why (optional).
            KeyCode::Char('n') | KeyCode::Char('N') => {
                scenario.approval_note = Some(String::new());
                None
            }
            KeyCode::Esc => Some(Answer::Deny(None)),
            _ => None,
        }
    };
    if let Some(answer) = answer {
        finish_approval(scenario, approvals, &call_id, answer, now_ms);
    }
}

/// How the operator answered the approval card.
enum Answer {
    Response(crate::ApprovalResponse),
    /// A denial, with the note typed for it (None: no note).
    Deny(Option<String>),
}

/// Deliver an answer to the parked worker and tidy the card: a call that
/// was allowed shows as running, the queue moves on, and an answer that
/// cannot be delivered (the worker is gone) says so.
fn finish_approval(
    scenario: &mut Scenario,
    approvals: &crate::ApprovalRegistry,
    call_id: &str,
    answer: Answer,
    now_ms: u64,
) {
    let allowed = matches!(
        answer,
        Answer::Response(
            crate::ApprovalResponse::Allow
                | crate::ApprovalResponse::AllowSession
                | crate::ApprovalResponse::AllowRule
                | crate::ApprovalResponse::AllowRuleAlways
        )
    );
    if allowed {
        // Allowed: the call runs now.
        for l in scenario.transcript.iter_mut().rev() {
            if l.kind == LineKind::Tool
                && l.call_id == call_id
                && l.tool_state == super::scenario::ToolState::AwaitingYou
            {
                l.tool_state = super::scenario::ToolState::Running;
                break;
            }
        }
    }
    let delivered = match answer {
        Answer::Response(r) => approvals.resolve(call_id, r),
        Answer::Deny(Some(note)) => approvals.resolve_denial_with_note(call_id, &note),
        Answer::Deny(None) => approvals.resolve(call_id, crate::ApprovalResponse::Deny),
    };
    scenario.approval_queue.remove(0);
    if !delivered {
        // §11.5.3: the worker is gone — drop the request and note it.
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

/// The overlay as a small code for change detection (0 none).
fn overlay_code(o: Option<Overlay>) -> u8 {
    match o {
        None => 0,
        Some(Overlay::Palette) => 1,
        Some(Overlay::Help) => 2,
        Some(Overlay::Quit) => 3,
        Some(Overlay::Diff) => 4,
    }
}

#[cfg(test)]
mod tool_card_tests {
    use super::*;
    use crate::model::ToolOutcome;
    use crate::msg::Msg;

    fn started(id: &str, name: &str, summary: &str) -> Msg {
        Msg::ToolCallStarted {
            call_id: id.into(),
            name: name.into(),
            summary: summary.into(),
        }
    }

    fn finished(id: &str, name: &str, outcome: ToolOutcome, fact: &str) -> Msg {
        Msg::ToolCallFinished {
            call_id: id.into(),
            name: name.into(),
            outcome,
            fact: fact.into(),
        }
    }

    fn tools(s: &Scenario) -> Vec<&TranscriptLine> {
        s.transcript
            .iter()
            .filter(|l| l.kind == LineKind::Tool)
            .collect()
    }

    /// The bug the live TUI showed: the engine's start carried the real
    /// target ("**/*.py") and the executor's carried an argument name
    /// ("pattern"). Two summaries, one call: one card, and it settles.
    #[test]
    fn one_card_per_call_even_when_the_summaries_differ() {
        let mut s = Scenario::new();
        apply_msg(started("c1", "Glob", "**/*.py"), &mut s, 10);
        apply_msg(started("c1", "Glob", "Glob(pattern)"), &mut s, 20);
        assert_eq!(tools(&s).len(), 1, "one card for one call");
        assert_eq!(s.turn_tools, 1, "and the turn counts one tool, not two");
        assert_eq!(tools(&s)[0].text, "**/*.py", "the first target wins");
        apply_msg(
            finished("c1", "Glob", ToolOutcome::Ok, "3 files"),
            &mut s,
            50,
        );
        let l = tools(&s)[0];
        assert_eq!(l.tool_state, ToolState::Done);
        assert!(l.meta.starts_with("3 files · "), "{}", l.meta);
        assert!(s.running.is_empty());
    }

    /// Two calls of one tool in a round settle each its own card, in the
    /// order they finish — not newest-first.
    #[test]
    fn two_calls_of_one_tool_settle_by_id() {
        let mut s = Scenario::new();
        apply_msg(started("a", "Bash", "echo one"), &mut s, 1);
        apply_msg(started("b", "Bash", "echo two"), &mut s, 2);
        assert_eq!(tools(&s).len(), 2);
        apply_msg(finished("a", "Bash", ToolOutcome::Ok, ""), &mut s, 30);
        let cards = tools(&s);
        assert_eq!(cards[0].tool_state, ToolState::Done, "a settled");
        assert_eq!(cards[1].tool_state, ToolState::Running, "b still runs");
        apply_msg(
            finished("b", "Bash", ToolOutcome::Failed, "exit 2"),
            &mut s,
            40,
        );
        let cards = tools(&s);
        assert_eq!(cards[1].tool_state, ToolState::Failed);
        assert!(cards[1].meta.starts_with("exit 2 · "), "{}", cards[1].meta);
    }

    /// The engine's own verdict arrives after the executor's richer one;
    /// a settled card keeps the state it settled in.
    #[test]
    fn a_settled_card_keeps_its_state() {
        let mut s = Scenario::new();
        apply_msg(started("c", "Edit", "calc.py"), &mut s, 1);
        apply_msg(finished("c", "Edit", ToolOutcome::Denied, ""), &mut s, 5);
        apply_msg(finished("c", "", ToolOutcome::Failed, ""), &mut s, 9);
        assert_eq!(tools(&s)[0].tool_state, ToolState::Denied);
    }

    /// A turn that ends (Esc, an error, the round guard) leaves no card
    /// "running" for ever: a call that never reported was cut off.
    #[test]
    fn a_finished_turn_leaves_no_card_running() {
        let mut s = Scenario::new();
        apply_msg(started("c", "Bash", "sleep 100"), &mut s, 1);
        apply_msg(
            Msg::ResponseFinished {
                output: String::new(),
                input_tokens: 0,
                output_tokens: 0,
                cost_microcents: 0,
            },
            &mut s,
            900,
        );
        assert_eq!(tools(&s)[0].tool_state, ToolState::Cancelled);
        assert!(s.running.is_empty());
    }

    fn lines(s: &Scenario, call_id: &str) -> Vec<String> {
        s.tapes
            .iter()
            .find(|t| t.call_id == call_id)
            .map(|t| t.lines.clone())
            .unwrap_or_default()
    }

    /// Every Bash call has its own tape: a new command does not erase the
    /// last one's output, and a late line of an older command lands on ITS
    /// tape (it used to be dropped, because only the newest command was
    /// taped).
    #[test]
    fn each_bash_call_has_its_own_tape() {
        let mut s = Scenario::new();
        let out = |id: &str, line: &str| Msg::ToolOutput {
            call_id: id.into(),
            line: line.into(),
        };
        apply_msg(started("old", "Bash", "echo old"), &mut s, 1);
        apply_msg(out("old", "old line"), &mut s, 2);
        assert_eq!(lines(&s, "old"), ["old line"]);
        apply_msg(started("new", "Bash", "echo new"), &mut s, 3);
        assert_eq!(lines(&s, "old"), ["old line"], "the first tape is kept");
        assert!(lines(&s, "new").is_empty(), "the new one starts empty");
        apply_msg(out("old", "late"), &mut s, 4);
        apply_msg(out("new", "fresh"), &mut s, 5);
        assert_eq!(lines(&s, "old"), ["old line", "late"]);
        assert_eq!(lines(&s, "new"), ["fresh"]);
        // A tool that is not Bash has no tape.
        apply_msg(started("g", "Glob", "*.rs"), &mut s, 6);
        assert_eq!(s.tapes.len(), 2);
        // Output for a call nobody started is dropped, not misfiled.
        apply_msg(out("ghost", "x"), &mut s, 7);
        assert_eq!(s.tapes.iter().map(|t| t.lines.len()).sum::<usize>(), 3);
    }

    #[test]
    fn a_tape_keeps_a_bounded_tail_and_says_what_it_dropped() {
        let mut s = Scenario::new();
        apply_msg(started("c", "Bash", "yes"), &mut s, 1);
        for i in 0..1000 {
            apply_msg(
                Msg::ToolOutput {
                    call_id: "c".into(),
                    line: format!("line {i}"),
                },
                &mut s,
                2,
            );
        }
        let t = &s.tapes[0];
        assert_eq!(t.lines.len(), 400);
        assert_eq!(t.lines.last().map(String::as_str), Some("line 999"));
        assert_eq!(t.dropped, 600, "the cut is counted");
    }

    /// The panel keeps the last 20 commands.
    #[test]
    fn the_panel_keeps_a_bounded_number_of_tapes() {
        let mut s = Scenario::new();
        for i in 0..30 {
            apply_msg(started(&format!("c{i}"), "Bash", "true"), &mut s, i);
        }
        assert_eq!(s.tapes.len(), 20);
        assert_eq!(s.tapes[0].call_id, "c10", "the oldest went");
        assert_eq!(s.tapes[19].call_id, "c29");
    }

    /// The panel follows the newest command; reading an older one pins it
    /// there until you come back to the newest.
    #[test]
    fn a_tape_picked_stays_picked_while_new_commands_run() {
        let mut s = Scenario::new();
        for id in ["a", "b", "c"] {
            apply_msg(started(id, "Bash", "true"), &mut s, 1);
        }
        assert_eq!(s.selected_tape(), Some(2), "follows the newest");
        s.move_tape_selection(-1);
        s.move_tape_selection(-1);
        assert_eq!(s.selected_tape(), Some(0));
        apply_msg(started("d", "Bash", "true"), &mut s, 2);
        assert_eq!(
            s.selected_tape(),
            Some(0),
            "a new command does not yank it away"
        );
        s.move_tape_selection(1);
        s.move_tape_selection(1);
        s.move_tape_selection(1);
        assert_eq!(s.selected_tape(), Some(3));
        assert!(
            s.tape_sel.is_none(),
            "landing on the newest follows it again"
        );
        apply_msg(started("e", "Bash", "true"), &mut s, 3);
        assert_eq!(s.selected_tape(), Some(4));
        s.pick_tape(1);
        assert_eq!(s.selected_tape(), Some(1));
        s.pick_tape(99);
        assert!(s.tape_sel.is_none());
    }

    /// A pinned tape stays on the same command when the oldest is dropped.
    #[test]
    fn dropping_the_oldest_tape_keeps_the_pick_on_its_command() {
        let mut s = Scenario::new();
        for i in 0..20 {
            apply_msg(started(&format!("c{i}"), "Bash", "true"), &mut s, 1);
        }
        s.pick_tape(5);
        apply_msg(started("c20", "Bash", "true"), &mut s, 2);
        let i = s.selected_tape().unwrap();
        assert_eq!(s.tapes[i].call_id, "c5");
    }

    /// The status line read "approval needed · tool": apply() stamped a
    /// placeholder over the real name.
    #[test]
    fn an_approval_names_the_tool() {
        let mut s = Scenario::new();
        apply_msg(
            Msg::ApprovalRequested {
                call_id: "c".into(),
                tool_name: "Edit".into(),
                summary: "Edit(calc.py)".into(),
                risk: 2,
                working_dir: "/tmp".into(),
            },
            &mut s,
            1,
        );
        assert_eq!(s.approval_pending.as_deref(), Some("Edit"));
        assert!(matches!(
            s.activity(),
            crate::proto::scenario::Activity::Approval(t) if t == "Edit"
        ));
    }
}

#[cfg(test)]
mod plan_tests {
    use super::*;
    use crate::msg::Msg;

    fn tasks(rows: &[(&str, &str)]) -> Msg {
        Msg::TasksUpdate(
            rows.iter()
                .map(|(t, s)| (t.to_string(), s.to_string()))
                .collect(),
        )
    }

    /// TaskCreate/TaskUpdate fill the Plan panel; it used to say "Nothing
    /// planned yet" for ever because no event carried the list.
    #[test]
    fn the_plan_panel_lists_the_models_tasks() {
        let mut s = Scenario::new();
        apply_msg(
            tasks(&[("Fix add", "pending"), ("Run tests", "pending")]),
            &mut s,
            10,
        );
        assert_eq!(s.tasks.len(), 2);
        assert_eq!(s.tasks[0].status, "pending");
        apply_msg(
            tasks(&[("Fix add", "in_progress"), ("Run tests", "pending")]),
            &mut s,
            20,
        );
        assert_eq!(s.tasks[0].status, "active");
        apply_msg(
            tasks(&[("Fix add", "done"), ("Run tests", "pending")]),
            &mut s,
            30,
        );
        assert_eq!(s.tasks[0].status, "done");
        // Only the row that changed flashes.
        assert_eq!(s.task_changed_ms, vec![30, 10]);
    }

    /// The worker's workspace update carries the reactor phase and an
    /// empty plan: it must not wipe the tasks.
    #[test]
    fn a_phase_update_does_not_wipe_the_plan() {
        let mut s = Scenario::new();
        apply_msg(tasks(&[("Fix add", "pending")]), &mut s, 10);
        apply_msg(
            Msg::WorkspaceUpdate(crate::model::Workspace {
                phase_index: 2,
                ..Default::default()
            }),
            &mut s,
            20,
        );
        assert_eq!(s.tasks.len(), 1, "the plan survives a phase change");
    }
}

#[cfg(test)]
mod approval_card_tests {
    use super::*;
    use crate::msg::Msg;

    /// A call that is waiting for the person is not "running": its card
    /// says "needs you", and the outcome still settles it from there.
    #[test]
    fn a_call_awaiting_approval_is_not_running() {
        let mut s = Scenario::new();
        apply_msg(
            Msg::ToolCallStarted {
                call_id: "c1".into(),
                name: "Edit".into(),
                summary: "calc.py".into(),
            },
            &mut s,
            1,
        );
        apply_msg(
            Msg::ApprovalRequested {
                call_id: "c1".into(),
                tool_name: "Edit".into(),
                summary: "Edit(calc.py)".into(),
                risk: 2,
                working_dir: "/tmp".into(),
            },
            &mut s,
            2,
        );
        let card = |s: &Scenario| {
            s.transcript
                .iter()
                .find(|l| l.kind == LineKind::Tool)
                .map(|l| l.tool_state)
                .unwrap()
        };
        assert_eq!(card(&s), ToolState::AwaitingYou);
        apply_msg(
            Msg::ToolCallFinished {
                call_id: "c1".into(),
                name: "Edit".into(),
                outcome: crate::model::ToolOutcome::Denied,
                fact: String::new(),
            },
            &mut s,
            9,
        );
        assert_eq!(card(&s), ToolState::Denied);
    }
}

#[cfg(test)]
mod activity_tests {
    use super::*;
    use crate::msg::Msg;

    fn row(kind: &str, digest: Option<&str>) -> Msg {
        Msg::Activity {
            kind: kind.into(),
            target: "Edit(calc.py)".into(),
            fact: "ok".into(),
            digest: digest.map(str::to_string),
        }
    }

    /// The Activity panel lists what happened, in order, and a ledger
    /// record is counted by the chip and pulses it; a runtime event
    /// (a request, a retry) is a row but not a record.
    #[test]
    fn rows_arrive_in_order_and_only_records_count_on_the_chip() {
        let mut s = Scenario::new();
        apply_msg(Msg::LedgerAppended { record_count: 10 }, &mut s, 1);
        apply_msg(row("intent", Some("aaaa")), &mut s, 2);
        apply_msg(row("request", None), &mut s, 3);
        apply_msg(row("verdict", Some("bbbb")), &mut s, 4);
        let kinds: Vec<&str> = s.activity.iter().map(|a| a.kind.as_str()).collect();
        assert_eq!(kinds, ["intent", "request", "verdict"]);
        assert_eq!(s.ledger_count, Some(12), "two records landed on top of 10");
        assert_eq!(s.ledger_ms, Some(4), "the chip pulsed at the last record");
        assert_eq!(s.activity[0].digest.as_deref(), Some("aaaa"));
        assert_eq!(s.activity[0].time.len(), 8, "HH:MM:SS");
    }

    #[test]
    fn the_activity_list_keeps_a_bounded_tail() {
        let mut s = Scenario::new();
        for i in 0..600 {
            apply_msg(
                Msg::Activity {
                    kind: "result".into(),
                    target: format!("call {i}"),
                    fact: "ok".into(),
                    digest: None,
                },
                &mut s,
                1,
            );
        }
        assert_eq!(s.activity.len(), 500);
        assert_eq!(
            s.activity.last().map(|a| a.target.as_str()),
            Some("call 599")
        );
    }

    /// Compaction used to be invisible: no message carried it, so the
    /// status line's amber "compacting context" could never show.
    #[test]
    fn compaction_shows_in_the_status_while_it_runs() {
        let mut s = Scenario::new();
        s.turn_live = true;
        apply_msg(
            Msg::Compaction {
                running: true,
                tokens: 150_000,
            },
            &mut s,
            1,
        );
        assert!(matches!(
            s.activity(),
            crate::proto::scenario::Activity::Compacting
        ));
        apply_msg(
            Msg::Compaction {
                running: false,
                tokens: 9_000,
            },
            &mut s,
            2,
        );
        assert!(!matches!(
            s.activity(),
            crate::proto::scenario::Activity::Compacting
        ));
    }
}

#[cfg(test)]
mod click_tests {
    use super::*;
    use crate::msg::Msg;
    use crate::proto::layout::Preset;
    use crossterm::event::{KeyCode, KeyModifiers, MouseButton, MouseEvent, MouseEventKind};
    use ratatui::backend::TestBackend;

    /// A Tui whose layout lives in a throwaway home: a click on a layout
    /// tab SAVES the layout, and an empty home would write it into the
    /// working directory — where the next test (and the repo) would find it.
    fn fresh_tui() -> Tui {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static N: AtomicUsize = AtomicUsize::new(0);
        let home = std::env::temp_dir().join(format!(
            "orbit-click-tests-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&home).unwrap();
        let mut tui = Tui::new();
        tui.app = super::super::app::App::new(home, true);
        tui.sync_focus();
        tui
    }

    /// Draw one frame, keep its clickable regions on `tui` (as the loop
    /// does) and return the screen as rows of text.
    fn frame(
        tui: &mut Tui,
        s: &Scenario,
        composer: &str,
        overlay: Option<Overlay>,
        w: u16,
        h: u16,
    ) -> Vec<String> {
        // Settled: overlays and panels animate in, and a frame at tick 0
        // would show none of it.
        tui.reduced = true;
        tui.tick_ms = tui.tick_ms.max(5_000);
        let mut term = ratatui::Terminal::new(TestBackend::new(w, h)).unwrap();
        let mut hits = Vec::new();
        let done = term
            .draw(|f| {
                hits = draw_with_hits(f, tui, s, composer, overlay, "", 0, None, false, 0);
            })
            .unwrap();
        tui.hits = hits;
        let buf = done.buffer.clone();
        (0..h)
            .map(|y| (0..w).map(|x| buf[(x, y)].symbol().to_string()).collect())
            .collect()
    }

    /// What dragging across `from`..`to` copies in the panel under `from`:
    /// the frame is drawn, the selection made as the mouse would make it,
    /// and the text read the way the release reads it.
    fn copied(
        tui: &mut Tui,
        s: &Scenario,
        from: (u16, u16),
        to: (u16, u16),
        w: u16,
        h: u16,
    ) -> String {
        tui.reduced = true;
        tui.tick_ms = tui.tick_ms.max(5_000);
        let mut term = ratatui::Terminal::new(TestBackend::new(w, h)).unwrap();
        let mut hits = Vec::new();
        let done = term
            .draw(|f| {
                hits = draw_with_hits(f, tui, s, "", None, "", 0, None, false, 0);
            })
            .unwrap();
        tui.hits = hits;
        let buf = done.buffer.clone();
        let rects = super::super::shell::panel_rects(Rect::new(0, 0, w, h), &tui.app);
        let (idx, r, _) = rects
            .iter()
            .find(|(_, r, _)| {
                from.0 >= r.x && from.0 < r.right() && from.1 >= r.y && from.1 < r.bottom()
            })
            .expect("the drag starts in a panel");
        let sel = super::super::shell::Selection {
            panel: *idx,
            a: from,
            b: to,
        };
        selected_text(&buf, &sel, *r, &tui.hits)
    }

    /// Where `needle` is on screen (column, row) — the click goes where
    /// the person would aim: at the words.
    fn at(rows: &[String], needle: &str) -> (u16, u16) {
        for (y, r) in rows.iter().enumerate() {
            if let Some(b) = r.find(needle) {
                return (r[..b].chars().count() as u16, y as u16);
            }
        }
        panic!("no {needle:?} on screen\n{}", rows.join("\n"));
    }

    fn click(tui: &mut Tui, (col, row): (u16, u16), modal: bool, w: u16, h: u16) -> MouseOutcome {
        let m = MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: col,
            row,
            modifiers: KeyModifiers::NONE,
        };
        handle_mouse(m, tui, Rect::new(0, 0, w, h), None, modal)
    }

    fn key_of(o: MouseOutcome) -> KeyCode {
        match o {
            MouseOutcome::Key(k) => k.code,
            other => panic!("expected a key, got {other:?}"),
        }
    }

    fn with_approval() -> Scenario {
        let mut s = Scenario::new();
        apply_msg(
            Msg::ToolCallStarted {
                call_id: "c1".into(),
                name: "Edit".into(),
                summary: "calc.py".into(),
            },
            &mut s,
            1,
        );
        apply_msg(
            Msg::ApprovalRequested {
                call_id: "c1".into(),
                tool_name: "Edit".into(),
                summary: "Edit(calc.py)".into(),
                risk: 2,
                working_dir: "/tmp".into(),
            },
            &mut s,
            2,
        );
        s
    }

    /// A key hint is the key it names: clicking `⏎ send` presses Enter.
    #[test]
    fn a_clicked_hint_presses_the_key_it_names() {
        let (w, h) = (164, 48);
        let mut tui = fresh_tui();
        let rows = frame(&mut tui, &Scenario::new(), "", None, w, h);
        assert_eq!(
            key_of(click(&mut tui, at(&rows, "⏎ send"), false, w, h)),
            KeyCode::Enter
        );
        assert_eq!(
            key_of(click(&mut tui, at(&rows, "send"), false, w, h)),
            KeyCode::Enter,
            "the label too"
        );
        assert_eq!(
            key_of(click(&mut tui, at(&rows, "@ file"), false, w, h)),
            KeyCode::Char('@')
        );
        assert_eq!(
            key_of(click(&mut tui, at(&rows, "⇧tab"), false, w, h)),
            KeyCode::BackTab
        );
    }

    /// A hint that names several keys has no one key to press: clicking
    /// it is the same as clicking the panel it sits in.
    #[test]
    fn a_composite_hint_is_not_a_button() {
        let (w, h) = (164, 48);
        let mut tui = fresh_tui();
        tui.app.focus = 0;
        let mut s = Scenario::new();
        s.file_changes = vec![crate::proto::panels::FileChangeRow {
            path: "a.rs".into(),
            added: 1,
            removed: 0,
            hunks: None,
        }];
        let rows = frame(&mut tui, &s, "", None, w, h);
        // The Changes footer reads `j/k file   ⏎ full diff`.
        let o = click(&mut tui, at(&rows, "j/k"), false, w, h);
        assert_eq!(o, MouseOutcome::None);
    }

    /// The approval card's three buttons are the keys y, R and n, so the
    /// card's own guards (the typing pause, the settle delay) apply.
    #[test]
    fn the_approval_buttons_are_y_r_and_n() {
        let (w, h) = (164, 48);
        let mut tui = fresh_tui();
        let s = with_approval();
        let rows = frame(&mut tui, &s, "", None, w, h);
        assert_eq!(
            key_of(click(&mut tui, at(&rows, "allow once"), false, w, h)),
            KeyCode::Char('y')
        );
        assert_eq!(
            key_of(click(&mut tui, at(&rows, "esc deny"), false, w, h)),
            KeyCode::Char('n')
        );
    }

    /// Dragging across a turn copies its words. The `▎ ›` and `✦` that
    /// mark who spoke, and the time beside the first row, stay out.
    #[test]
    fn a_selection_copies_the_words_of_a_turn_and_not_its_gutter() {
        let (w, h) = (100, 30);
        let mut tui = fresh_tui();
        let mut s = Scenario::new();
        s.transcript.push(TranscriptLine {
            kind: LineKind::User,
            text: "make the tests pass".into(),
            time: Some("16:46".into()),
            ..Default::default()
        });
        s.transcript.push(TranscriptLine {
            kind: LineKind::Model,
            text: "## Summary\n\nIt is **done**.\n\n> a quote".into(),
            time: Some("16:46".into()),
            ..Default::default()
        });
        let rows = frame(&mut tui, &s, "", None, w, h);
        let (c0, r0) = at(&rows, "make the tests");
        let (c1, r1) = at(&rows, "a quote");
        // From the gutter mark of the first row to past the last word.
        let text = copied(&mut tui, &s, (c0 - 4, r0), (c1 + 20, r1), w, h);
        assert_eq!(
            text,
            "make the tests pass\n\nSummary\n\nIt is done.\n\n\u{2502} a quote"
        );
        for mark in ["\u{258e}", "\u{203a}", "\u{2726}", "16:46"] {
            assert!(!text.contains(mark), "{mark:?} copied:\n{text}");
        }
    }

    /// While the person is typing the card shows no buttons at all (it says
    /// "paused while you type"), so there is nothing to click.
    #[test]
    fn a_paused_card_has_no_buttons() {
        let (w, h) = (164, 48);
        let mut tui = fresh_tui();
        let mut s = with_approval();
        s.last_key_ms = 5_000;
        tui.tick_ms = 5_100;
        let rows = frame(&mut tui, &s, "", None, w, h);
        assert!(
            rows.iter().any(|r| r.contains("paused while you type")),
            "{}",
            rows.join("\n")
        );
        assert!(!rows.iter().any(|r| r.contains("allow once")));
        // No card button — the status line keeps its own `y allow`, which
        // goes through the same key handler and the same pause.
        assert!(!tui.hits.iter().any(|hit| hit.rect.y < h - 1
            && matches!(
                hit.click,
                super::super::shell::hits::Click::Key(KeyCode::Char('y'), _)
            )));
    }

    /// A card with a pending request, a registered worker to answer, and
    /// the rule `s` and `a` would remember.
    fn parked(
        can_save: bool,
        offered: bool,
    ) -> (
        Scenario,
        ApprovalRegistry,
        std::sync::mpsc::Receiver<crate::ApprovalResponse>,
    ) {
        let mut s = with_approval();
        s.approval_call_id = Some("c1".into());
        s.approval_queue = vec!["Edit".into()];
        if offered {
            s.approval_grant = Some((
                "c1".into(),
                crate::ApprovalGrant {
                    rule: "Edit(calc.py)".into(),
                    can_save,
                },
            ));
        }
        let reg = ApprovalRegistry::new();
        let (tx, rx) = std::sync::mpsc::channel();
        reg.register("c1", tx);
        (s, reg, rx)
    }

    fn press(s: &mut Scenario, reg: &ApprovalRegistry, code: KeyCode, at_ms: u64) {
        // The previous key was long ago: the card is armed.
        approval_key(
            crossterm::event::KeyEvent::new(code, KeyModifiers::NONE),
            s,
            reg,
            at_ms.saturating_sub(5_000),
            at_ms,
        );
    }

    /// `s` and `a` answer for the rule the card showed; without one, or
    /// where it cannot be saved, they do nothing.
    #[test]
    fn s_and_a_answer_only_for_a_rule_that_was_offered() {
        use crate::ApprovalResponse as R;
        for (key, can_save, offered, want) in [
            ('y', true, true, Some(R::Allow)),
            ('s', true, true, Some(R::AllowRule)),
            ('a', true, true, Some(R::AllowRuleAlways)),
            // `R`, the whole-tool grant, is gone from the card: the key
            // now answers nothing.
            ('R', true, true, None),
            ('a', false, true, None),
            ('s', false, false, None),
            ('a', true, false, None),
        ] {
            let (mut s, reg, rx) = parked(can_save, offered);
            press(&mut s, &reg, KeyCode::Char(key), 10_000);
            assert_eq!(
                rx.try_recv().ok(),
                want,
                "key {key:?}, can_save {can_save}, offered {offered}"
            );
            assert_eq!(
                s.approval_call_id.is_some(),
                want.is_none(),
                "card state for {key:?}"
            );
        }
        // Esc denies at once, without a note.
        let (mut s, reg, rx) = parked(true, true);
        press(&mut s, &reg, KeyCode::Esc, 10_000);
        assert_eq!(rx.try_recv().ok(), Some(R::Deny));
        assert_eq!(reg.take_note("c1"), None);
    }

    /// `n` opens a field for a word on why; ⏎ sends it, esc skips it; the
    /// call is denied either way, and nothing else answers meanwhile.
    #[test]
    fn n_asks_for_a_note_and_the_denial_carries_it() {
        use crate::ApprovalResponse as R;
        let (mut s, reg, rx) = parked(true, true);
        press(&mut s, &reg, KeyCode::Char('n'), 10_000);
        assert_eq!(s.approval_note.as_deref(), Some(""));
        assert!(rx.try_recv().is_err(), "n alone does not answer");
        // `y` is text in the field now, not an approval.
        for c in "use y not n".chars() {
            press(&mut s, &reg, KeyCode::Char(c), 10_100);
        }
        assert!(
            rx.try_recv().is_err(),
            "typing in the field answered the card"
        );
        press(&mut s, &reg, KeyCode::Backspace, 10_200);
        press(&mut s, &reg, KeyCode::Char('!'), 10_300);
        press(&mut s, &reg, KeyCode::Enter, 10_400);
        assert_eq!(rx.try_recv().ok(), Some(R::Deny));
        assert_eq!(reg.take_note("c1").as_deref(), Some("use y not !"));
        assert!(s.approval_note.is_none() && s.approval_call_id.is_none());

        // esc in the field: denied, no note.
        let (mut s, reg, rx) = parked(true, true);
        press(&mut s, &reg, KeyCode::Char('n'), 10_000);
        press(&mut s, &reg, KeyCode::Char('x'), 10_100);
        press(&mut s, &reg, KeyCode::Esc, 10_200);
        assert_eq!(rx.try_recv().ok(), Some(R::Deny));
        assert_eq!(reg.take_note("c1"), None);

        // ⏎ with nothing typed is a plain denial.
        let (mut s, reg, rx) = parked(true, true);
        press(&mut s, &reg, KeyCode::Char('n'), 10_000);
        press(&mut s, &reg, KeyCode::Enter, 10_100);
        assert_eq!(rx.try_recv().ok(), Some(R::Deny));
        assert_eq!(reg.take_note("c1"), None);
    }

    /// The help names every approval key in full: its columns are narrow
    /// and a line that does not fit is cut with an ellipsis, which for a
    /// line about what a key grants hides the part that matters.
    #[test]
    fn the_help_names_every_approval_key_without_clipping() {
        let mut tui = fresh_tui();
        for (w, h) in [(120u16, 40u16), (164, 48), (94, 40)] {
            let text = frame(&mut tui, &Scenario::new(), "", Some(Overlay::Help), w, h).join("\n");
            for line in [
                "allow once",
                "this kind of call, session",
                "same, saved in this folder",
                "the whole tool, session",
                "deny, with a word on why",
            ] {
                assert!(
                    text.contains(line),
                    "{w}x{h}: {line:?} missing or clipped:\n{text}"
                );
            }
        }
    }

    /// A rule derived for another call is not offered: the card must never
    /// name one rule while `s` grants another.
    #[test]
    fn a_rule_for_another_call_is_not_offered() {
        let detail = |call: &str| Msg::ApprovalDetail {
            call_id: call.into(),
            facts: vec![],
            preview: vec![],
            grant: Some(crate::ApprovalGrant {
                rule: "Edit(other.py)".into(),
                can_save: true,
            }),
        };
        let mut s = with_approval(); // the card is about c1
        apply_msg(detail("c2"), &mut s, 3);
        assert!(s.offered_grant().is_none(), "c2's rule on c1's card");
        let reg = ApprovalRegistry::new();
        let (tx, rx) = std::sync::mpsc::channel();
        reg.register("c1", tx);
        press(&mut s, &reg, KeyCode::Char('s'), 10_000);
        press(&mut s, &reg, KeyCode::Char('a'), 10_000);
        assert!(
            rx.try_recv().is_err(),
            "s or a answered for another call's rule"
        );
        // The same detail, for the call that is asking, is offered.
        apply_msg(detail("c1"), &mut s, 4);
        assert_eq!(
            s.offered_grant().map(|g| g.rule.as_str()),
            Some("Edit(other.py)")
        );
    }

    /// The decision keys are disabled for a second after the last
    /// keypress: typing cannot answer the card, and `n` cannot open the
    /// field by accident either.
    #[test]
    fn the_new_keys_obey_the_arming_delay() {
        for key in ['y', 's', 'a', 'n'] {
            let (mut s, reg, rx) = parked(true, true);
            approval_key(
                crossterm::event::KeyEvent::new(KeyCode::Char(key), KeyModifiers::NONE),
                &mut s,
                &reg,
                9_800, // the previous key, 200 ms ago
                10_000,
            );
            assert!(rx.try_recv().is_err(), "{key:?} answered inside the delay");
            assert!(
                s.approval_note.is_none(),
                "{key:?} opened the field inside the delay"
            );
        }
    }

    /// A card that has just appeared answers no click for 700 ms.
    #[test]
    fn a_card_that_just_appeared_answers_no_click() {
        let mut s = with_approval();
        s.approval_call_id = Some("c1".into());
        s.approval_shown_ms = 10_000;
        assert!(card_just_appeared(&s, 10_300));
        assert!(!card_just_appeared(&s, 10_700));
        s.approval_call_id = None;
        assert!(!card_just_appeared(&s, 10_100), "no card, no guard");
    }

    /// An overlay answers only its own controls: a click anywhere else on
    /// it closes it, and what is drawn behind it cannot be clicked through.
    #[test]
    fn a_modal_swallows_clicks_aimed_behind_it() {
        let (w, h) = (164, 48);
        let mut tui = fresh_tui();
        let s = Scenario::new();
        // Closed: the composer hint is a button.
        let rows = frame(&mut tui, &s, "", None, w, h);
        let send = at(&rows, "⏎ send");
        assert_eq!(key_of(click(&mut tui, send, false, w, h)), KeyCode::Enter);
        // Open: the same spot closes the palette instead of sending.
        let rows = frame(&mut tui, &s, "", Some(Overlay::Palette), w, h);
        assert_eq!(key_of(click(&mut tui, send, true, w, h)), KeyCode::Esc);
        // Inside the palette box, off any row: nothing happens.
        let filter = at(&rows, "type to filter");
        assert_eq!(click(&mut tui, filter, true, w, h), MouseOutcome::None);
        // A row runs that command.
        let first = at(&rows, "/help");
        assert!(matches!(
            click(&mut tui, first, true, w, h),
            MouseOutcome::Palette(_)
        ));
    }

    /// Under the diff overlay, a click anywhere closes it ("a look, not a
    /// mode"), including on the text.
    #[test]
    fn a_click_closes_the_diff_overlay() {
        let (w, h) = (164, 48);
        let mut tui = fresh_tui();
        let mut s = Scenario::new();
        s.file_changes = vec![crate::proto::panels::FileChangeRow {
            path: "a.rs".into(),
            added: 1,
            removed: 0,
            hunks: None,
        }];
        let rows = frame(&mut tui, &s, "", Some(Overlay::Diff), w, h);
        let o = click(&mut tui, at(&rows, "no diff captured"), true, w, h);
        assert_eq!(key_of(o), KeyCode::Esc);
    }

    /// The quit card's buttons are y and n.
    #[test]
    fn the_quit_card_buttons_are_y_and_n() {
        let (w, h) = (164, 48);
        let mut tui = fresh_tui();
        let rows = frame(&mut tui, &Scenario::new(), "", Some(Overlay::Quit), w, h);
        assert_eq!(
            key_of(click(&mut tui, at(&rows, "quit"), true, w, h)),
            KeyCode::Char('y')
        );
        assert_eq!(
            key_of(click(&mut tui, at(&rows, "stay"), true, w, h)),
            KeyCode::Char('n')
        );
    }

    /// While arranging, the panels are dimmed and numbered: their hints
    /// are not buttons (a click focuses the panel), but the arrange bar's
    /// own keys are.
    #[test]
    fn arranging_leaves_only_the_arrange_bar_clickable() {
        let (w, h) = (164, 48);
        let mut tui = fresh_tui();
        tui.app.key(crate::proto::app::Key::Esc);
        assert!(tui.app.arranging);
        let rows = frame(&mut tui, &Scenario::new(), "", None, w, h);
        // Behind the veil, the composer's hint is just a panel to focus.
        assert_eq!(
            click(&mut tui, at(&rows, "⏎ send"), false, w, h),
            MouseOutcome::None
        );
        // The arrange bar names real keys.
        assert_eq!(
            key_of(click(&mut tui, at(&rows, "split right"), false, w, h)),
            KeyCode::Char('v')
        );
        assert_eq!(
            key_of(click(&mut tui, at(&rows, "back"), false, w, h)),
            KeyCode::Char('i')
        );
    }

    /// A key hint inside a panel goes to THAT panel: clicking `⏎ full diff`
    /// on the Changes panel while the composer has focus must not press
    /// Enter into the composer (it would send the draft).
    #[test]
    fn a_hint_focuses_its_panel_before_its_key() {
        let (w, h) = (164, 48);
        let mut tui = fresh_tui();
        let mut s = Scenario::new();
        s.file_changes = vec![crate::proto::panels::FileChangeRow {
            path: "a.rs".into(),
            added: 1,
            removed: 0,
            hunks: None,
        }];
        let rows = frame(&mut tui, &s, "", None, w, h);
        let conv = tui.app.focus;
        assert_eq!(
            tui.app.focused_view(),
            crate::proto::layout::View::Conversation
        );
        let o = click(&mut tui, at(&rows, "full diff"), false, w, h);
        assert_eq!(key_of(o), KeyCode::Enter);
        assert_ne!(
            tui.app.focus, conv,
            "focus moved to the Changes panel first"
        );
        assert_eq!(tui.app.focused_view(), crate::proto::layout::View::Changes);
    }

    /// The top bar's layout tabs apply their preset.
    #[test]
    fn a_layout_tab_applies_its_preset() {
        let (w, h) = (164, 48);
        let mut tui = fresh_tui();
        let rows = frame(&mut tui, &Scenario::new(), "", None, w, h);
        let review = at(&rows, "review");
        assert_eq!(review.1, 0, "the tab is in the top bar");
        click(&mut tui, review, false, w, h);
        assert_eq!(tui.app.current_preset(), Some(Preset::Review));
    }

    /// On a narrow screen the top bar is a panel switcher: a tab focuses
    /// its panel (it used to apply a layout preset by column arithmetic
    /// meant for the wide bar).
    #[test]
    fn a_switcher_tab_focuses_its_panel() {
        let (w, h) = (100, 30);
        let mut tui = fresh_tui();
        let before = tui.app.current_preset();
        let rows = frame(&mut tui, &Scenario::new(), "", None, w, h);
        let tab = at(&rows, "Terminal");
        assert_eq!(tab.1, 0);
        click(&mut tui, tab, false, w, h);
        assert_eq!(tui.app.focused_view(), crate::proto::layout::View::Terminal);
        assert_eq!(tui.app.current_preset(), before, "no preset was applied");
    }

    fn two_files() -> Scenario {
        let mut s = Scenario::new();
        let row = |p: &str, a| crate::proto::panels::FileChangeRow {
            path: p.into(),
            added: a,
            removed: 0,
            hunks: None,
        };
        s.file_changes = vec![row("src/first.rs", 3), row("src/second.rs", 7)];
        s
    }

    /// A row of the files list is a click target in both panels that list
    /// files; the first click selects, a click on the selected row opens it.
    #[test]
    fn a_file_row_selects_and_a_second_click_opens_the_diff() {
        let (w, h) = (164, 48);
        let mut tui = fresh_tui();
        tui.app.apply_preset(Preset::Review);
        let mut s = two_files();
        let rows = frame(&mut tui, &s, "", None, w, h);
        let row = rows
            .iter()
            .position(|r| r.contains("src/second.rs") && r.contains("+7"))
            .map(|y| (at(&rows, "src/second.rs").0, y as u16))
            .expect("second file's row");
        let o = click(&mut tui, row, false, w, h);
        assert_eq!(o, MouseOutcome::File(1));
        assert_eq!(tui.app.focused_view(), crate::proto::layout::View::Review);
        assert!(!click_file(&mut s, 1), "first click only selects");
        assert_eq!(s.selected_file(), Some(1));
        assert!(
            click_file(&mut s, 1),
            "a click on the selected row opens its diff"
        );
        assert!(!click_file(&mut s, 0));
        assert_eq!((s.selected_file(), s.hunk_sel), (Some(0), 0));
    }

    /// A command's tab in the Terminal is a click target.
    #[test]
    fn a_terminal_tab_selects_its_command() {
        use crate::proto::scenario::{LineKind, Tape, ToolState, TranscriptLine};
        let (w, h) = (164, 48);
        let mut tui = fresh_tui();
        let mut s = Scenario::new();
        for (id, cmd) in [("t1", "cargo test"), ("t2", "ls -la")] {
            s.transcript.push(TranscriptLine {
                kind: LineKind::Tool,
                text: cmd.into(),
                tool_name: "Bash".into(),
                call_id: id.into(),
                tool_state: ToolState::Done,
                ..Default::default()
            });
            s.tapes.push(Tape {
                call_id: id.into(),
                ..Default::default()
            });
        }
        let rows = frame(&mut tui, &s, "", None, w, h);
        // Numbered tabs: `✓1` is the first command's, `✓2 ls -la` the lit one.
        let first = at(&rows, "✓1");
        let o = click(&mut tui, first, false, w, h);
        assert_eq!(o, MouseOutcome::Tape(0));
        assert_eq!(tui.app.focused_view(), crate::proto::layout::View::Terminal);
        s.pick_tape(0);
        assert_eq!(s.selected_tape(), Some(0));
        let rows = frame(&mut tui, &s, "", None, w, h);
        let second = at(&rows, "✓2");
        assert_eq!(click(&mut tui, second, false, w, h), MouseOutcome::Tape(1));
    }

    /// A row of the `/` list is a click target, indexed in the WHOLE list.
    #[test]
    fn a_slash_row_is_a_target() {
        let (w, h) = (164, 48);
        let mut tui = fresh_tui();
        let rows = frame(&mut tui, &Scenario::new(), "/he", None, w, h);
        let list = super::super::chrome::slash_list("/he");
        let (idx, (cmd, _)) = list
            .iter()
            .enumerate()
            .find(|(_, (c, _))| *c == "/help")
            .expect("/help matches /he");
        let o = click(&mut tui, at(&rows, cmd), false, w, h);
        assert_eq!(o, MouseOutcome::Slash(idx));
    }

    /// Wheel and drag still belong to the panel under the pointer.
    #[test]
    fn the_wheel_still_scrolls_the_panel_under_it() {
        let (w, h) = (164, 48);
        let mut tui = fresh_tui();
        frame(&mut tui, &Scenario::new(), "", None, w, h);
        let m = MouseEvent {
            kind: MouseEventKind::ScrollUp,
            column: 80,
            row: 20,
            modifiers: KeyModifiers::NONE,
        };
        handle_mouse(m, &mut tui, Rect::new(0, 0, w, h), None, false);
        assert!(tui.scrolls.contains(&3), "{:?}", tui.scrolls);
        // …but not while an overlay is up.
        let before = tui.scrolls.clone();
        handle_mouse(m, &mut tui, Rect::new(0, 0, w, h), None, true);
        assert_eq!(tui.scrolls, before);
    }
}

#[cfg(test)]
mod subagent_tests {
    use super::*;
    use crate::msg::Msg;

    fn start(s: &mut Scenario, now: u64) {
        apply_msg(
            Msg::SubagentStarted {
                id: "a1".into(),
                name: "Explore".into(),
                task: "find where add() is defined".into(),
            },
            s,
            now,
        );
    }

    /// A subagent is listed with what it was asked, what it is doing, and
    /// — once it ends — what it reported. The task used to be overwritten
    /// by the first progress line and the report by nothing at all.
    #[test]
    fn a_subagent_has_a_task_an_action_and_a_report() {
        let mut s = Scenario::new();
        start(&mut s, 1_000);
        let a = &s.agents["a1"];
        assert_eq!(a.task, "find where add() is defined");
        assert!(a.action.is_empty(), "nothing started yet");
        assert!(!a.done && a.ok);
        assert_eq!(s.agents_running, 1);

        apply_msg(
            Msg::SubagentProgress {
                id: "a1".into(),
                action: "Read calc.py".into(),
            },
            &mut s,
            2_000,
        );
        let a = &s.agents["a1"];
        assert_eq!(a.action, "Read calc.py");
        assert_eq!(a.task, "find where add() is defined", "the task stays");

        let toast = apply_msg(
            Msg::SubagentFinished {
                id: "a1".into(),
                report: "add() is in calc.py".into(),
                ok: true,
            },
            &mut s,
            4_000,
        );
        assert_eq!(toast.as_deref(), Some("agent Explore done"));
        let a = &s.agents["a1"];
        assert!(a.done && a.ok);
        assert_eq!(a.report, "add() is in calc.py");
        assert_eq!(a.action, "Read calc.py", "its last action is kept");
        assert_eq!(a.done_ms, Some(4_000));
        assert_eq!(s.agents_running, 0);
    }

    /// A subagent that failed or was stopped says so: the toast and the
    /// panel must not call it done.
    #[test]
    fn a_failed_subagent_is_not_called_done() {
        let mut s = Scenario::new();
        start(&mut s, 1_000);
        let toast = apply_msg(
            Msg::SubagentFinished {
                id: "a1".into(),
                report: "ORBIT-E0403 credential_rejected".into(),
                ok: false,
            },
            &mut s,
            2_000,
        );
        assert_eq!(toast.as_deref(), Some("agent Explore failed"));
        let a = &s.agents["a1"];
        assert!(a.done && !a.ok);
        assert_eq!(a.report, "ORBIT-E0403 credential_rejected");
    }
}

#[cfg(test)]
mod context_tests {
    use super::*;
    use crate::msg::Msg;
    use orbit_frontend_protocol::ContextBreakdown;

    fn breakdown() -> ContextBreakdown {
        ContextBreakdown {
            system: 3_200,
            tools: 6_100,
            memory: 12_400,
            messages: 54_000,
            compact_at: 144_000,
            reserve: 16_000,
        }
    }

    #[test]
    fn usage_keeps_the_breakdown_the_engine_measured() {
        let mut s = Scenario::new();
        apply_msg(
            Msg::Usage {
                used_tokens: 80_000,
                window_tokens: 200_000,
                breakdown: Some(breakdown()),
            },
            &mut s,
            1,
        );
        assert_eq!(s.ctx_breakdown, Some(breakdown()));
        // A later event without one (an older producer) clears it: the
        // panel must not keep drawing parts that no longer add up.
        apply_msg(
            Msg::Usage {
                used_tokens: 81_000,
                window_tokens: 200_000,
                breakdown: None,
            },
            &mut s,
            2,
        );
        assert_eq!(s.ctx_breakdown, None);
    }

    /// A compaction is a row of history: when, and from how much to how
    /// much. A finish with no start (never announced) adds nothing.
    #[test]
    fn a_compaction_is_remembered_with_its_sizes() {
        let mut s = Scenario::new();
        apply_msg(
            Msg::Compaction {
                running: false,
                tokens: 5,
            },
            &mut s,
            1,
        );
        assert!(s.compactions.is_empty(), "a finish nobody started");
        apply_msg(
            Msg::Compaction {
                running: true,
                tokens: 180_000,
            },
            &mut s,
            2,
        );
        apply_msg(
            Msg::Compaction {
                running: false,
                tokens: 12_000,
            },
            &mut s,
            3,
        );
        assert_eq!(s.compactions.len(), 1);
        let c = &s.compactions[0];
        assert_eq!((c.before, c.after), (180_000, 12_000));
        assert_eq!(c.time.len(), 8, "HH:MM:SS");
        assert!(s.compacting_from.is_none());
    }

    #[test]
    fn the_history_keeps_the_last_twenty() {
        let mut s = Scenario::new();
        for i in 0..30u64 {
            apply_msg(
                Msg::Compaction {
                    running: true,
                    tokens: 1000 + i,
                },
                &mut s,
                1,
            );
            apply_msg(
                Msg::Compaction {
                    running: false,
                    tokens: 10 + i,
                },
                &mut s,
                2,
            );
        }
        assert_eq!(s.compactions.len(), 20);
        assert_eq!(s.compactions[0].before, 1010, "the oldest ten went");
    }

    /// `/usage` prints the numbers the panel draws.
    #[test]
    fn the_summary_matches_the_panel() {
        let mut s = Scenario::new();
        assert_eq!(context_summary(&s), None, "nothing measured yet");
        s.window_tokens = 200_000;
        s.used_tokens = 80_000;
        s.ctx_breakdown = Some(breakdown());
        let line = context_summary(&s).unwrap();
        for want in [
            "context 80k of 200k",
            "system ~3.2k",
            "tools ~6.1k",
            "memory ~12.4k",
            "messages ~54k",
            "free ~124k",
            "compacts at ~144k",
        ] {
            assert!(line.contains(want), "missing {want:?}: {line}");
        }
    }
}
