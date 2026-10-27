//! The prototype runtime (DR-20): the event loop that owns the
//! keyboard, the bus and the draw. The layout is the user's panel tree
//! (presets, arrange mode, saved to `tui.toml`); the screen is a pure
//! function of that tree, the scenario and the tick.

use std::io::Write;
use std::time::{Duration, Instant};

use crossterm::event::{self, Event, KeyCode, KeyModifiers};
use ratatui::layout::Rect;
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use unicode_segmentation::UnicodeSegmentation;
use unicode_width::UnicodeWidthChar;

use super::comps;
use super::core::Token;
use super::scenario::{
    LineKind, OrdinaryIntent, Picker, PickerKind, PickerRow, Scenario, ToolState, TranscriptLine,
    TurnReport,
};
use super::screen::Focus;
use super::shell::printable_text;
use crate::worker::WorkerCtx;

use crate::ApprovalRegistry;
use crate::WorkerCommand;
use crate::bus::{Bus, BusSender};
use crate::worker::CommandSink;

/// The UI tick: 16 ms. §10.5 — an idle ORBIT draws nothing; the loop
/// still polls so redraws after events are instant.
const UI_TICK: Duration = Duration::from_millis(16);

/// The composer history's bound (§11.3): newest first, the last 200
/// prompts. The persisted file holds the same bound.
const HISTORY_MAX: usize = 200;

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
    /// The model picker (`/models`): rows ride on `scenario.picker`.
    ModelPicker,
    /// The session picker (`/sessions`).
    SessionPicker,
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
    pub profile: orbit_frontend_protocol::customization::Profile,
    pub customization: Option<crate::customization::CustomizationSession>,
    pub focus: Focus,
    pub star: super::anim::StarClock,
    pub reduced: bool,
    pub tick_ms: u64,
    pub brand_tier: super::welcome::BrandTier,
    pub brand_preference: super::welcome::BrandTier,
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
    /// Insertion point in the composer, measured in grapheme clusters.
    pub composer_cursor: usize,
    /// Workspace file suggestions; accepting one changes only the draft.
    pub file_completion: super::composer::FileCompletion,
    /// An active reverse search, including the draft to restore on Escape.
    pub history_search: Option<super::composer::HistorySearch>,
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
            profile: Default::default(),
            customization: None,
            focus: Focus::Conversation,
            star: super::anim::StarClock::new(),
            reduced: false,
            tick_ms: 0,
            brand_tier: super::welcome::BrandTier::Static,
            brand_preference: super::welcome::BrandTier::Static,
            app: super::app::App::new(std::path::PathBuf::new(), false),
            fx: super::shell::Fx::default(),
            tier: super::core::Tier::TrueColor,
            scrolls: Vec::new(),
            selection: None,
            completion_sel: 0,
            composer_cursor: 0,
            file_completion: super::composer::FileCompletion::default(),
            history_search: None,
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
    run_proto_inner(
        args,
        worker_spawner,
        startup_home_from_env(),
        crate::model::StartupIdentity::from_env(),
        None,
    )
}

/// The caller owns storage/policy. This frontend only consumes the checked host interface.
pub fn run_proto_with_customization(
    args: &[String],
    worker_spawner: crate::worker::WorkerSpawner,
    host: std::sync::Arc<dyn orbit_frontend_protocol::customization::ProfileHost>,
) -> i32 {
    run_proto_with_startup(
        args,
        worker_spawner,
        startup_home_from_env(),
        crate::model::StartupIdentity::from_env(),
        host,
    )
}

/// Start with the same resolved home and identity used by the caller's worker.
pub fn run_proto_with_startup(
    args: &[String],
    worker_spawner: crate::worker::WorkerSpawner,
    home: std::path::PathBuf,
    identity: crate::model::StartupIdentity,
    host: std::sync::Arc<dyn orbit_frontend_protocol::customization::ProfileHost>,
) -> i32 {
    match crate::customization::CustomizationSession::open(host) {
        Ok(session) => run_proto_inner(args, worker_spawner, home, identity, Some(session)),
        Err(error) => {
            eprintln!("orbit-tui: {error}");
            1
        }
    }
}

fn startup_home_from_env() -> std::path::PathBuf {
    std::env::var("ORBIT_HOME")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::path::PathBuf::from(".orbit"))
}

fn run_proto_inner(
    args: &[String],
    worker_spawner: crate::worker::WorkerSpawner,
    home: std::path::PathBuf,
    identity: crate::model::StartupIdentity,
    customization: Option<crate::customization::CustomizationSession>,
) -> i32 {
    // tui.toml (Appendix C): colour mode, glyphs, motion, brand,
    // notify, colours, layout.
    let safe_session = args.iter().any(|arg| arg == "--safe-customization")
        || customization
            .as_ref()
            .is_some_and(|session| session.resolved.revision == "session-defaults");
    let raw = match load_legacy_theme(&home, safe_session) {
        Ok(theme) => theme,
        Err(error) => {
            eprintln!("orbit-tui: {error}");
            return 1;
        }
    };
    let profile = select_profile(&raw, customization.as_ref().map(|c| &c.resolved.profile));
    if let Err(error) = profile.validate() {
        eprintln!("orbit-tui: {error}");
        return 1;
    }
    let reduced = profile.reduced_motion;
    // Brand tier (Appendix C): `off` by default; reduced motion caps
    // at `static`.
    let brand_preference = {
        use super::welcome::BrandTier;
        match raw.capabilities.brand.as_str() {
            "anim" => BrandTier::Anim,
            "text" => BrandTier::Text,
            "static" => BrandTier::Static,
            _ => BrandTier::Off,
        }
    };
    let brand_tier = {
        use super::welcome::BrandTier;
        if reduced && brand_preference == BrandTier::Anim {
            BrandTier::Static
        } else {
            brand_preference
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
    scenario.welcome_chips = crate::model::compute_readiness_with_identity(&home, &identity)
        .into_iter()
        .map(|r| (r.ok, r.label))
        .collect();
    // The model name arrives via Msg::Identity; the waiting line
    // needs it before then too.
    scenario.model = identity.model.clone();

    let mut tui = Tui {
        profile,
        customization,
        focus: Focus::Conversation,
        star: super::anim::StarClock::new(),
        reduced,
        tick_ms: 0,
        brand_tier,
        brand_preference,
        app: super::app::App::new(home.clone(), reduced),
        fx: super::shell::Fx::default(),
        tier: super::core::Tier::detect(
            std::env::var_os("NO_COLOR").is_some(),
            std::env::var("COLORTERM").ok().as_deref(),
            std::env::var("TERM").ok().as_deref(),
        ),
        scrolls: Vec::new(),
        selection: None,
        completion_sel: 0,
        composer_cursor: 0,
        file_completion: super::composer::FileCompletion::default(),
        history_search: None,
        hits: Vec::new(),
    };
    if let Some(session) = tui.customization.as_mut() {
        match crate::customization::profile_tree(&session.resolved.profile) {
            Ok(tree) => {
                tui.app.tree = tree;
                crate::customization::focus_conversation(&mut tui.app);
            }
            Err(error) => {
                eprintln!("orbit-tui: {error}");
                return 1;
            }
        }
        session.refresh_all();
        scenario.custom_panes = session.outputs.clone();
    }
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
    // Composer history (§11.3), newest first. Persisted per session
    // (`sessions/<id>.history`): the caller supplies the same session id
    // the worker saves under, so a resumed session's memory loads before input.
    let history_path = composer_history_path(&home, &identity);
    let mut history: Vec<String> = history_path
        .as_ref()
        .and_then(|p| std::fs::read_to_string(p).ok())
        .map(|raw| read_history(&raw))
        .unwrap_or_default();
    let mut history_idx: Option<usize> = None;
    // The history length as of the last key: a change means a send
    // happened, and the file is written then, not at exit.
    let mut history_len_at_key = history.len();
    // Copy mode is `z y` (§11.2); armed by z.
    let mut pending_leader: Option<char> = None;
    let mut want_copy_mode = false;
    // The Sessions push (§8.2 Medium): Shift-Tab from Conversation.
    let mut sessions_pushed = false;

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
    let mut last_tick = Instant::now();
    let boot_ms = Instant::now();
    let mut last_drawn = String::new();
    let mut overlay_dirty = true;
    // A key a click stands for, handled on the next turn of the loop as
    // if it had been typed.
    let mut injected: Option<Event> = None;
    let mut pending_picker_click: Option<PickerClick> = None;
    let mut pending_palette_click: Option<PaletteClick> = None;
    let mut last_palette_frame: Option<PaletteFrame> = None;
    // The last frame drawn: a selection copies its text from here.
    let mut last_buf: Option<ratatui::buffer::Buffer> = None;

    let mut exit_code = 0;
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
        let ev = if let Some(click) = pending_picker_click.take() {
            picker_click_key(click, &mut scenario, overlay, now_ms).map(Event::Key)
        } else if let Some(click) = pending_palette_click.take() {
            palette_click_key(click, &scenario, overlay, &palette_query, &mut palette_sel)
                .map(Event::Key)
        } else {
            match injected.take() {
                Some(e) => Some(e),
                None => match event::poll(timeout) {
                    Ok(true) => event::read().ok(),
                    Ok(false) => None,
                    Err(_) => {
                        exit_code = crate::terminal::take_pending_signal()
                            .map_or(1, crate::terminal::ShutdownSignal::exit_code);
                        break;
                    }
                },
            }
        };
        if let Some(ev) = ev {
            match ev {
                Event::Key(k) => {
                    overlay_dirty = true;
                    let snap_before =
                        super::shell::Snap::of(&tui.app, overlay_code(overlay), palette_sel);
                    let handled_custom = handle_custom_key(
                        k,
                        &mut tui,
                        &mut scenario,
                        &mut composer,
                        cancel_handle.as_ref(),
                        &mut toast,
                        now_ms,
                        overlay.is_some(),
                    );
                    let quit = if handled_custom {
                        false
                    } else {
                        handle_key(
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
                        )
                    };
                    let snap_after =
                        super::shell::Snap::of(&tui.app, overlay_code(overlay), palette_sel);
                    tui.fx.observe(&snap_before, &snap_after, now_ms);
                    // The composer history persists as it grows: a
                    // send (or a `!` command) is the moment to write
                    // it, not the exit — a signal or a crash must not
                    // lose the session's ↑/↓ memory.
                    if history.len() != history_len_at_key {
                        history_len_at_key = history.len();
                        save_history(&history_path, &history);
                    }
                    if quit {
                        break;
                    }
                }
                Event::Paste(text) => {
                    if handle_paste(
                        &text,
                        &mut tui,
                        &mut scenario,
                        &mut composer,
                        &history,
                        &mut history_idx,
                        overlay.is_some(),
                    ) {
                        scenario.last_key_ms = now_ms;
                        overlay_dirty = true;
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
                        MouseOutcome::Completion(i) => {
                            tui.file_completion.selected = i;
                            injected = Some(Event::Key(crossterm::event::KeyEvent::new(
                                KeyCode::Tab,
                                KeyModifiers::NONE,
                            )));
                        }
                        MouseOutcome::Picker(i) => {
                            pending_picker_click = capture_picker_click(&scenario, overlay, i);
                        }
                        MouseOutcome::CustomAction { panel, action } => {
                            run_pane_action(
                                panel,
                                action,
                                &mut tui,
                                &mut scenario,
                                &mut composer,
                                cancel_handle.as_ref(),
                                &mut toast,
                                now_ms,
                            );
                        }
                        MouseOutcome::Tape(i) => {
                            scenario.pick_tape(i);
                            tui.scroll_follow(); // the other command is read from its end
                        }
                        // The palette is a menu: a click runs the row (⏎).
                        MouseOutcome::Palette(i) => {
                            pending_palette_click = capture_palette_click(
                                &scenario,
                                overlay,
                                &palette_query,
                                last_palette_frame.as_ref(),
                                i,
                            );
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
            copy_mode(&mut guard, &scenario);
        }
        if last_tick.elapsed() >= UI_TICK {
            // Signals (SIGHUP/SIGTERM/SIGINT): exit at once — a
            // closed terminal must not leak the process.
            if let Some(sig) = crate::terminal::take_pending_signal() {
                exit_code = sig.exit_code();
                break;
            }
            // Drain the bus into the scenario.
            let msgs_before = scenario.state_version();
            while let Some(msg) = bus.try_recv() {
                if let Some(text) =
                    reduce_runtime_message(msg, &mut tui, &mut scenario, &mut overlay, now_ms)
                {
                    // The agent-done toast (§9.13): replaces any current
                    // toast — the newest event wins.
                    toast = Some(Toast {
                        text,
                        ok: true,
                        shown_ms: now_ms,
                    });
                }
            }
            let mut bus_dirty = scenario.state_version() != msgs_before;
            // The queue (§11.4): when the turn ends and prompts are
            // queued, the head becomes the next user turn.
            if !scenario.is_busy() && !queued.is_empty() {
                let next = queued[0].clone();
                if submit_foreground(
                    &mut scenario,
                    &command_sink,
                    WorkerCommand::Prompt(next.clone()),
                )
                .is_ok()
                {
                    queued.remove(0);
                    if let Some(pos) = scenario
                        .transcript
                        .iter()
                        .position(|l| l.kind == LineKind::Queued && l.text == next)
                    {
                        scenario.transcript[pos].kind = LineKind::User;
                    }
                    scenario.turn_started_ms = now_ms;
                    scenario.apply("round_started", 0);
                }
            }
            let view_dirty = scenario.take_view_dirty();
            bus_dirty |= view_dirty;
            if toast
                .as_ref()
                .is_some_and(|t| now_ms.saturating_sub(t.shown_ms) >= 3000)
            {
                toast = None;
                overlay_dirty = true;
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
                    exit_code = crate::terminal::take_pending_signal()
                        .map_or(1, crate::terminal::ShutdownSignal::exit_code);
                    break;
                };
                last_buf = Some(done.buffer.clone());
                last_palette_frame =
                    capture_palette_frame(&scenario, overlay, &palette_query, &frame_hits);
                tui.hits = frame_hits;
            }
            last_tick = Instant::now();
        }
    }

    drop(guard);
    if let Some(sig) = crate::terminal::take_pending_signal()
        && matches!(exit_code, 0 | 1)
    {
        exit_code = sig.exit_code();
    }
    // The composer history outlives the run: one last save (the sends
    // saved as they happened; this catches nothing on a clean exit,
    // and everything on a signal).
    save_history(&history_path, &history);
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
    let cost = scenario.cost_status_text();
    let _ = writeln!(
        std::io::stdout(),
        "✦ ORBIT  session · {} turns · {} in · {} out · {cost}{session}",
        scenario.turns,
        scenario.input_tokens,
        scenario.output_tokens
    );
    exit_code
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
) -> bool {
    let prev_key_ms = scenario.last_key_ms;
    scenario.last_key_ms = now_ms;
    if k.code == KeyCode::Esc
        || (overlay.is_some()
            && !matches!(overlay, Some(Overlay::ModelPicker | Overlay::SessionPicker)))
        || tui.app.arranging
        || tui.app.picker.is_some()
    {
        scenario.dismiss_picker();
    }
    // Ctrl+C / Ctrl+D (§11.7): the quit card, from anywhere.
    if k.modifiers.contains(KeyModifiers::CONTROL)
        && !k.modifiers.contains(KeyModifiers::ALT)
        && (k.code == KeyCode::Char('c') || k.code == KeyCode::Char('d'))
    {
        scenario.dismiss_picker();
        *overlay = Some(Overlay::Quit);
        return false;
    }
    if let KeyCode::Char(c) = k.code
        && k.modifiers
            .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT)
    {
        let control_only =
            k.modifiers.contains(KeyModifiers::CONTROL) && !k.modifiers.contains(KeyModifiers::ALT);
        let composer_control = control_only
            && matches!(c, 'r' | 'w')
            && tui.focus == Focus::Conversation
            && overlay.is_none()
            && !tui.app.arranging
            && tui.app.picker.is_none()
            && scenario.approval_call_id.is_none();
        if !composer_control {
            return false;
        }
    }
    // Overlays own the keyboard (§9.19–9.21): the key that closes one
    // is spent — it must not also start arranging.
    let had_overlay = overlay.is_some();
    match overlay {
        Some(Overlay::Palette) => match k.code {
            KeyCode::Esc => *overlay = None,
            KeyCode::Up => {
                let last = super::shell::overlays::palette_items(palette_query)
                    .len()
                    .saturating_sub(1);
                *palette_sel = palette_sel.saturating_sub(1).min(last);
            }
            KeyCode::Down => {
                let last = super::shell::overlays::palette_items(palette_query)
                    .len()
                    .saturating_sub(1);
                *palette_sel = palette_sel.saturating_add(1).min(last);
            }
            KeyCode::Enter => {
                let matches = super::shell::overlays::palette_items(palette_query);
                if let Some((cmd, _)) = matches.get(*palette_sel).copied() {
                    *overlay = None;
                    palette_query.clear();
                    let mut fs = false;
                    if let Some(o) = run_command(
                        tui,
                        cmd,
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
        Some(Overlay::ModelPicker | Overlay::SessionPicker) => {
            // The picker owns the keyboard: arrows move, Enter commits,
            // Esc closes. The variant is copied out so the arm can
            // clear `overlay` while matching on it.
            let kind = match overlay {
                Some(Overlay::ModelPicker) => PickerKind::Models,
                _ => PickerKind::Sessions,
            };
            if scenario.approval_call_id.is_some()
                || scenario
                    .picker
                    .as_ref()
                    .is_some_and(|picker| picker.kind != kind)
            {
                scenario.dismiss_picker();
                *overlay = None;
                return false;
            }
            if let Some(picker) = scenario.picker.as_mut() {
                match k.code {
                    KeyCode::Esc => {
                        scenario.picker = None;
                        *overlay = None;
                    }
                    KeyCode::Up | KeyCode::Char('k') => {
                        picker.sel = picker
                            .sel
                            .min(picker.rows.len().saturating_sub(1))
                            .saturating_sub(1);
                    }
                    KeyCode::Down | KeyCode::Char('j') => {
                        picker.sel = picker
                            .sel
                            .saturating_add(1)
                            .min(picker.rows.len().saturating_sub(1));
                    }
                    KeyCode::Enter => {
                        let selected = picker.rows.get(picker.sel).cloned();
                        let picker_kind = picker.kind;
                        scenario.picker = None;
                        *overlay = None;
                        let Some(row) = selected else {
                            return false;
                        };
                        let current_id = scenario
                            .session_binding()
                            .map(|b| b.session_id.clone())
                            .unwrap_or_default();
                        let command = match (picker_kind, kind) {
                            (PickerKind::Models, PickerKind::Models) => {
                                Some(WorkerCommand::SetModel(row.value.clone()))
                            }
                            (PickerKind::Sessions, PickerKind::Sessions) => {
                                // Resuming the session we're already on
                                // is a no-op: just close.
                                (row.value != current_id)
                                    .then_some(WorkerCommand::ResumeSession(row.value.clone()))
                            }
                            _ => None,
                        };
                        if let Some(command) = command
                            && let Err(message) = submit_foreground(scenario, command_sink, command)
                        {
                            *toast = Some(Toast {
                                text: message.into(),
                                ok: false,
                                shown_ms: now_ms,
                            });
                        }
                    }
                    _ => {}
                }
            } else {
                // The rows vanished (worker restart): close.
                scenario.picker = None;
                *overlay = None;
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
    if k.code == KeyCode::Esc && scenario.is_busy() {
        if let Some(search) = tui.history_search.take() {
            tui.composer_cursor = search.restore(composer);
        }
        tui.file_completion
            .sync_at_cursor(composer, tui.composer_cursor);
        tui.file_completion.dismiss();
        if let Some(operation) = scenario.pending_manual() {
            let _ = operation.cancel();
        } else if let Some(cancel) = &cancel_handle {
            cancel();
        }
        return false;
    }

    if tui.focus == Focus::Conversation
        && !tui.app.arranging
        && tui.app.picker.is_none()
        && composer_key(k, tui, composer, history, history_idx)
    {
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
                    save_layout(tui, toast, now_ms);
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
        if let Some(key) = key
            && tui.app.key(key)
        {
            save_layout(tui, toast, now_ms);
        }
        tui.sync_focus();
        return false;
    }
    // Canceling a loading picker spends Escape while its old reply is pending.
    if k.code == KeyCode::Esc && scenario.pending_picker_kind().is_some() {
        return false;
    }

    // esc on an idle, empty composer starts arranging.
    if k.code == KeyCode::Esc
        && composer.is_empty()
        && !scenario.is_busy()
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
                    tui.composer_cursor = super::composer::grapheme_count(composer);
                    *history_idx = None;
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
            if scenario.is_busy() {
                *toast = Some(Toast {
                    text: "wait for the active work to finish".into(),
                    ok: false,
                    shown_ms: now_ms,
                });
                return false;
            }
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
            if let Err(message) = submit_foreground(
                scenario,
                command_sink,
                WorkerCommand::SetMode(next.to_string()),
            ) {
                *toast = Some(Toast {
                    text: message.into(),
                    ok: false,
                    shown_ms: now_ms,
                });
            }
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
                tui.composer_cursor = 1;
                *history_idx = None;
                *completion_sel = 0;
                return false;
            }
            KeyCode::Enter
                if k.modifiers
                    .intersects(KeyModifiers::ALT | KeyModifiers::SHIFT) =>
            {
                // §11.3: Alt+⏎ (and terminals reporting Shift+⏎) inserts a newline.
                super::composer::insert_at_cursor(
                    composer,
                    &mut tui.composer_cursor,
                    "\n",
                );
                *history_idx = None;
            }
            KeyCode::Enter => {
                // The shell bang (gate 1): `!command` runs one command
                if !composer.starts_with('/') && scenario.session_binding().is_none() {
                    *toast = Some(Toast { text: "session ownership is not ready; draft retained".into(), ok: false, shown_ms: now_ms });
                    return false;
                }
                if scenario.is_busy() && ((!scenario.ordinary_pending() && !composer.starts_with('/')) || composer.starts_with('!')) {
                    *toast = Some(Toast { text: "wait for the active work to finish; draft retained".into(), ok: false, shown_ms: now_ms });
                    return false;
                }
                // through the Bash tool's full path on the worker
                // thread — the composer stays responsive (the "!
                // sleep 5" gate).
                if composer.starts_with('!') && composer.trim().len() > 1 {
                    let command = composer.trim()[1..].trim().to_string();
                    composer.clear();
                    tui.composer_cursor = 0;
                    history.insert(0, format!("!{command}"));
                    *history_idx = None;
                    if let Err(message) = submit_foreground(scenario, command_sink, WorkerCommand::ShellBang(command)) {
                        *toast = Some(Toast { text: message.into(), ok: false, shown_ms: now_ms });
                    }
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
                    tui.composer_cursor = 0;
                    let mut fs = false;
                    if let Some(o) = run_command(
                        tui,
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
                    let text = composer.clone();
                    composer.clear();
                    tui.composer_cursor = 0;
                    history.insert(0, text.clone());
                    *history_idx = None;
                    if scenario.ordinary_pending() {
                        queued.push(text.clone());
                        scenario.transcript.push(TranscriptLine {
                            kind: LineKind::Queued,
                            text,
                            ..Default::default()
                        });
                    } else {
                        if let Err(message) = submit_foreground(scenario, command_sink, WorkerCommand::Prompt(text.clone())) {
                            *composer = text;
                            tui.composer_cursor = super::composer::grapheme_count(composer);
                            *toast = Some(Toast { text: message.into(), ok: false, shown_ms: now_ms });
                            return false;
                        }
                        scenario.transcript.push(TranscriptLine {
                            kind: LineKind::User,
                            text: text.clone(),
                            time: Some(now_hhmm()),
                            ..Default::default()
                        });
                        scenario.turn_started_ms = now_ms;
                        scenario.apply("round_started", 0);
                        if scenario.transcript.len() == 1 {
                            scenario.first_prompt_waiting = true;
                        }
                    }
                } else if composer.is_empty() && scenario.can_resend_ordinary()
                    && let Some(intent) = scenario.eligible_ordinary_intent().cloned() {
                    let p = intent.display_text();
                    if let Err(message) = submit_foreground(scenario, command_sink, intent.command()) {
                        *toast = Some(Toast { text: message.into(), ok: false, shown_ms: now_ms });
                        return false;
                    }
                    scenario.transcript.push(TranscriptLine {
                        kind: LineKind::User,
                        text: p.clone(),
                        time: Some(now_hhmm()),
                        ..Default::default()
                    });
                    scenario.turn_started_ms = now_ms;
                    scenario.apply("round_started", 0);
                    *toast = Some(Toast {
                        text: "resent your last prompt".into(),
                        ok: true,
                        shown_ms: now_ms,
                    });
                }
            }
            KeyCode::Up if history_idx.is_none() && !history.is_empty() => {
                *history_idx = Some(0);
                composer.clear();
                composer.push_str(&history[0]);
                tui.composer_cursor = super::composer::grapheme_count(composer);
            }
            KeyCode::Up => {
                if let Some(i) = *history_idx
                    && i + 1 < history.len() {
                        *history_idx = Some(i + 1);
                        composer.clear();
                        composer.push_str(&history[i + 1]);
                        tui.composer_cursor = super::composer::grapheme_count(composer);
                    }
            }
            KeyCode::Down => {
                if let Some(i) = *history_idx {
                    if i == 0 {
                        *history_idx = None;
                        composer.clear();
                        tui.composer_cursor = 0;
                    } else {
                        *history_idx = Some(i - 1);
                        composer.clear();
                        composer.push_str(&history[i - 1]);
                        tui.composer_cursor = super::composer::grapheme_count(composer);
                    }
                }
            }
            KeyCode::Backspace => {
                if super::composer::delete_before_cursor(composer, &mut tui.composer_cursor) {
                    *history_idx = None;
                }
                *completion_sel = 0;
            }
            KeyCode::Delete if k.modifiers.is_empty() => {
                if super::composer::delete_at_cursor(composer, &mut tui.composer_cursor) {
                    *history_idx = None;
                }
                *completion_sel = 0;
            }
            KeyCode::Left if k.modifiers.is_empty() => {
                super::composer::move_left(composer, &mut tui.composer_cursor);
            }
            KeyCode::Right if k.modifiers.is_empty() => {
                super::composer::move_right(composer, &mut tui.composer_cursor);
            }
            KeyCode::Home if k.modifiers.is_empty() => {
                super::composer::move_home(composer, &mut tui.composer_cursor);
            }
            KeyCode::End if k.modifiers.is_empty() => {
                super::composer::move_end(composer, &mut tui.composer_cursor);
            }
            KeyCode::Esc
                // §11.3: Esc closes the completion list; otherwise
                // nothing (the draft is kept).
                if composer == "/" => {
                    composer.clear();
                    tui.composer_cursor = 0;
                }

            _ => {}
        }
        if let KeyCode::Char(c) = k.code {
            if k.modifiers.contains(KeyModifiers::CONTROL)
                && !k
                    .modifiers
                    .intersects(KeyModifiers::ALT | KeyModifiers::SHIFT)
                && c == 'w'
            {
                if super::composer::delete_previous_word(composer, &mut tui.composer_cursor) {
                    *history_idx = None;
                }
            } else if k
                .modifiers
                .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT)
            {
                // Ignore unsupported printable chords instead of leaking
                // their character into the user's prompt.
            } else {
                let ch = if k.modifiers.contains(KeyModifiers::SHIFT) {
                    c.to_uppercase().next().unwrap_or(c)
                } else {
                    c
                };
                super::composer::insert_at_cursor(
                    composer,
                    &mut tui.composer_cursor,
                    &ch.to_string(),
                );
                *history_idx = None;
                *completion_sel = 0;
            }
        }
        tui.composer_cursor = super::composer::clamp_cursor(composer, tui.composer_cursor);
        tui.file_completion
            .sync_at_cursor(composer, tui.composer_cursor);
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

fn handle_paste(
    text: &str,
    tui: &mut Tui,
    scenario: &mut Scenario,
    draft: &mut String,
    history: &[String],
    history_idx: &mut Option<usize>,
    modal_open: bool,
) -> bool {
    if text.is_empty() || modal_open || tui.app.arranging || tui.app.picker.is_some() {
        return false;
    }
    if scenario.approval_call_id.is_some() {
        if let Some(note) = scenario.approval_note.as_mut() {
            note.push_str(text);
            return true;
        }
        return false;
    }
    if tui.focus != Focus::Conversation {
        return false;
    }
    if let Some(search) = tui.history_search.as_mut() {
        search.query.push_str(text);
        search.update(history);
        tui.composer_cursor = search.preview(history, draft);
    } else {
        super::composer::insert_at_cursor(draft, &mut tui.composer_cursor, text);
        *history_idx = None;
        tui.file_completion
            .sync_at_cursor(draft, tui.composer_cursor);
    }
    true
}

/// Draft modes own their keys before send, history navigation or panel focus.
/// Approval cards and overlays are handled before this function is called.
fn composer_key(
    k: crossterm::event::KeyEvent,
    tui: &mut Tui,
    draft: &mut String,
    history: &[String],
    history_idx: &mut Option<usize>,
) -> bool {
    let reverse = k.code == KeyCode::Char('r')
        && k.modifiers.contains(KeyModifiers::CONTROL)
        && !k
            .modifiers
            .intersects(KeyModifiers::ALT | KeyModifiers::SHIFT);
    if reverse && tui.history_search.is_none() {
        tui.file_completion.dismiss();
        let search =
            super::composer::HistorySearch::new_with_cursor(draft, tui.composer_cursor, history);
        tui.composer_cursor = search.preview(history, draft);
        tui.history_search = Some(search);
        *history_idx = None;
        return true;
    }
    if let Some(search) = tui.history_search.as_mut() {
        match k.code {
            KeyCode::Esc => {
                tui.composer_cursor = tui.history_search.take().unwrap().restore(draft);
                tui.file_completion
                    .sync_at_cursor(draft, tui.composer_cursor);
                return true;
            }
            KeyCode::Enter => {
                tui.history_search = None;
                tui.composer_cursor = super::composer::clamp_cursor(draft, tui.composer_cursor);
                tui.file_completion
                    .sync_at_cursor(draft, tui.composer_cursor);
                return true;
            }
            _ if reverse => search.older(history),
            KeyCode::Backspace => {
                let mut cursor = super::composer::grapheme_count(&search.query);
                super::composer::delete_before_cursor(&mut search.query, &mut cursor);
                search.update(history);
            }
            KeyCode::Char(c)
                if !k
                    .modifiers
                    .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
            {
                search.query.push(c);
                search.update(history);
            }
            _ => {}
        }
        tui.composer_cursor = search.preview(history, draft);
        return true;
    }

    tui.file_completion
        .sync_at_cursor(draft, tui.composer_cursor);
    if tui.file_completion.is_open() {
        let picker = &mut tui.file_completion;
        match k.code {
            KeyCode::Up => picker.selected = picker.selected.saturating_sub(1),
            KeyCode::Down => {
                picker.selected = (picker.selected + 1).min(picker.candidates.len() - 1)
            }
            KeyCode::Tab => {
                picker.accept_at_cursor(draft, &mut tui.composer_cursor);
                *history_idx = None;
            }
            KeyCode::Enter
                if !k
                    .modifiers
                    .intersects(KeyModifiers::ALT | KeyModifiers::SHIFT) =>
            {
                picker.accept_at_cursor(draft, &mut tui.composer_cursor);
                *history_idx = None;
            }
            KeyCode::Esc => picker.dismiss(),
            _ => return false,
        }
        return true;
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

/// Render the copy-mode transcript through the same terminal-safe converter
/// as the canvas. This pure formatter is also the unit-test seam for every
/// dynamic value printed after leaving the alternate screen.
fn copy_mode_rows(scenario: &Scenario) -> Vec<String> {
    let sid = if scenario.session_id.is_empty() {
        "—"
    } else {
        scenario.session_id.as_str()
    };
    let mut rows = vec![format!(
        "ORBIT transcript · session {} · select and copy, then press any key to return",
        copy_mode_metadata(sid)
    )];

    for line in &scenario.transcript {
        let time = copy_mode_metadata(line.time.as_deref().unwrap_or_default());
        let text = copy_mode_message(&line.text);
        match line.kind {
            LineKind::User => rows.push(if time.is_empty() {
                format!("you: {text}")
            } else {
                format!("{time} you: {text}")
            }),
            LineKind::Model => rows.push(if time.is_empty() {
                format!("orbit: {text}")
            } else {
                format!("{time} orbit: {text}")
            }),
            LineKind::Tool => {
                let tool_name = copy_mode_metadata(&line.tool_name);
                let state = match line.tool_state {
                    ToolState::Done => ": done",
                    ToolState::Denied => ": denied by you",
                    ToolState::Failed => ": failed",
                    ToolState::Running => ": running",
                    ToolState::AwaitingYou => ": awaiting you",
                    ToolState::Queued => ": queued",
                    ToolState::Blocked => ": blocked",
                    ToolState::Cancelled => ": cancelled",
                    ToolState::Unavailable => ": result unavailable",
                };
                rows.push(if time.is_empty() {
                    format!("tool {tool_name} {text}{state}")
                } else {
                    format!("{time} tool {tool_name} {text}{state}")
                });
            }
            LineKind::System => rows.push(format!("status: {text}")),
            LineKind::Queued => rows.push(format!("queued: {text}")),
        }
    }
    rows
}

/// Keep transcript LF and CRLF as one structural row break. The CR in CRLF
/// is a terminator, while an independent CR remains a visible control picture.
fn copy_mode_message(text: &str) -> String {
    let mut rendered = String::with_capacity(text.len());
    for piece in text.split_inclusive('\n') {
        let has_lf = piece.ends_with('\n');
        let body = if has_lf {
            let body = &piece[..piece.len() - 1];
            body.strip_suffix('\r').unwrap_or(body)
        } else {
            piece
        };
        rendered.push_str(&printable_text(body));
        if has_lf {
            rendered.push('\n');
        }
    }
    rendered
}

/// Metadata is one logical field: render line separators visibly instead of
/// allowing untrusted values to add headers or fields to the copied output.
fn copy_mode_metadata(text: &str) -> String {
    let mut visible = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(ch) = chars.next() {
        match ch {
            '\r' if chars.peek() == Some(&'\n') => {
                chars.next();
                visible.push('␊');
            }
            '\r' => visible.push('␍'),
            '\n' => visible.push('␊'),
            other => visible.push(other),
        }
    }
    printable_text(&visible)
}

const RESTORED_TRANSCRIPT_REDACTED: &str = "[redacted]";
const MAX_RESTORED_CSI_BYTES: usize = 4096;
const MAX_RESTORED_STRING_CONTROL_BYTES: usize = 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RestoredStringControl {
    Osc,
    Dcs,
    Pm,
    Apc,
    Sos,
}

/// A 7-bit string-control designator is meaningful only after ESC. These
/// printable characters must remain ordinary transcript text everywhere else.
fn restored_7bit_string_control(ch: char) -> Option<RestoredStringControl> {
    match ch {
        ']' => Some(RestoredStringControl::Osc),
        'P' => Some(RestoredStringControl::Dcs),
        '^' => Some(RestoredStringControl::Pm),
        '_' => Some(RestoredStringControl::Apc),
        'X' => Some(RestoredStringControl::Sos),
        _ => None,
    }
}

/// C1 string-control introducers are controls in their own right and may
/// appear without a preceding ESC.
fn restored_c1_string_control(ch: char) -> Option<RestoredStringControl> {
    match ch {
        '\u{009d}' => Some(RestoredStringControl::Osc),
        '\u{0090}' => Some(RestoredStringControl::Dcs),
        '\u{009e}' => Some(RestoredStringControl::Pm),
        '\u{009f}' => Some(RestoredStringControl::Apc),
        '\u{0098}' => Some(RestoredStringControl::Sos),
        _ => None,
    }
}

fn restored_default_ignorable(ch: char) -> bool {
    matches!(
        ch as u32,
        0x00ad
            | 0x034f
            | 0x061c
            | 0x115f..=0x1160
            | 0x17b4..=0x17b5
            | 0x180b..=0x180f
            | 0x200b..=0x200f
            | 0x202a..=0x202e
            | 0x2060..=0x206f
            | 0x3164
            | 0xfe00..=0xfe0f
            | 0xfeff
            | 0xffa0
            | 0xfff0..=0xfff8
            | 0x13430..=0x1343f
            | 0x1bca0..=0x1bca3
            | 0x1d173..=0x1d17a
            | 0xe0000..=0xe0fff
    )
}

fn restored_scan_separator(ch: char) -> bool {
    ch.is_control() || UnicodeWidthChar::width(ch) == Some(0) || restored_default_ignorable(ch)
}

fn restored_next_char(text: &str, offset: usize) -> Option<(char, usize)> {
    let ch = text.get(offset..)?.chars().next()?;
    Some((ch, offset + ch.len_utf8()))
}

/// Return the byte after a complete 7-bit or C1 CSI. The parameter and
/// intermediate byte order follows ECMA-48; malformed or unbounded CSI is
/// deliberately ambiguous to the caller.
fn restored_csi_end(text: &str, start: usize) -> Result<usize, ()> {
    let (introducer, mut cursor) = restored_next_char(text, start).ok_or(())?;
    if introducer == '\u{001b}' {
        let (bracket, after_bracket) = restored_next_char(text, cursor).ok_or(())?;
        if bracket != '[' {
            return Err(());
        }
        cursor = after_bracket;
    } else if introducer != '\u{009b}' {
        return Err(());
    }

    let mut saw_intermediate = false;
    loop {
        let (ch, next) = restored_next_char(text, cursor).ok_or(())?;
        if next.saturating_sub(start) > MAX_RESTORED_CSI_BYTES {
            return Err(());
        }
        match ch as u32 {
            0x30..=0x3f if !saw_intermediate => cursor = next,
            0x20..=0x2f => {
                saw_intermediate = true;
                cursor = next;
            }
            0x40..=0x7e => return Ok(next),
            _ => return Err(()),
        }
    }
}

/// Scan one OSC/DCS/PM/APC/SOS body. Printable payload stays visible to H-3;
/// CSI syntax is removed even when nested in a string body. A nested string
/// introducer or unknown ESC form is ambiguous and fails closed.
fn restored_string_control_body(
    text: &str,
    mut cursor: usize,
    kind: RestoredStringControl,
) -> Result<(String, usize), ()> {
    let body_start = cursor;
    let mut payload = String::new();
    loop {
        if cursor.saturating_sub(body_start) > MAX_RESTORED_STRING_CONTROL_BYTES {
            return Err(());
        }
        let (ch, next) = restored_next_char(text, cursor).ok_or(())?;
        if next.saturating_sub(body_start) > MAX_RESTORED_STRING_CONTROL_BYTES {
            return Err(());
        }

        match ch {
            '\u{0007}' if kind == RestoredStringControl::Osc => return Ok((payload, next)),
            '\u{009c}' => return Ok((payload, next)),
            '\u{001b}' => {
                let (following, after_following) = restored_next_char(text, next).ok_or(())?;
                match following {
                    '\\' => {
                        if after_following.saturating_sub(body_start)
                            > MAX_RESTORED_STRING_CONTROL_BYTES
                        {
                            return Err(());
                        }
                        return Ok((payload, after_following));
                    }
                    '[' => cursor = restored_csi_end(text, cursor)?,
                    _ => return Err(()),
                }
            }
            '\u{009b}' => cursor = restored_csi_end(text, cursor)?,
            _ if restored_c1_string_control(ch).is_some() => return Err(()),
            _ if restored_scan_separator(ch) => cursor = next,
            _ => {
                payload.push(ch);
                cursor = next;
            }
        }
        if cursor.saturating_sub(body_start) > MAX_RESTORED_STRING_CONTROL_BYTES {
            return Err(());
        }
    }
}

/// A scan-only view for the restored transcript display gate. It is not a
/// renderer: controls and invisible separators join adjacent text so H-3 sees
/// tokens and role markers split across terminal syntax.
fn restored_transcript_scan(text: &str) -> Result<String, ()> {
    let mut output = String::with_capacity(text.len());
    let mut cursor = 0;
    while cursor < text.len() {
        let (ch, next) = restored_next_char(text, cursor).ok_or(())?;
        match ch {
            '\u{001b}' => {
                let (following, after_introducer) = restored_next_char(text, next).ok_or(())?;
                match following {
                    '[' => cursor = restored_csi_end(text, cursor)?,
                    '\\' => cursor = after_introducer,
                    _ => {
                        let Some(kind) = restored_7bit_string_control(following) else {
                            return Err(());
                        };
                        let (payload, end) =
                            restored_string_control_body(text, after_introducer, kind)?;
                        output.push_str(&payload);
                        cursor = end;
                    }
                }
            }
            '\u{009b}' => cursor = restored_csi_end(text, cursor)?,
            '\u{009c}' => cursor = next,
            _ => {
                if let Some(kind) = restored_c1_string_control(ch) {
                    let (payload, end) = restored_string_control_body(text, next, kind)?;
                    output.push_str(&payload);
                    cursor = end;
                } else if restored_scan_separator(ch) {
                    cursor = next;
                } else {
                    output.push(ch);
                    cursor = next;
                }
            }
        }
    }
    Ok(output)
}

/// Gate the printable restored transcript against both its visible form and
/// a control-free scan. A scan redaction cannot be mapped safely back to
/// visible spans, so any such change withholds the whole message.
fn project_restored_transcript_text(text: &str) -> String {
    let visible = copy_mode_message(text);
    let visible = match orbit_hud::display_safe(&visible) {
        Ok(visible) => visible,
        Err(_) => return RESTORED_TRANSCRIPT_REDACTED.to_string(),
    };
    let scan = match restored_transcript_scan(text) {
        Ok(scan) => scan,
        Err(()) => return RESTORED_TRANSCRIPT_REDACTED.to_string(),
    };
    match orbit_hud::display_safe(&scan) {
        Ok(checked) if checked == scan => visible,
        Ok(_) | Err(_) => RESTORED_TRANSCRIPT_REDACTED.to_string(),
    }
}

/// Copy mode (§9.25): leave the alt screen, print the transcript,
/// wait for a key, return.
fn copy_mode(guard: &mut crate::terminal::TerminalGuard, scenario: &Scenario) {
    let _ = guard.terminal.draw(|_| {});
    let mut stdout = std::io::stdout();
    let _ = crossterm::execute!(stdout, crossterm::terminal::LeaveAlternateScreen);
    // §9.25: one event per line, no box drawing or colour.
    for row in copy_mode_rows(scenario) {
        println!("{row}");
    }
    let _ = event::read();
    let _ = crossterm::execute!(stdout, crossterm::terminal::EnterAlternateScreen);
    guard.terminal.clear().ok();
}

#[cfg(test)]
mod copy_mode_tests {
    use super::*;

    fn line(kind: LineKind, time: &str, tool_name: &str, text: &str) -> TranscriptLine {
        TranscriptLine {
            kind,
            time: Some(time.to_string()),
            tool_name: tool_name.to_string(),
            text: text.to_string(),
            tool_state: ToolState::Done,
            ..TranscriptLine::default()
        }
    }

    #[test]
    fn production_copy_mode_formatter_sanitizes_dynamic_fields_and_keeps_message_breaks() {
        let mut scenario = Scenario::new();
        scenario.session_id = "SID\x1b[2J\r\nAFTER".into();
        scenario.transcript = vec![
            line(
                LineKind::User,
                "UT\x1b]0;user\x07\r\nFIELD",
                "",
                "U-CSI\x1b[2J\nU-LF\r\nU-CRLF-END\r\nU-CR-START\rU-CR-END",
            ),
            line(
                LineKind::Model,
                "MT\nFIELD",
                "",
                "MODEL-OSC\x1b]0;model\x07",
            ),
            line(
                LineKind::Tool,
                "TT\rFIELD",
                "TOOL-NAME\r\nFIELD",
                "TOOL-TEXT\x1b[2J",
            ),
            line(LineKind::System, "", "", "SYSTEM-BEL\x07"),
            line(LineKind::Queued, "", "", "QUEUED-ESC\x1b[2J"),
        ];
        let original_session_id = scenario.session_id.clone();
        let original_transcript = scenario.transcript.clone();

        // Exercise the exact pure formatter called by copy_mode, not just
        // the lower-level printable-text helper.
        let rows = copy_mode_rows(&scenario);
        assert_eq!(rows.len(), 6, "metadata must not add transcript fields");
        assert_eq!(scenario.session_id, original_session_id);
        assert_eq!(scenario.transcript, original_transcript);

        let output = rows.join("\n");
        assert!(
            output.chars().all(|ch| ch == '\n' || !ch.is_control()),
            "raw terminal control reached copy-mode output: {output:?}"
        );
        for safe in [
            "SID␛[2J␊AFTER",
            "UT␛]0;user␇␊FIELD you:",
            "U-CSI␛[2J\nU-LF\nU-CRLF-END\nU-CR-START␍U-CR-END",
            "MT␊FIELD orbit:",
            "MODEL-OSC␛]0;model␇",
            "TT␍FIELD tool TOOL-NAME␊FIELD",
            "TOOL-TEXT␛[2J",
            "SYSTEM-BEL␇",
            "QUEUED-ESC␛[2J",
        ] {
            assert!(
                output.contains(safe),
                "missing safe display {safe:?}: {output:?}"
            );
        }
        assert!(
            !rows[1].contains("U-CRLF-END␍"),
            "CRLF message boundary must not display its CR half"
        );
        assert_eq!(
            rows[0].matches('␊').count(),
            1,
            "CRLF in session metadata must become exactly one marker"
        );
        let user_body = rows[1]
            .split_once(" you:")
            .expect("user label remains present")
            .1;
        assert_eq!(
            user_body.matches('␊').count(),
            0,
            "message LF/CRLF must stay structural, not become markers"
        );
    }

    #[test]
    fn copy_mode_preserves_final_standalone_cr_but_consumes_crlf() {
        assert_eq!(copy_mode_message("status\r"), "status␍");
        assert_eq!(copy_mode_message("line\r\n"), "line\n");
    }
}

#[cfg(test)]
mod restored_transcript_projection_tests {
    use super::*;

    const API_TOKEN: &str = "sk-abc123def456ghi789jkl012mno";
    const ENTROPY_VALUE: &str = "éAbCdEfGhIjKlMnOpQrStUvWxYz0123456789";

    fn assert_withheld(text: &str) {
        assert_eq!(
            project_restored_transcript_text(text),
            RESTORED_TRANSCRIPT_REDACTED,
            "unsafe restored transcript was not withheld: {text:?}"
        );
    }

    #[test]
    fn direct_api_tokens_and_high_entropy_assignments_withhold_the_whole_message() {
        assert_withheld(&format!("before token = {API_TOKEN} after"));
        assert_withheld(&format!("secret note = \"{ENTROPY_VALUE}\""));
    }

    #[test]
    fn csi_and_invisible_separators_cannot_split_a_secret() {
        assert_withheld("token = sk-abc123\u{001b}[31mdef456ghi789jkl012mno");
        assert_withheld("token = sk-abc123\u{009b}31mdef456ghi789jkl012mno");
        assert_withheld("token = sk-abc\u{0007}123\rdef\n456\u{200b}ghi789jkl012mno");
    }

    #[test]
    fn string_payloads_preserve_text_for_secret_and_h3_scanning() {
        assert_withheld(&format!("\u{001b}]0;token={API_TOKEN}\u{0007}"));
        assert_withheld("\u{001b}]0;token=sk-abc123\u{001b}[31mdef456ghi789jkl012mno\u{0007}");
        assert_withheld("\u{001b}]0;pro\u{001b}[31mmpt: hidden\u{0007}");
        assert_withheld("\u{001b}]0;chain_of_\u{001b}[31mthought: hidden\u{0007}");
        assert_withheld(&format!("\u{009d}0;token={API_TOKEN}\u{0007}"));
        assert_withheld("\u{009d}0;token=sk-abc123\u{009b}31mdef456ghi789jkl012mno\u{009c}");
    }

    #[test]
    fn every_supported_string_control_payload_is_scanned() {
        for (start, end) in [
            ("\u{001b}P", "\u{001b}\\"),
            ("\u{001b}_", "\u{001b}\\"),
            ("\u{001b}^", "\u{001b}\\"),
            ("\u{001b}X", "\u{001b}\\"),
            ("\u{0090}", "\u{009c}"),
            ("\u{009f}", "\u{009c}"),
            ("\u{009e}", "\u{009c}"),
            ("\u{0098}", "\u{009c}"),
        ] {
            assert_withheld(&format!(
                "{start}payload sk-abc123\u{001b}[31mdef456ghi789jkl012mno{end}"
            ));
        }
    }

    #[test]
    fn malformed_or_unsupported_escape_syntax_is_ambiguous() {
        for text in [
            "prefix\u{001b}[31",
            "prefix\u{001b}[31\u{0001}m",
            "prefix\u{001b}]unterminated",
            "prefix\u{001b}Punterminated",
            "prefix\u{009d}unterminated",
            "prefix\u{0090}unterminated",
            "prefix\u{001b}",
            "prefix\u{001b}c",
            "prefix\u{001b}(B",
            "prefix\u{001b}\u{0090}nested\u{009c}",
            "prefix\u{001b}]outer\u{001b}_nested\u{001b}\\\u{0007}",
            "\u{001b}]outer\u{0090}nested\u{009c}\u{0007}",
        ] {
            assert!(restored_transcript_scan(text).is_err(), "{text:?}");
            assert_withheld(text);
        }
    }

    #[test]
    fn printable_string_control_designators_remain_ordinary_text() {
        for text in [
            "Please give me a short greeting.",
            "ESC_RECOVERY_OK",
            "COPY_SEED_RESPONSE",
            "Literal ] P ^ _ X designators",
        ] {
            assert_eq!(restored_transcript_scan(text).unwrap(), text, "{text:?}");
            assert_eq!(project_restored_transcript_text(text), text, "{text:?}");
        }

        let payload = "\u{001b}]title: COPY_SEED_RESPONSE P^_X\u{0007}";
        assert_eq!(
            restored_transcript_scan(payload).unwrap(),
            "title: COPY_SEED_RESPONSE P^_X"
        );
        let visible = project_restored_transcript_text(payload);
        assert_ne!(visible, RESTORED_TRANSCRIPT_REDACTED);
        assert!(visible.contains("COPY_SEED_RESPONSE P^_X"));
    }

    #[test]
    fn safe_terminal_markers_and_message_line_structure_remain_visible() {
        assert_eq!(
            project_restored_transcript_text("\u{001b}[31mred\u{001b}[0m\tfirst\r\nsecond\rend"),
            "␛[31mred␛[0m⇥first\nsecond␍end"
        );
        assert_eq!(
            project_restored_transcript_text("\u{001b}]0;window title\u{0007}\n"),
            "␛]0;window title␇\n"
        );
        assert_eq!(
            restored_transcript_scan("\u{001b}]0;window title\u{0007}").unwrap(),
            "0;window title"
        );
        assert_eq!(
            project_restored_transcript_text("plain\nline\r\nend\r"),
            "plain\nline\nend␍"
        );
    }

    #[test]
    fn visible_redaction_does_not_hide_a_second_scan_only_secret() {
        let text = format!(
            "visible token={API_TOKEN}\nhidden: sk-abc123\u{001b}[31mdef456ghi789jkl012mno"
        );
        let visible = copy_mode_message(&text);
        let checked_visible = orbit_hud::display_safe(&visible).unwrap();
        assert!(checked_visible.contains("[redacted:api token]"));
        assert!(checked_visible.contains("sk-abc123"));
        let scan = restored_transcript_scan(&text).unwrap();
        assert_ne!(orbit_hud::display_safe(&scan).unwrap(), scan);
        assert_withheld(&text);
    }

    #[test]
    fn restored_projection_does_not_mutate_the_saved_transcript_bytes() {
        let text = format!("saved token={API_TOKEN}\u{001b}[31m");
        let saved = crate::model::TranscriptLine::User {
            text: text.clone(),
            time: Some("09:30".into()),
        };
        let original = saved.clone();
        let projected = restored_transcript_line(saved);
        assert_eq!(projected.text, RESTORED_TRANSCRIPT_REDACTED);
        let expected = crate::model::TranscriptLine::User {
            text,
            time: Some("09:30".into()),
        };
        assert_eq!(original, expected);
    }
}

fn request_picker(
    scenario: &mut Scenario,
    sink: &CommandSink,
    kind: PickerKind,
    toast: &mut Option<Toast>,
    now_ms: u64,
) {
    let result = scenario.begin_picker_request(kind).and_then(|()| {
        let command = match kind {
            PickerKind::Models => WorkerCommand::ListModels,
            PickerKind::Sessions => WorkerCommand::ListSessions,
        };
        sink.send(command).map_err(|_| {
            scenario.finish_picker_request(kind);
            "worker is unavailable"
        })
    });
    if let Err(message) = result {
        *toast = Some(Toast {
            text: message.into(),
            ok: false,
            shown_ms: now_ms,
        });
    }
}

fn submit_foreground(
    scenario: &mut Scenario,
    sink: &CommandSink,
    command: WorkerCommand,
) -> Result<(), &'static str> {
    let kind = command
        .foreground_kind()
        .ok_or("command cannot own foreground work")?;
    let operation = scenario.new_foreground_operation(kind)?;
    let intent = OrdinaryIntent::from_command(&command);
    let source = operation.source().clone();
    if sink
        .send(WorkerCommand::Bound {
            operation: operation.clone(),
            command: Box::new(command),
        })
        .is_err()
    {
        let _ = operation.finish_unstarted();
        return Err("worker is unavailable");
    }
    // The event loop cannot consume a worker message between this send and
    // admission, even if the worker has already produced its terminal frame.
    if !scenario.admit_foreground(operation) {
        return Err("foreground admission changed");
    }
    if let Some(intent) = intent {
        scenario.remember_ordinary_intent(intent, source);
    }
    scenario.dismiss_picker();
    Ok(())
}

/// Run a `/command` or bare `quit`/`exit` (§11.6). TUI-local ones
/// run at once; the rest go to the worker in order.
#[allow(clippy::too_many_arguments)]
fn run_command(
    tui: &mut Tui,
    text: &str,
    scenario: &mut Scenario,
    composer: &mut String,
    command_sink: &CommandSink,
    sender: &BusSender,
    now_ms: u64,
    toast: &mut Option<Toast>,
    queued: &mut [String],
    history: &mut Vec<String>,
    history_idx: &mut Option<usize>,
    focus_sessions: &mut bool,
) -> Option<Overlay> {
    let _ = (composer, history, history_idx, sender, focus_sessions);
    if text == "quit" || text == "exit" {
        scenario.dismiss_picker();
        return Some(Overlay::Quit);
    }
    let (cmd, arg) = match text.split_once(' ') {
        Some((c, a)) => (c, a.trim()),
        None => (text, ""),
    };
    if scenario.is_busy()
        && !matches!(
            cmd,
            "/help" | "/usage" | "/sessions" | "/models" | "/theme" | "/customize"
        )
    {
        *toast = Some(Toast {
            text: "wait for the active work to finish".into(),
            ok: false,
            shown_ms: now_ms,
        });
        return None;
    }
    let notice = |s: &mut Scenario, t: String| {
        s.transcript.push(TranscriptLine {
            kind: LineKind::System,
            text: t,
            ..Default::default()
        });
    };
    let open: Option<Overlay> = match cmd {
        "/route" => {
            if let Err(message) = submit_foreground(
                scenario,
                command_sink,
                WorkerCommand::Route(arg.to_string()),
            ) {
                *toast = Some(Toast {
                    text: message.into(),
                    ok: false,
                    shown_ms: now_ms,
                });
            }
            None
        }
        "/help" => Some(Overlay::Help),
        "/sessions" => {
            // The session picker: the worker's SessionsListed opens it.
            // The sidebar stays closed; the picker is the navigation.
            request_picker(scenario, command_sink, PickerKind::Sessions, toast, now_ms);
            None
        }
        "/usage" => {
            let cost = scenario.cost_status_text();
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
            } else {
                notice(scenario, "context unknown".into());
            }
            None
        }
        "/models" => {
            request_picker(scenario, command_sink, PickerKind::Models, toast, now_ms);
            None
        }
        "/model" => {
            if arg.is_empty() {
                notice(scenario, "usage: /model <model-id>".into());
            } else {
                if let Err(message) = submit_foreground(
                    scenario,
                    command_sink,
                    WorkerCommand::SetModel(arg.to_string()),
                ) {
                    *toast = Some(Toast {
                        text: message.into(),
                        ok: false,
                        shown_ms: now_ms,
                    });
                }
            }
            None
        }
        "/effort" => {
            if let Err(message) = submit_foreground(
                scenario,
                command_sink,
                WorkerCommand::Effort(arg.to_string()),
            ) {
                *toast = Some(Toast {
                    text: message.into(),
                    ok: false,
                    shown_ms: now_ms,
                });
            }
            None
        }
        "/resume" => {
            if arg.is_empty() {
                notice(scenario, "usage: /resume <session-id>".into());
            } else if scenario.is_busy() {
                *toast = Some(Toast {
                    text: "wait for this turn to finish first".into(),
                    ok: false,
                    shown_ms: now_ms,
                });
            } else {
                if let Err(message) = submit_foreground(
                    scenario,
                    command_sink,
                    WorkerCommand::ResumeSession(arg.to_string()),
                ) {
                    *toast = Some(Toast {
                        text: message.into(),
                        ok: false,
                        shown_ms: now_ms,
                    });
                }
            }
            None
        }
        "/clear" | "/compact" => {
            if !arg.is_empty() || !queued.is_empty() {
                *toast = Some(Toast {
                    text: if !arg.is_empty() {
                        format!("usage: {cmd}")
                    } else {
                        "wait for queued prompts to finish".into()
                    },
                    ok: false,
                    shown_ms: now_ms,
                });
                return None;
            }
            let action = if cmd == "/clear" {
                crate::worker::ManualAction::Clear
            } else {
                crate::worker::ManualAction::Compact
            };
            match scenario.new_manual_operation(action) {
                Ok(operation) => {
                    let command = if action == crate::worker::ManualAction::Clear {
                        WorkerCommand::ClearSession(operation.clone())
                    } else {
                        WorkerCommand::Compact(operation.clone())
                    };
                    if command_sink.send(command).is_ok() {
                        scenario.admit_manual(operation);
                    } else {
                        let _ = operation.finish_unstarted();
                        *toast = Some(Toast {
                            text: "worker is unavailable".into(),
                            ok: false,
                            shown_ms: now_ms,
                        });
                    }
                }
                Err(message) => {
                    *toast = Some(Toast {
                        text: message.into(),
                        ok: false,
                        shown_ms: now_ms,
                    })
                }
            }
            None
        }
        "/mode" => {
            const MODES: [&str; 5] = ["default", "acceptEdits", "plan", "dontAsk", "bypass"];
            if arg.is_empty() {
                let cur = scenario.permission_mode.as_deref().unwrap_or("default");
                notice(
                    scenario,
                    format!("mode: {cur} · /mode <{}>", MODES.join("|")),
                );
            } else if MODES.contains(&arg) {
                if let Err(message) = submit_foreground(
                    scenario,
                    command_sink,
                    WorkerCommand::SetMode(arg.to_string()),
                ) {
                    *toast = Some(Toast {
                        text: message.into(),
                        ok: false,
                        shown_ms: now_ms,
                    });
                }
            } else {
                notice(
                    scenario,
                    format!("unknown mode {arg} · /mode <{}>", MODES.join("|")),
                );
            }
            None
        }
        "/permissions" => {
            if let Err(message) = submit_foreground(
                scenario,
                command_sink,
                WorkerCommand::Permissions(arg.to_string()),
            ) {
                *toast = Some(Toast {
                    text: message.into(),
                    ok: false,
                    shown_ms: now_ms,
                });
            }
            None
        }
        "/rewind" => {
            if scenario.is_busy() {
                *toast = Some(Toast {
                    text: "wait for this turn to finish first".into(),
                    ok: false,
                    shown_ms: now_ms,
                });
            } else {
                if let Err(message) = submit_foreground(
                    scenario,
                    command_sink,
                    WorkerCommand::Rewind(arg.to_string()),
                ) {
                    *toast = Some(Toast {
                        text: message.into(),
                        ok: false,
                        shown_ms: now_ms,
                    });
                }
            }
            None
        }
        "/undo" => {
            if scenario.is_busy() {
                *toast = Some(Toast {
                    text: "wait for this turn to finish first".into(),
                    ok: false,
                    shown_ms: now_ms,
                });
            } else {
                if let Err(message) = submit_foreground(scenario, command_sink, WorkerCommand::Undo)
                {
                    *toast = Some(Toast {
                        text: message.into(),
                        ok: false,
                        shown_ms: now_ms,
                    });
                }
            }
            None
        }
        "/theme" | "/customize" => {
            *toast = Some(profile_command_toast(tui, scenario, text, now_ms));
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

fn restored_transcript_line(line: crate::model::TranscriptLine) -> TranscriptLine {
    use crate::model::TranscriptLine as Saved;
    match line {
        Saved::User { text, time } => TranscriptLine {
            kind: LineKind::User,
            text: project_restored_transcript_text(&text),
            time: time.map(|time| project_restored_transcript_text(&time)),
            ..Default::default()
        },
        Saved::Assistant { text, time } => TranscriptLine {
            kind: LineKind::Model,
            text: project_restored_transcript_text(&text),
            time: time.map(|time| project_restored_transcript_text(&time)),
            ..Default::default()
        },
        Saved::System(text) => TranscriptLine {
            kind: LineKind::System,
            text: project_restored_transcript_text(&text),
            ..Default::default()
        },
        Saved::Stripped {
            tool_name,
            call_id,
            summary,
            outcome,
            meta,
            ..
        } => {
            let tool_state = match outcome {
                Some(crate::model::ToolOutcome::Ok) => ToolState::Done,
                Some(crate::model::ToolOutcome::Failed) => ToolState::Failed,
                Some(crate::model::ToolOutcome::Denied) => ToolState::Denied,
                Some(crate::model::ToolOutcome::Blocked) => ToolState::Blocked,
                Some(crate::model::ToolOutcome::Cancelled) => ToolState::Cancelled,
                Some(crate::model::ToolOutcome::Unavailable) | None => ToolState::Unavailable,
            };
            TranscriptLine {
                kind: LineKind::Tool,
                tool_name: project_restored_transcript_text(&tool_name),
                text: project_restored_transcript_text(&summary),
                meta: if tool_state == ToolState::Unavailable {
                    String::new()
                } else {
                    project_restored_transcript_text(&meta)
                },
                call_id,
                tool_state,
                ..Default::default()
            }
        }
        Saved::Evidence { checks, note, rows } => TranscriptLine {
            kind: LineKind::System,
            text: project_restored_transcript_text(&format!(
                "{checks} · {note}\n{}",
                rows.into_iter()
                    .map(|(a, b)| format!("{a}: {b}"))
                    .collect::<Vec<_>>()
                    .join("\n")
            )),
            ..Default::default()
        },
        Saved::Sources(rows) => TranscriptLine {
            kind: LineKind::System,
            text: project_restored_transcript_text(
                &rows
                    .into_iter()
                    .map(|(a, b)| format!("{a}: {b}"))
                    .collect::<Vec<_>>()
                    .join("\n"),
            ),
            ..Default::default()
        },
        Saved::Redacted(kind) => TranscriptLine {
            kind: LineKind::System,
            text: format!("[blocked: {kind:?}]"),
            ..Default::default()
        },
    }
}

/// Apply one checked, session-bound view. Rejection has no side effects.
pub fn apply_session_projection(
    projection: crate::msg::SessionProjection,
    scenario: &mut Scenario,
    now_ms: u64,
) -> bool {
    use crate::msg::{ContextProjection, CostQualification, ManualOutcome, ProjectionReason};
    use crate::worker::ManualAction;
    let same = scenario.frontend.binding.as_ref() == Some(&projection.binding);
    let switching = match &projection.reason {
        ProjectionReason::Initial => {
            if scenario.frontend.binding.is_some()
                || scenario.frontend.pending.is_some()
                || (!scenario.session_id.is_empty()
                    && scenario.session_id != projection.binding.session_id)
                || projection.binding.generation != 1
            {
                return false;
            }
            true
        }
        ProjectionReason::Refresh => {
            if !same || scenario.session_id != projection.binding.session_id || scenario.is_busy() {
                return false;
            }
            false
        }
        ProjectionReason::Resume { previous } => {
            if scenario.frontend.binding.as_ref() != Some(previous)
                || scenario.frontend.pending.is_some()
                || scenario.is_busy()
                || previous.session_id == projection.binding.session_id
                || previous.generation.checked_add(1) != Some(projection.binding.generation)
            {
                return false;
            }
            true
        }
        ProjectionReason::Operation { operation } => {
            if scenario.frontend.foreground.as_ref() != Some(operation)
                || scenario.frontend.binding.as_ref() != Some(operation.source())
                || scenario.session_id != operation.source().session_id
                || scenario.frontend.pending.is_some()
            {
                return false;
            }
            if same {
                false
            } else {
                if operation.kind() != crate::worker::ForegroundKind::Resume
                    || projection.binding.session_id == operation.source().session_id
                    || operation.source().generation.checked_add(1)
                        != Some(projection.binding.generation)
                {
                    return false;
                }
                true
            }
        }
        ProjectionReason::Manual {
            operation,
            outcome,
            applied,
        } => {
            if scenario.frontend.pending.as_ref() != Some(operation)
                || scenario.frontend.binding.as_ref() != Some(operation.source())
            {
                return false;
            }
            match operation.action() {
                ManualAction::Compact => {
                    if !same || projection.turns != scenario.turns {
                        return false;
                    }
                    false
                }
                ManualAction::Clear => {
                    if *outcome == ManualOutcome::Completed && *applied {
                        if projection.binding.session_id == operation.source().session_id
                            || operation.source().generation.checked_add(1)
                                != Some(projection.binding.generation)
                        {
                            return false;
                        }
                        true
                    } else {
                        if !same || *applied {
                            return false;
                        }
                        false
                    }
                }
            }
        }
    };
    if projection.binding.session_id.is_empty()
        || projection.binding.session_id.len() > 128
        || !projection
            .binding
            .session_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
    {
        return false;
    }
    if !switching
        && projection.cost.revision().is_some_and(|revision| {
            scenario
                .frontend
                .revision_floor
                .is_some_and(|floor| revision < floor)
        })
    {
        return false;
    }
    let mut lines: Vec<_> = projection
        .lines
        .into_iter()
        .map(restored_transcript_line)
        .collect();
    if projection.context == ContextProjection::PreserveUnchanged
        && (switching
            || !matches!(&projection.reason,
            ProjectionReason::Manual { operation, applied: false, .. }
                if operation.action() == ManualAction::Compact))
    {
        return false;
    }
    // The Operation arm above already checked pointer identity with the active
    // foreground token and its source binding; this only narrows its kind.
    let preserves_measured_context_reason = matches!(&projection.reason, ProjectionReason::Refresh)
        || matches!(
            &projection.reason,
            ProjectionReason::Operation { operation } if operation.kind().is_ordinary()
        );
    if projection.context == ContextProjection::PreserveMeasured
        && (switching
            || !preserves_measured_context_reason
            || scenario.window_tokens == 0
            || scenario.model_id != projection.model
            || scenario.provider != projection.provider)
    {
        return false;
    }
    let cleared_from = match &projection.reason {
        ProjectionReason::Manual {
            operation,
            outcome: ManualOutcome::Completed,
            applied: true,
        } if operation.action() == ManualAction::Clear => {
            Some(operation.source().session_id.clone())
        }
        _ => None,
    };
    if switching {
        // Reuse the established identity-transition reset, once.
        apply_msg(
            crate::msg::Msg::TranscriptLoaded {
                lines: Vec::new(),
                input_tokens: 0,
                output_tokens: 0,
                cost_microcents: 0,
                turns: 0,
            },
            scenario,
            now_ms,
        );
        scenario.compactions.clear();
        scenario.frontend.revision_floor = None;
    }
    if scenario.model_id != projection.model || scenario.provider != projection.provider {
        scenario.dismiss_picker();
    }
    if !switching
        && matches!(&projection.reason, ProjectionReason::Operation { operation }
        if operation.kind().is_ordinary())
    {
        // Queued drafts belong to the local ordinary admission policy and
        // have not entered the worker's typed working history yet.
        lines.extend(
            scenario
                .transcript
                .iter()
                .filter(|line| line.kind == LineKind::Queued)
                .cloned(),
        );
    }
    scenario.model = projection.model.clone();
    scenario.model_id = projection.model;
    scenario.provider = projection.provider;
    scenario.session_prefix = projection
        .binding
        .session_id
        .strip_prefix("session-")
        .unwrap_or(&projection.binding.session_id)
        .chars()
        .take(8)
        .collect();
    scenario.session_id = projection.binding.session_id.clone();
    scenario.priced = projection.priced;
    scenario.frontend.binding = Some(projection.binding);
    scenario.transcript = lines;
    if let Some(source) = cleared_from {
        scenario.cleared_from = Some(source);
    }
    // Restored Bash rows get empty Terminal tapes. Never replay saved tool
    // output into the interactive tape; reuse live admission for tab limits
    // and selection behavior.
    let restored_bash_calls: Vec<String> = scenario
        .transcript
        .iter()
        .filter(|line| {
            line.kind == LineKind::Tool && line.tool_name == "Bash" && !line.call_id.is_empty()
        })
        .map(|line| line.call_id.clone())
        .collect();
    for call_id in restored_bash_calls {
        scenario.start_tape(&call_id);
    }
    scenario.turns = projection.turns;
    scenario.input_tokens = projection.input_tokens;
    scenario.output_tokens = projection.output_tokens;
    scenario.cost_microcents = projection.cost_microcents;
    if let Some(revision) = projection.cost.revision() {
        scenario.frontend.revision_floor = Some(revision);
    }
    let manual = matches!(&projection.reason, ProjectionReason::Manual { .. });
    let foreground = matches!(&projection.reason, ProjectionReason::Operation { .. });
    scenario.frontend.cost = if !manual && !foreground && scenario.is_busy() {
        CostQualification::Unavailable
    } else {
        projection.cost
    };
    if projection.context == ContextProjection::Unavailable {
        scenario.invalidate_context_sample();
    }
    if manual {
        scenario.frontend.pending = None;
        scenario.compacting = false;
        scenario.compacting_from = None;
    }
    if foreground {
        scenario.frontend.foreground = None;
        scenario.turn_live = false;
        scenario.compacting = false;
        scenario.compacting_from = None;
    }
    scenario.frontend.dirty = true;
    true
}

fn apply_msg(msg: crate::msg::Msg, scenario: &mut Scenario, now_ms: u64) -> Option<String> {
    let clean = |text: String| crate::bridge::safe_text(&crate::bridge::terminal_safe(&text));
    use crate::msg::Msg;
    if let Msg::SessionProjection(projection) = msg {
        apply_session_projection(projection, scenario, now_ms);
        return None;
    }
    if let Msg::OrdinaryTurnEnded {
        operation,
        end,
        publication,
    } = msg
    {
        let end = match end {
            crate::msg::OrdinaryEnd::Failed(reason) => {
                crate::msg::OrdinaryEnd::Failed(clean(reason))
            }
            other => other,
        };
        if scenario.accept_ordinary_end(&operation, end, publication) {
            scenario.motion_until_ms = now_ms + 1000;
        }
        return None;
    }
    // Every message may start a motion: keep redrawing for a second.
    scenario.motion_until_ms = now_ms + 1000;
    match msg {
        Msg::Routing(lines) => {
            scenario.routing_lines = lines
                .into_iter()
                .take(32)
                .map(|line| {
                    let clean = crate::bridge::safe_text(&crate::bridge::terminal_safe(&line));
                    let mut end = 0;
                    for (start, grapheme) in clean.grapheme_indices(true) {
                        let grapheme_end = start + grapheme.len();
                        if grapheme_end > 256 {
                            break;
                        }
                        end = grapheme_end;
                    }
                    clean[..end].to_string()
                })
                .collect();
        }
        Msg::TranscriptLoaded {
            lines,
            input_tokens,
            output_tokens,
            cost_microcents,
            turns,
        } => {
            scenario.dismiss_picker();
            scenario.invalidate_cost_qualification();
            scenario.invalidate_context_sample();
            scenario.frontend.dirty = true;
            scenario.routing_lines.clear();
            scenario.clear_namespace_view();
            scenario.transcript = lines.into_iter().map(restored_transcript_line).collect();
            scenario.input_tokens = input_tokens;
            scenario.output_tokens = output_tokens;
            scenario.cost_microcents = cost_microcents;
            scenario.turns = turns;
            scenario.turn_live = false;
            scenario.visible_output = false;
            scenario.last_failed = false;
            scenario.failure_reason = None;
            scenario.cleared_from = None;
            scenario.first_prompt_waiting = false;
            scenario.compacting = false;
            scenario.running.clear();
            scenario.approval_pending = None;
            scenario.approval_call_id = None;
            scenario.approval_queue.clear();
            scenario.approval_summary = None;
            scenario.approval_grant = None;
            scenario.approval_note = None;
            scenario.agents.clear();
            scenario.agents_running = 0;
            scenario.tasks.clear();
            scenario.file_changes.clear();
            scenario.tapes.clear();
            scenario.tape_sel = None;
            scenario.activity.clear();
            scenario.turn_report = None;
            scenario.turn_tools = 0;
            scenario.backoff_until_ms = None;
            for pane in scenario.custom_panes.values_mut() {
                pane.state = orbit_frontend_protocol::customization::PaneState::Stale;
                pane.text = "Session changed; refresh this pane".into();
            }
        }
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
                        crate::model::ToolOutcome::Unavailable => {
                            l.tool_state = super::scenario::ToolState::Unavailable;
                            l.meta = String::new();
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
            let managed = scenario.session_binding().is_some();
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
            scenario.compacting = false;
            scenario.compacting_from = None;
            // Managed workers publish whole checked totals immediately after
            // this lifecycle event. Legacy bridges still send per-turn deltas.
            if !managed {
                let totals = scenario
                    .turns
                    .checked_add(1)
                    .zip(scenario.input_tokens.checked_add(input_tokens))
                    .zip(scenario.output_tokens.checked_add(output_tokens))
                    .zip(scenario.cost_microcents.checked_add(cost_microcents));
                if let Some((((turns, input), output), cost)) = totals {
                    scenario.turns = turns;
                    scenario.input_tokens = input;
                    scenario.output_tokens = output;
                    scenario.cost_microcents = cost;
                } else {
                    scenario.invalidate_cost_qualification();
                }
            }
            scenario.turn_report = Some(TurnReport {
                duration_ms: now_ms.saturating_sub(scenario.turn_started_ms),
                tools: scenario.turn_tools,
                // Managed completion counters describe the whole session. The
                // report keeps its lifecycle facts and omits a monetary claim.
                cost_microcents: if managed { 0 } else { cost_microcents },
                priced: !managed && scenario.priced,
            });
            scenario.turn_ended_ms = Some(now_ms);
            scenario.apply("turn_ended", 0);
        }
        Msg::EffortStatus(text) => {
            scenario.transcript.push(TranscriptLine {
                kind: LineKind::System,
                text,
                wrap: true,
                ..Default::default()
            });
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
        Msg::ModelsListed(rows) => {
            if rows.is_empty() {
                scenario.transcript.push(TranscriptLine {
                    kind: LineKind::System,
                    text: "(no providers configured)".to_string(),
                    ..Default::default()
                });
            } else {
                scenario.open_picker(Picker {
                    kind: PickerKind::Models,
                    rows: rows
                        .into_iter()
                        .map(|(p, m)| PickerRow {
                            label: clean(format!("{p}/{m}")),
                            value: format!("{p}/{m}"),
                            detail: clean(format!("provider {p}")),
                        })
                        .collect(),
                    sel: 0,
                });
            }
        }
        Msg::SessionsListed(rows) => {
            if rows.is_empty() {
                scenario.transcript.push(TranscriptLine {
                    kind: LineKind::System,
                    text: "(no saved sessions)".to_string(),
                    ..Default::default()
                });
            } else {
                scenario.open_picker(Picker {
                    kind: PickerKind::Sessions,
                    rows: rows
                        .into_iter()
                        .map(|r| PickerRow {
                            label: clean(if r.current {
                                format!("{}  (this session)", r.id)
                            } else {
                                r.id.clone()
                            }),
                            value: r.id,
                            detail: clean(if r.current {
                                format!("{} turns · {}", r.turns, r.model)
                            } else {
                                format!(
                                    "{} turns · {} · updated {}",
                                    r.turns, r.model, r.updated_at
                                )
                            }),
                        })
                        .collect(),
                    sel: 0,
                });
            }
        }
        Msg::ModelsListFailed(error) | Msg::SessionsListFailed(error) => {
            scenario.transcript.push(TranscriptLine {
                kind: LineKind::System,
                text: clean(error),
                ..Default::default()
            });
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
        Msg::SubagentStarted {
            id,
            name,
            task,
            model,
        } => {
            scenario.agents.insert(
                id.clone(),
                super::scenario::Agent {
                    name,
                    model,
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
            scenario.dismiss_picker();
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
            scenario.dismiss_picker();
            scenario.invalidate_cost_qualification();
            scenario.invalidate_context_sample();
            if scenario.session_id != session_id {
                scenario.clear_namespace_view();
                scenario.frontend.binding = None;
                scenario.failure_reason = None;
                scenario.cleared_from = None;
                scenario.last_failed = false;
                scenario.turn_report = None;
                scenario.first_prompt_waiting = false;
            }
            scenario.frontend.dirty = true;
            scenario.model = model.clone();
            scenario.model_id = model;
            scenario.provider = provider;
            scenario.session_prefix = session_prefix;
            scenario.session_id = session_id;
            scenario.priced = priced;
        }
        Msg::BackendNotice(text) => scenario.set_backend_notice(clean(text)),
        // Callback errors can explain a failure, but never mint eligibility
        // or turn an already typed completion/cancellation into failure.
        Msg::BackendError(err)
            if !matches!(
                scenario.ordinary_end(),
                Some(crate::msg::OrdinaryEnd::Completed | crate::msg::OrdinaryEnd::Cancelled)
            ) =>
        {
            scenario.failure_reason = Some(clean(err));
            scenario.apply("turn_failed", 0);
            scenario.frontend.dirty = true;
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
    // The size notice (§9.23): below 40 × 11 it is the whole screen.
    if area.width < 40 || area.height < 11 {
        let lines = super::chrome::size_notice_lines_themed(
            super::shell::pal::Palette::from_profile(&tui.profile),
            area.width,
            area.height,
        );
        let star = Line::from(Span::styled(
            "✦",
            Style::default().fg(comps::colour_themed(
                super::shell::pal::Palette::from_profile(&tui.profile),
                Token::Magenta,
            )),
        ));
        let mut out = vec![star];
        out.extend(lines);
        f.render_widget(Paragraph::new(out), area);
        super::shell::tier::apply(
            f.buffer_mut(),
            super::shell::effective_tier(tui.tier, tui.profile.color_mode, false),
        );
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
        Some(Overlay::ModelPicker) | Some(Overlay::SessionPicker) => {
            // The rows the reducer loaded; no rows, no overlay.
            scenario.picker.as_ref().map(|p| Ov::Picker {
                title: match p.kind {
                    PickerKind::Models => "MODELS",
                    PickerKind::Sessions => "SESSIONS",
                },
                rows: &p.rows,
                sel: p.sel,
                opened_ms: tui.fx.overlay_ms,
            })
        }
        None => None,
    };
    super::shell::draw_with_profile(
        f,
        &super::shell::DrawIn {
            app: &tui.app,
            fx: &tui.fx,
            scenario,
            composer,
            composer_cursor: tui.composer_cursor,
            completion_sel: tui.completion_sel,
            file_completion: Some(&tui.file_completion),
            history_search: tui.history_search.as_ref(),
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
            toast: toast
                .map(|t| super::shell::ToastIn {
                    text: t.text.as_str(),
                    ok: t.ok,
                    shown_ms: t.shown_ms,
                })
                .or_else(|| {
                    tui.app
                        .layout_error
                        .as_ref()
                        .map(|text| super::shell::ToastIn {
                            text,
                            ok: false,
                            shown_ms: tui.tick_ms,
                        })
                }),
            overlay: ov,
        },
        &tui.profile,
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
    CustomAction {
        panel: usize,
        action: usize,
    },
    None,
    /// Text was copied: say so.
    Toast(String),
    /// A clicked hint: press its key through the key handler.
    Key(crossterm::event::KeyEvent),
    /// A click on row `i` of the changed-files list.
    File(usize),
    /// A click on row `i` of the `/` command list.
    Slash(usize),
    /// A click on row `i` of the file completion picker.
    Completion(usize),
    /// A click on row `i` of the command palette.
    Palette(usize),
    /// A click on the actual row of the model/session picker.
    Picker(usize),
    /// A click on the tab of the Terminal's tape `i`.
    Tape(usize),
}

#[derive(Debug, Clone)]
struct PaletteFrame {
    binding: Option<crate::worker::SessionBinding>,
    query: String,
    rows: Vec<(usize, &'static str)>,
}

#[derive(Debug, Clone)]
struct PaletteClick {
    binding: Option<crate::worker::SessionBinding>,
    query: String,
    command: &'static str,
}

fn capture_palette_frame(
    scenario: &Scenario,
    overlay: Option<Overlay>,
    query: &str,
    hits: &[super::shell::hits::Hit],
) -> Option<PaletteFrame> {
    if overlay != Some(Overlay::Palette) {
        return None;
    }
    let items = super::shell::overlays::palette_items(query);
    let rows = hits
        .iter()
        .filter_map(|hit| match hit.click {
            super::shell::hits::Click::Palette(index) => {
                items.get(index).map(|(command, _)| (index, *command))
            }
            _ => None,
        })
        .collect();
    Some(PaletteFrame {
        binding: scenario.session_binding().cloned(),
        query: query.into(),
        rows,
    })
}

fn capture_palette_click(
    scenario: &Scenario,
    overlay: Option<Overlay>,
    query: &str,
    frame: Option<&PaletteFrame>,
    index: usize,
) -> Option<PaletteClick> {
    let frame = frame?;
    if overlay != Some(Overlay::Palette)
        || frame.query != query
        || scenario.session_binding() != frame.binding.as_ref()
        || scenario.approval_call_id.is_some()
    {
        return None;
    }
    let command = frame.rows.iter().find(|(row, _)| *row == index)?.1;
    Some(PaletteClick {
        binding: frame.binding.clone(),
        query: frame.query.clone(),
        command,
    })
}

fn palette_click_key(
    click: PaletteClick,
    scenario: &Scenario,
    overlay: Option<Overlay>,
    query: &str,
    selection: &mut usize,
) -> Option<crossterm::event::KeyEvent> {
    if overlay != Some(Overlay::Palette)
        || click.query != query
        || scenario.session_binding() != click.binding.as_ref()
        || scenario.approval_call_id.is_some()
    {
        return None;
    }
    *selection = super::shell::overlays::palette_items(query)
        .iter()
        .position(|(command, _)| *command == click.command)?;
    Some(crossterm::event::KeyEvent::new(
        KeyCode::Enter,
        KeyModifiers::NONE,
    ))
}

#[derive(Debug, Clone)]
struct PickerClick {
    binding: Option<crate::worker::SessionBinding>,
    kind: PickerKind,
    index: usize,
}

fn capture_picker_click(
    scenario: &Scenario,
    overlay: Option<Overlay>,
    index: usize,
) -> Option<PickerClick> {
    let kind = match overlay {
        Some(Overlay::ModelPicker) => PickerKind::Models,
        Some(Overlay::SessionPicker) => PickerKind::Sessions,
        _ => return None,
    };
    let picker = scenario.picker.as_ref()?;
    if picker.kind != kind || index >= picker.rows.len() || scenario.approval_call_id.is_some() {
        return None;
    }
    Some(PickerClick {
        binding: scenario.session_binding().cloned(),
        kind,
        index,
    })
}

fn picker_click_key(
    click: PickerClick,
    scenario: &mut Scenario,
    overlay: Option<Overlay>,
    now_ms: u64,
) -> Option<crossterm::event::KeyEvent> {
    // A bus update can close the picker between the click and the next
    // input iteration. Never let that deferred Enter reach the composer.
    if scenario.session_binding() != click.binding.as_ref()
        || card_just_appeared(scenario, now_ms)
        || capture_picker_click(scenario, overlay, click.index)?.kind != click.kind
    {
        return None;
    }
    scenario.picker.as_mut()?.sel = click.index;
    Some(crossterm::event::KeyEvent::new(
        KeyCode::Enter,
        KeyModifiers::NONE,
    ))
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
                    Some(Click::Picker(i)) => MouseOutcome::Picker(i),
                    _ => MouseOutcome::None,
                };
            }
            // A control belongs to the panel it is drawn in: the key it
            // presses, or the row it picks, must reach THAT panel, not
            // whichever one happened to have focus.
            let focus_under = |tui: &mut Tui| {
                if let Some((i, _, _)) = under
                    && *i != tui.app.focus
                {
                    tui.app.focus = *i;
                    tui.sync_focus();
                }
            };
            match click {
                Some(Click::CustomAction { panel, action }) => {
                    focus_under(tui);
                    return MouseOutcome::CustomAction { panel, action };
                }
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
                Some(Click::Completion(i)) => {
                    focus_under(tui);
                    return MouseOutcome::Completion(i);
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
                        if let Some(session) = tui.customization.as_mut() {
                            tui.app.tree = super::layout::Node::profile_preset(*p);
                            crate::customization::focus_conversation(&mut tui.app);
                            if let Err(error) = session.persist_tree(&tui.app.tree) {
                                tui.app.layout_error = Some(error.to_string());
                            }
                        } else {
                            let _ = tui.app.save_yours();
                        }
                        tui.sync_focus();
                    }
                    return MouseOutcome::None;
                }
                // Modal-only regions: nothing is open, nothing to do.
                Some(Click::Dismiss | Click::Inert | Click::Palette(_) | Click::Picker(_)) => {
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
            // OSC 52 covers remote sessions; a local X display needs the
            // helper, or the terminal silently drops the sequence.
            crate::selection::set_x_clipboard(&text);
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
/// this session, `a` saves the offered rule, `n` a denial with a note,
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
                let mut cursor = super::composer::grapheme_count(note);
                super::composer::delete_before_cursor(note, &mut cursor);
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
        Some(Overlay::ModelPicker) => 5,
        Some(Overlay::SessionPicker) => 6,
    }
}

const HISTORY_FILE_SCHEMA: &str = "orbit.composer-history/v1";

fn composer_history_path(
    home: &std::path::Path,
    identity: &crate::model::StartupIdentity,
) -> Option<std::path::PathBuf> {
    (!identity.session_id.is_empty()).then(|| {
        home.join("sessions")
            .join(format!("{}.history", identity.session_id))
    })
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ComposerHistoryFile {
    schema: String,
    entries: Vec<String>,
}

/// Accept legacy line-based history while keeping new multiline entries exact.
/// A version tag distinguishes saved entries from a literal JSON-array prompt.
fn read_history(raw: &str) -> Vec<String> {
    let entries = serde_json::from_str::<ComposerHistoryFile>(raw)
        .ok()
        .filter(|file| file.schema == HISTORY_FILE_SCHEMA)
        .map(|file| file.entries)
        .unwrap_or_else(|| raw.lines().map(str::to_string).collect());
    entries
        .into_iter()
        .filter(|entry| !entry.trim().is_empty())
        .take(HISTORY_MAX)
        .collect()
}

/// Persist the composer history (§11.3): newest first, bounded at
/// [`HISTORY_MAX`], one versioned JSON file per session. Best-effort by design
/// — losing the history is a comfort, not a correctness, failure.
fn save_history(path: &Option<std::path::PathBuf>, history: &[String]) {
    let Some(p) = path else { return };
    if history.is_empty() {
        return;
    }
    let file = ComposerHistoryFile {
        schema: HISTORY_FILE_SCHEMA.into(),
        entries: history[..history.len().min(HISTORY_MAX)].to_vec(),
    };
    let Ok(raw) = serde_json::to_string(&file) else {
        return;
    };
    // Security posture (matches the ledger writer, DR-06 §1.2): dir 0700,
    // file 0600. The history can carry pasted credentials and engagement
    // text, so it must not leak to local users via the default umask
    // (0o022 would leave it group/world readable). Permission failures are
    // swallowed like the write itself — history persistence is best-effort,
    // never a reason to wedge a turn.
    if let Some(dir) = p.parent() {
        let _ = std::fs::create_dir_all(dir);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
        }
    }
    let _ = std::fs::write(p, raw);
    // set_permissions AFTER the write: `.mode()` at open only applies to
    // newly created files, but save_history may append to a file created by
    // an older build (or a permissive umask) — force 0600 every save so an
    // existing file is corrected, not just a fresh one.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o600));
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
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
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
    fn mouse_up_of_a_real_drag_copies_the_selected_text() {
        // The runtime's mouse-up path (OSC 52 + X clipboard fallback) rides
        // on a selection started by Down inside the content rect and
        // extended by Drag. Drive Down/Drag/Up over the user line of a
        // rendered frame and expect the copy toast.
        let (w, h) = (100, 30);
        let mut tui = fresh_tui();
        let mut s = Scenario::new();
        s.transcript.push(TranscriptLine {
            kind: LineKind::User,
            text: "make the tests pass".into(),
            time: Some("16:46".into()),
            ..Default::default()
        });
        // Draw once so tui.hits is populated, then keep the buffer.
        tui.reduced = true;
        tui.tick_ms = tui.tick_ms.max(5_000);
        let mut term = ratatui::Terminal::new(ratatui::backend::TestBackend::new(w, h)).unwrap();
        let mut hits = Vec::new();
        let done = term
            .draw(|f| {
                hits = draw_with_hits(f, &tui, &s, "", None, "", 0, None, false, 0);
            })
            .unwrap();
        tui.hits = hits;
        let buf = done.buffer.clone();
        let area = Rect::new(0, 0, w, h);
        // Where the user line sits.
        let rows: Vec<String> = (0..h)
            .map(|y| (0..w).map(|x| buf[(x, y)].symbol().to_string()).collect())
            .collect();
        let (col, row) = at(&rows, "make the tests");
        let mk = |kind: crossterm::event::MouseEventKind, c: u16| crossterm::event::MouseEvent {
            kind,
            column: c,
            row,
            modifiers: KeyModifiers::NONE,
        };
        use crossterm::event::{MouseButton, MouseEventKind};
        // Down on the first word starts the selection.
        assert_eq!(
            handle_mouse(
                mk(MouseEventKind::Down(MouseButton::Left), col),
                &mut tui,
                area,
                None,
                false
            ),
            MouseOutcome::None
        );
        assert!(tui.selection.is_some(), "Down over the user line selects");
        // Drag across the line.
        assert_eq!(
            handle_mouse(
                mk(MouseEventKind::Drag(MouseButton::Left), col + 8),
                &mut tui,
                area,
                None,
                false
            ),
            MouseOutcome::None
        );
        // Up copies: the toast carries the character count.
        let out = handle_mouse(
            mk(MouseEventKind::Up(MouseButton::Left), col + 8),
            &mut tui,
            area,
            Some(&buf),
            false,
        );
        assert!(
            matches!(out, MouseOutcome::Toast(ref t) if t.starts_with("copied ")),
            "mouse-up must copy the drag, got {out:?}"
        );
    }

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

    #[test]
    fn approval_note_backspace_removes_one_unicode_grapheme() {
        let (mut scenario, registry, response) = parked(true, true);
        press(&mut scenario, &registry, KeyCode::Char('n'), 10_000);
        for ch in "reason 🧑🏽‍💻".chars() {
            press(&mut scenario, &registry, KeyCode::Char(ch), 10_100);
        }
        press(&mut scenario, &registry, KeyCode::Backspace, 10_200);
        assert_eq!(scenario.approval_note.as_deref(), Some("reason "));
        press(&mut scenario, &registry, KeyCode::Enter, 10_300);
        assert_eq!(
            response.try_recv().ok(),
            Some(crate::ApprovalResponse::Deny)
        );
        assert_eq!(registry.take_note("c1").as_deref(), Some("reason"));
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
            assert!(
                !text.contains("whole tool"),
                "unsupported whole-tool grant: {text}"
            );
            for line in [
                "allow once",
                "this kind of call, session",
                "same, saved in this folder",
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
                model: "test-explore-model".into(),
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
        assert_eq!(a.name, "Explore");
        assert_eq!(a.model, "test-explore-model");
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

    #[test]
    fn a_resumed_subagent_replaces_its_model_and_stale_run_state() {
        let mut s = Scenario::new();
        start(&mut s, 1_000);
        apply_msg(
            Msg::SubagentProgress {
                id: "a1".into(),
                action: "Read calc.py".into(),
            },
            &mut s,
            2_000,
        );
        apply_msg(
            Msg::SubagentFinished {
                id: "a1".into(),
                report: "stopped".into(),
                ok: false,
            },
            &mut s,
            3_000,
        );
        apply_msg(
            Msg::SubagentStarted {
                id: "a1".into(),
                name: "Explore".into(),
                task: "check callers of add()".into(),
                model: "test-resumed-model".into(),
            },
            &mut s,
            4_000,
        );

        let a = &s.agents["a1"];
        assert_eq!(s.agents.len(), 1, "the same agent is resumed");
        assert_eq!(s.agents_running, 1);
        assert_eq!(a.name, "Explore");
        assert_eq!(a.model, "test-resumed-model");
        assert_eq!(a.task, "check callers of add()");
        assert!(a.action.is_empty() && a.report.is_empty());
        assert!(!a.done && a.ok);
        assert_eq!(a.started_ms, 4_000);
        assert_eq!(a.done_ms, None);

        apply_msg(
            Msg::SubagentProgress {
                id: "a1".into(),
                action: "Read caller.py".into(),
            },
            &mut s,
            5_000,
        );
        let a = &s.agents["a1"];
        assert_eq!(a.action, "Read caller.py");
        assert_eq!(a.model, "test-resumed-model");
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

#[cfg(test)]
mod activity_panel_tests {
    use super::*;
    use crate::msg::Msg;

    /// The Activity panel is the ledger's face: a row the session
    /// appended renders with its kind, target, fact and short hash —
    /// not just the running tool cards.
    #[test]
    fn ledger_rows_render_in_the_activity_panel() {
        let mut s = Scenario::new();
        apply_msg(
            Msg::Activity {
                kind: "intent".into(),
                target: "Read(a-fan.txt)".into(),
                fact: "requested".into(),
                digest: Some("a1b2c3d4e5f6a7b8c9d0".repeat(4)),
            },
            &mut s,
            1,
        );
        apply_msg(
            Msg::Activity {
                kind: "verdict".into(),
                target: "Read(a-fan.txt)".into(),
                fact: "allowed — read-only".into(),
                digest: Some("f1e2d3c4b5a697886970".repeat(4)),
            },
            &mut s,
            2,
        );
        let lines = crate::proto::panels::activity(&s, 5_000, true);
        let text: Vec<String> = lines
            .iter()
            .map(|l| {
                l.spans
                    .iter()
                    .map(|s| s.content.to_string())
                    .collect::<String>()
            })
            .collect();
        let joined = text.join("\n");
        assert!(joined.contains("Activity"), "the panel header: {joined}");
        assert!(
            joined.contains("intent") && joined.contains("Read(a-fan.txt)"),
            "the intent row with its target: {joined}"
        );
        assert!(
            joined.contains("allowed — read-only"),
            "the verdict's fact: {joined}"
        );
        assert!(
            joined.contains("a1b2c3d4"),
            "the record's short hash: {joined}"
        );
    }

    /// A denial is the one row that carries the amber: the operator
    /// must be able to spot refusals in the tail at a glance.
    #[test]
    fn a_denied_verdict_row_carries_the_amber() {
        let mut s = Scenario::new();
        apply_msg(
            Msg::Activity {
                kind: "verdict".into(),
                target: "Bash(rm -rf ~)".into(),
                fact: "denied by rule".into(),
                digest: Some("0".repeat(64)),
            },
            &mut s,
            1,
        );
        let lines = crate::proto::panels::activity(&s, 5_000, true);
        // Find the verdict row and check its kind span is amber.
        let row = lines
            .iter()
            .find(|l| l.spans.iter().any(|s| s.content.contains("verdict")))
            .expect("the verdict row renders");
        let amber = row.spans.iter().any(|s| {
            s.style.fg == Some(comps::colour(crate::proto::core::Token::Amber))
                || s.style.fg == Some(ratatui::style::Color::Rgb(0xF5, 0x9E, 0x0B))
        });
        assert!(amber, "the denied verdict is amber, not plain cyan");
    }

    /// Idle with no records says idle; a running card still renders
    /// above the ledger rows.
    #[test]
    fn running_cards_render_above_the_ledger_rows() {
        let mut s = Scenario::new();
        s.running.insert("call-1".into(), "Read".into());
        apply_msg(
            Msg::Activity {
                kind: "result".into(),
                target: "Read(a.txt)".into(),
                fact: "ok".into(),
                digest: None,
            },
            &mut s,
            1,
        );
        let lines = crate::proto::panels::activity(&s, 5_000, true);
        let text: Vec<String> = lines
            .iter()
            .map(|l| {
                l.spans
                    .iter()
                    .map(|s| s.content.to_string())
                    .collect::<String>()
            })
            .collect();
        let read_idx = text
            .iter()
            .position(|t| t.contains("call-1"))
            .expect("the running card renders");
        let result_idx = text
            .iter()
            .position(|t| t.contains("result"))
            .expect("the ledger row renders");
        assert!(read_idx < result_idx, "cards above, records below");
    }
}

#[cfg(test)]
mod composer_key_tests {
    use super::*;
    use crossterm::event::KeyEvent;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct Keyboard {
        tui: Tui,
        scenario: Scenario,
        draft: String,
        history: Vec<String>,
        history_idx: Option<usize>,
        overlay: Option<Overlay>,
        tx: CommandSink,
        rx: std::sync::mpsc::Receiver<WorkerCommand>,
        approvals: ApprovalRegistry,
        cancel_count: std::sync::Arc<AtomicUsize>,
        root: std::path::PathBuf,
    }

    impl Keyboard {
        fn new() -> Self {
            static SEQ: AtomicUsize = AtomicUsize::new(0);
            let root = std::env::temp_dir().join(format!(
                "orbit-keys-{}-{}",
                std::process::id(),
                SEQ.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir_all(&root).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
            }
            let (tx, rx) = std::sync::mpsc::channel();
            let mut tui = Tui::new();
            tui.app = super::super::app::App::new(root.clone(), true);
            tui.file_completion = super::super::composer::FileCompletion::new(root.clone());
            let mut scenario = Scenario::new();
            assert!(apply_session_projection(
                crate::msg::SessionProjection {
                    binding: crate::worker::SessionBinding {
                        session_id: "session-keyboard-fixture".into(),
                        generation: 1
                    },
                    model: "fixture-model".into(),
                    provider: "fixture-provider".into(),
                    priced: false,
                    lines: Vec::new(),
                    turns: 0,
                    input_tokens: 0,
                    output_tokens: 0,
                    cost_microcents: 0,
                    cost: crate::msg::CostQualification::Known { revision: 0 },
                    context: crate::msg::ContextProjection::Unavailable,
                    reason: crate::msg::ProjectionReason::Initial,
                },
                &mut scenario,
                0
            ));
            scenario.take_view_dirty();
            Self {
                tui,
                scenario,
                draft: String::new(),
                history: Vec::new(),
                history_idx: None,
                overlay: None,
                tx,
                rx,
                approvals: ApprovalRegistry::new(),
                cancel_count: std::sync::Arc::new(AtomicUsize::new(0)),
                root,
            }
        }

        fn key(&mut self, code: KeyCode, modifiers: KeyModifiers) {
            let (_, sender) = Bus::new();
            let count = self.cancel_count.clone();
            let cancel: crate::worker::CancelHandle = std::sync::Arc::new(move || {
                count.fetch_add(1, Ordering::SeqCst);
            });
            assert!(!handle_key(
                KeyEvent::new(code, modifiers),
                &mut self.tui,
                &mut self.scenario,
                &mut self.draft,
                Some(&cancel),
                &self.tx,
                &sender,
                &self.approvals,
                10_000,
                &mut self.overlay,
                &mut String::new(),
                &mut 0,
                &mut 0,
                &mut None,
                &mut Vec::new(),
                &mut self.history,
                &mut self.history_idx,
                &mut None,
                &mut false,
                &mut false,
            ));
        }

        fn plain(&mut self, code: KeyCode) {
            self.key(code, KeyModifiers::NONE);
        }
        fn reverse(&mut self) {
            self.key(KeyCode::Char('r'), KeyModifiers::CONTROL);
        }
        fn type_text(&mut self, text: &str) {
            for c in text.chars() {
                self.plain(KeyCode::Char(c));
            }
        }
        fn no_send(&self) {
            assert!(self.rx.try_recv().is_err());
        }

        fn list(&mut self, kind: PickerKind) {
            self.type_text(match kind {
                PickerKind::Models => "/models",
                PickerKind::Sessions => "/sessions",
            });
            self.plain(KeyCode::Enter);
            assert!(matches!(
                (kind, self.rx.try_recv().unwrap()),
                (PickerKind::Models, WorkerCommand::ListModels)
                    | (PickerKind::Sessions, WorkerCommand::ListSessions)
            ));
        }

        fn receive(&mut self, msg: crate::msg::Msg) {
            let (bus, sender) = Bus::new();
            sender.send(msg);
            while let Some(msg) = bus.try_recv() {
                reduce_runtime_message(
                    msg,
                    &mut self.tui,
                    &mut self.scenario,
                    &mut self.overlay,
                    5_000,
                );
            }
        }

        fn received_command(&self) -> WorkerCommand {
            let WorkerCommand::Bound { operation, command } = self.rx.try_recv().unwrap() else {
                panic!("managed keyboard admission must be bound");
            };
            assert_eq!(self.scenario.pending_foreground(), Some(&operation));
            assert_eq!(self.scenario.session_binding(), Some(operation.source()));
            assert_eq!(command.foreground_kind(), Some(operation.kind()));
            *command
        }

        fn frame(&mut self, width: u16, height: u16) -> String {
            self.tui.reduced = true;
            self.tui.tick_ms = 5_000;
            let mut terminal =
                ratatui::Terminal::new(ratatui::backend::TestBackend::new(width, height)).unwrap();
            let frame = terminal
                .draw(|f| {
                    self.tui.hits = draw_with_hits(
                        f,
                        &self.tui,
                        &self.scenario,
                        &self.draft,
                        self.overlay,
                        "",
                        0,
                        None,
                        false,
                        0,
                    );
                })
                .unwrap();
            (0..height)
                .map(|y| {
                    (0..width)
                        .map(|x| frame.buffer[(x, y)].symbol())
                        .collect::<String>()
                })
                .collect::<Vec<_>>()
                .join("\n")
        }
    }

    impl Drop for Keyboard {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    fn listed_models(count: usize) -> crate::msg::Msg {
        crate::msg::Msg::ModelsListed(
            (0..count)
                .map(|i| ("fixture".into(), format!("m{i}")))
                .collect(),
        )
    }

    fn requested_approval() -> crate::msg::Msg {
        crate::msg::Msg::ApprovalRequested {
            call_id: "picker-approval".into(),
            tool_name: "Read".into(),
            summary: "read fixture".into(),
            risk: 0,
            working_dir: ".".into(),
        }
    }

    #[test]
    fn history_query_backspace_and_escape_keep_graphemes_and_cursor() {
        let mut k = Keyboard::new();
        k.draft = "a🇧🇷b".into();
        k.tui.composer_cursor = 2;
        k.reverse();
        assert_eq!(k.tui.composer_cursor, 2);
        k.type_text("🧑🏽‍💻");
        assert_eq!(k.tui.history_search.as_ref().unwrap().query, "🧑🏽‍💻");
        k.plain(KeyCode::Backspace);
        assert_eq!(k.tui.history_search.as_ref().unwrap().query, "");
        k.plain(KeyCode::Esc);
        assert_eq!(k.draft, "a🇧🇷b");
        assert_eq!(k.tui.composer_cursor, 2);
    }

    #[test]
    fn composer_edits_move_and_delete_complete_graphemes() {
        let mut k = Keyboard::new();
        k.type_text("a🇧🇷b");
        assert_eq!(k.tui.composer_cursor, 3);
        k.plain(KeyCode::Left);
        k.type_text("猫");
        assert_eq!(k.draft, "a🇧🇷猫b");
        assert_eq!(k.tui.composer_cursor, 3);
        k.plain(KeyCode::Backspace);
        assert_eq!(k.draft, "a🇧🇷b");
        assert_eq!(k.tui.composer_cursor, 2);
        k.plain(KeyCode::Backspace);
        assert_eq!(k.draft, "ab");
        assert_eq!(k.tui.composer_cursor, 1);

        k.key(KeyCode::Char('x'), KeyModifiers::CONTROL);
        k.key(KeyCode::Char('y'), KeyModifiers::ALT);
        assert_eq!(
            k.draft, "ab",
            "unsupported chords must not type into the draft"
        );
        k.plain(KeyCode::Home);
        k.plain(KeyCode::Delete);
        assert_eq!(k.draft, "b");
        assert_eq!(k.tui.composer_cursor, 0);
        k.plain(KeyCode::End);
        assert_eq!(k.tui.composer_cursor, 1);
    }

    #[test]
    fn paste_is_literal_at_the_caret_and_submission_keeps_edge_whitespace() {
        let mut k = Keyboard::new();
        k.type_text("leftright");
        for _ in 0..5 {
            k.plain(KeyCode::Left);
        }
        assert!(handle_paste(
            " \n日本語\n ",
            &mut k.tui,
            &mut k.scenario,
            &mut k.draft,
            &k.history,
            &mut k.history_idx,
            false,
        ));
        assert_eq!(k.draft, "left \n日本語\n right");
        k.plain(KeyCode::Enter);
        assert!(matches!(
            k.received_command(),
            WorkerCommand::Prompt(text) if text == "left \n日本語\n right"
        ));

        let mut blank = Keyboard::new();
        blank.type_text("   ");
        blank.plain(KeyCode::Enter);
        assert_eq!(blank.draft, "   ");
        blank.no_send();
    }

    #[test]
    fn model_list_bus_opens_visible_picker_and_keyboard_selects_beyond_first_page() {
        let mut k = Keyboard::new();
        k.list(PickerKind::Models);
        k.receive(listed_models(30));
        assert_eq!(k.overlay, Some(Overlay::ModelPicker));
        assert!(
            k.scenario.take_view_dirty(),
            "bus activation requests a settled redraw"
        );
        for _ in 0..17 {
            k.plain(KeyCode::Down);
        }
        for (width, height) in [(100, 24), (40, 11)] {
            let frame = k.frame(width, height);
            assert!(
                frame.contains("fixture/m17"),
                "selection stays visible at {width}x{height}"
            );
            assert!(
                k.tui
                    .hits
                    .iter()
                    .any(|hit| hit.click == super::super::shell::hits::Click::Picker(17))
            );
            assert!(
                k.tui
                    .hits
                    .iter()
                    .all(|hit| hit.rect.right() <= width && hit.rect.bottom() <= height)
            );
        }
        k.no_send();
        k.plain(KeyCode::Enter);
        assert!(
            matches!(k.received_command(), WorkerCommand::SetModel(value) if value == "fixture/m17")
        );
        assert!(k.overlay.is_none());
        assert!(k.scenario.picker.is_none());
    }

    #[test]
    fn session_picker_current_row_is_noop_and_mouse_resumes_the_actual_row() {
        use crossterm::event::{MouseButton, MouseEvent, MouseEventKind};
        let mut k = Keyboard::new();
        let current = "session-01JAB12CD34EF56GH78JK90MNP".to_string();
        k.scenario.session_id = current.clone();
        k.scenario
            .frontend
            .binding
            .as_mut()
            .expect("keyboard fixture starts with a committed session")
            .session_id = current.clone();
        let rows = vec![
            crate::msg::SessionsRow {
                id: current.clone(),
                model: "m0".into(),
                turns: 12,
                updated_at: "today".into(),
                current: true,
            },
            crate::msg::SessionsRow {
                id: "session-other-fixture".into(),
                model: "m1".into(),
                turns: 4,
                updated_at: "yesterday".into(),
                current: false,
            },
        ];
        k.list(PickerKind::Sessions);
        k.receive(crate::msg::Msg::SessionsListed(rows.clone()));
        let frame = k.frame(80, 24);
        let lines: Vec<_> = frame.lines().collect();
        let current_rows = lines
            .windows(2)
            .filter(|pair| {
                pair[0].contains(&current)
                    && pair[0].contains("(this session)")
                    && pair[1].contains("12 turns")
                    && pair[1].contains("m0")
            })
            .count();
        assert_eq!(
            current_rows, 1,
            "current session identity and count must fit at 80 columns: {frame}"
        );
        k.plain(KeyCode::Enter);
        k.no_send();
        assert!(k.overlay.is_none());
        k.list(PickerKind::Sessions);
        k.receive(crate::msg::Msg::SessionsListed(rows));
        k.frame(100, 24);
        let hit = k
            .tui
            .hits
            .iter()
            .find(|hit| hit.click == super::super::shell::hits::Click::Picker(1))
            .copied()
            .unwrap();
        assert_eq!(hit.rect.height, 2, "session hit target covers both lines");
        for row in [hit.rect.y, hit.rect.y + hit.rect.height - 1] {
            let outcome = handle_mouse(
                MouseEvent {
                    kind: MouseEventKind::Down(MouseButton::Left),
                    column: hit.rect.x,
                    row,
                    modifiers: KeyModifiers::NONE,
                },
                &mut k.tui,
                Rect::new(0, 0, 100, 24),
                None,
                true,
            );
            assert!(matches!(outcome, MouseOutcome::Picker(1)));
        }
        let click = capture_picker_click(&k.scenario, k.overlay, 1).unwrap();
        let key = picker_click_key(click, &mut k.scenario, k.overlay, 10_000).unwrap();
        k.key(key.code, key.modifiers);
        assert!(
            matches!(k.received_command(), WorkerCommand::ResumeSession(id) if id == "session-other-fixture")
        );
    }

    #[test]
    fn canceled_list_request_blocks_reopen_until_its_old_terminal_reply() {
        let mut k = Keyboard::new();
        k.list(PickerKind::Models);
        k.plain(KeyCode::Esc);
        assert!(!k.tui.app.arranging, "canceling the list spends Escape");
        assert!(k.draft.is_empty());
        k.type_text("/models");
        k.plain(KeyCode::Enter);
        k.no_send();
        assert_eq!(k.scenario.pending_picker_kind(), Some(PickerKind::Models));
        k.receive(listed_models(1));
        assert!(k.overlay.is_none());
        assert!(k.scenario.picker.is_none());
        assert_eq!(k.scenario.pending_picker_kind(), None);
        k.list(PickerKind::Models);
        k.receive(crate::msg::Msg::ModelsListed(vec![(
            "new".into(),
            "fresh".into(),
        )]));
        assert_eq!(k.overlay, Some(Overlay::ModelPicker));
        assert_eq!(
            k.scenario.picker.as_ref().unwrap().rows[0].value,
            "new/fresh"
        );
        k.no_send();
    }

    #[test]
    fn late_list_cannot_replace_quit_help_approval_or_changed_identity() {
        for blocker in ["quit", "help", "help-closed", "approval", "identity"] {
            let mut k = Keyboard::new();
            k.list(PickerKind::Models);
            match blocker {
                "quit" => k.key(KeyCode::Char('c'), KeyModifiers::CONTROL),
                "help" => k.overlay = Some(Overlay::Help),
                "help-closed" => {
                    k.overlay = Some(Overlay::Help);
                    k.plain(KeyCode::Enter);
                }
                "approval" => k.receive(requested_approval()),
                "identity" => k.receive(crate::msg::Msg::Identity {
                    model: "new-model".into(),
                    provider: "new-provider".into(),
                    session_prefix: "new".into(),
                    session_id: "session-new-fixture".into(),
                    priced: false,
                }),
                _ => unreachable!(),
            }
            let expected_overlay = k.overlay;
            k.receive(listed_models(2));
            assert_eq!(
                k.overlay, expected_overlay,
                "{blocker} has priority over an old list"
            );
            assert!(k.scenario.picker.is_none(), "{blocker}");
            assert_eq!(
                k.scenario.pending_picker_kind(),
                None,
                "old reply settles even when ignored"
            );
            k.no_send();
        }
    }

    #[test]
    fn list_failures_settle_requests_without_replacing_modals_or_hiding_errors() {
        let mut k = Keyboard::new();
        k.receive(listed_models(1));
        assert!(k.overlay.is_none(), "unsolicited lists never open a picker");
        k.list(PickerKind::Models);
        k.receive(crate::msg::Msg::SessionsListed(Vec::new()));
        k.receive(crate::msg::Msg::SessionsListFailed("unrelated".into()));
        assert_eq!(k.scenario.pending_picker_kind(), Some(PickerKind::Models));
        assert!(
            !k.scenario
                .transcript
                .iter()
                .any(|line| line.text == "unrelated")
        );
        k.key(KeyCode::Char('c'), KeyModifiers::CONTROL);
        k.receive(crate::msg::Msg::ModelsListFailed(
            "invalid providers.toml".into(),
        ));
        assert_eq!(k.overlay, Some(Overlay::Quit));
        assert_eq!(k.scenario.pending_picker_kind(), None);
        assert!(
            k.scenario
                .transcript
                .iter()
                .any(|line| line.text == "invalid providers.toml")
        );
        k.plain(KeyCode::Esc);
        k.list(PickerKind::Sessions);
        k.receive(crate::msg::Msg::SessionsListFailed(
            "session directory unavailable".into(),
        ));
        assert_eq!(k.scenario.pending_picker_kind(), None);
        assert!(k.overlay.is_none());
        assert!(
            k.scenario
                .transcript
                .iter()
                .any(|line| line.text == "session directory unavailable")
        );
        k.list(PickerKind::Models);
        k.receive(listed_models(1));
        assert_eq!(k.overlay, Some(Overlay::ModelPicker));
    }

    #[test]
    fn picker_empty_stale_busy_and_approval_states_never_admit_a_selection() {
        for state in [
            "empty-reply",
            "empty-rows",
            "stale-selection",
            "busy",
            "approval",
        ] {
            let mut k = Keyboard::new();
            k.list(PickerKind::Models);
            k.receive(listed_models(if state == "empty-reply" { 0 } else { 2 }));
            match state {
                "empty-rows" => k.scenario.picker.as_mut().unwrap().rows.clear(),
                "stale-selection" => k.scenario.picker.as_mut().unwrap().sel = usize::MAX,
                "busy" => k.scenario.turn_live = true,
                "approval" => k.receive(requested_approval()),
                _ => {}
            }
            k.plain(KeyCode::Enter);
            k.no_send();
            assert!(k.scenario.pending_foreground().is_none(), "{state}");
            assert!(k.scenario.picker.is_none(), "{state}");
            assert!(k.overlay.is_none(), "{state}");
            if state == "approval" {
                assert!(k.scenario.approval_call_id.is_some());
            }
        }
    }

    #[test]
    fn deferred_picker_click_cannot_submit_a_draft_after_modal_or_identity_change() {
        for blocker in ["quit", "approval", "identity"] {
            let mut k = Keyboard::new();
            k.list(PickerKind::Models);
            k.receive(listed_models(2));
            k.draft = "unfinished prompt".into();
            let click = capture_picker_click(&k.scenario, k.overlay, 1).unwrap();
            match blocker {
                "quit" => k.key(KeyCode::Char('c'), KeyModifiers::CONTROL),
                "approval" => k.receive(requested_approval()),
                "identity" => k.receive(crate::msg::Msg::Identity {
                    model: "new".into(),
                    provider: "fixture".into(),
                    session_prefix: "new".into(),
                    session_id: "session-new-fixture".into(),
                    priced: false,
                }),
                _ => unreachable!(),
            }
            assert!(
                picker_click_key(click, &mut k.scenario, k.overlay, 10_000).is_none(),
                "{blocker}"
            );
            assert_eq!(k.draft, "unfinished prompt");
            k.no_send();
        }
    }

    #[test]
    fn unavailable_worker_does_not_leave_a_list_request_stuck() {
        let mut k = Keyboard::new();
        let (tx, rx) = std::sync::mpsc::channel();
        drop(rx);
        let mut toast = None;
        request_picker(&mut k.scenario, &tx, PickerKind::Models, &mut toast, 0);
        assert_eq!(k.scenario.pending_picker_kind(), None);
        assert!(k.scenario.picker.is_none());
        assert_eq!(toast.unwrap().text, "worker is unavailable");
        k.list(PickerKind::Models);
        k.receive(listed_models(1));
        assert_eq!(k.overlay, Some(Overlay::ModelPicker));
    }

    #[test]
    fn file_enter_and_tab_complete_the_draft_without_sending() {
        let mut k = Keyboard::new();
        std::fs::create_dir(k.root.join("docs")).unwrap();
        std::fs::write(k.root.join("docs/a b\"c.rs"), "content").unwrap();
        k.type_text("Read @do");
        assert!(k.frame(100, 30).contains("Files"));
        k.plain(KeyCode::Enter);
        assert_eq!(k.draft, "Read @\"docs/");
        assert!(k.tui.file_completion.is_open());
        k.no_send();
        k.plain(KeyCode::Tab);
        assert_eq!(k.draft, "Read @\"docs/a b\\\"c.rs\" ");
        assert!(!k.tui.file_completion.is_open());
        k.no_send();
        k.plain(KeyCode::Enter);
        assert!(
            matches!(k.received_command(), WorkerCommand::Prompt(text) if text == "Read @\"docs/a b\\\"c.rs\" ")
        );
    }

    #[test]
    fn file_picker_navigation_and_escape_preserve_the_draft() {
        let mut k = Keyboard::new();
        for path in ["alpha.rs", "beta.rs"] {
            std::fs::write(k.root.join(path), "content").unwrap();
        }
        k.type_text("@");
        k.plain(KeyCode::Down);
        assert_eq!(k.tui.file_completion.selected, 1);
        k.plain(KeyCode::Up);
        assert_eq!(k.tui.file_completion.selected, 0);
        k.plain(KeyCode::Esc);
        assert_eq!(k.draft, "@");
        assert!(!k.tui.file_completion.is_open());
        k.plain(KeyCode::Down);
        assert!(
            !k.tui.file_completion.is_open(),
            "dismissed picker stays closed until draft changes"
        );
        k.type_text("b");
        let frame = k.frame(164, 48);
        assert!(frame.contains("⇥/⏎ accept file"));
        assert!(!frame.contains("accept draft"));
        k.plain(KeyCode::Enter);
        assert_eq!(k.draft, "@\"beta.rs\" ");
        k.no_send();
    }

    #[test]
    fn reverse_history_queries_cycle_and_accept_only_the_draft() {
        let mut k = Keyboard::new();
        k.history = vec![
            "recent build".into(),
            "unrelated".into(),
            "old build\nnext".into(),
        ];
        k.draft = "unfinished\n日本語".into();
        k.reverse();
        k.type_text("build");
        assert_eq!(k.draft, "recent build");
        assert!(k.frame(100, 30).contains("History search: build"));
        k.reverse();
        assert_eq!(k.draft, "old build\nnext");
        k.plain(KeyCode::Enter);
        assert!(k.tui.history_search.is_none());
        k.no_send();
        k.plain(KeyCode::Enter);
        assert!(
            matches!(k.received_command(), WorkerCommand::Prompt(text) if text == "old build\nnext")
        );
    }

    #[test]
    fn reverse_history_no_match_and_escape_restore_exact_multiline_input() {
        let mut k = Keyboard::new();
        k.history = vec!["日本語 build".into()];
        k.draft = "unfinished\n日本語".into();
        k.reverse();
        k.type_text("日本");
        k.plain(KeyCode::Backspace);
        assert_eq!(k.tui.history_search.as_ref().unwrap().query, "日");
        k.type_text("missing");
        assert_eq!(k.draft, "unfinished\n日本語");
        assert!(k.frame(100, 30).contains("no match"));
        k.plain(KeyCode::Esc);
        assert_eq!(k.draft, "unfinished\n日本語");
        assert!(k.tui.history_search.is_none());
        k.no_send();
        k.history.clear();
        k.reverse();
        k.plain(KeyCode::Enter);
        assert_eq!(k.draft, "unfinished\n日本語");
        k.no_send();
    }

    #[test]
    fn slash_completion_and_multiline_input_keep_their_existing_behavior() {
        let mut k = Keyboard::new();
        k.type_text("/he");
        k.plain(KeyCode::Tab);
        assert_eq!(k.draft, "/help ");
        k.plain(KeyCode::Enter);
        assert_eq!(k.overlay, Some(Overlay::Help));
        k.plain(KeyCode::Esc);
        k.type_text("first");
        k.key(KeyCode::Enter, KeyModifiers::ALT);
        k.type_text("second");
        assert_eq!(k.draft, "first\nsecond");
        k.no_send();
    }

    #[test]
    fn question_mark_opens_and_closes_help_over_pending_approval() {
        for modifiers in [KeyModifiers::NONE, KeyModifiers::SHIFT] {
            let mut k = Keyboard::new();
            k.receive(requested_approval());

            k.key(KeyCode::Char('?'), modifiers);
            assert_eq!(k.overlay, Some(Overlay::Help));
            assert!(k.scenario.approval_call_id.is_some());
            let frame = k.frame(164, 30);
            assert!(frame.contains("KEYS"), "{frame}");
            assert!(frame.contains("APPROVALS"), "{frame}");

            k.plain(KeyCode::Esc);
            assert_eq!(k.overlay, None);
            assert!(k.scenario.approval_call_id.is_some());
        }
    }

    #[test]
    fn usage_command_adds_counter_notices_to_the_visible_transcript() {
        let mut k = Keyboard::new();
        k.type_text("/usage");
        k.plain(KeyCode::Enter);
        let frame = k.frame(164, 30);
        assert!(frame.contains("turns 0"), "{frame}");
        assert!(frame.contains("context unknown"), "{frame}");
        k.no_send();
    }

    #[test]
    fn modified_enter_in_an_open_file_picker_adds_a_newline() {
        for modifiers in [KeyModifiers::ALT, KeyModifiers::SHIFT] {
            let mut k = Keyboard::new();
            std::fs::write(k.root.join("alpha.rs"), "content").unwrap();
            k.type_text("@a");
            k.key(KeyCode::Enter, modifiers);
            assert_eq!(k.draft, "@a\n");
            assert!(!k.tui.file_completion.is_open());
            k.no_send();
        }
    }

    #[test]
    fn a_live_escape_stops_the_turn_even_with_a_picker_or_history_search() {
        let mut k = Keyboard::new();
        std::fs::write(k.root.join("alpha.rs"), "content").unwrap();
        k.type_text("@a");
        k.scenario.turn_live = true;
        k.plain(KeyCode::Esc);
        assert_eq!(k.cancel_count.load(Ordering::SeqCst), 1);
        assert!(!k.tui.file_completion.is_open());
        k.history = vec!["older prompt".into()];
        k.reverse();
        assert_eq!(k.draft, "older prompt");
        k.plain(KeyCode::Esc);
        assert_eq!(k.cancel_count.load(Ordering::SeqCst), 2);
        assert_eq!(k.draft, "@a");
        assert!(k.tui.history_search.is_none());
        k.no_send();
    }

    #[test]
    fn approval_keyboard_priority_prevents_completion_or_history_entry() {
        let mut k = Keyboard::new();
        std::fs::write(k.root.join("alpha.rs"), "content").unwrap();
        k.type_text("@a");
        k.scenario.approval_call_id = Some("read-1".into());
        k.scenario.approval_pending = Some("Read(alpha.rs)".into());
        k.scenario.approval_queue = vec!["Read".into()];
        k.plain(KeyCode::Enter);
        assert_eq!(k.draft, "@a");
        k.reverse();
        assert!(k.tui.history_search.is_none());
        assert!(!k.frame(100, 30).contains("Files"));
        k.no_send();
    }

    #[test]
    fn file_rows_are_clickable_and_history_hints_press_their_named_key() {
        let mut k = Keyboard::new();
        std::fs::write(k.root.join("alpha.rs"), "content").unwrap();
        k.type_text("@a");
        k.frame(100, 30);
        let hit = k
            .tui
            .hits
            .iter()
            .find(|hit| hit.click == super::super::shell::hits::Click::Completion(0))
            .unwrap();
        let event = crossterm::event::MouseEvent {
            kind: crossterm::event::MouseEventKind::Down(crossterm::event::MouseButton::Left),
            column: hit.rect.x + 2,
            row: hit.rect.y,
            modifiers: KeyModifiers::NONE,
        };
        assert_eq!(
            handle_mouse(event, &mut k.tui, Rect::new(0, 0, 100, 30), None, false),
            MouseOutcome::Completion(0)
        );
        assert_eq!(
            super::super::shell::hits::parse_key("⌃r"),
            Some((KeyCode::Char('r'), KeyModifiers::CONTROL))
        );
        k.no_send();
    }
}

#[cfg(test)]
mod history_persistence_tests {
    use super::*;

    #[test]
    fn typed_startup_keeps_readiness_and_history_on_the_resolved_session() {
        let root = tempfile_dir();
        let home = root.join("selected home");
        std::fs::create_dir_all(home.join("trust")).unwrap();
        std::fs::create_dir_all(home.join("ledger/segments")).unwrap();
        std::fs::write(home.join("trust/manifest.json"), "{}").unwrap();
        std::fs::write(home.join("ledger/segments/0000000000000000.log"), []).unwrap();
        let identity = crate::model::StartupIdentity {
            model: "family/selected-model".into(),
            provider_id: "selected-provider".into(),
            session_id: "resumed-session".into(),
        };
        let rows = crate::model::compute_readiness_with_identity(&home, &identity);
        assert_eq!(rows.len(), 3);
        assert!(rows.iter().all(|row| row.ok));
        assert_eq!(rows[1].label, "ledger · 1 segment");
        assert_eq!(rows[2].label, "selected-provider · family/selected-model");

        let history = vec!["first line\nsecond line".into()];
        let path = composer_history_path(&home, &identity);
        assert_eq!(path, Some(home.join("sessions/resumed-session.history")));
        save_history(&path, &history);
        let other = crate::model::StartupIdentity {
            session_id: "another-session".into(),
            ..identity.clone()
        };
        assert!(!composer_history_path(&home, &other).unwrap().exists());
        assert_eq!(
            read_history(&std::fs::read_to_string(path.unwrap()).unwrap()),
            history
        );
        assert!(composer_history_path(&home, &Default::default()).is_none());
        assert!(!crate::model::compute_readiness_with_identity(&home, &Default::default())[2].ok);
        std::fs::remove_dir_all(root).unwrap();
    }

    /// The history file has exact prompt entries, newest first, bounded:
    /// what save_history writes, the boot loader reads back.
    #[test]
    fn history_round_trips_through_the_file() {
        let dir = tempfile_dir();
        let path = Some(dir.join("sessions").join("s1.history"));
        let history = vec![
            "third prompt".to_string(),
            "second prompt".to_string(),
            "first prompt".to_string(),
        ];
        save_history(&path, &history);
        let raw = std::fs::read_to_string(path.as_ref().unwrap()).unwrap();
        assert_eq!(read_history(&raw), history);
        // And the boot loader's shape reads it back, newest first.
        let loaded: Vec<String> = std::fs::read_to_string(path.as_ref().unwrap())
            .map(|raw| read_history(&raw))
            .unwrap_or_default();
        assert_eq!(loaded, history);
    }

    /// Newlines and literal escape sequences survive a session resume.
    #[test]
    fn a_multiline_prompt_round_trips_as_one_exact_entry() {
        let dir = tempfile_dir();
        let path = Some(dir.join("sessions").join("s2.history"));
        save_history(
            &path,
            &["line one\nline two".to_string(), r"literal \n".to_string()],
        );
        let raw = std::fs::read_to_string(path.as_ref().unwrap()).unwrap();
        assert_eq!(read_history(&raw), ["line one\nline two", r"literal \n"]);
        assert_eq!(raw.lines().count(), 1);
    }

    /// Security (DR-06 §1.2): the history can carry pasted credentials, so
    /// the file is 0600 and its directory 0700 — a world-readable history
    /// would leak the operator's last prompts to any local user.
    #[cfg(unix)]
    #[test]
    fn history_file_and_dir_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile_dir();
        let path = Some(dir.join("sessions").join("s3.history"));
        save_history(&path, &["secret=AKIAEXAMPLE".to_string()]);
        let f = std::fs::metadata(path.as_ref().unwrap()).unwrap();
        assert_eq!(
            f.permissions().mode() & 0o777,
            0o600,
            "history file must be 0600"
        );
        let d = std::fs::metadata(path.as_ref().unwrap().parent().unwrap()).unwrap();
        assert_eq!(
            d.permissions().mode() & 0o777,
            0o700,
            "sessions dir must be 0700"
        );
    }

    /// A history file left world-readable by an older build is corrected on
    /// the next save — the mode is forced every write, not only at creation.
    #[cfg(unix)]
    #[test]
    fn an_existing_loose_file_is_tightened() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile_dir();
        let sessions = dir.join("sessions");
        std::fs::create_dir_all(&sessions).unwrap();
        let path = Some(sessions.join("s4.history"));
        std::fs::write(path.as_ref().unwrap(), "old prompt").unwrap();
        std::fs::set_permissions(
            path.as_ref().unwrap(),
            std::fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        save_history(&path, &["new prompt".to_string()]);
        let f = std::fs::metadata(path.as_ref().unwrap()).unwrap();
        assert_eq!(
            f.permissions().mode() & 0o777,
            0o600,
            "loose file must be tightened"
        );
    }

    /// The bound holds on write: an over-long history keeps the
    /// newest HISTORY_MAX entries.
    #[test]
    fn the_history_file_keeps_the_newest_entries() {
        let dir = tempfile_dir();
        let path = Some(dir.join("sessions").join("s3.history"));
        let history: Vec<String> = (0..HISTORY_MAX + 50)
            .map(|i| format!("prompt {i}"))
            .collect();
        save_history(&path, &history);
        let raw = std::fs::read_to_string(path.as_ref().unwrap()).unwrap();
        let loaded = read_history(&raw);
        assert_eq!(loaded.len(), HISTORY_MAX);
        assert_eq!(loaded[0], "prompt 0", "newest first");
        assert_eq!(
            loaded.last().unwrap(),
            &format!("prompt {}", HISTORY_MAX - 1)
        );
    }

    #[test]
    fn legacy_history_loads_without_rewriting_literal_escapes() {
        assert_eq!(
            read_history("recent\n\nold \\n prompt\n"),
            ["recent", r"old \n prompt"]
        );
        let overlong = (0..HISTORY_MAX + 5)
            .map(|i| format!("prompt {i}"))
            .collect::<Vec<_>>()
            .join("\n");
        assert_eq!(read_history(&overlong).len(), HISTORY_MAX);
    }

    #[test]
    fn legacy_json_array_prompts_stay_literal() {
        for prompt in [r#"["first","second"]"#, "[]", "[1, 2]"] {
            assert_eq!(read_history(prompt), vec![prompt.to_string()]);
        }
    }

    #[test]
    fn saved_history_requires_the_version_tag() {
        let raw = serde_json::to_string(&ComposerHistoryFile {
            schema: "unknown-version".into(),
            entries: vec!["a prompt".into()],
        })
        .unwrap();
        assert_eq!(read_history(&raw), vec![raw.clone()]);
        let tagged = serde_json::to_string(&ComposerHistoryFile {
            schema: HISTORY_FILE_SCHEMA.into(),
            entries: vec!["first\nsecond".into(), r"literal \n".into()],
        })
        .unwrap();
        assert_eq!(read_history(&tagged), ["first\nsecond", r"literal \n"]);
    }

    fn tempfile_dir() -> std::path::PathBuf {
        // Unique per CALL, not per process: tests in this binary run on
        // parallel threads, and a shared path whose setup does
        // remove_dir_all first means one test deletes another's files
        // mid-flight (observed as read/metadata failures only when enough
        // history tests ran concurrently).
        static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let d = std::env::temp_dir().join(format!("orbit-history-{}-{}", std::process::id(), n));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }
}

fn pane_context(
    s: &Scenario,
    controller: bool,
) -> orbit_frontend_protocol::customization::PaneContext {
    use orbit_frontend_protocol::customization::{PaneAgent, PaneContext};
    PaneContext {
        permission_mode: s.permission_mode.clone(),
        routing: s.routing_lines.clone(),
        input_tokens: s.input_tokens,
        output_tokens: s.output_tokens,
        cost_microcents: s.cost_microcents,
        agents: s
            .agents
            .iter()
            .take(32)
            .map(|(id, a)| PaneAgent {
                id: id.clone(),
                name: a.name.clone(),
                state: if a.done {
                    if a.ok { "done" } else { "failed" }
                } else {
                    "running"
                }
                .into(),
            })
            .collect(),
        controller,
    }
}

fn load_legacy_theme(
    home: &std::path::Path,
    safe_session: bool,
) -> Result<crate::tokens::Theme, String> {
    if safe_session {
        return Ok(crate::tokens::Theme::default());
    }
    let snapshot = super::layout::LayoutFile::load_checked(home).map_err(|e| e.to_string())?;
    match snapshot.legacy_bytes {
        None => Ok(Default::default()),
        Some(bytes) => std::str::from_utf8(&bytes)
            .ok()
            .and_then(|text| toml::from_str(text).ok())
            .ok_or_else(|| {
                "invalid tui.toml; choose an explicit safe-default session or repair the file"
                    .into()
            }),
    }
}

fn select_profile(
    legacy: &crate::tokens::Theme,
    canonical: Option<&orbit_frontend_protocol::customization::Profile>,
) -> orbit_frontend_protocol::customization::Profile {
    canonical.cloned().unwrap_or_else(|| legacy.profile())
}
fn apply_profile_preferences(
    tui: &mut Tui,
    profile: orbit_frontend_protocol::customization::Profile,
) {
    tui.reduced = profile.reduced_motion;
    tui.app.reduced = tui.reduced;
    tui.brand_tier = if tui.reduced && tui.brand_preference == super::welcome::BrandTier::Anim {
        super::welcome::BrandTier::Static
    } else {
        tui.brand_preference
    };
    tui.profile = profile;
}
fn reduce_runtime_message(
    msg: crate::msg::Msg,
    tui: &mut Tui,
    s: &mut Scenario,
    overlay: &mut Option<Overlay>,
    now: u64,
) -> Option<String> {
    use crate::msg::Msg;
    let previous_overlay = *overlay;
    let picker_overlay = matches!(overlay, Some(Overlay::ModelPicker | Overlay::SessionPicker));
    if (overlay.is_some() && !picker_overlay)
        || tui.app.picker.is_some()
        || tui.app.arranging
        || s.approval_call_id.is_some()
    {
        s.dismiss_picker();
    }
    if picker_overlay && s.picker.is_none() {
        *overlay = None;
        s.frontend.dirty = true;
    }
    let reply = match &msg {
        Msg::ModelsListed(_) => Some((PickerKind::Models, true)),
        Msg::SessionsListed(_) => Some((PickerKind::Sessions, true)),
        Msg::ModelsListFailed(_) => Some((PickerKind::Models, false)),
        Msg::SessionsListFailed(_) => Some((PickerKind::Sessions, false)),
        _ => None,
    };
    if let Some((kind, success)) = reply {
        let expected = s.pending_picker_kind() == Some(kind);
        let eligible = s.finish_picker_request(kind);
        if !expected || (success && !eligible) {
            return None;
        }
    }
    let result = reduce_frontend_message(msg, tui, s, now);
    if s.approval_call_id.is_some() {
        s.dismiss_picker();
    }
    if let Some((kind, true)) = reply
        && s.picker.is_some()
    {
        *overlay = Some(match kind {
            PickerKind::Models => Overlay::ModelPicker,
            PickerKind::Sessions => Overlay::SessionPicker,
        });
        tui.fx.overlay_ms = now;
    }
    if picker_overlay && s.picker.is_none() {
        *overlay = None;
    }
    if previous_overlay != *overlay {
        s.frontend.dirty = true;
    }
    result
}

fn reduce_frontend_message(
    msg: crate::msg::Msg,
    tui: &mut Tui,
    s: &mut Scenario,
    now: u64,
) -> Option<String> {
    if let crate::msg::Msg::SessionProjection(projection) = msg {
        if apply_session_projection(projection, s, now)
            && let Some(session) = tui.customization.as_mut()
        {
            session.invalidate_session(pane_context(s, session.context.controller));
            s.custom_panes = session.outputs.clone();
        }
        return None;
    }
    let restored = matches!(&msg, crate::msg::Msg::TranscriptLoaded { .. });
    let result = apply_msg(msg, s, now);
    if restored && let Some(session) = tui.customization.as_mut() {
        session.invalidate_session(pane_context(s, session.context.controller));
        s.custom_panes = session.outputs.clone();
    }
    result
}

#[allow(clippy::too_many_arguments)]
fn run_pane_action(
    panel: usize,
    action: usize,
    tui: &mut Tui,
    s: &mut Scenario,
    composer: &mut String,
    cancel: Option<&crate::worker::CancelHandle>,
    toast: &mut Option<Toast>,
    now: u64,
) {
    let Some(id) = tui.app.tree.custom_id_at(panel) else {
        return;
    };
    let Some(session) = tui.customization.as_mut() else {
        return;
    };
    session.context = pane_context(s, cancel.is_some());
    let result = session.action(&id, action);
    s.custom_panes = session.outputs.clone();
    match result {
        Ok(crate::customization::ActionEffect::InsertDraft(text)) => {
            *composer = text;
            tui.composer_cursor = super::composer::grapheme_count(composer);
            tui.file_completion
                .sync_at_cursor(composer, tui.composer_cursor);
            crate::customization::focus_conversation(&mut tui.app);
            tui.sync_focus();
        }
        Ok(crate::customization::ActionEffect::FocusConversation) => {
            crate::customization::focus_conversation(&mut tui.app);
            tui.sync_focus();
        }
        Ok(crate::customization::ActionEffect::OwnerCancel) => {
            if let Some(operation) = s.pending_manual() {
                let _ = operation.cancel();
            } else if let Some(cancel) = cancel {
                cancel();
            }
        }
        Ok(crate::customization::ActionEffect::Refreshed) => {}
        Err(error) => {
            *toast = Some(Toast {
                text: crate::bridge::terminal_safe(&crate::bridge::safe_text(&error.to_string())),
                ok: false,
                shown_ms: now,
            })
        }
    }
}

fn apply_profile_command(
    tui: &mut Tui,
    s: &mut Scenario,
    command: orbit_frontend_protocol::customization::ProfileCommand,
) -> Result<String, orbit_frontend_protocol::customization::CustomizationError> {
    let Some(session) = tui.customization.as_mut() else {
        return Err(
            orbit_frontend_protocol::customization::CustomizationError::Invalid(
                "customization host unavailable".into(),
            ),
        );
    };
    let reply = session.host.command(command)?;
    if let Some(profile) = reply.profile {
        let tree = crate::customization::profile_tree(&profile.profile)?;
        let focused = tui.app.tree.custom_id_at(tui.app.focus);
        session.accept(profile)?;
        session.refresh_all();
        let profile = session.resolved.profile.clone();
        tui.app.tree = tree;
        if let Some(id) = focused {
            tui.app.focus = (0..tui.app.tree.panel_count())
                .find(|i| tui.app.tree.custom_id_at(*i).as_deref() == Some(&id))
                .unwrap_or_else(|| {
                    tui.app
                        .tree
                        .leaves()
                        .iter()
                        .position(|(_, v)| *v == super::layout::View::Conversation)
                        .unwrap_or(0)
                });
        }
        apply_profile_preferences(tui, profile);
        s.brand_tier = tui.brand_tier;
        tui.sync_focus();
        s.custom_panes = tui.customization.as_ref().unwrap().outputs.clone();
    }
    Ok(crate::bridge::terminal_safe(&crate::bridge::safe_text(
        &reply.message,
    )))
}

fn profile_command_toast(tui: &mut Tui, s: &mut Scenario, text: &str, now: u64) -> Toast {
    let result =
        parse_profile_command(text).and_then(|command| apply_profile_command(tui, s, command));
    let (text, ok) = match result {
        Ok(text) => (text, true),
        Err(error) => (error.to_string(), false),
    };
    Toast {
        text,
        ok,
        shown_ms: now,
    }
}

#[allow(clippy::too_many_arguments)]
pub fn handle_custom_key(
    k: crossterm::event::KeyEvent,
    tui: &mut Tui,
    s: &mut Scenario,
    composer: &mut String,
    cancel: Option<&crate::worker::CancelHandle>,
    toast: &mut Option<Toast>,
    now: u64,
    modal: bool,
) -> bool {
    if modal || tui.app.arranging {
        return false;
    }
    if k.code == KeyCode::Enter
        && k.modifiers
            .intersects(KeyModifiers::ALT | KeyModifiers::SHIFT)
    {
        return false;
    }
    if matches!(k.code, KeyCode::Char(_))
        && k.modifiers
            .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT)
    {
        return false;
    }
    if k.code == KeyCode::Enter
        && (composer.starts_with("/theme") || composer.starts_with("/customize"))
    {
        *toast = Some(profile_command_toast(tui, s, composer, now));
        composer.clear();
        tui.composer_cursor = 0;
        tui.file_completion.sync_at_cursor(composer, 0);
        return true;
    }
    if tui.app.focused_view() == super::layout::View::Custom {
        match k.code {
            KeyCode::Char('r') => {
                if let Some(id) = tui.app.tree.custom_id_at(tui.app.focus)
                    && let Some(session) = tui.customization.as_mut()
                {
                    session.context = pane_context(s, cancel.is_some());
                    let result = session.refresh(&id);
                    s.custom_panes = session.outputs.clone();
                    if let Err(error) = result {
                        *toast = Some(Toast {
                            text: error.to_string(),
                            ok: false,
                            shown_ms: now,
                        });
                    }
                }
                return true;
            }
            KeyCode::Char(c @ '1'..='8') => {
                run_pane_action(
                    tui.app.focus,
                    c as usize - '1' as usize,
                    tui,
                    s,
                    composer,
                    cancel,
                    toast,
                    now,
                );
                return true;
            }
            KeyCode::Tab => {
                tui.app.cycle_focus(true);
                tui.sync_focus();
                return true;
            }
            KeyCode::BackTab => {
                tui.app.cycle_focus(false);
                tui.sync_focus();
                return true;
            }
            _ => {}
        }
    }
    false
}

pub fn parse_profile_command(
    input: &str,
) -> Result<
    orbit_frontend_protocol::customization::ProfileCommand,
    orbit_frontend_protocol::customization::CustomizationError,
> {
    use orbit_frontend_protocol::customization::{CustomizationError as E, ProfileCommand as C};
    if input.len() > 8192 {
        return Err(E::Invalid("customization command exceeds bounds".into()));
    }
    let (verb, rest) = input.trim().split_once(' ').unwrap_or((input.trim(), ""));
    let rest = rest.trim();
    if verb == "/theme" {
        return if rest.is_empty() {
            Ok(C::Show)
        } else {
            Ok(C::Theme { name: rest.into() })
        };
    }
    if verb != "/customize" {
        return Err(E::Invalid("unknown customization command".into()));
    }
    let (op, args) = rest.split_once(' ').unwrap_or((rest, ""));
    let args = args.trim();
    match op {
        "" | "show" if args.is_empty() => Ok(C::Show),
        "capabilities" if args.is_empty() => Ok(C::Capabilities),
        "reload" if args.is_empty() => Ok(C::Reload),
        "validate" | "import" | "export" if !args.is_empty() => Ok(match op {
            "validate" => C::Validate { path: args.into() },
            "import" => C::Import { path: args.into() },
            _ => C::Export { path: args.into() },
        }),
        "reset" => Ok(C::Reset {
            key: if args.is_empty() {
                None
            } else {
                Some(args.into())
            },
        }),
        "set" => {
            let (key, value) = args
                .split_once(' ')
                .ok_or_else(|| E::Invalid("set requires KEY VALUE".into()))?;
            Ok(C::Set {
                key: key.into(),
                value: value.trim().into(),
            })
        }
        _ => Err(E::Invalid(
            "usage: /customize show|capabilities|validate|import|export|set|reset|reload".into(),
        )),
    }
}

fn save_layout(tui: &mut Tui, toast: &mut Option<Toast>, now: u64) {
    if tui.customization.is_some() {
        tui.app.tree = tui.app.tree.clone().with_conversation();
        tui.sync_focus();
    }
    let result = if let Some(session) = tui.customization.as_mut() {
        session
            .persist_tree(&tui.app.tree)
            .map_err(|e| e.to_string())
    } else {
        tui.app.save_yours()
    };
    if let Err(error) = result {
        *toast = Some(Toast {
            text: format!("Layout not saved: {error}"),
            ok: false,
            shown_ms: now,
        });
    }
}

#[cfg(test)]
mod routing_projection_tests {
    use super::*;
    #[test]
    fn pane_context_tracks_authoritative_mode_changes_without_caching_startup_mode() {
        let mut scenario = Scenario::new();
        for mode in ["default", "dontAsk", "acceptEdits", "plan", "bypass"] {
            apply_msg(
                crate::msg::Msg::ModeChanged(mode.into()),
                &mut scenario,
                5000,
            );
            assert_eq!(
                pane_context(&scenario, true).permission_mode.as_deref(),
                Some(mode)
            );
        }
    }
    #[test]
    fn routing_projection_is_bounded_scanned_and_available_to_pane_context() {
        let mut scenario = Scenario::new();
        apply_msg(
            crate::msg::Msg::Routing(vec![
                "phase: coding".into(),
                "difficulty: easy".into(),
                "\u{1b}[31mprovider/model\u{1b}[0m".into(),
                "界".repeat(200),
            ]),
            &mut scenario,
            5000,
        );
        let context = pane_context(&scenario, true);
        assert_eq!(context.routing[0], "phase: coding");
        assert_eq!(context.routing[2], "provider/model");
        assert!(context.routing[3].len() <= 256);
        assert!(context.controller);
        assert!(scenario.transcript.is_empty());
    }
    #[test]
    fn routing_projection_byte_cap_never_splits_a_grapheme() {
        let mut scenario = Scenario::new();
        let routing = format!("{}e\u{301}", "a".repeat(255));
        apply_msg(crate::msg::Msg::Routing(vec![routing]), &mut scenario, 5000);
        assert_eq!(scenario.routing_lines[0], "a".repeat(255));
        assert!(scenario.routing_lines[0].len() <= 256);
    }
    #[test]
    fn resumed_transcript_replaces_old_chat_and_clears_route_and_working_state() {
        let mut scenario = Scenario::new();
        scenario.model = "preserved model".into();
        scenario.routing_lines = vec!["old route".into()];
        scenario.transcript.push(TranscriptLine {
            text: "old chat".into(),
            ..Default::default()
        });
        scenario.turn_live = true;
        scenario.running.insert("stale-call".into(), "Read".into());
        apply_msg(
            crate::msg::Msg::TranscriptLoaded {
                lines: vec![
                    crate::model::TranscriptLine::User {
                        text: "saved prompt".into(),
                        time: None,
                    },
                    crate::model::TranscriptLine::Assistant {
                        text: "saved answer".into(),
                        time: None,
                    },
                ],
                input_tokens: 55,
                output_tokens: 21,
                cost_microcents: 100,
                turns: 4,
            },
            &mut scenario,
            5000,
        );
        assert_eq!(
            scenario
                .transcript
                .iter()
                .map(|line| line.text.as_str())
                .collect::<Vec<_>>(),
            ["saved prompt", "saved answer"]
        );
        assert_eq!(scenario.model, "preserved model");
        assert!(scenario.routing_lines.is_empty());
        assert!(scenario.running.is_empty());
        assert!(!scenario.turn_live);
        assert_eq!(
            (
                scenario.input_tokens,
                scenario.output_tokens,
                scenario.cost_microcents,
                scenario.turns
            ),
            (55, 21, 100, 4)
        );
    }
}

#[cfg(test)]
mod customization_review_tests {
    use super::*;
    use orbit_frontend_protocol::customization::*;
    use ratatui::{Terminal, backend::TestBackend, style::Color};
    use std::{
        collections::BTreeMap,
        sync::{Arc, Mutex},
    };

    struct Host(Mutex<ResolvedProfile>);
    impl ProfileHost for Host {
        fn load(&self) -> Result<ResolvedProfile, CustomizationError> {
            Ok(self.0.lock().unwrap().clone())
        }
        fn replace(
            &self,
            profile: Profile,
            expected: &str,
        ) -> Result<ResolvedProfile, CustomizationError> {
            profile.validate()?;
            let mut current = self.0.lock().unwrap();
            if current.revision != expected {
                return Err(CustomizationError::Busy);
            }
            current.profile = profile;
            current.revision.push('x');
            Ok(current.clone())
        }
        fn reset(&self, _: &str) -> Result<ResolvedProfile, CustomizationError> {
            unreachable!()
        }
        fn command(&self, _: ProfileCommand) -> Result<ProfileCommandResult, CustomizationError> {
            Ok(ProfileCommandResult {
                message: "loaded".into(),
                profile: Some(self.load()?),
            })
        }
        fn read_pane(
            &self,
            id: &str,
            context: &PaneContext,
        ) -> Result<PaneOutput, CustomizationError> {
            let resolved = self.load()?;
            let def = resolved.profile.panes.iter().find(|p| p.id == id).unwrap();
            let text = match id {
                "routing" => context.routing.join("\n"),
                "usage" => format!("input {}", context.input_tokens),
                "agents" => context
                    .agents
                    .iter()
                    .map(|a| a.name.clone())
                    .collect::<Vec<_>>()
                    .join("\n"),
                _ => unreachable!(),
            };
            Ok(PaneOutput {
                id: id.into(),
                title: def.title.clone(),
                state: PaneState::Ready,
                text,
                truncated: false,
                actions: def.actions.clone(),
            })
        }
    }
    fn host(profile: Profile) -> Arc<Host> {
        Arc::new(Host(Mutex::new(ResolvedProfile {
            profile,
            revision: "review-1".into(),
            sources: BTreeMap::new(),
            capabilities: CustomizationCapabilities::default(),
        })))
    }
    fn buffer(tui: &Tui) -> ratatui::buffer::Buffer {
        let mut terminal = Terminal::new(TestBackend::new(160, 40)).unwrap();
        terminal
            .draw(|f| {
                draw(
                    f,
                    tui,
                    &Scenario::new(),
                    "local draft",
                    None,
                    "",
                    0,
                    None,
                    false,
                    0,
                )
            })
            .unwrap();
        terminal.backend().buffer().clone()
    }
    #[test]
    fn host_backed_review_preset_mouse_and_keyboard_keep_and_persist_conversation() {
        use crate::proto::layout::{Node, Preset, View as LayoutView};
        use crate::proto::shell::hits::Click;
        use crossterm::event::{KeyEvent, MouseButton, MouseEvent, MouseEventKind};
        let source = host(Profile::default());
        let mut tui = Tui::new();
        tui.reduced = true;
        tui.tick_ms = 5000;
        tui.customization =
            Some(crate::customization::CustomizationSession::open(source.clone()).unwrap());
        let mut scenario = Scenario::new();
        let mut terminal = Terminal::new(TestBackend::new(164, 48)).unwrap();
        terminal
            .draw(|f| {
                tui.hits = draw_with_hits(f, &tui, &scenario, "", None, "", 0, None, false, 0);
            })
            .unwrap();
        let hit = tui
            .hits
            .iter()
            .find(|hit| hit.click == Click::Preset(3))
            .unwrap()
            .rect;
        handle_mouse(
            MouseEvent {
                kind: MouseEventKind::Down(MouseButton::Left),
                column: hit.x,
                row: hit.y,
                modifiers: KeyModifiers::NONE,
            },
            &mut tui,
            Rect::new(0, 0, 164, 48),
            None,
            false,
        );
        assert_eq!(tui.app.current_preset(), Some(Preset::Review));
        assert_eq!(tui.app.tree, Node::profile_preset(Preset::Review));
        assert_eq!(
            tui.app
                .tree
                .leaves()
                .iter()
                .filter(|(_, view)| *view == LayoutView::Conversation)
                .count(),
            1
        );
        source.load().unwrap().profile.validate().unwrap();
        assert_eq!(
            serde_json::to_value(&tui.app.tree).unwrap(),
            serde_json::to_value(&source.load().unwrap().profile.layout.tree).unwrap()
        );
        let (commands, received) = std::sync::mpsc::channel();
        let (_bus, sender) = Bus::new();
        let approvals = ApprovalRegistry::new();
        tui.app.arranging = true;
        for ch in [']', '['] {
            handle_key(
                KeyEvent::new(KeyCode::Char(ch), KeyModifiers::NONE),
                &mut tui,
                &mut scenario,
                &mut String::new(),
                None,
                &commands,
                &sender,
                &approvals,
                5000,
                &mut None,
                &mut String::new(),
                &mut 0,
                &mut 0,
                &mut None,
                &mut Vec::new(),
                &mut Vec::new(),
                &mut None,
                &mut None,
                &mut false,
                &mut false,
            );
        }
        assert_eq!(tui.app.tree, Node::profile_preset(Preset::Review));
        assert_eq!(tui.app.current_preset(), Some(Preset::Review));
        assert_eq!(
            serde_json::to_value(&tui.app.tree).unwrap(),
            serde_json::to_value(&source.load().unwrap().profile.layout.tree).unwrap()
        );
        assert!(received.try_recv().is_err());
        assert!(tui.app.layout_error.is_none());
    }
    #[test]
    fn canonical_startup_profile_overrules_conflicting_real_legacy_capabilities() {
        let legacy: crate::tokens::Theme =
            toml::from_str("[color]\nmode='mono'\nreduced=true\nbrand='anim'\n").unwrap();
        assert!(legacy.profile().reduced_motion);
        assert_eq!(legacy.profile().color_mode, ColorMode::Mono);
        let canonical = Profile {
            reduced_motion: false,
            color_mode: ColorMode::Truecolor,
            ..Profile::default()
        };
        let mut tui = Tui::new();
        tui.tier =
            super::super::core::Tier::detect(false, Some("truecolor"), Some("xterm-256color"));
        tui.brand_preference = super::super::welcome::BrandTier::Anim;
        apply_profile_preferences(&mut tui, select_profile(&legacy, Some(&canonical)));
        tui.tick_ms = 5000;
        assert!(!tui.reduced && !tui.app.reduced);
        assert_eq!(tui.brand_tier, super::super::welcome::BrandTier::Anim);
        assert!(
            buffer(&tui)
                .content
                .iter()
                .any(|c| matches!(c.fg, Color::Rgb(..)))
        );
        assert!(select_profile(&legacy, None).reduced_motion);
    }
    #[test]
    fn hot_profile_reload_releases_mono_and_reduced_motion_without_caching_legacy() {
        let mut tui = Tui::new();
        tui.tick_ms = 5000;
        tui.brand_preference = super::super::welcome::BrandTier::Anim;
        apply_profile_preferences(
            &mut tui,
            Profile {
                color_mode: ColorMode::Mono,
                reduced_motion: true,
                ..Profile::default()
            },
        );
        let first = buffer(&tui);
        assert!(
            first
                .content
                .iter()
                .all(|c| c.fg == Color::Reset && c.bg == Color::Reset)
        );
        assert_eq!(tui.brand_tier, super::super::welcome::BrandTier::Static);
        let source = host(Profile::default());
        tui.customization = Some(crate::customization::CustomizationSession::open(source).unwrap());
        let mut scenario = Scenario::new();
        apply_profile_command(&mut tui, &mut scenario, ProfileCommand::Reload).unwrap();
        assert!(!tui.reduced && !tui.app.reduced);
        assert_eq!(scenario.brand_tier, super::super::welcome::BrandTier::Anim);
        assert_eq!(tui.tier, super::super::core::Tier::TrueColor);
        assert!(
            buffer(&tui)
                .content
                .iter()
                .any(|c| matches!(c.fg, Color::Rgb(..)))
        );
    }
    #[test]
    fn canonical_truecolor_cannot_upgrade_no_color_or_sixteen_color_hardware() {
        let mut tui = Tui::new();
        tui.tick_ms = 5000;
        for (no_color, expected) in [
            (true, super::super::core::Tier::None),
            (false, super::super::core::Tier::T16),
        ] {
            tui.tier = super::super::core::Tier::detect(no_color, None, Some("xterm"));
            apply_profile_preferences(
                &mut tui,
                Profile {
                    color_mode: ColorMode::Truecolor,
                    ..Profile::default()
                },
            );
            assert_eq!(tui.tier, expected);
            let actual = buffer(&tui);
            assert!(
                !actual
                    .content
                    .iter()
                    .any(|c| matches!(c.fg, Color::Rgb(..)) || matches!(c.bg, Color::Rgb(..)))
            );
            if no_color {
                assert!(
                    actual
                        .content
                        .iter()
                        .all(|c| c.fg == Color::Reset && c.bg == Color::Reset)
                );
            }
        }
    }
    #[test]
    fn transcript_replacement_keeps_all_snapshot_caches_stale_through_actions() {
        let mut profile = Profile::default();
        for (id, snapshot) in [
            ("routing", SnapshotKind::Routing),
            ("usage", SnapshotKind::Usage),
            ("agents", SnapshotKind::Agents),
        ] {
            profile.panes.push(PaneDef {
                id: id.into(),
                title: id.into(),
                surfaces: vec![Surface::Terminal],
                source: PaneSource::Snapshot { snapshot },
                actions: vec![
                    PaneAction::Refresh,
                    PaneAction::FocusConversation,
                    PaneAction::InsertPrompt {
                        text: "local draft".into(),
                    },
                ],
            });
        }
        profile.layout.tree = LayoutNode::Split {
            direction: Direction::Right,
            shares: vec![1, 1, 1, 1],
            children: vec![
                LayoutNode::panel(View::Conversation),
                LayoutNode::Custom {
                    pane_id: "routing".into(),
                },
                LayoutNode::Custom {
                    pane_id: "usage".into(),
                },
                LayoutNode::Custom {
                    pane_id: "agents".into(),
                },
            ],
        };
        let source = host(profile);
        let mut tui = Tui::new();
        let mut session = crate::customization::CustomizationSession::open(source).unwrap();
        session.context = PaneContext {
            routing: vec!["OLD ROUTE".into()],
            input_tokens: 999,
            agents: vec![PaneAgent {
                id: "old".into(),
                name: "OLD AGENT".into(),
                state: "done".into(),
            }],
            ..PaneContext::default()
        };
        session.refresh_all();
        assert!(session.outputs["routing"].text.contains("OLD ROUTE"));
        tui.app.tree = crate::customization::profile_tree(&session.resolved.profile).unwrap();
        let mut scenario = Scenario::new();
        scenario.custom_panes = session.outputs.clone();
        tui.customization = Some(session);
        reduce_frontend_message(
            crate::msg::Msg::TranscriptLoaded {
                lines: vec![],
                input_tokens: 55,
                output_tokens: 21,
                cost_microcents: 100,
                turns: 4,
            },
            &mut tui,
            &mut scenario,
            5000,
        );
        let mut composer = String::new();
        let mut toast = None;
        for action in [1, 2] {
            run_pane_action(
                1,
                action,
                &mut tui,
                &mut scenario,
                &mut composer,
                None,
                &mut toast,
                5000,
            );
            for id in ["routing", "usage", "agents"] {
                assert_eq!(scenario.custom_panes[id].state, PaneState::Stale);
                assert_eq!(
                    tui.customization.as_ref().unwrap().outputs[id].state,
                    PaneState::Stale
                );
                assert!(!scenario.custom_panes[id].text.contains("OLD"));
            }
        }
        assert_eq!(composer, "local draft");
        assert!(toast.is_none());
        run_pane_action(
            2,
            0,
            &mut tui,
            &mut scenario,
            &mut composer,
            None,
            &mut toast,
            5000,
        );
        assert_eq!(scenario.custom_panes["usage"].text, "input 55");
        assert_eq!(scenario.custom_panes["usage"].state, PaneState::Ready);
        for id in ["routing", "agents"] {
            assert_eq!(scenario.custom_panes[id].state, PaneState::Stale);
        }
        let context = &tui.customization.as_ref().unwrap().context;
        assert!(context.routing.is_empty() && context.agents.is_empty());
        assert_eq!(context.input_tokens, 55);
    }
    #[test]
    fn explicit_safe_session_bypasses_malformed_legacy_and_profile_without_rewrite() {
        let home =
            std::env::temp_dir().join(format!("orbit-safe-customization-{}", std::process::id()));
        std::fs::create_dir(&home).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let legacy = b"[layout\nthis cannot parse\n";
        let canonical = b"{invalid profile";
        std::fs::write(home.join("tui.toml"), legacy).unwrap();
        std::fs::write(home.join("customization.json"), canonical).unwrap();
        assert!(load_legacy_theme(&home, false).is_err());
        let safe = load_legacy_theme(&home, true).unwrap();
        assert_eq!(
            select_profile(&safe, None),
            crate::tokens::Theme::default().profile()
        );
        assert_eq!(std::fs::read(home.join("tui.toml")).unwrap(), legacy);
        assert_eq!(
            std::fs::read(home.join("customization.json")).unwrap(),
            canonical
        );
        assert!(!home.join(".customization.lock").exists());
        std::fs::remove_dir_all(home).unwrap();
    }
}

#[cfg(test)]
mod bound_projection_tests {
    use super::*;
    use crate::msg::{
        ContextProjection, CostQualification, ManualOutcome, ProjectionReason, SessionProjection,
    };
    use crate::worker::{ForegroundKind, ForegroundOperation, ManualAction, SessionBinding};
    use orbit_frontend_protocol::customization::*;
    use std::{collections::BTreeMap, sync::Arc};

    fn binding() -> SessionBinding {
        SessionBinding {
            session_id: "session-bound-test".into(),
            generation: 1,
        }
    }

    fn projection(reason: ProjectionReason) -> SessionProjection {
        SessionProjection {
            binding: binding(),
            model: "model".into(),
            provider: "provider".into(),
            priced: true,
            lines: vec![crate::model::TranscriptLine::User {
                text: "preserved".into(),
                time: None,
            }],
            turns: 2,
            input_tokens: 10,
            output_tokens: 20,
            cost_microcents: 30,
            cost: CostQualification::Known { revision: 3 },
            context: ContextProjection::Unavailable,
            reason,
        }
    }

    fn establish(s: &mut Scenario) {
        assert!(apply_session_projection(
            projection(ProjectionReason::Initial),
            s,
            1
        ));
        assert!(s.take_view_dirty());
    }

    fn active_ordinary_operation(
        command: WorkerCommand,
    ) -> (
        Scenario,
        ForegroundOperation,
        crate::worker::ForegroundRegistration,
    ) {
        let mut s = Scenario::new();
        establish(&mut s);
        let (sink, receiver) = std::sync::mpsc::channel();
        submit_foreground(&mut s, &sink, command).unwrap();
        let WorkerCommand::Bound { operation, command } = receiver.recv().unwrap() else {
            panic!("ordinary command was not bound");
        };
        let registration = operation.start(&command).unwrap();
        (s, operation, registration)
    }

    fn record_measured_context_sample(s: &mut Scenario) {
        apply_msg(
            crate::msg::Msg::Usage {
                used_tokens: 48_000,
                window_tokens: 200_000,
                breakdown: Some(orbit_frontend_protocol::ContextBreakdown {
                    system: 100,
                    tools: 200,
                    memory: 50,
                    messages: 47_650,
                    compact_at: 180_000,
                    reserve: 10_000,
                }),
            },
            s,
            2,
        );
    }

    fn assert_measured_context_rejected_atomically(s: &mut Scenario, reason: ProjectionReason) {
        let before = format!("{s:?}");
        let mut invalid = projection(reason);
        invalid.context = ContextProjection::PreserveMeasured;
        assert!(!apply_session_projection(invalid, s, 3));
        assert_eq!(format!("{s:?}"), before);
    }

    fn saved_bash(call_id: &str) -> crate::model::TranscriptLine {
        crate::model::TranscriptLine::Stripped {
            tool_name: "Bash".into(),
            call_id: call_id.into(),
            summary: String::new(),
            outcome: Some(crate::model::ToolOutcome::Ok),
            meta: "exit 0".into(),
            started_at: None,
        }
    }

    fn bash_history(count: usize) -> Vec<crate::model::TranscriptLine> {
        (0..count)
            .map(|index| saved_bash(&format!("call-{index}")))
            .collect()
    }

    #[test]
    fn initial_projection_restores_empty_tapes_in_transcript_order() {
        let mut s = Scenario::new();
        let mut p = projection(ProjectionReason::Initial);
        p.lines = vec![
            saved_bash("call-a"),
            crate::model::TranscriptLine::User {
                text: "between".into(),
                time: None,
            },
            saved_bash("call-b"),
        ];

        assert!(apply_session_projection(p, &mut s, 1));
        assert_eq!(
            s.tapes
                .iter()
                .map(|t| t.call_id.as_str())
                .collect::<Vec<_>>(),
            ["call-a", "call-b"]
        );
        assert!(s.tapes.iter().all(|t| t.lines.is_empty()));
    }

    #[test]
    fn refresh_preserves_existing_tapes_and_selection_and_adds_only_new_empty_tapes() {
        let mut s = Scenario::new();
        let mut initial = projection(ProjectionReason::Initial);
        initial.lines = vec![saved_bash("call-a"), saved_bash("call-b")];
        assert!(apply_session_projection(initial, &mut s, 1));
        s.push_tape_line("call-a", "kept first output".into());
        s.push_tape_line("call-b", "kept second output".into());
        s.pick_tape(0);

        let mut refresh = projection(ProjectionReason::Refresh);
        refresh.lines = vec![
            saved_bash("call-a"),
            saved_bash("call-b"),
            saved_bash("call-c"),
        ];
        assert!(apply_session_projection(refresh, &mut s, 2));

        assert_eq!(s.tapes.len(), 3);
        assert_eq!(s.tapes[0].lines, ["kept first output"]);
        assert_eq!(s.tapes[1].lines, ["kept second output"]);
        assert!(s.tapes[2].lines.is_empty());
        assert_eq!(
            s.selected_tape().map(|i| s.tapes[i].call_id.as_str()),
            Some("call-a")
        );
    }

    #[test]
    fn restored_tapes_obey_capacity_and_keep_a_surviving_selection() {
        let mut s = Scenario::new();
        let mut initial = projection(ProjectionReason::Initial);
        initial.lines = bash_history(super::super::scenario::TAPE_MAX);
        assert!(apply_session_projection(initial, &mut s, 1));
        s.pick_tape(7);

        let mut refresh = projection(ProjectionReason::Refresh);
        refresh.lines = bash_history(super::super::scenario::TAPE_MAX + 1);
        assert!(apply_session_projection(refresh, &mut s, 2));

        assert_eq!(s.tapes.len(), super::super::scenario::TAPE_MAX);
        assert_eq!(s.tapes.first().unwrap().call_id, "call-1");
        assert_eq!(s.tapes.last().unwrap().call_id, "call-20");
        assert_eq!(
            s.selected_tape().map(|i| s.tapes[i].call_id.as_str()),
            Some("call-7")
        );
        assert!(s.tapes.iter().all(|t| t.lines.is_empty()));
    }

    #[test]
    fn evicting_the_selected_oldest_tape_returns_to_following_newest() {
        let mut s = Scenario::new();
        let mut initial = projection(ProjectionReason::Initial);
        initial.lines = bash_history(super::super::scenario::TAPE_MAX);
        assert!(apply_session_projection(initial, &mut s, 1));
        s.pick_tape(0);

        let mut refresh = projection(ProjectionReason::Refresh);
        refresh.lines = bash_history(super::super::scenario::TAPE_MAX + 1);
        assert!(apply_session_projection(refresh, &mut s, 2));

        assert!(s.tape_sel.is_none());
        assert_eq!(
            s.selected_tape().map(|i| s.tapes[i].call_id.as_str()),
            Some("call-20")
        );
    }

    #[test]
    fn switching_sessions_replaces_old_tapes_with_empty_new_session_tapes() {
        let mut s = Scenario::new();
        let mut initial = projection(ProjectionReason::Initial);
        initial.lines = vec![saved_bash("old-call")];
        assert!(apply_session_projection(initial, &mut s, 1));

        let previous = binding();
        let mut resumed = projection(ProjectionReason::Resume {
            previous: previous.clone(),
        });
        resumed.binding = SessionBinding {
            session_id: "session-resumed-test".into(),
            generation: previous.generation + 1,
        };
        resumed.lines = vec![saved_bash("new-call")];

        assert!(apply_session_projection(resumed, &mut s, 2));
        assert_eq!(s.session_id, "session-resumed-test");
        assert_eq!(
            s.tapes
                .iter()
                .map(|t| t.call_id.as_str())
                .collect::<Vec<_>>(),
            ["new-call"]
        );
        assert!(s.tapes[0].lines.is_empty());
    }

    #[test]
    fn measured_context_sample_survives_matching_refresh_and_unavailable_clears_it() {
        let mut s = Scenario::new();
        establish(&mut s);
        apply_msg(
            crate::msg::Msg::Usage {
                used_tokens: 48_000,
                window_tokens: 200_000,
                breakdown: Some(orbit_frontend_protocol::ContextBreakdown {
                    system: 100,
                    tools: 200,
                    memory: 50,
                    messages: 47_650,
                    compact_at: 180_000,
                    reserve: 10_000,
                }),
            },
            &mut s,
            2,
        );

        let mut measured = projection(ProjectionReason::Refresh);
        measured.context = ContextProjection::PreserveMeasured;
        assert!(apply_session_projection(measured, &mut s, 3));
        assert_eq!(s.used_tokens, 48_000);
        assert_eq!(s.window_tokens, 200_000);
        assert_eq!(s.usage_shown_ms, 2);
        assert_eq!(
            s.ctx_breakdown,
            Some(orbit_frontend_protocol::ContextBreakdown {
                system: 100,
                tools: 200,
                memory: 50,
                messages: 47_650,
                compact_at: 180_000,
                reserve: 10_000,
            })
        );

        s.compacting_from = Some(48_000);
        let mut unavailable = projection(ProjectionReason::Refresh);
        unavailable.context = ContextProjection::Unavailable;
        assert!(apply_session_projection(unavailable, &mut s, 4));
        assert_eq!(s.used_tokens, 0);
        assert_eq!(s.window_tokens, 0);
        assert_eq!(s.usage_shown_ms, 0);
        assert_eq!(s.ctx_breakdown, None);
        assert_eq!(s.ctx_from, 0.0);
        assert_eq!(s.ctx_to, 0.0);
        assert_eq!(s.ctx_ms, 0);
        assert_eq!(s.compacting_from, None);
    }

    #[test]
    fn measured_context_survives_exact_active_prompt_and_plan_prompt_operations() {
        for command in [
            WorkerCommand::Prompt("prompt".into()),
            WorkerCommand::PlanPrompt("plan".into()),
        ] {
            let (mut s, operation, registration) = active_ordinary_operation(command);
            record_measured_context_sample(&mut s);
            drop(registration);

            let mut terminal = projection(ProjectionReason::Operation { operation });
            terminal.context = ContextProjection::PreserveMeasured;
            assert!(apply_session_projection(terminal, &mut s, 3));
            assert_eq!(s.used_tokens, 48_000);
            assert_eq!(s.window_tokens, 200_000);
            assert_eq!(s.usage_shown_ms, 2);
            assert_eq!(
                s.ctx_breakdown,
                Some(orbit_frontend_protocol::ContextBreakdown {
                    system: 100,
                    tools: 200,
                    memory: 50,
                    messages: 47_650,
                    compact_at: 180_000,
                    reserve: 10_000,
                })
            );
            assert!(s.frontend.foreground.is_none());
        }
    }

    #[test]
    fn measured_context_rejects_nonordinary_foreground_operation_atomically() {
        let mut s = Scenario::new();
        establish(&mut s);
        record_measured_context_sample(&mut s);
        let operation = s.new_foreground_operation(ForegroundKind::Control).unwrap();
        assert!(s.admit_foreground(operation.clone()));
        let registration = operation.start(&WorkerCommand::Undo).unwrap();
        drop(registration);

        assert_measured_context_rejected_atomically(
            &mut s,
            ProjectionReason::Operation { operation },
        );
    }

    #[test]
    fn measured_context_rejects_nonactive_ordinary_operation_id_atomically() {
        let (mut s, active, registration) =
            active_ordinary_operation(WorkerCommand::Prompt("prompt".into()));
        record_measured_context_sample(&mut s);
        drop(registration);
        let impostor =
            ForegroundOperation::new(active.source().clone(), ForegroundKind::Prompt, 99).unwrap();

        assert_measured_context_rejected_atomically(
            &mut s,
            ProjectionReason::Operation {
                operation: impostor,
            },
        );
    }

    #[test]
    fn measured_context_rejects_ordinary_operation_with_wrong_source_binding_atomically() {
        let (mut s, _, registration) =
            active_ordinary_operation(WorkerCommand::Prompt("prompt".into()));
        record_measured_context_sample(&mut s);
        drop(registration);
        let wrong_source = SessionBinding {
            session_id: "session-other".into(),
            generation: 1,
        };
        let operation = ForegroundOperation::new(wrong_source, ForegroundKind::Prompt, 99).unwrap();

        assert_measured_context_rejected_atomically(
            &mut s,
            ProjectionReason::Operation { operation },
        );
    }

    #[test]
    fn measured_context_operation_requires_an_existing_nonzero_sample() {
        let (mut s, operation, registration) =
            active_ordinary_operation(WorkerCommand::Prompt("prompt".into()));
        drop(registration);
        assert_eq!(s.window_tokens, 0);

        assert_measured_context_rejected_atomically(
            &mut s,
            ProjectionReason::Operation { operation },
        );
    }

    #[test]
    fn measured_context_rejects_wrong_identity_atomically() {
        for mismatch in ["model", "provider"] {
            let mut s = Scenario::new();
            establish(&mut s);
            apply_msg(
                crate::msg::Msg::Usage {
                    used_tokens: 48_000,
                    window_tokens: 200_000,
                    breakdown: None,
                },
                &mut s,
                2,
            );
            let before = format!("{s:?}");

            let mut invalid = projection(ProjectionReason::Refresh);
            invalid.context = ContextProjection::PreserveMeasured;
            if mismatch == "model" {
                invalid.model = "other-model".into();
            } else {
                invalid.provider = "other-provider".into();
            }
            assert!(!apply_session_projection(invalid, &mut s, 3));
            assert_eq!(
                format!("{s:?}"),
                before,
                "a {mismatch} mismatch must leave all session state unchanged",
            );
        }
    }

    #[test]
    fn measured_context_rejects_manual_reason_without_mutating_state() {
        let mut s = Scenario::new();
        establish(&mut s);
        apply_msg(
            crate::msg::Msg::Usage {
                used_tokens: 48_000,
                window_tokens: 200_000,
                breakdown: Some(orbit_frontend_protocol::ContextBreakdown {
                    system: 100,
                    tools: 200,
                    memory: 50,
                    messages: 47_650,
                    compact_at: 180_000,
                    reserve: 10_000,
                }),
            },
            &mut s,
            2,
        );
        let operation = s.new_manual_operation(ManualAction::Compact).unwrap();
        assert!(s.admit_manual(operation.clone()));
        let before = format!("{s:?}");

        let mut non_refresh = projection(ProjectionReason::Manual {
            operation,
            outcome: ManualOutcome::Failed,
            applied: false,
        });
        non_refresh.context = ContextProjection::PreserveMeasured;
        assert!(!apply_session_projection(non_refresh, &mut s, 3));
        assert_eq!(format!("{s:?}"), before);
    }

    #[test]
    fn measured_context_requires_an_existing_nonzero_sample_and_rejects_switches() {
        let mut s = Scenario::new();
        establish(&mut s);
        let mut missing = projection(ProjectionReason::Refresh);
        missing.context = ContextProjection::PreserveMeasured;
        assert!(!apply_session_projection(missing, &mut s, 2));

        apply_msg(
            crate::msg::Msg::Usage {
                used_tokens: 48_000,
                window_tokens: 200_000,
                breakdown: None,
            },
            &mut s,
            3,
        );
        let previous = binding();
        let mut resume = projection(ProjectionReason::Resume { previous });
        resume.binding = crate::worker::SessionBinding {
            session_id: "session-measured-next".into(),
            generation: 2,
        };
        resume.context = ContextProjection::PreserveMeasured;
        assert!(!apply_session_projection(resume, &mut s, 4));
        assert_eq!(s.used_tokens, 48_000);
        assert_eq!(s.window_tokens, 200_000);

        s.window_tokens = 0;
        let mut zero_window = projection(ProjectionReason::Refresh);
        zero_window.context = ContextProjection::PreserveMeasured;
        assert!(!apply_session_projection(zero_window, &mut s, 5));
        assert_eq!(s.used_tokens, 48_000);
        assert_eq!(s.window_tokens, 0);
    }

    fn failure_test_frame(s: &Scenario, width: u16, height: u16, scroll: usize) -> String {
        let mut tui = Tui::new();
        tui.reduced = true;
        tui.tick_ms = 10_000;
        let mut term =
            ratatui::Terminal::new(ratatui::backend::TestBackend::new(width, height)).unwrap();
        term.draw(|f| draw(f, &tui, s, "", None, "", 0, None, false, scroll))
            .unwrap();
        let buffer = term.backend().buffer();
        (0..height)
            .map(|y| {
                (0..width)
                    .map(|x| buffer[(x, y)].symbol())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn checked_clear_acknowledgement_survives_first_draw_and_refresh() {
        let old_id = "session-01J8ZK4QX2M7C9RT5VWEHN3B6D";
        let mut s = Scenario::new();
        let mut initial = projection(ProjectionReason::Initial);
        initial.binding.session_id = old_id.into();
        assert!(apply_session_projection(initial, &mut s, 1));
        let operation = s.new_manual_operation(ManualAction::Clear).unwrap();
        assert!(s.admit_manual(operation.clone()));
        let acknowledgement = format!("new session started; previous session {old_id} retained");
        assert_eq!(old_id.len(), 34);
        assert_eq!(acknowledgement.len(), 81);
        apply_msg(crate::msg::Msg::Status(acknowledgement.clone()), &mut s, 2);
        let mut cleared = projection(ProjectionReason::Manual {
            operation,
            outcome: ManualOutcome::Completed,
            applied: true,
        });
        cleared.binding = SessionBinding {
            session_id: "session-01J8ZK4QX2M7C9RT5VWEHN3B6E".into(),
            generation: 2,
        };
        cleared.lines.clear();
        cleared.turns = 0;
        cleared.input_tokens = 0;
        cleared.output_tokens = 0;
        cleared.cost_microcents = 0;
        cleared.cost = CostQualification::Known { revision: 0 };
        let mut refresh = cleared.clone();
        refresh.reason = ProjectionReason::Refresh;
        assert!(apply_session_projection(cleared, &mut s, 3));
        assert_eq!(s.session_id, refresh.binding.session_id);
        assert_eq!(s.session_binding(), Some(&refresh.binding));
        assert!(s.transcript.is_empty() && !s.is_busy());
        assert_eq!(
            (s.turns, s.input_tokens, s.output_tokens, s.cost_microcents),
            (0, 0, 0, 0)
        );
        let first = failure_test_frame(&s, 110, 30, 0);
        assert!(first.contains(&acknowledgement), "{first}");
        assert!(
            first.contains("New session") && first.contains("the harness that orbits"),
            "{first}"
        );
        assert_eq!(first.matches(&acknowledgement).count(), 1);
        assert!(apply_session_projection(refresh, &mut s, 4));
        let refreshed = failure_test_frame(&s, 110, 30, 0);
        assert!(refreshed.contains(&acknowledgement), "{refreshed}");
        assert_eq!(refreshed.matches(&acknowledgement).count(), 1);
        assert!(s.transcript.is_empty());
    }

    fn acknowledged_clear() -> (Scenario, SessionProjection) {
        let mut s = Scenario::new();
        let mut initial = projection(ProjectionReason::Initial);
        initial.binding.session_id = "session-01J8ZK4QX2M7C9RT5VWEHN3B6D".into();
        assert!(apply_session_projection(initial, &mut s, 1));
        let operation = s.new_manual_operation(ManualAction::Clear).unwrap();
        assert!(s.admit_manual(operation.clone()));
        let mut cleared = projection(ProjectionReason::Manual {
            operation,
            outcome: ManualOutcome::Completed,
            applied: true,
        });
        cleared.binding = SessionBinding {
            session_id: "session-01J8ZK4QX2M7C9RT5VWEHN3B6E".into(),
            generation: 2,
        };
        cleared.lines.clear();
        cleared.turns = 0;
        cleared.input_tokens = 0;
        cleared.output_tokens = 0;
        cleared.cost_microcents = 0;
        cleared.cost = CostQualification::Known { revision: 0 };
        assert!(apply_session_projection(cleared.clone(), &mut s, 2));
        assert_eq!(
            s.cleared_from.as_deref(),
            Some("session-01J8ZK4QX2M7C9RT5VWEHN3B6D")
        );
        (s, cleared)
    }

    #[test]
    fn clear_acknowledgement_follows_valid_admission_only() {
        for kind in [
            ForegroundKind::Prompt,
            ForegroundKind::PlanPrompt,
            ForegroundKind::Control,
        ] {
            let (mut s, _) = acknowledged_clear();
            let source = s.cleared_from.clone();
            let rejected = ForegroundOperation::new(
                SessionBinding {
                    session_id: "session-wrong".into(),
                    generation: 2,
                },
                kind,
                99,
            )
            .unwrap();
            let before = format!("{s:?}");
            assert!(!s.admit_foreground(rejected));
            assert_eq!(format!("{s:?}"), before);
            let operation = s.new_foreground_operation(kind).unwrap();
            assert!(s.admit_foreground(operation));
            assert_eq!(
                s.cleared_from,
                if kind.is_ordinary() { None } else { source }
            );
        }
        for action in [ManualAction::Compact, ManualAction::Clear] {
            let (mut s, _) = acknowledged_clear();
            let rejected = crate::worker::ManualOperation::new(
                SessionBinding {
                    session_id: "session-wrong".into(),
                    generation: 2,
                },
                action,
                99,
            )
            .unwrap();
            let before = format!("{s:?}");
            assert!(!s.admit_manual(rejected));
            assert_eq!(format!("{s:?}"), before);
            let operation = s.new_manual_operation(action).unwrap();
            assert!(s.admit_manual(operation));
            assert!(s.cleared_from.is_none());
        }
    }

    #[test]
    fn clear_acknowledgement_resets_on_round_restore_and_real_identity_change() {
        let (mut s, _) = acknowledged_clear();
        let source = s.cleared_from.clone();
        let identity = |session_id: String| crate::msg::Msg::Identity {
            model: "model".into(),
            provider: "provider".into(),
            session_prefix: "prefix".into(),
            session_id,
            priced: true,
        };
        apply_msg(identity(s.session_id.clone()), &mut s, 3);
        assert_eq!(s.cleared_from, source);
        apply_msg(identity("session-another".into()), &mut s, 4);
        assert!(s.cleared_from.is_none());
        let (mut s, _) = acknowledged_clear();
        s.apply("round_started", 5);
        assert!(s.cleared_from.is_none());
        let (mut s, _) = acknowledged_clear();
        apply_msg(
            crate::msg::Msg::TranscriptLoaded {
                lines: vec![],
                input_tokens: 0,
                output_tokens: 0,
                cost_microcents: 0,
                turns: 0,
            },
            &mut s,
            6,
        );
        assert!(s.cleared_from.is_none());
        let (mut s, mut next) = acknowledged_clear();
        next.reason = ProjectionReason::Resume {
            previous: s.session_binding().unwrap().clone(),
        };
        next.binding.session_id = "session-resumed".into();
        next.binding.generation = 3;
        assert!(apply_session_projection(next, &mut s, 7));
        assert!(s.cleared_from.is_none() && s.transcript.is_empty());
    }

    #[test]
    fn clear_acknowledgement_requires_completed_applied_result() {
        for outcome in [
            ManualOutcome::Completed,
            ManualOutcome::Failed,
            ManualOutcome::Cancelled,
            ManualOutcome::Unknown,
        ] {
            for applied in [false, true] {
                let mut s = Scenario::new();
                establish(&mut s);
                let operation = s.new_manual_operation(ManualAction::Clear).unwrap();
                assert!(s.admit_manual(operation.clone()));
                let mut result = projection(ProjectionReason::Manual {
                    operation,
                    outcome,
                    applied,
                });
                let successful = outcome == ManualOutcome::Completed && applied;
                if successful {
                    result.binding.session_id = "session-next".into();
                    result.binding.generation = 2;
                    result.lines.clear();
                    result.turns = 0;
                }
                let before = format!("{s:?}");
                assert_eq!(
                    apply_session_projection(result, &mut s, 3),
                    !applied || successful
                );
                assert_eq!(
                    s.cleared_from.as_deref(),
                    successful.then_some("session-bound-test")
                );
                if applied && !successful {
                    assert_eq!(format!("{s:?}"), before);
                }
            }
        }
        let mut s = Scenario::new();
        establish(&mut s);
        let operation = s.new_manual_operation(ManualAction::Compact).unwrap();
        assert!(s.admit_manual(operation.clone()));
        assert!(apply_session_projection(
            projection(ProjectionReason::Manual {
                operation,
                outcome: ManualOutcome::Completed,
                applied: true,
            }),
            &mut s,
            3
        ));
        assert!(s.cleared_from.is_none());
    }

    #[test]
    fn rejected_clear_acknowledgements_are_atomic_and_replay_safe() {
        let (mut s, replay) = acknowledged_clear();
        let mut refresh = replay.clone();
        refresh.reason = ProjectionReason::Refresh;
        refresh.cost = CostQualification::Known { revision: 7 };
        assert!(apply_session_projection(refresh.clone(), &mut s, 3));
        let mut stale = refresh;
        stale.cost = CostQualification::Known { revision: 6 };
        for rejected in [stale, replay.clone()] {
            s.take_view_dirty();
            let before = format!("{s:?}");
            let frame = failure_test_frame(&s, 110, 30, 0);
            assert!(!apply_session_projection(rejected, &mut s, 4));
            assert_eq!(format!("{s:?}"), before);
            assert!(!s.take_view_dirty());
            assert_eq!(failure_test_frame(&s, 110, 30, 0), frame);
        }
        let operation = s.new_manual_operation(ManualAction::Clear).unwrap();
        assert!(s.admit_manual(operation.clone()));
        let mut next = replay;
        next.reason = ProjectionReason::Manual {
            operation: operation.clone(),
            outcome: ManualOutcome::Completed,
            applied: true,
        };
        next.binding.session_id = "session-third".into();
        next.binding.generation = 3;
        let mut wrong_owner = next.clone();
        wrong_owner.reason = ProjectionReason::Manual {
            operation: crate::worker::ManualOperation::new(
                operation.source().clone(),
                ManualAction::Clear,
                operation.id(),
            )
            .unwrap(),
            outcome: ManualOutcome::Completed,
            applied: true,
        };
        let mut wrong_generation = next.clone();
        wrong_generation.binding.generation = 4;
        let mut invalid_id = next.clone();
        invalid_id.binding.session_id = "bad\u{1b}id".into();
        let mut invalid_context = next.clone();
        invalid_context.context = ContextProjection::PreserveMeasured;
        for rejected in [wrong_owner, wrong_generation, invalid_id, invalid_context] {
            s.take_view_dirty();
            let before = format!("{s:?}");
            assert!(!apply_session_projection(rejected, &mut s, 5));
            assert_eq!(format!("{s:?}"), before);
            assert!(!s.take_view_dirty());
        }
        let source = s.session_id.clone();
        assert!(apply_session_projection(next, &mut s, 6));
        assert_eq!(s.cleared_from.as_ref(), Some(&source));
        assert!(s.transcript.is_empty() && !s.is_busy());
    }

    #[test]
    fn failed_bound_turn_survives_checked_terminal_before_first_draw() {
        for command in [
            WorkerCommand::Prompt("prompt".into()),
            WorkerCommand::PlanPrompt("plan".into()),
        ] {
            let (mut s, operation, registration) = active_ordinary_operation(command);
            s.apply("round_started", 0);
            s.turn_started_ms = 1_000;
            apply_msg(
                crate::msg::Msg::BackendError("ERR_TERMINAL".into()),
                &mut s,
                2_000,
            );
            assert!(s.last_failed && s.is_busy());
            assert_eq!(s.pending_foreground(), Some(&operation));
            apply_msg(
                crate::msg::Msg::ResponseFinished {
                    output: String::new(),
                    input_tokens: 110,
                    output_tokens: 220,
                    cost_microcents: 330,
                },
                &mut s,
                3_000,
            );
            assert!(s.is_busy());
            assert_eq!(
                (s.turns, s.input_tokens, s.output_tokens, s.cost_microcents),
                (2, 10, 20, 30)
            );
            let mut terminal = projection(ProjectionReason::Operation {
                operation: operation.clone(),
            });
            terminal.turns = 3;
            terminal.input_tokens = 110;
            terminal.output_tokens = 220;
            terminal.cost_microcents = 330;
            terminal.cost = CostQualification::Known { revision: 5 };
            drop(registration);
            assert!(apply_session_projection(terminal, &mut s, 4_000));
            assert!(!s.is_busy() && s.pending_foreground().is_none());
            assert_eq!(
                (s.turns, s.input_tokens, s.output_tokens, s.cost_microcents),
                (3, 110, 220, 330)
            );
            assert_eq!(s.session_binding(), Some(&binding()));
            assert_eq!(
                s.cost_qualification(),
                CostQualification::Known { revision: 5 }
            );
            assert_eq!(s.qualified_revision_floor(), Some(5));
            let report = s.turn_report.as_ref().unwrap();
            assert!(!report.priced && report.cost_microcents == 0);
            assert_eq!(report.duration_ms, 2_000);
            let frame = failure_test_frame(&s, 110, 30, 0);
            assert!(
                frame.contains("ERR_TERMINAL"),
                "settled failure reason disappeared before first draw:\n{frame}"
            );
            assert!(s.last_failed);
            assert_eq!(s.activity(), super::super::scenario::Activity::Failed);
            let header = frame
                .lines()
                .skip(1)
                .find(|line| {
                    line.trim_start().starts_with('┃')
                        && line.trim_start_matches([' ', '┃']).starts_with("2 ")
                        && line.contains("Conversation")
                })
                .unwrap();
            assert!(
                header.contains("failed") && !header.contains("done"),
                "{frame}"
            );
            assert!(frame.contains("✕ failed · 2s · 0 tools"), "{frame}");
            assert!(!frame.contains("✓ done ·"), "{frame}");
            assert!(frame.lines().last().unwrap().contains("failed"), "{frame}");
        }
    }

    fn settled_failure(reason: &str) -> (Scenario, SessionProjection) {
        let (mut s, operation, registration) =
            active_ordinary_operation(WorkerCommand::Prompt("prompt".into()));
        s.apply("round_started", 0);
        s.first_prompt_waiting = true;
        apply_msg(crate::msg::Msg::BackendError(reason.into()), &mut s, 2);
        apply_msg(
            crate::msg::Msg::OrdinaryTurnEnded {
                operation: operation.clone(),
                end: crate::msg::OrdinaryEnd::Failed(reason.into()),
                publication: crate::msg::OrdinaryPublication::Saved,
            },
            &mut s,
            2,
        );
        assert!(!s.first_prompt_waiting && s.is_busy());
        apply_msg(
            crate::msg::Msg::ResponseFinished {
                output: String::new(),
                input_tokens: 10,
                output_tokens: 20,
                cost_microcents: 30,
            },
            &mut s,
            3,
        );
        let terminal = projection(ProjectionReason::Operation { operation });
        drop(registration);
        assert!(apply_session_projection(terminal.clone(), &mut s, 4));
        assert!(s.take_view_dirty());
        (s, terminal)
    }

    #[test]
    fn failed_reason_survives_same_session_refresh_and_manual_no_change() {
        let (mut s, terminal) = settled_failure("ERR_PRESERVED");
        let history = s.transcript.clone();
        let report = s.turn_report.clone();
        let mut refresh = terminal.clone();
        refresh.reason = ProjectionReason::Refresh;
        assert!(apply_session_projection(refresh, &mut s, 5));
        assert_eq!(s.failure_reason.as_deref(), Some("ERR_PRESERVED"));
        assert_eq!(s.turn_report, report);
        let operation = s.new_manual_operation(ManualAction::Compact).unwrap();
        assert!(s.admit_manual(operation.clone()));
        let mut unchanged = terminal;
        unchanged.reason = ProjectionReason::Manual {
            operation,
            outcome: ManualOutcome::Failed,
            applied: false,
        };
        assert!(apply_session_projection(unchanged, &mut s, 6));
        assert_eq!(s.transcript, history);
        assert_eq!(s.failure_reason.as_deref(), Some("ERR_PRESERVED"));
        assert_eq!(s.turn_report, report);
        assert!(s.last_failed && !s.is_busy());
        assert!(failure_test_frame(&s, 110, 30, 0).contains("ERR_PRESERVED"));
    }

    #[test]
    fn repeated_failure_replaces_one_visible_group_and_requests_redraw() {
        let (mut s, _) = settled_failure("ERR_ALPHA");
        let history = s.transcript.clone();
        let report = s.turn_report.clone();
        for reason in ["ERR_ALPHA", "ERR_BRAVO"] {
            s.take_view_dirty();
            apply_msg(crate::msg::Msg::BackendError(reason.into()), &mut s, 5);
            assert!(s.take_view_dirty());
            assert_eq!(s.transcript, history);
            assert_eq!(s.turn_report, report);
            let frame = failure_test_frame(&s, 110, 30, 0);
            assert_eq!(frame.matches("This turn failed").count(), 1, "{frame}");
            assert_eq!(
                frame.matches("empty composer resends it").count(),
                1,
                "{frame}"
            );
            assert!(frame.contains(reason), "{frame}");
            if reason == "ERR_BRAVO" {
                assert!(!frame.contains("ERR_ALPHA"), "{frame}");
            }
        }
    }

    #[test]
    fn rejected_failure_projections_have_no_view_or_accounting_effect() {
        let (mut s, terminal) = settled_failure("ERR_RETAINED");
        let mut wrong_binding = terminal.clone();
        wrong_binding.reason = ProjectionReason::Refresh;
        wrong_binding.binding.session_id = "session-wrong".into();
        let mut stale = terminal.clone();
        stale.reason = ProjectionReason::Refresh;
        stale.cost = CostQualification::Known { revision: 2 };
        let (_, wrong_operation, registration) =
            active_ordinary_operation(WorkerCommand::Prompt("other".into()));
        drop(registration);
        let mut wrong_owner = terminal.clone();
        wrong_owner.reason = ProjectionReason::Operation {
            operation: wrong_operation,
        };
        let mut rejected_switch = terminal.clone();
        rejected_switch.reason = ProjectionReason::Resume {
            previous: binding(),
        };
        rejected_switch.binding.session_id = "session-next".into();
        rejected_switch.binding.generation = 3;
        for rejected in [wrong_binding, stale, wrong_owner, rejected_switch, terminal] {
            s.take_view_dirty();
            let before = format!("{s:?}");
            let frame = failure_test_frame(&s, 110, 30, 0);
            assert!(!apply_session_projection(rejected, &mut s, 6));
            assert_eq!(format!("{s:?}"), before);
            assert!(!s.take_view_dirty());
            assert_eq!(failure_test_frame(&s, 110, 30, 0), frame);
        }
    }

    #[test]
    fn new_round_and_real_identity_changes_clear_failure_presentation() {
        let (mut s, _) = settled_failure("ERR_OLD");
        s.apply("round_started", 0);
        assert!(!s.last_failed && s.failure_reason.is_none() && s.turn_report.is_none());
        assert!(!failure_test_frame(&s, 110, 30, 0).contains("ERR_OLD"));
        let (mut s, _) = settled_failure("ERR_OLD");
        for session_id in [binding().session_id, "session-new".into()] {
            let same = s.session_id == session_id;
            apply_msg(
                crate::msg::Msg::Identity {
                    model: "model".into(),
                    provider: "provider".into(),
                    session_prefix: "prefix".into(),
                    session_id,
                    priced: true,
                },
                &mut s,
                8,
            );
            if same {
                assert_eq!(s.failure_reason.as_deref(), Some("ERR_OLD"));
            } else {
                assert!(!s.last_failed && s.failure_reason.is_none() && s.turn_report.is_none());
            }
        }
        let (mut s, _) = settled_failure("ERR_OLD");
        s.first_prompt_waiting = true;
        apply_msg(
            crate::msg::Msg::TranscriptLoaded {
                lines: vec![],
                turns: 0,
                input_tokens: 0,
                output_tokens: 0,
                cost_microcents: 0,
            },
            &mut s,
            9,
        );
        assert!(
            !s.last_failed
                && !s.first_prompt_waiting
                && s.failure_reason.is_none()
                && s.turn_report.is_none()
        );
    }

    #[test]
    fn accepted_clear_and_resume_drop_only_the_old_failure_view() {
        for clear in [false, true] {
            let (mut s, terminal) = settled_failure("ERR_OLD_SESSION");
            let reason = if clear {
                let operation = s.new_manual_operation(ManualAction::Clear).unwrap();
                assert!(s.admit_manual(operation.clone()));
                ProjectionReason::Manual {
                    operation,
                    outcome: ManualOutcome::Completed,
                    applied: true,
                }
            } else {
                ProjectionReason::Resume {
                    previous: binding(),
                }
            };
            let mut next = projection(reason);
            next.binding = SessionBinding {
                session_id: "session-next".into(),
                generation: 2,
            };
            next.lines = vec![crate::model::TranscriptLine::User {
                text: "new namespace".into(),
                time: None,
            }];
            next.turns = 0;
            assert!(apply_session_projection(next, &mut s, 10));
            assert!(!s.last_failed && s.failure_reason.is_none() && s.turn_report.is_none());
            assert_eq!(s.session_id, "session-next");
            assert!(failure_test_frame(&s, 110, 30, 0).contains("new namespace"));
            assert!(!failure_test_frame(&s, 110, 30, 0).contains("ERR_OLD_SESSION"));
            s.take_view_dirty();
            let before = format!("{s:?}");
            assert!(!apply_session_projection(terminal, &mut s, 11));
            assert_eq!(format!("{s:?}"), before);
            assert!(!s.take_view_dirty());
        }
    }

    #[test]
    fn empty_history_failure_stops_welcome_and_displays_safe_reason() {
        let mut s = Scenario::new();
        s.first_prompt_waiting = true;
        apply_msg(
            crate::msg::Msg::BackendError("\u{1b}[31mERR_EMPTY\u{1b}[0m".into()),
            &mut s,
            1,
        );
        assert!(!s.first_prompt_waiting && s.last_failed);
        assert_eq!(s.failure_reason.as_deref(), Some("ERR_EMPTY"));
        let frame = failure_test_frame(&s, 40, 24, 0);
        assert!(
            frame.contains("ERR_EMPTY") && frame.contains("Ask ORBIT"),
            "{frame}"
        );
        assert!(!frame.contains('\u{1b}'), "{frame}");
        assert!(!frame.contains("the harness that orbits"), "{frame}");
    }

    #[test]
    fn actual_finish_and_error_keep_bound_prompt_and_plan_ownership_until_checked_terminal() {
        for command in [
            WorkerCommand::Prompt("prompt".into()),
            WorkerCommand::PlanPrompt("plan".into()),
        ] {
            let mut s = Scenario::new();
            establish(&mut s);
            let (sink, receiver) = std::sync::mpsc::channel();
            submit_foreground(&mut s, &sink, command).unwrap();
            let WorkerCommand::Bound { operation, command } = receiver.recv().unwrap() else {
                panic!("bound admission")
            };
            let registration = operation.start(&command).unwrap();
            s.turn_live = true;
            apply_msg(
                crate::msg::Msg::BackendError("snapshot unavailable".into()),
                &mut s,
                2,
            );
            assert!(!s.turn_live && s.is_busy());
            assert_eq!(s.pending_foreground(), Some(&operation));
            assert!(s.new_manual_operation(ManualAction::Compact).is_err());
            apply_msg(
                crate::msg::Msg::ResponseFinished {
                    output: String::new(),
                    input_tokens: 110,
                    output_tokens: 220,
                    cost_microcents: 330,
                },
                &mut s,
                3,
            );
            assert_eq!(
                (s.turns, s.input_tokens, s.output_tokens, s.cost_microcents),
                (2, 10, 20, 30)
            );
            assert_eq!(s.cost_qualification(), CostQualification::Unavailable);
            assert_eq!(s.qualified_revision_floor(), Some(3));
            assert!(s.is_busy() && s.new_manual_operation(ManualAction::Clear).is_err());
            assert!(!s.turn_report.as_ref().unwrap().priced);
            assert_eq!(s.turn_report.as_ref().unwrap().cost_microcents, 0);
            let mut terminal = projection(ProjectionReason::Operation {
                operation: operation.clone(),
            });
            terminal.turns = 3;
            terminal.input_tokens = 110;
            terminal.output_tokens = 220;
            terminal.cost_microcents = 330;
            terminal.cost = CostQualification::Known { revision: 5 };
            drop(registration);
            assert!(apply_session_projection(terminal.clone(), &mut s, 4));
            assert_eq!(
                (s.turns, s.input_tokens, s.output_tokens, s.cost_microcents),
                (3, 110, 220, 330)
            );
            assert!(!s.is_busy() && s.pending_foreground().is_none());
            assert!(s.take_view_dirty());
            assert!(!apply_session_projection(terminal, &mut s, 5));
            assert!(!s.take_view_dirty());
        }
    }

    #[test]
    fn startup_and_control_admission_cannot_queue_a_stale_manual_source() {
        let (sink, receiver) = std::sync::mpsc::channel();
        let mut s = Scenario::new();
        assert!(submit_foreground(&mut s, &sink, WorkerCommand::Prompt("early".into())).is_err());
        assert!(receiver.try_recv().is_err());
        establish(&mut s);
        for command in [
            WorkerCommand::Undo,
            WorkerCommand::ResumeSession("session-target".into()),
        ] {
            let is_resume = matches!(&command, WorkerCommand::ResumeSession(_));
            submit_foreground(&mut s, &sink, command).unwrap();
            let WorkerCommand::Bound { operation, command } = receiver.recv().unwrap() else {
                panic!("bound control")
            };
            let registration = operation.start(&command).unwrap();
            assert!(s.new_manual_operation(ManualAction::Compact).is_err());
            assert!(
                submit_foreground(&mut s, &sink, WorkerCommand::Prompt("racing".into())).is_err()
            );
            let mut terminal = projection(ProjectionReason::Operation { operation });
            terminal.turns = 1;
            if is_resume {
                terminal.binding = SessionBinding {
                    session_id: "session-target".into(),
                    generation: 2,
                };
                terminal.cost = CostQualification::Known { revision: 0 };
            }
            drop(registration);
            assert!(apply_session_projection(terminal, &mut s, 10));
            assert_eq!(s.turns, 1);
            assert!(!s.is_busy());
        }
    }

    #[test]
    fn ordinary_checked_terminal_preserves_local_queued_drafts_for_promotion() {
        let mut s = Scenario::new();
        establish(&mut s);
        let (sink, receiver) = std::sync::mpsc::channel();
        submit_foreground(&mut s, &sink, WorkerCommand::Prompt("active".into())).unwrap();
        let WorkerCommand::Bound { operation, command } = receiver.recv().unwrap() else {
            panic!("bound prompt")
        };
        let registration = operation.start(&command).unwrap();
        for text in ["next", "later"] {
            s.transcript.push(TranscriptLine {
                kind: LineKind::Queued,
                text: text.into(),
                ..Default::default()
            });
        }
        drop(registration);
        assert!(apply_session_projection(
            projection(ProjectionReason::Operation { operation }),
            &mut s,
            2
        ));
        assert_eq!(
            s.transcript
                .iter()
                .filter(|line| line.kind == LineKind::Queued)
                .map(|line| line.text.as_str())
                .collect::<Vec<_>>(),
            ["next", "later"]
        );
        submit_foreground(&mut s, &sink, WorkerCommand::Prompt("next".into())).unwrap();
        assert!(s.ordinary_pending() && s.is_busy());
    }

    struct Host(ResolvedProfile);
    impl ProfileHost for Host {
        fn load(&self) -> Result<ResolvedProfile, CustomizationError> {
            Ok(self.0.clone())
        }
        fn replace(&self, _: Profile, _: &str) -> Result<ResolvedProfile, CustomizationError> {
            Err(CustomizationError::Busy)
        }
        fn reset(&self, _: &str) -> Result<ResolvedProfile, CustomizationError> {
            Err(CustomizationError::Busy)
        }
        fn read_pane(
            &self,
            id: &str,
            context: &PaneContext,
        ) -> Result<PaneOutput, CustomizationError> {
            Ok(PaneOutput {
                id: id.into(),
                title: "Usage".into(),
                state: PaneState::Ready,
                text: format!("input {}", context.input_tokens),
                truncated: false,
                actions: vec![PaneAction::Refresh],
            })
        }
    }

    fn customized_tui() -> Tui {
        let mut profile = Profile::default();
        profile.panes.push(PaneDef {
            id: "usage".into(),
            title: "Usage".into(),
            surfaces: vec![Surface::Terminal],
            source: PaneSource::Snapshot {
                snapshot: SnapshotKind::Usage,
            },
            actions: vec![PaneAction::Refresh],
        });
        let host = Arc::new(Host(ResolvedProfile {
            profile,
            revision: "fixture".into(),
            sources: BTreeMap::new(),
            capabilities: CustomizationCapabilities::default(),
        }));
        let mut tui = Tui::new();
        tui.reduced = true;
        tui.customization = Some(crate::customization::CustomizationSession::open(host).unwrap());
        tui
    }

    #[test]
    fn reduced_motion_wrapper_invalidates_only_accepted_projection_and_rejects_duplicate_terminal()
    {
        let mut s = Scenario::new();
        let mut tui = customized_tui();
        reduce_frontend_message(
            crate::msg::Msg::SessionProjection(projection(ProjectionReason::Initial)),
            &mut tui,
            &mut s,
            1,
        );
        assert!(s.take_view_dirty());
        tui.customization
            .as_mut()
            .unwrap()
            .refresh("usage")
            .unwrap();
        let operation = s.new_foreground_operation(ForegroundKind::Control).unwrap();
        assert!(s.admit_foreground(operation.clone()));
        assert!(s.take_view_dirty());
        let wrong = ForegroundOperation::new(binding(), ForegroundKind::Control, 99).unwrap();
        for rejected in [
            projection(ProjectionReason::Refresh),
            projection(ProjectionReason::Operation { operation: wrong }),
        ] {
            let before = format!("{s:?}");
            let context = tui.customization.as_ref().unwrap().context.clone();
            let outputs = tui.customization.as_ref().unwrap().outputs.clone();
            reduce_frontend_message(
                crate::msg::Msg::SessionProjection(rejected),
                &mut tui,
                &mut s,
                2,
            );
            assert_eq!(format!("{s:?}"), before);
            assert!(!s.take_view_dirty());
            assert_eq!(tui.customization.as_ref().unwrap().context, context);
            assert_eq!(tui.customization.as_ref().unwrap().outputs, outputs);
        }
        let mut terminal = projection(ProjectionReason::Operation { operation });
        terminal.input_tokens = 55;
        terminal.cost = CostQualification::Known { revision: 4 };
        reduce_frontend_message(
            crate::msg::Msg::SessionProjection(terminal.clone()),
            &mut tui,
            &mut s,
            3,
        );
        assert!(tui.reduced && s.take_view_dirty());
        assert_eq!(tui.customization.as_ref().unwrap().context.input_tokens, 55);
        assert_eq!(s.custom_panes["usage"].state, PaneState::Stale);
        tui.customization
            .as_mut()
            .unwrap()
            .refresh("usage")
            .unwrap();
        s.custom_panes = tui.customization.as_ref().unwrap().outputs.clone();
        let before = format!("{s:?}");
        let context = tui.customization.as_ref().unwrap().context.clone();
        let outputs = tui.customization.as_ref().unwrap().outputs.clone();
        reduce_frontend_message(
            crate::msg::Msg::SessionProjection(terminal),
            &mut tui,
            &mut s,
            4,
        );
        assert!(!s.take_view_dirty());
        assert_eq!(format!("{s:?}"), before);
        assert_eq!(tui.customization.as_ref().unwrap().context, context);
        assert_eq!(tui.customization.as_ref().unwrap().outputs, outputs);
        let mut stale = projection(ProjectionReason::Refresh);
        stale.cost = CostQualification::Known { revision: 3 };
        reduce_frontend_message(
            crate::msg::Msg::SessionProjection(stale),
            &mut tui,
            &mut s,
            5,
        );
        assert!(!s.take_view_dirty());
        assert_eq!(format!("{s:?}"), before);
        assert_eq!(tui.customization.as_ref().unwrap().outputs, outputs);
    }

    #[test]
    fn foreground_ticket_refuses_wrong_kind_nested_wrapping_and_reuse() {
        let operation = ForegroundOperation::new(binding(), ForegroundKind::Control, 1).unwrap();
        assert!(
            operation
                .start(&WorkerCommand::Prompt("wrong".into()))
                .is_err()
        );
        assert!(
            operation
                .start(&WorkerCommand::Bound {
                    operation: operation.clone(),
                    command: Box::new(WorkerCommand::Undo)
                })
                .is_err()
        );
        let registration = operation.start(&WorkerCommand::Undo).unwrap();
        assert!(operation.start(&WorkerCommand::Undo).is_err());
        drop(registration);
        assert!(operation.start(&WorkerCommand::Undo).is_err());
    }

    #[test]
    fn legacy_finish_uses_checked_deltas_and_preserves_entire_prefix_on_overflow() {
        let mut s = Scenario::new();
        s.turns = u64::MAX;
        s.input_tokens = 7;
        s.output_tokens = 8;
        s.cost_microcents = 9;
        s.turn_tools = 1;
        apply_msg(
            crate::msg::Msg::ResponseFinished {
                output: String::new(),
                input_tokens: 1,
                output_tokens: 2,
                cost_microcents: 3,
            },
            &mut s,
            1,
        );
        assert_eq!(
            (s.turns, s.input_tokens, s.output_tokens, s.cost_microcents),
            (u64::MAX, 7, 8, 9)
        );
        assert_eq!(s.cost_qualification(), CostQualification::Unavailable);
        assert_eq!(s.state_version(), u64::MAX);
        let mut normal = Scenario::new();
        normal.turns = 2;
        normal.input_tokens = 7;
        normal.output_tokens = 8;
        normal.cost_microcents = 9;
        apply_msg(
            crate::msg::Msg::ResponseFinished {
                output: String::new(),
                input_tokens: 1,
                output_tokens: 2,
                cost_microcents: 3,
            },
            &mut normal,
            1,
        );
        assert_eq!(
            (
                normal.turns,
                normal.input_tokens,
                normal.output_tokens,
                normal.cost_microcents
            ),
            (3, 8, 10, 12)
        );
    }

    fn finish_owned_view(
        s: &mut Scenario,
        operation: ForegroundOperation,
        registration: crate::worker::ForegroundRegistration,
        end: crate::msg::OrdinaryEnd,
        publication: crate::msg::OrdinaryPublication,
    ) {
        apply_msg(
            crate::msg::Msg::OrdinaryTurnEnded {
                operation: operation.clone(),
                end,
                publication,
            },
            s,
            2,
        );
        assert!(s.is_busy() && s.pending_foreground() == Some(&operation));
        apply_msg(
            crate::msg::Msg::ResponseFinished {
                output: String::new(),
                input_tokens: 10,
                output_tokens: 20,
                cost_microcents: 30,
            },
            s,
            3,
        );
        drop(registration);
        assert!(apply_session_projection(
            projection(ProjectionReason::Operation { operation }),
            s,
            4
        ));
        assert!(!s.is_busy());
    }

    fn press_enter_in_context(
        s: &mut Scenario,
        sink: &CommandSink,
        tui: &mut Tui,
        composer: &mut String,
        overlay: &mut Option<Overlay>,
        queued: &mut Vec<String>,
    ) {
        let (_, sender) = Bus::new();
        assert!(!handle_key(
            crossterm::event::KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE),
            tui,
            s,
            composer,
            None,
            sink,
            &sender,
            &ApprovalRegistry::new(),
            5000,
            overlay,
            &mut String::new(),
            &mut 0,
            &mut 0,
            &mut None,
            queued,
            &mut Vec::new(),
            &mut None,
            &mut None,
            &mut false,
            &mut false
        ));
    }

    fn press_empty_enter(s: &mut Scenario, sink: &CommandSink) {
        let mut tui = Tui::new();
        assert_eq!(tui.focus, Focus::Conversation);
        let mut composer = String::new();
        assert!(!s.is_busy() && composer.is_empty());
        press_enter_in_context(s, sink, &mut tui, &mut composer, &mut None, &mut Vec::new());
    }

    #[test]
    fn ordinary_intent_admission_preserves_original_variants_and_failed_send() {
        use crate::msg::{OrdinaryEnd, OrdinaryPublication};
        for command in [
            WorkerCommand::Prompt("p".into()),
            WorkerCommand::PlanPrompt("p".into()),
            WorkerCommand::ModCommand("m".into(), "c".into()),
        ] {
            let original = OrdinaryIntent::from_command(&command).unwrap();
            let (mut s, operation, registration) = active_ordinary_operation(command);
            s.apply("round_started", 0);
            assert!(!s.can_resend_ordinary());
            finish_owned_view(
                &mut s,
                operation,
                registration,
                OrdinaryEnd::Failed("failed".into()),
                OrdinaryPublication::Saved,
            );
            assert_eq!(s.eligible_ordinary_intent(), Some(&original));
            let (failed, receiver) = std::sync::mpsc::channel();
            drop(receiver);
            assert!(
                submit_foreground(&mut s, &failed, WorkerCommand::Prompt("new".into())).is_err()
            );
            assert_eq!(s.eligible_ordinary_intent(), Some(&original));
            assert!(
                !format!("{:?}", OrdinaryIntent::Prompt("private-prompt".into()))
                    .contains("private-prompt")
            );
        }
    }

    #[test]
    fn queued_ordinary_admission_replaces_resend_intent_before_round_started() {
        use crate::msg::{OrdinaryEnd, OrdinaryPublication};
        let (mut s, operation, registration) =
            active_ordinary_operation(WorkerCommand::Prompt("A".into()));
        finish_owned_view(
            &mut s,
            operation,
            registration,
            OrdinaryEnd::Failed("A failed".into()),
            OrdinaryPublication::Saved,
        );
        s.transcript.push(TranscriptLine {
            kind: LineKind::Queued,
            text: "B".into(),
            ..Default::default()
        });
        assert_eq!(
            s.eligible_ordinary_intent(),
            Some(&OrdinaryIntent::Prompt("A".into()))
        );
        let (sink, receiver) = std::sync::mpsc::channel();
        submit_foreground(&mut s, &sink, WorkerCommand::Prompt("B".into())).unwrap();
        let WorkerCommand::Bound { operation, command } = receiver.recv().unwrap() else {
            panic!("bound B");
        };
        let registration = operation.start(&command).unwrap();
        s.apply("round_started", 0);
        finish_owned_view(
            &mut s,
            operation,
            registration,
            OrdinaryEnd::Failed("B failed".into()),
            OrdinaryPublication::Saved,
        );
        assert_eq!(
            s.eligible_ordinary_intent(),
            Some(&OrdinaryIntent::Prompt("B".into()))
        );
    }

    #[test]
    fn ordinary_terminal_result_requires_exact_live_owner_and_binding() {
        use crate::msg::{OrdinaryEnd, OrdinaryPublication};
        let (mut s, operation, registration) =
            active_ordinary_operation(WorkerCommand::Prompt("p".into()));
        let mut foreign_binding = operation.source().clone();
        foreign_binding.generation += 1;
        for rejected in [
            ForegroundOperation::new(operation.source().clone(), operation.kind(), operation.id())
                .unwrap(),
            ForegroundOperation::new(foreign_binding, operation.kind(), operation.id()).unwrap(),
            ForegroundOperation::new(
                operation.source().clone(),
                ForegroundKind::Control,
                operation.id(),
            )
            .unwrap(),
        ] {
            s.take_view_dirty();
            let before = format!("{s:?}");
            apply_msg(
                crate::msg::Msg::OrdinaryTurnEnded {
                    operation: rejected,
                    end: OrdinaryEnd::Failed("bad".into()),
                    publication: OrdinaryPublication::Saved,
                },
                &mut s,
                2,
            );
            assert_eq!(format!("{s:?}"), before);
            assert!(!s.take_view_dirty());
        }
        let terminal = crate::msg::Msg::OrdinaryTurnEnded {
            operation: operation.clone(),
            end: OrdinaryEnd::Completed,
            publication: OrdinaryPublication::Saved,
        };
        apply_msg(terminal.clone(), &mut s, 2);
        s.take_view_dirty();
        let before = format!("{s:?}");
        apply_msg(terminal.clone(), &mut s, 3);
        assert_eq!(format!("{s:?}"), before);
        assert!(!s.take_view_dirty());
        apply_msg(
            crate::msg::Msg::ResponseFinished {
                output: String::new(),
                input_tokens: 10,
                output_tokens: 20,
                cost_microcents: 30,
            },
            &mut s,
            4,
        );
        drop(registration);
        assert!(apply_session_projection(
            projection(ProjectionReason::Operation { operation }),
            &mut s,
            5
        ));
        s.take_view_dirty();
        let before = format!("{s:?}");
        apply_msg(terminal, &mut s, 6);
        assert_eq!(format!("{s:?}"), before);
        assert!(!s.take_view_dirty());
    }

    #[test]
    fn ordinary_failed_saved_result_enables_only_guarded_fresh_resend() {
        use crate::msg::{OrdinaryEnd, OrdinaryPublication};
        for command in [
            WorkerCommand::Prompt("p".into()),
            WorkerCommand::PlanPrompt("p".into()),
            WorkerCommand::ModCommand("m".into(), "c".into()),
        ] {
            let expected = OrdinaryIntent::from_command(&command).unwrap();
            let (mut s, operation, registration) = active_ordinary_operation(command);
            apply_msg(
                crate::msg::Msg::BackendError("callback only".into()),
                &mut s,
                1,
            );
            assert!(!s.can_resend_ordinary());
            let previous = operation.clone();
            finish_owned_view(
                &mut s,
                operation,
                registration,
                OrdinaryEnd::Failed("failed".into()),
                OrdinaryPublication::Saved,
            );
            let (sink, receiver) = std::sync::mpsc::channel();
            assert!(receiver.try_recv().is_err());
            assert!(failure_test_frame(&s, 110, 30, 0).contains("empty composer resends it"));
            press_empty_enter(&mut s, &sink);
            let WorkerCommand::Bound { operation, command } = receiver.try_recv().unwrap() else {
                panic!("fresh ordinary resend");
            };
            assert_ne!(operation, previous);
            assert_eq!(operation.source(), previous.source());
            assert_eq!(OrdinaryIntent::from_command(&command), Some(expected));
            assert!(receiver.try_recv().is_err());
            assert!(s.is_busy() && !s.can_resend_ordinary());
        }

        // An eligible record cannot bypass the actual focus or modal key owner.
        for (focus, initial_overlay) in [
            (Focus::Workspace, None),
            (Focus::Conversation, Some(Overlay::Help)),
        ] {
            let (mut s, operation, registration) =
                active_ordinary_operation(WorkerCommand::Prompt("old intent".into()));
            finish_owned_view(
                &mut s,
                operation,
                registration,
                OrdinaryEnd::Failed("failed".into()),
                OrdinaryPublication::Saved,
            );
            assert!(s.can_resend_ordinary() && !s.is_busy());
            let history = s.transcript.clone();
            let report = s.turn_report.clone();
            let totals = (s.turns, s.input_tokens, s.output_tokens, s.cost_microcents);
            let (sink, receiver) = std::sync::mpsc::channel();
            let mut tui = Tui::new();
            if focus == Focus::Workspace {
                tui.app.focus = tui
                    .app
                    .tree
                    .leaves()
                    .iter()
                    .position(|(_, view)| *view != super::super::layout::View::Conversation)
                    .expect("the real layout must expose an unfocused panel");
            }
            tui.sync_focus();
            assert_eq!(tui.focus, focus);
            let mut composer = String::new();
            let mut overlay = initial_overlay;
            let mut queued = Vec::new();
            press_enter_in_context(
                &mut s,
                &sink,
                &mut tui,
                &mut composer,
                &mut overlay,
                &mut queued,
            );
            assert!(matches!(
                receiver.try_recv(),
                Err(std::sync::mpsc::TryRecvError::Empty)
            ));
            assert!(composer.is_empty() && queued.is_empty() && !s.is_busy());
            assert_eq!(
                s.eligible_ordinary_intent(),
                Some(&OrdinaryIntent::Prompt("old intent".into()))
            );
            assert_eq!(s.transcript, history);
            assert_eq!(s.turn_report, report);
            assert_eq!(
                (s.turns, s.input_tokens, s.output_tokens, s.cost_microcents),
                totals
            );
            if initial_overlay.is_some() {
                assert_eq!(overlay, None, "the key closes Help and is consumed");
            }
        }

        // A real nonempty draft uses ordinary fresh admission, never old intent.
        let (mut s, old_operation, registration) =
            active_ordinary_operation(WorkerCommand::Prompt("stale intent".into()));
        finish_owned_view(
            &mut s,
            old_operation.clone(),
            registration,
            OrdinaryEnd::Failed("failed".into()),
            OrdinaryPublication::Saved,
        );
        let (sink, receiver) = std::sync::mpsc::channel();
        let mut tui = Tui::new();
        let mut composer = "fresh draft".to_string();
        tui.composer_cursor = super::super::composer::grapheme_count(&composer);
        let mut queued = Vec::new();
        assert_eq!(tui.focus, Focus::Conversation);
        assert!(s.can_resend_ordinary());
        press_enter_in_context(
            &mut s,
            &sink,
            &mut tui,
            &mut composer,
            &mut None,
            &mut queued,
        );
        let WorkerCommand::Bound { operation, command } = receiver.try_recv().unwrap() else {
            panic!("fresh draft must be admitted");
        };
        assert_ne!(operation, old_operation);
        assert_eq!(
            OrdinaryIntent::from_command(&command),
            Some(OrdinaryIntent::Prompt("fresh draft".into()))
        );
        assert!(matches!(
            receiver.try_recv(),
            Err(std::sync::mpsc::TryRecvError::Empty)
        ));
        assert!(
            composer.is_empty() && queued.is_empty() && s.is_busy() && !s.can_resend_ordinary()
        );
        assert_eq!(s.transcript.last().unwrap().kind, LineKind::User);
        assert_eq!(s.transcript.last().unwrap().text, "fresh draft");
        let registration = operation.start(&command).unwrap();
        finish_owned_view(
            &mut s,
            operation,
            registration,
            OrdinaryEnd::Failed("fresh failed".into()),
            OrdinaryPublication::Saved,
        );
        assert_eq!(
            s.eligible_ordinary_intent(),
            Some(&OrdinaryIntent::Prompt("fresh draft".into()))
        );

        // Busy control work blocks empty Enter while retaining the prior record.
        let (mut s, operation, registration) =
            active_ordinary_operation(WorkerCommand::Prompt("prior failure".into()));
        finish_owned_view(
            &mut s,
            operation,
            registration,
            OrdinaryEnd::Failed("failed".into()),
            OrdinaryPublication::Saved,
        );
        let (sink, receiver) = std::sync::mpsc::channel();
        submit_foreground(&mut s, &sink, WorkerCommand::SetModel("model".into())).unwrap();
        let WorkerCommand::Bound { operation, command } = receiver.recv().unwrap() else {
            panic!("actual busy control");
        };
        let registration = operation.start(&command).unwrap();
        assert!(s.is_busy() && !s.ordinary_pending() && !s.can_resend_ordinary());
        let history = s.transcript.clone();
        let report = s.turn_report.clone();
        let mut tui = Tui::new();
        let mut composer = String::new();
        let mut queued = Vec::new();
        press_enter_in_context(
            &mut s,
            &sink,
            &mut tui,
            &mut composer,
            &mut None,
            &mut queued,
        );
        assert!(matches!(
            receiver.try_recv(),
            Err(std::sync::mpsc::TryRecvError::Empty)
        ));
        assert!(composer.is_empty() && queued.is_empty());
        assert_eq!(s.pending_foreground(), Some(&operation));
        assert_eq!(s.transcript, history);
        assert_eq!(s.turn_report, report);
        drop(registration);
        assert!(apply_session_projection(
            projection(ProjectionReason::Operation { operation }),
            &mut s,
            6
        ));
        assert_eq!(
            s.eligible_ordinary_intent(),
            Some(&OrdinaryIntent::Prompt("prior failure".into()))
        );

        // Existing ordinary queue policy is unchanged: empty Enter is inert,
        // and a nonempty busy draft is queued locally rather than dispatched.
        let (mut s, operation, registration) =
            active_ordinary_operation(WorkerCommand::Prompt("active ordinary".into()));
        s.apply("round_started", 0);
        assert!(s.is_busy() && s.ordinary_pending() && !s.can_resend_ordinary());
        let (sink, receiver) = std::sync::mpsc::channel();
        let mut tui = Tui::new();
        let mut composer = String::new();
        let mut queued = Vec::new();
        let history = s.transcript.clone();
        press_enter_in_context(
            &mut s,
            &sink,
            &mut tui,
            &mut composer,
            &mut None,
            &mut queued,
        );
        assert!(matches!(
            receiver.try_recv(),
            Err(std::sync::mpsc::TryRecvError::Empty)
        ));
        assert!(composer.is_empty() && queued.is_empty());
        assert_eq!(s.transcript, history);
        composer = "queued fresh draft".into();
        tui.composer_cursor = super::super::composer::grapheme_count(&composer);
        press_enter_in_context(
            &mut s,
            &sink,
            &mut tui,
            &mut composer,
            &mut None,
            &mut queued,
        );
        assert!(matches!(
            receiver.try_recv(),
            Err(std::sync::mpsc::TryRecvError::Empty)
        ));
        assert!(composer.is_empty());
        assert_eq!(queued, ["queued fresh draft".to_string()]);
        assert_eq!(s.transcript.last().unwrap().kind, LineKind::Queued);
        assert_eq!(s.transcript.last().unwrap().text, "queued fresh draft");
        assert_eq!(s.pending_foreground(), Some(&operation));
        finish_owned_view(
            &mut s,
            operation,
            registration,
            OrdinaryEnd::Completed,
            OrdinaryPublication::Saved,
        );
        assert_eq!(s.transcript.last().unwrap().kind, LineKind::Queued);
        assert_eq!(s.transcript.last().unwrap().text, "queued fresh draft");
    }

    #[test]
    fn ordinary_completed_cancelled_and_blocked_publication_never_resend() {
        use crate::msg::{OrdinaryEnd, OrdinaryPublication};
        for end in [
            OrdinaryEnd::Completed,
            OrdinaryEnd::Cancelled,
            OrdinaryEnd::Failed("failed".into()),
        ] {
            for publication in [
                OrdinaryPublication::Saved,
                OrdinaryPublication::BlockedOrUncertain,
            ] {
                if matches!(&end, OrdinaryEnd::Failed(_))
                    && publication == OrdinaryPublication::Saved
                {
                    continue;
                }
                let (mut s, operation, registration) =
                    active_ordinary_operation(WorkerCommand::Prompt("p".into()));
                finish_owned_view(&mut s, operation, registration, end.clone(), publication);
                let history = s.transcript.clone();
                let report = s.turn_report.clone();
                let totals = (s.turns, s.input_tokens, s.output_tokens, s.cost_microcents);
                apply_msg(
                    crate::msg::Msg::BackendNotice("storage warning".into()),
                    &mut s,
                    5,
                );
                let (control, received) = std::sync::mpsc::channel();
                submit_foreground(&mut s, &control, WorkerCommand::SetModel("model".into()))
                    .unwrap();
                let WorkerCommand::Bound { operation, command } = received.recv().unwrap() else {
                    panic!("settings repair");
                };
                let registration = operation.start(&command).unwrap();
                drop(registration);
                assert!(apply_session_projection(
                    projection(ProjectionReason::Operation { operation }),
                    &mut s,
                    6
                ));
                apply_msg(
                    crate::msg::Msg::BackendError("late diagnostic".into()),
                    &mut s,
                    7,
                );
                assert!(!s.is_busy() && !s.can_resend_ordinary());
                let (sink, receiver) = std::sync::mpsc::channel();
                press_empty_enter(&mut s, &sink);
                assert!(receiver.try_recv().is_err());
                assert_eq!(s.transcript, history);
                assert_eq!(s.turn_report, report);
                assert_eq!(
                    (s.turns, s.input_tokens, s.output_tokens, s.cost_microcents),
                    totals
                );
                assert!(!failure_test_frame(&s, 110, 30, 0).contains("empty composer resends it"));
            }
        }
    }

    #[test]
    fn ordinary_resend_namespace_refresh_and_control_lifecycle() {
        use crate::msg::{OrdinaryEnd, OrdinaryPublication};
        let (mut s, operation, registration) =
            active_ordinary_operation(WorkerCommand::Prompt("p".into()));
        finish_owned_view(
            &mut s,
            operation,
            registration,
            OrdinaryEnd::Failed("failed".into()),
            OrdinaryPublication::Saved,
        );
        let mut refreshed = projection(ProjectionReason::Refresh);
        assert!(apply_session_projection(refreshed.clone(), &mut s, 5));
        assert!(s.can_resend_ordinary());
        let (sink, receiver) = std::sync::mpsc::channel();
        submit_foreground(&mut s, &sink, WorkerCommand::SetModel("model".into())).unwrap();
        let WorkerCommand::Bound { operation, command } = receiver.recv().unwrap() else {
            panic!("control");
        };
        let registration = operation.start(&command).unwrap();
        drop(registration);
        refreshed.reason = ProjectionReason::Operation { operation };
        assert!(apply_session_projection(refreshed, &mut s, 6));
        assert!(s.can_resend_ordinary());
        apply_msg(
            crate::msg::Msg::Identity {
                model: "model".into(),
                provider: "provider".into(),
                session_prefix: "prefix".into(),
                session_id: s.session_id.clone(),
                priced: true,
            },
            &mut s,
            7,
        );
        assert!(s.can_resend_ordinary());
        apply_msg(
            crate::msg::Msg::Identity {
                model: "model".into(),
                provider: "provider".into(),
                session_prefix: "prefix".into(),
                session_id: "session-next".into(),
                priced: true,
            },
            &mut s,
            8,
        );
        assert!(!s.can_resend_ordinary());
        assert!(s.ordinary_end().is_none());
        for transition in ["clear", "resume", "restore", "initial"] {
            let (mut s, operation, registration) =
                active_ordinary_operation(WorkerCommand::Prompt("p".into()));
            finish_owned_view(
                &mut s,
                operation,
                registration,
                OrdinaryEnd::Failed("failed".into()),
                OrdinaryPublication::Saved,
            );
            apply_msg(
                crate::msg::Msg::BackendNotice("old notice".into()),
                &mut s,
                5,
            );
            if transition == "restore" {
                apply_msg(
                    crate::msg::Msg::TranscriptLoaded {
                        lines: vec![],
                        turns: 0,
                        input_tokens: 0,
                        output_tokens: 0,
                        cost_microcents: 0,
                    },
                    &mut s,
                    6,
                );
            } else if transition == "initial" {
                apply_msg(
                    crate::msg::Msg::Identity {
                        model: "model".into(),
                        provider: "provider".into(),
                        session_prefix: "fresh".into(),
                        session_id: "session-initial".into(),
                        priced: true,
                    },
                    &mut s,
                    6,
                );
                let mut initial = projection(ProjectionReason::Initial);
                initial.binding = SessionBinding {
                    session_id: "session-initial".into(),
                    generation: 1,
                };
                initial.lines.clear();
                initial.turns = 0;
                assert!(apply_session_projection(initial, &mut s, 7));
            } else {
                let reason = if transition == "clear" {
                    let operation = s.new_manual_operation(ManualAction::Clear).unwrap();
                    assert!(s.admit_manual(operation.clone()));
                    ProjectionReason::Manual {
                        operation,
                        outcome: ManualOutcome::Completed,
                        applied: true,
                    }
                } else {
                    ProjectionReason::Resume {
                        previous: binding(),
                    }
                };
                let mut next = projection(reason);
                next.binding = SessionBinding {
                    session_id: "session-next".into(),
                    generation: 2,
                };
                next.lines.clear();
                next.turns = 0;
                assert!(apply_session_projection(next, &mut s, 7));
            }
            assert!(s.ordinary_end().is_none() && !s.can_resend_ordinary());
            assert!(s.backend_notice().is_none());
        }
    }

    #[test]
    fn palette_customization_preserves_failed_intent_binding_notice_and_report() {
        use crate::msg::{OrdinaryEnd, OrdinaryPublication};
        for (command, available) in [
            ("/theme", false),
            ("/customize", false),
            ("/theme", true),
            ("/customize", true),
        ] {
            let (mut s, operation, registration) =
                active_ordinary_operation(WorkerCommand::Prompt("retained intent".into()));
            finish_owned_view(
                &mut s,
                operation,
                registration,
                OrdinaryEnd::Failed("ordinary failure".into()),
                OrdinaryPublication::Saved,
            );
            apply_msg(
                crate::msg::Msg::BackendNotice("separate notice".into()),
                &mut s,
                5,
            );
            let history = s.transcript.clone();
            let report = s.turn_report.clone();
            let binding = s.session_binding().cloned();
            let cost = s.cost_qualification();
            assert!(s.can_resend_ordinary());
            let mut tui = Tui::new();
            if available {
                let host = Arc::new(super::palette_review_tests::RecordingHost(
                    std::sync::Mutex::new(Vec::new()),
                ));
                tui.customization =
                    Some(crate::customization::CustomizationSession::open(host).unwrap());
            }
            let mut toast = None;
            let (sink, received) = std::sync::mpsc::channel();
            let (_bus, sender) = crate::bus::Bus::new();
            assert!(
                run_command(
                    &mut tui,
                    command,
                    &mut s,
                    &mut String::new(),
                    &sink,
                    &sender,
                    5000,
                    &mut toast,
                    &mut Vec::new(),
                    &mut Vec::new(),
                    &mut None,
                    &mut false
                )
                .is_none()
            );
            assert_eq!(toast.as_ref().unwrap().ok, available);
            assert_eq!(s.session_binding(), binding.as_ref());
            assert_eq!(s.cost_qualification(), cost);
            assert_eq!(s.transcript, history);
            assert_eq!(s.turn_report, report);
            assert_eq!(s.backend_notice(), Some("separate notice"));
            assert_eq!(s.failure_reason.as_deref(), Some("ordinary failure"));
            assert!(s.can_resend_ordinary());
            assert!(matches!(
                received.try_recv(),
                Err(std::sync::mpsc::TryRecvError::Empty)
            ));
            press_empty_enter(&mut s, &sink);
            let WorkerCommand::Bound { command, .. } = received.try_recv().unwrap() else {
                panic!("a later explicit Enter must retain the original eligible intent");
            };
            assert!(matches!(*command, WorkerCommand::Prompt(text) if text == "retained intent"));
        }
    }

    #[test]
    fn backend_notice_lifecycle_preserves_prior_failed_ordinary_and_report() {
        use crate::msg::{OrdinaryEnd, OrdinaryPublication};
        let (mut s, operation, registration) =
            active_ordinary_operation(WorkerCommand::Prompt("p".into()));
        finish_owned_view(
            &mut s,
            operation,
            registration,
            OrdinaryEnd::Failed("ordinary cause".into()),
            OrdinaryPublication::Saved,
        );
        let history = s.transcript.clone();
        let report = s.turn_report.clone();
        for text in ["notice A", "notice B"] {
            s.take_view_dirty();
            apply_msg(crate::msg::Msg::BackendNotice(text.into()), &mut s, 5);
            assert!(s.take_view_dirty());
            assert_eq!(s.backend_notice(), Some(text));
            assert!(s.can_resend_ordinary());
            assert_eq!(s.failure_reason.as_deref(), Some("ordinary cause"));
            assert_eq!(s.transcript, history);
            assert_eq!(s.turn_report, report);
            assert!(apply_session_projection(
                projection(ProjectionReason::Refresh),
                &mut s,
                6
            ));
            assert_eq!(s.backend_notice(), Some(text));
        }
        let wrong = ForegroundOperation::new(
            SessionBinding {
                session_id: "other".into(),
                generation: 1,
            },
            ForegroundKind::Control,
            20,
        )
        .unwrap();
        assert!(!s.admit_foreground(wrong));
        assert_eq!(s.backend_notice(), Some("notice B"));
        let (sink, receiver) = std::sync::mpsc::channel();
        submit_foreground(&mut s, &sink, WorkerCommand::SetModel("model".into())).unwrap();
        assert!(s.backend_notice().is_none());
        assert!(receiver.try_recv().is_ok());
        s.apply("round_started", 0);
        assert!(s.backend_notice().is_none() && !s.can_resend_ordinary());
        let mut empty = Scenario::new();
        let mut initial = projection(ProjectionReason::Initial);
        initial.lines.clear();
        initial.turns = 0;
        assert!(apply_session_projection(initial.clone(), &mut empty, 1));
        apply_msg(
            crate::msg::Msg::BackendNotice("settings unchanged 界 e\u{301}".into()),
            &mut empty,
            2,
        );
        initial.reason = ProjectionReason::Refresh;
        assert!(apply_session_projection(initial, &mut empty, 3));
        assert!(empty.transcript.is_empty() && empty.turn_report.is_none() && !empty.last_failed);
        let frame = failure_test_frame(&empty, 110, 30, 0);
        assert!(frame.contains("settings unchanged") && frame.contains("the harness that orbits"));
        assert!(
            !frame.contains("This turn failed") && !frame.contains("empty composer resends it")
        );
        let operation = empty.new_manual_operation(ManualAction::Compact).unwrap();
        assert!(empty.admit_manual(operation));
        assert!(empty.backend_notice().is_none());
    }

    #[test]
    fn typed_failed_and_cancelled_first_draw_keep_reports_and_truthful_cells() {
        use crate::msg::{OrdinaryEnd, OrdinaryPublication};
        use ratatui::{Terminal, backend::TestBackend, style::Color};
        for end in [
            OrdinaryEnd::Failed("useful failure 界 e\u{301}".into()),
            OrdinaryEnd::Cancelled,
        ] {
            let (mut s, operation, registration) =
                active_ordinary_operation(WorkerCommand::Prompt("p".into()));
            s.turn_started_ms = 0;
            s.turn_tools = 2;
            let cancelled = matches!(&end, OrdinaryEnd::Cancelled);
            finish_owned_view(
                &mut s,
                operation,
                registration,
                end,
                OrdinaryPublication::Saved,
            );
            assert_eq!(s.turn_report.as_ref().unwrap().tools, 2);
            let mut tui = Tui::new();
            tui.reduced = true;
            let mut terminal = Terminal::new(TestBackend::new(110, 30)).unwrap();
            terminal
                .draw(|frame| draw(frame, &tui, &s, "", None, "", 0, None, false, 0))
                .unwrap();
            let buffer = terminal.backend().buffer();
            let expected = if cancelled { "cancelled" } else { "failed" };
            let palette = super::super::shell::pal::Palette::default();
            let rgb = if cancelled {
                palette.amber
            } else {
                palette.red
            };
            let color = Color::Rgb(rgb.0, rgb.1, rgb.2);
            let report = s.turn_report.as_ref().unwrap();
            let report_text = format!(
                "{expected} · {}s · {} tools",
                report.duration_ms / 1000,
                report.tools
            );
            let mut found_report = false;
            let mut found = false;
            for y in 1..30 {
                let cells: Vec<_> = (0..110).map(|x| &buffer[(x, y)]).collect();
                let row = cells.iter().map(|cell| cell.symbol()).collect::<String>();
                if row.contains("2  Conversation") && row.contains(expected) {
                    let symbols: Vec<_> = cells.iter().map(|cell| cell.symbol()).collect();
                    let word: Vec<_> = expected.chars().map(|ch| ch.to_string()).collect();
                    for x in 0..=symbols.len() - word.len() {
                        if symbols[x..x + word.len()]
                            .iter()
                            .zip(&word)
                            .all(|(a, b)| *a == b.as_str())
                        {
                            assert!(cells[x..x + word.len()].iter().all(|cell| cell.fg == color));
                            found = true;
                        }
                    }
                }
                if row.contains(&report_text) && !row.contains("Conversation") {
                    let symbols: Vec<_> = cells.iter().map(|cell| cell.symbol()).collect();
                    let words: Vec<_> = report_text.chars().map(|ch| ch.to_string()).collect();
                    for x in 0..=symbols.len() - words.len() {
                        if symbols[x..x + words.len()]
                            .iter()
                            .zip(&words)
                            .all(|(a, b)| *a == b.as_str())
                        {
                            assert!(
                                cells[x..x + words.len()]
                                    .iter()
                                    .all(|cell| cell.fg == color),
                                "the actual product report branch must preserve its typed accent and facts"
                            );
                            if cancelled {
                                assert!(
                                    cells
                                        .iter()
                                        .any(|cell| cell.symbol() == "⊘" && cell.fg == color)
                                );
                            }
                            found_report = true;
                        }
                    }
                }
            }
            assert!(found, "typed header colour not observed");
            assert!(
                found_report,
                "actual typed report colour and duration/tool facts not observed"
            );
            let full = failure_test_frame(&s, 110, 30, 0);
            assert!(full.contains(expected) && !full.contains("✓ done ·"));
            let mut small = String::new();
            for offset in 0..16 {
                let frame = failure_test_frame(&s, 40, 11, offset);
                assert!(frame.contains("Ask ORBIT") && frame.contains("⏎ send"));
                small.push_str(&frame);
            }
            assert!(small.contains(expected) && small.contains("2 tools"));
            if !cancelled {
                assert!(
                    full.contains("useful failure"),
                    "the wide frame must preserve the failure reason:\n{full}"
                );
                assert!(
                    small.contains("useful")
                        && small.contains("failure")
                        && small.contains("界")
                        && small.contains("e\u{301}"),
                    "failure details must remain readable when wrapped:\n{small}"
                );
            }
        }
    }
}

#[cfg(test)]
mod palette_review_tests {
    use super::*;
    use crate::bus::{Bus, BusSender};
    use crate::msg::{ContextProjection, CostQualification, ProjectionReason, SessionProjection};
    use crate::proto::shell::hits::Click;
    use crate::worker::{ForegroundKind, SessionBinding};
    use crossterm::event::{MouseButton, MouseEvent, MouseEventKind};
    use orbit_frontend_protocol::customization::*;
    use ratatui::{Terminal, backend::TestBackend};
    use std::{
        collections::BTreeMap,
        sync::{Arc, Mutex, mpsc},
    };

    struct Keys {
        tui: Tui,
        s: Scenario,
        draft: String,
        overlay: Option<Overlay>,
        query: String,
        selected: usize,
        completion: usize,
        toast: Option<Toast>,
        queued: Vec<String>,
        history: Vec<String>,
        history_index: Option<usize>,
        leader: Option<char>,
        copy: bool,
        sessions: bool,
        sink: CommandSink,
        received: mpsc::Receiver<WorkerCommand>,
        _bus: Bus,
        sender: BusSender,
        approvals: ApprovalRegistry,
        drawn: Option<PaletteFrame>,
    }
    impl Keys {
        fn new(query: &str) -> Self {
            let (sink, received) = mpsc::channel();
            let (bus, sender) = Bus::new();
            let mut tui = Tui::new();
            tui.reduced = true;
            tui.tick_ms = 5000;
            Self {
                tui,
                s: Scenario::new(),
                draft: String::new(),
                overlay: Some(Overlay::Palette),
                query: query.into(),
                selected: 0,
                completion: 0,
                toast: None,
                queued: Vec::new(),
                history: Vec::new(),
                history_index: None,
                leader: None,
                copy: false,
                sessions: false,
                sink,
                received,
                _bus: bus,
                sender,
                approvals: ApprovalRegistry::new(),
                drawn: None,
            }
        }
        fn bind(&mut self) {
            assert!(apply_session_projection(
                SessionProjection {
                    binding: SessionBinding {
                        session_id: "palette-source".into(),
                        generation: 1
                    },
                    model: "fixture".into(),
                    provider: "fixture".into(),
                    priced: false,
                    lines: Vec::new(),
                    turns: 0,
                    input_tokens: 0,
                    output_tokens: 0,
                    cost_microcents: 0,
                    cost: CostQualification::Known { revision: 0 },
                    context: ContextProjection::Unavailable,
                    reason: ProjectionReason::Initial,
                },
                &mut self.s,
                1
            ));
        }
        fn press(&mut self, code: KeyCode) {
            let key = crossterm::event::KeyEvent::new(code, KeyModifiers::NONE);
            if handle_custom_key(
                key,
                &mut self.tui,
                &mut self.s,
                &mut self.draft,
                None,
                &mut self.toast,
                5000,
                self.overlay.is_some(),
            ) {
                return;
            }
            assert!(!handle_key(
                key,
                &mut self.tui,
                &mut self.s,
                &mut self.draft,
                None,
                &self.sink,
                &self.sender,
                &self.approvals,
                5000,
                &mut self.overlay,
                &mut self.query,
                &mut self.selected,
                &mut self.completion,
                &mut self.toast,
                &mut self.queued,
                &mut self.history,
                &mut self.history_index,
                &mut self.leader,
                &mut self.copy,
                &mut self.sessions
            ));
        }
        fn frame(&mut self, width: u16, height: u16) -> Vec<String> {
            let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
            let mut hits = Vec::new();
            terminal
                .draw(|f| {
                    hits = draw_with_hits(
                        f,
                        &self.tui,
                        &self.s,
                        &self.draft,
                        self.overlay,
                        &self.query,
                        self.selected,
                        self.toast.as_ref(),
                        false,
                        0,
                    );
                })
                .unwrap();
            self.drawn = capture_palette_frame(&self.s, self.overlay, &self.query, &hits);
            self.tui.hits = hits;
            let buffer = terminal.backend().buffer();
            (0..height)
                .map(|y| {
                    (0..width)
                        .map(|x| buffer[(x, y)].symbol())
                        .collect::<String>()
                })
                .collect()
        }
        fn click(&mut self, command: &str, width: u16, height: u16) -> Option<PaletteClick> {
            let index = self
                .drawn
                .as_ref()
                .unwrap()
                .rows
                .iter()
                .find(|(_, text)| *text == command)
                .unwrap()
                .0;
            let rect = self
                .tui
                .hits
                .iter()
                .find(|hit| hit.click == Click::Palette(index))
                .unwrap()
                .rect;
            let outcome = handle_mouse(
                MouseEvent {
                    kind: MouseEventKind::Down(MouseButton::Left),
                    column: rect.x + 1,
                    row: rect.y,
                    modifiers: KeyModifiers::NONE,
                },
                &mut self.tui,
                Rect::new(0, 0, width, height),
                None,
                true,
            );
            let MouseOutcome::Palette(index) = outcome else {
                panic!("the actual drawn command row must be clickable");
            };
            capture_palette_click(
                &self.s,
                self.overlay,
                &self.query,
                self.drawn.as_ref(),
                index,
            )
        }
        fn activate(&mut self, click: PaletteClick) -> bool {
            let key = palette_click_key(
                click,
                &self.s,
                self.overlay,
                &self.query,
                &mut self.selected,
            );
            if let Some(key) = key {
                self.press(key.code);
                true
            } else {
                false
            }
        }
        fn no_worker_command(&self) {
            assert!(matches!(
                self.received.try_recv(),
                Err(mpsc::TryRecvError::Empty)
            ));
        }
    }

    #[test]
    fn palette_keyboard_runs_the_drawn_subsequence_command() {
        for query in ["me", "md", "/ME"] {
            let mut keys = Keys::new(query);
            let rows = keys.frame(110, 30);
            assert!(
                rows.iter()
                    .any(|row| row.contains("▌") && row.contains("/mode"))
            );
            keys.press(KeyCode::Enter);
            assert!(
                keys.s
                    .transcript
                    .iter()
                    .any(|line| line.text.starts_with("mode: default"))
            );
            assert!(
                !keys
                    .s
                    .transcript
                    .iter()
                    .any(|line| line.text.contains("usage: /resume"))
            );
            assert_eq!(keys.overlay, None);
            keys.no_worker_command();
        }
    }

    #[test]
    fn palette_mouse_runs_the_actual_drawn_row() {
        for (width, height) in [(110, 30), (40, 11)] {
            let mut keys = Keys::new("me");
            let rows = keys.frame(width, height);
            let index = keys
                .drawn
                .as_ref()
                .unwrap()
                .rows
                .iter()
                .find(|(_, command)| *command == "/model")
                .unwrap()
                .0;
            let hit = keys
                .tui
                .hits
                .iter()
                .find(|hit| hit.click == Click::Palette(index))
                .unwrap();
            assert!(rows[hit.rect.y as usize].contains("/model"));
            assert!(!rows[hit.rect.y as usize].contains("/models"));
            let click = keys.click("/model", width, height).unwrap();
            assert!(keys.activate(click));
            assert!(
                keys.s
                    .transcript
                    .iter()
                    .any(|line| line.text == "usage: /model <model-id>")
            );
            keys.no_worker_command();
        }
    }

    #[test]
    fn palette_keeps_the_selected_row_visible_with_global_hit_indices() {
        for (width, height) in [(110, 30), (40, 11)] {
            let mut keys = Keys::new("");
            for _ in 0..8 {
                keys.press(KeyCode::Down);
            }
            let rows = keys.frame(width, height);
            let hit = keys
                .tui
                .hits
                .iter()
                .find(|hit| hit.click == Click::Palette(8))
                .unwrap();
            assert!(
                rows[hit.rect.y as usize].contains("▌")
                    && rows[hit.rect.y as usize].contains("/resume")
            );
            for _ in 0..50 {
                keys.press(KeyCode::Down);
            }
            assert_eq!(keys.selected, 15);
            let rows = keys.frame(width, height);
            let hit = keys
                .tui
                .hits
                .iter()
                .find(|hit| hit.click == Click::Palette(15))
                .unwrap();
            assert!(
                rows[hit.rect.y as usize].contains("▌")
                    && rows[hit.rect.y as usize].contains("/theme")
            );
            assert!(
                keys.tui
                    .hits
                    .iter()
                    .filter(|hit| matches!(hit.click, Click::Palette(_)))
                    .all(|hit| hit.rect.bottom() <= height)
            );
            for _ in 0..50 {
                keys.press(KeyCode::Up);
            }
            assert_eq!(keys.selected, 0);
            let rows = keys.frame(width, height);
            let hit = keys
                .tui
                .hits
                .iter()
                .find(|hit| hit.click == Click::Palette(0))
                .unwrap();
            assert!(
                rows[hit.rect.y as usize].contains("▌")
                    && rows[hit.rect.y as usize].contains("/clear")
            );
            keys.no_worker_command();
        }
    }

    #[test]
    fn palette_rejects_a_last_frame_click_after_query_input_before_redraw() {
        let mut keys = Keys::new("");
        keys.bind();
        keys.draft = "keep local draft".into();
        keys.frame(110, 30);
        keys.press(KeyCode::Char('m'));
        assert_eq!(keys.query, "m");
        // The old drawn row is /clear, while row zero of the new filter is
        // /compact. Both are real controls: a stale index must run neither.
        assert!(keys.click("/clear", 110, 30).is_none());
        assert_eq!(keys.draft, "keep local draft");
        assert_eq!(keys.overlay, Some(Overlay::Palette));
        keys.no_worker_command();
    }

    #[test]
    fn deferred_palette_click_cannot_reach_a_closed_overlay_or_changed_namespace() {
        for changed_namespace in [false, true] {
            let mut keys = Keys::new("me");
            keys.bind();
            keys.draft = "keep local draft".into();
            keys.frame(110, 30);
            let click = keys.click("/model", 110, 30).unwrap();
            if changed_namespace {
                apply_msg(
                    crate::msg::Msg::Identity {
                        model: "fixture".into(),
                        provider: "fixture".into(),
                        session_prefix: "different".into(),
                        session_id: "different-session".into(),
                        priced: false,
                    },
                    &mut keys.s,
                    5001,
                );
            } else {
                keys.overlay = None;
            }
            assert!(!keys.activate(click));
            assert_eq!(keys.draft, "keep local draft");
            keys.no_worker_command();
        }
    }

    #[test]
    fn palette_empty_result_does_not_activate_or_send_the_local_draft() {
        let mut keys = Keys::new("zzzz");
        keys.draft = "unsent".into();
        keys.press(KeyCode::Down);
        keys.press(KeyCode::Up);
        assert_eq!(keys.selected, 0);
        let rows = keys.frame(40, 11);
        assert!(rows.join("\n").contains("no matching command"));
        assert!(keys.drawn.as_ref().unwrap().rows.is_empty());
        keys.press(KeyCode::Enter);
        assert_eq!(keys.draft, "unsent");
        assert_eq!(keys.overlay, Some(Overlay::Palette));
        keys.no_worker_command();
    }

    pub(super) struct RecordingHost(pub(super) Mutex<Vec<ProfileCommand>>);
    impl ProfileHost for RecordingHost {
        fn load(&self) -> Result<ResolvedProfile, CustomizationError> {
            Ok(ResolvedProfile {
                profile: Profile::default(),
                sources: BTreeMap::new(),
                revision: "palette-fixture".into(),
                capabilities: CustomizationCapabilities::default(),
            })
        }
        fn command(
            &self,
            command: ProfileCommand,
        ) -> Result<ProfileCommandResult, CustomizationError> {
            self.0.lock().unwrap().push(command);
            Ok(ProfileCommandResult {
                message: "actual customization consumer".into(),
                profile: None,
            })
        }
        fn replace(&self, _: Profile, _: &str) -> Result<ResolvedProfile, CustomizationError> {
            Err(CustomizationError::Busy)
        }
        fn reset(&self, _: &str) -> Result<ResolvedProfile, CustomizationError> {
            Err(CustomizationError::Busy)
        }
        fn read_pane(&self, _: &str, _: &PaneContext) -> Result<PaneOutput, CustomizationError> {
            Err(CustomizationError::Busy)
        }
    }

    #[test]
    fn palette_and_typed_customization_reach_the_same_real_consumer_and_toast() {
        for (query, command) in [("th", "/theme"), ("cust", "/customize")] {
            for busy in [false, true] {
                let source = Arc::new(RecordingHost(Mutex::new(Vec::new())));
                for route in ["palette-key", "palette-click", "typed"] {
                    let mut keys = Keys::new(query);
                    keys.bind();
                    keys.tui.customization = Some(
                        crate::customization::CustomizationSession::open(source.clone()).unwrap(),
                    );
                    if busy {
                        let operation = keys
                            .s
                            .new_foreground_operation(ForegroundKind::Control)
                            .unwrap();
                        assert!(keys.s.admit_foreground(operation));
                    }
                    let owner = keys.s.pending_foreground().cloned();
                    if route == "typed" {
                        keys.overlay = None;
                        keys.draft = command.into();
                    }
                    if route == "palette-click" {
                        keys.frame(110, 30);
                        let click = keys.click(command, 110, 30).unwrap();
                        assert!(keys.activate(click));
                    } else {
                        keys.press(KeyCode::Enter);
                    }
                    let toast = keys.toast.as_ref().unwrap();
                    assert!(toast.ok);
                    assert_eq!(toast.text, "actual customization consumer");
                    assert_eq!(keys.s.pending_foreground(), owner.as_ref());
                    keys.no_worker_command();
                }
                assert_eq!(
                    *source.0.lock().unwrap(),
                    [
                        ProfileCommand::Show,
                        ProfileCommand::Show,
                        ProfileCommand::Show
                    ]
                );
            }
        }
    }

    #[test]
    fn palette_customization_without_a_host_returns_the_real_error_toast() {
        for query in ["th", "cust"] {
            let mut keys = Keys::new(query);
            keys.press(KeyCode::Enter);
            let toast = keys.toast.as_ref().unwrap();
            assert!(!toast.ok);
            assert_eq!(
                toast.text,
                "invalid customization: customization host unavailable"
            );
            keys.no_worker_command();
        }
    }
}
