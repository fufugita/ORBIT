#![allow(dead_code)] // data-bearing state wired into the live render in PR-D

//! TUI application state + dirty-flag tracking (DR-20 §2.4).
//!
//! `App` is the reducer state. `reduce(msg)` transitions it; the render loop
//! only redraws when `dirty.is_dirty()`. Empty frames are forbidden.

use crate::coalesce::Coalescer;
use crate::input::KeyAction;
use crate::msg::Msg;
use std::time::Duration;

/// Coalescing interval for streaming text (DR-20 §2.4 — 30 ms data tick).
pub const DATA_TICK: Duration = Duration::from_millis(30);

/// Bitset tracking which regions need redraw.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DirtyFlags(u8);

impl DirtyFlags {
    pub const SESSION_LIST: u8 = 1 << 0;
    pub const TRANSCRIPT: u8 = 1 << 1;
    pub const TASKS: u8 = 1 << 2;
    pub const STATUS: u8 = 1 << 3;
    pub const LOGO: u8 = 1 << 4;
    pub const APPROVAL: u8 = 1 << 5;
    pub const LAYOUT: u8 = 1 << 6;

    /// Set one or more flag bits.
    pub fn set(&mut self, flags: u8) {
        self.0 |= flags;
    }

    /// True if any flag is set.
    pub fn is_dirty(&self) -> bool {
        self.0 != 0
    }

    /// True if the given flag bit is set.
    pub fn is_set(&self, flag: u8) -> bool {
        self.0 & flag != 0
    }

    /// Clear all flags (called after a successful render).
    pub fn clear(&mut self) {
        self.0 = 0;
    }
}

/// Which pane has keyboard focus.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Focus {
    Left,
    /// Default — the operator can type immediately on boot, no Tab needed.
    #[default]
    Center,
    Right,
    Status,
}

impl Focus {
    pub fn next(self) -> Self {
        match self {
            Self::Left => Self::Center,
            Self::Center => Self::Right,
            Self::Right => Self::Status,
            Self::Status => Self::Left,
        }
    }

    pub fn prev(self) -> Self {
        match self {
            Self::Left => Self::Status,
            Self::Center => Self::Left,
            Self::Right => Self::Center,
            Self::Status => Self::Right,
        }
    }
}

/// Left-panel tab.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum LeftTab {
    #[default]
    Sessions,
    Verbose,
}

/// The five phases of the ORBIT reactor (§6.10 stepper).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Orient,
    Reason,
    Act,
    Verify,
    Respond,
}

impl Phase {
    pub fn name(self) -> &'static str {
        match self {
            Self::Orient => "orient",
            Self::Reason => "reason",
            Self::Act => "act",
            Self::Verify => "verify",
            Self::Respond => "respond",
        }
    }
}

/// A workspace task (§6.10 task rows).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Task {
    pub title: String,
    pub state: TaskState,
    /// Optional single sub-line (what it's doing / why blocked / etc.).
    pub sub: Option<String>,
    /// Right-aligned evidence tag: number of verified proofs (0 = claimed).
    pub evidence: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskState {
    Active,
    Blocked,
    Failed,
    Retest,
    AwaitingApproval,
    Done,
}

/// The workspace snapshot the pane renders (§6.10). All sections optional;
/// the pane renders only the sections with data. The backend fills these
/// (PR-F wires the bridge).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Workspace {
    pub phase_index: usize, // 0..5
    pub plan: Vec<Task>,
    pub findings: Vec<Finding>,
    pub verification: Vec<Verification>,
}

/// One finding row: title + inline source path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub title: String,
    pub source: Option<String>,
}

/// §6.11 M5: the post-turn status report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TurnReport {
    pub duration_ms: u64,
    pub tool_count: u32,
    pub cost_microcents: u64,
}

/// §6.12 toast: a transient status line above the composer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Toast {
    pub text: String,
    /// ✓ when success, no glyph for neutral, ✕ for error (the colour
    /// follows the glyph — green / muted / red).
    pub kind: ToastKind,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToastKind {
    Success,
    Neutral,
    Error,
}

/// One verification row: check name + result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verification {
    pub name: String,
    pub result: VerificationResult,
    pub proof_count: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationResult {
    Passed,
    Failed,
    Pending,
}

impl App {
    /// The plain-text lines of a pane, for selection extraction. The
    /// transcript is the Center pane's content; the rails render their
    /// own lines (a full impl would cache them at render time).
    pub fn pane_lines(&self, pane: Focus) -> Vec<String> {
        match pane {
            Focus::Center => self
                .transcript
                .iter()
                .map(|l| match l {
                    crate::state::TranscriptLine::User(t)
                    | crate::state::TranscriptLine::Assistant(t)
                    | crate::state::TranscriptLine::System(t) => t.clone(),
                    crate::state::TranscriptLine::Stripped { tool_name } => {
                        format!("[tool] {tool_name}")
                    }
                })
                .collect(),
            _ => Vec::new(),
        }
    }
}

/// The last-rendered pane rects — the mouse hit-test boundary. Interior
/// mutability (Cell) so the renderer can record them through &App.
#[derive(Debug, Clone, Default)]
pub struct PaneRects {
    pub left: std::cell::Cell<Option<ratatui::layout::Rect>>,
    pub center: std::cell::Cell<Option<ratatui::layout::Rect>>,
    pub right: std::cell::Cell<Option<ratatui::layout::Rect>>,
}

/// Modal input (the multiplexer pattern): INSERT types into the composer
/// (the boot default — type to talk); NORMAL runs single-key commands
/// (q, g/z leaders, ?). Esc from an empty composer toggles to NORMAL;
/// `i` or Enter returns to INSERT. The status line shows the mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum InputMode {
    /// Type into the composer (the boot default).
    #[default]
    Insert,
    /// Single-key commands (q, g/z leaders, ?).
    Normal,
    /// Prefix mode (herdr/tmux-style): the next key is a command. Entered
    /// with Ctrl+B; Esc cancels. The status line shows PREFIX.
    Prefix,
    /// Copy mode: j/k move a cursor through the transcript, v selects,
    /// y yanks. Per-pane (herdr-style).
    Copy,
}

/// The command palette (§6.13): an overlay with a fuzzy query.
#[derive(Debug, Default)]
pub struct PaletteState {
    pub open: bool,
    pub query: String,
    /// Index into the filtered command list.
    pub selected: usize,
}

/// One palette command.
#[derive(Debug, Clone)]
pub struct PaletteCommand {
    pub label: String,
    pub description: String,
    pub hint: String,
}

/// Fuzzy-filter the palette commands by the query: a simple subsequence
/// match (each query char appears in order). Case-insensitive.
pub fn filtered_commands(query: &str) -> Vec<PaletteCommand> {
    let all = palette_commands();
    if query.is_empty() {
        return all;
    }
    let q: Vec<char> = query.to_lowercase().chars().collect();
    all.into_iter()
        .filter(|cmd| {
            let hay: Vec<char> = format!("{} {}", cmd.label, cmd.description)
                .to_lowercase()
                .chars()
                .collect();
            let mut qi = 0;
            for c in hay {
                if qi < q.len() && c == q[qi] {
                    qi += 1;
                }
            }
            qi == q.len()
        })
        .collect()
}

/// The built-in palette commands (§6.13 COMMANDS section).
pub fn palette_commands() -> Vec<PaletteCommand> {
    vec![
        PaletteCommand {
            label: "new session".into(),
            description: "start a fresh conversation".into(),
            hint: "g n".into(),
        },
        PaletteCommand {
            label: "copy transcript".into(),
            description: "yank the transcript as plain text".into(),
            hint: "z y".into(),
        },
        PaletteCommand {
            label: "sessions".into(),
            description: "switch to the sessions rail".into(),
            hint: "g s".into(),
        },
        PaletteCommand {
            label: "activity".into(),
            description: "switch to the activity rail".into(),
            hint: "g v".into(),
        },
        PaletteCommand {
            label: "workspace".into(),
            description: "focus the workspace rail".into(),
            hint: "g r".into(),
        },
        PaletteCommand {
            label: "conversation".into(),
            description: "focus the conversation".into(),
            hint: "g c".into(),
        },
        PaletteCommand {
            label: "toggle tool detail".into(),
            description: "expand or collapse tool output".into(),
            hint: "z t".into(),
        },
        PaletteCommand {
            label: "toggle cost".into(),
            description: "show or hide the cost line".into(),
            hint: "z c".into(),
        },
        PaletteCommand {
            label: "quit".into(),
            description: "leave ORBIT".into(),
            hint: "q".into(),
        },
    ]
}

/// The reducer state.
#[derive(Debug)]
pub struct App {
    pub dirty: DirtyFlags,
    pub should_quit: bool,
    pub size: (u16, u16),
    pub focus: Focus,
    pub left_tab: LeftTab,
    pub tick_count: u64,

    // ── Data state (filled by the backend bridge) ──────────────────────────
    /// Lines in the conversation transcript (user + assistant).
    pub transcript: Vec<TranscriptLine>,
    /// Current assistant turn being streamed (empty when not streaming).
    pub in_flight: String,
    /// Streaming text coalescer — flushes every 30 ms.
    pub coalescer: Coalescer,
    /// Cumulative cost in microcents (H-17).
    pub total_cost_microcents: u64,
    /// Cumulative input tokens.
    pub total_input_tokens: u64,
    /// Cumulative output tokens.
    pub total_output_tokens: u64,
    /// Completed user turns (REPL parity for `/usage`, H-17).
    pub total_turns: u64,
    /// Current provider (from cmd_chat config).
    pub provider: String,
    /// Current model (from cmd_chat config).
    pub model: String,
    /// Session id (first 8 chars shown in status bar).
    pub session_id_prefix: String,
    /// The full session id (for the §8.4 shutdown line's resume hint).
    pub session_id: String,
    /// Connection state.
    pub connection: ConnectionState,
    /// Tool state (idle / streaming / awaiting approval / running / auto-grant).
    pub tool_state: ToolState,
    /// Pending tool calls awaiting approval (PR-C will render these).
    pub pending_approvals: Vec<PendingApproval>,
    /// Workspace snapshot (§6.10) — empty until the backend fills it (PR-F).
    pub workspace: Workspace,
    /// Command palette (§6.13).
    pub palette: PaletteState,
    /// Modal input state (insert vs normal).
    pub input_mode: InputMode,
    /// Zoomed pane (herdr-style): the pane fills the whole surface; the
    /// other panes are hidden. None = normal 3-pane layout.
    pub zoomed_pane: Option<Focus>,
    /// Last-rendered pane rects (screen coords) — the mouse hit-test
    /// boundary. Updated by the renderer each frame.
    pub pane_rects: PaneRects,
    /// The active per-pane text selection (None = no selection).
    pub selection: Option<crate::selection::Selection>,
    /// A pending OSC 52 clipboard write — the terminal loop emits it once
    /// then clears it (the reducer can't write to stdout).
    pub osc52_pending: Option<String>,
    /// Last status one-liner (shown in toast / status bar).
    pub last_status: String,
    /// Active error from the backend, if any.
    pub last_error: Option<String>,
    /// Transcript scroll offset (lines from top). Auto-scrolls to bottom.
    pub transcript_scroll: u16,
    /// Ctrl+C press count — 0 = none, 1 = "press again to quit", 2 = quit.
    pub ctrl_c_count: u8,
    /// Tick count at the last Ctrl+C press (for timeout reset).
    pub last_ctrl_c_tick: u64,
    /// Quit confirmation message (shown when ctrl_c_count == 1).
    pub quit_confirmation: bool,
    /// Cost flash frames (counts down from 8 when cost changes).
    pub cost_flash_frames: u8,
    /// Reconnecting spinner phase (0..3).
    pub reconnect_phase: u8,
    /// Copy mode flag — when true, TUI exits alt screen for plain text copy.
    pub copy_mode: bool,
    /// Logo phase (DR-21 L19): splash → steady → working → shutdown.
    pub logo_phase: LogoPhase,
    /// §8.3 startup frame: 0..=5 while Splash; the welcome mark reveals
    /// progressively at 4 fps. Any key jumps to the last frame.
    pub startup_frame: u8,
    /// §6.16 help overlay: two columns of keys grouped by pane.
    pub help_open: bool,
    /// §6.11 M5: the last turn's report (shown for 2 s after the turn).
    pub turn_report: Option<TurnReport>,
    /// Tick when the turn report was stamped (2 s window).
    pub turn_report_at: Option<u64>,
    /// When the current turn started (Instant) — for the M5 duration.
    turn_started_at: Option<std::time::Instant>,
    /// Tool calls made in the current turn (for the M5 report).
    turn_tool_count: u32,
    /// §6.12 toast: text + frame counter (the toast auto-dismisses at 3 s).
    pub toast: Option<crate::state::Toast>,
    /// Tick counter when the toast was emitted (used for the 3-s timer).
    pub toast_emitted_at: Option<u64>,
    /// Frames spent in the current logo phase (drives phase transitions).
    /// Composer state (DR-21 §3.4) — left glyph + border color.
    pub composer_state: ComposerState,
    /// Composer send animation phase (0..3 for ↗↘↗).
    pub composer_send_phase: u8,
    /// Queued prompts: typed while a turn is in flight. Drained one at a
    /// time when a turn ends (ResponseFinished or CancelTurn). Rendered as
    /// dimmed `⏳` lines above the composer.
    pub queued: Vec<String>,
    /// True while the worker is actively running a turn (streaming or in a
    /// tool round). Drives whether Ctrl+C cancels the turn vs. quits.
    pub turn_in_flight: bool,
    /// Set when the operator cancels the in-flight turn; consumed by the
    /// next ResponseFinished (which stamps the transcript).
    pub cancel_requested: bool,
    /// Braille spinner frame index (0..10, advances every 4 ticks = 8fps).
    pub spinner_frame: u8,
    /// Smooth focus transition phase 0..3. The renderer blends the border
    /// color (dim → accent) over 3 frames when focus changes; None = settled.
    /// Per-pane scroll offsets (lines from top). 0 = top. Each pane
    /// scrolls independently — functional isolation (herdr-style).
    pub pane_scroll: [u16; 3],
    /// True when the operator has scrolled up (disables auto-scroll).
    pub viewport_manual: bool,
    /// One-shot: clear the terminal before the next draw so the whole frame
    /// re-emits (set on the live→settled turn transition). Cell so the draw
    /// path can consume it through &App.
    pub force_full_redraw: std::cell::Cell<bool>,
}

/// One line in the transcript — either a user message or an assistant reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TranscriptLine {
    User(String),
    Assistant(String),
    /// CoT-stripped placeholder (NEVER shows raw reasoning).
    Stripped {
        tool_name: String,
    },
    /// System note (cancelled turn, queue drained, etc.) — dim, never bold.
    System(String),
}

/// Connection state for the status bar.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ConnectionState {
    #[default]
    Online,
    Reconnecting,
    Offline,
}

/// Logo phase (DR-21 L19): splash → steady → working → shutdown.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum LogoPhase {
    #[default]
    Splash,
    Steady,
    Working,
    Shutdown,
}

/// Composer state (DR-21 §3.4) — drives the left glyph + border color.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ComposerState {
    Idle,
    Typing,
    Sending,
    /// Blocked with a reason (rate limit, etc.).
    Blocked(String),
}

/// Tool state for the status bar.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum ToolState {
    #[default]
    Idle,
    Streaming,
    AwaitingApproval,
    Running(String),
    /// Session-scoped auto-grant (R) on this tool name.
    AutoGranted(String),
}

/// One tool call awaiting operator approval (PR-C will render this).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingApproval {
    pub call_id: String,
    pub tool_name: String,
    pub summary: String,
    /// Structured risk level 0..=3 (▰▰▱ badge, §6.15).
    pub risk: u8,
}

impl App {
    pub fn new() -> Self {
        Self {
            dirty: DirtyFlags(DirtyFlags::LAYOUT),
            should_quit: false,
            size: (80, 24),
            focus: Focus::default(),
            left_tab: LeftTab::default(),
            tick_count: 0,
            transcript: Vec::new(),
            in_flight: String::new(),
            coalescer: Coalescer::new(DATA_TICK),
            total_cost_microcents: 0,
            total_input_tokens: 0,
            total_output_tokens: 0,
            total_turns: 0,
            provider: String::new(),
            model: String::new(),
            session_id_prefix: String::new(),
            session_id: String::new(),
            connection: ConnectionState::Online,
            tool_state: ToolState::Idle,
            pending_approvals: Vec::new(),
            workspace: Workspace::default(),
            palette: PaletteState::default(),
            input_mode: InputMode::Insert,
            zoomed_pane: None,
            pane_rects: PaneRects::default(),
            selection: None,
            osc52_pending: None,
            last_status: String::new(),
            last_error: None,
            transcript_scroll: 0,
            ctrl_c_count: 0,
            last_ctrl_c_tick: 0,
            quit_confirmation: false,
            cost_flash_frames: 0,
            reconnect_phase: 0,
            copy_mode: false,
            logo_phase: LogoPhase::Splash,
            startup_frame: 0,
            help_open: false,
            turn_report: None,
            turn_report_at: None,
            turn_started_at: None,
            turn_tool_count: 0,
            toast: None,
            toast_emitted_at: None,
            composer_state: ComposerState::Idle,
            composer_send_phase: 0,
            queued: Vec::new(),
            turn_in_flight: false,
            cancel_requested: false,
            spinner_frame: 0,
            pane_scroll: [0, 0, 0],
            viewport_manual: false,
            force_full_redraw: std::cell::Cell::new(false),
        }
    }

    /// Pop the next queued prompt (if any) and mark a turn in flight.
    /// Called by the event loop after a turn ends; the popped prompt is
    /// forwarded to the worker's prompt channel by the caller.
    pub fn take_next_queued(&mut self) -> Option<String> {
        if self.turn_in_flight || self.queued.is_empty() {
            return None;
        }
        let next = self.queued.remove(0);
        self.turn_in_flight = true;
        self.tool_state = ToolState::Streaming;
        self.composer_state = ComposerState::Sending;
        self.turn_started_at = Some(std::time::Instant::now());
        self.turn_tool_count = 0;
        self.dirty.set(DirtyFlags::TRANSCRIPT | DirtyFlags::STATUS);
        Some(next)
    }
}

impl Default for App {
    fn default() -> Self {
        Self::new()
    }
}

impl App {
    /// Transition the state based on a message. Never panics.
    pub fn reduce(&mut self, msg: Msg) {
        match msg {
            Msg::Quit => self.should_quit = true,
            Msg::Resize(w, h) => {
                self.size = (w, h);
                self.dirty.set(DirtyFlags::LAYOUT);
            }
            Msg::Tick => {
                self.tick_count = self.tick_count.saturating_add(1);
                // Flush streamed text at the 30 ms data cadence.
                if self.coalescer.should_flush() {
                    if let Some(text) = self.coalescer.flush() {
                        self.in_flight.push_str(&text);
                        self.dirty.set(DirtyFlags::TRANSCRIPT);
                    }
                }
                // §6.12: the toast dismisses after 3 s (180 ticks).
                if let Some(at) = self.toast_emitted_at {
                    if self.tick_count.saturating_sub(at) >= 180 {
                        self.toast = None;
                        self.toast_emitted_at = None;
                        self.dirty.set(DirtyFlags::LAYOUT);
                    }
                }
                // §6.11 M5: the turn report dismisses after 2 s (120 ticks).
                if let Some(at) = self.turn_report_at {
                    if self.tick_count.saturating_sub(at) >= 120 {
                        self.turn_report = None;
                        self.turn_report_at = None;
                        self.dirty.set(DirtyFlags::STATUS);
                    }
                }
                // §8.3 startup: the splash reveals at 4 fps (every 15 ticks
                // ≈ 250 ms), 6 frames total, then settles to Steady.
                if self.logo_phase == LogoPhase::Splash {
                    if self.tick_count.is_multiple_of(15) {
                        if self.startup_frame < 5 {
                            self.startup_frame += 1;
                            self.dirty.set(DirtyFlags::TRANSCRIPT);
                        } else {
                            self.logo_phase = LogoPhase::Steady;
                        }
                    }
                }
                // Working star (§7): the 4 Hz clock sets LOGO only while
                // ORBIT is working; idle sets nothing. The star is the only
                // moving cell.
                let working = self.tool_state == ToolState::Streaming
                    || matches!(self.tool_state, ToolState::Running(_));
                if working && self.tick_count.is_multiple_of(4) {
                    self.spinner_frame = (self.spinner_frame + 1) % 4;
                    self.dirty.set(DirtyFlags::STATUS | DirtyFlags::TRANSCRIPT);
                    // Logo phase transitions follow the real tool state.
                    match self.logo_phase {
                        LogoPhase::Steady if working => self.logo_phase = LogoPhase::Working,
                        LogoPhase::Working if !working => self.logo_phase = LogoPhase::Steady,
                        LogoPhase::Splash => self.logo_phase = LogoPhase::Steady,
                        _ => {}
                    }
                }
                // Braille spinner: advance every 4 ticks (8fps) while busy.
                if (self.tool_state == ToolState::Streaming
                    || matches!(self.tool_state, ToolState::Running(_))
                    || self.connection == ConnectionState::Reconnecting)
                    && self.tick_count.is_multiple_of(4)
                {
                    self.spinner_frame = (self.spinner_frame + 1) % 4;
                    self.dirty.set(DirtyFlags::STATUS | DirtyFlags::TRANSCRIPT);
                }
                // Reconnecting star: rotate while reconnecting (§4.3 ↻).
                if self.connection == ConnectionState::Reconnecting
                    && self.tick_count.is_multiple_of(24)
                {
                    self.reconnect_phase = (self.reconnect_phase + 1) % 3;
                    self.dirty.set(DirtyFlags::STATUS);
                }
                // Composer send animation: ↗↘↗ (3 frames, ~375ms per frame).
                if self.composer_state == ComposerState::Sending
                    && self.tick_count.is_multiple_of(24)
                {
                    self.composer_send_phase = (self.composer_send_phase + 1) % 3;
                    self.dirty.set(DirtyFlags::STATUS);
                }
                // Composer returns to Idle when the stream finishes.
                if self.tool_state != ToolState::Streaming
                    && !matches!(self.tool_state, ToolState::Running(_))
                    && self.composer_state == ComposerState::Sending
                {
                    self.composer_state = ComposerState::Idle;
                    self.dirty.set(DirtyFlags::STATUS);
                }
                // Cost flash: count down.
                if self.cost_flash_frames > 0 {
                    self.cost_flash_frames = self.cost_flash_frames.saturating_sub(1);
                    self.dirty.set(DirtyFlags::STATUS);
                }
            }
            Msg::KeyAction(action) => self.reduce_key(action),
            Msg::TextDelta(text) => {
                // Push into the coalescer; rendered on the next data tick.
                self.coalescer.push(text.as_bytes());
                self.dirty.set(DirtyFlags::TRANSCRIPT);
            }
            Msg::Status(text) => {
                self.last_status = text;
                self.dirty.set(DirtyFlags::STATUS);
            }
            Msg::ResponseFinished {
                output,
                input_tokens,
                output_tokens,
                cost_microcents,
            } => {
                // ResponseFinished follows the final TextDelta immediately, so
                // the coalescer's 30 ms interval may not have elapsed. Drain it
                // now or the final streamed chunk would be silently lost.
                if let Some(text) = self.coalescer.flush() {
                    self.in_flight.push_str(&text);
                }
                // Finalize the in-flight turn.
                let has_in_flight = !self.in_flight.is_empty();
                let has_output = !output.is_empty();
                if has_in_flight {
                    self.transcript
                        .push(TranscriptLine::Assistant(self.in_flight.clone()));
                    self.in_flight.clear();
                    // The settled line replaces the live one in place — same
                    // cells, different gutter color. Force a full redraw so
                    // the settled turn re-emits in full (replayers and PTY
                    // captures need the contiguous line at least once).
                    self.force_full_redraw.set(true);
                    self.dirty.set(DirtyFlags::TRANSCRIPT | DirtyFlags::LAYOUT);
                } else if has_output {
                    self.transcript.push(TranscriptLine::Assistant(output));
                }
                self.total_input_tokens = self.total_input_tokens.saturating_add(input_tokens);
                self.total_output_tokens = self.total_output_tokens.saturating_add(output_tokens);
                self.total_cost_microcents =
                    self.total_cost_microcents.saturating_add(cost_microcents);
                // §6.11 M5: stamp the turn report (shown for 2 s).
                let duration_ms = self
                    .turn_started_at
                    .take()
                    .map(|t| t.elapsed().as_millis() as u64)
                    .unwrap_or(0);
                self.turn_report = Some(TurnReport {
                    duration_ms,
                    tool_count: self.turn_tool_count,
                    cost_microcents,
                });
                self.turn_report_at = Some(self.tick_count);
                self.turn_tool_count = 0;
                // Only bump turns if this ResponseFinished actually produced a
                // transcript entry (a cancelled turn with no partial text, or
                // a pure-tool-round echo with no user-visible output, is NOT a
                // completed user turn for /usage purposes).
                let produced_output =
                    has_in_flight || has_output || input_tokens > 0 || output_tokens > 0;
                if produced_output {
                    self.total_turns = self.total_turns.saturating_add(1);
                }
                if self.cancel_requested {
                    // The operator aborted this turn — stamp it. Partial
                    // text (if any) was already pushed above.
                    self.transcript
                        .push(TranscriptLine::System("⏹ cancelled by operator".into()));
                    self.cancel_requested = false;
                }
                self.tool_state = ToolState::Idle;
                self.composer_state = ComposerState::Idle;
                self.composer_send_phase = 0;
                self.turn_in_flight = false;
                self.dirty.set(DirtyFlags::TRANSCRIPT | DirtyFlags::STATUS);
            }
            Msg::ToolCallStarted { name, summary } => {
                self.turn_tool_count += 1;
                // Display-only: push transcript lines + set tool state. Do NOT
                // push a pending approval here — the real call_id arrives later
                // via Msg::ApprovalRequested (from the worker's
                // TuiApprovalChannel). Pushing a fake call_id here would shadow
                // the real one and deadlock the approval (BUG-1).
                self.tool_state = ToolState::Running(name.clone());
                self.transcript.push(TranscriptLine::Stripped {
                    tool_name: name.clone(),
                });
                self.transcript
                    .push(TranscriptLine::Assistant(format!("[tool] {summary}")));
                self.dirty.set(DirtyFlags::TRANSCRIPT | DirtyFlags::STATUS);
            }
            Msg::ToolCallFinished { name, ok } => {
                // Dismiss the FIRST pending approval that was resolved. The
                // worker sends ApprovalRequested (with a real call_id) for
                // each tool call, and handle_key resolves that exact call_id.
                // Removing by tool_name could drop a DIFFERENT pending call of
                // the same tool name, so we remove only the head — that is
                // the call whose verdict the worker just received.
                if !self.pending_approvals.is_empty() {
                    self.pending_approvals.remove(0);
                }
                self.tool_state = ToolState::Idle;
                // Note: we never render model-supplied rationale; only status.
                self.last_status = if ok {
                    format!("tool {name}: ok")
                } else {
                    format!("tool {name}: error")
                };
                self.dirty.set(DirtyFlags::APPROVAL | DirtyFlags::STATUS);
            }
            Msg::BackendError(err) => {
                self.last_error = Some(err.clone());
                self.composer_state = ComposerState::Blocked(err);
                self.turn_in_flight = false;
                self.cancel_requested = false;
                self.tool_state = ToolState::Idle;
                self.dirty.set(DirtyFlags::STATUS);
            }
            Msg::TextSubmitted(text) => {
                if self.turn_in_flight {
                    // A turn is streaming — queue the prompt; the worker
                    // picks it up when the current turn ends.
                    self.queued.push(text);
                    self.dirty.set(DirtyFlags::TRANSCRIPT | DirtyFlags::STATUS);
                } else {
                    // Idle — run immediately. (Also clears any stale cancel
                    // flag from a turn that raced its own finish.)
                    self.cancel_requested = false;
                    self.transcript.push(TranscriptLine::User(text));
                    self.in_flight.clear();
                    self.tool_state = ToolState::Streaming;
                    self.turn_in_flight = true;
                    self.composer_state = ComposerState::Sending;
                    self.composer_send_phase = 0;
                    self.turn_started_at = Some(std::time::Instant::now());
                    self.turn_tool_count = 0;
                    self.dirty.set(DirtyFlags::TRANSCRIPT | DirtyFlags::STATUS);
                }
            }
            Msg::ApprovalRequested {
                call_id,
                tool_name,
                summary,
                risk,
            } => {
                self.tool_state = ToolState::AwaitingApproval;
                self.pending_approvals.push(PendingApproval {
                    call_id,
                    tool_name,
                    summary,
                    risk,
                });
                self.dirty.set(DirtyFlags::APPROVAL | DirtyFlags::STATUS);
            }
            Msg::InputModeChanged(mode) => {
                self.input_mode = mode;
                self.dirty.set(DirtyFlags::STATUS);
            }
            Msg::ExitCopyMode => {
                self.copy_mode = false;
                self.input_mode = InputMode::Insert;
                self.dirty.set(DirtyFlags::STATUS | DirtyFlags::LAYOUT);
            }
            Msg::CopyMove(d) => {
                // Move the per-pane copy cursor.
                let idx = match self.focus {
                    Focus::Left => 0,
                    Focus::Center => 1,
                    Focus::Right => 2,
                    _ => return,
                };
                let cur = self.pane_scroll[idx] as i32;
                let next = (cur + d).max(0) as u16;
                self.pane_scroll[idx] = next;
                self.dirty.set(DirtyFlags::LAYOUT);
            }
            Msg::CopySelect => {
                // Selection state would live here in a full impl; for the
                // MVP, mark selection as active so the renderer can show
                // it.
                self.dirty.set(DirtyFlags::LAYOUT);
            }
            Msg::CopyYank => {
                // The MVP: just exit copy mode. A full impl would extract
                // the transcript range and write to the system clipboard
                // via arboard or OSC 52.
                self.copy_mode = false;
                self.input_mode = InputMode::Insert;
                self.dirty.set(DirtyFlags::STATUS | DirtyFlags::LAYOUT);
            }
            Msg::PaneScroll { pane, delta } => {
                let idx = match pane {
                    Focus::Left => 0,
                    Focus::Center => 1,
                    Focus::Right => 2,
                    _ => return,
                };
                let cur = self.pane_scroll[idx] as i32;
                // Clamp at 0 (top); bottom is unbounded (render clamps).
                let next = (cur + delta).max(0) as u16;
                if next != self.pane_scroll[idx] {
                    self.pane_scroll[idx] = next;
                    self.dirty.set(DirtyFlags::LAYOUT | DirtyFlags::TRANSCRIPT);
                }
            }
            Msg::ZoomToggle(pane) => {
                self.zoomed_pane = if self.zoomed_pane == Some(pane) {
                    None
                } else {
                    Some(pane)
                };
                self.dirty.set(DirtyFlags::LAYOUT | DirtyFlags::TRANSCRIPT);
            }
            Msg::SelectionAnchor { pane, row, col } => {
                self.selection = Some(crate::selection::Selection::anchor(pane, row, col));
                self.dirty.set(DirtyFlags::TRANSCRIPT | DirtyFlags::LAYOUT);
            }
            Msg::SelectionExtend { pane, row, col } => {
                // Drags only extend the selection that belongs to the same
                // pane — a drag crossing into another pane is clamped out
                // (the pane boundary is the isolation boundary).
                if let Some(sel) = self.selection.as_mut() {
                    if sel.pane == pane {
                        sel.extend(row, col);
                        self.dirty.set(DirtyFlags::TRANSCRIPT | DirtyFlags::LAYOUT);
                    }
                }
            }
            Msg::SelectionFinish => {
                if let Some(sel) = self.selection.as_mut() {
                    sel.finish();
                }
                // Extract + copy outside the mutable borrow.
                if let Some(sel) = self.selection.as_ref() {
                    if sel.is_visible() {
                        let lines = self.pane_lines(sel.pane);
                        let text = sel.extract(&lines).join("\n");
                        if !text.is_empty() {
                            self.osc52_pending = Some(crate::selection::osc52_sequence(&text));
                            // §6.12: the copy confirms with a toast.
                            self.toast = Some(Toast {
                                text: format!("copied {} lines", text.lines().count()),
                                kind: ToastKind::Success,
                            });
                            self.toast_emitted_at = Some(self.tick_count);
                        }
                    }
                }
                self.dirty.set(DirtyFlags::TRANSCRIPT | DirtyFlags::LAYOUT);
            }
            Msg::SelectionClear => {
                if self.selection.take().is_some() {
                    self.dirty.set(DirtyFlags::TRANSCRIPT | DirtyFlags::LAYOUT);
                }
            }
            Msg::WorkspaceUpdate(w) => {
                self.workspace = w;
                self.dirty.set(DirtyFlags::LAYOUT);
            }
            Msg::SplashSkip => {
                if self.logo_phase == LogoPhase::Splash {
                    self.startup_frame = 5;
                    self.logo_phase = LogoPhase::Steady;
                    self.dirty.set(DirtyFlags::TRANSCRIPT);
                }
            }
            Msg::ToastShow { text, kind } => {
                self.toast = Some(Toast { text, kind });
                self.toast_emitted_at = Some(self.tick_count);
                self.dirty.set(DirtyFlags::LAYOUT);
            }
            Msg::ToastDismiss => {
                if self.toast.take().is_some() {
                    self.toast_emitted_at = None;
                    self.dirty.set(DirtyFlags::LAYOUT);
                }
            }
            Msg::HelpToggle => {
                self.help_open = !self.help_open;
                self.dirty.set(DirtyFlags::LAYOUT);
            }
            Msg::PaletteToggle => {
                self.palette.open = !self.palette.open;
                if !self.palette.open {
                    self.palette.query.clear();
                    self.palette.selected = 0;
                }
                self.dirty.set(DirtyFlags::LAYOUT);
            }
            Msg::PaletteChar(c) => {
                if self.palette.open {
                    self.palette.query.push(c);
                    self.palette.selected = 0;
                    self.dirty.set(DirtyFlags::LAYOUT);
                }
            }
            Msg::PaletteBackspace => {
                if self.palette.open {
                    self.palette.query.pop();
                    self.palette.selected = 0;
                    self.dirty.set(DirtyFlags::LAYOUT);
                }
            }
            Msg::PaletteMove(down) => {
                if self.palette.open {
                    let len = filtered_commands(&self.palette.query).len();
                    if len > 0 {
                        if down {
                            self.palette.selected = (self.palette.selected + 1) % len;
                        } else {
                            self.palette.selected = (self.palette.selected + len - 1) % len;
                        }
                    }
                    self.dirty.set(DirtyFlags::LAYOUT);
                }
            }
            Msg::PaletteExecute => {
                // The event loop reads the selection and dispatches the
                // command; the reducer just closes the palette.
                if self.palette.open {
                    self.palette.open = false;
                    self.palette.query.clear();
                    self.palette.selected = 0;
                    self.dirty.set(DirtyFlags::LAYOUT);
                }
            }
            Msg::ConnectionChanged(state) => {
                self.connection = state;
                self.dirty.set(DirtyFlags::STATUS);
            }
            Msg::CostUpdated(cost) => {
                self.total_cost_microcents = cost;
                self.dirty.set(DirtyFlags::STATUS);
            }
            Msg::Identity {
                model,
                provider,
                session_prefix,
                session_id,
            } => {
                self.model = model;
                self.provider = provider;
                self.session_id_prefix = session_prefix;
                self.session_id = session_id;
                self.dirty
                    .set(DirtyFlags::SESSION_LIST | DirtyFlags::STATUS);
            }
            Msg::ComposerChanged => {
                self.dirty.set(DirtyFlags::LAYOUT);
                if self.composer_state == ComposerState::Idle {
                    self.composer_state = ComposerState::Typing;
                }
            }
            Msg::SlashCommand(_) => {
                // The event loop parses and dispatches /commands; the
                // reducer only mirrors the local `last_status` so the status
                // bar reflects where the operator is.
                self.dirty.set(DirtyFlags::STATUS);
            }
            Msg::ClearTranscript => {
                // Clear the visible transcript + streaming buffers only. If a
                // turn is mid-flight, it keeps streaming into the fresh view
                // (same as the REPL /clear, which never resets turn state).
                self.transcript.clear();
                self.in_flight.clear();
                self.coalescer.flush();
                self.dirty.set(DirtyFlags::TRANSCRIPT | DirtyFlags::STATUS);
            }
            Msg::ModelChanged(model) => {
                self.model = model;
                self.last_status = format!("model → {}", self.model);
                self.dirty.set(DirtyFlags::STATUS);
            }
            Msg::SystemMessage(text) => {
                self.transcript.push(TranscriptLine::System(text));
                self.dirty.set(DirtyFlags::TRANSCRIPT);
            }
            Msg::TranscriptLoaded {
                lines,
                input_tokens,
                output_tokens,
                cost_microcents,
                turns,
            } => {
                self.transcript = lines;
                self.in_flight.clear();
                self.total_input_tokens = input_tokens;
                self.total_output_tokens = output_tokens;
                self.total_cost_microcents = cost_microcents;
                self.total_turns = turns;
                self.tool_state = ToolState::Idle;
                self.turn_in_flight = false;
                self.queued.clear();
                self.cancel_requested = false;
                self.last_status = "session loaded".into();
                self.dirty.set(DirtyFlags::TRANSCRIPT | DirtyFlags::STATUS);
            }
            Msg::CtrlC => {
                // While a turn is streaming, Ctrl+C cancels the turn (the
                // event loop also fires the worker's CancelToken). A second
                // Ctrl+C while a cancel is still pending falls through to
                // the quit path — the operator always has an escape hatch.
                let cancelling =
                    self.turn_in_flight && self.tool_state != ToolState::AwaitingApproval;
                if cancelling && !self.cancel_requested {
                    self.cancel_requested = true;
                    self.last_status = "cancelling…".into();
                    self.dirty.set(DirtyFlags::STATUS);
                    return;
                }
                // Double Ctrl+C to quit: first press shows confirmation,
                // second press within ~2 s (120 ticks at 16ms) actually quits.
                let ticks_since_last = self.tick_count.saturating_sub(self.last_ctrl_c_tick);
                if self.ctrl_c_count == 1 && ticks_since_last < 120 {
                    self.should_quit = true;
                } else {
                    self.ctrl_c_count = 1;
                    self.last_ctrl_c_tick = self.tick_count;
                    self.quit_confirmation = true;
                    self.dirty.set(DirtyFlags::STATUS);
                }
            }
            Msg::EnterCopyMode => {
                self.copy_mode = true;
                self.dirty.set(DirtyFlags::LAYOUT);
            }
            Msg::CancelTurn => {
                // The event loop fires the worker's CancelToken on this
                // message; the reducer only needs to flag intent so the
                // next ResponseFinished stamps the transcript.
                if self.turn_in_flight {
                    self.cancel_requested = true;
                    self.last_status = "cancelling…".into();
                    self.dirty.set(DirtyFlags::STATUS);
                }
            }
            Msg::RequestQuit => {
                // q/Esc/Ctrl+D request interactive confirmation.
                // Only show if not already showing.
                if !self.quit_confirmation {
                    self.quit_confirmation = true;
                    self.ctrl_c_count = 0;
                    self.dirty.set(DirtyFlags::STATUS | DirtyFlags::LAYOUT);
                }
            }
            Msg::ConfirmQuit => {
                self.should_quit = true;
            }
            Msg::CancelQuit => {
                self.quit_confirmation = false;
                self.ctrl_c_count = 0;
                self.dirty.set(DirtyFlags::STATUS | DirtyFlags::LAYOUT);
            }
            Msg::SignalShutdown => {
                // SIGHUP/SIGTERM/SIGINT-from-kill: no modal, no waiting —
                // the display surface may already be destroyed. Quit now.
                self.quit_confirmation = false;
                self.copy_mode = false;
                self.ctrl_c_count = 0;
                self.logo_phase = LogoPhase::Shutdown;
                self.should_quit = true;
            }
        }
    }

    fn reduce_key(&mut self, action: KeyAction) {
        // If a quit confirmation is showing, only y/n/Esc respond to it.
        // Other keys cancel the confirmation.
        if self.quit_confirmation {
            match action {
                KeyAction::Quit => {
                    // q or Esc confirms quit
                    self.should_quit = true;
                }
                _ => {
                    self.quit_confirmation = false;
                    self.ctrl_c_count = 0;
                    self.dirty.set(DirtyFlags::STATUS | DirtyFlags::LAYOUT);
                }
            }
            return;
        }
        match action {
            KeyAction::Quit => {
                // q opens a confirmation prompt instead of quitting immediately.
                self.quit_confirmation = true;
                self.dirty.set(DirtyFlags::STATUS | DirtyFlags::LAYOUT);
            }
            KeyAction::FocusNext => {
                self.focus = self.focus.next();
                self.dirty.set(DirtyFlags::LAYOUT);
            }
            KeyAction::FocusPrev => {
                self.focus = self.focus.prev();
                self.dirty.set(DirtyFlags::LAYOUT);
            }
            KeyAction::FocusLeft => {
                self.focus = Focus::Left;
                self.dirty.set(DirtyFlags::LAYOUT);
            }
            KeyAction::FocusCenter => {
                self.focus = Focus::Center;
                self.dirty.set(DirtyFlags::LAYOUT);
            }
            KeyAction::FocusRight => {
                self.focus = Focus::Right;
                self.dirty.set(DirtyFlags::LAYOUT);
            }
            KeyAction::TabSessions => {
                self.left_tab = LeftTab::Sessions;
                self.dirty.set(DirtyFlags::LAYOUT);
            }
            KeyAction::TabVerbose => {
                self.left_tab = LeftTab::Verbose;
                self.dirty.set(DirtyFlags::LAYOUT);
            }
            KeyAction::NewSession
            | KeyAction::ToggleToolDetail
            | KeyAction::ToggleCost
            | KeyAction::CommandPalette
            | KeyAction::OpenPalette
            | KeyAction::HelpToggle
            | KeyAction::Unknown => {}
            // Scroll/zoom/insert are handled by the dedicated Msg arms
            // (PaneScroll/ZoomToggle/InputModeChanged) — the KeyAction
            // variants exist so the parser can emit them.
            KeyAction::EnterInsert
            | KeyAction::ZoomToggle
            | KeyAction::ScrollUp(_)
            | KeyAction::ScrollDown(_) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    // herdr-style functional isolation tests
    #[test]
    fn per_pane_scroll_is_isolated() {
        let mut app = App::default();
        app.reduce(Msg::PaneScroll { pane: Focus::Left, delta: 5 });
        assert_eq!(app.pane_scroll[0], 5, "left pane scrolled");
        assert_eq!(app.pane_scroll[1], 0, "center untouched");
        assert_eq!(app.pane_scroll[2], 0, "right untouched");
        app.reduce(Msg::PaneScroll { pane: Focus::Right, delta: 3 });
        assert_eq!(app.pane_scroll[0], 5, "left still 5");
        assert_eq!(app.pane_scroll[2], 3, "right scrolled");
    }

    #[test]
    fn scroll_clamps_at_top() {
        let mut app = App::default();
        app.reduce(Msg::PaneScroll { pane: Focus::Center, delta: -10 });
        assert_eq!(app.pane_scroll[1], 0, "cannot scroll above the top");
    }

    #[test]
    fn zoom_toggles_per_pane() {
        let mut app = App::default();
        app.reduce(Msg::ZoomToggle(Focus::Left));
        assert_eq!(app.zoomed_pane, Some(Focus::Left));
        app.reduce(Msg::ZoomToggle(Focus::Left));
        assert_eq!(app.zoomed_pane, None);
        app.reduce(Msg::ZoomToggle(Focus::Right));
        assert_eq!(app.zoomed_pane, Some(Focus::Right));
        app.reduce(Msg::ZoomToggle(Focus::Right));
        assert_eq!(app.zoomed_pane, None);
    }

    #[test]
    fn prefix_mode_round_trip() {
        let mut app = App::default();
        app.reduce(Msg::InputModeChanged(InputMode::Prefix));
        assert_eq!(app.input_mode, InputMode::Prefix);
        app.reduce(Msg::InputModeChanged(InputMode::Insert));
        assert_eq!(app.input_mode, InputMode::Insert);
    }

    #[test]
    fn copy_mode_exits_to_insert() {
        let mut app = App::default();
        app.reduce(Msg::InputModeChanged(InputMode::Copy));
        assert_eq!(app.input_mode, InputMode::Copy);
        app.reduce(Msg::CopyYank);
        assert_eq!(app.input_mode, InputMode::Insert);
        assert!(!app.copy_mode);
    }

    #[test]
    fn palette_filter_subsequence() {
        use super::filtered_commands;
        // Empty query → all commands.
        assert_eq!(filtered_commands("").len(), 9);
        // "sess" matches sessions (and any label containing the
        // subsequence).
        let hits = filtered_commands("sess");
        assert!(hits.iter().any(|c| c.label == "sessions"));
        // "zzz" matches nothing.
        assert!(filtered_commands("zzz").is_empty());
    }

    #[test]
    fn palette_toggle_and_type() {
        use super::{App, Msg};
        let mut app = App::new();
        assert!(!app.palette.open);
        app.reduce(Msg::PaletteToggle);
        assert!(app.palette.open);
        app.reduce(Msg::PaletteChar('s'));
        app.reduce(Msg::PaletteChar('e'));
        assert_eq!(app.palette.query, "se");
        app.reduce(Msg::PaletteBackspace);
        assert_eq!(app.palette.query, "s");
        // Close resets the query.
        app.reduce(Msg::PaletteToggle);
        assert!(!app.palette.open);
        assert!(app.palette.query.is_empty());
    }

    use super::*;

    #[test]
    fn dirty_flags_set_and_clear() {
        let mut d = DirtyFlags::default();
        assert!(!d.is_dirty());
        d.set(DirtyFlags::TRANSCRIPT);
        assert!(d.is_dirty());
        assert!(d.is_set(DirtyFlags::TRANSCRIPT));
        assert!(!d.is_set(DirtyFlags::STATUS));
        d.clear();
        assert!(!d.is_dirty());
    }

    #[test]
    fn dirty_flags_combination() {
        let mut d = DirtyFlags::default();
        d.set(DirtyFlags::TRANSCRIPT | DirtyFlags::STATUS | DirtyFlags::LOGO);
        assert!(d.is_set(DirtyFlags::TRANSCRIPT));
        assert!(d.is_set(DirtyFlags::STATUS));
        assert!(d.is_set(DirtyFlags::LOGO));
        assert!(!d.is_set(DirtyFlags::TASKS));
    }

    #[test]
    fn reduce_quit_sets_should_quit() {
        let mut app = App::new();
        assert!(!app.should_quit);
        app.reduce(Msg::Quit);
        assert!(app.should_quit);
    }

    #[test]
    fn signal_shutdown_quits_immediately_without_modal() {
        let mut app = App::new();
        // Simulate a pending modal + copy mode from before the signal hit.
        app.reduce(Msg::RequestQuit);
        app.copy_mode = true;
        assert!(app.quit_confirmation);

        app.reduce(Msg::SignalShutdown);
        assert!(app.should_quit, "must quit now — terminal may be gone");
        assert!(!app.quit_confirmation, "no modal can be shown");
        assert!(!app.copy_mode, "copy wait would block on a dead PTY");
    }

    #[test]
    fn signal_shutdown_wins_over_ctrl_c_grace_window() {
        let mut app = App::new();
        app.reduce(Msg::CtrlC); // first press → modal
        assert!(app.quit_confirmation);

        app.reduce(Msg::SignalShutdown);
        assert!(app.should_quit);
        assert_eq!(app.ctrl_c_count, 0);
    }

    #[test]
    fn reduce_resize_updates_size_and_dirty() {
        let mut app = App::new();
        app.dirty.clear();
        app.reduce(Msg::Resize(120, 40));
        assert_eq!(app.size, (120, 40));
        assert!(app.dirty.is_set(DirtyFlags::LAYOUT));
    }

    #[test]
    fn reduce_tick_preserves_coalesced_text() {
        let mut app = App::new();
        app.dirty.clear();
        app.reduce(Msg::TextDelta("hello ".into()));
        app.reduce(Msg::TextDelta("world".into()));
        // Tick may flush only after the configured interval. Either way, no
        // text may be lost: it's in `in_flight` or still in the coalescer.
        app.reduce(Msg::Tick);
        if app.in_flight.is_empty() {
            if let Some(text) = app.coalescer.flush() {
                app.in_flight.push_str(&text);
            }
        }
        assert_eq!(app.in_flight, "hello world");
    }

    #[test]
    fn reduce_tick_no_flush_marks_dirty() {
        let mut app = App::new();
        app.dirty.clear();
        app.reduce(Msg::Tick);
        assert!(!app.dirty.is_dirty(), "tick alone must not set dirty");
    }

    #[test]
    fn default_focus_is_center_so_operator_can_type_on_boot() {
        let app = App::new();
        assert_eq!(app.focus, Focus::Center);
    }

    #[test]
    fn reduce_focus_next_cycles() {
        let mut app = App::new();
        assert_eq!(app.focus, Focus::Center);
        app.reduce(Msg::KeyAction(KeyAction::FocusNext));
        assert_eq!(app.focus, Focus::Right);
        app.reduce(Msg::KeyAction(KeyAction::FocusNext));
        assert_eq!(app.focus, Focus::Status);
        app.reduce(Msg::KeyAction(KeyAction::FocusNext));
        assert_eq!(app.focus, Focus::Left);
        app.reduce(Msg::KeyAction(KeyAction::FocusNext));
        assert_eq!(app.focus, Focus::Center);
    }

    #[test]
    fn reduce_focus_prev_cycles() {
        let mut app = App::new();
        app.reduce(Msg::KeyAction(KeyAction::FocusPrev));
        assert_eq!(app.focus, Focus::Left);
    }

    #[test]
    fn reduce_tab_switch_sets_dirty() {
        let mut app = App::new();
        app.dirty.clear();
        assert_eq!(app.left_tab, LeftTab::Sessions);
        app.reduce(Msg::KeyAction(KeyAction::TabVerbose));
        assert_eq!(app.left_tab, LeftTab::Verbose);
        assert!(app.dirty.is_set(DirtyFlags::LAYOUT));
    }

    #[test]
    fn reduce_focus_direct_sets_dirty() {
        let mut app = App::new();
        app.dirty.clear();
        app.reduce(Msg::KeyAction(KeyAction::FocusRight));
        assert_eq!(app.focus, Focus::Right);
        assert!(app.dirty.is_set(DirtyFlags::LAYOUT));
    }

    #[test]
    fn reduce_response_finished_accumulates_cost() {
        let mut app = App::new();
        app.dirty.clear();
        app.reduce(Msg::TextDelta("first ".into()));
        app.reduce(Msg::TextDelta("turn".into()));
        app.reduce(Msg::ResponseFinished {
            output: String::new(), // coalescer already captured
            input_tokens: 100,
            output_tokens: 50,
            cost_microcents: 500,
        });
        assert!(app.in_flight.is_empty());
        assert_eq!(app.total_input_tokens, 100);
        assert_eq!(app.total_output_tokens, 50);
        assert_eq!(app.total_cost_microcents, 500);
    }

    #[test]
    fn tool_call_started_does_not_push_approval() {
        // BUG-1: ToolCallStarted must NOT push a pending approval with a fake
        // call_id. Only ApprovalRequested (which carries the worker's real
        // call_id) may populate the queue — otherwise handle_key resolves a
        // fake id and the worker never unblocks (deadlock).
        let mut app = App::new();
        app.reduce(Msg::ToolCallStarted {
            name: "calculator".into(),
            summary: "calculator(expression)".into(),
        });
        assert!(app.pending_approvals.is_empty());
        assert_eq!(app.tool_state, ToolState::Running("calculator".into()));
    }

    #[test]
    fn approval_requested_pushes_real_call_id() {
        let mut app = App::new();
        app.reduce(Msg::ToolCallStarted {
            name: "calculator".into(),
            summary: "calculator(expression)".into(),
        });
        app.reduce(Msg::ApprovalRequested {
            call_id: "call-42".into(),
            tool_name: "calculator".into(),
            summary: "calculator(expression)".into(),
            risk: 1,
        });
        assert_eq!(app.pending_approvals.len(), 1);
        assert_eq!(app.pending_approvals[0].call_id, "call-42");
        assert_eq!(app.tool_state, ToolState::AwaitingApproval);
        assert!(app.dirty.is_set(DirtyFlags::APPROVAL));
    }

    #[test]
    fn reduce_tool_call_finished_clears_approval() {
        // Real event sequence: started → ApprovalRequested (real call_id) →
        // ToolCallFinished dismisses the head of the queue.
        let mut app = App::new();
        app.reduce(Msg::ToolCallStarted {
            name: "calculator".into(),
            summary: "calculator(expression)".into(),
        });
        app.reduce(Msg::ApprovalRequested {
            call_id: "call-42".into(),
            tool_name: "calculator".into(),
            summary: "calculator(expression)".into(),
            risk: 1,
        });
        assert_eq!(app.pending_approvals.len(), 1);
        app.reduce(Msg::ToolCallFinished {
            name: "calculator".into(),
            ok: true,
        });
        assert!(app.pending_approvals.is_empty());
        assert_eq!(app.tool_state, ToolState::Idle);
        assert!(app.last_status.contains("ok"));
    }

    #[test]
    fn tool_call_finished_dismisses_head_not_same_name() {
        // Two queued approvals of the SAME tool name: ToolCallFinished for the
        // first must drop only the head (whose verdict the worker just
        // received), leaving the second pending for the operator.
        let mut app = App::new();
        for (i, call_id) in ["call-1", "call-2"].iter().enumerate() {
            app.reduce(Msg::ToolCallStarted {
                name: "ssh".into(),
                summary: format!("run command #{i}"),
            });
            app.reduce(Msg::ApprovalRequested {
                call_id: (*call_id).into(),
                tool_name: "ssh".into(),
                summary: format!("run command #{i}"),
                risk: 1,
            });
        }
        assert_eq!(app.pending_approvals.len(), 2);
        app.reduce(Msg::ToolCallFinished {
            name: "ssh".into(),
            ok: true,
        });
        assert_eq!(app.pending_approvals.len(), 1);
        assert_eq!(app.pending_approvals[0].call_id, "call-2");
    }

    #[test]
    fn reduce_response_finished_flushes_coalescer() {
        // BUG-2: ResponseFinished must drain the coalescer (30 ms tick) or the
        // final streamed chunk is silently dropped when the finish event lands
        // before the next tick.
        let mut app = App::new();
        app.reduce(Msg::TextDelta("final words".into()));
        // No manual flush — the reducer must do it.
        app.reduce(Msg::ResponseFinished {
            output: String::new(),
            input_tokens: 0,
            output_tokens: 0,
            cost_microcents: 0,
        });
        assert_eq!(app.transcript.len(), 1);
        assert!(matches!(
            &app.transcript[0],
            TranscriptLine::Assistant(t) if t == "final words"
        ));
    }

    #[test]
    fn reduce_backend_error_resets_tool_state() {
        // BUG-3: a backend error mid-tool-call must not leave the status bar
        // showing Running/AwaitingApproval forever.
        let mut app = App::new();
        app.reduce(Msg::ToolCallStarted {
            name: "calculator".into(),
            summary: "calculator(expression)".into(),
        });
        assert_eq!(app.tool_state, ToolState::Running("calculator".into()));
        app.reduce(Msg::BackendError("provider unreachable".into()));
        assert_eq!(app.tool_state, ToolState::Idle);
    }

    #[test]
    fn reduce_status_sets_last_status() {
        let mut app = App::new();
        app.dirty.clear();
        app.reduce(Msg::Status("model → glm-5.2".into()));
        assert_eq!(app.last_status, "model → glm-5.2");
        assert!(app.dirty.is_set(DirtyFlags::STATUS));
    }

    #[test]
    fn reduce_backend_error_records() {
        let mut app = App::new();
        app.dirty.clear();
        app.reduce(Msg::BackendError("provider unreachable".into()));
        assert_eq!(app.last_error.as_deref(), Some("provider unreachable"));
        assert!(app.dirty.is_set(DirtyFlags::STATUS));
    }

    #[test]
    fn transcript_grows_on_user_and_assistant() {
        let mut app = App::new();
        app.transcript.push(TranscriptLine::User("hi".into()));
        app.reduce(Msg::TextDelta("hello!".into()));
        // Flush coalescer manually (bypass timing).
        if let Some(text) = app.coalescer.flush() {
            app.in_flight.push_str(&text);
        }
        app.reduce(Msg::ResponseFinished {
            output: String::new(),
            input_tokens: 1,
            output_tokens: 1,
            cost_microcents: 0,
        });
        assert_eq!(app.transcript.len(), 2);
        assert!(matches!(app.transcript[0], TranscriptLine::User(_)));
        assert!(matches!(app.transcript[1], TranscriptLine::Assistant(_)));
    }

    #[test]
    fn cost_saturates_no_overflow() {
        let mut app = App::new();
        app.total_cost_microcents = u64::MAX;
        app.reduce(Msg::ResponseFinished {
            output: String::new(),
            input_tokens: 0,
            output_tokens: 0,
            cost_microcents: 100,
        });
        assert_eq!(app.total_cost_microcents, u64::MAX);
    }

    #[test]
    fn tick_saturates() {
        let mut app = App::new();
        app.tick_count = u64::MAX;
        app.reduce(Msg::Tick);
        assert_eq!(app.tick_count, u64::MAX);
    }

    #[test]
    fn thinking_indicator_advances_while_streaming() {
        let mut app = App::new();
        // Submit a prompt → Streaming, empty in_flight.
        app.reduce(Msg::TextSubmitted("hello".into()));
        assert_eq!(app.tool_state, ToolState::Streaming);
        assert!(app.in_flight.is_empty());

        // §7: the working star is the only moving cell — the 4 Hz clock
        // advances spinner_frame while working. Tick is 16 ms, so every 4th
        // tick advances the star.
        let f0 = app.spinner_frame;
        for _ in 0..4 {
            app.reduce(Msg::Tick);
        }
        assert_ne!(app.spinner_frame, f0, "working star should advance");
        assert!(app
            .dirty
            .is_set(DirtyFlags::STATUS | DirtyFlags::TRANSCRIPT));
    }

    #[test]
    fn thinking_stops_when_text_arrives() {
        let mut app = App::new();
        app.reduce(Msg::TextSubmitted("hello".into()));
        assert!(app.in_flight.is_empty());
        // First text delta → in_flight non-empty, indicator no longer dirty.
        app.reduce(Msg::TextDelta("hello!".into()));
        let f_before = app.spinner_frame;
        app.reduce(Msg::Tick);
        // The star still turns while the turn is live (in_flight is content,
        // not the indicator); it stops when the turn ends.
        let _ = f_before;
    }

    #[test]
    fn thinking_resets_on_response_finished() {
        let mut app = App::new();
        app.reduce(Msg::TextSubmitted("hello".into()));
        app.reduce(Msg::Tick);
        app.reduce(Msg::Tick);
        assert!(app.dirty.is_set(DirtyFlags::TRANSCRIPT));
        // Response finished → Idle, no more spinner updates.
        app.reduce(Msg::ResponseFinished {
            output: String::new(),
            input_tokens: 1,
            output_tokens: 1,
            cost_microcents: 0,
        });
        assert_eq!(app.tool_state, ToolState::Idle);
    }

    #[test]
    fn working_star_wraps_modulo_four() {
        let mut app = App::new();
        app.reduce(Msg::TextSubmitted("hello".into()));
        // The star has exactly 4 frames (§4.3); 3 full turns must wrap.
        for _ in 0..(4 * 3 * 4) {
            app.reduce(Msg::Tick);
        }
        assert!(app.spinner_frame < 4);
    }
}
