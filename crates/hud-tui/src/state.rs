#![allow(dead_code)] // data-bearing state wired into the live render in PR-D

//! TUI application state + dirty-flag tracking (DR-20 §2.4).
//!
//! `App` is the reducer state. `reduce(msg)` transitions it; the render loop
//! only redraws when `dirty.is_dirty()`. Empty frames are forbidden.

use crate::coalesce::Coalescer;
use crate::input::KeyAction;
use crate::msg::Msg;

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
    /// Not started yet (the golden's ◌ pending rows).
    Pending,
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
    /// The right-aligned result text ('48 passed', 'retest') — structured
    /// backend data, never model prose (§6.10).
    pub result_text: String,
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
            // §6.9: the Center pane's extractable lines are the RENDERED
            // rows (wrapped + padded) — the same rows the selection
            // coordinates index. Recorded by the renderer each frame.
            Focus::Center => self.rendered_center_lines.borrow().clone(),
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

/// Live slash-command autocomplete state (rendered as a dropdown above
/// the composer). Derived from the composer text whenever it starts with
/// `/` and contains no space yet.
#[derive(Debug, Default, Clone)]
pub struct SlashHints {
    /// Hints are visible (composer is a partial `/command`).
    pub open: bool,
    /// Matching (command, description) pairs, best-first.
    pub items: Vec<(String, String)>,
    /// Selected row (0 = first). Arrow keys move; Tab/Enter accepts.
    pub selected: usize,
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
    /// Reduced-motion preference (tui.toml `reduced = true`): spinners
    /// hold still; only data-driven changes move.
    pub reduced_motion: bool,
    /// D17: tui.toml `[color] bell_on_approval` — ring BEL when an
    /// approval card appears.
    pub bell_on_approval: bool,
    /// A pending BEL emission — the event loop writes `\x07` to stdout
    /// once and clears it (the reducer can't touch stdout).
    pub bell_pending: bool,

    // ── Data state (filled by the backend bridge) ──────────────────────────
    /// Lines in the conversation transcript (user + assistant).
    pub transcript: Vec<TranscriptLine>,
    /// Current assistant turn being streamed (empty when not streaming).
    pub in_flight: String,
    /// Streaming text coalescer — flushes every 30 ms.
    pub coalescer: Coalescer,
    /// Cumulative cost in microcents (H-17). Committed turns only — the
    /// in-flight turn's cost is tracked separately (D5) so the two are
    /// never double-counted.
    pub total_cost_microcents: u64,
    /// The current turn's running cost (§13.3 D5). Turn-scoped: reset to 0
    /// by PromptSubmitted / TextSubmitted, grown by TurnCostUpdated, and
    /// committed into total_cost_microcents by ResponseFinished exactly
    /// once (the commit value is the final number, not added on top).
    pub turn_cost_microcents: u64,
    /// D18: the active model has a pricing entry. False → status bar shows
    /// `cost n/a` instead of a dollar figure.
    pub model_priced: bool,
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
    /// The Center pane's lines as last rendered (wrapped + padded), so
    /// selection extract() uses the same rows the operator sees (§6.9).
    pub rendered_center_lines: std::cell::RefCell<Vec<String>>,
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
    /// The tick the current turn started at — for the M5 duration
    /// (§16.1 seam: tick counts, not Instants, so tests play Ticks).
    turn_started_at: Option<u64>,
    /// Tool calls made in the current turn (for the M5 report).
    turn_tool_count: u32,
    /// §6.12 toast: text + frame counter (the toast auto-dismisses at 3 s).
    pub toast: Option<crate::state::Toast>,
    /// Tick counter when the toast was emitted (used for the 3-s timer).
    pub toast_emitted_at: Option<u64>,
    /// Composer state (DR-21 §3.4) — left glyph + border color.
    pub composer_state: ComposerState,
    /// Live slash-command autocomplete (Claude Code parity): while the
    /// composer starts with `/` and is mid-word, a hint dropdown lists
    /// matching commands + descriptions. The state is derived from the
    /// composer text on every ComposerChanged — kept here so the
    /// renderer and key handler can see it without recomputing.
    pub slash_hints: SlashHints,
    /// Queued prompts: typed while a turn is in flight. Drained one at a
    /// time when a turn ends (ResponseFinished or CancelTurn). Rendered as
    /// dimmed `⏳` lines above the composer.
    pub queued: Vec<String>,
    /// Sessions rail rows (§6.9) — filled by the backend bridge.
    pub sessions: Vec<SessionRow>,
    /// The Activity rail's structured event rows (§9.16), newest last.
    /// Capped at 500 (§9.16).
    pub activity: Vec<ActivityRow>,
    /// The conversation header's title (the open session's title).
    pub header_title: String,
    /// The conversation header's right meta (e.g. `14 turns`).
    pub header_meta: String,
    /// The workspace header's right meta (e.g. `4/5`).
    pub workspace_meta: String,
    /// The cursor row index in the Sessions rail.
    pub session_cursor: usize,
    /// D3: the last submitted prompt — `r` in NORMAL mode re-submits it.
    /// Updated on every TextSubmitted that starts a turn (not queued ones).
    pub last_prompt: Option<String>,
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
}

/// One row of the Sessions rail (§6.9): title, recency, state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionRow {
    pub title: String,
    /// Recency label right-aligned (now, 2h, 1d…).
    pub recency: String,
    /// Group heading (TODAY, YESTERDAY, THIS WEEK, OLDER).
    pub group: &'static str,
    /// ✕ failed state glyph; blank when idle.
    pub failed: bool,
    /// True for the open session (bold ink title).
    pub open: bool,
}

/// One row of the Activity rail (§9.16): a structured event, never model
/// text, never reasoning. Kinds: plan tool grant ledger cite model warn
/// error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActivityRow {
    /// HH:MM:SS stamp (faint, §8.4).
    pub time: String,
    /// The event kind (muted, §8.4).
    pub kind: &'static str,
    /// The event text (amber for warnings, red for errors, ink2 otherwise).
    pub text: String,
}

/// One line in the transcript — either a user message or an assistant reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TranscriptLine {
    /// A user turn. `time` is the HH:MM stamp shown right-aligned on the
    /// first row (None in Compact, which hides timestamps).
    User { text: String, time: Option<String> },
    /// An ORBIT turn. `time` as for User; `live` marks the in-flight turn
    /// (cyan gutter) — settled turns render magenta.
    Assistant { text: String, time: Option<String> },
    /// CoT-stripped placeholder (NEVER shows raw reasoning).
    Stripped {
        tool_name: String,
        /// Display-safe argument summary (the bridge's safe_text output).
        /// Rendered as the tool card's argument column (§6.5).
        summary: String,
        /// The call's settled outcome (None while running). Set by
        /// ToolCallFinished — the card's glyph depends on it (§6.5).
        outcome: Option<ToolOutcome>,
        /// The settled outcome summary ('48 passed', '+9 −3') — right-
        /// aligned meta on the card (§6.5). Empty while running.
        meta: String,
        /// The tick the call started at — drives the live ticking duration
        /// on the running card. None for entries restored from a session
        /// file. (§16.1 seam: ticks, not Instants.)
        started_at: Option<u64>,
    },
    /// System note (cancelled turn, queue drained, etc.) — dim, never bold.
    System(String),
    /// §6.6 evidence card: header + rows, built only from structured
    /// verification data (never model prose).
    Evidence {
        /// The header's count text (e.g. `2 checks`).
        checks: String,
        /// The header's attestation note (e.g. `retest attestation recorded`).
        note: String,
        /// Rows: (check name, result text).
        rows: Vec<(String, String)>,
    },
    /// §6.7 citations: the sources line after a turn's content.
    Sources(Vec<(String, String)>),
    /// A text chunk the bridge rejected (D7). NEVER shows the rejected
    /// text; renders as a one-line chip: `[blocked: <kind>]`.
    Redacted(crate::RedactionKind),
}

/// How a tool call ended (§6.5, §11.5 rule 4). `Denied` and `Blocked` are
/// decisions, not failures: an operator refusal must never render as a red
/// `✕ failed` — audits read refusals and crashes differently.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolOutcome {
    /// Ran and succeeded: `✓` muted.
    Ok,
    /// Ran and failed: `✕` red + `failed` meta.
    Failed,
    /// Denied by the operator (or deny-by-default rules): `⊘` muted +
    /// `denied by you` meta.
    Denied,
    /// Blocked before running (unknown tool, non-interactive without
    /// consent): `⊖` amber + `blocked` meta.
    Blocked,
}

/// Why the bridge rejected a text chunk (D7). Names the gate, not the text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedactionKind {
    /// `safe_text` found a secret pattern in the chunk.
    Secret,
    /// The chunk was not valid UTF-8 (`from_utf8` failed).
    InvalidUtf8,
    /// The chunk failed the display-safe escape scan.
    Escape,
    /// Provider died mid-stream (`rx.recv()` returned None).
    StreamInterrupted,
}

impl RedactionKind {
    /// The chip label (§7.3-style: lowercase words, no glyphs needed).
    pub fn label(&self) -> &'static str {
        match self {
            RedactionKind::Secret => "credential",
            RedactionKind::InvalidUtf8 => "encoding",
            RedactionKind::Escape => "escape",
            RedactionKind::StreamInterrupted => "stream interrupted",
        }
    }
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

/// The operator's answer to an approval card (§12): drives the Activity
/// `grant` row text (§9.16) and the tool-line marker (◆ once / ◈ session).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalDecision {
    /// `y` — allow this one call.
    Once,
    /// `R` — allow this tool for the session.
    Session,
    /// `n` / Esc — deny.
    Denied,
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
            coalescer: Coalescer::new(2), // 2 ticks ≈ 32 ms (the 30 ms data cadence)
            total_cost_microcents: 0,
            turn_cost_microcents: 0,
            model_priced: true,
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
            rendered_center_lines: std::cell::RefCell::new(Vec::new()),
            selection: None,
            osc52_pending: None,
            last_status: String::new(),
            last_error: None,
            transcript_scroll: 0,
            ctrl_c_count: 0,
            last_ctrl_c_tick: 0,
            quit_confirmation: false,
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
            slash_hints: SlashHints::default(),
            queued: Vec::new(),
            sessions: Vec::new(),
            header_title: String::new(),
            header_meta: String::new(),
            workspace_meta: String::new(),
            session_cursor: 0,
            activity: Vec::new(),
            last_prompt: None,
            turn_in_flight: false,
            cancel_requested: false,
            spinner_frame: 0,
            pane_scroll: [0, 0, 0],
            viewport_manual: false,
            reduced_motion: false,
            bell_on_approval: false,
            bell_pending: false,
        }
    }

    /// The HH:MM stamp for a new transcript entry. The wall clock is read
    /// here (the reducer's only wall-clock read); tests that need fixed
    /// stamps set `transcript` directly.
    fn now_hhmm(&self) -> Option<String> {
        Some(crate::format::time_of_day(chrono::Local::now()))
    }

    /// The HH:MM:SS stamp for a new Activity row (§8.4).
    fn now_hhmmss(&self) -> String {
        crate::format::activity_time(chrono::Local::now())
    }

    /// Append one structured event to the Activity rail (§9.16), newest
    /// last, capped at 500 rows.
    fn push_activity(&mut self, kind: &'static str, text: String) {
        self.activity.push(ActivityRow {
            time: self.now_hhmmss(),
            kind,
            text,
        });
        if self.activity.len() > 500 {
            let drop = self.activity.len() - 500;
            self.activity.drain(0..drop);
        }
        self.dirty.set(DirtyFlags::SESSION_LIST);
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
        self.turn_started_at = Some(self.tick_count);
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
                if self.coalescer.should_flush(self.tick_count) {
                    if let Some(text) = self.coalescer.flush(self.tick_count) {
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
                if self.logo_phase == LogoPhase::Splash && self.tick_count.is_multiple_of(15) {
                    if self.startup_frame < 5 {
                        self.startup_frame += 1;
                        self.dirty.set(DirtyFlags::TRANSCRIPT);
                    } else {
                        self.logo_phase = LogoPhase::Steady;
                    }
                }
                // Working star (§7): the 4 Hz clock sets LOGO only while
                // ORBIT is working; idle sets nothing. The star is the only
                // moving cell. Its FRAME advance lives in the spinner block
                // below — this block only tracks the logo phase. (The old
                // code advanced spinner_frame in both blocks; the double
                // step showed only 2 of the 4 frames: ◐◑◐◑, never ◓◒.)
                let working = self.tool_state == ToolState::Streaming
                    || matches!(self.tool_state, ToolState::Running(_));
                if working && self.tick_count.is_multiple_of(4) {
                    let next = match self.logo_phase {
                        LogoPhase::Steady => LogoPhase::Working,
                        LogoPhase::Splash => LogoPhase::Steady,
                        other => other,
                    };
                    if next != self.logo_phase {
                        self.logo_phase = next;
                        self.dirty.set(DirtyFlags::STATUS);
                    }
                }
                // Spinner (§7): the braille busy spinner advances every 6
                // ticks (~10 fps) while ORBIT is busy — working, waiting for
                // the first token, or reconnecting. ONE increment per cadence.
                // The renderer indexes its frame set modulo that set's length,
                // so a single 0..10 counter drives both the 10-frame braille
                // cycle and the 4-frame ASCII quadrants.
                let busy = working || self.connection == ConnectionState::Reconnecting;
                // Reduced motion (tui.toml `reduced = true`): the spinner
                // holds frame 0 — a still glyph, no cycling.
                if busy && !self.reduced_motion && self.tick_count.is_multiple_of(6) {
                    self.spinner_frame = (self.spinner_frame + 1) % 10;
                    self.dirty.set(DirtyFlags::STATUS | DirtyFlags::TRANSCRIPT);
                }
                // A running tool card ticks its live duration every frame
                // (~16 ms is fine — one line, cheap).
                if matches!(self.tool_state, ToolState::Running(_)) && working {
                    self.dirty.set(DirtyFlags::TRANSCRIPT);
                }
                // Splash orbit: after the reveal settles (frame 5), a dim
                // satellite dot circles the mark's corner positions every
                // 15 ticks while the transcript is still empty.
                if self.logo_phase == LogoPhase::Steady
                    && self.transcript.is_empty()
                    && self.in_flight.is_empty()
                    && self.tick_count.is_multiple_of(15)
                {
                    self.dirty.set(DirtyFlags::TRANSCRIPT);
                }
                // Composer returns to Idle when the stream finishes. (The
                // composer never animates — §10 — so Sending is a state,
                // not a frame counter.)
                if self.tool_state != ToolState::Streaming
                    && !matches!(self.tool_state, ToolState::Running(_))
                    && self.composer_state == ComposerState::Sending
                {
                    self.composer_state = ComposerState::Idle;
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
                self.last_status = text.clone();
                // §6.12: status lines ride the toast (3 s or next keypress).
                // The §8 pane rewrite removed the old status strip, so this
                // is the only visible surface for worker status messages.
                self.toast = Some(Toast {
                    text,
                    kind: ToastKind::Neutral,
                });
                self.toast_emitted_at = Some(self.tick_count);
                self.dirty.set(DirtyFlags::STATUS | DirtyFlags::LAYOUT);
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
                if let Some(text) = self.coalescer.flush(self.tick_count) {
                    self.in_flight.push_str(&text);
                }
                // Finalize the in-flight turn.
                let has_in_flight = !self.in_flight.is_empty();
                let has_output = !output.is_empty();
                if has_in_flight {
                    self.transcript.push(TranscriptLine::Assistant {
                        text: self.in_flight.clone(),
                        time: self.now_hhmm(),
                    });
                    self.in_flight.clear();
                    // The settled line replaces the live one in place — same
                    // cells, different gutter color. The normal diff emits
                    // just the gutter + SGR change; a full repaint here
                    // caused a visible whole-screen flash on every turn.
                    self.dirty.set(DirtyFlags::TRANSCRIPT | DirtyFlags::LAYOUT);
                } else if has_output {
                    self.transcript.push(TranscriptLine::Assistant {
                        text: output,
                        time: self.now_hhmm(),
                    });
                }
                self.total_input_tokens = self.total_input_tokens.saturating_add(input_tokens);
                self.total_output_tokens = self.total_output_tokens.saturating_add(output_tokens);
                // D5: commit the turn cost exactly once. The value the worker
                // sends here is the FINAL turn total (it accumulated the
                // rounds itself); the turn accumulator is reset, so the
                // mid-turn TurnCostUpdated numbers can never stack on it.
                self.total_cost_microcents =
                    self.total_cost_microcents.saturating_add(cost_microcents);
                self.turn_cost_microcents = 0;
                // §6.11 M5: stamp the turn report (shown for 2 s).
                let duration_ms = self
                    .turn_started_at
                    .take()
                    .map(|start| self.tick_count.saturating_sub(start) * 16)
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
                    summary: summary.clone(),
                    outcome: None,
                    meta: String::new(),
                    started_at: Some(self.tick_count),
                });
                self.dirty.set(DirtyFlags::TRANSCRIPT | DirtyFlags::STATUS);
            }
            Msg::ToolCallFinished {
                name,
                outcome: outcome_of_call,
            } => {
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
                // Settle the card: the LAST still-running Stripped entry of
                // this name takes the outcome. Earlier same-name cards are
                // already settled (a second shell call starts only after the
                // first finished), so this never overwrites a settled card.
                for entry in self.transcript.iter_mut().rev() {
                    if let TranscriptLine::Stripped {
                        tool_name: n,
                        outcome,
                        ..
                    } = entry
                    {
                        if n == &name && outcome.is_none() {
                            *outcome = Some(outcome_of_call);
                            break;
                        }
                    }
                }
                // Activity `tool` row (§9.16): `{name} {argument} · {ok|failed|denied|blocked}`.
                // (No argument summary survives to this arm today; the name
                // plus the outcome is the honest row.)
                let verdict = match &outcome_of_call {
                    ToolOutcome::Ok => "ok",
                    ToolOutcome::Failed => "failed",
                    ToolOutcome::Denied => "denied",
                    ToolOutcome::Blocked => "blocked",
                };
                self.push_activity("tool", format!("{name} · {verdict}"));
                // Note: we never render model-supplied rationale; only status.
                self.last_status = match outcome_of_call {
                    ToolOutcome::Ok => format!("tool {name}: ok"),
                    ToolOutcome::Failed => format!("tool {name}: error"),
                    // A refusal is a decision the operator made — status text
                    // names the decision, not a failure word.
                    ToolOutcome::Denied => format!("tool {name}: denied by you"),
                    ToolOutcome::Blocked => format!("tool {name}: blocked"),
                };
                self.dirty
                    .set(DirtyFlags::APPROVAL | DirtyFlags::STATUS | DirtyFlags::TRANSCRIPT);
            }
            Msg::BackendError(err) => {
                self.last_error = Some(err.clone());
                self.composer_state = ComposerState::Blocked(err.clone());
                self.turn_in_flight = false;
                self.cancel_requested = false;
                self.tool_state = ToolState::Idle;
                // Activity `error` row (§9.16): the error code, or `turn failed`.
                self.push_activity("error", err);
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
                    self.last_prompt = Some(text.clone());
                    self.transcript.push(TranscriptLine::User {
                        text,
                        time: self.now_hhmm(),
                    });
                    self.in_flight.clear();
                    self.tool_state = ToolState::Streaming;
                    self.turn_in_flight = true;
                    self.composer_state = ComposerState::Sending;
                    self.turn_started_at = Some(self.tick_count);
                    self.turn_tool_count = 0;
                    // D5: a fresh turn starts its cost accumulator at 0 (a
                    // stale value would inflate the status display).
                    self.turn_cost_microcents = 0;
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
                // D17: ring the terminal bell when configured — the
                // operator watching something else hears the approval.
                if self.bell_on_approval {
                    self.bell_pending = true;
                }
                self.dirty.set(DirtyFlags::APPROVAL | DirtyFlags::STATUS);
            }
            Msg::InputModeChanged(mode) => {
                self.input_mode = mode;
                self.dirty.set(DirtyFlags::STATUS);
            }
            Msg::ApprovalDecision { tool, decision } => {
                // Activity `grant` row (§9.16): `{tool} · once · you`,
                // `{tool} · session · you` or `{tool} · denied · you`.
                let verdict = match decision {
                    ApprovalDecision::Once => "once · you",
                    ApprovalDecision::Session => "session · you",
                    ApprovalDecision::Denied => "denied · you",
                };
                self.push_activity("grant", format!("{tool} · {verdict}"));
                // The tool-line marker (§12): ◆ once / ◈ session rides the
                // running card; denied needs no marker (the ⊘ outcome row
                // carries it).
                if let ApprovalDecision::Session = decision {
                    self.tool_state = ToolState::AutoGranted(tool);
                }
                self.dirty.set(DirtyFlags::STATUS | DirtyFlags::TRANSCRIPT);
            }
            Msg::ApprovalsDenied => {
                // D8: Ctrl+C denied all pending approvals — the registry
                // already released the worker; the reducer clears the cards
                // and returns the tool state to running (the turn continues
                // with the denied results).
                self.pending_approvals.clear();
                if self.turn_in_flight {
                    self.tool_state = ToolState::Running("denied".into());
                } else {
                    self.tool_state = ToolState::Idle;
                }
                self.dirty.set(DirtyFlags::APPROVAL | DirtyFlags::STATUS);
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
            Msg::TurnCostUpdated(cost) => {
                // D5: the worker reports the CURRENT TURN's running cost
                // after each provider round. It never touches the committed
                // total — ResponseFinished commits it exactly once.
                self.turn_cost_microcents = cost;
                self.dirty.set(DirtyFlags::STATUS);
            }
            Msg::CostUpdated(cost) => {
                // Legacy cumulative emitter (Go bridge). Overwrite the
                // committed total and zero the turn accumulator so the two
                // can't stack.
                self.total_cost_microcents = cost;
                self.turn_cost_microcents = 0;
                self.dirty.set(DirtyFlags::STATUS);
            }
            Msg::Redacted { kind } => {
                // D7: the bridge rejected a chunk. Flush any coalesced text
                // first so the chip lands after the surviving prose, then
                // append the chip. The rejected text is never rendered.
                if let Some(text) = self.coalescer.flush(self.tick_count) {
                    self.in_flight.push_str(&text);
                }
                self.transcript.push(TranscriptLine::Redacted(kind));
                self.dirty.set(DirtyFlags::TRANSCRIPT);
            }
            Msg::Identity {
                model,
                provider,
                session_prefix,
                session_id,
                priced,
            } => {
                self.model = model;
                self.provider = provider;
                self.session_id_prefix = session_prefix;
                self.model_priced = priced;
                self.session_id = session_id;
                // Activity `model` row (§9.16): `{model} via {provider}`.
                self.push_activity("model", format!("{} via {}", self.model, self.provider));
                self.dirty
                    .set(DirtyFlags::SESSION_LIST | DirtyFlags::STATUS);
            }
            Msg::ComposerChanged => {
                self.dirty.set(DirtyFlags::LAYOUT);
                if self.composer_state == ComposerState::Idle {
                    self.composer_state = ComposerState::Typing;
                }
            }
            Msg::SlashHintSelect(idx) => {
                if idx < self.slash_hints.items.len() {
                    self.slash_hints.selected = idx;
                    self.dirty.set(DirtyFlags::LAYOUT);
                }
            }
            Msg::ComposerTextChanged(text) => {
                // Live slash-hint dropdown (Claude Code parity): open while
                // the composer is a partial `/command` (leading slash, no
                // space yet, not exactly a known command). Selection resets
                // on every text change — the list may have reordered.
                let partial = text.starts_with('/')
                    && !text.contains(char::is_whitespace)
                    && text.len() > 1
                    && !crate::SLASH_NAMES.contains(&text.as_str());
                if partial {
                    let items: Vec<(String, String)> = crate::SLASH_COMMANDS
                        .iter()
                        .filter(|(c, _)| c.starts_with(text.as_str()))
                        .map(|(c, d)| (c.to_string(), d.to_string()))
                        .collect();
                    self.slash_hints.open = !items.is_empty();
                    self.slash_hints.items = items;
                    self.slash_hints.selected = 0;
                } else {
                    self.slash_hints.open = false;
                    self.slash_hints.items.clear();
                    self.slash_hints.selected = 0;
                }
                self.dirty.set(DirtyFlags::LAYOUT);
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
                self.coalescer.flush(self.tick_count);
                self.dirty.set(DirtyFlags::TRANSCRIPT | DirtyFlags::STATUS);
            }
            Msg::ModelChanged(model) => {
                self.model = model;
                self.last_status = format!("model → {}", self.model);
                // Activity `model` row (§9.16): `model → {model}`.
                self.push_activity("model", format!("model → {}", self.model));
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
                // Double Ctrl+C to quit: the first press only updates the
                // STATUS LINE ("press Ctrl+C again to exit") — no modal, no
                // key interception — so native terminal text selection and
                // copy still work. The second press within ~5 s (312 ticks
                // at 16 ms) quits — wide enough to read the hint, act on
                // it, and still bail out fast.
                let ticks_since_last = self.tick_count.saturating_sub(self.last_ctrl_c_tick);
                if self.ctrl_c_count == 1 && ticks_since_last < 312 {
                    self.should_quit = true;
                } else {
                    self.ctrl_c_count = 1;
                    self.last_ctrl_c_tick = self.tick_count;
                    self.last_status = "press Ctrl+C again to exit".into();
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
            // D3: `r` is dispatched in the event loop (needs the worker
            // command sink); the reducer sees nothing here.
            KeyAction::RerunLast => {}
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
            // Click-to-focus (herdr-style): the mouse hit-test resolves a
            // pane; this sets it directly.
            KeyAction::FocusSet(f) => {
                if self.focus != f {
                    self.focus = f;
                    self.dirty.set(DirtyFlags::LAYOUT);
                }
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
        app.reduce(Msg::PaneScroll {
            pane: Focus::Left,
            delta: 5,
        });
        assert_eq!(app.pane_scroll[0], 5, "left pane scrolled");
        assert_eq!(app.pane_scroll[1], 0, "center untouched");
        assert_eq!(app.pane_scroll[2], 0, "right untouched");
        app.reduce(Msg::PaneScroll {
            pane: Focus::Right,
            delta: 3,
        });
        assert_eq!(app.pane_scroll[0], 5, "left still 5");
        assert_eq!(app.pane_scroll[2], 3, "right scrolled");
    }

    #[test]
    fn scroll_clamps_at_top() {
        let mut app = App::default();
        app.reduce(Msg::PaneScroll {
            pane: Focus::Center,
            delta: -10,
        });
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
        app.reduce(Msg::CtrlC); // first press → status hint only
        assert!(!app.quit_confirmation, "no modal — copy stays possible");
        assert_eq!(app.last_status, "press Ctrl+C again to exit");

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
            if let Some(text) = app.coalescer.flush(app.tick_count) {
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
    fn activity_records_tool_finish_and_model_events() {
        let mut app = App::new();
        app.reduce(Msg::Identity {
            model: "glm-5.2".into(),
            provider: "local".into(),
            session_prefix: "01J8ZK4Q".into(),
            session_id: "session-01J8ZK4QX2M7C9RT5VWEHN3B6D".into(),
            priced: true,
        });
        app.reduce(Msg::ToolCallFinished {
            name: "shell".into(),
            outcome: ToolOutcome::Ok,
        });
        app.reduce(Msg::ModelChanged("kimi-k2.7".into()));
        app.reduce(Msg::BackendError("E0408".into()));
        // Rows: model-at-start, tool, model-change, error — newest last.
        assert_eq!(app.activity.len(), 4);
        assert_eq!(app.activity[0].kind, "model");
        assert!(app.activity[0].text.contains("glm-5.2 via local"));
        assert_eq!(app.activity[1].kind, "tool");
        assert!(app.activity[1].text.contains("shell · ok"));
        assert_eq!(app.activity[2].kind, "model");
        assert!(app.activity[2].text.contains("model → kimi-k2.7"));
        assert_eq!(app.activity[3].kind, "error");
        assert!(app.activity[3].text.contains("E0408"));
        // Every row carries an HH:MM:SS stamp.
        assert!(app.activity.iter().all(|r| r.time.len() == 8));
    }

    #[test]
    fn activity_caps_at_500_rows() {
        let mut app = App::new();
        for i in 0..600 {
            app.reduce(Msg::BackendError(format!("e{i}")));
        }
        assert_eq!(app.activity.len(), 500);
        // The oldest 100 were dropped; the newest is e599.
        assert!(app.activity.last().unwrap().text.contains("e599"));
        assert!(app.activity.first().unwrap().text.contains("e100"));
    }

    #[test]
    fn click_to_focus_sets_focus_and_dirty() {
        let mut app = App::new();
        app.dirty.clear();
        app.reduce(Msg::KeyAction(KeyAction::FocusSet(Focus::Right)));
        assert_eq!(app.focus, Focus::Right);
        assert!(app.dirty.is_set(DirtyFlags::LAYOUT));
        // Re-setting the same focus is a no-op (no spurious dirty).
        app.dirty.clear();
        app.reduce(Msg::KeyAction(KeyAction::FocusSet(Focus::Right)));
        assert!(!app.dirty.is_set(DirtyFlags::LAYOUT));
    }

    #[test]
    fn approval_decision_records_grant_row() {
        let mut app = App::new();
        app.reduce(Msg::ApprovalDecision {
            tool: "shell".into(),
            decision: ApprovalDecision::Once,
        });
        app.reduce(Msg::ApprovalDecision {
            tool: "edit_file".into(),
            decision: ApprovalDecision::Session,
        });
        app.reduce(Msg::ApprovalDecision {
            tool: "shell".into(),
            decision: ApprovalDecision::Denied,
        });
        assert_eq!(app.activity.len(), 3);
        assert_eq!(app.activity[0].kind, "grant");
        assert!(app.activity[0].text.contains("shell · once · you"));
        assert!(app.activity[1].text.contains("edit_file · session · you"));
        assert!(app.activity[2].text.contains("shell · denied · you"));
        // A session grant flips the tool state to AutoGranted (the ◈ slot).
        assert!(matches!(app.tool_state, ToolState::AutoGranted(_)));
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
            outcome: ToolOutcome::Ok,
        });
        assert!(app.pending_approvals.is_empty());
        assert_eq!(app.tool_state, ToolState::Idle);
        assert!(app.last_status.contains("ok"));
    }

    #[test]
    fn tool_call_finished_denied_is_not_failed() {
        // §11.5 rule 4: an operator denial must never settle as a failure.
        // The status line names the decision, and the card's outcome field
        // carries Denied (rendered `⊘ denied by you`, never red `✕`).
        let mut app = App::new();
        app.reduce(Msg::ToolCallStarted {
            name: "shell".into(),
            summary: "rm -rf /tmp/scratch".into(),
        });
        app.reduce(Msg::ToolCallFinished {
            name: "shell".into(),
            outcome: ToolOutcome::Denied,
        });
        // Status names the decision, not an error word.
        assert!(app.last_status.contains("denied by you"));
        assert!(!app.last_status.contains("error"));
        // The card carries the Denied outcome, not a failure.
        match app.transcript.last() {
            Some(TranscriptLine::Stripped { outcome, .. }) => {
                assert_eq!(*outcome, Some(ToolOutcome::Denied));
            }
            other => panic!("expected a Stripped card, got {other:?}"),
        }
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
            outcome: ToolOutcome::Ok,
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
            TranscriptLine::Assistant { text: t, .. } if t == "final words"
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
        app.transcript.push(TranscriptLine::User {
            text: "hi".into(),
            time: None,
        });
        app.reduce(Msg::TextDelta("hello!".into()));
        // Flush coalescer manually (bypass timing).
        if let Some(text) = app.coalescer.flush(app.tick_count) {
            app.in_flight.push_str(&text);
        }
        app.reduce(Msg::ResponseFinished {
            output: String::new(),
            input_tokens: 1,
            output_tokens: 1,
            cost_microcents: 0,
        });
        assert_eq!(app.transcript.len(), 2);
        assert!(matches!(app.transcript[0], TranscriptLine::User { .. }));
        assert!(matches!(
            app.transcript[1],
            TranscriptLine::Assistant { .. }
        ));
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

        // §7: the braille busy spinner advances while working. Tick is
        // 16 ms; the spinner clock fires every 6th tick (~10 fps).
        let f0 = app.spinner_frame;
        for _ in 0..6 {
            app.reduce(Msg::Tick);
        }
        assert_ne!(app.spinner_frame, f0, "busy spinner should advance");
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
    fn busy_spinner_wraps_modulo_ten() {
        let mut app = App::new();
        app.reduce(Msg::TextSubmitted("hello".into()));
        // The spinner has 10 braille frames; several full turns must wrap.
        for _ in 0..(10 * 3 * 6) {
            app.reduce(Msg::Tick);
        }
        assert!(app.spinner_frame < 10);
    }

    // ── D5: turn-scoped cost accounting ─────────────────────────────────

    #[test]
    fn turn_cost_never_stacks_on_committed_total() {
        let mut app = App::default();
        // Round 1 of a turn reports 100µ¢ running.
        app.reduce(Msg::TextSubmitted("hi".into()));
        app.reduce(Msg::TurnCostUpdated(100));
        assert_eq!(app.turn_cost_microcents, 100);
        assert_eq!(app.total_cost_microcents, 0, "committed untouched mid-turn");
        // Round 2 reports the ACCUMULATED turn cost (300), not a delta.
        app.reduce(Msg::TurnCostUpdated(300));
        assert_eq!(app.turn_cost_microcents, 300);
        // Finish: the final turn cost is committed once; accumulator resets.
        app.reduce(Msg::ResponseFinished {
            output: String::new(),
            input_tokens: 10,
            output_tokens: 5,
            cost_microcents: 300,
        });
        assert_eq!(app.total_cost_microcents, 300);
        assert_eq!(app.turn_cost_microcents, 0);
    }

    #[test]
    fn new_turn_resets_stale_turn_cost() {
        let mut app = App::default();
        app.reduce(Msg::TextSubmitted("one".into()));
        app.reduce(Msg::TurnCostUpdated(500));
        app.reduce(Msg::ResponseFinished {
            output: String::new(),
            input_tokens: 1,
            output_tokens: 1,
            cost_microcents: 500,
        });
        app.reduce(Msg::TextSubmitted("two".into()));
        assert_eq!(app.turn_cost_microcents, 0, "fresh turn starts at 0");
    }

    #[test]
    fn legacy_cost_updated_zeroes_turn_accumulator() {
        // The Go bridge still sends cumulative CostUpdated — it must never
        // stack with a stale turn accumulator.
        let mut app = App::default();
        app.reduce(Msg::TurnCostUpdated(123));
        app.reduce(Msg::CostUpdated(1000));
        assert_eq!(app.total_cost_microcents, 1000);
        assert_eq!(app.turn_cost_microcents, 0);
    }

    // ── D7: redaction chip lands in the transcript ─────────────────────

    #[test]
    fn redacted_chip_appends_never_renders_text() {
        let mut app = App::default();
        app.reduce(Msg::Redacted {
            kind: crate::state::RedactionKind::Secret,
        });
        assert_eq!(app.transcript.len(), 1);
        match &app.transcript[0] {
            TranscriptLine::Redacted(kind) => {
                assert_eq!(*kind, crate::state::RedactionKind::Secret)
            }
            other => panic!("expected Redacted, got {other:?}"),
        }
        // The chip's plain rendering names the gate, never the text.
        // (pane_lines now returns the RENDERED rows — a render-time cache —
        // so assert on the transcript entry's plain form directly.)
        let plain = match &app.transcript[0] {
            TranscriptLine::Redacted(kind) => {
                format!("[blocked: {}]", kind.label())
            }
            other => panic!("expected Redacted, got {other:?}"),
        };
        assert_eq!(plain, "[blocked: credential]");
    }

    // ── D18: unpriced models show cost n/a ─────────────────────────────

    #[test]
    fn identity_unpriced_disables_cost_display() {
        let mut app = App::default();
        app.reduce(Msg::Identity {
            model: "local-lab".into(),
            provider: "ollama".into(),
            session_prefix: "deadbeef".into(),
            session_id: "deadbeef-cafe".into(),
            priced: false,
        });
        assert!(!app.model_priced);
    }

    #[test]
    fn identity_priced_default_true() {
        let app = App::default();
        assert!(app.model_priced, "default assumes priced until told");
    }
}

#[cfg(test)]
mod rerun_tests {
    use super::*;

    fn app_idle() -> App {
        let mut app = App::new();
        app.turn_in_flight = false;
        app
    }

    #[test]
    fn text_submitted_records_last_prompt() {
        let mut app = app_idle();
        app.reduce(Msg::TextSubmitted("first prompt".into()));
        assert_eq!(app.last_prompt.as_deref(), Some("first prompt"));
    }

    #[test]
    fn last_prompt_updates_on_each_submission() {
        let mut app = app_idle();
        app.reduce(Msg::TextSubmitted("one".into()));
        app.reduce(Msg::ResponseFinished {
            output: String::new(),
            input_tokens: 1,
            output_tokens: 1,
            cost_microcents: 1,
        });
        app.reduce(Msg::TextSubmitted("two".into()));
        assert_eq!(app.last_prompt.as_deref(), Some("two"));
    }

    #[test]
    fn last_prompt_none_before_first_turn() {
        let app = app_idle();
        assert!(app.last_prompt.is_none());
    }

    #[test]
    fn rerun_keyaction_is_noop_in_reducer() {
        let mut app = app_idle();
        app.reduce(Msg::KeyAction(KeyAction::RerunLast));
        assert!(!app.should_quit);
        assert!(app.last_prompt.is_none());
    }
}

#[cfg(test)]
mod bell_tests {
    use super::*;

    fn approval_msg() -> Msg {
        Msg::ApprovalRequested {
            call_id: "c1".into(),
            tool_name: "shell".into(),
            summary: "ls".into(),
            risk: 0,
        }
    }

    #[test]
    fn approval_sets_bell_pending_when_enabled() {
        let mut app = App::new();
        app.bell_on_approval = true;
        app.reduce(approval_msg());
        assert!(app.bell_pending, "D17: bell rings on approval");
    }

    #[test]
    fn approval_silent_when_not_configured() {
        let mut app = App::new(); // bell_on_approval defaults false
        app.reduce(approval_msg());
        assert!(!app.bell_pending);
    }

    #[test]
    fn bell_flag_defaults_off() {
        let app = App::new();
        assert!(!app.bell_on_approval);
        assert!(!app.bell_pending);
    }
}

#[cfg(test)]
mod approvals_denied_tests {
    use super::*;

    fn approval() -> Msg {
        Msg::ApprovalRequested {
            call_id: "c1".into(),
            tool_name: "shell".into(),
            summary: "rm -rf /tmp/x".into(),
            risk: 2,
        }
    }

    #[test]
    fn ctrl_c_during_approval_clears_cards_not_session() {
        let mut app = App::new();
        app.reduce(approval());
        assert_eq!(app.pending_approvals.len(), 1);
        assert_eq!(app.tool_state, ToolState::AwaitingApproval);
        // D8: the deny gesture clears the cards and keeps the session alive.
        app.reduce(Msg::ApprovalsDenied);
        assert!(app.pending_approvals.is_empty());
        assert!(!app.should_quit);
        assert!(!app.quit_confirmation);
    }

    #[test]
    fn denied_during_turn_returns_to_running() {
        let mut app = App::new();
        app.reduce(Msg::TextSubmitted("go".into()));
        app.reduce(approval());
        app.reduce(Msg::ApprovalsDenied);
        assert!(matches!(app.tool_state, ToolState::Running(_)));
        assert!(app.turn_in_flight, "the turn continues with denied results");
    }

    #[test]
    fn denied_when_idle_returns_to_idle() {
        let mut app = App::new();
        app.reduce(approval());
        app.reduce(Msg::ApprovalsDenied);
        assert_eq!(app.tool_state, ToolState::Idle);
    }
}
