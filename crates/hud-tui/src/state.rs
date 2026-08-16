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
    #[default]
    Left,
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
    /// Current provider (from cmd_chat config).
    pub provider: String,
    /// Current model (from cmd_chat config).
    pub model: String,
    /// Session id (first 8 chars shown in status bar).
    pub session_id_prefix: String,
    /// Connection state.
    pub connection: ConnectionState,
    /// Tool state (idle / streaming / awaiting approval / running / auto-grant).
    pub tool_state: ToolState,
    /// Pending tool calls awaiting approval (PR-C will render these).
    pub pending_approvals: Vec<PendingApproval>,
    /// Last status one-liner (shown in toast / status bar).
    pub last_status: String,
    /// Active error from the backend, if any.
    pub last_error: Option<String>,
    /// Thinking indicator phase (spinner frame index, modular).
    pub thinking_phase: u8,
    /// Thinking indicator phrase index (rotates every ~2.4 s).
    pub thinking_phrase: usize,
    /// Tick count at which the last phrase rotation happened.
    pub last_phrase_tick: u64,
    /// Transcript scroll offset (lines from top). Auto-scrolls to bottom.
    pub transcript_scroll: u16,
    /// Ctrl+C press count — 0 = none, 1 = "press again to quit", 2 = quit.
    pub ctrl_c_count: u8,
    /// Tick count at the last Ctrl+C press (for timeout reset).
    pub last_ctrl_c_tick: u64,
    /// Quit confirmation message (shown when ctrl_c_count == 1).
    pub quit_confirmation: bool,
    /// Focus shimmer phase (0 or 1, alternates every ~125ms).
    pub shimmer_phase: u8,
    /// Cost flash frames (counts down from 8 when cost changes).
    pub cost_flash_frames: u8,
    /// Reconnecting spinner phase (0..3).
    pub reconnect_phase: u8,
    /// Copy mode flag — when true, TUI exits alt screen for plain text copy.
    pub copy_mode: bool,
}

/// The fixed local thinking phrases (never model-generated rationale).
pub const THINKING_PHRASES: &[&str] = &[
    "Orbiting…",
    "Gathering context…",
    "Working through it…",
    "Forming a response…",
    "Almost there…",
];

/// Spinner frames for the thinking indicator.
pub const SPINNER_FRAMES: &[&str] = &["✦", "✧", "⋆", "·", "⋆", "✧"];

/// One line in the transcript — either a user message or an assistant reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TranscriptLine {
    User(String),
    Assistant(String),
    /// CoT-stripped placeholder (NEVER shows raw reasoning).
    Stripped {
        tool_name: String,
    },
}

/// Connection state for the status bar.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ConnectionState {
    #[default]
    Online,
    Reconnecting,
    Offline,
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
            provider: String::new(),
            model: String::new(),
            session_id_prefix: String::new(),
            connection: ConnectionState::Online,
            tool_state: ToolState::Idle,
            pending_approvals: Vec::new(),
            last_status: String::new(),
            last_error: None,
            thinking_phase: 0,
            thinking_phrase: 0,
            last_phrase_tick: 0,
            transcript_scroll: 0,
            ctrl_c_count: 0,
            last_ctrl_c_tick: 0,
            quit_confirmation: false,
            shimmer_phase: 0,
            cost_flash_frames: 0,
            reconnect_phase: 0,
            copy_mode: false,
        }
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
                // Animate the thinking indicator while streaming with no text.
                if self.tool_state == ToolState::Streaming && self.in_flight.is_empty() {
                    self.thinking_phase = (self.thinking_phase + 1) % SPINNER_FRAMES.len() as u8;
                    let ticks = self.tick_count;
                    if ticks.saturating_sub(self.last_phrase_tick) >= 150 {
                        self.last_phrase_tick = ticks;
                        self.thinking_phrase = (self.thinking_phrase + 1) % THINKING_PHRASES.len();
                    }
                    self.dirty.set(DirtyFlags::TRANSCRIPT);
                }
                // Focus shimmer: toggle every ~125ms (8 ticks at 16ms).
                if self.tick_count.is_multiple_of(8) {
                    self.shimmer_phase = (self.shimmer_phase + 1) % 2;
                    self.dirty.set(DirtyFlags::LAYOUT);
                }
                // Reconnecting spinner: advance every ~375ms (24 ticks).
                if self.connection == ConnectionState::Reconnecting
                    && self.tick_count.is_multiple_of(24)
                {
                    self.reconnect_phase = (self.reconnect_phase + 1) % 3;
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
                // Finalize the in-flight turn.
                if !self.in_flight.is_empty() {
                    self.transcript
                        .push(TranscriptLine::Assistant(self.in_flight.clone()));
                    self.in_flight.clear();
                } else if !output.is_empty() {
                    self.transcript.push(TranscriptLine::Assistant(output));
                }
                self.total_input_tokens = self.total_input_tokens.saturating_add(input_tokens);
                self.total_output_tokens = self.total_output_tokens.saturating_add(output_tokens);
                self.total_cost_microcents =
                    self.total_cost_microcents.saturating_add(cost_microcents);
                self.tool_state = ToolState::Idle;
                self.dirty.set(DirtyFlags::TRANSCRIPT | DirtyFlags::STATUS);
            }
            Msg::ToolCallStarted { name, summary } => {
                self.tool_state = ToolState::Running(name.clone());
                self.transcript.push(TranscriptLine::Stripped {
                    tool_name: name.clone(),
                });
                // Also append a display-safe note line.
                self.transcript
                    .push(TranscriptLine::Assistant(format!("[tool] {summary}")));
                self.pending_approvals.push(PendingApproval {
                    call_id: format!("call-{}", self.pending_approvals.len()),
                    tool_name: name,
                    summary,
                });
                self.tool_state = ToolState::AwaitingApproval;
                self.dirty
                    .set(DirtyFlags::TRANSCRIPT | DirtyFlags::APPROVAL | DirtyFlags::STATUS);
            }
            Msg::ToolCallFinished { name, ok } => {
                self.pending_approvals.retain(|p| p.tool_name != name);
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
                self.last_error = Some(err);
                self.dirty.set(DirtyFlags::STATUS);
            }
            Msg::TextSubmitted(text) => {
                // The operator's prompt becomes a transcript line.
                self.transcript.push(TranscriptLine::User(text));
                self.in_flight.clear();
                self.tool_state = ToolState::Streaming;
                self.dirty.set(DirtyFlags::TRANSCRIPT | DirtyFlags::STATUS);
            }
            Msg::ApprovalRequested {
                call_id,
                tool_name,
                summary,
            } => {
                self.tool_state = ToolState::AwaitingApproval;
                self.pending_approvals.push(PendingApproval {
                    call_id,
                    tool_name,
                    summary,
                });
                self.dirty.set(DirtyFlags::APPROVAL | DirtyFlags::STATUS);
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
            } => {
                self.model = model;
                self.provider = provider;
                self.session_id_prefix = session_prefix;
                self.dirty
                    .set(DirtyFlags::SESSION_LIST | DirtyFlags::STATUS);
            }
            Msg::ComposerChanged => {
                self.dirty.set(DirtyFlags::LAYOUT);
            }
            Msg::CtrlC => {
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
            | KeyAction::Unknown => {}
        }
    }
}

#[cfg(test)]
mod tests {
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
    fn reduce_focus_next_cycles() {
        let mut app = App::new();
        assert_eq!(app.focus, Focus::Left);
        app.reduce(Msg::KeyAction(KeyAction::FocusNext));
        assert_eq!(app.focus, Focus::Center);
        app.reduce(Msg::KeyAction(KeyAction::FocusNext));
        assert_eq!(app.focus, Focus::Right);
        app.reduce(Msg::KeyAction(KeyAction::FocusNext));
        assert_eq!(app.focus, Focus::Status);
        app.reduce(Msg::KeyAction(KeyAction::FocusNext));
        assert_eq!(app.focus, Focus::Left);
    }

    #[test]
    fn reduce_focus_prev_cycles() {
        let mut app = App::new();
        app.reduce(Msg::KeyAction(KeyAction::FocusPrev));
        assert_eq!(app.focus, Focus::Status);
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
    fn reduce_tool_call_started_adds_approval() {
        let mut app = App::new();
        app.reduce(Msg::ToolCallStarted {
            name: "calculator".into(),
            summary: "calculator(expression)".into(),
        });
        assert_eq!(app.pending_approvals.len(), 1);
        assert_eq!(app.pending_approvals[0].tool_name, "calculator");
        assert_eq!(app.tool_state, ToolState::AwaitingApproval);
        assert!(app.dirty.is_set(DirtyFlags::APPROVAL));
    }

    #[test]
    fn reduce_tool_call_finished_clears_approval() {
        let mut app = App::new();
        app.reduce(Msg::ToolCallStarted {
            name: "calculator".into(),
            summary: "calculator(expression)".into(),
        });
        app.reduce(Msg::ToolCallFinished {
            name: "calculator".into(),
            ok: true,
        });
        assert!(app.pending_approvals.is_empty());
        assert_eq!(app.tool_state, ToolState::Idle);
        assert!(app.last_status.contains("ok"));
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

        let phase0 = app.thinking_phase;
        app.reduce(Msg::Tick);
        app.reduce(Msg::Tick);
        assert_ne!(
            app.thinking_phase, phase0,
            "spinner should advance on ticks"
        );
        assert!(app.dirty.is_set(DirtyFlags::TRANSCRIPT));
    }

    #[test]
    fn thinking_stops_when_text_arrives() {
        let mut app = App::new();
        app.reduce(Msg::TextSubmitted("hello".into()));
        assert!(app.in_flight.is_empty());
        // First text delta → in_flight non-empty, indicator no longer dirty.
        app.reduce(Msg::TextDelta("hello!".into()));
        let phase_before = app.thinking_phase;
        app.reduce(Msg::Tick);
        // In-flight may flush on this tick; either way indicator isn't advancing.
        if !app.in_flight.is_empty() {
            assert_eq!(app.thinking_phase, phase_before);
        }
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
    fn thinking_phase_wraps_modulo() {
        let mut app = App::new();
        app.reduce(Msg::TextSubmitted("hello".into()));
        let len = SPINNER_FRAMES.len() as u8;
        for _ in 0..(len * 3) {
            app.reduce(Msg::Tick);
        }
        // Phase wraps without overflow.
        assert!(app.thinking_phase < len);
    }
}
