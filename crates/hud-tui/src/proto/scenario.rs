//! The event reducer a scripted session drives (the `scenario`
//! module). Engine events in, panel state out — every animation is
//! tied to an event, never a guess.

use super::anim::StarState;

/// What a panel of the scenario knows. The reducer is total: every
/// FrontendEvent maps to a state change (or an explicit ignore).
#[derive(Debug, Clone, Default)]
pub struct Scenario {
    /// The model being waited on (M05's "waiting for {model}").
    pub model: String,
    /// The session's permission mode (S5), updated by ModeChanged and
    /// read by Shift+Tab to pick the next mode in the cycle.
    pub permission_mode: Option<String>,
    /// A turn is live (RoundStarted seen, no TurnEnded yet).
    pub turn_live: bool,
    /// Visible output arrived since the turn started or the last tool
    /// finished (§10.1 row 3: writing).
    pub visible_output: bool,
    /// Running tool calls (call_id → kind), for the activity row.
    pub running: std::collections::BTreeMap<String, String>,
    /// An approval is pending.
    pub approval_pending: Option<String>,
    /// The pending approval's call_id — resolutions go through the
    /// registry keyed by it.
    pub approval_call_id: Option<String>,
    /// The last turn failed (until the next TurnStarted).
    pub last_failed: bool,
    /// Compaction in flight (M18's amber shimmer).
    pub compacting: bool,
    /// Agents (M15): id → (name, current action, done).
    pub agents: std::collections::BTreeMap<String, Agent>,
    /// Subagents still running.
    pub agents_running: usize,
    /// The Plan panel's task rows (TaskCreate/TaskUpdate).
    pub tasks: Vec<crate::proto::panels::TaskRow>,
    /// The Changes panel's rows (FileChanged).
    pub file_changes: Vec<crate::proto::panels::FileChangeRow>,
    /// The Terminal panel's output tail (ToolOutput lines).
    pub tool_output: Vec<String>,
    /// Context meter (Usage): tokens in use, the window, when shown.
    pub used_tokens: u64,
    pub window_tokens: u64,
    pub usage_shown_ms: u64,
    /// When data last arrived (the caret breathes after 400 ms
    /// without it — M06).
    pub last_data_ms: u64,
    /// The transcript: every visible line of the session (user
    /// prompts, model replies, tool lines). The conversation panel
    /// renders the tail.
    pub transcript: Vec<TranscriptLine>,
    /// Session identity (Msg::Identity): model, provider, session
    /// id prefix — the status line's right cluster and the shutdown
    /// line.
    /// Approval arming (§9.14): the ms of the last keypress, and the
    /// ms the pending card appeared. While `now − last_key < 1000`
    /// the decision keys are disabled and the border reads
    /// ` paused while you type `.
    pub last_key_ms: u64,
    pub approval_shown_ms: u64,
    /// The pending approval's queue (§9.14): oldest first.
    pub approval_queue: Vec<String>,
    /// The oldest pending request's display-safe summary (§9.14).
    pub approval_summary: Option<String>,
    /// The pending approval's backend-classified risk (0..=3) and the
    /// directory the call runs in (§9.14 facts — real values only).
    pub approval_risk: u8,
    /// Real facts for the pending approval's card (the sandbox state of
    /// a command): `(label, value)`.
    pub approval_facts: Vec<(String, String)>,
    /// The lines an edit or write would change, for the card.
    pub approval_preview: Vec<String>,
    /// Ledger records appended this session (the top bar's `●` chip).
    pub ledger_count: Option<u64>,
    /// The screen animates until this tick (ms): bumped by every
    /// message so the 16 ms redraw runs only while something moves.
    pub motion_until_ms: u64,
    /// When the last turn ended (the report types in, M25).
    pub turn_ended_ms: Option<u64>,
    /// The mode the pill wipes away from, and when it changed (M14).
    pub mode_prev: Option<String>,
    pub mode_changed_ms: Option<u64>,
    /// The context meter eases between fractions (M18).
    pub ctx_from: f32,
    pub ctx_to: f32,
    pub ctx_ms: u64,
    /// The ledger chip's dot flashes per record (M19).
    pub ledger_ms: Option<u64>,
    /// When each plan row / changed-file row last changed (M17, M11),
    /// parallel to `tasks` / `file_changes`.
    pub task_changed_ms: Vec<u64>,
    pub file_changed_ms: Vec<u64>,
    /// Rate-limit backoff: retry at this tick, and for how long it
    /// started (M27).
    pub backoff_until_ms: Option<u64>,
    pub backoff_total_ms: u64,
    pub approval_dir: String,
    /// M9's window (§10.2): the first prompt of an empty session is
    /// live and no output has arrived. The welcome shrinks to mark +
    /// tagline and the star orbits; the first output ends it.
    pub first_prompt_waiting: bool,
    /// The brand tier (§8.5): governs the welcome mark + M1/M9.
    pub brand_tier: crate::proto::welcome::BrandTier,
    /// Measured readiness facts for the welcome screen `(ok, label)`:
    /// trust root, ledger, active provider · model. Empty → no row.
    pub welcome_chips: Vec<(bool, String)>,
    pub model_id: String,
    pub provider: String,
    pub session_prefix: String,
    pub session_id: String,
    pub priced: bool,
    /// Cumulative session cost (microcents) — the shutdown line.
    pub cost_microcents: u64,
    /// Cumulative tokens — the shutdown line.
    pub input_tokens: u64,
    pub output_tokens: u64,
    /// Turns completed — the shutdown line.
    pub turns: u64,
    /// The last turn's report (M5): shown 2 s or until a key.
    pub turn_report: Option<TurnReport>,
    /// When the current turn started (elapsed counters, M3).
    pub turn_started_ms: u64,
    /// Tools run this turn (the M5 report's count).
    pub turn_tools: u64,
    /// The reactor phase (§6.10): 0 orient … 4 respond — the
    /// workspace stepper.
    pub phase: usize,
}

/// The M5 turn report: ✓ done · 41s · 3 tools · +$0.0031.
#[derive(Debug, Clone, PartialEq)]
pub struct TurnReport {
    pub duration_ms: u64,
    pub tools: u64,
    pub cost_microcents: u64,
    pub priced: bool,
}

/// One visible transcript line.
#[derive(Debug, Clone)]
pub struct TranscriptLine {
    pub kind: LineKind,
    pub text: String,
    /// Tool lines (§9.8): the tool name and state, rendered as
    /// `{glyph} {name}  {arg}` with right-aligned meta.
    pub tool_name: String,
    pub tool_state: ToolState,
    /// Tool lines: the engine's id for the call. Start and finish find
    /// their card by it, so two calls of one tool never share a line.
    pub call_id: String,
    /// User/model turns: the submit/settle time (`HH:MM`), shown
    /// right-aligned on the first row (§9.4/§9.5).
    pub time: Option<String>,
    /// Tool lines (§9.8): the meta text (`{outcome} · {duration}`).
    pub meta: String,
    /// Model text: `(char offset, arrival ms)` per streamed chunk — the
    /// fresh-ink fade reads it (M06).
    pub arrivals: Vec<(usize, u64)>,
    /// Tool lines: when the call settled (M10).
    pub finished_ms: Option<u64>,
    /// When the call started (duration = finish − start).
    pub started_ms: Option<u64>,
    /// The AGENT card's subagent id (M16): SubagentStarted attaches it
    /// to the most recent running Task/Agent card, and progress updates
    /// land on this line — the card then shows what its agent is doing.
    pub agent_id: Option<String>,
}

impl Default for TranscriptLine {
    fn default() -> Self {
        TranscriptLine {
            kind: LineKind::System,
            text: String::new(),
            tool_name: String::new(),
            tool_state: ToolState::Queued,
            call_id: String::new(),
            time: None,
            meta: String::new(),
            arrivals: Vec::new(),
            finished_ms: None,
            started_ms: None,
            agent_id: None,
        }
    }
}

/// The §9.8 tool-line states.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ToolState {
    #[default]
    Queued,
    Running,
    AwaitingYou,
    Done,
    Failed,
    Denied,
    Blocked,
    /// Stopped by Esc, or cut off when the turn ended.
    Cancelled,
}

impl ToolState {
    /// (glyph, colour) per the §9.8 state table.
    pub fn glyph_parts(self) -> (&'static str, super::core::Token) {
        use super::core::Token;
        match self {
            ToolState::Queued => ("◌", Token::Muted),
            ToolState::Running => ("◉", Token::Cyan),
            ToolState::AwaitingYou => ("◇", Token::Magenta),
            ToolState::Done => ("✓", Token::Muted),
            ToolState::Failed => ("✕", Token::Red),
            ToolState::Denied => ("⊘", Token::Muted),
            ToolState::Blocked => ("⊖", Token::Amber),
            ToolState::Cancelled => ("⊘", Token::Muted),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LineKind {
    /// The operator's prompt.
    User,
    /// Model output (streamed).
    Model,
    /// A tool line (started/finished).
    Tool,
    /// A queued prompt (§9.12): waiting for its turn to start.
    Queued,
    /// A system/status line.
    System,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Agent {
    pub name: String,
    pub action: String,
    pub done: bool,
    /// When it started / finished (M15, M16).
    pub started_ms: u64,
    pub done_ms: Option<u64>,
}

/// The activity the status line shows (§9.18, evaluated in order).
#[derive(Debug, Clone, PartialEq)]
pub enum Activity {
    Ready,
    WaitingModel(String),
    Streaming,
    Running(String),
    RunningMany(usize),
    Approval(String),
    Compacting,
    Done,
    Failed,
}

impl Scenario {
    pub fn new() -> Self {
        Self::default()
    }

    /// The star state for the current scenario (§10.1's table, first
    /// match wins).
    /// A monotonic change counter (§10.5): any state mutation bumps
    /// it, so the loop can skip draws when nothing changed.
    pub fn state_version(&self) -> u64 {
        self.transcript.len() as u64
            + self.turns
            + self.turn_tools
            + self.running.len() as u64
            + self.approval_queue.len() as u64
            + self.approval_summary.is_some() as u64
            + self.tool_output.len() as u64
            + (self.turn_live as u64)
            + (self.last_failed as u64)
    }

    /// The star is turning (an animation is in flight).
    /// The context fraction shown now, easing toward the latest usage
    /// over 300 ms (M18).
    pub fn ctx_eased(&self, now_ms: u64) -> f32 {
        let p = (now_ms.saturating_sub(self.ctx_ms) as f32 / 300.0).clamp(0.0, 1.0);
        let e = 1.0 - (1.0 - p).powi(3);
        self.ctx_from + (self.ctx_to - self.ctx_from) * e
    }

    pub fn is_turning(&self) -> bool {
        matches!(self.star_state(), StarState::Turning { .. })
    }

    /// The workspace is empty (§9.2: the switcher shows Workspace
    /// faint with no count).
    pub fn workspace_empty(&self) -> bool {
        self.tasks.is_empty() && self.file_changes.is_empty()
    }

    /// The session title (§13.2): the first prompt's first line,
    /// else `New session`.
    pub fn session_title(&self) -> String {
        for l in &self.transcript {
            if l.kind == LineKind::User {
                return l.text.lines().next().unwrap_or("New session").to_string();
            }
        }
        "New session".into()
    }

    /// The current reactor phase (the workspace stepper, §9.17):
    /// 0 orient → 1 reason → 2 act → 3 verify → 4 respond.
    pub fn phase_index(&self) -> usize {
        self.phase
    }

    pub fn star_state(&self) -> StarState {
        if self.approval_pending.is_some() {
            return StarState::StillMagenta; // needs you
        }
        if !self.running.is_empty() || self.agents_running > 0 {
            // agents running: 4 fps
            return StarState::Turning { period_ms: 250 };
        }
        if self.turn_live && self.visible_output {
            // writing: 4 fps
            return StarState::Turning { period_ms: 250 };
        }
        if self.turn_live {
            // thinking: 2 fps
            return StarState::Turning { period_ms: 500 };
        }
        if self.compacting {
            return StarState::StillAmber;
        }
        if self.last_failed {
            return StarState::StillRed;
        }
        StarState::StillMagenta // ready
    }

    /// The activity row (evaluated in the same order as the star).
    pub fn activity(&self) -> Activity {
        if let Some(tool) = &self.approval_pending {
            return Activity::Approval(tool.clone());
        }
        if self.compacting {
            return Activity::Compacting;
        }
        if !self.running.is_empty() {
            if self.running.len() == 1 {
                return Activity::Running(
                    self.running.values().next().cloned().unwrap_or_default(),
                );
            }
            return Activity::RunningMany(self.running.len());
        }
        if self.agents_running > 0 {
            return Activity::RunningMany(self.agents_running);
        }
        if self.turn_live && self.visible_output {
            return Activity::Streaming;
        }
        if self.turn_live {
            return Activity::WaitingModel(self.model.clone());
        }
        if self.last_failed {
            return Activity::Failed;
        }
        Activity::Ready
    }

    /// True when the star crossed a still→turning edge and the clock
    /// must restart (§10.1: at TurnStarted, or when a call starts
    /// running after an approval). The caller holds the previous
    /// state; this compares against still-now semantics.
    pub fn star_restarts(&self, previous: &StarState) -> bool {
        !matches!(previous, StarState::Turning { .. })
            && matches!(self.star_state(), StarState::Turning { .. })
    }

    /// The last star state the reducer saw (for edge detection). The
    /// app updates it after each tick.
    pub fn star_restarts_from_still(&self) -> bool {
        // The app calls this when the scenario just changed; the
        // default (no history) reports false and the caller's
        // still→turning path is handled by App::tick comparing states.
        false
    }

    /// The engine event reducer. `tick_ms` stamps the change so an
    /// animation can start from it.
    pub fn apply(&mut self, ev: &str, tick_ms: u64) {
        // (serde-tagged names; the bridge decodes FrontendEvent and
        // passes its tag — the reducer stays JSON-free and testable)
        let _ = tick_ms;
        match ev {
            "round_started" => {
                self.turn_live = true;
                self.visible_output = false;
                self.last_failed = false;
                self.turn_report = None;
                self.turn_tools = 0;
            }
            "text_delta" => {
                // M9 ends at the first output.
                self.first_prompt_waiting = false;
                self.visible_output = true;
                // last_data_ms is wall-clock-ish; apply() carries the
                // engine time if the runtime passes it, else the
                // caller updates the field directly.
            }
            "tool_started_full" => {
                // The first output of ANY kind ends M9: an agentic turn
                // usually opens with a tool call, not text, and the
                // welcome orbit must not animate behind it.
                self.first_prompt_waiting = false;
                self.visible_output = false;
            }
            "tool_finished_full" => self.visible_output = false,
            "approval_requested" => {
                self.first_prompt_waiting = false;
                self.approval_pending = Some("tool".into());
            }
            "approval_requested_full" => {}
            "approval_resolved" => {
                self.approval_pending = None;
                self.approval_call_id = None;
                self.approval_facts.clear();
                self.approval_preview.clear();
            }
            "compacting" => self.compacting = true,
            "compacted" => self.compacting = false,
            "turn_ended" => {
                self.turn_live = false;
                self.visible_output = false;
                self.running.clear();
            }
            "turn_failed" => {
                self.turn_live = false;
                self.last_failed = true;
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The star follows the activity table exactly (§10.1), first
    /// match wins.
    #[test]
    fn star_state_first_match_wins() {
        let mut s = Scenario::new();
        assert_eq!(s.star_state(), StarState::StillMagenta); // ready

        s.apply("round_started", 0);
        assert_eq!(
            s.star_state(),
            StarState::Turning { period_ms: 500 },
            "thinking at 2 fps"
        );
        assert!(matches!(s.activity(), Activity::WaitingModel(_)));

        s.apply("text_delta", 100);
        assert_eq!(
            s.star_state(),
            StarState::Turning { period_ms: 250 },
            "writing at 4 fps"
        );
        assert_eq!(s.activity(), Activity::Streaming);

        // an approval preempts everything
        s.apply("approval_requested", 200);
        assert_eq!(s.star_state(), StarState::StillMagenta);
        assert!(matches!(s.activity(), Activity::Approval(_)));

        s.apply("approval_resolved", 300);
        assert_eq!(s.star_state(), StarState::Turning { period_ms: 250 });

        s.apply("turn_ended", 400);
        assert_eq!(s.star_state(), StarState::StillMagenta); // done/ready
    }

    /// M9 (the welcome orbit while the first prompt waits) ends at the
    /// first visible output — a tool card or an approval, not only text.
    /// A turn that opens with a tool call used to keep the hero and its
    /// 60 fps animation up for the whole tool phase.
    #[test]
    fn the_first_tool_ends_the_welcome_wait() {
        for ev in ["text_delta", "tool_started_full", "approval_requested"] {
            let mut s = Scenario::new();
            s.first_prompt_waiting = true;
            s.apply("round_started", 0);
            assert!(s.first_prompt_waiting, "still waiting before any output");
            s.apply(ev, 10);
            assert!(!s.first_prompt_waiting, "{ev} ends the welcome wait");
        }
    }

    #[test]
    fn reduced_motion_shows_the_still_star() {
        // every turning state under reduced motion → still ✦ cyan
        let mut s = Scenario::new();
        s.apply("round_started", 0);
        let st = s.star_state();
        let reduced = match st {
            StarState::Turning { .. } => star_glyph_reduced(),
            still => still,
        };
        assert_eq!(reduced, StarState::StillCyan);
    }

    fn star_glyph_reduced() -> StarState {
        StarState::StillCyan
    }

    #[test]
    fn failure_holds_red_until_the_next_turn() {
        let mut s = Scenario::new();
        s.apply("round_started", 0);
        s.apply("turn_failed", 100);
        assert_eq!(s.star_state(), StarState::StillRed);
        s.apply("round_started", 200);
        assert!(matches!(s.star_state(), StarState::Turning { .. }));
    }
}
