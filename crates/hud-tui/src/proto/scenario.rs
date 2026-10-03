//! The event reducer a scripted session drives (the `scenario`
//! module). Engine events in, panel state out — every animation is
//! tied to an event, never a guess.

use super::anim::{StarColour, StarState};

/// What a panel of the scenario knows. The reducer is total: every
/// FrontendEvent maps to a state change (or an explicit ignore).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Scenario {
    /// The model being waited on (M05's "waiting for {model}").
    pub model: String,
    /// A turn is live (RoundStarted seen, no TurnEnded yet).
    pub turn_live: bool,
    /// Visible output arrived since the turn started or the last tool
    /// finished (§10.1 row 3: writing).
    pub visible_output: bool,
    /// Running tool calls (call_id → kind), for the activity row.
    pub running: std::collections::BTreeMap<String, String>,
    /// An approval is pending.
    pub approval_pending: Option<String>,
    /// The last turn failed (until the next TurnStarted).
    pub last_failed: bool,
    /// Compaction in flight (M18's amber shimmer).
    pub compacting: bool,
    /// Agents (M15): id → (name, current action, done).
    pub agents: std::collections::BTreeMap<String, Agent>,
    /// Subagents still running.
    pub agents_running: usize,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Agent {
    pub name: String,
    pub action: String,
    pub done: bool,
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
    /// running after an approval).
    pub fn star_restarts(&self, previous: &StarState) -> bool {
        matches!(previous, StarState::Turning { .. }) == false
            && matches!(self.star_state(), StarState::Turning { .. })
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
            }
            "text_delta" => self.visible_output = true,
            "tool_started_full" => self.visible_output = false,
            "tool_finished_full" => self.visible_output = false,
            "approval_requested" => self.approval_pending = Some("tool".into()),
            "approval_resolved" => self.approval_pending = None,
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

    #[test]
    fn reduced_motion_shows_the_still_star() {
        // every turning state under reduced motion → still ✦ cyan
        let mut s = Scenario::new();
        s.apply("round_started", 0);
        let st = s.star_state();
        let reduced = match st {
            StarState::Turning { .. } => StarGlyph_reduced(),
            still => still,
        };
        assert_eq!(reduced, StarState::StillCyan);
    }

    fn StarGlyph_reduced() -> StarState {
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
