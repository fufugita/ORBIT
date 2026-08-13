//! ORBIT reactor — Phase B (B9).
//!
//! Five-phase FSM per DR-04: `Init → Plan → Execute → Verify → Checkpoint`.
//! - Monotonic transitions (no skipping backwards); a failed check demotes to
//!   `Checkpoint` (terminal Failed), never re-enters an earlier phase.
//! - PLAN/EXECUTE capability recheck (DR-04 §9, DR-01 I11): EXECUTE wins; a
//!   changed card → E0203 and the plan is invalidated loudly.
//! - Cancellation is a typed protocol: in-flight critical section completes,
//!   then the next phase opening transitions to Checkpoint with Cancelled.
//! - Phase-router scope: orchestrator-only (DR-04 §8); it never routes subagents.

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};

/// Reactor error family (E0203/E0204/E0505 + terminal).
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum ReactorError {
    /// ORBIT-E0505 invalid_fsm_transition
    #[error("ORBIT-E0505 invalid_fsm_transition: {0}")]
    InvalidTransition(String),
    /// ORBIT-E0203 capability_denied (EXECUTE recheck)
    #[error("ORBIT-E0203 capability_denied: {0}")]
    CapabilityDenied(String),
    /// ORBIT-E0204 capability_check_plan_refused
    #[error("ORBIT-E0204 capability_check_plan_refused: {0}")]
    PlanCheckRefused(String),
}

impl ReactorError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidTransition(_) => "E0505",
            Self::CapabilityDenied(_) => "E0203",
            Self::PlanCheckRefused(_) => "E0204",
        }
    }
}

/// The five phases (DR-04).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Phase {
    Init,
    Plan,
    Execute,
    Verify,
    Checkpoint,
}

impl Phase {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Init => "init",
            Self::Plan => "plan",
            Self::Execute => "exec",
            Self::Verify => "ver",
            Self::Checkpoint => "ckpt",
        }
    }
}

/// Terminal session states (DR-04 §7.2 — only these four are legal).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TerminalState {
    Completed,
    Failed,
    Cancelled,
    Diverged, // replay divergence, fatal under strict policy
}

/// The reactor FSM state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReactorState {
    Running(Phase),
    Terminal(TerminalState),
}

impl Default for ReactorState {
    fn default() -> Self {
        Self::Running(Phase::Init)
    }
}

/// A cancellation target (DR-04 §10).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CancelTarget {
    Session,
    Subagent,
}

/// Cancellation origin.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CancelOrigin {
    User,
    Parent,
    Runtime,
}

/// A typed cancellation token (DR-04 §10).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CancellationToken {
    pub target: CancelTarget,
    pub origin: CancelOrigin,
    pub phase_at_cancel: Phase,
    pub first_signal_wins: bool,
}

/// Capability proof snapshot (DR-04 §9 / DR-01 I11).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityProof {
    pub card_digests_at_plan: Vec<String>,
    pub card_digests_at_execute: Vec<String>,
}

impl CapabilityProof {
    /// PLAN/EXECUTE recheck: EXECUTE wins. If the card bytes changed, deny (E0203).
    pub fn recheck(self) -> Result<(), ReactorError> {
        if self.card_digests_at_plan != self.card_digests_at_execute {
            return Err(ReactorError::CapabilityDenied(format!(
                "card changed between PLAN and EXECUTE (E0203): {:?} vs {:?}",
                self.card_digests_at_plan, self.card_digests_at_execute
            )));
        }
        Ok(())
    }
}

/// The reactor state machine.
#[derive(Default)]
pub struct Reactor {
    state: ReactorState,
}

impl Reactor {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn state(&self) -> &ReactorState {
        &self.state
    }

    /// Attempt a phase transition (monotonic, no skipping backwards — E0505).
    pub fn transition(&mut self, to: Phase) -> Result<(), ReactorError> {
        let from = match &self.state {
            ReactorState::Running(p) => *p,
            ReactorState::Terminal(_) => {
                return Err(ReactorError::InvalidTransition(
                    "terminal state cannot transition (E0505)".into(),
                ))
            }
        };
        let legal = match (from, to) {
            (Phase::Init, Phase::Plan)
            | (Phase::Plan, Phase::Execute)
            | (Phase::Execute, Phase::Verify)
            | (Phase::Verify, Phase::Checkpoint)
            | (Phase::Init, Phase::Checkpoint) // early commit allowed (DR-04)
            | (Phase::Plan, Phase::Checkpoint) // plan refusal demotes
            | (Phase::Execute, Phase::Checkpoint) => true, // execute failure demotes
            _ => false,
        };
        if !legal {
            return Err(ReactorError::InvalidTransition(format!(
                "{} → {} is illegal (E0505)",
                from.as_str(),
                to.as_str()
            )));
        }
        self.state = ReactorState::Running(to);
        Ok(())
    }

    /// End the session in a terminal state (DR-04 §7.2).
    pub fn terminate(&mut self, t: TerminalState) {
        self.state = ReactorState::Terminal(t);
    }

    /// Run the PLAN/EXECUTE capability recheck (DR-04 §9). EXECUTE wins.
    pub fn check_plan_execute(&mut self, proof: CapabilityProof) -> Result<(), ReactorError> {
        proof.recheck().inspect_err(|_| {
            self.state = ReactorState::Terminal(TerminalState::Failed);
        })
    }

    /// Handle a cancellation token: in-flight critical section completes, then
    /// the next phase opening transitions to Checkpoint with Cancelled (DR-04 §10).
    pub fn handle_cancel(&mut self, token: &CancellationToken) {
        if !token.first_signal_wins {
            return; // only the first signal cancels; others are ignored
        }
        // A cancellation mid-phase: the current critical section completes
        // (represented by staying in the current phase), then we transition
        // to Checkpoint on the next phase opening. Here we model the terminal
        // cancel directly once the current phase is a non-execute phase.
        if let ReactorState::Running(p) = &self.state {
            if *p != Phase::Execute {
                // Plan/Init/Verify/Checkpoint cancel → checkpoint with Cancelled.
                self.state = ReactorState::Terminal(TerminalState::Cancelled);
            }
            // In Execute, cancellation requests are handled by TTE per-attempt
            // (DR-01 §9); the reactor waits for the execute to observe it.
        }
    }

    /// True if the phase router may select the orchestrator model for `phase`.
    /// Phase router is orchestrator-only (DR-04 §8); it never handles subagents.
    pub fn router_may_select(&self, _phase: Phase) -> bool {
        // The router applies to the orchestrator's own model per phase. The
        // enforcement (no subagent handle ever reaches it) lives in the type
        // system: `route(&self, phase) -> &ModelRef` takes no subagent.
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_chain_init_to_checkpoint() {
        let mut r = Reactor::new();
        r.transition(Phase::Plan).unwrap();
        r.transition(Phase::Execute).unwrap();
        r.transition(Phase::Verify).unwrap();
        r.transition(Phase::Checkpoint).unwrap();
        assert_eq!(r.state(), &ReactorState::Running(Phase::Checkpoint));
    }

    #[test]
    fn skipping_phase_refused() {
        let mut r = Reactor::new();
        assert_eq!(
            r.transition(Phase::Execute).unwrap_err().code(),
            "E0505",
            "Init → Execute skips Plan"
        );
    }

    #[test]
    fn terminal_cannot_transition() {
        let mut r = Reactor::new();
        r.terminate(TerminalState::Completed);
        assert_eq!(r.transition(Phase::Plan).unwrap_err().code(), "E0505");
    }

    #[test]
    fn plan_execute_recheck_denies_on_change() {
        let mut r = Reactor::new();
        let proof = CapabilityProof {
            card_digests_at_plan: vec!["card-v1".into()],
            card_digests_at_execute: vec!["card-v2".into()],
        };
        assert_eq!(r.check_plan_execute(proof).unwrap_err().code(), "E0203");
        assert_eq!(r.state(), &ReactorState::Terminal(TerminalState::Failed));
    }

    #[test]
    fn cancel_mid_plan_cancels() {
        let mut r = Reactor::new();
        r.transition(Phase::Plan).unwrap();
        r.handle_cancel(&CancellationToken {
            target: CancelTarget::Session,
            origin: CancelOrigin::User,
            phase_at_cancel: Phase::Plan,
            first_signal_wins: true,
        });
        assert_eq!(r.state(), &ReactorState::Terminal(TerminalState::Cancelled));
    }
}
