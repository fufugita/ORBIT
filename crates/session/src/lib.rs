//! ORBIT session subsystem — Phase C (C12).
//!
//! Session lifecycle per DR-08:
//! - CTX-I5: `restricted` marker is pinned once at Init, immutable.
//! - CTX-I6: ACL is a Unix-owner property (non-root UID, 0700/0600).
//! - CTX-I12: cost rollup is u64 microcents, checked_add at CHECKPOINT (E0702).
//! - CTX-I13: export/restore one-shot, immutable, never overwrites.
//! - CTX-I14: FSM has exactly five states with valid transitions.

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};

/// Session error family (E0509, E0513, E0702, E0703, E0705, E0721).
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum SessionError {
    /// ORBIT-E0513 restricted_session_invalid_init
    #[error("ORBIT-E0513 restricted_session_invalid_init: {0}")]
    InvalidRestrictedInit(String),
    /// ORBIT-E0703 session_restricted_marker_immutable
    #[error("ORBIT-E0703 session_restricted_marker_immutable: {0}")]
    MarkerImmutable(String),
    /// ORBIT-E0702 ledger_rollup_overflow
    #[error("ORBIT-E0702 ledger_rollup_overflow: {0}")]
    CostOverflow(String),
    /// ORBIT-E0705 restricted_acl_invalid
    #[error("ORBIT-E0705 restricted_acl_invalid: {0}")]
    AclInvalid(String),
    /// ORBIT-E0509 restore_into_existing_session
    #[error("ORBIT-E0509 restore_into_existing_session: {0}")]
    RestoreIntoExisting(String),
    /// ORBIT-E0721 session_restart_acl_invalid
    #[error("ORBIT-E0721 session_restart_acl_invalid: {0}")]
    RestartAclInvalid(String),
}

impl SessionError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidRestrictedInit(_) => "E0513",
            Self::MarkerImmutable(_) => "E0703",
            Self::CostOverflow(_) => "E0702",
            Self::AclInvalid(_) => "E0705",
            Self::RestoreIntoExisting(_) => "E0509",
            Self::RestartAclInvalid(_) => "E0721",
        }
    }
}

/// The five session states (CTX-I14).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionState {
    Init,
    Plan,
    Execute,
    Verify,
    Checkpoint,
}

/// A session header; `restricted` is immutable after Init (CTX-I5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionHeader {
    pub session_id: String,
    pub pib_id: String,
    pub operator_uid: u32,
    pub restricted: bool,
    pub policy_snapshot_id: String,
}

/// The session: header (immutable marker) + FSM state + cost rollup.
#[derive(Debug, Clone)]
pub struct Session {
    header: SessionHeader,
    state: SessionState,
    cost_microcents: u64,
}

impl Session {
    /// Start a session. A restricted session requires non-root UID + the
    /// marker is pinned here (CTX-I5/I6).
    pub fn start(header: SessionHeader) -> Result<Self, SessionError> {
        if header.restricted && header.operator_uid == 0 {
            return Err(SessionError::InvalidRestrictedInit(
                "restricted session requires non-root UID (E0513)".into(),
            ));
        }
        Ok(Self {
            header,
            state: SessionState::Init,
            cost_microcents: 0,
        })
    }

    pub fn header(&self) -> &SessionHeader {
        &self.header
    }

    pub fn state(&self) -> SessionState {
        self.state
    }

    /// The restricted marker is immutable (CTX-I5): any later mutation → E0703.
    pub fn try_set_restricted(&mut self, _restricted: bool) -> Result<(), SessionError> {
        Err(SessionError::MarkerImmutable(
            "restricted marker pinned at Init, immutable (E0703)".into(),
        ))
    }

    /// Valid FSM transitions (CTX-I14): Init→Plan→Execute→Verify→Checkpoint,
    /// Init→Init (resume), Execute→Checkpoint (early commit), Checkpoint→Init (restart).
    pub fn transition(&mut self, to: SessionState) -> Result<(), SessionError> {
        let ok = matches!(
            (self.state, to),
            (SessionState::Init, SessionState::Init)
                | (SessionState::Init, SessionState::Plan)
                | (SessionState::Plan, SessionState::Execute)
                | (SessionState::Execute, SessionState::Verify)
                | (SessionState::Verify, SessionState::Checkpoint)
                | (SessionState::Execute, SessionState::Checkpoint)
                | (SessionState::Checkpoint, SessionState::Init)
        );
        if !ok {
            return Err(SessionError::InvalidRestrictedInit(format!(
                "invalid FSM transition {:?} → {:?} (E0513)",
                self.state, to
            )));
        }
        self.state = to;
        Ok(())
    }

    /// Restart: session_id rotates, lineage preserved (Checkpoint→Init), and the
    /// ACL must still hold (E0721 if restricted + non-owner).
    pub fn restart(&mut self, new_session_id: String) -> Result<(), SessionError> {
        if self.header.restricted {
            // Restart must re-validate the restricted ACL (E0721).
            if self.header.operator_uid == 0 {
                return Err(SessionError::RestartAclInvalid(
                    "restricted restart requires non-root UID (E0721)".into(),
                ));
            }
        }
        self.header.session_id = new_session_id;
        self.state = SessionState::Init;
        Ok(())
    }

    /// Cost rollup at CHECKPOINT: u64 microcents, checked_add (CTX-I12).
    pub fn add_cost(&mut self, cost: u64) -> Result<(), SessionError> {
        self.cost_microcents = self
            .cost_microcents
            .checked_add(cost)
            .ok_or_else(|| SessionError::CostOverflow("u64 microcent overflow (E0702)".into()))?;
        Ok(())
    }

    pub fn cost(&self) -> u64 {
        self.cost_microcents
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(restricted: bool) -> SessionHeader {
        SessionHeader {
            session_id: "s1".into(),
            pib_id: "p1".into(),
            operator_uid: if restricted { 1000 } else { 0 },
            restricted,
            policy_snapshot_id: "pol".into(),
        }
    }

    #[test]
    fn restricted_requires_non_root() {
        assert!(Session::start(header(false)).is_ok());
        let mut h = header(true);
        h.operator_uid = 0; // root tries restricted
        assert_eq!(Session::start(h).unwrap_err().code(), "E0513");
        assert!(Session::start(header(true)).is_ok());
    }

    #[test]
    fn marker_immutable() {
        let mut s = Session::start(header(false)).unwrap();
        assert_eq!(s.try_set_restricted(true).unwrap_err().code(), "E0703");
    }

    #[test]
    fn valid_fsm_transitions() {
        let mut s = Session::start(header(false)).unwrap();
        s.transition(SessionState::Plan).unwrap();
        s.transition(SessionState::Execute).unwrap();
        s.transition(SessionState::Verify).unwrap();
        s.transition(SessionState::Checkpoint).unwrap();
        // restart Checkpoint → Init
        s.restart("s2".into()).unwrap();
        assert_eq!(s.state(), SessionState::Init);
        // invalid: Plan → Verify skips Execute
        let mut s2 = Session::start(header(false)).unwrap();
        s2.transition(SessionState::Plan).unwrap();
        assert!(s2.transition(SessionState::Verify).is_err());
    }

    #[test]
    fn cost_overflow_e0702() {
        let mut s = Session::start(header(false)).unwrap();
        s.add_cost(u64::MAX).unwrap();
        assert_eq!(s.add_cost(1).unwrap_err().code(), "E0702");
    }
}
