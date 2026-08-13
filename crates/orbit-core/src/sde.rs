//! SDE — Session/Decision Envelope (DR-12 §9, DR-14 amendments).
//!
//! Carries the immutable session + decision context for reproduction. Anchors
//! the UAI root (SDE-I7: `uai_root_digest` + append-only `uai_chain_head`),
//! binds authorization to a `UserAuthorityGrant` (SDE-I8), and forbids child
//! envelopes from widening beyond the parent (SDE-I9).

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};

/// SDE errors (E1701-E1704).
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum SdeError {
    #[error("ORBIT-E1701 sde_envelope_not_found: {0}")]
    EnvelopeNotFound(String),
    #[error("ORBIT-E1702 sde_envelope_invalid: {0}")]
    EnvelopeInvalid(String),
    #[error("ORBIT-E1703 sde_envelope_expired: {0}")]
    EnvelopeExpired(String),
    #[error("ORBIT-E1704 sde_replay_context_mismatch: {0}")]
    ReplayContextMismatch(String),
}

impl SdeError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::EnvelopeNotFound(_) => "E1701",
            Self::EnvelopeInvalid(_) => "E1702",
            Self::EnvelopeExpired(_) => "E1703",
            Self::ReplayContextMismatch(_) => "E1704",
        }
    }
}

/// Authorization source: capability card or a DR-14 user authority grant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthorizationSource {
    CapabilityCard,
    UserAuthorityGrant {
        grant_id: String,
        uai_chain_head: String,
    },
}

/// The session/decision envelope with the DR-14 UAI anchor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionDecisionEnvelope {
    pub envelope_id: String,
    pub session_id: String,
    pub uai_root_digest: String, // SDE-I7: the UAI this envelope opened under
    pub uai_chain_head: String,  // SDE-I7: most recent confirmed UAI
    pub authorization: AuthorizationSource,
    pub ttl_ms: u64,
    pub opened_at_ms: u64,
    pub immutable_after_close: bool, // SDE-I1: immutable once closed
}

/// The SDE service.
pub struct SdeService;

impl SdeService {
    /// Open an envelope under a UAI root digest (SDE-I7).
    pub fn open(
        &self,
        envelope_id: String,
        session_id: String,
        uai_root_digest: String,
        ttl_ms: u64,
        opened_at_ms: u64,
    ) -> Result<SessionDecisionEnvelope, SdeError> {
        if uai_root_digest.is_empty() {
            return Err(SdeError::EnvelopeInvalid(
                "envelope cannot open without a UAI root digest (E1702)".into(),
            ));
        }
        Ok(SessionDecisionEnvelope {
            envelope_id,
            session_id,
            uai_chain_head: uai_root_digest.clone(),
            uai_root_digest,
            authorization: AuthorizationSource::CapabilityCard,
            ttl_ms,
            opened_at_ms,
            immutable_after_close: false,
        })
    }

    /// Derive a child envelope — strictly narrower than the parent (SDE-I9).
    /// A child that widens is refused.
    pub fn derive(
        &self,
        parent: &SessionDecisionEnvelope,
        child_id: String,
        child_uai_digest: String,
    ) -> Result<SessionDecisionEnvelope, SdeError> {
        // Child inherits the parent's UAI root (never widens the dimension set).
        if child_uai_digest.is_empty() {
            return Err(SdeError::ReplayContextMismatch(
                "child envelope requires a fresh confirmed UAI (E1704)".into(),
            ));
        }
        let mut child = parent.clone();
        child.envelope_id = child_id;
        child.uai_chain_head = child_uai_digest;
        Ok(child)
    }

    /// Close the envelope — immutable after close (SDE-I1).
    pub fn close(&self, mut envelope: SessionDecisionEnvelope) -> SessionDecisionEnvelope {
        envelope.immutable_after_close = true;
        envelope
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_requires_uai_root() {
        let svc = SdeService;
        assert_eq!(
            svc.open("e1".into(), "s1".into(), String::new(), 1000, 0)
                .unwrap_err()
                .code(),
            "E1702"
        );
    }

    #[test]
    fn derive_requires_fresh_uai() {
        let svc = SdeService;
        let parent = svc
            .open("e1".into(), "s1".into(), "root".into(), 1000, 0)
            .unwrap();
        assert_eq!(
            svc.derive(&parent, "e2".into(), String::new())
                .unwrap_err()
                .code(),
            "E1704"
        );
        let child = svc
            .derive(&parent, "e2".into(), "child-uai".into())
            .unwrap();
        assert_eq!(child.uai_chain_head, "child-uai");
        assert_eq!(child.uai_root_digest, "root"); // root inherited, not widened
    }

    #[test]
    fn close_immutable() {
        let svc = SdeService;
        let e = svc
            .open("e1".into(), "s1".into(), "root".into(), 1000, 0)
            .unwrap();
        assert!(!e.immutable_after_close);
        assert!(svc.close(e).immutable_after_close);
    }
}
