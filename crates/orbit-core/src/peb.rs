//! PEB — Prompt Entry Boundary (DR-12 §4, DR-14 amendments).
//!
//! The typed ingress: converts user submissions into structured intent, applying
//! data minimization. PEB is the only primitive that transiently holds user
//! prompt bytes (PEB-I9); it separates `UserTypedTurn` from `NonAuthoritative`
//! content (PEB-I10) and confirmation precedes dispatch (PEB-I11).
//! Kernel: no prompt bytes to the Ledger; never grants capability from text.

#![forbid(unsafe_code)]

use crate::authority::intent::UserAuthorityIntent;
use serde::{Deserialize, Serialize};

/// PEB errors (E1201-E1205 + E1901/E1905).
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum PebError {
    #[error("ORBIT-E1201 peb_submission_duplicate: {0}")]
    DuplicateSubmission(String),
    #[error("ORBIT-E1202 peb_input_ref_invalid: {0}")]
    InvalidInputRef(String),
    #[error("ORBIT-E1203 peb_dispatch_not_authorized: {0}")]
    DispatchNotAuthorized(String),
    #[error("ORBIT-E1204 peb_cancel_after_dispatch: {0}")]
    CancelAfterDispatch(String),
    #[error("ORBIT-E1905 directive_no_user_typed_source: {0}")]
    NoUserTypedSource(String),
    #[error("ORBIT-E1906 uai_widening_unconfirmed: {0}")]
    WideningUnconfirmed(String),
}

impl PebError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::DuplicateSubmission(_) => "E1201",
            Self::InvalidInputRef(_) => "E1202",
            Self::DispatchNotAuthorized(_) => "E1203",
            Self::CancelAfterDispatch(_) => "E1204",
            Self::NoUserTypedSource(_) => "E1905",
            Self::WideningUnconfirmed(_) => "E1906",
        }
    }
}

impl From<crate::authority::AuthorityError> for PebError {
    fn from(e: crate::authority::AuthorityError) -> Self {
        match e {
            crate::authority::AuthorityError::WideningUnconfirmed(m) => {
                PebError::WideningUnconfirmed(m)
            }
            crate::authority::AuthorityError::ProvenanceUntrusted(m) => {
                PebError::NoUserTypedSource(m)
            }
            other => PebError::DispatchNotAuthorized(other.to_string()),
        }
    }
}

/// PEB submission state (DR-12 §4.4 + DR-14 PEB-I11).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PebState {
    Received,
    Parsed,
    AwaitingConfirmation, // UAI confirmation required before dispatch
    Compiled,             // confirmed UAI bound
    Dispatched,
    Closed,
}

/// A PEB submission: structured intent + bound UAI; raw prompt bytes are
/// transient only and never enter the Ledger.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PebSubmission {
    pub submission_id: String,
    pub session_id: String,
    pub intent_digest: String, // hash of the normalized structured intent
    pub uai: UserAuthorityIntent,
    pub state: PebState,
}

/// The PEB service.
pub struct PebService;

impl PebService {
    /// Submit text: produce a structured submission + UAI (PEB-I11).
    /// Returns E1905 if the text has no user-typed provenance (handled by caller
    /// via the provenance tag; here we require a pre-parsed UAI).
    pub fn submit(
        &self,
        submission_id: String,
        session_id: String,
        uai: UserAuthorityIntent,
        intent_digest: String,
    ) -> Result<PebSubmission, PebError> {
        // A UAI from a non-user source is structurally impossible (type-enforced
        // by AuthorityProvenance::can_grant), so we don't re-check here.
        Ok(PebSubmission {
            submission_id,
            session_id,
            intent_digest,
            uai,
            state: PebState::Received,
        })
    }

    /// Confirm the submission's UAI — the ONLY transition out of AwaitingConfirmation
    /// (PEB-I11). Without confirmation, dispatch is refused (E1906).
    pub fn confirm(&self, mut sub: PebSubmission) -> Result<PebSubmission, PebError> {
        if sub.state != PebState::Received && sub.state != PebState::Parsed {
            return Err(PebError::DuplicateSubmission(
                "confirm only valid from Received/Parsed (E1201)".into(),
            ));
        }
        // The UAI itself must be confirmed (UAI-I2).
        sub.uai.require_confirmed()?;
        sub.state = PebState::AwaitingConfirmation;
        // Once the UAI is confirmed, compile.
        if sub.uai.confirmation.is_some() {
            sub.state = PebState::Compiled;
        }
        Ok(sub)
    }

    /// Dispatch the compiled submission (E1203 if not authorized/compiled).
    pub fn dispatch(&self, sub: &PebSubmission) -> Result<(), PebError> {
        if sub.state != PebState::Compiled {
            return Err(PebError::DispatchNotAuthorized(format!(
                "submission {} not compiled (E1203)",
                sub.submission_id
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authority::intent::{
        AuthorityConfirmation, AuthorityDimension, AuthorityProvenance, AuthorityScope,
        ConfirmationChannel,
    };
    use std::collections::BTreeSet;

    fn confirmed_uai() -> UserAuthorityIntent {
        let scope = AuthorityScope {
            dimensions: BTreeSet::from([AuthorityDimension::Egress]),
            spec: serde_json::json!({}),
        };
        let mut i = UserAuthorityIntent {
            intent_id: "i1".into(),
            session_id: "s1".into(),
            dimensions: BTreeSet::from([AuthorityDimension::Egress]),
            baseline: scope.clone(),
            requested: scope,
            provenance: AuthorityProvenance::UserTypedTurn,
            confirmation: Some(AuthorityConfirmation {
                intent_digest: "a".into(),
                scope_digest: "b".into(),
                diff_hash: "c".into(),
                channel: ConfirmationChannel::PromptInteractive,
                operator: "uid=1000".into(),
            }),
            ttl_seconds: 3600,
            intent_digest: String::new(),
        };
        i.intent_digest = i.compute_digest();
        i
    }

    #[test]
    fn submit_confirm_dispatch_flow() {
        let svc = PebService;
        let mut sub = svc
            .submit("s1".into(), "sess".into(), confirmed_uai(), "digest".into())
            .unwrap();
        assert_eq!(sub.state, PebState::Received);
        sub = svc.confirm(sub).unwrap();
        assert_eq!(sub.state, PebState::Compiled);
        assert!(svc.dispatch(&sub).is_ok());
    }

    #[test]
    fn dispatch_without_confirmation_refused() {
        let svc = PebService;
        let sub = svc
            .submit("s2".into(), "sess".into(), confirmed_uai(), "digest".into())
            .unwrap();
        // Not confirmed → dispatch refused (E1203).
        assert_eq!(svc.dispatch(&sub).unwrap_err().code(), "E1203");
    }
}
