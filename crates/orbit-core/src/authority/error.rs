//! ORBIT authority errors — canonical E19xx family (DR-14 §5).

use thiserror::Error;

/// Authority subsystem errors (E19xx).
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum AuthorityError {
    /// E1901 directive_in_non_authoritative_text
    #[error("ORBIT-E1901 directive_in_non_authoritative_text: {0}")]
    DirectiveInNonAuthoritative(String),
    /// E1902 directive_target_unsupported
    #[error("ORBIT-E1902 directive_target_unsupported: {0}")]
    DirectiveTargetUnsupported(String),
    /// E1903 directive_references_internal_id (kernel — refused even with confirmation)
    #[error("ORBIT-E1903 directive_references_internal_id: {0}")]
    ReferencesInternalId(String),
    /// E1904 directive_conflicting_classes
    #[error("ORBIT-E1904 directive_conflicting_classes: {0}")]
    ConflictingDirectives(String),
    /// E1905 directive_no_user_typed_source
    #[error("ORBIT-E1905 directive_no_user_typed_source: {0}")]
    NoUserTypedSource(String),
    /// E1906 uai_widening_unconfirmed
    #[error("ORBIT-E1906 uai_widening_unconfirmed: {0}")]
    WideningUnconfirmed(String),
    /// E1907 uai_widening_denied
    #[error("ORBIT-E1907 uai_widening_denied: {0}")]
    WideningDenied(String),
    /// E1908 uai_widening_expired
    #[error("ORBIT-E1908 uai_widening_expired: {0}")]
    WideningExpired(String),
    /// E1909 uai_provenance_untrusted
    #[error("ORBIT-E1909 uai_provenance_untrusted: {0}")]
    ProvenanceUntrusted(String),
    /// E1910 uai_kernel_override_attempt (never confirmable)
    #[error("ORBIT-E1910 uai_kernel_override_attempt: {0}")]
    KernelOverrideAttempt(String),
    /// E1914 confirm_denied
    #[error("ORBIT-E1914 confirm_denied: {0}")]
    ConfirmDenied(String),
    /// E1943 programmatic_policy_signature_invalid
    #[error("ORBIT-E1943 programmatic_policy_signature_invalid: {0}")]
    PolicySignatureInvalid(String),
    /// E1944 programmatic_policy_replay_detected
    #[error("ORBIT-E1944 programmatic_policy_replay_detected: {0}")]
    PolicyReplayDetected(String),
    /// E1945 programmatic_policy_revoked
    #[error("ORBIT-E1945 programmatic_policy_revoked: {0}")]
    PolicyRevoked(String),
}

impl AuthorityError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::DirectiveInNonAuthoritative(_) => "E1901",
            Self::DirectiveTargetUnsupported(_) => "E1902",
            Self::ReferencesInternalId(_) => "E1903",
            Self::ConflictingDirectives(_) => "E1904",
            Self::NoUserTypedSource(_) => "E1905",
            Self::WideningUnconfirmed(_) => "E1906",
            Self::WideningDenied(_) => "E1907",
            Self::WideningExpired(_) => "E1908",
            Self::ProvenanceUntrusted(_) => "E1909",
            Self::KernelOverrideAttempt(_) => "E1910",
            Self::ConfirmDenied(_) => "E1914",
            Self::PolicySignatureInvalid(_) => "E1943",
            Self::PolicyReplayDetected(_) => "E1944",
            Self::PolicyRevoked(_) => "E1945",
        }
    }
}
