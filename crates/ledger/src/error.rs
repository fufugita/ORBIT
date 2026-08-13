//! ORBIT Ledger errors — canonical E03xx/E06xx/E07xx families (DR-06, DR-03 §13).

use thiserror::Error;

/// Ledger subsystem errors.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum LedgerError {
    /// ORBIT-E0301 egress_intent_append_failed
    #[error("ORBIT-E0301 egress_intent_append_failed: {0}")]
    EgressIntentAppendFailed(String),

    /// ORBIT-E0302 egress_intent_durability_ambiguous
    #[error("ORBIT-E0302 egress_intent_durability_ambiguous: {0}")]
    EgressIntentDurabilityAmbiguous(String),

    /// ORBIT-E0602 verify_failed
    #[error("ORBIT-E0602 verify_failed: {0}")]
    VerifyFailed(String),

    /// ORBIT-E0701 decision_id_already_consumed
    #[error("ORBIT-E0701 decision_id_already_consumed: {0}")]
    DecisionIdAlreadyConsumed(String),

    /// ORBIT-E0702 ledger_rollup_overflow
    #[error("ORBIT-E0702 ledger_rollup_overflow: {0}")]
    LedgerRollupOverflow(String),

    /// ORBIT-E0700 ledger_required_for_mutation
    #[error("ORBIT-E0700 ledger_required_for_mutation: {0}")]
    LedgerRequiredForMutation(String),

    /// ORBIT-E0705 restricted_acl_invalid
    #[error("ORBIT-E0705 restricted_acl_invalid: {0}")]
    RestrictedAclInvalid(String),

    /// ORBIT-E0708 aux_ref_not_committed
    #[error("ORBIT-E0708 aux_ref_not_committed: {0}")]
    AuxRefNotCommitted(String),

    /// ORBIT-E0709 ledger_recovery_truncated
    #[error("ORBIT-E0709 ledger_recovery_truncated: {0}")]
    LedgerRecoveryTruncated(String),

    /// ORBIT-E0719 ledger_unavailable_at_boot
    #[error("ORBIT-E0719 ledger_unavailable_at_boot: {0}")]
    LedgerUnavailableAtBoot(String),

    /// ORBIT-E1921 grant_write_not_fsynced (DR-14)
    #[error("ORBIT-E1921 grant_write_not_fsynced: {0}")]
    GrantWriteNotFsynced(String),

    /// ORBIT-E1923 grant_replay_detected (DR-14)
    #[error("ORBIT-E1923 grant_replay_detected: {0}")]
    GrantReplayDetected(String),
}

impl LedgerError {
    /// Stable ORBIT-E code string.
    pub fn code(&self) -> &'static str {
        match self {
            Self::EgressIntentAppendFailed(_) => "E0301",
            Self::EgressIntentDurabilityAmbiguous(_) => "E0302",
            Self::VerifyFailed(_) => "E0602",
            Self::DecisionIdAlreadyConsumed(_) => "E0701",
            Self::LedgerRollupOverflow(_) => "E0702",
            Self::LedgerRequiredForMutation(_) => "E0700",
            Self::RestrictedAclInvalid(_) => "E0705",
            Self::AuxRefNotCommitted(_) => "E0708",
            Self::LedgerRecoveryTruncated(_) => "E0709",
            Self::LedgerUnavailableAtBoot(_) => "E0719",
            Self::GrantWriteNotFsynced(_) => "E1921",
            Self::GrantReplayDetected(_) => "E1923",
        }
    }
}
