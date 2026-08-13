//! ORBIT trust errors — canonical E07xx family (DR-05, DR-03 §13).
//!
//! Every code here is registered in `spec/errors.yaml` with the same id/name/meaning.

use thiserror::Error;

/// Trust subsystem errors (E0706, E0711-E0719).
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum TrustError {
    /// ORBIT-E0706 trust_root_invalid — manifest signature failed against all roots.
    #[error("ORBIT-E0706 trust_root_invalid: {0}")]
    RootInvalid(String),

    /// ORBIT-E0713 manifest_schema_invalid — manifest JSON does not match the schema.
    #[error("ORBIT-E0713 manifest_schema_invalid: {0}")]
    ManifestSchemaInvalid(String),

    /// ORBIT-E0714 manifest_version_unsupported — manifest v is not supported.
    #[error("ORBIT-E0714 manifest_version_unsupported: {0}")]
    ManifestVersionUnsupported(String),

    /// ORBIT-E0715 root_algorithm_unsupported — root key uses an unsupported algorithm.
    #[error("ORBIT-E0715 root_algorithm_unsupported: {0}")]
    RootAlgorithmUnsupported(String),

    /// ORBIT-E0716 trust_level_invalid — trust level is not one of Standard|Attested|Local.
    #[error("ORBIT-E0716 trust_level_invalid: {0}")]
    TrustLevelInvalid(String),

    /// ORBIT-E0717 issuer_key_unknown — an issuer key referenced is not in the allowlist.
    #[error("ORBIT-E0717 issuer_key_unknown: {0}")]
    IssuerKeyUnknown(String),

    /// ORBIT-E0711 registry_bootstrap_incomplete — startup registry incomplete.
    #[error("ORBIT-E0711 registry_bootstrap_incomplete: {0}")]
    RegistryBootstrapIncomplete(String),

    /// ORBIT-E0712 registry_periodic_refresh_failed — periodic registry refresh failed.
    #[error("ORBIT-E0712 registry_periodic_refresh_failed: {0}")]
    RegistryPeriodicRefreshFailed(String),

    /// ORBIT-E0718 namespace_owner_invalid — namespace owner key not allowlisted.
    #[error("ORBIT-E0718 namespace_owner_invalid: {0}")]
    NamespaceOwnerInvalid(String),

    /// ORBIT-E0719 ledger_unavailable_at_boot — Ledger not reachable during startup.
    #[error("ORBIT-E0719 ledger_unavailable_at_boot: {0}")]
    LedgerUnavailableAtBoot(String),
}

impl TrustError {
    /// Stable string form of the ORBIT-E code.
    pub fn code(&self) -> &'static str {
        match self {
            Self::RootInvalid(_) => "E0706",
            Self::ManifestSchemaInvalid(_) => "E0713",
            Self::ManifestVersionUnsupported(_) => "E0714",
            Self::RootAlgorithmUnsupported(_) => "E0715",
            Self::TrustLevelInvalid(_) => "E0716",
            Self::IssuerKeyUnknown(_) => "E0717",
            Self::RegistryBootstrapIncomplete(_) => "E0711",
            Self::RegistryPeriodicRefreshFailed(_) => "E0712",
            Self::NamespaceOwnerInvalid(_) => "E0718",
            Self::LedgerUnavailableAtBoot(_) => "E0719",
        }
    }
}
