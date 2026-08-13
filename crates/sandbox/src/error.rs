//! ORBIT sandbox errors — canonical E08xx family (DR-07, DR-03 §13).

use thiserror::Error;

/// Sandbox subsystem errors.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum SandboxError {
    /// ORBIT-E0801 plugin_wasi_violation
    #[error("ORBIT-E0801 plugin_wasi_violation: {0}")]
    WasiViolation(String),
    /// ORBIT-E0802 sandbox_required
    #[error("ORBIT-E0802 sandbox_required: {0}")]
    SandboxRequired(String),
    /// ORBIT-E0803 landlock_abi_unavailable
    #[error("ORBIT-E0803 landlock_abi_unavailable: {0}")]
    LandlockAbiUnavailable(String),
    /// ORBIT-E0804 sandbox_override_widens_profile
    #[error("ORBIT-E0804 sandbox_override_widens_profile: {0}")]
    OverrideWidensProfile(String),
    /// ORBIT-E0805 env_reserved_name
    #[error("ORBIT-E0805 env_reserved_name: {0}")]
    EnvReservedName(String),
    /// ORBIT-E0808 plugin_import_outside_allowlist
    #[error("ORBIT-E0808 plugin_import_outside_allowlist: {0}")]
    ImportOutsideAllowlist(String),
    /// ORBIT-E0812 seccomp_filter_rejected
    #[error("ORBIT-E0812 seccomp_filter_rejected: {0}")]
    SeccompFilterRejected(String),
    /// ORBIT-E0807 instance_pool_exhausted
    #[error("ORBIT-E0807 instance_pool_exhausted: {0}")]
    InstancePoolExhausted(String),
}

impl SandboxError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::WasiViolation(_) => "E0801",
            Self::SandboxRequired(_) => "E0802",
            Self::LandlockAbiUnavailable(_) => "E0803",
            Self::OverrideWidensProfile(_) => "E0804",
            Self::EnvReservedName(_) => "E0805",
            Self::ImportOutsideAllowlist(_) => "E0808",
            Self::SeccompFilterRejected(_) => "E0812",
            Self::InstancePoolExhausted(_) => "E0807",
        }
    }
}
