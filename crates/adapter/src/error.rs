//! Adapter error family — DR-09 §10 E04xx codes.
//!
//! The public envelope (DR-09 §10): code + typed reason + safe action hint.
//! Never arbitrary upstream text. Retry classification drives GW-07 — only
//! RetryableTransport / RetryableRate classes may be retried, and only once.

use crate::types::AdapterKind;

/// Stable ORBIT-E code for each adapter failure.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum AdapterError {
    /// ORBIT-E0401 provider_configuration_invalid
    #[error("ORBIT-E0401 provider_configuration_invalid: {0}")]
    ProviderConfigurationInvalid(String),
    /// ORBIT-E0402 credential_missing
    #[error("ORBIT-E0402 credential_missing: {0}")]
    CredentialMissing(String),
    /// ORBIT-E0403 credential_rejected
    #[error("ORBIT-E0403 credential_rejected: {0}")]
    CredentialRejected(String),
    /// ORBIT-E0404 provider_permission_denied
    #[error("ORBIT-E0404 provider_permission_denied: {0}")]
    ProviderPermissionDenied(String),
    /// ORBIT-E0405 model_or_deployment_not_found
    #[error("ORBIT-E0405 model_or_deployment_not_found: {0}")]
    ModelOrDeploymentNotFound(String),
    /// ORBIT-E0406 request_invalid_or_too_large
    #[error("ORBIT-E0406 request_invalid_or_too_large: {0}")]
    RequestInvalidOrTooLarge(String),
    /// ORBIT-E0407 rate_limited_exhausted
    #[error("ORBIT-E0407 rate_limited_exhausted: {0}")]
    RateLimitedExhausted(String),
    /// ORBIT-E0408 capacity_unavailable_exhausted
    #[error("ORBIT-E0408 capacity_unavailable_exhausted: {0}")]
    CapacityUnavailableExhausted(String),
    /// ORBIT-E0409 provider_timeout
    #[error("ORBIT-E0409 provider_timeout: {0}")]
    ProviderTimeout(String),
    /// ORBIT-E0410 provider_transport_failure
    #[error("ORBIT-E0410 provider_transport_failure: {0}")]
    ProviderTransportFailure(String),
    /// ORBIT-E0411 provider_protocol_or_stream_violation
    #[error("ORBIT-E0411 provider_protocol_or_stream_violation: {0}")]
    ProtocolOrStreamViolation(String),
    /// ORBIT-E0412 dispatch_ambiguous
    #[error("ORBIT-E0412 dispatch_ambiguous: {0}")]
    DispatchAmbiguous(String),
    /// ORBIT-E0413 provider_binding_drift
    #[error("ORBIT-E0413 provider_binding_drift: {0}")]
    BindingDrift(String),
    /// ORBIT-E0414 adapter_capability_mismatch
    #[error("ORBIT-E0414 adapter_capability_mismatch: {0}")]
    CapabilityMismatch(String),
    /// ORBIT-E0415 local_provider_sandbox_or_process_failure
    #[error("ORBIT-E0415 local_provider_sandbox_or_process_failure: {0}")]
    LocalProviderSandboxOrProcessFailure(String),
    /// ORBIT-E0416 provider_usage_invalid
    #[error("ORBIT-E0416 provider_usage_invalid: {0}")]
    ProviderUsageInvalid(String),
    /// ORBIT-E0417 stream_consumer_stalled
    #[error("ORBIT-E0417 stream_consumer_stalled: {0}")]
    StreamConsumerStalled(String),
    /// ORBIT-E0418 credential_source_acl_invalid
    #[error("ORBIT-E0418 credential_source_acl_invalid: {0}")]
    CredentialSourceAclInvalid(String),
    /// ORBIT-E0419 cost_arithmetic_overflow
    #[error("ORBIT-E0419 cost_arithmetic_overflow: {0}")]
    CostArithmeticOverflow(String),
    /// ORBIT-E0420 mixed_currency_scalar_rollup_forbidden
    #[error("ORBIT-E0420 mixed_currency_scalar_rollup_forbidden: {0}")]
    MixedCurrencyScalarRollupForbidden(String),
    /// ORBIT-E0421 route_lifecycle_denied
    #[error("ORBIT-E0421 route_lifecycle_denied: {0}")]
    RouteLifecycleDenied(String),
    /// ORBIT-E0422 adapter_profile_digest_mismatch
    #[error("ORBIT-E0422 adapter_profile_digest_mismatch: {0}")]
    AdapterProfileDigestMismatch(String),
    /// ORBIT-E0423 live_discovery_not_authorized
    #[error("ORBIT-E0423 live_discovery_not_authorized: {0}")]
    LiveDiscoveryNotAuthorized(String),
}

/// Retry classification (GW-07). Mirrors the gateway's `RetryClass` for the
/// adapter side: an adapter NEVER retries on its own — it classifies and the
/// gateway decides.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdapterRetryClass {
    RetryableTransport,
    RetryableRate,
    NotRetryable,
}

impl AdapterError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::ProviderConfigurationInvalid(_) => "E0401",
            Self::CredentialMissing(_) => "E0402",
            Self::CredentialRejected(_) => "E0403",
            Self::ProviderPermissionDenied(_) => "E0404",
            Self::ModelOrDeploymentNotFound(_) => "E0405",
            Self::RequestInvalidOrTooLarge(_) => "E0406",
            Self::RateLimitedExhausted(_) => "E0407",
            Self::CapacityUnavailableExhausted(_) => "E0408",
            Self::ProviderTimeout(_) => "E0409",
            Self::ProviderTransportFailure(_) => "E0410",
            Self::ProtocolOrStreamViolation(_) => "E0411",
            Self::DispatchAmbiguous(_) => "E0412",
            Self::BindingDrift(_) => "E0413",
            Self::CapabilityMismatch(_) => "E0414",
            Self::LocalProviderSandboxOrProcessFailure(_) => "E0415",
            Self::ProviderUsageInvalid(_) => "E0416",
            Self::StreamConsumerStalled(_) => "E0417",
            Self::CredentialSourceAclInvalid(_) => "E0418",
            Self::CostArithmeticOverflow(_) => "E0419",
            Self::MixedCurrencyScalarRollupForbidden(_) => "E0420",
            Self::RouteLifecycleDenied(_) => "E0421",
            Self::AdapterProfileDigestMismatch(_) => "E0422",
            Self::LiveDiscoveryNotAuthorized(_) => "E0423",
        }
    }

    /// The retry class (GW-07). Only transport + bounded rate are retryable.
    pub fn retry_class(&self) -> AdapterRetryClass {
        match self {
            Self::ProviderTransportFailure(_) | Self::ProviderTimeout(_) => {
                AdapterRetryClass::RetryableTransport
            }
            Self::RateLimitedExhausted(_) | Self::CapacityUnavailableExhausted(_) => {
                AdapterRetryClass::RetryableRate
            }
            _ => AdapterRetryClass::NotRetryable,
        }
    }

    /// Safe action hint (DR-09 §10). Never arbitrary upstream text.
    pub fn hint(&self) -> &'static str {
        match self {
            Self::CredentialMissing(_) => "check credential source is configured",
            Self::CredentialRejected(_) => "re-authenticate the credential source",
            Self::ProviderPermissionDenied(_) => "verify provider account permissions",
            Self::ModelOrDeploymentNotFound(_) => "verify the deployment exists and is active",
            Self::RateLimitedExhausted(_) => "retry after the provider's rate-limit window",
            Self::CapacityUnavailableExhausted(_) => "retry after provider capacity recovers",
            Self::ProviderTimeout(_) => "increase timeouts or retry once",
            Self::ProviderTransportFailure(_) => "check network/egress configuration",
            Self::ProtocolOrStreamViolation(_) => "check provider response format",
            Self::DispatchAmbiguous(_) => "confirm intent; create a fresh call",
            Self::RouteLifecycleDenied(_) => "the route is sunset/retired; use a supported one",
            Self::MixedCurrencyScalarRollupForbidden(_) => "aggregate per currency, never scalar",
            Self::AdapterProfileDigestMismatch(_) => "update the signed route profile",
            _ => "contact operator",
        }
    }
}

/// Render a digest mismatch with the two digests for diagnostics (E0422).
pub fn profile_mismatch(kind: AdapterKind, expected: &str, actual: &str) -> AdapterError {
    AdapterError::AdapterProfileDigestMismatch(format!(
        "{kind:?}: expected profile digest {expected}, got {actual} (E0422)"
    ))
}
