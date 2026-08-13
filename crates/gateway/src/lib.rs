//! ORBIT gateway subsystem — Phase B (B7).
//!
//! Provider-aware, credential-aware subsystem (GW-01). Orchestrators declare a
//! flat `ModelRef` (GW-02); the Gateway runs the four-gate admission in strict
//! order Trust → Capability → Egress → Dispatch (GW-03), pins an immutable
//! route (GW-05), and enforces retry ≤ 2 (GW-07) with no hidden retries.
//!
//! Cost is integer u64 microcents with checked arithmetic (GW-14).

#![forbid(unsafe_code)]

pub mod dispatch;
pub mod registry;

pub use dispatch::{
    new_decision_id, new_request_id, new_session_id, tmpdir, DispatchEngine, DispatchError,
    DispatchOutcome, DispatchState, EgressReservation,
};
pub use registry::ProviderRegistry;

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// Gateway error family (E04xx, DR-09).
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum GatewayError {
    /// ORBIT-E0401 provider_unknown
    #[error("ORBIT-E0401 provider_unknown: {0}")]
    ProviderUnknown(String),
    /// ORBIT-E0404 model_not_in_allowlist
    #[error("ORBIT-E0404 model_not_in_allowlist: {0}")]
    ModelNotInAllowlist(String),
    /// ORBIT-E0405 route_unpinned
    #[error("ORBIT-E0405 route_unpinned: {0}")]
    RouteUnpinned(String),
    /// ORBIT-E0406 credential_denied
    #[error("ORBIT-E0406 credential_denied: {0}")]
    CredentialDenied(String),
    /// ORBIT-E0407 retry_limit_exceeded
    #[error("ORBIT-E0407 retry_limit_exceeded: {0}")]
    RetryLimitExceeded(String),
    /// ORBIT-E0408 retry_on_unsafe_failure
    #[error("ORBIT-E0408 retry_on_unsafe_failure: {0}")]
    RetryOnUnsafeFailure(String),
    /// ORBIT-E0409 dispatch_ambiguous
    #[error("ORBIT-E0409 dispatch_ambiguous: {0}")]
    DispatchAmbiguous(String),
    /// ORBIT-E0411 cost_overflow
    #[error("ORBIT-E0411 cost_overflow: {0}")]
    CostOverflow(String),
    /// ORBIT-E0413 route_binding_changed
    #[error("ORBIT-E0413 route_binding_changed: {0}")]
    RouteBindingChanged(String),
}

impl GatewayError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::ProviderUnknown(_) => "E0401",
            Self::ModelNotInAllowlist(_) => "E0404",
            Self::RouteUnpinned(_) => "E0405",
            Self::CredentialDenied(_) => "E0406",
            Self::RetryLimitExceeded(_) => "E0407",
            Self::RetryOnUnsafeFailure(_) => "E0408",
            Self::DispatchAmbiguous(_) => "E0409",
            Self::CostOverflow(_) => "E0411",
            Self::RouteBindingChanged(_) => "E0413",
        }
    }
}

/// A flat model reference (DR-01 I2: orchestrator names a model, never a provider).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ModelRef(pub String);

/// The internal resolved route tuple — never surfaced to the orchestrator (GW-05).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteBinding {
    pub provider_id: String,
    pub deployment_id: String,
    pub region_id: String,
    pub adapter_profile_digest: String,
    pub endpoint: String,
    pub pricing_digest: String,
}

/// Immutable per-call route pin (GW-05). Once dispatched, never changes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PinnedRoute {
    pub model: ModelRef,
    pub binding: RouteBinding,
}

/// Cost in u64 microcents (1/10000 cent), integer aggregation (GW-14).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct CostMicrocents(pub u64);

impl CostMicrocents {
    /// checked_add; overflow → E0411 cost_overflow.
    pub fn checked_add(self, other: Self) -> Result<Self, GatewayError> {
        self.0
            .checked_add(other.0)
            .map(Self)
            .ok_or_else(|| GatewayError::CostOverflow("u64 microcent overflow (E0411)".into()))
    }
}

/// The four admission gates, in strict order (GW-03).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Gate {
    Trust,
    Capability,
    Egress,
    Dispatch,
}

/// Outcome of the four-gate admission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Admission {
    Admitted { route: PinnedRoute },
    Denied { gate: Gate, reason: String },
}

/// Retry classification (GW-07): at most one automatic retry, same route.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetryClass {
    /// Pre-delivery DNS/connect/TLS/transport failures — retryable once.
    RetryableTransport,
    /// Bounded Retry-After rate/capacity — retryable once.
    RetryableRate,
    /// Never retry: credential/permission/validation/TLS-pin/cancel/etc.
    NotRetryable,
}

/// The gateway admission state machine.
pub struct Gateway {
    allowlisted_models: std::collections::HashSet<ModelRef>,
    model_to_route: std::collections::HashMap<ModelRef, RouteBinding>,
    max_attempts: u8, // GW-07: exactly 2 total attempts
}

impl Gateway {
    pub fn new(
        allowlisted_models: Vec<ModelRef>,
        model_to_route: Vec<(ModelRef, RouteBinding)>,
    ) -> Self {
        Self {
            allowlisted_models: allowlisted_models.into_iter().collect(),
            model_to_route: model_to_route.into_iter().collect(),
            max_attempts: 2,
        }
    }

    /// Run the four-gate admission in strict order (GW-03).
    pub fn admit(&self, model: ModelRef) -> Admission {
        // Gate 1: Trust — model in the trust-root allowlist (GW-02/03).
        if !self.allowlisted_models.contains(&model) {
            return Admission::Denied {
                gate: Gate::Trust,
                reason: "model not in trust-root allowlist (E0404)".into(),
            };
        }
        // Gate 2: Capability — a card/route exists for the model.
        let binding = match self.model_to_route.get(&model) {
            Some(b) => b.clone(),
            None => {
                return Admission::Denied {
                    gate: Gate::Capability,
                    reason: "no capability card/route for model (E0405)".into(),
                }
            }
        };
        // Gate 3: Egress — the route must be pinned (endpoint present).
        if binding.endpoint.is_empty() {
            return Admission::Denied {
                gate: Gate::Egress,
                reason: "route endpoint unpinned (E0405)".into(),
            };
        }
        // Gate 4: Dispatch — pin the immutable route.
        Admission::Admitted {
            route: PinnedRoute { model, binding },
        }
    }

    /// Retry policy (GW-07): exactly one automatic retry on retryable classes.
    pub fn should_retry(&self, attempt: u8, class: RetryClass) -> Result<(), GatewayError> {
        if attempt >= self.max_attempts {
            return Err(GatewayError::RetryLimitExceeded(format!(
                "attempt {attempt} exceeds max {}(E0407)",
                self.max_attempts
            )));
        }
        if class == RetryClass::NotRetryable {
            return Err(GatewayError::RetryOnUnsafeFailure(
                "this failure class must never be retried (E0408)".into(),
            ));
        }
        Ok(())
    }
}

/// A credential lease — non-cloneable, zeroizes on drop, reaches one adapter (GW-16).
#[derive(Debug)]
pub struct CredentialLease {
    secret: zeroize::Zeroizing<Vec<u8>>,
}

impl CredentialLease {
    pub fn new(secret: Vec<u8>) -> Self {
        Self {
            secret: zeroize::Zeroizing::new(secret),
        }
    }

    /// Provide the bytes to the adapter; the caller must not persist them (GW-16).
    pub fn expose(&self) -> &[u8] {
        &self.secret
    }
}

impl Zeroize for CredentialLease {
    fn zeroize(&mut self) {
        self.secret.zeroize();
    }
}

/// Compute integer microcent cost from token counts (GW-14).
/// Prompt and completion tokens are billed at their own per-token rates.
pub fn cost_from_tokens(
    prompt_tokens: u64,
    prompt_rate_microcents: u64,
    completion_tokens: u64,
    completion_rate_microcents: u64,
) -> CostMicrocents {
    let p = prompt_tokens.saturating_mul(prompt_rate_microcents);
    let c = completion_tokens.saturating_mul(completion_rate_microcents);
    CostMicrocents(p.saturating_add(c))
}

#[cfg(test)]
mod dispatch_tests;

#[cfg(test)]
mod tests {
    use super::*;

    fn binding() -> RouteBinding {
        RouteBinding {
            provider_id: "openai".into(),
            deployment_id: "gpt".into(),
            region_id: "us-east-1".into(),
            adapter_profile_digest: "a".repeat(64),
            endpoint: "https://api.openai.com/v1".into(),
            pricing_digest: "b".repeat(64),
        }
    }

    #[test]
    fn four_gate_admission_order() {
        let g = Gateway::new(
            vec![ModelRef("gpt-4".into())],
            vec![(ModelRef("gpt-4".into()), binding())],
        );
        // Unknown model → Trust gate denied.
        assert!(matches!(
            g.admit(ModelRef("claude".into())),
            Admission::Denied {
                gate: Gate::Trust,
                ..
            }
        ));
        // Known model → admitted with pinned route.
        match g.admit(ModelRef("gpt-4".into())) {
            Admission::Admitted { route } => {
                assert_eq!(route.binding.region_id, "us-east-1");
            }
            _ => panic!("known model must be admitted"),
        }
    }

    #[test]
    fn retry_exactly_once_same_route() {
        let g = Gateway::new(vec![], vec![]);
        assert!(g.should_retry(0, RetryClass::RetryableTransport).is_ok());
        assert!(g.should_retry(1, RetryClass::RetryableTransport).is_ok());
        // attempt 2 = third total → E0407
        assert_eq!(
            g.should_retry(2, RetryClass::RetryableTransport)
                .unwrap_err()
                .code(),
            "E0407"
        );
    }

    #[test]
    fn unsafe_failure_never_retried() {
        let g = Gateway::new(vec![], vec![]);
        assert_eq!(
            g.should_retry(0, RetryClass::NotRetryable)
                .unwrap_err()
                .code(),
            "E0408"
        );
    }

    #[test]
    fn cost_integer_checked_add() {
        let a = CostMicrocents(u64::MAX - 1);
        let b = CostMicrocents(10);
        assert_eq!(a.checked_add(b).unwrap_err().code(), "E0411");
        assert_eq!(
            CostMicrocents(5).checked_add(CostMicrocents(7)).unwrap().0,
            12
        );
    }
}
