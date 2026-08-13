//! The provider-neutral adapter contract (DR-09 §3).
//!
//! v0.1 synchronous form of the DR-09 `ProviderAdapter` trait. The async
//! streaming surface (`Pin<Box<dyn Stream<...>>>`) is deferred to v0.2; this
//! form preserves every invariant that matters:
//!
//! - `validate_route` is OFFLINE — no DNS, socket, health probe, credential
//!   service, or provider contact (DR-09 §3).
//! - `invoke` returns the FULL terminal evidence — sequence-validated
//!   events, two-hash output evidence, integer cost, monotonic usage, drift
//!   observations. Exactly one terminalizer wins (GW-10).
//! - Adapters perform NO hidden retry (GW-07); they classify the failure and
//!   the gateway decides.
//! - Credential bytes reach exactly one adapter and are never persisted
//!   (GW-16) — the adapter receives a `&SecretBytes` for the call scope only.

use crate::credential::SecretBytes;
use crate::error::AdapterError;
use crate::types::{
    AdapterIdentity, ProviderCapabilities, ProviderRequest, ProviderResult, ProviderRouteBinding,
};

/// The adapter abstraction every shipped adapter must implement.
pub trait ProviderAdapter: Send + Sync + 'static {
    /// Identity: kind + implementation/profile digests (GW-05).
    fn identity(&self) -> AdapterIdentity;

    /// Declared capabilities (DR-09 §2). Adapters refuse out-of-capability
    /// requests with E0414.
    fn capabilities(&self) -> &ProviderCapabilities;

    /// Offline route validation. No I/O, no provider contact (DR-09 §3).
    /// E0422 on profile-digest mismatch, E0414 on capability mismatch,
    /// E0405 on unknown model/deployment.
    fn validate_route(&self, route: &ProviderRouteBinding) -> Result<(), AdapterError>;

    /// Invoke the provider. The credential, when present, is a single-use
    /// borrow for this call — never persisted, never cloned (GW-16).
    fn invoke(
        &self,
        request: &ProviderRequest,
        credential: Option<&SecretBytes>,
    ) -> Result<ProviderResult, AdapterError>;
}
