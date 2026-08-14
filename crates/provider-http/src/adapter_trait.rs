//! The async provider-neutral adapter contract (DR-09 §3).
//!
//! v0.2 promotes the DR-09 async form: `async fn invoke` returning a
//! `Pin<Box<dyn Stream>>`. The v0.1 sync `ProviderAdapter` (orbit-adapter)
//! stays for hermetic conformance; the async adapters implement this trait and
//! must pass the SAME invariant set (GW-04..GW-25).

use crate::cancel::CancelToken;
use crate::stream::AsyncProviderEventStream;
use orbit_adapter::credential::SecretBytes;
use orbit_adapter::error::AdapterError;
use orbit_adapter::types::{
    AdapterIdentity, ProviderCapabilities, ProviderRequest, ProviderRouteBinding,
};

/// The async adapter abstraction every shipped HTTP adapter must implement.
#[async_trait::async_trait]
pub trait AsyncProviderAdapter: Send + Sync + 'static {
    /// Identity: kind + implementation/profile digests (GW-05).
    fn identity(&self) -> AdapterIdentity;

    /// Declared capabilities (DR-09 §2). Adapters refuse out-of-capability
    /// requests with E0414.
    fn capabilities(&self) -> &ProviderCapabilities;

    /// Offline route validation. No I/O, no provider contact (DR-09 §3).
    /// E0422 on profile-digest mismatch, E0414 on capability mismatch.
    fn validate_route(&self, route: &ProviderRouteBinding) -> Result<(), AdapterError>;

    /// Invoke the provider asynchronously. Returns an event stream.
    /// The credential, when present, is a single-use borrow for this call —
    /// never persisted, never cloned (GW-16).
    async fn invoke(
        &self,
        request: &ProviderRequest,
        credential: Option<&SecretBytes>,
        cancel: &CancelToken,
    ) -> Result<AsyncProviderEventStream, AdapterError>;
}
