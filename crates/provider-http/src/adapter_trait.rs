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
use sha2::{Digest, Sha256};

/// Invoke failures retain their original public error independently of the
/// transport observation. Neither arm asserts generation finality or billing.
pub struct DetailedInvokeFailure {
    error: AdapterError,
    observation: FailureObservation,
}

impl DetailedInvokeFailure {
    pub fn unknown(error: AdapterError) -> Self {
        Self {
            error,
            observation: FailureObservation::Unknown,
        }
    }

    pub fn error(&self) -> &AdapterError {
        &self.error
    }
    pub fn observation(&self) -> &FailureObservation {
        &self.observation
    }
    pub fn into_error(self) -> AdapterError {
        self.error
    }

    pub(crate) fn with_rejection(
        error: AdapterError,
        observation: HttpRejectionObservation,
    ) -> Self {
        Self {
            error,
            observation: FailureObservation::CompleteHttpRejection(observation),
        }
    }
}

impl std::fmt::Debug for DetailedInvokeFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DetailedInvokeFailure")
            .field("code", &self.error.code())
            .field("observation", &self.observation)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FailureObservation {
    Unknown,
    CompleteHttpRejection(HttpRejectionObservation),
}

/// Pure request identity available before dispatch. It contains only bounded
/// identifiers and digests, and makes no assertion about delivery or billing.
#[derive(Clone, PartialEq, Eq)]
pub struct RequestFingerprint {
    request_id: String,
    decision_id: String,
    attempt_id: String,
    route_digest: String,
    body_digest: String,
    adapter_identity: AdapterIdentity,
    digest: String,
}

impl RequestFingerprint {
    pub fn for_request(
        request: &ProviderRequest,
        identity: &AdapterIdentity,
    ) -> Result<Self, AdapterError> {
        let url = crate::openai::chat_completions_url(&request.route)?;
        let body = crate::request::render_request_body(
            crate::request::HttpDialect::OpenAiCompatible,
            crate::request::RequestBodyInput::from(request),
        )?;
        let bytes = serde_json::to_vec(body.as_json()).map_err(|_| invalid_fingerprint())?;
        Self::from_rendered(request, identity, &url, &bytes).ok_or_else(invalid_fingerprint)
    }

    pub fn request_id(&self) -> &str {
        &self.request_id
    }
    pub fn decision_id(&self) -> &str {
        &self.decision_id
    }
    pub fn attempt_id(&self) -> &str {
        &self.attempt_id
    }
    pub fn route_digest(&self) -> &str {
        &self.route_digest
    }
    pub fn body_digest(&self) -> &str {
        &self.body_digest
    }
    pub fn adapter_identity(&self) -> &AdapterIdentity {
        &self.adapter_identity
    }
    pub fn digest(&self) -> &str {
        &self.digest
    }

    fn from_rendered(
        request: &ProviderRequest,
        identity: &AdapterIdentity,
        actual_url: &str,
        actual_body: &[u8],
    ) -> Option<Self> {
        if !valid_request_identity(request, identity)
            || crate::openai::chat_completions_url(&request.route)
                .ok()?
                .as_str()
                != actual_url
        {
            return None;
        }
        let route_digest = route_digest(&request.route, actual_url)?;
        let body_digest = domain_digest(b"orbit-http-rejection-body-v1\0", actual_body);
        let encoded = serde_json::to_vec(&(
            &request.request_id.0,
            &request.decision_id.0,
            &request.attempt_id.0,
            &route_digest,
            &body_digest,
            identity,
        ))
        .ok()?;
        let digest = domain_digest(b"orbit-http-request-fingerprint-v1\0", &encoded);
        if [&route_digest, &body_digest, &digest]
            .iter()
            .any(|digest| !valid_digest(digest))
        {
            return None;
        }
        Some(Self {
            request_id: request.request_id.0.clone(),
            decision_id: request.decision_id.0.clone(),
            attempt_id: request.attempt_id.0.clone(),
            route_digest,
            body_digest,
            adapter_identity: identity.clone(),
            digest,
        })
    }
}

impl std::fmt::Debug for RequestFingerprint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RequestFingerprint")
            .field("digest", &self.digest)
            .finish()
    }
}

/// Complete bounded HTTP rejection, bound to the exact sent request. Only the
/// concrete transport can construct it; consumers can verify, never mint it.
#[derive(Clone, PartialEq, Eq)]
pub struct HttpRejectionObservation {
    status: u16,
    fingerprint: Box<RequestFingerprint>,
    response_body_bytes: u32,
    observation_digest: String,
}

impl HttpRejectionObservation {
    pub fn status(&self) -> u16 {
        self.status
    }
    pub fn request_id(&self) -> &str {
        self.fingerprint.request_id()
    }
    pub fn decision_id(&self) -> &str {
        self.fingerprint.decision_id()
    }
    pub fn attempt_id(&self) -> &str {
        self.fingerprint.attempt_id()
    }
    pub fn route_digest(&self) -> &str {
        self.fingerprint.route_digest()
    }
    pub fn body_digest(&self) -> &str {
        self.fingerprint.body_digest()
    }
    pub fn adapter_identity(&self) -> &AdapterIdentity {
        self.fingerprint.adapter_identity()
    }
    pub fn response_body_bytes(&self) -> u32 {
        self.response_body_bytes
    }
    pub fn observation_digest(&self) -> &str {
        &self.observation_digest
    }

    pub fn matches_request(&self, request: &ProviderRequest, identity: &AdapterIdentity) -> bool {
        RequestFingerprint::for_request(request, identity)
            .is_ok_and(|fingerprint| self.fingerprint.as_ref() == &fingerprint)
    }

    pub(crate) fn new(
        request: &ProviderRequest,
        identity: &AdapterIdentity,
        actual_url: &str,
        actual_body: &[u8],
        status: u16,
        response_body_bytes: usize,
    ) -> Option<Self> {
        if !(400..600).contains(&status) || response_body_bytes > 65_536 {
            return None;
        }
        let fingerprint =
            RequestFingerprint::from_rendered(request, identity, actual_url, actual_body)?;
        let response_body_bytes = u32::try_from(response_body_bytes).ok()?;
        // The domain is NUL-terminated. Tuple serialization is deterministic
        // serde JSON with the complete route/identity structs in declared order.
        let encoded = serde_json::to_vec(&(
            fingerprint.request_id(),
            fingerprint.decision_id(),
            fingerprint.attempt_id(),
            fingerprint.route_digest(),
            fingerprint.body_digest(),
            identity,
            status,
            response_body_bytes,
        ))
        .ok()?;
        let observation_digest = domain_digest(b"orbit-http-rejection-observation-v1\0", &encoded);
        if !valid_digest(&observation_digest) {
            return None;
        }
        Some(Self {
            status,
            fingerprint: Box::new(fingerprint),
            response_body_bytes,
            observation_digest,
        })
    }
}

impl std::fmt::Debug for HttpRejectionObservation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpRejectionObservation")
            .field("status", &self.status)
            .field("response_body_bytes", &self.response_body_bytes)
            .field("observation_digest", &self.observation_digest)
            .finish()
    }
}

fn valid_request_identity(request: &ProviderRequest, identity: &AdapterIdentity) -> bool {
    [
        &request.request_id.0,
        &request.decision_id.0,
        &request.attempt_id.0,
    ]
    .iter()
    .all(|id| !id.is_empty() && id.len() <= 256 && id.bytes().all(|byte| byte.is_ascii_graphic()))
        && request.route.adapter_kind == identity.kind
        && matches!(
            identity.kind,
            orbit_adapter::types::AdapterKind::OpenAiCompatibleHttpV1
                | orbit_adapter::types::AdapterKind::MockHttpV1
        )
        && request.route.adapter_implementation_digest == identity.implementation_digest
        && request.route.adapter_profile_digest == identity.profile_digest
}

fn invalid_fingerprint() -> AdapterError {
    AdapterError::BindingDrift(
        "request identity does not match the selected adapter (E0413)".into(),
    )
}

fn valid_digest(digest: &str) -> bool {
    digest.len() == 64
        && digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn route_digest(route: &ProviderRouteBinding, url: &str) -> Option<String> {
    let encoded = serde_json::to_vec(&(route, url)).ok()?;
    Some(domain_digest(b"orbit-http-rejection-route-v1\0", &encoded))
}

fn domain_digest(domain: &[u8], bytes: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update(bytes);
    hex::encode(digest.finalize())
}

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

    /// Legacy-only adapters are called exactly once and produce no positive
    /// rejection observation. Their returned stream remains unchanged.
    async fn invoke_detailed(
        &self,
        request: &ProviderRequest,
        credential: Option<&SecretBytes>,
        cancel: &CancelToken,
    ) -> Result<AsyncProviderEventStream, DetailedInvokeFailure> {
        self.invoke(request, credential, cancel)
            .await
            .map_err(DetailedInvokeFailure::unknown)
    }
}
