//! Async provider error family — reuses the v0.1 `AdapterError` (E04xx) for
//! contract violations and adds transport/TLS/stream failure surfaces.

use orbit_adapter::error::AdapterError;

/// Errors from the async HTTP transport layer (before/around the adapter
/// contract). Mapped to `AdapterError` codes for the public envelope.
#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    #[error("ORBIT-E0410 provider_transport_failure: {0}")]
    Transport(String),
    #[error("ORBIT-E0409 provider_timeout: {0}")]
    Timeout(String),
    #[error("ORBIT-E0310 egress_tls_mismatch: {0}")]
    TlsMismatch(String),
    #[error("ORBIT-E0407 rate_limited_exhausted: {0}")]
    RateLimited(String),
    #[error("ORBIT-E0408 capacity_unavailable_exhausted: {0}")]
    Capacity(String),
    #[error("ORBIT-E0411 provider_protocol_or_stream_violation: {0}")]
    Protocol(String),
}

impl TransportError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Transport(_) => "E0410",
            Self::Timeout(_) => "E0409",
            Self::TlsMismatch(_) => "E0310",
            Self::RateLimited(_) => "E0407",
            Self::Capacity(_) => "E0408",
            Self::Protocol(_) => "E0411",
        }
    }
}

impl From<TransportError> for AdapterError {
    fn from(e: TransportError) -> Self {
        match e {
            TransportError::Transport(m) => AdapterError::ProviderTransportFailure(m),
            TransportError::Timeout(m) => AdapterError::ProviderTimeout(m),
            TransportError::TlsMismatch(m) => AdapterError::ProviderTransportFailure(m),
            TransportError::RateLimited(m) => AdapterError::RateLimitedExhausted(m),
            TransportError::Capacity(m) => AdapterError::CapacityUnavailableExhausted(m),
            TransportError::Protocol(m) => AdapterError::ProtocolOrStreamViolation(m),
        }
    }
}
