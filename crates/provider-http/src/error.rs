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


/// Classify an HTTP status into the adapter error that carries it,
/// reading the body for the provider's own message (E1: bodies were
/// thrown away, so every 4xx looked like auth) and mapping the
/// retryable server statuses to their retry classes (E2: 500/502/503/
/// 504/529 must be retried).
///
/// Callers must have already drained the body for this call.
pub async fn status_error(
    status: reqwest::StatusCode,
    body: String,
) -> AdapterError {
    use orbit_adapter::error::AdapterError as E;
    let brief = if body.is_empty() {
        format!("status {status}")
    } else {
        // Pull the provider's message out of the common JSON shapes;
        // fall back to a trimmed body.
        let msg = serde_json::from_str::<serde_json::Value>(&body)
            .ok()
            .and_then(|v| {
                v.pointer("/error/message")
                    .or_else(|| v.pointer("/error"))
                    .or_else(|| v.pointer("/message"))
                    .and_then(|m| m.as_str().map(str::to_string))
            })
            .unwrap_or_else(|| {
                body.chars().take(200).collect::<String>()
            });
        format!("status {status}: {msg}")
    };
    match status.as_u16() {
        429 => E::RateLimitedExhausted(brief),
        500 | 502 | 503 | 504 | 529 => E::CapacityUnavailableExhausted(brief),
        401 | 403 => E::CredentialRejected(brief),
        404 => E::ModelOrDeploymentNotFound(brief),
        // A 400 is the provider rejecting the REQUEST — often "prompt
        // is too long" (the compaction path, B6/E1) — not a permission
        // problem, and its message must reach the operator.
        400 | 413 => E::RequestInvalidOrTooLarge(brief),
        _ => E::ProviderPermissionDenied(brief),
    }
}
