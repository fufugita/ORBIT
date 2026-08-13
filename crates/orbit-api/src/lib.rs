//! ORBIT API surface — Phase D (D15).
//!
//! Request/response shapes for the six primitives (DR-12 §4.5) + the authority
//! pipeline. The HTTP server binding (axum/actix) is a later milestone; this
//! crate defines the typed envelopes + handler dispatch that the server will
//! serve, so conformance tests can target them directly.

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};

/// API error family.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum ApiError {
    #[error("bad request: {0}")]
    BadRequest(String),
    #[error("not found: {0}")]
    NotFound(String),
    #[error("unauthorized: {0}")]
    Unauthorized(String),
}

/// Every API response is wrapped in a stable envelope (orbit.cli/v1 style).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiEnvelope<T> {
    pub v: String,      // "orbit.api/v1"
    pub status: String, // "ok" | "error"
    pub data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
}

impl<T> ApiEnvelope<T> {
    pub fn ok(data: T) -> Self {
        Self {
            v: "orbit.api/v1".into(),
            status: "ok".into(),
            data: Some(data),
            errors: None,
        }
    }

    pub fn err(code: &str, message: &str) -> Self {
        Self {
            v: "orbit.api/v1".into(),
            status: "error".into(),
            data: None,
            errors: Some(vec![format!("{code}: {message}")]),
        }
    }
}

/// PEB submit request (DR-12 §4.5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PebSubmitRequest {
    pub session_id: String,
    pub prompt: String,
    pub model: String, // flat ModelRef
}

/// PEB submit response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PebSubmitResponse {
    pub submission_id: String,
    pub intent_digest: String,
    pub awaiting_confirmation: bool,
}

/// TTE run request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TteRunRequest {
    pub task_id: String,
    pub session_id: String,
    pub tool: String,
    pub model: String,
    pub uai_scope_digest: String,
}

/// TTE run response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TteRunResponse {
    pub task_id: String,
    pub state: String, // "authorized" | "running" | ...
}

/// ML write request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MlWriteRequest {
    pub key: String,
    pub value: String,
    pub scope: String, // "global" | "project" | "path_local"
    pub uai_digest: String,
}

/// ML write response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MlWriteResponse {
    pub memory_id: String,
    pub digest: String,
}

/// RTA assess request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RtaAssessRequest {
    pub target: String,
    pub trust_level: String, // "standard" | "local"
    pub max_age_ms: u64,
}

/// EPB build request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpbBuildRequest {
    pub artifact_digests: Vec<String>,
    pub kinds: Vec<String>,
}

/// SDE open request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SdeOpenRequest {
    pub session_id: String,
    pub uai_root_digest: String,
    pub ttl_ms: u64,
}

/// The dispatch router: maps a route to a primitive handler signature.
/// Handlers are pure functions over the request shapes; the server layer calls
/// them. This keeps conformance tests server-free.
pub mod routes {
    /// The route table (DR-12 §4.5 endpoints).
    pub const ROUTES: &[(&str, &str)] = &[
        ("POST", "/v0.1/peb/submissions"),
        ("GET", "/v0.1/peb/submissions/{id}"),
        ("POST", "/v0.1/tte/tasks"),
        ("POST", "/v0.1/ml/records"),
        ("POST", "/v0.1/rta/assess"),
        ("POST", "/v0.1/epb/bundles"),
        ("POST", "/v0.1/sde/envelopes"),
    ];

    /// Validate that a route is in the v0.1 table.
    pub fn is_known(method: &str, path: &str) -> bool {
        ROUTES.iter().any(|(m, p)| *m == method && *p == path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelope_ok_and_err() {
        let ok = ApiEnvelope::ok(42u32);
        assert_eq!(ok.status, "ok");
        let err = ApiEnvelope::<u32>::err("E1203", "denied");
        assert_eq!(err.status, "error");
        assert!(err.errors.unwrap()[0].starts_with("E1203"));
    }

    #[test]
    fn routes_match_dr12() {
        assert!(routes::is_known("POST", "/v0.1/peb/submissions"));
        assert!(routes::is_known("POST", "/v0.1/sde/envelopes"));
        assert!(!routes::is_known("GET", "/v0.1/admin"));
    }
}
