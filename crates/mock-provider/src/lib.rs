//! ORBIT mock provider server library surface (v0.2 conformance target).
//!
//! Exposes the scriptable mock behaviors so the async conformance harness can
//! spawn a server in-process (or point at a remote homelab instance) and drive
//! the real adapters against it.

#![forbid(unsafe_code)]

pub mod server;

pub use server::{router, spawn, ServerConfig, ServerState};

/// Scriptable behavior for a mock endpoint.
#[derive(Debug, Clone, Default)]
pub enum MockBehavior {
    /// A clean SSE success stream ending in `[DONE]`.
    #[default]
    Success,
    /// A partial stream that stops without `[DONE]`.
    Partial,
    /// HTTP 429 with a Retry-After header.
    RateLimited { retry_after_secs: u32 },
    /// HTTP 500 (pre-delivery transport failure).
    ServerError,
    /// Malformed SSE (garbage bytes).
    MalformedSse,
    /// Delayed first byte (for timeout tests).
    SlowFirstByte { delay_ms: u64 },
    /// A stream with tool-call deltas.
    ToolCalls,
}
