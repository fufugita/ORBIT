//! ORBIT provider-neutral adapter abstraction — Phase A of the DR-03 §5
//! row-4 closeout (provider adapters pass the same conformance suite).
//!
//! Implements the DR-09 §3 adapter contract in its synchronous v0.1 form:
//! the `ProviderAdapter` trait, the typed request/result/stream surfaces,
//! `SecretBytes` (zeroize-on-drop, no Display/Debug of the bytes), the
//! fixed-point sampling form, the redaction catalog, the two terminal
//! hashes, and the two concrete adapters (`DeterministicTestV1` +
//! `MockHttpV1`).
//!
//! The real async HTTP transport (provider APIs via tokio+reqwest) and the
//! async `ProviderEventStream` are deferred to v0.2 per the deferred
//! register — this crate proves every invariant that survives the sync form
//! without pulling an async runtime into the v0.1 kernel (DR-13 §5).

#![forbid(unsafe_code)]

pub mod adapters;
pub mod conformance;
pub mod credential;
pub mod error;
pub mod provider_adapter;
pub mod redaction;
pub mod stream;
pub mod types;

#[cfg(test)]
mod tests;

pub use adapters::{DeterministicTestV1, MockHttpV1, MockScript};
pub use credential::{CredentialLease, SecretBytes};
pub use error::{profile_mismatch, AdapterError, AdapterRetryClass};
pub use provider_adapter::ProviderAdapter;
pub use types::*;
