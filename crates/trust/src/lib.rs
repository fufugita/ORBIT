//! ORBIT trust subsystem — Phase A (A1-A4).
//!
//! Implements the trust-root manifest, namespace/issuer allowlist, policy
//! snapshot hashing, and restricted-session ACL per DR-05, DR-02 §1-2, DR-06 §1.2.
//! Errors are the canonical E07xx family registered in `spec/errors.yaml`.
//!
//! Safety: the single `unsafe` in this crate is `libc::geteuid()` (acl.rs),
//! a documented FFI call with no preconditions; every other path is safe.

#![deny(unsafe_code)]

pub mod acl;
pub mod canonical;
pub mod error;

pub mod manifest;
pub mod root;

pub use error::TrustError;
pub use manifest::{RootPublicKey, RouteSpec, TrustLevel, TrustRootManifest};
pub use root::{added_roots_path, TrustRootStore};
