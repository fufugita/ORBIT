//! ORBIT sandbox subsystem — Phase B (B5).
//!
//! Deny-by-default layered cage per DR-07: Landlock ABI v4 filesystem boundary,
//! seccomp syscall/address-family filter (never destinations — S4), WASI 0.2
//! host-import allowlist, and egress broker binding. Three locked profiles,
//! no default (S1). Every kernel-feature probe fails closed (S5).
//!
//! Safety: Linux syscall probes in `linux.rs` are reviewed, scoped `unsafe`
//! blocks with SAFETY comments; the crate itself is safe except those.

#![deny(unsafe_code)]

pub mod error;
pub mod linux;
pub mod profile;

pub use error::SandboxError;
pub use linux::{probe_kernel, validate_applicable, KernelFeatures};
pub use profile::{
    apply_override, builtin_profiles, resolve_profile, SandboxDomain, SandboxProfile,
    SandboxProfileId,
};
