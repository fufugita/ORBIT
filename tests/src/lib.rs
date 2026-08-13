//! ORBIT integration tests — DR-03 §5b named-test closeout.
//!
//! Implements the high-value traceability seeds (security / concurrency /
//! fault / migration / e2e classes) under their EXACT seeded names against the
//! real crates. `cargo test -p orbit-tests` runs the full inventory.

pub mod adapter;
pub mod authority;
pub mod compat;
pub mod concurrency;
pub mod core;
pub mod fault;
pub mod fuzz;
pub mod golden;
pub mod migration;
pub mod model_check;
pub mod primitives;
pub mod property;
pub mod release_seeds;
pub mod sdk;
pub mod security;
pub mod soak;
pub mod surface;
