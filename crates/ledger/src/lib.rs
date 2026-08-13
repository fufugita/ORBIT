//! ORBIT Ledger subsystem — Phase A (A5-A8).
//!
//! Append-only, hash-chained, single-writer Ledger per DR-06. Implements the
//! on-disk format, canonical serialization, single-writer flock + fsync-before-ACK,
//! segment rotation, recovery/verify, and the event taxonomy including
//! EgressIntent and DR-14 AuthorityGrant/Revoke.
//!
//! Safety: one reviewed `unsafe` (flock syscall in writer.rs); everything else safe.

#![deny(unsafe_code)]

pub mod canonical;
pub mod error;
pub mod event;
pub mod reader;
pub mod writer;

pub use error::LedgerError;
pub use event::{
    AuthorityGrant, AuthorityRevoke, EgressDestination, EgressIntent, GrantSignature, LedgerEvent,
    LedgerRecord, Phase, SessionId, TerminalOutcome,
};
pub use reader::{validate_record, verify_ledger};
pub use writer::{LedgerWriter, ReadRecord};
