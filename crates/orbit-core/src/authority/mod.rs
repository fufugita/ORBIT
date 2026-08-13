//! ORBIT authority kernel — Phase D (D13).
//!
//! The heart of the "harness that orbits around you" reframe (DR-14):
//! - The user is the locus of authority.
//! - Natural-language or typed-flag directives → typed, confirmed, signed
//!   `UserAuthorityGrant`s.
//! - Only `UserTypedTurn` / prior-turn-revoke / verified `ProgrammaticUserPolicy`
//!   can produce a `UserAuthorityIntent` (UAI-I4); everything else is
//!   `NonAuthoritative` and structurally cannot.
//! - The proof/privacy kernel (IF-1..IF-12, KERN-1..KERN-5) is non-overridable:
//!   no credentials/keys/hashes/internal IDs to providers (KERN-4, E1910).

#![forbid(unsafe_code)]

pub mod canonical;
pub mod error;
pub mod intent;
pub mod policy;

pub use error::AuthorityError;
pub use intent::{
    AuthorityConfirmation, AuthorityDimension, AuthorityProvenance, AuthorityScope,
    ConfirmationChannel, UserAuthorityIntent,
};
pub use policy::{ProgrammaticUserPolicy, VerifiedPolicy};
