//! ORBIT core — Phase D (D13-D15).
//!
//! The authority kernel + six primitives, the heart of the "harness that orbits
//! around you" reframe:
//! - `authority` — UserAuthorityIntent, provenance, deterministic extractor,
//!   ProgrammaticUserPolicy, E19xx errors (DR-14).
//! - `peb`/`tte`/`ml`/`rta`/`epb`/`sde` — six primitives consuming UAI (DR-12 + DR-14).
//!
//! The proof/privacy kernel (IF-1..IF-12, KERN-1..KERN-5) is non-overridable:
//! no credentials/keys/hashes/internal IDs to providers (KERN-4), no prompt
//! bytes in Ledger (UAI-I6), no untrusted content as authority (KERN-3).

#![forbid(unsafe_code)]

pub mod authority;
pub mod epb;
pub mod ml;
pub mod peb;
pub mod rta;
pub mod sde;
pub mod tte;

pub use authority::{
    AuthorityError, AuthorityProvenance, AuthorityScope, ConfirmationChannel,
    ProgrammaticUserPolicy, UserAuthorityIntent, VerifiedPolicy,
};
pub use epb::{EpbError, EpbService, EvidenceArtifact, EvidenceBundle};
pub use ml::{DataClass, MemoryRecord, MlError, MlService};
pub use peb::{PebError, PebService, PebState, PebSubmission};
pub use rta::{RtaError, RtaService, TrustAssessment, TrustLevel};
pub use sde::{AuthorizationSource, SdeError, SdeService, SessionDecisionEnvelope};
pub use tte::{TaskSpec, TaskState, TteError, TteService};
