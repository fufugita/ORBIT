//! SecretBytes — prompt/output/credential bytes (DR-09 §3, GW-25).
//!
//! - No `Display`, no `Debug` (a `Debug` impl would leak the bytes into logs).
//! - `zeroize::Zeroizing` inner storage → zeroized on drop.
//! - `consume()` is the only way to read the bytes; the caller must not
//!   persist them (GW-16).
//! - Prompt/output bytes NEVER enter Ledger events (GW-25) — the adapter and
//!   gateway both enforce this at the type boundary.

use zeroize::Zeroizing;

/// Immutable secret byte container. Not cloneable (a clone could be
/// persisted in a second sink). `consume()` yields the bytes; the caller
/// owns them for the duration of the call only.
pub struct SecretBytes {
    bytes: Zeroizing<Vec<u8>>,
}

impl SecretBytes {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self {
            bytes: Zeroizing::new(bytes),
        }
    }

    /// The only read accessor — returns a borrow valid for the call scope.
    /// The caller must not persist it beyond the adapter invocation.
    pub fn expose(&self) -> &[u8] {
        &self.bytes
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

impl std::fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecretBytes[{} bytes]", self.bytes.len())
    }
}

/// A credential lease — single-use, non-cloneable (GW-16).
#[derive(Debug)]
pub struct CredentialLease {
    inner: SecretBytes,
    pub source_ref: crate::types::CredentialRef,
    pub version: u64,
}

impl CredentialLease {
    pub fn new(inner: SecretBytes, source_ref: crate::types::CredentialRef, version: u64) -> Self {
        Self {
            inner,
            source_ref,
            version,
        }
    }

    pub fn expose(&self) -> &[u8] {
        self.inner.expose()
    }

    /// Consume the lease into its bytes (for a single adapter).
    pub fn consume(self) -> SecretBytes {
        self.inner
    }
}
