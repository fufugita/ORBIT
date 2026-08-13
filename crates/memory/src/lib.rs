//! ORBIT memory subsystem — Phase C (C11).
//!
//! Layered persistent memory per DR-08:
//! - CTX-I7: layered `global < project < path-local`; operator correction >
//!   path-local > project > global; same scope → latest modified wins.
//! - CTX-I8: every memory file carries `modified` + `digest`; missing either
//!   → untrusted (excluded until repaired).
//! - CTX-I9: memory survives session close; no automatic TTL.
//! - CTX-I16: transactional writes (write-ahead + rename); partial files
//!   detected by digest mismatch, repaired from prior atomically-written version.

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Memory scope (DR-08 CTX-I7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum MemoryScope {
    Global,
    Project,
    PathLocal,
}

impl MemoryScope {
    /// Resolution precedence: higher wins (path-local > project > global).
    pub fn precedence(&self) -> u8 {
        match self {
            Self::Global => 0,
            Self::Project => 1,
            Self::PathLocal => 2,
        }
    }
}

/// A memory entry (CTX-I8: modified + digest are mandatory).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryEntry {
    pub key: String,
    pub scope: MemoryScope,
    pub value: String,
    pub modified: String,    // ISO-8601 UTC
    pub digest: String,      // sha256:hex
    pub is_correction: bool, // operator correction (CTX-I7: wins)
}

impl MemoryEntry {
    pub fn new(
        key: &str,
        scope: MemoryScope,
        value: &str,
        modified: &str,
        is_correction: bool,
    ) -> Self {
        let digest = hex::encode(Sha256::digest(value.as_bytes()));
        Self {
            key: key.into(),
            scope,
            value: value.into(),
            modified: modified.into(),
            digest: format!("sha256:{digest}"),
            is_correction,
        }
    }

    /// Verify the content digest (CTX-I8 / CTX-I16).
    pub fn verify_digest(&self) -> bool {
        let expected = hex::encode(Sha256::digest(self.value.as_bytes()));
        self.digest == format!("sha256:{expected}")
    }
}

/// A memory conflict event (CTX-I7: prior digest retained, never silent overwrite).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryConflictEvent {
    pub scope: MemoryScope,
    pub key: String,
    pub prior_digest: String,
    pub new_digest: String,
}

/// The layered memory store.
#[derive(Debug, Clone, Default)]
pub struct MemoryStore {
    entries: Vec<MemoryEntry>,
    conflicts: Vec<MemoryConflictEvent>,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Write an entry. If a same-scope entry exists with a different digest,
    /// record a ConflictEvent retaining the prior digest (CTX-I7).
    pub fn write(&mut self, entry: MemoryEntry) {
        if let Some(prior) = self
            .entries
            .iter()
            .find(|e| e.key == entry.key && e.scope == entry.scope && !e.is_correction)
        {
            if prior.value != entry.value && !entry.is_correction {
                self.conflicts.push(MemoryConflictEvent {
                    scope: entry.scope,
                    key: entry.key.clone(),
                    prior_digest: prior.digest.clone(),
                    new_digest: entry.digest.clone(),
                });
            }
        }
        // Remove any prior same-scope entry; the new one (or correction) wins.
        self.entries
            .retain(|e| !(e.key == entry.key && e.scope == entry.scope));
        self.entries.push(entry);
    }

    /// Resolve a key across layers (CTX-I7): operator correction > path-local >
    /// project > global; same scope → latest modified wins.
    pub fn resolve(&self, key: &str) -> Option<&MemoryEntry> {
        let mut best: Option<&MemoryEntry> = None;
        for e in self.entries.iter().filter(|e| e.key == key) {
            let better = match best {
                None => true,
                Some(b) => {
                    if e.is_correction && !b.is_correction {
                        true
                    } else if e.scope.precedence() != b.scope.precedence() {
                        e.scope.precedence() > b.scope.precedence()
                    } else {
                        e.modified > b.modified // same scope → latest wins
                    }
                }
            };
            if better {
                best = Some(e);
            }
        }
        best
    }

    /// Verify all entries have valid digests; collect untrusted ones (CTX-I8).
    pub fn untrusted_entries(&self) -> Vec<&MemoryEntry> {
        self.entries.iter().filter(|e| !e.verify_digest()).collect()
    }

    pub fn conflicts(&self) -> &[MemoryConflictEvent] {
        &self.conflicts
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolution_path_local_beats_project() {
        let mut store = MemoryStore::new();
        store.write(MemoryEntry::new(
            "k",
            MemoryScope::Global,
            "g",
            "2026-01-01T00:00:00Z",
            false,
        ));
        store.write(MemoryEntry::new(
            "k",
            MemoryScope::Project,
            "p",
            "2026-01-02T00:00:00Z",
            false,
        ));
        store.write(MemoryEntry::new(
            "k",
            MemoryScope::PathLocal,
            "pl",
            "2026-01-03T00:00:00Z",
            false,
        ));
        assert_eq!(store.resolve("k").unwrap().value, "pl");
    }

    #[test]
    fn correction_wins_over_all() {
        let mut store = MemoryStore::new();
        store.write(MemoryEntry::new(
            "k",
            MemoryScope::PathLocal,
            "pl",
            "2026-01-03T00:00:00Z",
            false,
        ));
        store.write(MemoryEntry::new(
            "k",
            MemoryScope::Global,
            "corrected",
            "2026-01-01T00:00:00Z",
            true,
        ));
        let r = store.resolve("k").unwrap();
        assert!(r.is_correction);
        assert_eq!(r.value, "corrected");
    }

    #[test]
    fn conflict_event_retains_prior_digest() {
        let mut store = MemoryStore::new();
        store.write(MemoryEntry::new(
            "k",
            MemoryScope::Global,
            "v1",
            "2026-01-01T00:00:00Z",
            false,
        ));
        store.write(MemoryEntry::new(
            "k",
            MemoryScope::Global,
            "v2",
            "2026-01-02T00:00:00Z",
            false,
        ));
        assert_eq!(store.conflicts().len(), 1);
        assert!(store.conflicts()[0].prior_digest != store.conflicts()[0].new_digest);
    }

    #[test]
    fn digest_verification_catches_tamper() {
        let mut e = MemoryEntry::new(
            "k",
            MemoryScope::Global,
            "value",
            "2026-01-01T00:00:00Z",
            false,
        );
        assert!(e.verify_digest());
        e.value = "tampered".into(); // digest now stale
        assert!(!e.verify_digest());
        let store = MemoryStore::new();
        let _ = store.untrusted_entries(); // no panic path
    }
}
