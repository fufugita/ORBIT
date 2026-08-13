//! Trust root store: baked-in root + local `trust add-root` (DR-05 M1/M2, Foundation §1).
//!
//! - v0.1 ships with one baked-in root public key.
//! - Operators add roots locally via `orbit trust add-root <pubkey>`.
//! - Startup verifies the manifest signature against `{embedded} ∪ {added}`;
//!   failure → exit 2, E0706 (M1).
//! - Added roots are persisted under the restricted ACL (0700/0600).

use crate::error::TrustError;
use crate::manifest::{RootPublicKey, TrustRootManifest};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// Path of the added-roots allowlist within the trust state dir.
pub const ADDED_ROOTS_FILE: &str = "added-roots.json";

/// The set of root keys usable for manifest verification.
#[derive(Debug, Clone, Default)]
pub struct TrustRootStore {
    embedded: BTreeSet<RootPublicKey>,
    added: BTreeSet<RootPublicKey>,
}

impl TrustRootStore {
    /// Create a store with the baked-in root(s) from the release binary.
    pub fn new(embedded: impl IntoIterator<Item = RootPublicKey>) -> Self {
        Self {
            embedded: embedded.into_iter().collect(),
            added: BTreeSet::new(),
        }
    }

    /// All verification roots: embedded ∪ added.
    pub fn all_roots(&self) -> impl Iterator<Item = &RootPublicKey> {
        self.embedded.iter().chain(self.added.iter())
    }

    /// `orbit trust add-root <pubkey>` — persist a new root to the allowlist file.
    /// Written atomically (tmp + rename) under the restricted ACL (A4).
    pub fn add_root(&mut self, key: RootPublicKey, state_dir: &Path) -> Result<(), TrustError> {
        if self.added.contains(&key) || self.embedded.contains(&key) {
            return Ok(()); // idempotent
        }
        self.added.insert(key.clone());
        self.persist_added(state_dir)
    }

    /// Verify the manifest against all roots; E0706 if none match (M1).
    pub fn verify_manifest(&self, manifest: &TrustRootManifest) -> Result<(), TrustError> {
        let roots: Vec<RootPublicKey> = self.all_roots().cloned().collect();
        if roots.is_empty() {
            return Err(TrustError::RootInvalid(
                "no roots configured (embedded set empty)".into(),
            ));
        }
        manifest.verify(&roots)
    }

    /// Load added roots from `state_dir/added-roots.json` (if present).
    pub fn load_added(state_dir: &Path) -> Result<Self, TrustError> {
        let path = added_roots_path(state_dir);
        let mut store = Self::new(Vec::<RootPublicKey>::new());
        if path.exists() {
            let bytes = std::fs::read(&path).map_err(|e| {
                TrustError::RegistryBootstrapIncomplete(format!("cannot read {path:?}: {e}"))
            })?;
            let added: Vec<RootPublicKey> = serde_json::from_slice(&bytes)
                .map_err(|e| TrustError::ManifestSchemaInvalid(format!("added-roots.json: {e}")))?;
            store.added = added.into_iter().collect();
        }
        Ok(store)
    }

    fn persist_added(&self, state_dir: &Path) -> Result<(), TrustError> {
        std::fs::create_dir_all(state_dir).map_err(|e| {
            TrustError::RegistryBootstrapIncomplete(format!("mkdir {state_dir:?}: {e}"))
        })?;
        let tmp = state_dir.join(format!("{ADDED_ROOTS_FILE}.tmp"));
        let final_path = added_roots_path(state_dir);
        let bytes = serde_json::to_vec(&self.added.iter().cloned().collect::<Vec<_>>())
            .map_err(|e| TrustError::ManifestSchemaInvalid(e.to_string()))?;
        std::fs::write(&tmp, &bytes)
            .map_err(|e| TrustError::RegistryBootstrapIncomplete(format!("write: {e}")))?;
        std::fs::rename(&tmp, &final_path)
            .map_err(|e| TrustError::RegistryBootstrapIncomplete(format!("rename: {e}")))?;
        Ok(())
    }
}

/// Full path to the added-roots file.
pub fn added_roots_path(state_dir: &Path) -> PathBuf {
    state_dir.join(ADDED_ROOTS_FILE)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_root_persists_and_reloads() {
        let dir =
            std::env::temp_dir().join(format!("orbit-trust-root-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let key = RootPublicKey(hex::encode([7u8; 32]));
        let mut store = TrustRootStore::new(Vec::<RootPublicKey>::new());
        store.add_root(key.clone(), &dir).unwrap();

        let reloaded = TrustRootStore::load_added(&dir).unwrap();
        assert!(reloaded.all_roots().any(|r| *r == key));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn verify_manifest_no_roots_fails_e0706() {
        let store = TrustRootStore::new(Vec::<RootPublicKey>::new());
        let manifest = TrustRootManifest {
            body: crate::manifest::TrustRootManifestBody {
                schema: crate::manifest::MANIFEST_SCHEMA.into(),
                version: "0.1.0".into(),
                issuer_allowlist: vec![],
                routes: vec![],
                lifecycle: vec![],
                model_allowlist: BTreeSet::new(),
            },
            signature: String::new(),
        };
        assert_eq!(
            store.verify_manifest(&manifest).unwrap_err().code(),
            "E0706"
        );
    }
}
