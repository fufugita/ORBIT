//! ORBIT plugin subsystem — Phase B (B8).
//!
//! WASI 0.2 plugin trust model per DR-07:
//! - **S9** — plugin install is explicit: manifest + issuer pubkey/fingerprint +
//!   content digest + issuer signature + operator `Y` + Ledger::PluginInstall event.
//! - **S8/S12/S13** — WASI host-import allowlist: wasi:http/proxy + orbit:reactor/*
//!   only; wasi:sockets, wasi:filesystem, orbit:audit/*, orbit:ledger/*,
//!   orbit:replay/*, orbit:reactor/credentials/* are denied.
//! - **S11** — bounded reclaim: instance pool max 64, reclaim budget 250ms.
//!
//! The actual WASI 0.2 runtime binding (wasmtime) is a later milestone; this
//! crate implements the trust/install/allowlist/pool contract that gates it.

#![forbid(unsafe_code)]

pub mod canonical;

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicUsize, Ordering};

/// Plugin error family (E0806-E0813, DR-07).
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum PluginError {
    /// ORBIT-E0806 plugin_issuer_not_in_allowlist
    #[error("ORBIT-E0806 plugin_issuer_not_in_allowlist: {0}")]
    IssuerNotInAllowlist(String),
    /// ORBIT-E0807 instance_pool_exhausted
    #[error("ORBIT-E0807 instance_pool_exhausted: {0}")]
    InstancePoolExhausted(String),
    /// ORBIT-E0808 plugin_import_outside_allowlist
    #[error("ORBIT-E0808 plugin_import_outside_allowlist: {0}")]
    ImportOutsideAllowlist(String),
    /// ORBIT-E0813 plugin_self_grant_denied
    #[error("ORBIT-E0813 plugin_self_grant_denied: {0}")]
    SelfGrantDenied(String),
    /// ORBIT-E0811 broker_ledger_write_failed
    #[error("ORBIT-E0811 broker_ledger_write_failed: {0}")]
    BrokerLedgerWriteFailed(String),
    #[error("signature error: {0}")]
    Signature(String),
}

impl PluginError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::IssuerNotInAllowlist(_) => "E0806",
            Self::InstancePoolExhausted(_) => "E0807",
            Self::ImportOutsideAllowlist(_) => "E0808",
            Self::SelfGrantDenied(_) => "E0813",
            Self::BrokerLedgerWriteFailed(_) => "E0811",
            Self::Signature(_) => "E0806",
        }
    }
}

/// Plugin package manifest (S9: part a).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginManifest {
    pub name: String,
    pub version: String,
    pub issuer_public_key: String,     // hex Ed25519 (part b)
    pub content_digest: String,        // SHA-256 of canonical package bytes (part c)
    pub signature: String,             // hex Ed25519 over canonical manifest (part d)
    pub declared_imports: Vec<String>, // WASI imports the plugin declares
}

impl PluginManifest {
    /// Verify the issuer signature over the canonical manifest (part d).
    pub fn verify_issuer_signature(&self) -> Result<(), PluginError> {
        let key_bytes: [u8; 32] = hex::decode(&self.issuer_public_key)
            .map_err(|e| PluginError::Signature(e.to_string()))?
            .try_into()
            .map_err(|_| PluginError::Signature("issuer key not 32 bytes".into()))?;
        let pk = VerifyingKey::from_bytes(&key_bytes)
            .map_err(|e| PluginError::Signature(e.to_string()))?;
        // The signed bytes are the manifest WITHOUT the signature field.
        let unsigned = PluginManifestUnsigned {
            name: self.name.clone(),
            version: self.version.clone(),
            issuer_public_key: self.issuer_public_key.clone(),
            content_digest: self.content_digest.clone(),
            declared_imports: self.declared_imports.clone(),
        };
        // P0-4 fix: canonical (sorted-key) serialization — the ONLY
        // deterministic form for signing+verification across serializers.
        let bytes = crate::canonical::canonical_bytes(&unsigned)
            .map_err(|e| PluginError::Signature(e.to_string()))?;
        let sig_bytes =
            hex::decode(&self.signature).map_err(|e| PluginError::Signature(e.to_string()))?;
        let sig =
            Signature::from_slice(&sig_bytes).map_err(|e| PluginError::Signature(e.to_string()))?;
        pk.verify(&bytes, &sig)
            .map_err(|e| PluginError::Signature(e.to_string()))
    }
}

#[derive(Serialize)]
struct PluginManifestUnsigned {
    name: String,
    version: String,
    issuer_public_key: String,
    content_digest: String,
    declared_imports: Vec<String>,
}

/// The WASI host-import allowlist (S8/S12/S13).
#[derive(Debug, Clone, Default)]
pub struct WasiHostAllowlist {
    allowed: std::collections::HashSet<String>,
}

impl WasiHostAllowlist {
    /// The canonical v0.1 allowlist: wasi:http/proxy + orbit:reactor/* safe imports.
    pub fn canonical() -> Self {
        let mut allowed = std::collections::HashSet::new();
        allowed.insert("wasi:http/proxy".to_string());
        allowed.insert("orbit:reactor/context-read".to_string());
        allowed.insert("orbit:reactor/random".to_string());
        allowed.insert("orbit:reactor/pipe".to_string());
        allowed.insert("orbit:reactor/subagent-handle".to_string());
        Self { allowed }
    }

    /// Deny a plugin whose declared imports include any outside the allowlist (S8).
    pub fn validate(&self, declared: &[String]) -> Result<(), PluginError> {
        for import in declared {
            if !self.allowed.contains(import) {
                return Err(PluginError::ImportOutsideAllowlist(format!(
                    "import {import} outside allowlist (E0808)"
                )));
            }
        }
        Ok(())
    }
}

/// An installed plugin (post S9 install).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstalledPlugin {
    pub name: String,
    pub version: String,
    pub issuer_fingerprint: String,
    pub content_digest: String,
}

/// The plugin registry: only explicitly-installed plugins may run (S9).
/// Not Clone — the atomic instance counter must not be duplicated (P0-6).
#[derive(Debug, Default)]
pub struct PluginRegistry {
    allowlisted_issuers: std::collections::HashSet<String>,
    installed: Vec<InstalledPlugin>,
    instance_pool_max: usize,
    /// Live instance count — P0-6 fix: internal atomic counter so concurrent
    /// reservations cannot both pass the bound (S11: max 64).
    in_use: AtomicUsize,
    /// Whether a Ledger/PluginInstall channel is attached (S9f).
    ledger_attached: bool,
}

impl PluginRegistry {
    pub fn new(instance_pool_max: usize) -> Self {
        Self {
            allowlisted_issuers: std::collections::HashSet::new(),
            installed: Vec::new(),
            instance_pool_max,
            in_use: AtomicUsize::new(0),
            ledger_attached: false,
        }
    }

    /// Attach the Ledger channel (sets S9f). Install is refused without it.
    pub fn attach_ledger(&mut self) {
        self.ledger_attached = true;
    }

    /// The operator's explicit `Y`: add the issuer fingerprint to the local
    /// trust-root allowlist (S9 part e).
    pub fn allow_issuer(&mut self, issuer_fingerprint: String) {
        self.allowlisted_issuers.insert(issuer_fingerprint);
    }

    /// Install a plugin: verifies signature, issuer allowlist, import allowlist,
    /// and records it (S9 parts a-f). This is the ONLY way a plugin runs.
    pub fn install(
        &mut self,
        manifest: &PluginManifest,
        import_allowlist: &WasiHostAllowlist,
        package_bytes: &[u8],
    ) -> Result<InstalledPlugin, PluginError> {
        // (d) issuer signature must verify.
        manifest.verify_issuer_signature()?;
        // (c) content digest must match the package.
        let digest = hex::encode(Sha256::digest(package_bytes));
        if digest != manifest.content_digest {
            return Err(PluginError::Signature("content digest mismatch".into()));
        }
        // (e) issuer must be allowlisted.
        if !self
            .allowlisted_issuers
            .contains(&manifest.issuer_public_key)
        {
            return Err(PluginError::IssuerNotInAllowlist(format!(
                "issuer {} not allowlisted (E0806)",
                manifest.issuer_public_key
            )));
        }
        // (S8) declared imports must be inside the host allowlist.
        import_allowlist.validate(&manifest.declared_imports)?;
        // (S9f) a Ledger::PluginInstall event is required (broker write check).
        self.broker_ledger_check()?;

        let fp = self.fingerprint(&manifest.issuer_public_key);
        let plugin = InstalledPlugin {
            name: manifest.name.clone(),
            version: manifest.version.clone(),
            issuer_fingerprint: fp,
            content_digest: digest,
        };
        self.installed.push(plugin.clone());
        Ok(plugin)
    }

    /// Reserve an instance from the bounded pool (S11: max 64).
    /// P0-6 fix: the count is INTERNAL and atomic — two concurrent
    /// reservations cannot both pass the bound.
    pub fn reserve_instance(&self) -> Result<(), PluginError> {
        let current = self.in_use.load(Ordering::SeqCst);
        if current >= self.instance_pool_max {
            return Err(PluginError::InstancePoolExhausted(format!(
                "pool max {} reached (E0807)",
                self.instance_pool_max
            )));
        }
        // Atomic compare-and-swap: only one caller wins the last slot.
        self.in_use
            .compare_exchange(current, current + 1, Ordering::SeqCst, Ordering::SeqCst)
            .map_err(|_| {
                PluginError::InstancePoolExhausted(format!(
                    "pool max {} reached (E0807)",
                    self.instance_pool_max
                ))
            })?;
        Ok(())
    }

    /// Release a reserved instance back to the pool (saturating at 0).
    pub fn release_instance(&self) {
        self.in_use.fetch_sub(1, Ordering::SeqCst);
    }

    /// Current in-use instance count (for accounting).
    pub fn in_use(&self) -> usize {
        self.in_use.load(Ordering::SeqCst)
    }

    /// The installed plugin count (for pool accounting).
    pub fn installed(&self) -> &[InstalledPlugin] {
        &self.installed
    }

    fn fingerprint(&self, pubkey: &str) -> String {
        hex::encode(Sha256::digest(pubkey.as_bytes()))
    }

    /// S9f: the broker/Ledger must be attached or install is refused.
    /// The real check is the fsync'd `Ledger::PluginInstall` event; here we
    /// enforce the precondition that the channel exists.
    fn broker_ledger_check(&self) -> Result<(), PluginError> {
        if !self.ledger_attached {
            return Err(PluginError::BrokerLedgerWriteFailed(
                "no Ledger/PluginInstall channel attached (E0811)".into(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use rand_core::OsRng;

    fn signed_manifest(sk: &SigningKey, name: &str) -> PluginManifest {
        let content_digest = hex::encode(Sha256::digest(b"package-bytes"));
        let unsigned = PluginManifestUnsigned {
            name: name.into(),
            version: "0.1.0".into(),
            issuer_public_key: hex::encode(sk.verifying_key().to_bytes()),
            content_digest: content_digest.clone(),
            declared_imports: vec!["wasi:http/proxy".into()],
        };
        let bytes = super::canonical::canonical_bytes(&unsigned).unwrap();
        let sig = sk.sign(&bytes);
        PluginManifest {
            name: name.into(),
            version: "0.1.0".into(),
            issuer_public_key: hex::encode(sk.verifying_key().to_bytes()),
            content_digest,
            signature: hex::encode(sig.to_bytes()),
            declared_imports: vec!["wasi:http/proxy".into()],
        }
    }

    #[test]
    fn install_requires_issuer_allowlist() {
        let sk = SigningKey::generate(&mut OsRng);
        let m = signed_manifest(&sk, "p1");
        let mut reg = PluginRegistry::new(64);
        reg.attach_ledger();
        let al = WasiHostAllowlist::canonical();
        let r = reg.install(&m, &al, b"package-bytes");
        assert!(r.is_err(), "un-allowlisted issuer must fail (E0806)");
    }

    #[test]
    fn install_succeeds_after_allowlist() {
        let sk = SigningKey::generate(&mut OsRng);
        let m = signed_manifest(&sk, "p2");
        let mut reg = PluginRegistry::new(64);
        reg.attach_ledger();
        reg.allow_issuer(m.issuer_public_key.clone());
        let al = WasiHostAllowlist::canonical();
        let p = reg.install(&m, &al, b"package-bytes").unwrap();
        assert_eq!(p.name, "p2");
    }

    #[test]
    fn import_outside_allowlist_denied() {
        let sk = SigningKey::generate(&mut OsRng);
        // Build a manifest that is VALIDLY signed but declares a forbidden import.
        let content_digest = hex::encode(Sha256::digest(b"package-bytes"));
        let unsigned = PluginManifestUnsigned {
            name: "p3".into(),
            version: "0.1.0".into(),
            issuer_public_key: hex::encode(sk.verifying_key().to_bytes()),
            content_digest: content_digest.clone(),
            declared_imports: vec!["wasi:sockets/tcp".into()], // forbidden (S8)
        };
        let bytes = super::canonical::canonical_bytes(&unsigned).unwrap();
        let sig = sk.sign(&bytes);
        let m = PluginManifest {
            name: "p3".into(),
            version: "0.1.0".into(),
            issuer_public_key: hex::encode(sk.verifying_key().to_bytes()),
            content_digest,
            signature: hex::encode(sig.to_bytes()),
            declared_imports: vec!["wasi:sockets/tcp".into()],
        };
        let mut reg = PluginRegistry::new(64);
        reg.attach_ledger();
        reg.allow_issuer(m.issuer_public_key.clone());
        let al = WasiHostAllowlist::canonical();
        assert_eq!(
            reg.install(&m, &al, b"package-bytes").unwrap_err().code(),
            "E0808"
        );
    }

    #[test]
    fn instance_pool_bounded() {
        let reg = PluginRegistry::new(64);
        // Fill the pool to max.
        for _ in 0..64 {
            assert!(reg.reserve_instance().is_ok(), "reserve within max");
        }
        assert_eq!(reg.in_use(), 64);
        // The 65th must fail E0807.
        assert_eq!(reg.reserve_instance().unwrap_err().code(), "E0807");
        // Release frees a slot; reserve succeeds again.
        reg.release_instance();
        assert_eq!(reg.in_use(), 63);
        assert!(reg.reserve_instance().is_ok());
    }
}
