//! Trust-root manifest model (DR-05 FILE B, Foundation §1-2).
//!
//! v0.1 ships with a baked-in root public key plus local `trust add-root`.
//! The manifest is signed; failure to verify against any root → exit 2, E0706.

use crate::canonical::{canonical_bytes, sha256_hex, CanonicalError};
use crate::error::TrustError;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Manifest schema version (DR-05 M7).
pub const MANIFEST_SCHEMA: &str = "orbit.trust/v0.1";

/// A single trust root public key (hex-encoded Ed25519).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct RootPublicKey(pub String);

/// A route spec: model flat-name → (provider, deployment, region) internal tuple.
/// Per DR-01 I2, the orchestrator names a flat model string; the manifest maps it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteSpec {
    pub model: String,      // flat model name (orchestrator-facing)
    pub provider: String,   // internal provider_id
    pub deployment: String, // internal deployment_id
    pub region: String,     // internal region_id
}

/// Issuer allowlist entry: an issuer key fingerprint that may mint capability cards.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssuerSpec {
    pub name: String,
    pub public_key: RootPublicKey, // fingerprint (hex)
    pub trust_level: TrustLevel,
}

/// Lifecycle pin for a model/route (DR-05 §7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum LifecycleState {
    Active,
    Deprecated,
    Sunset,
    Retired,
    Revoked,
}

/// Trust levels (DR-01 §17.2). Attested is reserved in v0.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum TrustLevel {
    Standard,
    #[serde(rename = "attested_reserved")]
    Attested,
    Local,
}

impl TrustLevel {
    /// Validate that a trust level is usable in v0.1 (Attested reserved → E0104/E0716).
    pub fn usable_v0_1(&self) -> bool {
        matches!(self, Self::Standard | Self::Local)
    }
}

/// A lifecycle pin: which route is in which lifecycle state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LifecyclePin {
    pub model: String,
    pub state: LifecycleState,
}

/// The signed trust-root manifest body (before signature).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustRootManifestBody {
    pub schema: String,  // MANIFEST_SCHEMA
    pub version: String, // manifest version
    pub issuer_allowlist: Vec<IssuerSpec>,
    pub routes: Vec<RouteSpec>,
    pub lifecycle: Vec<LifecyclePin>,
    pub model_allowlist: BTreeSet<String>, // flat model names
}

/// The on-disk manifest: body + Ed25519 signature (hex).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustRootManifest {
    pub body: TrustRootManifestBody,
    pub signature: String, // hex Ed25519 over canonical(body)
}

impl TrustRootManifest {
    /// Load and verify a manifest against the provided root keys.
    /// Returns Err(E0706) if no root verifies. (DR-05 M1)
    pub fn verify(&self, roots: &[RootPublicKey]) -> Result<(), TrustError> {
        // Schema/version gates first.
        if self.body.schema != MANIFEST_SCHEMA {
            return Err(TrustError::ManifestSchemaInvalid(format!(
                "expected {MANIFEST_SCHEMA}, got {}",
                self.body.schema
            )));
        }
        if self.body.version.is_empty() {
            return Err(TrustError::ManifestVersionUnsupported(
                "empty version".into(),
            ));
        }

        let body_bytes = canonical_bytes(&self.body)
            .map_err(|e| TrustError::ManifestSchemaInvalid(e.to_string()))?;
        let sig_bytes = hex::decode(&self.signature)
            .map_err(|_| TrustError::RootInvalid("signature not hex".into()))?;
        let sig = Signature::from_slice(&sig_bytes)
            .map_err(|_| TrustError::RootInvalid("bad signature length".into()))?;

        for root in roots {
            let key_bytes: [u8; 32] = match hex::decode(&root.0) {
                Ok(b) => match <[u8; 32]>::try_from(b.as_slice()) {
                    Ok(arr) => arr,
                    Err(_) => continue, // not a 32-byte Ed25519 key; try next root
                },
                Err(_) => continue, // malformed root key; try next
            };
            let Ok(pk) = VerifyingKey::from_bytes(&key_bytes) else {
                continue;
            };
            if pk.verify(&body_bytes, &sig).is_ok() {
                return Ok(());
            }
        }
        Err(TrustError::RootInvalid(
            "no embedded or added root verifies the manifest signature".into(),
        ))
    }

    /// Compute `policy_snapshot_digest` = SHA256(canonical(registry + cards + trust-root)).
    /// Phase-router source is excluded (DR-01 I13). Here we hash this manifest body;
    /// the registry/cards halves are added by the caller (DR-05 M6).
    pub fn policy_snapshot_digest(&self) -> Result<String, CanonicalError> {
        sha256_hex(&self.body)
    }
}

/// A canonicalization helper for signatures: the bytes signed are canonical(body).
pub fn signed_bytes(body: &TrustRootManifestBody) -> Result<Vec<u8>, CanonicalError> {
    canonical_bytes(body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use rand_core::OsRng;

    fn sample_manifest() -> TrustRootManifest {
        TrustRootManifest {
            body: TrustRootManifestBody {
                schema: MANIFEST_SCHEMA.into(),
                version: "0.1.0".into(),
                issuer_allowlist: vec![],
                routes: vec![],
                lifecycle: vec![],
                model_allowlist: BTreeSet::new(),
            },
            signature: String::new(),
        }
    }

    #[test]
    fn verify_accepts_valid_root_signature() {
        let sk = SigningKey::generate(&mut OsRng);
        let mut m = sample_manifest();
        let body_bytes = signed_bytes(&m.body).unwrap();
        let sig = sk.sign(&body_bytes);
        m.signature = hex::encode(sig.to_bytes());
        let root = RootPublicKey(hex::encode(sk.verifying_key().to_bytes()));
        assert!(m.verify(&[root]).is_ok());
    }

    #[test]
    fn verify_rejects_wrong_root() {
        let sk = SigningKey::generate(&mut OsRng);
        let mut m = sample_manifest();
        let body_bytes = signed_bytes(&m.body).unwrap();
        let sig = sk.sign(&body_bytes);
        m.signature = hex::encode(sig.to_bytes());
        // Different root key
        let other = SigningKey::generate(&mut OsRng);
        let wrong = RootPublicKey(hex::encode(other.verifying_key().to_bytes()));
        assert_eq!(
            m.verify(&[wrong]).unwrap_err().code(),
            "E0706",
            "wrong root must fail with trust_root_invalid"
        );
    }

    #[test]
    fn reject_attested_trust_level_in_v0_1() {
        let lvl = TrustLevel::Attested;
        assert!(!lvl.usable_v0_1(), "Attested must be reserved in v0.1");
        assert!(TrustLevel::Standard.usable_v0_1());
        assert!(TrustLevel::Local.usable_v0_1());
    }
}
