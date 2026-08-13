//! ORBIT PIB identity subsystem — Phase A (A9).
//!
//! Per DR-08 §13 (CTX-I11): the PIB is the only cross-machine identity.
//! Sessions, memories, exports, and restores are bound to a `PibId`; the PIB
//! never leaves the machine it is local to — what travels is a signed export.
//! Cross-machine transfer requires the destination PIB to appear in the
//! trust-root allowlist (E0722 pib_cross_machine_denied).

#![forbid(unsafe_code)]

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

/// PibId is a ULID (DR-08 §13).
pub type PibId = String;
pub type TrustRootId = String;

/// Host fingerprint: SHA256 of the machine identity (hostname + machine-id).
pub type HostFingerprint = String;

/// v0.1 PIB record (DR-08 §3.4, locked).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PibIdentity {
    pub pib_id: PibId,
    pub display_name: String,
    pub created_at: String, // ISO-8601 nanos
    pub public_key: String, // hex Ed25519 public key
    pub host_fingerprint: HostFingerprint,
    pub trust_root_membership: BTreeSet<TrustRootId>,
    pub cross_machine_allowlist: BTreeSet<PibId>,
    pub rotation_count: u32,
}

/// The PIB error family (E0507, E0508, E0722).
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum PibError {
    /// ORBIT-E0722 pib_cross_machine_denied
    #[error("ORBIT-E0722 pib_cross_machine_denied: {0}")]
    CrossMachineDenied(String),
    /// ORBIT-E0507 restore_target_not_in_pib_allowlist
    #[error("ORBIT-E0507 restore_target_not_in_pib_allowlist: {0}")]
    RestoreTargetNotInAllowlist(String),
    /// ORBIT-E0508 restore_signature_verification_failed
    #[error("ORBIT-E0508 restore_signature_verification_failed: {0}")]
    SignatureVerificationFailed(String),
}

impl PibError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::CrossMachineDenied(_) => "E0722",
            Self::RestoreTargetNotInAllowlist(_) => "E0507",
            Self::SignatureVerificationFailed(_) => "E0508",
        }
    }
}

/// A signed export/restore artifact addressed to a destination PIB.
/// The PIB never leaves the machine; what travels is this signed artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedBySourcePib {
    pub source_pib_id: PibId,
    pub destination_pib_id: PibId,
    pub payload_digest: String, // SHA256 of the payload
    pub signature: String,      // hex Ed25519 over canonical (source, destination, payload_digest)
}

impl SignedBySourcePib {
    /// Sign the cross-machine artifact with the source PIB's key.
    pub fn sign(
        signing_key: &SigningKey,
        source_pib_id: PibId,
        destination_pib_id: PibId,
        payload: &[u8],
    ) -> Self {
        let payload_digest = hex::encode(Sha256::digest(payload));
        let to_sign = format!("{source_pib_id}|{destination_pib_id}|{payload_digest}");
        let sig = signing_key.sign(to_sign.as_bytes());
        Self {
            source_pib_id,
            destination_pib_id,
            payload_digest,
            signature: hex::encode(sig.to_bytes()),
        }
    }

    /// Verify the artifact against the source PIB's public key.
    pub fn verify(&self, source_public_key: &[u8; 32], payload: &[u8]) -> Result<(), PibError> {
        let pk = VerifyingKey::from_bytes(source_public_key)
            .map_err(|e| PibError::SignatureVerificationFailed(format!("bad key: {e}")))?;
        let actual_digest = hex::encode(Sha256::digest(payload));
        if actual_digest != self.payload_digest {
            return Err(PibError::SignatureVerificationFailed(
                "payload digest mismatch".into(),
            ));
        }
        let to_verify = format!(
            "{}|{}|{}",
            self.source_pib_id, self.destination_pib_id, self.payload_digest
        );
        let sig_bytes = hex::decode(&self.signature)
            .map_err(|e| PibError::SignatureVerificationFailed(format!("bad sig hex: {e}")))?;
        let sig = Signature::from_slice(&sig_bytes)
            .map_err(|e| PibError::SignatureVerificationFailed(format!("bad sig: {e}")))?;
        pk.verify(to_verify.as_bytes(), &sig)
            .map_err(|e| PibError::SignatureVerificationFailed(format!("verify: {e}")))?;
        Ok(())
    }
}

/// The PIB registry: local identity + cross-machine allowlist.
#[derive(Debug, Clone, Default)]
pub struct PibRegistry {
    identity: Option<PibIdentity>,
}

impl PibRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register the local PIB identity (from a generated keypair + host fp).
    pub fn register(
        &mut self,
        pib_id: PibId,
        display_name: String,
        public_key_hex: String,
        host_fingerprint: HostFingerprint,
        trust_root_id: TrustRootId,
    ) {
        self.identity = Some(PibIdentity {
            pib_id,
            display_name,
            created_at: chrono::Utc::now().to_rfc3339(),
            public_key: public_key_hex,
            host_fingerprint,
            trust_root_membership: BTreeSet::from([trust_root_id]),
            cross_machine_allowlist: BTreeSet::new(),
            rotation_count: 0,
        });
    }

    /// The local PIB identity (must be registered first).
    pub fn identity(&self) -> Option<&PibIdentity> {
        self.identity.as_ref()
    }

    /// Check whether a destination PIB is on the cross-machine allowlist.
    /// Denied → E0722 (CTX-I11).
    pub fn can_cross_to(&self, destination_pib: &PibId) -> Result<(), PibError> {
        let Some(id) = &self.identity else {
            return Err(PibError::CrossMachineDenied(
                "no local PIB registered".into(),
            ));
        };
        if id.cross_machine_allowlist.contains(destination_pib) {
            Ok(())
        } else {
            Err(PibError::RestoreTargetNotInAllowlist(format!(
                "destination PIB {destination_pib} not in allowlist (E0507)"
            )))
        }
    }

    /// `orbit trust add-pib <public-key>` — add a destination PIB to the allowlist.
    pub fn add_destination(&mut self, destination_pib: PibId) {
        if let Some(id) = &mut self.identity {
            id.cross_machine_allowlist.insert(destination_pib);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand_core::OsRng;

    #[test]
    fn signed_artifact_roundtrip() {
        let sk = SigningKey::generate(&mut OsRng);
        let pk: [u8; 32] = sk.verifying_key().to_bytes();
        let payload = b"export-bundle-bytes";
        let art = SignedBySourcePib::sign(&sk, "src".into(), "dst".into(), payload);
        assert!(art.verify(&pk, payload).is_ok());
    }

    #[test]
    fn tampered_payload_fails_verify() {
        let sk = SigningKey::generate(&mut OsRng);
        let pk: [u8; 32] = sk.verifying_key().to_bytes();
        let art = SignedBySourcePib::sign(&sk, "src".into(), "dst".into(), b"original");
        assert!(art.verify(&pk, b"tampered").is_err());
    }

    #[test]
    fn cross_machine_denied_without_allowlist() {
        let mut reg = PibRegistry::new();
        reg.register(
            "01J-local".into(),
            "local".into(),
            hex::encode([1u8; 32]),
            "fp".into(),
            "root".into(),
        );
        assert!(reg.can_cross_to(&"01J-remote".into()).is_err());
        reg.add_destination("01J-remote".into());
        assert!(reg.can_cross_to(&"01J-remote".into()).is_ok());
    }
}
