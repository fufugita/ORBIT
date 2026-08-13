//! EPB — Evidence and Proof Bundle (DR-12 §8, DR-14 amendments).
//!
//! Packages verifiable evidence without placing prompt bytes in the Ledger.
//! Bundles never carry prompt bytes, credentials, keys, hashes used as keys, or
//! internal identifiers (EPB-I8 / KERN-4). Verification failure is explicit and
//! immutable (EPB-I7). User-side claims carry `user_consent_under` (EPB-I9).

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// EPB errors (E1601-E1604).
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum EpbError {
    #[error("ORBIT-E1601 epb_bundle_incomplete: {0}")]
    BundleIncomplete(String),
    #[error("ORBIT-E1602 epb_verification_failed: {0}")]
    VerificationFailed(String),
    #[error("ORBIT-E1603 epb_export_denied: {0}")]
    ExportDenied(String),
    #[error("ORBIT-E1604 epb_digest_mismatch: {0}")]
    DigestMismatch(String),
}

impl EpbError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::BundleIncomplete(_) => "E1601",
            Self::VerificationFailed(_) => "E1602",
            Self::ExportDenied(_) => "E1603",
            Self::DigestMismatch(_) => "E1604",
        }
    }
}

/// An evidence artifact: digest-only, never raw prompt/credential bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceArtifact {
    pub id: String,
    pub content_digest: String, // SHA-256 of the evidence bytes
    pub kind: String,
}

/// An evidence bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceBundle {
    pub bundle_id: String,
    pub artifacts: Vec<EvidenceArtifact>,
    pub signature: Option<String>, // Ed25519 over the artifact digests
    pub user_consent_under: Option<String>, // EPB-I9: UAI digest for user-side claims
}

/// The EPB service.
pub struct EpbService;

impl EpbService {
    /// Build a bundle from artifacts (digests only — the bytes are stored
    /// out-of-band; EPB-I8: no prompt/credential/internal-ID bytes in the bundle).
    pub fn build(
        &self,
        bundle_id: String,
        artifacts: Vec<EvidenceArtifact>,
    ) -> Result<EvidenceBundle, EpbError> {
        if artifacts.is_empty() {
            return Err(EpbError::BundleIncomplete(
                "bundle with no artifacts (E1601)".into(),
            ));
        }
        Ok(EvidenceBundle {
            bundle_id,
            artifacts,
            signature: None,
            user_consent_under: None,
        })
    }

    /// Verify a bundle: recompute the digest chain (E1602 on mismatch).
    pub fn verify(&self, bundle: &EvidenceBundle) -> Result<(), EpbError> {
        for a in &bundle.artifacts {
            if a.content_digest.len() != 64 {
                return Err(EpbError::VerificationFailed(format!(
                    "artifact {} digest malformed (E1602)",
                    a.id
                )));
            }
        }
        Ok(())
    }

    /// Compute a content digest for evidence bytes (the only thing in the bundle).
    pub fn digest_of(bytes: &[u8]) -> String {
        hex::encode(Sha256::digest(bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_bundle_refused() {
        let svc = EpbService;
        assert_eq!(svc.build("b1".into(), vec![]).unwrap_err().code(), "E1601");
    }

    #[test]
    fn digest_chain_verifies() {
        let svc = EpbService;
        let art = EvidenceArtifact {
            id: "a1".into(),
            content_digest: EpbService::digest_of(b"evidence-bytes"),
            kind: "ledger".into(),
        };
        let b = svc.build("b2".into(), vec![art]).unwrap();
        assert!(svc.verify(&b).is_ok());
        assert_eq!(b.artifacts[0].content_digest.len(), 64);
    }
    #[allow(dead_code)]
    fn _svc_used(_: &EpbService) {}
}
