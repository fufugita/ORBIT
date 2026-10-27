//! Release metadata and layout helpers.
//!
//! This crate does not produce verified release evidence, and no verified
//! evidence is currently bound to the executable bytes reported by the CLI.
//! `VersionEvidence` only serializes caller-supplied assertions; it does not
//! verify them. `generate_sbom` serializes caller-supplied entries without
//! discovering dependencies, validating licenses, or computing their hashes.
//! `validate_evidence_bundle` checks required paths only; it does not inspect
//! contents or verify provenance, signatures, reproducibility, or audits.

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Release error family.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum ReleaseError {
    #[error("evidence missing: {0}")]
    EvidenceMissing(String),
}

/// The `orbit version --evidence` output (DR-13 §9).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VersionEvidence {
    pub version: String,
    pub commit_sha: String,
    pub built_at: String,
    pub toolchain: String,
    pub target: String,
    pub profile: String,
    pub sbom_sha256: String,
    pub provenance_uri: String,
    pub signature_key_id: String,
    pub reproducible_hash: String,
    pub audit_status: String,
    pub notice_sha256: String,
}

impl VersionEvidence {
    /// Serialize explicitly supplied release facts.
    ///
    /// This constructor computes hashes of the supplied SBOM and notice bytes,
    /// but it does not verify any other field or assertion.
    pub fn from_facts(facts: VersionEvidenceFacts<'_>) -> Self {
        Self {
            version: facts.version.into(),
            commit_sha: facts.commit_sha.into(),
            built_at: facts.built_at.into(),
            toolchain: facts.toolchain.into(),
            target: facts.target.into(),
            profile: facts.profile.into(),
            sbom_sha256: hex::encode(Sha256::digest(facts.sbom_bytes)),
            provenance_uri: facts.provenance_uri.into(),
            signature_key_id: facts.signature_key_id.into(),
            reproducible_hash: facts.reproducible_hash.into(),
            audit_status: facts.audit_status.into(),
            notice_sha256: hex::encode(Sha256::digest(facts.notice_bytes)),
        }
    }
}

/// Caller-provided metadata for [`VersionEvidence::from_facts`].
///
/// Values other than the two byte-slice hashes are copied as assertions; this
/// type does not establish that they are true.
pub struct VersionEvidenceFacts<'a> {
    pub version: &'a str,
    pub commit_sha: &'a str,
    pub built_at: &'a str,
    pub toolchain: &'a str,
    pub target: &'a str,
    pub profile: &'a str,
    pub sbom_bytes: &'a [u8],
    pub provenance_uri: &'a str,
    pub signature_key_id: &'a str,
    pub reproducible_hash: &'a str,
    pub audit_status: &'a str,
    pub notice_bytes: &'a [u8],
}

/// A minimal SBOM entry (SPDX 2.3 shape, DR-13 §8): one per dependency.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SbomEntry {
    pub name: String,
    pub version: String,
    pub license: String, // SPDX expression
    pub sha256: String,  // source hash
    pub supplier: String,
}

/// Serialize caller-supplied entries into an SPDX-shaped document.
///
/// This does not discover dependencies, validate license expressions, or
/// compute package hashes. The caller must provide a unique valid SPDX
/// document namespace and independently verify every entry.
pub fn generate_sbom(document_namespace: &str, entries: &[SbomEntry]) -> Vec<u8> {
    let doc = serde_json::json!({
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "documentNamespace": document_namespace,
        "packages": entries.iter().map(|e| serde_json::json!({
            "name": e.name,
            "versionInfo": e.version,
            "licenseConcluded": e.license,
            "checksums": [{"algorithm": "SHA256", "checksumValue": e.sha256}],
            "supplier": e.supplier,
        })).collect::<Vec<_>>(),
    });
    serde_json::to_vec_pretty(&doc).unwrap_or_default()
}

/// The release evidence bundle layout (DR-03 §11).
pub const EVIDENCE_LAYOUT: &[&str] = &[
    "spec-manifest.json",
    "traceability.json",
    "test-summary.json",
    "fuzz-summary.json",
    "concurrency-summary.json",
    "fault-summary.json",
    "security-review.md",
    "migration-summary.json",
    "benchmarks.json",
    "sbom.spdx.json",
    "provenance.intoto.jsonl",
    "reproducibility.json",
    "artifact-signatures/",
    "known-issues.md",
    "demo-transcript.md",
];

/// Check that required evidence-layout paths exist.
///
/// This is a presence-only check and does not verify content or authenticity.
pub fn validate_evidence_bundle(dir: &std::path::Path) -> Result<(), ReleaseError> {
    for required in EVIDENCE_LAYOUT {
        let p = dir.join(required);
        if !p.exists() {
            return Err(ReleaseError::EvidenceMissing(format!(
                "evidence bundle missing {required}"
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_evidence_is_json_stable() {
        let e = VersionEvidence::from_facts(VersionEvidenceFacts {
            version: "0.1.0",
            commit_sha: "abc123",
            built_at: "test-fixture-time",
            toolchain: "test-fixture-toolchain",
            target: "test-fixture-target",
            profile: "test-fixture-profile",
            sbom_bytes: b"sbom-bytes",
            provenance_uri: "test-fixture-provenance",
            signature_key_id: "test-fixture-key",
            reproducible_hash: "test-fixture-repro-hash",
            audit_status: "test-fixture-audit-status",
            notice_bytes: b"notice-bytes",
        });
        let a = serde_json::to_string(&e).unwrap();
        let b = serde_json::to_string(&e).unwrap();
        assert_eq!(a, b);
        assert_eq!(e.version, "0.1.0");
        assert_eq!(e.commit_sha, "abc123");
        assert_eq!(e.built_at, "test-fixture-time");
        assert_eq!(e.toolchain, "test-fixture-toolchain");
        assert_eq!(e.target, "test-fixture-target");
        assert_eq!(e.profile, "test-fixture-profile");
        assert_eq!(e.sbom_sha256, hex::encode(Sha256::digest(b"sbom-bytes")));
        assert_eq!(e.provenance_uri, "test-fixture-provenance");
        assert_eq!(e.signature_key_id, "test-fixture-key");
        assert_eq!(e.reproducible_hash, "test-fixture-repro-hash");
        assert_eq!(e.audit_status, "test-fixture-audit-status");
        assert_eq!(
            e.notice_sha256,
            hex::encode(Sha256::digest(b"notice-bytes"))
        );
    }

    #[test]
    fn sbom_shape_spdx23() {
        let entries = vec![SbomEntry {
            name: "serde".into(),
            version: "1.0".into(),
            license: "MIT OR Apache-2.0".into(),
            sha256: "a".repeat(64),
            supplier: "crates.io".into(),
        }];
        let sbom = generate_sbom("https://example.invalid/test/sbom", &entries);
        let v: serde_json::Value = serde_json::from_slice(&sbom).unwrap();
        assert_eq!(v["spdxVersion"], "SPDX-2.3");
        assert_eq!(v["documentNamespace"], "https://example.invalid/test/sbom");
        assert_eq!(v["packages"][0]["name"], "serde");
    }

    #[test]
    fn evidence_bundle_missing_file_rejected() {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let mut owned_dir = None;
        for attempt in 0..100 {
            let candidate = std::env::temp_dir().join(format!(
                "orbit-evidence-layout-test-{}-{timestamp}-{attempt}",
                std::process::id()
            ));
            match std::fs::create_dir(&candidate) {
                Ok(()) => {
                    owned_dir = Some(candidate);
                    break;
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("create isolated evidence-test directory: {error}"),
            }
        }
        let owned_dir = owned_dir.expect("find unused evidence-test directory name");
        let missing_bundle = owned_dir.join("bundle");
        assert!(validate_evidence_bundle(&missing_bundle).is_err());
        std::fs::remove_dir(&owned_dir).expect("remove empty evidence-test directory");
    }
}
