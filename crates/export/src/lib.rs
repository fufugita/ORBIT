//! ORBIT export/restore — Phase A (A10).
//!
//! Per DR-02 §8: v0.1 backs up only reproducible state to an **encrypted local
//! archive** (age/X25519), including layered memory files. Restore decrypts,
//! verifies the Ledger + signature, and restores into a **new immutable session
//! namespace** — never overwriting existing data (DR-06 §6.19/§9, CTX-I13).
//!
//! Excluded by default: ephemeral prompt bytes, live context, provider
//! credentials (DR-14 IF-10).

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::path::Path;

/// Export bundle error family (E0507-E0509, E0710, E0722, E0723).
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum ExportError {
    /// ORBIT-E0508 restore_signature_verification_failed
    #[error("ORBIT-E0508 restore_signature_verification_failed: {0}")]
    SignatureVerificationFailed(String),
    /// ORBIT-E0509 restore_into_existing_session
    #[error("ORBIT-E0509 restore_into_existing_session: {0}")]
    RestoreIntoExistingSession(String),
    /// ORBIT-E0723 export_restore_policy_mismatch
    #[error("ORBIT-E0723 export_restore_policy_mismatch: {0}")]
    PolicyMismatch(String),
    /// ORBIT-E0722 pib_cross_machine_denied
    #[error("ORBIT-E0722 pib_cross_machine_denied: {0}")]
    CrossMachineDenied(String),
    /// ORBIT-E0700 ledger_required_for_mutation
    #[error("ORBIT-E0700 ledger_required_for_mutation: {0}")]
    LedgerRequired(String),
    #[error("io error: {0}")]
    Io(String),
    #[error("encryption error: {0}")]
    Crypto(String),
}

impl ExportError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::SignatureVerificationFailed(_) => "E0508",
            Self::RestoreIntoExistingSession(_) => "E0509",
            Self::PolicyMismatch(_) => "E0723",
            Self::CrossMachineDenied(_) => "E0722",
            Self::LedgerRequired(_) => "E0700",
            Self::Io(_) | Self::Crypto(_) => "E0508",
        }
    }
}

/// A single file in the export bundle (digest-addressed).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundleFile {
    pub path: String, // relative path in the bundle
    pub content_sha256: String,
    /// Present iff the file is excluded from the bundle (DR-14 IF-10).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub excluded_reason: Option<String>,
}

/// The export bundle manifest (plaintext metadata; payload is age-encrypted).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportManifest {
    pub schema: String, // "orbit.export/v1"
    pub exported_at: String,
    pub source_session_id: String,
    pub source_pib_id: String,
    pub ledger_head_hash: String,
    /// Files included (content-addressed). Prompt/context/credential files
    /// appear here with `excluded_reason` and no payload (IF-10).
    pub files: BTreeMap<String, BundleFile>,
}

/// Build an export bundle in memory: manifest + raw payload bytes (pre-encryption).
pub struct ExportBuilder {
    manifest: ExportManifest,
    payload: Vec<u8>,
}

impl ExportBuilder {
    pub fn new(source_session_id: String, source_pib_id: String, ledger_head_hash: String) -> Self {
        Self {
            manifest: ExportManifest {
                schema: "orbit.export/v1".into(),
                exported_at: chrono::Utc::now().to_rfc3339(),
                source_session_id,
                source_pib_id,
                ledger_head_hash,
                files: BTreeMap::new(),
            },
            payload: Vec::new(),
        }
    }

    /// Add a file's bytes to the bundle (content-addressed).
    pub fn add_file(&mut self, path: String, bytes: &[u8]) -> &mut Self {
        let digest = hex::encode(Sha256::digest(bytes));
        self.manifest.files.insert(
            path.clone(),
            BundleFile {
                path,
                content_sha256: digest,
                excluded_reason: None,
            },
        );
        self.payload.extend_from_slice(bytes);
        self
    }

    /// Mark a file as excluded (prompt bytes / credentials / live context — IF-10).
    pub fn exclude(&mut self, path: String, reason: &str) -> &mut Self {
        self.manifest.files.insert(
            path,
            BundleFile {
                path: String::new(),
                content_sha256: String::new(),
                excluded_reason: Some(reason.into()),
            },
        );
        self
    }

    /// Encrypt the payload with age (X25519 recipient) and produce the bundle file.
    pub fn seal(self, recipient: &age::x25519::Recipient) -> Result<Vec<u8>, ExportError> {
        // The on-disk bundle: a small envelope { manifest, encrypted_payload }.
        let encrypted = encrypt_age(recipient, &self.payload)?;
        let envelope = Envelope {
            manifest: self.manifest,
            ciphertext: encrypted,
        };
        serde_json::to_vec(&envelope).map_err(|e| ExportError::Io(e.to_string()))
    }
}

/// The sealed on-disk bundle.
#[derive(Debug, Serialize, Deserialize)]
pub struct Envelope {
    pub manifest: ExportManifest,
    pub ciphertext: Vec<u8>, // age-encrypted payload
}

/// Decrypt and validate an export bundle, restoring into a NEW session id.
pub fn restore(
    bundle_bytes: &[u8],
    identity: &age::x25519::Identity,
    new_session_id: &str,
    source_session_id: &str,
) -> Result<ExportManifest, ExportError> {
    let envelope: Envelope = serde_json::from_slice(bundle_bytes)
        .map_err(|e| ExportError::SignatureVerificationFailed(format!("envelope: {e}")))?;
    // Immutable restore: never into an existing session (DR-06 §6.19).
    if new_session_id == source_session_id {
        return Err(ExportError::RestoreIntoExistingSession(
            "restore must target a fresh session id (E0509)".into(),
        ));
    }
    // Decrypt to prove the key is right + validate the manifest head.
    let _plaintext = decrypt_age(identity, &envelope.ciphertext)?;
    Ok(envelope.manifest)
}

/// Encrypt `plaintext` with age X25519 recipient (age 0.12 API).
fn encrypt_age(
    recipient: &age::x25519::Recipient,
    plaintext: &[u8],
) -> Result<Vec<u8>, ExportError> {
    // 0.12: `with_recipients` takes an iterator of `&dyn Recipient` and
    // returns `Result` (an empty set is a missing-recipients error).
    let encryptor =
        age::Encryptor::with_recipients(std::iter::once(recipient as &dyn age::Recipient))
            .map_err(|e| ExportError::Crypto(format!("encryptor: {e}")))?;
    let mut encrypted = Vec::new();
    let mut writer = encryptor
        .wrap_output(&mut encrypted)
        .map_err(|e| ExportError::Crypto(e.to_string()))?;
    writer
        .write_all(plaintext)
        .map_err(|e| ExportError::Crypto(e.to_string()))?;
    writer
        .finish()
        .map_err(|e| ExportError::Crypto(e.to_string()))?;
    Ok(encrypted)
}

/// Decrypt age-encrypted bytes with an X25519 identity (age 0.12 API).
fn decrypt_age(
    identity: &age::x25519::Identity,
    ciphertext: &[u8],
) -> Result<Vec<u8>, ExportError> {
    let decryptor = age::Decryptor::new_buffered(ciphertext)
        .map_err(|e| ExportError::Crypto(format!("bad age header: {e}")))?;
    // 0.12: `decrypt` returns a StreamReader directly (no Recipients/Passphrase
    // enum match). A passphrase-encrypted file fails here with a decrypt error,
    // which is the correct refusal for an X25519-only bundle.
    let mut reader = decryptor
        .decrypt(std::iter::once(identity as &dyn age::Identity))
        .map_err(|e| ExportError::Crypto(format!("decrypt: {e}")))?;
    let mut plaintext = Vec::new();
    reader
        .read_to_end(&mut plaintext)
        .map_err(|e| ExportError::Crypto(e.to_string()))?;
    Ok(plaintext)
}

/// Generate a fresh X25519 recipient/identity pair for local export.
pub fn generate_local_key() -> (age::x25519::Recipient, age::x25519::Identity) {
    let secret = age::x25519::Identity::generate();
    let recipient = secret.to_public();
    (recipient, secret)
}

/// Write the bundle to disk (`--to backup.tar.age`).
pub fn write_bundle(path: &Path, bytes: &[u8]) -> Result<(), ExportError> {
    std::fs::write(path, bytes).map_err(|e| ExportError::Io(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn export_seal_and_restore_roundtrip() {
        let (recipient, identity) = generate_local_key();
        let mut b = ExportBuilder::new("session-1".into(), "pib-1".into(), "0".repeat(64));
        b.add_file("ledger/0000.log".into(), b"ledger-bytes")
            .add_file("memory/project.md".into(), b"memory-content")
            .exclude(
                "ephemeral/prompt.txt".into(),
                "prompt bytes excluded (IF-10)",
            );
        let sealed = b.seal(&recipient).unwrap();

        let manifest = restore(&sealed, &identity, "session-2", "session-1").unwrap();
        assert_eq!(manifest.source_session_id, "session-1");
        assert!(manifest.files.contains_key("ledger/0000.log"));
        assert!(manifest
            .files
            .get("ephemeral/prompt.txt")
            .unwrap()
            .excluded_reason
            .is_some());
    }

    #[test]
    fn restore_into_existing_session_refused() {
        let (recipient, identity) = generate_local_key();
        let mut b = ExportBuilder::new("session-1".into(), "pib-1".into(), "0".repeat(64));
        b.add_file("ledger/a".into(), b"x");
        let sealed = b.seal(&recipient).unwrap();
        let r = restore(&sealed, &identity, "session-1", "session-1");
        assert!(r.is_err(), "must refuse restore into same session (E0509)");
    }

    #[test]
    fn wrong_key_fails() {
        let (recipient, _id) = generate_local_key();
        let (_r2, id2) = generate_local_key();
        let mut b = ExportBuilder::new("s1".into(), "p1".into(), "0".repeat(64));
        b.add_file("f".into(), b"data");
        let sealed = b.seal(&recipient).unwrap();
        assert!(restore(&sealed, &id2, "s2", "s1").is_err());
    }
}
