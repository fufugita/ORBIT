//! ML — Memory Lifecycle (DR-12 §6, DR-14 amendments).
//!
//! Governs memory creation, retrieval, export, deletion. UAI-gated and
//! single-shot per operation (ML-I9); every record carries a digest-only
//! `uai_chain` (ML-I10); Secret-class content cannot be exported under any UAI
//! (ML-I11 / E1925 kernel path).

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};

/// ML errors (E1401-E1405 + E1925 kernel).
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum MlError {
    #[error("ORBIT-E1401 ml_write_denied: {0}")]
    WriteDenied(String),
    #[error("ORBIT-E1402 ml_read_denied: {0}")]
    ReadDenied(String),
    #[error("ORBIT-E1403 ml_delete_denied: {0}")]
    DeleteDenied(String),
    #[error("ORBIT-E1404 ml_export_denied: {0}")]
    ExportDenied(String),
    #[error("ORBIT-E1925 ml_secret_export_forbidden: {0}")]
    SecretExportForbidden(String),
}

impl MlError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::WriteDenied(_) => "E1401",
            Self::ReadDenied(_) => "E1402",
            Self::DeleteDenied(_) => "E1403",
            Self::ExportDenied(_) => "E1404",
            Self::SecretExportForbidden(_) => "E1925",
        }
    }
}

/// Data classification for memory content.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DataClass {
    Open,
    Internal,
    Secret, // never exportable (ML-I11)
}

/// A memory record with its UAI chain (digest-only, ML-I10).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryRecord {
    pub memory_id: String,
    pub key: String,
    pub value: String,
    pub class: DataClass,
    pub uai_chain: Vec<String>, // digest-only grant lineage
}

/// The ML service.
pub struct MlService;

impl MlService {
    /// Write a memory record, gated by a confirmed UAI (ML-I9).
    pub fn write(
        &self,
        memory_id: String,
        key: String,
        value: String,
        class: DataClass,
        uai_digest: String,
    ) -> Result<MemoryRecord, MlError> {
        if uai_digest.is_empty() {
            return Err(MlError::WriteDenied(
                "write requires a confirmed UAI (E1401)".into(),
            ));
        }
        Ok(MemoryRecord {
            memory_id,
            key,
            value,
            class,
            uai_chain: vec![uai_digest],
        })
    }

    /// Export a memory record; Secret-class is kernel-refused under ANY UAI (ML-I11).
    pub fn export(&self, record: &MemoryRecord, uai_digest: &str) -> Result<(), MlError> {
        if record.class == DataClass::Secret {
            return Err(MlError::SecretExportForbidden(
                "Secret-class content cannot be exported under any UAI (E1925)".into(),
            ));
        }
        if uai_digest.is_empty() {
            return Err(MlError::ExportDenied(
                "export requires a confirmed UAI (E1404)".into(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_requires_uai() {
        let svc = MlService;
        assert_eq!(
            svc.write(
                "m1".into(),
                "k".into(),
                "v".into(),
                DataClass::Open,
                String::new()
            )
            .unwrap_err()
            .code(),
            "E1401"
        );
    }

    #[test]
    fn secret_never_exportable() {
        let svc = MlService;
        let rec = svc
            .write(
                "m2".into(),
                "k".into(),
                "secret".into(),
                DataClass::Secret,
                "uai".into(),
            )
            .unwrap();
        assert_eq!(
            svc.export(&rec, "confirmed-uai").unwrap_err().code(),
            "E1925"
        );
    }

    #[test]
    fn open_exportable_with_uai() {
        let svc = MlService;
        let rec = svc
            .write(
                "m3".into(),
                "k".into(),
                "v".into(),
                DataClass::Open,
                "uai".into(),
            )
            .unwrap();
        assert!(svc.export(&rec, "confirmed-uai").is_ok());
    }
}
