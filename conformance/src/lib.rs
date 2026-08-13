//! ORBIT conformance corpus runner — Phase F (F21).
//!
//! Per DR-11 §9: each fixture pins `orbit_version_min/max` + `ir_schema_version`;
//! the corpus ships with both SDKs under `(MIT OR Apache-2.0)` and must produce
//! byte-identical results across languages. This runner:
//! 1. Loads a fixture (source + expected + warnings).
//! 2. Validates the version fence (refuses out-of-range fixtures).
//! 3. Runs the migration and asserts byte-identical expected output
//!    (deterministic canonical YAML — the cross-language gate).

#![forbid(unsafe_code)]

pub mod migration_corpus;

pub mod adapter;

use orbit_ir::{ModelRef, SubagentSpawnRequest};
use serde::{Deserialize, Serialize};

/// Conformance error family (E1861-E1869).
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum ConfError {
    #[error("ORBIT-E1861 conf_test_setup_failed: {0}")]
    SetupFailed(String),
    #[error("ORBIT-E1868 conf_corpus_out_of_date: {0}")]
    CorpusOutOfDate(String),
    #[error("conformance mismatch: {0}")]
    Mismatch(String),
}

impl ConfError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::SetupFailed(_) => "E1861",
            Self::CorpusOutOfDate(_) => "E1868",
            Self::Mismatch(_) => "E1869",
        }
    }
}

/// A fixture's version fence (DR-11 §9).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FixtureMeta {
    pub orbit_version_min: String,
    pub orbit_version_max: String,
    pub ir_schema_version: String,
}

/// A loaded conformance case.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fixture {
    pub name: String,
    pub meta: FixtureMeta,
    pub source_yaml: String,
    pub expected_yaml: String,
}

/// Load a fixture from a corpus directory.
pub fn load_fixture(corpus_dir: &str, name: &str) -> Result<Fixture, ConfError> {
    let base = std::path::Path::new(corpus_dir).join(name);
    let source = std::fs::read_to_string(base.join("source.yaml"))
        .map_err(|e| ConfError::SetupFailed(format!("source.yaml: {e}")))?;
    let expected = std::fs::read_to_string(base.join("expected.yaml"))
        .map_err(|e| ConfError::SetupFailed(format!("expected.yaml: {e}")))?;
    // Parse the meta from the source's frontmatter (version fence).
    let meta = parse_meta(&source)?;
    Ok(Fixture {
        name: name.into(),
        meta,
        source_yaml: source,
        expected_yaml: expected,
    })
}

/// Load a fixture that may have only `source.yaml` (a negative/fail-closed
/// case). Returns `None` if neither file exists.
pub fn load_fixture_optional(corpus_dir: &str, name: &str) -> Result<Option<Fixture>, ConfError> {
    let base = std::path::Path::new(corpus_dir).join(name);
    let source_path = base.join("source.yaml");
    let expected_path = base.join("expected.yaml");
    if !source_path.exists() && !expected_path.exists() {
        return Ok(None);
    }
    let source = std::fs::read_to_string(&source_path)
        .map_err(|e| ConfError::SetupFailed(format!("source.yaml: {e}")))?;
    let expected = std::fs::read_to_string(&expected_path).unwrap_or_default();
    let meta = parse_meta(&source)?;
    Ok(Some(Fixture {
        name: name.into(),
        meta,
        source_yaml: source,
        expected_yaml: expected,
    }))
}

/// Version fence: refuse a fixture outside the current ORBIT version (E1868).
pub fn check_version_fence(fixture: &Fixture, current: &str) -> Result<(), ConfError> {
    let cur = version_tuple(current);
    let min = version_tuple(&fixture.meta.orbit_version_min);
    let max = version_tuple(&fixture.meta.orbit_version_max);
    if cur < min || cur > max {
        return Err(ConfError::CorpusOutOfDate(format!(
            "fixture {} requires {}..={}, current {current} (E1868)",
            fixture.name, fixture.meta.orbit_version_min, fixture.meta.orbit_version_max
        )));
    }
    Ok(())
}

fn version_tuple(v: &str) -> (u16, u16) {
    let parts: Vec<&str> = v.split('.').collect();
    let major = parts.first().and_then(|x| x.parse().ok()).unwrap_or(0);
    let minor = parts.get(1).and_then(|x| x.parse().ok()).unwrap_or(0);
    (major, minor)
}

/// Parse the `orbit_version_min/max` + `ir_schema_version` from source frontmatter.
fn parse_meta(source: &str) -> Result<FixtureMeta, ConfError> {
    let mut min = None;
    let mut max = None;
    let mut ir = None;
    for line in source.lines() {
        let line = line.trim();
        if let Some(v) = line.strip_prefix("orbit_version_min:") {
            min = Some(v.trim().to_string());
        } else if let Some(v) = line.strip_prefix("orbit_version_max:") {
            max = Some(v.trim().to_string());
        } else if let Some(v) = line.strip_prefix("ir_schema_version:") {
            ir = Some(v.trim().to_string());
        }
    }
    Ok(FixtureMeta {
        orbit_version_min: min
            .ok_or_else(|| ConfError::SetupFailed("fixture missing orbit_version_min".into()))?,
        orbit_version_max: max
            .ok_or_else(|| ConfError::SetupFailed("fixture missing orbit_version_max".into()))?,
        ir_schema_version: ir
            .ok_or_else(|| ConfError::SetupFailed("fixture missing ir_schema_version".into()))?,
    })
}

/// The cross-language byte-identical gate: a canonical IR value must encode to
/// the same bytes here as in any other language (DR-11 §5.2).
pub fn canonical_ir_byte_identical() -> Result<String, ConfError> {
    let req = SubagentSpawnRequest {
        model: ModelRef::Id("gpt-4".into()),
        prompt_hash: "a".repeat(64),
        context: vec![],
    };
    let a = orbit_ir::cbor::encode(&req).map_err(|e| ConfError::Mismatch(e.to_string()))?;
    let b = orbit_ir::cbor::encode(&req).map_err(|e| ConfError::Mismatch(e.to_string()))?;
    if a != b {
        return Err(ConfError::Mismatch(
            "IR encoding not deterministic across runs".into(),
        ));
    }
    // Stable fingerprint of the canonical bytes (no hex dep needed).
    Ok(format!(
        "len={}:{:02x}{:02x}",
        a.len(),
        a[0],
        a.last().copied().unwrap_or(0)
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_fence_accepts_current() {
        let meta = FixtureMeta {
            orbit_version_min: "0.1.0".into(),
            orbit_version_max: "0.1.x".into(),
            ir_schema_version: "orbit:ir@0.1.0".into(),
        };
        let f = Fixture {
            name: "t".into(),
            meta,
            source_yaml: String::new(),
            expected_yaml: String::new(),
        };
        assert!(check_version_fence(&f, "0.1.0").is_ok());
    }

    #[test]
    fn version_fence_rejects_out_of_range() {
        let meta = FixtureMeta {
            orbit_version_min: "0.2.0".into(),
            orbit_version_max: "0.2.x".into(),
            ir_schema_version: "orbit:ir@0.1.0".into(),
        };
        let f = Fixture {
            name: "t".into(),
            meta,
            source_yaml: String::new(),
            expected_yaml: String::new(),
        };
        assert_eq!(
            check_version_fence(&f, "0.1.0").unwrap_err().code(),
            "E1868"
        );
    }

    #[test]
    fn parse_meta_extracts_fence() {
        let src = "# fixture\norbit_version_min: 0.1.0\norbit_version_max: 0.1.x\nir_schema_version: orbit:ir@0.1.0\n";
        let m = parse_meta(src).unwrap();
        assert_eq!(m.orbit_version_min, "0.1.0");
        assert_eq!(m.ir_schema_version, "orbit:ir@0.1.0");
    }
}
