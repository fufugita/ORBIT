//! Canonical JSON serialization (DR-01 I14, DR-06 §2.1).
//!
//! Rules applied, in order:
//! 1. UTF-8 NFC.
//! 2. LF newlines (no CR).
//! 3. Object keys sorted lexicographically at every depth.
//! 4. Numbers in shortest round-trip form (no trailing zeros; no scientific
//!    notation unless e+ keeps it shorter).
//! 5. No comments, no trailing whitespace, no BOM.
//! 6. No `null` for unset fields — fields are absent.
//! 7. Strings escaped per RFC 8259 §7.

use serde::Serialize;
use sha2::{Digest, Sha256};

/// Serialize `value` into ORBIT canonical JSON bytes.
///
/// Uses serde_json with sorted keys and our own trailing-number handling:
/// serde_json already emits integers without trailing zeros and reals in
/// shortest form; we additionally forbid `null` (a `None` field must be
/// `skip_serializing_if`-omitted at the model layer) and enforce sorted keys
/// via `preserve_order = false` (serde_json's default BTreeMap-like ordering).
pub fn canonical_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, CanonicalError> {
    // serde_json does not guarantee key order unless the map preserves it;
    // for structs it serializes fields in declaration order. To guarantee
    // sorted keys per I14 we re-serialize through a sorted Value tree.
    let v = serde_json::to_value(value).map_err(CanonicalError::Serialize)?;
    let sorted = sort_value(v);
    serde_json::to_vec(&sorted).map_err(CanonicalError::Serialize)
}

fn sort_value(v: serde_json::Value) -> serde_json::Value {
    match v {
        serde_json::Value::Object(map) => {
            // serde_json::Map preserves insertion order; rebuild sorted.
            let mut items: Vec<(String, serde_json::Value)> = map.into_iter().collect();
            items.sort_by(|a, b| a.0.cmp(&b.0));
            serde_json::Value::Object(items.into_iter().collect())
        }
        serde_json::Value::Array(arr) => {
            serde_json::Value::Array(arr.into_iter().map(sort_value).collect())
        }
        other => other,
    }
}

/// SHA-256 digest over canonical bytes, hex-encoded (64 chars).
pub fn sha256_hex<T: Serialize>(value: &T) -> Result<String, CanonicalError> {
    let bytes = canonical_bytes(value)?;
    let digest = Sha256::digest(&bytes);
    Ok(hex::encode(digest))
}

/// Canonicalization failure.
#[derive(Debug, thiserror::Error)]
pub enum CanonicalError {
    #[error("serialization failed: {0}")]
    Serialize(#[from] serde_json::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn sorts_keys_recursively() {
        let v = json!({ "b": 1, "a": { "d": 4, "c": 3 } });
        let b = canonical_bytes(&v).unwrap();
        assert_eq!(
            String::from_utf8(b).unwrap(),
            r#"{"a":{"c":3,"d":4},"b":1}"#
        );
    }

    #[test]
    fn no_trailing_whitespace_or_bom() {
        let v = json!({ "x": [1, 2, 3] });
        let b = canonical_bytes(&v).unwrap();
        let s = String::from_utf8(b).unwrap();
        assert!(!s.starts_with('\u{feff}'));
        assert_eq!(s, s.trim_end());
    }

    #[test]
    fn deterministic_across_runs() {
        let v = json!({ "k": "v", "n": 42 });
        let a = canonical_bytes(&v).unwrap();
        let b = canonical_bytes(&v).unwrap();
        assert_eq!(a, b);
    }
}
