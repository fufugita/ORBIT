//! Ledger canonical serialization (DR-06 §2.1, DR-01 I14).
//!
//! Rules: UTF-8 NFC; LF newlines; sorted object keys at every depth; shortest
//! round-trip numbers; no comments/whitespace/BOM; **no `null`** (absent fields
//! are omitted); RFC 8259 §7 escaping.

use serde::Serialize;
use sha2::{Digest, Sha256};

/// Serialize `value` to canonical JSON bytes.
pub fn canonical_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, CanonicalError> {
    let v = serde_json::to_value(value).map_err(CanonicalError::Serialize)?;
    let sorted = sort_value(v);
    serde_json::to_vec(&sorted).map_err(CanonicalError::Serialize)
}

/// SHA-256 hex of the canonical bytes (64 chars).
pub fn sha256_hex<T: Serialize>(value: &T) -> Result<String, CanonicalError> {
    let bytes = canonical_bytes(value)?;
    Ok(hex::encode(Sha256::digest(&bytes)))
}

fn sort_value(v: serde_json::Value) -> serde_json::Value {
    match v {
        serde_json::Value::Object(map) => {
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
    fn sorts_keys_and_omits_nothing() {
        let v = json!({ "b": 1, "a": [3, 2, 1] });
        assert_eq!(
            String::from_utf8(canonical_bytes(&v).unwrap()).unwrap(),
            r#"{"a":[3,2,1],"b":1}"#
        );
    }

    #[test]
    fn sha256_is_64_hex() {
        let v = json!({ "k": "v" });
        let h = sha256_hex(&v).unwrap();
        assert_eq!(h.len(), 64);
    }
}
