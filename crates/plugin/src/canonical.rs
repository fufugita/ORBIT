//! Canonical manifest serialization (P0-4 fix).
//!
//! The signed manifest bytes MUST be deterministic across serializers and
//! versions — otherwise a manifest signed with one key order fails to verify
//! with another (or passes by accident). Contract mirrors the ledger's
//! canonical form (DR-06 §2.1): UTF-8, sorted object keys at every depth,
//! no comments/whitespace, RFC 8259 escaping. This is the ONLY serializer
//! used for signing AND verification.

use serde::Serialize;

/// Serialize `value` to canonical JSON bytes (sorted keys).
pub fn canonical_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, serde_json::Error> {
    let v = serde_json::to_value(value)?;
    let sorted = sort_value(v);
    serde_json::to_vec(&sorted)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sorts_keys_regardless_of_order() {
        let v1 = serde_json::json!({ "b": 1, "a": 2 });
        let v2 = serde_json::json!({ "a": 2, "b": 1 });
        assert_eq!(canonical_bytes(&v1).unwrap(), canonical_bytes(&v2).unwrap());
    }

    #[test]
    fn nested_keys_sorted() {
        let v = serde_json::json!({ "z": { "b": 1, "a": 2 } });
        assert_eq!(
            String::from_utf8(canonical_bytes(&v).unwrap()).unwrap(),
            r#"{"z":{"a":2,"b":1}}"#
        );
    }
}
