//! Canonical serialization for authority signing/digesting (NEW P1 #2 fix).
//!
//! `serde_json` output is NOT guaranteed sorted for `serde_json::Value`
//! objects — a scope field inside a signed struct could serialize in
//! different key order on different runs, silently breaking signatures or
//! admitting forged digests. This sorted-key serializer is the ONLY form
//! used for `compute_digest` and policy signing/verification.

use serde::Serialize;

/// Serialize to canonical JSON bytes (sorted keys at every depth).
pub fn canonical_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, serde_json::Error> {
    let v = serde_json::to_value(value)?;
    serde_json::to_vec(&sort_value(v))
}

/// Serialize to canonical JSON string (sorted keys).
pub fn canonical_string<T: Serialize>(value: &T) -> Result<String, serde_json::Error> {
    Ok(String::from_utf8(canonical_bytes(value)?).unwrap_or_default())
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
        let v1 = serde_json::json!({ "b": 1, "a": { "y": 2, "x": 3 } });
        let v2 = serde_json::json!({ "a": { "x": 3, "y": 2 }, "b": 1 });
        assert_eq!(canonical_bytes(&v1).unwrap(), canonical_bytes(&v2).unwrap());
    }
}
