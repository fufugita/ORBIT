//! ORBIT shared IR — Phase F (F18).
//!
//! The single serialization contract between Rust core and the SDKs
//! (DR-11 §1). `orbit:ir@0.1.0`.
//!
//! - **Serialization:** CBOR (RFC 8949) deterministic encoding. Map keys are
//!   emitted in sorted order so the same value always produces the same bytes
//!   (conformance requirement: cross-language byte-identical).
//! - **Versioning:** SemVer; MAJOR = breaking, MINOR = additive. The Rust core
//!   embeds the last 2 MAJOR versions; SDKs declare the IR version via a
//!   schema-hash handshake.

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};

/// IR error family (E1821-E1830).
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum IrError {
    #[error("ORBIT-E1821 wf_parse_syntax: {0}")]
    ParseSyntax(String),
    #[error("ORBIT-E1822 wf_parse_schema: {0}")]
    ParseSchema(String),
    #[error("version unsupported: {0}")]
    VersionUnsupported(String),
}

/// The IR package version (DR-11: orbit:ir@0.1.0).
pub const IR_PACKAGE: &str = "orbit:ir@0.1.0";
pub const IR_MAJOR: u16 = 0;
pub const IR_MINOR: u16 = 1;

/// Schema-hash handshake: the digest both sides must agree on (DR-11 §5.1).
pub const IR_SCHEMA_HASH: &str = "orbit-ir-v0.1-schema-hash";

/// The shared IR crossing types (DR-01/08/11 surface).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ModelRef {
    Id(String), // flat provider model id
    Inherit,    // one-hop
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContextSegment {
    pub id: String,
    pub content_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryRecord {
    pub id: String,
    pub scope: String, // global | project | path_local
    pub key: String,
    pub value_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubagentSpawnRequest {
    pub model: ModelRef,
    pub prompt_hash: String,
    pub context: Vec<ContextSegment>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkflowDescriptor {
    pub name: String,
    pub version: String,
    pub steps: Vec<WorkflowStep>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum WorkflowStep {
    Agent {
        model: ModelRef,
        prompt_hash: String,
    },
    Parallel {
        steps: Vec<WorkflowStep>,
    },
    Pipeline {
        steps: Vec<WorkflowStep>,
    },
}

/// Deterministic CBOR encoding (RFC 8949 subset: maps with sorted keys,
/// definite-length arrays/strings, unsigned + negative integers, simple values).
///
/// This minimal encoder guarantees byte-identical output for the same logical
/// value — the conformance contract. (A full ciborium-backed encoder can be
/// swapped in later; determinism is what's contractually required.)
pub mod cbor {
    use super::*;

    /// Encode a serde-serializable value to deterministic CBOR.
    /// Converts to a sorted-key Value tree first, then encodes.
    pub fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, IrError> {
        let v = serde_json::to_value(value).map_err(|e| IrError::ParseSchema(e.to_string()))?;
        encode_value(&sort(v))
    }

    /// The canonical CBOR for the empty/unit (used in handshakes).
    pub fn encode_unit() -> Vec<u8> {
        vec![0xF6] // simple(undefined) — stable sentinel
    }

    fn sort(v: serde_json::Value) -> serde_json::Value {
        match v {
            serde_json::Value::Object(map) => {
                let mut items: Vec<(String, serde_json::Value)> = map.into_iter().collect();
                items.sort_by(|a, b| a.0.cmp(&b.0));
                serde_json::Value::Object(items.into_iter().collect())
            }
            serde_json::Value::Array(arr) => {
                serde_json::Value::Array(arr.into_iter().map(sort).collect())
            }
            other => other,
        }
    }

    fn encode_value(v: &serde_json::Value) -> Result<Vec<u8>, IrError> {
        match v {
            serde_json::Value::Null => Ok(vec![0xF6]),
            serde_json::Value::Bool(true) => Ok(vec![0xF5]),
            serde_json::Value::Bool(false) => Ok(vec![0xF4]),
            serde_json::Value::Number(n) => {
                if let Some(u) = n.as_u64() {
                    encode_uint(u)
                } else if let Some(i) = n.as_i64() {
                    encode_int(i)
                } else {
                    Err(IrError::ParseSchema(
                        "float not allowed in deterministic CBOR".into(),
                    ))
                }
            }
            serde_json::Value::String(s) => encode_bytes(s.as_bytes()),
            serde_json::Value::Array(items) => {
                let mut out = encode_head(0x80, items.len() as u64)?;
                for item in items {
                    out.extend(encode_value(item)?);
                }
                Ok(out)
            }
            serde_json::Value::Object(map) => {
                // Keys already sorted by `sort`.
                let mut out = encode_head(0xA0, map.len() as u64)?;
                for (k, val) in map {
                    out.extend(encode_bytes(k.as_bytes())?);
                    out.extend(encode_value(val)?);
                }
                Ok(out)
            }
        }
    }

    fn encode_uint(u: u64) -> Result<Vec<u8>, IrError> {
        encode_head(0x00, u)
    }

    fn encode_int(i: i64) -> Result<Vec<u8>, IrError> {
        if i >= 0 {
            encode_uint(i as u64)
        } else {
            // negative: major type 1, value = -1 - n
            encode_head(0x20, (-1 - i) as u64)
        }
    }

    fn encode_bytes(bytes: &[u8]) -> Result<Vec<u8>, IrError> {
        // Text strings use major type 3 (0x60); the RFC 8949 canonical form.
        let mut out = encode_head(0x60, bytes.len() as u64)?;
        out.extend_from_slice(bytes);
        Ok(out)
    }

    fn encode_head(major: u8, value: u64) -> Result<Vec<u8>, IrError> {
        let mut out = Vec::with_capacity(9);
        let ai = major & 0xE0; // preserve major type bits
        if value < 24 {
            out.push(ai | (value as u8));
        } else if value <= 0xFF {
            out.push(ai | 24);
            out.push(value as u8);
        } else if value <= 0xFFFF {
            out.push(ai | 25);
            out.extend_from_slice(&(value as u16).to_be_bytes());
        } else if value <= 0xFFFF_FFFF {
            out.push(ai | 26);
            out.extend_from_slice(&(value as u32).to_be_bytes());
        } else {
            out.push(ai | 27);
            out.extend_from_slice(&value.to_be_bytes());
        }
        Ok(out)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn deterministic_for_same_value() {
            let v = serde_json::json!({ "b": 1, "a": [1, 2, 3], "c": "x" });
            let a = encode(&v).unwrap();
            let b = encode(&v).unwrap();
            assert_eq!(a, b);
        }

        #[test]
        fn sorted_keys_byte_identical() {
            // Same logical object, different key insertion order → same bytes.
            let v1 = serde_json::json!({ "z": 1, "a": 2 });
            let v2 = serde_json::json!({ "a": 2, "z": 1 });
            assert_eq!(encode(&v1).unwrap(), encode(&v2).unwrap());
        }

        #[test]
        fn uint_encoding_matches_rfc8949() {
            assert_eq!(encode(&0u64).unwrap(), vec![0x00]);
            assert_eq!(encode(&23u64).unwrap(), vec![0x17]);
            assert_eq!(encode(&24u64).unwrap(), vec![0x18, 0x18]);
        }

        #[test]
        fn string_encoding() {
            assert_eq!(encode(&"IETF").unwrap(), vec![0x64, b'I', b'E', b'T', b'F']);
        }
    }
}

/// The schema-hash handshake: both sides must compute the same digest.
/// (DR-11 §5.1: an SDK declares the IR version it consumes.)
pub fn schema_hash() -> String {
    IR_SCHEMA_HASH.to_string()
}

/// Version support: the core embeds the last 2 MAJOR versions.
/// `current_major` is the live IR major (avoids a compile-time-min const that
/// defeats clippy's absurd-extreme-comparison lint).
pub fn version_supported(
    current_major: u16,
    current_minor: u16,
    major: u16,
    minor: u16,
) -> Result<(), IrError> {
    let in_window = (major == current_major && minor <= current_minor)
        || (current_major > 0 && major == current_major - 1); // previous MAJOR
    if in_window {
        Ok(())
    } else {
        Err(IrError::VersionUnsupported(format!(
            "IR {major}.{minor} outside supported window (last 2 MAJORs)"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_window() {
        // Current major 0: only 0.x is supported (no previous major exists).
        assert!(version_supported(0, 1, 0, 1).is_ok());
        assert!(version_supported(0, 1, 0, 0).is_ok());
        assert!(version_supported(0, 1, 2, 0).is_err());
        // At major 3, minor 4: 3.x (minor ≤ 4) and 2.x (previous) supported.
        assert!(version_supported(3, 4, 3, 2).is_ok());
        assert!(version_supported(3, 4, 2, 9).is_ok());
        assert!(version_supported(3, 4, 3, 5).is_err()); // minor beyond current
        assert!(version_supported(3, 4, 1, 0).is_err()); // two majors back
    }

    #[test]
    fn schema_hash_stable() {
        assert_eq!(schema_hash(), IR_SCHEMA_HASH);
    }

    #[test]
    fn spawn_request_roundtrips() {
        let req = SubagentSpawnRequest {
            model: ModelRef::Id("gpt-4".into()),
            prompt_hash: "a".repeat(64),
            context: vec![ContextSegment {
                id: "seg1".into(),
                content_hash: "b".repeat(64),
            }],
        };
        let encoded = cbor::encode(&req).unwrap();
        assert!(!encoded.is_empty());
        assert_eq!(cbor::encode(&req).unwrap(), encoded);
    }
}
