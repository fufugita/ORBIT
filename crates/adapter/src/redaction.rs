//! Redaction catalog — DR-09 §7, GW-16.
//!
//! Redaction happens **before** formatting, persistence, hashing diagnostics,
//! logs, telemetry, crash reports, or Ledger events. Only category + count +
//! the redaction catalog version digest are returned — never the matched bytes.
//!
//! v0.1 intentionally avoids a regex dependency. The catalog is a closed
//! case-insensitive header/name/query key list + a secret-byte exact-match
//! scrubber. This is more predictable than hand-rolled regexes and satisfies
//! the fixed corpus in `tests/src/adapter.rs`.

use sha2::{Digest, Sha256};

pub const REDACTION_CATALOG_VERSION: &str = "orbit.redaction/v1";

/// What was redacted. Safe to persist — no byte values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RedactionCategory {
    AuthorizationHeader,
    CookieHeader,
    ApiKeyHeader,
    ProxyHeader,
    SignedQuery,
    SecretBytes,
}

/// Safe redaction evidence (category + count + catalog digest only).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedactionEvidence {
    pub category: RedactionCategory,
    pub count: u64,
    pub catalog_digest: String,
}

/// Header/query names that are always redacted before any sink.
const SENSITIVE_NAMES: &[(&str, RedactionCategory)] = &[
    ("authorization", RedactionCategory::AuthorizationHeader),
    ("proxy-authorization", RedactionCategory::ProxyHeader),
    ("cookie", RedactionCategory::CookieHeader),
    ("set-cookie", RedactionCategory::CookieHeader),
    ("x-api-key", RedactionCategory::ApiKeyHeader),
    ("api-key", RedactionCategory::ApiKeyHeader),
    ("x-goog-api-key", RedactionCategory::ApiKeyHeader),
    ("x-amz-signature", RedactionCategory::SignedQuery),
    ("sig", RedactionCategory::SignedQuery),
    ("signature", RedactionCategory::SignedQuery),
    ("token", RedactionCategory::SignedQuery),
    ("access_token", RedactionCategory::SignedQuery),
];

pub fn catalog_digest() -> String {
    let mut h = Sha256::new();
    h.update(REDACTION_CATALOG_VERSION.as_bytes());
    for (name, cat) in SENSITIVE_NAMES {
        h.update(name.as_bytes());
        h.update(format!("{cat:?}").as_bytes());
    }
    hex::encode(h.finalize())
}

/// Classify a header/query name as sensitive. Case-insensitive.
pub fn classify_sensitive_name(name: &str) -> Option<RedactionCategory> {
    let lower = name.trim().to_ascii_lowercase();
    SENSITIVE_NAMES
        .iter()
        .find(|(n, _)| *n == lower)
        .map(|(_, c)| *c)
}

/// Redact a `(name, value)` pair. The value is NEVER returned for sensitive
/// names. Evidence contains category + count + catalog digest only.
pub fn redact_pair(name: &str, value: &[u8]) -> (Vec<u8>, Option<RedactionEvidence>) {
    if let Some(category) = classify_sensitive_name(name) {
        return (
            b"[REDACTED]".to_vec(),
            Some(RedactionEvidence {
                category,
                count: if value.is_empty() { 0 } else { 1 },
                catalog_digest: catalog_digest(),
            }),
        );
    }
    (value.to_vec(), None)
}

/// Scrub an exact secret byte sequence from a diagnostic body before it
/// reaches any formatter/sink. Returns safe bytes + category/count/digest.
pub fn scrub_secret_bytes(
    diagnostic: &[u8],
    secret: &[u8],
) -> (Vec<u8>, Option<RedactionEvidence>) {
    if secret.is_empty() {
        return (diagnostic.to_vec(), None);
    }
    // P1-5 fix: bound the output. A small secret matching many bytes expands
    // the output ("[REDACTED]" is 10 bytes) — without a cap a hostile
    // diagnostic could OOM the process. Truncate at SCRUB_OUTPUT_CAP and
    // append a truncation marker so callers know the output was bounded.
    const SCRUB_OUTPUT_CAP: usize = 1 << 20; // 1 MiB
    let mut out = Vec::with_capacity(diagnostic.len().min(SCRUB_OUTPUT_CAP));
    let mut off = 0usize;
    let mut count = 0u64;
    let mut truncated = false;
    while off < diagnostic.len() {
        if off + secret.len() <= diagnostic.len() && &diagnostic[off..off + secret.len()] == secret
        {
            if out.len() + 10 > SCRUB_OUTPUT_CAP {
                truncated = true;
                break;
            }
            out.extend_from_slice(b"[REDACTED]");
            off += secret.len();
            count += 1;
        } else {
            if out.len() + 1 > SCRUB_OUTPUT_CAP {
                truncated = true;
                break;
            }
            out.push(diagnostic[off]);
            off += 1;
        }
    }
    if truncated {
        out.extend_from_slice(b"...[TRUNCATED]");
    }
    let evidence = if count > 0 {
        Some(RedactionEvidence {
            category: RedactionCategory::SecretBytes,
            count,
            catalog_digest: catalog_digest(),
        })
    } else {
        None
    };
    (out, evidence)
}
