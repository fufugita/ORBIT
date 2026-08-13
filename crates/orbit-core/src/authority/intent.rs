//! UserAuthorityIntent + authority vocabulary (DR-14 §1).

use super::error::AuthorityError;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// The authority dimensions the user may control (DR-14 §1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum AuthorityDimension {
    Models,
    Providers,
    FallbackPlan,
    Tools,
    Capabilities,
    Egress,
    SandboxStrictness,
    Context,
    Memory,
    Exports,
    Automation,
    Budget,
    Efficiency,
}

/// Authority provenance: only these three may produce a UAI (UAI-I4).
/// Everything else is NonAuthoritative and structurally cannot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthorityProvenance {
    /// Current turn, operator TTY — CAN create authority.
    UserTypedTurn,
    /// Prior turn, same session — REVOKE only.
    UserTypedPrior,
    /// Pre-signed policy file from a user-controlled store.
    ProgrammaticUserPolicy,
}

impl AuthorityProvenance {
    /// Whether this provenance may create a NEW grant (UAI-I4).
    pub fn can_grant(&self) -> bool {
        matches!(self, Self::UserTypedTurn | Self::ProgrammaticUserPolicy)
    }
}

/// The requested/effective authority scope (DR-14 §1).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorityScope {
    pub dimensions: BTreeSet<AuthorityDimension>,
    /// A subset scope spec (models/egress/etc.) — kept as a normalized map.
    pub spec: serde_json::Value,
}

/// Confirmation channel (DR-14 §1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConfirmationChannel {
    PromptInteractive,
    ConfirmCostToken,
    SignedPolicyFile,
}

/// Confirmation record (DR-14 §1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorityConfirmation {
    pub intent_digest: String,
    pub scope_digest: String,
    pub diff_hash: String,
    pub channel: ConfirmationChannel,
    pub operator: String,
}

/// The typed user authority intent — the only authority carrier (UAI-I1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserAuthorityIntent {
    pub intent_id: String,
    pub session_id: String,
    pub dimensions: BTreeSet<AuthorityDimension>,
    pub baseline: AuthorityScope,
    pub requested: AuthorityScope,
    pub provenance: AuthorityProvenance,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confirmation: Option<AuthorityConfirmation>,
    pub ttl_seconds: u64,
    pub intent_digest: String, // BLAKE3 — the ONLY thing the Ledger persists (UAI-I6)
}

impl UserAuthorityIntent {
    /// Compute the intent digest over the typed fields (UAI-I6: digest-only).
    pub fn compute_digest(&self) -> String {
        // NEW P1 #2 fix: canonical (sorted-key) serialization for EVERY
        // serialized field — a `serde_json::Value` scope must not serialize
        // in run-dependent key order (silent digest divergence).
        let mut dims: Vec<String> = self
            .dimensions
            .iter()
            .map(|d| crate::authority::canonical::canonical_string(d).unwrap_or_default())
            .collect();
        dims.sort();
        let dims_joined = dims.join(",");
        let requested =
            crate::authority::canonical::canonical_string(&self.requested).unwrap_or_default();
        let provenance =
            crate::authority::canonical::canonical_string(&self.provenance).unwrap_or_default();
        let canonical = format!(
            "{}|{}|{}|{}|{}|{}",
            self.intent_id, self.session_id, dims_joined, requested, provenance, self.ttl_seconds
        );
        blake3::hash(canonical.as_bytes()).to_hex().to_string()
    }

    /// Check provenance is user-side (UAI-I4 → E1909 on NonAuthoritative).
    pub fn check_provenance(&self) -> Result<(), AuthorityError> {
        if self.provenance.can_grant() {
            Ok(())
        } else {
            Err(AuthorityError::ProvenanceUntrusted(format!(
                "provenance {:?} cannot mint authority (E1909)",
                self.provenance
            )))
        }
    }

    /// Widening must be confirmed (UAI-I2): Pending/Denied/Expired acts as baseline.
    pub fn require_confirmed(&self) -> Result<(), AuthorityError> {
        match &self.confirmation {
            Some(_) => Ok(()),
            None => Err(AuthorityError::WideningUnconfirmed(
                "widening requires confirmation (E1906)".into(),
            )),
        }
    }
}

/// The deterministic authority directive extractor (DR-14 §1.2).
/// A typed parser over user-typed spans — NEVER an LLM.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthorityDirective {
    Grant {
        dimension: AuthorityDimension,
        scope: serde_json::Value,
    },
    Narrow {
        dimension: AuthorityDimension,
        scope: serde_json::Value,
    },
    Deny {
        dimension: AuthorityDimension,
    },
    Revoke {
        grant_id: String,
    },
}

/// A user-typed span eligible for extraction (provenance already attached).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserTypedSpan {
    pub text: String,
}

/// Parse a directive from a user-typed span using a deterministic grammar.
///
/// Recognized shapes (closed vocabulary, 1:1 to the typed flags):
/// - `grant <dimension> [<scope>]` / `allow <dimension>`
/// - `deny <dimension>`
/// - `narrow <dimension> <scope>`
/// - `revoke <grant_id>`
///
/// Unknown target → E1902; conflicting classes in one turn → E1904;
/// an authority-shaped string in non-user content is handled by the caller
/// (E1901) and never reaches this parser.
/// Parse a directive scope as JSON. Empty → Null (unrestricted). A non-empty
/// scope that is not valid JSON → E1902 (P1-2: never silently unrestricted).
fn parse_scope(scope_text: &str) -> Result<serde_json::Value, AuthorityError> {
    if scope_text.trim().is_empty() {
        return Ok(serde_json::Value::Null);
    }
    serde_json::from_str(scope_text).map_err(|_| {
        AuthorityError::DirectiveTargetUnsupported(format!(
            "malformed scope in directive: '{scope_text}' (E1902)"
        ))
    })
}

pub fn extract_directives(span: &UserTypedSpan) -> Result<Vec<AuthorityDirective>, AuthorityError> {
    let text = span.text.trim();
    let mut directives = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        let mut parts = line.split_whitespace();
        let verb = parts.next().unwrap_or("");
        let target = parts.next().unwrap_or("");
        let scope_text = parts.collect::<Vec<_>>().join(" ");

        // Only interpret the target as a dimension when the verb is actually a
        // directive verb; ordinary user lines are ignored, never errors.
        match verb {
            "grant" | "allow" => {
                let dimension = match_dimension(target)?;
                // P1-2 fix: a non-empty scope that is not valid JSON must be
                // REFUSED (E1902), never silently coerced to Null — otherwise
                // `grant models foo,bar` would become an unrestricted grant.
                let scope = parse_scope(&scope_text)?;
                directives.push(AuthorityDirective::Grant { dimension, scope })
            }
            "deny" => {
                let dimension = match_dimension(target)?;
                directives.push(AuthorityDirective::Deny { dimension })
            }
            "narrow" => {
                let dimension = match_dimension(target)?;
                let scope = parse_scope(&scope_text)?;
                directives.push(AuthorityDirective::Narrow { dimension, scope })
            }
            "revoke" => directives.push(AuthorityDirective::Revoke {
                grant_id: target.into(),
            }),
            _ => {
                // Not a directive line; ignore (only user-typed spans reach here).
            }
        }
    }
    // E1904: conflicting Grant + Deny on the same dimension.
    for d in &directives {
        if let AuthorityDirective::Grant { dimension, .. } = d {
            if directives
                .iter()
                .any(|x| matches!(x, AuthorityDirective::Deny { dimension: dd } if dd == dimension))
            {
                return Err(AuthorityError::ConflictingDirectives(format!(
                    "grant and deny on same dimension {dimension:?} (E1904)"
                )));
            }
        }
    }
    Ok(directives)
}

/// Map a dimension name to the enum (E1902 on unknown).
fn match_dimension(name: &str) -> Result<AuthorityDimension, AuthorityError> {
    match name {
        "models" | "model" => Ok(AuthorityDimension::Models),
        "providers" | "provider" => Ok(AuthorityDimension::Providers),
        "fallback" | "fallback-plan" => Ok(AuthorityDimension::FallbackPlan),
        "tools" | "tool" => Ok(AuthorityDimension::Tools),
        "capabilities" | "capability" => Ok(AuthorityDimension::Capabilities),
        "egress" | "network" => Ok(AuthorityDimension::Egress),
        "sandbox" | "sandbox-strictness" => Ok(AuthorityDimension::SandboxStrictness),
        "context" => Ok(AuthorityDimension::Context),
        "memory" => Ok(AuthorityDimension::Memory),
        "exports" | "export" => Ok(AuthorityDimension::Exports),
        "automation" | "auto" => Ok(AuthorityDimension::Automation),
        "budget" => Ok(AuthorityDimension::Budget),
        "efficiency" => Ok(AuthorityDimension::Efficiency),
        _ => Err(AuthorityError::DirectiveTargetUnsupported(format!(
            "unknown authority dimension {name} (E1902)"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provenance_grant_rules() {
        assert!(AuthorityProvenance::UserTypedTurn.can_grant());
        assert!(AuthorityProvenance::ProgrammaticUserPolicy.can_grant());
        assert!(!AuthorityProvenance::UserTypedPrior.can_grant());
    }

    #[test]
    fn extract_grant_directive() {
        let span = UserTypedSpan {
            text: "grant egress".into(),
        };
        let ds = extract_directives(&span).unwrap();
        assert!(matches!(
            ds.as_slice(),
            [AuthorityDirective::Grant {
                dimension: AuthorityDimension::Egress,
                ..
            }]
        ));
    }

    #[test]
    fn extract_conflict_denied() {
        let span = UserTypedSpan {
            text: "grant egress\ndeny egress".into(),
        };
        assert_eq!(extract_directives(&span).unwrap_err().code(), "E1904");
    }

    #[test]
    fn unknown_dimension_e1902() {
        let span = UserTypedSpan {
            text: "grant quantum-compute".into(),
        };
        assert_eq!(extract_directives(&span).unwrap_err().code(), "E1902");
    }

    #[test]
    fn intent_digest_deterministic() {
        let scope = AuthorityScope {
            dimensions: BTreeSet::from([AuthorityDimension::Egress]),
            spec: serde_json::json!({}),
        };
        let a = UserAuthorityIntent {
            intent_id: "i1".into(),
            session_id: "s1".into(),
            dimensions: BTreeSet::from([AuthorityDimension::Egress]),
            baseline: scope.clone(),
            requested: scope,
            provenance: AuthorityProvenance::UserTypedTurn,
            confirmation: None,
            ttl_seconds: 3600,
            intent_digest: String::new(),
        };
        assert_eq!(a.compute_digest(), a.compute_digest());
        assert_eq!(a.compute_digest().len(), 64); // blake3 hex
    }
}
