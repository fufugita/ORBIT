//! ORBIT egress broker — Phase B (B6).
//!
//! Strict ordering per DR-09 GW-04 / DR-06 §6.4 (S7):
//!   parse destination tuple → capability allowlist → trust-root route pin →
//!   lifecycle check → EgressEvent fsync ACK → DNS (pinned resolvers) →
//!   TLS (SPKI pinned) → payload.
//!
//! No `connect(2)` may dispatch until the broker has fsync'd the authorizing
//! EgressEvent (DR-07 S6/S7). seccomp never filters destinations (S4) — the
//! broker is the only destination authority.

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Egress error family (E0301, E0302, E0307, E0310; DR-06/DR-09).
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum EgressError {
    /// ORBIT-E0301 egress_intent_append_failed
    #[error("ORBIT-E0301 egress_intent_append_failed: {0}")]
    IntentAppendFailed(String),
    /// ORBIT-E0302 egress_intent_durability_ambiguous
    #[error("ORBIT-E0302 egress_intent_durability_ambiguous: {0}")]
    DurabilityAmbiguous(String),
    /// ORBIT-E0307 egress_denied
    #[error("ORBIT-E0307 egress_denied: {0}")]
    EgressDenied(String),
    /// ORBIT-E0310 egress_tls_mismatch
    #[error("ORBIT-E0310 egress_tls_mismatch: {0}")]
    TlsMismatch(String),
}

impl EgressError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::IntentAppendFailed(_) => "E0301",
            Self::DurabilityAmbiguous(_) => "E0302",
            Self::EgressDenied(_) => "E0307",
            Self::TlsMismatch(_) => "E0310",
        }
    }
}

/// A destination tuple (DR-01 I16).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EgressTuple {
    pub scheme: String,
    pub host: String,
    pub port: u16,
    pub path_prefix: String,
    pub provider_id: String,
    pub region_id: String,
}

impl EgressTuple {
    /// EgressDigest = SHA256(canonical_destinations_sorted) (DR-01 I16).
    pub fn digest(&self) -> String {
        let canonical = format!(
            "{}|{}|{}|{}|{}|{}",
            self.scheme, self.host, self.port, self.path_prefix, self.provider_id, self.region_id
        );
        hex::encode(Sha256::digest(canonical.as_bytes()))
    }
}

/// The capability-card-driven allowlist (DR-07 S6: card is the source of truth).
#[derive(Debug, Clone, Default)]
pub struct EgressAllowlist {
    allowed: Vec<EgressTuple>,
}

impl EgressAllowlist {
    pub fn new(allowed: Vec<EgressTuple>) -> Self {
        Self { allowed }
    }

    /// Deny-by-default: a tuple is allowed only if present in the allowlist.
    /// P1-6 fix: a path prefix must match at a PATH BOUNDARY (`/v1` matches
    /// `/v1/...` and `/v1` exactly, but NOT `/v1admin`) — no prefix-confusion.
    pub fn contains(&self, t: &EgressTuple) -> bool {
        self.allowed.iter().any(|a| {
            a.scheme == t.scheme
                && a.host == t.host
                && a.port == t.port
                && path_prefix_matches(&a.path_prefix, &t.path_prefix)
                && a.provider_id == t.provider_id
                && a.region_id == t.region_id
        })
    }
}

/// A path-prefix match at a boundary: the allowlist prefix is empty (matches
/// all), an exact match, or the target starts with the prefix followed by `/`.
fn path_prefix_matches(allow_prefix: &str, target: &str) -> bool {
    if allow_prefix.is_empty() {
        return true;
    }
    if target == allow_prefix {
        return true;
    }
    target.starts_with(allow_prefix) && target[allow_prefix.len()..].starts_with('/')
}

/// A TLS SPKI pin (SHA-256 of SubjectPublicKeyInfo) per (provider, region).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpkiPin {
    pub provider_id: String,
    pub region_id: String,
    pub spki_sha256: String,
}

/// The broker decision for a single destination.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BrokerDecision {
    Allowed,
    Denied { reason: String },
}

/// The EgressEvent written to the Ledger (DR-06 §6.4 / DR-07 §8.3 broker schema).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EgressEvent {
    pub decision_id: String,
    pub destination_digest: String,
    pub decision: BrokerDecision,
    pub policy_snapshot_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub egress_category: Option<String>,
}

/// Result of a broker decision including the event that must be fsync'd.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrokerVerdict {
    pub event: EgressEvent,
    pub allowed: bool,
}

/// The egress broker state machine: capability → policy → lifecycle → event.
pub struct EgressBroker {
    allowlist: EgressAllowlist,
    policy_snapshot_id: String,
    trusted_routes: Vec<EgressTuple>, // trust-root pinned route table
    spki_pins: Vec<SpkiPin>,
}

impl EgressBroker {
    pub fn new(
        allowlist: EgressAllowlist,
        policy_snapshot_id: String,
        trusted_routes: Vec<EgressTuple>,
        spki_pins: Vec<SpkiPin>,
    ) -> Self {
        Self {
            allowlist,
            policy_snapshot_id,
            trusted_routes,
            spki_pins,
        }
    }

    /// Evaluate a destination against allowlist + trust-root routes.
    /// Produces the EgressEvent that MUST be fsync'd before any connect (S7).
    pub fn evaluate(&self, destination: &EgressTuple, decision_id: &str) -> BrokerVerdict {
        let digest = destination.digest();
        if !self.allowlist.contains(destination) {
            return BrokerVerdict {
                event: EgressEvent {
                    decision_id: decision_id.into(),
                    destination_digest: digest,
                    decision: BrokerDecision::Denied {
                        reason: "not in capability-card egress_allowlist (E0307)".into(),
                    },
                    policy_snapshot_id: self.policy_snapshot_id.clone(),
                    egress_category: None,
                },
                allowed: false,
            };
        }
        let route_ok = self.trusted_routes.iter().any(|r| {
            r.provider_id == destination.provider_id && r.region_id == destination.region_id
        });
        if !route_ok {
            return BrokerVerdict {
                event: EgressEvent {
                    decision_id: decision_id.into(),
                    destination_digest: digest,
                    decision: BrokerDecision::Denied {
                        reason: "provider/region not pinned in trust-root routes (E0307)".into(),
                    },
                    policy_snapshot_id: self.policy_snapshot_id.clone(),
                    egress_category: None,
                },
                allowed: false,
            };
        }
        BrokerVerdict {
            event: EgressEvent {
                decision_id: decision_id.into(),
                destination_digest: digest,
                decision: BrokerDecision::Allowed,
                policy_snapshot_id: self.policy_snapshot_id.clone(),
                egress_category: Some("model_inference".into()),
            },
            allowed: true,
        }
    }

    /// Validate the SPKI pin for a (provider, region) before TLS (E0310 on mismatch).
    pub fn check_spki_pin(
        &self,
        provider: &str,
        region: &str,
        spki_sha256: &str,
    ) -> Result<(), EgressError> {
        let pin = self
            .spki_pins
            .iter()
            .find(|p| p.provider_id == provider && p.region_id == region)
            .ok_or_else(|| {
                EgressError::TlsMismatch(format!("no SPKI pin for {provider}/{region}"))
            })?;
        if pin.spki_sha256 == spki_sha256 {
            Ok(())
        } else {
            Err(EgressError::TlsMismatch(format!(
                "SPKI mismatch for {provider}/{region} (E0310)"
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tuple(host: &str) -> EgressTuple {
        EgressTuple {
            scheme: "https".into(),
            host: host.into(),
            port: 443,
            path_prefix: "/v1/".into(),
            provider_id: "openai".into(),
            region_id: "us-east-1".into(),
        }
    }

    #[test]
    fn digest_is_stable() {
        let a = tuple("api.openai.com");
        let b = tuple("api.openai.com");
        assert_eq!(a.digest(), b.digest());
        assert_eq!(a.digest().len(), 64);
    }

    #[test]
    fn deny_by_default() {
        let broker = EgressBroker::new(EgressAllowlist::new(vec![]), "pol".into(), vec![], vec![]);
        let v = broker.evaluate(&tuple("api.openai.com"), "d1");
        assert!(!v.allowed);
        assert!(matches!(v.event.decision, BrokerDecision::Denied { .. }));
    }

    #[test]
    fn allow_when_in_allowlist_and_routes() {
        let t = tuple("api.openai.com");
        let broker = EgressBroker::new(
            EgressAllowlist::new(vec![t.clone()]),
            "pol".into(),
            vec![t.clone()],
            vec![],
        );
        let v = broker.evaluate(&t, "d2");
        assert!(v.allowed);
        assert_eq!(v.event.decision, BrokerDecision::Allowed);
    }

    #[test]
    fn allowlist_but_no_route_denied() {
        let t = tuple("api.openai.com");
        let broker = EgressBroker::new(
            EgressAllowlist::new(vec![t.clone()]),
            "pol".into(),
            vec![],
            vec![],
        );
        let v = broker.evaluate(&t, "d3");
        assert!(
            !v.allowed,
            "allowlist alone is insufficient; route pin required"
        );
    }

    #[test]
    fn spki_pin_mismatch_e0310() {
        let broker = EgressBroker::new(
            EgressAllowlist::new(vec![]),
            "pol".into(),
            vec![],
            vec![SpkiPin {
                provider_id: "openai".into(),
                region_id: "us-east-1".into(),
                spki_sha256: "expected".into(),
            }],
        );
        assert!(broker
            .check_spki_pin("openai", "us-east-1", "expected")
            .is_ok());
        assert_eq!(
            broker
                .check_spki_pin("openai", "us-east-1", "wrong")
                .unwrap_err()
                .code(),
            "E0310"
        );
    }

    #[test]
    fn path_prefix_matches_at_boundary_not_prefix_confusion() {
        // P1-6: `/v1` must match `/v1` and `/v1/chat` but NOT `/v1admin`.
        assert!(path_prefix_matches("/v1", "/v1"));
        assert!(path_prefix_matches("/v1", "/v1/chat"));
        assert!(!path_prefix_matches("/v1", "/v1admin"));
        assert!(!path_prefix_matches("/v1", "/v12"));
        assert!(path_prefix_matches("", "/anything"));
    }
}
