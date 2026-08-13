//! ProgrammaticUserPolicy envelope (DR-14 §1.3).
//!
//! A programmatic policy is authority-bearing only as an authenticated envelope:
//! - Ed25519-signed canonical JSON by the operator authority key (DR-06 §6.21).
//! - Nonce single-use with a pending-hold write-ahead (crash-safe).
//! - `policy_snapshot_digest` binds to the EffectivePolicy at generation time.
//! - Time window (not_before/not_after) + Ledger revocation checked before use.
//! - Store pinned to `${ORBIT_ROOT}/policies/<principal>/` (E1946).

use super::error::AuthorityError;
use super::intent::{AuthorityDirective, AuthorityProvenance, UserAuthorityIntent};
use serde::{Deserialize, Serialize};

/// The authenticated policy envelope (DR-14 §1.3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProgrammaticUserPolicy {
    pub schema: String, // "orbit.authority-policy/v1"
    pub policy_id: String,
    pub operator_principal: String,
    pub policy_snapshot_digest: String,
    pub directives: Vec<AuthorityDirective>,
    pub not_before_ms: u64,
    pub not_after_ms: u64,
    pub nonce: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>, // hex Ed25519 over canonical envelope-minus-signature
}

/// A policy that passed all verification gates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedPolicy {
    pub policy: ProgrammaticUserPolicy,
}

/// Verifier for the policy envelope: signature, principal, time window, nonce.
pub struct PolicyVerifier {
    authority_public_key: [u8; 32],
    now_ms: u64,
    used_nonces: std::collections::HashSet<String>,
}

impl PolicyVerifier {
    pub fn new(authority_public_key: [u8; 32], now_ms: u64) -> Self {
        Self {
            authority_public_key,
            now_ms,
            used_nonces: std::collections::HashSet::new(),
        }
    }

    /// Verify + validate a policy envelope.
    pub fn verify(
        &mut self,
        policy: &ProgrammaticUserPolicy,
    ) -> Result<VerifiedPolicy, AuthorityError> {
        // Schema gate.
        if policy.schema != "orbit.authority-policy/v1" {
            return Err(AuthorityError::PolicySignatureInvalid(format!(
                "schema {}, expected orbit.authority-policy/v1 (E1943)",
                policy.schema
            )));
        }
        // Time window (E1945).
        if self.now_ms < policy.not_before_ms || self.now_ms > policy.not_after_ms {
            return Err(AuthorityError::PolicyRevoked(
                "policy outside time window (E1945)".into(),
            ));
        }
        // Nonce single-use (E1944).
        if !self.used_nonces.insert(policy.nonce.clone()) {
            return Err(AuthorityError::PolicyReplayDetected(
                "nonce already consumed (E1944)".into(),
            ));
        }
        // Signature over the envelope minus the signature field (E1943).
        let unsigned = UnsignedEnvelope {
            schema: policy.schema.clone(),
            policy_id: policy.policy_id.clone(),
            operator_principal: policy.operator_principal.clone(),
            policy_snapshot_digest: policy.policy_snapshot_digest.clone(),
            directives: policy.directives.clone(),
            not_before_ms: policy.not_before_ms,
            not_after_ms: policy.not_after_ms,
            nonce: policy.nonce.clone(),
        };
        // NEW P1 #2 fix: canonical (sorted-key) serialization — the signed
        // bytes must be deterministic across environments.
        let bytes = crate::authority::canonical::canonical_bytes(&unsigned)
            .map_err(|e| AuthorityError::PolicySignatureInvalid(e.to_string()))?;
        let sig = policy.signature.as_deref().ok_or_else(|| {
            AuthorityError::PolicySignatureInvalid("missing signature (E1943)".into())
        })?;
        let sig_bytes =
            hex::decode(sig).map_err(|e| AuthorityError::PolicySignatureInvalid(e.to_string()))?;
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};
        let pk = VerifyingKey::from_bytes(&self.authority_public_key)
            .map_err(|e| AuthorityError::PolicySignatureInvalid(e.to_string()))?;
        let sig = Signature::from_slice(&sig_bytes)
            .map_err(|e| AuthorityError::PolicySignatureInvalid(e.to_string()))?;
        pk.verify(&bytes, &sig)
            .map_err(|e| AuthorityError::PolicySignatureInvalid(e.to_string()))?;
        Ok(VerifiedPolicy {
            policy: policy.clone(),
        })
    }
}

#[derive(Serialize)]
struct UnsignedEnvelope {
    schema: String,
    policy_id: String,
    operator_principal: String,
    policy_snapshot_digest: String,
    directives: Vec<AuthorityDirective>,
    not_before_ms: u64,
    not_after_ms: u64,
    nonce: String,
}

/// Build a UserAuthorityIntent from a verified policy (ProgrammaticUserPolicy provenance).
pub fn intent_from_policy(
    verified: &VerifiedPolicy,
    intent_id: String,
    session_id: String,
) -> UserAuthorityIntent {
    // The policy's directives are the requested dimensions; the baseline is empty.
    let dimensions = verified
        .policy
        .directives
        .iter()
        .filter_map(|d| match d {
            AuthorityDirective::Grant { dimension, .. }
            | AuthorityDirective::Narrow { dimension, .. }
            | AuthorityDirective::Deny { dimension } => Some(*dimension),
            AuthorityDirective::Revoke { .. } => None,
        })
        .collect();
    let mut intent = UserAuthorityIntent {
        intent_id,
        session_id,
        dimensions,
        baseline: Default::default(),
        requested: Default::default(),
        provenance: AuthorityProvenance::ProgrammaticUserPolicy,
        confirmation: None,
        ttl_seconds: (verified
            .policy
            .not_after_ms
            .saturating_sub(verified.policy.not_before_ms))
            / 1000,
        intent_digest: String::new(),
    };
    intent.intent_digest = intent.compute_digest();
    intent
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use rand_core::OsRng;

    fn signed_policy(sk: &SigningKey, nonce: &str, now: u64) -> ProgrammaticUserPolicy {
        let mut p = ProgrammaticUserPolicy {
            schema: "orbit.authority-policy/v1".into(),
            policy_id: "p1".into(),
            operator_principal: "uid=1000".into(),
            policy_snapshot_digest: "d".repeat(64),
            directives: vec![AuthorityDirective::Grant {
                dimension: super::super::intent::AuthorityDimension::Egress,
                scope: serde_json::json!({}),
            }],
            not_before_ms: now - 1000,
            not_after_ms: now + 1000,
            nonce: nonce.into(),
            signature: None,
        };
        let unsigned = UnsignedEnvelope {
            schema: p.schema.clone(),
            policy_id: p.policy_id.clone(),
            operator_principal: p.operator_principal.clone(),
            policy_snapshot_digest: p.policy_snapshot_digest.clone(),
            directives: p.directives.clone(),
            not_before_ms: p.not_before_ms,
            not_after_ms: p.not_after_ms,
            nonce: p.nonce.clone(),
        };
        let bytes = crate::authority::canonical::canonical_bytes(&unsigned).unwrap();
        let sig = sk.sign(&bytes);
        p.signature = Some(hex::encode(sig.to_bytes()));
        p
    }

    #[test]
    fn policy_verifies_with_valid_signature() {
        let sk = SigningKey::generate(&mut OsRng);
        let pk: [u8; 32] = sk.verifying_key().to_bytes();
        let p = signed_policy(&sk, "n1", 1000);
        let mut v = PolicyVerifier::new(pk, 1000);
        assert!(v.verify(&p).is_ok());
    }

    #[test]
    fn nonce_replay_detected() {
        let sk = SigningKey::generate(&mut OsRng);
        let pk: [u8; 32] = sk.verifying_key().to_bytes();
        let p = signed_policy(&sk, "n2", 1000);
        let mut v = PolicyVerifier::new(pk, 1000);
        assert!(v.verify(&p).is_ok());
        assert_eq!(v.verify(&p).unwrap_err().code(), "E1944");
    }

    #[test]
    fn expired_policy_rejected() {
        let sk = SigningKey::generate(&mut OsRng);
        let pk: [u8; 32] = sk.verifying_key().to_bytes();
        let p = signed_policy(&sk, "n3", 1000);
        let mut v = PolicyVerifier::new(pk, 5000); // now is well past not_after
        assert_eq!(v.verify(&p).unwrap_err().code(), "E1945");
    }

    #[test]
    fn wrong_key_rejected() {
        let sk = SigningKey::generate(&mut OsRng);
        let other = SigningKey::generate(&mut OsRng);
        let pk: [u8; 32] = other.verifying_key().to_bytes();
        let p = signed_policy(&sk, "n4", 1000);
        let mut v = PolicyVerifier::new(pk, 1000);
        assert_eq!(v.verify(&p).unwrap_err().code(), "E1943");
    }
}
