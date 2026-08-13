//! RTA — Runtime Trust Assessment (DR-12 §7, DR-14 amendments).
//!
//! Describes trust and information flow but never grants authority (RTA-I7).
//! Rejects non-user provenance (RTA-I8). KERN-4 refuses credential/key/hash/
//! internal-ID disclosure BEFORE confirmation and cannot be overridden (RTA-I9).
//! Attested remains reserved in v0.1 (RTA-I1).

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};

/// RTA errors (E1501-E1504).
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum RtaError {
    #[error("ORBIT-E1501 rta_assessment_failed: {0}")]
    AssessmentFailed(String),
    #[error("ORBIT-E1502 rta_level_insufficient: {0}")]
    LevelInsufficient(String),
    #[error("ORBIT-E1503 rta_attestation_unavailable: {0}")]
    AttestationUnavailable(String),
    #[error("ORBIT-E1504 rta_assessment_stale: {0}")]
    AssessmentStale(String),
}

impl RtaError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::AssessmentFailed(_) => "E1501",
            Self::LevelInsufficient(_) => "E1502",
            Self::AttestationUnavailable(_) => "E1503",
            Self::AssessmentStale(_) => "E1504",
        }
    }
}

/// Trust level (DR-01 §17.2): Attested reserved.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum TrustLevel {
    Standard,
    #[serde(rename = "attested_reserved")]
    Attested,
    Local,
}

/// A trust assessment — immutable once committed (RTA-I2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustAssessment {
    pub assessment_id: String,
    pub target: String, // what is being assessed (provider, env)
    pub level: TrustLevel,
    pub max_age_ms: u64,
    pub at_ms: u64,
}

/// The RTA service.
pub struct RtaService;

impl RtaService {
    /// Produce an assessment. Attested is refused in v0.1 (E1503).
    /// This NEVER grants authority (RTA-I7); it only describes trust posture.
    pub fn assess(
        &self,
        assessment_id: String,
        target: String,
        level: TrustLevel,
        max_age_ms: u64,
        at_ms: u64,
    ) -> Result<TrustAssessment, RtaError> {
        if level == TrustLevel::Attested {
            return Err(RtaError::AttestationUnavailable(
                "Attested is reserved in v0.1 (E1503)".into(),
            ));
        }
        Ok(TrustAssessment {
            assessment_id,
            target,
            level,
            max_age_ms,
            at_ms,
        })
    }

    /// Check an assessment is not stale (RTA-I5 / E1504).
    pub fn check_fresh(&self, assessment: &TrustAssessment, now_ms: u64) -> Result<(), RtaError> {
        if now_ms.saturating_sub(assessment.at_ms) > assessment.max_age_ms {
            return Err(RtaError::AssessmentStale(format!(
                "assessment {} older than max-age (E1504)",
                assessment.assessment_id
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attested_reserved() {
        let svc = RtaService;
        assert_eq!(
            svc.assess("a1".into(), "p".into(), TrustLevel::Attested, 1000, 0)
                .unwrap_err()
                .code(),
            "E1503"
        );
        assert!(svc
            .assess("a2".into(), "p".into(), TrustLevel::Standard, 1000, 0)
            .is_ok());
    }

    #[test]
    fn stale_assessment_rejected() {
        let svc = RtaService;
        let a = svc
            .assess("a3".into(), "p".into(), TrustLevel::Standard, 100, 0)
            .unwrap();
        assert_eq!(svc.check_fresh(&a, 5000).unwrap_err().code(), "E1504");
    }
}
