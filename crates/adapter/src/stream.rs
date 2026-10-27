//! Stream event bookkeeping + the two terminal hashes (DR-09 §4).
//!
//! - Sequences start at 0 and increase by 1. Duplicate, skipped, reordered,
//!   or post-terminal events → `ProtocolOrStreamViolation`
//!   (E0411). Exactly one terminalizer wins (GW-10).
//! - `raw_stream_sha256` over `u16 tag || u64 sequence_be || u64 payload_len_be || payload`.
//! - `canonical_output_sha256` over reconstructed semantic output bytes, with
//!   NO undocumented Unicode/newline normalization (GW-12).
//! - Usage snapshots are monotonic; decreasing usage fails (GW-13).

use crate::error::AdapterError;
use crate::types::{
    OutputEvidence, ProviderEventKind, ProviderStreamEvent, ProviderUsage, Sha256Digest,
    UsageObservationDigestV1, UsageObservationDispositionV1, UsageObservationEvidenceV1,
    UsageObservationOriginV1, UsageObservationQualificationV1, UsageObservationSnapshotV1,
    UsageReasoningReportingV1, UsageReportingPresenceV1, UsageSnapshotOriginV1, UsageSource,
};
use sha2::{Digest, Sha256};

/// Tag a stream event kind for the raw-stream hash (DR-09 §4).
fn event_tag(kind: &ProviderEventKind) -> u16 {
    match kind {
        ProviderEventKind::ResponseStarted { .. } => 1,
        ProviderEventKind::TextDelta { .. } => 2,
        ProviderEventKind::ToolCallStarted { .. } => 3,
        ProviderEventKind::ToolCallArgumentsDelta { .. } => 4,
        ProviderEventKind::ToolCallFinished { .. } => 5,
        ProviderEventKind::UsageUpdate(_) => 6,
        ProviderEventKind::Finished { .. } => 7,
        ProviderEventKind::ThinkingDelta { .. } => 8,
        ProviderEventKind::ThinkingSignatureDelta { .. } => 9,
    }
}

/// Serialize a stream event to the raw-stream hash input
/// `u16 tag || u64 sequence_be || u64 payload_len_be || payload`.
fn event_to_hash_bytes(ev: &ProviderStreamEvent) -> Vec<u8> {
    let tag = event_tag(&ev.event);
    let payload: Vec<u8> = match &ev.event {
        ProviderEventKind::TextDelta { bytes }
        | ProviderEventKind::ThinkingDelta { bytes }
        | ProviderEventKind::ThinkingSignatureDelta { bytes }
        | ProviderEventKind::ToolCallArgumentsDelta { bytes, .. } => bytes.clone(),
        ProviderEventKind::ResponseStarted {
            upstream_request_id,
        } => upstream_request_id
            .as_deref()
            .unwrap_or("")
            .as_bytes()
            .to_vec(),
        ProviderEventKind::ToolCallStarted {
            name,
            provider_call_id,
            ..
        } => {
            let mut b = name.as_bytes().to_vec();
            if let Some(id) = provider_call_id {
                b.extend_from_slice(id.as_bytes());
            }
            b
        }
        ProviderEventKind::ToolCallFinished { .. } => Vec::new(),
        ProviderEventKind::UsageUpdate(u) => format!(
            "{},{},{},{},{}",
            u.input_tokens,
            u.output_tokens,
            u.cache_read_tokens,
            u.cache_write_tokens,
            u.reasoning_tokens
        )
        .into_bytes(),
        ProviderEventKind::Finished { finish_reason, .. } => {
            finish_reason.as_deref().unwrap_or("").as_bytes().to_vec()
        }
    };
    let payload_len = payload.len() as u64;
    let mut out = Vec::with_capacity(2 + 8 + 8 + payload.len());
    out.extend_from_slice(&tag.to_be_bytes());
    out.extend_from_slice(&ev.sequence.to_be_bytes());
    out.extend_from_slice(&payload_len.to_be_bytes());
    out.extend_from_slice(&payload);
    out
}

/// Callback inspection only. No accessor converts this capture into a result or receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProvisionalUsageObservationV1 {
    raw_stream_sha256: Sha256Digest,
    digest: UsageObservationDigestV1,
    selected: Option<UsageObservationSnapshotV1>,
    disposition: UsageObservationDispositionV1,
    qualification: UsageObservationQualificationV1,
    invalid: bool,
}

impl ProvisionalUsageObservationV1 {
    pub fn raw_stream_sha256(&self) -> &Sha256Digest {
        &self.raw_stream_sha256
    }
    pub fn digest(&self) -> &UsageObservationDigestV1 {
        &self.digest
    }
    pub fn selected(&self) -> Option<&UsageObservationSnapshotV1> {
        self.selected.as_ref()
    }
    pub fn disposition(&self) -> UsageObservationDispositionV1 {
        self.disposition
    }
    pub fn qualification(&self) -> UsageObservationQualificationV1 {
        self.qualification
    }
    pub fn is_invalid(&self) -> bool {
        self.invalid
    }
}

/// Bounded retained counters/hash state; the legacy per-event raw encoder still allocates.
#[derive(Debug, Clone)]
pub struct UsageObservationAccumulatorV1 {
    raw_hasher: Sha256,
    row_hasher: Sha256,
    last_sequence: Option<u64>,
    rows: u64,
    finished: bool,
    last_usage: ProviderUsage,
    selected: Option<UsageObservationSnapshotV1>,
    disposition: UsageObservationDispositionV1,
    qualification: UsageObservationQualificationV1,
    invalid: Option<AdapterError>,
}

impl Default for UsageObservationAccumulatorV1 {
    fn default() -> Self {
        Self::new()
    }
}

impl UsageObservationAccumulatorV1 {
    pub fn new() -> Self {
        let mut row_hasher = Sha256::new();
        row_hasher.update(b"orbit-usage-observation-v1\0");
        row_hasher.update(1_u16.to_be_bytes());
        Self {
            raw_hasher: Sha256::new(),
            row_hasher,
            last_sequence: None,
            rows: 0,
            finished: false,
            last_usage: ProviderUsage::default(),
            selected: None,
            disposition: UsageObservationDispositionV1::NoTerminal,
            qualification: UsageObservationQualificationV1::MissingSnapshot,
            invalid: None,
        }
    }

    /// Any fault is permanent for this invocation, including faults after a terminal callback.
    pub fn observe(&mut self, event: &ProviderStreamEvent) -> Result<(), AdapterError> {
        if let Some(error) = &self.invalid {
            return Err(error.clone());
        }
        let result = self.observe_valid(event);
        if let Err(error) = &result {
            self.invalid = Some(error.clone());
        }
        result
    }

    /// Revoke capture validity after an external collector or lifecycle fault.
    pub fn invalidate(&mut self) {
        if self.invalid.is_none() {
            self.invalid = Some(AdapterError::ProtocolOrStreamViolation(
                "usage observation capture invalidated (E0411)".into(),
            ));
        }
    }

    fn observe_valid(&mut self, event: &ProviderStreamEvent) -> Result<(), AdapterError> {
        let expected = match self.last_sequence {
            Some(sequence) => sequence.checked_add(1).ok_or_else(|| {
                AdapterError::ProtocolOrStreamViolation("stream sequence overflow (E0411)".into())
            })?,
            None => 0,
        };
        if event.sequence != expected {
            return Err(AdapterError::ProtocolOrStreamViolation(
                "stream sequence is not contiguous from zero (E0411)".into(),
            ));
        }
        if self.finished {
            return Err(AdapterError::ProtocolOrStreamViolation(
                "event after Finished (post-terminal) (E0411)".into(),
            ));
        }
        let usage = match &event.event {
            ProviderEventKind::UsageUpdate(usage) => Some(usage),
            ProviderEventKind::Finished { final_usage, .. } => final_usage.as_ref(),
            _ => None,
        };
        if let Some(metadata) = event.usage_observation {
            if usage.is_none() || metadata.version != 1 {
                return Err(AdapterError::ProtocolOrStreamViolation(
                    "invalid usage observation placement or version (E0411)".into(),
                ));
            }
            if metadata.reasoning_reporting == UsageReasoningReportingV1::NotReported
                && usage.is_some_and(|value| value.reasoning_tokens != 0)
            {
                return Err(AdapterError::ProviderUsageInvalid(
                    "not_reported contradicts the reasoning counter (E0416)".into(),
                ));
            }
        }
        if let Some(usage) = usage
            && (usage.input_tokens < self.last_usage.input_tokens
                || usage.output_tokens < self.last_usage.output_tokens
                || usage.cache_read_tokens < self.last_usage.cache_read_tokens
                || usage.cache_write_tokens < self.last_usage.cache_write_tokens
                || usage.reasoning_tokens < self.last_usage.reasoning_tokens)
        {
            return Err(AdapterError::ProviderUsageInvalid(
                "raw usage decreased from the previous snapshot (E0416)".into(),
            ));
        }
        let row = observation_row_bytes(event);
        let next_rows = if row.is_some() {
            self.rows.checked_add(1).ok_or_else(|| {
                AdapterError::ProtocolOrStreamViolation(
                    "usage observation row count overflow (E0411)".into(),
                )
            })?
        } else {
            self.rows
        };
        // No retained payload, and no changed legacy tag/preimage function.
        self.raw_hasher.update(event_to_hash_bytes(event));
        if let Some(row) = row {
            self.row_hasher.update(row);
        }
        self.rows = next_rows;
        self.last_sequence = Some(event.sequence);
        if let Some(usage) = usage {
            self.last_usage = *usage;
            let (reasoning_reporting, snapshot_origin) = match event.usage_observation {
                None => (
                    UsageReportingPresenceV1::LegacyUnknown,
                    UsageObservationOriginV1::LegacyUnknown,
                ),
                Some(metadata) => (
                    match metadata.reasoning_reporting {
                        UsageReasoningReportingV1::Reported => UsageReportingPresenceV1::Reported,
                        UsageReasoningReportingV1::NotReported => {
                            UsageReportingPresenceV1::NotReported
                        }
                    },
                    match metadata.snapshot_origin {
                        UsageSnapshotOriginV1::ProviderReported => {
                            UsageObservationOriginV1::ProviderReported
                        }
                        UsageSnapshotOriginV1::Synthetic => UsageObservationOriginV1::Synthetic,
                    },
                ),
            };
            self.selected = Some(UsageObservationSnapshotV1 {
                sequence: event.sequence,
                raw_usage: *usage,
                source: if matches!(event.event, ProviderEventKind::Finished { .. }) {
                    UsageSource::Final
                } else {
                    UsageSource::Incremental
                },
                reasoning_reporting,
                snapshot_origin,
            });
        }
        if let ProviderEventKind::Finished { finish_reason, .. } = &event.event {
            self.finished = true;
            self.disposition = terminal_disposition(finish_reason.as_deref());
        }
        self.qualification = match &self.selected {
            None => UsageObservationQualificationV1::MissingSnapshot,
            Some(snapshot) if snapshot.source != UsageSource::Final => {
                UsageObservationQualificationV1::ProvisionalSnapshot
            }
            Some(_) if self.disposition == UsageObservationDispositionV1::Cancelled => {
                UsageObservationQualificationV1::CancelledTerminalSnapshot
            }
            Some(snapshot) => match snapshot.snapshot_origin {
                UsageObservationOriginV1::ProviderReported => {
                    UsageObservationQualificationV1::ProviderReportedTerminalSnapshot
                }
                UsageObservationOriginV1::Synthetic => {
                    UsageObservationQualificationV1::SyntheticTerminalSnapshot
                }
                UsageObservationOriginV1::LegacyUnknown => {
                    UsageObservationQualificationV1::LegacyTerminalSnapshot
                }
            },
        };
        Ok(())
    }

    fn observation_digest(&self) -> UsageObservationDigestV1 {
        let mut hasher = self.row_hasher.clone();
        hasher.update([255]);
        hasher.update(self.rows.to_be_bytes());
        hasher.update(self.raw_hasher.clone().finalize());
        UsageObservationDigestV1(hex::encode(hasher.finalize()))
    }

    pub fn provisional(&self) -> ProvisionalUsageObservationV1 {
        ProvisionalUsageObservationV1 {
            raw_stream_sha256: Sha256Digest(hex::encode(self.raw_hasher.clone().finalize())),
            digest: self.observation_digest(),
            selected: self.selected.clone(),
            disposition: self.disposition,
            qualification: self.qualification,
            invalid: self.invalid.is_some(),
        }
    }

    /// Return billing counters only for a validated, provider-reported terminal
    /// snapshot. This is derived from the live accumulator, never a stored DTO.
    pub fn validated_terminal_billing_usage(&self) -> Option<crate::types::BillingObservedUsageV1> {
        if self.invalid.is_some()
            || !self.finished
            || self.disposition == UsageObservationDispositionV1::Cancelled
        {
            return None;
        }
        let snapshot = self.selected.as_ref()?;
        if snapshot.source != UsageSource::Final
            || snapshot.snapshot_origin != UsageObservationOriginV1::ProviderReported
        {
            return None;
        }
        let reasoning_reporting = match snapshot.reasoning_reporting {
            UsageReportingPresenceV1::Reported => crate::types::ReasoningReporting::Reported,
            UsageReportingPresenceV1::NotReported => crate::types::ReasoningReporting::NotReported,
            UsageReportingPresenceV1::LegacyUnknown => {
                crate::types::ReasoningReporting::LegacyUnknown
            }
        };
        Some(crate::types::BillingObservedUsageV1 {
            raw_usage: snapshot.raw_usage,
            reasoning_reporting,
        })
    }

    fn evidence(&self) -> UsageObservationEvidenceV1 {
        UsageObservationEvidenceV1 {
            encoding_version: 1,
            digest: self.observation_digest(),
            selected: self.selected.clone(),
            disposition: self.disposition,
            qualification: self.qualification,
        }
    }
}

fn terminal_disposition(reason: Option<&str>) -> UsageObservationDispositionV1 {
    match reason {
        Some("stop" | "end_turn" | "stop_sequence") => UsageObservationDispositionV1::CompleteText,
        Some("tool_calls" | "tool_use") => UsageObservationDispositionV1::CompleteTools,
        Some("cancelled") => UsageObservationDispositionV1::Cancelled,
        _ => UsageObservationDispositionV1::IncompleteOrOther,
    }
}

fn disposition_tag(disposition: UsageObservationDispositionV1) -> u8 {
    match disposition {
        UsageObservationDispositionV1::CompleteText => 1,
        UsageObservationDispositionV1::CompleteTools => 2,
        UsageObservationDispositionV1::Cancelled => 3,
        UsageObservationDispositionV1::IncompleteOrOther => 4,
        UsageObservationDispositionV1::NoTerminal => 0,
    }
}

fn observation_row_bytes(event: &ProviderStreamEvent) -> Option<Vec<u8>> {
    let (tag, usage, reason) = match &event.event {
        ProviderEventKind::UsageUpdate(usage) => (1, Some(usage), None),
        ProviderEventKind::Finished {
            final_usage,
            finish_reason,
        } => (2, final_usage.as_ref(), Some(finish_reason.as_deref())),
        _ => return None,
    };
    let mut row = Vec::with_capacity(56);
    row.push(tag);
    row.extend_from_slice(&event.sequence.to_be_bytes());
    row.push(u8::from(usage.is_some()));
    if let Some(usage) = usage {
        for counter in [
            usage.input_tokens,
            usage.output_tokens,
            usage.cache_read_tokens,
            usage.cache_write_tokens,
            usage.reasoning_tokens,
        ] {
            row.extend_from_slice(&counter.to_be_bytes());
        }
    }
    row.push(u8::from(event.usage_observation.is_some()));
    if let Some(metadata) = event.usage_observation {
        row.extend_from_slice(&metadata.version.to_be_bytes());
        row.push(match metadata.reasoning_reporting {
            UsageReasoningReportingV1::Reported => 1,
            UsageReasoningReportingV1::NotReported => 2,
        });
        row.push(match metadata.snapshot_origin {
            UsageSnapshotOriginV1::ProviderReported => 1,
            UsageSnapshotOriginV1::Synthetic => 2,
        });
    }
    if let Some(reason) = reason {
        row.push(disposition_tag(terminal_disposition(reason)));
    }
    Some(row)
}

/// Valid prefixes retain NoTerminal and provisional/missing qualification.
/// This computation returns inert inspection data, not a completed HTTP result.
pub fn usage_observation_evidence_v1(
    events: &[ProviderStreamEvent],
) -> Result<UsageObservationEvidenceV1, AdapterError> {
    let mut accumulator = UsageObservationAccumulatorV1::new();
    for event in events {
        accumulator.observe(event)?;
    }
    Ok(accumulator.evidence())
}

/// Validate raw counters/sequence/metadata and retain the unchanged legacy hash.
/// EOF without Finished remains a valid prefix; the HTTP collector enforces its own completion.
pub fn validate_stream(
    events: &[ProviderStreamEvent],
) -> Result<(Vec<ProviderStreamEvent>, Sha256Digest), AdapterError> {
    let mut accumulator = UsageObservationAccumulatorV1::new();
    for event in events {
        accumulator.observe(event)?;
    }
    let digest = Sha256Digest(hex::encode(accumulator.raw_hasher.finalize()));
    Ok((events.to_vec(), digest))
}

/// Canonical output SHA-256 over reconstructed semantic output bytes — the
/// concatenation of TextDelta bytes + ToolCallArgumentsDelta bytes, in
/// sequence order. No normalization (GW-12).
pub fn canonical_output_sha256(events: &[ProviderStreamEvent]) -> Sha256Digest {
    let mut hasher = Sha256::new();
    for ev in events {
        match &ev.event {
            ProviderEventKind::TextDelta { bytes } => hasher.update(bytes),
            ProviderEventKind::ToolCallArgumentsDelta { bytes, .. } => hasher.update(bytes),
            _ => {}
        }
    }
    Sha256Digest(hex::encode(hasher.finalize()))
}

/// Build the full `OutputEvidence` for a stream: raw hash + canonical hash +
/// observed/delivered byte counts.
pub fn output_evidence(events: &[ProviderStreamEvent]) -> Result<OutputEvidence, AdapterError> {
    let (_, raw_stream_sha256) = validate_stream(events)?;
    let canonical_output_sha256 = canonical_output_sha256(events);
    let observed_bytes: u64 = events
        .iter()
        .map(|e| match &e.event {
            ProviderEventKind::TextDelta { bytes }
            | ProviderEventKind::ToolCallArgumentsDelta { bytes, .. } => bytes.len() as u64,
            _ => 0,
        })
        .sum();
    Ok(OutputEvidence {
        raw_stream_sha256,
        canonical_output_sha256,
        observed_bytes,
        delivered_bytes: observed_bytes,
    })
}

#[cfg(test)]
mod observation_encoding_tests {
    use super::*;
    use crate::types::UsageObservationMetaV1;

    fn usage(values: [u64; 5]) -> ProviderUsage {
        ProviderUsage {
            input_tokens: values[0],
            output_tokens: values[1],
            cache_read_tokens: values[2],
            cache_write_tokens: values[3],
            reasoning_tokens: values[4],
        }
    }

    #[test]
    fn billing_counters_require_a_valid_provider_reported_terminal_snapshot() {
        fn capture(
            finish_reason: &str,
            origin: Option<UsageSnapshotOriginV1>,
            with_prior: bool,
        ) -> UsageObservationAccumulatorV1 {
            let mut capture = UsageObservationAccumulatorV1::new();
            capture
                .observe(&ProviderStreamEvent {
                    sequence: 0,
                    event: ProviderEventKind::ResponseStarted {
                        upstream_request_id: None,
                    },
                    usage_observation: None,
                })
                .unwrap();
            let mut sequence = 1;
            if with_prior {
                capture
                    .observe(&ProviderStreamEvent {
                        sequence,
                        event: ProviderEventKind::UsageUpdate(usage([8, 9, 0, 0, 0])),
                        usage_observation: None,
                    })
                    .unwrap();
                sequence += 1;
            }
            let metadata = origin.map(|snapshot_origin| UsageObservationMetaV1 {
                version: 1,
                reasoning_reporting: UsageReasoningReportingV1::Reported,
                snapshot_origin,
            });
            capture
                .observe(&ProviderStreamEvent {
                    sequence,
                    event: ProviderEventKind::Finished {
                        finish_reason: Some(finish_reason.into()),
                        final_usage: Some(usage([10, 20, 0, 0, 5])),
                    },
                    usage_observation: metadata,
                })
                .unwrap();
            capture
        }

        let reported = capture("stop", Some(UsageSnapshotOriginV1::ProviderReported), true);
        assert_eq!(
            reported.validated_terminal_billing_usage(),
            Some(crate::types::BillingObservedUsageV1 {
                raw_usage: usage([10, 20, 0, 0, 5]),
                reasoning_reporting: crate::types::ReasoningReporting::Reported,
            })
        );
        let truncated = capture(
            "length",
            Some(UsageSnapshotOriginV1::ProviderReported),
            false,
        );
        assert_eq!(
            truncated.validated_terminal_billing_usage(),
            Some(crate::types::BillingObservedUsageV1 {
                raw_usage: usage([10, 20, 0, 0, 5]),
                reasoning_reporting: crate::types::ReasoningReporting::Reported,
            })
        );
        assert!(
            capture("stop", Some(UsageSnapshotOriginV1::Synthetic), false)
                .validated_terminal_billing_usage()
                .is_none()
        );
        assert!(
            capture(
                "cancelled",
                Some(UsageSnapshotOriginV1::ProviderReported),
                false
            )
            .validated_terminal_billing_usage()
            .is_none()
        );
        assert!(
            capture("stop", None, false)
                .validated_terminal_billing_usage()
                .is_none()
        );
        let mut revoked = reported;
        revoked.invalidate();
        assert!(revoked.validated_terminal_billing_usage().is_none());
    }

    #[test]
    fn observation_raw_and_row_preimages_match_independent_fixed_bytes() {
        let cases = [
            (
                "empty_prefix",
                vec![],
                "",
                "",
                "6f726269742d75736167652d6f62736572766174696f6e2d7631000001ff0000000000000000e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            ),
            (
                "legacy_positive_text",
                vec![
                    ProviderStreamEvent {
                        sequence: 0,
                        event: ProviderEventKind::ResponseStarted {
                            upstream_request_id: None,
                        },
                        usage_observation: None,
                    },
                    ProviderStreamEvent {
                        sequence: 1,
                        event: ProviderEventKind::UsageUpdate(usage([10, 20, 3, 4, 5])),
                        usage_observation: None,
                    },
                    ProviderStreamEvent {
                        sequence: 2,
                        event: ProviderEventKind::TextDelta {
                            bytes: hex::decode("6f6b0a").unwrap(),
                        },
                        usage_observation: None,
                    },
                    ProviderStreamEvent {
                        sequence: 3,
                        event: ProviderEventKind::Finished {
                            finish_reason: Some("stop".into()),
                            final_usage: Some(usage([10, 20, 3, 4, 5])),
                        },
                        usage_observation: None,
                    },
                ],
                "00010000000000000000000000000000000000060000000000000001000000000000000b31302c32302c332c342c350002000000000000000200000000000000036f6b0a00070000000000000003000000000000000473746f70",
                "01000000000000000101000000000000000a00000000000000140000000000000003000000000000000400000000000000050002000000000000000301000000000000000a00000000000000140000000000000003000000000000000400000000000000050001",
                "6f726269742d75736167652d6f62736572766174696f6e2d763100000101000000000000000101000000000000000a00000000000000140000000000000003000000000000000400000000000000050002000000000000000301000000000000000a00000000000000140000000000000003000000000000000400000000000000050001ff00000000000000024a0f534b254c67245f19cb0d63c3119c05ac812c6af692ec053912380aeb5e14",
            ),
            (
                "mixed_legacy_reported_not_reported",
                vec![
                    ProviderStreamEvent {
                        sequence: 0,
                        event: ProviderEventKind::ResponseStarted {
                            upstream_request_id: None,
                        },
                        usage_observation: None,
                    },
                    ProviderStreamEvent {
                        sequence: 1,
                        event: ProviderEventKind::UsageUpdate(usage([10, 20, 3, 4, 0])),
                        usage_observation: None,
                    },
                    ProviderStreamEvent {
                        sequence: 2,
                        event: ProviderEventKind::UsageUpdate(usage([12, 25, 4, 5, 0])),
                        usage_observation: Some(UsageObservationMetaV1 {
                            version: 1,
                            reasoning_reporting: UsageReasoningReportingV1::Reported,
                            snapshot_origin: UsageSnapshotOriginV1::ProviderReported,
                        }),
                    },
                    ProviderStreamEvent {
                        sequence: 3,
                        event: ProviderEventKind::UsageUpdate(usage([14, 30, 4, 6, 0])),
                        usage_observation: Some(UsageObservationMetaV1 {
                            version: 1,
                            reasoning_reporting: UsageReasoningReportingV1::NotReported,
                            snapshot_origin: UsageSnapshotOriginV1::ProviderReported,
                        }),
                    },
                    ProviderStreamEvent {
                        sequence: 4,
                        event: ProviderEventKind::Finished {
                            finish_reason: Some("stop".into()),
                            final_usage: Some(usage([14, 30, 4, 6, 0])),
                        },
                        usage_observation: Some(UsageObservationMetaV1 {
                            version: 1,
                            reasoning_reporting: UsageReasoningReportingV1::NotReported,
                            snapshot_origin: UsageSnapshotOriginV1::ProviderReported,
                        }),
                    },
                ],
                "00010000000000000000000000000000000000060000000000000001000000000000000b31302c32302c332c342c3000060000000000000002000000000000000b31322c32352c342c352c3000060000000000000003000000000000000b31342c33302c342c362c3000070000000000000004000000000000000473746f70",
                "01000000000000000101000000000000000a00000000000000140000000000000003000000000000000400000000000000000001000000000000000201000000000000000c0000000000000019000000000000000400000000000000050000000000000000010001010101000000000000000301000000000000000e000000000000001e000000000000000400000000000000060000000000000000010001020102000000000000000401000000000000000e000000000000001e000000000000000400000000000000060000000000000000010001020101",
                "6f726269742d75736167652d6f62736572766174696f6e2d763100000101000000000000000101000000000000000a00000000000000140000000000000003000000000000000400000000000000000001000000000000000201000000000000000c0000000000000019000000000000000400000000000000050000000000000000010001010101000000000000000301000000000000000e000000000000001e000000000000000400000000000000060000000000000000010001020102000000000000000401000000000000000e000000000000001e000000000000000400000000000000060000000000000000010001020101ff0000000000000004241745da5dcabb26eec6230dbb9d26b96b833b9fa9f374c8e694a4f350e02e4b",
            ),
        ];
        for (name, events, expected_raw, expected_rows, expected_full) in cases {
            let raw: Vec<u8> = events.iter().flat_map(event_to_hash_bytes).collect();
            let rows: Vec<u8> = events
                .iter()
                .filter_map(observation_row_bytes)
                .flatten()
                .collect();
            assert_eq!(hex::encode(&raw), expected_raw, "{name}");
            assert_eq!(hex::encode(&rows), expected_rows, "{name}");
            let mut preimage = b"orbit-usage-observation-v1\0".to_vec();
            preimage.extend_from_slice(&1_u16.to_be_bytes());
            preimage.extend_from_slice(&rows);
            preimage.push(255);
            let row_count =
                u64::try_from(events.iter().filter_map(observation_row_bytes).count()).unwrap();
            preimage.extend_from_slice(&row_count.to_be_bytes());
            preimage.extend_from_slice(&Sha256::digest(&raw));
            assert_eq!(hex::encode(&preimage), expected_full, "{name}");
            let expected_digest = hex::encode(Sha256::digest(hex::decode(expected_full).unwrap()));
            assert_eq!(
                usage_observation_evidence_v1(&events)
                    .unwrap()
                    .digest
                    .as_str(),
                expected_digest,
                "{name}"
            );
        }
    }

    #[test]
    fn observation_external_fault_revokes_terminal_capture_without_changing_observed_state() {
        let mut capture = UsageObservationAccumulatorV1::new();
        capture
            .observe(&ProviderStreamEvent {
                sequence: 0,
                event: ProviderEventKind::ResponseStarted {
                    upstream_request_id: None,
                },
                usage_observation: None,
            })
            .unwrap();
        capture
            .observe(&ProviderStreamEvent {
                sequence: 1,
                event: ProviderEventKind::Finished {
                    finish_reason: Some("stop".into()),
                    final_usage: Some(usage([10, 20, 3, 4, 5])),
                },
                usage_observation: Some(UsageObservationMetaV1 {
                    version: 1,
                    reasoning_reporting: UsageReasoningReportingV1::Reported,
                    snapshot_origin: UsageSnapshotOriginV1::ProviderReported,
                }),
            })
            .unwrap();
        let mut expected = capture.provisional();
        assert!(!expected.is_invalid());
        let sequence = capture.last_sequence;
        let rows = capture.rows;
        let finished = capture.finished;
        let last_usage = capture.last_usage;
        capture.invalidate();
        let first_fault = format!("{:?}", capture.invalid);
        capture.invalidate();
        assert_eq!(format!("{:?}", capture.invalid), first_fault);
        expected.invalid = true;
        assert_eq!(capture.provisional(), expected);
        assert_eq!(capture.last_sequence, sequence);
        assert_eq!(capture.rows, rows);
        assert_eq!(capture.finished, finished);
        assert_eq!(capture.last_usage, last_usage);
        assert!(
            capture
                .observe(&ProviderStreamEvent {
                    sequence: 2,
                    event: ProviderEventKind::TextDelta {
                        bytes: b"late".to_vec()
                    },
                    usage_observation: None,
                })
                .is_err()
        );
        assert_eq!(capture.provisional(), expected);
        assert_eq!(format!("{:?}", capture.invalid), first_fault);
        let mut prior_fault = UsageObservationAccumulatorV1::new();
        assert!(
            prior_fault
                .observe(&ProviderStreamEvent {
                    sequence: 1,
                    event: ProviderEventKind::ResponseStarted {
                        upstream_request_id: None
                    },
                    usage_observation: None,
                })
                .is_err()
        );
        let original_fault = format!("{:?}", prior_fault.invalid);
        prior_fault.invalidate();
        prior_fault.invalidate();
        assert_eq!(format!("{:?}", prior_fault.invalid), original_fault);
        assert!(prior_fault.provisional().is_invalid());
    }

    #[test]
    fn observation_internal_counter_overflow_latches_without_a_fake_short_stream() {
        // Inject private arithmetic boundaries; no short valid stream reaches these states.
        let event = ProviderStreamEvent {
            sequence: 0,
            event: ProviderEventKind::UsageUpdate(ProviderUsage::default()),
            usage_observation: None,
        };
        let mut sequence = UsageObservationAccumulatorV1::new();
        sequence.last_sequence = Some(u64::MAX);
        assert_eq!(sequence.observe(&event).unwrap_err().code(), "E0411");
        assert!(sequence.provisional().is_invalid());
        assert!(sequence.observe(&event).is_err());
        let mut rows = UsageObservationAccumulatorV1::new();
        rows.rows = u64::MAX;
        assert_eq!(rows.observe(&event).unwrap_err().code(), "E0411");
        assert!(rows.provisional().is_invalid());
        assert!(
            rows.observe(&ProviderStreamEvent {
                sequence: 0,
                event: ProviderEventKind::ResponseStarted {
                    upstream_request_id: None
                },
                usage_observation: None
            })
            .is_err()
        );
    }
}
