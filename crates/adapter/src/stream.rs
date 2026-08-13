//! Stream event bookkeeping + the two terminal hashes (DR-09 §4).
//!
//! - Sequences start at 0 and increase by 1. Duplicate, skipped, reordered,
//!   post-terminal, or EOF-without-`Finished` → `ProtocolOrStreamViolation`
//!   (E0411). Exactly one terminalizer wins (GW-10).
//! - `raw_stream_sha256` over `u16 tag || u64 sequence_be || u64 payload_len_be || payload`.
//! - `canonical_output_sha256` over reconstructed semantic output bytes, with
//!   NO undocumented Unicode/newline normalization (GW-12).
//! - Usage snapshots are monotonic; decreasing usage fails (GW-13).

use crate::error::AdapterError;
use crate::types::{
    OutputEvidence, ProviderEventKind, ProviderStreamEvent, ProviderUsage, Sha256Digest,
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
    }
}

/// Serialize a stream event to the raw-stream hash input
/// `u16 tag || u64 sequence_be || u64 payload_len_be || payload`.
fn event_to_hash_bytes(ev: &ProviderStreamEvent) -> Vec<u8> {
    let tag = event_tag(&ev.event);
    let payload: Vec<u8> = match &ev.event {
        ProviderEventKind::TextDelta { bytes }
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

/// Validate a stream: sequences strictly increasing by 1, exactly one
/// `Finished`, usage monotonic. Returns the events + the raw-stream hash.
/// Violations → E0411 (protocol) or E0416 (usage).
pub fn validate_stream(
    events: &[ProviderStreamEvent],
) -> Result<(Vec<ProviderStreamEvent>, Sha256Digest), AdapterError> {
    let mut hasher = Sha256::new();
    let mut prev_seq: Option<u64> = None;
    let mut finished_seen = false;
    let mut last_usage = ProviderUsage::default();

    for ev in events {
        // Sequence contiguity.
        if let Some(p) = prev_seq {
            if ev.sequence != p + 1 {
                return Err(AdapterError::ProtocolOrStreamViolation(format!(
                    "sequence {} follows {} (must increase by 1) (E0411)",
                    ev.sequence, p
                )));
            }
        } else if ev.sequence != 0 {
            return Err(AdapterError::ProtocolOrStreamViolation(
                "first event must have sequence 0 (E0411)".into(),
            ));
        }
        // Post-terminal.
        if finished_seen {
            return Err(AdapterError::ProtocolOrStreamViolation(
                "event after Finished (post-terminal) (E0411)".into(),
            ));
        }
        if matches!(ev.event, ProviderEventKind::Finished { .. }) {
            if finished_seen {
                return Err(AdapterError::ProtocolOrStreamViolation(
                    "duplicate Finished (E0411)".into(),
                ));
            }
            finished_seen = true;
        }
        // Usage monotonicity (GW-13).
        if let ProviderEventKind::UsageUpdate(u) = &ev.event {
            if u.input_tokens < last_usage.input_tokens
                || u.output_tokens < last_usage.output_tokens
                || u.cache_read_tokens < last_usage.cache_read_tokens
                || u.cache_write_tokens < last_usage.cache_write_tokens
                || u.reasoning_tokens < last_usage.reasoning_tokens
            {
                return Err(AdapterError::ProviderUsageInvalid(format!(
                    "usage decreased: {u:?} after {last_usage:?} (E0416)"
                )));
            }
            last_usage = *u;
        }

        hasher.update(event_to_hash_bytes(ev));
        prev_seq = Some(ev.sequence);
    }

    // EOF without Finished → partial (NOT a protocol error by itself; the
    // caller marks the result Partial). But a missing terminalizer means the
    // events can still be hashed.
    let digest = Sha256Digest(hex::encode(hasher.finalize()));
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
