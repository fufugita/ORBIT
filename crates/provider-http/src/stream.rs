//! Async provider event stream (DR-09 §4, GW-11).
//!
//! `AsyncProviderEventStream` is the `Pin<Box<dyn Stream>>` surface the
//! async adapters return. Invariants are enforced by the v0.1
//! `orbit_adapter::stream::validate_stream` (contiguous sequence, one
//! terminal, monotonic usage) — the async harness re-uses it on the collected
//! events.

use futures::Stream;
use orbit_adapter::error::AdapterError;
use orbit_adapter::types::ProviderStreamEvent;
use std::pin::Pin;

pub(crate) const MAX_FRAME_BYTES: usize = 8 * 1024 * 1024;
pub(crate) const MAX_RESPONSE_BYTES: usize = 32 * 1024 * 1024;
pub(crate) const MAX_TOOL_CALLS: usize = 128;

pub(crate) fn protocol(message: &str) -> AdapterError {
    AdapterError::ProtocolOrStreamViolation(format!("{message} (E0411)"))
}

pub(crate) fn required_counter(
    value: &serde_json::Value,
    field: &str,
) -> Result<u64, AdapterError> {
    value
        .get(field)
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| protocol("provider usage is missing a nonnegative integer counter"))
}

pub(crate) fn optional_counter(
    value: &serde_json::Value,
    field: &str,
) -> Result<Option<u64>, AdapterError> {
    value
        .get(field)
        .map(|counter| {
            counter
                .as_u64()
                .ok_or_else(|| protocol("provider usage counter is not a nonnegative integer"))
        })
        .transpose()
}

pub(crate) fn count_bytes(total: &mut usize, added: usize) -> Result<(), AdapterError> {
    *total = total
        .checked_add(added)
        .filter(|n| *n <= MAX_RESPONSE_BYTES)
        .ok_or_else(|| protocol("provider response exceeds the byte limit"))?;
    Ok(())
}

pub(crate) fn append_bounded(
    target: &mut String,
    part: &str,
    limit: usize,
) -> Result<(), AdapterError> {
    if target
        .len()
        .checked_add(part.len())
        .is_none_or(|len| len > limit)
    {
        return Err(protocol("provider field exceeds the byte limit"));
    }
    target.push_str(part);
    Ok(())
}

#[derive(Default)]
pub(crate) struct WireCall {
    pub id: String,
    pub name: String,
    pub arguments: String,
}

pub(crate) fn validate_calls(
    calls: &std::collections::BTreeMap<u32, WireCall>,
) -> Result<(), AdapterError> {
    let mut ids = std::collections::BTreeSet::new();
    for call in calls.values() {
        if call.id.trim().is_empty()
            || call.id.len() > 512
            || call.name.trim().is_empty()
            || call.name.len() > 256
            || !ids.insert(call.id.as_str())
        {
            return Err(protocol("invalid or duplicate tool call identity"));
        }
        let arguments: serde_json::Value = serde_json::from_str(&call.arguments)
            .map_err(|_| protocol("incomplete tool call arguments"))?;
        if !arguments.is_object() {
            return Err(protocol("tool call arguments must be a JSON object"));
        }
    }
    Ok(())
}

pub(crate) fn incomplete_reason(reason: &str) -> bool {
    matches!(
        reason,
        "length" | "max_tokens" | "content_filter" | "refusal"
    )
}

pub(crate) fn record_reason(
    current: &mut Option<String>,
    reason: &str,
    allowed: &[&str],
) -> Result<(), AdapterError> {
    if !allowed.contains(&reason) {
        return Err(protocol("unknown provider finish reason"));
    }
    if let Some(previous) = current.as_deref() {
        if incomplete_reason(previous) {
            return Ok(());
        }
        if previous != reason && !incomplete_reason(reason) {
            return Err(protocol("conflicting provider finish reasons"));
        }
    }
    *current = Some(reason.to_owned());
    Ok(())
}

/// The async provider event stream (DR-09 §3 exact type).
pub type AsyncProviderEventStream =
    Pin<Box<dyn Stream<Item = Result<ProviderStreamEvent, AdapterError>> + Send>>;

/// A per-event observer for live streaming. When provided, called for every
/// event as the stream drains (before it lands in the collected Vec), so a
/// caller can render TextDeltas live. Observations are provisional: a terminal
/// callback can still be followed by a transport or validation failure.
/// Passing `None` preserves the same collected result and errors.
pub type StreamObserver<'a> = Option<&'a mut dyn FnMut(&ProviderStreamEvent)>;

/// Drain the stream, then validate the complete collected events (GW-11/GW-13).
/// Any transport error is returned unchanged, including after a terminal callback.
/// Only success returns the events and the two-hash output evidence.
pub async fn collect_stream(
    mut stream: AsyncProviderEventStream,
    mut observer: StreamObserver<'_>,
) -> Result<
    (
        Vec<ProviderStreamEvent>,
        orbit_adapter::types::OutputEvidence,
    ),
    AdapterError,
> {
    use futures::StreamExt;
    let mut events = Vec::new();
    while let Some(item) = stream.next().await {
        match item {
            Ok(ev) => {
                if let Some(cb) = observer.as_deref_mut() {
                    cb(&ev);
                }
                events.push(ev)
            }
            Err(e) => return Err(e),
        }
    }
    if !events.last().is_some_and(|event| {
        matches!(
            event.event,
            orbit_adapter::types::ProviderEventKind::Finished { .. }
        )
    }) {
        return Err(protocol("provider stream ended without a terminal event"));
    }
    let evidence = orbit_adapter::stream::output_evidence(&events)?;
    Ok((events, evidence))
}
