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

/// The async provider event stream (DR-09 §3 exact type).
pub type AsyncProviderEventStream =
    Pin<Box<dyn Stream<Item = Result<ProviderStreamEvent, AdapterError>> + Send>>;

/// A per-event observer for live streaming. When provided, called for every
/// event as the stream drains (before it lands in the collected Vec), so a
/// caller can render TextDeltas live. `collect_stream` is byte-identical to
/// the previous behavior when `None` is passed.
pub type StreamObserver<'a> = Option<&'a mut dyn FnMut(&ProviderStreamEvent)>;

/// Collect a stream to its terminal result, validating sequence/usage on the
/// way (GW-11/GW-13). Returns the events + the two-hash output evidence.
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
    let evidence = orbit_adapter::stream::output_evidence(&events)?;
    Ok((events, evidence))
}
