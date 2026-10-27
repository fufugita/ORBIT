//! Cooperative cancellation token (DR-09 §4, GW-10).
//!
//! A `CancelToken` is shared between the dispatcher and the adapter stream.
//! `cancel()` notifies waiters; adapters race pending network waits against
//! the signal and terminate with a partial result.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::Notify;

/// Shared cancellation signal. Clone is cheap; all clones observe the same flag.
#[derive(Clone, Default)]
pub struct CancelToken {
    flag: Arc<AtomicBool>,
    notify: Arc<Notify>,
}

impl CancelToken {
    pub fn new() -> Self {
        Self::default()
    }

    /// Request cancellation (idempotent). Wakes all `cancelled()` waiters.
    pub fn cancel(&self) {
        self.flag.store(true, Ordering::SeqCst);
        self.notify.notify_waiters();
    }

    /// Whether cancellation was requested.
    pub fn is_cancelled(&self) -> bool {
        self.flag.load(Ordering::SeqCst)
    }

    /// A future that resolves when cancellation is requested — usable in
    /// `tokio::select!` to race stream work against cancellation.
    pub async fn cancelled(&self) {
        // Fast path: already cancelled.
        if self.flag.load(Ordering::SeqCst) {
            return;
        }
        let notified = self.notify.notified();
        tokio::pin!(notified);
        // Constructing Notified does not register it with notify_waiters.
        // Enable the pinned waiter before the final flag check so cancellation
        // cannot fall between that check and the first poll of the waiter.
        notified.as_mut().enable();
        if self.flag.load(Ordering::SeqCst) {
            return;
        }
        notified.await;
    }

    /// Do not poll network work after cancellation, including when both
    /// branches become ready together. Dropping the losing HTTP future also
    /// releases its connection/body rather than leaving background work alive.
    pub(crate) async fn until_cancelled<F: std::future::Future>(
        &self,
        future: F,
    ) -> Option<F::Output> {
        tokio::select! {
            biased;
            () = self.cancelled() => None,
            value = future => Some(value),
        }
    }
}

/// Cancellation before a response body exists uses the same successful partial
/// terminal contract as cancellation during streaming. It is never a retryable
/// timeout or transport error.
pub(crate) fn cancelled_stream() -> crate::AsyncProviderEventStream {
    use orbit_adapter::types::{
        ProviderEventKind, ProviderStreamEvent, ProviderUsage, UsageObservationMetaV1,
        UsageReasoningReportingV1, UsageSnapshotOriginV1,
    };
    Box::pin(futures::stream::iter([
        Ok(ProviderStreamEvent {
            usage_observation: None,
            sequence: 0,
            event: ProviderEventKind::ResponseStarted {
                upstream_request_id: None,
            },
        }),
        Ok(ProviderStreamEvent {
            usage_observation: Some(UsageObservationMetaV1 {
                version: 1,
                reasoning_reporting: UsageReasoningReportingV1::NotReported,
                snapshot_origin: UsageSnapshotOriginV1::Synthetic,
            }),
            sequence: 1,
            event: ProviderEventKind::Finished {
                finish_reason: Some("cancelled".into()),
                final_usage: Some(ProviderUsage::default()),
            },
        }),
    ]))
}

impl std::fmt::Debug for CancelToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "CancelToken(cancelled={})", self.is_cancelled())
    }
}
