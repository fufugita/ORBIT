//! Cooperative cancellation token (DR-09 §4, GW-10).
//!
//! A `CancelToken` is shared between the dispatcher and the adapter stream.
//! `cancel()` notifies waiters; the adapter checks `is_cancelled()` between
//! events and terminates with a partial result.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
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
        // Re-check after arming to avoid a lost-wakeup race.
        if self.flag.load(Ordering::SeqCst) {
            return;
        }
        notified.await;
    }
}

impl std::fmt::Debug for CancelToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "CancelToken(cancelled={})", self.is_cancelled())
    }
}
