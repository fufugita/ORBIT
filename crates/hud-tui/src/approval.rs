//! Approval registry — maps pending call IDs to response channels (DR-20 §2.6).
//!
//! When the worker thread's `TuiApprovalChannel` is asked for approval, it
//! creates a channel, registers the `Sender` here keyed by `call_id`, posts
//! `Msg::ApprovalRequested` to the bus, and parks on `rx.recv()`.
//! The input handler resolves the approval by looking up the `call_id` in this
//! registry and sending the response.

use std::collections::HashMap;
use std::sync::{mpsc, Mutex};

/// The operator's response to an approval request. Defined in hud-tui so the
/// TUI doesn't depend on cli's `ApprovalVerdict`; the CLI maps at the boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalResponse {
    Allow,
    Deny,
    /// `R`: the whole tool, this session.
    AllowSession,
    /// `s`: this kind of call (the rule the card showed), this session.
    AllowRule,
    /// `a`: the same, and remembered in the folder's local settings.
    AllowRuleAlways,
}

/// Shared registry of pending approval response channels.
/// `call_id → Sender<ApprovalResponse>`.
///
/// `Clone` is cheap — the registry is `Arc<Mutex<...>>` inside, so all clones
/// share the same map. This lets both the worker thread (register) and the
/// main thread (resolve) hold a handle without `'static` lifetime gymnastics.
#[derive(Debug, Clone, Default)]
pub struct ApprovalRegistry {
    pending: std::sync::Arc<Mutex<HashMap<String, mpsc::Sender<ApprovalResponse>>>>,
    /// The note typed with a denial, by call id, until the worker takes it.
    notes: std::sync::Arc<Mutex<HashMap<String, String>>>,
}

impl ApprovalRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a response channel for a call_id. Called by the worker thread.
    pub fn register(&self, call_id: &str, tx: mpsc::Sender<ApprovalResponse>) {
        let mut map = self
            .pending
            .lock()
            .expect("approval registry lock poisoned");
        map.insert(call_id.to_string(), tx);
    }

    /// Resolve a pending approval. Called by the input handler when the operator
    /// presses y/n/R. Returns `true` if the approval was found and resolved.
    pub fn resolve(&self, call_id: &str, response: ApprovalResponse) -> bool {
        let mut map = self
            .pending
            .lock()
            .expect("approval registry lock poisoned");
        if let Some(tx) = map.remove(call_id) {
            tx.send(response).is_ok()
        } else {
            false
        }
    }

    /// Deny a pending approval and leave a note for the worker to hand to
    /// the model as the reason. An empty note is a plain denial.
    pub fn resolve_denial_with_note(&self, call_id: &str, note: &str) -> bool {
        let note = note.trim();
        if !note.is_empty() {
            self.notes
                .lock()
                .expect("approval notes lock poisoned")
                .insert(call_id.to_string(), note.to_string());
        }
        let delivered = self.resolve(call_id, ApprovalResponse::Deny);
        if !delivered {
            // Nobody is waiting to read it.
            self.take_note(call_id);
        }
        delivered
    }

    /// Take the note left with a denial, once.
    pub fn take_note(&self, call_id: &str) -> Option<String> {
        self.notes
            .lock()
            .expect("approval notes lock poisoned")
            .remove(call_id)
    }

    /// True if there are any pending approvals.
    pub fn has_pending(&self) -> bool {
        !self.pending.lock().expect("lock poisoned").is_empty()
    }

    /// Deny every pending approval and drop the response channels.
    ///
    /// Noninteractive shutdown path (SIGHUP/SIGTERM): the UI is going away,
    /// so no approval can ever be answered — deny them all so any worker
    /// parked on `rx.recv()` wakes immediately and aborts its turn. The
    /// dropped channels also unblock via `Err(RecvError)` on the other side
    /// should a response arrive after the map is cleared.
    pub fn deny_all(&self) -> usize {
        let mut map = self
            .pending
            .lock()
            .expect("approval registry lock poisoned");
        let denied = map.len();
        for (_id, tx) in map.drain() {
            let _ = tx.send(ApprovalResponse::Deny);
        }
        denied
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_and_resolve() {
        let reg = ApprovalRegistry::new();
        let (tx, rx) = mpsc::channel();
        reg.register("call-1", tx);
        assert!(reg.has_pending());
        assert!(reg.resolve("call-1", ApprovalResponse::Allow));
        assert!(!reg.has_pending());
        assert_eq!(rx.recv().unwrap(), ApprovalResponse::Allow);
    }

    #[test]
    fn resolve_unknown_call_returns_false() {
        let reg = ApprovalRegistry::new();
        assert!(!reg.resolve("nope", ApprovalResponse::Deny));
    }

    #[test]
    fn resolve_deny() {
        let reg = ApprovalRegistry::new();
        let (tx, rx) = mpsc::channel();
        reg.register("call-2", tx);
        reg.resolve("call-2", ApprovalResponse::Deny);
        assert_eq!(rx.recv().unwrap(), ApprovalResponse::Deny);
    }

    /// A denial's note is handed over once, to the worker that was
    /// waiting; one that nobody can read is not kept.
    #[test]
    fn a_denial_note_is_handed_over_once_and_never_kept_for_nobody() {
        let reg = ApprovalRegistry::new();
        let (tx, rx) = mpsc::channel();
        reg.register("call-n", tx);
        assert!(reg.resolve_denial_with_note("call-n", "  use make instead  "));
        assert_eq!(rx.recv().unwrap(), ApprovalResponse::Deny);
        assert_eq!(reg.take_note("call-n").as_deref(), Some("use make instead"));
        assert_eq!(reg.take_note("call-n"), None, "taken once");

        // A blank note is a plain denial.
        let (tx, rx) = mpsc::channel();
        reg.register("call-b", tx);
        assert!(reg.resolve_denial_with_note("call-b", "   "));
        assert_eq!(rx.recv().unwrap(), ApprovalResponse::Deny);
        assert_eq!(reg.take_note("call-b"), None);

        // No worker is waiting: nothing is delivered, and nothing is left.
        assert!(!reg.resolve_denial_with_note("gone", "too late"));
        assert_eq!(reg.take_note("gone"), None);
    }

    #[test]
    fn resolve_allow_session() {
        let reg = ApprovalRegistry::new();
        let (tx, rx) = mpsc::channel();
        reg.register("call-3", tx);
        reg.resolve("call-3", ApprovalResponse::AllowSession);
        assert_eq!(rx.recv().unwrap(), ApprovalResponse::AllowSession);
    }

    #[test]
    fn deny_all_releases_every_parked_worker_with_deny() {
        let reg = ApprovalRegistry::new();
        let (tx1, rx1) = mpsc::channel();
        let (tx2, rx2) = mpsc::channel();
        reg.register("a", tx1);
        reg.register("b", tx2);
        assert_eq!(reg.deny_all(), 2);
        assert!(!reg.has_pending());
        assert_eq!(rx1.recv().unwrap(), ApprovalResponse::Deny);
        assert_eq!(rx2.recv().unwrap(), ApprovalResponse::Deny);
    }

    #[test]
    fn deny_all_on_empty_registry_is_zero() {
        let reg = ApprovalRegistry::new();
        assert_eq!(reg.deny_all(), 0);
    }
}
