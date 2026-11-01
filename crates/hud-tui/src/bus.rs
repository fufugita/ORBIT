//! Multi-producer message bus with optional, ephemeral display provenance.

use crate::msg::Msg;
use crate::worker::{ForegroundOperation, ForegroundRegistration, ForegroundViewState};
use std::sync::{Arc, Mutex, mpsc};

/// A producer-derived correspondence recipe. It carries no execution authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ViewProjectionLayout {
    pub line_count: usize,
    pub baseline_lines: usize,
    pub input_index: usize,
    pub groups: Vec<ViewProjectionGroup>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ViewProjectionGroup {
    pub round: u32,
    pub model_index: Option<usize>,
    pub tools: Vec<ViewToolProjection>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ViewToolProjection {
    pub line_index: usize,
    pub call_id: String,
    pub tool_name: String,
    pub ordinal: usize,
}

#[derive(Clone)]
pub(crate) struct ViewStamp {
    pub operation: ForegroundOperation,
    pub round: Option<u32>,
    pub eligible: bool,
}
pub(crate) enum ObservedEvent {
    Message {
        msg: Box<Msg>,
        source: Option<ViewStamp>,
        layout: Option<ViewProjectionLayout>,
    },
    RoundStarted {
        round: u32,
        source: ViewStamp,
    },
}
struct ViewShared {
    operation: ForegroundOperation,
    gate: Arc<Mutex<ForegroundViewState>>,
}
#[derive(Clone)]
struct ViewSender {
    shared: Arc<ViewShared>,
    round: Option<u32>,
    projection: bool,
    layout: Arc<Mutex<Option<ViewProjectionLayout>>>,
}

/// Cloneable sender. Existing unscoped send/receive behavior is retained.
#[derive(Clone)]
pub struct BusSender {
    tx: mpsc::Sender<ObservedEvent>,
    view: Option<ViewSender>,
}
impl BusSender {
    pub fn send(&self, msg: Msg) {
        let Some(view) = &self.view else {
            let _ = self.tx.send(ObservedEvent::Message {
                msg: Box::new(msg),
                source: None,
                layout: None,
            });
            return;
        };
        // Holding this lock through enqueue linearizes stamping with close.
        let mut gate = view.shared.gate.lock().ok();
        let eligible = gate.as_mut().is_some_and(|gate| {
            if view.projection {
                if matches!(&msg, Msg::SessionProjection(_)) && !gate.projection_sent {
                    gate.projection_sent = true;
                    return true;
                }
                false
            } else {
                gate.open
            }
        });
        let layout = if eligible && view.projection {
            view.layout.lock().ok().and_then(|mut slot| slot.take())
        } else {
            None
        };
        let source = Some(ViewStamp {
            operation: view.shared.operation.clone(),
            round: view.round,
            eligible,
        });
        let _ = self.tx.send(ObservedEvent::Message {
            msg: Box::new(msg),
            source,
            layout,
        });
    }
    /// Obtain one view publisher from an already successful registration.
    pub fn scoped_view(&self, registration: &ForegroundRegistration) -> Option<ViewLease> {
        let (operation, gate) = registration.claim_view_source()?;
        let shared = Arc::new(ViewShared { operation, gate });
        Some(ViewLease {
            sender: Self {
                tx: self.tx.clone(),
                view: Some(ViewSender {
                    shared,
                    round: None,
                    projection: false,
                    layout: Arc::new(Mutex::new(None)),
                }),
            },
        })
    }
    /// Round tags annotate the existing event adapter, never worker authority.
    pub fn with_view_round(&self, round: u32) -> Self {
        let mut next = self.clone();
        if let Some(view) = &mut next.view {
            view.round = Some(round);
        }
        next
    }
    pub fn view_round_started(&self, round: u32) {
        let Some(view) = &self.view else {
            return;
        };
        let gate = view.shared.gate.lock().ok();
        let source = ViewStamp {
            operation: view.shared.operation.clone(),
            round: Some(round),
            eligible: gate.as_ref().is_some_and(|gate| gate.open) && !view.projection,
        };
        let _ = self.tx.send(ObservedEvent::RoundStarted { round, source });
    }
}

/// Its lifetime is only the ability to publish display observations.
pub struct ViewLease {
    sender: BusSender,
}
impl ViewLease {
    pub fn sender(&self) -> BusSender {
        self.sender.clone()
    }
    pub fn close(&self) {
        if let Some(view) = &self.sender.view
            && let Ok(mut gate) = view.shared.gate.lock()
        {
            gate.open = false;
        }
    }
    pub fn close_and_projection_sender(&self, layout: Option<ViewProjectionLayout>) -> BusSender {
        self.close();
        let mut next = self.sender.clone();
        if let Some(view) = &mut next.view {
            view.projection = true;
            view.round = None;
            view.layout = Arc::new(Mutex::new(layout));
        }
        next
    }
}
impl Drop for ViewLease {
    fn drop(&mut self) {
        self.close();
    }
}

/// The single consumer, owned by the main loop.
pub struct Bus {
    rx: mpsc::Receiver<ObservedEvent>,
}
impl Bus {
    pub fn new() -> (Self, BusSender) {
        let (tx, rx) = mpsc::channel();
        (Self { rx }, BusSender { tx, view: None })
    }
    pub fn try_recv(&self) -> Option<Msg> {
        while let Ok(event) = self.rx.try_recv() {
            if let ObservedEvent::Message { msg, .. } = event {
                return Some(*msg);
            }
        }
        None
    }
    pub(crate) fn try_recv_observed(&self) -> Option<ObservedEvent> {
        self.rx.try_recv().ok()
    }
}

#[cfg(test)]
mod view_source_tests {
    use super::*;
    use crate::worker::{ForegroundKind, SessionBinding, WorkerCommand};
    fn started() -> (
        Bus,
        BusSender,
        ForegroundOperation,
        ForegroundRegistration,
        ViewLease,
    ) {
        let (bus, sender) = Bus::new();
        let operation = ForegroundOperation::new(
            SessionBinding {
                session_id: "session-view".into(),
                generation: 1,
            },
            ForegroundKind::Prompt,
            1,
        )
        .unwrap();
        let registration = operation
            .start(&WorkerCommand::Prompt("input".into()))
            .unwrap();
        let lease = sender.scoped_view(&registration).unwrap();
        (bus, sender, operation, registration, lease)
    }
    fn projection(operation: ForegroundOperation) -> Msg {
        Msg::SessionProjection(crate::msg::SessionProjection {
            binding: operation.source().clone(),
            model: "model".into(),
            provider: "provider".into(),
            priced: false,
            lines: Vec::new(),
            turns: 0,
            input_tokens: 0,
            output_tokens: 0,
            cost_microcents: 0,
            cost: crate::msg::CostQualification::Unavailable,
            context: crate::msg::ContextProjection::Unavailable,
            reason: crate::msg::ProjectionReason::Operation { operation },
        })
    }
    #[test]
    fn registered_publisher_is_one_use_without_restarting_the_operation() {
        let (_, sender, operation, registration, _lease) = started();
        assert!(sender.scoped_view(&registration).is_none());
        assert!(
            operation
                .start(&WorkerCommand::Prompt("second".into()))
                .is_err()
        );
    }
    #[test]
    fn queued_preclose_stamp_survives_registration_drop_but_late_clone_is_expired() {
        let (bus, _, operation, registration, lease) = started();
        let sender = lease.sender().with_view_round(0);
        sender.send(Msg::TextDelta("before".into()));
        lease.close();
        drop(registration);
        sender.send(Msg::TextDelta("after".into()));
        assert!(
            matches!(bus.try_recv_observed(), Some(ObservedEvent::Message { source: Some(source), .. }) if source.eligible && source.operation == operation)
        );
        assert!(
            matches!(bus.try_recv_observed(), Some(ObservedEvent::Message { source: Some(source), .. }) if !source.eligible && source.operation == operation)
        );
    }
    #[test]
    fn registration_drop_closes_fresh_source_stamping_even_when_lease_is_retained() {
        let (bus, _, _, registration, lease) = started();
        let sender = lease.sender();
        drop(registration);
        sender.send(Msg::TextDelta("late".into()));
        assert!(
            matches!(bus.try_recv_observed(), Some(ObservedEvent::Message { source: Some(source), .. }) if !source.eligible)
        );
    }
    #[test]
    fn close_and_projection_use_one_stamp_after_all_source_sends() {
        let (bus, _, operation, _registration, lease) = started();
        let sender = lease.close_and_projection_sender(None);
        sender.send(projection(operation.clone()));
        sender.send(projection(operation));
        assert!(
            matches!(bus.try_recv_observed(), Some(ObservedEvent::Message { source: Some(source), .. }) if source.eligible)
        );
        assert!(
            matches!(bus.try_recv_observed(), Some(ObservedEvent::Message { source: Some(source), .. }) if !source.eligible)
        );
    }
    #[test]
    fn actual_enqueue_and_close_share_one_locked_linearization() {
        let (bus, _, _, _registration, lease) = started();
        let sender = lease.sender();
        let shared = sender.view.as_ref().unwrap().shared.clone();
        let mut gate = shared.gate.lock().unwrap();
        let ready = Arc::new(std::sync::Barrier::new(2));
        let signal = ready.clone();
        let thread = std::thread::spawn(move || {
            signal.wait();
            sender.send(Msg::TextDelta("blocked send".into()));
        });
        ready.wait();
        gate.open = false;
        drop(gate);
        thread.join().unwrap();
        assert!(
            matches!(bus.try_recv_observed(), Some(ObservedEvent::Message { source: Some(source), .. }) if !source.eligible)
        );
    }
    #[test]
    fn legacy_receiver_keeps_messages_and_does_not_expose_origin_annotations() {
        let (bus, sender, _, _registration, lease) = started();
        lease.sender().view_round_started(0);
        sender.send(Msg::TextDelta("legacy".into()));
        assert!(matches!(bus.try_recv(), Some(Msg::TextDelta(text)) if text == "legacy"));
        assert!(bus.try_recv().is_none());
    }
    #[test]
    fn equal_looking_operation_is_not_the_captured_identity() {
        let (bus, _, operation, _registration, lease) = started();
        let other =
            ForegroundOperation::new(operation.source().clone(), operation.kind(), operation.id())
                .unwrap();
        lease.sender().send(Msg::TextDelta("identity".into()));
        assert!(
            matches!(bus.try_recv_observed(), Some(ObservedEvent::Message { source: Some(source), .. }) if source.operation == operation && source.operation != other)
        );
    }
}
