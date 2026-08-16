//! Multi-producer single-consumer message bus (DR-20 §2.3).
//!
//! The reducer runs on the main thread and drains `Bus::try_recv` each UI tick.
//! The input poller, the tick timer, and (in PR-B) the worker thread all hold
//! `BusSender` clones to feed messages in.

use crate::msg::Msg;
use std::sync::mpsc;

/// Cloneable sender — each producer gets one.
#[derive(Clone)]
pub struct BusSender {
    tx: mpsc::Sender<Msg>,
}

impl BusSender {
    pub fn send(&self, msg: Msg) {
        let _ = self.tx.send(msg);
    }
}

/// The single consumer, owned by the main loop.
pub struct Bus {
    rx: mpsc::Receiver<Msg>,
}

impl Bus {
    pub fn new() -> (Self, BusSender) {
        let (tx, rx) = mpsc::channel();
        (Self { rx }, BusSender { tx })
    }

    /// Non-blocking receive — returns `None` if no message is pending.
    pub fn try_recv(&self) -> Option<Msg> {
        self.rx.try_recv().ok()
    }
}
