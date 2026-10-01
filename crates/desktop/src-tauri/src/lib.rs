//! The ORBIT desktop shell (Tauri) — the Rust side.
//!
//! Architecture: the webview renders; this crate owns the harness
//! connection and speaks `orbit-frontend-protocol` over Tauri events.
//! Every FrontendEvent is emitted as `orbit://event`; every
//! FrontendAction arrives as a `orbit://action` command. The protocol
//! crate is the single vocabulary — no ad-hoc payloads.

use orbit_frontend_protocol::{FrontendAction, FrontendEvent};
use std::sync::{Arc, Mutex};
use tauri::{AppHandle, Emitter, State};

/// The desktop app's harness state — the same shapes the TUI keeps,
/// driven by the same protocol events.
#[derive(Default)]
struct HarnessState {
    /// The live workspace (plan/findings/verification).
    workspace: orbit_frontend_protocol::Workspace,
    /// Cumulative cost in microcents.
    total_cost_microcents: u64,
    /// The session identity, once known.
    identity: Option<orbit_frontend_protocol::Identity>,
}

/// The shared state handle.
type SharedState = Arc<Mutex<HarnessState>>;

/// Emit a protocol event to the webview.
fn emit_event(app: &AppHandle, event: &FrontendEvent) {
    let _ = app.emit("orbit://event", event);
}

/// Apply a protocol event to the harness state (the Rust-side mirror).
fn apply_event(state: &mut HarnessState, event: &FrontendEvent) {
    match event {
        FrontendEvent::WorkspaceUpdate(w) => state.workspace = w.clone(),
        FrontendEvent::CostUpdated { total_microcents } => {
            state.total_cost_microcents = *total_microcents;
        }
        FrontendEvent::Identity(id) => state.identity = Some(id.clone()),
        _ => {}
    }
}

#[tauri::command]
fn state_snapshot(state: State<'_, SharedState>) -> serde_json::Value {
    let s = state.lock().unwrap();
    serde_json::json!({
        "workspace": s.workspace,
        "totalCostMicrocents": s.total_cost_microcents,
        "identity": s.identity,
    })
}

#[tauri::command]
fn send_action(app: AppHandle, state: State<'_, SharedState>, action: FrontendAction) {
    // The desktop shell currently mirrors state locally; the harness
    // connection lands with the worker bridge (implementation order §3).
    // Until then, actions apply their observable effects through the
    // same apply_event/emit_event path the real bridge will use — so the
    // UI is testable end-to-end and the bridge drops in without touching
    // this command.
    let events: Vec<FrontendEvent> = match action {
        FrontendAction::Prompt { text } => {
            // Placeholder harness: echo the prompt back as a finished
            // turn (the real bridge streams the model's response).
            vec![
                FrontendEvent::TextDelta { text },
                FrontendEvent::ResponseFinished {
                    output: String::new(),
                    input_tokens: 0,
                    output_tokens: 0,
                    cost_microcents: 0,
                },
            ]
        }
        FrontendAction::NewSession => {
            let mut s = state.lock().unwrap();
            s.workspace = orbit_frontend_protocol::Workspace::default();
            s.total_cost_microcents = 0;
            s.identity = None;
            vec![]
        }
        _ => vec![],
    };
    for ev in &events {
        {
            let mut s = state.lock().unwrap();
            apply_event(&mut s, ev);
        }
        emit_event(&app, ev);
    }
}

pub fn run() {
    tauri::Builder::default()
        .manage(Arc::new(Mutex::new(HarnessState::default())))
        .invoke_handler(tauri::generate_handler![state_snapshot, send_action])
        .run(tauri::generate_context!())
        .expect("error while running orbit-desktop");
}
