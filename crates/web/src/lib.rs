//! ORBIT browser harness bridge (docs/browser-harness.md).
//!
//! Projects the SAME harness — `run_turn` + tool runtime + sessions — to a
//! browser. The Rust core is the single source of truth; the browser is a
//! thin view. Transport: WebSocket (browser → Rust actions) + SSE
//! (Rust → browser events), same JSON shapes as the Go TUI bridge.
//!
//! Architecture (mirrors go_bridge.rs, transport swapped):
//! - axum serves the embedded SPA + `/events` (SSE) + `/actions` (WS).
//! - The WS pump forwards browser actions to a std mpsc channel AND fires
//!   `cancel` immediately on the shared cancel slot (a turn in flight owns
//!   the turn thread, so it cannot process cancel itself).
//! - A dedicated turn thread (spawned at server start) consumes actions,
//!   runs `run_turn` + tool loop, and broadcasts events to all SSE peers.
//! - Approvals park on the same action channel (`WebApprovalChannel`),
//!   exactly like `GoApprovalChannel`.
//!
//! Security (docs/browser-harness.md §Security):
//! - Loopback-only by default; binding non-loopback requires a bearer token
//!   (`?token=` on SSE/WS — EventSource cannot set headers).
//! - All streamed text passes through the TUI bridge's `safe_text`
//!   (display_safe, H-3) before it leaves Rust.
//! - Approvals are server-side: the browser sends a verdict, Rust applies
//!   it and the Ledger records the decision.

#![deny(unsafe_code)]

use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Query, State,
    },
    http::{header, StatusCode},
    response::{
        sse::{Event, KeepAlive, Sse},
        IntoResponse, Response,
    },
    routing::get,
    Router,
};
use futures::StreamExt;
use rust_embed::RustEmbed;
use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::{mpsc, Arc, Mutex};
use tokio::sync::broadcast;

mod turn;
pub use turn::{run_bridge, BridgeConfig};

/// Embedded SPA assets (crates/web/assets/). Served at `/` — no filesystem
/// dependency, one binary, same origin as the WS/SSE endpoints.
#[derive(RustEmbed)]
#[folder = "assets/"]
struct Assets;

/// A server → browser event (SSE `event:` + JSON `data:`).
/// Same shapes as the Go TUI bridge protocol.
#[derive(Debug, Clone)]
pub(crate) struct BridgeEvent {
    pub kind: &'static str,
    pub payload: serde_json::Value,
}

/// Shared bridge state: the SSE broadcast bus + the WS action funnel + the
/// cancel slot the WS pump fires immediately on `cancel`.
#[derive(Clone)]
pub struct BridgeState {
    pub(crate) events: broadcast::Sender<BridgeEvent>,
    pub(crate) actions: mpsc::Sender<serde_json::Value>,
    pub(crate) cancel_slot: Arc<Mutex<Option<orbit_provider_http::CancelToken>>>,
    /// Set when a non-loopback bind requires a bearer token.
    pub(crate) required_token: Option<String>,
    /// The current identity frame, replayed to every NEW SSE subscriber —
    /// tokio broadcast drops messages sent before anyone subscribed, and the
    /// boot-time identity is emitted before axum accepts connections.
    pub(crate) latest_identity: Arc<Mutex<Option<serde_json::Value>>>,
}

impl BridgeState {
    pub fn emit(&self, kind: &'static str, payload: serde_json::Value) {
        if kind == "identity" {
            if let Ok(mut g) = self.latest_identity.lock() {
                *g = Some(payload.clone());
            }
        }
        let _ = self.events.send(BridgeEvent { kind, payload });
    }
}

/// Build the router over the shared state.
pub fn router(state: BridgeState) -> Router {
    Router::new()
        .route("/", get(serve_index))
        .route("/static/:path", get(serve_asset))
        .route("/events", get(sse_events))
        .route("/actions", get(ws_actions))
        .with_state(state)
}

// ── Static SPA ────────────────────────────────────────────────────────────

async fn serve_index() -> Response {
    match Assets::get("index.html") {
        Some(a) => ([(header::CONTENT_TYPE, "text/html; charset=utf-8")], a.data).into_response(),
        None => (StatusCode::NOT_FOUND, "missing index.html").into_response(),
    }
}

async fn serve_asset(axum::extract::Path(path): axum::extract::Path<String>) -> Response {
    let mime = mime_guess::from_path(&path).first_or_octet_stream();
    match Assets::get(&path) {
        Some(a) => ([(header::CONTENT_TYPE, mime.as_ref())], a.data).into_response(),
        None => (StatusCode::NOT_FOUND, "no such asset").into_response(),
    }
}

// ── SSE: Rust → browser events ───────────────────────────────────────────

fn token_ok(state: &BridgeState, query: &HashMap<String, String>) -> bool {
    match &state.required_token {
        None => true,
        Some(tok) => query.get("token").map(|t| t == tok).unwrap_or(false),
    }
}

async fn sse_events(
    State(state): State<BridgeState>,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    if !token_ok(&state, &query) {
        return (StatusCode::UNAUTHORIZED, "bad or missing token").into_response();
    }
    let rx = state.events.subscribe();
    // Replay identity first: the boot-time broadcast had no subscribers yet.
    let first = state
        .latest_identity
        .lock()
        .ok()
        .and_then(|g| g.clone())
        .map(|payload| {
            Ok::<_, Infallible>(Event::default().event("identity").data(payload.to_string()))
        });
    let stream = futures::stream::unfold((first, rx), |(first, mut rx)| async move {
        if let Some(ev) = first {
            return Some((ev, (None, rx)));
        }
        match rx.recv().await {
            Ok(ev) => Some((
                Ok::<_, Infallible>(Event::default().event(ev.kind).data(ev.payload.to_string())),
                (None, rx),
            )),
            // The sender never drops while the server runs (state holds it);
            // Lagged just means the browser missed events — keep streaming.
            Err(broadcast::error::RecvError::Lagged(_)) => Some((
                Ok(Event::default()
                    .event("lagged")
                    .data(serde_json::json!({}).to_string())),
                (None, rx),
            )),
            Err(broadcast::error::RecvError::Closed) => None,
        }
    });
    Sse::new(stream)
        .keep_alive(KeepAlive::default())
        .into_response()
}

// ── WebSocket: browser → Rust actions ────────────────────────────────────

async fn ws_actions(
    State(state): State<BridgeState>,
    Query(query): Query<HashMap<String, String>>,
    ws: WebSocketUpgrade,
) -> Response {
    if !token_ok(&state, &query) {
        return (StatusCode::UNAUTHORIZED, "bad or missing token").into_response();
    }
    ws.on_upgrade(move |socket| ws_pump(socket, state))
}

/// Read WS frames → the shared action channel. `cancel` fires the in-flight
/// turn's token immediately (the turn thread is blocked inside `run_turn`
/// and cannot see the action itself — same reader-thread trick as go_bridge).
async fn ws_pump(mut socket: WebSocket, state: BridgeState) {
    while let Some(Ok(msg)) = socket.next().await {
        let Message::Text(text) = msg else { continue };
        let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) else {
            continue;
        };
        if v.get("type").and_then(|t| t.as_str()) == Some("cancel") {
            if let Ok(guard) = state.cancel_slot.lock() {
                if let Some(token) = guard.as_ref() {
                    token.cancel();
                }
            }
        }
        let _ = state.actions.send(v);
    }
}

/// The browser-side approval channel: parks on the shared action channel
/// until an `approve` verdict arrives (or cancel/quit ⇒ deny). Same contract
/// as `GoApprovalChannel`.
pub(crate) struct WebApprovalChannel {
    pub action_rx: Arc<Mutex<mpsc::Receiver<serde_json::Value>>>,
    /// Broadcast side so `ask` can surface the request to the browser before
    /// parking (mirrors TuiApprovalChannel posting Msg::ApprovalRequested).
    pub state: BridgeState,
}

impl orbit_cli::tool_runtime::ApprovalChannel for WebApprovalChannel {
    fn ask(
        &mut self,
        req: &orbit_cli::tool_runtime::ApprovalRequest,
        _auto_tools: bool,
    ) -> orbit_cli::tool_runtime::ApprovalVerdict {
        use orbit_cli::tool_runtime::ApprovalVerdict;
        // Surface the card first — the browser renders the modal from
        // this. MD gate 2: protocol name + protocol payload
        // (ApprovalRequested: tool_name, not name).
        self.state.emit(
            "approval_requested",
            serde_json::json!({
                "call_id": req.call_id,
                "tool_name": req.tool_name,
                "summary": req.summary,
                "risk": req.risk.level(),
            }),
        );
        let Ok(guard) = self.action_rx.lock() else {
            return ApprovalVerdict::Deny;
        };
        loop {
            match guard.recv() {
                Ok(a) => match a.get("type").and_then(|t| t.as_str()) {
                    Some("approve") => {
                        return match a.get("verdict").and_then(|v| v.as_str()) {
                            Some("allow") => ApprovalVerdict::AllowOnce,
                            Some("session") => ApprovalVerdict::AllowSession,
                            _ => ApprovalVerdict::Deny,
                        };
                    }
                    Some("cancel") | Some("quit") => return ApprovalVerdict::Deny,
                    _ => continue,
                },
                Err(_) => return ApprovalVerdict::Deny,
            }
        }
    }
}

/// Re-exported so `turn.rs` can build the shared pieces without reaching
/// into private fields from outside this module tree.
pub(crate) fn make_channels(
    required_token: Option<String>,
) -> (BridgeState, Arc<Mutex<mpsc::Receiver<serde_json::Value>>>) {
    let (events_tx, _events_rx) = broadcast::channel(1024);
    let (action_tx, action_rx) = mpsc::channel::<serde_json::Value>();
    let state = BridgeState {
        events: events_tx,
        actions: action_tx,
        cancel_slot: Arc::new(Mutex::new(None)),
        required_token,
        latest_identity: Arc::new(Mutex::new(None)),
    };
    (state, Arc::new(Mutex::new(action_rx)))
}

/// Test hook: build (state, action_rx) with an optional required token —
/// same as the server path, without spawning threads.
#[doc(hidden)]
pub fn __test_channels(
    required_token: Option<String>,
) -> (BridgeState, Arc<Mutex<mpsc::Receiver<serde_json::Value>>>) {
    make_channels(required_token)
}
