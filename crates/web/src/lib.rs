//! Browser transport over the shared, leased session owner.
//! WebSocket connections own a controller lease; event streams are read-only.

#![deny(unsafe_code)]

use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Query, State,
    },
    http::{header, HeaderMap, StatusCode},
    response::{
        sse::{Event, KeepAlive, Sse},
        IntoResponse, Response,
    },
    routing::get,
    Router,
};
use futures::StreamExt;
use orbit_cli::daemon::{ControllerLease, EventCursor, OwnerAction, OwnerHandle, OwnerSnapshot};
use rust_embed::RustEmbed;
use serde_json::{json, Value};
use std::{
    collections::{HashMap, VecDeque},
    convert::Infallible,
    sync::{mpsc, Arc, Mutex},
    time::Duration,
};
use tokio::sync::broadcast;

pub mod customization;
mod turn;
pub use turn::{run_bridge, run_bridge_owned, run_bridge_owned_with_customization, BridgeConfig};

#[derive(RustEmbed)]
#[folder = "assets/"]
struct Assets;

#[derive(Debug, Clone)]
struct BridgeEvent {
    kind: String,
    payload: Value,
}

/// The production state holds no transcript, configuration, approval queue or
/// turn loop. Those belong exclusively to `OwnerRuntime`.
#[derive(Clone)]
pub struct BridgeState {
    owner: Option<OwnerHandle>,
    required_token: Option<String>,
    bound_address: Option<std::net::SocketAddr>,
    customization: Option<Arc<dyn orbit_frontend_protocol::customization::ProfileHost>>,
    // Isolated transport test surface retained for the existing router tests.
    fixture_events: broadcast::Sender<BridgeEvent>,
    fixture_identity: Arc<Mutex<Option<Value>>>,
}

impl BridgeState {
    pub fn from_owner(owner: OwnerHandle, token: Option<String>) -> Result<Self, String> {
        if token.as_ref().is_some_and(|token| token.is_empty()) {
            return Err("an authentication token must not be empty".into());
        }
        let (fixture_events, _) = broadcast::channel(16);
        Ok(Self {
            owner: Some(owner),
            required_token: token,
            bound_address: None,
            customization: None,
            fixture_events,
            fixture_identity: Arc::new(Mutex::new(None)),
        })
    }

    /// Bind browser authority checks to the actual listening socket.
    pub fn with_bound_address(mut self, address: std::net::SocketAddr) -> Self {
        self.bound_address = Some(address);
        self
    }

    pub fn with_customization(
        mut self,
        host: Arc<dyn orbit_frontend_protocol::customization::ProfileHost>,
    ) -> Self {
        self.customization = Some(host);
        self
    }

    pub fn customization_snapshot(&self) -> Result<Value, String> {
        let host = self
            .customization
            .as_ref()
            .ok_or("customization host unavailable")?
            .clone();
        let owner = self.owner.as_ref().ok_or("session owner unavailable")?;
        let (session_id, context) = owner
            .pane_context_with_session()
            .map_err(|e| e.to_string())?;
        let mut session = customization::BrowserSession::open(host, session_id)?;
        session.refresh_all(&context);
        Ok(session.reply(""))
    }

    pub fn snapshot(&self) -> Result<OwnerSnapshot, String> {
        self.owner
            .as_ref()
            .ok_or("session owner unavailable")?
            .snapshot()
            .map_err(|error| error.to_string())
    }

    pub fn claim_controller(&self) -> Result<BridgeController, String> {
        let owner = self.owner.as_ref().ok_or("session owner unavailable")?;
        let customization = self
            .customization
            .as_ref()
            .map(|host| {
                let (session_id, context) = owner
                    .pane_context_with_session()
                    .map_err(|e| e.to_string())?;
                let mut session = customization::BrowserSession::open(host.clone(), session_id)?;
                session.refresh_all(&context);
                Ok::<_, String>(session)
            })
            .transpose()?;
        Ok(BridgeController {
            lease: owner
                .claim_controller()
                .map_err(|error| error.to_string())?,
            owner: owner.clone(),
            customization,
        })
    }

    /// Fixture injection is deliberately disconnected from production streams.
    #[doc(hidden)]
    pub fn emit(&self, kind: &'static str, payload: Value) {
        if self.owner.is_some() {
            return;
        }
        if kind == "identity" {
            if let Ok(mut identity) = self.fixture_identity.lock() {
                *identity = Some(payload.clone());
            }
        }
        let _ = self.fixture_events.send(BridgeEvent {
            kind: kind.into(),
            payload,
        });
    }
}

/// The exact action path used by the WebSocket pump, available to transport
/// acceptance tests without a second model/tool implementation.
pub struct BridgeController {
    lease: ControllerLease,
    owner: OwnerHandle,
    customization: Option<customization::BrowserSession>,
}
impl BridgeController {
    pub fn send(&mut self, mut value: Value) -> Result<Value, String> {
        if serde_json::to_vec(&value).map_or(true, |bytes| bytes.len() > 70 * 1024) {
            return Err("browser action exceeds the frame limit".into());
        }
        if matches!(
            value.get("type").and_then(Value::as_str),
            Some("customize" | "pane_refresh" | "pane_action")
        ) {
            let action = customization::parse(value)?;
            self.lease.check().map_err(|e| e.to_string())?;
            let (session_id, mut context) = self
                .owner
                .pane_context_with_session()
                .map_err(|e| e.to_string())?;
            context.controller = true;
            let session = self
                .customization
                .as_mut()
                .ok_or("customization host unavailable")?;
            session.session_changed(&session_id);
            let (mut reply, effect) = session.execute(action, &context)?;
            use orbit_frontend_protocol::customization::PaneAction;
            if let Some(effect) = effect {
                reply["effect"] = match effect {
                    PaneAction::InsertPrompt { text } => {
                        json!({"kind":"insert_draft","text":display_error(&text)})
                    }
                    PaneAction::FocusConversation => json!({"kind":"focus_conversation"}),
                    PaneAction::OwnerCancel => {
                        self.lease
                            .send(OwnerAction::Cancel)
                            .map_err(|e| e.to_string())?;
                        json!({"kind":"owner_cancel"})
                    }
                    PaneAction::Refresh => Value::Null,
                };
            }
            return Ok(reply);
        }
        if let Some(object) = value.as_object_mut() {
            match object
                .get("type")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_owned()
                .as_str()
            {
                "prompt" if !object.contains_key("request_id") => {
                    object.insert(
                        "request_id".into(),
                        json!(format!("browser-{}", ulid::Ulid::new())),
                    );
                }
                "approve" | "deny" => {
                    let deny = object.get("type").and_then(Value::as_str) == Some("deny");
                    let verdict = if deny {
                        "deny"
                    } else {
                        match object
                            .get("verdict")
                            .and_then(Value::as_str)
                            .unwrap_or("deny")
                        {
                            "allow" => "allow_once",
                            "session" => "allow_session",
                            "rule" => "allow_rule_session",
                            "always" => "allow_rule_always",
                            _ => "deny",
                        }
                    };
                    object.insert("type".into(), json!("approval"));
                    object.insert("verdict".into(), json!(verdict));
                    if !object.contains_key("note") {
                        object.insert("note".into(), Value::Null);
                    }
                }
                "resume" if !object.contains_key("session_id") => {
                    if let Some(id) = object.remove("id") {
                        object.insert("session_id".into(), id);
                    }
                }
                "quit" => {
                    object.insert("type".into(), json!("stop"));
                }
                _ => {}
            }
        }
        let action: OwnerAction = serde_json::from_value(value.clone())
            .map_err(|error| format!("invalid browser action: {error}"))?;
        // Serde's internally tagged unit variants can discard extra fields.
        // Compare against the shared action's serialized keys so those variants
        // obey the same strict frame contract as variants carrying fields.
        let canonical = serde_json::to_value(&action)
            .map_err(|error| format!("invalid browser action: {error}"))?;
        if let (Some(input), Some(expected)) = (value.as_object(), canonical.as_object()) {
            if input.keys().any(|key| !expected.contains_key(key)) {
                return Err("invalid browser action: unexpected field".into());
            }
        }
        let ack = self.lease.send(action).map_err(|error| error.to_string())?;
        let snapshot = self.owner.snapshot().map_err(|error| error.to_string())?;
        Ok(json!({"type":"action_ack","ack":ack,"snapshot":snapshot}))
    }
}

pub fn router(state: BridgeState) -> Router {
    Router::new()
        .route("/", get(serve_index))
        .route("/static/:path", get(serve_asset))
        .route("/events", get(sse_events))
        .route("/actions", get(ws_actions))
        .route("/customization", get(customization_get))
        .with_state(state)
}
async fn customization_get(
    State(state): State<BridgeState>,
    Query(query): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Response {
    if let Err(status) = authorized(&state, &query, &headers) {
        return (status, "browser authentication or origin refused").into_response();
    }
    match tokio::task::spawn_blocking(move || state.customization_snapshot()).await {
        Ok(Ok(value)) => ([(header::CACHE_CONTROL, "no-store")], axum::Json(value)).into_response(),
        Ok(Err(error)) => (StatusCode::UNPROCESSABLE_ENTITY, display_error(&error)).into_response(),
        Err(_) => (StatusCode::SERVICE_UNAVAILABLE, "customization unavailable").into_response(),
    }
}
async fn serve_index() -> Response {
    match Assets::get("index.html") {
        Some(asset) => (
            [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
            asset.data,
        )
            .into_response(),
        None => (StatusCode::NOT_FOUND, "missing index.html").into_response(),
    }
}
async fn serve_asset(axum::extract::Path(path): axum::extract::Path<String>) -> Response {
    let mime = mime_guess::from_path(&path).first_or_octet_stream();
    match Assets::get(&path) {
        Some(asset) => ([(header::CONTENT_TYPE, mime.as_ref())], asset.data).into_response(),
        None => (StatusCode::NOT_FOUND, "no such asset").into_response(),
    }
}
fn authorized(
    state: &BridgeState,
    query: &HashMap<String, String>,
    headers: &HeaderMap,
) -> Result<(), StatusCode> {
    if state
        .required_token
        .as_ref()
        .is_some_and(|token| query.get("token") != Some(token))
    {
        return Err(StatusCode::UNAUTHORIZED);
    }
    if state.owner.is_some() {
        let host = headers
            .get(header::HOST)
            .and_then(|value| value.to_str().ok())
            .ok_or(StatusCode::FORBIDDEN)?;
        let authority: axum::http::uri::Authority =
            host.parse().map_err(|_| StatusCode::FORBIDDEN)?;
        if authority.as_str().contains('@') {
            return Err(StatusCode::FORBIDDEN);
        }
        let name = authority
            .host()
            .trim_start_matches('[')
            .trim_end_matches(']');
        let loopback = name.eq_ignore_ascii_case("localhost")
            || name
                .parse::<std::net::IpAddr>()
                .is_ok_and(|address| address.is_loopback());
        let require_loopback = state
            .bound_address
            .is_none_or(|address| address.ip().is_loopback());
        if require_loopback && !loopback {
            return Err(StatusCode::FORBIDDEN);
        }
        if let Some(address) = state.bound_address {
            if authority.port_u16().unwrap_or(80) != address.port() {
                return Err(StatusCode::FORBIDDEN);
            }
            if !address.ip().is_loopback()
                && !address.ip().is_unspecified()
                && name.parse::<std::net::IpAddr>().ok() != Some(address.ip())
            {
                return Err(StatusCode::FORBIDDEN);
            }
        }
    }
    if let Some(origin) = headers.get(header::ORIGIN) {
        let origin = origin.to_str().map_err(|_| StatusCode::FORBIDDEN)?;
        let host = headers
            .get(header::HOST)
            .and_then(|host| host.to_str().ok())
            .ok_or(StatusCode::FORBIDDEN)?;
        if origin != format!("http://{host}") && origin != format!("https://{host}") {
            return Err(StatusCode::FORBIDDEN);
        }
    }
    Ok(())
}
fn recovery_frames(recovery: orbit_cli::daemon::Recovery) -> VecDeque<BridgeEvent> {
    let identity = recovery.snapshot.as_ref().map(|snapshot| json!({"model":snapshot.model,"provider":snapshot.provider,"session":snapshot.session_id.chars().take(8).collect::<String>(),"session_id":snapshot.session_id}));
    let mut frames = VecDeque::from([BridgeEvent {
        kind: "recovery".into(),
        payload: json!(recovery),
    }]);
    // Older protocol consumers still receive the initial identity frame.
    if let Some(payload) = identity {
        frames.push_back(BridgeEvent {
            kind: "identity".into(),
            payload,
        });
    }
    frames
}
fn event_frame(event: orbit_cli::daemon::OwnerEvent) -> BridgeEvent {
    let mut payload = event.payload;
    if let Some(object) = payload.as_object_mut() {
        object.insert("_cursor".into(), json!(event.cursor));
    }
    BridgeEvent {
        kind: event.kind,
        payload,
    }
}
fn display_error(message: &str) -> String {
    let scanned = orbit_tools::scan::scan_result(message);
    let mut output = String::new();
    for span in scanned.text.split_inclusive(|character: char| {
        !(character.is_ascii_alphanumeric() || character == '_' || character == '-')
    }) {
        output.push_str(&orbit_tools::scan::scan_result(span).text);
    }
    orbit_hud_tui::safe_text(&output)
}
fn sse_frame(event: BridgeEvent) -> Result<Event, Infallible> {
    Ok(Event::default()
        .event(event.kind)
        .data(event.payload.to_string()))
}

async fn sse_events(
    State(state): State<BridgeState>,
    Query(query): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Response {
    if let Err(status) = authorized(&state, &query, &headers) {
        return (status, "browser authentication or origin refused").into_response();
    }
    if let Some(owner) = state.owner {
        let cursor = match (query.get("instance"), query.get("sequence")) {
            (None, None) => None,
            (Some(instance), Some(sequence)) if instance.len() <= 128 => match sequence
                .parse::<u64>()
            {
                Ok(sequence) => Some(EventCursor {
                    instance: instance.clone(),
                    sequence,
                }),
                Err(_) => return (StatusCode::BAD_REQUEST, "invalid event cursor").into_response(),
            },
            _ => return (StatusCode::BAD_REQUEST, "incomplete event cursor").into_response(),
        };
        let subscription = match owner.subscribe(cursor.as_ref()) {
            Ok(subscription) => subscription,
            Err(_) => {
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "event subscriber limit reached",
                )
                    .into_response()
            }
        };
        let frames = recovery_frames(subscription.recovery.clone());
        let stream = futures::stream::unfold(
            (owner, Some(subscription), frames),
            |(owner, mut subscription, mut frames)| async move {
                loop {
                    if let Some(frame) = frames.pop_front() {
                        return Some((sse_frame(frame), (owner, subscription, frames)));
                    }
                    let receiver = subscription.take()?;
                    let (receiver, event) = tokio::task::spawn_blocking(move || {
                        let event = receiver.recv_timeout(Duration::from_millis(100));
                        (receiver, event)
                    })
                    .await
                    .ok()?;
                    subscription = Some(receiver);
                    match event {
                        Ok(event) => {
                            if event.kind == "identity" {
                                frames.push_back(BridgeEvent {
                                    kind: "model_changed".into(),
                                    payload: event.payload.clone(),
                                });
                            }
                            return Some((
                                sse_frame(event_frame(event)),
                                (owner, subscription, frames),
                            ));
                        }
                        Err(mpsc::RecvTimeoutError::Timeout) if !owner.is_stopping() => continue,
                        Err(mpsc::RecvTimeoutError::Timeout) => return None,
                        Err(mpsc::RecvTimeoutError::Disconnected) => {
                            // A bounded owner queue dropped this subscriber. Replace
                            // it with an atomic full snapshot and a new subscription.
                            drop(subscription.take());
                            let recovered = owner.subscribe(None).ok()?;
                            frames = recovery_frames(recovered.recovery.clone());
                            subscription = Some(recovered);
                        }
                    }
                }
            },
        );
        Sse::new(stream)
            .keep_alive(KeepAlive::default())
            .into_response()
    } else {
        let receiver = state.fixture_events.subscribe();
        let first = state
            .fixture_identity
            .lock()
            .ok()
            .and_then(|identity| identity.clone())
            .map(|payload| BridgeEvent {
                kind: "identity".into(),
                payload,
            });
        let stream =
            futures::stream::unfold((first, receiver), |(first, mut receiver)| async move {
                if let Some(event) = first {
                    return Some((sse_frame(event), (None, receiver)));
                }
                match receiver.recv().await {
                    Ok(event) => Some((sse_frame(event), (None, receiver))),
                    Err(_) => None,
                }
            });
        Sse::new(stream)
            .keep_alive(KeepAlive::default())
            .into_response()
    }
}
async fn ws_actions(
    State(state): State<BridgeState>,
    Query(query): Query<HashMap<String, String>>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Response {
    if let Err(status) = authorized(&state, &query, &headers) {
        return (status, "browser authentication or origin refused").into_response();
    }
    let controller = match state.claim_controller() {
        Ok(controller) => controller,
        Err(error) => return (StatusCode::CONFLICT, error).into_response(),
    };
    ws.max_message_size(70 * 1024)
        .max_frame_size(70 * 1024)
        .on_upgrade(move |socket| ws_pump(socket, controller))
}
async fn ws_pump(mut socket: WebSocket, mut controller: BridgeController) {
    if socket
        .send(Message::Text(
            json!({"type":"controller_ready"}).to_string(),
        ))
        .await
        .is_err()
    {
        return;
    }
    loop {
        let message = tokio::select! {
            message = socket.next() => message,
            _ = tokio::time::sleep(Duration::from_millis(100)) => {
                if controller.owner.is_stopping() { let _ = socket.close().await; return; }
                continue;
            }
        };
        let Some(Ok(message)) = message else {
            return;
        };
        let Message::Text(text) = message else {
            continue;
        };
        let value = serde_json::from_str::<Value>(&text);
        let response = match value {
            Ok(value) => {
                let Ok((returned, response)) = tokio::task::spawn_blocking(move || {
                    let response = controller.send(value);
                    (controller, response)
                })
                .await
                else {
                    return;
                };
                controller = returned;
                response
            }
            Err(_) => Err("invalid browser action JSON".into()),
        };
        let response = response.unwrap_or_else(
            |message| json!({"type":"action_error","message":display_error(&message)}),
        );
        if socket
            .send(Message::Text(response.to_string()))
            .await
            .is_err()
        {
            return;
        }
    }
    // Dropping this lease leaves the owned turn running and permits reconnect.
}

#[doc(hidden)]
pub fn __test_channels(token: Option<String>) -> (BridgeState, Arc<Mutex<mpsc::Receiver<Value>>>) {
    let (fixture_events, _) = broadcast::channel(16);
    let (_sender, receiver) = mpsc::channel();
    (
        BridgeState {
            owner: None,
            required_token: token,
            bound_address: None,
            customization: None,
            fixture_events,
            fixture_identity: Arc::new(Mutex::new(None)),
        },
        Arc::new(Mutex::new(receiver)),
    )
}
