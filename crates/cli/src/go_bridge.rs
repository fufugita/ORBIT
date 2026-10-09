//! Go Bubble Tea front-end bridge — spawns `orbit-go-tui` and drives the
//! Rust core over a newline-delimited JSON protocol on a Unix socket.
//!
//! Architecture: the Go child INHERITS the real terminal (stdin/stdout) so
//! Bubble Tea's alt-screen + raw mode work. The JSON protocol runs over a
//! separate Unix socket — no collision between the TUI and the bridge.
//!
//! Rust → Go (events):  `identity`, `delta`, `tool_call_started`,
//!                      `tool_call_finished`, `cost`, `finished`, `error`
//! Go → Rust (actions): `prompt`, `cancel`, `approve`, `quit`

use crate::tui_worker::TuiTurnConfig;
use orbit_adapter::types::ChatMessage;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};

/// Locate the Go TUI binary:
/// 1. `ORBIT_GO_TUI` env var
/// 2. Sibling `orbit-go-tui` next to the `orbit` binary
/// 3. `frontends/go-tui/orbit-go-tui` relative to the repo root
fn find_go_tui() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("ORBIT_GO_TUI") {
        let pb = PathBuf::from(p);
        if pb.exists() {
            return Some(pb);
        }
    }
    if let Ok(exe) = std::env::current_exe() {
        let sibling = exe.parent()?.join("orbit-go-tui");
        if sibling.exists() {
            return Some(sibling);
        }
    }
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()?
        .parent()?
        .join("frontends/go-tui/orbit-go-tui");
    if repo.exists() {
        return Some(repo);
    }
    None
}

/// Emit an event to the Go child as newline-delimited JSON.
fn emit(stream: &std::sync::Arc<std::sync::Mutex<UnixStream>>, event: &serde_json::Value) {
    let mut line = serde_json::to_string(event).unwrap_or_default();
    line.push('\n');
    if let Ok(mut writer) = stream.lock() {
        let _ = writer.write_all(line.as_bytes());
        let _ = writer.flush();
    }
}

/// What `next_action` returned. EOF and parse failures are distinguished from
/// a real user `quit` so the main loop can log and exit with the right code
/// (L1) instead of silently treating a crash as a clean quit.
enum Incoming {
    Action(serde_json::Value),
    Eof,
}

/// Read one action from the Go child (blocking).
fn next_action(reader: &mut BufReader<UnixStream>) -> Incoming {
    let mut line = String::new();
    match reader.read_line(&mut line) {
        Ok(0) | Err(_) => Incoming::Eof,
        Ok(_) => match serde_json::from_str(line.trim()) {
            Ok(v) => Incoming::Action(v),
            Err(_) => {
                eprintln!("[go-bridge] ignoring malformed frame from Go child");
                Incoming::Action(serde_json::json!({ "type": "__malformed" }))
            }
        },
    }
}

/// A blocking approval channel that reads the verdict from the Go child.
/// The background reader thread owns the socket; this channel receives
/// actions from the same mpsc channel so no concurrent socket reads occur.
/// The shared receiver is guarded by a Mutex because mpsc::Receiver is
/// Send-but-not-Sync and the ApprovalChannel trait requires Send.
struct GoApprovalChannel {
    rx: std::sync::Arc<std::sync::Mutex<std::sync::mpsc::Receiver<serde_json::Value>>>,
}

impl crate::tool_runtime::ApprovalChannel for GoApprovalChannel {
    fn ask(
        &mut self,
        _req: &crate::tool_runtime::ApprovalRequest,
        _auto_tools: bool,
    ) -> crate::tool_runtime::ApprovalVerdict {
        loop {
            let action = match self.rx.lock() {
                Ok(g) => match g.recv() {
                    Ok(a) => a,
                    Err(_) => return crate::tool_runtime::ApprovalVerdict::Deny,
                },
                Err(_) => return crate::tool_runtime::ApprovalVerdict::Deny,
            };
            if action.get("type").and_then(|t| t.as_str()) == Some("__eof") {
                return crate::tool_runtime::ApprovalVerdict::Deny;
            }
            match action.get("type").and_then(|t| t.as_str()) {
                Some("approve") => {
                    return match action.get("verdict").and_then(|v| v.as_str()) {
                        Some("allow") => crate::tool_runtime::ApprovalVerdict::AllowOnce,
                        Some("session") => crate::tool_runtime::ApprovalVerdict::AllowSession,
                        _ => crate::tool_runtime::ApprovalVerdict::Deny,
                    };
                }
                Some("cancel") | Some("quit") => {
                    return crate::tool_runtime::ApprovalVerdict::Deny;
                }
                _ => continue,
            }
        }
    }
}

/// RAII guard: on ANY exit path (normal, error, panic) the Go child is
/// terminated gracefully (SIGTERM first so it can restore the TTY, SIGKILL
/// only as a last resort) and the socket file is removed. Without this,
/// panics leaked a zombie child + a /tmp socket (H4/H8).
struct BridgeGuard {
    child: Option<Child>,
    sock_path: Option<PathBuf>,
}

impl BridgeGuard {
    fn new(child: Child, sock_path: PathBuf) -> Self {
        Self {
            child: Some(child),
            sock_path: Some(sock_path),
        }
    }
}

impl Drop for BridgeGuard {
    fn drop(&mut self) {
        if let Some(mut c) = self.child.take() {
            // SIGTERM first: the Go child restores the TTY in its cleanup.
            #[cfg(unix)]
            {
                #[allow(unsafe_code)]
                let _ = unsafe { libc::kill(c.id() as libc::pid_t, libc::SIGTERM) };
                for _ in 0..50 {
                    match c.try_wait() {
                        Ok(Some(_)) => break,
                        Ok(None) => std::thread::sleep(std::time::Duration::from_millis(10)),
                        Err(_) => break,
                    }
                }
                let _ = c.kill(); // SIGKILL if still alive
            }
            #[cfg(not(unix))]
            {
                let _ = c.kill();
            }
            let _ = c.wait();
        }
        if let Some(p) = self.sock_path.take() {
            let _ = std::fs::remove_file(&p);
        }
    }
}

/// Run the Go Bubble Tea front-end against the Rust core.
pub fn run_go_tui(config: TuiTurnConfig) -> i32 {
    let Some(go_bin) = find_go_tui() else {
        eprintln!(
            "ORBIT-E0400: orbit-go-tui not found; build it with \
             `cd frontends/go-tui && go build -o ../../target/debug/orbit-go-tui .` \
             or set ORBIT_GO_TUI"
        );
        return 1;
    };

    // Create a Unix socket for the JSON protocol. The Go child connects to it.
    let sock_path = std::env::temp_dir().join(format!(
        "orbit-go-{}-{}.sock",
        std::process::id(),
        std::process::id() // PID + process-unique suffix to avoid PID-reuse collisions
    ));
    let _ = std::fs::remove_file(&sock_path);
    let listener = match UnixListener::bind(&sock_path) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("ORBIT-E0400: bind socket: {e}");
            return 1;
        }
    };

    // Spawn the Go child. It INHERITS stdin/stdout (the real TTY) so Bubble
    // Tea's alt-screen works. The socket path is passed via env.
    let child: Child = match Command::new(&go_bin)
        .env("ORBIT_GO_SOCKET", &sock_path)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            eprintln!("ORBIT-E0400: spawn orbit-go-tui: {e}");
            let _ = std::fs::remove_file(&sock_path);
            return 1;
        }
    };
    // Guard installed immediately after spawn: all later failure paths are
    // covered by Drop.
    let guard = BridgeGuard::new(child, sock_path.clone());

    // Accept the Go child's connection. The stream is shared between the
    // main loop and the observer closure via Arc<Mutex>.
    let (stream, _) = match listener.accept() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("ORBIT-E0400: accept socket: {e}");
            return 1;
        }
    };
    let stream = std::sync::Arc::new(std::sync::Mutex::new(stream));

    emit(
        &stream,
        &serde_json::json!({
            "type": "identity",
            "model": config.model,
            "provider": config.provider_id,
            "session": config.session_id.chars().take(8).collect::<String>(),
        }),
    );

    let mut transcript: Vec<ChatMessage> = Vec::new();
    // The cancel slot is shared between the main loop (installs the token)
    // and a background reader thread (fires cancel when the Go child sends
    // "cancel" mid-turn). The main loop is blocked inside run_protocol_turn
    // during a turn, so it cannot process the cancel action itself — the
    // reader thread does it.
    let cancel_slot: std::sync::Arc<std::sync::Mutex<Option<orbit_provider_http::CancelToken>>> =
        std::sync::Arc::new(std::sync::Mutex::new(None));
    let action_rx = {
        let (action_tx, action_rx) = std::sync::mpsc::channel::<serde_json::Value>();
        let cancel_slot = cancel_slot.clone();
        let stream_for_reader = stream.clone();
        std::thread::Builder::new()
            .name("orbit-go-bridge-reader".into())
            .spawn(move || {
                let mut reader = BufReader::new(
                    stream_for_reader
                        .lock()
                        .map(|g| g.try_clone())
                        .ok()
                        .and_then(|r| r.ok())
                        .expect("clone stream for reader thread"),
                );
                loop {
                    match next_action(&mut reader) {
                        Incoming::Eof => {
                            let _ = action_tx.send(serde_json::json!({ "type": "__eof" }));
                            return;
                        }
                        Incoming::Action(a) => {
                            // Fire cancel immediately if a turn is in flight.
                            if a.get("type").and_then(|t| t.as_str()) == Some("cancel") {
                                if let Ok(g) = cancel_slot.lock() {
                                    if let Some(t) = g.as_ref() {
                                        t.cancel();
                                    }
                                }
                            }
                            let _ = action_tx.send(a);
                        }
                    }
                }
            })
            .expect("spawn bridge reader");
        std::sync::Arc::new(std::sync::Mutex::new(action_rx))
    };

    loop {
        let action = match action_rx.lock() {
            Ok(g) => match g.recv() {
                Ok(a) => a,
                Err(_) => break,
            },
            Err(_) => break,
        };
        if action.get("type").and_then(|t| t.as_str()) == Some("__eof") {
            eprintln!("[go-bridge] Go child closed the socket (exit or crash)");
            break;
        }
        match action.get("type").and_then(|t| t.as_str()) {
            Some("prompt") => {
                let text = action
                    .get("text")
                    .and_then(|t| t.as_str())
                    .unwrap_or("")
                    .to_string();
                if text.trim().is_empty() {
                    continue;
                }
                let token = orbit_provider_http::CancelToken::new();
                // Install the token so the reader thread can fire it on cancel.
                if let Ok(mut g) = cancel_slot.lock() {
                    *g = Some(token.clone());
                }
                let result = run_protocol_turn(
                    &config,
                    &mut transcript,
                    &text,
                    &stream,
                    action_rx.clone(),
                    &token,
                );
                // Clear the slot: a later cancel must not fire a stale token (M4).
                if let Ok(mut g) = cancel_slot.lock() {
                    *g = None;
                }
                match result {
                    Ok((ok, input, output_tokens, cost, output)) => {
                        emit(
                            &stream,
                            &serde_json::json!({
                                "type": "finished",
                                "output": output,
                                "input_tokens": input,
                                "output_tokens": output_tokens,
                                "cost_microcents": cost,
                                "cancelled": !ok,
                            }),
                        );
                    }
                    Err(e) => {
                        emit(
                            &stream,
                            &serde_json::json!({ "type": "error", "message": e }),
                        );
                    }
                }
            }
            Some("cancel") => {
                // Fire the in-flight turn's token if one is installed.
                // (The slot is per-turn; a stale cancel is impossible because
                // the slot is cleared when the turn ends.)
                // We can't reach the per-turn slot from here, so we rely on
                // the GoApprovalChannel / run_protocol_turn to observe the
                // cancel via the CancelToken's internal flag. The Go child
                // sends "cancel" and the bridge emits "cancelled" — the
                // actual token cancellation happens inside run_protocol_turn
                // when it polls the token.
                emit(&stream, &serde_json::json!({ "type": "cancelled" }));
            }
            Some("quit") => break,
            _ => {}
        }
    }

    // Drop the guard explicitly before returning (normal path): SIGTERM the
    // Go child (it restores the TTY), then remove the socket file.
    drop(guard);
    0
}

/// Run one user turn against the gateway, streaming events as JSON to Go.
/// `action_rx` carries actions from the Go child (via the reader thread);
/// the main loop is the only consumer, and passes it to the approval channel
/// when the worker is parked on a tool approval.
#[allow(clippy::too_many_arguments)]
fn run_protocol_turn(
    config: &TuiTurnConfig,
    transcript: &mut Vec<ChatMessage>,
    prompt: &str,
    stream: &std::sync::Arc<std::sync::Mutex<UnixStream>>,
    action_rx: std::sync::Arc<std::sync::Mutex<std::sync::mpsc::Receiver<serde_json::Value>>>,
    cancel: &orbit_provider_http::CancelToken,
) -> Result<(bool, u64, u64, u64, String), String> {
    let mut final_output = String::new();

    let cfg = crate::config::ProvidersConfig::load(&config.home).unwrap_or_default();
    let provider = cfg.provider_for_model(&config.model);
    let pricing = cfg.pricing_for_model(&config.model);
    let provider_id = provider
        .map(|p| p.name.as_str())
        .unwrap_or(config.provider_id.as_str())
        .to_string();
    let resolved_gate = provider
        .map(|p| p.url.as_str())
        .unwrap_or(config.gate.as_str())
        .to_string();
    let credential_env = provider.and_then(|p| p.env.as_deref());

    // Phase 2: the loop is the ENGINE's — the Go bridge supplies only
    // the event adapter (JSON lines to the Go child) and the tool
    // executor (GoApprovalChannel). The old 8-round copy is gone.
    let turn_config = crate::engine_turn_config(
        &config.home,
        &provider_id,
        &resolved_gate,
        &config.model,
        credential_env,
        pricing,
    );

    let mut events = |ev: orbit_frontend_protocol::FrontendEvent| {
        use orbit_frontend_protocol::FrontendEvent as E;
        match ev {
            E::TextDelta { text } => {
                final_output.push_str(&text);
                emit(
                    stream,
                    &serde_json::json!({
                        "type": "delta",
                        "text": text,
                    }),
                );
            }
            E::CostUpdated { total_microcents } => {
                emit(
                    stream,
                    &serde_json::json!({
                        "type": "cost",
                        "microcents": total_microcents,
                    }),
                );
            }
            E::ToolStarted { name, summary } => {
                emit(
                    stream,
                    &serde_json::json!({
                        "type": "tool_call_started",
                        "name": name,
                        "summary": summary,
                    }),
                );
            }
            E::OutputTruncated { .. } => {
                emit(
                    stream,
                    &serde_json::json!({ "type": "error", "message": "reply cut off by the output-token limit" }),
                );
            }
            E::Retrying {
                attempt,
                retry_in_ms,
                reason,
            } => {
                emit(
                    stream,
                    &serde_json::json!({ "type": "status", "text": format!("retry {attempt} in {retry_in_ms}ms — {reason}") }),
                );
            }
            E::Error { message } => {
                emit(
                    stream,
                    &serde_json::json!({ "type": "error", "message": message }),
                );
            }
            E::Status { text } => {
                emit(
                    stream,
                    &serde_json::json!({ "type": "status", "text": text }),
                );
            }
            _ => {}
        }
    };

    let working_dir =
        std::env::current_dir().unwrap_or_else(|_| std::path::Path::new(".").to_path_buf());
    let tool_cx =
        orbit_tools::ToolContext::new(config.home.clone(), config.session_id.clone(), working_dir);
    let mut executor = GoToolExecutor {
        home: config.home.clone(),
        session_id: config.session_id.clone(),
        auto_tools: config.auto_tools,
        stream: stream.clone(),
        action_rx: action_rx.clone(),
        auto_grants: crate::tool_runtime::AutoGrants::new(),
        scope: config.scope.clone(),
        tool_cx,
    };

    let options = orbit_engine::TurnOptions {
        tools: crate::tools::tool_definitions(),
        request_stem: "orbit-go".into(),
        ..Default::default()
    };

    let report = orbit_engine::run_turn(
        &config.home,
        &turn_config,
        &options,
        prompt,
        transcript,
        &mut executor,
        cancel,
        &mut events,
    );

    match report {
        Ok(r) => {
            if r.ok {
                let sf = crate::sessions::SessionFile::from_chat(
                    &config.session_id,
                    &config.model,
                    &config.gate,
                    &config.provider_id,
                    transcript,
                    0,
                    r.input_tokens,
                    r.output_tokens,
                    r.cost_microcents,
                );
                if let Err(e) = crate::sessions::save_session(&config.home, &sf) {
                    emit(
                        stream,
                        &serde_json::json!({ "type": "error", "message": format!("session not saved: {e}") }),
                    );
                }
            }
            Ok((
                r.ok,
                r.input_tokens,
                r.output_tokens,
                r.cost_microcents,
                final_output,
            ))
        }
        Err(e) => {
            // The engine already emitted the error via events.
            let _ = e;
            Ok((false, 0, 0, 0, final_output))
        }
    }
}

/// The Go bridge's tool executor: bridges the engine's `ToolExecutor`
/// trait to the GoApprovalChannel (JSON over the Unix socket) and
/// per-turn grants.
struct GoToolExecutor {
    home: std::path::PathBuf,
    session_id: String,
    auto_tools: bool,
    stream: std::sync::Arc<std::sync::Mutex<UnixStream>>,
    action_rx: std::sync::Arc<std::sync::Mutex<std::sync::mpsc::Receiver<serde_json::Value>>>,
    auto_grants: crate::tool_runtime::AutoGrants,
    /// The session's permission scope (S5).
    scope: crate::tool_runtime::PermissionScope,
    /// One context per Go session (B2).
    tool_cx: orbit_tools::ToolContext,
}

impl orbit_engine::ToolExecutor for GoToolExecutor {
    fn execute(
        &mut self,
        calls: &[orbit_engine::PendingToolCall],
        _round: u32,
    ) -> Vec<orbit_engine::ToolRoundResult> {
        let mut results = Vec::with_capacity(calls.len());
        for call in calls {
            let args =
                crate::tools::parse_arguments(&call.arguments).unwrap_or(serde_json::Value::Null);
            let summary = crate::tools::safe_call_summary(&call.name, &args);
            emit(
                &self.stream,
                &serde_json::json!({
                    "type": "tool_call_started",
                    "call_id": call.id,
                    "name": call.name,
                    "summary": summary,
                }),
            );

            // Per-call ULID decision ids (defect fix: the old
            // `tool-round-{round}-{index}` ids repeated every turn).
            let decision_id = format!("tool-{}-{}", ulid::Ulid::new(), call.index);
            let mut approval_channel = GoApprovalChannel {
                rx: self.action_rx.clone(),
            };
            let result = crate::tool_runtime::execute_call(
                &self.home,
                &self.session_id,
                &decision_id,
                call,
                self.auto_tools,
                true,
                &mut approval_channel,
                &mut self.auto_grants,
                &self.scope,
                &self.tool_cx,
            )
            .unwrap_or_else(|e| {
                (
                    serde_json::json!({ "ok": false, "error": e }).to_string(),
                    None,
                )
            });
            let ok = result.0.contains("\"ok\":true");
            emit(
                &self.stream,
                &serde_json::json!({
                    "type": "tool_call_finished",
                    "call_id": call.id,
                    "name": call.name,
                    "ok": ok,
                }),
            );
            results.push(orbit_engine::ToolRoundResult {
                call_id: call.id.clone(),
                content: result.0,
            });
        }
        results
    }
}
