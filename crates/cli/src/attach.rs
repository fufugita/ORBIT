//! Plain local client: disconnecting releases control without cancelling work.

use crate::daemon::{
    ActionAck, ApprovalChoice, EventCursor, OwnerAction, OwnerError, OwnerSnapshot, Recovery,
    TurnState,
};
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

const MAX_FRAME: usize = 256 * 1024;

#[cfg(unix)]
pub struct AttachClient {
    stream: BufReader<std::os::unix::net::UnixStream>,
    socket: PathBuf,
    controlling: bool,
    pub recovery: Recovery,
    cursor: EventCursor,
    healthy: bool,
}

#[cfg(unix)]
impl AttachClient {
    pub fn connect(
        socket: &Path,
        controlling: bool,
        cursor: Option<&EventCursor>,
    ) -> Result<Self, OwnerError> {
        let stream = crate::daemon::local_connect(socket)?;
        stream
            .set_read_timeout(Some(Duration::from_secs(12)))
            .map_err(io_error)?;
        stream
            .set_write_timeout(Some(Duration::from_secs(2)))
            .map_err(io_error)?;
        let mut stream = BufReader::new(stream);
        let recovery: Recovery = decode(rpc(
            &mut stream,
            json!({"type":"hello","controlling":controlling,"cursor":cursor}),
        )?)?;
        Ok(Self {
            stream,
            socket: socket.to_path_buf(),
            controlling,
            cursor: recovery.cursor.clone(),
            recovery,
            healthy: true,
        })
    }
    pub fn snapshot(&mut self) -> Result<OwnerSnapshot, OwnerError> {
        self.request(json!({"type":"status"}))
    }
    pub fn refresh(&mut self) -> Result<Recovery, OwnerError> {
        let recovery: Recovery = self.request(json!({"type":"subscribe","cursor":self.cursor}))?;
        self.cursor = recovery.cursor.clone();
        Ok(recovery)
    }
    pub fn logs(&mut self, cursor: Option<&EventCursor>) -> Result<Recovery, OwnerError> {
        self.request(json!({"type":"subscribe","cursor":cursor}))
    }
    pub fn send(&mut self, action: OwnerAction) -> Result<ActionAck, OwnerError> {
        if !self.controlling {
            return Err(OwnerError::NotController);
        }
        let request_id = match &action {
            OwnerAction::Prompt { request_id, .. } => Some(request_id.clone()),
            _ => None,
        };
        let value = self.request(json!({"type":"action","action":action}));
        match value{Ok(value)=>Ok(value),Err(error @ OwnerError::Protocol(_))=>Err(match request_id{Some(id)=>OwnerError::Runtime(format!("request {id}: outcome is unknown; inspect the session without resubmitting ({error})")),None=>error}),Err(error)=>Err(error)}
    }
    fn request<T: serde::de::DeserializeOwned>(&mut self, request: Value) -> Result<T, OwnerError> {
        if !self.healthy {
            return Err(OwnerError::Protocol("connection is closed after an uncertain response; reconnect explicitly before inspecting or sending another action".into()));
        }
        let result = rpc(&mut self.stream, request).and_then(decode);
        if matches!(&result, Err(OwnerError::Protocol(_))) {
            self.healthy = false;
            let _ = self.stream.get_mut().shutdown(std::net::Shutdown::Both);
        }
        result
    }
    pub fn prompt(&mut self, text: String) -> Result<ActionAck, OwnerError> {
        let request_id = ulid::Ulid::new().to_string();
        self.send(OwnerAction::Prompt { request_id, text })
    }
    /// Close the old stream before claiming a replacement controller.
    pub fn reconnect(self) -> Result<Self, OwnerError> {
        let socket = self.socket.clone();
        let controlling = self.controlling;
        let cursor = self.cursor.clone();
        drop(self);
        let until = std::time::Instant::now() + Duration::from_secs(2);
        loop {
            match Self::connect(&socket, controlling, Some(&cursor)) {
                Ok(client) => return Ok(client),
                Err(OwnerError::ControllerBusy) if std::time::Instant::now() < until => {
                    std::thread::sleep(Duration::from_millis(10))
                }
                Err(error) => return Err(error),
            }
        }
    }
}

#[cfg(unix)]
impl Drop for AttachClient {
    fn drop(&mut self) {
        let _ = self.stream.get_mut().shutdown(std::net::Shutdown::Both);
    }
}

fn io_error(error: std::io::Error) -> OwnerError {
    OwnerError::Protocol(error.to_string())
}
fn decode<T: serde::de::DeserializeOwned>(value: Value) -> Result<T, OwnerError> {
    serde_json::from_value(value).map_err(|error| OwnerError::Protocol(error.to_string()))
}

#[cfg(unix)]
fn rpc(
    stream: &mut BufReader<std::os::unix::net::UnixStream>,
    request: Value,
) -> Result<Value, OwnerError> {
    let request = serde_json::to_vec(&json!({"version":1,"request":request}))
        .map_err(|error| OwnerError::Protocol(error.to_string()))?;
    if request.len() > MAX_FRAME {
        return Err(OwnerError::Protocol(
            "request exceeds frame byte bound".into(),
        ));
    }
    stream.get_mut().write_all(&request).map_err(io_error)?;
    stream.get_mut().write_all(b"\n").map_err(io_error)?;
    let mut bytes = vec![];
    let deadline = std::time::Instant::now() + Duration::from_secs(12);
    loop {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            return Err(OwnerError::Protocol("response deadline exceeded".into()));
        }
        stream
            .get_mut()
            .set_read_timeout(Some(remaining))
            .map_err(io_error)?;
        let buffer = stream.fill_buf().map_err(io_error)?;
        if buffer.is_empty() {
            break;
        }
        let newline = buffer.iter().position(|byte| *byte == b'\n');
        let count = newline.map_or(buffer.len(), |index| index + 1);
        if bytes.len() + count > MAX_FRAME {
            return Err(OwnerError::Protocol(
                "response exceeds frame byte bound".into(),
            ));
        }
        bytes.extend_from_slice(&buffer[..count]);
        stream.consume(count);
        if newline.is_some() {
            break;
        }
    }
    if bytes.len() > MAX_FRAME || bytes.last() != Some(&b'\n') {
        return Err(OwnerError::Protocol(
            "response is missing, incomplete or exceeds frame byte bound".into(),
        ));
    }
    let response: Value =
        serde_json::from_slice(&bytes).map_err(|error| OwnerError::Protocol(error.to_string()))?;
    if response.get("ok").and_then(Value::as_bool) != Some(true) {
        let message = response
            .get("error")
            .and_then(Value::as_str)
            .unwrap_or("request refused")
            .to_owned();
        return Err(match response.get("code").and_then(Value::as_str) {
            Some("controller_busy") => OwnerError::ControllerBusy,
            Some("not_controller") => OwnerError::NotController,
            Some("busy") => OwnerError::Busy,
            Some("invalid") => OwnerError::Invalid(message),
            Some("publication_uncertain") => OwnerError::Storage(
                crate::sessions::SessionLeaseError::PublicationUncertain(message),
            ),
            Some("runtime" | "storage") => OwnerError::Runtime(message),
            _ => OwnerError::Protocol(message),
        });
    }
    response
        .get("value")
        .cloned()
        .ok_or_else(|| OwnerError::Protocol("response has no value".into()))
}

fn display(text: &str) -> String {
    crate::daemon::scan_display(text)
}

pub fn render_snapshot(
    snapshot: &OwnerSnapshot,
    output: &mut impl Write,
) -> Result<(), OwnerError> {
    writeln!(
        output,
        "Session {} · {}/{} · {:?}",
        display(&snapshot.session_id),
        display(&snapshot.provider),
        display(&snapshot.model),
        snapshot.state
    )
    .map_err(io_error)?;
    writeln!(output, "{}", display(&snapshot.effort_status)).map_err(io_error)?;
    for message in &snapshot.messages {
        if let Some(text) = message.get("text").and_then(Value::as_str) {
            writeln!(
                output,
                "{}: {}",
                display(
                    message
                        .get("role")
                        .and_then(Value::as_str)
                        .unwrap_or("status")
                ),
                display(text)
            )
            .map_err(io_error)?;
        }
    }
    if !snapshot.partial_response.is_empty() {
        write!(output, "{}", display(&snapshot.partial_response)).map_err(io_error)?;
    }
    for card in &snapshot.pending_approvals {
        render_approval(card, output)?;
    }
    output.flush().map_err(io_error)
}

fn render_approval(card: &Value, output: &mut impl Write) -> Result<(), OwnerError> {
    let id = display(
        card.get("call_id")
            .and_then(Value::as_str)
            .unwrap_or("unknown"),
    );
    writeln!(
        output,
        "Approval {id}: {} — {}\n/approve {id} [once|session|rule|always] or /deny {id} [note]",
        display(
            card.get("tool_name")
                .and_then(Value::as_str)
                .unwrap_or("tool")
        ),
        display(card.get("summary").and_then(Value::as_str).unwrap_or(""))
    )
    .map_err(io_error)
}

pub fn render_recovery(recovery: &Recovery, output: &mut impl Write) -> Result<(), OwnerError> {
    if let Some(snapshot) = &recovery.snapshot {
        render_snapshot(snapshot, output)?;
    }
    for event in &recovery.events {
        match event.kind.as_str() {
            "text_delta" => write!(
                output,
                "{}",
                display(
                    event
                        .payload
                        .get("text")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                )
            )
            .map_err(io_error)?,
            "approval_requested" => render_approval(&event.payload, output)?,
            "response_finished" | "request_finished" => writeln!(output).map_err(io_error)?,
            "error" | "status" => writeln!(
                output,
                "{}",
                display(
                    event
                        .payload
                        .get("message")
                        .or_else(|| event.payload.get("text"))
                        .and_then(Value::as_str)
                        .unwrap_or("")
                )
            )
            .map_err(io_error)?,
            "tool_started_full" | "tool_started" => writeln!(
                output,
                "Tool: {}",
                display(
                    event
                        .payload
                        .get("name")
                        .or_else(|| event.payload.get("tool_name"))
                        .or_else(|| event.payload.get("kind"))
                        .and_then(Value::as_str)
                        .unwrap_or("tool")
                )
            )
            .map_err(io_error)?,
            "models" | "sessions" | "routing" => writeln!(
                output,
                "{}: {}",
                event.kind,
                display(&serde_json::to_string(&event.payload).unwrap_or_default())
            )
            .map_err(io_error)?,
            _ => {}
        }
    }
    output.flush().map_err(io_error)
}

#[cfg(unix)]
pub fn status(socket: &Path) -> Result<OwnerSnapshot, OwnerError> {
    AttachClient::connect(socket, false, None)?.snapshot()
}
#[cfg(unix)]
pub fn logs(socket: &Path, cursor: Option<&EventCursor>) -> Result<Recovery, OwnerError> {
    AttachClient::connect(socket, false, None)?.logs(cursor)
}
#[cfg(unix)]
pub fn cancel(socket: &Path) -> Result<ActionAck, OwnerError> {
    AttachClient::connect(socket, true, None)?.send(OwnerAction::Cancel)
}
#[cfg(unix)]
pub fn stop(socket: &Path) -> Result<ActionAck, OwnerError> {
    AttachClient::connect(socket, true, None)?.send(OwnerAction::Stop)
}

#[cfg(unix)]
fn input_action(
    client: &mut AttachClient,
    line: &str,
    output: &mut impl Write,
) -> Result<bool, OwnerError> {
    let line = line.trim_end_matches(['\r', '\n']);
    match line {
        "/detach" | "/quit" => return Ok(false),
        "/status" => render_snapshot(&client.snapshot()?, output)?,
        "/logs" => render_recovery(&client.logs(None)?, output)?,
        "/effort" => {
            client.send(OwnerAction::Effort)?;
            render_snapshot(&client.snapshot()?, output)?;
        }
        line if line.starts_with("/effort ") => {
            let choice = crate::parse_effort_setting(line.trim_start_matches("/effort ").trim())
                .map_err(OwnerError::Invalid)?;
            client.send(OwnerAction::SetEffort { choice })?;
            render_snapshot(&client.snapshot()?, output)?;
        }
        "/route" | "/route status" => {
            client.send(OwnerAction::Routing)?;
        }
        "/route auto" => {
            client.send(OwnerAction::RouteAuto)?;
            render_snapshot(&client.snapshot()?, output)?;
        }
        "/model" => render_snapshot(&client.snapshot()?, output)?,
        line if line.starts_with("/model ") => {
            client.send(OwnerAction::SetModel {
                model: line.trim_start_matches("/model ").trim().into(),
                provider: None,
            })?;
            render_snapshot(&client.snapshot()?, output)?;
        }
        line if line.starts_with("/mode ") => {
            client.send(OwnerAction::SetMode {
                mode: line.trim_start_matches("/mode ").trim().into(),
            })?;
        }
        line if line.starts_with("/resume ") => {
            client.send(OwnerAction::Resume {
                session_id: line.trim_start_matches("/resume ").trim().into(),
            })?;
            render_snapshot(&client.snapshot()?, output)?;
        }
        "/models" => {
            client.send(OwnerAction::ListModels)?;
        }
        "/sessions" => {
            client.send(OwnerAction::ListSessions)?;
        }
        "/cancel" => {
            client.send(OwnerAction::Cancel)?;
        }
        "/stop" => {
            client.send(OwnerAction::Stop)?;
            return Ok(false);
        }
        line if line.starts_with("/approve ") => {
            let mut words = line.split_whitespace();
            words.next();
            let id = words
                .next()
                .ok_or_else(|| OwnerError::Invalid("approval ID required".into()))?;
            let verdict = match words.next().unwrap_or("once") {
                "once" => ApprovalChoice::AllowOnce,
                "session" => ApprovalChoice::AllowSession,
                "rule" => ApprovalChoice::AllowRuleSession,
                "always" => ApprovalChoice::AllowRuleAlways,
                _ => return Err(OwnerError::Invalid("unknown approval choice".into())),
            };
            client.send(OwnerAction::Approval {
                call_id: id.into(),
                verdict,
                note: None,
            })?;
        }
        line if line.starts_with("/deny ") => {
            let text = line.trim_start_matches("/deny ");
            let (id, note) = text
                .split_once(' ')
                .map_or((text, None), |(id, note)| (id, Some(note.to_owned())));
            client.send(OwnerAction::Approval {
                call_id: id.into(),
                verdict: ApprovalChoice::Deny,
                note,
            })?;
        }
        line if line.starts_with('/') => {
            return Err(OwnerError::Invalid("unknown attach command".into()))
        }
        line if line.trim().is_empty() => {}
        line => {
            let acknowledged = client.prompt(line.into())?;
            writeln!(
                output,
                "Request {} accepted",
                display(acknowledged.request_id.as_deref().unwrap_or("unknown"))
            )
            .map_err(io_error)?;
        }
    }
    Ok(true)
}

/// Synchronous input adapter for pipes and deterministic plain-view fixtures.
#[cfg(unix)]
pub fn run_with_io(
    socket: &Path,
    input: &mut impl BufRead,
    output: &mut impl Write,
) -> Result<(), OwnerError> {
    let mut client = AttachClient::connect(socket, true, None)?;
    render_recovery(&client.recovery, output)?;
    loop {
        let mut line = String::new();
        let read = Read::by_ref(input)
            .take(64 * 1024 + 1)
            .read_line(&mut line)
            .map_err(io_error)?;
        if read == 0 {
            return Ok(());
        }
        if line.len() > 64 * 1024 {
            return Err(OwnerError::Invalid("prompt exceeds byte bound".into()));
        }
        if !input_action(&mut client, &line, output)? {
            return Ok(());
        }
        render_recovery(&client.refresh()?, output)?;
    }
}

/// Interactive input and event polling stay independent during a running turn.
#[cfg(unix)]
pub fn run_interactive(socket: &Path) -> Result<(), OwnerError> {
    let mut client = AttachClient::connect(socket, true, None)?;
    let mut output = std::io::stdout().lock();
    render_recovery(&client.recovery, &mut output)?;
    writeln!(
        output,
        "/detach leaves work running · /cancel interrupts · /stop ends the owner · /effort [choice|default] · /model [model]"
    )
    .map_err(io_error)?;
    let (sender, receiver) = std::sync::mpsc::sync_channel(16);
    std::thread::spawn(move || {
        let stdin = std::io::stdin();
        let mut input = stdin.lock();
        loop {
            let mut line = String::new();
            let read = Read::by_ref(&mut input)
                .take(64 * 1024 + 1)
                .read_line(&mut line);
            match read {
                Ok(0) => break,
                Ok(_) if line.len() <= 64 * 1024 => {
                    if sender.send(Ok(line)).is_err() {
                        break;
                    }
                }
                Ok(_) => {
                    let _ = sender.send(Err("prompt exceeds byte bound".to_owned()));
                    break;
                }
                Err(error) => {
                    let _ = sender.send(Err(error.to_string()));
                    break;
                }
            }
        }
    });
    loop {
        match receiver.recv_timeout(Duration::from_millis(100)) {
            Ok(Ok(line)) => match input_action(&mut client, &line, &mut output) {
                Ok(false) => return Ok(()),
                Ok(true) => {}
                Err(error) => {
                    writeln!(output, "{}", display(&error.to_string())).map_err(io_error)?;
                }
            },
            Ok(Err(error)) => return Err(OwnerError::Invalid(error)),
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => return Ok(()),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
        }
        let recovery = client.refresh()?;
        let stopped = recovery
            .snapshot
            .as_ref()
            .is_some_and(|snapshot| snapshot.state == TurnState::Stopped)
            || recovery.events.iter().any(|event| event.kind == "stopped");
        render_recovery(&recovery, &mut output)?;
        if stopped {
            return Ok(());
        }
    }
}
