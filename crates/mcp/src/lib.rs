//! Bounded JSON-RPC MCP clients for stdio, Streamable HTTP and legacy SSE servers.
//!
//! Unix pipes are nonblocking: waiting for a server never owns a blocking read
//! thread. Each call has one deadline, including its pool wait and handshake.
//! Failed transports are retired; only a subsequent explicit call reconnects.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::{Read, Write};
#[cfg(unix)]
use std::os::fd::{AsRawFd, RawFd};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, TryLockError};
use std::time::{Duration, Instant};

mod http;
mod legacy;
pub mod oauth;

pub const MAX_FRAME_BYTES: usize = 1024 * 1024;
/// The most one server reply may hold.
pub const MAX_REPLY_BYTES: usize = 16 * 1024 * 1024;

/// A line a server wrote to standard output that is not JSON-RPC at all: it does not parse and
/// it is not the start of a JSON object. A banner, a log line or a usage text (a dotenv tip, an
/// `[INFO]` line) lands here, and the official clients skip it. A line that starts with `{` and
/// does not parse is a frame cut off in the middle, and a line that parses as something other
/// than an object is a protocol error: neither is noise.
fn is_log_noise(line: &[u8]) -> bool {
    serde_json::from_slice::<serde_json::Value>(line).is_err()
        && !line.trim_ascii_start().starts_with(b"{")
}

fn reply_too_large() -> String {
    format!("mcp input frame exceeds {} MiB", MAX_REPLY_BYTES >> 20)
}

/// The size `value` would have as JSON, without building it.
fn json_len(value: &serde_json::Value) -> Result<usize, String> {
    struct Count(usize);
    impl Write for Count {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0 = self.0.saturating_add(bytes.len());
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut count = Count(0);
    serde_json::to_writer(&mut count, value).map_err(|_| "mcp tool metadata is not JSON")?;
    Ok(count.0)
}
const MAX_TOOL_PAGES: usize = 32;
const MAX_TOOLS: usize = 4096;
const POLL_INTERVAL: Duration = Duration::from_millis(10);
const MAX_TIMEOUT_MS: u64 = 600_000;
fn default_enabled() -> bool {
    true
}
fn default_timeout_ms() -> u64 {
    30_000
}
fn default_initialize_timeout_ms() -> u64 {
    5_000
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum McpTransport {
    #[default]
    Stdio,
    StreamableHttp,
    Sse,
}

/// One configured server entry. Tool names are exact server names, not wire names.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct McpServerConfig {
    #[serde(default)]
    pub transport: McpTransport,
    #[serde(default)]
    pub command: String,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    /// None exposes all tools; an empty list exposes none.
    #[serde(default)]
    pub tools: Option<Vec<String>>,
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
    #[serde(default = "default_initialize_timeout_ms")]
    pub initialize_timeout_ms: u64,
}

impl McpServerConfig {
    pub fn validate(&self) -> Result<(), String> {
        match self.transport {
            McpTransport::Stdio => {
                if self.command.trim().is_empty() {
                    return Err("mcp command must not be empty".into());
                }
                if self.url.is_some() || !self.headers.is_empty() {
                    return Err(
                        "mcp stdio configuration cannot contain a URL or HTTP headers".into(),
                    );
                }
            }
            McpTransport::StreamableHttp | McpTransport::Sse => {
                if !self.command.is_empty() || !self.args.is_empty() || !self.env.is_empty() {
                    return Err(
                        "mcp remote configuration cannot contain command, args or env".into(),
                    );
                }
                http::validate_config(
                    self.url
                        .as_deref()
                        .ok_or("mcp remote configuration requires a URL")?,
                    &self.headers,
                )?;
            }
        }
        for (name, value) in [
            ("timeout_ms", self.timeout_ms),
            ("initialize_timeout_ms", self.initialize_timeout_ms),
        ] {
            if !(1..=MAX_TIMEOUT_MS).contains(&value) {
                return Err(format!("mcp {name} must be between 1 and {MAX_TIMEOUT_MS}"));
            }
        }
        Ok(())
    }

    pub fn tool_enabled(&self, tool: &str) -> bool {
        self.enabled
            && self
                .tools
                .as_ref()
                .is_none_or(|names| names.iter().any(|n| n == tool))
    }

    fn options(&self) -> McpCallOptions {
        McpCallOptions::new(Duration::from_millis(self.timeout_ms))
    }

    fn effective_cwd(&self, options: &McpCallOptions) -> Result<Option<PathBuf>, String> {
        if self.transport == McpTransport::Stdio {
            options.effective_cwd().map(Some)
        } else {
            Ok(None)
        }
    }
}

/// The merged server map from both scopes.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct McpConfig {
    #[serde(default)]
    pub servers: BTreeMap<String, McpServerConfig>,
}

impl McpConfig {
    /// Compatibility wrapper. New callers should use try_load to report invalid configuration.
    pub fn load(home: &Path, project_trusted: bool) -> Self {
        Self::try_load(home, project_trusted).unwrap_or_default()
    }

    pub fn try_load(home: &Path, project_trusted: bool) -> Result<Self, String> {
        let cwd = std::env::current_dir().map_err(|e| format!("mcp working directory: {e}"))?;
        Self::try_load_at(home, &cwd, project_trusted)
    }

    /// Load the trusted project's configuration without changing process-wide cwd.
    pub fn try_load_at(
        home: &Path,
        working_dir: &Path,
        project_trusted: bool,
    ) -> Result<Self, String> {
        oauth::remember_home(home);
        let mut cfg = Self::default();
        for (path, is_project) in [
            (home.join("mcp.json"), false),
            (working_dir.join(".orbit/mcp.json"), true),
        ] {
            if is_project && !project_trusted {
                continue;
            }
            let text = match std::fs::read_to_string(&path) {
                Ok(text) => text,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => return Err(format!("read mcp config {}: {e}", path.display())),
            };
            let scope: McpConfig = serde_json::from_str(&text)
                .map_err(|e| format!("parse mcp config {}: {e}", path.display()))?;
            for (name, server) in scope.servers {
                server
                    .validate()
                    .map_err(|e| format!("mcp server {name}: {e}"))?;
                cfg.servers.insert(name, server);
            }
        }
        // Claude Code's project file, for a trusted project. ORBIT's own
        // entries win a name clash, and an entry ORBIT cannot use is left
        // out: this file was written for another program.
        if project_trusted
            && let Some(text) = read_small(&working_dir.join(".mcp.json"))
            && let Ok(servers) = parse_claude_servers(&text)
        {
            for (name, server) in servers {
                if server.validate().is_ok() {
                    cfg.servers.entry(name).or_insert(server);
                }
            }
        }
        // `--mcp-config <file>`: one more file in either format, named by
        // the operator, so every entry must be valid and it overrides.
        if let Some(extra) = std::env::var_os("ORBIT_MCP_CONFIG").filter(|path| !path.is_empty()) {
            let path = PathBuf::from(extra);
            let text = read_small(&path).ok_or_else(|| {
                format!("read mcp config {}: not a readable file", path.display())
            })?;
            let servers = match serde_json::from_str::<McpConfig>(&text) {
                Ok(own) if !own.servers.is_empty() => own.servers,
                _ => parse_claude_servers(&text)
                    .map_err(|e| format!("parse mcp config {}: {e}", path.display()))?,
            };
            for (name, server) in servers {
                server
                    .validate()
                    .map_err(|e| format!("mcp server {name}: {e}"))?;
                cfg.servers.insert(name, server);
            }
        }
        Ok(cfg)
    }
}

fn read_small(path: &Path) -> Option<String> {
    let meta = std::fs::metadata(path).ok()?;
    (meta.is_file() && meta.len() <= 1024 * 1024)
        .then(|| std::fs::read_to_string(path).ok())
        .flatten()
}

/// `${VAR}` and `${VAR:-default}` from the environment, as Claude Code's
/// `.mcp.json` allows. An unset variable with no default is left as written.
fn expand_env(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(start) = rest.find("${") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        let Some(end) = after.find('}') else {
            out.push_str(&rest[start..]);
            return out;
        };
        let (name, default) = match after[..end].split_once(":-") {
            Some((name, default)) => (name, Some(default)),
            None => (&after[..end], None),
        };
        match (std::env::var(name).ok().filter(|v| !v.is_empty()), default) {
            (Some(value), _) => out.push_str(&value),
            (None, Some(default)) => out.push_str(default),
            (None, None) => out.push_str(&rest[start..start + 2 + end + 1]),
        }
        rest = &after[end + 1..];
    }
    out.push_str(rest);
    out
}

/// The `mcpServers` object of a Claude Code `.mcp.json`: `{command, args,
/// env}` is a stdio server; `{type: "http" | "sse", url, headers}` a remote
/// one.
pub fn parse_claude_servers(text: &str) -> Result<BTreeMap<String, McpServerConfig>, String> {
    let root: serde_json::Value = serde_json::from_str(text).map_err(|e| e.to_string())?;
    let servers = root
        .get("mcpServers")
        .and_then(serde_json::Value::as_object)
        .ok_or("no \"servers\" or \"mcpServers\" object")?;
    let text_of = |value: &serde_json::Value, key: &str| {
        value
            .get(key)
            .and_then(serde_json::Value::as_str)
            .map(expand_env)
    };
    let map_of = |value: &serde_json::Value, key: &str| -> BTreeMap<String, String> {
        value
            .get(key)
            .and_then(serde_json::Value::as_object)
            .map(|object| {
                object
                    .iter()
                    .filter_map(|(k, v)| Some((k.clone(), expand_env(v.as_str()?))))
                    .collect()
            })
            .unwrap_or_default()
    };
    let mut out = BTreeMap::new();
    for (name, entry) in servers {
        let kind = entry.get("type").and_then(serde_json::Value::as_str);
        let transport = match (kind, entry.get("url").is_some()) {
            (Some("sse"), _) => McpTransport::Sse,
            (Some("http" | "streamable-http"), _) | (None, true) => McpTransport::StreamableHttp,
            (Some("stdio") | None, false) => McpTransport::Stdio,
            // A transport ORBIT does not speak (for example "ws").
            _ => continue,
        };
        let remote = transport != McpTransport::Stdio;
        out.insert(
            name.clone(),
            McpServerConfig {
                transport,
                command: if remote {
                    String::new()
                } else {
                    text_of(entry, "command").unwrap_or_default()
                },
                args: if remote {
                    Vec::new()
                } else {
                    entry
                        .get("args")
                        .and_then(serde_json::Value::as_array)
                        .map(|args| {
                            args.iter()
                                .filter_map(|arg| arg.as_str().map(expand_env))
                                .collect()
                        })
                        .unwrap_or_default()
                },
                env: if remote {
                    BTreeMap::new()
                } else {
                    map_of(entry, "env")
                },
                url: remote.then(|| text_of(entry, "url")).flatten(),
                headers: if remote {
                    map_of(entry, "headers")
                } else {
                    BTreeMap::new()
                },
                enabled: entry.get("disabled") != Some(&serde_json::Value::Bool(true)),
                tools: None,
                timeout_ms: default_timeout_ms(),
                initialize_timeout_ms: default_initialize_timeout_ms(),
            },
        );
    }
    Ok(out)
}

/// One absolute budget for lock waits, initialization, writes and reads.
#[derive(Clone)]
pub struct McpCallOptions {
    pub deadline: Instant,
    pub cancel: Option<Arc<dyn Fn() -> bool + Send + Sync>>,
    /// None uses the process's current directory at the start of a pool operation.
    pub working_dir: Option<PathBuf>,
    /// The server this request is going to, for requests it sends back
    /// while we wait. Set by the session.
    pub server: Option<String>,
}

impl McpCallOptions {
    pub fn new(timeout: Duration) -> Self {
        Self {
            deadline: Instant::now() + timeout,
            cancel: None,
            working_dir: None,
            server: None,
        }
    }

    pub fn with_cancel(mut self, cancel: Arc<dyn Fn() -> bool + Send + Sync>) -> Self {
        self.cancel = Some(cancel);
        self
    }

    fn check(&self) -> Result<(), String> {
        if self.cancel.as_ref().is_some_and(|cancel| cancel()) {
            return Err("mcp request cancelled".into());
        }
        if Instant::now() >= self.deadline {
            return Err("mcp request timed out".into());
        }
        Ok(())
    }

    fn bounded(&self, timeout_ms: u64) -> Self {
        let mut opts = self.clone();
        opts.deadline = opts
            .deadline
            .min(Instant::now() + Duration::from_millis(timeout_ms));
        opts
    }

    fn effective_cwd(&self) -> Result<PathBuf, String> {
        let cwd = self
            .working_dir
            .clone()
            .map(Ok)
            .unwrap_or_else(std::env::current_dir)
            .map_err(|e| format!("mcp working directory: {e}"))?;
        std::fs::canonicalize(cwd).map_err(|e| format!("mcp working directory: {e}"))
    }
}

/// A server's request for input from the operator (`elicitation/create`),
/// sent while one of our requests to it is open.
#[derive(Clone)]
pub struct Elicitation {
    pub server: String,
    /// What the server asks, bounded.
    pub message: String,
    /// `form`: fields described by `schema`. `url`: the operator is sent to
    /// `url` and confirms when done.
    pub mode: String,
    /// The JSON schema of the fields asked for (`requestedSchema`).
    pub schema: serde_json::Value,
    pub url: Option<String>,
    /// When the wait for an answer ends.
    pub deadline: Instant,
    /// True once the request that is waiting has been cancelled.
    pub cancelled: Option<Arc<dyn Fn() -> bool + Send + Sync>>,
}

/// The operator's answer to an [`Elicitation`].
#[derive(Debug, Clone, PartialEq)]
pub enum ElicitationAnswer {
    /// The values asked for, as an object.
    Accept(serde_json::Value),
    /// The operator said no.
    Decline,
    /// The question was dismissed or never answered.
    Cancel,
}

impl ElicitationAnswer {
    fn result(self) -> serde_json::Value {
        match self {
            ElicitationAnswer::Accept(content) => {
                serde_json::json!({"action": "accept", "content": content})
            }
            ElicitationAnswer::Decline => serde_json::json!({"action": "decline"}),
            ElicitationAnswer::Cancel => serde_json::json!({"action": "cancel"}),
        }
    }
}

pub type ElicitationHandler = dyn Fn(&Elicitation) -> ElicitationAnswer + Send + Sync;

static ELICITATION: Mutex<Option<Arc<ElicitationHandler>>> = Mutex::new(None);

/// How long a stdio server's question may wait for the operator. The time
/// spent answering is not charged to the request that is waiting.
const ELICITATION_WAIT: Duration = Duration::from_secs(300);

/// Install what answers servers' questions. With one installed, sessions
/// opened afterwards tell their server that elicitation is supported;
/// without one the capability is not offered and a question is refused as
/// an unsupported method. Sessions already open keep what they announced.
pub fn set_elicitation_handler(handler: Option<Arc<ElicitationHandler>>) {
    if let Ok(mut slot) = ELICITATION.lock() {
        *slot = handler;
    }
}

fn elicitation_handler() -> Option<Arc<ElicitationHandler>> {
    ELICITATION.lock().ok().and_then(|slot| slot.clone())
}

/// The reply to a request a server sent us while we wait for its response:
/// `ping`, an elicitation when a handler is installed, and a refusal for
/// anything else.
static WITHHELD_ENV: Mutex<Vec<String>> = Mutex::new(Vec::new());

/// Environment variables a stdio server is not to inherit from this
/// process: the names that hold the model provider's credentials. A server
/// whose own configuration sets one of them still gets its own value.
pub fn set_withheld_env(names: Vec<String>) {
    if let Ok(mut slot) = WITHHELD_ENV.lock() {
        *slot = names;
    }
}

fn withheld_env() -> Vec<String> {
    WITHHELD_ENV
        .lock()
        .map(|slot| slot.clone())
        .unwrap_or_default()
}

/// A message a channel server pushed into the session: Claude Code's
/// `notifications/claude/channel`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelEvent {
    pub server: String,
    pub content: String,
    /// Attributes of the event. Only keys of letters, digits and `_` are
    /// kept, as in Claude Code.
    pub meta: BTreeMap<String, String>,
}

/// Receives channel events. One per process.
pub type ChannelSink = dyn Fn(ChannelEvent) + Send + Sync;

static CHANNEL_SINK: Mutex<Option<(Vec<String>, Arc<ChannelSink>)>> = Mutex::new(None);

/// Deliver `notifications/claude/channel` from the named servers to `sink`.
/// A notification from any other server is dropped: a server becomes a
/// channel because the operator named it, not because it says so. `None`
/// stops delivery.
pub fn set_channel_sink(sink: Option<(Vec<String>, Arc<ChannelSink>)>) {
    if let Ok(mut slot) = CHANNEL_SINK.lock() {
        *slot = sink;
    }
}

const CHANNEL_METHOD: &str = "notifications/claude/channel";
const PERMISSION_REQUEST_METHOD: &str = "notifications/claude/channel/permission_request";
const PERMISSION_VERDICT_METHOD: &str = "notifications/claude/channel/permission";

/// A channel's answer to a permission prompt that was relayed to it:
/// Claude Code's `notifications/claude/channel/permission`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PermissionVerdict {
    pub server: String,
    /// The id the request went out with: five letters of `a`-`z` without `l`.
    pub request_id: String,
    pub allow: bool,
}

/// Receives permission verdicts. One per process.
pub type PermissionSink = dyn Fn(PermissionVerdict) + Send + Sync;

static PERMISSION_SINK: Mutex<Option<(Vec<String>, Arc<PermissionSink>)>> = Mutex::new(None);

/// Deliver permission verdicts from the named servers to `sink`. A verdict
/// from any other server is dropped. `None` stops delivery.
pub fn set_permission_sink(sink: Option<(Vec<String>, Arc<PermissionSink>)>) {
    if let Ok(mut slot) = PERMISSION_SINK.lock() {
        *slot = sink;
    }
}

/// Is `id` shaped like a permission request id?
pub fn permission_request_id_ok(id: &str) -> bool {
    id.len() == 5 && id.bytes().all(|b| b.is_ascii_lowercase() && b != b'l')
}

fn dispatch_permission_verdict(server: &str, params: Option<&serde_json::Value>) {
    let sink = PERMISSION_SINK.lock().ok().and_then(|slot| {
        slot.as_ref()
            .filter(|(servers, _)| servers.iter().any(|name| name == server))
            .map(|(_, sink)| sink.clone())
    });
    let Some(sink) = sink else {
        return;
    };
    let text = |key: &str| {
        params
            .and_then(|params| params.get(key))
            .and_then(serde_json::Value::as_str)
    };
    let (Some(request_id), Some(behavior)) = (text("request_id"), text("behavior")) else {
        return;
    };
    let allow = match behavior {
        "allow" => true,
        "deny" => false,
        _ => return,
    };
    if !permission_request_id_ok(request_id) {
        return;
    }
    sink(PermissionVerdict {
        server: server.to_owned(),
        request_id: request_id.to_owned(),
        allow,
    });
}
/// How much of a server's `instructions` is kept.
const MAX_INSTRUCTIONS: usize = 4_000;
const MAX_CHANNEL_CONTENT: usize = 16 * 1024;
const MAX_CHANNEL_META: usize = 16;

/// Hand a channel notification to the sink, when `server` is a channel the
/// operator enabled and the notification has the documented shape.
pub(crate) fn dispatch_channel(server: &str, method: &str, params: Option<&serde_json::Value>) {
    if method == PERMISSION_VERDICT_METHOD {
        return dispatch_permission_verdict(server, params);
    }
    if method != CHANNEL_METHOD {
        return;
    }
    let sink = CHANNEL_SINK.lock().ok().and_then(|slot| {
        slot.as_ref()
            .filter(|(servers, _)| servers.iter().any(|name| name == server))
            .map(|(_, sink)| sink.clone())
    });
    let Some(sink) = sink else {
        return;
    };
    let Some(content) = params
        .and_then(|params| params.get("content"))
        .and_then(serde_json::Value::as_str)
    else {
        return;
    };
    let meta = params
        .and_then(|params| params.get("meta"))
        .and_then(serde_json::Value::as_object)
        .into_iter()
        .flatten()
        .filter(|(key, _)| {
            !key.is_empty()
                && key.len() <= 64
                && key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        })
        .filter_map(|(key, value)| Some((key.clone(), value.as_str()?.chars().take(256).collect())))
        .take(MAX_CHANNEL_META)
        .collect();
    sink(ChannelEvent {
        server: server.to_owned(),
        content: content.chars().take(MAX_CHANNEL_CONTENT).collect(),
        meta,
    });
}

pub(crate) fn server_request_reply(
    method: &str,
    request_id: &serde_json::Value,
    params: Option<&serde_json::Value>,
    options: &McpCallOptions,
) -> serde_json::Value {
    let handler = (method == "elicitation/create")
        .then(elicitation_handler)
        .flatten();
    match (method, handler) {
        ("ping", _) => serde_json::json!({"jsonrpc":"2.0", "id":request_id, "result":{}}),
        (_, Some(handler)) => {
            let text = |key: &str| {
                params
                    .and_then(|params| params.get(key))
                    .and_then(serde_json::Value::as_str)
            };
            let request = Elicitation {
                server: options.server.clone().unwrap_or_default(),
                message: text("message").unwrap_or("").chars().take(4_000).collect(),
                mode: text("mode").unwrap_or("form").to_owned(),
                schema: params
                    .and_then(|params| params.get("requestedSchema"))
                    .filter(|schema| schema.is_object())
                    .cloned()
                    .unwrap_or_else(|| serde_json::json!({})),
                url: text("url").map(str::to_owned),
                deadline: options.deadline,
                cancelled: options.cancel.clone(),
            };
            serde_json::json!({
                "jsonrpc":"2.0", "id":request_id, "result": handler(&request).result()
            })
        }
        _ => serde_json::json!({
            "jsonrpc":"2.0", "id":request_id,
            "error":{"code":-32601,"message":"client method not supported"}
        }),
    }
}

/// How much of a stdio server's standard error is kept (its end).
#[cfg(unix)]
const STDERR_TAIL_BYTES: usize = 2048;

/// A live session, retired immediately after transport or protocol failure.
pub struct McpSession {
    pub server_name: String,
    remote: Option<RemoteTransport>,
    child: Option<Child>,
    stdin: Option<ChildStdin>,
    stdout: Option<ChildStdout>,
    input: Vec<u8>,
    next_id: u64,
    cfg: McpServerConfig,
    /// What the server said about itself at the handshake (`instructions`).
    instructions: Option<String>,
    /// Whether the server declared that it relays permission prompts.
    relays_permission: bool,
    /// How the server's process ended, when it ended on its own before
    /// this session was retired.
    ended: Option<std::process::ExitStatus>,
    /// The server closed a pipe itself (not this side retiring it).
    peer_closed: bool,
    /// The last text the server wrote to standard output that was not JSON-RPC.
    /// It is skipped, and kept only to explain a server that then says nothing.
    noise: Option<String>,
}

enum RemoteTransport {
    Streamable(Box<http::HttpTransport>),
    Legacy(Box<legacy::LegacyTransport>),
}

impl RemoteTransport {
    fn exchange(
        &mut self,
        id: u64,
        method: &str,
        params: serde_json::Value,
        options: &McpCallOptions,
    ) -> Result<serde_json::Value, (String, bool)> {
        match self {
            Self::Streamable(transport) => transport.exchange(id, method, params, options),
            Self::Legacy(transport) => transport.exchange(id, method, params, options),
        }
    }

    fn notify(
        &mut self,
        method: &str,
        params: serde_json::Value,
        options: &McpCallOptions,
    ) -> Result<(), String> {
        match self {
            Self::Streamable(transport) => transport.notify(method, params, options),
            Self::Legacy(transport) => transport.notify(method, params, options),
        }
    }

    fn is_alive(&self) -> bool {
        match self {
            Self::Streamable(transport) => transport.is_alive(),
            Self::Legacy(transport) => transport.is_alive(),
        }
    }

    fn close(&mut self, options: &McpCallOptions) -> Result<(), String> {
        match self {
            Self::Streamable(transport) => transport.close(options),
            Self::Legacy(transport) => transport.close(options),
        }
    }

    fn retire(&mut self) {
        match self {
            Self::Streamable(transport) => transport.retire(),
            Self::Legacy(transport) => transport.retire(),
        }
    }
}

impl McpSession {
    pub fn spawn(name: &str, cfg: &McpServerConfig) -> Result<Self, String> {
        Self::spawn_with_options(name, cfg, &cfg.options())
    }

    pub fn spawn_with_options(
        name: &str,
        cfg: &McpServerConfig,
        options: &McpCallOptions,
    ) -> Result<Self, String> {
        cfg.validate()?;
        if !cfg.enabled {
            return Err(format!("mcp server {name} is disabled"));
        }
        options.check()?;
        let options = options.bounded(cfg.timeout_ms);
        let initialize_options = options.bounded(cfg.initialize_timeout_ms);
        match cfg.transport {
            McpTransport::StreamableHttp | McpTransport::Sse => {
                let url = cfg
                    .url
                    .as_deref()
                    .ok_or("mcp remote configuration requires a URL")?;
                // A stored sign-in supplies the bearer token unless the
                // configuration brings its own Authorization header. It
                // never enters the configuration itself.
                let mut headers = cfg.headers.clone();
                if !headers
                    .keys()
                    .any(|key| key.eq_ignore_ascii_case("authorization"))
                    && let Some(token) = oauth::bearer_for(name, url)
                {
                    headers.insert("Authorization".into(), format!("Bearer {token}"));
                }
                let remote = if cfg.transport == McpTransport::StreamableHttp {
                    RemoteTransport::Streamable(Box::new(http::HttpTransport::new(url, &headers)?))
                } else {
                    RemoteTransport::Legacy(Box::new(legacy::LegacyTransport::new(url, &headers)?))
                };
                let mut session = Self {
                    server_name: name.into(),
                    remote: Some(remote),
                    child: None,
                    stdin: None,
                    stdout: None,
                    input: Vec::new(),
                    next_id: 1,
                    instructions: None,
                    relays_permission: false,
                    ended: None,
                    peer_closed: false,
                    noise: None,
                    cfg: cfg.clone(),
                };
                session.initialize(&initialize_options)?;
                return Ok(session);
            }
            McpTransport::Stdio => {}
        }
        #[cfg(not(unix))]
        {
            return Err("bounded MCP stdio is supported on Unix only".into());
        }
        #[cfg(unix)]
        {
            let cwd = options.effective_cwd()?;
            options.check()?;
            let mut command = Command::new(&cfg.command);
            // The model provider's credentials are ORBIT's own: a server
            // does not inherit them. One that needs such a variable gets it
            // from its own `env` entry, which is applied after.
            for name in withheld_env() {
                command.env_remove(name);
            }
            let mut child = command
                .args(&cfg.args)
                .envs(&cfg.env)
                .current_dir(cwd)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .map_err(|e| format!("spawn mcp server {name}: {e}"))?;
            let stdin = child.stdin.take();
            let stdout = child.stdout.take();
            // What the server writes to standard error is read and dropped,
            // keeping only its end: when the server does not come up, its
            // last line is usually the reason.
            let stderr_tail = Arc::new(Mutex::new(Vec::<u8>::new()));
            let (stderr_done, stderr_drained) = std::sync::mpsc::channel();
            if let Some(mut stderr) = child.stderr.take() {
                let tail = stderr_tail.clone();
                std::thread::spawn(move || {
                    let mut bytes = [0_u8; 4096];
                    loop {
                        let read = match stderr.read(&mut bytes) {
                            Ok(0) => break,
                            Ok(read) => read,
                            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {
                                continue;
                            }
                            Err(_) => break,
                        };
                        if let Ok(mut tail) = tail.lock() {
                            tail.extend_from_slice(&bytes[..read]);
                            let extra = tail.len().saturating_sub(STDERR_TAIL_BYTES);
                            tail.drain(..extra);
                        }
                    }
                    let _ = stderr_done.send(());
                });
            }
            let mut session = Self {
                server_name: name.into(),
                remote: None,
                child: Some(child),
                stdin,
                stdout,
                input: Vec::new(),
                next_id: 1,
                instructions: None,
                relays_permission: false,
                ended: None,
                peer_closed: false,
                noise: None,
                cfg: cfg.clone(),
            };
            set_nonblocking(
                session
                    .stdin
                    .as_ref()
                    .ok_or("mcp has no stdin")?
                    .as_raw_fd(),
            )?;
            set_nonblocking(
                session
                    .stdout
                    .as_ref()
                    .ok_or("mcp has no stdout")?
                    .as_raw_fd(),
            )?;
            if let Err(error) = session.initialize(&initialize_options) {
                return Err(session.startup_failure(error, &stderr_tail, &stderr_drained));
            }
            Ok(session)
        }
    }

    /// Remember, and otherwise ignore, a line of standard output that is not JSON-RPC.
    fn note_noise(&mut self, line: &[u8]) {
        let head = &line[..line.len().min(1024)];
        let text: String = String::from_utf8_lossy(head)
            .chars()
            .filter(|c| !c.is_control())
            .collect();
        let text = text.trim();
        if !text.is_empty() {
            self.noise = Some(text.chars().take(160).collect());
        }
    }

    /// Why a server that was started did not answer its handshake: the
    /// handshake's own error, and when the process has already ended, how
    /// it ended and the last thing it wrote to standard error (or, when it
    /// wrote nothing there, to standard output as text that was not JSON-RPC).
    #[cfg(unix)]
    fn startup_failure(
        &self,
        error: String,
        stderr_tail: &Mutex<Vec<u8>>,
        stderr_drained: &std::sync::mpsc::Receiver<()>,
    ) -> String {
        if error == "mcp request cancelled" {
            return error;
        }
        if error == "mcp request timed out" {
            return match &self.noise {
                Some(noise) => {
                    format!(
                        "{error}; its standard output held text that is not JSON-RPC, the last line being: {noise}"
                    )
                }
                None => error,
            };
        }
        let Some(status) = self.ended else {
            return error;
        };
        // Wait for the final stderr bytes, but never join an unbounded reader:
        // a descendant may retain the pipe after the owned process exits.
        let _ = stderr_drained.recv_timeout(Duration::from_millis(100));
        let said = stderr_tail
            .lock()
            .map(|tail| String::from_utf8_lossy(&tail).into_owned())
            .unwrap_or_default();
        let last: String = said
            .lines()
            .rev()
            .map(str::trim)
            .find(|line| !line.is_empty())
            .unwrap_or("")
            .chars()
            .filter(|c| !c.is_control())
            .take(160)
            .collect();
        if last.is_empty() {
            match &self.noise {
                Some(noise) => format!(
                    "its process ended before answering ({status}); the last line on its standard output was: {noise}"
                ),
                None => format!("its process ended before answering ({status})"),
            }
        } else {
            format!("its process ended before answering ({status}): {last}")
        }
    }

    /// The `instructions` the server gave at its handshake, if any.
    pub fn instructions(&self) -> Option<&str> {
        self.instructions.as_deref()
    }

    /// Did the server declare, at its handshake, that it can relay
    /// permission prompts (`experimental["claude/channel/permission"]`)?
    pub fn relays_permission(&self) -> bool {
        self.relays_permission
    }

    /// Send a permission prompt to a server that relays them. Returns
    /// whether it was sent: a server that did not declare the capability
    /// is sent nothing.
    pub fn relay_permission_request(
        &mut self,
        request_id: &str,
        tool_name: &str,
        description: &str,
        input_preview: &str,
    ) -> Result<bool, String> {
        if !self.relays_permission || self.remote.is_some() {
            return Ok(false);
        }
        let options = self.cfg.options();
        self.notify(
            PERMISSION_REQUEST_METHOD,
            serde_json::json!({
                "request_id": request_id,
                "tool_name": tool_name,
                "description": description,
                "input_preview": input_preview,
            }),
            &options,
        )?;
        Ok(true)
    }

    fn initialize(&mut self, options: &McpCallOptions) -> Result<(), String> {
        let answer = self.request_with_options(
            "initialize",
            serde_json::json!({
                "protocolVersion":"2025-06-18",
                "capabilities": if elicitation_handler().is_some() {
                    serde_json::json!({"elicitation":{}})
                } else {
                    serde_json::json!({})
                },
                "clientInfo":{"name":"orbit","version":env!("CARGO_PKG_VERSION")}
            }),
            options,
        )?;
        self.instructions = answer
            .get("instructions")
            .and_then(serde_json::Value::as_str)
            .map(str::trim)
            .filter(|text| !text.is_empty())
            .map(|text| text.chars().take(MAX_INSTRUCTIONS).collect());
        // An object declares it; `false` or nothing does not.
        self.relays_permission = answer
            .pointer("/capabilities/experimental")
            .and_then(|experimental| experimental.get("claude/channel/permission"))
            .is_some_and(serde_json::Value::is_object);
        if let Err(error) = self.notify("notifications/initialized", serde_json::json!({}), options)
        {
            self.retire();
            return Err(error);
        }
        Ok(())
    }

    pub fn request(
        &mut self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        self.request_with_options(method, params, &self.cfg.options())
    }

    pub fn request_with_options(
        &mut self,
        method: &str,
        params: serde_json::Value,
        options: &McpCallOptions,
    ) -> Result<serde_json::Value, String> {
        if method == "tools/call" {
            let tool = params
                .get("name")
                .and_then(|n| n.as_str())
                .ok_or("mcp tools/call requires a tool name")?;
            if !self.cfg.tool_enabled(tool) {
                return Err(format!("mcp tool {tool} is disabled"));
            }
        }
        if self
            .remote
            .as_ref()
            .is_none_or(|transport| !transport.is_alive())
            && self.child.is_none()
        {
            return Err("mcp transport is retired".into());
        }
        let mut options = options.bounded(self.cfg.timeout_ms);
        options.server = Some(self.server_name.clone());
        let options = &options;
        let id = self.next_id;
        self.next_id = self
            .next_id
            .checked_add(1)
            .ok_or("mcp request id exhausted")?;
        let result = self.exchange(id, method, params, options);
        match result {
            Ok(value) => Ok(value),
            Err((error, fatal)) => {
                if fatal {
                    // initialize must never receive notifications/cancelled. There
                    // is also no cancellation frame after a partially written request.
                    self.retire();
                }
                Err(error)
            }
        }
    }

    fn exchange(
        &mut self,
        id: u64,
        method: &str,
        params: serde_json::Value,
        options: &McpCallOptions,
    ) -> Result<serde_json::Value, (String, bool)> {
        if let Some(remote) = self.remote.as_mut() {
            return remote.exchange(id, method, params, options);
        }
        let fatal = |error| (error, true);
        let msg = serde_json::json!({"jsonrpc":"2.0","id":id,"method":method,"params":params});
        let mut bytes_sent = false;
        let mut request_complete = false;
        let result = match self.write_frame_tracked(&msg, options, &mut bytes_sent) {
            Ok(()) => {
                request_complete = true;
                self.read_response(id, options)
            }
            Err(error) => Err(fatal(error)),
        };
        if result.as_ref().is_err_and(|(error, _)| {
            error == "mcp request cancelled" || error == "mcp request timed out"
        }) && method != "initialize"
            && request_complete
        {
            // The request frame is complete here. A nonblocking best-effort
            // write is allowed; it does not wait for a cancellation response.
            self.cancel_notification(id);
        }
        result.map_err(|(error, fatal)| {
            if fatal && method == "tools/call" {
                let context = if bytes_sent {
                    "tool outcome is unknown; inspect external effects before retrying"
                } else {
                    "no tool request was sent"
                };
                (format!("{error}; {context}"), fatal)
            } else {
                (error, fatal)
            }
        })
    }

    fn read_response(
        &mut self,
        id: u64,
        options: &McpCallOptions,
    ) -> Result<serde_json::Value, (String, bool)> {
        // The time an operator takes to answer a server's question is given
        // back to the request that is waiting for it.
        let mut extended = options.clone();
        let options = &mut extended;
        loop {
            let line = self.read_frame(options).map_err(|error| (error, true))?;
            options.check().map_err(|error| (error, true))?;
            let value: serde_json::Value = match serde_json::from_slice(&line) {
                Ok(value) => value,
                // A banner or a log line on standard output is not a reply to anything.
                Err(_) if is_log_noise(&line) => {
                    self.note_noise(&line);
                    continue;
                }
                Err(error) => return Err((format!("malformed mcp frame: {error}"), true)),
            };
            options.check().map_err(|error| (error, true))?;
            let object = value
                .as_object()
                .ok_or_else(|| ("mcp frame is not an object".into(), true))?;
            if object.get("jsonrpc").and_then(|v| v.as_str()) != Some("2.0") {
                return Err(("mcp frame has invalid jsonrpc version".into(), true));
            }
            if let Some(method) = object.get("method") {
                if !method.is_string() {
                    return Err(("mcp frame has invalid method".into(), true));
                }
                if let Some(request_id) = object.get("id") {
                    // Request IDs belong to the server's namespace. A matching
                    // numeric ID does not make an inbound request our response.
                    if !(request_id.is_string() || request_id.is_i64() || request_id.is_u64()) {
                        return Err(("mcp server request has invalid id".into(), true));
                    }
                    let asked = Instant::now();
                    let mut waiting = options.clone();
                    waiting.deadline = asked + ELICITATION_WAIT;
                    let response = server_request_reply(
                        method.as_str().unwrap_or(""),
                        request_id,
                        object.get("params"),
                        &waiting,
                    );
                    options.deadline += asked.elapsed();
                    self.write_frame(&response, options)
                        .map_err(|error| (error, true))?;
                } else {
                    // A notification. The only kind acted on is a channel
                    // event, and only from a server the operator enabled.
                    dispatch_channel(
                        &self.server_name,
                        method.as_str().unwrap_or(""),
                        object.get("params"),
                    );
                }
                continue;
            }
            // A reply with no id at all answers nothing we sent. A server that takes a
            // notification for a request (`notifications/initialized`) answers it with an
            // error like that; `id: null` is different, it is a server saying it could not
            // read a request, and stays an error below.
            let Some(response_id) = object.get("id") else {
                continue;
            };
            if !(response_id.is_string() || response_id.is_i64() || response_id.is_u64()) {
                return Err(("mcp response has invalid id".into(), true));
            }
            let result = object.get("result");
            let error = object.get("error");
            if result.is_some() == error.is_some() {
                return Err((
                    "mcp response requires exactly one result or error".into(),
                    true,
                ));
            }
            if let Some(error) = error
                && (error.get("code").and_then(|c| c.as_i64()).is_none()
                    || error.get("message").and_then(|m| m.as_str()).is_none())
            {
                return Err(("mcp response has invalid error".into(), true));
            }
            if response_id.as_u64() != Some(id) {
                continue;
            }
            let response = match (result, error) {
                (Some(result), _) => Ok(result.clone()),
                (_, Some(error)) => Err((format!("mcp server error: {error}"), false)),
                _ => unreachable!(),
            };
            options.check().map_err(|error| (error, true))?;
            return response;
        }
    }

    fn write_frame(
        &mut self,
        value: &serde_json::Value,
        options: &McpCallOptions,
    ) -> Result<(), String> {
        self.write_frame_tracked(value, options, &mut false)
    }

    fn write_frame_tracked(
        &mut self,
        value: &serde_json::Value,
        options: &McpCallOptions,
        bytes_sent: &mut bool,
    ) -> Result<(), String> {
        options.check()?;
        let mut bytes = encode_frame(value)?;
        bytes.push(b'\n');
        let stdin = self.stdin.as_mut().ok_or("mcp transport is retired")?;
        let mut written = 0;
        while written < bytes.len() {
            options.check()?;
            match stdin.write(&bytes[written..]) {
                Ok(0) => {
                    self.peer_closed = true;
                    return Err("mcp server closed stdin".into());
                }
                Ok(n) => {
                    *bytes_sent = true;
                    written += n;
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    wait_writable(stdin, options)?
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => {
                    self.peer_closed |= e.kind() == std::io::ErrorKind::BrokenPipe;
                    return Err(format!("mcp write: {e}"));
                }
            }
        }
        loop {
            options.check()?;
            match stdin.flush() {
                Ok(()) => return Ok(()),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    wait_writable(stdin, options)?
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => {
                    self.peer_closed |= e.kind() == std::io::ErrorKind::BrokenPipe;
                    return Err(format!("mcp flush: {e}"));
                }
            }
        }
    }

    fn read_frame(&mut self, options: &McpCallOptions) -> Result<Vec<u8>, String> {
        // What was already searched holds no newline, so each read is searched once. Searching
        // the whole buffer after every 8 KiB takes seconds on a 12 MiB reply.
        let mut searched = 0;
        loop {
            options.check()?;
            if let Some(offset) = self.input[searched..]
                .iter()
                .position(|byte| *byte == b'\n')
            {
                let newline = searched + offset;
                if newline > MAX_REPLY_BYTES {
                    return Err(reply_too_large());
                }
                let mut frame: Vec<_> = self.input.drain(..=newline).collect();
                frame.pop();
                return Ok(frame);
            }
            searched = self.input.len();
            if searched > MAX_REPLY_BYTES {
                return Err(reply_too_large());
            }
            let stdout = self.stdout.as_mut().ok_or("mcp transport is retired")?;
            let mut bytes = [0_u8; 8192];
            match stdout.read(&mut bytes) {
                Ok(0) => {
                    self.peer_closed = true;
                    return Err("mcp server closed stdout".into());
                }
                Ok(n) => self.input.extend_from_slice(&bytes[..n]),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    wait_readable(stdout, options)?
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(format!("mcp read: {e}")),
            }
        }
    }

    /// Listen for what a stdio server sends while no request is waiting:
    /// channel events are delivered, a server's own request (a ping, a
    /// question) is answered, anything else is dropped. Returns after
    /// `wait` with nothing more to read. An error means the session is no
    /// longer usable.
    pub fn poll_channel(&mut self, wait: Duration) -> Result<(), String> {
        if self.remote.is_some() {
            return Ok(());
        }
        let deadline = Instant::now() + wait;
        let mut searched = 0;
        loop {
            let Some(offset) = self.input[searched..]
                .iter()
                .position(|byte| *byte == b'\n')
            else {
                searched = self.input.len();
                if searched > MAX_REPLY_BYTES {
                    return Err(reply_too_large());
                }
                let stdout = self.stdout.as_mut().ok_or("mcp transport is retired")?;
                let mut bytes = [0_u8; 8192];
                match stdout.read(&mut bytes) {
                    Ok(0) => {
                        self.peer_closed = true;
                        return Err("mcp server closed stdout".into());
                    }
                    Ok(n) => self.input.extend_from_slice(&bytes[..n]),
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        if Instant::now() >= deadline {
                            return Ok(());
                        }
                        std::thread::sleep(Duration::from_millis(20));
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                    Err(e) => return Err(format!("mcp read: {e}")),
                }
                continue;
            };
            let newline = searched + offset;
            searched = 0;
            if newline > MAX_REPLY_BYTES {
                return Err(reply_too_large());
            }
            let mut frame: Vec<_> = self.input.drain(..=newline).collect();
            frame.pop();
            let object = match serde_json::from_slice::<serde_json::Value>(&frame) {
                Ok(serde_json::Value::Object(object)) => object,
                Err(_) if is_log_noise(&frame) => {
                    self.note_noise(&frame);
                    continue;
                }
                _ => return Err("malformed mcp frame".into()),
            };
            let Some(method) = object.get("method").and_then(serde_json::Value::as_str) else {
                // A response nobody is waiting for.
                continue;
            };
            match object.get("id") {
                Some(request_id) => {
                    let options = self.cfg.options();
                    let response =
                        server_request_reply(method, request_id, object.get("params"), &options);
                    self.write_frame(&response, &options)?;
                }
                None => dispatch_channel(&self.server_name, method, object.get("params")),
            }
        }
    }

    fn notify(
        &mut self,
        method: &str,
        params: serde_json::Value,
        options: &McpCallOptions,
    ) -> Result<(), String> {
        if let Some(remote) = self.remote.as_mut() {
            return remote.notify(method, params, options);
        }
        self.write_frame(
            &serde_json::json!({"jsonrpc":"2.0","method":method,"params":params}),
            options,
        )
    }

    fn cancel_notification(&mut self, id: u64) {
        // No new wait or deadline: one nonblocking best-effort write, only after
        // a complete request. A full or closed pipe is followed by retirement.
        let Ok(mut bytes) = encode_frame(&serde_json::json!({
            "jsonrpc":"2.0", "method":"notifications/cancelled",
            "params":{"requestId":id,"reason":"caller cancelled or deadline elapsed"}
        })) else {
            return;
        };
        bytes.push(b'\n');
        if let Some(stdin) = self.stdin.as_mut() {
            let _ = stdin.write(&bytes);
        }
    }

    pub fn list_tools(&mut self) -> Result<Vec<McpToolInfo>, String> {
        self.list_tools_with_options(&self.cfg.options())
    }

    pub fn list_tools_with_options(
        &mut self,
        options: &McpCallOptions,
    ) -> Result<Vec<McpToolInfo>, String> {
        let options = options.bounded(self.cfg.timeout_ms);
        options.check()?;
        if self.cfg.tools.as_ref().is_some_and(Vec::is_empty) {
            return Ok(Vec::new());
        }
        let result = self.list_tool_pages(&options);
        // A valid JSON-RPC error is a completed server response. Discovery
        // validation errors and transport failures retire the connection.
        if result
            .as_ref()
            .is_err_and(|error| !error.starts_with("mcp server error:"))
        {
            self.retire();
        }
        result
    }

    fn list_tool_pages(&mut self, options: &McpCallOptions) -> Result<Vec<McpToolInfo>, String> {
        let mut cursor = None;
        let mut seen_cursors = HashSet::new();
        let mut seen_names = HashSet::new();
        let mut total_bytes = 0_usize;
        let mut total_tools = 0_usize;
        let mut listed = Vec::new();
        for _ in 0..MAX_TOOL_PAGES {
            let params = match &cursor {
                Some(cursor) => serde_json::json!({"cursor":cursor}),
                None => serde_json::json!({}),
            };
            let result = self.request_with_options("tools/list", params, options)?;
            total_bytes = total_bytes
                .checked_add(json_len(&result)?)
                .ok_or("mcp tool metadata size overflow")?;
            if total_bytes > MAX_REPLY_BYTES {
                return Err(format!(
                    "mcp aggregate tool metadata exceeds {} MiB",
                    MAX_REPLY_BYTES >> 20
                ));
            }
            let tools = result
                .get("tools")
                .and_then(|t| t.as_array())
                .ok_or("mcp tools/list result has no tools array")?;
            total_tools = total_tools
                .checked_add(tools.len())
                .ok_or("mcp tool count overflow")?;
            if total_tools > MAX_TOOLS {
                return Err(format!("mcp tool list exceeds {MAX_TOOLS} tools"));
            }
            for tool in tools {
                let name = tool
                    .get("name")
                    .and_then(|n| n.as_str())
                    .ok_or("mcp tool metadata has no name")?;
                if name.is_empty() {
                    return Err("mcp tool metadata has an empty name".into());
                }
                if tool
                    .get("inputSchema")
                    .is_some_and(|schema| !schema.is_object())
                {
                    return Err("mcp tool metadata has invalid inputSchema".into());
                }
                if !seen_names.insert(name.to_string()) {
                    return Err("mcp tool list repeats a tool name".into());
                }
                if !self.cfg.tool_enabled(name) {
                    continue;
                }
                listed.push(McpToolInfo {
                    name: name.into(),
                    description: tool
                        .get("description")
                        .and_then(|d| d.as_str())
                        .unwrap_or("")
                        .into(),
                    input_schema: tool
                        .get("inputSchema")
                        .cloned()
                        .unwrap_or(serde_json::json!({"type":"object"})),
                });
            }
            options.check()?;
            match result.get("nextCursor") {
                None => return Ok(listed),
                Some(next) => {
                    let next = next
                        .as_str()
                        .ok_or("mcp tools/list has invalid nextCursor")?;
                    if !seen_cursors.insert(next.to_string()) {
                        return Err("mcp tools/list repeats a cursor".into());
                    }
                    cursor = Some(next.to_string());
                }
            }
        }
        Err(format!("mcp tool list exceeds {MAX_TOOL_PAGES} pages"))
    }

    pub fn call_tool(
        &mut self,
        tool: &str,
        arguments: serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        self.call_tool_with_options(tool, arguments, &self.cfg.options())
    }

    pub fn call_tool_with_options(
        &mut self,
        tool: &str,
        arguments: serde_json::Value,
        options: &McpCallOptions,
    ) -> Result<serde_json::Value, String> {
        self.request_with_options(
            "tools/call",
            serde_json::json!({"name":tool,"arguments":arguments}),
            options,
        )
    }

    pub fn is_alive(&mut self) -> bool {
        if let Some(remote) = self.remote.as_ref() {
            return remote.is_alive();
        }
        self.child
            .as_mut()
            .is_some_and(|child| child.try_wait().is_ok_and(|status| status.is_none()))
    }

    /// Explicit HTTP session teardown. Local retirement and Drop perform no HTTP requests.
    pub fn close_with_options(&mut self, options: &McpCallOptions) -> Result<(), String> {
        let result = if let Some(remote) = self.remote.as_mut() {
            remote.close(&options.bounded(self.cfg.timeout_ms))
        } else {
            Ok(())
        };
        self.retire();
        result
    }

    fn retire(&mut self) {
        if let Some(mut remote) = self.remote.take() {
            remote.retire();
        }
        if let Some(mut child) = self.child.take() {
            // Observe natural exit before closing our pipes or killing the
            // process. After peer closure only, give it a bounded moment to
            // finish; live timeouts and cancellations get no extra grace.
            for attempt in 0..if self.peer_closed { 11 } else { 1 } {
                if attempt > 0 {
                    std::thread::sleep(Duration::from_millis(10));
                }
                match child.try_wait() {
                    Ok(Some(status)) => {
                        self.ended = Some(status);
                        break;
                    }
                    Ok(None) => {}
                    Err(_) => break,
                }
            }
            // Kill only this Child, never a process group or a text-parsed PID.
            if self.ended.is_none() {
                let _ = child.kill();
            }
            let _ = child.wait();
        }
        self.stdin.take();
        self.stdout.take();
        self.input.clear();
    }
}

impl Drop for McpSession {
    fn drop(&mut self) {
        self.retire();
    }
}

fn encode_frame(value: &serde_json::Value) -> Result<Vec<u8>, String> {
    struct Frame(Vec<u8>);
    impl Write for Frame {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if bytes.len() > MAX_FRAME_BYTES.saturating_sub(self.0.len()) {
                return Err(std::io::Error::other("mcp output frame exceeds 1 MiB"));
            }
            self.0.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut frame = Frame(Vec::new());
    serde_json::to_writer(&mut frame, value).map_err(|error| error.to_string())?;
    Ok(frame.0)
}

#[cfg(unix)]
fn set_nonblocking(fd: RawFd) -> Result<(), String> {
    // SAFETY: fd is a borrowed, live Child pipe, and fcntl does not take ownership.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(format!(
            "mcp nonblocking pipe: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn wait_pipe(fd: RawFd, events: libc::c_short, options: &McpCallOptions) -> Result<(), String> {
    loop {
        options.check()?;
        let remaining = options
            .deadline
            .saturating_duration_since(Instant::now())
            .min(POLL_INTERVAL);
        let millis = remaining.as_millis().max(1) as libc::c_int;
        let mut pollfd = libc::pollfd {
            fd,
            events,
            revents: 0,
        };
        // SAFETY: pollfd points to one initialized structure for this synchronous call.
        let result = unsafe { libc::poll(&mut pollfd, 1, millis) };
        if result > 0 {
            return options.check();
        }
        if result < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() != std::io::ErrorKind::Interrupted {
                return Err(format!("mcp poll: {error}"));
            }
        }
    }
}
#[cfg(unix)]
fn wait_writable(pipe: &ChildStdin, options: &McpCallOptions) -> Result<(), String> {
    wait_pipe(pipe.as_raw_fd(), libc::POLLOUT, options)
}
#[cfg(unix)]
fn wait_readable(pipe: &ChildStdout, options: &McpCallOptions) -> Result<(), String> {
    wait_pipe(pipe.as_raw_fd(), libc::POLLIN, options)
}
#[cfg(not(unix))]
fn wait_writable(_: &ChildStdin, _: &McpCallOptions) -> Result<(), String> {
    Err("bounded MCP stdio is supported on Unix only".into())
}
#[cfg(not(unix))]
fn wait_readable(_: &ChildStdout, _: &McpCallOptions) -> Result<(), String> {
    Err("bounded MCP stdio is supported on Unix only".into())
}

#[derive(Debug, Clone)]
pub struct McpToolInfo {
    pub name: String,
    pub description: String,
    pub input_schema: serde_json::Value,
}

pub fn wire_name(server: &str, tool: &str) -> String {
    format!("mcp__{server}__{tool}")
}
pub fn split_wire_name(name: &str) -> Option<(String, String)> {
    let (server, tool) = name.strip_prefix("mcp__")?.split_once("__")?;
    Some((server.into(), tool.into()))
}

struct ServerSlot {
    cfg: McpServerConfig,
    cwd: Option<PathBuf>,
    session: Option<McpSession>,
}
type SlotMap = HashMap<String, Arc<Mutex<ServerSlot>>>;

/// Independent server locks: one stalled server cannot stop another server.
pub struct McpPool {
    sessions: OnceLock<Mutex<SlotMap>>,
}
impl McpPool {
    pub const fn new() -> Self {
        Self {
            sessions: OnceLock::new(),
        }
    }

    fn slot(
        &self,
        name: &str,
        cfg: &McpServerConfig,
        options: &McpCallOptions,
    ) -> Result<Arc<Mutex<ServerSlot>>, String> {
        cfg.validate()?;
        options.check()?;
        if !cfg.enabled {
            return Err(format!("mcp server {name} is disabled"));
        }
        let cwd = cfg.effective_cwd(options)?;
        let mutex = self.sessions.get_or_init(|| Mutex::new(HashMap::new()));
        let mut map = lock_with_options(mutex, options)?;
        Ok(map
            .entry(name.into())
            .or_insert_with(|| {
                Arc::new(Mutex::new(ServerSlot {
                    cfg: cfg.clone(),
                    cwd,
                    session: None,
                }))
            })
            .clone())
    }

    fn with_session<T>(
        &self,
        name: &str,
        cfg: &McpServerConfig,
        options: &McpCallOptions,
        call: impl FnOnce(&mut McpSession, &McpCallOptions) -> Result<T, String>,
    ) -> Result<T, String> {
        cfg.validate()?;
        let mut options = options.bounded(cfg.timeout_ms);
        options.check()?;
        let cwd = cfg.effective_cwd(&options)?;
        options.working_dir = cwd.clone();
        let slot = self.slot(name, cfg, &options)?;
        let mut entry = lock_with_options(&slot, &options)?;
        options.check()?;
        if entry.cfg != *cfg || entry.cwd != cwd {
            entry.session.take();
            entry.cfg = cfg.clone();
            entry.cwd = cwd;
        }
        if entry.session.as_mut().is_none_or(|s| !s.is_alive()) {
            entry.session.take();
            entry.session = Some(McpSession::spawn_with_options(name, cfg, &options)?);
        }
        let session = entry.session.as_mut().ok_or("mcp session vanished")?;
        let result = call(session, &options);
        if !session.is_alive() {
            entry.session.take();
        }
        result
    }

    pub fn get(&self, name: &str, cfg: &McpServerConfig) -> Result<(), String> {
        self.get_with_options(name, cfg, &cfg.options())
    }

    /// Stop a server's running process, so its next use starts a new one.
    /// `Ok(true)` when one was running. A call still in flight is waited for
    /// a little (two seconds), then reported rather than cut short.
    pub fn close(&self, name: &str) -> Result<bool, String> {
        let Some(map) = self.sessions.get() else {
            return Ok(false);
        };
        let slot = map
            .lock()
            .map_err(|_| "mcp pool lock poisoned".to_owned())?
            .get(name)
            .cloned();
        let Some(slot) = slot else {
            return Ok(false);
        };
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            match slot.try_lock() {
                Ok(mut entry) => return Ok(entry.session.take().is_some()),
                Err(TryLockError::Poisoned(_)) => return Err("mcp pool lock poisoned".into()),
                Err(TryLockError::WouldBlock) if Instant::now() >= deadline => {
                    return Err(format!("a call to {name} is still running"));
                }
                Err(TryLockError::WouldBlock) => std::thread::sleep(POLL_INTERVAL),
            }
        }
    }

    /// What each running server said about itself at its handshake
    /// (`instructions`), by server name, in name order. A server that is
    /// busy with a call right now is left out rather than waited for.
    pub fn instructions(&self) -> Vec<(String, String)> {
        let Some(mutex) = self.sessions.get() else {
            return Vec::new();
        };
        let slots: Vec<(String, Arc<Mutex<ServerSlot>>)> = match mutex.lock() {
            Ok(map) => map
                .iter()
                .map(|(name, slot)| (name.clone(), slot.clone()))
                .collect(),
            Err(_) => return Vec::new(),
        };
        let mut said: Vec<(String, String)> = slots
            .into_iter()
            .filter_map(|(name, slot)| {
                let entry = slot.try_lock().ok()?;
                let text = entry.session.as_ref()?.instructions()?.trim().to_owned();
                (!text.is_empty()).then_some((name, text))
            })
            .collect();
        said.sort();
        said
    }

    /// Listen on a channel server for `wait`, starting it when it is not
    /// running (see [`McpSession::poll_channel`]). Calls to the same server
    /// wait while this holds it, so `wait` is kept short.
    /// Returns the server's handshake `instructions`, when it gave any.
    pub fn poll_channel(
        &self,
        name: &str,
        cfg: &McpServerConfig,
        wait: Duration,
    ) -> Result<Option<String>, String> {
        self.with_session(name, cfg, &cfg.options(), |session, _| {
            let heard = session.poll_channel(wait);
            if heard.is_err() {
                session.retire();
            }
            heard.map(|()| session.instructions().map(str::to_owned))
        })
    }

    /// Does the running channel server relay permission prompts? Starts it
    /// when it is not running.
    pub fn channel_relays_permission(
        &self,
        name: &str,
        cfg: &McpServerConfig,
    ) -> Result<bool, String> {
        self.with_session(name, cfg, &cfg.options(), |session, _| {
            Ok(session.relays_permission())
        })
    }

    /// Relay a permission prompt to a channel server (see
    /// [`McpSession::relay_permission_request`]).
    pub fn relay_permission_request(
        &self,
        name: &str,
        cfg: &McpServerConfig,
        request_id: &str,
        tool_name: &str,
        description: &str,
        input_preview: &str,
    ) -> Result<bool, String> {
        self.with_session(name, cfg, &cfg.options(), |session, _| {
            let sent =
                session.relay_permission_request(request_id, tool_name, description, input_preview);
            if sent.is_err() {
                session.retire();
            }
            sent
        })
    }
    pub fn get_with_options(
        &self,
        name: &str,
        cfg: &McpServerConfig,
        options: &McpCallOptions,
    ) -> Result<(), String> {
        self.with_session(name, cfg, options, |_, options| options.check())
    }
    pub fn request(
        &self,
        name: &str,
        cfg: &McpServerConfig,
        method: &str,
        params: serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        self.request_with_options(name, cfg, method, params, &cfg.options())
    }
    pub fn request_with_options(
        &self,
        name: &str,
        cfg: &McpServerConfig,
        method: &str,
        params: serde_json::Value,
        options: &McpCallOptions,
    ) -> Result<serde_json::Value, String> {
        cfg.validate()?;
        if method == "tools/call" {
            let tool = params
                .get("name")
                .and_then(|n| n.as_str())
                .ok_or("mcp tools/call requires a tool name")?;
            if !cfg.tool_enabled(tool) {
                return Err(format!("mcp tool {tool} is disabled"));
            }
        }
        let mut attempted = false;
        let result = self.with_session(name, cfg, options, |session, options| {
            attempted = true;
            session.request_with_options(method, params, options)
        });
        if method == "tools/call" && !attempted {
            result.map_err(|error| format!("{error}; no tool request was sent"))
        } else {
            result
        }
    }
    pub fn list_tools(
        &self,
        name: &str,
        cfg: &McpServerConfig,
    ) -> Result<Vec<McpToolInfo>, String> {
        self.list_tools_with_options(name, cfg, &cfg.options())
    }
    pub fn list_tools_with_options(
        &self,
        name: &str,
        cfg: &McpServerConfig,
        options: &McpCallOptions,
    ) -> Result<Vec<McpToolInfo>, String> {
        cfg.validate()?;
        options.check()?;
        if !cfg.enabled || cfg.tools.as_ref().is_some_and(Vec::is_empty) {
            return Ok(Vec::new());
        }
        self.with_session(name, cfg, options, |session, options| {
            session.list_tools_with_options(options)
        })
    }
    pub fn call_tool(
        &self,
        name: &str,
        cfg: &McpServerConfig,
        tool: &str,
        arguments: serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        self.call_tool_with_options(name, cfg, tool, arguments, &cfg.options())
    }
    pub fn call_tool_with_options(
        &self,
        name: &str,
        cfg: &McpServerConfig,
        tool: &str,
        arguments: serde_json::Value,
        options: &McpCallOptions,
    ) -> Result<serde_json::Value, String> {
        self.request_with_options(
            name,
            cfg,
            "tools/call",
            serde_json::json!({"name":tool,"arguments":arguments}),
            options,
        )
    }
}

fn lock_with_options<'a, T>(
    mutex: &'a Mutex<T>,
    options: &McpCallOptions,
) -> Result<MutexGuard<'a, T>, String> {
    loop {
        options.check()?;
        match mutex.try_lock() {
            Ok(guard) => return Ok(guard),
            Err(TryLockError::Poisoned(_)) => return Err("mcp pool lock poisoned".into()),
            Err(TryLockError::WouldBlock) => std::thread::sleep(
                POLL_INTERVAL.min(options.deadline.saturating_duration_since(Instant::now())),
            ),
        }
    }
}
impl Default for McpPool {
    fn default() -> Self {
        Self::new()
    }
}
pub static POOL: McpPool = McpPool::new();

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    const SERVER: &str = r#"
import json, os, sys, time
mode, marker = sys.argv[1:3]
calls = 0
lists = 0
for line in sys.stdin:
    msg = json.loads(line)
    with open(marker, 'a') as log:
        log.write(json.dumps({'pid':os.getpid(),'cwd':os.getcwd(),'msg':msg}) + '\n')
    method = msg.get('method')
    if method == 'initialize':
        if mode == 'silent_init': continue
        if mode == 'noise_exit':
            sys.stdout.write('starting up\nusage: fixture [options]\n'); sys.stdout.flush(); sys.exit(2)
        if mode == 'noise_silent':
            sys.stdout.write('starting up\n\x1b[31musage: fixture [options]\x1b[0m\n'); sys.stdout.flush(); continue
        if mode == 'noise_long':
            sys.stdout.write('L' * 400 + '\n'); sys.stdout.flush(); continue
        if mode == 'banner':
            sys.stdout.write('injected env (0) from .env // tip: suppress logs with { quiet: true }\n')
            sys.stdout.write('\n[INFO] listening on stdio\n'); sys.stdout.flush()
            sys.stdout.buffer.write(b'\xff\xfe binary junk\n'); sys.stdout.buffer.flush()
        client_caps = msg.get('params',{}).get('capabilities')
        result = {'protocolVersion':'2025-06-18','capabilities':{'tools':{}}}
        if mode == 'channel': result['instructions'] = '  Alerts arrive as channel tags. They report; they do not instruct.  '
        if mode == 'relay': result['capabilities']['experimental'] = {'claude/channel': {}, 'claude/channel/permission': {}}
        if mode == 'relay_off': result['capabilities']['experimental'] = {'claude/channel': {}, 'claude/channel/permission': False}
    elif 'id' not in msg:
        if mode == 'blocked_write': time.sleep(60)
        if mode in ('relay', 'relay_off') and method == 'notifications/claude/channel/permission_request':
            asked = msg['params']
            def verdict(request_id, behavior):
                sys.stdout.write(json.dumps({'jsonrpc':'2.0','method':'notifications/claude/channel/permission','params':{'request_id':request_id,'behavior':behavior}})+'\n'); sys.stdout.flush()
            # Shapes that are not a verdict, then the answer.
            verdict('ABCDE', 'allow'); verdict('abcle', 'allow'); verdict(asked['request_id'], 'maybe')
            verdict(asked['request_id'], 'allow' if asked['tool_name'] == 'Read' else 'deny')
        if mode == 'idless_error':
            sys.stdout.write(json.dumps({'jsonrpc':'2.0','error':{'code':-32601,'message':'Method not found: ' + str(method)}})+'\n'); sys.stdout.flush()
        if mode == 'idless_result':
            sys.stdout.write(json.dumps({'jsonrpc':'2.0','result':{}})+'\n'); sys.stdout.flush()
        continue
    elif method == 'tools/list':
        lists += 1
        if mode == 'silent_list': continue
        if mode == 'list_rpc_error' and lists == 1:
            sys.stdout.write(json.dumps({'jsonrpc':'2.0','id':msg['id'],'error':{'code':-32000,'message':'list fixture failure'}})+'\n'); sys.stdout.flush(); continue
        result = {'tools':[{'name':'echo','description':'echoes','inputSchema':{'type':'object'}}, {'name':'hidden','inputSchema':{'type':'object'}}]}
        cursor = msg.get('params',{}).get('cursor')
        if mode == 'paged':
            result = {'tools':[{'name':'hidden' if cursor is None else 'echo','inputSchema':{'type':'object'}}]}
            if cursor is None: result['nextCursor'] = 'page-two'
        if mode == 'repeated_cursor':
            result = {'tools':[], 'nextCursor':'repeat'}
        if mode == 'aggregate':
            result = {'tools':[{'name':'large-'+str(cursor),'description':'x'*9000000,'inputSchema':{'type':'object'}}]}
            if cursor is None: result['nextCursor'] = 'page-two'
        if mode == 'big_list':
            result = {'tools':[{'name':'big-'+str(i),'description':'d'*175000,'inputSchema':{'type':'object'}} for i in range(20)]}
        if mode == 'huge_list':
            result = {'tools':[{'name':'huge-'+str(i),'description':'d'*600000,'inputSchema':{'type':'object'}} for i in range(20)]}
        if mode == 'invalid_page': result = {'tools':'invalid'}
        if mode == 'invalid_cursor': result = {'tools':[], 'nextCursor':42}
        if mode == 'invalid_schema': result = {'tools':[{'name':'broken','inputSchema':'oops'}]}
        if mode == 'empty_name': result = {'tools':[{'name':'','inputSchema':{'type':'object'}}]}
        if mode == 'page_limit': result = {'tools':[], 'nextCursor':str(int(cursor or 0)+1)}
        if mode == 'tool_limit': result = {'tools':[{'name':str(i)} for i in range(4097)]}
        if mode == 'paged_delay':
            time.sleep(.075)
            result = {'tools':[]}
            if cursor is None: result['nextCursor'] = 'page-two'
    else:
        calls += 1
        if mode == 'silent_call': continue
        if mode == 'eof': sys.exit(0)
        if mode == 'malformed':
            sys.stdout.write('not-json\n'); sys.stdout.flush(); continue
        if mode == 'broken_object':
            sys.stdout.write('{"jsonrpc": "2.0", "id": \n'); sys.stdout.flush(); continue
        if mode == 'null_id':
            sys.stdout.write(json.dumps({'jsonrpc':'2.0','id':None,'error':{'code':-32700,'message':'Parse error'}})+'\n'); sys.stdout.flush(); continue
        if mode == 'big_call':
            sys.stdout.write(json.dumps({'jsonrpc':'2.0','id':msg['id'],'result':{'content':[{'type':'text','text':'y'*(2*1024*1024)}]}})+'\n'); sys.stdout.flush(); continue
        if mode == 'idle_noise':
            import threading
            threading.Timer(.1, lambda: (sys.stdout.write('late log line\n'), sys.stdout.flush())).start()
        if mode == 'idle_huge':
            import threading
            threading.Timer(.1, lambda: (sys.stdout.write('z' * (12*1024*1024) + '\n'), sys.stdout.flush())).start()
        if mode == 'idle_oversize':
            import threading
            threading.Timer(.1, lambda: (sys.stdout.write('z' * (16*1024*1024+1) + '\n'), sys.stdout.flush())).start()
        if mode == 'idle_endless':
            import threading
            threading.Timer(.1, lambda: (sys.stdout.write('z' * (16*1024*1024+1)), sys.stdout.flush())).start()
        if mode == 'invalid_protocol':
            sys.stdout.write(json.dumps({'jsonrpc':'1.0','id':msg['id'],'result':{}})+'\n'); sys.stdout.flush(); continue
        if mode in ('oversize','no_newline'):
            sys.stdout.write('x' * (16*1024*1024+1) + ('\n' if mode == 'oversize' else '')); sys.stdout.flush(); continue
        if mode == 'noise_flood':
            while True:
                sys.stdout.write('a log line that never ends the conversation\n')
                sys.stdout.flush()
        if mode == 'flood':
            while True:
                sys.stdout.write(json.dumps({'jsonrpc':'2.0','method':'notifications/progress','params':{}})+'\n')
                sys.stdout.flush()
        if mode == 'unmatched_ids':
            while True:
                sys.stdout.write(json.dumps({'jsonrpc':'2.0','id':999,'result':{}})+'\n')
                sys.stdout.flush()
        if mode == 'server_request':
            for server_method in ('unsupported/clientMethod', 'ping'):
                sys.stdout.write(json.dumps({'jsonrpc':'2.0','id':msg['id'],'method':server_method,'params':{}})+'\n'); sys.stdout.flush()
                answer = json.loads(sys.stdin.readline())
                if answer.get('jsonrpc') != '2.0' or answer.get('id') != msg['id']: sys.exit(2)
                if server_method == 'ping':
                    if answer.get('result') != {} or 'error' in answer: sys.exit(2)
                elif answer.get('error',{}).get('code') != -32601: sys.exit(2)
        if mode == 'channel':
            def push(content, meta):
                sys.stdout.write(json.dumps({'jsonrpc':'2.0','method':'notifications/claude/channel','params':{'content':content,'meta':meta}})+'\n'); sys.stdout.flush()
            push('during the call', {'severity':'high','bad-key':'dropped','n':3})
            import threading
            threading.Timer(.15, push, ['while idle', {'run_id':'42'}]).start()
        if mode == 'elicit':
            sys.stdout.write(json.dumps({'jsonrpc':'2.0','id':'ask-1','method':'elicitation/create','params':{
                'message':'Which branch?','requestedSchema':{'type':'object','properties':{'branch':{'type':'string'}},'required':['branch']}}})+'\n'); sys.stdout.flush()
            answer = json.loads(sys.stdin.readline())
            result = {'content':[{'type':'text','text':json.dumps({'answer':answer,'caps':client_caps}, sort_keys=True)}]}
            sys.stdout.write(json.dumps({'jsonrpc':'2.0','id':msg['id'],'result':result}) + '\n'); sys.stdout.flush(); continue
        if mode == 'rpc_error' and calls == 1:
            sys.stdout.write(json.dumps({'jsonrpc':'2.0','id':msg['id'],'error':{'code':-32000,'message':'fixture failure'}})+'\n'); sys.stdout.flush(); continue
        result = {'content':[{'type':'text','text':'hello from mcp'}], 'pid':os.getpid(), 'cwd':os.getcwd(), 'arguments':msg.get('params',{}).get('arguments'), 'home':os.environ.get('HOME')}
    if mode == 'banner': sys.stdout.write('[INFO] answering ' + str(method) + '\n')
    sys.stdout.write(json.dumps({'jsonrpc':'2.0','id':msg['id'],'result':result}) + '\n')
    sys.stdout.flush()
"#;

    struct Fixture {
        dir: PathBuf,
        marker: PathBuf,
        cfg: McpServerConfig,
    }
    impl Fixture {
        fn new(mode: &str) -> Self {
            let dir = std::env::temp_dir().join(format!("orbit-mcp-test-{}", ulid::Ulid::new()));
            std::fs::create_dir_all(&dir).unwrap();
            let marker = dir.join("events.jsonl");
            let cfg = McpServerConfig {
                transport: McpTransport::Stdio,
                command: "python3".into(),
                args: vec![
                    "-u".into(),
                    "-c".into(),
                    SERVER.into(),
                    mode.into(),
                    marker.to_string_lossy().into(),
                ],
                env: Default::default(),
                url: None,
                headers: Default::default(),
                enabled: true,
                tools: None,
                timeout_ms: 2_000,
                initialize_timeout_ms: 1_000,
            };
            Self { dir, marker, cfg }
        }
        fn events(&self) -> Vec<serde_json::Value> {
            std::fs::read_to_string(&self.marker)
                .unwrap_or_default()
                .split_inclusive('\n')
                .filter(|line| line.ends_with('\n'))
                .map(|line| serde_json::from_str(line).unwrap())
                .collect()
        }
        fn wait_method(&self, method: &str) {
            let deadline = Instant::now() + Duration::from_secs(2);
            while !self.events().iter().any(|e| e["msg"]["method"] == method) {
                assert!(
                    Instant::now() < deadline,
                    "fixture did not receive {method}"
                );
                std::thread::sleep(Duration::from_millis(5));
            }
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    #[test]
    fn a_servers_question_reaches_the_handler_and_its_answer_goes_back() {
        // The handler is one per process: this is the only test that sets it.
        let asked = Arc::new(Mutex::new(Vec::new()));
        let record = asked.clone();
        set_elicitation_handler(Some(Arc::new(move |request: &Elicitation| {
            record.lock().unwrap().push((
                request.server.clone(),
                request.message.clone(),
                request.mode.clone(),
                request.schema["required"][0].as_str().map(str::to_owned),
            ));
            // Longer than the fixture's whole request budget (2 s): the
            // time spent answering is given back to the waiting call.
            std::thread::sleep(Duration::from_millis(2_300));
            ElicitationAnswer::Accept(serde_json::json!({"branch": "main"}))
        })));
        let fixture = Fixture::new("elicit");
        let mut session = McpSession::spawn("forge", &fixture.cfg).unwrap();
        let result = session.call_tool("echo", serde_json::json!({})).unwrap();
        let text: serde_json::Value =
            serde_json::from_str(result["content"][0]["text"].as_str().unwrap()).unwrap();
        assert_eq!(
            text["answer"],
            serde_json::json!({
                "jsonrpc": "2.0", "id": "ask-1",
                "result": {"action": "accept", "content": {"branch": "main"}}
            })
        );
        assert_eq!(text["caps"], serde_json::json!({"elicitation": {}}));
        assert_eq!(
            *asked.lock().unwrap(),
            [(
                "forge".to_owned(),
                "Which branch?".to_owned(),
                "form".to_owned(),
                Some("branch".to_owned())
            )]
        );
        // Declined and dismissed answers have their own shapes.
        assert_eq!(
            ElicitationAnswer::Decline.result(),
            serde_json::json!({"action": "decline"})
        );
        assert_eq!(
            ElicitationAnswer::Cancel.result(),
            serde_json::json!({"action": "cancel"})
        );
        set_elicitation_handler(None);
        // Without a handler the capability is not offered and the question
        // is refused as an unsupported method.
        let fixture = Fixture::new("elicit");
        let mut session = McpSession::spawn("forge", &fixture.cfg).unwrap();
        let result = session.call_tool("echo", serde_json::json!({})).unwrap();
        let text: serde_json::Value =
            serde_json::from_str(result["content"][0]["text"].as_str().unwrap()).unwrap();
        assert_eq!(text["answer"]["error"]["code"], -32601);
        assert_eq!(text["caps"], serde_json::json!({}));
    }

    /// A stdio server does not inherit a variable that holds the provider's
    /// credentials, unless its own configuration sets it.
    #[test]
    fn a_withheld_variable_is_not_inherited_unless_the_server_sets_it() {
        // `HOME` stands in for a credential variable: it is set in this
        // process, and the fixture runs without it. The list is the
        // process's: this is the only test that sets it.
        assert!(
            std::env::var_os("HOME").is_some(),
            "the test needs HOME set"
        );
        let fixture = Fixture::new("ok");
        let mut session = McpSession::spawn("plain", &fixture.cfg).unwrap();
        let inherited = session.call_tool("echo", serde_json::json!({})).unwrap();
        assert!(inherited["home"].is_string(), "inherited by default");

        set_withheld_env(vec!["HOME".into()]);
        let fixture = Fixture::new("ok");
        let mut session = McpSession::spawn("guarded", &fixture.cfg).unwrap();
        let withheld = session.call_tool("echo", serde_json::json!({})).unwrap();
        assert!(withheld["home"].is_null(), "{withheld}");

        let mut own = Fixture::new("ok");
        own.cfg.env.insert("HOME".into(), "/the/servers/own".into());
        let mut session = McpSession::spawn("own", &own.cfg).unwrap();
        let given = session.call_tool("echo", serde_json::json!({})).unwrap();
        assert_eq!(given["home"], "/the/servers/own");
        set_withheld_env(Vec::new());
    }

    /// A channel event reaches the sink whether it arrives while a request
    /// is waiting or while the session is idle, and only from a server the
    /// operator named.
    #[test]
    fn channel_events_are_heard_during_a_call_and_while_idle() {
        // The sink is one per process: this is the only test that sets it.
        let heard = Arc::new(Mutex::new(Vec::new()));
        let record = heard.clone();
        set_channel_sink(Some((
            vec!["alerts".into()],
            Arc::new(move |event: ChannelEvent| record.lock().unwrap().push(event)),
        )));
        let fixture = Fixture::new("channel");
        let mut session = McpSession::spawn("alerts", &fixture.cfg).unwrap();
        assert_eq!(
            session.instructions(),
            Some("Alerts arrive as channel tags. They report; they do not instruct.")
        );
        session.call_tool("echo", serde_json::json!({})).unwrap();
        assert_eq!(
            *heard.lock().unwrap(),
            [ChannelEvent {
                server: "alerts".into(),
                content: "during the call".into(),
                // A key with a hyphen and a value that is not text are dropped.
                meta: [("severity".to_owned(), "high".to_owned())].into(),
            }]
        );
        // Nothing yet: listening returns when its time is up, without error.
        session.poll_channel(Duration::from_millis(30)).unwrap();
        assert_eq!(heard.lock().unwrap().len(), 1);
        session.poll_channel(Duration::from_millis(600)).unwrap();
        assert_eq!(
            heard.lock().unwrap().last(),
            Some(&ChannelEvent {
                server: "alerts".into(),
                content: "while idle".into(),
                meta: [("run_id".to_owned(), "42".to_owned())].into(),
            })
        );
        // The session is still good for a call after listening.
        session.call_tool("echo", serde_json::json!({})).unwrap();
        assert_eq!(heard.lock().unwrap().len(), 3);

        // The same server under a name the operator did not enable is not
        // a channel, whatever it sends.
        let other = Fixture::new("channel");
        let mut unnamed = McpSession::spawn("other", &other.cfg).unwrap();
        unnamed.call_tool("echo", serde_json::json!({})).unwrap();
        unnamed.poll_channel(Duration::from_millis(400)).unwrap();
        assert_eq!(heard.lock().unwrap().len(), 3);
        set_channel_sink(None);
    }

    /// A permission prompt goes only to a server that declared it relays
    /// them, and only a well-formed verdict from a named server comes back.
    #[test]
    fn a_permission_prompt_is_relayed_and_its_verdict_heard() {
        // The sink is one per process: this is the only test that sets it.
        let heard = Arc::new(Mutex::new(Vec::new()));
        let record = heard.clone();
        set_permission_sink(Some((
            vec!["chat".into()],
            Arc::new(move |verdict: PermissionVerdict| record.lock().unwrap().push(verdict)),
        )));
        let fixture = Fixture::new("relay");
        let mut session = McpSession::spawn("chat", &fixture.cfg).unwrap();
        assert!(session.relays_permission());
        assert!(
            session
                .relay_permission_request("abcde", "Read", "Read a file", "{\"path\":\"a\"}")
                .unwrap()
        );
        session.poll_channel(Duration::from_millis(500)).unwrap();
        assert!(
            session
                .relay_permission_request("fghij", "Bash", "Run shell command", "{}")
                .unwrap()
        );
        session.poll_channel(Duration::from_millis(500)).unwrap();
        let verdict = |request_id: &str, allow| PermissionVerdict {
            server: "chat".into(),
            request_id: request_id.into(),
            allow,
        };
        assert_eq!(
            *heard.lock().unwrap(),
            [verdict("abcde", true), verdict("fghij", false)]
        );
        let asked = fixture
            .events()
            .into_iter()
            .find(|e| e["msg"]["method"] == "notifications/claude/channel/permission_request")
            .unwrap();
        assert_eq!(
            asked["msg"]["params"],
            serde_json::json!({
                "request_id": "abcde",
                "tool_name": "Read",
                "description": "Read a file",
                "input_preview": "{\"path\":\"a\"}",
            })
        );

        // `false` is not a declaration: nothing is sent.
        let off = Fixture::new("relay_off");
        let mut silent = McpSession::spawn("chat", &off.cfg).unwrap();
        assert!(!silent.relays_permission());
        assert!(
            !silent
                .relay_permission_request("abcde", "Read", "", "")
                .unwrap()
        );

        // The same server under a name that was not enabled is not heard.
        let other = Fixture::new("relay");
        let mut unnamed = McpSession::spawn("other", &other.cfg).unwrap();
        unnamed
            .relay_permission_request("abcde", "Read", "", "")
            .unwrap();
        unnamed.poll_channel(Duration::from_millis(400)).unwrap();
        assert_eq!(heard.lock().unwrap().len(), 2);
        set_permission_sink(None);

        assert!(permission_request_id_ok("abcde"));
        for bad in ["abcd", "abcdef", "abcle", "ABCDE", "abc1e", "abcdé"] {
            assert!(!permission_request_id_ok(bad), "{bad}");
        }
    }

    fn options(ms: u64) -> McpCallOptions {
        McpCallOptions::new(Duration::from_millis(ms))
    }
    fn cancel_options(ms: u64, cancelled: &Arc<AtomicBool>) -> McpCallOptions {
        let flag = cancelled.clone();
        options(ms).with_cancel(Arc::new(move || flag.load(Ordering::SeqCst)))
    }
    fn assert_quick(start: Instant) {
        assert!(
            start.elapsed() < Duration::from_secs(1),
            "call took {:?}",
            start.elapsed()
        );
    }

    #[test]
    fn wire_names_roundtrip() {
        assert_eq!(
            wire_name("github", "create_issue"),
            "mcp__github__create_issue"
        );
        assert_eq!(
            split_wire_name("mcp__github__create_issue"),
            Some(("github".into(), "create_issue".into()))
        );
        assert_eq!(split_wire_name("Read"), None);
    }

    #[test]
    fn config_defaults_merge_trusted_scope_and_validate() {
        let fixture = Fixture::new("normal");
        let project = fixture.dir.join("project");
        std::fs::create_dir_all(project.join(".orbit")).unwrap();
        std::fs::write(
            fixture.dir.join("mcp.json"),
            r#"{"servers":{"user":{"command":"cat"},"same":{"command":"user"}}}"#,
        )
        .unwrap();
        std::fs::write(
            project.join(".orbit/mcp.json"),
            r#"{"servers":{"project":{"command":"cat","tools":[]},"same":{"command":"project"}}}"#,
        )
        .unwrap();
        let untrusted = McpConfig::try_load_at(&fixture.dir, &project, false).unwrap();
        assert_eq!(untrusted.servers.len(), 2);
        assert_eq!(untrusted.servers["same"].command, "user");
        let user = &untrusted.servers["user"];
        assert!(user.enabled && user.tools.is_none());
        assert_eq!(
            (user.timeout_ms, user.initialize_timeout_ms),
            (30_000, 5_000)
        );
        let trusted = McpConfig::try_load_at(&fixture.dir, &project, true).unwrap();
        assert_eq!(trusted.servers["same"].command, "project");
        assert!(!trusted.servers["project"].tool_enabled("anything"));
        for field in ["timeout_ms", "initialize_timeout_ms"] {
            for value in [0, 600_001] {
                let mut value_cfg = serde_json::to_value(&fixture.cfg).unwrap();
                value_cfg[field] = value.into();
                let cfg: McpServerConfig = serde_json::from_value(value_cfg).unwrap();
                assert!(cfg.validate().is_err());
                assert!(McpSession::spawn("invalid", &cfg).is_err());
            }
        }
        assert!(fixture.events().is_empty());
        std::fs::write(
            fixture.dir.join("mcp.json"),
            r#"{"servers":{"bad":{"command":"cat","timeout_ms":0}}}"#,
        )
        .unwrap();
        assert!(McpConfig::try_load_at(&fixture.dir, &project, false).is_err());
        std::fs::write(fixture.dir.join("mcp.json"), "bad json").unwrap();
        assert!(McpConfig::try_load_at(&fixture.dir, &project, false).is_err());
    }

    #[test]
    fn close_stops_the_running_server_and_the_next_use_starts_a_new_process() {
        let fixture = Fixture::new("normal");
        let pool = McpPool::new();
        // Nothing has run: nothing to stop, and no error.
        assert_eq!(pool.close("fake"), Ok(false));
        let first = pool
            .call_tool("fake", &fixture.cfg, "echo", serde_json::json!({}))
            .unwrap();
        let again = pool
            .call_tool("fake", &fixture.cfg, "echo", serde_json::json!({}))
            .unwrap();
        assert_eq!(first["pid"], again["pid"], "one process is reused");
        assert_eq!(pool.close("fake"), Ok(true));
        assert_eq!(pool.close("fake"), Ok(false), "already stopped");
        // Another name is untouched, and the closed one starts afresh.
        assert_eq!(pool.close("never-started"), Ok(false));
        let fresh = pool
            .call_tool("fake", &fixture.cfg, "echo", serde_json::json!({}))
            .unwrap();
        assert_ne!(first["pid"], fresh["pid"]);
    }

    #[test]
    fn legacy_wrappers_reuse_session_and_filter_exact_tool_names() {
        let fixture = Fixture::new("normal");
        let pool = McpPool::new();
        let mut cfg = fixture.cfg.clone();
        cfg.tools = Some(vec!["echo".into()]);
        pool.get("fake", &cfg).unwrap();
        let tools = pool.list_tools("fake", &cfg).unwrap();
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0].name, "echo");
        let first = pool
            .call_tool("fake", &cfg, "echo", serde_json::json!({"text":"hi"}))
            .unwrap();
        let second = pool
            .request(
                "fake",
                &cfg,
                "tools/call",
                serde_json::json!({"name":"echo","arguments":{}}),
            )
            .unwrap();
        assert_eq!(first["pid"], second["pid"]);
        let before = fixture.events().len();
        assert!(
            pool.call_tool("fake", &cfg, "hidden", serde_json::json!({}))
                .unwrap_err()
                .contains("disabled")
        );
        assert!(
            pool.request(
                "fake",
                &cfg,
                "tools/call",
                serde_json::json!({"name":"Echo"})
            )
            .is_err()
        );
        assert_eq!(fixture.events().len(), before);
        assert_eq!(
            fixture
                .events()
                .iter()
                .filter(|e| e["msg"]["method"] == "initialize")
                .count(),
            1
        );
        let mut session = McpSession::spawn("direct", &cfg).unwrap();
        assert!(session.call_tool("hidden", serde_json::json!({})).is_err());
        assert!(
            session
                .request("tools/call", serde_json::json!({"name":"hidden"}))
                .is_err()
        );
        assert!(session.is_alive());
    }

    #[test]
    fn disabled_and_empty_allowlist_do_not_spawn() {
        let fixture = Fixture::new("normal");
        let pool = McpPool::new();
        let mut cfg = fixture.cfg.clone();
        cfg.enabled = false;
        assert!(McpSession::spawn("disabled", &cfg).is_err());
        assert!(pool.list_tools("disabled", &cfg).unwrap().is_empty());
        assert!(
            pool.call_tool("disabled", &cfg, "echo", serde_json::json!({}))
                .is_err()
        );
        cfg.enabled = true;
        cfg.tools = Some(vec![]);
        assert!(pool.list_tools("empty", &cfg).unwrap().is_empty());
        assert!(
            pool.request(
                "empty",
                &cfg,
                "tools/call",
                serde_json::json!({"name":"echo"})
            )
            .is_err()
        );
        assert!(fixture.events().is_empty());
    }

    #[test]
    fn selected_tools_are_discovered_on_later_pages_under_one_budget() {
        let fixture = Fixture::new("paged");
        let mut cfg = fixture.cfg.clone();
        cfg.tools = Some(vec!["echo".into()]);
        let pool = McpPool::new();
        let tools = pool.list_tools("paged", &cfg).unwrap();
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0].name, "echo");
        let events = fixture.events();
        let pages: Vec<_> = events
            .iter()
            .filter(|e| e["msg"]["method"] == "tools/list")
            .collect();
        assert_eq!(pages.len(), 2);
        assert_eq!(pages[1]["msg"]["params"]["cursor"], "page-two");

        let delayed = Fixture::new("paged_delay");
        let mut session = McpSession::spawn("delayed", &delayed.cfg).unwrap();
        let start = Instant::now();
        assert!(
            session
                .list_tools_with_options(&options(120))
                .unwrap_err()
                .contains("timed out")
        );
        assert!(start.elapsed() < Duration::from_millis(210));
        assert!(!session.is_alive());
    }

    #[test]
    fn discovery_rejects_repeated_cursor_invalid_pages_and_aggregate_caps() {
        for (mode, expected) in [
            ("repeated_cursor", "repeats a cursor"),
            ("aggregate", "aggregate tool metadata exceeds 16 MiB"),
            ("invalid_page", "no tools array"),
            ("invalid_cursor", "invalid nextCursor"),
            ("invalid_schema", "invalid inputSchema"),
            ("empty_name", "empty name"),
            ("page_limit", "exceeds 32 pages"),
            ("tool_limit", "exceeds 4096 tools"),
        ] {
            let fixture = Fixture::new(mode);
            let mut session = McpSession::spawn(mode, &fixture.cfg).unwrap();
            let error = session.list_tools().unwrap_err();
            assert!(error.contains(expected), "{mode}: {error}");
            assert!(!session.is_alive(), "{mode}");
        }
    }

    #[test]
    fn tool_transport_errors_distinguish_no_send_from_unknown_outcome() {
        let fixture = Fixture::new("silent_call");
        let pool = McpPool::new();
        let cancelled = Arc::new(AtomicBool::new(true));
        let error = pool
            .call_tool_with_options(
                "server",
                &fixture.cfg,
                "echo",
                serde_json::json!({}),
                &cancel_options(1000, &cancelled),
            )
            .unwrap_err();
        assert!(error.contains("no tool request was sent"));
        assert!(!error.contains("outcome is unknown"));
        assert!(fixture.events().is_empty());
        let error = pool
            .call_tool_with_options(
                "server",
                &fixture.cfg,
                "echo",
                serde_json::json!({"private":"not part of diagnostic"}),
                &options(100),
            )
            .unwrap_err();
        assert!(error.contains("tool outcome is unknown"));
        assert!(error.contains("inspect external effects before retrying"));
        assert!(!error.contains("private"));
        assert!(!error.contains("not part of diagnostic"));
        let fresh = Fixture::new("normal");
        let mut session = McpSession::spawn("direct", &fresh.cfg).unwrap();
        let error = session
            .call_tool_with_options(
                "echo",
                serde_json::json!({}),
                &cancel_options(1000, &cancelled),
            )
            .unwrap_err();
        assert!(error.contains("no tool request was sent"));
        assert!(!error.contains("outcome is unknown"));
        assert!(
            !fresh
                .events()
                .iter()
                .any(|e| e["msg"]["method"] == "tools/call")
        );
    }

    #[test]
    fn silent_initialize_has_own_ceiling_and_pre_cancel_never_spawns() {
        let fixture = Fixture::new("silent_init");
        let mut cfg = fixture.cfg.clone();
        cfg.initialize_timeout_ms = 70;
        let start = Instant::now();
        let error = McpSession::spawn_with_options("silent", &cfg, &options(500))
            .err()
            .unwrap();
        assert!(error.contains("timed out"));
        assert_quick(start);
        assert!(start.elapsed() < Duration::from_millis(400));
        assert!(
            !fixture
                .events()
                .iter()
                .any(|e| e["msg"]["method"] == "notifications/cancelled")
        );
        let cancelled = Arc::new(AtomicBool::new(true));
        let fresh = Fixture::new("normal");
        assert!(
            McpSession::spawn_with_options(
                "pre-cancelled",
                &fresh.cfg,
                &cancel_options(500, &cancelled)
            )
            .err()
            .unwrap()
            .contains("cancelled")
        );
        assert!(fresh.events().is_empty());
    }

    #[test]
    fn cancel_during_initialize_aborts_without_cancellation_notification() {
        let fixture = Fixture::new("silent_init");
        let cancelled = Arc::new(AtomicBool::new(false));
        let flag = cancelled.clone();
        let marker = fixture.marker.clone();
        let trigger = std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(2);
            while !marker.exists() {
                assert!(
                    Instant::now() < deadline,
                    "initialize fixture never started"
                );
                std::thread::sleep(Duration::from_millis(1));
            }
            flag.store(true, Ordering::SeqCst);
        });
        let start = Instant::now();
        let error = McpSession::spawn_with_options(
            "silent",
            &fixture.cfg,
            &cancel_options(1000, &cancelled),
        )
        .err()
        .unwrap();
        trigger.join().unwrap();
        assert!(error.contains("cancelled"));
        assert_quick(start);
        assert!(
            !fixture
                .events()
                .iter()
                .any(|e| e["msg"]["method"] == "notifications/cancelled")
        );
    }

    #[test]
    fn read_deadline_and_cancellation_retire_transport() {
        let fixture = Fixture::new("silent_call");
        let mut session = McpSession::spawn("silent", &fixture.cfg).unwrap();
        let start = Instant::now();
        assert!(
            session
                .call_tool_with_options("echo", serde_json::json!({}), &options(60))
                .unwrap_err()
                .contains("timed out")
        );
        assert_quick(start);
        assert!(!session.is_alive());
        assert!(
            session
                .call_tool("echo", serde_json::json!({}))
                .unwrap_err()
                .contains("retired")
        );
        let mut session = McpSession::spawn("cancel", &fixture.cfg).unwrap();
        let cancelled = Arc::new(AtomicBool::new(false));
        let flag = cancelled.clone();
        let trigger = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(40));
            flag.store(true, Ordering::SeqCst);
        });
        let start = Instant::now();
        assert!(
            session
                .call_tool_with_options(
                    "echo",
                    serde_json::json!({}),
                    &cancel_options(1000, &cancelled)
                )
                .unwrap_err()
                .contains("cancelled")
        );
        trigger.join().unwrap();
        assert_quick(start);
        assert!(!session.is_alive());
    }

    #[test]
    fn blocked_stdin_write_obeys_deadline_and_cancellation() {
        for cancel in [false, true] {
            let fixture = Fixture::new("blocked_write");
            let mut session = McpSession::spawn("blocked", &fixture.cfg).unwrap();
            fixture.wait_method("notifications/initialized");
            let cancelled = Arc::new(AtomicBool::new(false));
            let flag = cancelled.clone();
            let trigger = cancel.then(|| {
                std::thread::spawn(move || {
                    std::thread::sleep(Duration::from_millis(40));
                    flag.store(true, Ordering::SeqCst);
                })
            });
            let opts = cancel_options(if cancel { 1000 } else { 70 }, &cancelled);
            let start = Instant::now();
            let error = session
                .call_tool_with_options(
                    "echo",
                    serde_json::json!({"payload":"x".repeat(800_000)}),
                    &opts,
                )
                .unwrap_err();
            assert!(
                error.contains(if cancel { "cancelled" } else { "timed out" }),
                "{error}"
            );
            if let Some(trigger) = trigger {
                trigger.join().unwrap();
            }
            assert_quick(start);
            assert!(!session.is_alive());
        }
    }

    #[test]
    fn notification_flood_never_resets_deadline() {
        for mode in ["flood", "unmatched_ids", "noise_flood"] {
            let fixture = Fixture::new(mode);
            let mut session = McpSession::spawn(mode, &fixture.cfg).unwrap();
            let start = Instant::now();
            assert!(
                session
                    .call_tool_with_options("echo", serde_json::json!({}), &options(80))
                    .unwrap_err()
                    .contains("timed out")
            );
            assert_quick(start);
            assert!(!session.is_alive());
        }
        let fixture = Fixture::new("silent_list");
        let mut session = McpSession::spawn("silent-list", &fixture.cfg).unwrap();
        let start = Instant::now();
        assert!(
            session
                .list_tools_with_options(&options(60))
                .unwrap_err()
                .contains("timed out")
        );
        assert_quick(start);
        assert!(!session.is_alive());
    }

    #[test]
    fn malformed_eof_and_oversized_frames_retire_transport() {
        for mode in [
            "broken_object",
            "invalid_protocol",
            "eof",
            "oversize",
            "no_newline",
        ] {
            let fixture = Fixture::new(mode);
            let mut session = McpSession::spawn(mode, &fixture.cfg).unwrap();
            let start = Instant::now();
            let error = session
                .call_tool_with_options("echo", serde_json::json!({}), &options(700))
                .unwrap_err();
            assert!(!error.is_empty());
            assert_quick(start);
            assert!(!session.is_alive(), "{mode}");
            if mode == "oversize" || mode == "no_newline" {
                assert!(error.contains("16 MiB"), "{error}");
            }
        }
        let fixture = Fixture::new("normal");
        let mut session = McpSession::spawn("output", &fixture.cfg).unwrap();
        assert!(
            session
                .call_tool(
                    "echo",
                    serde_json::json!({"payload":"x".repeat(MAX_FRAME_BYTES)})
                )
                .unwrap_err()
                .contains("1 MiB")
        );
        assert!(!session.is_alive());
        assert!(
            !fixture
                .events()
                .iter()
                .any(|e| e["msg"]["method"] == "tools/call")
        );
    }

    /// Real servers print a banner, a log line or a usage text on standard output. The official
    /// clients skip what is not JSON-RPC; so does ORBIT, and a frame cut off in the middle (it starts
    /// with `{`) is still a broken server.
    #[test]
    fn only_text_that_cannot_start_a_json_object_is_noise() {
        for noise in [
            &b""[..],
            b"   ",
            b"hello",
            b"[INFO] up",
            b"[dotenv@17.2.3] injecting env (0) from .env",
            b"\xff\xfe binary junk",
            "\u{25c7} injected env (0) from .env".as_bytes(),
        ] {
            assert!(is_log_noise(noise), "{:?}", String::from_utf8_lossy(noise));
        }
        for not_noise in [
            &b"{"[..],
            b" \t{\"jsonrpc\":\"2.0\",\"id\":",
            b"{not json}",
            b"{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}",
            b"[]",
            b"42",
            b"\"text\"",
        ] {
            assert!(
                !is_log_noise(not_noise),
                "{:?}",
                String::from_utf8_lossy(not_noise)
            );
        }
    }

    #[test]
    fn text_a_server_prints_on_standard_output_is_skipped() {
        let fixture = Fixture::new("banner");
        let mut session = McpSession::spawn("banner", &fixture.cfg).unwrap();
        assert_eq!(session.list_tools().unwrap().len(), 2);
        assert!(session.call_tool("echo", serde_json::json!({})).unwrap()["content"].is_array());
        assert!(session.is_alive());
    }

    #[test]
    fn text_printed_while_nothing_is_asked_does_not_end_the_session() {
        let fixture = Fixture::new("idle_noise");
        let mut session = McpSession::spawn("idle", &fixture.cfg).unwrap();
        assert!(session.call_tool("echo", serde_json::json!({})).unwrap()["content"].is_array());
        std::thread::sleep(Duration::from_millis(250));
        session.poll_channel(Duration::from_millis(300)).unwrap();
        assert!(session.is_alive());
        assert!(session.call_tool("echo", serde_json::json!({})).is_ok());
    }

    /// What arrives while nothing is asked is read once, not searched again from its start for
    /// every 8 KiB, and a line beyond the limit ends the session instead of filling memory.
    #[test]
    fn a_huge_line_arriving_while_nothing_is_asked_is_read_in_linear_time() {
        let fixture = Fixture::new("idle_huge");
        let mut session = McpSession::spawn("idle-huge", &fixture.cfg).unwrap();
        assert!(session.call_tool("echo", serde_json::json!({})).is_ok());
        std::thread::sleep(Duration::from_millis(250));
        let start = Instant::now();
        session.poll_channel(Duration::from_millis(500)).unwrap();
        assert!(
            start.elapsed() < Duration::from_secs(3),
            "took {:?}",
            start.elapsed()
        );
        assert!(session.is_alive());
    }

    #[test]
    fn a_line_beyond_the_limit_while_nothing_is_asked_ends_the_session() {
        let fixture = Fixture::new("idle_oversize");
        let mut session = McpSession::spawn("idle-oversize", &fixture.cfg).unwrap();
        assert!(session.call_tool("echo", serde_json::json!({})).is_ok());
        std::thread::sleep(Duration::from_millis(250));
        let error = session.poll_channel(Duration::from_secs(5)).unwrap_err();
        assert!(error.contains("16 MiB"), "{error}");
    }

    /// The same bound holds for a line that never gets its newline: the buffer does not grow
    /// for as long as the server keeps writing.
    #[test]
    fn a_line_that_never_ends_while_nothing_is_asked_ends_the_session() {
        let fixture = Fixture::new("idle_endless");
        let mut session = McpSession::spawn("idle-endless", &fixture.cfg).unwrap();
        assert!(session.call_tool("echo", serde_json::json!({})).is_ok());
        std::thread::sleep(Duration::from_millis(250));
        let error = session.poll_channel(Duration::from_secs(5)).unwrap_err();
        assert!(error.contains("16 MiB"), "{error}");
    }

    #[test]
    fn standard_output_that_is_not_json_still_explains_a_server_that_ended() {
        let fixture = Fixture::new("noise_exit");
        let error = match McpSession::spawn("noise", &fixture.cfg) {
            Ok(_) => panic!("a server that exits cannot answer"),
            Err(error) => error,
        };
        assert!(error.contains("usage: fixture [options]"), "{error}");
        assert!(error.contains("exit status: 2"), "{error}");
        // The last line it wrote explains it, not the first.
        assert!(!error.contains("starting up"), "{error}");
    }

    #[test]
    fn standard_output_that_is_not_json_is_named_when_a_server_never_answers() {
        let mut fixture = Fixture::new("noise_silent");
        fixture.cfg.initialize_timeout_ms = 400;
        let error = match McpSession::spawn("quiet", &fixture.cfg) {
            Ok(_) => panic!("a server that only prints cannot answer"),
            Err(error) => error,
        };
        assert!(error.contains("timed out"), "{error}");
        assert!(error.contains("usage: fixture [options]"), "{error}");
        assert!(!error.contains("starting up"), "{error}");
        // Whatever a server prints is shown to the operator as text: its escape sequences are not.
        assert!(!error.chars().any(char::is_control), "{error:?}");
    }

    /// What a server printed is quoted in a message, not pasted in whole.
    #[test]
    fn a_long_line_of_standard_output_is_quoted_in_part() {
        let mut fixture = Fixture::new("noise_long");
        fixture.cfg.initialize_timeout_ms = 400;
        let error = match McpSession::spawn("long", &fixture.cfg) {
            Ok(_) => panic!("a server that only prints cannot answer"),
            Err(error) => error,
        };
        assert!(error.contains(&"L".repeat(160)), "{error}");
        assert!(!error.contains(&"L".repeat(161)), "{error}");
    }

    /// `id: null` is how JSON-RPC says "I could not read your request". Unlike a reply with no id
    /// at all, it is information, and the session is not carried on as if nothing had been said.
    #[test]
    fn a_reply_with_a_null_id_is_still_an_error() {
        let fixture = Fixture::new("null_id");
        let mut session = McpSession::spawn("null-id", &fixture.cfg).unwrap();
        let error = session
            .call_tool_with_options("echo", serde_json::json!({}), &options(700))
            .unwrap_err();
        assert!(error.contains("invalid id"), "{error}");
        assert!(!session.is_alive());
    }

    #[test]
    fn a_json_object_that_is_cut_off_is_still_a_broken_server() {
        let fixture = Fixture::new("broken_object");
        let mut session = McpSession::spawn("broken", &fixture.cfg).unwrap();
        let error = session
            .call_tool_with_options("echo", serde_json::json!({}), &options(700))
            .unwrap_err();
        assert!(error.contains("malformed mcp frame"), "{error}");
        assert!(!session.is_alive());
    }

    /// A real server answers the `initialized` notification with `{"jsonrpc":"2.0","error":…}` and
    /// no id: an answer to nothing.
    #[test]
    fn a_reply_without_an_id_is_ignored() {
        for mode in ["idless_error", "idless_result"] {
            let fixture = Fixture::new(mode);
            let mut session = McpSession::spawn(mode, &fixture.cfg).unwrap();
            assert_eq!(session.list_tools().unwrap().len(), 2, "{mode}");
            assert!(
                session.call_tool("echo", serde_json::json!({})).unwrap()["content"].is_array(),
                "{mode}"
            );
            assert!(session.is_alive(), "{mode}");
        }
    }

    /// One real server's `tools/list` is a single 3.5 MB line (229 tools).
    #[test]
    fn a_tool_list_and_a_result_of_a_few_megabytes_are_accepted() {
        let mut fixture = Fixture::new("big_list");
        fixture.cfg.timeout_ms = 20_000;
        let mut session = McpSession::spawn("big", &fixture.cfg).unwrap();
        assert_eq!(session.list_tools().unwrap().len(), 20);
        assert!(session.is_alive());
        let mut fixture = Fixture::new("big_call");
        fixture.cfg.timeout_ms = 20_000;
        let mut session = McpSession::spawn("big-call", &fixture.cfg).unwrap();
        let result = session.call_tool("echo", serde_json::json!({})).unwrap();
        assert_eq!(
            result["content"][0]["text"].as_str().map(str::len),
            Some(2 * 1024 * 1024)
        );
    }

    /// A buffer that is searched again from the start for every 8 KiB read takes seconds at 12 MiB.
    #[test]
    fn a_reply_near_the_limit_is_read_in_linear_time() {
        let mut fixture = Fixture::new("huge_list");
        fixture.cfg.timeout_ms = 30_000;
        let mut session = McpSession::spawn("huge", &fixture.cfg).unwrap();
        let start = Instant::now();
        assert_eq!(session.list_tools().unwrap().len(), 20);
        assert!(
            start.elapsed() < Duration::from_secs(3),
            "took {:?}",
            start.elapsed()
        );
    }

    #[test]
    fn server_requests_are_not_responses_and_rpc_errors_preserve_transport() {
        let fixture = Fixture::new("server_request");
        let mut session = McpSession::spawn("requests", &fixture.cfg).unwrap();
        assert!(session.call_tool("echo", serde_json::json!({})).unwrap()["content"].is_array());
        let fixture = Fixture::new("rpc_error");
        let mut session = McpSession::spawn("errors", &fixture.cfg).unwrap();
        assert!(
            session
                .call_tool("echo", serde_json::json!({}))
                .unwrap_err()
                .contains("fixture failure")
        );
        assert!(session.is_alive());
        assert!(session.call_tool("echo", serde_json::json!({})).is_ok());
        let fixture = Fixture::new("list_rpc_error");
        let mut session = McpSession::spawn("list-errors", &fixture.cfg).unwrap();
        assert!(
            session
                .list_tools()
                .unwrap_err()
                .contains("list fixture failure")
        );
        assert!(session.is_alive());
        assert_eq!(session.list_tools().unwrap().len(), 2);
    }

    #[test]
    fn other_servers_progress_while_same_server_wait_has_own_budget() {
        let silent = Fixture::new("silent_call");
        let normal = Fixture::new("normal");
        let pool = Arc::new(McpPool::new());
        let worker_pool = pool.clone();
        let cfg = silent.cfg.clone();
        let worker = std::thread::spawn(move || {
            worker_pool.call_tool_with_options(
                "slow",
                &cfg,
                "echo",
                serde_json::json!({}),
                &options(350),
            )
        });
        silent.wait_method("tools/call");
        let start = Instant::now();
        let result = pool
            .call_tool_with_options(
                "fast",
                &normal.cfg,
                "echo",
                serde_json::json!({}),
                &options(250),
            )
            .unwrap();
        assert!(result["content"].is_array());
        assert!(start.elapsed() < Duration::from_millis(250));
        let start = Instant::now();
        assert!(
            pool.call_tool_with_options(
                "slow",
                &silent.cfg,
                "echo",
                serde_json::json!({}),
                &options(40)
            )
            .unwrap_err()
            .contains("timed out")
        );
        assert!(start.elapsed() < Duration::from_millis(200));
        let cancelled = Arc::new(AtomicBool::new(false));
        let flag = cancelled.clone();
        let trigger = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(20));
            flag.store(true, Ordering::SeqCst);
        });
        assert!(
            pool.call_tool_with_options(
                "slow",
                &silent.cfg,
                "echo",
                serde_json::json!({}),
                &cancel_options(200, &cancelled)
            )
            .unwrap_err()
            .contains("cancelled")
        );
        trigger.join().unwrap();
        assert!(worker.join().unwrap().is_err());
        assert_eq!(
            silent
                .events()
                .iter()
                .filter(|e| e["msg"]["method"] == "tools/call")
                .count(),
            1
        );
    }

    #[test]
    fn explicit_next_call_reconnects_without_replaying_failed_tool() {
        let fixture = Fixture::new("silent_call");
        let pool = McpPool::new();
        for _ in 0..2 {
            assert!(
                pool.call_tool_with_options(
                    "server",
                    &fixture.cfg,
                    "echo",
                    serde_json::json!({}),
                    &options(90)
                )
                .is_err()
            );
        }
        let events = fixture.events();
        let calls: Vec<_> = events
            .iter()
            .filter(|e| e["msg"]["method"] == "tools/call")
            .collect();
        assert_eq!(calls.len(), 2);
        assert_ne!(calls[0]["pid"], calls[1]["pid"]);
        assert_eq!(
            events
                .iter()
                .filter(|e| e["msg"]["method"] == "initialize")
                .count(),
            2
        );
    }

    #[test]
    fn changed_config_and_cwd_replace_cached_session() {
        let first = Fixture::new("normal");
        let second = Fixture::new("normal");
        let pool = McpPool::new();
        let a = pool
            .call_tool("same", &first.cfg, "echo", serde_json::json!({}))
            .unwrap();
        let b = pool
            .call_tool("same", &second.cfg, "echo", serde_json::json!({}))
            .unwrap();
        assert_ne!(a["pid"], b["pid"]);
        let mut opts = options(500);
        opts.working_dir = Some(second.dir.clone());
        let c = pool
            .call_tool_with_options("same", &second.cfg, "echo", serde_json::json!({}), &opts)
            .unwrap();
        assert_ne!(b["pid"], c["pid"]);
        assert_eq!(c["cwd"], second.dir.to_string_lossy().as_ref());
        let mut changed = second.cfg.clone();
        changed.env.insert("ORBIT_TEST_ENV".into(), "new".into());
        let d = pool
            .call_tool_with_options("same", &changed, "echo", serde_json::json!({}), &opts)
            .unwrap();
        assert_ne!(c["pid"], d["pid"]);
        let slots = pool.sessions.get().unwrap().lock().unwrap();
        assert_eq!(slots.len(), 1);
    }

    #[test]
    fn overall_deadline_includes_handshake_and_request() {
        let fixture = Fixture::new("normal");
        let cfg = McpServerConfig {
            args: vec![
                "-u".into(),
                "-c".into(),
                format!("import time; time.sleep(.09);\n{SERVER}"),
                "silent_call".into(),
                fixture.marker.to_string_lossy().into(),
            ],
            ..fixture.cfg.clone()
        };
        let pool = McpPool::new();
        let start = Instant::now();
        assert!(
            pool.call_tool_with_options(
                "overall",
                &cfg,
                "echo",
                serde_json::json!({}),
                &options(170)
            )
            .unwrap_err()
            .contains("timed out")
        );
        assert!(
            start.elapsed() < Duration::from_millis(260),
            "{:?}",
            start.elapsed()
        );
        assert!(
            fixture
                .events()
                .iter()
                .any(|e| e["msg"]["method"] == "tools/call")
        );
    }

    #[test]
    fn claude_mcp_json_entries_become_server_configs() {
        // SAFETY-free: a name no other test reads.
        let servers = parse_claude_servers(
            r#"{"mcpServers": {
                "files": {"command": "npx", "args": ["-y", "server-fs", "${ORBIT_TEST_UNSET_DIR:-/tmp}"], "env": {"LEVEL": "debug"}},
                "docs": {"type": "http", "url": "https://mcp.example.com/mcp", "headers": {"X-Key": "${ORBIT_TEST_UNSET_KEY}"}},
                "events": {"type": "sse", "url": "https://mcp.example.com/sse"},
                "bare": {"url": "https://mcp.example.com/bare"},
                "socket": {"type": "ws", "url": "wss://mcp.example.com"},
                "off": {"command": "x", "disabled": true}
            }}"#,
        )
        .unwrap();
        assert_eq!(
            servers.keys().map(String::as_str).collect::<Vec<_>>(),
            ["bare", "docs", "events", "files", "off"]
        );
        let files = &servers["files"];
        assert_eq!(files.transport, McpTransport::Stdio);
        assert_eq!(files.args, ["-y", "server-fs", "/tmp"]);
        assert_eq!(files.env["LEVEL"], "debug");
        assert!(files.validate().is_ok());
        let docs = &servers["docs"];
        assert_eq!(docs.transport, McpTransport::StreamableHttp);
        assert_eq!(
            docs.headers["X-Key"], "${ORBIT_TEST_UNSET_KEY}",
            "unset stays as written"
        );
        assert!(docs.validate().is_ok());
        assert_eq!(servers["events"].transport, McpTransport::Sse);
        assert_eq!(servers["bare"].transport, McpTransport::StreamableHttp);
        assert!(!servers["off"].enabled);
        assert!(parse_claude_servers("{}").is_err());
    }

    #[test]
    fn a_trusted_project_mcp_json_is_merged_under_orbits_own_entries() {
        let root = std::env::temp_dir().join(format!(
            "orbit-mcp-compat-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos())
        ));
        let (home, project) = (root.join("home"), root.join("project"));
        std::fs::create_dir_all(&home).unwrap();
        std::fs::create_dir_all(&project).unwrap();
        std::fs::write(
            home.join("mcp.json"),
            r#"{"servers": {"files": {"command": "orbit-fs"}}}"#,
        )
        .unwrap();
        std::fs::write(
            project.join(".mcp.json"),
            r#"{"mcpServers": {"files": {"command": "claude-fs"}, "git": {"command": "git-mcp"}, "broken": {"type": "http"}}}"#,
        )
        .unwrap();
        let trusted = McpConfig::try_load_at(&home, &project, true).unwrap();
        assert_eq!(trusted.servers["files"].command, "orbit-fs");
        assert_eq!(trusted.servers["git"].command, "git-mcp");
        assert!(!trusted.servers.contains_key("broken"));
        let untrusted = McpConfig::try_load_at(&home, &project, false).unwrap();
        assert_eq!(untrusted.servers.len(), 1);
    }

    fn uninitialized_stdio_session(
        cfg: McpServerConfig,
    ) -> (McpSession, std::process::ChildStderr) {
        let mut child = Command::new(&cfg.command)
            .args(&cfg.args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let stdin = child.stdin.take().unwrap();
        let stdout = child.stdout.take().unwrap();
        let stderr = child.stderr.take().unwrap();
        let session = McpSession {
            server_name: "handshake-fixture".into(),
            remote: None,
            child: Some(child),
            stdin: Some(stdin),
            stdout: Some(stdout),
            input: Vec::new(),
            next_id: 1,
            cfg,
            instructions: None,
            relays_permission: false,
            ended: None,
            peer_closed: false,
            noise: None,
        };
        set_nonblocking(session.stdin.as_ref().unwrap().as_raw_fd()).unwrap();
        set_nonblocking(session.stdout.as_ref().unwrap().as_raw_fd()).unwrap();
        (session, stderr)
    }

    fn exited_handshake_session() -> (McpSession, Mutex<Vec<u8>>) {
        let cfg: McpServerConfig = serde_json::from_str(
            r#"{"command": "/bin/sh", "args": ["-c", "echo first >&2; echo no such module >&2; exit 3"]}"#,
        )
        .unwrap();
        let (mut session, mut stderr) = uninitialized_stdio_session(cfg);
        // Force the write/exit ordering: no pipe reader remains when the
        // handshake starts. Child caches the exit status for retirement.
        assert_eq!(
            session.child.as_mut().unwrap().wait().unwrap().code(),
            Some(3)
        );
        let mut tail = Vec::new();
        stderr.read_to_end(&mut tail).unwrap();
        (session, Mutex::new(tail))
    }

    #[test]
    fn a_server_that_exits_before_the_first_write_says_how_and_why() {
        let (mut session, tail) = exited_handshake_session();
        let error = session.initialize(&options(1000)).unwrap_err();
        assert!(error.contains("Broken pipe"), "{error}");
        let (done, drained) = std::sync::mpsc::channel();
        done.send(()).unwrap();
        let error = session.startup_failure(error, &tail, &drained);
        assert!(error.contains("ended before answering"), "{error}");
        assert!(error.contains("exit status: 3"), "{error}");
        assert!(error.ends_with("no such module"), "{error}");
    }

    #[test]
    fn a_server_that_exits_after_the_first_write_says_how_and_why() {
        let cfg: McpServerConfig = serde_json::from_str(
            r#"{"command": "/bin/sh", "args": ["-c", "IFS= read -r request; echo first >&2; echo no such module >&2; exit 3"]}"#,
        )
        .unwrap();
        let error = McpSession::spawn("gone-after-write", &cfg).err().unwrap();
        assert!(error.contains("ended before answering"), "{error}");
        assert!(error.contains("exit status: 3"), "{error}");
        assert!(error.ends_with("no such module"), "{error}");
    }

    #[test]
    fn startup_exit_diagnostics_preserve_cancellation_and_timeout() {
        for cancelled in [false, true] {
            let (mut session, tail) = exited_handshake_session();
            let opts = if cancelled {
                options(1000).with_cancel(Arc::new(|| true))
            } else {
                options(0)
            };
            let expected = if cancelled {
                "mcp request cancelled"
            } else {
                "mcp request timed out"
            };
            let error = session.initialize(&opts).unwrap_err();
            assert_eq!(session.ended.unwrap().code(), Some(3));
            let (_done, drained) = std::sync::mpsc::channel();
            assert_eq!(session.startup_failure(error, &tail, &drained), expected);
        }
    }

    #[test]
    fn startup_stderr_drain_wait_is_bounded() {
        let (mut session, tail) = exited_handshake_session();
        let error = session.initialize(&options(1000)).unwrap_err();
        // Model a descendant retaining stderr: the drain signal stays open
        // after the owned child exits, but startup diagnostics still return.
        let (_done, drained) = std::sync::mpsc::channel();
        let start = Instant::now();
        let error = session.startup_failure(error, &tail, &drained);
        assert!(error.ends_with("no such module"), "{error}");
        assert_quick(start);
    }

    #[test]
    fn a_live_server_with_closed_stdin_is_reaped_without_a_false_exit_diagnostic() {
        let cfg: McpServerConfig = serde_json::from_str(
            r#"{"command": "python3", "args": ["-c", "import os, time; os.close(0); print('closed', flush=True); time.sleep(60)"]}"#,
        )
        .unwrap();
        let (mut session, _stderr) = uninitialized_stdio_session(cfg);
        assert_eq!(session.read_frame(&options(1000)).unwrap(), b"closed");
        let start = Instant::now();
        let error = session.initialize(&options(1000)).unwrap_err();
        assert!(session.ended.is_none());
        assert!(session.child.is_none());
        assert!(!session.is_alive());
        let (_done, drained) = std::sync::mpsc::channel();
        let error = session.startup_failure(error, &Mutex::new(Vec::new()), &drained);
        assert!(error.contains("Broken pipe"), "{error}");
        assert_quick(start);
    }

    #[cfg(unix)]
    #[test]
    fn a_server_that_ends_at_once_says_how_and_why() {
        let cfg: McpServerConfig = serde_json::from_str(
            r#"{"command": "/bin/sh", "args": ["-c", "echo first >&2; echo no such module >&2; exit 3"]}"#,
        )
        .unwrap();
        let error = McpSession::spawn("gone", &cfg).err().unwrap();
        assert!(error.contains("ended before answering"), "{error}");
        assert!(error.contains("exit status: 3"), "{error}");
        assert!(error.ends_with("no such module"), "{error}");
    }
}
