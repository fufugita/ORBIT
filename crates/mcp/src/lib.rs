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

pub const MAX_FRAME_BYTES: usize = 1024 * 1024;
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
        Ok(cfg)
    }
}

/// One absolute budget for lock waits, initialization, writes and reads.
#[derive(Clone)]
pub struct McpCallOptions {
    pub deadline: Instant,
    pub cancel: Option<Arc<dyn Fn() -> bool + Send + Sync>>,
    /// None uses the process's current directory at the start of a pool operation.
    pub working_dir: Option<PathBuf>,
}

impl McpCallOptions {
    pub fn new(timeout: Duration) -> Self {
        Self {
            deadline: Instant::now() + timeout,
            cancel: None,
            working_dir: None,
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
                let remote = if cfg.transport == McpTransport::StreamableHttp {
                    RemoteTransport::Streamable(Box::new(http::HttpTransport::new(
                        url,
                        &cfg.headers,
                    )?))
                } else {
                    RemoteTransport::Legacy(Box::new(legacy::LegacyTransport::new(
                        url,
                        &cfg.headers,
                    )?))
                };
                let mut session = Self {
                    server_name: name.into(),
                    remote: Some(remote),
                    child: None,
                    stdin: None,
                    stdout: None,
                    input: Vec::new(),
                    next_id: 1,
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
            let mut child = Command::new(&cfg.command)
                .args(&cfg.args)
                .envs(&cfg.env)
                .current_dir(cwd)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .map_err(|e| format!("spawn mcp server {name}: {e}"))?;
            let stdin = child.stdin.take();
            let stdout = child.stdout.take();
            let mut session = Self {
                server_name: name.into(),
                remote: None,
                child: Some(child),
                stdin,
                stdout,
                input: Vec::new(),
                next_id: 1,
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
            session.initialize(&initialize_options)?;
            Ok(session)
        }
    }

    fn initialize(&mut self, options: &McpCallOptions) -> Result<(), String> {
        self.request_with_options(
            "initialize",
            serde_json::json!({
                "protocolVersion":"2025-06-18", "capabilities":{},
                "clientInfo":{"name":"orbit","version":env!("CARGO_PKG_VERSION")}
            }),
            options,
        )?;
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
        let options = options.bounded(self.cfg.timeout_ms);
        let id = self.next_id;
        self.next_id = self
            .next_id
            .checked_add(1)
            .ok_or("mcp request id exhausted")?;
        let result = self.exchange(id, method, params, &options);
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
        loop {
            let line = self.read_frame(options).map_err(|error| (error, true))?;
            options.check().map_err(|error| (error, true))?;
            let value: serde_json::Value = serde_json::from_slice(&line)
                .map_err(|e| (format!("malformed mcp frame: {e}"), true))?;
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
                    let response = if method.as_str() == Some("ping") {
                        serde_json::json!({"jsonrpc":"2.0", "id":request_id, "result":{}})
                    } else {
                        serde_json::json!({
                            "jsonrpc":"2.0", "id":request_id,
                            "error":{"code":-32601,"message":"client method not supported"}
                        })
                    };
                    self.write_frame(&response, options)
                        .map_err(|error| (error, true))?;
                }
                continue;
            }
            let response_id = object
                .get("id")
                .ok_or_else(|| ("mcp response has no id".into(), true))?;
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
                Ok(0) => return Err("mcp server closed stdin".into()),
                Ok(n) => {
                    *bytes_sent = true;
                    written += n;
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    wait_writable(stdin, options)?
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(format!("mcp write: {e}")),
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
                Err(e) => return Err(format!("mcp flush: {e}")),
            }
        }
    }

    fn read_frame(&mut self, options: &McpCallOptions) -> Result<Vec<u8>, String> {
        loop {
            options.check()?;
            if let Some(newline) = self.input.iter().position(|byte| *byte == b'\n') {
                if newline > MAX_FRAME_BYTES {
                    return Err("mcp input frame exceeds 1 MiB".into());
                }
                let mut frame: Vec<_> = self.input.drain(..=newline).collect();
                frame.pop();
                return Ok(frame);
            }
            if self.input.len() > MAX_FRAME_BYTES {
                return Err("mcp input frame exceeds 1 MiB".into());
            }
            let stdout = self.stdout.as_mut().ok_or("mcp transport is retired")?;
            let mut bytes = [0_u8; 8192];
            match stdout.read(&mut bytes) {
                Ok(0) => return Err("mcp server closed stdout".into()),
                Ok(n) => self.input.extend_from_slice(&bytes[..n]),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    wait_readable(stdout, options)?
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(format!("mcp read: {e}")),
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
            let encoded = encode_frame(&result)?;
            total_bytes = total_bytes
                .checked_add(encoded.len())
                .ok_or("mcp tool metadata size overflow")?;
            if total_bytes > MAX_FRAME_BYTES {
                return Err("mcp aggregate tool metadata exceeds 1 MiB".into());
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
        self.stdin.take();
        self.stdout.take();
        self.input.clear();
        if let Some(mut child) = self.child.take() {
            // Kill only this Child, never a process group or a text-parsed PID.
            let _ = child.kill();
            let _ = child.wait();
        }
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
        result = {'protocolVersion':'2025-06-18','capabilities':{'tools':{}}}
    elif 'id' not in msg:
        if mode == 'blocked_write': time.sleep(60)
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
            result = {'tools':[{'name':'large-'+str(cursor),'description':'x'*600000,'inputSchema':{'type':'object'}}]}
            if cursor is None: result['nextCursor'] = 'page-two'
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
        if mode == 'invalid_protocol':
            sys.stdout.write(json.dumps({'jsonrpc':'1.0','id':msg['id'],'result':{}})+'\n'); sys.stdout.flush(); continue
        if mode in ('oversize','no_newline'):
            sys.stdout.write('x' * (1024*1024+1) + ('\n' if mode == 'oversize' else '')); sys.stdout.flush(); continue
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
        if mode == 'rpc_error' and calls == 1:
            sys.stdout.write(json.dumps({'jsonrpc':'2.0','id':msg['id'],'error':{'code':-32000,'message':'fixture failure'}})+'\n'); sys.stdout.flush(); continue
        result = {'content':[{'type':'text','text':'hello from mcp'}], 'pid':os.getpid(), 'cwd':os.getcwd(), 'arguments':msg.get('params',{}).get('arguments')}
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
            ("aggregate", "aggregate tool metadata exceeds 1 MiB"),
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
        for mode in ["flood", "unmatched_ids"] {
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
            "malformed",
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
                assert!(error.contains("1 MiB"), "{error}");
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
}
