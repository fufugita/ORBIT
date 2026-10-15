//! Explicitly configured, on-demand diagnostics for one authorized document.
//! A trusted launch configuration authorizes a program; it does not confine it.

use crate::tool_runtime::PermissionScope;
use orbit_adapter::ToolDefinition;
use orbit_tools::permissions::{FolderTrust, RuleEffect, RuleEffectSerde, RuleSet, parse_rule};
use orbit_tools::{ToolContext, is_deny_read, resolve_path};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

const CONFIG_BYTES: u64 = 64 * 1024;
const DOCUMENT_BYTES: usize = 1024 * 1024;
const FRAME_BYTES: usize = 256 * 1024;
const TOTAL_BYTES: usize = 2 * 1024 * 1024;
const OUTPUT_BYTES: usize = 60 * 1024;
const DIAGNOSTICS: usize = 100;

#[derive(Debug, thiserror::Error)]
pub enum LspError {
    #[error("language-server configuration: {0}")]
    Configuration(String),
    #[error("diagnostics refused: {0}")]
    Denied(String),
    #[error("language-server protocol: {0}")]
    Protocol(String),
    #[error("language-server IO: {0}")]
    Io(String),
    #[error("language-server request cancelled")]
    Cancelled,
    #[error("language-server deadline exceeded")]
    Timeout,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LspDiagnosticsArgs {
    pub file_path: String,
    #[serde(default)]
    pub server: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct LspAvailability {
    pub servers: Vec<LspServerSummary>,
}
#[derive(Debug, Clone, Serialize)]
pub struct LspServerSummary {
    pub name: String,
    pub language_id: String,
    pub extensions: Vec<String>,
    pub workspace_root: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticStatus {
    Received,
    Unavailable,
    Stale,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Freshness {
    Confirmed,
    Unconfirmed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Position {
    pub line: u32,
    pub character: u32,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Range {
    pub start: Position,
    pub end: Position,
}

#[derive(Debug, Clone, Serialize)]
pub struct Diagnostic {
    pub range: Range,
    pub severity: Option<u8>,
    pub message: String,
    pub code: Option<Value>,
    pub source: Option<String>,
    pub tags: Vec<u8>,
}
#[derive(Debug, Clone, Serialize)]
pub struct DiagnosticReport {
    pub server: String,
    pub uri: String,
    pub document_version: i64,
    pub position_encoding: String,
    pub status: DiagnosticStatus,
    pub freshness: Freshness,
    pub reason: Option<String>,
    pub diagnostics: Vec<Diagnostic>,
    pub truncated: bool,
    pub redactions: Vec<String>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct Configuration {
    #[serde(default)]
    enabled: bool,
    #[serde(default)]
    servers: Vec<Server>,
}
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Server {
    name: String,
    command: String,
    #[serde(default)]
    args: Vec<String>,
    language_id: String,
    extensions: Vec<String>,
    workspace_root: PathBuf,
    #[serde(default = "default_timeout")]
    timeout_ms: u64,
}
fn default_timeout() -> u64 {
    5000
}

fn read_configuration(path: &Path) -> Result<Option<Configuration>, LspError> {
    let meta = match std::fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => {
            return Err(LspError::Configuration(
                "cannot inspect configuration".into(),
            ));
        }
    };
    if !meta.is_file() || meta.len() > CONFIG_BYTES {
        return Err(LspError::Configuration(
            "configuration must be a bounded regular file".into(),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
        // SAFETY: geteuid has no pointer arguments or preconditions.
        if meta.uid() != unsafe { libc::geteuid() } || meta.mode() & 0o022 != 0 {
            return Err(LspError::Configuration(
                "configuration must be owned by the operator and not writable by others".into(),
            ));
        }
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
            .map_err(|_| LspError::Configuration("cannot open configuration safely".into()))?;
        let mut text = String::new();
        file.take(CONFIG_BYTES + 1)
            .read_to_string(&mut text)
            .map_err(|_| LspError::Configuration("configuration is not bounded UTF-8".into()))?;
        if text.len() as u64 > CONFIG_BYTES {
            return Err(LspError::Configuration("configuration is too large".into()));
        }
        toml::from_str(&text)
            .map(Some)
            .map_err(|_| LspError::Configuration("invalid lsp.toml".into()))
    }
    #[cfg(not(unix))]
    {
        let _ = meta;
        Err(LspError::Configuration(
            "stdio diagnostics currently require Unix".into(),
        ))
    }
}

fn configuration(home: &Path, cx: &ToolContext) -> Result<Option<Vec<Server>>, LspError> {
    let Some(mut config) = read_configuration(&home.join("lsp.toml"))? else {
        return Ok(None);
    };
    if !config.enabled {
        return Ok(None);
    }
    let work = cx
        .working_dir
        .canonicalize()
        .map_err(|_| LspError::Configuration("working directory is unavailable".into()))?;
    let canonical_home = home
        .canonicalize()
        .map_err(|_| LspError::Configuration("configuration home is unavailable".into()))?;
    let trusted = FolderTrust::new(home.to_path_buf()).is_trusted(&cx.working_dir);
    if canonical_home.starts_with(&work) && !trusted {
        return Ok(None);
    }
    // A trusted project may specialize an already enabled user configuration.
    // It cannot activate diagnostics when the user configuration is absent/off.
    let local = work.join(".orbit/lsp.toml");
    if trusted
        && local != home.join("lsp.toml")
        && let Some(project) = read_configuration(&local)?
    {
        if !project.enabled {
            return Ok(None);
        }
        config = project;
    }
    if config.servers.is_empty() {
        return Ok(None);
    }
    if config.servers.len() > 16 {
        return Err(LspError::Configuration(
            "at most sixteen servers are supported".into(),
        ));
    }
    let mut names = std::collections::HashSet::new();
    for server in &mut config.servers {
        if !identifier(&server.name)
            || !identifier(&server.language_id)
            || !names.insert(server.name.clone())
        {
            return Err(LspError::Configuration(
                "server names/languages must be bounded unique identifiers".into(),
            ));
        }
        if server.command.is_empty()
            || server.command.len() > 4096
            || server.command.chars().any(char::is_control)
            || server.args.len() > 64
            || server.args.iter().map(String::len).sum::<usize>() > 16 * 1024
            || server.args.iter().any(|s| s.contains('\0'))
        {
            return Err(LspError::Configuration(
                "invalid executable or argument vector".into(),
            ));
        }
        if !(100..=30_000).contains(&server.timeout_ms)
            || server.extensions.is_empty()
            || server.extensions.len() > 32
            || server
                .extensions
                .iter()
                .any(|e| !identifier(e) || e.contains('.'))
        {
            return Err(LspError::Configuration(
                "invalid timeout or extension matches".into(),
            ));
        }
        let root = if server.workspace_root.is_absolute() {
            server.workspace_root.clone()
        } else {
            work.join(&server.workspace_root)
        };
        server.workspace_root = root.canonicalize().map_err(|_| {
            LspError::Configuration("configured workspace root is unavailable".into())
        })?;
        if !server.workspace_root.is_dir() {
            return Err(LspError::Configuration(
                "workspace root must be a directory".into(),
            ));
        }
    }
    Ok(Some(config.servers))
}

fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-' | b'+'))
}

/// Validate configuration without launching a program or reading a document.
pub fn availability(home: &Path, cx: &ToolContext) -> Result<Option<LspAvailability>, LspError> {
    Ok(configuration(home, cx)?.map(|servers| LspAvailability {
        servers: servers
            .into_iter()
            .map(|s| LspServerSummary {
                name: s.name,
                language_id: s.language_id,
                extensions: s.extensions,
                workspace_root: s.workspace_root,
            })
            .collect(),
    }))
}

pub fn tool_definition() -> ToolDefinition {
    let parameters = json!({"type":"object","properties":{
        "file_path":{"type":"string","description":"One file in the permitted configured workspace"},
        "server":{"type":"string","description":"Optional configured server name"}
    },"required":["file_path"],"additionalProperties":false});
    ToolDefinition {
        name: "LspDiagnostics".into(),
        description: "Request on-demand diagnostics from an explicitly configured language server. Results distinguish received, stale, and unavailable diagnostics and report freshness.".into(),
        schema_digest: orbit_adapter::types::Sha256Digest(hex::encode(Sha256::digest(parameters.to_string()))),
        parameters,
    }
}

fn authorize(
    home: &Path,
    cx: &ToolContext,
    scope: &PermissionScope,
    argument: &str,
    original: &Path,
    file: &Path,
    root: &Path,
) -> Result<(), LspError> {
    if scope
        .disallowlist
        .iter()
        .any(|t| t == "LspDiagnostics" || t == "Read")
        || scope
            .allowlist
            .as_ref()
            .is_some_and(|tools| !tools.iter().any(|t| t == "LspDiagnostics"))
    {
        return Err(LspError::Denied("excluded by inherited tool scope".into()));
    }
    if is_deny_read(original) || is_deny_read(file) {
        return Err(LspError::Denied(
            "file is protected by deny-read policy".into(),
        ));
    }
    let permitted = std::iter::once(&cx.working_dir)
        .chain(cx.working_dirs.iter())
        .filter_map(|dir| dir.canonicalize().ok())
        .any(|dir| file.starts_with(dir));
    if !permitted || !file.starts_with(root) {
        return Err(LspError::Denied(
            "file is outside the inherited/configured workspace".into(),
        ));
    }
    let rules = orbit_tools::executor::load_sourced_rules_in(home, &cx.working_dir)
        .map_err(|_| LspError::Denied("permission configuration is invalid".into()))?;
    let mut rules = RuleSet {
        rules: rules
            .into_iter()
            .filter(|r| !r.shadowed)
            .map(|r| r.rule)
            .collect(),
    };
    for entry in &scope.disallowlist {
        rules.rules.push(
            parse_rule(entry, RuleEffectSerde::Deny).ok_or_else(|| {
                LspError::Denied("inherited permission selector is invalid".into())
            })?,
        );
    }
    for tool in ["LspDiagnostics", "Read"] {
        if rules.evaluate(tool, argument) == Some(RuleEffect::Deny)
            || [original, file]
                .iter()
                .any(|p| rules.evaluate(tool, &p.to_string_lossy()) == Some(RuleEffect::Deny))
        {
            return Err(LspError::Denied(
                "file or tool is denied by a permission rule".into(),
            ));
        }
    }
    Ok(())
}

/// The shared runtime performs normal approval evaluation before this call.
/// Defense in depth repeats inherited scope, deny rules and path containment.
pub fn diagnostics(
    home: &Path,
    cx: &ToolContext,
    scope: &PermissionScope,
    args: &LspDiagnosticsArgs,
) -> Result<DiagnosticReport, LspError> {
    if cx.is_cancelled() {
        return Err(LspError::Cancelled);
    }
    if args.file_path.is_empty() || args.file_path.len() > 4096 || args.file_path.contains('\0') {
        return Err(LspError::Denied("invalid document path".into()));
    }
    let servers = configuration(home, cx)?
        .ok_or_else(|| LspError::Denied("diagnostics are disabled or unconfigured".into()))?;
    let original = resolve_path(cx, &args.file_path);
    let file = original
        .canonicalize()
        .map_err(|_| LspError::Denied("document is unavailable".into()))?;
    let extension = file.extension().and_then(|e| e.to_str()).unwrap_or("");
    let mut candidates = servers.into_iter().filter(|s| {
        args.server.as_ref().is_none_or(|name| &s.name == name)
            && s.extensions.iter().any(|e| e == extension)
            && file.starts_with(&s.workspace_root)
    });
    let server = candidates
        .next()
        .ok_or_else(|| LspError::Denied("no configured server matches the document".into()))?;
    if candidates.next().is_some() {
        return Err(LspError::Denied(
            "multiple servers match; select a configured server".into(),
        ));
    }
    authorize(
        home,
        cx,
        scope,
        &args.file_path,
        &original,
        &file,
        &server.workspace_root,
    )?;
    let deadline = Instant::now() + Duration::from_millis(server.timeout_ms);
    check(cx, deadline)?;
    #[cfg(unix)]
    let document = {
        use std::os::unix::fs::MetadataExt;
        use std::os::unix::fs::OpenOptionsExt;
        let before = std::fs::metadata(&file)
            .map_err(|_| LspError::Denied("document identity is unavailable".into()))?;
        if !before.is_file() || before.len() > DOCUMENT_BYTES as u64 {
            return Err(LspError::Denied(
                "document must be a bounded regular file".into(),
            ));
        }
        check(cx, deadline)?;
        let opened = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(&file)
            .map_err(|_| LspError::Denied("cannot safely open document".into()))?;
        if !opened.metadata().is_ok_and(|m| {
            m.is_file()
                && m.len() <= DOCUMENT_BYTES as u64
                && m.dev() == before.dev()
                && m.ino() == before.ino()
        }) {
            return Err(LspError::Denied(
                "document must be a bounded regular file".into(),
            ));
        }
        // An ancestor may have changed after canonicalization. Confirm the
        // kernel's actual open-file target before the first document read.
        use std::os::fd::AsRawFd;
        let descriptor_path = std::fs::read_link(format!("/proc/self/fd/{}", opened.as_raw_fd()))
            .map_err(|_| {
            LspError::Denied("cannot confirm the document descriptor target on this host".into())
        })?;
        if descriptor_path != file {
            return Err(LspError::Denied(
                "document target changed before reading".into(),
            ));
        }
        authorize(
            home,
            cx,
            scope,
            &args.file_path,
            &original,
            &descriptor_path,
            &server.workspace_root,
        )?;
        let mut bytes = Vec::new();
        opened
            .take((DOCUMENT_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| LspError::Io("document read failed".into()))?;
        if bytes.len() > DOCUMENT_BYTES {
            return Err(LspError::Denied("document is too large".into()));
        }
        String::from_utf8(bytes).map_err(|_| LspError::Denied("document must be UTF-8".into()))?
    };
    #[cfg(not(unix))]
    let document = String::new();
    check(cx, deadline)?;
    let uri = url::Url::from_file_path(&file)
        .map_err(|_| LspError::Denied("document URI cannot be encoded".into()))?
        .to_string();
    authorize(
        home,
        cx,
        scope,
        &args.file_path,
        &original,
        &file,
        &server.workspace_root,
    )?;
    let mut report = DiagnosticReport {
        server: server.name.clone(),
        uri,
        document_version: 1,
        position_encoding: "utf-16".into(),
        status: DiagnosticStatus::Unavailable,
        freshness: Freshness::Unconfirmed,
        reason: None,
        diagnostics: vec![],
        truncated: false,
        redactions: vec![],
    };
    #[cfg(unix)]
    {
        let mut peer = transport::Peer::start(&server, cx, deadline)?;
        let result = exchange(&mut peer, &server, &document, cx, deadline, &mut report);
        let cleanup = peer.finish(cx);
        if result.is_ok() || matches!(result, Err(LspError::Timeout)) {
            cleanup?;
        }
        match result {
            Ok(()) => Ok(report),
            Err(LspError::Timeout) => {
                report.reason =
                    Some("language server returned no usable result before the deadline".into());
                Ok(report)
            }
            Err(error) => Err(error),
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (server, document, report);
        Err(LspError::Configuration(
            "stdio diagnostics currently require Unix".into(),
        ))
    }
}

fn check(cx: &ToolContext, deadline: Instant) -> Result<(), LspError> {
    if cx.is_cancelled() {
        Err(LspError::Cancelled)
    } else if Instant::now() >= deadline {
        Err(LspError::Timeout)
    } else {
        Ok(())
    }
}

#[cfg(unix)]
fn exchange(
    peer: &mut transport::Peer,
    server: &Server,
    document: &str,
    cx: &ToolContext,
    deadline: Instant,
    report: &mut DiagnosticReport,
) -> Result<(), LspError> {
    let root_uri = url::Url::from_directory_path(&server.workspace_root)
        .map_err(|_| LspError::Configuration("workspace URI cannot be encoded".into()))?
        .to_string();
    peer.send(&json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{
        "processId":std::process::id(),"rootUri":root_uri,"capabilities":{
            "general":{"positionEncodings":["utf-8","utf-16","utf-32"]},
            "textDocument":{"diagnostic":{"dynamicRegistration":false},"publishDiagnostics":{"versionSupport":true}}
        },"clientInfo":{"name":"ORBIT"}}}), cx, deadline)?;
    let initialization = response(peer, 1, cx, deadline)?;
    let caps = initialization
        .get("capabilities")
        .and_then(Value::as_object)
        .ok_or_else(|| LspError::Protocol("initialize response lacks capabilities".into()))?;
    if let Some(encoding) = caps.get("positionEncoding") {
        let encoding = encoding
            .as_str()
            .ok_or_else(|| LspError::Protocol("invalid position encoding".into()))?;
        if !["utf-8", "utf-16", "utf-32"].contains(&encoding) {
            return Err(LspError::Protocol("unsupported position encoding".into()));
        }
        report.position_encoding = encoding.into();
    }
    let pull = caps.get("diagnosticProvider").is_some_and(Value::is_object);
    peer.send(
        &json!({"jsonrpc":"2.0","method":"initialized","params":{}}),
        cx,
        deadline,
    )?;
    peer.send(&json!({"jsonrpc":"2.0","method":"textDocument/didOpen","params":{"textDocument":{
        "uri":report.uri,"languageId":server.language_id,"version":report.document_version,"text":document
    }}}), cx, deadline)?;
    peer.document_uri = Some(report.uri.clone());
    if pull {
        peer.send(&json!({"jsonrpc":"2.0","id":2,"method":"textDocument/diagnostic","params":{"textDocument":{"uri":report.uri}}}), cx, deadline)?;
        let result = response(peer, 2, cx, deadline)?;
        if result.get("kind").and_then(Value::as_str) != Some("full") {
            return Err(LspError::Protocol(
                "expected a full diagnostic report".into(),
            ));
        }
        fill_report(report, result.get("items"), Freshness::Confirmed)?;
    } else {
        loop {
            let message = peer.receive(cx, deadline)?;
            if reject_server_request(peer, &message, cx, deadline)? {
                continue;
            }
            if message.get("method").and_then(Value::as_str)
                != Some("textDocument/publishDiagnostics")
            {
                continue;
            }
            let params = message
                .get("params")
                .and_then(Value::as_object)
                .ok_or_else(|| LspError::Protocol("invalid publish diagnostics".into()))?;
            let uri = params
                .get("uri")
                .and_then(Value::as_str)
                .ok_or_else(|| LspError::Protocol("publish diagnostics lacks URI".into()))?;
            if uri != report.uri {
                continue;
            }
            let version = params.get("version");
            let freshness = match version {
                Some(version) => {
                    let version = version
                        .as_i64()
                        .ok_or_else(|| LspError::Protocol("invalid diagnostic version".into()))?;
                    if version != report.document_version {
                        report.status = DiagnosticStatus::Stale;
                        report.reason =
                            Some("received diagnostics for another document version".into());
                        return Ok(());
                    }
                    Freshness::Confirmed
                }
                None => Freshness::Unconfirmed,
            };
            fill_report(report, params.get("diagnostics"), freshness)?;
            break;
        }
    }
    Ok(())
}

#[cfg(unix)]
fn response(
    peer: &mut transport::Peer,
    id: i64,
    cx: &ToolContext,
    deadline: Instant,
) -> Result<Value, LspError> {
    loop {
        let message = peer.receive(cx, deadline)?;
        if reject_server_request(peer, &message, cx, deadline)? {
            continue;
        }
        if message.get("id").and_then(Value::as_i64) != Some(id) {
            continue;
        }
        if message.get("error").is_some() {
            return Err(LspError::Protocol("server rejected the request".into()));
        }
        return message
            .get("result")
            .cloned()
            .ok_or_else(|| LspError::Protocol("response lacks a result".into()));
    }
}

#[cfg(unix)]
fn reject_server_request(
    peer: &mut transport::Peer,
    message: &Value,
    cx: &ToolContext,
    deadline: Instant,
) -> Result<bool, LspError> {
    if message.get("method").is_some() && message.get("id").is_some() {
        peer.send(&json!({"jsonrpc":"2.0","id":message["id"],"error":{"code":-32601,"message":"Server-initiated actions are not supported"}}), cx, deadline)?;
        return Ok(true);
    }
    Ok(false)
}

fn clean_text(value: &str, report: &mut DiagnosticReport) -> String {
    let scan = orbit_tools::scan::scan_result(value);
    for redaction in scan.redactions {
        if !report.redactions.contains(&redaction) {
            report.redactions.push(redaction);
        }
    }
    let mut safe = String::with_capacity(scan.text.len());
    // Whole-line scanning handles assignments and private-key blocks. Each
    // remaining token span is then scanned once so a short prefix or another
    // token on the same line cannot conceal a credential. Work remains linear.
    for span in scan
        .text
        .split_inclusive(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '-'))
    {
        let scan = orbit_tools::scan::scan_result(span);
        for redaction in scan.redactions {
            if !report.redactions.contains(&redaction) {
                report.redactions.push(redaction);
            }
        }
        safe.push_str(&scan.text);
    }
    safe.chars()
        .filter(|c| !c.is_control() || matches!(c, '\n' | '\t'))
        .collect()
}

fn fill_report(
    report: &mut DiagnosticReport,
    items: Option<&Value>,
    freshness: Freshness,
) -> Result<(), LspError> {
    let items = items
        .and_then(Value::as_array)
        .ok_or_else(|| LspError::Protocol("diagnostics must be an array".into()))?;
    let mut output_bytes = 0;
    for (index, item) in items.iter().enumerate() {
        let object = item
            .as_object()
            .ok_or_else(|| LspError::Protocol("diagnostic must be an object".into()))?;
        let range: Range =
            serde_json::from_value(object.get("range").cloned().unwrap_or(Value::Null))
                .map_err(|_| LspError::Protocol("invalid diagnostic range".into()))?;
        if (range.start.line, range.start.character) > (range.end.line, range.end.character) {
            return Err(LspError::Protocol("diagnostic range is reversed".into()));
        }
        let message = object
            .get("message")
            .and_then(Value::as_str)
            .ok_or_else(|| LspError::Protocol("diagnostic lacks a message".into()))?;
        let severity = match object.get("severity") {
            Some(v) => Some(
                v.as_u64()
                    .filter(|n| (1..=4).contains(n))
                    .ok_or_else(|| LspError::Protocol("invalid severity".into()))?
                    as u8,
            ),
            None => None,
        };
        let source = match object.get("source") {
            Some(v) => Some(clean_text(
                v.as_str()
                    .ok_or_else(|| LspError::Protocol("invalid diagnostic source".into()))?,
                report,
            )),
            None => None,
        };
        let code = match object.get("code") {
            Some(Value::String(v)) => Some(Value::String(clean_text(v, report))),
            Some(Value::Number(v)) if v.is_i64() || v.is_u64() => Some(Value::Number(v.clone())),
            Some(_) => return Err(LspError::Protocol("invalid diagnostic code".into())),
            None => None,
        };
        let tags = match object.get("tags") {
            Some(v) => v
                .as_array()
                .ok_or_else(|| LspError::Protocol("invalid diagnostic tags".into()))?
                .iter()
                .map(|v| {
                    v.as_u64()
                        .filter(|n| (1..=2).contains(n))
                        .map(|n| n as u8)
                        .ok_or_else(|| LspError::Protocol("invalid diagnostic tag".into()))
                })
                .collect::<Result<Vec<_>, _>>()?,
            None => vec![],
        };
        let diagnostic = Diagnostic {
            range,
            severity,
            message: clean_text(message, report),
            code,
            source,
            tags,
        };
        let bytes = serde_json::to_vec(&diagnostic)
            .map_err(|_| LspError::Protocol("cannot encode diagnostics".into()))?
            .len();
        if index >= DIAGNOSTICS || output_bytes + bytes > OUTPUT_BYTES {
            report.truncated = true;
            continue;
        }
        output_bytes += bytes;
        report.diagnostics.push(diagnostic);
    }
    report.status = DiagnosticStatus::Received;
    report.freshness = freshness;
    while serde_json::to_vec(report)
        .map_err(|_| LspError::Protocol("cannot encode diagnostic report".into()))?
        .len()
        > 64 * 1024
    {
        report.truncated = true;
        if report.diagnostics.pop().is_none() {
            return Err(LspError::Protocol(
                "diagnostic metadata exceeded its limit".into(),
            ));
        }
    }
    Ok(())
}

#[cfg(unix)]
mod transport {
    use super::*;
    use std::io::{Read, Write};
    use std::os::fd::AsRawFd;
    use std::os::unix::process::CommandExt;
    use std::process::{Child, ChildStderr, ChildStdin, ChildStdout, Command, Stdio};

    pub(super) struct Peer {
        child: Option<Child>,
        process_group: i32,
        input: Option<ChildStdin>,
        output: ChildStdout,
        errors: ChildStderr,
        buffer: Vec<u8>,
        received: usize,
        sent: usize,
        error_bytes: usize,
        terminated: bool,
        pub(super) document_uri: Option<String>,
    }
    impl Peer {
        pub(super) fn start(
            server: &Server,
            cx: &ToolContext,
            deadline: Instant,
        ) -> Result<Self, LspError> {
            check(cx, deadline)?;
            let mut child = Command::new(&server.command)
                .args(&server.args)
                .current_dir(&server.workspace_root)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .process_group(0)
                .spawn()
                .map_err(|_| LspError::Io("configured server could not start".into()))?;
            let input = child.stdin.take().expect("piped stdin");
            let output = child.stdout.take().expect("piped stdout");
            let errors = child.stderr.take().expect("piped stderr");
            let process_group = child.id() as i32;
            let mut peer = Self {
                child: Some(child),
                process_group,
                input: Some(input),
                output,
                errors,
                buffer: vec![],
                received: 0,
                sent: 0,
                error_bytes: 0,
                terminated: false,
                document_uri: None,
            };
            for fd in [
                peer.input.as_ref().unwrap().as_raw_fd(),
                peer.output.as_raw_fd(),
                peer.errors.as_raw_fd(),
            ] {
                // SAFETY: live child pipe descriptors; fcntl modifies only their flags.
                let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
                if flags < 0
                    || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0
                {
                    return Err(LspError::Io("cannot configure bounded server pipes".into()));
                }
            }
            check(cx, deadline)?;
            peer.drain_errors()?;
            Ok(peer)
        }
        fn drain_errors(&mut self) -> Result<(), LspError> {
            let mut bytes = [0; 4096];
            loop {
                match self.errors.read(&mut bytes) {
                    Ok(0) => return Ok(()),
                    Ok(n) => {
                        self.error_bytes += n;
                        if self.error_bytes > 64 * 1024 {
                            return Err(LspError::Protocol(
                                "server stderr exceeded its limit".into(),
                            ));
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return Ok(()),
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(_) => return Err(LspError::Io("server stderr read failed".into())),
                }
            }
        }
        fn wait(
            &mut self,
            fd: i32,
            events: i16,
            cx: &ToolContext,
            deadline: Instant,
        ) -> Result<(), LspError> {
            check(cx, deadline)?;
            self.drain_errors()?;
            let remaining = deadline
                .saturating_duration_since(Instant::now())
                .as_millis()
                .clamp(1, 20) as i32;
            let mut fds = [
                libc::pollfd {
                    fd,
                    events,
                    revents: 0,
                },
                libc::pollfd {
                    fd: self.errors.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                },
            ];
            // SAFETY: poll receives a valid array and finite timeout.
            if unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as _, remaining) } < 0 {
                let e = std::io::Error::last_os_error();
                if e.kind() != std::io::ErrorKind::Interrupted {
                    return Err(LspError::Io("server pipe polling failed".into()));
                }
            }
            check(cx, deadline)
        }
        pub(super) fn send(
            &mut self,
            value: &Value,
            cx: &ToolContext,
            deadline: Instant,
        ) -> Result<(), LspError> {
            let body = serde_json::to_vec(value)
                .map_err(|_| LspError::Protocol("cannot encode request".into()))?;
            if body.len() > DOCUMENT_BYTES + FRAME_BYTES {
                return Err(LspError::Protocol(
                    "outgoing frame exceeded its limit".into(),
                ));
            }
            let mut frame = format!("Content-Length: {}\r\n\r\n", body.len()).into_bytes();
            frame.extend(body);
            self.sent += frame.len();
            if self.sent > TOTAL_BYTES {
                return Err(LspError::Protocol("outgoing IO exceeded its limit".into()));
            }
            let mut written = 0;
            while written < frame.len() {
                check(cx, deadline)?;
                let input = self
                    .input
                    .as_mut()
                    .ok_or_else(|| LspError::Io("server input is closed".into()))?;
                match input.write(&frame[written..]) {
                    Ok(0) => return Err(LspError::Io("server input closed during write".into())),
                    Ok(n) => written += n,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        let fd = input.as_raw_fd();
                        self.wait(fd, libc::POLLOUT, cx, deadline)?;
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(_) => return Err(LspError::Io("server request write failed".into())),
                }
                self.drain_errors()?;
            }
            Ok(())
        }
        pub(super) fn receive(
            &mut self,
            cx: &ToolContext,
            deadline: Instant,
        ) -> Result<Value, LspError> {
            loop {
                check(cx, deadline)?;
                if let Some(end) = self.buffer.windows(4).position(|w| w == b"\r\n\r\n") {
                    if end > 4096 {
                        return Err(LspError::Protocol("frame header exceeded its limit".into()));
                    }
                    let header = std::str::from_utf8(&self.buffer[..end])
                        .map_err(|_| LspError::Protocol("invalid frame header encoding".into()))?;
                    let mut length = None;
                    for line in header.split("\r\n") {
                        let (name, value) = line
                            .split_once(':')
                            .ok_or_else(|| LspError::Protocol("malformed frame header".into()))?;
                        if name.eq_ignore_ascii_case("Content-Length") {
                            if length.is_some() {
                                return Err(LspError::Protocol("duplicate Content-Length".into()));
                            }
                            length = Some(value.trim().parse::<usize>().map_err(|_| {
                                LspError::Protocol("invalid Content-Length".into())
                            })?);
                        }
                    }
                    let length = length
                        .ok_or_else(|| LspError::Protocol("frame lacks Content-Length".into()))?;
                    if length > FRAME_BYTES {
                        return Err(LspError::Protocol("frame body exceeded its limit".into()));
                    }
                    let start = end + 4;
                    if self.buffer.len() >= start + length {
                        let message: Value = serde_json::from_slice(
                            &self.buffer[start..start + length],
                        )
                        .map_err(|_| LspError::Protocol("invalid UTF-8 or JSON message".into()))?;
                        self.buffer.drain(..start + length);
                        if !message.is_object()
                            || message.get("jsonrpc").and_then(Value::as_str) != Some("2.0")
                        {
                            return Err(LspError::Protocol("invalid JSON-RPC envelope".into()));
                        }
                        return Ok(message);
                    }
                } else if self.buffer.len() > 4096 {
                    return Err(LspError::Protocol("frame header exceeded its limit".into()));
                }
                let mut bytes = [0; 8192];
                match self.output.read(&mut bytes) {
                    Ok(0) => {
                        return Err(LspError::Io("server output closed before a result".into()));
                    }
                    Ok(n) => {
                        self.received += n;
                        if self.received > TOTAL_BYTES {
                            return Err(LspError::Protocol(
                                "incoming IO exceeded its limit".into(),
                            ));
                        }
                        self.buffer.extend_from_slice(&bytes[..n]);
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        self.wait(self.output.as_raw_fd(), libc::POLLIN, cx, deadline)?
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(_) => return Err(LspError::Io("server response read failed".into())),
                }
                self.drain_errors()?;
            }
        }
        pub(super) fn finish(&mut self, cx: &ToolContext) -> Result<(), LspError> {
            let deadline = Instant::now() + Duration::from_millis(250);
            let grace = deadline - Duration::from_millis(50);
            // Cancellation does not permit another document request. Cleanup can
            // still close pipes and terminate the owned child process group.
            if !cx.is_cancelled() {
                if let Some(uri) = self.document_uri.take() {
                    let _ = self.send(&json!({"jsonrpc":"2.0","method":"textDocument/didClose","params":{"textDocument":{"uri":uri}}}), cx, grace);
                }
                let _ = self.send(
                    &json!({"jsonrpc":"2.0","id":3,"method":"shutdown","params":null}),
                    cx,
                    grace,
                );
                let _ = response(self, 3, cx, grace);
                let _ = self.send(
                    &json!({"jsonrpc":"2.0","method":"exit","params":null}),
                    cx,
                    grace,
                );
            }
            self.input.take();
            while !cx.is_cancelled() && Instant::now() < grace {
                // Observe without reaping: the owned leader's PID must remain
                // reserved until its whole process group has been terminated.
                if self.leader_exited() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            self.terminate(deadline)
        }
        fn leader_exited(&self) -> bool {
            #[cfg(target_os = "linux")]
            {
                // SAFETY: a live owned child PID and valid siginfo storage;
                // WNOWAIT deliberately retains the child and PID ownership.
                let mut info = unsafe { std::mem::zeroed::<libc::siginfo_t>() };
                unsafe {
                    libc::waitid(
                        libc::P_PID,
                        self.process_group as _,
                        &mut info,
                        libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
                    ) == 0
                        && info.si_pid() == self.process_group
                }
            }
            #[cfg(not(target_os = "linux"))]
            {
                false
            }
        }
        fn terminate(&mut self, deadline: Instant) -> Result<(), LspError> {
            if self.terminated {
                return Ok(());
            }
            self.terminated = true;
            let Some(mut child) = self.child.take() else {
                return Ok(());
            };
            // SAFETY: process_group(0) assigned this child a distinct owned group.
            // No wait/try_wait has reaped it yet, so its PID/group identity cannot
            // be reused. Helpers are killed even if the leader has already exited.
            let group_failed = unsafe { libc::killpg(self.process_group, libc::SIGKILL) } < 0
                && std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH);
            let _ = child.kill();
            loop {
                if child.try_wait().is_ok_and(|status| status.is_some()) {
                    return if group_failed {
                        Err(LspError::Io(
                            "owned process group could not be terminated".into(),
                        ))
                    } else {
                        Ok(())
                    };
                }
                if Instant::now() >= deadline {
                    break;
                }
                std::thread::sleep(Duration::from_millis(2));
            }
            // A kernel-stalled process cannot hold the caller indefinitely.
            // Retain its wait ownership in a reaper, and report incomplete
            // cleanup rather than advertising a successful diagnostic request.
            let _ = std::thread::Builder::new()
                .name("lsp-reaper".into())
                .spawn(move || {
                    let _ = child.wait();
                });
            Err(LspError::Io(
                "owned server cleanup exceeded its deadline".into(),
            ))
        }
    }
    impl Drop for Peer {
        fn drop(&mut self) {
            let _ = self.terminate(Instant::now() + Duration::from_millis(250));
        }
    }
}
