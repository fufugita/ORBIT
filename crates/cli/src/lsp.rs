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
        "operation":{"type":"string","enum":["diagnostics","definition","references","hover","document_symbols","workspace_symbols"],"description":"What to ask; diagnostics when omitted"},
        "line":{"type":"integer","minimum":1,"description":"1-based line, for definition, references and hover"},
        "character":{"type":"integer","minimum":1,"description":"1-based column on that line, on the symbol"},
        "query":{"type":"string","description":"The symbol name to look for, for workspace_symbols"},
        "server":{"type":"string","description":"Optional configured server name"}
    },"required":["file_path"],"additionalProperties":false});
    ToolDefinition {
        name: "LspDiagnostics".into(),
        description: "Ask an explicitly configured language server about one file. Without an operation: on-demand diagnostics, which distinguish received, stale and unavailable results and report freshness. With an operation: where the symbol at a position is defined (definition) or used (references), what the server knows about it (hover), the symbols of the file (document_symbols), or symbols by name across the workspace (workspace_symbols). Results in files this session may not read are counted, not shown.".into(),
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

/// Everything a request needs before a server is started: the one
/// configured server that owns the document, the document's text read
/// through an identity-checked descriptor, and the deadline. Authorization
/// runs before the read, on the opened target, and after it.
struct Prepared {
    server: Server,
    document: String,
    uri: String,
    deadline: Instant,
}

fn prepare(
    home: &Path,
    cx: &ToolContext,
    scope: &PermissionScope,
    file_path: &str,
    server_name: Option<&String>,
) -> Result<Prepared, LspError> {
    if cx.is_cancelled() {
        return Err(LspError::Cancelled);
    }
    if file_path.is_empty() || file_path.len() > 4096 || file_path.contains('\0') {
        return Err(LspError::Denied("invalid document path".into()));
    }
    let servers = configuration(home, cx)?
        .ok_or_else(|| LspError::Denied("diagnostics are disabled or unconfigured".into()))?;
    let original = resolve_path(cx, file_path);
    let file = original
        .canonicalize()
        .map_err(|_| LspError::Denied("document is unavailable".into()))?;
    let extension = file.extension().and_then(|e| e.to_str()).unwrap_or("");
    let mut candidates = servers.into_iter().filter(|s| {
        server_name.is_none_or(|name| &s.name == name)
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
        file_path,
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
            file_path,
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
        file_path,
        &original,
        &file,
        &server.workspace_root,
    )?;
    Ok(Prepared {
        server,
        document,
        uri,
        deadline,
    })
}

/// The shared runtime performs normal approval evaluation before this call.
/// Defense in depth repeats inherited scope, deny rules and path containment.
pub fn diagnostics(
    home: &Path,
    cx: &ToolContext,
    scope: &PermissionScope,
    args: &LspDiagnosticsArgs,
) -> Result<DiagnosticReport, LspError> {
    let Prepared {
        server,
        document,
        uri,
        deadline,
    } = prepare(home, cx, scope, &args.file_path, args.server.as_ref())?;
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

/// Arguments of a navigation request: the same tool as diagnostics, with
/// an `operation`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LspNavigateArgs {
    /// `definition`, `references`, `hover`, `document_symbols` or
    /// `workspace_symbols`.
    pub operation: String,
    pub file_path: String,
    /// 1-based, as an editor shows them. Needed for `definition`,
    /// `references` and `hover`.
    #[serde(default)]
    pub line: Option<u32>,
    #[serde(default)]
    pub character: Option<u32>,
    /// The name to look for, for `workspace_symbols`.
    #[serde(default)]
    pub query: Option<String>,
    #[serde(default)]
    pub server: Option<String>,
}

/// What a navigation request found.
#[derive(Debug, Clone, Serialize)]
pub struct NavigationReport {
    pub server: String,
    pub operation: String,
    /// Locations and symbols: `path` relative to the server's workspace
    /// where it lies inside it, `line` and `character` 1-based.
    pub results: Vec<Value>,
    /// Hover text, for `hover`.
    pub text: Option<String>,
    /// Results in files this session may not read are counted, not shown.
    pub withheld: usize,
    pub truncated: bool,
    pub reason: Option<String>,
    pub redactions: Vec<String>,
}

const NAVIGATION_RESULTS: usize = 200;
const NAVIGATION_FILES: usize = 64;
const NAVIGATION_ATTEMPTS: u32 = 40;

/// The tool's one entry point: diagnostics when no `operation` is named (or
/// `diagnostics`), otherwise navigation.
pub fn run(
    home: &Path,
    cx: &ToolContext,
    scope: &PermissionScope,
    args: &Value,
) -> Result<Value, LspError> {
    let invalid = |error: serde_json::Error| LspError::Configuration(error.to_string());
    let encode = |error: serde_json::Error| LspError::Protocol(error.to_string());
    match args.get("operation").and_then(Value::as_str) {
        None | Some("diagnostics") => {
            let mut plain = args.clone();
            if let Some(object) = plain.as_object_mut() {
                object.remove("operation");
            }
            let arguments: LspDiagnosticsArgs = serde_json::from_value(plain).map_err(invalid)?;
            serde_json::to_value(diagnostics(home, cx, scope, &arguments)?).map_err(encode)
        }
        Some(_) => {
            let arguments: LspNavigateArgs =
                serde_json::from_value(args.clone()).map_err(invalid)?;
            serde_json::to_value(navigate(home, cx, scope, &arguments)?).map_err(encode)
        }
    }
}

/// The LSP method, the capability that announces it, and whether it takes a
/// position.
fn navigation_method(operation: &str) -> Option<(&'static str, &'static str, bool)> {
    Some(match operation {
        "definition" => ("textDocument/definition", "definitionProvider", true),
        "references" => ("textDocument/references", "referencesProvider", true),
        "hover" => ("textDocument/hover", "hoverProvider", true),
        "document_symbols" => (
            "textDocument/documentSymbol",
            "documentSymbolProvider",
            false,
        ),
        "workspace_symbols" => ("workspace/symbol", "workspaceSymbolProvider", false),
        _ => return None,
    })
}

/// A 1-based character column of `line` as the offset the server counts in.
fn encoded_column(line: &str, column: u32, encoding: &str) -> u32 {
    let before = line.chars().take(column.saturating_sub(1) as usize);
    match encoding {
        "utf-8" => before.map(char::len_utf8).sum::<usize>() as u32,
        "utf-32" => before.count() as u32,
        _ => before.map(char::len_utf16).sum::<usize>() as u32,
    }
}

/// Symbol kinds as words (the protocol's numbering).
fn symbol_kind(kind: u64) -> &'static str {
    const KINDS: [&str; 26] = [
        "file",
        "module",
        "namespace",
        "package",
        "class",
        "method",
        "property",
        "field",
        "constructor",
        "enum",
        "interface",
        "function",
        "variable",
        "constant",
        "string",
        "number",
        "boolean",
        "array",
        "object",
        "key",
        "null",
        "enum member",
        "struct",
        "event",
        "operator",
        "type parameter",
    ];
    usize::try_from(kind)
        .ok()
        .and_then(|kind| KINDS.get(kind.checked_sub(1)?))
        .copied()
        .unwrap_or("symbol")
}

/// Navigate from one authorized document: where a symbol is defined, where
/// it is used, what the server says about it, and the symbols of the
/// document or the workspace. The document passes the same checks as for
/// diagnostics. Every file a result names is checked the same way: one this
/// session may not read is counted in `withheld` and not named.
pub fn navigate(
    home: &Path,
    cx: &ToolContext,
    scope: &PermissionScope,
    args: &LspNavigateArgs,
) -> Result<NavigationReport, LspError> {
    let (method, capability, positional) = navigation_method(&args.operation).ok_or_else(|| {
        LspError::Denied(
            "operation must be diagnostics, definition, references, hover, document_symbols or workspace_symbols"
                .into(),
        )
    })?;
    let position = match (positional, args.line, args.character) {
        (true, Some(line), Some(character)) if line >= 1 && character >= 1 => {
            Some((line, character))
        }
        (true, _, _) => {
            return Err(LspError::Denied(
                "this operation needs a 1-based line and character".into(),
            ));
        }
        (false, _, _) => None,
    };
    let query = args.query.as_deref().unwrap_or("").trim();
    if args.operation == "workspace_symbols" && (query.is_empty() || query.len() > 200) {
        return Err(LspError::Denied(
            "workspace_symbols needs a query of at most 200 characters".into(),
        ));
    }
    let Prepared {
        server,
        document,
        uri,
        deadline,
    } = prepare(home, cx, scope, &args.file_path, args.server.as_ref())?;
    let mut report = NavigationReport {
        server: server.name.clone(),
        operation: args.operation.clone(),
        results: Vec::new(),
        text: None,
        withheld: 0,
        truncated: false,
        reason: None,
        redactions: Vec::new(),
    };
    #[cfg(unix)]
    {
        let mut peer = transport::Peer::start(&server, cx, deadline)?;
        let answer = navigation_exchange(
            &mut peer, &server, &document, &uri, method, capability, position, query, cx, deadline,
        );
        let cleanup = peer.finish(cx);
        if answer.is_ok() || matches!(answer, Err(LspError::Timeout)) {
            cleanup?;
        }
        match answer {
            Ok(Some(result)) => {
                fill_navigation(home, cx, scope, &server, &mut report, &result);
                Ok(report)
            }
            Ok(None) => {
                report.reason = Some("the server found nothing there".into());
                Ok(report)
            }
            Err(LspError::Timeout) => {
                report.reason = Some(
                    "the language server gave no answer before the deadline; it may still be indexing"
                        .into(),
                );
                Ok(report)
            }
            Err(error) => Err(error),
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (
            server, document, uri, deadline, method, capability, position, query, report,
        );
        Err(LspError::Configuration(
            "stdio language servers currently require Unix".into(),
        ))
    }
}

/// Handshake, open the document, ask. A server that is still loading
/// answers with an error or with nothing: the request is repeated, a little
/// apart, until it answers or the deadline passes. `Ok(None)` is a server
/// that answered "nothing".
#[cfg(unix)]
#[allow(clippy::too_many_arguments)]
fn navigation_exchange(
    peer: &mut transport::Peer,
    server: &Server,
    document: &str,
    uri: &str,
    method: &str,
    capability: &str,
    position: Option<(u32, u32)>,
    query: &str,
    cx: &ToolContext,
    deadline: Instant,
) -> Result<Option<Value>, LspError> {
    let root_uri = url::Url::from_directory_path(&server.workspace_root)
        .map_err(|_| LspError::Configuration("workspace URI cannot be encoded".into()))?
        .to_string();
    peer.send(
        &json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{
        "processId":std::process::id(),"rootUri":root_uri,"capabilities":{
            "general":{"positionEncodings":["utf-8","utf-16","utf-32"]},
            "textDocument":{
                "definition":{"linkSupport":true},
                "references":{},
                "hover":{"contentFormat":["plaintext","markdown"]},
                "documentSymbol":{"hierarchicalDocumentSymbolSupport":true}
            },
            "workspace":{"symbol":{}}
        },"clientInfo":{"name":"ORBIT"}}}),
        cx,
        deadline,
    )?;
    let initialization = response(peer, 1, cx, deadline)?;
    let caps = initialization
        .get("capabilities")
        .and_then(Value::as_object)
        .ok_or_else(|| LspError::Protocol("initialize response lacks capabilities".into()))?;
    let offered = caps
        .get(capability)
        .is_some_and(|value| value.as_bool().unwrap_or(!value.is_null()));
    if !offered {
        return Err(LspError::Denied(
            "the language server does not offer this operation".into(),
        ));
    }
    let encoding = caps
        .get("positionEncoding")
        .and_then(Value::as_str)
        .filter(|encoding| ["utf-8", "utf-16", "utf-32"].contains(encoding))
        .unwrap_or("utf-16");
    peer.send(
        &json!({"jsonrpc":"2.0","method":"initialized","params":{}}),
        cx,
        deadline,
    )?;
    peer.send(
        &json!({"jsonrpc":"2.0","method":"textDocument/didOpen","params":{"textDocument":{
            "uri":uri,"languageId":server.language_id,"version":1,"text":document
        }}}),
        cx,
        deadline,
    )?;
    peer.document_uri = Some(uri.to_owned());
    let mut params = match position {
        Some((line, character)) => {
            let text = document.lines().nth(line as usize - 1).unwrap_or("");
            json!({"textDocument":{"uri":uri},"position":{
                "line": line - 1,
                "character": encoded_column(text, character, encoding)
            }})
        }
        None if method == "workspace/symbol" => json!({"query": query}),
        None => json!({"textDocument":{"uri":uri}}),
    };
    if method == "textDocument/references" {
        params["context"] = json!({"includeDeclaration": true});
    }
    for attempt in 0..NAVIGATION_ATTEMPTS {
        let id = 2 + i64::from(attempt);
        peer.send(
            &json!({"jsonrpc":"2.0","id":id,"method":method,"params":params}),
            cx,
            deadline,
        )?;
        let answered = loop {
            let message = peer.receive(cx, deadline)?;
            if reject_server_request(peer, &message, cx, deadline)? {
                continue;
            }
            if message.get("id").and_then(Value::as_i64) != Some(id) {
                continue;
            }
            break message;
        };
        let result = answered.get("result");
        let empty = result
            .is_none_or(|result| result.is_null() || result.as_array().is_some_and(Vec::is_empty));
        if !empty {
            return Ok(result.cloned());
        }
        // An explicit "nothing" from a server that has had time to load is
        // an answer; an error, or nothing on the first tries, is asked again.
        if answered.get("error").is_none() && attempt >= 2 {
            return Ok(None);
        }
        check(cx, deadline)?;
        std::thread::sleep(
            Duration::from_millis(250).min(deadline.saturating_duration_since(Instant::now())),
        );
        check(cx, deadline)?;
    }
    Ok(None)
}

fn clean_into(value: &str, redactions: &mut Vec<String>) -> String {
    let mut scratch = DiagnosticReport {
        server: String::new(),
        uri: String::new(),
        document_version: 0,
        position_encoding: String::new(),
        status: DiagnosticStatus::Unavailable,
        freshness: Freshness::Unconfirmed,
        reason: None,
        diagnostics: Vec::new(),
        truncated: false,
        redactions: std::mem::take(redactions),
    };
    let text = clean_text(value, &mut scratch);
    *redactions = scratch.redactions;
    text
}

/// Turn the server's answer into bounded, checked results.
fn fill_navigation(
    home: &Path,
    cx: &ToolContext,
    scope: &PermissionScope,
    server: &Server,
    report: &mut NavigationReport,
    result: &Value,
) {
    if report.operation == "hover" {
        let contents = result.get("contents").unwrap_or(&Value::Null);
        let piece = |value: &Value| {
            value
                .as_str()
                .or_else(|| value.get("value").and_then(Value::as_str))
                .map(str::to_owned)
        };
        let text = match contents {
            Value::Array(parts) => parts
                .iter()
                .filter_map(piece)
                .collect::<Vec<_>>()
                .join("\n\n"),
            other => piece(other).unwrap_or_default(),
        };
        let text: String = text.chars().take(8_000).collect();
        if text.trim().is_empty() {
            report.reason = Some("the server has nothing to say about that position".into());
        } else {
            report.text = Some(clean_into(&text, &mut report.redactions));
        }
        return;
    }
    // Which files may be named: each is put through the document's own
    // checks once.
    let mut verdicts: std::collections::HashMap<PathBuf, Option<String>> =
        std::collections::HashMap::new();
    let mut shown_path = |uri: &str| -> Option<String> {
        let path = url::Url::parse(uri).ok()?.to_file_path().ok()?;
        if !verdicts.contains_key(&path) && verdicts.len() >= NAVIGATION_FILES {
            return None;
        }
        verdicts
            .entry(path.clone())
            .or_insert_with(|| {
                let real = path.canonicalize().ok()?;
                let named = real.to_string_lossy().into_owned();
                authorize(
                    home,
                    cx,
                    scope,
                    &named,
                    &real,
                    &real,
                    &server.workspace_root,
                )
                .ok()?;
                Some(
                    real.strip_prefix(&server.workspace_root)
                        .map_or(named.clone(), |inside| {
                            inside.to_string_lossy().into_owned()
                        }),
                )
            })
            .clone()
    };
    let start_of = |range: Option<&Value>| {
        let start = range?.get("start")?;
        Some((
            start.get("line")?.as_u64()? + 1,
            start.get("character")?.as_u64()? + 1,
        ))
    };
    // Flatten: a location, a list of them, location links, or symbols (flat
    // or nested under `children`).
    let mut pending: Vec<(&Value, Option<String>)> = match result {
        Value::Array(items) => items.iter().rev().map(|item| (item, None)).collect(),
        single => vec![(single, None)],
    };
    while let Some((item, container)) = pending.pop() {
        if report.results.len() >= NAVIGATION_RESULTS {
            report.truncated = true;
            break;
        }
        let location = item.get("location").unwrap_or(item);
        let uri = location
            .get("uri")
            .or_else(|| location.get("targetUri"))
            .and_then(Value::as_str);
        let range = location
            .get("targetSelectionRange")
            .or_else(|| location.get("selectionRange"))
            .or_else(|| location.get("range"));
        let name = item.get("name").and_then(Value::as_str);
        let mut entry = serde_json::Map::new();
        match uri {
            Some(uri) => match shown_path(uri) {
                Some(path) => {
                    entry.insert("path".into(), json!(path));
                }
                None => {
                    report.withheld += 1;
                    continue;
                }
            },
            // A document symbol has no URI: it is in the document asked about.
            None if name.is_some() => {}
            None => continue,
        }
        if let Some((line, character)) = start_of(range) {
            entry.insert("line".into(), json!(line));
            entry.insert("character".into(), json!(character));
        }
        if let Some(name) = name {
            let name: String = name.chars().take(200).collect();
            entry.insert(
                "name".into(),
                json!(clean_into(&name, &mut report.redactions)),
            );
            if let Some(kind) = item.get("kind").and_then(Value::as_u64) {
                entry.insert("kind".into(), json!(symbol_kind(kind)));
            }
            let within = container.clone().or_else(|| {
                item.get("containerName")
                    .and_then(Value::as_str)
                    .filter(|within| !within.is_empty())
                    .map(|within| within.chars().take(200).collect())
            });
            if let Some(within) = within {
                entry.insert(
                    "in".into(),
                    json!(clean_into(&within, &mut report.redactions)),
                );
            }
            if let Some(children) = item.get("children").and_then(Value::as_array) {
                for child in children.iter().rev() {
                    pending.push((child, Some(name.clone())));
                }
            }
        }
        report.results.push(Value::Object(entry));
    }
    if report.results.is_empty() && report.withheld == 0 {
        report.reason = Some("the server found nothing there".into());
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
