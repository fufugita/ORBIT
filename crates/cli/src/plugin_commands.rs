//! Local plugin inspection and managed immutable package snapshots.

use crate::CliError;
use orbit_plugin_compat::{
    CompatError, InspectOptions, PluginFormat, PluginId, PluginStore, StoreScope,
};
use serde_json::{Map, Value, json};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

const USAGE: &str = "orbit plugin inspect PATH [--format portable|claude|codex|hermes] [--model-map SOURCE=TARGET] [--tool-map SOURCE=TARGET] [--json]\norbit plugin import|install PATH [--scope user|project] [--no-enable] [--format FORMAT] [--model-map SOURCE=TARGET] [--tool-map SOURCE=TARGET] [--json]\norbit plugin list [--json]\norbit plugin status ID [--scope user|project] [--json]\norbit plugin enable|disable|remove ID [--scope user|project] [--revision REV] [--json]\norbit plugin upgrade ID PATH [--scope user|project] [--revision REV] [--format FORMAT] [--model-map SOURCE=TARGET] [--tool-map SOURCE=TARGET] [--json]";
const WITHHELD: &str = "[configured literal]";
const MAX_TEXT: usize = 8192;
const MAX_REPORT: usize = 256 * 1024;

/// Dispatch without initializing identity, providers or package runtimes.
pub fn command(home: &Path, project: &Path, args: &[String]) -> Result<Value, CliError> {
    let mut words = Vec::new();
    let mut json_seen = false;
    for word in args {
        if word == "--json" {
            if json_seen {
                return Err(usage("duplicate --json flag"));
            }
            json_seen = true;
        } else {
            words.push(word.as_str());
        }
    }
    if words.is_empty()
        || words == ["help"]
        || words == ["--help"]
        || words == ["-h"]
        || (words.len() == 2
            && [
                "inspect", "import", "install", "list", "status", "enable", "disable", "remove",
                "upgrade",
            ]
            .contains(&words[0])
            && ["--help", "-h"].contains(&words[1]))
    {
        return Ok(
            json!({"schema":"orbit.cli/v1", "command":"plugin help", "status":"ok", "usage":USAGE,
            "description":"Inspect local packages or manage immutable snapshots without executing package code."}),
        );
    }
    let operation = words[0];
    if operation == "list" {
        if words.len() != 1 {
            return Err(usage("plugin list accepts only --json"));
        }
        let snapshot = open_store(home, project)?.list().map_err(compat_error)?;
        return report("plugin list", "snapshot", &snapshot);
    }
    if operation == "status" {
        return status(home, project, &words[1..]);
    }
    if matches!(operation, "enable" | "disable" | "remove") {
        return mutate(home, project, operation, &words[1..]);
    }
    let importing = matches!(operation, "import" | "install");
    let upgrading = operation == "upgrade";
    if operation != "inspect" && !importing && !upgrading {
        return Err(usage("unknown plugin operation; use plugin --help"));
    }
    let mut options = InspectOptions::default();
    let mut path = None;
    let mut scope = None;
    let mut no_enable = false;
    let mut name = None;
    let mut revision = None;
    let mut index = 1;
    while index < words.len() {
        match words[index] {
            "--scope" if importing || upgrading => {
                if scope.is_some() {
                    return Err(usage("duplicate --scope flag"));
                }
                scope = Some(parse_scope(operand(&words, &mut index)?)?);
            }
            "--revision" if upgrading => {
                parse_revision(&words, &mut index, &mut revision)?;
            }
            "--no-enable" if importing => {
                if no_enable {
                    return Err(usage("duplicate --no-enable flag"));
                }
                no_enable = true;
            }
            "--format" => {
                if options.format.is_some() {
                    return Err(usage("duplicate --format flag"));
                }
                let value = operand(&words, &mut index)?;
                options.format = Some(match value {
                    "portable" => PluginFormat::Portable,
                    "claude" => PluginFormat::Claude,
                    "codex" => PluginFormat::Codex,
                    "hermes" => PluginFormat::Hermes,
                    _ => return Err(usage("format must be portable, claude, codex or hermes")),
                });
            }
            flag @ ("--model-map" | "--tool-map") => {
                let value = operand(&words, &mut index)?;
                let (source, target) = value
                    .split_once('=')
                    .filter(|(source, target)| valid_mapping(source) && valid_mapping(target))
                    .ok_or_else(|| usage("mapping must be SOURCE=TARGET with nonempty values"))?;
                let mappings = if flag == "--model-map" {
                    &mut options.model_map
                } else {
                    &mut options.tool_map
                };
                if mappings
                    .insert(source.to_owned(), target.to_owned())
                    .is_some()
                {
                    return Err(usage("duplicate mapping source"));
                }
            }
            word if word.starts_with('-') => return Err(usage("unknown plugin operation flag")),
            word => {
                if word.is_empty() {
                    return Err(usage("operation requires a nonempty package path"));
                }
                if upgrading && name.is_none() {
                    name = Some(word.to_owned());
                    index += 1;
                    continue;
                }
                if path.replace(PathBuf::from(word)).is_some() {
                    return Err(usage("operation requires exactly one package path"));
                }
            }
        }
        index += 1;
    }
    let path = path.ok_or_else(|| usage("operation requires a package path"))?;
    let path = if path.is_absolute() {
        path
    } else {
        project.join(path)
    };
    if upgrading {
        let id = PluginId {
            name: name.ok_or_else(|| usage("plugin upgrade requires an ID and package path"))?,
            scope: scope.unwrap_or(StoreScope::User),
        };
        let store = open_store(home, project)?;
        let revision = current_revision(&store, revision)?;
        let mut retained = store
            .status(&id)
            .map_err(compat_error)?
            .ok_or_else(|| {
                CliError::ConfigInvalid("plugin operation failed (store_plugin_not_found)".into())
            })?
            .options;
        if options.format.is_some() {
            retained.format = options.format;
        }
        retained.model_map.extend(options.model_map);
        retained.tool_map.extend(options.tool_map);
        let receipt = store
            .upgrade(&id, &path, &retained, &revision)
            .map_err(compat_error)?;
        return report("plugin upgrade", "receipt", &receipt);
    }
    if importing {
        let receipt = open_store(home, project)?
            .import(
                &path,
                &options,
                scope.unwrap_or(StoreScope::User),
                !no_enable,
            )
            .map_err(compat_error)?;
        return report(
            if operation == "install" {
                "plugin install"
            } else {
                "plugin import"
            },
            "receipt",
            &receipt,
        );
    }
    let inspected = orbit_plugin_compat::inspect(&path, &options).map_err(compat_error)?;
    report("plugin inspect", "inspection", &inspected)
}

fn open_store(home: &Path, project: &Path) -> Result<PluginStore, CliError> {
    let trusted =
        orbit_tools::permissions::FolderTrust::new(home.to_path_buf()).is_trusted(project);
    PluginStore::open(home, project, trusted).map_err(compat_error)
}

fn parse_scope(value: &str) -> Result<StoreScope, CliError> {
    match value {
        "user" => Ok(StoreScope::User),
        "project" => Ok(StoreScope::Project),
        _ => Err(usage("scope must be user or project")),
    }
}

fn parse_revision(
    words: &[&str],
    index: &mut usize,
    revision: &mut Option<String>,
) -> Result<(), CliError> {
    if revision.is_some() {
        return Err(usage("duplicate --revision flag"));
    }
    let value = operand(words, index)?;
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(usage("revision must be a 64-character hexadecimal digest"));
    }
    *revision = Some(value.to_owned());
    Ok(())
}

fn current_revision(store: &PluginStore, revision: Option<String>) -> Result<String, CliError> {
    match revision {
        Some(revision) => Ok(revision),
        None => Ok(store.list().map_err(compat_error)?.revision),
    }
}

fn mutate(home: &Path, project: &Path, operation: &str, words: &[&str]) -> Result<Value, CliError> {
    let mut name = None;
    let mut scope = None;
    let mut revision = None;
    let mut index = 0;
    while index < words.len() {
        match words[index] {
            "--scope" => {
                if scope.is_some() {
                    return Err(usage("duplicate --scope flag"));
                }
                scope = Some(parse_scope(operand(words, &mut index)?)?);
            }
            "--revision" => parse_revision(words, &mut index, &mut revision)?,
            word if word.starts_with('-') => return Err(usage("unknown plugin operation flag")),
            word => {
                if word.is_empty() || name.replace(word.to_owned()).is_some() {
                    return Err(usage("operation requires exactly one nonempty plugin ID"));
                }
            }
        }
        index += 1;
    }
    let id = PluginId {
        name: name.ok_or_else(|| usage("operation requires a plugin ID"))?,
        scope: scope.unwrap_or(StoreScope::User),
    };
    let store = open_store(home, project)?;
    let revision = current_revision(&store, revision)?;
    let snapshot = match operation {
        "enable" => store.enable(&id, &revision),
        "disable" => store.disable(&id, &revision),
        "remove" => store.remove(&id, &revision),
        _ => return Err(usage("unknown plugin operation")),
    }
    .map_err(compat_error)?;
    report(&format!("plugin {operation}"), "snapshot", &snapshot)
}

fn status(home: &Path, project: &Path, words: &[&str]) -> Result<Value, CliError> {
    let mut name = None;
    let mut scope = None;
    let mut index = 0;
    while index < words.len() {
        match words[index] {
            "--scope" => {
                if scope.is_some() {
                    return Err(usage("duplicate --scope flag"));
                }
                scope = Some(parse_scope(operand(words, &mut index)?)?);
            }
            word if word.starts_with('-') => return Err(usage("unknown plugin status flag")),
            word => {
                if word.is_empty() || name.replace(word.to_owned()).is_some() {
                    return Err(usage("plugin status requires exactly one nonempty ID"));
                }
            }
        }
        index += 1;
    }
    let id = PluginId {
        name: name.ok_or_else(|| usage("plugin status requires an ID"))?,
        scope: scope.unwrap_or(StoreScope::User),
    };
    let plugin = open_store(home, project)?
        .status(&id)
        .map_err(compat_error)?
        .ok_or_else(|| {
            CliError::ConfigInvalid("plugin operation failed (store_plugin_not_found)".into())
        })?;
    report("plugin status", "plugin", &plugin)
}

fn compat_error(error: CompatError) -> CliError {
    // Codes are source-free; never render parser excerpts, input paths or
    // package-provided values in the error channel.
    let code: String = error
        .code
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '_')
        .take(96)
        .collect();
    let message = format!("plugin operation failed ({code})");
    if error.code == "store_project_untrusted" {
        CliError::Policy(message)
    } else {
        CliError::ConfigInvalid(message)
    }
}

fn report(command: &str, field: &str, record: &impl serde::Serialize) -> Result<Value, CliError> {
    let rendered = serde_json::to_value(record)
        .map_err(|_| CliError::ConfigInvalid("plugin record serialization failed".into()))?;
    let literals = LiteralCatalog::collect(&rendered);
    let mut budget = DisplayBudget {
        nodes: 4096,
        text: 64 * 1024,
        work: 1024 * 1024,
        truncated: false,
    };
    // Typed mode starts only at a serialized compatibility DTO. Its serde-owned
    // keys and computed fields differ from arbitrary source metadata below.
    let rendered = redact(rendered, FieldContext::Typed, &literals, &mut budget, 0);
    let mut report = json!({"schema":"orbit.cli/v1", "command":command, "status":"ok", "display_truncated":budget.truncated,
        "package_code_executed":false, "runtime_readiness":"unchecked"});
    report[field] = rendered;
    if serde_json::to_vec(&report).map_or(true, |bytes| bytes.len() > MAX_REPORT) {
        return Err(CliError::ConfigInvalid(
            "plugin record exceeds the display limit".into(),
        ));
    }
    Ok(report)
}

fn usage(message: &str) -> CliError {
    CliError::Usage(format!("{message}; {USAGE}"))
}

fn operand<'a>(words: &[&'a str], index: &mut usize) -> Result<&'a str, CliError> {
    *index += 1;
    words
        .get(*index)
        .copied()
        .filter(|word| !word.starts_with('-'))
        .ok_or_else(|| usage("missing flag value"))
}

fn valid_mapping(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 512
        && !value.contains('=')
        && !value.chars().any(char::is_control)
        && value.trim() == value
}

fn env_reference(value: &str) -> bool {
    value
        .strip_prefix("${")
        .and_then(|v| v.strip_suffix('}'))
        .is_some_and(|name| {
            !name.is_empty()
                && name.bytes().enumerate().all(|(i, b)| {
                    b == b'_' || b.is_ascii_alphabetic() || (i > 0 && b.is_ascii_digit())
                })
        })
}

fn sensitive(name: &str) -> bool {
    if orbit_adapter::redaction::classify_sensitive_name(name).is_some() {
        return true;
    }
    let name = name.to_ascii_lowercase().replace('-', "_");
    matches!(
        name.as_str(),
        "auth"
            | "credentials"
            | "credential"
            | "api_key"
            | "apikey"
            | "client_secret"
            | "password"
            | "passwd"
            | "private_key"
            | "secret"
            | "token"
    ) || name.ends_with("_secret")
        || name.ends_with("_password")
        || name.ends_with("_token")
        || name.ends_with("apikey")
        || name.ends_with("accesstoken")
        || name.ends_with("refreshtoken")
        || name.ends_with("clientsecret")
        || name.ends_with("password")
}

fn literal_map(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "env" | "env_vars" | "headers" | "http_headers"
    )
}

/// Canonicalize before classifying either keys or values. The input bound is
/// checked before allocating; no control/bidi removal may create a later URL.
fn canonical(text: &str) -> Option<String> {
    if text.len() > MAX_TEXT {
        return None;
    }
    Some(text.chars().filter(|c| !c.is_control()
        && !matches!(*c, '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')).collect())
}

#[derive(Default)]
struct LiteralCatalog {
    values: Vec<String>,
    complete: bool,
}

impl LiteralCatalog {
    fn collect(value: &Value) -> Self {
        struct Collection {
            nodes: usize,
            total: usize,
            values: BTreeSet<String>,
            complete: bool,
        }
        fn visit(
            value: &Value,
            credential: bool,
            configured: bool,
            state: &mut Collection,
            depth: usize,
        ) {
            if state.nodes == 0 || depth > 32 {
                state.complete = false;
                return;
            }
            state.nodes -= 1;
            match value {
                Value::String(value) if credential || configured => {
                    let reference = env_reference(value);
                    let Some(value) = canonical(value) else {
                        state.complete = false;
                        return;
                    };
                    // Every configured value is hidden at its declared field.
                    // Short noncredential settings such as "1", "name" and
                    // "bytes" are not global secret-substring candidates.
                    if value.is_empty() || reference || (!credential && value.len() < 12) {
                        return;
                    }
                    if state.values.contains(&value) {
                        return;
                    }
                    if state.values.len() == 128
                        || state.total.saturating_add(value.len()) > 16 * 1024
                    {
                        state.complete = false;
                        return;
                    }
                    state.total += value.len();
                    state.values.insert(value);
                }
                Value::Array(values) => {
                    for value in values {
                        if state.nodes == 0 {
                            state.complete = false;
                            break;
                        }
                        visit(value, credential, configured, state, depth + 1);
                    }
                }
                Value::Object(values) => {
                    for (key, value) in values {
                        if state.nodes == 0 {
                            state.complete = false;
                            break;
                        }
                        let Some(key) = canonical(key) else {
                            state.complete = false;
                            continue;
                        };
                        visit(
                            value,
                            credential || sensitive(&key),
                            configured || literal_map(&key),
                            state,
                            depth + 1,
                        );
                    }
                }
                _ => {}
            }
        }
        let mut state = Collection {
            nodes: 16384,
            total: 0,
            values: BTreeSet::new(),
            complete: true,
        };
        visit(value, false, false, &mut state, 0);
        let mut values: Vec<String> = state.values.into_iter().collect();
        values.sort_by(|a, b| b.len().cmp(&a.len()).then_with(|| a.cmp(b)));
        Self {
            values,
            complete: state.complete,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum FieldContext {
    /// Fixed serde-owned Inspection/DTO keys, including enum discriminators.
    Typed,
    /// Computed hashes copied exactly from the typed inspector result.
    Computed,
    /// Arbitrary source metadata; its keys require their own display handling.
    Metadata,
    LiteralMap,
    Hidden,
    Bytes,
}

fn field_context(parent: FieldContext, key: &str) -> FieldContext {
    if parent == FieldContext::LiteralMap {
        return FieldContext::Hidden;
    }
    if key == "bytes" {
        return FieldContext::Bytes;
    }
    if sensitive(key) {
        return FieldContext::Hidden;
    }
    if literal_map(key) {
        return FieldContext::LiteralMap;
    }
    if parent == FieldContext::Metadata {
        return FieldContext::Metadata;
    }
    match key {
        "metadata" | "source_metadata" | "remaining_contract" | "effort" | "model_map"
        | "tool_map" => FieldContext::Metadata,
        "source_digest" | "sha256" | "revision" | "digest" => FieldContext::Computed,
        _ => FieldContext::Typed,
    }
}

struct DisplayBudget {
    nodes: usize,
    text: usize,
    work: usize,
    truncated: bool,
}

impl DisplayBudget {
    fn charge(&mut self, text: &str) -> String {
        if text.len() > self.text {
            self.truncated = true;
            return String::new();
        }
        self.text -= text.len();
        text.to_owned()
    }
    fn withheld(&mut self) -> String {
        self.truncated = true;
        self.charge("[text withheld by display limit]")
    }
}

fn redact(
    value: Value,
    context: FieldContext,
    literals: &LiteralCatalog,
    budget: &mut DisplayBudget,
    depth: usize,
) -> Value {
    if budget.nodes == 0 || depth > 32 {
        return Value::String(budget.withheld());
    }
    budget.nodes -= 1;
    if context == FieldContext::Hidden {
        let reference = value.as_str().filter(|text| env_reference(text));
        return Value::String(budget.charge(reference.unwrap_or(WITHHELD)));
    }
    if context == FieldContext::Bytes {
        return Value::String(budget.charge("[file payload withheld]"));
    }
    match value {
        Value::String(text) if context == FieldContext::Computed => {
            // These are fixed-size hashes produced by the typed inspector,
            // never source-provided metadata. Retain them even when free-form
            // display text has consumed its separate allowance.
            if text.len() > budget.text {
                budget.truncated = true;
            }
            budget.text = budget.text.saturating_sub(text.len());
            Value::String(text)
        }
        Value::String(text) => Value::String(safe_text(&text, literals, budget)),
        Value::Array(values) => {
            if values.len() > 128 {
                budget.truncated = true;
            }
            Value::Array(
                values
                    .into_iter()
                    .take(128)
                    .map(|value| redact(value, context, literals, budget, depth + 1))
                    .collect(),
            )
        }
        Value::Object(values) => {
            if values.len() > 128 {
                budget.truncated = true;
            }
            let mut result = Map::new();
            for (index, (original_key, value)) in values.into_iter().take(128).enumerate() {
                // Determine semantics before choosing an output label. Typed
                // keys are never scanned/replaced; only raw metadata keys are.
                let canonical_key = canonical(&original_key);
                let child_context = canonical_key
                    .as_deref()
                    .map(|key| field_context(context, key))
                    .unwrap_or(FieldContext::Hidden);
                let key =
                    if context == FieldContext::Metadata || context == FieldContext::LiteralMap {
                        let displayed = safe_text(&original_key, literals, budget);
                        let mut label = if displayed == original_key {
                            displayed
                        } else {
                            format!("[field {index}]")
                        };
                        let mut collision = 0;
                        while result.contains_key(&label) {
                            collision += 1;
                            label = format!("[field {index}.{collision}]");
                        }
                        label
                    } else {
                        original_key
                    };
                result.insert(
                    key,
                    redact(value, child_context, literals, budget, depth + 1),
                );
            }
            Value::Object(result)
        }
        other => other,
    }
}

/// All substitutions inspect original canonical input. Inserted markers are
/// appended once and never re-enter credential matching or URL classification.
fn redact_original(
    text: &str,
    literals: &LiteralCatalog,
    limit: usize,
    work: &mut usize,
) -> Option<String> {
    fn append(output: &mut String, text: &str, limit: usize) -> Option<()> {
        if output.len().checked_add(text.len())? > limit {
            return None;
        }
        output.push_str(text);
        Some(())
    }
    let mut output = String::new();
    let mut offset = 0;
    let mut span_end = 0;
    for span in text.split_inclusive(char::is_whitespace) {
        span_end += span.len();
        if offset >= span_end {
            continue;
        }
        if let Some(index) = span.find("://")
            && span[index + 3..].contains(['@', '?', '#'])
        {
            append(&mut output, "[URL credentials withheld] ", limit)?;
            offset = span_end;
            continue;
        }
        while offset < span_end {
            let mut matched = None;
            for literal in &literals.values {
                *work = work.checked_sub(literal.len().min(text.len() - offset).max(1))?;
                if text[offset..].starts_with(literal) {
                    matched = Some(literal.len());
                    break;
                }
            }
            if let Some(length) = matched {
                append(&mut output, WITHHELD, limit)?;
                offset += length;
            } else {
                *work = work.checked_sub(1)?;
                let character = text[offset..].chars().next()?;
                append(
                    &mut output,
                    &text[offset..offset + character.len_utf8()],
                    limit,
                )?;
                offset += character.len_utf8();
            }
        }
    }
    Some(output)
}

fn safe_text(text: &str, literals: &LiteralCatalog, budget: &mut DisplayBudget) -> String {
    if !literals.complete {
        return budget.withheld();
    }
    let Some(plain) = canonical(text) else {
        return budget.withheld();
    };
    let limit = MAX_TEXT.min(budget.text);
    let Some(plain) = redact_original(&plain, literals, limit, &mut budget.work) else {
        return budget.withheld();
    };
    let scanned = orbit_tools::scan::scan_result(&plain).text;
    if scanned.len() > limit {
        return budget.withheld();
    }
    let mut rescanned = String::new();
    for span in
        scanned.split_inclusive(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '-'))
    {
        let scanned = orbit_tools::scan::scan_result(span).text;
        if rescanned.len().saturating_add(scanned.len()) > limit {
            return budget.withheld();
        }
        rescanned.push_str(&scanned);
    }
    // The shared HUD helper retains its explicit disallowed-marker policy.
    // Its assignment suffix redactor is UTF-8 safe (covered by shared tests).
    let displayed = orbit_hud::display_safe(&rescanned)
        .unwrap_or_else(|_| "[content withheld by display policy]".into());
    if displayed.len() > limit {
        return budget.withheld();
    }
    budget.charge(&displayed)
}

/// Render only inspection metadata; package bodies and raw source metadata stay
/// in the bounded, redacted JSON record rather than being printed as prose.
pub fn human_report(value: &Value) -> String {
    if value.get("command").and_then(Value::as_str) == Some("plugin help") {
        return format!(
            "{USAGE}\nManage local snapshots without executing package code. Runtime readiness remains unchecked.\n"
        );
    }
    let text = |value: &Value| value.as_str().unwrap_or("unknown").to_owned();
    if matches!(
        value["command"].as_str(),
        Some("plugin list" | "plugin enable" | "plugin disable" | "plugin remove")
    ) {
        let mut lines = vec![
            match value["command"].as_str() {
                Some("plugin enable") => "Plugin enabled in index.",
                Some("plugin disable") => "Plugin disabled in index.",
                Some("plugin remove") => {
                    "Plugin removed from index; package versions and user data retained."
                }
                _ => "Managed plugins:",
            }
            .into(),
            format!("Revision: {}", text(&value["snapshot"]["revision"])),
        ];
        if let Some(entries) = value["snapshot"]["entries"].as_array() {
            for plugin in entries.iter().take(128) {
                lines.push(format!(
                    "  {} [{}], version {}, enabled in index: {}",
                    text(&plugin["id"]["name"]),
                    text(&plugin["id"]["scope"]),
                    plugin["manifest"]["version"]
                        .as_str()
                        .unwrap_or("unspecified"),
                    plugin["enabled"].as_bool().unwrap_or(false)
                ));
            }
            if entries.is_empty() {
                lines.push("  No managed packages.".into());
            }
        }
        lines.push("Runtime readiness: unchecked; no package code was executed.".into());
        append_diagnostics(&mut lines, &value["snapshot"]["diagnostics"]);
        return human_lines(lines, value["display_truncated"].as_bool() == Some(true));
    }
    let managed = value["command"] != "plugin inspect";
    let record = if value["command"] == "plugin status" {
        &value["plugin"]
    } else if managed {
        &value["receipt"]["plugin"]
    } else {
        &value["inspection"]
    };
    let mut lines = Vec::new();
    if managed {
        if value["command"] != "plugin status" {
            lines.push(if value["receipt"]["reused"].as_bool() == Some(true) {
                "Existing immutable snapshot reused.".into()
            } else if value["command"] == "plugin upgrade" {
                "Immutable plugin snapshot upgraded.".into()
            } else {
                "Immutable plugin snapshot imported.".into()
            });
        }
        lines.push(format!("Scope: {}", text(&record["id"]["scope"])));
        lines.push(format!(
            "Enabled in index: {}",
            record["enabled"].as_bool().unwrap_or(false)
        ));
        lines.push(format!("Digest: {}", text(&record["digest"])));
        lines.push("Runtime readiness: unchecked; no package code was executed.".into());
    }
    lines.extend([
        format!("Plugin: {}", text(&record["manifest"]["name"])),
        format!("Format: {}", text(&record["source"]["format"])),
        format!(
            "Version: {}",
            record["manifest"]["version"]
                .as_str()
                .unwrap_or("unspecified")
        ),
        if managed {
            "Stored declarations; no package code was executed.".into()
        } else {
            "Inspection only; no package code was executed.".into()
        },
        "Components:".into(),
    ]);
    if let Some(components) = record["components"].as_array() {
        for component in components.iter().take(128) {
            lines.push(format!(
                "  {} ({}, {})",
                text(&component["id"]),
                text(&component["kind"]["type"]),
                text(&component["compatibility"])
            ));
        }
    }
    lines.push("Requirements:".into());
    if let Some(requirements) = record["requirements"].as_array() {
        for requirement in requirements.iter().take(128) {
            lines.push(format!(
                "  {}: {} [{}] — {}",
                text(&requirement["kind"]),
                text(&requirement["name"]),
                if requirement["satisfied"].as_bool() == Some(true) {
                    "ready"
                } else {
                    "pending"
                },
                text(&requirement["action"])
            ));
        }
    }
    append_diagnostics(&mut lines, &record["diagnostics"]);
    human_lines(lines, value["display_truncated"].as_bool() == Some(true))
}

fn append_diagnostics(lines: &mut Vec<String>, diagnostics: &Value) {
    lines.push("Diagnostics:".into());
    if let Some(diagnostics) = diagnostics.as_array() {
        for diagnostic in diagnostics.iter().take(128) {
            lines.push(format!(
                "  {} [{}]: {}",
                diagnostic["code"].as_str().unwrap_or("unknown"),
                diagnostic["severity"].as_str().unwrap_or("unknown"),
                diagnostic["message"].as_str().unwrap_or("unknown")
            ));
        }
    }
}

fn human_lines(mut lines: Vec<String>, truncated: bool) -> String {
    if truncated {
        lines.push("Display truncated; source files were not changed.".into());
    }
    let mut budget = DisplayBudget {
        nodes: 0,
        text: 64 * 1024,
        work: 1024 * 1024,
        truncated: false,
    };
    let literals = LiteralCatalog {
        values: Vec::new(),
        complete: true,
    };
    let mut output = String::new();
    for line in lines {
        let line = safe_text(&line, &literals, &mut budget);
        if output.len() + line.len() + 1 > 64 * 1024 {
            output.push_str("\n[display truncated]");
            break;
        }
        if !output.is_empty() {
            output.push('\n');
        }
        output.push_str(&line);
    }
    output.push('\n');
    output
}
