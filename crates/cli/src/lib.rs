//! ORBIT CLI — Phase E (E17).
//!
//! Command tree (DR-03 §3.2), config precedence (CLI-13), exit codes (E11xx),
//! structured JSON output (CLI-03/04), and the DR-14 authority flags +
//! confirmation banner (CLI-A1..A4).

#![deny(unsafe_code)]

use serde::{Deserialize, Serialize};

/// CLI error family (E1100-E110D).
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum CliError {
    #[error("ORBIT-E1101 cli_usage: {0}")]
    Usage(String),
    #[error("ORBIT-E1106 cli_config_invalid: {0}")]
    ConfigInvalid(String),
    #[error("ORBIT-E1109 cli_policy: {0}")]
    Policy(String),
    #[error("ORBIT-E110B cli_telemetry_denied: {0}")]
    TelemetryDenied(String),
    #[error("ORBIT-E110C cli_v0_2_only: {0}")]
    V02Only(String),
    #[error("ORBIT-E1911 confirm_required_but_non_interactive: {0}")]
    ConfirmRequired(String),
}

impl CliError {
    /// Process exit code (DR-10 §5.1 supercodes).
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::Usage(_) => 64,
            Self::ConfigInvalid(_) => 78,
            Self::Policy(_) => 93,
            Self::TelemetryDenied(_) => 96,
            Self::V02Only(_) => 97,
            Self::ConfirmRequired(_) => 93,
        }
    }

    pub fn code(&self) -> &'static str {
        match self {
            Self::Usage(_) => "E1101",
            Self::ConfigInvalid(_) => "E1106",
            Self::Policy(_) => "E1109",
            Self::TelemetryDenied(_) => "E110B",
            Self::V02Only(_) => "E110C",
            Self::ConfirmRequired(_) => "E1911",
        }
    }
}

/// The v0.1 command tree (DR-03 §3.2 — all 15 commands), plus the interactive
/// `chat` harness (v0.2-promoted: bare `orbit` and `orbit chat`).
pub const COMMANDS: &[&str] = &[
    "run",
    "plan",
    "explain",
    "trace",
    "trust",
    "registry",
    "plugin",
    "migrate",
    "list-models",
    "audit",
    "verify-ledger",
    "replay",
    "export",
    "restore",
    "version",
    "chat",
    "web",
    "serve",
    "attach",
];

/// v0.2-reserved subcommands (CLI-26: must not be silently added in v0.1).
pub const V02_COMMANDS: &[&str] = &["import", "admin"];

/// The execution mode (DR-14 §2.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExecMode {
    Guided,          // orbit run
    Auto,            // orbit run --auto
    AutoDestructive, // orbit run --auto --destructive
    Manual,          // orbit run --manual
}

/// Config layers, high → low precedence (CLI-13).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigLayer {
    CliFlag,
    Env,
    Workspace,
    User,
    System,
    Defaults,
}

/// Reserved keys that are runtime-locked (CLI-13): cannot be widened by config.
pub const RESERVED_KEYS: &[&str] = &[
    "egress.allow_host",
    "trust.roots.add_inline",
    "context.window_tokens",
    "telemetry.outbound",
];

/// The parsed CLI invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedInvocation {
    pub command: String,
    pub mode: ExecMode,
    pub grants: Vec<String>, // --grant <AuthoritySpec>
    pub confirm_token: Option<String>,
    pub json: bool,
    pub quiet: bool,
}

/// Parse argv into a typed invocation (CLI-01 single tree, CLI-16 help/version first-class).
pub fn parse_args(args: &[String]) -> Result<ParsedInvocation, CliError> {
    if args.is_empty() {
        return Err(CliError::Usage(
            "no command given; try `orbit --help` (E1101)".into(),
        ));
    }
    let command = args[0].clone();
    if matches!(command.as_str(), "serve" | "attach") {
        validate_owner_arguments(&command, args)?;
    }
    if command == "--help" || command == "-h" || command == "--version" {
        return Ok(ParsedInvocation {
            command,
            mode: ExecMode::Guided,
            grants: vec![],
            confirm_token: None,
            json: false,
            quiet: false,
        });
    }
    if !COMMANDS.contains(&command.as_str()) {
        if V02_COMMANDS.contains(&command.as_str()) {
            return Err(CliError::V02Only(format!(
                "`orbit {command}` is v0.2-reserved (E110C)"
            )));
        }
        return Err(CliError::Usage(format!(
            "unknown command `{command}` (E1101)"
        )));
    }

    let mut mode = ExecMode::Guided;
    let mut grants = Vec::new();
    let mut confirm_token = None;
    let mut json = false;
    let mut quiet = false;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--auto" => mode = ExecMode::Auto,
            "--destructive" => {
                if mode == ExecMode::Auto {
                    mode = ExecMode::AutoDestructive;
                } else {
                    return Err(CliError::Usage(
                        "--destructive requires --auto (E1101)".into(),
                    ));
                }
            }
            "--manual" => mode = ExecMode::Manual,
            "--grant" => {
                i += 1;
                let spec = args.get(i).ok_or_else(|| {
                    CliError::Usage("--grant requires <AuthoritySpec> (E1101)".into())
                })?;
                grants.push(spec.clone());
            }
            "--confirm-cost" => {
                i += 1;
                confirm_token = args.get(i).cloned();
            }
            "--json" => json = true,
            "--quiet" => quiet = true,
            other
                if matches!(command.as_str(), "serve" | "attach")
                    && matches!(
                        other,
                        "--socket"
                            | "--home"
                            | "--session"
                            | "--resume"
                            | "--model"
                            | "--provider"
                            | "--gate"
                            | "--effort"
                            | "--permission-mode"
                            | "--allowedTools"
                            | "--disallowedTools"
                    ) =>
            {
                i += 1;
            }
            other
                if matches!(command.as_str(), "serve" | "attach")
                    && matches!(
                        other,
                        "--continue"
                            | "--fork-session"
                            | "--auto-tools"
                            | "--bare"
                            | "--status"
                            | "--logs"
                            | "--cancel"
                            | "--stop"
                    ) => {}
            other if other.starts_with("--") => {
                return Err(CliError::Usage(format!("unknown flag {other} (E1101)")));
            }
            _ => { /* positional arg; ignored for v0.1 parse */ }
        }
        i += 1;
    }
    Ok(ParsedInvocation {
        command,
        mode,
        grants,
        confirm_token,
        json,
        quiet,
    })
}

/// Config resolution: strict precedence (CLI-13). Later layers cannot override
/// reserved keys.
pub fn resolve_config(key: &str, layers: &[(ConfigLayer, Option<&str>)]) -> Option<String> {
    for (layer, value) in layers {
        if let Some(v) = value {
            // Reserved keys are runtime-locked: config layers below CliFlag cannot set them.
            if RESERVED_KEYS.contains(&key) && *layer != ConfigLayer::CliFlag {
                return None;
            }
            return Some(v.to_string());
        }
    }
    None
}

/// The telemetry gate (CLI-07, DR-13 §6 owner): outbound telemetry is refused.
pub fn check_telemetry(config_telemetry: &str) -> Result<(), CliError> {
    if config_telemetry != "off" {
        return Err(CliError::TelemetryDenied(
            "v0.1 has no outbound telemetry; telemetry.outbound must be `off` (E110B)".into(),
        ));
    }
    Ok(())
}

/// Structured JSON output envelope (CLI-03/04: stdout=data).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CliOutput {
    pub schema_version: String, // "orbit.cli/v1"
    pub command: String,
    pub status: String,
    pub data: serde_json::Value,
}

impl CliOutput {
    pub fn ok(command: &str, data: serde_json::Value) -> Self {
        Self {
            schema_version: "orbit.cli/v1".into(),
            command: command.into(),
            status: "ok".into(),
            data,
        }
    }
}

/// DR-14 confirmation banner (CLI-A2). In auto mode no per-action prompt is
/// shown; a widening still requires the operator's up-front consent.
pub fn confirmation_banner(spec: &str, mode: ExecMode) -> String {
    match mode {
        ExecMode::Auto | ExecMode::AutoDestructive => {
            format!("[auto] granted by up-front consent; widening flag {spec} Ledger-recorded")
        }
        ExecMode::Manual => format!("[manual] confirm widening: {spec} (yes/deny)"),
        ExecMode::Guided => {
            format!("[guided] proposed widening: {spec} — confirm with `yes` or --confirm-cost")
        }
    }
}

/// Build facts and the availability of evidence bound to this executable.
/// Historical checkout evidence cannot establish provenance for installed bytes.
pub fn version_evidence(version: &str, commit_sha: &str) -> CliOutput {
    CliOutput::ok(
        "version",
        serde_json::json!({
            "version": version,
            "commit_sha": commit_sha,
            "build": {
                "toolchain": env!("ORBIT_BUILD_RUSTC"),
                "minimum_rust_version": env!("CARGO_PKG_RUST_VERSION"),
                "edition": "2024",
                "target": std::env::consts::ARCH,
                "profile": if cfg!(debug_assertions) { "debug" } else { "release" },
            },
            "evidence": {
                "sbom_sha256": "",
                "provenance_sha256": "",
                "reproducibility_sha256": "",
                "signature_key": "",
                "bundle_ready": false,
                "status": "unavailable",
                "reason": "This build includes no release evidence bound to its executable bytes"
            }
        }),
    )
}

/// A monotonic-ish timestamp string for session metadata (std-only, no chrono
/// dep): seconds since the Unix epoch. Good enough for ordering/sorting.
pub fn timestamp_now() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    secs.to_string()
}

// ── Harness modules (shared by the CLI binary, the TUI worker, the Go
// bridge, and orbit-web) ────────────────────────────────────────────────
// Extracted from main.rs so the browser front-end (crates/web) can reuse
// run_turn + tool runtime + sessions verbatim (docs/browser-harness.md).

/// Validate local owner arguments before acquiring or changing a session.
pub fn validate_owner_arguments(command: &str, args: &[String]) -> Result<(), CliError> {
    let serve_values = [
        "--session",
        "--resume",
        "--model",
        "--provider",
        "--effort",
        "--permission-mode",
        "--allowedTools",
        "--disallowedTools",
    ];
    let mut seen = std::collections::HashSet::new();
    let mut found_command = false;
    let mut index = 0;
    while index < args.len() {
        let argument = args[index].as_str();
        if argument == command && !found_command {
            found_command = true;
            index += 1;
            continue;
        }
        let takes_value = matches!(argument, "--socket" | "--home")
            || (command == "serve" && serve_values.contains(&argument));
        let flag = match command {
            "serve" => matches!(
                argument,
                "--continue" | "--fork-session" | "--auto-tools" | "--bare"
            ),
            "attach" => matches!(argument, "--status" | "--logs" | "--cancel" | "--stop"),
            _ => false,
        };
        if !takes_value && !flag {
            return Err(CliError::Usage(format!(
                "unexpected {command} argument {argument}"
            )));
        }
        if !seen.insert(argument) {
            return Err(CliError::Usage(format!("duplicate {argument}")));
        }
        if takes_value {
            let value = args.get(index + 1).filter(|value| !value.starts_with('-'));
            if value.is_none_or(|value| {
                value.is_empty() && !matches!(argument, "--allowedTools" | "--disallowedTools")
            }) {
                return Err(CliError::Usage(format!("{argument} requires a value")));
            }
            index += 1;
        }
        index += 1;
    }
    if !found_command || !seen.contains("--socket") {
        return Err(CliError::Usage(format!(
            "{command} requires --socket <private Unix socket path>"
        )));
    }
    if seen.contains("--resume") && seen.contains("--continue") {
        return Err(CliError::Usage("choose --resume or --continue".into()));
    }
    if seen.contains("--session")
        && ["--resume", "--continue", "--fork-session"]
            .iter()
            .any(|flag| seen.contains(flag))
    {
        return Err(CliError::Usage(
            "--session names a new session; use --resume to reopen one".into(),
        ));
    }
    if command == "attach"
        && ["--status", "--logs", "--cancel", "--stop"]
            .iter()
            .filter(|flag| seen.contains(**flag))
            .count()
            > 1
    {
        return Err(CliError::Usage("choose one attach control command".into()));
    }
    Ok(())
}

pub mod attach;
pub mod cli_release_commands;
pub mod config;
pub mod context_history;
#[allow(unsafe_code)]
pub mod customization;
pub mod customization_host;
pub mod daemon;
pub mod doctor;
pub mod plain_input;
pub mod profile_commands;
mod recovery;
pub mod recovery_commands;
// The stdio backend confines Unix descriptor/signal operations to reviewed helpers.
#[allow(unsafe_code)]
pub mod lsp;
pub mod model_limits;
pub mod mods;
pub mod onboarding;
#[allow(unsafe_code)]
pub mod pentest;
pub mod permissions;
pub mod phase_routing;
pub mod plugin_commands;
pub mod plugin_content;
pub mod presets;
pub mod provider_discovery;
pub mod provider_policies;
pub mod session_accounting;
pub mod sessions;
#[allow(unsafe_code)]
pub mod setup;
#[allow(unsafe_code)]
pub mod signed_packages;
pub mod tool_runtime;
pub mod tools;
pub mod tui_worker;

use std::path::Path;

/// User-qualified identities and saved raw identities have different grammars.
pub fn resolve_selected_model(
    config: &config::ProvidersConfig,
    spec: &str,
    provider_hint: Option<&str>,
    saved_identity: bool,
) -> Result<phase_routing::ResolvedModel, String> {
    let qualified = config
        .provider
        .iter()
        .any(|provider| spec.starts_with(&format!("{}/", provider.name)));
    let resolved = phase_routing::resolve_model(
        config,
        spec,
        if saved_identity || !qualified {
            provider_hint
        } else {
            None
        },
    )?;
    if provider_hint.is_some_and(|hint| hint != resolved.provider_id) {
        return Err("selected provider conflicts with qualified model identity".into());
    }
    Ok(resolved)
}

/// Resolve declared models exactly. The legacy empty-config mode requires an
/// explicit endpoint, so it can never fall through to an ambient default URL.
pub fn checked_model_turn(
    home: &Path,
    spec: &str,
    provider_hint: Option<&str>,
    gate_override: Option<&str>,
    saved_identity: bool,
) -> Result<orbit_engine::TurnConfig, String> {
    let config = config::ProvidersConfig::load(home)?;
    if !config.provider.is_empty() {
        phase_routing::validate_settings(&config, &config.phase_settings())?;
        let resolved = resolve_selected_model(&config, spec, provider_hint, saved_identity)?;
        if let Some(gate) = gate_override {
            let supplied =
                url::Url::parse(gate).map_err(|_| "invalid explicit provider endpoint")?;
            let declared = url::Url::parse(&resolved.url)
                .map_err(|_| "invalid configured provider endpoint")?;
            if supplied.as_str().trim_end_matches('/') != declared.as_str().trim_end_matches('/') {
                return Err(
                    "explicit endpoint differs from the selected configured provider".into(),
                );
            }
        }
        return resolved.turn_config(None);
    }
    let gate = gate_override.ok_or(
        "configure a provider/model with orbit setup, or supply an explicit --gate endpoint",
    )?;
    config::validate_provider_endpoint(gate)?;
    if spec.is_empty() || spec.len() > 512 || spec.chars().any(char::is_control) {
        return Err("model identity must be nonempty printable text up to 512 bytes".into());
    }
    let turn = engine_turn_config_from(
        &config,
        provider_hint.unwrap_or("configured-gateway"),
        gate,
        spec,
        None,
        None,
    );
    turn.validate_effort()?;
    Ok(turn)
}

/// The same checked decision powers offline preview and every live caller.
/// Returning a per-turn config leaves the session's base identity and effort intact.
pub fn try_phase_turn_config(
    home: &Path,
    base: &orbit_engine::TurnConfig,
    prompt: &str,
    origin: phase_routing::SelectionOrigin,
) -> Result<
    (
        orbit_engine::TurnConfig,
        Option<phase_routing::RouteDecision>,
    ),
    String,
> {
    let config = config::ProvidersConfig::load(home)?;
    if config.provider.is_empty() {
        if config.phase_settings().enabled() || config.routing_table().enabled() {
            return Err("routing targets require declared providers and models".into());
        }
        if prompt.len() > orbit_engine::routing::MAX_ROUTING_PROMPT_BYTES {
            return Err("routing prompt exceeds 256 KiB".into());
        }
        base.validate_effort()?;
        return Ok((base.clone(), None));
    }
    let model = phase_routing::resolve_model(&config, &base.model, Some(&base.provider_id))?;
    let decision = phase_routing::preview(
        &config,
        &config.phase_settings(),
        &model,
        origin,
        prompt,
        None,
    )?;
    let turn = decision.model.turn_config(Some(base))?;
    Ok((turn, Some(decision)))
}

pub fn startup_selection_origin(
    flag: bool,
    environment: bool,
    saved: Option<&sessions::SessionFile>,
    has_role: bool,
) -> phase_routing::SelectionOrigin {
    use phase_routing::SelectionOrigin as O;
    if flag {
        O::Flag
    } else if environment {
        O::Environment
    } else if saved.is_some() {
        sessions::model_origin(saved)
    } else if has_role {
        O::Role
    } else {
        O::Default
    }
}

/// Offline routing operations shared by the command line and live session controls.
pub fn route_command(
    home: &Path,
    words: &[String],
    base: Option<&orbit_engine::TurnConfig>,
    origin: phase_routing::SelectionOrigin,
) -> Result<serde_json::Value, String> {
    use orbit_engine::routing::{Difficulty as D, TaskPhase as P};
    use phase_routing::RouteMutation as M;
    let config = config::ProvidersConfig::load(home)?;
    let settings = config.phase_settings();
    let sub = words.first().map(String::as_str).unwrap_or("status");
    let phase = |value: &str| -> Result<P, String> {
        serde_json::from_value(serde_json::json!(value)).map_err(|_| "unknown task phase".into())
    };
    let difficulty = |value: &str| -> Result<D, String> {
        match value {
            "default" | "normal" => Ok(D::Normal),
            "easy" => Ok(D::Easy),
            "hard" => Ok(D::Hard),
            _ => Err("difficulty must be easy, hard or default".into()),
        }
    };
    if sub == "status" {
        if words.len() > 1 {
            return Err("route status takes no operands".into());
        }
        phase_routing::validate_settings(&config, &settings)?;
        return Ok(
            serde_json::json!({"command":"route status","status":"ok","enabled":settings.enabled()||config.routing_table().enabled(),
            "phases":settings.phases,"phase_keywords":settings.phase_keywords,"hard":config.routing.hard,"easy":config.routing.easy,
            "selection_origin":origin,"pinned":origin.is_explicit(),"hint":"route setup --easy PROVIDER/MODEL --hard PROVIDER/MODEL; /route auto clears a session pin"}),
        );
    }
    if sub == "test" {
        let prompt = words.get(1..).unwrap_or_default().join(" ");
        if prompt.is_empty() {
            return Err("usage: route test PROMPT".into());
        }
        let model = if let Some(base) = base {
            phase_routing::resolve_model(&config, &base.model, Some(&base.provider_id))?
        } else {
            let spec = if !config.roles.main.is_empty() {
                config.roles.main.clone()
            } else {
                config
                    .provider
                    .iter()
                    .find_map(|provider| {
                        provider
                            .models
                            .first()
                            .map(|model| format!("{}/{}", provider.name, model.id))
                    })
                    .ok_or("configure a provider/model before preview")?
            };
            phase_routing::resolve_model(&config, &spec, None)?
        };
        let decision = phase_routing::preview(&config, &settings, &model, origin, &prompt, None)?;
        let mut value =
            serde_json::to_value(&decision).map_err(|_| "cannot encode routing decision")?;
        value["command"] = serde_json::json!("route test");
        value["status"] = serde_json::json!("ok");
        value["model"] = serde_json::json!(decision.model.qualified());
        value["prompt_chars"] = serde_json::json!(prompt.chars().count());
        return Ok(display_safe_json(value));
    }
    let mutation=match sub {
        "setup"=>{
            let mut easy=None;let mut hard=None;let mut index=1;
            while index<words.len() {
                let target=match words[index].as_str(){"--easy"=>&mut easy,"--hard"=>&mut hard,_=>return Err("usage: route setup --easy PROVIDER/MODEL --hard PROVIDER/MODEL".into())};
                if target.is_some(){return Err("duplicate route setup option".into());}
                *target=Some(words.get(index+1).filter(|value|!value.starts_with("--")).ok_or("route setup option requires a model")?.clone());index+=2;
            }
            M::Setup{easy:easy.ok_or("route setup requires --easy")?,hard:hard.ok_or("route setup requires --hard")?}
        }
        "set"=>match words.len() {
            3=>M::Set{phase:phase(&words[1])?,difficulty:None,model:words[2].clone()},
            4=>M::Set{phase:phase(&words[1])?,difficulty:Some(difficulty(&words[2])?),model:words[3].clone()},
            _=>return Err("usage: route set PHASE [easy|hard|default] PROVIDER/MODEL".into()),
        },
        "reset"=>{if words.len()>2{return Err("usage: route reset [PHASE]".into());}M::Reset{phase:words.get(1).map(|value|phase(value)).transpose()?}},
        "hard"|"easy"=>{if words.len()>2{return Err("usage: route hard|easy MODEL|off".into());}
            M::LegacyTarget{difficulty:difficulty(sub)?,model:words.get(1).filter(|value|value.as_str()!="off").cloned().unwrap_or_default()}},
        "off"=>{if words.len()!=1{return Err("route off takes no operands".into());}M::Disable},
        "keywords"=>match words.get(1).map(String::as_str) {
            Some("clear") if words.len()==2=>M::ClearKeywords,
            Some(action @ ("add"|"remove")) if words.len()>=4=>M::EditKeywords{difficulty:difficulty(&words[2])?,word:words[3..].join(" "),remove:action=="remove"},
            _=>return Err("usage: route keywords clear | add|remove easy|hard WORD".into()),
        },
        "auto"=>return Err("use /route auto in a live session, or orbit route auto --session ID".into()),
        _=>return Err("unknown route operation (status, test, setup, set, reset, hard, easy, off, keywords, auto)".into()),
    };
    let updated = config::ProvidersConfig::update_atomic(home, |raw| {
        phase_routing::config_candidate(raw, mutation)
    })?;
    Ok(
        serde_json::json!({"command":format!("route {sub}"),"status":"ok","enabled":updated.phase_settings().enabled() || updated.routing_table().enabled(),"phases":updated.routing.phases,"hard":updated.routing.hard,"easy":updated.routing.easy}),
    )
}

pub fn display_safe_json(value: serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::String(text) => serde_json::Value::String(daemon::scan_display(&text)),
        serde_json::Value::Array(values) => {
            serde_json::Value::Array(values.into_iter().map(display_safe_json).collect())
        }
        serde_json::Value::Object(values) => serde_json::Value::Object(
            values
                .into_iter()
                .map(|(key, value)| (key, display_safe_json(value)))
                .collect(),
        ),
        other => other,
    }
}

// The dispatch core moved to orbit-engine in phase 2 (one loop, one
// place). These re-exports keep every existing caller — the REPL, the
// TUI worker, the web bridge, the Go bridge, `orbit ask` — on the same
// tested core without churn; front-ends migrate to the engine's event
// protocol at their own pace and the wrappers fall away.
pub use orbit_engine::PendingToolCall;
pub use orbit_engine::TurnOutcome;

/// Resolve the engine's TurnConfig from the CLI's config surface.
/// The per-model output limit comes from providers.toml (defect fix:
/// the old hard 2,048 silently truncated long answers).
pub fn engine_turn_config(
    home: &Path,
    provider_id: &str,
    gate: &str,
    model: &str,
    credential_env: Option<&str>,
    pricing: Option<crate::config::Pricing>,
) -> orbit_engine::TurnConfig {
    let cfg = crate::config::ProvidersConfig::load(home).unwrap_or_default();
    engine_turn_config_from(&cfg, provider_id, gate, model, credential_env, pricing)
}

fn engine_turn_config_from(
    cfg: &crate::config::ProvidersConfig,
    provider_id: &str,
    gate: &str,
    model: &str,
    credential_env: Option<&str>,
    pricing: Option<crate::config::Pricing>,
) -> orbit_engine::TurnConfig {
    let entry = cfg.model_entry(provider_id, model).map(|(_, entry)| entry);
    let max_output_tokens = entry.and_then(|m| m.max_output_tokens).unwrap_or(32_000) as u64;
    // E8: sampling per model — only what providers.toml sets is sent.
    let sampling = entry
        .and_then(|m| m.sampling.as_ref())
        .map(|s| (s.temperature, s.top_p));
    // The provider kind selects the adapter (anthropic / ollama /
    // openai-compatible). Resolved from the provider entry owning this
    // model; the fallback chain covers a model with no declared owner.
    let kind = cfg
        .model_entry(provider_id, model)
        .map(|(p, _)| orbit_engine::dispatch::ProviderKind::from_config(&p.kind))
        .unwrap_or_default();
    orbit_engine::TurnConfig {
        provider_id: provider_id.to_string(),
        gate: gate.to_string(),
        model: model.to_string(),
        kind,
        credential_env: credential_env.map(str::to_string).or_else(|| {
            cfg.provider
                .is_empty()
                .then(legacy_gate_credential_env)
                .flatten()
        }),
        pricing: pricing.map(std::convert::From::from),
        max_output_tokens,
        sampling,
        effort: entry.and_then(|m| m.default_effort.clone()),
        supported_efforts: entry.and_then(|m| m.supported_efforts.clone()),
        first_byte_timeout_ms: entry.and_then(|m| m.first_byte_timeout_ms),
        idle_timeout_ms: entry.and_then(|m| m.idle_timeout_ms),
    }
}

pub(crate) fn legacy_gate_credential_env() -> Option<String> {
    let value = std::env::var_os("ORBIT_GATE_TOKEN")?;
    let secret = orbit_adapter::SecretBytes::new(value.into_encoded_bytes());
    (!secret.is_empty()).then(|| "ORBIT_GATE_TOKEN".to_owned())
}

/// Checked construction used at every runtime selection boundary. The old
/// builder remains available for callers that already checked configuration.
pub fn try_engine_turn_config(
    home: &Path,
    provider_id: &str,
    gate: &str,
    model: &str,
    credential_env: Option<&str>,
    pricing: Option<crate::config::Pricing>,
) -> Result<orbit_engine::TurnConfig, String> {
    let cfg = crate::config::ProvidersConfig::load(home)?;
    let config = engine_turn_config_from(&cfg, provider_id, gate, model, credential_env, pricing);
    config.validate_effort()?;
    Ok(config)
}

pub fn parse_effort_setting(value: &str) -> Result<orbit_adapter::types::EffortSetting, String> {
    use orbit_adapter::types::{EffortSetting, EffortValue};
    if value.starts_with('"') {
        if value.trim() != value {
            return Err("quoted effort levels must not have surrounding whitespace".into());
        }
        let level: String = serde_json::from_str(value)
            .map_err(|error| format!("effort must be a complete JSON string: {error}"))?;
        let choice = EffortValue::Level(level);
        choice.validate()?;
        return Ok(EffortSetting::Value(choice));
    }
    let choice = match value {
        "default" => return Ok(EffortSetting::Default),
        "true" => EffortValue::Bool(true),
        "false" => EffortValue::Bool(false),
        value => EffortValue::Level(value.to_owned()),
    };
    choice.validate()?;
    Ok(EffortSetting::Value(choice))
}

/// Validate a candidate before changing the live configuration.
pub fn apply_effort_setting(
    home: &Path,
    config: &mut orbit_engine::TurnConfig,
    choice: &orbit_adapter::types::EffortSetting,
) -> Result<(), String> {
    use orbit_adapter::types::EffortSetting;
    let models = crate::config::ProvidersConfig::load(home)?;
    let entry = models
        .model_entry(&config.provider_id, &config.model)
        .map(|(_, m)| m);
    let mut candidate = config.clone();
    candidate.supported_efforts = entry.and_then(|m| m.supported_efforts.clone());
    candidate.effort = match choice {
        EffortSetting::Default => entry.and_then(|m| m.default_effort.clone()),
        EffortSetting::Value(value) => Some(value.clone()),
    };
    candidate.validate_effort()?;
    *config = candidate;
    Ok(())
}

pub fn effort_status(_home: &Path, config: &orbit_engine::TurnConfig) -> String {
    let label = |value: &orbit_adapter::types::EffortValue| {
        serde_json::to_string(value).expect("effort values serialize as JSON literals")
    };
    let request = config
        .effort
        .as_ref()
        .map(label)
        .unwrap_or_else(|| "provider default (omitted)".into());
    let choices = match &config.supported_efforts {
        None => "unknown.\nDeclare supported_efforts before selecting a value".into(),
        Some(values) if values.is_empty() => "unsupported (default only)".into(),
        Some(values) => values.iter().map(label).collect::<Vec<_>>().join(", "),
    };
    format!(
        "Configured effort for {}/{}: {request}\nSupported: {choices}.\nReset: /effort default restores the model default.",
        config.provider_id, config.model
    )
}

/// The model's context window from providers.toml, for the engine's
/// auto-compaction threshold (None = compaction never triggers).
pub fn context_window_for(home: &Path, model: &str) -> Option<u64> {
    crate::config::ProvidersConfig::load(home)
        .ok()
        .and_then(|c| c.context_window_for(model))
}

/// Resolve context limits by the exact provider/raw-model pair of this turn.
pub fn context_window_for_turn(home: &Path, turn: &orbit_engine::TurnConfig) -> Option<u64> {
    config::ProvidersConfig::load(home).ok().and_then(|config| {
        config
            .model_entry(&turn.provider_id, &turn.model)
            .and_then(|(_, model)| model.context_window)
    })
}

/// Resolve one task role to a full TurnConfig. The role's model may live
/// on a different provider than the session's (a cheap explore model on
/// Ollama while the main conversation runs Anthropic), so the gate,
/// kind, credential and pricing all come from the role's own provider.
/// An unset role retains the base config; invalid declared targets are refused —
/// the caller's session model keeps serving that task.
/// Resolve a routed turn's TurnConfig, the routing sibling of
/// [`role_turn_config`]. Returns `(config, decision)`: when routing is
/// armed and the decision's phase has a target, the config points at
/// that model (gate/kind/credential/pricing from its own provider);
/// otherwise the base config comes back untouched. Callers record the
/// decision when the model actually changed.
pub fn routed_turn_config(
    home: &Path,
    base: &orbit_engine::TurnConfig,
    prompt: &str,
    session_id: &str,
) -> (
    orbit_engine::TurnConfig,
    orbit_engine::routing::RoutingDecision,
) {
    try_routed_turn_config(home, base, prompt, session_id).unwrap_or_else(|_| {
        (
            base.clone(),
            orbit_engine::routing::RoutingDecision {
                phase: orbit_engine::routing::RoutingPhase::Main,
                matched: Vec::new(),
            },
        )
    })
}

fn routed_turn_config_from(
    home: &Path,
    base: &orbit_engine::TurnConfig,
    prompt: &str,
    session_id: &str,
    cfg: &crate::config::ProvidersConfig,
) -> (
    orbit_engine::TurnConfig,
    orbit_engine::routing::RoutingDecision,
) {
    use orbit_engine::routing as r;
    let table = cfg.routing_table();
    let decision = r::classify(&table, prompt);
    let target = match decision.phase {
        r::RoutingPhase::Hard => table.hard.clone(),
        r::RoutingPhase::Easy => table.easy.clone(),
        r::RoutingPhase::Main => String::new(),
    };
    if target.is_empty() {
        return (base.clone(), decision);
    }
    // Explicit model choice wins over routing: the caller passes a
    // base whose model came from --model / ORBIT_MODEL / /model, and
    // those mean "use exactly this". Detect via roles.main: when the
    // base model equals the configured main (or the fallback first
    // model), no explicit choice is in force.
    let explicit = explicit_model_in_force(cfg, &base.model);
    if explicit {
        return (base.clone(), decision);
    }
    let Some((provider, entry)) = cfg.model_entry_for_spec(&target) else {
        return (base.clone(), decision);
    };
    let model = entry.id.clone();
    let mut out = base.clone();
    out.provider_id = provider.name.clone();
    out.gate = provider.url.clone();
    out.model = model.clone();
    out.kind = orbit_engine::dispatch::ProviderKind::from_config(&provider.kind);
    out.credential_env = provider.env.clone().filter(|s| !s.trim().is_empty());
    out.pricing = Some(entry.pricing.into());
    out.max_output_tokens = entry.max_output_tokens.unwrap_or(32_000) as u64;
    out.sampling = entry.sampling.as_ref().map(|s| (s.temperature, s.top_p));
    if out.provider_id != base.provider_id || out.model != base.model {
        let entry = cfg
            .model_entry(&out.provider_id, &out.model)
            .map(|(_, m)| m);
        out.effort = entry.and_then(|m| m.default_effort.clone());
        out.supported_efforts = entry.and_then(|m| m.supported_efforts.clone());
    }
    // Routing is observability, not authority: record the decision
    // next to the session (same pattern as egress grants).
    r::record_decision(
        home,
        session_id,
        &base.model,
        &out.model,
        decision.phase,
        &decision.matched,
    );
    (out, decision)
}

pub fn try_routed_turn_config(
    home: &Path,
    base: &orbit_engine::TurnConfig,
    prompt: &str,
    session_id: &str,
) -> Result<
    (
        orbit_engine::TurnConfig,
        orbit_engine::routing::RoutingDecision,
    ),
    String,
> {
    let cfg = crate::config::ProvidersConfig::load(home)?;
    let (mut config, decision) = routed_turn_config_from(home, base, prompt, session_id, &cfg);
    config.supported_efforts = cfg
        .model_entry(&config.provider_id, &config.model)
        .and_then(|(_, entry)| entry.supported_efforts.clone());
    config.validate_effort()?;
    Ok((config, decision))
}

/// Whether an explicit model choice (a flag, env or /model) is in
/// force, routing must not override. The base model differing from
/// both roles.main and the first configured model is the fingerprint
/// of an explicit choice.
fn explicit_model_in_force(cfg: &crate::config::ProvidersConfig, base_model: &str) -> bool {
    if std::env::var("ORBIT_MODEL").is_ok() || std::env::var("ORBIT_ACTIVE_MODEL").is_ok() {
        return true;
    }
    let main = cfg
        .model_entry_for_spec(&cfg.roles.main)
        .map(|(_, entry)| entry.id.as_str())
        .unwrap_or(&cfg.roles.main);
    if !main.is_empty() && base_model == main {
        return false; // the configured default — routing may act
    }
    // No roles.main: the fallback picks the first configured model.
    let first = cfg
        .provider
        .iter()
        .flat_map(|p| p.models.iter().map(|m| m.id.as_str()))
        .next()
        .unwrap_or("");
    base_model != first
}

pub fn role_turn_config(
    home: &Path,
    base: &orbit_engine::TurnConfig,
    role: &str,
) -> orbit_engine::TurnConfig {
    try_role_turn_config(home, base, role).unwrap_or_else(|_| base.clone())
}

pub fn try_role_turn_config(
    home: &Path,
    base: &orbit_engine::TurnConfig,
    role: &str,
) -> Result<orbit_engine::TurnConfig, String> {
    let config = config::ProvidersConfig::load(home)?;
    phase_routing::validate_settings(&config, &config.phase_settings())?;
    let selected = config.roles.get(role).filter(|spec| !spec.is_empty());
    if let Some(spec) = selected {
        return phase_routing::resolve_model(&config, spec, None)?.turn_config(Some(base));
    }
    if config.provider.is_empty() {
        base.validate_effort()?;
        return Ok(base.clone());
    }
    phase_routing::resolve_model(&config, &base.model, Some(&base.provider_id))?
        .turn_config(Some(base))
}

/// An admitted single provider round with its local context approximation and
/// actionable notices. No returned tool proposal is executed by this API.
#[derive(Debug, Clone)]
pub struct DetailedTurnOutcome {
    pub outcome: TurnOutcome,
    pub estimate: orbit_engine::context_budget::RequestEstimate,
    pub context_notices: Vec<String>,
}

/// Keep policy notices and any completed measurement when local admission or
/// provider dispatch fails. An estimate does not imply admission or egress.
#[derive(Debug, Clone)]
pub struct DetailedTurnFailure {
    pub code: &'static str,
    pub message: String,
    pub context_notices: Vec<String>,
    pub estimate: Option<Box<orbit_engine::context_budget::RequestEstimate>>,
}

fn append_unknown_media_notice(
    notices: &mut Vec<String>,
    estimate: Option<&orbit_engine::context_budget::RequestEstimate>,
) {
    if estimate.is_some_and(|estimate| {
        estimate.status == orbit_engine::context_budget::EstimateStatus::UnknownMedia
    }) {
        notices.push(
            "Media or opaque request cost is unknown; provider capacity is unverified.".into(),
        );
    }
}

/// Run one prompt through the configured gateway via the four-gate async
/// dispatch pipeline. This compatibility API returns one round and its tool
/// proposals; it never executes them or invokes a summarizer.
///
/// - `gate` / `model`: resolved by the caller (flags → env → defaults).
/// - `messages`: `Some(transcript)` for multi-turn chat, `None` for the
///   single-turn `ask` contract.
/// - `observer`: called per streamed event (live TextDelta rendering);
///   `None` = buffered output only.
#[allow(clippy::too_many_arguments)]
pub fn run_turn(
    home: &Path,
    provider_id: &str,
    gate: &str,
    model: &str,
    credential_env: Option<&str>,
    pricing: Option<crate::config::Pricing>,
    prompt: &str,
    messages: Option<Vec<orbit_adapter::types::ChatMessage>>,
    observer: orbit_provider_http::stream::StreamObserver<'_>,
    cancel: orbit_provider_http::CancelToken,
) -> Result<TurnOutcome, (&'static str, String)> {
    run_turn_with_tools(
        home,
        provider_id,
        gate,
        model,
        credential_env,
        pricing,
        prompt,
        messages,
        observer,
        cancel,
        tools::tool_definitions(),
        &format!("ask-{}", ulid::Ulid::new()),
    )
}

/// `run_turn` with an explicit tool set. Detailed policy notices are available
/// through `run_turn_with_tools_detailed`; the legacy result remains unchanged.
#[allow(clippy::too_many_arguments)]
pub fn run_turn_with_tools(
    home: &Path,
    provider_id: &str,
    gate: &str,
    model: &str,
    credential_env: Option<&str>,
    pricing: Option<crate::config::Pricing>,
    prompt: &str,
    messages: Option<Vec<orbit_adapter::types::ChatMessage>>,
    observer: orbit_provider_http::stream::StreamObserver<'_>,
    cancel: orbit_provider_http::CancelToken,
    tools: Vec<orbit_adapter::types::ToolDefinition>,
    session_id: &str,
) -> Result<TurnOutcome, (&'static str, String)> {
    run_turn_with_tools_detailed(
        home,
        provider_id,
        gate,
        model,
        credential_env,
        pricing,
        prompt,
        messages,
        observer,
        cancel,
        tools,
        session_id,
    )
    .map(|result| result.outcome)
    .map_err(|error| (error.code, error.message))
}

/// The selected-only detailed form of `run_turn`. Its unused compaction role is
/// neither resolved nor dispatched.
#[allow(clippy::too_many_arguments)]
pub fn run_turn_detailed(
    home: &Path,
    provider_id: &str,
    gate: &str,
    model: &str,
    credential_env: Option<&str>,
    pricing: Option<crate::config::Pricing>,
    prompt: &str,
    messages: Option<Vec<orbit_adapter::types::ChatMessage>>,
    observer: orbit_provider_http::stream::StreamObserver<'_>,
    cancel: orbit_provider_http::CancelToken,
) -> Result<DetailedTurnOutcome, DetailedTurnFailure> {
    run_turn_with_tools_detailed(
        home,
        provider_id,
        gate,
        model,
        credential_env,
        pricing,
        prompt,
        messages,
        observer,
        cancel,
        tools::tool_definitions(),
        &format!("ask-{}", ulid::Ulid::new()),
    )
}

/// Resolve the final selected configuration, admit its exact immutable request,
/// then make one dispatch. Supplied history and returned tool calls remain data.
#[allow(clippy::too_many_arguments)]
pub fn run_turn_with_tools_detailed(
    home: &Path,
    provider_id: &str,
    gate: &str,
    model: &str,
    credential_env: Option<&str>,
    pricing: Option<crate::config::Pricing>,
    prompt: &str,
    messages: Option<Vec<orbit_adapter::types::ChatMessage>>,
    observer: orbit_provider_http::stream::StreamObserver<'_>,
    cancel: orbit_provider_http::CancelToken,
    tools: Vec<orbit_adapter::types::ToolDefinition>,
    session_id: &str,
) -> Result<DetailedTurnOutcome, DetailedTurnFailure> {
    let config = try_engine_turn_config(home, provider_id, gate, model, credential_env, pricing)
        .map_err(|message| DetailedTurnFailure {
            code: "E1106",
            message,
            context_notices: Vec::new(),
            estimate: None,
        })?;
    let now_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| DetailedTurnFailure {
            code: "ORBIT-E0413",
            message: model_limits::BudgetError::ObservationTimeUnavailable.to_string(),
            context_notices: Vec::new(),
            estimate: None,
        })?
        .as_secs();
    let report =
        model_limits::resolve_turn_budget_detailed(home, &config, now_unix).map_err(|error| {
            DetailedTurnFailure {
                code: "ORBIT-E0413",
                message: error.to_string(),
                context_notices: Vec::new(),
                estimate: None,
            }
        })?;
    let mut context_notices: Vec<_> = report
        .notices
        .iter()
        .map(|notice| model_limits::turn_budget_notice("Selected", notice))
        .collect();
    let result = orbit_engine::run_budgeted_dispatch(
        home,
        &config,
        &report.budget,
        prompt,
        messages,
        observer,
        cancel,
        tools,
        "orbit-cli",
        session_id,
    )
    .map_err(|error| {
        let mut notices = context_notices.clone();
        append_unknown_media_notice(&mut notices, error.estimate.as_deref());
        DetailedTurnFailure {
            code: error.code,
            message: error.message,
            context_notices: notices,
            estimate: error.estimate,
        }
    })?;
    append_unknown_media_notice(&mut context_notices, Some(&result.estimate));
    Ok(DetailedTurnOutcome {
        outcome: result.outcome,
        estimate: result.estimate,
        context_notices,
    })
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_explicit_gateway_uses_the_shared_endpoint_validation() {
        let home = std::env::temp_dir().join(format!("orbit-legacy-gate-{}", ulid::Ulid::new()));
        for key in ["api_key", "%61pi%5fkey", "Access-Token"] {
            let gate = format!("http://127.0.0.1:1/v1?{key}=PRIVATE_QUERY_CREDENTIAL");
            let error = checked_model_turn(&home, "raw", None, Some(&gate), false).unwrap_err();
            assert!(!error.contains("PRIVATE_QUERY_CREDENTIAL"));
            assert!(!home.exists());
        }
        let gate = "http://127.0.0.1:1/v1?api-version=2026-01-01";
        let turn = checked_model_turn(&home, "raw", None, Some(gate), false).unwrap();
        assert_eq!(turn.gate, gate);
        assert_eq!(turn.model, "raw");
        assert!(!home.exists());
    }

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn parse_run_with_auto_destructive() {
        let args = s(&["run", "--auto", "--destructive", "--grant", "egress"]);
        let p = parse_args(&args).unwrap();
        assert_eq!(p.mode, ExecMode::AutoDestructive);
        assert_eq!(p.grants, vec!["egress"]);
    }

    #[test]
    fn destructive_without_auto_refused() {
        let args = s(&["run", "--destructive"]);
        assert_eq!(parse_args(&args).unwrap_err().code(), "E1101");
    }

    #[test]
    fn unknown_command_v02_gate() {
        let args = s(&["import"]);
        assert_eq!(parse_args(&args).unwrap_err().code(), "E110C");
        let args = s(&["frobnicate"]);
        assert_eq!(parse_args(&args).unwrap_err().code(), "E1101");
    }

    #[test]
    fn reserved_keys_not_widenable_by_config() {
        // CLI flag may set egress.allow_host; workspace config may not.
        assert_eq!(
            resolve_config(
                "egress.allow_host",
                &[
                    (ConfigLayer::CliFlag, Some("x")),
                    (ConfigLayer::Workspace, Some("y"))
                ]
            ),
            Some("x".into())
        );
        assert_eq!(
            resolve_config("egress.allow_host", &[(ConfigLayer::Workspace, Some("y"))]),
            None
        );
        // Non-reserved keys resolve normally.
        assert_eq!(
            resolve_config("log.level", &[(ConfigLayer::User, Some("debug"))]),
            Some("debug".into())
        );
    }

    #[test]
    fn telemetry_off_only() {
        assert!(check_telemetry("off").is_ok());
        assert_eq!(check_telemetry("on").unwrap_err().code(), "E110B");
    }

    #[test]
    fn auto_banner_no_prompt() {
        let b = confirmation_banner("egress", ExecMode::Auto);
        assert!(!b.contains("yes/deny"));
        assert!(b.contains("auto"));
    }
}

#[cfg(test)]
mod effort_resolution_tests {
    use super::*;
    use orbit_adapter::types::{EffortSetting, EffortValue};

    fn level(value: &str) -> EffortValue {
        EffortValue::Level(value.into())
    }
    struct Home(std::path::PathBuf);
    impl Home {
        fn new(raw: &str) -> Self {
            let path =
                std::env::temp_dir().join(format!("orbit-effort-models-{}", ulid::Ulid::new()));
            std::fs::create_dir_all(&path).unwrap();
            std::fs::write(path.join("providers.toml"), raw).unwrap();
            Self(path)
        }
    }
    impl Drop for Home {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn effort_parser_preserves_reset_and_exact_cli_values() {
        assert_eq!(
            parse_effort_setting("default").unwrap(),
            EffortSetting::Default
        );
        assert_eq!(
            parse_effort_setting("false").unwrap(),
            EffortSetting::Value(EffortValue::Bool(false))
        );
        assert_eq!(
            parse_effort_setting(r#""false""#).unwrap(),
            EffortSetting::Value(level("false"))
        );
        assert_eq!(
            parse_effort_setting(r#""true""#).unwrap(),
            EffortSetting::Value(level("true"))
        );
        assert_eq!(
            parse_effort_setting("custom").unwrap(),
            EffortSetting::Value(level("custom"))
        );
        for invalid in ["", " high", "high ", "high\n"] {
            assert!(parse_effort_setting(invalid).is_err());
        }
        for invalid in [
            r#""""#,
            r#""default""#,
            r#""false" junk"#,
            r#""false" "#,
            r#""high\n""#,
            r#"" high""#,
        ] {
            assert!(parse_effort_setting(invalid).is_err(), "{invalid:?}");
        }
    }

    #[test]
    fn exact_owner_metadata_and_reset_validate_before_mutation() {
        let home = Home::new(
            "[[provider]]\nname='one'\nurl='https://one.example'\n[[provider.models]]\nid='shared'\nsupported_efforts=['low','high']\ndefault_effort='low'\n[[provider.models]]\nid='unknown'\n[[provider.models]]\nid='unsupported'\nsupported_efforts=[]\n[[provider]]\nname='two'\nkind='ollama'\nurl='https://two.example'\n[[provider.models]]\nid='shared'\nsupported_efforts=[false,'false']\ndefault_effort=false\n",
        );
        let mut config =
            try_engine_turn_config(&home.0, "two", "https://two.example", "shared", None, None)
                .unwrap();
        assert_eq!(config.kind, orbit_engine::ProviderKind::Ollama);
        assert_eq!(config.effort, Some(EffortValue::Bool(false)));
        let boolean_status = effort_status(&home.0, &config);
        assert!(boolean_status.starts_with("Configured effort for two/shared: false\n"));
        assert!(boolean_status.contains("Supported: false, \"false\".\n"));
        apply_effort_setting(&home.0, &mut config, &EffortSetting::Value(level("false"))).unwrap();
        assert_eq!(config.effort, Some(level("false")));
        assert!(
            effort_status(&home.0, &config)
                .starts_with("Configured effort for two/shared: \"false\"\n")
        );
        apply_effort_setting(&home.0, &mut config, &EffortSetting::Default).unwrap();
        assert_eq!(config.effort, Some(EffortValue::Bool(false)));
        let before = format!("{config:?}");
        assert!(
            apply_effort_setting(&home.0, &mut config, &EffortSetting::Value(level("high")))
                .is_err()
        );
        assert_eq!(format!("{config:?}"), before);
        for model in ["unknown", "unsupported"] {
            let mut config =
                try_engine_turn_config(&home.0, "one", "https://one.example", model, None, None)
                    .unwrap();
            assert!(
                apply_effort_setting(&home.0, &mut config, &EffortSetting::Value(level("high")))
                    .is_err()
            );
            apply_effort_setting(&home.0, &mut config, &EffortSetting::Default).unwrap();
            assert!(config.effort.is_none());
            let status = effort_status(&home.0, &config);
            if model == "unknown" {
                assert!(status.contains("\nSupported: unknown.\nDeclare supported_efforts"));
            } else {
                assert!(status.contains("\nSupported: unsupported (default only).\n"));
            }
        }
    }

    #[test]
    fn different_role_and_route_models_use_their_own_default() {
        let home = Home::new(
            "[[provider]]\nname='p'\nurl='https://example.test'\n[[provider.models]]\nid='main'\nsupported_efforts=['low','high']\ndefault_effort='low'\n[[provider.models]]\nid='vendor/summary'\nsupported_efforts=['medium']\ndefault_effort='medium'\n[roles]\nmain='p/main'\ncompaction='p/vendor/summary'\nexplore='p/main'\n[routing]\nhard='vendor/summary'\n[routing.keywords]\nclear=true\nhard=['difficult']\n",
        );
        let mut base =
            try_engine_turn_config(&home.0, "p", "https://example.test", "main", None, None)
                .unwrap();
        apply_effort_setting(&home.0, &mut base, &EffortSetting::Value(level("high"))).unwrap();
        assert_eq!(
            try_role_turn_config(&home.0, &base, "explore")
                .unwrap()
                .effort,
            Some(level("high"))
        );
        assert_eq!(
            try_role_turn_config(&home.0, &base, "compaction")
                .unwrap()
                .effort,
            Some(level("medium"))
        );
        // Routing may be disabled by an ambient explicit model; the role assertion
        // above is independent and the target assertion exercises the same loaded config.
        let cfg = crate::config::ProvidersConfig::load(&home.0).unwrap();
        if !explicit_model_in_force(&cfg, "main") {
            assert_eq!(
                try_routed_turn_config(&home.0, &base, "difficult", "test")
                    .unwrap()
                    .0
                    .effort,
                Some(level("medium"))
            );
        }
        std::fs::write(home.0.join("providers.toml"),"[[provider]]\nname='p'\nurl='https://example.test'\n[[provider.models]]\nid='main'\ndefault_effort='high'\n").unwrap();
        assert!(
            try_engine_turn_config(&home.0, "p", "https://example.test", "main", None, None)
                .is_err()
        );
        assert!(try_role_turn_config(&home.0, &base, "compaction").is_err());
        assert!(try_routed_turn_config(&home.0, &base, "x", "test").is_err());
    }
}
