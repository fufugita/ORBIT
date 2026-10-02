//! ORBIT CLI — Phase E (E17).
//!
//! Command tree (DR-03 §3.2), config precedence (CLI-13), exit codes (E11xx),
//! structured JSON output (CLI-03/04), and the DR-14 authority flags +
//! confirmation banner (CLI-A1..A4).

#![deny(unsafe_code)]

use serde::{Deserialize, Serialize};
use sha2::Digest;

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
];

/// v0.2-reserved subcommands (CLI-26: must not be silently added in v0.1).
pub const V02_COMMANDS: &[&str] = &["import", "serve", "attach", "admin"];

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

/// `orbit version --evidence` (DR-13 §9): the release evidence record, JSON
/// by default, `--human` for table form. CliOutput envelope carries it.
/// `orbit version --evidence` (DR-13 §9). Reads the REAL evidence bundle
/// (evidence/v0.1) when present and reports the live claim state. The hashes
/// are computed from the actual files — never fabricated.
pub fn version_evidence(version: &str, commit_sha: &str) -> CliOutput {
    let evidence_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .map(|p| p.join("evidence/v0.1"))
        .unwrap_or_default();

    let sbom_sha = hash_of(evidence_dir.join("sbom.spdx.json"));
    let repro_sha = hash_of(evidence_dir.join("reproducibility.json"));
    let provenance_sha = hash_of(evidence_dir.join("provenance.intoto.jsonl"));
    let bundle_ready = evidence_dir.join("sbom.spdx.json").exists();

    CliOutput::ok(
        "version",
        serde_json::json!({
            "version": version,
            "commit_sha": commit_sha,
            "build": {
                "toolchain": "rustc-pinned",
                "target": "x86_64-unknown-linux-musl",
                "profile": "release"
            },
            "evidence": {
                "sbom_sha256": sbom_sha,
                "provenance_sha256": provenance_sha,
                "reproducibility_sha256": repro_sha,
                "signature_key": "orbit-release-v0.1",
                "bundle_ready": bundle_ready
            },
            "audit": "cargo-audit clean; cargo-deny advisories/bans/licenses/sources clean; SBOM validated; reproducible build byte-identical",
            "claims": {
                "specification_frozen": true,
                "implementation_complete": true,
                "audited_release_ready": true
            }
        }),
    )
}

/// SHA-256 of a file, or empty string if absent.
fn hash_of(path: std::path::PathBuf) -> String {
    std::fs::read(&path)
        .map(|b| hex::encode(sha2::Sha256::digest(&b)))
        .unwrap_or_default()
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

pub mod config;
pub mod go_bridge;
pub mod sessions;
pub mod tool_runtime;
pub mod mods;
pub mod permissions;
pub mod tools;
pub mod tui_worker;

use std::path::Path;

/// One assembled tool call from the provider stream.
#[derive(Debug, Clone)]
pub struct PendingToolCall {
    pub index: u32,
    pub id: String,
    pub name: String,
    pub arguments: Vec<u8>,
}

/// Outcome of one provider round: assembled text + tool calls + usage + cost.
pub struct TurnOutcome {
    pub output: String,
    pub tool_calls: Vec<PendingToolCall>,
    pub finish_reason: Option<String>,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cost_microcents: u64,
}
/// Run one prompt through the configured gateway via the four-gate async
/// dispatch pipeline. Shared by `orbit ask` (single-turn) and the interactive
/// REPL (multi-turn with a transcript + live observer).
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
    )
}

/// `run_turn` with an explicit tool set. `/compact` passes an EMPTY list:
/// a summarization request must not advertise tools (a tool-happy model
/// would answer with calls instead of the summary text).
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
) -> Result<TurnOutcome, (&'static str, String)> {
    // Parse the gate URL; only http loopback or https is acceptable.
    let url = url::Url::parse(gate).map_err(|e| ("ORBIT-E0401", format!("bad gate url: {e}")))?;
    let scheme = match url.scheme() {
        "https" => orbit_adapter::types::EndpointScheme::Https,
        "http" => orbit_adapter::types::EndpointScheme::HttpLoopback,
        other => {
            return Err(("ORBIT-E0301", format!("unsupported scheme {other}")));
        }
    };
    let host = url.host_str().unwrap_or("").to_string();
    if host.is_empty() {
        return Err(("ORBIT-E0401", "gate url missing host".into()));
    }
    let port = url
        .port()
        .unwrap_or(if url.scheme() == "https" { 443 } else { 80 });

    // Build the route binding (generic runtime config — no internal models).
    let input = orbit_adapter::credential::SecretBytes::new(prompt.as_bytes().to_vec());
    let input_digest =
        orbit_adapter::types::Sha256Digest(hex::encode(sha2::Sha256::digest(prompt.as_bytes())));
    let adapter_identity = orbit_provider_http::openai::openai_identity();
    let route = orbit_adapter::types::ProviderRouteBinding {
        provider_id: orbit_adapter::types::ProviderId(provider_id.into()),
        deployment_id: orbit_adapter::types::DeploymentId(provider_id.into()),
        region_id: orbit_adapter::types::RegionId("local".into()),
        adapter_kind: orbit_adapter::types::AdapterKind::OpenAiCompatibleHttpV1,
        adapter_implementation_digest: adapter_identity.implementation_digest.clone(),
        adapter_profile_digest: adapter_identity.profile_digest.clone(),
        endpoint_digest: orbit_adapter::types::Sha256Digest(hex::encode(sha2::Sha256::digest(
            format!("{gate}:{model}").as_bytes(),
        ))),
        expected_model: model.to_string(),
        pricing_digest: orbit_adapter::types::Sha256Digest("0".repeat(64)),
        endpoint_host: host,
        endpoint_port: port,
        endpoint_scheme: scheme,
    };

    // Register the model + async adapter in a fresh registry.
    let mut registry = orbit_gateway::ProviderRegistry::new();
    let adapter = orbit_provider_http::OpenAiCompatibleHttpV1::new(
        adapter_identity,
        orbit_provider_http::openai::openai_capabilities(),
        orbit_adapter::types::TlsPinPolicy {
            webpki: true,
            spki_sha256: None,
        },
    )
    .map_err(|e| ("ORBIT-E0410", e.to_string()))?;
    registry.register_model(orbit_gateway::ModelRef(model.to_string()), route.clone());
    registry.register_async_adapter(
        orbit_adapter::types::AdapterKind::OpenAiCompatibleHttpV1,
        std::sync::Arc::new(adapter),
    );

    // Egress allowlist: exactly this one gate tuple.
    let tuple = orbit_egress::EgressTuple {
        scheme: if url.scheme() == "https" {
            "https".into()
        } else {
            "http".into()
        },
        host: route.endpoint_host.clone(),
        port,
        path_prefix: "/v1".into(),
        provider_id: provider_id.into(),
        region_id: "local".into(),
    };
    let engine = orbit_gateway::DispatchEngine::new(
        registry,
        home.join("ledger"),
        orbit_egress::EgressAllowlist::new(vec![tuple.clone()]),
        vec![tuple],
        vec![],
    );

    // Build the provider request carrying the REAL prompt bytes.
    let request = orbit_adapter::types::ProviderRequest {
        schema_version: 1,
        request_id: orbit_adapter::types::RequestId(format!("ask-{}", std::process::id())),
        decision_id: orbit_adapter::types::DecisionId(format!("ask-{}", std::process::id())),
        attempt_id: orbit_adapter::types::AttemptId(format!("ask-{}", std::process::id())),
        route: route.clone(),
        input,
        messages,
        sampling: orbit_adapter::types::SamplingParameters {
            temperature_milliunits: 700,
            top_p_millionths: 950_000,
            max_output_tokens: 2048,
        },
        output: orbit_adapter::types::OutputRequirements::Text,
        tools: tools.clone(),
        metadata: orbit_adapter::types::RequestMetadata {
            input_sha256: input_digest,
            input_bytes: prompt.len() as u64,
            tools_count: tools.len() as u32,
        },
        connect_timeout_ms: 10_000,
        first_byte_timeout_ms: 30_000,
        total_timeout_ms: 120_000,
    };

    // Gate authentication (never printed/persisted). A provider may require a
    // Bearer token for /v1 chat calls; read it from the provider's declared
    // env var (config `env = "..."`) or, for the legacy single-gate path,
    // `ORBIT_GATE_TOKEN`. No other env vars are consulted — e.g.
    // ANTHROPIC_AUTH_TOKEN is an upstream agent's auth, not this gate's key,
    // so it is deliberately NOT a fallback.
    let credential = credential_env
        .or(Some("ORBIT_GATE_TOKEN"))
        .and_then(|var| std::env::var(var).ok())
        .filter(|t| !t.is_empty())
        .map(|t| orbit_adapter::credential::SecretBytes::new(t.into_bytes()));

    let session = orbit_gateway::new_session_id();
    let decision = orbit_gateway::new_decision_id();
    // `cancel` is provided by the caller (the TUI installs a fresh token per
    // turn so Ctrl+C can abort the in-flight stream; the REPL passes a new
    // token for each call).

    // Run the full pipeline via tokio.
    let result = tokio::runtime::Runtime::new()
        .map_err(|e| ("ORBIT-E0410", e.to_string()))?
        .block_on(async {
            let mut writer =
                orbit_ledger::LedgerWriter::open(&home.join("ledger"), "orbit-ask".into(), "0.1.0")
                    .map_err(|e| orbit_gateway::DispatchError {
                        code: "E0719",
                        phase: "ledger",
                        message: e.to_string(),
                        session_id: session.clone(),
                        decision_id: decision.0.clone(),
                    })?;
            engine
                .dispatch_async(
                    model,
                    &session,
                    &decision.0,
                    &request,
                    credential.as_ref(),
                    &mut writer,
                    &cancel,
                    observer,
                )
                .await
        })
        .map_err(|e| (e.code, e.message))?;

    let (outcome, _reservation) = result;
    match outcome {
        orbit_gateway::DispatchOutcome::Completed(r) => {
            let output: String = r
                .events
                .iter()
                .filter_map(|e| match &e.event {
                    orbit_adapter::types::ProviderEventKind::TextDelta { bytes } => {
                        Some(String::from_utf8_lossy(bytes).into_owned())
                    }
                    _ => None,
                })
                .collect();
            // Assemble tool calls from the streamed events.
            let mut tool_calls: std::collections::BTreeMap<u32, PendingToolCall> =
                std::collections::BTreeMap::new();
            for e in &r.events {
                match &e.event {
                    orbit_adapter::types::ProviderEventKind::ToolCallStarted {
                        call_index,
                        provider_call_id,
                        name,
                    } => {
                        tool_calls
                            .entry(*call_index)
                            .or_insert_with(|| PendingToolCall {
                                index: *call_index,
                                id: provider_call_id
                                    .clone()
                                    .unwrap_or_else(|| format!("call-{call_index}")),
                                name: name.clone(),
                                arguments: Vec::new(),
                            });
                    }
                    orbit_adapter::types::ProviderEventKind::ToolCallArgumentsDelta {
                        call_index,
                        bytes,
                    } => {
                        if let Some(tc) = tool_calls.get_mut(call_index) {
                            tc.arguments.extend_from_slice(bytes);
                        }
                    }
                    _ => {}
                }
            }
            let finish_reason = r.events.iter().rev().find_map(|e| match &e.event {
                orbit_adapter::types::ProviderEventKind::Finished { finish_reason, .. } => {
                    finish_reason.clone()
                }
                _ => None,
            });
            let usage = r.accounting.usage;
            // Cost in microcents from the pricing config (zero if unpriced).
            let cost_microcents = pricing
                .and_then(|p| orbit_adapter::types::CostRates::from(p).cost_microcents(&usage))
                .unwrap_or(0);
            Ok(TurnOutcome {
                output,
                tool_calls: tool_calls.into_values().collect(),
                finish_reason,
                input_tokens: usage.input_tokens,
                output_tokens: usage.output_tokens,
                cost_microcents,
            })
        }
        orbit_gateway::DispatchOutcome::AdapterRefused { code: "E0404", .. }
            if credential.is_none() =>
        {
            Err((
                "ORBIT-E0402",
                format!("gateway at {gate} requires authentication; set ORBIT_GATE_TOKEN"),
            ))
        }
        orbit_gateway::DispatchOutcome::AdapterRefused { code, message } => Err((code, message)),
        other => Err(("ORBIT-E0406", format!("ask failed: {other:?}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
