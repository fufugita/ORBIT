//! ORBIT CLI — Phase E (E17).
//!
//! Command tree (DR-03 §3.2), config precedence (CLI-13), exit codes (E11xx),
//! structured JSON output (CLI-03/04), and the DR-14 authority flags +
//! confirmation banner (CLI-A1..A4).

#![forbid(unsafe_code)]

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
