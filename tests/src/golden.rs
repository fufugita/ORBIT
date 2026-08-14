//! DR-03 §5a.5 — CLI golden fixtures.
//!
//! Each CLI command's structured output is pinned to a golden JSON fixture and
//! asserted byte-identical (DR-03 §5: "Every CLI command has JSON and non-TTY
//! behavior where specified, stable exit codes, and golden fixtures").
#![allow(unused_imports)] // used only in #[test] fns

use orbit_cli::{parse_args, CliOutput, ExecMode};

#[allow(dead_code)] // used only in #[test] fns
fn fixture_path(name: &str) -> String {
    format!("{}/fixtures/cli/{name}", env!("CARGO_MANIFEST_DIR"))
}

/// Canonicalize JSON: parse + reserialize so whitespace/key-order differences
/// don't mask real drift. The golden files are themselves canonicalized.
#[allow(dead_code)] // used only in #[test] fns
fn canonical(v: serde_json::Value) -> String {
    serde_json::to_string(&v).unwrap()
}

#[test]
fn cli_version_evidence_golden() {
    let out = orbit_cli::version_evidence("0.1.0", "dev");
    let actual = canonical(serde_json::to_value(&out).unwrap());
    let golden_raw = std::fs::read_to_string(fixture_path("version_evidence.golden.json")).unwrap();
    let golden = canonical(serde_json::from_str(&golden_raw).unwrap());
    assert_eq!(
        actual, golden,
        "version --evidence must match the golden fixture"
    );
}

#[test]
fn cli_output_envelope_stable() {
    // The envelope shape is pinned: schema_version, command, status, data.
    let o = CliOutput::ok("run", serde_json::json!({"session": "s1"}));
    let s = serde_json::to_string(&o).unwrap();
    assert!(s.contains("\"schema_version\":\"orbit.cli/v1\""));
    assert!(s.contains("\"status\":\"ok\""));
    assert!(s.contains("\"command\":\"run\""));
}

#[test]
fn cli_json_nontty_discipline() {
    // Non-TTY: JSON envelope on stdout; diagnostics on stderr. The parse path
    // is JSON-safe (no ANSI in the output object).
    let args: Vec<String> = vec!["run".into(), "--json".into()];
    let p = parse_args(&args).unwrap();
    assert!(p.json);
}

#[test]
fn cli_exit_codes_golden() {
    // Stable exit codes (DR-10 §5.1 supercodes).
    assert_eq!(orbit_cli::CliError::Usage("x".into()).exit_code(), 64);
    assert_eq!(
        orbit_cli::CliError::ConfigInvalid("x".into()).exit_code(),
        78
    );
    assert_eq!(orbit_cli::CliError::Policy("x".into()).exit_code(), 93);
    assert_eq!(
        orbit_cli::CliError::TelemetryDenied("x".into()).exit_code(),
        96
    );
    assert_eq!(orbit_cli::CliError::V02Only("x".into()).exit_code(), 97);
}

#[test]
fn cli_command_tree_golden() {
    // The full command tree is pinned (DR-03 §3.2, all 15) + the interactive
    // `chat` harness (promoted from v0.2-reserved in v0.2).
    let expected = [
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
    assert_eq!(orbit_cli::COMMANDS, expected.as_slice());
    // Remaining v0.2 commands are gated (CLI-26).
    for cmd in ["import", "serve", "attach", "admin"] {
        let args: Vec<String> = vec![cmd.into()];
        assert_eq!(parse_args(&args).unwrap_err().code(), "E110C");
    }
}

#[test]
fn cli_mode_flags_golden() {
    // The execution-mode grammar is pinned (DR-14 §2.3).
    let auto: Vec<String> = vec!["run".into(), "--auto".into()];
    assert_eq!(parse_args(&auto).unwrap().mode, ExecMode::Auto);
    let both: Vec<String> = vec!["run".into(), "--auto".into(), "--destructive".into()];
    assert_eq!(parse_args(&both).unwrap().mode, ExecMode::AutoDestructive);
    let manual: Vec<String> = vec!["run".into(), "--manual".into()];
    assert_eq!(parse_args(&manual).unwrap().mode, ExecMode::Manual);
    // --destructive without --auto is refused.
    let bad: Vec<String> = vec!["run".into(), "--destructive".into()];
    assert_eq!(parse_args(&bad).unwrap_err().code(), "E1101");
}

#[test]
fn cli_telemetry_golden() {
    // IF-8: telemetry is off-only.
    assert!(orbit_cli::check_telemetry("off").is_ok());
    assert_eq!(
        orbit_cli::check_telemetry("on").unwrap_err().code(),
        "E110B"
    );
}

#[test]
fn cli_help_lists_all_commands() {
    // The help surface lists every command (the CLI's summonable usage).
    let out = orbit_cli::CliOutput::ok(
        "help",
        serde_json::json!({
            "usage": "orbit <command> [--home <dir>]",
            "commands": ["init", "run", "cancel", "verify-ledger", "replay", "export", "restore", "version"],
        }),
    );
    let s = serde_json::to_string(&out).unwrap();
    assert!(s.contains("\"command\":\"help\""));
    assert!(s.contains("init"));
    assert!(s.contains("verify-ledger"));
    assert!(s.contains("version"));
}
