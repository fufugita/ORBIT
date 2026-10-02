//! orbit-web — the browser harness binary (docs/browser-harness.md).
//!
//! Serves the SPA + SSE/WS bridge over the SAME core as the TUI/REPL.
//! `orbit web` (the CLI command) execs this binary with passthrough flags.

#![deny(unsafe_code)]

use orbit_cli::tui_worker::TuiTurnConfig;
use orbit_web::{run_bridge, BridgeConfig};
use std::path::PathBuf;

fn value_after(args: &[String], flag: &str) -> Option<String> {
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1))
        .cloned()
        .filter(|v| !v.is_empty())
}

fn orbit_home(args: &[String]) -> Option<PathBuf> {
    if let Some(h) = value_after(args, "--home") {
        return Some(PathBuf::from(h));
    }
    std::env::var("ORBIT_HOME").ok().map(PathBuf::from)
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let home = orbit_home(&args).unwrap_or_else(|| PathBuf::from(".orbit"));
    if !home.join("trust").exists() {
        eprintln!("ORBIT-E1912: not initialized; run `orbit init` first");
        std::process::exit(2);
    }

    let gate = value_after(&args, "--gate")
        .or_else(|| std::env::var("ORBIT_GATE_URL").ok())
        .unwrap_or_else(|| "http://127.0.0.1:4001".into());
    // Model precedence: --model flag > ORBIT_MODEL > first configured
    // model in providers.toml. Never hardcode an id: a default that
    // matches no provider falls through to the generic gate URL, which
    // 401s (or worse) on every turn.
    let cfg_for_default = orbit_cli::config::ProvidersConfig::load(&home).unwrap_or_default();
    let model = value_after(&args, "--model")
        .or_else(|| std::env::var("ORBIT_MODEL").ok())
        .or_else(|| {
            cfg_for_default
                .all_models()
                .into_iter()
                .next()
                .map(|(_, m)| m)
        })
        .unwrap_or_else(|| "mock-echo".into());
    let port: u16 = value_after(&args, "--port")
        .and_then(|p| p.parse().ok())
        .unwrap_or(4173);
    let bind = value_after(&args, "--bind").unwrap_or_else(|| "127.0.0.1".into());
    let token = value_after(&args, "--token").or_else(|| std::env::var("ORBIT_GATE_TOKEN").ok());
    let no_browser = args.iter().any(|a| a == "--no-browser");
    let auto_tools = args.iter().any(|a| a == "--auto-tools");

    let resume = value_after(&args, "--resume");
    let resumed = resume
        .as_deref()
        .filter(|id| !id.is_empty())
        .and_then(|id| match orbit_cli::sessions::load_session(&home, id) {
            Ok(s) => Some(s),
            Err(e) => {
                eprintln!("warning: cannot resume {id}: {e}; starting fresh");
                None
            }
        });

    let session_id = resumed
        .as_ref()
        .map(|s| s.session_id.clone())
        .unwrap_or_else(orbit_gateway_new_session_id);
    let cfg = orbit_cli::config::ProvidersConfig::load(&home)
        .map_err(|e| eprintln!("warning: providers.toml: {e}"))
        .unwrap_or_default();
    let provider = cfg.provider_for_model(&model);
    let provider_id = provider
        .map(|p| p.name.clone())
        .unwrap_or_else(|| "configured-gateway".into());
    let turn = TuiTurnConfig {
        home,
        session_id,
        gate,
        model,
        provider_id,
        auto_tools,
        initial_transcript: resumed
            .as_ref()
            .map(|s| s.to_transcript())
            .unwrap_or_default(),
        initial_turns: resumed.as_ref().map(|s| s.turns).unwrap_or(0),
        initial_input_tokens: resumed.as_ref().map(|s| s.input_tokens).unwrap_or(0),
        initial_output_tokens: resumed.as_ref().map(|s| s.output_tokens).unwrap_or(0),
        initial_cost_microcents: resumed.as_ref().map(|s| s.cost_microcents).unwrap_or(0),
    };

    // Non-loopback bind without a token is refused (docs/browser-harness.md).
    let loopback = bind == "127.0.0.1" || bind == "localhost" || bind == "::1";
    if !loopback && token.is_none() {
        eprintln!(
            "ORBIT-E1109: non-loopback --bind requires --token <T> (or ORBIT_GATE_TOKEN); \
             remote access without a bearer token is refused"
        );
        std::process::exit(93);
    }

    let url = format!("http://{bind}:{port}");
    println!("orbit-web: {url}");
    if !no_browser {
        let _ = std::process::Command::new("xdg-open")
            .arg(&url)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn();
    }
    std::process::exit(run_bridge(BridgeConfig {
        turn,
        bind,
        port,
        token,
    }));
}

/// Session id without importing the whole gateway dep chain: ULID-shaped,
/// unique per process start. (The gateway crate is already in tree via cli.)
fn orbit_gateway_new_session_id() -> String {
    orbit_cli::config::ProvidersConfig::default();
    // Reuse the gateway's id generator through the cli's public surface.
    orbit_gateway::new_session_id()
}
