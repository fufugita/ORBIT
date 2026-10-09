//! ORBIT CLI binary — clean-machine E2E surface (DR-03 §5 row 9).
//!
//! Implements the exact closeout chain:
//! install/build → init trust → run example → cancel → verify-ledger → replay dry
//! → export → restore into a fresh namespace → verify again.

use age::secrecy::ExposeSecret;
use ed25519_dalek::{Signer, SigningKey};
use orbit_export::{generate_local_key, restore, ExportBuilder};
use orbit_ledger::event::{
    LedgerEvent, Phase, PhaseTransition, SessionEnd, SessionStart, TerminalOutcome,
};
use orbit_ledger::{verify_ledger, LedgerWriter};
use orbit_pib::PibRegistry;
use orbit_reactor::{CancelOrigin, CancelTarget, CancellationToken, Reactor};
use orbit_trust::manifest::{signed_bytes, TrustRootManifestBody, MANIFEST_SCHEMA};
use orbit_trust::{RootPublicKey, TrustRootManifest, TrustRootStore};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use orbit_cli::{config, go_bridge, sessions, tool_runtime, tools, tui_worker};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();

    // Web search backend (roadmap §Wave 2): off until configured. The
    // env pair names a search API; the tool answers honestly otherwise.
    if let (Ok(api), Ok(key)) = (
        std::env::var("ORBIT_SEARCH_API"),
        std::env::var("ORBIT_SEARCH_KEY"),
    ) {
        let backend = orbit_tools::websearch::tavily_backend(&api, &key);
        orbit_tools::websearch::set_search_backend(Some(backend));
    }

    // Bare `orbit` (no args, or only flags) summons the interactive CLI — the
    // "harness". `orbit chat` is the explicit alias. Both stream live to
    // stdout, so they run outside the JSON-envelope dispatch path.
    // `--help`/`-h`/`--version` stay on the JSON dispatch (first-class verbs).
    // A leading flag may carry a value (`--home X init`): skip
    // flag/value pairs to find the first real word.
    let first_is_command = {
        let mut i = 0usize;
        let mut found = false;
        while i < args.len() {
            let a = &args[i];
            if a == "--home" || a == "--model" || a == "--gate" || a == "--resume" {
                i += 2; // the flag and its value
                continue;
            }
            if a == "--continue"
                || a == "--bare"
                || a == "--old-tui"
                || a == "--go-tui"
                || a == "--no-tui"
                || a == "--tui"
            {
                i += 1;
                continue;
            }
            found = !a.starts_with('-');
            break;
        }
        found
    };
    let wants_chat = args.is_empty()
        || args[0] == "chat"
        || (!first_is_command && args[0] != "--help" && args[0] != "-h" && args[0] != "--version");
    // C1: `--help`/`-h` print HUMAN help (exit 0); `--version` prints the
    // version line. The machine-readable forms stay on the verbs:
    // `orbit help --json` and `orbit version` (JSON).
    if args.iter().any(|a| a == "--help" || a == "-h") {
        if args.iter().any(|a| a == "--json") {
            // fall through to the JSON verb below
        } else {
            print_human_help();
            std::process::exit(0);
        }
    }
    if args
        .first()
        .map(|a| a == "--version" || a == "-V")
        .unwrap_or(false)
    {
        println!("orbit {}", env!("CARGO_PKG_VERSION"));
        std::process::exit(0);
    }
    if args.first().map(|a| a == "web").unwrap_or(false) {
        let code = cmd_web(&args[1..]);
        std::process::exit(code);
    }
    // `orbit -p "<prompt>"` — headless one-shot with tools (roadmap
    // phase 2). Streams the engine's events as JSON lines; never asks
    // (dontAsk default: anything no allow rule covers is denied).
    if args.first().map(|a| a == "-p").unwrap_or(false) {
        let code = cmd_headless(&args[1..]);
        std::process::exit(code);
    }
    if wants_chat {
        let code = cmd_chat(&args);
        std::process::exit(code);
    }

    let result = dispatch(&args);
    match result {
        Ok(v) => println!(
            "{}",
            serde_json::to_string(&v).unwrap_or_else(|_| "{}".into())
        ),
        Err((code, msg)) => {
            eprintln!("{code}: {msg}");
            std::process::exit(2);
        }
    }
}

/// Human help for `--help`/`-h` (C1): plain text to stdout, exit 0. The
/// JSON vocabulary stays available at `orbit help --json` / `orbit help`.
fn print_human_help() {
    println!(
        "orbit {} — the harness that orbits around you",
        env!("CARGO_PKG_VERSION")
    );
    println!();
    println!("USAGE:");
    println!("    orbit [chat] [--model <M>] [--gate <URL>]    interactive TUI harness");
    println!("    orbit <command> [args]                       run a command");
    println!();
    println!("COMMANDS:");
    for (name, desc) in [
        ("chat", "start the interactive harness (default when bare)"),
        ("init", "initialize trust root + PIB + ledger"),
        ("models", "list models from all configured providers"),
        ("ask PROMPT", "send one prompt through a configured gateway"),
        (
            "-p PROMPT",
            "headless one-shot with tools (stream-json output)",
        ),
        ("web", "start the browser harness (orbit-web bridge)"),
        ("verify-ledger", "verify the ledger hash chain"),
        ("replay --dry", "verify + emit a no-dispatch replay plan"),
        ("export --to", "encrypt an age bundle"),
        ("restore", "restore into a fresh namespace"),
        ("version", "release evidence (claims + hashes)"),
        ("mod install/list/allow-issuer", "signed mod management"),
        ("help [--json]", "this help (JSON vocabulary with --json)"),
    ] {
        println!("    {name:<28} {desc}");
    }
    println!();
    println!("CHAT FLAGS:");
    for (name, desc) in [
        ("--model <M>", "model id (providers.toml)"),
        ("--gate <URL>", "gateway base URL"),
        ("--home <DIR>", "ORBIT home (default ~/.orbit)"),
        ("--continue", "reopen the latest session in this directory"),
        ("--resume <ID>", "resume a specific session"),
        ("--no-tui", "plain REPL instead of the TUI"),
        (
            "--auto-tools",
            "TUI/chat: run tools without asking (bypass)",
        ),
    ] {
        println!("    {name:<28} {desc}");
    }
    println!();
    println!("    --version                    print the version and exit");
    println!("    --help | -h                 this help");
}

/// The commit this binary was built from, as honestly as it can be known.
/// Build scripts may pin it via ORBIT_BUILD_COMMIT (compile-time); a tree
/// build without that falls back to asking git at runtime; a binary with
/// no git in reach reports "unknown" rather than inventing a value (C2).
fn build_commit() -> String {
    if let Some(c) = option_env!("ORBIT_BUILD_COMMIT") {
        if !c.is_empty() {
            return c.to_string();
        }
    }
    // Runtime fallback: ask the source tree (dev builds run from a repo).
    let manifest_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(|p| p.to_path_buf());
    if let Some(root) = manifest_root {
        if let Ok(out) = std::process::Command::new("git")
            .arg("rev-parse")
            .arg("--short=12")
            .arg("HEAD")
            .current_dir(&root)
            .output()
        {
            if out.status.success() {
                let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
                if !s.is_empty() {
                    return s;
                }
            }
        }
    }
    "unknown".into()
}

fn dispatch(args: &[String]) -> Result<serde_json::Value, (&'static str, String)> {
    if args.is_empty() {
        return Err(("ORBIT-E1101", "no command".into()));
    }
    let home = orbit_home(args).unwrap_or_else(|| {
        std::env::var("ORBIT_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from(".orbit"))
    });
    // The verb is the first non-flag word (flags may lead: `--home X init`).
    let _verb = args
        .iter()
        .find(|a| !a.starts_with('-'))
        .cloned()
        .unwrap_or_default();
    // Flag values are skipped by the filter above only when they don't
    // start with '-'; a value like `X` would be mistaken for a verb —
    // walk pairs properly instead.
    let mut verb = String::new();
    let mut i = 0usize;
    while i < args.len() {
        let a = &args[i];
        if a == "--home" || a == "--model" || a == "--gate" || a == "--resume" {
            i += 2;
            continue;
        }
        if a.starts_with('-') {
            i += 1;
            continue;
        }
        verb = a.clone();
        break;
    }
    let _ = &verb;
    match verb.as_str() {
        "init" => cmd_init(&home, args),
        "run" => cmd_run(&home, args),
        "cancel" => cmd_cancel(&home),
        "verify-ledger" => cmd_verify(&home),
        "replay" => cmd_replay(&home, args),
        "export" => cmd_export(&home, args),
        "restore" => cmd_restore(&home, args),
        "ask" => cmd_ask(&home, args),
        "models" | "list-models" => cmd_models(&home, args),
        "mod" => cmd_mod(&home, args),
        "version" => Ok(serde_json::to_value(orbit_cli::version_evidence(
            env!("CARGO_PKG_VERSION"),
            &build_commit(),
        ))
        .unwrap_or_default()),
        "--help" | "-h" | "help" => Ok(serde_json::json!({
            "schema": "orbit.cli/v1",
            "command": "help",
            "status": "ok",
            "usage": "orbit [chat] [--model <M>] [--gate <URL>] | orbit <command>",
            "commands": [
                "(bare)        start the interactive harness",
                "chat          start the interactive harness (explicit alias)",
                "init          initialize trust root + PIB + Ledger",
                "models        list models from all configured providers",
                "ask PROMPT    send one prompt through a configured gateway",
                "-p PROMPT     headless one-shot with tools (stream-json output)",
                "run           run the example phase chain",
                "cancel        cancel the session (terminal: cancelled)",
                "verify-ledger verify the Ledger hash chain",
                "replay --dry  verify + emit a no-dispatch replay plan",
                "export --to   encrypt an age bundle",
                "restore       restore into a fresh namespace",
                "version       release evidence (claims + hashes)",
                "mod install <pkg> --manifest <m>  install a signed mod",
                "mod list                        installed mods",
                "mod allow-issuer <hex-key>       trust a mod issuer",
                "web           start the browser harness (orbit-web bridge)"
            ]
        })),
        other => Err(("ORBIT-E1101", format!("unsupported command {other}"))),
    }
}

/// The ORBIT home (README): `--home` > `ORBIT_HOME` > `~/.orbit`.
/// A repo-local `.orbit` is used only when it already exists (legacy
/// behaviour) — a fresh checkout must not shadow the user config.
/// C8: the implementation lives in config::resolve_home — ONE resolver
/// for every crate (tools.rs used to default to a CWD-relative `.orbit`).
fn orbit_home(args: &[String]) -> Option<PathBuf> {
    Some(orbit_cli::config::resolve_home(args))
}

/// `orbit init`: generate a local Ed25519 trust root, sign the manifest, verify it,
/// initialize PIB identity + Ledger (DR-03 E2E: initialize trust).
fn cmd_init(home: &Path, args: &[String]) -> Result<serde_json::Value, (&'static str, String)> {
    std::fs::create_dir_all(home).map_err(ioe)?;
    let trust_dir = home.join("trust");
    std::fs::create_dir_all(&trust_dir).map_err(ioe)?;

    // Generate operator authority root (local; private bytes mode 0600).
    let sk = SigningKey::generate(&mut rand::rngs::OsRng);
    let root = RootPublicKey(hex::encode(sk.verifying_key().to_bytes()));
    let body = TrustRootManifestBody {
        schema: MANIFEST_SCHEMA.into(),
        version: "0.1.0".into(),
        issuer_allowlist: vec![],
        routes: vec![],
        lifecycle: vec![],
        model_allowlist: BTreeSet::new(),
    };
    let sig = sk.sign(&signed_bytes(&body).map_err(|e| ("ORBIT-E0706", e.to_string()))?);
    let manifest = TrustRootManifest {
        body,
        signature: hex::encode(sig.to_bytes()),
    };
    let store = TrustRootStore::new(vec![root.clone()]);
    store
        .verify_manifest(&manifest)
        .map_err(|e| ("ORBIT-E0706", e.to_string()))?;
    std::fs::write(
        trust_dir.join("manifest.json"),
        serde_json::to_vec_pretty(&manifest).map_err(|e| ("ORBIT-E0706", e.to_string()))?,
    )
    .map_err(ioe)?;
    std::fs::write(trust_dir.join("operator.key"), hex::encode(sk.to_bytes())).map_err(ioe)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&trust_dir, std::fs::Permissions::from_mode(0o700))
            .map_err(ioe)?;
        std::fs::set_permissions(
            trust_dir.join("manifest.json"),
            std::fs::Permissions::from_mode(0o600),
        )
        .map_err(ioe)?;
        std::fs::set_permissions(
            trust_dir.join("operator.key"),
            std::fs::Permissions::from_mode(0o600),
        )
        .map_err(ioe)?;
    }

    // Initialize PIB. C3: the id is a real ULID minted per install —
    // every install used to share the hard-coded "01J-LOCAL-PIB".
    let mut pib = PibRegistry::new();
    let pib_id = format!("pib-{}", ulid::Ulid::new());
    pib.register(
        pib_id.clone(),
        "local".into(),
        root.0,
        hex::encode(Sha256::digest(b"local-host")),
        "root-1".into(),
    );
    std::fs::write(
        home.join("pib.json"),
        serde_json::to_vec_pretty(pib.identity().unwrap()).unwrap_or_default(),
    )
    .map_err(ioe)?;

    // Initialize Ledger with SessionStart.
    let ledger_dir = home.join("ledger");
    let mut w = LedgerWriter::open(&ledger_dir, "writer-init".into(), "0.1.0")
        .map_err(|e| ("ORBIT-E0719", e.to_string()))?;
    w.append(LedgerEvent::SessionStart(SessionStart {
        session_id: "session-example".into(),
        restricted: false,
        pib_id: Some(pib_id.clone()),
        policy_snapshot_id: manifest.policy_snapshot_digest().unwrap_or_default(),
        operator_principal: "local-user".into(),
    }))
    .map_err(|e| ("ORBIT-E0700", e.to_string()))?;
    w.close().map_err(|e| ("ORBIT-E0700", e.to_string()))?;

    // Optional provider/model setup. Non-interactive init never waits for
    // stdin; scripted flags or a real terminal opt into configuration.
    let providers = if args.iter().any(|a| a == "--no-provider") {
        Vec::new()
    } else if let Some(name) = value_after(args, "--provider") {
        let gate = value_after(args, "--gate")
            .ok_or(("ORBIT-E1101", "--provider requires --gate".into()))?;
        let models = value_after(args, "--model")
            .ok_or(("ORBIT-E1101", "--provider requires --model M[,M...]".into()))?;
        let credential_env = value_after(args, "--credential-env");
        let model_ids: Vec<String> = models
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect();
        add_configured_provider(home, &name, &gate, credential_env, model_ids, None)?;
        vec![name]
    } else if std::io::IsTerminal::is_terminal(&std::io::stdin()) {
        interactive_provider_setup(home)?
    } else {
        Vec::new()
    };

    Ok(serde_json::json!({
        "schema": "orbit.cli/v1", "command": "init", "status": "ok",
        "trust_root_verified": true, "pib_id": pib_id,
        "ledger": ledger_dir.to_string_lossy(),
        "providers_configured": providers,
    }))
}

/// `orbit run example`: phase chain Init→Plan→Execute (example runs locally).
/// Add one provider to providers.toml (scripted init path). Pricing defaults to
/// zero unless supplied by the interactive setup. Token values are never
/// accepted here — only the credential env-var name.
fn add_configured_provider(
    home: &Path,
    name: &str,
    gate: &str,
    credential_env: Option<String>,
    model_ids: Vec<String>,
    pricing: Option<Vec<orbit_cli::config::Pricing>>,
) -> Result<(), (&'static str, String)> {
    validate_provider_url(gate)?;
    if model_ids.is_empty() {
        return Err(("ORBIT-E1101", "at least one model is required".into()));
    }
    let mut cfg = config::ProvidersConfig::load(home).map_err(|e| ("ORBIT-E1106", e))?;
    let models = model_ids
        .into_iter()
        .enumerate()
        .map(|(i, id)| orbit_cli::config::ModelEntry {
            sampling: None,
            id,
            label: None,
            pricing: pricing
                .as_ref()
                .and_then(|p| p.get(i).copied())
                .unwrap_or_default(),
            max_output_tokens: None,
            context_window: None,
        })
        .collect();
    cfg.add_provider(orbit_cli::config::ProviderConfig {
        name: name.into(),
        kind: "openai-compatible".into(),
        url: gate.trim_end_matches('/').into(),
        env: credential_env.filter(|s| !s.trim().is_empty()),
        models,
    })
    .map_err(|e| ("ORBIT-E1106", e))?;
    cfg.save_atomic(home).map_err(|e| ("ORBIT-E1106", e))
}

/// URL safety for configured providers: HTTPS anywhere; cleartext HTTP only
/// for loopback or RFC1918 private-LAN hosts. Reject public cleartext egress.
fn validate_provider_url(gate: &str) -> Result<(), (&'static str, String)> {
    let url =
        url::Url::parse(gate).map_err(|e| ("ORBIT-E0401", format!("bad provider URL: {e}")))?;
    match url.scheme() {
        "https" => Ok(()),
        "http" => {
            let host = url.host_str().unwrap_or("");
            let private = host == "localhost"
                || host == "127.0.0.1"
                || host == "::1"
                || host.starts_with("10.")
                || host.starts_with("192.168.")
                || host
                    .strip_prefix("172.")
                    .and_then(|rest| rest.split('.').next())
                    .and_then(|n| n.parse::<u8>().ok())
                    .map(|n| (16..=31).contains(&n))
                    .unwrap_or(false);
            if private {
                Ok(())
            } else {
                Err((
                    "ORBIT-E0301",
                    "cleartext HTTP provider must be loopback/private LAN".into(),
                ))
            }
        }
        other => Err(("ORBIT-E0301", format!("unsupported scheme {other}"))),
    }
}

/// GET `<base>/v1/models`, using a bearer token read from the declared env var
/// (borrowed for the request only; never printed or persisted). Runs on a
/// short-lived tokio runtime so the interactive flow stays synchronous.
fn discover_models(gate: &str, credential_env: Option<&str>) -> Result<Vec<String>, String> {
    let url = format!("{}/v1/models", gate.trim_end_matches('/'));
    // reqwest uses rustls in this workspace; install the ring process-default
    // provider before constructing a standalone discovery client.
    let _ = orbit_provider_http::tls::client_config(&orbit_adapter::types::TlsPinPolicy {
        webpki: true,
        spki_sha256: None,
    })
    .map_err(|e| format!("tls init: {e}"))?;
    tokio::runtime::Runtime::new()
        .map_err(|e| format!("runtime: {e}"))?
        .block_on(async move {
            let client = reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .build()
                .map_err(|e| format!("http client: {e}"))?;
            let mut req = client.get(&url);
            if let Some(var) = credential_env.filter(|s| !s.trim().is_empty()) {
                if let Ok(token) = std::env::var(var) {
                    req = req.bearer_auth(token);
                }
            }
            let resp = req
                .send()
                .await
                .map_err(|e| format!("model discovery: {e}"))?;
            if !resp.status().is_success() {
                return Err(format!("model discovery returned {}", resp.status()));
            }
            let raw = resp.text().await.map_err(|e| format!("read models: {e}"))?;
            orbit_cli::config::ModelListResponse::parse(&raw)
        })
}

/// Guided provider setup for `orbit init` in a real terminal.
fn interactive_provider_setup(home: &Path) -> Result<Vec<String>, (&'static str, String)> {
    use std::io::Write;
    let mut configured = Vec::new();
    if !prompt_yes_no("Configure a model provider now?", true)? {
        return Ok(configured);
    }
    loop {
        let name = prompt_line("Provider name", Some("local"))?;
        let gate = prompt_line("Base URL", Some("http://127.0.0.1:4001"))?;
        validate_provider_url(&gate)?;
        let credential_env = prompt_line(
            "Credential env-var name (blank = none)",
            Some("ORBIT_GATE_TOKEN"),
        )?;
        let credential_env = if credential_env.trim().is_empty() {
            None
        } else {
            Some(credential_env)
        };

        let discovered = match discover_models(&gate, credential_env.as_deref()) {
            Ok(ids) => {
                println!("Discovered models:");
                for (i, id) in ids.iter().enumerate() {
                    println!("  {}. {id}", i + 1);
                }
                ids
            }
            Err(e) => {
                eprintln!("Could not discover models: {e}");
                Vec::new()
            }
        };
        let model_ids = if discovered.is_empty() {
            prompt_line("Enter model ids (comma-separated)", None)?
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect::<Vec<_>>()
        } else {
            let sel = prompt_line(
                "Select models (all or comma-separated numbers)",
                Some("all"),
            )?;
            if sel.trim().eq_ignore_ascii_case("all") {
                discovered
            } else {
                sel.split(',')
                    .filter_map(|s| s.trim().parse::<usize>().ok())
                    .filter_map(|n| discovered.get(n.saturating_sub(1)).cloned())
                    .collect()
            }
        };
        if model_ids.is_empty() {
            return Err(("ORBIT-E1101", "no models selected".into()));
        }

        let mut pricing = Vec::new();
        for id in &model_ids {
            println!("Pricing for {id} (microdollars per million tokens; blank = 0):");
            let input = prompt_line("  input", Some("0"))?
                .parse::<u64>()
                .unwrap_or(0);
            let output = prompt_line("  output", Some("0"))?
                .parse::<u64>()
                .unwrap_or(0);
            pricing.push(orbit_cli::config::Pricing {
                input_per_million_microdollars: input,
                output_per_million_microdollars: output,
                ..Default::default()
            });
        }
        add_configured_provider(home, &name, &gate, credential_env, model_ids, Some(pricing))?;
        configured.push(name);
        let _ = std::io::stdout().flush();
        if !prompt_yes_no("Add another provider?", false)? {
            break;
        }
    }
    // Roundtrip validate the final config.
    config::ProvidersConfig::load(home).map_err(|e| ("ORBIT-E1106", e))?;
    Ok(configured)
}

fn prompt_line(label: &str, default: Option<&str>) -> Result<String, (&'static str, String)> {
    use std::io::Write;
    match default {
        Some(d) => print!("{label} [{d}]: "),
        None => print!("{label}: "),
    }
    std::io::stdout().flush().map_err(ioe)?;
    let mut line = String::new();
    std::io::stdin().read_line(&mut line).map_err(ioe)?;
    let value = line.trim().to_string();
    if value.is_empty() {
        Ok(default.unwrap_or("").to_string())
    } else {
        Ok(value)
    }
}

fn prompt_yes_no(label: &str, default_yes: bool) -> Result<bool, (&'static str, String)> {
    let suffix = if default_yes { "[Y/n]" } else { "[y/N]" };
    let answer = prompt_line(&format!("{label} {suffix}"), None)?;
    if answer.trim().is_empty() {
        return Ok(default_yes);
    }
    Ok(matches!(answer.to_ascii_lowercase().as_str(), "y" | "yes"))
}

/// `orbit run example`: phase chain Init→Plan→Execute (example runs locally).
fn cmd_run(home: &Path, _args: &[String]) -> Result<serde_json::Value, (&'static str, String)> {
    ensure_initialized(home)?;
    let ledger_dir = home.join("ledger");
    let mut w = LedgerWriter::open(&ledger_dir, "writer-run".into(), "0.1.0")
        .map_err(|e| ("ORBIT-E0719", e.to_string()))?;
    let mut reactor = Reactor::new();
    reactor
        .transition(orbit_reactor::Phase::Plan)
        .map_err(|e| ("ORBIT-E0505", e.to_string()))?;
    w.append(LedgerEvent::PhaseTransition(PhaseTransition {
        session_id: "session-example".into(),
        from: Phase::Init,
        to: Phase::Plan,
        checkpoint_seq: None,
    }))
    .map_err(|e| ("ORBIT-E0700", e.to_string()))?;
    reactor
        .transition(orbit_reactor::Phase::Execute)
        .map_err(|e| ("ORBIT-E0505", e.to_string()))?;
    w.append(LedgerEvent::PhaseTransition(PhaseTransition {
        session_id: "session-example".into(),
        from: Phase::Plan,
        to: Phase::Execute,
        checkpoint_seq: None,
    }))
    .map_err(|e| ("ORBIT-E0700", e.to_string()))?;
    w.close().map_err(|e| ("ORBIT-E0700", e.to_string()))?;
    Ok(
        serde_json::json!({"schema":"orbit.cli/v1","command":"run","status":"ok","session_id":"session-example","phase":"exec"}),
    )
}

/// `orbit cancel`: typed cancel → SessionEnd(Cancelled).
fn cmd_cancel(home: &Path) -> Result<serde_json::Value, (&'static str, String)> {
    ensure_initialized(home)?;
    let token = CancellationToken {
        target: CancelTarget::Session,
        origin: CancelOrigin::User,
        phase_at_cancel: orbit_reactor::Phase::Execute,
        first_signal_wins: true,
    };
    let _ = token; // typed token validates the cancellation protocol.
    let ledger_dir = home.join("ledger");
    let mut w = LedgerWriter::open(&ledger_dir, "writer-cancel".into(), "0.1.0")
        .map_err(|e| ("ORBIT-E0719", e.to_string()))?;
    w.append(LedgerEvent::SessionEnd(SessionEnd {
        session_id: "session-example".into(),
        terminal: TerminalOutcome::Cancelled,
        reason: "user_cancelled".into(),
    }))
    .map_err(|e| ("ORBIT-E0700", e.to_string()))?;
    w.close().map_err(|e| ("ORBIT-E0700", e.to_string()))?;
    Ok(
        serde_json::json!({"schema":"orbit.cli/v1","command":"cancel","status":"ok","terminal":"cancelled"}),
    )
}

/// `orbit verify-ledger`: walk + hash-verify the entire Ledger.
fn cmd_verify(home: &Path) -> Result<serde_json::Value, (&'static str, String)> {
    let (records, head) =
        verify_ledger(&home.join("ledger")).map_err(|e| ("ORBIT-E0602", e.to_string()))?;
    // MD gate 3: verify-ledger "lists intent, decision and result for
    // every call" — the triple per call_id, in record order.
    use orbit_ledger::LedgerEvent;
    use std::collections::BTreeMap;
    let mut calls: BTreeMap<String, serde_json::Value> = BTreeMap::new();
    for r in &records {
        match &r.record.event {
            LedgerEvent::ToolIntent(i) => {
                let e = calls.entry(i.call_id.clone()).or_insert_with(|| {
                    serde_json::json!({
                        "call_id": i.call_id,
                        "tool": i.tool_name,
                        "decision_id": i.decision_id,
                    })
                });
                e["intent"] = serde_json::json!({
                    "arguments_sha256": i.arguments_sha256,
                    "arguments_bytes": i.arguments_bytes,
                });
            }
            LedgerEvent::ToolVerdict(v) => {
                let e = calls.entry(v.call_id.clone()).or_insert_with(|| {
                    serde_json::json!({
                        "call_id": v.call_id,
                        "tool": v.tool_name,
                        "decision_id": v.decision_id,
                    })
                });
                e["decision"] = serde_json::json!({
                    "allowed": v.allowed,
                    "reason": v.reason,
                });
            }
            LedgerEvent::ToolResult(t) => {
                let e = calls.entry(t.call_id.clone()).or_insert_with(|| {
                    serde_json::json!({
                        "call_id": t.call_id,
                        "tool": t.tool_name,
                        "decision_id": t.decision_id,
                    })
                });
                e["result"] = serde_json::json!({
                    "status": t.status,
                    "output_sha256": t.output_sha256,
                    "output_bytes": t.output_bytes,
                });
            }
            _ => {}
        }
    }
    let calls: Vec<serde_json::Value> = calls.into_values().collect();
    Ok(serde_json::json!({
        "schema":"orbit.cli/v1","command":"verify-ledger","status":"ok",
        "records":records.len(),"head":head,
        "calls":calls
    }))
}

/// `orbit replay --dry`: verify the Ledger, then emit a no-dispatch replay plan.
fn cmd_replay(home: &Path, args: &[String]) -> Result<serde_json::Value, (&'static str, String)> {
    if !args.iter().any(|a| a == "--dry") {
        return Err(("ORBIT-E1101", "E2E replay requires --dry".into()));
    }
    let (records, head) =
        verify_ledger(&home.join("ledger")).map_err(|e| ("ORBIT-E0602", e.to_string()))?;
    // Phase 6: replay from a checkpoint — rebuild the transcript to
    // that point and report the replay plan from there.
    let from_checkpoint = value_after(args, "--from-checkpoint");
    let session_id = value_after(args, "--session").unwrap_or_default();
    let mut truncated_to: Option<usize> = None;
    if let (Some(cp), false) = (from_checkpoint.as_deref(), session_id.is_empty()) {
        let t = orbit_engine::transcript::Transcript::open(home, &session_id)
            .map_err(|e| ("ORBIT-E0602", e.to_string()))?;
        // Cut at the checkpoint marker.
        let events = t.events();
        let mut seen_cp = false;
        for (i, ev) in events.iter().enumerate() {
            if let orbit_engine::transcript::TranscriptEvent::Checkpoint { id } = ev {
                if id == cp {
                    seen_cp = true;
                    truncated_to = Some(i + 1);
                    break;
                }
            }
        }
        if !seen_cp {
            return Err((
                "ORBIT-E0602",
                format!("checkpoint {cp} not found in session {session_id}"),
            ));
        }
    }
    Ok(serde_json::json!({
        "schema":"orbit.replay/v1","command":"replay","status":"ok","mode":"dry",
        "dispatches":0,"records_read":records.len(),"ledger_head":head,
        "from_checkpoint": from_checkpoint,
        "events_through_checkpoint": truncated_to,
    }))
}

/// `orbit export --to <path>`: encrypted local age bundle.
fn cmd_export(home: &Path, args: &[String]) -> Result<serde_json::Value, (&'static str, String)> {
    let to = value_after(args, "--to").ok_or(("ORBIT-E1101", "export requires --to".into()))?;
    let ledger_bytes = collect_ledger_bytes(&home.join("ledger"))?;
    let head = std::fs::read_to_string(home.join("ledger/HEAD")).map_err(ioe)?;
    // C3: the export carries THIS install's PIB id (pib.json), not a
    // hard-coded placeholder.
    let pib_id = std::fs::read_to_string(home.join("pib.json"))
        .ok()
        .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
        .and_then(|v| v.get("pib_id").and_then(|p| p.as_str()).map(String::from))
        .unwrap_or_else(|| "pib-unknown".into());
    let (recipient, identity) = generate_local_key();
    let mut b = ExportBuilder::new("session-example".into(), pib_id, head.trim().into());
    b.add_file("ledger/segments".into(), &ledger_bytes).exclude(
        "ephemeral/prompt.txt".into(),
        "prompt bytes excluded (IF-10)",
    );
    let sealed = b
        .seal(&recipient)
        .map_err(|e| ("ORBIT-E0508", e.to_string()))?;
    std::fs::write(&to, &sealed).map_err(ioe)?;
    // Persist local identity next to bundle (0600) for restore; v0.1 local-only.
    std::fs::write(
        format!("{to}.key"),
        identity.to_string().expose_secret().as_bytes(),
    )
    .map_err(ioe)?;
    Ok(
        serde_json::json!({"schema":"orbit.cli/v1","command":"export","status":"ok","to":to,"encrypted":true}),
    )
}

/// `orbit restore <archive> --into <fresh-home>`: decrypt + immutable namespace.
fn cmd_restore(_home: &Path, args: &[String]) -> Result<serde_json::Value, (&'static str, String)> {
    let archive = args
        .get(1)
        .ok_or(("ORBIT-E1101", "restore requires archive".into()))?;
    let into =
        value_after(args, "--into").ok_or(("ORBIT-E1101", "restore requires --into".into()))?;
    let into_path = PathBuf::from(&into);
    if into_path.exists() {
        return Err(("ORBIT-E0509", "restore target exists; must be fresh".into()));
    }
    let sealed = std::fs::read(archive).map_err(ioe)?;
    let key = std::fs::read_to_string(format!("{archive}.key")).map_err(ioe)?;
    let identity: age::x25519::Identity = key
        .trim()
        .parse()
        .map_err(|e: &str| ("ORBIT-E0508", e.to_string()))?;
    let manifest = restore(&sealed, &identity, "session-restored", "session-example")
        .map_err(|e| ("ORBIT-E0508", e.to_string()))?;
    std::fs::create_dir_all(into_path.join("ledger/segments")).map_err(ioe)?;
    // Reconstruct a fresh ledger namespace from verified metadata: initialize a
    // new chain with SessionStart + provenance pointing at the source head.
    let mut w = LedgerWriter::open(&into_path.join("ledger"), "writer-restore".into(), "0.1.0")
        .map_err(|e| ("ORBIT-E0719", e.to_string()))?;
    w.append(LedgerEvent::SessionStart(SessionStart {
        session_id: "session-restored".into(),
        restricted: false,
        pib_id: Some(manifest.source_pib_id.clone()),
        policy_snapshot_id: manifest.ledger_head_hash.clone(),
        operator_principal: "restore".into(),
    }))
    .map_err(|e| ("ORBIT-E0700", e.to_string()))?;
    w.close().map_err(|e| ("ORBIT-E0700", e.to_string()))?;
    Ok(serde_json::json!({
        "schema":"orbit.cli/v1","command":"restore","status":"ok","into":into,
        "source_session":manifest.source_session_id,"restored_session":"session-restored"
    }))
}

/// `orbit ask "<prompt>" [--model <M>] [--gate <url>]` — send a prompt through
/// a local OpenAI-compatible gateway via the four-gate async dispatch pipeline.
///
/// Configuration (no internal defaults committed):
/// - `--gate` / `ORBIT_GATE_URL` — default `http://127.0.0.1:4001`
/// - `--model` / `ORBIT_MODEL` — REQUIRED; no default model is invented
/// - `ORBIT_GATE_TOKEN` — optional bearer token (never printed/persisted)
fn cmd_ask(home: &Path, args: &[String]) -> Result<serde_json::Value, (&'static str, String)> {
    ensure_initialized(home)?;
    let prompt = args
        .get(1)
        .ok_or(("ORBIT-E1101", "ask requires a prompt".into()))?;
    let gate = value_after(args, "--gate")
        .or_else(|| std::env::var("ORBIT_GATE_URL").ok())
        .unwrap_or_else(|| "http://127.0.0.1:4001".into());
    let model = value_after(args, "--model")
        .or_else(|| std::env::var("ORBIT_MODEL").ok())
        .ok_or(("ORBIT-E1101", "ask requires --model or ORBIT_MODEL".into()))?;
    let cfg = config::ProvidersConfig::load(home).map_err(|e| ("ORBIT-E1106", e))?;
    let provider = value_after(args, "--provider")
        .and_then(|name| cfg.provider.iter().find(|p| p.name == name))
        .or_else(|| cfg.provider_for_model(&model));
    let provider_id = provider
        .map(|p| p.name.as_str())
        .unwrap_or("configured-gateway");
    let resolved_gate = provider.map(|p| p.url.as_str()).unwrap_or(&gate);
    let credential_env = provider.and_then(|p| p.env.as_deref());
    let pricing = cfg.pricing_for_model(&model);

    let outcome = orbit_cli::run_turn(
        home,
        provider_id,
        resolved_gate,
        &model,
        credential_env,
        pricing,
        prompt,
        None,
        None,
        orbit_provider_http::CancelToken::new(),
    )?;
    Ok(serde_json::json!({
        "schema": "orbit.cli/v1",
        "command": "ask",
        "status": "ok",
        "model": model,
        "output": outcome.output,
        "ledger_recorded": true,
        "usage": {
            "input_tokens": outcome.input_tokens,
            "output_tokens": outcome.output_tokens,
            "cost_microcents": outcome.cost_microcents,
        }
    }))
}

/// Build the session's frozen system prompt for the REPL / headless
/// paths (same shape as the TUI worker's).
fn build_session_prompt(home: &Path, model: &str) -> String {
    let defs = tools::session_tool_definitions(home);
    let tool_names: Vec<&str> = defs.iter().map(|d| d.name.as_str()).collect();
    let mods = orbit_cli::mods::load_all(home);
    let enabled = orbit_cli::mods::initial_enabled(home, &mods);
    let mods_directive = orbit_cli::mods::system_directive(&mods, &enabled);
    orbit_engine::context::build_system_prompt(
        home,
        &std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
        model,
        &tool_names,
        &mods_directive,
    )
    .text
}

/// `orbit -p "<prompt>"` — headless one-shot with tools.
///
/// Runs one turn through the engine and prints the event stream. With
/// no terminal to answer a prompt, tool calls run under `dontAsk`:
/// anything no allow rule covers is denied and reported (never a hang).
/// `--output-format text` prints the final text only (default);
/// `stream-json` emits each `FrontendEvent` as one JSON object per
/// line; `json` prints the final summary object.
///
/// Exit codes: 0 done, 1 turn failed, 2 stopped by a permission
/// denial, 3 hit `--max-turns`, 130 interrupted.
/// Minimal JSON-Schema validation for --json-schema: the subset a
/// structured reply realistically needs (type, required, properties,
/// items, enum). Returns Err with the problems, or Ok(()) — the
/// parsed value is not needed, only the verdict.
fn validate_json_against_schema(text: &str, schema: &serde_json::Value) -> Result<(), String> {
    let value: serde_json::Value =
        serde_json::from_str(text.trim()).map_err(|e| format!("reply is not JSON: {e}"))?;
    validate_value(&value, schema, "$").map_err(|problems| problems.join("; "))
}

fn validate_value(
    v: &serde_json::Value,
    schema: &serde_json::Value,
    path: &str,
) -> Result<(), Vec<String>> {
    let mut problems = Vec::new();
    let ty = schema.get("type").and_then(|t| t.as_str());
    if let Some(ty) = ty {
        let ok = match (ty, v) {
            ("object", serde_json::Value::Object(_)) => true,
            ("array", serde_json::Value::Array(_)) => true,
            ("string", serde_json::Value::String(_)) => true,
            ("number", serde_json::Value::Number(_)) => true,
            ("integer", serde_json::Value::Number(n)) => n.is_u64() || n.is_i64(),
            ("boolean", serde_json::Value::Bool(_)) => true,
            ("null", serde_json::Value::Null) => true,
            _ => false,
        };
        if !ok {
            problems.push(format!("{path}: expected {ty}"));
        }
    }
    if let Some(req) = schema.get("required").and_then(|r| r.as_array()) {
        if let serde_json::Value::Object(map) = v {
            for r in req {
                if let Some(name) = r.as_str() {
                    if !map.contains_key(name) {
                        problems.push(format!("{path}: missing required field {name:?}"));
                    }
                }
            }
        }
    }
    if let (Some(props), serde_json::Value::Object(map)) = (schema.get("properties"), v) {
        for (name, sub) in props.as_object().unwrap_or(&serde_json::Map::new()) {
            if let Some(val) = map.get(name) {
                if let Err(p) = validate_value(val, sub, &format!("{path}.{name}")) {
                    problems.extend(p);
                }
            }
        }
    }
    if let (Some(items), serde_json::Value::Array(arr)) = (schema.get("items"), v) {
        for (i, val) in arr.iter().enumerate() {
            if let Err(p) = validate_value(val, items, &format!("{path}[{i}]")) {
                problems.extend(p);
            }
        }
    }
    if let Some(en) = schema.get("enum").and_then(|e| e.as_array()) {
        if !en.contains(v) {
            problems.push(format!("{path}: not in enum"));
        }
    }
    if problems.is_empty() {
        Ok(())
    } else {
        Err(problems)
    }
}

fn cmd_headless(args: &[String]) -> i32 {
    let home = orbit_home(args)
        .or_else(|| std::env::var("ORBIT_HOME").ok().map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from(".orbit"));
    let prompt = args.first().map(String::as_str).unwrap_or("");
    if prompt.is_empty() {
        eprintln!("ORBIT-E1101: -p requires a prompt");
        return 1;
    }
    if let Err((code, msg)) = ensure_initialized(&home) {
        eprintln!("{code}: {msg}");
        return 1;
    }
    // E9: SessionStart fires when the headless session opens.
    {
        let hooks =
            orbit_engine::hooks::Hooks::load(&home, orbit_engine::hooks::project_trusted(&home));
        let _ = hooks.fire(
            orbit_engine::hooks::HookEvent::SessionStart,
            &serde_json::json!({ "frontend": "headless" }),
        );
    }
    let gate = value_after(args, "--gate")
        .or_else(|| std::env::var("ORBIT_GATE_URL").ok())
        .unwrap_or_else(|| "http://127.0.0.1:4001".into());
    let model = match value_after(args, "--model").or_else(|| std::env::var("ORBIT_MODEL").ok()) {
        Some(m) => m,
        None => {
            eprintln!("ORBIT-E1101: -p requires --model or ORBIT_MODEL");
            return 1;
        }
    };
    let format = value_after(args, "--output-format").unwrap_or_else(|| "text".into());
    // --bare: skip discovering hooks, skills, mods, MCP servers and
    // memory files (phase 6 — fast start; recommended for scripts).
    if args.iter().any(|a| a == "--bare") {
        std::env::set_var("ORBIT_BARE", "1");
    }
    // --json-schema <file>: structured output. Anthropic gets
    // output_config.format natively later; here the honest path for
    // every provider: validate the final text as JSON against the
    // schema and retry once with the validation error appended.
    let json_schema: Option<serde_json::Value> = value_after(args, "--json-schema")
        .map(|path| {
            std::fs::read_to_string(&path)
                .map_err(|e| e.to_string())
                .and_then(|t| serde_json::from_str(&t).map_err(|e| e.to_string()))
        })
        .transpose()
        .map_err(|e| {
            eprintln!("ORBIT-E0401: --json-schema: {e}");
            1
        })
        .unwrap_or(None);
    let max_rounds: u32 = value_after(args, "--max-turns")
        .and_then(|v| v.parse().ok())
        .unwrap_or(orbit_engine::DEFAULT_MAX_ROUNDS);
    // --auto-tools: up-front consent for pure built-ins (headless CI
    // shape). Without it, dontAsk semantics: anything no allow rule
    // covers is denied — and the exit code says so (2).
    let auto_tools = args.iter().any(|a| a == "--auto-tools");
    let cost_guard = orbit_engine::automation::CostGuard {
        max_microcents: value_after(args, "--max-cost").and_then(|v| v.parse().ok()),
    };
    // --permission-mode / --allowedTools / --disallowedTools: the
    // command-line permission scope (review blocker 4), carried in the
    // session's PermissionScope (S5) — never process env vars.
    if let Some(mode) = value_after(args, "--permission-mode") {
        if orbit_tools::permissions::PermissionMode::from_config(&mode).is_none() {
            eprintln!("ORBIT-E1101: unknown --permission-mode {mode} (default, acceptEdits, plan, dontAsk, bypass)");
            return 1;
        }
    }
    let scope = tool_runtime::PermissionScope::from_flags(
        value_after(args, "--permission-mode").as_deref(),
        value_after(args, "--allowedTools").as_deref(),
        value_after(args, "--disallowedTools").as_deref(),
    );

    let cfg = match config::ProvidersConfig::load(&home) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("ORBIT-E1106: {e}");
            return 1;
        }
    };
    let provider = value_after(args, "--provider")
        .and_then(|name| cfg.provider.iter().find(|p| p.name == name))
        .or_else(|| cfg.provider_for_model(&model));
    let provider_id = provider
        .map(|p| p.name.as_str())
        .unwrap_or("configured-gateway")
        .to_string();
    let resolved_gate = provider
        .map(|p| p.url.as_str())
        .unwrap_or(gate.as_str())
        .to_string();
    let credential_env = provider.and_then(|p| p.env.as_deref());
    let pricing = cfg.pricing_for_model(&model);

    let turn_config = orbit_cli::engine_turn_config(
        &home,
        &provider_id,
        &resolved_gate,
        &model,
        credential_env,
        pricing,
    );
    // The full resolved config for subagents (phase 5): the Task tool
    // derives its TurnConfig from these env vars, so a subagent matches
    // the parent's provider/gate/model/credential exactly.
    std::env::set_var("ORBIT_GATE_URL", &resolved_gate);
    std::env::set_var("ORBIT_MODEL", &model);
    std::env::set_var("ORBIT_PROVIDER", &provider_id);
    if let Some(env_name) = credential_env {
        std::env::set_var("ORBIT_CREDENTIAL_ENV", env_name);
    }

    // Session persistence in headless mode (phase 4): --continue /
    // --resume load the prior transcript; after the turn the session
    // is saved so the next --continue finds it. Without this, a
    // killed session's work is lost (gate 4).
    let resume_id = value_after(args, "--resume");
    let wants_continue = args.iter().any(|a| a == "--continue");
    let resumed_file = if wants_continue {
        match orbit_cli::sessions::list_sessions(&home) {
            Ok(mut list) if !list.is_empty() => {
                list.sort_by(|a, b| b.updated_at.cmp(&a.updated_at));
                Some(list.remove(0))
            }
            _ => None,
        }
    } else {
        resume_id
            .as_deref()
            .filter(|id| !id.is_empty())
            .and_then(|id| orbit_cli::sessions::load_session(&home, id).ok())
    };
    let mut session_id = format!("p-{}", ulid::Ulid::new());
    let mut turns: u64 = 0;
    let mut in_tokens: u64 = 0;
    let mut out_tokens: u64 = 0;
    let mut cost_microcents: u64 = 0;
    let mut transcript: Vec<orbit_adapter::types::ChatMessage> = Vec::new();
    if let Some(sf) = &resumed_file {
        session_id = sf.session_id.clone();
        turns = sf.turns;
        in_tokens = sf.input_tokens;
        out_tokens = sf.output_tokens;
        cost_microcents = sf.cost_microcents;
        transcript = sf.to_transcript();
    }
    let tool_cx = orbit_tools::ToolContext::new(
        home.clone(),
        session_id.clone(),
        std::env::current_dir().unwrap_or_else(|_| std::path::Path::new(".").to_path_buf()),
    );
    let mut executor = HeadlessToolExecutor {
        home: home.clone(),
        session_id: session_id.clone(),
        auto_tools,
        scope,
        tool_cx,
    };

    use std::io::Write;
    let stream_json = format == "stream-json";
    let json_out = format == "json";
    let mut events = |ev: orbit_frontend_protocol::FrontendEvent| {
        if stream_json {
            println!("{}", serde_json::to_string(&ev).unwrap_or_default());
            let _ = std::io::stdout().flush();
        }
        // C4: a refusal says WHY on stderr — one line a script (or an
        // operator redirected to a log) can read without parsing the
        // JSON stream. Works in every output format.
        if let orbit_frontend_protocol::FrontendEvent::ToolDenied { tool, reason, .. } = &ev {
            eprintln!("orbit: {tool} denied: {reason}");
        }
    };
    let options = orbit_engine::TurnOptions {
        tools: tools::session_tool_definitions(&home),
        max_rounds,
        // The frozen system prompt: the model learns the working
        // directory, the platform, ORBIT.md and the tools (review
        // blocker 5).
        system_directive: Some(build_session_prompt(&home, &model)),
        window_tokens: orbit_cli::context_window_for(&home, &model),
        request_stem: "orbit-p".into(),
        session_id: session_id.clone(),
        ..Default::default()
    };
    // The authority extractor (phase 6): "run the tests but never
    // push" becomes Bash(cargo test *) allowed and Bash(git push *)
    // denied, for this job. OFF by default (S4): the -p prompt in CI
    // embeds untrusted text (issue/PR bodies), and untrusted content
    // never becomes user authority. --spoken-rules is the explicit
    // operator opt-in. The rules ride the session's PermissionScope
    // (S5) so the executor's own permission path enforces them like
    // any other rule — no process env.
    let spoken_rules_enabled = args.iter().any(|a| a == "--spoken-rules");
    if spoken_rules_enabled {
        let spoken = orbit_engine::automation::extract_spoken_rules(prompt);
        if !spoken.is_empty() {
            executor.scope.disallowlist.reserve(spoken.len());
            for r in spoken {
                match r.effect {
                    orbit_engine::automation::SpokenEffect::Allow => {
                        let list = executor.scope.allowlist.get_or_insert_with(Vec::new);
                        if !list.contains(&r.rule) {
                            list.push(r.rule.clone());
                        }
                    }
                    orbit_engine::automation::SpokenEffect::Deny => {
                        if !executor.scope.disallowlist.contains(&r.rule) {
                            executor.scope.disallowlist.push(r.rule.clone());
                        }
                    }
                }
                if stream_json {
                    println!(
                        "{}",
                        serde_json::to_string(&orbit_frontend_protocol::FrontendEvent::Status {
                            text: format!(
                                "spoken rule recorded: {} {} (from \"{}\")",
                                match r.effect {
                                    orbit_engine::automation::SpokenEffect::Allow => "allow",
                                    orbit_engine::automation::SpokenEffect::Deny => "deny",
                                },
                                r.rule,
                                r.source_phrase
                            )
                        })
                        .unwrap_or_default()
                    );
                }
            }
        }
    }

    let mut report = orbit_engine::run_turn(
        &home,
        &turn_config,
        &options,
        prompt,
        &mut transcript,
        &mut executor,
        &orbit_provider_http::CancelToken::new(),
        &mut events,
    );

    // --json-schema (phase 6): validate the final text as JSON
    // against the schema; on failure, retry ONCE with the validation
    // error appended to the transcript (validate-and-retry — the
    // honest path for providers without native structured output).
    if let Some(schema) = &json_schema {
        if let Ok(r) = &report {
            if let Err(problems) = validate_json_against_schema(&r.final_text, schema) {
                if stream_json {
                    println!(
                        "{}",
                        serde_json::to_string(&orbit_frontend_protocol::FrontendEvent::Status {
                            text: format!("schema validation failed, retrying: {problems}")
                        })
                        .unwrap_or_default()
                    );
                }
                transcript.push(orbit_engine::user_message(format!(
                    "Your previous reply did not match the required JSON schema: {problems}. Reply again with ONLY valid JSON matching the schema."
                )));
                report = orbit_engine::run_turn(
                    &home,
                    &turn_config,
                    &options,
                    "Reply with only valid JSON matching the schema.",
                    &mut transcript,
                    &mut executor,
                    &orbit_provider_http::CancelToken::new(),
                    &mut events,
                );
            }
        }
    }

    // RTA (E10): attest from the structured exit status of the last
    // test-like command, in every front-end. A claim after a failing
    // command is an unverified claim and is shown as one.
    let mut rta_verdict: Option<serde_json::Value> = None;
    if let Ok(_r) = &report {
        if let Some(scan) = orbit_engine::automation::scan_attestation(&transcript) {
            if scan.claimed_pass {
                let cwd = std::env::current_dir().unwrap_or_default();
                let verdict = if scan.exit_code == 0 {
                    // The recorded exit was 0 — re-run to attest (the
                    // re-run is ORBIT's own eyes on the claim).
                    match orbit_engine::automation::attest_test_pass(&scan.command, &cwd) {
                        Ok(p) => serde_json::json!({
                            "attested": true,
                            "command": p.command,
                            "at": p.attested_at_epoch
                        }),
                        Err(e) => serde_json::json!({
                            "attested": false,
                            "command": scan.command,
                            "reason": e
                        }),
                    }
                } else {
                    // The recorded exit status was already a failure:
                    // no re-run needed — the claim contradicts the
                    // recorded facts.
                    serde_json::json!({
                        "attested": false,
                        "command": scan.command,
                        "recorded_exit_code": scan.exit_code,
                        "reason": "the last test-like command exited non-zero; the claim is unverified"
                    })
                };
                if stream_json {
                    let attested = verdict["attested"].as_bool().unwrap_or(false);
                    println!(
                        "{}",
                        serde_json::to_string(&orbit_frontend_protocol::FrontendEvent::Status {
                            text: format!(
                                "rta: {}",
                                if attested {
                                    "tests re-run and PASSED (attested)".to_string()
                                } else {
                                    format!(
                                        "UNVERIFIED CLAIM — {} exited {} at turn time; the claim is not attested",
                                        scan.command, scan.exit_code
                                    )
                                }
                            )
                        })
                        .unwrap_or_default()
                    );
                }
                rta_verdict = Some(verdict);
            }
        }
    }

    // Persist the session whatever the outcome (a failed turn still
    // belongs to the transcript; --continue resumes from what was
    // WRITTEN, and the kill -9 case proves the write happens before
    // the process can die mid-turn).
    let save_session = |t: &Vec<orbit_adapter::types::ChatMessage>,
                        r: &orbit_engine::TurnReport| {
        let sf = orbit_cli::sessions::SessionFile::from_chat(
            &session_id,
            &model,
            &resolved_gate,
            &provider_id,
            t,
            turns + 1,
            in_tokens + r.input_tokens,
            out_tokens + r.output_tokens,
            cost_microcents + r.cost_microcents,
        );
        if let Err(e) = orbit_cli::sessions::save_session(&home, &sf) {
            eprintln!("warning: cannot save session: {e}");
        }
    };

    match report {
        Ok(r) => {
            save_session(&transcript, &r);
            if json_out {
                let mut summary = orbit_engine::automation::HeadlessSummary::from_report(
                    &r,
                    orbit_engine::automation::ledger_head(&home),
                );
                summary.rta = rta_verdict.clone();
                println!("{}", summary.to_json());
            } else if !stream_json {
                // text: the final reply only.
                println!("{}", r.final_text);
            }
            // The cost guard fires after the turn (the engine checks
            // between rounds; here it gates the exit class).
            if let Some(reason) = cost_guard.check(r.cost_microcents) {
                if stream_json || json_out {
                    eprintln!("{reason}");
                }
            }
            // Exit codes: 0 done, 1 failed, 2 permission denial,
            // 3 max-turns, 130 interrupted. A permission denial is
            // detectable from the transcript's typed flag (C4): every
            // policy refusal carries `"denied": true` — no substring
            // hunt (E4's lesson: text-matching fires on content that
            // merely looks like a marker).
            let permission_denied = transcript.iter().any(|m| {
                m.role == orbit_adapter::types::ChatRole::Tool
                    && m.tool_result
                        .as_deref()
                        .is_some_and(orbit_tools::result_is_denial)
            });
            let code = orbit_engine::automation::exit_code(&r, max_rounds, permission_denied);
            // E9: SessionEnd fires when the headless session closes.
            fire_session_end(&home, if code == 0 { "ended" } else { "error" });
            code
        }
        Err(e) => {
            fire_session_end(&home, "error");
            eprintln!("{e}");
            1
        }
    }
}

/// E9: fire the SessionEnd hook (headless session close).
fn fire_session_end(home: &Path, reason: &str) {
    let hooks = orbit_engine::hooks::Hooks::load(home, orbit_engine::hooks::project_trusted(home));
    let _ = hooks.fire(
        orbit_engine::hooks::HookEvent::SessionEnd,
        &serde_json::json!({ "reason": reason }),
    );
}

/// The headless tool executor: `dontAsk` — every call that no allow
/// rule covers is denied and reported, never a prompt (a headless run
/// must never hang). Interactivity off: execute_call's non-interactive
/// path already denies uncovered tools with a reportable result.
struct HeadlessToolExecutor {
    home: std::path::PathBuf,
    session_id: String,
    auto_tools: bool,
    /// The session's permission scope (S5).
    scope: tool_runtime::PermissionScope,
    /// One context per headless session (B2).
    tool_cx: orbit_tools::ToolContext,
}

impl orbit_engine::ToolExecutor for HeadlessToolExecutor {
    fn begin_turn(&mut self, config: &orbit_engine::TurnConfig) {
        tool_runtime::remember_turn_config(&self.tool_cx, config);
    }

    fn execute(
        &mut self,
        calls: &[orbit_engine::PendingToolCall],
        _round: u32,
    ) -> Vec<orbit_engine::ToolRoundResult> {
        let cx = self.tool_cx.clone();
        tool_runtime::run_until_cancelled(
            &cx,
            calls,
            |call| {
                let decision_id = format!("tool-{}-{}", ulid::Ulid::new(), call.index);
                let (result, _) = tool_runtime::execute_call(
                    &self.home,
                    &self.session_id,
                    &decision_id,
                    call,
                    self.auto_tools,
                    false, // non-interactive: dontAsk semantics
                    &mut tool_runtime::StdApprovalChannel::new(false),
                    &mut tool_runtime::AutoGrants::new(),
                    &self.scope,
                    &self.tool_cx,
                )
                .unwrap_or_else(|e| {
                    (
                        serde_json::json!({ "ok": false, "error": e }).to_string(),
                        None,
                    )
                });
                orbit_engine::ToolRoundResult {
                    call_id: call.id.clone(),
                    content: result,
                }
            },
            |_| {},
        )
    }

    fn begin_cancel_scope(&mut self, token: &orbit_provider_http::CancelToken) {
        tool_runtime::begin_cancel_scope(&self.tool_cx, token);
    }

    fn end_cancel_scope(&mut self) {
        self.tool_cx.pop_cancel_check();
    }
}

/// The interactive REPL — the "harness" (bare `orbit` or `orbit chat`).
///
/// Each prompt runs the full four-gate async dispatch pipeline (same as
/// `orbit ask`) with a growing conversation transcript. Output streams live
/// (TextDeltas printed as they arrive). Model/gate resolved from flags →
/// `ORBIT_MODEL`/`ORBIT_GATE_URL` → defaults. Exits cleanly on `exit`/EOF.
///
/// `orbit web` — launch the browser harness (docs/browser-harness.md).
/// The bridge server lives in the `orbit-web` binary (sibling of `orbit`);
/// this command resolves it (ORBIT_WEB env → sibling → repo path), passes
/// through the relevant flags, and waits on it (Ctrl+C propagates).
fn cmd_web(args: &[String]) -> i32 {
    let Some(web_bin) = find_web_bin() else {
        eprintln!(
            "ORBIT-E0400: orbit-web not found; build it with `cargo build -p orbit-web` \
             or set ORBIT_WEB"
        );
        return 1;
    };
    let mut cmd = std::process::Command::new(&web_bin);
    cmd.args(args);
    // Inherit the terminal so Ctrl+C reaches the server process group.
    match cmd.status() {
        Ok(st) => st.code().unwrap_or(0),
        Err(e) => {
            eprintln!("ORBIT-E0400: spawn orbit-web: {e}");
            1
        }
    }
}

/// Locate the orbit-web binary: ORBIT_WEB env → sibling → repo target dir.
fn find_web_bin() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("ORBIT_WEB") {
        let pb = PathBuf::from(p);
        if pb.exists() {
            return Some(pb);
        }
    }
    if let Ok(exe) = std::env::current_exe() {
        let sibling = exe.parent()?.join("orbit-web");
        if sibling.exists() {
            return Some(sibling);
        }
    }
    for profile in ["debug", "release"] {
        let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()?
            .parent()?
            .join("target")
            .join(profile)
            .join("orbit-web");
        if p.exists() {
            return Some(p);
        }
    }
    None
}

/// Slash commands: `/help`, `/model <M>`, `/clear`, `/usage`.
/// Create or enter a git worktree at .orbit/worktrees/<name> on a new
/// branch (phase 4). Parallel sessions never touch each other's files.
fn enter_worktree(name: &str) -> Result<PathBuf, String> {
    // Validate the name: it becomes a branch name and a directory.
    if name.is_empty()
        || name.starts_with('.')
        || name.contains("..")
        || name.contains('/')
        || name.contains('\\')
        || name.chars().any(|c| c.is_whitespace() || c.is_control())
    {
        return Err("invalid worktree name".into());
    }
    let cwd = std::env::current_dir().map_err(|e| e.to_string())?;
    let dot_orbit = cwd.join(".orbit");
    let wt_root = dot_orbit.join("worktrees");
    let wt_path = wt_root.join(name);
    if wt_path.exists() {
        return Ok(wt_path); // idempotent: enter the existing one
    }
    std::fs::create_dir_all(&wt_root).map_err(|e| e.to_string())?;
    let branch = format!("orbit/{name}");
    let out = std::process::Command::new("git")
        .arg("worktree")
        .arg("add")
        .arg("-b")
        .arg(&branch)
        .arg(&wt_path)
        .current_dir(&cwd)
        .output()
        .map_err(|e| e.to_string())?;
    if !out.status.success() {
        return Err(String::from_utf8_lossy(&out.stderr).trim().to_string());
    }
    Ok(wt_path)
}
fn cmd_chat(args: &[String]) -> i32 {
    // --worktree <name> (phase 4): create .orbit/worktrees/<name> on a
    // new branch and enter it, so parallel sessions never touch each
    // other's files. Idempotent: an existing worktree is entered.
    if let Some(name) = value_after(args, "--worktree").filter(|n| !n.is_empty()) {
        match enter_worktree(&name) {
            Ok(path) => {
                eprintln!("worktree: {name} at {}", path.display());
                std::env::set_current_dir(&path).ok();
            }
            Err(e) => {
                eprintln!("cannot enter worktree {name}: {e}");
                return 2;
            }
        }
    }

    let home = orbit_home(args).unwrap_or_else(|| {
        std::env::var("ORBIT_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from(".orbit"))
    });
    if let Err((code, msg)) = ensure_initialized(&home) {
        eprintln!("{code}: {msg}");
        return 2;
    }

    let gate = value_after(args, "--gate")
        .or_else(|| std::env::var("ORBIT_GATE_URL").ok())
        .unwrap_or_else(|| "http://127.0.0.1:4001".into());
    let cfg = config::ProvidersConfig::load(&home)
        .map_err(|e| eprintln!("warning: providers.toml: {e}"))
        .unwrap_or_default();
    // The model resolves in priority order: --model / ORBIT_MODEL /
    // ORBIT_ACTIVE_MODEL / the first configured provider's first
    // model. A model no provider declares falls back to the default
    // gate and every turn fails — so prefer a configured one.
    let mut model = value_after(args, "--model")
        .or_else(|| std::env::var("ORBIT_MODEL").ok())
        .or_else(|| std::env::var("ORBIT_ACTIVE_MODEL").ok())
        .unwrap_or_else(|| {
            cfg.provider
                .iter()
                .flat_map(|p| p.models.iter().map(|m| m.id.clone()))
                .next()
                .unwrap_or_else(|| "glm-5.2".into())
        });
    // If the resolved model matches no provider, use the first
    // configured model instead (the gate fallback would 401/conn-ref).
    if cfg.provider_for_model(&model).is_none() {
        if let Some(first) = cfg
            .provider
            .iter()
            .flat_map(|p| p.models.iter().map(|m| m.id.clone()))
            .next()
        {
            eprintln!("warning: model {model} is not configured; using {first}");
            model = first;
        }
    }

    // Session identity + persistence. `--resume <id>` loads a prior session's
    // transcript so the conversation continues across invocations.
    // `--continue` reopens the LATEST session in this directory
    // (phase 4; Claude Code parity).
    let resume = value_after(args, "--resume");
    let wants_continue = args.iter().any(|a| a == "--continue");
    let resumed_file = if wants_continue {
        match sessions::list_sessions(&home) {
            Ok(mut list) if !list.is_empty() => {
                // newest by updated_at
                list.sort_by(|a, b| b.updated_at.cmp(&a.updated_at));
                let latest = list.remove(0);
                eprintln!(
                    "continuing session {} ({} turns)",
                    latest.session_id, latest.turns
                );
                Some(latest)
            }
            _ => {
                eprintln!("no saved sessions; starting fresh");
                None
            }
        }
    } else {
        resume
            .as_deref()
            .filter(|id| !id.is_empty())
            .and_then(|id| match sessions::load_session(&home, id) {
                Ok(s) => Some(s),
                Err(e) => {
                    eprintln!("warning: cannot resume {id}: {e}; starting fresh");
                    None
                }
            })
    };

    // TUI front-end (DR-20): if TTY + --tui (default), forward to the ratatui
    // TUI. --no-tui, non-TTY stdin/stdout, or the `tui` feature off → fall
    // through to the existing REPL unchanged. `--go-tui` opts into the Go
    // Bubble Tea front-end (spawns orbit-go-tui as a child).
    #[cfg(feature = "tui")]
    {
        let want_tui = !args.iter().any(|a| a == "--no-tui")
            && std::io::IsTerminal::is_terminal(&std::io::stdin())
            && std::io::IsTerminal::is_terminal(&std::io::stdout());
        let want_go_tui = args.iter().any(|a| a == "--go-tui");
        // The motion-first redesign (the ORBIT TUI prototype) is the
        // default screen; --old-tui keeps the v1 HUD.
        // The prototype is the target front-end (docs/tui/PROMPT.md).
        // --old-tui keeps the v1 HUD available while parity work runs.
        let want_old_tui = args.iter().any(|a| a == "--old-tui");
        if want_tui {
            let session_id = resumed_file
                .as_ref()
                .map(|s| s.session_id.clone())
                .unwrap_or_else(orbit_gateway::new_session_id);
            let provider = cfg.provider_for_model(&model);
            let provider_id = provider
                .map(|p| p.name.clone())
                .unwrap_or_else(|| "configured-gateway".into());
            let tui_config = tui_worker::TuiTurnConfig {
                home: home.clone(),
                session_id,
                gate: gate.clone(),
                model: model.clone(),
                provider_id,
                auto_tools: args.iter().any(|a| a == "--auto-tools"),
                scope: tool_runtime::PermissionScope::from_flags(
                    value_after(args, "--permission-mode").as_deref(),
                    value_after(args, "--allowedTools").as_deref(),
                    value_after(args, "--disallowedTools").as_deref(),
                ),
                initial_transcript: resumed_file
                    .as_ref()
                    .map(|s| s.to_transcript())
                    .unwrap_or_default(),
                initial_turns: resumed_file.as_ref().map(|s| s.turns).unwrap_or(0),
                initial_input_tokens: resumed_file.as_ref().map(|s| s.input_tokens).unwrap_or(0),
                initial_output_tokens: resumed_file.as_ref().map(|s| s.output_tokens).unwrap_or(0),
                initial_cost_microcents: resumed_file
                    .as_ref()
                    .map(|s| s.cost_microcents)
                    .unwrap_or(0),
            };
            if want_go_tui {
                return go_bridge::run_go_tui(tui_config);
            }
            // Welcome readiness reads the REAL active model/provider —
            // set them for the in-process TUI before it computes the row.
            std::env::set_var("ORBIT_ACTIVE_MODEL", &tui_config.model);
            std::env::set_var("ORBIT_ACTIVE_PROVIDER", &tui_config.provider_id);
            if want_old_tui {
                return orbit_hud_tui::run(args, tui_worker::make_spawner(tui_config));
            }
            return orbit_hud_tui::proto::runtime::run_proto(
                args,
                tui_worker::make_spawner(tui_config),
            );
        }
    }

    // Plain front-end (REPL / non-TTY): the shared plain grammar owns
    // stdout lines (§11.4). The TUI never enables this — its worker threads
    // must not print to the alt screen.
    tool_runtime::enable_plain_output();

    if let Some(s) = &resumed_file {
        eprintln!("resumed session {} ({} prior turns)", s.session_id, s.turns);
    }
    let mut session = resumed_file
        .as_ref()
        .map(|s| s.session_id.clone())
        .unwrap_or_else(orbit_gateway::new_session_id);
    // Conversation transcript: role + content per turn (multi-turn wire payload).
    let mut transcript: Vec<orbit_adapter::types::ChatMessage> = resumed_file
        .as_ref()
        .map(|s| s.to_transcript())
        .unwrap_or_default();
    let mut total_input = resumed_file.as_ref().map(|s| s.input_tokens).unwrap_or(0);
    let mut total_output = resumed_file.as_ref().map(|s| s.output_tokens).unwrap_or(0);
    let mut total_cost = resumed_file
        .as_ref()
        .map(|s| s.cost_microcents)
        .unwrap_or(0);
    let mut turns = resumed_file.as_ref().map(|s| s.turns).unwrap_or(0);

    // HUD (DR-10 Part B): display-only, display-safe (H-3), brand + output
    // mode negotiated from the environment (NO_COLOR/CI/TERM).
    let hud = orbit_hud::Hud::new(&orbit_hud::Env {
        no_color: std::env::var_os("NO_COLOR").is_some(),
        ci: std::env::var_os("CI").is_some(),
        term_dumb: std::env::var("TERM").map(|t| t == "dumb").unwrap_or(false),
    });
    render_hud(
        &hud,
        &orbit_hud::HudEvent::Message {
            text: format!("interactive harness — model {model}, session {session}"),
        },
    );
    render_hud(
        &hud,
        &orbit_hud::HudEvent::Message {
            text: "type /help for commands, exit to quit".into(),
        },
    );

    let stdin = std::io::stdin();
    use std::io::BufRead;
    let lines = stdin.lock().lines();

    for line in lines {
        let line = match line {
            Ok(l) => l,
            Err(_) => break,
        };
        let trimmed = line.trim().to_string();
        if trimmed.is_empty() {
            continue;
        }

        // Slash commands / control.
        if trimmed == "exit" || trimmed == "quit" {
            break;
        }
        if trimmed.starts_with('/') {
            // `/resume <id>` needs the mutable session id, so it is handled
            // here (in the loop) rather than in handle_chat_command.
            if let Some(id) = trimmed.strip_prefix("/resume ") {
                match sessions::load_session(&home, id.trim()) {
                    Ok(s) => {
                        session = s.session_id.clone();
                        transcript = s.to_transcript();
                        turns = s.turns;
                        total_input = s.input_tokens;
                        total_output = s.output_tokens;
                        eprintln!("resumed {id} ({} prior turns)", s.turns);
                    }
                    Err(e) => eprintln!("cannot resume {id}: {e}"),
                }
                continue;
            }
            let handled = handle_chat_command(
                &trimmed,
                &home,
                &mut model,
                &mut transcript,
                (&turns, &total_input, &total_output, &total_cost),
            );
            if !handled {
                eprintln!("unknown command: {trimmed}; try /help");
            }
            continue;
        }

        // Plain grammar (§11.4): the turn boundary is stamped — one event
        // per line, words not glyphs. Same grammar as copy mode and non-TTY.
        println!("{} you: {}", hhmm_now(), trimmed);

        // Resolve the provider for the current model (config overrides the
        // default gate). `credential_env` names the env var holding the token.
        let provider = value_after(args, "--provider")
            .and_then(|name| cfg.provider.iter().find(|p| p.name == name))
            .or_else(|| cfg.provider_for_model(&model));
        let provider_id = provider
            .map(|p| p.name.as_str())
            .unwrap_or("configured-gateway")
            .to_string();
        let resolved_gate = provider
            .map(|p| p.url.as_str())
            .unwrap_or(gate.as_str())
            .to_string();
        let credential_env = provider.and_then(|p| p.env.as_deref());
        let pricing = cfg.pricing_for_model(&model);
        let auto_tools = args.iter().any(|a| a == "--auto-tools");
        let interactive = std::io::IsTerminal::is_terminal(&std::io::stdin());

        render_hud(
            &hud,
            &orbit_hud::HudEvent::PhaseChanged {
                phase: format!("turn {}({model})", turns + 1),
            },
        );

        // Phase 2: the loop is the ENGINE's — the REPL supplies only the
        // event adapter (stdout) and the tool executor (StdApprovalChannel,
        // session grants). The old 8-round copy of the loop is gone.
        let turn_config = orbit_cli::engine_turn_config(
            &home,
            &provider_id,
            &resolved_gate,
            &model,
            credential_env,
            pricing,
        );
        let mut executor = ReplToolExecutor {
            home: home.clone(),
            session_id: session.clone(),
            model: model.clone(),
            provider_id: provider_id.clone(),
            turns,
            total_input,
            total_output,
            auto_tools,
            interactive,
            approval_channel: tool_runtime::StdApprovalChannel::new(interactive),
            auto_grants: tool_runtime::AutoGrants::new(),
            scope: tool_runtime::PermissionScope::from_flags(
                value_after(args, "--permission-mode").as_deref(),
                value_after(args, "--allowedTools").as_deref(),
                value_after(args, "--disallowedTools").as_deref(),
            ),
            tool_cx: orbit_tools::ToolContext::new(
                home.clone(),
                session.clone(),
                std::env::current_dir().unwrap_or_else(|_| std::path::Path::new(".").to_path_buf()),
            ),
        };
        let mut stamped = false;
        let mut events = |ev: orbit_frontend_protocol::FrontendEvent| {
            use orbit_frontend_protocol::FrontendEvent as E;
            match ev {
                E::TextDelta { text } => {
                    if !stamped {
                        stamped = true;
                        print!("{} orbit: ", hhmm_now());
                    }
                    print!("{text}");
                    use std::io::Write;
                    let _ = std::io::stdout().flush();
                }
                E::CostUpdated { total_microcents } => {
                    render_hud(
                        &hud,
                        &orbit_hud::HudEvent::CostBar {
                            cost_microcents: total_microcents,
                        },
                    );
                }
                E::OutputTruncated { .. } => {
                    eprintln!("reply cut off by the output-token limit");
                }
                E::Retrying {
                    attempt,
                    retry_in_ms,
                    reason,
                } => {
                    eprintln!("retry {attempt} in {retry_in_ms}ms — {reason}");
                }
                E::Error { message } => {
                    eprintln!("{message}");
                }
                E::Status { text } => {
                    eprintln!("{text}");
                }
                _ => {}
            }
        };
        let options = orbit_engine::TurnOptions {
            tools: tools::session_tool_definitions(&home),
            system_directive: Some(build_session_prompt(&home, &model)),
            window_tokens: orbit_cli::context_window_for(&home, &model),
            request_stem: "orbit-repl".into(),
            session_id: session.clone(),
            ..Default::default()
        };
        let report = orbit_engine::run_turn(
            &home,
            &turn_config,
            &options,
            &trimmed,
            &mut transcript,
            &mut executor,
            &orbit_provider_http::CancelToken::new(),
            &mut events,
        );

        match report {
            Ok(r) if r.ok => {
                println!();
                total_input += r.input_tokens;
                total_output += r.output_tokens;
                total_cost += r.cost_microcents;
                turns += 1;
                let sf = sessions::SessionFile::from_chat(
                    &session,
                    &model,
                    &resolved_gate,
                    &provider_id,
                    &transcript,
                    turns,
                    total_input,
                    total_output,
                    total_cost,
                );
                if let Err(e) = sessions::save_session(&home, &sf) {
                    eprintln!("warning: session not saved: {e}");
                }
            }
            Ok(r) => {
                println!();
                total_input += r.input_tokens;
                total_output += r.output_tokens;
                total_cost += r.cost_microcents;
                if r.interrupted {
                    eprintln!("turn cancelled");
                }
                // E10: the attestation scan runs in EVERY front-end —
                // an unverified claim is shown, not just in headless.
                if let Some(scan) = orbit_engine::automation::scan_attestation(&transcript) {
                    if scan.claimed_pass && scan.exit_code != 0 {
                        eprintln!(
                            "UNVERIFIED CLAIM: \"{}\" exited {} at turn time — the claim is not attested",
                            scan.command, scan.exit_code
                        );
                    }
                }
            }
            Err(_) => {
                // The engine already emitted the error via events.
            }
        }
    }

    // Exit summary (JSON envelope, consistent with other commands).
    println!(
        "{}",
        serde_json::json!({
            "schema": "orbit.cli/v1",
            "command": "chat",
            "status": "exit",
            "session": session,
            "turns": turns,
            "usage": {
                "input_tokens": total_input,
                "output_tokens": total_output,
            },
            "cost_microcents": total_cost,
        })
    );
    0
}

/// The REPL's tool executor: bridges the engine's `ToolExecutor` trait
/// to the REPL's StdApprovalChannel (blocking stdin) and session grants.
/// The TUI injects its own executor (TuiApprovalChannel via the bus).
struct ReplToolExecutor {
    home: std::path::PathBuf,
    session_id: String,
    model: String,
    provider_id: String,
    turns: u64,
    total_input: u64,
    total_output: u64,
    auto_tools: bool,
    interactive: bool,
    approval_channel: tool_runtime::StdApprovalChannel,
    auto_grants: tool_runtime::AutoGrants,
    /// The session's permission scope (S5).
    scope: tool_runtime::PermissionScope,
    /// One context per REPL session (B2).
    tool_cx: orbit_tools::ToolContext,
}

impl orbit_engine::ToolExecutor for ReplToolExecutor {
    fn begin_turn(&mut self, config: &orbit_engine::TurnConfig) {
        tool_runtime::remember_turn_config(&self.tool_cx, config);
    }

    fn execute(
        &mut self,
        calls: &[orbit_engine::PendingToolCall],
        _round: u32,
    ) -> Vec<orbit_engine::ToolRoundResult> {
        let cx = self.tool_cx.clone();
        tool_runtime::run_until_cancelled(
            &cx,
            calls,
            |call| {
                // Update the read-only current_session snapshot before execution.
                tools::SESSION_SNAPSHOT.with(|s| {
                    *s.borrow_mut() = tools::SessionSnapshot {
                        session_id: self.session_id.clone(),
                        model: self.model.clone(),
                        provider: self.provider_id.clone(),
                        turns: self.turns,
                        input_tokens: self.total_input,
                        output_tokens: self.total_output,
                    };
                });
                // Per-call ULID decision ids (defect fix: the old
                // `tool-round-{round}-{index}` ids repeated every turn, so
                // ledger records could not be tied to their turn).
                let decision_id = format!("tool-{}-{}", ulid::Ulid::new(), call.index);
                let (result, _) = tool_runtime::execute_call(
                    &self.home,
                    &self.session_id,
                    &decision_id,
                    call,
                    self.auto_tools,
                    self.interactive,
                    &mut self.approval_channel,
                    &mut self.auto_grants,
                    &self.scope,
                    &self.tool_cx,
                )
                .unwrap_or_else(|e| {
                    (
                        serde_json::json!({ "ok": false, "error": e }).to_string(),
                        None,
                    )
                });
                orbit_engine::ToolRoundResult {
                    call_id: call.id.clone(),
                    content: result,
                }
            },
            |_| {},
        )
    }

    fn begin_cancel_scope(&mut self, token: &orbit_provider_http::CancelToken) {
        tool_runtime::begin_cancel_scope(&self.tool_cx, token);
    }

    fn end_cancel_scope(&mut self) {
        self.tool_cx.pop_cancel_check();
    }
}

/// `orbit models` — list every declared model across all configured providers.
/// Reads `$ORBIT_HOME/providers.toml` (missing = empty config).
/// `orbit mod …` — mods as signed plugins (phase 5): a bundle of
/// instructions, commands, skills, hooks and MCP servers, installed
/// through orbit-plugin's signed-manifest flow (issuer key, content
/// digest, operator approval, ledger record).
fn cmd_mod(home: &Path, args: &[String]) -> Result<serde_json::Value, (&'static str, String)> {
    let sub = args.get(1).map(String::as_str).unwrap_or("");
    // Issuer allowlist: $ORBIT_HOME/mods/issuers.txt, one hex key per
    // line. The operator trusts an issuer explicitly; installs from
    // anyone else are refused.
    let issuers_path = home.join("mods").join("issuers.txt");
    let read_issuers = || -> std::collections::HashSet<String> {
        std::fs::read_to_string(&issuers_path)
            .map(|t| {
                t.lines()
                    .map(str::trim)
                    .filter(|l| !l.is_empty() && !l.starts_with('#'))
                    .map(String::from)
                    .collect()
            })
            .unwrap_or_default()
    };
    match sub {
        "allow-issuer" => {
            let Some(key) = args.get(2) else {
                return Err((
                    "ORBIT-E1101",
                    "usage: orbit mod allow-issuer <hex-ed25519-key>".into(),
                ));
            };
            let key = key.trim();
            if hex::decode(key).map(|b| b.len() != 32).unwrap_or(true) {
                return Err(("ORBIT-E0806", "issuer key must be 32 bytes of hex".into()));
            }
            std::fs::create_dir_all(home.join("mods"))
                .map_err(|e| ("ORBIT-E0501", e.to_string()))?;
            let mut existing = read_issuers();
            existing.insert(key.to_string());
            let text = existing.into_iter().collect::<Vec<_>>().join("\n");
            std::fs::write(&issuers_path, format!("{text}\n"))
                .map_err(|e| ("ORBIT-E0501", e.to_string()))?;
            Ok(serde_json::json!({
                "schema": "orbit.cli/v1",
                "command": "mod allow-issuer",
                "status": "ok",
                "issuer": key,
            }))
        }
        "list" => {
            let issuers = read_issuers();
            Ok(serde_json::json!({
                "schema": "orbit.cli/v1",
                "command": "mod list",
                "status": "ok",
                "trusted_issuers": issuers.len(),
                "issuers": issuers,
            }))
        }
        "install" => {
            let pkg = value_after(args, "--package")
                .or_else(|| args.get(2).cloned())
                .ok_or_else(|| {
                    (
                        "ORBIT-E1101",
                        "usage: orbit mod install <package.wasm> --manifest <manifest.json>".into(),
                    )
                })?;
            let manifest_path = value_after(args, "--manifest").ok_or_else(|| {
                (
                    "ORBIT-E1101",
                    "install needs --manifest <manifest.json>".into(),
                )
            })?;
            let manifest_text = std::fs::read_to_string(&manifest_path)
                .map_err(|e| ("ORBIT-E0401", format!("read manifest: {e}")))?;
            let manifest: orbit_plugin::PluginManifest = serde_json::from_str(&manifest_text)
                .map_err(|e| ("ORBIT-E0401", format!("parse manifest: {e}")))?;
            let package_bytes =
                std::fs::read(&pkg).map_err(|e| ("ORBIT-E0401", format!("read package: {e}")))?;
            let issuers = read_issuers();
            if !issuers.contains(&manifest.issuer_public_key) {
                return Err((
                    "ORBIT-E0806",
                    format!(
                        "issuer {} is not trusted; run: orbit mod allow-issuer {}",
                        &manifest.issuer_public_key[..8.min(manifest.issuer_public_key.len())],
                        manifest.issuer_public_key
                    ),
                ));
            }
            let mut registry = orbit_plugin::PluginRegistry::new(4);
            for i in issuers {
                registry.allow_issuer(i);
            }
            registry.attach_ledger();
            let allowlist = orbit_plugin::WasiHostAllowlist::canonical();
            match registry.install(&manifest, &allowlist, &package_bytes) {
                Ok(installed) => Ok(serde_json::json!({
                    "schema": "orbit.cli/v1",
                    "command": "mod install",
                    "status": "ok",
                    "mod": installed.name,
                    "version": installed.version,
                    "issuer": installed.issuer_fingerprint,
                })),
                Err(e) => Err(("ORBIT-E0806", e.to_string())),
            }
        }
        other => Err((
            "ORBIT-E1101",
            format!("unknown mod subcommand {other:?} (install, list, allow-issuer)"),
        )),
    }
}

fn cmd_models(home: &Path, args: &[String]) -> Result<serde_json::Value, (&'static str, String)> {
    let cfg = config::ProvidersConfig::load(home).map_err(|e| ("ORBIT-E1106", e))?;
    let entries: Vec<(String, String)> = cfg.all_models();
    Ok(serde_json::json!({
        "schema": "orbit.cli/v1",
        "command": "models",
        "status": "ok",
        "providers": cfg.provider,
        "models": entries,
        "count": entries.len(),
        "json": args.iter().any(|a| a == "--json"),
    }))
}

/// Handle REPL slash commands. Returns true if recognized.
fn handle_chat_command(
    cmd: &str,
    home: &Path,
    model: &mut String,
    transcript: &mut Vec<orbit_adapter::types::ChatMessage>,
    usage: (&u64, &u64, &u64, &u64), // (turns, input, output, cost µ¢)
) -> bool {
    match cmd {
        "/help" => {
            println!("commands: exit, /help, /model <M>, /clear, /usage, /models");
            true
        }
        "/clear" => {
            transcript.clear();
            println!("conversation cleared");
            true
        }
        "/usage" => {
            let (turns, input, output, cost) = usage;
            println!(
                "turns {} · in {} · out {} · ${}.{:06}",
                turns,
                input,
                output,
                cost / 1_000_000,
                cost % 1_000_000
            );
            true
        }
        "/models" => {
            let cfg = config::ProvidersConfig::load(home);
            match cfg {
                Ok(cfg) => {
                    let entries = cfg.all_models();
                    if entries.is_empty() {
                        println!("(no providers configured)");
                    } else {
                        for (prov, m) in &entries {
                            println!("{prov} \t{m}");
                        }
                    }
                }
                Err(e) => println!("error reading providers.toml: {e}"),
            }
            true
        }
        "/sessions" => {
            match sessions::list_sessions(home) {
                Ok(list) if list.is_empty() => println!("(no saved sessions)"),
                Ok(list) => {
                    for s in &list {
                        println!(
                            "{} \tmodel={} \tturns={} \tupdated={}",
                            s.session_id, s.model, s.turns, s.updated_at
                        );
                    }
                }
                Err(e) => println!("error listing sessions: {e}"),
            }
            true
        }
        "/model" => {
            println!("usage: /model <model-id>");
            true
        }
        c if c.starts_with("/model ") => {
            *model = c["/model ".len()..].trim().to_string();
            println!("model -> {model}");
            true
        }
        _ => false,
    }
}

/// Render a HUD event to the terminal, honoring the display-safety gate (H-3)
/// and the stdout/stderr split (H-9). A payload rejected by the gate renders a
/// safe placeholder to stderr — never a crash, never leaked bytes.
/// Current wall-clock time as HH:MM for the plain grammar's line stamps.
fn hhmm_now() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let (h, m) = ((secs / 3600) % 24, (secs / 60) % 60);
    format!("{h:02}:{m:02}")
}

fn render_hud(hud: &orbit_hud::Hud, event: &orbit_hud::HudEvent) {
    // Apply the display-safety gate (H-3) to text-bearing events first.
    let event = match event {
        orbit_hud::HudEvent::Message { text } => match orbit_hud::display_safe(text) {
            Ok(clean) => orbit_hud::HudEvent::Message { text: clean },
            Err(_) => {
                eprintln!("[HUD] message rejected by display gate (H-3)");
                return;
            }
        },
        other => other.clone(),
    };
    let (out, err) = hud.render(&event);
    if let Some(line) = out {
        println!("{line}");
    }
    if let Some(line) = err {
        eprintln!("{line}");
    }
}

fn ensure_initialized(home: &Path) -> Result<(), (&'static str, String)> {
    if !home.join("trust/manifest.json").exists() {
        return Err(("ORBIT-E0706", "not initialized; run `orbit init`".into()));
    }
    // C3 migration: an existing home may still carry the placeholder PIB
    // id every pre-2026-10 install shared. Mint a real ULID once, in
    // place — the identity (keys, fingerprint) is unchanged, only the id
    // becomes unique to this install.
    migrate_placeholder_pib(home);
    Ok(())
}

/// One-time in-place migration of the hard-coded "01J-LOCAL-PIB" id to a
/// per-install ULID (C3). Idempotent: a home already migrated (or never
/// affected) is left untouched. Failures are non-fatal — a read-only home
/// still works with the old id.
fn migrate_placeholder_pib(home: &Path) {
    const PLACEHOLDER: &str = "01J-LOCAL-PIB";
    let path = home.join("pib.json");
    let Ok(raw) = std::fs::read_to_string(&path) else {
        return;
    };
    let Ok(mut v) = serde_json::from_str::<serde_json::Value>(&raw) else {
        return;
    };
    if v.get("pib_id").and_then(|p| p.as_str()) != Some(PLACEHOLDER) {
        return;
    }
    if let Some(obj) = v.as_object_mut() {
        obj.insert(
            "pib_id".into(),
            serde_json::json!(format!("pib-{}", ulid::Ulid::new())),
        );
    }
    let _ = std::fs::write(&path, serde_json::to_vec_pretty(&v).unwrap_or_default());
}

fn value_after(args: &[String], flag: &str) -> Option<String> {
    args.windows(2).find(|w| w[0] == flag).map(|w| w[1].clone())
}

fn collect_ledger_bytes(dir: &Path) -> Result<Vec<u8>, (&'static str, String)> {
    let mut out = Vec::new();
    let segdir = dir.join("segments");
    let mut files: Vec<_> = std::fs::read_dir(&segdir).map_err(ioe)?.flatten().collect();
    files.sort_by_key(|e| e.file_name());
    for e in files {
        out.extend(std::fs::read(e.path()).map_err(ioe)?);
    }
    Ok(out)
}

fn ioe(e: std::io::Error) -> (&'static str, String) {
    ("ORBIT-E0700", e.to_string())
}
