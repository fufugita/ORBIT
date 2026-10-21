//! ORBIT CLI binary — clean-machine E2E surface (DR-03 §5 row 9).
//!
//! Implements the exact closeout chain:
//! install/build → init trust → run example → cancel → verify-ledger → replay dry
//! → export → restore into a fresh namespace → verify again.

use age::secrecy::ExposeSecret;
use orbit_adapter::types::EffortSetting;
use orbit_export::{ExportBuilder, generate_local_key, restore};
use orbit_ledger::event::{
    LedgerEvent, Phase, PhaseTransition, SessionEnd, SessionStart, TerminalOutcome,
};
use orbit_ledger::{LedgerWriter, verify_ledger};
use orbit_reactor::{CancelOrigin, CancelTarget, CancellationToken, Reactor};
use std::path::{Path, PathBuf};

use orbit_cli::session_accounting::{self, FullCostStatus, NamespaceSpendPolicy, RootOrigin};
use orbit_cli::{config, sessions, tool_runtime, tools, tui_worker};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if let Some(code) = orbit_cli::recovery_commands::try_run(&args) {
        std::process::exit(code);
    }
    // Local compaction has its own complete grammar, including rejection of
    // help/prompt/model overrides before any ownership or discovery effects.
    if positionals(&args).first().copied() == Some("compact") {
        std::process::exit(cmd_compact(&args));
    }

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
    let first_word = positionals(&args).first().copied();
    let wants_chat = args.is_empty() || first_word == Some("chat") || first_word.is_none();
    // A prompt is arbitrary text. Only a top-level -p selects headless mode;
    // operands of local commands cannot change the execution path.
    if headless_prompt_index(&args).is_some() {
        let headless = match headless_arguments(&args) {
            Ok(arguments) => arguments,
            Err(error) => {
                eprintln!("ORBIT-E1101: {error}");
                std::process::exit(1);
            }
        };
        std::process::exit(cmd_headless(&headless));
    }
    // C1: `--help`/`-h` print HUMAN help (exit 0); `--version` prints the
    // version line. The machine-readable forms stay on the verbs:
    // `orbit help --json` and `orbit version` (JSON).
    if first_word != Some("plugin") && args.iter().any(|a| a == "--help" || a == "-h") {
        if args.iter().any(|a| a == "--json") {
            let value = dispatch(&["help".into(), "--json".into()]).expect("static help command");
            println!("{}", serde_json::to_string(&value).unwrap_or_default());
        } else {
            print_human_help();
        }
        std::process::exit(0);
    }
    if args
        .first()
        .map(|a| a == "--version" || a == "-V")
        .unwrap_or(false)
    {
        println!("orbit {}", env!("CARGO_PKG_VERSION"));
        std::process::exit(0);
    }
    if positionals(&args).first().copied() == Some("web") {
        let mut tail = match command_tail(&args) {
            Ok(tail) => tail,
            Err((code, error)) => {
                eprintln!("{code}: {error}");
                std::process::exit(2)
            }
        };
        tail.extend([
            "--home".into(),
            config::resolve_home(&args).to_string_lossy().into_owned(),
        ]);
        std::process::exit(cmd_web(&tail));
    }
    match positionals(&args).first().copied() {
        Some("serve") => std::process::exit(cmd_serve(&args)),
        Some("attach") => std::process::exit(cmd_attach(&args)),
        _ => {}
    }
    if wants_chat {
        let code = cmd_chat(&args);
        std::process::exit(code);
    }

    let result = dispatch(&args);
    match result {
        Ok(v) => {
            let command = positionals(&args).first().copied().unwrap_or("");
            let human = ["setup", "doctor", "pentest"].contains(&command)
                && !args.iter().any(|arg| arg == "--json");
            if command == "plugin" && !args.iter().any(|arg| arg == "--json") {
                print!("{}", orbit_cli::plugin_commands::human_report(&v));
            } else if human {
                print!("{}", orbit_cli::cli_release_commands::human_report(&v));
            } else {
                println!(
                    "{}",
                    serde_json::to_string(&v).unwrap_or_else(|_| "{}".into())
                );
            }
            if v.pointer("/report/ready")
                .and_then(serde_json::Value::as_bool)
                == Some(false)
            {
                std::process::exit(1);
            }
        }
        Err((code, msg)) => {
            eprintln!("{code}: {msg}");
            let exit_code = if first_word == Some("plugin") {
                match code {
                    "ORBIT-E1101" => 64,
                    "ORBIT-E1106" => 78,
                    "ORBIT-E1109" | "ORBIT-E1911" => 93,
                    "ORBIT-E110B" => 96,
                    "ORBIT-E110C" => 97,
                    _ => 2,
                }
            } else {
                2
            };
            std::process::exit(exit_code);
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
        (
            "setup",
            "terminal provider wizard; manual/JSON modes remain offline",
        ),
        ("init", "initialize once (setup compatibility alias)"),
        (
            "doctor [--json]",
            "offline readiness; never starts configured servers",
        ),
        (
            "pentest init/status/templates/readiness",
            "local engagement workspaces and templates",
        ),
        (
            "customize show/set/import/export/reset",
            "appearance, layouts and named panes",
        ),
        ("theme NAME", "select orbit, midnight or paper"),
        ("models", "list models from all configured providers"),
        (
            "provider add/list/remove/role/presets",
            "configure providers without sending a prompt",
        ),
        (
            "provider refresh NAME [--schema SCHEMA] [--json]",
            "explicitly refresh advertised model metadata",
        ),
        (
            "provider login NAME [--method browser|key|env]",
            "save provider authentication after review",
        ),
        (
            "provider logout NAME [--yes] [--json]",
            "remove only the current saved local key",
        ),
        (
            "route status/test/setup/set/reset",
            "configure or preview phase and difficulty routing",
        ),
        ("ask PROMPT", "send one prompt through a configured gateway"),
        (
            "compact --session ID [--json]",
            "compact an inactive saved session without another user turn",
        ),
        (
            "recovery status --session ID [--child CHILD] [--json]",
            "inspect tracked accounting without provider requests or replay",
        ),
        (
            "recovery export --session ID --expect-revision REV --expect-inspection DIGEST --to DIR [--json]",
            "preserve an inactive root session in a new private directory",
        ),
        (
            "-p PROMPT",
            "headless one-shot with tools (stream-json output)",
        ),
        ("web", "start the browser harness (orbit-web bridge)"),
        ("serve --socket <PATH>", "own one session in the foreground"),
        (
            "attach --socket <PATH>",
            "connect to its prompt, status or controls",
        ),
        ("verify-ledger", "verify the ledger hash chain"),
        ("replay --dry", "verify + emit a no-dispatch replay plan"),
        ("export --to", "encrypt an age bundle"),
        ("restore", "restore into a fresh namespace"),
        ("version", "release evidence (claims + hashes)"),
        (
            "mod install/list/search/status",
            "durable signed package catalog",
        ),
        ("mod issuers/allow-issuer", "trusted package issuers"),
        (
            "plugin inspect PATH",
            "inspect a portable or foreign plugin",
        ),
        (
            "folder trust/untrust/status",
            "let a folder's own settings loosen permissions",
        ),
        ("help [--json]", "this help (JSON vocabulary with --json)"),
    ] {
        println!("    {name:<28} {desc}");
    }
    println!();
    println!("SETUP:");
    println!(
        "    orbit setup                                 choose a provider, authentication, models and default"
    );
    println!(
        "    orbit provider add                          add another provider with the same wizard"
    );
    println!("    Model source: manual makes no request; discover fetches a filterable catalog.");
    println!(
        "    Refresh schema: generic, openrouter, anthropic or ollama; existing manual limits stay authoritative."
    );
    println!(
        "    Browser login: supported OpenRouter endpoint only. Other providers accept key or ENV."
    );
    println!(
        "    Login --no-browser: open the authorization URL manually; --headless: privately paste the displayed code."
    );
    println!(
        "    Login is terminal-only; logout needs --yes for JSON or redirected use. No key is accepted in argv."
    );
    println!(
        "    orbit setup --no-provider [--json]           offline identity setup for automation"
    );
    println!("    orbit setup --provider NAME --gate URL --model ID [--credential-env ENV_NAME]");
    println!(
        "    orbit setup --guided                        older offline ENV-name prompts (terminal only)"
    );
    println!(
        "    orbit setup repair --dry-run [--json]        inspect recovery without replacing identity"
    );
    println!();
    println!("CHAT FLAGS:");
    for (name, desc) in [
        ("--model <M>", "model id (providers.toml)"),
        (
            "--effort <VALUE>",
            "configured request effort (or default; ORBIT_EFFORT fallback)",
        ),
        ("--gate <URL>", "gateway base URL"),
        ("--home <DIR>", "ORBIT home (default ~/.orbit)"),
        ("--continue", "reopen the latest session in this directory"),
        (
            "--fork-session",
            "copy the resumed (or latest) session into a new id and continue there",
        ),
        ("--resume <ID>", "resume a specific session"),
        ("--no-tui", "plain REPL instead of the TUI"),
        (
            "--safe-customization",
            "read-only session defaults; preserve malformed stored files",
        ),
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
/// Only a compile-time stamp can describe the source of these executable bytes.
fn build_commit() -> String {
    if let Some(c) = option_env!("ORBIT_BUILD_COMMIT")
        && !c.is_empty()
    {
        return c.to_string();
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
        if a == "--home" || a == "--model" || a == "--gate" || a == "--resume" || a == "--effort" {
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
        "setup" => cmd_setup(&home, args, false),
        "doctor" => orbit_cli::cli_release_commands::doctor(&home, &command_tail(args)?),
        "pentest" => orbit_cli::cli_release_commands::pentest(&home, &command_tail(args)?),
        "customize" | "theme" => {
            let mut tail = command_tail(args)?;
            if verb == "theme" {
                tail.insert(0, "theme".into());
            }
            orbit_cli::customization_host::command(
                &home,
                &std::env::current_dir().map_err(ioe)?,
                &tail,
            )
            .map_err(|error| ("ORBIT-E1101", error))
        }
        "run" => cmd_run(&home, args),
        "cancel" => cmd_cancel(&home),
        "verify-ledger" => cmd_verify(&home),
        "replay" => cmd_replay(&home, args),
        "export" => cmd_export(&home, args),
        "restore" => cmd_restore(&home, args),
        "ask" => cmd_ask(&home, args),
        "models" | "list-models" => cmd_models(&home, args),
        "mod" => cmd_mod(&home, args),
        "plugin" => orbit_cli::plugin_commands::command(
            &home,
            &std::env::current_dir().map_err(ioe)?,
            &command_tail(args)?,
        )
        .map_err(|error| match error {
            orbit_cli::CliError::Usage(message) => ("ORBIT-E1101", message),
            orbit_cli::CliError::ConfigInvalid(message) => ("ORBIT-E1106", message),
            orbit_cli::CliError::Policy(message) => ("ORBIT-E1109", message),
            orbit_cli::CliError::TelemetryDenied(message) => ("ORBIT-E110B", message),
            orbit_cli::CliError::V02Only(message) => ("ORBIT-E110C", message),
            orbit_cli::CliError::ConfirmRequired(message) => ("ORBIT-E1911", message),
        }),
        "folder" => cmd_folder(&home, args),
        "provider" => cmd_provider(&home, args),
        "route" => cmd_route(&home, args),
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
                "setup         terminal provider wizard; explicit manual/JSON/offline flags supported",
                "init          setup compatibility alias",
                "doctor [--json] offline readiness without server startup",
                "pentest init|status|templates|readiness local engagement workflows",
                "customize show|capabilities|set|theme|reset|validate|import|export portable customization",
                "theme NAME    select a built-in appearance",
                "models        list models from all configured providers",
                "route status|test|setup|set|reset|auto  configure and preview model routing",
                "ask PROMPT    send one prompt through a configured gateway",
                "compact --session ID [--home PATH] [--json]  compact an inactive saved session",
                "recovery status --session ID [--child CHILD] [--json]  inspect existing accounting without replay",
                "recovery export --session ID --expect-revision REV --expect-inspection DIGEST --to DIR [--json]  preserve an inactive root session",
                "-p PROMPT     headless one-shot with tools (stream-json output)",
                "run           run the example phase chain",
                "cancel        cancel the session (terminal: cancelled)",
                "verify-ledger verify the Ledger hash chain",
                "replay --dry  verify + emit a no-dispatch replay plan",
                "export --to   encrypt an age bundle",
                "restore       restore into a fresh namespace",
                "version       release evidence (claims + hashes)",
                "mod install <pkg> --manifest <m> --yes  store a verified signed package",
                "mod list|search|status           verified installed package catalog",
                "mod issuers                     trusted package issuers",
                "mod allow-issuer <hex-key>       trust a mod issuer",
                "plugin inspect PATH [--format FORMAT]  inspect local plugin components",
                "folder trust|untrust|status [DIR]  trust a folder's own settings",
                "provider add|list|remove|role|presets    manage model providers",
                "setup model source manual|discover    offline entry or explicit filterable catalog",
                "provider refresh NAME [--schema generic|openrouter|anthropic|ollama] [--json]",
                "provider login NAME [--method browser|key|env] [--headless] [--no-browser]  terminal only",
                "provider logout NAME [--yes] [--json]  current local binding only; ENV/config/defaults preserved",
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

/// Strip the global home option and the actual command token, retaining every operand.
fn command_tail(args: &[String]) -> Result<Vec<String>, (&'static str, String)> {
    let words = positionals(args);
    let command = words
        .first()
        .ok_or(("ORBIT-E1101", "command required".into()))?;
    let command_index = args
        .iter()
        .position(|word| std::ptr::eq(word.as_str(), *command))
        .ok_or(("ORBIT-E1101", "command required".into()))?;
    let mut tail = Vec::new();
    let mut seen_home = false;
    let mut index = 0;
    while index < args.len() {
        if args[index] == "--home" {
            if seen_home
                || args
                    .get(index + 1)
                    .is_none_or(|value| value.is_empty() || value.starts_with("--"))
            {
                return Err((
                    "ORBIT-E1101",
                    "--home requires one directory and cannot be repeated".into(),
                ));
            }
            seen_home = true;
            index += 2;
            continue;
        }
        if index != command_index {
            tail.push(args[index].clone());
        }
        index += 1;
    }
    Ok(tail)
}

fn cmd_setup(
    home: &Path,
    args: &[String],
    initialize: bool,
) -> Result<serde_json::Value, (&'static str, String)> {
    let tail = command_tail(args)?;
    let parsed = orbit_cli::cli_release_commands::parse_setup(&tail)?;
    let terminal = std::io::IsTerminal::is_terminal(&std::io::stdin())
        && std::io::IsTerminal::is_terminal(&std::io::stdout());
    let interactive = parsed.interactive_provider || (!initialize && tail.is_empty() && terminal);
    if interactive {
        if tail.iter().any(|arg| arg == "--json") || !parsed.request.routing.is_empty() {
            return Err((
                "ORBIT-E1101",
                "interactive setup cannot use JSON or manual routing flags".into(),
            ));
        }
        if !terminal {
            return Err(("ORBIT-E1101", "interactive setup requires terminal input and output; use manual flags for automation".into()));
        }
        return run_onboarding_command(home, None, if initialize { "init" } else { "setup" });
    }
    if initialize {
        orbit_cli::cli_release_commands::init(home, &tail)
    } else {
        orbit_cli::cli_release_commands::setup(home, &tail)
    }
}

fn run_onboarding_command(
    home: &Path,
    preset: Option<&str>,
    command: &str,
) -> Result<serde_json::Value, (&'static str, String)> {
    let mut terminal = orbit_cli::onboarding::StdSetupTerminal::new()
        .map_err(|error| (error.code(), error.to_string()))?;
    let receipt = orbit_cli::onboarding::run_onboarding(home, preset, &mut terminal)
        .map_err(|error| (error.code(), error.to_string()))?;
    let offline = receipt.catalog_status == "not_requested" && !receipt.authentication_online;
    let mut result = serde_json::to_value(receipt)
        .map_err(|_| ("ORBIT-E1101", "setup result could not be encoded".into()))?;
    result["schema"] = serde_json::json!("orbit.cli/v1");
    result["command"] = serde_json::json!(command);
    result["status"] = serde_json::json!("ok");
    result["offline"] = serde_json::json!(offline);
    Ok(result)
}

fn cmd_init(home: &Path, args: &[String]) -> Result<serde_json::Value, (&'static str, String)> {
    cmd_setup(home, args, true)
}

/// Add one provider to providers.toml (scripted init path). Pricing defaults to
/// zero unless supplied by the interactive setup. Token values are never
/// accepted here — only the credential env-var name.
#[cfg(test)]
fn add_configured_provider(
    home: &Path,
    name: &str,
    gate: &str,
    credential_env: Option<String>,
    model_ids: Vec<String>,
    pricing: Option<Vec<orbit_cli::config::Pricing>>,
) -> Result<(), (&'static str, String)> {
    add_configured_provider_kind(
        home,
        name,
        gate,
        "openai-compatible",
        credential_env,
        model_ids,
        pricing,
        None,
    )
}

/// Add a provider with an explicit adapter kind and optional pre-built
/// model entries (preset facts + live-discovered limits). The legacy
/// wrapper above keeps the scripted `orbit init --provider` path.
#[allow(clippy::too_many_arguments)]
fn add_configured_provider_kind(
    home: &Path,
    name: &str,
    gate: &str,
    kind: &str,
    credential_env: Option<String>,
    model_ids: Vec<String>,
    pricing: Option<Vec<orbit_cli::config::Pricing>>,
    model_entries: Option<Vec<orbit_cli::config::ModelEntry>>,
) -> Result<(), (&'static str, String)> {
    validate_provider_url(gate)?;
    let models = model_entries.unwrap_or_else(|| {
        model_ids
            .into_iter()
            .enumerate()
            .map(|(i, id)| orbit_cli::config::ModelEntry {
                context_limits: None,
                sampling: None,
                supported_efforts: None,
                first_byte_timeout_ms: None,
                idle_timeout_ms: None,
                default_effort: None,
                id,
                label: None,
                pricing: pricing
                    .as_ref()
                    .and_then(|p| p.get(i).copied())
                    .unwrap_or_default(),
                max_output_tokens: None,
                context_window: None,
            })
            .collect()
    });
    let provider = orbit_cli::config::ProviderConfig {
        name: name.into(),
        kind: kind.into(),
        url: gate.trim_end_matches('/').into(),
        env: credential_env,
        models,
    };
    orbit_cli::setup::validate_provider(&provider).map_err(|e| ("ORBIT-E1101", e.to_string()))?;
    // This operation only edits configuration. Identity creation stays explicit.
    if !home.try_exists().map_err(ioe)? {
        return Err((
            "ORBIT-E0706",
            "provider add requires an existing private home; run orbit setup first".into(),
        ));
    }
    config::ProvidersConfig::update_atomic(home, |raw| {
        let mut document = provider_document(raw)?;
        let providers = document
            .as_table_mut()
            .ok_or("provider config must be a table")?
            .entry("provider")
            .or_insert_with(|| toml::Value::Array(Vec::new()))
            .as_array_mut()
            .ok_or("provider config must be an array")?;
        if providers
            .iter()
            .any(|p| p.get("name").and_then(toml::Value::as_str) == Some(name))
        {
            return Err("provider name is already configured".into());
        }
        providers
            .push(toml::Value::try_from(&provider).map_err(|_| "provider serialization failed")?);
        serialize_provider_document(&document)
    })
    .map_err(|e| ("ORBIT-E1106", e))?;
    Ok(())
}

fn provider_document(raw: &str) -> Result<toml::Value, String> {
    toml::from_str(raw).map_err(|_| "providers configuration is invalid".into())
}
fn validate_configured_provider_endpoints(
    config: &config::ProvidersConfig,
) -> Result<(), (&'static str, String)> {
    for provider in &config.provider {
        config::validate_provider_endpoint(&provider.url).map_err(|e| ("ORBIT-E1106", e))?;
    }
    Ok(())
}
fn serialize_provider_document(document: &toml::Value) -> Result<String, String> {
    toml::to_string(document).map_err(|_| "provider serialization failed".into())
}
fn provider_table<'a>(
    document: &'a mut toml::Value,
    key: &str,
) -> Result<&'a mut toml::map::Map<String, toml::Value>, String> {
    document
        .as_table_mut()
        .ok_or("provider config must be a table")?
        .entry(key)
        .or_insert_with(|| toml::Value::Table(Default::default()))
        .as_table_mut()
        .ok_or_else(|| "provider section must be a table".into())
}
fn set_provider_role(home: &Path, role: &str, spec: &str) -> Result<(), (&'static str, String)> {
    if !["main", "subagent", "explore", "compaction"].contains(&role) {
        return Err(("ORBIT-E1101", "unknown provider role".into()));
    }
    config::ProvidersConfig::update_atomic(home, |raw| {
        let cfg = config::ProvidersConfig::load_from_str(raw)?;
        if !spec.is_empty() {
            orbit_cli::phase_routing::resolve_model(&cfg, spec, None)?;
        }
        let mut document = provider_document(raw)?;
        provider_table(&mut document, "roles")?
            .insert(role.into(), toml::Value::String(spec.into()));
        serialize_provider_document(&document)
    })
    .map_err(|e| ("ORBIT-E1106", e))?;
    Ok(())
}

/// The legacy discovery UI retains its private-LAN HTTP policy and uses the same
/// credential/identity checks as offline setup before any optional request.
fn validate_provider_url(gate: &str) -> Result<(), (&'static str, String)> {
    let url = config::validate_provider_endpoint(gate).map_err(|e| ("ORBIT-E0401", e))?;
    match url.scheme() {
        "https" => Ok(()),
        "http" => {
            let private = match url.host() {
                Some(url::Host::Domain(host)) => host.eq_ignore_ascii_case("localhost"),
                Some(url::Host::Ipv4(ip)) => ip.is_loopback() || ip.is_private(),
                Some(url::Host::Ipv6(ip)) => ip.is_loopback() || ip.is_unique_local(),
                None => false,
            };
            if private {
                Ok(())
            } else {
                Err((
                    "ORBIT-E0301",
                    "cleartext HTTP provider must be loopback/private LAN".into(),
                ))
            }
        }
        _ => Err(("ORBIT-E0301", "provider URL must use http(s)".into())),
    }
}
#[cfg(test)]
fn validate_discovery_input(
    name: &str,
    gate: &str,
    credential_env: Option<&str>,
    kind: &str,
) -> Result<(), (&'static str, String)> {
    validate_provider_url(gate)?;
    orbit_cli::setup::validate_provider(&config::ProviderConfig {
        name: name.into(),
        kind: kind.into(),
        url: gate.into(),
        env: credential_env.map(String::from),
        models: vec![config::ModelEntry {
            context_limits: None,
            id: "discovery-validation".into(),
            label: None,
            pricing: Default::default(),
            max_output_tokens: None,
            context_window: None,
            sampling: None,
            supported_efforts: None,
            first_byte_timeout_ms: None,
            idle_timeout_ms: None,
            default_effort: None,
        }],
    })
    .map_err(|e| ("ORBIT-E1101", e.to_string()))
}
#[cfg(test)]
fn provider_models_url(gate: &str, kind: &str, model: Option<&str>) -> Result<url::Url, String> {
    validate_discovery_input("discovery", gate, None, kind).map_err(|(_, e)| e)?;
    let mut endpoint = url::Url::parse(gate).map_err(|_| "bad provider URL")?;
    let base = endpoint.path().trim_end_matches('/').to_string();
    let path = if kind == "ollama" {
        if base.ends_with("/api") {
            format!("{base}/tags")
        } else {
            format!("{base}/api/tags")
        }
    } else {
        format!("{}/models", if base.is_empty() { "/v1" } else { &base })
    };
    endpoint.set_path(&path);
    if let Some(model) = model {
        if model.is_empty() || model.len() > 256 || model.chars().any(char::is_control) {
            return Err("model ID is invalid".into());
        }
        endpoint
            .path_segments_mut()
            .map_err(|_| "provider URL cannot hold a model path")?
            .push(model);
    }
    Ok(endpoint)
}
#[cfg(test)]
const PROVIDER_RESPONSE_LIMIT: usize = 128 * 1024;
#[cfg(test)]
async fn bounded_provider_body(mut response: reqwest::Response) -> Result<String, String> {
    if response
        .content_length()
        .is_some_and(|n| n > PROVIDER_RESPONSE_LIMIT as u64)
    {
        return Err("provider response exceeds 128 KiB".into());
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| "provider response could not be read")?
    {
        if chunk.len() > PROVIDER_RESPONSE_LIMIT.saturating_sub(bytes.len()) {
            return Err("provider response exceeds 128 KiB".into());
        }
        bytes.extend_from_slice(&chunk);
    }
    String::from_utf8(bytes).map_err(|_| "provider response must be UTF-8".into())
}
#[cfg(test)]
fn parse_discovered_models(raw: &str, kind: &str) -> Result<Vec<String>, String> {
    let ids = if kind == "ollama" {
        config::OllamaTagsResponse::parse(raw).map_err(|_| "provider model response is invalid")?
    } else {
        config::ModelListResponse::parse(raw).map_err(|_| "provider model response is invalid")?
    };
    if ids.is_empty()
        || ids.len() > 128
        || ids
            .iter()
            .any(|id| id.is_empty() || id.len() > 256 || id.chars().any(char::is_control))
    {
        return Err("model discovery requires 1..128 bounded printable model IDs".into());
    }
    let mut unique = std::collections::BTreeSet::new();
    if ids.iter().any(|id| !unique.insert(id)) {
        return Err("model discovery returned duplicate model IDs".into());
    }
    Ok(ids)
}
/// Explicit discovery only; redirects cannot forward a credential to a second endpoint.
#[cfg(test)]
fn discover_models(
    gate: &str,
    credential_env: Option<&str>,
    kind: &str,
) -> Result<Vec<String>, String> {
    validate_discovery_input("discovery", gate, credential_env, kind).map_err(|(_, e)| e)?;
    let endpoint = provider_models_url(gate, kind, None)?;
    orbit_provider_http::tls::client_config(&orbit_adapter::types::TlsPinPolicy {
        webpki: true,
        spki_sha256: None,
    })
    .map_err(|_| "provider TLS initialization failed")?;
    tokio::runtime::Runtime::new()
        .map_err(|_| "provider runtime initialization failed")?
        .block_on(async move {
            let client = reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .map_err(|_| "provider HTTP initialization failed")?;
            let mut request = client.get(endpoint);
            if kind == "anthropic" {
                request = request.header("anthropic-version", "2023-06-01");
            }
            if kind != "ollama"
                && let Some(token) = credential_env.and_then(|var| std::env::var(var).ok())
            {
                request = if kind == "anthropic" {
                    request.header("x-api-key", token)
                } else {
                    request.bearer_auth(token)
                };
            }
            let response = request
                .send()
                .await
                .map_err(|_| "model discovery request failed")?;
            if !response.status().is_success() {
                return Err(format!(
                    "model discovery returned HTTP {}",
                    response.status().as_u16()
                ));
            }
            let raw = bounded_provider_body(response).await?;
            parse_discovered_models(&raw, kind)
        })
}
/// Best effort, sharing the same bounded endpoint/request policy as discovery.
#[cfg(test)]
fn anthropic_model_limits(
    gate: &str,
    credential_env: Option<&str>,
    model: &str,
) -> orbit_cli::config::AnthropicModelLimits {
    let result = (|| -> Option<config::AnthropicModelLimits> {
        validate_discovery_input("discovery", gate, credential_env, "anthropic").ok()?;
        let endpoint = provider_models_url(gate, "anthropic", Some(model)).ok()?;
        orbit_provider_http::tls::client_config(&orbit_adapter::types::TlsPinPolicy {
            webpki: true,
            spki_sha256: None,
        })
        .ok()?;
        tokio::runtime::Runtime::new().ok()?.block_on(async move {
            let client = reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .ok()?;
            let mut request = client
                .get(endpoint)
                .header("anthropic-version", "2023-06-01");
            if let Some(token) = credential_env.and_then(|var| std::env::var(var).ok()) {
                request = request.header("x-api-key", token);
            }
            let response = request.send().await.ok()?;
            if !response.status().is_success() {
                return None;
            }
            Some(config::parse_anthropic_model_detail(
                &bounded_provider_body(response).await.ok()?,
            ))
        })
    })();
    result.unwrap_or_default()
}

#[cfg(test)]
fn read_provider_line(
    reader: &mut impl std::io::BufRead,
    default: Option<&str>,
) -> Result<String, (&'static str, String)> {
    use std::io::BufRead;
    let mut bytes = Vec::new();
    let count = std::io::Read::take(&mut *reader, 4097)
        .read_until(b'\n', &mut bytes)
        .map_err(ioe)?;
    if count == 0 {
        return Err((
            "ORBIT-E1101",
            "provider input ended before setup was complete".into(),
        ));
    }
    if count > 4096 {
        return Err(("ORBIT-E1101", "provider input exceeds 4096 bytes".into()));
    }
    let line = std::str::from_utf8(&bytes)
        .map_err(|_| ("ORBIT-E1101", "provider input must be UTF-8".into()))?;
    let line = line.trim_end_matches(['\r', '\n']);
    if line.chars().any(char::is_control) {
        return Err((
            "ORBIT-E1101",
            "provider input contains a control character".into(),
        ));
    }
    let value = line.trim();
    Ok(if value.is_empty() {
        default.unwrap_or("").into()
    } else {
        value.into()
    })
}
fn parse_provider_models(raw: &str) -> Result<Vec<String>, (&'static str, String)> {
    let ids: Vec<_> = raw.split(',').map(|id| id.trim().to_string()).collect();
    let mut seen = std::collections::BTreeSet::new();
    if ids.is_empty()
        || ids.len() > 128
        || ids.iter().any(|id| {
            id.is_empty() || id.len() > 256 || id.chars().any(char::is_control) || !seen.insert(id)
        })
    {
        return Err((
            "ORBIT-E1101",
            "provide 1..128 unique printable model IDs without empty entries".into(),
        ));
    }
    Ok(ids)
}
#[cfg(test)]
fn select_provider_models(
    selection: &str,
    offered: &[String],
) -> Result<Vec<String>, (&'static str, String)> {
    if selection.trim().eq_ignore_ascii_case("all") {
        return Ok(offered.to_vec());
    }
    let mut selected = Vec::new();
    for part in selection.split(',') {
        let model = part
            .trim()
            .parse::<usize>()
            .ok()
            .and_then(|n| n.checked_sub(1))
            .and_then(|n| offered.get(n))
            .ok_or((
                "ORBIT-E1101",
                "model selection must name offered model numbers".into(),
            ))?;
        if selected.contains(model) {
            return Err(("ORBIT-E1101", "model selection contains duplicates".into()));
        }
        selected.push(model.clone());
    }
    Ok(selected)
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
            if let orbit_engine::transcript::TranscriptEvent::Checkpoint { id } = ev
                && id == cp
            {
                seen_cp = true;
                truncated_to = Some(i + 1);
                break;
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
/// - a configured provider endpoint, or explicit `--gate` / `ORBIT_GATE_URL`
/// - `--model` / `ORBIT_MODEL` — REQUIRED; no default model is invented
/// - `ORBIT_GATE_TOKEN` — optional bearer token (never printed/persisted)
fn cmd_ask(home: &Path, args: &[String]) -> Result<serde_json::Value, (&'static str, String)> {
    ensure_initialized(home)?;
    let prompt = args
        .get(1)
        .ok_or(("ORBIT-E1101", "ask requires a prompt".into()))?;
    let model = value_after(args, "--model")
        .or_else(|| std::env::var("ORBIT_MODEL").ok())
        .ok_or(("ORBIT-E1101", "ask requires --model or ORBIT_MODEL".into()))?;
    let cfg = config::ProvidersConfig::load(home).map_err(|e| ("ORBIT-E1106", e))?;
    let turn = orbit_cli::checked_model_turn(
        home,
        &model,
        value_after(args, "--provider").as_deref(),
        value_after(args, "--gate")
            .or_else(|| std::env::var("ORBIT_GATE_URL").ok())
            .as_deref(),
        false,
    )
    .map_err(|error| ("ORBIT-E0401", error))?;
    let provider_id = turn.provider_id.as_str();
    let resolved_gate = turn.gate.as_str();
    let model = turn.model.clone();
    let credential_env = turn.credential_env.as_deref();
    let pricing = cfg.pricing_for_model(&model);

    let detailed = match orbit_cli::run_turn_detailed(
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
    ) {
        Ok(result) => result,
        Err(error) => {
            for notice in &error.context_notices {
                eprintln!("{}", orbit_hud_tui::safe_text(notice));
            }
            return Err((error.code, error.message));
        }
    };
    for notice in &detailed.context_notices {
        eprintln!("{}", orbit_hud_tui::safe_text(notice));
    }
    let estimate_status = match detailed.estimate.status {
        orbit_engine::context_budget::EstimateStatus::Approximate => "approximate",
        orbit_engine::context_budget::EstimateStatus::UnknownMedia => "unknown_media",
    };
    eprintln!(
        "context estimate: {} text tokens, {} requested output tokens ({estimate_status})",
        detailed.estimate.estimated_input_tokens, detailed.estimate.requested_output_tokens,
    );
    let outcome = detailed.outcome;
    Ok(serde_json::json!({
        "schema": "orbit.cli/v1",
        "command": "ask",
        "status": "ok",
        "model": model,
        "output": outcome.output,
        "ledger_recorded": true,
        "context_notices": detailed.context_notices,
        "context_estimate": {
            "status":estimate_status,
            "body_bytes":detailed.estimate.body_bytes,
            "text_bytes":detailed.estimate.text_bytes,
            "estimated_input_tokens":detailed.estimate.estimated_input_tokens,
            "requested_output_tokens":detailed.estimate.requested_output_tokens,
        },
        "usage": {
            "input_tokens": outcome.input_tokens,
            "output_tokens": outcome.output_tokens,
            "cost_microcents": outcome.cost_microcents,
        }
    }))
}

/// Build the session's frozen system prompt for the REPL / headless
/// paths (same shape as the TUI worker's).
fn build_session_prompt(home: &Path, model: &str) -> orbit_engine::context::SystemPrompt {
    let defs = tools::session_tool_definitions(home);
    let tool_names: Vec<&str> = defs.iter().map(|d| d.name.as_str()).collect();
    build_session_prompt_with_tool_names(home, model, &tool_names)
}

fn build_session_prompt_with_tool_names(
    home: &Path,
    model: &str,
    tool_names: &[&str],
) -> orbit_engine::context::SystemPrompt {
    let mods = orbit_cli::mods::load_all(home);
    let enabled = orbit_cli::mods::initial_enabled(home, &mods);
    let mods_directive = orbit_cli::mods::system_directive(&mods, &enabled);
    orbit_engine::context::build_system_prompt(
        home,
        &std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
        model,
        tool_names,
        &mods_directive,
    )
}

fn parse_compact_arguments(args: &[String]) -> Result<(String, PathBuf, bool), &'static str> {
    let mut session = None;
    let mut seen_home = false;
    let mut json = false;
    let mut command = false;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "compact" if !command => command = true,
            "--home" if !seen_home => {
                args.get(index + 1)
                    .filter(|value| !value.is_empty() && !value.starts_with("--"))
                    .ok_or("compact_usage")?;
                seen_home = true;
                index += 1;
            }
            "--session" if command && session.is_none() => {
                let value = args
                    .get(index + 1)
                    .filter(|value| !value.starts_with('-'))
                    .ok_or("compact_usage")?;
                let id = value.strip_suffix(".json").unwrap_or(value);
                if id.is_empty()
                    || id.len() > 128
                    || !id
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
                {
                    return Err("invalid_session_id");
                }
                session = Some(id.to_owned());
                index += 1;
            }
            "--json" if command && !json => json = true,
            _ => return Err("compact_usage"),
        }
        index += 1;
    }
    if !command {
        return Err("compact_usage");
    }
    Ok((
        session.ok_or("compact_usage")?,
        config::resolve_home(args),
        json,
    ))
}

/// The same held namespace and actual token cover discovery, summaries and the
/// single final publication. Returned receipts have already settled in journal.
fn compact_local_session(
    owner: (
        &sessions::SessionLease,
        &session_accounting::RootSessionAccounting,
    ),
    working: &mut sessions::SessionFile,
    scope: &tool_runtime::PermissionScope,
    cancel: &orbit_provider_http::CancelToken,
    events: orbit_engine::EventSink<'_>,
) -> (
    Result<orbit_engine::ManualCompactionCompletion, &'static str>,
    Result<session_accounting::AccountingView, session_accounting::AccountingError>,
) {
    let (lease, accounting) = owner;
    let result = (|| {
        if cancel.is_cancelled() {
            return Err("cancelled");
        }
        let home = lease.home();
        let turn = chat_effort_config(
            home,
            &working.model,
            &working.gate,
            Some(&working.provider),
            working.effort.as_ref(),
        )
        .map_err(|_| "selection_invalid")?;
        let compaction = orbit_cli::try_role_turn_config(home, &turn, "compaction")
            .map_err(|_| "compaction_selection_invalid")?;
        let mut options = orbit_engine::TurnOptions {
            session_id: working.session_id.clone(),
            request_stem: format!("orbit-local-compact-{}", orbit_gateway::new_session_id()),
            max_attempts: 1,
            compaction_config: Some(compaction),
            ..Default::default()
        };
        let notices = orbit_cli::model_limits::apply_turn_budgets(home, &turn, &mut options)
            .map_err(|_| "context_budget_invalid")?;
        accounting
            .namespace()
            .apply_options_detailed(&mut options, None, None)
            .map_err(|_| "accounting_admission_refused")?;
        let cx = orbit_tools::ToolContext::new(
            home.to_path_buf(),
            working.session_id.clone(),
            std::env::current_dir().map_err(|_| "workspace_unavailable")?,
        );
        tool_runtime::remember_effort_setting(&cx, &working.effort);
        tool_runtime::begin_cancel_scope(&cx, cancel);
        struct CancelScope<'a>(&'a orbit_tools::ToolContext);
        impl Drop for CancelScope<'_> {
            fn drop(&mut self) {
                self.0.pop_cancel_check();
            }
        }
        let _scope = CancelScope(&cx);
        if cancel.is_cancelled() {
            return Err("cancelled");
        }
        let mut definitions =
            tools::session_tool_definitions_with_context(home, &cx, scope.allowlist.as_deref());
        definitions.retain(|definition| {
            !scope.disallowlist.contains(&definition.name)
                && scope
                    .allowlist
                    .as_ref()
                    .is_none_or(|allow| allow.contains(&definition.name))
        });
        let tool_names: Vec<&str> = definitions
            .iter()
            .map(|definition| definition.name.as_str())
            .collect();
        let prompt = build_session_prompt_with_tool_names(home, &turn.model, &tool_names);
        options.memory_bytes = prompt.memory_bytes;
        options.system_directive = Some(prompt.text);
        options.tools = definitions;
        for text in notices {
            events(orbit_frontend_protocol::FrontendEvent::Status { text });
        }
        Ok(orbit_engine::compact_context_detailed(
            home,
            &turn,
            &options,
            &mut working.transcript,
            cancel,
            events,
        ))
    })();
    // This common path also retains paid failure/cancel results. Never fold the
    // completion's accounting delta a second time or retry a failed save here.
    let persisted = accounting.persist(lease, working);
    (result, persisted)
}

/// A successful inspection may advance the namespace floor, so exact equality
/// with the just-projected revision is required before showing its qualification.
fn checked_local_accounting(
    accounting: &session_accounting::RootSessionAccounting,
    working: &sessions::SessionFile,
    persisted: &Result<session_accounting::AccountingView, session_accounting::AccountingError>,
) -> Option<session_accounting::AccountingView> {
    let projected = match persisted {
        Ok(view) => Some(*view),
        Err(session_accounting::AccountingError::Session(_)) => working
            .accounting_watermark
            .as_ref()
            .filter(|anchor| {
                anchor.owner_session_id == working.session_id && anchor.child_id.is_none()
            })
            .map(|anchor| session_accounting::AccountingView {
                revision: anchor.revision,
                input_tokens: working.input_tokens,
                output_tokens: working.output_tokens,
                known_cost_microcents: working.cost_microcents,
                full_cost_status: anchor.full_cost_status,
            }),
        _ => None,
    };
    let checkpoint = accounting.namespace().checkpoint_detailed().ok()?;
    let view = projected?;
    let uncertain = checkpoint.pending().is_some()
        || checkpoint.totals().knownness == orbit_engine::AccountingKnownness::Uncertain;
    (checkpoint.owner_session_id() == working.session_id
        && checkpoint.child_id().is_none()
        && checkpoint.revision().0 == view.revision
        && uncertain == (view.full_cost_status == FullCostStatus::Uncertain))
        .then_some(view)
}

fn compact_local_output(
    working: &sessions::SessionFile,
    result: &Result<orbit_engine::ManualCompactionCompletion, &'static str>,
    persisted: &Result<session_accounting::AccountingView, session_accounting::AccountingError>,
    checked: Option<session_accounting::AccountingView>,
) -> (serde_json::Value, i32) {
    use orbit_engine::CompactionStatus as S;
    let (reason, applied) = match result {
        Err(reason) => (*reason, false),
        Ok(completion) => (
            match completion.status {
                S::NothingToCompact => "nothing_to_compact",
                S::InvalidHistory => "invalid_history",
                S::ProtectedTooLarge => "protected_too_large",
                S::SummaryTooLarge => "summary_too_large",
                S::SourceTooLarge => "source_too_large",
                S::MissingJournal => "missing_journal",
                S::SummaryUnusable => "summary_unusable",
                S::Cancelled => "cancelled",
                S::StorageUnsafe => "storage_unsafe",
                S::PublicationUncertain => "publication_uncertain",
                S::AccountingUncertain => "accounting_uncertain",
                S::SpendRefused => "spend_refused",
                S::AccountingLimit => "accounting_limit",
                S::PublishedReady => "published_ready",
            },
            completion.applied,
        ),
    };
    let status = if persisted.is_err()
        || checked.is_none_or(|view| view.full_cost_status == FullCostStatus::Uncertain)
        || matches!(reason, "publication_uncertain" | "accounting_uncertain")
    {
        "unknown"
    } else if reason == "nothing_to_compact" || (reason == "published_ready" && applied) {
        "completed"
    } else if reason == "cancelled" {
        "cancelled"
    } else {
        "failed"
    };
    (
        serde_json::json!({
            "schema":"orbit.cli/v1", "command":"compact", "session":working.session_id,
            "status":status, "reason":reason, "applied":applied, "snapshot_saved":persisted.is_ok(),
            "turns":working.turns,
            "usage":{"input_tokens":working.input_tokens,"output_tokens":working.output_tokens},
            "cost_microcents":working.cost_microcents,
            "accounting_revision":checked.map(|view| view.revision),
            "full_cost_status":checked.map(|view| view.full_cost_status),
        }),
        if status == "completed" { 0 } else { 1 },
    )
}

fn print_compact_output(value: &serde_json::Value, json: bool) {
    if json {
        println!("{value}");
    } else {
        println!(
            "compaction: {} ({}); applied={}, snapshot_saved={}; known cost {} microcents; full cost {}",
            value["status"].as_str().unwrap_or("unknown"),
            value["reason"].as_str().unwrap_or("unavailable"),
            value["applied"],
            value["snapshot_saved"],
            value["cost_microcents"],
            value["full_cost_status"].as_str().unwrap_or("unavailable")
        );
    }
}

fn compact_local_progress(event: orbit_frontend_protocol::FrontendEvent) {
    if matches!(
        event,
        orbit_frontend_protocol::FrontendEvent::Compacting { .. }
    ) {
        eprintln!("compacting context");
    }
}

fn compact_local_failed(
    result: &Result<orbit_engine::ManualCompactionCompletion, &'static str>,
    persisted: &Result<session_accounting::AccountingView, session_accounting::AccountingError>,
    checked: Option<session_accounting::AccountingView>,
) -> bool {
    if persisted.is_err() || checked.is_none() {
        return true;
    }
    match result {
        Err(reason) => *reason != "cancelled",
        Ok(completion) if completion.status == orbit_engine::CompactionStatus::Cancelled => false,
        Ok(completion)
            if completion.status == orbit_engine::CompactionStatus::NothingToCompact
                || (completion.status == orbit_engine::CompactionStatus::PublishedReady
                    && completion.applied) =>
        {
            checked.is_some_and(|view| view.full_cost_status == FullCostStatus::Uncertain)
        }
        Ok(_) => true,
    }
}

fn plain_signal_exit_code(signal: i32, ordinary: i32, failed: bool) -> i32 {
    if failed {
        1
    } else if signal != 0 {
        128 + signal
    } else {
        ordinary
    }
}

fn close_plain_signals(
    guard: &mut ProcessSignalGuard,
    ordinary: i32,
    failed: impl FnOnce(i32) -> bool,
) -> i32 {
    match guard.close() {
        Ok(signal) => plain_signal_exit_code(signal, ordinary, failed(signal)),
        Err(error) => {
            eprintln!("process signal cleanup failed: {error}");
            1
        }
    }
}

fn cmd_compact(args: &[String]) -> i32 {
    let (id, home, json) = match parse_compact_arguments(args) {
        Ok(arguments) => arguments,
        Err(reason) => {
            eprintln!(
                "ORBIT-E1101: {reason}; usage: orbit compact --session ID [--home PATH] [--json]"
            );
            return 2;
        }
    };
    let (lease, mut working) = match sessions::SessionLease::acquire_and_load(&home, &id, "compact")
    {
        Ok(owned) => owned,
        Err(_) => {
            eprintln!("ORBIT-E0400: saved session unavailable or busy");
            return 2;
        }
    };
    let accounting = match session_accounting::prepare_root(
        &lease,
        &mut working,
        RootOrigin::RestoredOrLegacy,
    ) {
        Ok(accounting) => accounting,
        Err(_) => {
            eprintln!("ORBIT-E0400: session accounting inspection required");
            return 2;
        }
    };
    let mut signal_guard = match ProcessSignalGuard::new() {
        Ok(guard) => guard,
        Err(error) => {
            eprintln!("process signal setup failed: {error}");
            return 1;
        }
    };
    signal_guard.sync_signal();
    let mut events = compact_local_progress;
    let (result, persisted) = compact_local_session(
        (&lease, &accounting),
        &mut working,
        &tool_runtime::PermissionScope::default(),
        signal_guard.token(),
        &mut events,
    );
    let checked = checked_local_accounting(&accounting, &working, &persisted);
    let failed = compact_local_failed(&result, &persisted, checked);
    signal_guard.sync_signal();
    let (output, code) = compact_local_output(&working, &result, &persisted, checked);
    print_compact_output(&output, json);
    close_plain_signals(&mut signal_guard, code, |_| failed)
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
    if let Some(req) = schema.get("required").and_then(|r| r.as_array())
        && let serde_json::Value::Object(map) = v
    {
        for r in req {
            if let Some(name) = r.as_str()
                && !map.contains_key(name)
            {
                problems.push(format!("{path}: missing required field {name:?}"));
            }
        }
    }
    if let (Some(props), serde_json::Value::Object(map)) = (schema.get("properties"), v) {
        for (name, sub) in props.as_object().unwrap_or(&serde_json::Map::new()) {
            if let Some(val) = map.get(name)
                && let Err(p) = validate_value(val, sub, &format!("{path}.{name}"))
            {
                problems.extend(p);
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
    if let Some(en) = schema.get("enum").and_then(|e| e.as_array())
        && !en.contains(v)
    {
        problems.push(format!("{path}: not in enum"));
    }
    if problems.is_empty() {
        Ok(())
    } else {
        Err(problems)
    }
}

fn owned_startup_session_with_origin(
    home: &Path,
    args: &[String],
    kind: &str,
    fresh_id: &str,
) -> Result<
    (
        sessions::SessionLease,
        Option<sessions::SessionFile>,
        RootOrigin,
    ),
    String,
> {
    let requested = if args.iter().any(|arg| arg == "--resume") {
        Some(
            value_after(args, "--resume")
                .filter(|id| !id.is_empty())
                .ok_or("--resume requires a session id")?,
        )
    } else {
        None
    };
    let continuing = args.iter().any(|arg| arg == "--continue");
    let forking = args.iter().any(|arg| arg == "--fork-session");
    let source_id = if continuing || (forking && requested.is_none()) {
        sessions::list_sessions(home)?
            .first()
            .map(|saved| saved.session_id.clone())
    } else {
        requested
    };
    let Some(source_id) = source_id else {
        let lease = sessions::SessionLease::acquire(home, fresh_id, kind)
            .map_err(|error| error.to_string())?;
        if lease
            .load_optional()
            .map_err(|error| error.to_string())?
            .is_some()
        {
            return Err("session already exists; use --resume <id>".into());
        }
        return Ok((lease, None, RootOrigin::FreshCandidate));
    };
    let (source_lease, mut saved) =
        sessions::SessionLease::acquire_and_load(home, &source_id, kind)
            .map_err(|error| error.to_string())?;
    if !forking {
        return Ok((source_lease, Some(saved), RootOrigin::RestoredOrLegacy));
    }
    let lease =
        sessions::SessionLease::acquire(home, fresh_id, kind).map_err(|error| error.to_string())?;
    if lease
        .load_optional()
        .map_err(|error| error.to_string())?
        .is_some()
    {
        return Err("fork target already exists".into());
    }
    copy_owned_fork_transcript(home, source_lease.session_id(), lease.session_id())?;
    saved.session_id = lease.session_id().into();
    saved.accounting_watermark = None;
    saved.updated_at = orbit_cli::timestamp_now();
    lease
        .save_if_absent(&saved)
        .map_err(|error| error.to_string())?;
    Ok((lease, Some(saved), RootOrigin::ForkedThisInvocation))
}

#[cfg(test)]
fn owned_startup_session(
    home: &Path,
    args: &[String],
    kind: &str,
    fresh_id: &str,
) -> Result<(sessions::SessionLease, Option<sessions::SessionFile>), String> {
    owned_startup_session_with_origin(home, args, kind, fresh_id)
        .map(|(lease, saved, _origin)| (lease, saved))
}

fn copy_owned_fork_transcript(home: &Path, source: &str, target: &str) -> Result<(), String> {
    use std::io::{Read, Write};
    let directory = home.join("projects");
    let source_path = directory.join(format!("{source}.jsonl"));
    match std::fs::symlink_metadata(&source_path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(format!("fork transcript: {error}")),
        Ok(metadata) if !metadata.is_file() => {
            return Err("fork transcript must be a regular file".into());
        }
        _ => {}
    }
    if !std::fs::symlink_metadata(&directory)
        .map_err(|error| error.to_string())?
        .is_dir()
    {
        return Err("fork transcript directory must not be a symlink".into());
    }
    let mut source_options = std::fs::OpenOptions::new();
    source_options.read(true);
    let mut target_options = std::fs::OpenOptions::new();
    target_options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        source_options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
        target_options.custom_flags(libc::O_NOFOLLOW).mode(0o600);
    }
    let input = source_options
        .open(source_path)
        .map_err(|error| error.to_string())?;
    if !input
        .metadata()
        .map_err(|error| error.to_string())?
        .is_file()
    {
        return Err("fork transcript must be a regular file".into());
    }
    let mut bytes = Vec::new();
    input
        .take(64 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes.len() > 64 * 1024 * 1024 {
        return Err("fork transcript exceeds 64 MiB".into());
    }
    let mut output = target_options
        .open(directory.join(format!("{target}.jsonl")))
        .map_err(|error| error.to_string())?;
    output
        .write_all(&bytes)
        .and_then(|_| output.sync_all())
        .map_err(|error| error.to_string())?;
    std::fs::File::open(directory)
        .and_then(|file| file.sync_all())
        .map_err(|error| error.to_string())
}

#[cfg(test)]
mod owned_startup_tests {
    use super::*;
    use sessions::{SessionFile, SessionLease, SessionLeaseError};

    fn home() -> PathBuf {
        let home = std::env::temp_dir().join(format!("orbit-p35-startup-{}", ulid::Ulid::new()));
        std::fs::create_dir_all(&home).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        home
    }
    fn saved(home: &Path, id: &str, updated: &str) -> SessionFile {
        let lease = SessionLease::acquire(home, id, "fixture").unwrap();
        let mut session =
            SessionFile::from_chat(id, "m", "http://127.0.0.1:1", "p", &[], 7, 2, 3, 4)
                .with_effort(Some(EffortSetting::Default));
        session.updated_at = updated.into();
        lease.save(&session).unwrap();
        session
    }
    fn args(words: &[&str]) -> Vec<String> {
        words.iter().map(|word| word.to_string()).collect()
    }

    #[test]
    fn fresh_session_is_owned_before_first_persistence() {
        let home = home();
        let (lease, saved) = owned_startup_session(&home, &[], "chat", "fresh").unwrap();
        assert!(saved.is_none());
        assert!(!home.join("sessions/fresh.json").exists());
        assert!(matches!(
            SessionLease::acquire(&home, "fresh", "other"),
            Err(SessionLeaseError::Busy { .. })
        ));
        drop(lease);
        assert!(SessionLease::acquire(&home, "fresh", "after").is_ok());
        std::fs::remove_dir_all(home).unwrap();
    }
    #[test]
    fn busy_resume_refuses_without_fresh_fallback_or_disk_change() {
        let home = home();
        saved(&home, "busy", "2026-10-14T12:00:00Z");
        let guard = SessionLease::acquire(&home, "busy", "daemon").unwrap();
        let before = std::fs::read(home.join("sessions/busy.json")).unwrap();
        let error = owned_startup_session(&home, &args(&["--resume", "busy"]), "headless", "fresh")
            .unwrap_err();
        assert!(error.contains("already owned"), "{error}");
        assert_eq!(
            std::fs::read(home.join("sessions/busy.json")).unwrap(),
            before
        );
        assert!(!home.join("sessions/fresh.json").exists());
        drop(guard);
        std::fs::remove_dir_all(home).unwrap();
    }
    #[test]
    fn resume_loads_exact_saved_identity_and_effort_under_lease() {
        let home = home();
        saved(&home, "prior", "2026-10-14T12:00:00Z");
        let (lease, session) =
            owned_startup_session(&home, &args(&["--resume", "prior.json"]), "chat", "fresh")
                .unwrap();
        let session = session.unwrap();
        assert_eq!(session.session_id, lease.session_id());
        assert_eq!(session.turns, 7);
        assert_eq!(session.effort, Some(EffortSetting::Default));
        assert!(matches!(
            SessionLease::acquire(&home, "prior", "other"),
            Err(SessionLeaseError::Busy { .. })
        ));
        drop(lease);
        std::fs::remove_dir_all(home).unwrap();
    }
    #[test]
    fn continue_refuses_busy_latest_instead_of_selecting_older_session() {
        let home = home();
        saved(&home, "old", "2026-10-14T11:00:00Z");
        saved(&home, "latest", "2026-10-14T12:00:00Z");
        let guard = SessionLease::acquire(&home, "latest", "daemon").unwrap();
        assert!(
            owned_startup_session(&home, &args(&["--continue"]), "chat", "fresh")
                .unwrap_err()
                .contains("already owned")
        );
        assert!(!home.join("sessions/fresh.json").exists());
        drop(guard);
        std::fs::remove_dir_all(home).unwrap();
    }
    #[test]
    fn fork_acquires_target_before_any_new_saved_state() {
        let home = home();
        saved(&home, "source", "2026-10-14T12:00:00Z");
        let before = std::fs::read(home.join("sessions/source.json")).unwrap();
        let guard = SessionLease::acquire(&home, "fresh", "other").unwrap();
        assert!(
            owned_startup_session(
                &home,
                &args(&["--resume", "source", "--fork-session"]),
                "chat",
                "fresh"
            )
            .is_err()
        );
        assert_eq!(
            std::fs::read(home.join("sessions/source.json")).unwrap(),
            before
        );
        assert!(!home.join("sessions/fresh.json").exists());
        assert!(SessionLease::acquire(&home, "source", "after").is_ok());
        drop(guard);
        std::fs::remove_dir_all(home).unwrap();
    }
    #[test]
    fn fork_preserves_source_and_copies_transcript_under_new_target_lease() {
        let home = home();
        saved(&home, "source", "2026-10-14T12:00:00Z");
        std::fs::create_dir(home.join("projects")).unwrap();
        let history = b"{\"kind\":\"fixture\"}\n";
        std::fs::write(home.join("projects/source.jsonl"), history).unwrap();
        let before = std::fs::read(home.join("sessions/source.json")).unwrap();
        let (lease, session) = owned_startup_session(
            &home,
            &args(&["--resume", "source", "--fork-session"]),
            "chat",
            "fresh",
        )
        .unwrap();
        assert_eq!(session.unwrap().session_id, "fresh");
        assert_eq!(
            std::fs::read(home.join("projects/fresh.jsonl")).unwrap(),
            history
        );
        assert_eq!(
            std::fs::read(home.join("sessions/source.json")).unwrap(),
            before
        );
        assert!(matches!(
            SessionLease::acquire(&home, "fresh", "other"),
            Err(SessionLeaseError::Busy { .. })
        ));
        drop(lease);
        std::fs::remove_dir_all(home).unwrap();
    }
    #[test]
    fn malformed_resume_identity_never_loads_or_creates_fresh_state() {
        let home = home();
        assert!(
            owned_startup_session(&home, &args(&["--resume", "../outside"]), "chat", "fresh")
                .is_err()
        );
        assert!(!home.join("sessions/fresh.json").exists());
        std::fs::remove_dir_all(home).unwrap();
    }
    #[test]
    fn missing_or_empty_resume_value_never_acquires_fresh_ownership() {
        for values in [vec!["--resume"], vec!["--resume", ""]] {
            let home = home();
            assert!(owned_startup_session(&home, &args(&values), "chat", "fresh").is_err());
            assert!(!home.join("sessions/.leases/fresh.lock").exists());
            assert!(!home.join("sessions/fresh.json").exists());
            std::fs::remove_dir_all(home).unwrap();
        }
    }

    #[test]
    fn fresh_session_id_collision_refuses_without_overwriting_the_existing_snapshot() {
        let home = home();
        let id = "already-saved-id";
        let mut original = saved(&home, id, "2026-10-14T12:00:00Z");
        original.transcript = vec![
            orbit_engine::user_message("existing synthetic intent"),
            orbit_engine::assistant_message("existing synthetic answer"),
        ];
        let prior = SessionLease::acquire(&home, id, "fixture").unwrap();
        prior.save(&original).unwrap();
        drop(prior);
        let path = home.join("sessions").join(format!("{id}.json"));
        let before = std::fs::read(&path).unwrap();
        let result = owned_startup_session(&home, &[], "headless", id);
        let refused = result.is_err();
        drop(result);
        assert_eq!(std::fs::read(&path).unwrap(), before);
        let inspection = SessionLease::acquire(&home, id, "inspection").unwrap();
        let after = inspection.load().unwrap();
        assert_eq!(
            serde_json::to_value(after).unwrap(),
            serde_json::to_value(original).unwrap()
        );
        assert!(!home.join("context-history").exists());
        assert!(!home.join("ledger").exists());
        drop(inspection);
        std::fs::remove_dir_all(home).unwrap();
        assert!(
            refused,
            "an existing saved ID cannot establish a new fresh namespace"
        );
    }
}

fn local_budget_refusal(
    prompt: &str,
    options: &orbit_engine::TurnOptions,
    transcript: &mut Vec<orbit_adapter::types::ChatMessage>,
    message: String,
    events: &mut dyn FnMut(orbit_frontend_protocol::FrontendEvent),
) -> Result<orbit_engine::TurnCompletion, String> {
    let mut user = orbit_engine::user_message(prompt);
    user.blocks = options.user_blocks.clone();
    transcript.push(user);
    events(orbit_frontend_protocol::FrontendEvent::Error {
        message: message.clone(),
    });
    events(orbit_frontend_protocol::FrontendEvent::TurnEnded {
        ok: false,
        interrupted: false,
        rounds: 0,
        input_tokens: 0,
        output_tokens: 0,
        cost_microcents: 0,
    });
    Err(message)
}

fn retain_local_session_intent(
    lease: &sessions::SessionLease,
    accounting: &session_accounting::RootSessionAccounting,
    snapshot: &mut sessions::SessionFile,
    transcript: &mut Vec<orbit_adapter::types::ChatMessage>,
    prompt: &str,
) {
    transcript.push(orbit_engine::user_message(prompt));
    snapshot.transcript = transcript.clone();
    if let Err(error) = accounting.persist(lease, snapshot) {
        eprintln!("current prompt could not be saved: {error}");
    }
}

fn context_meter_text(
    used_tokens: u64,
    window_tokens: u64,
    breakdown: Option<orbit_frontend_protocol::ContextBreakdown>,
) -> String {
    match breakdown {
        Some(parts) => format!(
            "context estimate {used_tokens}/{window_tokens} tokens; compact at {}, output reserve {}",
            parts.compact_at, parts.reserve
        ),
        None => format!("context estimate {used_tokens}/{window_tokens} tokens"),
    }
}

fn cmd_headless(args: &[String]) -> i32 {
    let prompt = args.first().map(String::as_str).unwrap_or("");
    if prompt.is_empty() {
        eprintln!("ORBIT-E1101: -p requires a prompt");
        return 1;
    }
    // The consumed prompt is arbitrary text, never an option token.
    let args = &args[1..];
    let options = match headless_execution_options(args) {
        Ok(options) => options,
        Err(error) => {
            eprintln!("ORBIT-E1101: {error}");
            return 1;
        }
    };
    let home = orbit_home(args)
        .or_else(|| std::env::var("ORBIT_HOME").ok().map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from(".orbit"));
    if let Err((code, msg)) = ensure_initialized(&home) {
        eprintln!("{code}: {msg}");
        return 1;
    }
    let requested_gate =
        value_after(args, "--gate").or_else(|| std::env::var("ORBIT_GATE_URL").ok());
    let requested_model =
        value_after(args, "--model").or_else(|| std::env::var("ORBIT_MODEL").ok());
    let format = options.format;
    // --bare: skip discovering hooks, skills, mods, MCP servers and
    // memory files (phase 6 — fast start; recommended for scripts).
    if args.iter().any(|a| a == "--bare") {
        tools::enable_bare_mode();
    }
    // --json-schema <file>: structured output. Anthropic gets
    // output_config.format natively later; here the honest path for
    // every provider: validate the final text as JSON against the
    // schema and retry once with the validation error appended.
    let json_schema = options.schema;
    let max_rounds = options.max_rounds;
    // --auto-tools: up-front consent for pure built-ins (headless CI
    // shape). Without it, dontAsk semantics: anything no allow rule
    // covers is denied — and the exit code says so (2).
    let auto_tools = args.iter().any(|a| a == "--auto-tools");
    let cost_guard = orbit_engine::automation::CostGuard {
        max_microcents: options.max_cost,
    };
    // --permission-mode / --allowedTools / --disallowedTools: the
    // command-line permission scope (review blocker 4), carried in the
    // session's PermissionScope (S5) — never process env vars.
    if let Some(mode) = value_after(args, "--permission-mode")
        && orbit_tools::permissions::PermissionMode::from_config(&mode).is_none()
    {
        eprintln!(
            "ORBIT-E1101: unknown --permission-mode {mode} (default, acceptEdits, plan, dontAsk, bypass)"
        );
        return 1;
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
    let explicit_provider = value_after(args, "--provider");
    if let Some(spec) = &requested_model
        && let Err(error) = orbit_cli::checked_model_turn(
            &home,
            spec,
            explicit_provider.as_deref(),
            requested_gate.as_deref(),
            false,
        )
    {
        eprintln!("ORBIT-E0401: {error}");
        return 1;
    }
    let (live_lease, resumed_file, startup_origin) = match owned_startup_session_with_origin(
        &home,
        args,
        "headless",
        &format!("p-{}", ulid::Ulid::new()),
    ) {
        Ok(owned) => owned,
        Err(error) => {
            eprintln!("cannot open session: {error}");
            return 1;
        }
    };
    let spec = requested_model
        .clone()
        .or_else(|| resumed_file.as_ref().map(|saved| saved.model.clone()))
        .or_else(|| (!cfg.roles.main.is_empty()).then(|| cfg.roles.main.clone()))
        .or_else(|| {
            cfg.provider.iter().find_map(|provider| {
                provider
                    .models
                    .first()
                    .map(|model| format!("{}/{}", provider.name, model.id))
            })
        });
    let Some(spec) = spec else {
        eprintln!("ORBIT-E1101: configure a provider/model or supply --model and --gate");
        return 1;
    };
    let saved_identity = requested_model.is_none() && resumed_file.is_some();
    let provider_hint = explicit_provider
        .or_else(|| saved_identity.then(|| resumed_file.as_ref().unwrap().provider.clone()));
    let mut turn_config = match orbit_cli::checked_model_turn(
        &home,
        &spec,
        provider_hint.as_deref(),
        requested_gate.as_deref(),
        saved_identity,
    ) {
        Ok(turn) => turn,
        Err(error) => {
            eprintln!("ORBIT-E0401: {error}");
            return 1;
        }
    };
    let model = turn_config.model.clone();
    let provider_id = turn_config.provider_id.clone();
    let resolved_gate = turn_config.gate.clone();

    let selection_origin = orbit_cli::startup_selection_origin(
        value_after(args, "--model").is_some(),
        std::env::var("ORBIT_MODEL").is_ok(),
        resumed_file.as_ref(),
        !cfg.roles.main.is_empty(),
    );
    // Session persistence in headless mode (phase 4): --continue /
    // --resume load the prior transcript; after the turn the session
    // is saved so the next --continue finds it. Without this, a
    // killed session's work is lost (gate 4).
    // A busy session refuses before any session-start hook can run.
    {
        let hooks =
            orbit_engine::hooks::Hooks::load(&home, orbit_engine::hooks::project_trusted(&home));
        let _ = hooks.fire(
            orbit_engine::hooks::HookEvent::SessionStart,
            &serde_json::json!({ "frontend": "headless" }),
        );
    }
    let selected_effort = match startup_effort_argument(args, std::env::var("ORBIT_EFFORT").ok()) {
        Ok(s) => sessions::startup_effort(s, resumed_file.as_ref(), &model, &provider_id),
        Err(e) => {
            eprintln!("ORBIT-E1101: {e}");
            return 1;
        }
    };
    if let Err(e) = apply_selected_effort(&home, &mut turn_config, selected_effort.as_ref()) {
        eprintln!("ORBIT-E0401: {e}");
        return 1;
    }
    let mut session_id = live_lease.session_id().to_string();
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
    let mut initial = sessions::SessionFile::from_chat(
        &session_id,
        &model,
        &resolved_gate,
        &provider_id,
        &transcript,
        turns,
        in_tokens,
        out_tokens,
        cost_microcents,
    )
    .with_effort(selected_effort.clone())
    .with_selection_origin(selection_origin);
    let accounting =
        match session_accounting::prepare_root(&live_lease, &mut initial, startup_origin) {
            Ok(accounting) => accounting,
            Err(error) => {
                eprintln!("ORBIT-E0400: {error}");
                return 1;
            }
        };
    let next_turns = match turns.checked_add(1) {
        Some(value) => value,
        None => {
            retain_local_session_intent(
                &live_lease,
                &accounting,
                &mut initial,
                &mut transcript,
                prompt,
            );
            eprintln!("session turn count overflows");
            return 1;
        }
    };
    let spend_policy = match cost_guard
        .max_microcents
        .map(|allowance| {
            let checkpoint = accounting
                .namespace()
                .checkpoint_detailed()
                .map_err(|error| error.to_string())?;
            let spent = checkpoint
                .known_priced_subtotals()
                .ok_or("known priced accounting is unavailable")?;
            let maximum_microcents = spent
                .ordinary_microcents
                .checked_add(spent.housekeeping_microcents)
                .and_then(|sum| sum.checked_add(allowance))
                .ok_or("invocation spend ceiling overflows")?;
            Ok::<_, String>(NamespaceSpendPolicy {
                maximum_microcents,
                allow_unpriced_housekeeping: false,
            })
        })
        .transpose()
    {
        Ok(policy) => policy,
        Err(error) => {
            retain_local_session_intent(
                &live_lease,
                &accounting,
                &mut initial,
                &mut transcript,
                prompt,
            );
            eprintln!("ORBIT-E0411: {error}");
            return 1;
        }
    };
    let base_turn_config = turn_config.clone();
    let (turn_config, routing_decision) = match orbit_cli::try_phase_turn_config(
        &home,
        &base_turn_config,
        prompt,
        selection_origin,
    ) {
        Ok(value) => value,
        Err(error) => {
            retain_local_session_intent(
                &live_lease,
                &accounting,
                &mut initial,
                &mut transcript,
                prompt,
            );
            eprintln!("ORBIT-E0401: {error}");
            return 1;
        }
    };
    let tool_cx = orbit_tools::ToolContext::new(
        home.clone(),
        session_id.clone(),
        std::env::current_dir().unwrap_or_else(|_| std::path::Path::new(".").to_path_buf()),
    );
    tool_runtime::remember_effort_setting(
        &tool_cx,
        if turn_config.provider_id == base_turn_config.provider_id
            && turn_config.model == base_turn_config.model
        {
            &selected_effort
        } else {
            &None
        },
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
    if let Some(decision) = &routing_decision
        && stream_json
    {
        println!(
            "{}",
            serde_json::json!({"type":"status","text":format!("route {}/{} → {}/{}",decision.phase.as_str(),decision.difficulty.as_str(),decision.provider_id,decision.raw_model)})
        );
    }
    let mut context_notices = Vec::new();
    let mut context_usage = Vec::new();
    let mut events = |ev: orbit_frontend_protocol::FrontendEvent| {
        if stream_json {
            println!("{}", serde_json::to_string(&ev).unwrap_or_default());
            let _ = std::io::stdout().flush();
        }
        match &ev {
            orbit_frontend_protocol::FrontendEvent::Status { text } => {
                let text = orbit_hud_tui::safe_text(text);
                if !stream_json {
                    eprintln!("{text}");
                }
                context_notices.push(text);
            }
            orbit_frontend_protocol::FrontendEvent::Usage {
                used_tokens,
                window_tokens,
                breakdown,
            } => {
                if !stream_json {
                    eprintln!(
                        "{}",
                        context_meter_text(*used_tokens, *window_tokens, *breakdown)
                    );
                }
                context_usage.push(serde_json::to_value(&ev).unwrap_or_default());
            }
            _ => {}
        }
        // C4: a refusal says WHY on stderr — one line a script (or an
        // operator redirected to a log) can read without parsing the
        // JSON stream. Works in every output format.
        if let orbit_frontend_protocol::FrontendEvent::ToolDenied { tool, reason, .. } = &ev {
            eprintln!("orbit: {tool} denied: {reason}");
        }
    };
    let session_prompt = build_session_prompt(&home, &model);
    let mut options = orbit_engine::TurnOptions {
        tools: tools::session_tool_definitions(&home),
        max_rounds,
        // The frozen system prompt: the model learns the working
        // directory, the platform, ORBIT.md and the tools (review
        // blocker 5).
        memory_bytes: session_prompt.memory_bytes,
        system_directive: Some(session_prompt.text),
        request_stem: "orbit-p".into(),
        session_id: session_id.clone(),
        compaction_config: Some(
            match orbit_cli::try_role_turn_config(&home, &turn_config, "compaction") {
                Ok(c) => c,
                Err(e) => {
                    retain_local_session_intent(
                        &live_lease,
                        &accounting,
                        &mut initial,
                        &mut transcript,
                        prompt,
                    );
                    eprintln!("ORBIT-E0401: {e}");
                    return 1;
                }
            },
        ),
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

    let mut signal_guard = match ProcessSignalGuard::new() {
        Ok(guard) => guard,
        Err(error) => {
            retain_local_session_intent(
                &live_lease,
                &accounting,
                &mut initial,
                &mut transcript,
                prompt,
            );
            eprintln!("ORBIT-E0400: {error}");
            return 1;
        }
    };
    signal_guard.sync_signal();
    let first = match orbit_cli::model_limits::apply_turn_budgets(&home, &turn_config, &mut options)
        .map_err(|error| error.to_string())
        .and_then(|notices| {
            for text in notices {
                events(orbit_frontend_protocol::FrontendEvent::Status { text });
            }
            let retry_policy = orbit_cli::provider_policies::load_for_config(&home, &turn_config)
                .map_err(|error| error.to_string())?;
            accounting
                .namespace()
                .apply_options_detailed(&mut options, spend_policy, retry_policy.as_ref())
                .map_err(|error| error.to_string())?;
            Ok(retry_policy)
        }) {
        Ok(retry_policy) => {
            signal_guard.sync_signal();
            Ok(orbit_engine::turn::run_turn_detailed_with_retry_policy(
                &home,
                &turn_config,
                &options,
                prompt,
                &mut transcript,
                &mut executor,
                signal_guard.token(),
                &mut events,
                retry_policy.as_ref(),
            )
            .into_completion())
        }
        Err(error) => local_budget_refusal(prompt, &options, &mut transcript, error, &mut events),
    };
    let mut completions = Vec::with_capacity(2);
    let mut local_error = match first {
        Ok(completion) => {
            completions.push(completion);
            None
        }
        Err(error) => Some(error),
    };
    if signal_guard.sync_signal() == 0
        && !signal_guard.token().is_cancelled()
        && let Some(schema) = &json_schema
        && let Some(first) = completions.first()
        && first.end == orbit_engine::TurnEnd::Completed
        && !first.report.final_text.trim().is_empty()
        && let Err(problems) = validate_json_against_schema(&first.report.final_text, schema)
    {
        let repair_prompt = format!(
            "Your previous reply did not match the required JSON schema: {problems}. Reply with ONLY valid JSON matching this schema: {schema}"
        );
        events(orbit_frontend_protocol::FrontendEvent::Status {
            text: format!("schema validation failed, repairing once: {problems}"),
        });
        let mut repair_options = options.clone();
        repair_options.tools.clear();
        repair_options.max_rounds = 1;
        struct RepairExecutor;
        impl orbit_engine::ToolExecutor for RepairExecutor {
            fn execute(
                &mut self,
                calls: &[orbit_engine::PendingToolCall],
                _: u32,
            ) -> Vec<orbit_engine::ToolRoundResult> {
                calls.iter().map(|call| orbit_engine::ToolRoundResult {
                    call_id: call.id.clone(),
                    content: r#"{"ok":false,"denied":true,"error":"schema repair cannot execute tools"}"#.into(),
                }).collect()
            }
        }
        let repair_admission = orbit_cli::provider_policies::load_for_config(&home, &turn_config)
            .map_err(|error| error.to_string())
            .and_then(|retry_policy| {
                accounting
                    .namespace()
                    .apply_options_detailed(
                        &mut repair_options,
                        spend_policy,
                        retry_policy.as_ref(),
                    )
                    .map_err(|error| error.to_string())?;
                Ok(retry_policy)
            });
        // A latched signal skips both dispatch and a synthetic repair refusal
        // prompt: this second engine operation has not been entered.
        if signal_guard.sync_signal() == 0 && !signal_guard.token().is_cancelled() {
            match repair_admission {
                Ok(retry_policy) => {
                    let repair = orbit_engine::turn::run_turn_detailed_with_retry_policy(
                        &home,
                        &turn_config,
                        &repair_options,
                        &repair_prompt,
                        &mut transcript,
                        &mut RepairExecutor,
                        signal_guard.token(),
                        &mut events,
                        retry_policy.as_ref(),
                    )
                    .into_completion();
                    if repair.end == orbit_engine::TurnEnd::Completed
                        && let Err(problems) =
                            validate_json_against_schema(&repair.report.final_text, schema)
                    {
                        local_error = Some(format!(
                            "schema repair did not produce valid output: {problems}"
                        ));
                    }
                    completions.push(repair);
                }
                Err(error) => {
                    let _ = local_budget_refusal(
                        &repair_prompt,
                        &repair_options,
                        &mut transcript,
                        error.clone(),
                        &mut events,
                    );
                    local_error = Some(error);
                }
            }
        }
    }
    if json_schema.is_some()
        && completions.last().is_some_and(|completion| {
            completion.end == orbit_engine::TurnEnd::Completed
                && completion.report.final_text.trim().is_empty()
        })
    {
        local_error = Some("schema output is empty".into());
    }
    let mut completed = signal_guard.sync_signal() == 0
        && !signal_guard.token().is_cancelled()
        && local_error.is_none()
        && completions.last().is_some_and(|completion| {
            completion.end == orbit_engine::TurnEnd::Completed && completion.report.ok
        });

    // RTA (E10): attest from the structured exit status of the last
    // test-like command, in every front-end. A claim after a failing
    // command is an unverified claim and is shown as one.
    let mut rta_verdict: Option<serde_json::Value> = None;
    if completed
        && let Some(scan) = orbit_engine::automation::scan_attestation(&transcript)
        && scan.claimed_pass
    {
        let verdict = if scan.exit_code == 0 {
            serde_json::json!({
                "attested": true,
                "command": scan.command,
                "evidence": "recorded_tool_result",
                "recorded_exit_code": scan.exit_code
            })
        } else {
            serde_json::json!({
                "attested": false,
                "command": scan.command,
                "recorded_exit_code": scan.exit_code,
                "reason": "the current turn lacks a unique completed successful Bash result for this command; the claim is unverified"
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
                                    "recorded Bash command exited 0 (captured tool result)".to_string()
                                } else if scan.exit_code == -1 {
                                    format!(
                                        "UNVERIFIED CLAIM — {} has no unique completed Bash result",
                                        scan.command
                                    )
                                } else {
                                    format!(
                                        "UNVERIFIED CLAIM — {} has captured exit code {}; the claim is not attested",
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

    // Every entered operation, including failures, is projected from the journal.
    let mut saved = sessions::SessionFile::from_chat(
        &session_id,
        &model,
        &resolved_gate,
        &provider_id,
        &transcript,
        next_turns,
        initial.input_tokens,
        initial.output_tokens,
        initial.cost_microcents,
    )
    .with_effort(selected_effort.clone())
    .with_selection_origin(selection_origin);
    let persisted = accounting.persist(&live_lease, &mut saved);
    // A signal during the single final publication cannot leave an earlier
    // Completed result labelled as invocation success.
    completed &= signal_guard.sync_signal() == 0 && !signal_guard.token().is_cancelled();
    let storage_error = persisted.as_ref().err().map(|error| error.to_string());
    if let Some(error) = &storage_error {
        eprintln!("session not saved: {error}");
    }
    let full_status = saved
        .accounting_watermark
        .as_ref()
        .map_or(FullCostStatus::UnknownLegacy, |anchor| {
            anchor.full_cost_status
        });
    if full_status != FullCostStatus::Known {
        eprintln!(
            "full session cost is unknown ({full_status:?}); displayed cost is the known priced subtotal"
        );
    }
    let totals = completions
        .iter()
        .try_fold((0u64, 0u64, 0u64, 0u32), |sum, completion| {
            let report = &completion.report;
            Some((
                sum.0.checked_add(report.input_tokens)?,
                sum.1.checked_add(report.output_tokens)?,
                sum.2.checked_add(report.cost_microcents)?,
                sum.3.checked_add(report.rounds)?,
            ))
        });
    if totals.is_none() {
        local_error = Some("invocation accounting overflows".into());
    }
    let error = storage_error.or(local_error).or_else(|| {
        completions.last().and_then(|completion| {
            if let orbit_engine::TurnEnd::Failed(error) = &completion.end {
                Some(error.message.clone())
            } else {
                None
            }
        })
    });
    let final_report = completions.last().map(|completion| &completion.report);
    completed &= signal_guard.sync_signal() == 0 && !signal_guard.token().is_cancelled();
    let final_text = if completed {
        final_report.map_or("", |report| report.final_text.as_str())
    } else {
        completions
            .first()
            .map_or("", |completion| completion.report.final_text.as_str())
    };
    if json_out {
        let mut value = if let Some(report) = final_report {
            let mut summary = orbit_engine::automation::HeadlessSummary::from_report(
                report,
                orbit_engine::automation::ledger_head(&home),
            );
            summary.ok = completed && error.is_none();
            summary.final_text = final_text.to_owned();
            if let Some((input, output, cost, rounds)) = totals {
                summary.input_tokens = input;
                summary.output_tokens = output;
                summary.cost_microcents = cost;
                summary.rounds = rounds;
            }
            summary.rta = rta_verdict;
            summary.to_json()
        } else {
            serde_json::json!({"schema":"orbit.cli/v1", "command":"p", "status":"error"})
        };
        if totals.is_none() {
            value["usage"] = serde_json::Value::Null;
            value["cost_microcents"] = serde_json::Value::Null;
            value["rounds"] = serde_json::Value::Null;
        }
        if let Some(error) = &error {
            value["status"] = serde_json::json!("error");
            value["error"] = serde_json::json!(error);
        }
        value["context_notices"] = serde_json::json!(context_notices);
        value["context_usage"] = serde_json::json!(context_usage);
        value["full_cost_status"] = serde_json::json!(full_status);
        println!("{value}");
    } else if !stream_json && final_report.is_some() {
        println!("{final_text}");
    }
    if let Some(reason) = totals.and_then(|(_, _, cost, _)| cost_guard.check(cost)) {
        eprintln!("{reason}");
    }
    if let Some(error) = error {
        eprintln!("{error}");
        fire_session_end(&home, "error");
        if let Err(error) = signal_guard.close() {
            eprintln!("process signal cleanup failed: {error}");
        }
        return 1;
    }
    let permission_denied = transcript.iter().any(|message| {
        message.role == orbit_adapter::types::ChatRole::Tool
            && message
                .tool_result
                .as_deref()
                .is_some_and(orbit_tools::result_is_denial)
    });
    let ordinary_code = final_report.map_or(1, |report| {
        orbit_engine::automation::exit_code(report, max_rounds, permission_denied)
    });
    let signal = signal_guard.sync_signal();
    let code = if signal == 0 {
        ordinary_code
    } else {
        128 + signal
    };
    fire_session_end(
        &home,
        if signal != 0 {
            "cancelled"
        } else if code == 0 {
            "ended"
        } else {
            "error"
        },
    );
    match signal_guard.close() {
        Ok(signal) => {
            if signal == 0 {
                code
            } else {
                128 + signal
            }
        }
        Err(error) => {
            eprintln!("process signal cleanup failed: {error}");
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
        // Parallel read-only calls run concurrently (headless is the CI
        // path — a round of Reads is the common shape). The runner owns
        // its state; non-interactive dontAsk semantics as below.
        let home = self.home.clone();
        let session_id = self.session_id.clone();
        let auto_tools = self.auto_tools;
        let scope = self.scope.clone();
        let tool_cx = self.tool_cx.clone();
        let run_ro = move |call: orbit_engine::PendingToolCall| {
            let decision_id = format!("tool-{}-{}", ulid::Ulid::new(), call.index);
            let (result, _) = tool_runtime::execute_call(
                &home,
                &session_id,
                &decision_id,
                &call,
                auto_tools,
                false, // non-interactive: dontAsk semantics
                &mut tool_runtime::StdApprovalChannel::new(false),
                &mut tool_runtime::AutoGrants::new(),
                &scope,
                &tool_cx,
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
        };
        tool_runtime::run_round_parallel(
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
            run_ro,
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
/// Validate chat's complete grammar before worktree, identity or session changes.
fn validate_chat_arguments(args: &[String]) -> Result<(), String> {
    let values = [
        "--home",
        "--model",
        "--provider",
        "--gate",
        "--resume",
        "--effort",
        "--worktree",
        "--permission-mode",
        "--allowedTools",
        "--disallowedTools",
    ];
    let toggles = [
        "--continue",
        "--fork-session",
        "--bare",
        "--tui",
        "--no-tui",
        "--old-tui",
        "--auto-tools",
        "--safe-customization",
    ];
    let mut seen = std::collections::BTreeSet::new();
    let mut command = false;
    let mut index = 0;
    while index < args.len() {
        let word = args[index].as_str();
        if word == "chat" && !command {
            command = true;
            index += 1;
            continue;
        }
        if !seen.insert(word) {
            return Err(format!("duplicate chat option {word}"));
        }
        if values.contains(&word) {
            if args
                .get(index + 1)
                .is_none_or(|value| value.is_empty() || value.starts_with("--"))
            {
                return Err(format!("{word} requires a value"));
            }
            index += 2;
        } else if toggles.contains(&word) {
            index += 1;
        } else {
            return Err(format!("unknown chat option {word}"));
        }
    }
    if seen.contains("--resume") && seen.contains("--continue") {
        return Err("choose --resume or --continue".into());
    }
    if seen.contains("--tui") && seen.contains("--no-tui") {
        return Err("choose --tui or --no-tui".into());
    }
    if let Some(mode) = value_after(args, "--permission-mode")
        && orbit_tools::permissions::PermissionMode::from_config(&mode).is_none()
    {
        return Err("unknown permission mode".into());
    }
    Ok(())
}

fn cmd_chat(args: &[String]) -> i32 {
    if let Err(error) = validate_chat_arguments(args) {
        eprintln!("ORBIT-E1101: {error}");
        return 2;
    }
    // The v1 three-pane HUD was removed; say so rather than pretending the
    // flag is unknown (or, worse, quietly starting the default screen).
    if args.iter().any(|a| a == "--old-tui") {
        eprintln!("orbit: the v1 HUD was removed; use the default screen or --no-tui");
        return 2;
    }
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

    let requested_gate =
        value_after(args, "--gate").or_else(|| std::env::var("ORBIT_GATE_URL").ok());
    let cfg = match config::ProvidersConfig::load(&home) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("ORBIT-E1106: {error}");
            return 2;
        }
    };
    let requested_model = value_after(args, "--model")
        .or_else(|| std::env::var("ORBIT_MODEL").ok())
        .or_else(|| std::env::var("ORBIT_ACTIVE_MODEL").ok());
    let mut model = requested_model
        .clone()
        .or_else(|| (!cfg.roles.main.is_empty()).then(|| cfg.roles.main.clone()))
        .or_else(|| {
            cfg.provider.iter().find_map(|provider| {
                provider
                    .models
                    .first()
                    .map(|model| format!("{}/{}", provider.name, model.id))
            })
        })
        .unwrap_or_default();
    if let Some(spec) = &requested_model
        && let Err(error) = orbit_cli::checked_model_turn(
            &home,
            spec,
            value_after(args, "--provider").as_deref(),
            requested_gate.as_deref(),
            false,
        )
    {
        eprintln!("ORBIT-E0401: {error}");
        return 2;
    }

    // Session identity + persistence. `--resume <id>` loads a prior session's
    // transcript so the conversation continues across invocations.
    // `--continue` reopens the LATEST session in this directory
    // (phase 4; Claude Code parity).
    let (mut live_lease, resumed_file, startup_origin) = match owned_startup_session_with_origin(
        &home,
        args,
        "chat",
        &orbit_gateway::new_session_id(),
    ) {
        Ok(owned) => owned,
        Err(error) => {
            eprintln!("cannot open session: {error}");
            return 2;
        }
    };

    let saved_identity = requested_model.is_none() && resumed_file.is_some();
    if saved_identity {
        model = resumed_file.as_ref().unwrap().model.clone();
    }
    let provider_hint = value_after(args, "--provider")
        .or_else(|| saved_identity.then(|| resumed_file.as_ref().unwrap().provider.clone()));
    let mut startup_turn = match orbit_cli::checked_model_turn(
        &home,
        &model,
        provider_hint.as_deref(),
        requested_gate.as_deref(),
        saved_identity,
    ) {
        Ok(turn) => turn,
        Err(error) => {
            eprintln!("ORBIT-E0401: {error}");
            return 2;
        }
    };
    model = startup_turn.model.clone();
    let mut gate = startup_turn.gate.clone();
    let mut active_provider = startup_turn.provider_id.clone();
    let mut selected_effort =
        match startup_effort_argument(args, std::env::var("ORBIT_EFFORT").ok()) {
            Ok(s) => sessions::startup_effort(s, resumed_file.as_ref(), &model, &active_provider),
            Err(e) => {
                eprintln!("ORBIT-E1101: {e}");
                return 2;
            }
        };
    if let Err(e) = apply_selected_effort(&home, &mut startup_turn, selected_effort.as_ref()) {
        eprintln!("ORBIT-E0401: {e}");
        return 2;
    }

    let mut selection_origin = orbit_cli::startup_selection_origin(
        value_after(args, "--model").is_some(),
        std::env::var("ORBIT_MODEL").is_ok() || std::env::var("ORBIT_ACTIVE_MODEL").is_ok(),
        resumed_file.as_ref(),
        !cfg.roles.main.is_empty(),
    );
    let mut initial = sessions::SessionFile::from_chat(
        live_lease.session_id(),
        &model,
        &gate,
        &active_provider,
        &resumed_file
            .as_ref()
            .map(|saved| saved.to_transcript())
            .unwrap_or_default(),
        resumed_file.as_ref().map_or(0, |saved| saved.turns),
        resumed_file.as_ref().map_or(0, |saved| saved.input_tokens),
        resumed_file.as_ref().map_or(0, |saved| saved.output_tokens),
        resumed_file
            .as_ref()
            .map_or(0, |saved| saved.cost_microcents),
    )
    .with_effort(selected_effort.clone())
    .with_selection_origin(selection_origin);
    let mut accounting =
        match session_accounting::prepare_root(&live_lease, &mut initial, startup_origin) {
            Ok(accounting) => accounting,
            Err(error) => {
                eprintln!("ORBIT-E0400: {error}");
                return 2;
            }
        };
    let mut full_cost_status = initial
        .accounting_watermark
        .as_ref()
        .map(|anchor| anchor.full_cost_status);

    // TUI front-end (DR-20): if TTY + --tui (default), forward to the ratatui
    // TUI. --no-tui, non-TTY stdin/stdout, or the `tui` feature off → fall
    // through to the existing REPL unchanged.
    #[cfg(feature = "tui")]
    {
        let want_tui = !args.iter().any(|a| a == "--no-tui")
            && std::io::IsTerminal::is_terminal(&std::io::stdin())
            && std::io::IsTerminal::is_terminal(&std::io::stdout());
        if want_tui {
            let session_id = live_lease.session_id().to_string();
            let provider_id = active_provider.clone();
            let tui_config = tui_worker::TuiTurnConfig {
                home: home.clone(),
                session_id,
                gate: gate.clone(),
                model: model.clone(),
                effort: selected_effort.clone(),
                provider_id,
                auto_tools: args.iter().any(|a| a == "--auto-tools"),
                scope: tool_runtime::PermissionScope::from_flags(
                    value_after(args, "--permission-mode").as_deref(),
                    value_after(args, "--allowedTools").as_deref(),
                    value_after(args, "--disallowedTools").as_deref(),
                ),
                initial_transcript: initial.to_transcript(),
                initial_turns: initial.turns,
                initial_input_tokens: initial.input_tokens,
                initial_output_tokens: initial.output_tokens,
                initial_cost_microcents: initial.cost_microcents,
            };
            let identity = orbit_hud_tui::model::StartupIdentity {
                model: tui_config.model.clone(),
                provider_id: tui_config.provider_id.clone(),
                session_id: tui_config.session_id.clone(),
            };
            let host = orbit_cli::customization_host::host(
                &home,
                &std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
                tui_config.scope.clone(),
                args.iter().any(|arg| arg == "--safe-customization"),
            );
            return orbit_hud_tui::run_proto_with_startup(
                args,
                tui_worker::make_spawner_owned(tui_config, live_lease),
                home.clone(),
                identity,
                host,
            );
        }
    }

    let mut signal_guard = match ProcessSignalGuard::new() {
        Ok(guard) => guard,
        Err(error) => {
            eprintln!("process signal setup failed: {error}");
            return 1;
        }
    };
    let mut exit_error = false;
    let mut last_operation_failed = false;

    // Plain front-end (REPL / non-TTY): the shared plain grammar owns
    // stdout lines (§11.4). The TUI never enables this — its worker threads
    // must not print to the alt screen.
    tool_runtime::enable_plain_output();
    if orbit_cli::mods::validation_status(&home).is_err() {
        eprintln!(
            "Instruction bundles or enabled metadata are malformed or unsafe. Run orbit doctor; invalid entries remain disabled and stored files are unchanged."
        );
    }

    if let Some(s) = &resumed_file {
        eprintln!("resumed session {} ({} prior turns)", s.session_id, s.turns);
    }
    let mut session = live_lease.session_id().to_string();
    // Conversation transcript: role + content per turn (multi-turn wire payload).
    let mut transcript = initial.to_transcript();
    let mut total_input = initial.input_tokens;
    let mut total_output = initial.output_tokens;
    let mut total_cost = initial.cost_microcents;
    let mut turns = initial.turns;

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

    loop {
        if signal_guard.sync_signal() != 0 {
            exit_error |= last_operation_failed;
            break;
        }
        last_operation_failed = false;
        let line = match orbit_cli::plain_input::read_stdin_line(signal_guard.token()) {
            Ok(orbit_cli::plain_input::PlainInput::Line(line)) => line,
            Ok(
                orbit_cli::plain_input::PlainInput::Eof
                | orbit_cli::plain_input::PlainInput::Cancelled,
            ) => break,
            Err(error) => {
                eprintln!("input failed: {error}");
                exit_error = true;
                break;
            }
        };
        if signal_guard.sync_signal() != 0 {
            exit_error |= last_operation_failed;
            break;
        }
        let trimmed = line.trim().to_string();
        if trimmed.is_empty() {
            continue;
        }

        // Slash commands / control.
        if trimmed == "exit" || trimmed == "quit" {
            last_operation_failed = false;
            break;
        }
        last_operation_failed = true;
        if trimmed.starts_with('/') {
            if trimmed.split_whitespace().next() == Some("/compact") {
                if trimmed != "/compact" {
                    eprintln!("usage: /compact");
                    continue;
                }
                let mut working = sessions::SessionFile::from_chat(
                    &session,
                    &model,
                    &gate,
                    &active_provider,
                    &transcript,
                    turns,
                    total_input,
                    total_output,
                    total_cost,
                )
                .with_effort(selected_effort.clone())
                .with_selection_origin(selection_origin);
                let scope = tool_runtime::PermissionScope::from_flags(
                    value_after(args, "--permission-mode").as_deref(),
                    value_after(args, "--allowedTools").as_deref(),
                    value_after(args, "--disallowedTools").as_deref(),
                );
                signal_guard.sync_signal();
                let mut events = compact_local_progress;
                let (result, persisted) = compact_local_session(
                    (&live_lease, &accounting),
                    &mut working,
                    &scope,
                    signal_guard.token(),
                    &mut events,
                );
                let checked = checked_local_accounting(&accounting, &working, &persisted);
                last_operation_failed = compact_local_failed(&result, &persisted, checked);
                let (output, _) = compact_local_output(&working, &result, &persisted, checked);
                transcript = working.to_transcript();
                total_input = working.input_tokens;
                total_output = working.output_tokens;
                total_cost = working.cost_microcents;
                full_cost_status = checked.map(|view| view.full_cost_status);
                print_compact_output(&output, false);
                if persisted.is_err() || checked.is_none() {
                    eprintln!("session accounting publication or inspection failed");
                    exit_error = true;
                    break;
                }
                continue;
            }
            // `/resume <id>` needs the mutable session id, so it is handled
            // here (in the loop) rather than in handle_chat_command.
            if let Some(id) = trimmed.strip_prefix("/resume ") {
                let id = id.trim();
                let same_session =
                    id.strip_suffix(".json").unwrap_or(id) == live_lease.session_id();
                let target = if same_session {
                    live_lease.load().map(|saved| (None, saved))
                } else {
                    sessions::SessionLease::acquire_and_load(&home, id, "chat")
                        .map(|(lease, saved)| (Some(lease), saved))
                };
                match target {
                    Ok((candidate_lease, mut s)) => {
                        let resolved = match chat_effort_config(
                            &home,
                            &s.model,
                            &s.gate,
                            Some(&s.provider),
                            s.effort.as_ref(),
                        ) {
                            Ok(c) => c,
                            Err(e) => {
                                eprintln!("cannot resume {id}: {e}");
                                continue;
                            }
                        };
                        let candidate_accounting = match session_accounting::prepare_root(
                            candidate_lease.as_ref().unwrap_or(&live_lease),
                            &mut s,
                            RootOrigin::RestoredOrLegacy,
                        ) {
                            Ok(accounting) => accounting,
                            Err(error) => {
                                if same_session {
                                    full_cost_status = None;
                                }
                                eprintln!("cannot resume {id}: {error}");
                                continue;
                            }
                        };
                        if let Some(candidate_lease) = candidate_lease {
                            live_lease = candidate_lease;
                        }
                        accounting = candidate_accounting;
                        full_cost_status = s
                            .accounting_watermark
                            .as_ref()
                            .map(|anchor| anchor.full_cost_status);
                        selection_origin = sessions::model_origin(Some(&s));
                        model = s.model.clone();
                        selected_effort = s.effort.clone();
                        active_provider = resolved.provider_id;
                        gate = resolved.gate;
                        session = s.session_id.clone();
                        transcript = s.to_transcript();
                        turns = s.turns;
                        total_input = s.input_tokens;
                        total_output = s.output_tokens;
                        total_cost = s.cost_microcents;
                        eprintln!("resumed {id} ({} prior turns)", s.turns);
                        last_operation_failed = false;
                    }
                    Err(e) => {
                        if same_session {
                            full_cost_status = None;
                        }
                        eprintln!("cannot resume {id}: {e}");
                    }
                }
                continue;
            }
            if trimmed.split_whitespace().next() == Some("/permissions") {
                let scope = tool_runtime::PermissionScope::from_flags(
                    value_after(args, "--permission-mode").as_deref(),
                    value_after(args, "--allowedTools").as_deref(),
                    value_after(args, "--disallowedTools").as_deref(),
                );
                let working_dir = std::env::current_dir().unwrap_or_default();
                match tool_runtime::permission_command(
                    &home,
                    &scope,
                    &working_dir,
                    trimmed.strip_prefix("/permissions").unwrap_or_default(),
                ) {
                    Ok(text) => {
                        last_operation_failed = false;
                        println!("{text}");
                    }
                    Err(error) => eprintln!("permissions: {error}"),
                }
                continue;
            }
            if trimmed == "/customize"
                || trimmed.starts_with("/customize ")
                || trimmed == "/theme"
                || trimmed.starts_with("/theme ")
            {
                let (kind, rest) = trimmed.split_once(' ').unwrap_or((&trimmed, ""));
                let mut words = Vec::new();
                if kind == "/theme" {
                    words.push("theme".into());
                    if !rest.is_empty() {
                        words.push(rest.trim().into());
                    }
                } else {
                    let mut parts = rest.trim().splitn(2, char::is_whitespace);
                    if let Some(operation) = parts.next().filter(|value| !value.is_empty()) {
                        words.push(operation.into());
                    }
                    if let Some(tail) = parts
                        .next()
                        .map(str::trim)
                        .filter(|value| !value.is_empty())
                    {
                        if words.first().is_some_and(|word| word == "set") {
                            let (key, value) =
                                tail.split_once(char::is_whitespace).unwrap_or((tail, ""));
                            words.push(key.into());
                            words.push(value.trim().into());
                        } else {
                            words.push(tail.into());
                        }
                    }
                }
                let host = orbit_cli::customization_host::host(
                    &home,
                    &std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
                    tool_runtime::PermissionScope::from_flags(
                        value_after(args, "--permission-mode").as_deref(),
                        value_after(args, "--allowedTools").as_deref(),
                        value_after(args, "--disallowedTools").as_deref(),
                    ),
                    args.iter().any(|arg| arg == "--safe-customization"),
                );
                match orbit_cli::customization_host::command_for(host.as_ref(), &words) {
                    Ok(value) => {
                        last_operation_failed = false;
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&value).unwrap_or_default()
                        );
                    }
                    Err(error) => eprintln!("customize: {error}"),
                }
                continue;
            }
            if let Some(command) = trimmed.strip_prefix("/route") {
                if !command.is_empty() && !command.starts_with(char::is_whitespace) {
                    eprintln!("unknown command: {trimmed}");
                    continue;
                }
                let words: Vec<String> = command.split_whitespace().map(str::to_owned).collect();
                if words.first().map(String::as_str) == Some("auto") && words.len() == 1 {
                    let validation = config::ProvidersConfig::load(&home).and_then(|providers| {
                        orbit_cli::phase_routing::validate_settings(
                            &providers,
                            &providers.phase_settings(),
                        )
                    });
                    if let Err(error) = validation {
                        eprintln!("routing unchanged: {error}");
                        continue;
                    }
                    let mut saved = sessions::SessionFile::from_chat(
                        &session,
                        &model,
                        &gate,
                        &active_provider,
                        &transcript,
                        turns,
                        total_input,
                        total_output,
                        total_cost,
                    )
                    .with_effort(selected_effort.clone())
                    .with_selection_origin(orbit_cli::phase_routing::SelectionOrigin::Default);
                    match accounting.persist(&live_lease, &mut saved) {
                        Ok(view) => {
                            total_input = view.input_tokens;
                            total_output = view.output_tokens;
                            total_cost = view.known_cost_microcents;
                            full_cost_status = Some(view.full_cost_status);
                            selection_origin = orbit_cli::phase_routing::SelectionOrigin::Default;
                            println!("Automatic routing enabled for this session");
                            last_operation_failed = false;
                        }
                        Err(error) => {
                            total_input = saved.input_tokens;
                            total_output = saved.output_tokens;
                            total_cost = saved.cost_microcents;
                            let persisted = Err(error);
                            full_cost_status =
                                checked_local_accounting(&accounting, &saved, &persisted)
                                    .map(|view| view.full_cost_status);
                            if let Err(error) = persisted {
                                eprintln!("routing unchanged: {error}");
                            }
                            exit_error = true;
                            break;
                        }
                    }
                } else {
                    match chat_effort_config(
                        &home,
                        &model,
                        &gate,
                        Some(&active_provider),
                        selected_effort.as_ref(),
                    )
                    .and_then(|base| {
                        orbit_cli::route_command(&home, &words, Some(&base), selection_origin)
                    }) {
                        Ok(value) => {
                            last_operation_failed = false;
                            println!(
                                "{}",
                                serde_json::to_string_pretty(&value).unwrap_or_default()
                            );
                        }
                        Err(error) => eprintln!("route: {error}"),
                    }
                }
                continue;
            }
            let prior_selection = (
                model.clone(),
                selected_effort.clone(),
                selection_origin,
                active_provider.clone(),
                gate.clone(),
            );
            let handled = handle_chat_command(
                &trimmed,
                &home,
                &mut model,
                &mut selected_effort,
                &gate,
                &mut active_provider,
                &mut transcript,
                (&turns, &total_input, &total_output, &total_cost),
            );
            last_operation_failed = !handled;
            if handled && trimmed.starts_with("/model ") {
                let requested = trimmed["/model ".len()..].trim();
                if orbit_cli::checked_model_turn(
                    &home,
                    requested,
                    None,
                    if cfg.provider.is_empty() {
                        Some(&gate)
                    } else {
                        None
                    },
                    false,
                )
                .is_ok_and(|turn| turn.model == model && turn.provider_id == active_provider)
                {
                    selection_origin = orbit_cli::phase_routing::SelectionOrigin::Interactive;
                }
            }
            if !handled {
                eprintln!("unknown command: {trimmed}; try /help");
            } else if prior_selection
                != (
                    model.clone(),
                    selected_effort.clone(),
                    selection_origin,
                    active_provider.clone(),
                    gate.clone(),
                )
            {
                let resolved = match chat_effort_config(
                    &home,
                    &model,
                    &gate,
                    Some(&active_provider),
                    selected_effort.as_ref(),
                ) {
                    Ok(resolved) => resolved,
                    Err(error) => {
                        (
                            model,
                            selected_effort,
                            selection_origin,
                            active_provider,
                            gate,
                        ) = prior_selection;
                        eprintln!("settings unchanged: {error}");
                        last_operation_failed = true;
                        continue;
                    }
                };
                let mut sf = sessions::SessionFile::from_chat(
                    &session,
                    &model,
                    &resolved.gate,
                    &resolved.provider_id,
                    &transcript,
                    turns,
                    total_input,
                    total_output,
                    total_cost,
                )
                .with_effort(selected_effort.clone())
                .with_selection_origin(selection_origin);
                match accounting.persist(&live_lease, &mut sf) {
                    Ok(view) => {
                        gate = resolved.gate;
                        active_provider = resolved.provider_id;
                        total_input = view.input_tokens;
                        total_output = view.output_tokens;
                        total_cost = view.known_cost_microcents;
                        full_cost_status = Some(view.full_cost_status);
                    }
                    Err(error) => {
                        total_input = sf.input_tokens;
                        total_output = sf.output_tokens;
                        total_cost = sf.cost_microcents;
                        let persisted = Err(error);
                        full_cost_status = checked_local_accounting(&accounting, &sf, &persisted)
                            .map(|view| view.full_cost_status);
                        if let Err(error) = persisted {
                            eprintln!("settings unchanged: {error}");
                        }
                        exit_error = true;
                        break;
                    }
                }
            }
            if trimmed == "/usage" && full_cost_status != Some(FullCostStatus::Known) {
                match full_cost_status {
                    Some(status) => eprintln!(
                        "full session cost is unknown ({status:?}); displayed cost is the known priced subtotal"
                    ),
                    None => eprintln!(
                        "full session cost is unavailable; displayed cost is the known priced subtotal"
                    ),
                }
            }
            continue;
        }

        // Plain grammar (§11.4): the turn boundary is stamped — one event
        // per line, words not glyphs. Same grammar as copy mode and non-TTY.
        full_cost_status = None;
        println!("{} you: {}", hhmm_now(), trimmed);
        let mut local_snapshot = sessions::SessionFile::from_chat(
            &session,
            &model,
            &gate,
            &active_provider,
            &transcript,
            turns,
            total_input,
            total_output,
            total_cost,
        )
        .with_effort(selected_effort.clone())
        .with_selection_origin(selection_origin);
        let Some(next_turns) = turns.checked_add(1) else {
            retain_local_session_intent(
                &live_lease,
                &accounting,
                &mut local_snapshot,
                &mut transcript,
                &trimmed,
            );
            eprintln!("session turn count overflows");
            continue;
        };

        // Resolve the provider for the current model (config overrides the
        // default gate). `credential_env` names the env var holding the token.
        let provider = cfg
            .provider
            .iter()
            .find(|p| p.name == active_provider)
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
                phase: format!("turn {next_turns}({model})"),
            },
        );

        // Phase 2: the loop is the ENGINE's — the REPL supplies only the
        // event adapter (stdout) and the tool executor (StdApprovalChannel,
        // session grants). The old 8-round copy of the loop is gone.
        let mut base_turn_config = match orbit_cli::try_engine_turn_config(
            &home,
            &provider_id,
            &resolved_gate,
            &model,
            credential_env,
            pricing,
        ) {
            Ok(c) => c,
            Err(e) => {
                retain_local_session_intent(
                    &live_lease,
                    &accounting,
                    &mut local_snapshot,
                    &mut transcript,
                    &trimmed,
                );
                eprintln!("ORBIT-E0401: {e}");
                continue;
            }
        };
        if let Err(error) =
            apply_selected_effort(&home, &mut base_turn_config, selected_effort.as_ref())
        {
            retain_local_session_intent(
                &live_lease,
                &accounting,
                &mut local_snapshot,
                &mut transcript,
                &trimmed,
            );
            eprintln!("ORBIT-E0401: {error}");
            continue;
        }
        let (turn_config, routing_decision) = match orbit_cli::try_phase_turn_config(
            &home,
            &base_turn_config,
            &trimmed,
            selection_origin,
        ) {
            Ok(value) => value,
            Err(error) => {
                retain_local_session_intent(
                    &live_lease,
                    &accounting,
                    &mut local_snapshot,
                    &mut transcript,
                    &trimmed,
                );
                eprintln!("ORBIT-E0401: {error}");
                continue;
            }
        };
        if let Some(decision) = &routing_decision {
            println!(
                "route {}/{} → {}/{}",
                decision.phase.as_str(),
                decision.difficulty.as_str(),
                decision.provider_id,
                decision.raw_model
            );
        }
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
            approval_channel: tool_runtime::StdApprovalChannel::with_cancel(
                interactive,
                signal_guard.token().clone(),
            ),
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
        tool_runtime::remember_effort_setting(
            &executor.tool_cx,
            if turn_config.provider_id == base_turn_config.provider_id
                && turn_config.model == base_turn_config.model
            {
                &selected_effort
            } else {
                &None
            },
        );
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
                    eprintln!("{}", orbit_hud_tui::safe_text(&text));
                }
                E::Usage {
                    used_tokens,
                    window_tokens,
                    breakdown,
                } => {
                    eprintln!(
                        "{}",
                        context_meter_text(used_tokens, window_tokens, breakdown)
                    );
                }
                _ => {}
            }
        };
        let session_prompt = build_session_prompt(&home, &model);
        let mut options = orbit_engine::TurnOptions {
            tools: tools::session_tool_definitions(&home),
            memory_bytes: session_prompt.memory_bytes,
            system_directive: Some(session_prompt.text),
            request_stem: "orbit-repl".into(),
            session_id: session.clone(),
            compaction_config: Some(
                match orbit_cli::try_role_turn_config(&home, &turn_config, "compaction") {
                    Ok(c) => c,
                    Err(e) => {
                        retain_local_session_intent(
                            &live_lease,
                            &accounting,
                            &mut local_snapshot,
                            &mut transcript,
                            &trimmed,
                        );
                        eprintln!("ORBIT-E0401: {e}");
                        continue;
                    }
                },
            ),
            ..Default::default()
        };
        signal_guard.sync_signal();
        let completion =
            match orbit_cli::model_limits::apply_turn_budgets(&home, &turn_config, &mut options)
                .map_err(|error| error.to_string())
                .and_then(|notices| {
                    for text in notices {
                        events(orbit_frontend_protocol::FrontendEvent::Status { text });
                    }
                    let retry_policy =
                        orbit_cli::provider_policies::load_for_config(&home, &turn_config)
                            .map_err(|error| error.to_string())?;
                    accounting
                        .namespace()
                        .apply_options_detailed(&mut options, None, retry_policy.as_ref())
                        .map_err(|error| error.to_string())?;
                    Ok(retry_policy)
                }) {
                Ok(retry_policy) => Ok(orbit_engine::turn::run_turn_detailed_with_retry_policy(
                    &home,
                    &turn_config,
                    &options,
                    &trimmed,
                    &mut transcript,
                    &mut executor,
                    signal_guard.token(),
                    &mut events,
                    retry_policy.as_ref(),
                )
                .into_completion()),
                Err(error) => {
                    local_budget_refusal(&trimmed, &options, &mut transcript, error, &mut events)
                }
            };
        last_operation_failed = match &completion {
            Err(_) => true,
            Ok(completion) => {
                matches!(completion.end, orbit_engine::TurnEnd::Failed(_))
                    || (completion.end == orbit_engine::TurnEnd::Completed && !completion.report.ok)
            }
        };
        exit_error |= executor.approval_channel.input_failed();
        if let Ok(completion) = &completion {
            println!();
            if completion.end == orbit_engine::TurnEnd::Completed && completion.report.ok {
                turns = next_turns;
            }
            match &completion.end {
                orbit_engine::TurnEnd::Cancelled => eprintln!("turn cancelled"),
                orbit_engine::TurnEnd::Failed(error) => eprintln!("{error}"),
                orbit_engine::TurnEnd::Completed => {}
            }
            if let Some(scan) = orbit_engine::automation::scan_attestation(&transcript)
                && scan.claimed_pass
                && scan.exit_code != 0
            {
                eprintln!(
                    "UNVERIFIED CLAIM: \"{}\" exited {} at turn time — the claim is not attested",
                    scan.command, scan.exit_code
                );
            }
        }
        let mut sf = sessions::SessionFile::from_chat(
            &session,
            &model,
            &resolved_gate,
            &provider_id,
            &transcript,
            turns,
            total_input,
            total_output,
            total_cost,
        )
        .with_effort(selected_effort.clone())
        .with_selection_origin(selection_origin);
        let persisted = accounting.persist(&live_lease, &mut sf);
        let checked = checked_local_accounting(&accounting, &sf, &persisted);
        let persist_failed = persisted.is_err();
        match persisted {
            Ok(view) => {
                total_input = view.input_tokens;
                total_output = view.output_tokens;
                total_cost = view.known_cost_microcents;
                full_cost_status = checked.map(|view| view.full_cost_status);
            }
            Err(error) => {
                // Reconcile may have projected newer durable charges before a snapshot save failed.
                total_input = sf.input_tokens;
                total_output = sf.output_tokens;
                total_cost = sf.cost_microcents;
                full_cost_status = checked.map(|view| view.full_cost_status);
                eprintln!("session not saved: {error}");
            }
        }
        if persist_failed || checked.is_none() {
            if !persist_failed {
                eprintln!("session accounting inspection failed");
            }
            exit_error = true;
        }
        if exit_error || signal_guard.sync_signal() != 0 {
            exit_error |= last_operation_failed;
            break;
        }
    }

    let signal = signal_guard.sync_signal();
    exit_error |= signal != 0 && last_operation_failed;
    // Exit summary (JSON envelope, consistent with other commands).
    println!(
        "{}",
        serde_json::json!({
            "schema": "orbit.cli/v1",
            "command": "chat",
            "status": if exit_error { "error" } else if signal != 0 { "cancelled" } else { "exit" },
            "session": session,
            "turns": turns,
            "usage": {
                "input_tokens": total_input,
                "output_tokens": total_output,
            },
            "cost_microcents": total_cost,
            "full_cost_status": full_cost_status,
        })
    );
    close_plain_signals(&mut signal_guard, 0, |signal| {
        exit_error || (signal != 0 && last_operation_failed)
    })
}

/// The REPL's tool executor: bridges the engine's `ToolExecutor` trait
/// to the REPL's cancellable StdApprovalChannel and session grants.
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
        // A run of parallel-safe read-only calls runs concurrently; the
        // REPL's sequential closure (with its SESSION_SNAPSHOT refresh)
        // stays the executor for everything else. The runner owns its
        // state: the parallel set never prompts in default modes, so a
        // non-interactive StdApprovalChannel (never asks, dontAsk
        // semantics) is honest for it.
        let home = self.home.clone();
        let session_id = self.session_id.clone();
        let auto_tools = self.auto_tools;
        let scope = self.scope.clone();
        let tool_cx = self.tool_cx.clone();
        let run_ro = move |call: orbit_engine::PendingToolCall| {
            let decision_id = format!("tool-{}-{}", ulid::Ulid::new(), call.index);
            let (result, _) = tool_runtime::execute_call(
                &home,
                &session_id,
                &decision_id,
                &call,
                auto_tools,
                false,
                &mut tool_runtime::StdApprovalChannel::new(false),
                &mut tool_runtime::AutoGrants::new(),
                &scope,
                &tool_cx,
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
        };
        tool_runtime::run_round_parallel(
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
            run_ro,
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

/// Signed packages use durable storage; instruction mods retain their own loader.
fn package_install_arguments(args: &[String]) -> Result<bool, (&'static str, String)> {
    let mut seen = std::collections::HashSet::new();
    let mut confirmed = false;
    let mut index = 0;
    while index < args.len() {
        let flag = args[index].as_str();
        if matches!(flag, "--package" | "--manifest" | "--home") {
            if !seen.insert(flag) {
                return Err(("ORBIT-E1101", format!("duplicate {flag}")));
            }
            let value = args
                .get(index + 1)
                .filter(|value| !value.is_empty() && !value.starts_with('-'));
            if value.is_none() {
                return Err((
                    "ORBIT-E1101",
                    format!("{flag} requires a path; use ./ for a filename beginning with '-'"),
                ));
            }
            index += 1;
        } else if flag == "--yes" {
            if confirmed {
                return Err(("ORBIT-E1101", "duplicate --yes".into()));
            }
            confirmed = true;
        } else if flag.starts_with('-') {
            return Err((
                "ORBIT-E1101",
                format!("unknown package install flag {flag}"),
            ));
        }
        index += 1;
    }
    let pos = positionals(args);
    if pos.len() > 3 || (pos.get(2).is_some() && seen.contains("--package")) {
        return Err(("ORBIT-E1101", "choose one package path".into()));
    }
    Ok(confirmed)
}

fn cmd_mod(home: &Path, args: &[String]) -> Result<serde_json::Value, (&'static str, String)> {
    let pos = positionals(args);
    let sub = pos.get(1).copied().unwrap_or("");
    match sub {
        "allow-issuer" => {
            let key = pos.get(2).ok_or((
                "ORBIT-E1101",
                "usage: orbit mod allow-issuer <hex-ed25519-key>".into(),
            ))?;
            orbit_cli::signed_packages::trust_issuer(home, key)
                .map_err(|error| (error.code(), error.to_string()))?;
            Ok(
                serde_json::json!({"schema":"orbit.cli/v1","command":"mod allow-issuer","status":"ok","issuer":key.to_ascii_lowercase()}),
            )
        }
        "issuers" => {
            let issuers = orbit_cli::signed_packages::trusted_issuers(home)
                .map_err(|error| (error.code(), error.to_string()))?;
            Ok(
                serde_json::json!({"schema":"orbit.cli/v1","command":"mod issuers","status":"ok","trusted_issuers":issuers.len(),"issuers":issuers}),
            )
        }
        "list" | "search" | "status" => {
            let query = if sub == "search" {
                let term = pos.get(2..).unwrap_or_default().join(" ");
                if term.is_empty() {
                    return Err(("ORBIT-E1101", "usage: orbit mod search <text>".into()));
                }
                Some(term)
            } else if sub == "status" {
                Some(
                    pos.get(2)
                        .ok_or(("ORBIT-E1101", "usage: orbit mod status <name>".into()))?
                        .to_string(),
                )
            } else {
                None
            };
            let catalog = if sub == "status" {
                orbit_cli::signed_packages::status(home, query.as_deref().unwrap_or_default())
            } else {
                orbit_cli::signed_packages::catalog(home, query.as_deref())
            }
            .map_err(|error| (error.code(), error.to_string()))?;
            Ok(
                serde_json::json!({"schema":"orbit.cli/v1","command":format!("mod {sub}"),"status":"ok","catalog":catalog}),
            )
        }
        "install" => {
            let confirmed = package_install_arguments(args)?;
            let package = value_after(args, "--package")
                .or_else(|| pos.get(2).map(|path| path.to_string()))
                .ok_or((
                    "ORBIT-E1101",
                    "usage: orbit mod install <package.wasm> --manifest <manifest.json> --yes"
                        .into(),
                ))?;
            let manifest = value_after(args, "--manifest").ok_or((
                "ORBIT-E1101",
                "install needs --manifest <manifest.json>".into(),
            ))?;
            let (manifest, bytes) = orbit_cli::signed_packages::read_install_inputs(
                Path::new(&manifest),
                Path::new(&package),
            )
            .map_err(|error| (error.code(), error.to_string()))?;
            if !confirmed {
                return Err(("ORBIT-E1101", "installation requires explicit confirmation; add --yes after reviewing the signed manifest".into()));
            }
            let receipt = orbit_cli::signed_packages::install(home, &manifest, &bytes, confirmed)
                .map_err(|error| (error.code(), error.to_string()))?;
            Ok(
                serde_json::json!({"schema":"orbit.cli/v1","command":"mod install","status":"ok","installation":receipt}),
            )
        }
        _ => Err((
            "ORBIT-E1101",
            "usage: orbit mod install|list|search|status|issuers|allow-issuer".into(),
        )),
    }
}

/// `orbit folder trust|untrust|status [DIR]`: whether a folder's own
/// settings (`.orbit/settings.toml`, `.orbit/settings.local.toml`,
/// hooks, skills, MCP servers) may loosen what ORBIT does. A folder is
/// untrusted until a person says otherwise; its deny and ask rules apply
/// either way, since they only make ORBIT stricter.
fn cmd_folder(home: &Path, args: &[String]) -> Result<serde_json::Value, (&'static str, String)> {
    // The words that are not flags (or the value of one): `folder`, the
    // sub-command, the directory. Flags may come first (`--home X folder
    // status`) or last.
    let mut words: Vec<&str> = Vec::new();
    let mut i = 0usize;
    while i < args.len() {
        let a = args[i].as_str();
        if matches!(
            a,
            "--home" | "--model" | "--effort" | "--gate" | "--resume" | "--provider"
        ) {
            i += 2;
            continue;
        }
        if !a.starts_with('-') {
            words.push(a);
        }
        i += 1;
    }
    let sub = words.get(1).copied().unwrap_or("");
    let dir = match words.get(2) {
        Some(d) => PathBuf::from(d),
        None => std::env::current_dir().map_err(ioe)?,
    };
    // The marker is keyed by the absolute path the process will report as
    // its working directory, so resolve links the way getcwd does.
    let dir = std::fs::canonicalize(&dir)
        .map_err(|e| ("ORBIT-E0501", format!("{}: {e}", dir.display())))?;
    let trust = orbit_tools::permissions::FolderTrust::new(home.to_path_buf());
    let trusted = match sub {
        "trust" => {
            trust.trust(&dir).map_err(ioe)?;
            true
        }
        "untrust" => {
            trust.untrust(&dir).map_err(ioe)?;
            false
        }
        "status" => trust.is_trusted(&dir),
        _ => {
            return Err((
                "ORBIT-E1101",
                "usage: orbit folder trust|untrust|status [DIR]".into(),
            ));
        }
    };
    Ok(serde_json::json!({
        "schema": "orbit.cli/v1",
        "command": format!("folder {sub}"),
        "status": "ok",
        "folder": dir.display().to_string(),
        "trusted": trusted,
    }))
}

/// `orbit provider add|list|remove|presets` — provider management.
/// `add` walks a preset (or custom) through discovery into providers.toml;
/// it stores env-var NAMES and public model facts, never credential values.
/// `orbit route` — inspect and set difficulty routing. Setup is one
/// command per tier: `orbit route hard <model>` and `orbit route easy
/// <model>`; `off` disarms a tier. `test "<prompt>"` classifies
/// without sending anything, so the table can be tuned before it
/// spends money.
fn cmd_route(home: &Path, args: &[String]) -> Result<serde_json::Value, (&'static str, String)> {
    let pos = positionals(args);
    let sub = pos.get(1).copied().unwrap_or("status");
    let mut seen = std::collections::BTreeSet::new();
    let mut index = 0;
    while index < args.len() {
        let word = args[index].as_str();
        if word.starts_with("--") {
            if !seen.insert(word) {
                return Err(("ORBIT-E1101", format!("duplicate route option {word}")));
            }
            if [
                "--home",
                "--model",
                "--provider",
                "--gate",
                "--easy",
                "--hard",
                "--session",
                "--resume",
            ]
            .contains(&word)
            {
                if args
                    .get(index + 1)
                    .is_none_or(|value| value.is_empty() || value.starts_with("--"))
                {
                    return Err(("ORBIT-E1101", format!("{word} requires a value")));
                }
                index += 2;
                continue;
            }
            if word != "--json" {
                return Err(("ORBIT-E1101", format!("unknown route option {word}")));
            }
        }
        index += 1;
    }
    if (seen.contains("--easy") || seen.contains("--hard")) && sub != "setup" {
        return Err((
            "ORBIT-E1101",
            "--easy/--hard are only valid with route setup".into(),
        ));
    }
    if (seen.contains("--session") || seen.contains("--resume")) && sub != "auto" {
        return Err((
            "ORBIT-E1101",
            "--session/--resume are only valid with route auto".into(),
        ));
    }
    if sub != "test"
        && ["--model", "--provider", "--gate"]
            .iter()
            .any(|flag| seen.contains(flag))
    {
        return Err((
            "ORBIT-E1101",
            "selection flags are only valid with route test".into(),
        ));
    }
    if sub == "auto" {
        if pos.len() != 2 || (seen.contains("--session") && seen.contains("--resume")) {
            return Err(("ORBIT-E1101", "usage: route auto --session ID".into()));
        }
        let providers =
            config::ProvidersConfig::load(home).map_err(|error| ("ORBIT-E1106", error))?;
        orbit_cli::phase_routing::validate_settings(&providers, &providers.phase_settings())
            .map_err(|error| ("ORBIT-E1106", error))?;
        let id = value_after(args, "--session")
            .or_else(|| value_after(args, "--resume"))
            .ok_or((
                "ORBIT-E1101",
                "route auto requires --session ID; live chats use /route auto".into(),
            ))?;
        let (lease, mut saved) =
            sessions::SessionLease::acquire_and_load(home, &id, "route-settings")
                .map_err(|error| ("ORBIT-E0400", error.to_string()))?;
        saved.selection_origin = Some(orbit_cli::phase_routing::SelectionOrigin::Default);
        lease
            .save(&saved)
            .map_err(|error| ("ORBIT-E0400", error.to_string()))?;
        return Ok(
            serde_json::json!({"schema":"orbit.cli/v1","command":"route auto","status":"ok","session_id":saved.session_id,"selection_origin":"default"}),
        );
    }
    let words = if sub == "setup" {
        if pos.len() != 2 {
            return Err((
                "ORBIT-E1101",
                "usage: route setup --easy MODEL --hard MODEL".into(),
            ));
        }
        vec![
            "setup".into(),
            "--easy".into(),
            value_after(args, "--easy")
                .ok_or(("ORBIT-E1101", "route setup requires --easy".into()))?,
            "--hard".into(),
            value_after(args, "--hard")
                .ok_or(("ORBIT-E1101", "route setup requires --hard".into()))?,
        ]
    } else {
        pos.iter().skip(1).map(|word| word.to_string()).collect()
    };
    let cfg = config::ProvidersConfig::load(home).map_err(|error| ("ORBIT-E1106", error))?;
    let manual = (sub == "test")
        .then(|| value_after(args, "--model").or_else(|| std::env::var("ORBIT_MODEL").ok()))
        .flatten();
    if sub == "test" && manual.is_none() && (seen.contains("--provider") || seen.contains("--gate"))
    {
        return Err((
            "ORBIT-E1101",
            "--provider/--gate preview constraints require --model or ORBIT_MODEL".into(),
        ));
    }
    let gate = value_after(args, "--gate").or_else(|| std::env::var("ORBIT_GATE_URL").ok());
    let base = manual
        .as_ref()
        .map(|model| {
            orbit_cli::checked_model_turn(
                home,
                model,
                value_after(args, "--provider").as_deref(),
                gate.as_deref(),
                false,
            )
        })
        .transpose()
        .map_err(|error| ("ORBIT-E0401", error))?;
    let origin = if sub == "test" {
        orbit_cli::startup_selection_origin(
            value_after(args, "--model").is_some(),
            std::env::var("ORBIT_MODEL").is_ok(),
            None,
            !cfg.roles.main.is_empty(),
        )
    } else {
        orbit_cli::phase_routing::SelectionOrigin::Default
    };
    let mut result = orbit_cli::route_command(home, &words, base.as_ref(), origin)
        .map_err(|error| ("ORBIT-E1101", error))?;
    result["schema"] = serde_json::json!("orbit.cli/v1");
    Ok(result)
}

fn provider_refresh_arguments(
    args: &[String],
) -> Result<
    (
        String,
        Option<orbit_cli::provider_discovery::DiscoveryProfile>,
    ),
    (&'static str, String),
> {
    use orbit_cli::provider_discovery::DiscoveryProfile;
    let tail = command_tail(args)?;
    let invalid = || {
        (
            "ORBIT-E1101",
            "usage: provider refresh NAME [--schema generic|openrouter|anthropic|ollama] [--json]"
                .to_owned(),
        )
    };
    if tail.first().map(String::as_str) != Some("refresh")
        || tail.len() > 6
        || tail.iter().map(String::len).sum::<usize>() > 4096
        || tail.iter().any(|arg| arg.contains('\0'))
    {
        return Err(invalid());
    }
    let (mut name, mut schema, mut json) = (None, None, false);
    let mut index = 1;
    while index < tail.len() {
        match tail[index].as_str() {
            "--json" if !json => json = true,
            "--schema" if schema.is_none() => {
                index += 1;
                schema = Some(match tail.get(index).map(String::as_str) {
                    Some("generic") => DiscoveryProfile::GenericOpenAi,
                    Some("openrouter") => DiscoveryProfile::OpenRouter,
                    Some("anthropic") => DiscoveryProfile::Anthropic,
                    Some("ollama") => DiscoveryProfile::Ollama,
                    _ => return Err(invalid()),
                });
            }
            value
                if name.is_none()
                    && !value.starts_with('-')
                    && !value.is_empty()
                    && value.len() <= 128
                    && value.trim() == value
                    && !value.contains('/')
                    && !value.chars().any(char::is_control) =>
            {
                name = Some(value.to_owned())
            }
            _ => return Err(invalid()),
        }
        index += 1;
    }
    Ok((name.ok_or_else(invalid)?, schema))
}

enum ProviderCredentialCommand {
    Login {
        name: String,
        request: orbit_cli::onboarding::ProviderLoginRequest,
    },
    Logout {
        name: String,
        yes: bool,
    },
}
fn provider_credential_subcommand(tail: &[String]) -> Option<&str> {
    let index = usize::from(tail.first().map(String::as_str) == Some("--json"));
    tail.get(index)
        .map(String::as_str)
        .filter(|word| matches!(*word, "login" | "logout"))
}
fn provider_credential_arguments(
    args: &[String],
) -> Result<ProviderCredentialCommand, (&'static str, String)> {
    use orbit_cli::onboarding::provider_login::LoginMode;
    use orbit_cli::onboarding::{ProviderLoginMethod, ProviderLoginRequest};
    let tail = command_tail(args)?;
    let invalid = || {
        ("ORBIT-E1101", "usage: provider login NAME [--method browser|key|env] [--headless] [--no-browser]; provider logout NAME [--yes] [--json]".to_owned())
    };
    if tail.len() > 9
        || tail.iter().map(String::len).sum::<usize>() > 4096
        || tail.iter().any(|word| word.contains('\0'))
    {
        return Err(invalid());
    }
    let sub = provider_credential_subcommand(&tail).ok_or_else(invalid)?;
    let mut flags = std::collections::BTreeSet::new();
    let (mut name, mut method) = (None, None);
    let (mut headless, mut no_browser, mut yes) = (false, false, false);
    let mut index = 0;
    while index < tail.len() {
        let word = tail[index].as_str();
        if word == sub && (index == 0 || (index == 1 && tail[0] == "--json")) {
            index += 1;
            continue;
        }
        if word.starts_with('-') {
            if !flags.insert(word) {
                return Err(invalid());
            }
            match word {
                "--json" if sub == "logout" => {}
                "--yes" if sub == "logout" => yes = true,
                "--headless" if sub == "login" => headless = true,
                "--no-browser" if sub == "login" => no_browser = true,
                "--method" if sub == "login" => {
                    index += 1;
                    method = Some(match tail.get(index).map(String::as_str) {
                        Some("browser") => ProviderLoginMethod::Browser,
                        Some("key") => ProviderLoginMethod::Key,
                        Some("env") => ProviderLoginMethod::Env,
                        _ => return Err(invalid()),
                    });
                }
                _ => return Err(invalid()),
            }
        } else if name.is_none()
            && !word.is_empty()
            && word.len() <= 128
            && word.trim() == word
            && !word.contains('/')
            && !word.chars().any(char::is_control)
        {
            name = Some(word.to_owned());
        } else {
            return Err(invalid());
        }
        index += 1;
    }
    let name = name.ok_or_else(invalid)?;
    if sub == "logout" {
        if flags.contains("--json") && !yes {
            return Err(invalid());
        }
        Ok(ProviderCredentialCommand::Logout { name, yes })
    } else {
        if (headless || no_browser)
            && method.is_some_and(|method| method != ProviderLoginMethod::Browser)
        {
            return Err(invalid());
        }
        if headless || no_browser {
            method = Some(ProviderLoginMethod::Browser);
        }
        Ok(ProviderCredentialCommand::Login {
            name,
            request: ProviderLoginRequest {
                method,
                mode: if headless {
                    LoginMode::Headless
                } else {
                    LoginMode::Loopback
                },
                open_browser: !headless && !no_browser,
            },
        })
    }
}
fn cmd_provider_credentials(
    home: &Path,
    args: &[String],
) -> Result<serde_json::Value, (&'static str, String)> {
    use orbit_cli::onboarding::{
        StdSetupTerminal, collect_provider_login, commit_onboarding, commit_provider_logout,
        confirm_provider_logout, plan_provider_logout,
    };
    let (mut result, command, offline) = match provider_credential_arguments(args)? {
        ProviderCredentialCommand::Login { name, request } => {
            let mut terminal =
                StdSetupTerminal::new().map_err(|error| (error.code(), error.to_string()))?;
            let draft = collect_provider_login(home, &name, &request, &mut terminal)
                .map_err(|error| (error.code(), error.to_string()))?;
            let receipt =
                commit_onboarding(draft).map_err(|error| (error.code(), error.to_string()))?;
            let offline = !receipt.authentication_online;
            let result = serde_json::to_value(receipt).map_err(|_| {
                (
                    "ORBIT-E1101",
                    "login result could not be encoded".to_owned(),
                )
            })?;
            (result, "provider login", offline)
        }
        ProviderCredentialCommand::Logout { name, yes } => {
            let mut terminal = if yes {
                None
            } else {
                Some(StdSetupTerminal::new().map_err(|error| (error.code(), error.to_string()))?)
            };
            let plan = plan_provider_logout(home, &name)
                .map_err(|error| (error.code(), error.to_string()))?;
            let receipt = if let Some(terminal) = &mut terminal {
                confirm_provider_logout(plan, terminal)
            } else {
                commit_provider_logout(plan)
            }
            .map_err(|error| (error.code(), error.to_string()))?;
            let result = serde_json::to_value(receipt).map_err(|_| {
                (
                    "ORBIT-E1101",
                    "logout result could not be encoded".to_owned(),
                )
            })?;
            (result, "provider logout", true)
        }
    };
    result["schema"] = serde_json::json!("orbit.cli/v1");
    result["command"] = serde_json::json!(command);
    result["status"] = serde_json::json!("ok");
    result["offline"] = serde_json::json!(offline);
    Ok(result)
}

fn validate_provider_arguments(args: &[String]) -> Result<(), (&'static str, String)> {
    let tail = command_tail(args)?;
    if provider_credential_subcommand(&tail).is_some() {
        return provider_credential_arguments(args).map(|_| ());
    }
    if tail.first().map(String::as_str) == Some("refresh") {
        return provider_refresh_arguments(args).map(|_| ());
    }
    let positions = positionals(args);
    let sub = positions.get(1).copied().unwrap_or("list");
    let mut flags = std::collections::BTreeSet::new();
    let mut index = 0;
    while index < tail.len() {
        let word = tail[index].as_str();
        if word.starts_with('-') {
            if !flags.insert(word) {
                return Err(("ORBIT-E1101", "provider flag cannot be repeated".into()));
            }
            if word == "--json" {
                index += 1;
                continue;
            }
            if sub != "add"
                || !["--model", "--url", "--credential-env", "--kind", "--name"].contains(&word)
            {
                return Err(("ORBIT-E1101", "unknown provider flag".into()));
            }
            if tail
                .get(index + 1)
                .is_none_or(|v| v.is_empty() || v.starts_with('-'))
            {
                return Err(("ORBIT-E1101", "provider flag requires a value".into()));
            }
            index += 2;
        } else {
            index += 1;
        }
    }
    let count = positions.len();
    let valid = match sub {
        "list" | "presets" => count <= 2,
        "add" => (2..=3).contains(&count),
        "remove" => count == 3,
        "role" => (3..=4).contains(&count),
        _ => false,
    };
    if !valid {
        return Err(("ORBIT-E1101", "invalid provider command arguments".into()));
    }
    Ok(())
}
fn cmd_provider(home: &Path, args: &[String]) -> Result<serde_json::Value, (&'static str, String)> {
    validate_provider_arguments(args)?;
    if provider_credential_subcommand(&command_tail(args)?).is_some() {
        return cmd_provider_credentials(home, args);
    }
    let pos = positionals(args);
    let sub = pos.get(1).copied().unwrap_or("list");
    match sub {
        "refresh" => {
            let (name, schema) = provider_refresh_arguments(args)?;
            let draft = orbit_cli::onboarding::prepare_provider_refresh_auto(home, &name, schema)
                .map_err(|error| (error.code(), error.to_string()))?;
            let receipt = orbit_cli::onboarding::commit_provider_refresh(draft)
                .map_err(|error| (error.code(), error.to_string()))?;
            let mut result = serde_json::to_value(receipt)
                .map_err(|_| ("ORBIT-E1101", "refresh result could not be encoded".into()))?;
            result["schema"] = serde_json::json!("orbit.cli/v1");
            result["command"] = serde_json::json!("provider refresh");
            result["status"] = serde_json::json!("ok");
            result["offline"] = serde_json::json!(false);
            Ok(result)
        }
        "presets" => {
            let list: Vec<serde_json::Value> = orbit_cli::presets::presets()
                .into_iter()
                .map(|p| {
                    serde_json::json!({
                        "id": p.id,
                        "kind": p.kind,
                        "url": p.url,
                        "env": p.env,
                        "blurb": p.blurb,
                        "known_models": p.models.len(),
                    })
                })
                .collect();
            Ok(serde_json::json!({
                "schema": "orbit.cli/v1",
                "command": "provider presets",
                "status": "ok",
                "presets": list,
            }))
        }
        "list" => {
            let cfg = config::ProvidersConfig::load(home).map_err(|e| ("ORBIT-E1106", e))?;
            validate_configured_provider_endpoints(&cfg)?;
            Ok(serde_json::json!({
                "schema": "orbit.cli/v1",
                "command": "provider list",
                "status": "ok",
                "providers": cfg.provider,
            }))
        }
        "remove" => {
            let name = pos
                .get(2)
                .ok_or(("ORBIT-E1101", "usage: orbit provider remove <name>".into()))?;
            config::ProvidersConfig::update_atomic(home, |raw| {
                let mut document = provider_document(raw)?;
                let providers = document
                    .get_mut("provider")
                    .and_then(toml::Value::as_array_mut)
                    .ok_or("no providers are configured")?;
                let before = providers.len();
                providers.retain(|provider| {
                    provider.get("name").and_then(toml::Value::as_str) != Some(*name)
                });
                if providers.len() == before {
                    return Err("provider is not configured".into());
                }
                serialize_provider_document(&document)
            })
            .map_err(|e| ("ORBIT-E1106", e))?;
            Ok(serde_json::json!({
                "schema": "orbit.cli/v1",
                "command": "provider remove",
                "status": "ok",
                "removed": name,
            }))
        }
        "add" => cmd_provider_add(home, args),
        "role" => {
            let pos = positionals(args);
            let (role, spec) = match (pos.get(2), pos.get(3)) {
                (Some(r), Some(s)) => (r.to_string(), s.to_string()),
                (Some(r), None) => {
                    // Show the role's current value.
                    let cfg =
                        config::ProvidersConfig::load(home).map_err(|e| ("ORBIT-E1106", e))?;
                    let current = cfg.roles.get(r).unwrap_or("");
                    return Ok(serde_json::json!({
                        "schema": "orbit.cli/v1",
                        "command": "provider role",
                        "status": "ok",
                        "role": r,
                        "model": current,
                    }));
                }
                _ => {
                    return Err((
                        "ORBIT-E1101",
                        "usage: orbit provider role <main|subagent|explore|compaction> [model|provider/model]".into(),
                    ));
                }
            };
            set_provider_role(home, &role, &spec)?;
            Ok(serde_json::json!({
                "schema": "orbit.cli/v1",
                "command": "provider role",
                "status": "ok",
                "role": role,
                "model": spec,
            }))
        }
        other => Err((
            "ORBIT-E1101",
            format!("unknown provider subcommand '{other}'; add|list|remove|presets"),
        )),
    }
}

/// `orbit provider add [preset]` — the interactive (or scripted) setup
/// flow. Interactive: preset picker → credential env name → discovery →
/// model selection → confirm. Scripted: `orbit provider add <preset>
/// --model M[,M..] [--credential-env VAR] [--url URL]`.
fn cmd_provider_add(
    home: &Path,
    args: &[String],
) -> Result<serde_json::Value, (&'static str, String)> {
    let scripted_models = value_after(args, "--model");
    let preset_id = positionals(args).get(2).map(|value| value.to_string());
    if let Some(models) = scripted_models {
        let id = preset_id.as_deref().unwrap_or("custom");
        let preset = orbit_cli::presets::preset_by_id(id)
            .ok_or(("ORBIT-E1101", "unknown provider preset".into()))?;
        return run_provider_add_scripted(home, &preset, &models, args);
    }
    if args.iter().any(|arg| {
        matches!(
            arg.as_str(),
            "--json" | "--url" | "--credential-env" | "--kind" | "--name"
        )
    }) {
        return Err(("ORBIT-E1101", "scripted provider options require --model; enter provider details in the interactive wizard".into()));
    }
    if !std::io::IsTerminal::is_terminal(&std::io::stdin())
        || !std::io::IsTerminal::is_terminal(&std::io::stdout())
    {
        return Err((
            "ORBIT-E1101",
            "non-interactive add needs --model M[,M..] (and --url for custom)".into(),
        ));
    }
    run_onboarding_command(home, preset_id.as_deref(), "provider add")
}

#[cfg(test)]
fn select_provider_preset(
    selection: &str,
) -> Result<orbit_cli::presets::ProviderPreset, (&'static str, String)> {
    let preset = if let Ok(number) = selection.trim().parse::<usize>() {
        number
            .checked_sub(1)
            .and_then(|index| orbit_cli::presets::presets().get(index).cloned())
    } else {
        orbit_cli::presets::preset_by_id(selection.trim())
    };
    preset.ok_or((
        "ORBIT-E1101",
        "choose an offered provider name or number".into(),
    ))
}

#[cfg(test)]
fn ranked_provider_models(
    name: &str,
    models: &[String],
    preset: &orbit_cli::presets::ProviderPreset,
) -> Vec<String> {
    let mut models = models.to_vec();
    models.sort_by_key(|id| {
        orbit_cli::presets::preset_model(preset, id)
            .map(|fact| fact.pricing.0)
            .unwrap_or(u64::MAX)
    });
    models
        .into_iter()
        .map(|id| format!("{name}/{id}"))
        .collect()
}
#[cfg(test)]
fn fill_unset_provider_roles(
    home: &Path,
    name: &str,
    models: &[String],
    preset: &orbit_cli::presets::ProviderPreset,
) -> Result<Vec<(String, String)>, (&'static str, String)> {
    let ranked = ranked_provider_models(name, models, preset);
    let cheap = ranked
        .first()
        .ok_or(("ORBIT-E1101", "no models selected".into()))?;
    let main = ranked.last().unwrap();
    let mut applied = Vec::new();
    config::ProvidersConfig::update_atomic(home, |raw| {
        let cfg = config::ProvidersConfig::load_from_str(raw)?;
        let mut document = provider_document(raw)?;
        for role in ["main", "subagent", "explore", "compaction"] {
            if cfg.roles.get(role).is_some() {
                continue;
            }
            let spec = if role == "main" { main } else { cheap };
            orbit_cli::phase_routing::resolve_model(&cfg, spec, None)?;
            provider_table(&mut document, "roles")?
                .insert(role.into(), toml::Value::String(spec.clone()));
            applied.push((role.into(), spec.clone()));
        }
        serialize_provider_document(&document)
    })
    .map_err(|e| ("ORBIT-E1106", e))?;
    Ok(applied)
}
#[cfg(test)]
fn fill_unset_provider_routes(
    home: &Path,
    name: &str,
    models: &[String],
    preset: &orbit_cli::presets::ProviderPreset,
) -> Result<Vec<(String, String)>, (&'static str, String)> {
    let ranked = ranked_provider_models(name, models, preset);
    let cheap = ranked
        .first()
        .ok_or(("ORBIT-E1101", "no models selected".into()))?;
    let mut applied = Vec::new();
    config::ProvidersConfig::update_atomic(home, |raw| {
        let cfg = config::ProvidersConfig::load_from_str(raw)?;
        let big = if ranked.len() > 1 {
            ranked.last().unwrap().clone()
        } else {
            cfg.all_models()
                .iter()
                .map(|(p, m)| format!("{p}/{m}"))
                .find(|spec| spec != cheap)
                .ok_or("difficulty routing requires two distinct declared models")?
        };
        let mut document = provider_document(raw)?;
        for (difficulty, spec) in [("easy", cheap.clone()), ("hard", big)] {
            let existing = if difficulty == "easy" {
                &cfg.routing.easy
            } else {
                &cfg.routing.hard
            };
            if !existing.is_empty() {
                continue;
            }
            orbit_cli::phase_routing::resolve_model(&cfg, &spec, None)?;
            provider_table(&mut document, "routing")?
                .insert(difficulty.into(), toml::Value::String(spec.clone()));
            applied.push((difficulty.into(), spec));
        }
        serialize_provider_document(&document)
    })
    .map_err(|e| ("ORBIT-E1106", e))?;
    Ok(applied)
}

fn run_provider_add_scripted(
    home: &Path,
    preset: &orbit_cli::presets::ProviderPreset,
    models: &str,
    args: &[String],
) -> Result<serde_json::Value, (&'static str, String)> {
    let gate = value_after(args, "--url").unwrap_or_else(|| preset.url.to_string());
    if preset.id == "custom" && gate.is_empty() {
        return Err((
            "ORBIT-E1101",
            "a custom provider needs --url (and --credential-env, --kind when not openai)".into(),
        ));
    }
    validate_provider_url(&gate)?;
    let credential_env = value_after(args, "--credential-env");
    let kind = value_after(args, "--kind").unwrap_or_else(|| preset.kind.to_string());
    let model_ids = parse_provider_models(models)?;
    let entries: Vec<orbit_cli::config::ModelEntry> = model_ids
        .iter()
        .map(|id| orbit_cli::presets::preset_model_entry(preset, id))
        .collect();
    let name = value_after(args, "--name").unwrap_or_else(|| preset.id.to_string());
    add_configured_provider_kind(
        home,
        &name,
        &gate,
        &kind,
        credential_env,
        model_ids.clone(),
        None,
        Some(entries),
    )?;
    Ok(serde_json::json!({
        "schema": "orbit.cli/v1",
        "command": "provider add",
        "status": "ok",
        "provider": name,
        "kind": kind,
        "url": gate,
        "models": model_ids,
    }))
}

fn cmd_models(home: &Path, args: &[String]) -> Result<serde_json::Value, (&'static str, String)> {
    let cfg = config::ProvidersConfig::load(home).map_err(|e| ("ORBIT-E1106", e))?;
    validate_configured_provider_endpoints(&cfg)?;
    let entries: Vec<(String, String)> = cfg.all_models();
    let roles: std::collections::BTreeMap<String, String> = cfg
        .roles
        .entries()
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    Ok(serde_json::json!({
        "schema": "orbit.cli/v1",
        "command": "models",
        "status": "ok",
        "providers": cfg.provider,
        "models": entries,
        "count": entries.len(),
        "roles": roles,
        "json": args.iter().any(|a| a == "--json"),
    }))
}

/// Handle REPL slash commands. Returns true if recognized.
#[allow(clippy::too_many_arguments)]
fn handle_chat_command(
    cmd: &str,
    home: &Path,
    model: &mut String,
    effort: &mut Option<EffortSetting>,
    gate: &str,
    provider: &mut String,
    transcript: &mut Vec<orbit_adapter::types::ChatMessage>,
    usage: (&u64, &u64, &u64, &u64), // (turns, input, output, cost µ¢)
) -> bool {
    match cmd {
        "/help" => {
            println!(
                "commands: exit, /help, /compact, /model <M>, /effort [VALUE|default], /permissions [<tool>|allow|ask|deny|reset <tool>], /clear, /usage, /models, /sessions, /resume <ID>"
            );
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
                    let roles = cfg.roles.entries();
                    if !roles.is_empty() {
                        println!("roles:");
                        for (role, spec) in roles {
                            println!("  {role:<11} {spec}");
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
            let candidate = c["/model ".len()..].trim();
            let result = (|| -> Result<orbit_engine::TurnConfig, String> {
                let legacy = config::ProvidersConfig::load(home)?.provider.is_empty();
                let mut turn = orbit_cli::checked_model_turn(
                    home,
                    candidate,
                    None,
                    legacy.then_some(gate),
                    false,
                )?;
                apply_selected_effort(home, &mut turn, effort.as_ref())?;
                Ok(turn)
            })();
            match result {
                Ok(resolved) => {
                    *provider = resolved.provider_id;
                    *model = resolved.model;
                    println!("model -> {model}");
                }
                Err(error) => {
                    eprintln!("model unchanged: {error}; use /effort default before switching")
                }
            }
            true
        }
        "/effort" => {
            match chat_effort_config(home, model, gate, Some(provider.as_str()), effort.as_ref()) {
                Ok(config) => println!("{}", orbit_cli::effort_status(home, &config)),
                Err(e) => eprintln!("effort: {e}"),
            }
            true
        }
        c if c.starts_with("/effort ") => {
            let candidate = orbit_cli::parse_effort_setting(c["/effort ".len()..].trim());
            match candidate.and_then(|choice| {
                chat_effort_config(home, model, gate, Some(provider.as_str()), Some(&choice))
                    .map(|config| (choice, config))
            }) {
                Ok((choice, config)) => {
                    *effort = Some(choice);
                    println!("{}", orbit_cli::effort_status(home, &config));
                }
                Err(e) => eprintln!("effort unchanged: {e}"),
            }
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

fn startup_effort_argument(
    args: &[String],
    environment: Option<String>,
) -> Result<Option<EffortSetting>, String> {
    let flag = args.iter().position(|a| a == "--effort");
    let value = match flag {
        Some(index) => Some(
            args.get(index + 1)
                .filter(|v| !v.starts_with('-'))
                .ok_or_else(|| "--effort requires a value (or default)".to_string())?
                .clone(),
        ),
        None => environment,
    };
    value
        .map(|v| orbit_cli::parse_effort_setting(&v))
        .transpose()
}

fn headless_prompt_index(args: &[String]) -> Option<usize> {
    let mut index = 0;
    while let Some(argument) = args.get(index).map(String::as_str) {
        match argument {
            "-p" => return Some(index),
            "--help" | "-h" | "--version" | "-V" => return None,
            "--home" | "--model" | "--provider" | "--gate" | "--effort" | "--resume"
            | "--permission-mode" | "--allowedTools" | "--disallowedTools" | "--output-format"
            | "--json-schema" | "--max-turns" | "--max-cost" => index += 2,
            value if value.starts_with('-') => index += 1,
            _ => return None,
        }
    }
    None
}

fn headless_arguments(args: &[String]) -> Result<Vec<String>, String> {
    let index = headless_prompt_index(args).ok_or("-p must be a top-level option")?;
    let prompt = args
        .get(index + 1)
        .filter(|v| !v.is_empty())
        .ok_or_else(|| "-p requires a prompt".to_string())?;
    let mut remaining = args.to_vec();
    remaining.drain(index..=index + 1);
    validate_headless_arguments(&remaining)?;
    remaining.insert(0, prompt.clone());
    Ok(remaining)
}

fn validate_headless_arguments(args: &[String]) -> Result<(), String> {
    let mut seen = std::collections::HashSet::new();
    let mut index = 0;
    while let Some(argument) = args.get(index).map(String::as_str) {
        if !seen.insert(argument) {
            return Err(format!("duplicate {argument}"));
        }
        match argument {
            "--home" | "--model" | "--provider" | "--gate" | "--effort" | "--resume"
            | "--permission-mode" | "--allowedTools" | "--disallowedTools" | "--output-format"
            | "--json-schema" | "--max-turns" | "--max-cost" => {
                index += 1;
                args.get(index)
                    .filter(|value| !value.is_empty() && !value.starts_with("--"))
                    .ok_or_else(|| format!("{argument} requires a value"))?;
            }
            "--continue" | "--fork-session" | "--bare" | "--auto-tools" | "--spoken-rules" => {}
            _ => return Err(format!("unknown headless argument {argument}")),
        }
        index += 1;
    }
    Ok(())
}

struct HeadlessExecutionOptions {
    format: String,
    max_rounds: u32,
    max_cost: Option<u64>,
    schema: Option<serde_json::Value>,
}

fn headless_execution_options(args: &[String]) -> Result<HeadlessExecutionOptions, String> {
    use std::io::Read;
    validate_headless_arguments(args)?;
    if value_after(args, "--resume").is_some() && args.iter().any(|arg| arg == "--continue") {
        return Err("--resume and --continue cannot be combined".into());
    }
    if value_after(args, "--permission-mode")
        .is_some_and(|mode| orbit_tools::permissions::PermissionMode::from_config(&mode).is_none())
    {
        return Err("unknown --permission-mode".into());
    }
    let format = value_after(args, "--output-format").unwrap_or_else(|| "text".into());
    if !matches!(format.as_str(), "text" | "json" | "stream-json") {
        return Err("--output-format must be text, json or stream-json".into());
    }
    let max_rounds = value_after(args, "--max-turns")
        .map(|value| {
            value
                .parse::<u32>()
                .map_err(|_| "--max-turns must be an unsigned 32-bit integer")
        })
        .transpose()?
        .unwrap_or(orbit_engine::DEFAULT_MAX_ROUNDS);
    let max_cost = value_after(args, "--max-cost")
        .map(|value| {
            value
                .parse::<u64>()
                .map_err(|_| "--max-cost must be an unsigned integer in microcents")
        })
        .transpose()?;
    let schema = value_after(args, "--json-schema")
        .map(|path| {
            let mut options = std::fs::OpenOptions::new();
            options.read(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
            }
            let file = options
                .open(path)
                .map_err(|_| "cannot open --json-schema file")?;
            let metadata = file
                .metadata()
                .map_err(|_| "cannot inspect --json-schema file")?;
            const LIMIT: u64 = 128 * 1024;
            if !metadata.is_file() || metadata.len() > LIMIT {
                return Err("--json-schema must be a regular file of at most 128 KiB".to_string());
            }
            let mut bytes = Vec::new();
            file.take(LIMIT + 1)
                .read_to_end(&mut bytes)
                .map_err(|_| "cannot read --json-schema file")?;
            if bytes.len() as u64 > LIMIT {
                return Err("--json-schema exceeds 128 KiB".to_string());
            }
            let value: serde_json::Value = serde_json::from_slice(&bytes)
                .map_err(|_| "--json-schema file must contain valid JSON")?;
            if !value.is_object() {
                return Err("--json-schema must contain a schema object".to_string());
            }
            Ok(value)
        })
        .transpose()?;
    Ok(HeadlessExecutionOptions {
        format,
        max_rounds,
        max_cost,
        schema,
    })
}

fn apply_selected_effort(
    home: &Path,
    config: &mut orbit_engine::TurnConfig,
    selected: Option<&EffortSetting>,
) -> Result<(), String> {
    if let Some(choice) = selected {
        orbit_cli::apply_effort_setting(home, config, choice)?;
    }
    config.validate_effort()
}

fn chat_effort_config(
    home: &Path,
    model: &str,
    gate: &str,
    provider_override: Option<&str>,
    selected: Option<&EffortSetting>,
) -> Result<orbit_engine::TurnConfig, String> {
    let mut turn = orbit_cli::checked_model_turn(
        home,
        model,
        provider_override,
        if config::ProvidersConfig::load(home)?.provider.is_empty() {
            Some(gate)
        } else {
            None
        },
        true,
    )?;
    apply_selected_effort(home, &mut turn, selected)?;
    Ok(turn)
}

/// The positional words of an argument list: flag/value pairs and bare
/// flags removed, verbs and their operands kept, in order. `--home X
/// provider add ollama` yields `[provider, add, ollama]`, so a
/// subcommand is `positionals(args).get(1)` no matter which flags led.
fn positionals(args: &[String]) -> Vec<&str> {
    let value_flags = [
        "--home",
        "--model",
        "--effort",
        "--gate",
        "--resume",
        "--credential-env",
        "--url",
        "--name",
        "--kind",
        "--manifest",
        "--package",
        "--socket",
        "--session",
        "--provider",
        "--worktree",
        "--easy",
        "--hard",
        "--permission-mode",
        "--allowedTools",
        "--disallowedTools",
    ];
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < args.len() {
        let a = args[i].as_str();
        if value_flags.contains(&a) {
            i += 2;
            continue;
        }
        if a.starts_with('-') {
            i += 1;
            continue;
        }
        out.push(a);
        i += 1;
    }
    out
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

fn command_home(args: &[String]) -> PathBuf {
    config::resolve_home(args)
}

fn owner_model_entry<'a>(
    providers: &'a config::ProvidersConfig,
    model: &str,
    provider_hint: Option<&str>,
    saved_identity: bool,
) -> Result<(&'a config::ProviderConfig, &'a config::ModelEntry), String> {
    let resolved =
        orbit_cli::resolve_selected_model(providers, model, provider_hint, saved_identity)?;
    providers
        .model_entry(&resolved.provider_id, &resolved.raw_model)
        .ok_or_else(|| "selected model disappeared from configuration".into())
}

#[cfg(unix)]
fn cmd_serve(args: &[String]) -> i32 {
    let result = (|| -> Result<i32, String> {
        orbit_cli::validate_owner_arguments("serve", args).map_err(|error| error.to_string())?;
        let home = command_home(args);
        ensure_initialized(&home).map_err(|(code, text)| format!("{code}: {text}"))?;
        let socket = value_after(args, "--socket")
            .filter(|value| !value.is_empty())
            .ok_or("serve requires --socket <private Unix socket path>")?;
        let named = value_after(args, "--session");
        if named.is_some()
            && args
                .iter()
                .any(|value| matches!(value.as_str(), "--resume" | "--continue" | "--fork-session"))
        {
            return Err(
                "--session names a new session; use --resume to reopen an existing session".into(),
            );
        }
        let providers = config::ProvidersConfig::load(&home)?;
        let manual = value_after(args, "--model").or_else(|| std::env::var("ORBIT_MODEL").ok());
        if let Some(spec) = &manual {
            orbit_cli::resolve_selected_model(
                &providers,
                spec,
                value_after(args, "--provider").as_deref(),
                false,
            )?;
        }
        let fresh_id = named.unwrap_or_else(orbit_gateway::new_session_id);
        let (lease, saved, startup_origin) =
            owned_startup_session_with_origin(&home, args, "daemon", &fresh_id)?;
        let model = manual
            .clone()
            .or_else(|| saved.as_ref().map(|session| session.model.clone()))
            .or_else(|| (!providers.roles.main.is_empty()).then(|| providers.roles.main.clone()))
            .or_else(|| {
                providers.provider.iter().find_map(|provider| {
                    provider
                        .models
                        .first()
                        .map(|model| format!("{}/{}", provider.name, model.id))
                })
            })
            .ok_or("configure a provider/model before starting the owner")?;
        let provider_hint = value_after(args, "--provider").or_else(|| {
            manual
                .is_none()
                .then(|| saved.as_ref().map(|session| session.provider.clone()))
                .flatten()
        });
        let (provider, entry) = owner_model_entry(
            &providers,
            &model,
            provider_hint.as_deref(),
            manual.is_none() && saved.is_some(),
        )?;
        let mut checked =
            chat_effort_config(&home, &entry.id, &provider.url, Some(&provider.name), None)?;
        let requested = startup_effort_argument(args, std::env::var("ORBIT_EFFORT").ok())?;
        let effort = sessions::startup_effort(requested, saved.as_ref(), &entry.id, &provider.name);
        apply_selected_effort(&home, &mut checked, effort.as_ref())?;
        if let Some(mode) = value_after(args, "--permission-mode")
            && orbit_tools::permissions::PermissionMode::from_config(&mode).is_none()
        {
            return Err(format!("unknown permission mode {mode}"));
        }
        let mut turn = tui_worker::TuiTurnConfig {
            home: home.clone(),
            session_id: lease.session_id().into(),
            gate: checked.gate.clone(),
            model: entry.id.clone(),
            provider_id: provider.name.clone(),
            effort,
            auto_tools: args.iter().any(|value| value == "--auto-tools"),
            scope: tool_runtime::PermissionScope::from_flags(
                value_after(args, "--permission-mode").as_deref(),
                value_after(args, "--allowedTools").as_deref(),
                value_after(args, "--disallowedTools").as_deref(),
            ),
            initial_transcript: saved
                .as_ref()
                .map(|session| session.to_transcript())
                .unwrap_or_default(),
            initial_turns: saved.as_ref().map(|session| session.turns).unwrap_or(0),
            initial_input_tokens: saved
                .as_ref()
                .map(|session| session.input_tokens)
                .unwrap_or(0),
            initial_output_tokens: saved
                .as_ref()
                .map(|session| session.output_tokens)
                .unwrap_or(0),
            initial_cost_microcents: saved
                .as_ref()
                .map(|session| session.cost_microcents)
                .unwrap_or(0),
        };
        let origin = orbit_cli::startup_selection_origin(
            value_after(args, "--model").is_some(),
            std::env::var("ORBIT_MODEL").is_ok(),
            saved.as_ref(),
            !providers.roles.main.is_empty(),
        );
        let mut seed = sessions::SessionFile::from_chat(
            &turn.session_id,
            &turn.model,
            &turn.gate,
            &turn.provider_id,
            &turn.initial_transcript,
            turn.initial_turns,
            turn.initial_input_tokens,
            turn.initial_output_tokens,
            turn.initial_cost_microcents,
        )
        .with_effort(turn.effort.clone())
        .with_selection_origin(origin);
        session_accounting::prepare_root(&lease, &mut seed, startup_origin)
            .map_err(|error| error.to_string())?;
        turn.initial_transcript = seed.to_transcript();
        turn.initial_turns = seed.turns;
        turn.initial_input_tokens = seed.input_tokens;
        turn.initial_output_tokens = seed.output_tokens;
        turn.initial_cost_microcents = seed.cost_microcents;
        let cwd = std::env::current_dir().map_err(|error| error.to_string())?;
        if args.iter().any(|argument| argument == "--bare") {
            tools::enable_bare_mode();
        }
        eprintln!("Starting session {} at {}", lease.session_id(), socket);
        foreground_owner(
            orbit_cli::daemon::OwnerConfig::new(turn, cwd),
            lease,
            Path::new(&socket),
        )
        .map_err(|error| error.to_string())
    })();
    match result {
        Ok(code) => code,
        Err(error) => {
            eprintln!("orbit serve: {error}");
            2
        }
    }
}

#[cfg(unix)]
static OWNER_SIGNAL: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(0);
#[cfg(unix)]
static PROCESS_SIGNAL_ACTIVE: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

#[cfg(unix)]
extern "C" fn owner_signal(signal: i32) {
    let _ = OWNER_SIGNAL.compare_exchange(
        0,
        signal,
        std::sync::atomic::Ordering::Relaxed,
        std::sync::atomic::Ordering::Relaxed,
    );
}

#[cfg(unix)]
struct SavedSignalDisposition {
    signal: i32,
    previous: libc::sigaction,
    installed: Option<libc::sigaction>,
}

/// Owns process signal registration and the actual cooperative token. The
/// handler only latches an integer; cancellation happens outside signal context.
struct ProcessSignalGuard {
    token: orbit_provider_http::CancelToken,
    signal: i32,
    #[cfg(unix)]
    handlers: Vec<SavedSignalDisposition>,
    #[cfg(unix)]
    done: std::sync::Arc<std::sync::atomic::AtomicBool>,
    #[cfg(unix)]
    watcher: Option<std::thread::JoinHandle<()>>,
    #[cfg(unix)]
    owns_installer: bool,
}

#[cfg(unix)]
fn read_signal_action(signal: i32) -> Result<libc::sigaction, String> {
    // SAFETY: zero initializes this C output structure, and sigaction receives
    // a valid writable pointer. No field is read after a failed syscall.
    let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
    if unsafe { libc::sigaction(signal, std::ptr::null(), &mut action) } != 0 {
        return Err(format!(
            "cannot inspect process signal action: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(action)
}

#[cfg(unix)]
fn replace_signal_action(signal: i32, action: &libc::sigaction) -> Result<libc::sigaction, String> {
    // SAFETY: both C structures live for this call and the kernel writes the
    // complete previous disposition into the initialized output structure.
    let mut previous: libc::sigaction = unsafe { std::mem::zeroed() };
    if unsafe { libc::sigaction(signal, action, &mut previous) } != 0 {
        return Err(format!(
            "cannot replace process signal action: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(previous)
}

#[cfg(unix)]
fn same_signal_action(left: &libc::sigaction, right: &libc::sigaction) -> bool {
    if left.sa_sigaction != right.sa_sigaction || left.sa_flags != right.sa_flags {
        return false;
    }
    #[cfg(any(target_os = "linux", target_os = "android"))]
    if left
        .sa_restorer
        .map(|handler| handler as *const () as usize)
        != right
            .sa_restorer
            .map(|handler| handler as *const () as usize)
    {
        return false;
    }
    // Compare membership, never padding bytes in an opaque libc signal set.
    // Invalid signal numbers return -1 for both sets; every representable
    // valid signal is covered by this bounded bit-capacity walk.
    (1..=std::mem::size_of::<libc::sigset_t>() * 8).all(|signal| {
        // SAFETY: both masks are initialized and live throughout these reads.
        unsafe {
            libc::sigismember(&left.sa_mask, signal as i32)
                == libc::sigismember(&right.sa_mask, signal as i32)
        }
    })
}

impl ProcessSignalGuard {
    fn new() -> Result<Self, String> {
        #[cfg(unix)]
        {
            Self::install(&[libc::SIGINT, libc::SIGTERM, libc::SIGHUP])
        }
        #[cfg(not(unix))]
        {
            Ok(Self {
                token: orbit_provider_http::CancelToken::new(),
                signal: 0,
            })
        }
    }

    #[cfg(unix)]
    fn install(signals: &[i32]) -> Result<Self, String> {
        use std::sync::atomic::Ordering;
        if PROCESS_SIGNAL_ACTIVE
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err("another process signal guard is already active".into());
        }
        OWNER_SIGNAL.store(0, Ordering::Relaxed);
        let mut guard = Self {
            token: orbit_provider_http::CancelToken::new(),
            signal: 0,
            handlers: Vec::new(),
            done: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            watcher: None,
            owns_installer: true,
        };
        // SAFETY: zero is the C default action/mask representation; sigemptyset
        // initializes the mask before any membership or installation operation.
        let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
        if unsafe { libc::sigemptyset(&mut action.sa_mask) } != 0 {
            return Err("cannot initialize process signal mask".into());
        }
        for signal in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP] {
            // SAFETY: the mask is initialized and this is a valid signal.
            if unsafe { libc::sigaddset(&mut action.sa_mask, signal) } != 0 {
                return Err("cannot initialize process signal mask".into());
            }
        }
        action.sa_sigaction = owner_signal as *const () as libc::sighandler_t;
        action.sa_flags = libc::SA_RESTART;
        for signal in signals {
            let previous = replace_signal_action(*signal, &action)?;
            let index = guard.handlers.len();
            guard.handlers.push(SavedSignalDisposition {
                signal: *signal,
                previous,
                installed: None,
            });
            // Capture kernel-normalized flags/restorer for later ownership checks.
            guard.handlers[index].installed = Some(read_signal_action(*signal)?);
        }
        let done = guard.done.clone();
        let token = guard.token.clone();
        guard.watcher = Some(
            std::thread::Builder::new()
                .name("orbit-signal".into())
                .spawn(move || {
                    while !done.load(Ordering::Acquire) {
                        if OWNER_SIGNAL.load(Ordering::Relaxed) != 0 {
                            token.cancel();
                            break;
                        }
                        std::thread::park_timeout(std::time::Duration::from_millis(10));
                    }
                })
                .map_err(|error| format!("cannot start process signal watcher: {error}"))?,
        );
        Ok(guard)
    }

    fn token(&self) -> &orbit_provider_http::CancelToken {
        &self.token
    }

    fn sync_signal(&self) -> i32 {
        #[cfg(unix)]
        let signal = if self.owns_installer {
            OWNER_SIGNAL.load(std::sync::atomic::Ordering::Relaxed)
        } else {
            self.signal
        };
        #[cfg(not(unix))]
        let signal = self.signal;
        if signal != 0 {
            self.token.cancel();
        }
        signal
    }

    fn close(&mut self) -> Result<i32, String> {
        #[cfg(unix)]
        if self.owns_installer {
            self.signal = self.sync_signal();
            self.done.store(true, std::sync::atomic::Ordering::Release);
            let mut failure = None;
            if let Some(watcher) = self.watcher.take() {
                watcher.thread().unpark();
                if watcher.join().is_err() {
                    failure = Some("process signal watcher panicked".to_owned());
                }
            }
            for saved in self.handlers.drain(..).rev() {
                let restored = (|| {
                    let current = read_signal_action(saved.signal)?;
                    let owned = saved.installed.as_ref().map_or_else(
                        || current.sa_sigaction == owner_signal as *const () as libc::sighandler_t,
                        |installed| same_signal_action(&current, installed),
                    );
                    if !owned {
                        return Err(
                            "process signal action changed ownership; foreign action retained"
                                .to_owned(),
                        );
                    }
                    replace_signal_action(saved.signal, &saved.previous)?;
                    Ok(())
                })();
                if let Err(error) = restored {
                    failure.get_or_insert(error);
                }
            }
            self.signal = OWNER_SIGNAL.load(std::sync::atomic::Ordering::Relaxed);
            self.owns_installer = false;
            PROCESS_SIGNAL_ACTIVE.store(false, std::sync::atomic::Ordering::Release);
            if let Some(error) = failure {
                return Err(error);
            }
        }
        Ok(self.signal)
    }
}

impl Drop for ProcessSignalGuard {
    fn drop(&mut self) {
        if let Err(error) = self.close() {
            use std::io::Write;
            let _ = writeln!(std::io::stderr(), "process signal cleanup failed: {error}");
        }
    }
}

#[cfg(unix)]
fn foreground_owner(
    config: orbit_cli::daemon::OwnerConfig,
    lease: sessions::SessionLease,
    socket: &Path,
) -> Result<i32, orbit_cli::daemon::OwnerError> {
    let mut guard = ProcessSignalGuard::new().map_err(orbit_cli::daemon::OwnerError::Runtime)?;
    let result = orbit_cli::daemon::run_server(config, lease, socket, guard.token());
    let signal = guard
        .close()
        .map_err(orbit_cli::daemon::OwnerError::Runtime)?;
    match result {
        Ok(()) => Ok(if signal == 0 { 0 } else { 128 + signal }),
        Err(error) if signal != 0 => {
            eprintln!("orbit serve: {error}");
            Ok(128 + signal)
        }
        Err(error) => Err(error),
    }
}

#[cfg(unix)]
fn cmd_attach(args: &[String]) -> i32 {
    let result = (|| -> Result<(), String> {
        orbit_cli::validate_owner_arguments("attach", args).map_err(|error| error.to_string())?;
        let socket = value_after(args, "--socket")
            .filter(|value| !value.is_empty())
            .ok_or("attach requires --socket <private Unix socket path>")?;
        let commands: Vec<_> = ["--status", "--logs", "--cancel", "--stop"]
            .into_iter()
            .filter(|flag| args.iter().any(|value| value == flag))
            .collect();
        if commands.len() > 1 {
            return Err("choose one attach control command".into());
        }
        let path = Path::new(&socket);
        let value = match commands.first().copied() {
            Some("--status") => serde_json::to_value(
                orbit_cli::attach::status(path).map_err(|error| error.to_string())?,
            ),
            Some("--logs") => serde_json::to_value(
                orbit_cli::attach::logs(path, None).map_err(|error| error.to_string())?,
            ),
            Some("--cancel") => serde_json::to_value(
                orbit_cli::attach::cancel(path).map_err(|error| error.to_string())?,
            ),
            Some("--stop") => serde_json::to_value(
                orbit_cli::attach::stop(path).map_err(|error| error.to_string())?,
            ),
            _ => {
                return orbit_cli::attach::run_interactive(path).map_err(|error| error.to_string());
            }
        }
        .map_err(|error| error.to_string())?;
        println!("{value}");
        Ok(())
    })();
    match result {
        Ok(()) => 0,
        Err(error) => {
            eprintln!("orbit attach: {error}");
            2
        }
    }
}

#[cfg(not(unix))]
fn cmd_serve(_: &[String]) -> i32 {
    eprintln!("foreground ownership requires Unix");
    2
}
#[cfg(not(unix))]
fn cmd_attach(_: &[String]) -> i32 {
    eprintln!("local attach requires Unix");
    2
}

#[cfg(test)]
mod owner_cli_tests {
    use super::*;

    #[test]
    fn saved_provider_prefixed_raw_model_is_not_reinterpreted_as_a_spec() {
        let providers: config::ProvidersConfig = toml::from_str(
            r#"
[[provider]]
name="p"
url="http://127.0.0.1:1"
[[provider.models]]
id="p/foo"
supported_efforts=["high"]
[[provider.models]]
id="foo"
supported_efforts=["low"]
"#,
        )
        .unwrap();
        let (provider, entry) = owner_model_entry(&providers, "p/foo", Some("p"), true).unwrap();
        assert_eq!(
            (&provider.name, entry.id.as_str()),
            (&"p".to_owned(), "p/foo")
        );
        assert_eq!(
            entry.supported_efforts,
            Some(vec![orbit_adapter::types::EffortValue::Level(
                "high".into()
            )])
        );
        assert_eq!(
            owner_model_entry(&providers, "p/foo", Some("p"), false)
                .unwrap()
                .1
                .id,
            "foo"
        );
        assert!(owner_model_entry(&providers, "missing", Some("p"), true).is_err());
    }

    #[test]
    fn leading_owner_value_options_preserve_command_discovery() {
        for (flag, value) in [
            ("--permission-mode", "dontAsk"),
            ("--allowedTools", "Read"),
            ("--disallowedTools", "Bash"),
            ("--provider", "p"),
            ("--socket", "owner.sock"),
        ] {
            let args: Vec<String> = [flag, value, "serve", "--home", "private"]
                .into_iter()
                .map(String::from)
                .collect();
            assert_eq!(positionals(&args), ["serve"]);
        }
    }
}

#[cfg(test)]
mod effort_frontend_tests {
    use super::*;
    use orbit_adapter::types::EffortValue;

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn headless_selection_respects_commands_and_consumed_values() {
        assert!(
            headless_prompt_index(&args(&["customize", "set", "name", "-p", "hello"])).is_none()
        );
        assert!(
            headless_prompt_index(&args(&["--home", "fixture", "setup", "-p", "hello"])).is_none()
        );
        assert!(headless_prompt_index(&args(&["--model", "-p", "chat"])).is_none());
        assert!(headless_arguments(&args(&["-p", "hello", "extra"])).is_err());
        assert!(headless_arguments(&args(&["-p", "hello", "--unknown"])).is_err());
        assert!(headless_arguments(&args(&["-p", "hello", "-p", "again"])).is_err());
        for prompt in ["setup", "web", "--help", "--effort"] {
            assert_eq!(
                headless_arguments(&args(&["-p", prompt, "--bare"])).unwrap(),
                [prompt, "--bare"]
            );
        }
    }

    #[test]
    fn headless_limits_refuse_invalid_budgets_and_schema_instead_of_disabling_them() {
        for values in [
            vec!["--max-cost", "typo"],
            vec!["--max-cost", "-1"],
            vec!["--max-cost", "18446744073709551616"],
            vec!["--max-turns", "4294967296"],
            vec!["--max-turns", "typo"],
            vec!["--output-format", "unknown"],
            vec!["--permission-mode", "unknown"],
        ] {
            assert!(headless_execution_options(&args(&values)).is_err());
        }
        let limits =
            headless_execution_options(&args(&["--max-cost", "0", "--max-turns", "2"])).unwrap();
        assert_eq!(limits.max_cost, Some(0));
        assert_eq!(limits.max_rounds, 2);
        let path =
            std::env::temp_dir().join(format!("orbit-headless-schema-{}", ulid::Ulid::new()));
        let options = args(&["--json-schema", path.to_str().unwrap()]);
        assert!(headless_execution_options(&options).is_err());
        std::fs::write(&path, b"{broken").unwrap();
        assert!(headless_execution_options(&options).is_err());
        std::fs::write(&path, vec![b' '; 128 * 1024 + 1]).unwrap();
        assert!(headless_execution_options(&options).is_err());
        std::fs::write(&path, br#"{"type":"object","required":["result"]}"#).unwrap();
        assert_eq!(
            headless_execution_options(&options)
                .unwrap()
                .schema
                .unwrap()["required"][0],
            "result"
        );
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn effort_flag_beats_environment_and_is_not_a_positional() {
        let a = args(&["--effort", "default", "--model", "a", "chat"]);
        assert_eq!(
            startup_effort_argument(&a, Some("high".into())).unwrap(),
            Some(EffortSetting::Default)
        );
        assert_eq!(positionals(&a), ["chat"]);
        assert_eq!(
            startup_effort_argument(&[], Some("false".into())).unwrap(),
            Some(EffortSetting::Value(EffortValue::Bool(false)))
        );
        assert!(startup_effort_argument(&args(&["--effort"]), None).is_err());
        assert!(startup_effort_argument(&args(&["--effort", "--model", "a"]), None).is_err());
        let headless = headless_arguments(&args(&[
            "--effort",
            "high",
            "-p",
            "actual prompt",
            "--model",
            "a",
        ]))
        .unwrap();
        assert_eq!(headless[0], "actual prompt");
        let dash_prompt = headless_arguments(&args(&[
            "-p",
            "- inspect this module",
            "--effort",
            "default",
        ]))
        .unwrap();
        assert_eq!(dash_prompt[0], "- inspect this module");
        let flag_prompt = headless_arguments(&args(&["-p", "--effort", "--model", "a"])).unwrap();
        assert_eq!(flag_prompt[0], "--effort");
        assert_eq!(
            startup_effort_argument(&flag_prompt[1..], None).unwrap(),
            None
        );
        assert_eq!(
            startup_effort_argument(&headless[1..], None).unwrap(),
            Some(EffortSetting::Value(EffortValue::Level("high".into())))
        );
    }

    #[test]
    fn hot_plain_model_changes_revalidate_explicit_and_resolve_implicit_defaults() {
        let home = std::env::temp_dir().join(format!("orbit-effort-main-{}", ulid::Ulid::new()));
        std::fs::create_dir_all(&home).unwrap();
        std::fs::write(
            home.join("providers.toml"),
            r#"
[[provider]]
name = "fixture"
url = "http://127.0.0.1:1"
[[provider.models]]
id = "a"
supported_efforts = ["low", "high"]
default_effort = "low"
[[provider.models]]
id = "b"
supported_efforts = ["medium"]
default_effort = "medium"
"#,
        )
        .unwrap();
        let mut model = "a".to_string();
        let mut selected = None;
        let mut transcript = vec![];
        let mut provider = "fixture".to_string();
        let gate = "http://127.0.0.1:1";
        let usage = (0, 0, 0, 0);
        let mut command = |text: &str, model: &mut String, selected: &mut Option<EffortSetting>| {
            handle_chat_command(
                text,
                &home,
                model,
                selected,
                gate,
                &mut provider,
                &mut transcript,
                (&usage.0, &usage.1, &usage.2, &usage.3),
            )
        };
        assert!(command("/effort high", &mut model, &mut selected));
        command("/model b", &mut model, &mut selected);
        assert_eq!(model, "a", "invalid switch cannot change live model");
        assert_eq!(
            selected,
            Some(EffortSetting::Value(EffortValue::Level("high".into())))
        );
        command("/effort default", &mut model, &mut selected);
        command("/model b", &mut model, &mut selected);
        assert_eq!(model, "b");
        assert_eq!(selected, Some(EffortSetting::Default));
        assert_eq!(
            chat_effort_config(&home, &model, gate, None, selected.as_ref())
                .unwrap()
                .effort,
            Some(EffortValue::Level("medium".into()))
        );
        selected = None;
        command("/model a", &mut model, &mut selected);
        assert_eq!(
            chat_effort_config(&home, &model, gate, None, None)
                .unwrap()
                .effort,
            Some(EffortValue::Level("low".into()))
        );
        let _ = std::fs::remove_dir_all(home);
    }
}

#[cfg(all(test, target_os = "linux"))]
mod provider_wizard_tests {
    use super::*;
    use std::io::{Read, Write};
    use std::os::unix::fs::PermissionsExt;

    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            let path =
                std::env::temp_dir().join(format!("orbit-provider-wizard-{}", ulid::Ulid::new()));
            std::fs::create_dir(&path).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
            Self(path)
        }
        fn raw(&self) -> String {
            std::fs::read_to_string(self.0.join("providers.toml")).unwrap()
        }
        fn seed(&self) {
            std::fs::write(self.0.join("providers.toml"), "site_label='retain'\n[future]\noption='original'\n[[provider]]\nname='p'\nurl='https://example.invalid/v1'\ncustom='preserve'\n[[provider.models]]\nid='raw/shared'\ncontext_window=99000\n").unwrap();
            std::fs::set_permissions(
                self.0.join("providers.toml"),
                std::fs::Permissions::from_mode(0o600),
            )
            .unwrap();
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    fn add(home: &Path, name: &str) -> Result<(), (&'static str, String)> {
        add_configured_provider(
            home,
            name,
            "https://example.invalid/v1",
            Some("FIXTURE_PROVIDER_KEY".into()),
            vec!["vendor/raw".into()],
            None,
        )
    }
    fn argv(words: &[&str]) -> Vec<String> {
        words.iter().map(|word| (*word).into()).collect()
    }
    fn server(response: Vec<u8>) -> (String, std::thread::JoinHandle<String>) {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        listener.set_nonblocking(true).unwrap();
        let thread = std::thread::spawn(move || {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
            let mut socket = loop {
                match listener.accept() {
                    Ok((socket, _)) => break socket,
                    Err(error)
                        if error.kind() == std::io::ErrorKind::WouldBlock
                            && std::time::Instant::now() < deadline =>
                    {
                        std::thread::sleep(std::time::Duration::from_millis(2))
                    }
                    other => panic!("fixture request missing: {other:?}"),
                }
            };
            socket
                .set_read_timeout(Some(std::time::Duration::from_secs(3)))
                .unwrap();
            socket
                .set_write_timeout(Some(std::time::Duration::from_secs(3)))
                .unwrap();
            let mut bytes = Vec::new();
            let mut buf = [0; 1024];
            while bytes.len() < 16384 && !bytes.windows(4).any(|window| window == b"\r\n\r\n") {
                let count = socket.read(&mut buf).unwrap();
                assert!(count > 0);
                bytes.extend_from_slice(&buf[..count]);
            }
            let _ = socket.write_all(&response);
            String::from_utf8(bytes).unwrap()
        });
        (endpoint, thread)
    }
    fn response(body: &str) -> Vec<u8> {
        format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).into_bytes()
    }

    #[test]
    fn endpoint_paths_compose_once_and_encode_raw_model_identity() {
        for (base, kind, expected) in [
            ("https://example.invalid", "openai-compatible", "/v1/models"),
            ("https://example.invalid/v1/", "anthropic", "/v1/models"),
            (
                "https://example.invalid/gateway/v1",
                "openai-compatible",
                "/gateway/v1/models",
            ),
            ("http://127.0.0.1:1", "ollama", "/api/tags"),
            ("http://127.0.0.1:1/api", "ollama", "/api/tags"),
        ] {
            assert_eq!(
                provider_models_url(base, kind, None).unwrap().path(),
                expected
            );
        }
        assert_eq!(
            provider_models_url(
                "https://example.invalid/v1",
                "anthropic",
                Some("vendor/raw?x#y")
            )
            .unwrap()
            .path(),
            "/v1/models/vendor%2Fraw%3Fx%23y"
        );
    }
    #[test]
    fn unsafe_urls_and_credential_references_fail_without_discovery() {
        for url in [
            "https://user:PRIVATE@localhost/v1",
            "https://localhost/v1#PRIVATE",
            "http://10.evil.invalid/v1",
            "http://172.16.evil.invalid/v1",
            "ftp://localhost",
            "https://",
            "https://localhost/v1?%61Pi%2DKey=PRIVATE",
            "https://localhost/v1?Access.Token=PRIVATE",
            "https://localhost/v1?client_secret=PRIVATE",
        ] {
            let error =
                validate_discovery_input("p", url, Some("FIXTURE_KEY"), "openai-compatible")
                    .unwrap_err();
            assert!(!error.1.contains("PRIVATE"));
        }
        for (name, env, kind) in [
            ("bad/name", "FIXTURE_KEY", "openai-compatible"),
            ("p", "KEY=PRIVATE", "openai-compatible"),
            ("p", "KEY", "unknown"),
        ] {
            assert!(
                validate_discovery_input(name, "https://example.invalid", Some(env), kind).is_err()
            );
        }
        assert!(
            validate_discovery_input(
                "p",
                "https://example.invalid/v1?api-version=2026-01-01",
                Some("KEY"),
                "openai-compatible"
            )
            .is_ok()
        );
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        assert!(discover_models(&url, Some("INVALID=ENV"), "openai-compatible").is_err());
        assert!(
            matches!(listener.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock)
        );
        let f = Fixture::new();
        f.seed();
        let before = f.raw().replace(
            "https://example.invalid/v1",
            "https://example.invalid/v1?api_key=PRIVATE",
        );
        std::fs::write(f.0.join("providers.toml"), &before).unwrap();
        let error = cmd_provider(&f.0, &argv(&["provider", "list"])).unwrap_err();
        assert!(!error.1.contains("PRIVATE"));
        assert_eq!(f.raw(), before);
    }
    #[test]
    fn provider_preset_zero_and_out_of_range_never_choose_a_provider() {
        assert!(select_provider_preset("0").is_err());
        assert!(select_provider_preset("999999").is_err());
        assert_eq!(
            select_provider_preset("1").unwrap().id,
            orbit_cli::presets::presets()[0].id
        );
        assert_eq!(select_provider_preset("custom").unwrap().id, "custom");
    }
    #[test]
    fn bounded_prompt_refuses_oversize_invalid_utf8_controls_and_eof() {
        for bytes in [
            vec![b'x'; 4097],
            vec![0xff, b'\n'],
            b"\tPRIVATE\n".to_vec(),
            Vec::new(),
        ] {
            let error = read_provider_line(&mut std::io::Cursor::new(bytes), None).unwrap_err();
            assert!(!error.1.contains("PRIVATE"));
        }
        assert_eq!(
            read_provider_line(&mut std::io::Cursor::new(b"\r\n"), Some("default")).unwrap(),
            "default"
        );
        assert_eq!(
            read_provider_line(&mut std::io::Cursor::new(b" vendor/raw \n"), None).unwrap(),
            "vendor/raw"
        );
    }
    #[test]
    fn model_selection_and_csv_refuse_partial_or_ambiguous_input() {
        for csv in ["", "a,", "a,,b", "a,a", "a,\u{1b}b"] {
            assert!(parse_provider_models(csv).is_err());
        }
        assert_eq!(
            parse_provider_models("vendor/raw,other").unwrap(),
            ["vendor/raw", "other"]
        );
        let offered = vec!["a".into(), "b".into()];
        for selection in ["0", "1,garbage", "3", "1,1", ""] {
            assert!(select_provider_models(selection, &offered).is_err());
        }
        assert_eq!(select_provider_models("2,1", &offered).unwrap(), ["b", "a"]);
    }
    #[test]
    fn model_response_enforces_count_ids_and_secret_free_parse_errors() {
        for raw in [r#"{"data":[{"id":"a"},{"id":"a"}]}"#.to_string(), serde_json::json!({"data": (0..129).map(|n| serde_json::json!({"id":format!("m{n}")})).collect::<Vec<_>>()}).to_string(), r#"{"data":"PRIVATE RESPONSE"}"#.to_string(), r#"{"data":[{"id":"\u001bsecret"}]}"#.to_string()] {
            let error = parse_discovered_models(&raw, "openai-compatible").unwrap_err();
            assert!(!error.contains("PRIVATE RESPONSE"));
        }
    }
    #[test]
    fn add_preserves_raw_unknown_metadata_exact_caps_pricing_and_identity() {
        let f = Fixture::new();
        let plan =
            orbit_cli::setup::plan_setup(&f.0, &orbit_cli::setup::SetupRequest::default()).unwrap();
        orbit_cli::setup::apply_setup(&plan).unwrap();
        let identity: Vec<_> = ["trust/operator.key", "trust/manifest.json", "pib.json"]
            .map(|path| std::fs::read(f.0.join(path)).unwrap())
            .into();
        f.seed();
        let model = config::ModelEntry {
            context_limits: None,
            id: "vendor/raw".into(),
            label: Some("Exact".into()),
            pricing: config::Pricing {
                input_per_million_microdollars: 123,
                output_per_million_microdollars: 456,
                ..Default::default()
            },
            max_output_tokens: Some(12345),
            context_window: Some(200000),
            sampling: None,
            supported_efforts: Some(vec![orbit_adapter::types::EffortValue::Level(
                "high".into(),
            )]),
            default_effort: Some(orbit_adapter::types::EffortValue::Level("high".into())),
            first_byte_timeout_ms: None,
            idle_timeout_ms: None,
        };
        add_configured_provider_kind(
            &f.0,
            "q",
            "https://example.invalid/v1",
            "openai-compatible",
            Some("FIXTURE_KEY".into()),
            vec![model.id.clone()],
            None,
            Some(vec![model.clone()]),
        )
        .unwrap();
        let document: toml::Value = toml::from_str(&f.raw()).unwrap();
        assert_eq!(document["site_label"].as_str(), Some("retain"));
        assert_eq!(document["future"]["option"].as_str(), Some("original"));
        assert_eq!(document["provider"][0]["custom"].as_str(), Some("preserve"));
        assert_eq!(
            config::ProvidersConfig::load(&f.0).unwrap().provider[1].models,
            [model]
        );
        for (index, path) in ["trust/operator.key", "trust/manifest.json", "pib.json"]
            .iter()
            .enumerate()
        {
            assert_eq!(std::fs::read(f.0.join(path)).unwrap(), identity[index]);
        }
        assert_eq!(
            std::fs::metadata(f.0.join("providers.toml"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
    #[test]
    fn duplicate_or_invalid_provider_add_preserves_existing_bytes_and_missing_home() {
        let f = Fixture::new();
        f.seed();
        let before = f.raw();
        assert!(add(&f.0, "p").is_err());
        assert_eq!(f.raw(), before);
        let missing = f.0.join("absent");
        assert!(add(&missing, "q").unwrap_err().1.contains("setup"));
        assert!(!missing.exists());
        assert!(
            add_configured_provider(
                &missing,
                "q",
                "https://user:PRIVATE@example.invalid",
                None,
                vec!["m".into()],
                None
            )
            .is_err()
        );
        assert!(!missing.exists());
    }
    #[test]
    fn provider_mutations_observe_shared_lock_and_latest_unknown_settings() {
        let f = Fixture::new();
        f.seed();
        let lock = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(f.0.join(".config.lock"))
            .unwrap();
        std::fs::set_permissions(
            f.0.join(".config.lock"),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        lock.lock().unwrap();
        let before = f.raw();
        assert!(add(&f.0, "q").is_err());
        assert_eq!(f.raw(), before);
        std::fs::File::unlock(&lock).unwrap();
        config::ProvidersConfig::update_atomic(&f.0, |raw| {
            let mut document = provider_document(raw)?;
            document["future"]["option"] = toml::Value::String("concurrent-edit".into());
            serialize_provider_document(&document)
        })
        .unwrap();
        add(&f.0, "q").unwrap();
        let document: toml::Value = toml::from_str(&f.raw()).unwrap();
        assert_eq!(
            document["future"]["option"].as_str(),
            Some("concurrent-edit")
        );
        assert_eq!(
            config::ProvidersConfig::load(&f.0).unwrap().provider.len(),
            2
        );
    }
    #[test]
    fn role_edit_resolves_exact_identity_and_preserves_unknown_tables() {
        let f = Fixture::new();
        f.seed();
        set_provider_role(&f.0, "main", "p/raw/shared").unwrap();
        let before = f.raw();
        assert!(set_provider_role(&f.0, "main", "p/missing").is_err());
        assert_eq!(f.raw(), before);
        let document: toml::Value = toml::from_str(&f.raw()).unwrap();
        assert_eq!(document["roles"]["main"].as_str(), Some("p/raw/shared"));
        assert_eq!(document["provider"][0]["custom"].as_str(), Some("preserve"));
    }
    #[test]
    fn removal_refuses_dangling_role_then_preserves_other_provider_metadata() {
        let f = Fixture::new();
        f.seed();
        add(&f.0, "q").unwrap();
        set_provider_role(&f.0, "main", "q/vendor/raw").unwrap();
        let before = f.raw();
        assert!(cmd_provider(&f.0, &argv(&["provider", "remove", "q"])).is_err());
        assert_eq!(f.raw(), before);
        set_provider_role(&f.0, "main", "").unwrap();
        cmd_provider(&f.0, &argv(&["provider", "remove", "q"])).unwrap();
        let document: toml::Value = toml::from_str(&f.raw()).unwrap();
        assert_eq!(document["future"]["option"].as_str(), Some("original"));
        assert_eq!(document["provider"][0]["custom"].as_str(), Some("preserve"));
        assert_eq!(
            config::ProvidersConfig::load(&f.0).unwrap().provider.len(),
            1
        );
    }
    #[test]
    fn role_and_route_offers_preserve_concurrent_selections_and_exact_second_identity() {
        let f = Fixture::new();
        f.seed();
        add(&f.0, "q").unwrap();
        set_provider_role(&f.0, "main", "p/raw/shared").unwrap();
        config::ProvidersConfig::update_atomic(&f.0, |raw| {
            let mut document = provider_document(raw)?;
            provider_table(&mut document, "routing")?
                .insert("hard".into(), toml::Value::String("p/raw/shared".into()));
            serialize_provider_document(&document)
        })
        .unwrap();
        let preset = orbit_cli::presets::preset_by_id("custom").unwrap();
        let roles = fill_unset_provider_roles(&f.0, "q", &["vendor/raw".into()], &preset).unwrap();
        assert!(!roles.iter().any(|(role, _)| role == "main"));
        let routes =
            fill_unset_provider_routes(&f.0, "q", &["vendor/raw".into()], &preset).unwrap();
        assert_eq!(routes, [("easy".into(), "q/vendor/raw".into())]);
        let cfg = config::ProvidersConfig::load(&f.0).unwrap();
        assert_eq!(cfg.roles.main, "p/raw/shared");
        assert_eq!(cfg.routing.hard, "p/raw/shared");
        assert!(
            fill_unset_provider_routes(&f.0, "q", &["vendor/raw".into()], &preset)
                .unwrap()
                .is_empty()
        );
    }
    #[test]
    fn unknown_duplicate_and_incomplete_provider_flags_fail_before_mutation() {
        let f = Fixture::new();
        let missing = f.0.join("absent");
        for words in [
            vec!["provider", "add", "custom", "--model", "m", "--unknown"],
            vec!["provider", "add", "custom", "--model", "m", "--model", "n"],
            vec!["provider", "add", "custom", "--url"],
            vec!["provider", "remove", "p", "unexpected"],
        ] {
            assert!(cmd_provider(&missing, &argv(&words)).is_err());
            assert!(!missing.exists());
        }
    }
    #[test]
    fn actual_discovery_uses_single_base_path_for_all_three_dialects() {
        for (kind, base, path, body) in [
            (
                "openai-compatible",
                "/v1",
                "/v1/models",
                r#"{"data":[{"id":"vendor/raw"}]}"#,
            ),
            (
                "anthropic",
                "/gateway/v1",
                "/gateway/v1/models",
                r#"{"data":[{"id":"vendor/raw"}]}"#,
            ),
            (
                "ollama",
                "/api",
                "/api/tags",
                r#"{"models":[{"name":"vendor/raw"}]}"#,
            ),
        ] {
            let (endpoint, thread) = server(response(body));
            assert_eq!(
                discover_models(&format!("{endpoint}{base}"), None, kind).unwrap(),
                ["vendor/raw"]
            );
            let request = thread.join().unwrap();
            assert!(
                request.starts_with(&format!("GET {path} HTTP/1.1\r\n")),
                "unexpected fixture endpoint"
            );
            if kind == "anthropic" {
                assert!(
                    request
                        .to_ascii_lowercase()
                        .contains("anthropic-version: 2023-06-01")
                );
            }
        }
    }
    #[test]
    fn actual_anthropic_detail_uses_encoded_identity_and_retains_limits() {
        let (endpoint, thread) = server(response(
            r#"{"max_input_tokens":190000,"max_tokens":24000}"#,
        ));
        let limits = anthropic_model_limits(&format!("{endpoint}/v1"), None, "vendor/raw");
        assert_eq!(limits.context_window, Some(190000));
        assert_eq!(limits.max_output_tokens, Some(24000));
        assert!(
            thread
                .join()
                .unwrap()
                .starts_with("GET /v1/models/vendor%2Fraw HTTP/1.1\r\n")
        );
    }
    #[test]
    fn actual_discovery_caps_declared_and_chunked_response_bodies() {
        let (endpoint, thread) = server(
            b"HTTP/1.1 200 OK\r\nContent-Length: 131073\r\nConnection: close\r\n\r\n".to_vec(),
        );
        assert!(
            discover_models(&endpoint, None, "openai-compatible")
                .unwrap_err()
                .contains("128 KiB")
        );
        assert!(thread.join().unwrap().starts_with("GET /v1/models "));
        let body = "x".repeat(PROVIDER_RESPONSE_LIMIT + 1);
        let bytes = format!("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n{:x}\r\n{body}\r\n0\r\n\r\n", body.len()).into_bytes();
        let (endpoint, thread) = server(bytes);
        assert!(
            discover_models(&endpoint, None, "openai-compatible")
                .unwrap_err()
                .contains("128 KiB")
        );
        thread.join().unwrap();
    }
    #[test]
    fn actual_discovery_refuses_redirect_without_contacting_second_endpoint() {
        let destination = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        destination.set_nonblocking(true).unwrap();
        let (endpoint, thread) = server(format!("HTTP/1.1 302 Found\r\nLocation: http://{}/PRIVATE\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", destination.local_addr().unwrap()).into_bytes());
        let error = discover_models(&endpoint, None, "openai-compatible").unwrap_err();
        assert!(error.contains("302"));
        assert!(!error.contains("PRIVATE"));
        thread.join().unwrap();
        assert!(
            matches!(destination.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock)
        );
    }
}

#[cfg(test)]
mod provider_credential_parser_tests {
    use super::*;
    use orbit_cli::onboarding::{ProviderLoginMethod, provider_login::LoginMode};
    fn args(words: &[&str]) -> Vec<String> {
        words.iter().map(|word| (*word).to_owned()).collect()
    }

    #[test]
    fn login_parser_preserves_name_and_distinguishes_private_browser_modes() {
        let value = args(&[
            "provider",
            "login",
            "custom provider",
            "--headless",
            "--no-browser",
        ]);
        validate_provider_arguments(&value).unwrap();
        let ProviderCredentialCommand::Login { name, request } =
            provider_credential_arguments(&value).unwrap()
        else {
            panic!("login expected");
        };
        assert_eq!(name, "custom provider");
        assert_eq!(request.method, Some(ProviderLoginMethod::Browser));
        assert_eq!(request.mode, LoginMode::Headless);
        assert!(!request.open_browser);
        let ProviderCredentialCommand::Login { request, .. } =
            provider_credential_arguments(&args(&[
                "provider", "login", "login", "--method", "key",
            ]))
            .unwrap()
        else {
            panic!("login expected");
        };
        assert_eq!(request.method, Some(ProviderLoginMethod::Key));
    }

    #[test]
    fn logout_parser_requires_explicit_yes_for_redirected_json() {
        for words in [
            vec!["provider", "logout", "p", "--yes", "--json"],
            vec!["--json", "provider", "logout", "p", "--yes"],
        ] {
            let ProviderCredentialCommand::Logout { name, yes } =
                provider_credential_arguments(&args(&words)).unwrap()
            else {
                panic!("logout expected");
            };
            assert_eq!(name, "p");
            assert!(yes);
        }
        assert!(
            provider_credential_arguments(&args(&["provider", "logout", "p", "--json"])).is_err()
        );
    }

    #[test]
    fn credential_parser_refuses_duplicate_unknown_incomplete_and_conflicting_flags() {
        for words in [
            vec!["provider", "login"],
            vec!["provider", "login", "p", "q"],
            vec!["provider", "login", "p", "--method"],
            vec!["provider", "login", "p", "--method", "unknown"],
            vec!["provider", "login", "p", "--method", "key", "--headless"],
            vec!["provider", "login", "p", "--method", "env", "--no-browser"],
            vec![
                "provider", "login", "p", "--method", "key", "--method", "key",
            ],
            vec!["provider", "login", "p", "--headless", "--headless"],
            vec!["provider", "login", "p", "--json"],
            vec!["--json", "provider", "login", "p"],
            vec!["provider", "login", "p", "--api-key", "private"],
            vec!["provider", "logout", "p", "--yes", "--yes"],
            vec!["provider", "logout", "p", "--method", "key"],
            vec!["provider", "logout", "p", "--unknown"],
            vec!["provider", "logout", "p/q", "--yes"],
        ] {
            assert!(validate_provider_arguments(&args(&words)).is_err());
        }
    }

    #[test]
    fn offline_provider_commands_accept_credential_words_as_ordinary_operands() {
        for words in [
            vec!["provider", "remove", "login"],
            vec!["provider", "role", "main", "logout"],
            vec!["provider", "add", "custom", "--model", "login"],
            vec!["provider", "list", "--json"],
        ] {
            validate_provider_arguments(&args(&words)).unwrap();
        }
    }
}

#[cfg(test)]
mod provider_refresh_parser_tests {
    use super::*;

    #[test]
    fn refresh_parser_preserves_exact_name_and_schema() {
        let args = [
            "provider",
            "refresh",
            "--schema",
            "openrouter",
            "custom provider",
            "--json",
        ]
        .map(str::to_owned);
        let (name, schema) = provider_refresh_arguments(&args).unwrap();
        assert_eq!(name, "custom provider");
        assert_eq!(
            schema,
            Some(orbit_cli::provider_discovery::DiscoveryProfile::OpenRouter)
        );
        validate_provider_arguments(&args).unwrap();
    }

    #[test]
    fn refresh_parser_refuses_ambiguous_or_incomplete_flags_before_lookup() {
        for tail in [
            vec!["provider", "refresh"],
            vec!["provider", "refresh", "p", "q"],
            vec!["provider", "refresh", "p", "--schema"],
            vec!["provider", "refresh", "p", "--schema", "unknown"],
            vec!["provider", "refresh", "p", "--json", "--json"],
            vec![
                "provider", "refresh", "p", "--schema", "generic", "--schema", "generic",
            ],
            vec![
                "provider",
                "refresh",
                "p",
                "--url",
                "https://example.invalid",
            ],
            vec!["provider", "refresh", "p/q"],
        ] {
            let args: Vec<String> = tail.into_iter().map(str::to_owned).collect();
            assert!(validate_provider_arguments(&args).is_err());
        }
    }
}

#[cfg(all(test, unix))]
mod process_signal_guard_tests {
    use super::*;
    use std::sync::atomic::Ordering;

    // Only these tests alter the main binary's process-wide dispositions.
    // Kernel delivery belongs to the isolated CLI integration cases, not libtest.
    static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

    extern "C" fn preserved_handler(_: i32) {}

    struct DispositionFixture {
        originals: Vec<(i32, libc::sigaction)>,
        expected: Vec<(i32, libc::sigaction)>,
    }

    impl DispositionFixture {
        fn new() -> Self {
            let mut fixture = Self {
                originals: Vec::new(),
                expected: Vec::new(),
            };
            // SAFETY: initialize the entire C action and then initialize its
            // signal mask before installing this benign, never-signalled fixture.
            let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
            assert_eq!(unsafe { libc::sigemptyset(&mut action.sa_mask) }, 0);
            assert_eq!(
                unsafe { libc::sigaddset(&mut action.sa_mask, libc::SIGUSR1) },
                0
            );
            assert_eq!(
                unsafe { libc::sigaddset(&mut action.sa_mask, libc::SIGUSR2) },
                0
            );
            action.sa_sigaction = preserved_handler as *const () as libc::sighandler_t;
            action.sa_flags = libc::SA_RESTART | libc::SA_NODEFER;
            for signal in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP] {
                fixture
                    .originals
                    .push((signal, replace_signal_action(signal, &action).unwrap()));
                fixture
                    .expected
                    .push((signal, read_signal_action(signal).unwrap()));
            }
            fixture
        }

        fn assert_restored(&self) {
            for (signal, expected) in &self.expected {
                let current = read_signal_action(*signal).unwrap();
                assert_eq!(current.sa_flags, expected.sa_flags);
                assert_eq!(current.sa_sigaction, expected.sa_sigaction);
                for member in [
                    libc::SIGUSR1,
                    libc::SIGUSR2,
                    libc::SIGINT,
                    libc::SIGTERM,
                    libc::SIGHUP,
                ] {
                    assert_eq!(
                        unsafe { libc::sigismember(&current.sa_mask, member) },
                        unsafe { libc::sigismember(&expected.sa_mask, member) }
                    );
                }
                assert!(
                    same_signal_action(&current, expected),
                    "complete handler/mask/flags/restorer for signal {signal}"
                );
            }
        }
    }

    impl Drop for DispositionFixture {
        fn drop(&mut self) {
            for (signal, original) in self.originals.iter().rev() {
                // Preserve the outer libtest process even on a failed assertion.
                let _ = replace_signal_action(*signal, original);
            }
        }
    }

    #[test]
    fn full_dispositions_restore_and_normal_cleanup_joins_the_actual_watcher() {
        let _serial = SERIAL
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let fixture = DispositionFixture::new();
        for (_, expected) in &fixture.expected {
            assert_ne!(expected.sa_flags & libc::SA_NODEFER, 0);
            assert_eq!(
                unsafe { libc::sigismember(&expected.sa_mask, libc::SIGUSR1) },
                1
            );
            assert_eq!(
                unsafe { libc::sigismember(&expected.sa_mask, libc::SIGUSR2) },
                1
            );
        }
        let mut guard = ProcessSignalGuard::new().unwrap();
        assert!(guard.watcher.is_some() && guard.owns_installer);
        assert_eq!(guard.close().unwrap(), 0);
        assert!(guard.watcher.is_none() && guard.handlers.is_empty() && !guard.owns_installer);
        assert!(guard.done.load(Ordering::Acquire));
        assert!(!PROCESS_SIGNAL_ACTIVE.load(Ordering::Acquire));
        fixture.assert_restored();
        assert_eq!(guard.close().unwrap(), 0);
    }

    #[test]
    fn nested_guard_cannot_reset_first_signal_and_sync_cancels_both_shared_operation_tokens() {
        let _serial = SERIAL
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let fixture = DispositionFixture::new();
        for (first_signal, exit) in [
            (libc::SIGINT, 130),
            (libc::SIGTERM, 143),
            (libc::SIGHUP, 129),
        ] {
            let mut guard = ProcessSignalGuard::new().unwrap();
            let first = guard.token().clone();
            let repair = guard.token().clone();
            let installed: Vec<_> = [libc::SIGINT, libc::SIGTERM, libc::SIGHUP]
                .into_iter()
                .map(|signal| (signal, read_signal_action(signal).unwrap()))
                .collect();
            // Direct calls exercise the real atomic handler without process-wide
            // signal delivery into unrelated parallel libtest workers.
            owner_signal(first_signal);
            assert!(ProcessSignalGuard::new().is_err());
            owner_signal(if first_signal == libc::SIGINT {
                libc::SIGTERM
            } else {
                libc::SIGINT
            });
            assert_eq!(guard.sync_signal(), first_signal);
            assert!(first.is_cancelled() && repair.is_cancelled());
            let may_repair = guard.sync_signal() == 0 && !guard.token().is_cancelled();
            assert!(!may_repair, "repair admission must stay closed");
            for (signal, expected) in installed {
                assert!(same_signal_action(
                    &read_signal_action(signal).unwrap(),
                    &expected
                ));
            }
            let signal = guard.close().unwrap();
            assert_eq!(signal, first_signal);
            assert_eq!(128 + signal, exit);
            fixture.assert_restored();
        }
    }

    #[test]
    fn an_early_return_drops_and_joins_before_releasing_the_installer() {
        let _serial = SERIAL
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let fixture = DispositionFixture::new();
        fn leave(
            done: &mut Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
        ) -> Result<(), &'static str> {
            let guard = ProcessSignalGuard::new().unwrap();
            *done = Some(guard.done.clone());
            Err("ordinary early return")
        }
        let mut done = None;
        assert_eq!(leave(&mut done), Err("ordinary early return"));
        assert!(done.unwrap().load(Ordering::Acquire));
        assert!(!PROCESS_SIGNAL_ACTIVE.load(Ordering::Acquire));
        fixture.assert_restored();
        let mut next = ProcessSignalGuard::new().unwrap();
        next.close().unwrap();
    }

    #[test]
    fn unwind_restores_complete_actions_and_releases_the_actual_guard() {
        let _serial = SERIAL
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let fixture = DispositionFixture::new();
        let mut done = None;
        let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let guard = ProcessSignalGuard::new().unwrap();
            done = Some(guard.done.clone());
            panic!("signal guard unwind control");
        }));
        assert!(unwind.is_err());
        assert!(done.unwrap().load(Ordering::Acquire));
        assert!(!PROCESS_SIGNAL_ACTIVE.load(Ordering::Acquire));
        fixture.assert_restored();
        let mut next = ProcessSignalGuard::new().unwrap();
        next.close().unwrap();
    }

    #[test]
    fn a_real_later_sigaction_failure_rolls_back_prior_complete_dispositions() {
        let _serial = SERIAL
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let fixture = DispositionFixture::new();
        // Signal zero is invalid for sigaction. The first two replacements are
        // real successes before the deterministic later syscall failure.
        assert!(ProcessSignalGuard::install(&[libc::SIGINT, libc::SIGTERM, 0]).is_err());
        assert!(!PROCESS_SIGNAL_ACTIVE.load(Ordering::Acquire));
        fixture.assert_restored();
        let mut next = ProcessSignalGuard::new().unwrap();
        next.close().unwrap();
    }

    #[test]
    fn foreign_mask_and_flag_changes_are_reported_and_never_overwritten() {
        let _serial = SERIAL
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let fixture = DispositionFixture::new();
        for mask_change in [false, true] {
            let mut guard = ProcessSignalGuard::new().unwrap();
            let mut foreign = read_signal_action(libc::SIGTERM).unwrap();
            if mask_change {
                assert_eq!(
                    unsafe { libc::sigaddset(&mut foreign.sa_mask, libc::SIGUSR1) },
                    0
                );
            } else {
                foreign.sa_flags ^= libc::SA_RESTART;
            }
            replace_signal_action(libc::SIGTERM, &foreign).unwrap();
            let foreign = read_signal_action(libc::SIGTERM).unwrap();
            let error = guard.close().unwrap_err();
            assert!(error.contains("changed ownership"));
            assert!(same_signal_action(
                &read_signal_action(libc::SIGTERM).unwrap(),
                &foreign
            ));
            for (signal, expected) in &fixture.expected {
                if *signal != libc::SIGTERM {
                    assert!(same_signal_action(
                        &read_signal_action(*signal).unwrap(),
                        expected
                    ));
                }
            }
            assert!(guard.watcher.is_none() && !PROCESS_SIGNAL_ACTIVE.load(Ordering::Acquire));
            // The fixture, not the guard, owns restoration of this deliberately
            // foreign replacement. It restores the outer process on scope exit.
            let expected = &fixture
                .expected
                .iter()
                .find(|(signal, _)| *signal == libc::SIGTERM)
                .unwrap()
                .1;
            replace_signal_action(libc::SIGTERM, expected).unwrap();
            fixture.assert_restored();
        }
    }
}

#[cfg(test)]
mod plain_signal_result_tests {
    use super::*;

    #[test]
    fn caught_signals_preserve_their_exit_codes_but_never_override_a_real_error() {
        assert_eq!(plain_signal_exit_code(0, 2, false), 2);
        for (signal, expected) in [(2, 130), (15, 143), (1, 129)] {
            assert_eq!(plain_signal_exit_code(signal, 0, false), expected);
            assert_eq!(plain_signal_exit_code(signal, 1, false), expected);
            assert_eq!(plain_signal_exit_code(signal, 0, true), 1);
            assert_eq!(plain_signal_exit_code(signal, 1, true), 1);
        }
    }

    #[test]
    fn cancelled_uncertain_compaction_is_distinct_from_failed_publication_or_inspection() {
        use orbit_engine::CompactionStatus as S;
        let view = session_accounting::AccountingView {
            revision: 2,
            input_tokens: 100,
            output_tokens: 40,
            known_cost_microcents: 60,
            full_cost_status: FullCostStatus::Uncertain,
        };
        let completion = |status, applied| {
            Ok(orbit_engine::ManualCompactionCompletion {
                status,
                applied,
                accounting: orbit_engine::AccountingDelta::known_zero(),
                attempts: Vec::new(),
            })
        };
        assert!(!compact_local_failed(
            &completion(S::Cancelled, false),
            &Ok(view),
            Some(view)
        ));
        assert!(!compact_local_failed(
            &Err("cancelled"),
            &Ok(view),
            Some(view)
        ));
        let known = session_accounting::AccountingView {
            full_cost_status: FullCostStatus::Known,
            ..view
        };
        assert!(!compact_local_failed(
            &completion(S::PublishedReady, true),
            &Ok(known),
            Some(known)
        ));
        assert!(compact_local_failed(
            &completion(S::PublishedReady, true),
            &Ok(view),
            Some(view)
        ));
        for status in [
            S::PublicationUncertain,
            S::AccountingUncertain,
            S::StorageUnsafe,
            S::InvalidHistory,
        ] {
            assert!(compact_local_failed(
                &completion(status, false),
                &Ok(view),
                Some(view)
            ));
        }
        assert!(compact_local_failed(
            &completion(S::PublishedReady, false),
            &Ok(view),
            Some(view)
        ));
        assert!(compact_local_failed(
            &Err("selection_invalid"),
            &Ok(view),
            Some(view)
        ));
        assert!(compact_local_failed(
            &completion(S::Cancelled, false),
            &Ok(view),
            None
        ));
        let failed = Err(session_accounting::AccountingError::InvalidState(
            "publication failed",
        ));
        assert!(compact_local_failed(
            &completion(S::Cancelled, false),
            &failed,
            Some(view)
        ));
    }
}
