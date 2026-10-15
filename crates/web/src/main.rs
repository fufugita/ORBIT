//! Browser entry point with the same owned-session and provider selection rules.
#![deny(unsafe_code)]

use orbit_cli::{
    config::ProvidersConfig,
    sessions::{SessionFile, SessionLease},
    tui_worker::TuiTurnConfig,
};
use orbit_web::{BridgeConfig, run_bridge_owned_with_customization};

fn value_after(args: &[String], flag: &str) -> Option<String> {
    args.iter()
        .position(|argument| argument == flag)
        .and_then(|index| args.get(index + 1))
        .cloned()
}
fn options(args: &[String]) -> Result<(), String> {
    let values = [
        "--home",
        "--model",
        "--provider",
        "--effort",
        "--gate",
        "--port",
        "--bind",
        "--token",
        "--resume",
        "--permission-mode",
        "--allowedTools",
        "--disallowedTools",
    ];
    let toggles = [
        "--no-browser",
        "--auto-tools",
        "--bare",
        "--safe-customization",
    ];
    let mut seen = std::collections::HashSet::new();
    let mut index = 0;
    while index < args.len() {
        let flag = args[index].as_str();
        if !seen.insert(flag) {
            return Err(format!("duplicate option {flag}"));
        }
        if values.contains(&flag) {
            let value = args
                .get(index + 1)
                .ok_or_else(|| format!("{flag} requires a value"))?;
            if value.starts_with("--")
                || (value.is_empty() && !matches!(flag, "--allowedTools" | "--disallowedTools"))
            {
                return Err(format!("{flag} requires a value"));
            }
            index += 2;
        } else if toggles.contains(&flag) {
            index += 1;
        } else {
            return Err(format!("unknown browser option {flag}"));
        }
    }
    Ok(())
}
/// Validate a legacy gate argument against declared provider identity before
/// acquiring ownership. Resumed metadata is intentionally never read here.
fn configured_gate_preflight(
    args: &[String],
    providers: &ProvidersConfig,
) -> Result<Option<String>, String> {
    let gate = value_after(args, "--gate").or_else(|| std::env::var("ORBIT_GATE_URL").ok());
    let Some(gate) = gate else {
        return Ok(None);
    };
    let hint = value_after(args, "--provider");
    let model = value_after(args, "--model").or_else(|| std::env::var("ORBIT_MODEL").ok());
    let provider = if let Some(hint) = hint {
        Some(
            providers
                .provider
                .iter()
                .find(|provider| provider.name == hint)
                .ok_or("unknown selected provider")?,
        )
    } else if let Some(model) = model {
        let resolved = orbit_cli::resolve_selected_model(providers, &model, None, false)?;
        Some(
            providers
                .model_entry(&resolved.provider_id, &resolved.raw_model)
                .ok_or("model is not configured")?
                .0,
        )
    } else if value_after(args, "--resume").is_none() {
        if !providers.roles.main.is_empty() {
            Some(
                providers
                    .model_entry_for_spec(&providers.roles.main)
                    .ok_or("main model is not configured")?
                    .0,
            )
        } else {
            providers
                .provider
                .iter()
                .find(|provider| !provider.models.is_empty())
        }
    } else {
        None
    };
    if let Some(provider) = provider {
        if provider.url != gate {
            return Err("--gate must exactly match the selected provider URL".into());
        }
    } else if providers.provider.is_empty()
        || !providers
            .provider
            .iter()
            .all(|provider| provider.url == gate)
    {
        return Err("resumed --gate requires --provider to identify one exact configured URL before ownership".into());
    }
    Ok(Some(gate))
}
fn startup(args: &[String]) -> Result<(BridgeConfig, SessionLease, bool), String> {
    options(args)?;
    let home = orbit_cli::config::resolve_home(args);
    if !home.join("trust").exists() {
        return Err("not initialized; run `orbit init` first".into());
    }
    let bind = value_after(args, "--bind").unwrap_or_else(|| "127.0.0.1".into());
    let port = match value_after(args, "--port") {
        Some(port) => port.parse::<u16>().map_err(|_| "--port requires 0–65535")?,
        None => 4173,
    };
    let token = value_after(args, "--token").or_else(|| std::env::var("ORBIT_WEB_TOKEN").ok());
    if token.as_ref().is_some_and(|token| token.is_empty())
        || (!matches!(bind.as_str(), "127.0.0.1" | "localhost" | "::1") && token.is_none())
    {
        return Err("non-loopback --bind requires a nonempty --token (or ORBIT_WEB_TOKEN)".into());
    }
    let providers = ProvidersConfig::load(&home)?;
    let requested_gate = configured_gate_preflight(args, &providers)?;
    if let Some(spec) = value_after(args, "--model").or_else(|| std::env::var("ORBIT_MODEL").ok()) {
        orbit_cli::resolve_selected_model(
            &providers,
            &spec,
            value_after(args, "--provider").as_deref(),
            false,
        )?;
    }
    let (lease, saved): (_, Option<SessionFile>) = match value_after(args, "--resume") {
        Some(id) => {
            let (lease, saved) = SessionLease::acquire_and_load(&home, &id, "browser")
                .map_err(|error| error.to_string())?;
            (lease, Some(saved))
        }
        None => {
            let id = orbit_gateway::new_session_id();
            (
                SessionLease::acquire(&home, &id, "browser").map_err(|error| error.to_string())?,
                None,
            )
        }
    };
    let manual = value_after(args, "--model").or_else(|| std::env::var("ORBIT_MODEL").ok());
    let spec = manual
        .clone()
        .or_else(|| saved.as_ref().map(|saved| saved.model.clone()))
        .or_else(|| (!providers.roles.main.is_empty()).then(|| providers.roles.main.clone()))
        .or_else(|| {
            providers
                .all_models()
                .first()
                .map(|(provider, model)| format!("{provider}/{model}"))
        })
        .ok_or("no configured model; add a provider first")?;
    let hint = value_after(args, "--provider").or_else(|| {
        manual
            .is_none()
            .then(|| saved.as_ref().map(|saved| saved.provider.clone()))
            .flatten()
    });
    let resolved = orbit_cli::resolve_selected_model(
        &providers,
        &spec,
        hint.as_deref(),
        manual.is_none() && saved.is_some(),
    )?;
    if requested_gate
        .as_ref()
        .is_some_and(|gate| gate != &resolved.url)
    {
        return Err("--gate must exactly match the selected provider URL".into());
    }
    let (provider, model) = providers
        .model_entry(&resolved.provider_id, &resolved.raw_model)
        .ok_or("selected model disappeared from configuration")?;
    let selected_effort = value_after(args, "--effort")
        .or_else(|| std::env::var("ORBIT_EFFORT").ok())
        .map(|value| orbit_cli::parse_effort_setting(&value))
        .transpose()?;
    let effort = orbit_cli::sessions::startup_effort(
        selected_effort,
        saved.as_ref(),
        &model.id,
        &provider.name,
    );
    let mut checked = orbit_cli::try_engine_turn_config(
        &home,
        &provider.name,
        &provider.url,
        &model.id,
        provider.env.as_deref(),
        Some(model.pricing),
    )?;
    if let Some(choice) = &effort {
        orbit_cli::apply_effort_setting(&home, &mut checked, choice)?;
    }
    let mut scope = orbit_cli::tool_runtime::PermissionScope::default();
    if let Some(mode) = value_after(args, "--permission-mode") {
        scope.mode = orbit_tools::permissions::PermissionMode::from_config(&mode)
            .ok_or("unknown permission mode")?;
    }
    scope.allowlist = value_after(args, "--allowedTools").map(|value| {
        value
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string)
            .collect()
    });
    scope.disallowlist = value_after(args, "--disallowedTools")
        .map(|value| {
            value
                .split(',')
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    if args.iter().any(|argument| argument == "--bare") {
        orbit_cli::tools::enable_bare_mode();
    }
    let origin = orbit_cli::startup_selection_origin(
        value_after(args, "--model").is_some(),
        std::env::var("ORBIT_MODEL").is_ok(),
        saved.as_ref(),
        !providers.roles.main.is_empty(),
    );
    lease
        .save(
            &SessionFile::from_chat(
                lease.session_id(),
                &checked.model,
                &checked.gate,
                &checked.provider_id,
                &saved
                    .as_ref()
                    .map(SessionFile::to_transcript)
                    .unwrap_or_default(),
                saved.as_ref().map_or(0, |saved| saved.turns),
                saved.as_ref().map_or(0, |saved| saved.input_tokens),
                saved.as_ref().map_or(0, |saved| saved.output_tokens),
                saved.as_ref().map_or(0, |saved| saved.cost_microcents),
            )
            .with_effort(effort.clone())
            .with_selection_origin(origin),
        )
        .map_err(|error| error.to_string())?;
    let turn = TuiTurnConfig {
        home,
        session_id: lease.session_id().to_owned(),
        gate: checked.gate,
        model: model.id.clone(),
        provider_id: provider.name.clone(),
        effort,
        auto_tools: args.iter().any(|argument| argument == "--auto-tools"),
        scope,
        initial_transcript: saved
            .as_ref()
            .map(SessionFile::to_transcript)
            .unwrap_or_default(),
        initial_turns: saved.as_ref().map_or(0, |saved| saved.turns),
        initial_input_tokens: saved.as_ref().map_or(0, |saved| saved.input_tokens),
        initial_output_tokens: saved.as_ref().map_or(0, |saved| saved.output_tokens),
        initial_cost_microcents: saved.as_ref().map_or(0, |saved| saved.cost_microcents),
    };
    Ok((
        BridgeConfig {
            turn,
            bind,
            port,
            token,
        },
        lease,
        args.iter().any(|argument| argument == "--no-browser"),
    ))
}
fn main() {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    let (config, lease, no_browser) = match startup(&args) {
        Ok(startup) => startup,
        Err(error) => {
            eprintln!("ORBIT-E0400: {error}");
            std::process::exit(2);
        }
    };
    if !no_browser && config.port != 0 {
        let host = if config.bind.contains(':') {
            format!("[{}]", config.bind)
        } else {
            config.bind.clone()
        };
        let token = config
            .token
            .as_ref()
            .map(|token| format!("?token={}", percent_encode(token)))
            .unwrap_or_default();
        let _ = std::process::Command::new("xdg-open")
            .arg(format!("http://{host}:{}{token}", config.port))
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn();
    }
    let workspace = match std::env::current_dir() {
        Ok(path) => path,
        Err(error) => {
            eprintln!("ORBIT-E0400: {error}");
            std::process::exit(2)
        }
    };
    let host = orbit_cli::customization_host::host(
        &config.turn.home,
        &workspace,
        config.turn.scope.clone(),
        args.iter().any(|arg| arg == "--safe-customization"),
    );
    std::process::exit(run_bridge_owned_with_customization(config, lease, host));
}
fn percent_encode(value: &str) -> String {
    value
        .bytes()
        .map(|byte| {
            if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
                (byte as char).to_string()
            } else {
                format!("%{byte:02X}")
            }
        })
        .collect()
}

#[cfg(all(test, unix))]
mod browser_startup_tests {
    use super::*;
    use std::{fs, os::unix::fs::DirBuilderExt, path::PathBuf};
    struct Home(PathBuf);
    impl Home {
        fn new() -> Self {
            let root =
                std::env::temp_dir().join(format!("orbit-web-startup-{}", ulid::Ulid::new()));
            fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
            fs::create_dir(root.join("trust")).unwrap();
            fs::write(root.join("providers.toml"),"[[provider]]\nname=\"fixture\"\nurl=\"http://127.0.0.1:45678\"\n[[provider.models]]\nid=\"vendor/model-a\"\n").unwrap();
            Self(root)
        }
        fn args(&self, gate: &str) -> Vec<String> {
            vec![
                "--home".into(),
                self.0.display().to_string(),
                "--model".into(),
                "vendor/model-a".into(),
                "--gate".into(),
                gate.into(),
                "--no-browser".into(),
            ]
        }
    }
    impl Drop for Home {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    #[test]
    fn legacy_gate_same_provider_url_preserves_exact_raw_model() {
        let home = Home::new();
        let (config, lease, no_browser) = startup(&home.args("http://127.0.0.1:45678")).unwrap();
        assert_eq!(config.turn.gate, "http://127.0.0.1:45678");
        assert_eq!(config.turn.provider_id, "fixture");
        assert_eq!(config.turn.model, "vendor/model-a");
        assert_eq!(lease.session_id(), config.turn.session_id);
        assert!(no_browser);
    }
    #[test]
    fn legacy_gate_mismatch_refuses_before_creating_ownership_files() {
        let home = Home::new();
        let error = startup(&home.args("http://127.0.0.1:45679")).err().unwrap();
        assert!(error.contains("--gate must exactly match"));
        assert!(!home.0.join("sessions").exists());
    }
    #[test]
    fn legacy_gate_does_not_load_ambiguous_resume_before_ownership() {
        let home = Home::new();
        let mut providers = ProvidersConfig::load(&home.0).unwrap();
        let mut neighbor = providers.provider[0].clone();
        neighbor.name = "neighbor".into();
        neighbor.url = "http://127.0.0.1:45679".into();
        providers.provider.push(neighbor);
        let args = vec![
            "--resume".into(),
            "unopened-session".into(),
            "--gate".into(),
            "http://127.0.0.1:45678".into(),
        ];
        assert!(
            configured_gate_preflight(&args, &providers)
                .unwrap_err()
                .contains("requires --provider")
        );
        assert!(!home.0.join("sessions").exists());
    }
}
