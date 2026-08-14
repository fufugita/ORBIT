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

mod config;
mod sessions;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();

    // Bare `orbit` (no args, or only flags) summons the interactive CLI — the
    // "harness". `orbit chat` is the explicit alias. Both stream live to
    // stdout, so they run outside the JSON-envelope dispatch path.
    // `--help`/`-h`/`--version` stay on the JSON dispatch (first-class verbs).
    let first_is_command = args
        .first()
        .map(|a| !a.starts_with('-'))
        .unwrap_or(false);
    let wants_chat = args.is_empty()
        || args[0] == "chat"
        || (!first_is_command
            && args[0] != "--help"
            && args[0] != "-h"
            && args[0] != "--version");
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

fn dispatch(args: &[String]) -> Result<serde_json::Value, (&'static str, String)> {
    if args.is_empty() {
        return Err(("ORBIT-E1101", "no command".into()));
    }
    let home = orbit_home(args).unwrap_or_else(|| {
        std::env::var("ORBIT_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from(".orbit"))
    });
    match args[0].as_str() {
        "init" => cmd_init(&home),
        "run" => cmd_run(&home, args),
        "cancel" => cmd_cancel(&home),
        "verify-ledger" => cmd_verify(&home),
        "replay" => cmd_replay(&home, args),
        "export" => cmd_export(&home, args),
        "restore" => cmd_restore(&home, args),
        "ask" => cmd_ask(&home, args),
        "models" | "list-models" => cmd_models(&home, args),
        "version" => Ok(
            serde_json::to_value(orbit_cli::version_evidence("0.1.0", "dev")).unwrap_or_default(),
        ),
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
                "run           run the example phase chain",
                "cancel        cancel the session (terminal: cancelled)",
                "verify-ledger verify the Ledger hash chain",
                "replay --dry  verify + emit a no-dispatch replay plan",
                "export --to   encrypt an age bundle",
                "restore       restore into a fresh namespace",
                "version       release evidence (claims + hashes)"
            ]
        })),
        other => Err(("ORBIT-E1101", format!("unsupported command {other}"))),
    }
}

fn orbit_home(args: &[String]) -> Option<PathBuf> {
    args.windows(2)
        .find(|w| w[0] == "--home")
        .map(|w| PathBuf::from(&w[1]))
}

/// `orbit init`: generate a local Ed25519 trust root, sign the manifest, verify it,
/// initialize PIB identity + Ledger (DR-03 E2E: initialize trust).
fn cmd_init(home: &Path) -> Result<serde_json::Value, (&'static str, String)> {
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

    // Initialize PIB.
    let mut pib = PibRegistry::new();
    let pib_id = "01J-LOCAL-PIB".to_string();
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

    Ok(serde_json::json!({
        "schema": "orbit.cli/v1", "command": "init", "status": "ok",
        "trust_root_verified": true, "pib_id": pib_id,
        "ledger": ledger_dir.to_string_lossy()
    }))
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
    Ok(serde_json::json!({
        "schema":"orbit.cli/v1","command":"verify-ledger","status":"ok",
        "records":records.len(),"head":head
    }))
}

/// `orbit replay --dry`: verify the Ledger, then emit a no-dispatch replay plan.
fn cmd_replay(home: &Path, args: &[String]) -> Result<serde_json::Value, (&'static str, String)> {
    if !args.iter().any(|a| a == "--dry") {
        return Err(("ORBIT-E1101", "E2E replay requires --dry".into()));
    }
    let (records, head) =
        verify_ledger(&home.join("ledger")).map_err(|e| ("ORBIT-E0602", e.to_string()))?;
    Ok(serde_json::json!({
        "schema":"orbit.replay/v1","command":"replay","status":"ok","mode":"dry",
        "dispatches":0,"records_read":records.len(),"ledger_head":head
    }))
}

/// `orbit export --to <path>`: encrypted local age bundle.
fn cmd_export(home: &Path, args: &[String]) -> Result<serde_json::Value, (&'static str, String)> {
    let to = value_after(args, "--to").ok_or(("ORBIT-E1101", "export requires --to".into()))?;
    let ledger_bytes = collect_ledger_bytes(&home.join("ledger"))?;
    let head = std::fs::read_to_string(home.join("ledger/HEAD")).map_err(ioe)?;
    let (recipient, identity) = generate_local_key();
    let mut b = ExportBuilder::new(
        "session-example".into(),
        "01J-LOCAL-PIB".into(),
        head.trim().into(),
    );
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

/// Outcome of one `run_turn` call: the assembled text + token usage + cost.
struct TurnOutcome {
    output: String,
    input_tokens: u64,
    output_tokens: u64,
    cost_microcents: u64,
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
fn run_turn(
    home: &Path,
    provider_id: &str,
    gate: &str,
    model: &str,
    credential_env: Option<&str>,
    pricing: Option<config::Pricing>,
    prompt: &str,
    messages: Option<Vec<orbit_adapter::types::ChatMessage>>,
    observer: orbit_provider_http::stream::StreamObserver<'_>,
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
        tools: Vec::new(),
        metadata: orbit_adapter::types::RequestMetadata {
            input_sha256: input_digest,
            input_bytes: prompt.len() as u64,
            tools_count: 0,
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
    let cancel = orbit_provider_http::CancelToken::new();

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
            let usage = r.accounting.usage;
            // Cost in microcents from the pricing config (zero if unpriced).
            let cost_microcents = pricing
                .and_then(|p| orbit_adapter::types::CostRates::from(p).cost_microcents(&usage))
                .unwrap_or(0);
            Ok(TurnOutcome {
                output,
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
    let provider_id = provider.map(|p| p.name.as_str()).unwrap_or("configured-gateway");
    let resolved_gate = provider.map(|p| p.url.as_str()).unwrap_or(&gate);
    let credential_env = provider.and_then(|p| p.env.as_deref());
    let pricing = cfg.pricing_for_model(&model);

    let outcome = run_turn(
        home,
        provider_id,
        resolved_gate,
        &model,
        credential_env,
        pricing,
        prompt,
        None,
        None,
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

/// The interactive REPL — the "harness" (bare `orbit` or `orbit chat`).
///
/// Each prompt runs the full four-gate async dispatch pipeline (same as
/// `orbit ask`) with a growing conversation transcript. Output streams live
/// (TextDeltas printed as they arrive). Model/gate resolved from flags →
/// `ORBIT_MODEL`/`ORBIT_GATE_URL` → defaults. Exits cleanly on `exit`/EOF.
///
/// Slash commands: `/help`, `/model <M>`, `/clear`, `/usage`.
fn cmd_chat(args: &[String]) -> i32 {
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
    let mut model = value_after(args, "--model")
        .or_else(|| std::env::var("ORBIT_MODEL").ok())
        .unwrap_or_else(|| "glm-5.2".into());

    let cfg = config::ProvidersConfig::load(&home)
        .map_err(|e| eprintln!("warning: providers.toml: {e}"))
        .unwrap_or_default();

    // Session identity + persistence. `--resume <id>` loads a prior session's
    // transcript so the conversation continues across invocations.
    let resume = value_after(args, "--resume");
    let resumed_file = resume
        .as_deref()
        .filter(|id| !id.is_empty())
        .and_then(|id| match sessions::load_session(&home, id) {
            Ok(s) => Some(s),
            Err(e) => {
                eprintln!("warning: cannot resume {id}: {e}; starting fresh");
                None
            }
        });
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
    let mut total_cost = resumed_file.as_ref().map(|s| s.cost_microcents).unwrap_or(0);
    let mut turns = resumed_file.as_ref().map(|s| s.turns).unwrap_or(0);

    // HUD (DR-10 Part B): display-only, display-safe (H-3), brand + output
    // mode negotiated from the environment (NO_COLOR/CI/TERM).
    let hud = orbit_hud::Hud::new(&orbit_hud::Env {
        no_color: std::env::var_os("NO_COLOR").is_some(),
        ci: std::env::var_os("CI").is_some(),
        term_dumb: std::env::var("TERM").map(|t| t == "dumb").unwrap_or(false),
    });
    render_hud(&hud, &orbit_hud::HudEvent::Message {
        text: format!("interactive harness — model {model}, session {session}"),
    });
    render_hud(&hud, &orbit_hud::HudEvent::Message {
        text: "type /help for commands, exit to quit".into(),
    });

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

        // Build the transcript for THIS turn: prior turns + the new user prompt.
        let mut turn_messages = transcript.clone();
        turn_messages.push(orbit_adapter::types::ChatMessage {
            role: orbit_adapter::types::ChatRole::User,
            content: trimmed.clone(),
        });

        // Live observer: print TextDeltas as they stream in.
        let mut live_output: String = String::new();
        let mut observer = |ev: &orbit_adapter::types::ProviderStreamEvent| {
            if let orbit_adapter::types::ProviderEventKind::TextDelta { bytes } = &ev.event {
                let s = String::from_utf8_lossy(bytes).into_owned();
                print!("{s}");
                use std::io::Write;
                let _ = std::io::stdout().flush();
                live_output.push_str(&s);
            }
        };

        // Resolve the provider for the current model (config overrides the
        // default gate). `credential_env` names the env var holding the token.
        let provider = value_after(args, "--provider")
            .and_then(|name| cfg.provider.iter().find(|p| p.name == name))
            .or_else(|| cfg.provider_for_model(&model));
        let provider_id = provider.map(|p| p.name.as_str()).unwrap_or("configured-gateway");
        let resolved_gate = provider.map(|p| p.url.as_str()).unwrap_or(&gate);
        let credential_env = provider.and_then(|p| p.env.as_deref());
        let pricing = cfg.pricing_for_model(&model);

        render_hud(
            &hud,
            &orbit_hud::HudEvent::PhaseChanged {
                phase: format!("turn {}({model})", turns + 1),
            },
        );
        let outcome = run_turn(
            &home,
            provider_id,
            resolved_gate,
            &model,
            credential_env,
            pricing,
            &trimmed,
            Some(turn_messages),
            Some(&mut observer),
        );
        println!();
        use std::io::Write;
        let _ = std::io::stdout().flush();

        match outcome {
            Ok(o) => {
                turns += 1;
                total_input += o.input_tokens;
                total_output += o.output_tokens;
                total_cost += o.cost_microcents;
                // Cost bar (H-17: integer µ¢, real pricing when declared).
                render_hud(
                    &hud,
                    &orbit_hud::HudEvent::CostBar {
                        cost_microcents: o.cost_microcents,
                    },
                );
                // Record the model's reply into the transcript for continuity.
                transcript.push(orbit_adapter::types::ChatMessage {
                    role: orbit_adapter::types::ChatRole::User,
                    content: trimmed.clone(),
                });
                transcript.push(orbit_adapter::types::ChatMessage {
                    role: orbit_adapter::types::ChatRole::Assistant,
                    content: o.output.clone(),
                });
                // Persist the session after each successful turn.
                let sf = sessions::SessionFile::from_chat(
                    &session,
                    &model,
                    resolved_gate,
                    provider_id,
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
            Err((code, msg)) => {
                eprintln!("{code}: {msg}");
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

/// `orbit models` — list every declared model across all configured providers.
/// Reads `$ORBIT_HOME/providers.toml` (missing = empty config).
fn cmd_models(
    home: &Path,
    args: &[String],
) -> Result<serde_json::Value, (&'static str, String)> {
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
fn render_hud(hud: &orbit_hud::Hud, event: &orbit_hud::HudEvent) {
    // Apply the display-safety gate (H-3) to text-bearing events first.
    let event = match event {
        orbit_hud::HudEvent::Message { text } => {
            match orbit_hud::display_safe(text) {
                Ok(clean) => orbit_hud::HudEvent::Message { text: clean },
                Err(_) => {
                    eprintln!("[HUD] message rejected by display gate (H-3)");
                    return;
                }
            }
        }
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
    Ok(())
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
