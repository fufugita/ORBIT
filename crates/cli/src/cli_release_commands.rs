//! Strict, offline command adapters for setup, diagnostics and engagement workspaces.
use crate::{
    config, customization, doctor as diagnostics, pentest as engagement, setup as identity,
};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufRead, IsTerminal, Write};
use std::path::{Path, PathBuf};

pub type CommandResult = Result<Value, (&'static str, String)>;
fn invalid(message: impl Into<String>) -> (&'static str, String) {
    ("ORBIT-E1101", message.into())
}
fn storage(error: customization::Error) -> (&'static str, String) {
    ("ORBIT-E0501", error.to_string())
}
fn bounded(args: &[String]) -> Result<(), (&'static str, String)> {
    if args.len() > 128 || args.iter().map(String::len).sum::<usize>() > 64 * 1024 {
        return Err(invalid("command arguments exceed bounds"));
    }
    if args.iter().any(|a| a.contains('\0')) {
        return Err(invalid("command arguments contain NUL"));
    }
    Ok(())
}

#[derive(Debug, Clone, Default)]
pub struct SetupArguments {
    pub request: identity::SetupRequest,
    pub dry_run: bool,
    pub guided: bool,
    /// Main owns the existing discovery wizard. This module never launches it.
    pub interactive_provider: bool,
    pub repair: bool,
}

/// Parse the complete verb-tail before creating a home or reading guided input.
pub fn parse_setup(args: &[String]) -> Result<SetupArguments, (&'static str, String)> {
    bounded(args)?;
    let mut parsed = SetupArguments::default();
    let mut values = BTreeMap::new();
    let mut seen = BTreeSet::new();
    let mut no_provider = false;
    let mut index = 0;
    if args.first().is_some_and(|a| a == "repair") {
        parsed.repair = true;
        index = 1;
    }
    while index < args.len() {
        let flag = args[index].as_str();
        if !seen.insert(flag) {
            return Err(invalid(format!("duplicate option {flag}")));
        }
        match flag {
            "--json" => {}
            "--dry-run" => parsed.dry_run = true,
            "--guided" => parsed.guided = true,
            "--interactive-provider" => parsed.interactive_provider = true,
            "--no-provider" => no_provider = true,
            "--provider" | "--gate" | "--model" | "--credential-env" | "--kind"
            | "--route-easy" | "--route-hard" => {
                index += 1;
                let value = args
                    .get(index)
                    .filter(|v| !v.starts_with("--"))
                    .ok_or_else(|| invalid(format!("{flag} requires a value")))?;
                values.insert(flag, value.clone());
            }
            _ => return Err(invalid("unknown setup option; use setup --help")),
        }
        index += 1;
    }
    if parsed.repair {
        if !parsed.dry_run
            || parsed.guided
            || parsed.interactive_provider
            || no_provider
            || !values.is_empty()
        {
            return Err(invalid("usage: setup repair --dry-run [--json]"));
        }
        return Ok(parsed);
    }
    let provider_flags = [
        "--provider",
        "--gate",
        "--model",
        "--credential-env",
        "--kind",
    ];
    let has_provider = provider_flags.iter().any(|k| values.contains_key(k));
    if (no_provider && (has_provider || parsed.guided || parsed.interactive_provider))
        || (parsed.guided && (has_provider || parsed.interactive_provider))
        || (parsed.interactive_provider && has_provider)
    {
        return Err(invalid(
            "choose one of manual provider flags, --guided, --interactive-provider or --no-provider",
        ));
    }
    if parsed.dry_run && (parsed.guided || parsed.interactive_provider) {
        return Err(invalid(
            "--dry-run requires explicit offline provider flags",
        ));
    }
    if has_provider {
        let required = |flag| {
            values
                .get(flag)
                .cloned()
                .ok_or_else(|| invalid(format!("manual provider setup requires {flag}")))
        };
        let name = required("--provider")?;
        let url = required("--gate")?;
        let ids = required("--model")?;
        let models: Vec<_> = ids
            .split(',')
            .map(str::trim)
            .map(|id| {
                serde_json::from_value::<config::ModelEntry>(json!({"id":id}))
                    .map_err(|_| invalid("model declaration is invalid"))
            })
            .collect::<Result<_, _>>()?;
        let provider = config::ProviderConfig {
            name,
            kind: values
                .get("--kind")
                .cloned()
                .unwrap_or_else(|| "openai-compatible".into()),
            url,
            env: values.get("--credential-env").cloned(),
            models,
        };
        identity::validate_provider(&provider).map_err(storage)?;
        parsed.request.provider = Some(provider);
    }
    for (flag, key) in [("--route-easy", "easy"), ("--route-hard", "hard")] {
        if let Some(target) = values.get(flag) {
            if target.is_empty() || target.len() > 1024 || target.chars().any(char::is_control) {
                return Err(invalid("routing target is invalid"));
            }
            parsed.request.routing.insert(key.into(), target.clone());
        }
    }
    Ok(parsed)
}

fn prompt_line(
    reader: &mut impl BufRead,
    writer: &mut impl Write,
    label: &str,
) -> Result<String, (&'static str, String)> {
    write!(writer, "{label}")
        .and_then(|_| writer.flush())
        .map_err(|_| invalid("cannot write setup prompt"))?;
    let mut bytes = Vec::new();
    std::io::Read::take(&mut *reader, 4097)
        .read_until(b'\n', &mut bytes)
        .map_err(|_| invalid("cannot read setup input"))?;
    if bytes.len() > 4096 {
        return Err(invalid("setup input exceeds 4096 bytes"));
    }
    let value = String::from_utf8(bytes).map_err(|_| invalid("setup input is not UTF-8"))?;
    let value = value.trim().to_string();
    if value.chars().any(char::is_control) {
        return Err(invalid("setup input contains control characters"));
    }
    Ok(value)
}

/// Manual guided input is offline; credentials are requested only by ENV name.
pub fn guided_request(
    reader: &mut impl BufRead,
    writer: &mut impl Write,
) -> Result<identity::SetupRequest, (&'static str, String)> {
    writeln!(writer, "Offline setup. Enter model IDs manually; no discovery or provider request is sent.\nCredentials stay in your environment. Leave provider name empty to initialize identity only.")
        .map_err(|_| invalid("cannot write setup guidance"))?;
    let name = prompt_line(reader, writer, "Provider name: ")?;
    if name.is_empty() {
        return Ok(identity::SetupRequest::default());
    }
    let gate = prompt_line(reader, writer, "Absolute provider URL (http/https): ")?;
    let kind = prompt_line(
        reader,
        writer,
        "Adapter [openai-compatible / anthropic / ollama] (default openai-compatible): ",
    )?;
    let models = prompt_line(reader, writer, "Model IDs, comma separated: ")?;
    let env = prompt_line(
        reader,
        writer,
        "Credential ENV name (optional; never enter the credential value): ",
    )?;
    let mut flags = vec![
        "--provider".into(),
        name,
        "--gate".into(),
        gate,
        "--model".into(),
        models,
    ];
    if !kind.is_empty() {
        flags.extend(["--kind".into(), kind]);
    }
    if !env.is_empty() {
        flags.extend(["--credential-env".into(), env]);
    }
    Ok(parse_setup(&flags)?.request)
}

fn setup_as(home: &Path, args: &[String], command: &str) -> CommandResult {
    let mut parsed = parse_setup(args)?;
    if parsed.repair {
        return Ok(
            json!({"schema":"orbit.cli/v1","command":"setup repair","status":"dry_run","report":identity::repair_dry_run(home).map_err(storage)?}),
        );
    }
    if parsed.guided {
        if !std::io::stdin().is_terminal() {
            return Err(invalid(
                "--guided requires a terminal; use explicit provider flags for automation",
            ));
        }
        parsed.request.provider =
            guided_request(&mut std::io::stdin().lock(), &mut std::io::stderr().lock())?.provider;
    }
    let plan = identity::plan_setup(home, &parsed.request).map_err(storage)?;
    if parsed.dry_run {
        return Ok(
            json!({"schema":"orbit.cli/v1","command":command,"status":"dry_run","plan":plan,"offline":true}),
        );
    }
    let receipt = identity::apply_setup(&plan).map_err(storage)?;
    let mut value =
        serde_json::to_value(receipt).map_err(|_| invalid("cannot encode setup receipt"))?;
    let fields = value
        .as_object_mut()
        .ok_or_else(|| invalid("setup receipt is invalid"))?;
    fields.extend([
        ("schema".into(), json!("orbit.cli/v1")),
        ("command".into(), json!(command)),
        ("status".into(), json!("ok")),
        (
            "ledger".into(),
            json!(home.join("ledger").to_string_lossy()),
        ),
        ("offline".into(), json!(true)),
    ]);
    Ok(value)
}
pub fn setup(home: &Path, args: &[String]) -> CommandResult {
    setup_as(home, args, "setup")
}
pub fn init(home: &Path, args: &[String]) -> CommandResult {
    setup_as(home, args, "init")
}

fn checked_workspace(value: &str) -> Result<PathBuf, (&'static str, String)> {
    if value.is_empty() || value.len() > 256 || value.chars().any(char::is_control) {
        return Err(invalid(
            "workspace path must contain 1..256 printable bytes",
        ));
    }
    let path = PathBuf::from(value);
    if path.components().any(|c| {
        matches!(
            c,
            std::path::Component::ParentDir | std::path::Component::Prefix(_)
        )
    }) {
        return Err(invalid("workspace path must not contain parent traversal"));
    }
    let path = if path.is_absolute() {
        path
    } else {
        std::env::current_dir()
            .map_err(|_| invalid("cannot determine workspace"))?
            .join(path)
    };
    let normalized: PathBuf = path
        .components()
        .filter(|c| !matches!(c, std::path::Component::CurDir))
        .collect();
    if normalized.as_os_str().len() > 256 {
        return Err(invalid("resolved workspace path exceeds 256 bytes"));
    }
    Ok(normalized)
}
pub fn doctor(home: &Path, args: &[String]) -> CommandResult {
    bounded(args)?;
    let mut seen = BTreeSet::new();
    let mut workspace =
        std::env::current_dir().map_err(|_| invalid("cannot determine workspace"))?;
    let mut index = 0;
    while index < args.len() {
        let flag = args[index].as_str();
        if !seen.insert(flag) {
            return Err(invalid("duplicate doctor option"));
        }
        match flag {
            "--json" => {}
            "--workspace" => {
                index += 1;
                workspace = checked_workspace(
                    args.get(index)
                        .filter(|v| !v.starts_with("--"))
                        .ok_or_else(|| invalid("--workspace requires DIR"))?,
                )?;
            }
            _ => return Err(invalid("usage: doctor [--workspace DIR] [--json]")),
        }
        index += 1;
    }
    Ok(
        json!({"schema":"orbit.cli/v1","command":"doctor","report":diagnostics::doctor(home, &workspace)}),
    )
}

pub fn pentest(home: &Path, args: &[String]) -> CommandResult {
    bounded(args)?;
    let words: Vec<_> = args.iter().filter(|a| a.as_str() != "--json").collect();
    if args.iter().filter(|a| a.as_str() == "--json").count() > 1 {
        return Err(invalid("duplicate --json option"));
    }
    let verb = words
        .first()
        .map(|s| s.as_str())
        .ok_or_else(|| invalid("usage: pentest init|status|templates|readiness"))?;
    if verb == "templates" {
        if words.len() != 1 {
            return Err(invalid("usage: pentest templates [--json]"));
        }
        return Ok(
            json!({"schema":"orbit.cli/v1","command":"pentest templates","templates":engagement::templates().into_iter().map(|(id,title)| json!({"id":id,"title":title})).collect::<Vec<_>>() }),
        );
    }
    if !["init", "status", "readiness"].contains(&verb) {
        return Err(invalid("unknown pentest command"));
    }
    let path = checked_workspace(
        words
            .get(1)
            .filter(|s| !s.starts_with("--"))
            .ok_or_else(|| invalid("pentest command requires DIR"))?,
    )?;
    if verb != "init" {
        if words.len() != 2 {
            return Err(invalid("unexpected pentest command argument"));
        }
        return if verb == "status" {
            Ok(
                json!({"schema":"orbit.cli/v1","command":"pentest status","report":engagement::status(home,&path).map_err(storage)?}),
            )
        } else {
            Ok(
                json!({"schema":"orbit.cli/v1","command":"pentest readiness","report":engagement::readiness(home,&path)}),
            )
        };
    }
    let mut options = engagement::ScaffoldOptions::default();
    let mut seen = BTreeSet::new();
    let mut index = 2;
    while index < words.len() {
        let flag = words[index].as_str();
        if !seen.insert(flag) {
            return Err(invalid("duplicate pentest option"));
        }
        match flag {
            "--dry-run" => options.dry_run = true,
            "--profile" | "--name" => {
                index += 1;
                let value = words
                    .get(index)
                    .filter(|s| !s.starts_with("--"))
                    .ok_or_else(|| invalid("pentest option requires a value"))?;
                if flag == "--profile" {
                    options.profile = (*value).clone();
                } else {
                    options.name = Some((*value).clone());
                }
            }
            _ => {
                return Err(invalid(
                    "usage: pentest init DIR [--profile standard] [--name NAME] [--dry-run] [--json]",
                ));
            }
        }
        index += 1;
    }
    Ok(
        json!({"schema":"orbit.cli/v1","command":"pentest init","report":engagement::scaffold(&path,&options).map_err(storage)?}),
    )
}

/// Main prints this for the new human command forms; init retains its JSON compatibility.
pub fn human_report(value: &Value) -> String {
    let command = value
        .get("command")
        .and_then(Value::as_str)
        .unwrap_or("orbit");
    let mut out = format!("{command}\n");
    if let Some(checks) = value.pointer("/report/checks").and_then(Value::as_array) {
        out.push_str(
            if value.pointer("/report/ready").and_then(Value::as_bool) == Some(true) {
                "Ready for a configured local session. Provider connectivity remains untested.\n"
            } else {
                "Needs attention before use. No provider or configured server was contacted.\n"
            },
        );
        for check in checks {
            out.push_str(&format!(
                "{}: {} — {}\n",
                check["id"].as_str().unwrap_or("check"),
                check["status"].as_str().unwrap_or("unknown"),
                check["detail"].as_str().unwrap_or("")
            ));
        }
    } else if let Some(templates) = value.get("templates").and_then(Value::as_array) {
        for template in templates {
            out.push_str(&format!(
                "{}: {}\n",
                template["id"].as_str().unwrap_or(""),
                template["title"].as_str().unwrap_or("")
            ));
        }
    } else if value.pointer("/report/scope_valid").is_some() {
        out.push_str(
            if value.pointer("/report/exists").and_then(Value::as_bool) == Some(true) {
                "Local engagement workspace exists.\n"
            } else {
                "Engagement workspace is missing.\n"
            },
        );
        out.push_str(&format!(
            "Scope document: {}\nPortable profile: {}\n",
            if value
                .pointer("/report/scope_valid")
                .and_then(Value::as_bool)
                == Some(true)
            {
                "valid"
            } else {
                "missing or invalid"
            },
            if value
                .pointer("/report/profile_valid")
                .and_then(Value::as_bool)
                == Some(true)
            {
                "valid"
            } else {
                "missing or invalid"
            }
        ));
        for kind in ["evidence", "findings"] {
            let count = value
                .pointer(&format!("/report/{kind}/files"))
                .and_then(Value::as_u64)
                .unwrap_or(0);
            let state = if value
                .pointer(&format!("/report/{kind}/missing"))
                .and_then(Value::as_bool)
                == Some(true)
            {
                "missing directory"
            } else if value
                .pointer(&format!("/report/{kind}/truncated"))
                .and_then(Value::as_bool)
                == Some(true)
            {
                "bounded count; truncated"
            } else {
                "local inventory"
            };
            out.push_str(&format!("{kind}: {count} files ({state})\n"));
        }
        out.push_str("Counts are inventory, not verified findings. Folder trust and global profile remain explicit choices.\n");
    } else if let Some(actions) = value.pointer("/plan/actions").and_then(Value::as_array) {
        out.push_str("Dry run; no files changed. Planned actions:\n");
        for action in actions {
            out.push_str(&format!("- {}\n", action.as_str().unwrap_or("")));
        }
        if actions.is_empty() {
            out.push_str("Existing identity and configuration already match.\n");
        }
    } else if let Some(missing) = value.pointer("/report/missing").and_then(Value::as_array) {
        out.push_str("Repair dry run; no files changed. Identity is never regenerated.\n");
        for item in missing {
            out.push_str(&format!("Missing: {}\n", item.as_str().unwrap_or("")));
        }
        if missing.is_empty() {
            out.push_str("No identity artifacts are missing.\n");
        }
    } else if let Some(guidance) = value.pointer("/report/guidance").and_then(Value::as_str) {
        out.push_str(guidance);
        out.push('\n');
        for key in ["created", "preserved", "conflicts"] {
            if let Some(items) = value
                .pointer(&format!("/report/{key}"))
                .and_then(Value::as_array)
            {
                out.push_str(&format!("{key}: {}\n", items.len()));
            }
        }
    } else if value.get("pib_id").is_some() {
        out.push_str(
            if value.get("initialized").and_then(Value::as_bool) == Some(true) {
                "Local identity initialized.\n"
            } else {
                "Existing local identity preserved.\n"
            },
        );
        out.push_str("Offline setup complete. Add explicit provider models with setup --provider NAME --gate URL --model ID --credential-env ENV_NAME. Run doctor to inspect readiness.\n");
    } else {
        out.push_str(&serde_json::to_string_pretty(value).unwrap_or_default());
        out.push('\n');
    }
    out
}
