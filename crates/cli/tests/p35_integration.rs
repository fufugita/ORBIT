use orbit_cli::tool_runtime::{PermissionScope, permission_command};
use std::path::PathBuf;

struct PolicyFixture {
    root: PathBuf,
    home: PathBuf,
    work: PathBuf,
}
impl PolicyFixture {
    fn new() -> Self {
        let root =
            std::env::temp_dir().join(format!("orbit-p35-integration-{}", ulid::Ulid::new()));
        let home = root.join("home");
        let work = root.join("workspace");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::create_dir_all(&work).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for path in [&root, &home, &work] {
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
            }
        }
        std::fs::write(
            home.join("mcp.json"),
            r#"{"servers":{"browser__local":{"command":"unused-fixture","tools":["snapshot"]}}}"#,
        )
        .unwrap();
        Self { root, home, work }
    }
    fn command(&self, args: &str) -> Result<String, String> {
        permission_command(&self.home, &PermissionScope::default(), &self.work, args)
    }
}
impl Drop for PolicyFixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

struct Refuse {
    asked: usize,
    auto_hint: bool,
}
impl orbit_cli::tool_runtime::ApprovalChannel for Refuse {
    fn ask(
        &mut self,
        _: &orbit_cli::tool_runtime::ApprovalRequest,
        auto: bool,
    ) -> orbit_cli::tool_runtime::ApprovalVerdict {
        self.asked += 1;
        self.auto_hint |= auto;
        if auto {
            orbit_cli::tool_runtime::ApprovalVerdict::AllowOnce
        } else {
            orbit_cli::tool_runtime::ApprovalVerdict::Deny
        }
    }
}

fn run_calculator(
    f: &PolicyFixture,
    scope: &PermissionScope,
    answer: &mut Refuse,
) -> serde_json::Value {
    let cx = orbit_tools::ToolContext::new(f.home.clone(), "calculator".into(), f.work.clone());
    run_tool(
        f,
        scope,
        answer,
        &cx,
        "calculator",
        serde_json::json!({"expression":"1+1"}),
    )
}

fn run_tool(
    f: &PolicyFixture,
    scope: &PermissionScope,
    answer: &mut Refuse,
    cx: &orbit_tools::ToolContext,
    name: &str,
    arguments: serde_json::Value,
) -> serde_json::Value {
    let call = orbit_cli::PendingToolCall {
        index: 0,
        id: ulid::Ulid::new().to_string(),
        name: name.into(),
        arguments: serde_json::to_vec(&arguments).unwrap(),
    };
    let mut grants = orbit_cli::tool_runtime::AutoGrants::new();
    grants.grant(name);
    let (output, _) = orbit_cli::tool_runtime::execute_call(
        &f.home,
        "calculator",
        "decision",
        &call,
        true,
        true,
        answer,
        &mut grants,
        scope,
        cx,
    )
    .unwrap();
    serde_json::from_str(&output).unwrap()
}

#[cfg(unix)]
fn configure_lsp(f: &PolicyFixture) -> (orbit_tools::ToolContext, PathBuf) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&f.home, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::remove_file(f.home.join("mcp.json")).unwrap();
    std::fs::write(f.work.join("file.rs"), "fn main() {}\n").unwrap();
    let script =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../scripts/fixtures/p35_lsp_server.py");
    let log = f.root.join("frames.jsonl");
    std::fs::write(f.home.join("lsp.toml"), format!(
        "enabled=true\n[[servers]]\nname='fixture'\ncommand='python3'\nargs=[{:?},'pull',{:?}]\nlanguage_id='rust'\nextensions=['rs']\nworkspace_root={:?}\ntimeout_ms=1000\n",
        script.to_string_lossy(), log.to_string_lossy(), f.work.to_string_lossy(),
    )).unwrap();
    std::fs::set_permissions(
        f.home.join("lsp.toml"),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    (
        orbit_tools::ToolContext::new(f.home.clone(), "lsp".into(), f.work.clone()),
        log,
    )
}

#[cfg(unix)]
#[test]
fn integration_lsp_enabled_catalog_is_available_without_launch() {
    let f = PolicyFixture::new();
    let (cx, log) = configure_lsp(&f);
    let definitions = orbit_cli::tools::session_tool_definitions_with_context(&f.home, &cx, None);
    assert_eq!(
        definitions
            .iter()
            .filter(|tool| tool.name == "LspDiagnostics")
            .count(),
        1
    );
    assert!(!log.exists());
    std::fs::remove_file(f.home.join("lsp.toml")).unwrap();
    let definitions = orbit_cli::tools::session_tool_definitions_with_context(&f.home, &cx, None);
    assert!(!definitions.iter().any(|tool| tool.name == "LspDiagnostics"));
    assert!(!log.exists());
}

#[cfg(unix)]
#[test]
fn integration_lsp_shared_dispatch_reports_actual_diagnostics_and_ledger_result() {
    let f = PolicyFixture::new();
    let (cx, log) = configure_lsp(&f);
    let mut answer = Refuse {
        asked: 0,
        auto_hint: false,
    };
    let output = run_tool(
        &f,
        &PermissionScope::default(),
        &mut answer,
        &cx,
        "LspDiagnostics",
        serde_json::json!({"file_path":"file.rs"}),
    );
    assert_eq!(output["ok"], true, "{output}");
    assert_eq!(output["result"]["status"], "received");
    assert_eq!(output["result"]["diagnostics"][0]["message"], "pull issue");
    let frames = std::fs::read_to_string(log).unwrap();
    assert!(frames.contains("textDocument/didOpen") && frames.contains("textDocument/diagnostic"));
    assert_eq!(answer.asked, 0);
    let (records, _) = orbit_ledger::verify_ledger(&f.home.join("ledger")).unwrap();
    let result = records
        .iter()
        .find_map(|record| match &record.record.event {
            orbit_ledger::LedgerEvent::ToolResult(result)
                if result.tool_name == "LspDiagnostics" =>
            {
                Some(result)
            }
            _ => None,
        })
        .unwrap();
    let encoded = output.to_string();
    use sha2::Digest;
    assert_eq!(result.status, "ok");
    assert_eq!(result.output_bytes, encoded.len() as u64);
    assert_eq!(
        result.output_sha256,
        hex::encode(sha2::Sha256::digest(encoded.as_bytes()))
    );
}

#[cfg(unix)]
#[test]
fn integration_lsp_bypass_query_preserves_unconditional_diagnostics_and_read_denials() {
    for tool in ["LspDiagnostics", "Read"] {
        let f = PolicyFixture::new();
        let (cx, log) = configure_lsp(&f);
        f.command(&format!("deny {tool}")).unwrap();
        let scope = PermissionScope {
            mode: orbit_tools::permissions::PermissionMode::Bypass,
            ..Default::default()
        };
        let report = permission_command(&f.home, &scope, &f.work, "LspDiagnostics").unwrap();
        assert!(
            report.contains("LspDiagnostics: Deny") && report.contains("operator-override"),
            "{tool}: {report}"
        );
        let mut answer = Refuse {
            asked: 0,
            auto_hint: false,
        };
        let output = run_tool(
            &f,
            &scope,
            &mut answer,
            &cx,
            "LspDiagnostics",
            serde_json::json!({"file_path":"file.rs"}),
        );
        assert_eq!(output["ok"], false, "{tool}: {output}");
        assert_eq!(answer.asked, 0);
        assert!(!log.exists());
    }
}

#[cfg(unix)]
#[test]
fn integration_lsp_universal_patterns_match_query_and_actual_confirmation() {
    for effect in ["deny", "ask"] {
        let f = PolicyFixture::new();
        let (cx, log) = configure_lsp(&f);
        std::fs::write(
            f.home.join("settings.toml"),
            format!("[permissions]\n{effect}=[\"LspDiagnostics(*)\"]\n"),
        )
        .unwrap();
        let scope = PermissionScope {
            mode: if effect == "deny" {
                orbit_tools::permissions::PermissionMode::Bypass
            } else {
                orbit_tools::permissions::PermissionMode::Default
            },
            ..Default::default()
        };
        let report = permission_command(&f.home, &scope, &f.work, "LspDiagnostics").unwrap();
        let expected = if effect == "deny" { "Deny" } else { "Ask" };
        assert!(
            report.contains(&format!("LspDiagnostics: {expected}")),
            "{report}"
        );
        let mut answer = Refuse {
            asked: 0,
            auto_hint: false,
        };
        let output = run_tool(
            &f,
            &scope,
            &mut answer,
            &cx,
            "LspDiagnostics",
            serde_json::json!({"file_path":"file.rs"}),
        );
        assert_eq!(output["ok"], false, "{output}");
        assert_eq!(answer.asked, usize::from(effect == "ask"));
        assert!(!answer.auto_hint && !log.exists());
    }
}

#[cfg(unix)]
#[test]
fn integration_lsp_inherited_read_denial_prevents_document_and_server_launch() {
    let f = PolicyFixture::new();
    let (cx, log) = configure_lsp(&f);
    let scope = PermissionScope {
        disallowlist: vec!["Read(file.rs)".into()],
        ..Default::default()
    };
    let mut answer = Refuse {
        asked: 0,
        auto_hint: false,
    };
    let output = run_tool(
        &f,
        &scope,
        &mut answer,
        &cx,
        "LspDiagnostics",
        serde_json::json!({"file_path":"file.rs"}),
    );
    assert_eq!(output["ok"], false, "{output}");
    assert_eq!(output["denied"], true);
    assert!(!log.exists());
}

#[cfg(unix)]
#[test]
fn integration_lsp_explicit_confirmation_precedes_any_launch() {
    let f = PolicyFixture::new();
    let (cx, log) = configure_lsp(&f);
    f.command("ask LspDiagnostics").unwrap();
    let mut answer = Refuse {
        asked: 0,
        auto_hint: false,
    };
    let output = run_tool(
        &f,
        &PermissionScope::default(),
        &mut answer,
        &cx,
        "LspDiagnostics",
        serde_json::json!({"file_path":"file.rs"}),
    );
    assert_eq!(output["ok"], false, "{output}");
    assert_eq!(answer.asked, 1);
    assert!(!answer.auto_hint && !log.exists());
}

#[cfg(unix)]
#[test]
fn integration_lsp_child_profile_cannot_widen_parent_exclusion() {
    let f = PolicyFixture::new();
    let (parent, log) = configure_lsp(&f);
    let child = orbit_tools::ToolContext::new(f.home.clone(), "child".into(), f.work.clone());
    orbit_cli::tool_runtime::set_lsp_tool_selection(&child, &parent, &["Read".into()]);
    let grandchild =
        orbit_tools::ToolContext::new(f.home.clone(), "grandchild".into(), f.work.clone());
    orbit_cli::tool_runtime::set_lsp_tool_selection(
        &grandchild,
        &child,
        &["LspDiagnostics".into()],
    );
    assert!(
        !orbit_cli::tools::session_tool_definitions_with_context(&f.home, &grandchild, None)
            .iter()
            .any(|tool| tool.name == "LspDiagnostics")
    );
    let mut answer = Refuse {
        asked: 0,
        auto_hint: false,
    };
    let output = run_tool(
        &f,
        &PermissionScope::default(),
        &mut answer,
        &grandchild,
        "LspDiagnostics",
        serde_json::json!({"file_path":"file.rs"}),
    );
    assert_eq!(output["ok"], false, "{output}");
    assert_eq!(answer.asked, 0);
    assert!(!log.exists());
}

#[cfg(unix)]
#[test]
fn integration_lsp_cancelled_context_never_launches() {
    let f = PolicyFixture::new();
    let (cx, log) = configure_lsp(&f);
    cx.push_cancel_check(std::sync::Arc::new(|| true));
    let mut answer = Refuse {
        asked: 0,
        auto_hint: false,
    };
    let output = run_tool(
        &f,
        &PermissionScope::default(),
        &mut answer,
        &cx,
        "LspDiagnostics",
        serde_json::json!({"file_path":"file.rs"}),
    );
    assert_eq!(output["ok"], false, "{output}");
    assert!(!log.exists());
}

#[test]
fn frontend_policy_builtin_deny_overrides_auto_tools_and_session_grants() {
    let f = PolicyFixture::new();
    assert!(
        f.command("deny calculator")
            .unwrap()
            .contains("calculator: Deny")
    );
    let mut answer = Refuse {
        asked: 0,
        auto_hint: false,
    };
    let output = run_calculator(&f, &PermissionScope::default(), &mut answer);
    assert_eq!(output["ok"], false, "{output}");
    assert_eq!(answer.asked, 0);
    assert!(
        f.command("reset calculator")
            .unwrap()
            .contains("calculator: Allow")
    );
    let output = run_calculator(&f, &PermissionScope::default(), &mut answer);
    assert_eq!(output["ok"], true, "{output}");
    assert_eq!(output["result"]["result"], 2.0);
}

#[test]
fn frontend_policy_builtin_ask_requires_confirmation_despite_convenience_grants() {
    let f = PolicyFixture::new();
    assert!(
        f.command("ask calculator")
            .unwrap()
            .contains("calculator: Ask")
    );
    let mut answer = Refuse {
        asked: 0,
        auto_hint: false,
    };
    let output = run_calculator(&f, &PermissionScope::default(), &mut answer);
    assert_eq!(output["ok"], false, "{output}");
    assert_eq!(answer.asked, 1);
    assert!(!answer.auto_hint);
    let scope = PermissionScope {
        mode: orbit_tools::permissions::PermissionMode::DontAsk,
        ..Default::default()
    };
    assert!(
        permission_command(&f.home, &scope, &f.work, "calculator")
            .unwrap()
            .contains("calculator: Deny")
    );
    let output = run_calculator(&f, &scope, &mut answer);
    assert_eq!(output["ok"], false, "{output}");
    assert_eq!(answer.asked, 1);
}

#[test]
fn frontend_policy_builtin_scope_exclusion_refuses_even_with_auto_tools() {
    let f = PolicyFixture::new();
    let scope = PermissionScope {
        allowlist: Some(vec!["Read".into()]),
        ..Default::default()
    };
    assert!(
        permission_command(&f.home, &scope, &f.work, "calculator")
            .unwrap()
            .contains("calculator: Deny")
    );
    let mut answer = Refuse {
        asked: 0,
        auto_hint: false,
    };
    let output = run_calculator(&f, &scope, &mut answer);
    assert_eq!(output["ok"], false, "{output}");
    assert_eq!(answer.asked, 0);
}

#[test]
fn frontend_policy_builtin_universal_patterns_match_report_and_dispatch() {
    let f = PolicyFixture::new();
    let mut answer = Refuse {
        asked: 0,
        auto_hint: false,
    };
    let scope = PermissionScope {
        allowlist: Some(vec!["calculator(*)".into()]),
        ..Default::default()
    };
    let report = permission_command(&f.home, &scope, &f.work, "calculator").unwrap();
    assert!(
        report.contains("calculator: Allow") && report.contains("operator-allowlist"),
        "{report}"
    );
    assert_eq!(run_calculator(&f, &scope, &mut answer)["ok"], true);
    std::fs::write(
        f.home.join("settings.toml"),
        "[permissions]\ndeny=[\"calculator(*)\"]\n",
    )
    .unwrap();
    let report = permission_command(&f.home, &scope, &f.work, "calculator").unwrap();
    assert!(report.contains("calculator: Deny"), "{report}");
    assert_eq!(run_calculator(&f, &scope, &mut answer)["ok"], false);
    assert_eq!(answer.asked, 0);
}

fn discovery_fixture(f: &PolicyFixture, ambiguous: bool) -> (String, String, PathBuf) {
    let script = f.home.join("discovery.py");
    let log = f.home.join("discovery.log");
    std::fs::write(&script, r#"
import json,sys
tool,log=sys.argv[1:]
with open(log,'a') as capture: capture.write('spawn '+tool+'\n')
for line in sys.stdin:
    msg=json.loads(line)
    if 'id' not in msg: continue
    method=msg.get('method')
    if method=='initialize': result={'protocolVersion':'2025-06-18','capabilities':{'tools':{}},'serverInfo':{'name':'fixture','version':'1'}}
    elif method=='tools/list':
        with open(log,'a') as capture: capture.write('tools/list '+tool+'\n')
        result={'tools':[{'name':tool,'description':tool,'inputSchema':{'type':'object'}}]}
    elif method=='ping': result={}
    else: result={}
    print(json.dumps({'jsonrpc':'2.0','id':msg['id'],'result':result}),flush=True)
"#).unwrap();
    let base = format!("fixture{}", ulid::Ulid::new());
    let separator = format!("{base}__b");
    let wire = format!("mcp__{separator}__c");
    let second_tool = if ambiguous { "b__c" } else { "neighbor" };
    let server = |tool: &str| {
        serde_json::json!({
            "command":"python3", "args":["-u",script.to_string_lossy(),tool,log.to_string_lossy()],
            "enabled":true,"tools":[tool],"timeout_ms":1000,
        })
    };
    std::fs::write(
        f.home.join("mcp.json"),
        serde_json::json!({"servers":{
            (&separator):server("c"), (&base):server(second_tool),
        }})
        .to_string(),
    )
    .unwrap();
    (wire, separator, log)
}

#[test]
fn catalog_ambiguous_unrestricted_discovery_omits_duplicate_wire_definitions() {
    let f = PolicyFixture::new();
    let (wire, _, log) = discovery_fixture(&f, true);
    let cx = orbit_tools::ToolContext::new(f.home.clone(), "catalog".into(), f.work.clone());
    let definitions = orbit_cli::tools::session_tool_definitions_with_context(&f.home, &cx, None);
    assert!(!definitions.iter().any(|definition| definition.name == wire));
    let recorded = std::fs::read_to_string(log).unwrap();
    assert_eq!(
        recorded
            .lines()
            .filter(|line| line.starts_with("tools/list"))
            .count(),
        2
    );
    let names: std::collections::HashSet<_> = definitions
        .iter()
        .map(|definition| &definition.name)
        .collect();
    assert_eq!(names.len(), definitions.len());
}

#[test]
fn catalog_ambiguous_profile_selection_refuses_before_server_launch() {
    let f = PolicyFixture::new();
    let (wire, _, log) = discovery_fixture(&f, true);
    let cx = orbit_tools::ToolContext::new(f.home.clone(), "catalog".into(), f.work.clone());
    let definitions = orbit_cli::tools::session_tool_definitions_with_context(
        &f.home,
        &cx,
        Some(std::slice::from_ref(&wire)),
    );
    assert!(!definitions.iter().any(|definition| definition.name == wire));
    assert!(!log.exists());
}

#[test]
fn catalog_exact_separator_profile_discovers_only_its_configured_server() {
    let f = PolicyFixture::new();
    let (wire, separator, log) = discovery_fixture(&f, false);
    let cx = orbit_tools::ToolContext::new(f.home.clone(), "catalog".into(), f.work.clone());
    let definitions = orbit_cli::tools::session_tool_definitions_with_context(
        &f.home,
        &cx,
        Some(std::slice::from_ref(&wire)),
    );
    let matching: Vec<_> = definitions
        .iter()
        .filter(|definition| definition.name == wire)
        .collect();
    assert_eq!(matching.len(), 1);
    assert!(
        matching[0]
            .description
            .contains(&format!("mcp: {separator}"))
    );
    assert_eq!(
        std::fs::read_to_string(log).unwrap(),
        "spawn c\ntools/list c\n"
    );
}

#[test]
fn frontend_policy_uncovered_query_does_not_mutate_disk() {
    let f = PolicyFixture::new();
    let text = f.command("mcp__browser__local__snapshot").unwrap();
    assert!(text.contains("Ask"), "{text}");
    assert!(!f.home.join("permission-overrides.toml").exists());
}

#[test]
fn frontend_policy_uncovered_builtin_modes_match_canonical_evaluation() {
    use orbit_tools::permissions::{PermissionMode, RuleSet, Verdict, evaluate};
    let f = PolicyFixture::new();
    for mode in [
        PermissionMode::Default,
        PermissionMode::AcceptEdits,
        PermissionMode::Plan,
        PermissionMode::DontAsk,
        PermissionMode::Bypass,
    ] {
        let scope = PermissionScope {
            mode,
            ..Default::default()
        };
        for tool in ["Read", "Write", "Edit", "Bash", "TaskList", "WebFetch"] {
            let expected = match evaluate(
                mode,
                &RuleSet::default(),
                tool,
                "",
                orbit_cli::tools::is_read_only(tool),
                false,
            ) {
                Verdict::Allow => "Allow",
                Verdict::Ask => "Ask",
                Verdict::Deny(_) => "Deny",
            };
            let text = permission_command(&f.home, &scope, &f.work, tool).unwrap();
            assert!(
                text.contains(&format!("{tool}: {expected}")),
                "{mode:?}/{tool}: {text}"
            );
        }
        let text = permission_command(&f.home, &scope, &f.work, "calculator").unwrap();
        assert!(text.contains("calculator: Allow"), "{mode:?}: {text}");
    }
    assert!(!f.home.join("permission-overrides.toml").exists());
}
#[test]
fn frontend_policy_ask_is_saved_and_visible_after_reload() {
    let f = PolicyFixture::new();
    let text = f.command("ask mcp__browser__local__*").unwrap();
    assert!(
        text.contains("Ask") && text.contains("operator-override"),
        "{text}"
    );
    assert!(
        f.command("mcp__browser__local__snapshot")
            .unwrap()
            .contains("Ask")
    );
    assert!(
        std::fs::read_to_string(f.home.join("permission-overrides.toml"))
            .unwrap()
            .contains("ask")
    );
}
#[test]
fn frontend_policy_allow_replaces_identical_ask_and_reset_reveals_it() {
    let f = PolicyFixture::new();
    std::fs::write(
        f.home.join("settings.toml"),
        "[permissions]\nask=[\"mcp__browser__local__*\"]\n",
    )
    .unwrap();
    let allow = f.command("allow mcp__browser__local__*").unwrap();
    assert!(
        allow.contains("Allow") && allow.contains("replaces"),
        "{allow}"
    );
    let reset = f.command("reset mcp__browser__local__*").unwrap();
    assert!(reset.contains("Ask"), "{reset}");
    assert!(!reset.contains("operator-override"), "{reset}");
}
#[test]
fn frontend_policy_independent_deny_remains_visible_after_allow() {
    let f = PolicyFixture::new();
    std::fs::write(
        f.home.join("permissions.toml"),
        "[deny]\ntools=[\n\"mcp__browser__local__*\",\n]\n",
    )
    .unwrap();
    let text = f.command("allow mcp__browser__local__snapshot").unwrap();
    assert!(text.contains("Deny") && text.contains("legacy"), "{text}");
}
#[test]
fn frontend_policy_deny_and_reset_roundtrip() {
    let f = PolicyFixture::new();
    assert!(
        f.command("deny mcp__browser__local__*")
            .unwrap()
            .contains("Deny")
    );
    assert!(
        f.command("reset mcp__browser__local__*")
            .unwrap()
            .contains("Ask")
    );
}
#[test]
fn frontend_policy_malformed_command_preserves_saved_bytes() {
    let f = PolicyFixture::new();
    f.command("ask mcp__browser__local__*").unwrap();
    let path = f.home.join("permission-overrides.toml");
    let before = std::fs::read(&path).unwrap();
    for args in [
        "allow",
        "allow mcp__browser__local__* extra",
        "reset",
        "allow mcp__bad*",
        "ask *",
    ] {
        assert!(f.command(args).is_err(), "{args}");
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }
}
#[test]
fn frontend_policy_status_shows_sources_and_operator_exclusion() {
    let f = PolicyFixture::new();
    f.command("allow mcp__browser__local__*").unwrap();
    assert!(f.command("").unwrap().contains("operator-override"));
    let scope = PermissionScope {
        disallowlist: vec!["mcp__browser__local__*".into()],
        ..Default::default()
    };
    let text =
        permission_command(&f.home, &scope, &f.work, "mcp__browser__local__snapshot").unwrap();
    assert!(
        text.contains("Deny") && text.contains("operator-disallowlist"),
        "{text}"
    );
}
#[cfg(unix)]
mod package_commands {
    use super::PolicyFixture;
    use ed25519_dalek::SigningKey;
    use orbit_ledger::{LedgerEvent, verify_ledger};
    use orbit_plugin::sign_manifest;
    use serde_json::Value;
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    fn command(f: &PolicyFixture, args: &[&str], expected: i32) -> Value {
        let mut child = Command::new(env!("CARGO_BIN_EXE_orbit"))
            .args(args)
            .arg("--home")
            .arg(&f.home)
            .current_dir(&f.work)
            .env_remove("ORBIT_MODEL")
            .env_remove("ORBIT_ACTIVE_MODEL")
            .env_remove("ORBIT_EFFORT")
            .env("ORBIT_BARE", "1")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if child.try_wait().unwrap().is_some() {
                break;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!("package CLI timed out: {args:?}");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let output = child.wait_with_output().unwrap();
        assert_eq!(
            output.status.code(),
            Some(expected),
            "{args:?}: {} {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        if expected == 0 {
            serde_json::from_slice(&output.stdout).unwrap()
        } else {
            Value::String(String::from_utf8(output.stderr).unwrap())
        }
    }

    fn inputs(f: &PolicyFixture) -> (orbit_plugin::PluginManifest, String, String) {
        command(f, &["init", "--no-provider"], 0);
        let bytes = b"\0asm\x01\0\0\0local signed package";
        let manifest = sign_manifest(
            "browser-tools",
            "1.0.0",
            &SigningKey::from_bytes(&[19; 32]),
            bytes,
            vec![],
        );
        let package = f.root.join("package.wasm");
        let metadata = f.root.join("manifest.json");
        std::fs::write(&package, bytes).unwrap();
        std::fs::write(&metadata, serde_json::to_vec(&manifest).unwrap()).unwrap();
        (
            manifest,
            package.to_str().unwrap().into(),
            metadata.to_str().unwrap().into(),
        )
    }

    #[test]
    fn frontend_package_cli_install_catalog_status_retry_and_exact_ledger() {
        let f = PolicyFixture::new();
        let (manifest, package, metadata) = inputs(&f);
        command(&f, &["mod", "allow-issuer", &manifest.issuer_public_key], 0);
        let install = command(
            &f,
            &["mod", "install", &package, "--manifest", &metadata, "--yes"],
            0,
        );
        let receipt = &install["installation"];
        assert_eq!(receipt["name"], "browser-tools");
        assert_eq!(receipt["reused"], false);
        for args in [
            vec!["mod", "list"],
            vec!["mod", "search", "browser"],
            vec!["mod", "status", "browser-tools"],
        ] {
            let result = command(&f, &args, 0);
            assert_eq!(result["catalog"]["total"], 1);
            assert_eq!(result["catalog"]["packages"][0]["status"], "verified");
            assert_eq!(
                result["catalog"]["packages"][0]["ledger_record_hash"],
                receipt["ledger_record_hash"]
            );
        }
        let issuers = command(&f, &["mod", "issuers"], 0);
        assert_eq!(issuers["issuers"][0], manifest.issuer_public_key);
        let retry = command(
            &f,
            &["mod", "install", &package, "--manifest", &metadata, "--yes"],
            0,
        );
        assert_eq!(retry["installation"]["reused"], true);
        assert_eq!(
            retry["installation"]["ledger_record_hash"],
            receipt["ledger_record_hash"]
        );
        let (records, _) = verify_ledger(&f.home.join("ledger")).unwrap();
        let proofs: Vec<_> = records
            .iter()
            .filter(|r| matches!(&r.record.event, LedgerEvent::PluginInstall(_)))
            .collect();
        assert_eq!(proofs.len(), 1);
        assert_eq!(
            proofs[0].self_hash,
            receipt["ledger_record_hash"].as_str().unwrap()
        );
        assert_eq!(
            command(&f, &["mod", "status", "browser"], 0)["catalog"]["total"],
            0
        );
    }

    #[test]
    fn frontend_package_cli_refusals_preserve_install_store_and_ledger() {
        let f = PolicyFixture::new();
        let (manifest, package, metadata) = inputs(&f);
        let before = verify_ledger(&f.home.join("ledger")).unwrap().0.len();
        let error = command(
            &f,
            &["mod", "install", &package, "--manifest", &metadata],
            2,
        );
        assert!(error.as_str().unwrap().contains("explicit confirmation"));
        let error = command(
            &f,
            &["mod", "install", &package, "--manifest", &metadata, "--yes"],
            2,
        );
        assert!(error.as_str().unwrap().contains("issuer"));
        command(&f, &["mod", "allow-issuer", &manifest.issuer_public_key], 0);
        std::fs::write(f.work.join("--yes"), serde_json::to_vec(&manifest).unwrap()).unwrap();
        command(&f, &["mod", "install", &package, "--manifest", "--yes"], 2);
        assert!(!f.home.join("signed-packages").exists());
        std::fs::write(&package, b"different bytes").unwrap();
        command(
            &f,
            &["mod", "install", &package, "--manifest", &metadata, "--yes"],
            2,
        );
        assert!(!f.home.join("signed-packages").exists());
        assert_eq!(
            verify_ledger(&f.home.join("ledger")).unwrap().0.len(),
            before
        );
        assert_eq!(command(&f, &["mod", "list"], 0)["catalog"]["total"], 0);
    }

    #[test]
    fn frontend_package_cli_status_reports_tampered_saved_content() {
        let f = PolicyFixture::new();
        let (manifest, package, metadata) = inputs(&f);
        command(&f, &["mod", "allow-issuer", &manifest.issuer_public_key], 0);
        let result = command(
            &f,
            &["mod", "install", &package, "--manifest", &metadata, "--yes"],
            0,
        );
        let digest = result["installation"]["content_digest"].as_str().unwrap();
        std::fs::write(
            f.home
                .join("signed-packages/content")
                .join(format!("{digest}.blob")),
            b"tampered",
        )
        .unwrap();
        let result = command(&f, &["mod", "status", "browser-tools"], 0);
        assert_eq!(result["catalog"]["packages"][0]["status"], "tampered");
    }
}
