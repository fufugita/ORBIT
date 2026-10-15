#![cfg(unix)]

use orbit_cli::tool_runtime::{
    execute_call, ApprovalChannel, ApprovalRequest, ApprovalVerdict, AutoGrants, PermissionScope,
    StdApprovalChannel,
};
use orbit_tools::permissions::PermissionMode;
use serde_json::{json, Value};
use std::path::PathBuf;

struct Fixture {
    home: PathBuf,
    work: PathBuf,
    server: String,
    cx: orbit_tools::ToolContext,
}

impl Fixture {
    fn new() -> Self {
        let server = format!("policy{}", ulid::Ulid::new());
        let home = std::env::temp_dir().join(format!("orbit-p35-{server}"));
        let work = home.join("work");
        std::fs::create_dir_all(&work).unwrap();
        std::fs::write(home.join("server.py"), r#"
import json, sys
for line in sys.stdin:
    request = json.loads(line)
    with open(sys.argv[1], 'a') as log:
        log.write(json.dumps(request) + '\n')
    if 'id' not in request:
        continue
    method = request.get('method')
    if method == 'initialize':
        result = {'protocolVersion':'2025-06-18','capabilities':{},'serverInfo':{'name':'policy','version':'1'}}
    elif method == 'tools/call':
        result = {'content':[{'type':'text','text':'executed ' + request['params']['name']}]}
    else:
        result = {'tools':[{'name':'action','inputSchema':{'type':'object'}}]}
    print(json.dumps({'jsonrpc':'2.0','id':request['id'],'result':result}), flush=True)
"#).unwrap();
        let cx = orbit_tools::ToolContext::new(home.clone(), "owner".into(), work.clone());
        let fixture = Self {
            home,
            work,
            server,
            cx,
        };
        fixture.config(None);
        fixture
    }
    fn wire(&self) -> String {
        orbit_mcp::wire_name(&self.server, "action")
    }
    fn selector(&self) -> String {
        format!("mcp__{}__*", self.server)
    }
    fn config(&self, tools: Option<Vec<&str>>) {
        std::fs::write(self.home.join("mcp.json"), json!({"servers":{
            (self.server.clone()): {"command":"python3","args":[self.home.join("server.py"), self.home.join("calls.jsonl")],"tools":tools,"timeout_ms":1000,"initialize_timeout_ms":1000}
        }}).to_string()).unwrap();
    }
    fn explicit_ask(&self) {
        std::fs::write(
            self.home.join("settings.toml"),
            format!("[permissions]\nask = [\"{}\"]\n", self.wire()),
        )
        .unwrap();
    }
    fn legacy(&self, effect: &str) {
        std::fs::write(
            self.home.join("permissions.toml"),
            format!("[{effect}]\ntools = [\"{}\"]\n", self.wire()),
        )
        .unwrap();
    }
    fn run(
        &self,
        scope: &PermissionScope,
        auto: bool,
        interactive: bool,
        grants: &mut AutoGrants,
        channel: &mut dyn ApprovalChannel,
    ) -> Value {
        let call = orbit_cli::PendingToolCall {
            index: 0,
            id: ulid::Ulid::new().to_string(),
            name: self.wire(),
            arguments: b"{}".to_vec(),
        };
        let (output, _) = execute_call(
            &self.home,
            "owner",
            "decision",
            &call,
            auto,
            interactive,
            channel,
            grants,
            scope,
            &self.cx,
        )
        .unwrap();
        serde_json::from_str(&output).unwrap()
    }
    fn calls(&self) -> usize {
        std::fs::read_to_string(self.home.join("calls.jsonl"))
            .unwrap_or_default()
            .lines()
            .filter(|line| serde_json::from_str::<Value>(line).unwrap()["method"] == "tools/call")
            .count()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.home);
    }
}
struct Answer {
    answer: ApprovalVerdict,
    asked: usize,
    auto_seen: bool,
}
impl Answer {
    fn new(answer: ApprovalVerdict) -> Self {
        Self {
            answer,
            asked: 0,
            auto_seen: false,
        }
    }
}
impl ApprovalChannel for Answer {
    fn ask(&mut self, _: &ApprovalRequest, auto: bool) -> ApprovalVerdict {
        self.asked += 1;
        self.auto_seen |= auto;
        if auto {
            ApprovalVerdict::AllowOnce
        } else {
            self.answer
        }
    }
}

#[test]
fn explicit_ask_beats_legacy_allow_and_refusal_executes_zero_calls() {
    let f = Fixture::new();
    f.explicit_ask();
    f.legacy("allow");
    let mut answer = Answer::new(ApprovalVerdict::Deny);
    let out = f.run(
        &PermissionScope::default(),
        false,
        true,
        &mut AutoGrants::new(),
        &mut answer,
    );
    assert_eq!(out["ok"], false, "{out}");
    assert_eq!(answer.asked, 1);
    assert_eq!(f.calls(), 0);
}
#[test]
fn explicit_ask_beats_auto_tools_and_passes_no_auto_hint() {
    let f = Fixture::new();
    f.explicit_ask();
    let mut answer = Answer::new(ApprovalVerdict::Deny);
    let out = f.run(
        &PermissionScope::default(),
        true,
        true,
        &mut AutoGrants::new(),
        &mut answer,
    );
    assert_eq!(out["ok"], false, "{out}");
    assert_eq!(answer.asked, 1);
    assert!(!answer.auto_seen);
    assert_eq!(f.calls(), 0);
}
#[test]
fn explicit_ask_beats_remembered_session_grant() {
    let f = Fixture::new();
    f.explicit_ask();
    let mut grants = AutoGrants::new();
    grants.grant(&f.wire());
    let mut answer = Answer::new(ApprovalVerdict::Deny);
    let out = f.run(
        &PermissionScope::default(),
        false,
        true,
        &mut grants,
        &mut answer,
    );
    assert_eq!(out["ok"], false, "{out}");
    assert_eq!(answer.asked, 1);
    assert_eq!(f.calls(), 0);
}
#[test]
fn explicit_ask_headless_unavailability_executes_zero_calls() {
    let f = Fixture::new();
    f.explicit_ask();
    f.legacy("allow");
    let out = f.run(
        &PermissionScope::default(),
        true,
        false,
        &mut AutoGrants::new(),
        &mut StdApprovalChannel::new(false),
    );
    assert_eq!(out["ok"], false, "{out}");
    assert_eq!(f.calls(), 0);
}
#[test]
fn explicit_ask_accepted_confirmation_executes_exactly_once() {
    let f = Fixture::new();
    f.explicit_ask();
    let mut answer = Answer::new(ApprovalVerdict::AllowOnce);
    let out = f.run(
        &PermissionScope::default(),
        true,
        true,
        &mut AutoGrants::new(),
        &mut answer,
    );
    assert_eq!(out["ok"], true, "{out}");
    assert_eq!(answer.asked, 1);
    assert!(!answer.auto_seen);
    assert_eq!(f.calls(), 1);
}
#[test]
fn explicit_ask_dont_ask_mode_is_refused_before_channel() {
    let f = Fixture::new();
    f.explicit_ask();
    f.legacy("allow");
    let mut answer = Answer::new(ApprovalVerdict::AllowOnce);
    let scope = PermissionScope {
        mode: PermissionMode::DontAsk,
        ..Default::default()
    };
    let out = f.run(&scope, true, true, &mut AutoGrants::new(), &mut answer);
    assert_eq!(out["ok"], false, "{out}");
    assert_eq!(answer.asked, 0);
    assert_eq!(f.calls(), 0);
}
#[test]
fn explicit_ask_existing_bypass_mode_still_runs_once() {
    let f = Fixture::new();
    f.explicit_ask();
    let mut answer = Answer::new(ApprovalVerdict::Deny);
    let scope = PermissionScope {
        mode: PermissionMode::Bypass,
        ..Default::default()
    };
    let out = f.run(&scope, false, true, &mut AutoGrants::new(), &mut answer);
    assert_eq!(out["ok"], true, "{out}");
    assert_eq!(answer.asked, 0);
    assert_eq!(f.calls(), 1);
}

#[test]
fn uncovered_default_ask_keeps_upfront_and_legacy_convenience() {
    for legacy in [false, true] {
        let f = Fixture::new();
        if legacy {
            f.legacy("allow");
        }
        let mut answer = Answer::new(ApprovalVerdict::Deny);
        let out = f.run(
            &PermissionScope::default(),
            !legacy,
            false,
            &mut AutoGrants::new(),
            &mut answer,
        );
        assert_eq!(out["ok"], true, "{out}");
        assert_eq!(answer.asked, 0);
        assert_eq!(f.calls(), 1);
    }
}
#[test]
fn matching_server_deny_beats_exact_allow_and_grants() {
    let f = Fixture::new();
    std::fs::write(
        f.home.join("settings.toml"),
        format!(
            "[permissions]\nallow = [\"{}\"]\ndeny = [\"{}\"]\n",
            f.wire(),
            f.selector()
        ),
    )
    .unwrap();
    let mut grants = AutoGrants::new();
    grants.grant(&f.wire());
    let mut answer = Answer::new(ApprovalVerdict::AllowOnce);
    let out = f.run(
        &PermissionScope::default(),
        true,
        true,
        &mut grants,
        &mut answer,
    );
    assert_eq!(out["ok"], false, "{out}");
    assert_eq!(answer.asked, 0);
    assert_eq!(f.calls(), 0);
}
#[test]
fn server_explicit_ask_beats_exact_allow() {
    let f = Fixture::new();
    std::fs::write(
        f.home.join("settings.toml"),
        format!(
            "[permissions]\nallow = [\"{}\"]\nask = [\"{}\"]\n",
            f.wire(),
            f.selector()
        ),
    )
    .unwrap();
    let mut answer = Answer::new(ApprovalVerdict::Deny);
    let out = f.run(
        &PermissionScope::default(),
        true,
        true,
        &mut AutoGrants::new(),
        &mut answer,
    );
    assert_eq!(out["ok"], false, "{out}");
    assert_eq!(answer.asked, 1);
    assert_eq!(f.calls(), 0);
}
#[test]
fn plan_operator_scope_and_exposure_each_refuse_before_requests() {
    for case in 0..3 {
        let f = Fixture::new();
        f.legacy("allow");
        let scope = match case {
            0 => PermissionScope {
                mode: PermissionMode::Plan,
                ..Default::default()
            },
            1 => PermissionScope {
                allowlist: Some(vec!["Read".into()]),
                ..Default::default()
            },
            _ => {
                f.config(Some(vec!["different"]));
                PermissionScope::default()
            }
        };
        let mut answer = Answer::new(ApprovalVerdict::AllowOnce);
        let out = f.run(&scope, true, true, &mut AutoGrants::new(), &mut answer);
        assert_eq!(out["ok"], false, "case {case}: {out}");
        assert_eq!(answer.asked, 0);
        assert_eq!(f.calls(), 0);
        assert!(
            !f.home.join("calls.jsonl").exists(),
            "refusal spawned an MCP server"
        );
    }
}
#[test]
fn decoded_separator_server_isolated_from_prefix_neighbor() {
    let mut f = Fixture::new();
    let base = f.server.clone();
    f.server = format!("{base}__alt");
    f.config(Some(vec!["action"]));
    let path = f.home.join("mcp.json");
    let mut config: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    let mut neighbor = config["servers"][&f.server].clone();
    neighbor["tools"] = json!(["action"]);
    config["servers"][&base] = neighbor;
    std::fs::write(&path, config.to_string()).unwrap();
    std::fs::write(
        f.home.join("settings.toml"),
        format!(
            "[permissions]\ndeny = [\"mcp__{base}__*\"]\nallow = [\"{}\"]\n",
            f.selector()
        ),
    )
    .unwrap();
    let mut answer = Answer::new(ApprovalVerdict::Deny);
    let out = f.run(
        &PermissionScope::default(),
        false,
        false,
        &mut AutoGrants::new(),
        &mut answer,
    );
    assert_eq!(out["ok"], true, "{out}");
    assert_eq!(f.calls(), 1);
    assert_eq!(answer.asked, 0);
    let log = std::fs::read_to_string(f.home.join("calls.jsonl")).unwrap();
    assert!(log.lines().any(|line| {
        let request: Value = serde_json::from_str(line).unwrap();
        request["method"] == "tools/call" && request["params"]["name"] == "action"
    }));
}
#[test]
fn genuinely_ambiguous_wire_alias_refuses_before_spawn() {
    let mut f = Fixture::new();
    let base = f.server.clone();
    f.server = format!("{base}__alt");
    f.config(Some(vec!["action"]));
    let path = f.home.join("mcp.json");
    let mut config: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    let mut neighbor = config["servers"][&f.server].clone();
    neighbor["tools"] = json!(["alt__action"]);
    config["servers"][&base] = neighbor;
    std::fs::write(&path, config.to_string()).unwrap();
    let mut answer = Answer::new(ApprovalVerdict::AllowOnce);
    let out = f.run(
        &PermissionScope::default(),
        true,
        true,
        &mut AutoGrants::new(),
        &mut answer,
    );
    assert_eq!(out["ok"], false, "{out}");
    assert!(out.to_string().contains("ambiguous"));
    assert_eq!(answer.asked, 0);
    assert_eq!(f.calls(), 0);
    assert!(!f.home.join("calls.jsonl").exists());
}
#[test]
fn invalid_mcp_selector_refuses_without_grant_fallback() {
    for invalid in [
        "mcp__*",
        "mcp__server*__*",
        "mcp__server__tool*",
        "mcp__server__*(arg)",
    ] {
        let f = Fixture::new();
        std::fs::write(
            f.home.join("settings.toml"),
            format!("[permissions]\nask = [\"{invalid}\"]\n"),
        )
        .unwrap();
        let mut answer = Answer::new(ApprovalVerdict::AllowOnce);
        let out = f.run(
            &PermissionScope::default(),
            true,
            true,
            &mut AutoGrants::new(),
            &mut answer,
        );
        assert_eq!(out["ok"], false, "{invalid}: {out}");
        assert_eq!(answer.asked, 0);
        assert_eq!(f.calls(), 0);
    }
}
#[test]
fn override_replacements_reload_and_reset_to_user_ask() {
    use orbit_cli::tool_runtime::{effective_permission_policy, set_permission_override};
    use orbit_tools::permissions::RuleEffectSerde as Effect;
    let f = Fixture::new();
    f.explicit_ask();
    let scope = PermissionScope::default();
    for effect in [Effect::Allow, Effect::Deny, Effect::Ask] {
        let report =
            set_permission_override(&f.home, &scope, &f.work, &f.wire(), Some(effect)).unwrap();
        assert_eq!(report.effect, effect);
        assert!(report
            .matching_rules
            .iter()
            .any(|rule| rule.source == "user" && rule.shadowed));
        let raw = std::fs::read_to_string(f.home.join("permission-overrides.toml")).unwrap();
        assert_eq!(raw.matches(&f.wire()).count(), 1);
        let reloaded = effective_permission_policy(&f.home, &scope, &f.work, &f.wire()).unwrap();
        assert!(reloaded
            .matching_rules
            .iter()
            .any(|rule| rule.source == "operator-override" && rule.effect == effect));
    }
    let report = set_permission_override(&f.home, &scope, &f.work, &f.wire(), None).unwrap();
    assert_eq!(report.effect, Effect::Ask);
    assert_eq!(report.sources, ["user"]);
    let mut answer = Answer::new(ApprovalVerdict::Deny);
    let out = f.run(&scope, true, true, &mut AutoGrants::new(), &mut answer);
    assert_eq!(out["ok"], false);
    assert_eq!(f.calls(), 0);
}
#[test]
fn deliberate_same_selector_override_replaces_ask_and_reset_restores_it() {
    use orbit_cli::tool_runtime::{permission_policy_status, set_permission_override};
    use orbit_tools::permissions::RuleEffectSerde as Effect;
    let f = Fixture::new();
    f.explicit_ask();
    let scope = PermissionScope::default();
    let report =
        set_permission_override(&f.home, &scope, &f.work, &f.wire(), Some(Effect::Allow)).unwrap();
    assert_eq!(report.effect, Effect::Allow);
    assert!(
        permission_policy_status(&f.home, &scope, &f.work, Some(&f.wire()))
            .unwrap()
            .contains("replaces same-selector user")
    );
    let mut answer = Answer::new(ApprovalVerdict::Deny);
    let out = f.run(&scope, false, true, &mut AutoGrants::new(), &mut answer);
    assert_eq!(out["ok"], true);
    assert_eq!(f.calls(), 1);
    assert_eq!(answer.asked, 0);
    set_permission_override(&f.home, &scope, &f.work, &f.wire(), None).unwrap();
    let out = f.run(&scope, true, true, &mut AutoGrants::new(), &mut answer);
    assert_eq!(out["ok"], false);
    assert_eq!(f.calls(), 1);
    assert_eq!(answer.asked, 1);
}
#[test]
fn broader_server_ask_survives_deliberate_exact_allow() {
    use orbit_cli::tool_runtime::set_permission_override;
    use orbit_tools::permissions::RuleEffectSerde as Effect;
    let f = Fixture::new();
    let scope = PermissionScope::default();
    std::fs::write(
        f.home.join("settings.toml"),
        format!("[permissions]\nask = [\"{}\"]\n", f.selector()),
    )
    .unwrap();
    let report =
        set_permission_override(&f.home, &scope, &f.work, &f.wire(), Some(Effect::Allow)).unwrap();
    assert_eq!(report.effect, Effect::Ask);
    assert_eq!(report.sources, ["user"]);
    let mut answer = Answer::new(ApprovalVerdict::Deny);
    let out = f.run(&scope, true, true, &mut AutoGrants::new(), &mut answer);
    assert_eq!(out["ok"], false);
    assert_eq!(f.calls(), 0);
    assert_eq!(answer.asked, 1);
}
#[test]
fn other_layer_project_and_operator_denies_survive_override_allow() {
    use orbit_cli::tool_runtime::set_permission_override;
    use orbit_tools::permissions::RuleEffectSerde as Effect;
    for case in 0..2 {
        let f = Fixture::new();
        let scope = if case == 0 {
            std::fs::create_dir(f.work.join(".orbit")).unwrap();
            std::fs::write(
                f.work.join(".orbit/settings.toml"),
                format!("[permissions]\ndeny = [\"{}\"]\n", f.selector()),
            )
            .unwrap();
            PermissionScope::default()
        } else {
            PermissionScope {
                disallowlist: vec![f.selector()],
                ..Default::default()
            }
        };
        let report =
            set_permission_override(&f.home, &scope, &f.work, &f.wire(), Some(Effect::Allow))
                .unwrap();
        assert_eq!(report.effect, Effect::Deny);
        assert!(report.sources.iter().any(|source| source
            == if case == 0 {
                "project"
            } else {
                "operator-disallowlist"
            }));
        let mut answer = Answer::new(ApprovalVerdict::AllowOnce);
        let out = f.run(&scope, true, true, &mut AutoGrants::new(), &mut answer);
        assert_eq!(out["ok"], false);
        assert_eq!(f.calls(), 0);
        assert_eq!(answer.asked, 0);
    }
}
#[test]
fn failed_save_leaves_effective_state_and_disk_unchanged() {
    use orbit_cli::tool_runtime::{effective_permission_policy, set_permission_override};
    use orbit_tools::permissions::RuleEffectSerde as Effect;
    let f = Fixture::new();
    let scope = PermissionScope::default();
    set_permission_override(&f.home, &scope, &f.work, &f.wire(), Some(Effect::Ask)).unwrap();
    let path = f.home.join("permission-overrides.toml");
    let before = std::fs::read(&path).unwrap();
    assert!(
        set_permission_override(&f.home, &scope, &f.work, "mcp__*", Some(Effect::Allow)).is_err()
    );
    assert_eq!(std::fs::read(&path).unwrap(), before);
    let backup = f.home.join("override-backup");
    std::fs::rename(&path, &backup).unwrap();
    std::os::unix::fs::symlink(&backup, &path).unwrap();
    assert!(
        set_permission_override(&f.home, &scope, &f.work, &f.wire(), Some(Effect::Allow)).is_err()
    );
    assert_eq!(std::fs::read(&backup).unwrap(), before);
    std::fs::remove_file(&path).unwrap();
    std::fs::rename(&backup, &path).unwrap();
    assert_eq!(
        effective_permission_policy(&f.home, &scope, &f.work, &f.wire())
            .unwrap()
            .effect,
        Effect::Ask
    );
    let mut answer = Answer::new(ApprovalVerdict::Deny);
    let out = f.run(&scope, true, true, &mut AutoGrants::new(), &mut answer);
    assert_eq!(out["ok"], false);
    assert_eq!(f.calls(), 0);
}
#[test]
fn durable_server_allow_dispatches_then_deny_and_reset_change_real_calls() {
    use orbit_cli::tool_runtime::{permission_policy_status, set_permission_override};
    use orbit_tools::permissions::RuleEffectSerde as Effect;
    let f = Fixture::new();
    let scope = PermissionScope::default();
    for (effect, expected, count) in [
        (Some(Effect::Allow), true, 1),
        (Some(Effect::Deny), false, 1),
        (Some(Effect::Ask), false, 1),
        (None, false, 1),
    ] {
        set_permission_override(&f.home, &scope, &f.work, &f.selector(), effect).unwrap();
        let mut answer = Answer::new(ApprovalVerdict::Deny);
        let out = f.run(&scope, false, true, &mut AutoGrants::new(), &mut answer);
        assert_eq!(out["ok"], expected);
        assert_eq!(f.calls(), count);
        let status = permission_policy_status(&f.home, &scope, &f.work, Some(&f.wire())).unwrap();
        assert!(status.contains(if effect.is_some() {
            "operator-override"
        } else {
            "uncovered-default"
        }));
    }
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(
        std::fs::metadata(f.home.join("permission-overrides.toml"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
}

#[test]
#[cfg(target_os = "linux")]
fn actual_temporary_file_save_failure_preserves_prior_policy_and_bytes() {
    use orbit_cli::tool_runtime::{effective_permission_policy, set_permission_override};
    use orbit_tools::permissions::RuleEffectSerde as Effect;
    let mut f = Fixture::new();
    let original = f.home.clone();
    let mut deep = original.join("deep");
    // The existing files fit Linux's path bound, but the longer private
    // temporary filename does not. This causes a real pre-publication IO error.
    while deep.as_os_str().len() < 4055 {
        let remaining = 4055 - deep.as_os_str().len();
        deep.push("d".repeat(remaining.saturating_sub(1).clamp(1, 200)));
    }
    std::fs::create_dir_all(&deep).unwrap();
    std::fs::copy(original.join("server.py"), deep.join("server.py")).unwrap();
    f.home = deep;
    f.config(None);
    f.cx = orbit_tools::ToolContext::new(f.home.clone(), "owner".into(), f.work.clone());
    let path = f.home.join("permission-overrides.toml");
    let before = format!("[permissions]\nask = [\"{}\"]\n", f.wire());
    std::fs::write(&path, &before).unwrap();
    let scope = PermissionScope::default();
    let error = set_permission_override(&f.home, &scope, &f.work, &f.wire(), Some(Effect::Allow))
        .unwrap_err();
    assert!(error.contains("create operator overrides"), "{error}");
    assert_eq!(std::fs::read_to_string(&path).unwrap(), before);
    assert_eq!(
        effective_permission_policy(&f.home, &scope, &f.work, &f.wire())
            .unwrap()
            .effect,
        Effect::Ask
    );
    let mut answer = Answer::new(ApprovalVerdict::Deny);
    let out = f.run(&scope, true, true, &mut AutoGrants::new(), &mut answer);
    assert_eq!(out["ok"], false);
    assert_eq!(answer.asked, 1);
    assert_eq!(f.calls(), 0);
    drop(f);
    std::fs::remove_dir_all(original).unwrap();
}

#[test]
fn competing_override_writer_refuses_without_changing_saved_policy() {
    use orbit_cli::tool_runtime::set_permission_override;
    use orbit_tools::permissions::RuleEffectSerde as Effect;
    let f = Fixture::new();
    let scope = PermissionScope::default();
    set_permission_override(&f.home, &scope, &f.work, &f.wire(), Some(Effect::Ask)).unwrap();
    let before = std::fs::read(f.home.join("permission-overrides.toml")).unwrap();
    let lock = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(f.home.join("permission-overrides.lock"))
        .unwrap();
    lock.try_lock().unwrap();
    let error = set_permission_override(&f.home, &scope, &f.work, &f.wire(), Some(Effect::Allow))
        .unwrap_err();
    assert!(error.contains("writer unavailable"), "{error}");
    assert_eq!(
        std::fs::read(f.home.join("permission-overrides.toml")).unwrap(),
        before
    );
    let mut answer = Answer::new(ApprovalVerdict::Deny);
    let out = f.run(&scope, true, true, &mut AutoGrants::new(), &mut answer);
    assert_eq!(out["ok"], false);
    assert_eq!(f.calls(), 0);
    drop(lock);
    set_permission_override(&f.home, &scope, &f.work, &f.wire(), Some(Effect::Allow)).unwrap();
    let out = f.run(&scope, false, true, &mut AutoGrants::new(), &mut answer);
    assert_eq!(out["ok"], true);
    assert_eq!(f.calls(), 1);
}

#[test]
fn legacy_server_deny_under_bypass_matches_report_and_zero_calls() {
    use orbit_cli::tool_runtime::effective_permission_policy;
    use orbit_tools::permissions::RuleEffectSerde;
    let f = Fixture::new();
    std::fs::write(
        f.home.join("permissions.toml"),
        format!("[deny]\ntools = [\"{}\"]\n", f.selector()),
    )
    .unwrap();
    let scope = PermissionScope {
        mode: PermissionMode::Bypass,
        ..Default::default()
    };
    let report = effective_permission_policy(&f.home, &scope, &f.work, &f.wire()).unwrap();
    assert_eq!(report.effect, RuleEffectSerde::Deny);
    assert_eq!(report.sources, ["legacy"]);
    let mut answer = Answer::new(ApprovalVerdict::AllowOnce);
    let out = f.run(&scope, true, true, &mut AutoGrants::new(), &mut answer);
    assert_eq!(out["ok"], false, "{out}");
    assert_eq!(f.calls(), 0);
    assert_eq!(answer.asked, 0);
}
#[test]
fn legacy_multiline_exact_deny_under_bypass_matches_report_and_zero_calls() {
    use orbit_cli::tool_runtime::effective_permission_policy;
    use orbit_tools::permissions::RuleEffectSerde;
    let f = Fixture::new();
    std::fs::write(
        f.home.join("permissions.toml"),
        format!("[deny]\ntools = [\n  \"{}\",\n]\n", f.wire()),
    )
    .unwrap();
    let scope = PermissionScope {
        mode: PermissionMode::Bypass,
        ..Default::default()
    };
    let report = effective_permission_policy(&f.home, &scope, &f.work, &f.wire()).unwrap();
    assert_eq!(report.effect, RuleEffectSerde::Deny);
    assert_eq!(report.sources, ["legacy"]);
    let mut answer = Answer::new(ApprovalVerdict::AllowOnce);
    let out = f.run(&scope, true, true, &mut AutoGrants::new(), &mut answer);
    assert_eq!(out["ok"], false, "{out}");
    assert_eq!(f.calls(), 0);
    assert_eq!(answer.asked, 0);
}

struct MutateApproval {
    change: Box<dyn FnMut() + Send>,
    asked: usize,
}
impl ApprovalChannel for MutateApproval {
    fn ask(&mut self, _: &ApprovalRequest, auto: bool) -> ApprovalVerdict {
        assert!(!auto);
        self.asked += 1;
        (self.change)();
        ApprovalVerdict::AllowOnce
    }
}

#[test]
fn approval_target_rebinding_to_a_denied_separator_neighbor_executes_zero_calls() {
    let mut f = Fixture::new();
    let base = f.server.clone();
    f.server = format!("{base}__alt");
    f.config(Some(vec!["action"]));
    std::fs::write(
        f.home.join("settings.toml"),
        format!(
            "[permissions]\nask=[\"{}\"]\ndeny=[\"mcp__{base}__*\"]\n",
            f.selector()
        ),
    )
    .unwrap();
    let config_path = f.home.join("mcp.json");
    let config: Value = serde_json::from_slice(&std::fs::read(&config_path).unwrap()).unwrap();
    let mut replacement = config["servers"][&f.server].clone();
    replacement["tools"] = json!(["alt__action"]);
    let mut answer = MutateApproval {
        asked: 0,
        change: Box::new(move || {
            std::fs::write(
                &config_path,
                json!({"servers":{(&base):replacement.clone()}}).to_string(),
            )
            .unwrap();
        }),
    };
    let out = f.run(
        &PermissionScope::default(),
        false,
        true,
        &mut AutoGrants::new(),
        &mut answer,
    );
    assert_eq!(answer.asked, 1);
    assert_eq!(out["ok"], false, "{out}");
    assert!(out.to_string().contains("changed"));
    assert_eq!(f.calls(), 0);
    assert!(!f.home.join("calls.jsonl").exists());
}
#[test]
fn approval_same_server_executable_replacement_executes_zero_calls() {
    let f = Fixture::new();
    f.explicit_ask();
    let config_path = f.home.join("mcp.json");
    let server = f.server.clone();
    let mut config: Value = serde_json::from_slice(&std::fs::read(&config_path).unwrap()).unwrap();
    let replacement = f.home.join("replacement.sh");
    let spawned = f.home.join("replacement-spawned");
    std::fs::write(
        &replacement,
        format!("printf replacement > '{}'\n", spawned.display()),
    )
    .unwrap();
    let mut answer = MutateApproval {
        asked: 0,
        change: Box::new(move || {
            config["servers"][&server]["command"] = json!("/bin/sh");
            config["servers"][&server]["args"] = json!([replacement]);
            std::fs::write(&config_path, config.to_string()).unwrap();
        }),
    };
    let out = f.run(
        &PermissionScope::default(),
        false,
        true,
        &mut AutoGrants::new(),
        &mut answer,
    );
    assert_eq!(answer.asked, 1);
    assert_eq!(out["ok"], false, "{out}");
    assert!(out.to_string().contains("changed"));
    assert_eq!(f.calls(), 0);
    assert!(!spawned.exists());
}
#[test]
fn approval_policy_replacement_with_deny_executes_zero_calls() {
    let f = Fixture::new();
    f.explicit_ask();
    let settings = f.home.join("settings.toml");
    let selector = f.selector();
    let mut answer = MutateApproval {
        asked: 0,
        change: Box::new(move || {
            std::fs::write(&settings, format!("[permissions]\ndeny=[\"{selector}\"]\n")).unwrap();
        }),
    };
    let out = f.run(
        &PermissionScope::default(),
        false,
        true,
        &mut AutoGrants::new(),
        &mut answer,
    );
    assert_eq!(answer.asked, 1);
    assert_eq!(out["ok"], false, "{out}");
    assert!(out.to_string().contains("changed"));
    assert_eq!(f.calls(), 0);
    assert!(!f.home.join("calls.jsonl").exists());
}
#[test]
fn approval_unchanged_captured_target_dispatches_exactly_once() {
    let f = Fixture::new();
    f.explicit_ask();
    let mut answer = MutateApproval {
        asked: 0,
        change: Box::new(|| {}),
    };
    let out = f.run(
        &PermissionScope::default(),
        false,
        true,
        &mut AutoGrants::new(),
        &mut answer,
    );
    assert_eq!(answer.asked, 1);
    assert_eq!(out["ok"], true, "{out}");
    assert_eq!(f.calls(), 1);
}
