#![cfg(target_os = "linux")]
use orbit_cli::tool_runtime::{
    self, ApprovalChannel, ApprovalRequest, ApprovalVerdict, AutoGrants, PermissionScope,
};
use serde_json::{Value, json};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
struct Mock {
    url: String,
    directory: PathBuf,
    process: std::process::Child,
}
impl Mock {
    fn new() -> Self {
        let directory =
            std::env::temp_dir().join(format!("orbit-task-provider-{}", ulid::Ulid::new()));
        std::fs::create_dir(&directory).unwrap();
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        let process = std::process::Command::new("python3")
            .arg(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../scripts/fixtures/p35_provider.py"
            ))
            .arg(&directory)
            .env("PYTHONDONTWRITEBYTECODE", "1")
            .stdout(std::process::Stdio::null())
            .stderr(std::fs::File::create(directory.join("provider.stderr")).unwrap())
            .spawn()
            .unwrap();
        let mut fixture = Self {
            url: String::new(),
            directory,
            process,
        };
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        fixture.url = loop {
            if let Some(gate) = std::fs::read(fixture.directory.join("ready.json"))
                .ok()
                .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
                .and_then(|ready| ready["gate"].as_str().map(str::to_owned))
            {
                break gate;
            }
            assert!(
                fixture.process.try_wait().unwrap().is_none(),
                "captured Task provider stopped"
            );
            if std::time::Instant::now() >= deadline {
                panic!("captured Task provider did not become ready within five seconds");
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        };
        assert_eq!(
            url::Url::parse(&fixture.url).unwrap().host_str(),
            Some("127.0.0.1")
        );
        fixture
    }
    fn capture(&self, name: &str) -> Vec<Value> {
        std::fs::read_to_string(self.directory.join(name))
            .unwrap_or_default()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }
    fn calls(&self) -> u64 {
        self.capture("calls.jsonl").len() as u64
    }
    fn body(&self) -> Value {
        self.capture("calls.jsonl").last().unwrap().clone()
    }
    fn bodies(&self) -> Vec<Value> {
        self.capture("calls.jsonl")
    }
    fn request_metadata(&self) -> Vec<Value> {
        self.capture("requests.jsonl")
    }
}
impl Drop for Mock {
    fn drop(&mut self) {
        if matches!(self.process.try_wait(), Ok(None)) {
            let _ = self.process.kill();
        }
        let _ = self.process.wait();
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}
struct Approve;
impl ApprovalChannel for Approve {
    fn ask(&mut self, _: &ApprovalRequest, _: bool) -> ApprovalVerdict {
        ApprovalVerdict::AllowOnce
    }
}
struct Fixture {
    home: PathBuf,
    cx: orbit_tools::ToolContext,
    a: Mock,
    b: Mock,
}
impl Fixture {
    fn new() -> Self {
        let home = std::env::temp_dir().join(format!("orbit-task-route-{}", ulid::Ulid::new()));
        std::fs::create_dir(&home).unwrap();
        std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700)).unwrap();
        let work = home.join("workspace");
        std::fs::create_dir(&work).unwrap();
        let a = Mock::new();
        let b = Mock::new();
        let cx = orbit_tools::ToolContext::new(home.clone(), "owner".into(), work);
        let f = Self { home, cx, a, b };
        f.configure("b/family/routed-notools");
        let config = orbit_cli::phase_routing::resolve_model(
            &orbit_cli::config::ProvidersConfig::load(&f.home).unwrap(),
            "a/family/base-notools",
            None,
        )
        .unwrap()
        .turn_config(None)
        .unwrap();
        tool_runtime::remember_turn_config(&f.cx, &config);
        f
    }
    fn configure(&self, target: &str) {
        std::fs::write(self.home.join("providers.toml"),format!("[[provider]]\nname='a'\nurl='{}'\n[[provider.models]]\nid='family/base-notools'\nsupported_efforts=['low','high']\ndefault_effort='low'\n[[provider.models]]\nid='family/role-notools'\nsupported_efforts=['low']\ndefault_effort='low'\n[[provider.models]]\nid='family/pinned-notools'\nsupported_efforts=['low']\ndefault_effort='low'\n[[provider.models]]\nid='shared/notools'\n[[provider]]\nname='b'\nurl='{}'\n[[provider.models]]\nid='family/routed-notools'\nsupported_efforts=['medium']\ndefault_effort='medium'\n[[provider.models]]\nid='shared/notools'\n[roles]\nexplore='a/family/role-notools'\nsubagent='a/family/role-notools'\n[routing.phases.coding]\ndefault='{target}'\n[routing.phase_keywords]\nclear=true\ncoding=['implement']\n",self.a.url,self.b.url)).unwrap();
    }
    fn task(&self, args: Value) -> Value {
        let call = orbit_cli::PendingToolCall {
            index: 0,
            id: ulid::Ulid::new().to_string(),
            name: "Task".into(),
            arguments: serde_json::to_vec(&args).unwrap(),
        };
        let (output, _) = tool_runtime::execute_call(
            &self.home,
            "owner",
            "decision",
            &call,
            true,
            false,
            &mut Approve,
            &mut AutoGrants::new(),
            &PermissionScope::default(),
            &self.cx,
        )
        .unwrap();
        serde_json::from_str(&output).unwrap()
    }
    fn store(&self) -> orbit_engine::agent_store::AgentStore {
        orbit_engine::agent_store::AgentStore::new(&self.home, "owner").unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.home);
    }
}
fn id(result: &Value) -> String {
    result["result"]["agent_id"].as_str().unwrap().into()
}
#[test]
fn implicit_fresh_explore_phase_reaches_exact_cross_provider_raw_identity() {
    let f = Fixture::new();
    let result = f.task(json!({"agent":"Explore","prompt":"implement a parser"}));
    assert_eq!(result["ok"], true, "{result}");
    assert_eq!(result["result"]["model"], "b/family/routed-notools");
    assert_eq!(f.a.calls(), 0);
    assert_eq!(f.b.calls(), 1);
    assert_eq!(f.b.body()["model"], "family/routed-notools");
    assert_eq!(
        f.store().load(&id(&result)).unwrap().model,
        "b/family/routed-notools"
    );
}
#[test]
fn implicit_general_task_keeps_explore_role_when_no_phase_target() {
    let f = Fixture::new();
    let result = f.task(json!({"agent":"Explore","prompt":"observe the files"}));
    assert_eq!(result["ok"], true, "{result}");
    assert_eq!(result["result"]["model"], "a/family/role-notools");
    assert_eq!(f.a.calls(), 1);
    assert_eq!(f.b.calls(), 0);
    assert_eq!(f.a.body()["model"], "family/role-notools");
}
#[test]
fn explicit_task_model_suppresses_phase_routing_even_on_coding_prompt() {
    let f = Fixture::new();
    let result = f.task(
        json!({"agent":"Explore","prompt":"implement a parser","model":"a/family/pinned-notools"}),
    );
    assert_eq!(result["ok"], true, "{result}");
    assert_eq!(result["result"]["model"], "a/family/pinned-notools");
    assert_eq!(f.a.calls(), 1);
    assert_eq!(f.b.calls(), 0);
}
#[test]
fn explicit_selection_equal_to_role_default_still_suppresses_routing() {
    let f = Fixture::new();
    let result =
        f.task(json!({"agent":"Explore","prompt":"implement","model":"a/family/role-notools"}));
    assert_eq!(result["ok"], true, "{result}");
    assert_eq!(f.a.body()["model"], "family/role-notools");
    assert_eq!(f.a.calls(), 1);
    assert_eq!(f.b.calls(), 0);
}
#[test]
fn absent_role_mapping_keeps_parent_identity_for_unmatched_phase() {
    let f = Fixture::new();
    let path = f.home.join("providers.toml");
    let mut value: toml::Value = toml::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    value.as_table_mut().unwrap().remove("roles");
    std::fs::write(path, toml::to_string(&value).unwrap()).unwrap();
    let result = f.task(json!({"agent":"Explore","prompt":"observe files"}));
    assert_eq!(result["ok"], true, "{result}");
    assert_eq!(f.a.body()["model"], "family/base-notools");
    assert_eq!(f.a.calls(), 1);
    assert_eq!(f.b.calls(), 0);
}
#[test]
fn resumed_agent_sticks_to_first_actual_routed_identity_after_config_change() {
    let f = Fixture::new();
    let first = f.task(json!({"agent":"Explore","prompt":"implement first"}));
    assert_eq!(first["ok"], true, "{first}");
    let agent = id(&first);
    f.configure("a/family/role-notools");
    let result = f.task(json!({"agent":"Explore","resume":agent,"prompt":"implement next"}));
    assert_eq!(result["ok"], true, "{result}");
    assert_eq!(result["result"]["model"], "b/family/routed-notools");
    assert_eq!(f.a.calls(), 0);
    assert_eq!(f.b.calls(), 2);
    assert_eq!(f.store().load(&id(&result)).unwrap().turns, 2);
}
#[test]
fn explicit_resumed_model_change_remains_pinned() {
    let f = Fixture::new();
    let first = f.task(json!({"agent":"Explore","prompt":"implement first"}));
    let result=f.task(json!({"agent":"Explore","resume":id(&first),"prompt":"implement next","model":"a/family/pinned-notools"}));
    assert_eq!(result["ok"], true, "{result}");
    assert_eq!(result["result"]["model"], "a/family/pinned-notools");
    assert_eq!(f.a.calls(), 1);
    assert_eq!(f.b.calls(), 1);
}
#[test]
fn declared_agent_profile_model_suppresses_phase_routing() {
    let f = Fixture::new();
    std::fs::create_dir(f.home.join("agents")).unwrap();
    std::fs::write(f.home.join("agents/pinned.md"),"---\nname: pinned\ndescription: Explicit model profile\nmodel: a/family/pinned-notools\ntools: [Read]\n---\n").unwrap();
    let result = f.task(json!({"agent":"pinned","prompt":"implement a parser"}));
    assert_eq!(result["ok"], true, "{result}");
    assert_eq!(result["result"]["model"], "a/family/pinned-notools");
    assert_eq!(f.a.calls(), 1);
    assert_eq!(f.b.calls(), 0);
}
#[test]
fn agent_instructions_reach_fresh_and_durable_resumed_task_requests_once() {
    use orbit_adapter::types::{ChatRole, EffortSetting, EffortValue};

    const AGENT: &str = "instruction-reviewer";
    const MARKER: &str = "agent-instruction-wire-marker-7e3b6a";
    const BODY: &str = "# Review procedure\n\nagent-instruction-wire-marker-7e3b6a\nKeep each finding tied to its evidence.\n\nPreserve this Unicode instruction: λ → evidence.\nUse the declared Read tool; return a concise report.";
    let f = Fixture::new();
    let agents = f.home.join("agents");
    std::fs::create_dir(&agents).unwrap();
    std::fs::set_permissions(&agents, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::write(
        agents.join("instruction-reviewer.md"),
        format!(
            "---\nname: {AGENT}\ndescription: Review evidence with the declared profile\ntools: [Read]\nmodel: a/family/pinned-notools\neffort: low\nmaxTurns: 3\n---\n\n{BODY}\n"
        ),
    )
    .unwrap();
    let mut parent = orbit_cli::phase_routing::resolve_model(
        &orbit_cli::config::ProvidersConfig::load(&f.home).unwrap(),
        "a/family/base-notools",
        None,
    )
    .unwrap()
    .turn_config(None)
    .unwrap();
    let parent_effort = EffortSetting::Value(EffortValue::Level("high".into()));
    orbit_cli::apply_effort_setting(&f.home, &mut parent, &parent_effort).unwrap();
    tool_runtime::remember_turn_config(&f.cx, &parent);
    tool_runtime::remember_effort_setting(&f.cx, &Some(parent_effort.clone()));
    let parent_before = format!("{parent:?}");
    let profile_effort = Some(EffortSetting::Value(EffortValue::Level("low".into())));

    let first = f.task(json!({"agent": AGENT, "prompt": "implement the first review"}));
    assert_eq!(first["ok"], true, "{first}");
    let agent_id = id(&first);
    let first_request = f.a.body();
    let first_saved = f.store().load(&agent_id).unwrap();
    assert_eq!(first_saved.agent_type, AGENT);
    assert_eq!(first_saved.model, "a/family/pinned-notools");
    assert_eq!(first_saved.effort, profile_effort);
    assert_eq!(first_saved.turns, 1);

    // Reload through a fresh store handle: the second run must use durable
    // history rather than an in-memory continuation of the first request.
    let reloaded = f.store().load(&agent_id).unwrap();
    assert_eq!(reloaded.transcript, first_saved.transcript);
    let resumed = f.task(json!({
        "agent": AGENT,
        "resume": reloaded.agent_id,
        "prompt": "implement the second review"
    }));
    assert_eq!(resumed["ok"], true, "{resumed}");
    assert_eq!(id(&resumed), agent_id);
    let resumed_request = f.a.body();
    let resumed_saved = f.store().load(&agent_id).unwrap();
    assert_eq!(f.a.calls(), 2);
    assert_eq!(f.b.calls(), 0);
    assert_eq!(resumed_saved.turns, 2);
    assert_eq!(resumed_saved.model, first_saved.model);
    assert_eq!(resumed_saved.effort, profile_effort);
    assert!(
        resumed_saved
            .transcript
            .starts_with(&first_saved.transcript)
    );
    assert_eq!(
        resumed_saved.transcript.len(),
        first_saved.transcript.len() + 2
    );
    assert!(
        resumed_saved.transcript.iter().all(|message| {
            message.role != ChatRole::System && !message.content.contains(MARKER)
        })
    );
    assert_eq!(
        format!(
            "{:?}",
            f.cx.ext::<tool_runtime::SessionTurnConfig>().unwrap().0
        ),
        parent_before
    );
    assert_eq!(
        f.cx.ext::<tool_runtime::SessionEffortSetting>().unwrap().0,
        Some(parent_effort)
    );
    assert!(!parent_before.contains(MARKER));

    for (label, request) in [("fresh", first_request), ("resumed", resumed_request)] {
        assert_eq!(request["model"], "family/pinned-notools", "{label}");
        assert_eq!(request["reasoning_effort"], "low", "{label}");
        let tools: Vec<_> = request["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|tool| tool["function"]["name"].as_str().unwrap())
            .collect();
        assert_eq!(tools, vec!["Read"], "{label}: restricted tool exposure");
        assert!(!tools.contains(&"Bash") && !tools.contains(&"Write"));
        let messages = request["messages"].as_array().unwrap();
        let system: Vec<_> = messages
            .iter()
            .filter(|message| message["role"] == "system")
            .collect();
        assert_eq!(system.len(), 1, "{label}: one system directive");
        let directive = system[0]["content"].as_str().unwrap();
        assert_eq!(
            directive.matches(MARKER).count(),
            1,
            "{label}: the selected agent body must reach the provider once"
        );
        assert!(
            directive.ends_with(BODY),
            "{label}: complete multiline body"
        );
        assert_eq!(request.to_string().matches(MARKER).count(), 1, "{label}");
        assert!(
            messages
                .iter()
                .filter(|m| m["role"] != "system")
                .all(|m| { !m["content"].as_str().unwrap_or_default().contains(MARKER) })
        );
    }
}
#[test]
fn agent_instructions_empty_profiles_preserve_existing_system_directive() {
    let f = Fixture::new();
    std::fs::create_dir(f.home.join("agents")).unwrap();
    std::fs::write(
        f.home.join("agents/empty-reviewer.md"),
        "---\nname: empty-reviewer\ndescription: Review without extra instructions\ntools: [Read]\nmodel: a/family/pinned-notools\n---\n\n \t\n",
    )
    .unwrap();
    for (agent, expected) in [
        (
            "empty-reviewer",
            "You are empty-reviewer, a subagent. Review without extra instructions\n\nComplete the task and reply with your final report. You do not see the parent conversation.",
        ),
        (
            "Explore",
            "You are Explore, a subagent. Read-only exploration; returns a thorough report\n\nComplete the task and reply with your final report. You do not see the parent conversation.",
        ),
    ] {
        let result = f.task(json!({"agent": agent, "prompt": "observe the evidence"}));
        assert_eq!(result["ok"], true, "{agent}: {result}");
        let request = f.a.body();
        let system: Vec<_> = request["messages"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|message| message["role"] == "system")
            .collect();
        assert_eq!(system.len(), 1, "{agent}");
        assert_eq!(system[0]["content"], expected, "{agent}");
        assert!(
            f.store()
                .load(&id(&result))
                .unwrap()
                .transcript
                .iter()
                .all(|message| message.role != orbit_adapter::types::ChatRole::System)
        );
    }
    assert_eq!(f.a.calls(), 2);
    assert_eq!(f.b.calls(), 0);
}
#[test]
fn ambiguous_bare_task_identity_fails_without_provider_or_agent() {
    let f = Fixture::new();
    let result = f.task(json!({"agent":"Explore","prompt":"implement","model":"shared/notools"}));
    assert_eq!(result["ok"], false);
    assert_eq!(f.a.calls() + f.b.calls(), 0);
    assert!(f.store().list().unwrap().is_empty());
}
#[test]
fn qualified_duplicate_raw_identity_reaches_selected_provider() {
    let f = Fixture::new();
    let result = f.task(json!({"agent":"Explore","prompt":"implement","model":"a/shared/notools"}));
    assert_eq!(result["ok"], true, "{result}");
    assert_eq!(f.a.body()["model"], "shared/notools");
    assert_eq!(f.a.calls(), 1);
    assert_eq!(f.b.calls(), 0);
}
#[test]
fn routed_target_uses_own_default_effort_and_preserves_parent_selection() {
    let f = Fixture::new();
    let mut base = orbit_cli::phase_routing::resolve_model(
        &orbit_cli::config::ProvidersConfig::load(&f.home).unwrap(),
        "a/family/base-notools",
        None,
    )
    .unwrap()
    .turn_config(None)
    .unwrap();
    let high = orbit_adapter::types::EffortSetting::Value(
        orbit_adapter::types::EffortValue::Level("high".into()),
    );
    orbit_cli::apply_effort_setting(&f.home, &mut base, &high).unwrap();
    tool_runtime::remember_turn_config(&f.cx, &base);
    tool_runtime::remember_effort_setting(&f.cx, &Some(high.clone()));
    let result = f.task(json!({"agent":"Explore","prompt":"implement a parser"}));
    assert_eq!(result["ok"], true, "{result}");
    assert_eq!(f.b.body()["reasoning_effort"], "medium");
    let after = f.cx.ext::<tool_runtime::SessionTurnConfig>().unwrap();
    assert_eq!(after.0.model, "family/base-notools");
    assert_eq!(after.0.effort, base.effort);
    assert_eq!(
        f.cx.ext::<tool_runtime::SessionEffortSetting>().unwrap().0,
        Some(high)
    );
}
#[test]
fn incompatible_explicit_effort_refuses_before_agent_creation() {
    let f = Fixture::new();
    let result = f.task(json!({"agent":"Explore","prompt":"implement a parser","effort":"high"}));
    assert_eq!(result["ok"], false, "{result}");
    assert_eq!(f.a.calls() + f.b.calls(), 0);
    assert!(f.store().list().unwrap().is_empty());
}
#[test]
fn routed_parent_inherits_new_model_default_without_base_override_leak() {
    let f = Fixture::new();
    let path = f.home.join("providers.toml");
    let mut value: toml::Value = toml::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    value.as_table_mut().unwrap().remove("roles");
    std::fs::write(path, toml::to_string(&value).unwrap()).unwrap();
    let mut base = orbit_cli::phase_routing::resolve_model(
        &orbit_cli::config::ProvidersConfig::load(&f.home).unwrap(),
        "a/family/base-notools",
        None,
    )
    .unwrap()
    .turn_config(None)
    .unwrap();
    orbit_cli::apply_effort_setting(
        &f.home,
        &mut base,
        &orbit_adapter::types::EffortSetting::Value(orbit_adapter::types::EffortValue::Level(
            "high".into(),
        )),
    )
    .unwrap();
    let routed = orbit_cli::try_phase_turn_config(
        &f.home,
        &base,
        "implement parent",
        orbit_cli::phase_routing::SelectionOrigin::Default,
    )
    .unwrap()
    .0;
    assert_eq!(routed.provider_id, "b");
    tool_runtime::remember_turn_config(&f.cx, &routed);
    tool_runtime::remember_effort_setting(&f.cx, &None);
    let result = f.task(json!({"agent":"Explore","prompt":"observe files"}));
    assert_eq!(result["ok"], true, "{result}");
    assert_eq!(f.b.body()["reasoning_effort"], "medium");
    assert_eq!(f.b.calls(), 1);
    assert_eq!(f.a.calls(), 0);
    assert_eq!(base.model, "family/base-notools");
    assert_eq!(
        base.effort,
        Some(orbit_adapter::types::EffortValue::Level("high".into()))
    );
    assert_eq!(
        f.cx.ext::<tool_runtime::SessionTurnConfig>()
            .unwrap()
            .0
            .model,
        "family/routed-notools"
    );
    assert!(
        f.cx.ext::<tool_runtime::SessionEffortSetting>()
            .unwrap()
            .0
            .is_none()
    );
}
#[test]
fn invalid_phase_target_refuses_before_provider_or_agent() {
    let f = Fixture::new();
    f.configure("absent/no-model");
    let result = f.task(json!({"agent":"Explore","prompt":"implement"}));
    assert_eq!(result["ok"], false);
    assert_eq!(f.a.calls() + f.b.calls(), 0);
    assert!(f.store().list().unwrap().is_empty());
}
#[test]
fn cancelled_parent_keeps_routed_agent_durable_without_provider_call() {
    let f = Fixture::new();
    f.cx.push_cancel_check(std::sync::Arc::new(|| true));
    let result = f.task(json!({"agent":"Explore","prompt":"implement a parser"}));
    f.cx.pop_cancel_check();
    assert_eq!(result["ok"], false, "{result}");
    assert_eq!(f.a.calls() + f.b.calls(), 0);
    let agent = f.store().list().unwrap().into_iter().next().unwrap();
    assert_eq!(agent.model, "b/family/routed-notools");
    assert_eq!(
        agent.status,
        orbit_engine::agent_store::AgentStatus::Cancelled
    );
}

const SAVED_TASK_RAW: &str = "family/shared-notools";
const SAVED_TASK_A: &str = "synthetic-task-private-a-034ddb";
const SAVED_TASK_B: &str = "synthetic-task-private-b-8bdc02";
const SAVED_TASK_B_NEXT: &str = "synthetic-task-private-b-next-d9f404";

struct SavedTaskFixture {
    fixture: Fixture,
    env_b: String,
    revision_b: orbit_adapter::provider_credentials::ProviderCredentialRevision,
}

impl SavedTaskFixture {
    fn new() -> Self {
        use orbit_adapter::provider_credentials::{ExpectedRevision, ProviderCredentialStore};
        let fixture = Fixture::new();
        let env_a = format!("ORBIT_TASK_SAVE_A_{}", ulid::Ulid::new());
        let env_b = format!("ORBIT_TASK_SAVE_B_{}", ulid::Ulid::new());
        assert!(std::env::var_os(&env_a).is_none());
        assert!(std::env::var_os(&env_b).is_none());
        let config = format!(
            "[[provider]]\nname='a'\nurl={:?}\nenv={env_a:?}\n\
             [[provider.models]]\nid={SAVED_TASK_RAW:?}\ncontext_window=65536\nmax_output_tokens=1111\n\
             [[provider]]\nname='b'\nurl={:?}\nenv={env_b:?}\n\
             [[provider.models]]\nid={SAVED_TASK_RAW:?}\ncontext_window=131072\nmax_output_tokens=733\n\
             supported_efforts=['medium','high']\ndefault_effort='medium'\n\
             [roles]\nmain='a/{SAVED_TASK_RAW}'\nexplore='a/{SAVED_TASK_RAW}'\nsubagent='a/{SAVED_TASK_RAW}'\n\
             [routing.phases.coding]\ndefault='b/{SAVED_TASK_RAW}'\nhard='b/{SAVED_TASK_RAW}'\n\
             [routing.phase_keywords]\nclear=true\ncoding=['implement']\n",
            fixture.a.url, fixture.b.url
        );
        std::fs::write(fixture.home.join("providers.toml"), config).unwrap();
        std::fs::set_permissions(
            fixture.home.join("providers.toml"),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        let store = ProviderCredentialStore::new(&fixture.home).unwrap();
        store
            .save(
                &Self::identity(&fixture, "a", &env_a),
                orbit_adapter::SecretBytes::new(SAVED_TASK_A.as_bytes().to_vec()),
                ExpectedRevision::Absent,
            )
            .unwrap();
        let revision_b = store
            .save(
                &Self::identity(&fixture, "b", &env_b),
                orbit_adapter::SecretBytes::new(SAVED_TASK_B.as_bytes().to_vec()),
                ExpectedRevision::Absent,
            )
            .unwrap()
            .revision;
        let parent = orbit_cli::checked_model_turn(
            &fixture.home,
            "a/family/shared-notools",
            None,
            None,
            false,
        )
        .unwrap();
        assert_eq!(parent.supported_efforts, None);
        assert_eq!(parent.effort, None);
        tool_runtime::remember_turn_config(&fixture.cx, &parent);
        tool_runtime::remember_effort_setting(&fixture.cx, &None);
        Self {
            fixture,
            env_b,
            revision_b,
        }
    }

    fn identity(
        fixture: &Fixture,
        provider_id: &str,
        env: &str,
    ) -> orbit_adapter::provider_credentials::ProviderAuthIdentity {
        let config = orbit_cli::config::ProvidersConfig::load(&fixture.home).unwrap();
        let provider = config
            .provider
            .iter()
            .find(|p| p.name == provider_id)
            .unwrap();
        let endpoint = orbit_cli::config::validate_provider_endpoint(&provider.url).unwrap();
        orbit_adapter::provider_credentials::ProviderAuthIdentity::new(
            provider_id,
            &provider.kind,
            endpoint.as_str(),
            Some(env),
        )
        .unwrap()
    }

    fn assert_call(provider: &Mock, index: usize, key: &str, max: u64, effort: Option<&str>) {
        let bodies = provider.bodies();
        let metadata = provider.request_metadata();
        assert_eq!(bodies.len(), metadata.len(), "one metadata record per POST");
        assert_eq!(metadata[index]["method"], "POST");
        assert_eq!(metadata[index]["path"], "/v1/chat/completions");
        assert_eq!(
            metadata[index]["authorization"],
            json!([format!("Bearer {key}")])
        );
        assert_eq!(metadata[index]["x_api_key"], json!([]));
        assert_eq!(bodies[index]["model"], SAVED_TASK_RAW);
        assert_eq!(bodies[index]["max_tokens"], max);
        match effort {
            Some(value) => assert_eq!(bodies[index]["reasoning_effort"], value),
            None => assert!(bodies[index].get("reasoning_effort").is_none()),
        }
        assert!(bodies[index].get("context_window").is_none());
        assert!(bodies[index].get("window_tokens").is_none());
        assert!(!bodies[index].to_string().contains(key));
    }

    fn assert_no_keys_in_parent_or_durable_state(&self, result: &Value) {
        let f = &self.fixture;
        let public = format!(
            "{result}\n{:?}\n{:?}",
            f.cx.ext::<tool_runtime::SessionTurnConfig>().unwrap().0,
            f.store().list().unwrap()
        );
        for key in [SAVED_TASK_A, SAVED_TASK_B, SAVED_TASK_B_NEXT] {
            assert!(!public.contains(key));
        }
        fn visit(path: &std::path::Path) {
            if path.is_dir() {
                for entry in std::fs::read_dir(path).unwrap() {
                    visit(&entry.unwrap().path());
                }
            } else {
                let bytes = std::fs::read(path).unwrap();
                for key in [SAVED_TASK_A, SAVED_TASK_B, SAVED_TASK_B_NEXT] {
                    assert!(
                        !bytes.windows(key.len()).any(|w| w == key.as_bytes()),
                        "secret copied outside private store: {}",
                        path.display()
                    );
                }
            }
        }
        for relative in ["providers.toml", "agents", "sessions", "ledger"] {
            let path = f.home.join(relative);
            if path.exists() {
                visit(&path);
            }
        }
    }
}

#[test]
fn saved_private_fresh_routed_child_uses_target_key_duplicate_raw_output_and_default_effort() {
    use orbit_adapter::types::EffortSetting;
    let f = SavedTaskFixture::new();
    assert_eq!(f.fixture.a.calls() + f.fixture.b.calls(), 0);
    let result = f
        .fixture
        .task(json!({"agent":"Explore","prompt":"implement a comprehensive parser"}));
    assert_eq!(result["ok"], true, "{result}");
    assert_eq!(result["result"]["model"], "b/family/shared-notools");
    assert_eq!(f.fixture.a.calls(), 0);
    assert_eq!(f.fixture.b.calls(), 1);
    SavedTaskFixture::assert_call(&f.fixture.b, 0, SAVED_TASK_B, 733, Some("medium"));
    let saved = f.fixture.store().load(&id(&result)).unwrap();
    assert_eq!(saved.model, "b/family/shared-notools");
    assert_eq!(saved.effort, Some(EffortSetting::Default));
    assert_eq!(saved.turns, 1);
    assert_eq!(
        saved.status,
        orbit_engine::agent_store::AgentStatus::Completed
    );
    let parent_config = f
        .fixture
        .cx
        .ext::<tool_runtime::SessionTurnConfig>()
        .unwrap();
    let parent = &parent_config.0;
    assert_eq!(parent.provider_id, "a");
    assert_eq!(parent.model, SAVED_TASK_RAW);
    assert_eq!(parent.max_output_tokens, 1111);
    assert_eq!(parent.supported_efforts, None);
    assert_eq!(parent.effort, None);
    f.assert_no_keys_in_parent_or_durable_state(&result);
}

#[test]
fn saved_private_explicit_child_override_uses_a_key_and_omits_unknown_effort_control() {
    use orbit_adapter::types::EffortSetting;
    let f = SavedTaskFixture::new();
    let result = f.fixture.task(json!({"agent":"Explore","prompt":"implement a comprehensive parser","model":"a/family/shared-notools"}));
    assert_eq!(result["ok"], true, "{result}");
    assert_eq!(result["result"]["model"], "a/family/shared-notools");
    assert_eq!(f.fixture.a.calls(), 1);
    assert_eq!(f.fixture.b.calls(), 0);
    SavedTaskFixture::assert_call(&f.fixture.a, 0, SAVED_TASK_A, 1111, None);
    let saved = f.fixture.store().load(&id(&result)).unwrap();
    assert_eq!(saved.model, "a/family/shared-notools");
    assert_eq!(saved.effort, Some(EffortSetting::Default));
    assert_eq!(
        saved.status,
        orbit_engine::agent_store::AgentStatus::Completed
    );
    f.assert_no_keys_in_parent_or_durable_state(&result);
}

#[test]
fn saved_private_resumed_child_reresolves_rotated_b_key_with_saved_explicit_effort() {
    use orbit_adapter::provider_credentials::{ExpectedRevision, ProviderCredentialStore};
    use orbit_adapter::types::{EffortSetting, EffortValue};
    let mut f = SavedTaskFixture::new();
    let first = f
        .fixture
        .task(json!({"agent":"Explore","prompt":"implement first","effort":"high"}));
    assert_eq!(first["ok"], true, "{first}");
    let agent_id = id(&first);
    let saved_first = f.fixture.store().load(&agent_id).unwrap();
    assert_eq!(saved_first.model, "b/family/shared-notools");
    let expected_effort = Some(EffortSetting::Value(EffortValue::Level("high".into())));
    assert_eq!(saved_first.effort, expected_effort);
    ProviderCredentialStore::new(&f.fixture.home)
        .unwrap()
        .save(
            &SavedTaskFixture::identity(&f.fixture, "b", &f.env_b),
            orbit_adapter::SecretBytes::new(SAVED_TASK_B_NEXT.as_bytes().to_vec()),
            ExpectedRevision::Exact(f.revision_b),
        )
        .unwrap();
    let path = f.fixture.home.join("providers.toml");
    let mut config: toml::Value = toml::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    config["routing"]["phases"]["coding"]["default"] =
        toml::Value::String("a/family/shared-notools".into());
    config["routing"]["phases"]["coding"]["hard"] =
        toml::Value::String("a/family/shared-notools".into());
    std::fs::write(path, toml::to_string(&config).unwrap()).unwrap();
    let workspace = f.fixture.cx.working_dir.clone();
    f.fixture.cx = orbit_tools::ToolContext::new(f.fixture.home.clone(), "owner".into(), workspace);
    let parent = orbit_cli::checked_model_turn(
        &f.fixture.home,
        "a/family/shared-notools",
        None,
        None,
        false,
    )
    .unwrap();
    tool_runtime::remember_turn_config(&f.fixture.cx, &parent);
    tool_runtime::remember_effort_setting(&f.fixture.cx, &None);
    assert_eq!(f.fixture.a.calls(), 0);
    assert_eq!(
        f.fixture.b.calls(),
        1,
        "fresh parent/store reload is offline"
    );
    let resumed = f
        .fixture
        .task(json!({"agent":"Explore","resume":agent_id,"prompt":"implement next"}));
    assert_eq!(resumed["ok"], true, "{resumed}");
    assert_eq!(id(&resumed), id(&first));
    assert_eq!(resumed["result"]["model"], "b/family/shared-notools");
    assert_eq!(f.fixture.a.calls(), 0);
    assert_eq!(f.fixture.b.calls(), 2);
    SavedTaskFixture::assert_call(&f.fixture.b, 0, SAVED_TASK_B, 733, Some("high"));
    SavedTaskFixture::assert_call(&f.fixture.b, 1, SAVED_TASK_B_NEXT, 733, Some("high"));
    let saved = f.fixture.store().load(&id(&resumed)).unwrap();
    assert_eq!(saved.turns, 2);
    assert_eq!(saved.effort, expected_effort);
    assert_eq!(
        saved.status,
        orbit_engine::agent_store::AgentStatus::Completed
    );
    assert!(saved.transcript.starts_with(&saved_first.transcript));
    f.assert_no_keys_in_parent_or_durable_state(&resumed);
}

const SAVED_CONTEXT_AGENT: &str = "saved-context-reviewer";
const SAVED_CONTEXT_MARKER: &str = "selected-child-context-instruction-c483be";
const SAVED_CONTEXT_BODY: &str =
    "selected-child-context-instruction-c483be\nRead the evidence and return a concise report.";
const SAVED_CONTEXT_PROMPT: &str = "implement the resumed context boundary review";
const SAVED_CONTEXT_WINDOW: u64 = 10_000;
const SAVED_CONTEXT_RESERVE: u64 = 8_192;

impl SavedTaskFixture {
    fn seed_selected_context_resume(
        &mut self,
        window: Option<u64>,
    ) -> orbit_engine::agent_store::AgentSnapshot {
        use orbit_adapter::types::{EffortSetting, EffortValue};
        use orbit_engine::agent_store::AgentStatus;

        let path = self.fixture.home.join("providers.toml");
        let mut config: toml::Value =
            toml::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let models = config["provider"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|provider| provider["name"].as_str() == Some("b"))
            .unwrap()["models"]
            .as_array_mut()
            .unwrap();
        assert_eq!(models.len(), 1);
        assert_eq!(models[0]["id"].as_str(), Some(SAVED_TASK_RAW));
        match window {
            Some(window) => {
                models[0]["context_window"] = toml::Value::Integer(window.try_into().unwrap());
            }
            None => {
                models[0].as_table_mut().unwrap().remove("context_window");
            }
        }
        let parent_window = if window.is_some() {
            65_536u64
        } else {
            SAVED_CONTEXT_WINDOW
        };
        if window.is_none() {
            // This control deliberately makes only A small: inheriting the
            // parent's window would incorrectly add a summary for unknown B.
            let parent = config["provider"]
                .as_array_mut()
                .unwrap()
                .iter_mut()
                .find(|provider| provider["name"].as_str() == Some("a"))
                .unwrap();
            parent["models"][0]["context_window"] =
                toml::Value::Integer(parent_window.try_into().unwrap());
        }
        // A route changed after the durable B pin must not redirect housekeeping
        // or continuation, even though A and B declare an identical raw ID.
        config["routing"]["phases"]["coding"]["default"] =
            toml::Value::String(format!("a/{SAVED_TASK_RAW}"));
        config["routing"]["phases"]["coding"]["hard"] =
            toml::Value::String(format!("a/{SAVED_TASK_RAW}"));
        assert!(config["roles"].get("compaction").is_none());
        std::fs::write(&path, toml::to_string(&config).unwrap()).unwrap();

        let profiles = self.fixture.home.join("agents");
        std::fs::create_dir_all(&profiles).unwrap();
        std::fs::set_permissions(&profiles, std::fs::Permissions::from_mode(0o700)).unwrap();
        let profile = profiles.join(format!("{SAVED_CONTEXT_AGENT}.md"));
        std::fs::write(&profile, format!(
            "---\nname: {SAVED_CONTEXT_AGENT}\ndescription: Review selected context evidence\nmodel: b/{SAVED_TASK_RAW}\neffort: medium\ntools: [Read]\nmaxTurns: 2\n---\n\n{SAVED_CONTEXT_BODY}\n"
        )).unwrap();
        std::fs::set_permissions(profile, std::fs::Permissions::from_mode(0o600)).unwrap();

        let mut transcript = Vec::new();
        for pair in 0..10 {
            transcript.push(orbit_engine::user_message(format!(
                "OLD-CONTEXT-{pair:02}-user {}",
                "x".repeat(1_200)
            )));
            transcript.push(orbit_engine::assistant_message(format!(
                "OLD-CONTEXT-{pair:02}-assistant {}",
                "y".repeat(1_200)
            )));
        }
        for pair in 0..3 {
            transcript.push(orbit_engine::user_message(format!(
                "recent-small-user-{pair}"
            )));
            transcript.push(orbit_engine::assistant_message(format!(
                "recent-small-assistant-{pair}"
            )));
        }
        // The engine appends the current prompt before checking its existing
        // threshold. This precondition separates B's exact selected limit from A.
        let mut upcoming = transcript.clone();
        upcoming.push(orbit_engine::user_message(SAVED_CONTEXT_PROMPT));
        let estimated = orbit_engine::turn::estimate_transcript_tokens(&upcoming);
        let b_threshold = SAVED_CONTEXT_WINDOW.saturating_sub(SAVED_CONTEXT_RESERVE) / 10 * 9;
        let a_threshold = 65_536u64.saturating_sub(SAVED_CONTEXT_RESERVE) / 10 * 9;
        assert!(estimated > b_threshold && estimated < a_threshold);
        assert!(serde_json::to_vec(&transcript).unwrap().len() < 64 * 1024);

        let effort = Some(EffortSetting::Value(EffortValue::Level("high".into())));
        let store = self.fixture.store();
        let created = store
            .create_with_effort(
                SAVED_CONTEXT_AGENT,
                Some("context evidence"),
                &format!("b/{SAVED_TASK_RAW}"),
                effort.clone(),
                None,
            )
            .unwrap();
        let seeded = store
            .begin(&created.agent_id, None)
            .unwrap()
            .finish(
                transcript,
                "seeded durable context fixture".into(),
                AgentStatus::Completed,
                13,
            )
            .unwrap();
        assert_eq!(seeded.effort, effort);
        assert_eq!(
            self.fixture
                .store()
                .load(&created.agent_id)
                .unwrap()
                .transcript,
            seeded.transcript
        );

        // Resolve a fresh parent and store context; no previously retained child
        // config, credentials or observer state can supply the selected window.
        let workspace = self.fixture.cx.working_dir.clone();
        self.fixture.cx =
            orbit_tools::ToolContext::new(self.fixture.home.clone(), "owner".into(), workspace);
        let parent = orbit_cli::checked_model_turn(
            &self.fixture.home,
            &format!("a/{SAVED_TASK_RAW}"),
            None,
            None,
            false,
        )
        .unwrap();
        assert_eq!(
            orbit_cli::context_window_for_turn(&self.fixture.home, &parent),
            Some(parent_window)
        );
        let child = orbit_cli::checked_model_turn(
            &self.fixture.home,
            &format!("b/{SAVED_TASK_RAW}"),
            None,
            None,
            false,
        )
        .unwrap();
        assert_eq!(
            orbit_cli::context_window_for_turn(&self.fixture.home, &child),
            window
        );
        tool_runtime::remember_turn_config(&self.fixture.cx, &parent);
        tool_runtime::remember_effort_setting(&self.fixture.cx, &None);
        assert_eq!(
            self.fixture.a.calls() + self.fixture.b.calls(),
            0,
            "seeding/reloading is offline"
        );
        seeded
    }

    fn resume_selected_context(&self, agent_id: &str) -> Value {
        self.fixture
            .task(json!({"agent": SAVED_CONTEXT_AGENT, "resume": agent_id,
            "prompt": SAVED_CONTEXT_PROMPT, "model": format!("b/{SAVED_TASK_RAW}")}))
    }

    fn assert_selected_context_normal(&self, body: &Value) {
        let tools: Vec<_> = body["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|tool| tool["function"]["name"].as_str().unwrap())
            .collect();
        assert_eq!(
            tools,
            ["Read"],
            "normal continuation preserves profile restriction"
        );
        let messages = body["messages"].as_array().unwrap();
        let system: Vec<_> = messages
            .iter()
            .filter(|message| message["role"] == "system")
            .collect();
        assert_eq!(system.len(), 1);
        let directive = system[0]["content"].as_str().unwrap();
        assert_eq!(directive.matches(SAVED_CONTEXT_MARKER).count(), 1);
        assert!(directive.ends_with(SAVED_CONTEXT_BODY));
        assert_eq!(body.to_string().matches(SAVED_CONTEXT_MARKER).count(), 1);
        assert!(body.get("context_window").is_none() && body.get("window_tokens").is_none());
        assert_eq!(messages.last().unwrap()["role"], "user");
        assert_eq!(messages.last().unwrap()["content"], SAVED_CONTEXT_PROMPT);
    }

    fn assert_selected_context_parent_unchanged(&self, before: &str, result: &Value) {
        assert_eq!(
            format!(
                "{:?}",
                self.fixture
                    .cx
                    .ext::<tool_runtime::SessionTurnConfig>()
                    .unwrap()
                    .0
            ),
            before
        );
        assert_eq!(
            self.fixture
                .cx
                .ext::<tool_runtime::SessionEffortSetting>()
                .unwrap()
                .0,
            None
        );
        self.assert_no_keys_in_parent_or_durable_state(result);
    }
}

#[test]
fn saved_private_resumed_child_compacts_for_exact_b_window_then_continues_with_b_auth_and_tail() {
    use orbit_adapter::types::{ChatRole, EffortSetting, EffortValue};
    use orbit_engine::agent_store::AgentStatus;

    let mut f = SavedTaskFixture::new();
    let seeded = f.seed_selected_context_resume(Some(SAVED_CONTEXT_WINDOW));
    let parent_before = format!(
        "{:?}",
        f.fixture
            .cx
            .ext::<tool_runtime::SessionTurnConfig>()
            .unwrap()
            .0
    );
    let result = f.resume_selected_context(&seeded.agent_id);
    assert_eq!(result["ok"], true, "{result}");
    assert_eq!(id(&result), seeded.agent_id);
    assert_eq!(result["result"]["model"], format!("b/{SAVED_TASK_RAW}"));
    assert_eq!(f.fixture.a.calls(), 0);
    assert_eq!(
        f.fixture.b.calls(),
        2,
        "one B summary POST precedes one B continuation POST"
    );
    for index in 0..2 {
        SavedTaskFixture::assert_call(&f.fixture.b, index, SAVED_TASK_B, 733, Some("high"));
    }
    let bodies = f.fixture.b.bodies();
    let summary = &bodies[0];
    assert!(
        summary
            .get("tools")
            .is_none_or(|tools| tools.as_array().is_some_and(Vec::is_empty))
    );
    let summary_messages = summary["messages"].as_array().unwrap();
    assert_eq!(summary_messages.len(), 1);
    assert_eq!(summary_messages[0]["role"], "user");
    let summary_prompt = summary_messages[0]["content"].as_str().unwrap();
    assert!(summary_prompt.starts_with("Summarize this conversation for continuation."));
    assert!(
        summary_prompt.contains("OLD-CONTEXT-00-user")
            && summary_prompt.contains("OLD-CONTEXT-09-assistant")
    );
    assert!(
        !summary_prompt.contains(SAVED_CONTEXT_PROMPT)
            && !summary_prompt.contains(SAVED_CONTEXT_MARKER)
    );
    assert!(
        summary_prompt.len() < 10_000,
        "summary fixture remains bounded after prefix truncation"
    );

    let continuation = &bodies[1];
    f.assert_selected_context_normal(continuation);
    let non_system: Vec<_> = continuation["messages"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|message| message["role"] != "system")
        .collect();
    assert_eq!(
        non_system.len(),
        7,
        "one summary plus all six retained messages"
    );
    assert!(
        non_system[0]["content"]
            .as_str()
            .unwrap()
            .starts_with("[context compacted from 21 older messages]")
    );
    assert!(
        non_system[0]["content"]
            .as_str()
            .unwrap()
            .ends_with("owned fixture reply")
    );
    assert!(!continuation.to_string().contains("OLD-CONTEXT-"));
    let mut expected_tail = seeded.transcript[seeded.transcript.len() - 5..].to_vec();
    expected_tail.push(orbit_engine::user_message(SAVED_CONTEXT_PROMPT));
    for (wire, expected) in non_system[1..].iter().zip(&expected_tail) {
        assert_eq!(wire["role"], expected.role.as_str());
        assert_eq!(wire["content"], expected.content);
    }
    // A byte-size guard keeps this particular fixture comfortably bounded; it
    // is not a tokenizer or a general whole-request/context accounting proof.
    assert!(
        continuation.to_string().len()
            < ((SAVED_CONTEXT_WINDOW - SAVED_CONTEXT_RESERVE) * 4) as usize
    );
    let saved = f.fixture.store().load(&seeded.agent_id).unwrap();
    assert_eq!(saved.model, format!("b/{SAVED_TASK_RAW}"));
    assert_eq!(saved.status, AgentStatus::Completed);
    assert_eq!(saved.turns, 14);
    assert_eq!(
        saved.effort,
        Some(EffortSetting::Value(EffortValue::Level("high".into())))
    );
    assert_eq!(saved.transcript.len(), 8);
    assert_eq!(&saved.transcript[1..7], expected_tail.as_slice());
    assert_eq!(saved.transcript.last().unwrap().role, ChatRole::Assistant);
    assert_eq!(
        saved.transcript.last().unwrap().content,
        "owned fixture reply"
    );
    f.assert_selected_context_parent_unchanged(&parent_before, &result);
}

#[test]
fn saved_private_resumed_child_with_unknown_b_window_continues_once_without_summary_or_parent_window()
 {
    let mut f = SavedTaskFixture::new();
    let seeded = f.seed_selected_context_resume(None);
    let parent_before = format!(
        "{:?}",
        f.fixture
            .cx
            .ext::<tool_runtime::SessionTurnConfig>()
            .unwrap()
            .0
    );
    let result = f.resume_selected_context(&seeded.agent_id);
    assert_eq!(result["ok"], true, "{result}");
    assert_eq!(id(&result), seeded.agent_id);
    assert_eq!(f.fixture.a.calls(), 0);
    assert_eq!(
        f.fixture.b.calls(),
        1,
        "an unknown child window must not invent a summary request"
    );
    SavedTaskFixture::assert_call(&f.fixture.b, 0, SAVED_TASK_B, 733, Some("high"));
    let body = f.fixture.b.body();
    f.assert_selected_context_normal(&body);
    let messages = body["messages"].as_array().unwrap();
    let non_system: Vec<_> = messages
        .iter()
        .filter(|message| message["role"] != "system")
        .collect();
    assert_eq!(non_system.len(), seeded.transcript.len() + 1);
    for (wire, expected) in non_system.iter().zip(&seeded.transcript) {
        assert_eq!(wire["role"], expected.role.as_str());
        assert_eq!(wire["content"], expected.content);
    }
    assert!(
        !body
            .to_string()
            .contains("Summarize this conversation for continuation.")
    );
    assert!(!body.to_string().contains("[context compacted"));
    let saved = f.fixture.store().load(&seeded.agent_id).unwrap();
    assert_eq!(saved.model, seeded.model);
    assert_eq!(saved.effort, seeded.effort);
    assert_eq!(saved.turns, 14);
    assert_eq!(
        saved.status,
        orbit_engine::agent_store::AgentStatus::Completed
    );
    assert!(saved.transcript.starts_with(&seeded.transcript));
    assert_eq!(saved.transcript.len(), seeded.transcript.len() + 2);
    f.assert_selected_context_parent_unchanged(&parent_before, &result);
}
