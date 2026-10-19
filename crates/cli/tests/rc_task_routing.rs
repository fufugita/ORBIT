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
                models[0].as_table_mut().unwrap().insert(
                    "context_limits".into(),
                    toml::Value::try_from(json!({"input_tokens": window})).unwrap(),
                );
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
                "x".repeat(2_000)
            )));
            transcript.push(orbit_engine::assistant_message(format!(
                "OLD-CONTEXT-{pair:02}-assistant {}",
                "y".repeat(2_000)
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
        // Complete old messages exceed B's explicit input policy even without
        // the old 8192 reserve. Actual continuation system/tools are checked below.
        let mut upcoming = transcript.clone();
        upcoming.push(orbit_engine::user_message(SAVED_CONTEXT_PROMPT));
        assert!(serde_json::to_vec(&upcoming).unwrap().len() > (SAVED_CONTEXT_WINDOW * 4) as usize);
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

    fn assert_complete_context_compaction(
        &self,
        summary: &Value,
        continuation: &Value,
        seeded: &orbit_engine::agent_store::AgentSnapshot,
    ) -> Vec<orbit_adapter::types::ChatMessage> {
        use orbit_adapter::types::ChatRole;

        let messages = summary["messages"].as_array().unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0]["role"], "user");
        let prompt = messages[0]["content"].as_str().unwrap();
        let (directive, data) = prompt.split_once("\n\n").unwrap();
        assert!(directive.starts_with("Summarize this conversation for continuation."));
        let records: Vec<Value> = serde_json::from_str(data).unwrap();
        let boundary = records.len();
        assert!(boundary > 0 && boundary < seeded.transcript.len());
        assert_eq!(
            boundary % 2,
            0,
            "only complete historical exchanges may be summarized"
        );
        assert!(seeded.transcript.len() >= 2);
        assert!(
            boundary <= seeded.transcript.len() - 2,
            "the newest complete historical exchange must remain"
        );
        for (index, message) in seeded.transcript.iter().enumerate() {
            assert_eq!(
                message.role,
                if index % 2 == 0 {
                    ChatRole::User
                } else {
                    ChatRole::Assistant
                }
            );
            assert!(
                message.blocks.is_none()
                    && message.tool_calls.is_none()
                    && message.tool_call_id.is_none()
                    && message.tool_result.is_none()
            );
        }
        let expected_records: Vec<_> = seeded.transcript[..boundary]
            .iter()
            .map(|message| json!({"role":message.role.as_str(),"text":[message.content]}))
            .collect();
        assert_eq!(
            records, expected_records,
            "the actual summary must receive the full exact contiguous source prefix without truncation or invented tool fields"
        );
        assert!(!prompt.contains(SAVED_CONTEXT_PROMPT) && !prompt.contains(SAVED_CONTEXT_MARKER));

        let mut original = seeded.transcript.clone();
        original.push(orbit_engine::user_message(SAVED_CONTEXT_PROMPT));
        let retained = &original[boundary..];
        assert!(retained.len() >= 3);
        assert_eq!(
            &retained[retained.len() - 3..],
            &original[original.len() - 3..]
        );
        let mut candidate = vec![
            orbit_engine::user_message("[Earlier conversation summary: historical data]"),
            orbit_engine::assistant_message("owned fixture reply"),
        ];
        candidate.extend_from_slice(retained);
        let expected_wire: Vec<_> = candidate
            .iter()
            .map(|message| json!({"role":message.role.as_str(),"content":message.content}))
            .collect();
        let actual_wire: Vec<_> = continuation["messages"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|message| message["role"] != "system")
            .cloned()
            .collect();
        assert_eq!(
            actual_wire, expected_wire,
            "the closed summary exchange must precede the complete exact retained suffix and current intent"
        );

        let directory = self
            .fixture
            .home
            .join("context-history")
            .join(&seeded.owner_session_id)
            .join("archives");
        let metadata = std::fs::symlink_metadata(&directory).unwrap();
        assert!(metadata.is_dir() && !metadata.file_type().is_symlink());
        let records: Vec<_> = std::fs::read_dir(&directory)
            .unwrap()
            .take(2)
            .map(|entry| entry.unwrap())
            .collect();
        assert_eq!(
            records.len(),
            1,
            "this operation must publish exactly one full original archive"
        );
        let entry = &records[0];
        let kind = entry.file_type().unwrap();
        assert!(kind.is_file() && !kind.is_symlink());
        let name = entry.file_name().into_string().unwrap();
        let record_id = name.strip_suffix(".json").unwrap();
        let suffix = record_id.strip_prefix("compact-").unwrap();
        assert_eq!(suffix.parse::<ulid::Ulid>().unwrap().to_string(), suffix);
        let recovered = orbit_cli::context_history::load_compaction_source(
            &self.fixture.home,
            &seeded.owner_session_id,
            Some(&seeded.agent_id),
            record_id,
        )
        .unwrap();
        assert_eq!(
            recovered, original,
            "qualified inert recovery must return every full typed historical message plus the current User"
        );
        candidate
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
        !summary_prompt.contains(SAVED_CONTEXT_PROMPT)
            && !summary_prompt.contains(SAVED_CONTEXT_MARKER)
    );

    let continuation = &bodies[1];
    f.assert_selected_context_normal(continuation);
    // Reconstruct the unsummarized request from the actual normal wire body:
    // keep its frozen system/tools/output/effort, substitute the complete source.
    let mut original_request = continuation.clone();
    let mut original_messages: Vec<_> = continuation["messages"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|message| message["role"] == "system")
        .cloned()
        .collect();
    original_messages.extend(seeded.transcript.iter().map(|message| {
        assert!(
            message.blocks.is_none()
                && message.tool_calls.is_none()
                && message.tool_result.is_none()
        );
        json!({"role":message.role.as_str(),"content":message.content})
    }));
    original_messages.push(json!({"role":"user","content":SAVED_CONTEXT_PROMPT}));
    original_request["messages"] = Value::Array(original_messages);
    let original_bytes = serde_json::to_vec(&original_request).unwrap().len();
    let summary_bytes = serde_json::to_vec(summary).unwrap().len();
    let continuation_bytes = serde_json::to_vec(continuation).unwrap().len();
    assert!(original_bytes > (SAVED_CONTEXT_WINDOW * 4) as usize);
    assert!(original_bytes < (65_536 * 4) as usize);
    assert!(summary_bytes < (SAVED_CONTEXT_WINDOW / 10 * 9 * 4) as usize);
    assert!(continuation_bytes < (SAVED_CONTEXT_WINDOW / 10 * 9 * 4) as usize);
    assert_eq!(summary["max_tokens"], 733);
    assert_eq!(continuation["max_tokens"], 733);
    let mut expected = f.assert_complete_context_compaction(summary, continuation, &seeded);
    expected.push(orbit_engine::assistant_message("owned fixture reply"));
    // A byte-size guard keeps this particular fixture comfortably bounded; it
    // is not a tokenizer or a general whole-request/context accounting proof.
    assert!(continuation.to_string().len() < (SAVED_CONTEXT_WINDOW / 10 * 9 * 4) as usize);
    let saved = f.fixture.store().load(&seeded.agent_id).unwrap();
    assert_eq!(saved.model, format!("b/{SAVED_TASK_RAW}"));
    assert_eq!(saved.status, AgentStatus::Completed);
    assert_eq!(saved.turns, 14);
    assert_eq!(
        saved.effort,
        Some(EffortSetting::Value(EffortValue::Level("high".into())))
    );
    assert_eq!(saved.transcript.len(), expected.len());
    assert_eq!(saved.transcript, expected);
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

mod typed_task_budget_tracers {
    use super::*;
    use orbit_adapter::types::{ChatRole, EffortSetting, EffortValue};
    use orbit_engine::agent_store::{AgentSnapshot, AgentStatus};

    const CHILD_INPUT: u64 = 10_000;
    const PARENT_INPUT: u64 = 65_536;
    const SUMMARY_INPUT: u64 = 3_000;
    const SUMMARY_RAW: &str = "family/task-summary-notools";
    const SUMMARY_OUTPUT: u64 = 97;

    // Covers provider readiness, synchronous Task and teardown if a regression
    // stalls. Each owned Mock also retains its5s startup deadline and Drop kill.
    struct Watchdog {
        done: Option<std::sync::mpsc::Sender<()>>,
        join: Option<std::thread::JoinHandle<()>>,
    }
    impl Watchdog {
        fn new() -> Self {
            let (done, wait) = std::sync::mpsc::channel();
            let join = std::thread::spawn(move || {
                if matches!(
                    wait.recv_timeout(std::time::Duration::from_secs(30)),
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout)
                ) {
                    eprintln!("owned typed Task budget tracer exceeded finite watchdog");
                    std::process::exit(94);
                }
            });
            Self {
                done: Some(done),
                join: Some(join),
            }
        }
    }
    impl Drop for Watchdog {
        fn drop(&mut self) {
            if let Some(done) = self.done.take() {
                let _ = done.send(());
            }
            if let Some(join) = self.join.take() {
                join.join().unwrap();
            }
        }
    }

    fn configure_typed(f: &mut SavedTaskFixture, child_limits: Value, summary_input: Option<u64>) {
        let path = f.fixture.home.join("providers.toml");
        let mut config: toml::Value =
            toml::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        for provider in config["provider"].as_array_mut().unwrap() {
            let is_parent = provider["name"].as_str() == Some("a");
            for model in provider["models"].as_array_mut().unwrap() {
                if model["id"].as_str() == Some(SAVED_TASK_RAW) {
                    let table = model.as_table_mut().unwrap();
                    table.remove("context_window");
                    let limits = if is_parent {
                        json!({"input_tokens":PARENT_INPUT,"unknown_policy":"require-limit"})
                    } else {
                        child_limits.clone()
                    };
                    table.insert(
                        "context_limits".into(),
                        toml::Value::try_from(limits).unwrap(),
                    );
                }
            }
        }
        config["routing"]["phases"]["coding"]["default"] =
            toml::Value::String(format!("a/{SAVED_TASK_RAW}"));
        config["routing"]["phases"]["coding"]["hard"] =
            toml::Value::String(format!("a/{SAVED_TASK_RAW}"));
        config["roles"].as_table_mut().unwrap().remove("compaction");
        if let Some(input) = summary_input {
            let b = config["provider"]
                .as_array_mut()
                .unwrap()
                .iter_mut()
                .find(|provider| provider["name"].as_str() == Some("b"))
                .unwrap();
            b["models"].as_array_mut().unwrap().push(
                toml::Value::try_from(json!({
                    "id":SUMMARY_RAW,"max_output_tokens":SUMMARY_OUTPUT,
                    "supported_efforts":["low"],"default_effort":"low",
                    "context_limits":{"input_tokens":input,"unknown_policy":"require-limit"}
                }))
                .unwrap(),
            );
            config["roles"].as_table_mut().unwrap().insert(
                "compaction".into(),
                toml::Value::String(format!("b/{SUMMARY_RAW}")),
            );
        }
        std::fs::write(&path, toml::to_string(&config).unwrap()).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let parsed = orbit_cli::config::ProvidersConfig::load(&f.fixture.home).unwrap();
        orbit_cli::phase_routing::validate_providers(&parsed).unwrap();
        for provider in &parsed.provider {
            let model = provider
                .models
                .iter()
                .find(|model| model.id == SAVED_TASK_RAW)
                .unwrap();
            assert!(
                model.context_window.is_none(),
                "no legacy window may explain typed admission"
            );
            assert!(model.context_limits.is_some());
        }
        assert_ne!(parsed.provider[0].url, parsed.provider[1].url);

        // Install the same restricted profile as the retained resume fixture,
        // also usable by the new fitting/immutable fresh-Task controls.
        let profiles = f.fixture.home.join("agents");
        std::fs::create_dir_all(&profiles).unwrap();
        std::fs::set_permissions(&profiles, std::fs::Permissions::from_mode(0o700)).unwrap();
        let profile = profiles.join(format!("{SAVED_CONTEXT_AGENT}.md"));
        std::fs::write(&profile, format!(
            "---\nname: {SAVED_CONTEXT_AGENT}\ndescription: Review selected context evidence\nmodel: b/{SAVED_TASK_RAW}\neffort: medium\ntools: [Read]\nmaxTurns: 2\n---\n\n{SAVED_CONTEXT_BODY}\n"
        )).unwrap();
        std::fs::set_permissions(profile, std::fs::Permissions::from_mode(0o600)).unwrap();

        // Reconstruct the parent context so neither a remembered child config
        // nor a legacy-window extension can explain the observed result.
        let workspace = f.fixture.cx.working_dir.clone();
        f.fixture.cx =
            orbit_tools::ToolContext::new(f.fixture.home.clone(), "owner".into(), workspace);
        let parent = orbit_cli::checked_model_turn(
            &f.fixture.home,
            &format!("a/{SAVED_TASK_RAW}"),
            None,
            None,
            false,
        )
        .unwrap();
        let child = orbit_cli::checked_model_turn(
            &f.fixture.home,
            &format!("b/{SAVED_TASK_RAW}"),
            None,
            None,
            false,
        )
        .unwrap();
        assert_eq!(parent.model, child.model);
        assert_ne!(parent.provider_id, child.provider_id);
        assert_ne!(parent.gate, child.gate);
        assert_eq!(parent.max_output_tokens, 1111);
        assert_eq!(child.max_output_tokens, 733);
        assert!(orbit_cli::context_window_for_turn(&f.fixture.home, &parent).is_none());
        assert!(orbit_cli::context_window_for_turn(&f.fixture.home, &child).is_none());
        tool_runtime::remember_turn_config(&f.fixture.cx, &parent);
        tool_runtime::remember_effort_setting(&f.fixture.cx, &None);
        assert_eq!(
            f.fixture.a.calls() + f.fixture.b.calls(),
            0,
            "setup stays offline"
        );
    }

    fn seed_typed(f: &mut SavedTaskFixture, summary_input: Option<u64>) -> AgentSnapshot {
        let seeded = f.seed_selected_context_resume(None);
        configure_typed(
            f,
            json!({"input_tokens":CHILD_INPUT,"unknown_policy":"require-limit"}),
            summary_input,
        );
        let mut original = seeded.transcript.clone();
        original.push(orbit_engine::user_message(SAVED_CONTEXT_PROMPT));
        assert!(serde_json::to_vec(&original).unwrap().len() > (CHILD_INPUT * 4) as usize);
        assert!(serde_json::to_vec(&original).unwrap().len() < (PARENT_INPUT * 4) as usize);
        assert_eq!(
            f.fixture.store().load(&seeded.agent_id).unwrap().transcript,
            seeded.transcript
        );
        seeded
    }
    fn parent_state(f: &SavedTaskFixture) -> String {
        format!(
            "{:?}",
            f.fixture
                .cx
                .ext::<tool_runtime::SessionTurnConfig>()
                .unwrap()
                .0
        )
    }
    fn assert_workspace_empty(f: &SavedTaskFixture) {
        assert!(
            std::fs::read_dir(&f.fixture.cx.working_dir)
                .unwrap()
                .next()
                .is_none()
        );
    }
    fn assert_selected_posts_within_child_input(f: &SavedTaskFixture) {
        for body in f.fixture.b.bodies() {
            if body["model"] == SAVED_TASK_RAW {
                assert!(
                    serde_json::to_vec(&body).unwrap().len() <= (CHILD_INPUT * 4) as usize,
                    "an oversized unsummarized child POST escaped its exact typed input policy"
                );
            }
        }
    }
    fn assert_summary_request(f: &SavedTaskFixture, index: usize, input: u64, independent: bool) {
        let body = &f.fixture.b.bodies()[index];
        let metadata = &f.fixture.b.request_metadata()[index];
        assert_eq!(metadata["method"], "POST");
        assert_eq!(metadata["path"], "/v1/chat/completions");
        assert_eq!(
            metadata["authorization"],
            json!([format!("Bearer {SAVED_TASK_B}")])
        );
        assert_eq!(metadata["x_api_key"], json!([]));
        assert_eq!(
            body["model"],
            if independent {
                SUMMARY_RAW
            } else {
                SAVED_TASK_RAW
            }
        );
        assert_eq!(
            body["max_tokens"],
            if independent { SUMMARY_OUTPUT } else { 733 }
        );
        assert_eq!(
            body["reasoning_effort"],
            if independent { "low" } else { "high" }
        );
        assert!(
            body.get("tools")
                .is_none_or(|tools| tools.as_array().is_some_and(Vec::is_empty))
        );
        let messages = body["messages"].as_array().unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0]["role"], "user");
        let prompt = messages[0]["content"].as_str().unwrap();
        assert!(prompt.starts_with("Summarize this conversation for continuation."));
        assert!(!prompt.contains(SAVED_CONTEXT_PROMPT) && !prompt.contains(SAVED_CONTEXT_MARKER));
        let bytes = serde_json::to_vec(body).unwrap().len();
        assert!(
            bytes > 4000,
            "smaller1000-token summary refusal has a real request-size boundary"
        );
        assert!(
            bytes < (input / 10 * 9 * 4) as usize,
            "this allowed summary fits its own soft input threshold"
        );
        assert!(!body.to_string().contains(SAVED_TASK_B));
    }
    fn assert_compacted_continuation(f: &SavedTaskFixture, seeded: &AgentSnapshot) {
        SavedTaskFixture::assert_call(&f.fixture.b, 1, SAVED_TASK_B, 733, Some("high"));
        let body = &f.fixture.b.bodies()[1];
        f.assert_selected_context_normal(body);
        assert!(serde_json::to_vec(body).unwrap().len() < (CHILD_INPUT / 10 * 9 * 4) as usize);
        let summary = &f.fixture.b.bodies()[0];
        let mut expected = f.assert_complete_context_compaction(summary, body, seeded);
        expected.push(orbit_engine::assistant_message("owned fixture reply"));
        let saved = f.fixture.store().load(&seeded.agent_id).unwrap();
        assert_eq!(saved.model, seeded.model);
        assert_eq!(saved.effort, seeded.effort);
        assert_eq!(saved.status, AgentStatus::Completed);
        assert_eq!(saved.turns, 14);
        assert!(saved.active_run_id.is_none());
        assert_eq!(saved.transcript.len(), expected.len());
        assert_eq!(saved.transcript, expected);
        assert_eq!(saved.transcript.last().unwrap().role, ChatRole::Assistant);
        assert_eq!(
            saved.transcript.last().unwrap().content,
            "owned fixture reply"
        );
    }

    #[test]
    fn typed_task_budget_oldapi_resumed_small_child_compacts_before_oversized_post() {
        let _watchdog = Watchdog::new();
        let mut f = SavedTaskFixture::new();
        let seeded = seed_typed(&mut f, None);
        let parent = parent_state(&f);
        let result = f.resume_selected_context(&seeded.agent_id);
        assert_selected_posts_within_child_input(&f);
        assert_eq!(result["ok"], true, "{result}");
        assert_eq!(id(&result), seeded.agent_id);
        assert_eq!(f.fixture.a.calls(), 0);
        assert_eq!(
            f.fixture.b.calls(),
            2,
            "one admitted B summary, then one admitted B continuation"
        );
        assert_summary_request(&f, 0, CHILD_INPUT, false);
        assert_compacted_continuation(&f, &seeded);
        f.assert_selected_context_parent_unchanged(&parent, &result);
        assert_workspace_empty(&f);
    }

    #[test]
    fn typed_task_budget_oldapi_fitting_fresh_child_posts_once_with_own_auth_and_controls() {
        let _watchdog = Watchdog::new();
        let mut f = SavedTaskFixture::new();
        configure_typed(
            &mut f,
            json!({"input_tokens":CHILD_INPUT,"unknown_policy":"require-limit"}),
            None,
        );
        let parent = parent_state(&f);
        let result = f.fixture.task(
            json!({"agent":SAVED_CONTEXT_AGENT,"prompt":SAVED_CONTEXT_PROMPT,
            "model":format!("b/{SAVED_TASK_RAW}"),"effort":"high"}),
        );
        assert_eq!(result["ok"], true, "{result}");
        assert_eq!(f.fixture.a.calls(), 0);
        assert_eq!(f.fixture.b.calls(), 1);
        SavedTaskFixture::assert_call(&f.fixture.b, 0, SAVED_TASK_B, 733, Some("high"));
        let body = f.fixture.b.body();
        f.assert_selected_context_normal(&body);
        assert!(serde_json::to_vec(&body).unwrap().len() < (CHILD_INPUT / 10 * 9 * 4) as usize);
        assert!(
            !body
                .to_string()
                .contains("Summarize this conversation for continuation.")
        );
        assert!(!body.to_string().contains("[context compacted"));
        let saved = f.fixture.store().load(&id(&result)).unwrap();
        assert_eq!(saved.model, format!("b/{SAVED_TASK_RAW}"));
        assert_eq!(
            saved.effort,
            Some(EffortSetting::Value(EffortValue::Level("high".into())))
        );
        assert_eq!(saved.status, AgentStatus::Completed);
        assert_eq!(saved.turns, 1);
        assert!(saved.active_run_id.is_none());
        assert_eq!(saved.transcript.len(), 2);
        assert_eq!(
            saved.transcript[0],
            orbit_engine::user_message(SAVED_CONTEXT_PROMPT)
        );
        assert_eq!(saved.transcript[1].content, "owned fixture reply");
        f.assert_selected_context_parent_unchanged(&parent, &result);
        assert_workspace_empty(&f);
    }

    #[test]
    fn typed_task_budget_oldapi_fresh_child_combined_below_actual_output_refuses_zero_posts() {
        let _watchdog = Watchdog::new();
        let mut f = SavedTaskFixture::new();
        //733 requested output cannot fit a512 combined policy even with zero
        // input. Parent1111 output and65536 input are a different binding.
        configure_typed(
            &mut f,
            json!({"combined_tokens":512,"unknown_policy":"require-limit"}),
            None,
        );
        let parent = parent_state(&f);
        let result = f.fixture.task(
            json!({"agent":SAVED_CONTEXT_AGENT,"prompt":SAVED_CONTEXT_PROMPT,
            "model":format!("b/{SAVED_TASK_RAW}"),"effort":"high"}),
        );
        assert_eq!(f.fixture.a.calls(), 0);
        assert_eq!(
            f.fixture.b.calls(),
            0,
            "the child's actual requested output alone exceeds its typed combined policy"
        );
        assert_eq!(result["ok"], false, "{result}");
        let agents = f.fixture.store().list().unwrap();
        assert_eq!(agents.len(), 1);
        let saved = f.fixture.store().load(&agents[0].agent_id).unwrap();
        assert_eq!(saved.model, format!("b/{SAVED_TASK_RAW}"));
        assert_eq!(saved.status, AgentStatus::Failed);
        assert_eq!(saved.turns, 1);
        assert!(saved.active_run_id.is_none());
        assert_eq!(
            saved.transcript,
            [orbit_engine::user_message(SAVED_CONTEXT_PROMPT)]
        );
        f.assert_selected_context_parent_unchanged(&parent, &result);
        assert_workspace_empty(&f);
    }

    #[test]
    fn typed_task_budget_oldapi_own_smaller_summary_role_keeps_final_output_and_effort() {
        let _watchdog = Watchdog::new();
        let mut f = SavedTaskFixture::new();
        let seeded = seed_typed(&mut f, Some(SUMMARY_INPUT));
        let parent = parent_state(&f);
        let result = f.resume_selected_context(&seeded.agent_id);
        assert_selected_posts_within_child_input(&f);
        assert_eq!(result["ok"], true, "{result}");
        assert_eq!(id(&result), seeded.agent_id);
        assert_eq!(f.fixture.a.calls(), 0);
        assert_eq!(f.fixture.b.calls(), 2);
        assert_summary_request(&f, 0, SUMMARY_INPUT, true);
        assert_compacted_continuation(&f, &seeded);
        f.assert_selected_context_parent_unchanged(&parent, &result);
        assert_workspace_empty(&f);
    }

    #[test]
    fn typed_task_budget_oldapi_unfit_summary_role_refuses_and_keeps_complete_source() {
        let _watchdog = Watchdog::new();
        let mut f = SavedTaskFixture::new();
        let seeded = seed_typed(&mut f, Some(1000));
        let parent = parent_state(&f);
        // Existing bounded summary projection retains up to400 bytes/message.
        // Its first20 complete messages alone contribute8000 text bytes, above
        // the summary's4000-byte input boundary, before framing or instructions.
        assert!(
            seeded.transcript[..20]
                .iter()
                .all(|message| message.content.len() >= 400)
        );
        let result = f.resume_selected_context(&seeded.agent_id);
        assert_eq!(f.fixture.a.calls(), 0);
        assert_eq!(
            f.fixture.b.calls(),
            0,
            "neither unfit summary nor oversized ordinary request may escape"
        );
        assert_eq!(result["ok"], false, "{result}");
        let saved = f.fixture.store().load(&seeded.agent_id).unwrap();
        assert_eq!(saved.model, seeded.model);
        assert_eq!(saved.effort, seeded.effort);
        assert_eq!(saved.status, AgentStatus::Failed);
        assert_eq!(saved.turns, 14);
        assert!(saved.active_run_id.is_none());
        let mut original = seeded.transcript.clone();
        original.push(orbit_engine::user_message(SAVED_CONTEXT_PROMPT));
        assert_eq!(
            saved.transcript, original,
            "failed housekeeping preserves every complete original message and the in-flight prompt"
        );
        assert!(
            !saved
                .transcript
                .iter()
                .any(|message| message.content.contains("[context compacted"))
        );
        f.assert_selected_context_parent_unchanged(&parent, &result);
        assert_workspace_empty(&f);
    }

    fn assert_failed_budget_run_releases_lease(f: &SavedTaskFixture, saved: &AgentSnapshot) {
        let store = f.fixture.store();
        let run = store
            .begin(&saved.agent_id, None)
            .expect("failed budget run must release its lease");
        assert!(
            !run.interrupted_previous_run(),
            "a handled policy refusal is a failure, not an interrupted run"
        );
        let again = run
            .finish(
                saved.transcript.clone(),
                saved.report.clone(),
                AgentStatus::Failed,
                saved.turns,
            )
            .unwrap();
        assert_eq!(again.transcript, saved.transcript);
        assert_eq!(again.status, AgentStatus::Failed);
        assert_eq!(again.turns, saved.turns);
        assert!(again.active_run_id.is_none());
    }

    #[test]
    fn typed_task_budget_oldapi_fresh_required_limit_failure_preserves_prompt_and_failed_state() {
        let _watchdog = Watchdog::new();
        let mut f = SavedTaskFixture::new();
        configure_typed(&mut f, json!({"unknown_policy":"require-limit"}), None);
        let parent = parent_state(&f);
        let result = f.fixture.task(json!({
            "agent":SAVED_CONTEXT_AGENT,"prompt":SAVED_CONTEXT_PROMPT,
            "model":format!("b/{SAVED_TASK_RAW}"),"effort":"high"
        }));
        assert_eq!(f.fixture.a.calls(), 0);
        assert_eq!(
            f.fixture.b.calls(),
            0,
            "a missing required input limit must refuse before any provider POST"
        );
        assert_eq!(result["ok"], false, "{result}");
        assert!(
            result.to_string().contains("context_limits"),
            "the local refusal must explain how to configure a usable limit"
        );
        let agents = f.fixture.store().list().unwrap();
        assert_eq!(agents.len(), 1);
        let saved = f.fixture.store().load(&agents[0].agent_id).unwrap();
        assert_eq!(result["agent_id"], saved.agent_id);
        assert_eq!(saved.model, format!("b/{SAVED_TASK_RAW}"));
        assert_eq!(
            saved.effort,
            Some(EffortSetting::Value(EffortValue::Level("high".into())))
        );
        assert_eq!(saved.status, AgentStatus::Failed);
        assert_eq!(saved.turns, 1);
        assert!(saved.active_run_id.is_none());
        assert_eq!(
            saved.transcript,
            [orbit_engine::user_message(SAVED_CONTEXT_PROMPT)]
        );
        assert_failed_budget_run_releases_lease(&f, &saved);
        f.assert_selected_context_parent_unchanged(&parent, &result);
        assert_workspace_empty(&f);
    }

    #[test]
    fn typed_task_budget_oldapi_resumed_required_limit_failure_keeps_source_prompt_and_failed_state()
     {
        let _watchdog = Watchdog::new();
        let mut f = SavedTaskFixture::new();
        let seeded = seed_typed(&mut f, None);
        configure_typed(&mut f, json!({"unknown_policy":"require-limit"}), None);
        let parent = parent_state(&f);
        let result = f.resume_selected_context(&seeded.agent_id);
        assert_eq!(f.fixture.a.calls(), 0);
        assert_eq!(
            f.fixture.b.calls(),
            0,
            "a resumed child cannot bypass strict missing-limit policy with its durable history"
        );
        assert_eq!(result["ok"], false, "{result}");
        assert_eq!(result["agent_id"], seeded.agent_id);
        assert!(result.to_string().contains("context_limits"));
        let saved = f.fixture.store().load(&seeded.agent_id).unwrap();
        assert_eq!(saved.model, seeded.model);
        assert_eq!(saved.effort, seeded.effort);
        assert_eq!(saved.status, AgentStatus::Failed);
        assert_eq!(saved.turns, seeded.turns + 1);
        assert!(saved.active_run_id.is_none());
        let mut original = seeded.transcript.clone();
        original.push(orbit_engine::user_message(SAVED_CONTEXT_PROMPT));
        assert_eq!(
            saved.transcript, original,
            "pre-dispatch resolver failure must preserve all source history and the current prompt exactly once"
        );
        assert!(
            !saved
                .transcript
                .iter()
                .any(|message| message.content.contains("[context compacted"))
        );
        assert_failed_budget_run_releases_lease(&f, &saved);
        f.assert_selected_context_parent_unchanged(&parent, &result);
        assert_workspace_empty(&f);
    }

    #[test]
    fn typed_task_budget_oldapi_fallback_notices_reach_result_without_observer() {
        let _watchdog = Watchdog::new();
        let mut f = SavedTaskFixture::new();
        configure_typed(&mut f, json!({}), None);
        let result = f.fixture.task(
            json!({"agent":SAVED_CONTEXT_AGENT,"prompt":SAVED_CONTEXT_PROMPT,
            "model":format!("b/{SAVED_TASK_RAW}"),"effort":"high"}),
        );
        assert_eq!(result["ok"], true, "{result}");
        assert_eq!(f.fixture.a.calls(), 0);
        assert_eq!(f.fixture.b.calls(), 1);
        let notices = result["result"]["context_notices"]
            .as_array()
            .expect("Task result must surface fallback policy without an observer");
        assert!(notices.iter().any(|n| {
            n.as_str()
                .is_some_and(|s| s.starts_with("Child context uses a harness fallback policy"))
        }));
        assert!(notices.iter().any(|n| {
            n.as_str()
                .is_some_and(|s| s.starts_with("Summary context uses a harness fallback policy"))
        }));
        f.assert_no_keys_in_parent_or_durable_state(&result);
    }
}

#[cfg(target_os = "linux")]
mod child_journal_activation {
    use super::*;
    use orbit_cli::context_history::context_journal;
    use orbit_cli::sessions::SessionLease;
    use orbit_engine::{AccountingBaseline, AccountingKnownness};
    use std::fs;
    use std::os::unix::fs::MetadataExt;
    use std::path::Path;

    fn dispatch_isolated(exact: &str) -> bool {
        let isolated = std::env::var_os("ORBIT_ACTIVATION_ISOLATED");
        let depth = std::env::var_os("ORBIT_ACTIVATION_RUNNER_DEPTH");
        if isolated.as_deref() == Some(std::ffi::OsStr::new("1")) {
            assert_eq!(
                depth.as_deref(),
                Some(std::ffi::OsStr::new("1")),
                "invalid isolated runner depth"
            );
            return true;
        }
        assert!(
            isolated.is_none() && depth.is_none(),
            "malformed isolation dispatch controls"
        );
        let required =
            std::env::var("ORBIT_REQUIRE_CONTEXT_SESSION_ISOLATION").as_deref() == Ok("1");
        let output = std::process::Command::new("/usr/bin/python3")
            .arg(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../scripts/fixtures/context_session_isolation.py"
            ))
            .arg("--binary")
            .arg(std::env::current_exe().unwrap())
            .args(["--exact", exact, "--timeout", "45"])
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("LANG", "C.UTF-8")
            .stdin(std::process::Stdio::null())
            .output()
            .expect("tracked isolation runner did not start");
        assert!(
            output.stdout.len() <= 512 * 1024 && output.stderr.len() <= 64 * 1024,
            "runner receipt output bound"
        );
        let report: Value = serde_json::from_slice(&output.stdout).unwrap_or_else(|_| {
            panic!(
                "invalid isolation runner receipt, exit {:?}",
                output.status.code()
            )
        });
        assert_eq!(report["schema"], "orbit.context-session-isolation/v1");
        assert_eq!(report["test_filter"], exact);
        let visible = json!({"schema":report["schema"],"test_filter":exact,"status":report["status"],
            "test_started":report["test_started"],"reason":report["reason"],"harness":report["harness"],
            "binary_sha256":report["binary_sha256"],"binary_metadata_and_hash_unchanged":report["binary_metadata_and_hash_unchanged"],
            "host_managed_path_metadata_unchanged":report["host_managed_path_metadata_unchanged"],"owned_fixture_removed":report["owned_fixture_removed"]});
        // Direct Write bypasses libtest's println capture. A returning NOTRUN
        // wrapper must stay visible and must not count as an inner pass.
        let line = format!("ORBIT_CONTEXT_SESSION_ISOLATION {visible}\n");
        std::io::Write::write_all(&mut std::io::stdout().lock(), line.as_bytes()).unwrap();
        match report["status"].as_str() {
            Some("TEST_PASSED") => {
                assert_eq!(output.status.code(), Some(0));
                assert_eq!(report["test_started"], true);
                assert_eq!(report["harness"]["passed"], 1);
                assert_eq!(report["harness"]["failed"], 0);
                assert_eq!(report["harness"]["ignored"], 0);
                for field in [
                    "binary_metadata_and_hash_unchanged",
                    "host_managed_path_metadata_unchanged",
                    "owned_fixture_removed",
                    "binary_postcheck_inside",
                ] {
                    assert_eq!(report[field], true);
                }
            }
            Some("NOTRUN") => {
                assert_eq!(output.status.code(), Some(77));
                assert_eq!(report["test_started"], false);
                assert!(
                    !required,
                    "NOTRUN: this infrastructure-required job needs namespace capability"
                );
            }
            Some("TEST_FAILED") | Some("INFRA_FAILURE") => {
                panic!(
                    "isolated test did not pass: {} / {} / {}",
                    report["status"], report["stdout_excerpt"], report["stderr_excerpt"]
                );
            }
            _ => panic!("unknown isolation runner status"),
        }
        false
    }

    fn require_private_system_fixture() {
        // Check descriptors/namespace identity BEFORE opening managed content,
        // creating a fixture, spawning a provider or starting any caller.
        let descriptor = |name: &str| {
            let value: u32 = std::env::var(name)
                .expect("isolated runner descriptor missing")
                .parse()
                .unwrap();
            assert!(value < 4096);
            fs::metadata(format!("/proc/self/fd/{value}")).unwrap()
        };
        let parent_mount = descriptor("ORBIT_ACTIVATION_PARENT_MOUNT_FD");
        let parent_user = descriptor("ORBIT_ACTIVATION_PARENT_USER_FD");
        let own_mount = fs::metadata("/proc/self/ns/mnt").unwrap();
        let own_user = fs::metadata("/proc/self/ns/user").unwrap();
        assert_ne!(
            (parent_mount.dev(), parent_mount.ino()),
            (own_mount.dev(), own_mount.ino())
        );
        assert_ne!(
            (parent_user.dev(), parent_user.ino()),
            (own_user.dev(), own_user.ino())
        );
        let mounts = fs::read_to_string("/proc/self/mountinfo").unwrap();
        assert!(mounts.lines().any(
            |line| line.split_whitespace().nth(4) == Some("/etc") && line.contains(" - tmpfs ")
        ));
        let expected = std::env::var("ORBIT_ACTIVATION_MANAGED_MARKER").unwrap();
        assert!(expected.starts_with("ORBIT_ACTIVATION_MANAGED_") && expected.len() <= 128);
        assert!(
            expected
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_')
        );
        let path = Path::new("/etc/orbit/ORBIT.md");
        let metadata = fs::symlink_metadata(path).unwrap();
        assert!(metadata.is_file() && !metadata.file_type().is_symlink());
        assert_eq!(metadata.mode() & 0o777, 0o600);
        assert_eq!(metadata.nlink(), 1);
        assert!(metadata.len() <= 128);
        assert_eq!(fs::read(path).unwrap(), expected.as_bytes());
        assert_eq!(fs::read_dir("/etc/orbit").unwrap().count(), 1);
        let root =
            PathBuf::from(std::env::var_os("ORBIT_ACTIVATION_ROOT").expect("private root missing"));
        assert!(root.is_absolute());
        assert_eq!(root.canonicalize().unwrap(), root);
        assert!(
            root.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("oc-")
        );
        assert_eq!(fs::symlink_metadata(&root).unwrap().mode() & 0o777, 0o700);
        for name in [
            "HOME",
            "XDG_CONFIG_HOME",
            "XDG_DATA_HOME",
            "XDG_STATE_HOME",
            "XDG_CACHE_HOME",
            "XDG_RUNTIME_DIR",
            "TMPDIR",
        ] {
            let path = PathBuf::from(std::env::var_os(name).expect("private user path missing"));
            assert!(path.is_absolute() && path.starts_with(&root) && path != root);
            assert_eq!(path.canonicalize().unwrap(), path);
            let metadata = fs::symlink_metadata(&path).unwrap();
            assert!(metadata.is_dir() && !metadata.file_type().is_symlink());
            assert_eq!(metadata.mode() & 0o777, 0o700);
        }
        assert!(std::env::current_dir().unwrap().starts_with(&root));
        for name in [
            "ORBIT_HOME",
            "ANTHROPIC_API_KEY",
            "OPENAI_API_KEY",
            "ANTHROPIC_BASE_URL",
            "OPENAI_BASE_URL",
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "ALL_PROXY",
            "http_proxy",
            "https_proxy",
            "all_proxy",
        ] {
            assert!(
                std::env::var_os(name).is_none(),
                "runner did not clear an inherited provider setting"
            );
        }
    }

    fn price_models(f: &Fixture) {
        let mut config = orbit_cli::config::ProvidersConfig::load(&f.home).unwrap();
        for provider in &mut config.provider {
            for model in &mut provider.models {
                let value = json!({"input_per_million_microdollars":0,"output_per_million_microdollars":0,
                    "cache_read_per_million_microdollars":0,"cache_write_per_million_microdollars":0,
                    "reasoning_per_million_microdollars":0,"request_flat_microdollars":5});
                model.pricing = serde_json::from_value(value).unwrap();
                model.context_limits =
                    Some(serde_json::from_value(json!({"input_tokens":64_000})).unwrap());
            }
        }
        fs::write(
            f.home.join("providers.toml"),
            toml::to_string(&config).unwrap(),
        )
        .unwrap();
    }
    fn task_alias(f: &Fixture, name: &str, args: Value) -> Value {
        let call = orbit_cli::PendingToolCall {
            index: 0,
            id: ulid::Ulid::new().to_string(),
            name: name.into(),
            arguments: serde_json::to_vec(&args).unwrap(),
        };
        let (output, _) = tool_runtime::execute_call(
            &f.home,
            "owner",
            "decision",
            &call,
            true,
            false,
            &mut Approve,
            &mut AutoGrants::new(),
            &PermissionScope::default(),
            &f.cx,
        )
        .unwrap();
        serde_json::from_str(&output).unwrap()
    }
    fn child_checkpoint(f: &Fixture, child: &str) -> orbit_engine::AccountingCheckpoint {
        context_journal(&f.home, "owner", Some(child))
            .unwrap()
            .accounting_checkpoint()
            .unwrap()
    }
    fn assert_child_schema_unchanged(saved: &orbit_engine::agent_store::AgentSnapshot) {
        let value = serde_json::to_value(saved).unwrap();
        for field in [
            "accounting_watermark",
            "input_tokens",
            "output_tokens",
            "cost_microcents",
        ] {
            assert!(value.get(field).is_none());
        }
    }

    #[test]
    fn actual_task_then_agent_resume_keeps_the_same_qualified_fresh_child_and_known_bill() {
        if !dispatch_isolated(
            "child_journal_activation::actual_task_then_agent_resume_keeps_the_same_qualified_fresh_child_and_known_bill",
        ) {
            return;
        }
        require_private_system_fixture();
        let f = Fixture::new();
        price_models(&f);
        let _owner_lease = SessionLease::acquire(&f.home, "owner", "activation-parent").unwrap();
        let parent = context_journal(&f.home, "owner", None).unwrap();
        let parent_before = parent
            .initialize_accounting(AccountingBaseline::FreshKnownZero)
            .unwrap();
        let first = task_alias(
            &f,
            "Task",
            json!({"agent":"Explore","model":"b/family/routed-notools","prompt":"first exact child intent"}),
        );
        assert_eq!(first["ok"], true, "{first}");
        let child = id(&first);
        let first_snapshot = f.store().load(&child).unwrap();
        let first_checkpoint = child_checkpoint(&f, &child);
        assert_eq!(first_checkpoint.owner_session_id, "owner");
        assert_eq!(first_checkpoint.child_id.as_deref(), Some(child.as_str()));
        assert_eq!(
            first_checkpoint.baseline,
            AccountingBaseline::FreshKnownZero
        );
        assert_eq!(first_checkpoint.revision.0, 2);
        assert_eq!(
            first_checkpoint.totals.knownness,
            AccountingKnownness::Known
        );
        assert_eq!(
            (
                first_checkpoint.totals.ordinary.input_tokens,
                first_checkpoint.totals.ordinary.output_tokens
            ),
            (2, 3)
        );
        assert_eq!(
            first_checkpoint
                .known_priced_subtotals
                .unwrap()
                .ordinary_microcents,
            5
        );
        assert_child_schema_unchanged(&first_snapshot);
        assert_eq!(parent.accounting_checkpoint().unwrap(), parent_before);
        // A fresh public tool invocation and store load, using the Agent alias,
        // must retain the existing stable child namespace rather than reset it.
        let second = task_alias(
            &f,
            "Agent",
            json!({"agent":"Explore","resume":child,"prompt":"second exact child intent"}),
        );
        assert_eq!(second["ok"], true, "{second}");
        assert_eq!(id(&second), child);
        let second_snapshot = f.store().load(&child).unwrap();
        assert!(
            second_snapshot
                .transcript
                .starts_with(&first_snapshot.transcript)
        );
        let checkpoint = child_checkpoint(&f, &child);
        assert_eq!(checkpoint.revision.0, 4);
        assert_eq!(
            (
                checkpoint.totals.ordinary.input_tokens,
                checkpoint.totals.ordinary.output_tokens,
                checkpoint.totals.ordinary.cost_microcents
            ),
            (4, 6, Some(10))
        );
        assert_eq!(
            checkpoint
                .known_priced_subtotals
                .unwrap()
                .ordinary_microcents,
            10
        );
        assert!(checkpoint.pending.is_none());
        assert_eq!(parent.accounting_checkpoint().unwrap(), parent_before);
        assert_eq!(f.a.calls(), 0);
        assert_eq!(f.b.calls(), 2);
        assert_eq!(f.b.bodies()[1]["model"], "family/routed-notools");
        assert_child_schema_unchanged(&second_snapshot);
        let ledger = orbit_ledger::verify_ledger(&f.home.join("ledger"))
            .unwrap()
            .0;
        let ids: Vec<_> = ledger
            .into_iter()
            .filter_map(|record| match record.record.event {
                orbit_ledger::LedgerEvent::EgressIntent(event) => {
                    assert_eq!(event.session_id, child);
                    Some(event.decision_id)
                }
                _ => None,
            })
            .collect();
        assert_eq!(ids.len(), 2);
        assert_ne!(ids[0], ids[1]);
        assert_eq!(
            checkpoint.last_settlement.unwrap().reference.request_id,
            ids[1]
        );
    }

    #[test]
    fn actual_resumed_child_failure_keeps_the_prior_paid_bill_and_refuses_another_resume() {
        if !dispatch_isolated(
            "child_journal_activation::actual_resumed_child_failure_keeps_the_prior_paid_bill_and_refuses_another_resume",
        ) {
            return;
        }
        require_private_system_fixture();
        let f = Fixture::new();
        price_models(&f);
        let _lease = SessionLease::acquire(&f.home, "owner", "activation-parent").unwrap();
        let parent_journal = context_journal(&f.home, "owner", None).unwrap();
        assert!(matches!(
            parent_journal.accounting_checkpoint(),
            Err(orbit_engine::compaction::HistoryError::Missing)
        ));
        let parent_config = format!(
            "{:?}",
            f.cx.ext::<tool_runtime::SessionTurnConfig>().unwrap().0
        );
        let parent_effort =
            f.cx.ext::<tool_runtime::SessionEffortSetting>()
                .map(|value| value.0.clone());
        let first=f.task(json!({"agent":"Explore","model":"b/family/routed-notools","prompt":"paid child prefix"}));
        assert_eq!(first["ok"], true, "{first}");
        let child = id(&first);
        let original = f.store().load(&child).unwrap();
        fs::write(
            f.b.directory.join("mode.json"),
            json!({"disconnect":true}).to_string(),
        )
        .unwrap();
        let failed = task_alias(
            &f,
            "Agent",
            json!({"agent":"Explore","resume":child,"prompt":"retain this failed child intent"}),
        );
        assert_eq!(failed["ok"], false, "{failed}");
        let checkpoint = child_checkpoint(&f, &child);
        assert_eq!(checkpoint.revision.0, 4);
        assert_eq!(
            checkpoint
                .known_priced_subtotals
                .unwrap()
                .ordinary_microcents,
            5
        );
        assert_eq!(
            (
                checkpoint.totals.ordinary.input_tokens,
                checkpoint.totals.ordinary.output_tokens
            ),
            (2, 3)
        );
        assert_eq!(checkpoint.totals.ordinary.cost_microcents, None);
        assert_eq!(checkpoint.totals.knownness, AccountingKnownness::Uncertain);
        assert!(checkpoint.pending.as_ref().unwrap().uncertain);
        assert_eq!(checkpoint.owner_session_id, "owner");
        assert_eq!(checkpoint.child_id.as_deref(), Some(child.as_str()));
        let pending = checkpoint.pending.as_ref().unwrap();
        assert_eq!(pending.intent.owner_session_id, "owner");
        assert_eq!(pending.intent.child_id.as_deref(), Some(child.as_str()));
        assert_eq!(
            pending.intent.purpose,
            orbit_engine::AttemptPurpose::Ordinary
        );
        let ledger_ids: Vec<_> = orbit_ledger::verify_ledger(&f.home.join("ledger"))
            .unwrap()
            .0
            .into_iter()
            .filter_map(|record| match record.record.event {
                orbit_ledger::LedgerEvent::EgressIntent(event) => {
                    assert_eq!(event.session_id, child);
                    Some(event.decision_id)
                }
                _ => None,
            })
            .collect();
        assert_eq!(ledger_ids.len(), 2);
        assert_eq!(pending.reference.request_id, *ledger_ids.last().unwrap());
        let accounting_path = f.home.join("context-history/owner/accounting.json");
        let accounting_bytes = fs::read(&accounting_path).unwrap();
        let container: Value = serde_json::from_slice(&accounting_bytes).unwrap();
        let entries = container["entries"].as_array().unwrap();
        assert_eq!(
            entries.len(),
            1,
            "child work must not create a parent billing entry"
        );
        assert_eq!(entries[0]["namespace"], json!({"kind":"child","id":child}));
        let receipt = &entries[0]["pending"]["uncertain_receipt"];
        assert_eq!(receipt["request_id"], pending.reference.request_id);
        assert_eq!(receipt["purpose"], "ordinary");
        assert_eq!(receipt["knownness"], "uncertain");
        assert_eq!(receipt["completed"], false);
        assert_eq!(receipt["totals"]["input_tokens"], 0);
        assert_eq!(receipt["totals"]["output_tokens"], 0);
        assert!(receipt["totals"]["cost_microcents"].is_null());
        assert_eq!(
            checkpoint
                .last_settlement
                .as_ref()
                .unwrap()
                .reference
                .request_id,
            ledger_ids[0]
        );
        let saved = f.store().load(&child).unwrap();
        let mut failed_history = original.transcript.clone();
        failed_history.push(orbit_engine::user_message(
            "retain this failed child intent",
        ));
        assert_eq!(saved.transcript, failed_history);
        assert!(saved.transcript.starts_with(&original.transcript));
        assert_eq!(
            saved
                .transcript
                .iter()
                .filter(|message| message.content == "retain this failed child intent")
                .count(),
            1
        );
        assert_eq!(
            saved.status,
            orbit_engine::agent_store::AgentStatus::Interrupted
        );
        assert_child_schema_unchanged(&saved);
        let before_refusal = saved.clone();
        let again = f.task(
            json!({"agent":"Explore","resume":child,"prompt":"must not replay failed child work"}),
        );
        assert_eq!(again["ok"], false, "{again}");
        assert_eq!(again["agent_id"], child);
        assert_eq!(
            again["error"],
            "a pending uncertain request requires explicit inspection before admission"
        );
        assert_eq!(fs::read(&accounting_path).unwrap(), accounting_bytes);
        assert!(matches!(
            parent_journal.accounting_checkpoint(),
            Err(orbit_engine::compaction::HistoryError::Missing)
        ));
        assert_eq!(
            format!(
                "{:?}",
                f.cx.ext::<tool_runtime::SessionTurnConfig>().unwrap().0
            ),
            parent_config
        );
        assert_eq!(
            f.cx.ext::<tool_runtime::SessionEffortSetting>()
                .map(|value| value.0.clone()),
            parent_effort
        );
        let after_refusal = f.store().load(&child).unwrap();
        assert_eq!(
            after_refusal.status,
            orbit_engine::agent_store::AgentStatus::Interrupted
        );
        assert!(after_refusal.active_run_id.is_none());
        assert_eq!(after_refusal.owner_session_id, "owner");
        assert_eq!(after_refusal.agent_id, before_refusal.agent_id);
        assert_eq!(after_refusal.model, before_refusal.model);
        assert_eq!(after_refusal.effort, before_refusal.effort);
        assert_eq!(
            after_refusal.turns,
            before_refusal.turns.checked_add(1).unwrap()
        );
        let mut expected = before_refusal.transcript.clone();
        expected.push(orbit_engine::user_message(concat!(
            "The previous run was interrupted. Inspect the actual work and tool results before continuing; do not automatically replay the previous task.\n\n",
            "must not replay failed child work",
        )));
        assert_eq!(after_refusal.transcript, expected);
        assert_eq!(
            after_refusal
                .transcript
                .iter()
                .filter(|message| message.content == "retain this failed child intent")
                .count(),
            1
        );
        assert_child_schema_unchanged(&after_refusal);
        assert_eq!(child_checkpoint(&f, &child), checkpoint);
        assert_eq!(f.b.calls(), 2);
        assert_eq!(f.a.calls(), 0);
        // A genuine new run lease is available after both failed invocations.
        let run = f.store().begin(&child, None).unwrap();
        drop(run);
    }

    #[test]
    fn actual_child_cancellation_after_post_is_durable_and_blocks_later_agent_invocation() {
        if !dispatch_isolated(
            "child_journal_activation::actual_child_cancellation_after_post_is_durable_and_blocks_later_agent_invocation",
        ) {
            return;
        }
        require_private_system_fixture();
        let f = Fixture::new();
        price_models(&f);
        let _lease = SessionLease::acquire(&f.home, "owner", "activation-parent").unwrap();
        let parent_journal = context_journal(&f.home, "owner", None).unwrap();
        assert!(matches!(
            parent_journal.accounting_checkpoint(),
            Err(orbit_engine::compaction::HistoryError::Missing)
        ));
        let parent_config = format!(
            "{:?}",
            f.cx.ext::<tool_runtime::SessionTurnConfig>().unwrap().0
        );
        let parent_effort =
            f.cx.ext::<tool_runtime::SessionEffortSetting>()
                .map(|value| value.0.clone());
        fs::write(
            f.b.directory.join("mode.json"),
            json!({"blocked":true}).to_string(),
        )
        .unwrap();
        let captured = f.b.directory.join("calls.jsonl");
        f.cx.push_cancel_check(std::sync::Arc::new(move || captured.exists()));
        let result=f.task(json!({"agent":"Explore","model":"b/family/routed-notools","prompt":"actual cancelled child intent"}));
        f.cx.pop_cancel_check();
        assert_eq!(result["ok"], false, "{result}");
        assert_eq!(f.b.calls(), 1);
        assert_eq!(f.a.calls(), 0);
        let children = f.store().list().unwrap();
        assert_eq!(children.len(), 1);
        let snapshot = f.store().load(&children[0].agent_id).unwrap();
        let saved = &snapshot;
        assert_eq!(
            saved.transcript,
            vec![orbit_engine::user_message("actual cancelled child intent")]
        );
        assert_eq!(
            saved.status,
            orbit_engine::agent_store::AgentStatus::Interrupted
        );
        assert_eq!(
            saved
                .transcript
                .iter()
                .filter(|message| message.content == "actual cancelled child intent")
                .count(),
            1
        );
        let checkpoint = child_checkpoint(&f, &saved.agent_id);
        assert_eq!(checkpoint.revision.0, 2);
        assert!(checkpoint.pending.as_ref().unwrap().uncertain);
        assert_eq!(checkpoint.totals.knownness, AccountingKnownness::Uncertain);
        assert_eq!(checkpoint.totals.ordinary.cost_microcents, None);
        assert_eq!(checkpoint.owner_session_id, "owner");
        assert_eq!(
            checkpoint.child_id.as_deref(),
            Some(saved.agent_id.as_str())
        );
        let pending = checkpoint.pending.as_ref().unwrap();
        assert_eq!(pending.intent.owner_session_id, "owner");
        assert_eq!(
            pending.intent.child_id.as_deref(),
            Some(saved.agent_id.as_str())
        );
        assert_eq!(
            pending.intent.purpose,
            orbit_engine::AttemptPurpose::Ordinary
        );
        let ledger_ids: Vec<_> = orbit_ledger::verify_ledger(&f.home.join("ledger"))
            .unwrap()
            .0
            .into_iter()
            .filter_map(|record| match record.record.event {
                orbit_ledger::LedgerEvent::EgressIntent(event) => {
                    assert_eq!(event.session_id, saved.agent_id);
                    Some(event.decision_id)
                }
                _ => None,
            })
            .collect();
        assert_eq!(ledger_ids.len(), 1);
        assert_eq!(pending.reference.request_id, *ledger_ids.last().unwrap());
        let accounting_path = f.home.join("context-history/owner/accounting.json");
        let accounting_bytes = fs::read(&accounting_path).unwrap();
        let container: Value = serde_json::from_slice(&accounting_bytes).unwrap();
        let entries = container["entries"].as_array().unwrap();
        assert_eq!(
            entries.len(),
            1,
            "child work must not create a parent billing entry"
        );
        assert_eq!(
            entries[0]["namespace"],
            json!({"kind":"child","id":saved.agent_id})
        );
        let receipt = &entries[0]["pending"]["uncertain_receipt"];
        assert_eq!(receipt["request_id"], pending.reference.request_id);
        assert_eq!(receipt["purpose"], "ordinary");
        assert_eq!(receipt["knownness"], "uncertain");
        assert_eq!(receipt["completed"], false);
        assert_eq!(receipt["totals"]["input_tokens"], 0);
        assert_eq!(receipt["totals"]["output_tokens"], 0);
        assert!(receipt["totals"]["cost_microcents"].is_null());
        assert!(checkpoint.last_settlement.is_none());
        let before_refusal = f.store().load(&saved.agent_id).unwrap();
        let again = task_alias(
            &f,
            "Agent",
            json!({"agent":"Explore","resume":saved.agent_id,"prompt":"do not replay cancelled child intent"}),
        );
        assert_eq!(again["ok"], false, "{again}");
        assert_eq!(again["agent_id"], saved.agent_id);
        assert_eq!(
            again["error"],
            "a pending uncertain request requires explicit inspection before admission"
        );
        assert_eq!(fs::read(&accounting_path).unwrap(), accounting_bytes);
        assert!(matches!(
            parent_journal.accounting_checkpoint(),
            Err(orbit_engine::compaction::HistoryError::Missing)
        ));
        assert_eq!(
            format!(
                "{:?}",
                f.cx.ext::<tool_runtime::SessionTurnConfig>().unwrap().0
            ),
            parent_config
        );
        assert_eq!(
            f.cx.ext::<tool_runtime::SessionEffortSetting>()
                .map(|value| value.0.clone()),
            parent_effort
        );
        let after_refusal = f.store().load(&saved.agent_id).unwrap();
        assert_eq!(
            after_refusal.status,
            orbit_engine::agent_store::AgentStatus::Interrupted
        );
        assert!(after_refusal.active_run_id.is_none());
        assert_eq!(after_refusal.owner_session_id, "owner");
        assert_eq!(after_refusal.agent_id, before_refusal.agent_id);
        assert_eq!(after_refusal.model, before_refusal.model);
        assert_eq!(after_refusal.effort, before_refusal.effort);
        assert_eq!(
            after_refusal.turns,
            before_refusal.turns.checked_add(1).unwrap()
        );
        let mut expected = before_refusal.transcript.clone();
        expected.push(orbit_engine::user_message(concat!(
            "The previous run was interrupted. Inspect the actual work and tool results before continuing; do not automatically replay the previous task.\n\n",
            "do not replay cancelled child intent",
        )));
        assert_eq!(after_refusal.transcript, expected);
        assert_eq!(
            after_refusal
                .transcript
                .iter()
                .filter(|message| message.content == "actual cancelled child intent")
                .count(),
            1
        );
        assert_child_schema_unchanged(&after_refusal);
        assert_eq!(f.b.calls(), 1);
        assert_eq!(child_checkpoint(&f, &saved.agent_id), checkpoint);
        assert_child_schema_unchanged(saved);
    }
}
