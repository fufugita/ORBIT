#![cfg(target_os = "linux")]
use orbit_cli::tool_runtime::{
    self, ApprovalChannel, ApprovalRequest, ApprovalVerdict, AutoGrants, PermissionScope,
};
use serde_json::{Value, json};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::atomic::Ordering;
struct Mock {
    url: String,
    state: orbit_mock_provider::server::ServerState,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}
impl Mock {
    fn new() -> Self {
        let (ready, receive) = std::sync::mpsc::channel();
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let thread = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async move {
                let (address, state, handle) = orbit_mock_provider::server::spawn().await.unwrap();
                ready.send((address, state)).unwrap();
                let _ = stopped.await;
                handle.abort();
                let _ = handle.await;
            });
        });
        let (address, state) = receive.recv().unwrap();
        Self {
            url: format!("http://{address}"),
            state,
            stop: Some(stop),
            thread: Some(thread),
        }
    }
    fn calls(&self) -> u64 {
        self.state.requests.load(Ordering::SeqCst)
    }
    fn body(&self) -> Value {
        self.state.last_body.lock().unwrap().clone().unwrap()
    }
}
impl Drop for Mock {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(thread) = self.thread.take() {
            thread.join().unwrap();
        }
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
