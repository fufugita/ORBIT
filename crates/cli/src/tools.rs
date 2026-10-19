//! Pure built-in tools (DR-19 tool-calling phase).
//!
//! Safety boundary: these tools are PURE DATA. No shell, no process spawning,
//! no filesystem writes, no network, no credentials, no plugin execution.
//! They cannot harm the host. Any unknown tool name is denied; malformed
//! arguments are rejected before any execution.

use orbit_adapter::types::ToolDefinition;
use sha2::{Digest, Sha256};

static BARE_MODE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Select the process's script-friendly tool set before starting workers.
pub fn enable_bare_mode() {
    BARE_MODE.store(true, std::sync::atomic::Ordering::Relaxed);
}

pub fn bare_mode() -> bool {
    BARE_MODE.load(std::sync::atomic::Ordering::Relaxed)
        || std::env::var("ORBIT_BARE").is_ok_and(|value| value == "1")
}

pub(crate) fn config_home_from_env() -> std::path::PathBuf {
    // C8: the ONE home resolver — same precedence as the CLI entry
    // (--home > ORBIT_HOME > ~/.orbit > existing local .orbit). The old
    // CWD-relative default silently disagreed with every other path.
    crate::config::resolve_home(&[])
}

/// A built-in tool's declarative identity (sent to the provider as the JSON
/// schema) plus a pure executor.
pub struct BuiltinTool {
    pub name: &'static str,
    pub description: &'static str,
    pub parameters: serde_json::Value,
    pub execute: fn(&serde_json::Value) -> Result<serde_json::Value, String>,
}

impl BuiltinTool {
    fn to_definition(&self) -> ToolDefinition {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(self.name.as_bytes());
        bytes.extend_from_slice(self.description.as_bytes());
        bytes.extend_from_slice(
            serde_json::to_string(&self.parameters)
                .unwrap_or_default()
                .as_bytes(),
        );
        ToolDefinition {
            name: self.name.to_string(),
            description: self.description.to_string(),
            parameters: self.parameters.clone(),
            schema_digest: orbit_adapter::types::Sha256Digest(hex::encode(Sha256::digest(&bytes))),
        }
    }
}

/// The three locked pure built-ins.
pub fn builtin_tools() -> Vec<BuiltinTool> {
    vec![calculator(), current_session_tool(), list_models_tool()]
}

/// Adapter-facing definitions for the provider: the Wave 1 tool set
/// (Read/Write/Edit/Glob/Grep/Bash/TaskStop) plus the locked pure
/// built-ins (calculator, session/model lookups). Phase 3.
pub fn tool_definitions() -> Vec<ToolDefinition> {
    let mut defs: Vec<ToolDefinition> = orbit_tools::tool_definitions();
    defs.extend(builtin_tools().iter().map(|t| t.to_definition()));
    defs
}

/// The full session tool list: Wave 1 + built-ins + the Skill tool +
/// MCP server tools (mcp__<server>__<tool>). MCP servers from the
/// trusted scopes are spawned once, their tools declared up front so
/// the list never changes mid-conversation (phase 5).
pub fn session_tool_definitions(home: &std::path::Path) -> Vec<ToolDefinition> {
    let cwd = std::env::current_dir().unwrap_or_default();
    let cx = orbit_tools::ToolContext::new(home.into(), String::new(), cwd);
    session_tool_definitions_with_context(home, &cx, None)
}

/// Discover only the MCP servers relevant to this caller, before spawning them.
/// An empty profile retains its existing unrestricted meaning.
pub fn session_tool_definitions_with_context(
    home: &std::path::Path,
    cx: &orbit_tools::ToolContext,
    selection: Option<&[String]>,
) -> Vec<ToolDefinition> {
    // --bare skips discovering skills, mods, MCP servers and memory
    // files (phase 6: fast start for scripts).
    if bare_mode() {
        return tool_definitions();
    }
    let mut defs = tool_definitions();

    // The Skill tool: load a skill's body on demand.
    defs.push(skill_tool_definition());

    // The Task tool: spawn a subagent (phase 5).
    defs.push(task_tool_definition());
    defs.extend(agent_control_definitions());

    // Availability reads only trusted configuration; diagnostics launch on demand.
    if selection
        .is_none_or(|names| names.is_empty() || names.iter().any(|name| name == "LspDiagnostics"))
        && cx
            .ext::<crate::tool_runtime::LspToolSelection>()
            .is_none_or(|allowed| allowed.0)
        && crate::lsp::availability(home, cx).is_ok_and(|available| available.is_some())
    {
        defs.push(crate::lsp::tool_definition());
    }

    // MCP tools.
    let trusted =
        orbit_tools::permissions::FolderTrust::new(home.to_path_buf()).is_trusted(&cx.working_dir);
    let Ok(cfg) = orbit_mcp::McpConfig::try_load_at(home, &cx.working_dir, trusted) else {
        return defs
            .into_iter()
            .filter(|tool| crate::plugin_content::exposed(cx, &tool.name))
            .collect();
    };
    let selected = crate::tool_runtime::effective_mcp_tool_selection(cx, selection);
    let selection = selected.as_deref();
    let mut emitted_mcp = std::collections::HashSet::new();
    for (name, server) in &cfg.servers {
        if !server.enabled
            || !crate::plugin_content::server_exposed(cx, &cfg, name)
            || server.tools.as_ref().is_some_and(Vec::is_empty)
            || selection
                .is_some_and(|names| !crate::plugin_content::selects_mcp_server(&cfg, names, name))
        {
            continue;
        }
        // The process-lifetime pool: one server process per name,
        // reused across calls and definition builds (phase 5).
        let mut options =
            orbit_mcp::McpCallOptions::new(std::time::Duration::from_millis(server.timeout_ms));
        options.cancel = cx.cancel_check();
        options.working_dir = Some(cx.working_dir.clone());
        if let Ok(tools) = orbit_mcp::POOL.list_tools_with_options(name, server, &options) {
            for t in tools {
                let wire = orbit_mcp::wire_name(name, &t.name);
                if !server.tool_enabled(&t.name)
                    || !crate::plugin_content::selected(cx, selection, &wire)
                    || !crate::plugin_content::exposed(cx, &wire)
                    || !crate::tool_runtime::resolve_mcp_target_in(&cfg, &wire).is_ok_and(
                        |(resolved_server, resolved_tool)| {
                            resolved_server == *name && resolved_tool == t.name
                        },
                    )
                    || !emitted_mcp.insert(wire.clone())
                {
                    continue;
                }
                let mut bytes = Vec::new();
                bytes.extend_from_slice(wire.as_bytes());
                bytes.extend_from_slice(t.description.as_bytes());
                bytes.extend_from_slice(
                    serde_json::to_string(&t.input_schema)
                        .unwrap_or_default()
                        .as_bytes(),
                );
                defs.push(ToolDefinition {
                    name: wire.clone(),
                    description: format!("{} (mcp: {name})", t.description),
                    parameters: t.input_schema,
                    schema_digest: orbit_adapter::types::Sha256Digest(hex::encode(
                        sha2::Sha256::digest(&bytes),
                    )),
                });
            }
        }
    }
    defs.into_iter()
        .filter(|tool| crate::plugin_content::exposed(cx, &tool.name))
        .collect()
}

/// The Skill tool definition (phase 5).
fn skill_tool_definition() -> ToolDefinition {
    let name = "Skill";
    let description =
        "Load a skill's full instructions by name (the index is in the system prompt)";
    let parameters = serde_json::json!({
        "type": "object",
        "properties": {
            "name": { "type": "string", "description": "The skill to load" }
        },
        "required": ["name"]
    });
    let mut bytes = Vec::new();
    bytes.extend_from_slice(name.as_bytes());
    bytes.extend_from_slice(description.as_bytes());
    bytes.extend_from_slice(
        serde_json::to_string(&parameters)
            .unwrap_or_default()
            .as_bytes(),
    );
    ToolDefinition {
        name: name.into(),
        description: description.into(),
        parameters,
        schema_digest: orbit_adapter::types::Sha256Digest(hex::encode(sha2::Sha256::digest(
            &bytes,
        ))),
    }
}

/// The Task tool definition (phase 5): spawn a subagent. The agent
/// list is in the system prompt; the subagent runs a nested engine
/// turn with the agent's restricted tool set and returns its final
/// report.
fn task_tool_definition() -> ToolDefinition {
    let name = "Task";
    let description = "Run or resume a subagent: Explore (read-only research), Plan (implementation plan), or general-purpose (delegated work). Returns its stable agent_id and final report. Resume retains the conversation and model. Queued messages are delivered only on an explicit resume.";
    let parameters = serde_json::json!({
        "type": "object",
        "properties": {
            "agent": { "type": "string", "description": "The subagent to run (Explore, Plan, general-purpose)" },
            "prompt": { "type": "string", "description": "The task for the subagent" },
            "name": { "type": "string", "description": "Optional display name when creating an agent" },
            "resume": { "type": "string", "description": "Stable agent_id to resume with the same agent type" },
            "model": { "type": "string", "description": "Explicit configured model or provider/model override" },
            "effort": { "type": ["boolean", "string", "null"], "description": "Exact declared boolean or level; null or default resets to this model's default. Absent retains the saved/profile/same-model parent selection." }
        },
        "required": ["agent", "prompt"]
    });
    let mut bytes = Vec::new();
    bytes.extend_from_slice(name.as_bytes());
    bytes.extend_from_slice(description.as_bytes());
    bytes.extend_from_slice(
        serde_json::to_string(&parameters)
            .unwrap_or_default()
            .as_bytes(),
    );
    ToolDefinition {
        name: name.into(),
        description: description.into(),
        parameters,
        schema_digest: orbit_adapter::types::Sha256Digest(hex::encode(sha2::Sha256::digest(
            &bytes,
        ))),
    }
}

fn agent_control_definitions() -> Vec<ToolDefinition> {
    [
        (
            "ListAgents",
            "List this session's agents, IDs, names, models, status and pending message counts. Does not include conversation or message contents.",
            serde_json::json!({
                "type": "object",
                "properties": {
                    "offset": { "type": "integer", "minimum": 0, "description": "Start at next_offset from the previous page; default 0" },
                    "limit": { "type": "integer", "minimum": 1, "maximum": 64, "description": "Maximum agents to return; default 20" }
                }
            }),
        ),
        (
            "AgentSendMessage",
            "Queue a message for this session's agent. Delivery occurs only on its next explicit Task resume; this does not start or steer a running agent.",
            serde_json::json!({
                "type": "object",
                "properties": {
                    "agent_id": { "type": "string" },
                    "message": { "type": "string" }
                },
                "required": ["agent_id", "message"]
            }),
        ),
    ]
    .into_iter()
    .map(|(name, description, parameters)| {
        BuiltinTool {
            name,
            description,
            parameters,
            execute: |_| Err("agent control requires a session context".into()),
        }
        .to_definition()
    })
    .collect()
}

/// Keeps a child turn's cancel token in step with its parent's check: a
/// helper thread polls the check every 50 ms and cancels the token when
/// it fires. Dropping the link stops the thread, so it never outlives
/// the child turn.
pub struct CancelLink {
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl Drop for CancelLink {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::SeqCst);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

/// Make `child` follow `parent` (see [`CancelLink`]). No parent check:
/// nothing to follow, no thread.
pub fn link_cancel(
    parent: Option<orbit_tools::CancelCheck>,
    child: &orbit_provider_http::CancelToken,
) -> CancelLink {
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let handle = parent.map(|check| {
        let (child, stop) = (child.clone(), stop.clone());
        std::thread::spawn(move || {
            while !stop.load(std::sync::atomic::Ordering::SeqCst) {
                if check() {
                    child.cancel();
                    return;
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
        })
    });
    CancelLink { stop, handle }
}

/// Execute the Task tool: run a subagent as a nested engine turn.
/// `turn_config` carries the provider/gate/model the session already
/// uses; the subagent's own tool set comes from its definition.
#[allow(dead_code)] // compatibility for existing callers without a session context
pub fn execute_task(
    home: &std::path::Path,
    agent_name: &str,
    prompt: &str,
    turn_config: &orbit_engine::TurnConfig,
    approval: &mut dyn crate::tool_runtime::ApprovalChannel,
    parent_cancel: Option<orbit_tools::CancelCheck>,
    observe: Option<&(dyn Fn(&crate::tool_runtime::SubagentUpdate) + Send + Sync)>,
) -> Result<serde_json::Value, String> {
    let session_id = format!("legacy-task-{}", ulid::Ulid::new());
    let cwd = std::env::current_dir().unwrap_or_else(|_| ".".into());
    let cx = orbit_tools::ToolContext::new(home.into(), session_id.clone(), cwd);
    crate::tool_runtime::remember_turn_config(&cx, turn_config);
    if let Some(check) = parent_cancel {
        cx.push_cancel_check(check);
    }
    execute_task_in_session(
        home,
        &session_id,
        &serde_json::json!({ "agent": agent_name, "prompt": prompt }),
        &cx,
        &crate::tool_runtime::PermissionScope::default(),
        approval,
        observe,
    )
    .map_err(|error| error.message)
}

pub(crate) struct AgentTaskError {
    pub(crate) message: String,
    agent_id: Option<String>,
    context_notices: Vec<String>,
}

impl From<String> for AgentTaskError {
    fn from(message: String) -> Self {
        Self {
            message,
            agent_id: None,
            context_notices: Vec::new(),
        }
    }
}

impl AgentTaskError {
    fn for_agent(message: String, id: &str) -> Self {
        Self {
            message,
            agent_id: Some(id.into()),
            context_notices: Vec::new(),
        }
    }

    fn with_context_notices(mut self, notices: Vec<String>) -> Self {
        self.context_notices = notices;
        self
    }

    pub(crate) fn into_value(self) -> serde_json::Value {
        let mut value =
            serde_json::json!({ "ok": false, "error": self.message, "agent_id": self.agent_id });
        if !self.context_notices.is_empty() {
            value["context_notices"] = serde_json::json!(self.context_notices);
        }
        value
    }
}

fn task_context_notice(role: &str, notice: &crate::model_limits::BudgetNotice) -> String {
    use crate::model_limits::{BudgetNotice, LimitComponent};
    let component = |component: &LimitComponent| match component {
        LimitComponent::Input => "input",
        LimitComponent::Combined => "combined context",
        LimitComponent::Output => "output",
    };
    match notice {
        BudgetNotice::FallbackPolicy { .. } => {
            format!(
                "{role} context uses a harness fallback policy; declare an explicit context limit to replace it."
            )
        }
        BudgetNotice::LegacyContextUnspecified => {
            format!(
                "{role} legacy context has no ownership evidence; declare an explicit context limit to preserve a local policy."
            )
        }
        BudgetNotice::StaleObservation(limit) => {
            format!(
                "{role} {} observation is stale; its limit was excluded from the budget.",
                component(limit)
            )
        }
        BudgetNotice::UnusableObservation(limit) => {
            format!(
                "{role} {} observation cannot establish a usable limit and was excluded from the budget.",
                component(limit)
            )
        }
    }
}

fn optional_task_string<'a>(
    args: &'a serde_json::Value,
    key: &str,
) -> Result<Option<&'a str>, String> {
    match args.get(key) {
        None => Ok(None),
        Some(value) => value
            .as_str()
            .filter(|s| !s.trim().is_empty())
            .map(Some)
            .ok_or_else(|| format!("Task/Agent '{key}' must be a non-empty string")),
    }
}

fn task_effort_setting(
    args: &serde_json::Value,
) -> Result<Option<orbit_adapter::types::EffortSetting>, String> {
    use orbit_adapter::types::{EffortSetting, EffortValue};
    match args.get("effort") {
        None => Ok(None),
        Some(serde_json::Value::Null) => Ok(Some(EffortSetting::Default)),
        Some(serde_json::Value::Bool(value)) => {
            Ok(Some(EffortSetting::Value(EffortValue::Bool(*value))))
        }
        Some(serde_json::Value::String(value)) if value == "default" => {
            Ok(Some(EffortSetting::Default))
        }
        Some(serde_json::Value::String(value)) => {
            let value = EffortValue::Level(value.clone());
            value.validate()?;
            Ok(Some(EffortSetting::Value(value)))
        }
        Some(_) => {
            Err("Task/Agent 'effort' must be a boolean, exact level, null, or default".into())
        }
    }
}

fn resolve_agent_effort(
    home: &std::path::Path,
    parent_cx: &orbit_tools::ToolContext,
    config: &mut orbit_engine::TurnConfig,
    explicit: Option<&orbit_adapter::types::EffortSetting>,
    saved: Option<&orbit_engine::agent_store::AgentSnapshot>,
    profile: Option<&orbit_adapter::types::EffortSetting>,
    explicit_model: bool,
) -> Result<orbit_adapter::types::EffortSetting, String> {
    use orbit_adapter::types::EffortSetting;
    let parent = crate::tool_runtime::session_subagent_config(parent_cx, home);
    let same_parent = parent.provider_id == config.provider_id && parent.model == config.model;
    let model_spec = format!("{}/{}", config.provider_id, config.model);
    let model_changed = explicit_model && saved.is_some_and(|s| s.model != model_spec);
    // An explicit new target also discards a parent override. Equality alone is
    // insufficient to revive old saved choices after a real model change.
    let parent_selection = parent_cx.ext::<crate::tool_runtime::SessionEffortSetting>();
    let setting = explicit
        .or_else(|| {
            (!model_changed)
                .then(|| saved.and_then(|s| s.effort.as_ref()))
                .flatten()
        })
        .or(profile)
        .or_else(|| {
            (same_parent && !model_changed)
                .then(|| parent_selection.as_ref().and_then(|s| s.0.as_ref()))
                .flatten()
        })
        .cloned()
        .unwrap_or(EffortSetting::Default);
    crate::apply_effort_setting(home, config, &setting)?;
    Ok(setting)
}

/// Run an owned, durable agent conversation through the existing synchronous
/// engine. No stored state restores permissions or credentials.
pub(crate) fn execute_task_in_session(
    home: &std::path::Path,
    session_id: &str,
    args: &serde_json::Value,
    parent_cx: &orbit_tools::ToolContext,
    scope: &crate::tool_runtime::PermissionScope,
    approval: &mut dyn crate::tool_runtime::ApprovalChannel,
    observe: Option<&(dyn Fn(&crate::tool_runtime::SubagentUpdate) + Send + Sync)>,
) -> Result<serde_json::Value, AgentTaskError> {
    execute_task_resolved(
        home, session_id, args, parent_cx, scope, approval, observe, None,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn execute_task_resolved(
    home: &std::path::Path,
    session_id: &str,
    args: &serde_json::Value,
    parent_cx: &orbit_tools::ToolContext,
    scope: &crate::tool_runtime::PermissionScope,
    approval: &mut dyn crate::tool_runtime::ApprovalChannel,
    observe: Option<&(dyn Fn(&crate::tool_runtime::SubagentUpdate) + Send + Sync)>,
    resolved: Option<orbit_engine::skills::CatalogAgent>,
) -> Result<serde_json::Value, AgentTaskError> {
    use crate::tool_runtime::SubagentUpdate;
    use orbit_engine::agent_store::AgentStatus;

    // This check precedes model resolution and creation of any persisted agent.
    let parent_agent_id = crate::tool_runtime::agent_parent_and_depth(parent_cx, session_id)?;
    let agent_type = orbit_tools::agent_permission_key(args).pattern;
    let prompt = args
        .get("prompt")
        .or_else(|| args.get("description"))
        .and_then(|v| v.as_str())
        .filter(|p| !p.trim().is_empty())
        .ok_or_else(|| "Task/Agent requires a 'prompt'".to_string())?;
    let resume = optional_task_string(args, "resume")?;
    let name = optional_task_string(args, "name")?;
    let explicit = optional_task_string(args, "model")?;
    let explicit_effort = task_effort_setting(args)?;
    if resume.is_some() && name.is_some() {
        return Err("Task/Agent 'name' is only accepted when creating an agent"
            .to_string()
            .into());
    }
    let trusted =
        orbit_tools::permissions::FolderTrust::new(home.into()).is_trusted(&parent_cx.working_dir);
    let supplied_profile = resolved.is_some();
    let profile = match resolved {
        Some(profile) => profile,
        None => crate::plugin_content::resolve_agent(parent_cx, &agent_type)?,
    };
    let agent = &profile.agent;
    let store = crate::tool_runtime::agent_store_for_context(home, session_id, parent_cx)?;
    let saved = resume.map(|id| store.load(id)).transpose()?;
    if let Some(saved) = &saved
        && saved.agent_type != agent_type
    {
        return Err(AgentTaskError::for_agent(
            format!(
                "agent type mismatch: stored '{}', requested '{}'",
                saved.agent_type, agent_type
            ),
            &saved.agent_id,
        ));
    }
    let mut turn_config = crate::tool_runtime::task_config_for(
        parent_cx,
        home,
        &agent_type,
        explicit,
        saved.as_ref().map(|s| s.model.as_str()),
        (!agent.model.is_empty()).then_some(agent.model.as_str()),
    )?;
    let fresh = saved.is_none();
    if fresh {
        let origin = if explicit.is_some() || !agent.model.trim().is_empty() {
            crate::phase_routing::SelectionOrigin::AgentExplicit
        } else {
            crate::phase_routing::SelectionOrigin::Role
        };
        // Classify once before creating the durable agent. The actual selected
        // identity and compatible effort are persisted before any provider call.
        turn_config = crate::try_phase_turn_config(home, &turn_config, prompt, origin)?.0;
        turn_config.sampling = None;
    }
    let snapshot = match saved {
        Some(snapshot) => snapshot,
        None => {
            let setting = resolve_agent_effort(
                home,
                parent_cx,
                &mut turn_config,
                explicit_effort.as_ref(),
                None,
                agent.effort.as_ref(),
                explicit.is_some(),
            )?;
            let model_spec = format!("{}/{}", turn_config.provider_id, turn_config.model);
            store.create_with_effort(
                &agent_type,
                name,
                &model_spec,
                Some(setting),
                parent_agent_id.as_deref(),
            )?
        }
    };
    let id = snapshot.agent_id.clone();
    let run = store
        .begin_resolved(&id, |leased| {
            if leased.agent_type != agent_type {
                return Err("leased agent type changed".into());
            }
            turn_config = crate::tool_runtime::task_config_for(
                parent_cx,
                home,
                &agent_type,
                explicit,
                Some(&leased.model),
                (!agent.model.is_empty()).then_some(agent.model.as_str()),
            )?;
            if !fresh {
                // Resumed identity is read under its lease and remains an
                // explicit pin even when its model equals a configured default.
                turn_config = crate::try_phase_turn_config(
                    home,
                    &turn_config,
                    prompt,
                    crate::phase_routing::SelectionOrigin::AgentExplicit,
                )?
                .0;
                turn_config.sampling = None;
            }
            let setting = resolve_agent_effort(
                home,
                parent_cx,
                &mut turn_config,
                explicit_effort.as_ref(),
                Some(leased),
                agent.effort.as_ref(),
                explicit.is_some(),
            )?;
            Ok((
                format!("{}/{}", turn_config.provider_id, turn_config.model),
                Some(setting),
            ))
        })
        .map_err(|error| AgentTaskError::for_agent(error, &id))?;

    let mut input = String::new();
    if run.interrupted_previous_run() {
        input.push_str("The previous run was interrupted. Inspect the actual work and tool results before continuing; do not automatically replay the previous task.\n\n");
    }
    for message in run.messages() {
        input.push_str(&format!(
            "Queued message {} from {}:\n{}\n\n",
            message.message_id,
            message
                .sender_agent_id
                .as_deref()
                .unwrap_or("owning session"),
            message.text
        ));
    }
    input.push_str(prompt);
    let mut transcript = run.snapshot().transcript.clone();
    let turns = run.snapshot().turns.checked_add(1);
    let session_tools =
        session_tool_definitions_with_context(home, parent_cx, profile.allowed_tools.as_deref());
    let sub_tools: Vec<_> = if profile.allowed_tools.is_none() {
        session_tools
    } else {
        session_tools
            .into_iter()
            .filter(|tool| {
                crate::plugin_content::selected(
                    parent_cx,
                    profile.allowed_tools.as_deref(),
                    &tool.name,
                )
            })
            .collect()
    }
    .into_iter()
    .filter(|tool| crate::plugin_content::exposed(parent_cx, &tool.name))
    .collect();
    let hooks = orbit_engine::hooks::Hooks::load(home, trusted);
    let _ = hooks.fire(
        orbit_engine::hooks::HookEvent::SubagentStart,
        &serde_json::json!({ "agent": agent.name, "agent_id": id, "prompt_bytes": prompt.len() }),
    );
    let cancel = orbit_provider_http::CancelToken::new();
    let parent_cancel = parent_cx.cancel_check();
    if parent_cancel.as_ref().is_some_and(|check| check()) {
        cancel.cancel();
    }
    let _link = link_cancel(parent_cancel, &cancel);
    let mut system_directive = format!(
        "You are {name}, a subagent. {desc}\n\nComplete the task and reply with your final report. You do not see the parent conversation.",
        name = agent.name,
        desc = agent.description
    );
    if !agent.instructions.is_empty() {
        system_directive.push_str("\n\n");
        if supplied_profile {
            system_directive.push_str(&agent.instructions);
        } else {
            system_directive.push_str(&crate::plugin_content::expand_prompt(
                &agent.instructions,
                &[],
                profile.binding.as_ref(),
            )?);
        }
    }
    let mut options = orbit_engine::TurnOptions {
        session_id: id.clone(),
        tools: sub_tools,
        max_rounds: agent.max_turns,
        system_directive: Some(system_directive),
        request_stem: format!("orbit-task-{id}"),
        ..Default::default()
    };
    let child_cx = crate::tool_runtime::child_agent_context(home, session_id, &id, parent_cx);
    crate::plugin_content::restrict_context(&child_cx, profile.allowed_tools.as_deref())?;
    crate::tool_runtime::remember_effort_setting(&child_cx, &run.snapshot().effort);
    crate::tool_runtime::set_mcp_tool_selection_exact(
        &child_cx,
        parent_cx,
        &options
            .tools
            .iter()
            .filter(|tool| tool.name.starts_with("mcp__"))
            .map(|tool| tool.name.clone())
            .collect::<Vec<_>>(),
    );
    crate::tool_runtime::set_lsp_tool_selection(&child_cx, parent_cx, &agent.tools);
    let mut executor = crate::tool_runtime::SubagentExecutor::with_context(
        home.into(),
        id.clone(),
        child_cx,
        scope.clone(),
        approval,
    );
    let notify = |update: SubagentUpdate| {
        if let Some(observe) = observe {
            observe(&update);
        }
    };
    notify(SubagentUpdate::Started {
        id: id.clone(),
        name: agent.name.clone(),
        model: turn_config.model.clone(),
        task: prompt
            .lines()
            .map(str::trim)
            .find(|line| !line.is_empty())
            .unwrap_or("")
            .into(),
    });
    // The lease has resolved the actual child identity, output, effort and
    // sampling. Resolve its summary role independently, then bind both exact
    // final configurations without changing either after budget resolution.
    // This run came from the local store constructed with this same trusted
    // home above; neither the run nor its accounting home comes from tool args.
    let accounting = crate::session_accounting::prepare_child(
        home,
        &run,
        if fresh {
            crate::session_accounting::ChildOrigin::CreatedThisInvocation
        } else {
            crate::session_accounting::ChildOrigin::Resumed
        },
    )
    .map_err(|error| error.to_string());
    let resolution: Result<_, String> = (|| {
        accounting.as_ref().map_err(Clone::clone)?;
        turns.ok_or_else(|| "agent turn count overflows".to_owned())?;
        if cancel.is_cancelled() {
            // Keep the existing engine cancellation lifecycle and prompt
            // preservation; a pre-cancelled child needs no metadata read.
            return Ok(None);
        }
        let retry_policy = crate::provider_policies::load_for_config(home, &turn_config)
            .map_err(|error| error.to_string())?;
        let compaction = crate::try_role_turn_config(home, &turn_config, "compaction")?;
        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| "context budget observation time is unavailable".to_owned())?
            .as_secs();
        let reports = crate::model_limits::resolve_turn_budgets_detailed(
            home,
            &turn_config,
            &compaction,
            now_unix,
        )
        .map_err(|error| error.to_string())?;
        Ok(Some((compaction, reports, retry_policy)))
    })();
    let mut context_notices = Vec::new();
    let result: Result<_, String> = (|| {
        let resolved = resolution?;
        let retry_policy = if let Some((compaction, reports, retry_policy)) = resolved {
            for (role, report) in [("Child", &reports.selected), ("Summary", &reports.summary)] {
                for notice in &report.notices {
                    let action = task_context_notice(role, notice);
                    notify(SubagentUpdate::Progress {
                        id: id.clone(),
                        action: action.clone(),
                    });
                    context_notices.push(action);
                }
            }
            options.selected_budget = Some(reports.selected.budget);
            options.compaction_budget = Some(reports.summary.budget);
            options.compaction_config = Some(compaction);
            retry_policy
        } else {
            None
        };
        accounting
            .as_ref()
            .map_err(Clone::clone)?
            .apply_options_detailed(&mut options, None, retry_policy.as_ref())
            .map_err(|error| error.to_string())?;
        Ok(orbit_engine::turn::run_turn_detailed_with_retry_policy(
            home,
            &turn_config,
            &options,
            &input,
            &mut transcript,
            &mut executor,
            &cancel,
            &mut |event| match event {
                orbit_frontend_protocol::FrontendEvent::ToolStartedFull {
                    kind, target, ..
                } => {
                    notify(SubagentUpdate::Progress {
                        id: id.clone(),
                        action: format!("{kind} {target}").trim().into(),
                    });
                }
                orbit_frontend_protocol::FrontendEvent::Status { text } => {
                    let action = orbit_hud_tui::safe_text(&text);
                    notify(SubagentUpdate::Progress {
                        id: id.clone(),
                        action: action.clone(),
                    });
                    context_notices.push(action);
                }
                _ => {}
            },
            retry_policy.as_ref(),
        )
        .into_completion())
    })();
    let (mut ok, rounds, mut status, report_text, mut failure) = match result {
        Ok(completion) => {
            let (ok, status, failure) = match completion.end {
                orbit_engine::TurnEnd::Completed => (true, AgentStatus::Completed, None),
                orbit_engine::TurnEnd::Cancelled => (false, AgentStatus::Cancelled, None),
                orbit_engine::TurnEnd::Failed(error) => {
                    (false, AgentStatus::Failed, Some(error.message))
                }
            };
            let text = if completion.report.final_text.is_empty() {
                failure.clone().unwrap_or_default()
            } else {
                completion.report.final_text
            };
            (ok, completion.report.rounds, status, text, failure)
        }
        Err(error) => {
            // The engine did not append this input. Keep it exactly once even
            // when checked accounting refuses the operation before dispatch.
            transcript.push(orbit_engine::user_message(input.clone()));
            let status = if accounting.is_err() {
                AgentStatus::Interrupted
            } else if cancel.is_cancelled() {
                AgentStatus::Cancelled
            } else {
                AgentStatus::Failed
            };
            (false, 0, status, error.clone(), Some(error))
        }
    };
    if let Ok(accounting) = &accounting {
        let inspected = accounting
            .checkpoint_detailed()
            .map_err(|error| error.to_string());
        let uncertain = match &inspected {
            Ok(checkpoint) => {
                checkpoint.pending().is_some()
                    || checkpoint.totals().knownness == orbit_engine::AccountingKnownness::Uncertain
            }
            Err(_) => true,
        };
        if uncertain {
            ok = false;
            status = AgentStatus::Interrupted;
            if failure.is_none() {
                failure = Some(inspected.err().unwrap_or_else(|| {
                    "child request accounting is uncertain; inspect before continuing".into()
                }));
            }
        }
    }
    let turns = turns.unwrap_or(run.snapshot().turns);
    let persisted = run.finish(transcript, report_text.clone(), status, turns);
    let _ = hooks.fire(
        orbit_engine::hooks::HookEvent::SubagentStop,
        &serde_json::json!({ "agent": agent.name, "agent_id": id, "ok": ok }),
    );
    notify(SubagentUpdate::Finished {
        id: id.clone(),
        ok: ok && persisted.is_ok(),
        report: persisted.as_ref().err().cloned().unwrap_or_else(|| {
            if !report_text.is_empty() {
                report_text.clone()
            } else if status == AgentStatus::Cancelled {
                "cancelled".into()
            } else {
                "stopped before it finished".into()
            }
        }),
    });
    let snapshot = persisted.map_err(|error| {
        AgentTaskError::for_agent(error, &id).with_context_notices(context_notices.clone())
    })?;
    if let Some(error) = failure {
        return Err(AgentTaskError::for_agent(error, &id).with_context_notices(context_notices));
    }
    let mut result = serde_json::json!({
        "ok": ok, "agent": agent.name, "agent_id": id, "name": snapshot.name,
        "model": snapshot.model, "effort": snapshot.effort, "status": snapshot.status, "turns": snapshot.turns,
        "rounds": rounds, "report": report_text,
    });
    if !context_notices.is_empty() {
        result["context_notices"] = serde_json::json!(context_notices);
    }
    Ok(result)
}

/// Execute the Skill tool: return the named skill's body.
pub fn execute_skill(home: &std::path::Path, name: &str) -> Result<serde_json::Value, String> {
    let trusted = {
        let cwd = std::env::current_dir().unwrap_or_default();
        orbit_tools::permissions::FolderTrust::new(home.to_path_buf()).is_trusted(&cwd)
    };
    let skills = orbit_engine::skills::load_skills(home, trusted);
    skills
        .into_iter()
        .find(|s| s.name == name)
        .map(|s| serde_json::json!({ "ok": true, "body": s.body }))
        .ok_or_else(|| format!("unknown skill: {name}"))
}

/// Execute a tool by name with parsed JSON arguments. Unknown tools are denied
/// (fail closed). Returns the JSON result or a structured error string.
pub fn execute(name: &str, args: &serde_json::Value) -> Result<serde_json::Value, String> {
    for tool in builtin_tools() {
        if tool.name == name {
            return (tool.execute)(args);
        }
    }
    Err(format!("unknown tool: {name}"))
}

/// The risk of one call: a file write is Medium; a shell command is at
/// least Medium (it runs arbitrary code) and High when the command
/// itself looks destructive (`rm -rf`, `git push --force`, `curl | sh`).
/// `tool_risk` knows only the tool, so it called `rm -rf ~` the same
/// MEDIUM as `ls`.
pub fn call_risk(name: &str, args: &serde_json::Value) -> RiskLevel {
    if name == "Bash" {
        let cmd = args.get("command").and_then(|v| v.as_str()).unwrap_or("");
        return if orbit_tools::bash::command_risk(cmd) >= 3 {
            RiskLevel::High
        } else {
            RiskLevel::Medium
        };
    }
    tool_risk(name)
}

/// The lines an approval card shows under the action, from the call's
/// own arguments: what an Edit would remove and add, what a Write would
/// do to its target. Real values only — an Edit shows its `old_string`
/// and `new_string`, never an invented diff. `- ` removed, `+ ` added.
pub fn approval_preview(name: &str, args: &serde_json::Value) -> Vec<String> {
    const SIDE: usize = 4; // lines shown per side
    let lines = |key: &str| -> Vec<String> {
        args.get(key)
            .and_then(|v| v.as_str())
            .map(|s| s.lines().map(str::to_string).collect())
            .unwrap_or_default()
    };
    let clip = |l: &str| -> String { l.chars().take(160).collect() };
    let side = |marker: &str, all: &[String], out: &mut Vec<String>| {
        for l in all.iter().take(SIDE) {
            out.push(format!("{marker} {}", clip(l)));
        }
        if all.len() > SIDE {
            out.push(format!("  … {} more", all.len() - SIDE));
        }
    };
    match name {
        "Edit" => {
            let (old, new) = (lines("old_string"), lines("new_string"));
            let mut out = Vec::new();
            side("-", &old, &mut out);
            side("+", &new, &mut out);
            if args.get("replace_all").and_then(|v| v.as_bool()) == Some(true) {
                out.push("  every occurrence".to_string());
            }
            out
        }
        "Write" => {
            let n = lines("content").len();
            let exists = args
                .get("file_path")
                .and_then(|v| v.as_str())
                .map(|p| std::path::Path::new(p).exists())
                .unwrap_or(false);
            vec![if exists {
                format!("  replaces the file with {n} lines")
            } else {
                format!("  creates a new file · {n} lines")
            }]
        }
        _ => Vec::new(),
    }
}

/// Display-safe summary of a tool call's arguments (name + argument keys only;
/// never raw argument values — they may be secrets).
pub fn safe_call_summary(name: &str, args: &serde_json::Value) -> String {
    // The card and transcript lines must name the target (review
    // blocker 2): the path for file tools, the command for Bash. The
    // value passes the secret scanner first — a real secret redacts,
    // an ordinary path or command shows.
    // Glob and Grep search by `pattern`, WebFetch by `url`, … — the
    // summary names the VALUE the operator is approving, not the
    // argument's name ("Glob(pattern)" told them nothing).
    let target_keys: &[&str] = match name {
        "Bash" => &["command"],
        "Read" | "Write" | "Edit" => &["file_path"],
        "NotebookEdit" => &["notebook_path", "file_path"],
        "Glob" | "Grep" => &["pattern", "file_path"],
        "WebFetch" => &["url"],
        "WebSearch" => &["query"],
        "TaskCreate" => &["title"],
        _ => &[],
    };
    for key in target_keys {
        if let Some(v) = args.get(*key).and_then(|v| v.as_str()) {
            let scanned = orbit_tools::scan::scan_result(v);
            return format!("{name}({})", scanned.text.trim());
        }
    }
    // A subagent: WHICH agent, and what it was asked. The operator is
    // approving work that will run tools of its own, so "Task(agent,
    // prompt)" — the argument names — told them nothing.
    if matches!(name, "Task" | "Agent") {
        let who = ["agent", "agent_type", "subagent_type"]
            .iter()
            .find_map(|k| args.get(*k).and_then(|v| v.as_str()))
            .unwrap_or("");
        let task = args
            .get("prompt")
            .and_then(|v| v.as_str())
            .and_then(|p| p.lines().map(str::trim).find(|l| !l.is_empty()))
            .map(|l| orbit_tools::scan::scan_result(l).text)
            .map(|l| {
                let l = l.trim();
                if l.chars().count() > 100 {
                    format!("{}…", l.chars().take(99).collect::<String>())
                } else {
                    l.to_string()
                }
            })
            .unwrap_or_default();
        return match (who.is_empty(), task.is_empty()) {
            (false, false) => format!("{name}({who}: {task})"),
            (false, true) => format!("{name}({who})"),
            (true, false) => format!("{name}({task})"),
            (true, true) => format!("{name}()"),
        };
    }
    let keys: Vec<&str> = args
        .as_object()
        .map(|o| o.keys().map(String::as_str).collect())
        .unwrap_or_default();
    format!("{name}({})", keys.join(", "))
}

// ── Built-ins ────────────────────────────────────────────────────────────────

fn calculator() -> BuiltinTool {
    BuiltinTool {
        name: "calculator",
        description: "Evaluate a pure arithmetic expression over numbers and the operators + - * / ( ) ^ % with integer and floating point operands. Never executes shell or code.",
        parameters: serde_json::json!({
            "type": "object",
            "properties": {
                "expression": {
                    "type": "string",
                    "description": "Arithmetic expression, e.g. '2 * (3 + 4)' or '10 / 4'"
                }
            },
            "required": ["expression"]
        }),
        execute: |args| {
            let expr = args
                .get("expression")
                .and_then(|v| v.as_str())
                .ok_or_else(|| "calculator requires a string 'expression'".to_string())?;
            if expr.len() > 512 {
                return Err("expression too long".into());
            }
            if !expr
                .chars()
                .all(|c| c.is_ascii_digit() || c.is_ascii_whitespace() || "+-*/()^%.".contains(c))
            {
                return Err("expression contains disallowed characters".into());
            }
            let result = eval_arithmetic(expr).ok_or_else(|| "invalid expression".to_string())?;
            Ok(serde_json::json!({ "result": result }))
        },
    }
}

/// Tiny recursive-descent evaluator for + - * / ^ % over f64. Pure, no eval.
fn eval_arithmetic(expr: &str) -> Option<f64> {
    let mut chars = expr.chars().peekable();
    let mut pos = 0usize;
    let value = parse_expr(&mut chars, &mut pos)?;
    if chars.next().is_some() {
        return None; // trailing garbage
    }
    Some(value)
}

fn parse_expr(chars: &mut std::iter::Peekable<std::str::Chars>, pos: &mut usize) -> Option<f64> {
    let mut left = parse_term(chars, pos)?;
    loop {
        match chars.peek().copied() {
            Some('+') => {
                *pos += 1;
                chars.next();
                left += parse_term(chars, pos)?;
            }
            Some('-') => {
                *pos += 1;
                chars.next();
                left -= parse_term(chars, pos)?;
            }
            _ => return Some(left),
        }
    }
}

fn parse_term(chars: &mut std::iter::Peekable<std::str::Chars>, pos: &mut usize) -> Option<f64> {
    let mut left = parse_power(chars, pos)?;
    loop {
        match chars.peek().copied() {
            Some('*') => {
                *pos += 1;
                chars.next();
                left *= parse_power(chars, pos)?;
            }
            Some('/') => {
                *pos += 1;
                chars.next();
                let denom = parse_power(chars, pos)?;
                if denom == 0.0 {
                    return None; // division by zero
                }
                left /= denom;
            }
            Some('%') => {
                *pos += 1;
                chars.next();
                let denom = parse_power(chars, pos)?;
                if denom == 0.0 {
                    return None;
                }
                left %= denom;
            }
            _ => return Some(left),
        }
    }
}

fn parse_power(chars: &mut std::iter::Peekable<std::str::Chars>, pos: &mut usize) -> Option<f64> {
    let base = parse_unary(chars, pos)?;
    if chars.peek() == Some(&'^') {
        *pos += 1;
        chars.next();
        let exp = parse_unary(chars, pos)?;
        return Some(base.powf(exp));
    }
    Some(base)
}

fn parse_unary(chars: &mut std::iter::Peekable<std::str::Chars>, pos: &mut usize) -> Option<f64> {
    while chars
        .peek()
        .map(|c| c.is_ascii_whitespace())
        .unwrap_or(false)
    {
        *pos += 1;
        chars.next();
    }
    match chars.peek().copied() {
        Some('-') => {
            *pos += 1;
            chars.next();
            Some(-parse_unary(chars, pos)?)
        }
        Some('+') => {
            *pos += 1;
            chars.next();
            parse_unary(chars, pos)
        }
        Some('(') => {
            *pos += 1;
            chars.next();
            let inner = parse_expr(chars, pos)?;
            if chars.next() != Some(')') {
                return None;
            }
            *pos += 1;
            Some(inner)
        }
        _ => parse_number(chars, pos),
    }
}

fn parse_number(chars: &mut std::iter::Peekable<std::str::Chars>, pos: &mut usize) -> Option<f64> {
    while chars
        .peek()
        .map(|c| c.is_ascii_whitespace())
        .unwrap_or(false)
    {
        *pos += 1;
        chars.next();
    }
    let mut s = String::new();
    let mut saw_dot = false;
    while let Some(c) = chars.peek().copied() {
        if c.is_ascii_digit() {
            s.push(c);
            *pos += 1;
            chars.next();
        } else if c == '.' && !saw_dot {
            saw_dot = true;
            s.push(c);
            *pos += 1;
            chars.next();
        } else {
            break;
        }
    }
    if s.is_empty() {
        return None;
    }
    s.parse::<f64>().ok()
}

fn current_session_tool() -> BuiltinTool {
    BuiltinTool {
        name: "current_session",
        description: "Read-only metadata about the current ORBIT session: session id, model, provider, turn count, and token usage. Contains no prompts, secrets, or conversation content.",
        parameters: serde_json::json!({
            "type": "object",
            "properties": {},
            "additionalProperties": false
        }),
        execute: |_args| {
            // Populated by the harness via a thread-local/closure set before
            // execution; a missing snapshot yields the empty default.
            let snap = SESSION_SNAPSHOT.with(|s| s.borrow().clone());
            Ok(serde_json::json!({
                "session_id": snap.session_id,
                "model": snap.model,
                "provider": snap.provider,
                "turns": snap.turns,
                "input_tokens": snap.input_tokens,
                "output_tokens": snap.output_tokens,
            }))
        },
    }
}

fn list_models_tool() -> BuiltinTool {
    BuiltinTool {
        name: "list_models",
        description: "List every model id declared across all configured providers (provider/model ids only).",
        parameters: serde_json::json!({
            "type": "object",
            "properties": {},
            "additionalProperties": false
        }),
        execute: |_args| {
            let home = config_home_from_env();
            let cfg = crate::config::ProvidersConfig::load(&home).unwrap_or_default();
            let models: Vec<serde_json::Value> = cfg
                .all_models()
                .into_iter()
                .map(|(p, m)| serde_json::json!({ "provider": p, "model": m }))
                .collect();
            Ok(serde_json::json!({ "models": models }))
        },
    }
}

/// Session snapshot exposed to `current_session` (never prompts/secrets).
#[derive(Clone, Default)]
pub struct SessionSnapshot {
    pub session_id: String,
    pub model: String,
    pub provider: String,
    pub turns: u64,
    pub input_tokens: u64,
    pub output_tokens: u64,
}

thread_local! {
    pub static SESSION_SNAPSHOT: std::cell::RefCell<SessionSnapshot> =
        std::cell::RefCell::new(SessionSnapshot::default());
}

/// Validate + parse a tool call's accumulated arguments JSON.
pub fn parse_arguments(accumulated: &[u8]) -> Result<serde_json::Value, String> {
    if accumulated.is_empty() {
        return Err("tool call had no arguments".into());
    }
    serde_json::from_slice(accumulated).map_err(|e| format!("invalid arguments JSON: {e}"))
}

/// Validate a tool definition name against the built-in set (fail closed).
/// Read-only classification (backend-authoritative). Read-only tools
/// are parallel-safe AND allowed in plan mode — the model researches
/// while planning. Every current built-in is a pure-data calculator;
/// when write/shell tools land they classify false by default
/// (fail toward caution, like `tool_risk`).
pub fn is_read_only(name: &str) -> bool {
    orbit_tools::is_read_only(name)
        || matches!(
            name,
            "calculator" | "current_session" | "list_models" | "ListAgents" | "LspDiagnostics"
        )
}

pub fn is_known_tool(name: &str) -> bool {
    orbit_tools::is_wave1(name)
        || orbit_tools::registry().iter().any(|t| t.name() == name)
        || builtin_tools().iter().any(|t| t.name == name)
        // B3: these have handlers in tool_runtime::execute_call but
        // were denied as "unknown tool (deny-by-default)" before the
        // handlers were ever reached — Task and Skill are advertised
        // to the model in the same request.
        || name == "Skill"
        || name == "Task"
        || name == "Agent"
        || name == "ListAgents"
        || name == "AgentSendMessage"
        || name == "LspDiagnostics"
        || name.starts_with("mcp__")
}

/// Structured risk classification for a tool (backend-authoritative — the
/// UI never classifies actions itself; the facts rule).
/// All current built-ins are pure-data calculators: low risk. Shell/fs/net
/// tools, when they exist, will classify higher by construction.
/// The full classification vocabulary exists so future tools (shell, fs,
/// net) slot in without reshaping the type; v0.1's pure-data built-ins only
/// construct Low. `as_str` is exercised by tests and used by ledger/REPL
/// surfaces as they adopt the field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Destructive,
}

impl RiskLevel {
    #[allow(dead_code)]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Destructive => "destructive",
        }
    }

    /// 0..=3 for the ▰▰▱ badge.
    pub fn level(self) -> u8 {
        match self {
            Self::Low => 1,
            Self::Medium => 2,
            Self::High => 3,
            Self::Destructive => 3,
        }
    }
}

/// Risk classification for a known tool. Unknown tools never reach the UI
/// (deny-by-default before the approval channel), so this is total over the
/// known set.
pub fn tool_risk(name: &str) -> RiskLevel {
    // Wave 1 risk: Bash is per-command (the executor computes it);
    // writes are Medium at the classification level.
    if matches!(name, "Write" | "Edit") {
        return RiskLevel::Medium;
    }
    if orbit_tools::is_wave1(name) && !orbit_tools::is_read_only(name) {
        return RiskLevel::Medium;
    }
    // WebFetch: an egress question per domain — Low risk class (a read),
    // but it always asks for a new domain.
    if name == "WebFetch" {
        return RiskLevel::Low;
    }
    // All v0.1 built-ins are pure-data (calculator, session snapshot, model
    // list). Anything not explicitly classified defaults to medium — fail
    // toward caution, never silently low.
    match name {
        "calculator" | "current_session" | "list_models" => RiskLevel::Low,
        // Wave 2 pure-data tools: the task list is session state, not
        // the filesystem.
        "TaskList" => RiskLevel::Low,
        _ => RiskLevel::Medium,
    }
}

/// B3: a tool is advertised to the model only if a handler exists.
/// Every name in the session list must dispatch somewhere: the
/// registry (execute_wave1), a tool_runtime handler, or a pure
/// built-in. This is the invariant whose absence made six advertised
/// tools answer "unknown tool".
#[test]
fn advertised_tools_all_dispatch() {
    let home = std::env::temp_dir().join("orbit-b3-dispatch");
    let _ = std::fs::remove_dir_all(&home);
    std::fs::create_dir_all(&home).unwrap();
    let defs = session_tool_definitions(&home);
    assert!(!defs.is_empty(), "the session must offer tools");
    for d in &defs {
        let name = d.name.as_str();
        let handled = orbit_tools::is_wave1(name)
            || orbit_tools::registry().iter().any(|t| t.name() == name)
            || builtin_tools().iter().any(|t| t.name == name)
            || name == "Skill"
            || name == "Task"
            || name == "ListAgents"
            || name == "AgentSendMessage"
            || name.starts_with("mcp__");
        assert!(handled, "{name} is advertised but has no handler (B3)");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bare_tool_definitions_respect_startup_and_environment() {
        const CHILD: &str = "ORBIT_BARE_TOOL_TEST_CHILD";
        if let Ok(mode) = std::env::var(CHILD) {
            if mode == "flag" {
                enable_bare_mode();
            }
            let home = std::env::temp_dir().join(format!("orbit-bare-{}", ulid::Ulid::new()));
            std::fs::create_dir(&home).unwrap();
            let definitions = session_tool_definitions(&home);
            let has = |name: &str| definitions.iter().any(|tool| tool.name == name);
            assert!(has("Read") && has("Bash") && has("calculator"));
            if mode == "full" {
                assert!(has("Skill") && has("Task") && has("ListAgents"));
            } else {
                assert_eq!(definitions.len(), tool_definitions().len());
                assert!(!has("Skill") && !has("Task") && !has("ListAgents"));
            }
            std::fs::remove_dir_all(home).unwrap();
            println!("ORBIT_BARE_TOOLS_CHECKED={mode}");
            return;
        }
        for (mode, bare) in [("full", "0"), ("env", "1"), ("flag", "0")] {
            let mut child = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "tools::tests::bare_tool_definitions_respect_startup_and_environment",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env(CHILD, mode)
                .env("ORBIT_BARE", bare)
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .unwrap();
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
            loop {
                if child.try_wait().unwrap().is_some() {
                    break;
                }
                if std::time::Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    panic!("isolated bare-tool check timed out");
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            let output = child.wait_with_output().unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(
                String::from_utf8_lossy(&output.stdout)
                    .contains(&format!("ORBIT_BARE_TOOLS_CHECKED={mode}"))
            );
        }
    }

    #[test]
    fn risk_classification_is_backend_authoritative() {
        // Known pure-data tools are low; anything unclassified fails toward
        // medium, never silently low.
        assert_eq!(tool_risk("calculator"), RiskLevel::Low);
        assert_eq!(tool_risk("current_session"), RiskLevel::Low);
        assert_eq!(tool_risk("list_models"), RiskLevel::Low);
        assert_eq!(tool_risk("some_future_tool"), RiskLevel::Medium);
        assert_eq!(RiskLevel::Low.as_str(), "low");
        assert_eq!(RiskLevel::Medium.as_str(), "medium");
        assert_eq!(RiskLevel::High.as_str(), "high");
        assert_eq!(RiskLevel::Destructive.as_str(), "destructive");
        assert_eq!(RiskLevel::Destructive.level(), 3);
    }

    #[test]
    fn calculator_evaluates_without_code_execution() {
        let out = execute("calculator", &serde_json::json!({"expression":"2*(3+4)"})).unwrap();
        assert_eq!(out["result"].as_f64(), Some(14.0));
    }

    #[test]
    fn calculator_rejects_code_characters_and_div_zero() {
        assert!(
            execute(
                "calculator",
                &serde_json::json!({"expression":"system(\"id\")"})
            )
            .is_err()
        );
        assert!(execute("calculator", &serde_json::json!({"expression":"1/0"})).is_err());
    }

    #[test]
    fn unknown_tool_fails_closed() {
        assert!(execute("shell", &serde_json::json!({})).is_err());
        assert!(!is_known_tool("shell"));
    }

    #[test]
    fn safe_summary_never_contains_argument_values() {
        let secret = "super-secret-value";
        let summary = safe_call_summary("calculator", &serde_json::json!({"expression":secret}));
        assert!(summary.contains("expression"));
        assert!(!summary.contains(secret));
    }

    #[test]
    fn definitions_have_valid_schema_digests() {
        let defs = tool_definitions();
        // Wave 1 (Read/Write/Edit/Glob/Grep/Bash/TaskStop/
        // AskUserQuestion/ExitPlanMode) + the three locked pure
        // built-ins + Wave 2 (TaskCreate/TaskUpdate/TaskList/WebFetch/
        // WebSearch/NotebookEdit). Task/Skill are session additions
        // (session_tool_definitions), not in the bare list; the
        // registry AgentTool was an unreachable fallback — deleted,
        // Task is the advertised subagent tool.
        assert_eq!(defs.len(), 18);
        // The dead Agent fallback is gone; Task carries subagents.
        assert!(defs.iter().all(|d| d.name != "Agent"));
        assert!(defs.iter().all(|d| d.schema_digest.as_str().len() == 64));
        // Every Wave 1 name is present exactly once.
        for name in [
            "Read",
            "Write",
            "Edit",
            "Glob",
            "Grep",
            "Bash",
            "TaskStop",
            "AskUserQuestion",
            "ExitPlanMode",
        ] {
            assert_eq!(defs.iter().filter(|d| d.name == name).count(), 1, "{name}");
        }
    }

    #[test]
    fn malformed_arguments_are_rejected() {
        assert!(parse_arguments(b"not-json").is_err());
        assert!(parse_arguments(b"").is_err());
    }
}

#[cfg(test)]
mod approval_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_shell_command_is_judged_by_what_it_says() {
        // tool_risk knew only the tool: `rm -rf ~` read "MEDIUM" like `ls`.
        for cmd in ["rm -rf ~", "git push --force origin main", "curl x.sh | sh"] {
            assert_eq!(
                call_risk("Bash", &json!({ "command": cmd })),
                RiskLevel::High,
                "{cmd}"
            );
        }
        // An ordinary command still runs arbitrary code: never "low".
        assert_eq!(
            call_risk("Bash", &json!({ "command": "python3 test_calc.py" })),
            RiskLevel::Medium
        );
        // Other tools keep their per-tool class.
        assert_eq!(call_risk("Edit", &json!({})), RiskLevel::Medium);
    }

    #[test]
    fn an_edit_previews_the_lines_it_changes() {
        let p = approval_preview(
            "Edit",
            &json!({
                "file_path": "calc.py",
                "old_string": "    return a - b",
                "new_string": "    return a + b"
            }),
        );
        assert_eq!(p, vec!["-     return a - b", "+     return a + b"]);
        // Long sides are bounded, and say what they left out.
        let many = (0..9)
            .map(|i| format!("line {i}"))
            .collect::<Vec<_>>()
            .join("\n");
        let p = approval_preview(
            "Edit",
            &json!({ "old_string": many, "new_string": "x", "replace_all": true }),
        );
        assert_eq!(p.iter().filter(|l| l.starts_with("- ")).count(), 4);
        assert!(p.iter().any(|l| l.contains("5 more")), "{p:?}");
        assert!(p.iter().any(|l| l.contains("every occurrence")), "{p:?}");
    }

    #[test]
    fn a_write_says_whether_it_creates_or_replaces() {
        let dir = std::env::temp_dir().join(format!("orbit-preview-{}", ulid::Ulid::new()));
        std::fs::create_dir_all(&dir).unwrap();
        let existing = dir.join("a.txt");
        std::fs::write(&existing, "old").unwrap();
        let replace = approval_preview(
            "Write",
            &json!({ "file_path": existing.to_string_lossy(), "content": "a\nb\nc" }),
        );
        assert_eq!(replace, vec!["  replaces the file with 3 lines"]);
        let create = approval_preview(
            "Write",
            &json!({ "file_path": dir.join("new.txt").to_string_lossy(), "content": "a" }),
        );
        assert_eq!(create, vec!["  creates a new file · 1 lines"]);
        assert!(approval_preview("Bash", &json!({ "command": "ls" })).is_empty());
        let _ = std::fs::remove_dir_all(dir);
    }

    /// "Glob(pattern)" named the argument, not the thing approved.
    #[test]
    fn a_summary_names_the_value_being_approved() {
        assert_eq!(
            safe_call_summary("Glob", &json!({ "pattern": "**/*.py" })),
            "Glob(**/*.py)"
        );
        assert_eq!(
            safe_call_summary("Grep", &json!({ "pattern": "fn main" })),
            "Grep(fn main)"
        );
        assert_eq!(
            safe_call_summary("WebFetch", &json!({ "url": "https://docs.rs/x" })),
            "WebFetch(https://docs.rs/x)"
        );
        assert_eq!(
            safe_call_summary("Edit", &json!({ "file_path": "src/a.rs" })),
            "Edit(src/a.rs)"
        );
    }

    /// Approving a subagent is approving work that runs tools of its own:
    /// the card says which agent and what it was asked ("Task(agent,
    /// prompt)" named the arguments), from the prompt's first line, bounded,
    /// through the secret scanner like every other value.
    #[test]
    fn a_subagent_summary_says_who_and_what() {
        assert_eq!(
            safe_call_summary(
                "Task",
                &json!({ "agent": "Explore", "prompt": "find where add() is defined\nthen report" })
            ),
            "Task(Explore: find where add() is defined)"
        );
        assert_eq!(
            safe_call_summary(
                "Agent",
                &json!({ "agent_type": "plan", "prompt": "\n  outline the fix  \n" })
            ),
            "Agent(plan: outline the fix)"
        );
        assert_eq!(
            safe_call_summary("Task", &json!({ "agent": "Explore" })),
            "Task(Explore)"
        );
        assert_eq!(
            safe_call_summary("Agent", &json!({ "prompt": "just do it" })),
            "Agent(just do it)"
        );
        let long = "x".repeat(300);
        let s = safe_call_summary("Task", &json!({ "agent": "Explore", "prompt": long }));
        assert!(s.chars().count() <= "Task(Explore: )".len() + 100, "{s}");
        assert!(s.ends_with("…)"), "{s}");
    }

    #[test]
    fn a_subagent_summary_redacts_secrets() {
        let secret = "sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let s = safe_call_summary(
            "Task",
            &json!({ "agent": "Explore", "prompt": format!("use key {secret} to call the api") }),
        );
        assert!(!s.contains(secret), "{s}");
    }
}

#[cfg(test)]
mod link_tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::{Duration, Instant};

    /// The subagent's token was a fresh one nobody could cancel: Esc on
    /// the parent stopped neither its stream nor its commands.
    #[test]
    fn a_subagent_follows_its_parents_cancel() {
        let parent = Arc::new(AtomicBool::new(false));
        let p = parent.clone();
        let child = orbit_provider_http::CancelToken::new();
        let _link = link_cancel(Some(Arc::new(move || p.load(Ordering::SeqCst))), &child);
        std::thread::sleep(Duration::from_millis(120));
        assert!(!child.is_cancelled(), "not cancelled while the parent runs");
        parent.store(true, Ordering::SeqCst);
        let t0 = Instant::now();
        while !child.is_cancelled() && t0.elapsed() < Duration::from_secs(3) {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(child.is_cancelled(), "the child follows the parent's Esc");
    }

    /// The watcher never outlives the child turn, and costs nothing when
    /// there is no parent to follow.
    #[test]
    fn dropping_the_link_stops_the_watcher_promptly() {
        let child = orbit_provider_http::CancelToken::new();
        let link = link_cancel(Some(Arc::new(|| false)), &child);
        let t0 = Instant::now();
        drop(link);
        assert!(t0.elapsed() < Duration::from_secs(1), "joined quickly");
        assert!(!child.is_cancelled());
        // No parent: no thread to join.
        drop(link_cancel(None, &child));
    }
}
