//! Verified installed content and invocation-local restrictions.

use orbit_adapter::types::{EffortSetting, EffortValue};
use orbit_engine::skills::{CatalogAgent, CatalogSkill, ContentBinding};
use orbit_tools::ToolContext;
use serde_json::Value;

/// Chosen by a trusted frontend, never by model-supplied arguments.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvocationOrigin {
    Model,
    User,
}

pub fn resolve_skill(
    cx: &ToolContext,
    name: &str,
    origin: InvocationOrigin,
) -> Result<CatalogSkill, String> {
    if crate::tools::bare_mode() {
        return Err("skills are unavailable in bare mode".into());
    }
    let catalog = orbit_engine::skills::load_catalog(&cx.home, &cx.working_dir, true)
        .map_err(|e| e.to_string())?;
    let mut skill = catalog
        .skills
        .into_iter()
        .find(|entry| entry.skill.name == name)
        .ok_or_else(|| {
            untrusted_folder_skill(cx, name)
                .unwrap_or_else(|| format!("unknown or unavailable skill: {name}"))
        })?;
    if let Some(spec) = skill.policy.as_mut() {
        spec.allowed_tools = known_tools(spec.allowed_tools.take());
        if inherits_session_model(cx, spec.model.as_deref()) {
            spec.model = None;
        }
    }
    if let Some(spec) = &skill.policy {
        if origin == InvocationOrigin::Model && spec.disable_model_invocation {
            return Err("this skill requires explicit user invocation".into());
        }
        if origin == InvocationOrigin::User && !spec.user_invocable {
            return Err("this skill is not user-invocable".into());
        }
        validate_tools(spec.allowed_tools.as_deref())?;
        validate_model(cx, spec.model.as_deref())?;
        effort(spec.effort.as_ref())?;
    }
    validate_binding(skill.binding.as_ref())?;
    Ok(skill)
}

/// A skill that sits in this folder but is left out because the folder is
/// not trusted. "Unknown skill" would send the operator looking for a typo.
fn untrusted_folder_skill(cx: &ToolContext, name: &str) -> Option<String> {
    let plain = !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'));
    if !plain
        || orbit_tools::permissions::FolderTrust::new(cx.home.clone()).is_trusted(&cx.working_dir)
    {
        return None;
    }
    [".orbit/skills", ".claude/skills"]
        .iter()
        .any(|dir| cx.working_dir.join(dir).join(name).join("SKILL.md").is_file())
        .then(|| {
            format!(
                "skill {name} is in this folder, but the folder is not trusted, so what the folder provides is left out; the operator can run `orbit folder trust` here and start again"
            )
        })
}

pub fn resolve_agent(cx: &ToolContext, name: &str) -> Result<CatalogAgent, String> {
    if crate::tools::bare_mode() {
        return Err("agents are unavailable in bare mode".into());
    }
    let catalog = orbit_engine::skills::load_catalog(&cx.home, &cx.working_dir, true)
        .map_err(|e| e.to_string())?;
    let mut agent = catalog
        .agents
        .into_iter()
        .find(|entry| entry.agent.name == name)
        .ok_or_else(|| format!("unknown or unavailable subagent: {name}"))?;
    // Written for another harness: tool names it has and ORBIT does not are
    // left out of the agent's ceiling (which only narrows it), and a model
    // named by that harness's own alias means the session's model.
    if agent.binding.is_some() {
        agent.allowed_tools = known_tools(agent.allowed_tools.take());
        if let Some(tools) = &agent.allowed_tools {
            agent.agent.tools = tools.clone();
        }
        if inherits_session_model(cx, Some(agent.agent.model.as_str())) {
            agent.agent.model.clear();
        }
    }
    validate_tools(agent.allowed_tools.as_deref())?;
    validate_model(
        cx,
        (!agent.agent.model.is_empty()).then_some(agent.agent.model.as_str()),
    )?;
    validate_binding(agent.binding.as_ref())?;
    Ok(agent)
}

/// Execute policy-bearing skills in a real child; loading never changes a parent ceiling.
pub fn invoke_skill(
    cx: &ToolContext,
    session_id: &str,
    name: &str,
    args: &Value,
    origin: InvocationOrigin,
    scope: &crate::tool_runtime::PermissionScope,
    approval: &mut dyn crate::tool_runtime::ApprovalChannel,
) -> Result<Value, String> {
    let resolved = resolve_skill(cx, name, origin)?;
    let arguments = match args.get("arguments") {
        None => Vec::new(),
        Some(Value::String(value)) => vec![value.clone()],
        Some(Value::Array(values)) => values
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .map(str::to_owned)
                    .ok_or("skill arguments must be strings".to_string())
            })
            .collect::<Result<Vec<_>, _>>()?,
        _ => return Err("skill arguments must be a string or string array".into()),
    };
    let policy = resolved.policy.as_ref();
    let needs_child = policy.is_some_and(|policy| {
        policy.allowed_tools.is_some()
            || policy.model.is_some()
            || policy.effort.is_some()
            || policy.context.is_some()
            || policy.agent.is_some()
    });
    let body = expand_prompt(&resolved.skill.body, &arguments, resolved.binding.as_ref())?;
    // A plugin's skill: its files live in the plugin's stored snapshot and
    // are read through the snapshot's address. Say what that address is,
    // beside the body (which stays the skill's own words): without it a
    // path the skill names in passing cannot be followed.
    let plugin_files = resolved.binding.as_ref().map(|binding| {
        let prefix = binding.asset_prefix();
        let folder = binding
            .source_path
            .as_deref()
            .and_then(|path| path.rsplit_once('/'))
            .map(|(folder, _)| format!("{prefix}/{folder}"))
            .unwrap_or(prefix);
        format!(
            "Base address for this skill's files: {folder}\nPaths in these instructions are relative to it: read `{folder}/<path>` with the Read tool. These files can only be read; they cannot be listed, searched or run."
        )
    });
    if !needs_child {
        // The operator's own skill folder: say where it is, so the files
        // and scripts its instructions name can be found; let this
        // session's commands read it; and let its `allowed-tools` cover
        // the turn that loaded it, as a command file's do.
        let base = resolved.dir.as_ref().map(|dir| dir.display().to_string());
        let body = match &base {
            Some(base) => format!(
                "Base directory for this skill: {base}\nPaths in these instructions are relative to it. Read its files with Read and run its scripts with Bash from there.\n\n{body}"
            ),
            None => body,
        };
        if let Some(dir) = &resolved.dir {
            cx.allow_reading(dir.clone());
        }
        let grants: Vec<orbit_tools::permissions::PermissionRule> = resolved
            .grants
            .iter()
            .filter_map(|selector| checked_rule(selector).ok())
            .collect();
        if !grants.is_empty() {
            crate::custom_commands::add_turn_grants(cx, grants);
        }
        return Ok(
            serde_json::json!({"ok":true,"body":body,"mode":"load","base_dir":base,"files":plugin_files,"source_root":resolved.binding.as_ref().map(ContentBinding::asset_prefix)}),
        );
    }
    let policy = policy.expect("child invocation has policy");
    let mut profile = if let Some(agent) = &policy.agent {
        resolve_skill_agent(cx, agent, resolved.binding.as_ref())?
    } else {
        CatalogAgent {
            agent: orbit_engine::skills::AgentDef {
                name: resolved.skill.name.clone(),
                description: resolved.skill.description.clone(),
                instructions: String::new(),
                tools: Vec::new(),
                model: String::new(),
                effort: None,
                max_turns: 25,
            },
            allowed_tools: None,
            binding: resolved.binding.clone(),
            origin: resolved.origin.clone(),
        }
    };
    if let Some(model) = &policy.model {
        profile.agent.model = model.clone();
    }
    if let Some(setting) = effort(policy.effort.as_ref())? {
        profile.agent.effort = Some(setting);
    }
    profile.agent.name = resolved.skill.name.clone();
    profile.agent.instructions =
        expand_prompt(&profile.agent.instructions, &[], profile.binding.as_ref())?;
    if !profile.agent.instructions.is_empty() {
        profile.agent.instructions.push_str("\n\n");
    }
    if let Some(files) = &plugin_files {
        profile.agent.instructions.push_str(files);
        profile.agent.instructions.push_str("\n\n");
    }
    profile.agent.instructions.push_str(&body);
    // A fresh invocation context preserves existing layers without modifying the parent.
    let invocation = crate::tool_runtime::invocation_context(cx, session_id);
    restrict_context(&invocation, policy.allowed_tools.as_deref())?;
    let config = crate::tool_runtime::session_subagent_config(cx, &cx.home);
    crate::tool_runtime::remember_turn_config(&invocation, &config);
    if let Some(effort) = cx.ext::<crate::tool_runtime::SessionEffortSetting>() {
        invocation.set_ext((*effort).clone());
    }
    let task = serde_json::json!({"agent":resolved.skill.name,"prompt":"Complete the loaded skill instructions for this invocation."});
    crate::tools::execute_task_resolved(&cx.home, session_id, &task, &invocation, scope, approval, None, Some(profile))
        .map(|result| serde_json::json!({"ok":result.get("ok").and_then(Value::as_bool).unwrap_or(true),"mode":"restricted_child","result":result}))
        .map_err(|error| error.message)
}

fn resolve_skill_agent(
    cx: &ToolContext,
    name: &str,
    binding: Option<&ContentBinding>,
) -> Result<CatalogAgent, String> {
    if name.contains(':') {
        return resolve_agent(cx, name);
    }
    let catalog = orbit_engine::skills::load_catalog(&cx.home, &cx.working_dir, true)
        .map_err(|error| error.to_string())?;
    let local = binding.map(|binding| format!("{}:{name}", binding.plugin.name));
    let candidates: Vec<_> = catalog
        .agents
        .iter()
        .filter(|entry| {
            entry.agent.name == name
                || local
                    .as_ref()
                    .is_some_and(|local| entry.agent.name == *local)
        })
        .collect();
    match candidates.as_slice() {
        [agent] => resolve_agent(cx, &agent.agent.name),
        [] => Err(format!("unknown or unavailable subagent: {name}")),
        _ => {
            Err("skill agent reference is ambiguous; use an exact namespaced agent identity".into())
        }
    }
}

fn validate_binding(binding: Option<&ContentBinding>) -> Result<(), String> {
    if binding.is_some_and(|binding| {
        binding
            .options
            .tool_map
            .iter()
            .any(|(source, target)| source != target)
    }) {
        return Err("tool mapping requires an argument/result-equivalent adapter; arbitrary tool renaming is unavailable".into());
    }
    Ok(())
}

/// A tool ceiling without the names ORBIT has no tool for. A ceiling names
/// what may be used at most, so dropping a name can only narrow it. Claude
/// Code's `Task` is ORBIT's `Agent`; its other own tools (`LS`,
/// `TodoWrite`, `BashOutput`, `KillShell`, `NotebookRead`, …) have no
/// counterpart to grant.
fn known_tools(tools: Option<Vec<String>>) -> Option<Vec<String>> {
    tools.map(|tools| {
        tools
            .into_iter()
            .filter(|selector| {
                checked_rule(selector).is_ok_and(|rule| {
                    crate::tools::is_known_tool(&rule.tool) || rule.tool.starts_with("mcp__")
                })
            })
            .collect()
    })
}

/// Whether a plugin's `model:` is another harness's alias for "one of your
/// usual models" that this configuration cannot name: `inherit`, or a
/// Claude tier (`sonnet`, `opus`, `haiku`) where no configured model has
/// that id. Such content runs on the session's model. A full model id that
/// is not configured is still an error: that was a specific request.
fn inherits_session_model(cx: &ToolContext, model: Option<&str>) -> bool {
    let Some(model) = model.filter(|model| !model.is_empty()) else {
        return false;
    };
    matches!(model, "inherit" | "sonnet" | "opus" | "haiku")
        && validate_model(cx, Some(model)).is_err()
}

fn validate_model(cx: &ToolContext, model: Option<&str>) -> Result<(), String> {
    if let Some(model) = model {
        let configured = crate::config::ProvidersConfig::load(&cx.home)?;
        crate::phase_routing::resolve_model(&configured, model, None)
            .map_err(|_| "plugin model is not an exact configured identity; provide --model-map SOURCE=PROVIDER/MODEL".to_string())?;
    }
    Ok(())
}

pub fn effort(value: Option<&Value>) -> Result<Option<EffortSetting>, String> {
    let setting = match value {
        None => return Ok(None),
        Some(Value::String(value)) if value == "default" => EffortSetting::Default,
        Some(Value::Bool(value)) => EffortSetting::Value(EffortValue::Bool(*value)),
        Some(Value::String(value)) => {
            let value = EffortValue::Level(value.clone());
            value.validate()?;
            EffortSetting::Value(value)
        }
        _ => return Err("plugin effort must be a boolean, exact level, or default".into()),
    };
    Ok(Some(setting))
}

fn validate_tools(tools: Option<&[String]>) -> Result<(), String> {
    if let Some(tools) = tools {
        for selector in tools {
            let rule = checked_rule(selector)?;
            if !crate::tools::is_known_tool(&rule.tool) && !rule.tool.starts_with("mcp__") {
                return Err("plugin tool requires an argument/result-equivalent adapter".into());
            }
        }
    }
    Ok(())
}

fn checked_rule(selector: &str) -> Result<orbit_tools::permissions::PermissionRule, String> {
    if selector.is_empty() || selector.len() > 512 || selector.chars().any(char::is_control) {
        return Err("invalid invocation tool selector".into());
    }
    if selector.contains('(') && !selector.ends_with(')') {
        return Err("invalid invocation tool selector".into());
    }
    let mut rule = orbit_tools::permissions::parse_rule(
        selector,
        orbit_tools::permissions::RuleEffectSerde::Allow,
    )
    .ok_or("invalid invocation tool selector")?;
    if rule.tool == "Task" {
        rule.tool = "Agent".into();
    }
    orbit_tools::permissions::validate_mcp_selector(&rule.tool)?;
    if rule.tool.starts_with("mcp__") && !rule.pattern.is_empty() {
        return Err("MCP invocation selectors cannot contain argument patterns".into());
    }
    Ok(rule)
}

/// Each layer is an independent ceiling. No layer adds a permission grant.
#[derive(Debug, Clone, Default)]
pub struct InvocationToolCeiling {
    layers: Vec<Vec<String>>,
}

pub fn restrict_context(cx: &ToolContext, tools: Option<&[String]>) -> Result<(), String> {
    validate_tools(tools)?;
    let mut ceiling = cx
        .ext::<InvocationToolCeiling>()
        .as_deref()
        .cloned()
        .unwrap_or_default();
    if let Some(tools) = tools {
        ceiling.layers.push(tools.to_vec());
    }
    cx.set_ext(ceiling);
    Ok(())
}

pub(crate) fn inherit_context(parent: &ToolContext, child: &ToolContext) {
    if let Some(ceiling) = parent.ext::<InvocationToolCeiling>() {
        child.set_ext((*ceiling).clone());
    }
}

pub(crate) fn permits_alias(
    cx: &ToolContext,
    tool: &str,
    args: &Value,
    alias: Option<&Value>,
    server: Option<&str>,
) -> bool {
    let Some(ceiling) = cx.ext::<InvocationToolCeiling>() else {
        return true;
    };
    let key = if tool == "Task" || tool == "Agent" {
        orbit_tools::agent_permission_key(args)
    } else if let Some(tool) = orbit_tools::registry()
        .into_iter()
        .find(|entry| entry.name() == tool)
    {
        tool.permission_key(args)
    } else {
        orbit_tools::PermissionKey {
            tool: tool.into(),
            pattern: String::new(),
        }
    };
    ceiling.layers.iter().all(|layer| {
        layer.iter().any(|selector| {
            checked_rule(selector).is_ok_and(|rule| {
                orbit_tools::permissions::rule_tool_matches(&rule, &key.tool, server)
                    && (orbit_tools::permissions::rule_matches(&rule, &key.pattern)
                        || alias
                            .and_then(|alias| alias.get("file_path"))
                            .and_then(Value::as_str)
                            .is_some_and(|path| {
                                orbit_tools::permissions::rule_matches(&rule, path)
                            }))
            })
        })
    })
}

pub(crate) fn exposed(cx: &ToolContext, tool: &str) -> bool {
    cx.ext::<InvocationToolCeiling>().is_none_or(|ceiling| {
        ceiling
            .layers
            .iter()
            .all(|layer| selected(cx, Some(layer), tool))
    })
}

pub(crate) fn selected(cx: &ToolContext, selection: Option<&[String]>, tool: &str) -> bool {
    let server = tool
        .starts_with("mcp__")
        .then(|| {
            crate::tool_runtime::resolve_mcp_target(&cx.home, &cx.working_dir, tool)
                .ok()
                .map(|(server, _)| server)
        })
        .flatten();
    selection.is_none_or(|selection| {
        selection.iter().any(|selector| {
            checked_rule(selector).is_ok_and(|rule| {
                orbit_tools::permissions::rule_tool_matches(
                    &rule,
                    if tool == "Task" { "Agent" } else { tool },
                    server.as_deref(),
                )
            })
        })
    })
}

pub(crate) fn selects_mcp_server(
    cfg: &orbit_mcp::McpConfig,
    selection: &[String],
    server: &str,
) -> bool {
    selection.iter().any(|selector| {
        checked_rule(selector).is_ok_and(|rule| {
            rule.pattern.is_empty()
                && (orbit_tools::permissions::rule_tool_matches(&rule, "", Some(server))
                    || crate::tool_runtime::resolve_mcp_target_in(cfg, &rule.tool)
                        .is_ok_and(|(selected, _)| selected == server))
        })
    })
}

pub(crate) fn server_exposed(cx: &ToolContext, cfg: &orbit_mcp::McpConfig, server: &str) -> bool {
    cx.ext::<InvocationToolCeiling>().is_none_or(|ceiling| {
        ceiling
            .layers
            .iter()
            .all(|layer| selects_mcp_server(cfg, layer, server))
    })
}

/// Whether the text holds the command-file form `` !`command` ``: a bang
/// that starts a word, a backtick, and a closing backtick on the same line
/// with something between them. A code span that merely ends in `!`, or a
/// sentence with a stray `` !` ``, is ordinary text.
fn has_dynamic_shell(template: &str) -> bool {
    template.lines().any(|line| {
        let mut from = 0;
        while let Some(at) = line[from..].find("!`") {
            let start = from + at;
            let opens_word = line[..start].chars().next_back().is_none_or(|before| {
                before.is_whitespace() || matches!(before, '(' | '[' | ':' | '>')
            });
            let body = &line[start + 2..];
            if opens_word
                && body
                    .find('`')
                    .is_some_and(|end| !body[..end].trim().is_empty())
            {
                return true;
            }
            from = start + 2;
        }
        false
    })
}

/// One pass: argument text is never reparsed as template or shell source.
pub fn expand_prompt(
    template: &str,
    arguments: &[String],
    binding: Option<&ContentBinding>,
) -> Result<String, String> {
    if has_dynamic_shell(template) {
        return Err(
            "this content runs a shell command (!`command`), which only a command file may do"
                .into(),
        );
    }
    let all = arguments.join(" ");
    let mut output = String::new();
    let mut remaining = template;
    while let Some(offset) = remaining.find('$') {
        output.push_str(&remaining[..offset]);
        remaining = &remaining[offset..];
        let mut replaced = false;
        for (marker, value) in [("$ARGUMENTS", all.as_str())] {
            if let Some(tail) = remaining.strip_prefix(marker) {
                output.push_str(value);
                remaining = tail;
                replaced = true;
                break;
            }
        }
        if replaced {
            continue;
        }
        let digits = remaining[1..]
            .bytes()
            .take_while(u8::is_ascii_digit)
            .count();
        if digits > 0 {
            let index = remaining[1..1 + digits]
                .parse::<usize>()
                .map_err(|_| "invalid positional argument")?;
            if index == 0 {
                return Err("positional arguments start at $1".into());
            }
            output.push_str(arguments.get(index - 1).map(String::as_str).unwrap_or(""));
            remaining = &remaining[1 + digits..];
            continue;
        }
        if let Some(binding) = binding {
            for marker in [
                "${CLAUDE_PLUGIN_ROOT}",
                "$CLAUDE_PLUGIN_ROOT",
                "${CODEX_PLUGIN_ROOT}",
                "$CODEX_PLUGIN_ROOT",
                "${HERMES_PLUGIN_ROOT}",
                "$HERMES_PLUGIN_ROOT",
            ] {
                if let Some(tail) = remaining.strip_prefix(marker) {
                    output.push_str(&binding.asset_prefix());
                    remaining = tail;
                    replaced = true;
                    break;
                }
            }
        }
        if !replaced {
            output.push('$');
            remaining = &remaining[1..];
        }
        if output.len() > 64 * 1024 {
            return Err("expanded plugin prompt exceeds 64 KiB".into());
        }
    }
    output.push_str(remaining);
    if output.len() > 64 * 1024 {
        return Err("expanded plugin prompt exceeds 64 KiB".into());
    }
    Ok(output)
}

pub(crate) fn read_asset(cx: &ToolContext, path: &str) -> Result<Option<Vec<u8>>, String> {
    if !path.starts_with("orbit-plugin://") {
        return Ok(None);
    }
    if crate::tools::bare_mode() {
        return Err("plugin assets are unavailable in bare mode".into());
    }
    let catalog = orbit_engine::skills::load_catalog(&cx.home, &cx.working_dir, true)
        .map_err(|e| e.to_string())?;
    let bindings = catalog
        .skills
        .iter()
        .filter_map(|entry| entry.binding.as_ref())
        .chain(
            catalog
                .agents
                .iter()
                .filter_map(|entry| entry.binding.as_ref()),
        );
    for binding in bindings {
        if let Some(relative) = path.strip_prefix(&(binding.asset_prefix() + "/")) {
            let trusted = orbit_tools::permissions::FolderTrust::new(cx.home.clone())
                .is_trusted(&cx.working_dir);
            let bytes = orbit_plugin_compat::PluginStore::open(&cx.home, &cx.working_dir, trusted)
                .and_then(|store| {
                    store.read_asset(&binding.plugin, &binding.digest, relative, 64 * 1024)
                })
                .map_err(|error| error.to_string())?;
            return Ok(Some(bytes));
        }
    }
    Err("plugin asset binding is stale, disabled, or unavailable".into())
}

pub(crate) fn asset_policy_path(
    cx: &ToolContext,
    path: &str,
) -> Result<Option<std::path::PathBuf>, String> {
    if !path.starts_with("orbit-plugin://") {
        return Ok(None);
    }
    if crate::tools::bare_mode() {
        return Err("plugin assets are unavailable in bare mode".into());
    }
    let catalog = orbit_engine::skills::load_catalog(&cx.home, &cx.working_dir, true)
        .map_err(|error| error.to_string())?;
    for binding in catalog
        .skills
        .iter()
        .filter_map(|entry| entry.binding.as_ref())
        .chain(
            catalog
                .agents
                .iter()
                .filter_map(|entry| entry.binding.as_ref()),
        )
    {
        if let Some(relative) = path.strip_prefix(&(binding.asset_prefix() + "/")) {
            if relative.is_empty()
                || relative.split('/').any(|part| {
                    part.is_empty() || part == "." || part == ".." || part.contains('\\')
                })
            {
                return Err("invalid plugin asset path".into());
            }
            let path = binding.root.join(relative);
            if orbit_tools::is_deny_read(&path) {
                return Err("plugin asset is on the deny-read list".into());
            }
            return Ok(Some(path));
        }
    }
    Err("plugin asset binding is stale, disabled, or unavailable".into())
}

pub(crate) fn asset_result(cx: &ToolContext, args: &Value) -> orbit_tools::ToolResult {
    let read = || -> Result<Value, String> {
        let path = args
            .get("file_path")
            .and_then(Value::as_str)
            .ok_or("Read requires file_path")?;
        asset_policy_path(cx, path)?;
        let bytes = read_asset(cx, path)?.ok_or("missing plugin asset binding")?;
        let text = String::from_utf8(bytes).map_err(|_| "plugin asset is not UTF-8 text")?;
        let offset = args
            .get("offset")
            .map(|value| {
                value
                    .as_u64()
                    .filter(|value| *value > 0)
                    .ok_or("offset must be a positive integer")
            })
            .transpose()?
            .unwrap_or(1);
        let limit = args
            .get("limit")
            .map(|value| {
                value
                    .as_u64()
                    .filter(|value| *value <= 2000)
                    .ok_or("limit must be at most 2000")
            })
            .transpose()?
            .unwrap_or(2000);
        let content = text
            .lines()
            .enumerate()
            .skip(
                usize::try_from(offset.saturating_sub(1))
                    .map_err(|_| "offset exceeds platform limits")?,
            )
            .take(limit as usize)
            .map(|(index, line)| format!("{}\t{line}", index + 1))
            .collect::<Vec<_>>()
            .join("\n");
        let scanned = orbit_tools::scan::scan_result(&content);
        Ok(
            serde_json::json!({"ok":true,"file_path":path,"content":scanned.text,"redactions":scanned.redactions}),
        )
    };
    match read() {
        Ok(result) => orbit_tools::ToolResult::ok(result),
        Err(error) => orbit_tools::ToolResult::err(&error),
    }
}

#[cfg(test)]
mod dynamic_shell_tests {
    use super::{expand_prompt, has_dynamic_shell};

    #[test]
    fn only_a_command_in_backticks_after_a_bang_is_shell_context() {
        for plain in [
            "reply like `!!!HELLO!!!`. Nothing else.",
            "say `wow!` and then `ok`",
            "a stray !` with no end",
            "empty !`` is nothing",
            "no bang `ls` here",
        ] {
            assert!(!has_dynamic_shell(plain), "{plain}");
            assert!(expand_prompt(plain, &[], None).is_ok(), "{plain}");
        }
        for shell in [
            "Status: !`git status --short`",
            "!`ls`",
            "first line\n(see !`date`)",
        ] {
            assert!(has_dynamic_shell(shell), "{shell}");
            assert!(expand_prompt(shell, &[], None).is_err(), "{shell}");
        }
    }
}

#[cfg(test)]
mod skill_trust_tests {
    use super::*;

    /// A skill in a folder that is not trusted is left out. Asking for it
    /// by name says so, and says what to run, instead of "unknown skill".
    #[test]
    fn a_skill_in_an_untrusted_folder_says_the_folder_is_not_trusted() {
        let root = std::env::temp_dir().join(format!("orbit-skill-trust-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let (home, work) = (root.join("home"), root.join("work"));
        std::fs::create_dir_all(&home).unwrap();
        std::fs::create_dir_all(work.join(".orbit/skills/shout")).unwrap();
        std::fs::write(
            work.join(".orbit/skills/shout/SKILL.md"),
            "---\nname: shout\ndescription: shout\n---\nShout.\n",
        )
        .unwrap();
        let cx = ToolContext::new(home.clone(), "skill-trust".into(), work.clone());
        let error = resolve_skill(&cx, "shout", InvocationOrigin::User).unwrap_err();
        assert!(
            error.contains("not trusted") && error.contains("orbit folder trust"),
            "{error}"
        );
        // A name that is nowhere is still simply unknown.
        let error = resolve_skill(&cx, "nowhere", InvocationOrigin::User).unwrap_err();
        assert_eq!(error, "unknown or unavailable skill: nowhere");
        // Once the folder is trusted the skill loads.
        orbit_tools::permissions::FolderTrust::new(home)
            .trust(&work)
            .unwrap();
        assert_eq!(
            resolve_skill(&cx, "shout", InvocationOrigin::User)
                .unwrap()
                .skill
                .name,
            "shout"
        );
        let _ = std::fs::remove_dir_all(&root);
    }
}
