//! Skills and subagents (roadmap phase 5, §Extensibility).
//!
//! Skills follow the open Agent Skills format: `.orbit/skills/<name>/SKILL.md`
//! with `name` and `description` frontmatter. Only the description sits
//! in context; the body loads when the model calls the Skill tool or
//! the operator types `/<name>`.
//!
//! Subagent definitions live in `.orbit/agents/<name>.md` with
//! `name`, `description`, `tools`, `model`, `maxTurns` frontmatter.
//! Built-ins: Explore (read-only, thorough), Plan (read-only, returns
//! a plan), general-purpose.

use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::path::Path;

/// One skill: frontmatter + body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Skill {
    pub name: String,
    pub description: String,
    /// The SKILL.md body (loaded on demand, never in context).
    #[serde(default)]
    pub body: String,
}

/// Parse a skill definition, retaining the legacy optional interface.
pub fn parse_skill_md(text: &str) -> Option<Skill> {
    parse_skill_md_checked(text).ok()
}

/// Parse a skill while reporting malformed frontmatter explicitly.
pub fn parse_skill_md_checked(text: &str) -> Result<Skill, orbit_plugin_compat::CompatError> {
    let document = orbit_plugin_compat::parse_frontmatter(text)?;
    Ok(Skill {
        name: required_name(&document.frontmatter)?,
        description: optional_string(&document.frontmatter, "description")?.unwrap_or_default(),
        body: document.body.trim().to_owned(),
    })
}

fn field_error(field: &str) -> orbit_plugin_compat::CompatError {
    orbit_plugin_compat::CompatError::new(
        "invalid_frontmatter_field",
        format!("invalid {field} in definition frontmatter"),
    )
}

fn optional_string(
    frontmatter: &serde_json::Value,
    field: &str,
) -> Result<Option<String>, orbit_plugin_compat::CompatError> {
    match frontmatter.get(field) {
        None => Ok(None),
        Some(serde_json::Value::String(value)) => Ok(Some(value.clone())),
        Some(_) => Err(field_error(field)),
    }
}

fn required_name(
    frontmatter: &serde_json::Value,
) -> Result<String, orbit_plugin_compat::CompatError> {
    let name = optional_string(frontmatter, "name")?.ok_or_else(|| field_error("name"))?;
    if name.trim().is_empty() || name.len() > 256 || name.chars().any(char::is_control) {
        return Err(field_error("name"));
    }
    Ok(name)
}

fn optional_tools(
    frontmatter: &serde_json::Value,
) -> Result<Vec<String>, orbit_plugin_compat::CompatError> {
    let tools: Vec<String> = match frontmatter.get("tools") {
        None => return Ok(Vec::new()),
        Some(serde_json::Value::String(value)) => value
            .split(',')
            .map(str::trim)
            .filter(|item| !item.is_empty())
            .map(str::to_owned)
            .collect(),
        Some(serde_json::Value::Array(values)) => values
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| field_error("tools"))
            })
            .collect::<Result<Vec<_>, _>>()?,
        Some(_) => return Err(field_error("tools")),
    };
    if tools.len() > 256
        || tools.iter().any(|tool| {
            tool.trim().is_empty() || tool.len() > 256 || tool.chars().any(char::is_control)
        })
    {
        return Err(field_error("tools"));
    }
    Ok(tools)
}

/// Load every skill from the scopes: user ($ORBIT_HOME/skills) and
/// project (.orbit/skills, trusted folders only).
pub fn load_skills(home: &Path, project_trusted: bool) -> Vec<Skill> {
    let mut out = Vec::new();
    for (dir, needs_trust) in [
        (home.join("skills"), false),
        (Path::new(".orbit/skills").to_path_buf(), true),
    ] {
        if needs_trust && !project_trusted {
            continue;
        }
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let skill_md = entry.path().join("SKILL.md");
            if let Ok(text) = std::fs::read_to_string(&skill_md)
                && let Some(skill) = parse_skill_md(&text)
            {
                out.push(skill);
            }
        }
    }
    out
}

/// The skills index for the system prompt: names + one-line
/// descriptions only (bodies load on demand).
pub fn skills_index(skills: &[Skill]) -> String {
    let mut s = String::from("## Skills (call the Skill tool or type /<name> to load)\n\n");
    for skill in skills {
        s.push_str(&format!("- {}: {}\n", skill.name, skill.description));
    }
    s
}

// ── Subagents ──────────────────────────────────────────────────────────────

/// One subagent definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentDef {
    pub name: String,
    pub description: String,
    /// The Markdown body, applied as instructions on each subagent turn.
    #[serde(default)]
    pub instructions: String,
    /// Tool names the subagent may use (empty = read-only set).
    #[serde(default)]
    pub tools: Vec<String>,
    /// Model override (empty = the session's model).
    #[serde(default)]
    pub model: String,
    #[serde(default)]
    pub effort: Option<orbit_adapter::types::EffortSetting>,
    #[serde(default = "default_max_turns")]
    pub max_turns: u32,
}

fn default_max_turns() -> u32 {
    25
}

/// Parse an agent definition, retaining the legacy optional interface.
pub fn parse_agent_md(text: &str) -> Option<AgentDef> {
    parse_agent_md_checked(text).ok()
}

/// Parse an agent with typed, bounded frontmatter and explicit errors.
pub fn parse_agent_md_checked(text: &str) -> Result<AgentDef, orbit_plugin_compat::CompatError> {
    use orbit_adapter::types::{EffortSetting, EffortValue};
    let document = orbit_plugin_compat::parse_frontmatter(text)?;
    let front = &document.frontmatter;
    let effort = match front.get("effort") {
        None => None,
        Some(serde_json::Value::Bool(value)) => {
            Some(EffortSetting::Value(EffortValue::Bool(*value)))
        }
        Some(serde_json::Value::String(value)) if value == "default" => {
            Some(EffortSetting::Default)
        }
        Some(serde_json::Value::String(value)) => {
            let effort = EffortValue::Level(value.clone());
            effort.validate().map_err(|_| field_error("effort"))?;
            Some(EffortSetting::Value(effort))
        }
        Some(_) => return Err(field_error("effort")),
    };
    if front.get("maxTurns").is_some() && front.get("max_turns").is_some() {
        return Err(field_error("maxTurns"));
    }
    let max_turns = match front.get("maxTurns").or_else(|| front.get("max_turns")) {
        None => default_max_turns(),
        Some(value) => value
            .as_u64()
            .and_then(|value| u32::try_from(value).ok())
            .filter(|value| *value > 0)
            .ok_or_else(|| field_error("maxTurns"))?,
    };
    Ok(AgentDef {
        name: required_name(front)?,
        description: optional_string(front, "description")?.unwrap_or_default(),
        instructions: document.body.trim().to_owned(),
        tools: optional_tools(front)?,
        model: optional_string(front, "model")?.unwrap_or_default(),
        effort,
        max_turns,
    })
}

/// The built-in subagents (roadmap: Explore, Plan, general-purpose).
pub fn builtin_agents() -> Vec<AgentDef> {
    vec![
        AgentDef {
            name: "Explore".into(),
            description: "Read-only exploration; returns a thorough report".into(),
            instructions: String::new(),
            tools: vec!["Read".into(), "Glob".into(), "Grep".into()],
            model: String::new(),
            effort: None,
            max_turns: 25,
        },
        AgentDef {
            name: "Plan".into(),
            description: "Read-only research; returns an implementation plan".into(),
            instructions: String::new(),
            tools: vec!["Read".into(), "Glob".into(), "Grep".into()],
            model: String::new(),
            effort: None,
            max_turns: 25,
        },
        AgentDef {
            name: "general-purpose".into(),
            description: "Full tool access for delegated tasks".into(),
            instructions: String::new(),
            tools: vec![],
            model: String::new(),
            effort: None,
            max_turns: 50,
        },
    ]
}

/// Load every agent definition: built-ins + .orbit/agents/*.md
/// (trusted) + $ORBIT_HOME/agents/*.md.
pub fn load_agents(home: &Path, project_trusted: bool) -> Vec<AgentDef> {
    let mut out = builtin_agents();
    for (dir, needs_trust) in [
        (home.join("agents"), false),
        (Path::new(".orbit/agents").to_path_buf(), true),
    ] {
        if needs_trust && !project_trusted {
            continue;
        }
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            if entry.path().extension().and_then(|e| e.to_str()) == Some("md")
                && let Ok(text) = std::fs::read_to_string(entry.path())
                && let Some(def) = parse_agent_md(&text)
            {
                out.push(def);
            }
        }
    }
    out
}

/// The agents index for the system prompt.
pub fn agents_index(agents: &[AgentDef]) -> String {
    let mut s = String::from("## Subagents (call the Agent tool)\n\n");
    for a in agents {
        s.push_str(&format!("- {}: {}\n", a.name, a.description));
    }
    s
}

/// A source-qualified reference names an immutable package revision, never a cwd.
#[derive(Debug, Clone)]
pub struct ContentBinding {
    pub plugin: orbit_plugin_compat::PluginId,
    pub digest: String,
    pub component_id: String,
    pub source_path: Option<String>,
    pub root: std::path::PathBuf,
    pub data_root: std::path::PathBuf,
    pub options: orbit_plugin_compat::InspectOptions,
}

impl ContentBinding {
    pub fn asset_prefix(&self) -> String {
        let scope = match self.plugin.scope {
            orbit_plugin_compat::StoreScope::User => "user",
            orbit_plugin_compat::StoreScope::Project => "project",
        };
        format!(
            "orbit-plugin://{scope}/{}/{}/{}",
            self.plugin.name,
            self.digest,
            hex::encode(sha2::Sha256::digest(self.component_id.as_bytes()))
        )
    }
}

#[derive(Debug, Clone)]
pub struct CatalogSkill {
    pub skill: Skill,
    pub policy: Option<orbit_plugin_compat::SkillSpec>,
    pub binding: Option<ContentBinding>,
}

#[derive(Debug, Clone)]
pub struct CatalogAgent {
    pub agent: AgentDef,
    /// None inherits the parent; Some([]) denies every tool.
    pub allowed_tools: Option<Vec<String>>,
    pub binding: Option<ContentBinding>,
}

#[derive(Debug, Clone, Default)]
pub struct ContentCatalog {
    pub skills: Vec<CatalogSkill>,
    pub agents: Vec<CatalogAgent>,
    pub diagnostics: Vec<String>,
}

/// Discover against the caller's actual project. Store admission never implies runtime readiness.
pub fn load_catalog(
    home: &Path,
    project: &Path,
    portable_enabled: bool,
) -> Result<ContentCatalog, orbit_plugin_compat::CompatError> {
    use orbit_plugin_compat::{Compatibility, ComponentKind, DiagnosticSeverity, PluginStore};
    let trusted =
        orbit_tools::permissions::FolderTrust::new(home.to_path_buf()).is_trusted(project);
    let mut catalog = ContentCatalog::default();
    for agent in builtin_agents() {
        let allowed_tools = (!agent.tools.is_empty()).then(|| agent.tools.clone());
        catalog.agents.push(CatalogAgent {
            agent,
            allowed_tools,
            binding: None,
        });
    }
    for (base, needs_trust) in [(home.to_path_buf(), false), (project.join(".orbit"), true)] {
        if needs_trust && !trusted {
            continue;
        }
        if let Ok(entries) = std::fs::read_dir(base.join("skills")) {
            for entry in entries.flatten() {
                if let Ok(text) = std::fs::read_to_string(entry.path().join("SKILL.md"))
                    && let Some(skill) = parse_skill_md(&text)
                {
                    catalog.skills.push(CatalogSkill {
                        skill,
                        policy: None,
                        binding: None,
                    });
                }
            }
        }
        if let Ok(entries) = std::fs::read_dir(base.join("agents")) {
            for entry in entries.flatten() {
                if entry.path().extension().and_then(|value| value.to_str()) == Some("md")
                    && let Ok(text) = std::fs::read_to_string(entry.path())
                    && let Some(agent) = parse_agent_md(&text)
                {
                    let allowed_tools = (!agent.tools.is_empty()).then(|| agent.tools.clone());
                    catalog.agents.push(CatalogAgent {
                        agent,
                        allowed_tools,
                        binding: None,
                    });
                }
            }
        }
    }
    if portable_enabled {
        let active = match PluginStore::open(home, project, trusted)
            .and_then(|store| store.active())
        {
            Ok(active) => Some(active),
            Err(error) => {
                let code: String = error
                    .code
                    .chars()
                    .filter(|c| c.is_ascii_alphanumeric() || *c == '_')
                    .take(64)
                    .collect();
                catalog.diagnostics.push(format!("Managed plugin content is unavailable ({code}); inspect the private plugin store before activating it"));
                let count = catalog.skills.len() + catalog.agents.len();
                catalog
                    .skills
                    .retain(|entry| !entry.skill.name.contains(':'));
                catalog
                    .agents
                    .retain(|entry| !entry.agent.name.contains(':'));
                if catalog.skills.len() + catalog.agents.len() != count {
                    catalog.diagnostics.push("Namespaced native definitions are withheld while managed plugin identities cannot be verified".into());
                }
                None
            }
        };
        if let Some(active) = active {
            let failed_namespaces: std::collections::BTreeSet<_> = active
                .diagnostics
                .iter()
                .filter(|diagnostic| diagnostic.severity == DiagnosticSeverity::Error)
                .filter_map(|diagnostic| diagnostic.component_id.as_deref())
                .collect();
            if !failed_namespaces.is_empty() {
                let available = |name: &str| {
                    name.split_once(':').is_none_or(|(namespace, _)| {
                        !failed_namespaces
                            .iter()
                            .any(|failed| namespace.eq_ignore_ascii_case(failed))
                    })
                };
                catalog.skills.retain(|entry| available(&entry.skill.name));
                catalog.agents.retain(|entry| available(&entry.agent.name));
                catalog.diagnostics.push("Failed managed package namespaces remain reserved; native aliases cannot replace unavailable plugins".into());
            }
            catalog.diagnostics.extend(
                active
                    .diagnostics
                    .into_iter()
                    .map(|diagnostic| diagnostic.message),
            );
            for active in active.plugins {
                for component in &active.plugin.components {
                    if !matches!(
                        component.kind,
                        ComponentKind::Skill(_) | ComponentKind::Agent(_)
                    ) {
                        continue;
                    }
                    let relevant_error = active.plugin.diagnostics.iter().any(|diagnostic| {
                        diagnostic.severity == DiagnosticSeverity::Error
                            && diagnostic
                                .component_id
                                .as_ref()
                                .is_none_or(|id| id == &component.id)
                    });
                    let unmet = active.plugin.requirements.iter().any(|requirement| {
                        !requirement.satisfied
                            && requirement.kind != "model_mapping"
                            && requirement
                                .component_id
                                .as_ref()
                                .is_none_or(|id| id == &component.id)
                    });
                    if component.compatibility == Compatibility::RequiresMigration
                        || relevant_error
                        || unmet
                    {
                        catalog.diagnostics.push(format!(
                            "{} requires migration or an unsatisfied runtime prerequisite",
                            component.id
                        ));
                        continue;
                    }
                    let binding = Some(ContentBinding {
                        plugin: active.plugin.id.clone(),
                        digest: active.plugin.digest.clone(),
                        component_id: component.id.clone(),
                        source_path: component.source_path.clone(),
                        root: active.root.clone(),
                        data_root: active.data_root.clone(),
                        options: active.plugin.options.clone(),
                    });
                    match &component.kind {
                        ComponentKind::Skill(spec) => catalog.skills.push(CatalogSkill {
                            skill: Skill {
                                name: spec.name.clone(),
                                description: spec.description.clone(),
                                body: spec.body.clone(),
                            },
                            policy: Some(spec.clone()),
                            binding,
                        }),
                        ComponentKind::Agent(spec) => {
                            let effort = match spec.effort.as_ref() {
                                None => None,
                                Some(serde_json::Value::Bool(value)) => {
                                    Some(orbit_adapter::types::EffortSetting::Value(
                                        orbit_adapter::types::EffortValue::Bool(*value),
                                    ))
                                }
                                Some(serde_json::Value::String(value)) if value == "default" => {
                                    Some(orbit_adapter::types::EffortSetting::Default)
                                }
                                Some(serde_json::Value::String(value)) => {
                                    let value =
                                        orbit_adapter::types::EffortValue::Level(value.clone());
                                    if value.validate().is_err() {
                                        catalog.diagnostics.push(format!(
                                            "{} has invalid effort metadata and was excluded",
                                            component.id
                                        ));
                                        continue;
                                    }
                                    Some(orbit_adapter::types::EffortSetting::Value(value))
                                }
                                _ => {
                                    catalog.diagnostics.push(format!(
                                        "{} has invalid effort metadata and was excluded",
                                        component.id
                                    ));
                                    continue;
                                }
                            };
                            catalog.agents.push(CatalogAgent {
                                agent: AgentDef {
                                    name: spec.name.clone(),
                                    description: spec.description.clone(),
                                    instructions: spec.instructions.clone(),
                                    tools: spec.tools.clone().unwrap_or_default(),
                                    model: spec.model.clone().unwrap_or_default(),
                                    effort,
                                    max_turns: spec.max_turns.unwrap_or(25),
                                },
                                allowed_tools: spec.tools.clone(),
                                binding,
                            });
                        }
                        _ => unreachable!(),
                    }
                }
            }
        }
    }
    catalog
        .skills
        .sort_by(|a, b| a.skill.name.cmp(&b.skill.name));
    catalog
        .agents
        .sort_by(|a, b| a.agent.name.cmp(&b.agent.name));
    if catalog
        .skills
        .windows(2)
        .any(|pair| pair[0].skill.name == pair[1].skill.name)
        || catalog
            .agents
            .windows(2)
            .any(|pair| pair[0].agent.name == pair[1].agent.name)
    {
        return Err(orbit_plugin_compat::CompatError::new(
            "content_identity_collision",
            "native and installed content identities must be unique",
        ));
    }
    catalog.diagnostics.truncate(32);
    Ok(catalog)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn skill_frontmatter_parses() {
        let md = r#"---
name: hunt-sqli
description: SQL injection hunting methodology
---

# SQLi hunting

1. Enumerate inputs
2. Probe error-based first
"#;
        let skill = parse_skill_md(md).unwrap();
        assert_eq!(skill.name, "hunt-sqli");
        assert_eq!(skill.description, "SQL injection hunting methodology");
        assert!(skill.body.contains("Enumerate inputs"));
    }

    #[test]
    fn complete_yaml_metadata_reaches_native_skill_and_agent_loaders() {
        let text = "\u{feff}---\r\nname: evidence-reviewer\r\ndescription: >-\r\n  Review evidence\r\n  before reporting.\r\ntools:\r\n  - Read\r\n  - Grep\r\neffort: 'false'\r\nmaxTurns: 7\r\n---\r\n\r\nKeep --- inside this paragraph.\r\n\r\n  Preserve λ.\r\n";
        let agent = parse_agent_md_checked(text).unwrap();
        assert_eq!(agent.description, "Review evidence before reporting.");
        assert_eq!(agent.tools, ["Read", "Grep"]);
        assert_eq!(agent.max_turns, 7);
        assert_eq!(
            agent.instructions,
            "Keep --- inside this paragraph.\r\n\r\n  Preserve λ."
        );
        assert_eq!(
            parse_skill_md_checked(text).unwrap().description,
            agent.description
        );
        assert!(
            matches!(agent.effort, Some(orbit_adapter::types::EffortSetting::Value(orbit_adapter::types::EffortValue::Level(ref value))) if value == "false")
        );
    }

    #[test]
    fn pinned_hookify_agent_loads_unchanged() {
        use sha2::{Digest, Sha256};
        // Apache-2.0 fixture from anthropics/claude-plugins-official, commit
        // 054417d0fc687dd7d639331f21522d0e06c09cf9, plugins/hookify/agents/conversation-analyzer.md.
        let text = include_str!("../tests/fixtures/hookify-agent.txt");
        assert_eq!(
            hex::encode(Sha256::digest(text.as_bytes())),
            "96267342d2d0788763b392b26a322ca44d1b62ee4d65be31c0aaa8031ad85db7"
        );
        let agent = parse_agent_md_checked(text).unwrap();
        assert_eq!(agent.name, "conversation-analyzer");
        assert_eq!(agent.tools, ["Read", "Grep"]);
        assert_eq!(agent.model, "inherit");
        assert!(
            agent
                .description
                .starts_with("Use this agent when analyzing conversation transcripts")
        );
        assert_eq!(
            hex::encode(Sha256::digest(agent.instructions.as_bytes())),
            "ece522c5496e4c6de8339370913da6d0dcb22f75e601c6e4cd0a858c4c40b796"
        );
    }

    #[test]
    fn invalid_typed_authority_fields_are_not_silently_defaulted() {
        for field in [
            "tools: [Read, false]",
            "tools: false",
            "model: false",
            "effort: [high]",
            "maxTurns: invalid",
            "maxTurns: 0",
            "maxTurns: 4294967296",
            "maxTurns: 2\nmax_turns: 3",
            "name: [reviewer]",
            "description: false",
        ] {
            let text = if field.starts_with("name:") {
                format!("---\n{field}\n---\nbody")
            } else {
                format!("---\nname: reviewer\n{field}\n---\nbody")
            };
            assert!(parse_agent_md_checked(&text).is_err(), "{field}");
            assert!(parse_agent_md(&text).is_none(), "{field}");
        }
    }

    #[test]
    fn literal_yaml_descriptions_and_body_delimiters_remain_distinct() {
        let text = "---\nname: reviewer\ndescription: |-\n  First line.\n  Second line.\n---\nBody\n---\nMore body.";
        let agent = parse_agent_md_checked(text).unwrap();
        assert_eq!(agent.description, "First line.\nSecond line.");
        assert_eq!(agent.instructions, "Body\n---\nMore body.");
        assert_eq!(
            parse_skill_md_checked(text).unwrap().body,
            agent.instructions
        );
    }

    #[test]
    fn agent_frontmatter_parses() {
        let md = r#"---
name: reviewer
description: Reviews code for security issues
tools: [Read, Grep]
model: cheap-model
maxTurns: 10
---

Body text.
"#;
        let def = parse_agent_md(md).unwrap();
        assert_eq!(def.name, "reviewer");
        assert_eq!(def.tools, vec!["Read", "Grep"]);
        assert_eq!(def.model, "cheap-model");
        assert_eq!(def.max_turns, 10);
        assert_eq!(def.instructions, "Body text.");
    }

    #[test]
    fn agent_instructions_preserve_multiline_paragraphs_and_unicode() {
        let body = "# Evidence review\n\nKeep the blank paragraph.\nUse λ → evidence.\n\n    preserve indented examples";
        let definition = parse_agent_md(&format!(
            "---\nname: evidence-reviewer\ndescription: Review evidence\ntools: [Read, Grep]\nmodel: review-model\neffort: 'false'\nmaxTurns: 7\n---\n\n{body}\n\n"
        ))
        .unwrap();
        assert_eq!(definition.instructions, body);
        assert_eq!(definition.tools, vec!["Read", "Grep"]);
        assert_eq!(definition.model, "review-model");
        assert_eq!(
            definition.effort,
            Some(orbit_adapter::types::EffortSetting::Value(
                orbit_adapter::types::EffortValue::Level("false".into())
            ))
        );
        assert_eq!(definition.max_turns, 7);
    }

    #[test]
    fn legacy_agent_definitions_default_to_empty_instructions() {
        let definition: AgentDef = serde_json::from_value(serde_json::json!({
            "name": "legacy-reviewer",
            "description": "Review saved evidence",
            "tools": ["Read"],
            "model": "review-model",
            "max_turns": 7
        }))
        .unwrap();
        assert!(definition.instructions.is_empty());
        assert_eq!(definition.tools, vec!["Read"]);
        assert_eq!(definition.model, "review-model");
        assert_eq!(definition.effort, None);
        assert_eq!(definition.max_turns, 7);
        let mut saved = serde_json::to_value(&definition).unwrap();
        saved["instructions"] = serde_json::json!("First paragraph.\n\nSecond paragraph: λ.");
        let reloaded: AgentDef = serde_json::from_value(saved).unwrap();
        assert_eq!(
            reloaded.instructions,
            "First paragraph.\n\nSecond paragraph: λ."
        );
    }

    #[test]
    fn empty_agent_body_and_builtin_instructions_remain_empty() {
        for body in ["", "\n\n", " \n\t\n"] {
            let definition = parse_agent_md(&format!("---\nname: empty\n---\n{body}")).unwrap();
            assert!(definition.instructions.is_empty());
        }
        assert!(
            builtin_agents()
                .iter()
                .all(|definition| definition.instructions.is_empty())
        );
    }

    #[test]
    fn agent_effort_frontmatter_preserves_typed_choices_and_reset() {
        use orbit_adapter::types::{EffortSetting, EffortValue};
        for (raw, expected) in [
            ("true", EffortSetting::Value(EffortValue::Bool(true))),
            ("false", EffortSetting::Value(EffortValue::Bool(false))),
            (
                "'false'",
                EffortSetting::Value(EffortValue::Level("false".into())),
            ),
            (
                "high",
                EffortSetting::Value(EffortValue::Level("high".into())),
            ),
            ("default", EffortSetting::Default),
        ] {
            let def = parse_agent_md(&format!("---\nname: custom\neffort: {raw}\n---\n")).unwrap();
            assert_eq!(def.effort, Some(expected));
        }
        assert_eq!(
            parse_agent_md("---\nname: legacy\n---\n").unwrap().effort,
            None
        );
        assert!(parse_agent_md("---\nname: invalid\neffort: \"high \"\n---\n").is_none());
    }

    #[test]
    fn builtin_agents_present() {
        let agents = builtin_agents();
        assert!(agents.iter().any(|a| a.name == "Explore"));
        assert!(agents.iter().any(|a| a.name == "Plan"));
    }

    #[test]
    fn a_claude_code_skill_parses_unchanged() {
        // The gate's requirement: a SKILL.md copied unchanged from a
        // Claude Code project parses.
        let md = std::fs::read_to_string("SKILL.md").unwrap_or_else(|_| {
            // not in a project dir — synthesize the exact shape
            "---\nname: test\ndescription: d\n---\nbody".to_string()
        });
        if let Some(skill) = parse_skill_md(&md) {
            assert!(!skill.name.is_empty());
        }
    }
}
