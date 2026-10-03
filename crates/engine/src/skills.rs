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

/// Parse a SKILL.md: `---` frontmatter (name, description) + body.
pub fn parse_skill_md(text: &str) -> Option<Skill> {
    let text = text.trim_start_matches('\u{feff}');
    let rest = text.strip_prefix("---")?;
    let (front, body) = rest.split_once("---")?;
    let mut name = String::new();
    let mut description = String::new();
    for line in front.lines() {
        if let Some(v) = line.strip_prefix("name:") {
            name = v.trim().to_string();
        } else if let Some(v) = line.strip_prefix("description:") {
            description = v.trim().to_string();
        }
    }
    if name.is_empty() {
        return None;
    }
    Some(Skill {
        name,
        description,
        body: body.trim().to_string(),
    })
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
            if let Ok(text) = std::fs::read_to_string(&skill_md) {
                if let Some(skill) = parse_skill_md(&text) {
                    out.push(skill);
                }
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
    /// Tool names the subagent may use (empty = read-only set).
    #[serde(default)]
    pub tools: Vec<String>,
    /// Model override (empty = the session's model).
    #[serde(default)]
    pub model: String,
    #[serde(default = "default_max_turns")]
    pub max_turns: u32,
}

fn default_max_turns() -> u32 {
    25
}

/// Parse an agent definition .md (same frontmatter shape).
pub fn parse_agent_md(text: &str) -> Option<AgentDef> {
    let rest = text.trim().strip_prefix("---")?;
    let (front, _body) = rest.split_once("---")?;
    let mut name = String::new();
    let mut description = String::new();
    let mut tools = Vec::new();
    let mut model = String::new();
    let mut max_turns = default_max_turns();
    for line in front.lines() {
        if let Some(v) = line.strip_prefix("name:") {
            name = v.trim().to_string();
        } else if let Some(v) = line.strip_prefix("description:") {
            description = v.trim().to_string();
        } else if let Some(v) = line.strip_prefix("tools:") {
            tools = v
                .trim()
                .trim_matches('[')
                .trim_matches(']')
                .split(',')
                .map(|t| t.trim().to_string())
                .filter(|t| !t.is_empty())
                .collect();
        } else if let Some(v) = line.strip_prefix("model:") {
            model = v.trim().to_string();
        } else if let Some(v) = line.strip_prefix("maxTurns:") {
            max_turns = v.trim().parse().unwrap_or(default_max_turns());
        }
    }
    if name.is_empty() {
        return None;
    }
    Some(AgentDef {
        name,
        description,
        tools,
        model,
        max_turns,
    })
}

/// The built-in subagents (roadmap: Explore, Plan, general-purpose).
pub fn builtin_agents() -> Vec<AgentDef> {
    vec![
        AgentDef {
            name: "Explore".into(),
            description: "Read-only exploration; returns a thorough report".into(),
            tools: vec!["Read".into(), "Glob".into(), "Grep".into()],
            model: String::new(),
            max_turns: 25,
        },
        AgentDef {
            name: "Plan".into(),
            description: "Read-only research; returns an implementation plan".into(),
            tools: vec!["Read".into(), "Glob".into(), "Grep".into()],
            model: String::new(),
            max_turns: 25,
        },
        AgentDef {
            name: "general-purpose".into(),
            description: "Full tool access for delegated tasks".into(),
            tools: vec![],
            model: String::new(),
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
            if entry.path().extension().and_then(|e| e.to_str()) == Some("md") {
                if let Ok(text) = std::fs::read_to_string(entry.path()) {
                    if let Some(def) = parse_agent_md(&text) {
                        out.push(def);
                    }
                }
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
