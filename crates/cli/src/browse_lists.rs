//! The lists `/hooks`, `/skills` and `/agents` open as menus to read.
//!
//! One row per item. What the one-line text listing cannot say (where the
//! item came from, what it may do) is in the preview. Free text taken from a
//! file passes through the display scanner, so a secret a hook command or a
//! description happens to hold never reaches the screen, and an HTTP hook's
//! header values are not read at all: only their names are shown.
//!
//! The skills and agents are the runtime's own catalog (`load_catalog`), the
//! one `/name`, the Skill tool and the Agent tool resolve against, so the list
//! holds what an imported plugin brings too.

use orbit_engine::hooks::{HookConfig, HookHandler, HookSource, Hooks};
use orbit_engine::skills::{CatalogAgent, CatalogSkill, ContentOrigin};
use orbit_hud_tui::msg::{BrowseRow, Msg};
use std::path::Path;

/// Said under every row when the folder's own entries were left out.
const TRUST_NOTE: &str = "this folder is not trusted: project entries are not loaded";

/// Most characters of a one-line description beside a name.
const LINE: usize = 100;
/// Most characters of a description or command in a preview, which holds six
/// lines at most.
const LONG: usize = 210;

/// `text` cut to `max` characters, with an ellipsis where it was cut.
fn clip(text: &str, max: usize) -> String {
    let cut: String = text.chars().take(max).collect();
    if cut.chars().count() < text.chars().count() {
        format!("{}…", cut.trim_end())
    } else {
        cut
    }
}

/// The first line that says anything, cut to `max`.
fn first_line(text: &str, max: usize) -> String {
    clip(
        text.lines()
            .map(str::trim)
            .find(|line| !line.is_empty())
            .unwrap_or(""),
        max,
    )
}

/// All the words of `text` on one line, cut to `max`.
fn flat(text: &str, max: usize) -> String {
    clip(&text.split_whitespace().collect::<Vec<_>>().join(" "), max)
}

/// `path` with the home folder written as `~`, and a leading `./` left off.
fn tilde(path: &Path) -> String {
    let text = path.display().to_string();
    let text = text.strip_prefix("./").unwrap_or(&text).to_owned();
    if let Some(home) = std::env::var_os("HOME") {
        let home = home.to_string_lossy();
        if let Some(rest) = text.strip_prefix(home.as_ref())
            && (rest.is_empty() || rest.starts_with('/'))
        {
            return format!("~{rest}");
        }
    }
    text
}

/// `path` as the project sees it, or with `~` when it is somewhere else.
fn in_project(path: &Path, working_dir: &Path) -> String {
    match path.strip_prefix(working_dir) {
        Ok(relative) if !relative.as_os_str().is_empty() => relative.display().to_string(),
        _ => tilde(path),
    }
}

fn safe(text: &str) -> String {
    crate::daemon::scan_display(text)
}

/// The menu, or in words what there is instead of one.
fn list(title: &str, rows: Vec<BrowseRow>, empty: &str, trusted: bool) -> Msg {
    if rows.is_empty() {
        return Msg::SystemMessage(if trusted {
            empty.to_owned()
        } else {
            format!("{empty}\n{TRUST_NOTE}")
        });
    }
    Msg::BrowseList {
        title: format!("{title} ({})", rows.len()),
        rows,
        note: if trusted {
            String::new()
        } else {
            TRUST_NOTE.to_owned()
        },
    }
}

// ── hooks ──────────────────────────────────────────────────────────────────

/// `/hooks`: every hook a session started here would load, in the order they
/// are read (the hooks of one event then run side by side).
pub fn hooks_menu(home: &Path) -> Msg {
    let trusted = orbit_engine::hooks::project_trusted(home);
    let rows: Vec<BrowseRow> = Hooks::inspect_sourced(home, trusted.then_some(Path::new(".")))
        .iter()
        .map(|(source, hook)| hook_row(home, source, hook))
        .collect();
    list(
        "HOOKS",
        rows,
        "no hooks — add [[hooks]] tables to settings.toml",
        trusted,
    )
}

/// What a hook does, once short for beside its name and once in full.
fn hook_action(hook: &HookConfig) -> (String, String) {
    if let Some(http) = &hook.http {
        let names: Vec<&str> = http.headers.keys().map(String::as_str).collect();
        let mut full = format!("POST {}", flat(&http.url, LONG));
        if !names.is_empty() {
            // Only the names: a header value is a credential more often than not.
            full.push_str(&format!(" · headers {}", names.join(", ")));
        }
        return (format!("POST {}", clip(&http.url, LINE)), full);
    }
    let with_model = |model: &Option<String>| match model.as_deref() {
        Some(model) if !model.is_empty() => format!(" ({model})"),
        _ => String::new(),
    };
    match &hook.handler {
        Some(HookHandler::Prompt { prompt, model }) => (
            // Not `prompt: …`: the display scanner takes that for a key and a
            // value, and hides the value.
            format!("asks a model: {}", first_line(prompt, LINE)),
            format!("asks a model{}: {}", with_model(model), flat(prompt, LONG)),
        ),
        Some(HookHandler::Agent { prompt, model }) => (
            format!("asks an agent: {}", first_line(prompt, LINE)),
            format!(
                "asks a read-only agent{}: {}",
                with_model(model),
                flat(prompt, LONG)
            ),
        ),
        Some(HookHandler::McpTool { server, tool, .. }) => (
            format!("mcp {server}.{tool}"),
            format!("calls {tool} on the {server} MCP server"),
        ),
        None => (first_line(&hook.command, LINE), flat(&hook.command, LONG)),
    }
}

fn hook_source(home: &Path, source: &HookSource) -> String {
    match source {
        HookSource::User => format!("from {}", tilde(&home.join("settings.toml"))),
        HookSource::SettingsFlag(file) => format!("from {} (--settings)", tilde(file)),
        HookSource::Project => "from .orbit/settings.toml in this project".to_owned(),
        HookSource::Claude(file) => format!("from {} (Claude Code's file)", tilde(file)),
        HookSource::Plugin(name) => format!("from the {name} plugin"),
    }
}

fn hook_row(home: &Path, source: &HookSource, hook: &HookConfig) -> BrowseRow {
    let matcher = hook
        .matcher
        .as_deref()
        .map(str::trim)
        .filter(|matcher| !matcher.is_empty() && *matcher != "*");
    let label = match matcher {
        Some(matcher) => format!("{} {matcher}", hook.event),
        None => hook.event.clone(),
    };
    let (what, full) = hook_action(hook);
    let detail = if hook.run_async {
        format!("async · {what}")
    } else {
        what
    };
    let mut facts: Vec<String> = Vec::new();
    if let Some(condition) = &hook.condition {
        facts.push(format!("if {condition}"));
    }
    if let Some(seconds) = hook.timeout_secs {
        facts.push(format!("timeout {seconds} s"));
    }
    facts.push(
        if hook.run_async {
            "does not wait, so it cannot block"
        } else {
            "waits for its answer"
        }
        .to_owned(),
    );
    let mut preview = vec![facts.join(" · "), hook_source(home, source)];
    if let Some(matcher) = matcher
        && let Some(reason) = orbit_engine::hooks::matcher_problem(matcher)
    {
        preview.push(format!(
            "the matcher is not a valid regular expression ({reason}); only its plain names match"
        ));
    }
    preview.push(full);
    BrowseRow {
        label: safe(&label),
        detail: safe(&detail),
        preview: safe(&preview.join("\n")),
        complete: String::new(),
    }
}

// ── skills ─────────────────────────────────────────────────────────────────

/// `/skills`: every skill the runtime offers, plugins' included, by name.
pub fn skills_menu(home: &Path, working_dir: &Path) -> Msg {
    let trusted =
        orbit_tools::permissions::FolderTrust::new(home.to_path_buf()).is_trusted(working_dir);
    let catalog = match orbit_engine::skills::load_catalog(home, working_dir, true) {
        Ok(catalog) => catalog,
        Err(error) => {
            return Msg::SystemMessage(format!("cannot read the skills ({})", safe(&error.code)));
        }
    };
    let mut skills: Vec<&CatalogSkill> = catalog.skills.iter().collect();
    skills.sort_by_key(|entry| entry.skill.name.to_lowercase());
    let rows = skills
        .into_iter()
        .map(|entry| skill_row(working_dir, entry))
        .collect();
    list(
        "SKILLS",
        rows,
        "no skills — add skills/<name>/SKILL.md",
        trusted,
    )
}

/// Where a definition came from, said once for skills and agents.
fn origin_text(
    origin: &ContentOrigin,
    working_dir: &Path,
    plugin_scope: Option<&'static str>,
) -> String {
    match origin {
        ContentOrigin::BuiltIn => "built into ORBIT".to_owned(),
        ContentOrigin::User(path) => format!("from {}", tilde(path)),
        ContentOrigin::Project(path) => {
            format!("from {} in this project", in_project(path, working_dir))
        }
        ContentOrigin::Claude(path) => {
            format!("from {} (Claude Code's folder)", tilde(path))
        }
        ContentOrigin::Plugin(name) => match plugin_scope {
            Some(scope) => format!("from the {name} plugin ({scope})"),
            None => format!("from the {name} plugin"),
        },
    }
}

fn scope_word(binding: Option<&orbit_engine::skills::ContentBinding>) -> Option<&'static str> {
    binding.map(|binding| match binding.plugin.scope {
        orbit_plugin_compat::StoreScope::User => "user",
        orbit_plugin_compat::StoreScope::Project => "project",
    })
}

/// A list of tool names, short enough for a preview.
fn tool_list(tools: &[String]) -> String {
    let shown: Vec<&str> = tools.iter().take(6).map(String::as_str).collect();
    let more = tools.len().saturating_sub(shown.len());
    if more > 0 {
        format!("{}, +{more} more", shown.join(", "))
    } else {
        shown.join(", ")
    }
}

fn tokens(body: &str) -> String {
    let count = body.chars().count() / 4;
    if count == 1 {
        "about 1 token when loaded".to_owned()
    } else if count < 1000 {
        format!("about {count} tokens when loaded")
    } else {
        format!("about {:.1}k tokens when loaded", count as f64 / 1000.0)
    }
}

fn skill_row(working_dir: &Path, entry: &CatalogSkill) -> BrowseRow {
    let name = &entry.skill.name;
    let policy = entry.policy.as_ref();
    let person_only = policy.is_some_and(|policy| policy.disable_model_invocation);
    let model_only = policy.is_some_and(|policy| !policy.user_invocable);
    // The description is the one free text a file brings; scanning it once
    // serves the line beside the name and the preview.
    let description = safe(&clip(&entry.skill.description, 4 * LONG));
    let mut detail = Vec::new();
    if person_only {
        detail.push("you only".to_owned());
    }
    if model_only {
        detail.push("model only".to_owned());
    }
    let first = first_line(&description, LINE);
    if !first.is_empty() {
        detail.push(first);
    }
    let mut facts = vec![tokens(&entry.skill.body)];
    let tools: Vec<String> = match policy.and_then(|policy| policy.allowed_tools.clone()) {
        Some(tools) if !tools.is_empty() => tools,
        _ => entry.grants.clone(),
    };
    if !tools.is_empty() {
        facts.push(format!("may use {}", safe(&tool_list(&tools))));
    }
    if let Some(model) = policy.and_then(|policy| policy.model.as_deref()) {
        facts.push(format!("model {}", safe(model)));
    }
    if let Some(effort) = policy.and_then(|policy| policy.effort.as_ref()) {
        facts.push(format!(
            "effort {}",
            safe(
                &effort
                    .as_str()
                    .map_or_else(|| effort.to_string(), str::to_owned)
            )
        ));
    }
    if let Some(context) = policy.and_then(|policy| policy.context.as_deref()) {
        facts.push(format!("context {}", safe(context)));
    }
    if person_only {
        facts.push("only a person starts it".to_owned());
    }
    if model_only {
        facts.push("only the model starts it".to_owned());
    }
    let preview = [
        if description.trim().is_empty() {
            "no description".to_owned()
        } else {
            flat(&description, LONG)
        },
        facts.join(" · "),
        origin_text(
            &entry.origin,
            working_dir,
            scope_word(entry.binding.as_ref()),
        ),
    ];
    BrowseRow {
        label: format!("/{name}"),
        detail: detail.join(" · "),
        preview: preview.join("\n"),
        // A name a person cannot type is shown and left alone.
        complete: if model_only {
            String::new()
        } else {
            format!("/{name}")
        },
    }
}

// ── agents ─────────────────────────────────────────────────────────────────

/// `/agents`: ORBIT's own subagents first, then the others by name.
pub fn agents_menu(home: &Path, working_dir: &Path) -> Msg {
    let trusted =
        orbit_tools::permissions::FolderTrust::new(home.to_path_buf()).is_trusted(working_dir);
    let catalog = match orbit_engine::skills::load_catalog(home, working_dir, true) {
        Ok(catalog) => catalog,
        Err(error) => {
            return Msg::SystemMessage(format!("cannot read the agents ({})", safe(&error.code)));
        }
    };
    let (builtin, mut others): (Vec<&CatalogAgent>, Vec<&CatalogAgent>) = catalog
        .agents
        .iter()
        .partition(|entry| entry.origin == ContentOrigin::BuiltIn);
    others.sort_by_key(|entry| entry.agent.name.to_lowercase());
    let rows = builtin
        .into_iter()
        .chain(others)
        .map(|entry| agent_row(working_dir, entry))
        .collect();
    list("AGENTS", rows, "no agents — add agents/<name>.md", trusted)
}

fn effort_word(effort: &orbit_adapter::types::EffortSetting) -> String {
    use orbit_adapter::types::{EffortSetting, EffortValue};
    match effort {
        EffortSetting::Default => "default".to_owned(),
        EffortSetting::Value(EffortValue::Level(level)) => level.clone(),
        EffortSetting::Value(EffortValue::Bool(true)) => "on".to_owned(),
        EffortSetting::Value(EffortValue::Bool(false)) => "off".to_owned(),
    }
}

fn agent_row(working_dir: &Path, entry: &CatalogAgent) -> BrowseRow {
    let agent = &entry.agent;
    let description = safe(&clip(&agent.description, 4 * LONG));
    let tools = match &entry.allowed_tools {
        // Nothing said: it takes what the session has.
        None => "uses the session's tools".to_owned(),
        Some(tools) if tools.is_empty() => "no tools".to_owned(),
        Some(tools) => format!("tools {}", safe(&tool_list(tools))),
    };
    let mut facts = vec![tools];
    facts.push(if agent.model.is_empty() {
        "the session's model".to_owned()
    } else {
        format!("model {}", safe(&agent.model))
    });
    if let Some(effort) = &agent.effort {
        facts.push(format!("effort {}", safe(&effort_word(effort))));
    }
    facts.push(format!("at most {} turns", agent.max_turns));
    let preview = [
        if description.trim().is_empty() {
            "no description".to_owned()
        } else {
            flat(&description, LONG)
        },
        facts.join(" · "),
        origin_text(
            &entry.origin,
            working_dir,
            scope_word(entry.binding.as_ref()),
        ),
    ];
    BrowseRow {
        label: agent.name.clone(),
        detail: first_line(&description, LINE),
        preview: preview.join("\n"),
        complete: String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("orbit-browse-{name}-{}", ulid::Ulid::new()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write(path: std::path::PathBuf, text: &str) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    }

    /// The rows of a list, or the words that stood in for it.
    fn rows(msg: Msg) -> Vec<BrowseRow> {
        match msg {
            Msg::BrowseList { rows, .. } => rows,
            other => panic!("expected a list, got {other:?}"),
        }
    }

    fn words(msg: Msg) -> String {
        match msg {
            Msg::SystemMessage(text) => text,
            other => panic!("expected words, got {other:?}"),
        }
    }

    #[test]
    fn nothing_configured_is_said_in_words_and_an_untrusted_folder_is_named() {
        let home = temp("empty");
        // A fresh home has trusted nothing, so this folder is not trusted.
        if !orbit_engine::hooks::claude_compat(&home) {
            let said = words(hooks_menu(&home));
            assert!(said.starts_with("no hooks — add [[hooks]]"), "{said}");
            assert!(said.contains("this folder is not trusted"), "{said}");
        }
        // The machine's own Claude Code skills join when compatibility is on
        // where the test runs, so only a home that stands alone is asserted.
        if !orbit_engine::hooks::claude_compat(&home) {
            let said = words(skills_menu(&home, &home));
            assert!(said.starts_with("no skills"), "{said}");
        }
        // Only ORBIT's own subagents exist, so the agents list is not empty.
        assert!(!rows(agents_menu(&home, &home)).is_empty());
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn a_command_hook_row_says_what_it_runs_when_it_fires_and_where_it_came_from() {
        let home = temp("hook");
        write(
            home.join("settings.toml"),
            "[[hooks]]\nevent = \"PreToolUse\"\nmatcher = \"Write|Edit\"\ncommand = \"check-edit --strict\"\ntimeout_secs = 30\nif = \"Edit(src/**)\"\n\n[[hooks]]\nevent = \"Stop\"\ncommand = \"notify-done\"\nasync = true\n",
        );
        let Msg::BrowseList { title, rows, note } = hooks_menu(&home) else {
            panic!("expected a list");
        };
        assert!(title.starts_with("HOOKS ("), "{title}");
        assert!(
            note.contains("not trusted"),
            "an untrusted folder says so: {note}"
        );
        // The order is the order they are read.
        assert_eq!(rows[0].label, "PreToolUse Write|Edit");
        assert_eq!(
            rows[1].label, "Stop",
            "a hook with no matcher is just its event"
        );
        assert_eq!(rows[0].detail, "check-edit --strict");
        assert_eq!(rows[1].detail, "async · notify-done");
        let first = rows[0].preview.lines().collect::<Vec<_>>();
        assert_eq!(
            first[0],
            "if Edit(src/**) · timeout 30 s · waits for its answer"
        );
        assert!(
            first[1].starts_with("from ") && first[1].ends_with("settings.toml"),
            "{first:?}"
        );
        assert_eq!(first[2], "check-edit --strict");
        assert!(
            rows[1]
                .preview
                .contains("does not wait, so it cannot block")
        );
        // A hook is only to read.
        assert!(rows.iter().all(|row| row.complete.is_empty()));
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn a_hook_that_is_not_a_command_says_what_it_is_instead() {
        let home = temp("kinds");
        write(
            home.join("settings.toml"),
            "[[hooks]]\nevent = \"PreToolUse\"\nurl = \"https://hooks.example.com/pre\"\nheader = \"X-Team: core\"\n\n[[hooks]]\nevent = \"Stop\"\nprompt = \"Were the tests run? $ARGUMENTS\"\nmodel = \"fast-model\"\n\n[[hooks]]\nevent = \"PostToolUse\"\nmatcher = \"Edit\"\nmcp_server = \"scanner\"\nmcp_tool = \"scan\"\n",
        );
        let rows = rows(hooks_menu(&home));
        assert!(rows.len() >= 3);
        assert_eq!(rows[0].detail, "POST https://hooks.example.com/pre");
        assert!(
            rows[0].preview.contains("headers X-Team"),
            "{}",
            rows[0].preview
        );
        assert!(
            rows[1]
                .detail
                .starts_with("asks a model: Were the tests run?"),
            "{}",
            rows[1].detail
        );
        assert!(
            rows[1].preview.contains("asks a model (fast-model)"),
            "{}",
            rows[1].preview
        );
        assert_eq!(rows[2].detail, "mcp scanner.scan");
        assert!(
            rows[2]
                .preview
                .contains("calls scan on the scanner MCP server")
        );
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn a_secret_in_a_hook_command_or_a_header_value_never_reaches_the_screen() {
        let home = temp("secret");
        let token = format!("ghp_{}", "a1B2c3D4e5".repeat(4));
        write(
            home.join("settings.toml"),
            &format!(
                "[[hooks]]\nevent = \"PreToolUse\"\ncommand = \"curl -H 'Authorization: token {token}' https://example.com\"\n\n[[hooks]]\nevent = \"Stop\"\nurl = \"https://hooks.example.com/stop\"\nheader = \"Authorization: Bearer {token}\"\n"
            ),
        );
        let rows = rows(hooks_menu(&home));
        assert!(rows.len() >= 2);
        for row in &rows {
            for text in [&row.label, &row.detail, &row.preview] {
                assert!(!text.contains(&token), "{text}");
                assert!(!text.contains("ghp_a1B2"), "{text}");
            }
        }
        // The header's name is shown, never its value.
        assert!(
            rows[1].preview.contains("headers Authorization"),
            "{}",
            rows[1].preview
        );
        assert!(!rows[1].preview.contains("Bearer"), "{}", rows[1].preview);
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn a_matcher_that_is_not_a_regular_expression_is_flagged_in_its_row() {
        let home = temp("regex");
        write(
            home.join("settings.toml"),
            "[[hooks]]\nevent = \"PreToolUse\"\nmatcher = \"mcp__.*(exa\"\ncommand = \"broken\"\n\n[[hooks]]\nevent = \"PreToolUse\"\nmatcher = \"^(Bash|Edit)$\"\ncommand = \"fine\"\n",
        );
        let rows = rows(hooks_menu(&home));
        assert!(
            rows[0].preview.contains("not a valid regular expression")
                && rows[0].preview.contains("unclosed group"),
            "{}",
            rows[0].preview
        );
        assert!(!rows[1].preview.contains("not a valid regular expression"));
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn a_skill_row_has_its_description_its_cost_its_source_and_a_name_to_complete() {
        let home = temp("skills");
        let work = temp("skills-work");
        write(
            home.join("skills/release-notes/SKILL.md"),
            "---\nname: release-notes\ndescription: Draft release notes from the commit log\nallowed-tools: Read, Bash(git log:*)\n---\nStep one.\nStep two.\n",
        );
        write(
            home.join("skills/only-me/SKILL.md"),
            "---\nname: only-me\ndescription: A person starts this one\ndisable-model-invocation: true\n---\nbody\n",
        );
        write(
            home.join("skills/the-model/SKILL.md"),
            "---\nname: the-model\ndescription: Only the model uses this\nuser-invocable: false\n---\nbody\n",
        );
        let Msg::BrowseList { title, rows, .. } = skills_menu(&home, &work) else {
            panic!("expected a list");
        };
        assert!(title.starts_with("SKILLS ("), "{title}");
        let by = |label: &str| rows.iter().find(|row| row.label == label).unwrap();
        // By name, and every one found: the plain text listing hid `only-me`.
        let ours = ["/only-me", "/release-notes", "/the-model"];
        let names: Vec<&str> = rows
            .iter()
            .map(|row| row.label.as_str())
            .filter(|label| ours.contains(label))
            .collect();
        assert_eq!(names, ours);
        let notes = by("/release-notes");
        assert_eq!(notes.detail, "Draft release notes from the commit log");
        assert_eq!(notes.complete, "/release-notes");
        let lines: Vec<&str> = notes.preview.lines().collect();
        assert_eq!(lines[0], "Draft release notes from the commit log");
        assert!(lines[1].contains("about 4 tokens when loaded"), "{lines:?}");
        assert!(
            lines[1].contains("may use Read, Bash(git log:*)"),
            "{lines:?}"
        );
        assert!(
            lines[2].starts_with("from ") && lines[2].ends_with("skills/release-notes"),
            "{lines:?}"
        );
        // A skill only a person starts is listed, and says so.
        let mine = by("/only-me");
        assert!(mine.detail.starts_with("you only · "), "{}", mine.detail);
        assert_eq!(mine.complete, "/only-me");
        // A skill only the model starts cannot be typed: nothing to complete.
        let theirs = by("/the-model");
        assert!(
            theirs.detail.starts_with("model only · "),
            "{}",
            theirs.detail
        );
        assert!(theirs.complete.is_empty());
        let _ = std::fs::remove_dir_all(&home);
        let _ = std::fs::remove_dir_all(&work);
    }

    #[test]
    fn an_agent_row_has_its_tools_model_turns_and_source_and_the_built_ins_come_first() {
        let home = temp("agents");
        let work = temp("agents-work");
        write(
            home.join("agents/zeta.md"),
            "---\nname: zeta\ndescription: Reviews diffs\ntools: Read, Grep\nmodel: fast-model\nmaxTurns: 7\n---\nReview carefully.\n",
        );
        write(
            home.join("agents/alpha.md"),
            "---\nname: alpha\ndescription: Does anything\n---\nbody\n",
        );
        let Msg::BrowseList { title, rows, .. } = agents_menu(&home, &work) else {
            panic!("expected a list");
        };
        assert!(title.starts_with("AGENTS ("), "{title}");
        let names: Vec<&str> = rows.iter().map(|row| row.label.as_str()).collect();
        assert_eq!(
            &names[..3],
            ["Explore", "Plan", "general-purpose"],
            "ORBIT's own, in their own order, first"
        );
        let ours: Vec<&str> = names[3..]
            .iter()
            .copied()
            .filter(|name| *name == "alpha" || *name == "zeta")
            .collect();
        assert_eq!(ours, ["alpha", "zeta"], "then the rest by name");
        let explore = &rows[0];
        let lines: Vec<&str> = explore.preview.lines().collect();
        assert!(
            lines[1].starts_with("tools Read, Glob, Grep · the session's model"),
            "{lines:?}"
        );
        assert_eq!(lines[2], "built into ORBIT");
        let general = &rows[2];
        assert!(
            general.preview.contains("uses the session's tools"),
            "{}",
            general.preview
        );
        assert!(
            general.preview.contains("at most 50 turns"),
            "{}",
            general.preview
        );
        let zeta = rows.iter().find(|row| row.label == "zeta").unwrap();
        assert_eq!(zeta.detail, "Reviews diffs");
        assert!(
            zeta.preview
                .contains("tools Read, Grep · model fast-model · at most 7 turns"),
            "{}",
            zeta.preview
        );
        let from = zeta.preview.lines().last().unwrap();
        assert!(
            from.starts_with("from ") && from.ends_with("agents/zeta.md"),
            "{from}"
        );
        // An agent is only to read.
        assert!(rows.iter().all(|row| row.complete.is_empty()));
        let _ = std::fs::remove_dir_all(&home);
        let _ = std::fs::remove_dir_all(&work);
    }

    #[test]
    fn an_imported_plugins_skills_and_agents_are_listed_under_the_plugin() {
        use orbit_plugin_compat::{InspectOptions, PluginFormat, PluginStore, StoreScope};
        use std::os::unix::fs::PermissionsExt;
        let root = temp("plugin");
        let (home, project, source) = (root.join("home"), root.join("project"), root.join("src"));
        for dir in [
            &home,
            &project,
            &source.join(".claude-plugin"),
            &source.join("skills/writing-rules"),
            &source.join("agents"),
        ] {
            std::fs::create_dir_all(dir).unwrap();
        }
        // The store keeps its copies only in a private home.
        std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700)).unwrap();
        write(
            source.join(".claude-plugin/plugin.json"),
            r#"{"name":"hookify","description":"d"}"#,
        );
        write(
            source.join("skills/writing-rules/SKILL.md"),
            "---\nname: writing-rules\ndescription: How to write a rule\n---\nBody of the skill.\n",
        );
        write(
            source.join("agents/analyzer.md"),
            "---\nname: analyzer\ndescription: Looks for patterns\ntools: Read\n---\nAnalyze.\n",
        );
        PluginStore::open(&home, &project, false)
            .unwrap()
            .import(
                &source,
                &InspectOptions {
                    format: Some(PluginFormat::Claude),
                    ..InspectOptions::default()
                },
                StoreScope::User,
                true,
            )
            .unwrap();
        let skills = rows(skills_menu(&home, &project));
        let skill = skills
            .iter()
            .find(|row| row.label.contains("writing-rules"))
            .unwrap_or_else(|| {
                let labels: Vec<&str> = skills.iter().map(|row| row.label.as_str()).collect();
                panic!("the plugin's skill is listed, got {labels:?}")
            });
        assert_eq!(skill.detail, "How to write a rule");
        assert_eq!(skill.complete, skill.label, "a person can type it");
        assert_eq!(
            skill.preview.lines().last().unwrap(),
            "from the hookify plugin (user)"
        );
        let agents = rows(agents_menu(&home, &project));
        let agent = agents
            .iter()
            .find(|row| row.label.contains("analyzer"))
            .unwrap_or_else(|| {
                let labels: Vec<&str> = agents.iter().map(|row| row.label.as_str()).collect();
                panic!("the plugin's agent is listed, got {labels:?}")
            });
        assert!(agent.preview.contains("tools Read"), "{}", agent.preview);
        assert_eq!(
            agent.preview.lines().last().unwrap(),
            "from the hookify plugin (user)"
        );
        // The stored copy is read-only: open it up to remove it.
        fn open(path: &Path) {
            if let Ok(meta) = std::fs::symlink_metadata(path)
                && meta.is_dir()
            {
                let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700));
                for entry in std::fs::read_dir(path).into_iter().flatten().flatten() {
                    open(&entry.path());
                }
            }
        }
        open(&root);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_skill_with_no_description_has_no_dangling_separator_and_a_leading_dot_slash_is_dropped() {
        let home = temp("quiet");
        let work = temp("quiet-work");
        write(
            home.join("skills/quiet/SKILL.md"),
            "---\nname: quiet\ndisable-model-invocation: true\n---\nbody\n",
        );
        let rows = rows(skills_menu(&home, &work));
        let quiet = rows.iter().find(|row| row.label == "/quiet").unwrap();
        assert_eq!(quiet.detail, "you only");
        assert_eq!(quiet.preview.lines().next().unwrap(), "no description");
        // A path read from the working directory is shown as the project sees it.
        assert_eq!(
            tilde(Path::new("./.claude/settings.json")),
            ".claude/settings.json"
        );
        let _ = std::fs::remove_dir_all(&home);
        let _ = std::fs::remove_dir_all(&work);
    }

    #[test]
    fn a_long_description_is_cut_and_a_name_with_a_space_cannot_be_completed() {
        let home = temp("long");
        let work = temp("long-work");
        let long = "word ".repeat(400);
        write(
            home.join("skills/wordy/SKILL.md"),
            &format!("---\nname: wordy\ndescription: {long}\n---\nbody\n"),
        );
        write(
            home.join("skills/two/SKILL.md"),
            "---\nname: two words\ndescription: d\n---\nbody\n",
        );
        let rows = rows(skills_menu(&home, &work));
        let wordy = rows.iter().find(|row| row.label == "/wordy").unwrap();
        assert!(wordy.detail.chars().count() <= LINE + 1, "{}", wordy.detail);
        let description = wordy.preview.lines().next().unwrap();
        assert!(
            description.chars().count() <= LONG + 1 && description.ends_with('…'),
            "{description}"
        );
        // The row keeps its name as given; the menu refuses to complete it.
        let two = rows.iter().find(|row| row.label == "/two words").unwrap();
        assert_eq!(two.complete, "/two words");
        let _ = std::fs::remove_dir_all(&home);
        let _ = std::fs::remove_dir_all(&work);
    }
}
