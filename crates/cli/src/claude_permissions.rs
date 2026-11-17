//! `orbit config import-claude`: carry the permission rules of a Claude
//! Code `settings.json` over to ORBIT, on request and in plain sight.
//!
//! ORBIT reads a Claude Code `settings.json` for its hooks only: rules
//! written for another program are never applied silently. This command is
//! the explicit step. It lists every rule it found, the ORBIT rule each one
//! becomes, and the ones it leaves for the operator to write by hand because
//! the two programs read them differently (path patterns, above all). With
//! `--apply` the rules that carry over are added to ORBIT's own settings:
//! the operator's file to `$ORBIT_HOME/settings.toml`, a project's files to
//! that project's `.orbit/settings.local.toml`. An unsupported ask or deny
//! rule blocks the whole application so its protection is not dropped.

use std::path::{Path, PathBuf};

use serde_json::{Value, json};

/// One rule found in a Claude Code settings file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FoundRule {
    /// `allow`, `ask` or `deny`.
    pub effect: &'static str,
    /// The rule as Claude Code spells it.
    pub claude: String,
    /// The ORBIT rule, or why there is none.
    pub orbit: Result<String, String>,
}

/// The ORBIT spelling of a Claude Code permission rule, or why it does not
/// carry over. `tools` is the set of tool names ORBIT has.
pub fn translate(rule: &str, tools: &[String]) -> Result<String, String> {
    let rule = rule.trim();
    if rule.is_empty() || rule.len() > 512 || rule.chars().any(char::is_control) {
        return Err("not a rule ORBIT can read".into());
    }
    let (tool, pattern) = match rule.split_once('(') {
        Some((tool, rest)) => match rest.strip_suffix(')') {
            Some(pattern) => (tool.trim(), Some(pattern.trim())),
            None => return Err("unbalanced brackets".into()),
        },
        None => (rule, None),
    };
    if let Some(name) = tool.strip_prefix("mcp__") {
        if pattern.is_some() {
            return Err("an MCP rule takes no pattern in ORBIT".into());
        }
        // `mcp__server` is the whole server in Claude Code.
        let selector = if name.contains("__") {
            tool.to_owned()
        } else {
            format!("{tool}__*")
        };
        return orbit_tools::permissions::validate_mcp_selector(&selector).map(|()| selector);
    }
    if !tools.iter().any(|known| known == tool) {
        return Err(format!("ORBIT has no tool named {tool}"));
    }
    match (tool, pattern) {
        ("Read" | "Edit", None) => Err(format!(
            "Claude {tool} rules group several file operations; ORBIT selects individual tools, so migrate this policy manually"
        )),
        ("Read" | "Edit", Some(_)) => Err(format!(
            "Claude {tool} path rules require grouped operation coverage, settings-dependent anchors and resolved symlink checks; migrate this policy manually"
        )),
        ("WebFetch", Some(pattern)) if pattern.starts_with("domain:") => Err(
            "Claude WebFetch domain rules normalize hostnames and also change sandbox network policy; translating only the tool selector cannot preserve this policy, so migrate it manually".into(),
        ),
        ("Bash", Some("" | "*")) => Ok("Bash".to_owned()),
        // `npm run test:*` is Claude Code's older spelling of a prefix.
        ("Bash", Some(pattern)) => Ok(format!(
            "Bash({})",
            match pattern.strip_suffix(":*") {
                Some(prefix) => format!("{} *", prefix.trim_end()),
                None => pattern.to_owned(),
            }
        )),
        (_, Some(_)) => Err(format!(
            "ORBIT reads {tool} patterns differently; write this rule by hand"
        )),
        (name, None) => Ok(name.to_owned()),
    }
}

/// The checked rules in one Claude source. Missing files are benign; malformed,
/// oversized, linked or unreadable sources are explicit failures.
fn checked_rules_in(path: &Path, tools: &[String]) -> Result<Vec<FoundRule>, String> {
    let Some(bytes) = crate::migration::source_bytes(path)
        .map_err(|reason| format!("Claude permission source is {reason}; nothing imported"))?
    else {
        return Ok(Vec::new());
    };
    let doc: Value = serde_json::from_slice(&bytes)
        .map_err(|_| "Claude permission source is malformed JSON; nothing imported".to_owned())?;
    if !doc.is_object() {
        return Err("Claude permission source must be a JSON object".into());
    }
    let Some(permissions) = doc.get("permissions") else {
        return Ok(Vec::new());
    };
    let permissions = permissions
        .as_object()
        .ok_or_else(|| "Claude permissions must be an object".to_owned())?;
    let mut found = Vec::new();
    for effect in ["deny", "ask", "allow"] {
        let Some(rules) = permissions.get(effect) else {
            continue;
        };
        let rules = rules
            .as_array()
            .ok_or_else(|| "Claude permission effects must be lists".to_owned())?;
        if rules.len() > 512 {
            return Err("Claude permission list exceeds 512 rules; nothing imported".into());
        }
        for rule in rules {
            let rule = rule
                .as_str()
                .ok_or_else(|| "Claude permission rules must be strings".to_owned())?;
            found.push(FoundRule {
                effect,
                claude: rule.to_owned(),
                orbit: translate(rule, tools),
            });
        }
    }
    Ok(found)
}

/// Compatibility inspection API. Imports use the checked variant so an error
/// cannot silently be interpreted as an empty permission set.
pub fn rules_in(path: &Path, tools: &[String]) -> Vec<FoundRule> {
    checked_rules_in(path, tools).unwrap_or_default()
}

fn checked_destination(bytes: &[u8]) -> Result<toml_edit::DocumentMut, String> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| "Existing settings are not UTF-8; left untouched".to_owned())?;
    let doc: toml_edit::DocumentMut = text
        .parse()
        .map_err(|_| "Existing settings are malformed; left untouched".to_owned())?;
    if let Some(permissions) = doc.get("permissions") {
        let permissions = permissions
            .as_table()
            .ok_or_else(|| "Existing permissions are not a table; left untouched".to_owned())?;
        for effect in ["allow", "ask", "deny"] {
            let Some(list) = permissions.get(effect) else {
                continue;
            };
            let list = list.as_array().ok_or_else(|| {
                "Existing permission effect is not a list; left untouched".to_owned()
            })?;
            if list.iter().any(|value| value.as_str().is_none()) {
                return Err(
                    "Existing permission list contains a non-string; left untouched".into(),
                );
            }
        }
    }
    Ok(doc)
}

/// Add rules to the `[permissions]` table of an ORBIT settings file,
/// keeping everything else in it. Returns how many were not there before.
fn add_rules(path: &Path, rules: &[(&'static str, String)]) -> Result<usize, String> {
    use crate::customization::{Directory, Lock, read_regular};
    use std::io::Write;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
    use toml_edit::{Array, Item, Table, value};
    if rules.is_empty() {
        return Ok(0);
    }
    let parent = path
        .parent()
        .ok_or_else(|| "Settings destination has no parent".to_owned())?;
    let directory = match crate::migration::path_status(parent)
        .map_err(|_| "Settings destination is unsafe".to_owned())?
    {
        Some(_) => Directory::open(parent, false),
        None => Directory::create(parent),
    }
    .map_err(|_| "Settings destination directory is unsafe or unavailable".to_owned())?;
    let directory_metadata = std::fs::metadata(
        directory
            .io()
            .map_err(|_| "Settings directory changed".to_owned())?,
    )
    .map_err(|_| "Settings directory could not be checked".to_owned())?;
    if directory_metadata.uid() != rustix::process::geteuid().as_raw()
        || directory_metadata.permissions().mode() & 0o022 != 0
    {
        return Err("Settings destination must be owned and not writable by others".into());
    }
    let name = path
        .file_name()
        .ok_or_else(|| "Settings destination has no file name".to_owned())?;
    let _lock = Lock::acquire(&directory, ".permissions-import.lock")
        .map_err(|_| "Permission import is busy or its lock is unsafe".to_owned())?;
    let target = directory
        .io()
        .map_err(|_| "Settings directory changed".to_owned())?
        .join(name);
    let original =
        match std::fs::symlink_metadata(&target) {
            Ok(_) => Some(read_regular(&target, 1024 * 1024, false).map_err(|_| {
                "Existing settings are unsafe or oversized; left untouched".to_owned()
            })?),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(_) => return Err("Existing settings could not be checked; left untouched".into()),
        };
    let mut doc = checked_destination(original.as_deref().unwrap_or_default())?;
    if doc.get("permissions").is_none() {
        doc["permissions"] = Item::Table(Table::new());
    }
    let perms = doc["permissions"]
        .as_table_mut()
        .ok_or_else(|| "Existing permissions are not a table; left untouched".to_owned())?;
    let mut added = 0;
    for (effect, rule) in rules {
        if perms.get(effect).is_none() {
            perms[effect] = value(Array::new());
        }
        let list = perms[effect]
            .as_array_mut()
            .ok_or_else(|| "Existing permission effect is not a list; left untouched".to_owned())?;
        if !list
            .iter()
            .any(|value| value.as_str() == Some(rule.as_str()))
        {
            list.push(rule.as_str());
            added += 1;
        }
    }
    if added == 0 {
        return Ok(0);
    }
    let body = doc.to_string();
    if body.len() > 1024 * 1024 {
        return Err("Imported settings would exceed 1 MiB; left untouched".into());
    }
    let temporary = directory
        .io()
        .map_err(|_| "Settings directory changed".to_owned())?
        .join(format!(".import-{}", ulid::Ulid::new()));
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&temporary)
        .map_err(|_| "Could not stage private settings; left untouched".to_owned())?;
    let owned = file
        .metadata()
        .map_err(|_| "Could not inspect staged settings".to_owned())?;
    let mut published = false;
    let result = (|| {
        file.write_all(body.as_bytes())
            .and_then(|()| file.sync_all())
            .map_err(|_| "Could not write staged settings; destination untouched".to_owned())?;
        directory
            .check()
            .map_err(|_| "Settings directory changed; destination untouched".to_owned())?;
        match (&original, std::fs::symlink_metadata(&target)) {
            (Some(expected), Ok(_)) => {
                let current = read_regular(&target, 1024 * 1024, false).map_err(|_| {
                    "Settings changed or became unsafe; destination untouched".to_owned()
                })?;
                if &current != expected {
                    return Err("Settings changed during import; destination untouched".into());
                }
            }
            (None, Err(error)) if error.kind() == std::io::ErrorKind::NotFound => {}
            _ => return Err("Settings changed during import; destination untouched".into()),
        }
        let staged = std::fs::symlink_metadata(&temporary)
            .map_err(|_| "Staged settings disappeared; destination untouched".to_owned())?;
        if !staged.is_file() || staged.dev() != owned.dev() || staged.ino() != owned.ino() {
            return Err("Staged settings changed; destination untouched".into());
        }
        if original.is_none() {
            rustix::fs::renameat_with(
                rustix::fs::CWD,
                &temporary,
                rustix::fs::CWD,
                &target,
                rustix::fs::RenameFlags::NOREPLACE,
            )
            .map_err(|_| "Settings appeared during import; destination untouched".to_owned())?;
        } else {
            std::fs::rename(&temporary, &target)
                .map_err(|_| "Could not publish settings; destination untouched".to_owned())?;
        }
        published = true;
        directory.sync().map_err(|_| {
            "Settings published but durable storage is uncertain; inspect before retrying"
                .to_owned()
        })?;
        Ok(added)
    })();
    if !published
        && std::fs::symlink_metadata(&temporary)
            .is_ok_and(|metadata| metadata.dev() == owned.dev() && metadata.ino() == owned.ino())
    {
        let _ = std::fs::remove_file(&temporary);
    }
    result
}

/// `orbit config import-claude [--apply]`: what each Claude Code settings
/// file holds and what becomes of it. Nothing is written without `apply`.
pub fn import(home: &Path, project: &Path, tools: &[String], apply: bool) -> Result<Value, String> {
    let mut sources: Vec<(&str, PathBuf, PathBuf)> = Vec::new();
    if let Some(dir) = orbit_engine::hooks::claude_config_dir() {
        sources.push((
            "user",
            dir.join("settings.json"),
            home.join("settings.toml"),
        ));
    }
    for name in ["settings.json", "settings.local.json"] {
        sources.push((
            "project",
            project.join(".claude").join(name),
            project.join(".orbit/settings.local.toml"),
        ));
    }
    import_sources(sources, tools, apply)
}

fn import_sources(
    sources: Vec<(&str, PathBuf, PathBuf)>,
    tools: &[String],
    apply: bool,
) -> Result<Value, String> {
    // Check every source before applying any file so a malformed later source
    // cannot leave an apparently successful partial import.
    let planned = sources
        .into_iter()
        .map(|(scope, from, to)| {
            checked_rules_in(&from, tools).map(|found| (scope, from, to, found))
        })
        .collect::<Result<Vec<_>, _>>()?;
    if apply {
        if planned.iter().any(|(_, _, _, found)| {
            found
                .iter()
                .any(|rule| matches!(rule.effect, "ask" | "deny") && rule.orbit.is_err())
        }) {
            return Err("Claude ask or deny rules are not portable; preview them and migrate the permission policy manually; nothing imported".into());
        }
        // Validate every destination before the first write, including effects
        // that receive no rules. A malformed later target must not leave an
        // earlier user or project target partially imported.
        for (_, _, to, found) in &planned {
            if found.iter().any(|rule| rule.orbit.is_ok()) {
                let bytes = crate::migration::source_bytes(to)
                    .map_err(|_| {
                        "Existing settings are unsafe or oversized; left untouched".to_owned()
                    })?
                    .unwrap_or_default();
                checked_destination(&bytes)?;
            }
        }
    }
    let mut files = Vec::new();
    for (scope, from, to, found) in planned {
        if found.is_empty() {
            continue;
        }
        let carried: Vec<(&'static str, String)> = found
            .iter()
            .filter_map(|rule| Some((rule.effect, rule.orbit.clone().ok()?)))
            .collect();
        let added = if apply {
            Some(add_rules(&to, &carried)?)
        } else {
            None
        };
        files.push(json!({
            "scope": scope,
            "from": from.to_string_lossy(),
            "to": to.to_string_lossy(),
            "added": added,
            "rules": found.iter().map(|rule| json!({
                "effect": rule.effect,
                "claude": rule.claude,
                "orbit": rule.orbit.as_ref().ok(),
                "not_carried": rule.orbit.as_ref().err(),
            })).collect::<Vec<_>>(),
        }));
    }
    Ok(json!({
        "schema": "orbit.cli/v1",
        "command": "config import-claude",
        "status": "ok",
        "applied": apply,
        "files": files,
    }))
}

/// The report as text.
pub fn human_report(value: &Value) -> String {
    let text = |v: &Value| {
        orbit_hud::display_safe(v.as_str().unwrap_or(""))
            .unwrap_or_else(|_| "[unsafe text withheld]".into())
            .replace('\n', "\\n")
    };
    let files = value["files"].as_array().cloned().unwrap_or_default();
    if files.is_empty() {
        return "No permission rules found in your Claude Code settings (~/.claude/settings.json, or .claude/settings.json and .claude/settings.local.json here).\n".into();
    }
    let applied = value["applied"] == true;
    let apply_blocked = files.iter().any(|file| {
        file["rules"].as_array().into_iter().flatten().any(|rule| {
            matches!(rule["effect"].as_str(), Some("ask" | "deny")) && rule["orbit"].is_null()
        })
    });
    let mut out = String::new();
    let mut left = 0;
    for file in &files {
        out.push_str(&format!("{}\n", text(&file["from"])));
        for rule in file["rules"].as_array().into_iter().flatten() {
            match rule["orbit"].as_str() {
                Some(_) => out.push_str(&format!(
                    "  {:<5} {}  ->  {}\n",
                    text(&rule["effect"]),
                    text(&rule["claude"]),
                    text(&rule["orbit"])
                )),
                None => {
                    left += 1;
                    out.push_str(&format!(
                        "  {:<5} {}  (not carried over: {})\n",
                        text(&rule["effect"]),
                        text(&rule["claude"]),
                        text(&rule["not_carried"])
                    ));
                }
            }
        }
        match file["added"].as_u64() {
            Some(added) => out.push_str(&format!(
                "  {added} rule(s) added to {}\n\n",
                text(&file["to"])
            )),
            None => out.push_str(&format!("  would go to {}\n\n", text(&file["to"]))),
        }
    }
    if !applied {
        if apply_blocked {
            out.push_str("Nothing was changed. Automatic application is blocked by ask or deny rules that cannot carry over; migrate the permission policy manually.\n");
        } else {
            out.push_str("Nothing was changed. Run `orbit config import-claude --apply` to add the rules that carry over.\n");
        }
    }
    if left > 0 {
        out.push_str(&format!(
            "{left} rule(s) were not carried over; add them to settings.toml yourself if you still want them.\n"
        ));
    }
    if files.iter().any(|file| file["scope"] == "project") {
        out.push_str(
            "A project's allow rules apply only in a trusted folder (orbit folder trust).\n",
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preview_never_emits_terminal_controls_from_rejected_rules_or_paths() {
        let value = json!({"applied":false,"files":[{
            "from":"project\u{1b}]0;untrusted\u{7}",
            "to":"settings.toml",
            "scope":"project",
            "rules":[{"effect":"allow","claude":"Bash(\u{1b}]52;c;payload\u{7})",
                      "orbit":null,"not_carried":"not a rule ORBIT can read"}]
        }]});
        let output = human_report(&value);
        assert!(!output.contains('\u{1b}') && !output.contains('\u{7}'));
        assert!(output.contains("not carried over"));
    }

    fn tools() -> Vec<String> {
        ["Bash", "Read", "Edit", "Write", "WebFetch"]
            .iter()
            .map(|name| (*name).to_owned())
            .collect()
    }

    #[test]
    fn only_rules_that_mean_the_same_carry_over() {
        let t = tools();
        assert_eq!(
            translate("Bash(npm run test:*)", &t).unwrap(),
            "Bash(npm run test *)"
        );
        assert_eq!(
            translate("Bash(git status)", &t).unwrap(),
            "Bash(git status)"
        );
        assert_eq!(
            translate("Bash(cargo test *)", &t).unwrap(),
            "Bash(cargo test *)"
        );
        assert_eq!(translate("Bash(*)", &t).unwrap(), "Bash");
        assert_eq!(translate(" WebFetch ", &t).unwrap(), "WebFetch");
        assert_eq!(translate("mcp__github", &t).unwrap(), "mcp__github__*");
        assert_eq!(
            translate("mcp__github__get_issue", &t).unwrap(),
            "mcp__github__get_issue"
        );
        for left in [
            "Read",
            " Read ",
            "Edit",
            "Read(./.env)",
            "Edit(src/**)",
            "WebFetch(domain:example.com)",
            "MultiEdit",
            "Bash(ls",
            "mcp__a__*__b",
            "",
        ] {
            assert!(translate(left, &t).is_err(), "{left}");
        }
    }

    #[test]
    fn bare_file_tool_groups_are_reported_as_not_carried_over() {
        let root = private_fixture();
        let source = root.join("source.json");
        let target = root.join("settings.toml");
        std::fs::write(&source, r#"{"permissions":{"allow":["Read","Edit"],"ask":["Read","Edit"],"deny":["Read","Edit"]}}"#).unwrap();
        let preview =
            import_sources(vec![("user", source, target.clone())], &tools(), false).unwrap();
        let rules = preview["files"][0]["rules"].as_array().unwrap();
        assert_eq!(rules.len(), 6);
        assert!(
            rules
                .iter()
                .all(|rule| rule["orbit"].is_null() && rule["not_carried"].is_string())
        );
        let report = human_report(&preview);
        assert!(report.contains("Automatic application is blocked"));
        assert!(!report.contains("Run `orbit config import-claude --apply`"));
        assert!(!target.exists());
        assert!(!root.join(".permissions-import.lock").exists());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn preview_explains_grouped_paths_and_sandbox_domain_policy_without_guessing_rules() {
        let root = private_fixture();
        let source = root.join("source.json");
        let target = root.join("settings.toml");
        let raw_rules = [
            "Read",
            "Edit",
            "Read(./private/**)",
            "Edit(/src/**)",
            "WebFetch(domain:EXAMPLE.com.)",
            "Write",
        ];
        std::fs::write(
            &source,
            json!({"permissions":{"allow":raw_rules}}).to_string(),
        )
        .unwrap();
        let preview =
            import_sources(vec![("user", source, target.clone())], &tools(), false).unwrap();
        let rules = preview["files"][0]["rules"].as_array().unwrap();
        assert_eq!(rules.len(), raw_rules.len());
        for (index, rule) in rules.iter().take(5).enumerate() {
            assert!(rule["orbit"].is_null());
            let reason = rule["not_carried"].as_str().unwrap();
            if index >= 2 {
                assert!(!reason.contains(raw_rules[index]));
            }
            if index < 2 {
                assert!(reason.contains("group"));
                assert!(reason.contains("individual tools"));
            } else if index < 4 {
                assert!(reason.contains("group"));
                assert!(reason.contains("settings-dependent anchors"));
                assert!(reason.contains("resolved symlink"));
            } else {
                assert!(reason.contains("normalize hostnames"));
                assert!(reason.contains("sandbox network policy"));
            }
        }
        assert_eq!(rules[5]["orbit"], "Write");
        let report = human_report(&preview);
        assert!(report.contains("settings-dependent anchors"));
        assert!(report.contains("sandbox network policy"));
        assert!(!target.exists());
        assert!(!root.join(".permissions-import.lock").exists());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn unsupported_protections_block_every_source_before_apply() {
        for effect in ["ask", "deny"] {
            for rule in [
                "Edit",
                "Read(private/**)",
                "WebFetch(domain:EXAMPLE.com.)",
                "WebFetch(domain:*.example.com)",
            ] {
                let root = private_fixture();
                let first_source = root.join("user.json");
                let later_source = root.join("project.json");
                std::fs::write(&first_source, r#"{"permissions":{"allow":["Bash"]}}"#).unwrap();
                let mut permissions = json!({"allow":["WebFetch"]});
                permissions[effect] = json!([rule]);
                std::fs::write(
                    &later_source,
                    json!({"permissions":permissions}).to_string(),
                )
                .unwrap();
                let first_target = root.join("user.toml");
                let later_directory = root.join("project");
                let later_target = later_directory.join("settings.toml");
                let original = "# preserve existing policy\n[permissions]\nallow = [\"Write\"]\n";
                std::fs::write(&first_target, original).unwrap();
                let sources = vec![
                    ("user", first_source, first_target.clone()),
                    ("project", later_source, later_target),
                ];
                let preview = import_sources(sources.clone(), &tools(), false).unwrap();
                assert_eq!(preview["applied"], false);
                assert_eq!(preview["files"].as_array().unwrap().len(), 2);
                let error = import_sources(sources, &tools(), true).unwrap_err();
                assert!(error.contains("manually"));
                assert!(!error.contains("private/**"));
                assert_eq!(std::fs::read_to_string(first_target).unwrap(), original);
                assert!(!later_directory.exists());
                assert!(!root.join(".permissions-import.lock").exists());
                std::fs::remove_dir_all(root).unwrap();
            }
        }
    }

    #[test]
    fn a_dry_run_writes_nothing_and_apply_adds_once() {
        let root = std::env::temp_dir().join(format!(
            "orbit-claude-import-{}-{}",
            std::process::id(),
            ulid::Ulid::new()
        ));
        let (home, project) = (root.join("home"), root.join("project"));
        std::fs::create_dir_all(project.join(".claude")).unwrap();
        std::fs::create_dir_all(&home).unwrap();
        std::fs::write(
            project.join(".claude/settings.json"),
            r#"{"permissions": {"allow": ["Bash(npm run lint:*)", "Read(./docs/**)"], "deny": ["Bash(curl:*)"]}, "hooks": {}}"#,
        )
        .unwrap();
        let target = project.join(".orbit/settings.local.toml");
        std::fs::create_dir_all(project.join(".orbit")).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for dir in [&home, &project.join(".orbit")] {
                std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).unwrap();
            }
        }
        std::fs::write(&target, "# mine\n[permissions]\nallow = [\"Bash(ls)\"]\n").unwrap();

        let project_only = |value: &Value| -> Vec<Value> {
            value["files"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|file| file["scope"] == "project")
                .cloned()
                .collect()
        };
        let dry = import(&home, &project, &tools(), false).unwrap();
        let files = project_only(&dry);
        assert_eq!(files.len(), 1);
        assert!(files[0]["added"].is_null());
        assert_eq!(
            std::fs::read_to_string(&target).unwrap(),
            "# mine\n[permissions]\nallow = [\"Bash(ls)\"]\n"
        );
        assert!(human_report(&dry).contains("Read(./docs/**)  (not carried over"));

        let applied = import(&home, &project, &tools(), true).unwrap();
        assert_eq!(project_only(&applied)[0]["added"], 2);
        let text = std::fs::read_to_string(&target).unwrap();
        assert!(text.starts_with("# mine\n"), "{text}");
        let doc: toml::Table = toml::from_str(&text).unwrap();
        let list = |key: &str| -> Vec<String> {
            doc["permissions"][key]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_str().unwrap().to_owned())
                .collect()
        };
        assert_eq!(list("allow"), ["Bash(ls)", "Bash(npm run lint *)"]);
        assert_eq!(list("deny"), ["Bash(curl *)"]);
        // A second run finds them already there.
        let again = import(&home, &project, &tools(), true).unwrap();
        assert_eq!(project_only(&again)[0]["added"], 0);
        let _ = std::fs::remove_dir_all(root);
    }
    fn private_fixture() -> PathBuf {
        let path =
            std::env::temp_dir().join(format!("orbit-claude-safe-import-{}", ulid::Ulid::new()));
        std::fs::create_dir(&path).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        path
    }

    #[test]
    fn invalid_sources_fail_before_any_permission_application() {
        let root = private_fixture();
        let home = root.join("home");
        let project = root.join("project");
        std::fs::create_dir(&home).unwrap();
        std::fs::create_dir_all(project.join(".claude")).unwrap();
        std::fs::write(
            project.join(".claude/settings.json"),
            r#"{"permissions":{"allow":["Write"]}}"#,
        )
        .unwrap();
        std::fs::write(
            project.join(".claude/settings.local.json"),
            "{not valid JSON",
        )
        .unwrap();
        assert!(import(&home, &project, &tools(), true).is_err());
        assert!(!home.join("settings.toml").exists());
        assert!(!project.join(".orbit").exists());
        for raw in [
            "[]",
            r#"{"permissions":{"allow":false}}"#,
            r#"{"permissions":{"allow":[1]}}"#,
        ] {
            let file = project.join(".claude/settings.json");
            std::fs::write(&file, raw).unwrap();
            assert!(checked_rules_in(&file, &tools()).is_err());
        }
        let file = project.join(".claude/settings.json");
        std::fs::write(&file, " ".repeat(1024 * 1024 + 1)).unwrap();
        assert!(checked_rules_in(&file, &tools()).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn linked_destinations_and_predictable_temp_links_cannot_redirect_import() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let root = private_fixture();
        let outside = root.join("outside");
        std::fs::write(&outside, "unchanged").unwrap();
        let target = root.join("settings.toml");
        symlink(&outside, &target).unwrap();
        let rules = vec![("allow", "Read".to_owned())];
        assert!(add_rules(&target, &rules).is_err());
        assert!(
            std::fs::symlink_metadata(&target)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        std::fs::remove_file(&target).unwrap();
        let old_temp = target.with_extension("toml.import-tmp");
        symlink(&outside, &old_temp).unwrap();
        assert_eq!(add_rules(&target, &rules).unwrap(), 1);
        assert_eq!(std::fs::read_to_string(&outside).unwrap(), "unchanged");
        assert!(
            std::fs::symlink_metadata(&old_temp)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(
            std::fs::metadata(&target).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let linked_parent = root.join("linked");
        symlink(&root, &linked_parent).unwrap();
        assert!(add_rules(&linked_parent.join("other.toml"), &rules).is_err());
        assert!(!root.join("other.toml").exists());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn malformed_existing_settings_are_preserved_without_echoing_content() {
        let root = private_fixture();
        let target = root.join("settings.toml");
        let original = "PRIVATE_SENTINEL = [ invalid";
        std::fs::write(&target, original).unwrap();
        let error = add_rules(&target, &[("allow", "Read".to_owned())]).unwrap_err();
        assert!(!error.contains("PRIVATE_SENTINEL"));
        assert_eq!(std::fs::read_to_string(target).unwrap(), original);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn malformed_untouched_permission_effects_block_additions() {
        let root = private_fixture();
        let target = root.join("settings.toml");
        for effect in ["allow", "ask", "deny"] {
            let receiving = if effect == "allow" { "deny" } else { "allow" };
            for malformed in ["false", "[1]", "[\"Read\", 1]"] {
                let original = format!("[permissions]\n{effect} = {malformed}\n");
                std::fs::write(&target, &original).unwrap();
                assert!(add_rules(&target, &[(receiving, "Read".to_owned())]).is_err());
                assert_eq!(std::fs::read_to_string(&target).unwrap(), original);
            }
        }
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn later_invalid_destination_blocks_every_target_before_import() {
        let root = private_fixture();
        let first_source = root.join("user.json");
        let later_source = root.join("project.json");
        for source in [&first_source, &later_source] {
            std::fs::write(source, r#"{"permissions":{"allow":["Write"]}}"#).unwrap();
        }
        let first_target = root.join("user.toml");
        let later_target = root.join("project.toml");
        let first_bytes = "# preserve user settings\n[permissions]\ndeny = [\"Bash\"]\n";
        let later_bytes = "[permissions]\ndeny = [1]\n";
        std::fs::write(&first_target, first_bytes).unwrap();
        std::fs::write(&later_target, later_bytes).unwrap();
        let result = import_sources(
            vec![
                ("user", first_source, first_target.clone()),
                ("project", later_source, later_target.clone()),
            ],
            &tools(),
            true,
        );
        assert!(result.is_err());
        assert_eq!(std::fs::read_to_string(first_target).unwrap(), first_bytes);
        assert_eq!(std::fs::read_to_string(later_target).unwrap(), later_bytes);
        assert!(!root.join(".permissions-import.lock").exists());
        assert!(!std::fs::read_dir(&root).unwrap().any(|entry| {
            entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".import-")
        }));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn shared_writable_destination_is_refused_without_creating_settings() {
        use std::os::unix::fs::PermissionsExt;
        let root = private_fixture();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(add_rules(&root.join("settings.toml"), &[("allow", "Read".to_owned())]).is_err());
        assert!(!root.join("settings.toml").exists());
        assert!(!root.join(".permissions-import.lock").exists());
        std::fs::remove_dir_all(root).unwrap();
    }
}
