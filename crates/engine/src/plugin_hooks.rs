//! Hooks that come with imported plugins, and run only when the operator names the plugin.
//!
//! An imported plugin is an immutable, verified copy. Its hooks are not part of the operator's own
//! configuration, so they never run on their own: `plugin_hooks = ["name"]` in the operator's
//! settings (never a project's) is what lets a plugin's command hooks run, and it can pin the copy
//! it means (`"name@8f3a1c9d"`). What cannot run as written, because ORBIT has nothing that does what
//! it asks (`asyncRewake`, a hook written for PowerShell, an event ORBIT does not have), is left out
//! and named, never run in a form that does something else.

use crate::hooks::{HookConfig, HookEvent, PluginOrigin};
use orbit_plugin_compat::{
    ActivePlugin, ComponentKind, DiagnosticSeverity, PluginComponent, PluginId, PluginStore,
    StoreScope,
};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

const KEY: &str = "plugin_hooks";
/// The most plugins the setting can name.
const MAX_NAMED: usize = 64;
/// How many lines a list in the setting may take.
const MAX_LIST_LINES: usize = 256;
const MAX_CACHED: usize = 16;

/// A plugin the operator named in `plugin_hooks`, and the digest prefix that pins its stored copy.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Allowed {
    pub name: String,
    pub pin: Option<String>,
}

/// What became of one plugin the operator named.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginHookReport {
    pub name: String,
    /// The stored copy's digest, when the plugin was found.
    pub digest: Option<String>,
    /// The hooks that run, as `Event` or `Event [matcher]`.
    pub active: Vec<String>,
    /// The hooks that do not, each as `Event: why`. A command is never shown.
    pub skipped: Vec<String>,
    /// Why none of the plugin's hooks run, when the plugin as a whole is not active.
    pub inactive: Option<String>,
}

/// The plugin hooks that run for this home, and what to tell the operator about the rest.
#[derive(Debug, Clone, Default)]
pub struct PluginHooks {
    pub hooks: Vec<HookConfig>,
    pub report: Vec<PluginHookReport>,
    /// Said once per run.
    pub problems: Vec<String>,
}

/// The plugins named in `plugin_hooks`, and what to tell the operator about the setting itself.
/// Only the operator's own settings count: `$ORBIT_HOME/settings.toml`, then the `--settings` file
/// (which adds to it for this run). A project's settings never do, so a repository cannot switch
/// a plugin's hooks on.
pub fn allowed(home: &Path) -> (Vec<Allowed>, Vec<String>) {
    if crate::bare_mode() {
        return (Vec::new(), Vec::new());
    }
    let user = std::fs::read_to_string(home.join("settings.toml")).ok();
    let extra = orbit_tools::executor::extra_settings_file()
        .filter(|file| !orbit_tools::executor::is_json(file))
        .and_then(|file| crate::hooks::read_bounded(&file));
    merge_allowed([user, extra].into_iter().flatten())
}

/// What several settings files name, together: a plugin named in both counts once, and at most
/// `MAX_NAMED` plugins count in all, which is said.
pub(crate) fn merge_allowed(
    texts: impl IntoIterator<Item = String>,
) -> (Vec<Allowed>, Vec<String>) {
    let mut named: Vec<Allowed> = Vec::new();
    let mut problems = Vec::new();
    for text in texts {
        let (list, said) = allowed_from(&text);
        for entry in list {
            if !named.contains(&entry) {
                named.push(entry);
            }
        }
        problems.extend(said);
    }
    if named.len() > MAX_NAMED {
        named.truncate(MAX_NAMED);
        problems.push(format!(
            "{KEY} names more than {MAX_NAMED} plugins between the settings files; the first {MAX_NAMED} count"
        ));
    }
    (named, problems)
}

/// What one settings file says. Like `claude_compat`, the key counts only above the first
/// `[table]`: TOML puts a key below one inside that table.
pub(crate) fn allowed_from(text: &str) -> (Vec<Allowed>, Vec<String>) {
    let lines: Vec<&str> = text.lines().collect();
    let (mut at_top, mut under_table, mut found) = (true, false, None);
    let mut index = 0;
    while index < lines.len() {
        let line = lines[index].trim();
        index += 1;
        if line.starts_with('[') {
            at_top = false;
            continue;
        }
        let Some((name, rest)) = line.split_once('=') else {
            continue;
        };
        if name.trim() != KEY {
            continue;
        }
        if !at_top {
            under_table = true;
            continue;
        }
        let mut raw = rest.trim().to_owned();
        // A list may run over several lines: take lines up to the one that closes it.
        if raw.starts_with('[') && !list_closed(&raw) {
            for _ in 0..MAX_LIST_LINES {
                let Some(next) = lines.get(index) else { break };
                index += 1;
                raw.push('\n');
                raw.push_str(next);
                if list_closed(&raw) {
                    break;
                }
            }
        }
        found = Some(raw);
    }
    let mut problems = Vec::new();
    let Some(raw) = found else {
        if under_table {
            problems.push(format!(
                "{KEY} is under a [table] in settings.toml, where it is not read; put it above the first [table]"
            ));
        }
        return (Vec::new(), problems);
    };
    let must_be = format!(
        "{KEY} must be a list of plugin names, as in {KEY} = [\"hookify\"]; no plugin's hooks run from it"
    );
    let parsed = (raw.len() <= 16 * 1024)
        .then(|| toml::from_str::<toml::Table>(&format!("{KEY} = {raw}")).ok())
        .flatten()
        .and_then(|table| table.get(KEY).cloned());
    let Some(toml::Value::Array(items)) = parsed else {
        problems.push(must_be);
        return (Vec::new(), problems);
    };
    let mut list: Vec<Allowed> = Vec::new();
    let mut not_text = false;
    for item in &items {
        let toml::Value::String(entry) = item else {
            not_text = true;
            continue;
        };
        match entry_of(entry) {
            Some(entry) => {
                if !list.contains(&entry) {
                    list.push(entry);
                }
            }
            None => problems.push(format!(
                "{KEY}: \"{}\" is not a plugin name (letters, digits and - _ . only, 64 at most; an @ and 8 to 64 hex digits pin the stored copy); it is ignored",
                shown(entry)
            )),
        }
    }
    if not_text {
        problems.push(must_be);
    }
    if list.len() > MAX_NAMED {
        list.truncate(MAX_NAMED);
        problems.push(format!(
            "{KEY} names more than {MAX_NAMED} plugins; the first {MAX_NAMED} count"
        ));
    }
    (list, problems)
}

/// Is there a `]` in `raw`, outside quotes and comments, that ends the list it starts?
fn list_closed(raw: &str) -> bool {
    let (mut quoted, mut escaped, mut comment) = (false, false, false);
    for c in raw.chars() {
        if comment {
            comment = c != '\n';
        } else if quoted {
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                quoted = false;
            }
        } else {
            match c {
                '"' => quoted = true,
                '#' => comment = true,
                ']' => return true,
                _ => {}
            }
        }
    }
    false
}

fn entry_of(entry: &str) -> Option<Allowed> {
    let (name, pin) = match entry.split_once('@') {
        Some((name, pin)) => (name, Some(pin.to_ascii_lowercase())),
        None => (entry, None),
    };
    let plain = !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
        && name.as_bytes()[0].is_ascii_alphanumeric()
        && name.as_bytes()[name.len() - 1].is_ascii_alphanumeric()
        && !name.contains("..");
    let pinned = pin.as_ref().is_none_or(|pin| {
        (8..=64).contains(&pin.len()) && pin.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    });
    (plain && pinned).then(|| Allowed {
        name: name.to_owned(),
        pin,
    })
}

/// An entry of the operator's, short enough to put in a sentence.
fn shown(entry: &str) -> String {
    entry.chars().filter(|c| !c.is_control()).take(40).collect()
}

type CacheKey = (PathBuf, Vec<Allowed>, String);

static CACHE: Mutex<Option<HashMap<CacheKey, PluginHooks>>> = Mutex::new(None);

/// The command hooks of the plugins the operator named, resolved once per store revision.
///
/// The store verifies a whole package every time it loads one, and hooks are loaded on every tool
/// call, so a resolution is kept until the store's revision, which is cheap to read and moves
/// with every import, upgrade, enable, disable and remove, says something changed. Only user-scope
/// plugins count: the folder the store is opened on is never a project's.
pub fn resolve(home: &Path) -> PluginHooks {
    let (named, setting_problems) = allowed(home);
    let mut resolved = PluginHooks {
        problems: setting_problems,
        ..PluginHooks::default()
    };
    if named.is_empty() {
        return resolved;
    }
    let store = match PluginStore::open(home, Path::new("/"), false) {
        Ok(store) => store,
        Err(error) => {
            return all_inactive(
                resolved,
                &named,
                &format!("the plugin store could not be opened ({})", error.code),
            );
        }
    };
    let revision = match store.current_revision() {
        Ok(revision) => revision,
        Err(error) => {
            return all_inactive(
                resolved,
                &named,
                &format!("the plugin store could not be read ({})", error.code),
            );
        }
    };
    let key: CacheKey = (home.to_path_buf(), named.clone(), revision);
    if let Ok(cache) = CACHE.lock()
        && let Some(kept) = cache.as_ref().and_then(|cache| cache.get(&key))
    {
        let mut kept = kept.clone();
        kept.problems.splice(0..0, resolved.problems);
        return kept;
    }
    let names: Vec<&str> = named.iter().map(|entry| entry.name.as_str()).collect();
    let active = store.active_named(&names);
    let mut fresh = PluginHooks::default();
    for entry in &named {
        let found = active.as_ref().ok().and_then(|active| {
            active.plugins.iter().find(|candidate| {
                candidate.plugin.id.name == entry.name
                    && candidate.plugin.id.scope == StoreScope::User
            })
        });
        let report = match found {
            Some(plugin) => activate(entry, plugin, &mut fresh),
            None => PluginHookReport {
                name: entry.name.clone(),
                digest: None,
                active: Vec::new(),
                skipped: Vec::new(),
                inactive: Some(why_absent(&store, &entry.name)),
            },
        };
        if let Some(inactive) = &report.inactive {
            fresh.problems.push(format!(
                "plugin {}: its hooks do not run: {inactive}",
                entry.name
            ));
        }
        fresh.report.push(report);
    }
    if let Ok(mut cache) = CACHE.lock() {
        let cache = cache.get_or_insert_with(HashMap::new);
        if cache.len() >= MAX_CACHED {
            cache.clear();
        }
        cache.insert(key, fresh.clone());
    }
    fresh.problems.splice(0..0, resolved.problems.drain(..));
    fresh
}

fn all_inactive(mut resolved: PluginHooks, named: &[Allowed], why: &str) -> PluginHooks {
    for entry in named {
        resolved.report.push(PluginHookReport {
            name: entry.name.clone(),
            digest: None,
            active: Vec::new(),
            skipped: Vec::new(),
            inactive: Some(why.to_owned()),
        });
    }
    resolved
        .problems
        .push(format!("plugin hooks do not run: {why}"));
    resolved
}

/// Why a plugin the operator named is not among the active ones.
fn why_absent(store: &PluginStore, name: &str) -> String {
    match store.status(&PluginId {
        name: name.to_owned(),
        scope: StoreScope::User,
    }) {
        Ok(None) => "it is not imported at user scope (orbit plugin import PATH)".to_owned(),
        Ok(Some(plugin)) if !plugin.enabled => {
            "it is not enabled (orbit plugin enable NAME)".to_owned()
        }
        Ok(Some(_)) => "its stored copy did not verify".to_owned(),
        Err(error) => format!(
            "its stored copy did not verify ({}){}",
            error.code,
            if matches!(
                error.code.as_str(),
                "store_file_unsafe" | "store_package_tampered"
            ) {
                ": something changed files inside it (see \"A damaged stored copy\" in docs/integrations.md)"
            } else {
                ""
            }
        ),
    }
}

/// The hooks of one plugin that is active and, if pinned, the pinned copy.
fn activate(entry: &Allowed, plugin: &ActivePlugin, into: &mut PluginHooks) -> PluginHookReport {
    let digest = plugin.plugin.digest.clone();
    let mut report = PluginHookReport {
        name: entry.name.clone(),
        digest: Some(digest.clone()),
        active: Vec::new(),
        skipped: Vec::new(),
        inactive: None,
    };
    if let Some(pin) = &entry.pin
        && !digest.starts_with(pin.as_str())
    {
        report.inactive = Some(format!(
            "its stored copy has digest {}…, which is not the pinned {pin}",
            &digest[..digest.len().min(8)]
        ));
        return report;
    }
    let origin = PluginOrigin {
        name: entry.name.clone(),
        root: plugin.root.clone(),
        data: plugin.data_root.clone(),
    };
    let mut hooks: Vec<(usize, &PluginComponent)> = plugin
        .plugin
        .components
        .iter()
        .filter(|component| matches!(component.kind, ComponentKind::Hook(_)))
        .map(|component| {
            let ordinal = component
                .id
                .rsplit(':')
                .next()
                .and_then(|text| text.parse().ok())
                .unwrap_or(usize::MAX);
            (ordinal, component)
        })
        .collect();
    // Declaration order, which the component ids' sort order is not once there are ten of them.
    hooks.sort_by_key(|(ordinal, _)| *ordinal);
    for (_, component) in hooks {
        let ComponentKind::Hook(spec) = &component.kind else {
            continue;
        };
        match hook_of(plugin, component, &origin) {
            Ok(hook) => {
                report.active.push(match &hook.matcher {
                    Some(matcher) => format!("{} [{matcher}]", hook.event),
                    None => hook.event.clone(),
                });
                into.hooks.push(hook);
            }
            Err(why) => report.skipped.push(format!("{}: {why}", spec.event)),
        }
    }
    report
}

/// One hook component as a hook that runs, or why it does not.
fn hook_of(
    plugin: &ActivePlugin,
    component: &PluginComponent,
    origin: &PluginOrigin,
) -> Result<HookConfig, String> {
    let ComponentKind::Hook(spec) = &component.kind else {
        return Err("not a hook".into());
    };
    let handler = component.metadata.get("handler");
    let flag = |key: &str| {
        handler
            .and_then(|handler| handler.get(key))
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false)
    };
    let word = |key: &str| {
        handler
            .and_then(|handler| handler.get(key))
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned)
    };
    if flag("asyncRewake") {
        return Err("asyncRewake wakes the model when a background hook finishes; ORBIT has nothing that does that, and running it as a plain hook would drop what it found".into());
    }
    if let Some(shell) = word("shell").filter(|shell| !matches!(shell.as_str(), "bash" | "sh")) {
        return Err(format!(
            "written for {shell}, and ORBIT runs hooks with bash"
        ));
    }
    let event: HookEvent = spec
        .event
        .parse()
        .map_err(|_| format!("ORBIT has no {} event", spec.event))?;
    if flag("once")
        && !matches!(
            event,
            HookEvent::SessionStart | HookEvent::SessionEnd | HookEvent::Setup
        )
    {
        return Err("`once` (run once per session) is not supported on this event".into());
    }
    let component_error = plugin.plugin.diagnostics.iter().any(|diagnostic| {
        diagnostic.severity == DiagnosticSeverity::Error
            && diagnostic.component_id.as_deref() == Some(component.id.as_str())
    });
    if component_error {
        return Err("it has fields that are not understood, so it is not run".into());
    }
    let command = spec
        .command
        .clone()
        .filter(|command| !command.trim().is_empty())
        .ok_or_else(|| "it has no command".to_owned())?;
    Ok(HookConfig {
        event: spec.event.clone(),
        command: written_out(&command, origin),
        timeout_secs: spec.timeout_secs.map(|secs| secs.clamp(1, 600)),
        matcher: spec.matcher.clone().filter(|matcher| !matcher.is_empty()),
        condition: word("if").filter(|condition| !condition.trim().is_empty()),
        run_async: flag("async"),
        http: None,
        handler: None,
        origin: Some(origin.clone()),
    })
}

/// `${CLAUDE_PLUGIN_ROOT}` and `${CLAUDE_PLUGIN_DATA}` written out in the command, as Claude Code
/// does before it runs one, so they work inside single quotes too. A folder with anything in its
/// name that a shell would read differently is left to the environment variable.
fn written_out(command: &str, origin: &PluginOrigin) -> String {
    let plain = |path: &Path| {
        path.to_str().is_some_and(|text| {
            text.bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'.' | b'-' | b'_'))
        })
    };
    let mut command = command.to_owned();
    for (name, path) in [
        ("CLAUDE_PLUGIN_ROOT", &origin.root),
        ("CLAUDE_PLUGIN_DATA", &origin.data),
    ] {
        if plain(path) {
            command = command.replace(&format!("${{{name}}}"), path.to_str().unwrap_or_default());
        }
    }
    command
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hooks::{HookEvent, Hooks, blocked};
    use orbit_plugin_compat::{InspectOptions, PluginFormat, PluginId, PluginStore, StoreScope};
    use serde_json::json;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    struct Fixture {
        root: PathBuf,
        home: PathBuf,
        project: PathBuf,
    }

    impl Fixture {
        fn new(name: &str) -> Self {
            let root = std::env::temp_dir().join(format!(
                "orbit-plugin-hooks-{name}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            let (home, project) = (root.join("home"), root.join("project"));
            std::fs::create_dir_all(&home).unwrap();
            std::fs::create_dir_all(&project).unwrap();
            std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700)).unwrap();
            Self {
                root,
                home,
                project,
            }
        }

        fn store(&self, trusted: bool) -> PluginStore {
            PluginStore::open(&self.home, &self.project, trusted).unwrap()
        }

        /// Import a Claude plugin that has these files and this `hooks/hooks.json`, enabled.
        fn plugin(&self, name: &str, hooks: &str, files: &[(&str, &str, u32)]) -> String {
            self.plugin_in(name, hooks, files, StoreScope::User)
        }

        fn plugin_in(
            &self,
            name: &str,
            hooks: &str,
            files: &[(&str, &str, u32)],
            scope: StoreScope,
        ) -> String {
            let source = self.root.join(format!("source-{name}-{scope:?}"));
            let write = |path: &str, text: &str, mode: u32| {
                let target = source.join(path);
                std::fs::create_dir_all(target.parent().unwrap()).unwrap();
                std::fs::write(&target, text).unwrap();
                std::fs::set_permissions(&target, std::fs::Permissions::from_mode(mode)).unwrap();
            };
            write(
                ".claude-plugin/plugin.json",
                &format!(r#"{{"name":"{name}","description":"d"}}"#),
                0o644,
            );
            write("hooks/hooks.json", hooks, 0o644);
            for (path, text, mode) in files {
                write(path, text, *mode);
            }
            let receipt = self
                .store(true)
                .import(
                    &source,
                    &InspectOptions {
                        format: Some(PluginFormat::Claude),
                        ..InspectOptions::default()
                    },
                    scope,
                    true,
                )
                .unwrap();
            receipt.plugin.digest
        }

        fn settings(&self, text: &str) {
            std::fs::write(self.home.join("settings.toml"), text).unwrap();
        }

        fn package_root(&self, name: &str, digest: &str) -> PathBuf {
            self.home
                .join("plugins/portable/packages")
                .join(name)
                .join(digest)
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            // The stored copy is read-only.
            fn open(path: &Path) {
                if let Ok(meta) = std::fs::symlink_metadata(path)
                    && meta.is_dir()
                {
                    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700));
                    if let Ok(entries) = std::fs::read_dir(path) {
                        for entry in entries.flatten() {
                            open(&entry.path());
                        }
                    }
                }
            }
            open(&self.root);
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    const ONE_HOOK: &str =
        r#"{"hooks":{"PreToolUse":[{"hooks":[{"type":"command","command":"echo hi"}]}]}}"#;

    #[test]
    fn nothing_runs_unless_the_operator_names_the_plugin() {
        let fixture = Fixture::new("named");
        fixture.plugin("hookify", ONE_HOOK, &[]);
        assert!(resolve(&fixture.home).hooks.is_empty(), "no setting");
        fixture.settings("claude_compat = false\n");
        assert!(
            resolve(&fixture.home).hooks.is_empty(),
            "other keys do not name it"
        );
        fixture.settings("plugin_hooks = [\"someone-else\"]\n");
        assert!(resolve(&fixture.home).hooks.is_empty(), "another name");
        fixture.settings("plugin_hooks = [\"hookify\"]\n");
        let resolved = resolve(&fixture.home);
        assert_eq!(resolved.hooks.len(), 1, "{resolved:?}");
        assert_eq!(resolved.hooks[0].event, "PreToolUse");
        assert_eq!(resolved.report.len(), 1);
        assert_eq!(resolved.report[0].name, "hookify");
        assert!(
            resolved.report[0].inactive.is_none(),
            "{:?}",
            resolved.report
        );
        assert_eq!(resolved.report[0].active, ["PreToolUse"]);
    }

    #[test]
    fn a_hooks_matcher_timeout_condition_and_async_flag_are_kept_and_its_root_is_the_stored_copy() {
        let fixture = Fixture::new("mapping");
        let digest = fixture.plugin(
            "guard",
            r#"{"hooks":{
              "PreToolUse":[{"matcher":"Write|Edit","hooks":[
                {"type":"command","command":"\"${CLAUDE_PLUGIN_ROOT}/scripts/guard\" a","timeout":7,"if":"Bash(git *)","async":true,
                 "commandWindows":"x","powershell":"y","shell":"bash","statusMessage":"s"}]}],
              "Stop":[{"hooks":[{"type":"command","command":"echo stop"}]}]}}"#,
            &[("scripts/guard", "#!/bin/sh\necho guard\n", 0o755)],
        );
        fixture.settings("plugin_hooks = [\"guard\"]\n");
        let resolved = resolve(&fixture.home);
        assert_eq!(resolved.hooks.len(), 2, "{:?}", resolved.report);
        let first = &resolved.hooks[0];
        assert_eq!(first.event, "PreToolUse");
        assert_eq!(first.matcher.as_deref(), Some("Write|Edit"));
        assert_eq!(first.timeout_secs, Some(7));
        assert_eq!(first.condition.as_deref(), Some("Bash(git *)"));
        assert!(first.run_async);
        let origin = first
            .origin
            .as_ref()
            .expect("a plugin hook says where it is from");
        assert_eq!(origin.name, "guard");
        assert_eq!(origin.root, fixture.package_root("guard", &digest));
        assert!(origin.root.join("scripts/guard").is_file());
        assert!(origin.data.ends_with("data/guard"), "{:?}", origin.data);
        assert!(
            first.command.contains(origin.root.to_str().unwrap())
                && !first.command.contains("${CLAUDE_PLUGIN_ROOT}"),
            "the variable is written out the way Claude Code does: {}",
            first.command
        );
        let second = &resolved.hooks[1];
        assert_eq!(
            (second.event.as_str(), second.matcher.as_deref()),
            ("Stop", None)
        );
        assert_eq!(second.timeout_secs, None);
        assert!(!second.run_async && second.condition.is_none());
    }

    #[test]
    fn the_hooks_of_one_event_keep_the_order_they_were_declared_in() {
        let fixture = Fixture::new("order");
        let handlers: Vec<String> = (0..12)
            .map(|n| format!(r#"{{"type":"command","command":"echo {n}"}}"#))
            .collect();
        fixture.plugin(
            "many",
            &format!(
                r#"{{"hooks":{{"PreToolUse":[{{"hooks":[{}]}}]}}}}"#,
                handlers.join(",")
            ),
            &[],
        );
        fixture.settings("plugin_hooks = [\"many\"]\n");
        let commands: Vec<_> = resolve(&fixture.home)
            .hooks
            .iter()
            .map(|hook| hook.command.clone())
            .collect();
        let expected: Vec<_> = (0..12).map(|n| format!("echo {n}")).collect();
        assert_eq!(commands, expected);
    }

    #[test]
    fn a_hook_that_needs_what_orbit_does_not_have_is_named_and_not_run() {
        let fixture = Fixture::new("skips");
        fixture.plugin(
            "mixed",
            r#"{"hooks":{
              "PreToolUse":[{"hooks":[
                {"type":"command","command":"echo plain"},
                {"type":"command","command":"echo rewake","asyncRewake":true,"rewakeMessage":"m","rewakeSummary":"s"},
                {"type":"command","command":"echo ps","shell":"powershell"},
                {"type":"command","command":"echo once","once":true},
                {"type":"command","command":"echo extra","rewakeMessage":"only the message"}]}],
              "SessionStart":[{"hooks":[{"type":"command","command":"echo start","once":true}]}],
              "Stop":[{"hooks":[{"type":"command","command":"echo stop-once","once":true}]}],
              "Weird":[{"hooks":[{"type":"command","command":"echo weird"}]}]}}"#,
            &[],
        );
        fixture.settings("plugin_hooks = [\"mixed\"]\n");
        let resolved = resolve(&fixture.home);
        let mut running: Vec<_> = resolved.hooks.iter().map(|h| h.command.as_str()).collect();
        running.sort();
        assert_eq!(
            running,
            ["echo plain", "echo start"],
            "{:?}",
            resolved.report
        );
        let report = &resolved.report[0];
        assert!(report.inactive.is_none());
        assert_eq!(report.skipped.len(), 6, "{:?}", report.skipped);
        let said = report.skipped.join(" | ");
        for part in [
            "asyncRewake",
            "powershell",
            "once",
            "Weird",
            "not understood",
        ] {
            assert!(said.contains(part), "{part} in {said}");
        }
        assert!(
            report.skipped.iter().all(|s| !s.contains("echo ")),
            "no command text is shown: {said}"
        );
    }

    #[test]
    fn a_digest_pin_must_match_the_stored_copy() {
        let fixture = Fixture::new("pin");
        let digest = fixture.plugin("hookify", ONE_HOOK, &[]);
        fixture.settings(&format!("plugin_hooks = [\"hookify@{}\"]\n", &digest[..8]));
        assert_eq!(resolve(&fixture.home).hooks.len(), 1, "the right prefix");
        fixture.settings(&format!("plugin_hooks = [\"hookify@{}\"]\n", digest));
        assert_eq!(resolve(&fixture.home).hooks.len(), 1, "the whole digest");
        fixture.settings("plugin_hooks = [\"hookify@00000000\"]\n");
        let wrong = resolve(&fixture.home);
        assert!(wrong.hooks.is_empty());
        let inactive = wrong.report[0].inactive.clone().expect("said why");
        assert!(inactive.contains("digest"), "{inactive}");
        assert!(
            wrong
                .problems
                .iter()
                .any(|p| p.contains("hookify") && p.contains("digest")),
            "{:?}",
            wrong.problems
        );
        // A pin too short to mean anything is not taken.
        fixture.settings("plugin_hooks = [\"hookify@abc\"]\n");
        let (named, problems) = allowed(&fixture.home);
        assert!(named.is_empty(), "{named:?}");
        assert!(
            problems.iter().any(|p| p.contains("hookify@abc")),
            "{problems:?}"
        );
    }

    #[test]
    fn a_plugin_that_is_missing_disabled_damaged_or_only_in_a_project_is_reported_not_run() {
        let fixture = Fixture::new("states");
        fixture.plugin("hookify", ONE_HOOK, &[]);
        let digest = fixture.plugin("damaged", ONE_HOOK, &[("LICENSE", "text", 0o644)]);
        fixture.plugin("off", ONE_HOOK, &[]);
        fixture.plugin_in("projectonly", ONE_HOOK, &[], StoreScope::Project);
        let store = fixture.store(true);
        let revision = store.current_revision().unwrap();
        store
            .disable(
                &PluginId {
                    name: "off".into(),
                    scope: StoreScope::User,
                },
                &revision,
            )
            .unwrap();
        let license = fixture.package_root("damaged", &digest).join("LICENSE");
        std::fs::set_permissions(&license, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::write(&license, "tampered").unwrap();
        fixture.settings(
            "plugin_hooks = [\"hookify\", \"ghost\", \"off\", \"damaged\", \"projectonly\"]\n",
        );
        let resolved = resolve(&fixture.home);
        assert_eq!(
            resolved.hooks.len(),
            1,
            "only hookify runs: {:?}",
            resolved.report
        );
        let why = |name: &str| {
            resolved
                .report
                .iter()
                .find(|r| r.name == name)
                .unwrap_or_else(|| panic!("{name} is reported"))
                .inactive
                .clone()
        };
        assert!(why("hookify").is_none());
        for name in ["ghost", "off", "damaged", "projectonly"] {
            let text = why(name).unwrap_or_else(|| panic!("{name} is said not to run"));
            assert!(!text.is_empty(), "{name}");
            assert!(
                resolved.problems.iter().any(|p| p.contains(name)),
                "{name} is told to the operator: {:?}",
                resolved.problems
            );
        }
        assert!(
            why("damaged").unwrap().contains("verify"),
            "{:?}",
            why("damaged")
        );
        assert!(
            why("damaged")
                .unwrap()
                .contains("something changed files inside it"),
            "a changed copy says so and points at the way back: {:?}",
            why("damaged")
        );
        assert!(why("off").unwrap().contains("enabled"), "{:?}", why("off"));
    }

    #[test]
    fn only_the_operators_own_settings_can_name_a_plugin() {
        let fixture = Fixture::new("scope");
        fixture.plugin("hookify", ONE_HOOK, &[]);
        std::fs::create_dir_all(fixture.project.join(".orbit")).unwrap();
        std::fs::write(
            fixture.project.join(".orbit/settings.toml"),
            "plugin_hooks = [\"hookify\"]\n",
        )
        .unwrap();
        let hooks = Hooks::inspect(&fixture.home, Some(&fixture.project));
        assert!(
            hooks.hooks.iter().all(|h| h.origin.is_none()),
            "a repository cannot switch a plugin's hooks on"
        );
        fixture.settings("plugin_hooks = [\"hookify\"]\n");
        let hooks = Hooks::inspect(&fixture.home, Some(&fixture.project));
        assert_eq!(hooks.hooks.iter().filter(|h| h.origin.is_some()).count(), 1);
    }

    #[test]
    fn a_plugins_hook_is_listed_under_the_plugin_it_came_with() {
        use crate::hooks::HookSource;
        let fixture = Fixture::new("sourced");
        fixture.plugin("hookify", ONE_HOOK, &[]);
        fixture.settings("plugin_hooks = [\"hookify\"]\n");
        let sourced = Hooks::inspect_sourced(&fixture.home, None);
        assert_eq!(
            sourced
                .iter()
                .filter(|(source, _)| *source == HookSource::Plugin("hookify".into()))
                .count(),
            1
        );
        // Only a plugin's own hook carries that source.
        assert!(
            sourced
                .iter()
                .all(|(source, hook)| matches!(source, HookSource::Plugin(_))
                    == hook.origin.is_some())
        );
    }

    #[test]
    fn the_setting_is_read_from_the_top_of_a_settings_file_and_its_faults_are_named() {
        let named = |text: &str| allowed_in(text);
        let (list, problems) = named("plugin_hooks = [\"a\", \"b@12345678\"]\n");
        assert_eq!(
            list,
            [
                Allowed {
                    name: "a".into(),
                    pin: None
                },
                Allowed {
                    name: "b".into(),
                    pin: Some("12345678".into())
                }
            ]
        );
        assert!(problems.is_empty());
        // A list over several lines, with comments and a trailing comma.
        let (list, problems) = named(
            "stop_hook_max_continuations = 5\nplugin_hooks = [\n  \"a\", # first\n  \"b\",\n]\nclaude_compat = true\n",
        );
        assert_eq!(list.len(), 2, "{problems:?}");
        assert!(problems.is_empty(), "{problems:?}");
        // Not a list, or not names.
        for text in [
            "plugin_hooks = \"a\"\n",
            "plugin_hooks = 3\n",
            "plugin_hooks = [1]\n",
            "plugin_hooks = [\"a\", 3]\n",
        ] {
            let (list, problems) = named(text);
            assert!(list.is_empty() || text.contains("\"a\", 3"), "{text}");
            assert!(
                problems.iter().any(|p| p.contains("plugin_hooks must be")),
                "{text}: {problems:?}"
            );
        }
        // Bad names are dropped one by one and named; good ones still count.
        let (list, problems) =
            named("plugin_hooks = [\"good\", \"bad name\", \"*\", \"../x\", \"\"]\n");
        assert_eq!(
            list,
            [Allowed {
                name: "good".into(),
                pin: None
            }]
        );
        assert_eq!(problems.len(), 4, "{problems:?}");
        assert!(
            problems.iter().any(|p| p.contains('*')),
            "no wildcard: {problems:?}"
        );
        // Twice is once; an empty list is not a fault; too many are cut.
        assert_eq!(named("plugin_hooks = [\"a\", \"a\"]\n").0.len(), 1);
        let (list, problems) = named("plugin_hooks = []\n");
        assert!(list.is_empty() && problems.is_empty());
        let many = format!(
            "plugin_hooks = [{}]\n",
            (0..70)
                .map(|n| format!("\"p{n}\""))
                .collect::<Vec<_>>()
                .join(", ")
        );
        let (list, problems) = named(&many);
        assert_eq!(list.len(), 64);
        assert!(problems.iter().any(|p| p.contains("64")), "{problems:?}");
        // Under a table it is not read, and the operator is told.
        let (list, problems) = named("[sandbox]\nplugin_hooks = [\"a\"]\n");
        assert!(list.is_empty());
        assert!(
            problems.iter().any(|p| p.contains("under a [table]")),
            "{problems:?}"
        );
        // Nothing is said about a file that does not mention it.
        assert_eq!(named("claude_compat = true\n"), (Vec::new(), Vec::new()));
    }

    #[test]
    fn the_resolution_is_kept_until_the_store_changes() {
        let fixture = Fixture::new("cache");
        let digest = fixture.plugin("hookify", ONE_HOOK, &[("LICENSE", "text", 0o644)]);
        fixture.settings("plugin_hooks = [\"hookify\"]\n");
        assert_eq!(resolve(&fixture.home).hooks.len(), 1);
        // The stored copy is damaged behind the store's back: the cached answer stands, because
        // the store's revision, which reading is cheap, has not moved. (Verifying again on every
        // tool call would read every named package every time.)
        let license = fixture.package_root("hookify", &digest).join("LICENSE");
        std::fs::set_permissions(&license, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::write(&license, "tampered").unwrap();
        assert_eq!(resolve(&fixture.home).hooks.len(), 1, "kept");
        // Any change to the store is seen at once.
        let store = fixture.store(true);
        let revision = store.current_revision().unwrap();
        store
            .disable(
                &PluginId {
                    name: "hookify".into(),
                    scope: StoreScope::User,
                },
                &revision,
            )
            .unwrap();
        assert!(resolve(&fixture.home).hooks.is_empty(), "disabled");
    }

    #[test]
    fn a_plugin_hook_runs_from_the_stored_copy_with_its_folders_and_can_block() {
        let fixture = Fixture::new("run");
        fixture.plugin(
            "echoer",
            r#"{"hooks":{"PreToolUse":[
              {"matcher":"Bash","hooks":[{"type":"command","command":"printf '%s|%s|%s|' \"$CLAUDE_PLUGIN_ROOT\" \"$CLAUDE_PLUGIN_DATA\" '${CLAUDE_PLUGIN_ROOT}'; \"${CLAUDE_PLUGIN_ROOT}/scripts/run.sh\" arg"}]},
              {"matcher":"Write","hooks":[{"type":"command","command":"echo refused >&2; exit 2"}]}]}}"#,
            &[("scripts/run.sh", "#!/bin/sh\necho \"ran $1\"\n", 0o755)],
        );
        fixture.settings("plugin_hooks = [\"echoer\"]\n");
        let hooks = Hooks::inspect(&fixture.home, None);
        let origin = hooks
            .hooks
            .iter()
            .find_map(|h| h.origin.clone())
            .expect("a plugin hook");
        assert!(!origin.data.exists(), "resolving creates nothing");
        let outcomes = hooks.fire(HookEvent::PreToolUse, &json!({"tool":"Bash"}));
        assert_eq!(outcomes.len(), 1, "{outcomes:?}");
        let parts: Vec<&str> = outcomes[0].stdout.trim_end().split('|').collect();
        assert_eq!(parts[0], origin.root.to_str().unwrap());
        assert_eq!(parts[1], origin.data.to_str().unwrap());
        assert_eq!(
            parts[2],
            origin.root.to_str().unwrap(),
            "written out inside quotes"
        );
        assert_eq!(
            parts[3], "ran arg",
            "an executable file of the stored copy runs"
        );
        let mode = std::fs::metadata(&origin.data)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            mode, 0o700,
            "private state folder, made when the hook first ran"
        );
        let blocking = hooks.fire(HookEvent::PreToolUse, &json!({"tool":"Write"}));
        assert!(
            blocked(&blocking).is_some_and(|text| text.contains("refused")),
            "{blocking:?}"
        );
    }

    #[test]
    fn a_plugin_hook_cannot_write_bytecode_into_its_stored_copy() {
        // A Python hook that imports a file next to it writes `__pycache__` there, which changes the
        // verified copy: the next run would find it damaged and run none of the plugin's hooks. The
        // interpreter is told to put its bytecode in the plugin's own state folder instead.
        let fixture = Fixture::new("bytecode");
        fixture.plugin(
            "pyhook",
            r#"{"hooks":{"PreToolUse":[{"hooks":[{"type":"command","command":"printf '%s' \"$PYTHONPYCACHEPREFIX\""}]}]}}"#,
            &[],
        );
        fixture.plugin("pyhook2", ONE_HOOK, &[]);
        fixture.settings("plugin_hooks = [\"pyhook\"]\n");
        let hooks = Hooks::inspect(&fixture.home, None);
        let origin = hooks.hooks[0].origin.clone().expect("a plugin hook");
        let outcomes = hooks.fire(HookEvent::PreToolUse, &json!({"tool":"Bash"}));
        assert_eq!(
            outcomes[0].stdout,
            origin.data.join("pycache").to_str().unwrap(),
            "{outcomes:?}"
        );
        // The operator's own hooks keep the environment the operator gave them.
        fixture.settings(
            "[[hooks]]\nevent = \"PreToolUse\"\ncommand = \"printf '%s' \\\"${PYTHONPYCACHEPREFIX:-none}\\\"\"\n",
        );
        let own = Hooks::inspect(&fixture.home, None)
            .fire(HookEvent::PreToolUse, &json!({"tool":"Bash"}));
        assert_eq!(own[0].stdout, "none", "{own:?}");
    }

    #[test]
    fn two_settings_files_add_up_to_at_most_sixty_four_plugins_and_it_is_said() {
        let names = |from: usize, to: usize| {
            format!(
                "plugin_hooks = [{}]\n",
                (from..to)
                    .map(|n| format!("\"p{n}\""))
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        };
        // 0..70 between them, with 30..40 named in both: seventy plugins, sixty-four count.
        let (merged, problems) = merge_allowed([names(0, 40), names(30, 70)]);
        assert_eq!(merged.len(), 64);
        assert_eq!(merged[0].name, "p0");
        assert_eq!(merged[63].name, "p63", "the first sixty-four, in order");
        assert!(
            problems.iter().any(|p| p.contains("more than 64")),
            "{problems:?}"
        );
        // Within the cap nothing is said, and a name in both files counts once.
        let (merged, problems) = merge_allowed([names(0, 40), names(20, 60)]);
        assert_eq!(merged.len(), 60);
        assert!(problems.is_empty(), "{problems:?}");
    }

    #[test]
    fn a_hooks_timeout_is_kept_but_bounded() {
        // The importer takes any positive number; a plugin must not be able to hold a tool call for a day.
        let fixture = Fixture::new("timeouts");
        fixture.plugin(
            "slow",
            r#"{"hooks":{"PreToolUse":[{"hooks":[
              {"type":"command","command":"echo short","timeout":7},
              {"type":"command","command":"echo long","timeout":86400},
              {"type":"command","command":"echo none"}]}]}}"#,
            &[],
        );
        fixture.settings("plugin_hooks = [\"slow\"]\n");
        let resolved = resolve(&fixture.home);
        let timeout = |command: &str| {
            resolved
                .hooks
                .iter()
                .find(|h| h.command == command)
                .unwrap_or_else(|| panic!("{command} runs"))
                .timeout_secs
        };
        assert_eq!(timeout("echo short"), Some(7));
        assert_eq!(timeout("echo long"), Some(600));
        assert_eq!(timeout("echo none"), None, "no timeout stays the default");
    }

    fn allowed_in(text: &str) -> (Vec<Allowed>, Vec<String>) {
        allowed_from(text)
    }
}
