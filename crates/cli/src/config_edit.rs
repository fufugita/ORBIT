//! Editing from inside the chat: `/memory add …` and `/config set …`.
//!
//! `/memory add <text>` appends one line to an instruction file the session
//! reads at its next prompt: the project's `ORBIT.md` by default,
//! `--user` for `$ORBIT_HOME/ORBIT.md`, `--local` for
//! `.orbit/ORBIT.local.md`. `/memory remove <text>` takes out the lines
//! that say exactly that. A file is created when it is not there; nothing
//! else in it changes.
//!
//! `/memory edit` and `/config edit` open the file in `$VISUAL` or
//! `$EDITOR`. The terminal chat hands its screen to the editor; the plain
//! chat runs it in place ([`plain_command`]), at a terminal only.
//!
//! `/config set <key> <value>` and `/config unset <key>` change the
//! top-level keys of `$ORBIT_HOME/settings.toml` that are single values:
//! `claude_compat`, `output_style`, `status_line`. Tables (`[permissions]`,
//! `[[hooks]]`) have their own commands. The file is edited as TOML, so
//! comments and everything else in it stay as they are, and it is replaced
//! in one step.

use std::path::{Path, PathBuf};

const MAX_MEMORY_LINE: usize = 2_000;
const MAX_MEMORY_FILE: u64 = 256 * 1024;

/// Which instruction file `/memory add` writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryScope {
    Project,
    Local,
    User,
}

impl MemoryScope {
    fn path(self, home: &Path, project: &Path) -> PathBuf {
        match self {
            Self::Project => project.join("ORBIT.md"),
            Self::Local => project.join(".orbit").join("ORBIT.local.md"),
            Self::User => home.join("ORBIT.md"),
        }
    }
}

/// `--user` / `--local` / `--project` at the front of the words, and what
/// follows it.
fn scoped(text: &str) -> (MemoryScope, &str) {
    let text = text.trim();
    for (flag, scope) in [
        ("--user", MemoryScope::User),
        ("--local", MemoryScope::Local),
        ("--project", MemoryScope::Project),
    ] {
        if let Some(rest) = text.strip_prefix(flag)
            && (rest.is_empty() || rest.starts_with(char::is_whitespace))
        {
            return (scope, rest.trim());
        }
    }
    (MemoryScope::Project, text)
}

/// One line of an instruction file: no line breaks or control characters,
/// bounded.
fn memory_line(text: &str) -> Result<String, String> {
    let line: String = text
        .chars()
        .map(|c| {
            if c == '\n' || c == '\r' || c == '\t' {
                ' '
            } else {
                c
            }
        })
        .filter(|c| !c.is_control())
        .collect();
    let line = line.trim().to_owned();
    if line.is_empty() {
        return Err("nothing to remember: /memory add <text>".into());
    }
    if line.chars().count() > MAX_MEMORY_LINE {
        return Err(format!(
            "a memory line is at most {MAX_MEMORY_LINE} characters"
        ));
    }
    Ok(line)
}

fn read_memory(path: &Path) -> Result<String, String> {
    match std::fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(String::new()),
        Err(error) => Err(format!("{}: {error}", path.display())),
        // A link could point the edit at any file the person can write.
        Ok(meta) if !meta.is_file() => Err(format!("{} is not a regular file", path.display())),
        Ok(meta) if meta.len() > MAX_MEMORY_FILE => {
            Err(format!("{} is too large to edit from here", path.display()))
        }
        Ok(_) => {
            std::fs::read_to_string(path).map_err(|error| format!("{}: {error}", path.display()))
        }
    }
}

/// Replace a file in one step: written beside it, then renamed over it.
fn replace(path: &Path, body: &str) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|error| format!("{}: {error}", parent.display()))?;
    }
    let mut name = path
        .file_name()
        .map(std::ffi::OsStr::to_os_string)
        .unwrap_or_default();
    name.push(".orbit-tmp");
    let temporary = path.with_file_name(name);
    let _ = std::fs::remove_file(&temporary);
    std::fs::write(&temporary, body)
        .and_then(|()| std::fs::rename(&temporary, path))
        .map_err(|error| {
            let _ = std::fs::remove_file(&temporary);
            format!("{}: {error}", path.display())
        })
}

/// `/memory edit [--user|--local]`: the instruction file to open in the
/// editor, created empty when it is not there yet, and the scope words to
/// report on it afterwards.
pub fn memory_edit_target(
    home: &Path,
    project: &Path,
    words: &str,
) -> Result<(PathBuf, &'static str), String> {
    let (scope, rest) = scoped(words);
    if !rest.is_empty() {
        return Err("usage: /memory edit [--user|--local|--project]".into());
    }
    let path = scope.path(home, project);
    // Refuses a link or anything else that is not a plain file.
    if read_memory(&path)?.is_empty() && std::fs::symlink_metadata(&path).is_err() {
        replace(&path, "")?;
    }
    Ok((
        path,
        match scope {
            MemoryScope::Project => "--project",
            MemoryScope::Local => "--local",
            MemoryScope::User => "--user",
        },
    ))
}

/// What `/memory edit` left behind, said once the editor has closed.
pub fn memory_edited(home: &Path, project: &Path, words: &str) -> String {
    let path = scoped(words).0.path(home, project);
    match read_memory(&path) {
        // The outcome first: a narrow conversation shows the start.
        Ok(body) => format!(
            "saved, {} · read from the next prompt · {}",
            match body.lines().count() {
                1 => "1 line".to_owned(),
                lines => format!("{lines} lines"),
            },
            path.display()
        ),
        Err(error) => error,
    }
}

/// `/config edit`: the settings file to open in the editor, created empty
/// when it is not there yet. A link to a file is opened as the file it
/// names: the home folder is the person's own, and settings kept by a
/// dotfile manager are links.
pub fn config_edit_target(home: &Path) -> Result<PathBuf, String> {
    let path = home.join("settings.toml");
    match std::fs::symlink_metadata(&path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => replace(&path, "")?,
        Err(error) => return Err(format!("{}: {error}", path.display())),
        Ok(_) => match std::fs::metadata(&path) {
            Ok(meta) if meta.is_file() => {}
            Ok(_) => return Err(format!("{} is not a file", path.display())),
            Err(error) => {
                return Err(format!(
                    "{} is a link that cannot be followed: {error}",
                    path.display()
                ));
            }
        },
    }
    Ok(path)
}

/// What `/config edit` left behind: whether the file still reads as TOML,
/// said once the editor has closed.
pub fn config_edited(home: &Path) -> Result<String, String> {
    let path = home.join("settings.toml");
    let text =
        std::fs::read_to_string(&path).map_err(|error| format!("{}: {error}", path.display()))?;
    match text.parse::<toml_edit::DocumentMut>() {
        Ok(_) => Ok(format!(
            "saved, valid TOML · some settings are read again at the next prompt, the status line and output style by the next session · {}",
            path.display()
        )),
        Err(error) => Err(format!(
            "not valid TOML now, so these settings are not applied: {} · /config edit opens it again · {}",
            error.to_string().lines().next().unwrap_or("syntax error"),
            path.display()
        )),
    }
}

/// `/memory add [--user|--local] <text>`.
pub fn memory_add(home: &Path, project: &Path, words: &str) -> Result<String, String> {
    let (scope, text) = scoped(words);
    let line = memory_line(text)?;
    let path = scope.path(home, project);
    let mut body = read_memory(&path)?;
    let entry = format!("- {line}");
    if body.lines().any(|known| known.trim() == entry) {
        return Ok(format!("{} already says that", path.display()));
    }
    if !body.is_empty() && !body.ends_with('\n') {
        body.push('\n');
    }
    body.push_str(&entry);
    body.push('\n');
    replace(&path, &body)?;
    Ok(format!(
        "added to {} · it is read from the next prompt · /memory remove takes it out",
        path.display()
    ))
}

/// `/memory remove [--user|--local] <text>`: the lines that say exactly
/// that, with or without the list dash.
pub fn memory_remove(home: &Path, project: &Path, words: &str) -> Result<String, String> {
    let (scope, text) = scoped(words);
    let line = memory_line(text)?;
    let path = scope.path(home, project);
    let body = read_memory(&path)?;
    let matches = |known: &str| {
        let known = known.trim();
        known == line
            || known
                .strip_prefix("- ")
                .is_some_and(|rest| rest.trim() == line)
    };
    let removed = body.lines().filter(|known| matches(known)).count();
    if removed == 0 {
        return Err(format!(
            "{} has no line that says exactly that",
            path.display()
        ));
    }
    let mut kept: String = body
        .lines()
        .filter(|known| !matches(known))
        .collect::<Vec<_>>()
        .join("\n");
    if !kept.is_empty() {
        kept.push('\n');
    }
    replace(&path, &kept)?;
    Ok(format!("removed {removed} line(s) from {}", path.display()))
}

/// A setting `/config set` may change, and what it accepts.
enum Setting {
    Flag,
    Text,
}

fn setting(key: &str) -> Option<Setting> {
    match key {
        "claude_compat" => Some(Setting::Flag),
        "output_style" | "status_line" => Some(Setting::Text),
        _ => None,
    }
}

const KEYS: &str = "claude_compat (true|false), output_style (a name), status_line (a command)";

fn load_settings(path: &Path) -> Result<toml_edit::DocumentMut, String> {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(error) => return Err(format!("{}: {error}", path.display())),
    };
    text.parse::<toml_edit::DocumentMut>().map_err(|error| {
        format!(
            "{} is not valid TOML and was left alone: {error}",
            path.display()
        )
    })
}

/// `/config set <key> <value…>`.
pub fn config_set(home: &Path, key: &str, value: &str) -> Result<String, String> {
    let kind = setting(key).ok_or_else(|| format!("/config set changes: {KEYS}"))?;
    let value = value.trim();
    let item = match kind {
        Setting::Flag => match value {
            "true" | "on" => toml_edit::value(true),
            "false" | "off" => toml_edit::value(false),
            _ => return Err(format!("{key} is true or false")),
        },
        Setting::Text => {
            let text = value.trim_matches('"');
            if text.is_empty() || text.chars().any(char::is_control) || text.len() > 1_000 {
                return Err(format!("{key} needs one line of text"));
            }
            toml_edit::value(text)
        }
    };
    let path = home.join("settings.toml");
    let mut document = load_settings(&path)?;
    // A top-level key must come before the first table: toml_edit places a
    // new one there. An existing one is changed where it is, keeping the
    // comment on its line.
    match (
        document
            .get_mut(key)
            .and_then(toml_edit::Item::as_value_mut),
        item.as_value(),
    ) {
        (Some(existing), Some(new)) => {
            let decor = existing.decor().clone();
            *existing = new.clone();
            *existing.decor_mut() = decor;
        }
        _ => document[key] = item,
    }
    replace(&path, &document.to_string())?;
    Ok(format!(
        "{key} = {} in {} · {}",
        document[key].to_string().trim(),
        path.display(),
        applies(key)
    ))
}

/// `/config unset <key>`.
pub fn config_unset(home: &Path, key: &str) -> Result<String, String> {
    setting(key).ok_or_else(|| format!("/config unset changes: {KEYS}"))?;
    let path = home.join("settings.toml");
    let mut document = load_settings(&path)?;
    if document.as_table_mut().remove(key).is_none() {
        return Ok(format!("{key} is not set in {}", path.display()));
    }
    replace(&path, &document.to_string())?;
    Ok(format!(
        "{key} removed from {} · {}",
        path.display(),
        applies(key)
    ))
}

fn applies(key: &str) -> &'static str {
    match key {
        "status_line" => "used by sessions started after this one",
        "output_style" => "used from the next session; /output-style changes this one",
        _ => "read again at the next prompt",
    }
}

/// Open `path` in `$VISUAL` or `$EDITOR` on this terminal and wait for it.
/// The setting may carry arguments ("code -w"); the path is a positional
/// parameter, never spliced into the command text.
fn run_editor(path: &Path) -> Result<(), String> {
    let editor = ["VISUAL", "EDITOR"]
        .iter()
        .find_map(|name| {
            std::env::var(name)
                .ok()
                .filter(|value| !value.trim().is_empty())
        })
        .ok_or_else(|| format!("set $EDITOR to edit {} from here", path.display()))?;
    match std::process::Command::new("sh")
        .arg("-c")
        .arg(format!("{editor} \"$1\""))
        .arg("orbit-editor")
        .arg(path)
        .status()
    {
        Ok(status) if status.success() => Ok(()),
        Ok(_) => Err("the editor exited with an error".into()),
        Err(error) => Err(format!("could not start the editor: {error}")),
    }
}

/// The plain chat's `/memory …` and `/config …`: the same commands as the
/// terminal chat's, answered in one text. `None` when `line` is neither.
/// `at_terminal` says whether an editor can be given the terminal.
pub fn plain_command(home: &Path, project: &Path, line: &str, at_terminal: bool) -> Option<String> {
    plain_command_with(home, project, line, at_terminal, &run_editor)
}

fn plain_command_with(
    home: &Path,
    project: &Path,
    line: &str,
    at_terminal: bool,
    editor: &dyn Fn(&Path) -> Result<(), String>,
) -> Option<String> {
    const MEMORY: &str = "usage: /memory add [--user|--local] <text> · /memory remove [--user|--local] <text> · /memory edit [--user|--local]";
    const CONFIG: &str = "usage: /config set <key> <value> · /config unset <key> · /config edit · keys: claude_compat, output_style, status_line";
    let line = line.trim();
    let (command, rest) = line
        .split_once(char::is_whitespace)
        .map_or((line, ""), |(command, rest)| (command, rest.trim()));
    let (verb, words) = rest
        .split_once(char::is_whitespace)
        .map_or((rest, ""), |(verb, words)| (verb, words.trim()));
    let changed = |source: &str, value: &str| {
        let _ = orbit_engine::hooks::Hooks::load(home, orbit_engine::hooks::project_trusted(home))
            .fire(
                orbit_engine::hooks::HookEvent::ConfigChange,
                &serde_json::json!({ "source": source, "value": value }),
            );
    };
    let edit = |path: PathBuf| -> Result<(), String> {
        if !at_terminal {
            return Err(format!(
                "an editor needs a terminal; the file is {}",
                path.display()
            ));
        }
        editor(&path)
    };
    let text = match (command, verb) {
        ("/memory", "add") => memory_add(home, project, words),
        ("/memory", "remove") => memory_remove(home, project, words),
        ("/memory", "edit") => memory_edit_target(home, project, words)
            .and_then(|(path, scope)| edit(path).map(|()| memory_edited(home, project, scope))),
        ("/memory", _) => Ok(MEMORY.to_owned()),
        ("/config", "set") => match words.split_once(char::is_whitespace) {
            Some((key, value)) => {
                config_set(home, key, value).inspect(|_| changed(key, value.trim()))
            }
            None => Ok(CONFIG.to_owned()),
        },
        ("/config", "unset") if !words.is_empty() && !words.contains(char::is_whitespace) => {
            config_unset(home, words)
        }
        ("/config", "edit") if words.is_empty() => config_edit_target(home)
            .and_then(edit)
            .and_then(|()| config_edited(home))
            .inspect(|_| changed("settings.toml", "")),
        ("/config", _) => Ok(CONFIG.to_owned()),
        _ => return None,
    };
    Some(text.unwrap_or_else(|error| error))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The plain chat's commands do what the terminal chat's do; an editor
    /// is only started at a terminal, on the file the scope names.
    #[test]
    fn the_plain_chat_edits_memory_and_settings() {
        let dir = scratch("plain");
        let (home, project) = (dir.join("h"), dir.join("p"));
        std::fs::create_dir_all(&project).unwrap();
        std::fs::create_dir_all(&home).unwrap();
        let opened = std::cell::RefCell::new(Vec::new());
        let editor = |path: &Path| -> Result<(), String> {
            opened.borrow_mut().push(path.to_path_buf());
            let mut body = std::fs::read_to_string(path).unwrap();
            body.push_str("claude_compat = true\n");
            std::fs::write(path, body).map_err(|error| error.to_string())
        };
        let run = |line: &str, at_terminal: bool| {
            plain_command_with(&home, &project, line, at_terminal, &editor)
        };
        assert_eq!(run("/model x", true), None);
        assert_eq!(run("/memoryx add y", true), None);
        assert!(
            run("/memory", true)
                .unwrap()
                .starts_with("usage: /memory add")
        );
        assert!(
            run("/config", true)
                .unwrap()
                .starts_with("usage: /config set")
        );
        assert!(
            run("/config set claude_compat", true)
                .unwrap()
                .starts_with("usage:")
        );

        assert!(
            run("/memory add --user run the tests", true)
                .unwrap()
                .starts_with("added to ")
        );
        assert_eq!(
            std::fs::read_to_string(home.join("ORBIT.md")).unwrap(),
            "- run the tests\n"
        );
        assert!(run("/memory remove --user run the tests", true).is_some());
        assert_eq!(std::fs::read_to_string(home.join("ORBIT.md")).unwrap(), "");

        // No terminal: no editor, and the file is named.
        let refused = run("/config edit", false).unwrap();
        assert!(
            refused.starts_with("an editor needs a terminal"),
            "{refused}"
        );
        assert!(opened.borrow().is_empty());
        assert!(
            run("/config edit", true)
                .unwrap()
                .starts_with("saved, valid TOML")
        );
        assert!(
            run("/memory edit --local", true)
                .unwrap()
                .starts_with("saved, 1 line")
        );
        assert_eq!(
            *opened.borrow(),
            [
                home.join("settings.toml"),
                project.join(".orbit").join("ORBIT.local.md")
            ]
        );
        assert!(run("/config unset claude_compat", true).is_some());
        assert!(
            !std::fs::read_to_string(home.join("settings.toml"))
                .unwrap()
                .contains("claude_compat")
        );
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn the_editor_is_pointed_at_a_plain_file_that_exists() {
        let dir = scratch("edit");
        let (home, project) = (dir.join("h"), dir.join("p"));
        std::fs::create_dir_all(&project).unwrap();
        let (path, scope) = memory_edit_target(&home, &project, "--local").unwrap();
        assert_eq!(path, project.join(".orbit").join("ORBIT.local.md"));
        assert_eq!(scope, "--local");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "");
        std::fs::write(&path, "- keep\n- this\n").unwrap();
        // An existing file is opened as it is.
        memory_edit_target(&home, &project, "--local").unwrap();
        assert!(memory_edited(&home, &project, "--local").starts_with("saved, 2 lines · "));
        assert!(memory_edit_target(&home, &project, "--user extra").is_err());

        // A link is not followed, for either file.
        std::os::unix::fs::symlink(&path, project.join("ORBIT.md")).unwrap();
        assert!(memory_edit_target(&home, &project, "").is_err());
        let settings = config_edit_target(&home).unwrap();
        assert_eq!(settings, home.join("settings.toml"));
        assert!(config_edited(&home).is_ok());
        std::fs::write(&settings, "claude_compat = \n").unwrap();
        assert!(
            config_edited(&home)
                .unwrap_err()
                .starts_with("not valid TOML now")
        );
        // Settings kept elsewhere and linked are opened; a link to a
        // folder, or to nothing, is not.
        std::fs::remove_file(&settings).unwrap();
        std::os::unix::fs::symlink(&path, &settings).unwrap();
        assert_eq!(config_edit_target(&home).unwrap(), settings);
        for target in [project.clone(), dir.join("nowhere")] {
            std::fs::remove_file(&settings).unwrap();
            std::os::unix::fs::symlink(&target, &settings).unwrap();
            assert!(config_edit_target(&home).is_err(), "{target:?}");
        }
        std::fs::remove_dir_all(dir).ok();
    }

    fn scratch(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("orbit-config-edit-{name}-{}", ulid::Ulid::new()));
        std::fs::create_dir_all(dir.join("home")).unwrap();
        std::fs::create_dir_all(dir.join("project")).unwrap();
        dir
    }

    /// A memory line lands in the file its scope names, once, as one clean
    /// line, and comes out again; the rest of the file is untouched.
    #[test]
    fn memory_lines_are_added_once_and_removed_exactly() {
        let dir = scratch("memory");
        let (home, project) = (dir.join("home"), dir.join("project"));
        std::fs::write(project.join("ORBIT.md"), "# Project\n\nBuild with make.").unwrap();

        memory_add(
            &home,
            &project,
            "run the  tests\twith `make check`\u{1b}[2J",
        )
        .unwrap();
        assert_eq!(
            std::fs::read_to_string(project.join("ORBIT.md")).unwrap(),
            "# Project\n\nBuild with make.\n- run the  tests with `make check`[2J\n"
        );
        let again = memory_add(&home, &project, "run the  tests with `make check`[2J").unwrap();
        assert!(again.contains("already says that"), "{again}");

        memory_add(&home, &project, "--user prefer short answers").unwrap();
        assert_eq!(
            std::fs::read_to_string(home.join("ORBIT.md")).unwrap(),
            "- prefer short answers\n"
        );
        memory_add(&home, &project, "--local my scratch branch is wip/x").unwrap();
        assert!(project.join(".orbit/ORBIT.local.md").is_file());
        // The flag is a word of its own, not a prefix of the text.
        memory_add(&home, &project, "--userland tools live in bin/").unwrap();
        assert!(
            std::fs::read_to_string(project.join("ORBIT.md"))
                .unwrap()
                .contains("- --userland tools live in bin/")
        );

        assert!(
            memory_remove(&home, &project, "build with make").is_err(),
            "exact, not loose"
        );
        memory_remove(&home, &project, "Build with make.").unwrap();
        memory_remove(&home, &project, "run the  tests with `make check`[2J").unwrap();
        assert_eq!(
            std::fs::read_to_string(project.join("ORBIT.md")).unwrap(),
            "# Project\n\n- --userland tools live in bin/\n"
        );
        assert!(memory_add(&home, &project, "   ").is_err());
        assert!(memory_add(&home, &project, &"x".repeat(MAX_MEMORY_LINE + 1)).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// An instruction file that is a link is not written through.
    #[cfg(unix)]
    #[test]
    fn a_linked_memory_file_is_refused() {
        let dir = scratch("link");
        let (home, project) = (dir.join("home"), dir.join("project"));
        std::fs::write(dir.join("elsewhere.md"), "untouched\n").unwrap();
        std::os::unix::fs::symlink(dir.join("elsewhere.md"), project.join("ORBIT.md")).unwrap();
        assert!(memory_add(&home, &project, "anything").is_err());
        assert_eq!(
            std::fs::read_to_string(dir.join("elsewhere.md")).unwrap(),
            "untouched\n"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A setting is changed where it is, the rest of the file stays word for
    /// word, and a new one is still a top-level key the readers find.
    #[test]
    fn settings_are_set_and_unset_without_touching_the_rest() {
        let dir = scratch("config");
        let home = dir.join("home");
        let settings = home.join("settings.toml");
        std::fs::write(
            &settings,
            "# mine\noutput_style = \"learning\" # keep\n\n[permissions]\ndeny = [\"Bash(rm *)\"]\n",
        )
        .unwrap();
        config_set(&home, "claude_compat", "on").unwrap();
        config_set(&home, "status_line", "\"~/bin/line.sh --short\"").unwrap();
        config_set(&home, "output_style", "explanatory").unwrap();
        let text = std::fs::read_to_string(&settings).unwrap();
        assert!(
            text.starts_with("# mine\noutput_style = \"explanatory\" # keep\n"),
            "{text}"
        );
        assert!(
            text.contains("[permissions]\ndeny = [\"Bash(rm *)\"]\n"),
            "{text}"
        );
        let parsed: toml::Table = toml::from_str(&text).unwrap();
        assert_eq!(parsed["claude_compat"].as_bool(), Some(true), "{text}");
        assert_eq!(
            parsed["status_line"].as_str(),
            Some("~/bin/line.sh --short")
        );
        assert!(parsed["permissions"].is_table());

        config_unset(&home, "status_line").unwrap();
        let text = std::fs::read_to_string(&settings).unwrap();
        assert!(!text.contains("status_line"), "{text}");
        assert!(
            config_unset(&home, "status_line")
                .unwrap()
                .contains("is not set")
        );

        assert!(
            config_set(&home, "permissions", "x").is_err(),
            "tables have their own commands"
        );
        assert!(config_set(&home, "claude_compat", "maybe").is_err());
        assert!(config_set(&home, "status_line", "").is_err());
        std::fs::write(&settings, "[broken\n").unwrap();
        assert!(config_set(&home, "claude_compat", "true").is_err());
        assert_eq!(
            std::fs::read_to_string(&settings).unwrap(),
            "[broken\n",
            "left alone"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
