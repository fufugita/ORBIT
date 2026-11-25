//! The session's working directory after launch: `/cd`, and the
//! `EnterWorktree` / `ExitWorktree` tools.
//!
//! A session stays bound to the workspace it was opened in: its files, its
//! lease, the process's own directory and the tool context's `working_dir`
//! (where settings, permission rules, folder trust and MCP configuration are
//! looked up) never move. What moves is where the session's tools run: Bash
//! starts there and relative paths resolve there. That is the tool
//! context's `cwd`, shared by every clone of the context, so a move made by
//! one call holds for the next.
//!
//! `/cd` only goes somewhere inside the session's working directories
//! (`/add-dir` adds one). A worktree made by `EnterWorktree` lives at
//! `.orbit/worktrees/<name>` on branch `orbit/<name>`, as `--worktree`
//! makes them, unless a `WorktreeCreate` hook supplies the directory.

use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// The worktree this session is in, when it entered one.
#[derive(Default)]
pub struct SessionDir(Mutex<Option<Worktree>>);

/// The worktree this session entered with `EnterWorktree`.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Worktree {
    name: String,
    path: PathBuf,
    /// Where the session was before it entered.
    back: PathBuf,
    /// A `WorktreeCreate` hook made it; git did not.
    by_hook: bool,
}

fn state(cx: &orbit_tools::ToolContext) -> std::sync::Arc<SessionDir> {
    if let Some(found) = cx.ext::<SessionDir>() {
        return found;
    }
    cx.set_ext(SessionDir::default());
    cx.ext::<SessionDir>().expect("just set")
}

/// The session's working directory when `/cd` or a worktree tool moved it.
pub fn session_dir(cx: &orbit_tools::ToolContext) -> Option<PathBuf> {
    Some(cx.cwd()).filter(|dir| *dir != cx.working_dir)
}

fn inside_any(path: &Path, dirs: &[PathBuf]) -> bool {
    dirs.iter()
        .filter_map(|dir| dir.canonicalize().ok())
        .any(|dir| path.starts_with(dir))
}

/// Record the move and tell the hooks: every later payload reports the new
/// `cwd`, and `CwdChanged` fires once.
fn move_to(home: &Path, cx: &orbit_tools::ToolContext, to: &Path, reason: &str) {
    let from = cx.cwd();
    cx.set_cwd(Some(to.to_path_buf()));
    // Hook payloads report the session's directory. A subagent that enters
    // a worktree of its own moves only itself.
    if !crate::tool_runtime::is_agent_context(cx) {
        orbit_engine::hooks::set_working_dir(Some(to));
    }
    if from != to {
        let _ = orbit_engine::hooks::Hooks::load(home, orbit_engine::hooks::project_trusted(home))
            .fire(
                orbit_engine::hooks::HookEvent::CwdChanged,
                &serde_json::json!({
                    "old_cwd": from.to_string_lossy(),
                    "new_cwd": to.to_string_lossy(),
                    "cwd": to.to_string_lossy(),
                    "reason": reason,
                }),
            );
    }
}

/// `/cd <path>`: move the session's working directory. Relative paths are
/// taken from where the session is now. The target must be a directory
/// inside one of the session's working directories.
pub fn change_dir(
    home: &Path,
    cx: &orbit_tools::ToolContext,
    target: &str,
) -> Result<PathBuf, String> {
    let target = target.trim();
    if target.is_empty() {
        return Err("usage: /cd <directory>".into());
    }
    let wanted = if let Some(rest) = target.strip_prefix("~/") {
        std::env::var_os("HOME")
            .map(PathBuf::from)
            .ok_or("HOME is not set")?
            .join(rest)
    } else {
        cx.cwd().join(target)
    };
    let dir = wanted
        .canonicalize()
        .map_err(|error| format!("{target}: {error}"))?;
    if !dir.is_dir() {
        return Err(format!("{target} is not a directory"));
    }
    if orbit_tools::is_deny_read(&dir) {
        return Err(format!("{target} is on the deny-read list"));
    }
    if !inside_any(&dir, &cx.working_dirs) {
        return Err(format!(
            "{} is outside this session's working directories; /add-dir it first",
            dir.display()
        ));
    }
    move_to(home, cx, &dir, "cd");
    Ok(dir)
}

/// A line for the system prompt once the session has moved, so the model
/// knows where its commands run. Empty while it is where it started.
pub fn prompt_note(cx: &orbit_tools::ToolContext, started_in: &Path) -> String {
    match session_dir(cx) {
        Some(dir) if dir != started_in => format!(
            "\n\n## Working directory\nThe working directory is now {} (the session started in {}). Commands run there and relative paths resolve there.",
            dir.display(),
            started_in.display()
        ),
        _ => String::new(),
    }
}

pub fn is_worktree_tool(name: &str) -> bool {
    matches!(name, "EnterWorktree" | "ExitWorktree")
}

/// A worktree name becomes a directory and a branch.
fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && !name.starts_with(['.', '-'])
        && !name.contains("..")
        && !name.contains(['/', '\\'])
        && !name.chars().any(|c| c.is_whitespace() || c.is_control())
}

/// Create (or find) the git worktree `.orbit/worktrees/<name>` of the
/// repository at `root`, on a new branch `orbit/<name>`. An existing one is
/// returned as it is.
pub fn create_git_worktree(root: &Path, name: &str) -> Result<PathBuf, String> {
    if !valid_name(name) {
        return Err("invalid worktree name".into());
    }
    let parent = root.join(".orbit").join("worktrees");
    let path = parent.join(name);
    if path.exists() {
        return Ok(path);
    }
    std::fs::create_dir_all(&parent).map_err(|error| error.to_string())?;
    let out = std::process::Command::new("git")
        .args(["worktree", "add", "-b"])
        .arg(format!("orbit/{name}"))
        .arg(&path)
        .current_dir(root)
        .stdin(std::process::Stdio::null())
        .output()
        .map_err(|error| error.to_string())?;
    if !out.status.success() {
        return Err(String::from_utf8_lossy(&out.stderr).trim().to_string());
    }
    Ok(path)
}

/// The directory a `WorktreeCreate` hook answered with: plain text on
/// standard output, or `hookSpecificOutput.worktreePath` in JSON.
fn hook_path(stdout: &str) -> Option<PathBuf> {
    let text = stdout.trim();
    let named = match serde_json::from_str::<serde_json::Value>(text) {
        Ok(value) => value
            .pointer("/hookSpecificOutput/worktreePath")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned),
        Err(_) => text
            .lines()
            .rev()
            .map(str::trim)
            .find(|line| !line.is_empty())
            .map(str::to_owned),
    }?;
    let path = PathBuf::from(named);
    path.is_absolute().then_some(path)
}

/// A name for a worktree the model did not name. It is taken from the
/// random end of a ULID: the start is a timestamp, the same for two made in
/// one millisecond.
fn generated_name() -> String {
    let id = ulid::Ulid::new().to_string().to_lowercase();
    format!("wt-{}", &id[id.len() - 10..])
}

/// `EnterWorktree` and `ExitWorktree`.
pub fn tool(
    home: &Path,
    cx: &orbit_tools::ToolContext,
    name: &str,
    args: &serde_json::Value,
) -> Result<serde_json::Value, String> {
    let hooks = orbit_engine::hooks::Hooks::load(home, orbit_engine::hooks::project_trusted(home));
    let shared = state(cx);
    let entered = shared
        .0
        .lock()
        .map_err(|_| "session directory state is unavailable")?
        .clone();
    match name {
        "EnterWorktree" => {
            if let Some(worktree) = entered {
                return Err(format!(
                    "already in worktree {} ({}); ExitWorktree first",
                    worktree.name,
                    worktree.path.display()
                ));
            }
            let name = match args.get("name").and_then(serde_json::Value::as_str) {
                Some(name) if !name.trim().is_empty() => name.trim().to_owned(),
                _ => generated_name(),
            };
            // A name the model chose is held to the stated alphabet; the
            // `--worktree` flag keeps the operator's wider one.
            let plain = name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'));
            if !valid_name(&name) || !plain {
                return Err(
                    "invalid worktree name: letters, digits, '-', '_' and '.', no path separators"
                        .into(),
                );
            }
            let back = cx.cwd();
            // A WorktreeCreate hook replaces git: it prints the directory it
            // made. Any failing hook, or none naming a directory, fails the
            // tool.
            let fired = hooks.fire(
                orbit_engine::hooks::HookEvent::WorktreeCreate,
                &serde_json::json!({ "name": name }),
            );
            let (path, by_hook) = if fired.is_empty() {
                // The repository is the one the session was opened in.
                (create_git_worktree(&cx.working_dir, &name)?, false)
            } else {
                if let Some(failed) = fired.iter().find(|outcome| outcome.exit_code != 0) {
                    return Err(format!(
                        "a WorktreeCreate hook failed: {}",
                        failed.stderr.trim()
                    ));
                }
                let path = fired
                    .iter()
                    .rev()
                    .find_map(|outcome| hook_path(&outcome.stdout))
                    .ok_or("the WorktreeCreate hook did not print the worktree's absolute path")?;
                (path, true)
            };
            let path = path
                .canonicalize()
                .map_err(|error| format!("{}: {error}", path.display()))?;
            if !path.is_dir() {
                return Err(format!("{} is not a directory", path.display()));
            }
            if orbit_tools::is_deny_read(&path) {
                return Err(format!("{} is on the deny-read list", path.display()));
            }
            // What git made lives inside the project. A `.orbit/worktrees`
            // entry that is a link to somewhere else would otherwise move
            // the session, and the sandbox's write access, out of it. Only
            // a hook, which the operator configured, may name a directory
            // elsewhere.
            if !by_hook && !inside_any(&path, std::slice::from_ref(&cx.working_dir)) {
                return Err(format!(
                    "{} resolves outside the project; not entering it",
                    path.display()
                ));
            }
            if let Ok(mut state) = shared.0.lock() {
                *state = Some(Worktree {
                    name: name.clone(),
                    path: path.clone(),
                    back,
                    by_hook,
                });
            }
            move_to(home, cx, &path, "worktree");
            Ok(serde_json::json!({
                "worktree": name,
                "path": path.to_string_lossy(),
                "branch": (!by_hook).then(|| format!("orbit/{name}")),
                "note": "The working directory is now this worktree: commands run here and relative paths resolve here. ExitWorktree returns.",
            }))
        }
        "ExitWorktree" => {
            let Some(worktree) = entered else {
                return Err("this session has not entered a worktree with EnterWorktree".into());
            };
            let action = args
                .get("action")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("keep");
            let discard = args
                .get("discard_changes")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false);
            let mut report = serde_json::json!({
                "worktree": worktree.name,
                "path": worktree.path.to_string_lossy(),
                "returned_to": worktree.back.to_string_lossy(),
            });
            match action {
                "keep" => report["kept"] = serde_json::json!(true),
                "remove" => {
                    report["removed"] =
                        serde_json::json!(remove(&hooks, &cx.working_dir, &worktree, discard)?);
                }
                _ => return Err("ExitWorktree 'action' must be \"keep\" or \"remove\"".into()),
            }
            if let Ok(mut state) = shared.0.lock() {
                *state = None;
            }
            move_to(home, cx, &worktree.back, "worktree");
            Ok(report)
        }
        _ => Err(format!("unknown worktree tool {name}")),
    }
}

/// Remove an entered worktree. Uncommitted work stops it unless `discard`.
/// `WorktreeRemove` hooks run first and a failing one keeps the worktree;
/// git removes what git made.
fn remove(
    hooks: &orbit_engine::hooks::Hooks,
    repository: &Path,
    worktree: &Worktree,
    discard: bool,
) -> Result<String, String> {
    let git = |args: &[&str], dir: &Path| {
        std::process::Command::new("git")
            .args(args)
            .current_dir(dir)
            .stdin(std::process::Stdio::null())
            .output()
            .map_err(|error| error.to_string())
    };
    if !worktree.by_hook && !discard {
        let status = git(&["status", "--porcelain"], &worktree.path)?;
        if !status.status.success() || !status.stdout.is_empty() {
            return Err(
                "the worktree has uncommitted changes; commit them, or pass discard_changes: true, or use action: \"keep\""
                    .into(),
            );
        }
    }
    let fired = hooks.fire(
        orbit_engine::hooks::HookEvent::WorktreeRemove,
        &serde_json::json!({
            "name": worktree.name,
            "worktree_path": worktree.path.to_string_lossy(),
        }),
    );
    if let Some(failed) = fired.iter().find(|outcome| outcome.exit_code != 0)
        && worktree.path.exists()
    {
        return Err(format!(
            "a WorktreeRemove hook failed and the worktree was kept: {}",
            failed.stderr.trim()
        ));
    }
    if worktree.by_hook || !worktree.path.exists() {
        return Ok(if worktree.path.exists() {
            "the hooks ran; the directory is still there".into()
        } else {
            "removed".into()
        });
    }
    let path = worktree.path.to_string_lossy();
    let mut args = vec!["worktree", "remove"];
    if discard {
        args.push("--force");
    }
    args.push(&path);
    let out = git(&args, repository)?;
    if !out.status.success() {
        return Err(String::from_utf8_lossy(&out.stderr).trim().to_string());
    }
    // The branch goes with it only when nothing would be lost: `-d` refuses
    // an unmerged branch, and that refusal is reported, not forced.
    let branch = format!("orbit/{}", worktree.name);
    let deleted = git(
        &["branch", if discard { "-D" } else { "-d" }, &branch],
        repository,
    )?;
    Ok(if deleted.status.success() {
        format!("removed the worktree and branch {branch}")
    } else {
        format!("removed the worktree; branch {branch} was kept (it has unmerged commits)")
    })
}

/// The definitions the session advertises.
pub fn definitions() -> [(&'static str, &'static str, serde_json::Value); 2] {
    [
        (
            "EnterWorktree",
            "Create a git worktree (.orbit/worktrees/<name>, branch orbit/<name>) and move the working directory into it until ExitWorktree. Only when the operator asks to work in a worktree.",
            serde_json::json!({
                "type": "object",
                "properties": {
                    "name": { "type": "string", "description": "Worktree and branch name; generated when omitted" }
                }
            }),
        ),
        (
            "ExitWorktree",
            "Leave the worktree entered with EnterWorktree. \"keep\" leaves it and its branch on disk; \"remove\" deletes them, and refuses over uncommitted changes unless discard_changes is true.",
            serde_json::json!({
                "type": "object",
                "properties": {
                    "action": { "type": "string", "enum": ["keep", "remove"] },
                    "discard_changes": { "type": "boolean" }
                },
                "required": ["action"]
            }),
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("orbit-worktree-{name}-{}", ulid::Ulid::new()));
        std::fs::create_dir_all(dir.join("home")).unwrap();
        std::fs::create_dir_all(dir.join("project/src/deep")).unwrap();
        dir.canonicalize().unwrap()
    }

    fn context(dir: &Path) -> orbit_tools::ToolContext {
        orbit_tools::ToolContext::new(dir.join("home"), "s-wt".into(), dir.join("project"))
    }

    #[test]
    fn cd_moves_inside_the_working_directories_and_nowhere_else() {
        let dir = scratch("cd");
        let (home, cx) = (dir.join("home"), context(&dir));
        assert_eq!(session_dir(&cx), None);
        assert_eq!(cx.cwd(), dir.join("project"));
        assert_eq!(
            change_dir(&home, &cx, "src").unwrap(),
            dir.join("project/src")
        );
        // Relative to where the session is now, and seen by every clone.
        assert_eq!(
            change_dir(&home, &cx.clone(), "deep").unwrap(),
            dir.join("project/src/deep")
        );
        assert_eq!(cx.clone().cwd(), dir.join("project/src/deep"));
        // The project itself never moves: rules and settings stay found.
        assert_eq!(cx.working_dir, dir.join("project"));
        assert_eq!(cx.writable_dirs(), cx.working_dirs, "still inside");
        assert_eq!(
            orbit_tools::resolve_path(&cx, "x.rs"),
            dir.join("project/src/deep/x.rs")
        );
        assert_eq!(
            change_dir(&home, &cx, "../..").unwrap(),
            dir.join("project")
        );
        assert_eq!(session_dir(&cx), None, "back where the session started");
        for refused in ["..", "/", "nope", "", &dir.join("home").to_string_lossy()] {
            assert!(change_dir(&home, &cx, refused).is_err(), "{refused}");
        }
        std::fs::write(dir.join("project/file.txt"), "x").unwrap();
        assert!(
            change_dir(&home, &cx, "file.txt")
                .unwrap_err()
                .contains("not a directory")
        );
        assert_eq!(session_dir(&cx), None);
        assert_eq!(prompt_note(&cx, &dir.join("project")), "");
        change_dir(&home, &cx, "src").unwrap();
        assert!(prompt_note(&cx, &dir.join("project")).contains("project/src"));
        orbit_engine::hooks::set_working_dir(None);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn worktree_names_and_hook_answers_are_checked() {
        for good in ["fix-1", "a", "feature_x.2"] {
            assert!(valid_name(good), "{good}");
        }
        for bad in [
            "",
            ".hidden",
            "-flag",
            "a/b",
            "a..b",
            "a b",
            "a\\b",
            &"x".repeat(65),
        ] {
            assert!(!valid_name(bad), "{bad}");
        }
        assert_eq!(
            hook_path("log line\n/tmp/wt-1\n\n"),
            Some(PathBuf::from("/tmp/wt-1"))
        );
        assert_eq!(
            hook_path(r#"{"hookSpecificOutput": {"worktreePath": "/tmp/wt-2"}}"#),
            Some(PathBuf::from("/tmp/wt-2"))
        );
        assert_eq!(hook_path("relative/path"), None);
        assert_eq!(hook_path(""), None);
        assert_eq!(hook_path(r#"{"ok": true}"#), None);
        let name = generated_name();
        assert!(valid_name(&name) && name.len() == 13, "{name}");
        assert_ne!(name, generated_name(), "two in a row differ");
    }

    /// A `.orbit/worktrees` entry that links out of the project is not
    /// entered: the session and its sandbox stay inside, and a name outside
    /// the stated alphabet is refused before anything runs.
    #[cfg(unix)]
    #[test]
    fn a_worktree_entry_linking_out_of_the_project_is_refused() {
        let dir = scratch("link");
        let cx = context(&dir);
        let outside = dir.join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::create_dir_all(dir.join("project/.orbit/worktrees")).unwrap();
        std::os::unix::fs::symlink(&outside, dir.join("project/.orbit/worktrees/escape")).unwrap();
        let error = tool(
            &dir.join("home"),
            &cx,
            "EnterWorktree",
            &serde_json::json!({ "name": "escape" }),
        )
        .unwrap_err();
        assert!(error.contains("outside the project"), "{error}");
        assert_eq!(cx.cwd(), dir.join("project"), "the session did not move");
        assert_eq!(cx.writable_dirs(), vec![dir.join("project")]);

        let error = tool(
            &dir.join("home"),
            &cx,
            "EnterWorktree",
            &serde_json::json!({ "name": "a:b" }),
        )
        .unwrap_err();
        assert!(error.contains("invalid worktree name"), "{error}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn git(dir: &Path, args: &[&str]) -> bool {
        std::process::Command::new("git")
            .args(args)
            .current_dir(dir)
            .env("GIT_AUTHOR_NAME", "t")
            .env("GIT_AUTHOR_EMAIL", "t@example.com")
            .env("GIT_COMMITTER_NAME", "t")
            .env("GIT_COMMITTER_EMAIL", "t@example.com")
            .output()
            .is_ok_and(|out| out.status.success())
    }

    #[test]
    fn a_git_worktree_is_created_once_and_removed_only_when_clean() {
        let dir = scratch("git");
        let project = dir.join("project");
        if !git(&project, &["init", "-q", "-b", "main"]) {
            // No git on this machine: nothing to exercise.
            std::fs::remove_dir_all(dir).unwrap();
            return;
        }
        std::fs::write(project.join("a.txt"), "one\n").unwrap();
        assert!(git(&project, &["add", "a.txt"]));
        assert!(git(&project, &["commit", "-q", "-m", "first"]));
        let path = create_git_worktree(&project, "fix").unwrap();
        assert_eq!(path, project.join(".orbit/worktrees/fix"));
        assert!(
            path.join("a.txt").exists(),
            "the worktree has the repository's files"
        );
        assert_eq!(
            create_git_worktree(&project, "fix").unwrap(),
            path,
            "entered, not remade"
        );
        assert!(create_git_worktree(&project, "../x").is_err());
        let worktree = Worktree {
            name: "fix".into(),
            path: path.clone(),
            back: project.clone(),
            by_hook: false,
        };
        let hooks = orbit_engine::hooks::Hooks::default();
        std::fs::write(path.join("new.txt"), "wip\n").unwrap();
        let refused = remove(&hooks, &project, &worktree, false).unwrap_err();
        assert!(refused.contains("uncommitted"), "{refused}");
        assert!(path.exists());
        let removed = remove(&hooks, &project, &worktree, true).unwrap();
        assert!(removed.contains("orbit/fix"), "{removed}");
        assert!(!path.exists());
        assert!(!git(
            &project,
            &["rev-parse", "--verify", "-q", "orbit/fix"]
        ));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn removing_a_worktree_from_an_added_repo_restores_cwd_and_cleans_the_owner() {
        let dir = scratch("added-repo");
        let home = dir.join("home");
        let mut cx = context(&dir);
        let other = dir.join("other");
        let previous_cwd = other.join("src");
        std::fs::create_dir_all(&previous_cwd).unwrap();
        for repo in [&cx.working_dir, &other] {
            assert!(git(repo, &["init", "-q", "-b", "main"]));
            assert!(git(repo, &["commit", "-q", "--allow-empty", "-m", "first"]));
        }
        assert!(git(&other, &["branch", "orbit/topic"]));
        cx.working_dirs.push(other.clone());
        change_dir(&home, &cx, previous_cwd.to_str().unwrap()).unwrap();

        tool(
            &home,
            &cx,
            "EnterWorktree",
            &serde_json::json!({"name": "topic"}),
        )
        .unwrap();
        let worktree = cx.working_dir.join(".orbit/worktrees/topic");
        assert_eq!(cx.cwd(), worktree);
        let result = tool(
            &home,
            &cx,
            "ExitWorktree",
            &serde_json::json!({"action": "remove"}),
        )
        .unwrap();

        assert_eq!(cx.cwd(), previous_cwd);
        assert_eq!(result["returned_to"], previous_cwd.to_str().unwrap());
        assert!(!worktree.exists());
        let branch_exists = ["show-ref", "--verify", "--quiet", "refs/heads/orbit/topic"];
        assert!(!git(&cx.working_dir, &branch_exists));
        assert!(git(&other, &branch_exists));
        orbit_engine::hooks::set_working_dir(None);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn exit_needs_an_entered_worktree_and_enter_refuses_a_second_one() {
        let dir = scratch("tool");
        let (home, cx) = (dir.join("home"), context(&dir));
        let exit = tool(
            &home,
            &cx,
            "ExitWorktree",
            &serde_json::json!({"action": "keep"}),
        );
        assert!(exit.unwrap_err().contains("has not entered"));
        // As if EnterWorktree had run: a hook-made worktree outside the project.
        let elsewhere = dir.join("elsewhere");
        std::fs::create_dir_all(&elsewhere).unwrap();
        *state(&cx).0.lock().unwrap() = Some(Worktree {
            name: "side".into(),
            path: elsewhere.clone(),
            back: dir.join("project"),
            by_hook: true,
        });
        move_to(&home, &cx, &elsewhere, "worktree");
        assert_eq!(cx.cwd(), elsewhere);
        assert!(
            cx.writable_dirs().contains(&elsewhere),
            "a directory to write in"
        );
        assert!(
            !cx.working_dirs.contains(&elsewhere),
            "not a working directory"
        );
        let again = tool(
            &home,
            &cx,
            "EnterWorktree",
            &serde_json::json!({"name": "two"}),
        );
        assert!(again.unwrap_err().contains("already in worktree side"));
        let bad = tool(
            &home,
            &cx,
            "ExitWorktree",
            &serde_json::json!({"action": "burn"}),
        );
        assert!(bad.is_err());
        assert_eq!(
            session_dir(&cx),
            Some(elsewhere.clone()),
            "a refused exit moves nothing"
        );
        let kept = tool(
            &home,
            &cx,
            "ExitWorktree",
            &serde_json::json!({"action": "keep"}),
        )
        .unwrap();
        assert_eq!(kept["kept"], true);
        assert_eq!(session_dir(&cx), None);
        assert_eq!(cx.cwd(), dir.join("project"));
        assert!(elsewhere.exists());
        orbit_engine::hooks::set_working_dir(None);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
