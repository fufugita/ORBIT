//! The context builder — the frozen system prompt, project memory,
//! and the token budget (roadmap phase 4, §Context).
//!
//! The system prompt is built once per session, stable parts first so
//! they cache: base instructions, the tool set, the environment
//! snapshot, memory files (lowest scope first), enabled mods. The
//! transcript stays append-only — a mid-session change arrives as an
//! appended note, never an edit.

use std::path::{Path, PathBuf};

/// The memory file names ORBIT reads, in scope order (managed → user →
/// project → local). AGENTS.md and CLAUDE.md are read too so existing
/// repositories work on day one.
pub const MEMORY_FILES: &[&str] = &[
    "/etc/orbit/ORBIT.md",
    "ORBIT.md",
    ".orbit/ORBIT.md",
    ".orbit/ORBIT.local.md",
    "AGENTS.md",
    "CLAUDE.md",
];

/// Auto-memory cap (the spec's 200-line / 25 KB bound).
const AUTO_MEMORY_MAX_LINES: usize = 200;
const AUTO_MEMORY_MAX_BYTES: usize = 25 * 1024;

/// The environment snapshot for the system prompt.
#[derive(Debug, Clone)]
pub struct EnvSnapshot {
    pub working_dir: String,
    pub platform: String,
    pub shell: String,
    pub date: String,
    pub model: String,
    pub git_repo: bool,
    pub git_branch: Option<String>,
    pub git_status_short: Vec<String>,
    pub recent_commits: Vec<String>,
}

impl EnvSnapshot {
    /// Probe the working directory. Git facts are best-effort (a repo
    /// without git just reports absent).
    pub fn probe(working_dir: &Path, model: &str) -> Self {
        let git_repo = working_dir.join(".git").exists();
        let (git_branch, git_status_short, recent_commits) = if git_repo {
            (
                run_git(working_dir, &["rev-parse", "--abbrev-ref", "HEAD"]),
                run_git_lines(working_dir, &["status", "--short"], 50),
                run_git_lines(working_dir, &["log", "--oneline", "-5"], 5),
            )
        } else {
            (None, Vec::new(), Vec::new())
        };
        EnvSnapshot {
            working_dir: working_dir.to_string_lossy().into_owned(),
            platform: format!("{} ({})", std::env::consts::OS, std::env::consts::ARCH),
            shell: std::env::var("SHELL").unwrap_or_else(|_| "sh".into()),
            date: now_iso8601(),
            model: model.to_string(),
            git_repo,
            git_branch,
            git_status_short,
            recent_commits,
        }
    }

    /// Render the snapshot block for the system prompt.
    pub fn render(&self) -> String {
        let mut s = String::new();
        s.push_str("## Environment\n\n");
        s.push_str(&format!("- Working directory: {}\n", self.working_dir));
        s.push_str(&format!("- Platform: {}\n", self.platform));
        s.push_str(&format!("- Shell: {}\n", self.shell));
        s.push_str(&format!("- Date: {}\n", self.date));
        s.push_str(&format!("- Model: {}\n", self.model));
        if self.git_repo {
            s.push_str(&format!(
                "- Git repository: yes (branch: {})\n",
                self.git_branch.as_deref().unwrap_or("?")
            ));
            if !self.git_status_short.is_empty() {
                s.push_str("\n### git status --short (first 50 lines)\n```\n");
                for l in &self.git_status_short {
                    s.push_str(l);
                    s.push('\n');
                }
                s.push_str("```\n");
            }
            if !self.recent_commits.is_empty() {
                s.push_str("\n### Recent commits\n```\n");
                for l in &self.recent_commits {
                    s.push_str(l);
                    s.push('\n');
                }
                s.push_str("```\n");
            }
        } else {
            s.push_str("- Git repository: no\n");
        }
        s
    }
}

/// The frozen system prompt, built once per session.
pub struct SystemPrompt {
    pub text: String,
    /// How many bytes of `text` are the project instructions (the memory
    /// files): the context meter names them separately.
    pub memory_bytes: usize,
}

/// Build the system prompt. `home` is ORBIT_HOME; `working_dir` is the
/// project. `mods_directive` is the enabled mods' instruction text
/// (moved here from the per-request re-insertion — defect: the old
/// path re-inserted the directive at the front of every request,
/// breaking prompt caching and edited-history replay).
pub fn build_system_prompt(
    home: &Path,
    working_dir: &Path,
    model: &str,
    tool_names: &[&str],
    mods_directive: &str,
) -> SystemPrompt {
    let mut s = String::new();

    // 1. Base instructions — identical across sessions (cache-stable).
    s.push_str(BASE_INSTRUCTIONS);
    s.push_str("\n\n");

    // 2. The tool set for the session, declared up front.
    s.push_str("## Tools\n\n");
    for name in tool_names {
        if let Some(desc) = tool_description(name) {
            s.push_str(&format!("- {name}: {desc}\n"));
        }
    }
    s.push('\n');

    // 2b. Skills (phase 5): the index — names + one-line purposes.
    // Bodies load on demand via the Skill tool.
    if !crate::bare_mode()
        && tool_names
            .iter()
            .any(|name| matches!(*name, "Skill" | "Task" | "Agent"))
    {
        match crate::skills::load_catalog(home, working_dir, true) {
            Ok(catalog) => {
                let mut index = String::new();
                if tool_names.contains(&"Skill") {
                    index.push_str(
                        "## Skills\n\nLoad a skill with the Skill tool when a task matches.\n\n",
                    );
                    for entry in catalog.skills.iter().filter(|entry| {
                        entry
                            .policy
                            .as_ref()
                            .is_none_or(|policy| !policy.disable_model_invocation)
                    }) {
                        index.push_str(&format!(
                            "- {}: {}\n",
                            entry.skill.name, entry.skill.description
                        ));
                        if index.len() > 16 * 1024 {
                            break;
                        }
                    }
                }
                if tool_names
                    .iter()
                    .any(|name| matches!(*name, "Task" | "Agent"))
                {
                    index.push_str("\n## Subagents (call Task or Agent)\n\n");
                    for entry in &catalog.agents {
                        index.push_str(&format!(
                            "- {}: {}\n",
                            entry.agent.name, entry.agent.description
                        ));
                        if index.len() > 24 * 1024 {
                            break;
                        }
                    }
                }
                for diagnostic in catalog.diagnostics.iter().take(8) {
                    index.push_str(&format!("\nContent availability: {diagnostic}\n"));
                }
                s.push_str(&cap_auto_memory(&index));
                s.push('\n');
            }
            Err(error) => s.push_str(&format!("Content unavailable: {error}\n\n")),
        }
    }

    // 3. Environment snapshot.
    let env = EnvSnapshot::probe(working_dir, model);
    s.push_str(&env.render());
    s.push('\n');

    // 4. Memory files, lowest scope first.
    let memory_bytes = if crate::bare_mode() {
        0
    } else {
        let memory_from = s.len();
        s.push_str("## Project instructions\n\n");
        // Managed, then the operator's own file, then the project's.
        let mut files: Vec<PathBuf> = vec![PathBuf::from(MEMORY_FILES[0]), home.join("ORBIT.md")];
        files.extend(MEMORY_FILES[1..].iter().map(|rel| working_dir.join(rel)));
        files.extend(
            [".claude/CLAUDE.md", "CLAUDE.local.md"]
                .iter()
                .map(|rel| working_dir.join(rel)),
        );
        let mut imports = ImportBudget::default();
        for path in files {
            if let Ok(text) = std::fs::read_to_string(&path) {
                let capped = cap_auto_memory(&text);
                s.push_str(&format!(
                    "### {} ({} bytes)\n\n{}\n\n",
                    path.display(),
                    text.len(),
                    capped
                ));
                let scope = path.parent().unwrap_or(working_dir).to_path_buf();
                push_imports(
                    &mut s,
                    &text,
                    &path,
                    &[working_dir, &scope],
                    1,
                    &mut imports,
                );
            }
        }
        push_rules(&mut s, working_dir);
        s.len() - memory_from
    };

    // 5. Enabled mods' instructions (frozen here, not re-inserted).
    if !crate::bare_mode() && !mods_directive.is_empty() {
        s.push_str("## Enabled mods\n\n");
        s.push_str(mods_directive);
        s.push_str("\n\n");
    }

    // 6. The output style, then anything appended for this run.
    if let Some(style) = output_style(home, working_dir) {
        s.push_str("## Output style\n\n");
        s.push_str(&style);
        s.push_str("\n\n");
    }
    if let Some(extra) = std::env::var("ORBIT_APPEND_SYSTEM_PROMPT")
        .ok()
        .filter(|extra| !extra.trim().is_empty())
    {
        s.push_str("## Additional instructions\n\n");
        s.push_str(&cap_auto_memory(&extra));
        s.push_str("\n\n");
    }

    SystemPrompt {
        text: s,
        memory_bytes,
    }
}

static OUTPUT_STYLE: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);

/// Choose the output style for prompts built from here on (`/output-style`),
/// ahead of the environment and settings; `None` returns to those. Reports
/// whether the name resolves: `default`, a built-in, or a style file. An
/// unknown name leaves the previous choice in place.
pub fn set_output_style(home: &Path, working_dir: &Path, name: Option<&str>) -> bool {
    let Ok(mut slot) = OUTPUT_STYLE.lock() else {
        return false;
    };
    let previous = slot.clone();
    *slot = name.map(str::to_owned);
    drop(slot);
    let known = match name.map(|name| name.trim().to_ascii_lowercase()) {
        None => true,
        Some(name) if name == "default" => true,
        Some(_) => output_style(home, working_dir).is_some(),
    };
    if !known && let Ok(mut slot) = OUTPUT_STYLE.lock() {
        *slot = previous;
    }
    known
}

/// The selected output style's instructions. The name comes from
/// `ORBIT_OUTPUT_STYLE` (`--output-style`), else a top-level
/// `output_style = "name"` in `$ORBIT_HOME/settings.toml`. `explanatory`
/// and `learning` are built in; any other name is a Markdown file in
/// `.orbit/output-styles/`, `.claude/output-styles/` or
/// `$ORBIT_HOME/output-styles/`, used without its front matter. `default`,
/// no name, or a name with no file adds nothing.
fn output_style(home: &Path, working_dir: &Path) -> Option<String> {
    let chosen = OUTPUT_STYLE.lock().ok().and_then(|slot| slot.clone());
    let name = chosen
        .or_else(|| std::env::var("ORBIT_OUTPUT_STYLE").ok())
        .filter(|name| !name.trim().is_empty())
        .or_else(|| {
            if crate::bare_mode() {
                return None;
            }
            // `--settings <file>` is read first: it is this run's choice.
            let named = |text: String| {
                text.lines()
                    .map(str::trim)
                    .take_while(|line| !line.starts_with('['))
                    .filter_map(|line| line.split('#').next()?.split_once('='))
                    .find(|(key, _)| key.trim() == "output_style")
                    .map(|(_, value)| value.trim().trim_matches('"').to_owned())
            };
            orbit_tools::executor::extra_settings_file()
                .filter(|file| !orbit_tools::executor::is_json(file))
                .and_then(|file| std::fs::read_to_string(file).ok())
                .and_then(named)
                .or_else(|| {
                    std::fs::read_to_string(home.join("settings.toml"))
                        .ok()
                        .and_then(named)
                })
        })?;
    let name = name.trim();
    match name.to_ascii_lowercase().as_str() {
        "" | "default" => return None,
        "explanatory" => {
            return Some(
                "Explain as you work. Before and after a piece of work, add a short \
                 note on why the code is shaped the way it is and what trade-off the \
                 change makes, so the operator learns the codebase along the way."
                    .into(),
            );
        }
        "learning" => {
            return Some(
                "Work as a teacher. Explain your reasoning, and when a small, \
                 self-contained piece of the change would be instructive, leave it \
                 for the operator: mark the spot with TODO(human), say what is needed \
                 there, and wait for them before continuing."
                    .into(),
            );
        }
        _ => {}
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'))
    {
        return None;
    }
    [
        working_dir.join(".orbit/output-styles"),
        working_dir.join(".claude/output-styles"),
        home.join("output-styles"),
    ]
    .iter()
    .find_map(|dir| std::fs::read_to_string(dir.join(format!("{name}.md"))).ok())
    .map(|text| cap_auto_memory(rule_front_matter(&text).1))
    .filter(|body| !body.trim().is_empty())
}

/// The instruction files that exist for this home and project, in the
/// order the prompt reads them, with their sizes: what `/memory` lists.
pub fn instruction_files(home: &Path, working_dir: &Path) -> Vec<(PathBuf, u64)> {
    let mut files: Vec<PathBuf> = vec![PathBuf::from(MEMORY_FILES[0]), home.join("ORBIT.md")];
    files.extend(MEMORY_FILES[1..].iter().map(|rel| working_dir.join(rel)));
    files.extend(
        [".claude/CLAUDE.md", "CLAUDE.local.md"]
            .iter()
            .map(|rel| working_dir.join(rel)),
    );
    for dir in [".orbit/rules", ".claude/rules"] {
        let mut rules: Vec<PathBuf> = std::fs::read_dir(working_dir.join(dir))
            .into_iter()
            .flatten()
            .flatten()
            .map(|entry| entry.path())
            .filter(|path| path.extension().is_some_and(|ext| ext == "md"))
            .collect();
        rules.sort();
        files.extend(rules);
    }
    files
        .into_iter()
        .filter_map(|path| {
            let meta = std::fs::metadata(&path).ok()?;
            meta.is_file().then_some((path, meta.len()))
        })
        .collect()
}

/// `@path` imports: how deep they nest and how many files they may add.
const IMPORT_MAX_DEPTH: usize = 5;
const IMPORT_MAX_FILES: usize = 24;

#[derive(Default)]
struct ImportBudget {
    seen: Vec<PathBuf>,
}

/// The `@path` tokens of an instruction file: at the start of a line or
/// after whitespace, outside fenced code blocks and inline code. Relative
/// paths are relative to the file that names them; `~/` is the home folder.
fn import_tokens(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut fenced = false;
    for line in text.lines() {
        if line.trim_start().starts_with("```") {
            fenced = !fenced;
            continue;
        }
        if fenced {
            continue;
        }
        let mut in_code = false;
        let mut previous = ' ';
        for (at, c) in line.char_indices() {
            if c == '`' {
                in_code = !in_code;
            } else if c == '@' && !in_code && previous.is_whitespace() {
                let rest = &line[at + 1..];
                let end = rest
                    .find(|c: char| c.is_whitespace() || c == '`')
                    .unwrap_or(rest.len());
                let token = rest[..end].trim_end_matches(['.', ',', ';', ':', ')', '!', '?']);
                if !token.is_empty() && !out.iter().any(|seen| seen == token) {
                    out.push(token.to_owned());
                }
            }
            previous = c;
        }
    }
    out
}

/// Append the files an instruction file imports. An import is honoured only
/// when it resolves to a regular file inside one of `roots` (the project, or
/// the importing scope's own folder) that is not on the deny-read list: a
/// repository's instructions cannot pull a key or another project's files
/// into the prompt. Anything else `@name` might mean is left as text.
fn push_imports(
    out: &mut String,
    text: &str,
    from: &Path,
    roots: &[&Path],
    depth: usize,
    budget: &mut ImportBudget,
) {
    if depth > IMPORT_MAX_DEPTH {
        return;
    }
    let base = from.parent().unwrap_or(Path::new("."));
    for token in import_tokens(text) {
        if budget.seen.len() >= IMPORT_MAX_FILES {
            return;
        }
        let candidate = match token.strip_prefix("~/") {
            Some(rest) => match std::env::home_dir() {
                Some(home) => home.join(rest),
                None => continue,
            },
            None => base.join(&token),
        };
        let Ok(resolved) = candidate.canonicalize() else {
            continue;
        };
        let inside = roots
            .iter()
            .filter_map(|root| root.canonicalize().ok())
            .any(|root| resolved.starts_with(root));
        if !inside
            || !resolved.is_file()
            || orbit_tools::is_deny_read(&resolved)
            || budget.seen.contains(&resolved)
            || from.canonicalize().is_ok_and(|own| own == resolved)
        {
            continue;
        }
        let Ok(imported) = std::fs::read_to_string(&resolved) else {
            continue;
        };
        budget.seen.push(resolved.clone());
        out.push_str(&format!(
            "#### Imported by {}: {} ({} bytes)\n\n{}\n\n",
            from.display(),
            resolved.display(),
            imported.len(),
            cap_auto_memory(&imported)
        ));
        push_imports(out, &imported, &resolved, roots, depth + 1, budget);
    }
}

/// Rule files: `.orbit/rules/*.md` and `.claude/rules/*.md`. A rule with no
/// `paths:` front matter is always in the prompt. A path-scoped rule is
/// listed with its patterns here; its text arrives with the result of the
/// first Read, Edit or Write of a matching file (see [`scoped_rules_for`]).
fn push_rules(out: &mut String, working_dir: &Path) {
    const MAX_RULES: usize = 32;
    let mut files: Vec<PathBuf> = [".orbit/rules", ".claude/rules"]
        .iter()
        .filter_map(|dir| std::fs::read_dir(working_dir.join(dir)).ok())
        .flat_map(|entries| entries.flatten().map(|entry| entry.path()))
        .filter(|path| path.extension().is_some_and(|ext| ext == "md") && path.is_file())
        .collect();
    files.sort();
    files.truncate(MAX_RULES);
    let mut scoped = Vec::new();
    for path in files {
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        let (paths, body) = rule_front_matter(&text);
        if paths.is_empty() {
            out.push_str(&format!(
                "### {} ({} bytes)\n\n{}\n\n",
                path.display(),
                text.len(),
                cap_auto_memory(body)
            ));
        } else {
            scoped.push(format!("- `{}` — for {}", path.display(), paths.join(", ")));
        }
    }
    if !scoped.is_empty() {
        out.push_str(
            "### Path-scoped rules\n\nEach rule's text is added to the result the first time you read or edit a matching file.\n\n",
        );
        out.push_str(&scoped.join("\n"));
        out.push_str("\n\n");
    }
}

/// `a/{b,c}/*.{ts,tsx}` → every alternative, at most 64.
fn expand_braces(pattern: &str) -> Vec<String> {
    let mut done = Vec::new();
    let mut work = vec![pattern.to_owned()];
    while let Some(next) = work.pop() {
        let alternatives = next.find('{').and_then(|open| {
            let close = open + next[open..].find('}')?;
            Some((open, close))
        });
        match alternatives {
            Some((open, close)) if done.len() + work.len() < 64 => {
                for option in next[open + 1..close].split(',') {
                    work.push(format!("{}{option}{}", &next[..open], &next[close + 1..]));
                }
            }
            _ => done.push(next),
        }
    }
    done
}

/// The path-scoped rules that apply to `file`: every rule in
/// `.orbit/rules/` or `.claude/rules/` whose `paths:` has a pattern
/// matching the file's path relative to the working directory. Returned as
/// (rule file, body), bodies capped like any instruction file.
pub fn scoped_rules_for(working_dir: &Path, file: &Path) -> Vec<(String, String)> {
    const MAX_RULES: usize = 32;
    let (Ok(root), Ok(file)) = (working_dir.canonicalize(), file.canonicalize()) else {
        return Vec::new();
    };
    let Ok(relative) = file.strip_prefix(&root) else {
        return Vec::new();
    };
    let relative = relative.to_string_lossy().replace('\\', "/");
    let mut files: Vec<PathBuf> = [".orbit/rules", ".claude/rules"]
        .iter()
        .filter_map(|dir| std::fs::read_dir(root.join(dir)).ok())
        .flat_map(|entries| entries.flatten().map(|entry| entry.path()))
        .filter(|path| path.extension().is_some_and(|ext| ext == "md") && path.is_file())
        .collect();
    files.sort();
    files.truncate(MAX_RULES);
    files
        .into_iter()
        .filter_map(|path| {
            let text = std::fs::read_to_string(&path).ok()?;
            let (patterns, body) = rule_front_matter(&text);
            patterns
                .iter()
                .flat_map(|pattern| expand_braces(pattern.trim_start_matches("./")))
                .any(|pattern| {
                    orbit_tools::fs_tools::glob_path_match(&pattern, &relative)
                        // A bare `*.rs` means "anywhere", as in a gitignore.
                        || (!pattern.contains('/')
                            && orbit_tools::fs_tools::glob_path_match(
                                &format!("**/{pattern}"),
                                &relative,
                            ))
                })
                .then(|| (path.display().to_string(), cap_auto_memory(body)))
        })
        .collect()
}

/// The `paths:` patterns of a rule's YAML front matter (inline list, block
/// list or a single value) and the body after it.
fn rule_front_matter(text: &str) -> (Vec<String>, &str) {
    let Some(rest) = text.strip_prefix("---") else {
        return (Vec::new(), text);
    };
    let Some(end) = rest.find("\n---") else {
        return (Vec::new(), text);
    };
    let (front, body) = (&rest[..end], &rest[end + 4..]);
    let clean = |value: &str| -> Option<String> {
        let value = value.trim().trim_matches(['"', '\'']).trim();
        (!value.is_empty() && value.len() <= 256).then(|| value.to_owned())
    };
    let mut paths = Vec::new();
    let mut in_paths = false;
    for line in front.lines() {
        if let Some(value) = line.strip_prefix("paths:") {
            in_paths = true;
            let value = value.trim();
            let value = value
                .strip_prefix('[')
                .and_then(|v| v.strip_suffix(']'))
                .unwrap_or(value);
            paths.extend(value.split(',').filter_map(clean));
        } else if in_paths && line.trim_start().starts_with("- ") {
            paths.extend(clean(line.trim_start().trim_start_matches("- ")));
        } else if !line.starts_with(char::is_whitespace) {
            in_paths = false;
        }
    }
    paths.truncate(16);
    (paths, body.trim_start_matches(['\r', '\n']))
}

/// Cap auto-memory at 200 lines / 25 KB (the spec's bound).
fn cap_auto_memory(text: &str) -> String {
    let mut out: Vec<&str> = text.lines().collect();
    out.truncate(AUTO_MEMORY_MAX_LINES);
    let mut s = out.join("\n");
    if s.len() > AUTO_MEMORY_MAX_BYTES {
        s.truncate(AUTO_MEMORY_MAX_BYTES);
        s.push_str("\n… (truncated at 25 KB)");
    }
    s
}

fn tool_description(name: &str) -> Option<&'static str> {
    Some(match name {
        "Read" => "Reads a file with line numbers (read before edit)",
        "Write" => "Creates or overwrites a file (atomic)",
        "Edit" => "Replaces an exact string in a file",
        "Glob" => "Lists files matching a glob pattern",
        "Grep" => "Searches file contents",
        "Bash" => "Runs a command in the working directory",
        "TaskStop" => "Stops a background command",
        "TaskOutput" => "Reads a background command's latest output",
        "calculator" => "Evaluates a math expression",
        "current_session" => "Reports session identity and usage",
        "list_models" => "Lists configured models",
        _ => return None,
    })
}

const BASE_INSTRUCTIONS: &str = r#"# ORBIT

You are ORBIT, an agent working in the operator's repository. You have
tools; use them to explore before you change anything, and prefer
reading over guessing.

- Read a file before editing it; keep edits minimal and in the
  surrounding code's style.
- Run tests after changes when a test setup exists.
- Never invent facts: report what the tools returned, and say when
  something failed.
- Credentials and secrets never leave the machine: paths on the
  deny-read list are refused, and results are scanned before you see
  them.
- Commit messages are plain, first-person, and never mention tooling."#;

fn now_iso8601() -> String {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| {
            let secs = d.as_secs();
            // days since epoch → y/m/d (civil algorithm)
            let days = secs / 86_400;
            let (y, m, day) = civil_from_days(days as i64);
            let rem = secs % 86_400;
            format!(
                "{y:04}-{m:02}-{day:02}T{:02}:{:02}:{:02}Z",
                rem / 3600,
                (rem % 3600) / 60,
                rem % 60
            )
        })
        .unwrap_or_default()
}

fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

fn run_git(dir: &Path, args: &[&str]) -> Option<String> {
    std::process::Command::new("git")
        .args(args)
        .current_dir(dir)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|s| !s.is_empty())
}

fn run_git_lines(dir: &Path, args: &[&str], cap: usize) -> Vec<String> {
    run_git(dir, args)
        .map(|s| s.lines().take(cap).map(str::to_string).collect())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    /// The prompt says which part of it is project instructions, exactly
    /// (the memory files contain `##` headings of their own, so it cannot
    /// be found from the text afterwards).
    #[test]
    fn the_prompt_measures_its_memory_section() {
        let dir = std::env::temp_dir().join(format!("orbit-ctx-mem-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("CLAUDE.md"),
            "# Rules\n\n## Style\nKeep it small.\n\n## Testing\nRun the tests.\n",
        )
        .unwrap();
        let home = dir.join("home");
        std::fs::create_dir_all(&home).unwrap();
        let none = super::build_system_prompt(&home, &dir, "m", &[], "");
        let start = none.text.find("## Project instructions").unwrap();
        // With no mods the memory runs to the end.
        assert_eq!(none.text.len() - start, none.memory_bytes);
        assert!(
            none.text[start..].contains("## Testing"),
            "headings inside stay inside"
        );
        // With mods after it, the memory stops where they start.
        let with = super::build_system_prompt(&home, &dir, "m", &[], "be terse");
        let start = with.text.find("## Project instructions").unwrap();
        let mods = with.text.find("## Enabled mods").unwrap();
        assert_eq!(start + with.memory_bytes, mods);
        assert!(with.memory_bytes > "Keep it small.".len());
        let _ = std::fs::remove_dir_all(&dir);
    }

    use super::*;

    #[test]
    fn bare_prompt_skips_discovered_content_and_keeps_explicit_instructions() {
        const CHILD: &str = "ORBIT_BARE_CONTEXT_TEST_CHILD";
        if let Ok(mode) = std::env::var(CHILD) {
            let root = std::env::temp_dir().join(format!(
                "orbit-bare-context-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            let home = root.join("home");
            let project = root.join("project");
            std::fs::create_dir_all(&home).unwrap();
            std::fs::create_dir_all(home.join("skills/fixture")).unwrap();
            std::fs::create_dir_all(project.join(".claude/rules")).unwrap();
            std::fs::write(home.join("ORBIT.md"), "AUTO_HOME_MEMORY_SENTINEL").unwrap();
            std::fs::write(home.join("settings.toml"), "output_style = \"learning\"\n").unwrap();
            std::fs::write(project.join("AGENTS.md"), "AUTO_PROJECT_MEMORY_SENTINEL").unwrap();
            std::fs::write(
                project.join(".claude/rules/fixture.md"),
                "AUTO_RULE_SENTINEL",
            )
            .unwrap();
            std::fs::write(
                home.join("skills/fixture/SKILL.md"),
                "---\nname: fixture\ndescription: AUTO_SKILL_SENTINEL\n---\nSkill body.\n",
            )
            .unwrap();
            let prompt = build_system_prompt(
                &home,
                &project,
                "fixture-model",
                &["Read", "Skill", "Agent"],
                "AUTO_MOD_SENTINEL",
            );
            assert!(prompt.text.contains("## Tools"));
            assert!(prompt.text.contains("fixture-model"));
            assert!(prompt.text.contains("EXPLICIT_APPEND_SENTINEL"));
            for content in [
                "AUTO_HOME_MEMORY_SENTINEL",
                "AUTO_PROJECT_MEMORY_SENTINEL",
                "AUTO_RULE_SENTINEL",
                "AUTO_SKILL_SENTINEL",
                "AUTO_MOD_SENTINEL",
                "Work as a teacher.",
            ] {
                assert_eq!(
                    prompt.text.contains(content),
                    mode == "full",
                    "{mode}: {content}"
                );
            }
            assert_eq!(prompt.memory_bytes == 0, mode == "bare");
            std::fs::remove_dir_all(root).unwrap();
            return;
        }
        for (mode, bare) in [("full", "0"), ("bare", "1")] {
            let mut child = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "context::tests::bare_prompt_skips_discovered_content_and_keeps_explicit_instructions",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env(CHILD, mode)
                .env("ORBIT_BARE", bare)
                .env("ORBIT_CLAUDE_COMPAT", "0")
                .env("ORBIT_OUTPUT_STYLE", "")
                .env("ORBIT_APPEND_SYSTEM_PROMPT", "EXPLICIT_APPEND_SENTINEL")
                .env_remove("ORBIT_SETTINGS_FILE")
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .unwrap();
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
            while child.try_wait().unwrap().is_none() {
                if std::time::Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    panic!("isolated bare-context check timed out");
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            let output = child.wait_with_output().unwrap();
            assert!(
                output.status.success(),
                "{mode}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }

    #[test]
    fn snapshot_rendes_git_facts() {
        let dir = std::env::temp_dir();
        let snap = EnvSnapshot::probe(&dir, "test-model");
        let text = snap.render();
        assert!(text.contains("Working directory:"));
        assert!(text.contains("Model: test-model"));
        assert!(text.contains("Git repository:"));
    }

    #[test]
    fn memory_files_capped() {
        let long = "line\n".repeat(500);
        let capped = cap_auto_memory(&long);
        assert!(capped.lines().count() <= AUTO_MEMORY_MAX_LINES + 1);
    }

    #[test]
    fn date_algorithm_sane() {
        // 2026-10-02 is day 20728 since epoch.
        let (y, m, d) = civil_from_days(20_728);
        assert_eq!((y, m, d), (2026, 10, 2));
        // And the boundary the off-by-algorithm would break: 2000-02-29.
        let (y, m, d) = civil_from_days(11_016);
        assert_eq!((y, m, d), (2000, 2, 29));
    }

    #[test]
    fn import_tokens_skip_code_and_ordinary_at_signs() {
        let text = "See @docs/style.md and @~/notes.md.\nmail me@example.com, use `@not/this`\n```\n@fenced/file.md\n```\n@docs/style.md again\n";
        assert_eq!(import_tokens(text), ["docs/style.md", "~/notes.md"]);
    }

    #[test]
    fn imports_stay_inside_the_project_and_nest() {
        let root = std::env::temp_dir().join(format!("orbit-ctx-imp-{}", std::process::id()));
        let project = root.join("project");
        std::fs::create_dir_all(project.join("docs")).unwrap();
        std::fs::write(root.join("outside.md"), "OUTSIDE SECRET").unwrap();
        std::fs::write(
            project.join("CLAUDE.md"),
            "Rules: @docs/style.md @../outside.md @types/node @CLAUDE.md\n",
        )
        .unwrap();
        std::fs::write(
            project.join("docs/style.md"),
            "STYLE BODY, see @deeper.md\n",
        )
        .unwrap();
        std::fs::write(project.join("docs/deeper.md"), "DEEPER BODY @style.md\n").unwrap();
        let home = root.join("home");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::write(home.join("ORBIT.md"), "OPERATOR RULES\n").unwrap();
        let prompt = build_system_prompt(&home, &project, "m", &[], "").text;
        assert!(
            prompt.contains("OPERATOR RULES"),
            "the operator's own file is read"
        );
        assert!(prompt.contains("STYLE BODY"));
        assert!(
            prompt.contains("DEEPER BODY"),
            "imports nest, relative to the importer"
        );
        assert!(
            !prompt.contains("OUTSIDE SECRET"),
            "nothing from outside the project"
        );
        assert_eq!(
            prompt.matches("STYLE BODY").count(),
            1,
            "a cycle imports once"
        );
    }

    #[test]
    fn rules_load_whole_or_as_a_pointer_when_path_scoped() {
        let project = std::env::temp_dir().join(format!("orbit-ctx-rules-{}", std::process::id()));
        std::fs::create_dir_all(project.join(".claude/rules")).unwrap();
        std::fs::write(project.join(".claude/rules/always.md"), "ALWAYS RULE\n").unwrap();
        std::fs::write(
            project.join(".claude/rules/api.md"),
            "---\npaths:\n  - \"src/api/**/*.ts\"\n  - src/routes/**\n---\nSCOPED RULE BODY\n",
        )
        .unwrap();
        let home = project.join("home");
        std::fs::create_dir_all(&home).unwrap();
        let prompt = build_system_prompt(&home, &project, "m", &[], "").text;
        assert!(prompt.contains("ALWAYS RULE"));
        assert!(!prompt.contains("SCOPED RULE BODY"));
        assert!(
            prompt.contains("for src/api/**/*.ts, src/routes/**"),
            "{prompt}"
        );
        assert_eq!(
            rule_front_matter("---\npaths: [\"a/**\", b.rs]\n---\nbody").0,
            ["a/**", "b.rs"]
        );
        assert_eq!(rule_front_matter("no front matter").0, Vec::<String>::new());
    }

    #[test]
    fn a_custom_output_style_file_is_added_without_its_front_matter() {
        let root = std::env::temp_dir().join(format!("orbit-ctx-style-{}", std::process::id()));
        let (home, project) = (root.join("home"), root.join("project"));
        std::fs::create_dir_all(home.join("output-styles")).unwrap();
        std::fs::create_dir_all(&project).unwrap();
        std::fs::write(
            home.join("output-styles/terse.md"),
            "---\nname: terse\ndescription: short\n---\nANSWER IN ONE LINE\n",
        )
        .unwrap();
        std::fs::write(
            home.join("settings.toml"),
            "output_style = \"terse\"\n[permissions]\n",
        )
        .unwrap();
        if std::env::var_os("ORBIT_OUTPUT_STYLE").is_none() {
            let prompt = build_system_prompt(&home, &project, "m", &[], "").text;
            assert!(
                prompt.contains("## Output style\n\nANSWER IN ONE LINE"),
                "{prompt}"
            );
            assert!(!prompt.contains("description: short"));
            std::fs::write(home.join("settings.toml"), "output_style = \"default\"\n").unwrap();
            assert!(
                !build_system_prompt(&home, &project, "m", &[], "")
                    .text
                    .contains("## Output style")
            );
            std::fs::write(home.join("settings.toml"), "output_style = \"../etc\"\n").unwrap();
            assert!(output_style(&home, &project).is_none());
            std::fs::write(home.join("settings.toml"), "output_style = \"learning\"\n").unwrap();
            assert!(
                output_style(&home, &project)
                    .unwrap()
                    .contains("TODO(human)")
            );
        }
    }

    #[test]
    fn a_scoped_rule_applies_to_files_matching_its_patterns() {
        let project = std::env::temp_dir().join(format!(
            "orbit-ctx-scoped-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos())
        ));
        std::fs::create_dir_all(project.join(".claude/rules")).unwrap();
        std::fs::create_dir_all(project.join("src/api/v1")).unwrap();
        std::fs::create_dir_all(project.join("docs")).unwrap();
        std::fs::write(
            project.join(".claude/rules/api.md"),
            "---\npaths:\n  - \"src/api/**/*.{ts,tsx}\"\n---\nAPI RULE\n",
        )
        .unwrap();
        std::fs::write(
            project.join(".claude/rules/md.md"),
            "---\npaths: \"*.md\"\n---\nMARKDOWN RULE\n",
        )
        .unwrap();
        std::fs::write(project.join(".claude/rules/always.md"), "ALWAYS\n").unwrap();
        for file in [
            "src/api/v1/users.ts",
            "src/api/index.tsx",
            "src/api/v1/users.rs",
            "docs/guide.md",
        ] {
            std::fs::write(project.join(file), "x").unwrap();
        }
        let bodies = |file: &str| -> Vec<String> {
            scoped_rules_for(&project, &project.join(file))
                .into_iter()
                .map(|(_, body)| body.trim().to_owned())
                .collect()
        };
        assert_eq!(bodies("src/api/v1/users.ts"), ["API RULE"]);
        assert_eq!(bodies("src/api/index.tsx"), ["API RULE"]);
        assert!(bodies("src/api/v1/users.rs").is_empty());
        assert_eq!(bodies("docs/guide.md"), ["MARKDOWN RULE"]);
        assert!(scoped_rules_for(&project, Path::new("/etc/hostname")).is_empty());
        assert_eq!(
            expand_braces("a/{b,c}/*.{ts,tsx}").len(),
            4,
            "every combination"
        );
    }
}
