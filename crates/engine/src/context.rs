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
    build_system_prompt_for(
        home,
        working_dir,
        model,
        tool_names,
        mods_directive,
        claude_user_memory(home).as_deref(),
    )
}

/// [`build_system_prompt`] with the operator's Claude Code user memory file named
/// (`None`: it is not read). Split out so a test can point it at a scratch folder
/// instead of the real `~/.claude`.
pub fn build_system_prompt_for(
    home: &Path,
    working_dir: &Path,
    model: &str,
    tool_names: &[&str],
    mods_directive: &str,
    claude_user: Option<&Path>,
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
        // Managed, then the operator's own files, then the project's.
        let mut imports = ImportBudget::default();
        for (path, origin) in memory_files(home, working_dir, claude_user) {
            match open_instruction(&path, origin, working_dir) {
                Some(Opened::Text { text, size }) => {
                    let capped = cap_noting(&path, &text);
                    s.push_str(&format!(
                        "### {} ({} bytes)\n\n{}\n\n",
                        path.display(),
                        size,
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
                Some(Opened::Refused(why)) => note_refusal(&path, &why),
                None => {}
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

/// One instruction file the prompt reads, and what the cap does to it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstructionFile {
    pub path: PathBuf,
    /// Size on disk.
    pub bytes: u64,
    pub lines: usize,
    /// What the cap leaves out, in words, when it leaves something out.
    pub cut: Option<String>,
    /// Read because `claude_compat` is on: the operator's Claude Code user file.
    pub claude_compat: bool,
    /// Why the file is not read, when it is not: where a link in it leads.
    pub refused: Option<String>,
}

impl InstructionFile {
    /// One line for `/memory`: the file, its size, where it came from, and what the cap leaves out.
    pub fn describe(&self) -> String {
        if let Some(why) = &self.refused {
            return format!("{} · not read: {why}", self.path.display());
        }
        let mut line = format!("{} · {} bytes", self.path.display(), self.bytes);
        if self.claude_compat {
            line.push_str(" · read because claude_compat is on");
        }
        if let Some(cut) = &self.cut {
            line.push_str(&format!(" · cut: {cut}"));
        }
        line
    }
}

/// The instruction files the prompt reads, in the order it reads them: the managed file, the
/// operator's Claude Code user file when it is named, the operator's own `ORBIT.md`, then the
/// project's, each with where it comes from. Names that lead to nothing are left out, and each
/// file is listed once however many names reach it (a link, or `AGENTS.md` pointing at
/// `CLAUDE.md`): the first name wins. Whether what a name leads to is a regular file, and whether
/// it may be read, is [`open_instruction`]'s call.
fn memory_files(
    home: &Path,
    working_dir: &Path,
    claude_user: Option<&Path>,
) -> Vec<(PathBuf, Origin)> {
    let operator = |path: PathBuf| (path, Origin::Operator);
    let project = |rel: &&str| (working_dir.join(rel), Origin::Project);
    let mut candidates = vec![operator(PathBuf::from(MEMORY_FILES[0]))];
    candidates.extend(claude_user.map(|path| operator(path.to_path_buf())));
    candidates.push(operator(home.join("ORBIT.md")));
    candidates.extend(MEMORY_FILES[1..].iter().map(project));
    candidates.extend([".claude/CLAUDE.md", "CLAUDE.local.md"].iter().map(project));
    let mut seen = std::collections::HashSet::new();
    candidates
        .into_iter()
        .filter(|(path, _)| path.canonicalize().is_ok_and(|real| seen.insert(real)))
        .collect()
}

/// The operator's Claude Code user memory file, `$CLAUDE_CONFIG_DIR/CLAUDE.md` (default
/// `~/.claude/CLAUDE.md`), when `claude_compat` is on: it is one of the "own Claude Code
/// files" that switch opts into. `None` when the switch is off.
pub fn claude_user_memory(home: &Path) -> Option<PathBuf> {
    crate::hooks::claude_compat(home)
        .then(crate::hooks::claude_config_dir)
        .flatten()
        .map(|dir| dir.join("CLAUDE.md"))
}

/// The instruction files the prompt reads, with what the cap does to each.
pub fn instruction_report(home: &Path, working_dir: &Path) -> Vec<InstructionFile> {
    instruction_report_for(home, working_dir, claude_user_memory(home).as_deref())
}

/// [`instruction_report`] with the Claude Code user memory file named, as
/// [`build_system_prompt_for`] takes it.
pub fn instruction_report_for(
    home: &Path,
    working_dir: &Path,
    claude_user: Option<&Path>,
) -> Vec<InstructionFile> {
    let mut files: Vec<(PathBuf, Origin, bool)> = memory_files(home, working_dir, claude_user)
        .into_iter()
        .map(|(path, origin)| (path, origin, false))
        .collect();
    for dir in [".orbit/rules", ".claude/rules"] {
        let mut rules: Vec<PathBuf> = std::fs::read_dir(working_dir.join(dir))
            .into_iter()
            .flatten()
            .flatten()
            .map(|entry| entry.path())
            .filter(|path| path.extension().is_some_and(|ext| ext == "md"))
            .collect();
        rules.sort();
        files.extend(rules.into_iter().map(|path| (path, Origin::Project, true)));
    }
    files
        .into_iter()
        .filter_map(|(path, origin, is_rule)| {
            let claude_compat = claude_user.is_some_and(|claude| claude == path);
            let (text, size) = match open_instruction(&path, origin, working_dir)? {
                Opened::Text { text, size } => (text, size),
                Opened::Refused(why) => {
                    return Some(InstructionFile {
                        path,
                        bytes: 0,
                        lines: 0,
                        cut: None,
                        claude_compat,
                        refused: Some(why),
                    });
                }
            };
            // A rule's front matter is not part of what the prompt reads.
            let body = if is_rule {
                rule_front_matter(&text).1
            } else {
                text.as_str()
            };
            let capped = cap_instruction(body);
            Some(InstructionFile {
                claude_compat,
                path,
                bytes: size,
                lines: capped.lines,
                cut: capped.cut,
                refused: None,
            })
        })
        .collect()
}

/// The instruction files that exist for this home and project, in the
/// order the prompt reads them, with their sizes: what `/memory` lists.
pub fn instruction_files(home: &Path, working_dir: &Path) -> Vec<(PathBuf, u64)> {
    instruction_report(home, working_dir)
        .into_iter()
        .filter(|file| file.refused.is_none())
        .map(|file| (file.path, file.bytes))
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
        let Some((imported, _)) = read_instruction(&resolved) else {
            continue;
        };
        budget.seen.push(resolved.clone());
        out.push_str(&format!(
            "#### Imported by {}: {} ({} bytes)\n\n{}\n\n",
            from.display(),
            resolved.display(),
            imported.len(),
            cap_noting(&resolved, &imported)
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
        let (text, size) = match open_instruction(&path, Origin::Project, working_dir) {
            Some(Opened::Text { text, size }) => (text, size),
            Some(Opened::Refused(why)) => {
                note_refusal(&path, &why);
                continue;
            }
            None => continue,
        };
        let (paths, body) = rule_front_matter(&text);
        if paths.is_empty() {
            out.push_str(&format!(
                "### {} ({} bytes)\n\n{}\n\n",
                path.display(),
                size,
                cap_noting(&path, body)
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
            let text = match open_instruction(&path, Origin::Project, &root)? {
                Opened::Text { text, .. } => text,
                Opened::Refused(why) => {
                    note_refusal(&path, &why);
                    return None;
                }
            };
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
                .then(|| (path.display().to_string(), cap_noting(&path, body)))
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

/// The most of an instruction file that is read: the cap is 25 KB, so more is never used.
const READ_BOUND: u64 = 1024 * 1024;

/// What an instruction file holds, and how big it is on disk. Only a regular file is read, and at
/// most [`READ_BOUND`] of it: a named pipe called `CLAUDE.md` in a cloned repository would
/// otherwise make session start wait for ever. Text that is not UTF-8 is read with replacement
/// characters, as Claude Code reads it.
fn read_instruction(path: &Path) -> Option<(String, u64)> {
    use std::io::Read;
    let meta = std::fs::metadata(path).ok()?;
    if !meta.is_file() {
        return None;
    }
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .ok()?
        .take(READ_BOUND)
        .read_to_end(&mut bytes)
        .ok()?;
    Some((String::from_utf8_lossy(&bytes).into_owned(), meta.len()))
}

/// Where an instruction file comes from decides how far a link in it may lead. The operator's own
/// files are theirs to link anywhere that is not a key: their dotfiles, their Claude Code file. A
/// project's files arrive with the repository, and the prompt goes to the provider, so a link in
/// one must stay inside the project, as an `@import` must.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Origin {
    Operator,
    Project,
}

/// What opening an instruction file came to.
enum Opened {
    Text {
        text: String,
        size: u64,
    },
    /// Not read, and why.
    Refused(String),
}

/// Why `path` may not be read, when it may not. No instruction file may lead to what the deny-read
/// list names, and a project's files may not lead out of the project: a cloned repository's
/// `CLAUDE.md -> ../../.config/gh/hosts.yml` would put a token in the prompt. A name that leads to
/// nothing, or to something that is not a regular file, is not refused: it is just not there.
fn refusal(path: &Path, origin: Origin, project: &Path) -> Option<String> {
    let real = path.canonicalize().ok().filter(|real| real.is_file())?;
    if orbit_tools::is_deny_read(&real) {
        return Some(format!(
            "its real path {} is on the deny-read list",
            real.display()
        ));
    }
    let outside = origin == Origin::Project
        && !project
            .canonicalize()
            .is_ok_and(|root| real.starts_with(root));
    outside.then(|| format!("its real path {} is outside the project", real.display()))
}

/// Open an instruction file: refused before a byte of it is read when it leads where it may not,
/// else its text (see [`read_instruction`]). `None`: nothing there, or not a regular file.
fn open_instruction(path: &Path, origin: Origin, project: &Path) -> Option<Opened> {
    if let Some(why) = refusal(path, origin, project) {
        return Some(Opened::Refused(why));
    }
    read_instruction(path).map(|(text, size)| Opened::Text { text, size })
}

/// Tell the operator, once, that a file they may expect in the prompt is not in it.
fn note_refusal(path: &Path, why: &str) {
    crate::hooks::note_load_problem(format!("{} is not read: {why}", path.display()));
}

/// An instruction text after the cap, and what the cap did to it.
struct Capped {
    text: String,
    /// How many lines the whole text has.
    lines: usize,
    /// What the cap left out, in words, when it left something out.
    cut: Option<String>,
}

/// Cap an instruction text at 200 lines / 25 KB (the spec's bound). A cut is marked in the text
/// the model reads, on a character boundary: a cut at the byte limit used to land inside a
/// multi-byte character and panic.
fn cap_instruction(text: &str) -> Capped {
    let lines: Vec<&str> = text.lines().collect();
    let total = lines.len();
    let mut kept = lines[..total.min(AUTO_MEMORY_MAX_LINES)].join("\n");
    let by_lines = total > AUTO_MEMORY_MAX_LINES;
    let cut = if kept.len() > AUTO_MEMORY_MAX_BYTES {
        let mut end = AUTO_MEMORY_MAX_BYTES;
        while !kept.is_char_boundary(end) {
            end -= 1;
        }
        kept.truncate(end);
        kept.push_str("\n… (truncated at 25 KB)");
        Some(format!(
            "ORBIT reads the first 25 KB of its {} bytes and {total} line{}",
            text.len(),
            if total == 1 { "" } else { "s" }
        ))
    } else if by_lines {
        kept.push_str("\n… (truncated at 200 lines)");
        Some(format!(
            "ORBIT reads the first {AUTO_MEMORY_MAX_LINES} of its {total} lines"
        ))
    } else {
        None
    };
    Capped {
        text: kept,
        lines: total,
        cut,
    }
}

/// Cap auto-memory at 200 lines / 25 KB (the spec's bound).
fn cap_auto_memory(text: &str) -> String {
    cap_instruction(text).text
}

/// [`cap_auto_memory`] for a file the operator keeps: when it cuts something, the operator is
/// told once, with the file's name, because rules that never reach the model are not a thing to
/// find out about from its behaviour.
fn cap_noting(path: &Path, text: &str) -> String {
    let capped = cap_instruction(text);
    if let Some(cut) = &capped.cut {
        crate::hooks::note_load_problem(format!("{} is cut: {cut}", path.display()));
    }
    capped.text
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

    // ---- the operator's Claude Code user file, the caps, and what is read twice or not at all ----

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "orbit-ctx-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// An ORBIT home, a project, and a folder that stands in for `~/.claude`.
    fn tree(name: &str) -> (PathBuf, PathBuf, PathBuf, PathBuf) {
        let root = scratch(name);
        let (home, project, claude) =
            (root.join("home"), root.join("project"), root.join("claude"));
        for dir in [&home, &project, &claude] {
            std::fs::create_dir_all(dir).unwrap();
        }
        (root, home, project, claude)
    }

    fn prompt_with_claude_file(home: &Path, project: &Path, claude: Option<&Path>) -> String {
        build_system_prompt_for(home, project, "m", &[], "", claude).text
    }

    /// 25,600 bytes is not a multiple of 3, so a cut at the byte limit lands inside a
    /// three-byte character (`—`): `String::truncate` panicked there.
    #[test]
    fn the_byte_cap_never_cuts_a_character_in_two() {
        for pad in 0..4 {
            for unit in ["—", "é", "🙂", "→"] {
                let text = format!("{}{}", "a".repeat(pad), unit.repeat(20_000));
                let capped = cap_auto_memory(&text);
                assert!(
                    capped.contains("truncated at 25 KB"),
                    "pad {pad} unit {unit}"
                );
                assert!(
                    capped.len() <= AUTO_MEMORY_MAX_BYTES + 64,
                    "{} bytes",
                    capped.len()
                );
            }
        }
    }

    #[test]
    fn a_cut_at_the_line_limit_says_so() {
        let many: String = (1..=300).map(|n| format!("line {n}\n")).collect();
        let capped = cap_auto_memory(&many);
        assert!(capped.contains("line 200") && !capped.contains("line 201"));
        assert!(
            capped.trim_end().ends_with("(truncated at 200 lines)"),
            "{capped}"
        );
        // A file that fits is not marked.
        let exact: String = (1..=200).map(|n| format!("line {n}\n")).collect();
        assert!(!cap_auto_memory(&exact).contains("truncated"));
    }

    #[test]
    fn the_claude_user_file_is_read_between_the_managed_and_the_orbit_user_file() {
        let (root, home, project, claude) = tree("compat-order");
        std::fs::write(claude.join("CLAUDE.md"), "CLAUDE USER RULES\n").unwrap();
        std::fs::write(home.join("ORBIT.md"), "ORBIT USER RULES\n").unwrap();
        std::fs::write(project.join("CLAUDE.md"), "PROJECT RULES\n").unwrap();
        let file = claude.join("CLAUDE.md");
        let prompt = prompt_with_claude_file(&home, &project, Some(&file));
        let at = |needle: &str| {
            prompt
                .find(needle)
                .unwrap_or_else(|| panic!("{needle} missing"))
        };
        assert!(at("CLAUDE USER RULES") < at("ORBIT USER RULES"));
        assert!(at("ORBIT USER RULES") < at("PROJECT RULES"));
        assert!(
            prompt.contains(&format!("### {} (18 bytes)", file.display())),
            "the header names the file: {prompt}"
        );
        // Named by the report, and marked as read because of the switch.
        let report = instruction_report_for(&home, &project, Some(&file));
        let entry = report.iter().find(|f| f.path == file).expect("listed");
        assert!(entry.claude_compat && entry.bytes == 18, "{entry:?}");
        assert_eq!(report.iter().filter(|f| f.claude_compat).count(), 1);
        // Without the file named, nothing extra is read.
        let without = prompt_with_claude_file(&home, &project, None);
        assert!(!without.contains("CLAUDE USER RULES"));
        assert!(
            instruction_report_for(&home, &project, None)
                .iter()
                .all(|f| !f.claude_compat)
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn a_file_reached_twice_is_read_once() {
        let (root, home, project, claude) = tree("twice");
        std::fs::write(project.join("CLAUDE.md"), "SHARED RULES\n").unwrap();
        std::os::unix::fs::symlink(project.join("CLAUDE.md"), project.join("AGENTS.md")).unwrap();
        // The operator links their Claude file in as ORBIT.md, and the switch reads it too.
        std::fs::write(claude.join("CLAUDE.md"), "LINKED USER RULES\n").unwrap();
        std::os::unix::fs::symlink(claude.join("CLAUDE.md"), home.join("ORBIT.md")).unwrap();
        let file = claude.join("CLAUDE.md");
        let prompt = prompt_with_claude_file(&home, &project, Some(&file));
        assert_eq!(prompt.matches("SHARED RULES").count(), 1, "{prompt}");
        assert_eq!(prompt.matches("LINKED USER RULES").count(), 1, "{prompt}");
        let listed = instruction_files(&home, &project);
        assert_eq!(
            listed
                .iter()
                .filter(|(path, _)| path.ends_with("AGENTS.md") || path.ends_with("CLAUDE.md"))
                .count(),
            1,
            "the project's linked pair is one entry: {listed:?}"
        );
        assert_eq!(
            listed.len(),
            2,
            "that one and the linked ORBIT.md: {listed:?}"
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn imports_from_the_claude_user_file_stay_in_its_folder_or_the_project() {
        let (root, home, project, claude) = tree("compat-imports");
        std::fs::write(root.join("outside.md"), "OUTSIDE SECRET").unwrap();
        std::fs::write(claude.join("style.md"), "CLAUDE STYLE BODY").unwrap();
        std::fs::write(project.join("local.md"), "PROJECT NOTES BODY").unwrap();
        std::fs::write(
            claude.join("CLAUDE.md"),
            format!(
                "Style: @style.md and @{} and @../outside.md\n",
                project.join("local.md").display()
            ),
        )
        .unwrap();
        let file = claude.join("CLAUDE.md");
        let prompt = prompt_with_claude_file(&home, &project, Some(&file));
        assert!(prompt.contains("CLAUDE STYLE BODY"), "its own folder");
        assert!(prompt.contains("PROJECT NOTES BODY"), "the project");
        assert!(!prompt.contains("OUTSIDE SECRET"), "nothing else");
        std::fs::remove_dir_all(root).unwrap();
    }

    /// A named pipe called `CLAUDE.md` in a cloned repository made `read_to_string` wait for ever.
    #[cfg(unix)]
    #[test]
    fn a_pipe_or_a_folder_with_an_instruction_name_is_skipped() {
        let (root, home, project, _claude) = tree("not-regular");
        let made = std::process::Command::new("mkfifo")
            .arg(project.join("CLAUDE.md"))
            .status()
            .map(|status| status.success())
            .unwrap_or(false);
        assert!(made, "mkfifo is needed for this test");
        std::fs::create_dir_all(project.join("AGENTS.md")).unwrap();
        std::fs::write(project.join("ORBIT.md"), "REGULAR RULES\n").unwrap();
        let (sender, receiver) = std::sync::mpsc::channel();
        let (home2, project2) = (home.clone(), project.clone());
        std::thread::spawn(move || {
            let _ = sender.send(build_system_prompt_for(
                &home2,
                &project2,
                "m",
                &[],
                "",
                None,
            ));
        });
        let prompt = receiver
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("the session starts even though a pipe is named CLAUDE.md")
            .text;
        assert!(prompt.contains("REGULAR RULES"));
        assert!(
            instruction_files(&home, &project)
                .iter()
                .all(|(path, _)| path.ends_with("ORBIT.md")),
            "only the regular file is listed"
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn an_instruction_file_is_read_bounded_and_keeps_its_size_on_disk() {
        let root = scratch("bounded");
        let file = root.join("CLAUDE.md");
        std::fs::write(&file, "x".repeat(3 * 1024 * 1024)).unwrap();
        let (text, size) = read_instruction(&file).expect("a regular file is read");
        assert_eq!(size, 3 * 1024 * 1024, "the size on disk");
        assert!(text.len() <= 1024 * 1024, "{} bytes read", text.len());
        assert!(read_instruction(&root).is_none(), "a folder is not a file");
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn the_report_says_what_the_cap_leaves_out() {
        let (root, home, project, _claude) = tree("report");
        let many: String = (1..=231).map(|n| format!("rule {n}\n")).collect();
        std::fs::write(project.join("CLAUDE.md"), &many).unwrap();
        std::fs::write(project.join("AGENTS.md"), "short\n").unwrap();
        let report = instruction_report_for(&home, &project, None);
        let long = report
            .iter()
            .find(|f| f.path.ends_with("CLAUDE.md"))
            .unwrap();
        assert_eq!(long.lines, 231);
        let cut = long.cut.as_deref().expect("a cut file says so");
        assert!(cut.contains("200") && cut.contains("231"), "{cut}");
        let short = report
            .iter()
            .find(|f| f.path.ends_with("AGENTS.md"))
            .unwrap();
        assert_eq!((short.lines, short.cut.as_deref()), (1, None));
        // The bytes cap, with few lines.
        std::fs::write(
            project.join("ORBIT.md"),
            format!("{}\n", "y".repeat(40_000)),
        )
        .unwrap();
        let report = instruction_report_for(&home, &project, None);
        let wide = report
            .iter()
            .find(|f| f.path.ends_with("ORBIT.md"))
            .unwrap();
        assert!(
            wide.cut.as_deref().is_some_and(|cut| cut.contains("25 KB")
                && cut.contains("40001")
                && cut.ends_with("1 line")),
            "{wide:?}"
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    /// The public builder reads the operator's Claude file exactly when the switch is on:
    /// through `ORBIT_CLAUDE_COMPAT`, or `claude_compat = true` in `settings.toml`. A child
    /// process carries the environment, as the bare-mode check does.
    #[test]
    fn the_switch_decides_whether_the_public_builder_reads_the_claude_file() {
        const CHILD: &str = "ORBIT_CLAUDE_USER_FILE_TEST_ROOT";
        if let Some(root) = std::env::var_os(CHILD) {
            let root = PathBuf::from(root);
            let want = std::env::var("ORBIT_CLAUDE_USER_FILE_TEST_WANT").unwrap() == "yes";
            let prompt =
                build_system_prompt(&root.join("home"), &root.join("project"), "m", &[], "").text;
            assert_eq!(prompt.contains("CLAUDE USER RULES"), want, "{prompt}");
            return;
        }
        for (label, env, settings, want) in [
            ("env on", Some("1"), "", "yes"),
            (
                "env off beats settings",
                Some("0"),
                "claude_compat = true\n",
                "no",
            ),
            ("settings on", None, "claude_compat = true\n", "yes"),
            ("nothing on", None, "", "no"),
        ] {
            let (root, home, _project, claude) = tree("switch");
            std::fs::write(claude.join("CLAUDE.md"), "CLAUDE USER RULES\n").unwrap();
            std::fs::write(home.join("settings.toml"), settings).unwrap();
            let mut child = std::process::Command::new(std::env::current_exe().unwrap());
            child
                .args([
                    "--exact",
                    "context::tests::the_switch_decides_whether_the_public_builder_reads_the_claude_file",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env(CHILD, &root)
                .env("ORBIT_CLAUDE_USER_FILE_TEST_WANT", want)
                .env("CLAUDE_CONFIG_DIR", &claude)
                .env("ORBIT_BARE", "0")
                .env("ORBIT_OUTPUT_STYLE", "")
                .env_remove("ORBIT_SETTINGS_FILE")
                .env_remove("ORBIT_CLAUDE_COMPAT");
            if let Some(value) = env {
                child.env("ORBIT_CLAUDE_COMPAT", value);
            }
            let output = child.output().unwrap();
            assert!(
                output.status.success(),
                "{label}: {}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            std::fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn a_memory_line_says_where_the_file_came_from_and_what_is_cut() {
        let plain = InstructionFile {
            path: "/p/AGENTS.md".into(),
            bytes: 5,
            lines: 1,
            cut: None,
            claude_compat: false,
            refused: None,
        };
        assert_eq!(plain.describe(), "/p/AGENTS.md · 5 bytes");
        let user = InstructionFile {
            path: "/h/.claude/CLAUDE.md".into(),
            bytes: 4_096,
            lines: 80,
            cut: None,
            claude_compat: true,
            refused: None,
        };
        assert_eq!(
            user.describe(),
            "/h/.claude/CLAUDE.md · 4096 bytes · read because claude_compat is on"
        );
        let cut = InstructionFile {
            cut: Some("ORBIT reads the first 200 of its 231 lines".into()),
            ..plain
        };
        assert_eq!(
            cut.describe(),
            "/p/AGENTS.md · 5 bytes · cut: ORBIT reads the first 200 of its 231 lines"
        );
    }

    #[test]
    fn the_caps_are_exactly_200_lines_and_25_kb() {
        assert_eq!(
            (AUTO_MEMORY_MAX_LINES, AUTO_MEMORY_MAX_BYTES),
            (200, 25 * 1024)
        );
        let fits = "x".repeat(25 * 1024);
        assert!(cap_instruction(&fits).cut.is_none(), "25 KB itself fits");
        assert!(
            cap_instruction(&format!("{fits}x")).cut.is_some(),
            "one byte more is cut"
        );
        let lines_200: String = (0..200).map(|_| "x\n").collect();
        assert!(cap_instruction(&lines_200).cut.is_none(), "200 lines fit");
        let lines_201: String = (0..201).map(|_| "x\n").collect();
        assert!(
            cap_instruction(&lines_201).cut.is_some(),
            "one line more is cut"
        );
    }

    /// A rule's front matter is not part of what the prompt reads, so it is not part of what the
    /// cap counts: 199 lines of rule behind a 4-line header are not cut.
    #[test]
    fn the_report_counts_a_rules_body_and_not_its_front_matter() {
        let (root, home, project, _claude) = tree("rule-body");
        std::fs::create_dir_all(project.join(".claude/rules")).unwrap();
        let body: String = (1..=199).map(|n| format!("rule {n}\n")).collect();
        std::fs::write(
            project.join(".claude/rules/api.md"),
            format!("---\npaths:\n  - \"src/**\"\n---\n{body}"),
        )
        .unwrap();
        let report = instruction_report_for(&home, &project, None);
        let rule = report.iter().find(|f| f.path.ends_with("api.md")).unwrap();
        assert_eq!((rule.lines, rule.cut.as_deref()), (199, None), "{rule:?}");
        std::fs::remove_dir_all(root).unwrap();
    }

    /// The header says how big the file is on disk, not how much of it was read.
    #[test]
    fn the_prompt_header_names_the_size_on_disk() {
        let (root, home, project, _claude) = tree("header-size");
        std::fs::write(project.join("CLAUDE.md"), "x".repeat(3 * 1024 * 1024)).unwrap();
        let prompt = prompt_with_claude_file(&home, &project, None);
        assert!(prompt.contains("CLAUDE.md (3145728 bytes)"));
        std::fs::remove_dir_all(root).unwrap();
    }

    /// A pipe can be named as a rule too; the report does not wait for it.
    #[cfg(unix)]
    #[test]
    fn a_pipe_named_as_a_rule_does_not_stop_the_report() {
        let (root, home, project, _claude) = tree("rule-pipe");
        std::fs::create_dir_all(project.join(".claude/rules")).unwrap();
        let made = std::process::Command::new("mkfifo")
            .arg(project.join(".claude/rules/pipe.md"))
            .status()
            .map(|status| status.success())
            .unwrap_or(false);
        assert!(made, "mkfifo is needed for this test");
        std::fs::write(project.join(".claude/rules/real.md"), "REAL RULE\n").unwrap();
        let (sender, receiver) = std::sync::mpsc::channel();
        let (home2, project2) = (home.clone(), project.clone());
        std::thread::spawn(move || {
            let _ = sender.send(instruction_report_for(&home2, &project2, None));
        });
        let report = receiver
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("the report is made even though a pipe is named as a rule");
        assert_eq!(report.len(), 1, "{report:?}");
        assert!(report[0].path.ends_with("real.md"));
        std::fs::remove_dir_all(root).unwrap();
    }

    // ---- a link in an instruction file: where it may lead ----

    /// A repository ships its own `CLAUDE.md`, and a link in it can lead anywhere on the machine
    /// (`CLAUDE.md -> ../../.config/gh/hosts.yml`). An `@import` already may not lead to what the
    /// deny-read list names, or out of the project. The files themselves were read from wherever a
    /// link pointed, and the prompt goes to the provider.
    #[cfg(unix)]
    #[test]
    fn a_project_file_that_leads_to_a_key_or_out_of_the_project_is_not_read() {
        let (root, home, project, _claude) = tree("links-out");
        std::fs::create_dir_all(root.join("outside")).unwrap();
        for dir in [".claude/rules", ".orbit/rules"] {
            std::fs::create_dir_all(project.join(dir)).unwrap();
        }
        // (link, where it leads, what is there, what the refusal says)
        let cases = [
            (
                "CLAUDE.md",
                "../outside/id_rsa_made_up",
                "MADE-UP KEY ONE",
                "deny-read",
            ),
            (
                ".claude/CLAUDE.md",
                "../../outside/.env",
                "MADE-UP KEY TWO",
                "deny-read",
            ),
            (
                "AGENTS.md",
                "../outside/notes.md",
                "OUTSIDE NOTES ONE",
                "outside the project",
            ),
            (
                "CLAUDE.local.md",
                "../outside/more-notes.md",
                "OUTSIDE NOTES TWO",
                "outside the project",
            ),
            (
                ".orbit/ORBIT.md",
                "../../outside/other-notes.md",
                "OUTSIDE NOTES THREE",
                "outside the project",
            ),
            (
                ".claude/rules/key.md",
                "../../../outside/credentials.json",
                "MADE-UP KEY THREE",
                "deny-read",
            ),
            (
                ".orbit/rules/notes.md",
                "../../../outside/rule-notes.md",
                "OUTSIDE NOTES FOUR",
                "outside the project",
            ),
        ];
        for (name, target, text, _) in cases {
            let at = root
                .join("outside")
                .join(Path::new(target).file_name().unwrap());
            std::fs::write(at, format!("{text}\n")).unwrap();
            std::os::unix::fs::symlink(target, project.join(name)).unwrap();
        }
        let prompt = prompt_with_claude_file(&home, &project, None);
        let report = instruction_report_for(&home, &project, None);
        for (name, _, text, why) in cases {
            assert!(
                !prompt.contains(text),
                "{name}: what it leads to reached the prompt"
            );
            let entry = report
                .iter()
                .find(|file| file.path == project.join(name))
                .unwrap_or_else(|| panic!("{name} is listed, so /memory and doctor can say why"));
            let reason = entry
                .refused
                .as_deref()
                .unwrap_or_else(|| panic!("{name} is marked as not read: {entry:?}"));
            assert!(reason.contains(why), "{name}: {reason}");
            assert!(entry.bytes == 0 && entry.cut.is_none(), "{entry:?}");
        }
        assert!(
            instruction_files(&home, &project).is_empty(),
            "nothing of that is read"
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    /// A path-scoped rule is delivered with the first read of a matching file, and listed in the
    /// prompt before that: neither may come from outside the project.
    #[cfg(unix)]
    #[test]
    fn a_path_scoped_rule_that_leads_out_of_the_project_is_neither_listed_nor_delivered() {
        let (root, home, project, _claude) = tree("links-scoped");
        std::fs::create_dir_all(root.join("outside")).unwrap();
        std::fs::write(
            root.join("outside/shared-rule.md"),
            "---\npaths: [\"src/**\"]\n---\nOUTSIDE SCOPED RULE\n",
        )
        .unwrap();
        std::fs::create_dir_all(project.join(".claude/rules")).unwrap();
        std::os::unix::fs::symlink(
            "../../../outside/shared-rule.md",
            project.join(".claude/rules/shared.md"),
        )
        .unwrap();
        std::fs::write(
            project.join(".claude/rules/own.md"),
            "---\npaths: [\"src/**\"]\n---\nOWN SCOPED RULE\n",
        )
        .unwrap();
        std::fs::create_dir_all(project.join("src")).unwrap();
        std::fs::write(project.join("src/a.rs"), "x").unwrap();
        let delivered = scoped_rules_for(&project, &project.join("src/a.rs"));
        assert_eq!(delivered.len(), 1, "{delivered:?}");
        assert!(delivered[0].1.contains("OWN SCOPED RULE"), "{delivered:?}");
        let prompt = prompt_with_claude_file(&home, &project, None);
        assert!(
            prompt.contains("own.md") && !prompt.contains("shared.md"),
            "{prompt}"
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    /// The operator's own files are theirs to link anywhere that is not a key: their dotfiles, their
    /// Claude Code file. A key is refused for them too.
    #[cfg(unix)]
    #[test]
    fn the_operators_own_links_are_read_unless_they_lead_to_a_key() {
        let (root, home, project, claude) = tree("links-operator");
        std::fs::create_dir_all(project.join("docs")).unwrap();
        std::fs::write(project.join("docs/shared.md"), "SHARED INSIDE\n").unwrap();
        std::os::unix::fs::symlink("docs/shared.md", project.join("CLAUDE.md")).unwrap();
        std::fs::write(root.join("dotfiles.md"), "ORBIT HOME DOTFILE\n").unwrap();
        std::os::unix::fs::symlink("../dotfiles.md", home.join("ORBIT.md")).unwrap();
        std::fs::write(root.join("claude-dotfiles.md"), "CLAUDE USER DOTFILE\n").unwrap();
        std::os::unix::fs::symlink("../claude-dotfiles.md", claude.join("CLAUDE.md")).unwrap();
        let file = claude.join("CLAUDE.md");
        let prompt = prompt_with_claude_file(&home, &project, Some(&file));
        for text in ["SHARED INSIDE", "ORBIT HOME DOTFILE", "CLAUDE USER DOTFILE"] {
            assert_eq!(prompt.matches(text).count(), 1, "{text}: {prompt}");
        }
        assert!(
            instruction_report_for(&home, &project, Some(&file))
                .iter()
                .all(|file| file.refused.is_none())
        );
        // Now both of the operator's files lead to keys.
        std::fs::write(root.join("id_rsa_made_up"), "MADE-UP KEY FOUR\n").unwrap();
        std::fs::write(root.join("credentials.json"), "MADE-UP KEY FIVE\n").unwrap();
        std::fs::remove_file(home.join("ORBIT.md")).unwrap();
        std::fs::remove_file(claude.join("CLAUDE.md")).unwrap();
        std::os::unix::fs::symlink("../id_rsa_made_up", home.join("ORBIT.md")).unwrap();
        std::os::unix::fs::symlink("../credentials.json", claude.join("CLAUDE.md")).unwrap();
        let prompt = prompt_with_claude_file(&home, &project, Some(&file));
        assert!(!prompt.contains("MADE-UP KEY"), "{prompt}");
        assert!(
            prompt.contains("SHARED INSIDE"),
            "the project's own link still reads"
        );
        let refused: Vec<_> = instruction_report_for(&home, &project, Some(&file))
            .into_iter()
            .filter(|file| file.refused.is_some())
            .collect();
        assert_eq!(refused.len(), 2, "{refused:?}");
        assert!(refused.iter().all(|file| {
            file.refused
                .as_deref()
                .is_some_and(|why| why.contains("deny-read"))
        }));
        std::fs::remove_dir_all(root).unwrap();
    }

    /// Only a regular file that a link takes somewhere it may not go is refused. A link to a
    /// folder, or to nothing, is just not there: nothing was going to be read.
    #[cfg(unix)]
    #[test]
    fn a_link_to_a_folder_or_to_nothing_is_absent_and_not_refused() {
        let (root, home, project, _claude) = tree("links-absent");
        std::fs::create_dir_all(root.join("outside-folder")).unwrap();
        std::os::unix::fs::symlink("../outside-folder", project.join("AGENTS.md")).unwrap();
        std::os::unix::fs::symlink("../nowhere.md", project.join("CLAUDE.md")).unwrap();
        let report = instruction_report_for(&home, &project, None);
        assert!(report.is_empty(), "{report:?}");
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn a_memory_line_for_a_refused_file_says_why_it_is_not_read() {
        let refused = InstructionFile {
            path: "/p/CLAUDE.md".into(),
            bytes: 0,
            lines: 0,
            cut: None,
            claude_compat: false,
            refused: Some("its real path /h/.ssh/id_rsa is on the deny-read list".into()),
        };
        assert_eq!(
            refused.describe(),
            "/p/CLAUDE.md · not read: its real path /h/.ssh/id_rsa is on the deny-read list"
        );
    }
}
