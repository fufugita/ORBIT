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
    {
        let trusted =
            orbit_tools::permissions::FolderTrust::new(home.to_path_buf()).is_trusted(working_dir);
        let skills = crate::skills::load_skills(home, trusted);
        if !skills.is_empty() {
            s.push_str("## Skills\n\n");
            s.push_str("Load a skill with the Skill tool when a task matches.\n\n");
            for sk in &skills {
                let first = sk.body.lines().next().unwrap_or("").trim();
                let purpose = first.trim_start_matches("# ").trim();
                s.push_str(&format!("- {}: {}\n", sk.name, purpose));
            }
            s.push('\n');
        }
    }

    // 3. Environment snapshot.
    let env = EnvSnapshot::probe(working_dir, model);
    s.push_str(&env.render());
    s.push('\n');

    // 4. Memory files, lowest scope first.
    s.push_str("## Project instructions\n\n");
    for rel in MEMORY_FILES {
        let path: PathBuf = if rel.starts_with('/') {
            PathBuf::from(rel)
        } else {
            working_dir.join(rel)
        };
        if let Ok(text) = std::fs::read_to_string(&path) {
            let capped = cap_auto_memory(&text);
            s.push_str(&format!(
                "### {} ({} bytes)\n\n{}\n\n",
                path.display(),
                text.len(),
                capped
            ));
        }
    }
    let _ = home; // managed scope /etc/orbit/ORBIT.md is in MEMORY_FILES

    // 5. Enabled mods' instructions (frozen here, not re-inserted).
    if !mods_directive.is_empty() {
        s.push_str("## Enabled mods\n\n");
        s.push_str(mods_directive);
        s.push_str("\n\n");
    }

    SystemPrompt { text: s }
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
    use super::*;

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
}
