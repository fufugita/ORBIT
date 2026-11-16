//! Custom slash commands: a Markdown file whose body is the prompt.
//!
//! `/name args` looks for `name.md` in, first match wins:
//!
//! 1. `.orbit/commands/` and `.claude/commands/` in a trusted project;
//! 2. `$ORBIT_HOME/commands/`;
//! 3. `~/.claude/commands/` (or `$CLAUDE_CONFIG_DIR/commands/`), when the
//!    operator turned on `claude_compat`.
//!
//! `/a:b` is `a/b.md`. YAML front matter is dropped. `$ARGUMENTS` becomes
//! the whole argument text and `$1`…`$9` its words; when the body uses
//! neither, the arguments are appended.
//!
//! `` !`command` `` in the body runs the command before the prompt is sent
//! and puts its output in that place, as in Claude Code, under these
//! conditions, all of them:
//!
//! * the file's own front matter allows it: `allowed-tools` names `Bash`, or
//!   a `Bash(pattern)` that matches the command after the arguments were
//!   put in (`Bash(git status:*)` and `Bash(git status *)` mean the same).
//!   A pattern speaks for one simple command: a line with `;`, `&&` or a
//!   pipe needs a pattern that spells out the whole line;
//! * no permission rule of the session denies it or asks about it, and no
//!   `PreToolUse` hook blocks it;
//! * the shell sandbox is up, and the command runs inside it;
//! * the session is not in plan mode and has not excluded `Bash`.
//!
//! `allowed-tools` also covers the turn the command starts: a call it names
//! (`Read`, `Bash(cargo test:*)`, `mcp__server__tool`) is not put to the
//! operator while that turn runs. It only answers the mode's own question.
//! A deny rule, a rule that asks, plan mode, an explicit `--allowedTools`
//! scope and hooks all still decide first, and a subagent the turn starts
//! does not inherit it. The grant ends with the next prompt.
//!
//! Otherwise the text is sent as written, with a note saying why. At most
//! [`MAX_SHELL_BLOCKS`] commands run per use, each for at most
//! [`SHELL_TIMEOUT_SECS`] seconds. `@file` is left to the prompt's own
//! file mentions.

use std::path::{Path, PathBuf};

const MAX_COMMAND_BYTES: u64 = 64 * 1024;
/// Commands one use of a command file may run.
pub const MAX_SHELL_BLOCKS: usize = 8;
/// How long each may take.
pub const SHELL_TIMEOUT_SECS: u64 = 20;
const MAX_SHELL_OUTPUT_CHARS: usize = 8 * 1024;

/// May this use of a command file run its `` !`command` `` lines?
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shell {
    /// Send them as written.
    Off,
    /// Run the ones the file's `allowed-tools` covers.
    On,
}

impl Shell {
    /// What the session's own scope permits: not in plan mode, and `Bash`
    /// neither excluded nor left out of an explicit allowlist.
    pub fn for_scope(scope: &crate::tool_runtime::PermissionScope) -> Self {
        let names_bash = |entry: &String| {
            orbit_tools::permissions::parse_rule(
                entry,
                orbit_tools::permissions::RuleEffectSerde::Allow,
            )
            .is_some_and(|rule| rule.tool == "Bash")
        };
        let off = scope.mode == orbit_tools::permissions::PermissionMode::Plan
            || scope.disallowlist.iter().any(names_bash)
            || scope
                .allowlist
                .as_ref()
                .is_some_and(|list| !list.iter().any(names_bash));
        if off { Shell::Off } else { Shell::On }
    }
}

fn valid_segment(segment: &str) -> bool {
    !segment.is_empty()
        && segment.len() <= 64
        && segment
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'))
}

fn roots(home: &Path, working_dir: &Path, project_trusted: bool) -> Vec<PathBuf> {
    let mut roots = Vec::new();
    if project_trusted {
        roots.push(working_dir.join(".orbit/commands"));
        roots.push(working_dir.join(".claude/commands"));
    }
    roots.push(home.join("commands"));
    if orbit_engine::hooks::claude_compat(home)
        && let Some(dir) = orbit_engine::hooks::claude_config_dir()
    {
        roots.push(dir.join("commands"));
    }
    roots
}

/// The prompt `/name args` stands for, or `None` when no such command file
/// exists where this session may read one.
pub fn prompt(
    home: &Path,
    working_dir: &Path,
    project_trusted: bool,
    name: &str,
    args: &str,
    shell: Shell,
) -> Option<String> {
    let segments: Vec<&str> = name.split(':').collect();
    if segments.len() > 4 || !segments.iter().all(|segment| valid_segment(segment)) {
        return None;
    }
    let relative: PathBuf = segments.iter().collect();
    for root in roots(home, working_dir, project_trusted) {
        let path = root.join(&relative).with_extension("md");
        let Ok(meta) = std::fs::metadata(&path) else {
            continue;
        };
        if !meta.is_file() || meta.len() > MAX_COMMAND_BYTES {
            continue;
        }
        if let Ok(text) = std::fs::read_to_string(&path) {
            let allowed = allowed_bash(front_matter(&text));
            if shell == Shell::Off || allowed.is_empty() {
                return Some(expand(body(&text), args.trim()));
            }
            let mut run =
                |command: &str| run_shell(home, working_dir, project_trusted, &allowed, command);
            return Some(expand_with(body(&text), args.trim(), &mut run));
        }
    }
    built_in(name)
        .map(|text| expand(text, args.trim()))
        .or_else(|| plugin_command(home, working_dir, name, args))
}

/// `/plugin:command` of an installed, enabled plugin: its prompt with the
/// arguments put in. A plugin's command never runs shell lines of its own
/// (`` !`…` `` stays text) and grants nothing: importing a plugin runs none
/// of its code, and neither does its command.
fn plugin_command(home: &Path, working_dir: &Path, name: &str, args: &str) -> Option<String> {
    if !name.contains(':') || crate::tools::bare_mode() {
        return None;
    }
    let catalog = orbit_engine::skills::load_catalog(home, working_dir, true).ok()?;
    let command = catalog
        .commands
        .into_iter()
        .find(|command| command.name == name)?;
    Some(expand(&command.prompt, args.trim()))
}

/// What a command file's `allowed-tools` lets the turn it starts do without
/// asking. Held on the session's tool context for that one turn.
#[derive(Debug, Clone, Default)]
pub struct TurnGrants(pub Vec<orbit_tools::permissions::PermissionRule>);

/// The `allowed-tools` of the command file `/name` stands for, as allow
/// rules. Empty when there is no such file or it names none.
pub fn turn_grants(
    home: &Path,
    working_dir: &Path,
    project_trusted: bool,
    name: &str,
) -> TurnGrants {
    let segments: Vec<&str> = name.split(':').collect();
    if segments.len() > 4 || !segments.iter().all(|segment| valid_segment(segment)) {
        return TurnGrants::default();
    }
    let relative: PathBuf = segments.iter().collect();
    for root in roots(home, working_dir, project_trusted) {
        let path = root.join(&relative).with_extension("md");
        let readable = std::fs::metadata(&path)
            .is_ok_and(|meta| meta.is_file() && meta.len() <= MAX_COMMAND_BYTES);
        if readable && let Ok(text) = std::fs::read_to_string(&path) {
            return TurnGrants(allowed_tools(front_matter(&text)));
        }
    }
    TurnGrants::default()
}

/// The model a command file asks for with `model:` in its front matter, for
/// the one turn the command starts. Held on the session's tool context.
#[derive(Debug, Clone, Default)]
pub struct TurnModel(pub Option<String>);

/// The `model:` of the command file `/name` stands for: a model
/// specification as `/model` takes it. `None` when the file names none, or
/// says `inherit`.
pub fn turn_model(
    home: &Path,
    working_dir: &Path,
    project_trusted: bool,
    name: &str,
) -> Option<String> {
    let segments: Vec<&str> = name.split(':').collect();
    if segments.len() > 4 || !segments.iter().all(|segment| valid_segment(segment)) {
        return None;
    }
    let relative: PathBuf = segments.iter().collect();
    for root in roots(home, working_dir, project_trusted) {
        let path = root.join(&relative).with_extension("md");
        let readable = std::fs::metadata(&path)
            .is_ok_and(|meta| meta.is_file() && meta.len() <= MAX_COMMAND_BYTES);
        if readable && let Ok(text) = std::fs::read_to_string(&path) {
            return front_matter(&text)
                .lines()
                .find_map(|line| line.trim().strip_prefix("model:"))
                .map(|value| value.trim().trim_matches(['"', '\'']).trim().to_owned())
                .filter(|spec| {
                    !spec.is_empty()
                        && spec != "inherit"
                        && spec.len() <= 200
                        && !spec.chars().any(|c| c.is_whitespace() || c.is_control())
                });
        }
    }
    None
}

/// Start a prompt's turn on the model its command file named, or on the
/// session's own.
pub fn set_turn_model(cx: &orbit_tools::ToolContext, model: Option<String>) {
    cx.set_ext(TurnModel(model));
}

/// The model the command that started this turn asked for, if any.
pub fn turn_model_of(cx: &orbit_tools::ToolContext) -> Option<String> {
    cx.ext::<TurnModel>().and_then(|model| model.0.clone())
}

/// Start a prompt's turn with these grants: a command's own, or none.
pub fn set_turn_grants(cx: &orbit_tools::ToolContext, grants: TurnGrants) {
    cx.set_ext(grants);
}

/// The skill the operator named with `/skill` to start this turn, if they
/// did: its load by the model is then the operator's own invocation, which
/// a skill marked `disable-model-invocation` accepts.
pub struct UserSkill(pub Option<String>);

/// Say which skill (if any) the operator started this turn with. Every
/// prompt sets it, so it never outlives its turn.
pub fn set_user_skill(cx: &orbit_tools::ToolContext, name: Option<String>) {
    cx.set_ext(UserSkill(name));
}

/// Did the operator start this turn by naming this skill?
pub fn user_invoked(cx: &orbit_tools::ToolContext, name: &str) -> bool {
    cx.ext::<UserSkill>()
        .is_some_and(|skill| skill.0.as_deref() == Some(name))
}

/// Add to what this turn may do without asking: a skill's own
/// `allowed-tools`, when the skill is loaded. They end with the turn, as a
/// command file's do (the next prompt sets the turn's grants afresh).
pub fn add_turn_grants(
    cx: &orbit_tools::ToolContext,
    more: Vec<orbit_tools::permissions::PermissionRule>,
) {
    let mut all = cx
        .ext::<TurnGrants>()
        .map(|grants| grants.0.clone())
        .unwrap_or_default();
    all.extend(more);
    all.truncate(256);
    cx.set_ext(TurnGrants(all));
}

/// Does the command that started this turn allow this call? `tool` and
/// `pattern` are the call's permission key (the tool's name and an empty
/// pattern for a tool without one).
pub fn turn_granted(cx: &orbit_tools::ToolContext, tool: &str, pattern: &str) -> bool {
    cx.ext::<TurnGrants>().is_some_and(|grants| {
        grants
            .0
            .iter()
            .any(|rule| rule.tool == tool && orbit_tools::permissions::rule_matches(rule, pattern))
    })
}

/// [`prompt`], then the `UserPromptExpansion` hook: `Some(Err(reason))` when
/// a hook refused the command, `None` when there is no such command. Every
/// front end expands a command through this, once per use.
pub fn expand_command(
    home: &Path,
    working_dir: &Path,
    project_trusted: bool,
    name: &str,
    args: &str,
    shell: Shell,
) -> Option<Result<String, String>> {
    let prompt = prompt(home, working_dir, project_trusted, name, args, shell)?;
    let outcomes = orbit_engine::hooks::Hooks::load(home, project_trusted).fire(
        orbit_engine::hooks::HookEvent::UserPromptExpansion,
        &serde_json::json!({
            "command_name": name,
            "command_args": args,
            "prompt": prompt,
        }),
    );
    Some(match orbit_engine::hooks::blocked(&outcomes) {
        Some(reason) => Err(reason),
        None => Ok(prompt),
    })
}

/// `/name args` as typed → (`name`, `args`), when it has the shape of a
/// custom command.
pub fn parse_invocation(line: &str) -> Option<(&str, &str)> {
    let rest = line.trim().strip_prefix('/')?;
    let (name, args) = rest
        .split_once(char::is_whitespace)
        .map_or((rest, ""), |(name, args)| (name, args.trim()));
    (name.split(':').count() <= 4 && name.split(':').all(valid_segment)).then_some((name, args))
}

/// One line about a command or skill for the interface's lists: printable,
/// short.
fn list_line(text: &str, fallback: &str) -> String {
    let line: String = text
        .lines()
        .next()
        .unwrap_or("")
        .trim()
        .trim_matches(['"', '\''])
        .chars()
        .filter(|c| !c.is_control())
        .take(72)
        .collect();
    if line.is_empty() {
        fallback.to_owned()
    } else {
        line
    }
}

/// What this session adds to the built-in commands, as `/name` and a line
/// about it: its command files, then the skills a person may invoke
/// (a plugin's as `/plugin:skill`). For the `/` list and the palette.
pub fn session_commands(
    home: &Path,
    working_dir: &Path,
    project_trusted: bool,
) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    for name in names(home, working_dir, project_trusted) {
        let header = roots(home, working_dir, project_trusted)
            .iter()
            .map(|root| root.join(&name).with_extension("md"))
            .find(|path| {
                std::fs::metadata(path)
                    .is_ok_and(|meta| meta.is_file() && meta.len() <= MAX_COMMAND_BYTES)
            })
            .and_then(|path| std::fs::read_to_string(path).ok())
            .map(|text| front_matter(&text).to_owned())
            .unwrap_or_default();
        let field = |key: &str| {
            header
                .lines()
                .find_map(|line| line.trim().strip_prefix(key))
                .unwrap_or("")
        };
        // `argument-hint: <issue> [priority]` leads the line, as the
        // arguments the command expects.
        let hint = list_line(field("argument-hint:"), "");
        let description = list_line(field("description:"), "command file");
        out.push((
            format!("/{name}"),
            if hint.is_empty() {
                description
            } else {
                list_line(&format!("{hint} · {description}"), "command file")
            },
        ));
    }
    if !crate::tools::bare_mode()
        && let Ok(catalog) = orbit_engine::skills::load_catalog(home, working_dir, true)
    {
        for command in catalog.commands {
            let name = format!("/{}", command.name);
            if !out.iter().any(|(known, _)| *known == name) {
                let description = list_line(&command.description, "plugin command");
                out.push((
                    name,
                    match command
                        .argument_hint
                        .as_deref()
                        .map(|hint| list_line(hint, ""))
                    {
                        Some(hint) if !hint.is_empty() => {
                            list_line(&format!("{hint} · {description}"), "plugin command")
                        }
                        _ => description,
                    },
                ));
            }
        }
        for entry in catalog.skills {
            let invocable = entry
                .policy
                .as_ref()
                .is_none_or(|policy| policy.user_invocable);
            let name = format!("/{}", entry.skill.name);
            if invocable && !out.iter().any(|(known, _)| *known == name) {
                out.push((name, list_line(&entry.skill.description, "skill")));
            }
        }
    }
    out
}

/// The prompt that runs a skill a person named with `/skill` or
/// `/plugin:skill`: the model loads it with the Skill tool, so the skill's
/// own tool ceiling, model and effort apply as for any other use of it.
/// `None` when there is no such skill or a person may not invoke it.
pub fn skill_prompt(cx: &orbit_tools::ToolContext, name: &str, args: &str) -> Option<String> {
    crate::plugin_content::resolve_skill(cx, name, crate::plugin_content::InvocationOrigin::User)
        .ok()?;
    let mut prompt =
        format!("Run the `{name}` skill: load it with the Skill tool and follow its instructions.");
    if !args.trim().is_empty() {
        prompt.push_str("\n\nARGUMENTS: ");
        prompt.push_str(args.trim());
    }
    Some(prompt)
}

/// Commands that are prompts and nothing more, used when no file of that
/// name exists.
fn built_in(name: &str) -> Option<&'static str> {
    Some(match name {
        "init" => {
            "Study this repository and write an ORBIT.md at its root for future sessions. \
             Read the README, the build and test configuration, and enough of the source to \
             understand the layout. Record only what a newcomer could not guess: how to build, \
             test and lint (exact commands, including running a single test), the architecture \
             that spans several files, and conventions the code actually follows. Keep it short \
             and specific; leave out generic advice and anything you did not verify. If an \
             ORBIT.md, AGENTS.md or CLAUDE.md already exists, improve it instead of replacing it."
        }
        "review" | "code-review" => {
            "Review the uncommitted changes in this repository (or the range or pull request \
             named in the arguments). Read the diff and the code around it. Report real \
             defects only, most severe first: for each, the file and line, what goes wrong and \
             on which input, and a concrete fix. Say plainly when you find none. Do not \
             restate what the change does and do not comment on style."
        }
        "recap" => {
            "Give a short recap of this session for someone returning to it: what the goal \
             is, what has been done and verified so far, what is in progress, and the next \
             step. Use only what is in this conversation; do not run tools."
        }
        "security-review" => {
            "Review the uncommitted changes in this repository (or the range named in the \
             arguments) for security defects only: injection, missing authorization, unsafe \
             deserialization, path traversal, secrets in code or logs, unsafe use of \
             cryptography, and trust placed in input an attacker controls. For each finding \
             give the file and line, how it is reached, the impact, and a fix. Leave out \
             anything you cannot trace to a reachable path."
        }
        _ => return None,
    })
}

/// The names available, for `/help`-style listings: sorted, de-duplicated.
pub fn names(home: &Path, working_dir: &Path, project_trusted: bool) -> Vec<String> {
    let mut out: Vec<String> = roots(home, working_dir, project_trusted)
        .iter()
        .filter_map(|root| std::fs::read_dir(root).ok())
        .flat_map(|entries| entries.flatten())
        .filter_map(|entry| {
            let path = entry.path();
            (path.extension().is_some_and(|ext| ext == "md") && path.is_file())
                .then(|| path.file_stem()?.to_str().map(str::to_owned))
                .flatten()
        })
        .filter(|name| valid_segment(name))
        .collect();
    out.sort();
    out.dedup();
    out.truncate(128);
    out
}

fn body(text: &str) -> &str {
    text.strip_prefix("---")
        .and_then(|rest| rest.find("\n---").map(|end| &rest[end + 4..]))
        .map_or(text, |body| {
            body.split_once('\n').map_or("", |(_, after)| after)
        })
}

/// The front matter of a command file: the text between its leading `---`
/// lines, or nothing.
fn front_matter(text: &str) -> &str {
    text.strip_prefix("---")
        .and_then(|rest| rest.find("\n---").map(|end| &rest[..end]))
        .unwrap_or("")
}

/// The `Bash` rules of a front matter's `allowed-tools`: an inline list
/// (`Bash(git status:*), Read`), a bracketed one, or one entry per `- `
/// line. Claude Code's `prefix:*` is read as `prefix *`.
fn allowed_bash(front: &str) -> Vec<orbit_tools::permissions::PermissionRule> {
    allowed_tools(front)
        .into_iter()
        .filter(|rule| rule.tool == "Bash")
        .collect()
}

/// Every rule of a front matter's `allowed-tools`, in the same three shapes.
fn allowed_tools(front: &str) -> Vec<orbit_tools::permissions::PermissionRule> {
    let mut lines = front.lines();
    let mut entries: Vec<String> = Vec::new();
    while let Some(line) = lines.next() {
        let Some(value) = line.trim().strip_prefix("allowed-tools:") else {
            continue;
        };
        let value = value.trim();
        if value.is_empty() {
            entries.extend(
                lines
                    .by_ref()
                    .map(str::trim)
                    .take_while(|item| item.starts_with('-'))
                    .map(|item| item.trim_start_matches('-').trim().to_owned()),
            );
        } else {
            // Commas inside parentheses belong to a pattern.
            let value = value.trim_start_matches('[').trim_end_matches(']');
            let (mut depth, mut item) = (0usize, String::new());
            for c in value.chars() {
                match c {
                    '(' => depth += 1,
                    ')' => depth = depth.saturating_sub(1),
                    ',' if depth == 0 => {
                        entries.push(std::mem::take(&mut item));
                        continue;
                    }
                    _ => {}
                }
                item.push(c);
            }
            entries.push(item);
        }
        break;
    }
    entries
        .iter()
        .map(|entry| entry.trim().trim_matches(['"', '\'']).trim())
        .filter_map(|entry| {
            orbit_tools::permissions::parse_rule(
                entry,
                orbit_tools::permissions::RuleEffectSerde::Allow,
            )
        })
        .filter(|rule| !rule.tool.contains(char::is_whitespace))
        .take(64)
        .map(|mut rule| {
            if let Some(prefix) = rule.pattern.strip_suffix(":*") {
                rule.pattern = format!("{prefix} *");
            }
            rule
        })
        .collect()
}

/// Run one `` !`command` `` of a command file and return what takes its
/// place: the command's output, or the text as written with the reason it
/// was not run.
fn run_shell(
    home: &Path,
    working_dir: &Path,
    project_trusted: bool,
    allowed: &[orbit_tools::permissions::PermissionRule],
    command: &str,
) -> String {
    use orbit_tools::permissions::RuleEffect;
    let unrun = |why: &str| format!("!`{command}` [not run: {why}]");
    if !allowed
        .iter()
        .any(|rule| orbit_tools::permissions::rule_matches(rule, command))
    {
        return unrun("the command file's allowed-tools does not cover it");
    }
    // The file's grant never outranks the session's own rules.
    let rules = match orbit_tools::executor::load_sourced_rules_in(home, working_dir) {
        Ok(entries) => orbit_tools::permissions::RuleSet {
            rules: entries
                .into_iter()
                .filter(|entry| !entry.shadowed)
                .map(|entry| entry.rule)
                .collect(),
        },
        Err(_) => return unrun("the permission rules could not be read"),
    };
    match rules.evaluate("Bash", command) {
        Some(RuleEffect::Deny) => return unrun("a permission rule denies it"),
        Some(RuleEffect::Ask) => {
            return unrun("a permission rule asks about it; run it yourself");
        }
        Some(RuleEffect::Allow) | None => {}
    }
    let fired = orbit_engine::hooks::Hooks::load(home, project_trusted).fire(
        orbit_engine::hooks::HookEvent::PreToolUse,
        &serde_json::json!({
            "tool": "Bash",
            "arguments": { "command": command },
            "source": "command-file",
        }),
    );
    if orbit_engine::hooks::blocked(&fired).is_some() {
        return unrun("a hook blocked it");
    }
    if !matches!(
        orbit_tools::sandbox::ShellSandbox::probe(),
        orbit_tools::sandbox::SandboxStatus::Confined
    ) {
        return unrun("the shell sandbox is not available here");
    }
    let cx = orbit_tools::ToolContext::new(
        home.to_path_buf(),
        "command-file".into(),
        working_dir.to_path_buf(),
    );
    let result = orbit_tools::bash::run_command(command, SHELL_TIMEOUT_SECS, &cx);
    let value: serde_json::Value = serde_json::from_str(&result.payload).unwrap_or_default();
    // A command still going at the limit was moved to the background: it is
    // stopped, not left running behind a prompt that never saw its output.
    if let Some(task) = value.get("task_id").and_then(serde_json::Value::as_str) {
        if let Some(stop) = orbit_tools::registry()
            .into_iter()
            .find(|tool| tool.name() == "TaskStop")
        {
            let _ = stop.run(&serde_json::json!({ "task_id": task }), &cx);
        }
        return unrun("it did not finish in time");
    }
    // What a command prints goes to the provider with the prompt: it gets
    // the secret scan every tool result gets.
    let output = orbit_tools::scan::scan_result(
        value
            .get("output")
            .and_then(serde_json::Value::as_str)
            .unwrap_or(""),
    )
    .text;
    let output: String = output
        .trim_end()
        .chars()
        .take(MAX_SHELL_OUTPUT_CHARS)
        .collect();
    match value.get("exit_code").and_then(serde_json::Value::as_i64) {
        Some(0) => output,
        Some(code) => format!("{output}\n[exit code {code}]")
            .trim_start()
            .to_owned(),
        None => unrun(
            value
                .get("error")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("it could not be started"),
        ),
    }
}

/// Put the arguments into one piece of a body: `$ARGUMENTS` and `$1`…`$9`.
fn substitute(text: &str, args: &str, words: &[&str], used: &mut bool) -> String {
    let mut out = String::with_capacity(text.len() + args.len());
    let mut rest = text;
    while let Some(at) = rest.find('$') {
        out.push_str(&rest[..at]);
        let after = &rest[at + 1..];
        if let Some(tail) = after.strip_prefix("ARGUMENTS") {
            out.push_str(args);
            *used = true;
            rest = tail;
        } else if let Some(digit) = after.chars().next().filter(|c| ('1'..='9').contains(c)) {
            let index = digit as usize - '1' as usize;
            out.push_str(words.get(index).copied().unwrap_or(""));
            *used = true;
            rest = &after[1..];
        } else {
            out.push('$');
            rest = after;
        }
    }
    out.push_str(rest);
    out
}

/// The body with its arguments in and its `` !`command` `` lines sent as
/// written.
fn expand(body: &str, args: &str) -> String {
    expand_with(body, args, &mut |command| format!("!`{command}`"))
}

/// The body with its arguments in. Each `` !`command` `` of the body itself
/// (never one that arrived inside the arguments) is given to `run` with its
/// arguments already in, and replaced by what `run` returns.
fn expand_with(body: &str, args: &str, run: &mut dyn FnMut(&str) -> String) -> String {
    let words: Vec<&str> = args.split_whitespace().collect();
    let mut out = String::with_capacity(body.len() + args.len());
    let mut used = false;
    let mut blocks = 0;
    let mut rest = body;
    while let Some(at) = rest.find("!`") {
        let after = &rest[at + 2..];
        // A command is on one line and closed on it.
        let command = after
            .find('`')
            .map(|end| &after[..end])
            .filter(|command| !command.contains('\n') && !command.trim().is_empty());
        let Some(command) = command else {
            out.push_str(&substitute(&rest[..at + 2], args, &words, &mut used));
            rest = after;
            continue;
        };
        out.push_str(&substitute(&rest[..at], args, &words, &mut used));
        let line = substitute(command.trim(), args, &words, &mut used);
        blocks += 1;
        if blocks <= MAX_SHELL_BLOCKS {
            out.push_str(&run(&line));
        } else {
            out.push_str(&format!(
                "!`{line}` [not run: too many commands in one file]"
            ));
        }
        rest = &after[command.len() + 1..];
    }
    out.push_str(&substitute(rest, args, &words, &mut used));
    let mut out = out.trim().to_owned();
    if !used && !args.is_empty() {
        out.push_str("\n\nARGUMENTS: ");
        out.push_str(args);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `allowed-tools` is read in its three shapes, only `Bash` entries
    /// count, and Claude Code's `prefix:*` means `prefix *`.
    #[test]
    fn the_bash_rules_of_a_front_matter_are_read() {
        let patterns = |front: &str| -> Vec<String> {
            allowed_bash(front)
                .into_iter()
                .map(|rule| rule.pattern)
                .collect()
        };
        assert_eq!(
            patterns(
                "description: x\nallowed-tools: Bash(git status:*), Read, Bash(git log -n 5, --oneline)"
            ),
            ["git status *", "git log -n 5, --oneline"]
        );
        assert_eq!(
            patterns("allowed-tools: [\"Bash(git diff *)\", 'Edit']"),
            ["git diff *"]
        );
        assert_eq!(
            patterns("allowed-tools:\n  - Bash(ls)\n  - Grep\n  - Bash\nmodel: x\n  - Bash(rm *)"),
            ["ls", ""],
            "the list ends where the next key begins"
        );
        assert!(patterns("description: no tools").is_empty());
        assert_eq!(
            front_matter("---\nallowed-tools: Bash\n---\nBody !`ls`\n"),
            "\nallowed-tools: Bash"
        );
        assert_eq!(front_matter("No front matter"), "");
    }

    /// `allowed-tools` covers the turn a command starts, for the calls it
    /// names and nothing else, and only while it is set.
    #[test]
    fn a_commands_allowed_tools_cover_its_own_turn() {
        let dir = std::env::temp_dir().join(format!("orbit-command-grant-{}", ulid::Ulid::new()));
        let (home, project) = (dir.join("home"), dir.join("project"));
        std::fs::create_dir_all(project.join(".orbit/commands")).unwrap();
        std::fs::create_dir_all(home.join("commands")).unwrap();
        std::fs::write(
            project.join(".orbit/commands/test.md"),
            "---\nallowed-tools: Bash(cargo test:*), Edit, mcp__tracker__create_issue\n---\nRun the tests.\n",
        )
        .unwrap();
        std::fs::write(home.join("commands/plain.md"), "No front matter.\n").unwrap();
        let cx = orbit_tools::ToolContext::new(home.clone(), "s".into(), project.clone());
        assert!(
            !turn_granted(&cx, "Edit", "/src/main.rs"),
            "nothing set yet"
        );

        set_turn_grants(&cx, turn_grants(&home, &project, true, "test"));
        assert!(turn_granted(&cx, "Bash", "cargo test --workspace"));
        assert!(turn_granted(&cx, "Edit", "/src/main.rs"));
        assert!(turn_granted(&cx, "mcp__tracker__create_issue", ""));
        assert!(!turn_granted(&cx, "Bash", "cargo test; rm -rf target"));
        assert!(!turn_granted(&cx, "Bash", "cargo publish"));
        assert!(!turn_granted(&cx, "Write", "/src/main.rs"));
        assert!(!turn_granted(&cx, "mcp__tracker__delete_issue", ""));

        // The same file may name the model for its turn.
        std::fs::write(
            home.join("commands/quick.md"),
            "---\nmodel: \"acme/small\"\n---\nBe quick.\n",
        )
        .unwrap();
        std::fs::write(
            home.join("commands/same.md"),
            "---\nmodel: inherit\n---\nGo.\n",
        )
        .unwrap();
        assert_eq!(
            turn_model(&home, &project, true, "quick").as_deref(),
            Some("acme/small")
        );
        assert_eq!(turn_model(&home, &project, true, "same"), None);
        assert_eq!(turn_model(&home, &project, true, "test"), None);
        assert_eq!(turn_model_of(&cx), None);
        set_turn_model(&cx, turn_model(&home, &project, true, "quick"));
        assert_eq!(turn_model_of(&cx).as_deref(), Some("acme/small"));
        set_turn_model(&cx, None);
        assert_eq!(turn_model_of(&cx), None);

        // An untrusted project's file grants nothing; neither does a file
        // without the key; the next prompt clears what was set.
        assert!(turn_grants(&home, &project, false, "test").0.is_empty());
        assert!(turn_grants(&home, &project, true, "plain").0.is_empty());
        assert!(turn_grants(&home, &project, true, "../test").0.is_empty());
        set_turn_grants(&cx, TurnGrants::default());
        assert!(!turn_granted(&cx, "Edit", "/src/main.rs"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The interface is told about command files with their description
    /// line, cleaned for a terminal.
    #[test]
    fn command_files_are_listed_with_a_line_about_each() {
        let dir = std::env::temp_dir().join(format!("orbit-command-list-{}", ulid::Ulid::new()));
        let (home, project) = (dir.join("home"), dir.join("project"));
        std::fs::create_dir_all(project.join(".orbit/commands")).unwrap();
        std::fs::create_dir_all(home.join("commands")).unwrap();
        std::fs::write(
            project.join(".orbit/commands/ship.md"),
            "---\ndescription: \"Cut a release\u{1b}[2J\"\n---\nDo it.\n",
        )
        .unwrap();
        std::fs::write(home.join("commands/tidy.md"), "Tidy up.\n").unwrap();
        std::fs::write(
            home.join("commands/triage.md"),
            "---\nargument-hint: \"<issue> [priority]\"\ndescription: Sort an issue\n---\nSort $1.\n",
        )
        .unwrap();
        let listed = session_commands(&home, &project, true);
        // The arguments a command expects lead its line.
        assert!(
            listed.contains(&(
                "/triage".into(),
                "<issue> [priority] · Sort an issue".into()
            )),
            "{listed:?}"
        );
        assert!(
            listed.contains(&("/ship".into(), "Cut a release[2J".into())),
            "{listed:?}"
        );
        assert!(
            listed.contains(&("/tidy".into(), "command file".into())),
            "{listed:?}"
        );
        let untrusted = session_commands(&home, &project, false);
        assert!(
            !untrusted.iter().any(|(name, _)| name == "/ship"),
            "{untrusted:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Commands of the body are handed to the runner with the arguments in;
    /// one that arrived inside the arguments is text; an unclosed or
    /// multi-line one is text; only so many run.
    #[test]
    fn body_commands_run_and_argument_text_does_not() {
        let mut seen = Vec::new();
        let mut run = |command: &str| {
            seen.push(command.to_owned());
            format!("<{command}>")
        };
        assert_eq!(
            expand_with(
                "Branch: !`git branch --show-current`\nLog for $1: !` git log $1 `\nNotes: $ARGUMENTS",
                "main !`rm -rf x`",
                &mut run
            ),
            "Branch: <git branch --show-current>\nLog for main: <git log main>\nNotes: main !`rm -rf x`"
        );
        assert_eq!(seen, ["git branch --show-current", "git log main"]);

        let mut none = |_: &str| -> String { panic!("nothing here is a command") };
        assert_eq!(
            expand_with("Wow!`\nnext !`` and !`a\nb` done", "", &mut none),
            "Wow!`\nnext !`` and !`a\nb` done"
        );

        let mut count = 0;
        let mut tally = |_: &str| {
            count += 1;
            "ok".to_owned()
        };
        let many = "!`true` ".repeat(MAX_SHELL_BLOCKS + 2);
        let out = expand_with(&many, "", &mut tally);
        assert_eq!(count, MAX_SHELL_BLOCKS);
        assert_eq!(out.matches("too many commands").count(), 2, "{out}");
        // Without a runner the text is sent as written.
        assert_eq!(expand("Now: !`date`", ""), "Now: !`date`");
    }

    /// What decides whether a command of a file runs: its own allowed-tools
    /// first, then the session's rules. Neither needs the sandbox to refuse.
    #[test]
    fn a_command_runs_only_when_the_file_and_the_session_allow_it() {
        let dir = std::env::temp_dir().join(format!("orbit-command-shell-{}", ulid::Ulid::new()));
        let (home, project) = (dir.join("home"), dir.join("project"));
        std::fs::create_dir_all(project.join(".orbit/commands")).unwrap();
        std::fs::create_dir_all(&home).unwrap();
        std::fs::write(
            home.join("settings.toml"),
            "[permissions]\ndeny = [\"Bash(git push *)\"]\nask = [\"Bash(git fetch *)\"]\n",
        )
        .unwrap();
        std::fs::write(
            project.join(".orbit/commands/sync.md"),
            "---\nallowed-tools: Bash(git status:*), Bash(git push:*), Bash(git fetch:*)\n---\nA !`git push origin` B !`git fetch origin` C !`rm -rf build` D !`git status; rm -rf build`\n",
        )
        .unwrap();
        let text = prompt(&home, &project, true, "sync", "", Shell::On).unwrap();
        assert!(
            text.contains("!`git push origin` [not run: a permission rule denies it]"),
            "{text}"
        );
        assert!(
            text.contains("!`git fetch origin` [not run: a permission rule asks about it"),
            "{text}"
        );
        assert!(
            text.contains(
                "!`rm -rf build` [not run: the command file's allowed-tools does not cover it]"
            ),
            "{text}"
        );
        assert!(
            text.contains("!`git status; rm -rf build` [not run: the command file's allowed-tools does not cover it]"),
            "an allowed prefix does not carry a second command: {text}"
        );
        // Off (plan mode, Bash excluded): everything is sent as written.
        let text = prompt(&home, &project, true, "sync", "", Shell::Off).unwrap();
        assert!(
            text.contains("A !`git push origin` B") && !text.contains("not run"),
            "{text}"
        );

        use crate::tool_runtime::PermissionScope;
        assert_eq!(Shell::for_scope(&PermissionScope::default()), Shell::On);
        assert_eq!(
            Shell::for_scope(&PermissionScope::from_flags(Some("plan"), None, None)),
            Shell::Off
        );
        assert_eq!(
            Shell::for_scope(&PermissionScope::from_flags(None, None, Some("Bash"))),
            Shell::Off
        );
        assert_eq!(
            Shell::for_scope(&PermissionScope::from_flags(None, Some("Read,Grep"), None)),
            Shell::Off
        );
        assert_eq!(
            Shell::for_scope(&PermissionScope::from_flags(
                None,
                Some("Read,Bash(git *)"),
                None
            )),
            Shell::On
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn fixture(tag: &str) -> (PathBuf, PathBuf) {
        let root = std::env::temp_dir().join(format!("orbit-cmds-{tag}-{}", std::process::id()));
        let (home, project) = (root.join("home"), root.join("project"));
        std::fs::create_dir_all(home.join("commands")).unwrap();
        std::fs::create_dir_all(project.join(".claude/commands/git")).unwrap();
        (home, project)
    }

    #[test]
    fn arguments_substitute_or_append() {
        assert_eq!(expand("Review $ARGUMENTS now", "pr 12"), "Review pr 12 now");
        assert_eq!(
            expand("Fix #$1 at $2 ($3)", "12 high"),
            "Fix #12 at high ()"
        );
        assert_eq!(expand("Costs $5.00 and $HOME", "x"), "Costs .00 and $HOME");
        assert_eq!(
            expand("Write tests.", "for the parser"),
            "Write tests.\n\nARGUMENTS: for the parser"
        );
        assert_eq!(expand("Write tests.\n", ""), "Write tests.");
    }

    #[test]
    fn an_invocation_splits_into_name_and_arguments() {
        assert_eq!(
            parse_invocation("/review  the diff "),
            Some(("review", "the diff"))
        );
        assert_eq!(parse_invocation("/git:sync"), Some(("git:sync", "")));
        for bad in ["review", "/", "/../x", "/a b:c d", "/a::b"] {
            let parsed = parse_invocation(bad);
            assert!(parsed.is_none() || bad == "/a b:c d", "{bad}: {parsed:?}");
        }
        assert_eq!(parse_invocation("/a b:c d"), Some(("a", "b:c d")));
    }

    #[test]
    fn front_matter_is_dropped() {
        assert_eq!(
            body("---\ndescription: x\nallowed-tools: Bash\n---\nDo it.\n"),
            "Do it.\n"
        );
        assert_eq!(body("No front matter\n"), "No front matter\n");
        assert_eq!(body("---\nunterminated\n"), "---\nunterminated\n");
    }

    #[test]
    fn project_commands_need_trust_and_names_stay_inside() {
        let (home, project) = fixture("trust");
        std::fs::write(
            project.join(".claude/commands/review.md"),
            "PROJECT REVIEW $ARGUMENTS",
        )
        .unwrap();
        std::fs::write(project.join(".claude/commands/git/sync.md"), "SYNC").unwrap();
        std::fs::write(home.join("commands/review.md"), "HOME REVIEW").unwrap();
        std::fs::write(home.join("commands/notes.md"), "NOTES").unwrap();

        assert_eq!(
            prompt(&home, &project, true, "review", " the diff ", Shell::Off).as_deref(),
            Some("PROJECT REVIEW the diff")
        );
        // Untrusted: the project's file is not read; the operator's is.
        assert_eq!(
            prompt(&home, &project, false, "review", "", Shell::Off).as_deref(),
            Some("HOME REVIEW")
        );
        assert_eq!(
            prompt(&home, &project, true, "git:sync", "", Shell::Off).as_deref(),
            Some("SYNC")
        );
        assert_eq!(
            prompt(&home, &project, false, "git:sync", "", Shell::Off),
            None
        );
        assert!(
            prompt(&home, &project, false, "init", "", Shell::Off)
                .unwrap()
                .contains("ORBIT.md")
        );
        assert!(
            prompt(
                &home,
                &project,
                false,
                "code-review",
                "HEAD~3..",
                Shell::Off
            )
            .unwrap()
            .ends_with("ARGUMENTS: HEAD~3..")
        );
        for bad in [
            "",
            "..",
            "../review",
            "a/b",
            "git:..",
            "a:b:c:d:e",
            "re view",
        ] {
            assert_eq!(
                prompt(&home, &project, true, bad, "", Shell::Off),
                None,
                "{bad}"
            );
        }
        let listed = names(&home, &project, true);
        assert!(listed.contains(&"review".to_string()) && listed.contains(&"notes".to_string()));
        assert_eq!(listed.iter().filter(|n| *n == "review").count(), 1);
    }
}
