//! Shell-facing output is usable directly; JSON stays an explicit interface.

use std::process::{Command, Output};

fn orbit(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_orbit"))
        .args(args)
        .env_clear()
        .output()
        .expect("CLI starts")
}

#[test]
fn completion_stdout_is_a_shell_script_and_json_remains_available() {
    for shell in ["bash", "zsh", "fish"] {
        let plain = orbit(&["completions", shell]);
        assert!(plain.status.success(), "{shell}: {:?}", plain.stderr);
        let script = String::from_utf8(plain.stdout).unwrap();
        assert!(
            script.starts_with('#'),
            "{shell}: missing shell script header"
        );
        assert!(!script.trim_start().starts_with('{'));
        if shell == "zsh" {
            assert!(script.lines().any(|line| line == "compdef _orbit orbit"));
            assert!(!script.lines().any(|line| line == "_orbit \"$@\""));
        }
        for verb in ["mcp", "compact", "recovery", "serve", "attach", "migrate"] {
            assert!(script.contains(verb), "{shell}: missing {verb}");
        }
        let json = orbit(&["completions", shell, "--json"]);
        assert!(json.status.success());
        let value: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
        assert_eq!(value["shell"], shell);
        assert_eq!(value["script"], script);
    }
}

#[test]
fn invalid_completion_arguments_fail_without_emitting_a_script() {
    for args in [
        vec!["completions", "powershell"],
        vec!["completions", "bash", "unexpected"],
        vec!["completions", "bash", "--json", "unexpected"],
    ] {
        let output = orbit(&args);
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert!(String::from_utf8_lossy(&output.stderr).contains("ORBIT-E1101"));
    }
}

#[test]
fn help_exposes_supported_migration_and_session_controls() {
    let output = orbit(&["--help"]);
    assert!(output.status.success());
    let help = String::from_utf8(output.stdout).unwrap();
    for option in [
        "migrate --from claude",
        "completions bash|zsh|fish",
        "--bare",
        "--worktree",
        "--permission-mode",
        "--fallback-model",
        "--channels",
        "--channel-permissions",
    ] {
        assert!(help.contains(option), "missing supported control: {option}");
    }
}
