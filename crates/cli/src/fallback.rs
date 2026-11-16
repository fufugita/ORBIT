//! `--fallback-model`: a second model for a headless prompt whose first
//! model could not be reached.
//!
//! It applies to `-p` only, as in Claude Code. The engine's retries run
//! first, under the selected model's own policy. Only when they are
//! exhausted on a failure that says the provider was unavailable (rate
//! limit, capacity, timeout, transport), and the turn produced nothing, is
//! the same prompt run once more on the fallback model. That run is a
//! session of its own: a failed request stays on the first session as an
//! unsettled charge until it is inspected, and nothing more may be billed
//! to that session meanwhile. A conversation that was being resumed
//! continues as a fork of it. Anything else
//! (a refused credential, a bad request, a reply that started and broke
//! off) is reported as it is: another model would not make it right, or
//! could repeat work already done.

/// The codes a provider failure carries when the model could not be
/// reached: rate limit, capacity, timeout, transport.
const UNAVAILABLE: [&str; 4] = ["E0407", "E0408", "E0409", "E0410"];

/// Set for the fallback run of a resumed conversation: the fork it starts
/// from ends with the prompt the failed run left unanswered.
pub const RETRY_MARK: &str = "ORBIT_FALLBACK_RETRY";

/// The fallback model named for this run: `--fallback-model` (carried in
/// `ORBIT_FALLBACK_MODEL`). Empty means none.
pub fn requested() -> Option<String> {
    std::env::var("ORBIT_FALLBACK_MODEL")
        .ok()
        .map(|spec| spec.trim().to_owned())
        .filter(|spec| !spec.is_empty())
}

/// Did this failed turn end because the model was unavailable, before it
/// produced anything?
pub fn applies(failure: &str, final_text: &str, output_tokens: u64, completed_rounds: u32) -> bool {
    // A completed round may have executed tools even when the provider
    // reports zero tokens. Replaying the prompt would repeat those effects.
    completed_rounds == 0
        && final_text.is_empty()
        && output_tokens == 0
        && UNAVAILABLE.iter().any(|code| failure.contains(code))
}

/// The arguments of the fallback run: the same headless prompt and options
/// on the fallback model. The first run's model, provider and effort
/// choices are dropped (they belong to the model that failed), and so are
/// its session choices: a conversation that was being resumed continues as
/// a fork, because the failed session keeps its unsettled request.
pub fn rerun_arguments(
    prompt: &str,
    args: &[String],
    fallback: &str,
    resumed_session: Option<&str>,
) -> Vec<String> {
    let mut out = vec!["-p".to_owned(), prompt.to_owned()];
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--model" | "--provider" | "--effort" | "--resume" => {
                args.next();
            }
            "--continue" | "--fork-session" => {}
            _ => out.push(arg.clone()),
        }
    }
    out.extend(["--model".to_owned(), fallback.to_owned()]);
    if let Some(session) = resumed_session {
        out.extend([
            "--resume".to_owned(),
            session.to_owned(),
            "--fork-session".to_owned(),
        ]);
    }
    out
}

/// Run the prompt again on the fallback model, as a process of its own with
/// this one's terminal, and return its exit code. The fallback run gets no
/// fallback of its own.
pub fn rerun(prompt: &str, args: &[String], fallback: &str, resumed_session: Option<&str>) -> i32 {
    let binary = match std::env::current_exe() {
        Ok(binary) => binary,
        Err(error) => {
            eprintln!("fallback model {fallback} could not be started: {error}");
            return 1;
        }
    };
    match std::process::Command::new(binary)
        .args(rerun_arguments(prompt, args, fallback, resumed_session))
        .env_remove("ORBIT_FALLBACK_MODEL")
        .env_remove("ORBIT_MODEL")
        // `--init` ran its Setup hooks once, in this process.
        .env_remove("ORBIT_SETUP_TRIGGER")
        .env_remove("ORBIT_SETUP_ONLY")
        .envs(resumed_session.map(|_| (RETRY_MARK, "1")))
        .status()
    {
        Ok(status) => status.code().unwrap_or(1),
        Err(error) => {
            eprintln!("fallback model {fallback} could not be started: {error}");
            1
        }
    }
}

/// The variable that carries the unanswered prompt to the plain chat a
/// fallback starts: that chat asks it first, before reading its input.
pub const CHAT_FIRST_PROMPT: &str = "ORBIT_CHAT_FIRST_PROMPT";

/// The longest prompt that is carried to the fallback chat. One variable of
/// a process's environment is bounded (128 KiB on Linux); a longer prompt
/// would stop the new chat from starting at all.
const MAX_CARRIED_PROMPT: usize = 96 * 1024;

/// The arguments of the plain chat that continues a conversation on the
/// fallback model: this chat's own options, without its model, provider,
/// effort and session choices, on the fork that was just made.
pub fn chat_rerun_arguments(args: &[String], fallback: &str, fork: &str) -> Vec<String> {
    // Options whose value is kept with them: a value is never read as a
    // word of the command line.
    const KEPT_WITH_VALUE: [&str; 5] = [
        "--home",
        "--gate",
        "--permission-mode",
        "--allowedTools",
        "--disallowedTools",
    ];
    let mut out = vec!["chat".to_owned()];
    let mut command = false;
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            // `--worktree` was entered by this chat; its fallback starts
            // inside it.
            "--model" | "--provider" | "--effort" | "--resume" | "--worktree" => {
                args.next();
            }
            "--continue" | "--fork-session" | "--adopt-workspace" => {}
            "chat" if !command => command = true,
            option if KEPT_WITH_VALUE.contains(&option) => {
                out.push(arg.clone());
                out.extend(args.next().cloned());
            }
            _ => out.push(arg.clone()),
        }
    }
    out.extend([
        "--model".to_owned(),
        fallback.to_owned(),
        "--resume".to_owned(),
        fork.to_owned(),
    ]);
    out
}

/// Continue the plain chat on the fallback model, in the fork `fork` of the
/// conversation: it asks `prompt` again first and then reads on. It gets no
/// fallback of its own. On Unix the new chat takes this process's place
/// (same terminal, same signals, and this chat's MCP servers end with it);
/// elsewhere it runs as a child and its exit code is returned. The caller
/// has saved the session and let go of it.
pub fn chat_rerun(args: &[String], fallback: &str, fork: &str, prompt: &str) -> i32 {
    let binary = match std::env::current_exe() {
        Ok(binary) => binary,
        Err(error) => {
            eprintln!("fallback model {fallback} could not be started: {error}");
            return 1;
        }
    };
    let mut chat = std::process::Command::new(binary);
    chat.args(chat_rerun_arguments(args, fallback, fork))
        .env_remove("ORBIT_FALLBACK_MODEL")
        .env_remove("ORBIT_MODEL")
        .env_remove("ORBIT_SETUP_TRIGGER")
        .env_remove("ORBIT_SETUP_ONLY")
        .env_remove(CHAT_FIRST_PROMPT);
    if prompt.len() <= MAX_CARRIED_PROMPT && !prompt.contains('\0') {
        chat.env(CHAT_FIRST_PROMPT, prompt);
    } else {
        eprintln!("the prompt is too long to carry over to the fallback chat: send it again there");
    }
    {
        use std::io::Write;
        let _ = std::io::stdout().flush();
        let _ = std::io::stderr().flush();
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        // Returns only when the new chat could not be started.
        let error = chat.exec();
        eprintln!("fallback model {fallback} could not be started: {error}");
        1
    }
    #[cfg(not(unix))]
    match chat.status() {
        Ok(status) => status.code().unwrap_or(1),
        Err(error) => {
            eprintln!("fallback model {fallback} could not be started: {error}");
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_fallback_chat_keeps_the_options_and_moves_to_the_fork() {
        let args: Vec<String> = [
            "chat",
            "--home",
            "/h",
            "--no-tui",
            "--model",
            "big",
            "--continue",
            "--auto-tools",
            "--worktree",
            "w",
            "--resume",
            "old",
        ]
        .iter()
        .map(|arg| (*arg).to_owned())
        .collect();
        assert_eq!(
            chat_rerun_arguments(&args, "p/small", "session-fork"),
            [
                "chat",
                "--home",
                "/h",
                "--no-tui",
                "--auto-tools",
                "--model",
                "p/small",
                "--resume",
                "session-fork"
            ]
        );
        // The command word may come after an option, and a value that
        // spells it is still a value.
        let args: Vec<String> = ["--no-tui", "chat", "--home", "chat"]
            .iter()
            .map(|arg| (*arg).to_owned())
            .collect();
        assert_eq!(
            chat_rerun_arguments(&args, "small", "fork"),
            [
                "chat", "--no-tui", "--home", "chat", "--model", "small", "--resume", "fork"
            ]
        );
    }

    #[test]
    fn the_fallback_run_keeps_the_options_and_drops_the_failed_models_choices() {
        let args: Vec<String> = [
            "--home",
            "/h",
            "--model",
            "big",
            "--provider",
            "p",
            "--effort",
            "high",
            "--output-format",
            "json",
            "--continue",
            "--max-turns",
            "4",
            "--auto-tools",
        ]
        .iter()
        .map(|arg| (*arg).to_owned())
        .collect();
        assert_eq!(
            rerun_arguments("fix --model it", &args, "p/small", None),
            [
                "-p",
                "fix --model it",
                "--home",
                "/h",
                "--output-format",
                "json",
                "--max-turns",
                "4",
                "--auto-tools",
                "--model",
                "p/small"
            ]
        );
        let resumed = rerun_arguments(
            "go",
            &["--resume".into(), "s-1".into()],
            "small",
            Some("s-1"),
        );
        assert_eq!(
            resumed,
            [
                "-p",
                "go",
                "--model",
                "small",
                "--resume",
                "s-1",
                "--fork-session"
            ]
        );
    }

    #[test]
    fn only_an_unreachable_model_with_no_output_falls_back() {
        for unavailable in [
            "ORBIT-E0407 rate_limited_exhausted: 429 after 3 attempts",
            "ORBIT-E0408 capacity_unavailable_exhausted: 529",
            "ORBIT-E0409 provider_timeout: no first byte",
            "ORBIT-E0410 provider_transport_failure: connection reset",
        ] {
            assert!(applies(unavailable, "", 0, 0), "{unavailable}");
            assert!(!applies(unavailable, "partial rep", 0, 0), "{unavailable}");
            assert!(!applies(unavailable, "", 12, 0), "{unavailable}");
        }
        for other in [
            "ORBIT-E0402: credential refused",
            "ORBIT-E0411 provider_protocol_or_stream_violation: bad frame",
            "context budget policy refuses this request",
            "prompt blocked by hook: freeze",
            "",
        ] {
            assert!(!applies(other, "", 0, 0), "{other}");
        }
    }

    #[test]
    fn a_completed_tool_round_prevents_replaying_the_prompt_even_with_zero_tokens() {
        let report = orbit_engine::TurnReport {
            rounds: 1,
            ..Default::default()
        };
        assert!(!applies(
            "ORBIT-E0408 capacity_unavailable_exhausted: 529",
            &report.final_text,
            report.output_tokens,
            report.rounds,
        ));
    }
}
