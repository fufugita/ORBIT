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

/// Byte length of the normalized prompt on the fallback child's stdin.
/// A resumed fallback also removes the saved copy of that unanswered prompt.
pub const RETRY_MARK: &str = "ORBIT_FALLBACK_RETRY";
pub const STDIN_RETRY_PREFIX: &str = "stdin-v1:";
pub const SAVED_TAIL_MARK: &str = "ORBIT_FALLBACK_SAVED_TAIL";

/// Identify the exact unanswered message, including hook-added content, at its
/// saved position. Another process may update the source before the fork opens.
pub fn saved_tail_identity(history: &[orbit_adapter::types::ChatMessage]) -> Option<String> {
    use sha2::{Digest, Sha256};

    let message = history.last()?;
    if message.role != orbit_adapter::types::ChatRole::User {
        return None;
    }
    let mut digest = Sha256::new();
    digest.update((history.len() as u64).to_be_bytes());
    serde_json::to_writer(&mut digest, message).ok()?;
    Some(hex::encode(digest.finalize()))
}

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
/// a fork, because the failed session keeps its unsettled request. An
/// empty operand leaves a trailing `-p` for the prompt sent over stdin.
pub fn rerun_arguments(
    prompt: &str,
    args: &[String],
    fallback: &str,
    resumed_session: Option<&str>,
) -> Vec<String> {
    let mut out = if prompt.is_empty() {
        Vec::new()
    } else {
        vec!["-p".to_owned(), prompt.to_owned()]
    };
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--model" | "--provider" | "--effort" | "--resume" => {
                args.next();
            }
            "--continue" | "--fork-session" | "--adopt-workspace" => {}
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
    if prompt.is_empty() {
        out.push("-p".to_owned());
    }
    out
}

/// Run the prompt again on the fallback model, as a process of its own with
/// this one's terminal, and return its exit code. The fallback run gets no
/// fallback of its own.
pub fn rerun(prompt: &str, args: &[String], fallback: &str, resumed_session: Option<&str>) -> i32 {
    rerun_with_saved_tail(prompt, args, fallback, resumed_session, None)
}

pub fn rerun_with_saved_tail(
    prompt: &str,
    args: &[String],
    fallback: &str,
    resumed_session: Option<&str>,
    saved_tail: Option<&str>,
) -> i32 {
    use std::io::Write;
    use std::process::{Command, Stdio};

    let run = || -> std::io::Result<std::process::ExitStatus> {
        let mut child = Command::new(std::env::current_exe()?)
            .args(rerun_arguments("", args, fallback, resumed_session))
            .stdin(Stdio::piped())
            .env(RETRY_MARK, format!("{STDIN_RETRY_PREFIX}{}", prompt.len()))
            .env_remove(SAVED_TAIL_MARK)
            .envs(saved_tail.map(|identity| (SAVED_TAIL_MARK, identity)))
            .env_remove("ORBIT_FALLBACK_MODEL")
            .env_remove("ORBIT_MODEL")
            // Setup hooks ran once, in this process.
            .env_remove("ORBIT_SETUP_TRIGGER")
            .env_remove("ORBIT_SETUP_ONLY")
            .spawn()?;
        let sent = child
            .stdin
            .take()
            .expect("piped fallback stdin")
            .write_all(prompt.as_bytes());
        let status = child.wait()?;
        if status.success() {
            sent?;
        }
        Ok(status)
    };
    match run() {
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
    fn resumed_fallback_identity_tracks_the_saved_user_message_and_its_position() {
        let user = orbit_engine::user_message("prompt\n\n<hook-context>\none\n</hook-context>");
        let saved = saved_tail_identity(std::slice::from_ref(&user)).unwrap();
        let edited = orbit_engine::user_message("prompt\n\n<hook-context>\ntwo\n</hook-context>");
        assert_ne!(saved_tail_identity(&[edited]), Some(saved.clone()));
        assert_ne!(saved_tail_identity(&[user.clone(), user]), Some(saved));
        assert!(saved_tail_identity(&[orbit_engine::assistant_message("answer")]).is_none());
    }

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
        assert_eq!(
            rerun_arguments("--help", &[], "small", None),
            ["-p", "--help", "--model", "small"]
        );
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
            rerun_arguments("", &args, "p/small", None),
            [
                "--home",
                "/h",
                "--output-format",
                "json",
                "--max-turns",
                "4",
                "--auto-tools",
                "--model",
                "p/small",
                "-p"
            ]
        );
        let resumed = rerun_arguments(
            "",
            &["--resume".into(), "s-1".into(), "--adopt-workspace".into()],
            "small",
            Some("s-1"),
        );
        assert_eq!(
            resumed,
            [
                "--model",
                "small",
                "--resume",
                "s-1",
                "--fork-session",
                "-p"
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
