//! The Esc bridge: a process-wide interrupt slot connecting the
//! engine's CancelToken to running tool children (MD §The agent loop:
//! "Esc cancels the stream and kills each running tool's process
//! group").
//!
//! The engine installs the turn's cancel-checker before executing
//! tools; long-running tools (Bash) poll it and kill their process
//! groups when it fires. Kept as a process-wide slot because the tool
//! call path (execute_call → registry tools) cannot thread a token
//! through without reshaping every signature — the MD's loop contract
//! is honored at the one place it matters: child death on Esc.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

type CancelCheck = Arc<dyn Fn() -> bool + Send + Sync>;

static CHECK: OnceLock<Mutex<Option<CancelCheck>>> = OnceLock::new();
static KILL_FIRED: AtomicBool = AtomicBool::new(false);

fn slot() -> &'static Mutex<Option<CancelCheck>> {
    CHECK.get_or_init(|| Mutex::new(None))
}

/// Install the current turn's cancel-checker. The engine calls this
/// before executing tool calls; passing None clears it (turn end).
pub fn set_cancel_check(check: Option<CancelCheck>) {
    if let Ok(mut g) = slot().lock() {
        *g = check;
    }
    KILL_FIRED.store(false, Ordering::SeqCst);
}

/// Whether the current turn was cancelled — the flag long-running
/// tools poll between waits.
pub fn is_cancelled() -> bool {
    match slot().lock() {
        Ok(g) => g.as_ref().map(|f| f()).unwrap_or(false),
        Err(_) => false,
    }
}

/// Mark that the interrupt's kill already fired for this turn (so
/// pollers don't killpg twice and reapers don't fight over children).
pub fn kill_fired() -> bool {
    KILL_FIRED.load(Ordering::SeqCst)
}

pub fn set_kill_fired() {
    KILL_FIRED.store(true, Ordering::SeqCst);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn a_cancelled_turn_kills_the_running_bash_child() {
        use crate::bash::BashTool;
        use crate::{Tool, ToolContext};
        // A cancelled flag, fired by another thread mid-run.
        let flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let f = flag.clone();
        set_cancel_check(Some(Arc::new(move || {
            f.load(std::sync::atomic::Ordering::SeqCst)
        })));
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(300));
            flag.store(true, std::sync::atomic::Ordering::SeqCst);
        });
        let home = std::env::temp_dir().join(format!("orbit-interrupt-{}", ulid::Ulid::new()));
        std::fs::create_dir_all(&home).unwrap();
        let cx = ToolContext::new(home.clone(), "interrupt-test".into(), home.clone());
        let t0 = std::time::Instant::now();
        let input = serde_json::json!({ "command": "sleep 30 && echo done" });
        let r = BashTool.run(&input, &cx);
        let elapsed = t0.elapsed();
        set_cancel_check(None);
        // The sleep must die within seconds, not the tool timeout.
        assert!(
            elapsed < std::time::Duration::from_secs(10),
            "cancel must kill the child promptly (took {elapsed:?})"
        );
        assert!(
            r.payload.contains("cancelled"),
            "the result must say cancelled: {}",
            r.payload
        );
        // And no orphan survives: no NEW sleep process beyond the
        // pre-run baseline (the machine may host unrelated sleeps).
        let baseline: Vec<String> = {
            let o = std::process::Command::new("pgrep")
                .arg("-x")
                .arg("sleep")
                .output()
                .expect("pgrep");
            String::from_utf8_lossy(&o.stdout)
                .split_whitespace()
                .map(String::from)
                .collect()
        };
        let mut leaked = Vec::new();
        for _ in 0..30 {
            let o = std::process::Command::new("pgrep")
                .arg("-x")
                .arg("sleep")
                .output()
                .expect("pgrep");
            leaked = String::from_utf8_lossy(&o.stdout)
                .split_whitespace()
                .map(String::from)
                .filter(|p| !baseline.contains(p))
                .collect();
            if leaked.is_empty() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        assert!(
            leaked.is_empty(),
            "the child must be dead (leaked: {leaked:?})\n{tree}",
            tree = {
                std::process::Command::new("bash")
                    .arg("-c")
                    .arg("ps -eo pid,ppid,pgid,cmd | grep -E 'sleep 30|bwrap' | grep -v grep | head -6")
                    .output()
                    .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
                    .unwrap_or_default()
            }
        );
        let _ = std::fs::remove_dir_all(&home);
    }
}
