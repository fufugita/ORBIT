//! A `Stop` hook that keeps blocking sends the model back to work, but only so
//! often: 3 times a turn unless the operator's own settings raise it with
//! `stop_hook_max_continuations`. When the limit ends a turn while the hook
//! still wants it to go on, the operator is told.

#![deny(unsafe_code)]

use orbit_adapter::types::ChatMessage;
use orbit_engine::{PendingToolCall, ToolExecutor, ToolRoundResult};
use orbit_mock_provider::server::spawn;
use orbit_provider_http::CancelToken;
use std::sync::Mutex;

/// Hook trouble is reported process-wide, so the tests take turns.
static ONE_AT_A_TIME: Mutex<()> = Mutex::new(());

struct NoTools;

impl ToolExecutor for NoTools {
    fn execute(&mut self, calls: &[PendingToolCall], _round: u32) -> Vec<ToolRoundResult> {
        calls
            .iter()
            .map(|c| ToolRoundResult {
                call_id: c.id.clone(),
                content: r#"{"ok":true}"#.into(),
            })
            .collect()
    }
}

fn spawn_mock_on_thread() -> std::net::SocketAddr {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::Builder::new()
        .name("mock-provider".into())
        .spawn(move || {
            let rt = tokio::runtime::Runtime::new().expect("mock runtime");
            rt.block_on(async move {
                let (addr, _state, handle) = spawn().await.expect("mock spawn");
                tx.send(addr).expect("send addr");
                let _ = handle.await;
            });
        })
        .expect("spawn mock thread");
    rx.recv().expect("mock address")
}

/// Run one turn whose only `Stop` hook always blocks. `before` and `after`
/// are settings text placed above and below that hook's `[[hooks]]` table.
/// Returns how often the hook ran and the hook trouble the operator was told.
fn turn_with_a_blocking_stop_hook(name: &str, before: &str, after: &str) -> (usize, Vec<String>) {
    turn_with_a_round_limit(name, before, after, None)
}

/// The same, with the turn limited to `rounds` model rounds.
fn turn_with_a_round_limit(
    name: &str,
    before: &str,
    after: &str,
    rounds: Option<u32>,
) -> (usize, Vec<String>) {
    let _turn = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    let _ = orbit_engine::hooks::take_hook_problems();
    let addr = spawn_mock_on_thread();
    let home = std::env::temp_dir().join(format!("orbit-stop-limit-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&home);
    std::fs::create_dir_all(home.join("ledger")).expect("mkdir ledger");
    let ran = home.join("stop-hook-ran");
    std::fs::write(
        home.join("settings.toml"),
        format!(
            "{before}\n[[hooks]]\nevent = \"Stop\"\ncommand = \"echo ran >> '{}'; echo keep going >&2; exit 2\"\n{after}",
            ran.display()
        ),
    )
    .expect("write settings");
    let config = orbit_engine::TurnConfig {
        billing: None,
        sampling: None,
        effort: None,
        supported_efforts: None,
        first_byte_timeout_ms: None,
        idle_timeout_ms: None,
        provider_id: "mock".into(),
        gate: format!("http://127.0.0.1:{}", addr.port()),
        model: "test-model".into(),
        kind: orbit_engine::ProviderKind::OpenAiCompatible,
        credential_env: None,
        pricing: None,
        max_output_tokens: 32_000,
    };
    let mut options = orbit_engine::TurnOptions {
        request_stem: format!("stop-limit-{name}"),
        ..Default::default()
    };
    if let Some(rounds) = rounds {
        options.max_rounds = rounds;
    }
    let mut transcript: Vec<ChatMessage> = Vec::new();
    let mut events = |_ev: orbit_frontend_protocol::FrontendEvent| {};
    orbit_engine::run_turn(
        &home,
        &config,
        &options,
        "say hello",
        &mut transcript,
        &mut NoTools,
        &CancelToken::new(),
        &mut events,
    )
    .expect("engine turn");
    let runs = std::fs::read_to_string(&ran).map_or(0, |text| text.lines().count());
    (runs, orbit_engine::hooks::take_hook_problems())
}

#[test]
fn a_hook_that_keeps_blocking_gets_three_continuations_unless_told_otherwise() {
    let (runs, problems) = turn_with_a_blocking_stop_hook("default", "", "");
    assert_eq!(runs, 4, "the first stop, then three continuations");
    assert!(
        problems
            .iter()
            .any(|p| p.contains("stop_hook_max_continuations") && p.contains("3")),
        "the operator is told the hook was not obeyed, and which setting to raise: {problems:?}"
    );
}

#[test]
fn the_operators_limit_replaces_the_default() {
    let (runs, problems) =
        turn_with_a_blocking_stop_hook("raised", "stop_hook_max_continuations = 6\n", "");
    assert_eq!(runs, 7, "the first stop, then six continuations");
    assert!(
        problems.iter().any(|p| p.contains("6")),
        "the notice names the limit that was reached: {problems:?}"
    );
}

#[test]
fn a_limit_of_zero_never_sends_the_model_back() {
    let (runs, _) = turn_with_a_blocking_stop_hook("zero", "stop_hook_max_continuations = 0\n", "");
    assert_eq!(runs, 1, "the block is not obeyed at all");
}

#[test]
fn a_limit_written_under_a_table_is_reported_and_not_obeyed() {
    // TOML puts a key that follows `[[hooks]]` inside that table.
    let (runs, problems) =
        turn_with_a_blocking_stop_hook("misplaced", "", "stop_hook_max_continuations = 9\n");
    assert_eq!(runs, 4, "the default holds");
    assert!(
        problems.iter().any(|p| p.contains("under a [table]")),
        "{problems:?}"
    );
}

#[test]
fn a_limit_that_is_not_a_number_keeps_the_default_and_says_so() {
    let (runs, problems) =
        turn_with_a_blocking_stop_hook("invalid", "stop_hook_max_continuations = \"lots\"\n", "");
    assert_eq!(runs, 4, "the default holds");
    assert!(
        problems.iter().any(|p| p.contains("whole number")),
        "{problems:?}"
    );
}

#[test]
fn a_turn_that_runs_out_of_rounds_says_the_hook_was_overruled() {
    // Room for fifty continuations, but the turn has two rounds: the second
    // stop finds none left.
    let (runs, problems) =
        turn_with_a_round_limit("rounds", "stop_hook_max_continuations = 50\n", "", Some(2));
    assert_eq!(runs, 2, "one continuation, then no round left");
    assert!(
        problems.iter().any(|p| p.contains("2 rounds")),
        "{problems:?}"
    );
}
