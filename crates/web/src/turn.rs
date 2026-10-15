//! Server lifetime for the shared session owner. No browser-specific turn loop.

use crate::{BridgeState, router};
use orbit_cli::{
    daemon::{OwnerConfig, OwnerRuntime},
    sessions::SessionLease,
    tui_worker::TuiTurnConfig,
};

#[derive(Clone)]
pub struct BridgeConfig {
    pub turn: TuiTurnConfig,
    pub bind: String,
    pub port: u16,
    pub token: Option<String>,
}

/// Library callers get the same lease-before-load guarantee as the binary.
/// Explicitly resumed state is reloaded only after the lease is acquired.
pub fn run_bridge(mut config: BridgeConfig) -> i32 {
    let lease = match SessionLease::acquire(&config.turn.home, &config.turn.session_id, "browser") {
        Ok(lease) => lease,
        Err(error) => {
            eprintln!("ORBIT-E0400: {error}");
            return 2;
        }
    };
    if config
        .turn
        .home
        .join("sessions")
        .join(format!("{}.json", config.turn.session_id))
        .exists()
    {
        match lease.load() {
            Ok(saved) => {
                config.turn.model = saved.model;
                config.turn.provider_id = saved.provider;
                config.turn.gate = saved.gate;
                config.turn.effort = saved.effort;
                config.turn.initial_transcript = saved.transcript;
                config.turn.initial_turns = saved.turns;
                config.turn.initial_input_tokens = saved.input_tokens;
                config.turn.initial_output_tokens = saved.output_tokens;
                config.turn.initial_cost_microcents = saved.cost_microcents;
            }
            Err(error) => {
                eprintln!("ORBIT-E0400: {error}");
                return 2;
            }
        }
    }
    run_bridge_owned(config, lease)
}

/// Start with an already acquired and loaded session, retaining the lease until
/// HTTP shutdown and bounded owner cleanup have both completed.
pub fn run_bridge_owned(config: BridgeConfig, lease: SessionLease) -> i32 {
    run_bridge_owned_inner(config, lease, None)
}

pub fn run_bridge_owned_with_customization(
    config: BridgeConfig,
    lease: SessionLease,
    host: std::sync::Arc<dyn orbit_frontend_protocol::customization::ProfileHost>,
) -> i32 {
    run_bridge_owned_inner(config, lease, Some(host))
}

fn run_bridge_owned_inner(
    config: BridgeConfig,
    lease: SessionLease,
    customization: Option<std::sync::Arc<dyn orbit_frontend_protocol::customization::ProfileHost>>,
) -> i32 {
    let loopback = matches!(config.bind.as_str(), "127.0.0.1" | "localhost" | "::1");
    if config.token.as_ref().is_some_and(|token| token.is_empty())
        || (!loopback && config.token.is_none())
    {
        eprintln!("ORBIT-E1109: a nonempty --token is required for non-loopback access");
        return 93;
    }
    let working_dir = match std::env::current_dir() {
        Ok(directory) => directory,
        Err(error) => {
            eprintln!("ORBIT-E0400: {error}");
            return 2;
        }
    };
    let runtime = match OwnerRuntime::start(OwnerConfig::new(config.turn, working_dir), lease) {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("ORBIT-E0400: {error}");
            return 2;
        }
    };
    let handle = runtime.handle();
    let mut state = match BridgeState::from_owner(handle.clone(), config.token) {
        Ok(state) => state,
        Err(error) => {
            eprintln!("ORBIT-E0400: {error}");
            return 2;
        }
    };
    if let Some(host) = customization {
        state = state.with_customization(host);
    }
    let rt = match tokio::runtime::Runtime::new() {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("ORBIT-E0400: {error}");
            return 2;
        }
    };
    let result = rt.block_on(async {
        let listener = tokio::net::TcpListener::bind((config.bind.as_str(), config.port))
            .await
            .map_err(|error| error.to_string())?;
        println!(
            "orbit-web: http://{}",
            listener.local_addr().map_err(|error| error.to_string())?
        );
        let state =
            state.with_bound_address(listener.local_addr().map_err(|error| error.to_string())?);
        axum::serve(listener, router(state))
            .with_graceful_shutdown(async move {
                while !handle.is_stopping() {
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                }
            })
            .await
            .map_err(|error| error.to_string())
    });
    let cleanup = runtime.shutdown().map_err(|error| error.to_string());
    match result.and(cleanup) {
        Ok(()) => 0,
        Err(error) => {
            eprintln!("ORBIT-E0400: {error}");
            2
        }
    }
}
