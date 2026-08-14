//! ORBIT mock provider server — v0.2 conformance target.
//!
//! Speaks OpenAI-compatible / Anthropic / Ollama wire formats over HTTP. Run
//! it locally or deploy it to the homelab; configure the adapters to point at
//! the printed address.

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let bind = std::env::var("ORBIT_MOCK_BIND").unwrap_or_else(|_| "0.0.0.0:8088".into());
    let listener = tokio::net::TcpListener::bind(&bind).await?;
    let addr = listener.local_addr()?;
    println!("orbit-mock-provider listening on http://{addr}");
    println!("  OpenAI:   POST /v1/chat/completions");
    println!("  Anthropic: POST /v1/messages");
    println!("  Ollama:   POST /api/chat");
    axum::serve(
        listener,
        orbit_mock_provider::router(orbit_mock_provider::ServerState::default()),
    )
    .await?;
    Ok(())
}
