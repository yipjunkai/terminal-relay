mod relay;

use std::{net::SocketAddr, sync::Arc, time::Duration};

use anyhow::Context;
use axum::{Router, routing::get};
use clap::Parser;
use tokio::net::TcpListener;
use tracing::{info, warn};

use crate::relay::{RelayState, health_handler, ws_handler};

#[derive(Debug, Parser)]
#[command(name = "terminal-relay-server")]
#[command(about = "Zero-knowledge relay server for terminal-relay")]
struct Args {
    #[arg(long, default_value = "0.0.0.0:8080")]
    bind: SocketAddr,
    #[arg(long, default_value = "0.1.0")]
    min_version: String,
    #[arg(long, default_value_t = 24 * 60 * 60)]
    session_ttl_secs: u64,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,terminal_relay_server=debug".into()),
        )
        .init();

    let args = Args::parse();
    let state = Arc::new(RelayState::new(
        args.min_version.clone(),
        Duration::from_secs(args.session_ttl_secs),
    ));

    let cleanup_state = Arc::clone(&state);
    tokio::spawn(async move {
        cleanup_state.cleanup_loop().await;
    });

    let app = Router::new()
        .route("/healthz", get(health_handler))
        .route("/ws", get(ws_handler))
        .with_state(state);

    info!(bind = %args.bind, min_version = %args.min_version, "relay server ready");
    let listener = TcpListener::bind(args.bind)
        .await
        .with_context(|| format!("failed binding to {}", args.bind))?;

    if let Err(err) = axum::serve(listener, app).await {
        warn!(error = %err, "relay server terminated");
    }

    Ok(())
}
