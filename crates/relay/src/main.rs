mod auth;
mod relay;

use std::{net::SocketAddr, sync::Arc, time::Duration};

use anyhow::Context;
use axum::{Router, routing::get};
use clap::Parser;
use tokio::net::TcpListener;
use tracing::info;

use crate::auth::AuthState;
use crate::relay::{RelayState, health_handler, ws_handler};

#[derive(Debug, Parser)]
#[command(name = "relay")]
#[command(about = "Zero-knowledge relay server for terminal-relay")]
struct Args {
    #[arg(long, default_value = "0.0.0.0:8080")]
    bind: SocketAddr,
    #[arg(long, default_value = "0.1.0")]
    min_version: String,
    #[arg(long, default_value_t = 24 * 60 * 60)]
    session_ttl_secs: u64,
    /// Maximum number of concurrent sessions (0 = unlimited).
    #[arg(long, default_value_t = 0, env = "RELAY_MAX_SESSIONS")]
    max_sessions: usize,
    /// Maximum concurrent sessions per IP address (0 = unlimited).
    #[arg(long, default_value_t = 0, env = "RELAY_MAX_SESSIONS_PER_IP")]
    max_sessions_per_ip: usize,
    /// HMAC secret for verifying signed API keys. If empty, auth is disabled (open relay).
    #[arg(long, default_value = "", env = "HMAC_SECRET")]
    hmac_secret: String,
    /// Previous HMAC secret for key rotation. Optional.
    #[arg(long, default_value = "", env = "HMAC_SECRET_PREVIOUS")]
    hmac_secret_previous: String,
    /// Control API base URL for revocation sync and session reporting (e.g. https://api.terminal-relay.dev).
    #[arg(long, env = "CONTROL_API_URL")]
    control_api_url: Option<String>,
    /// Shared secret for authenticating with the control API internal endpoints.
    #[arg(long, default_value = "", env = "INTERNAL_SECRET")]
    internal_secret: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,relay=debug".into()),
        )
        .init();

    let args = Args::parse();

    let auth = Arc::new(AuthState::new(
        args.hmac_secret.clone(),
        if args.hmac_secret_previous.is_empty() {
            None
        } else {
            Some(args.hmac_secret_previous.clone())
        },
        args.control_api_url.clone(),
        if args.internal_secret.is_empty() {
            None
        } else {
            Some(args.internal_secret.clone())
        },
    ));

    let state = Arc::new(RelayState::new(
        args.min_version.clone(),
        Duration::from_secs(args.session_ttl_secs),
        args.max_sessions,
        args.max_sessions_per_ip,
        Arc::clone(&auth),
    ));

    let cleanup_state = Arc::clone(&state);
    let cleanup_handle = tokio::spawn(async move {
        cleanup_state.cleanup_loop().await;
    });

    // Start revocation sync loop if auth is enabled
    let revocation_handle = if auth.is_enabled() {
        let auth_clone = Arc::clone(&auth);
        Some(tokio::spawn(async move {
            auth_clone.revocation_sync_loop().await;
        }))
    } else {
        info!("HMAC_SECRET not set, running as open relay (no auth)");
        None
    };

    let app = Router::new()
        .route("/healthz", get(health_handler))
        .route("/ws", get(ws_handler))
        .with_state(state);

    info!(
        bind = %args.bind,
        min_version = %args.min_version,
        version = env!("CARGO_PKG_VERSION"),
        auth_enabled = auth.is_enabled(),
        "relay server ready"
    );
    let listener = TcpListener::bind(args.bind)
        .await
        .with_context(|| format!("failed binding to {}", args.bind))?;

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await
    .context("relay server error")?;

    info!("shutting down");
    cleanup_handle.abort();
    if let Some(handle) = revocation_handle {
        handle.abort();
    }
    Ok(())
}

/// Wait for SIGINT (ctrl-c) or SIGTERM for graceful shutdown.
async fn shutdown_signal() {
    let ctrl_c = tokio::signal::ctrl_c();

    #[cfg(unix)]
    {
        let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to register SIGTERM handler");
        tokio::select! {
            _ = ctrl_c => { info!("received SIGINT, initiating graceful shutdown"); }
            _ = sigterm.recv() => { info!("received SIGTERM, initiating graceful shutdown"); }
        }
    }

    #[cfg(not(unix))]
    {
        ctrl_c.await.ok();
        info!("received SIGINT, initiating graceful shutdown");
    }
}
