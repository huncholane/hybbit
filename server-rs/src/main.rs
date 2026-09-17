//! Hygo analytics backend: the Rust port of the Fastify server in `../server`.
//!
//! The port happens route by route. Caddy sends every path this service implements
//! here and everything else to the Node backend until the port is complete; see
//! PORT_PLAN.md for what is ported and what must match Node exactly.

mod clickhouse;
mod config;
mod error;
mod feature_flags;
mod geo;
mod http;
mod json_shape;
mod routes;
mod site_config;
mod state;

use std::net::SocketAddr;

use anyhow::Context;
use tracing::info;

use crate::{config::Config, state::AppState};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing();

    let config = Config::from_env().context("reading configuration")?;
    let port = config.port;
    let state = AppState::connect(config).await.context("connecting to data stores")?;

    let app = routes::router(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("binding {addr}"))?;
    info!(%addr, "hygo backend listening");

    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("serving")?;

    info!("hygo backend stopped");
    Ok(())
}

/// JSON logs to stdout, one object per line, filtered by LOG_LEVEL (default info).
fn init_tracing() {
    use tracing_subscriber::{EnvFilter, fmt, prelude::*};

    let filter = EnvFilter::try_from_env("LOG_LEVEL").unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::registry()
        .with(filter)
        .with(fmt::layer().json().with_current_span(false))
        .init();
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    #[cfg(unix)]
    let terminate = async {
        if let Ok(mut signal) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            signal.recv().await;
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {}
        _ = terminate => {}
    }
    info!("shutdown signal received");
}
