use std::sync::Arc;

use axum::{Router, middleware, routing::get};

use crate::{
    http::{
        cors::{self, CorsPolicy},
        errors, logging, static_files,
    },
    state::AppState,
};

mod health;
mod misc;

/// Every route this service answers. Paths match the Node backend exactly, because
/// Caddy switches them over to this service one area at a time.
pub fn router(state: AppState) -> Router {
    let cors_policy = Arc::new(CorsPolicy::new(state.config.base_url.as_deref(), state.config.production));

    Router::new()
        .route("/api/health", get(health::health))
        .route("/api/config", get(misc::config))
        .route("/api/version", get(misc::version))
        .route("/api/script.js", get(static_files::script_js))
        .route("/api/replay.js", get(static_files::replay_js))
        .route("/api/metrics.js", get(static_files::metrics_js))
        .fallback(static_files::fallback)
        .method_not_allowed_fallback(errors::not_found)
        // Innermost first: CORS runs before handlers, errors are rewritten after
        // CORS headers are set, and the log sees the final response
        .layer(middleware::from_fn_with_state(cors_policy, cors::cors))
        .layer(middleware::from_fn(errors::api_error_responses))
        .layer(middleware::from_fn(logging::request_log))
        .with_state(state)
}
