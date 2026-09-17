use std::sync::Arc;

use axum::{
    Router, middleware,
    routing::{get, post},
};

use crate::{
    http::{
        cors::{self, CorsPolicy},
        errors, logging, static_files,
    },
    state::AppState,
};

mod feature_flags;
mod health;
mod misc;
mod track;
mod tracking_config;

/// Every route this service answers. Paths match the Node backend exactly, because
/// Caddy switches them over to this service one area at a time.
pub fn router(state: AppState) -> Router {
    let cors_policy = Arc::new(CorsPolicy::new(state.config.base_url.as_deref(), state.config.production));

    let routes = Router::new()
        .route("/api/health", get(health::health))
        .route("/api/config", get(misc::config))
        .route("/api/version", get(misc::version))
        .route("/api/script.js", get(static_files::script_js))
        .route("/api/replay.js", get(static_files::replay_js))
        .route("/api/metrics.js", get(static_files::metrics_js))
        .route("/api/site/tracking-config/{siteId}", get(tracking_config::tracking_config))
        .route("/api/track", post(track::track))
        .route("/api/identify", post(track::identify))
        .route("/api/site/{siteId}/feature-flags/evaluate", post(feature_flags::evaluate_client))
        .route("/api/sites/{siteId}/feature-flags/evaluate", post(feature_flags::evaluate_server))
        .merge(crate::analytics::routes::router())
        .merge(crate::auth::endpoints::router())
        .merge(crate::auth::endpoints::mcp::well_known_router())
        .fallback(static_files::fallback)
        .method_not_allowed_fallback(errors::not_found)
        .with_state(state);

    // The middleware wraps the whole router rather than each route: layered per
    // route, a CORS preflight answered for a POST-only path would pass back through
    // axum's method routing, which appends an `Allow` header Node never sends.
    // Innermost first: CORS runs before handlers, errors are rewritten after CORS
    // headers are set, and the log sees the final response.
    Router::new()
        .fallback_service(routes)
        .layer(middleware::from_fn_with_state(cors_policy, cors::cors))
        .layer(middleware::from_fn(errors::api_error_responses))
        .layer(middleware::from_fn(logging::request_log))
}
