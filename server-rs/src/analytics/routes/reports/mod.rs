//! Funnels, goals, performance (web vitals) and bot analytics, ported from
//! server/src/api/analytics/{funnels,goals,performance,bots} with the guard chains
//! server/src/index.ts registers them with:
//!
//! - funnels: `publicFunnelsRead` for the list, analysis and step sessions,
//!   `authFunnelsWrite` for create and delete
//! - goals: `publicGoalsRead` for the list, time series and sessions,
//!   `authGoalsWrite` for create, update and delete
//! - performance and bots: `publicAnalyticsRead`
//!
//! Fastify's router matches per method, so a literal segment only shadows a
//! parameter for the methods registered on it: `DELETE .../funnels/analyze`
//! reaches deleteFunnel and `PUT`/`DELETE .../goals/time-series` reach
//! updateGoal/deleteGoal. axum matches the path first, so those method
//! combinations are routed to the same handlers explicitly.

use axum::{
    Router,
    body::Body,
    extract::{RawPathParams, State},
    http::{HeaderMap, Method, Uri},
    response::Response,
    routing::{delete, get, post},
};

use crate::{
    analytics::chain::{ChainSteps, SiteGuard, route_scope, site_scoped},
    state::AppState,
};

mod bots;
mod conditions;
mod funnels;
mod goals;
pub mod openrouter;
mod performance;
mod support;

#[cfg(test)]
mod parity_tests;

use support::{path_params, read_body};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/sites/{siteId}/funnels", get(funnels::get_funnels).post(funnels::create_funnel))
        .route("/api/sites/{siteId}/funnels/analyze", post(funnels::analyze_funnel).delete(delete_funnel_named_analyze))
        .route("/api/sites/{siteId}/funnels/{funnelId}/sessions", post(funnels::get_funnel_step_sessions))
        .route("/api/sites/{siteId}/funnels/{funnelId}", delete(funnels::delete_funnel))
        .route("/api/sites/{siteId}/goals", get(goals::get_goals).post(goals::create_goal))
        .route(
            "/api/sites/{siteId}/goals/time-series",
            get(goals::get_goal_time_series).put(update_goal_named_time_series).delete(delete_goal_named_time_series),
        )
        .route("/api/sites/{siteId}/goals/{goalId}/sessions", get(goals::get_goal_sessions))
        .route("/api/sites/{siteId}/goals/{goalId}", delete(goals::delete_goal).put(goals::update_goal))
        .route("/api/sites/{siteId}/performance/overview", get(performance::get_performance_overview))
        .route("/api/sites/{siteId}/performance/time-series", get(performance::get_performance_time_series))
        .route("/api/sites/{siteId}/performance/by-dimension", get(performance::get_performance_by_dimension))
        .route("/api/sites/{siteId}/bots/overview", get(bots::get_bot_overview))
        .route("/api/sites/{siteId}/bots/time-series", get(bots::get_bot_time_series))
        .route("/api/sites/{siteId}/bots/by-dimension", get(bots::get_bot_dimension))
        .route("/api/sites/{siteId}/bots/ai-summary", get(bots::get_bot_ai_summary))
}

/// DELETE /api/sites/:siteId/funnels/analyze: deleteFunnel with `funnelId` "analyze".
async fn delete_funnel_named_analyze(
    State(state): State<AppState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    raw_params: RawPathParams,
    body: Body,
) -> Response {
    let params = match path_params(&raw_params, &method, &uri).await {
        Ok(params) => params,
        Err(response) => return response,
    };
    if let Err(response) = read_body(&headers, body).await {
        return response;
    }
    let site_param = params.get("siteId").cloned().unwrap_or_default();
    let request = match site_scoped(&state, &headers, &uri, &site_param, SiteGuard::Member, route_scope("funnels", "write"), ChainSteps::FULL).await {
        Ok(request) => request,
        Err(response) => return response,
    };
    funnels::delete_funnel_by_param(&state, &request.auth, &request.site_id, "analyze").await
}

/// PUT /api/sites/:siteId/goals/time-series: updateGoal with `goalId` "time-series".
async fn update_goal_named_time_series(
    State(state): State<AppState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    raw_params: RawPathParams,
    body: Body,
) -> Response {
    let params = match path_params(&raw_params, &method, &uri).await {
        Ok(params) => params,
        Err(response) => return response,
    };
    let body = match read_body(&headers, body).await {
        Ok(body) => body,
        Err(response) => return response,
    };
    let site_param = params.get("siteId").cloned().unwrap_or_default();
    let request = match site_scoped(&state, &headers, &uri, &site_param, SiteGuard::Member, route_scope("goals", "write"), ChainSteps::FULL).await {
        Ok(request) => request,
        Err(response) => return response,
    };
    goals::update_goal_by_param(&state, &request.auth, &request.site_id, "time-series", &body).await
}

/// DELETE /api/sites/:siteId/goals/time-series: deleteGoal with `goalId` "time-series".
async fn delete_goal_named_time_series(
    State(state): State<AppState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    raw_params: RawPathParams,
    body: Body,
) -> Response {
    let params = match path_params(&raw_params, &method, &uri).await {
        Ok(params) => params,
        Err(response) => return response,
    };
    if let Err(response) = read_body(&headers, body).await {
        return response;
    }
    let site_param = params.get("siteId").cloned().unwrap_or_default();
    let request = match site_scoped(&state, &headers, &uri, &site_param, SiteGuard::Member, route_scope("goals", "write"), ChainSteps::FULL).await {
        Ok(request) => request,
        Err(response) => return response,
    };
    goals::delete_goal_by_param(&state, &request.auth, &request.site_id, "time-series").await
}
