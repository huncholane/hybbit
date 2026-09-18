//! The admin panel API plus feature flag and experiment management, ported from
//! server/src/api/admin, server/src/api/featureFlags and server/src/api/experiments.
//!
//! - the panel routes run behind `adminOnly` (requireAdmin, then validateTimeParams),
//!   which answers 401 - not 403 - for everyone who is not a Better Auth system admin;
//! - `POST /api/admin/telemetry` has no guard and refuses every request without
//!   `CLOUD=true`;
//! - feature flags read behind `authFlagsRead` and write behind `adminFlagsWrite`,
//!   experiments behind `authExperimentsRead` and `adminExperimentsWrite`.
//!
//! Routing mirrors find-my-way where axum's matcher differs: a parameter may match
//! an empty segment, and a method a path does not register gets Fastify's plain
//! 404 rather than axum's 405 with an `Allow` header.
// Early replies travel as `Err(Response)`, the shape `analytics::chain` hands back
#![allow(clippy::result_large_err)]

use axum::{
    Router,
    http::{HeaderMap, Uri},
    response::Response,
    routing::{MethodRouter, get, post, put},
};

use crate::{
    analytics::{chain::account_scoped, js::JsObject},
    auth::guards::Authenticated,
    state::AppState,
};

mod clickhouse_stats;
mod event_counts;
mod experiment_results;
mod experiments;
mod flags;
mod goal_conditions;
mod move_site;
mod org_management;
mod organizations;
mod plans;
mod service_event_count;
mod sites;
mod subscriptions;
mod support;
mod telemetry;
mod zod;

/// What an `adminOnly` handler receives once the chain has run.
pub(crate) struct AdminRequest {
    #[allow(dead_code)]
    pub auth: Authenticated,
    /// `request.query`, parsed the way Fastify parses it
    pub query: JsObject,
}

/// `adminOnly`: `requireAdmin`, then `validateTimeParams`.
pub(crate) async fn admin_chain(
    state: &AppState,
    headers: &HeaderMap,
    uri: &Uri,
) -> Result<AdminRequest, Response> {
    let request = account_scoped(state, headers, uri, true, None).await?;
    Ok(AdminRequest { auth: request.auth, query: request.query })
}

/// A route the admin panel does not expose under a method it does not register.
fn route(
    router: Router<AppState>,
    pattern: &str,
    handlers: MethodRouter<AppState>,
    registered: &[&str],
) -> Router<AppState> {
    support::with_empty_params(router, pattern, support::complete(handlers, registered))
}

pub fn router() -> Router<AppState> {
    let mut router = Router::new();

    // The admin panel
    router = route(router, "/api/admin/clickhouse-stats", get(clickhouse_stats::stats), &["GET"]);
    router = route(router, "/api/admin/clickhouse-query-log", get(clickhouse_stats::query_log), &["GET"]);
    router = route(router, "/api/admin/sites", get(sites::list), &["GET"]);
    router = route(router, "/api/admin/sites/{siteId}/move", put(move_site::move_site), &["PUT"]);
    router = route(router, "/api/admin/organizations", get(organizations::list), &["GET"]);
    router = route(router, "/api/admin/organization-options", get(org_management::organization_options), &["GET"]);
    router = route(router, "/api/admin/subscription-plans", get(org_management::subscription_plans), &["GET"]);
    router = route(
        router,
        "/api/admin/organizations/{organizationId}/subscription-override",
        put(org_management::subscription_override),
        &["PUT"],
    );
    router = route(
        router,
        "/api/admin/organizations/{organizationId}/members/{memberId}",
        get(org_management::get_member).patch(org_management::update_member).delete(org_management::delete_member),
        &["GET", "PATCH", "DELETE"],
    );
    router = route(router, "/api/admin/service-event-count", get(service_event_count::service_event_count), &["GET"]);
    router = route(router, "/api/admin/telemetry", post(telemetry::collect), &["POST"]);

    // Feature flags: the evaluate routes stay in crate::routes::feature_flags
    router = route(
        router,
        "/api/sites/{siteId}/feature-flags",
        get(flags::list).post(flags::create),
        &["GET", "POST"],
    );
    router = route(
        router,
        "/api/sites/{siteId}/feature-flags/{flagId}",
        put(flags::update).delete(flags::delete),
        &["PUT", "DELETE"],
    );
    // find-my-way falls back to the parametric sibling when the static node has no
    // handler for the method, so PUT and DELETE on `.../feature-flags/evaluate`
    // reach the `:flagId` handlers with "evaluate" as the id (a 400). POST there
    // belongs to `crate::routes::feature_flags`, which registers it on the same
    // path; axum merges the two method routers as long as neither claims POST twice.
    router = router.route(
        "/api/sites/{siteId}/feature-flags/evaluate",
        support::complete_except(put(flags::update).delete(flags::delete), &["PUT", "DELETE"], &["POST"]),
    );

    // Experiments
    router = route(
        router,
        "/api/sites/{siteId}/experiments",
        get(experiments::list).post(experiments::create),
        &["GET", "POST"],
    );
    router = route(
        router,
        "/api/sites/{siteId}/experiments/{experimentId}",
        put(experiments::update).delete(experiments::delete),
        &["PUT", "DELETE"],
    );
    router = route(
        router,
        "/api/sites/{siteId}/experiments/{experimentId}/results",
        get(experiment_results::results),
        &["GET"],
    );

    router
}
