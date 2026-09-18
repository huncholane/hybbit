//! `DELETE /api/sites/:siteId`, ported from server/src/api/sites/deleteSite.ts on
//! the `adminSitesWrite` chain. The work is the lifecycle service's `delete`: the
//! two session-replay tables in ClickHouse, then the `sites` row, then the Site
//! Configuration cache.

use axum::{
    body::Body,
    extract::State,
    http::{HeaderMap, Method, StatusCode, Uri},
    response::Response,
};
use serde_json::json;
use tracing::error;

use super::{
    config::lifecycle_error_response,
    lifecycle::{self, LifecycleFailure},
    request,
};
use crate::{
    analytics::{
        chain::{ChainSteps, SiteGuard, route_scope, site_scoped},
        routes::people::common::path_params,
    },
    state::AppState,
};

pub async fn delete_site(
    State(state): State<AppState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let params = match path_params(&method, &uri, &[3]).await {
        Ok(params) => params,
        Err(response) => return response,
    };
    // Fastify parses a DELETE body before the preHandlers, so a malformed one is
    // refused ahead of the access check
    if let Err(response) = request::read_body(&headers, body).await {
        return response;
    }
    let site = match site_scoped(
        &state,
        &headers,
        &uri,
        &params[0],
        SiteGuard::Admin,
        route_scope("sites", "write"),
        ChainSteps::TIME_ONLY,
    )
    .await
    {
        Ok(site) => site,
        Err(response) => return response,
    };

    let site_id = request::js_number(&site.site_id);
    if !request::positive_integer(site_id) {
        return request::failure(StatusCode::BAD_REQUEST, "Invalid site ID");
    }

    match lifecycle::delete_site(&state, site_id).await {
        Ok(()) => request::send(StatusCode::OK, &json!({ "success": true })),
        // `deleteSite` sends no `details`, and only the IP-pattern error has any
        Err(LifecycleFailure::Lifecycle(error)) => {
            lifecycle_error_response(&lifecycle::SiteLifecycleError { details: None, ..error })
        }
        Err(LifecycleFailure::Store(message)) => {
            error!(error = %message, site_id, "Error deleting site");
            request::failure(StatusCode::INTERNAL_SERVER_ERROR, "Failed to delete site")
        }
    }
}
