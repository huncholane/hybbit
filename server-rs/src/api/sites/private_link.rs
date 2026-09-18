//! `GET`/`POST /api/sites/:siteId/private-link-config`, ported from
//! server/src/api/sites/getSitePrivateLinkConfig.ts and
//! updateSitePrivateLinkConfig.ts, both on the `adminSitesWrite` chain.
//!
//! The two disagree on how they read `:siteId`: the GET uses `parseInt(id, 10)`
//! and only rejects NaN (so `-5` reaches the lookup and answers 404, and `12abc`
//! reads as 12), while the POST uses `Number(id)` and requires a positive
//! integer. Both spellings are kept.

use axum::{
    body::Body,
    extract::State,
    http::{HeaderMap, Method, StatusCode, Uri},
    response::Response,
};
use serde_json::{Value, json};
use tracing::{debug, error, warn};

use super::{
    config::lifecycle_error_response,
    lifecycle::{self, LifecycleFailure},
    request::{self, Issues, object},
};
use crate::{
    analytics::{
        chain::{ChainSteps, SiteGuard, route_scope, site_scoped},
        js::number::parse_int_10,
        routes::people::common::path_params,
    },
    site_config::SiteRef,
    state::AppState,
};

const ACTIONS: [&str; 2] = ["generate_private_link_key", "revoke_private_link_key"];

/// `updatePrivateLinkConfigSchema.safeParse(body)`: the action, or `error.flatten()`.
pub fn parse_action(body: Option<&Value>) -> Result<String, Value> {
    let mut issues = Issues::default();
    let Some(Value::Object(fields)) = body else {
        issues.form(request::invalid_type("object", body));
        return Err(issues.flatten());
    };
    match fields.get("action") {
        Some(Value::String(action)) if ACTIONS.contains(&action.as_str()) => Ok(action.clone()),
        Some(Value::String(action)) => {
            issues.field("action", request::invalid_enum_value(&ACTIONS, action));
            Err(issues.flatten())
        }
        other => {
            issues.field("action", request::enum_invalid_type(&ACTIONS, other));
            Err(issues.flatten())
        }
    }
}

pub async fn get_private_link_config(
    State(state): State<AppState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    let params = match path_params(&method, &uri, &[3]).await {
        Ok(params) => params,
        Err(response) => return response,
    };
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

    // `parseInt(siteId, 10)`; only NaN is refused here
    let parsed = parse_int_10(&site.site_id);
    if parsed.is_nan() {
        return request::failure(StatusCode::BAD_REQUEST, "Invalid site ID");
    }
    let Some(numeric) = request::pg_int(parsed) else {
        // Outside int4 Postgres refuses the bind and `reload` lets the throw out
        error!(site_id = %site.site_id, "Site id is not a Postgres integer; Node's reload throws here");
        return request::failure(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to get site private link configuration",
        );
    };

    match state.site_config.reload(&SiteRef::Number(i64::from(numeric))).await {
        Ok(Some(config)) => {
            debug!(site_id = numeric, present = config.private_link_key.is_some(), "Private link config read");
            request::send(
                StatusCode::OK,
                &object(vec![
                    ("success", Value::Bool(true)),
                    (
                        "data",
                        object(vec![(
                            "privateLinkKey",
                            config.private_link_key.map_or(Value::Null, Value::String),
                        )]),
                    ),
                ]),
            )
        }
        Ok(None) => request::failure(StatusCode::NOT_FOUND, "Site not found"),
        Err(err) => {
            error!(error = %err, site_id = numeric, "Error getting site private link configuration");
            request::failure(StatusCode::INTERNAL_SERVER_ERROR, "Failed to get site private link configuration")
        }
    }
}

pub async fn update_private_link_config(
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
    let body = match request::read_body(&headers, body).await {
        Ok(body) => body,
        Err(response) => return response,
    };
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
    let action = match parse_action(body.as_ref()) {
        Ok(action) => action,
        Err(details) => {
            warn!(site_id, "Private link payload failed validation");
            return request::send(
                StatusCode::BAD_REQUEST,
                &json!({ "success": false, "error": "Invalid request body", "details": details }),
            );
        }
    };

    match lifecycle::update_private_link(&state, site_id, action == ACTIONS[0]).await {
        Ok(key) => request::send(
            StatusCode::OK,
            &object(vec![
                ("success", Value::Bool(true)),
                ("data", object(vec![("privateLinkKey", key.map_or(Value::Null, Value::String))])),
            ]),
        ),
        Err(LifecycleFailure::Lifecycle(error)) => {
            lifecycle_error_response(&lifecycle::SiteLifecycleError { details: None, ..error })
        }
        Err(LifecycleFailure::Store(message)) => {
            error!(error = %message, site_id, "Error updating site private link config");
            request::failure(StatusCode::INTERNAL_SERVER_ERROR, "Failed to update site API configuration")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn action_schema_matches_zod() {
        assert_eq!(parse_action(Some(&json!({ "action": "revoke_private_link_key" }))).unwrap(), "revoke_private_link_key");
        assert_eq!(
            parse_action(Some(&json!({ "action": "nope" }))).unwrap_err(),
            json!({ "formErrors": [], "fieldErrors": { "action": [
                "Invalid enum value. Expected 'generate_private_link_key' | 'revoke_private_link_key', received 'nope'"
            ] } })
        );
        assert_eq!(
            parse_action(Some(&json!({}))).unwrap_err(),
            json!({ "formErrors": [], "fieldErrors": { "action": ["Required"] } })
        );
        assert_eq!(parse_action(None).unwrap_err(), json!({ "formErrors": ["Required"], "fieldErrors": {} }));
    }
}
