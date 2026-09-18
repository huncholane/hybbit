//! Organization-wide IP exclusions, ported from the organization half of
//! server/src/api/organizationExclusions/organizationExcludedIPs.ts
//! (`getOrganizationExcludedIPs`, `updateOrganizationExcludedIPs`).

use axum::{
    body::Body,
    extract::State,
    http::{HeaderMap, Method, StatusCode, Uri},
    response::Response,
};
use tracing::{debug, error, info};

use super::{
    request::{self, object},
    zod,
};
use crate::{
    analytics::{
        chain::{org_scoped, route_scope},
        js::{JsValue, json},
    },
    state::AppState,
    tracking::validate_ip_pattern,
};

fn failed(message: &str) -> JsValue {
    object(vec![("success", JsValue::Bool(false)), ("error", message.into())])
}

/// GET /api/organizations/:organizationId/excluded-ips, chain `orgOrgRead`.
pub async fn get(State(state): State<AppState>, method: Method, uri: Uri, headers: HeaderMap) -> Response {
    let params = match request::route_params(&uri, &[3]) {
        Ok(params) => params,
        Err(failure) => return request::param_failure(failure, method, uri).await,
    };
    let organization_id = params[0].clone();
    if let Err(response) = org_scoped(&state, &headers, &uri, &organization_id, false, route_scope("org", "read")).await
    {
        return response;
    }

    let stored: Result<Option<Option<String>>, sqlx::Error> =
        sqlx::query_scalar(r#"select "excluded_ips"::text from "organization" where "id" = $1 limit 1"#)
            .bind(&organization_id)
            .fetch_optional(&state.pg)
            .await;
    match stored {
        Err(err) => {
            error!(error = %err, "Error getting organization excluded IPs");
            request::send(StatusCode::INTERNAL_SERVER_ERROR, &failed("Failed to get organization excluded IPs"))
        }
        Ok(None) => request::send(StatusCode::NOT_FOUND, &failed("Organization not found")),
        Ok(Some(stored)) => {
            // `Array.isArray(org.excludedIPs) ? org.excludedIPs : []`
            let value = stored.as_deref().and_then(|text| json::parse(text).ok()).filter(|value| matches!(value, JsValue::Array(_)));
            debug!(organization_id, "Fetched organization excluded IPs");
            request::send(
                StatusCode::OK,
                &object(vec![
                    ("success", JsValue::Bool(true)),
                    ("excludedIPs", value.unwrap_or(JsValue::Array(Vec::new()))),
                ]),
            )
        }
    }
}

/// PUT /api/organizations/:organizationId/excluded-ips, chain `orgAdminOrgWrite`.
/// Replaces the list wholesale.
pub async fn update(
    State(state): State<AppState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let params = match request::route_params(&uri, &[3]) {
        Ok(params) => params,
        Err(failure) => return request::param_failure(failure, method, uri).await,
    };
    let organization_id = params[0].clone();
    let (body, lone_surrogate) = match request::read_body_checked(&headers, body).await {
        Ok(body) => body,
        Err(response) => return response,
    };
    if let Err(response) = org_scoped(&state, &headers, &uri, &organization_id, true, route_scope("org", "write")).await
    {
        return response;
    }

    let excluded = match zod::excluded_ips(&body) {
        Ok(excluded) => excluded,
        Err(issues) => {
            return request::send(
                StatusCode::BAD_REQUEST,
                &object(vec![
                    ("success", JsValue::Bool(false)),
                    ("error", "Invalid request data".into()),
                    ("details", zod::flatten(&issues)),
                ]),
            );
        }
    };

    let invalid: Vec<JsValue> = excluded
        .iter()
        .filter_map(|ip| {
            let validation = validate_ip_pattern(ip);
            validation.error.map(|error| JsValue::String(format!("{ip}: {error}")))
        })
        .collect();
    if !invalid.is_empty() {
        return request::send(
            StatusCode::BAD_REQUEST,
            &object(vec![
                ("success", JsValue::Bool(false)),
                ("error", "Invalid IP patterns".into()),
                ("details", JsValue::Array(invalid)),
            ]),
        );
    }

    let stored = JsValue::Array(excluded.iter().map(|ip| JsValue::String(ip.clone())).collect());
    let stored_json = json::stringify(&stored).unwrap_or_default();
    if request::jsonb_rejects(lone_surrogate, &stored_json) {
        error!("Error updating organization excluded IPs");
        return request::send(
            StatusCode::INTERNAL_SERVER_ERROR,
            &failed("Failed to update organization excluded IPs"),
        );
    }

    let updated: Result<Option<String>, sqlx::Error> = sqlx::query_scalar(
        r#"update "organization" set "excluded_ips" = $1::jsonb where "id" = $2 returning "id""#,
    )
    .bind(&stored_json)
    .bind(&organization_id)
    .fetch_optional(&state.pg)
    .await;
    match updated {
        Err(err) => {
            error!(error = %err, "Error updating organization excluded IPs");
            request::send(StatusCode::INTERNAL_SERVER_ERROR, &failed("Failed to update organization excluded IPs"))
        }
        Ok(None) => request::send(StatusCode::NOT_FOUND, &failed("Organization not found")),
        Ok(Some(_)) => {
            // Every Site in the Organization reads this list at ingestion
            state.site_config.invalidate_organization(&organization_id);
            info!(organization_id, count = excluded.len(), "Updated organization excluded IPs");
            request::send(
                StatusCode::OK,
                &object(vec![("success", JsValue::Bool(true)), ("excludedIPs", stored)]),
            )
        }
    }
}
