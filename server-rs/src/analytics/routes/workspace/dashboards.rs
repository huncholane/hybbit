//! Saved dashboards, ported from server/src/api/analytics/dashboards
//! (getDashboards, getDashboard, createDashboard, updateDashboard,
//! deleteDashboard).
//!
//! The two GETs share `authDashboardsRead` with POST /dashboards/run-card, and
//! @fastify/rate-limit appended run-card's hook to that shared chain, so they are
//! rate limited under run-card's key (see `rate_limit`).

use std::net::SocketAddr;

use axum::{
    body::Body,
    extract::{ConnectInfo, State},
    http::{HeaderMap, Method, StatusCode, Uri},
    response::Response,
};
use sqlx::{PgPool, Row, postgres::PgRow};
use tracing::{debug, error, info, warn};

use super::{
    dashboard_schema,
    rate_limit::{self, RUN_CARD},
    request::{self, object, pg_int},
    schema::validation_error_body,
};
use crate::{
    analytics::{
        chain::{ChainSteps, SiteGuard, SiteRequest, route_scope, site_scoped},
        js::{JsValue, json, number::parse_int_10},
        utils::time_window::now_ms,
    },
    state::AppState,
};

#[derive(Debug, thiserror::Error)]
enum HandlerError {
    #[error(transparent)]
    Db(#[from] sqlx::Error),
    #[error("integer out of range for type integer")]
    OutOfRange,
}

fn bind_int(id: f64) -> Result<i32, HandlerError> {
    pg_int(id).ok_or(HandlerError::OutOfRange)
}

/// `parseInt(raw, 10)` when it is a positive number
fn parse_positive(raw: &str) -> Option<f64> {
    let id = parse_int_10(raw);
    (!id.is_nan() && id > 0.0).then_some(id)
}

const COLUMNS: &str = r#""dashboard_id", "site_id", "user_id", "name", "config"::text as "config",
    "created_at"::text as "created_at", "updated_at"::text as "updated_at""#;

/// A `dashboards` row as drizzle hands it back: jsonb through `JSON.parse`,
/// timestamps as Postgres text.
fn dashboard_row(row: &PgRow) -> Result<(Option<i32>, JsValue), sqlx::Error> {
    let site_id: Option<i32> = row.try_get("site_id")?;
    let config_text: String = row.try_get("config")?;
    let config = json::parse(&config_text).unwrap_or(JsValue::String(config_text));
    let text = |value: Option<String>| value.map_or(JsValue::Null, JsValue::String);
    let value = object(vec![
        ("dashboardId", JsValue::Number(f64::from(row.try_get::<i32, _>("dashboard_id")?))),
        ("siteId", site_id.map_or(JsValue::Null, |id| JsValue::Number(f64::from(id)))),
        ("userId", text(row.try_get("user_id")?)),
        ("name", JsValue::String(row.try_get("name")?)),
        ("config", config),
        ("createdAt", text(row.try_get("created_at")?)),
        ("updatedAt", text(row.try_get("updated_at")?)),
    ]);
    Ok((site_id, value))
}

async fn find_dashboard(pg: &PgPool, dashboard_id: f64) -> Result<Option<(Option<i32>, JsValue)>, HandlerError> {
    let row = sqlx::query(&format!(r#"select {COLUMNS} from "dashboards" where "dashboards"."dashboard_id" = $1 limit 1"#))
        .bind(bind_int(dashboard_id)?)
        .fetch_optional(pg)
        .await?;
    Ok(row.as_ref().map(dashboard_row).transpose()?)
}

fn failure(err: &HandlerError, message: &str) -> Response {
    error!(error = %err, "{message}");
    request::error(StatusCode::INTERNAL_SERVER_ERROR, message)
}

fn peer_ip(headers: &HeaderMap, connect_info: Option<ConnectInfo<SocketAddr>>) -> String {
    let peer = connect_info.map_or_else(|| std::net::Ipv4Addr::LOCALHOST.into(), |ConnectInfo(address)| address.ip());
    request::request_ip(headers, peer)
}

/// `authDashboardsRead` plus the run-card limiter: the chain, then one charge.
async fn read_chain(
    state: &AppState,
    uri: &Uri,
    headers: &HeaderMap,
    site_param: &str,
    ip: String,
) -> Result<(SiteRequest, rate_limit::LimitHeaders), Response> {
    let site = site_scoped(state, headers, uri, site_param, SiteGuard::Member, route_scope("dashboards", "read"), ChainSteps::FULL)
        .await?;
    let key = site.auth.user_id.clone().unwrap_or(ip);
    let limit_headers = rate_limit::check(state, RUN_CARD, &key).await?;
    Ok((site, limit_headers))
}

async fn write_chain(state: &AppState, uri: &Uri, headers: &HeaderMap, site_param: &str) -> Result<SiteRequest, Response> {
    site_scoped(state, headers, uri, site_param, SiteGuard::Member, route_scope("dashboards", "write"), ChainSteps::FULL).await
}

/// GET /api/sites/:siteId/dashboards
pub async fn list(
    State(state): State<AppState>,
    connect_info: Option<ConnectInfo<SocketAddr>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    let params = match request::route_params(&uri, &[3]) {
        Ok(params) => params,
        Err(failure) => return request::param_failure(failure, method, uri).await,
    };
    let ip = peer_ip(&headers, connect_info);
    let (site, limit_headers) = match read_chain(&state, &uri, &headers, &params[0], ip).await {
        Ok(chain) => chain,
        Err(response) => return response,
    };
    let response = match parse_positive(&site.site_id) {
        None => request::error(StatusCode::BAD_REQUEST, "Invalid site ID"),
        Some(site_id) => {
            let result: Result<Response, HandlerError> = async {
                let rows = sqlx::query(&format!(
                    r#"select {COLUMNS} from "dashboards" where "dashboards"."site_id" = $1 order by "dashboards"."updated_at" desc"#
                ))
                .bind(bind_int(site_id)?)
                .fetch_all(&state.pg)
                .await?;
                let items = rows.iter().map(|row| dashboard_row(row).map(|(_, value)| value)).collect::<Result<Vec<_>, _>>()?;
                debug!(site_id, count = items.len(), "Fetched dashboards");
                Ok(request::send(StatusCode::OK, &JsValue::Array(items)))
            }
            .await;
            result.unwrap_or_else(|err| failure(&err, "Failed to fetch dashboards"))
        }
    };
    rate_limit::with_headers(response, limit_headers)
}

/// The two ids of `/dashboards/:dashboardId` routes, validated in Node's order.
fn ids(site_param: &str, dashboard_param: &str) -> Result<(f64, f64), Response> {
    let site_id = parse_positive(site_param);
    let dashboard_id = parse_positive(dashboard_param);
    let Some(site_id) = site_id else {
        return Err(request::error(StatusCode::BAD_REQUEST, "Invalid site ID"));
    };
    let Some(dashboard_id) = dashboard_id else {
        return Err(request::error(StatusCode::BAD_REQUEST, "Invalid dashboard ID"));
    };
    Ok((site_id, dashboard_id))
}

/// Whether a loaded dashboard belongs to the route's site (`dashboard.siteId !== siteId`).
fn same_site(row_site: Option<i32>, site_id: f64) -> bool {
    row_site.is_some_and(|id| f64::from(id) == site_id)
}

/// GET /api/sites/:siteId/dashboards/:dashboardId
pub async fn get_one(
    State(state): State<AppState>,
    connect_info: Option<ConnectInfo<SocketAddr>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    let params = match request::route_params(&uri, &[3, 5]) {
        Ok(params) => params,
        Err(failure) => return request::param_failure(failure, method, uri).await,
    };
    let ip = peer_ip(&headers, connect_info);
    let (site, limit_headers) = match read_chain(&state, &uri, &headers, &params[0], ip).await {
        Ok(chain) => chain,
        Err(response) => return response,
    };
    let response = match ids(&site.site_id, &params[1]) {
        Err(response) => response,
        Ok((site_id, dashboard_id)) => {
            let result: Result<Response, HandlerError> = async {
                let Some((row_site, value)) = find_dashboard(&state.pg, dashboard_id).await? else {
                    return Ok(request::error(StatusCode::NOT_FOUND, "Dashboard not found"));
                };
                if !same_site(row_site, site_id) {
                    return Ok(request::error(StatusCode::FORBIDDEN, "Dashboard does not belong to the specified site"));
                }
                Ok(request::send(StatusCode::OK, &value))
            }
            .await;
            result.unwrap_or_else(|err| failure(&err, "Failed to fetch dashboard"))
        }
    };
    rate_limit::with_headers(response, limit_headers)
}

/// POST /api/sites/:siteId/dashboards
pub async fn create(State(state): State<AppState>, method: Method, uri: Uri, headers: HeaderMap, body: Body) -> Response {
    let params = match request::route_params(&uri, &[3]) {
        Ok(params) => params,
        Err(failure) => return request::param_failure(failure, method, uri).await,
    };
    let body = match request::read_body(&headers, body).await {
        Ok(body) => body,
        Err(response) => return response,
    };
    let site = match write_chain(&state, &uri, &headers, &params[0]).await {
        Ok(site) => site,
        Err(response) => return response,
    };
    let Some(site_id) = parse_positive(&site.site_id) else {
        return request::error(StatusCode::BAD_REQUEST, "Invalid site ID");
    };
    let input = match dashboard_schema::parse_create(&body) {
        Ok(input) => input,
        Err(issues) => return request::send(StatusCode::BAD_REQUEST, &validation_error_body(&issues)),
    };
    let config = input.config.unwrap_or_else(|| object(vec![("cards", JsValue::Array(Vec::new()))]));
    let config_text = json::stringify(&config).unwrap_or_default();

    let result: Result<Response, HandlerError> = async {
        let dashboard_id: Option<i32> = sqlx::query_scalar(
            r#"insert into "dashboards" ("site_id", "user_id", "name", "config") values ($1, $2, $3, $4::jsonb)
               returning "dashboard_id""#,
        )
        .bind(bind_int(site_id)?)
        .bind(site.auth.user_id.as_deref())
        .bind(input.name.as_deref().unwrap_or_default())
        .bind(&config_text)
        .fetch_optional(&state.pg)
        .await?;
        let Some(dashboard_id) = dashboard_id else {
            return Ok(request::error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to create dashboard"));
        };
        info!(site_id, dashboard_id, "Dashboard created");
        Ok(request::send(
            StatusCode::CREATED,
            &object(vec![("success", true.into()), ("dashboardId", JsValue::Number(f64::from(dashboard_id)))]),
        ))
    }
    .await;
    result.unwrap_or_else(|err| failure(&err, "Failed to create dashboard"))
}

/// PUT /api/sites/:siteId/dashboards/:dashboardId
pub async fn update(State(state): State<AppState>, method: Method, uri: Uri, headers: HeaderMap, body: Body) -> Response {
    let params = match request::route_params(&uri, &[3, 5]) {
        Ok(params) => params,
        Err(failure) => return request::param_failure(failure, method, uri).await,
    };
    let body = match request::read_body(&headers, body).await {
        Ok(body) => body,
        Err(response) => return response,
    };
    let site = match write_chain(&state, &uri, &headers, &params[0]).await {
        Ok(site) => site,
        Err(response) => return response,
    };
    let (site_id, dashboard_id) = match ids(&site.site_id, &params[1]) {
        Ok(ids) => ids,
        Err(response) => return response,
    };
    let input = match dashboard_schema::parse_update(&body) {
        Ok(input) => input,
        Err(issues) => return request::send(StatusCode::BAD_REQUEST, &validation_error_body(&issues)),
    };

    let result: Result<Response, HandlerError> = async {
        let Some((row_site, _)) = find_dashboard(&state.pg, dashboard_id).await? else {
            return Ok(request::error(StatusCode::NOT_FOUND, "Dashboard not found"));
        };
        if !same_site(row_site, site_id) {
            return Ok(request::error(StatusCode::FORBIDDEN, "Dashboard does not belong to the specified site"));
        }
        let mut assignments = Vec::new();
        let mut position = 1;
        if input.name.is_some() {
            assignments.push(format!(r#""name" = ${position}"#));
            position += 1;
        }
        if input.config.is_some() {
            assignments.push(format!(r#""config" = ${position}::jsonb"#));
            position += 1;
        }
        assignments.push(format!(r#""updated_at" = ${position}::timestamp"#));
        position += 1;
        let sql = format!(
            r#"update "dashboards" set {} where "dashboards"."dashboard_id" = ${position} returning "dashboard_id""#,
            assignments.join(", ")
        );
        let mut statement = sqlx::query_scalar::<_, i32>(&sql);
        if let Some(name) = &input.name {
            statement = statement.bind(name.clone());
        }
        if let Some(config) = &input.config {
            statement = statement.bind(json::stringify(config).unwrap_or_default());
        }
        let now = crate::analytics::js::date::to_iso_string(now_ms()).unwrap_or_default();
        statement = statement.bind(now).bind(bind_int(dashboard_id)?);
        if statement.fetch_optional(&state.pg).await?.is_none() {
            return Ok(request::error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to update dashboard"));
        }
        info!(site_id, dashboard_id, "Dashboard updated");
        Ok(request::send(StatusCode::OK, &object(vec![("success", true.into())])))
    }
    .await;
    result.unwrap_or_else(|err| failure(&err, "Failed to update dashboard"))
}

/// DELETE /api/sites/:siteId/dashboards/:dashboardId
pub async fn delete(State(state): State<AppState>, method: Method, uri: Uri, headers: HeaderMap, body: Body) -> Response {
    let params = match request::route_params(&uri, &[3, 5]) {
        Ok(params) => params,
        Err(failure) => return request::param_failure(failure, method, uri).await,
    };
    if let Err(response) = request::read_body(&headers, body).await {
        return response;
    }
    let site = match write_chain(&state, &uri, &headers, &params[0]).await {
        Ok(site) => site,
        Err(response) => return response,
    };
    let (site_id, dashboard_id) = match ids(&site.site_id, &params[1]) {
        Ok(ids) => ids,
        Err(response) => return response,
    };

    let result: Result<Response, HandlerError> = async {
        let Some((row_site, _)) = find_dashboard(&state.pg, dashboard_id).await? else {
            return Ok(request::error(StatusCode::NOT_FOUND, "Dashboard not found"));
        };
        if !same_site(row_site, site_id) {
            return Ok(request::error(StatusCode::FORBIDDEN, "Dashboard does not belong to the specified site"));
        }
        let deleted: Option<i32> =
            sqlx::query_scalar(r#"delete from "dashboards" where "dashboards"."dashboard_id" = $1 returning "dashboard_id""#)
                .bind(bind_int(dashboard_id)?)
                .fetch_optional(&state.pg)
                .await?;
        if deleted.is_none() {
            warn!(site_id, dashboard_id, "Dashboard vanished before delete");
            return Ok(request::error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to delete dashboard"));
        }
        info!(site_id, dashboard_id, "Dashboard deleted");
        Ok(request::send(StatusCode::OK, &object(vec![("success", true.into())])))
    }
    .await;
    result.unwrap_or_else(|err| failure(&err, "Failed to delete dashboard"))
}
