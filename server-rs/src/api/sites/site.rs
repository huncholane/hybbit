//! `GET /api/sites/:siteId`, ported from server/src/api/sites/getSite.ts on the
//! `publicSitesRead` chain.
//!
//! The payload is the `sites` row itself, not the Site Configuration: only
//! `type` and `domain` get a fallback, so every other nullable column reaches the
//! client as `null`. `createdAt`/`updatedAt` are `timestamp without time zone`
//! columns drizzle maps with `mode: "string"`, so Node sends Postgres's own text
//! (`2026-09-18 08:14:22.380466`) and Rust reads them with `::text`.

use axum::{
    extract::State,
    http::{HeaderMap, Method, StatusCode, Uri},
    response::Response,
};
use serde_json::Value;
use sqlx::Row;
use tracing::{debug, error};

use super::request::{self, object};
use crate::{
    analytics::{
        chain::{ChainSteps, SiteGuard, route_scope, site_scoped},
        routes::{people::common::path_params, workspace::access::RequestAccess},
    },
    state::AppState,
};

/// The columns `db.query.sites.findFirst` hands the handler, in the order the
/// response literal reads them.
const COLUMNS: &str = r#"id, site_id, name, type, domain, created_at::text AS created_at,
    updated_at::text AS updated_at, created_by, organization_id, "saltUserIds", "public", embed_enabled,
    "blockBots", first_party_proxy, "trackIp", "sessionReplay", "webVitals", "trackErrors", "trackOutbound",
    "trackUrlParams", "trackInitialPageView", "trackSpaNavigation", "trackButtonClicks", "trackCopy",
    "trackFormInteractions", track_heartbeat, heartbeat_interval, bounce_threshold"#;

fn nullable_bool(row: &sqlx::postgres::PgRow, column: &str) -> Result<Value, sqlx::Error> {
    Ok(row.try_get::<Option<bool>, _>(column)?.map_or(Value::Null, Value::Bool))
}

fn nullable_text(row: &sqlx::postgres::PgRow, column: &str) -> Result<Value, sqlx::Error> {
    Ok(row.try_get::<Option<String>, _>(column)?.map_or(Value::Null, Value::String))
}

fn nullable_int(row: &sqlx::postgres::PgRow, column: &str) -> Result<Value, sqlx::Error> {
    Ok(row.try_get::<Option<i32>, _>(column)?.map_or(Value::Null, Value::from))
}

pub async fn get_site(State(state): State<AppState>, method: Method, uri: Uri, headers: HeaderMap) -> Response {
    let params = match path_params(&method, &uri, &[3]).await {
        Ok(params) => params,
        Err(response) => return response,
    };
    let site = match site_scoped(
        &state,
        &headers,
        &uri,
        &params[0],
        SiteGuard::Public,
        route_scope("sites", "read"),
        ChainSteps::FULL,
    )
    .await
    {
        Ok(site) => site,
        Err(response) => return response,
    };

    // `Number(siteId)` bound to an int4 column: a value Postgres cannot read as an
    // integer throws inside the handler's try, which answers 500 like any other
    // failure there.
    let numeric = request::js_number(&site.site_id);
    let Some(site_id) = request::pg_int(numeric) else {
        error!(site_id = %site.site_id, "Site id is not a Postgres integer; Node's query throws here");
        return request::error(StatusCode::INTERNAL_SERVER_ERROR, "Internal server error");
    };

    let row = match sqlx::query(&format!("SELECT {COLUMNS} FROM sites WHERE site_id = $1 LIMIT 1"))
        .bind(site_id)
        .fetch_optional(&state.pg)
        .await
    {
        Ok(row) => row,
        Err(err) => {
            error!(error = %err, site_id, "Error retrieving site");
            return request::error(StatusCode::INTERNAL_SERVER_ERROR, "Internal server error");
        }
    };
    let Some(row) = row else {
        debug!(site_id, "Site row is gone after the access guard");
        return request::error(StatusCode::NOT_FOUND, "Site not found");
    };

    // `getUserHasAdminAccessToSite(request, site.siteId)`
    let access = RequestAccess::new(&state, &headers, &site.auth);
    let is_owner = access.has_site(f64::from(site_id), true).await;

    let payload = || -> Result<Value, sqlx::Error> {
        let site_type: Option<String> = row.try_get("type")?;
        let domain: Option<String> = row.try_get("domain")?;
        Ok(object(vec![
            ("id", nullable_text(&row, "id")?),
            ("siteId", Value::from(row.try_get::<i32, _>("site_id")?)),
            ("name", Value::String(row.try_get("name")?)),
            // `site.type || "web"`
            ("type", Value::String(site_type.filter(|value| !value.is_empty()).unwrap_or_else(|| "web".into()))),
            // `site.domain || ""`
            ("domain", Value::String(domain.unwrap_or_default())),
            ("createdAt", nullable_text(&row, "created_at")?),
            ("updatedAt", nullable_text(&row, "updated_at")?),
            ("createdBy", nullable_text(&row, "created_by")?),
            ("organizationId", nullable_text(&row, "organization_id")?),
            ("saltUserIds", nullable_bool(&row, "saltUserIds")?),
            ("public", nullable_bool(&row, "public")?),
            ("embedEnabled", nullable_bool(&row, "embed_enabled")?),
            ("blockBots", nullable_bool(&row, "blockBots")?),
            ("firstPartyProxy", nullable_bool(&row, "first_party_proxy")?),
            ("trackIp", nullable_bool(&row, "trackIp")?),
            ("isOwner", Value::Bool(is_owner)),
            ("sessionReplay", nullable_bool(&row, "sessionReplay")?),
            ("webVitals", nullable_bool(&row, "webVitals")?),
            ("trackErrors", nullable_bool(&row, "trackErrors")?),
            ("trackOutbound", nullable_bool(&row, "trackOutbound")?),
            ("trackUrlParams", nullable_bool(&row, "trackUrlParams")?),
            ("trackInitialPageView", nullable_bool(&row, "trackInitialPageView")?),
            ("trackSpaNavigation", nullable_bool(&row, "trackSpaNavigation")?),
            ("trackButtonClicks", nullable_bool(&row, "trackButtonClicks")?),
            ("trackCopy", nullable_bool(&row, "trackCopy")?),
            ("trackFormInteractions", nullable_bool(&row, "trackFormInteractions")?),
            ("trackHeartbeat", nullable_bool(&row, "track_heartbeat")?),
            ("heartbeatInterval", nullable_int(&row, "heartbeat_interval")?),
            ("bounceThreshold", nullable_int(&row, "bounce_threshold")?),
        ]))
    }();

    match payload {
        Ok(payload) => {
            debug!(site_id, is_owner, "Site read");
            request::send(StatusCode::OK, &payload)
        }
        Err(err) => {
            error!(error = %err, site_id, "Error retrieving site");
            request::error(StatusCode::INTERNAL_SERVER_ERROR, "Internal server error")
        }
    }
}
