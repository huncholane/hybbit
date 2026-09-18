//! PUT /api/admin/sites/:siteId/move, ported from
//! server/src/api/admin/adminMoveSite.ts and the `applySiteMove` helper it calls
//! (server/src/api/sites/applySiteMove.ts).
//!
//! The system-admin route deliberately skips the per-organization admin and
//! site-limit checks the org-scoped move enforces, so the only gate is `adminOnly`.

use axum::{
    body::Body,
    extract::{RawPathParams, State},
    http::{HeaderMap, Method, StatusCode, Uri},
    response::Response,
};
use chrono::{SecondsFormat, Utc};
use sqlx::PgPool;
use tracing::{debug, error, info};

use crate::{
    analytics::js::{JsValue, number::parse_int_10},
    state::AppState,
};

use super::{
    support::{object, param, path_params, pg_int4, read_body, send_error, send_error_details, send_js},
    zod::parse_move_site_body,
};

/// `applySiteMove(siteId, sourceOrganizationId, targetOrganizationId)`: the
/// reassignment plus the grants that no longer apply in the new organization.
async fn apply_site_move(
    pg: &PgPool,
    site_id: i32,
    source_organization_id: Option<&str>,
    target_organization_id: &str,
) -> Result<Vec<String>, sqlx::Error> {
    let updated_at = Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true);
    let mut tx = pg.begin().await?;
    sqlx::query(
        r#"update "sites" set "organization_id" = $1, "updated_at" = $2::timestamp where "sites"."site_id" = $3"#,
    )
    .bind(target_organization_id)
    .bind(&updated_at)
    .bind(site_id)
    .execute(&mut *tx)
    .await?;
    sqlx::query(r#"delete from "member_site_access" where "member_site_access"."site_id" = $1"#)
        .bind(site_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query(r#"delete from "team_site_access" where "team_site_access"."site_id" = $1"#)
        .bind(site_id)
        .execute(&mut *tx)
        .await?;
    // Site-specific segments travel with the site; organization-wide ones stay put
    sqlx::query(r#"update "segments" set "organization_id" = $1 where "segments"."site_id" = $2"#)
        .bind(target_organization_id)
        .bind(site_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;

    let mut organization_ids = Vec::new();
    if let Some(source) = source_organization_id {
        organization_ids.push(source.to_string());
    }
    organization_ids.push(target_organization_id.to_string());
    let affected: Vec<String> = sqlx::query_scalar(
        r#"select "userId" from "member" where "member"."organizationId" = any($1)"#,
    )
    .bind(&organization_ids)
    .fetch_all(pg)
    .await?;
    Ok(affected)
}

/// `adminMoveSite`
pub async fn move_site(
    State(state): State<AppState>,
    raw_params: RawPathParams,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let body = match read_body(&headers, body).await {
        Ok(body) => body,
        Err(response) => return response,
    };
    let params = match path_params(&raw_params, &method, &uri).await {
        Ok(params) => params,
        Err(response) => return response,
    };
    if let Err(response) = super::admin_chain(&state, &headers, &uri).await {
        return response;
    }

    let site_id = parse_int_10(&param(&params, "siteId"));
    if site_id.is_nan() || site_id <= 0.0 {
        debug!("Rejected an admin site move with a non-positive site id");
        return send_error(StatusCode::BAD_REQUEST, "Invalid site ID: must be a positive integer");
    }

    let target_organization_id = match parse_move_site_body(&body) {
        Ok(id) => id,
        Err(issues) => {
            return send_error_details(StatusCode::BAD_REQUEST, "Invalid request data", issues.flatten());
        }
    };

    // The handler's try block: any Postgres failure becomes "Failed to move site"
    let failed = |err: &dyn std::fmt::Display| {
        error!(error = %err, "Error moving site (admin)");
        send_error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to move site")
    };

    // `parseInt` can outrun int4, and postgres.js sends the text as it is
    let Some(bound_site_id) = pg_int4(site_id) else {
        return failed(&format!("value \"{site_id}\" is out of range for type integer"));
    };

    let site: Result<Option<Option<String>>, sqlx::Error> =
        sqlx::query_scalar(r#"select "organization_id" from "sites" where "sites"."site_id" = $1 limit 1"#)
            .bind(bound_site_id)
            .fetch_optional(&state.pg)
            .await;
    let source_organization_id = match site {
        Err(err) => return failed(&err),
        Ok(None) => return send_error(StatusCode::NOT_FOUND, "Site not found"),
        Ok(Some(organization_id)) => organization_id,
    };

    if source_organization_id.as_deref() == Some(target_organization_id.as_str()) {
        return send_error(StatusCode::BAD_REQUEST, "Site is already in this organization");
    }

    let target: Result<Option<String>, sqlx::Error> =
        sqlx::query_scalar(r#"select "id" from "organization" where "organization"."id" = $1 limit 1"#)
            .bind(&target_organization_id)
            .fetch_optional(&state.pg)
            .await;
    match target {
        Err(err) => return failed(&err),
        Ok(None) => return send_error(StatusCode::NOT_FOUND, "Target organization not found"),
        Ok(Some(_)) => {}
    }

    match apply_site_move(&state.pg, bound_site_id, source_organization_id.as_deref(), &target_organization_id).await {
        Err(err) => failed(&err),
        Ok(affected_users) => {
            for user_id in &affected_users {
                state.sites_access.invalidate_user(user_id);
            }
            info!(
                site_id = bound_site_id,
                target = %target_organization_id,
                members = affected_users.len(),
                "Moved a site to another organization from the admin panel"
            );
            send_js(
                StatusCode::OK,
                &object(vec![
                    ("success", JsValue::Bool(true)),
                    ("organizationId", JsValue::String(target_organization_id)),
                ]),
            )
        }
    }
}
