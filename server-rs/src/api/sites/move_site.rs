//! `PUT /api/sites/:siteId/move`, ported from server/src/api/sites/moveSite.ts
//! and applySiteMove.ts on the `adminSitesWrite` chain.
//!
//! The order of the checks is load bearing: target-org membership is tested
//! before the target org is looked up, so a caller without access gets the same
//! 403 whether or not the organization exists. The cloud site-limit branch is not
//! ported (no billing here), which leaves the move itself unconditional once the
//! membership checks pass.

use axum::{
    body::Body,
    extract::State,
    http::{HeaderMap, Method, StatusCode, Uri},
    response::Response,
};
use serde_json::{Value, json};
use tracing::{error, info, warn};

use super::{
    lifecycle::now_iso,
    request::{self, Issues},
};
use crate::{
    analytics::{
        chain::{ChainSteps, SiteGuard, route_scope, site_scoped},
        js::number::parse_int_10,
        routes::people::common::path_params,
    },
    auth::access::get_org_membership,
    state::AppState,
};

/// `moveSiteSchema.safeParse(body)`: `{ organizationId: z.string().min(1) }`.
pub fn parse_move_body(body: Option<&Value>) -> Result<String, Value> {
    let mut issues = Issues::default();
    let Some(Value::Object(fields)) = body else {
        issues.form(request::invalid_type("object", body));
        return Err(issues.flatten());
    };
    match fields.get("organizationId") {
        Some(Value::String(organization_id)) => {
            if request::string_length(organization_id) < 1 {
                issues.field("organizationId", request::string_too_small(1));
                return Err(issues.flatten());
            }
            Ok(organization_id.clone())
        }
        other => {
            issues.field("organizationId", request::invalid_type("string", other));
            Err(issues.flatten())
        }
    }
}

/// `applySiteMove`: the transaction, then the sites-access cache invalidation for
/// every member of both organizations.
async fn apply_site_move(
    state: &AppState,
    site_id: i32,
    source_organization_id: Option<&str>,
    target_organization_id: &str,
) -> Result<(), sqlx::Error> {
    let mut tx = state.pg.begin().await?;
    // `$2::timestamp`: postgres-js sends the ISO string untyped and lets Postgres
    // parse it, sqlx sends typed binary
    sqlx::query("UPDATE sites SET organization_id = $1, updated_at = $2::timestamp WHERE site_id = $3")
        .bind(target_organization_id)
        .bind(now_iso())
        .bind(site_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM member_site_access WHERE site_id = $1").bind(site_id).execute(&mut *tx).await?;
    sqlx::query("DELETE FROM team_site_access WHERE site_id = $1").bind(site_id).execute(&mut *tx).await?;
    // Site-specific segments travel with the site; organization-wide ones (null
    // site_id) stay with their organization
    sqlx::query("UPDATE segments SET organization_id = $1 WHERE site_id = $2")
        .bind(target_organization_id)
        .bind(site_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;

    let organization_ids: Vec<String> = match source_organization_id {
        Some(source) => vec![source.to_string(), target_organization_id.to_string()],
        None => vec![target_organization_id.to_string()],
    };
    let affected: Vec<String> = sqlx::query_scalar(r#"SELECT "userId" FROM member WHERE "organizationId" = ANY($1)"#)
        .bind(&organization_ids)
        .fetch_all(&state.pg)
        .await?;
    for user_id in &affected {
        state.sites_access.invalidate_user(user_id);
    }
    info!(site_id, target = target_organization_id, members = affected.len(), "Site moved");
    Ok(())
}

pub async fn move_site(
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

    // `parseInt(siteId, 10)`
    let parsed = parse_int_10(&site.site_id);
    if parsed.is_nan() || parsed <= 0.0 {
        return request::error(StatusCode::BAD_REQUEST, "Invalid site ID: must be a positive integer");
    }
    let target_organization_id = match parse_move_body(body.as_ref()) {
        Ok(organization_id) => organization_id,
        Err(details) => {
            warn!("Site move payload failed validation");
            return request::send(
                StatusCode::BAD_REQUEST,
                &json!({ "error": "Invalid request data", "details": details }),
            );
        }
    };
    let Some(user_id) = site.auth.user_id.clone() else {
        // An organization-owned API key has no `request.user`
        return request::error(StatusCode::UNAUTHORIZED, "Unauthorized");
    };

    let Some(site_id) = request::pg_int(parsed) else {
        error!(site_id = %site.site_id, "Site id is not a Postgres integer; Node's query throws here");
        return request::error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to move site");
    };

    let result: Result<Response, sqlx::Error> = async {
        let source: Option<Option<String>> =
            sqlx::query_scalar("SELECT organization_id FROM sites WHERE site_id = $1 LIMIT 1")
                // i64 like the identical statement in auth and the analytics chain: sqlx
                // caches prepared statements per connection by SQL text, and an int4 bound
                // to the cached int8 one fails
                .bind(i64::from(site_id))
                .fetch_optional(&state.pg)
                .await?;
        let Some(source_organization_id) = source else {
            return Ok(request::error(StatusCode::NOT_FOUND, "Site not found"));
        };
        if source_organization_id.as_deref() == Some(target_organization_id.as_str()) {
            return Ok(request::error(StatusCode::BAD_REQUEST, "Site is already in this organization"));
        }

        // Membership first, so a nonexistent organization is indistinguishable
        // from one the caller cannot reach
        let membership = get_org_membership(&state.pg, Some(&user_id), Some(&target_organization_id)).await?;
        let Some(membership) = membership else {
            return Ok(request::error(StatusCode::FORBIDDEN, "You are not a member of the target organization"));
        };
        if !membership.is_admin() {
            return Ok(request::error(
                StatusCode::FORBIDDEN,
                "You must be an admin or owner of the target organization",
            ));
        }

        let target_exists: Option<String> = sqlx::query_scalar("SELECT id FROM organization WHERE id = $1 LIMIT 1")
            .bind(&target_organization_id)
            .fetch_optional(&state.pg)
            .await?;
        if target_exists.is_none() {
            return Ok(request::error(StatusCode::NOT_FOUND, "Target organization not found"));
        }

        apply_site_move(&state, site_id, source_organization_id.as_deref(), &target_organization_id).await?;
        Ok(request::send(
            StatusCode::OK,
            &json!({ "success": true, "organizationId": target_organization_id }),
        ))
    }
    .await;

    match result {
        Ok(response) => response,
        Err(err) => {
            error!(error = %err, site_id, "Error moving site");
            request::error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to move site")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn move_schema_matches_zod() {
        assert_eq!(parse_move_body(Some(&json!({ "organizationId": "org" }))).unwrap(), "org");
        assert_eq!(
            parse_move_body(Some(&json!({ "organizationId": "" }))).unwrap_err(),
            json!({ "formErrors": [], "fieldErrors": { "organizationId": ["String must contain at least 1 character(s)"] } })
        );
        assert_eq!(
            parse_move_body(Some(&json!({}))).unwrap_err(),
            json!({ "formErrors": [], "fieldErrors": { "organizationId": ["Required"] } })
        );
        assert_eq!(
            parse_move_body(Some(&json!({ "organizationId": 1 }))).unwrap_err(),
            json!({ "formErrors": [], "fieldErrors": { "organizationId": ["Expected string, received number"] } })
        );
        assert_eq!(parse_move_body(None).unwrap_err(), json!({ "formErrors": ["Required"], "fieldErrors": {} }));
    }
}
