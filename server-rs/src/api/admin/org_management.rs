//! The organization side of the admin panel, ported from
//! server/src/api/admin/adminOrganizationManagement.ts: the organization picker,
//! the plan list, the subscription override and the member read, update and
//! delete endpoints.
//!
//! Timestamps come back as Postgres prints them (`::text`), because drizzle maps
//! these columns with `mode: "string"` and hands Node exactly that text.

use axum::{
    body::Body,
    extract::{RawPathParams, State},
    http::{HeaderMap, Method, StatusCode, Uri},
    response::Response,
};
use sqlx::{PgPool, Row};
use tracing::{debug, error, info};

use crate::{
    analytics::js::{JsValue, number::number_to_string},
    auth::guards::Authenticated,
    state::AppState,
};

use super::{
    plans::{APPSUMO_TIER_LIMITS, STRIPE_PRICES, appsumo_override_tier, find_stripe_plan},
    support::{nullable_text, object, param, path_params, read_body, send_error, send_error_details, send_js},
    zod::{SubscriptionOverride, parse_organization_options_query, parse_subscription_override, parse_update_member},
};

use super::admin_chain;

fn failure(err: &sqlx::Error, log: &str, message: &str) -> Response {
    error!(error = %err, "{log}");
    send_error(StatusCode::INTERNAL_SERVER_ERROR, message)
}

// ---------------------------------------------------------------------------------
// GET /api/admin/organization-options
// ---------------------------------------------------------------------------------

/// `getAdminOrganizationOptions`
pub async fn organization_options(State(state): State<AppState>, headers: HeaderMap, uri: Uri) -> Response {
    let request = match admin_chain(&state, &headers, &uri).await {
        Ok(request) => request,
        Err(response) => return response,
    };

    let parsed = match parse_organization_options_query(&request.query) {
        Ok(parsed) => parsed,
        Err(issues) => {
            debug!("Admin organization options query failed validation");
            return send_error_details(StatusCode::BAD_REQUEST, "Invalid query", issues.flatten());
        }
    };

    // postgres.js sends the limit as `String(limit)`; zod already proved it is an
    // integer between 1 and 50, so the cast cannot fail
    let limit = number_to_string(parsed.limit).parse::<i64>().unwrap_or(25);
    let rows = if parsed.search.is_empty() {
        sqlx::query(
            r#"select "organization"."id", "organization"."name" from "organization"
               order by "organization"."createdAt" desc limit $1"#,
        )
        .bind(limit)
        .fetch_all(&state.pg)
        .await
    } else {
        let pattern = format!("%{}%", parsed.search);
        sqlx::query(
            r#"select distinct "organization"."id", "organization"."name", "organization"."createdAt"
               from "organization"
               left join "sites" on "sites"."organization_id" = "organization"."id"
               left join "member" on "member"."organizationId" = "organization"."id"
               left join "user" on "user"."id" = "member"."userId"
               where "organization"."name" ilike $1 or "organization"."id" ilike $1
                  or "sites"."domain" ilike $1 or "user"."email" ilike $1
               order by "organization"."createdAt" desc limit $2"#,
        )
        .bind(&pattern)
        .bind(limit)
        .fetch_all(&state.pg)
        .await
    };

    let rows = match rows {
        Ok(rows) => rows,
        Err(err) => return failure(&err, "Failed to search admin organization options", "Failed to search organizations"),
    };

    let items = rows
        .iter()
        .map(|row| {
            object(vec![
                ("id", JsValue::String(row.try_get::<String, _>("id").unwrap_or_default())),
                ("name", JsValue::String(row.try_get::<String, _>("name").unwrap_or_default())),
            ])
        })
        .collect();
    debug!(items = rows.len(), search = %parsed.search, "Listed admin organization options");
    send_js(StatusCode::OK, &object(vec![("items", JsValue::Array(items))]))
}

// ---------------------------------------------------------------------------------
// GET /api/admin/subscription-plans
// ---------------------------------------------------------------------------------

/// `getAdminSubscriptionPlans`: the Stripe price list followed by the AppSumo tiers.
pub async fn subscription_plans(State(state): State<AppState>, headers: HeaderMap, uri: Uri) -> Response {
    if let Err(response) = admin_chain(&state, &headers, &uri).await {
        return response;
    }
    let mut plans: Vec<JsValue> = STRIPE_PRICES
        .iter()
        .map(|plan| {
            object(vec![
                ("name", JsValue::String(plan.name.to_string())),
                ("type", JsValue::String("stripe".into())),
                ("eventLimit", JsValue::Number(plan.events as f64)),
                ("interval", JsValue::String(plan.interval.to_string())),
            ])
        })
        .collect();
    plans.extend(APPSUMO_TIER_LIMITS.iter().map(|(tier, limit)| {
        object(vec![
            ("name", JsValue::String(format!("appsumo-{tier}"))),
            ("type", JsValue::String("appsumo".into())),
            ("eventLimit", JsValue::Number(*limit as f64)),
            ("interval", JsValue::String("lifetime".into())),
        ])
    }));
    send_js(StatusCode::OK, &JsValue::Array(plans))
}

// ---------------------------------------------------------------------------------
// PUT /api/admin/organizations/:organizationId/subscription-override
// ---------------------------------------------------------------------------------

/// `updateAdminSubscriptionOverride`
pub async fn subscription_override(
    State(state): State<AppState>,
    raw_params: RawPathParams,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Body,
) -> Response {
    // Fastify parses the body before the preHandlers run
    let body = match read_body(&headers, body).await {
        Ok(body) => body,
        Err(response) => return response,
    };
    let params = match path_params(&raw_params, &method, &uri).await {
        Ok(params) => params,
        Err(response) => return response,
    };
    if let Err(response) = admin_chain(&state, &headers, &uri).await {
        return response;
    }

    let parsed = match parse_subscription_override(&body) {
        Ok(parsed) => parsed,
        Err(issues) => {
            debug!("Admin subscription override body failed validation");
            return send_error_details(StatusCode::BAD_REQUEST, "Invalid subscription override", issues.flatten());
        }
    };

    let organization_id = param(&params, "organizationId");
    let found: Result<Option<String>, sqlx::Error> =
        sqlx::query_scalar(r#"select "id" from "organization" where "organization"."id" = $1 limit 1"#)
            .bind(&organization_id)
            .fetch_optional(&state.pg)
            .await;
    let id = match found {
        // The lookup has no try/catch in Node, so a failure escapes to Fastify
        Err(err) => return super::support::uncaught_exception("subscription-override", None, &err.to_string()),
        Ok(None) => return send_error(StatusCode::NOT_FOUND, "Organization not found"),
        Ok(Some(id)) => id,
    };

    if let SubscriptionOverride::Preset { plan_override } = &parsed
        && find_stripe_plan(plan_override).is_none()
        && appsumo_override_tier(plan_override).is_none()
    {
        debug!(plan_override, "Rejected an unknown subscription override preset");
        return send_error(StatusCode::BAD_REQUEST, "Unknown subscription override");
    }

    // `update` is spread into the reply, so it is built once and used for both
    let (plan_override, custom_plan) = match &parsed {
        SubscriptionOverride::None => (JsValue::Null, JsValue::Null),
        SubscriptionOverride::Preset { plan_override } => (JsValue::String(plan_override.clone()), JsValue::Null),
        SubscriptionOverride::Custom { events, members, websites } => (
            JsValue::Null,
            object(vec![
                ("events", JsValue::Number(*events)),
                ("members", members.map_or(JsValue::Null, JsValue::Number)),
                ("websites", websites.map_or(JsValue::Null, JsValue::Number)),
            ]),
        ),
    };

    let custom_plan_text = match &custom_plan {
        JsValue::Null => None,
        value => crate::analytics::js::json::stringify(value),
    };
    let written = sqlx::query(
        r#"update "organization" set "planOverride" = $1, "custom_plan" = $2::jsonb where "organization"."id" = $3"#,
    )
    .bind(plan_override.as_str())
    .bind(custom_plan_text.as_deref())
    .bind(&id)
    .execute(&state.pg)
    .await;
    if let Err(err) = written {
        return failure(&err, "Failed to update subscription override", "Failed to update subscription override");
    }

    info!(organization_id = %id, "Updated an organization's subscription override");
    send_js(
        StatusCode::OK,
        &object(vec![
            ("success", JsValue::Bool(true)),
            ("planOverride", plan_override),
            ("customPlan", custom_plan),
        ]),
    )
}

// ---------------------------------------------------------------------------------
// The member endpoints
// ---------------------------------------------------------------------------------

/// What `findAdminMember` selects.
struct AdminMember {
    member_id: String,
    organization_id: String,
    user_id: String,
    member_role: String,
    has_restricted_site_access: bool,
    name: String,
    email: String,
    system_role: String,
    banned: Option<bool>,
    ban_reason: Option<String>,
    ban_expires: Option<String>,
}

/// `findAdminMember`
async fn find_admin_member(
    pg: &PgPool,
    organization_id: &str,
    member_id: &str,
) -> Result<Option<AdminMember>, sqlx::Error> {
    let row = sqlx::query(
        r#"select "member"."id" as "member_id", "member"."organizationId" as "organization_id",
                  "member"."userId" as "user_id", "member"."role" as "member_role",
                  "member"."has_restricted_site_access" as "has_restricted_site_access",
                  "user"."name" as "name", "user"."email" as "email", "user"."role" as "system_role",
                  "user"."banned" as "banned", "user"."banReason" as "ban_reason",
                  "user"."banExpires"::text as "ban_expires"
           from "member" inner join "user" on "user"."id" = "member"."userId"
           where "member"."id" = $1 and "member"."organizationId" = $2 limit 1"#,
    )
    .bind(member_id)
    .bind(organization_id)
    .fetch_optional(pg)
    .await?;
    row.map(|row| {
        Ok(AdminMember {
            member_id: row.try_get("member_id")?,
            organization_id: row.try_get("organization_id")?,
            user_id: row.try_get("user_id")?,
            member_role: row.try_get("member_role")?,
            has_restricted_site_access: row.try_get("has_restricted_site_access")?,
            name: row.try_get("name")?,
            email: row.try_get("email")?,
            system_role: row.try_get("system_role")?,
            banned: row.try_get("banned")?,
            ban_reason: row.try_get("ban_reason")?,
            ban_expires: row.try_get("ban_expires")?,
        })
    })
    .transpose()
}

/// `isLastOwner`
async fn is_last_owner(pg: &PgPool, organization_id: &str, member_id: &str) -> Result<bool, sqlx::Error> {
    let count: i64 = sqlx::query_scalar(
        r#"select count(*) from "member"
           where "member"."organizationId" = $1 and "member"."role" = 'owner' and "member"."id" <> $2"#,
    )
    .bind(organization_id)
    .bind(member_id)
    .fetch_one(pg)
    .await?;
    Ok(count == 0)
}

/// The member, organization and route parameters every member endpoint starts from.
async fn member_context(
    state: &AppState,
    headers: &HeaderMap,
    uri: &Uri,
    raw_params: &RawPathParams,
    method: &Method,
) -> Result<(Authenticated, String, String), Response> {
    let params = match path_params(raw_params, method, uri).await {
        Ok(params) => params,
        Err(response) => return Err(response),
    };
    let request = admin_chain(state, headers, uri).await?;
    Ok((request.auth, param(&params, "organizationId"), param(&params, "memberId")))
}

/// GET /api/admin/organizations/:organizationId/members/:memberId
pub async fn get_member(
    State(state): State<AppState>,
    raw_params: RawPathParams,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    let (_, organization_id, member_id) =
        match member_context(&state, &headers, &uri, &raw_params, &method).await {
            Ok(context) => context,
            Err(response) => return response,
        };

    let found = match find_admin_member(&state.pg, &organization_id, &member_id).await {
        Ok(Some(found)) => found,
        Ok(None) => return send_error(StatusCode::NOT_FOUND, "Member not found"),
        Err(err) => return failure(&err, "Failed to load admin organization member", "Failed to load member"),
    };

    let access = sqlx::query_scalar::<_, i32>(
        r#"select "site_id" from "member_site_access" where "member_site_access"."member_id" = $1"#,
    )
    .bind(&found.member_id)
    .fetch_all(&state.pg)
    .await;
    let sites = sqlx::query(
        r#"select "site_id", "name", "domain" from "sites"
           where "sites"."organization_id" = $1 order by "sites"."name""#,
    )
    .bind(&found.organization_id)
    .fetch_all(&state.pg)
    .await;
    let (access, sites) = match (access, sites) {
        (Ok(access), Ok(sites)) => (access, sites),
        (Err(err), _) | (_, Err(err)) => {
            return failure(&err, "Failed to load admin organization member", "Failed to load member");
        }
    };

    let site_ids = access.into_iter().map(|id| JsValue::Number(f64::from(id))).collect();
    let organization_sites = sites
        .iter()
        .map(|row| {
            object(vec![
                ("siteId", JsValue::Number(f64::from(row.try_get::<i32, _>("site_id").unwrap_or_default()))),
                ("name", JsValue::String(row.try_get::<String, _>("name").unwrap_or_default())),
                ("domain", JsValue::String(row.try_get::<String, _>("domain").unwrap_or_default())),
            ])
        })
        .collect();

    send_js(
        StatusCode::OK,
        &object(vec![
            (
                "user",
                object(vec![
                    ("id", JsValue::String(found.user_id)),
                    ("name", JsValue::String(found.name)),
                    ("email", JsValue::String(found.email)),
                    ("role", JsValue::String(found.system_role)),
                    ("banned", JsValue::Bool(found.banned.unwrap_or(false))),
                    ("banReason", nullable_text(found.ban_reason)),
                    ("banExpires", nullable_text(found.ban_expires)),
                ]),
            ),
            (
                "membership",
                object(vec![
                    ("id", JsValue::String(found.member_id)),
                    ("role", JsValue::String(found.member_role)),
                    ("hasRestrictedSiteAccess", JsValue::Bool(found.has_restricted_site_access)),
                    ("siteIds", JsValue::Array(site_ids)),
                ]),
            ),
            ("sites", JsValue::Array(organization_sites)),
        ]),
    )
}

/// PATCH /api/admin/organizations/:organizationId/members/:memberId
pub async fn update_member(
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
    let (auth, organization_id, member_id) =
        match member_context(&state, &headers, &uri, &raw_params, &method).await {
            Ok(context) => context,
            Err(response) => return response,
        };

    let value = match parse_update_member(&body) {
        Ok(value) => value,
        Err(issues) => {
            debug!("Admin member update body failed validation");
            return send_error_details(StatusCode::BAD_REQUEST, "Invalid member settings", issues.flatten());
        }
    };

    let found = match find_admin_member(&state.pg, &organization_id, &member_id).await {
        Ok(Some(found)) => found,
        Ok(None) => return send_error(StatusCode::NOT_FOUND, "Member not found"),
        Err(err) => return failure(&err, "Failed to update admin organization member", "Failed to update member"),
    };

    if found.member_role == "owner" && value.role != "owner" {
        match is_last_owner(&state.pg, &found.organization_id, &found.member_id).await {
            Ok(true) => {
                return send_error(StatusCode::BAD_REQUEST, "An organization must have at least one owner");
            }
            Ok(false) => {}
            Err(err) => {
                return failure(&err, "Failed to update admin organization member", "Failed to update member");
            }
        }
    }

    let restricted = value.role == "member" && value.has_restricted_site_access;
    // `[...new Set(value.siteIds)]` keeps the first occurrence of each id
    let mut requested: Vec<f64> = Vec::new();
    if restricted {
        for site_id in &value.site_ids {
            if !requested.contains(site_id) {
                requested.push(*site_id);
            }
        }
    }

    // `siteIdsInOrganization` answers with the ids that really belong to the org.
    // An id past int4 makes the statement fail in Node, which the catch answers.
    let mut bound: Vec<i32> = Vec::with_capacity(requested.len());
    for site_id in &requested {
        match super::support::pg_int4(*site_id) {
            Some(id) => bound.push(id),
            None => {
                error!(site_id, "Selected site id is out of range for the sites table");
                return send_error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to update member");
            }
        }
    }
    let valid: Vec<i32> = if bound.is_empty() {
        Vec::new()
    } else {
        match sqlx::query_scalar::<_, i32>(
            r#"select "site_id" from "sites"
               where "sites"."organization_id" = $1 and "sites"."site_id" = any($2)"#,
        )
        .bind(&found.organization_id)
        .bind(&bound)
        .fetch_all(&state.pg)
        .await
        {
            Ok(rows) => rows,
            Err(err) => {
                return failure(&err, "Failed to update admin organization member", "Failed to update member");
            }
        }
    };
    if bound.iter().any(|site_id| !valid.contains(site_id)) {
        debug!("Rejected site grants outside the member's organization");
        return send_error(StatusCode::BAD_REQUEST, "All selected sites must belong to this organization");
    }

    let created_by = auth.user_id.clone();
    let written = async {
        let mut tx = state.pg.begin().await?;
        sqlx::query(
            r#"update "member" set "role" = $1, "has_restricted_site_access" = $2 where "member"."id" = $3"#,
        )
        .bind(&value.role)
        .bind(restricted)
        .bind(&found.member_id)
        .execute(&mut *tx)
        .await?;
        sqlx::query(r#"delete from "member_site_access" where "member_site_access"."member_id" = $1"#)
            .bind(&found.member_id)
            .execute(&mut *tx)
            .await?;
        if restricted {
            for site_id in &bound {
                sqlx::query(
                    r#"insert into "member_site_access" ("member_id", "site_id", "created_by") values ($1, $2, $3)"#,
                )
                .bind(&found.member_id)
                .bind(site_id)
                .bind(created_by.as_deref())
                .execute(&mut *tx)
                .await?;
            }
        }
        tx.commit().await
    }
    .await;
    if let Err(err) = written {
        return failure(&err, "Failed to update admin organization member", "Failed to update member");
    }

    state.sites_access.invalidate_user(&found.user_id);
    info!(member_id = %found.member_id, role = %value.role, restricted, "Updated an organization member from the admin panel");
    send_js(StatusCode::OK, &object(vec![("success", JsValue::Bool(true))]))
}

/// DELETE /api/admin/organizations/:organizationId/members/:memberId
pub async fn delete_member(
    State(state): State<AppState>,
    raw_params: RawPathParams,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    let (_, organization_id, member_id) =
        match member_context(&state, &headers, &uri, &raw_params, &method).await {
            Ok(context) => context,
            Err(response) => return response,
        };

    let found = match find_admin_member(&state.pg, &organization_id, &member_id).await {
        Ok(Some(found)) => found,
        Ok(None) => return send_error(StatusCode::NOT_FOUND, "Member not found"),
        Err(err) => return failure(&err, "Failed to remove admin organization member", "Failed to remove member"),
    };

    if found.member_role == "owner" {
        match is_last_owner(&state.pg, &found.organization_id, &found.member_id).await {
            Ok(true) => {
                return send_error(StatusCode::BAD_REQUEST, "An organization must have at least one owner");
            }
            Ok(false) => {}
            Err(err) => {
                return failure(&err, "Failed to remove admin organization member", "Failed to remove member");
            }
        }
    }

    if let Err(err) = sqlx::query(r#"delete from "member" where "member"."id" = $1"#)
        .bind(&found.member_id)
        .execute(&state.pg)
        .await
    {
        return failure(&err, "Failed to remove admin organization member", "Failed to remove member");
    }

    state.sites_access.invalidate_user(&found.user_id);
    info!(member_id = %found.member_id, "Removed an organization member from the admin panel");
    send_js(StatusCode::OK, &object(vec![("success", JsValue::Bool(true))]))
}
