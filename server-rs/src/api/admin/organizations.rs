//! GET /api/admin/organizations, ported from
//! server/src/api/admin/getAdminOrganizations.ts.
//!
//! Unlike the site list this handler wraps everything in a try/catch and the
//! ClickHouse lookup in a second one, so a missing `hourly_events_by_site_mv_target`
//! only costs the event counts. Members and sites keep the order their queries
//! returned them in, because Node groups them into maps as it iterates.

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode, Uri},
    response::Response,
};
use sqlx::{Row, postgres::PgRow};
use tracing::{debug, error};

use crate::{analytics::js::JsValue, state::AppState};

use super::{
    event_counts::{self, Bounds},
    subscriptions::{MonthBounds, OrganizationPlan, organization_subscription, stripe_dashboard_url},
    support::{object, send_error_details, send_js},
};

/// `getAdminOrganizations`
pub async fn list(State(state): State<AppState>, headers: HeaderMap, uri: Uri) -> Response {
    if let Err(response) = super::admin_chain(&state, &headers, &uri).await {
        return response;
    }
    match build(&state).await {
        Ok(response) => response,
        Err(err) => {
            error!(error = %err, "Get Admin Organizations Error");
            // `details: error instanceof Error ? error.message : "Unknown error"`
            send_error_details(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to fetch organizations data",
                serde_json::Value::String(err.to_string()),
            )
        }
    }
}

/// The handler's `try` block. Any Postgres failure inside it lands in the catch.
async fn build(state: &AppState) -> Result<Response, sqlx::Error> {
    let organizations = sqlx::query(
        r#"select "id", "name", "createdAt"::text as "createdAt", "monthlyEventCount", "overMonthlyLimit",
                  "planOverride", "custom_plan"::text as "custom_plan", "stripeCustomerId"
           from "organization" order by "organization"."createdAt" desc"#,
    )
    .fetch_all(&state.pg)
    .await?;

    let members = sqlx::query(
        r#"select "member"."id" as "member_id", "member"."organizationId" as "organization_id",
                  "member"."userId" as "user_id", "member"."role" as "role",
                  "member"."createdAt"::text as "created_at",
                  "user"."name" as "user_name", "user"."email" as "user_email"
           from "member" inner join "user" on "member"."userId" = "user"."id""#,
    )
    .fetch_all(&state.pg)
    .await?;

    let organization_ids: Vec<String> =
        organizations.iter().filter_map(|row| row.try_get::<String, _>("id").ok()).collect();
    // `allOrgIds.length > 0 ? inArray(...) : undefined`: no organizations means no
    // predicate at all, so every Site is read
    let sites = if organization_ids.is_empty() {
        sqlx::query(
            r#"select "site_id", "name", "domain", "type", "created_at"::text as "created_at", "organization_id"
               from "sites""#,
        )
        .fetch_all(&state.pg)
        .await?
    } else {
        sqlx::query(
            r#"select "site_id", "name", "domain", "type", "created_at"::text as "created_at", "organization_id"
               from "sites" where "sites"."organization_id" = any($1)"#,
        )
        .bind(&organization_ids)
        .fetch_all(&state.pg)
        .await?
    };

    let bounds = Bounds::now();
    let (events_24h, events_30d) = event_counts::for_admin_organizations(state, &bounds).await;
    let month_bounds = MonthBounds::now();

    let site_entry = |row: &PgRow| -> JsValue {
        let site_id = row.try_get::<i32, _>("site_id").unwrap_or_default();
        object(vec![
            ("siteId", JsValue::Number(f64::from(site_id))),
            ("name", JsValue::String(row.try_get::<String, _>("name").unwrap_or_default())),
            ("domain", JsValue::String(row.try_get::<String, _>("domain").unwrap_or_default())),
            ("type", row.try_get::<Option<String>, _>("type").ok().flatten().map_or(JsValue::Null, JsValue::String)),
            (
                "createdAt",
                row.try_get::<Option<String>, _>("created_at").ok().flatten().map_or(JsValue::Null, JsValue::String),
            ),
            ("eventsLast24Hours", events_24h.get_or_zero(f64::from(site_id))),
            ("eventsLast30Days", events_30d.get_or_zero(f64::from(site_id))),
        ])
    };

    let member_entry = |row: &PgRow| -> JsValue {
        object(vec![
            ("memberId", JsValue::String(row.try_get::<String, _>("member_id").unwrap_or_default())),
            ("userId", JsValue::String(row.try_get::<String, _>("user_id").unwrap_or_default())),
            ("name", JsValue::String(row.try_get::<String, _>("user_name").unwrap_or_default())),
            ("email", JsValue::String(row.try_get::<String, _>("user_email").unwrap_or_default())),
            ("role", JsValue::String(row.try_get::<String, _>("role").unwrap_or_default())),
            (
                "createdAt",
                row.try_get::<Option<String>, _>("created_at").ok().flatten().map_or(JsValue::Null, JsValue::String),
            ),
        ])
    };

    let mut enriched = Vec::with_capacity(organizations.len());
    for row in &organizations {
        let id: String = row.try_get("id")?;
        let custom_plan = row
            .try_get::<Option<String>, _>("custom_plan")?
            .and_then(|text| crate::analytics::js::json::parse(&text).ok())
            .unwrap_or(JsValue::Null);
        let plan = OrganizationPlan { plan_override: row.try_get("planOverride")?, custom_plan: custom_plan.clone() };
        let stripe_customer_id: Option<String> = row.try_get("stripeCustomerId")?;
        // `org.monthlyEventCount || 0` and `org.overMonthlyLimit || false`
        let monthly_event_count = row.try_get::<Option<i32>, _>("monthlyEventCount")?.unwrap_or(0);
        let over_monthly_limit = row.try_get::<Option<bool>, _>("overMonthlyLimit")?.unwrap_or(false);

        let org_sites: Vec<JsValue> = sites
            .iter()
            .filter(|site| {
                site.try_get::<Option<String>, _>("organization_id").ok().flatten().as_deref() == Some(id.as_str())
            })
            .map(site_entry)
            .collect();
        let org_members: Vec<JsValue> = members
            .iter()
            .filter(|member| member.try_get::<String, _>("organization_id").ok().as_deref() == Some(id.as_str()))
            .map(member_entry)
            .collect();

        enriched.push(object(vec![
            ("id", JsValue::String(id.clone())),
            ("name", JsValue::String(row.try_get("name")?)),
            (
                "createdAt",
                row.try_get::<Option<String>, _>("createdAt")?.map_or(JsValue::Null, JsValue::String),
            ),
            ("monthlyEventCount", JsValue::Number(f64::from(monthly_event_count))),
            ("overMonthlyLimit", JsValue::Bool(over_monthly_limit)),
            ("subscription", organization_subscription(&plan, true, &month_bounds)),
            ("planOverride", plan.plan_override.clone().map_or(JsValue::Null, JsValue::String)),
            ("customPlan", custom_plan),
            ("stripeCustomerId", stripe_customer_id.clone().map_or(JsValue::Null, JsValue::String)),
            // `org.stripeCustomerId ? ... : null` is a truthiness test, so a stored
            // empty string prints as the id and still has no dashboard link
            ("stripeDashboardUrl", stripe_dashboard_url(stripe_customer_id.as_deref().filter(|id| !id.is_empty()))),
            ("sites", JsValue::Array(org_sites)),
            ("members", JsValue::Array(org_members)),
        ]));
    }

    debug!(organizations = enriched.len(), "Listed organizations for the admin panel");
    Ok(send_js(StatusCode::OK, &JsValue::Array(enriched)))
}
