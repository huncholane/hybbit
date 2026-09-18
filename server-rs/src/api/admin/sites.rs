//! GET /api/admin/sites, ported from server/src/api/admin/getAdminSites.ts.
//!
//! The handler has no try/catch, so the ClickHouse lookup of the per-Site event
//! counts - against a table only cloud deployments create - escapes to Fastify's
//! default error handler. That is the answer this endpoint gives here, and the
//! port reproduces it, error code and message included, rather than inventing a
//! healthier one that would differ from Node during the cutover.

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
    subscriptions::{MonthBounds, OrganizationPlan, organization_subscription},
    support::{clickhouse_exception, object, send_error, send_js},
};

/// The site columns the response is built from.
struct SiteRow {
    site_id: i32,
    name: String,
    site_type: Option<String>,
    domain: String,
    organization_id: Option<String>,
    created_at: Option<String>,
    public: Option<bool>,
    session_replay: Option<bool>,
}

impl SiteRow {
    fn from_row(row: &PgRow) -> Result<Self, sqlx::Error> {
        Ok(Self {
            site_id: row.try_get("site_id")?,
            name: row.try_get("name")?,
            site_type: row.try_get("type")?,
            domain: row.try_get("domain")?,
            organization_id: row.try_get("organization_id")?,
            created_at: row.try_get("created_at")?,
            public: row.try_get("public")?,
            session_replay: row.try_get("sessionReplay")?,
        })
    }
}

/// `count()` per site id, as drizzle's `mapWith(Number)` hands it to Node.
fn counts_for(rows: &[PgRow], column: &str) -> Vec<(i32, f64)> {
    rows.iter()
        .filter_map(|row| {
            let site_id: Option<i32> = row.try_get(column).ok()?;
            let count: i64 = row.try_get("count").ok()?;
            site_id.map(|site_id| (site_id, count as f64))
        })
        .collect()
}

fn lookup(counts: &[(i32, f64)], site_id: i32) -> f64 {
    counts.iter().rev().find(|(id, _)| *id == site_id).map_or(0.0, |(_, count)| *count)
}

/// `getAdminSites`
pub async fn list(State(state): State<AppState>, headers: HeaderMap, uri: Uri) -> Response {
    if let Err(response) = super::admin_chain(&state, &headers, &uri).await {
        return response;
    }

    let sites = sqlx::query(
        r#"select "site_id", "name", "type", "domain", "organization_id", "created_at"::text as "created_at",
                  "public", "sessionReplay"
           from "sites" order by "sites"."created_at" desc"#,
    )
    .fetch_all(&state.pg)
    .await;
    let sites = match sites {
        Ok(rows) => rows,
        Err(err) => return super::support::uncaught_exception("admin/sites", None, &err.to_string()),
    };

    // Organization owners, last row winning as repeated `map.set` calls do
    let owners = sqlx::query(
        r#"select "member"."organizationId" as "organization_id", "user"."email" as "email"
           from "member" inner join "user" on "member"."userId" = "user"."id"
           where "member"."role" = 'owner'"#,
    )
    .fetch_all(&state.pg)
    .await;
    let owners = match owners {
        Ok(rows) => rows,
        Err(err) => return super::support::uncaught_exception("admin/sites", None, &err.to_string()),
    };
    let owner_emails: Vec<(String, String)> = owners
        .iter()
        .filter_map(|row| Some((row.try_get("organization_id").ok()?, row.try_get("email").ok()?)))
        .collect();

    let organizations = sqlx::query(
        r#"select "id", "planOverride", "custom_plan"::text as "custom_plan" from "organization""#,
    )
    .fetch_all(&state.pg)
    .await;
    let organizations = match organizations {
        Ok(rows) => rows,
        Err(err) => return super::support::uncaught_exception("admin/sites", None, &err.to_string()),
    };
    let month_bounds = MonthBounds::now();
    let subscriptions: Vec<(String, JsValue)> = organizations
        .iter()
        .filter_map(|row| {
            let id: String = row.try_get("id").ok()?;
            let plan = OrganizationPlan {
                plan_override: row.try_get("planOverride").ok().flatten(),
                custom_plan: row
                    .try_get::<Option<String>, _>("custom_plan")
                    .ok()
                    .flatten()
                    .and_then(|text| crate::analytics::js::json::parse(&text).ok())
                    .unwrap_or(JsValue::Null),
            };
            // `getOrganizationSubscriptions(organizationsData, false)`
            Some((id, organization_subscription(&plan, false, &month_bounds)))
        })
        .collect();

    // No catch block wraps these: a failure is Fastify's to answer
    let bounds = Bounds::now();
    let (events_24h, events_30d) = match event_counts::for_admin_sites(&state, &bounds).await {
        Ok(counts) => counts,
        Err(err) => return clickhouse_exception("admin/sites", &err),
    };

    let goal_counts =
        sqlx::query(r#"select "site_id", count(*) as "count" from "goals" group by "goals"."site_id""#)
            .fetch_all(&state.pg)
            .await;
    let funnel_counts =
        sqlx::query(r#"select "site_id", count(*) as "count" from "funnels" group by "funnels"."site_id""#)
            .fetch_all(&state.pg)
            .await;
    let (goal_counts, funnel_counts) = match (goal_counts, funnel_counts) {
        (Ok(goals), Ok(funnels)) => (counts_for(&goals, "site_id"), counts_for(&funnels, "site_id")),
        (Err(err), _) | (_, Err(err)) => {
            error!(error = %err, "Failed to count goals or funnels for the admin site list");
            return send_error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to load admin sites");
        }
    };

    let mut enriched = Vec::with_capacity(sites.len());
    for row in &sites {
        let site = match SiteRow::from_row(row) {
            Ok(site) => site,
            Err(err) => return super::support::uncaught_exception("admin/sites", None, &err.to_string()),
        };
        let organization_id = site.organization_id.clone().filter(|id| !id.is_empty());
        let subscription = organization_id
            .as_ref()
            .and_then(|id| subscriptions.iter().rev().find(|(key, _)| key == id).map(|(_, value)| value.clone()));
        // A Site with no organization gets the literal `{ planName: "free", status: "free" }`
        let plan_name = subscription
            .as_ref()
            .and_then(|value| value.as_object().map(|object| object.get_or_undefined("planName").clone()))
            .filter(JsValue::is_truthy)
            .unwrap_or(JsValue::String("free".into()));
        let status = subscription
            .as_ref()
            .and_then(|value| value.as_object().map(|object| object.get_or_undefined("status").clone()))
            .filter(JsValue::is_truthy)
            .unwrap_or(JsValue::String("free".into()));

        // `orgOwnerMap.get(id)` is undefined for an organization with no owner, and
        // `JSON.stringify` then drops the member entirely
        let owner_email = match &organization_id {
            None => JsValue::Null,
            Some(id) => owner_emails
                .iter()
                .rev()
                .find(|(key, _)| key == id)
                .map_or(JsValue::Undefined, |(_, email)| JsValue::String(email.clone())),
        };

        enriched.push(object(vec![
            ("siteId", JsValue::Number(f64::from(site.site_id))),
            ("name", JsValue::String(site.name)),
            (
                "type",
                match site.site_type.filter(|value| !value.is_empty()) {
                    Some(value) => JsValue::String(value),
                    None => JsValue::String("web".into()),
                },
            ),
            ("domain", JsValue::String(site.domain)),
            ("organizationId", site.organization_id.map_or(JsValue::Null, JsValue::String)),
            ("createdAt", site.created_at.map_or(JsValue::Null, JsValue::String)),
            ("public", site.public.map_or(JsValue::Null, JsValue::Bool)),
            ("eventsLast24Hours", events_24h.get_or_zero(f64::from(site.site_id))),
            ("eventsLast30Days", events_30d.get_or_zero(f64::from(site.site_id))),
            ("goalsCount", JsValue::Number(lookup(&goal_counts, site.site_id))),
            ("funnelsCount", JsValue::Number(lookup(&funnel_counts, site.site_id))),
            ("sessionReplay", JsValue::Bool(site.session_replay.unwrap_or(false))),
            ("organizationOwnerEmail", owner_email),
            ("subscription", object(vec![("planName", plan_name), ("status", status)])),
        ]));
    }

    debug!(sites = enriched.len(), "Listed sites for the admin panel");
    send_js(StatusCode::OK, &JsValue::Array(enriched))
}
