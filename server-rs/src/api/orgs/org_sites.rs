//! An organization's sites, ported from server/src/api/sites/getSitesFromOrg.ts and
//! server/src/api/sites/addSite.ts (through
//! server/src/services/sites/siteConfigurationLifecycle.ts's `create`).
//!
//! No billing here, so the subscription block is the self-hosted one Node builds
//! without `CLOUD`: no plan lookup, an unlimited event allowance (`Infinity`, which
//! `JSON.stringify` writes as `null`) and the "free" plan name.

use std::sync::LazyLock;

use axum::{
    body::Body,
    extract::State,
    http::{HeaderMap, Method, StatusCode, Uri},
    response::Response,
};
use regex::Regex;
use serde_json::{Map, Value};
use sqlx::{Row, postgres::PgRow};
use tracing::{debug, error, info};

use super::{
    access,
    js::{self},
    request::{self, boolean, integer, object, text},
};
use crate::{
    analytics::{
        chain::{org_scoped, route_scope},
        js::{JsObject, JsValue, json as js_json},
        utils::{
            analytics_query::{AnalyticsClickHouse, QueryParam, QuerySpec},
            utils::process_results,
        },
    },
    auth::access::{get_org_membership, member_can_access_site, resolve_member_site_grants},
    state::AppState,
};

static CLICKHOUSE: LazyLock<std::sync::OnceLock<AnalyticsClickHouse>> =
    LazyLock::new(std::sync::OnceLock::new);

fn clickhouse(state: &AppState) -> &'static AnalyticsClickHouse {
    CLICKHOUSE.get_or_init(|| AnalyticsClickHouse::new(&state.config.clickhouse).expect("ClickHouse client"))
}

/// `buildSiteSessionCountsQuery(false)`; `LITE_DASHBOARD` is unset in production.
const SESSION_COUNTS_QUERY: &str = "
    SELECT
      site_id,
      uniqExact(session_id) AS total_sessions
    FROM events
    WHERE timestamp >= now() - INTERVAL 1 DAY
      AND site_id IN {siteIds:Array(UInt16)}
    GROUP BY site_id
  ";

/// Every `sites` column in the order `db.select().from(sites)` projects them, which
/// is the order they appear in the response object.
const SITE_COLUMNS: &str = r#""id", "site_id", "name", "type", "domain", "created_at"::text as "created_at",
    "updated_at"::text as "updated_at", "created_by", "organization_id", "public", "embed_enabled", "saltUserIds",
    "blockBots", "first_party_proxy", "excluded_ips"::text as "excluded_ips", "use_organization_excluded_ips",
    "excluded_countries"::text as "excluded_countries", "excluded_paths"::text as "excluded_paths",
    "excluded_hostnames"::text as "excluded_hostnames", "excluded_user_agents"::text as "excluded_user_agents",
    "excluded_asns"::text as "excluded_asns", "excluded_query_params"::text as "excluded_query_params",
    "sessionReplay", "webVitals", "trackErrors", "trackOutbound", "trackUrlParams", "trackInitialPageView",
    "trackSpaNavigation", "trackIp", "trackButtonClicks", "trackCopy", "trackFormInteractions", "track_heartbeat",
    "heartbeat_interval", "bounce_threshold", "api_key", "private_link_key", "tags"::text as "tags",
    "detected_platform""#;

/// `JSON.parse` of a jsonb column's text, or `null` when the column is null.
fn jsonb(value: Option<String>) -> JsValue {
    match value {
        None => JsValue::Null,
        Some(text) => js_json::parse(&text).unwrap_or(JsValue::String(text)),
    }
}

/// One `sites` row as the response spells it, minus the two secrets
/// (`apiKey`, `privateLinkKey`) the destructuring in `getSitesFromOrg` removes.
fn site_fields(row: &PgRow, with_secrets: bool) -> Result<Vec<(&'static str, JsValue)>, sqlx::Error> {
    let mut fields: Vec<(&'static str, JsValue)> = vec![
        ("id", text(row.try_get("id")?)),
        ("siteId", JsValue::Number(f64::from(row.try_get::<i32, _>("site_id")?))),
        ("name", JsValue::String(row.try_get("name")?)),
        ("type", text(row.try_get("type")?)),
        ("domain", JsValue::String(row.try_get("domain")?)),
        ("createdAt", text(row.try_get("created_at")?)),
        ("updatedAt", text(row.try_get("updated_at")?)),
        ("createdBy", text(row.try_get("created_by")?)),
        ("organizationId", text(row.try_get("organization_id")?)),
        ("public", boolean(row.try_get("public")?)),
        ("embedEnabled", boolean(row.try_get("embed_enabled")?)),
        ("saltUserIds", boolean(row.try_get("saltUserIds")?)),
        ("blockBots", JsValue::Bool(row.try_get("blockBots")?)),
        ("firstPartyProxy", boolean(row.try_get("first_party_proxy")?)),
        ("excludedIPs", jsonb(row.try_get("excluded_ips")?)),
        ("useOrganizationExcludedIPs", boolean(row.try_get("use_organization_excluded_ips")?)),
        ("excludedCountries", jsonb(row.try_get("excluded_countries")?)),
        ("excludedPaths", jsonb(row.try_get("excluded_paths")?)),
        ("excludedHostnames", jsonb(row.try_get("excluded_hostnames")?)),
        ("excludedUserAgents", jsonb(row.try_get("excluded_user_agents")?)),
        ("excludedASNs", jsonb(row.try_get("excluded_asns")?)),
        ("excludedQueryParams", jsonb(row.try_get("excluded_query_params")?)),
        ("sessionReplay", boolean(row.try_get("sessionReplay")?)),
        ("webVitals", boolean(row.try_get("webVitals")?)),
        ("trackErrors", boolean(row.try_get("trackErrors")?)),
        ("trackOutbound", boolean(row.try_get("trackOutbound")?)),
        ("trackUrlParams", boolean(row.try_get("trackUrlParams")?)),
        ("trackInitialPageView", boolean(row.try_get("trackInitialPageView")?)),
        ("trackSpaNavigation", boolean(row.try_get("trackSpaNavigation")?)),
        ("trackIp", boolean(row.try_get("trackIp")?)),
        ("trackButtonClicks", boolean(row.try_get("trackButtonClicks")?)),
        ("trackCopy", boolean(row.try_get("trackCopy")?)),
        ("trackFormInteractions", boolean(row.try_get("trackFormInteractions")?)),
        ("trackHeartbeat", boolean(row.try_get("track_heartbeat")?)),
        ("heartbeatInterval", integer(row.try_get("heartbeat_interval")?)),
        ("bounceThreshold", integer(row.try_get("bounce_threshold")?)),
    ];
    if with_secrets {
        fields.push(("apiKey", text(row.try_get("api_key")?)));
        fields.push(("privateLinkKey", text(row.try_get("private_link_key")?)));
    }
    fields.push(("tags", jsonb(row.try_get("tags")?)));
    fields.push(("detectedPlatform", text(row.try_get("detected_platform")?)));
    Ok(fields)
}

/// Every `organization` column, in the order `db.select().from(organization)`
/// projects them.
fn organization_value(row: &PgRow) -> Result<JsValue, sqlx::Error> {
    Ok(object(vec![
        ("id", JsValue::String(row.try_get("id")?)),
        ("name", JsValue::String(row.try_get("name")?)),
        ("slug", JsValue::String(row.try_get("slug")?)),
        ("logo", text(row.try_get("logo")?)),
        ("createdAt", text(row.try_get("createdAt")?)),
        ("metadata", text(row.try_get("metadata")?)),
        ("stripeCustomerId", text(row.try_get("stripeCustomerId")?)),
        ("monthlyEventCount", integer(row.try_get("monthlyEventCount")?)),
        ("overMonthlyLimit", boolean(row.try_get("overMonthlyLimit")?)),
        ("approachingLimitNotifiedPeriodStart", text(row.try_get("approachingLimitNotifiedPeriodStart")?)),
        ("planOverride", text(row.try_get("planOverride")?)),
        ("customPlan", jsonb(row.try_get("custom_plan")?)),
        ("excludedIPs", jsonb(row.try_get("excluded_ips")?)),
    ]))
}

/// GET /api/organizations/:organizationId/sites (`getSitesFromOrg`), chain `orgOrgRead`.
pub async fn list(State(state): State<AppState>, method: Method, uri: Uri, headers: HeaderMap) -> Response {
    let params = match request::route_params(&uri, &[3]) {
        Ok(params) => params,
        Err(failure) => return request::param_failure(failure, method, uri).await,
    };
    let organization_id = params[0].clone();
    let scoped = match org_scoped(&state, &headers, &uri, &organization_id, false, route_scope("org", "read")).await {
        Ok(scoped) => scoped,
        Err(response) => return response,
    };

    let user_id = match scoped.auth.user_id.clone() {
        Some(user_id) => Some(user_id),
        None => {
            let context = super::chain::context(&state, &headers, &scoped.query);
            match access::user_id_from_request(&state, &headers, &scoped.query, &context).await {
                Ok(user_id) => user_id,
                Err(response) => return response,
            }
        }
    };

    match build_listing(&state, &organization_id, user_id.as_deref()).await {
        Ok(value) => request::send(StatusCode::OK, &value),
        Err(message) => {
            error!(error = %message, "Error in getSitesFromOrg");
            request::send(StatusCode::INTERNAL_SERVER_ERROR, &object(vec![("error", message.into())]))
        }
    }
}

async fn build_listing(state: &AppState, organization_id: &str, user_id: Option<&str>) -> Result<JsValue, String> {
    let pg = &state.pg;
    let db = |err: sqlx::Error| format!("PostgresError: {err}");

    let membership = get_org_membership(pg, user_id, Some(organization_id)).await.map_err(db)?;
    let rows = sqlx::query(&format!(r#"select {SITE_COLUMNS} from "sites" where "organization_id" = $1"#))
        .bind(organization_id)
        .fetch_all(pg)
        .await
        .map_err(db)?;
    let org_row = sqlx::query(
        r#"select "id", "name", "slug", "logo", "createdAt"::text as "createdAt", "metadata", "stripeCustomerId",
                  "monthlyEventCount", "overMonthlyLimit", "approachingLimitNotifiedPeriodStart", "planOverride",
                  "custom_plan"::text as "custom_plan", "excluded_ips"::text as "excluded_ips"
           from "organization" where "id" = $1 limit 1"#,
    )
    .bind(organization_id)
    .fetch_optional(pg)
    .await
    .map_err(db)?;

    // Only a member-role caller is filtered; admins and owners see every site
    let mut sites: Vec<&PgRow> = rows.iter().collect();
    if let (Some(membership), Some(user_id)) = (&membership, user_id)
        && membership.role == "member"
    {
        let granted = if membership.has_restricted_site_access { vec![membership.id.clone()] } else { Vec::new() };
        let grants =
            resolve_member_site_grants(pg, user_id, &[organization_id.to_string()], &granted).await.map_err(db)?;
        let mut kept = Vec::new();
        for row in sites {
            let site_id: i32 = row.try_get("site_id").map_err(db)?;
            if member_can_access_site(&grants, site_id, membership.has_restricted_site_access) {
                kept.push(row);
            }
        }
        sites = kept;
    }

    let mut session_counts: Vec<(f64, f64)> = Vec::new();
    if !sites.is_empty() {
        let ids: Vec<QueryParam> = sites
            .iter()
            .map(|row| Ok(QueryParam::Number(f64::from(row.try_get::<i32, _>("site_id")?))))
            .collect::<Result<_, sqlx::Error>>()
            .map_err(db)?;
        let spec = QuerySpec::new(SESSION_COUNTS_QUERY).param("siteIds", QueryParam::Array(ids));
        let mut rows: Vec<Map<String, Value>> =
            clickhouse(state).query_rows(&spec, &[]).await.map_err(|err| format!("Error: {err}"))?;
        process_results(&mut rows);
        for row in &rows {
            if let (Some(Value::Number(site)), Some(Value::Number(total))) =
                (row.get("site_id"), row.get("total_sessions"))
                && let (Some(site), Some(total)) = (site.as_f64(), total.as_f64())
            {
                session_counts.push((site, total));
            }
        }
    }

    let team_rows = sqlx::query(
        r#"select "team_site_access"."site_id", "team"."id" as "teamId", "team"."name" as "teamName"
           from "team_site_access" inner join "team" on "team_site_access"."team_id" = "team"."id"
           where "team"."organizationId" = $1"#,
    )
    .bind(organization_id)
    .fetch_all(pg)
    .await
    .map_err(db)?;

    let is_owner = membership.as_ref().is_none_or(|membership| membership.role != "member");
    let mut enhanced: Vec<(f64, JsValue)> = Vec::with_capacity(sites.len());
    for row in &sites {
        let site_id: i32 = row.try_get("site_id").map_err(db)?;
        let mut fields = site_fields(row, false).map_err(db)?;
        // `type: site.type || "web"` and `domain: site.domain || ""` replace the
        // values in place, so the keys keep their positions
        for (name, value) in fields.iter_mut() {
            if *name == "type" && !js::truthy(value) {
                *value = "web".into();
            }
            if *name == "domain" && !js::truthy(value) {
                *value = "".into();
            }
        }
        let sessions = session_counts
            .iter()
            .find(|(site, _)| *site == f64::from(site_id))
            .map_or(0.0, |(_, total)| *total);
        let mut teams = Vec::new();
        for team in &team_rows {
            if team.try_get::<i32, _>("site_id").map_err(db)? == site_id {
                teams.push(object(vec![
                    ("id", JsValue::String(team.try_get("teamId").map_err(db)?)),
                    ("name", JsValue::String(team.try_get("teamName").map_err(db)?)),
                ]));
            }
        }
        fields.push(("sessionsLast24Hours", JsValue::Number(sessions)));
        fields.push(("isOwner", JsValue::Bool(is_owner)));
        fields.push(("teams", JsValue::Array(teams)));
        enhanced.push((sessions, object(fields)));
    }
    // `sort((a, b) => b.sessionsLast24Hours - a.sessionsLast24Hours)`, stable in V8
    enhanced.sort_by(|left, right| right.0.partial_cmp(&left.0).unwrap_or(std::cmp::Ordering::Equal));

    debug!(organization_id, sites = enhanced.len(), "Listed organization sites");
    Ok(object(vec![
        ("organization", org_row.as_ref().map(organization_value).transpose().map_err(db)?.unwrap_or(JsValue::Null)),
        ("sites", JsValue::Array(enhanced.into_iter().map(|(_, value)| value).collect())),
        (
            "subscription",
            object(vec![
                ("monthlyEventCount", JsValue::Number(0.0)),
                // `eventLimit = Infinity` without CLOUD; JSON.stringify writes null
                ("eventLimit", JsValue::Null),
                ("overMonthlyLimit", JsValue::Bool(false)),
                ("planName", "free".into()),
                ("status", "free".into()),
            ]),
        ),
    ]))
}

// ---------------------------------------------------------------------------
// POST /api/organizations/:organizationId/sites

/// `DOMAIN_PATTERN` in siteConfigurationLifecycle.ts
static DOMAIN_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(?:[\p{L}\p{N}](?:[\p{L}\p{N}\-]{0,61}[\p{L}\p{N}])?\.)+\p{L}{2,}$").expect("valid domain pattern")
});

/// `APP_IDENTIFIER_PATTERN`
static APP_IDENTIFIER_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z0-9][A-Za-z0-9._\-]{0,252}$").expect("valid identifier pattern"));

/// `normalizeDomain`
fn normalize_domain(domain: &str) -> String {
    let without_scheme =
        domain.strip_prefix("http://").or_else(|| domain.strip_prefix("https://")).unwrap_or(domain);
    without_scheme.trim_end_matches('/').to_string()
}

/// A `SiteLifecycleError`: the status and message the route reports.
struct LifecycleError {
    status: StatusCode,
    message: &'static str,
}

/// `siteConfigurationLifecycle.create`, without the cloud entitlement checks.
struct CreateInput {
    site_type: &'static str,
    domain: String,
    name: JsValue,
    public: JsValue,
    salt_user_ids: JsValue,
    block_bots: JsValue,
    optional: Vec<(&'static str, &'static str, JsValue)>,
}

/// The fields `create` only writes when they are present, as (column, kind, value).
const OPTIONAL_FIELDS: &[(&str, &str, &str)] = &[
    ("excludedIPs", "excluded_ips", "json"),
    ("excludedCountries", "excluded_countries", "json"),
    ("sessionReplay", "sessionReplay", "bool"),
    ("webVitals", "webVitals", "bool"),
    ("trackErrors", "trackErrors", "bool"),
    ("trackOutbound", "trackOutbound", "bool"),
    ("trackUrlParams", "trackUrlParams", "bool"),
    ("trackInitialPageView", "trackInitialPageView", "bool"),
    ("trackSpaNavigation", "trackSpaNavigation", "bool"),
    ("trackIp", "trackIp", "bool"),
    ("trackButtonClicks", "trackButtonClicks", "bool"),
    ("trackCopy", "trackCopy", "bool"),
    ("trackFormInteractions", "trackFormInteractions", "bool"),
    ("tags", "tags", "json"),
];

/// POST /api/organizations/:organizationId/sites (`addSite`), chain
/// `orgAdminSitesWrite`.
pub async fn create(
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
    let scoped = match org_scoped(&state, &headers, &uri, &organization_id, true, route_scope("sites", "write")).await {
        Ok(scoped) => scoped,
        Err(response) => return response,
    };

    // `{ ...request.body, organizationId, createdBy }`: a non-object body spreads to
    // nothing the lifecycle reads
    let fields = match &body {
        JsValue::Object(object) => object.clone(),
        _ => JsObject::new(),
    };
    let input = match build_input(&fields) {
        Ok(input) => input,
        Err(Some(err)) => return request::error(err.status, err.message),
        // `normalizeDomain(undefined)` and friends are plain TypeErrors, not
        // SiteLifecycleErrors, so the route reports its generic 500
        Err(None) => {
            error!("Error adding site");
            return request::error(StatusCode::INTERNAL_SERVER_ERROR, "Internal server error");
        }
    };

    match insert_site(&state, &organization_id, scoped.auth.user_id.as_deref(), &input, lone_surrogate).await {
        Ok(value) => {
            if let Some(user_id) = scoped.auth.user_id.as_deref() {
                access::invalidate_sites_access(&state, user_id);
            }
            request::send(StatusCode::CREATED, &value)
        }
        Err(err) => {
            error!(error = %err, "Error adding site");
            request::error(StatusCode::INTERNAL_SERVER_ERROR, "Internal server error")
        }
    }
}

/// `Err(Some(_))` is a `SiteLifecycleError`, `Err(None)` a thrown TypeError.
#[allow(clippy::result_large_err)]
fn build_input(fields: &JsObject) -> Result<CreateInput, Option<LifecycleError>> {
    // `normalizeSiteType(input.type)`
    let site_type = if fields.get_or_undefined("type") == &JsValue::String("mobile".into()) { "mobile" } else { "web" };
    // `normalizeDomain(input.domain)` throws for anything but a string
    let JsValue::String(raw_domain) = fields.get_or_undefined("domain") else { return Err(None) };
    let domain = normalize_domain(raw_domain);

    if site_type == "web" && !DOMAIN_PATTERN.is_match(&domain) {
        return Err(Some(LifecycleError {
            status: StatusCode::BAD_REQUEST,
            message: "Invalid domain format. Must be a valid domain like example.com or sub.example.com",
        }));
    }
    if site_type == "mobile" && !APP_IDENTIFIER_PATTERN.is_match(&domain) {
        return Err(Some(LifecycleError {
            status: StatusCode::BAD_REQUEST,
            message: "Invalid app identifier. Use a bundle/package identifier like com.example.app",
        }));
    }
    if site_type == "mobile"
        && (js::truthy(fields.get_or_undefined("sessionReplay")) || js::truthy(fields.get_or_undefined("webVitals")))
    {
        return Err(Some(LifecycleError {
            status: StatusCode::BAD_REQUEST,
            message: "Session replay and Web Vitals are only available for web sites",
        }));
    }

    let optional = OPTIONAL_FIELDS
        .iter()
        .filter_map(|(field, column, kind)| {
            let value = fields.get_or_undefined(field);
            (!matches!(value, JsValue::Undefined)).then(|| (*column, *kind, value.clone()))
        })
        .collect();

    Ok(CreateInput {
        site_type,
        domain,
        name: fields.get_or_undefined("name").clone(),
        public: fields.get_or_undefined("public").clone(),
        salt_user_ids: fields.get_or_undefined("saltUserIds").clone(),
        block_bots: fields.get_or_undefined("blockBots").clone(),
        optional,
    })
}

/// `db.insert(sites).values({...}).returning()`
async fn insert_site(
    state: &AppState,
    organization_id: &str,
    created_by: Option<&str>,
    input: &CreateInput,
    lone_surrogate: bool,
) -> Result<JsValue, String> {
    let mut columns: Vec<String> = vec![
        r#""id""#.into(),
        r#""type""#.into(),
        r#""domain""#.into(),
        r#""name""#.into(),
        r#""created_by""#.into(),
        r#""organization_id""#.into(),
        r#""public""#.into(),
        r#""saltUserIds""#.into(),
        r#""blockBots""#.into(),
    ];
    let mut placeholders: Vec<String> = (1..=columns.len()).map(|index| format!("${index}")).collect();
    let mut extra: Vec<(&str, JsValue)> = Vec::new();
    for (position, (column, kind, value)) in (columns.len() + 1..).zip(input.optional.iter()) {
        columns.push(format!("\"{column}\""));
        placeholders.push(if *kind == "json" { format!("${position}::jsonb") } else { format!("${position}") });
        extra.push((kind, value.clone()));
    }

    let sql = format!(
        "insert into \"sites\" ({}) values ({}) returning {SITE_COLUMNS}",
        columns.join(", "),
        placeholders.join(", ")
    );
    let mut query = sqlx::query(&sql)
        .bind(random_site_id())
        .bind(if input.site_type == "web" { None } else { Some(input.site_type) })
        .bind(input.domain.clone())
        .bind(bind_text(&input.name)?)
        .bind(created_by.map(str::to_string))
        .bind(organization_id.to_string())
        .bind(bind_bool(&input.public, false))
        .bind(bind_bool(&input.salt_user_ids, false))
        .bind(bind_bool(&input.block_bots, true));
    for (kind, value) in &extra {
        if *kind == "json" {
            let stored = js_json::stringify(value).unwrap_or_else(|| "null".to_string());
            if request::jsonb_rejects(lone_surrogate, &stored) {
                return Err("PostgresError: unsupported Unicode escape sequence".into());
            }
            query = query.bind(stored);
        } else {
            query = query.bind(bind_bool(value, false));
        }
    }

    let row = query.fetch_one(&state.pg).await.map_err(|err| format!("PostgresError: {err}"))?;
    let site_id: i32 = row.try_get("site_id").map_err(|err| err.to_string())?;
    info!(organization_id, site_id, domain = %input.domain, "Site created");
    Ok(object(site_fields(&row, true).map_err(|err| err.to_string())?))
}

/// `randomBytes(6).toString("hex")`
fn random_site_id() -> String {
    let mut bytes = [0u8; 6];
    rand::Rng::fill_bytes(&mut rand::rng(), &mut bytes);
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// A text column's parameter, as postgres-js serialises it (`String(value)`).
/// `true` and `false` carry a type of their own, which the column rejects.
fn bind_text(value: &JsValue) -> Result<Option<String>, String> {
    match js::bind_value(value) {
        js::Bind::Null => Ok(None),
        js::Bind::Text(text) => Ok(Some(text)),
        js::Bind::Throws => {
            Err("PostgresError: column \"name\" is of type text but expression is of type boolean".into())
        }
    }
}

/// A boolean column's parameter: `value ?? fallback` in the lifecycle's own
/// defaulting, then postgres-js's `x === true ? 't' : 'f'`, so anything but `true`
/// stores false.
fn bind_bool(value: &JsValue, fallback: bool) -> bool {
    // `input.public ?? false` and friends replace a nullish value before binding
    js::bind_boolean(value).unwrap_or(fallback)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domains_are_normalised_then_matched() {
        assert_eq!(normalize_domain("https://example.com//"), "example.com");
        assert_eq!(normalize_domain("http://sub.example.com"), "sub.example.com");
        assert!(DOMAIN_PATTERN.is_match("example.com"));
        assert!(DOMAIN_PATTERN.is_match("sub.example.co.uk"));
        assert!(DOMAIN_PATTERN.is_match("xn--bcher-kva.example"));
        assert!(DOMAIN_PATTERN.is_match("bücher.example"));
        assert!(!DOMAIN_PATTERN.is_match("example"));
        assert!(!DOMAIN_PATTERN.is_match("-example.com"));
        assert!(!DOMAIN_PATTERN.is_match("example.c"));
        assert!(!DOMAIN_PATTERN.is_match("example.com/path"));
        assert!(APP_IDENTIFIER_PATTERN.is_match("com.example.app"));
        assert!(!APP_IDENTIFIER_PATTERN.is_match(".com.example"));
    }

    #[test]
    fn site_id_is_twelve_hex_characters() {
        let id = random_site_id();
        assert_eq!(id.len(), 12);
        assert!(id.bytes().all(|byte| byte.is_ascii_hexdigit()));
    }
}
