//! User reads on the `publicUsersRead` chain, ported from
//! server/src/api/analytics/users: the user list with trait search
//! (getUsers.ts), a user's sessions per day (getUserSessionCount.ts) and the
//! user detail page (getUserInfo.ts).

use axum::{
    extract::State,
    http::{HeaderMap, Method, StatusCode, Uri},
    response::Response,
};
use serde_json::{Map, Value, json};
use sqlx::Row;
use tracing::{debug, error, info};

use super::{
    common::{
        BuildError, HandlerError, RouteFailure, bad_request, clickhouse, is_object_prototype_key, number_value, ok, parse_int_radix_10, path_params,
        pg_integer, query_value, render, route_failure, send_json, uncaught_error, with_default,
    },
};
use crate::{
    analytics::{
        chain::{ChainSteps, SiteGuard, SiteRequest, route_scope, site_scoped},
        js::{JsObject, JsValue, string::trim},
        sql_string::escape,
        utils::{
            analytics_query::{AnalyticsQueryError, QueryParam, QuerySpec},
            effective_user_id::{effective_user_id, matches_user},
            session_attribution::{SESSION_CHANNEL_AGG, SESSION_REFERRER_AGG},
            session_filters::build_filtered_sessions_cte,
            time_window::{TimeWindowParams, get_time_statement},
            utils::enrich_with_traits,
        },
    },
    state::AppState,
};

/// `publicUsersRead`: resolveSiteId, `allowPublicSiteAccess` with `users:read`,
/// validateTimeParams, expandSegmentParam. Returns the chain's request and the
/// extra path parameters at `positions`.
pub(super) async fn users_chain(
    state: &AppState,
    method: &Method,
    uri: &Uri,
    headers: &HeaderMap,
    positions: &[usize],
) -> Result<(SiteRequest, Vec<String>), Response> {
    let mut all_positions = vec![3];
    all_positions.extend_from_slice(positions);
    let mut params = path_params(method, uri, &all_positions).await?;
    let request =
        site_scoped(state, headers, uri, &params[0], SiteGuard::Public, route_scope("users", "read"), ChainSteps::FULL)
            .await?;
    params.remove(0);
    Ok((request, params))
}

fn site_number(request: &SiteRequest) -> f64 {
    JsValue::from(request.site_id.as_str()).to_number()
}

// ---------------------------------------------------------------------------
// GET /users

const USERS_COUNT_IDENTIFIED_TEMPLATE: &str = r#"
${withFilteredSessions}
SELECT count(*) AS total_count
FROM (
    SELECT DISTINCT identified_user_id
    FROM events
    ${filteredSessionsJoin}
    WHERE
        site_id = {siteId:Int32}
        AND identified_user_id != ''
        ${timeStatement}
        ${matchingClause}
)
"#;

const USERS_COUNT_TEMPLATE: &str = r#"
${withFilteredSessions}
SELECT
    count(DISTINCT ${effectiveUserId}) AS total_count
FROM events
${filteredSessionsJoin}
WHERE
    site_id = {siteId:Int32}
    ${timeStatement}
    ${matchingClause}
  "#;

const USERS_TEMPLATE: &str = r#"
WITH ${cte}
AggregatedUsers AS (
    SELECT
        -- Group by effective user: identified_user_id for identified users, user_id (device) for anonymous
        ${effectiveUserId} AS effective_user_id,
        argMax(user_id, timestamp) AS user_id,
        argMax(identified_user_id, timestamp) AS identified_user_id,
        argMax(country, timestamp) AS country,
        argMax(region, timestamp) AS region,
        argMax(city, timestamp) AS city,
        argMax(language, timestamp) AS language,
        argMax(browser, timestamp) AS browser,
        argMax(browser_version, timestamp) AS browser_version,
        argMax(operating_system, timestamp) AS operating_system,
        argMax(operating_system_version, timestamp) AS operating_system_version,
        argMax(device_type, timestamp) AS device_type,
        argMax(screen_width, timestamp) AS screen_width,
        argMax(screen_height, timestamp) AS screen_height,
        ${SESSION_REFERRER_AGG} AS referrer,
        ${SESSION_CHANNEL_AGG} AS channel,
        argMin(hostname, timestamp) AS hostname,
        countIf(type = 'pageview') AS pageviews,
        countIf(type = 'custom_event') AS events,
        count(distinct session_id) AS sessions,
        max(timestamp) AS last_seen,
        min(timestamp) AS first_seen,
        argMax(tag, timestamp) AS tag
    FROM (
        SELECT *
        FROM events
        ${filteredSessionsJoin}
        WHERE
            site_id = {siteId:Int32}
            ${timeStatement}
            ${matchingClause}
    ) AS events
    GROUP BY
        effective_user_id
),
SessionDurations AS (
    SELECT
        ${effectiveUserId} AS effective_user_id,
        session_id,
        dateDiff('second', min(timestamp), max(timestamp)) AS session_duration
    FROM (
        SELECT *
        FROM events
        ${filteredSessionsJoin}
        WHERE
            site_id = {siteId:Int32}
            ${timeStatement}
            ${matchingClause}
    ) AS events
    GROUP BY
        effective_user_id,
        session_id
),
UserAvgDuration AS (
    SELECT
        effective_user_id,
        round(avg(session_duration)) AS avg_session_duration
    FROM SessionDurations
    GROUP BY
        effective_user_id
)
SELECT
    AggregatedUsers.*,
    coalesce(UserAvgDuration.avg_session_duration, 0) AS avg_session_duration
FROM AggregatedUsers
LEFT JOIN UserAvgDuration USING (effective_user_id)
WHERE 1 = 1
${identifiedClause}
ORDER BY ${actualSortBy} ${actualSortOrder}
LIMIT {limit:Int32} OFFSET {offset:Int32}
  "#;

const VALID_SORT_FIELDS: [&str; 6] = ["first_seen", "last_seen", "pageviews", "sessions", "events", "avg_session_duration"];

/// `buildUsersQuery(query, siteId, matchingUserIds, isCountQuery)`.
pub fn build_users_query(
    query: &JsObject,
    site_id: i64,
    has_matching_user_ids: bool,
    is_count_query: bool,
) -> Result<String, BuildError> {
    let sort_by = with_default(query_value(query, "sort_by"), JsValue::from("last_seen"));
    let sort_order = with_default(query_value(query, "sort_order"), JsValue::from("desc"));
    let identified_only = with_default(query_value(query, "identified_only"), JsValue::from("false"));
    // Search results force the identified-only view
    let filter_identified = identified_only.as_str() == Some("true") || has_matching_user_ids;

    // `validSortFields.includes(sortBy)` is a strict comparison
    let actual_sort_by = match sort_by.as_str() {
        Some(field) if VALID_SORT_FIELDS.contains(&field) => field,
        _ => "last_seen",
    };
    let actual_sort_order = if sort_order.as_str() == Some("asc") { "ASC" } else { "DESC" };

    let time_statement = get_time_statement(&TimeWindowParams::from_object(query), "timestamp")?;
    let cte = build_filtered_sessions_cte(query_value(query, "filters"), site_id, &time_statement, "FilteredSessions")?;
    let join = if cte.is_some() { "INNER JOIN FilteredSessions USING (session_id)" } else { "" };
    let matching_clause =
        if has_matching_user_ids { "AND events.identified_user_id IN ({matchingUserIds:Array(String)})" } else { "" };
    let effective = effective_user_id("events");

    if is_count_query {
        let with_filtered = cte.as_ref().map(|cte| format!("WITH {cte}")).unwrap_or_default();
        let values = [
            ("withFilteredSessions", with_filtered.as_str()),
            ("filteredSessionsJoin", join),
            ("timeStatement", time_statement.as_str()),
            ("matchingClause", matching_clause),
            ("effectiveUserId", effective.as_str()),
        ];
        return Ok(render(
            if filter_identified { USERS_COUNT_IDENTIFIED_TEMPLATE } else { USERS_COUNT_TEMPLATE },
            &values,
        ));
    }

    let cte_prefix = cte.map(|cte| format!("{cte},")).unwrap_or_default();
    Ok(render(
        USERS_TEMPLATE,
        &[
            ("cte", &cte_prefix),
            ("effectiveUserId", &effective),
            ("SESSION_REFERRER_AGG", SESSION_REFERRER_AGG),
            ("SESSION_CHANNEL_AGG", SESSION_CHANNEL_AGG),
            ("filteredSessionsJoin", join),
            ("timeStatement", &time_statement),
            ("matchingClause", matching_clause),
            ("identifiedClause", if filter_identified { "AND identified_user_id != ''" } else { "" }),
            ("actualSortBy", actual_sort_by),
            ("actualSortOrder", actual_sort_order),
        ],
    ))
}

/// What `fieldConditions[searchField] ?? fieldConditions.username` selects.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SearchCondition {
    /// A real condition on the profile row, `$2` being the search term
    Sql(&'static str),
    /// An inherited `Object.prototype` method: drizzle binds the function as a
    /// parameter, postgres.js sends it as NULL, and `AND NULL` matches nothing
    MatchesNothing,
}

/// The trait column each `search_field` matches. `__proto__` resolves to
/// `Object.prototype`, which drizzle cannot classify (a TypeError).
fn search_condition(search_field: &JsValue) -> Result<SearchCondition, HandlerError> {
    let key = search_field.to_js_string();
    Ok(match key.as_str() {
        "username" => SearchCondition::Sql("traits->>'username' ILIKE $2"),
        "name" => SearchCondition::Sql("traits->>'name' ILIKE $2"),
        "email" => SearchCondition::Sql("traits->>'email' ILIKE $2"),
        "user_id" => SearchCondition::Sql("user_id ILIKE $2"),
        "__proto__" => return Err(HandlerError::new("Cannot read properties of null (reading 'constructor')")),
        other if is_object_prototype_key(other) => SearchCondition::MatchesNothing,
        _ => SearchCondition::Sql("traits->>'username' ILIKE $2"),
    })
}

/// `MAX_MATCHING_USER_IDS`
const MAX_MATCHING_USER_IDS: i64 = 10_000;

/// `GET /api/sites/:siteId/users`
pub async fn get_users(State(state): State<AppState>, method: Method, uri: Uri, headers: HeaderMap) -> Response {
    let (request, _) = match users_chain(&state, &method, &uri, &headers, &[]).await {
        Ok(chained) => chained,
        Err(response) => return response,
    };
    let query = &request.query;
    let site = site_number(&request);

    let result: Result<Value, RouteFailure> = async {
        let page = with_default(query_value(query, "page"), JsValue::from("1"));
        let page_size = with_default(query_value(query, "page_size"), JsValue::from("100"));
        let search = query_value(query, "search");
        let search_field = with_default(query_value(query, "search_field"), JsValue::from("username"));

        let mut matching_user_ids: Option<Vec<String>> = None;
        if search.is_truthy() {
            let JsValue::String(search_text) = search else {
                return Err(HandlerError::new("search.trim is not a function").into());
            };
            let trimmed = trim(search_text);
            if !trimmed.is_empty() {
                let search_term = format!("%{trimmed}%");
                let ids = match search_condition(&search_field)? {
                    SearchCondition::Sql(condition) => {
                        let sql = format!(
                            "\n        SELECT user_id FROM user_profiles\n        WHERE site_id = $1 AND {condition}\n        LIMIT $3\n      "
                        );
                        let rows = sqlx::query(&sql)
                            .bind(pg_integer(site)?)
                            .bind(&search_term)
                            .bind(MAX_MATCHING_USER_IDS)
                            .fetch_all(&state.pg)
                            .await?;
                        rows.iter().map(|row| row.try_get::<String, _>("user_id")).collect::<Result<Vec<_>, _>>()?
                    }
                    SearchCondition::MatchesNothing => {
                        pg_integer(site)?;
                        Vec::new()
                    }
                };
                debug!(site_id = %request.site_id, matches = ids.len(), "User search matched profiles");
                if ids.is_empty() {
                    return Ok(json!({
                        "data": [],
                        "totalCount": 0,
                        "page": number_value(parse_int_radix_10(&page)),
                        "pageSize": number_value(parse_int_radix_10(&page_size)),
                    }));
                }
                matching_user_ids = Some(ids);
            }
        }

        let page_number = parse_int_radix_10(&page);
        let page_size_number = parse_int_radix_10(&page_size);
        let offset = (page_number - 1.0) * page_size_number;

        let matching_param = matching_user_ids
            .as_ref()
            .map(|ids| QueryParam::Array(ids.iter().map(|id| QueryParam::String(id.clone())).collect()));
        let mut data_spec = QuerySpec::new(build_users_query(query, site as i64, matching_user_ids.is_some(), false)?)
            .param("siteId", site)
            .param("limit", page_size_number)
            .param("offset", offset);
        let mut count_spec =
            QuerySpec::new(build_users_query(query, site as i64, matching_user_ids.is_some(), true)?).param("siteId", site);
        if let Some(matching) = matching_param {
            data_spec = data_spec.param("matchingUserIds", matching.clone());
            count_spec = count_spec.param("matchingUserIds", matching);
        }

        let client = clickhouse(&state);
        let (data, count) = tokio::join!(client.run_analytics_query(&data_spec), client.run_analytics_query(&count_spec));
        let data = data?;
        let count = count?;
        // `countData[0]?.total_count || 0`
        let total_count = match count.first().and_then(|row| row.get("total_count")) {
            Some(value) if JsValue::from_serde(value).is_truthy() => value.clone(),
            _ => json!(0),
        };
        let data = enrich_with_traits(&state.pg, data, pg_integer(site)?).await?;
        Ok(json!({
            "data": data,
            "totalCount": total_count,
            "page": number_value(page_number),
            "pageSize": number_value(page_size_number),
        }))
    }
    .await;

    match result {
        Ok(body) => {
            info!(site_id = %request.site_id, "Served users");
            ok(body)
        }
        Err(failure) => route_failure("users", failure),
    }
}

// ---------------------------------------------------------------------------
// GET /users/session-count

const USER_SESSION_COUNT_TEMPLATE: &str = r#"
    WITH ${cte}
    UserSessions AS (
      SELECT
        session_id,
        min(timestamp) AS session_start
      FROM events
      ${filteredSessionsJoin}
      WHERE
        site_id = {siteId:Int32}
        AND ${matchesUser}
      GROUP BY session_id
    )
    SELECT
      toDate(session_start, ${timeZone}) as date,
      count() as sessions
    FROM UserSessions
    GROUP BY date
    ORDER BY date ASC
  "#;

/// `buildUserSessionCountQuery(query, siteId)`.
pub fn build_user_session_count_query(query: &JsObject, site_id: i64) -> Result<String, BuildError> {
    let time_zone = with_default(query_value(query, "time_zone"), JsValue::from("UTC"));
    // The calendar spans the user's full history, so no time range applies
    let cte = build_filtered_sessions_cte(query_value(query, "filters"), site_id, "", "FilteredSessions")?;
    let join = if cte.is_some() { "INNER JOIN FilteredSessions USING (session_id)" } else { "" };
    let cte_prefix = cte.map(|cte| format!("{cte},")).unwrap_or_default();
    Ok(render(
        USER_SESSION_COUNT_TEMPLATE,
        &[
            ("cte", &cte_prefix),
            ("filteredSessionsJoin", join),
            ("matchesUser", &matches_user("{userId:String}", "")),
            ("timeZone", &escape(&time_zone)),
        ],
    ))
}

/// `GET /api/sites/:siteId/users/session-count`
pub async fn get_user_session_count(
    State(state): State<AppState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    let (request, _) = match users_chain(&state, &method, &uri, &headers, &[]).await {
        Ok(chained) => chained,
        Err(response) => return response,
    };
    let user_id = query_value(&request.query, "user_id");
    if !user_id.is_truthy() {
        return bad_request("user_id is required");
    }
    let site = site_number(&request);
    let sql = match build_user_session_count_query(&request.query, site as i64) {
        Ok(sql) => sql,
        Err(failure) => return route_failure("user session count", failure),
    };
    let spec = QuerySpec::new(sql).param("siteId", site).param("userId", user_id);
    match clickhouse(&state).run_analytics_query(&spec).await {
        Ok(rows) => {
            info!(site_id = %request.site_id, days = rows.len(), "Served user session counts");
            ok(json!({ "data": rows }))
        }
        Err(failure) => route_failure("user session count", failure),
    }
}

// ---------------------------------------------------------------------------
// GET /users/:userId

/// The four panels `buildUserInfoQueries(query, siteId)` returns.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UserInfoQueries {
    pub sessions_query: String,
    pub vitals_query: String,
    pub locations_query: String,
    pub devices_query: String,
}

const SCOPED_EVENTS_TEMPLATE: &str = r#"(
        SELECT source_events.*
        FROM events AS source_events
        ${filteredSessionsJoin}
        WHERE
            ${matchesUser}
            AND source_events.site_id = {site:Int32}
            ${timeStatement}
    ) AS events"#;

const USER_SESSIONS_TEMPLATE: &str = r#"
    WITH ${cte}
    sessions AS (
        SELECT
            session_id,
            argMax(user_id, timestamp) AS user_id,
            argMax(identified_user_id, timestamp) AS identified_user_id,
            argMax(country, timestamp) AS country,
            argMax(region, timestamp) AS region,
            argMax(city, timestamp) AS city,
            -- Not aliased lat/lon: those aliases would shadow the columns in each other's conditions
            argMaxIf(lat, timestamp, lat != 0 OR lon != 0) AS session_lat,
            argMaxIf(lon, timestamp, lat != 0 OR lon != 0) AS session_lon,
            argMax(language, timestamp) AS language,
            argMax(device_type, timestamp) AS device_type,
            argMax(browser, timestamp) AS browser,
            argMax(browser_version, timestamp) AS browser_version,
            argMax(operating_system, timestamp) AS operating_system,
            argMax(operating_system_version, timestamp) AS operating_system_version,
            argMax(screen_width, timestamp) AS screen_width,
            argMax(screen_height, timestamp) AS screen_height,
            ${SESSION_REFERRER_AGG} AS referrer,
            ${SESSION_CHANNEL_AGG} AS channel,
            argMinIf(url_parameters['utm_source'], timestamp, url_parameters['utm_source'] != '') AS utm_source,
            argMinIf(url_parameters['utm_medium'], timestamp, url_parameters['utm_medium'] != '') AS utm_medium,
            argMinIf(url_parameters['utm_campaign'], timestamp, url_parameters['utm_campaign'] != '') AS utm_campaign,
            argMaxIf(timezone, timestamp, timezone != '') AS user_timezone,
            MAX(timestamp) AS session_end,
            MIN(timestamp) AS session_start,
            dateDiff('second', MIN(timestamp), MAX(timestamp)) AS session_duration,
            argMinIf(pathname, timestamp_ms, type = 'pageview') AS entry_page,
            argMaxIf(pathname, timestamp_ms, type = 'pageview') AS exit_page,
            countIf(type = 'pageview') AS pageviews,
            countIf(type = 'custom_event') AS events,
            argMax(ip, timestamp) AS ip
        FROM ${scopedEvents}
        GROUP BY
            session_id
        ORDER BY
            session_end DESC
    )
    SELECT
        COUNT(DISTINCT session_id) AS sessions,
        ROUND(avg(session_duration)) AS duration,
        any(user_id) AS user_id,
        any(identified_user_id) AS identified_user_id,
        any(country) as country,
        any(region) AS region,
        any(city) AS city,
        -- Latest session with IP-lookup coordinates; 0,0 when none had any
        argMaxIf(session_lat, session_end, session_lat != 0 OR session_lon != 0) AS lat,
        argMaxIf(session_lon, session_end, session_lat != 0 OR session_lon != 0) AS lon,
        any(language) AS language,
        any(device_type) AS device_type,
        any(browser) AS browser,
        any(browser_version) AS browser_version,
        any(operating_system) AS operating_system,
        any(operating_system_version) AS operating_system_version,
        any(screen_height) AS screen_height,
        any(screen_width) AS screen_width,
        MAX(session_end) AS last_seen,
        MIN(session_start) AS first_seen,
        SUM(pageviews) AS pageviews,
        SUM(events) AS events,
        any(ip) AS ip,
        argMin(referrer, session_start) AS first_referrer,
        argMin(channel, session_start) AS first_channel,
        argMinIf(entry_page, session_start, entry_page != '') AS first_entry_page,
        argMinIf(utm_source, session_start, utm_source != '') AS first_utm_source,
        argMinIf(utm_medium, session_start, utm_medium != '') AS first_utm_medium,
        argMinIf(utm_campaign, session_start, utm_campaign != '') AS first_utm_campaign,
        argMax(referrer, session_end) AS last_referrer,
        argMax(channel, session_end) AS last_channel,
        argMaxIf(user_timezone, session_end, user_timezone != '') AS timezone
    FROM
        sessions
      "#;

const USER_VITALS_TEMPLATE: &str = r#"
    ${withFilteredSessions}
    SELECT
        quantile(0.75)(lcp) AS lcp_p75,
        quantile(0.75)(cls) AS cls_p75,
        quantile(0.75)(inp) AS inp_p75,
        quantile(0.75)(fcp) AS fcp_p75,
        quantile(0.75)(ttfb) AS ttfb_p75,
        COUNT(*) AS performance_events
    FROM ${scopedEvents}
    WHERE type = 'performance'
      "#;

const USER_LOCATIONS_TEMPLATE: &str = r#"
    ${withFilteredSessions}
    SELECT
        country,
        region,
        city,
        uniq(session_id) AS sessions,
        MAX(timestamp) AS last_seen
    FROM ${scopedEvents}
    WHERE country != ''
    GROUP BY
        country, region, city
    ORDER BY
        sessions DESC, last_seen DESC
    LIMIT 20
      "#;

const USER_DEVICES_TEMPLATE: &str = r#"
    ${withFilteredSessions}
    SELECT
        device_type,
        browser,
        operating_system,
        argMax(browser_version, timestamp) AS browser_version,
        argMax(operating_system_version, timestamp) AS operating_system_version,
        argMax(screen_width, timestamp) AS screen_width,
        argMax(screen_height, timestamp) AS screen_height,
        uniq(session_id) AS sessions,
        MAX(timestamp) AS last_seen
    FROM ${scopedEvents}
    WHERE NOT (device_type = '' AND browser = '' AND operating_system = '')
    GROUP BY
        device_type, browser, operating_system
    ORDER BY
        sessions DESC, last_seen DESC
    LIMIT 20
      "#;

/// `buildUserInfoQueries(query, siteId)`.
pub fn build_user_info_queries(query: &JsObject, site_id: i64) -> Result<UserInfoQueries, BuildError> {
    let time_statement = get_time_statement(&TimeWindowParams::from_object(query), "timestamp")?;
    let cte = build_filtered_sessions_cte(query_value(query, "filters"), site_id, &time_statement, "FilteredSessions")?;
    let join = if cte.is_some() { "INNER JOIN FilteredSessions USING (session_id)" } else { "" };
    let with_filtered = cte.as_ref().map(|cte| format!("WITH {cte}")).unwrap_or_default();
    let cte_prefix = cte.map(|cte| format!("{cte},")).unwrap_or_default();

    let scoped_events = render(
        SCOPED_EVENTS_TEMPLATE,
        &[
            ("filteredSessionsJoin", join),
            ("matchesUser", &matches_user("{userId:String}", "source_events")),
            ("timeStatement", &time_statement),
        ],
    );
    let panel = |template: &str| {
        render(template, &[("withFilteredSessions", with_filtered.as_str()), ("scopedEvents", scoped_events.as_str())])
    };
    Ok(UserInfoQueries {
        sessions_query: render(
            USER_SESSIONS_TEMPLATE,
            &[
                ("cte", &cte_prefix),
                ("SESSION_REFERRER_AGG", SESSION_REFERRER_AGG),
                ("SESSION_CHANNEL_AGG", SESSION_CHANNEL_AGG),
                ("scopedEvents", &scoped_events),
            ],
        ),
        vitals_query: panel(USER_VITALS_TEMPLATE),
        locations_query: panel(USER_LOCATIONS_TEMPLATE),
        devices_query: panel(USER_DEVICES_TEMPLATE),
    })
}

/// A Postgres read or ClickHouse query inside getUserInfo's try block.
#[derive(Debug, thiserror::Error)]
enum UserInfoFailure {
    #[error(transparent)]
    Query(#[from] AnalyticsQueryError),
    #[error(transparent)]
    Postgres(#[from] sqlx::Error),
    #[error(transparent)]
    Handler(#[from] HandlerError),
}

/// What `loadUser(effectiveUserId)` resolves to.
struct LoadedUser {
    data: Vec<Map<String, Value>>,
    vitals: Vec<Map<String, Value>>,
    locations: Vec<Map<String, Value>>,
    devices: Vec<Map<String, Value>>,
    /// `profileResult[0]?.traits`: None when there is no profile row
    profile_traits: Option<Option<Value>>,
    /// `{ anonymous_id, created_at }` rows
    aliases: Vec<Value>,
}

/// `userProfiles.traits` for one user (`db.select().from(userProfiles)...limit(1)`).
async fn load_profile_traits(state: &AppState, site_id: i32, user_id: &str) -> Result<Option<Option<Value>>, sqlx::Error> {
    let row = sqlx::query(
        r#"select "traits" from "user_profiles" where ("user_profiles"."site_id" = $1 and "user_profiles"."user_id" = $2) limit $3"#,
    )
    .bind(site_id)
    .bind(user_id)
    .bind(1_i64)
    .fetch_optional(&state.pg)
    .await?;
    row.map(|row| row.try_get::<Option<Value>, _>("traits")).transpose()
}

/// The identity a device fingerprint was linked to, if any.
async fn load_alias_user(state: &AppState, site_id: i32, anonymous_id: &str) -> Result<Option<String>, sqlx::Error> {
    sqlx::query_scalar(
        r#"select "user_id" from "user_aliases" where ("user_aliases"."site_id" = $1 and "user_aliases"."anonymous_id" = $2) limit $3"#,
    )
    .bind(site_id)
    .bind(anonymous_id)
    .bind(1_i64)
    .fetch_optional(&state.pg)
    .await
}

async fn load_user(
    state: &AppState,
    queries: &UserInfoQueries,
    site_param: &str,
    site_number: f64,
    user_id: &str,
) -> Result<LoadedUser, UserInfoFailure> {
    let spec = |sql: &str| {
        QuerySpec::new(sql).param("userId", user_id).param("site", QueryParam::String(site_param.to_string()))
    };
    let (sessions_spec, vitals_spec, locations_spec, devices_spec) = (
        spec(&queries.sessions_query),
        spec(&queries.vitals_query),
        spec(&queries.locations_query),
        spec(&queries.devices_query),
    );
    let client = clickhouse(state);
    let postgres = async {
        let site_id = pg_integer(site_number)?;
        let (traits, aliases) = tokio::join!(load_profile_traits(state, site_id, user_id), async {
            sqlx::query(
                r#"select "anonymous_id", "created_at"::text as "created_at" from "user_aliases" where ("user_aliases"."site_id" = $1 and "user_aliases"."user_id" = $2)"#,
            )
            .bind(site_id)
            .bind(user_id)
            .fetch_all(&state.pg)
            .await
        });
        Ok::<_, UserInfoFailure>((traits?, aliases?))
    };
    let (data, vitals, locations, devices, postgres) = tokio::join!(
        client.run_analytics_query(&sessions_spec),
        client.run_analytics_query(&vitals_spec),
        client.run_analytics_query(&locations_spec),
        client.run_analytics_query(&devices_spec),
        postgres,
    );
    let (profile_traits, alias_rows) = postgres?;
    let aliases = alias_rows
        .iter()
        .map(|row| {
            Ok(json!({
                "anonymous_id": row.try_get::<String, _>("anonymous_id")?,
                "created_at": row.try_get::<String, _>("created_at")?,
            }))
        })
        .collect::<Result<Vec<_>, sqlx::Error>>()?;
    Ok(LoadedUser { data: data?, vitals: vitals?, locations: locations?, devices: devices?, profile_traits, aliases })
}

/// `loadUser(userId)` and getUserInfo's alias fallback: a device whose events
/// were all claimed by an identity (the dashboard's Identify User backfills the
/// full history) matches nothing anonymously, so on a miss the panels load again
/// for the identity its alias names. Only on a miss: while a shared fingerprint
/// still has anonymous activity, that activity is what the route is about.
async fn load_with_alias_fallback<T, E, Load, LoadFuture, Alias, AliasFuture>(
    user_id: &str,
    load: Load,
    is_empty: impl Fn(&T) -> bool,
    alias: Alias,
) -> Result<T, E>
where
    Load: Fn(String) -> LoadFuture,
    LoadFuture: Future<Output = Result<T, E>>,
    Alias: FnOnce() -> AliasFuture,
    AliasFuture: Future<Output = Result<Option<String>, E>>,
{
    let loaded = load(user_id.to_string()).await?;
    if !is_empty(&loaded) {
        return Ok(loaded);
    }
    match alias().await? {
        Some(alias_user) if alias_user != user_id => {
            debug!("Following alias to identified user");
            load(alias_user).await
        }
        _ => Ok(loaded),
    }
}

/// A jsonb value as `JSON.parse` would give it (integer-like keys first).
fn js_json(value: &Value) -> Value {
    JsValue::from_serde(value).to_serde()
}

/// `value || null` for a parsed JSON value.
fn truthy_or_null(value: Option<&Value>) -> Value {
    match value {
        Some(value) if JsValue::from_serde(value).is_truthy() => js_json(value),
        _ => Value::Null,
    }
}

/// `GET /api/sites/:siteId/users/:userId`
pub async fn get_user_info(State(state): State<AppState>, method: Method, uri: Uri, headers: HeaderMap) -> Response {
    let (request, params) = match users_chain(&state, &method, &uri, &headers, &[5]).await {
        Ok(chained) => chained,
        Err(response) => return response,
    };
    let user_id = params[0].clone();
    let site = site_number(&request);

    // Built before the try block in Node: a bad filter is an uncaught throw
    let queries = match build_user_info_queries(&request.query, site as i64) {
        Ok(queries) => queries,
        Err(failure) => return uncaught_error(&failure.to_string()),
    };

    let result: Result<Response, UserInfoFailure> = async {
        let loaded = load_with_alias_fallback(
            &user_id,
            |id: String| {
                let (state, queries, site_param) = (&state, &queries, request.site_id.as_str());
                async move { load_user(state, queries, site_param, site, &id).await }
            },
            |loaded: &LoadedUser| loaded.data.is_empty(),
            || async {
                let site_id = pg_integer(site)?;
                Ok(load_alias_user(&state, site_id, &user_id).await?)
            },
        )
        .await?;

        let Some(first) = loaded.data.first() else {
            return Ok(send_json(StatusCode::NOT_FOUND, &json!({ "error": "User not found" })));
        };

        let mut identified_user_id = first.get("identified_user_id").cloned().unwrap_or(Value::Null);
        let mut traits = truthy_or_null(loaded.profile_traits.as_ref().and_then(|traits| traits.as_ref()));

        // The identify backfill is asynchronous: fall back to the alias table so a
        // freshly identified device shows its identity and traits right away
        if !JsValue::from_serde(&identified_user_id).is_truthy() {
            let site_id = pg_integer(site)?;
            if let Some(alias_user) = load_alias_user(&state, site_id, &user_id).await? {
                let alias_traits = load_profile_traits(&state, site_id, &alias_user).await?;
                identified_user_id = Value::String(alias_user);
                let alias_traits = alias_traits.as_ref().and_then(|traits| traits.as_ref());
                if alias_traits.is_some_and(|value| JsValue::from_serde(value).is_truthy()) {
                    traits = js_json(alias_traits.expect("checked above"));
                }
            }
        }

        // `vitalsData[0]?.performance_events > 0`
        let vitals = match loaded.vitals.first() {
            Some(row)
                if row
                    .get("performance_events")
                    .is_some_and(|count| JsValue::from_serde(count).to_number() > 0.0) =>
            {
                Value::Object(row.clone())
            }
            _ => Value::Null,
        };

        let mut body = loaded.data.into_iter().next().expect("checked non-empty");
        body.insert("identified_user_id".into(), identified_user_id);
        body.insert("traits".into(), traits);
        body.insert("linked_devices".into(), Value::Array(loaded.aliases));
        body.insert("vitals".into(), vitals);
        body.insert("locations".into(), Value::Array(loaded.locations.into_iter().map(Value::Object).collect()));
        body.insert("devices".into(), Value::Array(loaded.devices.into_iter().map(Value::Object).collect()));
        Ok(ok(json!({ "data": Value::Object(body) })))
    }
    .await;

    match result {
        Ok(response) => {
            info!(site_id = %request.site_id, status = response.status().as_u16(), "Served user info");
            response
        }
        Err(failure) => {
            error!(err = %failure, site_id = %request.site_id, "Error fetching user info");
            send_json(StatusCode::INTERNAL_SERVER_ERROR, &json!({ "error": "Internal server error" }))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CAMPAIGN: &str = r#"{"parameter":"utm_campaign","type":"equals","value":["recipe_book_2026"]}"#;
    const PATHNAME: &str = r#"{"parameter":"pathname","type":"equals","value":["/thank-you"]}"#;

    fn base_query(filters: &str) -> JsObject {
        [("filters", filters), ("start_date", ""), ("end_date", ""), ("time_zone", "UTC")]
            .iter()
            .map(|(key, value)| (key.to_string(), JsValue::from(*value)))
            .collect()
    }

    // Ported from userQueries.test.ts
    #[test]
    fn users_aggregate_all_events_after_campaign_qualifies_session() {
        let query = base_query(&format!("[{CAMPAIGN}]"));
        let data_sql = build_users_query(&query, 1, false, false).unwrap();
        let count_sql = build_users_query(&query, 1, false, true).unwrap();
        for sql in [&data_sql, &count_sql] {
            assert!(sql.contains("FilteredSessions AS"));
            assert!(sql.contains("WHERE 1 = 1 AND utm_campaign = 'recipe_book_2026'"));
            assert!(sql.contains("INNER JOIN FilteredSessions USING (session_id)"));
            assert_eq!(sql.matches("utm_campaign = 'recipe_book_2026'").count(), 1);
        }
        assert!(data_sql.contains("countIf(type = 'pageview') AS pageviews"));
        assert!(data_sql.contains("countIf(type = 'custom_event') AS events"));
    }

    #[test]
    fn users_campaign_and_pathname_match_different_rows() {
        let query = base_query(&format!("[{CAMPAIGN},{PATHNAME}]"));
        for sql in [build_users_query(&query, 1, false, false).unwrap(), build_users_query(&query, 1, false, true).unwrap()] {
            assert!(sql.contains("WHERE 1 = 1 AND utm_campaign = 'recipe_book_2026'"));
            assert!(sql.contains("AND pathname = '/thank-you'"));
            assert!(sql.contains("INNER JOIN FilteredSessions USING (session_id)"));
            assert_eq!(sql.matches("utm_campaign = 'recipe_book_2026'").count(), 1);
            assert_eq!(sql.matches("pathname = '/thank-you'").count(), 1);
        }
    }

    #[test]
    fn user_detail_panels_share_selected_sessions() {
        let queries = build_user_info_queries(&base_query(&format!("[{CAMPAIGN}]")), 1).unwrap();
        for sql in [&queries.sessions_query, &queries.vitals_query, &queries.locations_query, &queries.devices_query] {
            assert!(sql.contains("FilteredSessions AS"));
            assert!(sql.contains("WHERE 1 = 1 AND utm_campaign = 'recipe_book_2026'"));
            assert!(sql.contains("INNER JOIN FilteredSessions USING (session_id)"));
            assert_eq!(sql.matches("utm_campaign = 'recipe_book_2026'").count(), 1);
        }
        assert!(queries.sessions_query.contains("dateDiff('second', MIN(timestamp), MAX(timestamp)) AS session_duration"));
        assert!(queries.vitals_query.contains("WHERE type = 'performance'"));
    }

    #[test]
    fn user_detail_returns_latest_coordinates() {
        let queries = build_user_info_queries(&base_query("[]"), 1).unwrap();
        assert!(queries.sessions_query.contains("argMaxIf(lat, timestamp, lat != 0 OR lon != 0) AS session_lat"));
        assert!(queries.sessions_query.contains("argMaxIf(session_lat, session_end, session_lat != 0 OR session_lon != 0) AS lat"));
        assert!(queries.sessions_query.contains("argMaxIf(session_lon, session_end, session_lat != 0 OR session_lon != 0) AS lon"));
    }

    #[test]
    fn session_count_uses_start_dates() {
        let mut query = base_query(&format!("[{CAMPAIGN},{PATHNAME}]"));
        query.remove("start_date");
        query.remove("end_date");
        query.insert("time_zone", JsValue::from("America/New_York"));
        let sql = build_user_session_count_query(&query, 1).unwrap();
        assert!(sql.contains("FilteredSessions AS"));
        assert!(sql.contains("WHERE 1 = 1 AND utm_campaign = 'recipe_book_2026'"));
        assert!(sql.contains("AND pathname = '/thank-you'"));
        assert!(sql.contains("INNER JOIN FilteredSessions USING (session_id)"));
        assert!(sql.contains("min(timestamp) AS session_start"));
        assert!(sql.contains("toDate(session_start, 'America/New_York') as date"));
        assert!(sql.contains("FROM UserSessions"));
    }

    /// Runs the alias fallback against in-memory rows and aliases, recording
    /// which user ids the panels were loaded for.
    async fn alias_fallback(
        route_user: &str,
        rows: &[(&str, &str)],
        aliases: &[(&str, &str)],
    ) -> (Vec<(String, String)>, Vec<String>) {
        let queried = std::sync::Mutex::new(Vec::new());
        let loaded = load_with_alias_fallback(
            route_user,
            |id: String| {
                queried.lock().unwrap().push(id.clone());
                let found: Vec<(String, String)> = rows
                    .iter()
                    .filter(|(user, _)| *user == id)
                    .map(|(user, identified)| (user.to_string(), identified.to_string()))
                    .collect();
                async move { Ok::<_, ()>(found) }
            },
            |rows: &Vec<(String, String)>| rows.is_empty(),
            || async {
                Ok(aliases.iter().find(|(device, _)| *device == route_user).map(|(_, user)| user.to_string()))
            },
        )
        .await
        .unwrap();
        let queried = queried.into_inner().unwrap();
        (loaded, queried)
    }

    // Ported from getUserInfo.test.ts
    #[tokio::test]
    async fn serves_the_identity_when_device_rows_were_backfilled() {
        let (loaded, queried) = alias_fallback("fp1", &[("alice", "alice")], &[("fp1", "alice")]).await;
        assert_eq!(loaded, vec![("alice".to_string(), "alice".to_string())]);
        assert!(queried.contains(&"fp1".to_string()) && queried.contains(&"alice".to_string()));
    }

    #[tokio::test]
    async fn keeps_a_devices_own_anonymous_activity() {
        let (loaded, queried) = alias_fallback("fp1", &[("fp1", "")], &[("fp1", "alice")]).await;
        assert_eq!(loaded.len(), 1);
        assert!(!queried.contains(&"alice".to_string()));
    }

    #[tokio::test]
    async fn unknown_device_without_alias_stays_empty() {
        let (loaded, queried) = alias_fallback("unknown", &[], &[]).await;
        assert!(loaded.is_empty());
        assert_eq!(queried, vec!["unknown".to_string()]);
    }

    #[test]
    fn sort_and_search_fields() {
        let mut query = base_query("");
        query.insert("sort_by", JsValue::Array(vec!["sessions".into(), "events".into()]));
        query.insert("sort_order", JsValue::from("asc"));
        let sql = build_users_query(&query, 1, true, false).unwrap();
        assert!(sql.contains("ORDER BY last_seen ASC"));
        assert!(sql.contains("AND events.identified_user_id IN ({matchingUserIds:Array(String)})"));
        assert!(sql.contains("AND identified_user_id != ''"));
        assert_eq!(search_condition(&"email".into()).unwrap(), SearchCondition::Sql("traits->>'email' ILIKE $2"));
        assert_eq!(search_condition(&"bogus".into()).unwrap(), SearchCondition::Sql("traits->>'username' ILIKE $2"));
        assert_eq!(
            search_condition(&JsValue::Array(vec!["email".into(), "name".into()])).unwrap(),
            SearchCondition::Sql("traits->>'username' ILIKE $2")
        );
        assert_eq!(search_condition(&"constructor".into()).unwrap(), SearchCondition::MatchesNothing);
        assert!(search_condition(&"__proto__".into()).is_err());
    }
}
