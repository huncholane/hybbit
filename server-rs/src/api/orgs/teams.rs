//! Teams, ported from server/src/api/teams (listTeams, createTeam, updateTeam,
//! deleteTeam). Registered in `teamsRoutes` with `orgOrgRead` for the listing and
//! `orgAdminOrgWrite` for the three writes.
//!
//! The three writes read `request.body` without a schema, so the JavaScript a value
//! of the wrong shape runs into is part of the contract: see `js` for the pieces
//! (destructuring, `.length`, spreading, what postgres-js binds).

use axum::{
    body::Body,
    extract::State,
    http::{HeaderMap, Method, StatusCode, Uri},
    response::Response,
};
use sqlx::{PgPool, Postgres, Row, Transaction};
use tracing::{debug, error, info};

use super::{
    access,
    js::{self, Bind, ListArg},
    request::{self, object, text},
};
use crate::{
    analytics::{
        chain::{org_scoped, route_scope},
        js::JsValue,
    },
    auth::access::get_org_membership,
    state::AppState,
};

/// `crypto.randomUUID()`
pub fn random_uuid() -> String {
    let bits: u128 = rand::random();
    let bits = (bits & !(0xF << 76) & !(0x3 << 62)) | (0x4 << 76) | (0x2 << 62);
    let hex = format!("{bits:032x}");
    format!("{}-{}-{}-{}-{}", &hex[0..8], &hex[8..12], &hex[12..16], &hex[16..20], &hex[20..32])
}

/// What a team write can fail with inside its `try`.
#[derive(Debug)]
enum Failure {
    Db(sqlx::Error),
    /// A JavaScript throw the handler's catch turns into its own 500
    Thrown(String),
    /// An early `reply.status(...).send(...)`
    Reply(Response),
}

impl From<sqlx::Error> for Failure {
    fn from(err: sqlx::Error) -> Self {
        Failure::Db(err)
    }
}

fn handler_failure(failure: Failure, message: &str) -> Response {
    match failure {
        Failure::Reply(response) => response,
        Failure::Db(err) => {
            error!(error = %err, "{message}");
            request::error(StatusCode::INTERNAL_SERVER_ERROR, message)
        }
        Failure::Thrown(thrown) => {
            error!(error = %thrown, "{message}");
            request::error(StatusCode::INTERNAL_SERVER_ERROR, message)
        }
    }
}

/// GET /api/organizations/:organizationId/teams (`listTeams`).
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

    // `request.user?.id ?? (await getUserIdFromRequest(request))`: an organization-owned
    // API key attaches no user, so it falls through to the credential resolver, which
    // answers None for it too
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

    match list_teams(&state.pg, &organization_id, user_id.as_deref()).await {
        Ok(value) => request::send(StatusCode::OK, &value),
        Err(err) => {
            error!(error = %err, "Failed to list teams");
            request::error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to list teams")
        }
    }
}

struct TeamRow {
    id: String,
    name: String,
    organization_id: String,
    created_at: String,
    updated_at: Option<String>,
}

async fn org_teams(pg: &PgPool, organization_id: &str) -> Result<Vec<TeamRow>, sqlx::Error> {
    let rows = sqlx::query(
        r#"select "team"."id", "team"."name", "team"."organizationId", "team"."createdAt"::text as "createdAt",
                  "team"."updatedAt"::text as "updatedAt"
           from "team" where "team"."organizationId" = $1"#,
    )
    .bind(organization_id)
    .fetch_all(pg)
    .await?;
    rows.iter()
        .map(|row| {
            Ok(TeamRow {
                id: row.try_get("id")?,
                name: row.try_get("name")?,
                organization_id: row.try_get("organizationId")?,
                created_at: row.try_get("createdAt")?,
                updated_at: row.try_get("updatedAt")?,
            })
        })
        .collect()
}

async fn list_teams(pg: &PgPool, organization_id: &str, user_id: Option<&str>) -> Result<JsValue, sqlx::Error> {
    let membership = get_org_membership(pg, user_id, Some(organization_id)).await?;
    let is_admin_or_owner = membership.as_ref().is_some_and(|membership| membership.is_admin());

    let mut teams = org_teams(pg, organization_id).await?;
    if !is_admin_or_owner
        && let Some(user_id) = user_id
    {
        // Every team the user belongs to, across organizations; intersecting with this
        // organization's teams is what the filter does
        let own: Vec<String> = sqlx::query_scalar(r#"select "teamId" from "teamMember" where "userId" = $1"#)
            .bind(user_id)
            .fetch_all(pg)
            .await?;
        teams.retain(|team| own.iter().any(|id| *id == team.id));
    }
    if teams.is_empty() {
        return Ok(object(vec![("teams", JsValue::Array(Vec::new()))]));
    }

    let team_ids: Vec<String> = teams.iter().map(|team| team.id.clone()).collect();
    let member_rows = sqlx::query(
        r#"select "teamMember"."teamId", "teamMember"."userId", "user"."name" as "userName",
                  "user"."email" as "userEmail"
           from "teamMember" inner join "user" on "teamMember"."userId" = "user"."id"
           where "teamMember"."teamId" = ANY($1)"#,
    )
    .bind(&team_ids)
    .fetch_all(pg)
    .await?;
    let site_rows = sqlx::query(
        r#"select "team_site_access"."team_id", "sites"."site_id", "sites"."domain", "sites"."name"
           from "team_site_access" inner join "sites" on "team_site_access"."site_id" = "sites"."site_id"
           where "team_site_access"."team_id" = ANY($1)"#,
    )
    .bind(&team_ids)
    .fetch_all(pg)
    .await?;

    let mut listed = Vec::with_capacity(teams.len());
    for team in &teams {
        let mut members = Vec::new();
        for row in &member_rows {
            if row.try_get::<String, _>("teamId")? != team.id {
                continue;
            }
            members.push(object(vec![
                ("userId", JsValue::String(row.try_get("userId")?)),
                ("userName", text(row.try_get("userName")?)),
                ("userEmail", JsValue::String(row.try_get("userEmail")?)),
            ]));
        }
        let mut sites = Vec::new();
        for row in &site_rows {
            if row.try_get::<String, _>("team_id")? != team.id {
                continue;
            }
            sites.push(object(vec![
                ("siteId", JsValue::Number(f64::from(row.try_get::<i32, _>("site_id")?))),
                ("domain", JsValue::String(row.try_get("domain")?)),
                ("name", JsValue::String(row.try_get("name")?)),
            ]));
        }
        listed.push(object(vec![
            ("id", team.id.clone().into()),
            ("name", team.name.clone().into()),
            ("organizationId", team.organization_id.clone().into()),
            ("createdAt", team.created_at.clone().into()),
            ("updatedAt", text(team.updated_at.clone())),
            ("members", JsValue::Array(members)),
            ("sites", JsValue::Array(sites)),
        ]));
    }
    debug!(organization_id, teams = listed.len(), "Listed teams");
    Ok(object(vec![("teams", JsValue::Array(listed))]))
}

/// `if (memberUserIds && memberUserIds.length > 0) { ... }`: the org members among
/// the requested ids, or the 400 naming the ones that are not.
async fn check_member_user_ids(
    pg: &PgPool,
    organization_id: &str,
    member_user_ids: &ListArg<'_>,
) -> Result<(), Failure> {
    if !(member_user_ids.truthy() && member_user_ids.has_items()) {
        return Ok(());
    }
    let Some(items) = member_user_ids.items() else {
        // A truthy non-array with a length: drizzle's inArray cannot map it
        return Err(Failure::Thrown("values.map is not a function".into()));
    };
    let mut bound: Vec<Option<String>> = Vec::with_capacity(items.len());
    for item in items {
        match js::bind_value(item) {
            Bind::Text(text) => bound.push(Some(text)),
            Bind::Null => bound.push(None),
            Bind::Throws => {
                return Err(Failure::Thrown("operator does not exist: text = boolean".into()));
            }
        }
    }
    let present: Vec<String> =
        sqlx::query_scalar(r#"select "userId" from "member" where ("organizationId" = $1 and "userId" = ANY($2))"#)
            .bind(organization_id)
            .bind(&bound)
            .fetch_all(pg)
            .await?;
    // `new Set(orgMembers.map(m => m.userId))` holds strings, and `Set.has` is
    // strict: a number that matched in SQL is still reported as not in the org
    let invalid: Vec<JsValue> = items.iter().filter(|item| !js::is_present_string(item, &present)).cloned().collect();
    if !invalid.is_empty() {
        return Err(Failure::Reply(request::error(
            StatusCode::BAD_REQUEST,
            &format!("Users not in organization: {}", js::join_display(&invalid, ", ")),
        )));
    }
    Ok(())
}

/// `if (siteIds && siteIds.length > 0) { ... }`, the same for the site grants.
/// Every bound value has to read as an `integer`, so anything else is the
/// handler's 500 rather than a rejection.
async fn check_site_ids(pg: &PgPool, organization_id: &str, site_ids: &ListArg<'_>) -> Result<Vec<i32>, Failure> {
    if !(site_ids.truthy() && site_ids.has_items()) {
        return Ok(Vec::new());
    }
    let Some(items) = site_ids.items() else {
        return Err(Failure::Thrown("values.map is not a function".into()));
    };
    let bound = bind_site_ids(items)?;
    let present: Vec<i32> =
        sqlx::query_scalar(r#"select "site_id" from "sites" where ("organization_id" = $1 and "site_id" = ANY($2))"#)
            .bind(organization_id)
            .bind(&bound)
            .fetch_all(pg)
            .await?;
    // `new Set(orgSites.map(s => s.siteId))` holds numbers, and `Set.has` is strict:
    // the string "65300" matches in SQL but is still reported as not in the org
    let invalid: Vec<JsValue> = items.iter().filter(|item| !js::is_present_number(item, &present)).cloned().collect();
    if !invalid.is_empty() {
        return Err(Failure::Reply(request::error(
            StatusCode::BAD_REQUEST,
            &format!("Sites not in organization: {}", js::join_display(&invalid, ", ")),
        )));
    }
    Ok(bound.into_iter().flatten().collect())
}

/// The `site_id` values postgres-js sends, `None` for SQL NULL.
fn bind_site_ids(items: &[JsValue]) -> Result<Vec<Option<i32>>, Failure> {
    items
        .iter()
        .map(|item| match js::bind_value(item) {
            Bind::Null => Ok(None),
            Bind::Text(text) => js::pg_int_literal(&text).map(Some).ok_or_else(|| {
                Failure::Thrown(format!("invalid input syntax for type integer: \"{text}\""))
            }),
            Bind::Throws => Err(Failure::Thrown("operator does not exist: integer = boolean".into())),
        })
        .collect()
}

async fn insert_team_members(
    tx: &mut Transaction<'_, Postgres>,
    team_id: &str,
    user_ids: &[JsValue],
    now: &str,
) -> Result<(), Failure> {
    for user_id in user_ids {
        let Bind::Text(value) = js::bind_value(user_id) else {
            return Err(Failure::Thrown("null value in column \"userId\" violates not-null constraint".into()));
        };
        sqlx::query(
            r#"insert into "teamMember" ("id", "teamId", "userId", "createdAt") values ($1, $2, $3, $4::timestamp)"#,
        )
        .bind(random_uuid())
        .bind(team_id)
        .bind(value)
        .bind(now)
        .execute(&mut **tx)
        .await?;
    }
    Ok(())
}

async fn insert_team_sites(
    tx: &mut Transaction<'_, Postgres>,
    team_id: &str,
    site_ids: &[i32],
) -> Result<(), Failure> {
    for site_id in site_ids {
        sqlx::query(r#"insert into "team_site_access" ("team_id", "site_id") values ($1, $2)"#)
            .bind(team_id)
            .bind(site_id)
            .execute(&mut **tx)
            .await?;
    }
    Ok(())
}

/// POST /api/organizations/:organizationId/teams (`createTeam`).
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
    let body = match request::read_body(&headers, body).await {
        Ok(body) => body,
        Err(response) => return response,
    };
    if let Err(response) = org_scoped(&state, &headers, &uri, &organization_id, true, route_scope("org", "write")).await
    {
        return response;
    }

    // The destructuring and the blank-name check both run before the try, so their
    // TypeErrors are Fastify's 500 rather than the handler's
    let fields = match js::destructure(&body, "name") {
        Ok(fields) => fields,
        Err(message) => return js::fastify_uncaught(&message),
    };
    let name = fields.get("name").clone();
    let member_user_ids = fields.get("memberUserIds").clone();
    let site_ids = fields.get("siteIds").clone();
    if !js::truthy(&name) {
        return request::error(StatusCode::BAD_REQUEST, "Team name is required");
    }
    let trimmed = match js::trim_call(&name, "name") {
        Ok(text) => text,
        Err(message) => return js::fastify_uncaught(&message),
    };
    if trimmed.is_empty() {
        return request::error(StatusCode::BAD_REQUEST, "Team name is required");
    }

    let members = ListArg::new(&member_user_ids);
    let sites = ListArg::new(&site_ids);
    match create_team(&state, &organization_id, &trimmed, &members, &sites).await {
        Ok(response) => response,
        Err(failure) => handler_failure(failure, "Failed to create team"),
    }
}

async fn create_team(
    state: &AppState,
    organization_id: &str,
    name: &str,
    member_user_ids: &ListArg<'_>,
    site_ids: &ListArg<'_>,
) -> Result<Response, Failure> {
    let pg = &state.pg;
    check_member_user_ids(pg, organization_id, member_user_ids).await?;
    let sites = check_site_ids(pg, organization_id, site_ids).await?;

    let team_id = random_uuid();
    let now = js::now_iso();
    let members: Vec<JsValue> = if member_user_ids.truthy() && member_user_ids.has_items() {
        member_user_ids.items().unwrap_or_default().to_vec()
    } else {
        Vec::new()
    };

    let mut tx = pg.begin().await?;
    sqlx::query(
        r#"insert into "team" ("id", "name", "organizationId", "createdAt", "updatedAt")
           values ($1, $2, $3, $4::timestamp, $5::timestamp)"#,
    )
    .bind(&team_id)
    .bind(name)
    .bind(organization_id)
    .bind(&now)
    .bind(&now)
    .execute(&mut *tx)
    .await?;
    insert_team_members(&mut tx, &team_id, &members, &now).await?;
    insert_team_sites(&mut tx, &team_id, &sites).await?;
    tx.commit().await?;

    // `if (memberUserIds) for (const userId of memberUserIds)`: a truthy value that is
    // not iterable throws here, after the transaction has committed
    if member_user_ids.truthy() {
        for user_id in member_user_ids.spread().map_err(Failure::Thrown)? {
            access::invalidate_sites_access(state, &js::to_display(&user_id));
        }
    }
    info!(organization_id, team_id, members = members.len(), sites = sites.len(), "Team created");

    Ok(request::send(
        StatusCode::CREATED,
        &object(vec![
            ("id", team_id.into()),
            ("name", name.into()),
            ("organizationId", organization_id.into()),
            ("createdAt", now.clone().into()),
            ("updatedAt", now.into()),
            ("members", member_user_ids.or_empty_array()),
            ("siteIds", site_ids.or_empty_array()),
        ]),
    ))
}

/// The team behind `:teamId` in this organization, or `None` for the 404.
async fn find_team(pg: &PgPool, team_id: &str, organization_id: &str) -> Result<Option<String>, sqlx::Error> {
    sqlx::query_scalar(r#"select "id" from "team" where ("id" = $1 and "organizationId" = $2) limit 1"#)
        .bind(team_id)
        .bind(organization_id)
        .fetch_optional(pg)
        .await
}

/// PUT /api/organizations/:organizationId/teams/:teamId (`updateTeam`).
pub async fn update(
    State(state): State<AppState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let params = match request::route_params(&uri, &[3, 5]) {
        Ok(params) => params,
        Err(failure) => return request::param_failure(failure, method, uri).await,
    };
    let (organization_id, team_id) = (params[0].clone(), params[1].clone());
    let body = match request::read_body(&headers, body).await {
        Ok(body) => body,
        Err(response) => return response,
    };
    if let Err(response) = org_scoped(&state, &headers, &uri, &organization_id, true, route_scope("org", "write")).await
    {
        return response;
    }

    let fields = match js::destructure(&body, "name") {
        Ok(fields) => fields,
        Err(message) => return js::fastify_uncaught(&message),
    };
    let name = fields.get("name").clone();
    let member_user_ids = fields.get("memberUserIds").clone();
    let site_ids = fields.get("siteIds").clone();
    let members = ListArg::new(&member_user_ids);
    let sites = ListArg::new(&site_ids);

    match update_team(&state, &organization_id, &team_id, &name, &members, &sites).await {
        Ok(response) => response,
        Err(failure) => handler_failure(failure, "Failed to update team"),
    }
}

async fn update_team(
    state: &AppState,
    organization_id: &str,
    team_id: &str,
    name: &JsValue,
    member_user_ids: &ListArg<'_>,
    site_ids: &ListArg<'_>,
) -> Result<Response, Failure> {
    let pg = &state.pg;
    if find_team(pg, team_id, organization_id).await?.is_none() {
        return Ok(request::error(StatusCode::NOT_FOUND, "Team not found"));
    }

    let existing: Vec<String> = sqlx::query_scalar(r#"select "userId" from "teamMember" where "teamId" = $1"#)
        .bind(team_id)
        .fetch_all(pg)
        .await?;

    check_member_user_ids(pg, organization_id, member_user_ids).await?;
    let sites = check_site_ids(pg, organization_id, site_ids).await?;

    let now = js::now_iso();
    // `updates.name = name.trim()` is inside the try, so a name of the wrong type is
    // the handler's own 500
    let trimmed = match name {
        JsValue::Undefined => None,
        other => Some(js::trim_call(other, "name").map_err(Failure::Thrown)?),
    };
    let replace_members = !member_user_ids.is_undefined();
    let replace_sites = !site_ids.is_undefined();
    // `memberUserIds.length` inside the transaction throws for null, after the delete
    if replace_members && member_user_ids.is_nullish() {
        return Err(Failure::Thrown(js::nullish_property_message(member_user_ids.value(), "length")));
    }
    if replace_sites && site_ids.is_nullish() {
        return Err(Failure::Thrown(js::nullish_property_message(site_ids.value(), "length")));
    }
    let members: Vec<JsValue> = if member_user_ids.has_items() {
        match member_user_ids.items() {
            Some(items) => items.to_vec(),
            None => return Err(Failure::Thrown("memberUserIds.map is not a function".into())),
        }
    } else {
        Vec::new()
    };

    let mut tx = pg.begin().await?;
    match &trimmed {
        Some(name) => {
            sqlx::query(r#"update "team" set "updatedAt" = $1::timestamp, "name" = $2 where "id" = $3"#)
                .bind(&now)
                .bind(name)
                .bind(team_id)
                .execute(&mut *tx)
                .await?;
        }
        None => {
            sqlx::query(r#"update "team" set "updatedAt" = $1::timestamp where "id" = $2"#)
                .bind(&now)
                .bind(team_id)
                .execute(&mut *tx)
                .await?;
        }
    }
    if replace_members {
        sqlx::query(r#"delete from "teamMember" where "teamId" = $1"#).bind(team_id).execute(&mut *tx).await?;
        insert_team_members(&mut tx, team_id, &members, &now).await?;
    }
    if replace_sites {
        sqlx::query(r#"delete from "team_site_access" where "team_id" = $1"#)
            .bind(team_id)
            .execute(&mut *tx)
            .await?;
        insert_team_sites(&mut tx, team_id, &sites).await?;
    }
    tx.commit().await?;

    // `new Set([...existingUserIds, ...(memberUserIds || [])])`, in insertion order
    let mut affected: Vec<String> = Vec::new();
    for user_id in existing.iter().cloned().chain(
        member_user_ids.spread().map_err(Failure::Thrown)?.iter().map(js::to_display),
    ) {
        if !affected.contains(&user_id) {
            affected.push(user_id);
        }
    }
    for user_id in &affected {
        access::invalidate_sites_access(state, user_id);
    }
    info!(organization_id, team_id, "Team updated");
    Ok(request::send(StatusCode::OK, &object(vec![("success", JsValue::Bool(true))])))
}

/// DELETE /api/organizations/:organizationId/teams/:teamId (`deleteTeam`).
pub async fn delete(
    State(state): State<AppState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let params = match request::route_params(&uri, &[3, 5]) {
        Ok(params) => params,
        Err(failure) => return request::param_failure(failure, method, uri).await,
    };
    let (organization_id, team_id) = (params[0].clone(), params[1].clone());
    if let Err(response) = request::read_body(&headers, body).await {
        return response;
    }
    if let Err(response) = org_scoped(&state, &headers, &uri, &organization_id, true, route_scope("org", "write")).await
    {
        return response;
    }

    let result: Result<Response, sqlx::Error> = async {
        if find_team(&state.pg, &team_id, &organization_id).await?.is_none() {
            return Ok(request::error(StatusCode::NOT_FOUND, "Team not found"));
        }
        let affected: Vec<String> = sqlx::query_scalar(r#"select "userId" from "teamMember" where "teamId" = $1"#)
            .bind(&team_id)
            .fetch_all(&state.pg)
            .await?;
        sqlx::query(r#"delete from "team" where ("id" = $1 and "organizationId" = $2)"#)
            .bind(&team_id)
            .bind(&organization_id)
            .execute(&state.pg)
            .await?;
        for user_id in &affected {
            access::invalidate_sites_access(&state, user_id);
        }
        info!(organization_id, team_id, "Team deleted");
        Ok(request::send(StatusCode::OK, &object(vec![("success", JsValue::Bool(true))])))
    }
    .await;
    result.unwrap_or_else(|err| {
        error!(error = %err, "Failed to delete team");
        request::error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to delete team")
    })
}
