//! Organization members, ported from server/src/api/user/listOrganizationMembers.ts,
//! addUserToOrganization.ts and createUserInOrganization.ts, plus the member site
//! grants from server/src/api/memberAccess/updateMemberSiteAccess.ts.

use axum::{
    body::Body,
    extract::State,
    http::{HeaderMap, Method, StatusCode, Uri},
    response::Response,
};
use sqlx::{PgPool, Row};
use tracing::{debug, error, info};

use super::{
    access,
    js::{self, Bind, ListArg},
    request::{self, object, text},
};
use crate::{
    analytics::{
        chain::{account_scoped, org_scoped, route_scope},
        js::JsValue,
    },
    auth::{
        access::{get_org_membership, is_system_admin},
        endpoints::{crypto, db as auth_db},
        guards::Authenticated,
    },
    state::AppState,
};

/// `generateId(32)` in addUserToOrganization/createUserInOrganization: 32 characters
/// of `0-9A-Za-z`, drawn with `randomBytes(32)[i] % 62`.
fn member_id() -> String {
    const ALPHABET: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    let mut bytes = [0u8; 32];
    rand::Rng::fill_bytes(&mut rand::rng(), &mut bytes);
    bytes.iter().map(|byte| ALPHABET[usize::from(*byte) % ALPHABET.len()] as char).collect()
}

// ---------------------------------------------------------------------------
// GET /api/organizations/:organizationId/members

/// `listOrganizationMembers`, chain `orgOrgRead`.
pub async fn list(State(state): State<AppState>, method: Method, uri: Uri, headers: HeaderMap) -> Response {
    let params = match request::route_params(&uri, &[3]) {
        Ok(params) => params,
        Err(failure) => return request::param_failure(failure, method, uri).await,
    };
    let organization_id = params[0].clone();
    if let Err(response) = org_scoped(&state, &headers, &uri, &organization_id, false, route_scope("org", "read")).await
    {
        return response;
    }

    match list_members(&state.pg, &organization_id).await {
        Ok(value) => request::send(StatusCode::OK, &value),
        Err(err) => {
            error!(error = %err, "Error listing organization members");
            request::send(
                StatusCode::INTERNAL_SERVER_ERROR,
                &object(vec![
                    ("error", "InternalServerError".into()),
                    ("message", "An error occurred while listing organization members".into()),
                ]),
            )
        }
    }
}

async fn list_members(pg: &PgPool, organization_id: &str) -> Result<JsValue, sqlx::Error> {
    let rows = sqlx::query(
        r#"select "member"."id", "member"."role", "member"."userId", "member"."organizationId",
                  "member"."createdAt"::text as "createdAt", "member"."has_restricted_site_access",
                  "user"."name" as "userName", "user"."email" as "userEmail", "user"."image" as "userImage",
                  "user"."id" as "userActualId"
           from "member" left join "user" on "member"."userId" = "user"."id"
           where "member"."organizationId" = $1"#,
    )
    .bind(organization_id)
    .fetch_all(pg)
    .await?;

    let member_ids: Vec<String> = rows.iter().map(|row| row.get("id")).collect();
    let member_user_ids: Vec<String> = rows.iter().map(|row| row.get("userId")).collect();

    let site_access = if member_ids.is_empty() {
        Vec::new()
    } else {
        sqlx::query(r#"select "member_id", "site_id" from "member_site_access" where "member_id" = ANY($1)"#)
            .bind(&member_ids)
            .fetch_all(pg)
            .await?
    };
    let team_memberships = if member_user_ids.is_empty() {
        Vec::new()
    } else {
        sqlx::query(
            r#"select "teamMember"."userId", "team"."id" as "teamId", "team"."name" as "teamName"
               from "teamMember" inner join "team" on "teamMember"."teamId" = "team"."id"
               where ("teamMember"."userId" = ANY($1) and "team"."organizationId" = $2)"#,
        )
        .bind(&member_user_ids)
        .bind(organization_id)
        .fetch_all(pg)
        .await?
    };

    let mut data = Vec::with_capacity(rows.len());
    for row in &rows {
        let id: String = row.try_get("id")?;
        let user_id: String = row.try_get("userId")?;
        let mut site_ids = Vec::new();
        for record in &site_access {
            if record.try_get::<String, _>("member_id")? == id {
                site_ids.push(JsValue::Number(f64::from(record.try_get::<i32, _>("site_id")?)));
            }
        }
        let mut teams = Vec::new();
        for record in &team_memberships {
            if record.try_get::<String, _>("userId")? == user_id {
                teams.push(object(vec![
                    ("id", JsValue::String(record.try_get("teamId")?)),
                    ("name", JsValue::String(record.try_get("teamName")?)),
                ]));
            }
        }
        data.push(object(vec![
            ("id", JsValue::String(id)),
            ("role", JsValue::String(row.try_get("role")?)),
            ("userId", JsValue::String(user_id)),
            ("organizationId", JsValue::String(row.try_get("organizationId")?)),
            ("createdAt", text(row.try_get("createdAt")?)),
            (
                "user",
                object(vec![
                    ("id", text(row.try_get("userActualId")?)),
                    ("name", text(row.try_get("userName")?)),
                    ("email", text(row.try_get("userEmail")?)),
                ]),
            ),
            (
                "siteAccess",
                object(vec![
                    ("hasRestrictedSiteAccess", JsValue::Bool(row.try_get("has_restricted_site_access")?)),
                    ("siteIds", JsValue::Array(site_ids)),
                ]),
            ),
            ("teams", JsValue::Array(teams)),
        ]));
    }
    debug!(organization_id, members = data.len(), "Listed organization members");
    Ok(object(vec![("success", JsValue::Bool(true)), ("data", JsValue::Array(data))]))
}

// ---------------------------------------------------------------------------
// The authorisation both `authOrgWrite` handlers repeat inside their own bodies

/// System admin, or an admin/owner of this organization. `Err` is the reply the
/// handler sends; `Ok` carries whether the caller is a system admin and their
/// membership role.
async fn authorize_org_write(
    state: &AppState,
    headers: &HeaderMap,
    query: &crate::analytics::js::JsObject,
    auth: &Authenticated,
    organization_id: &str,
) -> Result<(bool, Option<String>), Response> {
    // `getIsUserAdmin(request)` reads the cookie session, never `request.user`, so a
    // user API key sent alongside a system admin's cookie is authorised as that admin
    let session_user_id = match auth.session.as_ref().map(|session| session.user_id.clone()) {
        Some(user_id) => Some(user_id),
        None => {
            let context = super::chain::context(state, headers, query);
            access::session(&context).await?.map(|session| session.user_id)
        }
    };
    let is_admin = is_system_admin(&state.pg, session_user_id.as_deref()).await.map_err(db_error_500)?;
    if is_admin {
        return Ok((true, None));
    }
    let Some(user_id) = auth.user_id.as_deref() else {
        return Err(request::error(StatusCode::UNAUTHORIZED, "Unauthorized"));
    };
    let membership =
        get_org_membership(&state.pg, Some(user_id), Some(organization_id)).await.map_err(db_error_500)?;
    match membership {
        Some(membership) if membership.is_admin() => Ok((false, Some(membership.role))),
        _ => Err(request::error(StatusCode::UNAUTHORIZED, "Unauthorized")),
    }
}

/// `reply.status(500).send({ error: String(error) })`, how both handlers report an
/// exception. `String(error)` is `"<name>: <message>"`.
fn thrown_500(text: &str) -> Response {
    error!(error = %text, "Organization member write failed");
    request::send(StatusCode::INTERNAL_SERVER_ERROR, &object(vec![("error", text.into())]))
}

/// The same for a postgres-js failure, which prints as `PostgresError: <message>`.
fn db_error_500(err: sqlx::Error) -> Response {
    let message = match err.as_database_error() {
        Some(database) => format!("PostgresError: {}", database.message()),
        None => format!("Error: {err}"),
    };
    thrown_500(&message)
}

/// The same for a JavaScript `TypeError`.
fn type_error_500(message: &str) -> Response {
    thrown_500(&format!("TypeError: {message}"))
}

/// `role !== "admin" && role !== "member" && role !== "owner"`
fn known_role(role: &JsValue) -> Option<&str> {
    match role {
        JsValue::String(text) if matches!(text.as_str(), "admin" | "member" | "owner") => Some(text),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// POST /api/organizations/:organizationId/members

/// `addUserToOrganization`, chain `authOrgWrite`.
pub async fn add_user(
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
    let scoped = match account_scoped(&state, &headers, &uri, false, route_scope("org", "write")).await {
        Ok(scoped) => scoped,
        Err(response) => return response,
    };

    // Everything below is inside Node's try, so a throw is `{error: String(error)}`
    let fields = match js::destructure(&body, "email") {
        Ok(fields) => fields,
        Err(message) => return type_error_500(&message),
    };
    let email = fields.get("email").clone();
    let role = fields.get("role").clone();

    let (is_admin, caller_role) =
        match authorize_org_write(&state, &headers, &scoped.query, &scoped.auth, &organization_id).await {
            Ok(result) => result,
            Err(response) => return response,
        };

    if !js::truthy(&email) || !js::truthy(&role) {
        return request::error(StatusCode::BAD_REQUEST, "Missing required fields: email and role");
    }
    let Some(role) = known_role(&role) else {
        return request::error(StatusCode::BAD_REQUEST, "Role must be either admin, member, or owner");
    };
    if role == "owner" && !is_admin && caller_role.as_deref() != Some("owner") {
        return request::error(StatusCode::FORBIDDEN, "Only an organization owner can assign the owner role");
    }

    let Bind::Text(email_value) = js::bind_value(&email) else {
        return thrown_500("operator does not exist: text = boolean");
    };
    let result: Result<Response, sqlx::Error> = async {
        let found: Option<String> = sqlx::query_scalar(r#"select "id" from "user" where "email" = $1 limit 1"#)
            .bind(&email_value)
            .fetch_optional(&state.pg)
            .await?;
        let Some(found) = found else {
            return Ok(request::error(StatusCode::NOT_FOUND, "User not found"));
        };
        let existing: Option<String> =
            sqlx::query_scalar(r#"select "id" from "member" where ("userId" = $1 and "organizationId" = $2) limit 1"#)
                .bind(&found)
                .bind(&organization_id)
                .fetch_optional(&state.pg)
                .await?;
        if existing.is_some() {
            return Ok(request::error(StatusCode::BAD_REQUEST, "User is already a member of this organization"));
        }
        let id = member_id();
        sqlx::query(
            r#"insert into "member" ("id", "organizationId", "userId", "role", "createdAt")
               values ($1, $2, $3, $4, $5::timestamp)"#,
        )
        .bind(&id)
        .bind(&organization_id)
        .bind(&found)
        .bind(role)
        .bind(js::now_iso())
        .execute(&state.pg)
        .await?;
        info!(organization_id, member_id = %id, role, "User added to organization");
        Ok(request::send(
            StatusCode::CREATED,
            &object(vec![("message", "User added to organization successfully".into())]),
        ))
    }
    .await;
    result.unwrap_or_else(db_error_500)
}

// ---------------------------------------------------------------------------
// POST /api/organizations/:organizationId/users

/// `createUserInOrganization`, chain `authOrgWrite`. Creates the user through the
/// same rows Better Auth's `internalAdapter.createUser` and `linkAccount` write, so
/// the account can sign in with the password straight away.
pub async fn create_user(
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
    let scoped = match account_scoped(&state, &headers, &uri, false, route_scope("org", "write")).await {
        Ok(scoped) => scoped,
        Err(response) => return response,
    };

    let fields = match js::destructure(&body, "email") {
        Ok(fields) => fields,
        Err(message) => return type_error_500(&message),
    };
    let raw_email = fields.get("email").clone();
    let name = fields.get("name").clone();
    let password = fields.get("password").clone();
    let role = fields.get("role").clone();

    let (is_admin, caller_role) =
        match authorize_org_write(&state, &headers, &scoped.query, &scoped.auth, &organization_id).await {
            Ok(result) => result,
            Err(response) => return response,
        };

    if !js::truthy(&raw_email) || !js::truthy(&password) || !js::truthy(&role) {
        return request::error(StatusCode::BAD_REQUEST, "Missing required fields: email, password and role");
    }
    // `rawEmail.toLowerCase()` throws for anything but a string
    let JsValue::String(raw_email) = &raw_email else {
        return type_error_500(&js::not_a_function_message("rawEmail", "toLowerCase"));
    };
    let email = auth_db::js_lowercase(raw_email);

    let Some(role) = known_role(&role) else {
        return request::error(StatusCode::BAD_REQUEST, "Role must be either admin, member, or owner");
    };
    if role == "owner" && !is_admin && caller_role.as_deref() != Some("owner") {
        return request::error(StatusCode::FORBIDDEN, "Only an organization owner can assign the owner role");
    }
    // `password.length < 8`: a non-string password has no length, so `undefined < 8`
    // is false and the check passes, exactly as in Node
    if let JsValue::String(text) = &password
        && crate::analytics::js::string::utf16_len(text) < 8
    {
        return request::error(StatusCode::BAD_REQUEST, "Password must be at least 8 characters long");
    }

    let existing = auth_db::find_user_by_email(&state.pg, &email).await;
    match existing {
        Err(err) => return db_error_500(err),
        Ok(Some(_)) => return request::error(StatusCode::BAD_REQUEST, "A user with this email already exists"),
        Ok(None) => {}
    }

    let display_name = if js::truthy(&name) { js::to_display(&name) } else { email.clone() };
    let created = match create_auth_user(&state, &email, &display_name).await {
        Ok(created) => created,
        Err(err) => return db_error_500(err),
    };

    // `ctx.password.hash(password)` runs after the user row exists, so a password of
    // the wrong type leaves that row behind, as it does in Node
    let JsValue::String(password) = &password else {
        return type_error_500(&js::not_a_function_message("password", "normalize"));
    };
    let hash = crypto::hash_password(password).await;
    if let Err(err) = auth_db::create_credential_account(&state.pg, &created, &hash).await {
        return db_error_500(err);
    }

    let id = member_id();
    let inserted = sqlx::query(
        r#"insert into "member" ("id", "organizationId", "userId", "role", "createdAt")
           values ($1, $2, $3, $4, $5::timestamp)"#,
    )
    .bind(&id)
    .bind(&organization_id)
    .bind(&created)
    .bind(role)
    .bind(js::now_iso())
    .execute(&state.pg)
    .await;
    if let Err(err) = inserted {
        return db_error_500(err);
    }
    info!(organization_id, user_id = %created, role, "User created in organization");
    request::send(
        StatusCode::CREATED,
        &object(vec![("message", "User created and added to organization successfully".into())]),
    )
}

/// `internalAdapter.createUser` with the admin plugin's default role, plus
/// auth.ts's `user.create.after` hook (the only user becomes a system admin; the
/// welcome mail and the marketing contact are cloud-only).
async fn create_auth_user(state: &AppState, email: &str, name: &str) -> Result<String, sqlx::Error> {
    let id = crypto::generate_id();
    let now = auth_db::now_ms();
    sqlx::query(
        r#"INSERT INTO "user" (id, name, email, "emailVerified", "createdAt", "updatedAt", role, banned, "sendAutoEmailReports")
           VALUES ($1, $2, $3, false, $4, $5, 'user', false, true)"#,
    )
    .bind(&id)
    .bind(name)
    .bind(email)
    .bind(now)
    .bind(now)
    .execute(&state.pg)
    .await?;
    info!(user_id = %id, "User created");
    let count: i64 = sqlx::query_scalar(r#"SELECT count(*) FROM "user""#).fetch_one(&state.pg).await?;
    if count == 1 {
        sqlx::query(r#"UPDATE "user" SET role = 'admin' WHERE id = $1"#).bind(&id).execute(&state.pg).await?;
        info!(user_id = %id, "First user promoted to admin");
    }
    Ok(id)
}

// ---------------------------------------------------------------------------
// PUT /api/organizations/:organizationId/members/:memberId/sites

/// `updateMemberSiteAccess`, chain `orgAdminOrgWrite`.
pub async fn update_site_access(
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
    let (organization_id, member_id) = (params[0].clone(), params[1].clone());
    let body = match request::read_body(&headers, body).await {
        Ok(body) => body,
        Err(response) => return response,
    };
    let scoped = match org_scoped(&state, &headers, &uri, &organization_id, true, route_scope("org", "write")).await {
        Ok(scoped) => scoped,
        Err(response) => return response,
    };

    // The destructuring is before the try, so it is Fastify's own 500
    let fields = match js::destructure(&body, "hasRestrictedSiteAccess") {
        Ok(fields) => fields,
        Err(message) => return js::fastify_uncaught(&message),
    };
    let restricted = fields.get("hasRestrictedSiteAccess").clone();
    let site_ids = fields.get("siteIds").clone();
    let current_user_id = scoped.auth.user_id.clone();

    let list = ListArg::new(&site_ids);
    match update_access(&state, &organization_id, &member_id, &restricted, &list, current_user_id.as_deref()).await {
        Ok(response) => response,
        Err(Ok(response)) => response,
        Err(Err(message)) => {
            error!(error = %message, "Error updating member site access");
            request::error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to update member site access")
        }
    }
}

#[allow(clippy::result_large_err)]
async fn update_access(
    state: &AppState,
    organization_id: &str,
    member_id: &str,
    restricted: &JsValue,
    site_ids: &ListArg<'_>,
    current_user_id: Option<&str>,
) -> Result<Response, Result<Response, String>> {
    let pg = &state.pg;
    let row = sqlx::query(
        r#"select "id", "userId", "role", "organizationId" from "member"
           where ("id" = $1 and "organizationId" = $2) limit 1"#,
    )
    .bind(member_id)
    .bind(organization_id)
    .fetch_optional(pg)
    .await
    .map_err(|err| Err(err.to_string()))?;
    let Some(row) = row else {
        return Ok(request::error(StatusCode::NOT_FOUND, "Member not found"));
    };
    let member_user_id: String = row.try_get("userId").map_err(|err| Err(err.to_string()))?;
    let role: String = row.try_get("role").map_err(|err| Err(err.to_string()))?;
    if role == "admin" || role == "owner" {
        return Ok(request::error(StatusCode::BAD_REQUEST, "Cannot restrict site access for admin or owner roles"));
    }

    // `siteIdsInOrganization` binds every id, so a value Postgres cannot read as an
    // integer throws inside the try
    let mut bound: Vec<Option<i32>> = Vec::new();
    if site_ids.truthy() && site_ids.has_items() {
        let Some(items) = site_ids.items() else {
            return Err(Err("values.map is not a function".into()));
        };
        for item in items {
            match js::bind_value(item) {
                Bind::Null => bound.push(None),
                Bind::Text(text) => match js::pg_int_literal(&text) {
                    Some(value) => bound.push(Some(value)),
                    None => return Err(Err(format!("invalid input syntax for type integer: \"{text}\""))),
                },
                Bind::Throws => return Err(Err("operator does not exist: integer = boolean".into())),
            }
        }
        let present: Vec<i32> = sqlx::query_scalar(
            r#"select "site_id" from "sites" where ("organization_id" = $1 and "site_id" = ANY($2))"#,
        )
        .bind(organization_id)
        .bind(&bound)
        .fetch_all(pg)
        .await
        .map_err(|err| Err(err.to_string()))?;
        let invalid: Vec<JsValue> = items
            .iter()
            .zip(&bound)
            .filter(|(_, bound)| !bound.is_some_and(|value| present.contains(&value)))
            .map(|(item, _)| item.clone())
            .collect();
        if !invalid.is_empty() {
            return Ok(request::error(
                StatusCode::BAD_REQUEST,
                &format!(
                    "Invalid site IDs: {}. Sites must belong to this organization.",
                    js::join_display(&invalid, ", ")
                ),
            ));
        }
    }

    // drizzle refuses an update with nothing to set, which is what an absent
    // `hasRestrictedSiteAccess` produces
    let Some(restricted_literal) = boolean_literal(restricted) else {
        return Err(Err(if matches!(restricted, JsValue::Undefined) {
            "No values to set".to_string()
        } else {
            format!("invalid input syntax for type boolean: \"{}\"", js::to_display(restricted))
        }));
    };

    let mut tx = pg.begin().await.map_err(|err| Err(err.to_string()))?;
    sqlx::query(r#"update "member" set "has_restricted_site_access" = $1 where "id" = $2"#)
        .bind(restricted_literal)
        .bind(member_id)
        .execute(&mut *tx)
        .await
        .map_err(|err| Err(err.to_string()))?;
    sqlx::query(r#"delete from "member_site_access" where "member_id" = $1"#)
        .bind(member_id)
        .execute(&mut *tx)
        .await
        .map_err(|err| Err(err.to_string()))?;
    if js::truthy(restricted) && site_ids.truthy() && site_ids.has_items() {
        for site_id in bound.iter().flatten() {
            sqlx::query(
                r#"insert into "member_site_access" ("member_id", "site_id", "created_by") values ($1, $2, $3)"#,
            )
            .bind(member_id)
            .bind(site_id)
            .bind(current_user_id)
            .execute(&mut *tx)
            .await
            .map_err(|err| Err(err.to_string()))?;
        }
    }
    tx.commit().await.map_err(|err| Err(err.to_string()))?;

    access::invalidate_sites_access(state, &member_user_id);

    let updated = sqlx::query(
        r#"select "member_site_access"."site_id", "sites"."name" as "siteName", "sites"."domain" as "siteDomain"
           from "member_site_access" inner join "sites" on "member_site_access"."site_id" = "sites"."site_id"
           where "member_site_access"."member_id" = $1"#,
    )
    .bind(member_id)
    .fetch_all(pg)
    .await
    .map_err(|err| Err(err.to_string()))?;
    let mut access_rows = Vec::with_capacity(updated.len());
    for row in &updated {
        access_rows.push(object(vec![
            ("siteId", JsValue::Number(f64::from(row.try_get::<i32, _>("site_id").map_err(|err| Err(err.to_string()))?))),
            ("name", JsValue::String(row.try_get("siteName").map_err(|err| Err(err.to_string()))?)),
            ("domain", JsValue::String(row.try_get("siteDomain").map_err(|err| Err(err.to_string()))?)),
        ]));
    }
    info!(organization_id, member_id, sites = access_rows.len(), "Updated member site access");
    Ok(request::send(
        StatusCode::OK,
        &object(vec![
            ("memberId", member_id.into()),
            ("hasRestrictedSiteAccess", restricted.clone()),
            ("siteAccess", JsValue::Array(access_rows)),
        ]),
    ))
}

/// What Postgres accepts for a `boolean` column from the value postgres-js sends.
fn boolean_literal(value: &JsValue) -> Option<bool> {
    match value {
        JsValue::Bool(flag) => Some(*flag),
        JsValue::Undefined => None,
        JsValue::Null => None,
        other => {
            let text = js::to_display(other);
            match text.trim().to_ascii_lowercase().as_str() {
                "t" | "true" | "y" | "yes" | "on" | "1" => Some(true),
                "f" | "false" | "n" | "no" | "off" | "0" => Some(false),
                _ => None,
            }
        }
    }
}
