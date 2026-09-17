//! The admin plugin (better-auth/dist/plugins/admin) with its defaults: roles
//! `admin` and `user`, admins may not be impersonated, bans default to "No reason",
//! impersonation sessions last an hour.

use axum::http::StatusCode;
use serde_json::{Map, Value, json};
use tracing::{error, info, warn};

use super::{
    authoritative_session,
    context::{ApiError, Ctx, EndpointResult, Reply, truthy},
    cookies,
    core_routes::new_session_options,
    db::{self, SessionWithUser, UserField},
    organization::authorize,
    session_from_ctx,
    validate::{self, Ty, optional, required},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Route {
    SetRole,
    GetUser,
    UpdateUser,
    ListUsers,
    ListUserSessions,
    UnbanUser,
    BanUser,
    ImpersonateUser,
    StopImpersonating,
    RevokeUserSession,
    RevokeUserSessions,
    HasPermission,
}

pub async fn run(ctx: &mut Ctx<'_>, route: Route) -> EndpointResult {
    match route {
        Route::SetRole => set_role(ctx).await,
        Route::GetUser => get_user(ctx).await,
        Route::UpdateUser => update_user(ctx).await,
        Route::ListUsers => list_users(ctx).await,
        Route::ListUserSessions => list_user_sessions(ctx).await,
        Route::UnbanUser => unban_user(ctx).await,
        Route::BanUser => ban_user(ctx).await,
        Route::ImpersonateUser => impersonate_user(ctx).await,
        Route::StopImpersonating => stop_impersonating(ctx).await,
        Route::RevokeUserSession => revoke_user_session(ctx).await,
        Route::RevokeUserSessions => revoke_user_sessions(ctx).await,
        Route::HasPermission => has_permission_endpoint(ctx).await,
    }
}

/// The admin plugin's `defaultRoles`
fn role_statements(role: &str) -> Option<&'static [(&'static str, &'static [&'static str])]> {
    match role {
        "admin" => Some(&[
            ("user", &["create", "list", "set-role", "ban", "impersonate", "delete", "set-password", "set-email", "get", "update"]),
            ("session", &["list", "revoke", "delete"]),
        ]),
        "user" => Some(&[("user", &[]), ("session", &[])]),
        _ => None,
    }
}

/// admin `hasPermission`: a missing role counts as the default "user"
pub fn has_permission(role: Option<&str>, permissions: Option<&Map<String, Value>>) -> bool {
    let Some(permissions) = permissions else { return false };
    let role = role.filter(|role| !role.is_empty()).unwrap_or("user");
    role.split(',').any(|role| role_statements(role).is_some_and(|statements| authorize(statements, permissions)))
}

fn allowed(session: &SessionWithUser, resource: &str, action: &str) -> bool {
    let mut request = Map::new();
    request.insert(resource.into(), json!([action]));
    has_permission(session.user.role.as_deref(), Some(&request))
}

fn admin_error(status: StatusCode, code: &str, message: &str) -> ApiError {
    ApiError::code(status, code, message)
}

fn user_not_found() -> ApiError {
    admin_error(StatusCode::NOT_FOUND, "USER_NOT_FOUND", "User not found")
}

/// `adminMiddleware`: an authoritative session or 401 with no body
async fn admin_session(ctx: &mut Ctx<'_>) -> Result<SessionWithUser, ApiError> {
    authoritative_session(ctx).await.ok_or_else(|| ApiError::status(StatusCode::UNAUTHORIZED))
}

/// `z.coerce.string()` for `userId`
fn coerce_user_id(ctx: &Ctx<'_>) -> String {
    match ctx.body_object().and_then(|body| body.get("userId")) {
        None => "undefined".to_string(),
        Some(Value::String(text)) => text.clone(),
        Some(Value::Null) => "null".to_string(),
        Some(Value::Array(items)) => items.iter().map(|item| if item.is_null() { String::new() } else { js_string(item) }).collect::<Vec<_>>().join(","),
        Some(Value::Object(_)) => "[object Object]".to_string(),
        Some(other) => crate::js_json::stringify(other),
    }
}

fn js_string(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        other => crate::js_json::stringify(other),
    }
}

fn parse_roles(value: Option<&Value>) -> String {
    match value {
        Some(Value::Array(items)) => items.iter().map(js_string).collect::<Vec<_>>().join(","),
        Some(Value::String(role)) => role.clone(),
        _ => String::new(),
    }
}

/// `POST /admin/set-role`
async fn set_role(ctx: &mut Ctx<'_>) -> EndpointResult {
    validate::object(ctx.body.as_ref(), &[required("userId", Ty::CoerceString), required("role", Ty::StringOrStringArray)], "body", false)?;
    let session = admin_session(ctx).await?;
    if !allowed(&session, "user", "set-role") {
        return Err(admin_error(StatusCode::FORBIDDEN, "YOU_ARE_NOT_ALLOWED_TO_CHANGE_USERS_ROLE", "You are not allowed to change users role"));
    }
    let user_id = coerce_user_id(ctx);
    if db::find_user_by_id(&ctx.state.pg, &user_id).await?.is_none() {
        return Err(user_not_found());
    }
    let role = parse_roles(ctx.body_object().and_then(|b| b.get("role")));
    let updated = db::update_user(&ctx.state.pg, &user_id, vec![UserField::Role(Some(role.clone()))]).await?.ok_or_else(ApiError::internal)?;
    info!(admin_id = %session.user.id, user_id = %user_id, role = %role, "User role set");
    Ok(Reply::Json(json!({"user": updated.to_json()})))
}

/// `GET /admin/get-user?id=`
async fn get_user(ctx: &mut Ctx<'_>) -> EndpointResult {
    validate::object(Some(&Value::Object(ctx.query.clone())), &[required("id", Ty::String)], "query", false)?;
    let session = admin_session(ctx).await?;
    if !allowed(&session, "user", "get") {
        return Err(admin_error(StatusCode::FORBIDDEN, "YOU_ARE_NOT_ALLOWED_TO_GET_USER", "You are not allowed to get user"));
    }
    let id = ctx.query_str("id").unwrap_or_default().to_string();
    let user = db::find_user_by_id(&ctx.state.pg, &id).await?.ok_or_else(user_not_found)?;
    Ok(Reply::Json(user.to_json()))
}

/// `POST /admin/update-user {userId, data}`
async fn update_user(ctx: &mut Ctx<'_>) -> EndpointResult {
    validate::object(ctx.body.as_ref(), &[required("userId", Ty::CoerceString), required("data", Ty::Record)], "body", false)?;
    let session = admin_session(ctx).await?;
    if !allowed(&session, "user", "update") {
        return Err(admin_error(StatusCode::FORBIDDEN, "YOU_ARE_NOT_ALLOWED_TO_UPDATE_USERS", "You are not allowed to update users"));
    }
    let user_id = coerce_user_id(ctx);
    let data = ctx.body_object().and_then(|b| b.get("data")).and_then(Value::as_object).cloned().unwrap_or_default();
    if data.is_empty() {
        return Err(admin_error(StatusCode::BAD_REQUEST, "NO_DATA_TO_UPDATE", "No data to update"));
    }
    if data.contains_key("password") {
        return Err(admin_error(
            StatusCode::BAD_REQUEST,
            "PASSWORD_CANNOT_BE_UPDATED_VIA_UPDATE_USER",
            "Password cannot be updated through update-user. Use the set-user-password endpoint instead",
        ));
    }
    let mut fields: Vec<UserField> = Vec::new();
    if let Some(role) = data.get("role") {
        if !allowed(&session, "user", "set-role") {
            return Err(admin_error(StatusCode::FORBIDDEN, "YOU_ARE_NOT_ALLOWED_TO_CHANGE_USERS_ROLE", "You are not allowed to change users role"));
        }
        let roles: Vec<&Value> = match role {
            Value::Array(items) => items.iter().collect(),
            other => vec![other],
        };
        if roles.iter().any(|role| !role.is_string()) {
            return Err(admin_error(StatusCode::BAD_REQUEST, "INVALID_ROLE_TYPE", "Invalid role type"));
        }
        fields.push(UserField::Role(Some(roles.iter().filter_map(|r| r.as_str()).collect::<Vec<_>>().join(","))));
    }
    if ["banned", "banReason", "banExpires"].iter().any(|key| data.contains_key(*key)) {
        if !allowed(&session, "user", "ban") {
            return Err(admin_error(StatusCode::FORBIDDEN, "YOU_ARE_NOT_ALLOWED_TO_BAN_USERS", "You are not allowed to ban users"));
        }
        if data.get("banned") == Some(&Value::Bool(true)) && user_id == session.user.id {
            return Err(admin_error(StatusCode::BAD_REQUEST, "YOU_CANNOT_BAN_YOURSELF", "You cannot ban yourself"));
        }
    }
    let mut email_update = None;
    if data.contains_key("email") || data.contains_key("emailVerified") {
        if !allowed(&session, "user", "set-email") {
            return Err(admin_error(StatusCode::FORBIDDEN, "YOU_ARE_NOT_ALLOWED_TO_SET_USERS_EMAIL", "You are not allowed to update users email"));
        }
        if let Some(email) = data.get("email") {
            let email = db::js_lowercase(&js_string(email));
            if !validate::is_email(&email) {
                return Err(admin_error(StatusCode::BAD_REQUEST, "INVALID_EMAIL", "Invalid email"));
            }
            if db::find_user_by_email(&ctx.state.pg, &email).await?.is_some_and(|existing| existing.id != user_id) {
                return Err(admin_error(StatusCode::BAD_REQUEST, "USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL", "User already exists. Use another email."));
            }
            email_update = Some(email);
        }
    }
    if db::find_user_by_id(&ctx.state.pg, &user_id).await?.is_none() {
        return Err(user_not_found());
    }
    // updateUser writes whichever schema fields `data` carries
    for (key, value) in &data {
        let field = match key.as_str() {
            "name" => match value {
                Value::Null => return Err(ApiError::internal()),
                other => Some(UserField::Name(js_string(other))),
            },
            "email" => email_update.clone().map(UserField::Email),
            "emailVerified" => match value {
                Value::Bool(flag) => Some(UserField::EmailVerified(*flag)),
                _ => return Err(ApiError::internal()),
            },
            "image" => Some(UserField::Image((!value.is_null()).then(|| js_string(value)))),
            "banned" => Some(UserField::Banned(match value {
                Value::Null => None,
                Value::Bool(flag) => Some(*flag),
                _ => return Err(ApiError::internal()),
            })),
            "banReason" => Some(UserField::BanReason((!value.is_null()).then(|| js_string(value)))),
            "banExpires" => match value {
                Value::Null => Some(UserField::BanExpires(None)),
                Value::String(text) => match chrono::DateTime::parse_from_rfc3339(text) {
                    Ok(date) => Some(UserField::BanExpires(Some(db::ms(date.naive_utc())))),
                    Err(_) => return Err(ApiError::internal()),
                },
                Value::Number(number) => number.as_i64().map(|millis| UserField::BanExpires(Some(db::from_epoch_ms(millis)))),
                _ => return Err(ApiError::internal()),
            },
            "sendAutoEmailReports" => match value {
                Value::Null => Some(UserField::SendAutoEmailReports(None)),
                Value::Bool(flag) => Some(UserField::SendAutoEmailReports(Some(*flag))),
                _ => return Err(ApiError::internal()),
            },
            "updatedAt" => match value {
                Value::String(text) => match chrono::DateTime::parse_from_rfc3339(text) {
                    Ok(date) => Some(UserField::UpdatedAt(db::ms(date.naive_utc()))),
                    Err(_) => return Err(ApiError::internal()),
                },
                _ => None,
            },
            _ => None,
        };
        if let Some(field) = field
            && !fields.iter().any(|existing| std::mem::discriminant(existing) == std::mem::discriminant(&field))
        {
            fields.push(field);
        }
    }
    let banned = data.get("banned") == Some(&Value::Bool(true));
    let updated = if fields.is_empty() {
        // Only unknown keys: Better Auth still stamps updatedAt
        db::update_user(&ctx.state.pg, &user_id, Vec::new()).await?
    } else {
        db::update_user(&ctx.state.pg, &user_id, fields).await?
    };
    if banned {
        db::delete_user_sessions(&ctx.state.pg, &user_id).await?;
    }
    info!(admin_id = %session.user.id, user_id = %user_id, "User updated by an admin");
    Ok(Reply::Json(updated.map_or(Value::Null, |user| user.to_json())))
}

/// The user columns list-users may filter and sort on, with their SQL names and types
fn user_field(name: &str) -> Option<(&'static str, char)> {
    Some(match name {
        "id" => ("id", 's'),
        "name" => ("name", 's'),
        "email" => ("email", 's'),
        "emailVerified" => (r#""emailVerified""#, 'b'),
        "image" => ("image", 's'),
        "createdAt" => (r#""createdAt""#, 'd'),
        "updatedAt" => (r#""updatedAt""#, 'd'),
        "role" => ("role", 's'),
        "banned" => ("banned", 'b'),
        "banReason" => (r#""banReason""#, 's'),
        "banExpires" => (r#""banExpires""#, 'd'),
        "sendAutoEmailReports" => (r#""sendAutoEmailReports""#, 'b'),
        _ => return None,
    })
}

enum Bind {
    Text(String),
    Bool(bool),
    TextList(Vec<String>),
}

/// `GET /admin/list-users`: filters and sorting become SQL; any failure answers
/// `{users: [], total: 0}` like the endpoint's catch-all.
async fn list_users(ctx: &mut Ctx<'_>) -> EndpointResult {
    validate::object(
        Some(&Value::Object(ctx.query.clone())),
        &[
            optional("searchValue", Ty::String),
            optional("searchField", Ty::Enum(&["email", "name"])),
            optional("searchOperator", Ty::Enum(&["contains", "starts_with", "ends_with"])),
            optional("sortBy", Ty::String),
            optional("sortDirection", Ty::Enum(&["asc", "desc"])),
            optional("filterField", Ty::String),
            optional("filterOperator", Ty::Enum(&["eq", "ne", "lt", "lte", "gt", "gte", "in", "not_in", "contains", "starts_with", "ends_with"])),
        ],
        "query",
        false,
    )?;
    let session = admin_session(ctx).await?;
    if !allowed(&session, "user", "list") {
        return Err(admin_error(StatusCode::FORBIDDEN, "YOU_ARE_NOT_ALLOWED_TO_LIST_USERS", "You are not allowed to list users"));
    }
    let number = |key: &str| -> Option<i64> {
        let text = ctx.query_str(key)?;
        let parsed = if text.trim().is_empty() { 0.0 } else { text.trim().parse::<f64>().ok()? };
        (parsed != 0.0 && parsed.is_finite()).then_some(parsed as i64)
    };
    let limit = number("limit");
    let offset = number("offset");

    let empty = || Ok(Reply::Json(json!({"users": [], "total": 0})));
    let mut conditions: Vec<String> = Vec::new();
    let mut binds: Vec<Bind> = Vec::new();
    let add_condition = |field: &str, operator: &str, value: &Value, conditions: &mut Vec<String>, binds: &mut Vec<Bind>| -> bool {
        let Some((column, kind)) = user_field(field) else { return false };
        let placeholder = binds.len() + 1;
        let text = |value: &Value| js_string(value);
        let sql_operator = match operator {
            "eq" => "=",
            "ne" => "<>",
            "lt" => "<",
            "lte" => "<=",
            "gt" => ">",
            "gte" => ">=",
            "contains" | "starts_with" | "ends_with" => "like",
            "in" => "in",
            "not_in" => "not in",
            _ => return false,
        };
        match operator {
            "contains" => binds.push(Bind::Text(format!("%{}%", text(value)))),
            "starts_with" => binds.push(Bind::Text(format!("{}%", text(value)))),
            "ends_with" => binds.push(Bind::Text(format!("%{}", text(value)))),
            "in" | "not_in" => {
                let items = match value {
                    Value::Array(items) => items.iter().map(text).collect(),
                    other => vec![text(other)],
                };
                binds.push(Bind::TextList(items));
                let cast = if kind == 'b' { "::boolean[]" } else if kind == 'd' { "::timestamp[]" } else { "" };
                let negate = if operator == "not_in" { "NOT " } else { "" };
                conditions.push(format!("{negate}{column} = ANY(${placeholder}{cast})"));
                return true;
            }
            _ => {
                if kind == 'b' {
                    binds.push(Bind::Bool(text(value) == "true"));
                } else if value.is_null() && operator == "eq" {
                    conditions.push(format!("{column} IS NULL"));
                    return true;
                } else {
                    binds.push(Bind::Text(text(value)));
                }
            }
        }
        let cast = if kind == 'd' && !matches!(operator, "contains" | "starts_with" | "ends_with") { "::timestamp" } else { "" };
        conditions.push(format!("{column} {sql_operator} ${placeholder}{cast}"));
        true
    };
    if let Some(search) = ctx.query_str("searchValue").filter(|value| !value.is_empty()) {
        let field = ctx.query_str("searchField").unwrap_or("email").to_string();
        let operator = ctx.query_str("searchOperator").unwrap_or("contains").to_string();
        if !add_condition(&field, &operator, &Value::from(search), &mut conditions, &mut binds) {
            return empty();
        }
    }
    if let Some(filter_value) = ctx.query.get("filterValue").cloned() {
        let field = ctx.query_str("filterField").filter(|f| !f.is_empty()).unwrap_or("email").to_string();
        let operator = ctx.query_str("filterOperator").unwrap_or("eq").to_string();
        if !add_condition(&field, &operator, &filter_value, &mut conditions, &mut binds) {
            warn!(field = %field, "list-users filter on an unknown field");
            return empty();
        }
    }
    let where_clause = if conditions.is_empty() { String::new() } else { format!(" WHERE {}", conditions.join(" AND ")) };
    let order = match ctx.query_str("sortBy").filter(|s| !s.is_empty()) {
        Some(field) => match user_field(field) {
            Some((column, _)) => format!(" ORDER BY {column} {}", if ctx.query_str("sortDirection") == Some("desc") { "desc" } else { "asc" }),
            None => return empty(),
        },
        None => String::new(),
    };
    let paging = format!(" LIMIT {}{}", limit.unwrap_or(100), offset.map(|o| format!(" OFFSET {o}")).unwrap_or_default());
    let select_sql = format!(
        r#"SELECT id, name, email, "emailVerified", image, "createdAt", "updatedAt", role, banned, "banReason", "banExpires", "sendAutoEmailReports" FROM "user"{where_clause}{order}{paging}"#
    );
    let count_sql = format!(r#"SELECT count(id) FROM "user"{where_clause}"#);
    fn bind_all<'q>(sql: &'q str, binds: &[Bind]) -> sqlx::query::Query<'q, sqlx::Postgres, sqlx::postgres::PgArguments> {
        let mut query = sqlx::query(sql);
        for bind in binds {
            query = match bind {
                Bind::Text(text) => query.bind(text.clone()),
                Bind::Bool(flag) => query.bind(*flag),
                Bind::TextList(items) => query.bind(items.clone()),
            };
        }
        query
    }
    let rows = match bind_all(&select_sql, &binds).fetch_all(&ctx.state.pg).await {
        Ok(rows) => rows,
        Err(err) => {
            error!(error = %err, "list-users query failed");
            return empty();
        }
    };
    let total: i64 = match bind_all(&count_sql, &binds).fetch_one(&ctx.state.pg).await {
        Ok(row) => sqlx::Row::try_get(&row, 0).unwrap_or(0),
        Err(err) => {
            error!(error = %err, "list-users count failed");
            return empty();
        }
    };
    let mut users = Vec::new();
    for row in &rows {
        let user = db::User {
            id: sqlx::Row::try_get(row, "id")?,
            name: sqlx::Row::try_get(row, "name")?,
            email: sqlx::Row::try_get(row, "email")?,
            email_verified: sqlx::Row::try_get(row, "emailVerified")?,
            image: sqlx::Row::try_get(row, "image")?,
            created_at: sqlx::Row::try_get(row, "createdAt")?,
            updated_at: sqlx::Row::try_get(row, "updatedAt")?,
            role: sqlx::Row::try_get(row, "role")?,
            banned: sqlx::Row::try_get(row, "banned")?,
            ban_reason: sqlx::Row::try_get(row, "banReason")?,
            ban_expires: sqlx::Row::try_get(row, "banExpires")?,
            send_auto_email_reports: sqlx::Row::try_get(row, "sendAutoEmailReports")?,
        };
        users.push(user.to_json());
    }
    let mut body = Map::new();
    body.insert("users".into(), Value::Array(users));
    body.insert("total".into(), Value::from(total));
    if let Some(limit) = limit {
        body.insert("limit".into(), Value::from(limit));
    }
    if let Some(offset) = offset {
        body.insert("offset".into(), Value::from(offset));
    }
    Ok(Reply::Json(Value::Object(body)))
}

/// `POST /admin/list-user-sessions`
async fn list_user_sessions(ctx: &mut Ctx<'_>) -> EndpointResult {
    validate::object(ctx.body.as_ref(), &[required("userId", Ty::CoerceString)], "body", false)?;
    let session = admin_session(ctx).await?;
    if !allowed(&session, "session", "list") {
        return Err(admin_error(StatusCode::FORBIDDEN, "YOU_ARE_NOT_ALLOWED_TO_LIST_USERS_SESSIONS", "You are not allowed to list users sessions"));
    }
    let user_id = coerce_user_id(ctx);
    let sessions = db::list_user_sessions(&ctx.state.pg, &user_id).await?;
    Ok(Reply::Json(json!({"sessions": sessions.iter().map(db::Session::to_json).collect::<Vec<_>>()})))
}

/// `POST /admin/unban-user`
async fn unban_user(ctx: &mut Ctx<'_>) -> EndpointResult {
    validate::object(ctx.body.as_ref(), &[required("userId", Ty::CoerceString)], "body", false)?;
    let session = admin_session(ctx).await?;
    if !allowed(&session, "user", "ban") {
        return Err(admin_error(StatusCode::FORBIDDEN, "YOU_ARE_NOT_ALLOWED_TO_BAN_USERS", "You are not allowed to ban users"));
    }
    let user_id = coerce_user_id(ctx);
    if db::find_user_by_id(&ctx.state.pg, &user_id).await?.is_none() {
        return Err(user_not_found());
    }
    let user = db::update_user(
        &ctx.state.pg,
        &user_id,
        vec![UserField::Banned(Some(false)), UserField::BanExpires(None), UserField::BanReason(None), UserField::UpdatedAt(db::now_ms())],
    )
    .await?
    .ok_or_else(ApiError::internal)?;
    info!(admin_id = %session.user.id, user_id = %user_id, "User unbanned");
    Ok(Reply::Json(json!({"user": user.to_json()})))
}

/// `POST /admin/ban-user`: every session of the user is revoked
async fn ban_user(ctx: &mut Ctx<'_>) -> EndpointResult {
    validate::object(
        ctx.body.as_ref(),
        &[required("userId", Ty::CoerceString), optional("banReason", Ty::String), optional("banExpiresIn", Ty::Number)],
        "body",
        false,
    )?;
    let session = admin_session(ctx).await?;
    if !allowed(&session, "user", "ban") {
        return Err(admin_error(StatusCode::FORBIDDEN, "YOU_ARE_NOT_ALLOWED_TO_BAN_USERS", "You are not allowed to ban users"));
    }
    let user_id = coerce_user_id(ctx);
    if db::find_user_by_id(&ctx.state.pg, &user_id).await?.is_none() {
        return Err(user_not_found());
    }
    if user_id == session.user.id {
        return Err(admin_error(StatusCode::BAD_REQUEST, "YOU_CANNOT_BAN_YOURSELF", "You cannot ban yourself"));
    }
    let reason = ctx.body_str("banReason").filter(|r| !r.is_empty()).unwrap_or("No reason").to_string();
    let mut fields = vec![UserField::Banned(Some(true)), UserField::BanReason(Some(reason))];
    let expires_in = ctx.body_object().and_then(|b| b.get("banExpiresIn")).and_then(Value::as_f64).filter(|n| *n != 0.0);
    if let Some(seconds) = expires_in {
        let millis = chrono::Utc::now().timestamp_millis() as f64 + seconds * 1000.0;
        fields.push(UserField::BanExpires(Some(db::from_epoch_ms(millis.trunc() as i64))));
    }
    fields.push(UserField::UpdatedAt(db::now_ms()));
    let user = db::update_user(&ctx.state.pg, &user_id, fields).await?.ok_or_else(ApiError::internal)?;
    db::delete_user_sessions(&ctx.state.pg, &user_id).await?;
    info!(admin_id = %session.user.id, user_id = %user_id, "User banned");
    Ok(Reply::Json(json!({"user": user.to_json()})))
}

/// `POST /admin/impersonate-user`: a one-hour don't-remember session for the target,
/// the admin's token kept in the signed `admin_session` cookie
async fn impersonate_user(ctx: &mut Ctx<'_>) -> EndpointResult {
    validate::object(ctx.body.as_ref(), &[required("userId", Ty::CoerceString)], "body", false)?;
    let session = admin_session(ctx).await?;
    if !allowed(&session, "user", "impersonate") {
        return Err(admin_error(StatusCode::FORBIDDEN, "YOU_ARE_NOT_ALLOWED_TO_IMPERSONATE_USERS", "You are not allowed to impersonate users"));
    }
    let user_id = coerce_user_id(ctx);
    let target = db::find_user_by_id(&ctx.state.pg, &user_id).await?.ok_or_else(user_not_found)?;
    let target_roles = target.role.clone().filter(|role| !role.is_empty()).unwrap_or_else(|| "user".to_string());
    if target_roles.split(',').any(|role| role == "admin") && !allowed(&session, "user", "impersonate-admins") {
        warn!(admin_id = %session.user.id, target_id = %target.id, "Impersonation of an admin refused");
        return Err(admin_error(StatusCode::FORBIDDEN, "YOU_CANNOT_IMPERSONATE_ADMINS", "You cannot impersonate admins"));
    }
    let mut options = new_session_options(ctx);
    options.dont_remember = true;
    options.impersonated_by = Some(session.user.id.clone());
    options.expires_at = Some(db::in_seconds(3600));
    let created = db::create_session(&ctx.state.pg, &target.id, options)
        .await
        .map_err(|err| if err.status == StatusCode::FORBIDDEN { err } else { ApiError::code(StatusCode::INTERNAL_SERVER_ERROR, "FAILED_TO_CREATE_USER", "Failed to create user") })?;
    ctx.delete_session_cookie(false);
    let production = ctx.production();
    let (dont_remember_name, _) = cookies::dont_remember_cookie(production);
    let dont_remember_value = ctx.verified_cookie(&dont_remember_name).unwrap_or_default();
    let (admin_cookie, _) = cookies::auth_cookie(production, "admin_session");
    let (_, token_attributes) = cookies::session_token_cookie(production);
    ctx.set_signed_cookie(&admin_cookie, &format!("{}:{dont_remember_value}", session.session.token), &token_attributes);
    let pair = SessionWithUser { session: created, user: target.clone() };
    ctx.set_session_cookie(&pair, Some(true), None);
    info!(admin_id = %session.user.id, target_id = %target.id, "Impersonation started");
    Ok(Reply::Json(json!({"session": pair.session.to_json(), "user": target.to_json()})))
}

/// `POST /admin/stop-impersonating`
async fn stop_impersonating(ctx: &mut Ctx<'_>) -> EndpointResult {
    let Some(session) = session_from_ctx(ctx).await else { return Err(ApiError::status(StatusCode::UNAUTHORIZED)) };
    let Some(admin_id) = session.session.impersonated_by.clone().filter(|id| !id.is_empty()) else {
        return Err(ApiError::message(StatusCode::BAD_REQUEST, "You are not impersonating anyone"));
    };
    let Some(admin) = db::find_user_by_id(&ctx.state.pg, &admin_id).await? else {
        return Err(ApiError::message(StatusCode::INTERNAL_SERVER_ERROR, "Failed to find user"));
    };
    let production = ctx.production();
    let (admin_cookie, admin_attributes) = cookies::auth_cookie(production, "admin_session");
    let Some(value) = ctx.verified_cookie(&admin_cookie) else {
        return Err(ApiError::message(StatusCode::INTERNAL_SERVER_ERROR, "Failed to find admin session"));
    };
    let mut parts = value.split(':');
    let admin_token = parts.next().unwrap_or_default().to_string();
    let dont_remember = parts.next().is_some_and(|part| !part.is_empty());
    let admin_session = db::find_session(&ctx.state.pg, &admin_token).await?;
    let Some(admin_session) = admin_session.filter(|found| found.session.user_id == admin.id) else {
        return Err(ApiError::message(StatusCode::INTERNAL_SERVER_ERROR, "Failed to find admin session"));
    };
    db::delete_session(&ctx.state.pg, &session.session.token).await?;
    ctx.set_session_cookie(&admin_session, Some(dont_remember), None);
    ctx.expire_cookie(&admin_cookie, &admin_attributes);
    info!(admin_id = %admin.id, "Impersonation stopped");
    Ok(Reply::Json(json!({"session": admin_session.session.to_json(), "user": admin_session.user.to_json()})))
}

/// `POST /admin/revoke-user-session`
async fn revoke_user_session(ctx: &mut Ctx<'_>) -> EndpointResult {
    validate::object(ctx.body.as_ref(), &[required("sessionToken", Ty::String)], "body", false)?;
    let session = admin_session(ctx).await?;
    if !allowed(&session, "session", "revoke") {
        return Err(admin_error(StatusCode::FORBIDDEN, "YOU_ARE_NOT_ALLOWED_TO_REVOKE_USERS_SESSIONS", "You are not allowed to revoke users sessions"));
    }
    let token = ctx.body_str("sessionToken").unwrap_or_default().to_string();
    db::delete_session(&ctx.state.pg, &token).await?;
    Ok(Reply::Json(json!({"success": true})))
}

/// `POST /admin/revoke-user-sessions`
async fn revoke_user_sessions(ctx: &mut Ctx<'_>) -> EndpointResult {
    validate::object(ctx.body.as_ref(), &[required("userId", Ty::CoerceString)], "body", false)?;
    let session = admin_session(ctx).await?;
    if !allowed(&session, "session", "revoke") {
        return Err(admin_error(StatusCode::FORBIDDEN, "YOU_ARE_NOT_ALLOWED_TO_REVOKE_USERS_SESSIONS", "You are not allowed to revoke users sessions"));
    }
    let user_id = coerce_user_id(ctx);
    db::delete_user_sessions(&ctx.state.pg, &user_id).await?;
    Ok(Reply::Json(json!({"success": true})))
}

/// `POST /admin/has-permission`
async fn has_permission_endpoint(ctx: &mut Ctx<'_>) -> EndpointResult {
    validate::object_and_permission_xor(ctx.body.as_ref(), &[optional("userId", Ty::CoerceString), optional("role", Ty::String)])?;
    let permissions = ctx.body_object().and_then(|b| b.get("permissions")).and_then(Value::as_object).cloned();
    if !truthy(ctx.body_object().and_then(|b| b.get("permissions"))) {
        return Err(ApiError::message(StatusCode::BAD_REQUEST, "invalid permission check. no permission(s) were passed."));
    }
    let Some(session) = authoritative_session(ctx).await else {
        return Err(ApiError::status(StatusCode::UNAUTHORIZED));
    };
    let success = has_permission(session.user.role.as_deref(), permissions.as_ref());
    Ok(Reply::Json(json!({"error": null, "success": success})))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(value: Value) -> Map<String, Value> {
        value.as_object().unwrap().clone()
    }

    #[test]
    fn admin_roles() {
        assert!(has_permission(Some("admin"), Some(&request(json!({"user": ["impersonate"]})))));
        assert!(!has_permission(Some("admin"), Some(&request(json!({"user": ["impersonate-admins"]})))));
        assert!(!has_permission(Some("user"), Some(&request(json!({"user": ["list"]})))));
        assert!(!has_permission(None, Some(&request(json!({"user": ["list"]})))));
        assert!(has_permission(Some("user,admin"), Some(&request(json!({"session": ["revoke"]})))));
        assert!(!has_permission(Some("admin"), None));
    }
}
