//! The rows Better Auth reads and writes, through the same statements its Kysely
//! adapter issues (`createWithHooks`, `updateWithHooks`, ...), and their JSON
//! output in Better Auth's field order (schema fields, plugin fields, additional
//! fields, then `id`).
//!
//! Timestamps: Node runs with TZ=UTC and stores JS Dates, so every column holds
//! naive UTC with millisecond precision; reads truncate to milliseconds like a
//! revived JS Date.

use chrono::{DateTime, Duration, NaiveDateTime, SubsecRound, Utc};
use serde_json::{Map, Value};
use sqlx::{PgPool, Row, postgres::PgRow};
use tracing::{debug, info};

use super::{
    context::ApiError,
    crypto::generate_id,
};

/// `new Date()` as Node stores it
pub fn now_ms() -> NaiveDateTime {
    Utc::now().trunc_subsecs(3).naive_utc()
}

/// `new Date(Date.now() + seconds * 1000)`
pub fn in_seconds(seconds: i64) -> NaiveDateTime {
    (Utc::now() + Duration::seconds(seconds)).trunc_subsecs(3).naive_utc()
}

/// `Date.prototype.toISOString`
pub fn iso(value: NaiveDateTime) -> String {
    value.and_utc().trunc_subsecs(3).format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()
}

pub fn iso_opt(value: Option<NaiveDateTime>) -> Value {
    value.map_or(Value::Null, |value| Value::String(iso(value)))
}

pub fn ms(value: NaiveDateTime) -> NaiveDateTime {
    value.trunc_subsecs(3)
}

pub fn epoch_ms(value: NaiveDateTime) -> i64 {
    value.and_utc().timestamp_millis()
}

pub fn from_epoch_ms(millis: i64) -> NaiveDateTime {
    DateTime::from_timestamp_millis(millis).unwrap_or_default().naive_utc()
}

/// `value < new Date()`
pub fn is_past(value: NaiveDateTime) -> bool {
    ms(value) < now_ms()
}

// ---------------------------------------------------------------------------
// user

#[derive(Clone, Debug)]
pub struct User {
    pub id: String,
    pub name: String,
    pub email: String,
    pub email_verified: bool,
    pub image: Option<String>,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
    pub role: Option<String>,
    pub banned: Option<bool>,
    pub ban_reason: Option<String>,
    pub ban_expires: Option<NaiveDateTime>,
    pub send_auto_email_reports: Option<bool>,
}

const USER_COLUMNS: &str = r#"id, name, email, "emailVerified", image, "createdAt", "updatedAt", role, banned, "banReason", "banExpires", "sendAutoEmailReports""#;

impl User {
    fn from_row(row: &PgRow) -> Result<Self, sqlx::Error> {
        Ok(Self {
            id: row.try_get("id")?,
            name: row.try_get("name")?,
            email: row.try_get("email")?,
            email_verified: row.try_get("emailVerified")?,
            image: row.try_get("image")?,
            created_at: row.try_get("createdAt")?,
            updated_at: row.try_get("updatedAt")?,
            role: row.try_get("role")?,
            banned: row.try_get("banned")?,
            ban_reason: row.try_get("banReason")?,
            ban_expires: row.try_get("banExpires")?,
            send_auto_email_reports: row.try_get("sendAutoEmailReports")?,
        })
    }

    /// `parseUserOutput`
    pub fn to_json(&self) -> Value {
        let mut map = Map::new();
        map.insert("name".into(), Value::from(self.name.clone()));
        map.insert("email".into(), Value::from(self.email.clone()));
        map.insert("emailVerified".into(), Value::from(self.email_verified));
        map.insert("image".into(), self.image.clone().map_or(Value::Null, Value::from));
        map.insert("createdAt".into(), Value::from(iso(self.created_at)));
        map.insert("updatedAt".into(), Value::from(iso(self.updated_at)));
        map.insert("role".into(), self.role.clone().map_or(Value::Null, Value::from));
        map.insert("banned".into(), self.banned.map_or(Value::Null, Value::from));
        map.insert("banReason".into(), self.ban_reason.clone().map_or(Value::Null, Value::from));
        map.insert("banExpires".into(), iso_opt(self.ban_expires));
        map.insert("sendAutoEmailReports".into(), self.send_auto_email_reports.map_or(Value::Null, Value::from));
        map.insert("id".into(), Value::from(self.id.clone()));
        Value::Object(map)
    }
}

pub async fn find_user_by_id(pg: &PgPool, id: &str) -> Result<Option<User>, sqlx::Error> {
    let row = sqlx::query(&format!(r#"SELECT {USER_COLUMNS} FROM "user" WHERE id = $1"#)).bind(id).fetch_optional(pg).await?;
    row.as_ref().map(User::from_row).transpose()
}

/// `findUserByEmail`: the address is lowercased before the lookup
pub async fn find_user_by_email(pg: &PgPool, email: &str) -> Result<Option<User>, sqlx::Error> {
    let row = sqlx::query(&format!(r#"SELECT {USER_COLUMNS} FROM "user" WHERE email = $1"#))
        .bind(js_lowercase(email))
        .fetch_optional(pg)
        .await?;
    row.as_ref().map(User::from_row).transpose()
}

/// JavaScript `toLowerCase` (Unicode aware, like Rust's)
pub fn js_lowercase(text: &str) -> String {
    text.to_lowercase()
}

/// A field `updateUser` may write, with its SQL binding.
#[derive(Clone, Debug)]
pub enum UserField {
    Name(String),
    Email(String),
    EmailVerified(bool),
    Image(Option<String>),
    Role(Option<String>),
    Banned(Option<bool>),
    BanReason(Option<String>),
    BanExpires(Option<NaiveDateTime>),
    SendAutoEmailReports(Option<bool>),
    UpdatedAt(NaiveDateTime),
}

impl UserField {
    fn column(&self) -> &'static str {
        match self {
            UserField::Name(_) => "name",
            UserField::Email(_) => "email",
            UserField::EmailVerified(_) => r#""emailVerified""#,
            UserField::Image(_) => "image",
            UserField::Role(_) => "role",
            UserField::Banned(_) => "banned",
            UserField::BanReason(_) => r#""banReason""#,
            UserField::BanExpires(_) => r#""banExpires""#,
            UserField::SendAutoEmailReports(_) => r#""sendAutoEmailReports""#,
            UserField::UpdatedAt(_) => r#""updatedAt""#,
        }
    }
}

enum Where<'a> {
    Id(&'a str),
    Email(&'a str),
}

/// `internalAdapter.updateUser` / `updateUserByEmail`: `UPDATE ... RETURNING *` with
/// `updatedAt` stamped unless given (the schema's `onUpdate`). The auth.ts
/// `user.update.before` hook returns the data unchanged, so `role` is written too.
async fn update_user_where(pg: &PgPool, target: Where<'_>, mut fields: Vec<UserField>) -> Result<Option<User>, sqlx::Error> {
    if !fields.iter().any(|field| matches!(field, UserField::UpdatedAt(_))) {
        fields.push(UserField::UpdatedAt(now_ms()));
    }
    let assignments: Vec<String> =
        fields.iter().enumerate().map(|(index, field)| format!("{} = ${}", field.column(), index + 1)).collect();
    let (column, value) = match target {
        Where::Id(id) => ("id", id.to_string()),
        Where::Email(email) => ("email", js_lowercase(email)),
    };
    let sql = format!(
        r#"UPDATE "user" SET {} WHERE {column} = ${} RETURNING {USER_COLUMNS}"#,
        assignments.join(", "),
        fields.len() + 1
    );
    let mut query = sqlx::query(&sql);
    for field in fields {
        query = match field {
            UserField::Name(value) => query.bind(value),
            UserField::Email(value) => query.bind(js_lowercase(&value)),
            UserField::EmailVerified(value) => query.bind(value),
            UserField::Image(value) => query.bind(value),
            UserField::Role(value) => query.bind(value),
            UserField::Banned(value) => query.bind(value),
            UserField::BanReason(value) => query.bind(value),
            UserField::BanExpires(value) => query.bind(value),
            UserField::SendAutoEmailReports(value) => query.bind(value),
            UserField::UpdatedAt(value) => query.bind(value),
        };
    }
    let row = query.bind(value).fetch_optional(pg).await?;
    row.as_ref().map(User::from_row).transpose()
}

pub async fn update_user(pg: &PgPool, user_id: &str, fields: Vec<UserField>) -> Result<Option<User>, sqlx::Error> {
    update_user_where(pg, Where::Id(user_id), fields).await
}

pub async fn update_user_by_email(pg: &PgPool, email: &str, fields: Vec<UserField>) -> Result<Option<User>, sqlx::Error> {
    update_user_where(pg, Where::Email(email), fields).await
}

/// `internalAdapter.deleteUser`: sessions, accounts, then the user row
pub async fn delete_user(pg: &PgPool, user_id: &str) -> Result<(), sqlx::Error> {
    sqlx::query(r#"DELETE FROM session WHERE "userId" = $1"#).bind(user_id).execute(pg).await?;
    sqlx::query(r#"DELETE FROM account WHERE "userId" = $1"#).bind(user_id).execute(pg).await?;
    sqlx::query(r#"DELETE FROM "user" WHERE id = $1"#).bind(user_id).execute(pg).await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// session

#[derive(Clone, Debug)]
pub struct Session {
    pub id: String,
    pub expires_at: NaiveDateTime,
    pub token: String,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub user_id: String,
    pub impersonated_by: Option<String>,
    pub active_organization_id: Option<String>,
    pub active_team_id: Option<String>,
}

const SESSION_COLUMNS: &str = r#"id, "expiresAt", token, "createdAt", "updatedAt", "ipAddress", "userAgent", "userId", "impersonatedBy", "activeOrganizationId", "activeTeamId""#;

impl Session {
    fn from_row(row: &PgRow) -> Result<Self, sqlx::Error> {
        Ok(Self {
            id: row.try_get("id")?,
            expires_at: row.try_get("expiresAt")?,
            token: row.try_get("token")?,
            created_at: row.try_get("createdAt")?,
            updated_at: row.try_get("updatedAt")?,
            ip_address: row.try_get("ipAddress")?,
            user_agent: row.try_get("userAgent")?,
            user_id: row.try_get("userId")?,
            impersonated_by: row.try_get("impersonatedBy")?,
            active_organization_id: row.try_get("activeOrganizationId")?,
            active_team_id: row.try_get("activeTeamId")?,
        })
    }

    /// `parseSessionOutput`
    pub fn to_json(&self) -> Value {
        let mut map = Map::new();
        map.insert("expiresAt".into(), Value::from(iso(self.expires_at)));
        map.insert("token".into(), Value::from(self.token.clone()));
        map.insert("createdAt".into(), Value::from(iso(self.created_at)));
        map.insert("updatedAt".into(), Value::from(iso(self.updated_at)));
        map.insert("ipAddress".into(), self.ip_address.clone().map_or(Value::Null, Value::from));
        map.insert("userAgent".into(), self.user_agent.clone().map_or(Value::Null, Value::from));
        map.insert("userId".into(), Value::from(self.user_id.clone()));
        map.insert("impersonatedBy".into(), self.impersonated_by.clone().map_or(Value::Null, Value::from));
        map.insert("activeOrganizationId".into(), self.active_organization_id.clone().map_or(Value::Null, Value::from));
        map.insert("activeTeamId".into(), self.active_team_id.clone().map_or(Value::Null, Value::from));
        map.insert("id".into(), Value::from(self.id.clone()));
        Value::Object(map)
    }
}

#[derive(Clone, Debug)]
pub struct SessionWithUser {
    pub session: Session,
    pub user: User,
}

impl SessionWithUser {
    pub fn to_json(&self) -> Value {
        let mut map = Map::new();
        map.insert("session".into(), self.session.to_json());
        map.insert("user".into(), self.user.to_json());
        Value::Object(map)
    }
}

/// `internalAdapter.findSession(token)`: the session row and its user, or None
/// when either is missing.
pub async fn find_session(pg: &PgPool, token: &str) -> Result<Option<SessionWithUser>, sqlx::Error> {
    let Some(row) = sqlx::query(&format!("SELECT {SESSION_COLUMNS} FROM session WHERE token = $1"))
        .bind(token)
        .fetch_optional(pg)
        .await?
    else {
        return Ok(None);
    };
    let session = Session::from_row(&row)?;
    let Some(user) = find_user_by_id(pg, &session.user_id).await? else {
        return Ok(None);
    };
    Ok(Some(SessionWithUser { session, user }))
}

pub async fn list_user_sessions(pg: &PgPool, user_id: &str) -> Result<Vec<Session>, sqlx::Error> {
    let rows = sqlx::query(&format!(r#"SELECT {SESSION_COLUMNS} FROM session WHERE "userId" = $1 LIMIT 100"#))
        .bind(user_id)
        .fetch_all(pg)
        .await?;
    rows.iter().map(Session::from_row).collect()
}

/// Options for `internalAdapter.createSession`.
#[derive(Clone, Debug, Default)]
pub struct NewSession {
    pub dont_remember: bool,
    pub impersonated_by: Option<String>,
    /// Overrides the computed expiry (impersonation sessions last an hour)
    pub expires_at: Option<NaiveDateTime>,
    pub ip_address: String,
    pub user_agent: String,
}

/// `internalAdapter.createSession` with the database hooks this app registers:
/// the admin plugin's `session.create.before` refuses banned users (lifting an
/// expired ban first). `expiresAt` is 7 days, or 1 day for don't-remember sessions.
pub async fn create_session(pg: &PgPool, user_id: &str, options: NewSession) -> Result<Session, ApiError> {
    if let Some(user) = find_user_by_id(pg, user_id).await?
        && user.banned == Some(true)
    {
        if let Some(expires) = user.ban_expires
            && epoch_ms(ms(expires)) < Utc::now().timestamp_millis()
        {
            update_user(pg, user_id, vec![UserField::Banned(Some(false)), UserField::BanReason(None), UserField::BanExpires(None)]).await?;
            info!(user_id = %user_id, "Expired ban lifted at session creation");
        } else {
            info!(user_id = %user_id, "Session refused for banned user");
            return Err(ApiError::code(
                axum::http::StatusCode::FORBIDDEN,
                "BANNED_USER",
                "You have been banned from this application. Please contact support if you believe this is an error.",
            ));
        }
    }

    let now = now_ms();
    let expires_at = options.expires_at.unwrap_or_else(|| {
        if options.dont_remember { in_seconds(86_400) } else { in_seconds(super::SESSION_EXPIRES_IN) }
    });
    let id = generate_id();
    let token = generate_id();
    let row = sqlx::query(&format!(
        r#"INSERT INTO session (id, "expiresAt", token, "createdAt", "updatedAt", "ipAddress", "userAgent", "userId", "impersonatedBy")
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING {SESSION_COLUMNS}"#
    ))
    .bind(&id)
    .bind(expires_at)
    .bind(&token)
    .bind(now)
    .bind(now)
    .bind(&options.ip_address)
    .bind(&options.user_agent)
    .bind(user_id)
    .bind(&options.impersonated_by)
    .fetch_one(pg)
    .await?;
    debug!(user_id = %user_id, impersonated = options.impersonated_by.is_some(), "Session created");
    Ok(Session::from_row(&row)?)
}

/// A session column `updateSession` may write.
pub enum SessionField {
    ExpiresAt(NaiveDateTime),
    ActiveOrganizationId(Option<String>),
    ActiveTeamId(Option<String>),
}

/// `internalAdapter.updateSession(token, data)` with the `updatedAt` stamp
pub async fn update_session(pg: &PgPool, token: &str, field: SessionField) -> Result<Option<Session>, sqlx::Error> {
    let column = match &field {
        SessionField::ExpiresAt(_) => r#""expiresAt""#,
        SessionField::ActiveOrganizationId(_) => r#""activeOrganizationId""#,
        SessionField::ActiveTeamId(_) => r#""activeTeamId""#,
    };
    let sql = format!(r#"UPDATE session SET {column} = $1, "updatedAt" = $2 WHERE token = $3 RETURNING {SESSION_COLUMNS}"#);
    let query = match field {
        SessionField::ExpiresAt(value) => sqlx::query(&sql).bind(value),
        SessionField::ActiveOrganizationId(value) | SessionField::ActiveTeamId(value) => sqlx::query(&sql).bind(value),
    };
    let row = query.bind(now_ms()).bind(token).fetch_optional(pg).await?;
    row.as_ref().map(Session::from_row).transpose()
}

pub async fn delete_session(pg: &PgPool, token: &str) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM session WHERE token = $1").bind(token).execute(pg).await?;
    Ok(())
}

pub async fn delete_user_sessions(pg: &PgPool, user_id: &str) -> Result<(), sqlx::Error> {
    sqlx::query(r#"DELETE FROM session WHERE "userId" = $1"#).bind(user_id).execute(pg).await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// account

#[derive(Clone, Debug)]
pub struct Account {
    pub id: String,
    pub provider_id: String,
    pub user_id: String,
    pub password: Option<String>,
}

/// `internalAdapter.findAccounts(userId)` (the fallback join's 100-row limit)
pub async fn find_accounts(pg: &PgPool, user_id: &str) -> Result<Vec<Account>, sqlx::Error> {
    let rows = sqlx::query(r#"SELECT id, "providerId", "userId", password FROM account WHERE "userId" = $1 LIMIT 100"#)
        .bind(user_id)
        .fetch_all(pg)
        .await?;
    rows.iter()
        .map(|row| {
            Ok(Account {
                id: row.try_get("id")?,
                provider_id: row.try_get("providerId")?,
                user_id: row.try_get("userId")?,
                password: row.try_get("password")?,
            })
        })
        .collect()
}

/// `internalAdapter.linkAccount` / `createAccount` for a credential account
pub async fn create_credential_account(pg: &PgPool, user_id: &str, password_hash: &str) -> Result<(), sqlx::Error> {
    let now = now_ms();
    sqlx::query(
        r#"INSERT INTO account (id, "accountId", "providerId", "userId", password, "createdAt", "updatedAt")
           VALUES ($1, $2, 'credential', $3, $4, $5, $6)"#,
    )
    .bind(generate_id())
    .bind(user_id)
    .bind(user_id)
    .bind(password_hash)
    .bind(now)
    .bind(now)
    .execute(pg)
    .await?;
    Ok(())
}

/// `internalAdapter.updateAccount(id, { password })`
pub async fn update_account_password(pg: &PgPool, account_id: &str, password_hash: &str) -> Result<(), sqlx::Error> {
    sqlx::query(r#"UPDATE account SET password = $1, "updatedAt" = $2 WHERE id = $3"#)
        .bind(password_hash)
        .bind(now_ms())
        .bind(account_id)
        .execute(pg)
        .await?;
    Ok(())
}

/// `internalAdapter.updatePassword(userId, hash)`: every credential account of the user
pub async fn update_credential_passwords(pg: &PgPool, user_id: &str, password_hash: &str) -> Result<(), sqlx::Error> {
    sqlx::query(r#"UPDATE account SET password = $1, "updatedAt" = $2 WHERE "userId" = $3 AND "providerId" = 'credential'"#)
        .bind(password_hash)
        .bind(now_ms())
        .bind(user_id)
        .execute(pg)
        .await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// verification

#[derive(Clone, Debug)]
pub struct Verification {
    pub id: String,
    pub identifier: String,
    pub value: String,
    pub expires_at: NaiveDateTime,
}

impl Verification {
    fn from_row(row: &PgRow) -> Result<Self, sqlx::Error> {
        Ok(Self {
            id: row.try_get("id")?,
            identifier: row.try_get("identifier")?,
            value: row.try_get("value")?,
            expires_at: row.try_get("expiresAt")?,
        })
    }
}

/// `internalAdapter.createVerificationValue`
pub async fn create_verification(pg: &PgPool, identifier: &str, value: &str, expires_at: NaiveDateTime) -> Result<(), sqlx::Error> {
    let now = now_ms();
    sqlx::query(
        r#"INSERT INTO verification (id, identifier, value, "expiresAt", "createdAt", "updatedAt") VALUES ($1, $2, $3, $4, $5, $6)"#,
    )
    .bind(generate_id())
    .bind(identifier)
    .bind(value)
    .bind(expires_at)
    .bind(now)
    .bind(now)
    .execute(pg)
    .await?;
    Ok(())
}

/// `internalAdapter.findVerificationValue`: the newest row for the identifier, after
/// which every expired verification row in the table is deleted.
pub async fn find_verification(pg: &PgPool, identifier: &str) -> Result<Option<Verification>, sqlx::Error> {
    let row = sqlx::query(
        r#"SELECT id, identifier, value, "expiresAt" FROM verification WHERE identifier = $1 ORDER BY "createdAt" DESC LIMIT 1"#,
    )
    .bind(identifier)
    .fetch_optional(pg)
    .await?;
    sqlx::query(r#"DELETE FROM verification WHERE "expiresAt" < $1"#).bind(now_ms()).execute(pg).await?;
    row.as_ref().map(Verification::from_row).transpose()
}

/// `internalAdapter.consumeVerificationValue`: atomically take the newest row for
/// the identifier and delete every row for it. Expired rows are consumed but
/// reported as None.
pub async fn consume_verification(pg: &PgPool, identifier: &str) -> Result<Option<Verification>, sqlx::Error> {
    let mut tx = pg.begin().await?;
    let latest: Option<String> =
        sqlx::query_scalar(r#"SELECT id FROM verification WHERE identifier = $1 ORDER BY "createdAt" DESC LIMIT 1"#)
            .bind(identifier)
            .fetch_optional(&mut *tx)
            .await?;
    let Some(latest) = latest else {
        tx.commit().await?;
        return Ok(None);
    };
    let row = sqlx::query(
        r#"DELETE FROM verification WHERE id IN (SELECT id FROM verification WHERE id = $1 LIMIT 1) RETURNING id, identifier, value, "expiresAt""#,
    )
    .bind(&latest)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(row) = row else {
        tx.commit().await?;
        return Ok(None);
    };
    sqlx::query("DELETE FROM verification WHERE identifier = $1").bind(identifier).execute(&mut *tx).await?;
    tx.commit().await?;
    let consumed = Verification::from_row(&row)?;
    if is_past(consumed.expires_at) {
        return Ok(None);
    }
    Ok(Some(consumed))
}

/// `internalAdapter.deleteVerificationByIdentifier`
pub async fn delete_verification(pg: &PgPool, identifier: &str) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM verification WHERE identifier = $1").bind(identifier).execute(pg).await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// JSON helpers shared by the plugin rows

pub fn opt_str(value: Option<String>) -> Value {
    value.map_or(Value::Null, Value::from)
}

pub fn get_opt<T>(row: &PgRow, column: &str) -> Result<Option<T>, sqlx::Error>
where
    T: for<'r> sqlx::Decode<'r, sqlx::Postgres> + sqlx::Type<sqlx::Postgres>,
{
    row.try_get(column)
}
