//! API key creation and the organization's API usage, ported from
//! server/src/api/user/createApiKey.ts, createOrgApiKey.ts and getOrgApiUsage.ts,
//! together with the pieces they call: `lib/apiKeyLimits.ts`, the parts of
//! `lib/apiRateLimit.ts` the usage route reads, and Better Auth's
//! `auth.api.createApiKey` (@better-auth/api-key 1.6.25, `/api-key/create` called
//! server side) with auth.ts's two key configurations.
//!
//! No billing here, so `IS_CLOUD` is false throughout: the plan gate never runs, the
//! key cap is the flat self-hosted one and API requests are not metered.

use axum::{
    body::Body,
    extract::State,
    http::{HeaderMap, Method, StatusCode, Uri},
    response::Response,
};
use chrono::NaiveDateTime;
use serde_json::{Map, json};
use sqlx::PgPool;
use tracing::{debug, error, info};

use super::{
    chain,
    request::{self, object},
    zod,
};
use crate::{
    analytics::{
        chain::{org_scoped, route_scope},
        js::{JsObject, JsValue, json as js, number::number_to_string},
        utils::time_window::now_ms,
    },
    auth::{
        bearer::ORG_API_KEY_CONFIG_ID,
        endpoints::{api_key as auth_api_key, crypto, db as auth_db, organization},
    },
    state::AppState,
};

/// `SELF_HOSTED_API_KEY_LIMIT` in server/src/lib/const.ts. `apiKeyLimitForPlan`
/// returns it for every caller when `CLOUD` is unset.
const SELF_HOSTED_API_KEY_LIMIT: i64 = 50;

/// `API_BURST_LIMIT` and `API_BURST_WINDOW_MS`
const API_BURST_LIMIT: f64 = 50.0;
const API_BURST_WINDOW_MS: f64 = 10_000.0;

const MS_PER_DAY: f64 = 86_400_000.0;

/// The plugin's defaults for both configurations in auth.ts (`rateLimit.enabled`
/// is false, everything else is the plugin default).
const DEFAULT_KEY_LENGTH: usize = 64;
const RATE_LIMIT_TIME_WINDOW: i32 = 86_400_000;
const RATE_LIMIT_MAX: i32 = 10;
const STARTING_CHARACTERS: usize = 6;
const MIN_NAME_LENGTH: usize = 1;
const MAX_NAME_LENGTH: usize = 32;
const MIN_EXPIRES_IN_DAYS: f64 = 1.0;
const MAX_EXPIRES_IN_DAYS: f64 = 365.0;
/// `defaultPrefix` of the organization configuration
const ORG_KEY_PREFIX: &str = "rb_org_";

/// A Better Auth `APIError` the Fastify routes surface as `{error: message}`.
struct ApiKeyError {
    status: StatusCode,
    message: &'static str,
}

/// `API_KEY_ERROR_CODES`
mod codes {
    pub const EXPIRES_IN_IS_TOO_SMALL: &str = "The expiresIn is smaller than the predefined minimum value.";
    pub const EXPIRES_IN_IS_TOO_LARGE: &str = "The expiresIn is larger than the predefined maximum value.";
    pub const INVALID_NAME_LENGTH: &str = "The name length is either too large or too small.";
    pub const USER_NOT_MEMBER_OF_ORGANIZATION: &str =
        "You are not a member of the organization that owns this API key.";
    pub const INSUFFICIENT_API_KEY_PERMISSIONS: &str =
        "You do not have permission to perform this action on organization API keys.";
}

/// What a created key answers with, plus what has to be written.
struct NewKey {
    id: String,
    config_id: &'static str,
    name: String,
    start: String,
    reference_id: String,
    prefix: Option<&'static str>,
    key: String,
    hashed: String,
    expires_at: Option<NaiveDateTime>,
    created_at: NaiveDateTime,
    permissions_text: Option<String>,
    permissions: Option<JsObject>,
    metadata: Option<JsValue>,
}

impl NewKey {
    /// `ctx.json({ ...apiKey, key, metadata, permissions })`: the adapter's output
    /// order (the plugin's schema fields, then `id`), with `key`, `metadata` and
    /// `permissions` replaced in place.
    fn to_json(&self) -> JsValue {
        object(vec![
            ("configId", self.config_id.into()),
            ("name", self.name.clone().into()),
            ("start", self.start.clone().into()),
            ("referenceId", self.reference_id.clone().into()),
            ("prefix", self.prefix.map_or(JsValue::Null, JsValue::from)),
            ("key", self.key.clone().into()),
            ("refillInterval", JsValue::Null),
            ("refillAmount", JsValue::Null),
            ("lastRefillAt", JsValue::Null),
            ("enabled", JsValue::Bool(true)),
            ("rateLimitEnabled", JsValue::Bool(false)),
            ("rateLimitTimeWindow", JsValue::Number(f64::from(RATE_LIMIT_TIME_WINDOW))),
            ("rateLimitMax", JsValue::Number(f64::from(RATE_LIMIT_MAX))),
            ("requestCount", JsValue::Number(0.0)),
            ("remaining", JsValue::Null),
            ("lastRequest", JsValue::Null),
            ("expiresAt", self.expires_at.map_or(JsValue::Null, |at| JsValue::String(auth_db::iso(at)))),
            ("createdAt", auth_db::iso(self.created_at).into()),
            ("updatedAt", auth_db::iso(self.created_at).into()),
            ("permissions", self.permissions.clone().map_or(JsValue::Null, JsValue::Object)),
            ("metadata", self.metadata.clone().unwrap_or(JsValue::Null)),
            ("id", self.id.clone().into()),
        ])
    }
}

/// `keyGenerator({ length, prefix })` and `defaultKeyHasher`.
fn generate_key(prefix: Option<&str>) -> (String, String) {
    let body = crypto::random_string(DEFAULT_KEY_LENGTH, &[crypto::LOWER, crypto::UPPER]);
    let key = format!("{}{body}", prefix.unwrap_or_default());
    let hashed = crate::auth::bearer::hash_api_key(&key);
    (key, hashed)
}

/// `key.substring(0, 6)` in UTF-16 units; the generated alphabet is ASCII.
fn starting_characters(key: &str) -> String {
    key.chars().take(STARTING_CHARACTERS).collect()
}

/// The plugin's validation of `expiresIn` and `name`, in its order.
fn validate_key_input(name: &str, expires_in: Option<f64>) -> Result<(), ApiKeyError> {
    if let Some(expires_in) = expires_in.filter(|seconds| *seconds != 0.0 && !seconds.is_nan()) {
        let days = expires_in / (3600.0 * 24.0);
        if MIN_EXPIRES_IN_DAYS > days {
            return Err(ApiKeyError { status: StatusCode::BAD_REQUEST, message: codes::EXPIRES_IN_IS_TOO_SMALL });
        }
        if MAX_EXPIRES_IN_DAYS < days {
            return Err(ApiKeyError { status: StatusCode::BAD_REQUEST, message: codes::EXPIRES_IN_IS_TOO_LARGE });
        }
    }
    let length = crate::analytics::js::string::utf16_len(name);
    if !(MIN_NAME_LENGTH..=MAX_NAME_LENGTH).contains(&length) {
        return Err(ApiKeyError { status: StatusCode::BAD_REQUEST, message: codes::INVALID_NAME_LENGTH });
    }
    Ok(())
}

/// `countApiKeysForReference`: enabled keys that have not expired. Expired and
/// disabled keys linger until the plugin's lazy purge and do not hold a slot.
async fn count_keys_for_reference(
    executor: &mut sqlx::PgConnection,
    reference_id: &str,
    now: NaiveDateTime,
) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar(
        r#"select count(*) from "apikey"
           where ("referenceId" = $1 and "enabled" = true and ("expiresAt" is null or "expiresAt" > $2))"#,
    )
    .bind(reference_id)
    .bind(now)
    .fetch_one(executor)
    .await
}

/// `createApiKeyWithinLimit(referenceId, limit, create)`: the check and the insert
/// are serialised per owner with a transaction advisory lock, so concurrent
/// requests cannot overshoot the cap. The insert runs on its own connection (as
/// better-auth's pool does in Node) and commits before the lock is released.
async fn create_within_limit(pg: &PgPool, key: &NewKey, limit: i64) -> Result<bool, sqlx::Error> {
    let mut tx = pg.begin().await?;
    sqlx::query("select pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(&key.reference_id)
        .execute(&mut *tx)
        .await?;
    let held = count_keys_for_reference(&mut tx, &key.reference_id, key.created_at).await?;
    if held >= limit {
        tx.commit().await?;
        debug!(reference_id = %key.reference_id, held, limit, "API key limit reached");
        return Ok(false);
    }
    insert_key(pg, key).await?;
    tx.commit().await?;
    Ok(true)
}

/// `ctx.context.adapter.create({ model: "apikey", data })`
async fn insert_key(pg: &PgPool, key: &NewKey) -> Result<(), sqlx::Error> {
    let metadata_text = key.metadata.as_ref().map(|value| js::stringify(value).unwrap_or_default());
    sqlx::query(
        r#"insert into apikey ("configId", "createdAt", "updatedAt", name, prefix, start, key, enabled,
                               "expiresAt", "referenceId", "lastRefillAt", "lastRequest", metadata,
                               "rateLimitMax", "rateLimitTimeWindow", remaining, "refillAmount",
                               "refillInterval", "rateLimitEnabled", "requestCount", permissions, id)
           values ($1, $2, $2, $3, $4, $5, $6, true, $7, $8, null, null, $9::jsonb,
                   $10, $11, null, null, null, false, 0, $12, $13)"#,
    )
    .bind(key.config_id)
    .bind(key.created_at)
    .bind(&key.name)
    .bind(key.prefix)
    .bind(&key.start)
    .bind(&key.hashed)
    .bind(key.expires_at)
    .bind(&key.reference_id)
    .bind(metadata_text)
    .bind(RATE_LIMIT_MAX)
    .bind(RATE_LIMIT_TIME_WINDOW)
    .bind(&key.permissions_text)
    .bind(&key.id)
    .execute(pg)
    .await?;
    Ok(())
}

/// Everything both routes share once the caller and the owner are known.
async fn mint_key(
    state: &AppState,
    config_id: &'static str,
    reference_id: String,
    body: zod::ApiKeyBody,
    metadata: Option<JsValue>,
) -> Result<Response, ApiKeyError> {
    validate_key_input(&body.name, body.expires_in)?;
    auth_api_key::sweep_expired_keys(&state.pg);

    let prefix = (config_id == ORG_API_KEY_CONFIG_ID).then_some(ORG_KEY_PREFIX);
    let (key, hashed) = generate_key(prefix);
    let created_at = auth_db::now_ms();
    let expires_at = body
        .expires_in
        .filter(|seconds| *seconds != 0.0 && !seconds.is_nan())
        .map(|seconds| auth_db::from_epoch_ms((auth_db::epoch_ms(created_at) as f64 + seconds * 1000.0) as i64));
    let permissions_text = body.permissions.as_ref().map(|value| js::stringify(&JsValue::Object(value.clone())).unwrap_or_default());

    let new_key = NewKey {
        id: crypto::generate_id(),
        config_id,
        start: starting_characters(&key),
        name: body.name,
        reference_id,
        prefix,
        key,
        hashed,
        expires_at,
        created_at,
        permissions_text,
        permissions: body.permissions,
        metadata,
    };

    match create_within_limit(&state.pg, &new_key, SELF_HOSTED_API_KEY_LIMIT).await {
        Ok(true) => {
            info!(key_id = %new_key.id, config = config_id, "API key created");
            Ok(request::send(StatusCode::OK, &new_key.to_json()))
        }
        Ok(false) => Ok(limit_reached(config_id)),
        Err(err) => {
            error!(error = %err, "Error creating API key");
            Ok(request::error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to create API key"))
        }
    }
}

/// The two wordings of the cap rejection.
fn limit_reached(config_id: &str) -> Response {
    let message = if config_id == ORG_API_KEY_CONFIG_ID {
        format!(
            "This organization has reached its limit of {} API keys. Delete an unused key or upgrade your plan.",
            number_to_string(SELF_HOSTED_API_KEY_LIMIT as f64)
        )
    } else {
        format!(
            "You have reached your limit of {} API keys. Delete an unused key or upgrade your plan.",
            number_to_string(SELF_HOSTED_API_KEY_LIMIT as f64)
        )
    };
    request::error(StatusCode::FORBIDDEN, &message)
}

// ---------------------------------------------------------------------------
// POST /api/user/api-keys

/// `createUserApiKey`, chain `authOnlyNoScopedKeys`. The guard lets an unrestricted
/// user API key through, but the handler asks for the cookie session itself, so only
/// a signed-in person can mint a key.
pub async fn create_user_key(
    State(state): State<AppState>,
    _method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let body = match request::read_body(&headers, body).await {
        Ok(body) => body,
        Err(response) => return response,
    };
    let scoped = match chain::auth_only_no_scoped_keys(&state, &headers, &uri).await {
        Ok(scoped) => scoped,
        Err(response) => return response,
    };
    let context = chain::context(&state, &headers, &scoped.query);
    let session = match super::access::session(&context).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    let Some(session) = session else {
        return request::error(StatusCode::UNAUTHORIZED, "Unauthorized");
    };

    let parsed = match zod::api_key_body(&body) {
        Ok(parsed) => parsed,
        Err(issues) => return request::error(StatusCode::BAD_REQUEST, &zod::first_message(&issues)),
    };
    match mint_key(&state, "default", session.user_id.clone(), parsed, None).await {
        Ok(response) => response,
        Err(err) => request::error(err.status, err.message),
    }
}

// ---------------------------------------------------------------------------
// POST /api/organizations/:organizationId/api-keys

/// `createOrgApiKey`, chain `orgAdminNoScopedKeys`. The key authenticates as the
/// organization itself, so it survives member departures; better-auth re-checks the
/// minting user's role through the organization roles' `apiKey` resource.
pub async fn create_org_key(
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
    let scoped = match chain::org_admin_no_scoped_keys(&state, &headers, &uri, &organization_id).await {
        Ok(scoped) => scoped,
        Err(response) => return response,
    };
    let Some(user_id) = scoped.auth.user_id.clone() else {
        return request::error(
            StatusCode::UNAUTHORIZED,
            "Organization API keys must be created by a signed-in user",
        );
    };

    let parsed = match zod::api_key_body(&body) {
        Ok(parsed) => parsed,
        Err(issues) => return request::error(StatusCode::BAD_REQUEST, &zod::first_message(&issues)),
    };

    // `checkOrgApiKeyPermission(ctx, userId, orgId, "create")` runs before every
    // other plugin check
    match check_org_permission(&state.pg, &user_id, &organization_id).await {
        Ok(()) => {}
        Err(Ok(err)) => return request::error(err.status, err.message),
        Err(Err(err)) => {
            error!(error = %err, "Error creating organization API key");
            return request::error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to create API key");
        }
    }

    let mut metadata = JsObject::new();
    metadata.insert("createdBy", JsValue::String(user_id));
    match mint_key(
        &state,
        ORG_API_KEY_CONFIG_ID,
        organization_id,
        parsed,
        Some(JsValue::Object(metadata)),
    )
    .await
    {
        Ok(response) => response,
        Err(err) => request::error(err.status, err.message),
    }
}

/// `checkOrgApiKeyPermission`: membership first, then the role's `apiKey` action
/// (owners always pass). A thrown lookup answers "not a member", as in the plugin.
#[allow(clippy::result_large_err)]
async fn check_org_permission(
    pg: &PgPool,
    user_id: &str,
    organization_id: &str,
) -> Result<(), Result<ApiKeyError, sqlx::Error>> {
    let role: Option<String> =
        sqlx::query_scalar(r#"SELECT role FROM member WHERE "userId" = $1 AND "organizationId" = $2"#)
            .bind(user_id)
            .bind(organization_id)
            .fetch_optional(pg)
            .await
            .map_err(Err)?;
    let Some(role) = role else {
        return Err(Ok(ApiKeyError {
            status: StatusCode::FORBIDDEN,
            message: codes::USER_NOT_MEMBER_OF_ORGANIZATION,
        }));
    };
    let mut permissions = Map::new();
    permissions.insert("apiKey".into(), json!(["create"]));
    if !organization::has_permission(&role, Some(&permissions), true) {
        return Err(Ok(ApiKeyError {
            status: StatusCode::FORBIDDEN,
            message: codes::INSUFFICIENT_API_KEY_PERMISSIONS,
        }));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// GET /api/organizations/:organizationId/api-usage

/// `dailyQuotaResetSeconds()`: seconds until the quota resets at 00:00 UTC.
fn daily_quota_reset_seconds(now: f64) -> f64 {
    ((((now / MS_PER_DAY).floor() + 1.0) * MS_PER_DAY - now) / 1000.0).ceil()
}

/// `getOrgApiUsage`, chain `orgOrgRead`. Self-hosted requests are not metered, so
/// the whole answer is constant apart from the reset countdown.
pub async fn org_api_usage(State(state): State<AppState>, method: Method, uri: Uri, headers: HeaderMap) -> Response {
    let params = match request::route_params(&uri, &[3]) {
        Ok(params) => params,
        Err(failure) => return request::param_failure(failure, method, uri).await,
    };
    let organization_id = params[0].clone();
    if let Err(response) = org_scoped(&state, &headers, &uri, &organization_id, false, route_scope("org", "read")).await
    {
        return response;
    }
    debug!(organization_id, "Reported API usage");
    request::send(
        StatusCode::OK,
        &object(vec![
            ("metered", JsValue::Bool(false)),
            ("available", JsValue::Bool(true)),
            ("dailyUsed", JsValue::Number(0.0)),
            ("dailyLimit", JsValue::Number(0.0)),
            ("dailyRemaining", JsValue::Number(0.0)),
            ("resetsInSeconds", JsValue::Number(daily_quota_reset_seconds(now_ms()))),
            ("burstLimit", JsValue::Number(API_BURST_LIMIT)),
            ("burstWindowSeconds", JsValue::Number(API_BURST_WINDOW_MS / 1000.0)),
        ]),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reset_counts_up_to_midnight() {
        // 23:59:59.500 UTC leaves one second (ceil of 0.5)
        let now = 1_796_083_200_000.0 - 500.0;
        assert_eq!(daily_quota_reset_seconds(now), 1.0);
        let midnight = 1_796_083_200_000.0;
        assert_eq!(daily_quota_reset_seconds(midnight), 86_400.0);
    }

    #[test]
    fn name_and_expiry_follow_the_plugin() {
        assert!(validate_key_input("name", None).is_ok());
        assert!(validate_key_input("", None).is_err());
        assert!(validate_key_input(&"x".repeat(33), None).is_err());
        assert!(validate_key_input("name", Some(86_400.0)).is_ok());
        assert!(validate_key_input("name", Some(86_399.0)).is_err());
        assert!(validate_key_input("name", Some(365.0 * 86_400.0)).is_ok());
        assert!(validate_key_input("name", Some(365.0 * 86_400.0 + 1.0)).is_err());
    }

    #[test]
    fn generated_keys_carry_their_prefix() {
        let (key, hashed) = generate_key(Some(ORG_KEY_PREFIX));
        assert!(key.starts_with(ORG_KEY_PREFIX));
        assert_eq!(key.len(), ORG_KEY_PREFIX.len() + DEFAULT_KEY_LENGTH);
        assert_eq!(starting_characters(&key), "rb_org");
        assert_eq!(hashed.len(), 43);
    }
}
