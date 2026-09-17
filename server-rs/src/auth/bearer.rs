//! Bearer credential resolution, ported from server/src/lib/bearerAuth.ts and the
//! two Better Auth 1.6.25 endpoints it calls: `verifyApiKey`
//! (@better-auth/api-key `validateApiKey`) and `getMcpSession` (plugins/mcp).
//!
//! Timestamps: the drizzle schema maps these columns with `mode: "string"` and the
//! Node process runs in UTC, so every `timestamp without time zone` holds UTC wall
//! time written with millisecond precision. Rust reads and writes the same.

use base64::Engine;
use chrono::{DateTime, NaiveDateTime, SubsecRound, Utc};
use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Row};
use tracing::{debug, error, warn};

use super::scopes::{ScopeStatements, parse_oauth_scopes, statements_from_api_key_permissions};

/// `ORG_API_KEY_CONFIG_ID` from @hygo/shared
pub const ORG_API_KEY_CONFIG_ID: &str = "org";

/// `extractBearerToken`: exactly `Bearer <token>`, case-sensitive, non-empty.
pub fn extract_bearer_token(authorization: Option<&str>) -> Option<&str> {
    authorization?.strip_prefix("Bearer ").filter(|token| !token.is_empty())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BearerIdentityStatus {
    Valid,
    Invalid,
    RateLimited,
    VerifyError,
}

/// `BearerIdentity`. Exactly one of `user_id`/`organization_id` is set when valid.
#[derive(Clone, Debug)]
pub struct BearerIdentity {
    pub status: BearerIdentityStatus,
    pub user_id: Option<String>,
    pub organization_id: Option<String>,
    /// None = unrestricted (legacy key or a full OAuth grant)
    pub statements: Option<ScopeStatements>,
}

impl BearerIdentity {
    fn invalid(status: BearerIdentityStatus) -> Self {
        Self { status, user_id: None, organization_id: None, statements: None }
    }
}

/// The key row fields `resolveBearerIdentity` reads after a successful verification.
#[derive(Clone, Debug)]
pub struct VerifiedApiKey {
    pub id: String,
    pub config_id: Option<String>,
    pub reference_id: String,
    pub permissions: Option<Value>,
}

/// Better Auth's `API_KEY_ERROR_CODES` for the failures this deployment can hit
/// (plugin rate limiting is disabled in both key configurations).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApiKeyRejection {
    InvalidApiKey,
    KeyDisabled,
    KeyExpired,
    UsageExceeded,
}

impl ApiKeyRejection {
    pub fn code(self) -> &'static str {
        match self {
            ApiKeyRejection::InvalidApiKey => "INVALID_API_KEY",
            ApiKeyRejection::KeyDisabled => "KEY_DISABLED",
            ApiKeyRejection::KeyExpired => "KEY_EXPIRED",
            ApiKeyRejection::UsageExceeded => "USAGE_EXCEEDED",
        }
    }
}

/// `defaultKeyHasher`: base64url without padding of SHA-256 over the UTF-8 key.
pub fn hash_api_key(key: &str) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(key.as_bytes()))
}

/// What Node's `new Date()` stores in these columns: UTC, millisecond precision.
fn now_millis() -> NaiveDateTime {
    Utc::now().trunc_subsecs(3).naive_utc()
}

fn as_utc(value: NaiveDateTime) -> DateTime<Utc> {
    value.and_utc()
}

/// `auth.api.verifyApiKey({ body: { key } })` with this app's configuration:
/// database storage, no deferred updates, plugin rate limiting disabled. Like the
/// endpoint, database failures report an invalid key instead of erroring.
pub async fn verify_api_key(pg: &PgPool, key: &str) -> Result<VerifiedApiKey, ApiKeyRejection> {
    match validate_api_key(pg, key).await {
        Ok(result) => result,
        Err(error) => {
            error!(error = %error, "Failed to validate API key");
            Err(ApiKeyRejection::InvalidApiKey)
        }
    }
}

async fn validate_api_key(pg: &PgPool, key: &str) -> Result<Result<VerifiedApiKey, ApiKeyRejection>, sqlx::Error> {
    let hashed = hash_api_key(key);
    let Some(row) = sqlx::query(
        r#"SELECT id, "configId", "referenceId", enabled, "expiresAt", remaining, "refillAmount",
                  "refillInterval", "lastRefillAt", "createdAt", permissions
           FROM apikey WHERE key = $1 LIMIT 1"#,
    )
    .bind(&hashed)
    .fetch_optional(pg)
    .await?
    else {
        return Ok(Err(ApiKeyRejection::InvalidApiKey));
    };

    let id: String = row.try_get("id")?;
    let enabled: bool = row.try_get("enabled")?;
    let expires_at: Option<NaiveDateTime> = row.try_get("expiresAt")?;
    let remaining: Option<i32> = row.try_get("remaining")?;
    let refill_amount: Option<i32> = row.try_get("refillAmount")?;
    let refill_interval: Option<i32> = row.try_get("refillInterval")?;
    let last_refill_at: Option<NaiveDateTime> = row.try_get("lastRefillAt")?;
    let created_at: NaiveDateTime = row.try_get("createdAt")?;

    if !enabled {
        debug!(key_id = %id, "API key disabled");
        return Ok(Err(ApiKeyRejection::KeyDisabled));
    }

    if let Some(expires_at) = expires_at
        && Utc::now() > as_utc(expires_at)
    {
        sqlx::query("DELETE FROM apikey WHERE id = $1").bind(&id).execute(pg).await?;
        debug!(key_id = %id, "API key expired and deleted");
        return Ok(Err(ApiKeyRejection::KeyExpired));
    }

    if remaining == Some(0) && refill_amount.is_none() {
        sqlx::query("DELETE FROM apikey WHERE id = $1").bind(&id).execute(pg).await?;
        debug!(key_id = %id, "API key usage exhausted and deleted");
        return Ok(Err(ApiKeyRejection::UsageExceeded));
    }

    // claimUsageInDatabase: quota first, then the rate-limit "skip" branch that
    // stamps lastRequest, then updatedAt
    if remaining.is_some() && !consume_remaining(pg, &id, refill_interval, refill_amount, last_refill_at, created_at).await? {
        return Ok(Err(ApiKeyRejection::UsageExceeded));
    }

    sqlx::query(r#"UPDATE apikey SET "lastRequest" = $2 WHERE id = $1"#)
        .bind(&id)
        .bind(now_millis())
        .execute(pg)
        .await?;
    let Some(row) = sqlx::query(
        r#"UPDATE apikey SET "updatedAt" = $2 WHERE id = $1 RETURNING "configId", "referenceId", permissions"#,
    )
    .bind(&id)
    .bind(now_millis())
    .fetch_optional(pg)
    .await?
    else {
        return Ok(Err(ApiKeyRejection::InvalidApiKey));
    };

    let permissions: Option<String> = row.try_get("permissions")?;
    Ok(Ok(VerifiedApiKey {
        id,
        config_id: row.try_get("configId")?,
        reference_id: row.try_get("referenceId")?,
        // safeJSONParse: unparseable text behaves like no permissions at all
        permissions: permissions.and_then(|text| serde_json::from_str(&text).ok()),
    }))
}

/// `consumeRemaining`: a due refill is won by exactly one verification
/// (compare-and-swap on the observed `lastRefillAt`), otherwise a guarded
/// decrement that never goes below zero. False means the quota is used up.
async fn consume_remaining(
    pg: &PgPool,
    id: &str,
    refill_interval: Option<i32>,
    refill_amount: Option<i32>,
    last_refill_at: Option<NaiveDateTime>,
    created_at: NaiveDateTime,
) -> Result<bool, sqlx::Error> {
    // JS truthiness: zero disables refills just like null
    if let (Some(interval), Some(amount)) = (refill_interval.filter(|v| *v != 0), refill_amount.filter(|v| *v != 0)) {
        let last = as_utc(last_refill_at.unwrap_or(created_at));
        if (Utc::now() - last).num_milliseconds() > i64::from(interval) {
            let refilled = sqlx::query(
                r#"UPDATE apikey SET remaining = $2, "lastRefillAt" = $3
                   WHERE id = $1 AND "lastRefillAt" IS NOT DISTINCT FROM $4"#,
            )
            .bind(id)
            .bind(amount - 1)
            .bind(now_millis())
            // Better Auth compares against the value it revived as a JS Date, which
            // keeps milliseconds only; Node-written rows never carry more
            .bind(last_refill_at.map(|value| value.trunc_subsecs(3)))
            .execute(pg)
            .await?;
            if refilled.rows_affected() > 0 {
                return Ok(true);
            }
        }
    }

    let decremented = sqlx::query("UPDATE apikey SET remaining = remaining - 1 WHERE id = $1 AND remaining > 0")
        .bind(id)
        .execute(pg)
        .await?;
    Ok(decremented.rows_affected() > 0)
}

/// `auth.api.getMcpSession` followed by `isUsableOAuthToken`: the access token
/// row's user and scopes when the token exists, has a user and has not expired.
async fn usable_oauth_token(pg: &PgPool, token: &str) -> Result<Option<(String, String)>, sqlx::Error> {
    let row = sqlx::query(
        r#"SELECT "userId", "accessTokenExpiresAt", scopes FROM "oauthAccessToken" WHERE "accessToken" = $1 LIMIT 1"#,
    )
    .bind(token)
    .fetch_optional(pg)
    .await?;
    let Some(row) = row else { return Ok(None) };

    let user_id: Option<String> = row.try_get("userId")?;
    let expires_at: NaiveDateTime = row.try_get("accessTokenExpiresAt")?;
    let scopes: String = row.try_get("scopes")?;
    match user_id.filter(|id| !id.is_empty()) {
        Some(user_id) if as_utc(expires_at) > Utc::now() => Ok(Some((user_id, scopes))),
        _ => Ok(None),
    }
}

/// `resolveBearerIdentity`: API key first, then MCP OAuth access token.
///
/// Per-owner rate limiting (`consumeRateLimit`) only exists when CLOUD=true and is
/// not ported yet; self-hosted deployments like production never charge it.
pub async fn resolve_bearer_identity(pg: &PgPool, token: &str) -> BearerIdentity {
    match verify_api_key(pg, token).await {
        Ok(key) if !key.reference_id.is_empty() => {
            let statements = statements_from_api_key_permissions(key.permissions.as_ref());
            let is_org_key = key.config_id.as_deref() == Some(ORG_API_KEY_CONFIG_ID);
            debug!(key_id = %key.id, org_key = is_org_key, "Bearer resolved to an API key");
            return BearerIdentity {
                status: BearerIdentityStatus::Valid,
                user_id: (!is_org_key).then(|| key.reference_id.clone()),
                organization_id: is_org_key.then_some(key.reference_id),
                statements,
            };
        }
        Ok(_) => {}
        Err(rejection) => debug!(code = rejection.code(), "Bearer is not a usable API key"),
    }

    // Not a valid API key: try it as an OAuth access token. Lookup failures are
    // tolerated so API-key auth is unaffected by the OAuth tables.
    match usable_oauth_token(pg, token).await {
        Ok(Some((user_id, scopes))) => BearerIdentity {
            status: BearerIdentityStatus::Valid,
            user_id: Some(user_id),
            organization_id: None,
            statements: parse_oauth_scopes(Some(&scopes)),
        },
        Ok(None) => BearerIdentity::invalid(BearerIdentityStatus::Invalid),
        Err(error) => {
            warn!(error = %error, "OAuth access token lookup failed");
            BearerIdentity::invalid(BearerIdentityStatus::Invalid)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bearer_parsing_matches_node() {
        assert_eq!(extract_bearer_token(Some("Bearer abc")), Some("abc"));
        assert_eq!(extract_bearer_token(Some("Bearer ")), None);
        assert_eq!(extract_bearer_token(Some("bearer abc")), None);
        assert_eq!(extract_bearer_token(Some("Bearer  abc")), Some(" abc"));
        assert_eq!(extract_bearer_token(None), None);
    }

    #[test]
    fn key_hash_is_base64url_sha256_without_padding() {
        // node -e 'console.log(require("crypto").createHash("sha256").update("rb_org_test").digest("base64url"))'
        assert_eq!(hash_api_key("rb_org_test"), "XaxDHEbsgdEB-7vOevVv6CD1rrnWiQiKbf0Rga4GPno");
        assert_eq!(hash_api_key("").len(), 43);
    }
}
