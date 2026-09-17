//! Cookie sessions, ported from Better Auth 1.6.25 `getSession`
//! (better-auth/dist/api/routes/session.mjs) and the better-call cookie helpers it
//! relies on. See AUTH_COMPAT.md "Sessions and cookies".
//!
//! Server-side guard lookups (`auth.api.getSession({ headers })`) perform the same
//! database writes as the browser's own `/get-session` call (deleting expired rows,
//! sliding `expiresAt` forward once a day) but never set cookies, so neither does
//! `get_session` here.

use base64::{
    Engine,
    alphabet,
    engine::{GeneralPurpose, GeneralPurposeConfig},
};
use chrono::{DateTime, Duration, NaiveDateTime, SubsecRound, Utc};
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use sqlx::{PgPool, Row};
use tracing::{debug, error, info};

/// `session.expiresIn` default: 7 days
pub const SESSION_EXPIRES_IN_SECONDS: i64 = 604_800;
/// `session.updateAge` default: refresh at most once a day
pub const SESSION_UPDATE_AGE_SECONDS: i64 = 86_400;

/// A signed-in user's session row and the user fields guards and handlers read.
#[derive(Clone, Debug)]
pub struct AuthSession {
    pub id: String,
    pub token: String,
    pub user_id: String,
    pub expires_at: DateTime<Utc>,
    pub impersonated_by: Option<String>,
    pub active_organization_id: Option<String>,
    pub user: SessionUser,
}

#[derive(Clone, Debug)]
pub struct SessionUser {
    pub id: String,
    pub name: String,
    pub email: String,
    pub email_verified: bool,
    pub role: Option<String>,
}

/// Better Auth cookie names: `__Secure-` prefixed when cookies are secure
/// (NODE_ENV=production).
pub fn cookie_name(production: bool, name: &str) -> String {
    if production { format!("__Secure-better-auth.{name}") } else { format!("better-auth.{name}") }
}

/// better-call `parseCookies`: first occurrence of a name wins, values trimmed,
/// one leading quote strips the first and last character, `%` values decoded
/// when they decode cleanly.
pub fn parse_cookies(header: &str) -> Vec<(String, String)> {
    let mut cookies: Vec<(String, String)> = Vec::new();
    let mut index = 0;
    while index < header.len() {
        let Some(eq) = header[index..].find('=').map(|offset| index + offset) else { break };
        let end = match header[index..].find(';').map(|offset| index + offset) {
            None => header.len(),
            Some(end) if end < eq => {
                // A segment without '=': restart just after the last ';' before this '='
                index = header[..eq].rfind(';').map_or(0, |semicolon| semicolon + 1);
                continue;
            }
            Some(end) => end,
        };
        let key = header[index..eq].trim_matches(js_whitespace);
        if !cookies.iter().any(|(existing, _)| existing == key) {
            let mut value = header[eq + 1..end].trim_matches(js_whitespace);
            if let Some(rest) = value.strip_prefix('"') {
                // slice(1, -1): drops the last character whatever it is
                value = rest.char_indices().last().map_or("", |(last, _)| &rest[..last]);
            }
            cookies.push((key.to_string(), try_decode(value)));
        }
        index = end + 1;
    }
    cookies
}

/// `String.prototype.trim`'s whitespace set, close enough for header text
fn js_whitespace(character: char) -> bool {
    character.is_whitespace() || character == '\u{feff}'
}

/// `tryDecode`: `decodeURIComponent` when the value contains `%`, the raw value
/// when decoding throws (malformed escapes or invalid UTF-8).
fn try_decode(value: &str) -> String {
    if !value.contains('%') {
        return value.to_string();
    }
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let hex = value.get(index + 1..index + 3).and_then(|pair| u8::from_str_radix(pair, 16).ok());
            match hex {
                Some(byte) if value[index + 1..index + 3].chars().all(|c| c.is_ascii_hexdigit()) => {
                    decoded.push(byte);
                    index += 3;
                }
                _ => return value.to_string(),
            }
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(decoded).unwrap_or_else(|_| value.to_string())
}

/// `atob` is forgiving about the unused low bits of the final base64 character.
const FORGIVING_BASE64: GeneralPurpose = GeneralPurpose::new(
    &alphabet::STANDARD,
    GeneralPurposeConfig::new().with_decode_allow_trailing_bits(true),
);

/// better-call `getSignedCookie`: the value before the last `.` when the 44
/// character base64 HMAC-SHA256 (keyed with the secret's UTF-8 bytes) after it
/// verifies.
pub fn verify_signed_value(value: &str, secret: &str) -> Option<String> {
    let dot = value.rfind('.')?;
    if dot < 1 {
        return None;
    }
    let (signed, signature) = (&value[..dot], &value[dot + 1..]);
    if signature.chars().count() != 44 || !signature.ends_with('=') {
        return None;
    }
    let signature = FORGIVING_BASE64.decode(signature).ok()?;
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).ok()?;
    mac.update(signed.as_bytes());
    mac.verify_slice(&signature).ok()?;
    Some(signed.to_string())
}

/// Sign a cookie value the way better-call's `signCookieValue` does (before
/// `encodeURIComponent`).
pub fn sign_value(value: &str, secret: &str) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key length");
    mac.update(value.as_bytes());
    let signature = base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes());
    format!("{value}.{signature}")
}

/// The request's cookie header as Node sees it: repeated headers joined with
/// "; ", bytes read as latin1.
pub fn cookie_header(headers: &axum::http::HeaderMap) -> Option<String> {
    let values: Vec<String> = headers
        .get_all(axum::http::header::COOKIE)
        .iter()
        .map(|value| value.as_bytes().iter().map(|byte| char::from(*byte)).collect())
        .collect();
    (!values.is_empty()).then(|| values.join("; "))
}

fn now_millis() -> NaiveDateTime {
    Utc::now().trunc_subsecs(3).naive_utc()
}

/// `auth.api.getSession({ headers })`: the signed session cookie's session and
/// user, or None. Expired sessions are deleted; sessions past `updateAge` slide
/// their expiry forward unless the `dont_remember` cookie is set.
pub async fn get_session(
    pg: &PgPool,
    secret: Option<&str>,
    production: bool,
    headers: &axum::http::HeaderMap,
) -> Result<Option<AuthSession>, sqlx::Error> {
    let Some(header) = cookie_header(headers) else { return Ok(None) };
    let Some(secret) = secret else {
        error!("BETTER_AUTH_SECRET is not set, no session can be verified");
        return Ok(None);
    };

    let cookies = parse_cookies(&header);
    let signed = |name: &str| {
        let name = cookie_name(production, name);
        cookies
            .iter()
            .find(|(key, _)| *key == name)
            .map(|(_, value)| value.as_str())
            .filter(|value| !value.is_empty())
            .and_then(|value| verify_signed_value(value, secret))
    };

    let Some(token) = signed("session_token").filter(|token| !token.is_empty()) else {
        return Ok(None);
    };

    let Some(row) = sqlx::query(
        r#"SELECT id, token, "userId", "expiresAt", "impersonatedBy", "activeOrganizationId"
           FROM session WHERE token = $1 LIMIT 1"#,
    )
    .bind(&token)
    .fetch_optional(pg)
    .await?
    else {
        debug!("Session cookie names no session");
        return Ok(None);
    };

    let user_id: String = row.try_get("userId")?;
    let Some(user_row) = sqlx::query(r#"SELECT id, name, email, "emailVerified", role FROM "user" WHERE id = $1 LIMIT 1"#)
        .bind(&user_id)
        .fetch_optional(pg)
        .await?
    else {
        return Ok(None);
    };

    let expires_at = row.try_get::<NaiveDateTime, _>("expiresAt")?.and_utc();
    let now = Utc::now();
    if expires_at < now {
        sqlx::query("DELETE FROM session WHERE token = $1").bind(&token).execute(pg).await?;
        info!(user_id = %user_id, "Expired session deleted");
        return Ok(None);
    }

    let mut session = AuthSession {
        id: row.try_get("id")?,
        token: token.clone(),
        user_id,
        expires_at,
        impersonated_by: row.try_get("impersonatedBy")?,
        active_organization_id: row.try_get("activeOrganizationId")?,
        user: SessionUser {
            id: user_row.try_get("id")?,
            name: user_row.try_get("name")?,
            email: user_row.try_get("email")?,
            email_verified: user_row.try_get("emailVerified")?,
            role: user_row.try_get("role")?,
        },
    };

    let dont_remember = signed("dont_remember").is_some_and(|value| !value.is_empty());
    let refresh_due = expires_at - Duration::seconds(SESSION_EXPIRES_IN_SECONDS)
        + Duration::seconds(SESSION_UPDATE_AGE_SECONDS)
        <= now;
    if refresh_due && !dont_remember {
        let new_expiry = (now + Duration::seconds(SESSION_EXPIRES_IN_SECONDS)).trunc_subsecs(3);
        let updated = sqlx::query(r#"UPDATE session SET "expiresAt" = $2, "updatedAt" = $3 WHERE token = $1"#)
            .bind(&token)
            .bind(new_expiry.naive_utc())
            .bind(now_millis())
            .execute(pg)
            .await?;
        if updated.rows_affected() == 0 {
            // Deleted concurrently: Better Auth answers FAILED_TO_GET_SESSION
            return Ok(None);
        }
        debug!(user_id = %session.user_id, "Session expiry refreshed");
        session.expires_at = new_expiry;
    }

    Ok(Some(session))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cookies_parse_like_better_call() {
        let cookies = parse_cookies("a=1; b=\"quoted\"; a=2; junk; c=%E2%9C%93; d=%zz; e = spaced ");
        assert_eq!(
            cookies,
            vec![
                ("a".into(), "1".into()),
                ("b".into(), "quoted".into()),
                ("c".into(), "\u{2713}".into()),
                ("d".into(), "%zz".into()),
                ("e".into(), "spaced".into()),
            ]
        );
    }

    #[test]
    fn signatures_round_trip_and_reject_tampering() {
        let signed = sign_value("tokenvalue", "secret");
        assert_eq!(verify_signed_value(&signed, "secret").as_deref(), Some("tokenvalue"));
        assert_eq!(verify_signed_value(&signed, "other"), None);
        assert_eq!(verify_signed_value("tokenvalue.short=", "secret"), None);
        assert_eq!(verify_signed_value(".abc", "secret"), None);
    }
}

/// Differential check against Node's `auth.api.getSession`; run through parity/session/run.sh.
#[cfg(test)]
mod parity {
    use serde_json::{Value, json};
    use sqlx::postgres::{PgConnectOptions, PgPoolOptions};

    use super::*;

    #[tokio::test]
    #[ignore = "needs the parity Postgres; run parity/session/run.sh"]
    async fn session_cases_match_node() {
        let plan: Value =
            serde_json::from_str(&std::fs::read_to_string(std::env::var("PARITY_SESSION_PLAN").unwrap()).unwrap()).unwrap();
        let config = crate::config::Config::from_env().unwrap();
        let options = PgConnectOptions::new()
            .host(&config.postgres.host)
            .port(config.postgres.port)
            .username(&config.postgres.user)
            .password(&config.postgres.password)
            .database(&config.postgres.database);
        let pg = PgPoolOptions::new().max_connections(2).connect_with(options).await.unwrap();

        let mut results = Vec::new();
        for case in plan["cases"].as_array().unwrap() {
            for statement in case["setup"].as_array().unwrap() {
                sqlx::query(statement.as_str().unwrap()).execute(&pg).await.unwrap();
            }
            let mut headers = axum::http::HeaderMap::new();
            if let Some(cookie) = case["cookie"].as_str() {
                headers.insert(axum::http::header::COOKIE, cookie.parse().unwrap());
            }
            let outcome =
                get_session(&pg, config.better_auth_secret.as_deref(), config.production, &headers).await;
            let rows: String = sqlx::query_scalar(plan["state"].as_str().unwrap()).fetch_one(&pg).await.unwrap();
            results.push(json!({
                "name": case["name"],
                "userId": outcome.as_ref().ok().and_then(|session| session.as_ref().map(|s| s.user_id.clone())),
                "error": outcome.is_err(),
                "rows": serde_json::from_str::<Value>(&rows).unwrap(),
            }));
        }
        for statement in plan["cleanup"].as_array().unwrap() {
            sqlx::query(statement.as_str().unwrap()).execute(&pg).await.unwrap();
        }
        std::fs::write(std::env::var("PARITY_SESSION_OUT").unwrap(), Value::Array(results).to_string()).unwrap();
    }
}
