//! Authentication, ported from server/src/lib/{auth-utils,bearerAuth,scopes}.ts and
//! the Better Auth 1.6.25 behaviour recorded in AUTH_COMPAT.md.
#![allow(dead_code)] // consumed as ingest and the authenticated API are ported

pub mod access;
pub mod bearer;
pub mod endpoints;
pub mod guards;
pub mod scopes;
pub mod session;

use sqlx::PgPool;
use tracing::debug;

use bearer::{BearerIdentityStatus, extract_bearer_token, resolve_bearer_identity};
use scopes::ScopeStatements;

/// `BearerAuthResult`
#[derive(Clone, Debug, Default)]
pub struct BearerAuthResult {
    pub valid: bool,
    pub role: Option<String>,
    pub user_id: Option<String>,
    /// Set instead of `user_id` for organization-owned keys
    pub organization_id: Option<String>,
    pub rate_limited: bool,
    /// None = unrestricted
    pub statements: Option<ScopeStatements>,
}

/// Which organization a bearer credential must belong to.
#[derive(Clone, Copy, Debug, Default)]
pub struct AccessTarget<'a> {
    pub organization_id: Option<&'a str>,
    pub site_id: Option<i64>,
    /// The `siteId` route parameter the target came from, when it did: Node binds
    /// `Number(siteId)` to the integer column, so a value Postgres cannot read as
    /// an integer fails the lookup (see [`SiteIdQueryFailed`])
    pub site_param: Option<&'a str>,
}

/// The query error `resolveTargetOrganizationId` throws when `Number(siteId)` is
/// not an integer Postgres accepts (NaN, a fraction, out of range): drizzle wraps
/// the failure as `Failed query: <sql>\nparams: <values>`, and the guard lets it
/// escape to Fastify's default error handler as a 500 carrying that message.
#[derive(Debug, thiserror::Error)]
#[error("Failed query: select \"organization_id\" from \"sites\" where \"sites\".\"site_id\" = $1 limit $2\nparams: {param},1")]
pub struct SiteIdQueryFailed {
    /// `String(Number(siteId))`, as node-postgres sends it
    pub param: String,
}

impl SiteIdQueryFailed {
    /// The error for a truthy `siteId` whose number Postgres would reject.
    fn check(site_param: &str) -> Option<Self> {
        use crate::analytics::js::number::{number_to_string, string_to_number};
        if site_param.is_empty() {
            return None;
        }
        let param = number_to_string(string_to_number(site_param));
        param.parse::<i32>().is_err().then_some(Self { param })
    }
}

/// `resolveBearerTokenFromRequest`: `Authorization: Bearer` first, then `?api_key=`
/// (only when it parsed as a single string).
pub fn bearer_token<'a>(authorization: Option<&'a str>, query_api_key: Option<&'a str>) -> Option<&'a str> {
    extract_bearer_token(authorization).or(query_api_key)
}

/// `resolveTargetOrganizationId`
async fn target_organization_id(pg: &PgPool, target: AccessTarget<'_>) -> Result<Option<String>, sqlx::Error> {
    if let Some(organization_id) = target.organization_id.filter(|id| !id.is_empty()) {
        return Ok(Some(organization_id.to_string()));
    }
    if let Some(failed) = target.site_param.and_then(SiteIdQueryFailed::check) {
        debug!(param = %failed.param, "Site id cannot bind to the integer column");
        return Err(sqlx::Error::Encode(Box::new(failed)));
    }
    let Some(site_id) = target.site_id.filter(|id| *id != 0) else {
        return Ok(None);
    };
    let organization_id: Option<Option<String>> =
        sqlx::query_scalar("SELECT organization_id FROM sites WHERE site_id = $1 LIMIT 1")
            .bind(site_id)
            .fetch_optional(pg)
            .await?;
    Ok(organization_id.flatten().filter(|id| !id.is_empty()))
}

/// `checkApiKey`: verify the request's bearer credential and resolve its role in
/// the target organization. Organization keys act as org admins of their own
/// organization only; user credentials need a membership there. Database errors
/// in the membership lookups propagate like Node's, to the route's error handler.
pub async fn check_api_key(
    pg: &PgPool,
    token: Option<&str>,
    target: AccessTarget<'_>,
) -> Result<BearerAuthResult, sqlx::Error> {
    let Some(token) = token else {
        return Ok(BearerAuthResult::default());
    };

    let identity = resolve_bearer_identity(pg, token).await;
    if identity.status == BearerIdentityStatus::RateLimited {
        return Ok(BearerAuthResult { rate_limited: true, ..Default::default() });
    }
    if identity.status != BearerIdentityStatus::Valid {
        return Ok(BearerAuthResult::default());
    }

    if let Some(organization_id) = identity.organization_id {
        let target_org = target_organization_id(pg, target).await?;
        if target_org.as_deref() == Some(organization_id.as_str()) {
            return Ok(BearerAuthResult {
                valid: true,
                role: Some("admin".to_string()),
                organization_id: Some(organization_id),
                statements: identity.statements,
                ..Default::default()
            });
        }
        debug!(organization_id = %organization_id, "Organization API key used outside its organization");
        return Ok(BearerAuthResult::default());
    }

    let Some(user_id) = identity.user_id else {
        return Ok(BearerAuthResult::default());
    };
    let role: Option<String> = match target_organization_id(pg, target).await? {
        Some(target_org) => {
            sqlx::query_scalar(r#"SELECT role FROM member WHERE "userId" = $1 AND "organizationId" = $2 LIMIT 1"#)
                .bind(&user_id)
                .bind(&target_org)
                .fetch_optional(pg)
                .await?
        }
        None => None,
    };
    Ok(match role {
        Some(role) => BearerAuthResult {
            valid: true,
            role: Some(role),
            user_id: Some(user_id),
            statements: identity.statements,
            ..Default::default()
        },
        None => BearerAuthResult { statements: identity.statements, ..Default::default() },
    })
}

/// Differential check against Node's `checkApiKey`; run through parity/auth/run.sh.
#[cfg(test)]
mod parity {
    use serde_json::{Value, json};
    use sqlx::postgres::{PgConnectOptions, PgPoolOptions};

    use super::*;

    #[tokio::test]
    #[ignore = "needs the parity Postgres; run parity/auth/run.sh"]
    async fn bearer_cases_match_node() {
        let plan: Value = serde_json::from_str(&std::fs::read_to_string(std::env::var("PARITY_AUTH_PLAN").unwrap()).unwrap()).unwrap();
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
            let authorization = case["token"].as_str().map(|token| format!("Bearer {token}"));
            let token = bearer_token(authorization.as_deref(), case["queryApiKey"].as_str());
            let target = AccessTarget {
                organization_id: case["target"]["organizationId"].as_str(),
                site_id: case["target"]["siteId"].as_i64(),
                site_param: None,
            };
            let result = check_api_key(&pg, token, target).await.unwrap();
            let rows: String = sqlx::query_scalar(plan["state"].as_str().unwrap()).fetch_one(&pg).await.unwrap();
            let statements = result.statements.as_ref().map(|statements| {
                Value::Object(statements.iter().map(|(resource, actions)| (resource.clone(), json!(actions))).collect())
            });
            results.push(json!({
                "name": case["name"],
                "result": {
                    "valid": result.valid,
                    "role": result.role,
                    "userId": result.user_id,
                    "organizationId": result.organization_id,
                    "rateLimited": result.rate_limited,
                    "statements": statements,
                },
                "rows": serde_json::from_str::<Value>(&rows).unwrap(),
            }));
        }
        for statement in plan["cleanup"].as_array().unwrap() {
            sqlx::query(statement.as_str().unwrap()).execute(&pg).await.unwrap();
        }
        std::fs::write(std::env::var("PARITY_AUTH_OUT").unwrap(), Value::Array(results).to_string()).unwrap();
    }
}
