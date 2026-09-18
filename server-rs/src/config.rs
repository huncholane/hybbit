use std::path::PathBuf;

use anyhow::{Context, Result};

/// Settings read from the same environment variables as the Node backend, so the
/// Rust container can reuse the backend service's environment block unchanged.
/// Not `Debug`: it holds credentials and must never end up in a log line.
#[derive(Clone)]
pub struct Config {
    pub port: u16,
    /// Public origin of the dashboard (BASE_URL); the trusted CORS origin
    pub base_url: Option<String>,
    /// NODE_ENV == "production": no localhost CORS origins, secure cookies
    pub production: bool,
    pub disable_signup: bool,
    pub lite_dashboard: bool,
    /// MAPBOX_TOKEN exactly as Node sees it: unset stays absent from /api/config,
    /// an empty value is sent as ""
    pub mapbox_token: Option<String>,
    /// BETTER_AUTH_SECRET: signs session cookies and salts user ids (Node's `SECRET`)
    pub better_auth_secret: Option<String>,
    /// Directory with script.js, rrweb.min.js and friends (PUBLIC_DIR, default ./public)
    pub public_dir: PathBuf,
    /// Directory with GeoLite2-City.mmdb and GeoLite2-ASN.mmdb (GEOIP_DIR, default: working directory, like Node)
    pub geoip_dir: PathBuf,
    /// The dashboard's static export, `client/out` (CLIENT_DIR, default: `client` next to the binary)
    pub client_dir: PathBuf,
    /// The API origin the embed widget's script calls: NEXT_PUBLIC_BACKEND_URL (what the
    /// client export was built with), else BASE_URL, else Node's default, plus `/api`
    pub widget_api_url: String,
    pub postgres: PostgresConfig,
    pub clickhouse: ClickHouseConfig,
    pub redis: RedisConfig,
    pub auth: AuthConfig,
}

/// The environment Better Auth (server/src/lib/auth.ts) and the email module read
/// beyond the settings above.
#[derive(Clone)]
pub struct AuthConfig {
    /// CLOUD == "true": Resend email, Turnstile captcha, plan gates
    pub cloud: bool,
    pub resend_api_key: Option<String>,
    pub turnstile_secret_key: Option<String>,
    /// Better Auth's `getBaseURL` environment chain: BETTER_AUTH_URL,
    /// NEXT_PUBLIC_BETTER_AUTH_URL, PUBLIC_BETTER_AUTH_URL, NUXT_PUBLIC_BETTER_AUTH_URL,
    /// NUXT_PUBLIC_AUTH_URL, then BASE_URL unless it is "/". Raw value, unvalidated.
    pub base_url_env: Option<String>,
    /// BETTER_AUTH_TRUSTED_ORIGINS, comma separated
    pub trusted_origins_env: Option<String>,
    pub google_client_id: Option<String>,
    pub google_client_secret: Option<String>,
    pub github_client_id: Option<String>,
    /// NODE_ENV "dev"/"development": Better Auth's `isDevelopment()` (client IP falls
    /// back to 127.0.0.1)
    pub development: bool,
    /// NODE_ENV "test" or TEST truthy: `isTest()` (origin checks skipped)
    pub test: bool,
}

impl AuthConfig {
    pub fn from_env() -> Self {
        // `env.X || ...`: empty strings fall through like undefined
        let base_url_env = [
            "BETTER_AUTH_URL",
            "NEXT_PUBLIC_BETTER_AUTH_URL",
            "PUBLIC_BETTER_AUTH_URL",
            "NUXT_PUBLIC_BETTER_AUTH_URL",
            "NUXT_PUBLIC_AUTH_URL",
        ]
        .iter()
        .find_map(|name| env_opt(name))
        .or_else(|| env_opt("BASE_URL").filter(|value| value != "/"));
        Self {
            cloud: flag("CLOUD"),
            resend_api_key: env_opt("RESEND_API_KEY"),
            turnstile_secret_key: env_opt("TURNSTILE_SECRET_KEY"),
            base_url_env,
            trusted_origins_env: env_opt("BETTER_AUTH_TRUSTED_ORIGINS"),
            google_client_id: env_opt("GOOGLE_CLIENT_ID"),
            google_client_secret: env_opt("GOOGLE_CLIENT_SECRET"),
            github_client_id: env_opt("GITHUB_CLIENT_ID"),
            development: matches!(std::env::var("NODE_ENV").as_deref(), Ok("dev" | "development")),
            test: std::env::var("NODE_ENV").as_deref() == Ok("test")
                || std::env::var("TEST").is_ok_and(|value| !value.is_empty() && value != "false"),
        }
    }
}

#[derive(Clone)]
pub struct PostgresConfig {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub password: String,
    pub database: String,
}

#[derive(Clone)]
pub struct ClickHouseConfig {
    /// Full HTTP endpoint, e.g. http://clickhouse:8123 (CLICKHOUSE_HOST)
    pub url: String,
    pub database: String,
    pub user: String,
    pub password: String,
    /// Least-privilege user for user-authored SQL (CLICKHOUSE_QUERY_USER)
    pub query_user: String,
    pub query_password: String,
    /// The database `provisionQueryUser` names in its GRANT. It reads CLICKHOUSE_DB
    /// itself and falls back to "default", not to the connection's "analytics", so a
    /// deployment that leaves CLICKHOUSE_DB unset grants on a database it never uses.
    /// Kept as Node has it so the two backends provision the same grant.
    pub query_grant_database: String,
}

#[derive(Clone)]
pub struct RedisConfig {
    pub host: String,
    pub port: u16,
    pub password: Option<String>,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        Ok(Self {
            port: port_from_env("PORT", 3001)?,
            base_url: env_opt("BASE_URL"),
            production: std::env::var("NODE_ENV").as_deref() == Ok("production"),
            disable_signup: flag("DISABLE_SIGNUP"),
            lite_dashboard: flag("LITE_DASHBOARD"),
            mapbox_token: std::env::var("MAPBOX_TOKEN").ok(),
            better_auth_secret: std::env::var("BETTER_AUTH_SECRET").ok(),
            public_dir: PathBuf::from(env_or("PUBLIC_DIR", "public")),
            geoip_dir: PathBuf::from(env_or("GEOIP_DIR", ".")),
            client_dir: env_opt("CLIENT_DIR").map_or_else(default_client_dir, PathBuf::from),
            widget_api_url: format!(
                "{}/api",
                env_opt("NEXT_PUBLIC_BACKEND_URL")
                    .or_else(|| env_opt("BASE_URL"))
                    .unwrap_or_else(|| "http://localhost:3001".to_string())
            ),
            postgres: PostgresConfig {
                host: env_or("POSTGRES_HOST", "postgres"),
                port: port_from_env("POSTGRES_PORT", 5432)?,
                user: env_or("POSTGRES_USER", "frog"),
                password: env_or("POSTGRES_PASSWORD", "frog"),
                database: env_or("POSTGRES_DB", "analytics"),
            },
            clickhouse: ClickHouseConfig {
                url: env_or("CLICKHOUSE_HOST", "http://clickhouse:8123"),
                database: env_or("CLICKHOUSE_DB", "analytics"),
                // Node always connects as `default`; CLICKHOUSE_USER is honoured here
                // only so a local setup can differ
                user: env_or("CLICKHOUSE_USER", "default"),
                password: env_or("CLICKHOUSE_PASSWORD", ""),
                query_user: env_or("CLICKHOUSE_QUERY_USER", "hygo_query"),
                query_password: env_opt("CLICKHOUSE_QUERY_PASSWORD")
                    .unwrap_or_else(|| env_or("CLICKHOUSE_PASSWORD", "")),
                query_grant_database: env_or("CLICKHOUSE_DB", "default"),
            },
            redis: RedisConfig {
                host: env_or("REDIS_HOST", "redis"),
                port: port_from_env("REDIS_PORT", 6379)?,
                password: env_opt("REDIS_PASSWORD"),
            },
            auth: AuthConfig::from_env(),
        })
    }
}

/// `client` beside the executable, so a release directory can carry its own export.
fn default_client_dir() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(|dir| dir.join("client")))
        .unwrap_or_else(|| PathBuf::from("client"))
}

/// Node's `process.env.X === "true"`
fn flag(name: &str) -> bool {
    std::env::var(name).as_deref() == Ok("true")
}

fn env_opt(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|value| !value.is_empty())
}

fn env_or(name: &str, default: &str) -> String {
    env_opt(name).unwrap_or_else(|| default.to_string())
}

fn port_from_env(name: &str, default: u16) -> Result<u16> {
    match env_opt(name) {
        Some(value) => value.parse().with_context(|| format!("{name} must be a port number, got {value:?}")),
        None => Ok(default),
    }
}
