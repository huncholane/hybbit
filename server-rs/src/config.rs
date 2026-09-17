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
    /// Directory with script.js, rrweb.min.js and friends (PUBLIC_DIR, default ./public)
    pub public_dir: PathBuf,
    /// Directory with GeoLite2-City.mmdb and GeoLite2-ASN.mmdb (GEOIP_DIR, default: working directory, like Node)
    pub geoip_dir: PathBuf,
    pub postgres: PostgresConfig,
    pub clickhouse: ClickHouseConfig,
    pub redis: RedisConfig,
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
            public_dir: PathBuf::from(env_or("PUBLIC_DIR", "public")),
            geoip_dir: PathBuf::from(env_or("GEOIP_DIR", ".")),
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
            },
            redis: RedisConfig {
                host: env_or("REDIS_HOST", "redis"),
                port: port_from_env("REDIS_PORT", 6379)?,
                password: env_opt("REDIS_PASSWORD"),
            },
        })
    }
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
