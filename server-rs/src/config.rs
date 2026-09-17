use anyhow::{Context, Result};

/// Settings read from the same environment variables as the Node backend, so the
/// Rust container can reuse the backend service's environment block unchanged.
/// Not `Debug`: it holds credentials and must never end up in a log line.
#[derive(Clone)]
pub struct Config {
    pub port: u16,
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
