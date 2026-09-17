use anyhow::{Context, Result};
use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use sqlx::PgPool;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use tracing::info;

use crate::{clickhouse::ClickHouse, config::Config};

/// Shared handles to the data stores, cloned into every handler.
#[derive(Clone)]
pub struct AppState {
    pub pg: PgPool,
    pub clickhouse: ClickHouse,
    pub redis: redis::aio::ConnectionManager,
}

impl AppState {
    pub async fn connect(config: &Config) -> Result<Self> {
        let pg_options = PgConnectOptions::new()
            .host(&config.postgres.host)
            .port(config.postgres.port)
            .username(&config.postgres.user)
            .password(&config.postgres.password)
            .database(&config.postgres.database);
        let pg = PgPoolOptions::new()
            .max_connections(20)
            .connect_with(pg_options)
            .await
            .context("connecting to Postgres")?;
        info!(host = %config.postgres.host, database = %config.postgres.database, "Postgres connected");

        let clickhouse = ClickHouse::new(
            &config.clickhouse.url,
            &config.clickhouse.database,
            &config.clickhouse.user,
            &config.clickhouse.password,
        )
        .context("building the ClickHouse client")?;
        clickhouse.ping().await.context("pinging ClickHouse")?;
        info!(url = %config.clickhouse.url, database = %config.clickhouse.database, "ClickHouse reachable");

        let redis_url = match &config.redis.password {
            Some(password) => format!(
                "redis://:{}@{}:{}/",
                utf8_percent_encode(password, NON_ALPHANUMERIC),
                config.redis.host,
                config.redis.port
            ),
            None => format!("redis://{}:{}/", config.redis.host, config.redis.port),
        };
        let client = redis::Client::open(redis_url).context("parsing the Redis address")?;
        let redis = redis::aio::ConnectionManager::new(client)
            .await
            .context("connecting to Redis")?;
        info!(host = %config.redis.host, "Redis connected");

        Ok(Self { pg, clickhouse, redis })
    }
}
