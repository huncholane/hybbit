use std::sync::Arc;

use anyhow::{Context, Result};
use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use sqlx::PgPool;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use tracing::info;

use crate::{
    auth::access::SitesAccessCache, clickhouse::ClickHouse, config::Config, geo::Geo, http::client_app::ClientApp,
    ingest::Ingest,
    site_config::SiteConfigCache,
};

/// Shared handles to the configuration and data stores, cloned into every handler.
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub pg: PgPool,
    pub clickhouse: ClickHouse,
    pub redis: redis::aio::ConnectionManager,
    pub site_config: Arc<SiteConfigCache>,
    pub geo: Arc<Geo>,
    /// `sitesAccessCache`: per-process, 15 s
    pub sites_access: Arc<SitesAccessCache>,
    /// Tracking pipeline services and queues
    pub ingest: Arc<Ingest>,
    /// The dashboard's static export, when CLIENT_DIR holds one
    pub client_app: Option<Arc<ClientApp>>,
}

impl AppState {
    pub async fn connect(config: Config) -> Result<Self> {
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

        let site_config = Arc::new(SiteConfigCache::new(pg.clone()));
        let geo = Arc::new(Geo::load(&config.geoip_dir).context("loading GeoLite2 databases")?);
        let client_app = ClientApp::load(&config.client_dir).map(Arc::new);

        let ingest = Arc::new(Ingest::new(redis.clone(), clickhouse.clone()));

        Ok(Self {
            config: Arc::new(config),
            pg,
            clickhouse,
            redis,
            site_config,
            geo,
            sites_access: Arc::new(SitesAccessCache::default()),
            ingest,
            client_app,
        })
    }
}
