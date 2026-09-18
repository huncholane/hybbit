//! Everything a boot does to the databases before the first request is served.
//!
//! Under Node this is two things in two places: `server/docker-entrypoint.sh` runs
//! `drizzle-kit migrate` and then `server/src/index.ts` runs
//! `Promise.all([initializeClickhouse(), initPostgres()])`. Rust owns both, so a
//! deployment with no Node container still comes up on an empty Postgres and an empty
//! ClickHouse, and still heals an existing one.
//!
//! Ordering is Node's: migrations first (`initPostgres` promotes an admin in a table
//! only a migration creates), then the two initialisers together.
//!
//! Failure behaviour is Node's too, and it is not uniform:
//!   - migrations fatal (`set -e` in the entrypoint),
//!   - ClickHouse init fatal (`execClickhouseInitStep` rethrows, `start()` exits 1),
//!   - Postgres init logged and survived (`initPostgres` catches everything),
//!   - the ClickHouse query user logged and survived (it catches its own errors).
//!
//! Node skips all of it in a cluster worker because the primary already ran it. This
//! deployment is one process per container, so it always runs.

mod clickhouse;
mod migrations;
mod postgres;
mod query_user;

use anyhow::{Context, Result};
use sqlx::PgPool;

use crate::{clickhouse::ClickHouse, config::Config};

pub async fn run(pg: &PgPool, clickhouse: &ClickHouse, config: &Config) -> Result<()> {
    migrations::migrate(pg).await.context("running the drizzle migrations")?;

    let clickhouse_init =
        clickhouse::initialize_clickhouse(clickhouse, &config.clickhouse, config.auth.cloud, config.lite_dashboard);
    let postgres_init = postgres::init_postgres(pg, config.auth.cloud);

    let (clickhouse_result, ()) = tokio::join!(clickhouse_init, postgres_init);
    clickhouse_result.context("initializing ClickHouse")
}
