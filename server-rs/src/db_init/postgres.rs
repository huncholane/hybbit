//! `initPostgres`, ported from server/src/db/postgres/initPostgres.ts.
//!
//! Node swallows every error here (one `try`/`catch` around the whole thing, logged
//! with `console.error`) and boots anyway, so this returns `()` and logs too: a
//! backend that cannot promote an admin is still a backend that serves traffic.

use sqlx::PgPool;
use tracing::{error, info};

pub async fn init_postgres(pool: &PgPool, cloud: bool) {
    if let Err(error) = promote_oldest_user(pool).await {
        error!(%error, "Error initializing postgres");
        return;
    }

    if cloud && let Err(error) = initialize_appsumo_tables(pool).await {
        error!(%error, "Error initializing AppSumo tables:");
    }
}

/// Every boot re-asserts that the first account is an admin, whatever it is now. The
/// write is unconditional in Node, so it stays unconditional here.
async fn promote_oldest_user(pool: &PgPool) -> Result<(), sqlx::Error> {
    let oldest: Option<String> =
        sqlx::query_scalar(r#"select "id" from "user" order by "createdAt" asc limit 1"#).fetch_optional(pool).await?;

    if let Some(id) = oldest {
        sqlx::query(r#"update "user" set "role" = 'admin' where "id" = $1"#).bind(&id).execute(pool).await?;
        info!(user_id = %id, "Oldest user promoted to admin");
    }
    Ok(())
}

/// Cloud-only tables for the AppSumo licence flow. The routes that read them are not
/// ported (PORT_PLAN: no billing), but the DDL is: it is part of what a boot does, and
/// `CLOUD` is never set in this deployment, so nothing here runs in production.
async fn initialize_appsumo_tables(pool: &PgPool) -> Result<(), sqlx::Error> {
    info!("Initializing AppSumo tables...");

    sqlx::raw_sql("CREATE SCHEMA IF NOT EXISTS appsumo").execute(pool).await?;

    sqlx::raw_sql(
        r#"
      CREATE TABLE IF NOT EXISTS appsumo.licenses (
        id SERIAL PRIMARY KEY NOT NULL,
        organization_id TEXT REFERENCES organization(id),
        license_key TEXT NOT NULL UNIQUE,
        tier TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'active',
        parent_license_key TEXT,
        activated_at TIMESTAMP,
        deactivated_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
      )
    "#,
    )
    .execute(pool)
    .await?;

    sqlx::raw_sql(
        r#"
      CREATE TABLE IF NOT EXISTS appsumo.webhook_events (
        id SERIAL PRIMARY KEY NOT NULL,
        license_key TEXT NOT NULL,
        event TEXT NOT NULL,
        payload TEXT NOT NULL,
        processed_at TIMESTAMP DEFAULT NOW(),
        created_at TIMESTAMP DEFAULT NOW()
      )
    "#,
    )
    .execute(pool)
    .await?;

    info!("AppSumo schema and tables initialized successfully");
    Ok(())
}
