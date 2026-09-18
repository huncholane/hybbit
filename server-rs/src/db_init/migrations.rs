//! Drizzle's file migrator, ported from `drizzle-orm/pg-core/dialect.js`'s
//! `PgDialect.migrate` and `drizzle-orm/migrator.js`'s `readMigrationFiles`.
//!
//! `server/docker-entrypoint.sh` runs `drizzle-kit migrate` before Node starts, and
//! drizzle-kit hands the work straight to those two functions. Rust has to write
//! `drizzle.__drizzle_migrations` in exactly the format they read, or the next
//! `npm run db:generate` file would be applied twice (or not at all) depending on
//! which backend booted last.
//!
//! The bookkeeping contract, all of it load-bearing:
//!   - schema `drizzle`, table `__drizzle_migrations` (the defaults; drizzle.config.ts
//!     sets no `migrations` block), columns `id SERIAL PRIMARY KEY, hash text NOT NULL,
//!     created_at bigint`.
//!   - `hash` is the SHA-256 of the whole `.sql` file, hex, untrimmed.
//!   - `created_at` is the journal entry's `when`, not a clock reading.
//!   - what to apply is decided by one row: the newest `created_at`. Anything with a
//!     larger `when` runs, in journal order, in a single transaction. Hashes are never
//!     compared, so editing an applied migration file changes nothing.

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use tracing::info;

/// One `server/drizzle/meta/_journal.json` entry with its SQL file. Embedded at build
/// time the way `server/package.json`'s version is, so the running binary and the
/// migrations it believes in cannot drift apart on disk. `migrations_match_journal`
/// fails the build's tests if a generated migration is missing from this list.
struct Migration {
    tag: &'static str,
    /// The journal's `when`; drizzle compares it against the newest stored `created_at`
    when: i64,
    sql: &'static str,
}

const MIGRATIONS: &[Migration] = &[
    Migration { tag: "0000_premium_jubilee", when: 1773977221784, sql: include_str!("../../../server/drizzle/0000_premium_jubilee.sql") },
    Migration { tag: "0001_workable_cable", when: 1774062736532, sql: include_str!("../../../server/drizzle/0001_workable_cable.sql") },
    Migration { tag: "0002_short_bishop", when: 1774244342221, sql: include_str!("../../../server/drizzle/0002_short_bishop.sql") },
    Migration { tag: "0003_nice_xavin", when: 1774763742452, sql: include_str!("../../../server/drizzle/0003_nice_xavin.sql") },
    Migration { tag: "0004_bored_raider", when: 1777182754960, sql: include_str!("../../../server/drizzle/0004_bored_raider.sql") },
    Migration { tag: "0005_sticky_gressill", when: 1778551960948, sql: include_str!("../../../server/drizzle/0005_sticky_gressill.sql") },
    Migration { tag: "0006_orange_thunderbird", when: 1779981165610, sql: include_str!("../../../server/drizzle/0006_orange_thunderbird.sql") },
    Migration { tag: "0007_site_type", when: 1779981165611, sql: include_str!("../../../server/drizzle/0007_site_type.sql") },
    Migration { tag: "0008_black_prowler", when: 1780551464784, sql: include_str!("../../../server/drizzle/0008_black_prowler.sql") },
    Migration { tag: "0009_ambiguous_gabe_jones", when: 1781895152210, sql: include_str!("../../../server/drizzle/0009_ambiguous_gabe_jones.sql") },
    Migration { tag: "0010_tiny_diamondback", when: 1784070943021, sql: include_str!("../../../server/drizzle/0010_tiny_diamondback.sql") },
    Migration { tag: "0011_neat_starhawk", when: 1784173607652, sql: include_str!("../../../server/drizzle/0011_neat_starhawk.sql") },
    Migration { tag: "0012_perfect_nebula", when: 1784511287442, sql: include_str!("../../../server/drizzle/0012_perfect_nebula.sql") },
    Migration { tag: "0013_square_bloodaxe", when: 1784659838680, sql: include_str!("../../../server/drizzle/0013_square_bloodaxe.sql") },
    Migration { tag: "0014_huge_dagger", when: 1786751242462, sql: include_str!("../../../server/drizzle/0014_huge_dagger.sql") },
    Migration { tag: "0015_round_trish_tilby", when: 1788371100067, sql: include_str!("../../../server/drizzle/0015_round_trish_tilby.sql") },
    Migration { tag: "0016_shocking_vance_astro", when: 1788386038776, sql: include_str!("../../../server/drizzle/0016_shocking_vance_astro.sql") },
    Migration { tag: "0017_burly_nick_fury", when: 1788393490335, sql: include_str!("../../../server/drizzle/0017_burly_nick_fury.sql") },
    Migration { tag: "0018_keen_silk_fever", when: 1789081353359, sql: include_str!("../../../server/drizzle/0018_keen_silk_fever.sql") },
    Migration { tag: "0019_cultured_lizard", when: 1789084287930, sql: include_str!("../../../server/drizzle/0019_cultured_lizard.sql") },
    Migration { tag: "0020_loving_silhouette", when: 1789085773946, sql: include_str!("../../../server/drizzle/0020_loving_silhouette.sql") },
];

/// `readMigrationFiles` splits on the marker and keeps the pieces verbatim: no trim,
/// no empty-chunk filtering. A chunk can hold several `;`-separated statements, which
/// is why they go out over the simple query protocol (`raw_sql`) like node-postgres
/// sends them.
const STATEMENT_BREAKPOINT: &str = "--> statement-breakpoint";

const MIGRATIONS_SCHEMA: &str = "drizzle";
const MIGRATIONS_TABLE: &str = "__drizzle_migrations";

pub async fn migrate(pool: &PgPool) -> Result<()> {
    sqlx::raw_sql(&format!(r#"CREATE SCHEMA IF NOT EXISTS "{MIGRATIONS_SCHEMA}""#))
        .execute(pool)
        .await
        .context("creating the drizzle schema")?;
    sqlx::raw_sql(&format!(
        r#"CREATE TABLE IF NOT EXISTS "{MIGRATIONS_SCHEMA}"."{MIGRATIONS_TABLE}" (
            id SERIAL PRIMARY KEY,
            hash text NOT NULL,
            created_at bigint
        )"#
    ))
    .execute(pool)
    .await
    .context("creating the drizzle migrations table")?;

    // `Number(undefined_row)` never happens in drizzle because it guards on the row
    // existing, and `Number(null)` is 0, so a missing row and a NULL created_at both
    // mean "apply everything".
    let last_created_at: i64 = sqlx::query_scalar::<_, Option<i64>>(&format!(
        r#"select created_at from "{MIGRATIONS_SCHEMA}"."{MIGRATIONS_TABLE}" order by created_at desc limit 1"#
    ))
    .fetch_optional(pool)
    .await
    .context("reading the applied drizzle migrations")?
    .flatten()
    .unwrap_or(0);

    let pending: Vec<&Migration> = MIGRATIONS.iter().filter(|migration| last_created_at < migration.when).collect();
    if pending.is_empty() {
        info!(last_created_at, "Drizzle migrations up to date");
        return Ok(());
    }

    let mut tx = pool.begin().await.context("opening the migration transaction")?;
    for migration in &pending {
        for statement in migration.sql.split(STATEMENT_BREAKPOINT) {
            sqlx::raw_sql(statement)
                .execute(&mut *tx)
                .await
                .with_context(|| format!("applying migration {}", migration.tag))?;
        }
        sqlx::query(&format!(
            r#"insert into "{MIGRATIONS_SCHEMA}"."{MIGRATIONS_TABLE}" ("hash", "created_at") values($1, $2)"#
        ))
        .bind(hash(migration.sql))
        .bind(migration.when)
        .execute(&mut *tx)
        .await
        .with_context(|| format!("recording migration {}", migration.tag))?;
    }
    tx.commit().await.context("committing the migrations")?;

    info!(
        applied = pending.len(),
        through = pending.last().map(|migration| migration.tag),
        "Drizzle migrations applied"
    );
    Ok(())
}

fn hash(sql: &str) -> String {
    hex::encode(Sha256::digest(sql.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The embedded list is written by hand, so this is what stops a
    /// `npm run db:generate` file from silently never being applied by Rust.
    #[test]
    fn migrations_match_journal() {
        let root = concat!(env!("CARGO_MANIFEST_DIR"), "/../server/drizzle");
        let journal: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(format!("{root}/meta/_journal.json")).unwrap()).unwrap();
        let entries = journal["entries"].as_array().unwrap();

        assert_eq!(entries.len(), MIGRATIONS.len(), "journal entry count");
        for (entry, migration) in entries.iter().zip(MIGRATIONS) {
            assert_eq!(entry["tag"].as_str().unwrap(), migration.tag);
            assert_eq!(entry["when"].as_i64().unwrap(), migration.when, "{}", migration.tag);
            let on_disk = std::fs::read_to_string(format!("{root}/{}.sql", migration.tag)).unwrap();
            assert_eq!(on_disk, migration.sql, "{} contents", migration.tag);
        }
    }

    /// Journal order is apply order, and the "newest created_at wins" rule silently
    /// skips anything out of order.
    #[test]
    fn journal_is_ordered_by_when() {
        for pair in MIGRATIONS.windows(2) {
            assert!(pair[0].when < pair[1].when, "{} then {}", pair[0].tag, pair[1].tag);
        }
    }

    /// Pinned against `crypto.createHash("sha256").update(file).digest("hex")` run over
    /// the same files, so a change to how the file is read shows up here.
    #[test]
    fn hashes_match_drizzle() {
        assert_eq!(hash(MIGRATIONS[0].sql), "3a737ac0c91d9b4f387a612a1a601ca5303d81c5a51ef3044283871eb2e0465f");
        assert_eq!(hash(MIGRATIONS[7].sql), "a58aaf7b287fa12076eafaa34cc9fd9ae565ec2bda58c1a7825201aa097386f6");
        assert_eq!(
            hash(MIGRATIONS[MIGRATIONS.len() - 1].sql),
            "ac82b6d69aa22421be25b94018c0c512e25df687f0929618344bae113c5ebdab"
        );
    }

    /// `String.split` keeps every piece; none of the files splits into a blank one, and
    /// Postgres would reject an empty simple query.
    #[test]
    fn no_statement_is_blank() {
        for migration in MIGRATIONS {
            for statement in migration.sql.split(STATEMENT_BREAKPOINT) {
                assert!(!statement.trim().is_empty(), "blank statement in {}", migration.tag);
            }
        }
    }
}
