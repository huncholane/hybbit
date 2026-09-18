//! `initializeClickhouse`, ported from server/src/db/clickhouse/{clickhouse,initUtils}.ts
//! and schema/{core,cloud,liteDashboard}.ts.
//!
//! The DDL is copied verbatim, comments included, so a diff against the TypeScript is
//! a diff of the text and not of the formatting. ClickHouse normalises what it stores,
//! so only column order, types, defaults, engine, key and TTL survive into
//! `SHOW CREATE TABLE`; keeping the statements identical is what makes the two
//! backends produce the same schema byte for byte.
//!
//! The database itself is not created here: the compose file's `CLICKHOUSE_DB` makes
//! it, exactly as under Node.

use anyhow::{Context, Result};
use serde::Deserialize;
use tracing::{debug, info};

use crate::{clickhouse::ClickHouse, config::ClickHouseConfig};

use super::query_user;

pub async fn initialize_clickhouse(clickhouse: &ClickHouse, config: &ClickHouseConfig, cloud: bool, lite: bool) -> Result<()> {
    initialize_core_tables(clickhouse).await?;

    if cloud {
        initialize_cloud_tables(clickhouse).await?;
    }

    if lite {
        initialize_lite_dashboard_mvs(clickhouse).await?;
    }

    query_user::provision_query_user(clickhouse, config).await;
    Ok(())
}

/// `execClickhouseInitStep`. Node also takes an `optional` flag that swallows the
/// error, but no step in the schema files sets it, so a failing step is always fatal
/// here as it is there.
async fn exec_step(clickhouse: &ClickHouse, step: &str, query: &str, lock_acquire_timeout_seconds: Option<u32>) -> Result<()> {
    let settings = match lock_acquire_timeout_seconds {
        Some(seconds) => vec![("lock_acquire_timeout", seconds.to_string())],
        None => Vec::new(),
    };
    clickhouse
        .exec(query, &settings)
        .await
        .with_context(|| format!("ClickHouse initialization step failed: {step}"))
}

#[derive(Deserialize)]
struct NameRow {
    name: String,
}

async fn table_columns(clickhouse: &ClickHouse, table: &str) -> Result<Vec<String>> {
    let rows: Vec<NameRow> = clickhouse
        .query(
            r#"
      SELECT name
      FROM system.columns
      WHERE database = currentDatabase()
        AND table = {table:String}
    "#,
            &[("table", table.to_string())],
        )
        .await
        .with_context(|| format!("reading the columns of {table}"))?;
    Ok(rows.into_iter().map(|row| row.name).collect())
}

#[derive(Deserialize)]
struct CreateQueryRow {
    create_table_query: String,
}

async fn table_create_query(clickhouse: &ClickHouse, table: &str) -> Result<Option<String>> {
    let rows: Vec<CreateQueryRow> = clickhouse
        .query(
            r#"
      SELECT create_table_query
      FROM system.tables
      WHERE database = currentDatabase()
        AND name = {table:String}
      LIMIT 1
    "#,
            &[("table", table.to_string())],
        )
        .await
        .with_context(|| format!("reading the definition of {table}"))?;
    Ok(rows.into_iter().next().map(|row| row.create_table_query))
}

/// `timestamp` is part of the MergeTree key and ClickHouse forbids widening a
/// key column in place. Keep it for partition pruning; use this additive
/// column wherever event order matters. Old rows read as whole-second values.
const EVENTS_COLUMNS_TO_ENSURE: &[(&str, &str)] = &[
    ("timestamp_ms", "timestamp_ms DateTime64(3) DEFAULT toDateTime64(timestamp, 3) AFTER timestamp"),
    ("lcp", "lcp Nullable(Float64)"),
    ("cls", "cls Nullable(Float64)"),
    ("inp", "inp Nullable(Float64)"),
    ("fcp", "fcp Nullable(Float64)"),
    ("ttfb", "ttfb Nullable(Float64)"),
    ("ip", "ip Nullable(String)"),
    ("timezone", "timezone LowCardinality(String) DEFAULT ''"),
    ("identified_user_id", "identified_user_id String DEFAULT ''"),
    ("import_id", "import_id Nullable(UUID)"),
    ("tag", "tag LowCardinality(String) DEFAULT ''"),
    ("feature_flags", "feature_flags Map(String, String) DEFAULT map()"),
    ("asn", "asn Nullable(UInt32)"),
    ("asn_org", "asn_org LowCardinality(String) DEFAULT ''"),
    ("is_datacenter_asn", "is_datacenter_asn UInt8 DEFAULT 0"),
];

const BOT_EVENTS_COLUMNS_TO_ENSURE: &[(&str, &str)] = &[
    // Prod tables created before session_id landed in the CREATE statement lack
    // it; the insert already sends it, so healing the column starts populating it.
    ("session_id", "session_id String DEFAULT ''"),
    // Null = the client sent no score and the server inferred nothing.
    ("client_bot_score", "client_bot_score Nullable(UInt8)"),
    ("client_signal_mask", "client_signal_mask UInt16 DEFAULT 0"),
    // Which anomaly rules fired and what they summed to. "Rate anomaly" is a
    // dozen rules with different meanings, so without these an audit row cannot
    // say why the request was convicted.
    ("anomaly_reasons", "anomaly_reasons String DEFAULT ''"),
    ("anomaly_score", "anomaly_score UInt8 DEFAULT 0"),
    // Bot identity. `matched_ua_pattern` stores a regex source, which is evidence
    // but not an answer to "who is this"; these carry the name the operator
    // publishes. Empty on rows written before the columns existed; nothing is
    // backfilled, so readers must tolerate ''.
    ("bot_name", "bot_name LowCardinality(String) DEFAULT ''"),
    ("bot_operator", "bot_operator LowCardinality(String) DEFAULT ''"),
    ("bot_purpose", "bot_purpose LowCardinality(String) DEFAULT ''"),
    // The curated provider behind the request's ASN, resolved during detection
    // and until now discarded. A UA can claim any name; this is the independent
    // half of the claim, so the two together are what makes attribution arguable.
    ("asn_provider", "asn_provider LowCardinality(String) DEFAULT ''"),
];

/// Node builds one ALTER out of the definitions of the columns that are missing, so
/// the statement's text depends on the table it finds. Reproduced rather than
/// simplified to an unconditional ALTER: even a no-op ALTER takes the table's ALTER
/// lock, which on `events` is the expensive part.
async fn ensure_missing_columns(
    clickhouse: &ClickHouse,
    table: &str,
    step: &str,
    wanted: &[(&str, &str)],
    up_to_date_message: &str,
) -> Result<()> {
    let existing = table_columns(clickhouse, table).await?;
    let missing: Vec<&(&str, &str)> =
        wanted.iter().filter(|(name, _)| !existing.iter().any(|column| column == name)).collect();

    if missing.is_empty() {
        debug!(table, "{up_to_date_message}");
        return Ok(());
    }

    let names: Vec<&str> = missing.iter().map(|(name, _)| *name).collect();
    info!(table, ?names, "Adding missing table columns");

    let additions: Vec<String> =
        missing.iter().map(|(_, definition)| format!("ADD COLUMN IF NOT EXISTS {definition}")).collect();
    exec_step(clickhouse, step, &format!("\n      ALTER TABLE {table}\n        {}\n      ", additions.join(",\n        ")), Some(15))
        .await
}

async fn initialize_core_tables(clickhouse: &ClickHouse) -> Result<()> {
    exec_step(
        clickhouse,
        "create events table",
        r#"
      CREATE TABLE IF NOT EXISTS events (
        site_id UInt16,
        timestamp DateTime,
        timestamp_ms DateTime64(3) DEFAULT toDateTime64(timestamp, 3),
        session_id String,
        user_id String,
        hostname String,
        pathname String,
        querystring String, /* URL parameters stored in raw format */
        url_parameters Map(String, String), /* Structured storage for all URL parameters */
        page_title String,
        referrer String,
        channel String,
        browser LowCardinality(String),
        browser_version LowCardinality(String),
        operating_system LowCardinality(String),
        operating_system_version LowCardinality(String),
        language LowCardinality(String),
        country LowCardinality(FixedString(2)),
        region LowCardinality(String),
        city String,
        lat Float64,
        lon Float64,
        screen_width UInt16,
        screen_height UInt16,
        device_type LowCardinality(String),
        type LowCardinality(String) DEFAULT 'pageview',
        event_name String,
        props JSON,
        lcp Nullable(Float64),
        cls Nullable(Float64),
        inp Nullable(Float64),
        fcp Nullable(Float64),
        ttfb Nullable(Float64),
        ip Nullable(String),
        timezone LowCardinality(String) DEFAULT '',
        identified_user_id String DEFAULT '',
        import_id Nullable(UUID),
        tag LowCardinality(String) DEFAULT '',
        feature_flags Map(String, String) DEFAULT map(),
        asn Nullable(UInt32),
        asn_org LowCardinality(String) DEFAULT '',
        is_datacenter_asn UInt8 DEFAULT 0
      )
      ENGINE = MergeTree()
      PARTITION BY toYYYYMM(timestamp)
      ORDER BY (site_id, timestamp)
      "#,
        None,
    )
    .await?;

    // Heal tables created by older versions (or by the window where the CREATE
    // TABLE above was missing these columns).
    ensure_missing_columns(
        clickhouse,
        "events",
        "add missing events columns",
        EVENTS_COLUMNS_TO_ENSURE,
        "Events table columns are up to date",
    )
    .await?;

    exec_step(
        clickhouse,
        "create bot events table",
        r#"
      CREATE TABLE IF NOT EXISTS bot_events (
        site_id UInt16,
        timestamp DateTime,
        session_id String,
        user_id String,
        hostname String,
        pathname String,
        querystring String,
        referrer String,
        browser LowCardinality(String),
        browser_version LowCardinality(String),
        operating_system LowCardinality(String),
        operating_system_version LowCardinality(String),
        country LowCardinality(FixedString(2)),
        region LowCardinality(String),
        city String,
        lat Float64,
        lon Float64,
        screen_width UInt16,
        screen_height UInt16,
        device_type LowCardinality(String),
        type LowCardinality(String) DEFAULT 'pageview',
        asn Nullable(UInt32),
        asn_org String DEFAULT '',
        detected_ua_pattern Bool DEFAULT false,
        detected_header_heuristics Bool DEFAULT false,
        detected_client_signals Bool DEFAULT false,
        detected_bot_asn Bool DEFAULT false,
        detected_rate_anomaly Bool DEFAULT false,
        matched_ua_pattern String DEFAULT '',
        bot_category LowCardinality(String) DEFAULT '',
        client_bot_score Nullable(UInt8),
        client_signal_mask UInt16 DEFAULT 0,
        anomaly_reasons String DEFAULT '',
        anomaly_score UInt8 DEFAULT 0,
        bot_name LowCardinality(String) DEFAULT '',
        bot_operator LowCardinality(String) DEFAULT '',
        bot_purpose LowCardinality(String) DEFAULT '',
        asn_provider LowCardinality(String) DEFAULT ''
      )
      ENGINE = MergeTree()
      PARTITION BY toYYYYMM(timestamp)
      ORDER BY (site_id, timestamp)
      TTL timestamp + INTERVAL 3 MONTH
      "#,
        None,
    )
    .await?;

    ensure_bot_events_columns(clickhouse, "bot_events").await?;

    // Forensic mirror of bot_events for sites with bot blocking turned OFF: the
    // event is still tracked normally, and this row is the only trace that
    // detection fired. Columns match bot_events exactly so the same analysis
    // queries run against either table; only the TTL is shorter.
    exec_step(
        clickhouse,
        "create bot observations table",
        r#"
      CREATE TABLE IF NOT EXISTS bot_observations (
        site_id UInt16,
        timestamp DateTime,
        session_id String,
        user_id String,
        hostname String,
        pathname String,
        querystring String,
        referrer String,
        browser LowCardinality(String),
        browser_version LowCardinality(String),
        operating_system LowCardinality(String),
        operating_system_version LowCardinality(String),
        country LowCardinality(FixedString(2)),
        region LowCardinality(String),
        city String,
        lat Float64,
        lon Float64,
        screen_width UInt16,
        screen_height UInt16,
        device_type LowCardinality(String),
        type LowCardinality(String) DEFAULT 'pageview',
        asn Nullable(UInt32),
        asn_org String DEFAULT '',
        detected_ua_pattern Bool DEFAULT false,
        detected_header_heuristics Bool DEFAULT false,
        detected_client_signals Bool DEFAULT false,
        detected_bot_asn Bool DEFAULT false,
        detected_rate_anomaly Bool DEFAULT false,
        matched_ua_pattern String DEFAULT '',
        bot_category LowCardinality(String) DEFAULT '',
        client_bot_score Nullable(UInt8),
        client_signal_mask UInt16 DEFAULT 0,
        anomaly_reasons String DEFAULT '',
        anomaly_score UInt8 DEFAULT 0,
        bot_name LowCardinality(String) DEFAULT '',
        bot_operator LowCardinality(String) DEFAULT '',
        bot_purpose LowCardinality(String) DEFAULT '',
        asn_provider LowCardinality(String) DEFAULT ''
      )
      ENGINE = MergeTree()
      PARTITION BY toYYYYMM(timestamp)
      ORDER BY (site_id, timestamp)
      TTL timestamp + INTERVAL 30 DAY
      "#,
        None,
    )
    .await?;

    ensure_bot_events_columns(clickhouse, "bot_observations").await?;

    exec_step(
        clickhouse,
        "create session replay events table",
        r#"
      CREATE TABLE IF NOT EXISTS session_replay_events (
        site_id UInt16,
        session_id String,
        user_id String,
        timestamp DateTime64(3),
        event_type LowCardinality(String),
        event_data String,
        event_data_key Nullable(String), -- R2 storage key for cloud deployments
        batch_index Nullable(UInt16), -- Index within the R2 batch
        sequence_number UInt32,
        event_size_bytes UInt32,
        viewport_width Nullable(UInt16),
        viewport_height Nullable(UInt16),
        is_complete UInt8 DEFAULT 0
      )
      ENGINE = MergeTree()
      PARTITION BY toYYYYMM(timestamp)
      ORDER BY (site_id, session_id, sequence_number)
      TTL toDateTime(timestamp) + INTERVAL 30 DAY
      "#,
        None,
    )
    .await?;

    exec_step(
        clickhouse,
        "add session replay events columns",
        r#"
      ALTER TABLE session_replay_events
        ADD COLUMN IF NOT EXISTS event_data_key Nullable(String), -- R2 storage key for cloud deployments
        ADD COLUMN IF NOT EXISTS batch_index Nullable(UInt16), -- Index within the R2 batch
        ADD COLUMN IF NOT EXISTS identified_user_id String DEFAULT ''
      "#,
        None,
    )
    .await?;

    exec_step(
        clickhouse,
        "create session replay metadata table",
        r#"
      CREATE TABLE IF NOT EXISTS session_replay_metadata (
        site_id UInt16,
        session_id String,
        user_id String,
        start_time DateTime,
        end_time Nullable(DateTime),
        duration_ms Nullable(UInt32),
        event_count UInt32,
        compressed_size_bytes UInt32,
        page_url String,
        country LowCardinality(FixedString(2)),
        region LowCardinality(String),
        city String,
        lat Float64,
        lon Float64,
        browser LowCardinality(String),
        browser_version LowCardinality(String),
        operating_system LowCardinality(String),
        operating_system_version LowCardinality(String),
        language LowCardinality(String),
        screen_width UInt16,
        screen_height UInt16,
        device_type LowCardinality(String),
        channel String,
        hostname String,
        referrer String,
        has_replay_data UInt8 DEFAULT 1,
        created_at DateTime DEFAULT now()
      )
      ENGINE = ReplacingMergeTree(created_at)
      PARTITION BY toYYYYMM(start_time)
      ORDER BY (site_id, session_id)
      TTL start_time + INTERVAL 30 DAY
      "#,
        None,
    )
    .await?;

    exec_step(
        clickhouse,
        "add session replay metadata columns",
        r#"
      ALTER TABLE session_replay_metadata
        ADD COLUMN IF NOT EXISTS identified_user_id String DEFAULT ''
      "#,
        None,
    )
    .await?;

    // Successor to session_replay_metadata. The old table is a
    // ReplacingMergeTree holding one cumulative row per session, so every replay
    // batch had to re-derive that row: SELECT MIN/MAX/COUNT/SUM over the whole
    // session, then rewrite it. That read scanned 818 B rows in six days, 76% of
    // everything the cluster read, and the rewrites left 2.5 M single-row parts.
    //
    // Aggregating the columns instead lets each batch insert only what it
    // observed, and the engine does the combining. Nothing reads back during
    // ingest. Every column keeps its name and its post-merge meaning, so readers
    // only need FINAL, which they already used.
    //
    // duration_ms and created_at are deliberately absent: duration is derived
    // from the merged bounds at read time, and there is no version column to
    // order by any more.
    exec_step(
        clickhouse,
        "create session replay metadata v2 table",
        r#"
      CREATE TABLE IF NOT EXISTS session_replay_metadata_v2 (
        site_id UInt16,
        session_id String,
        user_id SimpleAggregateFunction(anyLast, String),
        -- Rows arrive with '' until the visitor identifies, and max() over a
        -- String makes any real id win over the empty one.
        identified_user_id SimpleAggregateFunction(max, String),
        -- Millisecond resolution, matching session_replay_events.timestamp:
        -- duration is now derived from these bounds instead of being stored,
        -- and second-resolution columns would floor a 900ms replay to 0.
        start_time SimpleAggregateFunction(min, DateTime64(3)),
        end_time SimpleAggregateFunction(max, Nullable(DateTime64(3))),
        event_count SimpleAggregateFunction(sum, UInt64),
        compressed_size_bytes SimpleAggregateFunction(sum, UInt64),
        -- KNOWN LIMITATION. These merge independently, so a session whose
        -- batches disagreed can assemble a row from more than one of them,
        -- where the old ReplacingMergeTree always returned one whole
        -- batch's snapshot. Measured over 30 days of production, of the 423 sessions
        -- that had more than one metadata version: page_url differed in 62,
        -- region/city/lat in 18, country in 11, language in 13; browser,
        -- operating_system, device_type, channel, hostname, referrer and
        -- user_id never differed at all.
        --
        -- The geo group is the one that matters, because those fields are only
        -- meaningful together: ~4% of multi-version sessions could show a city
        -- and a country drawn from different batches. Making them coherent
        -- needs one versioned snapshot (a max() over a leading-version tuple,
        -- or argMaxState + GROUP BY), which changes every read site.
        --
        -- Weighed and accepted, 2026-08: the exposure is narrow and the fix
        -- costs more than the defect. Don't re-open it without new evidence
        -- that mixed geo is actually misleading someone.
        page_url SimpleAggregateFunction(anyLast, String),
        country SimpleAggregateFunction(anyLast, LowCardinality(FixedString(2))),
        region SimpleAggregateFunction(anyLast, LowCardinality(String)),
        city SimpleAggregateFunction(anyLast, String),
        lat SimpleAggregateFunction(anyLast, Float64),
        lon SimpleAggregateFunction(anyLast, Float64),
        browser SimpleAggregateFunction(anyLast, LowCardinality(String)),
        browser_version SimpleAggregateFunction(anyLast, LowCardinality(String)),
        operating_system SimpleAggregateFunction(anyLast, LowCardinality(String)),
        operating_system_version SimpleAggregateFunction(anyLast, LowCardinality(String)),
        language SimpleAggregateFunction(anyLast, LowCardinality(String)),
        screen_width SimpleAggregateFunction(max, UInt16),
        screen_height SimpleAggregateFunction(max, UInt16),
        device_type SimpleAggregateFunction(anyLast, LowCardinality(String)),
        channel SimpleAggregateFunction(anyLast, String),
        hostname SimpleAggregateFunction(anyLast, String),
        referrer SimpleAggregateFunction(anyLast, String),
        has_replay_data SimpleAggregateFunction(max, UInt8)
      )
      ENGINE = AggregatingMergeTree()
      PARTITION BY toYYYYMM(start_time)
      ORDER BY (site_id, session_id)
      TTL toDateTime(start_time) + INTERVAL 30 DAY
      "#,
        None,
    )
    .await?;

    Ok(())
}

// Runs against both audit tables: they carry the same columns on purpose, so a
// column added to one has to reach the other or the shared queries stop working.
async fn ensure_bot_events_columns(clickhouse: &ClickHouse, table: &str) -> Result<()> {
    ensure_missing_columns(
        clickhouse,
        table,
        &format!("add missing {table} columns"),
        BOT_EVENTS_COLUMNS_TO_ENSURE,
        "Bot events table columns are up to date",
    )
    .await
}

// Hourly per-site event counts, used by cloud usage tracking / billing.
async fn initialize_cloud_tables(clickhouse: &ClickHouse) -> Result<()> {
    exec_step(
        clickhouse,
        "create hourly events by site target table",
        r#"
      CREATE TABLE IF NOT EXISTS hourly_events_by_site_mv_target (
        event_hour DateTime,          -- The specific hour
        site_id UInt16,
        event_count UInt64            -- The count of events for that site in that hour
      )
      ENGINE = SummingMergeTree()     -- Sums 'event_count' for rows with the same sorting key
      PARTITION BY toYYYYMM(event_hour)
      ORDER BY (event_hour, site_id)
      TTL event_hour + INTERVAL 60 DAY
    "#,
        None,
    )
    .await?;

    exec_step(
        clickhouse,
        "create hourly events by site materialized view",
        r#"
      CREATE MATERIALIZED VIEW IF NOT EXISTS hourly_events_by_site_mv
      TO hourly_events_by_site_mv_target -- Name of the target table
      AS SELECT
        toStartOfHour(timestamp) AS event_hour,
        site_id,
        count() AS event_count
      FROM events
      GROUP BY event_hour, site_id
    "#,
        None,
    )
    .await
}

const SESSION_HOURLY_MV_NAME: &str = "session_hourly_mv";
const SESSION_HOURLY_MV_REFRESH_INTERVAL: &str = "REFRESH EVERY 1 HOUR";
const SESSION_HOURLY_MV_SOURCE: &str = "sessions_mv_target FINAL";

const SESSION_HOURLY_MV_CREATE_QUERY: &str = r#"
  CREATE MATERIALIZED VIEW session_hourly_mv
  REFRESH EVERY 1 HOUR
  TO session_hourly_mv_target
  AS
  SELECT
    site_id,
    toStartOfHour(start_time) AS session_hour,
    count() AS sessions,
    sum(session_pageviews) AS pageviews,
    uniqState(user_id) AS users,
    sum(toUInt64(end_time - start_time)) AS total_session_duration_seconds,
    countIf(session_pageviews = 1) AS bounced_sessions
  FROM (
    SELECT
      site_id,
      user_id,
      start_time,
      end_time,
      pageviews AS session_pageviews
    FROM sessions_mv_target FINAL
  ) AS sessions
  GROUP BY site_id, session_hour
"#;

async fn ensure_session_hourly_materialized_view(clickhouse: &ClickHouse) -> Result<()> {
    let existing = table_create_query(clickhouse, SESSION_HOURLY_MV_NAME).await?;
    let is_current = existing.as_ref().is_some_and(|query| {
        query.contains(SESSION_HOURLY_MV_REFRESH_INTERVAL) && query.contains(SESSION_HOURLY_MV_SOURCE)
    });

    if is_current {
        debug!("Session hourly materialized view is up to date");
        return Ok(());
    }

    if existing.is_some() {
        info!("Replacing outdated session hourly materialized view");
        exec_step(
            clickhouse,
            "drop outdated session hourly materialized view",
            &format!("DROP VIEW IF EXISTS {SESSION_HOURLY_MV_NAME} SYNC"),
            Some(15),
        )
        .await?;
    }

    exec_step(clickhouse, "create session hourly materialized view", SESSION_HOURLY_MV_CREATE_QUERY, None).await
}

// Materialized views that back the simplified high-traffic dashboard.
// All views are hourly-bucketed and feed the lite endpoints; raw `events`
// is still queried for filters that aren't keyed in these MVs.
async fn initialize_lite_dashboard_mvs(clickhouse: &ClickHouse) -> Result<()> {
    // Per-session rollup. Replaces the AllSessionPageviews / FilteredSessions
    // CTEs that getOverview and getOverviewBucketed run over raw events.
    //
    // This is a streaming MV: it fires once per inserted block and writes a
    // PARTIAL session row for whatever events were in that block. AggregatingMergeTree
    // then composes the SimpleAggregateFunction columns (min/max/sum) across parts
    // sharing (site_id, session_id), and the read queries additionally re-aggregate
    // by session_id at query time, so pageviews/start_time/end_time are always
    // correct even before merges complete.
    //
    // The plain metadata columns below (country, region, device_type, browser,
    // operating_system, hostname) are session-INVARIANT, so every partial row of a
    // session carries the same value and `any()` is well-defined. Entry/acquisition
    // attributes (entry_page, referrer, channel) are deliberately NOT stored here:
    // they are first-event values that differ across a session's blocks, can't be
    // composed correctly per-partial-row, and so are served by the raw-events
    // fallback instead (see LITE_SESSION_FILTER_COLUMNS in lite/utils.ts).
    exec_step(
        clickhouse,
        "create sessions rollup target table",
        r#"
      CREATE TABLE IF NOT EXISTS sessions_mv_target (
        site_id UInt16,
        session_id String,
        user_id String,
        start_time SimpleAggregateFunction(min, DateTime),
        end_time SimpleAggregateFunction(max, DateTime),
        pageviews SimpleAggregateFunction(sum, UInt64),
        events SimpleAggregateFunction(sum, UInt64),
        country LowCardinality(FixedString(2)),
        region LowCardinality(String),
        device_type LowCardinality(String),
        browser LowCardinality(String),
        operating_system LowCardinality(String),
        hostname String,
        last_seen SimpleAggregateFunction(max, DateTime)
      )
      ENGINE = AggregatingMergeTree()
      PARTITION BY toYYYYMM(start_time)
      ORDER BY (site_id, session_id)
    "#,
        None,
    )
    .await?;

    exec_step(
        clickhouse,
        "create sessions rollup materialized view",
        r#"
      CREATE MATERIALIZED VIEW IF NOT EXISTS sessions_mv
      TO sessions_mv_target
      AS SELECT
        site_id,
        session_id,
        any(user_id) AS user_id,
        min(timestamp) AS start_time,
        max(timestamp) AS end_time,
        countIf(type = 'pageview') AS pageviews,
        count() AS events,
        any(country) AS country,
        any(region) AS region,
        any(device_type) AS device_type,
        any(browser) AS browser,
        any(operating_system) AS operating_system,
        any(hostname) AS hostname,
        max(timestamp) AS last_seen
      FROM events
      GROUP BY site_id, session_id
    "#,
        None,
    )
    .await?;

    // Hourly overview rollup. Drives the bucketed chart and overview cards.
    exec_step(
        clickhouse,
        "create hourly overview rollup target table",
        r#"
      CREATE TABLE IF NOT EXISTS overview_hourly_mv_target (
        site_id UInt16,
        event_hour DateTime,
        pageviews SimpleAggregateFunction(sum, UInt64),
        events SimpleAggregateFunction(sum, UInt64),
        users AggregateFunction(uniq, String),
        sessions AggregateFunction(uniq, String)
      )
      ENGINE = AggregatingMergeTree()
      PARTITION BY toYYYYMM(event_hour)
      ORDER BY (site_id, event_hour)
    "#,
        None,
    )
    .await?;

    exec_step(
        clickhouse,
        "create hourly overview rollup materialized view",
        r#"
      CREATE MATERIALIZED VIEW IF NOT EXISTS overview_hourly_mv
      TO overview_hourly_mv_target
      AS SELECT
        site_id,
        toStartOfHour(timestamp) AS event_hour,
        countIf(type = 'pageview') AS pageviews,
        count() AS events,
        uniqState(user_id) AS users,
        uniqState(session_id) AS sessions
      FROM events
      GROUP BY site_id, event_hour
    "#,
        None,
    )
    .await?;

    // Top-pathname rollup. Cardinality is bounded by hour, so high-URL sites
    // still get smaller-than-raw storage. Filtered queries fall back to events.
    exec_step(
        clickhouse,
        "create hourly pathname rollup target table",
        r#"
      CREATE TABLE IF NOT EXISTS pathname_hourly_mv_target (
        site_id UInt16,
        event_hour DateTime,
        pathname String,
        hostname String,
        pageviews SimpleAggregateFunction(sum, UInt64),
        users AggregateFunction(uniq, String),
        sessions AggregateFunction(uniq, String)
      )
      ENGINE = AggregatingMergeTree()
      PARTITION BY toYYYYMM(event_hour)
      ORDER BY (site_id, event_hour, pathname)
    "#,
        None,
    )
    .await?;

    exec_step(
        clickhouse,
        "create hourly pathname rollup materialized view",
        r#"
      CREATE MATERIALIZED VIEW IF NOT EXISTS pathname_hourly_mv
      TO pathname_hourly_mv_target
      AS SELECT
        site_id,
        toStartOfHour(timestamp) AS event_hour,
        pathname,
        any(hostname) AS hostname,
        countIf(type = 'pageview') AS pageviews,
        uniqState(user_id) AS users,
        uniqState(session_id) AS sessions
      FROM events
      WHERE type = 'pageview'
      GROUP BY site_id, event_hour, pathname
    "#,
        None,
    )
    .await?;

    // Country/region rollup. Cardinality is naturally bounded.
    exec_step(
        clickhouse,
        "create hourly country rollup target table",
        r#"
      CREATE TABLE IF NOT EXISTS country_hourly_mv_target (
        site_id UInt16,
        event_hour DateTime,
        country LowCardinality(FixedString(2)),
        region LowCardinality(String),
        pageviews SimpleAggregateFunction(sum, UInt64),
        users AggregateFunction(uniq, String),
        sessions AggregateFunction(uniq, String)
      )
      ENGINE = AggregatingMergeTree()
      PARTITION BY toYYYYMM(event_hour)
      ORDER BY (site_id, event_hour, country, region)
    "#,
        None,
    )
    .await?;

    exec_step(
        clickhouse,
        "create hourly country rollup materialized view",
        r#"
      CREATE MATERIALIZED VIEW IF NOT EXISTS country_hourly_mv
      TO country_hourly_mv_target
      AS SELECT
        site_id,
        toStartOfHour(timestamp) AS event_hour,
        country,
        region,
        countIf(type = 'pageview') AS pageviews,
        uniqState(user_id) AS users,
        uniqState(session_id) AS sessions
      FROM events
      GROUP BY site_id, event_hour, country, region
    "#,
        None,
    )
    .await?;

    // Device-type rollup.
    exec_step(
        clickhouse,
        "create hourly device type rollup target table",
        r#"
      CREATE TABLE IF NOT EXISTS device_type_hourly_mv_target (
        site_id UInt16,
        event_hour DateTime,
        device_type LowCardinality(String),
        pageviews SimpleAggregateFunction(sum, UInt64),
        users AggregateFunction(uniq, String),
        sessions AggregateFunction(uniq, String)
      )
      ENGINE = AggregatingMergeTree()
      PARTITION BY toYYYYMM(event_hour)
      ORDER BY (site_id, event_hour, device_type)
    "#,
        None,
    )
    .await?;

    exec_step(
        clickhouse,
        "create hourly device type rollup materialized view",
        r#"
      CREATE MATERIALIZED VIEW IF NOT EXISTS device_type_hourly_mv
      TO device_type_hourly_mv_target
      AS SELECT
        site_id,
        toStartOfHour(timestamp) AS event_hour,
        device_type,
        countIf(type = 'pageview') AS pageviews,
        uniqState(user_id) AS users,
        uniqState(session_id) AS sessions
      FROM events
      GROUP BY site_id, event_hour, device_type
    "#,
        None,
    )
    .await?;

    // Session-keyed hourly rollup, populated by a REFRESHABLE materialized view.
    // Streaming MVs can't compute bounce_rate or session_duration because they
    // see one event at a time, never the full per-session state. The refreshable
    // MV compacts the already-populated per-session rollup hourly instead of
    // repeatedly rebuilding sessions from every raw event.
    exec_step(
        clickhouse,
        "create session hourly rollup target table",
        r#"
      CREATE TABLE IF NOT EXISTS session_hourly_mv_target (
        site_id UInt16,
        session_hour DateTime,
        sessions UInt64,
        pageviews UInt64,
        users AggregateFunction(uniq, String),
        total_session_duration_seconds UInt64,
        bounced_sessions UInt64
      )
      ENGINE = MergeTree()
      PARTITION BY toYYYYMM(session_hour)
      ORDER BY (site_id, session_hour)
    "#,
        None,
    )
    .await?;

    // CREATE IF NOT EXISTS cannot update an already-installed view. Inspect the
    // stored definition so deployments replace the old five-minute raw-events
    // refresh once, while subsequent startups remain no-ops.
    ensure_session_hourly_materialized_view(clickhouse).await
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The refreshable view is recreated whenever the stored definition stops
    /// containing these two strings, so they have to keep appearing in the statement
    /// that creates it or every boot would drop and rebuild the view.
    #[test]
    fn session_hourly_create_query_matches_its_own_freshness_probes() {
        assert!(SESSION_HOURLY_MV_CREATE_QUERY.contains(SESSION_HOURLY_MV_REFRESH_INTERVAL));
        assert!(SESSION_HOURLY_MV_CREATE_QUERY.contains(SESSION_HOURLY_MV_SOURCE));
        assert!(SESSION_HOURLY_MV_CREATE_QUERY.contains(SESSION_HOURLY_MV_NAME));
    }
}
