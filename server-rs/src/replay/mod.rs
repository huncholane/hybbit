//! Session replay: recording (server/src/api/sessionReplay/recordSessionReplay.ts,
//! server/src/services/replay/sessionReplayIngestService.ts) and the dashboard's
//! replay reads (getSessionReplays.ts, getSessionReplayEvents.ts,
//! deleteSessionReplay.ts over sessionReplayQueryService.ts).
//!
//! - `clock_skew`: device clocks corrected onto server time
//! - `json`: `JSON.parse` / `JSON.stringify` for rrweb data, UTF-16 exact
//! - `schema`: the zod request schema
//! - `page_url`: `new URL(pageUrl)` and `parseReplayPageUrl`
//! - `ingest`: identity, session and the ClickHouse rows
//! - `store`: the ClickHouse calls, sent like `@clickhouse/client`
//! - `query`: the read and delete queries
//! - `record`, `read`: the route handlers
//!
//! Billing gates (`usageService`) and R2 storage exist only with CLOUD=true, which
//! this deployment never sets: the gates always pass and R2 is disabled.
//!
//! Parity is checked by parity/replay/run.py (record responses and rows, reads and
//! deletes against the Node backend). Engine limits Node hits and Rust does not:
//! - V8 stack depth: Node 24 throws a RangeError from `JSON.stringify` for event
//!   data nested past roughly 2,000 to 4,000 levels (a 500 on record, and on read
//!   for such stored data); Node 26 and Rust serialise it.
//! - Spread arguments: `Math.min(...timestamps)` throws past roughly 125,000 events
//!   in one batch, after the events were inserted, so Node answers 500 without a
//!   metadata row; Rust records the metadata. The recorder sends small batches.

use axum::{
    Router,
    routing::{MethodRouter, any},
};

use crate::{http::errors, state::AppState};

pub mod clock_skew;
pub mod ingest;
pub mod json;
pub mod page_url;
pub mod query;
pub mod read;
pub mod record;
pub mod schema;
pub mod store;

/// A method router whose unmatched methods get Fastify's 404, without the
/// `Allow` header axum adds to its default 405 fallback.
fn methods() -> MethodRouter<AppState> {
    any(errors::not_found)
}

/// The replay routes, at Node's paths, with two find-my-way behaviours axum does
/// not share:
/// - a parameter may be empty (`…/record/`, `/api/sites//session-replay/list`,
///   `…/session-replay/`), so those spellings get routes of their own;
/// - `DELETE …/session-replay/list` reaches the `:sessionId` route, while axum
///   matches the static `list` segment first, so that route answers DELETE too.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/session-replay/record/{siteId}", methods().post(record::record_session_replay))
        .route("/api/session-replay/record/", methods().post(record::record_session_replay_without_site))
        .route(
            "/api/sites/{siteId}/session-replay/list",
            methods().get(read::list_session_replays).delete(read::delete_session_replay_named_list),
        )
        .route(
            "/api/sites//session-replay/list",
            methods().get(read::list_without_site).delete(read::delete_named_list_without_site),
        )
        .route(
            "/api/sites/{siteId}/session-replay/{sessionId}",
            methods().get(read::get_session_replay).delete(read::delete_session_replay_route),
        )
        .route(
            "/api/sites//session-replay/{sessionId}",
            methods().get(read::get_without_site).delete(read::delete_without_site),
        )
        .route(
            "/api/sites/{siteId}/session-replay/",
            methods().get(read::get_without_session).delete(read::delete_without_session),
        )
        .route(
            "/api/sites//session-replay/",
            methods().get(read::get_without_site_or_session).delete(read::delete_without_site_or_session),
        )
}
