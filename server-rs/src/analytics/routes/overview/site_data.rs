//! GET /api/sites/:siteId/has-data (server/src/api/sites/getSiteHasData.ts) and
//! GET /api/sites/:siteId/is-public (getSiteIsPublic.ts). The onboarding screen
//! polls has-data until the first event lands.

use axum::http::StatusCode;
use serde_json::json;
use tracing::{debug, error};

use crate::analytics::{js::JsObject, utils::analytics_query::QuerySpec};

use super::{Outcome, OverviewBackend, Reply, js_number};

/// The has-data probe. `count(*)` read every row of the Site just to answer "any?";
/// `LIMIT 1` pinned to one thread turns it into a two-granule read.
pub const HAS_DATA_QUERY: &str = "SELECT 1 AS has_data FROM events WHERE site_id = {siteId:Int32} LIMIT 1";

/// `getSiteHasData`: `{ hasData }`, or 500 `Internal server error`.
pub(crate) async fn get_site_has_data<B: OverviewBackend>(backend: &B, site_id: &str, _query: &JsObject) -> Outcome {
    let site = js_number(site_id);
    let spec = QuerySpec::new(HAS_DATA_QUERY).param("siteId", site);
    match backend.query_rows_single_thread(&spec).await {
        Ok(rows) => {
            debug!(site_id = site, has_data = !rows.is_empty(), "site has-data checked");
            Ok(Reply::ok(json!({ "hasData": !rows.is_empty() })))
        }
        Err(err) => {
            error!(err = %err, site_id = site, "Error checking if site has data");
            Ok(Reply::error(StatusCode::INTERNAL_SERVER_ERROR, "Internal server error"))
        }
    }
}

/// `getSiteIsPublic`: `{ isPublic }` from Site Configuration (false when unreadable).
pub(crate) async fn get_site_is_public<B: OverviewBackend>(backend: &B, site_id: &str, _query: &JsObject) -> Outcome {
    let is_public = backend.site_is_public(site_id).await;
    debug!(site_id, is_public, "site is-public checked");
    Ok(Reply::ok(json!({ "isPublic": is_public })))
}
