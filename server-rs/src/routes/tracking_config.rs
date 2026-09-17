//! GET /api/site/tracking-config/:siteId (server/src/api/sites/getTrackingConfig.ts).
//! Public: the tracking script fetches it on every page load.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Response,
};
use serde_json::{Map, Value, json};

use crate::{
    feature_flags, http,
    site_config::{SiteRef, SiteType},
    state::AppState,
};

pub async fn tracking_config(State(state): State<AppState>, Path(site_id): Path<String>) -> Response {
    let Some(config) = state.site_config.get_config(&SiteRef::Text(site_id)).await else {
        return http::json(StatusCode::NOT_FOUND, &json!({ "error": "Site not found" }));
    };
    let mobile = config.site_type == SiteType::Mobile;

    let feature_flags_enabled = match feature_flags::has_feature_flags_for_runtime(&state, config.site_id, "client").await {
        Ok(enabled) => enabled,
        Err(error) => {
            tracing::error!(error = %error, site_id = config.site_id, "Error getting tracking config");
            return http::json(
                StatusCode::INTERNAL_SERVER_ERROR,
                &json!({ "error": "Failed to get tracking configuration" }),
            );
        }
    };

    // Replay is reported off when the plan excludes it (cloud usage checks, which
    // only exist when CLOUD=true and are not ported yet), and always for apps
    let session_replay = !mobile && config.session_replay;

    let mut body = Map::new();
    body.insert("type".into(), Value::from(config.site_type.as_str()));
    body.insert("featureFlagsEnabled".into(), Value::from(feature_flags_enabled));
    body.insert("sessionReplay".into(), Value::from(session_replay));
    body.insert("webVitals".into(), Value::from(!mobile && config.web_vitals));
    body.insert("trackErrors".into(), Value::from(config.track_errors));
    body.insert("trackOutbound".into(), Value::from(config.track_outbound));
    body.insert("trackUrlParams".into(), Value::from(config.track_url_params));
    body.insert("trackInitialPageView".into(), Value::from(config.track_initial_page_view));
    body.insert("trackSpaNavigation".into(), Value::from(config.track_spa_navigation));
    body.insert("trackButtonClicks".into(), Value::from(config.track_button_clicks));
    body.insert("trackCopy".into(), Value::from(config.track_copy));
    body.insert("trackFormInteractions".into(), Value::from(config.track_form_interactions));
    body.insert("trackHeartbeat".into(), Value::from(!mobile && config.track_heartbeat));
    body.insert("heartbeatInterval".into(), Value::from(config.heartbeat_interval));

    http::json(StatusCode::OK, &Value::Object(body))
}
