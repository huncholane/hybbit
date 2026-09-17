use std::sync::LazyLock;

use axum::{extract::State, http::StatusCode, response::Response};
use serde_json::{Map, Value, json};

use crate::{http, state::AppState};

/// The version Node reports: server/package.json, embedded at build time.
static VERSION: LazyLock<String> = LazyLock::new(|| {
    serde_json::from_str::<Value>(include_str!("../../../server/package.json"))
        .ok()
        .and_then(|package| package.get("version")?.as_str().map(str::to_string))
        .unwrap_or_default()
});

/// GET /api/config (server/src/api/getConfig.ts)
pub async fn config(State(state): State<AppState>) -> Response {
    let mut body = Map::new();
    body.insert("disableSignup".into(), Value::Bool(state.config.disable_signup));
    // An unset token is `undefined` in Node and so left out of the JSON
    if let Some(token) = &state.config.mapbox_token {
        body.insert("mapboxToken".into(), Value::String(token.clone()));
    }
    body.insert("liteDashboard".into(), Value::Bool(state.config.lite_dashboard));
    http::json(StatusCode::OK, &Value::Object(body))
}

/// GET /api/version
pub async fn version() -> Response {
    http::json(StatusCode::OK, &json!({ "version": VERSION.as_str() }))
}
