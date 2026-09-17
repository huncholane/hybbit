//! The replay read routes (server/src/api/sessionReplay/getSessionReplays.ts,
//! getSessionReplayEvents.ts, deleteSessionReplay.ts), each behind the chain
//! server/src/index.ts registers it with: `publicReplayRead` for the list and one
//! session's events, `authReplayWrite` for deletion.

use axum::{
    body::Body,
    extract::{Path, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode, Uri, header},
    response::Response,
};
use serde_json::{Map, Value};
use tracing::{debug, error, info};

use super::{
    json::quote_str,
    query::{
        ListOptions, QueryError, delete_session_replay, get_session_replay_events, get_session_replay_list,
        get_session_replay_metadata,
    },
    record::MAX_PARAM_LENGTH,
    store::ReplayClickHouse,
};
use crate::{
    analytics::{
        chain::{self, ChainSteps, SiteGuard, SiteRequest},
        js::{
            JsValue,
            number::{parse_int_10, string_to_number},
        },
        utils::{time_window::TimeWindowParams, utils::enrich_with_traits},
    },
    http,
    js_json::{stringify, utf16_len},
    state::AppState,
};

fn json_text(status: StatusCode, body: String) -> Response {
    let mut response = Response::new(Body::from(body));
    *response.status_mut() = status;
    response.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json; charset=utf-8"));
    response
}

fn error_body(status: StatusCode, message: &str) -> Response {
    let mut body = String::from("{\"error\":");
    quote_str(&mut body, message);
    body.push('}');
    json_text(status, body)
}

fn params_too_long(params: &[&str]) -> bool {
    params.iter().any(|param| utf16_len(param) > MAX_PARAM_LENGTH)
}

fn store(state: &AppState) -> &'static ReplayClickHouse {
    ReplayClickHouse::shared(&state.config.clickhouse)
}

/// `parseInt(text)` with no radix: decimal, or hexadecimal after `0x`.
fn parse_int(text: &str) -> f64 {
    let trimmed = crate::analytics::js::string::trim(text);
    let (negative, unsigned) = match trimmed.as_bytes().first() {
        Some(b'-') => (true, &trimmed[1..]),
        Some(b'+') => (false, &trimmed[1..]),
        _ => (false, trimmed),
    };
    let Some(hex) = unsigned.strip_prefix("0x").or_else(|| unsigned.strip_prefix("0X")) else {
        return parse_int_10(text);
    };
    let digits: Vec<u32> = hex.chars().map_while(|c| c.to_digit(16)).collect();
    if digits.is_empty() {
        return f64::NAN;
    }
    let value = digits.iter().fold(0.0_f64, |total, digit| total * 16.0 + f64::from(*digit));
    if negative { -value } else { value }
}

/// `enrichWithTraits(rows, siteId)`. The Postgres lookup only runs when a row is
/// identified; a site id Postgres cannot bind as an integer fails it there.
async fn enrich(state: &AppState, rows: Vec<Map<String, Value>>, site_id: f64) -> Result<Vec<Map<String, Value>>, QueryError> {
    let identified = rows.iter().any(|row| matches!(row.get("identified_user_id"), Some(Value::String(id)) if !id.is_empty()));
    let bindable = site_id.fract() == 0.0 && site_id >= f64::from(i32::MIN) && site_id <= f64::from(i32::MAX);
    if identified && !bindable {
        return Err(QueryError::Traits(sqlx::Error::Protocol(format!("invalid input syntax for type integer: {site_id}"))));
    }
    Ok(enrich_with_traits(&state.pg, rows, if bindable { site_id as i32 } else { 0 }).await?)
}

/// The query values `getSessionReplays` reads, converted as its handler does.
fn list_options(request: &SiteRequest) -> ListOptions {
    let query = &request.query;
    let raw = |name: &str| query.get_or_undefined(name).clone();
    // `value ? Number(value) : fallback`
    let number_if_truthy = |name: &str| {
        let value = query.get_or_undefined(name);
        value.is_truthy().then(|| value.to_number())
    };
    let as_js = |number: Option<f64>| number.map_or(JsValue::Undefined, JsValue::Number);
    let filters = raw("filters");

    ListOptions {
        limit: number_if_truthy("limit").unwrap_or(50.0),
        offset: number_if_truthy("offset").unwrap_or(0.0),
        user_id: Some(raw("userId")).filter(JsValue::is_truthy),
        min_duration: number_if_truthy("minDuration"),
        time: TimeWindowParams {
            start_date: raw("start_date"),
            end_date: raw("end_date"),
            time_zone: raw("time_zone"),
            past_minutes_start: as_js(number_if_truthy("past_minutes_start")),
            past_minutes_end: as_js(number_if_truthy("past_minutes_end")),
            ..TimeWindowParams::default()
        },
        filters: if filters.is_truthy() { filters } else { JsValue::from("") },
    }
}

/// GET /api/sites/:siteId/session-replay/list (`getSessionReplays`)
pub async fn list_session_replays(
    State(state): State<AppState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    Path(site_id_param): Path<String>,
) -> Response {
    list_replays(state, method, uri, headers, site_id_param).await
}

/// GET /api/sites//session-replay/list: an empty `:siteId`
pub async fn list_without_site(State(state): State<AppState>, method: Method, uri: Uri, headers: HeaderMap) -> Response {
    list_replays(state, method, uri, headers, String::new()).await
}

/// GET /api/sites/:siteId/session-replay/:sessionId (`getSessionReplayEvents`)
pub async fn get_session_replay(
    State(state): State<AppState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    Path((site_id_param, session_id)): Path<(String, String)>,
) -> Response {
    replay_events(state, method, uri, headers, site_id_param, session_id).await
}

/// GET /api/sites//session-replay/:sessionId: an empty `:siteId`
pub async fn get_without_site(
    State(state): State<AppState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    Path(session_id): Path<String>,
) -> Response {
    replay_events(state, method, uri, headers, String::new(), session_id).await
}

/// GET /api/sites/:siteId/session-replay/: an empty `:sessionId`
pub async fn get_without_session(
    State(state): State<AppState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    Path(site_id_param): Path<String>,
) -> Response {
    replay_events(state, method, uri, headers, site_id_param, String::new()).await
}

/// GET /api/sites//session-replay/: both parameters empty
pub async fn get_without_site_or_session(
    State(state): State<AppState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    replay_events(state, method, uri, headers, String::new(), String::new()).await
}

async fn list_replays(state: AppState, method: Method, uri: Uri, headers: HeaderMap, site_id_param: String) -> Response {
    if params_too_long(&[&site_id_param]) {
        return http::errors::not_found(method, uri).await;
    }
    let request = match chain::site_scoped(
        &state,
        &headers,
        &uri,
        &site_id_param,
        SiteGuard::Public,
        chain::route_scope("replay", "read"),
        ChainSteps::FULL,
    )
    .await
    {
        Ok(request) => request,
        Err(response) => return response,
    };

    let site_id = string_to_number(&request.site_id);
    let options = list_options(&request);
    let result = async {
        let rows = get_session_replay_list(store(&state), site_id, &options).await?;
        enrich(&state, rows, site_id).await
    }
    .await;

    match result {
        Ok(rows) => {
            info!(site_id, replays = rows.len(), "Listed session replays");
            let mut body = Map::new();
            body.insert("data".into(), Value::Array(rows.into_iter().map(Value::Object).collect()));
            json_text(StatusCode::OK, stringify(&Value::Object(body)))
        }
        Err(err) => {
            error!(site_id, error = %err, "Error fetching session replays");
            error_body(StatusCode::INTERNAL_SERVER_ERROR, "Internal server error")
        }
    }
}

async fn replay_events(
    state: AppState,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    site_id_param: String,
    session_id: String,
) -> Response {
    if params_too_long(&[&site_id_param, &session_id]) {
        return http::errors::not_found(method, uri).await;
    }
    let request = match chain::site_scoped(
        &state,
        &headers,
        &uri,
        &site_id_param,
        SiteGuard::Public,
        chain::route_scope("replay", "read"),
        ChainSteps::FULL,
    )
    .await
    {
        Ok(request) => request,
        Err(response) => return response,
    };

    let site_id = string_to_number(&request.site_id);
    let result = async {
        let replay = get_session_replay_events(store(&state), site_id, &session_id).await?;
        let mut metadata = replay.metadata;
        // `identified_user_id: metadata.identified_user_id || ""`, keeping its position
        let identified = match metadata.get("identified_user_id") {
            Some(value @ Value::String(text)) if !text.is_empty() => value.clone(),
            Some(value @ (Value::Array(_) | Value::Object(_) | Value::Bool(true))) => value.clone(),
            Some(Value::Number(number)) if number.as_f64().is_some_and(|n| n != 0.0) => Value::Number(number.clone()),
            _ => Value::String(String::new()),
        };
        metadata.insert("identified_user_id".into(), identified);
        let enriched = enrich(&state, vec![metadata], site_id).await?.into_iter().next().unwrap_or_default();
        Ok::<_, QueryError>((replay.events, enriched))
    }
    .await;

    match result {
        Ok((events, metadata)) => {
            debug!(site_id, session_id = %session_id, events = events.len(), "Fetched session replay events");
            let mut body = String::with_capacity(events.iter().map(|event| event.data.len() + 48).sum::<usize>() + 1024);
            body.push_str("{\"events\":[");
            for (index, event) in events.iter().enumerate() {
                if index > 0 {
                    body.push(',');
                }
                body.push_str("{\"timestamp\":");
                body.push_str(&stringify(&event.timestamp));
                body.push_str(",\"type\":");
                body.push_str(&stringify(&event.event_type));
                body.push_str(",\"data\":");
                body.push_str(&event.data);
                body.push('}');
            }
            body.push_str("],\"metadata\":");
            body.push_str(&stringify(&Value::Object(metadata)));
            body.push('}');
            json_text(StatusCode::OK, body)
        }
        Err(err) => {
            // Node compares the message with "Session replay not found", which the
            // service's "... for session <id>" never equals: a missing replay is a 500
            error!(site_id, session_id = %session_id, error = %err, "Error fetching session replay events");
            error_body(StatusCode::INTERNAL_SERVER_ERROR, "Internal server error")
        }
    }
}

/// DELETE /api/sites/:siteId/session-replay/:sessionId (`deleteSessionReplay`)
pub async fn delete_session_replay_route(
    State(state): State<AppState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    Path((site_id_param, session_id)): Path<(String, String)>,
) -> Response {
    delete_replay(state, method, uri, headers, site_id_param, session_id).await
}

/// DELETE /api/sites/:siteId/session-replay/list: Node's router matches the
/// `:sessionId` route for it, so "list" is a session id there.
pub async fn delete_session_replay_named_list(
    State(state): State<AppState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    Path(site_id_param): Path<String>,
) -> Response {
    delete_replay(state, method, uri, headers, site_id_param, "list".to_string()).await
}

/// DELETE /api/sites//session-replay/list: an empty `:siteId`, session "list"
pub async fn delete_named_list_without_site(
    State(state): State<AppState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    delete_replay(state, method, uri, headers, String::new(), "list".to_string()).await
}

/// DELETE /api/sites//session-replay/:sessionId: an empty `:siteId`
pub async fn delete_without_site(
    State(state): State<AppState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    Path(session_id): Path<String>,
) -> Response {
    delete_replay(state, method, uri, headers, String::new(), session_id).await
}

/// DELETE /api/sites/:siteId/session-replay/: an empty `:sessionId`
pub async fn delete_without_session(
    State(state): State<AppState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    Path(site_id_param): Path<String>,
) -> Response {
    delete_replay(state, method, uri, headers, site_id_param, String::new()).await
}

/// DELETE /api/sites//session-replay/: both parameters empty
pub async fn delete_without_site_or_session(
    State(state): State<AppState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    delete_replay(state, method, uri, headers, String::new(), String::new()).await
}

async fn delete_replay(
    state: AppState,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    site_id_param: String,
    session_id: String,
) -> Response {
    if params_too_long(&[&site_id_param, &session_id]) {
        return http::errors::not_found(method, uri).await;
    }
    let request = match chain::site_scoped(
        &state,
        &headers,
        &uri,
        &site_id_param,
        SiteGuard::Member,
        chain::route_scope("replay", "write"),
        ChainSteps::FULL,
    )
    .await
    {
        Ok(request) => request,
        Err(response) => return response,
    };

    let numeric_site_id = parse_int(&request.site_id);
    if numeric_site_id.is_nan() {
        return error_body(StatusCode::BAD_REQUEST, "Invalid site ID");
    }

    let store = store(&state);
    let result = async {
        let Some(_metadata) = get_session_replay_metadata(store, numeric_site_id, &session_id).await? else {
            return Ok(false);
        };
        delete_session_replay(store, numeric_site_id, &session_id).await?;
        Ok::<_, QueryError>(true)
    }
    .await;

    match result {
        Ok(true) => {
            info!(site_id = numeric_site_id, session_id = %session_id, "Deleted session replay");
            json_text(StatusCode::OK, "{\"success\":true}".to_string())
        }
        Ok(false) => {
            debug!(site_id = numeric_site_id, session_id = %session_id, "Session replay to delete not found");
            error_body(StatusCode::NOT_FOUND, "Session replay not found")
        }
        Err(err) => {
            error!(site_id = numeric_site_id, session_id = %session_id, error = %err, "Error deleting session replay");
            error_body(StatusCode::INTERNAL_SERVER_ERROR, "Failed to delete session replay")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_int_follows_javascript() {
        assert_eq!(parse_int("12"), 12.0);
        assert_eq!(parse_int(" 12abc"), 12.0);
        assert_eq!(parse_int("0x1A"), 26.0);
        assert_eq!(parse_int("-0x10"), -16.0);
        assert_eq!(parse_int("1e5"), 1.0);
        assert!(parse_int("0x").is_nan());
        assert!(parse_int("abc").is_nan());
        assert!(parse_int("").is_nan());
    }
}
