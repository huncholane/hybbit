//! POST /api/session-replay/record/:siteId (server/src/api/sessionReplay/recordSessionReplay.ts).
//! Public: the tracking script's rrweb recorder posts batches here.
//!
//! Order, as in Node: Fastify's body parsing (415/413/400 before the handler), the
//! Site Configuration (replay off or unknown Site: 200 "not enabled", before the
//! body is validated), the usage gates (never closed without billing), zod
//! validation, client IP and the Site Exclusion Decision, then recording.

use std::net::{IpAddr, SocketAddr};

use axum::{
    body::Body,
    extract::{ConnectInfo, Path, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode, Uri, header},
    response::Response,
};
use serde_json::{Value, json};
use tracing::{debug, error, info, warn};

use super::{
    ingest::{IngestDeps, RecordError, RequestMeta, record_events},
    json,
    page_url::parse_replay_page_url,
    schema::{self, ReplayBatch},
    store::{ReplayClickHouse, serialized_error},
};
use crate::{
    analytics::{js::zod::ZodIssue, utils::analytics_query::ClickHouseFailure},
    geo::{AsnLookup, Location},
    http,
    identity::{UserIdDeps, UserIdError, UserIdOptions},
    site_config::{SiteConfigData, SiteRef},
    state::AppState,
    tracking::{
        AsnSource, LocationSource,
        body::{BodyHeaders, BodyRejection, TRACK_BODY_LIMIT_BYTES, body_too_large, parse_body_with_depth, reject_before_reading},
        client_ip::{collect_candidate_client_ips, get_request_user_agent, resolve_client_ip},
        exclusions::{SiteExclusionDecision, SiteExclusionRequest, SiteExclusionRules, decide_site_exclusion},
        js::latin1,
        json::JsValue as TrackingJsValue,
    },
};

/// Bodies past this size are parsed and serialised on the blocking pool.
const BLOCKING_PARSE_BYTES: usize = 256 * 1024;

/// find-my-way answers 404 when a decoded parameter is longer than
/// `maxParamLength` (1500 in server/src/index.ts).
pub const MAX_PARAM_LENGTH: usize = 1500;

fn json_response(status: StatusCode, body: String) -> Response {
    let mut response = Response::new(Body::from(body));
    *response.status_mut() = status;
    response.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json; charset=utf-8"));
    response
}

fn rejection_response(rejection: BodyRejection) -> Response {
    let mut response = http::json(rejection.status, &rejection.body);
    if rejection.close_connection {
        response.headers_mut().insert(header::CONNECTION, HeaderValue::from_static("close"));
    }
    response
}

/// What Fastify made of the body before the handler ran.
enum ParsedBody {
    /// `request.body` is not an object; zod's received type name
    NotAnObject(&'static str),
    /// A JSON object body, as the decoded text `JSON.parse` saw
    Object(String),
}

/// Fastify's default parsers for this route (the same root-context parsers as
/// /api/track, with the global 10 MB `bodyLimit`). The tracking body port validates
/// the JSON and reports poisoning; the replay tape parse runs later, once the Site
/// is known to record.
async fn read_body(headers: &HeaderMap, body: Body) -> Result<ParsedBody, Response> {
    let body_headers = BodyHeaders::from_headers(headers);
    if let Some(rejection) = reject_before_reading(&body_headers) {
        return Err(rejection_response(rejection));
    }
    let raw = match axum::body::to_bytes(body, TRACK_BODY_LIMIT_BYTES + 1).await {
        Ok(raw) => raw,
        Err(err) => {
            warn!(error = %err, "Replay body could not be read within the limit");
            return Err(rejection_response(body_too_large()));
        }
    };
    // Depth 0 keeps only the root's type; everything below is checked, not stored
    let parsed = parse_body_with_depth(&body_headers, &raw, 0).map_err(rejection_response)?;
    Ok(match parsed {
        None => ParsedBody::NotAnObject("undefined"),
        Some(TrackingJsValue::Object(_) | TrackingJsValue::UnreadObject) => {
            let text = String::from_utf8_lossy(&raw);
            // secure-json-parse dropped one leading byte order mark
            let text = text.strip_prefix('\u{FEFF}').unwrap_or(&text);
            ParsedBody::Object(text.to_string())
        }
        Some(other) => ParsedBody::NotAnObject(other.zod_type_name()),
    })
}

/// `recordSessionReplaySchema.parse(request.body)`
async fn validate_body(body: ParsedBody) -> Result<ReplayBatch, Vec<ZodIssue>> {
    let text = match body {
        ParsedBody::NotAnObject(received) => return Err(schema::non_object_body_issues(received)),
        ParsedBody::Object(text) => text,
    };
    let large = text.len() > BLOCKING_PARSE_BYTES;
    let work = move || match json::parse(&text) {
        Ok(tape) => schema::validate(&tape),
        // Unreachable after the Fastify parse accepted the text; keep the handler total
        Err(err) => {
            error!(position = err.position, "Replay body failed the tape parse after passing Fastify's");
            Err(schema::non_object_body_issues("string"))
        }
    };
    if large {
        tokio::task::spawn_blocking(work).await.unwrap_or_else(|join| {
            error!(error = %join, "Replay body parse task failed");
            Err(schema::non_object_body_issues("string"))
        })
    } else {
        work()
    }
}

/// The facts the handler derives from the request once the Site is known
/// (`resolveClientIp`, `parseReplayPageUrl`, `collectCandidateClientIps` and the
/// Site Exclusion Decision), split out so the exclusion mapping is testable.
pub struct PreparedRecording {
    pub exclusion: SiteExclusionDecision,
    pub meta: RequestMeta,
}

pub fn prepare_recording(
    headers: &HeaderMap,
    peer: IpAddr,
    site: &SiteConfigData,
    batch: &ReplayBatch,
    geo: &impl LocationSource,
    asn: &impl AsnSource,
) -> PreparedRecording {
    let request_ip = resolve_client_ip(headers, peer, site.first_party_proxy, asn);
    let page_url = batch.metadata.as_ref().map(|metadata| metadata.page_url.to_lossy());
    let page = parse_replay_page_url(page_url.as_deref());
    let user_agent = get_request_user_agent(headers);
    let candidate_ips = collect_candidate_client_ips(headers, peer, &[request_ip.as_str()]);

    let exclusion = decide_site_exclusion(
        &SiteExclusionRules::from(site),
        &SiteExclusionRequest {
            ip_address: &request_ip,
            candidate_ips: &candidate_ips,
            pathname: page.pathname.as_deref(),
            querystring: page.querystring.as_deref(),
            hostname: page.hostname.as_deref(),
            user_agent: Some(&user_agent),
        },
        geo,
        asn,
    );

    // Node's http parser keeps the first Origin and Referer
    let header_text = |name: header::HeaderName| headers.get(name).map(|value| latin1(value.as_bytes())).unwrap_or_default();
    PreparedRecording {
        exclusion,
        meta: RequestMeta {
            user_agent,
            ip_address: request_ip,
            origin: header_text(header::ORIGIN),
            referrer: header_text(header::REFERER),
        },
    }
}

/// `Session replay not recorded - <label> excluded`
pub fn excluded_message(decision: &SiteExclusionDecision) -> Option<String> {
    match decision {
        SiteExclusionDecision::Accepted => None,
        SiteExclusionDecision::Excluded { reason, .. } => {
            Some(format!("Session replay not recorded - {} excluded", reason.label()))
        }
    }
}

/// The production wiring of `IngestDeps`.
struct LiveDeps<'a> {
    state: &'a AppState,
    asn_lookup: AsnLookup<'a>,
    clickhouse: &'static ReplayClickHouse,
}

impl IngestDeps for LiveDeps<'_> {
    async fn generate_user_id(&self, ip: &str, user_agent: &str, site_id: i32) -> Result<String, UserIdError> {
        let deps = UserIdDeps {
            redis: &self.state.redis,
            salt_source: self.state.site_config.as_ref(),
            secret: self.state.config.better_auth_secret.as_deref(),
        };
        // No options: Node's call reads the salting setting and the clock itself
        self.state
            .ingest
            .user_ids
            .generate_user_id(&deps, &self.asn_lookup, ip, user_agent, site_id, UserIdOptions::default())
            .await
    }

    async fn update_session(&self, user_id: &str, identified_user_id: &str, site_id: i32) -> String {
        self.state.ingest.sessions.update_session(&self.state.redis, user_id, identified_user_id, site_id).await
    }

    async fn insert(&self, table: &'static str, body: String, rows: usize) -> Result<(), ClickHouseFailure> {
        self.clickhouse.insert_json_each_row(table, body, rows).await
    }

    fn location(&self, ip: &str) -> Option<Location> {
        self.state.geo.location(ip)
    }

    fn now_ms(&self) -> f64 {
        chrono::Utc::now().timestamp_millis() as f64
    }
}

/// The 500 Node sends from its catch block: `{ error }` with the thrown value
/// serialised (only a ClickHouse error has enumerable fields).
fn failure_response(site_id: i32, error: &RecordError) -> Response {
    error!(site_id, error = %error, "Error recording session replay");
    let serialized = match error {
        RecordError::Insert { failure, .. } => serialized_error(failure),
        RecordError::UserId(_) | RecordError::MissingEventData { .. } => json!({}),
    };
    http::json(StatusCode::INTERNAL_SERVER_ERROR, &json!({ "error": serialized }))
}

/// POST /api/session-replay/record/:siteId
pub async fn record_session_replay(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    method: Method,
    uri: Uri,
    Path(site_id_param): Path<String>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    record(state, peer, method, uri, site_id_param, headers, body).await
}

/// POST /api/session-replay/record/: find-my-way matches an empty `:siteId`
pub async fn record_session_replay_without_site(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Body,
) -> Response {
    record(state, peer, method, uri, String::new(), headers, body).await
}

/// `recordSessionReplay`
async fn record(
    state: AppState,
    peer: SocketAddr,
    method: Method,
    uri: Uri,
    site_id_param: String,
    headers: HeaderMap,
    body: Body,
) -> Response {
    if crate::js_json::utf16_len(&site_id_param) > MAX_PARAM_LENGTH {
        return http::errors::not_found(method, uri).await;
    }

    let body = match read_body(&headers, body).await {
        Ok(body) => body,
        Err(response) => return response,
    };

    // Get the site configuration to get the numeric siteId
    let site: Option<SiteConfigData> = state.site_config.get_config(&SiteRef::Text(site_id_param.clone())).await;
    let Some(site) = site.filter(|site| site.session_replay) else {
        info!(site = %site_id_param, "Skipping session replay event because replay is not enabled");
        return http::json(StatusCode::OK, &json!({ "success": true, "message": "Session replay not enabled" }));
    };
    let site_id = site.site_id;
    if site_id == 0 {
        // `if (!siteId) throw`: caught into a 500 carrying an Error, which serialises to {}
        error!(site = %site_id_param, "Error recording session replay: Site not found");
        return http::json(StatusCode::INTERNAL_SERVER_ERROR, &json!({ "error": {} }));
    }

    // usageService.isSiteOverLimit and isSiteWithoutReplay only close with CLOUD
    // billing, which this deployment does not run (PORT_PLAN.md, Decisions)

    let batch = match validate_body(body).await {
        Ok(batch) => batch,
        Err(issues) => {
            debug!(site_id, issues = issues.len(), "Replay batch failed validation");
            return json_response(StatusCode::BAD_REQUEST, schema::error_body(&issues));
        }
    };

    let asn_lookup = state.geo.asn_lookup();
    let prepared = prepare_recording(&headers, peer.ip(), &site, &batch, state.geo.as_ref(), &asn_lookup);
    if let Some(message) = excluded_message(&prepared.exclusion) {
        let reason = match &prepared.exclusion {
            SiteExclusionDecision::Excluded { reason, .. } => reason.as_str(),
            SiteExclusionDecision::Accepted => "",
        };
        info!(site_id, exclusion_reason = reason, "Skipping session replay event because a Site Exclusion Decision matched");
        return http::json(StatusCode::OK, &json!({ "success": true, "message": message }));
    }

    let event_count = batch.events.len();
    let deps = LiveDeps { state: &state, asn_lookup, clickhouse: ReplayClickHouse::shared(&state.config.clickhouse) };
    match record_events(&deps, site_id, batch, &prepared.meta).await {
        Ok(()) => {
            debug!(site_id, event_count, "Recorded session replay batch");
            http::json(StatusCode::OK, &Value::Object([("success".to_string(), Value::Bool(true))].into_iter().collect()))
        }
        Err(error) => failure_response(site_id, &error),
    }
}

#[cfg(test)]
mod tests {
    //! Port of server/src/api/sessionReplay/recordSessionReplay.test.ts. Node mocks
    //! the decision and checks what it was asked; here the real decision runs over
    //! the same Site Configurations, so both the request it sees and the response
    //! message it produces are checked.

    use axum::http::HeaderName;

    use super::*;
    use crate::{
        geo::AsnInfo,
        replay::{
            json::JsString,
            schema::{EventType, ReplayEvent, ReplayMetadata},
        },
        site_config::SiteType,
    };

    struct NoGeo;
    impl LocationSource for NoGeo {
        fn country_iso(&self, _ip: &str) -> Option<String> {
            None
        }
    }
    impl AsnSource for NoGeo {
        fn asn_info(&self, _ip: &str) -> Option<AsnInfo> {
            None
        }
    }

    fn base_config() -> SiteConfigData {
        SiteConfigData {
            id: Some("site_abc".into()),
            site_id: 42,
            organization_id: None,
            site_type: SiteType::Web,
            public: false,
            embed_enabled: false,
            salt_user_ids: false,
            domain: "example.com".into(),
            block_bots: true,
            first_party_proxy: false,
            excluded_ips: vec![],
            use_organization_excluded_ips: true,
            organization_excluded_ips: vec![],
            excluded_countries: vec![],
            excluded_paths: vec![],
            excluded_hostnames: vec![],
            excluded_user_agents: vec![],
            excluded_asns: vec![],
            excluded_query_params: vec![],
            private_link_key: None,
            session_replay: true,
            web_vitals: false,
            track_errors: false,
            track_outbound: true,
            track_url_params: true,
            track_initial_page_view: true,
            track_spa_navigation: true,
            track_ip: false,
            track_button_clicks: false,
            track_copy: false,
            track_form_interactions: false,
            track_heartbeat: false,
            heartbeat_interval: 15,
            bounce_threshold: 10,
            tags: vec![],
        }
    }

    fn base_body(page_url: &str) -> ReplayBatch {
        ReplayBatch {
            user_id: JsString::from("user-1"),
            events: vec![ReplayEvent { event_type: EventType::Number(2.0), data: Some("{\"source\":0}".into()), timestamp: 1_700_000_000_000.0 }],
            metadata: Some(ReplayMetadata {
                page_url: JsString::from(page_url),
                viewport_width: Some(1280.0),
                viewport_height: Some(720.0),
                language: Some(JsString::from("en-US")),
            }),
        }
    }

    fn headers() -> HeaderMap {
        let mut headers = HeaderMap::new();
        for (name, value) in [
            ("user-agent", "Mozilla/5.0 HeadlessChrome/120"),
            ("x-real-ip", "198.51.100.10"),
            ("origin", "https://example.com"),
            ("referer", "https://example.com/admin/users"),
        ] {
            headers.insert(HeaderName::from_static(name), HeaderValue::from_static(value));
        }
        headers
    }

    const SOCKET: &str = "203.0.113.10";

    fn prepare(config: &SiteConfigData, page_url: &str) -> PreparedRecording {
        prepare_recording(&headers(), SOCKET.parse().unwrap(), config, &base_body(page_url), &NoGeo, &NoGeo)
    }

    #[test]
    fn records_the_replay_when_the_decision_accepts_the_request() {
        let prepared = prepare(&base_config(), "https://example.com/admin/users?tab=settings");
        assert_eq!(prepared.exclusion, SiteExclusionDecision::Accepted);
        assert_eq!(
            prepared.meta,
            RequestMeta {
                user_agent: "Mozilla/5.0 HeadlessChrome/120".into(),
                ip_address: "198.51.100.10".into(),
                origin: "https://example.com".into(),
                referrer: "https://example.com/admin/users".into(),
            }
        );
    }

    #[test]
    fn maps_an_ip_decision_to_the_replay_skip_response() {
        let config = SiteConfigData { excluded_ips: vec!["198.51.100.0/24".into()], ..base_config() };
        let prepared = prepare(&config, "https://example.com/admin/users?tab=settings");
        assert_eq!(prepared.exclusion, SiteExclusionDecision::Excluded { reason: crate::tracking::SiteExclusionReason::Ip, value: "198.51.100.10".into() });
        assert_eq!(excluded_message(&prepared.exclusion).as_deref(), Some("Session replay not recorded - IP excluded"));
        // The candidate IPs the decision matched against: the resolved IP, then the socket
        assert_eq!(collect_candidate_client_ips(&headers(), SOCKET.parse().unwrap(), &["198.51.100.10"]), ["198.51.100.10", "203.0.113.10"]);
        let page = parse_replay_page_url(Some("https://example.com/admin/users?tab=settings"));
        assert_eq!((page.pathname.as_deref(), page.querystring.as_deref(), page.hostname.as_deref()), (Some("/admin/users"), Some("?tab=settings"), Some("example.com")));
    }

    #[test]
    fn does_not_record_replay_batches_for_excluded_page_paths() {
        let config = SiteConfigData { excluded_paths: vec!["/admin/*".into()], ..base_config() };
        let prepared = prepare(&config, "https://example.com/admin/users?tab=settings");
        assert_eq!(excluded_message(&prepared.exclusion).as_deref(), Some("Session replay not recorded - path excluded"));
    }

    #[test]
    fn does_not_record_replay_batches_for_excluded_hostnames() {
        let config = SiteConfigData { excluded_hostnames: vec!["*.vercel.app".into()], ..base_config() };
        let prepared = prepare(&config, "https://preview.vercel.app/app");
        assert_eq!(excluded_message(&prepared.exclusion).as_deref(), Some("Session replay not recorded - hostname excluded"));
    }

    #[test]
    fn does_not_record_replay_batches_for_excluded_user_agents() {
        let config = SiteConfigData { excluded_user_agents: vec!["HeadlessChrome".into()], ..base_config() };
        let prepared = prepare(&config, "https://example.com/admin/users?tab=settings");
        assert_eq!(excluded_message(&prepared.exclusion).as_deref(), Some("Session replay not recorded - user agent excluded"));
    }
}
