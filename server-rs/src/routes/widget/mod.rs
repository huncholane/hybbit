//! GET /widget/:siteId, the embeddable live-visitors widget, ported from the Next
//! route handler client/src/app/widget/[siteId]/route.ts so the dashboard can be a
//! static export. The HTML is byte-identical to Next's for the same request (see
//! the golden cases in cases.json, captured from the Next server); the page itself
//! fetches `/api/sites/:siteId/embed-stats` from the browser.

use axum::{
    body::Body,
    extract::State,
    http::{HeaderValue, Method, StatusCode, Uri, header},
    response::Response,
};
use serde_json::json;

use crate::{bot::js::js_string_to_number, state::AppState};

mod templates;

const ALLOWED_MINUTES: [u32; 3] = [30, 1440, 10080];

/// Next adds this to every App Router response, route handlers included.
const NEXT_VARY: &str = "rsc, next-router-state-tree, next-router-prefetch, next-router-segment-prefetch";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Theme {
    Dark,
    Light,
}

impl Theme {
    fn as_str(self) -> &'static str {
        match self {
            Theme::Dark => "dark",
            Theme::Light => "light",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Variant {
    Card,
    Inline,
}

pub(super) struct WidgetConfig<'a> {
    site_id: &'a str,
    minutes: u32,
    chart: bool,
    countries: bool,
    theme: Theme,
    accent: String,
    variant: Variant,
    backend_url: &'a str,
    window_label: &'static str,
}

pub(super) struct Colors {
    bg: &'static str,
    fg: &'static str,
    muted: &'static str,
    border: &'static str,
}

fn colors(theme: Theme) -> Colors {
    match theme {
        Theme::Dark => Colors { bg: "#171717", fg: "#fafafa", muted: "#737373", border: "rgba(255,255,255,0.08)" },
        Theme::Light => Colors { bg: "#ffffff", fg: "#171717", muted: "#737373", border: "rgba(0,0,0,0.08)" },
    }
}

fn window_label(minutes: u32) -> &'static str {
    match minutes {
        1440 => "LAST 24 HOURS",
        10080 => "LAST 7 DAYS",
        _ => "LAST 30 MINUTES",
    }
}

/// The request as the route handler read it: `searchParams.get` returns the first
/// value of a name, form-decoded.
struct Query<'a> {
    pairs: Vec<(std::borrow::Cow<'a, str>, std::borrow::Cow<'a, str>)>,
}

impl<'a> Query<'a> {
    fn parse(query: Option<&'a str>) -> Self {
        Self { pairs: url::form_urlencoded::parse(query.unwrap_or("").as_bytes()).collect() }
    }

    fn get(&self, name: &str) -> Option<&str> {
        self.pairs.iter().find(|(key, _)| key == name).map(|(_, value)| value.as_ref())
    }
}

/// `/^[a-zA-Z0-9_-]+$/`
fn is_valid_site_id(site_id: &str) -> bool {
    !site_id.is_empty() && site_id.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
}

/// `/^[0-9a-fA-F]{6}$/`
fn is_hex_color(value: &str) -> bool {
    value.len() == 6 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn config_from_request<'a>(site_id: &'a str, query: &Query<'_>, backend_url: &'a str) -> WidgetConfig<'a> {
    // `Number(sp.get("minutes") ?? 30)`, so " 1440 ", "0x5a0" and "1.44e3" all count
    let minutes_raw = query.get("minutes").map_or(30.0, js_string_to_number);
    let minutes = ALLOWED_MINUTES
        .into_iter()
        .find(|allowed| f64::from(*allowed) == minutes_raw)
        .unwrap_or(30);
    let accent = match query.get("accent") {
        Some(raw) if is_hex_color(raw) => format!("#{raw}"),
        _ => "#10b981".to_string(),
    };

    WidgetConfig {
        site_id,
        minutes,
        chart: query.get("chart") == Some("true"),
        countries: query.get("countries") == Some("true"),
        theme: if query.get("theme") == Some("light") { Theme::Light } else { Theme::Dark },
        accent,
        variant: if query.get("variant") == Some("inline") { Variant::Inline } else { Variant::Card },
        backend_url,
        window_label: window_label(minutes),
    }
}

fn render_html(c: &WidgetConfig) -> String {
    let col = colors(c.theme);
    let mut body = String::with_capacity(2_048);
    match c.variant {
        Variant::Inline => {
            let logo = if c.theme == Theme::Dark { "/hygo/frog_white.svg" } else { "/hygo/frog_black.svg" };
            templates::inline(&mut body, &col, logo);
        }
        Variant::Card => {
            let logo = if c.theme == Theme::Dark { "/hygo/horizontal_white.svg" } else { "/hygo/horizontal_black.svg" };
            templates::card(&mut body, c, &col, logo);
        }
    }
    // JSON.stringify of an object literal: keys in this order
    let config = json!({
        "siteId": c.site_id,
        "minutes": c.minutes,
        "chart": c.chart,
        "countries": c.countries,
        "backendUrl": c.backend_url,
    })
    .to_string();

    let mut html = String::with_capacity(8_192);
    templates::document(&mut html, c, &body, &config);
    html
}

/// `decodeURIComponent`, which is how Next decodes a route param: `None` where it
/// throws (a bad escape or bytes that are not UTF-8).
fn decode_uri_component(raw: &str) -> Option<String> {
    let bytes = raw.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let hex = bytes.get(index + 1..index + 3)?;
            let text = std::str::from_utf8(hex).ok()?;
            decoded.push(u8::from_str_radix(text, 16).ok().filter(|_| hex.iter().all(u8::is_ascii_hexdigit))?);
            index += 3;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(decoded).ok()
}

fn with_vary(mut response: Response) -> Response {
    response.headers_mut().insert(header::VARY, HeaderValue::from_static(NEXT_VARY));
    response
}

fn respond(site_id_raw: &str, query: Option<&str>, backend_url: &str) -> Response {
    let Some(site_id) = decode_uri_component(site_id_raw) else {
        // Next fails the request while decoding params, before the handler runs
        tracing::warn!(site_id = site_id_raw, "widget: malformed escape in site id");
        let mut response = Response::new(Body::from("Internal Server Error"));
        *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
        let headers = response.headers_mut();
        headers.insert(
            header::CACHE_CONTROL,
            HeaderValue::from_static("private, no-cache, no-store, max-age=0, must-revalidate"),
        );
        headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/plain"));
        return response;
    };

    if !is_valid_site_id(&site_id) {
        tracing::debug!(site_id = %site_id, "widget: invalid site id");
        let mut response = Response::new(Body::from("Invalid site id"));
        *response.status_mut() = StatusCode::BAD_REQUEST;
        response
            .headers_mut()
            .insert(header::CONTENT_TYPE, HeaderValue::from_static("text/plain;charset=UTF-8"));
        return with_vary(response);
    }

    let query = Query::parse(query);
    let config = config_from_request(&site_id, &query, backend_url);
    tracing::debug!(
        site_id = %site_id,
        minutes = config.minutes,
        chart = config.chart,
        countries = config.countries,
        theme = config.theme.as_str(),
        variant = ?config.variant,
        "widget rendered"
    );

    let mut response = Response::new(Body::from(render_html(&config)));
    let headers = response.headers_mut();
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=60, stale-while-revalidate=3600"),
    );
    headers.insert(header::CONTENT_SECURITY_POLICY, HeaderValue::from_static("frame-ancestors *"));
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/html; charset=utf-8"));
    headers.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    with_vary(response)
}

/// Every method on /widget/:siteId. Dispatched here rather than with a method
/// router, which would add an `Allow` header to the 405 that Next never sent.
pub async fn widget(State(state): State<AppState>, method: Method, uri: Uri) -> Response {
    match method {
        Method::GET | Method::HEAD => {
            // The router only sends single-segment paths here; read the raw segment
            // so it is decoded exactly like Next decodes params
            let raw = uri.path().strip_prefix("/widget/").unwrap_or_default();
            respond(raw, uri.query(), &state.config.widget_api_url)
        }
        Method::OPTIONS => options(),
        _ => method_not_allowed(),
    }
}

/// OPTIONS: Next answers route handlers itself with the methods they export.
fn options() -> Response {
    let mut response = Response::new(Body::empty());
    *response.status_mut() = StatusCode::NO_CONTENT;
    response
        .headers_mut()
        .insert(header::ALLOW, HeaderValue::from_static("GET, HEAD, OPTIONS"));
    with_vary(response)
}

/// Any other method: an empty 405, as Next sends for a method the handler lacks.
fn method_not_allowed() -> Response {
    let mut response = Response::new(Body::empty());
    *response.status_mut() = StatusCode::METHOD_NOT_ALLOWED;
    with_vary(response)
}

#[cfg(test)]
mod tests {
    use axum::body::to_bytes;
    use serde::Deserialize;

    use super::*;

    #[derive(Deserialize)]
    struct Case {
        name: String,
        path: String,
        status: u16,
        headers: std::collections::BTreeMap<String, String>,
        body: String,
    }

    /// The backend URL the Next build that produced cases.json was configured with
    const CAPTURED_API_URL: &str = "http://localhost:8491/api";

    #[tokio::test]
    async fn matches_the_next_route_handler_byte_for_byte() {
        let cases: Vec<Case> = serde_json::from_str(include_str!("cases.json")).expect("cases.json parses");
        assert!(cases.len() >= 20);
        for case in cases {
            let uri: Uri = case.path.parse().expect("case path is a URI");
            let raw = uri.path().strip_prefix("/widget/").expect("widget path");
            let response = respond(raw, uri.query(), CAPTURED_API_URL);

            assert_eq!(response.status().as_u16(), case.status, "{}: status", case.name);
            for (name, value) in &case.headers {
                let actual = response.headers().get(name.as_str()).and_then(|value| value.to_str().ok());
                assert_eq!(actual, Some(value.as_str()), "{}: header {name}", case.name);
            }
            let expected_headers: Vec<&str> = case.headers.keys().map(String::as_str).collect();
            for name in response.headers().keys() {
                assert!(expected_headers.contains(&name.as_str()), "{}: unexpected header {name}", case.name);
            }
            let body = to_bytes(response.into_body(), usize::MAX).await.expect("body");
            assert!(body == case.body.as_bytes(), "{}: body differs", case.name);
        }
    }

    #[test]
    fn decodes_like_decode_uri_component() {
        assert_eq!(decode_uri_component("abc%2Ddef").as_deref(), Some("abc-def"));
        assert_eq!(decode_uri_component("%C3%A9").as_deref(), Some("\u{e9}"));
        assert_eq!(decode_uri_component("a+b").as_deref(), Some("a+b"));
        assert_eq!(decode_uri_component("%zz"), None);
        assert_eq!(decode_uri_component("%4"), None);
        assert_eq!(decode_uri_component("%C3"), None);
        assert_eq!(decode_uri_component("%+1"), None);
    }

    #[tokio::test]
    async fn malformed_escapes_fail_like_next() {
        let response = respond("%zz", None, CAPTURED_API_URL);
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(response.headers()[header::CONTENT_TYPE], "text/plain");
        let body = to_bytes(response.into_body(), usize::MAX).await.expect("body");
        assert_eq!(&body[..], b"Internal Server Error");
    }

    #[test]
    fn minutes_follow_javascript_number_conversion() {
        let minutes = |query: &str| {
            let parsed = Query::parse(Some(query));
            config_from_request("abc", &parsed, CAPTURED_API_URL).minutes
        };
        assert_eq!(minutes("minutes=0X5A0"), 1440);
        assert_eq!(minutes("minutes=.144e4"), 1440);
        assert_eq!(minutes("minutes=1440."), 1440);
        assert_eq!(minutes("minutes=%C2%A01440"), 1440);
        assert_eq!(minutes("minutes=Infinity"), 30);
        assert_eq!(minutes("minutes=0b10011101100000"), 10080);
        assert_eq!(minutes(""), 30);
    }
}
