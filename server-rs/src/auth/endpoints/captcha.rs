//! The captcha plugin's `onRequest` (better-auth/dist/plugins/captcha) as auth.ts
//! enables it: Cloudflare Turnstile, only when `CLOUD=true`, `TURNSTILE_SECRET_KEY`
//! is set and `NODE_ENV=production`. It runs after the rate limiter and before
//! routing, on the raw pathname, so unknown paths that contain a guarded endpoint
//! are checked too.

use std::time::Duration;

use axum::{
    body::Body,
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::Response,
};
use serde_json::{Value, json};
use tracing::{debug, error, info, warn};

use crate::config::Config;

const SITE_VERIFY_URL: &str = "https://challenges.cloudflare.com/turnstile/v0/siteverify";
/// `CAPTCHA_VERIFY_TIMEOUT_MS`
const VERIFY_TIMEOUT: Duration = Duration::from_secs(10);
/// `defaultEndpoints`
const GUARDED: [&str; 3] = ["/sign-up/email", "/sign-in/email", "/request-password-reset"];
const EXEMPT: &str = "/sign-in/email-otp";

/// The secret when the plugin is registered at all.
pub fn secret_key(config: &Config) -> Option<&str> {
    let auth = &config.auth;
    (auth.cloud && config.production).then_some(()).and(auth.turnstile_secret_key.as_deref()).filter(|key| !key.is_empty())
}

/// The plugin's pathname massaging: base path removed (first occurrence), one
/// doubled slash trimmed at either end, leading slash ensured.
fn plugin_pathname(full_path: &str) -> String {
    let mut pathname = full_path.replacen("/api/auth", "", 1);
    if pathname.ends_with("//") {
        pathname.pop();
    }
    if pathname.starts_with("//") {
        pathname.remove(0);
    }
    if !pathname.starts_with('/') {
        pathname.insert(0, '/');
    }
    pathname
}

pub fn is_guarded(full_path: &str) -> bool {
    let pathname = plugin_pathname(full_path);
    GUARDED.iter().any(|endpoint| pathname.contains(endpoint) && !pathname.contains(EXEMPT))
}

/// `middlewareResponse`: a JSON body in a bare `Response`, so undici labels it text/plain.
fn middleware_response(status: StatusCode, code: &str, message: &str) -> Response {
    let mut response = Response::new(Body::from(json!({"message": message, "code": code}).to_string()));
    *response.status_mut() = status;
    response.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("text/plain;charset=UTF-8"));
    response
}

/// `None` lets the request through; `Some` is the plugin's short-circuit response.
pub async fn on_request(config: &Config, full_path: &str, headers: &HeaderMap, ip: Option<&str>) -> Option<Response> {
    let secret = secret_key(config)?;
    if !is_guarded(full_path) {
        return None;
    }
    verify(SITE_VERIFY_URL, secret, full_path, headers, ip).await
}

async fn verify(site_verify_url: &str, secret: &str, full_path: &str, headers: &HeaderMap, ip: Option<&str>) -> Option<Response> {
    let captcha_response = joined_header(headers, "x-captcha-response").filter(|value| !value.is_empty());
    let Some(captcha_response) = captcha_response else {
        info!(path = %full_path, "Captcha response header missing");
        return Some(middleware_response(StatusCode::BAD_REQUEST, "MISSING_RESPONSE", "Missing CAPTCHA response"));
    };
    let unknown = || middleware_response(StatusCode::INTERNAL_SERVER_ERROR, "UNKNOWN_ERROR", "Something went wrong");
    let mut payload = serde_json::Map::new();
    payload.insert("secret".into(), Value::from(secret));
    payload.insert("response".into(), Value::from(captcha_response));
    if let Some(ip) = ip.filter(|ip| !ip.is_empty()) {
        payload.insert("remoteip".into(), Value::from(ip));
    }
    let client = match reqwest::Client::builder().timeout(VERIFY_TIMEOUT).build() {
        Ok(client) => client,
        Err(err) => {
            error!(error = %err, "Captcha HTTP client could not be built");
            return Some(unknown());
        }
    };
    let result = client
        .post(site_verify_url)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Value::Object(payload).to_string())
        .send()
        .await;
    let response = match result {
        Ok(response) => response,
        Err(err) => {
            error!(error = %err, "CAPTCHA service unavailable");
            return Some(unknown());
        }
    };
    let status = response.status();
    let is_json = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.split(';').next().is_some_and(|mime| mime.trim().eq_ignore_ascii_case("application/json") || mime.trim().ends_with("+json")));
    let text = match response.text().await {
        Ok(text) => text,
        Err(err) => {
            error!(error = %err, "CAPTCHA service response unreadable");
            return Some(unknown());
        }
    };
    if !status.is_success() {
        error!(status = status.as_u16(), "CAPTCHA service unavailable");
        return Some(unknown());
    }
    // betterFetch: JSON bodies are parsed, anything else stays text
    let data = if is_json {
        match serde_json::from_str::<Value>(&text) {
            Ok(value) => value,
            Err(err) => {
                error!(error = %err, "CAPTCHA service returned invalid JSON");
                return Some(unknown());
            }
        }
    } else {
        Value::String(text)
    };
    if !super::better_json::is_truthy(&data) {
        error!("CAPTCHA service unavailable (empty response)");
        return Some(unknown());
    }
    let success = data.get("success").is_some_and(super::better_json::is_truthy);
    if !success {
        warn!(path = %full_path, "Captcha verification failed");
        return Some(middleware_response(StatusCode::FORBIDDEN, "VERIFICATION_FAILED", "Captcha verification failed"));
    }
    debug!(path = %full_path, "Captcha verified");
    None
}

/// `Headers.get`: repeated headers joined with ", ".
fn joined_header(headers: &HeaderMap, name: &str) -> Option<String> {
    let values: Vec<&str> = headers.get_all(name).iter().filter_map(|value| value.to_str().ok()).collect();
    (!values.is_empty()).then(|| values.join(", "))
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use axum::{Json, Router, extract::State, routing::post};

    use super::*;

    #[test]
    fn guarded_paths() {
        assert!(is_guarded("/api/auth/sign-in/email"));
        assert!(is_guarded("/api/auth/sign-up/email"));
        assert!(is_guarded("/api/auth/email-otp/request-password-reset"));
        assert!(is_guarded("/api/auth/sign-in/emailx"));
        assert!(!is_guarded("/api/auth/sign-in/email-otp"));
        assert!(!is_guarded("/api/auth/sign-in/social"));
        assert!(!is_guarded("/api/auth/get-session"));
        assert_eq!(plugin_pathname("/api/auth//sign-in/email//"), "/sign-in/email/");
    }

    async fn body_of(response: Response) -> (u16, String) {
        let status = response.status().as_u16();
        let bytes = axum::body::to_bytes(response.into_body(), 1 << 16).await.unwrap();
        (status, String::from_utf8(bytes.to_vec()).unwrap())
    }

    /// A local stand-in for siteverify that records what it was sent.
    async fn fake_siteverify(reply: Value) -> (String, Arc<Mutex<Vec<Value>>>) {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let app = Router::new()
            .route(
                "/siteverify",
                post(|State((reply, seen)): State<(Value, Arc<Mutex<Vec<Value>>>)>, Json(body): Json<Value>| async move {
                    seen.lock().unwrap().push(body);
                    Json(reply)
                }),
            )
            .with_state((reply, seen.clone()));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (format!("http://{addr}/siteverify"), seen)
    }

    #[tokio::test]
    async fn verification_outcomes() {
        let mut headers = HeaderMap::new();
        let missing = verify("http://127.0.0.1:9/unused", "s", "/api/auth/sign-in/email", &headers, None).await.unwrap();
        assert_eq!(body_of(missing).await, (400, r#"{"message":"Missing CAPTCHA response","code":"MISSING_RESPONSE"}"#.to_string()));

        headers.insert("x-captcha-response", HeaderValue::from_static("token"));
        let (url, seen) = fake_siteverify(json!({"success": true})).await;
        assert!(verify(&url, "secret", "/api/auth/sign-in/email", &headers, Some("1.2.3.4")).await.is_none());
        assert_eq!(seen.lock().unwrap()[0].to_string(), r#"{"secret":"secret","response":"token","remoteip":"1.2.3.4"}"#);

        let (url, _) = fake_siteverify(json!({"success": false})).await;
        let failed = verify(&url, "secret", "/api/auth/sign-in/email", &headers, None).await.unwrap();
        assert_eq!(body_of(failed).await, (403, r#"{"message":"Captcha verification failed","code":"VERIFICATION_FAILED"}"#.to_string()));

        let unreachable = verify("http://127.0.0.1:9/siteverify", "secret", "/api/auth/sign-in/email", &headers, None).await.unwrap();
        assert_eq!(body_of(unreachable).await, (500, r#"{"message":"Something went wrong","code":"UNKNOWN_ERROR"}"#.to_string()));
    }
}
