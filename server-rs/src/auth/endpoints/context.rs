//! The per-request state better-call and Better Auth thread through an endpoint:
//! parsed cookies, query and body, the accumulated response headers (with
//! `Headers` set/append semantics), the resolved session and the `APIError` shape.

use axum::http::{HeaderMap, Method, StatusCode};
use serde_json::{Map, Value, json};

use crate::state::AppState;

use super::db::SessionWithUser;

/// `APIError`: a status, an optional JSON body (`undefined` sends an empty body)
/// and headers to add to the response (`ctx.redirect` sets `location`).
#[derive(Clone, Debug)]
pub struct ApiError {
    pub status: StatusCode,
    pub body: Option<Value>,
    pub headers: Vec<(String, String)>,
}

impl ApiError {
    /// `APIError.from(status, { code, message })`: body `{message, code}`
    pub fn code(status: StatusCode, code: &str, message: &str) -> Self {
        Self { status, body: Some(json!({"message": message, "code": code})), headers: Vec::new() }
    }

    /// `APIError.fromStatus(status, { message })`: body `{message}`
    pub fn message(status: StatusCode, message: &str) -> Self {
        Self { status, body: Some(json!({"message": message})), headers: Vec::new() }
    }

    /// `APIError.fromStatus(status)` / `ctx.error(status)`: no body at all
    pub fn status(status: StatusCode) -> Self {
        Self { status, body: None, headers: Vec::new() }
    }

    /// An error with an arbitrary JSON body (OAuth errors carry `error` and `error_description`)
    pub fn body(status: StatusCode, body: Value) -> Self {
        Self { status, body: Some(body), headers: Vec::new() }
    }

    /// `ctx.redirect(url)`: a 302 APIError carrying `location`
    pub fn redirect(url: &str) -> Self {
        Self { status: StatusCode::FOUND, body: None, headers: vec![("location".into(), url.to_string())] }
    }

    /// A thrown non-APIError: better-call logs it and answers 500 with no body and
    /// none of the headers accumulated so far.
    pub fn internal() -> Self {
        Self { status: StatusCode::INTERNAL_SERVER_ERROR, body: None, headers: Vec::new() }
    }

    pub fn oauth(status: StatusCode, error: &str, description: &str) -> Self {
        Self::body(status, json!({"error_description": description, "error": error}))
    }
}

/// Database failures inside an endpoint are unexpected errors: logged, answered 500.
impl From<sqlx::Error> for ApiError {
    fn from(error: sqlx::Error) -> Self {
        tracing::error!(error = %error, "Better Auth endpoint database error");
        ApiError::internal()
    }
}

/// A successful endpoint result before `toResponse`.
#[derive(Clone, Debug)]
pub enum Reply {
    /// `ctx.json(value)` (also `null`), optionally with a status set by the handler
    Json(Value),
    /// A raw `Response` built by the handler (`/mcp/register`, `/error`)
    Raw { status: StatusCode, headers: Vec<(String, String)>, body: Option<String> },
}

pub type EndpointResult = Result<Reply, ApiError>;

/// Response headers with WHATWG `Headers` semantics: names are case-insensitive,
/// `set` replaces, `set-cookie` is appended and kept as separate values.
#[derive(Clone, Debug, Default)]
pub struct ResponseHeaders {
    pub cookies: Vec<String>,
    pub other: Vec<(String, String)>,
}

impl ResponseHeaders {
    pub fn set(&mut self, name: &str, value: &str) {
        let lower = name.to_ascii_lowercase();
        if lower == "set-cookie" {
            self.cookies = vec![value.to_string()];
            return;
        }
        self.other.retain(|(existing, _)| *existing != lower);
        self.other.push((lower, value.to_string()));
    }

    pub fn append_cookie(&mut self, cookie: String) {
        self.cookies.push(cookie);
    }

    pub fn get(&self, name: &str) -> Option<&str> {
        let lower = name.to_ascii_lowercase();
        self.other.iter().find(|(existing, _)| *existing == lower).map(|(_, value)| value.as_str())
    }

    /// `removeSetCookieEntries`: drop earlier cookies named exactly `name` or chunked `name.N`
    pub fn remove_cookies_named(&mut self, name: &str) {
        let exact = format!("{name}=");
        let chunk = format!("{name}.");
        self.cookies.retain(|cookie| !cookie.starts_with(&exact) && !cookie.starts_with(&chunk));
    }

    /// `mergeResponseHeaders`: cookies appended, other headers replaced
    pub fn merge(&mut self, other: ResponseHeaders) {
        self.cookies.extend(other.cookies);
        for (name, value) in other.other {
            self.set(&name, &value);
        }
    }
}

/// Whether the session lookup ran yet (`ctx.context.session` is `null` both before
/// and after a miss, but Better Auth only memoises hits).
#[derive(Clone, Debug)]
pub enum SessionSlot {
    Unresolved,
    Resolved(Box<Option<SessionWithUser>>),
}

pub struct Ctx<'a> {
    pub state: &'a AppState,
    pub method: Method,
    /// Path below the base path, e.g. `/sign-in/email`
    pub path: String,
    /// Raw query string (without `?`), as `request.url.split("?")[1]` sees it
    pub raw_query: Option<String>,
    pub headers: &'a HeaderMap,
    /// `parseCookies(cookie header)`: first occurrence wins
    pub cookies: Vec<(String, String)>,
    /// `url.searchParams` folded into an object: repeated keys become arrays
    pub query: Map<String, Value>,
    /// The parsed body: JSON, a form object, text, or absent
    pub body: Option<Value>,
    pub response: ResponseHeaders,
    pub session: SessionSlot,
    /// `ctx.context.newSession`, set by `setSessionCookie`
    pub new_session: Option<SessionWithUser>,
    /// Better Auth's `getIp`: the single trusted X-Forwarded-For address
    pub ip: Option<String>,
}

impl<'a> Ctx<'a> {
    pub fn secret(&self) -> &str {
        self.state.config.better_auth_secret.as_deref().unwrap_or_default()
    }

    pub fn production(&self) -> bool {
        self.state.config.production
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).and_then(|value| value.to_str().ok())
    }

    /// `ctx.getCookie(name)`
    pub fn cookie(&self, name: &str) -> Option<&str> {
        self.cookies.iter().find(|(key, _)| key == name).map(|(_, value)| value.as_str())
    }

    /// `ctx.getSignedCookie(name, secret)`: `None` when absent or empty, `Some(None)`
    /// when the signature is wrong (JS `false`), `Some(Some(value))` when valid.
    pub fn signed_cookie(&self, name: &str) -> Option<Option<String>> {
        let value = self.cookie(name).filter(|value| !value.is_empty())?;
        let dot = value.rfind('.')?;
        if dot < 1 {
            return None;
        }
        let signature = &value[dot + 1..];
        if signature.chars().count() != 44 || !signature.ends_with('=') {
            return None;
        }
        Some(crate::auth::session::verify_signed_value(value, self.secret()))
    }

    /// The signed cookie's value only when it verifies (JS truthiness of the result)
    pub fn verified_cookie(&self, name: &str) -> Option<String> {
        self.signed_cookie(name).flatten().filter(|value| !value.is_empty())
    }

    pub fn body_object(&self) -> Option<&Map<String, Value>> {
        self.body.as_ref().and_then(Value::as_object)
    }

    /// `ctx.body.<field>` as a string when it is one
    pub fn body_str(&self, field: &str) -> Option<&str> {
        self.body_object().and_then(|body| body.get(field)).and_then(Value::as_str)
    }

    pub fn query_str(&self, field: &str) -> Option<&str> {
        self.query.get(field).and_then(Value::as_str)
    }

    pub fn user_agent(&self) -> String {
        self.header("user-agent").unwrap_or_default().to_string()
    }
}

/// JavaScript truthiness for JSON values
pub fn truthy(value: Option<&Value>) -> bool {
    match value {
        None | Some(Value::Null) => false,
        Some(Value::Bool(flag)) => *flag,
        Some(Value::Number(number)) => number.as_f64().is_some_and(|n| n != 0.0 && !n.is_nan()),
        Some(Value::String(text)) => !text.is_empty(),
        Some(_) => true,
    }
}
