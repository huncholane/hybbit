//! `/api/auth/*`: the Better Auth 1.6.25 HTTP surface this app uses, reimplemented
//! request for request. The pipeline mirrors what a request goes through in Node:
//!
//! 1. Fastify's body gate (server/src/index.ts registers no-op JSON and form
//!    parsers for this mount, so other bodies are 415 or swallowed),
//! 2. better-call's router `onRequest` (Better Auth's in-memory rate limiter),
//! 3. route matching under the base path (404 with an empty body otherwise),
//! 4. body parsing against the route's allowed media types,
//! 5. `originCheckMiddleware`,
//! 6. `dispatchAuthEndpoint`: before hooks, the endpoint (validation, `use`
//!    middlewares, handler), after hooks, then `toResponse`.
//!
//! See AUTH_COMPAT.md for the configuration this reproduces.
#![allow(dead_code)]

pub mod admin;
pub mod api_key;
pub mod better_json;
pub mod captcha;
pub mod context;
pub mod cookies;
pub mod core_routes;
pub mod crypto;
pub mod dash;
pub mod db;
pub mod email_otp;
pub mod mcp;
pub mod organization;
pub mod origin;
pub mod rate_limit;
pub mod validate;

use axum::{
    Router,
    body::{Body, to_bytes},
    extract::{Request, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode, header},
    response::Response,
    routing::any,
};
use serde_json::{Map, Value, json};
use tracing::{debug, error, info, warn};

use crate::{config::Config, state::AppState};

use context::{ApiError, Ctx, EndpointResult, Reply, ResponseHeaders, SessionSlot};
use db::SessionWithUser;

/// `session.expiresIn` default: 7 days
pub const SESSION_EXPIRES_IN: i64 = 604_800;
/// `session.updateAge` default: 1 day
pub const SESSION_UPDATE_AGE: i64 = 86_400;
/// `session.freshAge` default: 1 day
pub const SESSION_FRESH_AGE: i64 = 86_400;

/// Fastify's bodyLimit, which also bounds what Better Auth can read here
const BODY_LIMIT: usize = 10 * 1024 * 1024;

/// Every path under /api/auth, answered like Node's Better Auth mount.
pub fn router() -> Router<AppState> {
    Router::new().route("/api/auth/", any(handle)).route("/api/auth/{*rest}", any(handle))
}

/// Better Auth's `baseURL` (`getBaseURL(undefined, "/api/auth")`): the first set
/// variable of the env chain, with `/api/auth` appended unless it already has a path.
pub fn base_url(config: &Config) -> Option<String> {
    let raw = config.auth.base_url_env.as_deref()?;
    let parsed = url::Url::parse(raw).ok().filter(|url| matches!(url.scheme(), "http" | "https"))?;
    let path = parsed.path().trim_end_matches('/');
    if !path.is_empty() {
        return Some(raw.to_string());
    }
    Some(format!("{}/api/auth", raw.trim_end_matches('/')))
}

/// `options.baseURL` after `createAuthContext`: the origin of the base URL
pub fn base_origin(config: &Config) -> Option<String> {
    base_url(config).and_then(|base| origin::url_origin(&base))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Media {
    /// The router default: JSON only
    Json,
    /// `metadata.allowedMediaTypes: ["application/x-www-form-urlencoded", "application/json"]`
    FormOrJson,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Endpoint {
    GetSession,
    SignOut,
    SignInEmail,
    SignInSocial,
    SignUpEmail,
    UpdateUser,
    ChangePassword,
    ChangeEmail,
    DeleteUser,
    VerifyEmail,
    SendVerificationEmail,
    ListSessions,
    RevokeSession,
    RevokeSessions,
    RevokeOtherSessions,
    Ok,
    Error,
    EmailOtp(email_otp::Route),
    Organization(organization::Route),
    ApiKey(api_key::Route),
    Admin(admin::Route),
    Mcp(mcp::Route),
}

struct RouteDef {
    methods: &'static [Method],
    path: &'static str,
    endpoint: Endpoint,
    media: Media,
}

const GET: &[Method] = &[Method::GET];
const POST: &[Method] = &[Method::POST];
const GET_POST: &[Method] = &[Method::GET, Method::POST];

macro_rules! route {
    ($methods:expr, $path:expr, $endpoint:expr) => {
        RouteDef { methods: $methods, path: $path, endpoint: $endpoint, media: Media::Json }
    };
    ($methods:expr, $path:expr, $endpoint:expr, form) => {
        RouteDef { methods: $methods, path: $path, endpoint: $endpoint, media: Media::FormOrJson }
    };
}

/// The routes this service implements. Anything else under /api/auth answers
/// Better Auth's 404; `UNPORTED_ROUTES` lists the Node routes that still exist there.
static ROUTES: &[RouteDef] = &[
    route!(POST, "/sign-in/social", Endpoint::SignInSocial),
    route!(GET_POST, "/get-session", Endpoint::GetSession),
    route!(POST, "/sign-out", Endpoint::SignOut),
    route!(POST, "/sign-up/email", Endpoint::SignUpEmail, form),
    route!(POST, "/sign-in/email", Endpoint::SignInEmail, form),
    route!(GET, "/verify-email", Endpoint::VerifyEmail),
    route!(POST, "/send-verification-email", Endpoint::SendVerificationEmail),
    route!(POST, "/change-email", Endpoint::ChangeEmail),
    route!(POST, "/change-password", Endpoint::ChangePassword),
    route!(POST, "/update-user", Endpoint::UpdateUser),
    route!(POST, "/delete-user", Endpoint::DeleteUser),
    route!(GET, "/list-sessions", Endpoint::ListSessions),
    route!(POST, "/revoke-session", Endpoint::RevokeSession),
    route!(POST, "/revoke-sessions", Endpoint::RevokeSessions),
    route!(POST, "/revoke-other-sessions", Endpoint::RevokeOtherSessions),
    route!(POST, "/admin/set-role", Endpoint::Admin(admin::Route::SetRole)),
    route!(GET, "/admin/get-user", Endpoint::Admin(admin::Route::GetUser)),
    route!(POST, "/admin/update-user", Endpoint::Admin(admin::Route::UpdateUser)),
    route!(GET, "/admin/list-users", Endpoint::Admin(admin::Route::ListUsers)),
    route!(POST, "/admin/list-user-sessions", Endpoint::Admin(admin::Route::ListUserSessions)),
    route!(POST, "/admin/unban-user", Endpoint::Admin(admin::Route::UnbanUser)),
    route!(POST, "/admin/ban-user", Endpoint::Admin(admin::Route::BanUser)),
    route!(POST, "/admin/impersonate-user", Endpoint::Admin(admin::Route::ImpersonateUser)),
    route!(POST, "/admin/stop-impersonating", Endpoint::Admin(admin::Route::StopImpersonating)),
    route!(POST, "/admin/revoke-user-session", Endpoint::Admin(admin::Route::RevokeUserSession)),
    route!(POST, "/admin/revoke-user-sessions", Endpoint::Admin(admin::Route::RevokeUserSessions)),
    route!(POST, "/admin/has-permission", Endpoint::Admin(admin::Route::HasPermission)),
    route!(POST, "/oauth2/consent", Endpoint::Mcp(mcp::Route::Consent)),
    route!(GET, "/.well-known/oauth-authorization-server", Endpoint::Mcp(mcp::Route::AuthorizationServer)),
    route!(GET, "/.well-known/oauth-protected-resource", Endpoint::Mcp(mcp::Route::ProtectedResource)),
    route!(GET, "/mcp/authorize", Endpoint::Mcp(mcp::Route::Authorize)),
    route!(POST, "/mcp/token", Endpoint::Mcp(mcp::Route::Token), form),
    route!(POST, "/mcp/register", Endpoint::Mcp(mcp::Route::Register)),
    route!(GET, "/mcp/get-session", Endpoint::Mcp(mcp::Route::GetSession)),
    route!(POST, "/api-key/delete", Endpoint::ApiKey(api_key::Route::Delete)),
    route!(GET, "/api-key/list", Endpoint::ApiKey(api_key::Route::List)),
    route!(POST, "/organization/create", Endpoint::Organization(organization::Route::Create)),
    route!(POST, "/organization/update", Endpoint::Organization(organization::Route::Update)),
    route!(POST, "/organization/delete", Endpoint::Organization(organization::Route::Delete)),
    route!(POST, "/organization/set-active", Endpoint::Organization(organization::Route::SetActive)),
    route!(GET, "/organization/get-full-organization", Endpoint::Organization(organization::Route::GetFull)),
    route!(GET, "/organization/list", Endpoint::Organization(organization::Route::List)),
    route!(POST, "/organization/invite-member", Endpoint::Organization(organization::Route::InviteMember)),
    route!(POST, "/organization/cancel-invitation", Endpoint::Organization(organization::Route::CancelInvitation)),
    route!(POST, "/organization/accept-invitation", Endpoint::Organization(organization::Route::AcceptInvitation)),
    route!(GET, "/organization/get-invitation", Endpoint::Organization(organization::Route::GetInvitation)),
    route!(POST, "/organization/reject-invitation", Endpoint::Organization(organization::Route::RejectInvitation)),
    route!(GET, "/organization/list-invitations", Endpoint::Organization(organization::Route::ListInvitations)),
    route!(GET, "/organization/get-active-member", Endpoint::Organization(organization::Route::GetActiveMember)),
    route!(POST, "/organization/check-slug", Endpoint::Organization(organization::Route::CheckSlug)),
    route!(POST, "/organization/remove-member", Endpoint::Organization(organization::Route::RemoveMember)),
    route!(POST, "/organization/update-member-role", Endpoint::Organization(organization::Route::UpdateMemberRole)),
    route!(POST, "/organization/leave", Endpoint::Organization(organization::Route::Leave)),
    route!(GET, "/organization/list-user-invitations", Endpoint::Organization(organization::Route::ListUserInvitations)),
    route!(POST, "/organization/has-permission", Endpoint::Organization(organization::Route::HasPermission)),
    route!(POST, "/email-otp/send-verification-otp", Endpoint::EmailOtp(email_otp::Route::SendVerificationOtp)),
    route!(POST, "/email-otp/check-verification-otp", Endpoint::EmailOtp(email_otp::Route::CheckVerificationOtp)),
    route!(POST, "/email-otp/verify-email", Endpoint::EmailOtp(email_otp::Route::VerifyEmail)),
    route!(POST, "/sign-in/email-otp", Endpoint::EmailOtp(email_otp::Route::SignIn)),
    route!(POST, "/email-otp/request-password-reset", Endpoint::EmailOtp(email_otp::Route::RequestPasswordReset)),
    route!(POST, "/forget-password/email-otp", Endpoint::EmailOtp(email_otp::Route::ForgetPassword)),
    route!(POST, "/email-otp/reset-password", Endpoint::EmailOtp(email_otp::Route::ResetPassword)),
    route!(POST, "/email-otp/request-email-change", Endpoint::EmailOtp(email_otp::Route::RequestEmailChange)),
    route!(POST, "/email-otp/change-email", Endpoint::EmailOtp(email_otp::Route::ChangeEmail)),
    route!(GET, "/ok", Endpoint::Ok),
    route!(GET, "/error", Endpoint::Error),
];

/// Node routes not implemented here: they answer 404 from this service, so Caddy
/// must keep sending them to Node (none of them is called by the dashboard).
pub const UNPORTED_ROUTES: &[&str] = &[
    "GET,POST /callback/:id",
    "POST /reset-password",
    "POST /verify-password",
    "POST /update-session",
    "POST /request-password-reset",
    "GET /reset-password/:token",
    "POST /link-social",
    "GET /list-accounts",
    "GET /delete-user/callback",
    "POST /unlink-account",
    "POST /refresh-token",
    "POST /get-access-token",
    "GET /account-info",
    "POST /admin/create-user",
    "POST /admin/remove-user",
    "POST /admin/set-user-password",
    "POST /api-key/create",
    "GET /api-key/get",
    "POST /api-key/update",
    "GET /organization/list-members",
    "GET /organization/get-active-member-role",
    "POST /organization/create-team",
    "GET /organization/list-teams",
    "POST /organization/remove-team",
    "POST /organization/update-team",
    "POST /organization/set-active-team",
    "GET /organization/list-user-teams",
    "GET /organization/list-team-members",
    "POST /organization/add-team-member",
    "POST /organization/remove-team-member",
    "every /dash/* and /events/* route of @better-auth/infra (see dash.rs)",
];

/// Paths this router answers the way Node does, for the Caddy matcher.
pub fn ported_paths() -> Vec<&'static str> {
    ROUTES.iter().map(|route| route.path).collect()
}

fn find_route(method: &Method, path: &str) -> Option<(Endpoint, Media)> {
    ROUTES.iter().find(|route| route.path == path && route.methods.contains(method)).map(|route| (route.endpoint, route.media))
}

/// Better Auth's own 404 (`new Response(null, { status: 404 })`)
fn empty_404() -> Response {
    let mut response = Response::new(Body::empty());
    *response.status_mut() = StatusCode::NOT_FOUND;
    response
}

static CLOUD_WARNING: std::sync::Once = std::sync::Once::new();

async fn handle(State(state): State<AppState>, request: Request) -> Response {
    if state.config.auth.cloud {
        CLOUD_WARNING.call_once(|| {
            warn!(
                "CLOUD=true: the Rust /api/auth port does not enforce auth.ts's cloud-only plan gates \
                 (invite-member member limits) nor send the welcome email or marketing contact on user creation; \
                 keep /api/auth on Node for cloud deployments"
            )
        });
    }
    let (parts, body) = request.into_parts();
    let method = parts.method.clone();
    let full_path = parts.uri.path().to_string();
    let raw_query = parts.uri.query().map(str::to_string);

    let bytes = match to_bytes(body, BODY_LIMIT).await {
        Ok(bytes) => bytes,
        Err(err) => {
            warn!(error = %err, path = %full_path, "Auth request body could not be read");
            return fastify_error(StatusCode::PAYLOAD_TOO_LARGE, "FST_ERR_CTP_BODY_TOO_LARGE", "Payload Too Large", "Request body is too large");
        }
    };

    // 1. Fastify's content-type gate for this mount
    let body = match fastify_body_gate(&method, &parts.headers, bytes) {
        Ok(body) => body,
        Err(response) => return *response,
    };

    let dev_or_test = state.config.auth.development || state.config.auth.test;
    let ip = rate_limit::client_ip(&parts.headers, dev_or_test);

    // 2. onRequest: the rate limiter runs before routing, keyed on ip|path
    if state.config.production {
        let limited_path = rate_limit::normalize_pathname(&full_path);
        if let Some(retry_after) = rate_limit::consume(ip.as_deref(), &limited_path) {
            info!(path = %limited_path, "Better Auth rate limit refused a request");
            let mut response = Response::new(Body::from(r#"{"message":"Too many requests. Please try again later."}"#));
            *response.status_mut() = StatusCode::TOO_MANY_REQUESTS;
            response.headers_mut().insert("x-retry-after", HeaderValue::from(retry_after));
            response.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("text/plain;charset=UTF-8"));
            return response;
        }
    }
    // the captcha plugin's onRequest follows the limiter (CLOUD production only)
    if let Some(response) = captcha::on_request(&state.config, &full_path, &parts.headers, ip.as_deref()).await {
        return response;
    }

    // 3. routing below the base path
    let Some(path) = full_path.strip_prefix("/api/auth").map(str::to_string) else { return empty_404() };
    if path.is_empty() || path.contains("//") {
        return empty_404();
    }
    let lookup = path.strip_suffix('/').unwrap_or(&path);
    let Some((endpoint, media)) = find_route(&method, lookup) else {
        debug!(method = %method, path = %path, "No Better Auth route");
        return empty_404();
    };
    if path.ends_with('/') {
        return empty_404();
    }

    let cookies = crate::auth::session::cookie_header(&parts.headers)
        .map(|header| crate::auth::session::parse_cookies(&header))
        .unwrap_or_default();
    let query = parse_query(raw_query.as_deref());

    let mut ctx = Ctx {
        state: &state,
        method: method.clone(),
        path: path.clone(),
        raw_query,
        headers: &parts.headers,
        cookies,
        query,
        body: None,
        response: ResponseHeaders::default(),
        session: SessionSlot::Unresolved,
        new_session: None,
        ip,
    };

    // 4. body parsing, 5. origin check: failures are APIErrors answered directly
    let prepared = parse_body(&ctx, body.as_deref(), media).and_then(|parsed| {
        ctx.body = parsed;
        origin::origin_check_middleware(&ctx)
    });
    if let Err(err) = prepared {
        debug!(method = %method, path = %path, status = err.status.as_u16(), "Auth request refused before its endpoint");
        return to_response(Err(err), ResponseHeaders::default());
    }

    // 6. dispatch
    let result = run_endpoint(&mut ctx, endpoint).await;
    let result = after_hooks(&mut ctx, endpoint, result).await;
    let status = match &result {
        Ok(_) => 200,
        Err(err) => err.status.as_u16(),
    };
    if status >= 500 {
        error!(method = %method, path = %path, status, "Auth endpoint failed");
    } else {
        debug!(method = %method, path = %path, status, "Auth endpoint answered");
    }
    let headers = std::mem::take(&mut ctx.response);
    to_response(result, headers)
}

/// Fastify in front of Better Auth: GET/HEAD bodies are ignored; a body without a
/// content type, or with a type no parser handles, is a 415 (rewritten by the api
/// error hook); `text/plain` is consumed by Fastify's default parser so Better Auth
/// sees no body; JSON and form bodies pass through untouched. Returns the body
/// Better Auth reads (None when it sees none).
fn fastify_body_gate(method: &Method, headers: &HeaderMap, bytes: axum::body::Bytes) -> Result<Option<Vec<u8>>, Box<Response>> {
    if matches!(*method, Method::GET | Method::HEAD | Method::TRACE) {
        return Ok(None);
    }
    let content_type = headers.get(header::CONTENT_TYPE).map(|value| String::from_utf8_lossy(value.as_bytes()).into_owned());
    let content_length = headers.get(header::CONTENT_LENGTH).and_then(|value| value.to_str().ok()).map(str::to_string);
    let chunked = headers.contains_key(header::TRANSFER_ENCODING);
    let Some(content_type) = content_type else {
        let empty = !chunked && content_length.as_deref().is_none_or(|length| length == "0");
        if empty {
            return Ok(None);
        }
        return Err(Box::new(unsupported_media_type()));
    };
    let Some(media_type) = fastify_media_type(&content_type) else {
        return Err(Box::new(unsupported_media_type()));
    };
    match media_type.as_str() {
        "application/json" | "application/x-www-form-urlencoded" => {}
        "text/plain" => return Ok(None),
        _ => return Err(Box::new(unsupported_media_type())),
    }
    // better-call's get_raw_body: no stream for a zero or missing length without chunking
    let length: Option<f64> = content_length.as_deref().map(|length| length.trim().parse::<f64>().unwrap_or(f64::NAN));
    let has_stream = match length {
        Some(length) if length.is_nan() => chunked,
        None => chunked,
        Some(length) => length != 0.0,
    };
    Ok(has_stream.then(|| bytes.to_vec()))
}

/// Fastify's `ContentType` parser: `type/subtype` lowercased, validated as tokens
fn fastify_media_type(header: &str) -> Option<String> {
    let token = |text: &str| !text.is_empty() && text.chars().all(|c| c.is_ascii_alphanumeric() || "!#$%&'*+.^_`|~-".contains(c));
    let media = header.split(';').next().unwrap_or_default().to_ascii_lowercase();
    let (kind, subtype) = media.split_once('/')?;
    let kind = kind.trim_start();
    let subtype = subtype.trim_end();
    (token(kind) && token(subtype)).then(|| format!("{kind}/{subtype}"))
}

/// Fastify's FST_ERR_CTP_INVALID_MEDIA_TYPE after server/src/lib/api-errors.ts rewrote it
fn unsupported_media_type() -> Response {
    fastify_error(
        StatusCode::UNSUPPORTED_MEDIA_TYPE,
        "FST_ERR_CTP_INVALID_MEDIA_TYPE",
        "Unsupported Media Type",
        "Unsupported Media Type",
    )
}

fn fastify_error(status: StatusCode, code: &str, error: &str, message: &str) -> Response {
    let payload = json!({"statusCode": status.as_u16(), "code": code, "error": error, "message": message});
    let normalized = crate::http::errors::normalize_api_error(status.as_u16(), payload);
    let mut response = crate::http::json(status, &Value::Object(normalized));
    response.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response.headers_mut().insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    response
}

/// `url.searchParams.forEach` folded into an object: repeated keys become arrays
fn parse_query(raw: Option<&str>) -> Map<String, Value> {
    let mut query = Map::new();
    let Some(raw) = raw else { return query };
    for (key, value) in url::form_urlencoded::parse(raw.as_bytes()) {
        let value = Value::String(value.into_owned());
        match query.get_mut(key.as_ref()) {
            None => {
                query.insert(key.into_owned(), value);
            }
            Some(Value::Array(items)) => items.push(value),
            Some(existing) => {
                let first = existing.take();
                *existing = Value::Array(vec![first, value]);
            }
        }
    }
    query
}

/// better-call `getBody`: the route's allowed media types, then JSON (400 on a
/// syntax error), form fields (last value wins) or text.
fn parse_body(ctx: &Ctx<'_>, body: Option<&[u8]>, media: Media) -> Result<Option<Value>, ApiError> {
    let Some(body) = body else { return Ok(None) };
    let content_type = ctx.header("content-type").unwrap_or_default().to_string();
    let normalized = content_type.to_lowercase();
    let base = normalized.split(';').next().unwrap_or_default().trim().to_string();
    let allowed: &[&str] = match media {
        Media::Json => &["application/json"],
        Media::FormOrJson => &["application/x-www-form-urlencoded", "application/json"],
    };
    if !allowed.iter().any(|allowed| base == *allowed || base.contains(allowed)) {
        let list = allowed.join(", ");
        if normalized.is_empty() {
            return Err(ApiError::code(
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "UNSUPPORTED_MEDIA_TYPE",
                &format!("Content-Type is required. Allowed types: {list}"),
            ));
        }
        return Err(ApiError::code(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "UNSUPPORTED_MEDIA_TYPE",
            &format!("Content-Type \"{content_type}\" is not allowed. Allowed types: {list}"),
        ));
    }
    let is_json = {
        let lower = normalized.as_str();
        lower.strip_prefix("application/").is_some_and(|rest| {
            let suffix_start = rest.find("json");
            match suffix_start {
                Some(0) => true,
                Some(index) => rest[..index].ends_with('+') && rest[..index - 1].chars().all(|c| c.is_ascii_alphanumeric() || ".+-".contains(c)),
                None => false,
            }
        })
    };
    if is_json {
        // Request.json(): UTF-8 decode (BOM stripped), then JSON.parse
        let text = String::from_utf8_lossy(body);
        let text = text.strip_prefix('\u{feff}').unwrap_or(&text);
        return serde_json::from_str::<Value>(text)
            .map(Some)
            .map_err(|_| ApiError::code(StatusCode::BAD_REQUEST, "BAD_REQUEST", "Invalid JSON in request body"));
    }
    if normalized.contains("application/x-www-form-urlencoded") {
        let mut fields = Map::new();
        for (key, value) in url::form_urlencoded::parse(body) {
            fields.insert(key.into_owned(), Value::String(value.into_owned()));
        }
        return Ok(Some(Value::Object(fields)));
    }
    Ok(Some(Value::String(String::from_utf8_lossy(body).into_owned())))
}

async fn run_endpoint(ctx: &mut Ctx<'_>, endpoint: Endpoint) -> EndpointResult {
    match endpoint {
        Endpoint::GetSession => core_routes::get_session_endpoint(ctx).await,
        Endpoint::SignOut => core_routes::sign_out(ctx).await,
        Endpoint::SignInEmail => core_routes::sign_in_email(ctx).await,
        Endpoint::SignInSocial => core_routes::sign_in_social(ctx).await,
        Endpoint::SignUpEmail => core_routes::sign_up_email(ctx).await,
        Endpoint::UpdateUser => core_routes::update_user(ctx).await,
        Endpoint::ChangePassword => core_routes::change_password(ctx).await,
        Endpoint::ChangeEmail => core_routes::change_email(ctx).await,
        Endpoint::DeleteUser => core_routes::delete_user(ctx).await,
        Endpoint::VerifyEmail => core_routes::verify_email(ctx).await,
        Endpoint::SendVerificationEmail => core_routes::send_verification_email(ctx).await,
        Endpoint::ListSessions => core_routes::list_sessions(ctx).await,
        Endpoint::RevokeSession => core_routes::revoke_session(ctx).await,
        Endpoint::RevokeSessions => core_routes::revoke_sessions(ctx).await,
        Endpoint::RevokeOtherSessions => core_routes::revoke_other_sessions(ctx).await,
        Endpoint::Ok => Ok(Reply::Json(json!({"ok": true}))),
        Endpoint::Error => core_routes::error_page(ctx),
        Endpoint::EmailOtp(route) => email_otp::run(ctx, route).await,
        Endpoint::Organization(route) => organization::run(ctx, route).await,
        Endpoint::ApiKey(route) => api_key::run(ctx, route).await,
        Endpoint::Admin(route) => admin::run(ctx, route).await,
        Endpoint::Mcp(route) => mcp::run(ctx, route).await,
    }
}

/// `runAfterHooks` in registration order: the app's own after hook (auth.ts),
/// admin (list-sessions filter, applied in its endpoint), mcp (resume a pending
/// authorization once a session cookie is set), dash (identification cookie on
/// non-GET requests), email-otp (sign-up only, inert while sign-ups are disabled).
async fn after_hooks(ctx: &mut Ctx<'_>, endpoint: Endpoint, result: EndpointResult) -> EndpointResult {
    let result = organization::app_after_hook(ctx, endpoint, result).await;
    let result = mcp::login_prompt_after_hook(ctx, result).await;
    dash::identification_after_hook(ctx);
    result
}

/// better-call `toResponse` for what the dispatch produced, plus the accumulated
/// response headers.
fn to_response(result: EndpointResult, headers: ResponseHeaders) -> Response {
    let (status, mut extra, body, content_type) = match result {
        Ok(Reply::Json(value)) => (StatusCode::OK, Vec::new(), Some(crate::js_json::stringify(&value)), Some("application/json")),
        Ok(Reply::Raw { status, headers: raw_headers, body }) => (status, raw_headers, body, None),
        Err(err) => {
            let body = err.body.as_ref().map(crate::js_json::stringify);
            if err.status == StatusCode::INTERNAL_SERVER_ERROR && err.body.is_none() && err.headers.is_empty() {
                // A thrown non-APIError: nothing but the status
                let mut response = Response::new(Body::empty());
                *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                return response;
            }
            (err.status, err.headers, body, Some("application/json"))
        }
    };
    let mut response = Response::new(body.map(Body::from).unwrap_or_else(Body::empty));
    *response.status_mut() = status;
    let response_headers = response.headers_mut();
    if let Some(content_type) = content_type {
        response_headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    }
    // The error's own headers (location), then the accumulated ones replace them
    for (name, value) in extra.drain(..) {
        insert_header(response_headers, &name, &value, false);
    }
    for (name, value) in headers.other {
        insert_header(response_headers, &name, &value, false);
    }
    for cookie in headers.cookies {
        insert_header(response_headers, "set-cookie", &cookie, true);
    }
    response
}

fn insert_header(headers: &mut HeaderMap, name: &str, value: &str, append: bool) {
    let (Ok(name), Ok(value)) = (header::HeaderName::from_bytes(name.as_bytes()), HeaderValue::from_str(value)) else {
        warn!(header = name, "Dropped a response header that is not valid HTTP");
        return;
    };
    if append {
        headers.append(name, value);
    } else {
        headers.insert(name, value);
    }
}

// ---------------------------------------------------------------------------
// sessions shared by every endpoint

/// What the core `/get-session` logic decided about the request's cookie.
pub struct SessionLookup {
    pub session: Option<SessionWithUser>,
}

/// The heart of `GET /get-session` (better-auth/dist/api/routes/session.mjs). With
/// `emit_cookies` false it is `getSessionFromCtx`'s inner call, whose cookies the
/// dispatch later discards: the database effects (expired row deleted, expiry slid
/// forward once a day) happen either way.
pub async fn resolve_session(ctx: &mut Ctx<'_>, emit_cookies: bool, disable_refresh: bool) -> Result<SessionLookup, ApiError> {
    let production = ctx.production();
    let (token_name, _) = cookies::session_token_cookie(production);
    let token = match ctx.signed_cookie(&token_name) {
        Some(Some(token)) if !token.is_empty() => token,
        _ => return Ok(SessionLookup { session: None }),
    };

    match core_routes::inspect_session_data_cookie(ctx) {
        Err(()) => {
            warn!("Undecodable session cache cookie failed the session lookup");
            return Err(ApiError::code(StatusCode::INTERNAL_SERVER_ERROR, "FAILED_TO_GET_SESSION", "Failed to get session"));
        }
        Ok(false) if emit_cookies => core_routes::check_session_data_cookie(ctx),
        Ok(_) => {}
    }
    let (dont_remember_name, _) = cookies::dont_remember_cookie(production);
    let dont_remember = ctx.verified_cookie(&dont_remember_name).is_some();

    let found = db::find_session(&ctx.state.pg, &token).await.map_err(|err| {
        error!(error = %err, "Session lookup failed");
        ApiError::code(StatusCode::INTERNAL_SERVER_ERROR, "FAILED_TO_GET_SESSION", "Failed to get session")
    })?;
    let expired = found.as_ref().is_none_or(|found| db::is_past(found.session.expires_at));
    if expired {
        if emit_cookies {
            ctx.delete_session_cookie(false);
        }
        if let Some(found) = &found {
            db::delete_session(&ctx.state.pg, &found.session.token).await.map_err(|err| {
                error!(error = %err, "Expired session delete failed");
                ApiError::code(StatusCode::INTERNAL_SERVER_ERROR, "FAILED_TO_GET_SESSION", "Failed to get session")
            })?;
            info!(user_id = %found.session.user_id, "Expired session deleted");
        }
        return Ok(SessionLookup { session: None });
    }
    let found = found.expect("present when not expired");
    if dont_remember || disable_refresh {
        return Ok(SessionLookup { session: Some(found) });
    }

    let due = db::epoch_ms(db::ms(found.session.expires_at)) - SESSION_EXPIRES_IN * 1000 + SESSION_UPDATE_AGE * 1000
        <= chrono::Utc::now().timestamp_millis();
    if !due {
        return Ok(SessionLookup { session: Some(found) });
    }
    let updated = db::update_session(&ctx.state.pg, &token, db::SessionField::ExpiresAt(db::in_seconds(SESSION_EXPIRES_IN)))
        .await
        .map_err(|err| {
            error!(error = %err, "Session refresh failed");
            ApiError::code(StatusCode::INTERNAL_SERVER_ERROR, "FAILED_TO_GET_SESSION", "Failed to get session")
        })?;
    let Some(updated) = updated else {
        if emit_cookies {
            ctx.delete_session_cookie(false);
        }
        return Err(ApiError::code(StatusCode::UNAUTHORIZED, "FAILED_TO_GET_SESSION", "Failed to get session"));
    };
    debug!(user_id = %updated.user_id, "Session expiry refreshed");
    let refreshed = SessionWithUser { session: updated, user: found.user };
    if emit_cookies {
        ctx.set_session_cookie(&refreshed, Some(false), Some(SESSION_EXPIRES_IN));
    }
    Ok(SessionLookup { session: Some(refreshed) })
}

/// `getSessionFromCtx(ctx, { disableRefresh? })`: memoised per request, errors
/// swallowed, the outer request's `?disableRefresh` honoured.
pub async fn session_from_ctx(ctx: &mut Ctx<'_>) -> Option<SessionWithUser> {
    if let SessionSlot::Resolved(slot) = &ctx.session
        && let Some(session) = slot.as_ref()
    {
        return Some(session.clone());
    }
    let disable_refresh = context::truthy(ctx.query.get("disableRefresh"));
    let session = resolve_session(ctx, false, disable_refresh).await.ok().and_then(|lookup| lookup.session);
    ctx.session = SessionSlot::Resolved(Box::new(session.clone()));
    session
}

/// `sessionMiddleware` (and `sensitiveSessionMiddleware`, identical without a
/// cookie cache): 401 `{"message":"Unauthorized","code":"UNAUTHORIZED"}`
pub async fn require_session(ctx: &mut Ctx<'_>) -> Result<SessionWithUser, ApiError> {
    session_from_ctx(ctx)
        .await
        .ok_or_else(|| ApiError::code(StatusCode::UNAUTHORIZED, "UNAUTHORIZED", "Unauthorized"))
}

/// `getAuthoritativeSessionFromCtx`: a fresh read of the store
pub async fn authoritative_session(ctx: &mut Ctx<'_>) -> Option<SessionWithUser> {
    ctx.session = SessionSlot::Unresolved;
    session_from_ctx(ctx).await
}

/// Serves the full stack (this router behind the HTTP edge layers, plus every route
/// already on main) for the differential suite in parity/auth-endpoints/. Blocks
/// until killed: `PORT=3031 cargo test parity_server -- --ignored --nocapture`.
#[cfg(test)]
mod parity {
    use std::{net::SocketAddr, sync::Arc};

    use axum::{Json, extract::State, http::HeaderMap, middleware, routing::get};
    use serde_json::{Value, json};

    use crate::{
        auth::bearer::{extract_bearer_token, resolve_bearer_identity},
        http::{cors, errors, logging},
        state::AppState,
    };

    /// Test-only probe for the cross-compat suite: what the Rust bearer gate
    /// (`resolveBearerIdentity`) makes of an `Authorization: Bearer` credential.
    async fn parity_bearer(State(state): State<AppState>, headers: HeaderMap) -> Json<Value> {
        let authorization = headers.get("authorization").and_then(|value| value.to_str().ok());
        let Some(token) = extract_bearer_token(authorization) else { return Json(json!({"status": "Missing"})) };
        let identity = resolve_bearer_identity(&state.pg, token).await;
        Json(json!({
            "status": format!("{:?}", identity.status),
            "userId": identity.user_id,
            "organizationId": identity.organization_id,
            "restricted": identity.statements.is_some(),
        }))
    }

    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "long-running server for parity/auth-endpoints/run.sh"]
    async fn parity_server() {
        tracing_subscriber::fmt().json().with_env_filter(std::env::var("LOG_LEVEL").unwrap_or_else(|_| "info".into())).try_init().ok();
        let config = crate::config::Config::from_env().unwrap();
        let port = config.port;
        let state = crate::state::AppState::connect(config).await.unwrap();
        let cors_policy = Arc::new(cors::CorsPolicy::new(state.config.base_url.as_deref(), state.config.production));
        let auth = super::router()
            .merge(super::mcp::well_known_router())
            .with_state(state.clone())
            .layer(middleware::from_fn_with_state(cors_policy, cors::cors))
            .layer(middleware::from_fn(errors::api_error_responses))
            .layer(middleware::from_fn(logging::request_log));
        let probe = axum::Router::new().route("/__parity/bearer", get(parity_bearer)).with_state(state.clone());
        let app = auth.merge(probe).merge(crate::routes::router(state));
        let listener = tokio::net::TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], port))).await.unwrap();
        axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await.unwrap();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn media_types_parse_like_fastify() {
        assert_eq!(fastify_media_type("application/json; charset=utf-8").as_deref(), Some("application/json"));
        assert_eq!(fastify_media_type("Application/JSON").as_deref(), Some("application/json"));
        assert_eq!(fastify_media_type("nonsense"), None);
        assert_eq!(fastify_media_type("text/plain").as_deref(), Some("text/plain"));
    }

    #[test]
    fn query_strings_fold_repeated_keys() {
        let query = parse_query(Some("a=1&b=2&a=3&c=%20x+y"));
        assert_eq!(query["a"], json!(["1", "3"]));
        assert_eq!(query["c"], json!(" x y"));
    }

    #[test]
    fn every_route_is_unique() {
        for (index, route) in ROUTES.iter().enumerate() {
            for other in &ROUTES[index + 1..] {
                assert!(!(route.path == other.path && route.methods.iter().any(|m| other.methods.contains(m))), "{}", route.path);
            }
        }
    }
}
