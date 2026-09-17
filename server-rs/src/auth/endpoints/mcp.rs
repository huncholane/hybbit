//! The MCP OAuth provider (better-auth/dist/plugins/mcp and the oidc-provider consent
//! endpoint it reuses) as auth.ts configures it: login page `/login`, resource
//! `${BASE_URL}/api/mcp`, the app's `resource:action` scopes, S256 PKCE only.
//! Also the root `/.well-known` documents re-served by server/src/mcp/wellKnown.ts.

use axum::{
    Router,
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::get,
};
use serde_json::{Map, Value, json};
use sqlx::Row;
use tracing::{error, info, warn};

use crate::{
    auth::scopes::{OIDC_STANDARD_SCOPES, SCOPE_MATRIX},
    state::AppState,
};

use super::{
    context::{ApiError, Ctx, EndpointResult, Reply, SessionSlot, truthy},
    cookies::{self, CookieAttributes},
    crypto,
    db::{self, SessionWithUser, iso, opt_str},
    require_session, session_from_ctx,
    validate::{self, Ty, optional, required},
};

const CODE_EXPIRES_IN: i64 = 600;
const ACCESS_TOKEN_EXPIRES_IN: i64 = 3600;
const REFRESH_TOKEN_EXPIRES_IN: i64 = 604_800;
const LOGIN_PAGE: &str = "/login";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Route {
    AuthorizationServer,
    ProtectedResource,
    Authorize,
    Token,
    Register,
    GetSession,
    Consent,
}

pub async fn run(ctx: &mut Ctx<'_>, route: Route) -> EndpointResult {
    match route {
        Route::AuthorizationServer => Ok(Reply::Json(authorization_server_metadata(&ctx.state.config).map_or(Value::Null, Value::Object))),
        Route::ProtectedResource => protected_resource_metadata(&ctx.state.config)
            .map(|metadata| Reply::Json(Value::Object(metadata)))
            .ok_or_else(ApiError::internal),
        Route::Authorize => {
            let query = ctx.query.clone();
            let session = session_from_ctx(ctx).await;
            Err(authorize(ctx, &query, session).await)
        }
        Route::Token => token(ctx).await,
        Route::Register => register(ctx).await,
        Route::GetSession => get_session(ctx).await,
        Route::Consent => consent(ctx).await,
    }
}

/// `[...OIDC_STANDARD_SCOPES, ...ALL_SCOPE_STRINGS]`
pub fn scopes_supported() -> Vec<String> {
    let mut scopes: Vec<String> = OIDC_STANDARD_SCOPES.iter().map(|scope| scope.to_string()).collect();
    for (resource, actions) in SCOPE_MATRIX {
        for action in *actions {
            scopes.push(format!("{resource}:{action}"));
        }
    }
    scopes
}

/// `getMCPProviderMetadata`: None when no base URL is configured (the endpoint then
/// answers `null`)
pub fn authorization_server_metadata(config: &crate::config::Config) -> Option<Map<String, Value>> {
    let issuer = super::base_origin(config)?;
    let base = super::base_url(config)?;
    let value = json!({
        "issuer": issuer,
        "authorization_endpoint": format!("{base}/mcp/authorize"),
        "token_endpoint": format!("{base}/mcp/token"),
        "userinfo_endpoint": format!("{base}/mcp/userinfo"),
        "jwks_uri": format!("{base}/mcp/jwks"),
        "registration_endpoint": format!("{base}/mcp/register"),
        "scopes_supported": ["openid", "profile", "email", "offline_access"],
        "response_types_supported": ["code"],
        "response_modes_supported": ["query"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "acr_values_supported": ["urn:mace:incommon:iap:silver", "urn:mace:incommon:iap:bronze"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "none"],
        "code_challenge_methods_supported": ["S256"],
        "claims_supported": ["sub", "iss", "aud", "exp", "nbf", "iat", "jti", "email", "email_verified", "name"],
    });
    value.as_object().cloned()
}

/// `getMCPProtectedResourceMetadata` with auth.ts's resource and scope list
pub fn protected_resource_metadata(config: &crate::config::Config) -> Option<Map<String, Value>> {
    let base = super::base_url(config)?;
    let origin = super::origin::url_origin(&base)?;
    let resource = match config.base_url.as_deref() {
        Some(base_url) => format!("{}/api/mcp", base_url.strip_suffix('/').unwrap_or(base_url)),
        None => origin.clone(),
    };
    let value = json!({
        "resource": resource,
        "authorization_servers": [origin],
        "jwks_uri": format!("{base}/mcp/jwks"),
        "scopes_supported": scopes_supported(),
        "bearer_methods_supported": ["header"],
        "resource_signing_alg_values_supported": ["RS256"],
    });
    value.as_object().cloned()
}

/// `withScopesSupported` from server/src/mcp/wellKnown.ts
fn with_scopes_supported(mut metadata: Map<String, Value>) -> Map<String, Value> {
    metadata.insert("scopes_supported".into(), json!(scopes_supported()));
    metadata
}

fn well_known_response(metadata: Option<Map<String, Value>>) -> Response {
    match metadata {
        Some(metadata) => {
            let mut response = crate::http::json(StatusCode::OK, &Value::Object(with_scopes_supported(metadata)));
            response.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("public, max-age=3600"));
            response
        }
        None => crate::http::json(StatusCode::NOT_FOUND, &json!({"error": "OAuth discovery metadata is not available"})),
    }
}

/// The root discovery documents from server/src/mcp/wellKnown.ts, for the lead to
/// mount at the domain root (they are outside /api/auth).
pub fn well_known_router() -> Router<AppState> {
    async fn authorization_server(axum::extract::State(state): axum::extract::State<AppState>) -> Response {
        well_known_response(authorization_server_metadata(&state.config))
    }
    async fn protected_resource(axum::extract::State(state): axum::extract::State<AppState>) -> Response {
        match protected_resource_metadata(&state.config) {
            Some(metadata) => well_known_response(Some(metadata)),
            None => {
                error!("Failed to build OAuth discovery metadata");
                crate::http::json(StatusCode::INTERNAL_SERVER_ERROR, &json!({"error": "Failed to build OAuth discovery metadata"})).into_response()
            }
        }
    }
    Router::new()
        .route("/.well-known/oauth-authorization-server", get(authorization_server))
        .route("/.well-known/oauth-authorization-server/api/mcp", get(authorization_server))
        .route("/.well-known/openid-configuration", get(authorization_server))
        .route("/.well-known/openid-configuration/api/mcp", get(authorization_server))
        .route("/.well-known/oauth-protected-resource", get(protected_resource))
        .route("/.well-known/oauth-protected-resource/api/mcp", get(protected_resource))
}

/// The four CORS headers `authorizeMCPOAuth` and `/mcp/register` set
fn set_open_cors(ctx: &mut Ctx<'_>) {
    ctx.response.set("Access-Control-Allow-Origin", "*");
    ctx.response.set("Access-Control-Allow-Methods", "POST, OPTIONS");
    ctx.response.set("Access-Control-Allow-Headers", "Content-Type, Authorization");
    ctx.response.set("Access-Control-Max-Age", "86400");
}

fn redirect_error_url(url: &str, error: &str, description: &str) -> String {
    let separator = if url.contains('?') { '&' } else { '?' };
    format!("{url}{separator}error={error}&error_description={description}")
}

/// `new URL(uri)` with `searchParams.set("code")` and `set("state")`
fn with_code(uri: &str, code: &str, state: Option<&str>) -> Option<String> {
    let mut url = url::Url::parse(uri).ok()?;
    let mut pairs: Vec<(String, String)> = url.query_pairs().map(|(k, v)| (k.into_owned(), v.into_owned())).collect();
    let set = |pairs: &mut Vec<(String, String)>, key: &str, value: &str| match pairs.iter().position(|(k, _)| k == key) {
        Some(index) => {
            pairs[index].1 = value.to_string();
            let mut seen = false;
            pairs.retain(|(k, _)| {
                if k != key {
                    return true;
                }
                let keep = !seen;
                seen = true;
                keep
            });
        }
        None => pairs.push((key.to_string(), value.to_string())),
    };
    set(&mut pairs, "code", code);
    if let Some(state) = state.filter(|s| !s.is_empty()) {
        set(&mut pairs, "state", state);
    }
    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    for (key, value) in &pairs {
        serializer.append_pair(key, value);
    }
    url.set_query(Some(&serializer.finish()));
    Some(url.to_string())
}

/// `authorizeMCPOAuth`: always ends in an APIError (a redirect or a 400)
async fn authorize(ctx: &mut Ctx<'_>, query: &Map<String, Value>, session: Option<SessionWithUser>) -> ApiError {
    set_open_cors(ctx);
    let Some(session) = session else {
        let (production, value) = (ctx.production(), crate::js_json::stringify(&Value::Object(query.clone())));
        let _ = production;
        ctx.set_signed_cookie(
            "oidc_login_prompt",
            &value,
            &CookieAttributes { max_age: Some(600), path: Some("/"), http_only: false, secure: false, same_site: Some("lax") },
        );
        let raw = ctx.raw_query.clone();
        info!("MCP authorization waits for a login");
        return ApiError::redirect(&format!("{LOGIN_PAGE}?{}", raw.unwrap_or_else(|| "undefined".to_string())));
    };
    let base = super::base_url(&ctx.state.config).unwrap_or_default();
    let text = |key: &str| query.get(key).filter(|v| truthy(Some(v))).and_then(Value::as_str).map(str::to_string);
    let Some(client_id) = query.get("client_id").filter(|v| truthy(Some(v))) else {
        return ApiError::redirect(&format!("{base}/error?error=invalid_client"));
    };
    if !truthy(query.get("response_type")) {
        return ApiError::redirect(&redirect_error_url(&format!("{base}/error"), "invalid_request", "response_type is required"));
    }
    let client_id = match client_id {
        Value::String(id) => id.clone(),
        other => crate::js_json::stringify(other),
    };
    let client = match sqlx::query(r#"SELECT "clientId", "redirectUrls", disabled, metadata FROM "oauthApplication" WHERE "clientId" = $1"#)
        .bind(&client_id)
        .fetch_optional(&ctx.state.pg)
        .await
    {
        Ok(row) => row,
        Err(err) => return err.into(),
    };
    let Some(client) = client else { return ApiError::redirect(&format!("{base}/error?error=invalid_client")) };
    let redirect_urls: String = client.try_get("redirectUrls").unwrap_or_default();
    let disabled: Option<bool> = client.try_get("disabled").unwrap_or(None);
    let metadata: Option<String> = client.try_get("metadata").unwrap_or(None);
    if let Some(metadata) = metadata.filter(|m| !m.is_empty())
        && serde_json::from_str::<Value>(&metadata).is_err()
    {
        return ApiError::internal();
    }
    let requested_redirect = query.get("redirect_uri").and_then(Value::as_str);
    let Some(redirect_uri) = redirect_urls.split(',').find(|url| Some(*url) == requested_redirect).map(str::to_string) else {
        warn!(client_id = %client_id, "MCP authorize with an unregistered redirect_uri");
        return ApiError::message(StatusCode::BAD_REQUEST, "Invalid redirect URI");
    };
    if disabled == Some(true) {
        return ApiError::redirect(&format!("{base}/error?error=client_disabled"));
    }
    if text("response_type").as_deref() != Some("code") {
        return ApiError::redirect(&format!("{base}/error?error=unsupported_response_type"));
    }
    let custom_scopes = scopes_supported();
    let requested_scopes: Vec<String> = match text("scope") {
        Some(scope) => scope.split(' ').filter(|s| !s.is_empty()).map(str::to_string).collect(),
        None => vec!["openid".to_string()],
    };
    let invalid: Vec<&String> = requested_scopes.iter().filter(|scope| !custom_scopes.contains(scope)).collect();
    if !invalid.is_empty() {
        let list: Vec<&str> = invalid.iter().map(|s| s.as_str()).collect();
        return ApiError::redirect(&redirect_error_url(&redirect_uri, "invalid_scope", &format!("The following scopes are invalid: {}", list.join(", "))));
    }
    let challenge = text("code_challenge");
    let mut method = text("code_challenge_method");
    if method.is_some() && challenge.is_none() {
        return ApiError::redirect(&redirect_error_url(&redirect_uri, "invalid_request", "code_challenge_method requires code_challenge"));
    }
    if challenge.is_some() {
        let lowered = method.as_deref().map(str::to_lowercase);
        if lowered.as_deref() != Some("s256") {
            return ApiError::redirect(&redirect_error_url(&redirect_uri, "invalid_request", "invalid code_challenge method"));
        }
        method = lowered;
    }
    let code = crypto::random_string(32, &[crypto::LOWER, crypto::UPPER, crypto::DIGITS]);
    let prompt_consent = query.get("prompt").and_then(Value::as_str) == Some("consent");
    let mut value = Map::new();
    value.insert("clientId".into(), Value::from(client_id.clone()));
    value.insert("redirectURI".into(), query.get("redirect_uri").cloned().unwrap_or(Value::Null));
    value.insert("scope".into(), json!(requested_scopes));
    value.insert("userId".into(), Value::from(session.user.id.clone()));
    value.insert("authTime".into(), Value::from(db::epoch_ms(db::ms(session.session.created_at))));
    value.insert("requireConsent".into(), Value::Bool(prompt_consent));
    value.insert("state".into(), if prompt_consent { query.get("state").cloned().unwrap_or(Value::Null) } else { Value::Null });
    if let Some(challenge) = query.get("code_challenge") {
        value.insert("codeChallenge".into(), challenge.clone());
    }
    if let Some(method) = &method {
        value.insert("codeChallengeMethod".into(), Value::from(method.clone()));
    } else if let Some(raw) = query.get("code_challenge_method") {
        value.insert("codeChallengeMethod".into(), raw.clone());
    }
    if let Some(nonce) = query.get("nonce") {
        value.insert("nonce".into(), nonce.clone());
    }
    if let Err(err) = db::create_verification(&ctx.state.pg, &code, &crate::js_json::stringify(&Value::Object(value)), db::in_seconds(CODE_EXPIRES_IN)).await {
        error!(error = %err, "Authorization code could not be stored");
        return ApiError::redirect(&redirect_error_url(&redirect_uri, "server_error", "An error occurred while processing the request"));
    }
    let state = query.get("state").filter(|v| truthy(Some(v))).and_then(Value::as_str);
    let Some(location) = with_code(&redirect_uri, &code, state) else { return ApiError::internal() };
    info!(client_id = %client_id, user_id = %session.user.id, "MCP authorization code issued");
    ApiError::redirect(&location)
}

/// Better Auth's `mcp` after hook: once any response sets the session cookie while
/// an `oidc_login_prompt` is pending, the authorization resumes from the stored query.
pub async fn login_prompt_after_hook(ctx: &mut Ctx<'_>, result: EndpointResult) -> EndpointResult {
    let Some(cookie) = ctx.verified_cookie("oidc_login_prompt") else { return result };
    let (session_cookie, _) = cookies::session_token_cookie(ctx.production());
    // parseSetCookieHeader: the last cookie of a name wins, values URI-decoded
    let mut token_value: Option<String> = None;
    for set_cookie in &ctx.response.cookies {
        let name_value = set_cookie.split(';').next().unwrap_or_default().trim();
        let (name, value) = name_value.split_once('=').unwrap_or((name_value, ""));
        if name == session_cookie {
            let value = value.strip_prefix('"').and_then(|v| v.strip_suffix('"')).unwrap_or(value);
            token_value = Some(percent_encoding::percent_decode_str(value).decode_utf8().map(|v| v.into_owned()).unwrap_or_else(|_| value.to_string()));
        }
    }
    let Some(token_value) = token_value else { return result };
    ctx.expire_cookie("oidc_login_prompt", &CookieAttributes { path: Some("/"), ..Default::default() });
    let token = token_value.split('.').next().unwrap_or_default().to_string();
    if token.is_empty() {
        return result;
    }
    let session = match db::find_session(&ctx.state.pg, &token).await {
        Ok(Some(found)) => Some(found),
        Ok(None) => ctx.new_session.clone(),
        Err(err) => return Err(err.into()),
    };
    let Some(session) = session else { return result };
    let Ok(Value::Object(mut query)) = serde_json::from_str::<Value>(&cookie) else { return result };
    let prompt = query.get("prompt").map(|p| match p {
        Value::String(text) => text.clone(),
        Value::Null => "null".to_string(),
        other => crate::js_json::stringify(other),
    });
    let prompts: Vec<&str> = prompt.as_deref().unwrap_or("undefined").split(' ').map(str::trim).collect();
    let known: Vec<&str> = {
        let mut set: Vec<&str> = Vec::new();
        for p in prompts {
            if ["login", "consent", "select_account", "none"].contains(&p) && !set.contains(&p) {
                set.push(p);
            }
        }
        set
    };
    if known.contains(&"none") && known.len() > 1 {
        // parsePrompt throws InvalidRequest, an APIError: the cookies already set
        // (the new session, the expired prompt) stay on the 400
        warn!("MCP login prompt resumed with prompt none combined with others");
        let description = "prompt none must only be used alone";
        let mut body = Map::new();
        body.insert("message".into(), Value::from(description));
        body.insert("error".into(), Value::from("invalid_request"));
        body.insert("error_description".into(), Value::from(description));
        return Err(ApiError::body(StatusCode::BAD_REQUEST, Value::Object(body)));
    }
    if known.contains(&"login") {
        let remaining: Vec<&str> = known.iter().copied().filter(|p| *p != "login").collect();
        query.insert("prompt".into(), Value::from(remaining.join(" ")));
    }
    ctx.session = SessionSlot::Resolved(Box::new(Some(session.clone())));
    info!(user_id = %session.user.id, "Resuming MCP authorization after login");
    Err(authorize(ctx, &query, Some(session)).await)
}

/// A body value's `toString()`
fn value_string(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        Value::Array(items) => items.iter().map(|item| if item.is_null() { String::new() } else { value_string(item) }).collect::<Vec<_>>().join(","),
        Value::Object(_) => "[object Object]".to_string(),
        other => crate::js_json::stringify(other),
    }
}

struct Client {
    client_secret: Option<String>,
    kind: String,
    disabled: Option<bool>,
}

async fn find_client(ctx: &Ctx<'_>, client_id: &str) -> Result<Option<Client>, ApiError> {
    let row = sqlx::query(r#"SELECT "clientSecret", type, disabled, metadata FROM "oauthApplication" WHERE "clientId" = $1"#)
        .bind(client_id)
        .fetch_optional(&ctx.state.pg)
        .await?;
    let Some(row) = row else { return Ok(None) };
    let metadata: Option<String> = row.try_get("metadata")?;
    if let Some(metadata) = metadata.filter(|m| !m.is_empty())
        && serde_json::from_str::<Value>(&metadata).is_err()
    {
        return Err(ApiError::internal());
    }
    Ok(Some(Client { client_secret: row.try_get("clientSecret")?, kind: row.try_get("type")?, disabled: row.try_get("disabled")? }))
}

fn oauth(status: StatusCode, error: &str, description: &str) -> ApiError {
    ApiError::oauth(status, error, description)
}

/// `POST /mcp/token`: authorization_code (PKCE, client secret for confidential
/// clients) and refresh_token grants
async fn token(ctx: &mut Ctx<'_>) -> EndpointResult {
    validate::record(ctx.body.as_ref(), "body")?;
    let body = ctx.body_object().cloned().unwrap_or_default();
    let field = |key: &str| body.get(key).filter(|v| truthy(Some(v))).map(value_string);
    let mut client_id = field("client_id");
    let mut client_secret = field("client_secret");
    if let Some(authorization) = ctx.header("authorization").map(str::to_string)
        && client_secret.is_none()
        && authorization.starts_with("Basic ")
    {
        let invalid = || oauth(StatusCode::UNAUTHORIZED, "invalid_client", "invalid authorization header format");
        let encoded = authorization.replacen("Basic ", "", 1);
        let decoded = basic_decode(&encoded).ok_or_else(invalid)?;
        let Some(colon) = decoded.find(':') else { return Err(invalid()) };
        let decode = |part: &str| percent_encoding::percent_decode_str(part).decode_utf8().map(|v| v.into_owned()).ok();
        let (Some(id), Some(secret)) = (decode(&decoded[..colon]), decode(&decoded[colon + 1..])) else { return Err(invalid()) };
        if id.is_empty() || secret.is_empty() {
            return Err(invalid());
        }
        if client_id.as_deref().is_some_and(|existing| existing != id) {
            return Err(oauth(StatusCode::UNAUTHORIZED, "invalid_client", "client_id in body does not match Authorization header"));
        }
        client_id = Some(id);
        client_secret = Some(secret);
    }
    let grant_type = field("grant_type");
    let pg = &ctx.state.pg;

    if grant_type.as_deref() == Some("refresh_token") {
        let Some(refresh_token) = field("refresh_token") else {
            return Err(oauth(StatusCode::BAD_REQUEST, "invalid_request", "refresh_token is required"));
        };
        let row = sqlx::query(
            r#"SELECT "clientId", "userId", "refreshTokenExpiresAt", scopes FROM "oauthAccessToken" WHERE "refreshToken" = $1"#,
        )
        .bind(&refresh_token)
        .fetch_optional(pg)
        .await?;
        let Some(row) = row else { return Err(oauth(StatusCode::UNAUTHORIZED, "invalid_grant", "invalid refresh token")) };
        let token_client: String = row.try_get("clientId")?;
        let user_id: Option<String> = row.try_get("userId")?;
        let refresh_expires: Option<chrono::NaiveDateTime> = row.try_get("refreshTokenExpiresAt")?;
        let scopes: String = row.try_get("scopes")?;
        if Some(token_client.as_str()) != client_id.as_deref() {
            return Err(oauth(StatusCode::UNAUTHORIZED, "invalid_client", "invalid client_id"));
        }
        if refresh_expires.is_some_and(db::is_past) {
            return Err(oauth(StatusCode::UNAUTHORIZED, "invalid_grant", "refresh token expired"));
        }
        if !scopes.split(' ').any(|scope| scope == "offline_access") {
            return Err(oauth(StatusCode::UNAUTHORIZED, "invalid_grant", "refresh token was not issued for the offline_access scope"));
        }
        let client_id = client_id.unwrap_or_default();
        let Some(client) = find_client(ctx, &client_id).await? else {
            return Err(oauth(StatusCode::UNAUTHORIZED, "invalid_client", "invalid client_id"));
        };
        if client.disabled == Some(true) {
            return Err(oauth(StatusCode::UNAUTHORIZED, "invalid_client", "client is disabled"));
        }
        if client.kind != "public" {
            let (Some(stored), Some(given)) = (client.client_secret.filter(|s| !s.is_empty()), client_secret) else {
                return Err(oauth(StatusCode::UNAUTHORIZED, "invalid_client", "client_secret is required for confidential clients"));
            };
            if !crypto::constant_time_eq(&stored, &given) {
                return Err(oauth(StatusCode::UNAUTHORIZED, "invalid_client", "invalid client_secret"));
            }
        }
        let access_token = crypto::random_string(32, &[crypto::LOWER, crypto::UPPER]);
        let new_refresh = crypto::random_string(32, &[crypto::LOWER, crypto::UPPER]);
        insert_access_token(ctx, &access_token, &new_refresh, &client_id, user_id.as_deref(), &scopes).await?;
        info!(client_id = %client_id, "MCP access token refreshed");
        return Ok(Reply::Json(json!({
            "access_token": access_token,
            "token_type": "bearer",
            "expires_in": ACCESS_TOKEN_EXPIRES_IN,
            "refresh_token": new_refresh,
            "scope": scopes,
        })));
    }

    let Some(code) = field("code") else {
        return Err(oauth(StatusCode::BAD_REQUEST, "invalid_request", "code is required"));
    };
    let Some(verification) = db::consume_verification(pg, &code).await? else {
        return Err(oauth(StatusCode::UNAUTHORIZED, "invalid_grant", "invalid code"));
    };
    let Some(client_id) = client_id else { return Err(oauth(StatusCode::UNAUTHORIZED, "invalid_client", "client_id is required")) };
    let Some(grant_type) = grant_type else { return Err(oauth(StatusCode::BAD_REQUEST, "invalid_request", "grant_type is required")) };
    if grant_type != "authorization_code" {
        return Err(oauth(StatusCode::BAD_REQUEST, "unsupported_grant_type", "grant_type must be 'authorization_code'"));
    }
    let Some(redirect_uri) = field("redirect_uri") else {
        return Err(oauth(StatusCode::BAD_REQUEST, "invalid_request", "redirect_uri is required"));
    };
    let Some(client) = find_client(ctx, &client_id).await? else {
        return Err(oauth(StatusCode::UNAUTHORIZED, "invalid_client", "invalid client_id"));
    };
    if client.disabled == Some(true) {
        return Err(oauth(StatusCode::UNAUTHORIZED, "invalid_client", "client is disabled"));
    }
    let code_verifier = field("code_verifier");
    if client.kind == "public" {
        if code_verifier.is_none() {
            return Err(oauth(StatusCode::BAD_REQUEST, "invalid_request", "code verifier is required for public clients"));
        }
    } else {
        let (Some(stored), Some(given)) = (client.client_secret.clone().filter(|s| !s.is_empty()), client_secret.clone()) else {
            return Err(oauth(StatusCode::UNAUTHORIZED, "invalid_client", "client_secret is required for confidential clients"));
        };
        if !crypto::constant_time_eq(&stored, &given) {
            return Err(oauth(StatusCode::UNAUTHORIZED, "invalid_client", "invalid client_secret"));
        }
    }
    let Ok(Value::Object(value)) = serde_json::from_str::<Value>(&verification.value) else { return Err(ApiError::internal()) };
    if value.get("clientId").and_then(Value::as_str) != Some(client_id.as_str()) {
        return Err(oauth(StatusCode::UNAUTHORIZED, "invalid_client", "invalid client_id"));
    }
    if value.get("redirectURI").and_then(Value::as_str) != Some(redirect_uri.as_str()) {
        return Err(oauth(StatusCode::UNAUTHORIZED, "invalid_client", "invalid redirect_uri"));
    }
    if let Some(challenge) = value.get("codeChallenge").filter(|v| truthy(Some(v))).and_then(Value::as_str) {
        let Some(verifier) = &code_verifier else {
            return Err(oauth(StatusCode::BAD_REQUEST, "invalid_request", "code verifier is missing"));
        };
        let computed = if value.get("codeChallengeMethod").and_then(Value::as_str) == Some("plain") {
            verifier.clone()
        } else {
            crypto::sha256_base64url(verifier)
        };
        if computed != challenge {
            warn!(client_id = %client_id, "PKCE verification failed");
            return Err(oauth(StatusCode::UNAUTHORIZED, "invalid_request", "code verification failed"));
        }
    }
    let scopes: Vec<String> = value.get("scope").and_then(Value::as_array).map(|s| s.iter().map(value_string).collect()).unwrap_or_default();
    let user_id = value.get("userId").and_then(Value::as_str).map(str::to_string);
    let access_token = crypto::random_string(32, &[crypto::LOWER, crypto::UPPER]);
    let refresh_token = crypto::random_string(32, &[crypto::UPPER, crypto::LOWER]);
    insert_access_token(ctx, &access_token, &refresh_token, &client_id, user_id.as_deref(), &scopes.join(" ")).await?;
    let Some(user) = (match &user_id {
        Some(id) => db::find_user_by_id(pg, id).await?,
        None => None,
    }) else {
        return Err(oauth(StatusCode::UNAUTHORIZED, "invalid_grant", "user not found"));
    };

    let mut response = Map::new();
    response.insert("access_token".into(), Value::from(access_token));
    response.insert("token_type".into(), Value::from("Bearer"));
    response.insert("expires_in".into(), Value::from(ACCESS_TOKEN_EXPIRES_IN));
    if scopes.iter().any(|s| s == "offline_access") {
        response.insert("refresh_token".into(), Value::from(refresh_token));
    }
    response.insert("scope".into(), Value::from(scopes.join(" ")));
    if scopes.iter().any(|s| s == "openid") {
        response.insert("id_token".into(), Value::from(id_token(&user, &client_id, &scopes, value.get("nonce"))));
    }
    info!(client_id = %client_id, user_id = %user.id, "MCP access token issued");
    Ok(Reply::Json(Value::Object(response)))
}

/// The id_token Better Auth signs with a throwaway HMAC key (nobody can verify it)
fn id_token(user: &db::User, client_id: &str, scopes: &[String], nonce: Option<&Value>) -> String {
    let mut claims = Map::new();
    claims.insert("sub".into(), Value::from(user.id.clone()));
    claims.insert("aud".into(), Value::from(client_id));
    claims.insert("iat".into(), Value::from(chrono::Utc::now().timestamp()));
    if let Some(nonce) = nonce {
        claims.insert("nonce".into(), nonce.clone());
    }
    claims.insert("acr".into(), Value::from("urn:mace:incommon:iap:silver"));
    if scopes.iter().any(|s| s == "profile") {
        let mut parts = user.name.split(' ');
        claims.insert("given_name".into(), Value::from(parts.next().unwrap_or_default()));
        if let Some(family) = parts.next() {
            claims.insert("family_name".into(), Value::from(family));
        }
        claims.insert("name".into(), Value::from(user.name.clone()));
        claims.insert("profile".into(), opt_str(user.image.clone()));
        claims.insert("updated_at".into(), Value::from(db::epoch_ms(db::ms(user.updated_at)) / 1000));
    }
    if scopes.iter().any(|s| s == "email") {
        claims.insert("email".into(), Value::from(user.email.clone()));
        claims.insert("email_verified".into(), Value::from(user.email_verified));
    }
    claims.insert("exp".into(), Value::from(chrono::Utc::now().timestamp() + ACCESS_TOKEN_EXPIRES_IN));
    let mut key = [0u8; 32];
    rand::Rng::fill_bytes(&mut rand::rng(), &mut key);
    crypto::sign_hs256(&claims, &key)
}

/// @better-auth/utils `base64.decode` then UTF-8, as the Basic header parser does
fn basic_decode(encoded: &str) -> Option<String> {
    let url_safe = encoded.contains('-') || encoded.contains('_');
    let alphabet: &[u8] = if url_safe {
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    } else {
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    };
    let mut out = Vec::new();
    let (mut buffer, mut bits) = (0u32, 0);
    for character in encoded.chars() {
        if character == '=' {
            break;
        }
        let value = u8::try_from(character).ok().and_then(|b| alphabet.iter().position(|a| *a == b))?;
        buffer = (buffer << 6) | value as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((buffer >> bits) & 0xff) as u8);
        }
    }
    Some(String::from_utf8_lossy(&out).into_owned())
}

async fn insert_access_token(
    ctx: &Ctx<'_>,
    access_token: &str,
    refresh_token: &str,
    client_id: &str,
    user_id: Option<&str>,
    scopes: &str,
) -> Result<(), ApiError> {
    let now = db::now_ms();
    sqlx::query(
        r#"INSERT INTO "oauthAccessToken" (id, "accessToken", "refreshToken", "accessTokenExpiresAt", "refreshTokenExpiresAt", "clientId", "userId", scopes, "createdAt", "updatedAt")
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)"#,
    )
    .bind(crypto::generate_id())
    .bind(access_token)
    .bind(refresh_token)
    .bind(db::in_seconds(ACCESS_TOKEN_EXPIRES_IN))
    .bind(db::in_seconds(REFRESH_TOKEN_EXPIRES_IN))
    .bind(client_id)
    .bind(user_id)
    .bind(scopes)
    .bind(now)
    .bind(now)
    .execute(&ctx.state.pg)
    .await?;
    Ok(())
}

const GRANT_TYPES: &[&str] = &[
    "authorization_code",
    "implicit",
    "password",
    "client_credentials",
    "refresh_token",
    "urn:ietf:params:oauth:grant-type:jwt-bearer",
    "urn:ietf:params:oauth:grant-type:saml2-bearer",
];

/// `POST /mcp/register`: dynamic client registration (RFC 7591)
async fn register(ctx: &mut Ctx<'_>) -> EndpointResult {
    validate::object(
        ctx.body.as_ref(),
        &[
            required("redirect_uris", Ty::ArrayOfStrings),
            optional("token_endpoint_auth_method", Ty::Enum(&["none", "client_secret_basic", "client_secret_post"])),
            optional("client_name", Ty::String),
            optional("client_uri", Ty::String),
            optional("logo_uri", Ty::String),
            optional("scope", Ty::String),
            optional("contacts", Ty::ArrayOfStrings),
            optional("tos_uri", Ty::String),
            optional("policy_uri", Ty::String),
            optional("jwks_uri", Ty::String),
            optional("jwks", Ty::Record),
            optional("metadata", Ty::Record),
            optional("software_id", Ty::String),
            optional("software_version", Ty::String),
            optional("software_statement", Ty::String),
        ],
        "body",
        false,
    )?;
    let body = ctx.body_object().cloned().unwrap_or_default();
    for (key, allowed) in [("grant_types", GRANT_TYPES), ("response_types", &["code", "token"][..])] {
        match body.get(key) {
            None => {}
            Some(Value::Array(items)) => {
                if let Some(index) = items.iter().position(|item| !item.as_str().is_some_and(|s| allowed.contains(&s))) {
                    let listed: Vec<String> = allowed.iter().map(|a| format!("\"{a}\"")).collect();
                    return Err(ApiError::code(
                        StatusCode::BAD_REQUEST,
                        "VALIDATION_ERROR",
                        &format!("[body.{key}.{index}] Invalid option: expected one of {}", listed.join("|")),
                    ));
                }
            }
            Some(other) => {
                return Err(ApiError::code(
                    StatusCode::BAD_REQUEST,
                    "VALIDATION_ERROR",
                    &format!("[body.{key}] Invalid input: expected array, received {}", validate::type_name(Some(other))),
                ));
            }
        }
    }
    if let Some(Value::Array(uris)) = body.get("redirect_uris")
        && let Some(index) = uris.iter().position(|uri| uri.as_str().is_some_and(|uri| !is_safe_url_scheme(uri)))
    {
        return Err(ApiError::code(
            StatusCode::BAD_REQUEST,
            "VALIDATION_ERROR",
            &format!("[body.redirect_uris.{index}] redirect_uri cannot use a javascript:, data:, or vbscript: scheme"),
        ));
    }
    let session = session_from_ctx(ctx).await;
    set_open_cors(ctx);
    let grant_types = body.get("grant_types").cloned().unwrap_or_else(|| json!(["authorization_code"]));
    let response_types = body.get("response_types").cloned().unwrap_or_else(|| json!(["code"]));
    let redirect_uris: Vec<String> =
        body.get("redirect_uris").and_then(Value::as_array).map(|u| u.iter().filter_map(Value::as_str).map(str::to_string).collect()).unwrap_or_default();
    let includes = |list: &Value, item: &str| list.as_array().is_some_and(|items| items.iter().any(|v| v == item));
    if (includes(&grant_types, "authorization_code") || includes(&grant_types, "implicit")) && redirect_uris.is_empty() {
        return Err(ApiError::body(
            StatusCode::BAD_REQUEST,
            json!({"error": "invalid_redirect_uri", "error_description": "Redirect URIs are required for authorization_code and implicit grant types"}),
        ));
    }
    if includes(&grant_types, "authorization_code") && !includes(&response_types, "code") {
        return Err(ApiError::body(
            StatusCode::BAD_REQUEST,
            json!({"error": "invalid_client_metadata", "error_description": "When 'authorization_code' grant type is used, 'code' response type must be included"}),
        ));
    }
    if includes(&grant_types, "implicit") && !includes(&response_types, "token") {
        return Err(ApiError::body(
            StatusCode::BAD_REQUEST,
            json!({"error": "invalid_client_metadata", "error_description": "When 'implicit' grant type is used, 'token' response type must be included"}),
        ));
    }
    let client_id = crypto::random_string(32, &[crypto::LOWER, crypto::UPPER]);
    let client_secret = crypto::random_string(32, &[crypto::LOWER, crypto::UPPER]);
    let auth_method = body.get("token_endpoint_auth_method").and_then(Value::as_str).unwrap_or("client_secret_basic").to_string();
    let public = auth_method == "none";
    let final_secret = if public { String::new() } else { client_secret };
    let now = db::now_ms();
    let metadata = body.get("metadata").filter(|m| truthy(Some(m))).map(crate::js_json::stringify);
    let insert = sqlx::query(
        r#"INSERT INTO "oauthApplication" (id, name, icon, metadata, "clientId", "clientSecret", "redirectUrls", type, disabled, "userId", "createdAt", "updatedAt")
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, false, $9, $10, $11)"#,
    )
    .bind(crypto::generate_id())
    .bind(body.get("client_name").and_then(Value::as_str))
    .bind(body.get("logo_uri").and_then(Value::as_str))
    .bind(metadata)
    .bind(&client_id)
    .bind(&final_secret)
    .bind(redirect_uris.join(","))
    .bind(if public { "public" } else { "web" })
    .bind(session.as_ref().map(|s| s.session.user_id.clone()))
    .bind(now)
    .bind(now)
    .execute(&ctx.state.pg)
    .await;
    if let Err(err) = insert {
        error!(error = %err, "OAuth client registration failed");
        return Err(ApiError::internal());
    }
    let mut response = Map::new();
    response.insert("client_id".into(), Value::from(client_id.clone()));
    response.insert("client_id_issued_at".into(), Value::from(chrono::Utc::now().timestamp()));
    response.insert("redirect_uris".into(), body.get("redirect_uris").cloned().unwrap_or(Value::Null));
    response.insert("token_endpoint_auth_method".into(), Value::from(auth_method));
    response.insert("grant_types".into(), grant_types);
    response.insert("response_types".into(), response_types);
    for key in [
        "client_name",
        "client_uri",
        "logo_uri",
        "scope",
        "contacts",
        "tos_uri",
        "policy_uri",
        "jwks_uri",
        "jwks",
        "software_id",
        "software_version",
        "software_statement",
        "metadata",
    ] {
        if let Some(value) = body.get(key) {
            response.insert(key.into(), value.clone());
        }
    }
    if !public {
        response.insert("client_secret".into(), Value::from(final_secret));
        response.insert("client_secret_expires_at".into(), Value::from(0));
    }
    info!(client_id = %client_id, public, "OAuth client registered");
    Ok(Reply::Raw {
        status: StatusCode::CREATED,
        headers: vec![
            ("content-type".into(), "application/json".into()),
            ("cache-control".into(), "no-store".into()),
            ("pragma".into(), "no-cache".into()),
        ],
        body: Some(crate::js_json::stringify(&Value::Object(response))),
    })
}

/// @better-auth/core `isSafeUrlScheme`
fn is_safe_url_scheme(value: &str) -> bool {
    match url::Url::parse(value) {
        Ok(url) => !matches!(url.scheme(), "javascript" | "data" | "vbscript"),
        Err(_) => true,
    }
}

/// `GET /mcp/get-session`: the access token row behind `Authorization: Bearer`
async fn get_session(ctx: &mut Ctx<'_>) -> EndpointResult {
    let Some(authorization) = ctx.header("authorization") else { return Ok(Reply::Json(Value::Null)) };
    let token = authorization.replacen("Bearer ", "", 1);
    if token.is_empty() {
        return Ok(Reply::Json(Value::Null));
    }
    let row = sqlx::query(
        r#"SELECT id, "accessToken", "refreshToken", "accessTokenExpiresAt", "refreshTokenExpiresAt", "clientId", "userId", scopes, "createdAt", "updatedAt"
           FROM "oauthAccessToken" WHERE "accessToken" = $1"#,
    )
    .bind(&token)
    .fetch_optional(&ctx.state.pg)
    .await?;
    let Some(row) = row else { return Ok(Reply::Json(Value::Null)) };
    let expires: chrono::NaiveDateTime = row.try_get("accessTokenExpiresAt")?;
    if db::is_past(expires) {
        return Ok(Reply::Json(Value::Null));
    }
    let refresh_expires: Option<chrono::NaiveDateTime> = row.try_get("refreshTokenExpiresAt")?;
    let mut map = Map::new();
    map.insert("accessToken".into(), Value::from(row.try_get::<String, _>("accessToken")?));
    map.insert("refreshToken".into(), opt_str(row.try_get("refreshToken")?));
    map.insert("accessTokenExpiresAt".into(), Value::from(iso(expires)));
    map.insert("refreshTokenExpiresAt".into(), db::iso_opt(refresh_expires));
    map.insert("clientId".into(), Value::from(row.try_get::<String, _>("clientId")?));
    map.insert("userId".into(), opt_str(row.try_get("userId")?));
    map.insert("scopes".into(), Value::from(row.try_get::<String, _>("scopes")?));
    map.insert("createdAt".into(), Value::from(iso(row.try_get("createdAt")?)));
    map.insert("updatedAt".into(), Value::from(iso(row.try_get("updatedAt")?)));
    map.insert("id".into(), Value::from(row.try_get::<String, _>("id")?));
    Ok(Reply::Json(Value::Object(map)))
}

/// `POST /oauth2/consent`
async fn consent(ctx: &mut Ctx<'_>) -> EndpointResult {
    validate::object(
        ctx.body.as_ref(),
        &[required("accept", Ty::Boolean), validate::nullish("consent_code", Ty::String)],
        "body",
        false,
    )?;
    require_session(ctx).await?;
    let pg = &ctx.state.pg;
    let consent_code = ctx
        .body_str("consent_code")
        .filter(|code| !code.is_empty())
        .map(str::to_string)
        .or_else(|| ctx.verified_cookie("oidc_consent_prompt"));
    let Some(consent_code) = consent_code else {
        return Err(oauth(StatusCode::UNAUTHORIZED, "invalid_request", "consent_code is required (either in body or cookie)"));
    };
    let Some(verification) = db::find_verification(pg, &consent_code).await? else {
        return Err(oauth(StatusCode::UNAUTHORIZED, "invalid_request", "Invalid code"));
    };
    if db::is_past(verification.expires_at) {
        return Err(oauth(StatusCode::UNAUTHORIZED, "invalid_request", "Code expired"));
    }
    ctx.expire_cookie("oidc_consent_prompt", &CookieAttributes { path: Some("/"), ..Default::default() });
    let Ok(Value::Object(mut value)) = serde_json::from_str::<Value>(&verification.value) else { return Err(ApiError::internal()) };
    if !truthy(value.get("requireConsent")) {
        return Err(oauth(StatusCode::UNAUTHORIZED, "invalid_request", "Consent not required"));
    }
    let redirect = value.get("redirectURI").map(value_string).unwrap_or_else(|| "undefined".to_string());
    if ctx.body_object().and_then(|b| b.get("accept")) != Some(&Value::Bool(true)) {
        db::delete_verification(pg, &consent_code).await?;
        info!("MCP consent denied");
        return Ok(Reply::Json(json!({"redirectURI": format!("{redirect}?error=access_denied&error_description=User denied access")})));
    }
    let code = crypto::random_string(32, &[crypto::LOWER, crypto::UPPER, crypto::DIGITS]);
    value.insert("requireConsent".into(), Value::Bool(false));
    sqlx::query(r#"UPDATE verification SET value = $1, identifier = $2, "expiresAt" = $3, "updatedAt" = $4 WHERE identifier = $5"#)
        .bind(crate::js_json::stringify(&Value::Object(value.clone())))
        .bind(&code)
        .bind(db::in_seconds(CODE_EXPIRES_IN))
        .bind(db::now_ms())
        .bind(&consent_code)
        .execute(pg)
        .await?;
    let scopes: Vec<String> = value.get("scope").and_then(Value::as_array).map(|s| s.iter().map(value_string).collect()).unwrap_or_default();
    let now = db::now_ms();
    sqlx::query(
        r#"INSERT INTO "oauthConsent" (id, "clientId", "userId", scopes, "consentGiven", "createdAt", "updatedAt") VALUES ($1, $2, $3, $4, true, $5, $6)"#,
    )
    .bind(crypto::generate_id())
    .bind(value.get("clientId").map(value_string))
    .bind(value.get("userId").map(value_string))
    .bind(scopes.join(" "))
    .bind(now)
    .bind(now)
    .execute(pg)
    .await?;
    let state = value.get("state").filter(|v| truthy(Some(v))).and_then(Value::as_str);
    let Some(location) = with_code(&redirect, &code, state) else { return Err(ApiError::internal()) };
    info!("MCP consent given");
    Ok(Reply::Json(json!({"redirectURI": location})))
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn read(response: Response) -> (u16, Option<String>, Value) {
        let status = response.status().as_u16();
        let cache = response.headers().get(header::CACHE_CONTROL).and_then(|v| v.to_str().ok()).map(str::to_string);
        let bytes = axum::body::to_bytes(response.into_body(), 1 << 20).await.unwrap();
        (status, cache, serde_json::from_slice(&bytes).unwrap())
    }

    /// server/src/mcp/wellKnown.test.ts: metadata served with a max-age and the full
    /// scope list injected; 404 with a fixed body when unavailable.
    #[tokio::test]
    async fn well_known_documents() {
        let mut metadata = Map::new();
        metadata.insert("issuer".into(), json!("https://hygo.example.com"));
        metadata.insert("scopes_supported".into(), json!(["openid"]));
        let (status, cache, body) = read(well_known_response(Some(metadata))).await;
        assert_eq!(status, 200);
        assert_eq!(cache.as_deref(), Some("public, max-age=3600"));
        assert_eq!(body["issuer"], json!("https://hygo.example.com"));
        assert_eq!(body["scopes_supported"], json!(scopes_supported()));

        let (status, cache, body) = read(well_known_response(None)).await;
        assert_eq!(status, 404);
        assert_eq!(cache, None);
        assert_eq!(body, json!({"error": "OAuth discovery metadata is not available"}));
    }

    #[test]
    fn scopes_list_matches_well_known() {
        let scopes = scopes_supported();
        assert_eq!(&scopes[..5], &["openid", "profile", "email", "offline_access", "analytics:read"]);
        assert!(scopes.contains(&"ingest:write".to_string()));
    }

    #[test]
    fn codes_are_added_like_url_search_params() {
        assert_eq!(with_code("http://localhost:3000/cb", "abc", Some("xyz")).unwrap(), "http://localhost:3000/cb?code=abc&state=xyz");
        assert_eq!(with_code("https://x.test/cb?a=1&code=old", "new", None).unwrap(), "https://x.test/cb?a=1&code=new");
        assert!(with_code("not a url", "c", None).is_none());
    }

    #[test]
    fn basic_header_decoding() {
        assert_eq!(basic_decode("Y2xpZW50OnNlY3JldA==").as_deref(), Some("client:secret"));
        assert_eq!(basic_decode("!!"), None);
    }
}
