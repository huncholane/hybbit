//! Better Auth's own routes: sessions, email and password, social sign-in without
//! client ids, account changes (better-auth/dist/api/routes/*.mjs), with the
//! callbacks server/src/lib/auth.ts configures.

use axum::http::StatusCode;
use base64::Engine;
use serde_json::{Map, Value, json};
use tracing::{error, info, warn};

use crate::email;

use super::{
    SESSION_FRESH_AGE, authoritative_session,
    context::{ApiError, Ctx, EndpointResult, Reply, truthy},
    cookies, crypto,
    db::{self, NewSession, SessionWithUser, UserField},
    origin, require_session, resolve_session, session_from_ctx,
    validate::{self, Ty, optional, required},
};

const MIN_PASSWORD_LENGTH: usize = 8;
const MAX_PASSWORD_LENGTH: usize = 128;

fn bad_request(code: &str, message: &str) -> ApiError {
    ApiError::code(StatusCode::BAD_REQUEST, code, message)
}

/// `password.length` in UTF-16 units
fn js_length(text: &str) -> usize {
    text.encode_utf16().count()
}

pub fn new_session_options(ctx: &Ctx<'_>) -> NewSession {
    NewSession { ip_address: ctx.ip.clone().unwrap_or_default(), user_agent: ctx.user_agent(), ..Default::default() }
}

/// `GET /get-session` (POST is refused without `deferSessionRefresh`)
pub async fn get_session_endpoint(ctx: &mut Ctx<'_>) -> EndpointResult {
    ctx.response.set("cache-control", "no-store");
    ctx.response.set("pragma", "no-cache");
    if ctx.method == axum::http::Method::POST {
        return Err(ApiError::code(
            StatusCode::METHOD_NOT_ALLOWED,
            "METHOD_NOT_ALLOWED_DEFER_SESSION_REQUIRED",
            "POST method requires deferSessionRefresh to be enabled in session config",
        ));
    }
    let disable_refresh = truthy(ctx.query.get("disableRefresh"));
    let lookup = resolve_session(ctx, true, disable_refresh).await?;
    ctx.session = super::context::SessionSlot::Resolved(Box::new(lookup.session.clone()));
    Ok(Reply::Json(lookup.session.map_or(Value::Null, |session| session.to_json())))
}

/// @better-auth/utils `base64Url.decode`: the URL-safe alphabet when the text has
/// `-` or `_`, stop at `=`, throw on any other character, drop leftover bits.
fn lenient_base64_decode(text: &str) -> Result<Vec<u8>, ()> {
    let url_safe = text.contains('-') || text.contains('_');
    let alphabet: &[u8] = if url_safe {
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    } else {
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    };
    let mut out = Vec::new();
    let mut buffer: u32 = 0;
    let mut bits = 0;
    for character in text.chars() {
        if character == '=' {
            break;
        }
        let value = u8::try_from(character).ok().and_then(|byte| alphabet.iter().position(|a| *a == byte)).ok_or(())?;
        buffer = (buffer << 6) | value as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((buffer >> bits) & 0xff) as u8);
        }
    }
    Ok(out)
}

/// The cookie-cache half of `/get-session`: this app never sets `session_data`, but
/// a leftover one is still decoded. Returns Err when decoding throws (the whole
/// lookup fails), Ok(false) when it parsed but its signature is wrong.
pub fn inspect_session_data_cookie(ctx: &Ctx<'_>) -> Result<bool, ()> {
    let (name, _) = cookies::session_data_cookie(ctx.production());
    let value = ctx.cookie(&name).filter(|value| !value.is_empty()).map(str::to_string).or_else(|| {
        let mut chunks: Vec<(i64, String)> = ctx
            .cookies
            .iter()
            .filter_map(|(cookie, value)| {
                let rest = cookie.strip_prefix(&format!("{name}."))?;
                rest.parse::<i64>().ok().map(|index| (index, value.clone()))
            })
            .collect();
        chunks.sort_by_key(|(index, _)| *index);
        (!chunks.is_empty()).then(|| chunks.into_iter().map(|(_, value)| value).collect())
    });
    let Some(value) = value else { return Ok(true) };
    let bytes = lenient_base64_decode(&value)?;
    let Ok(Value::Object(parsed)) = serde_json::from_str::<Value>(&String::from_utf8_lossy(&bytes)) else { return Ok(true) };
    let mut signed = parsed.get("session").and_then(Value::as_object).cloned().unwrap_or_default();
    match parsed.get("expiresAt") {
        Some(expires) => {
            signed.insert("expiresAt".into(), expires.clone());
        }
        None => {
            signed.remove("expiresAt");
        }
    }
    let payload = crate::js_json::stringify(&Value::Object(signed));
    // `base64.decode(undefined)` decodes "" (a failed verification); other non-strings throw
    let signature = match parsed.get("signature") {
        None => "",
        Some(Value::String(signature)) => signature.as_str(),
        Some(_) => return Err(()),
    };
    let expected = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode({
        use hmac::{KeyInit, Mac};
        let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(ctx.secret().as_bytes()).expect("any key length");
        mac.update(payload.as_bytes());
        mac.finalize().into_bytes()
    });
    Ok(lenient_base64_decode(signature)? == lenient_base64_decode(&expected)?)
}

/// Expire a `session_data` cookie whose signature did not verify
pub fn check_session_data_cookie(ctx: &mut Ctx<'_>) {
    let (name, attributes) = cookies::session_data_cookie(ctx.production());
    if matches!(inspect_session_data_cookie(ctx), Ok(false)) {
        warn!("Session cache cookie with an invalid signature expired");
        ctx.expire_cookie(&name, &attributes);
    }
}

/// `POST /sign-out`
pub async fn sign_out(ctx: &mut Ctx<'_>) -> EndpointResult {
    let (name, _) = cookies::session_token_cookie(ctx.production());
    if let Some(Some(token)) = ctx.signed_cookie(&name)
        && !token.is_empty()
    {
        match db::delete_session(&ctx.state.pg, &token).await {
            Ok(()) => info!("Signed out"),
            Err(err) => error!(error = %err, "Failed to delete session from database"),
        }
    }
    ctx.delete_session_cookie(false);
    Ok(Reply::Json(json!({"success": true})))
}

const SIGN_IN_FIELDS: &[validate::Field] = &[
    required("email", Ty::String),
    required("password", Ty::String),
    optional("callbackURL", Ty::String),
    optional("rememberMe", Ty::Boolean),
];

/// `POST /sign-in/email`: every miss still hashes the password so response times
/// don't reveal which part was wrong.
pub async fn sign_in_email(ctx: &mut Ctx<'_>) -> EndpointResult {
    validate::object(ctx.body.as_ref(), SIGN_IN_FIELDS, "body", false)?;
    origin::form_csrf_middleware(ctx)?;
    let email = ctx.body_str("email").unwrap_or_default().to_string();
    let password = ctx.body_str("password").unwrap_or_default().to_string();
    let remember_me_false = ctx.body_object().and_then(|body| body.get("rememberMe")) == Some(&Value::Bool(false));
    let callback_url = ctx.body_str("callbackURL").map(str::to_string);

    if !validate::is_email(&email) {
        return Err(bad_request("INVALID_EMAIL", "Invalid email"));
    }
    let invalid = || ApiError::code(StatusCode::UNAUTHORIZED, "INVALID_EMAIL_OR_PASSWORD", "Invalid email or password");
    let Some(user) = db::find_user_by_email(&ctx.state.pg, &email).await? else {
        crypto::hash_password(&password).await;
        info!("Sign-in for an unknown email");
        return Err(invalid());
    };
    let accounts = db::find_accounts(&ctx.state.pg, &user.id).await?;
    let Some(credential) = accounts.iter().find(|account| account.provider_id == "credential") else {
        crypto::hash_password(&password).await;
        info!(user_id = %user.id, "Sign-in without a credential account");
        return Err(invalid());
    };
    let Some(stored) = credential.password.clone().filter(|stored| !stored.is_empty()) else {
        crypto::hash_password(&password).await;
        info!(user_id = %user.id, "Sign-in for an account without a password");
        return Err(invalid());
    };
    match crypto::verify_password(&stored, &password).await {
        Ok(true) => {}
        Ok(false) => {
            info!(user_id = %user.id, "Sign-in with a wrong password");
            return Err(invalid());
        }
        Err(_) => {
            error!(user_id = %user.id, "Stored password hash is malformed");
            return Err(ApiError::internal());
        }
    }

    let mut options = new_session_options(ctx);
    options.dont_remember = remember_me_false;
    let session = db::create_session(&ctx.state.pg, &user.id, options).await?;
    let pair = SessionWithUser { session, user };
    ctx.set_session_cookie(&pair, Some(remember_me_false), None);
    if let Some(callback) = &callback_url
        && !callback.is_empty()
    {
        ctx.response.set("location", callback);
    }
    info!(user_id = %pair.user.id, "Signed in with email and password");
    let mut body = Map::new();
    body.insert("redirect".into(), Value::Bool(callback_url.as_deref().is_some_and(|cb| !cb.is_empty())));
    body.insert("token".into(), Value::from(pair.session.token.clone()));
    if let Some(callback) = callback_url {
        body.insert("url".into(), Value::from(callback));
    }
    body.insert("user".into(), pair.user.to_json());
    Ok(Reply::Json(Value::Object(body)))
}

const SOCIAL_FIELDS: &[validate::Field] = &[
    optional("callbackURL", Ty::String),
    optional("newUserCallbackURL", Ty::String),
    optional("errorCallbackURL", Ty::String),
    required("provider", Ty::UnionString),
    optional("disableRedirect", Ty::Boolean),
    optional("scopes", Ty::ArrayOfStrings),
    optional("requestSignUp", Ty::Boolean),
    optional("loginHint", Ty::String),
    optional("additionalData", Ty::Record),
];

/// `POST /sign-in/social` for the two providers auth.ts configures. Production has
/// no client ids: GitHub still builds an authorize URL with `client_id=undefined`,
/// Google throws after the state row was written (500, no body).
pub async fn sign_in_social(ctx: &mut Ctx<'_>) -> EndpointResult {
    validate::object(ctx.body.as_ref(), SOCIAL_FIELDS, "body", false)?;
    if let Some(Value::Object(id_token)) = ctx.body_object().and_then(|body| body.get("idToken")).cloned() {
        validate::object(Some(&Value::Object(id_token)), &[required("token", Ty::String)], "body.idToken", false)?;
    } else if let Some(other) = ctx.body_object().and_then(|body| body.get("idToken"))
        && !other.is_null()
    {
        return Err(ApiError::code(
            StatusCode::BAD_REQUEST,
            "VALIDATION_ERROR",
            &format!("[body.idToken] Invalid input: expected object, received {}", validate::type_name(Some(other))),
        ));
    }
    let body = ctx.body_object().cloned().unwrap_or_default();
    let provider = body.get("provider").and_then(Value::as_str).unwrap_or_default().to_string();
    if provider != "google" && provider != "github" {
        error!(provider = %provider, "Provider not found");
        return Err(ApiError::code(StatusCode::NOT_FOUND, "PROVIDER_NOT_FOUND", "Provider not found"));
    }
    if truthy(body.get("idToken")) {
        if provider == "github" {
            return Err(ApiError::code(StatusCode::NOT_FOUND, "ID_TOKEN_NOT_SUPPORTED", "id_token not supported"));
        }
        // Google ID tokens need Google's keys and an audience; none is configured
        warn!("Google ID token sign-in refused: not supported without a client id");
        return Err(ApiError::code(StatusCode::UNAUTHORIZED, "INVALID_TOKEN", "Invalid token"));
    }

    // generateState: the state row and signed cookie come first
    let callback_url = body
        .get("callbackURL")
        .and_then(Value::as_str)
        .filter(|cb| !cb.is_empty())
        .map(str::to_string)
        .or_else(|| super::base_origin(&ctx.state.config));
    let Some(callback_url) = callback_url else {
        return Err(bad_request("CALLBACK_URL_REQUIRED", "callbackURL is required"));
    };
    let code_verifier = crypto::generate_random_string_default(128);
    let state = crypto::generate_random_string_default(32);
    let mut state_data = match body.get("additionalData") {
        Some(Value::Object(extra)) => extra.clone(),
        _ => Map::new(),
    };
    state_data.insert("callbackURL".into(), Value::from(callback_url));
    state_data.insert("codeVerifier".into(), Value::from(code_verifier.clone()));
    for (key, source) in [("errorURL", "errorCallbackURL"), ("newUserURL", "newUserCallbackURL")] {
        match body.get(source) {
            Some(value) => {
                state_data.insert(key.into(), value.clone());
            }
            None => {
                state_data.remove(key);
            }
        }
    }
    state_data.remove("link");
    state_data.insert("expiresAt".into(), Value::from(chrono::Utc::now().timestamp_millis() + 600_000));
    match body.get("requestSignUp") {
        Some(value) => {
            state_data.insert("requestSignUp".into(), value.clone());
        }
        None => {
            state_data.remove("requestSignUp");
        }
    }
    state_data.insert("oauthState".into(), Value::from(state.clone()));

    let (state_cookie, attributes) = cookies::auth_cookie(ctx.production(), "state");
    ctx.set_signed_cookie(&state_cookie, &state, &attributes.with_max_age(Some(300)));
    db::create_verification(&ctx.state.pg, &state, &crate::js_json::stringify(&Value::Object(state_data)), db::in_seconds(600)).await?;

    let base = super::base_url(&ctx.state.config).unwrap_or_default();
    let redirect_uri = format!("{base}/callback/{provider}");
    let challenge = crypto::sha256_base64url(&code_verifier);
    let (client_id, endpoint, mut scopes) = if provider == "google" {
        if ctx.state.config.auth.google_client_id.is_none() || ctx.state.config.auth.google_client_secret.is_none() {
            error!("Client Id and Client Secret is required for Google. Make sure to provide them in the options.");
            return Err(ApiError::internal());
        }
        (
            ctx.state.config.auth.google_client_id.clone().unwrap_or_default(),
            "https://accounts.google.com/o/oauth2/v2/auth",
            vec!["email".to_string(), "profile".to_string(), "openid".to_string()],
        )
    } else {
        (
            ctx.state.config.auth.github_client_id.clone().unwrap_or_else(|| "undefined".to_string()),
            "https://github.com/login/oauth/authorize",
            vec!["read:user".to_string(), "user:email".to_string()],
        )
    };
    if let Some(Value::Array(extra)) = body.get("scopes") {
        scopes.extend(extra.iter().filter_map(Value::as_str).map(str::to_string));
    }
    let mut params = url::form_urlencoded::Serializer::new(String::new());
    params.append_pair("response_type", "code");
    params.append_pair("client_id", &client_id);
    params.append_pair("state", &state);
    params.append_pair("scope", &scopes.join(" "));
    params.append_pair("redirect_uri", &redirect_uri);
    if let Some(hint) = body.get("loginHint").and_then(Value::as_str).filter(|hint| !hint.is_empty()) {
        params.append_pair("login_hint", hint);
    }
    if provider == "google" {
        params.append_pair("access_type", "offline");
    }
    params.append_pair("code_challenge_method", "S256");
    params.append_pair("code_challenge", &challenge);
    let url = format!("{endpoint}?{}", params.finish());

    let disable_redirect = truthy(body.get("disableRedirect"));
    if !disable_redirect {
        ctx.response.set("location", &url);
    }
    info!(provider = %provider, "Social sign-in redirect issued");
    Ok(Reply::Json(json!({"url": url, "redirect": !disable_redirect})))
}

const SIGN_UP_FIELDS: &[validate::Field] = &[
    required("name", Ty::String),
    required("email", Ty::Email),
    required("password", Ty::NonEmptyString),
    optional("image", Ty::String),
    optional("callbackURL", Ty::String),
    optional("rememberMe", Ty::Boolean),
];

/// Better Auth's `parseUserInput(options, data, action)` over the input fields
/// (`sendAutoEmailReports`, then the admin plugin's role/ban fields).
fn parse_user_input(data: &Map<String, Value>, create: bool) -> Result<Vec<UserField>, ApiError> {
    let mut fields = Vec::new();
    match data.get("sendAutoEmailReports") {
        Some(value) => fields.push(UserField::SendAutoEmailReports(pg_boolean(value)?)),
        None if create => fields.push(UserField::SendAutoEmailReports(Some(true))),
        None => {}
    }
    for key in ["role", "banned", "banReason", "banExpires"] {
        if let Some(value) = data.get(key) {
            if create && key == "banned" {
                fields.push(UserField::Banned(Some(false)));
                continue;
            }
            if truthy(Some(value)) {
                return Err(bad_request("FIELD_NOT_ALLOWED", &format!("{key} is not allowed to be set")));
            }
        } else if create && key == "banned" {
            fields.push(UserField::Banned(Some(false)));
        }
    }
    Ok(fields)
}

/// How node-postgres hands a JS value to a boolean column
fn pg_boolean(value: &Value) -> Result<Option<bool>, ApiError> {
    match value {
        Value::Null => Ok(None),
        Value::Bool(flag) => Ok(Some(*flag)),
        Value::Number(number) => {
            let n = number.as_f64();
            if n == Some(1.0) {
                Ok(Some(true))
            } else if n == Some(0.0) {
                Ok(Some(false))
            } else {
                Err(ApiError::internal())
            }
        }
        Value::String(text) => match text.trim().to_ascii_lowercase().as_str() {
            "t" | "true" | "y" | "yes" | "on" | "1" => Ok(Some(true)),
            "f" | "false" | "n" | "no" | "off" | "0" => Ok(Some(false)),
            _ => Err(ApiError::internal()),
        },
        _ => Err(ApiError::internal()),
    }
}

/// How node-postgres hands a JS value to a text column (objects are JSON)
fn pg_text(value: &Value) -> Option<String> {
    match value {
        Value::Null => None,
        Value::String(text) => Some(text.clone()),
        Value::Number(_) | Value::Bool(_) => Some(crate::js_json::stringify(value)),
        other => Some(crate::js_json::stringify(other)),
    }
}

/// `POST /sign-up/email`: refused while DISABLE_SIGNUP=true.
pub async fn sign_up_email(ctx: &mut Ctx<'_>) -> EndpointResult {
    validate::object(ctx.body.as_ref(), SIGN_UP_FIELDS, "body", false)?;
    origin::form_csrf_middleware(ctx)?;
    if ctx.state.config.disable_signup {
        info!("Sign-up refused: DISABLE_SIGNUP");
        return Err(bad_request("EMAIL_PASSWORD_SIGN_UP_DISABLED", "Email and password sign up is not enabled"));
    }
    let body = ctx.body_object().cloned().unwrap_or_default();
    let email = body.get("email").and_then(Value::as_str).unwrap_or_default().to_string();
    let password = body.get("password").and_then(Value::as_str).unwrap_or_default().to_string();
    if !validate::is_email(&email) {
        return Err(bad_request("INVALID_EMAIL", "Invalid email"));
    }
    if js_length(&password) < MIN_PASSWORD_LENGTH {
        return Err(bad_request("PASSWORD_TOO_SHORT", "Password too short"));
    }
    if js_length(&password) > MAX_PASSWORD_LENGTH {
        return Err(bad_request("PASSWORD_TOO_LONG", "Password too long"));
    }
    let mut rest = body.clone();
    for key in ["name", "email", "password", "image", "callbackURL", "rememberMe"] {
        rest.remove(key);
    }
    let additional = parse_user_input(&rest, true)?;
    if db::find_user_by_email(&ctx.state.pg, &email).await?.is_some() {
        info!("Sign-up attempt for an existing email");
        return Err(ApiError::code(
            StatusCode::UNPROCESSABLE_ENTITY,
            "USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL",
            "User already exists. Use another email.",
        ));
    }
    let hash = crypto::hash_password(&password).await;
    let name = body.get("name").and_then(Value::as_str).unwrap_or_default().to_string();
    let image = body.get("image").and_then(Value::as_str).map(str::to_string);
    let user = create_user(ctx, &email, &name, image, false, &additional).await?;
    db::create_credential_account(&ctx.state.pg, &user.id, &hash).await?;
    let remember_me_false = body.get("rememberMe") == Some(&Value::Bool(false));
    let mut options = new_session_options(ctx);
    options.dont_remember = remember_me_false;
    let session = db::create_session(&ctx.state.pg, &user.id, options).await?;
    let pair = SessionWithUser { session, user };
    ctx.set_session_cookie(&pair, Some(remember_me_false), None);
    info!(user_id = %pair.user.id, "Signed up with email and password");
    Ok(Reply::Json(json!({"token": pair.session.token, "user": pair.user.to_json()})))
}

/// `internalAdapter.createUser` with the admin plugin's default role and auth.ts's
/// `user.create.after` hook (the only user becomes admin; welcome mail and the
/// marketing contact only exist in the cloud).
pub async fn create_user(
    ctx: &Ctx<'_>,
    email: &str,
    name: &str,
    image: Option<String>,
    email_verified: bool,
    additional: &[UserField],
) -> Result<db::User, ApiError> {
    let now = db::now_ms();
    let id = crypto::generate_id();
    let send_reports = additional.iter().find_map(|field| match field {
        UserField::SendAutoEmailReports(value) => Some(*value),
        _ => None,
    });
    sqlx::query(
        r#"INSERT INTO "user" (id, name, email, "emailVerified", image, "createdAt", "updatedAt", role, banned, "sendAutoEmailReports")
           VALUES ($1, $2, $3, $4, $5, $6, $7, 'user', false, $8)"#,
    )
    .bind(&id)
    .bind(name)
    .bind(db::js_lowercase(email))
    .bind(email_verified)
    .bind(image)
    .bind(now)
    .bind(now)
    .bind(send_reports.unwrap_or(Some(true)))
    .execute(&ctx.state.pg)
    .await?;
    info!(user_id = %id, "User created");
    let count: i64 = sqlx::query_scalar(r#"SELECT count(*) FROM "user""#).fetch_one(&ctx.state.pg).await?;
    if count == 1 {
        sqlx::query(r#"UPDATE "user" SET role = 'admin' WHERE id = $1"#).bind(&id).execute(&ctx.state.pg).await?;
        info!(user_id = %id, "First user promoted to admin");
    }
    db::find_user_by_id(&ctx.state.pg, &id).await?.ok_or_else(ApiError::internal)
}

/// `POST /update-user`
pub async fn update_user(ctx: &mut Ctx<'_>) -> EndpointResult {
    validate::record(ctx.body.as_ref(), "body")?;
    let session = require_session(ctx).await?;
    let body = ctx.body_object().cloned().unwrap_or_default();
    if truthy(body.get("email")) {
        return Err(bad_request("EMAIL_CAN_NOT_BE_UPDATED", "Email can not be updated"));
    }
    let mut rest = body.clone();
    let name = rest.remove("name");
    let image = rest.remove("image");
    let additional = parse_user_input(&rest, false)?;
    if name.is_none() && image.is_none() && additional.is_empty() {
        return Err(ApiError::message(StatusCode::BAD_REQUEST, "No fields to update"));
    }
    let mut fields = Vec::new();
    if let Some(name) = &name {
        match pg_text(name) {
            Some(name) => fields.push(UserField::Name(name)),
            None => return Err(ApiError::internal()),
        }
    }
    if let Some(image) = &image {
        fields.push(UserField::Image(pg_text(image)));
    }
    fields.extend(additional);
    let updated = db::update_user(&ctx.state.pg, &session.user.id, fields).await.map_err(|err| {
        error!(error = %err, "User update failed");
        ApiError::internal()
    })?;
    let user = updated.unwrap_or_else(|| session.user.clone());
    info!(user_id = %user.id, "User updated");
    let pair = SessionWithUser { session: session.session.clone(), user };
    ctx.set_session_cookie(&pair, None, None);
    Ok(Reply::Json(json!({"status": true})))
}

const CHANGE_PASSWORD_FIELDS: &[validate::Field] = &[
    required("newPassword", Ty::String),
    required("currentPassword", Ty::String),
    optional("revokeOtherSessions", Ty::Boolean),
];

/// `POST /change-password`
pub async fn change_password(ctx: &mut Ctx<'_>) -> EndpointResult {
    validate::object(ctx.body.as_ref(), CHANGE_PASSWORD_FIELDS, "body", false)?;
    let session = require_session(ctx).await?;
    let new_password = ctx.body_str("newPassword").unwrap_or_default().to_string();
    let current_password = ctx.body_str("currentPassword").unwrap_or_default().to_string();
    let revoke = ctx.body_object().and_then(|body| body.get("revokeOtherSessions")) == Some(&Value::Bool(true));
    if js_length(&new_password) < MIN_PASSWORD_LENGTH {
        return Err(bad_request("PASSWORD_TOO_SHORT", "Password too short"));
    }
    if js_length(&new_password) > MAX_PASSWORD_LENGTH {
        return Err(bad_request("PASSWORD_TOO_LONG", "Password too long"));
    }
    let accounts = db::find_accounts(&ctx.state.pg, &session.user.id).await?;
    let Some(account) = accounts
        .into_iter()
        .find(|account| account.provider_id == "credential" && account.password.as_deref().is_some_and(|p| !p.is_empty()))
    else {
        return Err(bad_request("CREDENTIAL_ACCOUNT_NOT_FOUND", "Credential account not found"));
    };
    let hash = crypto::hash_password(&new_password).await;
    match crypto::verify_password(account.password.as_deref().unwrap_or_default(), &current_password).await {
        Ok(true) => {}
        Ok(false) => {
            info!(user_id = %session.user.id, "Password change with a wrong current password");
            return Err(bad_request("INVALID_PASSWORD", "Invalid password"));
        }
        Err(_) => return Err(ApiError::internal()),
    }
    db::update_account_password(&ctx.state.pg, &account.id, &hash).await?;
    info!(user_id = %session.user.id, "Password changed");
    let mut token = Value::Null;
    if revoke {
        db::delete_user_sessions(&ctx.state.pg, &session.user.id).await?;
        let new_session = db::create_session(&ctx.state.pg, &session.user.id, new_session_options(ctx))
            .await
            .map_err(|_| ApiError::code(StatusCode::INTERNAL_SERVER_ERROR, "FAILED_TO_GET_SESSION", "Failed to get session"))?;
        token = Value::from(new_session.token.clone());
        let pair = SessionWithUser { session: new_session, user: session.user.clone() };
        ctx.set_session_cookie(&pair, None, None);
        info!(user_id = %session.user.id, "Other sessions revoked after password change");
    }
    Ok(Reply::Json(json!({"token": token, "user": session.user.to_json()})))
}

/// `createEmailVerificationToken(secret, email, updateTo, 3600, extra)`
pub fn email_verification_token(secret: &str, email: &str, update_to: Option<&str>, request_type: Option<&str>) -> String {
    let mut payload = Map::new();
    payload.insert("email".into(), Value::from(db::js_lowercase(email)));
    if let Some(update_to) = update_to {
        payload.insert("updateTo".into(), Value::from(db::js_lowercase(update_to)));
    }
    if let Some(request_type) = request_type {
        payload.insert("requestType".into(), Value::from(request_type));
    }
    crypto::sign_jwt(payload, secret, 3600)
}

fn verification_url(ctx: &Ctx<'_>, token: &str, callback: Option<&str>) -> String {
    let base = super::base_url(&ctx.state.config).unwrap_or_default();
    let callback = callback.filter(|cb| !cb.is_empty()).unwrap_or("/");
    format!("{base}/verify-email?token={token}&callbackURL={}", cookies::encode_uri_component(callback))
}

/// auth.ts `emailVerification.sendVerificationEmail`, awaited like
/// `runInBackgroundOrAwait` without a background handler (errors logged)
async fn send_verification_email_to(ctx: &Ctx<'_>, email: &str, url: &str) {
    if let Err(err) = email::send_email_verification_link(&ctx.state.config, email, url).await {
        error!(error = %err, "Failed to run background task");
    }
}

const CHANGE_EMAIL_FIELDS: &[validate::Field] = &[required("newEmail", Ty::Email), optional("callbackURL", Ty::String)];

/// `POST /change-email`: verified users confirm from their current address first,
/// unverified users get the verification link at the new address.
pub async fn change_email(ctx: &mut Ctx<'_>) -> EndpointResult {
    validate::object(ctx.body.as_ref(), CHANGE_EMAIL_FIELDS, "body", false)?;
    let session = require_session(ctx).await?;
    let new_email = db::js_lowercase(ctx.body_str("newEmail").unwrap_or_default());
    let callback = ctx.body_str("callbackURL").map(str::to_string);
    if new_email == session.user.email {
        return Err(ApiError::message(StatusCode::BAD_REQUEST, "Email is the same"));
    }
    let secret = ctx.secret().to_string();
    if db::find_user_by_email(&ctx.state.pg, &new_email).await?.is_some() {
        info!(user_id = %session.user.id, "Change email attempt for existing email");
        return Ok(Reply::Json(json!({"status": true})));
    }
    if session.user.email_verified {
        let token = email_verification_token(&secret, &session.user.email, Some(&new_email), Some("change-email-confirmation"));
        let url = verification_url(ctx, &token, callback.as_deref());
        if let Err(err) = email::send_change_email_verification(&ctx.state.config, &session.user.email, &new_email, &url).await {
            error!(error = %err, "Failed to run background task");
        }
        info!(user_id = %session.user.id, "Email change confirmation sent");
        return Ok(Reply::Json(json!({"status": true})));
    }
    let token = email_verification_token(&secret, &session.user.email, Some(&new_email), Some("change-email-verification"));
    let url = verification_url(ctx, &token, callback.as_deref());
    send_verification_email_to(ctx, &new_email, &url).await;
    info!(user_id = %session.user.id, "Email change verification sent to the new address");
    Ok(Reply::Json(json!({"status": true})))
}

const DELETE_USER_FIELDS: &[validate::Field] =
    &[optional("callbackURL", Ty::String), optional("password", Ty::String), optional("token", Ty::String)];

/// `POST /delete-user` with auth.ts's `afterDelete` (the user's API keys go too)
pub async fn delete_user(ctx: &mut Ctx<'_>) -> EndpointResult {
    validate::object(ctx.body.as_ref(), DELETE_USER_FIELDS, "body", false)?;
    let session = require_session(ctx).await?;
    let password = ctx.body_str("password").filter(|p| !p.is_empty()).map(str::to_string);
    let token = ctx.body_str("token").filter(|t| !t.is_empty()).map(str::to_string);
    if let Some(password) = &password {
        let accounts = db::find_accounts(&ctx.state.pg, &session.user.id).await?;
        let Some(account) = accounts
            .into_iter()
            .find(|account| account.provider_id == "credential" && account.password.as_deref().is_some_and(|p| !p.is_empty()))
        else {
            return Err(bad_request("CREDENTIAL_ACCOUNT_NOT_FOUND", "Credential account not found"));
        };
        match crypto::verify_password(account.password.as_deref().unwrap_or_default(), password).await {
            Ok(true) => {}
            Ok(false) => return Err(bad_request("INVALID_PASSWORD", "Invalid password")),
            Err(_) => return Err(ApiError::internal()),
        }
    }
    if let Some(token) = token {
        // deleteUserCallback: the token must be a delete-account verification for this user
        let consumed = db::consume_verification(&ctx.state.pg, &format!("delete-account-{token}")).await?;
        if consumed.is_none_or(|row| row.value != session.user.id) {
            return Err(ApiError::code(StatusCode::NOT_FOUND, "INVALID_TOKEN", "Invalid token"));
        }
        remove_user(ctx, &session).await?;
        return Ok(Reply::Json(json!({"success": true, "message": "User deleted"})));
    }
    if password.is_none() {
        let age_ms = chrono::Utc::now().timestamp_millis() - db::epoch_ms(db::ms(session.session.created_at));
        if age_ms >= SESSION_FRESH_AGE * 1000 {
            return Err(bad_request("SESSION_EXPIRED", "Session expired. Re-authenticate to perform this action."));
        }
    }
    remove_user(ctx, &session).await?;
    Ok(Reply::Json(json!({"success": true, "message": "User deleted"})))
}

async fn remove_user(ctx: &mut Ctx<'_>, session: &SessionWithUser) -> Result<(), ApiError> {
    db::delete_user(&ctx.state.pg, &session.user.id).await?;
    db::delete_user_sessions(&ctx.state.pg, &session.user.id).await?;
    ctx.delete_session_cookie(false);
    if let Err(err) = sqlx::query(r#"DELETE FROM apikey WHERE "referenceId" = $1"#).bind(&session.user.id).execute(&ctx.state.pg).await {
        error!(error = %err, user_id = %session.user.id, "Error deleting API keys for removed user");
    }
    info!(user_id = %session.user.id, "User deleted");
    Ok(())
}

/// `GET /verify-email?token=&callbackURL=`
pub async fn verify_email(ctx: &mut Ctx<'_>) -> EndpointResult {
    validate::object(Some(&Value::Object(ctx.query.clone())), &[required("token", Ty::String), optional("callbackURL", Ty::String)], "query", false)?;
    let callback = ctx.query_str("callbackURL").map(str::to_string);
    origin::origin_check_value(ctx, callback.as_deref())?;
    let token = ctx.query_str("token").unwrap_or_default().to_string();

    let redirect_on_error = |code: &str, message: &str| -> ApiError {
        match &callback {
            Some(cb) if !cb.is_empty() => {
                let separator = if cb.contains('?') { '&' } else { '?' };
                ApiError::redirect(&format!("{cb}{separator}error={code}"))
            }
            _ => ApiError::code(StatusCode::UNAUTHORIZED, code, message),
        }
    };
    let claims = match crypto::verify_hs256(&token, ctx.secret()) {
        Ok(claims) => claims,
        Err(crypto::JwtError::Expired) => return Err(redirect_on_error("TOKEN_EXPIRED", "Token expired")),
        Err(crypto::JwtError::Invalid) => return Err(redirect_on_error("INVALID_TOKEN", "Invalid token")),
    };
    // z.object({ email: z.email(), updateTo, requestType }).parse(): a ZodError is a 500
    let email = claims.get("email").and_then(Value::as_str).filter(|email| validate::is_email(email)).map(str::to_string);
    let string_or_absent = |key: &str| claims.get(key).is_none_or(Value::is_string);
    let (Some(email), true, true) = (email, string_or_absent("updateTo"), string_or_absent("requestType")) else {
        error!("Verification token payload failed validation");
        return Err(ApiError::internal());
    };
    let update_to = claims.get("updateTo").and_then(Value::as_str).map(str::to_string);
    let request_type = claims.get("requestType").and_then(Value::as_str).map(str::to_string);

    let Some(user) = db::find_user_by_email(&ctx.state.pg, &email).await? else {
        return Err(redirect_on_error("USER_NOT_FOUND", "User not found"));
    };
    let finish = |ctx: &Ctx<'_>, body: Value| -> EndpointResult {
        let _ = ctx;
        match &callback {
            Some(cb) if !cb.is_empty() => Err(ApiError::redirect(cb)),
            _ => Ok(Reply::Json(body)),
        }
    };

    if let Some(update_to) = update_to {
        let session = session_from_ctx(ctx).await;
        if session.as_ref().is_some_and(|session| session.user.email != email) {
            return Err(redirect_on_error("INVALID_USER", "Invalid user"));
        }
        match request_type.as_deref() {
            Some("change-email-confirmation") => {
                let new_token = email_verification_token(ctx.secret(), &email, Some(&update_to), Some("change-email-verification"));
                let url = verification_url(ctx, &new_token, callback.as_deref());
                send_verification_email_to(ctx, &update_to, &url).await;
                info!(user_id = %user.id, "Email change confirmed, verification sent to the new address");
                return finish(ctx, json!({"status": true}));
            }
            Some("change-email-verification") => {
                let active = match session {
                    Some(session) => session,
                    None => {
                        let created = db::create_session(&ctx.state.pg, &user.id, new_session_options(ctx)).await.map_err(|_| {
                            ApiError::code(StatusCode::INTERNAL_SERVER_ERROR, "FAILED_TO_CREATE_SESSION", "Failed to create session")
                        })?;
                        SessionWithUser { session: created, user: user.clone() }
                    }
                };
                let updated = db::update_user_by_email(&ctx.state.pg, &email, vec![UserField::Email(update_to.clone()), UserField::EmailVerified(true)])
                    .await?;
                let mut cookie_user = active.user.clone();
                cookie_user.email = update_to.clone();
                cookie_user.email_verified = true;
                ctx.set_session_cookie(&SessionWithUser { session: active.session, user: cookie_user }, None, None);
                info!(user_id = %user.id, "Email changed");
                return finish(ctx, json!({"status": true, "user": updated.map_or(Value::Null, |u| u.to_json())}));
            }
            _ => {
                let active = match session {
                    Some(session) => session,
                    None => {
                        let created = db::create_session(&ctx.state.pg, &user.id, new_session_options(ctx)).await.map_err(|_| {
                            ApiError::code(StatusCode::INTERNAL_SERVER_ERROR, "FAILED_TO_CREATE_SESSION", "Failed to create session")
                        })?;
                        SessionWithUser { session: created, user: user.clone() }
                    }
                };
                let updated = db::update_user_by_email(&ctx.state.pg, &email, vec![UserField::Email(update_to.clone()), UserField::EmailVerified(false)])
                    .await?;
                let new_token = email_verification_token(ctx.secret(), &update_to, None, None);
                let url = verification_url(ctx, &new_token, callback.as_deref());
                if let Some(updated) = &updated {
                    send_verification_email_to(ctx, &updated.email, &url).await;
                }
                let mut cookie_user = active.user.clone();
                cookie_user.email = update_to.clone();
                cookie_user.email_verified = false;
                ctx.set_session_cookie(&SessionWithUser { session: active.session, user: cookie_user }, None, None);
                info!(user_id = %user.id, "Email changed through a legacy verification token");
                return finish(ctx, json!({"status": true, "user": updated.map_or(Value::Null, |u| u.to_json())}));
            }
        }
    }

    if user.email_verified {
        return finish(ctx, json!({"status": true, "user": null}));
    }
    db::update_user_by_email(&ctx.state.pg, &email, vec![UserField::EmailVerified(true)]).await?;
    info!(user_id = %user.id, "Email verified");
    finish(ctx, json!({"status": true, "user": null}))
}

/// `POST /send-verification-email`: without a session the answer takes at least
/// 500 ms whatever happened, so it cannot reveal whether the address exists.
pub async fn send_verification_email(ctx: &mut Ctx<'_>) -> EndpointResult {
    validate::object(ctx.body.as_ref(), &[required("email", Ty::Email), optional("callbackURL", Ty::String)], "body", false)?;
    let email = ctx.body_str("email").unwrap_or_default().to_string();
    let callback = ctx.body_str("callbackURL").map(str::to_string);
    let Some(session) = session_from_ctx(ctx).await else {
        let started = std::time::Instant::now();
        if let Some(user) = db::find_user_by_email(&ctx.state.pg, &email).await?
            && !user.email_verified
        {
            let token = email_verification_token(ctx.secret(), &user.email, None, None);
            let url = verification_url(ctx, &token, callback.as_deref());
            if let Err(err) = email::send_email_verification_link(&ctx.state.config, &user.email, &url).await {
                error!(error = %err, "Verification email failed");
            }
        }
        let elapsed = started.elapsed();
        if elapsed < std::time::Duration::from_millis(500) {
            tokio::time::sleep(std::time::Duration::from_millis(500) - elapsed).await;
        }
        return Ok(Reply::Json(json!({"status": true})));
    };
    if db::js_lowercase(&session.user.email) != db::js_lowercase(&email) {
        return Err(bad_request("EMAIL_MISMATCH", "Email mismatch"));
    }
    if session.user.email_verified {
        return Err(bad_request("EMAIL_ALREADY_VERIFIED", "Email is already verified"));
    }
    let token = email_verification_token(ctx.secret(), &session.user.email, None, None);
    let url = verification_url(ctx, &token, callback.as_deref());
    email::send_email_verification_link(&ctx.state.config, &session.user.email, &url).await.map_err(|_| ApiError::internal())?;
    Ok(Reply::Json(json!({"status": true})))
}

/// `freshSessionMiddleware`
async fn require_fresh_session(ctx: &mut Ctx<'_>) -> Result<SessionWithUser, ApiError> {
    let session = require_session(ctx).await?;
    let age_ms = chrono::Utc::now().timestamp_millis() - db::epoch_ms(db::ms(session.session.created_at));
    if age_ms >= SESSION_FRESH_AGE * 1000 {
        return Err(ApiError::code(StatusCode::FORBIDDEN, "SESSION_NOT_FRESH", "Session is not fresh"));
    }
    Ok(session)
}

/// `GET /list-sessions`, with the admin plugin's after hook hiding impersonation sessions
pub async fn list_sessions(ctx: &mut Ctx<'_>) -> EndpointResult {
    let session = require_fresh_session(ctx).await?;
    let now = db::now_ms();
    let rows = sqlx::query_scalar::<_, String>(r#"SELECT token FROM session WHERE "userId" = $1 AND "expiresAt" > $2 LIMIT 100"#)
        .bind(&session.user.id)
        .bind(now)
        .fetch_all(&ctx.state.pg)
        .await?;
    let sessions = db::list_user_sessions(&ctx.state.pg, &session.user.id).await?;
    let listed: Vec<Value> = sessions
        .into_iter()
        .filter(|row| rows.contains(&row.token) && !db::is_past(row.expires_at) && row.impersonated_by.as_deref().is_none_or(str::is_empty))
        .map(|row| row.to_json())
        .collect();
    Ok(Reply::Json(Value::Array(listed)))
}

/// `POST /revoke-session`
pub async fn revoke_session(ctx: &mut Ctx<'_>) -> EndpointResult {
    validate::object(ctx.body.as_ref(), &[required("token", Ty::String)], "body", false)?;
    let session = require_session(ctx).await?;
    let token = ctx.body_str("token").unwrap_or_default().to_string();
    if db::find_session(&ctx.state.pg, &token).await?.is_some_and(|found| found.session.user_id == session.user.id) {
        db::delete_session(&ctx.state.pg, &token)
            .await
            .map_err(|_| ApiError::code(StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL_SERVER_ERROR", "Internal Server Error"))?;
        info!(user_id = %session.user.id, "Session revoked");
    }
    Ok(Reply::Json(json!({"status": true})))
}

/// `POST /revoke-sessions`
pub async fn revoke_sessions(ctx: &mut Ctx<'_>) -> EndpointResult {
    let session = require_session(ctx).await?;
    db::delete_user_sessions(&ctx.state.pg, &session.user.id)
        .await
        .map_err(|_| ApiError::code(StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL_SERVER_ERROR", "Internal Server Error"))?;
    info!(user_id = %session.user.id, "All sessions revoked");
    Ok(Reply::Json(json!({"status": true})))
}

/// `POST /revoke-other-sessions`
pub async fn revoke_other_sessions(ctx: &mut Ctx<'_>) -> EndpointResult {
    let session = require_session(ctx).await?;
    let others: Vec<String> = db::list_user_sessions(&ctx.state.pg, &session.user.id)
        .await?
        .into_iter()
        .filter(|row| !db::is_past(row.expires_at) && row.token != session.session.token)
        .map(|row| row.token)
        .collect();
    for token in others {
        db::delete_session(&ctx.state.pg, &token).await?;
    }
    info!(user_id = %session.user.id, "Other sessions revoked");
    Ok(Reply::Json(json!({"status": true})))
}

/// `GET /error`: production redirects to the dashboard root with the sanitised code
pub fn error_page(ctx: &mut Ctx<'_>) -> EndpointResult {
    let params: Vec<(String, String)> = url::form_urlencoded::parse(ctx.raw_query.as_deref().unwrap_or_default().as_bytes())
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect();
    let get = |name: &str| params.iter().find(|(key, _)| key == name).map(|(_, value)| value.clone()).filter(|v| !v.is_empty());
    let code = get("error").unwrap_or_else(|| "UNKNOWN".to_string());
    let safe_code = if code.chars().all(|c| c.is_ascii_alphanumeric() || "'_-".contains(c)) { code } else { "UNKNOWN".to_string() };
    let mut query = url::form_urlencoded::Serializer::new(String::new());
    query.append_pair("error", &safe_code);
    if let Some(description) = get("error_description") {
        query.append_pair("error_description", &description);
    }
    if !ctx.production() {
        warn!("Better Auth's HTML error page is not ported; redirecting as in production");
    }
    Ok(Reply::Raw { status: StatusCode::FOUND, headers: vec![("location".into(), format!("/?{}", query.finish()))], body: None })
}

/// Helpers for other modules
pub fn session_is_fresh_for_delete(session: &SessionWithUser) -> bool {
    chrono::Utc::now().timestamp_millis() - db::epoch_ms(db::ms(session.session.created_at)) < SESSION_FRESH_AGE * 1000
}

pub async fn authoritative(ctx: &mut Ctx<'_>) -> Option<SessionWithUser> {
    authoritative_session(ctx).await
}
