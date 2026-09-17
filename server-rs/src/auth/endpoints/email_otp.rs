//! The email OTP plugin (better-auth/dist/plugins/email-otp) as auth.ts configures
//! it: 6 digits stored in plain text as `otp:attempts` in `verification`, 5 minute
//! expiry, 3 attempts, no resend reuse, `disableSignUp` from DISABLE_SIGNUP, and
//! `sendOtpEmail` as the sender. Change-email by OTP is not enabled.

use axum::http::StatusCode;
use serde_json::{Value, json};
use tracing::{error, info, warn};

use crate::email::{self, OtpEmailType};

use super::{
    context::{ApiError, Ctx, EndpointResult, Reply},
    core_routes::{create_user, new_session_options},
    crypto,
    db::{self, SessionWithUser, UserField},
    origin, require_session,
    validate::{self, Ty, optional, required},
};

const OTP_EXPIRES_IN: i64 = 300;
const ALLOWED_ATTEMPTS: i64 = 3;
const TYPES: &[&str] = &["email-verification", "sign-in", "forget-password", "change-email"];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Route {
    SendVerificationOtp,
    CheckVerificationOtp,
    VerifyEmail,
    SignIn,
    RequestPasswordReset,
    ForgetPassword,
    ResetPassword,
    RequestEmailChange,
    ChangeEmail,
}

pub async fn run(ctx: &mut Ctx<'_>, route: Route) -> EndpointResult {
    match route {
        Route::SendVerificationOtp => send_verification_otp(ctx).await,
        Route::CheckVerificationOtp => check_verification_otp(ctx).await,
        Route::VerifyEmail => verify_email(ctx).await,
        Route::SignIn => sign_in(ctx).await,
        Route::RequestPasswordReset | Route::ForgetPassword => request_password_reset(ctx, route).await,
        Route::ResetPassword => reset_password(ctx).await,
        Route::RequestEmailChange | Route::ChangeEmail => change_email_disabled(ctx, route).await,
    }
}

/// `toOTPIdentifier`
fn identifier(kind: &str, email: &str) -> String {
    format!("{kind}-otp-{email}")
}

fn invalid_otp() -> ApiError {
    ApiError::code(StatusCode::BAD_REQUEST, "INVALID_OTP", "Invalid OTP")
}

/// `splitAtLastColon`
fn split_at_last_colon(value: &str) -> (&str, &str) {
    match value.rfind(':') {
        Some(index) => (&value[..index], &value[index + 1..]),
        None => (value, ""),
    }
}

/// JavaScript `parseInt(text)` for the attempt counter (NaN compares false)
fn parse_int(text: &str) -> Option<i64> {
    let trimmed = text.trim_start();
    let (sign, digits) = match trimmed.strip_prefix('-') {
        Some(rest) => (-1, rest),
        None => (1, trimmed.strip_prefix('+').unwrap_or(trimmed)),
    };
    let digits: String = digits.chars().take_while(char::is_ascii_digit).collect();
    digits.parse::<i64>().ok().map(|value| sign * value)
}

/// `resolveOTP`: a fresh code, its row created (on an insert error the identifier's
/// rows are deleted and the insert retried)
async fn resolve_otp(ctx: &Ctx<'_>, email: &str, kind: &str) -> Result<String, ApiError> {
    let otp = crypto::random_string(6, &[crypto::DIGITS]);
    let id = identifier(kind, email);
    let value = format!("{otp}:0");
    if let Err(err) = db::create_verification(&ctx.state.pg, &id, &value, db::in_seconds(OTP_EXPIRES_IN)).await {
        warn!(error = %err, "OTP insert failed, retrying after clearing the identifier");
        db::delete_verification(&ctx.state.pg, &id).await?;
        db::create_verification(&ctx.state.pg, &id, &value, db::in_seconds(OTP_EXPIRES_IN)).await?;
    }
    Ok(otp)
}

/// `sendOtpEmail` through `runInBackgroundOrAwait` (errors logged, not surfaced)
async fn send(ctx: &Ctx<'_>, email: &str, otp: &str, kind: &str) {
    let Some(kind) = OtpEmailType::parse(kind) else { return };
    if let Err(err) = email::send_otp_email(&ctx.state.config, email, otp, kind).await {
        error!(error = %err, "Failed to run background task");
    }
}

/// `POST /email-otp/send-verification-otp`
async fn send_verification_otp(ctx: &mut Ctx<'_>) -> EndpointResult {
    validate::object(ctx.body.as_ref(), &[required("email", Ty::String), required("type", Ty::Enum(TYPES))], "body", false)?;
    origin::form_csrf_middleware(ctx)?;
    let email = db::js_lowercase(ctx.body_str("email").unwrap_or_default());
    let kind = ctx.body_str("type").unwrap_or_default().to_string();
    if !validate::is_email(&email) {
        return Err(ApiError::code(StatusCode::BAD_REQUEST, "INVALID_EMAIL", "Invalid email"));
    }
    if kind == "change-email" {
        error!("Use the /email-otp/request-email-change endpoint to send OTP for changing email");
        return Err(ApiError::message(StatusCode::BAD_REQUEST, "Invalid OTP type"));
    }
    let otp = resolve_otp(ctx, &email, &kind).await?;
    let sends_to_unknown = kind == "sign-in" && !ctx.state.config.disable_signup;
    if db::find_user_by_email(&ctx.state.pg, &email).await?.is_none() && !sends_to_unknown {
        db::delete_verification(&ctx.state.pg, &identifier(&kind, &email)).await?;
        info!(kind = %kind, "OTP requested for an unknown email; nothing sent");
        return Ok(Reply::Json(json!({"success": true})));
    }
    send(ctx, &email, &otp, &kind).await;
    info!(kind = %kind, "OTP sent");
    Ok(Reply::Json(json!({"success": true})))
}

/// `POST /email-otp/check-verification-otp`: checks without consuming
async fn check_verification_otp(ctx: &mut Ctx<'_>) -> EndpointResult {
    validate::object(
        ctx.body.as_ref(),
        &[required("email", Ty::String), required("type", Ty::Enum(TYPES)), required("otp", Ty::String)],
        "body",
        false,
    )?;
    let email = db::js_lowercase(ctx.body_str("email").unwrap_or_default());
    let kind = ctx.body_str("type").unwrap_or_default().to_string();
    let provided = ctx.body_str("otp").unwrap_or_default().to_string();
    if !validate::is_email(&email) {
        return Err(ApiError::code(StatusCode::BAD_REQUEST, "INVALID_EMAIL", "Invalid email"));
    }
    if db::find_user_by_email(&ctx.state.pg, &email).await?.is_none() {
        return Err(ApiError::code(StatusCode::BAD_REQUEST, "USER_NOT_FOUND", "User not found"));
    }
    let id = identifier(&kind, &email);
    let Some(row) = db::find_verification(&ctx.state.pg, &id).await? else { return Err(invalid_otp()) };
    if db::is_past(row.expires_at) {
        db::delete_verification(&ctx.state.pg, &id).await?;
        return Err(ApiError::code(StatusCode::BAD_REQUEST, "OTP_EXPIRED", "OTP expired"));
    }
    let (stored, attempts) = split_at_last_colon(&row.value);
    if !attempts.is_empty() && parse_int(attempts).is_some_and(|used| used >= ALLOWED_ATTEMPTS) {
        db::delete_verification(&ctx.state.pg, &id).await?;
        return Err(ApiError::code(StatusCode::FORBIDDEN, "TOO_MANY_ATTEMPTS", "Too many attempts"));
    }
    if !crypto::constant_time_eq(&provided, stored) {
        let next = parse_int(if attempts.is_empty() { "0" } else { attempts }).map_or("NaN".to_string(), |used| (used + 1).to_string());
        sqlx::query(r#"UPDATE verification SET value = $1, "updatedAt" = $2 WHERE identifier = $3"#)
            .bind(format!("{stored}:{next}"))
            .bind(db::now_ms())
            .bind(&id)
            .execute(&ctx.state.pg)
            .await?;
        return Err(invalid_otp());
    }
    Ok(Reply::Json(json!({"success": true})))
}

/// `atomicVerifyOTP`: an expired row is deleted (OTP_EXPIRED); otherwise the row is
/// consumed, and a wrong code puts it back with one more attempt and the same expiry.
async fn atomic_verify(ctx: &Ctx<'_>, id: &str, provided: &str) -> Result<(), ApiError> {
    if let Some(existing) = db::find_verification(&ctx.state.pg, id).await?
        && db::is_past(existing.expires_at)
    {
        db::delete_verification(&ctx.state.pg, id).await?;
        info!("Expired OTP refused");
        return Err(ApiError::code(StatusCode::BAD_REQUEST, "OTP_EXPIRED", "OTP expired"));
    }
    let Some(consumed) = db::consume_verification(&ctx.state.pg, id).await? else {
        return Err(invalid_otp());
    };
    let (stored, attempts) = split_at_last_colon(&consumed.value);
    let used = parse_int(if attempts.is_empty() { "0" } else { attempts });
    if used.is_some_and(|used| used >= ALLOWED_ATTEMPTS) {
        info!("OTP refused after too many attempts");
        return Err(ApiError::code(StatusCode::FORBIDDEN, "TOO_MANY_ATTEMPTS", "Too many attempts"));
    }
    if !crypto::constant_time_eq(provided, stored) {
        let next = used.map_or("NaN".to_string(), |used| (used + 1).to_string());
        db::create_verification(&ctx.state.pg, id, &format!("{stored}:{next}"), consumed.expires_at).await?;
        info!("Wrong OTP");
        return Err(invalid_otp());
    }
    Ok(())
}

/// `POST /email-otp/verify-email`
async fn verify_email(ctx: &mut Ctx<'_>) -> EndpointResult {
    validate::object(ctx.body.as_ref(), &[required("email", Ty::String), required("otp", Ty::String)], "body", false)?;
    let email = db::js_lowercase(ctx.body_str("email").unwrap_or_default());
    let otp = ctx.body_str("otp").unwrap_or_default().to_string();
    if !validate::is_email(&email) {
        return Err(ApiError::code(StatusCode::BAD_REQUEST, "INVALID_EMAIL", "Invalid email"));
    }
    atomic_verify(ctx, &identifier("email-verification", &email), &otp).await?;
    let Some(user) = db::find_user_by_email(&ctx.state.pg, &email).await? else {
        return Err(ApiError::code(StatusCode::BAD_REQUEST, "USER_NOT_FOUND", "User not found"));
    };
    let updated = db::update_user(&ctx.state.pg, &user.id, vec![UserField::Email(email.clone()), UserField::EmailVerified(true)])
        .await?
        .ok_or_else(ApiError::internal)?;
    // With no cookie cache the session re-read changes nothing observable
    let _ = super::session_from_ctx(ctx).await;
    info!(user_id = %updated.id, "Email verified with an OTP");
    Ok(Reply::Json(json!({"status": true, "token": null, "user": updated.to_json()})))
}

/// `POST /sign-in/email-otp`: unknown emails are refused while sign-ups are
/// disabled; an unverified account loses its password and sessions first.
async fn sign_in(ctx: &mut Ctx<'_>) -> EndpointResult {
    validate::object(
        ctx.body.as_ref(),
        &[required("email", Ty::String), required("otp", Ty::String), optional("name", Ty::String), optional("image", Ty::String)],
        "body",
        false,
    )?;
    let body = ctx.body_object().cloned().unwrap_or_default();
    let email = db::js_lowercase(body.get("email").and_then(Value::as_str).unwrap_or_default());
    let otp = body.get("otp").and_then(Value::as_str).unwrap_or_default().to_string();
    atomic_verify(ctx, &identifier("sign-in", &email), &otp).await?;

    let user = match db::find_user_by_email(&ctx.state.pg, &email).await? {
        Some(user) => user,
        None => {
            if ctx.state.config.disable_signup {
                info!("OTP sign-in for an unknown email refused: sign-ups disabled");
                return Err(invalid_otp());
            }
            let name = body.get("name").and_then(Value::as_str).unwrap_or_default().to_string();
            let image = body.get("image").and_then(Value::as_str).map(str::to_string);
            let user = create_user(ctx, &email, &name, image, true, &[]).await?;
            let session = db::create_session(&ctx.state.pg, &user.id, new_session_options(ctx)).await?;
            let pair = SessionWithUser { session, user };
            ctx.set_session_cookie(&pair, None, None);
            return Ok(Reply::Json(json!({"token": pair.session.token, "user": pair.user.to_json()})));
        }
    };
    if !user.email_verified {
        // revokeUnprovenAccountAccess
        if db::find_user_by_id(&ctx.state.pg, &user.id).await?.is_some_and(|fresh| !fresh.email_verified) {
            sqlx::query(r#"DELETE FROM account WHERE "userId" = $1 AND "providerId" = 'credential'"#)
                .bind(&user.id)
                .execute(&ctx.state.pg)
                .await?;
            db::delete_user_sessions(&ctx.state.pg, &user.id).await?;
        }
        db::update_user(&ctx.state.pg, &user.id, vec![UserField::EmailVerified(true)]).await?;
    }
    let session = db::create_session(&ctx.state.pg, &user.id, new_session_options(ctx)).await?;
    let pair = SessionWithUser { session, user };
    ctx.set_session_cookie(&pair, None, None);
    info!(user_id = %pair.user.id, "Signed in with an email OTP");
    Ok(Reply::Json(json!({"token": pair.session.token, "user": pair.user.to_json()})))
}

/// `POST /email-otp/request-password-reset` and the deprecated `/forget-password/email-otp`
async fn request_password_reset(ctx: &mut Ctx<'_>, route: Route) -> EndpointResult {
    validate::object(ctx.body.as_ref(), &[required("email", Ty::String)], "body", false)?;
    if route == Route::ForgetPassword {
        warn!("The \"/forget-password/email-otp\" endpoint is deprecated");
    }
    let email = db::js_lowercase(ctx.body_str("email").unwrap_or_default());
    let otp = resolve_otp(ctx, &email, "forget-password").await?;
    if db::find_user_by_email(&ctx.state.pg, &email).await?.is_none() {
        db::delete_verification(&ctx.state.pg, &identifier("forget-password", &email)).await?;
        return Ok(Reply::Json(json!({"success": true})));
    }
    send(ctx, &email, &otp, "forget-password").await;
    info!("Password reset OTP sent");
    Ok(Reply::Json(json!({"success": true})))
}

/// `POST /email-otp/reset-password`: sessions are kept (no `revokeSessionsOnPasswordReset`)
async fn reset_password(ctx: &mut Ctx<'_>) -> EndpointResult {
    validate::object(
        ctx.body.as_ref(),
        &[required("email", Ty::String), required("otp", Ty::String), required("password", Ty::String)],
        "body",
        false,
    )?;
    let email = db::js_lowercase(ctx.body_str("email").unwrap_or_default());
    let otp = ctx.body_str("otp").unwrap_or_default().to_string();
    let password = ctx.body_str("password").unwrap_or_default().to_string();
    atomic_verify(ctx, &identifier("forget-password", &email), &otp).await?;
    let Some(user) = db::find_user_by_email(&ctx.state.pg, &email).await? else {
        return Err(ApiError::code(StatusCode::BAD_REQUEST, "USER_NOT_FOUND", "User not found"));
    };
    let length = password.encode_utf16().count();
    if length < 8 {
        return Err(ApiError::code(StatusCode::BAD_REQUEST, "PASSWORD_TOO_SHORT", "Password too short"));
    }
    if length > 128 {
        return Err(ApiError::code(StatusCode::BAD_REQUEST, "PASSWORD_TOO_LONG", "Password too long"));
    }
    let hash = crypto::hash_password(&password).await;
    let accounts = db::find_accounts(&ctx.state.pg, &user.id).await?;
    if accounts.iter().any(|account| account.provider_id == "credential") {
        db::update_credential_passwords(&ctx.state.pg, &user.id, &hash).await?;
    } else {
        db::create_credential_account(&ctx.state.pg, &user.id, &hash).await?;
    }
    if !user.email_verified {
        db::update_user(&ctx.state.pg, &user.id, vec![UserField::EmailVerified(true)]).await?;
    }
    info!(user_id = %user.id, "Password reset with an OTP");
    Ok(Reply::Json(json!({"success": true})))
}

/// `/email-otp/request-email-change` and `/email-otp/change-email`: a session is
/// required, then the feature is off in this configuration.
async fn change_email_disabled(ctx: &mut Ctx<'_>, route: Route) -> EndpointResult {
    let fields: &[validate::Field] = match route {
        Route::RequestEmailChange => &[required("newEmail", Ty::String), optional("otp", Ty::String)],
        _ => &[required("newEmail", Ty::String), required("otp", Ty::String)],
    };
    validate::object(ctx.body.as_ref(), fields, "body", false)?;
    require_session(ctx).await?;
    error!("Change email with OTP is disabled.");
    Err(ApiError::message(StatusCode::BAD_REQUEST, "Change email with OTP is disabled"))
}
