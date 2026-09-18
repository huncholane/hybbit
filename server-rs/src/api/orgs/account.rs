//! Account settings and the marketing unsubscribe endpoints, ported from
//! server/src/api/user/updateAccountSettings.ts and
//! server/src/api/user/unsubscribeMarketing.ts.
//!
//! Resend is only configured in the cloud, so `cancelScheduledEmail` and
//! `unsubscribeContact` are no-ops here, exactly as they are in a self-hosted Node:
//! the rows this writes are the whole effect.

use axum::{
    body::Body,
    extract::State,
    http::{HeaderMap, Method, StatusCode, Uri},
    response::Response,
};
use tracing::{debug, error, info};

use super::{
    chain,
    request::{self, object},
    signed_token, zod,
};
use crate::{
    analytics::{js::JsValue, utils::time_window::now_ms},
    auth::endpoints::db as auth_db,
    state::AppState,
};

/// `LEGACY_UNSIGNED_CUTOFF`: 2026-12-01T00:00:00Z as epoch milliseconds. Emails
/// sent before link signing existed carry no signature and must keep working
/// until then.
const LEGACY_UNSIGNED_CUTOFF_MS: f64 = 1_796_083_200_000.0;

const INVALID_REQUEST_PAGE: &str = "\n          <!DOCTYPE html>\n          <html><head><title>Unsubscribe - Hygo</title></head>\n          <body style=\"font-family: sans-serif; max-width: 600px; margin: 50px auto; text-align: center;\">\n            <h1>Invalid Request</h1>\n            <p>Email address is required to unsubscribe.</p>\n          </body></html>\n        ";

const UNSUBSCRIBED_PAGE: &str = "\n        <!DOCTYPE html>\n        <html><head><title>Unsubscribed - Hygo</title></head>\n        <body style=\"font-family: sans-serif; max-width: 600px; margin: 50px auto; text-align: center;\">\n          <h1>Unsubscribed</h1>\n          <p>You have been successfully unsubscribed from Hygo marketing emails.</p>\n          <p style=\"color: #666; margin-top: 20px;\">You can close this page.</p>\n        </body></html>\n      ";

/// POST /api/user/account-settings (`updateAccountSettings`), chain
/// `authOnlyNoScopedKeys`.
pub async fn update_settings(
    State(state): State<AppState>,
    _method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let body = match request::read_body(&headers, body).await {
        Ok(body) => body,
        Err(response) => return response,
    };
    let scoped = match chain::auth_only_no_scoped_keys(&state, &headers, &uri).await {
        Ok(scoped) => scoped,
        Err(response) => return response,
    };
    let Some(user_id) = scoped.auth.user_id else {
        return request::error(StatusCode::UNAUTHORIZED, "Unauthorized");
    };

    let settings = match zod::account_settings(&body) {
        Ok(settings) => settings,
        Err(issues) => {
            return request::send(
                StatusCode::BAD_REQUEST,
                &object(vec![
                    ("error", "Invalid request body".into()),
                    ("details", zod::zod_error_value(&issues)),
                ]),
            );
        }
    };
    let Some(send_auto_email_reports) = settings else {
        return request::error(StatusCode::BAD_REQUEST, "No settings provided to update");
    };

    let updated: Result<Option<Option<bool>>, sqlx::Error> = sqlx::query_scalar(
        r#"update "user" set "sendAutoEmailReports" = $1, "updatedAt" = $2 where "id" = $3
           returning "sendAutoEmailReports""#,
    )
    .bind(send_auto_email_reports)
    .bind(auth_db::now_ms())
    .bind(&user_id)
    .fetch_optional(&state.pg)
    .await;
    match updated {
        Err(err) => {
            error!(error = %err, "Error updating account settings");
            request::error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to update account settings")
        }
        Ok(None) => request::error(StatusCode::NOT_FOUND, "User not found"),
        Ok(Some(stored)) => {
            info!(user_id, send_auto_email_reports, "Updated account settings");
            request::send(
                StatusCode::OK,
                &object(vec![
                    ("success", JsValue::Bool(true)),
                    ("settings", object(vec![("sendAutoEmailReports", request::boolean(stored))])),
                ]),
            )
        }
    }
}

/// POST /api/user/unsubscribe-marketing (`unsubscribeMarketing`), chain
/// `authOnlyNoScopedKeys`.
pub async fn unsubscribe(
    State(state): State<AppState>,
    _method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Body,
) -> Response {
    if let Err(response) = request::read_body(&headers, body).await {
        return response;
    }
    let scoped = match chain::auth_only_no_scoped_keys(&state, &headers, &uri).await {
        Ok(scoped) => scoped,
        Err(response) => return response,
    };
    let Some(user_id) = scoped.auth.user_id else {
        return request::error(StatusCode::UNAUTHORIZED, "Unauthorized");
    };

    let result: Result<Response, sqlx::Error> = async {
        let found: Option<String> = sqlx::query_scalar(r#"select "email" from "user" where "id" = $1"#)
            .bind(&user_id)
            .fetch_optional(&state.pg)
            .await?;
        if found.is_none() {
            return Ok(request::error(StatusCode::NOT_FOUND, "User not found"));
        }
        clear_scheduled_tips(&state, &user_id).await?;
        info!(user_id, "Unsubscribed from marketing emails");
        Ok(request::send(
            StatusCode::OK,
            &object(vec![
                ("success", JsValue::Bool(true)),
                ("message", "Successfully unsubscribed from marketing emails".into()),
            ]),
        ))
    }
    .await;
    result.unwrap_or_else(|err| {
        error!(error = %err, "Error unsubscribing from marketing emails");
        request::error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to unsubscribe")
    })
}

/// `db.update(user).set({ scheduledTipEmailIds: [], updatedAt: ... })`
async fn clear_scheduled_tips(state: &AppState, user_id: &str) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"update "user" set "scheduled_tip_email_ids" = $1::jsonb, "updatedAt" = $2 where "id" = $3"#,
    )
    .bind("[]")
    .bind(auth_db::now_ms())
    .bind(user_id)
    .execute(&state.pg)
    .await?;
    Ok(())
}

/// GET and POST /api/user/unsubscribe-marketing-oneclick
/// (`oneClickUnsubscribeMarketing`). No preHandler: the signature is the whole
/// authorisation. A GET shows a confirmation page, a POST answers RFC 8058's
/// List-Unsubscribe-Post with a bare 200.
pub async fn one_click_unsubscribe(
    State(state): State<AppState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Body,
) -> Response {
    if method != Method::GET
        && method != Method::HEAD
        && let Err(response) = request::read_body(&headers, body).await
    {
        return response;
    }
    let query = chain::unguarded(&uri);
    let email = query.get_or_undefined("email").clone();
    let exp = query.get_or_undefined("exp").clone();
    let sig = query.get_or_undefined("sig").clone();
    let is_get = method == Method::GET || method == Method::HEAD;

    if super::js::truthy(&email) {
        let secret = state.config.better_auth_secret.as_deref().unwrap_or_default();
        let payload = format!("unsubscribe:{}", email.to_js_string());
        let valid_signature = super::js::truthy(&sig)
            && super::js::truthy(&exp)
            && signed_token::verify_expiring_payload(secret, &payload, &exp, &sig.to_js_string(), now_ms());
        let legacy_window_open = now_ms() < LEGACY_UNSIGNED_CUTOFF_MS;
        let acceptable_legacy = !super::js::truthy(&sig) && !super::js::truthy(&exp) && legacy_window_open;
        if !valid_signature && !acceptable_legacy {
            debug!("Rejected an unsigned or expired unsubscribe link");
            return request::error(StatusCode::BAD_REQUEST, "Invalid or expired unsubscribe link");
        }
    }

    if !super::js::truthy(&email) {
        if is_get {
            return request::send_html(StatusCode::BAD_REQUEST, INVALID_REQUEST_PAGE);
        }
        return request::error(StatusCode::BAD_REQUEST, "Email is required");
    }

    let result: Result<(), sqlx::Error> = async {
        let JsValue::String(address) = &email else {
            // A repeated `email` parameter is an array, which postgres-js sends as an
            // array parameter: the comparison against a text column throws
            return Err(sqlx::Error::Protocol("operator does not exist: text = text[]".into()));
        };
        let found: Option<String> = sqlx::query_scalar(r#"select "id" from "user" where "email" = $1"#)
            .bind(address)
            .fetch_optional(&state.pg)
            .await?;
        if let Some(user_id) = found {
            clear_scheduled_tips(&state, &user_id).await?;
            info!(user_id, "One-click unsubscribe cleared the scheduled tips");
        }
        Ok(())
    }
    .await;
    if let Err(err) = result {
        // Node still answers 200 so email clients are not confused
        error!(error = %err, "Error in one-click unsubscribe");
        return request::send_empty(StatusCode::OK);
    }

    if is_get {
        return request::send_html(StatusCode::OK, UNSUBSCRIBED_PAGE);
    }
    request::send_empty(StatusCode::OK)
}
