//! What the @better-auth/infra `dash()` plugin (auth.ts) does to ordinary requests.
//!
//! Its `/dash/*` and `/events/*` endpoints are not ported: they are unusable without
//! the Better Auth dashboard's signing keys, several call out to better-auth.com, and
//! `/dash/check-user-exists` answers `{exists, userId}` for any email to any request
//! carrying an Authorization header. This service answers 404 for all of them.
//!
//! What remains observable is its identification after hook on every non-GET
//! endpoint: an `X-Request-Id` header is echoed into an `__infra-rid` cookie, and a
//! request carrying only that cookie gets it cleared. (Its before hook also looks the
//! id up at kv.better-auth.com, which changes nothing in the response.)

use tracing::debug;

use super::{context::Ctx, cookies::CookieAttributes};

const IDENTIFICATION_COOKIE: &str = "__infra-rid";

pub fn identification_after_hook(ctx: &mut Ctx<'_>) {
    if ctx.method == axum::http::Method::GET {
        return;
    }
    let header = ctx.header("x-request-id").filter(|value| !value.is_empty()).map(str::to_string);
    if let Some(request_id) = header {
        debug!("Identification cookie set from X-Request-Id");
        ctx.set_cookie(
            IDENTIFICATION_COOKIE,
            &request_id,
            &CookieAttributes { max_age: Some(600), path: Some("/"), http_only: true, secure: false, same_site: Some("lax") },
        );
    } else if ctx.cookie(IDENTIFICATION_COOKIE).is_some_and(|value| !value.is_empty()) {
        debug!("Identification cookie cleared");
        ctx.set_cookie(IDENTIFICATION_COOKIE, "", &CookieAttributes { max_age: Some(0), path: Some("/"), ..Default::default() });
    }
}
