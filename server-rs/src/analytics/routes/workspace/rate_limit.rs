//! Per-route rate limiting, ported from @fastify/rate-limit 10.3.0 as
//! server/src/index.ts registers it: `global: false`, `hook: "preHandler"`, the
//! Redis store (key prefix `fastify-rate-limit-`), `skipOnError: true`, and
//! `keyGenerator: request.user?.id ?? request.ip`.
//!
//! Both backends share Redis during the cutover, so the key, the Lua script and
//! the headers are the same bytes Node uses: one counter per route and caller,
//! whichever backend served the request.
//!
//! The limiter's hook runs after the route's preHandler chain (the plugin appends
//! it to the route's `preHandler` array), so the caller is already known. The
//! plugin *mutates* that array, and index.ts shares chain objects between routes,
//! which gives two effective limiters rather than three:
//!
//! - `authDashboardsRead` is shared by GET /dashboards, GET /dashboards/:id and
//!   POST /dashboards/run-card, so all three (and the HEAD twins of the GETs)
//!   count against the run-card limiter.
//! - `orgSqlRead` is shared by POST /analytics/query and /analytics/query/generate;
//!   both arrays end with the query hook then the generate hook, and the plugin's
//!   `rateLimitRan` flag lets only the first run. Generate is therefore limited
//!   by the query limiter (60 per minute, the query key), never by its own 20.

use std::{sync::LazyLock, time::Duration};

use axum::{
    http::{HeaderName, HeaderValue, StatusCode},
    response::Response,
};
use serde_json::json;
use tracing::{debug, warn};

use crate::{http, state::AppState};

/// `RedisStore`'s Lua script, byte for byte.
const RATE_LIMIT_LUA: &str = "
  -- Key to operate on
  local key = KEYS[1]
  -- Time window for the TTL
  local timeWindow = tonumber(ARGV[1])
  -- Max requests
  local max = tonumber(ARGV[2])
  -- Flag to determine if TTL should be reset after exceeding
  local continueExceeding = ARGV[3] == 'true'
  --Flag to determine if exponential backoff should be applied
  local exponentialBackoff = ARGV[4] == 'true'

  --Max safe integer
  local MAX_SAFE_INTEGER = (2^53) - 1

  -- Increment the key's value
  local current = redis.call('INCR', key)

  if current == 1 or (continueExceeding and current > max) then
    redis.call('PEXPIRE', key, timeWindow)
  elseif exponentialBackoff and current > max then
    local backoffExponent = current - max - 1
    timeWindow = math.min(timeWindow * (2 ^ backoffExponent), MAX_SAFE_INTEGER)
    redis.call('PEXPIRE', key, timeWindow)
  else
    timeWindow = redis.call('PTTL', key)
  end

  return {current, timeWindow}
";

static RATE_LIMIT_SCRIPT: LazyLock<redis::Script> = LazyLock::new(|| redis::Script::new(RATE_LIMIT_LUA));

/// ioredis `commandTimeout` on the limiter's connection
const REDIS_COMMAND_TIMEOUT: Duration = Duration::from_millis(1000);

/// One route's limiter: the store child's key prefix and its `max`/`timeWindow`.
#[derive(Clone, Copy, Debug)]
pub struct RouteLimiter {
    /// `${routeInfo.method}${routeInfo.url}` of the route whose hook runs
    pub route: &'static str,
    pub max: i64,
    pub time_window_ms: i64,
}

/// `customQueryRateLimit` on POST /dashboards/run-card (and, through the shared
/// chain, the dashboard GETs)
pub const RUN_CARD: RouteLimiter =
    RouteLimiter { route: "POST/api/sites/:siteId/dashboards/run-card", max: 60, time_window_ms: 60_000 };

/// `customQueryRateLimit` on POST /analytics/query (and, through the shared
/// chain, /analytics/query/generate)
pub const CUSTOM_QUERY: RouteLimiter =
    RouteLimiter { route: "POST/api/organizations/:organizationId/analytics/query", max: 60, time_window_ms: 60_000 };

/// The headers a request that got through carries on whatever response follows.
pub type LimitHeaders = Vec<(HeaderName, HeaderValue)>;

fn header_value(number: i64) -> HeaderValue {
    HeaderValue::from_str(&number.to_string()).expect("digits are a valid header value")
}

/// `@lukeed/ms` `format(ms, true)` for the non-negative whole-second values the
/// plugin passes.
pub fn format_long(ms: i64) -> String {
    const SEC: f64 = 1e3;
    const MIN: f64 = SEC * 60.0;
    const HOUR: f64 = MIN * 60.0;
    const DAY: f64 = HOUR * 24.0;
    const YEAR: f64 = DAY * 365.25;
    let value = ms as f64;
    let prefix = if value < 0.0 { "-" } else { "" };
    let abs = value.abs();
    if abs < SEC {
        return format!("{ms} ms");
    }
    let fmt = |amount: f64, unit: &str| {
        let number = if amount.fract() == 0.0 { amount } else { (amount + 0.5).trunc() };
        let plural = if number != 1.0 { "s" } else { "" };
        format!("{prefix}{} {unit}{plural}", number as i64)
    };
    if abs < MIN {
        fmt(abs / SEC, "second")
    } else if abs < HOUR {
        fmt(abs / MIN, "minute")
    } else if abs < DAY {
        fmt(abs / HOUR, "hour")
    } else if abs < YEAR {
        fmt(abs / DAY, "day")
    } else {
        fmt(abs / YEAR, "year")
    }
}

/// The plugin's decision given the store's `{ current, ttl }`: the headers for a
/// request under the limit, or the 429 response (headers included).
pub fn decide(limiter: RouteLimiter, current: i64, ttl: i64) -> Result<LimitHeaders, Response> {
    let ttl_in_seconds = (ttl as f64 / 1000.0).ceil() as i64;
    let remaining = (limiter.max - current).max(0);
    if current <= limiter.max {
        return Ok(vec![
            (HeaderName::from_static("x-ratelimit-limit"), header_value(limiter.max)),
            (HeaderName::from_static("x-ratelimit-remaining"), header_value(remaining)),
            (HeaderName::from_static("x-ratelimit-reset"), header_value(ttl_in_seconds)),
        ]);
    }
    // defaultErrorResponse, serialised by Fastify's default error handler
    let message = format!("Rate limit exceeded, retry in {}", format_long(ttl_in_seconds * 1000));
    let mut response = http::json(
        StatusCode::TOO_MANY_REQUESTS,
        &json!({ "statusCode": 429, "error": "Too Many Requests", "message": message }),
    );
    let headers = response.headers_mut();
    headers.insert(HeaderName::from_static("x-ratelimit-limit"), header_value(limiter.max));
    headers.insert(HeaderName::from_static("x-ratelimit-remaining"), header_value(0));
    headers.insert(HeaderName::from_static("x-ratelimit-reset"), header_value(ttl_in_seconds));
    headers.insert(HeaderName::from_static("retry-after"), header_value(ttl_in_seconds));
    Err(response)
}

/// Charge one request to `key` (the caller's user id, else `request.ip`).
pub async fn check(state: &AppState, limiter: RouteLimiter, key: &str) -> Result<LimitHeaders, Response> {
    let redis_key = format!("fastify-rate-limit-{}-{key}", limiter.route);
    let mut connection = state.redis.clone();
    let mut invocation = RATE_LIMIT_SCRIPT.key(&redis_key);
    invocation.arg(limiter.time_window_ms).arg(limiter.max).arg("false").arg("false");
    let outcome = tokio::time::timeout(REDIS_COMMAND_TIMEOUT, invocation.invoke_async::<(i64, i64)>(&mut connection)).await;
    let (current, ttl) = match outcome {
        Ok(Ok(result)) => result,
        // skipOnError: an unreachable store lets the request through uncounted
        Ok(Err(err)) => {
            warn!(error = %err, route = limiter.route, "Rate limit store failed; allowing request");
            (0, 0)
        }
        Err(_) => {
            warn!(route = limiter.route, "Rate limit store timed out; allowing request");
            (0, 0)
        }
    };
    let decision = decide(limiter, current, ttl);
    match &decision {
        Ok(_) => debug!(route = limiter.route, current, ttl, "Rate limit charged"),
        Err(_) => warn!(route = limiter.route, current, ttl, "Rate limit exceeded"),
    }
    decision
}

/// Attach a passed limiter's headers to the handler's response.
pub fn with_headers(mut response: Response, headers: LimitHeaders) -> Response {
    for (name, value) in headers {
        response.headers_mut().insert(name, value);
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_like_lukeed_ms() {
        // require("@lukeed/ms").format(n, true)
        assert_eq!(format_long(0), "0 ms");
        assert_eq!(format_long(1000), "1 second");
        assert_eq!(format_long(46_000), "46 seconds");
        assert_eq!(format_long(60_000), "1 minute");
        assert_eq!(format_long(90_000), "2 minutes");
    }

    #[tokio::test]
    async fn exceeding_answers_429_with_retry_after() {
        let headers = decide(CUSTOM_QUERY, 60, 1500).unwrap();
        assert_eq!(headers[1].1, "0");
        assert_eq!(headers[2].1, "2");
        let response = decide(CUSTOM_QUERY, 61, 59_001).unwrap_err();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(response.headers()["retry-after"], "60");
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert_eq!(
            &body[..],
            br#"{"statusCode":429,"error":"Too Many Requests","message":"Rate limit exceeded, retry in 1 minute"}"#
        );
        // a key without a TTL reports PTTL -1, which rounds to a zero reset
        assert_eq!(decide(RUN_CARD, 1, -1).unwrap()[2].1, "0");
    }
}
