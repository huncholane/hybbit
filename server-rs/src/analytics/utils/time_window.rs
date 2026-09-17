//! Port of server/src/api/analytics/utils/timeWindow.ts: resolve a request's
//! date range, datetime range or past-minutes window once, then render the
//! `WHERE` predicate, the bucket expression and the `WITH FILL` clause from it.
//!
//! No Luxon here: date-range bounds stay symbolic (midnight in the Site's zone is
//! resolved by ClickHouse), datetime bounds go through `Date.parse` and
//! `toISOString`, and past-minutes bounds are `Date.now()` arithmetic.

use std::time::{SystemTime, UNIX_EPOCH};

use tracing::debug;

use crate::analytics::{
    js::{JsObject, JsValue, date, intl},
    sql_string::{escape, escape_string},
    types::TimeBucket,
};

/// `TimeBucketToFn`.
pub fn time_bucket_fn(bucket: TimeBucket) -> &'static str {
    match bucket {
        TimeBucket::Minute => "toStartOfMinute",
        TimeBucket::FiveMinutes => "toStartOfFiveMinutes",
        TimeBucket::TenMinutes => "toStartOfTenMinutes",
        TimeBucket::FifteenMinutes => "toStartOfFifteenMinutes",
        TimeBucket::Hour => "toStartOfHour",
        TimeBucket::Day => "toStartOfDay",
        TimeBucket::Week => "toStartOfWeek",
        TimeBucket::Month => "toStartOfMonth",
        TimeBucket::Year => "toStartOfYear",
    }
}

/// `bucketIntervalMap`.
pub fn bucket_interval(bucket: TimeBucket) -> &'static str {
    match bucket {
        TimeBucket::Minute => "1 MINUTE",
        TimeBucket::FiveMinutes => "5 MINUTES",
        TimeBucket::TenMinutes => "10 MINUTES",
        TimeBucket::FifteenMinutes => "15 MINUTES",
        TimeBucket::Hour => "1 HOUR",
        TimeBucket::Day => "1 DAY",
        TimeBucket::Week => "7 DAY",
        TimeBucket::Month => "1 MONTH",
        TimeBucket::Year => "1 YEAR",
    }
}

/// JavaScript's `RangeError: Invalid time value` from `toISOString` on an
/// invalid date. Node's routes answer it with a 500.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("Invalid time value")]
pub struct RangeError;

fn is_digits(bytes: &[u8]) -> bool {
    bytes.iter().all(u8::is_ascii_digit)
}

/// `dateRegex`: `^\d{4}-\d{2}-\d{2}$`.
pub fn is_date_format(value: &str) -> bool {
    let b = value.as_bytes();
    b.len() == 10 && is_digits(&b[0..4]) && b[4] == b'-' && is_digits(&b[5..7]) && b[7] == b'-' && is_digits(&b[8..10])
}

/// `dateTimeRegex`: `^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(Z|[+-]\d{2}:?\d{2})?$`.
pub fn is_date_time_format(value: &str) -> bool {
    let b = value.as_bytes();
    if b.len() < 19
        || !is_date_format(&value[..10])
        || !(b[10] == b' ' || b[10] == b'T')
        || !is_digits(&b[11..13])
        || b[13] != b':'
        || !is_digits(&b[14..16])
        || b[16] != b':'
        || !is_digits(&b[17..19])
    {
        return false;
    }
    let zone = &b[19..];
    match zone.len() {
        0 => true,
        1 => zone[0] == b'Z',
        5 => matches!(zone[0], b'+' | b'-') && is_digits(&zone[1..5]),
        6 => matches!(zone[0], b'+' | b'-') && is_digits(&zone[1..3]) && zone[3] == b':' && is_digits(&zone[4..6]),
        _ => false,
    }
}

/// `/(?:Z|[+-]\d{2}:?\d{2})$/.test(value)`.
fn has_zone_suffix(value: &str) -> bool {
    let b = value.as_bytes();
    let n = b.len();
    if b.last() == Some(&b'Z') {
        return true;
    }
    let signed_at = |position: usize| matches!(b[position], b'+' | b'-');
    (n >= 5 && signed_at(n - 5) && is_digits(&b[n - 4..]))
        || (n >= 6 && signed_at(n - 6) && is_digits(&b[n - 5..n - 3]) && b[n - 3] == b':' && is_digits(&b[n - 2..]))
}

/// `value.includes("T") ? value : value.replace(" ", "T")`, then a `Z` unless a
/// zone is already there.
fn with_utc_zone(value: &str) -> String {
    let normalized = if value.contains('T') { value.to_string() } else { value.replacen(' ', "T", 1) };
    if has_zone_suffix(&normalized) { normalized } else { format!("{normalized}Z") }
}

/// `parseDateTimeMs`.
pub fn parse_date_time_ms(value: &str) -> f64 {
    date::parse(&with_utc_zone(value))
}

/// `toClickhouseInstant`: `toISOString().slice(0, 19).replace("T", " ")`.
fn to_clickhouse_instant(ms: f64) -> Result<String, RangeError> {
    let iso = date::to_iso_string(ms).ok_or(RangeError)?;
    let prefix: String = iso.chars().take(19).collect();
    Ok(prefix.replacen('T', " ", 1))
}

/// `normalizeDatetimeForClickhouse`: the instant's plain UTC rendering.
pub fn normalize_datetime_for_clickhouse(value: &str) -> Result<String, RangeError> {
    to_clickhouse_instant(date::parse(&with_utc_zone(value)))
}

/// `isValidTimeZone(tz)`: `Intl.DateTimeFormat` stringifies the option, and an
/// undefined zone means the default one.
pub fn is_valid_time_zone_value(time_zone: &JsValue) -> bool {
    match time_zone {
        JsValue::Undefined => true,
        other => intl::is_valid_time_zone(&other.to_js_string()),
    }
}

/// `isValidTimeZone` for a string.
pub fn is_valid_time_zone(time_zone: &str) -> bool {
    intl::is_valid_time_zone(time_zone)
}

/// `TimeWindowParams`: raw request values, `Undefined` when absent. Query-string
/// values are strings or arrays of strings; body-derived ones may be numbers.
#[derive(Clone, Debug, PartialEq)]
pub struct TimeWindowParams {
    pub start_date: JsValue,
    pub end_date: JsValue,
    pub time_zone: JsValue,
    pub start_datetime: JsValue,
    pub end_datetime: JsValue,
    pub past_minutes_start: JsValue,
    pub past_minutes_end: JsValue,
}

impl Default for TimeWindowParams {
    fn default() -> Self {
        Self {
            start_date: JsValue::Undefined,
            end_date: JsValue::Undefined,
            time_zone: JsValue::Undefined,
            start_datetime: JsValue::Undefined,
            end_datetime: JsValue::Undefined,
            past_minutes_start: JsValue::Undefined,
            past_minutes_end: JsValue::Undefined,
        }
    }
}

impl TimeWindowParams {
    /// Picks the seven time params off a request query (or any params object).
    pub fn from_object(object: &JsObject) -> Self {
        let field = |name: &str| object.get_or_undefined(name).clone();
        Self {
            start_date: field("start_date"),
            end_date: field("end_date"),
            time_zone: field("time_zone"),
            start_datetime: field("start_datetime"),
            end_datetime: field("end_datetime"),
            past_minutes_start: field("past_minutes_start"),
            past_minutes_end: field("past_minutes_end"),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
enum ResolvedWindow {
    All,
    Date { start_date: String, end_date: String, time_zone: JsValue },
    DateTime { start: String, end: String, time_zone: JsValue },
    PastMinutes { start: String, end: String, time_zone: JsValue },
}

/// `dateSchema.safeParse`.
fn valid_date(value: &JsValue) -> Option<&str> {
    let text = value.as_str()?;
    (is_date_format(text) && !date::parse(text).is_nan()).then_some(text)
}

/// `dateTimeSchema.safeParse`.
fn valid_date_time(value: &JsValue) -> Option<&str> {
    let text = value.as_str()?;
    (is_date_time_format(text) && !parse_date_time_ms(text).is_nan()).then_some(text)
}

/// `minutesSchema.safeParse`: string or number, `Number()`-ed, non-negative.
fn valid_minutes(value: &JsValue) -> Option<f64> {
    let number = match value {
        JsValue::String(_) => value.to_number(),
        JsValue::Number(number) if !number.is_nan() => *number,
        _ => return None,
    };
    (!number.is_nan() && number >= 0.0).then_some(number)
}

fn resolve(params: &TimeWindowParams, now_ms: impl FnOnce() -> f64) -> Result<ResolvedWindow, RangeError> {
    let time_zone = if params.time_zone.is_truthy() { params.time_zone.clone() } else { JsValue::from("UTC") };
    if !is_valid_time_zone_value(&time_zone) {
        return Ok(ResolvedWindow::All);
    }

    if params.start_date.is_truthy()
        && params.end_date.is_truthy()
        && let (Some(start_date), Some(end_date)) = (valid_date(&params.start_date), valid_date(&params.end_date))
    {
        return Ok(ResolvedWindow::Date { start_date: start_date.to_string(), end_date: end_date.to_string(), time_zone });
    }

    if params.start_datetime.is_truthy()
        && params.end_datetime.is_truthy()
        && let (Some(start), Some(end)) = (valid_date_time(&params.start_datetime), valid_date_time(&params.end_datetime))
        && parse_date_time_ms(start) < parse_date_time_ms(end)
    {
        return Ok(ResolvedWindow::DateTime {
            start: normalize_datetime_for_clickhouse(start)?,
            end: normalize_datetime_for_clickhouse(end)?,
            time_zone,
        });
    }

    if !params.past_minutes_start.is_undefined()
        && !params.past_minutes_end.is_undefined()
        && let (Some(start), Some(end)) = (valid_minutes(&params.past_minutes_start), valid_minutes(&params.past_minutes_end))
        && start > end
    {
        let now = now_ms();
        return Ok(ResolvedWindow::PastMinutes {
            start: to_clickhouse_instant(now - start * 60.0 * 1000.0)?,
            end: to_clickhouse_instant(now - end * 60.0 * 1000.0)?,
            time_zone,
        });
    }

    Ok(ResolvedWindow::All)
}

/// `truncate`: `toDateTime(<fn>(toTimeZone(expression, tz)))`.
fn truncate(expression: &str, bucket: TimeBucket, time_zone: &JsValue) -> String {
    format!("toDateTime({}(toTimeZone({expression}, {})))", time_bucket_fn(bucket), escape(time_zone))
}

/// `alignInstant`.
fn align_instant(instant: &str, bucket: TimeBucket, time_zone: &JsValue) -> String {
    truncate(&format!("toDateTime({}, 'UTC')", escape_string(instant)), bucket, time_zone)
}

fn where_clause(window: &ResolvedWindow, column: &str) -> String {
    match window {
        ResolvedWindow::All => String::new(),
        ResolvedWindow::Date { start_date, end_date, time_zone } => {
            let tz = escape(time_zone);
            let start = escape_string(start_date);
            let end = escape_string(end_date);
            format!(
                "AND {column} >= toTimeZone(
      toStartOfDay(toDateTime({start}, {tz})),
      'UTC'
      )
      AND if(
        toDate({end}) = toDate(now(), {tz}),
        {column} <= toTimeZone(now64(3), 'UTC'),
        {column} < toTimeZone(
          toStartOfDay(toDateTime({end}, {tz})) + INTERVAL 1 DAY,
          'UTC'
        )
      )"
            )
        }
        ResolvedWindow::DateTime { start, end, .. } => format!(
            "AND {column} >= toDateTime({}, 'UTC')
      AND {column} < toDateTime({}, 'UTC')",
            escape_string(start),
            escape_string(end)
        ),
        ResolvedWindow::PastMinutes { start, end, .. } => format!(
            "AND {column} > toDateTime({}, 'UTC') AND {column} <= toDateTime({}, 'UTC')",
            escape_string(start),
            escape_string(end)
        ),
    }
}

fn fill_clause(window: &ResolvedWindow, bucket: TimeBucket) -> String {
    let step = bucket_interval(bucket);
    match window {
        ResolvedWindow::All => String::new(),
        ResolvedWindow::Date { start_date, end_date, time_zone } => {
            let tz = escape(time_zone);
            let midnight = |date: &str| truncate(&format!("toDateTime({}, {tz})", escape_string(date)), bucket, time_zone);
            format!(
                "WITH FILL FROM toTimeZone({}, 'UTC')
      TO if(
        toDate({}) = toDate(now(), {tz}),
        toTimeZone(now(), 'UTC'),
        toTimeZone({} + INTERVAL 1 DAY, 'UTC')
      ) STEP INTERVAL {step}",
                midnight(start_date),
                escape_string(end_date),
                midnight(end_date)
            )
        }
        ResolvedWindow::DateTime { start, end, time_zone } | ResolvedWindow::PastMinutes { start, end, time_zone } => {
            let from = align_instant(start, bucket, time_zone);
            let end_instant = format!("toDateTime({}, 'UTC')", escape_string(end));
            let aligned_end = align_instant(end, bucket, time_zone);
            let to = format!("if({aligned_end} = {end_instant}, {aligned_end}, {aligned_end} + INTERVAL {step})");
            format!("WITH FILL FROM {from} TO {to} STEP INTERVAL {step}")
        }
    }
}

/// A resolved window, ready to render either SQL fragment (`TimeWindow`).
#[derive(Clone, Debug, PartialEq)]
pub struct TimeWindow {
    window: ResolvedWindow,
    /// The zone an all-time window still buckets in
    bucket_time_zone: JsValue,
}

impl TimeWindow {
    /// True when the request named no usable window.
    pub fn is_all_time(&self) -> bool {
        self.window == ResolvedWindow::All
    }

    /// `where(column)`: the `AND ...` predicate bounding `column`, or "".
    pub fn where_clause(&self, column: &str) -> String {
        where_clause(&self.window, column)
    }

    /// `where()` on the default `timestamp` column.
    pub fn where_timestamp(&self) -> String {
        self.where_clause("timestamp")
    }

    /// `bucketed(column, bucket)`.
    pub fn bucketed(&self, column: &str, bucket: TimeBucket) -> String {
        let time_zone = if is_valid_time_zone_value(&self.bucket_time_zone) {
            self.bucket_time_zone.clone()
        } else {
            JsValue::from("UTC")
        };
        truncate(column, bucket, &time_zone)
    }

    /// `fill(bucket)`: the `WITH FILL` clause, or "" for an all-time window.
    pub fn fill(&self, bucket: TimeBucket) -> String {
        fill_clause(&self.window, bucket)
    }
}

/// `Date.now()`.
pub fn now_ms() -> f64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|elapsed| elapsed.as_millis() as f64).unwrap_or(0.0)
}

/// `resolveTimeWindow(params)`, reading the clock only for a past-minutes window.
pub fn resolve_time_window(params: &TimeWindowParams) -> Result<TimeWindow, RangeError> {
    resolve_time_window_with_clock(params, now_ms)
}

/// `resolveTimeWindow` with an injected clock (for tests and replays).
pub fn resolve_time_window_with_clock(
    params: &TimeWindowParams,
    now: impl FnOnce() -> f64,
) -> Result<TimeWindow, RangeError> {
    let window = resolve(params, now).inspect_err(|_| debug!("time window bound is not a valid date"))?;
    let bucket_time_zone = match &window {
        ResolvedWindow::All => {
            if params.time_zone.is_truthy() {
                params.time_zone.clone()
            } else {
                JsValue::from("UTC")
            }
        }
        ResolvedWindow::Date { time_zone, .. }
        | ResolvedWindow::DateTime { time_zone, .. }
        | ResolvedWindow::PastMinutes { time_zone, .. } => time_zone.clone(),
    };
    Ok(TimeWindow { window, bucket_time_zone })
}

/// `getTimeStatement(params, column)`.
pub fn get_time_statement(params: &TimeWindowParams, column: &str) -> Result<String, RangeError> {
    Ok(resolve_time_window(params)?.where_clause(column))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn normalize(sql: &str) -> String {
        sql.split_whitespace().collect::<Vec<_>>().join(" ")
    }

    fn params(pairs: &[(&str, JsValue)]) -> TimeWindowParams {
        TimeWindowParams::from_object(&pairs.iter().map(|(key, value)| (key.to_string(), value.clone())).collect())
    }

    fn s(text: &str) -> JsValue {
        JsValue::from(text)
    }

    fn n(number: f64) -> JsValue {
        JsValue::Number(number)
    }

    fn date_range() -> Vec<(&'static str, JsValue)> {
        vec![("start_date", s("2024-01-01")), ("end_date", s("2024-01-31")), ("time_zone", s("America/New_York"))]
    }

    fn datetime_range() -> Vec<(&'static str, JsValue)> {
        vec![("start_datetime", s("2024-01-01 05:30:00")), ("end_datetime", s("2024-01-02 06:45:00"))]
    }

    fn past_minutes() -> Vec<(&'static str, JsValue)> {
        vec![("past_minutes_start", n(120.0)), ("past_minutes_end", n(0.0))]
    }

    fn get_time(pairs: &[(&str, JsValue)]) -> String {
        get_time_statement(&params(pairs), "timestamp").unwrap()
    }

    fn get_time_at(pairs: &[(&str, JsValue)], now: &str, column: &str) -> String {
        let now = date::parse(now);
        resolve_time_window_with_clock(&params(pairs), || now).unwrap().where_clause(column)
    }

    fn fill_of(pairs: &[(&str, JsValue)], bucket: TimeBucket) -> String {
        normalize(&resolve_time_window(&params(pairs)).unwrap().fill(bucket))
    }

    fn fill_at(pairs: &[(&str, JsValue)], now: &str, bucket: TimeBucket) -> String {
        let now = date::parse(now);
        normalize(&resolve_time_window_with_clock(&params(pairs), || now).unwrap().fill(bucket))
    }

    fn bucketed_of(pairs: &[(&str, JsValue)], column: &str, bucket: TimeBucket) -> String {
        normalize(&resolve_time_window(&params(pairs)).unwrap().bucketed(column, bucket))
    }

    fn with(mut base: Vec<(&'static str, JsValue)>, extra: &[(&'static str, JsValue)]) -> Vec<(&'static str, JsValue)> {
        for (key, value) in extra {
            base.retain(|(existing, _)| existing != key);
            base.push((key, value.clone()));
        }
        base
    }

    // Ported from timeWindow.test.ts: where()
    #[test]
    fn where_date_range() {
        assert_eq!(
            normalize(&get_time(&date_range())),
            normalize(
                "AND timestamp >= toTimeZone(
          toStartOfDay(toDateTime('2024-01-01', 'America/New_York')),
          'UTC'
          )
          AND if(
            toDate('2024-01-31') = toDate(now(), 'America/New_York'),
            timestamp <= toTimeZone(now64(3), 'UTC'),
            timestamp < toTimeZone(
              toStartOfDay(toDateTime('2024-01-31', 'America/New_York')) + INTERVAL 1 DAY,
              'UTC'
            )
          )"
            )
        );
        let result = get_time(&[("start_date", s("2024-01-01")), ("end_date", s("2024-01-31"))]);
        assert!(result.contains("toDateTime('2024-01-01', 'UTC')") && result.contains("toDateTime('2024-01-31', 'UTC')"));
        let result = normalize(&get_time(&[("start_date", s("2024-06-15")), ("end_date", s("2024-06-15")), ("time_zone", s("UTC"))]));
        assert!(result.contains("toDate('2024-06-15') = toDate(now(), 'UTC')"));
        assert!(result.contains("timestamp <= toTimeZone(now64(3), 'UTC')"));
        assert!(result.contains("timestamp < toTimeZone( toStartOfDay(toDateTime('2024-06-15', 'UTC')) + INTERVAL 1 DAY, 'UTC' )"));

        let mut all = vec![("start_date", s("2024-01-01")), ("end_date", s("2024-01-31")), ("time_zone", s("UTC"))];
        all.extend(datetime_range());
        all.extend(past_minutes());
        let result = get_time(&all);
        assert!(result.contains("toStartOfDay(toDateTime('2024-01-01', 'UTC'))") && !result.contains("2024-01-02"));

        let mut malformed = vec![("start_date", s("01/01/2024")), ("end_date", s("2024-01-31"))];
        malformed.extend(datetime_range());
        assert_eq!(
            normalize(&get_time(&malformed)),
            "AND timestamp >= toDateTime('2024-01-01 05:30:00', 'UTC') AND timestamp < toDateTime('2024-01-02 06:45:00', 'UTC')"
        );
        assert_eq!(get_time(&[("start_date", s("01/01/2024")), ("end_date", s("2024-01-31")), ("time_zone", s("UTC"))]), "");
    }

    #[test]
    fn where_datetime_range() {
        assert_eq!(
            normalize(&get_time(&[("start_datetime", s("2024-01-01 00:00:00")), ("end_datetime", s("2024-01-02 12:30:00"))])),
            "AND timestamp >= toDateTime('2024-01-01 00:00:00', 'UTC') AND timestamp < toDateTime('2024-01-02 12:30:00', 'UTC')"
        );
        assert_eq!(
            normalize(&get_time(&[
                ("start_datetime", s("2024-01-01T05:00:00+02:00")),
                ("end_datetime", s("2024-01-02T05:00:00+02:00"))
            ])),
            "AND timestamp >= toDateTime('2024-01-01 03:00:00', 'UTC') AND timestamp < toDateTime('2024-01-02 03:00:00', 'UTC')"
        );
        assert_eq!(get_time(&[("start_datetime", s("2024-01-02 00:00:00")), ("end_datetime", s("2024-01-01 00:00:00"))]), "");
        assert_eq!(get_time(&[("start_datetime", s("2024-01-01 00:00:00")), ("end_datetime", s("2024-01-01 00:00:00"))]), "");
    }

    #[test]
    fn where_past_minutes() {
        let now = "2024-06-15T12:00:00Z";
        assert_eq!(
            get_time_at(&[("past_minutes_start", n(60.0)), ("past_minutes_end", n(0.0))], now, "timestamp"),
            "AND timestamp > toDateTime('2024-06-15 11:00:00', 'UTC') AND timestamp <= toDateTime('2024-06-15 12:00:00', 'UTC')"
        );
        assert_eq!(
            get_time_at(&[("past_minutes_start", s("30")), ("past_minutes_end", s("0"))], now, "timestamp"),
            "AND timestamp > toDateTime('2024-06-15 11:30:00', 'UTC') AND timestamp <= toDateTime('2024-06-15 12:00:00', 'UTC')"
        );
        assert_eq!(get_time_at(&[("past_minutes_start", n(0.0)), ("past_minutes_end", n(60.0))], now, "timestamp"), "");
        assert_eq!(get_time_at(&[("past_minutes_start", n(30.0)), ("past_minutes_end", n(30.0))], now, "timestamp"), "");
        assert_eq!(get_time_at(&[("past_minutes_start", n(60.0))], now, "timestamp"), "");
        assert!(!resolve_time_window(&params(&past_minutes())).unwrap().is_all_time());
        assert_ne!(get_time(&past_minutes()), "");
    }

    #[test]
    fn where_column_and_empty() {
        assert!(get_time_statement(&params(&date_range()), "start_time").unwrap().contains("AND start_time >="));
        assert!(!get_time_statement(&params(&date_range()), "start_time").unwrap().contains("timestamp"));
        assert!(get_time_statement(&params(&past_minutes()), "event_hour").unwrap().contains("AND event_hour >"));
        assert!(get_time_statement(&params(&datetime_range()), "session_hour").unwrap().contains("AND session_hour >="));
        assert!(get_time(&date_range()).contains("AND timestamp >="));
        assert_eq!(get_time(&[]), "");
        assert_eq!(get_time(&[("start_date", s("2024-01-01")), ("time_zone", s("UTC"))]), "");
        assert_eq!(get_time(&[("end_date", s("2024-01-31")), ("time_zone", s("UTC"))]), "");
        let bad_zone = [("time_zone", s("Not/AZone"))];
        assert_eq!(get_time(&with(date_range(), &bad_zone)), "");
        assert_eq!(get_time(&with(datetime_range(), &bad_zone)), "");
        assert_eq!(get_time(&with(past_minutes(), &bad_zone)), "");
    }

    #[test]
    fn fill_date_and_datetime() {
        assert_eq!(
            fill_of(&date_range(), TimeBucket::Day),
            "WITH FILL FROM toTimeZone(toDateTime(toStartOfDay(toTimeZone(toDateTime('2024-01-01', 'America/New_York'), \
             'America/New_York'))), 'UTC') TO if( toDate('2024-01-31') = toDate(now(), 'America/New_York'), toTimeZone(now(), 'UTC'), \
             toTimeZone(toDateTime(toStartOfDay(toTimeZone(toDateTime('2024-01-31', 'America/New_York'), \
             'America/New_York'))) + INTERVAL 1 DAY, 'UTC') ) STEP INTERVAL 1 DAY"
        );
        assert!(
            fill_of(&[("start_date", s("2024-01-01")), ("end_date", s("2024-01-31"))], TimeBucket::Day)
                .contains("toDateTime('2024-01-01', 'UTC')")
        );
        let aligned_end = "toDateTime(toStartOfHour(toTimeZone(toDateTime('2024-01-02 06:45:00', 'UTC'), 'UTC')))";
        assert_eq!(
            fill_of(&with(datetime_range(), &[("time_zone", s("UTC"))]), TimeBucket::Hour),
            format!(
                "WITH FILL FROM toDateTime(toStartOfHour(toTimeZone(toDateTime('2024-01-01 05:30:00', 'UTC'), 'UTC'))) \
                 TO if({aligned_end} = toDateTime('2024-01-02 06:45:00', 'UTC'), {aligned_end}, {aligned_end} + INTERVAL 1 HOUR) \
                 STEP INTERVAL 1 HOUR"
            )
        );
        let result = fill_of(
            &[("start_datetime", s("2024-01-01T05:30:00Z")), ("end_datetime", s("2024-01-02T06:45:00+02:00"))],
            TimeBucket::Hour,
        );
        assert!(result.contains("'2024-01-01 05:30:00'") && result.contains("'2024-01-02 04:45:00'"));
        assert!(!result.contains("Z'") && !result.contains("+02:00"));
        let result = fill_of(&[("start_datetime", s("2024-01-01 10:30:00")), ("end_datetime", s("2024-01-01 14:45:00"))], TimeBucket::Hour);
        assert!(result.contains("+ INTERVAL 1 HOUR)") && result.contains("'2024-01-01 14:45:00'"));
        assert!(
            fill_of(&[("start_datetime", s("2024-01-01 00:00:00")), ("end_datetime", s("2024-01-01 04:00:00"))], TimeBucket::Hour)
                .contains("TO if(")
        );
    }

    #[test]
    fn fill_past_minutes() {
        let now = "2024-06-15T12:34:00Z";
        let aligned_end = "toDateTime(toStartOfHour(toTimeZone(toDateTime('2024-06-15 12:34:00', 'UTC'), 'UTC')))";
        assert_eq!(
            fill_at(&past_minutes(), now, TimeBucket::Hour),
            format!(
                "WITH FILL FROM toDateTime(toStartOfHour(toTimeZone(toDateTime('2024-06-15 10:34:00', 'UTC'), 'UTC'))) \
                 TO if({aligned_end} = toDateTime('2024-06-15 12:34:00', 'UTC'), {aligned_end}, {aligned_end} + INTERVAL 1 HOUR) \
                 STEP INTERVAL 1 HOUR"
            )
        );
        assert!(
            fill_at(&with(past_minutes(), &[("time_zone", s("Asia/Kolkata"))]), now, TimeBucket::Hour)
                .contains("toDateTime(toStartOfHour(toTimeZone(toDateTime('2024-06-15 10:34:00', 'UTC'), 'Asia/Kolkata')))")
        );
        assert!(fill_at(&past_minutes(), now, TimeBucket::FiveMinutes).contains("+ INTERVAL 5 MINUTES) STEP INTERVAL 5 MINUTES"));
        let clock = date::parse(now);
        let window = resolve_time_window_with_clock(&params(&past_minutes()), || clock).unwrap();
        assert!(window.where_timestamp().contains("2024-06-15 12:34:00"));
        assert!(window.fill(TimeBucket::Hour).contains("2024-06-15 12:34:00"));
    }

    #[test]
    fn fill_buckets_and_all_time() {
        for bucket in TimeBucket::ALL {
            let result = fill_of(&date_range(), bucket);
            assert!(result.contains(time_bucket_fn(bucket)));
            assert!(result.contains(&format!("STEP INTERVAL {}", bucket_interval(bucket))));
        }
        assert_eq!(fill_of(&[], TimeBucket::Day), "");
        assert_eq!(fill_of(&[("start_date", s("2024-01-01"))], TimeBucket::Day), "");
        assert_eq!(fill_of(&[("past_minutes_start", n(0.0)), ("past_minutes_end", n(60.0))], TimeBucket::Hour), "");
    }

    #[test]
    fn bucketed_cases() {
        assert_eq!(bucketed_of(&date_range(), "timestamp", TimeBucket::Hour), "toDateTime(toStartOfHour(toTimeZone(timestamp, 'America/New_York')))");
        for column in ["timestamp", "start_time", "event_hour", "session_hour", "session_start"] {
            assert!(bucketed_of(&date_range(), column, TimeBucket::Day).contains(&format!("toTimeZone({column}, 'America/New_York')")));
        }
        for bucket in TimeBucket::ALL {
            assert!(bucketed_of(&date_range(), "timestamp", bucket).starts_with("toDateTime("));
            assert!(fill_of(&date_range(), bucket).contains(&format!("toDateTime({}(", time_bucket_fn(bucket))));
        }
        let window = resolve_time_window(&params(&[("time_zone", s("Asia/Kolkata"))])).unwrap();
        assert!(window.is_all_time());
        assert!(window.bucketed("timestamp", TimeBucket::Day).contains("'Asia/Kolkata'"));
        assert!(bucketed_of(&[("time_zone", s("Not/AZone"))], "timestamp", TimeBucket::Day).contains("toTimeZone(timestamp, 'UTC')"));
    }

    #[test]
    fn is_all_time_agrees_with_fragments() {
        let cases: Vec<Vec<(&str, JsValue)>> = vec![
            vec![],
            date_range(),
            datetime_range(),
            past_minutes(),
            vec![("start_date", s("2024-01-01"))],
            vec![("end_date", s("2024-01-31"))],
            vec![("start_datetime", s("2024-01-01 00:00:00"))],
            vec![("past_minutes_start", n(60.0))],
            vec![("past_minutes_start", n(0.0)), ("past_minutes_end", n(60.0))],
            vec![("start_date", s("01/01/2024")), ("end_date", s("2024-01-31"))],
            with(date_range(), &[("time_zone", s("Not/AZone"))]),
        ];
        for case in cases {
            let window = resolve_time_window(&params(&case)).unwrap();
            assert_eq!(window.is_all_time(), window.where_timestamp().is_empty());
            assert_eq!(window.is_all_time(), window.fill(TimeBucket::Hour).is_empty());
        }
    }

    #[test]
    fn normalize_datetime_cases() {
        assert_eq!(normalize_datetime_for_clickhouse("2024-01-15T10:30:00Z").unwrap(), "2024-01-15 10:30:00");
        assert_eq!(normalize_datetime_for_clickhouse("2024-01-15T10:30:00+02:00").unwrap(), "2024-01-15 08:30:00");
        assert_eq!(normalize_datetime_for_clickhouse("2024-01-15T10:30:00-05:00").unwrap(), "2024-01-15 15:30:00");
        assert_eq!(normalize_datetime_for_clickhouse("2024-01-15T10:30:00").unwrap(), "2024-01-15 10:30:00");
        assert_eq!(normalize_datetime_for_clickhouse("2024-01-15 10:30:00").unwrap(), "2024-01-15 10:30:00");
        assert_eq!(normalize_datetime_for_clickhouse("2024-01-15 10:30:00+02:00").unwrap(), "2024-01-15 08:30:00");
        assert_eq!(normalize_datetime_for_clickhouse("2024-01-15").unwrap(), "2024-01-15 00:00:00");
        assert_eq!(normalize_datetime_for_clickhouse("2024-01-15T10:30:00.999Z").unwrap(), "2024-01-15 10:30:00");
        assert_eq!(normalize_datetime_for_clickhouse("not-a-date"), Err(RangeError));
    }

    #[test]
    fn sql_injection_cases() {
        assert_eq!(get_time(&[("start_date", s("2024-01-01'; DROP TABLE events;--")), ("end_date", s("2024-01-31"))]), "");
        assert_eq!(
            get_time(&[("start_datetime", s("2024-01-01 00:00:00' OR '1'='1")), ("end_datetime", s("2024-01-02 00:00:00"))]),
            ""
        );
        assert_eq!(get_time(&[("past_minutes_start", s("60; DROP TABLE events")), ("past_minutes_end", n(0.0))]), "");
        let injected = [("time_zone", s("UTC'; DROP TABLE events;--"))];
        assert_eq!(get_time(&with(date_range(), &injected)), "");
        assert_eq!(fill_of(&with(date_range(), &injected), TimeBucket::Day), "");
    }
}
