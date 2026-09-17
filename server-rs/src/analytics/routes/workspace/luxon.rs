//! The Luxon 3.7.2 arithmetic GET /annotations uses to turn its day bounds into
//! instants: `DateTime.fromISO(date, { zone }).startOf("day")`, optionally
//! `.plus({ days: 1 }).startOf("day")`, then `.toUTC().toISO()`.
//!
//! Luxon asks `Intl.DateTimeFormat` for a zone's offset one second at a time and
//! guesses local times with `fixOffset`; this port asks chrono-tz for the same
//! offsets and repeats Luxon's steps with the same floating-point operations, so
//! daylight-saving gaps and overlaps land on the instant Node computes. Zones
//! chrono-tz does not know (ICU-only aliases such as `US/Pacific-New`) fall back
//! to UTC with a warning.

use chrono::{DateTime, Offset, TimeZone, Utc};
use chrono_tz::Tz;
use tracing::warn;

use super::annotation_schema::{civil_from_days, days_from_civil};

const MS_PER_MINUTE: f64 = 60_000.0;
const MS_PER_DAY: f64 = 86_400_000.0;
/// ECMAScript's time value range, in milliseconds either side of the epoch
const MAX_TIME_MS: f64 = 8.64e15;

/// A zone as Luxon's `normalizeZone` resolves the query's `time_zone`.
#[derive(Clone, Debug)]
pub enum Zone {
    /// `FixedOffsetZone`: "utc"/"gmt" in any case, or a V8 offset identifier
    Fixed(f64),
    Iana(Tz),
}

impl Zone {
    /// The zone for a `time_zone` value that already passed `isValidTimeZone`.
    pub fn resolve(name: &str) -> Zone {
        let lowered = name.to_lowercase();
        if lowered == "utc" || lowered == "gmt" {
            return Zone::Fixed(0.0);
        }
        if let Some(minutes) = offset_identifier_minutes(name) {
            return Zone::Fixed(minutes);
        }
        match Tz::from_str_insensitive(name) {
            Ok(tz) => Zone::Iana(tz),
            Err(_) => {
                warn!(time_zone = name, "Time zone unknown to chrono-tz; using UTC for annotation bounds");
                Zone::Fixed(0.0)
            }
        }
    }

    /// `zone.offset(ts)` in minutes (NaN for an invalid time).
    fn offset(&self, ts: f64) -> f64 {
        match self {
            Zone::Fixed(minutes) => *minutes,
            Zone::Iana(tz) => {
                let date = time_clip(ts);
                if date.is_nan() {
                    return f64::NAN;
                }
                // Intl formats whole seconds: the offset is measured at the second's start
                let seconds = (date / 1000.0).floor() as i64;
                let Some(instant) = DateTime::<Utc>::from_timestamp(seconds, 0) else { return f64::NAN };
                let offset_seconds = tz.offset_from_utc_datetime(&instant.naive_utc()).fix().local_minus_utc();
                (offset_seconds as f64 * 1000.0) / MS_PER_MINUTE
            }
        }
    }
}

/// V8's offset time zone identifier, `[+-\u{2212}]hh(:?mm)?`, as minutes east of UTC.
fn offset_identifier_minutes(name: &str) -> Option<f64> {
    let mut chars = name.chars();
    let sign = match chars.next()? {
        '+' => 1.0,
        '-' | '\u{2212}' => -1.0,
        _ => return None,
    };
    let rest: String = chars.collect();
    let digits: String = rest.chars().filter(|c| *c != ':').collect();
    if !digits.chars().all(|c| c.is_ascii_digit()) || !(digits.len() == 2 || digits.len() == 4) {
        return None;
    }
    let hours: f64 = digits[0..2].parse().ok()?;
    let minutes: f64 = if digits.len() == 4 { digits[2..4].parse().ok()? } else { 0.0 };
    Some(sign * (hours * 60.0 + minutes))
}

/// `TimeClip`: truncate toward zero, NaN outside the representable range.
fn time_clip(time: f64) -> f64 {
    if time.is_finite() && time.abs() <= MAX_TIME_MS { time.trunc() + 0.0 } else { f64::NAN }
}

/// Luxon's calendar object.
#[derive(Clone, Copy, Debug, PartialEq)]
struct Civil {
    year: f64,
    month: f64,
    day: f64,
    hour: f64,
    minute: f64,
    second: f64,
    millisecond: f64,
}

/// `objToLocalTS`: `Date.UTC` of the fields, with years 0 to 99 kept as written.
fn obj_to_local_ts(civil: &Civil) -> f64 {
    let month_zero = civil.month - 1.0;
    let year = civil.year + (month_zero / 12.0).floor();
    let month = month_zero.rem_euclid(12.0) + 1.0;
    let days = days_from_civil(year as i64, month as i64, 1) as f64 + civil.day - 1.0;
    let time = civil.hour * 3_600_000.0 + civil.minute * MS_PER_MINUTE + civil.second * 1000.0 + civil.millisecond;
    time_clip(days * MS_PER_DAY + time)
}

/// `tsToObj`
fn ts_to_obj(ts: f64, offset: f64) -> Option<Civil> {
    let date = time_clip(ts + offset * 60.0 * 1000.0);
    if date.is_nan() {
        return None;
    }
    let days = (date / MS_PER_DAY).floor();
    let in_day = date - days * MS_PER_DAY;
    let (year, month, day) = civil_from_days(days as i64);
    Some(Civil {
        year: year as f64,
        month: month as f64,
        day: day as f64,
        hour: (in_day / 3_600_000.0).floor(),
        minute: (in_day / MS_PER_MINUTE).floor() % 60.0,
        second: (in_day / 1000.0).floor() % 60.0,
        millisecond: in_day % 1000.0,
    })
}

/// `fixOffset(localTS, o, tz)`
fn fix_offset(local_ts: f64, guess: f64, zone: &Zone) -> (f64, f64) {
    let mut utc_guess = local_ts - guess * 60.0 * 1000.0;
    let o2 = zone.offset(utc_guess);
    if guess == o2 {
        return (utc_guess, guess);
    }
    utc_guess -= (o2 - guess) * 60.0 * 1000.0;
    let o3 = zone.offset(utc_guess);
    if o2 == o3 {
        return (utc_guess, o2);
    }
    (local_ts - o2.min(o3) * 60.0 * 1000.0, o2.max(o3))
}

/// A valid Luxon `DateTime`: its instant, offset and calendar fields.
struct LuxonDateTime<'a> {
    ts: f64,
    o: f64,
    c: Civil,
    zone: &'a Zone,
}

impl<'a> LuxonDateTime<'a> {
    /// `new DateTime({ ts, zone, o })` outside `clone`: the offset is trusted.
    fn with_offset(ts: f64, o: f64, zone: &'a Zone) -> Option<LuxonDateTime<'a>> {
        Some(LuxonDateTime { ts, o, c: ts_to_obj(ts, o)?, zone })
    }

    /// `clone(this, { ts, o })`: the constructor keeps the old fields for an
    /// unchanged instant and otherwise ignores the passed offset and re-reads the
    /// zone's offset at the new instant.
    fn clone_at(&self, ts: f64) -> Option<LuxonDateTime<'a>> {
        if ts == self.ts {
            return Some(LuxonDateTime { ts, o: self.o, c: self.c, zone: self.zone });
        }
        let offset = self.zone.offset(ts);
        Some(LuxonDateTime { ts, o: offset, c: ts_to_obj(ts, offset)?, zone: self.zone })
    }

    /// `startOf("day")` through `set({ hour: 0, minute: 0, second: 0, millisecond: 0 })`
    fn start_of_day(&self) -> Option<LuxonDateTime<'a>> {
        let mixed = Civil { hour: 0.0, minute: 0.0, second: 0.0, millisecond: 0.0, ..self.c };
        let (ts, _) = fix_offset(obj_to_local_ts(&mixed), self.o, self.zone);
        self.clone_at(ts)
    }

    /// `plus({ days })` through `adjustTime`
    fn plus_days(&self, days: f64) -> Option<LuxonDateTime<'a>> {
        let c = Civil { day: self.c.day + days, ..self.c };
        let (ts, _) = fix_offset(obj_to_local_ts(&c), self.o, self.zone);
        self.clone_at(ts)
    }

    /// `toUTC().toISO()`
    fn to_utc_iso(&self) -> Option<String> {
        let c = ts_to_obj(self.ts, 0.0)?;
        let year = c.year as i64;
        let year_text = if (0..=9999).contains(&year) {
            format!("{year:04}")
        } else if year < 0 {
            format!("-{:06}", -year)
        } else {
            format!("+{year:06}")
        };
        Some(format!(
            "{year_text}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
            c.month as i64, c.day as i64, c.hour as i64, c.minute as i64, c.second as i64, c.millisecond as i64
        ))
    }
}

/// `DateTime.fromISO(date, { zone })`, for a `YYYY-MM-DD` that is a real date.
fn from_iso_date<'a>(date: &str, zone: &'a Zone, now_ms: f64) -> Option<LuxonDateTime<'a>> {
    let year: f64 = date.get(0..4)?.parse().ok()?;
    let month: f64 = date.get(5..7)?.parse().ok()?;
    let day: f64 = date.get(8..10)?.parse().ok()?;
    let civil = Civil { year, month, day, hour: 0.0, minute: 0.0, second: 0.0, millisecond: 0.0 };
    let provisional = zone.offset(now_ms);
    let (ts, offset) = fix_offset(obj_to_local_ts(&civil), provisional, zone);
    LuxonDateTime::with_offset(ts, offset, zone)
}

/// `DateTime.fromISO(date, { zone }).startOf("day").toUTC().toISO()`
pub fn day_start_iso(date: &str, zone: &Zone, now_ms: f64) -> Option<String> {
    from_iso_date(date, zone, now_ms)?.start_of_day()?.to_utc_iso()
}

/// `DateTime.fromISO(date, { zone }).plus({ days: 1 }).startOf("day").toUTC().toISO()`
pub fn next_day_start_iso(date: &str, zone: &Zone, now_ms: f64) -> Option<String> {
    from_iso_date(date, zone, now_ms)?.plus_days(1.0)?.start_of_day()?.to_utc_iso()
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: f64 = 1_789_632_000_000.0; // 2026-09-17T08:00:00Z

    fn bounds(date: &str, zone: &str) -> (String, String) {
        let zone = Zone::resolve(zone);
        (day_start_iso(date, &zone, NOW).unwrap(), next_day_start_iso(date, &zone, NOW).unwrap())
    }

    #[test]
    fn day_bounds_match_luxon() {
        // DateTime.fromISO(d, { zone }).startOf("day").toUTC().toISO() and the plus({ days: 1 }) twin
        assert_eq!(bounds("2026-08-01", "UTC"), ("2026-08-01T00:00:00.000Z".into(), "2026-08-02T00:00:00.000Z".into()));
        assert_eq!(
            bounds("2026-08-01", "America/New_York"),
            ("2026-08-01T04:00:00.000Z".into(), "2026-08-02T04:00:00.000Z".into())
        );
        assert_eq!(
            bounds("2026-03-08", "america/new_york"),
            ("2026-03-08T05:00:00.000Z".into(), "2026-03-09T04:00:00.000Z".into())
        );
        assert_eq!(bounds("2026-08-31", "+05:30"), ("2026-08-30T18:30:00.000Z".into(), "2026-08-31T18:30:00.000Z".into()));
        assert_eq!(bounds("2026-12-31", "Pacific/Kiritimati"), ("2026-12-30T10:00:00.000Z".into(), "2026-12-31T10:00:00.000Z".into()));
    }
}
