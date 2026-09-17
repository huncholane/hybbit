//! Replay clock skew correction, ported from server/src/services/replay/replayClockSkew.ts.
//!
//! Replay event timestamps come from the browser, so they carry whatever the
//! device's clock says; a few devices are years out, which lands rows in far-future
//! partitions that never expire. rrweb reconstructs playback from the gaps between
//! timestamps, so a skewed batch is shifted by one offset (keeping every gap)
//! rather than pinned to now.

/// A day of tolerance absorbs ordinary drift and timezone-confused devices.
pub const MAX_FUTURE_SKEW_MS: f64 = 24.0 * 60.0 * 60.0 * 1000.0;
/// Matches the replay TTL: anything older is already unreadable.
pub const MAX_PAST_SKEW_MS: f64 = 30.0 * 24.0 * 60.0 * 60.0 * 1000.0;

/// `sanitize`: non-finite timestamps take the bound they were heading for, NaN
/// (no ordering at all) takes now.
fn sanitize(timestamp: f64, now_ms: f64, lower_bound: f64, upper_bound: f64) -> f64 {
    if timestamp.is_finite() {
        timestamp
    } else if timestamp == f64::INFINITY {
        upper_bound
    } else if timestamp == f64::NEG_INFINITY {
        lower_bound
    } else {
        now_ms
    }
}

fn median(values: &[f64]) -> f64 {
    let mut sorted = values.to_vec();
    // Array.prototype.sort with (a, b) => a - b; sanitized values are never NaN
    sorted.sort_by(|a, b| a.total_cmp(b));
    let mid = sorted.len() / 2;
    if sorted.len() % 2 == 0 { (sorted[mid - 1] + sorted[mid]) / 2.0 } else { sorted[mid] }
}

/// `correctReplayClockSkew`: the corrected timestamps (in input order) and the
/// detected skew in ms, 0 when nothing needed shifting. `None` means the batch was
/// healthy and every timestamp stays exactly as received.
pub fn correct_replay_clock_skew(timestamps: &[f64], now_ms: f64) -> (Option<Vec<f64>>, f64) {
    if timestamps.is_empty() {
        return (None, 0.0);
    }

    let upper_bound = now_ms + MAX_FUTURE_SKEW_MS;
    let lower_bound = now_ms - MAX_PAST_SKEW_MS;

    let sanitized: Vec<f64> = timestamps
        .iter()
        .map(|timestamp| sanitize(*timestamp, now_ms, lower_bound, upper_bound))
        .collect();
    // The median, not the max, so one corrupt timestamp cannot drag a healthy batch
    let anchor = median(&sanitized);

    let skew_ms = if anchor > upper_bound || anchor < lower_bound { anchor - now_ms } else { 0.0 };

    let all_finite = timestamps.iter().all(|timestamp| timestamp.is_finite());
    if skew_ms == 0.0 && all_finite && sanitized.iter().all(|t| *t <= upper_bound && *t >= lower_bound) {
        return (None, 0.0);
    }

    let corrected = sanitized
        .iter()
        .map(|timestamp| (timestamp - skew_ms).max(lower_bound).min(upper_bound))
        .collect();
    (Some(corrected), skew_ms)
}

#[cfg(test)]
mod tests {
    use chrono::{TimeZone, Utc};

    use super::*;

    fn utc(year: i32, month0: u32, day: u32, hour: u32, minute: u32, second: u32) -> f64 {
        Utc.with_ymd_and_hms(year, month0 + 1, day, hour, minute, second).unwrap().timestamp_millis() as f64
    }

    fn now() -> f64 {
        utc(2026, 7, 19, 12, 0, 0)
    }

    fn apply(timestamps: &[f64]) -> (Vec<f64>, f64) {
        let (corrected, skew) = correct_replay_clock_skew(timestamps, now());
        (corrected.unwrap_or_else(|| timestamps.to_vec()), skew)
    }

    #[test]
    fn leaves_a_healthy_batch_untouched() {
        let (corrected, skew) = correct_replay_clock_skew(&[now() - 3000.0, now() - 2000.0, now() - 1000.0], now());
        assert_eq!(skew, 0.0);
        assert!(corrected.is_none());
    }

    #[test]
    fn shifts_a_batch_from_a_device_decades_ahead() {
        let year2090 = utc(2090, 6, 2, 21, 31, 45);
        let (events, skew) = apply(&[year2090, year2090 + 1000.0, year2090 + 5000.0]);
        assert!(skew > 0.0);
        for timestamp in events {
            assert!(timestamp <= now() + MAX_FUTURE_SKEW_MS);
            assert!(timestamp >= now() - MAX_PAST_SKEW_MS);
        }
    }

    #[test]
    fn preserves_gaps_between_events() {
        let year2076 = utc(2076, 1, 3, 12, 56, 50);
        let gaps = [0.0, 250.0, 1750.0, 187_000.0];
        let (events, _) = apply(&gaps.map(|gap| year2076 + gap));
        let shifted: Vec<f64> = events.iter().map(|timestamp| timestamp - events[0]).collect();
        assert_eq!(shifted, gaps);
    }

    #[test]
    fn is_not_dragged_off_by_a_single_corrupt_timestamp() {
        let (events, skew) = apply(&[now() - 3000.0, now() - 2000.0, now() - 1000.0, utc(2064, 0, 5, 0, 0, 0)]);
        assert_eq!(skew, 0.0);
        assert_eq!(&events[..3], &[now() - 3000.0, now() - 2000.0, now() - 1000.0]);
        assert_eq!(events[3], now() + MAX_FUTURE_SKEW_MS);
    }

    #[test]
    fn pulls_forward_a_batch_older_than_the_ttl() {
        let ancient = now() - MAX_PAST_SKEW_MS - 90.0 * 24.0 * 60.0 * 60.0 * 1000.0;
        let (events, skew) = apply(&[ancient, ancient + 1000.0]);
        assert!(skew < 0.0);
        assert!(events[0] >= now() - MAX_PAST_SKEW_MS);
    }

    #[test]
    fn handles_an_empty_batch() {
        assert_eq!(correct_replay_clock_skew(&[], now()), (None, 0.0));
    }

    #[test]
    fn clamps_non_finite_timestamps() {
        assert_eq!(apply(&[f64::INFINITY]).0, vec![now() + MAX_FUTURE_SKEW_MS]);
        assert!(apply(&[f64::INFINITY]).1.is_finite());
        assert_eq!(apply(&[f64::NEG_INFINITY]).0, vec![now() - MAX_PAST_SKEW_MS]);
        assert_eq!(
            apply(&[now(), now() + 100.0, f64::INFINITY, now() + 300.0]).0,
            vec![now(), now() + 100.0, now() + MAX_FUTURE_SKEW_MS, now() + 300.0]
        );
        assert_eq!(apply(&[f64::NAN]).0, vec![now()]);
    }
}
