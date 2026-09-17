//! Time zone validation as `Intl.DateTimeFormat(undefined, { timeZone })`
//! performs it in V8 13.6 (`JSDateTimeFormat::CreateTimeZone`).
//!
//! V8 accepts two shapes. An offset (`+05`, `-0530`, `−` `05:30`) is
//! checked syntactically. Anything else goes through
//! `CanonicalizeTimeZoneID`, which only upper-cases, title-cases or maps the
//! ASCII letters of the input before ICU looks the ID up, so a name is valid
//! exactly when its ASCII upper-casing equals that of an ICU zone ID other than
//! `Etc/Unknown` and `Factory`. `js/zone_ids.rs` holds that list.

#[path = "zone_ids.rs"]
mod zone_ids;

use zone_ids::UPPERCASE_ZONE_IDS;

/// V8 `GetOffsetTimeZone`: `[+-−]hh(:?mm)?` with hh 00-23 and mm 00-59.
fn is_offset_time_zone(units: &[u16]) -> bool {
    if units.len() < 3 || !matches!(units[0], 0x2B | 0x2D | 0x2212) {
        return false;
    }
    let digit = |unit: u16, lo: u8, hi: u8| (lo as u16..=hi as u16).contains(&unit);
    let (h0, h1) = (units[1], units[2]);
    if !((digit(h0, b'0', b'1') && digit(h1, b'0', b'9')) || (h0 == b'2' as u16 && digit(h1, b'0', b'3'))) {
        return false;
    }
    if units.len() == 3 {
        return true;
    }
    let mut p = 3;
    if units[p] == b':' as u16 {
        p += 1;
        if units.len() == p {
            return false;
        }
    }
    if units.len() - p != 2 {
        return false;
    }
    digit(units[p], b'0', b'5') && digit(units[p + 1], b'0', b'9')
}

/// `isValidTimeZone` in timeWindow.ts: whether `Intl.DateTimeFormat` accepts
/// the value's string form.
pub fn is_valid_time_zone(time_zone: &str) -> bool {
    let units: Vec<u16> = time_zone.encode_utf16().collect();
    if is_offset_time_zone(&units) {
        return true;
    }
    let upper = time_zone.to_ascii_uppercase();
    UPPERCASE_ZONE_IDS.binary_search(&upper.as_str()).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_what_v8_accepts() {
        for zone in [
            "UTC", "utc", "Etc/UTC", "GMT", "america/new_york", "AMERICA/NEW_YORK", "America/Port-au-Prince",
            "antarctica/dumontdurville", "EST", "PST8PDT", "Etc/GMT+5", "GMT+0", "GMT0", "+01:00", "+0100", "+01",
            "-00:00", "+23:59", "\u{2212}05:30", "SystemV/AST4", "US/Pacific-New", "Asia/Calcutta", "IST", "Europe/Kyiv",
            "europe/istanbul",
        ] {
            assert!(is_valid_time_zone(zone), "{zone:?}");
        }
        for zone in [
            "Etc/Unknown", "Etc/GMT+15", "+24:00", "+01:00:00", "Z", "", " UTC", "UTC ", "posix/America/New_York", "Factory",
            "localtime", "Europe/İstanbul", "Not/AZone", "UTC\0",
        ] {
            assert!(!is_valid_time_zone(zone), "{zone:?}");
        }
    }
}
