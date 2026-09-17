//! ASN lookups that read the IP string exactly the way Node's `lookupAsn`
//! (server/src/db/geolocation/asn.ts) does.
//!
//! Node's reader (`@maxmind/geoip2-node` 6.1.0 over `mmdb-lib` 2.2.1) gates the
//! string with `net.isIP` and then parses it with mmdb-lib's own parser, which
//! is looser than `std::net`: an IPv6 zone id (`2a06:98c0::1%eth0`) passes the
//! gate and is then mostly ignored. `crate::geo::Geo::asn` instead trims the
//! string and uses `std::net` parsing, so for a spoofed forwarding header the two
//! backends could disagree on whether the visitor is datacenter egress, and
//! therefore on the user id. Identity routes lookups through this module so the
//! ids match; the tree walk itself is still `AsnLookup`'s.
//!
//! Everything below mirrors the JavaScript, number quirks included: mmdb-lib
//! stores `parseInt(chunk, 16) >> 8` and `& 0xff`, so only the low 16 bits of
//! JavaScript's ToInt32 of the parsed double survive.

use std::{net::Ipv6Addr, sync::LazyLock};

use regex::Regex;

use crate::geo::AsnLookup;

/// Node's `IPv4Reg` (lib/internal/net.js, Node 26).
static NODE_IPV4: LazyLock<Regex> = LazyLock::new(|| {
    let v4_seg = "(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])";
    Regex::new(&format!(r"^(?:{v4_seg}\.){{3}}{v4_seg}$")).expect("IPv4Reg compiles")
});

/// Node's `IPv6Reg` (lib/internal/net.js, Node 26), built from the same pieces.
static NODE_IPV6: LazyLock<Regex> = LazyLock::new(|| {
    let v4_seg = "(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])";
    let v4 = format!(r"(?:{v4_seg}\.){{3}}{v4_seg}");
    let v6 = "(?:[0-9a-fA-F]{1,4})";
    let pattern = [
        "^(?:".to_string(),
        format!("(?:{v6}:){{7}}(?:{v6}|:)|"),
        format!("(?:{v6}:){{6}}(?:{v4}|:{v6}|:)|"),
        format!("(?:{v6}:){{5}}(?::{v4}|(?::{v6}){{1,2}}|:)|"),
        format!("(?:{v6}:){{4}}(?:(?::{v6}){{0,1}}:{v4}|(?::{v6}){{1,3}}|:)|"),
        format!("(?:{v6}:){{3}}(?:(?::{v6}){{0,2}}:{v4}|(?::{v6}){{1,4}}|:)|"),
        format!("(?:{v6}:){{2}}(?:(?::{v6}){{0,3}}:{v4}|(?::{v6}){{1,5}}|:)|"),
        format!("(?:{v6}:){{1}}(?:(?::{v6}){{0,4}}:{v4}|(?::{v6}){{1,6}}|:)|"),
        format!("(?::(?:(?::{v6}){{0,5}}:{v4}|(?::{v6}){{1,7}}|:))"),
        r")(?:%[0-9a-zA-Z.:\-]{1,})?$".to_string(),
    ]
    .concat();
    Regex::new(&pattern).expect("IPv6Reg compiles")
});

/// mmdb-lib's IPv4-in-IPv6 rewrite, `/(\d+)\.(\d+)\.(\d+)\.(\d+)/` (ASCII digits).
static DOTTED_QUAD: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9]+)").expect("dotted quad compiles"));

/// `net.isIP`: 4, 6 or 0.
pub fn node_is_ip(input: &str) -> u8 {
    if NODE_IPV4.is_match(input) {
        4
    } else if NODE_IPV6.is_match(input) {
        6
    } else {
        0
    }
}

/// `lookupAsn(ip)?.asn`, resolved through the request's memoised `AsnLookup`.
pub fn lookup_asn_like_node(lookup: &AsnLookup<'_>, ip: &str) -> Option<u32> {
    if ip.is_empty() {
        return None;
    }
    match node_is_ip(ip) {
        // A string that passes IPv4Reg is canonical dotted decimal, which std parses alike
        4 => lookup.lookup(ip).map(|info| info.asn),
        6 => {
            let address = Ipv6Addr::from(mmdb_lib_parse_ipv6(ip));
            lookup.lookup(&address.to_string()).map(|info| info.asn)
        }
        _ => None,
    }
}

/// mmdb-lib `parseIPv6`, reduced to the 16 bytes the tree walk reads.
pub(crate) fn mmdb_lib_parse_ipv6(input: &str) -> [u8; 16] {
    let mut address = [0u8; 16];

    let rewritten = if input.contains('.') {
        match DOTTED_QUAD.captures(input) {
            Some(captures) => {
                let whole = captures.get(0).expect("group 0");
                let replacement = format!(
                    "{}{}:{}{}",
                    mmdb_hex(&captures[1]),
                    mmdb_hex(&captures[2]),
                    mmdb_hex(&captures[3]),
                    mmdb_hex(&captures[4])
                );
                format!("{}{}{}", &input[..whole.start()], replacement, &input[whole.end()..])
            }
            None => input.to_string(),
        }
    } else {
        input.to_string()
    };

    // `ip.split('::', 2)`: the text before the first `::` and between the first and second
    let mut halves = rewritten.split("::");
    let left = halves.next().unwrap_or_default();
    let right = halves.next();

    if !left.is_empty() {
        for (index, chunk) in left.split(':').enumerate() {
            let value = js_parse_int_hex_low16(chunk);
            // Writes past the 16th byte only lengthen the JS array; the walk ends first
            if index * 2 + 1 < 16 {
                address[index * 2] = (value >> 8) as u8;
                address[index * 2 + 1] = value as u8;
            }
        }
    }

    if let Some(right) = right.filter(|right| !right.is_empty()) {
        let chunks: Vec<&str> = right.split(':').collect();
        let offset = 16 - chunks.len() as i64 * 2;
        for (index, chunk) in chunks.iter().enumerate() {
            let value = js_parse_int_hex_low16(chunk);
            let high = offset + index as i64 * 2;
            // Negative indices become plain properties on the JS array
            if high >= 0 {
                address[high as usize] = (value >> 8) as u8;
            }
            if high + 1 >= 0 {
                address[(high + 1) as usize] = value as u8;
            }
        }
    }

    address
}

/// mmdb-lib's `hex(v)`: `parseInt(v, 10).toString(16)`, zero-prefixed unless it
/// is exactly two characters long.
fn mmdb_hex(digits: &str) -> String {
    let hex = js_decimal_digits_to_hex(digits);
    if hex.len() == 2 { hex } else { format!("0{hex}") }
}

/// `parseInt(digits, 10).toString(16)` for a run of ASCII digits: the double
/// nearest the decimal value, printed exactly in hex ("Infinity" past 2^1024).
fn js_decimal_digits_to_hex(digits: &str) -> String {
    let trimmed = digits.trim_start_matches('0');
    if trimmed.is_empty() {
        return "0".to_string();
    }
    if trimmed.len() <= 15 {
        // Below 2^53: exact
        return format!("{:x}", trimmed.parse::<u64>().expect("15 digits fit"));
    }

    let double: f64 = trimmed.parse().expect("ASCII digits parse");
    if double.is_infinite() {
        return "Infinity".to_string();
    }
    let (mantissa, exponent) = integer_parts(double);
    if exponent <= 0 {
        return format!("{:x}", mantissa >> (-exponent));
    }
    // mantissa * 2^exponent with the exponent aligned to a hex digit boundary
    let shift = exponent % 4;
    format!("{:x}{}", mantissa << shift, "0".repeat(((exponent - shift) / 4) as usize))
}

/// A finite, non-negative double as `mantissa * 2^exponent`.
fn integer_parts(double: f64) -> (u64, i64) {
    let bits = double.to_bits();
    let raw_exponent = ((bits >> 52) & 0x7ff) as i64;
    let fraction = bits & ((1u64 << 52) - 1);
    if raw_exponent == 0 { (fraction, -1074) } else { (fraction | (1u64 << 52), raw_exponent - 1075) }
}

/// `parseInt(text, 16)` as mmdb-lib consumes it: `>> 8` and `& 0xff` of ToInt32,
/// then read bit by bit, so the low 16 bits of ToInt32 of the double. NaN (no
/// digits) and anything at or beyond 2^1024 read as 0.
pub(crate) fn js_parse_int_hex_low16(text: &str) -> u16 {
    let (negative, unsigned) = match text.as_bytes().first() {
        Some(b'-') => (true, &text[1..]),
        Some(b'+') => (false, &text[1..]),
        _ => (false, text),
    };
    let body = unsigned.strip_prefix("0x").or_else(|| unsigned.strip_prefix("0X")).unwrap_or(unsigned);
    let digit_count = body.bytes().take_while(u8::is_ascii_hexdigit).count();
    let significant = body[..digit_count].trim_start_matches('0');

    let low = if significant.len() > 32 {
        // At least 2^128: the rounded double's low 76+ bits are zero (or it is Infinity)
        0
    } else {
        let value = if significant.is_empty() { 0 } else { u128::from_str_radix(significant, 16).expect("hex digits") };
        if value < (1u128 << 53) {
            value as u16
        } else {
            // V8 rounds power-of-two radixes to nearest, ties to even, like `as f64`
            let (mantissa, exponent) = integer_parts(value as f64);
            if exponent >= 16 { 0 } else { ((mantissa << exponent) & 0xffff) as u16 }
        }
    };

    if negative { low.wrapping_neg() } else { low }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gates_like_net_is_ip() {
        assert_eq!(node_is_ip("1.2.3.4"), 4);
        assert_eq!(node_is_ip("01.2.3.4"), 0);
        assert_eq!(node_is_ip(" 1.2.3.4"), 0);
        assert_eq!(node_is_ip("2a06:98c0:3600::103%eth0"), 6);
        assert_eq!(node_is_ip("::ffff:1.2.3.4"), 6);
        assert_eq!(node_is_ip("1:2:3:4:5:6:7::"), 6);
        assert_eq!(node_is_ip("fe80::1%"), 0);
        assert_eq!(node_is_ip(""), 0);
    }

    #[test]
    fn parses_like_mmdb_lib() {
        let parse = |text: &str| Ipv6Addr::from(mmdb_lib_parse_ipv6(text));
        assert_eq!(parse("2a06:98c0:3600::103%eth0"), "2a06:98c0:3600::103".parse::<Ipv6Addr>().unwrap());
        assert_eq!(parse("::ffff:1.2.3.4"), "::ffff:1.2.3.4".parse::<Ipv6Addr>().unwrap());
        // The IPv4 rewrite runs on the first dotted quad anywhere, zone included
        assert_eq!(parse("fe80::1%1.2.3.4"), "fe80::1:304".parse::<Ipv6Addr>().unwrap());
    }

    #[test]
    fn parse_int_keeps_the_low_16_bits_of_to_int32() {
        assert_eq!(js_parse_int_hex_low16("103%eth0"), 0x103);
        assert_eq!(js_parse_int_hex_low16(""), 0);
        assert_eq!(js_parse_int_hex_low16("zz"), 0);
        assert_eq!(js_parse_int_hex_low16("-1"), 0xffff);
        assert_eq!(js_parse_int_hex_low16("0x1f"), 0x1f);
        assert_eq!(js_parse_int_hex_low16("123456789"), 0x6789);
        // 2^53 + 1 rounds to 2^53 (ties to even)
        assert_eq!(js_parse_int_hex_low16("20000000000001"), 0);
        assert_eq!(js_decimal_digits_to_hex("1234"), "4d2");
        assert_eq!(js_decimal_digits_to_hex("0000"), "0");
        assert_eq!(js_decimal_digits_to_hex("100000000000000000000"), "56bc75e2d63100000");
    }
}
