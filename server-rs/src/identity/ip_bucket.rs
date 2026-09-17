//! Coarse IP buckets for identity hashing, ported from
//! server/src/services/userId/identityIpBucket.ts.
//!
//! Node builds the bucket with the `ip-address` package (10.2.0):
//! `new Address6(`${ip}/48`).startAddress().correctForm()` and the `Address4`
//! equivalent for `/24`. The bucket string is hashed into the user id, so this is
//! a port of that package's parsing and formatting rather than a use of
//! `std::net`: `ip-address` accepts inputs the standard library rejects (IPv4
//! octets with leading zeros such as `01.2.3.4`, zone ids, a stray `/64` inside an
//! IPv6 string) and rejects some it accepts (`::ffff:01.2.3.4`), and every one of
//! those decides whether the visitor hashes a bucket or the raw string.

/// `bucketIpForIdentity`: the IP string to feed into the anonymous user id hash.
///
/// Visitors whose egress sits in a hosting or datacenter ASN (corporate proxies,
/// Cloudflare WARP, iCloud Private Relay, VPNs) rotate IPs between requests, so
/// hashing the exact IP mints a new "user" mid-session. Those hash a /24 (IPv4)
/// or /48 (IPv6) instead, trading splitting for merging. Residential IPs, empty
/// strings and anything `ip-address` cannot parse come back unchanged.
///
/// Identity only: geolocation, IP exclusion and storage keep the exact IP.
pub fn bucket_ip_for_identity(ip: &str, is_datacenter_egress: impl FnOnce(&str) -> bool) -> String {
    if ip.is_empty() || !is_datacenter_egress(ip) {
        return ip.to_string();
    }

    let bucket = if ip.contains(':') {
        address6_start_correct_form(&format!("{ip}/48")).map(|start| format!("{start}/48"))
    } else {
        address4_start_correct_form(&format!("{ip}/24")).map(|start| format!("{start}/24"))
    };

    match bucket {
        Some(bucket) => bucket,
        None => {
            tracing::debug!(ip_len = ip.len(), "Identity IP bucket unparseable, hashing the raw IP");
            ip.to_string()
        }
    }
}

// ---------------------------------------------------------------------------
// Address4

/// `new Address4(input).startAddress().correctForm()`, or None where the
/// constructor (or the BigInt conversion behind `startAddress`) throws.
fn address4_start_correct_form(input: &str) -> Option<String> {
    let (address, mask) = address4_split_subnet(input)?;
    let octets = parse_address4(address)?;
    let value = u32::from_be_bytes(octets);
    let start = if mask == 0 { 0 } else { value & (u32::MAX << (32 - mask)) };
    let [a, b, c, d] = start.to_be_bytes();
    Some(format!("{a}.{b}.{c}.{d}"))
}

/// `RE_SUBNET_STRING = /\/\d{1,2}$/`: the mask and the address without it.
/// Masks above 32 throw ("Invalid subnet mask.").
fn address4_split_subnet(input: &str) -> Option<(&str, u32)> {
    let bytes = input.as_bytes();
    let digits = bytes.iter().rev().take_while(|b| b.is_ascii_digit()).count();
    if (1..=2).contains(&digits) && bytes.len() > digits && bytes[bytes.len() - digits - 1] == b'/' {
        let split = bytes.len() - digits - 1;
        let mask: u32 = input[split + 1..].parse().ok()?;
        if mask > 32 {
            return None;
        }
        return Some((&input[..split], mask));
    }
    Some((input, 32))
}

/// `Address4.parse`: `RE_ADDRESS`, four dot-separated octets of `25[0-5]`,
/// `2[0-4][0-9]` or `[01]?[0-9][0-9]?`. That is one to three ASCII digits worth at
/// most 255, leading zeros allowed (`correctForm` strips them).
fn parse_address4(address: &str) -> Option<[u8; 4]> {
    let mut octets = [0u8; 4];
    let mut parts = address.split('.');
    for octet in octets.iter_mut() {
        *octet = parse_address4_octet(parts.next()?)?;
    }
    parts.next().is_none().then_some(octets)
}

fn parse_address4_octet(part: &str) -> Option<u8> {
    if !(1..=3).contains(&part.len()) || !part.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    part.parse::<u16>().ok().and_then(|value| u8::try_from(value).ok())
}

// ---------------------------------------------------------------------------
// Address6

/// `new Address6(input).startAddress().correctForm()`, or None where the
/// constructor throws or `startAddress` does (a group that `parseInt` could not
/// read becomes the string "NaN", which `BigInt()` rejects).
fn address6_start_correct_form(input: &str) -> Option<String> {
    let (address, mask) = address6_split_subnet(input)?;
    let address = strip_zone(&address);
    let groups = parse_address6(address)?;

    let mut value: u128 = 0;
    for group in groups {
        value = (value << 16) | u128::from(group?);
    }
    let start = if mask == 0 { 0 } else { value & (u128::MAX << (128 - mask)) };

    let start_groups: [u16; 8] = std::array::from_fn(|index| (start >> (16 * (7 - index))) as u16);
    Some(correct_form6(&start_groups))
}

/// `RE_SUBNET_STRING = /\/\d{1,3}(?=%|$)/`, first match: a slash, one to three
/// ASCII digits (a longer run never matches, since the lookahead sees a digit),
/// then `%` or the end of the string. The match is removed from the address.
/// Masks above 128 throw; a slash with no match throws too.
fn address6_split_subnet(input: &str) -> Option<(String, u32)> {
    let bytes = input.as_bytes();
    for (slash, _) in input.match_indices('/') {
        let digits = bytes[slash + 1..].iter().take_while(|b| b.is_ascii_digit()).count();
        let after = slash + 1 + digits;
        if (1..=3).contains(&digits) && (after == bytes.len() || bytes[after] == b'%') {
            let mask: u32 = input[slash + 1..after].parse().ok()?;
            if mask > 128 {
                return None;
            }
            let mut address = String::with_capacity(input.len());
            address.push_str(&input[..slash]);
            address.push_str(&input[after..]);
            return Some((address, mask));
        }
    }
    if input.contains('/') {
        return None;
    }
    Some((input.to_string(), 128))
}

/// `RE_ZONE_STRING = /%.*$/`: from the first `%` that has no JavaScript line
/// terminator after it to the end. A line terminator left behind is a bad
/// character later, so the address is rejected either way.
fn strip_zone(address: &str) -> &str {
    for (percent, _) in address.match_indices('%') {
        let rest = &address[percent..];
        if !rest.chars().any(|c| matches!(c, '\n' | '\r' | '\u{2028}' | '\u{2029}')) {
            return &address[..percent];
        }
    }
    address
}

/// `Address6.parse`: eight groups, each `None` where JavaScript's
/// `parseInt(group, 16)` yields NaN.
fn parse_address6(address: &str) -> Option<Vec<Option<u16>>> {
    let address = parse_4in6(address)?;

    // RE_BAD_CHARACTERS = /([^0-9a-f:/%])/gi
    if !address.bytes().all(|b| b.is_ascii_hexdigit() || matches!(b, b':' | b'/' | b'%')) {
        return None;
    }

    // RE_BAD_ADDRESS = /([0-9a-f]{5,}|:{3,}|[^:]:$|^:[^:]|\/$)/gi
    let bytes = address.as_bytes();
    if longest_run(bytes, |b| b.is_ascii_hexdigit()) >= 5
        || longest_run(bytes, |b| b == b':') >= 3
        || (bytes.len() >= 2 && bytes[bytes.len() - 1] == b':' && bytes[bytes.len() - 2] != b':')
        || (bytes.len() >= 2 && bytes[0] == b':' && bytes[1] != b':')
        || bytes.last() == Some(&b'/')
    {
        return None;
    }

    let halves: Vec<&str> = address.split("::").collect();
    let groups: Vec<&str> = match halves.as_slice() {
        [first, last] => {
            let first = split_groups(first);
            let last = split_groups(last);
            let remaining = 8 - (first.len() as i64 + last.len() as i64);
            if remaining == 0 {
                return None;
            }
            let mut groups = first;
            groups.extend(std::iter::repeat_n("0", remaining.max(0) as usize));
            groups.extend(last);
            groups
        }
        [single] => single.split(':').collect(),
        _ => return None,
    };

    if groups.len() != 8 {
        return None;
    }
    Some(groups.into_iter().map(parse_int_hex).collect())
}

/// `halves[i].split(':')`, with `['']` turned into `[]`.
fn split_groups(half: &str) -> Vec<&str> {
    if half.is_empty() { Vec::new() } else { half.split(':').collect() }
}

/// `Address6.parse4in6`: when the address has a dot and its last colon-separated
/// group is a dotted IPv4 address, that group becomes two hex groups. Octets with
/// a leading zero followed by more digits throw.
fn parse_4in6(address: &str) -> Option<String> {
    if !address.contains('.') {
        return Some(address.to_string());
    }

    let (prefix, last) = match address.rfind(':') {
        Some(colon) => (&address[..=colon], &address[colon + 1..]),
        None => ("", address),
    };
    let Some(octets) = parse_address4(last) else {
        return Some(address.to_string());
    };

    let has_leading_zero = last.split('.').any(|octet| octet.len() >= 2 && octet.starts_with('0'));
    if has_leading_zero {
        return None;
    }

    let [a, b, c, d] = octets;
    Some(format!("{prefix}{a:02x}{b:02x}:{c:02x}{d:02x}"))
}

/// JavaScript `parseInt(group, 16)` for the characters that survive the bad
/// character check (`[0-9a-fA-F/%]`): the leading hex digits, or NaN when there
/// are none. The bad address check caps the run at four digits.
fn parse_int_hex(group: &str) -> Option<u16> {
    let digits = group.bytes().take_while(|b| b.is_ascii_hexdigit()).count();
    if digits == 0 {
        return None;
    }
    u16::from_str_radix(&group[..digits], 16).ok()
}

fn longest_run(bytes: &[u8], predicate: impl Fn(u8) -> bool) -> usize {
    let mut longest = 0;
    let mut current = 0;
    for &byte in bytes {
        if predicate(byte) {
            current += 1;
            longest = longest.max(current);
        } else {
            current = 0;
        }
    }
    longest
}

/// `Address6.correctForm`: lowercase hex without leading zeros, the longest run
/// of two or more zero groups (the first one on a tie) compressed to `::`.
fn correct_form6(groups: &[u16; 8]) -> String {
    let mut zeroes: Vec<(usize, usize)> = Vec::new();
    let mut zero_counter = 0;
    for (index, &group) in groups.iter().enumerate() {
        if group == 0 {
            zero_counter += 1;
        }
        if group != 0 && zero_counter > 0 {
            if zero_counter > 1 {
                zeroes.push((index - zero_counter, index - 1));
            }
            zero_counter = 0;
        }
    }
    if zero_counter > 1 {
        zeroes.push((groups.len() - zero_counter, groups.len() - 1));
    }

    let hex = |group: &u16| format!("{group:x}");
    let Some(&(start, end)) = zeroes
        .iter()
        .reduce(|best, candidate| if candidate.1 - candidate.0 > best.1 - best.0 { candidate } else { best })
    else {
        return groups.iter().map(hex).collect::<Vec<_>>().join(":");
    };

    let left = groups[..start].iter().map(hex).collect::<Vec<_>>().join(":");
    let right = groups[end + 1..].iter().map(hex).collect::<Vec<_>>().join(":");
    format!("{left}::{right}")
}

#[cfg(test)]
mod tests {
    //! Port of server/src/services/userId/identityIpBucket.test.ts, plus the
    //! `ip-address` quirks the bucket inherits.

    use super::bucket_ip_for_identity;

    fn datacenter(ip: &str) -> String {
        bucket_ip_for_identity(ip, |_| true)
    }

    #[test]
    fn returns_residential_ips_unchanged() {
        assert_eq!(bucket_ip_for_identity("203.0.113.55", |_| false), "203.0.113.55");
    }

    #[test]
    fn buckets_rotating_datacenter_egress_into_the_same_24() {
        assert_eq!(datacenter("172.68.34.28"), "172.68.34.0/24");
        assert_eq!(datacenter("172.68.34.29"), "172.68.34.0/24");
    }

    #[test]
    fn buckets_ipv6_datacenter_egress_into_the_same_48() {
        assert_eq!(datacenter("2a06:98c0:3600:0:1:2:3:4"), "2a06:98c0:3600::/48");
        assert_eq!(datacenter("2a06:98c0:3600:ffff::1"), "2a06:98c0:3600::/48");
    }

    #[test]
    fn returns_unparseable_input_unchanged() {
        assert_eq!(datacenter("not-an-ip"), "not-an-ip");
        assert_eq!(datacenter(""), "");
    }

    #[test]
    fn never_asks_about_an_empty_ip() {
        assert_eq!(bucket_ip_for_identity("", |_| panic!("must not look up an empty IP")), "");
    }

    #[test]
    fn follows_ip_address_parsing_quirks() {
        // Leading zeros are fine in a bare IPv4 address and stripped
        assert_eq!(datacenter("010.001.002.003"), "10.1.2.0/24");
        assert_eq!(datacenter("1.2.3.256"), "1.2.3.256");
        // but not inside IPv6
        assert_eq!(datacenter("::ffff:01.2.3.4"), "::ffff:01.2.3.4");
        // Mapped IPv4 keeps only the /48 prefix, which is all zero
        assert_eq!(datacenter("::ffff:1.2.3.4"), "::/48");
        // Zone ids are dropped, and a slash inside the address is read past
        assert_eq!(datacenter("2a06:98c0:3600::1%eth0"), "2a06:98c0:3600::/48");
        assert_eq!(datacenter("2001:db8:1:2::1/64"), "2001:db8:1::/48");
        // An earlier /mask before a zone wins over the appended /48
        assert_eq!(datacenter("2001:db8:ffff::1/16%eth0"), "2001::/48");
        // Single zero groups are not compressed; the first longest run is
        assert_eq!(datacenter("2001:0:1::"), "2001:0:1::/48");
        assert_eq!(datacenter("0:0:1::"), "0:0:1::/48");
        assert_eq!(datacenter("1:2:3:4:5:6:7:8:9"), "1:2:3:4:5:6:7:8:9");
        assert_eq!(datacenter("12345::"), "12345::");
    }
}
