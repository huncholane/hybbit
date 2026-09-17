//! IP pattern matching, ported from server/src/lib/ipUtils.ts together with the parts
//! of the `ip-address` 10.2.0 package it relies on (`Address4`, `Address6`,
//! `isInSubnet`). The library's parsing is looser and stricter than `std::net` in
//! different places (it accepts `01.2.3.4`, `::a/1/64` and zone suffixes, rejects
//! `::ffff:01.2.3.4`), and excluded-IP rules are user input, so its rules are
//! reproduced rather than approximated with `IpAddr::from_str`.

use super::js::js_trim;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Address4 {
    value: u32,
    subnet_mask: u32,
}

/// An `Address6` whose groups parsed; a group `parseInt` could not read (one that
/// starts with `/`) is kept as `None`, standing for the NaN that makes the library
/// throw once the address is converted to bits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Address6 {
    groups: [Option<u16>; 8],
    subnet_mask: u32,
}

/// One dotted-quad part accepted by `(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)`: one to
/// three digits worth at most 255, leading zeros allowed
fn octet(part: &str) -> Option<u8> {
    let bytes = part.as_bytes();
    if bytes.is_empty() || bytes.len() > 3 || !bytes.iter().all(u8::is_ascii_digit) {
        return None;
    }
    part.parse::<u8>().ok()
}

/// `RE_ADDRESS` from ip-address's v4 constants, anchored at both ends
fn dotted_quad(text: &str) -> Option<[u8; 4]> {
    let mut parts = text.split('.');
    let address = [octet(parts.next()?)?, octet(parts.next()?)?, octet(parts.next()?)?, octet(parts.next()?)?];
    parts.next().is_none().then_some(address)
}

/// `new Address4(address)`
fn parse_address4(address: &str) -> Option<Address4> {
    let bytes = address.as_bytes();
    let len = bytes.len();
    // RE_SUBNET_STRING = /\/\d{1,2}$/, leftmost match first
    let (rest, subnet_mask) =
        if len >= 3 && bytes[len - 3] == b'/' && bytes[len - 2].is_ascii_digit() && bytes[len - 1].is_ascii_digit() {
            (&address[..len - 3], address[len - 2..].parse::<u32>().ok()?)
        } else if len >= 2 && bytes[len - 2] == b'/' && bytes[len - 1].is_ascii_digit() {
            (&address[..len - 2], address[len - 1..].parse::<u32>().ok()?)
        } else {
            (address, 32)
        };
    if subnet_mask > 32 {
        return None;
    }
    let octets = dotted_quad(rest)?;
    Some(Address4 { value: u32::from_be_bytes(octets), subnet_mask })
}

fn is_line_terminator(c: char) -> bool {
    matches!(c, '\n' | '\r' | '\u{2028}' | '\u{2029}')
}

/// `new Address6(address)`
fn parse_address6(address: &str) -> Option<Address6> {
    let mut address = address.to_string();

    // RE_SUBNET_STRING = /\/\d{1,3}(?=%|$)/: the first `/` followed by one to three
    // digits and then `%` or the end
    let bytes = address.as_bytes();
    let subnet = bytes.iter().enumerate().filter(|(_, b)| **b == b'/').find_map(|(slash, _)| {
        let digits = bytes[slash + 1..].iter().take_while(|b| b.is_ascii_digit()).count();
        let end = slash + 1 + digits;
        ((1..=3).contains(&digits) && (end == bytes.len() || bytes[end] == b'%')).then_some((slash, end))
    });
    let subnet_mask = match subnet {
        Some((slash, end)) => {
            let mask = address[slash + 1..end].parse::<u32>().ok()?;
            if mask > 128 {
                return None;
            }
            address.replace_range(slash..end, "");
            mask
        }
        None if address.contains('/') => return None,
        None => 128,
    };

    // RE_ZONE_STRING = /%.*$/: `.` stops at line terminators and `$` is the very end
    let after_last_terminator =
        address.rfind(is_line_terminator).map_or(0, |at| at + address[at..].chars().next().map_or(1, char::len_utf8));
    if let Some(percent) = address[after_last_terminator..].find('%') {
        address.truncate(after_last_terminator + percent);
    }

    // parse4in6: a trailing dotted quad becomes two groups
    if address.contains('.') {
        let mut groups: Vec<String> = address.split(':').map(str::to_string).collect();
        let last = groups.last().cloned().unwrap_or_default();
        if let Some(octets) = dotted_quad(&last) {
            if last.split('.').any(|part| part.len() > 1 && part.starts_with('0')) {
                return None; // "IPv4 addresses can't have leading zeroes."
            }
            let replaced = format!("{:02x}{:02x}:{:02x}{:02x}", octets[0], octets[1], octets[2], octets[3]);
            *groups.last_mut()? = replaced;
            address = groups.join(":");
        }
    }

    // RE_BAD_CHARACTERS = /([^0-9a-f:/%])/gi
    if !address.bytes().all(|b| b.is_ascii_hexdigit() || matches!(b, b':' | b'/' | b'%')) {
        return None;
    }
    // RE_BAD_ADDRESS = /([0-9a-f]{5,}|:{3,}|[^:]:$|^:[^:]|\/$)/gi
    let bytes = address.as_bytes();
    let long_hex_run = bytes.split(|b| !b.is_ascii_hexdigit()).any(|run| run.len() >= 5);
    let len = bytes.len();
    if long_hex_run
        || address.contains(":::")
        || (len >= 2 && bytes[len - 1] == b':' && bytes[len - 2] != b':')
        || (len >= 2 && bytes[0] == b':' && bytes[1] != b':')
        || address.ends_with('/')
    {
        return None;
    }

    let halves: Vec<&str> = address.split("::").collect();
    let groups: Vec<&str> = match halves.as_slice() {
        [first, last] => {
            let first: Vec<&str> = if first.is_empty() { Vec::new() } else { first.split(':').collect() };
            let last: Vec<&str> = if last.is_empty() { Vec::new() } else { last.split(':').collect() };
            let remaining = 8 - (first.len() + last.len()) as isize;
            if remaining <= 0 {
                return None; // "Error parsing groups" or "Incorrect number of groups found"
            }
            first.into_iter().chain(std::iter::repeat_n("0", remaining as usize)).chain(last).collect()
        }
        [only] => only.split(':').collect(),
        _ => return None, // "Too many :: groups found"
    };
    if groups.len() != 8 {
        return None;
    }

    let mut parsed = [None; 8];
    for (slot, group) in parsed.iter_mut().zip(groups) {
        // parseInt(group, 16): the leading hex digits, NaN when there are none
        let digits = group.bytes().take_while(u8::is_ascii_hexdigit).count();
        *slot = (digits > 0).then(|| u16::from_str_radix(&group[..digits], 16).ok()).flatten();
    }
    Some(Address6 { groups: parsed, subnet_mask })
}

/// `address.isInSubnet(subnet)` for IPv4
fn in_subnet4(address: Address4, subnet: Address4) -> bool {
    if address.subnet_mask < subnet.subnet_mask {
        return false;
    }
    let bits = subnet.subnet_mask;
    bits == 0 || (address.value >> (32 - bits)) == (subnet.value >> (32 - bits))
}

fn address6_bits(address: &Address6) -> Option<u128> {
    address.groups.iter().try_fold(0u128, |bits, group| Some((bits << 16) | u128::from((*group)?)))
}

/// `address.isInSubnet(subnet)` for IPv6; the library throws (and the caller answers
/// false) when either side holds a NaN group
fn in_subnet6(address: &Address6, subnet: &Address6) -> Option<bool> {
    if address.subnet_mask < subnet.subnet_mask {
        return Some(false);
    }
    let bits = subnet.subnet_mask;
    let (address_bits, subnet_bits) = (address6_bits(address)?, address6_bits(subnet)?);
    Some(bits == 0 || (address_bits >> (128 - bits)) == (subnet_bits >> (128 - bits)))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IpPatternValidation {
    pub valid: bool,
    pub error: Option<&'static str>,
}

impl IpPatternValidation {
    fn valid() -> Self {
        Self { valid: true, error: None }
    }

    fn invalid(error: &'static str) -> Self {
        Self { valid: false, error: Some(error) }
    }
}

/// `validateIPPattern`
pub fn validate_ip_pattern(pattern: &str) -> IpPatternValidation {
    let trimmed = js_trim(pattern);
    if trimmed.is_empty() {
        return IpPatternValidation::valid();
    }
    let parses = |text: &str| parse_address4(text).is_some() || parse_address6(text).is_some();

    if !trimmed.contains('/') && !trimmed.contains('-') {
        return if parses(trimmed) {
            IpPatternValidation::valid()
        } else {
            IpPatternValidation::invalid("Invalid IP address format")
        };
    }

    if trimmed.contains('/') {
        return if parses(trimmed) {
            IpPatternValidation::valid()
        } else {
            IpPatternValidation::invalid("Invalid CIDR notation")
        };
    }

    let mut ends = trimmed.split('-').map(js_trim);
    let (start, end) = (ends.next().unwrap_or_default(), ends.next().unwrap_or_default());
    if start.is_empty() || end.is_empty() {
        return IpPatternValidation::invalid("Invalid range format");
    }
    if parse_address4(start).is_some() && parse_address4(end).is_some() {
        return IpPatternValidation::valid();
    }
    if parse_address6(start).is_some() && parse_address6(end).is_some() {
        return IpPatternValidation::invalid(
            "IPv6 range notation not supported. Use CIDR notation instead (e.g., 2001:db8::/32)",
        );
    }
    IpPatternValidation::invalid("Invalid IP addresses in range")
}

/// `matchesCIDR`: the address and the pattern must be the same family.
pub fn matches_cidr(ip_address: &str, cidr: &str) -> bool {
    if let Some(address) = parse_address4(ip_address) {
        return parse_address4(cidr).is_some_and(|subnet| in_subnet4(address, subnet));
    }
    let Some(address) = parse_address6(ip_address) else { return false };
    let Some(subnet) = parse_address6(cidr) else { return false };
    match in_subnet6(&address, &subnet) {
        Some(matched) => matched,
        None => {
            tracing::warn!(cidr, ip = ip_address, "Error matching CIDR {cidr} for IP {ip_address}");
            false
        }
    }
}

/// `matchesRange`: inclusive IPv4 ranges only.
pub fn matches_range(ip_address: &str, range: &str) -> bool {
    let mut ends = range.split('-').map(js_trim);
    let start = ends.next().unwrap_or_default();
    let end = ends.next();

    let ipv4 = (|| {
        let address = parse_address4(ip_address)?;
        let first = parse_address4(start)?;
        let last = parse_address4(end?)?;
        Some(address.value >= first.value && address.value <= last.value)
    })();
    if let Some(matched) = ipv4 {
        return matched;
    }

    let all_ipv6 = parse_address6(ip_address).is_some()
        && parse_address6(start).is_some()
        && end.is_some_and(|end| parse_address6(end).is_some());
    if all_ipv6 {
        tracing::warn!(
            range,
            "IPv6 range notation not supported: {range}. Use CIDR notation instead (e.g., 2001:db8::/32)"
        );
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok() -> IpPatternValidation {
        IpPatternValidation::valid()
    }

    fn err(message: &'static str) -> IpPatternValidation {
        IpPatternValidation::invalid(message)
    }

    // Ported from server/src/lib/ipUtils.test.ts

    #[test]
    fn treats_empty_and_whitespace_only_patterns_as_valid() {
        assert_eq!(validate_ip_pattern(""), ok());
        assert_eq!(validate_ip_pattern("   "), ok());
        assert_eq!(validate_ip_pattern("\t\n"), ok());
    }

    #[test]
    fn accepts_single_ipv4_and_ipv6_addresses_trimming_whitespace() {
        for pattern in
            ["192.168.1.1", "  10.0.0.1  ", "0.0.0.0", "255.255.255.255", "2001:db8::1", "::1", "::ffff:192.168.1.1"]
        {
            assert_eq!(validate_ip_pattern(pattern), ok(), "{pattern}");
        }
    }

    #[test]
    fn rejects_malformed_single_addresses() {
        for pattern in ["256.1.1.1", "1.2.3", "1.2.3.4.5", "abc", "1.2.3.4x", "0x1.2.3.4", "2130706433", "..."] {
            assert_eq!(validate_ip_pattern(pattern), err("Invalid IP address format"), "{pattern}");
        }
    }

    #[test]
    fn accepts_zero_padded_ipv4_octets() {
        assert_eq!(validate_ip_pattern("01.2.3.4"), ok());
        assert_eq!(validate_ip_pattern("192.168.001.1"), ok());
    }

    #[test]
    fn accepts_cidr_notation_for_ipv4_and_ipv6() {
        for pattern in ["192.168.1.0/24", "10.0.0.1/32", "0.0.0.0/0", "2001:db8::/32", "::/0"] {
            assert_eq!(validate_ip_pattern(pattern), ok(), "{pattern}");
        }
    }

    #[test]
    fn rejects_malformed_cidr_notation() {
        for pattern in ["192.168.1.1/33", "192.168.1.1/-1", "192.168.1.1/", "192.168.1.1/abc", "/24", "1.2.3/24"] {
            assert_eq!(validate_ip_pattern(pattern), err("Invalid CIDR notation"), "{pattern}");
        }
    }

    #[test]
    fn classifies_a_pattern_with_slash_and_dash_as_cidr() {
        assert_eq!(validate_ip_pattern("192.168.1.0/24-192.168.2.0/24"), err("Invalid CIDR notation"));
    }

    #[test]
    fn accepts_ipv4_range_notation_with_inner_whitespace() {
        assert_eq!(validate_ip_pattern("192.168.1.1-192.168.1.10"), ok());
        assert_eq!(validate_ip_pattern("  192.168.1.1 - 192.168.1.10  "), ok());
        assert_eq!(validate_ip_pattern("10.0.0.5-10.0.0.5"), ok());
    }

    #[test]
    fn does_not_enforce_range_ordering() {
        assert_eq!(validate_ip_pattern("192.168.1.10-192.168.1.1"), ok());
    }

    #[test]
    fn rejects_incomplete_range_notation() {
        for pattern in ["192.168.1.1-", "-192.168.1.1", "-", " - "] {
            assert_eq!(validate_ip_pattern(pattern), err("Invalid range format"), "{pattern}");
        }
    }

    #[test]
    fn rejects_ranges_whose_endpoints_are_not_ipv4() {
        assert_eq!(validate_ip_pattern("192.168.1.1-999.1.1.1"), err("Invalid IP addresses in range"));
        assert_eq!(validate_ip_pattern("abc-def"), err("Invalid IP addresses in range"));
        assert_eq!(validate_ip_pattern("192.168.1.1-2001:db8::1"), err("Invalid IP addresses in range"));
        assert_eq!(validate_ip_pattern("10.0.0.1-10.0.0.5-10.0.0.9"), ok());
    }

    #[test]
    fn points_ipv6_ranges_at_cidr_notation() {
        assert_eq!(
            validate_ip_pattern("2001:db8::1-2001:db8::5"),
            err("IPv6 range notation not supported. Use CIDR notation instead (e.g., 2001:db8::/32)")
        );
    }

    #[test]
    fn matches_cidr_cases() {
        assert!(matches_cidr("192.168.1.42", "192.168.1.0/24"));
        assert!(matches_cidr("192.168.1.0", "192.168.1.0/24"));
        assert!(matches_cidr("192.168.1.255", "192.168.1.0/24"));
        assert!(!matches_cidr("192.168.0.255", "192.168.1.0/24"));
        assert!(!matches_cidr("192.168.2.0", "192.168.1.0/24"));
        assert!(matches_cidr("10.0.0.1", "10.0.0.1/32"));
        assert!(!matches_cidr("10.0.0.2", "10.0.0.1/32"));
        assert!(matches_cidr("10.0.0.1", "10.0.0.1"));
        assert!(!matches_cidr("10.0.0.2", "10.0.0.1"));
        assert!(matches_cidr("8.8.8.8", "0.0.0.0/0"));
        assert!(matches_cidr("255.255.255.255", "0.0.0.0/0"));
        assert!(matches_cidr("2001:db8::1", "::/0"));
        assert!(matches_cidr("10.0.0.0", "10.0.0.0/31"));
        assert!(matches_cidr("10.0.0.1", "10.0.0.0/31"));
        assert!(!matches_cidr("10.0.0.2", "10.0.0.0/31"));
        assert!(matches_cidr("192.168.1.9", "192.168.1.5/24"));
        assert!(matches_cidr("2001:db8::5", "2001:db8::/32"));
        assert!(!matches_cidr("2001:db9::5", "2001:db8::/32"));
        assert!(matches_cidr("::1", "::1/128"));
        assert!(!matches_cidr("::2", "::1/128"));
    }

    #[test]
    fn matches_cidr_returns_false_across_families_and_for_garbage() {
        assert!(!matches_cidr("192.168.1.1", "2001:db8::/32"));
        assert!(!matches_cidr("2001:db8::1", "192.168.1.0/24"));
        assert!(!matches_cidr("::ffff:192.168.1.5", "192.168.1.0/24"));
        assert!(matches_cidr("::ffff:192.168.1.5", "::ffff:192.168.1.0/120"));
        for (ip, cidr) in [
            ("", "192.168.1.0/24"),
            ("192.168.1.1", ""),
            ("not-an-ip", "192.168.1.0/24"),
            ("192.168.1.1", "not-a-cidr"),
            ("999.1.1.1", "192.168.1.0/24"),
            ("192.168.1.1", "192.168.1.0/33"),
            ("192.168.1.1", "192.168.1.0/-1"),
            (" 192.168.1.1", "192.168.1.0/24"),
        ] {
            assert!(!matches_cidr(ip, cidr), "{ip} {cidr}");
        }
    }

    #[test]
    fn matches_range_cases() {
        assert!(matches_range("192.168.1.5", "192.168.1.1-192.168.1.10"));
        assert!(matches_range("192.168.1.1", "192.168.1.1-192.168.1.10"));
        assert!(matches_range("192.168.1.10", "192.168.1.1-192.168.1.10"));
        assert!(!matches_range("192.168.1.0", "192.168.1.1-192.168.1.10"));
        assert!(!matches_range("192.168.1.11", "192.168.1.1-192.168.1.10"));
        assert!(matches_range("10.0.0.5", "10.0.0.5-10.0.0.5"));
        assert!(!matches_range("10.0.0.6", "10.0.0.5-10.0.0.5"));
        assert!(!matches_range("192.168.1.5", "192.168.1.10-192.168.1.1"));
        assert!(!matches_range("192.168.1.10", "192.168.1.10-192.168.1.1"));
        assert!(matches_range("200.0.0.1", "0.0.0.0-255.255.255.255"));
        assert!(matches_range("128.0.0.1", "127.0.0.0-255.255.255.255"));
        assert!(!matches_range("126.255.255.255", "127.0.0.0-255.255.255.255"));
        assert!(matches_range("255.255.255.255", "255.255.255.254-255.255.255.255"));
        assert!(!matches_range("10.0.0.1", "127.0.0.0-129.0.0.0"));
        assert!(matches_range("192.168.1.5", " 192.168.1.1 - 192.168.1.10 "));
        assert!(matches_range("10.0.0.3", "10.0.0.1-10.0.0.5-10.0.0.9"));
        assert!(!matches_range("10.0.0.7", "10.0.0.1-10.0.0.5-10.0.0.9"));
        assert!(!matches_range("10.0.0.5", "10.0.0.5"));
        assert!(!matches_range("10.0.0.5", ""));
        assert!(!matches_range("2001:db8::5", "2001:db8::1-2001:db8::10"));
        assert!(!matches_range("::1", "::0-::ffff"));
        for (ip, range) in [
            ("2001:db8::5", "192.168.1.1-192.168.1.10"),
            ("192.168.1.5", "2001:db8::1-2001:db8::10"),
            ("not-an-ip", "192.168.1.1-192.168.1.10"),
            ("192.168.1.5", "garbage-garbage"),
            ("192.168.1.5", "192.168.1.1-"),
            ("192.168.1.5", "-192.168.1.10"),
            (" 192.168.1.5", "192.168.1.1-192.168.1.10"),
        ] {
            assert!(!matches_range(ip, range), "{ip} {range}");
        }
    }

    #[test]
    fn library_quirks() {
        // A slash group that parseInt reads as NaN still constructs
        assert_eq!(validate_ip_pattern("::a/1/64"), ok());
        assert!(matches_cidr("::a", "::a/1/64"));
        assert_eq!(validate_ip_pattern("::/5/64"), ok());
        assert!(!matches_cidr("::1", "::/5/64"));
        assert_eq!(validate_ip_pattern("fe80::1%eth0"), ok());
        assert_eq!(validate_ip_pattern("::ffff:01.2.3.4"), err("Invalid IP address format"));
    }
}
