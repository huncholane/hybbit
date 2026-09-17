//! Site exclusions, ported from server/src/services/sites/siteExclusionDecision.ts.
//! The first match wins in a fixed order: IP, ASN, country, path, query param,
//! hostname, user agent.

use super::{
    AsnSource, LocationSource,
    ip_utils::{matches_cidr, matches_range},
    js::{js_to_lower, js_to_upper, js_trim},
    url_params::url_search_params,
};
use crate::site_config::SiteConfigData;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SiteExclusionReason {
    Ip,
    Asn,
    Country,
    Path,
    QueryParam,
    Hostname,
    UserAgent,
}

impl SiteExclusionReason {
    /// `SiteExclusionReason`, logged as `exclusionReason`
    pub fn as_str(self) -> &'static str {
        match self {
            SiteExclusionReason::Ip => "ip",
            SiteExclusionReason::Asn => "asn",
            SiteExclusionReason::Country => "country",
            SiteExclusionReason::Path => "path",
            SiteExclusionReason::QueryParam => "query_param",
            SiteExclusionReason::Hostname => "hostname",
            SiteExclusionReason::UserAgent => "user_agent",
        }
    }

    /// `SiteExclusionLabel`, used in the tracking response message
    pub fn label(self) -> &'static str {
        match self {
            SiteExclusionReason::Ip => "IP",
            SiteExclusionReason::Asn => "ASN",
            SiteExclusionReason::Country => "country",
            SiteExclusionReason::Path => "path",
            SiteExclusionReason::QueryParam => "query param",
            SiteExclusionReason::Hostname => "hostname",
            SiteExclusionReason::UserAgent => "user agent",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SiteExclusionDecision {
    Accepted,
    Excluded { reason: SiteExclusionReason, value: String },
}

impl SiteExclusionDecision {
    pub fn is_excluded(&self) -> bool {
        matches!(self, SiteExclusionDecision::Excluded { .. })
    }

    /// The `message` `trackEvent` answers an excluded event with
    pub fn tracked_message(&self) -> Option<String> {
        match self {
            SiteExclusionDecision::Accepted => None,
            SiteExclusionDecision::Excluded { reason, .. } => {
                Some(format!("Event not tracked - {} excluded", reason.label()))
            }
        }
    }
}

/// The Site Configuration lists a decision reads.
#[derive(Clone, Copy, Debug)]
pub struct SiteExclusionRules<'a> {
    pub excluded_ips: &'a [String],
    pub use_organization_excluded_ips: bool,
    pub organization_excluded_ips: &'a [String],
    pub excluded_countries: &'a [String],
    pub excluded_paths: &'a [String],
    pub excluded_hostnames: &'a [String],
    pub excluded_user_agents: &'a [String],
    pub excluded_asns: &'a [String],
    pub excluded_query_params: &'a [String],
}

impl<'a> From<&'a SiteConfigData> for SiteExclusionRules<'a> {
    fn from(site: &'a SiteConfigData) -> Self {
        Self {
            excluded_ips: &site.excluded_ips,
            use_organization_excluded_ips: site.use_organization_excluded_ips,
            organization_excluded_ips: &site.organization_excluded_ips,
            excluded_countries: &site.excluded_countries,
            excluded_paths: &site.excluded_paths,
            excluded_hostnames: &site.excluded_hostnames,
            excluded_user_agents: &site.excluded_user_agents,
            excluded_asns: &site.excluded_asns,
            excluded_query_params: &site.excluded_query_params,
        }
    }
}

/// `SiteExclusionRequest`; `None` and `Some("")` both skip a check, like Node's falsy tests.
#[derive(Clone, Copy, Debug, Default)]
pub struct SiteExclusionRequest<'a> {
    pub ip_address: &'a str,
    /// Every plausible client IP (see `collect_candidate_client_ips`); IP and ASN
    /// exclusions match any of them
    pub candidate_ips: &'a [String],
    pub pathname: Option<&'a str>,
    pub querystring: Option<&'a str>,
    pub hostname: Option<&'a str>,
    pub user_agent: Option<&'a str>,
}

/// `decideSiteExclusion`. Geolocation is consulted only when country rules exist and
/// nothing earlier matched.
pub fn decide_site_exclusion(
    rules: &SiteExclusionRules,
    request: &SiteExclusionRequest,
    geo: &impl LocationSource,
    asn: &impl AsnSource,
) -> SiteExclusionDecision {
    let decision = decide(rules, request, geo, asn);
    if let SiteExclusionDecision::Excluded { reason, value } = &decision {
        tracing::debug!(exclusion_reason = reason.as_str(), value = %value, "Site exclusion matched");
    }
    decision
}

fn decide(
    rules: &SiteExclusionRules,
    request: &SiteExclusionRequest,
    geo: &impl LocationSource,
    asn: &impl AsnSource,
) -> SiteExclusionDecision {
    let excluded = |reason, value: &str| SiteExclusionDecision::Excluded { reason, value: value.to_string() };

    let mut ips_to_check: Vec<&str> = Vec::with_capacity(request.candidate_ips.len() + 1);
    for ip in std::iter::once(request.ip_address).chain(request.candidate_ips.iter().map(String::as_str)) {
        if !ips_to_check.contains(&ip) {
            ips_to_check.push(ip);
        }
    }

    let organization_ips: &[String] =
        if rules.use_organization_excluded_ips { rules.organization_excluded_ips } else { &[] };
    let matched_ip = ips_to_check
        .iter()
        .find(|ip| rules.excluded_ips.iter().chain(organization_ips).any(|pattern| matches_ip_pattern(ip, pattern)));
    // `if (matchedIp)`: a matching empty string counts as no match, and ends the search
    if let Some(ip) = matched_ip
        && !ip.is_empty()
    {
        return excluded(SiteExclusionReason::Ip, ip);
    }

    if !rules.excluded_asns.is_empty() {
        let excluded_asns: Vec<u64> =
            rules.excluded_asns.iter().filter_map(|pattern| parse_asn_pattern(pattern)).collect();
        for ip in &ips_to_check {
            if let Some(info) = asn.asn_info(ip)
                && excluded_asns.contains(&u64::from(info.asn))
            {
                return excluded(SiteExclusionReason::Asn, &format!("AS{}", info.asn));
            }
        }
    }

    if !rules.excluded_countries.is_empty()
        && let Some(country_iso) = geo.country_iso(request.ip_address).filter(|iso| !iso.is_empty())
    {
        let wanted = js_to_upper(&country_iso);
        if rules.excluded_countries.iter().any(|country| js_to_upper(country) == wanted) {
            return excluded(SiteExclusionReason::Country, &country_iso);
        }
    }

    if let Some(pathname) = request.pathname.filter(|path| !path.is_empty())
        && rules.excluded_paths.iter().any(|pattern| matches_glob(pathname, pattern))
    {
        return excluded(SiteExclusionReason::Path, pathname);
    }

    if let Some(querystring) = request.querystring.filter(|query| !query.is_empty())
        && !rules.excluded_query_params.is_empty()
        && let Some(matched) = matches_query_params(querystring, rules.excluded_query_params)
    {
        return excluded(SiteExclusionReason::QueryParam, &matched);
    }

    if let Some(hostname) = request.hostname.filter(|host| !host.is_empty())
        && rules.excluded_hostnames.iter().any(|pattern| matches_glob(hostname, pattern))
    {
        return excluded(SiteExclusionReason::Hostname, hostname);
    }

    if let Some(user_agent) = request.user_agent.filter(|agent| !agent.is_empty()) {
        let normalized = js_to_lower(user_agent);
        let matches = rules.excluded_user_agents.iter().any(|substring| {
            let trimmed = js_to_lower(js_trim(substring));
            !trimmed.is_empty() && normalized.contains(&trimmed)
        });
        if matches {
            return excluded(SiteExclusionReason::UserAgent, user_agent);
        }
    }

    SiteExclusionDecision::Accepted
}

/// `matchesGlob`: case-insensitive, `*` matches any run, compared per UTF-16 unit
/// with a linear-time backtracking scan.
pub fn matches_glob(value: &str, pattern: &str) -> bool {
    let glob: Vec<u16> = js_to_lower(js_trim(pattern)).encode_utf16().collect();
    if glob.is_empty() {
        return false;
    }
    let text: Vec<u16> = js_to_lower(value).encode_utf16().collect();
    let star = u16::from(b'*');

    let (mut text_index, mut glob_index) = (0usize, 0usize);
    let mut last_star: Option<usize> = None;
    let mut text_after_star = 0usize;

    while text_index < text.len() {
        if glob_index < glob.len() && glob[glob_index] == text[text_index] {
            text_index += 1;
            glob_index += 1;
        } else if glob_index < glob.len() && glob[glob_index] == star {
            last_star = Some(glob_index);
            text_after_star = text_index;
            glob_index += 1;
        } else if let Some(star_index) = last_star {
            glob_index = star_index + 1;
            text_after_star += 1;
            text_index = text_after_star;
        } else {
            return false;
        }
    }
    while glob_index < glob.len() && glob[glob_index] == star {
        glob_index += 1;
    }
    glob_index == glob.len()
}

/// `matchesIPPattern`: exact address, CIDR, or IPv4 range.
fn matches_ip_pattern(ip_address: &str, pattern: &str) -> bool {
    let trimmed = js_trim(pattern);
    if !trimmed.contains('/') && !trimmed.contains('-') {
        return ip_address == trimmed;
    }
    if trimmed.contains('/') {
        return matches_cidr(ip_address, trimmed);
    }
    matches_range(ip_address, trimmed)
}

/// `parseAsnPattern`: "13335" or "AS13335" in any case. Numbers past `u64` saturate,
/// which can never equal an ASN, just as Node's rounded doubles cannot.
fn parse_asn_pattern(pattern: &str) -> Option<u64> {
    let trimmed = js_trim(pattern);
    let digits = match trimmed.get(..2) {
        Some(prefix) if prefix.eq_ignore_ascii_case("as") => &trimmed[2..],
        _ => trimmed,
    };
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some(digits.parse::<u64>().unwrap_or(u64::MAX))
}

/// `matchesQueryParams`: "name" matches presence, "name=glob" matches the value; the
/// first pattern (in rule order) with a matching parameter wins.
fn matches_query_params(querystring: &str, patterns: &[String]) -> Option<String> {
    let entries = url_search_params(querystring);
    if entries.is_empty() {
        return None;
    }

    for pattern in patterns {
        let trimmed = js_trim(pattern);
        if trimmed.is_empty() {
            continue;
        }
        let (name, value_glob) = match trimmed.find('=') {
            Some(separator) => (js_to_lower(&trimmed[..separator]), Some(&trimmed[separator + 1..])),
            None => (js_to_lower(trimmed), None),
        };
        if name.is_empty() {
            continue;
        }

        let matched = entries
            .iter()
            .find(|(key, value)| js_to_lower(key) == name && value_glob.is_none_or(|glob| matches_glob(value, glob)));
        if let Some((key, value)) = matched {
            return Some(if value.is_empty() { key.clone() } else { format!("{key}={value}") });
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use std::{cell::RefCell, collections::HashMap};

    use super::*;
    use crate::geo::AsnInfo;

    #[derive(Default)]
    struct FakeGeo {
        countries: HashMap<String, String>,
        calls: RefCell<Vec<String>>,
    }

    impl LocationSource for FakeGeo {
        fn country_iso(&self, ip: &str) -> Option<String> {
            self.calls.borrow_mut().push(ip.to_string());
            self.countries.get(ip).cloned()
        }
    }

    #[derive(Default)]
    struct FakeAsn {
        by_ip: HashMap<String, u32>,
        every_ip: Option<u32>,
        calls: RefCell<usize>,
    }

    impl AsnSource for FakeAsn {
        fn asn_info(&self, ip: &str) -> Option<AsnInfo> {
            *self.calls.borrow_mut() += 1;
            self.by_ip.get(ip).copied().or(self.every_ip).map(|asn| AsnInfo { asn, organization: String::new() })
        }
    }

    #[derive(Default)]
    struct Rules {
        excluded_ips: Vec<String>,
        use_organization_excluded_ips: Option<bool>,
        organization_excluded_ips: Vec<String>,
        excluded_countries: Vec<String>,
        excluded_paths: Vec<String>,
        excluded_hostnames: Vec<String>,
        excluded_user_agents: Vec<String>,
        excluded_asns: Vec<String>,
        excluded_query_params: Vec<String>,
    }

    impl Rules {
        fn view(&self) -> SiteExclusionRules<'_> {
            SiteExclusionRules {
                excluded_ips: &self.excluded_ips,
                use_organization_excluded_ips: self.use_organization_excluded_ips.unwrap_or(true),
                organization_excluded_ips: &self.organization_excluded_ips,
                excluded_countries: &self.excluded_countries,
                excluded_paths: &self.excluded_paths,
                excluded_hostnames: &self.excluded_hostnames,
                excluded_user_agents: &self.excluded_user_agents,
                excluded_asns: &self.excluded_asns,
                excluded_query_params: &self.excluded_query_params,
            }
        }
    }

    fn strings(items: &[&str]) -> Vec<String> {
        items.iter().map(|item| item.to_string()).collect()
    }

    fn request() -> SiteExclusionRequest<'static> {
        SiteExclusionRequest {
            ip_address: "198.51.100.10",
            candidate_ips: &[],
            pathname: Some("/admin/users"),
            querystring: None,
            hostname: Some("preview.vercel.app"),
            user_agent: Some("Mozilla/5.0 HeadlessChrome/120"),
        }
    }

    fn decide_with(rules: &Rules, request: &SiteExclusionRequest) -> SiteExclusionDecision {
        decide_site_exclusion(&rules.view(), request, &FakeGeo::default(), &FakeAsn::default())
    }

    fn excluded(reason: SiteExclusionReason, value: &str) -> SiteExclusionDecision {
        SiteExclusionDecision::Excluded { reason, value: value.to_string() }
    }

    fn reason(decision: &SiteExclusionDecision) -> Option<SiteExclusionReason> {
        match decision {
            SiteExclusionDecision::Excluded { reason, .. } => Some(*reason),
            SiteExclusionDecision::Accepted => None,
        }
    }

    // Ported from siteExclusionDecision.test.ts

    #[test]
    fn matches_an_organization_wide_ip_exclusion_the_site_applies() {
        let rules = Rules { organization_excluded_ips: strings(&["198.51.100.0/24"]), ..Default::default() };
        assert_eq!(decide_with(&rules, &request()), excluded(SiteExclusionReason::Ip, "198.51.100.10"));
    }

    #[test]
    fn ignores_the_organizations_ip_exclusions_when_the_site_turned_them_off() {
        let rules = Rules {
            organization_excluded_ips: strings(&["198.51.100.10"]),
            use_organization_excluded_ips: Some(false),
            ..Default::default()
        };
        assert_eq!(decide_with(&rules, &request()), SiteExclusionDecision::Accepted);
    }

    #[test]
    fn accepts_a_request_when_no_exclusion_matches_without_resolving_geolocation() {
        let geo = FakeGeo::default();
        let decision = decide_site_exclusion(&Rules::default().view(), &request(), &geo, &FakeAsn::default());
        assert_eq!(decision, SiteExclusionDecision::Accepted);
        assert!(geo.calls.borrow().is_empty());
    }

    #[test]
    fn matches_an_excluded_ip_using_single_cidr_and_range_rules() {
        for pattern in ["198.51.100.10", "198.51.100.0/24", "198.51.100.1-198.51.100.20"] {
            let rules = Rules { excluded_ips: strings(&[pattern]), ..Default::default() };
            let decision = decide_with(&rules, &request());
            assert_eq!(decision, excluded(SiteExclusionReason::Ip, "198.51.100.10"), "{pattern}");
            assert_eq!(decision.tracked_message().as_deref(), Some("Event not tracked - IP excluded"));
        }
    }

    #[test]
    fn matches_an_excluded_ip_among_the_candidates() {
        let rules = Rules { excluded_ips: strings(&["203.0.113.7"]), ..Default::default() };
        let candidates = strings(&["172.68.34.28", "203.0.113.7"]);
        let proxied = SiteExclusionRequest { ip_address: "172.68.34.28", candidate_ips: &candidates, ..request() };
        assert_eq!(decide_with(&rules, &proxied), excluded(SiteExclusionReason::Ip, "203.0.113.7"));

        let other = strings(&["198.51.100.1"]);
        let unrelated = SiteExclusionRequest { ip_address: "172.68.34.28", candidate_ips: &other, ..request() };
        assert_eq!(decide_with(&rules, &unrelated), SiteExclusionDecision::Accepted);
    }

    #[test]
    fn resolves_geolocation_only_when_country_rules_exist() {
        let geo = FakeGeo {
            countries: HashMap::from([("198.51.100.10".to_string(), "us".to_string())]),
            ..Default::default()
        };
        let rules = Rules { excluded_countries: strings(&["US", "GB"]), ..Default::default() };
        let decision = decide_site_exclusion(&rules.view(), &request(), &geo, &FakeAsn::default());
        assert_eq!(decision, excluded(SiteExclusionReason::Country, "us"));
        assert_eq!(*geo.calls.borrow(), ["198.51.100.10"]);
    }

    #[test]
    fn matches_path_globs_case_insensitively() {
        let rules = Rules { excluded_paths: strings(&["/admin/*", "/preview"]), ..Default::default() };
        let with_path = |path| SiteExclusionRequest { pathname: Some(path), ..request() };
        assert_eq!(reason(&decide_with(&rules, &with_path("/ADMIN/users"))), Some(SiteExclusionReason::Path));
        assert_eq!(reason(&decide_with(&rules, &with_path("/preview"))), Some(SiteExclusionReason::Path));
        assert_eq!(decide_with(&rules, &with_path("/admin")), SiteExclusionDecision::Accepted);
    }

    #[test]
    fn handles_multiple_and_consecutive_wildcards_without_backtracking() {
        let long_pattern = format!("/{}b", "*a".repeat(30));
        let rules = Rules { excluded_paths: strings(&["/a/*/b/*", "/x**y", &long_pattern]), ..Default::default() };
        let with_path = |path: &str| decide_with(&rules, &SiteExclusionRequest { pathname: Some(path), ..request() });
        assert_eq!(reason(&with_path("/a/1/b/2")), Some(SiteExclusionReason::Path));
        assert_eq!(reason(&with_path("/a//b/")), Some(SiteExclusionReason::Path));
        assert_eq!(reason(&with_path("/xANYTHINGy")), Some(SiteExclusionReason::Path));
        assert_eq!(with_path(&format!("/{}", "a".repeat(2000))), SiteExclusionDecision::Accepted);
    }

    #[test]
    fn matches_hostname_globs() {
        let rules = Rules { excluded_hostnames: strings(&["localhost", "*.vercel.app"]), ..Default::default() };
        assert_eq!(reason(&decide_with(&rules, &request())), Some(SiteExclusionReason::Hostname));
        let apex = SiteExclusionRequest { hostname: Some("vercel.app"), ..request() };
        assert_eq!(decide_with(&rules, &apex), SiteExclusionDecision::Accepted);
    }

    #[test]
    fn matches_user_agent_substrings_case_insensitively_and_ignores_blank_rules() {
        let rules = Rules { excluded_user_agents: strings(&["  ", "headlesschrome"]), ..Default::default() };
        assert_eq!(reason(&decide_with(&rules, &request())), Some(SiteExclusionReason::UserAgent));
        let real = SiteExclusionRequest { user_agent: Some("Mozilla/5.0 (real browser)"), ..request() };
        assert_eq!(decide_with(&rules, &real), SiteExclusionDecision::Accepted);
    }

    #[test]
    fn matches_an_excluded_asn_with_or_without_the_as_prefix() {
        let asn = FakeAsn { every_ip: Some(13335), ..Default::default() };
        let decide_asns = |patterns: &[&str]| {
            let rules = Rules { excluded_asns: strings(patterns), ..Default::default() };
            decide_site_exclusion(&rules.view(), &request(), &FakeGeo::default(), &asn)
        };
        let expected = excluded(SiteExclusionReason::Asn, "AS13335");
        assert_eq!(decide_asns(&["AS13335"]), expected);
        assert_eq!(decide_asns(&["as13335"]), expected);
        assert_eq!(decide_asns(&["13335"]), expected);
        assert_eq!(decide_asns(&["bogus", "AS999"]), SiteExclusionDecision::Accepted);
    }

    #[test]
    fn matches_an_excluded_asn_on_any_candidate_and_skips_lookups_without_asn_rules() {
        let asn = FakeAsn { by_ip: HashMap::from([("203.0.113.7".to_string(), 16509)]), ..Default::default() };
        let rules = Rules { excluded_asns: strings(&["AS16509"]), ..Default::default() };
        let candidates = strings(&["203.0.113.7"]);
        let with_candidates = SiteExclusionRequest { candidate_ips: &candidates, ..request() };
        let decision = decide_site_exclusion(&rules.view(), &with_candidates, &FakeGeo::default(), &asn);
        assert_eq!(decision, excluded(SiteExclusionReason::Asn, "AS16509"));

        *asn.calls.borrow_mut() = 0;
        let accepted = decide_site_exclusion(&Rules::default().view(), &request(), &FakeGeo::default(), &asn);
        assert_eq!(accepted, SiteExclusionDecision::Accepted);
        assert_eq!(*asn.calls.borrow(), 0);
    }

    #[test]
    fn matches_query_params_by_presence_and_by_value_glob() {
        let with_query = |query: Option<&'static str>| SiteExclusionRequest {
            pathname: Some("/pricing"),
            hostname: Some("example.com"),
            user_agent: Some("Mozilla/5.0"),
            querystring: query,
            ..request()
        };
        let rules = |patterns: &[&str]| Rules { excluded_query_params: strings(patterns), ..Default::default() };

        let presence = decide_with(&rules(&["preview"]), &with_query(Some("?Preview=true&x=1")));
        assert_eq!(presence, excluded(SiteExclusionReason::QueryParam, "Preview=true"));
        assert_eq!(presence.tracked_message().as_deref(), Some("Event not tracked - query param excluded"));

        let glob = decide_with(&rules(&["utm_source=internal-*"]), &with_query(Some("utm_source=Internal-QA")));
        assert_eq!(glob, excluded(SiteExclusionReason::QueryParam, "utm_source=Internal-QA"));

        let miss = decide_with(
            &rules(&["utm_source=internal", "preview"]),
            &with_query(Some("utm_source=external&other=preview")),
        );
        assert_eq!(miss, SiteExclusionDecision::Accepted);

        assert_eq!(decide_with(&rules(&["preview"]), &with_query(None)), SiteExclusionDecision::Accepted);
    }

    #[test]
    fn returns_the_first_exclusion_in_the_fixed_order_and_short_circuits() {
        let geo = FakeGeo {
            countries: HashMap::from([("198.51.100.10".to_string(), "US".to_string())]),
            ..Default::default()
        };
        let rules = Rules {
            excluded_ips: strings(&["198.51.100.0/24"]),
            excluded_countries: strings(&["US"]),
            excluded_paths: strings(&["/admin/*"]),
            excluded_hostnames: strings(&["*.vercel.app"]),
            excluded_user_agents: strings(&["HeadlessChrome"]),
            ..Default::default()
        };
        let decision = decide_site_exclusion(&rules.view(), &request(), &geo, &FakeAsn::default());
        assert_eq!(reason(&decision), Some(SiteExclusionReason::Ip));
        assert!(geo.calls.borrow().is_empty());
    }

    #[test]
    fn lets_country_exclusion_preempt_matching_request_metadata() {
        let geo = FakeGeo {
            countries: HashMap::from([("198.51.100.10".to_string(), "US".to_string())]),
            ..Default::default()
        };
        let rules = Rules {
            excluded_countries: strings(&["US"]),
            excluded_paths: strings(&["/admin/*"]),
            excluded_hostnames: strings(&["*.vercel.app"]),
            excluded_user_agents: strings(&["HeadlessChrome"]),
            ..Default::default()
        };
        let decision = decide_site_exclusion(&rules.view(), &request(), &geo, &FakeAsn::default());
        assert_eq!(reason(&decision), Some(SiteExclusionReason::Country));
    }

    #[test]
    fn labels_match_track_event_messages() {
        let labels: Vec<_> = [
            SiteExclusionReason::Ip,
            SiteExclusionReason::Asn,
            SiteExclusionReason::Country,
            SiteExclusionReason::Path,
            SiteExclusionReason::QueryParam,
            SiteExclusionReason::Hostname,
            SiteExclusionReason::UserAgent,
        ]
        .iter()
        .map(|reason| (reason.as_str(), reason.label()))
        .collect();
        assert_eq!(
            labels,
            [
                ("ip", "IP"),
                ("asn", "ASN"),
                ("country", "country"),
                ("path", "path"),
                ("query_param", "query param"),
                ("hostname", "hostname"),
                ("user_agent", "user agent")
            ]
        );
    }
}
