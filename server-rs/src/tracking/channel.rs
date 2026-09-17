//! Channel attribution, ported from server/src/services/tracker/getChannel.ts and the
//! classifiers in server/src/services/tracker/const.ts. The lists live in
//! `channel_lists.rs`, generated from the TypeScript source.

use super::{
    channel_lists::*,
    js::js_to_lower,
    url_params::{get_utm_params, url_hostname},
};

/// `isMobileAppId`: reverse-DNS bundle ids, `/^[a-z0-9_]+(\.([a-z0-9_]+))+$/`
pub fn is_mobile_app_id(source: &str) -> bool {
    let mut segments = 0;
    for segment in source.split('.') {
        if segment.is_empty() || !segment.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_') {
            return false;
        }
        segments += 1;
    }
    segments >= 2
}

/// `getSourceType`
pub fn get_source_type(source: &str) -> &'static str {
    let lower = js_to_lower(source);
    let contains_any = |domains: &[&str]| domains.iter().any(|domain| lower.contains(domain));
    let equals_any = |names: &[&str]| names.contains(&lower.as_str());

    // Domains first, AI before search so chat.openai.com is not "search"
    if contains_any(AI_CHAT_DOMAINS) {
        return "ai";
    }
    if contains_any(SEARCH_DOMAINS) {
        return "search";
    }
    if contains_any(SOCIAL_DOMAINS) {
        return "social";
    }
    if contains_any(VIDEO_DOMAINS) {
        return "video";
    }
    if contains_any(SHOPPING_DOMAINS) {
        return "shopping";
    }

    if equals_any(AI_CHAT_SOURCES) {
        return "ai";
    }
    if equals_any(SEARCH_SOURCES) {
        return "search";
    }
    if equals_any(SOCIAL_SOURCES) {
        return "social";
    }
    if equals_any(VIDEO_SOURCES) {
        return "video";
    }
    if equals_any(SHOPPING_SOURCES) {
        return "shopping";
    }
    if equals_any(EMAIL_SOURCES) {
        return "email";
    }
    if equals_any(SMS_SOURCES) {
        return "sms";
    }

    // App ids compare case-sensitively against the original value
    if is_mobile_app_id(source) {
        let listed = |ids: &[&str]| ids.contains(&source);
        return if listed(AI_CHAT_APP_IDS) {
            "ai"
        } else if listed(SOCIAL_APP_IDS) {
            "social"
        } else if listed(VIDEO_APP_IDS) {
            "video"
        } else if listed(SEARCH_APP_IDS) {
            "search"
        } else if listed(EMAIL_APP_IDS) {
            "email"
        } else if listed(SHOPPING_APP_IDS) {
            "shopping"
        } else if listed(NEWS_APP_IDS) {
            "news"
        } else if listed(PRODUCTIVITY_APP_IDS) {
            "productivity"
        } else {
            "mobile-app"
        };
    }

    "direct"
}

/// `getMediumType`
pub fn get_medium_type(medium: &str) -> &'static str {
    let lower = js_to_lower(medium);
    let listed = |mediums: &[&str]| mediums.contains(&lower.as_str());
    let table: [(&[&str], &'static str); 14] = [
        (AI_CHAT_MEDIUMS, "ai"),
        (SOCIAL_MEDIUMS, "social"),
        (VIDEO_MEDIUMS, "video"),
        (DISPLAY_MEDIUMS, "display"),
        (AFFILIATE_MEDIUMS, "affiliate"),
        (REFERRAL_MEDIUMS, "referral"),
        (EMAIL_MEDIUMS, "email"),
        (PUSH_MEDIUMS, "push"),
        (AUDIO_MEDIUMS, "audio"),
        (INFLUENCER_MEDIUMS, "influencer"),
        (CPC_MEDIUMS, "cpc"),
        (CPM_MEDIUMS, "cpm"),
        (CONTENT_MEDIUMS, "content"),
        (EVENT_MEDIUMS, "event"),
    ];
    table.into_iter().find(|(mediums, _)| listed(mediums)).map_or("organic", |(_, kind)| kind)
}

/// `isPaidTraffic`: substring matches, so "broadcast" counts as paid ("ad")
pub fn is_paid_traffic(medium: &str, source: &str) -> bool {
    const EXTRA_PAID_MEDIUMS: [&str; 6] = ["paid", "ad", "ads", "advertising", "sponsored", "promotion"];
    const PAID_SOURCES: [&str; 10] = [
        "google ads",
        "googleads",
        "bing ads",
        "facebook ads",
        "instagram ads",
        "twitter ads",
        "linkedin ads",
        "tiktok ads",
        "youtube ads",
        "pinterest ads",
    ];
    let lower_medium = js_to_lower(medium);
    let lower_source = js_to_lower(source);

    let paid_medium = CPC_MEDIUMS
        .iter()
        .chain(CPM_MEDIUMS)
        .chain(DISPLAY_MEDIUMS)
        .chain(EXTRA_PAID_MEDIUMS.iter())
        .any(|paid| lower_medium.contains(paid));
    paid_medium || PAID_SOURCES.iter().any(|paid| lower_source.contains(paid))
}

/// `getMobileAppCategory`: lowercased substring matches, so ids listed with capitals
/// (com.google.Gmail) never match here.
fn mobile_app_category(app_id: &str) -> Option<&'static str> {
    let lower = js_to_lower(app_id);
    let table: [(&[&str], &'static str); 8] = [
        (SOCIAL_APP_IDS, "Organic Social"),
        (VIDEO_APP_IDS, "Organic Video"),
        (AI_CHAT_APP_IDS, "AI"),
        (SEARCH_APP_IDS, "Organic Search"),
        (EMAIL_APP_IDS, "Email"),
        (SHOPPING_APP_IDS, "Organic Shopping"),
        (NEWS_APP_IDS, "News"),
        (PRODUCTIVITY_APP_IDS, "Productivity"),
    ];
    table.into_iter().find(|(ids, _)| ids.iter().any(|id| lower.contains(id))).map(|(_, channel)| channel)
}

/// `getDomainFromReferrer`: the referrer URL's hostname (possibly empty), or
/// `$direct` for no referrer or one that is not a URL.
fn domain_from_referrer(referrer: &str) -> String {
    if referrer.is_empty() {
        return "$direct".into();
    }
    url_hostname(referrer).unwrap_or_else(|| "$direct".into())
}

/// `isSelfReferral`
fn is_self_referral(referring_domain: &str, hostname: &str) -> bool {
    if referring_domain.is_empty() || hostname.is_empty() {
        return false;
    }
    let referring = referring_domain.strip_prefix("www.").unwrap_or(referring_domain);
    let current = hostname.strip_prefix("www.").unwrap_or(hostname);
    referring == current || referring.ends_with(&format!(".{current}"))
}

/// `/\bai\b/` with JavaScript's ASCII word boundaries
fn contains_word_ai(text: &str) -> bool {
    let bytes = text.as_bytes();
    let is_word = |byte: u8| byte.is_ascii_alphanumeric() || byte == b'_';
    text.match_indices("ai").any(|(at, _)| {
        let before = at.checked_sub(1).map(|i| bytes[i]);
        let after = bytes.get(at + 2).copied();
        !before.is_some_and(is_word) && !after.is_some_and(is_word)
    })
}

/// `getChannel(referrer, querystring, hostname)`; an empty querystring or hostname
/// behaves like Node's `undefined`.
pub fn get_channel(referrer: &str, querystring: &str, hostname: &str) -> &'static str {
    let utm_params = get_utm_params(querystring);
    let referring_domain = domain_from_referrer(referrer);
    let self_referral = !hostname.is_empty() && is_self_referral(&referring_domain, hostname);

    let param = |name: &str| utm_params.get(name).map_or("", String::as_str);
    let utm_source = param("utm_source");
    let utm_medium = param("utm_medium");
    let utm_campaign = param("utm_campaign");
    let gclid = param("gclid");
    let gad_source = param("gad_source");

    if !utm_source.is_empty()
        && is_mobile_app_id(utm_source)
        && let Some(category) = mobile_app_category(utm_source)
    {
        return category;
    }

    if referrer.is_empty()
        && utm_source.is_empty()
        && utm_medium.is_empty()
        && utm_campaign.is_empty()
        && gclid.is_empty()
        && gad_source.is_empty()
    {
        return if self_referral { "Internal" } else { "Direct" };
    }

    let source_type = get_source_type(if utm_source.is_empty() { &referring_domain } else { utm_source });
    let medium_type = get_medium_type(utm_medium);
    let is_paid = is_paid_traffic(utm_medium, utm_source) || !gclid.is_empty() || !gad_source.is_empty();

    if utm_campaign == "cross-network" {
        return "Cross-Network";
    }

    if (referring_domain == "$direct" || (referrer.is_empty() && !self_referral))
        && utm_medium.is_empty()
        && utm_campaign.is_empty()
        && (utm_source.is_empty() || utm_source == "direct" || utm_source == "(direct)")
    {
        return "Direct";
    }

    if is_paid {
        return match source_type {
            "ai" => "Paid AI",
            "search" => "Paid Search",
            "social" => "Paid Social",
            "video" => "Paid Video",
            "shopping" => "Paid Shopping",
            _ => match medium_type {
                "ai" => "Paid AI",
                "social" => "Paid Social",
                "video" => "Paid Video",
                "display" | "cpm" => "Display",
                "cpc" => "Paid Search",
                "influencer" => "Paid Influencer",
                "audio" => "Paid Audio",
                _ => "Paid Unknown",
            },
        };
    }

    match source_type {
        "ai" => return "AI",
        "search" => return "Organic Search",
        "social" => return "Organic Social",
        "video" => return "Organic Video",
        "shopping" => return "Organic Shopping",
        "email" => return "Email",
        "sms" => return "SMS",
        "news" => return "News",
        "productivity" => return "Productivity",
        _ => {}
    }

    match medium_type {
        "ai" => return "AI",
        "social" => return "Organic Social",
        "video" => return "Organic Video",
        "affiliate" => return "Affiliate",
        "referral" => return "Referral",
        "display" => return "Display",
        "audio" => return "Audio",
        "push" => return "Push",
        "influencer" => return "Influencer",
        "content" => return "Content",
        "event" => return "Event",
        "email" => return "Email",
        _ => {}
    }

    let campaign_has = |needles: &[&str]| needles.iter().any(|needle| utm_campaign.contains(needle));
    if contains_word_ai(utm_campaign) || campaign_has(&["chatgpt", "claude", "gemini", "copilot", "llm"]) {
        return "AI";
    }
    if campaign_has(&["video"]) {
        return "Organic Video";
    }
    if campaign_has(&["shop"]) {
        return "Organic Shopping";
    }
    if campaign_has(&["influencer", "creator", "sponsored"]) {
        return "Influencer";
    }
    if campaign_has(&["event", "conference", "webinar"]) {
        return "Event";
    }
    if campaign_has(&["social", "facebook", "twitter", "instagram", "linkedin"]) {
        return "Organic Social";
    }

    let has_referring_domain = !referring_domain.is_empty() && referring_domain != "$direct";
    if (!utm_source.is_empty() || !utm_medium.is_empty() || !utm_campaign.is_empty() || has_referring_domain)
        && !self_referral
    {
        return "Referral";
    }

    "Unknown"
}

#[cfg(test)]
mod tests {
    use super::*;

    // Ported from getChannel.test.ts
    #[test]
    fn classifies_custom_utm_parameters_as_referral_without_a_referrer() {
        assert_eq!(get_channel("", "utm_source=my_app&utm_medium=custom", ""), "Referral");
        assert_eq!(get_channel("", "utm_source=gsuite_extension", ""), "Referral");
        assert_eq!(get_channel("", "utm_medium=custom_link", ""), "Referral");
        assert_eq!(get_channel("", "utm_campaign=custom_campaign", ""), "Referral");
    }

    #[test]
    fn retains_direct_without_referrer_or_utm_parameters() {
        assert_eq!(get_channel("", "", ""), "Direct");
    }

    #[test]
    fn retains_referral_for_external_referring_domains() {
        assert_eq!(get_channel("https://external-site.com/blog", "", ""), "Referral");
        assert_ne!(get_channel("https://example.com/page", "utm_source=custom_source", "example.com"), "Referral");
    }

    #[test]
    fn well_known_sources() {
        assert_eq!(get_channel("https://www.google.com/", "", "example.com"), "Organic Search");
        assert_eq!(get_channel("https://chatgpt.com/", "", "example.com"), "AI");
        assert_eq!(get_channel("", "utm_source=google&utm_medium=cpc", ""), "Paid Search");
        assert_eq!(get_channel("", "utm_source=com.google.android.gm", ""), "Email");
        // A self-referral with a referrer is neither Internal nor Referral
        assert_eq!(get_channel("https://example.com/", "", "www.example.com"), "Unknown");
        assert_eq!(get_channel("", "", "www.example.com"), "Direct");
        assert_eq!(get_channel("", "utm_campaign=spring-ai-launch", ""), "AI");
        assert_eq!(get_channel("", "utm_campaign=maintenance", ""), "Referral");
    }

    #[test]
    fn app_ids() {
        assert!(is_mobile_app_id("com.google.android.gm"));
        assert!(is_mobile_app_id("www.google.com"));
        assert!(!is_mobile_app_id("com"));
        assert!(!is_mobile_app_id("com..x"));
        assert!(!is_mobile_app_id("Com.x"));
    }
}
