//! Bot ASN classification, ported from
//! server/src/services/tracker/botBlocking/botProviderAsns.ts (`classifyBotAsn`).
//!
//! Three sources, in priority order: the curated bot provider list (convicts on
//! its own), the ipverse hosting list in `crate::datacenter_asns`, and a short
//! curated hosting list ipverse misses. The two hosting sources only corroborate.

use serde::Serialize;

use crate::datacenter_asns::is_datacenter_asn;

/// `BotAsnSource`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BotAsnSource {
    IpverseHosting,
    CuratedBotProvider,
    CuratedHosting,
}

impl BotAsnSource {
    pub const fn as_str(self) -> &'static str {
        match self {
            BotAsnSource::IpverseHosting => "ipverse_hosting",
            BotAsnSource::CuratedBotProvider => "curated_bot_provider",
            BotAsnSource::CuratedHosting => "curated_hosting",
        }
    }
}

/// `CuratedBotProviderCategory`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CuratedBotProviderCategory {
    Ai,
    SecurityScanner,
    InternetMeasurement,
    ScrapingInfrastructure,
}

impl CuratedBotProviderCategory {
    pub const fn as_str(self) -> &'static str {
        match self {
            CuratedBotProviderCategory::Ai => "ai",
            CuratedBotProviderCategory::SecurityScanner => "security_scanner",
            CuratedBotProviderCategory::InternetMeasurement => "internet_measurement",
            CuratedBotProviderCategory::ScrapingInfrastructure => "scraping_infrastructure",
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct CuratedBotProviderAsnEntry {
    pub asn: u32,
    pub provider: &'static str,
    pub category: CuratedBotProviderCategory,
    pub note: &'static str,
}

/// `BotAsnMatch`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BotAsnMatch {
    pub is_bot_infrastructure: bool,
    pub source: Option<BotAsnSource>,
    pub provider: Option<&'static str>,
    pub category: Option<CuratedBotProviderCategory>,
    pub note: Option<&'static str>,
}

const NO_MATCH: BotAsnMatch =
    BotAsnMatch { is_bot_infrastructure: false, source: None, provider: None, category: None, note: None };

const fn curated(
    asn: u32,
    provider: &'static str,
    category: CuratedBotProviderCategory,
    note: &'static str,
) -> CuratedBotProviderAsnEntry {
    CuratedBotProviderAsnEntry { asn, provider, category, note }
}

use CuratedBotProviderCategory::{Ai, InternetMeasurement, ScrapingInfrastructure, SecurityScanner};

/// `CURATED_BOT_PROVIDER_ASNS`: non-hosting ASNs dedicated to bot, crawler,
/// scanner or AI agent traffic. Keep this list tight.
pub const CURATED_BOT_PROVIDER_ASNS: [CuratedBotProviderAsnEntry; 17] = [
    // AI crawler and agent providers ipverse does not mark as hosting.
    curated(4167, "Anthropic", Ai, "ipverse category missing"),
    curated(60808, "Anthropic", Ai, "known AI provider ASN"),
    curated(399358, "Anthropic", Ai, "ipverse category business"),
    curated(400243, "Anthropic", Ai, "ipverse category missing"),
    curated(401551, "Anthropic", Ai, "ipverse category missing"),
    curated(401518, "OpenAI", Ai, "ipverse category business"),
    curated(401864, "OpenAI", Ai, "ipverse category business"),
    // Internet-wide scanner and recon providers.
    curated(27385, "Qualys", SecurityScanner, "vulnerability scanner provider"),
    curated(211607, "SecurityTrails", SecurityScanner, "recon scanner provider"),
    curated(398324, "Censys", SecurityScanner, "internet scanner provider"),
    curated(398705, "Censys", SecurityScanner, "internet scanner provider"),
    curated(398722, "Censys", SecurityScanner, "internet scanner provider"),
    curated(395213, "Rapid7", SecurityScanner, "internet scanner provider"),
    curated(399628, "Internet Measurement Research", InternetMeasurement, "internet measurement scanner provider"),
    // Crawler infrastructure added from measured traffic shape: each reached
    // hundreds of sites over three days with a handful of interaction events.
    curated(
        64267,
        "Sprious",
        ScrapingInfrastructure,
        "710 sites / 1203 visitors / 4 interaction events in 3d; desktop Linux Chrome",
    ),
    curated(
        64286,
        "LogicWeb",
        ScrapingInfrastructure,
        "1001 sites / 774 visitors / 4 interaction events in 3d; desktop Linux Chrome",
    ),
    curated(
        398464,
        "Buddy Software",
        ScrapingInfrastructure,
        "175 sites / 166 visitors / 0 interaction events in 3d; web vitals on 0.1% of events",
    ),
];

/// `CURATED_BOT_PROVIDER_ASN_COUNT`.
pub const CURATED_BOT_PROVIDER_ASN_COUNT: usize = CURATED_BOT_PROVIDER_ASNS.len();

/// `EXTRA_DATACENTER_ASNS`: hosting and proxy networks missing from the ipverse
/// hosting category. Corroborating only, like an ipverse match.
pub const EXTRA_DATACENTER_ASNS: [u32; 6] = [
    30236,  // Cronomagic Canada Inc.: 103 sites / 168 visitors / 0 interactions in 3d
    50077,  // SYN LTD: 141 sites / 691 visitors / 0 interactions in 3d
    64445,  // NetJoin srl: 117 sites / 458 visitors / 0 interactions in 3d
    134756, // CHINANET Nanjing Jishan IDC network: 295 sites / 204 visitors / 0 interactions in 3d
    209372, // WS Telecom Inc: 384 sites / 1286 visitors / 1 interaction in 3d
    213541, // WS Telecom Inc: 166 sites / 311 visitors / 0 interactions in 3d
];

/// `classifyBotAsn`. `None` is Node's non-number ASN.
pub fn classify_bot_asn(asn: Option<u32>) -> BotAsnMatch {
    let Some(asn) = asn else {
        return NO_MATCH;
    };

    if let Some(entry) = CURATED_BOT_PROVIDER_ASNS.iter().find(|entry| entry.asn == asn) {
        return BotAsnMatch {
            is_bot_infrastructure: true,
            source: Some(BotAsnSource::CuratedBotProvider),
            provider: Some(entry.provider),
            category: Some(entry.category),
            note: Some(entry.note),
        };
    }

    if is_datacenter_asn(Some(asn)) {
        return BotAsnMatch { is_bot_infrastructure: true, source: Some(BotAsnSource::IpverseHosting), ..NO_MATCH };
    }

    if EXTRA_DATACENTER_ASNS.contains(&asn) {
        return BotAsnMatch { is_bot_infrastructure: true, source: Some(BotAsnSource::CuratedHosting), ..NO_MATCH };
    }

    NO_MATCH
}

#[cfg(test)]
mod tests {
    //! Ported from server/src/services/tracker/botBlocking/botProviderAsns.test.ts.
    use super::*;

    #[test]
    fn matches_ipverse_hosting_asns() {
        let result = classify_bot_asn(Some(16509));
        assert!(result.is_bot_infrastructure);
        assert_eq!(result.source, Some(BotAsnSource::IpverseHosting));
    }

    #[test]
    fn matches_curated_ai_provider_asns() {
        let openai = classify_bot_asn(Some(401518));
        assert_eq!(
            (openai.is_bot_infrastructure, openai.source, openai.provider, openai.category),
            (true, Some(BotAsnSource::CuratedBotProvider), Some("OpenAI"), Some(Ai))
        );
        let anthropic = classify_bot_asn(Some(4167));
        assert_eq!(
            (anthropic.is_bot_infrastructure, anthropic.source, anthropic.provider, anthropic.category),
            (true, Some(BotAsnSource::CuratedBotProvider), Some("Anthropic"), Some(Ai))
        );
    }

    #[test]
    fn matches_curated_security_scanner_asns() {
        let censys = classify_bot_asn(Some(398324));
        assert_eq!(
            (censys.is_bot_infrastructure, censys.source, censys.provider, censys.category),
            (true, Some(BotAsnSource::CuratedBotProvider), Some("Censys"), Some(SecurityScanner))
        );
    }

    #[test]
    fn matches_curated_scraping_infrastructure() {
        let sprious = classify_bot_asn(Some(64267));
        assert_eq!(
            (sprious.source, sprious.provider, sprious.category),
            (Some(BotAsnSource::CuratedBotProvider), Some("Sprious"), Some(ScrapingInfrastructure))
        );
        let logicweb = classify_bot_asn(Some(64286));
        assert_eq!((logicweb.source, logicweb.provider), (Some(BotAsnSource::CuratedBotProvider), Some("LogicWeb")));
    }

    #[test]
    fn treats_curated_hosting_asns_as_corroborating() {
        for asn in EXTRA_DATACENTER_ASNS {
            let result = classify_bot_asn(Some(asn));
            assert!(result.is_bot_infrastructure, "{asn}");
            assert_eq!(result.source, Some(BotAsnSource::CuratedHosting), "{asn}");
        }
    }

    #[test]
    fn does_not_match_arbitrary_business_asns() {
        assert_eq!(classify_bot_asn(Some(13949)), NO_MATCH);
        assert_eq!(classify_bot_asn(None), NO_MATCH);
        const { assert!(CURATED_BOT_PROVIDER_ASN_COUNT > 0) };
    }
}
