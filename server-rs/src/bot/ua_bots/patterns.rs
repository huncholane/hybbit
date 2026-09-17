//! Bot user-agent patterns, ported from
//! server/src/services/tracker/botBlocking/uaBots/patterns.ts, which vendors the
//! `isbot` package's patterns.json (Unlicense / public domain) and annotates it.
//!
//! The pattern sources are copied byte for byte (generated from the TypeScript,
//! not retyped): `matched_ua_pattern` in `bot_events` stores the source string,
//! so Node and Rust rows must carry identical text, and the regex semantics are
//! JavaScript's (see `bot::js::JsRegex`).
//!
//! Order matters. `classify_ua` returns the first match, so the curated
//! `EXTRA_BOT_PATTERNS` come before the vendored upstream list, and within each
//! list more specific patterns come before generic substrings. Re-sync the tables
//! at the bottom whenever patterns.ts changes, with
//! `parity/bot/generate_sources.mts`.

use serde::Serialize;

/// `BotCategory`: which family a pattern belongs to. Persisted as `bot_category`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BotCategory {
    /// search engine crawlers (Googlebot, Bingbot, DuckDuckBot, ...)
    Search,
    /// AI training, retrieval and agent crawlers
    Ai,
    /// social link-preview bots
    Social,
    /// uptime, synthetic and performance monitoring
    Monitoring,
    /// SEO crawlers
    Seo,
    /// security scanners
    Security,
    /// HTTP libraries and scripting clients
    Framework,
    /// headless browsers and browser automation
    Headless,
    /// matched a bot-ish pattern but uncategorized
    Generic,
}

impl BotCategory {
    pub const fn as_str(self) -> &'static str {
        match self {
            BotCategory::Search => "search",
            BotCategory::Ai => "ai",
            BotCategory::Social => "social",
            BotCategory::Monitoring => "monitoring",
            BotCategory::Seo => "seo",
            BotCategory::Security => "security",
            BotCategory::Framework => "framework",
            BotCategory::Headless => "headless",
            BotCategory::Generic => "generic",
        }
    }
}

/// `BotPurpose`: what the operator does with the fetch. Additive to `category`,
/// which keeps its historical meaning.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BotPurpose {
    /// corpus collection for model training
    AiTraining,
    /// indexing for an AI answer engine
    AiSearch,
    /// a human asked an AI to fetch this page, right now
    AiAgent,
    /// classic search engine indexing
    Search,
    /// link unfurling
    SocialPreview,
    /// backlink, rank and site-audit crawlers
    Seo,
    /// uptime, synthetic, performance
    Monitoring,
    /// scanners
    Security,
    /// HTTP libraries and CLI clients
    Scripted,
    /// browser automation
    Headless,
    Unknown,
}

impl BotPurpose {
    pub const fn as_str(self) -> &'static str {
        match self {
            BotPurpose::AiTraining => "ai_training",
            BotPurpose::AiSearch => "ai_search",
            BotPurpose::AiAgent => "ai_agent",
            BotPurpose::Search => "search",
            BotPurpose::SocialPreview => "social_preview",
            BotPurpose::Seo => "seo",
            BotPurpose::Monitoring => "monitoring",
            BotPurpose::Security => "security",
            BotPurpose::Scripted => "scripted",
            BotPurpose::Headless => "headless",
            BotPurpose::Unknown => "unknown",
        }
    }
}

/// `BotPattern`. The source is compiled case-insensitively.
#[derive(Clone, Copy, Debug)]
pub struct BotPattern {
    pub pattern: &'static str,
    pub category: BotCategory,
    /// Human-readable bot name; only the curated entries carry one.
    pub name: Option<&'static str>,
    /// Who operates the bot.
    pub operator: Option<&'static str>,
    pub purpose: Option<BotPurpose>,
}

const fn upstream(pattern: &'static str, category: BotCategory) -> BotPattern {
    BotPattern { pattern, category, name: None, operator: None, purpose: None }
}

const fn named(
    pattern: &'static str,
    category: BotCategory,
    name: Option<&'static str>,
    operator: Option<&'static str>,
    purpose: Option<BotPurpose>,
) -> BotPattern {
    BotPattern { pattern, category, name, operator, purpose }
}

/// `ALL_BOT_PATTERNS`: curated patterns first, so named bots win before the
/// upstream generic substrings (`(?<! cu)bots?`) catch them as generic.
pub fn all_bot_patterns() -> impl Iterator<Item = &'static BotPattern> {
    EXTRA_BOT_PATTERNS.iter().chain(BOT_PATTERNS.iter())
}

// `EXTRA_BOT_PATTERNS` (curated, named) and `BOT_PATTERNS` (vendored isbot),
// generated from patterns.ts.

pub static EXTRA_BOT_PATTERNS: [BotPattern; 66] = [
    named(r"\bgptbot\b", BotCategory::Ai, Some("GPTBot"), Some("OpenAI"), Some(BotPurpose::AiTraining)),
    named(r"\bclaudebot\b", BotCategory::Ai, Some("ClaudeBot"), Some("Anthropic"), Some(BotPurpose::AiTraining)),
    named(r"\bccbot\b", BotCategory::Ai, Some("CCBot"), Some("Common Crawl"), Some(BotPurpose::AiTraining)),
    named(
        r"\bgoogle-extended\b",
        BotCategory::Ai,
        Some("Google-Extended"),
        Some("Google"),
        Some(BotPurpose::AiTraining),
    ),
    named(
        r"\bapplebot-extended\b",
        BotCategory::Ai,
        Some("Applebot-Extended"),
        Some("Apple"),
        Some(BotPurpose::AiTraining),
    ),
    named(r"\bbytespider\b", BotCategory::Ai, Some("Bytespider"), Some("ByteDance"), Some(BotPurpose::AiTraining)),
    named(
        r"\bmeta-externalagent\b",
        BotCategory::Ai,
        Some("Meta-ExternalAgent"),
        Some("Meta"),
        Some(BotPurpose::AiTraining),
    ),
    named(r"\bamazonbot\b", BotCategory::Ai, Some("Amazonbot"), Some("Amazon"), Some(BotPurpose::AiTraining)),
    named(r"\bcohere-ai\b", BotCategory::Ai, Some("cohere-ai"), Some("Cohere"), Some(BotPurpose::AiTraining)),
    named(r"\bdiffbot\b", BotCategory::Ai, Some("Diffbot"), Some("Diffbot"), Some(BotPurpose::AiTraining)),
    named(r"\bomgilibot\b", BotCategory::Ai, Some("Omgilibot"), Some("Webz.io"), Some(BotPurpose::AiTraining)),
    named(r"\boai-searchbot\b", BotCategory::Ai, Some("OAI-SearchBot"), Some("OpenAI"), Some(BotPurpose::AiSearch)),
    named(
        r"\bclaude-searchbot\b",
        BotCategory::Ai,
        Some("Claude-SearchBot"),
        Some("Anthropic"),
        Some(BotPurpose::AiSearch),
    ),
    named(r"\bperplexitybot\b", BotCategory::Ai, Some("PerplexityBot"), Some("Perplexity"), Some(BotPurpose::AiSearch)),
    named(r"\bduckassistbot\b", BotCategory::Ai, Some("DuckAssistBot"), Some("DuckDuckGo"), Some(BotPurpose::AiSearch)),
    named(r"\byouchat\b", BotCategory::Ai, Some("YouChat"), Some("You.com"), Some(BotPurpose::AiSearch)),
    named(r"\bgrokbot\b", BotCategory::Ai, Some("GrokBot"), Some("xAI"), Some(BotPurpose::AiSearch)),
    named(r"\bchatgpt-user\b", BotCategory::Ai, Some("ChatGPT-User"), Some("OpenAI"), Some(BotPurpose::AiAgent)),
    named(r"\bclaude-user\b", BotCategory::Ai, Some("Claude-User"), Some("Anthropic"), Some(BotPurpose::AiAgent)),
    named(
        r"\bperplexity-user\b",
        BotCategory::Ai,
        Some("Perplexity-User"),
        Some("Perplexity"),
        Some(BotPurpose::AiAgent),
    ),
    named(r"\bmistralai-user\b", BotCategory::Ai, Some("MistralAI-User"), Some("Mistral"), Some(BotPurpose::AiAgent)),
    named(
        r"\bmeta-externalfetcher\b",
        BotCategory::Ai,
        Some("Meta-ExternalFetcher"),
        Some("Meta"),
        Some(BotPurpose::AiAgent),
    ),
    named(r"\bgoogle-agent\b", BotCategory::Ai, Some("Google-Agent"), Some("Google"), Some(BotPurpose::AiAgent)),
    named("^openai/", BotCategory::Ai, Some("OpenAI API client"), Some("OpenAI"), Some(BotPurpose::AiAgent)),
    named("^claude-code/", BotCategory::Ai, Some("Claude Code"), Some("Anthropic"), Some(BotPurpose::AiAgent)),
    named(r"\bcursor/", BotCategory::Ai, Some("Cursor"), Some("Cursor"), Some(BotPurpose::AiAgent)),
    named(r"\bmanus-user/", BotCategory::Ai, Some("Manus"), Some("Manus"), Some(BotPurpose::AiAgent)),
    named(r"\bfirecrawl\b", BotCategory::Ai, Some("Firecrawl"), Some("Firecrawl"), Some(BotPurpose::AiAgent)),
    named("yandexbot", BotCategory::Search, Some("YandexBot"), Some("Yandex"), Some(BotPurpose::Search)),
    named("duckduckgo", BotCategory::Search, Some("DuckDuckBot"), Some("DuckDuckGo"), Some(BotPurpose::Search)),
    named("slurp", BotCategory::Search, Some("Yahoo! Slurp"), Some("Yahoo"), Some(BotPurpose::Search)),
    named(
        "facebookexternalhit",
        BotCategory::Social,
        Some("facebookexternalhit"),
        Some("Meta"),
        Some(BotPurpose::SocialPreview),
    ),
    named("facebot", BotCategory::Social, Some("Facebot"), Some("Meta"), Some(BotPurpose::SocialPreview)),
    named("twitterbot", BotCategory::Social, Some("Twitterbot"), Some("X"), Some(BotPurpose::SocialPreview)),
    named("slackbot", BotCategory::Social, Some("Slackbot"), Some("Slack"), Some(BotPurpose::SocialPreview)),
    named("discordbot", BotCategory::Social, Some("Discordbot"), Some("Discord"), Some(BotPurpose::SocialPreview)),
    named("linkedinbot", BotCategory::Social, Some("LinkedInBot"), Some("LinkedIn"), Some(BotPurpose::SocialPreview)),
    named("telegrambot", BotCategory::Social, Some("TelegramBot"), Some("Telegram"), Some(BotPurpose::SocialPreview)),
    named(
        "skypeuripreview",
        BotCategory::Social,
        Some("SkypeUriPreview"),
        Some("Microsoft"),
        Some(BotPurpose::SocialPreview),
    ),
    named("redditbot", BotCategory::Social, Some("RedditBot"), Some("Reddit"), Some(BotPurpose::SocialPreview)),
    named(
        "pinterestbot",
        BotCategory::Social,
        Some("Pinterestbot"),
        Some("Pinterest"),
        Some(BotPurpose::SocialPreview),
    ),
    named("embedly", BotCategory::Social, Some("Embedly"), Some("Embedly"), Some(BotPurpose::SocialPreview)),
    named("ahrefsbot", BotCategory::Seo, Some("AhrefsBot"), Some("Ahrefs"), Some(BotPurpose::Seo)),
    named("semrushbot", BotCategory::Seo, Some("SemrushBot"), Some("Semrush"), Some(BotPurpose::Seo)),
    named("mj12bot", BotCategory::Seo, Some("MJ12bot"), Some("Majestic"), Some(BotPurpose::Seo)),
    named("dotbot", BotCategory::Seo, Some("DotBot"), Some("Moz"), Some(BotPurpose::Seo)),
    named("rogerbot", BotCategory::Seo, Some("rogerbot"), Some("Moz"), Some(BotPurpose::Seo)),
    named(
        "screaming frog seo spider",
        BotCategory::Seo,
        Some("Screaming Frog"),
        Some("Screaming Frog"),
        Some(BotPurpose::Seo),
    ),
    named("serpstatbot", BotCategory::Seo, Some("serpstatbot"), Some("Serpstat"), Some(BotPurpose::Seo)),
    named("python-requests", BotCategory::Framework, Some("python-requests"), None, Some(BotPurpose::Scripted)),
    named("curl/", BotCategory::Framework, Some("curl"), None, Some(BotPurpose::Scripted)),
    named("^wget", BotCategory::Framework, Some("Wget"), None, Some(BotPurpose::Scripted)),
    named("postmanruntime", BotCategory::Framework, Some("Postman"), Some("Postman"), Some(BotPurpose::Scripted)),
    named("apache-httpclient", BotCategory::Framework, Some("Apache HttpClient"), None, Some(BotPurpose::Scripted)),
    named("headlesschrome", BotCategory::Headless, Some("HeadlessChrome"), None, Some(BotPurpose::Headless)),
    named("phantomjs", BotCategory::Headless, Some("PhantomJS"), None, Some(BotPurpose::Headless)),
    named(r"\bplaywright\b", BotCategory::Headless, Some("Playwright"), None, Some(BotPurpose::Headless)),
    named(r"\bselenium\b", BotCategory::Headless, Some("Selenium"), None, Some(BotPurpose::Headless)),
    named("pingdom", BotCategory::Monitoring, Some("Pingdom"), Some("Pingdom"), Some(BotPurpose::Monitoring)),
    named(
        "uptimerobot",
        BotCategory::Monitoring,
        Some("UptimeRobot"),
        Some("UptimeRobot"),
        Some(BotPurpose::Monitoring),
    ),
    named("datadog", BotCategory::Monitoring, Some("Datadog"), Some("Datadog"), Some(BotPurpose::Monitoring)),
    named("newrelic", BotCategory::Monitoring, Some("New Relic"), Some("New Relic"), Some(BotPurpose::Monitoring)),
    named("site24x7", BotCategory::Monitoring, Some("Site24x7"), Some("Site24x7"), Some(BotPurpose::Monitoring)),
    named(
        "betteruptime",
        BotCategory::Monitoring,
        Some("Better Uptime"),
        Some("Better Stack"),
        Some(BotPurpose::Monitoring),
    ),
    named("statuscake", BotCategory::Monitoring, Some("StatusCake"), Some("StatusCake"), Some(BotPurpose::Monitoring)),
    named(
        "chrome-lighthouse",
        BotCategory::Monitoring,
        Some("Lighthouse"),
        Some("Google"),
        Some(BotPurpose::Monitoring),
    ),
];

pub static BOT_PATTERNS: [BotPattern; 183] = [
    upstream(" daum[ /]", BotCategory::Search),
    upstream(" deusu/", BotCategory::Search),
    upstream("(?:^|[^g])news(?!sapphire)", BotCategory::Generic),
    upstream("(?<! (?:channel/|google/))google(?!(app|/google| pixel))", BotCategory::Search),
    upstream(r"(?<! cu)bots?(?:\b|_)", BotCategory::Generic),
    upstream("(?<!(?:lib))http", BotCategory::Framework),
    upstream("(?<!cam)scan", BotCategory::Security),
    upstream("24x7", BotCategory::Monitoring),
    upstream(r"@[a-z][\w-]+\.", BotCategory::Generic),
    upstream(r"\(\)", BotCategory::Generic),
    upstream(r"\.com\b", BotCategory::Generic),
    upstream(r"\b\w+\.ai", BotCategory::Ai),
    upstream(r"\bcursor/", BotCategory::Ai),
    upstream(r"\bmanus-user/", BotCategory::Ai),
    upstream(r"\bort/", BotCategory::Generic),
    upstream(r"\bperl\b", BotCategory::Framework),
    upstream(r"\bplaywright\b", BotCategory::Headless),
    upstream(r"\bsecurityheaders\b", BotCategory::Monitoring),
    upstream(r"\bselenium\b", BotCategory::Headless),
    upstream(r"\btime/", BotCategory::Generic),
    upstream(r"\|", BotCategory::Generic),
    upstream(r"^[\w \.\-\(?:\):%]+(?:/v?\d+(?:\.\d+)?(?:\.\d{1,10})*?)?(?:,|$)", BotCategory::Generic),
    upstream(r"^[\w\-]+/[\w]+$", BotCategory::Generic),
    upstream("^[^ ]{50,}$", BotCategory::Generic),
    upstream(r"^\d+\b", BotCategory::Generic),
    upstream(r"^\W", BotCategory::Generic),
    upstream(r"^\w*search\b", BotCategory::Search),
    upstream(r"^\w+/[\w\(\)]*$", BotCategory::Generic),
    upstream(r"^\w+/\d\.\d\s\([\w@]+\)$", BotCategory::Generic),
    upstream("^active", BotCategory::Generic),
    upstream("^ad muncher", BotCategory::Generic),
    upstream("^amaya", BotCategory::Generic),
    upstream("^apache/", BotCategory::Framework),
    upstream("^avsdevicesdk/", BotCategory::Generic),
    upstream("^azure", BotCategory::Framework),
    upstream("^biglotron", BotCategory::Seo),
    upstream("^bot", BotCategory::Generic),
    upstream("^bw/", BotCategory::Generic),
    upstream("^clamav[ /]", BotCategory::Security),
    upstream("^claude-code/", BotCategory::Ai),
    upstream("^client/", BotCategory::Generic),
    upstream("^cobweb/", BotCategory::Seo),
    upstream("^custom", BotCategory::Generic),
    upstream("^ddg[_-]android", BotCategory::Search),
    upstream("^discourse", BotCategory::Generic),
    upstream(r"^dispatch/\d", BotCategory::Generic),
    upstream("^downcast/", BotCategory::Generic),
    upstream("^duckduckgo", BotCategory::Search),
    upstream("^email", BotCategory::Generic),
    upstream("^facebook", BotCategory::Social),
    upstream("^getright/", BotCategory::Generic),
    upstream("^gozilla/", BotCategory::Generic),
    upstream("^hobbit", BotCategory::Generic),
    upstream("^hotzonu", BotCategory::Generic),
    upstream("^hwcdn/", BotCategory::Generic),
    upstream("^igetter/", BotCategory::Generic),
    upstream("^jeode/", BotCategory::Framework),
    upstream("^jetty/", BotCategory::Framework),
    upstream("^jigsaw", BotCategory::Framework),
    upstream("^microsoft bits", BotCategory::Framework),
    upstream("^movabletype", BotCategory::Generic),
    upstream(r"^mozilla/\d\.\d\s[\w\.-]+$", BotCategory::Generic),
    upstream(r"^mozilla/\d\.\d\s\((?:compatible;)?(?:\s?[\w\d-.]+\/\d+\.\d+)?\)$", BotCategory::Generic),
    upstream("^navermailapp", BotCategory::Generic),
    upstream("^netsurf", BotCategory::Generic),
    upstream("^offline", BotCategory::Generic),
    upstream("^openai/", BotCategory::Ai),
    upstream("^owler", BotCategory::Seo),
    upstream("^php", BotCategory::Framework),
    upstream("^postman", BotCategory::Framework),
    upstream("^python", BotCategory::Framework),
    upstream("^rank", BotCategory::Seo),
    upstream("^read", BotCategory::Generic),
    upstream("^reed", BotCategory::Generic),
    upstream("^rest", BotCategory::Framework),
    upstream("^rss", BotCategory::Generic),
    upstream("^snapchat", BotCategory::Social),
    upstream("^space bison", BotCategory::Generic),
    upstream("^svn", BotCategory::Framework),
    upstream("^swcd ", BotCategory::Generic),
    upstream("^taringa", BotCategory::Social),
    upstream("^thumbor/", BotCategory::Framework),
    upstream("^track", BotCategory::Generic),
    upstream("^w3c", BotCategory::Generic),
    upstream("^webbandit/", BotCategory::Generic),
    upstream("^webcopier", BotCategory::Generic),
    upstream("^wget", BotCategory::Framework),
    upstream("^whatsapp", BotCategory::Social),
    upstream("^wordpress", BotCategory::Generic),
    upstream("^xenu link sleuth", BotCategory::Seo),
    upstream("^yahoo", BotCategory::Search),
    upstream("^yandex", BotCategory::Search),
    upstream(r"^zdm/\d", BotCategory::Generic),
    upstream("^zoom marketplace/", BotCategory::Generic),
    upstream("advisor", BotCategory::Generic),
    upstream(r"agent\b", BotCategory::Generic),
    upstream("analyzer", BotCategory::Monitoring),
    upstream("archive", BotCategory::Generic),
    upstream("ask jeeves/teoma", BotCategory::Search),
    upstream("audit", BotCategory::Monitoring),
    upstream(r"bit\.ly/", BotCategory::Generic),
    upstream("bluecoat drtr", BotCategory::Generic),
    upstream("browsex", BotCategory::Generic),
    upstream("burpcollaborator", BotCategory::Security),
    upstream("capture", BotCategory::Generic),
    upstream("catch", BotCategory::Generic),
    upstream(r"check\b", BotCategory::Monitoring),
    upstream("checker", BotCategory::Monitoring),
    upstream("chrome-lighthouse", BotCategory::Monitoring),
    upstream("chromeframe", BotCategory::Generic),
    upstream("classifier", BotCategory::Generic),
    upstream("cloudflare", BotCategory::Generic),
    upstream("convertify", BotCategory::Generic),
    upstream("crawl", BotCategory::Generic),
    upstream("cypress/", BotCategory::Headless),
    upstream("dareboost", BotCategory::Monitoring),
    upstream("datanyze", BotCategory::Seo),
    upstream("dejaclick", BotCategory::Monitoring),
    upstream("detect", BotCategory::Monitoring),
    upstream("dmbrowser", BotCategory::Generic),
    upstream("download", BotCategory::Generic),
    upstream("exaleadcloudview", BotCategory::Search),
    upstream("feed", BotCategory::Generic),
    upstream("fetcher", BotCategory::Generic),
    upstream("firephp", BotCategory::Framework),
    upstream("functionize", BotCategory::Monitoring),
    upstream("grab", BotCategory::Generic),
    upstream("headless", BotCategory::Headless),
    upstream("httrack", BotCategory::Generic),
    upstream("hubspot marketing grader", BotCategory::Monitoring),
    upstream("ibisbrowser", BotCategory::Generic),
    upstream("infrawatch", BotCategory::Monitoring),
    upstream("insight", BotCategory::Monitoring),
    upstream("inspect", BotCategory::Monitoring),
    upstream("iplabel", BotCategory::Monitoring),
    upstream("java(?!;)", BotCategory::Framework),
    upstream("library", BotCategory::Generic),
    upstream("linkcheck", BotCategory::Seo),
    upstream(r"mail\.ru/", BotCategory::Search),
    upstream("manager", BotCategory::Generic),
    upstream("measure", BotCategory::Monitoring),
    upstream(r"monitor\b", BotCategory::Monitoring),
    upstream("neustar wpm", BotCategory::Monitoring),
    upstream(r"node\b", BotCategory::Framework),
    upstream("nutch", BotCategory::Seo),
    upstream("offbyone", BotCategory::Generic),
    upstream("onetrust", BotCategory::Generic),
    upstream("optimize", BotCategory::Monitoring),
    upstream("pageburst", BotCategory::Monitoring),
    upstream("pagespeed", BotCategory::Monitoring),
    upstream("parser", BotCategory::Framework),
    upstream("phantomjs", BotCategory::Headless),
    upstream("pingdom", BotCategory::Monitoring),
    upstream("powermarks", BotCategory::Generic),
    upstream("preview", BotCategory::Social),
    upstream("proxy", BotCategory::Generic),
    upstream(r"ptst[ /]\d", BotCategory::Monitoring),
    upstream("retriever", BotCategory::Generic),
    upstream("rexx;", BotCategory::Framework),
    upstream("rigor", BotCategory::Monitoring),
    upstream(r"rss\b", BotCategory::Generic),
    upstream("scrape", BotCategory::Generic),
    upstream("server", BotCategory::Generic),
    upstream("sogou", BotCategory::Search),
    upstream("sparkler/", BotCategory::Generic),
    upstream("speedcurve", BotCategory::Monitoring),
    upstream("spider", BotCategory::Generic),
    upstream("splash", BotCategory::Headless),
    upstream("statuscake", BotCategory::Monitoring),
    upstream("supercleaner", BotCategory::Generic),
    upstream("synapse", BotCategory::Generic),
    upstream("synthetic", BotCategory::Monitoring),
    upstream("tools", BotCategory::Generic),
    upstream("torrent", BotCategory::Generic),
    upstream("transcoder", BotCategory::Generic),
    upstream("url", BotCategory::Generic),
    upstream("validator", BotCategory::Monitoring),
    upstream("virtuoso", BotCategory::Framework),
    upstream("wappalyzer", BotCategory::Seo),
    upstream("webglance", BotCategory::Generic),
    upstream("webkit2png", BotCategory::Headless),
    upstream("whatcms/", BotCategory::Seo),
    upstream("xtate/", BotCategory::Generic),
];
