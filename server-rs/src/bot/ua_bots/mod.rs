//! User-agent classification, ported from
//! server/src/services/tracker/botBlocking/uaBots/index.ts (`classifyUA`).

pub mod patterns;

use std::{
    collections::HashMap,
    sync::{LazyLock, Mutex},
};

pub use patterns::{BotCategory, BotPattern, BotPurpose};

use super::js::{JsRegex, JsText};

/// `BotClassification`. Identity fields are present only for the curated
/// patterns: a match on a generic upstream rule ("crawl", "spider") is a bot
/// without a name, and saying so beats inventing one from the regex.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BotClassification {
    pub is_bot: bool,
    pub category: Option<BotCategory>,
    pub matched_pattern: Option<&'static str>,
    pub name: Option<&'static str>,
    pub operator: Option<&'static str>,
    pub purpose: Option<BotPurpose>,
}

const NON_BOT: BotClassification = BotClassification {
    is_bot: false,
    category: None,
    matched_pattern: None,
    name: None,
    operator: None,
    purpose: None,
};

/// Node keeps `CLASSIFY_CACHE_MAX` entries in a recency-ordered Map.
const CLASSIFY_CACHE_MAX: usize = 10_000;

/// One compiled pattern with its prefilter.
struct CompiledPattern {
    regex: JsRegex,
    /// A literal every match must contain, lowercase (see [`required_literal`]).
    literal: Option<String>,
    pattern: &'static BotPattern,
}

/// `COMPILED_PATTERNS`, in source order so the first match wins.
///
/// Node first tests `COMBINED_REGEX` (every pattern joined with `|`) and only
/// scans the patterns when it matches. An alternation of independent patterns
/// matches exactly when one of them does, so the scan alone gives the same
/// answer; what makes it cheap here is the literal prefilter, since regress
/// matching UTF-16 input does not search for literals itself.
static COMPILED: LazyLock<Vec<CompiledPattern>> = LazyLock::new(|| {
    patterns::all_bot_patterns()
        .map(|pattern| CompiledPattern {
            regex: JsRegex::ignore_case(pattern.pattern),
            literal: required_literal(pattern.pattern),
            pattern,
        })
        .collect()
});

/// The longest run of literal characters (at least three) that every match of a
/// regex source must contain, lowercased, or None when there is no such run.
///
/// Deliberately conservative: a top-level alternation yields nothing, groups and
/// classes end a run, an optional atom (`?`, `*`, `{0,`) ends a run without
/// joining it, and only zero-width items (`^`, `$`, `\b`, lookarounds) may sit
/// inside one. Since the regexes are case-insensitive over ASCII and the literal
/// is ASCII, the match can only exist if the ASCII-lowercased input contains it.
fn required_literal(source: &str) -> Option<String> {
    let chars: Vec<char> = source.chars().collect();

    // Find the end of a group or class starting at `start`, honouring escapes.
    fn skip_group(chars: &[char], start: usize) -> usize {
        let mut depth = 0;
        let mut index = start;
        let mut in_class = false;
        while index < chars.len() {
            match chars[index] {
                '\\' => index += 1,
                '[' if !in_class => in_class = true,
                ']' if in_class => in_class = false,
                '(' if !in_class => depth += 1,
                ')' if !in_class => {
                    depth -= 1;
                    if depth == 0 {
                        return index;
                    }
                }
                _ => {}
            }
            index += 1;
        }
        chars.len()
    }

    fn skip_class(chars: &[char], start: usize) -> usize {
        let mut index = start + 1;
        while index < chars.len() {
            match chars[index] {
                '\\' => index += 1,
                ']' => return index,
                _ => {}
            }
            index += 1;
        }
        chars.len()
    }

    // A quantifier following position `index`: (makes the atom optional, length).
    fn quantifier(chars: &[char], index: usize) -> (bool, usize) {
        let optional_or_repeated = match chars.get(index) {
            Some('?') | Some('*') => (true, 1),
            Some('+') => (false, 1),
            Some('{') => {
                let end = chars[index..].iter().position(|c| *c == '}').map(|offset| index + offset).unwrap_or(index);
                let min: String = chars[index + 1..end].iter().take_while(|c| c.is_ascii_digit()).collect();
                (min.parse::<u32>().unwrap_or(0) == 0, end + 1 - index)
            }
            _ => return (false, 0),
        };
        // A lazy suffix does not change what is required.
        let lazy = usize::from(chars.get(index + optional_or_repeated.1) == Some(&'?'));
        (optional_or_repeated.0, optional_or_repeated.1 + lazy)
    }

    let mut best = String::new();
    let mut run = String::new();
    let mut end_run = |run: &mut String| {
        if run.len() > best.len() {
            best = run.clone();
        }
        run.clear();
    };

    let mut index = 0;
    while index < chars.len() {
        let c = chars[index];
        match c {
            '|' => return None,
            '^' | '$' => index += 1,
            '(' => {
                let close = skip_group(&chars, index);
                let lookaround = chars[index..].starts_with(&['(', '?', '='])
                    || chars[index..].starts_with(&['(', '?', '!'])
                    || chars[index..].starts_with(&['(', '?', '<', '='])
                    || chars[index..].starts_with(&['(', '?', '<', '!']);
                if !lookaround {
                    end_run(&mut run);
                }
                index = close + 1;
                let (_, length) = quantifier(&chars, index);
                if length > 0 {
                    end_run(&mut run);
                }
                index += length;
            }
            '[' | '.' => {
                end_run(&mut run);
                index = if c == '[' { skip_class(&chars, index) + 1 } else { index + 1 };
                index += quantifier(&chars, index).1;
            }
            '\\' => {
                let escaped = chars.get(index + 1).copied().unwrap_or('\\');
                index += 2;
                if matches!(escaped, 'b' | 'B') {
                    continue;
                }
                if matches!(escaped, 'w' | 'W' | 'd' | 'D' | 's' | 'S') {
                    end_run(&mut run);
                    index += quantifier(&chars, index).1;
                    continue;
                }
                let (optional, length) = quantifier(&chars, index);
                if optional {
                    end_run(&mut run);
                } else {
                    run.push(escaped.to_ascii_lowercase());
                    if length > 0 {
                        end_run(&mut run);
                    }
                }
                index += length;
            }
            _ => {
                index += 1;
                let (optional, length) = quantifier(&chars, index);
                if optional {
                    end_run(&mut run);
                } else {
                    run.push(c.to_ascii_lowercase());
                    if length > 0 {
                        end_run(&mut run);
                    }
                }
                index += length;
            }
        }
    }
    end_run(&mut run);

    (best.len() >= 3).then_some(best)
}

/// Classifications keyed by user agent. User agents repeat heavily, so this keeps
/// the regex scan off the hot path. Node evicts in exact recency order; here two
/// generations approximate it (a hit in the older one is promoted, and when the
/// young one fills the old one is dropped), which bounds memory at the same size
/// without reordering a map on every hit. Classification is a pure function of
/// the user agent, so eviction order cannot change a result.
struct ClassifyCache {
    young: HashMap<String, BotClassification>,
    old: HashMap<String, BotClassification>,
}

static CLASSIFY_CACHE: LazyLock<Mutex<ClassifyCache>> =
    LazyLock::new(|| Mutex::new(ClassifyCache { young: HashMap::new(), old: HashMap::new() }));

impl ClassifyCache {
    fn get(&mut self, user_agent: &str) -> Option<BotClassification> {
        if let Some(found) = self.young.get(user_agent) {
            return Some(*found);
        }
        let found = self.old.remove(user_agent)?;
        self.insert(user_agent.to_string(), found);
        Some(found)
    }

    fn insert(&mut self, user_agent: String, classification: BotClassification) {
        if self.young.len() >= CLASSIFY_CACHE_MAX / 2 {
            self.old = std::mem::take(&mut self.young);
        }
        self.young.insert(user_agent, classification);
    }
}

/// `classifyUA`: the first matching bot pattern, or a non-bot result. An empty
/// user agent is not a bot here (the header heuristics judge its absence).
pub fn classify_ua(user_agent: &str) -> BotClassification {
    if user_agent.is_empty() {
        return NON_BOT;
    }

    if let Some(cached) = CLASSIFY_CACHE.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).get(user_agent) {
        return cached;
    }

    let result = compute_classification(user_agent);
    CLASSIFY_CACHE.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).insert(user_agent.to_string(), result);
    result
}

/// `isBotUA`: boolean shorthand.
pub fn is_bot_ua(user_agent: &str) -> bool {
    classify_ua(user_agent).is_bot
}

fn compute_classification(user_agent: &str) -> BotClassification {
    let text = JsText::new(user_agent);
    let lowered = user_agent.to_ascii_lowercase();
    for compiled in COMPILED.iter() {
        if compiled.literal.as_deref().is_some_and(|literal| !lowered.contains(literal)) {
            continue;
        }
        if compiled.regex.test(&text) {
            let pattern = compiled.pattern;
            return BotClassification {
                is_bot: true,
                category: Some(pattern.category),
                matched_pattern: Some(pattern.pattern),
                name: pattern.name,
                operator: pattern.operator,
                purpose: pattern.purpose,
            };
        }
    }
    NON_BOT
}

/// Classification without the cache, for tests and benchmarks.
#[cfg(test)]
pub(crate) fn classify_ua_uncached(user_agent: &str) -> BotClassification {
    if user_agent.is_empty() { NON_BOT } else { compute_classification(user_agent) }
}

/// Classification without the cache or the literal prefilter: Node's algorithm
/// as written, combined regex included, to prove the shortcuts change nothing.
#[cfg(test)]
pub(crate) fn classify_ua_reference(user_agent: &str) -> BotClassification {
    static COMBINED: LazyLock<JsRegex> = LazyLock::new(|| {
        JsRegex::ignore_case(&patterns::all_bot_patterns().map(|pattern| pattern.pattern).collect::<Vec<_>>().join("|"))
    });
    if user_agent.is_empty() {
        return NON_BOT;
    }
    let text = JsText::new(user_agent);
    if !COMBINED.test(&text) {
        return NON_BOT;
    }
    for compiled in COMPILED.iter() {
        if compiled.regex.test(&text) {
            let pattern = compiled.pattern;
            return BotClassification {
                is_bot: true,
                category: Some(pattern.category),
                matched_pattern: Some(pattern.pattern),
                name: pattern.name,
                operator: pattern.operator,
                purpose: pattern.purpose,
            };
        }
    }
    BotClassification { is_bot: true, category: Some(BotCategory::Generic), ..NON_BOT }
}

#[cfg(test)]
mod tests {
    //! Ported from server/src/services/tracker/botBlocking/uaBots/index.test.ts.
    use super::*;

    fn assert_category(user_agents: &[&str], category: BotCategory) {
        for user_agent in user_agents {
            let classification = classify_ua(user_agent);
            assert!(classification.is_bot, "{user_agent}");
            assert_eq!(classification.category, Some(category), "{user_agent}");
        }
    }

    #[test]
    fn compiles_every_pattern_and_keeps_node_counts() {
        assert_eq!(patterns::EXTRA_BOT_PATTERNS.len(), 66);
        assert_eq!(patterns::BOT_PATTERNS.len(), 183);
        assert_eq!(COMPILED.len(), 249);
    }

    #[test]
    fn extracts_only_literals_every_match_must_contain() {
        let cases = [
            (r"\bgptbot\b", Some("gptbot")),
            ("(?<! (?:channel/|google/))google(?!(app|/google| pixel))", Some("google")),
            ("(?<! cu)bots?(?:\\b|_)", Some("bot")),
            ("(?<!cam)scan", Some("scan")),
            ("(?:^|[^g])news(?!sapphire)", Some("news")),
            (r"\b\w+\.ai", Some(".ai")),
            (r"bit\.ly/", Some("bit.ly/")),
            ("^claude-code/", Some("claude-code/")),
            ("java(?!;)", Some("java")),
            ("ptst[ /]\\d", Some("ptst")),
            (r"^\w+/\d\.\d\s\([\w@]+\)$", None),
            ("^[^ ]{50,}$", None),
            ("screaming frog seo spider", Some("screaming frog seo spider")),
            ("check\\b", Some("check")),
            ("24x7", Some("24x7")),
            (r"\bwv\b|;\s?wv\)", None),
            ("ab?cdef", Some("cdef")),
            ("abc+def", Some("abc")),
            ("x{0,2}yzw", Some("yzw")),
        ];
        for (source, expected) in cases {
            assert_eq!(required_literal(source).as_deref(), expected, "{source}");
        }
    }

    #[test]
    fn prefiltered_scan_agrees_with_nodes_algorithm() {
        for user_agent in [
            "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
            "Mozilla/5.0 (Linux; Android 10; K) Chrome/120 GoogleApp/15",
            "Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 Chrome/120 Safari/537.36",
            "a cubot phone",
            "CamScanner",
            "Java;",
            "\u{212A}url/7",
            "",
        ] {
            assert_eq!(classify_ua_uncached(user_agent), classify_ua_reference(user_agent), "{user_agent}");
        }
    }

    #[test]
    fn returns_non_bot_for_empty_input() {
        assert!(!classify_ua("").is_bot);
    }

    #[test]
    fn returns_non_bot_for_typical_real_browsers() {
        for user_agent in [
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
            "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
        ] {
            assert!(!classify_ua(user_agent).is_bot, "{user_agent}");
        }
    }

    #[test]
    fn categorizes_ai_crawlers_as_ai() {
        assert_category(
            &[
                "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; GPTBot/1.2; +https://openai.com/gptbot)",
                "Mozilla/5.0 (compatible; ClaudeBot/1.0; +claudebot@anthropic.com)",
                "Mozilla/5.0 (compatible; PerplexityBot/1.0; +https://perplexity.ai/perplexitybot)",
                "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; OAI-SearchBot/1.0; +https://openai.com/searchbot)",
                "Mozilla/5.0 (compatible; Bytespider; spider-feedback@bytedance.com) AppleWebKit/537.36",
                "CCBot/2.0 (https://commoncrawl.org/faq/)",
                "Mozilla/5.0 (compatible; meta-externalagent/1.1; +https://developers.facebook.com/docs/sharing/webmasters/crawler)",
                "openai/1.0",
                "claude-code/0.5",
            ],
            BotCategory::Ai,
        );
    }

    #[test]
    fn categorizes_search_engine_crawlers_as_search() {
        assert_category(
            &[
                "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
                "Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)",
                "DuckDuckGo-Favicons-Bot/1.0",
                "Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)",
            ],
            BotCategory::Search,
        );
    }

    #[test]
    fn categorizes_social_link_preview_bots_as_social() {
        assert_category(
            &[
                "facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)",
                "Twitterbot/1.0",
                "Slackbot-LinkExpanding 1.0 (+https://api.slack.com/robots)",
                "Mozilla/5.0 (compatible; Discordbot/2.0; +https://discordapp.com)",
                "LinkedInBot/1.0 (compatible; Mozilla/5.0; +https://www.linkedin.com)",
            ],
            BotCategory::Social,
        );
    }

    #[test]
    fn categorizes_http_frameworks_as_framework() {
        assert_category(
            &[
                "python-requests/2.31.0",
                "curl/8.4.0",
                "Wget/1.21.4",
                "PostmanRuntime/7.36.0",
                "Apache-HttpClient/4.5.13 (Java/11.0.20)",
            ],
            BotCategory::Framework,
        );
    }

    #[test]
    fn categorizes_headless_automation_as_headless() {
        assert_category(
            &[
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/120.0.0.0 Safari/537.36",
                "Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) PhantomJS/2.1.1 Safari/538.1",
                "Mozilla/5.0 Playwright/1.40.0 (Chromium; +https://playwright.dev)",
                "Mozilla/5.0 Selenium/4.16",
            ],
            BotCategory::Headless,
        );
    }

    #[test]
    fn categorizes_uptime_monitors_as_monitoring() {
        assert_category(
            &[
                "Pingdom.com_bot_version_1.4_(http://www.pingdom.com/)",
                "Mozilla/5.0 (compatible; UptimeRobot/2.0; http://www.uptimerobot.com/)",
                "StatusCake_Pagespeed_Indev",
                "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Chrome-Lighthouse",
            ],
            BotCategory::Monitoring,
        );
    }

    #[test]
    fn categorizes_seo_crawlers_as_seo() {
        assert_category(
            &[
                "Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)",
                "Mozilla/5.0 (compatible; SemrushBot/7~bl; +http://www.semrush.com/bot.html)",
                "Mozilla/5.0 (compatible; MJ12bot/v1.4.8; http://mj12bot.com/)",
                "Mozilla/5.0 (compatible; DotBot/1.2; +https://opensiteexplorer.org/dotbot)",
            ],
            BotCategory::Seo,
        );
    }

    #[test]
    fn names_ai_bots_and_splits_them_by_purpose() {
        let cases = [
            (
                "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; GPTBot/1.2; +https://openai.com/gptbot",
                "GPTBot",
                "OpenAI",
                BotPurpose::AiTraining,
            ),
            (
                "Mozilla/5.0 (compatible; ClaudeBot/1.0; +claudebot@anthropic.com)",
                "ClaudeBot",
                "Anthropic",
                BotPurpose::AiTraining,
            ),
            ("CCBot/2.0 (https://commoncrawl.org/faq/)", "CCBot", "Common Crawl", BotPurpose::AiTraining),
            (
                "Mozilla/5.0 (compatible; OAI-SearchBot/1.0; +https://openai.com/searchbot)",
                "OAI-SearchBot",
                "OpenAI",
                BotPurpose::AiSearch,
            ),
            ("Mozilla/5.0 (compatible; PerplexityBot/1.0)", "PerplexityBot", "Perplexity", BotPurpose::AiSearch),
            (
                "Mozilla/5.0 (compatible; ChatGPT-User/1.0; +https://openai.com/bot)",
                "ChatGPT-User",
                "OpenAI",
                BotPurpose::AiAgent,
            ),
            ("Mozilla/5.0 (compatible; Claude-User/1.0)", "Claude-User", "Anthropic", BotPurpose::AiAgent),
            ("Mozilla/5.0 (compatible; Perplexity-User/1.0)", "Perplexity-User", "Perplexity", BotPurpose::AiAgent),
            ("claude-code/1.0.0", "Claude Code", "Anthropic", BotPurpose::AiAgent),
            ("Google-Agent", "Google-Agent", "Google", BotPurpose::AiAgent),
        ];
        for (user_agent, name, operator, purpose) in cases {
            let classification = classify_ua(user_agent);
            assert!(classification.is_bot, "{user_agent}");
            assert_eq!(classification.category, Some(BotCategory::Ai), "{user_agent}");
            assert_eq!(classification.name, Some(name), "{user_agent}");
            assert_eq!(classification.operator, Some(operator), "{user_agent}");
            assert_eq!(classification.purpose, Some(purpose), "{user_agent}");
        }
    }

    #[test]
    fn names_bots_outside_the_ai_family_too() {
        let ahrefs = classify_ua("Mozilla/5.0 (compatible; AhrefsBot/7.0)");
        assert_eq!(
            (ahrefs.name, ahrefs.operator, ahrefs.purpose),
            (Some("AhrefsBot"), Some("Ahrefs"), Some(BotPurpose::Seo))
        );
        let facebook = classify_ua("facebookexternalhit/1.1");
        assert_eq!(
            (facebook.name, facebook.operator, facebook.purpose),
            (Some("facebookexternalhit"), Some("Meta"), Some(BotPurpose::SocialPreview))
        );
        let requests = classify_ua("python-requests/2.31.0");
        assert_eq!(
            (requests.name, requests.operator, requests.purpose),
            (Some("python-requests"), None, Some(BotPurpose::Scripted))
        );
    }

    #[test]
    fn leaves_identity_null_for_a_generic_upstream_match() {
        let classification = classify_ua("Mozilla/5.0 (compatible; SomeUnknownCrawler/3.1)");
        assert!(classification.is_bot);
        assert_eq!((classification.name, classification.operator, classification.purpose), (None, None, None));
    }

    #[test]
    fn returns_null_identity_for_a_non_bot() {
        let classification = classify_ua("Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 Chrome/120 Safari/537.36");
        assert!(!classification.is_bot);
        assert_eq!((classification.name, classification.operator, classification.purpose), (None, None, None));
    }

    #[test]
    fn is_bot_ua_agrees_with_classify_ua() {
        assert!(is_bot_ua("Googlebot/2.1"));
        assert!(!is_bot_ua("Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 Chrome/120 Safari/537.36"));
    }

    #[test]
    fn cache_returns_what_a_fresh_classification_would() {
        for user_agent in ["curl/8.4.0", "Mozilla/5.0 Chrome/120", "Googlebot/2.1"] {
            assert_eq!(classify_ua(user_agent), classify_ua_uncached(user_agent));
            assert_eq!(classify_ua(user_agent), classify_ua_uncached(user_agent));
        }
        let mut cache = ClassifyCache { young: HashMap::new(), old: HashMap::new() };
        for index in 0..(CLASSIFY_CACHE_MAX * 3) {
            cache.insert(format!("agent {index}"), NON_BOT);
        }
        assert!(cache.young.len() + cache.old.len() <= CLASSIFY_CACHE_MAX);
    }
}
