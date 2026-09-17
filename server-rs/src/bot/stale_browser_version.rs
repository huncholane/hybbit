//! Stale browser major version detection, ported from
//! server/src/services/tracker/botBlocking/staleBrowserVersion.ts.
//!
//! A user agent claiming a browser release older than the cutoff is, in practice,
//! fabricated: the fleets behind this rule rotate a fixed list of old version
//! strings to mint fresh identities (one spans Chrome 39-60 across Android
//! 5.0-8.0), which defeats every per-identity rate rule. Over a day of production
//! traffic, Chrome/Edge/Firefox below the cutoff was 36,807 visitors with 15
//! interaction events in total, so the population is not human and this convicts.

use std::sync::LazyLock;

use super::js::{JsRegex, JsText};

/// Chrome 70 shipped 2018-10 and Firefox 70 2019-10; a browser that old could not
/// run the tracker. Deliberately far behind current so genuinely old but real
/// installs (clustered around 90-110) stay out of scope.
const MIN_SUPPORTED_MAJOR_VERSION: u32 = 70;

/// Version tokens on fast, auto-updating release trains. `Version/` (Safari),
/// `SamsungBrowser`, `OPR` and Android WebView are excluded on purpose.
static VERSION_TOKEN_PATTERN: LazyLock<JsRegex> =
    LazyLock::new(|| JsRegex::new(r"(?:EdgiOS|EdgA|Edge|Edg|CriOS|FxiOS|Firefox|Chrome)\/(\d{1,4})"));

static WEBVIEW_PATTERN: LazyLock<JsRegex> = LazyLock::new(|| JsRegex::new(r"\bwv\b|;\s?wv\)"));

/// `StaleBrowserClassification`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StaleBrowserClassification {
    pub is_stale: bool,
    /// e.g. "Chrome/40", stored as the matched pattern for auditing.
    pub matched_version: Option<String>,
    pub major_version: Option<u32>,
}

const NOT_STALE: StaleBrowserClassification =
    StaleBrowserClassification { is_stale: false, matched_version: None, major_version: None };

/// `classifyStaleBrowserVersion`.
pub fn classify_stale_browser_version(user_agent: &str) -> StaleBrowserClassification {
    if user_agent.is_empty() {
        return NOT_STALE;
    }

    let text = JsText::new(user_agent);
    if WEBVIEW_PATTERN.test(&text) {
        return NOT_STALE;
    }

    let Some(found) = VERSION_TOKEN_PATTERN.exec(&text) else {
        return NOT_STALE;
    };
    // One to four ASCII digits, so the parse cannot fail or overflow.
    let Some(major_version) = text.group(&found, 1).and_then(|digits| digits.parse::<u32>().ok()) else {
        return NOT_STALE;
    };
    if major_version == 0 || major_version >= MIN_SUPPORTED_MAJOR_VERSION {
        return NOT_STALE;
    }

    // `match[0].split("/")[0]`: the token name before the slash.
    let whole = text.group(&found, 0).unwrap_or_default();
    let token = whole.split('/').next().unwrap_or_default();
    StaleBrowserClassification {
        is_stale: true,
        matched_version: Some(format!("{token}/{major_version}")),
        major_version: Some(major_version),
    }
}

#[cfg(test)]
mod tests {
    //! Ported from server/src/services/tracker/botBlocking/staleBrowserVersion.test.ts.
    use super::*;

    fn android_chrome(version: u32) -> String {
        format!(
            "Mozilla/5.0 (Linux; Android 8.0; SM-G930F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{version}.0.0.0 Mobile Safari/537.36"
        )
    }

    fn desktop_chrome(version: u32) -> String {
        format!(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{version}.0.0.0 Safari/537.36"
        )
    }

    #[test]
    fn flags_the_rotating_old_chrome_fleet() {
        assert_eq!(
            classify_stale_browser_version(&android_chrome(39)),
            StaleBrowserClassification {
                is_stale: true,
                matched_version: Some("Chrome/39".into()),
                major_version: Some(39)
            }
        );
        let sixty = classify_stale_browser_version(&android_chrome(60));
        assert!(sixty.is_stale);
        assert_eq!(sixty.major_version, Some(60));
    }

    #[test]
    fn leaves_current_browsers_alone() {
        assert!(!classify_stale_browser_version(&desktop_chrome(151)).is_stale);
        assert!(!classify_stale_browser_version(&android_chrome(150)).is_stale);
    }

    #[test]
    fn leaves_the_cutoff_and_the_older_but_real_range_alone() {
        assert!(!classify_stale_browser_version(&desktop_chrome(70)).is_stale);
        assert!(!classify_stale_browser_version(&desktop_chrome(95)).is_stale);
        assert!(classify_stale_browser_version(&desktop_chrome(69)).is_stale);
    }

    #[test]
    fn ignores_android_webview() {
        assert!(
            !classify_stale_browser_version(
                "Mozilla/5.0 (Linux; Android 11; SM-A115M Build/RP1A; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/43.0.2357.121 Mobile Safari/537.36"
            )
            .is_stale
        );
    }

    #[test]
    fn ignores_safari() {
        assert!(
            !classify_stale_browser_version(
                "Mozilla/5.0 (iPhone; CPU iPhone OS 15_8 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.6 Mobile/15E148 Safari/604.1"
            )
            .is_stale
        );
    }

    #[test]
    fn reads_the_version_token_of_each_supported_release_train() {
        let firefox = classify_stale_browser_version("Mozilla/5.0 Firefox/52.0");
        assert!(firefox.is_stale);
        assert_eq!(firefox.matched_version.as_deref(), Some("Firefox/52"));
        let crios = classify_stale_browser_version(
            "Mozilla/5.0 (iPhone) AppleWebKit/605.1.15 CriOS/48.0.2564.87 Mobile/15E148 Safari/604.1",
        );
        assert!(crios.is_stale);
        assert_eq!(crios.matched_version.as_deref(), Some("CriOS/48"));
        assert!(
            !classify_stale_browser_version(
                "Mozilla/5.0 (Windows NT 10.0) Chrome/151.0.0.0 Safari/537.36 Edg/151.0.0.0"
            )
            .is_stale
        );
    }

    #[test]
    fn ignores_user_agents_with_no_recognizable_version_token() {
        assert!(!classify_stale_browser_version("okhttp/4.12.0").is_stale);
        assert!(!classify_stale_browser_version("").is_stale);
    }

    #[test]
    fn strips_leading_zeros_like_number() {
        assert_eq!(classify_stale_browser_version("Chrome/0040").matched_version.as_deref(), Some("Chrome/40"));
        assert!(!classify_stale_browser_version("Chrome/0000").is_stale);
    }
}
