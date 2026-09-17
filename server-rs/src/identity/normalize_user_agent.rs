//! Version-free user agents for identity hashing, ported from
//! server/src/services/userId/normalizeUserAgent.ts.
//!
//! `generateUserId` hashes the user agent, so every byte of it is part of a
//! visitor's identity, including the version tokens a browser or app update
//! changes. An update would mint a new "user" for the same machine (op.gg's
//! synchronised Electron rollout on 2026-08-14 re-minted every identity at once),
//! so the hash is taken over this view instead: every version number replaced by
//! `#`, while product names, form factors, architectures and device models stay.
//!
//! The Node module is a chain of JavaScript regular expressions and the output is
//! part of the user id hash, so this port must produce byte-identical strings.
//! JavaScript semantics that matter here:
//! - `\b` is an ASCII word boundary (`[A-Za-z0-9_]`); non-ASCII is never a word
//!   character. The Rust patterns spell it `(?-u:\b)`.
//! - Replacement runs left to right over the original string without overlaps,
//!   which is what `Regex::replace_all` does too.
//! - `BARE_VERSION` uses a lookbehind and a lookahead, which the `regex` crate has
//!   no syntax for, so it is a hand-written scanner with the same matches.

use std::sync::LazyLock;

use regex::Regex;

/// Placeholder standing in for every elided version (`ELIDED`).
const ELIDED: &str = "#";

/// `SLASHED_VERSION`: a slash-delimited numeric version, `Chrome/151.0.0.0`,
/// `MyApp/v2.3.1`. Numeric only, so `FBDV/SM-J320F` and `FBDV/iPhone12,8` keep
/// their hardware identifiers.
static SLASHED_VERSION: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"/v?[0-9]+(?:[._][0-9]+)*").expect("SLASHED_VERSION compiles"));

/// `SLASHED_BUILD`: alphanumeric build ids under a key that is unambiguous,
/// `Build/UP1A.231005.007`, `Mobile/15E148`.
static SLASHED_BUILD: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?-u:\b)(Build|Mobile)/[0-9A-Za-z._-]+").expect("SLASHED_BUILD compiles"));

/// `GECKO_REVISION`: Gecko's `rv:153.0`.
static GECKO_REVISION: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?-u:\b)rv:[0-9][0-9._]*").expect("GECKO_REVISION compiles"));

/// `OS_VERSIONS`: OS version numbers, only where an OS name introduces them, so
/// device models keep their digits. Applied in this order.
static OS_VERSIONS: LazyLock<[Regex; 6]> = LazyLock::new(|| {
    [
        r"(?-u:\b)(Windows NT) [0-9][0-9._]*",
        r"(?-u:\b)(Windows Phone(?: OS)?) [0-9][0-9._]*",
        r"(?-u:\b)(Android)[ /][0-9][0-9._]*",
        r"(?-u:\b)(CPU(?: iPhone)? OS) [0-9][0-9._]*",
        r"(?-u:\b)(Mac OS X) [0-9][0-9._]*",
        r"(?-u:\b)(CrOS [^ )]+) [0-9][0-9._]*",
    ]
    .map(|pattern| Regex::new(pattern).expect("OS_VERSIONS compile"))
});

/// `normalizeUserAgentForIdentity`: the identity-bearing view of a user agent,
/// the same string with every version number replaced by `#`.
///
/// Identity only: reporting keeps parsing the raw user agent, and sticky
/// re-attachment keeps matching on the raw string.
pub fn normalize_user_agent_for_identity(user_agent: &str) -> String {
    if user_agent.is_empty() {
        return String::new();
    }

    let normalized = SLASHED_VERSION.replace_all(user_agent, "/#");
    let normalized = SLASHED_BUILD.replace_all(&normalized, "${1}/#").into_owned();
    let mut normalized = GECKO_REVISION.replace_all(&normalized, "rv:#").into_owned();

    for pattern in OS_VERSIONS.iter() {
        normalized = pattern.replace_all(&normalized, "${1} #").into_owned();
    }

    replace_bare_versions(&normalized)
}

/// `BARE_VERSION`, `/(?<=^|[ (;])[0-9]+(?:\.[0-9]+){2,}(?=$|[ );])/g`: a bare,
/// space-delimited dotted version with at least three numeric groups (two would
/// also eat `Nokia 6.1 Plus`).
///
/// Scanned by hand because of the lookarounds. At a candidate start (string start
/// or after one of ` (;`) the greedy match is `digits(.digits)*`; if that has
/// fewer than three groups or is not followed by the end or one of ` );`, no
/// shorter backtracked match can succeed either, because every shorter prefix is
/// followed by a digit or a dot. So the greedy candidate decides the position, as
/// in the JavaScript engine, and scanning resumes one byte later on a miss.
fn replace_bare_versions(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut output = String::with_capacity(input.len());
    let mut copied_until = 0;
    let mut position = 0;

    while position < bytes.len() {
        let preceded_ok = position == 0 || matches!(bytes[position - 1], b' ' | b'(' | b';');
        if preceded_ok
            && bytes[position].is_ascii_digit()
            && let Some(end) = bare_version_end(bytes, position)
        {
            output.push_str(&input[copied_until..position]);
            output.push_str(ELIDED);
            copied_until = end;
            position = end;
            continue;
        }
        position += 1;
    }

    output.push_str(&input[copied_until..]);
    output
}

/// End offset of a `[0-9]+(?:\.[0-9]+){2,}(?=$|[ );])` match starting at `start`.
fn bare_version_end(bytes: &[u8], start: usize) -> Option<usize> {
    let mut end = start;
    while end < bytes.len() && bytes[end].is_ascii_digit() {
        end += 1;
    }

    let mut groups = 1;
    while end + 1 < bytes.len() && bytes[end] == b'.' && bytes[end + 1].is_ascii_digit() {
        end += 1;
        while end < bytes.len() && bytes[end].is_ascii_digit() {
            end += 1;
        }
        groups += 1;
    }

    let followed_ok = end == bytes.len() || matches!(bytes[end], b' ' | b')' | b';');
    (groups >= 3 && followed_ok).then_some(end)
}

#[cfg(test)]
mod tests {
    //! Port of server/src/services/userId/normalizeUserAgent.test.ts. Every fixture
    //! is a real user agent captured off production ingestion (op.gg, 2026-08-18).

    use super::normalize_user_agent_for_identity as normalize;

    const OPGG_ELECTRON_251: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) opgg-electron-app/2.5.1 Chrome/132.0.6834.210 Electron/34.5.7 Safari/537.36";
    const OPGG_ELECTRON_253: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) opgg-electron-app/2.5.3 Chrome/142.0.7444.265 Electron/39.8.13 Safari/537.36";
    const CHROME_WIN_150: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36";
    const CHROME_WIN_151: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36";
    const EDGE_WIN_151: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36 Edg/151.0.0.0";
    const SAFARI_IOS_1857: &str = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.7 Mobile/15E148 Safari/604.1";
    const SAFARI_IOS_266: &str = "Mozilla/5.0 (iPhone; CPU iPhone OS 26_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.6 Mobile/15E148 Safari/604.1";
    const SAFARI_IPAD_266: &str = "Mozilla/5.0 (iPad; CPU OS 26_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.6 Mobile/15E148 Safari/604.1";
    const CHROME_IOS: &str = "Mozilla/5.0 (iPhone; CPU iPhone OS 26_0_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/151.0.7922.112 Mobile/15E148 Safari/604.1";
    const CHROME_IOS_PATCHED: &str = "Mozilla/5.0 (iPhone; CPU iPhone OS 26_0_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/151.0.7922.140 Mobile/15E148 Safari/604.1";
    const MAC_SAFARI: &str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15";
    const ANDROID_S928N: &str = "Mozilla/5.0 (Linux; Android 15; SM-S928N Build/AP3A.240905.015) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Mobile Safari/537.36";
    const ANDROID_A536N: &str = "Mozilla/5.0 (Linux; Android 15; SM-A536N Build/AP3A.240905.015) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Mobile Safari/537.36";
    const REACT_NATIVE: &str = "Mozilla/5.0 (iPhone; CPU iPhone OS 26_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) HygoReactNative/0.1.1 8.0.14";
    const REACT_NATIVE_BUMPED: &str = "Mozilla/5.0 (iPhone; CPU iPhone OS 26_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) HygoReactNative/0.2.0 8.1.0";
    const FIREFOX: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:153.0) Gecko/20100101 Firefox/153.0";
    const FIREFOX_NEXT: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:154.0) Gecko/20100101 Firefox/154.0";
    const FB_IOS_PHONE12: &str = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 [FBAN/FBIOS;FBDV/iPhone12,8;FBAV/440.0.0.32.108]";
    const FB_IOS_PHONE14: &str = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 [FBAN/FBIOS;FBDV/iPhone14,8;FBAV/440.0.0.32.108]";
    const FB_IOS_PHONE12_UPDATED: &str = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 [FBAN/FBIOS;FBDV/iPhone12,8;FBAV/441.0.0.28.90]";
    const FB_ANDROID_J320F: &str = "Mozilla/5.0 (Linux; Android 9; SM-J320F) AppleWebKit/537.36 [FBAN/EMA;FBDV/SM-J320F;FBCA/armeabi-v7a:armeabi;FBAV/239.0.0.10.109]";
    const FB_ANDROID_G930F: &str = "Mozilla/5.0 (Linux; Android 9; SM-G930F) AppleWebKit/537.36 [FBAN/EMA;FBDV/SM-G930F;FBCA/armeabi-v7a:armeabi;FBAV/239.0.0.10.109]";
    const NOKIA_61_PLUS: &str = "Mozilla/5.0 (Linux; Android 10; Nokia 6.1 Plus Build/QKQ1.190828.002; wv) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.7778.178 Mobile Safari/537.36";
    const NOKIA_83_PLUS: &str = "Mozilla/5.0 (Linux; Android 10; Nokia 8.3 Plus Build/QKQ1.190828.002; wv) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.7778.178 Mobile Safari/537.36";

    const ALL: [&str; 25] = [
        OPGG_ELECTRON_251,
        OPGG_ELECTRON_253,
        CHROME_WIN_150,
        CHROME_WIN_151,
        EDGE_WIN_151,
        SAFARI_IOS_1857,
        SAFARI_IOS_266,
        SAFARI_IPAD_266,
        CHROME_IOS,
        CHROME_IOS_PATCHED,
        MAC_SAFARI,
        ANDROID_S928N,
        ANDROID_A536N,
        REACT_NATIVE,
        REACT_NATIVE_BUMPED,
        FIREFOX,
        FIREFOX_NEXT,
        FB_IOS_PHONE12,
        FB_IOS_PHONE14,
        FB_IOS_PHONE12_UPDATED,
        FB_ANDROID_J320F,
        FB_ANDROID_G930F,
        NOKIA_61_PLUS,
        NOKIA_83_PLUS,
        "Mediapartners-Google",
    ];

    fn same(a: &str, b: &str) {
        assert_eq!(normalize(a), normalize(b), "{a:?} and {b:?} should normalize alike");
    }

    fn differs(a: &str, b: &str) {
        assert_ne!(normalize(a), normalize(b), "{a:?} and {b:?} should stay apart");
    }

    // survives updates

    #[test]
    fn collapses_an_electron_app_update() {
        same(OPGG_ELECTRON_251, OPGG_ELECTRON_253);
    }

    #[test]
    fn collapses_a_chrome_major_bump() {
        same(CHROME_WIN_150, CHROME_WIN_151);
    }

    #[test]
    fn collapses_an_ios_point_release() {
        same(SAFARI_IOS_1857, SAFARI_IOS_266);
    }

    #[test]
    fn collapses_a_chrome_on_ios_patch() {
        same(CHROME_IOS, CHROME_IOS_PATCHED);
    }

    #[test]
    fn collapses_a_firefox_bump_including_rv() {
        same(FIREFOX, FIREFOX_NEXT);
    }

    #[test]
    fn collapses_a_react_native_bump_including_the_bare_trailing_version() {
        same(REACT_NATIVE, REACT_NATIVE_BUMPED);
    }

    // keeps distinct devices distinct

    #[test]
    fn separates_browser_families_on_the_same_os() {
        differs(CHROME_WIN_151, EDGE_WIN_151);
    }

    #[test]
    fn separates_firefox_from_chrome() {
        differs(CHROME_WIN_151, FIREFOX);
    }

    #[test]
    fn separates_operating_systems() {
        differs(CHROME_WIN_151, MAC_SAFARI);
    }

    #[test]
    fn separates_iphone_from_ipad() {
        differs(SAFARI_IOS_266, SAFARI_IPAD_266);
    }

    #[test]
    fn separates_safari_from_chrome_on_the_same_iphone() {
        differs(SAFARI_IOS_266, CHROME_IOS);
    }

    #[test]
    fn separates_a_native_app_from_the_browser_on_the_same_os() {
        differs(REACT_NATIVE, SAFARI_IOS_266);
    }

    #[test]
    fn keeps_android_device_models_apart() {
        differs(ANDROID_S928N, ANDROID_A536N);
    }

    // keeps hardware identifiers, which never change under the user

    #[test]
    fn keeps_the_ios_device_model_in_a_facebook_in_app_user_agent() {
        assert!(normalize(FB_IOS_PHONE12).contains("FBDV/iPhone12,8"));
    }

    #[test]
    fn separates_two_iphone_models_behind_the_same_in_app_browser() {
        differs(FB_IOS_PHONE12, FB_IOS_PHONE14);
    }

    #[test]
    fn still_collapses_the_in_app_browsers_own_version_bump() {
        same(FB_IOS_PHONE12, FB_IOS_PHONE12_UPDATED);
    }

    #[test]
    fn keeps_the_android_model_and_cpu_abi_in_a_facebook_in_app_user_agent() {
        let normalized = normalize(FB_ANDROID_J320F);
        assert!(normalized.contains("FBDV/SM-J320F"));
        assert!(normalized.contains("FBCA/armeabi-v7a:armeabi"));
    }

    #[test]
    fn separates_two_android_models_behind_the_same_in_app_browser() {
        differs(FB_ANDROID_J320F, FB_ANDROID_G930F);
    }

    #[test]
    fn keeps_a_dotted_marketing_model_name() {
        assert!(normalize(NOKIA_61_PLUS).contains("Nokia 6.1 Plus"));
    }

    #[test]
    fn separates_two_handsets_whose_model_names_differ_only_in_their_digits() {
        differs(NOKIA_61_PLUS, NOKIA_83_PLUS);
    }

    // mechanics

    #[test]
    fn elides_every_version_token_in_a_representative_desktop_ua() {
        assert_eq!(
            normalize(CHROME_WIN_151),
            "Mozilla/# (Windows NT #; Win64; x64) AppleWebKit/# (KHTML, like Gecko) Chrome/# Safari/#"
        );
    }

    #[test]
    fn keeps_the_android_model_while_eliding_the_os_and_build() {
        assert_eq!(
            normalize(ANDROID_S928N),
            "Mozilla/# (Linux; Android #; SM-S928N Build/#) AppleWebKit/# (KHTML, like Gecko) Chrome/# Mobile Safari/#"
        );
    }

    #[test]
    fn is_idempotent() {
        for ua in ALL {
            let once = normalize(ua);
            assert_eq!(normalize(&once), once, "{ua:?}");
        }
    }

    #[test]
    fn passes_an_empty_user_agent_through_untouched() {
        assert_eq!(normalize(""), "");
    }

    #[test]
    fn leaves_a_version_free_user_agent_alone() {
        assert_eq!(normalize("Mediapartners-Google"), "Mediapartners-Google");
    }

    /// JavaScript's `\b` treats non-ASCII as non-word, so a key right after an
    /// accented letter still starts a word; a Unicode `\b` would not.
    #[test]
    fn word_boundaries_are_ascii_like_javascript() {
        assert_eq!(normalize("éBuild/AB12"), "éBuild/#");
        assert_eq!(normalize("xBuild/AB12"), "xBuild/AB12");
        assert_eq!(normalize("1.2.3 (4.5.6;7.8.9)"), "# (#;#)");
        assert_eq!(normalize("a1.2.3 1.2.3x 1.2.3."), "a1.2.3 1.2.3x 1.2.3.");
    }
}
