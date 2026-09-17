//! `getDeviceType` from server/src/utils.ts: the OS family decides when it is
//! known, screen size otherwise.

use super::ParsedUserAgent;

const DESKTOP_OS: &[&str] = &[
    "AIX", "macOS", "Windows", "Linux", "FreeBSD", "OpenBSD", "NetBSD", "DragonFly", "Solaris", "Unix", "HP-UX", "QNX",
    "BeOS", "Haiku", "OS/2", "ArcaOS", "OpenVMS", "RISC OS", "Plan9", "Hurd", "GNU", "Minix", "SerenityOS", "GhostBSD",
    "PC-BSD", "Arch", "CentOS", "Debian", "Deepin", "elementary OS", "Fedora", "Gentoo", "Knoppix", "Kubuntu", "Linpus",
    "Linspire", "Mageia", "Mandriva", "Manjaro", "Mint", "PCLinuxOS", "RedHat", "Sabayon", "Slackware", "SUSE", "Ubuntu",
    "Xubuntu", "VectorLinux", "Zenwalk", "Chrome OS", "Android-x86", "Fuchsia",
];

const MOBILE_OS: &[&str] = &[
    "Android", "iOS", "watchOS", "Windows Phone", "Windows Mobile", "Windows CE", "BlackBerry", "Symbian", "Palm", "Bada",
    "Firefox OS", "KaiOS", "MeeGo", "Maemo", "Sailfish", "Tizen", "WebOS", "HarmonyOS", "OpenHarmony", "RIM Tablet OS",
    "Series40", "Ubuntu Touch", "Joli",
];

const TV_OS: &[&str] = &["Chromecast", "Chromecast Android", "Chromecast Fuchsia", "Chromecast Linux", "Chromecast SmartSpeaker", "NetTV"];

const GAMING_OS: &[&str] = &["PlayStation", "Xbox", "Nintendo"];

const EMBEDDED_OS: &[&str] = &["Windows IoT", "Contiki", "Raspbian", "Morph OS", "Pico", "NetRange"];

/// `getDeviceType(screenWidth, screenHeight, ua)`. The sets are matched with the
/// exact spelling ua-parser-js reports, so e.g. `"webOS"` or `"Chromium OS"` fall
/// through to the screen size, as they do in Node. Screen sizes are JS numbers:
/// NaN makes both comparisons false (`Math.max` propagates it), which lands on
/// "Mobile".
pub fn get_device_type(screen_width: f64, screen_height: f64, ua: &ParsedUserAgent) -> &'static str {
    if let Some(os) = ua.os.name.as_deref().filter(|name| !name.is_empty()) {
        if DESKTOP_OS.contains(&os) {
            return "Desktop";
        } else if MOBILE_OS.contains(&os) {
            return "Mobile";
        } else if TV_OS.contains(&os) {
            return "TV";
        } else if GAMING_OS.contains(&os) {
            return "Console";
        } else if EMBEDDED_OS.contains(&os) {
            return "Embedded";
        }
    }

    let larger = js_math_max(screen_width, screen_height);
    let smaller = js_math_min(screen_width, screen_height);
    if larger > 1024.0 {
        "Desktop"
    } else if larger > 768.0 && smaller > 1024.0 {
        // unreachable in practice (smaller > 1024 implies larger > 1024), kept as Node has it
        "Tablet"
    } else {
        "Mobile"
    }
}

/// `Math.max` for two numbers: NaN if either is NaN (Rust's `f64::max` ignores it).
fn js_math_max(a: f64, b: f64) -> f64 {
    if a.is_nan() || b.is_nan() { f64::NAN } else { a.max(b) }
}

fn js_math_min(a: f64, b: f64) -> f64 {
    if a.is_nan() || b.is_nan() { f64::NAN } else { a.min(b) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ua::parse;

    #[test]
    fn os_family_wins_over_screen_size() {
        let windows = parse("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36");
        assert_eq!(get_device_type(390.0, 844.0, &windows), "Desktop");
        let iphone = parse("Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1");
        assert_eq!(get_device_type(1920.0, 1080.0, &iphone), "Mobile");
        let playstation = parse("Mozilla/5.0 (PlayStation; PlayStation 5/6.50) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.4 Safari/605.1.15");
        assert_eq!(playstation.os.name.as_deref(), Some("PlayStation"));
        assert_eq!(get_device_type(0.0, 0.0, &playstation), "Console");
        let chromecast = parse("Mozilla/5.0 (Fuchsia) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36 CrKey/1.56.500000");
        assert_eq!(get_device_type(0.0, 0.0, &chromecast), "TV");
    }

    #[test]
    fn falls_back_to_screen_size() {
        let unknown = parse("");
        assert_eq!(get_device_type(1920.0, 1080.0, &unknown), "Desktop");
        assert_eq!(get_device_type(1080.0, 1920.0, &unknown), "Desktop");
        assert_eq!(get_device_type(1024.0, 768.0, &unknown), "Mobile");
        assert_eq!(get_device_type(1024.5, 0.0, &unknown), "Desktop");
        assert_eq!(get_device_type(0.0, 0.0, &unknown), "Mobile");
        assert_eq!(get_device_type(f64::NAN, 4000.0, &unknown), "Mobile");
        // ua-parser-js says "webOS" while the set lists "WebOS": the screen decides
        let web_os = parse("Mozilla/5.0 (Web0S; Linux/SmartTV) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36 WebAppManager");
        assert_eq!(web_os.os.name.as_deref(), Some("webOS"));
        assert_eq!(get_device_type(0.0, 0.0, &web_os), "Mobile");
        assert_eq!(get_device_type(1920.0, 1080.0, &web_os), "Desktop");
    }
}
