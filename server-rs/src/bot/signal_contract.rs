//! The Bot Signal contract, ported from shared/src/botSignalContract.ts: the wire
//! format of the tracker's `_bs` score and `_bsm` bitmask.
//!
//! The tracker, the Node server and this port must agree bit for bit, so the bit
//! layout, the weights, the plausible-dimension bounds and the implausible
//! viewport list are transcribed from the shared package in its declaration
//! order (which is also the order Node iterates them in, for stats labels and
//! signal lists).

use serde::Serialize;

/// `ClientBotSignalName`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ClientBotSignal {
    AutomationApi,
    ZeroOuterDimensions,
    MissingChrome,
    SwiftShader,
    EmptyPlugins,
    #[serde(rename = "defaultViewport800x600")]
    DefaultViewport800x600,
    #[serde(rename = "defaultViewport1024x768")]
    DefaultViewport1024x768,
    ImpossibleDimensions,
    OuterDimensionsWeird,
    PluginApiAbsence,
    #[serde(rename = "defaultViewport1280x1200")]
    DefaultViewport1280x1200,
    SquareScreen,
    MissingScreenDimensions,
}

impl ClientBotSignal {
    /// `CLIENT_BOT_SIGNAL_NAMES`, in `CLIENT_BOT_SIGNAL_MASKS` declaration order.
    pub const ALL: [ClientBotSignal; 13] = [
        ClientBotSignal::AutomationApi,
        ClientBotSignal::ZeroOuterDimensions,
        ClientBotSignal::MissingChrome,
        ClientBotSignal::SwiftShader,
        ClientBotSignal::EmptyPlugins,
        ClientBotSignal::DefaultViewport800x600,
        ClientBotSignal::DefaultViewport1024x768,
        ClientBotSignal::ImpossibleDimensions,
        ClientBotSignal::OuterDimensionsWeird,
        ClientBotSignal::PluginApiAbsence,
        ClientBotSignal::DefaultViewport1280x1200,
        ClientBotSignal::SquareScreen,
        ClientBotSignal::MissingScreenDimensions,
    ];

    /// `CLIENT_BOT_SIGNAL_MASKS[name]`.
    pub const fn mask(self) -> i32 {
        match self {
            ClientBotSignal::AutomationApi => 1 << 0,
            ClientBotSignal::ZeroOuterDimensions => 1 << 1,
            ClientBotSignal::MissingChrome => 1 << 2,
            ClientBotSignal::SwiftShader => 1 << 3,
            ClientBotSignal::EmptyPlugins => 1 << 4,
            ClientBotSignal::DefaultViewport800x600 => 1 << 5,
            ClientBotSignal::DefaultViewport1024x768 => 1 << 6,
            ClientBotSignal::ImpossibleDimensions => 1 << 7,
            ClientBotSignal::OuterDimensionsWeird => 1 << 8,
            ClientBotSignal::PluginApiAbsence => 1 << 9,
            ClientBotSignal::DefaultViewport1280x1200 => 1 << 10,
            ClientBotSignal::SquareScreen => 1 << 11,
            ClientBotSignal::MissingScreenDimensions => 1 << 12,
        }
    }

    /// `CLIENT_BOT_SIGNAL_WEIGHTS[name]`.
    pub const fn weight(self) -> i64 {
        match self {
            ClientBotSignal::AutomationApi => 3,
            ClientBotSignal::ZeroOuterDimensions => 2,
            ClientBotSignal::MissingChrome => 1,
            ClientBotSignal::SwiftShader => 1,
            ClientBotSignal::EmptyPlugins => 1,
            ClientBotSignal::DefaultViewport800x600 => 3,
            ClientBotSignal::DefaultViewport1024x768 => 3,
            ClientBotSignal::ImpossibleDimensions => 3,
            ClientBotSignal::OuterDimensionsWeird => 2,
            ClientBotSignal::PluginApiAbsence => 0,
            ClientBotSignal::DefaultViewport1280x1200 => 3,
            ClientBotSignal::SquareScreen => 3,
            ClientBotSignal::MissingScreenDimensions => 1,
        }
    }

    /// The contract's name for the signal, as logged and used for stats fields.
    pub const fn name(self) -> &'static str {
        match self {
            ClientBotSignal::AutomationApi => "automationApi",
            ClientBotSignal::ZeroOuterDimensions => "zeroOuterDimensions",
            ClientBotSignal::MissingChrome => "missingChrome",
            ClientBotSignal::SwiftShader => "swiftShader",
            ClientBotSignal::EmptyPlugins => "emptyPlugins",
            ClientBotSignal::DefaultViewport800x600 => "defaultViewport800x600",
            ClientBotSignal::DefaultViewport1024x768 => "defaultViewport1024x768",
            ClientBotSignal::ImpossibleDimensions => "impossibleDimensions",
            ClientBotSignal::OuterDimensionsWeird => "outerDimensionsWeird",
            ClientBotSignal::PluginApiAbsence => "pluginApiAbsence",
            ClientBotSignal::DefaultViewport1280x1200 => "defaultViewport1280x1200",
            ClientBotSignal::SquareScreen => "squareScreen",
            ClientBotSignal::MissingScreenDimensions => "missingScreenDimensions",
        }
    }
}

/// `ALL_CLIENT_BOT_SIGNAL_BITS`: every bit the contract defines, and the largest
/// `_bsm` a current tracker can send.
pub const ALL_CLIENT_BOT_SIGNAL_BITS: i32 = {
    let mut mask = 0;
    let mut index = 0;
    while index < ClientBotSignal::ALL.len() {
        mask |= ClientBotSignal::ALL[index].mask();
        index += 1;
    }
    mask
};

/// `STRONG_CLIENT_BOT_SIGNAL_BITS`: signals automation-specific enough to convict
/// on their own. The rest occur on real devices and only corroborate.
pub const STRONG_CLIENT_BOT_SIGNAL_BITS: i32 = ClientBotSignal::AutomationApi.mask()
    | ClientBotSignal::ImpossibleDimensions.mask()
    | ClientBotSignal::DefaultViewport800x600.mask()
    | ClientBotSignal::DefaultViewport1024x768.mask()
    | ClientBotSignal::DefaultViewport1280x1200.mask()
    | ClientBotSignal::SquareScreen.mask();

/// `MAX_CLIENT_BOT_SCORE`: upper bound on the reported bot score.
pub const MAX_CLIENT_BOT_SCORE: i64 = 10;

/// `MIN_PLAUSIBLE_SCREEN_DIMENSION` / `MAX_PLAUSIBLE_SCREEN_DIMENSION`: the smallest
/// real phone screens report about 240 CSS px and the largest single display 7680.
pub const MIN_PLAUSIBLE_SCREEN_DIMENSION: f64 = 200.0;
pub const MAX_PLAUSIBLE_SCREEN_DIMENSION: f64 = 8192.0;

/// `IMPLAUSIBLE_DESKTOP_VIEWPORTS`: default automation and display-server
/// geometries, implausible on a desktop user agent.
pub const IMPLAUSIBLE_DESKTOP_VIEWPORTS: [(f64, f64, ClientBotSignal); 3] = [
    (800.0, 600.0, ClientBotSignal::DefaultViewport800x600),
    (1024.0, 768.0, ClientBotSignal::DefaultViewport1024x768),
    (1280.0, 1200.0, ClientBotSignal::DefaultViewport1280x1200),
];

/// JavaScript's ToInt32, which every `&` on a mask goes through.
pub fn to_int32(value: i64) -> i32 {
    value as i32
}

/// `isPlausibleScreenDimensions`. NaN stands in for an unreported dimension.
pub fn is_plausible_screen_dimensions(width: f64, height: f64) -> bool {
    width.is_finite()
        && height.is_finite()
        && width >= MIN_PLAUSIBLE_SCREEN_DIMENSION
        && height >= MIN_PLAUSIBLE_SCREEN_DIMENSION
        && width <= MAX_PLAUSIBLE_SCREEN_DIMENSION
        && height <= MAX_PLAUSIBLE_SCREEN_DIMENSION
}

/// `isDesktopUserAgent`: `/Windows NT|Macintosh|X11|Linux x86_64/` and not
/// `/Mobile|Android|iPhone|iPad/`. Both are case-sensitive literal alternations,
/// so substring tests are exact.
pub fn is_desktop_user_agent(user_agent: &str) -> bool {
    ["Windows NT", "Macintosh", "X11", "Linux x86_64"].iter().any(|token| user_agent.contains(token))
        && !["Mobile", "Android", "iPhone", "iPad"].iter().any(|token| user_agent.contains(token))
}

/// `getScreenDimensionSignals`: the screen-geometry rules, evaluated against the
/// reported dimensions. An implausible display short-circuits.
pub fn get_screen_dimension_signals(width: f64, height: f64, user_agent: &str) -> Vec<ClientBotSignal> {
    if !is_plausible_screen_dimensions(width, height) {
        return vec![ClientBotSignal::ImpossibleDimensions];
    }

    let mut signals = Vec::new();
    if width == height {
        signals.push(ClientBotSignal::SquareScreen);
    }
    if is_desktop_user_agent(user_agent) {
        for (viewport_width, viewport_height, signal) in IMPLAUSIBLE_DESKTOP_VIEWPORTS {
            if width == viewport_width && height == viewport_height {
                signals.push(signal);
            }
        }
    }
    signals
}

/// `getClientBotSignalNames`: the signals a mask carries, ignoring undefined bits.
pub fn get_client_bot_signal_names(mask: i32) -> Vec<ClientBotSignal> {
    ClientBotSignal::ALL.into_iter().filter(|signal| mask & signal.mask() != 0).collect()
}

/// `scoreFromMask`: uncapped sum of the weights of the signals a mask carries.
pub fn score_from_mask(mask: i32) -> i64 {
    get_client_bot_signal_names(mask).iter().map(|signal| signal.weight()).sum()
}

#[cfg(test)]
mod tests {
    //! Ported from server/src/services/tracker/botBlocking/botSignalContract.test.ts.
    use std::collections::HashSet;

    use super::*;

    const DESKTOP_UA: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36";
    const MOBILE_UA: &str = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) Mobile/15E148 Safari/604.1";

    #[test]
    fn gives_every_signal_its_own_single_bit() {
        let bits: Vec<i32> = ClientBotSignal::ALL.iter().map(|signal| signal.mask()).collect();
        for bit in &bits {
            assert!(*bit > 0, "each signal occupies exactly one bit");
            assert_eq!(bit & (bit - 1), 0, "{bit} is a power of two");
        }
        assert_eq!(bits.iter().collect::<HashSet<_>>().len(), bits.len(), "no two signals share a bit");
    }

    #[test]
    fn names_match_the_contract() {
        for signal in ClientBotSignal::ALL {
            assert_eq!(serde_json::to_value(signal).unwrap(), signal.name());
        }
    }

    #[test]
    fn bounds_itself_by_the_union_of_every_declared_bit() {
        let union = ClientBotSignal::ALL.iter().fold(0, |mask, signal| mask | signal.mask());
        assert_eq!(ALL_CLIENT_BOT_SIGNAL_BITS, union);
        assert_eq!(ALL_CLIENT_BOT_SIGNAL_BITS, 8191);
        assert_eq!(
            ALL_CLIENT_BOT_SIGNAL_BITS & ClientBotSignal::SquareScreen.mask(),
            ClientBotSignal::SquareScreen.mask()
        );
    }

    #[test]
    fn only_convicts_on_signals_it_also_defines() {
        assert_eq!(STRONG_CLIENT_BOT_SIGNAL_BITS & !ALL_CLIENT_BOT_SIGNAL_BITS, 0);
        const { assert!(STRONG_CLIENT_BOT_SIGNAL_BITS > 0) };
    }

    #[test]
    fn names_the_signals_a_mask_carries_and_ignores_undefined_bits() {
        let mask = ClientBotSignal::AutomationApi.mask() | ClientBotSignal::SquareScreen.mask() | (1 << 30);
        assert_eq!(
            get_client_bot_signal_names(mask),
            vec![ClientBotSignal::AutomationApi, ClientBotSignal::SquareScreen]
        );
    }

    #[test]
    fn scores_a_mask_as_the_sum_of_its_signal_weights() {
        let mask = ClientBotSignal::AutomationApi.mask() | ClientBotSignal::EmptyPlugins.mask();
        assert_eq!(
            score_from_mask(mask),
            ClientBotSignal::AutomationApi.weight() + ClientBotSignal::EmptyPlugins.weight()
        );
        assert_eq!(score_from_mask(0), 0);
        assert_eq!(score_from_mask(1 << 30), 0, "undefined bits carry no weight");
    }

    #[test]
    fn leaves_real_displays_alone() {
        for (width, height) in [
            (1920.0, 1080.0),
            (MIN_PLAUSIBLE_SCREEN_DIMENSION, 320.0),
            (7680.0, 4320.0),
            (MAX_PLAUSIBLE_SCREEN_DIMENSION, 4320.0),
        ] {
            assert_eq!(get_screen_dimension_signals(width, height, DESKTOP_UA), vec![], "{width}x{height}");
        }
    }

    #[test]
    fn flags_displays_no_real_one_reports_and_says_nothing_else() {
        for (width, height) in [(1.0, 1.0), (16384.0, 16384.0), (1920.0, 10000.0), (199.0, 800.0), (f64::NAN, 1080.0)] {
            assert_eq!(
                get_screen_dimension_signals(width, height, DESKTOP_UA),
                vec![ClientBotSignal::ImpossibleDimensions],
                "{width}x{height}"
            );
        }
    }

    #[test]
    fn flags_a_square_screen_on_any_platform() {
        assert_eq!(get_screen_dimension_signals(2000.0, 2000.0, DESKTOP_UA), vec![ClientBotSignal::SquareScreen]);
        assert_eq!(get_screen_dimension_signals(2000.0, 2000.0, MOBILE_UA), vec![ClientBotSignal::SquareScreen]);
    }

    #[test]
    fn flags_default_automation_viewports_on_desktop_user_agents_only() {
        for (width, height, signal) in IMPLAUSIBLE_DESKTOP_VIEWPORTS {
            assert!(get_screen_dimension_signals(width, height, DESKTOP_UA).contains(&signal));
            assert_eq!(get_screen_dimension_signals(width, height, MOBILE_UA), vec![]);
        }
    }

    #[test]
    fn produces_signals_the_weights_table_can_score() {
        let mut signals = get_screen_dimension_signals(1.0, 1.0, DESKTOP_UA);
        signals.extend(get_screen_dimension_signals(2000.0, 2000.0, DESKTOP_UA));
        for (width, height, _) in IMPLAUSIBLE_DESKTOP_VIEWPORTS {
            signals.extend(get_screen_dimension_signals(width, height, DESKTOP_UA));
        }
        for signal in signals {
            assert!(signal.mask() > 0, "{signal:?} is in the mask table");
            assert!(signal.weight() > 0, "{signal:?} is in the weights table");
        }
    }
}
