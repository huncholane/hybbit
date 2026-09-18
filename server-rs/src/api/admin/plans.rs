//! The plan tables from server/src/lib/const.ts that the admin screens read:
//! `getStripePrices()`, `APPSUMO_TIER_LIMITS` and `DEFAULT_EVENT_LIMIT`.
//!
//! No billing runs in this deployment (see PORT_PLAN.md), so nothing here talks
//! to Stripe. The names and limits are still needed, because `/subscription-plans`
//! lists them and `subscription-override` validates a preset against them.
//! `getStripePrices()` swaps in test price ids without `sk_live`, which changes
//! only `priceId` - a member no admin route ever sends - so the list below keeps
//! name, interval and event limit and nothing else, in the array's order,
//! duplicated legacy annual entries included.

/// `DEFAULT_EVENT_LIMIT`
pub const DEFAULT_EVENT_LIMIT: f64 = 3_000.0;

/// One entry of `STRIPE_PRICES`, as far as the admin routes look at it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StripePlan {
    pub name: &'static str,
    pub interval: &'static str,
    pub events: u64,
}

/// `getStripePrices()` in array order.
pub const STRIPE_PRICES: &[StripePlan] = &{
    const fn plan(name: &'static str, interval: &'static str, events: u64) -> StripePlan {
        StripePlan { name, interval, events }
    }
    [
        plan("basic100k", "month", 100_000),
        plan("basic100k-annual", "year", 100_000),
        plan("basic250k", "month", 250_000),
        plan("basic250k-annual", "year", 250_000),
        plan("standard100k", "month", 100_000),
        plan("standard100k-annual", "year", 100_000),
        plan("standard250k", "month", 250_000),
        plan("standard250k-annual", "year", 250_000),
        plan("standard500k", "month", 500_000),
        plan("standard500k-annual", "year", 500_000),
        plan("standard1m", "month", 1_000_000),
        plan("standard1m-annual", "year", 1_000_000),
        plan("standard2m", "month", 2_000_000),
        plan("standard2m-annual", "year", 2_000_000),
        plan("standard5m", "month", 5_000_000),
        plan("standard5m-annual", "year", 5_000_000),
        plan("standard10m", "month", 10_000_000),
        plan("standard10m-annual", "year", 10_000_000),
        plan("standard20m", "month", 20_000_000),
        plan("standard20m-annual", "year", 20_000_000),
        plan("standard30m", "month", 30_000_000),
        plan("standard30m-annual", "year", 30_000_000),
        plan("standard40m", "month", 40_000_000),
        plan("standard40m-annual", "year", 40_000_000),
        plan("standard50m", "month", 50_000_000),
        plan("standard50m-annual", "year", 50_000_000),
        plan("pro100k", "month", 100_000),
        plan("pro100k-annual", "year", 100_000),
        plan("pro250k", "month", 250_000),
        plan("pro250k-annual", "year", 250_000),
        plan("pro500k", "month", 500_000),
        plan("pro500k-annual", "year", 500_000),
        plan("pro1m", "month", 1_000_000),
        plan("pro1m-annual", "year", 1_000_000),
        plan("pro2m", "month", 2_000_000),
        plan("pro2m-annual", "year", 2_000_000),
        plan("pro5m", "month", 5_000_000),
        plan("pro5m-annual", "year", 5_000_000),
        plan("pro10m", "month", 10_000_000),
        plan("pro10m-annual", "year", 10_000_000),
        plan("pro20m", "month", 20_000_000),
        plan("pro20m-annual", "year", 20_000_000),
        plan("pro30m", "month", 30_000_000),
        plan("pro30m-annual", "year", 30_000_000),
        plan("pro40m", "month", 40_000_000),
        plan("pro40m-annual", "year", 40_000_000),
        plan("pro50m", "month", 50_000_000),
        plan("pro50m-annual", "year", 50_000_000),
        // Legacy annual price ids (old 10-month pricing); the names repeat, and
        // `/subscription-plans` prints every entry, duplicates included.
        plan("standard100k-annual", "year", 100_000),
        plan("standard250k-annual", "year", 250_000),
        plan("standard500k-annual", "year", 500_000),
        plan("standard1m-annual", "year", 1_000_000),
        plan("standard2m-annual", "year", 2_000_000),
        plan("standard5m-annual", "year", 5_000_000),
        plan("standard10m-annual", "year", 10_000_000),
        plan("standard20m-annual", "year", 20_000_000),
        plan("pro100k-annual", "year", 100_000),
        plan("pro250k-annual", "year", 250_000),
        plan("pro500k-annual", "year", 500_000),
        plan("pro1m-annual", "year", 1_000_000),
        plan("pro2m-annual", "year", 2_000_000),
        plan("pro5m-annual", "year", 5_000_000),
    ]
};

/// `APPSUMO_TIER_LIMITS`, in `Object.entries` order (the insertion order of the
/// integer-like keys, which V8 sorts numerically - the same order here).
pub const APPSUMO_TIER_LIMITS: &[(&str, u64)] = &[
    ("1", 20_000),
    ("2", 100_000),
    ("3", 250_000),
    ("4", 500_000),
    ("5", 1_000_000),
    ("6", 2_000_000),
    ("7", 3_000_000),
];

/// `getStripePrices().find(plan => plan.name === name)`: the first entry with
/// this name, which is what both the override validation and the event limit read.
pub fn find_stripe_plan(name: &str) -> Option<&'static StripePlan> {
    STRIPE_PRICES.iter().find(|plan| plan.name == name)
}

/// `APPSUMO_TIER_LIMITS[tier]`
pub fn appsumo_tier_limit(tier: &str) -> Option<u64> {
    APPSUMO_TIER_LIMITS.iter().find(|(key, _)| *key == tier).map(|(_, limit)| *limit)
}

/// `/^appsumo-([1-7])$/.exec(value)?.[1]`
pub fn appsumo_override_tier(value: &str) -> Option<&str> {
    let tier = value.strip_prefix("appsumo-")?;
    (tier.len() == 1 && matches!(tier.as_bytes()[0], b'1'..=b'7')).then_some(tier)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plan_table_matches_const_ts() {
        assert_eq!(STRIPE_PRICES.len(), 62);
        assert_eq!(find_stripe_plan("pro1m").map(|plan| plan.events), Some(1_000_000));
        // The first entry wins for a name the legacy block repeats
        assert_eq!(find_stripe_plan("standard100k-annual").map(|plan| plan.interval), Some("year"));
        assert_eq!(find_stripe_plan("nope"), None);
    }

    #[test]
    fn appsumo_overrides() {
        assert_eq!(appsumo_override_tier("appsumo-4"), Some("4"));
        assert_eq!(appsumo_override_tier("appsumo-8"), None);
        assert_eq!(appsumo_override_tier("appsumo-"), None);
        assert_eq!(appsumo_override_tier("appsumo-44"), None);
        assert_eq!(appsumo_tier_limit("4"), Some(500_000));
    }
}
