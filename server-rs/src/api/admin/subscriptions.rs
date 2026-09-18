//! `getOrganizationSubscriptions` from server/src/services/admin/subscriptionService.ts,
//! reduced to the answer it gives without billing.
//!
//! Node builds the map from three sources. Two of them are inert here:
//! `fetchSubscriptionsForCustomers` returns nothing because `stripe` is null
//! without `STRIPE_SECRET_KEY`, and `fetchAppSumoLicensesForOrganizations`
//! queries `appsumo.licenses`, a schema self-hosted installs do not have, so its
//! own try/catch swallows the failure and returns nothing. What is left is the
//! custom plan, the plan override and the free fallback, which is exactly what
//! this module computes. `stripeDashboardUrl` is still built from a stored
//! `stripeCustomerId`, because the column survives even where Stripe does not.

use chrono::{DateTime, Datelike, Local, NaiveDate, TimeZone, Utc};
use tracing::debug;

use crate::analytics::js::{JsObject, JsValue};

use super::plans::{DEFAULT_EVENT_LIMIT, appsumo_override_tier, appsumo_tier_limit, find_stripe_plan};

/// The organization columns the subscription answer reads.
#[derive(Clone, Debug)]
pub struct OrganizationPlan {
    /// `organization.planOverride`
    pub plan_override: Option<String>,
    /// `organization.customPlan`, the jsonb value as postgres.js parses it
    pub custom_plan: JsValue,
}

/// The two month boundaries the service stamps onto every subscription:
/// `DateTime.now().startOf("month")` and the same plus a month, both as the
/// `Date` values `JSON.stringify` prints with `toISOString`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MonthBounds {
    pub current_period_start: String,
    pub next_month_start: String,
}

fn month_start_instant(year: i32, month: u32) -> DateTime<Utc> {
    let naive = NaiveDate::from_ymd_opt(year, month, 1)
        .unwrap_or_else(|| NaiveDate::from_ymd_opt(1970, 1, 1).expect("epoch"))
        .and_hms_opt(0, 0, 0)
        .expect("midnight");
    // Luxon resolves a local time that a DST gap skips by moving forward; the
    // earliest mapping is the same instant for every zone that has a midnight.
    Local
        .from_local_datetime(&naive)
        .earliest()
        .map(|local| local.with_timezone(&Utc))
        .unwrap_or_else(|| Utc.from_utc_datetime(&naive))
}

/// `new Date(...).toISOString()`.
fn to_iso(instant: DateTime<Utc>) -> String {
    instant.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()
}

impl MonthBounds {
    /// Both boundaries from one reading of the clock, as Node takes them.
    pub fn now() -> Self {
        let local = Local::now();
        let (year, month) = (local.year(), local.month());
        let (next_year, next_month) = if month == 12 { (year + 1, 1) } else { (year, month + 1) };
        let bounds = Self {
            current_period_start: to_iso(month_start_instant(year, month)),
            next_month_start: to_iso(month_start_instant(next_year, next_month)),
        };
        debug!(
            current_period_start = %bounds.current_period_start,
            next_month_start = %bounds.next_month_start,
            "Resolved the admin subscription month bounds"
        );
        bounds
    }
}

/// `value ?? null` for a member read off a stored custom plan.
fn nullish(value: &JsValue) -> JsValue {
    match value {
        JsValue::Undefined | JsValue::Null => JsValue::Null,
        other => other.clone(),
    }
}

/// `object[key]` where the object may be any stored jsonb value.
fn member(value: &JsValue, key: &str) -> JsValue {
    match value {
        JsValue::Object(object) => object.get_or_undefined(key).clone(),
        _ => JsValue::Undefined,
    }
}

/// The `...(includeFullDetails ? {...} : {})` tail the custom, override and
/// AppSumo branches share.
fn push_full_details(target: &mut JsObject, bounds: &MonthBounds, interval: &str) {
    target.insert("currentPeriodStart", JsValue::String(bounds.current_period_start.clone()));
    target.insert("cancelAtPeriodEnd", JsValue::Bool(false));
    target.insert("interval", JsValue::String(interval.to_string()));
}

/// One organization's entry of `getOrganizationSubscriptions(orgs, includeFullDetails)`.
/// Members are inserted in the order the object literals name them, because the
/// admin screens receive this object verbatim.
pub fn organization_subscription(org: &OrganizationPlan, include_full_details: bool, bounds: &MonthBounds) -> JsValue {
    let mut subscription = JsObject::new();

    // A stored custom plan wins, whatever the override says
    if org.custom_plan.is_truthy() {
        subscription.insert("id", JsValue::String(String::new()));
        subscription.insert("source", JsValue::String("custom".into()));
        subscription.insert("planName", JsValue::String("custom".into()));
        subscription.insert("status", JsValue::String("active".into()));
        subscription.insert("eventLimit", member(&org.custom_plan, "events"));
        subscription.insert("memberLimit", nullish(&member(&org.custom_plan, "members")));
        subscription.insert("siteLimit", nullish(&member(&org.custom_plan, "websites")));
        subscription.insert("currentPeriodEnd", JsValue::String(bounds.next_month_start.clone()));
        if include_full_details {
            push_full_details(&mut subscription, bounds, "lifetime");
        }
        return JsValue::Object(subscription);
    }

    if let Some(plan_override) = org.plan_override.as_deref().filter(|value| !value.is_empty()) {
        let appsumo_tier = appsumo_override_tier(plan_override);
        let plan = find_stripe_plan(plan_override);
        if appsumo_tier.is_some() || plan.is_some() {
            let event_limit = match appsumo_tier {
                // `APPSUMO_TIER_LIMITS[match[1]]` for a tier the regex accepted
                Some(tier) => appsumo_tier_limit(tier).map_or(JsValue::Undefined, |limit| JsValue::Number(limit as f64)),
                None => JsValue::Number(plan.expect("a plan or a tier matched").events as f64),
            };
            subscription.insert("id", JsValue::String(String::new()));
            subscription.insert("source", JsValue::String("override".into()));
            subscription.insert("planName", JsValue::String(plan_override.to_string()));
            subscription.insert("status", JsValue::String("active".into()));
            subscription.insert("eventLimit", event_limit);
            subscription.insert("currentPeriodEnd", JsValue::String(bounds.next_month_start.clone()));
            if include_full_details {
                // `plan?.interval ?? "lifetime"`
                push_full_details(&mut subscription, bounds, plan.map_or("lifetime", |plan| plan.interval));
            }
            return JsValue::Object(subscription);
        }
        debug!(plan_override, "Plan override names no known plan; the organization reads as free");
    }

    // No Stripe subscription and no AppSumo licence can exist here, so free it is
    subscription.insert("id", JsValue::String(String::new()));
    subscription.insert("source", JsValue::String("free".into()));
    subscription.insert("planName", JsValue::String("free".into()));
    subscription.insert("status", JsValue::String("free".into()));
    subscription.insert("eventLimit", JsValue::Number(DEFAULT_EVENT_LIMIT));
    subscription.insert("currentPeriodEnd", JsValue::String(bounds.next_month_start.clone()));
    JsValue::Object(subscription)
}

/// `stripeDashboardUrl`: the test path, because `STRIPE_SECRET_KEY` never starts
/// with `sk_live` in a deployment with no billing.
pub fn stripe_dashboard_url(stripe_customer_id: Option<&str>) -> JsValue {
    match stripe_customer_id {
        Some(id) => JsValue::String(format!("https://dashboard.stripe.com/test/customers/{id}")),
        None => JsValue::Null,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analytics::js::json::{parse, stringify};

    fn bounds() -> MonthBounds {
        MonthBounds {
            current_period_start: "2026-09-01T00:00:00.000Z".into(),
            next_month_start: "2026-10-01T00:00:00.000Z".into(),
        }
    }

    fn rendered(plan_override: Option<&str>, custom_plan: &str, full: bool) -> String {
        let org = OrganizationPlan {
            plan_override: plan_override.map(str::to_string),
            custom_plan: parse(custom_plan).expect("valid JSON"),
        };
        stringify(&organization_subscription(&org, full, &bounds())).expect("object")
    }

    #[test]
    fn free_is_the_fallback() {
        assert_eq!(
            rendered(None, "null", true),
            r#"{"id":"","source":"free","planName":"free","status":"free","eventLimit":3000,"currentPeriodEnd":"2026-10-01T00:00:00.000Z"}"#
        );
        // An override naming no plan falls through to free
        assert_eq!(rendered(Some("secret-tier"), "null", false), rendered(None, "null", false));
    }

    #[test]
    fn overrides_carry_their_limits() {
        assert_eq!(
            rendered(Some("appsumo-4"), "null", true),
            concat!(
                r#"{"id":"","source":"override","planName":"appsumo-4","status":"active","eventLimit":500000,"#,
                r#""currentPeriodEnd":"2026-10-01T00:00:00.000Z","currentPeriodStart":"2026-09-01T00:00:00.000Z","#,
                r#""cancelAtPeriodEnd":false,"interval":"lifetime"}"#
            )
        );
        assert_eq!(
            rendered(Some("pro1m"), "null", true),
            concat!(
                r#"{"id":"","source":"override","planName":"pro1m","status":"active","eventLimit":1000000,"#,
                r#""currentPeriodEnd":"2026-10-01T00:00:00.000Z","currentPeriodStart":"2026-09-01T00:00:00.000Z","#,
                r#""cancelAtPeriodEnd":false,"interval":"month"}"#
            )
        );
    }

    #[test]
    fn a_custom_plan_wins_over_an_override() {
        assert_eq!(
            rendered(Some("pro1m"), r#"{"events":1234,"members":null,"websites":7}"#, false),
            concat!(
                r#"{"id":"","source":"custom","planName":"custom","status":"active","eventLimit":1234,"#,
                r#""memberLimit":null,"siteLimit":7,"currentPeriodEnd":"2026-10-01T00:00:00.000Z"}"#
            )
        );
    }

    #[test]
    fn dashboard_url_uses_the_test_path() {
        assert_eq!(
            stripe_dashboard_url(Some("cus_1")),
            JsValue::String("https://dashboard.stripe.com/test/customers/cus_1".into())
        );
        assert_eq!(stripe_dashboard_url(None), JsValue::Null);
    }
}
