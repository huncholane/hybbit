//! Anonymous user ids, ported from server/src/services/userId/userIdService.ts.
//!
//! A user id is the first 12 hex characters of
//! `sha256(identityIp + identityUserAgent + dailySalt?)`, run through sticky
//! re-attachment. Node computes the same id for the same visitor, so the
//! bucketing, normalization, salt and day selection are exact ports.

use std::{future::Future, sync::Mutex};

use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};

use super::{
    ip_bucket::bucket_ip_for_identity,
    node_asn::lookup_asn_like_node,
    normalize_user_agent::normalize_user_agent_for_identity,
    sticky::{StickyIdentityInput, StickyStore, resolve_sticky_user_id_with, sticky_identity_enabled},
};
use crate::{
    datacenter_asns::is_datacenter_asn,
    geo::AsnLookup,
    site_config::{SiteConfigCache, SiteRef},
};

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum UserIdError {
    /// Node throws `Error("BETTER_AUTH_SECRET environment variable is missing.")`
    /// when a salted Site needs a salt and `SECRET` is unset or empty.
    #[error("BETTER_AUTH_SECRET environment variable is missing.")]
    MissingSecret,
}

/// Where `isSalted` reads a Site's `saltUserIds` when the caller does not know
/// it. Production reads the Site Configuration cache; tests count reads.
pub trait SaltSettingSource: Sync {
    fn salt_user_ids(&self, site_id: i32) -> impl Future<Output = bool> + Send;
}

impl SaltSettingSource for SiteConfigCache {
    /// `!!(await siteConfig.getConfig(siteId))?.saltUserIds`, keyed by the number
    /// like Node's call.
    async fn salt_user_ids(&self, site_id: i32) -> bool {
        // Node's getConfig treats a falsy id (0) as "no Site"
        if site_id == 0 {
            return false;
        }
        self.get_config(&SiteRef::Number(site_id.into())).await.is_some_and(|config| config.salt_user_ids)
    }
}

/// `UserIdOptions`: facts the caller already holds, so they are not looked up again.
#[derive(Clone, Copy, Debug, Default)]
pub struct UserIdOptions {
    /// The Site's salting setting when the caller holds its Site Configuration.
    /// None fetches it from the salt source.
    pub salt_user_ids: Option<bool>,
    /// The moment the event belongs to, the same instant it is timestamped with.
    /// The daily salt is picked for this instant's UTC day, so an event accepted
    /// at 23:59:59.9 is not fingerprinted with the next day's salt. Defaults to now.
    pub received_at: Option<DateTime<Utc>>,
}

/// What `generateUserId` needs besides the request facts.
pub struct UserIdDeps<'a, R, C> {
    /// Sticky identity store (the shared Redis connection in production).
    pub redis: &'a R,
    /// Consulted only when `UserIdOptions::salt_user_ids` is None.
    pub salt_source: &'a C,
    /// Node's `SECRET` (BETTER_AUTH_SECRET). Unset or empty is missing.
    pub secret: Option<&'a str>,
}

/// `UserIdService`. Holds the most recent day's salt, like Node's instance.
#[derive(Default)]
pub struct UserIdService {
    /// (utcDay, salt)
    cached_salt: Mutex<Option<(String, String)>>,
}

/// `utcDayOf`: the UTC day (YYYY-MM-DD) an instant falls in, as
/// `toISOString().split("T")[0]` prints it.
pub fn utc_day_of(instant: DateTime<Utc>) -> String {
    instant.format("%Y-%m-%d").to_string()
}

fn sha256_hex(input: &str) -> String {
    hex::encode(Sha256::digest(input.as_bytes()))
}

impl UserIdService {
    pub fn new() -> Self {
        Self::default()
    }

    /// `getDailySalt`: `sha256(SECRET + utcDay)` as hex, cached for the latest day.
    fn daily_salt(&self, secret: Option<&str>, utc_day: &str) -> Result<String, UserIdError> {
        let Some(secret) = secret.filter(|secret| !secret.is_empty()) else {
            tracing::error!(
                "FATAL: BETTER_AUTH_SECRET environment variable is not set. User ID generation will be insecure or fail."
            );
            return Err(UserIdError::MissingSecret);
        };

        let mut cached = self.cached_salt.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some((day, salt)) = cached.as_ref()
            && day == utc_day
        {
            return Ok(salt.clone());
        }

        let salt = sha256_hex(&format!("{secret}{utc_day}"));
        *cached = Some((utc_day.to_string(), salt.clone()));
        Ok(salt)
    }

    /// `isSalted`
    async fn is_salted<C: SaltSettingSource>(&self, site_id: i32, options: &UserIdOptions, source: &C) -> bool {
        match options.salt_user_ids {
            Some(salted) => salted,
            None => source.salt_user_ids(site_id).await,
        }
    }

    /// `generateUserId`: the anonymous id for an IP and user agent.
    ///
    /// Datacenter egress hashes a /24 or /48 bucket instead of the exact IP, the
    /// user agent is version-stripped, and salted Sites add the event day's salt.
    /// The fingerprint then goes through sticky re-attachment with the raw IP and
    /// raw user agent.
    ///
    /// `asn_lookup` is the request's memoised resolver (Node falls back to the
    /// global `lookupAsn`, which answers the same). The IP string is read the way
    /// Node's `lookupAsn` reads it (see `node_asn`), so spoofed spellings such as
    /// zone ids classify alike on both backends.
    pub async fn generate_user_id<R: StickyStore, C: SaltSettingSource>(
        &self,
        deps: &UserIdDeps<'_, R, C>,
        asn_lookup: &AsnLookup<'_>,
        ip: &str,
        user_agent: &str,
        site_id: i32,
        options: UserIdOptions,
    ) -> Result<String, UserIdError> {
        let is_datacenter_egress = |candidate: &str| is_datacenter_asn(lookup_asn_like_node(asn_lookup, candidate));
        self.generate_user_id_with(
            deps,
            &is_datacenter_egress,
            ip,
            user_agent,
            site_id,
            options,
            None,
            sticky_identity_enabled(),
        )
        .await
    }

    /// `generateUserId` with the datacenter predicate injected (the tests' seam),
    /// an optional fixed clock for sticky resolution, and the sticky switch.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn generate_user_id_with<R: StickyStore, C: SaltSettingSource>(
        &self,
        deps: &UserIdDeps<'_, R, C>,
        is_datacenter_egress: &(dyn Fn(&str) -> bool + Sync),
        ip: &str,
        user_agent: &str,
        site_id: i32,
        options: UserIdOptions,
        sticky_now_ms: Option<i64>,
        sticky_enabled: bool,
    ) -> Result<String, UserIdError> {
        let identity_ip = bucket_ip_for_identity(ip, is_datacenter_egress);
        let identity_user_agent = normalize_user_agent_for_identity(user_agent);

        // The event's own day, fixed before anything is hashed against it
        let salt_day = utc_day_of(options.received_at.unwrap_or_else(Utc::now));
        let salted = self.is_salted(site_id, &options, deps.salt_source).await;
        let salt = if salted { self.daily_salt(deps.secret, &salt_day)? } else { String::new() };

        let raw_user_id = sha256_hex(&format!("{identity_ip}{identity_user_agent}{salt}"))[..12].to_string();
        tracing::debug!(
            site_id,
            salted,
            bucketed = identity_ip != ip,
            raw_user_id = %raw_user_id,
            "Generated identity fingerprint"
        );

        let resolved = resolve_sticky_user_id_with(
            deps.redis,
            StickyIdentityInput {
                site_id,
                raw_user_id: &raw_user_id,
                ip_address: ip,
                user_agent,
                salt_scope: if salted { &salt_day } else { "" },
                now_ms: sticky_now_ms,
                is_datacenter_egress,
            },
            sticky_enabled,
        )
        .await;
        Ok(resolved)
    }

    /// `generateUserIdFromClientId`: the id for a consented, client-supplied
    /// anonymous id, `sha256(`${siteId}:${clientId}:${salt}`)` truncated to 12.
    pub async fn generate_user_id_from_client_id<C: SaltSettingSource>(
        &self,
        salt_source: &C,
        secret: Option<&str>,
        client_id: &str,
        site_id: i32,
        options: UserIdOptions,
    ) -> Result<String, UserIdError> {
        let salt_day = utc_day_of(options.received_at.unwrap_or_else(Utc::now));
        let salt = if self.is_salted(site_id, &options, salt_source).await {
            self.daily_salt(secret, &salt_day)?
        } else {
            String::new()
        };

        Ok(sha256_hex(&format!("{site_id}:{client_id}:{salt}"))[..12].to_string())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    //! Port of server/src/services/userId/userIdService.test.ts.

    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;
    use crate::identity::sticky::tests::RecordingStickyStore;

    /// Counts reads and answers with a fixed setting, like the mocked getConfig.
    pub(crate) struct CountingSaltSource {
        pub salted: bool,
        pub reads: AtomicUsize,
    }

    impl CountingSaltSource {
        pub fn new(salted: bool) -> Self {
            Self { salted, reads: AtomicUsize::new(0) }
        }
    }

    impl SaltSettingSource for CountingSaltSource {
        fn salt_user_ids(&self, _site_id: i32) -> impl Future<Output = bool> + Send {
            self.reads.fetch_add(1, Ordering::SeqCst);
            let salted = self.salted;
            async move { salted }
        }
    }

    fn day_end() -> DateTime<Utc> {
        "2026-08-14T23:59:59.900Z".parse().unwrap()
    }

    fn next_day() -> DateTime<Utc> {
        "2026-08-15T00:00:00.100Z".parse().unwrap()
    }

    fn no_asn(_: &str) -> bool {
        false
    }

    struct Fixture {
        service: UserIdService,
        sticky: RecordingStickyStore,
        salt: CountingSaltSource,
    }

    impl Fixture {
        fn new() -> Self {
            Self {
                service: UserIdService::new(),
                sticky: RecordingStickyStore::passthrough(),
                salt: CountingSaltSource::new(true),
            }
        }

        async fn generate(&self, ip: &str, ua: &str, options: UserIdOptions) -> String {
            let deps = UserIdDeps { redis: &self.sticky, salt_source: &self.salt, secret: Some("test-secret") };
            self.service.generate_user_id_with(&deps, &no_asn, ip, ua, 42, options, None, true).await.unwrap()
        }

        async fn client_id_hash(&self, client_id: &str, options: UserIdOptions) -> String {
            self.service
                .generate_user_id_from_client_id(&self.salt, Some("test-secret"), client_id, 42, options)
                .await
                .unwrap()
        }

        fn last_salt_scope(&self) -> String {
            let calls = self.sticky.calls();
            let key = &calls.last().unwrap().candidates_key;
            // sticky:cand:<site>:<saltScope>:<uaHash>
            key.split(':').nth(3).unwrap().to_string()
        }
    }

    fn salted(received_at: DateTime<Utc>) -> UserIdOptions {
        UserIdOptions { salt_user_ids: Some(true), received_at: Some(received_at) }
    }

    fn unsalted(received_at: Option<DateTime<Utc>>) -> UserIdOptions {
        UserIdOptions { salt_user_ids: Some(false), received_at }
    }

    const CHROME_150: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36";
    const CHROME_151: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36";

    #[tokio::test]
    async fn reads_the_site_configuration_when_the_caller_does_not_supply_salt_user_ids() {
        let f = Fixture::new();
        f.generate("198.51.100.10", "Mozilla/5.0", UserIdOptions::default()).await;
        assert_eq!(f.salt.reads.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn skips_the_site_configuration_read_when_the_caller_already_knows_the_setting() {
        let f = Fixture::new();
        f.generate("198.51.100.10", "Mozilla/5.0", UserIdOptions { salt_user_ids: Some(true), received_at: None })
            .await;
        assert_eq!(f.salt.reads.load(Ordering::SeqCst), 0);
    }

    /// The event's UTC day comes from receivedAt, not from the clock at hashing
    /// time. With the day passed explicitly there is no clock to move, so the
    /// "ingestion crossed midnight" case is the same call twice.
    #[tokio::test]
    async fn salts_against_the_day_the_event_arrived() {
        let f = Fixture::new();
        let before_midnight = f.generate("198.51.100.10", "Mozilla/5.0", salted(day_end())).await;
        let across_midnight = f.generate("198.51.100.10", "Mozilla/5.0", salted(day_end())).await;
        assert_eq!(across_midnight, before_midnight);
        assert_eq!(f.last_salt_scope(), "2026-08-14");
    }

    #[tokio::test]
    async fn still_rotates_the_fingerprint_for_an_event_that_belongs_to_the_next_day() {
        let f = Fixture::new();
        let day_one = f.generate("198.51.100.10", "Mozilla/5.0", salted(day_end())).await;
        let day_two = f.generate("198.51.100.10", "Mozilla/5.0", salted(next_day())).await;
        assert_ne!(day_two, day_one);
        assert_eq!(f.last_salt_scope(), "2026-08-15");
    }

    #[tokio::test]
    async fn leaves_an_unsalted_sites_fingerprint_stable_across_the_day_boundary() {
        let f = Fixture::new();
        let day_one = f.generate("198.51.100.10", "Mozilla/5.0", unsalted(Some(day_end()))).await;
        let day_two = f.generate("198.51.100.10", "Mozilla/5.0", unsalted(Some(next_day()))).await;
        assert_eq!(day_two, day_one);
        assert_eq!(f.last_salt_scope(), "");
    }

    #[tokio::test]
    async fn salts_an_anonymous_id_against_the_events_day_too() {
        let f = Fixture::new();
        let before = f.client_id_hash("consented-visitor", salted(day_end())).await;
        let across = f.client_id_hash("consented-visitor", salted(day_end())).await;
        assert_eq!(across, before);
        assert_ne!(f.client_id_hash("consented-visitor", salted(next_day())).await, before);
    }

    #[tokio::test]
    async fn keeps_an_unsalted_anonymous_id_independent_of_the_day() {
        let f = Fixture::new();
        let day_one = f.client_id_hash("consented-visitor", unsalted(Some(day_end()))).await;
        let day_two = f.client_id_hash("consented-visitor", unsalted(Some(next_day()))).await;
        assert_eq!(day_two, day_one);
    }

    #[tokio::test]
    async fn keeps_one_identity_across_a_browser_update() {
        let f = Fixture::new();
        let before = f.generate("198.51.100.10", CHROME_150, unsalted(None)).await;
        let after = f.generate("198.51.100.10", CHROME_151, unsalted(None)).await;
        assert_eq!(after, before);
    }

    #[tokio::test]
    async fn still_separates_different_browsers_on_one_ip() {
        let f = Fixture::new();
        let chrome = f.generate("198.51.100.10", CHROME_151, unsalted(None)).await;
        let firefox = f
            .generate(
                "198.51.100.10",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:153.0) Gecko/20100101 Firefox/153.0",
                unsalted(None),
            )
            .await;
        assert_ne!(firefox, chrome);
    }

    /// Sticky re-attachment keys its candidate pool on the raw user agent.
    #[tokio::test]
    async fn hands_sticky_re_attachment_the_raw_user_agent() {
        let f = Fixture::new();
        f.generate("198.51.100.10", CHROME_151, unsalted(None)).await;
        let expected = &hex::encode(Sha256::digest(CHROME_151.as_bytes()))[..16];
        assert!(f.sticky.calls()[0].candidates_key.ends_with(expected));
    }

    #[tokio::test]
    async fn salted_ids_need_the_secret_and_unsalted_ones_do_not() {
        let service = UserIdService::new();
        let sticky = RecordingStickyStore::passthrough();
        let salt = CountingSaltSource::new(true);
        let deps = UserIdDeps { redis: &sticky, salt_source: &salt, secret: Some("") };
        let salted_result = service
            .generate_user_id_with(&deps, &no_asn, "198.51.100.10", "UA", 42, UserIdOptions::default(), None, true)
            .await;
        assert_eq!(salted_result, Err(UserIdError::MissingSecret));

        let unsalted_result =
            service.generate_user_id_with(&deps, &no_asn, "198.51.100.10", "UA", 42, unsalted(None), None, true).await;
        assert!(unsalted_result.is_ok());
    }

    /// Known answers computed with Node's userIdService (secret "test-secret",
    /// no datacenter ASN, sticky passthrough).
    #[tokio::test]
    async fn matches_node_known_answers() {
        let f = Fixture::new();
        assert_eq!(f.generate("198.51.100.10", CHROME_151, unsalted(None)).await, NODE_UNSALTED_CHROME_151);
        assert_eq!(f.generate("198.51.100.10", CHROME_151, salted(day_end())).await, NODE_SALTED_CHROME_151_DAY_END);
        assert_eq!(f.client_id_hash("consented-visitor", unsalted(None)).await, NODE_CLIENT_ID_UNSALTED);
        assert_eq!(f.client_id_hash("consented-visitor", salted(next_day())).await, NODE_CLIENT_ID_SALTED_NEXT_DAY);
    }

    const NODE_UNSALTED_CHROME_151: &str = "b2b8aeb29dff";
    const NODE_SALTED_CHROME_151_DAY_END: &str = "7520cdf90dea";
    const NODE_CLIENT_ID_UNSALTED: &str = "49a6a7a644ff";
    const NODE_CLIENT_ID_SALTED_NEXT_DAY: &str = "63efdc3eaab2";
}
