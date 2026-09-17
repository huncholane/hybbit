//! Sticky identity re-attachment, ported from
//! server/src/services/userId/stickyUserId.ts, the `stickyResolve` Lua in
//! server/src/db/redis/stickyResolveLua.ts and its wrapper in
//! server/src/db/redis/redis.ts.
//!
//! Node and Rust serve the same visitors during the cutover, so the key names,
//! TTLs, argument order and the Lua body are byte-for-byte Node's. Identical Lua
//! text also means an identical SHA1, so `EVALSHA` finds the script whichever
//! backend loaded it first.

use std::{
    future::Future,
    sync::{
        LazyLock,
        atomic::{AtomicBool, Ordering},
    },
};

use anyhow::{Context, anyhow};
use redis::aio::ConnectionManager;
use sha2::{Digest, Sha256};

use super::REDIS_COMMAND_TIMEOUT;

/// `CANDIDATE_WINDOW_MS`: how far back a previous identity counts as a
/// re-attachment candidate (15 minutes; production gap analysis of 2026-07-21).
pub const CANDIDATE_WINDOW_MS: u64 = 15 * 60 * 1000;
/// `SEEN_TTL_MS`: how long a fingerprint stays known without activity; matches
/// the session TTL.
pub const SEEN_TTL_MS: u64 = 30 * 60 * 1000;
/// `ALIAS_TTL_MS`: how long a re-attachment decision is remembered (sliding).
pub const ALIAS_TTL_MS: u64 = 24 * 60 * 60 * 1000;
/// `MAX_CANDIDATES`: only 0 / 1 / many matters, so a small cap never changes a decision.
pub const MAX_CANDIDATES: u32 = 32;

/// `STICKY_RESOLVE_LUA`, verbatim (including indentation, so the SHA1 matches).
///
/// KEYS: [1] seen:<rawId>  [2] candidate ZSET  [3] alias:<rawId>
/// ARGV: rawId, nowMs, candidateWindowMs, seenTtlMs, aliasTtlMs, eligible(0/1),
///       seenKeyPrefix, aliasKeyPrefix, maxCandidates
pub const STICKY_RESOLVE_LUA: &str = "
    local rawId = ARGV[1]
    local now = tonumber(ARGV[2])
    local windowMs = tonumber(ARGV[3])
    local seenTtlMs = ARGV[4]
    local aliasTtlMs = ARGV[5]
    local eligible = ARGV[6] == '1'
    local seenPrefix = ARGV[7]
    local aliasPrefix = ARGV[8]
    local maxCandidates = tonumber(ARGV[9])

    local function touch(id)
      redis.call('SET', seenPrefix .. id, '1', 'PX', seenTtlMs)
      if eligible then
        redis.call('ZADD', KEYS[2], now, id)
        redis.call('ZREMRANGEBYSCORE', KEYS[2], '-inf', '(' .. (now - windowMs))
        redis.call('ZREMRANGEBYRANK', KEYS[2], 0, -maxCandidates - 1)
        redis.call('PEXPIRE', KEYS[2], windowMs)
      end
    end

    local canonical = redis.call('GET', KEYS[3])
    if canonical then
      for _ = 1, 5 do
        local hop = redis.call('GET', aliasPrefix .. canonical)
        if not hop then break end
        canonical = hop
      end
      redis.call('SET', KEYS[3], canonical, 'PX', aliasTtlMs)
      touch(canonical)
      return {canonical, 'alias'}
    end

    if redis.call('EXISTS', KEYS[1]) == 1 then
      touch(rawId)
      return {rawId, 'known'}
    end

    if eligible then
      redis.call('ZREMRANGEBYSCORE', KEYS[2], '-inf', '(' .. (now - windowMs))
      local candidates = redis.call('ZRANGE', KEYS[2], 0, -1)
      local matched = nil
      local count = 0
      for _, id in ipairs(candidates) do
        if id ~= rawId then
          count = count + 1
          matched = id
        end
      end
      if count == 1 then
        redis.call('SET', KEYS[3], matched, 'PX', aliasTtlMs)
        touch(matched)
        return {matched, 'attach'}
      end
      touch(rawId)
      if count == 0 then
        return {rawId, 'abstain_none'}
      end
      return {rawId, 'abstain_multi'}
    end

    touch(rawId)
    return {rawId, 'new'}
";

static STICKY_RESOLVE_SCRIPT: LazyLock<redis::Script> = LazyLock::new(|| redis::Script::new(STICKY_RESOLVE_LUA));

/// `stickyIdentityEnabled`: read once, like Node's module-level
/// `process.env.DISABLE_STICKY_IDENTITY !== "true"`.
static STICKY_IDENTITY_ENABLED: LazyLock<AtomicBool> =
    LazyLock::new(|| AtomicBool::new(std::env::var("DISABLE_STICKY_IDENTITY").as_deref() != Ok("true")));

pub fn sticky_identity_enabled() -> bool {
    STICKY_IDENTITY_ENABLED.load(Ordering::Relaxed)
}

/// `setStickyIdentityEnabledForTests`
pub fn set_sticky_identity_enabled_for_tests(enabled: bool) {
    STICKY_IDENTITY_ENABLED.store(enabled, Ordering::Relaxed);
}

/// `StickyResolveOutcome`
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StickyResolveOutcome {
    Alias,
    Known,
    Attach,
    AbstainNone,
    AbstainMulti,
    New,
    /// Anything else the script might return; Node passes the id through as is.
    Other(String),
}

impl StickyResolveOutcome {
    pub fn parse(outcome: &str) -> Self {
        match outcome {
            "alias" => Self::Alias,
            "known" => Self::Known,
            "attach" => Self::Attach,
            "abstain_none" => Self::AbstainNone,
            "abstain_multi" => Self::AbstainMulti,
            "new" => Self::New,
            other => Self::Other(other.to_string()),
        }
    }

    pub fn as_str(&self) -> &str {
        match self {
            Self::Alias => "alias",
            Self::Known => "known",
            Self::Attach => "attach",
            Self::AbstainNone => "abstain_none",
            Self::AbstainMulti => "abstain_multi",
            Self::New => "new",
            Self::Other(other) => other,
        }
    }
}

/// `StickyResolveInput`: the keys and arguments of one `stickyResolve` call.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StickyResolveInput {
    pub seen_key: String,
    pub candidates_key: String,
    pub alias_key: String,
    pub raw_user_id: String,
    pub now_ms: i64,
    pub candidate_window_ms: u64,
    pub seen_ttl_ms: u64,
    pub alias_ttl_ms: u64,
    /// Whether this request may attempt re-attachment (datacenter-egress IPs only).
    pub eligible: bool,
    pub seen_key_prefix: String,
    pub alias_key_prefix: String,
    pub max_candidates: u32,
}

/// Where sticky decisions are made. Production uses the shared Redis connection;
/// tests substitute a recorder, as the Node tests mock `stickyResolve`.
pub trait StickyStore: Sync {
    fn sticky_resolve(
        &self,
        input: &StickyResolveInput,
    ) -> impl Future<Output = anyhow::Result<(String, StickyResolveOutcome)>> + Send;
}

impl StickyStore for ConnectionManager {
    fn sticky_resolve(
        &self,
        input: &StickyResolveInput,
    ) -> impl Future<Output = anyhow::Result<(String, StickyResolveOutcome)>> + Send {
        let mut connection = self.clone();
        let input = input.clone();
        async move { sticky_resolve(&mut connection, &input).await }
    }
}

/// `stickyResolve`: one atomic round-trip, keys and arguments in Node's order.
/// Numbers go over the wire in decimal like ioredis sends them, and the call
/// gives up after Node's one-second `commandTimeout`.
pub async fn sticky_resolve(
    connection: &mut ConnectionManager,
    input: &StickyResolveInput,
) -> anyhow::Result<(String, StickyResolveOutcome)> {
    let mut invocation = STICKY_RESOLVE_SCRIPT.key(&input.seen_key);
    invocation
        .key(&input.candidates_key)
        .key(&input.alias_key)
        .arg(&input.raw_user_id)
        .arg(input.now_ms)
        .arg(input.candidate_window_ms)
        .arg(input.seen_ttl_ms)
        .arg(input.alias_ttl_ms)
        .arg(if input.eligible { "1" } else { "0" })
        .arg(&input.seen_key_prefix)
        .arg(&input.alias_key_prefix)
        .arg(input.max_candidates);

    let (user_id, outcome): (String, String) =
        tokio::time::timeout(REDIS_COMMAND_TIMEOUT, invocation.invoke_async(connection))
            .await
            .map_err(|_| anyhow!("Command timed out"))?
            .context("stickyResolve")?;
    Ok((user_id, StickyResolveOutcome::parse(&outcome)))
}

/// `StickyIdentityInput`
pub struct StickyIdentityInput<'a> {
    pub site_id: i32,
    /// The fingerprint hash `generateUserId` computed (bucketed IP + UA [+ salt]).
    pub raw_user_id: &'a str,
    /// The exact client IP, used only for the datacenter-egress eligibility gate.
    pub ip_address: &'a str,
    /// The raw user agent (never the normalized one).
    pub user_agent: &'a str,
    /// The UTC date the salt was built from on salted Sites, "" otherwise.
    /// Prevents re-attachment across a salt rotation.
    pub salt_scope: &'a str,
    /// Defaults to the wall clock.
    pub now_ms: Option<i64>,
    pub is_datacenter_egress: &'a (dyn Fn(&str) -> bool + Sync),
}

/// `resolveStickyUserId`: the canonical anonymous user id for a fingerprint hash.
///
/// When a never-seen fingerprint arrives from datacenter egress and exactly one
/// identity with the same user agent was active on this Site through datacenter
/// egress in the last few minutes, re-attach to it; with zero or several
/// candidates, abstain. Enhancement layer only: any Redis failure returns the raw
/// fingerprint and never delays ingestion beyond the command timeout.
///
/// Node also skips straight to the raw fingerprint while ioredis reports the
/// connection as not ready; the connection manager has no such state, so a
/// down Redis is noticed as a failed or timed-out call instead.
pub async fn resolve_sticky_user_id<S: StickyStore>(store: &S, input: StickyIdentityInput<'_>) -> String {
    resolve_sticky_user_id_with(store, input, sticky_identity_enabled()).await
}

pub(crate) async fn resolve_sticky_user_id_with<S: StickyStore>(
    store: &S,
    input: StickyIdentityInput<'_>,
    enabled: bool,
) -> String {
    if !enabled || input.ip_address.is_empty() || input.user_agent.is_empty() {
        return input.raw_user_id.to_string();
    }

    let ua_hash = &hex::encode(Sha256::digest(input.user_agent.as_bytes()))[..16];
    let seen_key_prefix = format!("sticky:seen:{}:", input.site_id);
    let alias_key_prefix = format!("sticky:alias:{}:", input.site_id);

    let request = StickyResolveInput {
        seen_key: format!("{seen_key_prefix}{}", input.raw_user_id),
        candidates_key: format!("sticky:cand:{}:{}:{ua_hash}", input.site_id, input.salt_scope),
        alias_key: format!("{alias_key_prefix}{}", input.raw_user_id),
        raw_user_id: input.raw_user_id.to_string(),
        now_ms: input.now_ms.unwrap_or_else(|| chrono::Utc::now().timestamp_millis()),
        candidate_window_ms: CANDIDATE_WINDOW_MS,
        seen_ttl_ms: SEEN_TTL_MS,
        alias_ttl_ms: ALIAS_TTL_MS,
        eligible: (input.is_datacenter_egress)(input.ip_address),
        seen_key_prefix,
        alias_key_prefix,
        max_candidates: MAX_CANDIDATES,
    };

    match store.sticky_resolve(&request).await {
        Ok((user_id, outcome)) => {
            if outcome == StickyResolveOutcome::Attach {
                tracing::info!(
                    site_id = input.site_id,
                    raw_user_id = input.raw_user_id,
                    canonical_user_id = %user_id,
                    "Re-attached rotated egress fingerprint to existing identity"
                );
            } else {
                tracing::debug!(
                    site_id = input.site_id,
                    raw_user_id = input.raw_user_id,
                    user_id = %user_id,
                    outcome = outcome.as_str(),
                    eligible = request.eligible,
                    "Sticky identity resolved"
                );
            }
            user_id
        }
        Err(error) => {
            tracing::error!(
                error = %format!("{error:#}"),
                site_id = input.site_id,
                "Sticky identity resolution failed; using raw fingerprint"
            );
            input.raw_user_id.to_string()
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    //! Port of server/src/services/userId/stickyUserId.test.ts (the TypeScript
    //! layer, with a recording store) and of
    //! server/src/db/redis/stickyResolve.integration.test.ts (the Lua, run for real
    //! against the parity Redis when it is reachable).

    use std::sync::Mutex;

    use super::*;

    /// Records every call and answers with a canned result, like the vitest mock.
    pub(crate) struct RecordingStickyStore {
        pub calls: Mutex<Vec<StickyResolveInput>>,
        pub result: Mutex<Result<(String, StickyResolveOutcome), String>>,
    }

    impl RecordingStickyStore {
        pub fn answering(user_id: &str, outcome: StickyResolveOutcome) -> Self {
            Self { calls: Mutex::new(Vec::new()), result: Mutex::new(Ok((user_id.to_string(), outcome))) }
        }

        /// A store that hands back the raw fingerprint, like `mockImplementation(input => input.rawUserId)`.
        pub fn passthrough() -> Self {
            Self::answering("", StickyResolveOutcome::Known)
        }

        pub fn calls(&self) -> Vec<StickyResolveInput> {
            self.calls.lock().unwrap().clone()
        }
    }

    impl StickyStore for RecordingStickyStore {
        fn sticky_resolve(
            &self,
            input: &StickyResolveInput,
        ) -> impl Future<Output = anyhow::Result<(String, StickyResolveOutcome)>> + Send {
            self.calls.lock().unwrap().push(input.clone());
            let result = match &*self.result.lock().unwrap() {
                Ok((user_id, _)) if user_id.is_empty() => Ok((input.raw_user_id.clone(), StickyResolveOutcome::Known)),
                Ok(result) => Ok(result.clone()),
                Err(message) => Err(anyhow!(message.clone())),
            };
            async move { result }
        }
    }

    const RAW: &str = "abc123def456";
    const UA: &str = "Mozilla/5.0 Chrome/120 Safari/537.36";

    fn datacenter(_: &str) -> bool {
        true
    }

    fn residential(_: &str) -> bool {
        false
    }

    fn base_input<'a>() -> StickyIdentityInput<'a> {
        StickyIdentityInput {
            site_id: 123,
            raw_user_id: RAW,
            ip_address: "203.0.113.10",
            user_agent: UA,
            salt_scope: "",
            now_ms: Some(1_000_000),
            is_datacenter_egress: &datacenter,
        }
    }

    #[tokio::test]
    async fn returns_the_resolved_canonical_id_from_redis() {
        let store = RecordingStickyStore::answering("canonical9999", StickyResolveOutcome::Attach);
        let user_id = resolve_sticky_user_id_with(&store, base_input(), true).await;
        assert_eq!(user_id, "canonical9999");
        assert_eq!(store.calls().len(), 1);
    }

    #[tokio::test]
    async fn builds_keys_scoped_by_site_salt_partition_and_ua_hash() {
        let store = RecordingStickyStore::answering(RAW, StickyResolveOutcome::Known);
        resolve_sticky_user_id_with(&store, StickyIdentityInput { salt_scope: "2026-07-19", ..base_input() }, true)
            .await;

        let call = &store.calls()[0];
        assert_eq!(call.seen_key, "sticky:seen:123:abc123def456");
        assert_eq!(call.alias_key, "sticky:alias:123:abc123def456");
        assert_eq!(call.seen_key_prefix, "sticky:seen:123:");
        assert_eq!(call.alias_key_prefix, "sticky:alias:123:");
        let pattern = regex::Regex::new(r"^sticky:cand:123:2026-07-19:[0-9a-f]{16}$").unwrap();
        assert!(pattern.is_match(&call.candidates_key), "{}", call.candidates_key);
        assert_eq!(call.raw_user_id, RAW);
        assert_eq!(call.now_ms, 1_000_000);
        assert_eq!(
            (call.candidate_window_ms, call.seen_ttl_ms, call.alias_ttl_ms, call.max_candidates),
            (900_000, 1_800_000, 86_400_000, 32)
        );
    }

    #[tokio::test]
    async fn uses_different_candidate_pools_for_different_user_agents() {
        let store = RecordingStickyStore::answering(RAW, StickyResolveOutcome::Known);
        resolve_sticky_user_id_with(&store, base_input(), true).await;
        resolve_sticky_user_id_with(
            &store,
            StickyIdentityInput { user_agent: "Mozilla/5.0 Firefox/128", ..base_input() },
            true,
        )
        .await;

        let calls = store.calls();
        assert_ne!(calls[0].candidates_key, calls[1].candidates_key);
    }

    #[tokio::test]
    async fn marks_residential_egress_ineligible_for_re_attachment() {
        let store = RecordingStickyStore::answering(RAW, StickyResolveOutcome::Known);
        resolve_sticky_user_id_with(
            &store,
            StickyIdentityInput { is_datacenter_egress: &residential, ..base_input() },
            true,
        )
        .await;
        assert!(!store.calls()[0].eligible);
    }

    #[tokio::test]
    async fn marks_datacenter_egress_eligible() {
        let store = RecordingStickyStore::answering(RAW, StickyResolveOutcome::Known);
        resolve_sticky_user_id_with(&store, base_input(), true).await;
        assert!(store.calls()[0].eligible);
    }

    #[tokio::test]
    async fn skips_when_ip_or_user_agent_is_missing() {
        let store = RecordingStickyStore::answering(RAW, StickyResolveOutcome::Known);
        let no_ip =
            resolve_sticky_user_id_with(&store, StickyIdentityInput { ip_address: "", ..base_input() }, true).await;
        let no_ua =
            resolve_sticky_user_id_with(&store, StickyIdentityInput { user_agent: "", ..base_input() }, true).await;
        assert_eq!((no_ip.as_str(), no_ua.as_str()), (RAW, RAW));
        assert!(store.calls().is_empty());
    }

    #[tokio::test]
    async fn falls_back_to_the_raw_fingerprint_when_redis_fails_without_throwing() {
        let store = RecordingStickyStore::answering(RAW, StickyResolveOutcome::Known);
        *store.result.lock().unwrap() = Err("redis down".to_string());
        assert_eq!(resolve_sticky_user_id_with(&store, base_input(), true).await, RAW);
    }

    #[tokio::test]
    async fn does_nothing_when_disabled() {
        let store = RecordingStickyStore::answering("canonical9999", StickyResolveOutcome::Attach);
        assert_eq!(resolve_sticky_user_id_with(&store, base_input(), false).await, RAW);
        assert!(store.calls().is_empty());
    }

    // -- The Lua script against a real Redis ------------------------------------

    use redis::AsyncCommands;

    const WINDOW_MS: u64 = 5 * 60 * 1000;

    /// The parity Redis, or None when it is not running (the test then passes
    /// vacuously, like the GeoLite2 tests in geo.rs).
    pub(crate) async fn parity_redis() -> Option<ConnectionManager> {
        let url =
            std::env::var("IDENTITY_TEST_REDIS_URL").unwrap_or_else(|_| "redis://:hygo@127.0.0.1:56379/".to_string());
        let client = redis::Client::open(url).ok()?;
        tokio::time::timeout(std::time::Duration::from_secs(2), ConnectionManager::new(client)).await.ok()?.ok()
    }

    /// Keys for one test, under a site id no real Site uses, so parallel tests and
    /// production data never collide.
    struct LuaFixture {
        redis: ConnectionManager,
        prefix: String,
    }

    impl LuaFixture {
        async fn new(name: &str) -> Option<Self> {
            let redis = parity_redis().await?;
            let fixture = Self { redis, prefix: format!("rs-test-{name}-{}", std::process::id()) };
            fixture.cleanup().await;
            Some(fixture)
        }

        fn seen(&self) -> String {
            format!("{}:seen:", self.prefix)
        }

        fn alias(&self) -> String {
            format!("{}:alias:", self.prefix)
        }

        fn cand(&self) -> String {
            format!("{}:cand::ua1", self.prefix)
        }

        async fn resolve(&self, raw_id: &str, now_ms: i64, eligible: bool, cand: Option<&str>) -> (String, String) {
            let input = StickyResolveInput {
                seen_key: format!("{}{raw_id}", self.seen()),
                candidates_key: cand.map(str::to_string).unwrap_or_else(|| self.cand()),
                alias_key: format!("{}{raw_id}", self.alias()),
                raw_user_id: raw_id.to_string(),
                now_ms,
                candidate_window_ms: WINDOW_MS,
                seen_ttl_ms: SEEN_TTL_MS,
                alias_ttl_ms: ALIAS_TTL_MS,
                eligible,
                seen_key_prefix: self.seen(),
                alias_key_prefix: self.alias(),
                max_candidates: MAX_CANDIDATES,
            };
            let (user_id, outcome) = sticky_resolve(&mut self.redis.clone(), &input).await.unwrap();
            (user_id, outcome.as_str().to_string())
        }

        async fn cleanup(&self) {
            let mut redis = self.redis.clone();
            let keys: Vec<String> = redis.keys(format!("{}:*", self.prefix)).await.unwrap_or_default();
            if !keys.is_empty() {
                let _: () = redis.del(keys).await.unwrap();
            }
        }

        async fn exists(&self, key: String) -> bool {
            self.redis.clone().exists(key).await.unwrap()
        }

        async fn get(&self, key: String) -> Option<String> {
            self.redis.clone().get(key).await.unwrap()
        }

        async fn members(&self) -> Vec<String> {
            self.redis.clone().zrange(self.cand(), 0, -1).await.unwrap()
        }
    }

    macro_rules! lua_fixture {
        ($name:expr) => {
            match LuaFixture::new($name).await {
                Some(fixture) => fixture,
                None => return,
            }
        };
    }

    fn pair(user_id: &str, outcome: &str) -> (String, String) {
        (user_id.to_string(), outcome.to_string())
    }

    #[tokio::test]
    async fn lua_registers_a_first_time_datacenter_visitor_as_identity_and_candidate() {
        let f = lua_fixture!("first-dc");
        assert_eq!(f.resolve("userA", 1_000_000, true, None).await, pair("userA", "abstain_none"));
        assert!(f.exists(format!("{}userA", f.seen())).await);
        assert_eq!(f.members().await, vec!["userA"]);
        f.cleanup().await;
    }

    #[tokio::test]
    async fn lua_registers_a_residential_visitor_as_identity_but_never_as_candidate() {
        let f = lua_fixture!("first-res");
        assert_eq!(f.resolve("userA", 1_000_000, false, None).await, pair("userA", "new"));
        assert!(f.exists(format!("{}userA", f.seen())).await);
        assert!(f.members().await.is_empty());
        f.cleanup().await;
    }

    #[tokio::test]
    async fn lua_keeps_a_known_fingerprint_unchanged() {
        let f = lua_fixture!("known");
        f.resolve("userA", 1_000_000, true, None).await;
        assert_eq!(f.resolve("userA", 1_010_000, true, None).await, pair("userA", "known"));
        f.cleanup().await;
    }

    #[tokio::test]
    async fn lua_attaches_a_new_datacenter_fingerprint_with_exactly_one_candidate() {
        let f = lua_fixture!("attach");
        f.resolve("userA", 1_000_000, true, None).await;
        assert_eq!(f.resolve("rotatedB", 1_010_000, true, None).await, pair("userA", "attach"));
        assert_eq!(f.get(format!("{}rotatedB", f.alias())).await.as_deref(), Some("userA"));
        assert!(!f.exists(format!("{}rotatedB", f.seen())).await);
        assert_eq!(f.members().await, vec!["userA"]);
        f.cleanup().await;
    }

    #[tokio::test]
    async fn lua_never_attaches_a_datacenter_arrival_to_a_residential_only_visitor() {
        let f = lua_fixture!("res-bait");
        f.resolve("residentialA", 1_000_000, false, None).await;
        assert_eq!(f.resolve("rotatedB", 1_010_000, true, None).await, pair("rotatedB", "abstain_none"));
        assert_eq!(f.get(format!("{}rotatedB", f.alias())).await, None);
        f.cleanup().await;
    }

    #[tokio::test]
    async fn lua_follows_the_alias_on_subsequent_events() {
        let f = lua_fixture!("follow");
        f.resolve("userA", 1_000_000, true, None).await;
        f.resolve("rotatedB", 1_010_000, true, None).await;
        assert_eq!(f.resolve("rotatedB", 1_020_000, true, None).await, pair("userA", "alias"));
        f.cleanup().await;
    }

    #[tokio::test]
    async fn lua_abstains_with_several_candidates() {
        let f = lua_fixture!("multi");
        let _: () = f.redis.clone().zadd(f.cand(), "userA", 1_000_000).await.unwrap();
        let _: () = f.redis.clone().zadd(f.cand(), "userB", 1_001_000).await.unwrap();
        assert_eq!(f.resolve("rotatedC", 1_010_000, true, None).await, pair("rotatedC", "abstain_multi"));
        assert_eq!(f.get(format!("{}rotatedC", f.alias())).await, None);
        f.cleanup().await;
    }

    #[tokio::test]
    async fn lua_never_attaches_for_residential_egress_even_with_one_candidate() {
        let f = lua_fixture!("res-one");
        f.resolve("userA", 1_000_000, true, None).await;
        assert_eq!(f.resolve("freshB", 1_010_000, false, None).await, pair("freshB", "new"));
        f.cleanup().await;
    }

    #[tokio::test]
    async fn lua_ignores_candidates_outside_the_window() {
        let f = lua_fixture!("window");
        f.resolve("userA", 1_000_000, true, None).await;
        let late = 1_000_000 + WINDOW_MS as i64 + 1;
        assert_eq!(f.resolve("rotatedB", late, true, None).await, pair("rotatedB", "abstain_none"));
        f.cleanup().await;
    }

    #[tokio::test]
    async fn lua_does_not_attach_across_user_agents() {
        let f = lua_fixture!("ua");
        f.resolve("userA", 1_000_000, true, None).await;
        let other = format!("{}:cand::ua2", f.prefix);
        assert_eq!(f.resolve("rotatedB", 1_010_000, true, Some(&other)).await, pair("rotatedB", "abstain_none"));
        f.cleanup().await;
    }

    #[tokio::test]
    async fn lua_resolves_alias_chains_to_the_terminal_id_and_compresses_the_path() {
        let f = lua_fixture!("chain");
        let mut redis = f.redis.clone();
        let _: () = redis.set(format!("{}userX", f.alias()), "userA").await.unwrap();
        let _: () = redis.set(format!("{}userA", f.alias()), "userB").await.unwrap();
        let _: () = redis.set(format!("{}userB", f.alias()), "userC").await.unwrap();
        assert_eq!(f.resolve("userX", 1_020_000, true, None).await, pair("userC", "alias"));
        assert_eq!(f.get(format!("{}userX", f.alias())).await.as_deref(), Some("userC"));
        f.cleanup().await;
    }

    #[tokio::test]
    async fn lua_caps_the_candidate_set_without_enabling_a_wrong_single_match() {
        let f = lua_fixture!("cap");
        let mut redis = f.redis.clone();
        for i in 0..40 {
            let _: () = redis.zadd(f.cand(), format!("user{i}"), 1_000_000 + i).await.unwrap();
        }
        assert_eq!(f.resolve("rotatedZ", 1_010_000, true, None).await.1, "abstain_multi");
        assert!(f.members().await.len() <= MAX_CANDIDATES as usize);
        f.cleanup().await;
    }

    #[test]
    fn script_hash_matches_the_lua_node_loads() {
        // sha1 of STICKY_RESOLVE_LUA as ioredis computes it for EVALSHA
        assert_eq!(STICKY_RESOLVE_SCRIPT.get_hash().len(), 40);
    }
}
