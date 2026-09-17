//! Sessions, ported from server/src/services/sessions/sessionsService.ts and the
//! `sessionGetOrCreate` / `sessionRefresh` commands in
//! server/src/db/redis/redis.ts.
//!
//! A session is one Redis string, `session:<siteId>:<userId>` (or the hashed
//! identified form) holding a 14-character nanoid, with a sliding 30-minute TTL.
//! Node and Rust share these keys during the cutover, so the key format, the TTL
//! and the Lua bodies are Node's exactly, and whichever backend creates a session
//! the other one continues it.

use std::{
    future::Future,
    sync::{LazyLock, Mutex},
};

use anyhow::{Context, anyhow};
use indexmap::IndexMap;
use redis::aio::ConnectionManager;
use sha2::{Digest, Sha256};

use super::REDIS_COMMAND_TIMEOUT;

/// `SESSION_TTL_MS`: sessions expire after this much inactivity.
pub const SESSION_TTL_MS: u64 = 30 * 60 * 1000;

/// `FALLBACK_CACHE_MAX`: bound on the in-process mirror of handed-out session ids.
pub const FALLBACK_CACHE_MAX: usize = 50_000;

/// nanoid's `urlAlphabet` (nanoid 5.1.6), in its order.
const URL_ALPHABET: [char; 64] = [
    'u', 's', 'e', 'a', 'n', 'd', 'o', 'm', '-', '2', '6', 'T', '1', '9', '8', '3', '4', '0', 'P', 'X', '7', '5', 'p',
    'x', 'J', 'A', 'C', 'K', 'V', 'E', 'R', 'Y', 'M', 'I', 'N', 'D', 'B', 'U', 'S', 'H', 'W', 'O', 'L', 'F', '_', 'G',
    'Q', 'Z', 'b', 'f', 'g', 'h', 'j', 'k', 'l', 'q', 'v', 'w', 'y', 'z', 'r', 'i', 'c', 't',
];

/// `sessionGetOrCreate` Lua, verbatim from redis.ts (same text, same SHA1).
/// KEYS[1] session key; ARGV[1] candidate id; ARGV[2] TTL in ms.
pub const SESSION_GET_OR_CREATE_LUA: &str = "
    local existing = redis.call('GET', KEYS[1])
    if existing then
      redis.call('PEXPIRE', KEYS[1], ARGV[2])
      return existing
    end
    redis.call('SET', KEYS[1], ARGV[1], 'PX', ARGV[2])
    return ARGV[1]
  ";

/// `sessionRefresh` Lua, verbatim from redis.ts. KEYS[1] session key; ARGV[1] TTL in ms.
pub const SESSION_REFRESH_LUA: &str = "
    local existing = redis.call('GET', KEYS[1])
    if existing then
      redis.call('PEXPIRE', KEYS[1], ARGV[1])
    end
    return existing
  ";

static SESSION_GET_OR_CREATE_SCRIPT: LazyLock<redis::Script> =
    LazyLock::new(|| redis::Script::new(SESSION_GET_OR_CREATE_LUA));
static SESSION_REFRESH_SCRIPT: LazyLock<redis::Script> = LazyLock::new(|| redis::Script::new(SESSION_REFRESH_LUA));

/// The two atomic session commands. Production uses the shared Redis connection;
/// tests substitute a scripted store, as the Node tests mock these functions.
pub trait SessionStore: Sync {
    /// `sessionGetOrCreate(key, candidateId, ttlMs)`
    fn get_or_create(
        &self,
        key: &str,
        candidate: &str,
        ttl_ms: u64,
    ) -> impl Future<Output = anyhow::Result<String>> + Send;

    /// `sessionRefresh(key, ttlMs)`
    fn refresh(&self, key: &str, ttl_ms: u64) -> impl Future<Output = anyhow::Result<Option<String>>> + Send;
}

impl SessionStore for ConnectionManager {
    fn get_or_create(
        &self,
        key: &str,
        candidate: &str,
        ttl_ms: u64,
    ) -> impl Future<Output = anyhow::Result<String>> + Send {
        let mut connection = self.clone();
        let (key, candidate) = (key.to_string(), candidate.to_string());
        async move {
            let mut invocation = SESSION_GET_OR_CREATE_SCRIPT.key(&key);
            invocation.arg(&candidate).arg(ttl_ms);
            tokio::time::timeout(REDIS_COMMAND_TIMEOUT, invocation.invoke_async(&mut connection))
                .await
                .map_err(|_| anyhow!("Command timed out"))?
                .context("sessionGetOrCreate")
        }
    }

    fn refresh(&self, key: &str, ttl_ms: u64) -> impl Future<Output = anyhow::Result<Option<String>>> + Send {
        let mut connection = self.clone();
        let key = key.to_string();
        async move {
            let mut invocation = SESSION_REFRESH_SCRIPT.key(&key);
            invocation.arg(ttl_ms);
            tokio::time::timeout(REDIS_COMMAND_TIMEOUT, invocation.invoke_async(&mut connection))
                .await
                .map_err(|_| anyhow!("Command timed out"))?
                .context("sessionRefresh")
        }
    }
}

struct CachedSession {
    session_id: String,
    expires_at: i64,
}

/// `SessionsService`. One per process: the fallback cache is what keeps a Redis
/// blip from splitting a visitor's session.
pub struct SessionsService {
    fallback_cache: Mutex<IndexMap<String, CachedSession>>,
    now_ms: Box<dyn Fn() -> i64 + Send + Sync>,
}

impl Default for SessionsService {
    fn default() -> Self {
        Self::new()
    }
}

/// `nanoid(14)`
fn new_session_id() -> String {
    nanoid::nanoid!(14, &URL_ALPHABET)
}

/// `getSessionKey`: `session:<siteId>:<userId>`, or for an identified visitor
/// `session:<siteId>:identified:<sha256(userId \0 identifiedUserId)>`, which keeps
/// custom user ids out of Redis keys while keeping sessions fingerprint-scoped.
/// An empty identified user id is anonymous, as in Node.
pub fn session_key(user_id: &str, site_id: i32, identified_user_id: &str) -> String {
    if identified_user_id.is_empty() {
        return format!("session:{site_id}:{user_id}");
    }
    let mut hasher = Sha256::new();
    hasher.update(user_id.as_bytes());
    hasher.update(b"\0");
    hasher.update(identified_user_id.as_bytes());
    format!("session:{site_id}:identified:{}", hex::encode(hasher.finalize()))
}

impl SessionsService {
    pub fn new() -> Self {
        Self::with_clock(Box::new(|| chrono::Utc::now().timestamp_millis()))
    }

    /// A service reading time from `now_ms` (tests move it like fake timers).
    pub fn with_clock(now_ms: Box<dyn Fn() -> i64 + Send + Sync>) -> Self {
        Self { fallback_cache: Mutex::new(IndexMap::new()), now_ms }
    }

    fn cache(&self) -> std::sync::MutexGuard<'_, IndexMap<String, CachedSession>> {
        self.fallback_cache.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// `updateSession`: the active session id for an anonymous or identified
    /// visitor, created if none exists, with its sliding TTL refreshed. On a Redis
    /// failure the last id this process handed out for the key is reused while it
    /// is inside the window, and only then is a fresh id minted.
    pub async fn update_session<S: SessionStore>(
        &self,
        store: &S,
        user_id: &str,
        identified_user_id: &str,
        site_id: i32,
    ) -> String {
        let key = session_key(user_id, site_id, identified_user_id);
        let candidate = new_session_id();

        match store.get_or_create(&key, &candidate, SESSION_TTL_MS).await {
            Ok(session_id) => {
                tracing::debug!(
                    site_id,
                    created = session_id == candidate,
                    identified = !identified_user_id.is_empty(),
                    "Session resolved"
                );
                self.remember_session(&key, &session_id);
                session_id
            }
            Err(error) => {
                tracing::error!(
                    error = %format!("{error:#}"),
                    site_id,
                    "Redis session lookup failed; using in-process fallback session id"
                );
                self.fallback_session_id(&key, candidate)
            }
        }
    }

    /// `refreshSession`: extend a live session and return its id without ever
    /// creating one (heartbeats). None when the visitor has no live session; on a
    /// Redis failure, the last id this process handed out if still in the window.
    pub async fn refresh_session<S: SessionStore>(
        &self,
        store: &S,
        user_id: &str,
        identified_user_id: &str,
        site_id: i32,
    ) -> Option<String> {
        let key = session_key(user_id, site_id, identified_user_id);

        match store.refresh(&key, SESSION_TTL_MS).await {
            Ok(Some(session_id)) => {
                self.remember_session(&key, &session_id);
                Some(session_id)
            }
            Ok(None) => {
                tracing::debug!(site_id, "No live session to refresh");
                None
            }
            Err(error) => {
                tracing::error!(
                    error = %format!("{error:#}"),
                    site_id,
                    "Redis session refresh failed; using in-process fallback session id"
                );
                let cached = {
                    let cache = self.cache();
                    cache
                        .get(&key)
                        .filter(|cached| cached.expires_at > (self.now_ms)())
                        .map(|cached| cached.session_id.clone())
                };
                let session_id = cached?;
                self.remember_session(&key, &session_id);
                Some(session_id)
            }
        }
    }

    /// `rememberSession`: cache with a fresh sliding expiry, LRU-bounded.
    fn remember_session(&self, key: &str, session_id: &str) {
        let expires_at = (self.now_ms)() + SESSION_TTL_MS as i64;
        let mut cache = self.cache();
        // Re-insert to mark as most recently used
        cache.shift_remove(key);
        cache.insert(key.to_string(), CachedSession { session_id: session_id.to_string(), expires_at });
        if cache.len() > FALLBACK_CACHE_MAX {
            cache.shift_remove_index(0);
        }
    }

    /// `fallbackSessionId`: reuse the cached id while it is inside the window,
    /// otherwise adopt the candidate; either way store it back.
    fn fallback_session_id(&self, key: &str, candidate: String) -> String {
        let now = (self.now_ms)();
        let cached =
            self.cache().get(key).filter(|cached| cached.expires_at > now).map(|cached| cached.session_id.clone());
        let session_id = cached.unwrap_or(candidate);
        self.remember_session(key, &session_id);
        session_id
    }

    #[cfg(test)]
    fn cached_len(&self) -> usize {
        self.cache().len()
    }
}

#[cfg(test)]
mod tests {
    //! Port of server/src/services/sessions/sessionsService.test.ts. The "closes
    //! the Redis connection on shutdown" case has no counterpart: the Rust service
    //! shares the process-wide connection manager and owns no connection.

    use std::{
        collections::VecDeque,
        sync::{
            Arc,
            atomic::{AtomicI64, Ordering},
        },
    };

    use super::*;

    #[derive(Clone, Debug)]
    enum Answer {
        Id(String),
        Missing,
        Fail,
    }

    /// Scripted answers (`mockResolvedValueOnce` / `mockRejectedValue`) plus a call log.
    #[derive(Default)]
    struct ScriptedStore {
        once: Mutex<VecDeque<Answer>>,
        always: Mutex<Option<Answer>>,
        get_or_create_calls: Mutex<Vec<(String, String, u64)>>,
        refresh_calls: Mutex<Vec<(String, u64)>>,
    }

    impl ScriptedStore {
        fn always(&self, answer: Answer) {
            *self.always.lock().unwrap() = Some(answer);
        }

        fn once(&self, answer: Answer) {
            self.once.lock().unwrap().push_back(answer);
        }

        fn next(&self) -> Answer {
            self.once
                .lock()
                .unwrap()
                .pop_front()
                .or_else(|| self.always.lock().unwrap().clone())
                .unwrap_or(Answer::Missing)
        }

        fn keys(&self) -> Vec<String> {
            self.get_or_create_calls.lock().unwrap().iter().map(|call| call.0.clone()).collect()
        }
    }

    impl SessionStore for ScriptedStore {
        fn get_or_create(
            &self,
            key: &str,
            candidate: &str,
            ttl_ms: u64,
        ) -> impl Future<Output = anyhow::Result<String>> + Send {
            self.get_or_create_calls.lock().unwrap().push((key.to_string(), candidate.to_string(), ttl_ms));
            let answer = self.next();
            async move {
                match answer {
                    Answer::Id(id) => Ok(id),
                    Answer::Missing => Ok(String::new()),
                    Answer::Fail => Err(anyhow!("redis down")),
                }
            }
        }

        fn refresh(&self, key: &str, ttl_ms: u64) -> impl Future<Output = anyhow::Result<Option<String>>> + Send {
            self.refresh_calls.lock().unwrap().push((key.to_string(), ttl_ms));
            let answer = self.next();
            async move {
                match answer {
                    Answer::Id(id) => Ok(Some(id)),
                    Answer::Missing => Ok(None),
                    Answer::Fail => Err(anyhow!("redis down")),
                }
            }
        }
    }

    /// 2026-01-01T00:00:00.000Z, advanced by hand like vi.setSystemTime.
    fn fake_clock() -> (Arc<AtomicI64>, SessionsService) {
        let now = Arc::new(AtomicI64::new(1_767_225_600_000));
        let reader = now.clone();
        (now, SessionsService::with_clock(Box::new(move || reader.load(Ordering::SeqCst))))
    }

    const TTL: i64 = SESSION_TTL_MS as i64;

    // SessionsService.refreshSession

    #[tokio::test]
    async fn extends_a_live_session_without_creating_one() {
        let (_, service) = fake_clock();
        let store = ScriptedStore::default();
        store.always(Answer::Id("sess-live".into()));

        let result = service.refresh_session(&store, "user-a", "", 42).await;

        assert_eq!(result.as_deref(), Some("sess-live"));
        assert_eq!(*store.refresh_calls.lock().unwrap(), vec![("session:42:user-a".to_string(), SESSION_TTL_MS)]);
        assert!(store.get_or_create_calls.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn returns_none_when_the_visitor_has_no_live_session() {
        let (_, service) = fake_clock();
        let store = ScriptedStore::default();
        store.always(Answer::Missing);
        assert_eq!(service.refresh_session(&store, "user-a", "", 42).await, None);
    }

    #[tokio::test]
    async fn refresh_falls_back_to_this_workers_last_id_but_never_invents_one() {
        let (now, service) = fake_clock();
        let store = ScriptedStore::default();
        store.once(Answer::Id("sess-known".into()));
        service.update_session(&store, "user-a", "", 42).await;
        store.always(Answer::Fail);

        assert_eq!(service.refresh_session(&store, "user-a", "", 42).await.as_deref(), Some("sess-known"));
        assert_eq!(service.refresh_session(&store, "stranger", "", 42).await, None);

        now.fetch_add(TTL + 1, Ordering::SeqCst);
        assert_eq!(service.refresh_session(&store, "user-a", "", 42).await, None);
    }

    // SessionsService (Redis-backed)

    #[tokio::test]
    async fn returns_the_session_id_resolved_by_redis_and_refreshes_its_ttl() {
        let (_, service) = fake_clock();
        let store = ScriptedStore::default();
        store.always(Answer::Id("sess-existing".into()));

        let session_id = service.update_session(&store, "user-a", "", 42).await;

        assert_eq!(session_id, "sess-existing");
        let calls = store.get_or_create_calls.lock().unwrap().clone();
        assert_eq!(calls.len(), 1);
        let (key, candidate, ttl) = &calls[0];
        assert_eq!(key, "session:42:user-a");
        assert_eq!(candidate.chars().count(), 14);
        assert!(candidate.chars().all(|c| URL_ALPHABET.contains(&c)));
        assert_eq!(*ttl, SESSION_TTL_MS);
    }

    #[tokio::test]
    async fn namespaces_the_redis_key_by_site_and_user() {
        let (_, service) = fake_clock();
        let store = ScriptedStore::default();
        store.always(Answer::Id("x".into()));

        service.update_session(&store, "u1", "", 1).await;
        service.update_session(&store, "u1", "", 2).await;
        service.update_session(&store, "u2", "", 1).await;

        assert_eq!(store.keys(), vec!["session:1:u1", "session:2:u1", "session:1:u2"]);
    }

    #[tokio::test]
    async fn keeps_the_anonymous_key_unchanged_when_identified_user_id_is_empty() {
        let (_, service) = fake_clock();
        let store = ScriptedStore::default();
        store.always(Answer::Id("x".into()));
        service.update_session(&store, "anonymous-user", "", 42).await;
        assert_eq!(store.keys(), vec!["session:42:anonymous-user"]);
    }

    #[tokio::test]
    async fn separates_identified_users_that_share_the_same_anonymous_fingerprint() {
        let (_, service) = fake_clock();
        let store = ScriptedStore::default();
        store.always(Answer::Id("x".into()));

        service.update_session(&store, "shared-fingerprint", "employee-alice", 42).await;
        service.update_session(&store, "shared-fingerprint", "employee-bob", 42).await;

        let keys = store.keys();
        assert_ne!(keys[0], keys[1]);
        assert!(keys.iter().all(|key| key.starts_with("session:42:identified:")));
        assert!(keys.iter().all(|key| !key.contains("employee-alice") && !key.contains("employee-bob")));
    }

    #[tokio::test]
    async fn separates_the_same_identified_user_across_distinct_fingerprints() {
        let (_, service) = fake_clock();
        let store = ScriptedStore::default();
        store.always(Answer::Id("x".into()));

        service.update_session(&store, "device-a", "employee-alice", 42).await;
        service.update_session(&store, "device-b", "employee-alice", 42).await;

        let keys = store.keys();
        assert_ne!(keys[0], keys[1]);
    }

    #[tokio::test]
    async fn keeps_colliding_identified_users_separate_during_a_redis_outage() {
        let (_, service) = fake_clock();
        let store = ScriptedStore::default();
        store.always(Answer::Fail);

        let alice = service.update_session(&store, "shared-fingerprint", "employee-alice", 42).await;
        let bob = service.update_session(&store, "shared-fingerprint", "employee-bob", 42).await;

        assert_ne!(alice, bob);
    }

    #[tokio::test]
    async fn falls_back_to_a_window_stable_id_when_redis_fails() {
        let (now, service) = fake_clock();
        let store = ScriptedStore::default();
        store.always(Answer::Fail);

        let first = service.update_session(&store, "user-b", "", 7).await;
        now.fetch_add(TTL - 1000, Ordering::SeqCst);
        let second = service.update_session(&store, "user-b", "", 7).await;

        assert_eq!(first, second);
        assert!(!first.is_empty());
    }

    #[tokio::test]
    async fn reuses_the_real_redis_session_id_when_a_later_command_blips() {
        let (_, service) = fake_clock();
        let store = ScriptedStore::default();
        store.once(Answer::Id("sess-real".into()));
        let ok = service.update_session(&store, "user-d", "", 9).await;

        store.once(Answer::Fail);
        let blip = service.update_session(&store, "user-d", "", 9).await;

        assert_eq!(ok, "sess-real");
        assert_eq!(blip, "sess-real");
    }

    #[tokio::test]
    async fn rotates_the_fallback_id_once_the_sliding_window_lapses() {
        let (now, service) = fake_clock();
        let store = ScriptedStore::default();
        store.always(Answer::Fail);

        let first = service.update_session(&store, "user-c", "", 7).await;
        now.fetch_add(TTL + 1000, Ordering::SeqCst);
        let later = service.update_session(&store, "user-c", "", 7).await;

        assert_ne!(first, later);
    }

    #[tokio::test]
    async fn bounds_the_fallback_cache() {
        let (_, service) = fake_clock();
        for index in 0..=FALLBACK_CACHE_MAX {
            service.remember_session(&format!("session:1:{index}"), "x");
        }
        assert_eq!(service.cached_len(), FALLBACK_CACHE_MAX);
        assert!(!service.cache().contains_key("session:1:0"));
    }

    #[test]
    fn identified_key_matches_node() {
        // node -e 'crypto.createHash("sha256").update("fp").update("\0").update("alice").digest("hex")'
        assert_eq!(
            session_key("fp", 42, "alice"),
            format!("session:42:identified:{}", hex::encode(Sha256::digest(b"fp\0alice")))
        );
    }

    /// The Lua against the parity Redis when it is reachable.
    #[tokio::test]
    async fn lua_creates_continues_and_refreshes_sessions() {
        let Some(redis) = crate::identity::sticky::tests::parity_redis().await else { return };
        let key = format!("rs-test-session-{}", std::process::id());
        let mut connection = redis.clone();
        let _: () = redis::AsyncCommands::del(&mut connection, &key).await.unwrap();

        assert_eq!(redis.refresh(&key, SESSION_TTL_MS).await.unwrap(), None);
        assert_eq!(redis.get_or_create(&key, "first", SESSION_TTL_MS).await.unwrap(), "first");
        assert_eq!(redis.get_or_create(&key, "second", SESSION_TTL_MS).await.unwrap(), "first");
        assert_eq!(redis.refresh(&key, 5_000).await.unwrap().as_deref(), Some("first"));
        let ttl: i64 = redis::cmd("PTTL").arg(&key).query_async(&mut connection).await.unwrap();
        assert!((1..=5_000).contains(&ttl), "{ttl}");

        let _: () = redis::AsyncCommands::del(&mut connection, &key).await.unwrap();
    }
}
