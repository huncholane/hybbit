//! Visitor identity and sessions, ported from server/src/services/userId,
//! server/src/services/sessions, and the identify pipeline in
//! server/src/services/tracker (identifyService.ts, identityBackfillQueue.ts).
//!
//! Node and Rust serve the same visitors side by side during the cutover, so a
//! visitor whose events alternate between the two backends must keep one user id
//! and one session id. Everything that feeds those ids is therefore a byte-exact
//! port: the version-stripped user agent, the `ip-address` /24 and /48 buckets,
//! the daily salt and its day selection, the Redis key names, TTLs, argument
//! order and Lua bodies, and the nanoid alphabet.
//!
//! Wiring (for the route and startup code):
//! - `user_id::UserIdService`, `sessions::SessionsService` and
//!   `backfill::IdentityBackfillQueue` are process-wide singletons (Node exports
//!   one instance of each); keep them in AppState.
//! - The Redis handle is `AppState::redis` (`ConnectionManager` implements
//!   `StickyStore` and `SessionStore`); Node's separate identity and session
//!   connections are one multiplexed connection here.
//! - `IdentityBackfillQueue::start_flush_timer` at startup, and
//!   `IdentityBackfillQueue::drain_completely` after the server stops accepting
//!   requests (Node's shutdown does both).
//! - `identify::handle_identify` is `POST /api/identify`.
//!
//! Call sites, mapped from Node:
//! - `createBasePayload`: with `payload.anonymous_id`,
//!   `UserIdService::generate_user_id_from_client_id`; otherwise
//!   `UserIdService::generate_user_id` with the request's `AsnLookup`. Both get
//!   `UserIdOptions { salt_user_ids: Some(site.salt_user_ids), received_at: Some(receivedAt) }`.
//!   `UserIdError::MissingSecret` is where Node throws.
//! - `ingestEvent`: heartbeats `SessionsService::refresh_session` (None drops the
//!   event), everything else `SessionsService::update_session`; the identified
//!   user id is the trimmed `payload.user_id` or "".
//! - Dashboard identify (`identifyUser.ts`): `identify::backfill_identified_user_id`
//!   with `days: None`.
//! - ASN questions about the client IP go through `node_asn::lookup_asn_like_node`,
//!   which reads IP strings the way Node's `lookupAsn` does.
#![allow(dead_code)] // wired into the track and identify routes as they are ported

use std::time::Duration;

pub mod backfill;
pub mod identify;
pub mod ip_bucket;
pub mod node_asn;
pub mod normalize_user_agent;
pub mod sessions;
pub mod sticky;
pub mod user_id;

#[cfg(test)]
mod differential;

#[allow(unused_imports)]
pub use backfill::{BACKFILL_DAYS, BackfillSink, IdentityAssignment, IdentityBackfillQueue};
#[allow(unused_imports)]
pub use identify::{IdentifyDeps, IdentifyPayload, IdentifyRequest, backfill_identified_user_id, handle_identify};
#[allow(unused_imports)]
pub use ip_bucket::bucket_ip_for_identity;
#[allow(unused_imports)]
pub use node_asn::lookup_asn_like_node;
#[allow(unused_imports)]
pub use normalize_user_agent::normalize_user_agent_for_identity;
#[allow(unused_imports)]
pub use sessions::{SESSION_TTL_MS, SessionStore, SessionsService, session_key};
#[allow(unused_imports)]
pub use sticky::{StickyIdentityInput, StickyStore, resolve_sticky_user_id};
#[allow(unused_imports)]
pub use user_id::{SaltSettingSource, UserIdDeps, UserIdError, UserIdOptions, UserIdService, utc_day_of};

/// ioredis `commandTimeout` in server/src/db/redis/redis.ts: identity and
/// session commands fail fast so callers fall back instead of hanging.
pub const REDIS_COMMAND_TIMEOUT: Duration = Duration::from_millis(1000);
