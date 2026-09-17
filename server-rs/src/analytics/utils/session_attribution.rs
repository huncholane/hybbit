//! Port of server/src/api/analytics/utils/sessionAttribution.ts: how a session
//! (or user) derives its referrer and channel from its events, shared by every
//! report so one session never shows two different sources.

/// First non-empty referrer in the session; '' when every event is direct.
pub const SESSION_REFERRER_AGG: &str = "argMinIf(referrer, timestamp, referrer != '')";

/// First attributed channel in the session, falling back to the first event's
/// channel when no event carries an acquisition signal (`UNATTRIBUTED_CHANNELS`
/// are Direct, Internal and legacy '').
pub const SESSION_CHANNEL_AGG: &str = "if(countIf(channel NOT IN ('Direct', 'Internal', '')) > 0, argMinIf(channel, timestamp, channel NOT IN ('Direct', 'Internal', '')), argMin(channel, timestamp))";
