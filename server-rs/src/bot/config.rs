//! Detection thresholds, ported from server/src/services/tracker/botBlocking/config.ts.

/// `BOT_SCORE_THRESHOLD`: minimum header-heuristic score to classify a request
/// as a bot. Each signal contributes points; a total at or above this convicts.
pub const BOT_SCORE_THRESHOLD: i64 = 5;

/// `CLIENT_BOT_SCORE_THRESHOLD`: minimum client-side bot signal score to classify
/// a request as a bot. The client sends one cached weighted integer; a score at or
/// above this is rejected.
pub const CLIENT_BOT_SCORE_THRESHOLD: i64 = 3;
