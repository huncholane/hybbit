//! Port of server/src/api/analytics/utils/effectiveUserId.ts: how a "user" is
//! counted. Identified users key on `identified_user_id`, anonymous ones fall
//! back to the `user_id` device fingerprint.

/// `effectiveUserId(tableAlias)`: event-level key.
pub fn effective_user_id(table_alias: &str) -> String {
    let prefix = if table_alias.is_empty() { String::new() } else { format!("{table_alias}.") };
    format!("COALESCE(NULLIF({prefix}identified_user_id, ''), {prefix}user_id)")
}

/// `EFFECTIVE_SESSION_USER_ID`: session-level key inside `GROUP BY session_id`.
pub const EFFECTIVE_SESSION_USER_ID: &str =
    "COALESCE(NULLIF(anyIf(identified_user_id, identified_user_id != ''), ''), anyLast(user_id))";

/// `matchesUser(valueExpr, tableAlias)`. `value_expr` must already be a bound
/// parameter or an escaped literal.
pub fn matches_user(value_expr: &str, table_alias: &str) -> String {
    let prefix = if table_alias.is_empty() { String::new() } else { format!("{table_alias}.") };
    format!(
        "({prefix}identified_user_id = {value_expr} OR ({prefix}user_id = {value_expr} AND {prefix}identified_user_id = ''))"
    )
}

/// `doesNotMatchUser(valueExpr, tableAlias)`: the exact complement.
pub fn does_not_match_user(value_expr: &str, table_alias: &str) -> String {
    format!("NOT {}", matches_user(value_expr, table_alias))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Ported from effectiveUserId.test.ts
    #[test]
    fn effective_user_id_cases() {
        assert_eq!(effective_user_id(""), "COALESCE(NULLIF(identified_user_id, ''), user_id)");
        assert_eq!(effective_user_id("e"), "COALESCE(NULLIF(e.identified_user_id, ''), e.user_id)");
        assert_eq!(effective_user_id("events"), "COALESCE(NULLIF(events.identified_user_id, ''), events.user_id)");
        assert_eq!(
            effective_user_id("db.events"),
            "COALESCE(NULLIF(db.events.identified_user_id, ''), db.events.user_id)"
        );
        assert!(effective_user_id("").contains("NULLIF(identified_user_id, '')"));
    }

    #[test]
    fn session_user_id_constant() {
        assert_eq!(
            EFFECTIVE_SESSION_USER_ID,
            "COALESCE(NULLIF(anyIf(identified_user_id, identified_user_id != ''), ''), anyLast(user_id))"
        );
        assert!(!EFFECTIVE_SESSION_USER_ID.contains('.'));
        assert!(EFFECTIVE_SESSION_USER_ID.starts_with("COALESCE(NULLIF(") && effective_user_id("").starts_with("COALESCE(NULLIF("));
    }

    #[test]
    fn matches_user_cases() {
        assert_eq!(
            matches_user("{userId:String}", ""),
            "(identified_user_id = {userId:String} OR (user_id = {userId:String} AND identified_user_id = ''))"
        );
        assert_eq!(
            matches_user("{userId:String}", "e"),
            "(e.identified_user_id = {userId:String} OR (e.user_id = {userId:String} AND e.identified_user_id = ''))"
        );
        assert_eq!(
            matches_user("'user123'", ""),
            "(identified_user_id = 'user123' OR (user_id = 'user123' AND identified_user_id = ''))"
        );
        let aliased = matches_user("{userId:String}", "e");
        assert!(!aliased.contains("e.{userId:String}"));
        assert_eq!(aliased.matches("{userId:String}").count(), 2);
        assert_eq!(aliased.matches("e.").count(), 3);
    }

    #[test]
    fn does_not_match_user_cases() {
        for alias in ["", "e", "events"] {
            assert_eq!(does_not_match_user("{userId:String}", alias), format!("NOT {}", matches_user("{userId:String}", alias)));
        }
        let sql = does_not_match_user("'user123'", "");
        assert!(sql.starts_with("NOT (") && sql.ends_with(')'));
    }
}
