//! Scope taxonomy and enforcement, ported from shared/src/scopes.ts and
//! server/src/lib/scopes.ts.
//!
//! - `None` statements = UNRESTRICTED (legacy credentials created before scopes
//!   existed, or credentials deliberately issued with full access).
//! - `Some(empty)` = deny-all. Never conflate the two.
//! - `write` implies `read` on the same resource, checked in `has_scope`.

use indexmap::IndexMap;
use serde_json::Value;

/// `SCOPE_MATRIX`, in declaration order (the order `ALL_SCOPE_STRINGS` lists).
pub const SCOPE_MATRIX: &[(&str, &[&str])] = &[
    ("analytics", &["read"]),
    ("sessions", &["read"]),
    ("events", &["read"]),
    ("users", &["read", "write"]),
    ("goals", &["read", "write"]),
    ("funnels", &["read", "write"]),
    ("dashboards", &["read", "write"]),
    ("annotations", &["read", "write"]),
    ("segments", &["read", "write"]),
    ("flags", &["read", "write"]),
    ("experiments", &["read", "write"]),
    ("sites", &["read", "write"]),
    ("gsc", &["read", "write"]),
    ("org", &["read", "write"]),
    ("replay", &["read", "write"]),
    ("sql", &["read"]),
    ("ingest", &["write"]),
];

pub const OIDC_STANDARD_SCOPES: &[&str] = &["openid", "profile", "email", "offline_access"];

/// Resource to granted actions, in the order they were first seen.
pub type ScopeStatements = IndexMap<String, Vec<String>>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScopeRequirement {
    pub resource: &'static str,
    pub action: &'static str,
}

/// `isValidScopePair`
pub fn is_valid_scope_pair(resource: &str, action: &str) -> bool {
    SCOPE_MATRIX
        .iter()
        .any(|(name, actions)| *name == resource && actions.contains(&action))
}

/// `parseOAuthScopes`: standard OIDC scopes are stripped first; nothing custom
/// left means an unrestricted token. Unknown custom entries are dropped but the
/// result stays `Some`, so a token with only unknown scopes is denied everything.
pub fn parse_oauth_scopes(scope: Option<&str>) -> Option<ScopeStatements> {
    // JS splits on /\s+/, which includes Unicode whitespace like char::is_whitespace
    let custom: Vec<&str> = scope
        .unwrap_or("")
        .split(char::is_whitespace)
        .filter(|entry| !entry.is_empty() && !OIDC_STANDARD_SCOPES.contains(entry))
        .collect();
    if custom.is_empty() {
        return None;
    }

    let mut statements = ScopeStatements::new();
    for entry in custom {
        let mut parts = entry.split(':');
        let (Some(resource), Some(action), None) = (parts.next(), parts.next(), parts.next()) else {
            continue;
        };
        if resource.is_empty() || action.is_empty() || !is_valid_scope_pair(resource, action) {
            continue;
        }
        let actions = statements.entry(resource.to_string()).or_default();
        if !actions.iter().any(|existing| existing == action) {
            actions.push(action.to_string());
        }
    }
    Some(statements)
}

/// `statementsFromApiKeyPermissions`: the parsed `apikey.permissions` JSON.
/// Absent = legacy key = unrestricted; anything malformed yields deny-all.
pub fn statements_from_api_key_permissions(permissions: Option<&Value>) -> Option<ScopeStatements> {
    let permissions = match permissions {
        None | Some(Value::Null) => return None,
        Some(value) => value,
    };

    let mut statements = ScopeStatements::new();
    if let Value::Object(map) = permissions {
        for (resource, actions) in map {
            let Value::Array(actions) = actions else { continue };
            let mut valid: Vec<String> = Vec::new();
            for action in actions {
                if let Value::String(action) = action
                    && is_valid_scope_pair(resource, action)
                    && !valid.contains(action)
                {
                    valid.push(action.clone());
                }
            }
            if !valid.is_empty() {
                statements.insert(resource.clone(), valid);
            }
        }
    }
    Some(statements)
}

/// `hasScope`: better-auth's access matcher with a single requested action,
/// where `write` on a resource also satisfies `read`.
pub fn has_scope(statements: Option<&ScopeStatements>, requirement: ScopeRequirement) -> bool {
    let Some(statements) = statements else { return true };
    let granted = |action: &str| {
        statements
            .get(requirement.resource)
            .is_some_and(|actions| actions.iter().any(|granted| granted == action))
    };
    granted(requirement.action) || (requirement.action == "read" && granted("write"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const INGEST_WRITE: ScopeRequirement = ScopeRequirement { resource: "ingest", action: "write" };
    const GOALS_READ: ScopeRequirement = ScopeRequirement { resource: "goals", action: "read" };

    #[test]
    fn null_statements_are_unrestricted_and_empty_ones_deny() {
        assert!(has_scope(None, INGEST_WRITE));
        assert!(!has_scope(Some(&ScopeStatements::new()), INGEST_WRITE));
    }

    #[test]
    fn write_implies_read() {
        let statements = statements_from_api_key_permissions(Some(&json!({"goals": ["write"]}))).unwrap();
        assert!(has_scope(Some(&statements), GOALS_READ));
        assert!(!has_scope(Some(&statements), INGEST_WRITE));
    }

    #[test]
    fn api_key_permissions_keep_only_valid_pairs() {
        assert_eq!(statements_from_api_key_permissions(None), None);
        assert_eq!(statements_from_api_key_permissions(Some(&Value::Null)), None);
        assert_eq!(statements_from_api_key_permissions(Some(&json!("junk"))), Some(ScopeStatements::new()));
        let statements = statements_from_api_key_permissions(Some(&json!({
            "ingest": ["write", "write", "read"],
            "nope": ["read"],
            "sql": "read",
        })))
        .unwrap();
        assert_eq!(statements.len(), 1);
        assert_eq!(statements["ingest"], vec!["write".to_string()]);
    }

    #[test]
    fn oauth_scopes_strip_oidc_and_fail_closed() {
        assert_eq!(parse_oauth_scopes(None), None);
        assert_eq!(parse_oauth_scopes(Some("openid profile  email offline_access")), None);
        assert_eq!(parse_oauth_scopes(Some("openid mystery:scope")), Some(ScopeStatements::new()));
        let statements = parse_oauth_scopes(Some("openid analytics:read goals:write goals:write a:b:c")).unwrap();
        assert_eq!(statements.keys().collect::<Vec<_>>(), vec!["analytics", "goals"]);
        assert_eq!(statements["goals"], vec!["write".to_string()]);
    }
}
