//! Port of server/src/api/analytics/utils/customQueryValidation.ts: the guard
//! in front of user-authored SQL (custom query page and dashboard cards), and
//! the ClickHouse error sanitizer.
//!
//! The JavaScript regexes run without the `u` flag, so `\b` is an ASCII word
//! boundary, `i` folds ASCII letters only and `\s` is ECMAScript whitespace;
//! the patterns below spell those out (`(?-u:\b)`, `(?i-u:...)`, an explicit
//! whitespace class) so the `regex` crate matches exactly the same spans.
//! The literal/comment scanners walk UTF-16 code units, as JavaScript indexes.

use std::sync::LazyLock;

use indexmap::IndexSet;
use regex::Regex;
use tracing::debug;

use crate::analytics::js::{
    number::{number_to_string, string_to_number},
    string::{JS_SPACE_CLASS, is_js_space_char, trim},
};

pub const MAX_CUSTOM_QUERY_LENGTH: usize = 20_000;

const BLOCKED_KEYWORDS: [&str; 28] = [
    "ALTER", "ATTACH", "BACKUP", "CREATE", "DELETE", "DESCRIBE", "DETACH", "DROP", "EXCHANGE", "EXPLAIN", "FORMAT", "GRANT",
    "INFILE", "INSERT", "INTO", "KILL", "OPTIMIZE", "OUTFILE", "RENAME", "RESTORE", "REVOKE", "SET", "SETTINGS", "SHOW",
    "SYSTEM", "TRUNCATE", "USE", "WATCH",
];

const BLOCKED_FUNCTIONS: [&str; 75] = [
    "arrowFlight",
    "azureBlobStorage",
    "azureBlobStorageCluster",
    "cluster",
    "clusterAllReplicas",
    "currentProfiles",
    "currentRoles",
    "currentUser",
    "defaultProfiles",
    "defaultRoles",
    "enabledProfiles",
    "enabledRoles",
    "cosn",
    "deltaLake",
    "dictionary",
    "executable",
    "file",
    "filesystemAvailable",
    "filesystemCapacity",
    "filesystemUnreserved",
    "format",
    "FQDN",
    "fuzzJSON",
    "fuzzQuery",
    "gcs",
    "generateRandom",
    "getClientHTTPHeader",
    "getMacro",
    "getOSKernelVersion",
    "getServerPort",
    "getSetting",
    "getSettingOrDefault",
    "hdfs",
    "hdfsCluster",
    "hostName",
    "hostname",
    "hudi",
    "iceberg",
    "icebergCluster",
    "input",
    "jdbc",
    "kafka",
    "loop",
    "meilisearch",
    "merge",
    "mergeTreeIndex",
    "mergeTreeProjection",
    "mongodb",
    "mysql",
    "nats",
    "numbers",
    "odbc",
    "paimon",
    "postgresql",
    "prometheus",
    "rabbitmq",
    "redis",
    "remote",
    "remoteSecure",
    "s3",
    "s3Cluster",
    "showCertificate",
    "sleep",
    "sleepEachRow",
    "sqlite",
    "tcpPort",
    "timeSeriesData",
    "timeSeriesMetrics",
    "timeSeriesTags",
    "url",
    "urlCluster",
    "values",
    "view",
    "viewExplain",
    "viewIfPermitted",
];

const BLOCKED_FUNCTION_PREFIXES: [&str; 15] = [
    "iceberg", "deltaLake", "hudi", "hive", "azure", "s3", "hdfs", "gcs", "oss", "cosn", "timeSeries", "fuzz", "numbers", "zeros",
    "generate",
];

const UNSUPPORTED_SYNTAX_ERROR: &str =
    "Quoted identifiers, # and // comments, and $$ strings are not allowed in custom analytics queries";
const SCOPED_ONLY_ERROR: &str = "Queries can only read from scoped_events";

/// `(?i-u:literal)`: ASCII case-insensitive literal.
fn ci(literal: &str) -> String {
    format!("(?i-u:{})", regex::escape(literal))
}

const BOUNDARY: &str = r"(?-u:\b)";

fn compile(pattern: &str) -> Regex {
    Regex::new(pattern).unwrap_or_else(|error| panic!("invalid static pattern {pattern}: {error}"))
}

struct Patterns {
    select_or_with: Regex,
    cte: Regex,
    table_keyword: Regex,
    in_keyword: Regex,
    keywords: Vec<(&'static str, Regex)>,
    functions: Vec<(&'static str, Regex)>,
    prefixes: Vec<Regex>,
    dictionary: Regex,
    system_schema: Regex,
    redefine_with: Regex,
    redefine_as: Regex,
    scoped_events: Regex,
    version: Regex,
    uuid: Regex,
    from_address: Regex,
    stack_trace: Regex,
    privileges: Regex,
    code: Regex,
}

static PATTERNS: LazyLock<Patterns> = LazyLock::new(|| {
    let s = JS_SPACE_CLASS;
    Patterns {
        select_or_with: compile(&format!(r"\A(?:{}|{}){BOUNDARY}", ci("SELECT"), ci("WITH"))),
        cte: compile(&format!(r"(?:{BOUNDARY}{}|,){s}*([a-zA-Z_][a-zA-Z0-9_]*){s}+{}{s}*\(", ci("WITH"), ci("AS"))),
        table_keyword: compile(&format!(r"{BOUNDARY}({}{s}+{}|{}|{}){BOUNDARY}", ci("ARRAY"), ci("JOIN"), ci("FROM"), ci("JOIN"))),
        in_keyword: compile(&format!(r"{BOUNDARY}(?:{}{s}+)?(?:{}{s}+)?{}{BOUNDARY}", ci("GLOBAL"), ci("NOT"), ci("IN"))),
        keywords: BLOCKED_KEYWORDS.iter().map(|&keyword| (keyword, compile(&format!("{BOUNDARY}{}{BOUNDARY}", ci(keyword))))).collect(),
        functions: BLOCKED_FUNCTIONS.iter().map(|&name| (name, compile(&format!(r"{BOUNDARY}{}{s}*\(", ci(name))))).collect(),
        prefixes: BLOCKED_FUNCTION_PREFIXES
            .iter()
            .map(|&prefix| compile(&format!(r"{BOUNDARY}({}[A-Za-z0-9_]*){s}*\(", ci(prefix))))
            .collect(),
        dictionary: compile(&format!(r"{BOUNDARY}{}[A-Za-z]*{s}*\(", ci("dict"))),
        system_schema: compile(&format!(r"{BOUNDARY}(?:{}|{}){s}*\.", ci("system"), ci("information_schema"))),
        redefine_with: compile(&format!(r"{BOUNDARY}{}{s}+{}{s}+{}{BOUNDARY}", ci("WITH"), ci("scoped_events"), ci("AS"))),
        redefine_as: compile(&format!(r"{BOUNDARY}{}{s}+{}{BOUNDARY}", ci("AS"), ci("scoped_events"))),
        scoped_events: compile(&format!(r"{BOUNDARY}{}{BOUNDARY}", ci("scoped_events"))),
        version: compile(&format!(r"{s}*\(version [^()]*(?:\([^()]*\)[^()]*)*\)")),
        uuid: compile(&format!(
            r"{s}*\([0-9a-fA-F]{{8}}-[0-9a-fA-F]{{4}}-[0-9a-fA-F]{{4}}-[0-9a-fA-F]{{4}}-[0-9a-fA-F]{{12}}\)"
        )),
        from_address: compile(&format!(r"{s}*\(from [^)]*\)")),
        stack_trace: compile(&format!(r"{s}*Stack trace:(?s:.)*\z")),
        privileges: compile(&ci("Not enough privileges")),
        code: compile(r"\ACode: ([0-9]+)\."),
    }
});

#[derive(Clone, Copy, PartialEq, Eq)]
enum ScanState {
    Normal,
    Single,
    Double,
    Backtick,
    LineComment,
    BlockComment,
}

const QUOTE: u16 = b'\'' as u16;
const DOUBLE_QUOTE: u16 = b'"' as u16;
const BACKTICK: u16 = b'`' as u16;
const BACKSLASH: u16 = b'\\' as u16;
const NEWLINE: u16 = b'\n' as u16;
const SPACE: u16 = b' ' as u16;

fn unit(character: u8) -> Option<u16> {
    Some(character as u16)
}

/// `hasUnsupportedSyntax`: double quotes, backticks, `#`, `$` or `//` outside a
/// single-quoted literal or comment.
pub fn has_unsupported_syntax(query: &str) -> bool {
    let units: Vec<u16> = query.encode_utf16().collect();
    let mut index = 0;
    let mut state = ScanState::Normal;
    while index < units.len() {
        let current = units[index];
        let next = units.get(index + 1).copied();
        match state {
            ScanState::Normal => {
                if current == DOUBLE_QUOTE
                    || current == BACKTICK
                    || current == b'#' as u16
                    || current == b'$' as u16
                    || (current == b'/' as u16 && next == unit(b'/'))
                {
                    return true;
                }
                if current == QUOTE {
                    state = ScanState::Single;
                } else if current == b'-' as u16 && next == unit(b'-') {
                    state = ScanState::LineComment;
                    index += 1;
                } else if current == b'/' as u16 && next == unit(b'*') {
                    state = ScanState::BlockComment;
                    index += 1;
                }
            }
            ScanState::Single => {
                // A backslash escape or a doubled quote stays inside the literal
                if (current == BACKSLASH && next.is_some()) || (current == QUOTE && next == Some(QUOTE)) {
                    index += 1;
                } else if current == QUOTE {
                    state = ScanState::Normal;
                }
            }
            ScanState::LineComment => {
                if current == NEWLINE {
                    state = ScanState::Normal;
                }
            }
            ScanState::BlockComment => {
                if current == b'*' as u16 && next == unit(b'/') {
                    state = ScanState::Normal;
                    index += 1;
                }
            }
            ScanState::Double | ScanState::Backtick => unreachable!("not tracked by this scanner"),
        }
        index += 1;
    }
    false
}

/// `stripSqlLiteralsAndComments`: blank out literals, quoted identifiers and
/// comments in place, keeping length and newlines.
pub fn strip_sql_literals_and_comments(query: &str) -> String {
    let units: Vec<u16> = query.encode_utf16().collect();
    let mut result: Vec<u16> = Vec::with_capacity(units.len());
    let mut index = 0;
    let mut state = ScanState::Normal;
    let blank_or_newline = |value: u16| if value == NEWLINE { NEWLINE } else { SPACE };
    while index < units.len() {
        let current = units[index];
        let next = units.get(index + 1).copied();
        match state {
            ScanState::Normal => {
                if current == QUOTE {
                    state = ScanState::Single;
                    result.push(SPACE);
                } else if current == DOUBLE_QUOTE {
                    state = ScanState::Double;
                    result.push(SPACE);
                } else if current == BACKTICK {
                    state = ScanState::Backtick;
                    result.push(SPACE);
                } else if current == b'-' as u16 && next == unit(b'-') {
                    state = ScanState::LineComment;
                    result.extend([SPACE, SPACE]);
                    index += 1;
                } else if current == b'/' as u16 && next == unit(b'*') {
                    state = ScanState::BlockComment;
                    result.extend([SPACE, SPACE]);
                    index += 1;
                } else {
                    result.push(current);
                }
            }
            ScanState::Single => {
                if (current == BACKSLASH && next.is_some()) || (current == QUOTE && next == Some(QUOTE)) {
                    result.extend([SPACE, SPACE]);
                    index += 1;
                } else if current == QUOTE {
                    state = ScanState::Normal;
                    result.push(SPACE);
                } else {
                    result.push(blank_or_newline(current));
                }
            }
            ScanState::Double => {
                if current == BACKSLASH && next.is_some() {
                    result.extend([SPACE, SPACE]);
                    index += 1;
                } else if current == DOUBLE_QUOTE {
                    state = ScanState::Normal;
                    result.push(SPACE);
                } else {
                    result.push(blank_or_newline(current));
                }
            }
            ScanState::Backtick => {
                if current == BACKTICK {
                    state = ScanState::Normal;
                }
                result.push(SPACE);
            }
            ScanState::LineComment => {
                if current == NEWLINE {
                    state = ScanState::Normal;
                    result.push(NEWLINE);
                } else {
                    result.push(SPACE);
                }
            }
            ScanState::BlockComment => {
                if current == b'*' as u16 && next == unit(b'/') {
                    state = ScanState::Normal;
                    result.extend([SPACE, SPACE]);
                    index += 1;
                } else {
                    result.push(blank_or_newline(current));
                }
            }
        }
        index += 1;
    }
    String::from_utf16_lossy(&result)
}

/// `normalizeCustomQuery`: trim, drop trailing semicolons, trim again.
pub fn normalize_custom_query(query: &str) -> String {
    trim(trim(query).trim_end_matches(';')).to_string()
}

/// `getCteNames`: lowercased names declared as `WITH name AS (` or `, name AS (`.
pub fn get_cte_names(query: &str) -> IndexSet<String> {
    PATTERNS.cte.captures_iter(query).map(|captures| captures[1].to_ascii_lowercase()).collect()
}

const FROM_CLAUSE_TERMINATORS: [&str; 14] =
    ["where", "prewhere", "group", "having", "order", "limit", "settings", "union", "intersect", "except", "window", "qualify", "format", "into"];

fn is_identifier_start(byte: Option<&u8>) -> bool {
    matches!(byte, Some(b) if b.is_ascii_alphabetic() || *b == b'_')
}

fn is_identifier_char(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'.'
}

fn read_identifier(query: &str, start: usize) -> (&str, usize) {
    let bytes = query.as_bytes();
    let mut end = start;
    while end < bytes.len() && is_identifier_char(bytes[end]) {
        end += 1;
    }
    (&query[start..end], end)
}

fn skip_whitespace(query: &str, mut index: usize) -> usize {
    while let Some(character) = query[index..].chars().next() {
        if !is_js_space_char(character) {
            break;
        }
        index += character.len_utf8();
    }
    index
}

/// `collectTableReferences`: every table named after FROM / JOIN, including each
/// entry of a comma-separated FROM list.
pub fn collect_table_references(query: &str) -> Vec<String> {
    let bytes = query.as_bytes();
    let length = bytes.len();
    let mut references = Vec::new();
    let read_reference = |references: &mut Vec<String>, index: usize| {
        let start = skip_whitespace(query, index.min(length));
        if start < length && is_identifier_start(bytes.get(start)) {
            references.push(read_identifier(query, start).0.to_string());
        }
    };

    for keyword_match in PATTERNS.table_keyword.find_iter(query) {
        let after_keyword = keyword_match.end();
        let keyword = keyword_match.as_str().to_ascii_lowercase();
        if keyword.contains("array") {
            continue;
        }
        if keyword == "join" {
            read_reference(&mut references, after_keyword);
            continue;
        }

        read_reference(&mut references, after_keyword);
        let mut depth = 0;
        let mut index = after_keyword;
        while index < length {
            let byte = bytes[index];
            if byte == b'(' {
                depth += 1;
                index += 1;
            } else if byte == b')' {
                if depth == 0 {
                    break;
                }
                depth -= 1;
                index += 1;
            } else if byte == b',' && depth == 0 {
                read_reference(&mut references, index + 1);
                index += 1;
            } else if depth == 0 && is_identifier_start(Some(&byte)) {
                let (word, end) = read_identifier(query, index);
                if FROM_CLAUSE_TERMINATORS.contains(&word.to_ascii_lowercase().as_str()) {
                    break;
                }
                index = end;
            } else {
                index += 1;
            }
        }
    }
    references
}

/// `collectInTableReferences`: the `expr IN table` shorthand.
pub fn collect_in_table_references(query: &str) -> Vec<String> {
    let bytes = query.as_bytes();
    let mut references = Vec::new();
    for in_match in PATTERNS.in_keyword.find_iter(query) {
        let start = skip_whitespace(query, in_match.end());
        if start < bytes.len() && is_identifier_start(bytes.get(start)) {
            let (identifier, end) = read_identifier(query, start);
            if bytes.get(skip_whitespace(query, end)) == Some(&b'(') {
                continue;
            }
            references.push(identifier.to_string());
        }
    }
    references
}

/// `validateScopedQuery(query)`: why the query may not run, or `None`.
pub fn validate_scoped_query(query: &str) -> Option<String> {
    let result = validate_scoped_query_inner(query);
    if let Some(reason) = &result {
        debug!(reason = %reason, length = query.len(), "custom query rejected");
    }
    result
}

fn validate_scoped_query_inner(query: &str) -> Option<String> {
    let normalized = normalize_custom_query(query);
    if has_unsupported_syntax(&normalized) {
        return Some(UNSUPPORTED_SYNTAX_ERROR.to_string());
    }

    let without_literals = strip_sql_literals_and_comments(&normalized);
    let compact = trim(&without_literals);
    let cte_names = get_cte_names(compact);
    let patterns = &*PATTERNS;

    if !patterns.select_or_with.is_match(compact) {
        return Some("Only SELECT queries are allowed".to_string());
    }
    if compact.contains(';') {
        return Some("Only one SQL statement is allowed".to_string());
    }
    for (keyword, pattern) in &patterns.keywords {
        if pattern.is_match(compact) {
            return Some(format!("{keyword} is not allowed in custom analytics queries"));
        }
    }
    for (name, pattern) in &patterns.functions {
        if pattern.is_match(compact) {
            return Some(format!("{name}() is not allowed in custom analytics queries"));
        }
    }
    for pattern in &patterns.prefixes {
        if let Some(captures) = pattern.captures(compact) {
            return Some(format!("{}() is not allowed in custom analytics queries", &captures[1]));
        }
    }
    if patterns.dictionary.is_match(compact) {
        return Some("Dictionary functions are not allowed in custom analytics queries".to_string());
    }
    if patterns.system_schema.is_match(compact) {
        return Some(SCOPED_ONLY_ERROR.to_string());
    }
    if patterns.redefine_with.is_match(compact) || patterns.redefine_as.is_match(compact) {
        return Some("scoped_events is reserved and cannot be redefined".to_string());
    }
    for reference in collect_table_references(compact).into_iter().chain(collect_in_table_references(compact)) {
        let table = reference.to_ascii_lowercase();
        if table != "scoped_events" && !cte_names.contains(&table) {
            return Some(SCOPED_ONLY_ERROR.to_string());
        }
    }
    if !patterns.scoped_events.is_match(compact) {
        return Some("Query must read from scoped_events".to_string());
    }
    None
}

/// `userFacingClickhouseErrorCodes`.
const USER_FACING_CLICKHOUSE_ERROR_CODES: [u32; 30] =
    [6, 10, 16, 36, 42, 43, 44, 46, 47, 48, 49, 53, 62, 69, 70, 117, 158, 159, 160, 164, 179, 182, 184, 215, 241, 306, 386, 394, 452, 497];

/// `sanitizeClickhouseError(error)`. `message` is `error.message` when the thrown
/// value is an `Error`, `None` otherwise.
pub fn sanitize_clickhouse_error(message: Option<&str>) -> String {
    let raw = message.unwrap_or("");
    if raw.is_empty() {
        return "Failed to run query".to_string();
    }
    let patterns = &*PATTERNS;
    let code = patterns
        .code
        .captures(raw)
        .map_or(f64::NAN, |captures| string_to_number(&captures[1]));
    if code == 497.0 || patterns.privileges.is_match(raw) {
        return "Query references data outside scoped_events".to_string();
    }
    let user_facing = USER_FACING_CLICKHOUSE_ERROR_CODES.iter().any(|&known| f64::from(known) == code);
    if !code.is_finite() || !user_facing {
        return if code.is_finite() {
            format!("Query failed (ClickHouse error {})", number_to_string(code))
        } else {
            "Failed to run query".to_string()
        };
    }
    let cleaned = patterns.version.replace_all(raw, "");
    let cleaned = patterns.uuid.replace_all(&cleaned, "");
    let cleaned = patterns.from_address.replace_all(&cleaned, "");
    let cleaned = patterns.stack_trace.replace(&cleaned, "");
    trim(&cleaned).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    const QUOTED: &str = UNSUPPORTED_SYNTAX_ERROR;

    // Ported from customQueryValidation.test.ts
    #[test]
    fn table_reference_scoping() {
        assert_eq!(validate_scoped_query("SELECT count(*) FROM scoped_events"), None);
        assert_eq!(validate_scoped_query("WITH t AS (SELECT user_id, count() c FROM scoped_events GROUP BY user_id) SELECT * FROM t"), None);
        assert_eq!(validate_scoped_query("SELECT a.user_id FROM scoped_events a JOIN scoped_events b ON a.user_id = b.user_id"), None);
        assert_eq!(
            validate_scoped_query("SELECT count(*), uniq(user_id) FROM scoped_events GROUP BY pathname ORDER BY pathname, count() LIMIT 10"),
            None
        );
        assert_eq!(
            validate_scoped_query("SELECT sessions_mv_target.site_id FROM scoped_events, sessions_mv_target WHERE sessions_mv_target.site_id > 0 LIMIT 100").as_deref(),
            Some(SCOPED_ONLY_ERROR)
        );
        assert_eq!(
            validate_scoped_query("SELECT pathname_hourly_mv_target.pathname FROM scoped_events, pathname_hourly_mv_target LIMIT 100").as_deref(),
            Some(SCOPED_ONLY_ERROR)
        );
        assert_eq!(validate_scoped_query("SELECT * FROM scoped_events,sessions_mv_target LIMIT 1").as_deref(), Some(SCOPED_ONLY_ERROR));
        assert_eq!(
            validate_scoped_query("SELECT * FROM (SELECT * FROM scoped_events, sessions_mv_target) x LIMIT 1").as_deref(),
            Some(SCOPED_ONLY_ERROR)
        );
        assert_eq!(validate_scoped_query("SELECT * FROM events").as_deref(), Some(SCOPED_ONLY_ERROR));
        assert_eq!(validate_scoped_query("SELECT * FROM scoped_events JOIN events ON 1=1").as_deref(), Some(SCOPED_ONLY_ERROR));
        for query in [
            "SELECT count() FROM scoped_events WHERE user_id IN events",
            "SELECT count() FROM scoped_events WHERE user_id NOT IN events",
            "SELECT count() FROM scoped_events WHERE user_id in events",
            "SELECT count() FROM scoped_events WHERE user_id GLOBAL IN events",
            "SELECT count() FROM scoped_events WHERE user_id GLOBAL NOT IN events",
        ] {
            assert_eq!(validate_scoped_query(query).as_deref(), Some(SCOPED_ONLY_ERROR), "{query}");
        }
        assert_eq!(validate_scoped_query("SELECT count() FROM scoped_events WHERE user_id IN scoped_events"), None);
        assert_eq!(
            validate_scoped_query("WITH safe_users AS (SELECT user_id FROM scoped_events) SELECT count() FROM scoped_events WHERE user_id IN safe_users"),
            None
        );
        assert_eq!(validate_scoped_query("SELECT count() FROM scoped_events WHERE country IN tuple('US','GB')"), None);
        assert_eq!(validate_scoped_query("SELECT count() FROM scoped_events WHERE country IN ('US','GB')"), None);
        assert_eq!(validate_scoped_query("SELECT k, count() FROM scoped_events ARRAY JOIN mapKeys(url_parameters) AS k GROUP BY k"), None);
        assert_eq!(validate_scoped_query("SELECT k FROM scoped_events LEFT ARRAY JOIN mapKeys(url_parameters) AS k"), None);
        assert_eq!(
            validate_scoped_query("SELECT k FROM scoped_events ARRAY JOIN mapKeys(url_parameters) AS k JOIN events e ON 1=1").as_deref(),
            Some(SCOPED_ONLY_ERROR)
        );
        assert_eq!(validate_scoped_query(r#"SELECT * FROM "events" scoped_events WHERE 1=1"#).as_deref(), Some(QUOTED));
        assert_eq!(validate_scoped_query("SELECT * FROM `events` scoped_events WHERE 1=1").as_deref(), Some(QUOTED));
        assert_eq!(validate_scoped_query(r#"SELECT * FROM "scoped_events" WHERE 1=1"#).as_deref(), Some(QUOTED));
        assert_eq!(validate_scoped_query("SELECT 'quoted \"text\" and `ticks`' AS label FROM scoped_events"), None);
        assert_eq!(validate_scoped_query("SELECT 1").as_deref(), Some("Query must read from scoped_events"));
    }

    #[test]
    fn lexer_mismatch_bypasses() {
        for query in [
            "SELECT * FROM scoped_events WHERE 1=1 # '\nUNION ALL SELECT * FROM events WHERE site_id = 2 -- '",
            "SELECT * FROM scoped_events #! '\nUNION ALL SELECT * FROM events -- '",
            "SELECT * FROM scoped_events WHERE 1=1 // '\nUNION ALL SELECT * FROM events -- '",
            "SELECT * FROM scoped_events WHERE pathname = $$'$$ UNION ALL SELECT * FROM events -- '",
            "SELECT $x$'$x$ AS a FROM scoped_events UNION ALL SELECT * FROM events -- '",
        ] {
            assert_eq!(validate_scoped_query(query).as_deref(), Some(QUOTED), "{query}");
        }
        assert_eq!(validate_scoped_query("SELECT count() FROM scoped_events WHERE pathname LIKE '%#top%' OR pathname = '$x$'"), None);
        assert!(validate_scoped_query("SELECT * FROM icebergS3('http://x'), scoped_events").unwrap().contains("icebergS3() is not allowed"));
        assert!(validate_scoped_query("SELECT * FROM deltaLakeLocal('/tmp'), scoped_events").unwrap().contains("deltaLakeLocal() is not allowed"));
        assert_eq!(validate_scoped_query("SELECT hostName() FROM scoped_events").as_deref(), Some("hostName() is not allowed in custom analytics queries"));
        assert_eq!(validate_scoped_query("SELECT currentUser() FROM scoped_events").as_deref(), Some("currentUser() is not allowed in custom analytics queries"));
        assert_eq!(validate_scoped_query("SELECT sleepEachRow(1) FROM scoped_events").as_deref(), Some("sleepEachRow() is not allowed in custom analytics queries"));
        assert_eq!(
            validate_scoped_query("SELECT * FROM mergeTreeProjection('a','events','p'), scoped_events").as_deref(),
            Some("mergeTreeProjection() is not allowed in custom analytics queries")
        );
    }

    #[test]
    fn sanitize_errors() {
        assert_eq!(
            sanitize_clickhouse_error(Some(
                "Code: 47. DB::Exception: Unknown expression identifier 'foo' (table default.events (072583d3-1467-4d46-89ff-3f6981180a16)). (UNKNOWN_IDENTIFIER) (version 26.7.4.58 (official build))"
            )),
            "Code: 47. DB::Exception: Unknown expression identifier 'foo' (table default.events). (UNKNOWN_IDENTIFIER)"
        );
        assert_eq!(
            sanitize_clickhouse_error(Some("Code: 497. DB::Exception: hygo_query: Not enough privileges. (ACCESS_DENIED)")),
            "Query references data outside scoped_events"
        );
        assert_eq!(sanitize_clickhouse_error(None), "Failed to run query");
        assert_eq!(
            sanitize_clickhouse_error(Some("Code: 1. DB::Exception: user hygo_query failed reading /var/lib/clickhouse/store/x.bin on host ch-1")),
            "Query failed (ClickHouse error 1)"
        );
        assert_eq!(
            sanitize_clickhouse_error(Some("Code: 62. DB::Exception: Syntax error: failed at position 5 (from 10.0.0.1:1234)")),
            "Code: 62. DB::Exception: Syntax error: failed at position 5"
        );
    }

    // Ported from customQueryValidation.internals.test.ts
    #[test]
    fn strip_literals_and_comments() {
        for input in ["SELECT 'abc' FROM t", "SELECT 1 -- comment\nFROM t", "SELECT /* c */ 1 FROM t", "SELECT \"col\" FROM t"] {
            assert_eq!(strip_sql_literals_and_comments(input).len(), input.len());
        }
        assert_eq!(strip_sql_literals_and_comments("SELECT 'abc' FROM t"), "SELECT       FROM t");
        assert_eq!(strip_sql_literals_and_comments("SELECT 'it''s' FROM t"), "SELECT         FROM t");
        assert_eq!(strip_sql_literals_and_comments("SELECT 'a\\'b' FROM t"), "SELECT        FROM t");
        assert_eq!(strip_sql_literals_and_comments("SELECT 'a\nb' FROM t"), "SELECT   \n   FROM t");
        assert_eq!(strip_sql_literals_and_comments("SELECT 'abc"), "SELECT     ");
        assert_eq!(strip_sql_literals_and_comments("SELECT 1 -- FROM secret\nFROM t"), "SELECT 1               \nFROM t");
        assert_eq!(strip_sql_literals_and_comments("SELECT /* FROM secret */ 1 FROM t"), "SELECT                   1 FROM t");
        assert_eq!(strip_sql_literals_and_comments("SELECT 1 /* FROM secret"), "SELECT 1               ");
        let nested = "SELECT 1 /* a /* b */ x */ FROM t";
        let out = strip_sql_literals_and_comments(nested);
        assert_eq!(out.len(), nested.len());
        assert!(out.contains("x */ FROM t"));
        assert_eq!(strip_sql_literals_and_comments("SELECT \"col\" FROM t"), "SELECT       FROM t");
        assert_eq!(strip_sql_literals_and_comments("SELECT `col` FROM t"), "SELECT       FROM t");
        let out = strip_sql_literals_and_comments("SELECT 'FROM events' FROM scoped_events");
        assert_eq!(out, "SELECT               FROM scoped_events");
        assert_eq!(collect_table_references(&out), ["scoped_events"]);
        let out = strip_sql_literals_and_comments("SELECT 1 /* , events */ FROM scoped_events");
        assert_eq!(collect_table_references(&out), ["scoped_events"]);
        let out = strip_sql_literals_and_comments("SELECT '/* not a comment */' FROM t");
        assert_eq!(out, "SELECT                       FROM t");
        assert!(strip_sql_literals_and_comments("SELECT '-- x' AS c FROM scoped_events").contains("AS c FROM scoped_events"));
    }

    #[test]
    fn cte_names() {
        let names = |query: &str| get_cte_names(query).into_iter().collect::<Vec<_>>();
        assert_eq!(names("WITH foo AS (SELECT 1)"), ["foo"]);
        assert_eq!(names("WITH foo AS (SELECT 1), bar AS (SELECT 2)"), ["foo", "bar"]);
        assert_eq!(names("with FOO as (select 1)"), ["foo"]);
        assert_eq!(names("WITH Bar AS (SELECT 1)"), ["bar"]);
        assert_eq!(names("with foo as(select 1)"), ["foo"]);
        assert!(names("WITH foo AS SELECT 1").is_empty());
        assert!(names("SELECT x AS foo FROM scoped_events").is_empty());
        assert_eq!(names("WITH foo AS (SELECT 1), foo AS (SELECT 2)"), ["foo"]);
    }

    #[test]
    fn table_references() {
        assert_eq!(collect_table_references("SELECT * FROM a JOIN b ON 1=1"), ["a", "b"]);
        assert_eq!(collect_table_references("SELECT * FROM a, b, c WHERE x"), ["a", "b", "c"]);
        assert_eq!(collect_table_references("SELECT * FROM a WHERE x IN (1, 2)"), ["a"]);
        assert_eq!(collect_table_references("SELECT * FROM a GROUP BY x, y"), ["a"]);
        assert_eq!(collect_table_references("SELECT * FROM a ORDER BY x, y"), ["a"]);
        assert_eq!(collect_table_references("SELECT * FROM (SELECT * FROM inner) x"), ["inner"]);
        assert_eq!(collect_table_references("SELECT k FROM t ARRAY JOIN mapKeys(m) AS k"), ["t"]);
        assert_eq!(collect_table_references("SELECT k FROM t LEFT ARRAY JOIN mapKeys(m) AS k"), ["t"]);
        assert_eq!(collect_table_references("SELECT count(*), uniq(x) FROM t GROUP BY p"), ["t"]);
        assert_eq!(collect_table_references("SELECT * FROM system.tables"), ["system.tables"]);
        assert_eq!(collect_in_table_references("WHERE x IN events"), ["events"]);
        assert_eq!(collect_in_table_references("WHERE x NOT IN events"), ["events"]);
        assert_eq!(collect_in_table_references("WHERE x GLOBAL IN events"), ["events"]);
        assert_eq!(collect_in_table_references("WHERE x GLOBAL NOT IN events"), ["events"]);
        assert_eq!(collect_in_table_references("WHERE x in events"), ["events"]);
        assert!(collect_in_table_references("WHERE x IN (1, 2, 3)").is_empty());
        assert!(collect_in_table_references("WHERE x IN tuple('a', 'b')").is_empty());
        assert_eq!(collect_in_table_references("WHERE a IN t1 AND b IN t2"), ["t1", "t2"]);
    }

    #[test]
    fn unsupported_syntax_and_normalize() {
        assert!(has_unsupported_syntax("SELECT \"x\" FROM t"));
        assert!(has_unsupported_syntax("SELECT `x` FROM t"));
        assert!(!has_unsupported_syntax("SELECT 'has \" quote'"));
        assert!(!has_unsupported_syntax("SELECT 'has ` tick'"));
        assert!(!has_unsupported_syntax("SELECT 1 -- a \" b\nFROM t"));
        assert!(!has_unsupported_syntax("SELECT 1 /* a \" b */ FROM t"));
        assert!(!has_unsupported_syntax("SELECT 'it''s a \" test'"));
        assert!(!has_unsupported_syntax("SELECT 'a\\' \" b'"));
        assert!(!has_unsupported_syntax("SELECT count(*) FROM scoped_events"));
        assert_eq!(normalize_custom_query("  SELECT 1  "), "SELECT 1");
        assert_eq!(normalize_custom_query("SELECT 1;"), "SELECT 1");
        assert_eq!(normalize_custom_query("SELECT 1;;;"), "SELECT 1");
        assert_eq!(normalize_custom_query("  SELECT 1 ;;  "), "SELECT 1");
        assert_eq!(normalize_custom_query("SELECT 1; SELECT 2"), "SELECT 1; SELECT 2");
    }
}
