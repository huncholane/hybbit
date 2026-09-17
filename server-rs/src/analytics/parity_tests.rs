//! Differential tests: replay the corpora that `parity/analytics/dump.mts` ran
//! through the real Node modules (Node 24, TZ=UTC) and compare every output.
//!
//! Fixtures live in `parity/analytics/fixtures/*.json.gz`. Each comparison
//! re-encodes the Rust result the way the dump script encodes JavaScript values
//! (`undefined`, NaN, the infinities and -0 as `{"$js": ...}` tags) and compares
//! the JSON text. Up to 25 mismatches per corpus are printed with both outputs.

use std::{collections::HashSet, fs::File, io::Read, path::PathBuf};

use flate2::read::GzDecoder;

use super::{
    js::{JsObject, JsValue, date, intl, json, number, regexp},
    segments::{
        expand_segment_param::{LoadedSegment, apply_loaded_segment, segment_param_lookup},
        segment_schema::{
            Nullable, SegmentBody, parse_create_segment_body, parse_update_segment_body, segment_filters_schema_parse,
        },
    },
    sql_string,
    types::{Filter, FilterParameter, FilterType, FilterValue, TimeBucket},
    utils::{
        analytics_query::{QueryParam, format_query_param, get_pagination_statements, parse_clickhouse_error},
        custom_query_validation as cqv,
        event_conditions::{
            AutocaptureTargetType, PropertyFilter, PropertyValue, build_autocapture_condition, build_event_condition,
            build_page_condition,
        },
        get_filter_statement::{
            FilterStatementError, FilterStatementOptions, build_string_filter_condition, get_filter_statement, get_sql_param,
            validate_regex_pattern, wrap_like_value,
        },
        query_validation::{FiltersError, validate_filters, validate_http_time_params},
        session_filters::{
            build_filtered_sessions_cte, build_session_and_row_filter_fragments, get_session_filter_statement,
            target_event_row_level_params,
        },
        time_window::{
            TimeWindowParams, get_time_statement, normalize_datetime_for_clickhouse, parse_date_time_ms,
            resolve_time_window_with_clock,
        },
        utils::{pattern_to_regex, process_results},
    },
};

const FIXED_NOW: f64 = 1_710_056_096_789.0; // 2024-03-10T07:34:56.789Z
const MAX_PRINTED: usize = 25;

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("parity/analytics/fixtures").join(format!("{name}.json.gz"))
}

/// The fixture's cases, or `None` (test skipped) when fixtures were not generated.
fn load(name: &str) -> Option<Vec<JsValue>> {
    let path = fixture_path(name);
    let Ok(file) = File::open(&path) else {
        eprintln!("parity {name}: fixture {} missing, skipped", path.display());
        return None;
    };
    let mut text = String::new();
    GzDecoder::new(file).read_to_string(&mut text).expect("readable fixture");
    let root = json::parse(&text).expect("fixture is JSON");
    let JsValue::Object(root) = root else { panic!("fixture root is an object") };
    match root.get("cases") {
        Some(JsValue::Array(cases)) => Some(cases.clone()),
        _ => panic!("fixture has cases"),
    }
}

/// `enc` from the dump script.
fn enc(value: &JsValue) -> JsValue {
    let tag = |name: &str| {
        let mut object = JsObject::new();
        object.insert("$js", name.into());
        JsValue::Object(object)
    };
    match value {
        JsValue::Undefined => tag("undefined"),
        JsValue::Number(n) if n.is_nan() => tag("NaN"),
        JsValue::Number(n) if *n == f64::INFINITY => tag("Infinity"),
        JsValue::Number(n) if *n == f64::NEG_INFINITY => tag("-Infinity"),
        JsValue::Number(n) if *n == 0.0 && n.is_sign_negative() => tag("-0"),
        JsValue::Array(items) => JsValue::Array(items.iter().map(enc).collect()),
        JsValue::Object(object) => JsValue::Object(object.iter().map(|(key, item)| (key.to_string(), enc(item))).collect()),
        other => other.clone(),
    }
}

/// Inverse of `enc` for inputs.
fn dec(value: &JsValue) -> JsValue {
    match value {
        JsValue::Object(object) => {
            if object.len() == 1
                && let Some(JsValue::String(tag)) = object.get("$js")
            {
                return match tag.as_str() {
                    "undefined" => JsValue::Undefined,
                    "NaN" => JsValue::Number(f64::NAN),
                    "Infinity" => JsValue::Number(f64::INFINITY),
                    "-Infinity" => JsValue::Number(f64::NEG_INFINITY),
                    "-0" => JsValue::Number(-0.0),
                    other => panic!("unknown tag {other}"),
                };
            }
            JsValue::Object(object.iter().map(|(key, item)| (key.to_string(), dec(item))).collect())
        }
        JsValue::Array(items) => JsValue::Array(items.iter().map(dec).collect()),
        other => other.clone(),
    }
}

fn object(pairs: Vec<(&str, JsValue)>) -> JsValue {
    JsValue::Object(pairs.into_iter().map(|(key, value)| (key.to_string(), value)).collect())
}

/// `run(() => value)` succeeded.
fn ok(value: JsValue) -> JsValue {
    object(vec![("ok", enc(&value))])
}

/// `run` caught an error.
fn err(message: String, name: &str) -> JsValue {
    object(vec![("error", message.into()), ("name", name.into())])
}

fn field<'a>(case: &'a JsValue, name: &str) -> &'a JsValue {
    case.as_object().expect("case object").get_or_undefined(name)
}

fn text(case: &JsValue, name: &str) -> String {
    field(case, name).as_str().unwrap_or_else(|| panic!("{name} is a string")).to_string()
}

fn string_or_null(value: Option<String>) -> JsValue {
    value.map_or(JsValue::Null, JsValue::String)
}

struct Tally {
    name: &'static str,
    cases: usize,
    comparisons: usize,
    mismatches: usize,
}

impl Tally {
    fn new(name: &'static str) -> Self {
        Self { name, cases: 0, comparisons: 0, mismatches: 0 }
    }

    fn check(&mut self, index: usize, label: &str, input: &JsValue, expected: &JsValue, actual: JsValue) {
        self.comparisons += 1;
        let expected_text = json::stringify(expected).unwrap_or_else(|| "undefined".into());
        let actual_text = json::stringify(&actual).unwrap_or_else(|| "undefined".into());
        if expected_text != actual_text {
            self.mismatches += 1;
            if self.mismatches <= MAX_PRINTED {
                eprintln!(
                    "MISMATCH {} #{index} [{label}]\n  input: {}\n  node:  {}\n  rust:  {}",
                    self.name,
                    json::stringify(input).unwrap_or_default(),
                    expected_text,
                    actual_text
                );
            }
        }
    }

    fn finish(self) {
        eprintln!(
            "parity {}: {} cases, {} comparisons, {} agree, {} mismatches",
            self.name,
            self.cases,
            self.comparisons,
            self.comparisons - self.mismatches,
            self.mismatches
        );
        assert_eq!(self.mismatches, 0, "{} mismatches in {}", self.mismatches, self.name);
    }
}

fn filter_error(error: FilterStatementError) -> JsValue {
    let name = match &error {
        FilterStatementError::Filters(FiltersError::Schema(_)) => "ZodError",
        _ => "Error",
    };
    err(error.to_string(), name)
}

fn filter_value_of(value: &JsValue) -> FilterValue {
    match value {
        JsValue::String(text) => FilterValue::String(text.clone()),
        JsValue::Number(number) => FilterValue::Number(*number),
        other => panic!("unexpected filter value {other:?}"),
    }
}

fn filters_js(filters: &[Filter]) -> JsValue {
    JsValue::Array(filters.iter().map(Filter::to_js).collect())
}

#[test]
fn parity_filters() {
    let Some(cases) = load("filters") else { return };
    let mut tally = Tally::new("filters");
    const TIME: &str = "AND timestamp >= toDateTime('2024-01-01 00:00:00', 'UTC')";
    const TIME2: &str = "and\n\t timestamp > now() - INTERVAL 1 DAY  ";
    let allowlist: HashSet<FilterParameter> = ["browser", "country", "pathname", "user_id", "channel", "event_name", "lat", "feature_flag:beta"]
        .iter()
        .map(|name| FilterParameter::from_name(name).unwrap())
        .collect();
    let mappings: Vec<(String, String)> = [
        ("url_parameters['utm_source']", "utm_source"),
        ("pathname", "page_path"),
        ("lat", "latitude"),
        ("feature_flags['beta']", "beta_flag"),
    ]
    .iter()
    .map(|(from, to)| (from.to_string(), to.to_string()))
    .collect();

    for (index, case) in cases.iter().enumerate() {
        tally.cases += 1;
        let filters = dec(field(case, "filters"));
        let JsValue::Array(expected) = field(case, "results") else { panic!("results") };
        let statement = |result: Result<String, FilterStatementError>| result.map_or_else(filter_error, |sql| ok(sql.into()));
        let actual = vec![
            statement(get_filter_statement(&filters, None, None, &FilterStatementOptions::default())),
            statement(get_filter_statement(&filters, Some(42), Some(TIME), &FilterStatementOptions::default())),
            statement(get_filter_statement(
                &filters,
                Some(7),
                Some(TIME2),
                &FilterStatementOptions::session_level(vec![FilterParameter::Channel]),
            )),
            statement(get_filter_statement(
                &filters,
                Some(0),
                Some(TIME),
                &FilterStatementOptions {
                    session_level_params: Some(vec![]),
                    parameter_allowlist: Some(allowlist.clone()),
                    dual_user_id_columns: Some(false),
                    ..Default::default()
                },
            )),
            statement(get_filter_statement(
                &filters,
                Some(9),
                Some(""),
                &FilterStatementOptions {
                    field_mappings: Some(mappings.clone()),
                    session_level_params: Some(vec![
                        FilterParameter::Pathname,
                        FilterParameter::Hostname,
                        FilterParameter::City,
                        FilterParameter::FeatureFlag("beta".into()),
                    ]),
                    ..Default::default()
                },
            )),
            statement(get_session_filter_statement(&filters, 3, TIME)),
            build_filtered_sessions_cte(&filters, 3, TIME, "FilteredSessions")
                .map_or_else(filter_error, |cte| ok(string_or_null(cte))),
            build_session_and_row_filter_fragments(&filters, 3, TIME, &target_event_row_level_params(), "FilteredSessions")
                .map_or_else(filter_error, |fragments| {
                    ok(object(vec![
                        ("filteredSessionsCTE", string_or_null(fragments.filtered_sessions_cte)),
                        ("rowFilterStatement", fragments.row_filter_statement.into()),
                    ]))
                }),
            build_session_and_row_filter_fragments(&filters, 3, TIME, &[FilterParameter::EventName], "Custom").map_or_else(
                filter_error,
                |fragments| {
                    ok(object(vec![
                        ("filteredSessionsCTE", string_or_null(fragments.filtered_sessions_cte)),
                        ("rowFilterStatement", fragments.row_filter_statement.into()),
                    ]))
                },
            ),
            validate_filters(&filters.to_js_string()).map_or_else(
                |error| filter_error(FilterStatementError::Filters(error)),
                |parsed| ok(filters_js(&parsed)),
            ),
        ];
        for (position, (expected, actual)) in expected.iter().zip(actual).enumerate() {
            tally.check(index, &format!("result {position}"), &filters, expected, actual);
        }
    }
    tally.finish();
}

#[test]
fn parity_sql_params() {
    let Some(cases) = load("sql_params") else { return };
    let mut tally = Tally::new("sql_params");
    for (index, case) in cases.iter().enumerate() {
        tally.cases += 1;
        let parameter = text(case, "parameter");
        let actual = get_sql_param(&parameter).map_or_else(|error| err(error.to_string(), "ZodError"), |sql| ok(sql.into()));
        tally.check(index, "getSqlParam", field(case, "parameter"), field(case, "result"), actual);
    }
    tally.finish();
}

#[test]
fn parity_conditions() {
    let Some(cases) = load("conditions") else { return };
    let mut tally = Tally::new("conditions");
    for (index, case) in cases.iter().enumerate() {
        tally.cases += 1;
        let expression = text(case, "expression");
        let filter_type = FilterType::parse(&text(case, "type")).unwrap();
        let JsValue::Array(raw_values) = dec(field(case, "values")) else { panic!("values") };
        let values: Vec<FilterValue> = raw_values.iter().map(filter_value_of).collect();
        let condition = build_string_filter_condition(&expression, filter_type, &values)
            .map_or_else(filter_error, |sql| ok(sql.into()));
        tally.check(index, "condition", case, field(case, "condition"), condition);
        let wrapped = JsValue::Array(values.iter().map(|value| wrap_like_value(filter_type, value).into()).collect());
        tally.check(index, "wrapLikeValue", case, field(case, "wrapped"), wrapped);
        let regex = JsValue::Array(values.iter().map(|value| string_or_null(validate_regex_pattern(&value.to_js_string()))).collect());
        tally.check(index, "validateRegexPattern", case, field(case, "regex"), regex);
    }
    tally.finish();
}

#[test]
fn parity_time_windows() {
    let Some(cases) = load("time_windows") else { return };
    let mut tally = Tally::new("time_windows");
    let buckets = TimeBucket::ALL;
    for (index, case) in cases.iter().enumerate() {
        tally.cases += 1;
        let params = dec(field(case, "params"));
        tally.check(index, "validateHttpTimeParams", &params, field(case, "validate"), ok(string_or_null(validate_http_time_params(&params))));

        // resolveTimeWindow reads params.time_zone first: undefined and null throw
        let type_error = match &params {
            JsValue::Undefined => Some("Cannot read properties of undefined (reading 'time_zone')"),
            JsValue::Null => Some("Cannot read properties of null (reading 'time_zone')"),
            _ => None,
        };
        let window_params = match &params {
            JsValue::Object(object) => TimeWindowParams::from_object(object),
            _ => TimeWindowParams::default(),
        };
        let window = match type_error {
            Some(message) => err(message.to_string(), "TypeError"),
            None => match resolve_time_window_with_clock(&window_params, || FIXED_NOW) {
                Ok(window) => ok(object(vec![
                    ("isAllTime", window.is_all_time().into()),
                    ("where", window.where_timestamp().into()),
                    ("whereStart", window.where_clause("start_time").into()),
                    (
                        "bucketed",
                        JsValue::Array(
                            [TimeBucket::Minute, TimeBucket::Hour, TimeBucket::Week]
                                .iter()
                                .map(|bucket| window.bucketed("timestamp", *bucket).into())
                                .collect(),
                        ),
                    ),
                    ("fill", JsValue::Array(buckets.iter().map(|bucket| window.fill(*bucket).into()).collect())),
                ])),
                Err(error) => err(error.to_string(), "RangeError"),
            },
        };
        tally.check(index, "resolveTimeWindow", &params, field(case, "window"), window);

        let statement = match type_error {
            Some(message) => err(message.to_string(), "TypeError"),
            None => match resolve_time_window_with_clock(&window_params, || FIXED_NOW) {
                Ok(window) => ok(window.where_clause("event_hour").into()),
                Err(error) => err(error.to_string(), "RangeError"),
            },
        };
        tally.check(index, "getTimeStatement", &params, field(case, "statement"), statement);
    }
    // get_time_statement reads the real clock; exercise it once for coverage
    assert_eq!(get_time_statement(&TimeWindowParams::default(), "timestamp"), Ok(String::new()));
    tally.finish();
}

#[test]
fn parity_dates() {
    let Some(cases) = load("dates") else { return };
    let mut tally = Tally::new("dates");
    for (index, case) in cases.iter().enumerate() {
        tally.cases += 1;
        let input = text(case, "text");
        tally.check(index, "Date.parse", case, field(case, "parse"), enc(&JsValue::Number(date::parse(&input))));
        tally.check(index, "parseDateTimeMs", case, field(case, "parseDateTimeMs"), enc(&JsValue::Number(parse_date_time_ms(&input))));
        let normalized = normalize_datetime_for_clickhouse(&input)
            .map_or_else(|error| err(error.to_string(), "RangeError"), |value| ok(value.into()));
        tally.check(index, "normalizeDatetimeForClickhouse", case, field(case, "normalized"), normalized);
    }
    tally.finish();
}

#[test]
fn parity_numbers() {
    let Some(cases) = load("numbers") else { return };
    let mut tally = Tally::new("numbers");
    let show = |value: f64| -> JsValue {
        if value == 0.0 && value.is_sign_negative() { "-0".into() } else { number::number_to_string(value).into() }
    };
    for (index, case) in cases.iter().enumerate() {
        tally.cases += 1;
        let input = text(case, "text");
        tally.check(index, "Number", case, field(case, "number"), show(number::string_to_number(&input)));
        tally.check(index, "parseInt", case, field(case, "parseInt"), show(number::parse_int_10(&input)));
    }
    tally.finish();
}

#[test]
fn parity_time_zones() {
    let Some(cases) = load("time_zones") else { return };
    let mut tally = Tally::new("time_zones");
    for (index, case) in cases.iter().enumerate() {
        tally.cases += 1;
        let zone = text(case, "zone");
        let valid = intl::is_valid_time_zone(&zone);
        tally.check(index, "Intl.DateTimeFormat", case, field(case, "valid"), valid.into());
        tally.check(index, "isValidTimeZone", case, field(case, "isValidTimeZone"), valid.into());
    }
    tally.finish();
}

#[test]
fn parity_regexes() {
    let Some(cases) = load("regexes") else { return };
    let mut tally = Tally::new("regexes");
    for (index, case) in cases.iter().enumerate() {
        tally.cases += 1;
        let pattern = text(case, "pattern");
        // The fixture stores the SyntaxError message without its `Invalid regular expression: /<pattern>/: ` prefix
        let prefix = format!("Invalid regular expression: /{pattern}/: ");
        let raw = regexp::validate(&pattern)
            .err()
            .map(|message| message.strip_prefix(&prefix).map_or_else(|| format!("UNEXPECTED {message}"), str::to_string));
        tally.check(index, "new RegExp", case, field(case, "rawError"), string_or_null(raw));
        // and omits validateRegexPattern's result when it is exactly that SyntaxError
        let expected_validate = match (field(case, "validate"), field(case, "rawError")) {
            (JsValue::Undefined, JsValue::String(error)) => {
                JsValue::String(format!("Invalid regex pattern: Invalid regular expression: /{pattern}/: {error}"))
            }
            (stored, _) => stored.clone(),
        };
        tally.check(index, "validateRegexPattern", case, &expected_validate, string_or_null(validate_regex_pattern(&pattern)));
    }
    tally.finish();
}

#[test]
fn parity_custom_queries() {
    let Some(cases) = load("custom_queries") else { return };
    let mut tally = Tally::new("custom_queries");
    let strings = |items: Vec<String>| JsValue::Array(items.into_iter().map(JsValue::String).collect());
    for (index, case) in cases.iter().enumerate() {
        tally.cases += 1;
        let query = text(case, "query");
        let stripped = cqv::strip_sql_literals_and_comments(&query);
        let compact = crate::analytics::js::string::trim(&stripped);
        tally.check(index, "validateScopedQuery", case, field(case, "validate"), string_or_null(cqv::validate_scoped_query(&query)));
        tally.check(index, "normalizeCustomQuery", case, field(case, "normalized"), cqv::normalize_custom_query(&query).into());
        tally.check(index, "hasUnsupportedSyntax", case, field(case, "unsupported"), cqv::has_unsupported_syntax(&query).into());
        tally.check(index, "stripSqlLiteralsAndComments", case, field(case, "stripped"), stripped.clone().into());
        tally.check(index, "getCteNames", case, field(case, "cteNames"), strings(cqv::get_cte_names(compact).into_iter().collect()));
        tally.check(index, "collectTableReferences", case, field(case, "tables"), strings(cqv::collect_table_references(compact)));
        tally.check(index, "collectInTableReferences", case, field(case, "inTables"), strings(cqv::collect_in_table_references(compact)));
    }
    tally.finish();
}

#[test]
fn parity_clickhouse_errors() {
    let Some(cases) = load("clickhouse_errors") else { return };
    let mut tally = Tally::new("clickhouse_errors");
    for (index, case) in cases.iter().enumerate() {
        tally.cases += 1;
        let message = field(case, "message").as_str().map(str::to_string);
        tally.check(index, "sanitizeClickhouseError", case, field(case, "sanitized"), cqv::sanitize_clickhouse_error(message.as_deref()).into());
        let parsed = match &message {
            None => JsValue::Null,
            Some(body) => {
                let info = parse_clickhouse_error(body);
                object(vec![("message", info.message.into()), ("code", string_or_null(info.code)), ("type", string_or_null(info.kind))])
            }
        };
        tally.check(index, "parseError", case, field(case, "parsed"), parsed);
    }
    tally.finish();
}

fn segment_outcome(result: Result<SegmentBody, Vec<crate::analytics::js::zod::ZodIssue>>) -> JsValue {
    match result {
        Err(issues) => object(vec![("issues", crate::analytics::js::zod::issues_value(&issues))]),
        Ok(parsed) => {
            let mut data = JsObject::new();
            if let Some(name) = parsed.name {
                data.insert("name", name.into());
            }
            match parsed.description {
                Nullable::Absent => {}
                Nullable::Null => data.insert("description", JsValue::Null),
                Nullable::Value(text) => data.insert("description", text.into()),
            }
            if let Some(filters) = parsed.filters {
                data.insert("filters", filters_js(&filters));
            }
            if let Some(flag) = parsed.is_public {
                data.insert("isPublic", flag.into());
            }
            if let Some(scope) = parsed.scope {
                data.insert("scope", scope.as_str().into());
            }
            object(vec![("data", JsValue::Object(data))])
        }
    }
}

#[test]
fn parity_segment_schemas() {
    let Some(cases) = load("segment_schemas") else { return };
    let mut tally = Tally::new("segment_schemas");
    for (index, case) in cases.iter().enumerate() {
        tally.cases += 1;
        let body = dec(field(case, "body"));
        tally.check(index, "createSegmentSchema", &body, field(case, "create"), enc(&segment_outcome(parse_create_segment_body(&body))));
        tally.check(index, "updateSegmentSchema", &body, field(case, "update"), enc(&segment_outcome(parse_update_segment_body(&body))));
        let filters_value = match &body {
            JsValue::Object(object) => object.get_or_undefined("filters").clone(),
            _ => JsValue::Undefined,
        };
        let filters = match segment_filters_schema_parse(&filters_value) {
            Ok(filters) => object(vec![("data", filters_js(&filters))]),
            Err(issues) => object(vec![("issues", crate::analytics::js::zod::issues_value(&issues))]),
        };
        tally.check(index, "segmentFiltersSchema", &body, field(case, "filters"), enc(&filters));
    }
    tally.finish();
}

#[test]
fn parity_expand_segment() {
    let Some(cases) = load("expand_segment") else { return };
    let mut tally = Tally::new("expand_segment");
    for (index, case) in cases.iter().enumerate() {
        tally.cases += 1;
        let JsValue::Object(mut query) = dec(field(case, "query")) else { panic!("query") };
        let site_id = dec(field(case, "siteId"));
        let bearer = match field(case, "bearerCanRead") {
            JsValue::Bool(flag) => Some(*flag),
            _ => None,
        };
        let loaded = match field(case, "loaded") {
            JsValue::Null => None,
            other => {
                let loaded = dec(other);
                Some(LoadedSegment {
                    filters: field(&loaded, "filters").clone(),
                    is_public: matches!(field(&loaded, "isPublic"), JsValue::Bool(true)),
                })
            }
        };
        let has_site_access = matches!(field(case, "hasSiteAccess"), JsValue::Bool(true));

        let outcome = segment_param_lookup(&query, site_id.as_str(), bearer).and_then(|lookup| match lookup {
            None => Ok(()),
            Some(_) => apply_loaded_segment(&mut query, loaded.as_ref(), has_site_access),
        });
        let (status, payload) = match outcome {
            Ok(()) => (JsValue::Null, JsValue::Null),
            Err(rejection) => (JsValue::Number(f64::from(rejection.status)), rejection.body),
        };
        tally.check(index, "status", case, field(case, "status"), status);
        tally.check(index, "payload", case, field(case, "payload"), enc(&payload));
        tally.check(index, "filters", case, field(case, "filtersAfter"), enc(query.get_or_undefined("filters")));
    }
    tally.finish();
}

#[test]
fn parity_pagination() {
    let Some(cases) = load("pagination") else { return };
    let mut tally = Tally::new("pagination");
    for (index, case) in cases.iter().enumerate() {
        tally.cases += 1;
        let limit = dec(field(case, "limit"));
        let page = dec(field(case, "page"));
        let default_limit = field(case, "defaultLimit").to_number();
        let is_count = matches!(field(case, "isCount"), JsValue::Bool(true));
        let statements = get_pagination_statements(&limit, &page, default_limit, is_count);
        let actual = object(vec![
            ("limitStatement", statements.limit_statement.into()),
            ("offsetStatement", statements.offset_statement.into()),
        ]);
        tally.check(index, "getPaginationStatements", case, field(case, "result"), actual);
    }
    tally.finish();
}

#[test]
fn parity_event_conditions() {
    let Some(cases) = load("event_conditions") else { return };
    let mut tally = Tally::new("event_conditions");
    for (index, case) in cases.iter().enumerate() {
        tally.cases += 1;
        let pattern = text(case, "pattern");
        let JsValue::Array(raw_filters) = dec(field(case, "filters")) else { panic!("filters") };
        let filters: Vec<PropertyFilter> = raw_filters
            .iter()
            .map(|item| PropertyFilter {
                key: field(item, "key").as_str().unwrap().to_string(),
                value: match field(item, "value") {
                    JsValue::String(text) => PropertyValue::String(text.clone()),
                    JsValue::Number(number) => PropertyValue::Number(*number),
                    JsValue::Bool(flag) => PropertyValue::Bool(*flag),
                    other => panic!("unexpected property value {other:?}"),
                },
            })
            .collect();
        let target = match text(case, "type").as_str() {
            "outbound" => AutocaptureTargetType::Outbound,
            "button_click" => AutocaptureTargetType::ButtonClick,
            "form_submit" => AutocaptureTargetType::FormSubmit,
            _ => AutocaptureTargetType::Copy,
        };
        let autocapture_pattern = dec(field(case, "autocapturePattern"));
        tally.check(index, "patternToRegex", case, field(case, "patternToRegex"), pattern_to_regex(&pattern).into());
        tally.check(index, "buildPageCondition", case, field(case, "page"), build_page_condition(&pattern, &filters).into());
        tally.check(index, "buildEventCondition", case, field(case, "event"), build_event_condition(&pattern, &filters).into());
        tally.check(
            index,
            "buildAutocaptureCondition",
            case,
            field(case, "autocapture"),
            build_autocapture_condition(target, autocapture_pattern.as_str(), &filters).into(),
        );
    }
    tally.finish();
}

#[test]
fn parity_sql_string() {
    let Some(cases) = load("sql_string") else { return };
    let mut tally = Tally::new("sql_string");
    for (index, case) in cases.iter().enumerate() {
        tally.cases += 1;
        let value = dec(field(case, "value"));
        tally.check(index, "SqlString.escape", case, field(case, "escaped"), sql_string::escape(&value).into());
    }
    tally.finish();
}

fn query_param_of(value: &JsValue) -> QueryParam {
    if let JsValue::Object(object) = value
        && object.len() == 1
        && let Some(ms) = object.get("$date")
    {
        return QueryParam::Date(dec(ms).to_number());
    }
    match dec(value) {
        JsValue::Array(items) => QueryParam::Array(
            match value {
                JsValue::Array(raw) => raw.iter().map(query_param_of).collect(),
                _ => items.iter().map(QueryParam::from).collect(),
            },
        ),
        other => QueryParam::from(&other),
    }
}

#[test]
fn parity_query_params() {
    let Some(cases) = load("query_params") else { return };
    let mut tally = Tally::new("query_params");
    for (index, case) in cases.iter().enumerate() {
        tally.cases += 1;
        let param = query_param_of(field(case, "value"));
        tally.check(index, "formatQueryParams", case, field(case, "formatted"), format_query_param(&param, false, false).into());
    }
    tally.finish();
}

#[test]
fn parity_process_results() {
    let Some(cases) = load("process_results") else { return };
    let mut tally = Tally::new("process_results");
    for (index, case) in cases.iter().enumerate() {
        tally.cases += 1;
        let row = dec(field(case, "row"));
        let serde_json::Value::Object(map) = row.to_serde() else { panic!("row") };
        let mut rows = vec![map];
        process_results(&mut rows);
        let processed = JsValue::from_serde(&serde_json::Value::Object(rows.remove(0)));
        tally.check(index, "processResults", case, field(case, "processed"), enc(&processed));
    }
    tally.finish();
}

/// The query text one ClickHouse case rebuilds from its inputs (data query and,
/// for paginated cases, the count query).
fn rebuild_clickhouse_query(name: &str, inputs: &JsValue, now: f64) -> Result<(String, Option<String>), String> {
    let site_id = field(inputs, "siteId").to_number() as i64;
    let filters = field(inputs, "filters").clone();
    let params = match field(inputs, "params") {
        JsValue::Object(object) => TimeWindowParams::from_object(object),
        _ => TimeWindowParams::default(),
    };
    let bucket = TimeBucket::parse(field(inputs, "bucket").as_str().unwrap_or("hour")).unwrap_or(TimeBucket::Hour);
    let window = resolve_time_window_with_clock(&params, || now).map_err(|error| error.to_string())?;
    let time = window.where_timestamp();
    let filter = get_filter_statement(&filters, Some(site_id), Some(&time), &FilterStatementOptions::default())
        .map_err(|error| error.to_string())?;
    Ok(match name {
        "totals" => (
            format!(
                "SELECT count() AS events, uniqExact(session_id) AS sessions, round(avg(lat), 6) AS avg_lat FROM events WHERE site_id = {{siteId:Int32}} {time} {filter}"
            ),
            None,
        ),
        "filtered-sessions" => {
            let cte = build_filtered_sessions_cte(&filters, site_id, &time, "FilteredSessions").map_err(|error| error.to_string())?;
            let query = match cte {
                Some(cte) => {
                    format!("WITH {cte} SELECT count() AS sessions, toString(min(session_id)) AS first_session FROM FilteredSessions")
                }
                None => format!("SELECT uniqExact(session_id) AS sessions FROM events WHERE site_id = {{siteId:Int32}} {time}"),
            };
            (query, None)
        }
        "bucketed" => (
            format!(
                "SELECT {} AS time, count() AS pageviews, uniqExact(session_id) AS sessions\n          FROM events\n          WHERE site_id = {{siteId:Int32}} AND type = 'pageview' {time} {filter}\n          GROUP BY time ORDER BY time {}",
                window.bucketed("timestamp", bucket),
                window.fill(bucket)
            ),
            None,
        ),
        "row-fragments" => {
            let fragments =
                build_session_and_row_filter_fragments(&filters, site_id, &time, &target_event_row_level_params(), "FilteredSessions")
                    .map_err(|error| error.to_string())?;
            let cte = fragments.filtered_sessions_cte;
            (
                format!(
                    "{}\n          SELECT pathname, count() AS count, round(count() * 100 / sum(count()) OVER (), 2) AS percentage\n          FROM events {}\n          WHERE site_id = {{siteId:Int32}} {time} {}\n          GROUP BY pathname ORDER BY count DESC, pathname ASC LIMIT {{limit:Int32}};",
                    cte.as_ref().map(|cte| format!("WITH {cte}")).unwrap_or_default(),
                    if cte.is_some() { "INNER JOIN FilteredSessions USING (session_id)" } else { "" },
                    fragments.row_filter_statement
                ),
                None,
            )
        }
        "paginated" => {
            let pagination = field(inputs, "pagination");
            let statements = get_pagination_statements(field(pagination, "limit"), field(pagination, "page"), 4.0, false);
            (
                format!(
                    "SELECT session_id, count() AS events, max(timestamp) AS last_seen FROM events WHERE site_id = {{siteId:Int32}} {time} {filter} GROUP BY session_id ORDER BY events DESC, session_id ASC {} {}",
                    statements.limit_statement, statements.offset_statement
                ),
                Some(format!(
                    "SELECT COUNT(DISTINCT session_id) AS totalCount FROM events WHERE site_id = {{siteId:Int32}} {time} {filter}"
                )),
            )
        }
        other => panic!("unknown ClickHouse case {other}"),
    })
}

/// Complete queries built from the shared utils, run against the parity
/// ClickHouse by Node (fixture) and by the Rust executor (live). Needs the
/// parity stores: `cargo test parity_clickhouse -- --ignored`.
#[tokio::test]
#[ignore = "needs the parity ClickHouse (parity/docker-compose.yml)"]
async fn parity_clickhouse() {
    use crate::analytics::utils::analytics_query::{AnalyticsClickHouse, QuerySpec};

    let Some(cases) = load("clickhouse") else { return };
    let env = |name: &str, default: &str| std::env::var(name).unwrap_or_else(|_| default.to_string());
    let client = AnalyticsClickHouse::from_parts(
        &env("CLICKHOUSE_HOST", "http://127.0.0.1:58123"),
        &env("CLICKHOUSE_DB", "analytics"),
        &env("CLICKHOUSE_USER", "default"),
        &env("CLICKHOUSE_PASSWORD", "hygo"),
    )
    .expect("client");
    const CH_NOW: f64 = 1_789_043_696_789.0; // 2026-09-10T12:34:56.789Z

    let rows_value = |rows: Vec<serde_json::Map<String, serde_json::Value>>| {
        JsValue::Array(rows.into_iter().map(|row| JsValue::from_serde(&serde_json::Value::Object(row))).collect())
    };
    let spec_of = |query: String, params: &JsValue| {
        let mut spec = QuerySpec::new(query);
        if let JsValue::Object(object) = dec(params) {
            for (name, value) in object.iter() {
                spec.params.push((name.to_string(), QueryParam::from(value)));
            }
        }
        spec
    };

    let pg = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(&env("PARITY_DATABASE_URL", "postgres://hygo:hygo@127.0.0.1:55432/analytics"))
        .await
        .expect("parity Postgres");

    let mut tally = Tally::new("clickhouse");
    for (index, case) in cases.iter().enumerate() {
        tally.cases += 1;
        let name = text(case, "name");
        let inputs = dec(field(case, "inputs"));

        if name == "enrich" {
            use sqlx::Row;
            let current: Vec<String> = sqlx::query("SELECT site_id, user_id, traits FROM user_profiles")
                .fetch_all(&pg)
                .await
                .expect("profiles")
                .iter()
                .map(|row| {
                    let traits: Option<serde_json::Value> = row.get("traits");
                    let entry = JsValue::Array(vec![
                        JsValue::Number(f64::from(row.get::<i32, _>("site_id"))),
                        row.get::<String, _>("user_id").into(),
                        traits.as_ref().map_or(JsValue::Null, JsValue::from_serde),
                    ]);
                    json::stringify(&entry).unwrap_or_default()
                })
                .collect();
            let JsValue::Array(recorded) = field(case, "profiles") else { panic!("profiles") };
            let mut recorded: Vec<String> = recorded.iter().map(|item| json::stringify(item).unwrap_or_default()).collect();
            let mut current = current;
            recorded.sort();
            current.sort();
            if recorded != current {
                eprintln!("parity clickhouse #{index}: user_profiles changed since the dump, enrich case skipped");
                continue;
            }
            let site_id = field(&inputs, "siteId").to_number() as i32;
            let serde_json::Value::Array(rows) = field(&inputs, "rows").to_serde() else { panic!("rows") };
            let rows = rows.into_iter().map(|row| if let serde_json::Value::Object(map) = row { map } else { panic!("row") }).collect();
            let enriched = crate::analytics::utils::utils::enrich_with_traits(&pg, rows, site_id).await.expect("enrich");
            tally.check(index, "enrichWithTraits", &inputs, field(case, "rows"), enc(&rows_value(enriched)));
            continue;
        }

        if name == "filter-error" {
            let message = rebuild_clickhouse_query("totals", &inputs, CH_NOW).err().unwrap_or_else(|| "no error".into());
            tally.check(index, "filter error", &inputs, field(case, "error"), message.into());
            continue;
        }

        let (query, count_query) = if name == "params" || name == "error" {
            (text(case, "query"), None)
        } else {
            match rebuild_clickhouse_query(&name, &inputs, CH_NOW) {
                Ok((query, count)) => {
                    tally.check(index, "query text", &inputs, field(case, "query"), query.clone().into());
                    if let Some(count) = &count {
                        tally.check(index, "count query text", &inputs, field(case, "countQuery"), count.clone().into());
                    }
                    (query, count)
                }
                Err(message) => {
                    tally.check(index, "build", &inputs, &JsValue::from("built"), message.into());
                    continue;
                }
            }
        };

        let data_spec = spec_of(query, field(case, "params"));
        if let Some(count_query) = count_query {
            match client.run_paginated_query(&data_spec, &spec_of(count_query, field(case, "params"))).await {
                Ok(result) => {
                    tally.check(index, "rows", &inputs, field(case, "rows"), enc(&rows_value(result.data)));
                    tally.check(index, "totalCount", &inputs, field(case, "totalCount"), enc(&JsValue::from_serde(&result.total_count)));
                }
                Err(error) => tally.check(index, "error", &inputs, field(case, "error"), error.original.message().into()),
            }
            continue;
        }
        match client.run_analytics_query(&data_spec).await {
            Ok(rows) => tally.check(index, "rows", &inputs, field(case, "rows"), enc(&rows_value(rows))),
            Err(error) => tally.check(index, "error", &inputs, field(case, "error"), error.original.message().into()),
        }
    }
    tally.finish();
}
