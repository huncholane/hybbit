//! Handler-level differential test against the real Node handlers.
//!
//! `parity/dump_handlers.mts` ran generated requests through the Node handlers with
//! ClickHouse, Site Configuration and site access stubbed, recording every I/O call
//! (SQL text, formatted query params, settings, the rows answered or the failure
//! raised) and the response. This test replays each case through the Rust handler
//! with a backend that checks each call against the recording, in order, answers
//! the same rows, and then compares the status and the JSON body byte for byte.
//!
//! The dump covers what the live HTTP harness (`parity/http_parity.py`) cannot:
//! the lite endpoints' materialized views (absent from the parity ClickHouse), and
//! injected ClickHouse failures on every query.

use std::{
    cell::RefCell,
    collections::VecDeque,
    fs::File,
    io::Read,
    path::PathBuf,
};

use flate2::read::GzDecoder;
use serde_json::{Map, Value};

use super::{Outcome, OverviewBackend, Row};
use crate::analytics::{
    js::{JsObject, JsValue, json, number::number_to_string},
    utils::{
        analytics_query::{AnalyticsQueryError, ClickHouseFailure, PaginatedRows, QuerySpec, format_query_param},
        utils::process_results,
    },
};

const MAX_PRINTED: usize = 30;

fn fixture() -> Option<JsObject> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/analytics/routes/overview/parity/fixtures/handlers.json.gz");
    let Ok(file) = File::open(&path) else {
        eprintln!("overview parity: fixture {} missing, skipped", path.display());
        return None;
    };
    let mut text = String::new();
    GzDecoder::new(file).read_to_string(&mut text).expect("readable fixture");
    match json::parse(&text).expect("fixture is JSON") {
        JsValue::Object(root) => Some(root),
        _ => panic!("fixture root is an object"),
    }
}

fn get<'a>(value: &'a JsValue, name: &str) -> &'a JsValue {
    value.as_object().expect("object").get_or_undefined(name)
}

fn text(value: &JsValue) -> String {
    value.as_str().map(str::to_string).unwrap_or_else(|| value.to_js_string())
}

fn rows_of(value: &JsValue, processed: bool) -> Vec<Row> {
    let JsValue::Array(items) = value else { panic!("rows are an array") };
    let mut rows: Vec<Row> = items
        .iter()
        .map(|item| match item.to_serde() {
            Value::Object(map) => map,
            other => panic!("row is an object, got {other}"),
        })
        .collect();
    if processed {
        process_results(&mut rows);
    }
    rows
}

/// Checks every call against Node's recording and answers Node's rows.
struct ReplayBackend<'a> {
    sql: &'a [JsValue],
    now: f64,
    expected: RefCell<VecDeque<JsValue>>,
    problems: RefCell<Vec<String>>,
}

impl ReplayBackend<'_> {
    fn next(&self, io: &str) -> Option<JsValue> {
        let call = self.expected.borrow_mut().pop_front();
        match call {
            Some(call) if get(&call, "io").as_str() == Some(io) => Some(call),
            Some(call) => {
                self.problems.borrow_mut().push(format!(
                    "Rust made a {io} call where Node made a {} call",
                    text(get(&call, "io"))
                ));
                None
            }
            None => {
                self.problems.borrow_mut().push(format!("Rust made an extra {io} call"));
                None
            }
        }
    }

    fn failure(spec: &QuerySpec) -> AnalyticsQueryError {
        AnalyticsQueryError { original: ClickHouseFailure::Decode { position: 0 }, queries: vec![spec.query.clone()] }
    }

    /// Compares one query call; `Some(rows)` when Node got rows, `None` when it failed.
    fn check_query(&self, spec: &QuerySpec, settings: &str, processed: bool) -> Option<Vec<Row>> {
        let call = self.next("query")?;
        let node_sql = text(&self.sql[get(&call, "sql").to_number() as usize]);
        if node_sql != spec.query {
            self.problems.borrow_mut().push(format!("SQL differs\n--- node\n{node_sql}\n--- rust\n{}", spec.query));
        }
        let node_params: Vec<(String, String)> = match get(&call, "params") {
            JsValue::Array(pairs) => pairs
                .iter()
                .map(|pair| match pair {
                    JsValue::Array(items) => (text(&items[0]), text(&items[1])),
                    _ => panic!("param pair"),
                })
                .collect(),
            _ => Vec::new(),
        };
        let rust_params: Vec<(String, String)> =
            spec.params.iter().map(|(name, value)| (name.clone(), format_query_param(value, false, false))).collect();
        if node_params != rust_params {
            self.problems.borrow_mut().push(format!("params differ: node {node_params:?}, rust {rust_params:?}"));
        }
        let node_settings = json::stringify(get(&call, "settings")).unwrap_or_default();
        if node_settings != settings {
            self.problems.borrow_mut().push(format!("settings differ: node {node_settings}, rust {settings}"));
        }
        if !get(&call, "error").is_undefined() {
            return None;
        }
        Some(rows_of(get(&call, "rows"), processed))
    }
}

impl OverviewBackend for ReplayBackend<'_> {
    async fn run_analytics_query(&self, spec: &QuerySpec) -> Result<Vec<Row>, AnalyticsQueryError> {
        self.check_query(spec, r#"{"max_execution_time":60}"#, true).ok_or_else(|| Self::failure(spec))
    }

    async fn run_paginated_query(&self, data: &QuerySpec, count: &QuerySpec) -> Result<PaginatedRows, AnalyticsQueryError> {
        let data_rows = self.check_query(data, r#"{"max_execution_time":60}"#, true);
        let count_rows = self.check_query(count, r#"{"max_execution_time":60}"#, true);
        let data_rows = data_rows.ok_or_else(|| Self::failure(data))?;
        let count_rows = count_rows.ok_or_else(|| Self::failure(count))?;
        let total_count = match count_rows.first().and_then(|row| row.get("totalCount")) {
            None | Some(Value::Null) => Value::from(0),
            Some(value) => value.clone(),
        };
        Ok(PaginatedRows { data: data_rows, total_count })
    }

    async fn query_rows_single_thread(&self, spec: &QuerySpec) -> Result<Vec<Row>, ClickHouseFailure> {
        self.check_query(spec, r#"{"max_threads":1}"#, false).ok_or(ClickHouseFailure::Decode { position: 0 })
    }

    async fn bounce_threshold(&self, site: f64) -> i32 {
        let Some(call) = self.next("bounce") else { return 10 };
        if text(get(&call, "site")) != number_to_string(site) || get(&call, "type").as_str() != Some("number") {
            self.problems.borrow_mut().push(format!(
                "bounce threshold read for {} ({}), Rust asked for {site}",
                text(get(&call, "site")),
                text(get(&call, "type"))
            ));
        }
        get(&call, "value").to_number() as i32
    }

    async fn site_is_public(&self, site_id: &str) -> bool {
        let Some(call) = self.next("config") else { return false };
        if text(get(&call, "site")) != site_id || get(&call, "type").as_str() != Some("string") {
            self.problems.borrow_mut().push(format!("config read for {}, Rust asked for {site_id}", text(get(&call, "site"))));
        }
        match get(&call, "value") {
            JsValue::Object(config) => config.get_or_undefined("public").is_truthy(),
            _ => false,
        }
    }

    async fn organization_site_ids(&self, organization_id: &str) -> Vec<i64> {
        let Some(call) = self.next("sites") else { return Vec::new() };
        let JsValue::Array(sites) = get(&call, "value") else { return Vec::new() };
        sites
            .iter()
            .filter(|site| get(site, "organizationId").as_str() == Some(organization_id))
            .map(|site| get(site, "siteId").to_number() as i64)
            .collect()
    }

    fn now_ms(&self) -> f64 {
        self.now
    }
}

async fn run_handler(backend: &ReplayBackend<'_>, handler: &str, params: &JsValue, query: &JsObject) -> Outcome {
    let site_id = text(get(params, "siteId"));
    match handler {
        "live" => super::live_users::get_live_user_count(backend, &site_id, query).await,
        "overview" => super::overview::get_overview(backend, &site_id, query).await,
        "overviewBucketed" => super::overview::get_overview_bucketed(backend, &site_id, query).await,
        "overviewLite" => super::lite::get_overview_lite(backend, &site_id, query).await,
        "overviewBucketedLite" => super::lite::get_overview_bucketed_lite(backend, &site_id, query).await,
        "metricLite" => super::lite::get_metric_lite(backend, &site_id, query).await,
        "metric" => super::metric::get_metric(backend, &site_id, query).await,
        "pageTitles" => super::page_titles::get_page_titles(backend, &site_id, query).await,
        "retention" => super::retention::get_retention(backend, &site_id, query).await,
        "journeys" => super::journeys::get_journeys(backend, &site_id, query).await,
        "hasData" => super::site_data::get_site_has_data(backend, &site_id, query).await,
        "isPublic" => super::site_data::get_site_is_public(backend, &site_id, query).await,
        "siteEventCount" => super::event_counts::get_site_event_count(backend, &site_id, query).await,
        "orgEventCount" => {
            super::event_counts::get_org_event_count(backend, &text(get(params, "organizationId")), query).await
        }
        other => panic!("unknown handler {other}"),
    }
}

#[tokio::test]
async fn overview_handlers_match_node() {
    let Some(root) = fixture() else { return };
    let JsValue::Array(sql) = root.get_or_undefined("sql") else { panic!("sql table") };
    let JsValue::Array(cases) = root.get_or_undefined("cases") else { panic!("cases") };
    let now = root.get_or_undefined("now").to_number();

    let mut per_handler: Map<String, Value> = Map::new();
    let mut failures = 0usize;
    for (index, case) in cases.iter().enumerate() {
        let handler = text(get(case, "handler"));
        let query = get(case, "query").as_object().cloned().unwrap_or_default();
        let JsValue::Array(calls) = get(case, "calls") else { panic!("calls") };
        let expected: VecDeque<JsValue> =
            calls.iter().filter(|call| !get(call, "rejected").is_truthy()).cloned().collect();
        let backend = ReplayBackend { sql, now, expected: RefCell::new(expected), problems: RefCell::new(Vec::new()) };

        let reply = match run_handler(&backend, &handler, get(case, "params"), &query).await {
            Ok(reply) => reply,
            Err(thrown) => thrown.into_reply(),
        };

        let mut problems = backend.problems.into_inner();
        let leftover = backend.expected.into_inner();
        if !leftover.is_empty() {
            problems.push(format!("Rust skipped {} call(s) Node made: {:?}", leftover.len(), leftover.iter().map(|call| text(get(call, "io"))).collect::<Vec<_>>()));
        }
        let response = get(case, "response");
        let node_status = get(response, "status").to_number() as u16;
        let node_body = text(get(response, "body"));
        let rust_body = reply.body_text();
        if node_status != reply.status.as_u16() || node_body != rust_body {
            problems.push(format!(
                "response differs\n  node {node_status} {node_body}\n  rust {} {rust_body}",
                reply.status.as_u16()
            ));
        }

        let entry = per_handler.entry(handler.clone()).or_insert_with(|| serde_json::json!({ "cases": 0, "failed": 0 }));
        entry["cases"] = Value::from(entry["cases"].as_u64().unwrap_or(0) + 1);
        if !problems.is_empty() {
            entry["failed"] = Value::from(entry["failed"].as_u64().unwrap_or(0) + 1);
            failures += 1;
            if failures <= MAX_PRINTED {
                eprintln!(
                    "overview parity #{index} {handler} query {}:\n{}",
                    json::stringify(&JsValue::Object(query.clone())).unwrap_or_default(),
                    problems.join("\n")
                );
            }
        }
    }
    eprintln!("overview parity: {} cases, {failures} failing, per handler {}", cases.len(), Value::Object(per_handler));
    assert_eq!(failures, 0, "Rust handlers diverge from Node");
}
