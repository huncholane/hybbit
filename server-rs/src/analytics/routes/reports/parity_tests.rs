//! Differential test: replay `parity/fixtures.json.gz`, which `parity/dump.mts`
//! produced by running the Node query builders and `goalBodySchema` (Node 24,
//! TZ=UTC), and compare every SQL text, `null` result, thrown error and zod issue
//! list with the Rust port. Up to 25 mismatches are printed with both outputs.
//!
//! One divergence is by design: for a time-series `bucket` that is not a
//! `TimeBucketToFn` key, Node renders `undefined(...)` or a native function's
//! source into SQL that ClickHouse then rejects, while the Rust builders stop
//! before building it. Both answer the same 500, so those cases only require the
//! Rust side to fail.

use std::{fs::File, io::Read, path::PathBuf};

use flate2::read::GzDecoder;

use crate::analytics::js::{JsObject, JsValue, json, zod};

use super::{bots, conditions, funnels, goals, performance};

const MAX_PRINTED: usize = 25;

fn load() -> Option<Vec<JsValue>> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/analytics/routes/reports/parity/fixtures.json.gz");
    let Ok(file) = File::open(&path) else {
        eprintln!("reports parity: fixture {} missing, skipped", path.display());
        return None;
    };
    let mut text = String::new();
    GzDecoder::new(file).read_to_string(&mut text).expect("readable fixture");
    match json::parse(&text).expect("fixture is JSON") {
        JsValue::Object(root) => match root.get("cases") {
            Some(JsValue::Array(cases)) => Some(cases.clone()),
            _ => panic!("fixture has cases"),
        },
        _ => panic!("fixture root is an object"),
    }
}

fn object(value: &JsValue) -> JsObject {
    value.as_object().cloned().unwrap_or_default()
}

fn number(value: &JsValue) -> f64 {
    match value {
        JsValue::Number(number) => *number,
        other => panic!("expected a number, got {other:?}"),
    }
}

fn goal_rows(value: &JsValue) -> Vec<goals::GoalRow> {
    let JsValue::Array(items) = value else { panic!("goals are an array") };
    items.iter().map(goal_row).collect()
}

fn goal_row(value: &JsValue) -> goals::GoalRow {
    let goal = object(value);
    goals::GoalRow {
        goal_id: number(goal.get_or_undefined("goalId")) as i32,
        site_id: number(goal.get_or_undefined("siteId")) as i32,
        name: goal.get_or_undefined("name").as_str().map(str::to_string),
        goal_type: goal.get_or_undefined("goalType").as_str().unwrap_or_default().to_string(),
        config: goal.get_or_undefined("config").clone(),
        created_at: goal.get_or_undefined("createdAt").as_str().map(str::to_string),
    }
}

/// What a builder returned, as the fixture spells it: `{"ok": sql}`,
/// `{"ok": null}` or `{"error": ...}` (the message is not compared).
#[derive(Debug, PartialEq)]
enum Outcome {
    Sql(String),
    Null,
    Error,
}

fn expected(result: &JsValue) -> Outcome {
    let result = object(result);
    match (result.get("ok"), result.get("error")) {
        (Some(JsValue::String(sql)), _) => Outcome::Sql(sql.clone()),
        (Some(JsValue::Null), _) => Outcome::Null,
        (_, Some(_)) => Outcome::Error,
        other => panic!("unexpected fixture result {other:?}"),
    }
}

fn from_result<E>(result: Result<String, E>) -> Outcome {
    result.map_or(Outcome::Error, Outcome::Sql)
}

fn from_optional<E>(result: Result<Option<String>, E>) -> Outcome {
    match result {
        Ok(Some(sql)) => Outcome::Sql(sql),
        Ok(None) => Outcome::Null,
        Err(_) => Outcome::Error,
    }
}

/// Node built SQL around a bucket that is not a time bucket function.
fn renders_invalid_bucket(outcome: &Outcome) -> bool {
    matches!(outcome, Outcome::Sql(sql) if sql.contains("toDateTime(undefined(") || sql.contains("[native code]") || sql.contains("toDateTime([object Object]("))
}

fn goal_body_value(body: &goals::GoalBody) -> JsValue {
    let mut data = JsObject::new();
    if let Some(name) = &body.name {
        data.insert("name", JsValue::String(name.clone()));
    }
    data.insert("goalType", JsValue::String(body.goal_type.clone()));
    data.insert("config", JsValue::Object(body.config.clone()));
    let mut result = JsObject::new();
    result.insert("ok", JsValue::Object(data));
    JsValue::Object(result)
}

#[test]
fn reports_builders_match_node() {
    let Some(cases) = load() else { return };
    let mut failures = 0;
    let mut compared = 0;
    for case in &cases {
        let case = object(case);
        let function = case.get_or_undefined("fn").as_str().unwrap_or_default().to_string();
        let JsValue::Array(args) = case.get_or_undefined("args").clone() else { panic!("args") };
        let result = case.get_or_undefined("result");
        compared += 1;

        if function == "goalBodySchema" {
            let actual = match goals::parse_goal_body(&args[0]) {
                Ok(body) => json::stringify(&goal_body_value(&body)).unwrap(),
                Err(issues) => {
                    let mut wrapper = JsObject::new();
                    wrapper.insert("issues", zod::issues_value(&issues));
                    json::stringify(&JsValue::Object(wrapper)).unwrap()
                }
            };
            let wanted = json::stringify(result).unwrap();
            if actual != wanted {
                failures += 1;
                if failures <= MAX_PRINTED {
                    eprintln!("goalBodySchema {}\n  node: {wanted}\n  rust: {actual}", json::stringify(&args[0]).unwrap());
                }
            }
            continue;
        }

        let wanted = expected(result);
        let query = || object(&args[0]);
        let actual = match function.as_str() {
            "buildFunnelQuery" => from_result(funnels::build_funnel_query(&query(), number(&args[1]), &args[2])),
            "buildFunnelStepSessionsQuery" => from_result(funnels::build_funnel_step_sessions_query(
                &query(),
                number(&args[1]),
                &args[2],
                number(&args[3]) as usize,
            )),
            "buildGoalsTotalSessionsQuery" => from_result(goals::build_goals_total_sessions_query(&query(), number(&args[1]))),
            "buildGoalsConversionsQuery" => {
                from_optional(goals::build_goals_conversions_query(&query(), number(&args[1]), &goal_rows(&args[2])))
            }
            "buildGoalTimeSeriesQuery" => {
                from_optional(goals::build_goal_time_series_query(&query(), number(&args[1]), &goal_rows(&args[2])))
            }
            "buildGoalCondition" => {
                let goal = goal_row(&args[0]);
                from_optional(conditions::build_goal_condition(&goal.goal_type, &goal.config))
            }
            "buildGoalSessionsQuery" => from_result(goals::build_goal_sessions_query(
                &query(),
                number(&args[1]),
                args[2].as_str().unwrap_or_default(),
            )),
            "buildPerformanceOverviewQuery" => {
                from_result(performance::build_performance_overview_query(&query(), number(&args[1])))
            }
            "buildPerformanceTimeSeriesQuery" => {
                from_result(performance::build_performance_time_series_query(&query(), number(&args[1])))
            }
            "buildPerformanceByDimensionQuery" => from_result(performance::build_performance_by_dimension_query(
                &query(),
                number(&args[1]),
                args[2] == JsValue::Bool(true),
            )),
            "buildBotOverviewQuery" => from_result(bots::build_bot_overview_query(&query())),
            "buildBotTimeSeriesQuery" => from_result(bots::build_bot_time_series_query(&query())),
            "buildBotDimensionQuery" => from_result(bots::build_bot_dimension_query(&query(), args[1] == JsValue::Bool(true))),
            "buildBotAiSummaryQuery" => from_result(bots::build_bot_ai_summary_query(&query())),
            other => panic!("unknown builder {other}"),
        };

        let time_series = matches!(function.as_str(), "buildPerformanceTimeSeriesQuery" | "buildBotTimeSeriesQuery");
        if actual == wanted || (time_series && actual == Outcome::Error && renders_invalid_bucket(&wanted)) {
            continue;
        }
        failures += 1;
        if failures <= MAX_PRINTED {
            eprintln!(
                "{function} {}\n  node: {wanted:?}\n  rust: {actual:?}",
                json::stringify(&JsValue::Array(args.clone())).unwrap_or_default()
            );
        }
    }
    eprintln!("reports parity: {compared} cases, {failures} mismatches");
    assert_eq!(failures, 0, "{failures} of {compared} builder cases differ from Node");
}
