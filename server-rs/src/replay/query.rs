//! `SessionReplayQueryService` (server/src/services/replay/sessionReplayQueryService.ts):
//! the replay list, one session's metadata and events, and deletion.
//!
//! The SQL is Node's template text byte for byte, whitespace included, so both
//! backends leave identical entries in ClickHouse's query log and bind the same
//! `{name:Type}` parameters.

use serde_json::{Map, Value};
use tracing::{debug, error};

use super::{
    json::{JsonSyntaxError, canonicalize},
    store::ReplayClickHouse,
};
use crate::analytics::{
    js::JsValue,
    utils::{
        analytics_query::{ClickHouseFailure, QueryParam, QuerySpec},
        effective_user_id::matches_user,
        get_filter_statement::{FilterStatementError, FilterStatementOptions, get_filter_statement},
        time_window::{RangeError, TimeWindowParams, get_time_statement},
    },
};

const DURATION_MS: &str = "dateDiff('millisecond', start_time, end_time)";

/// `METADATA_COLUMNS`: an aggregating table cannot be read with `SELECT *`.
fn metadata_columns() -> String {
    format!(
        "
  site_id,
  session_id,
  user_id,
  identified_user_id,
  start_time,
  end_time,
  {DURATION_MS} AS duration_ms,
  event_count,
  compressed_size_bytes,
  page_url,
  country,
  region,
  city,
  lat,
  lon,
  browser,
  browser_version,
  operating_system,
  operating_system_version,
  language,
  screen_width,
  screen_height,
  device_type,
  channel,
  hostname,
  referrer,
  has_replay_data
"
    )
}

/// Everything the service can throw; handlers map them to their 500s.
#[derive(Debug, thiserror::Error)]
pub enum QueryError {
    #[error(transparent)]
    ClickHouse(#[from] ClickHouseFailure),
    #[error("invalid time window: {0:?}")]
    TimeWindow(RangeError),
    #[error(transparent)]
    Filters(#[from] FilterStatementError),
    #[error("Session replay not found for session {0}")]
    NotFound(String),
    /// `JSON.parse(event.data)` threw
    #[error("stored event data is not JSON: {0}")]
    EventData(#[from] JsonSyntaxError),
    #[error("event serialisation task failed: {0}")]
    Task(String),
    #[error("loading user traits failed: {0}")]
    Traits(#[from] sqlx::Error),
}

/// The list options `getSessionReplays` passes, as raw JavaScript values.
#[derive(Clone, Debug)]
pub struct ListOptions {
    /// `limit ? Number(limit) : 50`
    pub limit: f64,
    /// `offset ? Number(offset) : 0`
    pub offset: f64,
    /// `userId || undefined`, the raw query value (a repeated param is an array)
    pub user_id: Option<JsValue>,
    /// `minDuration ? Number(minDuration) : undefined`
    pub min_duration: Option<f64>,
    pub time: TimeWindowParams,
    /// `filters || ""`
    pub filters: JsValue,
}

/// `getSessionReplayList`'s query.
pub fn list_query(site_id: f64, options: &ListOptions) -> Result<QuerySpec, QueryError> {
    let time_statement = get_time_statement(&options.time, "start_time").map_err(QueryError::TimeWindow)?;
    let filter_statement = get_filter_statement(&options.filters, None, None, &FilterStatementOptions::default())?;

    let mut where_conditions = vec!["site_id = {siteId:UInt16}".to_string()];
    let mut params: Vec<(String, QueryParam)> = vec![
        ("siteId".into(), QueryParam::Number(site_id)),
        ("limit".into(), QueryParam::Number(options.limit)),
        ("offset".into(), QueryParam::Number(options.offset)),
    ];

    if let Some(user_id) = &options.user_id {
        where_conditions.push(matches_user("{userId:String}", ""));
        params.push(("userId".into(), QueryParam::from(user_id)));
    }

    if let Some(min_duration) = options.min_duration {
        // Derived from the merged bounds: each batch only knows its own slice
        where_conditions.push(format!("{DURATION_MS} >= {{minDuration:UInt32}}"));
        params.push(("minDuration".into(), QueryParam::Number(min_duration * 1000.0)));
    }

    let session_ids_subquery = if filter_statement.is_empty() {
        "
      SELECT DISTINCT session_id
      FROM session_replay_events
      WHERE site_id = {siteId:UInt16} AND event_type = '2'
    "
        .to_string()
    } else {
        format!(
            "
        SELECT DISTINCT srm.session_id
        FROM session_replay_metadata_v2 srm
        FINAL
        WHERE srm.site_id = {{siteId:UInt16}}
          AND srm.session_id IN (
            SELECT DISTINCT session_id
            FROM session_replay_events
            WHERE site_id = {{siteId:UInt16}} AND event_type = '2'
          )
          AND srm.session_id IN (
            SELECT DISTINCT session_id
            FROM events
            WHERE site_id = {{siteId:UInt16}}
              {filter_statement}
          )
      "
        )
    };

    let query = format!(
        "
      SELECT
        session_id,
        user_id,
        identified_user_id,
        start_time,
        end_time,
        {DURATION_MS} AS duration_ms,
        page_url,
        event_count,
        country,
        region,
        city,
        browser,
        browser_version,
        operating_system,
        operating_system_version,
        device_type,
        screen_width,
        screen_height
      FROM session_replay_metadata_v2
      FINAL
      WHERE {where_clause}
        AND event_count >= 2
        AND session_id IN ({session_ids_subquery})
      {time_statement}
      ORDER BY start_time DESC
      LIMIT {{limit:UInt32}}
      OFFSET {{offset:UInt32}}
    ",
        where_clause = where_conditions.join(" AND "),
    );
    Ok(QuerySpec { query, params })
}

fn site_and_session(query: String, site_id: f64, session_id: &str) -> QuerySpec {
    QuerySpec::new(query).param("siteId", QueryParam::Number(site_id)).param("sessionId", session_id)
}

/// The metadata query shared by `getSessionReplayEvents` and `getSessionReplayMetadata`.
pub fn metadata_query(site_id: f64, session_id: &str) -> QuerySpec {
    let query = format!(
        "
        SELECT {columns}
        FROM session_replay_metadata_v2
        FINAL
        WHERE site_id = {{siteId:UInt16}}
          AND session_id = {{sessionId:String}}
        LIMIT 1
      ",
        columns = metadata_columns()
    );
    site_and_session(query, site_id, session_id)
}

pub fn events_query(site_id: f64, session_id: &str) -> QuerySpec {
    // Spelled with explicit newlines: Node's text has trailing spaces after SELECT
    // and after the site predicate, which editors would otherwise strip
    let query = concat!(
        "\n",
        "        SELECT \n",
        "          toUnixTimestamp64Milli(timestamp) as timestamp,\n",
        "          event_type as type,\n",
        "          event_data as data,\n",
        "          event_data_key,\n",
        "          batch_index\n",
        "        FROM session_replay_events\n",
        "        WHERE site_id = {siteId:UInt16} \n",
        "          AND session_id = {sessionId:String}\n",
        "        ORDER BY timestamp ASC, sequence_number ASC\n",
        "      ",
    );
    site_and_session(query.to_string(), site_id, session_id)
}

pub fn delete_queries(site_id: f64, session_id: &str) -> [QuerySpec; 2] {
    let events = "
        DELETE FROM session_replay_events
        WHERE site_id = {siteId:UInt16}
          AND session_id = {sessionId:String}
      ";
    let metadata = "
        DELETE FROM session_replay_metadata_v2
        WHERE site_id = {siteId:UInt16}
          AND session_id = {sessionId:String}
      ";
    [site_and_session(events.to_string(), site_id, session_id), site_and_session(metadata.to_string(), site_id, session_id)]
}

/// `getSessionReplayList`
pub async fn get_session_replay_list(
    store: &ReplayClickHouse,
    site_id: f64,
    options: &ListOptions,
) -> Result<Vec<Map<String, Value>>, QueryError> {
    let spec = list_query(site_id, options)?;
    let rows = store.query(&spec).await?;
    debug!(site_id, rows = rows.len(), "Loaded session replay list");
    Ok(rows)
}

/// `getSessionReplayMetadata`: the first row or None.
pub async fn get_session_replay_metadata(
    store: &ReplayClickHouse,
    site_id: f64,
    session_id: &str,
) -> Result<Option<Map<String, Value>>, QueryError> {
    Ok(store.query(&metadata_query(site_id, session_id)).await?.into_iter().next())
}

/// One replay event, `data` already in its `JSON.stringify(JSON.parse(data))` form.
pub struct ReplayEventOut {
    pub timestamp: Value,
    pub event_type: Value,
    pub data: String,
}

/// `GetSessionReplayEventsResponse` before the handler enriches the metadata.
pub struct ReplayEventsOut {
    pub events: Vec<ReplayEventOut>,
    pub metadata: Map<String, Value>,
}

/// `JSON.parse(event.data)`: processResults may have turned numeric text into a
/// number, which `JSON.parse` converts back to the same text first.
fn event_data_text(value: Option<Value>) -> String {
    match value {
        Some(Value::String(text)) => text,
        Some(Value::Number(number)) => crate::js_json::stringify(&Value::Number(number)),
        Some(Value::Null) => "null".to_string(),
        Some(Value::Bool(flag)) => flag.to_string(),
        // `undefined` and objects do not come out of this column
        _ => "undefined".to_string(),
    }
}

/// A timestamp's numeric value for the `a.timestamp - b.timestamp` sort.
fn js_number(value: &Value) -> f64 {
    match value {
        Value::Number(number) => number.as_f64().unwrap_or(f64::NAN),
        Value::String(text) => crate::analytics::js::number::string_to_number(text),
        Value::Null => 0.0,
        Value::Bool(flag) => f64::from(u8::from(*flag)),
        _ => f64::NAN,
    }
}

/// `getSessionReplayEvents`
pub async fn get_session_replay_events(
    store: &ReplayClickHouse,
    site_id: f64,
    session_id: &str,
) -> Result<ReplayEventsOut, QueryError> {
    let Some(metadata) = store.query(&metadata_query(site_id, session_id)).await?.into_iter().next() else {
        return Err(QueryError::NotFound(session_id.to_string()));
    };

    let rows = store.query(&events_query(site_id, session_id)).await?;
    let row_count = rows.len();

    let events = tokio::task::spawn_blocking(move || assemble_events(rows))
        .await
        .map_err(|join| QueryError::Task(join.to_string()))??;
    debug!(site_id, rows = row_count, events = events.len(), "Loaded session replay events");
    Ok(ReplayEventsOut { events, metadata })
}

/// Groups rows by `event_data_key` in first-seen order (R2 is disabled, so every
/// group is read from ClickHouse), parses each row's data, then sorts by timestamp
/// with a stable sort, as Node's `Array.prototype.sort` does.
fn assemble_events(rows: Vec<Map<String, Value>>) -> Result<Vec<ReplayEventOut>, QueryError> {
    let mut groups: Vec<(Value, Vec<Map<String, Value>>)> = Vec::new();
    for row in rows {
        let key = row.get("event_data_key").cloned().unwrap_or(Value::Null);
        match groups.iter_mut().find(|(existing, _)| *existing == key) {
            Some((_, members)) => members.push(row),
            None => groups.push((key, vec![row])),
        }
    }

    let mut events = Vec::new();
    for (_, members) in groups {
        for mut row in members {
            let text = event_data_text(row.remove("data"));
            let data = canonicalize(&text).inspect_err(|err| {
                error!(position = err.position, bytes = text.len(), "Stored replay event data is not valid JSON");
            })?;
            events.push(ReplayEventOut {
                timestamp: row.remove("timestamp").unwrap_or(Value::Null),
                event_type: row.remove("type").unwrap_or(Value::Null),
                data,
            });
        }
    }

    events.sort_by(|a, b| {
        let difference = js_number(&a.timestamp) - js_number(&b.timestamp);
        // A comparator returning NaN or 0 leaves the pair in place
        difference.partial_cmp(&0.0).unwrap_or(std::cmp::Ordering::Equal)
    });
    Ok(events)
}

/// `deleteSessionReplay`: events, then metadata (R2 keys only exist on cloud).
pub async fn delete_session_replay(store: &ReplayClickHouse, site_id: f64, session_id: &str) -> Result<(), QueryError> {
    let [events, metadata] = delete_queries(site_id, session_id);
    store.command(&events).await?;
    store.command(&metadata).await?;
    debug!(site_id, session_id, "Deleted session replay");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn options() -> ListOptions {
        ListOptions {
            limit: 50.0,
            offset: 0.0,
            user_id: None,
            min_duration: None,
            time: TimeWindowParams::default(),
            filters: JsValue::from(""),
        }
    }

    #[test]
    fn list_query_matches_node_text() {
        let spec = list_query(3.0, &options()).unwrap();
        assert!(spec.query.starts_with("\n      SELECT\n        session_id,\n"));
        assert!(spec.query.contains("      WHERE site_id = {siteId:UInt16}\n        AND event_count >= 2\n        AND session_id IN (\n      SELECT DISTINCT session_id\n      FROM session_replay_events\n      WHERE site_id = {siteId:UInt16} AND event_type = '2'\n    )\n"));
        assert!(spec.query.ends_with("      ORDER BY start_time DESC\n      LIMIT {limit:UInt32}\n      OFFSET {offset:UInt32}\n    "));
        assert_eq!(spec.params.iter().map(|(name, _)| name.as_str()).collect::<Vec<_>>(), ["siteId", "limit", "offset"]);

        let spec = list_query(
            3.0,
            &ListOptions {
                user_id: Some(JsValue::from("u1")),
                min_duration: Some(1.5),
                filters: JsValue::from(r#"[{"parameter":"browser","type":"equals","value":["Chrome"]}]"#),
                ..options()
            },
        )
        .unwrap();
        assert!(spec.query.contains("WHERE site_id = {siteId:UInt16} AND (identified_user_id = {userId:String} OR (user_id = {userId:String} AND identified_user_id = '')) AND dateDiff('millisecond', start_time, end_time) >= {minDuration:UInt32}\n"));
        assert!(spec.query.contains("FROM session_replay_metadata_v2 srm\n        FINAL\n"));
        assert_eq!(spec.params[4], ("minDuration".to_string(), QueryParam::Number(1500.0)));
    }

    #[test]
    fn events_query_keeps_node_trailing_spaces() {
        let spec = events_query(3.0, "s");
        assert!(spec.query.contains("        SELECT \n          toUnixTimestamp64Milli(timestamp) as timestamp,\n"));
        assert!(spec.query.contains("        WHERE site_id = {siteId:UInt16} \n          AND session_id = {sessionId:String}\n"));
    }

    #[test]
    fn events_are_grouped_by_batch_key_then_stably_sorted() {
        let row = |timestamp: i64, key: Value, data: &str| {
            let mut map = Map::new();
            map.insert("timestamp".into(), Value::from(timestamp));
            map.insert("type".into(), Value::from(3));
            map.insert("data".into(), Value::from(data));
            map.insert("event_data_key".into(), key);
            map.insert("batch_index".into(), Value::Null);
            map
        };
        let events = assemble_events(vec![
            row(1, Value::Null, "{\"n\":1}"),
            row(2, Value::from("k"), "{\"n\":2}"),
            row(2, Value::Null, "{\"n\":3}"),
            row(3, Value::Null, "[1.0]"),
        ])
        .unwrap();
        assert_eq!(events.iter().map(|event| event.data.as_str()).collect::<Vec<_>>(), ["{\"n\":1}", "{\"n\":3}", "{\"n\":2}", "[1]"]);
        assert!(assemble_events(vec![row(1, Value::from("r2"), "")]).is_err());
    }
}
