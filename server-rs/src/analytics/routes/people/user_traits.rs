//! Trait inventory on the `publicUsersRead` chain, ported from
//! server/src/api/analytics/users/getUserTraits.ts: the trait keys a Site's
//! profiles carry, the values of one key, and the users holding one value.

use std::collections::HashMap;

use axum::{
    extract::State,
    http::{HeaderMap, Method, Uri},
    response::Response,
};
use serde_json::{Map, Value, json};
use sqlx::Row;
use tracing::{debug, info};

use super::{
    common::{
        HandlerError, RouteFailure, bad_request, clickhouse, number_value, ok, parse_int_radix_10, pg_integer, pg_row_count, query_value,
        route_failure, with_default,
    },
    users::users_chain,
};
use crate::{
    analytics::{
        js::JsValue,
        utils::{
            analytics_query::{QueryParam, QuerySpec},
            effective_user_id::effective_user_id,
        },
    },
    state::AppState,
};

fn site_number(site_id: &str) -> f64 {
    JsValue::from(site_id).to_number()
}

/// A query value bound into Postgres. postgres.js cannot bind the array a
/// repeated query parameter becomes, so only strings get through.
fn pg_text(value: &JsValue, name: &str) -> Result<String, HandlerError> {
    match value {
        JsValue::String(text) => Ok(text.clone()),
        other => Err(HandlerError::new(format!("{name} cannot be bound as a {} parameter", other.type_of()))),
    }
}

/// `GET /api/sites/:siteId/user-traits/keys`
pub async fn get_user_trait_keys(State(state): State<AppState>, method: Method, uri: Uri, headers: HeaderMap) -> Response {
    let (request, _) = match users_chain(&state, &method, &uri, &headers, &[]).await {
        Ok(chained) => chained,
        Err(response) => return response,
    };
    let result: Result<Value, RouteFailure> = async {
        let rows = sqlx::query(
            r#"
      SELECT key, COUNT(*)::int AS user_count
      FROM user_profiles,
           LATERAL jsonb_object_keys(COALESCE(traits, '{}'::jsonb)) AS key
      WHERE site_id = $1
      GROUP BY key
      ORDER BY user_count DESC
    "#,
        )
        .bind(pg_integer(site_number(&request.site_id))?)
        .fetch_all(&state.pg)
        .await?;
        let keys = rows
            .iter()
            .map(|row| {
                Ok(json!({
                    "key": row.try_get::<Option<String>, _>("key")?,
                    "userCount": row.try_get::<Option<i32>, _>("user_count")?,
                }))
            })
            .collect::<Result<Vec<Value>, sqlx::Error>>()?;
        Ok(json!({ "keys": keys }))
    }
    .await;
    match result {
        Ok(body) => {
            info!(site_id = %request.site_id, "Served user trait keys");
            ok(body)
        }
        Err(failure) => route_failure("user trait keys", failure),
    }
}

/// `GET /api/sites/:siteId/user-traits/values`
pub async fn get_user_trait_values(
    State(state): State<AppState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    let (request, _) = match users_chain(&state, &method, &uri, &headers, &[]).await {
        Ok(chained) => chained,
        Err(response) => return response,
    };
    let query = &request.query;
    let key = query_value(query, "key");
    if !key.is_truthy() {
        return bad_request("key query parameter is required");
    }

    let result: Result<Value, RouteFailure> = async {
        let limit = parse_int_radix_10(&with_default(query_value(query, "limit"), JsValue::from("1000")));
        let offset = parse_int_radix_10(&with_default(query_value(query, "offset"), JsValue::from("0")));
        let site_id = pg_integer(site_number(&request.site_id))?;
        let key = pg_text(key, "key")?;
        let limit_count = pg_row_count(limit, "LIMIT");
        let offset_count = pg_row_count(offset, "OFFSET");

        let values_query = async {
            let (limit_count, offset_count) = (limit_count?, offset_count?);
            let rows = sqlx::query(
                r#"
        SELECT traits->>$2 AS value, COUNT(*)::int AS user_count
        FROM user_profiles
        WHERE site_id = $1 AND traits ? $3
        GROUP BY value
        ORDER BY user_count DESC
        LIMIT $4 OFFSET $5
      "#,
            )
            .bind(site_id)
            .bind(&key)
            .bind(&key)
            .bind(limit_count)
            .bind(offset_count)
            .fetch_all(&state.pg)
            .await?;
            Ok::<_, RouteFailure>(rows)
        };
        let count_query = async {
            sqlx::query_scalar::<_, Option<i32>>(
                r#"
        SELECT COUNT(DISTINCT traits->>$2)::int AS total
        FROM user_profiles
        WHERE site_id = $1 AND traits ? $3
      "#,
            )
            .bind(site_id)
            .bind(&key)
            .bind(&key)
            .fetch_optional(&state.pg)
            .await
        };
        let (values, total) = tokio::join!(values_query, count_query);
        let values = values?;
        let total = total?.flatten().map_or(0.0, f64::from);

        let values = values
            .iter()
            .map(|row| {
                Ok(json!({
                    "value": row.try_get::<Option<String>, _>("value")?,
                    "userCount": row.try_get::<Option<i32>, _>("user_count")?,
                }))
            })
            .collect::<Result<Vec<Value>, sqlx::Error>>()?;
        debug!(site_id = %request.site_id, values = values.len(), total, "Loaded trait values");
        Ok(json!({ "values": values, "total": number_value(total), "hasMore": offset + limit < total }))
    }
    .await;
    match result {
        Ok(body) => {
            info!(site_id = %request.site_id, "Served user trait values");
            ok(body)
        }
        Err(failure) => route_failure("user trait values", failure),
    }
}

/// `buildTraitValueUsersQuery()`.
pub fn build_trait_value_users_query() -> String {
    format!(
        "
      SELECT
        {} AS effective_user_id,
        argMax(events.user_id, timestamp) AS user_id,
        argMax(events.identified_user_id, timestamp) AS identified_user_id,
        argMax(country, timestamp) AS country,
        argMax(region, timestamp) AS region,
        argMax(city, timestamp) AS city,
        argMax(browser, timestamp) AS browser,
        argMax(operating_system, timestamp) AS operating_system,
        argMax(device_type, timestamp) AS device_type,
        count(DISTINCT session_id) AS sessions
      FROM events
      WHERE site_id = {{siteId:Int32}}
        AND events.identified_user_id IN ({{userIds:Array(String)}})
      GROUP BY effective_user_id
    ",
        effective_user_id("events")
    )
}

/// `ch?.[field] ?? fallback`
fn field_or(row: Option<&Map<String, Value>>, field: &str, fallback: Value) -> Value {
    match row.and_then(|row| row.get(field)) {
        Some(Value::Null) | None => fallback,
        Some(value) => value.clone(),
    }
}

/// `GET /api/sites/:siteId/user-traits/users`
pub async fn get_user_trait_value_users(
    State(state): State<AppState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    let (request, _) = match users_chain(&state, &method, &uri, &headers, &[]).await {
        Ok(chained) => chained,
        Err(response) => return response,
    };
    let query = &request.query;
    let key = query_value(query, "key");
    let value = query_value(query, "value");
    if !key.is_truthy() || value.is_undefined() {
        return bad_request("key and value query parameters are required");
    }

    let result: Result<Value, RouteFailure> = async {
        let site = site_number(&request.site_id);
        let limit = parse_int_radix_10(&with_default(query_value(query, "limit"), JsValue::from("50")));
        let offset = parse_int_radix_10(&with_default(query_value(query, "offset"), JsValue::from("0")));
        let site_id = pg_integer(site)?;
        let key = pg_text(key, "key")?;
        let value = pg_text(value, "value")?;
        let (limit_count, offset_count) = (pg_row_count(limit, "LIMIT"), pg_row_count(offset, "OFFSET"));

        let profiles_query = async {
            let (limit_count, offset_count) = (limit_count?, offset_count?);
            let rows = sqlx::query(
                r#"
        SELECT user_id, traits
        FROM user_profiles
        WHERE site_id = $1 AND traits->>$2 = $3
        ORDER BY user_id
        LIMIT $4 OFFSET $5
      "#,
            )
            .bind(site_id)
            .bind(&key)
            .bind(&value)
            .bind(limit_count)
            .bind(offset_count)
            .fetch_all(&state.pg)
            .await?;
            Ok::<_, RouteFailure>(rows)
        };
        let count_query = async {
            sqlx::query_scalar::<_, Option<i32>>(
                r#"
        SELECT COUNT(*)::int AS total
        FROM user_profiles
        WHERE site_id = $1 AND traits->>$2 = $3
      "#,
            )
            .bind(site_id)
            .bind(&key)
            .bind(&value)
            .fetch_optional(&state.pg)
            .await
        };
        let (profiles, total) = tokio::join!(profiles_query, count_query);
        let profiles = profiles?;
        let total = total?.flatten().map_or(0.0, f64::from);
        let has_more = offset + limit < total;

        let profiles = profiles
            .iter()
            .map(|row| Ok((row.try_get::<String, _>("user_id")?, row.try_get::<Option<Value>, _>("traits")?)))
            .collect::<Result<Vec<(String, Option<Value>)>, sqlx::Error>>()?;
        if profiles.is_empty() {
            return Ok(json!({ "users": [], "total": number_value(total), "hasMore": has_more }));
        }

        let user_ids: Vec<QueryParam> = profiles.iter().map(|(user_id, _)| QueryParam::String(user_id.clone())).collect();
        let spec = QuerySpec::new(build_trait_value_users_query()).param("siteId", site).param("userIds", QueryParam::Array(user_ids));
        let ch_rows = clickhouse(&state).run_analytics_query(&spec).await?;

        // `new Map(chData.map(row => [row.identified_user_id, row]))`: later rows win
        let mut lookup: HashMap<String, Map<String, Value>> = HashMap::new();
        for row in ch_rows {
            let identified = JsValue::from_serde(row.get("identified_user_id").unwrap_or(&Value::Null)).to_js_string();
            lookup.insert(identified, row);
        }

        let users: Vec<Value> = profiles
            .into_iter()
            .map(|(user_id, traits)| {
                let ch = lookup.get(&user_id);
                json!({
                    "user_id": field_or(ch, "user_id", Value::String(user_id.clone())),
                    "identified_user_id": user_id,
                    "traits": traits.map_or(Value::Null, |traits| JsValue::from_serde(&traits).to_serde()),
                    "country": field_or(ch, "country", json!("")),
                    "region": field_or(ch, "region", json!("")),
                    "city": field_or(ch, "city", json!("")),
                    "browser": field_or(ch, "browser", json!("")),
                    "operating_system": field_or(ch, "operating_system", json!("")),
                    "device_type": field_or(ch, "device_type", json!("")),
                    "sessions": field_or(ch, "sessions", json!(0)),
                })
            })
            .collect();
        Ok(json!({ "users": users, "total": number_value(total), "hasMore": has_more }))
    }
    .await;
    match result {
        Ok(body) => {
            info!(site_id = %request.site_id, "Served trait value users");
            ok(body)
        }
        Err(failure) => route_failure("trait value users", failure),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trait_value_users_query_groups_identified_users() {
        let sql = build_trait_value_users_query();
        assert!(sql.contains("COALESCE(NULLIF(events.identified_user_id, ''), events.user_id) AS effective_user_id"));
        assert!(sql.contains("AND events.identified_user_id IN ({userIds:Array(String)})"));
        assert!(sql.contains("WHERE site_id = {siteId:Int32}"));
    }

    #[test]
    fn missing_fields_fall_back() {
        let row = json!({ "user_id": "fp", "sessions": 3, "country": null }).as_object().unwrap().clone();
        assert_eq!(field_or(Some(&row), "user_id", json!("x")), json!("fp"));
        assert_eq!(field_or(Some(&row), "country", json!("")), json!(""));
        assert_eq!(field_or(None, "sessions", json!(0)), json!(0));
    }
}
