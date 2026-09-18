//! POST /api/admin/telemetry, ported from
//! server/src/api/admin/collectTelemetry.ts.
//!
//! The route is registered with no guard, and the handler's first act is to
//! refuse every request unless `CLOUD=true`. This deployment never sets it, so
//! the endpoint answers 403 to everyone; the insert is ported anyway so the
//! behaviour is the same if the flag is ever turned on.

use axum::{
    body::Body,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::Response,
};
use tracing::{debug, error, info};

use crate::{analytics::js::JsValue, state::AppState};

use super::support::{object, read_body, send_error, send_js};

/// `collectTelemetry`
pub async fn collect(State(state): State<AppState>, headers: HeaderMap, body: Body) -> Response {
    let body = match read_body(&headers, body).await {
        Ok(body) => body,
        Err(response) => return response,
    };

    if !state.config.auth.cloud {
        debug!("Refused telemetry collection outside a cloud instance");
        return send_error(StatusCode::FORBIDDEN, "Telemetry collection is only available on cloud instances");
    }

    // `const { instanceId, version, tableCounts, clickhouseSizeGb } = request.body`
    // throws a TypeError when the body is absent, which the catch turns into a 500
    let Some(fields) = body.as_object() else {
        error!("Error collecting telemetry: the request carried no object body");
        return send_error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to collect telemetry");
    };
    let instance_id = fields.get_or_undefined("instanceId").clone();
    let version = fields.get_or_undefined("version").clone();
    let table_counts = fields.get_or_undefined("tableCounts").clone();
    let clickhouse_size_gb = fields.get_or_undefined("clickhouseSizeGb").clone();

    if !instance_id.is_truthy()
        || !version.is_truthy()
        || !table_counts.is_truthy()
        || clickhouse_size_gb.is_undefined()
    {
        return send_error(StatusCode::BAD_REQUEST, "Missing required fields");
    }

    let table_counts_text = crate::analytics::js::json::stringify(&table_counts);
    let written = sqlx::query(
        r#"insert into "telemetry" ("instance_id", "version", "table_counts", "clickhouse_size_gb")
           values ($1, $2, $3::jsonb, $4)"#,
    )
    .bind(instance_id.to_js_string())
    .bind(version.to_js_string())
    .bind(table_counts_text.as_deref())
    .bind(clickhouse_size_gb.to_number() as f32)
    .execute(&state.pg)
    .await;
    if let Err(err) = written {
        error!(error = %err, "Error collecting telemetry");
        return send_error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to collect telemetry");
    }

    info!("Collected telemetry from a self-hosted instance");
    send_js(StatusCode::OK, &object(vec![("success", JsValue::Bool(true))]))
}
