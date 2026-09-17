//! POST /api/organizations/:organizationId/analytics/query/generate, ported from
//! server/src/api/analytics/generateCustomQuery.ts: ask OpenRouter for one
//! ClickHouse query over `scoped_events`, then hold it to the same validator the
//! run route uses.
//!
//! Rate limiting: the route shares `orgSqlRead` with /analytics/query, so the
//! query limiter (60 per minute, the query route's key) is the one that runs.
//! A client that disconnects drops this future and with it the OpenRouter call,
//! which is what Node's abort signal achieves (its 499 never reaches a closed
//! socket).

use std::{net::SocketAddr, sync::LazyLock};

use axum::{
    body::Body,
    extract::{ConnectInfo, State},
    http::{HeaderMap, Method, StatusCode, Uri},
    response::Response,
};
use tracing::{error, info, warn};

use super::{
    access::RequestAccess,
    custom_query::{org_chain, organization_site_ids},
    openrouter::{self, Message, OpenRouterErrorCode, OpenRouterFailure},
    rate_limit,
    request::{self, object},
    schema::{self, ObjectStatus, StringCheck, first_message},
};
use crate::{
    analytics::{
        js::{
            JsValue,
            number::number_to_string,
            string::{is_js_space_char, trim, utf16_len},
            zod::{self, Parsed, Path, PathSegment, Status, ZodIssue},
        },
        utils::{
            custom_query_validation::{MAX_CUSTOM_QUERY_LENGTH, normalize_custom_query, validate_scoped_query},
            event_schema::EVENT_SCHEMA,
        },
    },
    state::AppState,
};

const OPENROUTER_TEMPERATURE: f64 = 0.1;
const OPENROUTER_MAX_TOKENS: f64 = 5000.0;

static OPENROUTER_HTTP: LazyLock<reqwest::Client> = LazyLock::new(reqwest::Client::new);

/// A history entry after `generationMessageSchema`.
#[derive(Clone, Debug, PartialEq)]
struct HistoryMessage {
    role: &'static str,
    content: String,
}

#[derive(Clone, Debug, PartialEq)]
struct GenerateBody {
    prompt: String,
    current_site_id: Option<f64>,
    current_query: Option<String>,
    history: Vec<HistoryMessage>,
}

fn key_path(name: &str) -> Path {
    vec![PathSegment::Key(name.to_string())]
}

fn history_message(value: &JsValue, path: &Path, issues: &mut Vec<ZodIssue>) -> Parsed<HistoryMessage> {
    let object = schema::object(value, path, issues)?;
    let mut status = ObjectStatus::new();
    let role = status.field(zod::enumeration(object.get_or_undefined("role"), &["user", "assistant"], &schema::key(path, "role"), issues));
    let content = status.field(schema::string(
        object.get_or_undefined("content"),
        &schema::key(path, "content"),
        issues,
        &[StringCheck::Trim, StringCheck::Min(1, None), StringCheck::Max(MAX_CUSTOM_QUERY_LENGTH, None)],
    ));
    let object_status = status.finish()?;
    let role = if role? == "assistant" { "assistant" } else { "user" };
    Some((object_status, HistoryMessage { role, content: content? }))
}

/// `requestBodySchema.safeParse(request.body)`
fn parse_body(body: &JsValue) -> Result<GenerateBody, String> {
    let mut issues = Vec::new();
    let Some(object) = schema::object(body, &Vec::new(), &mut issues) else { return Err(first_message(&issues)) };
    let mut status = ObjectStatus::new();
    let prompt = status.field(schema::string(
        object.get_or_undefined("prompt"),
        &key_path("prompt"),
        &mut issues,
        &[StringCheck::Trim, StringCheck::Min(1, None), StringCheck::Max(4000, None)],
    ));
    let current_site_id = status.field(schema::optional(object.get_or_undefined("currentSiteId"), |inner| {
        schema::number(inner, &key_path("currentSiteId"), &mut issues, true, true)
    }));
    let current_query = status.field(schema::optional(object.get_or_undefined("currentQuery"), |inner| {
        schema::string(inner, &key_path("currentQuery"), &mut issues, &[StringCheck::Trim, StringCheck::Max(MAX_CUSTOM_QUERY_LENGTH, None)])
    }));
    let history = status.field(match object.get_or_undefined("history") {
        JsValue::Undefined => Some((Status::Valid, Vec::new())),
        other => schema::array(other, &key_path("history"), &mut issues, Some((12, None)), history_message),
    });
    let result = match (status.finish(), prompt, current_site_id, current_query, history) {
        (Some(object_status), Some(prompt), Some(current_site_id), Some(current_query), Some(history)) => Some((
            object_status,
            GenerateBody {
                prompt,
                current_site_id: current_site_id.value().copied(),
                current_query: current_query.value().cloned(),
                history,
            },
        )),
        _ => None,
    };
    schema::finish(result, issues).map_err(|issues| first_message(&issues))
}

/// The chat the route sends, byte for byte.
fn build_messages(body: &GenerateBody) -> Vec<Message> {
    let current_site_instruction = match body.current_site_id {
        Some(site_id) => {
            let site = number_to_string(site_id);
            format!(
                "The user is currently viewing site_id {site}. If they say \"this site\" or do not ask for an organization-wide result, include WHERE site_id = {site}."
            )
        }
        None => "The query can summarize all accessible sites unless the prompt asks for a specific site_id.".to_string(),
    };
    let system = format!(
        "\nYou generate ClickHouse SQL for Hygo custom analytics.\nReturn exactly one SQL query and no Markdown, explanation, comments, or semicolon.\nThe query must be a SELECT or WITH ... SELECT query.\nThe only readable table is scoped_events. Never read from events or any other table.\nNever define or shadow scoped_events.\nUse ClickHouse syntax.\nUse LIMIT 1000 or smaller for detail/list queries.\nFor custom event properties, use JSONExtractString(toString(props), 'property_name').\nUse the previous messages and current editor query as context.\nIf the user asks an incremental follow-up, revise the current editor query.\nIf the user clearly asks for a new query, a different analysis, or to start over, generate a fresh query.\nIf the current editor query is empty, generate a fresh query.\n{current_site_instruction}\n{EVENT_SCHEMA}\n\nGood examples:\nSELECT pathname, countIf(type = 'pageview') AS pageviews FROM scoped_events GROUP BY pathname ORDER BY pageviews DESC LIMIT 100\nSELECT event_name, count() AS events FROM scoped_events WHERE type = 'custom_event' GROUP BY event_name ORDER BY events DESC LIMIT 100\nSELECT toStartOfDay(timestamp) AS day, count() AS events FROM scoped_events GROUP BY day ORDER BY day ASC LIMIT 1000\n          "
    );
    let mut messages = vec![Message { role: "system", content: trim(&system).to_string() }];
    let skip = body.history.len().saturating_sub(10);
    for message in &body.history[skip..] {
        let content = if message.role == "assistant" {
            format!("Previously generated SQL:\n{}", message.content)
        } else {
            format!("Previous user request:\n{}", message.content)
        };
        messages.push(Message { role: message.role, content });
    }
    let current_query = body.current_query.as_deref().map(trim).filter(|query| !query.is_empty()).unwrap_or("(empty)");
    let user = format!("\nCurrent editor query:\n{current_query}\n\nCurrent user request:\n{}\n          ", body.prompt);
    messages.push(Message { role: "user", content: trim(&user).to_string() });
    messages
}

/// `extractSql(content)`
fn extract_sql(content: &str) -> String {
    let trimmed = trim(content);
    let sql = fenced_sql(trimmed).unwrap_or(trimmed);
    normalize_custom_query(strip_sql_label(sql))
}

/// The capture of ``/```(?:sql)?\s*([\s\S]*?)```/i``: the first fence that has a
/// closing fence after it (a later opening can only close where this one does).
fn fenced_sql(text: &str) -> Option<&str> {
    let open = text.find("```")?;
    let mut start = open + 3;
    if text.get(start..start + 3).is_some_and(|word| word.eq_ignore_ascii_case("sql")) && text[start + 3..].contains("```") {
        start += 3;
    }
    let rest = &text[start..];
    let start = start + (rest.len() - rest.trim_start_matches(is_js_space_char).len());
    let close = text[start..].find("```")?;
    Some(&text[start..start + close])
}

/// `sql.replace(/^sql\s*:/i, "")`
fn strip_sql_label(sql: &str) -> &str {
    if !sql.get(..3).is_some_and(|word| word.eq_ignore_ascii_case("sql")) {
        return sql;
    }
    let rest = sql[3..].trim_start_matches(is_js_space_char);
    rest.strip_prefix(':').unwrap_or(sql)
}

/// The catch block's mapping of a thrown error to a reply.
fn failure_response(failure: &OpenRouterFailure) -> Response {
    if let OpenRouterFailure::OpenRouter { code: OpenRouterErrorCode::EmptyContent, finish_reason: Some(JsValue::String(reason)), .. } = failure
        && reason == "length"
    {
        return request::error(
            StatusCode::BAD_GATEWAY,
            "AI provider hit the output token limit before returning SQL. Try a shorter prompt or simpler query.",
        );
    }
    let message = failure.message();
    if message == "No response from OpenRouter" || message.starts_with("OpenRouter returned an empty response") {
        return request::error(StatusCode::BAD_GATEWAY, "AI provider returned an empty response. Try again.");
    }
    if message.starts_with("OpenRouter API error") {
        return request::error(StatusCode::BAD_GATEWAY, "AI query generation provider error");
    }
    if message == "OPENROUTER_API_KEY is not configured" {
        return request::error(StatusCode::INTERNAL_SERVER_ERROR, "AI query generation is not configured");
    }
    request::error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to generate query")
}

/// POST /api/organizations/:organizationId/analytics/query/generate
pub async fn generate(
    State(state): State<AppState>,
    peer: ConnectInfo<SocketAddr>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let params = match request::route_params(&uri, &[3]) {
        Ok(params) => params,
        Err(failure) => return request::param_failure(failure, method, uri).await,
    };
    let body = match request::read_body(&headers, body).await {
        Ok(body) => body,
        Err(response) => return response,
    };
    let (auth, limit_headers) = match org_chain(&state, &uri, &headers, &params[0], peer).await {
        Ok(chain) => chain,
        Err(response) => return response,
    };
    let organization_id = &params[0];

    let response = async {
        let body = match parse_body(&body) {
            Ok(body) => body,
            Err(message) => return request::error(StatusCode::BAD_REQUEST, &message),
        };
        let access = RequestAccess::new(&state, &headers, &auth);
        let site_ids = organization_site_ids(&access, organization_id).await;
        if site_ids.is_empty() {
            return request::error(StatusCode::FORBIDDEN, "No access to organization or no sites found");
        }
        if let Some(current) = body.current_site_id
            && !site_ids.iter().any(|id| f64::from(*id) == current)
        {
            return request::error(StatusCode::FORBIDDEN, "No access to current site");
        }

        let messages = build_messages(&body);
        let message_chars: usize = messages.iter().map(|message| utf16_len(&message.content)).sum();
        info!(
            organization_id = %organization_id,
            current_site_id = body.current_site_id,
            accessible_site_count = site_ids.len(),
            prompt_length = utf16_len(&body.prompt),
            history_count = body.history.len(),
            message_count = messages.len(),
            message_char_count = message_chars,
            open_router_model = %openrouter::model(),
            "Generating custom analytics query"
        );

        match openrouter::call(&OPENROUTER_HTTP, &messages, OPENROUTER_TEMPERATURE, OPENROUTER_MAX_TOKENS).await {
            Ok(generated) => {
                info!(generated_length = utf16_len(&generated), "OpenRouter returned custom analytics query candidate");
                let query = extract_sql(&generated);
                if let Some(reason) = validate_scoped_query(&query) {
                    warn!(validation_error = %reason, query_length = utf16_len(&query), "Generated custom query failed validation");
                    return request::send(
                        StatusCode::UNPROCESSABLE_ENTITY,
                        &object(vec![("error", "Generated query failed validation".into()), ("details", reason.into())]),
                    );
                }
                info!(query_length = utf16_len(&query), "Generated custom analytics query passed validation");
                request::send(StatusCode::OK, &object(vec![("query", query.into())]))
            }
            Err(failure) => {
                error!(error = %failure.message(), "Failed to generate custom analytics query");
                failure_response(&failure)
            }
        }
    }
    .await;
    rate_limit::with_headers(response, limit_headers)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analytics::js::json;

    #[test]
    fn extracts_sql_like_the_regexes() {
        assert_eq!(extract_sql("```sql\nSELECT 1 FROM scoped_events;\n```"), "SELECT 1 FROM scoped_events");
        assert_eq!(extract_sql("Here:\n```SQL SELECT 2```\nthanks"), "SELECT 2");
        assert_eq!(extract_sql("```\nsql: SELECT 3\n```"), "SELECT 3");
        assert_eq!(extract_sql("sql : SELECT 4;;"), "SELECT 4");
        assert_eq!(extract_sql("```sql SELECT 5"), "```sql SELECT 5");
        assert_eq!(extract_sql("``````"), "");
        assert_eq!(extract_sql("```sql```"), "");
        assert_eq!(extract_sql("sqlx: 1"), "sqlx: 1");
    }

    #[test]
    fn body_schema_messages() {
        let parse = |text: &str| parse_body(&json::parse(text).unwrap());
        assert_eq!(parse("{}").unwrap_err(), "Required");
        assert_eq!(parse(r#"{"prompt":" "}"#).unwrap_err(), "String must contain at least 1 character(s)");
        assert_eq!(parse(r#"{"prompt":"x","history":[{"role":"bot","content":"y"}]}"#).unwrap_err(), "Invalid enum value. Expected 'user' | 'assistant', received 'bot'");
        let many = format!(r#"{{"prompt":"x","history":[{}]}}"#, vec![r#"{"role":"user","content":"a"}"#; 13].join(","));
        assert_eq!(parse(&many).unwrap_err(), "Array must contain at most 12 element(s)");
        let parsed = parse(r#"{"prompt":" count ","currentSiteId":4,"currentQuery":"  ","history":[{"role":"assistant","content":" SELECT 1 "}]}"#).unwrap();
        let messages = build_messages(&parsed);
        assert_eq!(messages.len(), 3);
        assert!(messages[0].content.starts_with("You generate ClickHouse SQL"));
        assert!(messages[0].content.contains("The user is currently viewing site_id 4."));
        assert!(messages[0].content.ends_with("LIMIT 1000"));
        assert_eq!(messages[1].content, "Previously generated SQL:\nSELECT 1");
        assert_eq!(messages[2].content, "Current editor query:\n(empty)\n\nCurrent user request:\ncount");
    }
}
