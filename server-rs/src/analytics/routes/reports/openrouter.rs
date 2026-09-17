//! OpenRouter chat completions client, ported from server/src/lib/openrouter.ts.
//!
//! Node's client has no cache and no rate limiting of its own: every call is one
//! POST, and the caller (generateCustomQuery, whose route carries the 20 per
//! minute limit) decides what to do with the typed failure. The request body,
//! headers, defaults and the failure classification (`missing_api_key`,
//! `http_error`, `invalid_json`, `empty_choices`, `empty_content`) match Node so
//! logs and error handling stay comparable across backends. Cancellation, which
//! Node does with an `AbortSignal`, is dropping the future (or wrapping it in
//! `tokio::time::timeout`).
//!
//! Note: getBotAiSummary.ts does not call OpenRouter; the bot AI summary is a
//! ClickHouse query only. This client lives with the reports routes until the
//! custom query generator is ported.
#![allow(dead_code)] // consumed when POST .../analytics/query/generate is ported

use std::time::Instant;

use serde::Serialize;
use serde_json::{Value, json};
use tracing::{debug, warn};

pub const OPENROUTER_API_URL: &str = "https://openrouter.ai/api/v1/chat/completions";
pub const DEFAULT_OPENROUTER_MODEL: &str = "moonshotai/kimi-k2.6";

/// A chat message (`role` is "system", "user" or "assistant").
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ChatMessage {
    pub role: String,
    pub content: String,
}

impl ChatMessage {
    pub fn new(role: &str, content: impl Into<String>) -> Self {
        Self { role: role.to_string(), content: content.into() }
    }
}

/// `OpenRouterOptions` without the abort signal.
#[derive(Clone, Debug, Default)]
pub struct OpenRouterOptions {
    pub temperature: Option<f64>,
    pub max_tokens: Option<u32>,
    pub model: Option<String>,
}

/// `OpenRouterErrorCode`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OpenRouterErrorCode {
    MissingApiKey,
    HttpError,
    InvalidJson,
    EmptyChoices,
    EmptyContent,
}

impl OpenRouterErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            OpenRouterErrorCode::MissingApiKey => "missing_api_key",
            OpenRouterErrorCode::HttpError => "http_error",
            OpenRouterErrorCode::InvalidJson => "invalid_json",
            OpenRouterErrorCode::EmptyChoices => "empty_choices",
            OpenRouterErrorCode::EmptyContent => "empty_content",
        }
    }
}

/// `OpenRouterMetadata`: what a call learned about the response, for logs.
#[derive(Clone, Debug, Default, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OpenRouterMetadata {
    pub model: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_model: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_id: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub choice_count: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub finish_reason: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub native_finish_reason: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub usage: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_error: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_body_preview: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_length: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message_role: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message_content_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message_content_length: Option<usize>,
}

/// `OpenRouterError`: a classified failure with the metadata gathered so far.
#[derive(Debug, thiserror::Error)]
#[error("{message}")]
pub struct OpenRouterError {
    pub code: OpenRouterErrorCode,
    pub message: String,
    pub details: OpenRouterMetadata,
}

/// A failure below the classification: the request never produced a response
/// (Node's `fetch` rejecting).
#[derive(Debug, thiserror::Error)]
pub enum OpenRouterCallError {
    #[error(transparent)]
    OpenRouter(Box<OpenRouterError>),
    #[error("fetch failed: {0}")]
    Transport(#[from] reqwest::Error),
}

impl From<OpenRouterError> for OpenRouterCallError {
    fn from(error: OpenRouterError) -> Self {
        OpenRouterCallError::OpenRouter(Box::new(error))
    }
}

/// `truncateForLog(value, 1000)`: at most 1000 UTF-16 units, then `...`.
fn truncate_for_log(value: &str) -> String {
    const MAX: usize = 1000;
    let units: Vec<u16> = value.encode_utf16().collect();
    if units.len() > MAX { format!("{}...", String::from_utf16_lossy(&units[..MAX])) } else { value.to_string() }
}

/// `getOpenRouterModel(model)`: the explicit model, else `OPENROUTER_MODEL`, else
/// the default (empty strings count as unset, as `||` does).
pub fn get_openrouter_model(model: Option<&str>) -> String {
    model
        .filter(|model| !model.is_empty())
        .map(str::to_string)
        .or_else(|| std::env::var("OPENROUTER_MODEL").ok().filter(|model| !model.is_empty()))
        .unwrap_or_else(|| DEFAULT_OPENROUTER_MODEL.to_string())
}

/// The JSON body `callOpenRouterWithMetadata` posts.
pub fn request_body(model: &str, messages: &[ChatMessage], options: &OpenRouterOptions) -> String {
    crate::js_json::stringify(&json!({
        "model": model,
        "messages": messages,
        "temperature": options.temperature.unwrap_or(0.3),
        "max_tokens": options.max_tokens.unwrap_or(1000),
    }))
}

/// The client: endpoint and key are read like Node reads `process.env` (per call
/// through [`OpenRouterClient::from_env`]); tests point it at a local server.
#[derive(Clone)]
pub struct OpenRouterClient {
    http: reqwest::Client,
    url: String,
    api_key: Option<String>,
}

impl OpenRouterClient {
    pub fn new(url: impl Into<String>, api_key: Option<String>) -> Self {
        Self { http: reqwest::Client::new(), url: url.into(), api_key: api_key.filter(|key| !key.is_empty()) }
    }

    /// `OPENROUTER_API_KEY` against the public endpoint.
    pub fn from_env() -> Self {
        Self::new(OPENROUTER_API_URL, std::env::var("OPENROUTER_API_KEY").ok())
    }

    /// `callOpenRouter(messages, options)`: the assistant's content.
    pub async fn call(&self, messages: &[ChatMessage], options: &OpenRouterOptions) -> Result<String, OpenRouterCallError> {
        Ok(self.call_with_metadata(messages, options).await?.0)
    }

    /// `callOpenRouterWithMetadata(messages, options)`.
    pub async fn call_with_metadata(
        &self,
        messages: &[ChatMessage],
        options: &OpenRouterOptions,
    ) -> Result<(String, OpenRouterMetadata), OpenRouterCallError> {
        let model = get_openrouter_model(options.model.as_deref());
        let Some(api_key) = &self.api_key else {
            warn!(model = %model, "OpenRouter call without OPENROUTER_API_KEY");
            return Err(OpenRouterError {
                code: OpenRouterErrorCode::MissingApiKey,
                message: "OPENROUTER_API_KEY is not configured".to_string(),
                details: OpenRouterMetadata { model, ..Default::default() },
            }
            .into());
        };

        let started = Instant::now();
        let response = self
            .http
            .post(&self.url)
            .header("Authorization", format!("Bearer {api_key}"))
            .header("Content-Type", "application/json")
            .header("HTTP-Referer", "https://hygo.ai")
            .header("X-Title", "Hygo Analytics")
            .body(request_body(&model, messages, options))
            .send()
            .await?;

        let header = |name: &str| response.headers().get(name).and_then(|value| value.to_str().ok()).map(str::to_string);
        let status = response.status();
        let base = OpenRouterMetadata {
            model: model.clone(),
            status: Some(status.as_u16()),
            status_text: Some(status.canonical_reason().unwrap_or_default().to_string()),
            request_id: header("x-request-id").or_else(|| header("x-openrouter-request-id")).or_else(|| header("cf-ray")),
            content_type: header("content-type"),
            // Number(header) || undefined
            content_length: header("content-length")
                .map(|text| crate::analytics::js::number::string_to_number(&text))
                .filter(|length| !length.is_nan() && *length != 0.0),
            ..Default::default()
        };
        debug!(model = %model, status = status.as_u16(), elapsed_ms = started.elapsed().as_millis() as u64, "OpenRouter responded");

        let text = response.text().await;
        if !status.is_success() {
            let preview = truncate_for_log(&text.unwrap_or_default());
            warn!(model = %model, status = status.as_u16(), "OpenRouter returned an error status");
            return Err(OpenRouterError {
                code: OpenRouterErrorCode::HttpError,
                message: format!("OpenRouter API error: {}", status.as_u16()),
                details: OpenRouterMetadata { response_body_preview: Some(preview), ..base },
            }
            .into());
        }
        let data: Value = match text.map_err(|err| err.to_string()).and_then(|text| serde_json::from_str(&text).map_err(|err| err.to_string())) {
            Ok(data) => data,
            Err(message) => {
                warn!(model = %model, error = %message, "OpenRouter returned invalid JSON");
                return Err(OpenRouterError {
                    code: OpenRouterErrorCode::InvalidJson,
                    message: "OpenRouter returned invalid JSON".to_string(),
                    details: OpenRouterMetadata { response_error: Some(Value::String(message)), ..base },
                }
                .into());
            }
        };

        let field = |name: &str| data.get(name).cloned();
        let choices = data.get("choices").and_then(Value::as_array).filter(|choices| !choices.is_empty());
        let Some(choices) = choices else {
            warn!(model = %model, "OpenRouter returned no choices");
            return Err(OpenRouterError {
                code: OpenRouterErrorCode::EmptyChoices,
                message: "No response from OpenRouter".to_string(),
                details: OpenRouterMetadata {
                    response_id: field("id"),
                    response_model: field("model"),
                    provider: field("provider"),
                    choice_count: Some(data.get("choices").and_then(Value::as_array).map_or(0, Vec::len)),
                    usage: field("usage"),
                    response_error: field("error"),
                    ..base
                },
            }
            .into());
        };

        let choice = &choices[0];
        let message = choice.get("message");
        let content = message.and_then(|message| message.get("content"));
        let finish_reason = choice.get("finish_reason").cloned();
        let metadata = OpenRouterMetadata {
            response_id: field("id"),
            response_model: field("model"),
            provider: field("provider"),
            choice_count: Some(choices.len()),
            finish_reason: finish_reason.clone(),
            native_finish_reason: choice.get("native_finish_reason").cloned(),
            usage: field("usage"),
            response_error: field("error"),
            message_role: message.and_then(|message| message.get("role")).cloned(),
            message_content_type: Some(
                match content {
                    None => "undefined",
                    Some(Value::Array(_)) => "array",
                    Some(Value::String(_)) => "string",
                    Some(Value::Number(_)) => "number",
                    Some(Value::Bool(_)) => "boolean",
                    Some(Value::Null | Value::Object(_)) => "object",
                }
                .to_string(),
            ),
            message_content_length: content.and_then(Value::as_str).map(crate::js_json::utf16_len),
            ..base
        };

        match content.and_then(Value::as_str) {
            Some(text) if !crate::analytics::js::string::trim(text).is_empty() => Ok((text.to_string(), metadata)),
            _ => {
                let reason = finish_reason
                    .as_ref()
                    .filter(|reason| match reason {
                        Value::Null => false,
                        Value::String(text) => !text.is_empty(),
                        Value::Bool(flag) => *flag,
                        Value::Number(number) => number.as_f64().is_some_and(|n| n != 0.0),
                        _ => true,
                    })
                    .map(|reason| format!(" ({})", reason.as_str().map_or_else(|| reason.to_string(), str::to_string)))
                    .unwrap_or_default();
                warn!(model = %model, finish_reason = %reason, "OpenRouter returned empty content");
                Err(OpenRouterError {
                    code: OpenRouterErrorCode::EmptyContent,
                    message: format!("OpenRouter returned an empty response{reason}"),
                    details: metadata,
                }
                .into())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use axum::{Router, http::HeaderMap, routing::post};

    use super::*;

    /// A local stand-in for OpenRouter answering `status` with `body`, recording
    /// the request it received.
    async fn mock(status: u16, body: &'static str) -> (String, Arc<Mutex<Option<(HeaderMap, String)>>>) {
        let seen = Arc::new(Mutex::new(None));
        let recorder = seen.clone();
        let app = Router::new().route(
            "/chat",
            post(move |headers: HeaderMap, request: String| {
                let recorder = recorder.clone();
                async move {
                    *recorder.lock().unwrap() = Some((headers, request));
                    (axum::http::StatusCode::from_u16(status).unwrap(), [("content-type", "application/json")], body)
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (format!("http://{address}/chat"), seen)
    }

    fn user(content: &str) -> Vec<ChatMessage> {
        vec![ChatMessage::new("user", content)]
    }

    fn failure(result: Result<String, OpenRouterCallError>) -> OpenRouterError {
        match result {
            Err(OpenRouterCallError::OpenRouter(error)) => *error,
            other => panic!("expected an OpenRouterError, got {other:?}"),
        }
    }

    // Ported from lib/openrouter.test.ts
    #[tokio::test]
    async fn returns_assistant_content() {
        let (url, seen) = mock(
            200,
            r#"{"id":"completion-id","choices":[{"message":{"role":"assistant","content":"SELECT count() FROM scoped_events"},"finish_reason":"stop"}]}"#,
        )
        .await;
        let client = OpenRouterClient::new(url, Some("test-key".into()));
        let content = client.call(&user("count events"), &OpenRouterOptions { model: Some("m".into()), ..Default::default() }).await.unwrap();
        assert_eq!(content, "SELECT count() FROM scoped_events");

        let (headers, body) = seen.lock().unwrap().clone().unwrap();
        assert_eq!(headers["authorization"], "Bearer test-key");
        assert_eq!(headers["content-type"], "application/json");
        assert_eq!(headers["http-referer"], "https://hygo.ai");
        assert_eq!(headers["x-title"], "Hygo Analytics");
        assert_eq!(body, r#"{"model":"m","messages":[{"role":"user","content":"count events"}],"temperature":0.3,"max_tokens":1000}"#);
    }

    #[tokio::test]
    async fn rejects_null_assistant_content() {
        let (url, _) = mock(200, r#"{"id":"completion-id","choices":[{"message":{"role":"assistant","content":null},"finish_reason":"stop"}]}"#).await;
        let error = failure(OpenRouterClient::new(url, Some("test-key".into())).call(&user("count events"), &OpenRouterOptions::default()).await);
        assert_eq!(error.code, OpenRouterErrorCode::EmptyContent);
        assert_eq!(error.message, "OpenRouter returned an empty response (stop)");
        assert_eq!(error.details.message_content_type.as_deref(), Some("object"));
    }

    #[tokio::test]
    async fn classifies_failures() {
        let error = failure(OpenRouterClient::new("http://127.0.0.1:9/unused", None).call(&user("x"), &OpenRouterOptions::default()).await);
        assert_eq!((error.code, error.message.as_str()), (OpenRouterErrorCode::MissingApiKey, "OPENROUTER_API_KEY is not configured"));

        let (url, _) = mock(429, r#"{"error":{"message":"slow down"}}"#).await;
        let error = failure(OpenRouterClient::new(url, Some("k".into())).call(&user("x"), &OpenRouterOptions::default()).await);
        assert_eq!((error.code, error.message.as_str()), (OpenRouterErrorCode::HttpError, "OpenRouter API error: 429"));
        assert_eq!(error.details.response_body_preview.as_deref(), Some(r#"{"error":{"message":"slow down"}}"#));

        let (url, _) = mock(200, "not json").await;
        let error = failure(OpenRouterClient::new(url, Some("k".into())).call(&user("x"), &OpenRouterOptions::default()).await);
        assert_eq!(error.code, OpenRouterErrorCode::InvalidJson);

        let (url, _) = mock(200, r#"{"id":"a","choices":[]}"#).await;
        let error = failure(OpenRouterClient::new(url, Some("k".into())).call(&user("x"), &OpenRouterOptions::default()).await);
        assert_eq!((error.code, error.message.as_str()), (OpenRouterErrorCode::EmptyChoices, "No response from OpenRouter"));
        assert_eq!(error.details.choice_count, Some(0));

        let (url, _) = mock(200, r#"{"choices":[{"message":{"content":"   "}}]}"#).await;
        let error = failure(OpenRouterClient::new(url, Some("k".into())).call(&user("x"), &OpenRouterOptions::default()).await);
        assert_eq!(error.message, "OpenRouter returned an empty response");
    }

    #[test]
    fn request_building() {
        let options = OpenRouterOptions { temperature: Some(0.1), max_tokens: Some(5000), model: None };
        let messages = vec![ChatMessage::new("system", "rules"), ChatMessage::new("user", "q\"uote")];
        assert_eq!(
            request_body("moonshotai/kimi-k2.6", &messages, &options),
            r#"{"model":"moonshotai/kimi-k2.6","messages":[{"role":"system","content":"rules"},{"role":"user","content":"q\"uote"}],"temperature":0.1,"max_tokens":5000}"#
        );
        assert_eq!(get_openrouter_model(Some("explicit")), "explicit");
        assert_eq!(truncate_for_log(&"a".repeat(1001)), format!("{}...", "a".repeat(1000)));
        assert_eq!(truncate_for_log("short"), "short");
    }
}
