//! OpenRouter chat completions, ported from server/src/lib/openrouter.ts
//! (`callOpenRouterWithMetadata`). The response is read with JavaScript's
//! semantics because Node's error mapping depends on them: a `choices` value
//! that is not an array, a choice that is not an object and a content that is not
//! a string each end in a different reply.

use axum::http::HeaderMap;
use serde_json::{Value, json};
use tracing::{debug, warn};

use crate::analytics::js::{JsValue, json as js_json, string::trim, string::utf16_len};

const OPENROUTER_API_URL: &str = "https://openrouter.ai/api/v1/chat/completions";
const DEFAULT_OPENROUTER_MODEL: &str = "moonshotai/kimi-k2.6";

/// `OpenRouterErrorCode`
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OpenRouterErrorCode {
    MissingApiKey,
    HttpError,
    InvalidJson,
    EmptyChoices,
    EmptyContent,
}

/// A thrown error as the route's catch block sees it.
#[derive(Clone, Debug, PartialEq)]
pub enum OpenRouterFailure {
    /// `OpenRouterError`: its code, message and `details.finishReason`
    OpenRouter { code: OpenRouterErrorCode, message: String, finish_reason: Option<JsValue> },
    /// Any other `Error` (a failed `fetch`, a property read on `undefined`)
    Other(String),
}

impl OpenRouterFailure {
    pub fn message(&self) -> &str {
        match self {
            OpenRouterFailure::OpenRouter { message, .. } | OpenRouterFailure::Other(message) => message,
        }
    }
}

/// `getOpenRouterModel()`
pub fn model() -> String {
    std::env::var("OPENROUTER_MODEL").ok().filter(|model| !model.is_empty()).unwrap_or_else(|| DEFAULT_OPENROUTER_MODEL.to_string())
}

/// The endpoint. `OPENROUTER_API_URL` exists only so the differential harness can
/// point both backends at the same mock; Node's URL is a constant.
fn api_url() -> String {
    std::env::var("OPENROUTER_API_URL").ok().filter(|url| !url.is_empty()).unwrap_or_else(|| OPENROUTER_API_URL.to_string())
}

/// A chat message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Message {
    pub role: &'static str,
    pub content: String,
}

/// JavaScript property access `value[name]` for the JSON shapes a response can
/// hold; `None` stands for `undefined`, `Err` for reading off null or undefined.
fn property(value: Option<&JsValue>, name: &str) -> Result<Option<JsValue>, String> {
    match value {
        None => Err(format!("Cannot read properties of undefined (reading '{name}')")),
        Some(JsValue::Null) => Err(format!("Cannot read properties of null (reading '{name}')")),
        Some(JsValue::Object(object)) => Ok(object.get(name).cloned()),
        Some(JsValue::Array(items)) => Ok(match name {
            "length" => Some(JsValue::Number(items.len() as f64)),
            _ => name.parse::<usize>().ok().filter(|index| index.to_string() == name).and_then(|index| items.get(index).cloned()),
        }),
        Some(JsValue::String(text)) => Ok(match name {
            "length" => Some(JsValue::Number(utf16_len(text) as f64)),
            _ => name
                .parse::<usize>()
                .ok()
                .filter(|index| index.to_string() == name)
                .and_then(|index| text.encode_utf16().nth(index))
                .map(|unit| JsValue::String(String::from_utf16_lossy(&[unit]))),
        }),
        Some(_) => Ok(None),
    }
}

/// Optional chaining `value?.[name]`
fn optional_property(value: Option<&JsValue>, name: &str) -> Option<JsValue> {
    match value {
        None | Some(JsValue::Null) => None,
        other => property(other, name).ok().flatten(),
    }
}

/// `callOpenRouterWithMetadata(messages, { temperature, maxTokens })`: the
/// message content, or what Node would throw.
pub async fn call(http: &reqwest::Client, messages: &[Message], temperature: f64, max_tokens: f64) -> Result<String, OpenRouterFailure> {
    let model = model();
    let Some(api_key) = std::env::var("OPENROUTER_API_KEY").ok().filter(|key| !key.is_empty()) else {
        return Err(OpenRouterFailure::OpenRouter {
            code: OpenRouterErrorCode::MissingApiKey,
            message: "OPENROUTER_API_KEY is not configured".to_string(),
            finish_reason: None,
        });
    };

    let body = json!({
        "model": model,
        "messages": messages.iter().map(|message| json!({ "role": message.role, "content": message.content })).collect::<Vec<Value>>(),
        "temperature": temperature,
        "max_tokens": max_tokens,
    });
    let response = http
        .post(api_url())
        .header("Authorization", format!("Bearer {api_key}"))
        .header("Content-Type", "application/json")
        .header("HTTP-Referer", "https://hygo.ai")
        .header("X-Title", "Hygo Analytics")
        .body(crate::js_json::stringify(&body))
        .send()
        .await
        .map_err(|err| {
            warn!(error = %err, "OpenRouter request failed");
            OpenRouterFailure::Other("fetch failed".to_string())
        })?;

    let status = response.status();
    let request_id = header_text(response.headers(), &["x-request-id", "x-openrouter-request-id", "cf-ray"]);
    debug!(status = status.as_u16(), request_id = request_id.as_deref().unwrap_or(""), model = %model, "OpenRouter responded");

    if !status.is_success() {
        let preview = response.text().await.unwrap_or_default();
        warn!(status = status.as_u16(), body_length = preview.len(), "OpenRouter API error");
        return Err(OpenRouterFailure::OpenRouter {
            code: OpenRouterErrorCode::HttpError,
            message: format!("OpenRouter API error: {}", status.as_u16()),
            finish_reason: None,
        });
    }

    let invalid_json = || OpenRouterFailure::OpenRouter {
        code: OpenRouterErrorCode::InvalidJson,
        message: "OpenRouter returned invalid JSON".to_string(),
        finish_reason: None,
    };
    let bytes = response.bytes().await.map_err(|err| {
        warn!(error = %err, "OpenRouter body could not be read");
        invalid_json()
    })?;
    // undici decodes UTF-8 and drops a byte order mark before JSON.parse
    let text = String::from_utf8_lossy(&bytes);
    let text = text.strip_prefix('\u{FEFF}').unwrap_or(&text);
    let data = js_json::parse(text).map_err(|_| invalid_json())?;
    interpret(&data)
}

fn header_text(headers: &HeaderMap, names: &[&str]) -> Option<String> {
    names.iter().find_map(|name| headers.get(*name).and_then(|value| value.to_str().ok()).map(str::to_string))
}

/// Everything after `response.json()`.
pub fn interpret(data: &JsValue) -> Result<String, OpenRouterFailure> {
    let choices = property(Some(data), "choices").map_err(OpenRouterFailure::Other)?;
    let empty_choices = || OpenRouterFailure::OpenRouter {
        code: OpenRouterErrorCode::EmptyChoices,
        message: "No response from OpenRouter".to_string(),
        finish_reason: None,
    };
    let Some(choices) = choices.filter(JsValue::is_truthy) else { return Err(empty_choices()) };
    if property(Some(&choices), "length").map_err(OpenRouterFailure::Other)? == Some(JsValue::Number(0.0)) {
        return Err(empty_choices());
    }
    let choice = property(Some(&choices), "0").map_err(OpenRouterFailure::Other)?;
    let message = property(choice.as_ref(), "message").map_err(OpenRouterFailure::Other)?;
    let content = optional_property(message.as_ref(), "content");
    let finish_reason = property(choice.as_ref(), "finish_reason").map_err(OpenRouterFailure::Other)?;

    match content {
        Some(JsValue::String(text)) if !trim(&text).is_empty() => Ok(text),
        _ => {
            let suffix = match &finish_reason {
                Some(reason) if reason.is_truthy() => format!(" ({})", reason.to_js_string()),
                _ => String::new(),
            };
            Err(OpenRouterFailure::OpenRouter {
                code: OpenRouterErrorCode::EmptyContent,
                message: format!("OpenRouter returned an empty response{suffix}"),
                finish_reason,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(text: &str) -> Result<String, OpenRouterFailure> {
        interpret(&js_json::parse(text).unwrap())
    }

    fn code(text: &str) -> Option<OpenRouterErrorCode> {
        match run(text) {
            Err(OpenRouterFailure::OpenRouter { code, .. }) => Some(code),
            _ => None,
        }
    }

    #[test]
    fn reads_responses_with_javascript_semantics() {
        assert_eq!(run(r#"{"choices":[{"message":{"content":"SELECT 1"}}]}"#).unwrap(), "SELECT 1");
        assert_eq!(code(r#"{"choices":[]}"#), Some(OpenRouterErrorCode::EmptyChoices));
        assert_eq!(code(r#"{}"#), Some(OpenRouterErrorCode::EmptyChoices));
        assert_eq!(code("5"), Some(OpenRouterErrorCode::EmptyChoices));
        assert_eq!(code(r#"{"choices":"abc"}"#), Some(OpenRouterErrorCode::EmptyContent));
        assert!(matches!(run("null"), Err(OpenRouterFailure::Other(_))));
        assert!(matches!(run(r#"{"choices":[null]}"#), Err(OpenRouterFailure::Other(_))));
        assert!(matches!(run(r#"{"choices":{}}"#), Err(OpenRouterFailure::Other(_))));
        assert_eq!(code(r#"{"choices":{"length":0}}"#), Some(OpenRouterErrorCode::EmptyChoices));
        match run(r#"{"choices":[{"message":{"content":"  "},"finish_reason":"length"}]}"#) {
            Err(OpenRouterFailure::OpenRouter { message, finish_reason, .. }) => {
                assert_eq!(message, "OpenRouter returned an empty response (length)");
                assert_eq!(finish_reason, Some(JsValue::String("length".into())));
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(code(r#"{"choices":[{"message":{"content":["a"]}}]}"#), Some(OpenRouterErrorCode::EmptyContent));
    }
}
