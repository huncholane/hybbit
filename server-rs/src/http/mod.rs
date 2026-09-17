//! The HTTP edge shared by every route: CORS, error bodies, request logs and static
//! files, each matching what the Node backend does around its handlers.

pub mod cors;
pub mod errors;
pub mod logging;
pub mod static_files;

use axum::{
    body::Body,
    http::{HeaderValue, StatusCode, header},
    response::Response,
};
use serde_json::Value;

/// Response extension for replies Fastify writes straight to the socket before
/// any hook runs (`onBadUrl`): the CORS and error-body layers pass them through
/// untouched.
#[derive(Clone, Copy, Debug)]
pub struct RawFrameworkResponse;

/// A JSON response spelled the way `JSON.stringify` spells it (see `js_json`), for
/// bodies that carry user-provided numbers such as feature flag payloads.
pub fn js_json(status: StatusCode, value: &Value) -> Response {
    let mut response = Response::new(Body::from(crate::js_json::stringify(value)));
    *response.status_mut() = status;
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json; charset=utf-8"));
    response
}

/// A JSON response with the content type Fastify sends for objects.
pub fn json(status: StatusCode, value: &Value) -> Response {
    let mut response = Response::new(Body::from(serde_json::to_vec(value).unwrap_or_default()));
    *response.status_mut() = status;
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json; charset=utf-8"));
    response
}
