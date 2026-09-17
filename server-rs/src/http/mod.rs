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

/// A JSON response with the content type Fastify sends for objects.
pub fn json(status: StatusCode, value: &Value) -> Response {
    let mut response = Response::new(Body::from(serde_json::to_vec(value).unwrap_or_default()));
    *response.status_mut() = status;
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json; charset=utf-8"));
    response
}
