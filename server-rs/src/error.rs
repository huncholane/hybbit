use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde_json::json;

/// Error returned by handlers, rendered as `{ "error": message }`: the body shape
/// the Node backend's handlers send.
#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("{message}")]
    Status { status: StatusCode, message: String },
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

impl AppError {
    pub fn status(status: StatusCode, message: impl Into<String>) -> Self {
        Self::Status { status, message: message.into() }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        match self {
            AppError::Status { status, message } => (status, Json(json!({ "error": message }))).into_response(),
            AppError::Internal(err) => {
                tracing::error!(error = ?err, "request failed");
                (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": "Internal server error" }))).into_response()
            }
        }
    }
}
