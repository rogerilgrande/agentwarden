//! The library error type and how it maps to an HTTP response.

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;

#[derive(Debug, thiserror::Error)]
pub(crate) enum GateError {
    #[error("invalid request: {0}")]
    InvalidRequest(String),

    #[error("invalid agent name: {0:?}")]
    InvalidAgent(String),

    #[error("invalid session id: {0:?}")]
    InvalidSession(String),

    #[error("missing or invalid admin key")]
    Unauthorized,

    #[error("reload endpoint is disabled (no admin key configured)")]
    Forbidden,

    #[error("failed to read policy file {path}: {source}")]
    PolicyIo {
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to parse policy file: {0}")]
    PolicyParse(#[from] toml::de::Error),

    #[error("invalid regex in rule {id}: {source}")]
    BadRegex {
        id: u32,
        #[source]
        source: regex::Error,
    },

    #[error("invalid glob in rule {id}: {source}")]
    BadGlob {
        id: u32,
        #[source]
        source: globset::Error,
    },

    #[error("rule {id} has an empty pattern that would match every command")]
    EmptyRule { id: u32 },
}

impl IntoResponse for GateError {
    fn into_response(self) -> Response {
        // The compiler forces this match to stay exhaustive: a new variant won't
        // compile until its status is decided here.
        let status = match &self {
            GateError::InvalidRequest(_)
            | GateError::InvalidAgent(_)
            | GateError::InvalidSession(_) => StatusCode::UNPROCESSABLE_ENTITY,
            GateError::Unauthorized => StatusCode::UNAUTHORIZED,
            GateError::Forbidden => StatusCode::FORBIDDEN,
            GateError::PolicyIo { .. }
            | GateError::PolicyParse(_)
            | GateError::BadRegex { .. }
            | GateError::BadGlob { .. }
            | GateError::EmptyRule { .. } => StatusCode::INTERNAL_SERVER_ERROR,
        };

        // Client errors carry an actionable message; server errors are redacted
        // so internal details (paths, parser internals) never reach the client.
        let body = if status.is_client_error() {
            self.to_string()
        } else {
            "internal error".to_owned()
        };

        tracing::warn!(error = %self, status = %status, "request rejected");
        (status, Json(json!({ "error": body }))).into_response()
    }
}
