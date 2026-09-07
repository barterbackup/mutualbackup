use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const MAX_WIRE_ERROR_BYTES: usize = 4096;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WireErrorCode {
    InvalidRequest,
    Unauthorized,
    NotFound,
    Conflict,
    Busy,
    Locked,
    OperationFailed,
}

/// Bounded error information carried by both local JSON and peer CBOR.
#[derive(Clone, Debug, Eq, Error, PartialEq, Serialize, Deserialize)]
#[error("{message}")]
pub struct WireError {
    pub code: WireErrorCode,
    pub retryable: bool,
    pub message: String,
}

impl WireError {
    pub fn new(code: WireErrorCode, retryable: bool, message: impl Into<String>) -> Self {
        Self {
            code,
            retryable,
            message: truncate_utf8(message.into(), MAX_WIRE_ERROR_BYTES),
        }
    }

    pub fn operation(error: impl std::fmt::Display) -> Self {
        Self::new(WireErrorCode::OperationFailed, false, error.to_string())
    }

    pub fn busy(message: impl Into<String>) -> Self {
        Self::new(WireErrorCode::Busy, true, message)
    }

    pub fn locked() -> Self {
        Self::new(
            WireErrorCode::Locked,
            true,
            "daemon is locked; only status and unlock are available",
        )
    }
}

fn truncate_utf8(mut value: String, max_bytes: usize) -> String {
    if value.len() <= max_bytes {
        return value;
    }
    let mut boundary = max_bytes;
    while !value.is_char_boundary(boundary) {
        boundary -= 1;
    }
    value.truncate(boundary);
    value
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_errors_are_bounded_on_utf8_boundaries() {
        let error = WireError::operation("a".repeat(MAX_WIRE_ERROR_BYTES - 1) + "🔒");
        assert_eq!(error.message.len(), MAX_WIRE_ERROR_BYTES - 1);
        assert!(error.message.is_char_boundary(error.message.len()));
    }
}
