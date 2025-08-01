use serde::{Deserialize, Serialize};
use std::fmt;

/// Error type for TiDB Cloud API operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TiDBCloudError {
    /// HTTP request failed
    HttpError { status: u16, message: String },
    /// Network/transport error
    NetworkError(String),
    /// JSON serialization/deserialization error
    SerializationError(String),
    /// API returned an error response
    ApiError {
        code: i32,
        message: String,
        details: Option<Vec<serde_json::Value>>,
    },
    /// Invalid configuration
    ConfigError(String),
    /// Authentication error
    AuthError(String),
    /// Rate limiting error
    RateLimitError {
        retry_after: Option<u64>,
        message: String,
    },
    /// Resource not found
    NotFound(String),
    /// Resource already exists
    AlreadyExists(String),
    /// Invalid request parameters
    ValidationError(String),
    /// Timeout error
    TimeoutError(String),
    /// Unknown error
    Unknown(String),
}

impl fmt::Display for TiDBCloudError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TiDBCloudError::HttpError { status, message } => {
                write!(f, "HTTP error {status}: {message}")
            }
            TiDBCloudError::NetworkError(msg) => {
                write!(f, "Network error: {msg}")
            }
            TiDBCloudError::SerializationError(msg) => {
                write!(f, "Serialization error: {msg}")
            }
            TiDBCloudError::ApiError {
                code,
                message,
                details,
            } => {
                write!(f, "API error {code}: {message}")?;
                if let Some(details) = details {
                    // Try to extract request ID from details for better debugging
                    for detail in details {
                        if let Some(detail_obj) = detail.as_object()
                            && let Some(request_id) =
                                detail_obj.get("requestId").and_then(|v| v.as_str())
                        {
                            write!(f, " (Request ID: {request_id})")?;
                            break;
                        }
                    }
                }
                Ok(())
            }
            TiDBCloudError::ConfigError(msg) => {
                write!(f, "Configuration error: {msg}")
            }
            TiDBCloudError::AuthError(msg) => {
                write!(f, "Authentication error: {msg}")
            }
            TiDBCloudError::RateLimitError {
                retry_after,
                message,
            } => {
                write!(f, "Rate limit error: {message}")?;
                if let Some(retry_after) = retry_after {
                    write!(f, " (retry after {retry_after} seconds)")?;
                }
                Ok(())
            }
            TiDBCloudError::NotFound(resource) => {
                write!(f, "Resource not found: {resource}")
            }
            TiDBCloudError::AlreadyExists(resource) => {
                write!(f, "Resource already exists: {resource}")
            }
            TiDBCloudError::ValidationError(msg) => {
                write!(f, "Validation error: {msg}")
            }
            TiDBCloudError::TimeoutError(msg) => {
                write!(f, "Timeout error: {msg}")
            }
            TiDBCloudError::Unknown(msg) => {
                write!(f, "Unknown error: {msg}")
            }
        }
    }
}

impl std::error::Error for TiDBCloudError {}

impl From<reqwest::Error> for TiDBCloudError {
    fn from(err: reqwest::Error) -> Self {
        if err.is_timeout() {
            TiDBCloudError::TimeoutError(err.to_string())
        } else {
            TiDBCloudError::NetworkError(err.to_string())
        }
    }
}

impl From<serde_json::Error> for TiDBCloudError {
    fn from(err: serde_json::Error) -> Self {
        TiDBCloudError::SerializationError(err.to_string())
    }
}

impl From<std::time::SystemTimeError> for TiDBCloudError {
    fn from(err: std::time::SystemTimeError) -> Self {
        TiDBCloudError::Unknown(err.to_string())
    }
}

/// Result type for TiDB Cloud API operations
pub type TiDBCloudResult<T> = Result<T, TiDBCloudError>;

/// Google RPC Status response structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoogleRpcStatus {
    pub code: i32,
    pub message: String,
    pub details: Option<Vec<serde_json::Value>>,
}

impl From<GoogleRpcStatus> for TiDBCloudError {
    fn from(status: GoogleRpcStatus) -> Self {
        TiDBCloudError::ApiError {
            code: status.code,
            message: status.message,
            details: status.details,
        }
    }
}
