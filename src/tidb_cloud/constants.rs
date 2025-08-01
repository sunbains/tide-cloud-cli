//! TiDB Cloud API Constants
//!
//! This module contains all the constants used throughout the TiDB Cloud client,
//! including URLs, API versions, and default values.

/// Production API base URL
pub const PRODUCTION_API_BASE_URL: &str = "https://cloud.tidbapi.com";

/// Development API base URL
pub const DEVELOPMENT_API_BASE_URL: &str = "https://dev-api.tidbcloud.com";

/// API version
pub const API_VERSION: &str = "v1beta2";

/// Production API full URL (base + version)
pub const PRODUCTION_API_URL: &str = "https://cloud.tidbapi.com/v1beta2";

/// Development API full URL (base + version)
pub const DEVELOPMENT_API_URL: &str = "https://dev-api.tidbcloud.com/v1beta2";

/// Default timeout for API requests (30 seconds)
pub const DEFAULT_TIMEOUT_SECS: u64 = 30;

/// Default user agent for API requests
pub const DEFAULT_USER_AGENT: &str = "tidb-cloud-rust-client/1.0.0";

/// Test user agent for API requests
pub const TEST_USER_AGENT: &str = "tidb-cloud-rust-client-test/1.0.0";

/// Default minimum API key length
pub const DEFAULT_MIN_API_KEY_LENGTH: usize = 20;

/// Default maximum API key length
pub const DEFAULT_MAX_API_KEY_LENGTH: usize = 100;

/// Allowed hostnames for API requests
pub const ALLOWED_HOSTNAMES: &[&str] = &[
    "cloud.tidbapi.com",
    "cloud.dev.tidbapi.com",
    "api.tidbcloud.com",
    "dev-api.tidbcloud.com",
    "localhost",
    "127.0.0.1",
];

/// Default maximum request size in bytes (10MB)
pub const DEFAULT_MAX_REQUEST_SIZE: usize = 10 * 1024 * 1024;

/// Default maximum URL length
pub const DEFAULT_MAX_URL_LENGTH: usize = 2048;

/// Default maximum query length
pub const DEFAULT_MAX_QUERY_LENGTH: usize = 1024;

/// Default requests per minute for rate limiting
pub const DEFAULT_REQUESTS_PER_MINUTE: u32 = 100;

/// Default rate limit window in seconds
pub const DEFAULT_RATE_LIMIT_WINDOW_SECS: u64 = 60;

/// Default retry after seconds
pub const DEFAULT_RETRY_AFTER_SECS: u64 = 60;

/// Default retry delay in seconds
pub const DEFAULT_RETRY_DELAY_SECS: u64 = 1;

/// Default maximum retries
pub const DEFAULT_MAX_RETRIES: u32 = 3;

/// Default connection pool size
pub const DEFAULT_POOL_SIZE: usize = 10;

/// Default logging level
pub const DEFAULT_LOG_LEVEL: &str = "info";

/// Default enable request logging
pub const DEFAULT_ENABLE_REQUEST_LOGGING: bool = false;

/// Default enable API logging
pub const DEFAULT_ENABLE_API_LOGGING: bool = true;

/// Default enable security logging
pub const DEFAULT_ENABLE_SECURITY_LOGGING: bool = true;

/// Default include API keys in logs
pub const DEFAULT_INCLUDE_API_KEYS_IN_LOGS: bool = false;

/// Default require HTTPS
pub const DEFAULT_REQUIRE_HTTPS: bool = true;

/// Default enable rate limiting
pub const DEFAULT_ENABLE_RATE_LIMIT: bool = true;

/// Verbosity levels for debugging
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub enum VerbosityLevel {
    /// No debug output
    Silent = 0,
    /// Basic error messages only
    Error = 1,
    /// Warning and error messages
    Warning = 2,
    /// Info, warning, and error messages
    #[default]
    Info = 3,
    /// Debug, info, warning, and error messages
    Debug = 4,
    /// Trace, debug, info, warning, and error messages
    Trace = 5,
}

impl From<u8> for VerbosityLevel {
    fn from(level: u8) -> Self {
        match level {
            0 => VerbosityLevel::Silent,
            1 => VerbosityLevel::Error,
            2 => VerbosityLevel::Warning,
            3 => VerbosityLevel::Info,
            4 => VerbosityLevel::Debug,
            _ => VerbosityLevel::Trace,
        }
    }
}

impl std::fmt::Display for VerbosityLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VerbosityLevel::Silent => write!(f, "SILENT"),
            VerbosityLevel::Error => write!(f, "ERROR"),
            VerbosityLevel::Warning => write!(f, "WARNING"),
            VerbosityLevel::Info => write!(f, "INFO"),
            VerbosityLevel::Debug => write!(f, "DEBUG"),
            VerbosityLevel::Trace => write!(f, "TRACE"),
        }
    }
}
