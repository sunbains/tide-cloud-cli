//! # Error Handling
//!
//! Comprehensive error types and retry mechanisms for the TiDB connection framework.
//! Provides specific error variants, retry strategies, and circuit breaker patterns.

use crate::state_machine::State;
use std::future::Future;
use std::pin::Pin;
use std::time::Duration;
use thiserror::Error;

/// Main error type for the `TiDB` connection and testing framework
#[derive(Error, Debug)]
pub enum ConnectError {
    #[error("Connection error: {0}")]
    Connection(mysql::Error),

    #[error("Authentication error: {0}")]
    Authentication(String),

    #[error("Configuration error: {0}")]
    Configuration(String),

    #[error("State machine error: {0}")]
    StateMachine(String),

    #[error("Database error: {0}")]
    Database(String),

    #[error("Isolation test error: {0}")]
    IsolationTest(String),

    #[error("CLI argument error: {0}")]
    CliArgument(String),

    #[error("Logging error: {0}")]
    Logging(String),

    #[error("IO error: {0}")]
    Io(std::io::Error),

    #[error("Parse error: {0}")]
    Parse(String),

    #[error("Validation error: {0}")]
    Validation(String),

    #[error("Timeout error: {0}")]
    Timeout(String),

    #[error("Retry error: {0}")]
    Retry(String),

    #[error("Circuit breaker error: {0}")]
    CircuitBreaker(String),

    #[error("Network error: {0}")]
    Network(String),

    #[error("Protocol error: {0}")]
    Protocol(String),

    #[error("Resource error: {0}")]
    Resource(String),

    #[error("Unknown error: {0}")]
    Unknown(String),
}

/// Enhanced state machine error with specific variants
#[derive(Error, Debug)]
pub enum StateError {
    #[error("Connection timeout after {timeout:?}")]
    ConnectionTimeout { timeout: Duration },

    #[error("Authentication failed: {reason}")]
    AuthenticationFailure { reason: String },

    #[error("SQL execution failed - Query: {query}, Error: {error}")]
    SqlExecutionError { query: String, error: String },

    #[error("State transition failed from {from:?} to {to:?}: {reason}")]
    StateTransitionError {
        from: State,
        to: State,
        reason: String,
    },

    #[error("Configuration error: {0}")]
    ConfigError(#[from] ConfigError),

    #[error("Network error: {0}")]
    NetworkError(#[from] std::io::Error),

    #[error("State machine context error: {0}")]
    ContextError(String),

    #[error("Handler execution failed: {0}")]
    HandlerError(String),

    #[error("State machine timeout after {duration:?}")]
    Timeout { duration: Duration },

    #[error("State machine deadlock detected")]
    Deadlock,

    #[error("State machine initialization failed: {reason}")]
    InitializationFailed { reason: String },
}

/// Configuration-specific error type
#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("Invalid configuration: {message}")]
    Invalid { message: String },

    #[error("Missing required configuration: {field}")]
    Missing { field: String },

    #[error("Configuration file not found: {path}")]
    FileNotFound { path: String },

    #[error("Configuration parse error: {0}")]
    ParseError(#[from] serde_json::Error),
}

/// Retry configuration
#[derive(Debug, Clone)]
pub struct RetryConfig {
    pub max_retries: usize,
    pub base_delay: Duration,
    pub max_delay: Duration,
    pub backoff_multiplier: f64,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_retries: 3,
            base_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(30),
            backoff_multiplier: 2.0,
        }
    }
}

/// Retry mechanism with exponential backoff
pub struct RetryStrategy {
    config: RetryConfig,
}

impl RetryStrategy {
    #[must_use]
    pub fn new(config: RetryConfig) -> Self {
        Self { config }
    }

    #[must_use]
    pub fn with_default_config() -> Self {
        Self::new(RetryConfig::default())
    }

    /// Retry an operation with exponential backoff
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails after all retry attempts.
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        clippy::cast_precision_loss
    )]
    pub async fn retry<F, T, E>(&self, mut operation: F) -> std::result::Result<T, E>
    where
        F: FnMut() -> Pin<Box<dyn Future<Output = std::result::Result<T, E>> + Send>>,
        E: std::error::Error,
    {
        let mut delay = self.config.base_delay;

        for attempt in 0..self.config.max_retries {
            match operation().await {
                Ok(result) => return Ok(result),
                Err(e) if attempt == self.config.max_retries - 1 => return Err(e),
                Err(_) => {
                    tokio::time::sleep(delay).await;
                    delay = Duration::from_millis(
                        (delay.as_millis() as f64 * self.config.backoff_multiplier) as u64,
                    )
                    .min(self.config.max_delay);
                }
            }
        }
        unreachable!()
    }

    /// Retry an operation with exponential backoff and error transformation
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails after all retry attempts.
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        clippy::cast_precision_loss
    )]
    pub async fn retry_with_transform<F, T, E, E2>(
        &self,
        mut operation: F,
        transform: impl Fn(E) -> E2,
    ) -> std::result::Result<T, E2>
    where
        F: FnMut() -> Pin<Box<dyn Future<Output = std::result::Result<T, E>> + Send>>,
        E: std::error::Error,
        E2: std::error::Error,
    {
        let mut delay = self.config.base_delay;

        for attempt in 0..self.config.max_retries {
            match operation().await {
                Ok(result) => return Ok(result),
                Err(e) if attempt == self.config.max_retries - 1 => return Err(transform(e)),
                Err(_) => {
                    tokio::time::sleep(delay).await;
                    delay = Duration::from_millis(
                        (delay.as_millis() as f64 * self.config.backoff_multiplier) as u64,
                    )
                    .min(self.config.max_delay);
                }
            }
        }
        unreachable!()
    }
}

/// Specific error types for different components
#[derive(Error, Debug)]
pub enum ConnectionError {
    #[error("Failed to connect to {host}:{port}: {message}")]
    ConnectFailed {
        host: String,
        port: u16,
        message: String,
    },

    #[error("Authentication failed for user {user}: {message}")]
    AuthFailed { user: String, message: String },

    #[error("Database {database} does not exist or access denied")]
    DatabaseNotFound { database: String },

    #[error("Connection pool error: {0}")]
    PoolError(#[from] mysql::Error),

    #[error("Connection timeout after {timeout_secs} seconds")]
    Timeout { timeout_secs: u64 },

    #[error("Connection lost: {reason}")]
    ConnectionLost { reason: String },

    #[error("Connection refused by server")]
    ConnectionRefused,

    #[error("SSL/TLS error: {message}")]
    SslError { message: String },

    #[error("DNS resolution failed for {host}: {message}")]
    DnsResolutionFailed { host: String, message: String },

    #[error("Connection pool exhausted (max: {max_connections})")]
    PoolExhausted { max_connections: usize },

    #[error("Connection validation failed: {reason}")]
    ValidationFailed { reason: String },
}

#[derive(Error, Debug)]
pub enum CliError {
    #[error("Missing required argument: {arg}")]
    MissingArgument { arg: String },

    #[error("Invalid argument value for {arg}: {value}")]
    InvalidArgumentValue { arg: String, value: String },

    #[error("Conflicting arguments: {args}")]
    ConflictingArguments { args: String },

    #[error("Password required but not provided")]
    PasswordRequired,

    #[error("Configuration file {file} not found")]
    ConfigFileNotFound { file: String },

    #[error("Configuration file {file} is invalid: {reason}")]
    InvalidConfigFile { file: String, reason: String },

    #[error("Environment variable {var} is invalid: {reason}")]
    InvalidEnvironmentVariable { var: String, reason: String },
}

/// Enhanced error with additional context
#[derive(Error, Debug)]
pub enum EnhancedError {
    #[error("Database operation failed: {operation} - {error}")]
    DatabaseOperation {
        operation: String,
        error: Box<ConnectError>,
        context: ErrorContext,
    },

    #[error("Network operation failed: {operation} - {error}")]
    NetworkOperation {
        operation: String,
        error: Box<ConnectError>,
        context: ErrorContext,
    },

    #[error("Retry operation failed after {attempts} attempts: {error}")]
    RetryFailed {
        attempts: usize,
        error: Box<ConnectError>,
        context: ErrorContext,
    },

    #[error("Circuit breaker open: {operation} - {error}")]
    CircuitBreakerOpen {
        operation: String,
        error: Box<ConnectError>,
        context: ErrorContext,
    },
}

/// Error context for better debugging
#[derive(Debug, Clone)]
pub struct ErrorContext {
    pub timestamp: std::time::Instant,
    pub operation: String,
    pub attempt: usize,
    pub duration: Duration,
    pub host: Option<String>,
    pub database: Option<String>,
    pub user: Option<String>,
    pub additional_info: std::collections::HashMap<String, String>,
}

impl ErrorContext {
    #[must_use]
    pub fn new(operation: String) -> Self {
        Self {
            timestamp: std::time::Instant::now(),
            operation,
            attempt: 0,
            duration: Duration::ZERO,
            host: None,
            database: None,
            user: None,
            additional_info: std::collections::HashMap::new(),
        }
    }

    #[must_use]
    pub fn with_attempt(mut self, attempt: usize) -> Self {
        self.attempt = attempt;
        self
    }

    #[must_use]
    pub fn with_duration(mut self, duration: Duration) -> Self {
        self.duration = duration;
        self
    }

    #[must_use]
    pub fn with_host(mut self, host: String) -> Self {
        self.host = Some(host);
        self
    }

    #[must_use]
    pub fn with_database(mut self, database: String) -> Self {
        self.database = Some(database);
        self
    }

    #[must_use]
    pub fn with_user(mut self, user: String) -> Self {
        self.user = Some(user);
        self
    }

    #[must_use]
    pub fn with_info(mut self, key: String, value: String) -> Self {
        self.additional_info.insert(key, value);
        self
    }
}

// Type aliases for backward compatibility
pub type Result<T> = std::result::Result<T, ConnectError>;

// Conversion implementations
impl From<mysql::Error> for ConnectError {
    fn from(err: mysql::Error) -> Self {
        ConnectError::Connection(err)
    }
}

impl From<std::io::Error> for ConnectError {
    fn from(err: std::io::Error) -> Self {
        ConnectError::Io(err)
    }
}

impl From<String> for ConnectError {
    fn from(err: String) -> Self {
        ConnectError::Unknown(err)
    }
}

impl From<&str> for ConnectError {
    fn from(err: &str) -> Self {
        ConnectError::Unknown(err.to_string())
    }
}

impl From<ConnectionError> for ConnectError {
    fn from(err: ConnectionError) -> Self {
        match err {
            ConnectionError::ConnectFailed {
                host: _,
                port: _,
                message: _,
            } => ConnectError::Connection(mysql::Error::server_disconnected()),
            ConnectionError::AuthFailed { user, message } => {
                ConnectError::Authentication(format!("User {user}: {message}"))
            }
            ConnectionError::DatabaseNotFound { database } => {
                ConnectError::Database(format!("Database {database} not found"))
            }
            ConnectionError::PoolError(e) => ConnectError::Connection(e),
            ConnectionError::Timeout { timeout_secs } => {
                ConnectError::Timeout(format!("Connection timeout after {timeout_secs} seconds"))
            }
            ConnectionError::ConnectionLost { reason: _ }
            | ConnectionError::ConnectionRefused
            | ConnectionError::SslError { message: _ } => {
                ConnectError::Connection(mysql::Error::server_disconnected())
            }
            ConnectionError::DnsResolutionFailed { host, message } => {
                ConnectError::Network(format!("DNS resolution failed for {host}: {message}"))
            }
            ConnectionError::PoolExhausted { max_connections } => ConnectError::Resource(format!(
                "Connection pool exhausted (max: {max_connections})"
            )),
            ConnectionError::ValidationFailed { reason } => ConnectError::Validation(reason),
        }
    }
}

impl From<StateError> for ConnectError {
    fn from(err: StateError) -> Self {
        ConnectError::StateMachine(err.to_string())
    }
}

impl From<CliError> for ConnectError {
    fn from(err: CliError) -> Self {
        ConnectError::CliArgument(err.to_string())
    }
}

impl From<Box<dyn std::error::Error>> for ConnectError {
    fn from(err: Box<dyn std::error::Error>) -> Self {
        ConnectError::Unknown(err.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;

    #[test]
    fn test_connect_error_display() {
        let error = ConnectError::Connection(mysql::Error::server_disconnected());
        assert!(error.to_string().contains("Connection error"));
    }

    #[test]
    fn test_from_io_error() {
        let io_error = io::Error::new(io::ErrorKind::ConnectionRefused, "connection refused");
        let connect_error: ConnectError = io_error.into();
        assert!(matches!(connect_error, ConnectError::Io(_)));
    }

    #[test]
    fn test_result_alias() {
        fn returns_result() -> Result<u32> {
            Ok(42)
        }
        assert_eq!(returns_result().unwrap(), 42);
    }

    #[test]
    fn test_error_context() {
        let context = ErrorContext::new("test_operation".to_string())
            .with_attempt(3)
            .with_duration(Duration::from_secs(5))
            .with_host("localhost".to_string())
            .with_database("testdb".to_string())
            .with_user("testuser".to_string())
            .with_info("key".to_string(), "value".to_string());

        assert_eq!(context.operation, "test_operation");
        assert_eq!(context.attempt, 3);
        assert_eq!(context.duration, Duration::from_secs(5));
        assert_eq!(context.host, Some("localhost".to_string()));
        assert_eq!(context.database, Some("testdb".to_string()));
        assert_eq!(context.user, Some("testuser".to_string()));
        assert_eq!(
            context.additional_info.get("key"),
            Some(&"value".to_string())
        );
    }
}
