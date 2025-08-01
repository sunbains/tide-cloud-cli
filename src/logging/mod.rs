//! # Logging
//!
//! Structured logging configuration and utilities.
//! Provides multiple log formats, file and console output, and configurable log levels.

use std::fs;
use std::path::PathBuf;
use tracing::Level;

/// Logging configuration
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone)]
pub struct LogConfig {
    /// Log level (default: INFO)
    pub level: Level,
    /// Whether to log to console
    pub console: bool,
    /// Whether to log to file
    pub file: bool,
    /// Log file path (default: `logs/tidb_connect.log`)
    pub file_path: PathBuf,
    /// Maximum log file size in MB (default: 10)
    pub max_file_size: usize,
    /// Number of log files to keep (default: 5)
    pub max_files: usize,
    /// Whether to include timestamps
    pub include_timestamps: bool,
    /// Whether to include thread IDs
    pub include_thread_ids: bool,
    /// Whether to include file and line numbers
    pub include_file_line: bool,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            level: Level::INFO,
            console: true,
            file: false,
            file_path: PathBuf::from("logs/tidb_connect.log"),
            max_file_size: 10,
            max_files: 5,
            include_timestamps: true,
            include_thread_ids: false,
            include_file_line: true,
        }
    }
}

impl LogConfig {
    /// Create a new log config with custom settings
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the log level
    #[must_use]
    pub fn with_level(mut self, level: Level) -> Self {
        self.level = level;
        self
    }

    /// Enable/disable console logging
    #[must_use]
    pub fn with_console(mut self, console: bool) -> Self {
        self.console = console;
        self
    }

    /// Enable/disable file logging
    #[must_use]
    pub fn with_file(mut self, file: bool) -> Self {
        self.file = file;
        self
    }

    /// Set the log file path
    #[must_use]
    pub fn with_file_path(mut self, path: PathBuf) -> Self {
        self.file_path = path;
        self
    }

    /// Set maximum file size in MB
    #[must_use]
    pub fn with_max_file_size(mut self, size_mb: usize) -> Self {
        self.max_file_size = size_mb;
        self
    }

    /// Set maximum number of files to keep
    #[must_use]
    pub fn with_max_files(mut self, count: usize) -> Self {
        self.max_files = count;
        self
    }

    /// Enable/disable timestamps
    #[must_use]
    pub fn with_timestamps(mut self, include: bool) -> Self {
        self.include_timestamps = include;
        self
    }

    /// Enable/disable thread IDs
    #[must_use]
    pub fn with_thread_ids(mut self, include: bool) -> Self {
        self.include_thread_ids = include;
        self
    }

    /// Enable/disable file and line numbers
    #[must_use]
    pub fn with_file_line(mut self, include: bool) -> Self {
        self.include_file_line = include;
        self
    }
}

/// Initialize logging system
///
/// # Errors
///
/// Returns an error if logging initialization fails.
pub fn init_logging(config: &LogConfig) -> Result<(), Box<dyn std::error::Error>> {
    // Create logs directory if it doesn't exist
    if config.file
        && let Some(parent) = config.file_path.parent()
    {
        fs::create_dir_all(parent)?;
    }

    // Build the subscriber with proper filter configuration
    let filter = if config.level == Level::TRACE {
        tracing_subscriber::EnvFilter::new("trace,tidb_cloud=trace")
    } else {
        tracing_subscriber::EnvFilter::new(format!("{}", config.level))
            .add_directive("tidb_cloud=debug".parse().unwrap_or_else(|_| "tidb_cloud=info".parse().unwrap()))
    };
    
    let subscriber = tracing_subscriber::FmtSubscriber::builder()
        .with_level(true)
        .with_target(true)
        .with_file(true)
        .with_line_number(true)
        .with_thread_ids(config.include_thread_ids)
        .with_ansi(true)
        .with_env_filter(filter)
        .finish();

    // Set the global subscriber
    tracing::subscriber::set_global_default(subscriber)?;

    // Log initialization
    tracing::info!("Logging system initialized");
    tracing::debug!("Log config: {:?}", config);

    Ok(())
}

/// Initialize default logging configuration
///
/// # Errors
///
/// Returns an error if logging initialization fails.
pub fn init_default_logging() -> Result<(), Box<dyn std::error::Error>> {
    init_logging(&LogConfig::default())
}

/// Initialize logging from environment variables
///
/// # Errors
///
/// Returns an error if logging initialization fails.
pub fn init_logging_from_env() -> Result<(), Box<dyn std::error::Error>> {
    let mut config = LogConfig::default();

    // Set log level from environment
    if let Ok(level_str) = std::env::var("RUST_LOG")
        && let Ok(level) = level_str.parse::<Level>()
    {
        config = config.with_level(level);
    }

    // Set file logging from environment
    if let Ok(file_enabled) = std::env::var("TIDB_LOG_FILE")
        && file_enabled.to_lowercase() == "true"
    {
        config = config.with_file(true);
    }

    // Set file path from environment
    if let Ok(file_path) = std::env::var("TIDB_LOG_FILE_PATH") {
        config = config.with_file_path(PathBuf::from(file_path));
    }

    init_logging(&config)
}

/// Logging macros for common operations
#[macro_export]
macro_rules! log_connection_attempt {
    ($host:expr, $user:expr) => {
        tracing::info!("Attempting connection to {} as user {}", $host, $user);
    };
}

#[macro_export]
macro_rules! log_connection_success {
    ($host:expr) => {
        tracing::info!("Successfully connected to {}", $host);
    };
}

#[macro_export]
macro_rules! log_connection_error {
    ($host:expr, $error:expr) => {
        tracing::error!("Failed to connect to {}: {}", $host, $error);
    };
}

#[macro_export]
macro_rules! log_query {
    ($query:expr) => {
        tracing::debug!("Executing query: {}", $query);
    };
}

#[macro_export]
macro_rules! log_query_result {
    ($rows:expr) => {
        tracing::debug!("Query returned {} rows", $rows);
    };
}

#[macro_export]
macro_rules! log_state_transition {
    ($from:expr, $to:expr) => {
        tracing::info!("State transition: {} -> {}", $from, $to);
    };
}

#[macro_export]
macro_rules! log_import_job {
    ($job_id:expr, $status:expr) => {
        tracing::info!("Import job {}: {}", $job_id, $status);
    };
}

/// Error context wrapper for better error logging
pub struct ErrorContext {
    pub operation: String,
    pub details: String,
}

impl ErrorContext {
    #[must_use]
    pub fn new(operation: &str, details: &str) -> Self {
        Self {
            operation: operation.to_string(),
            details: details.to_string(),
        }
    }

    pub fn log_error(&self, error: &dyn std::error::Error) {
        tracing::error!(
            operation = %self.operation,
            details = %self.details,
            error = %error,
            "Operation failed"
        );
    }
}

/// Log performance metrics
pub fn log_performance_metric(operation: &str, duration: std::time::Duration) {
    tracing::info!(
        operation = %operation,
        duration_ms = duration.as_millis(),
        "Performance metric"
    );
}

/// Log memory usage
pub fn log_memory_usage(component: &str, bytes: usize) {
    tracing::debug!(
        component = %component,
        bytes = bytes,
        "Memory usage"
    );
}
