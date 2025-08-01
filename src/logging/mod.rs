//! # Logging
//!
//! Structured logging configuration and utilities.
//! Provides multiple log formats, file and console output, and configurable log levels.

use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU8, Ordering};
use tracing::Level;
use tracing_subscriber::{EnvFilter, FmtSubscriber};

// Global log level state
static CURRENT_LOG_LEVEL: AtomicU8 = AtomicU8::new(2); // Default to INFO (2)

// Log level constants
const LEVEL_TRACE: u8 = 0;
const LEVEL_DEBUG: u8 = 1;
const LEVEL_INFO: u8 = 2;
const LEVEL_WARN: u8 = 3;
const LEVEL_ERROR: u8 = 4;

/// Get the current log level
pub fn get_current_log_level() -> Level {
    let level = CURRENT_LOG_LEVEL.load(Ordering::Relaxed);
    match level {
        LEVEL_TRACE => Level::TRACE,
        LEVEL_DEBUG => Level::DEBUG,
        LEVEL_INFO => Level::INFO,
        LEVEL_WARN => Level::WARN,
        LEVEL_ERROR => Level::ERROR,
        _ => Level::INFO, // Default fallback
    }
}

/// Set the current log level
pub fn set_current_log_level(level: Level) {
    let level_u8 = match level {
        Level::TRACE => LEVEL_TRACE,
        Level::DEBUG => LEVEL_DEBUG,
        Level::INFO => LEVEL_INFO,
        Level::WARN => LEVEL_WARN,
        Level::ERROR => LEVEL_ERROR,
    };
    CURRENT_LOG_LEVEL.store(level_u8, Ordering::Relaxed);
}

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
    // Initialize the global log level state
    set_current_log_level(config.level);

    // Create logs directory if it doesn't exist
    if config.file
        && let Some(parent) = config.file_path.parent()
    {
        fs::create_dir_all(parent)?;
    }

    // Build the subscriber with proper filter configuration
    let filter = if config.level == Level::TRACE {
        EnvFilter::new("trace,tidb_cloud=trace")
    } else {
        EnvFilter::new(format!("{}", config.level)).add_directive(
            "tidb_cloud=debug"
                .parse()
                .unwrap_or_else(|_| "tidb_cloud=info".parse().unwrap()),
        )
    };

    let subscriber = FmtSubscriber::builder()
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
    tracing::debug!("Logging system initialized");
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

/// Change the log level dynamically
///
/// # Errors
///
/// Returns an error if the log level change fails.
pub fn change_log_level(level: Level) -> Result<(), Box<dyn std::error::Error>> {
    // Update the global log level state
    set_current_log_level(level);

    // For now, we'll use a simple approach that doesn't try to change the global dispatcher
    // The global state is updated, and we can use custom logging functions that respect this state

    // Log the change using a custom function that respects our global state
    log_with_global_level(Level::DEBUG, &format!("Log level changed to: {level}"));

    // Note: This is a simplified implementation that updates the global state
    // but doesn't affect the existing tracing subscriber. For a full implementation,
    // we would need to use tracing_subscriber::reload or implement a custom layer.
    // The current approach at least prevents the "global dispatcher already set" error.

    Ok(())
}

/// Custom logging function that respects the global log level state
pub fn log_with_global_level(level: Level, message: &str) {
    let current_level = get_current_log_level();
    if level <= current_level {
        match level {
            Level::TRACE => eprintln!("[TRACE] {message}"),
            Level::DEBUG => eprintln!("[DEBUG] {message}"),
            Level::INFO => eprintln!("[INFO] {message}"),
            Level::WARN => eprintln!("[WARN] {message}"),
            Level::ERROR => eprintln!("[ERROR] {message}"),
        }
    }
}

/// Custom logging function that respects the global log level
pub fn log_with_level(level: Level, message: &str) {
    let current_level = get_current_log_level();
    if level <= current_level {
        match level {
            Level::TRACE => tracing::trace!("{}", message),
            Level::DEBUG => tracing::debug!("{}", message),
            Level::INFO => tracing::info!("{}", message),
            Level::WARN => tracing::warn!("{}", message),
            Level::ERROR => tracing::error!("{}", message),
        }
    }
}

/// Logging macros for common operations
#[macro_export]
macro_rules! log_connection_attempt {
    ($host:expr, $user:expr) => {
        tracing::debug!("Attempting connection to {} as user {}", $host, $user);
    };
}

#[macro_export]
macro_rules! log_connection_success {
    ($host:expr) => {
        tracing::debug!("Successfully connected to {}", $host);
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
        tracing::debug!("State transition: {} -> {}", $from, $to);
    };
}

#[macro_export]
macro_rules! log_import_job {
    ($job_id:expr, $status:expr) => {
        tracing::debug!("Import job {}: {}", $job_id, $status);
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
    tracing::debug!(
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
