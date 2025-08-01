//! Debug Logger for TiDB Cloud Client
//!
//! This module provides verbose logging capabilities for debugging TiDB Cloud API interactions.
//! Uses the common tracing infrastructure for consistent logging across the application.

use crate::tidb_cloud::constants::VerbosityLevel;
use tracing::{debug, error, trace, warn};

/// Debug logger for TiDB Cloud operations
#[derive(Clone)]
pub struct DebugLogger {
    verbosity: VerbosityLevel,
    enabled: bool,
}

impl DebugLogger {
    /// Create a new debug logger
    pub fn new(verbosity: VerbosityLevel) -> Self {
        Self {
            verbosity,
            enabled: verbosity != VerbosityLevel::Silent,
        }
    }

    /// Check if logging is enabled
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Get current verbosity level
    pub fn verbosity(&self) -> VerbosityLevel {
        self.verbosity
    }

    /// Log a message if the current verbosity level allows it
    pub fn log(&self, level: VerbosityLevel, message: &str) {
        if self.enabled && level <= self.verbosity {
            match level {
                VerbosityLevel::Error => error!(target: "tidb_cloud", "{}", message),
                VerbosityLevel::Warning => warn!(target: "tidb_cloud", "{}", message),
                VerbosityLevel::Info => debug!(target: "tidb_cloud", "{}", message),
                VerbosityLevel::Debug => debug!(target: "tidb_cloud", "{}", message),
                VerbosityLevel::Trace => trace!(target: "tidb_cloud", "{}", message),
                VerbosityLevel::Silent => {}
            }
        }
    }

    /// Log an error message
    pub fn error(&self, message: &str) {
        self.log(VerbosityLevel::Error, message);
    }

    /// Log a warning message
    pub fn warning(&self, message: &str) {
        self.log(VerbosityLevel::Warning, message);
    }

    /// Log an info message
    pub fn info(&self, message: &str) {
        self.log(VerbosityLevel::Info, message);
    }

    /// Log a debug message
    pub fn debug(&self, message: &str) {
        self.log(VerbosityLevel::Debug, message);
    }

    /// Log a trace message
    pub fn trace(&self, message: &str) {
        self.log(VerbosityLevel::Trace, message);
    }

    /// Log API request details
    pub fn log_request(&self, method: &str, url: &str, headers: Option<&str>, body: Option<&str>) {
        if self.verbosity >= VerbosityLevel::Debug {
            self.debug(&format!("API Request: {method} {url}"));

            if let Some(headers) = headers {
                self.trace(&format!("Headers: {headers}"));
            }

            if let Some(body) = body {
                // Truncate body for security
                let truncated_body = if body.len() > 500 {
                    format!("{}... (truncated)", &body[..500])
                } else {
                    body.to_string()
                };
                self.trace(&format!("Body: {truncated_body}"));
            }
        }
    }

    /// Log full API query details (for detailed debugging)
    pub fn log_api_query(&self, method: &str, url: &str, body: Option<&str>) {
        if self.verbosity >= VerbosityLevel::Trace {
            self.trace("=== FULL API QUERY ===");
            self.trace(&format!("Method: {method}"));
            self.trace(&format!("URL: {url}"));

            if let Some(body) = body {
                self.trace("Request Body:");
                // Log each line of the body with proper trace prefix
                for line in body.lines() {
                    self.trace(line);
                }
            }
            self.trace("=====================");
        } else if self.verbosity >= VerbosityLevel::Debug {
            self.debug(&format!("API Query: {method} {url}"));
            if let Some(body) = body {
                let truncated_body = if body.len() > 200 {
                    format!("{}... (truncated)", &body[..200])
                } else {
                    body.to_string()
                };
                self.debug(&format!("Body: {truncated_body}"));
            }
        }
    }

    /// Log full API query details including headers (for detailed debugging)
    pub fn log_api_query_with_headers(
        &self,
        method: &str,
        url: &str,
        headers: Option<&str>,
        body: Option<&str>,
    ) {
        if self.verbosity >= VerbosityLevel::Trace {
            self.trace("=== FULL API QUERY WITH HEADERS ===");
            self.trace(&format!("Method: {method}"));
            self.trace(&format!("URL: {url}"));

            if let Some(headers) = headers {
                self.trace("Request Headers:");
                // Log each header line with proper trace prefix
                for line in headers.lines() {
                    self.trace(line);
                }
            }

            if let Some(body) = body {
                self.trace("Request Body:");
                // Log each line of the body with proper trace prefix
                for line in body.lines() {
                    self.trace(line);
                }
            }
            self.trace("=================================");
        } else if self.verbosity >= VerbosityLevel::Debug {
            self.debug(&format!("API Query: {method} {url}"));
            if let Some(headers) = headers {
                self.debug(&format!("Headers: {headers}"));
            }
            if let Some(body) = body {
                let truncated_body = if body.len() > 200 {
                    format!("{}... (truncated)", &body[..200])
                } else {
                    body.to_string()
                };
                self.debug(&format!("Body: {truncated_body}"));
            }
        }
    }

    /// Log API response details
    pub fn log_response(&self, status: u16, headers: Option<&str>, body: Option<&str>) {
        if self.verbosity >= VerbosityLevel::Debug {
            self.debug(&format!("API Response: Status {status}"));

            if let Some(headers) = headers {
                self.trace(&format!("Response Headers: {headers}"));
            }

            if let Some(body) = body {
                // Truncate body for security
                let truncated_body = if body.len() > 500 {
                    format!("{}... (truncated)", &body[..500])
                } else {
                    body.to_string()
                };
                self.trace(&format!("Response Body: {truncated_body}"));
            }
        }
    }

    /// Log configuration details
    pub fn log_config(&self, config_name: &str, config_value: &str) {
        if self.verbosity >= VerbosityLevel::Info {
            self.info(&format!("Config {config_name}: {config_value}"));
        }
    }

    /// Log validation details
    pub fn log_validation(&self, validation_name: &str, result: bool, details: Option<&str>) {
        if self.verbosity >= VerbosityLevel::Debug {
            let status = if result { "PASS" } else { "FAIL" };
            let message = if let Some(details) = details {
                format!("Validation {validation_name}: {status} - {details}")
            } else {
                format!("Validation {validation_name}: {status}")
            };
            self.debug(&message);
        }
    }

    /// Log timing information
    pub fn log_timing(&self, operation: &str, duration_ms: u64) {
        if self.verbosity >= VerbosityLevel::Debug {
            self.debug(&format!("Timing {operation}: {duration_ms}ms"));
        }
    }

    /// Log security-related information
    pub fn log_security(&self, security_check: &str, result: bool, details: Option<&str>) {
        if self.verbosity >= VerbosityLevel::Warning {
            let status = if result { "PASS" } else { "FAIL" };
            let message = if let Some(details) = details {
                format!("Security {security_check}: {status} - {details}")
            } else {
                format!("Security {security_check}: {status}")
            };

            if result {
                self.debug(&message);
            } else {
                self.warning(&message);
            }
        }
    }
}

impl Default for DebugLogger {
    fn default() -> Self {
        Self::new(VerbosityLevel::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_debug_logger_creation() {
        let logger = DebugLogger::new(VerbosityLevel::Debug);
        assert!(logger.is_enabled());
        assert_eq!(logger.verbosity(), VerbosityLevel::Debug);
    }

    #[test]
    fn test_debug_logger_silent() {
        let logger = DebugLogger::new(VerbosityLevel::Silent);
        assert!(!logger.is_enabled());
    }

    #[test]
    fn test_verbosity_levels() {
        assert_eq!(VerbosityLevel::Silent as u8, 0);
        assert_eq!(VerbosityLevel::Error as u8, 1);
        assert_eq!(VerbosityLevel::Warning as u8, 2);
        assert_eq!(VerbosityLevel::Info as u8, 3);
        assert_eq!(VerbosityLevel::Debug as u8, 4);
        assert_eq!(VerbosityLevel::Trace as u8, 5);
    }

    #[test]
    fn test_verbosity_from_u8() {
        assert_eq!(VerbosityLevel::from(0), VerbosityLevel::Silent);
        assert_eq!(VerbosityLevel::from(3), VerbosityLevel::Info);
        assert_eq!(VerbosityLevel::from(10), VerbosityLevel::Trace);
    }
}
