use crate::tidb_cloud::constants::*;
use crate::tidb_cloud::error::{TiDBCloudError, TiDBCloudResult};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// TiDB Cloud specific configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TiDBCloudConfig {
    /// API configuration
    #[serde(default)]
    pub api: ApiConfig,

    /// Client configuration
    #[serde(default)]
    pub client: ClientConfig,

    /// Security configuration
    #[serde(default)]
    pub security: SecurityConfig,

    /// Debug configuration
    #[serde(default)]
    pub debug: DebugConfig,
}

/// API configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiConfig {
    /// Base URL for TiDB Cloud API
    #[serde(default = "default_api_base_url")]
    pub base_url: String,

    /// API version
    #[serde(default = "default_api_version")]
    pub version: String,

    /// API key (can be overridden by environment variable)
    #[serde(default)]
    pub api_key: Option<String>,
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            base_url: default_api_base_url(),
            version: default_api_version(),
            api_key: None,
        }
    }
}

/// Client configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientConfig {
    /// Default timeout for operations in seconds
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,

    /// User agent string
    #[serde(default = "default_user_agent")]
    pub user_agent: String,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            timeout_secs: default_timeout(),
            user_agent: default_user_agent(),
        }
    }
}

/// Security configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    /// Minimum API key length
    #[serde(default = "default_min_api_key_length")]
    pub min_api_key_length: usize,

    /// Maximum API key length
    #[serde(default = "default_max_api_key_length")]
    pub max_api_key_length: usize,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            min_api_key_length: default_min_api_key_length(),
            max_api_key_length: default_max_api_key_length(),
        }
    }
}

/// Debug configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DebugConfig {
    /// Verbosity level for debugging
    #[serde(default = "default_verbosity_level")]
    pub verbosity_level: u8,

    /// Enable request logging
    #[serde(default = "default_enable_request_logging")]
    pub enable_request_logging: bool,

    /// Enable API logging
    #[serde(default = "default_enable_api_logging")]
    pub enable_api_logging: bool,

    /// Enable security logging
    #[serde(default = "default_enable_security_logging")]
    pub enable_security_logging: bool,
}

impl Default for DebugConfig {
    fn default() -> Self {
        Self {
            verbosity_level: default_verbosity_level(),
            enable_request_logging: default_enable_request_logging(),
            enable_api_logging: default_enable_api_logging(),
            enable_security_logging: default_enable_security_logging(),
        }
    }
}

// Default value functions
fn default_api_base_url() -> String {
    PRODUCTION_API_BASE_URL.to_string()
}

fn default_api_version() -> String {
    API_VERSION.to_string()
}

fn default_timeout() -> u64 {
    DEFAULT_TIMEOUT_SECS
}

fn default_user_agent() -> String {
    DEFAULT_USER_AGENT.to_string()
}

fn default_min_api_key_length() -> usize {
    DEFAULT_MIN_API_KEY_LENGTH
}

fn default_max_api_key_length() -> usize {
    DEFAULT_MAX_API_KEY_LENGTH
}

fn default_verbosity_level() -> u8 {
    3 // VerbosityLevel::Info
}

fn default_enable_request_logging() -> bool {
    DEFAULT_ENABLE_REQUEST_LOGGING
}

fn default_enable_api_logging() -> bool {
    DEFAULT_ENABLE_API_LOGGING
}

fn default_enable_security_logging() -> bool {
    DEFAULT_ENABLE_SECURITY_LOGGING
}

impl TiDBCloudConfig {
    /// Load TiDB Cloud configuration from a specific file
    pub fn from_file<P: AsRef<Path>>(path: P) -> TiDBCloudResult<Self> {
        let content = std::fs::read_to_string(&path)
            .map_err(|e| TiDBCloudError::ConfigError(format!("Failed to read config file: {e}")))?;

        if path.as_ref().extension().and_then(|s| s.to_str()) == Some("toml") {
            toml::from_str(&content).map_err(|e| {
                TiDBCloudError::ConfigError(format!("Failed to parse TOML config: {e}"))
            })
        } else {
            serde_json::from_str(&content).map_err(|e| {
                TiDBCloudError::ConfigError(format!("Failed to parse JSON config: {e}"))
            })
        }
    }

    /// Load TiDB Cloud configuration with environment overrides
    pub fn from_env() -> TiDBCloudResult<Self> {
        let mut config = TiDBCloudConfig::default();
        config.apply_environment_overrides();
        Ok(config)
    }

    /// Apply environment variable overrides
    pub fn apply_environment_overrides(&mut self) {
        // API configuration
        if let Ok(api_key) = std::env::var("TIDB_CLOUD_API_KEY") {
            self.api.api_key = Some(api_key);
        }
        if let Ok(base_url) = std::env::var("TIDB_CLOUD_BASE_URL") {
            self.api.base_url = base_url;
        }
        if let Ok(version) = std::env::var("TIDB_CLOUD_API_VERSION") {
            self.api.version = version;
        }

        // Client configuration
        if let Ok(timeout) = std::env::var("TIDB_CLOUD_TIMEOUT_SECS")
            && let Ok(timeout_secs) = timeout.parse()
        {
            self.client.timeout_secs = timeout_secs;
        }
        if let Ok(user_agent) = std::env::var("TIDB_CLOUD_USER_AGENT") {
            self.client.user_agent = user_agent;
        }
    }

    /// Get the full API URL
    pub fn get_api_url(&self) -> String {
        format!("{}/{}", self.api.base_url, self.api.version)
    }

    /// Get the API key with validation
    pub fn get_api_key(&self) -> TiDBCloudResult<String> {
        self.api.api_key.clone().ok_or_else(|| {
            TiDBCloudError::ConfigError(
                "TIDB_CLOUD_API_KEY must be provided via config or environment variable"
                    .to_string(),
            )
        })
    }

    /// Validate the configuration
    pub fn validate(&self) -> TiDBCloudResult<()> {
        // Validate API key if provided
        if let Some(api_key) = &self.api.api_key {
            if api_key.len() < self.security.min_api_key_length {
                return Err(TiDBCloudError::ConfigError(format!(
                    "API key too short: {} characters (minimum: {})",
                    api_key.len(),
                    self.security.min_api_key_length
                )));
            }
            if api_key.len() > self.security.max_api_key_length {
                return Err(TiDBCloudError::ConfigError(format!(
                    "API key too long: {} characters (maximum: {})",
                    api_key.len(),
                    self.security.max_api_key_length
                )));
            }
        }

        // Validate base URL
        if self.api.base_url.is_empty() {
            return Err(TiDBCloudError::ConfigError(
                "Base URL cannot be empty".to_string(),
            ));
        }

        // Validate timeout
        if self.client.timeout_secs == 0 {
            return Err(TiDBCloudError::ConfigError(
                "Timeout must be greater than 0".to_string(),
            ));
        }

        Ok(())
    }

    /// Get a debug logger configured from this config
    pub fn get_debug_logger(&self) -> crate::tidb_cloud::DebugLogger {
        crate::tidb_cloud::DebugLogger::new(self.debug.verbosity_level.into())
    }
}
