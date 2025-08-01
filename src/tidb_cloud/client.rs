use crate::tidb_cloud::{
    error::{TiDBCloudError, TiDBCloudResult},
    http_utils::{HttpMethods, HttpRequestBuilder},
    config::TiDBCloudConfig,
    debug_logger::DebugLogger,
    API_BASE_URL, DEFAULT_TIMEOUT, DEFAULT_USER_AGENT,
};
use reqwest::Client;
use std::time::Duration;

/// TiDB Cloud API client
pub struct TiDBCloudClient {
    pub(crate) http_methods: HttpMethods,
    pub(crate) base_url: String,
    api_key: String,
    debug_logger: DebugLogger,
}

impl TiDBCloudClient {
    /// Create a new TiDB Cloud client
    pub fn new(api_key: String) -> TiDBCloudResult<Self> {
        Self::with_config(api_key, API_BASE_URL.to_string(), DEFAULT_TIMEOUT, DebugLogger::default())
    }

    /// Create a new TiDB Cloud client with username and password
    pub fn with_credentials(username: String, password: String) -> TiDBCloudResult<Self> {
        Self::with_config_and_credentials(username, password, API_BASE_URL.to_string(), DEFAULT_TIMEOUT, DebugLogger::default())
    }

    /// Create a new TiDB Cloud client from configuration
    pub fn from_config(config: &TiDBCloudConfig) -> TiDBCloudResult<Self> {
        let api_key = config.get_api_key()?;
        let base_url = config.get_api_url();
        let timeout = Duration::from_secs(config.client.timeout_secs);
        let debug_logger = config.get_debug_logger();
        
        Self::with_config(api_key, base_url, timeout, debug_logger)
    }

    /// Create a new TiDB Cloud client with custom configuration
    pub fn with_config(
        api_key: String,
        base_url: String,
        timeout: Duration,
        debug_logger: DebugLogger,
    ) -> TiDBCloudResult<Self> {
        if api_key.trim().is_empty() {
            return Err(TiDBCloudError::ConfigError("API key cannot be empty".to_string()));
        }

        debug_logger.info(&format!("Creating TiDB Cloud client with base URL: {}", base_url));
        debug_logger.debug(&format!("API key length: {} characters", api_key.len()));

        // Create HTTP request builder with security validations
        let builder = HttpRequestBuilder::new(
            base_url.clone(),
            timeout,
            DEFAULT_USER_AGENT.to_string(),
        ).with_debug_logger(debug_logger.clone());

        // Create headers with security validations
        let headers = builder.create_headers(&api_key)?;
        debug_logger.debug("HTTP headers created successfully");

        // Create HTTP client
        let client = Client::builder()
            .timeout(timeout)
            .default_headers(headers)
            .build()
            .map_err(|e| {
                debug_logger.error(&format!("Failed to create HTTP client: {}", e));
                TiDBCloudError::ConfigError(format!("Failed to create HTTP client: {}", e))
            })?;

        debug_logger.info("HTTP client created successfully");

        // Create HTTP methods wrapper
        let http_methods = HttpMethods::new(builder, client, api_key.clone());

        Ok(Self {
            http_methods,
            base_url,
            api_key,
            debug_logger,
        })
    }

    /// Create a new TiDB Cloud client with username and password configuration
    pub fn with_config_and_credentials(
        username: String,
        password: String,
        base_url: String,
        timeout: Duration,
        debug_logger: DebugLogger,
    ) -> TiDBCloudResult<Self> {
        if password.trim().is_empty() {
            return Err(TiDBCloudError::ConfigError("Password cannot be empty".to_string()));
        }

        debug_logger.info(&format!("Creating TiDB Cloud client with username '{}' and base URL: {}", username, base_url));
        debug_logger.debug(&format!("Password length: {} characters", password.len()));

        // Create HTTP request builder with security validations
        let builder = HttpRequestBuilder::new(
            base_url.clone(),
            timeout,
            DEFAULT_USER_AGENT.to_string(),
        ).with_debug_logger(debug_logger.clone());

        // Create headers for digest authentication (no API key validation)
        let headers = builder.create_digest_headers(&password)?;
        debug_logger.debug("HTTP headers created successfully");

        // Create HTTP client
        let client = Client::builder()
            .timeout(timeout)
            .default_headers(headers)
            .build()
            .map_err(|e| {
                debug_logger.error(&format!("Failed to create HTTP client: {}", e));
                TiDBCloudError::ConfigError(format!("Failed to create HTTP client: {}", e))
            })?;

        debug_logger.info("HTTP client created successfully");

        // Create HTTP methods wrapper with username and password
        let http_methods = HttpMethods::new_with_credentials(builder, client, username, password.clone());

        Ok(Self {
            http_methods,
            base_url,
            api_key: password, // Store password as api_key for backward compatibility
            debug_logger,
        })
    }

    /// Get the API key (for debugging purposes)
    pub fn api_key(&self) -> &str {
        &self.api_key
    }

    /// Get the base URL
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Get the debug logger
    pub fn debug_logger(&self) -> &DebugLogger {
        &self.debug_logger
    }

    /// Make a GET request with security validations
    pub(crate) async fn get<T>(&self, path: &str, query: Option<&str>) -> TiDBCloudResult<T>
    where
        T: for<'de> serde::Deserialize<'de>,
    {
        self.http_methods.get(path, query).await
    }

    /// Make a POST request with security validations
    pub(crate) async fn post<T, B>(&self, path: &str, body: Option<&B>) -> TiDBCloudResult<T>
    where
        T: for<'de> serde::Deserialize<'de>,
        B: serde::Serialize,
    {
        self.http_methods.post(path, body).await
    }

    /// Make a PATCH request with security validations
    pub(crate) async fn patch<T, B>(&self, path: &str, body: &B) -> TiDBCloudResult<T>
    where
        T: for<'de> serde::Deserialize<'de>,
        B: serde::Serialize,
    {
        self.http_methods.patch(path, body).await
    }

    /// Make a DELETE request with security validations
    pub(crate) async fn delete<T>(&self, path: &str, query: Option<&str>) -> TiDBCloudResult<T>
    where
        T: for<'de> serde::Deserialize<'de>,
    {
        self.http_methods.delete(path, query).await
    }

    /// Build query string from parameters with security validations
    pub(crate) fn build_query_string(&self, params: &impl serde::Serialize) -> TiDBCloudResult<String> {
        // Use the HTTP request builder to sanitize query parameters
        let builder = HttpRequestBuilder::new(
            self.base_url.clone(),
            std::time::Duration::from_secs(30),
            DEFAULT_USER_AGENT.to_string(),
        );
        builder.sanitize_query_params(params)
    }
}

impl std::fmt::Debug for TiDBCloudClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TiDBCloudClient")
            .field("base_url", &self.base_url)
            .field("api_key", &"***")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_creation() {
        let client = TiDBCloudClient::new("test-api-key-that-is-long-enough-for-validation".to_string());
        assert!(client.is_ok());
    }

    #[test]
    fn test_client_creation_with_empty_api_key() {
        let client = TiDBCloudClient::new("".to_string());
        assert!(client.is_err());
        match client.unwrap_err() {
            TiDBCloudError::ConfigError(_) => {}
            _ => panic!("Expected ConfigError"),
        }
    }

    #[test]
    fn test_client_debug() {
        let client = TiDBCloudClient::new("test-api-key-that-is-long-enough-for-validation".to_string()).unwrap();
        let debug_str = format!("{:?}", client);
        assert!(debug_str.contains("TiDBCloudClient"));
        assert!(debug_str.contains("***")); // API key should be masked
    }
} 