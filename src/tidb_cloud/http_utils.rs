use crate::tidb_cloud::error::{TiDBCloudError, TiDBCloudResult};
use crate::tidb_cloud::constants::*;
use crate::tidb_cloud::debug_logger::DebugLogger;
use crate::tidb_cloud::digest_auth::{DigestAuth, DigestSession};
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION, CONTENT_TYPE, USER_AGENT};
use std::time::Duration;
use url::Url;

/// Maximum request body size (10MB)
pub const MAX_REQUEST_SIZE: usize = DEFAULT_MAX_REQUEST_SIZE;

/// Maximum URL length (2048 characters)
pub const MAX_URL_LENGTH: usize = DEFAULT_MAX_URL_LENGTH;

/// Maximum query string length (1024 characters)
pub const MAX_QUERY_LENGTH: usize = DEFAULT_MAX_QUERY_LENGTH;

/// HTTP request builder with security validations
pub struct HttpRequestBuilder {
    base_url: String,
    _timeout: Duration,
    user_agent: String,
    debug_logger: Option<DebugLogger>,
}

impl HttpRequestBuilder {
    pub fn new(base_url: String, timeout: Duration, user_agent: String) -> Self {
        Self {
            base_url,
            _timeout: timeout,
            user_agent,
            debug_logger: None,
        }
    }

    pub fn with_debug_logger(mut self, debug_logger: DebugLogger) -> Self {
        self.debug_logger = Some(debug_logger);
        self
    }

    /// Validate and build a complete URL
    pub fn build_url(&self, path: &str, query: Option<&str>) -> TiDBCloudResult<String> {
        // Validate path
        self.validate_path(path)?;
        
        // Validate query string length
        if let Some(query) = query {
            if query.len() > MAX_QUERY_LENGTH {
                return Err(TiDBCloudError::ConfigError(
                    format!("Query string too long: {} characters (max: {})", query.len(), MAX_QUERY_LENGTH)
                ));
            }
        }

        // Build URL - if base_url already contains the path, don't append it
        let path_without_slash = path.trim_start_matches('/');
        
        // Debug logging to see what's happening
        if let Some(logger) = &self.debug_logger {
            logger.debug(&format!("URL construction - base_url: '{}', path: '{}', path_without_slash: '{}', base_url.ends_with(path_without_slash): {}", 
                self.base_url, path, path_without_slash, self.base_url.ends_with(path_without_slash)));
        }
        
        let url = if let Some(query) = query {
            if self.base_url.ends_with(path_without_slash) {
                format!("{}?{}", self.base_url, query)
            } else {
                format!("{}{}?{}", self.base_url, path, query)
            }
        } else {
            if self.base_url.ends_with(path_without_slash) {
                self.base_url.clone()
            } else {
                format!("{}{}", self.base_url, path)
            }
        };

        // Debug logging to see the exact URL being constructed
        if let Some(logger) = &self.debug_logger {
            logger.debug(&format!("Building URL - base_url: '{}', path: '{}', final_url: '{}'", self.base_url, path, url));
        }

        // Validate final URL
        self.validate_url(&url)?;

        Ok(url)
    }

    /// Validate URL format and security
    pub fn validate_url(&self, url: &str) -> TiDBCloudResult<()> {
        if let Some(logger) = &self.debug_logger {
            logger.debug(&format!("Validating URL: {}", url));
        }

        // Check URL length
        if url.len() > MAX_URL_LENGTH {
            if let Some(logger) = &self.debug_logger {
                logger.error(&format!("URL too long: {} characters (max: {})", url.len(), MAX_URL_LENGTH));
            }
            return Err(TiDBCloudError::ConfigError(
                format!("URL too long: {} characters (max: {})", url.len(), MAX_URL_LENGTH)
            ));
        }

        // Parse and validate URL
        let parsed_url = Url::parse(url)
            .map_err(|e| {
                if let Some(logger) = &self.debug_logger {
                    logger.error(&format!("Invalid URL: {}", e));
                }
                TiDBCloudError::ConfigError(format!("Invalid URL: {}", e))
            })?;

        // Ensure HTTPS for production URLs
        if parsed_url.scheme() != "https" && self.base_url.contains("cloud.tidbapi.com") {
            if let Some(logger) = &self.debug_logger {
                logger.warning("HTTPS is required for TiDB Cloud API requests");
            }
            return Err(TiDBCloudError::ConfigError(
                "HTTPS is required for TiDB Cloud API requests".to_string()
            ));
        }

        // Validate hostname
        if let Some(host) = parsed_url.host_str() {
            if !self.is_valid_hostname(host) {
                if let Some(logger) = &self.debug_logger {
                    logger.error(&format!("Invalid hostname: {}", host));
                }
                return Err(TiDBCloudError::ConfigError(
                    format!("Invalid hostname: {}", host)
                ));
            }
        }

        if let Some(logger) = &self.debug_logger {
            logger.debug("URL validation passed");
        }

        Ok(())
    }

    /// Validate path for security
    pub fn validate_path(&self, path: &str) -> TiDBCloudResult<()> {
        // Check for path traversal attempts
        if path.contains("..") || path.contains("//") {
            return Err(TiDBCloudError::ConfigError(
                "Path traversal detected in URL path".to_string()
            ));
        }

        // Check for suspicious characters
        let suspicious_chars = ['<', '>', '"', '\'', '&', '|', ';', '`', '$', '(', ')'];
        if path.chars().any(|c| suspicious_chars.contains(&c)) {
            return Err(TiDBCloudError::ConfigError(
                "Suspicious characters detected in URL path".to_string()
            ));
        }

        Ok(())
    }

    /// Validate hostname
    fn is_valid_hostname(&self, hostname: &str) -> bool {
        // Allow localhost for testing
        if hostname == "localhost" || hostname.starts_with("127.0.0.1") {
            return true;
        }

        // Validate TiDB Cloud domains
        ALLOWED_HOSTNAMES.iter().any(|domain| hostname == *domain || hostname.ends_with(domain))
    }

    /// Create headers with security considerations
    pub fn create_headers(&self, api_key: &str) -> TiDBCloudResult<HeaderMap> {
        let mut headers = HeaderMap::new();
        
        // Validate API key format
        if api_key.len() < DEFAULT_MIN_API_KEY_LENGTH || api_key.len() > DEFAULT_MAX_API_KEY_LENGTH {
            return Err(TiDBCloudError::ConfigError(
                format!("API key length must be between {} and {} characters", 
                    DEFAULT_MIN_API_KEY_LENGTH, DEFAULT_MAX_API_KEY_LENGTH)
            ));
        }

        // Check for suspicious patterns in API key
        if api_key.contains("..") || api_key.contains("//") {
            return Err(TiDBCloudError::ConfigError(
                "Suspicious patterns detected in API key".to_string()
            ));
        }

        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {}", api_key))
                .map_err(|e| TiDBCloudError::ConfigError(format!("Invalid API key format: {}", e)))?,
        );
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        headers.insert(USER_AGENT, HeaderValue::from_str(&self.user_agent)
            .map_err(|e| TiDBCloudError::ConfigError(format!("Invalid user agent: {}", e)))?);

        Ok(headers)
    }

    /// Create headers for digest authentication (no API key validation)
    pub fn create_digest_headers(&self, _password: &str) -> TiDBCloudResult<HeaderMap> {
        let mut headers = HeaderMap::new();
        
        // For digest auth, we don't set Authorization header initially
        // It will be set during the digest authentication process
        
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        headers.insert(USER_AGENT, HeaderValue::from_str(&self.user_agent)
            .map_err(|e| TiDBCloudError::ConfigError(format!("Invalid user agent: {}", e)))?);

        Ok(headers)
    }

    /// Validate request body size
    pub fn validate_request_size(&self, body: &str) -> TiDBCloudResult<()> {
        if body.len() > MAX_REQUEST_SIZE {
            return Err(TiDBCloudError::ConfigError(
                format!("Request body too large: {} bytes (max: {} bytes)", 
                    body.len(), MAX_REQUEST_SIZE)
            ));
        }
        Ok(())
    }

    /// Sanitize query parameters
    pub fn sanitize_query_params(&self, params: &impl serde::Serialize) -> TiDBCloudResult<String> {
        let query = serde_urlencoded::to_string(params)
            .map_err(|e| TiDBCloudError::SerializationError(format!("Failed to serialize query: {}", e)))?;
        
        // Validate query string length
        if query.len() > MAX_QUERY_LENGTH {
            return Err(TiDBCloudError::ConfigError(
                format!("Query string too long: {} characters (max: {})", query.len(), MAX_QUERY_LENGTH)
            ));
        }

        Ok(query)
    }
}

/// Common HTTP methods with security validations
#[allow(dead_code)]
pub struct HttpMethods {
    builder: HttpRequestBuilder,
    pub(crate) client: reqwest::Client,
    api_key: String, // Store API key for logging purposes
    username: String, // Store username for digest authentication
    digest_session: Option<DigestSession>, // For digest authentication
}

impl HttpMethods {
    pub fn new(builder: HttpRequestBuilder, client: reqwest::Client, api_key: String) -> Self {
        Self { 
            builder, 
            client, 
            api_key,
            username: "tidb_cloud_user".to_string(), // Default username for API key auth
            digest_session: None,
        }
    }

    pub fn new_with_credentials(builder: HttpRequestBuilder, client: reqwest::Client, username: String, password: String) -> Self {
        Self { 
            builder, 
            client, 
            api_key: password, // Store password as api_key
            username, // Store the actual username
            digest_session: None,
        }
    }

    /// Make a GET request with security validations
    pub async fn get<T>(&self, path: &str, query: Option<&str>) -> TiDBCloudResult<T>
    where
        T: for<'de> serde::Deserialize<'de>,
    {
        let url = self.builder.build_url(path, query)?;
        
        // First attempt without authentication
        let response = self.client.get(&url).send().await?;
        
        // Check if we need authentication
        if response.status() == reqwest::StatusCode::UNAUTHORIZED {
            // Log all response headers for debugging
            if let Some(logger) = &self.builder.debug_logger {
                logger.info("=== RESPONSE HEADERS (401 Unauthorized) ===");
                for (name, value) in response.headers() {
                    if let Ok(value_str) = value.to_str() {
                        logger.info(&format!("{}: {}", name, value_str));
                    }
                }
                logger.info("==========================================");
            }
            
            // Test and log available authorization methods
            self.test_available_auth_methods(&response).await?;
            
            if let Some(www_authenticate) = response.headers().get("www-authenticate") {
                if let Ok(www_auth_str) = www_authenticate.to_str() {
                    if www_auth_str.starts_with("Digest") {
                        if let Some(logger) = &self.builder.debug_logger {
                            logger.info("=== TRIGGERING DIGEST AUTHENTICATION ===");
                        }
                        return self.handle_digest_auth("GET", &url, query).await;
                    }
                }
            }
            
            // If we get here, it's a 401 but not digest auth, so return the error
            return self.handle_response(response).await;
        }
        
        // Log the API query with actual headers
        if let Some(logger) = &self.builder.debug_logger {
            // Log the actual headers that will be sent (using info level to ensure visibility)
            logger.info("=== ACTUAL HTTP REQUEST HEADERS ===");
            logger.info(&format!("Method: GET"));
            logger.info(&format!("URL: {}", url));
            logger.info("Headers that will be sent:");
            
            // Show the actual API key (masked for security) - now using digest auth
            let masked_api_key = if self.api_key.len() > 8 {
                format!("Digest username=api_user, realm=***, nonce=***, response=***")
            } else {
                "Digest ***SHORT_KEY***".to_string()
            };
            logger.info(&format!("Authorization: {}", masked_api_key));
            logger.info("Content-Type: application/json");
            logger.info("User-Agent: tidb-cloud-rust-client/1.0.0");
            logger.info("Accept: application/json");
            logger.info("===================================");
            
            // Also log with the existing method for compatibility
            let headers_str = self.format_headers_for_logging();
            logger.log_api_query_with_headers("GET", &url, Some(&headers_str), None);
        }
        
        self.handle_response(response).await
    }

    /// Handle digest authentication
    async fn handle_digest_auth<T>(&self, method: &str, url: &str, _query: Option<&str>) -> TiDBCloudResult<T>
    where
        T: for<'de> serde::Deserialize<'de>,
    {
        if let Some(logger) = &self.builder.debug_logger {
            logger.info("=== DIGEST AUTHENTICATION STARTED ===");
        }
        
        // Create digest auth configuration
        let digest_auth = DigestAuth::new(self.username.clone(), self.api_key.clone());
        
        // First request to get the challenge
        let response = self.client.get(url).send().await?;
        
        if let Some(www_authenticate) = response.headers().get("www-authenticate") {
            if let Ok(www_auth_str) = www_authenticate.to_str() {
                if let Some(logger) = &self.builder.debug_logger {
                    logger.info(&format!("WWW-Authenticate: {}", www_auth_str));
                }
                
                // Extract the request-URI from the full URL for digest authentication
                // According to RFC 2617, the uri parameter should be the request-URI (path + query)
                let request_uri = if let Ok(parsed_url) = url::Url::parse(url) {
                    // Get the path and query part
                    let path = parsed_url.path();
                    let query = parsed_url.query();
                    if let Some(query) = query {
                        format!("{}?{}", path, query)
                    } else {
                        path.to_string()
                    }
                } else {
                    // Fallback: try to extract path from URL string
                    if let Some(path_start) = url.find("://") {
                        if let Some(path_part) = url[path_start..].find('/') {
                            url[path_start + path_part..].to_string()
                        } else {
                            "/".to_string()
                        }
                    } else {
                        url.to_string()
                    }
                };
                
                // Use the convenience method to handle the entire authentication flow
                let auth_header = digest_auth.authenticate(www_auth_str, method, &request_uri)?;
                
                if let Some(logger) = &self.builder.debug_logger {
                    logger.info(&format!("Generated Authorization: {}", auth_header));
                }
                
                // Log the authenticated request headers
                if let Some(logger) = &self.builder.debug_logger {
                    logger.info("=== AUTHENTICATED HTTP REQUEST HEADERS ===");
                    logger.info(&format!("Method: {}", method));
                    logger.info(&format!("URL: {}", url));
                    logger.info("Headers that will be sent:");
                    logger.info(&format!("Authorization: {}", auth_header));
                    logger.info("Content-Type: application/json");
                    logger.info("User-Agent: tidb-cloud-rust-client/1.0.0");
                    logger.info("Accept: application/json");
                    logger.info("===================================");
                }
                
                // Make the authenticated request
                let response = self.client
                    .get(url)
                    .header("Authorization", auth_header)
                    .send()
                    .await?;
                
                if let Some(logger) = &self.builder.debug_logger {
                    logger.info(&format!("Authenticated response status: {}", response.status()));
                }
                
                return self.handle_response(response).await;
            }
        }
        
        Err(TiDBCloudError::AuthError("Failed to handle digest authentication".to_string()))
    }

    /// Test and log available authorization methods
    async fn test_available_auth_methods(&self, response: &reqwest::Response) -> TiDBCloudResult<()> {
        if let Some(logger) = &self.builder.debug_logger {
            logger.info("=== TESTING AVAILABLE AUTHORIZATION METHODS ===");
            
            // Test different authorization methods
            let auth_methods = vec![
                ("Bearer", format!("Bearer {}", self.api_key)),
                ("Basic", format!("Basic {}", format!("user:{}", self.api_key))),
                ("API-Key", format!("API-Key {}", self.api_key)),
                ("X-API-Key", format!("X-API-Key {}", self.api_key)),
                ("Authorization", self.api_key.clone()),
            ];
            
            for (method_name, auth_header) in auth_methods {
                logger.info(&format!("Testing {} authentication...", method_name));
                
                // Get the URL from the original request
                let url = response.url().clone();
                
                // Try the authentication method
                let test_response = match method_name {
                    "Bearer" => {
                        self.client.get(url.clone())
                            .header("Authorization", auth_header)
                            .send()
                            .await
                    }
                    "Basic" => {
                        self.client.get(url.clone())
                            .header("Authorization", auth_header)
                            .send()
                            .await
                    }
                    "API-Key" => {
                        self.client.get(url.clone())
                            .header("Authorization", auth_header)
                            .send()
                            .await
                    }
                    "X-API-Key" => {
                        self.client.get(url.clone())
                            .header("X-API-Key", &self.api_key)
                            .send()
                            .await
                    }
                    "Authorization" => {
                        self.client.get(url.clone())
                            .header("Authorization", auth_header)
                            .send()
                            .await
                    }
                    _ => continue,
                };
                
                match test_response {
                    Ok(resp) => {
                        let status = resp.status();
                        logger.info(&format!("  {} auth result: {} {}", method_name, status.as_u16(), status.canonical_reason().unwrap_or("Unknown")));
                        
                        // Log response headers for successful or interesting responses
                        if status.is_success() {
                            logger.info(&format!("  ✅ {} authentication SUCCESSFUL!", method_name));
                            for (name, value) in resp.headers() {
                                if let Ok(value_str) = value.to_str() {
                                    logger.info(&format!("    {}: {}", name, value_str));
                                }
                            }
                        } else if status == reqwest::StatusCode::UNAUTHORIZED {
                            if let Some(www_auth) = resp.headers().get("www-authenticate") {
                                if let Ok(www_auth_str) = www_auth.to_str() {
                                    logger.info(&format!("    WWW-Authenticate: {}", www_auth_str));
                                }
                            }
                        }
                    }
                    Err(e) => {
                        logger.info(&format!("  ❌ {} auth failed: {}", method_name, e));
                    }
                }
            }
            
            logger.info("=== END AUTHORIZATION METHOD TESTING ===");
        }
        
        Ok(())
    }

    /// Make a POST request with security validations
    pub async fn post<T, B>(&self, path: &str, body: Option<&B>) -> TiDBCloudResult<T>
    where
        T: for<'de> serde::Deserialize<'de>,
        B: serde::Serialize,
    {
        let url = self.builder.build_url(path, None)?;
        let mut request = self.client.post(&url);

        let body_str = if let Some(body) = body {
            // Validate body size by serializing it first
            let body_str = serde_json::to_string_pretty(body)
                .map_err(|e| TiDBCloudError::SerializationError(format!("Failed to serialize body: {}", e)))?;
            self.builder.validate_request_size(&body_str)?;
            request = request.json(body);
            Some(body_str)
        } else {
            None
        };

        // Log the API query with headers and full JSON body at TRACE level
        if let Some(logger) = &self.builder.debug_logger {
            let headers_str = self.format_headers_for_logging();
            logger.log_api_query_with_headers("POST", &url, Some(&headers_str), body_str.as_deref());
            
            // Additional TRACE level logging for JSON body
            if let Some(body_str) = &body_str {
                logger.trace("=== FULL JSON REQUEST BODY ===");
                logger.trace(body_str);
                logger.trace("=============================");
            }
        }

        let response = request.send().await?;
        self.handle_response(response).await
    }

    /// Make a PATCH request with security validations
    pub async fn patch<T, B>(&self, path: &str, body: &B) -> TiDBCloudResult<T>
    where
        T: for<'de> serde::Deserialize<'de>,
        B: serde::Serialize,
    {
        let url = self.builder.build_url(path, None)?;
        
        // Validate body size and serialize with pretty formatting
        let body_str = serde_json::to_string_pretty(body)
            .map_err(|e| TiDBCloudError::SerializationError(format!("Failed to serialize body: {}", e)))?;
        self.builder.validate_request_size(&body_str)?;
        
        // Log the API query with headers and full JSON body at TRACE level
        if let Some(logger) = &self.builder.debug_logger {
            let headers_str = self.format_headers_for_logging();
            logger.log_api_query_with_headers("PATCH", &url, Some(&headers_str), Some(&body_str));
            
            // Additional TRACE level logging for JSON body
            logger.trace("=== FULL JSON REQUEST BODY ===");
            logger.trace(&body_str);
            logger.trace("=============================");
        }
        
        let response = self.client.patch(&url).json(body).send().await?;
        self.handle_response(response).await
    }

    /// Make a DELETE request with security validations
    pub async fn delete<T>(&self, path: &str, query: Option<&str>) -> TiDBCloudResult<T>
    where
        T: for<'de> serde::Deserialize<'de>,
    {
        let url = self.builder.build_url(path, query)?;
        
        // Log the API query with headers
        if let Some(logger) = &self.builder.debug_logger {
            let headers_str = self.format_headers_for_logging();
            logger.log_api_query_with_headers("DELETE", &url, Some(&headers_str), None);
        }
        
        let response = self.client.delete(&url).send().await?;
        self.handle_response(response).await
    }

    /// Format headers for logging (with API key masked)
    fn format_headers_for_logging(&self) -> String {
        let mut headers = Vec::new();
        
        // Since we can't directly access the default headers from reqwest::Client,
        // we'll log the headers that we know are being set during client creation
        // These are the headers that are actually sent with each request
        
        // Get the API key from the builder to show it (masked)
        if let Some(logger) = &self.builder.debug_logger {
            logger.debug("Logging actual request headers that will be sent:");
        }
        
        // These are the headers that are actually set in create_headers() method
        headers.push("Authorization: Digest ***API_KEY_PRESENT***".to_string());
        headers.push("Content-Type: application/json".to_string());
        headers.push("User-Agent: tidb-cloud-rust-client/1.0.0".to_string());
        
        headers.join("\n")
    }

    /// Handle HTTP response with enhanced error handling
    pub(crate) async fn handle_response<T>(&self, response: reqwest::Response) -> TiDBCloudResult<T>
    where
        T: for<'de> serde::Deserialize<'de>,
    {
        let status = response.status();
        let headers = response.headers().clone();
        
        // Log response status and headers
        if let Some(logger) = &self.builder.debug_logger {
            logger.debug(&format!("API Response Status: {}", status));
            
            // Log response headers
            logger.info(&format!("=== RESPONSE HEADERS ({} {}) ===", status.as_u16(), status.canonical_reason().unwrap_or("Unknown")));
            for (name, value) in &headers {
                if let Ok(value_str) = value.to_str() {
                    logger.info(&format!("{}: {}", name, value_str));
                }
            }
            logger.info("==========================================");
        }

        // Read response body BEFORE checking error status codes
        let text = response.text().await?;

        // Log response body with enhanced TRACE level logging
        if let Some(logger) = &self.builder.debug_logger {
            logger.log_response(status.as_u16(), None, Some(&text));
            
            // Additional TRACE level logging for full JSON response body
            if !text.is_empty() {
                logger.trace("=== FULL JSON RESPONSE BODY ===");
                logger.trace(&text);
                logger.trace("==============================");
            }
        }

        // Check for rate limiting
        if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
            let retry_after = headers
                .get("retry-after")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.parse::<u64>().ok());

            return Err(TiDBCloudError::RateLimitError {
                retry_after,
                message: "Rate limit exceeded".to_string(),
            });
        }

        // Check for authentication errors
        if status == reqwest::StatusCode::UNAUTHORIZED {
            return Err(TiDBCloudError::AuthError("Invalid API key".to_string()));
        }

        // Check for forbidden errors
        if status == reqwest::StatusCode::FORBIDDEN {
            return Err(TiDBCloudError::AuthError("Insufficient permissions".to_string()));
        }

        // Check for not found errors
        if status == reqwest::StatusCode::NOT_FOUND {
            return Err(TiDBCloudError::NotFound("Resource not found".to_string()));
        }

        // Check for server errors
        if status.is_server_error() {
            return Err(TiDBCloudError::HttpError {
                status: status.as_u16(),
                message: format!("Server error: {}", status),
            });
        }

        // Validate response size
        if text.len() > MAX_REQUEST_SIZE {
            return Err(TiDBCloudError::SerializationError(
                format!("Response too large: {} bytes (max: {} bytes)", text.len(), MAX_REQUEST_SIZE)
            ));
        }

        // Try to parse as JSON first
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&text) {
            // Check if it's an error response
            if let Some(error) = json.get("error") {
                let code = error.get("code").and_then(|v| v.as_i64()).unwrap_or(0) as i32;
                let message = error
                    .get("message")
                    .and_then(|v| v.as_str())
                    .unwrap_or("Unknown error")
                    .to_string();
                let details = error.get("details").and_then(|v| v.as_array()).cloned();

                return Err(TiDBCloudError::ApiError {
                    code,
                    message,
                    details: details.map(|d| d.into_iter().collect()),
                });
            }

            // Try to deserialize as the expected type
            match serde_json::from_value::<T>(json) {
                Ok(result) => Ok(result),
                Err(e) => Err(TiDBCloudError::SerializationError(format!(
                    "Failed to deserialize response: {}",
                    e
                ))),
            }
        } else {
            // If not JSON, check if it's a successful response
            if status.is_success() {
                Err(TiDBCloudError::SerializationError(
                    "Expected JSON response but got non-JSON".to_string(),
                ))
            } else {
                Err(TiDBCloudError::HttpError {
                    status: status.as_u16(),
                    message: text,
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_url_validation() {
        let builder = HttpRequestBuilder::new(
            PRODUCTION_API_URL.to_string(),
            Duration::from_secs(30),
            "test-agent".to_string(),
        );

        // Valid URLs
        assert!(builder.validate_url(&format!("{}/tidbs", PRODUCTION_API_URL)).is_ok());
        assert!(builder.validate_url("https://api.tidbcloud.com/v1beta2/tidbs").is_ok());

        // Invalid URLs
        assert!(builder.validate_url("http://cloud.tidbapi.com/v1beta2/tidbs").is_err()); // HTTP not allowed
        assert!(builder.validate_url("https://malicious.com/v1beta2/tidbs").is_err()); // Invalid domain
    }

    #[test]
    fn test_path_validation() {
        let builder = HttpRequestBuilder::new(
            PRODUCTION_API_URL.to_string(),
            Duration::from_secs(30),
            "test-agent".to_string(),
        );

        // Valid paths
        assert!(builder.validate_path("/tidbs").is_ok());
        assert!(builder.validate_path("/tidbs/123").is_ok());

        // Invalid paths
        assert!(builder.validate_path("/tidbs/../etc/passwd").is_err()); // Path traversal
        assert!(builder.validate_path("/tidbs//123").is_err()); // Double slash
        assert!(builder.validate_path("/tidbs/<script>").is_err()); // Suspicious characters
    }

    #[test]
    fn test_request_size_validation() {
        let builder = HttpRequestBuilder::new(
            PRODUCTION_API_URL.to_string(),
            Duration::from_secs(30),
            "test-agent".to_string(),
        );

        // Valid size
        let small_body = "a".repeat(1000);
        assert!(builder.validate_request_size(&small_body).is_ok());

        // Invalid size
        let large_body = "a".repeat(MAX_REQUEST_SIZE + 1);
        assert!(builder.validate_request_size(&large_body).is_err());
    }

    #[test]
    fn test_hostname_validation() {
        let builder = HttpRequestBuilder::new(
            PRODUCTION_API_URL.to_string(),
            Duration::from_secs(30),
            "test-agent".to_string(),
        );

        // Valid hostnames
        assert!(builder.is_valid_hostname("cloud.tidbapi.com"));
        assert!(builder.is_valid_hostname("api.tidbcloud.com"));
        assert!(builder.is_valid_hostname("localhost"));
        assert!(builder.is_valid_hostname("127.0.0.1"));

        // Invalid hostnames
        assert!(!builder.is_valid_hostname("malicious.com"));
        assert!(!builder.is_valid_hostname("evil.tidbapi.com.evil.com"));
    }
} 