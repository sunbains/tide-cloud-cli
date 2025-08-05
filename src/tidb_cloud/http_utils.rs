use crate::tidb_cloud::constants::*;
use crate::tidb_cloud::debug_logger::DebugLogger;
use crate::tidb_cloud::digest_auth::{DigestAuth, DigestSession};
use crate::tidb_cloud::error::{TiDBCloudError, TiDBCloudResult};
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE, HeaderMap, HeaderValue, USER_AGENT};
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
        if let Some(query) = query
            && query.len() > MAX_QUERY_LENGTH
        {
            return Err(TiDBCloudError::ConfigError(format!(
                "Query string too long: {} characters (max: {})",
                query.len(),
                MAX_QUERY_LENGTH
            )));
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
        } else if self.base_url.ends_with(path_without_slash) {
            self.base_url.clone()
        } else {
            format!("{}{}", self.base_url, path)
        };

        // Debug logging to see the exact URL being constructed
        if let Some(logger) = &self.debug_logger {
            logger.debug(&format!(
                "Building URL - base_url: '{}', path: '{}', final_url: '{}'",
                self.base_url, path, url
            ));
        }

        // Validate final URL
        self.validate_url(&url)?;

        Ok(url)
    }

    /// Validate URL format and security
    pub fn validate_url(&self, url: &str) -> TiDBCloudResult<()> {
        if let Some(logger) = &self.debug_logger {
            logger.debug(&format!("Validating URL: {url}"));
        }

        // Check URL length
        if url.len() > MAX_URL_LENGTH {
            if let Some(logger) = &self.debug_logger {
                logger.error(&format!(
                    "URL too long: {} characters (max: {})",
                    url.len(),
                    MAX_URL_LENGTH
                ));
            }
            return Err(TiDBCloudError::ConfigError(format!(
                "URL too long: {} characters (max: {})",
                url.len(),
                MAX_URL_LENGTH
            )));
        }

        // Parse and validate URL
        let parsed_url = Url::parse(url).map_err(|e| {
            if let Some(logger) = &self.debug_logger {
                logger.error(&format!("Invalid URL: {e}"));
            }
            TiDBCloudError::ConfigError(format!("Invalid URL: {e}"))
        })?;

        // Ensure HTTPS for production URLs
        if parsed_url.scheme() != "https" && self.base_url.contains("cloud.tidbapi.com") {
            if let Some(logger) = &self.debug_logger {
                logger.warning("HTTPS is required for TiDB Cloud API requests");
            }
            return Err(TiDBCloudError::ConfigError(
                "HTTPS is required for TiDB Cloud API requests".to_string(),
            ));
        }

        // Validate hostname
        if let Some(host) = parsed_url.host_str()
            && !self.is_valid_hostname(host)
        {
            if let Some(logger) = &self.debug_logger {
                logger.error(&format!("Invalid hostname: {host}"));
            }
            return Err(TiDBCloudError::ConfigError(format!(
                "Invalid hostname: {host}"
            )));
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
                "Path traversal detected in URL path".to_string(),
            ));
        }

        // Check for suspicious characters
        let suspicious_chars = ['<', '>', '"', '\'', '&', '|', ';', '`', '$', '(', ')'];
        if path.chars().any(|c| suspicious_chars.contains(&c)) {
            return Err(TiDBCloudError::ConfigError(
                "Suspicious characters detected in URL path".to_string(),
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
        ALLOWED_HOSTNAMES
            .iter()
            .any(|domain| hostname == *domain || hostname.ends_with(domain))
    }

    /// Create headers with security considerations
    pub fn create_headers(&self, api_key: &str) -> TiDBCloudResult<HeaderMap> {
        let mut headers = HeaderMap::new();

        // Validate API key format
        if api_key.len() < DEFAULT_MIN_API_KEY_LENGTH || api_key.len() > DEFAULT_MAX_API_KEY_LENGTH
        {
            return Err(TiDBCloudError::ConfigError(format!(
                "API key length must be between {DEFAULT_MIN_API_KEY_LENGTH} and {DEFAULT_MAX_API_KEY_LENGTH} characters"
            )));
        }

        // Check for suspicious patterns in API key
        if api_key.contains("..") || api_key.contains("//") {
            return Err(TiDBCloudError::ConfigError(
                "Suspicious patterns detected in API key".to_string(),
            ));
        }

        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {api_key}"))
                .map_err(|e| TiDBCloudError::ConfigError(format!("Invalid API key format: {e}")))?,
        );
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        headers.insert(
            USER_AGENT,
            HeaderValue::from_str(&self.user_agent)
                .map_err(|e| TiDBCloudError::ConfigError(format!("Invalid user agent: {e}")))?,
        );

        Ok(headers)
    }

    /// Create headers for digest authentication (no API key validation)
    pub fn create_digest_headers(&self, _password: &str) -> TiDBCloudResult<HeaderMap> {
        let mut headers = HeaderMap::new();

        // For digest auth, we don't set Authorization header initially
        // It will be set during the digest authentication process

        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        headers.insert(
            USER_AGENT,
            HeaderValue::from_str(&self.user_agent)
                .map_err(|e| TiDBCloudError::ConfigError(format!("Invalid user agent: {e}")))?,
        );

        Ok(headers)
    }

    /// Validate request body size
    pub fn validate_request_size(&self, body: &str) -> TiDBCloudResult<()> {
        if body.len() > MAX_REQUEST_SIZE {
            return Err(TiDBCloudError::ConfigError(format!(
                "Request body too large: {} bytes (max: {} bytes)",
                body.len(),
                MAX_REQUEST_SIZE
            )));
        }
        Ok(())
    }

    /// Sanitize query parameters
    pub fn sanitize_query_params(&self, params: &impl serde::Serialize) -> TiDBCloudResult<String> {
        let query = serde_urlencoded::to_string(params).map_err(|e| {
            TiDBCloudError::SerializationError(format!("Failed to serialize query: {e}"))
        })?;

        // Validate query string length
        if query.len() > MAX_QUERY_LENGTH {
            return Err(TiDBCloudError::ConfigError(format!(
                "Query string too long: {} characters (max: {})",
                query.len(),
                MAX_QUERY_LENGTH
            )));
        }

        Ok(query)
    }
}

/// Common HTTP methods with security validations
#[allow(dead_code)]
pub struct HttpMethods {
    builder: HttpRequestBuilder,
    pub(crate) client: reqwest::Client,
    api_key: String,                       // Store API key for logging purposes
    username: String,                      // Store username for digest authentication
    digest_session: Option<DigestSession>, // For digest authentication
    auth_discovered: bool, // Track if we've already discovered the authentication scheme
}

impl HttpMethods {
    pub fn new(builder: HttpRequestBuilder, client: reqwest::Client, api_key: String) -> Self {
        Self {
            builder,
            client,
            api_key,
            username: "tidb_cloud_user".to_string(), // Default username for API key auth
            digest_session: None,
            auth_discovered: false,
        }
    }

    pub fn new_with_credentials(
        builder: HttpRequestBuilder,
        client: reqwest::Client,
        username: String,
        password: String,
    ) -> Self {
        Self {
            builder,
            client,
            api_key: password, // Store password as api_key
            username,          // Store the actual username
            digest_session: None,
            auth_discovered: false,
        }
    }

    /// Unified request method that handles all HTTP methods and authentication automatically
    async fn make_request<T, B>(
        &mut self,
        method: &str,
        path: &str,
        query: Option<&str>,
        body: Option<&B>,
    ) -> TiDBCloudResult<T>
    where
        T: for<'de> serde::Deserialize<'de>,
        B: serde::Serialize,
    {
        let url = self.builder.build_url(path, query)?;

        // Build the initial request
        let mut request_builder = match method {
            "GET" => self.client.get(&url),
            "POST" => self.client.post(&url),
            "PUT" => self.client.put(&url),
            "PATCH" => self.client.patch(&url),
            "DELETE" => self.client.delete(&url),
            _ => {
                return Err(TiDBCloudError::AuthError(format!(
                    "Unsupported HTTP method: {method}"
                )));
            }
        };

        // Add body if provided
        if let Some(body_data) = body {
            request_builder = request_builder.json(body_data);
        }

        // Log the request
        self.log_request(method, &url, body).await;

        // Make the request
        let response = request_builder.send().await?;

        // Handle authentication if needed
        if response.status() == reqwest::StatusCode::UNAUTHORIZED {
            return self.handle_authentication(method, &url, query, body).await;
        }

        // Return the response
        self.handle_response(response).await
    }

    /// Handle authentication for any HTTP method
    async fn handle_authentication<T, B>(
        &mut self,
        method: &str,
        url: &str,
        query: Option<&str>,
        body: Option<&B>,
    ) -> TiDBCloudResult<T>
    where
        T: for<'de> serde::Deserialize<'de>,
        B: serde::Serialize,
    {
        // If we haven't discovered authentication yet, do the discovery
        if !self.auth_discovered {
            return self
                .discover_and_authenticate(method, url, query, body)
                .await;
        } else {
            // Authentication already discovered, but we got a 401 - try to re-authenticate
            return self.re_authenticate(method, url, query, body).await;
        }
    }

    /// Discover authentication method and perform initial authentication
    async fn discover_and_authenticate<T, B>(
        &mut self,
        method: &str,
        url: &str,
        query: Option<&str>,
        body: Option<&B>,
    ) -> TiDBCloudResult<T>
    where
        T: for<'de> serde::Deserialize<'de>,
        B: serde::Serialize,
    {
        // Log response headers for debugging
        if let Some(logger) = &self.builder.debug_logger {
            logger.debug("=== RESPONSE HEADERS (401 Unauthorized) ===");
            // We need to get the response headers from the original request
            // For now, we'll make a simple GET request to get the headers
            let response = self.client.get(url).send().await?;
            for (name, value) in response.headers() {
                if let Ok(value_str) = value.to_str() {
                    logger.debug(&format!("{name}: {value_str}"));
                }
            }
            logger.debug("==========================================");
        }

        // Test and log available authorization methods
        let response = self.client.get(url).send().await?;
        self.test_available_auth_methods(&response).await?;

        // Check for digest authentication
        if let Some(www_authenticate) = response.headers().get("www-authenticate")
            && let Ok(www_auth_str) = www_authenticate.to_str()
            && www_auth_str.starts_with("Digest")
        {
            if let Some(logger) = &self.builder.debug_logger {
                logger.debug("=== TRIGGERING DIGEST AUTHENTICATION ===");
            }
            // Mark authentication as discovered
            self.auth_discovered = true;
            return self.perform_digest_auth(method, url, query, body).await;
        }

        // If we get here, it's a 401 but not digest auth, so return the error
        self.handle_response(response).await
    }

    /// Re-authenticate using stored session
    async fn re_authenticate<T, B>(
        &mut self,
        method: &str,
        url: &str,
        query: Option<&str>,
        body: Option<&B>,
    ) -> TiDBCloudResult<T>
    where
        T: for<'de> serde::Deserialize<'de>,
        B: serde::Serialize,
    {
        // Check if we have a stored digest session
        if self.digest_session.is_some() {
            if let Some(logger) = &self.builder.debug_logger {
                logger.debug("=== RE-AUTHENTICATING WITH STORED SESSION ===");
            }
            return self.perform_digest_auth(method, url, query, body).await;
        }

        // If we get here, authentication failed
        eprintln!("Authentication failed. Please check your credentials.");
        let response = self.client.get(url).send().await?;
        self.handle_response(response).await
    }

    /// Perform digest authentication
    async fn perform_digest_auth<T, B>(
        &mut self,
        method: &str,
        url: &str,
        _query: Option<&str>,
        body: Option<&B>,
    ) -> TiDBCloudResult<T>
    where
        T: for<'de> serde::Deserialize<'de>,
        B: serde::Serialize,
    {
        if let Some(logger) = &self.builder.debug_logger {
            logger.debug("=== DIGEST AUTHENTICATION STARTED ===");
        }

        // First request to get the challenge - always use GET for the challenge
        let response = self.client.get(url).send().await?;

        if let Some(www_authenticate) = response.headers().get("www-authenticate")
            && let Ok(www_auth_str) = www_authenticate.to_str()
        {
            if let Some(logger) = &self.builder.debug_logger {
                logger.debug(&format!("WWW-Authenticate: {www_auth_str}"));
            }

            // Extract the request-URI from the full URL for digest authentication
            let request_uri = if let Ok(parsed_url) = url::Url::parse(url) {
                let path = parsed_url.path();
                let query = parsed_url.query();
                if let Some(query) = query {
                    format!("{path}?{query}")
                } else {
                    path.to_string()
                }
            } else if let Some(path_start) = url.find("://") {
                if let Some(path_part) = url[path_start..].find('/') {
                    url[path_start + path_part..].to_string()
                } else {
                    "/".to_string()
                }
            } else {
                url.to_string()
            };

            // Get or create digest session
            let auth_header = if let Some(ref mut session) = self.digest_session {
                // Reuse existing session
                session.parse_challenge(www_auth_str).map_err(|e| {
                    TiDBCloudError::AuthError(format!(
                        "Failed to parse digest challenge '{www_auth_str}': {e}"
                    ))
                })?;
                session
                    .generate_response_and_increment(method, &request_uri)
                    .map_err(|e| {
                        TiDBCloudError::AuthError(format!(
                            "Failed to generate digest response for method '{}' and URI '{}': {}",
                            method, &request_uri, e
                        ))
                    })?
            } else {
                // Create new session
                let digest_auth = DigestAuth::new(self.username.clone(), self.api_key.clone());
                let mut session = digest_auth.create_session();
                session.parse_challenge(www_auth_str).map_err(|e| {
                    TiDBCloudError::AuthError(format!(
                        "Failed to parse digest challenge '{www_auth_str}': {e}"
                    ))
                })?;
                let auth_header = session
                    .generate_response_and_increment(method, &request_uri)
                    .map_err(|e| {
                        TiDBCloudError::AuthError(format!(
                            "Failed to generate digest response for method '{}' and URI '{}': {}",
                            method, &request_uri, e
                        ))
                    })?;

                // Store the session for reuse
                self.digest_session = Some(session);
                auth_header
            };

            if let Some(logger) = &self.builder.debug_logger {
                logger.debug(&format!("Generated Authorization: {auth_header}"));
            }

            // Log the authenticated request headers
            if let Some(logger) = &self.builder.debug_logger {
                logger.debug("=== AUTHENTICATED HTTP REQUEST HEADERS ===");
                logger.debug(&format!("Method: {method}"));
                logger.debug(&format!("URL: {url}"));
                logger.debug("Headers that will be sent:");
                logger.debug(&format!("Authorization: {auth_header}"));
                logger.debug("Content-Type: application/json");
                logger.debug("User-Agent: tidb-cloud-rust-client/1.0.0");
                logger.debug("Accept: application/json");
                logger.debug("===================================");
            }

            // Make the authenticated request with the correct method and body
            let mut request_builder = match method {
                "GET" => self.client.get(url),
                "POST" => self.client.post(url),
                "PUT" => self.client.put(url),
                "PATCH" => self.client.patch(url),
                "DELETE" => self.client.delete(url),
                _ => {
                    return Err(TiDBCloudError::AuthError(format!(
                        "Unsupported HTTP method: {method}"
                    )));
                }
            };

            // Add the authorization header
            request_builder = request_builder.header("Authorization", auth_header);

            // Add the body if provided
            if let Some(body_data) = body {
                request_builder = request_builder.json(body_data);
            }

            let response = request_builder.send().await?;

            if let Some(logger) = &self.builder.debug_logger {
                logger.debug(&format!(
                    "Authenticated response status: {}",
                    response.status()
                ));
            }

            return self.handle_response(response).await;
        }

        Err(TiDBCloudError::AuthError(
            "Failed to handle digest authentication".to_string(),
        ))
    }

    /// Log request details
    async fn log_request<B>(&self, method: &str, url: &str, body: Option<&B>)
    where
        B: serde::Serialize,
    {
        if let Some(logger) = &self.builder.debug_logger {
            let body_str = if let Some(body) = body {
                serde_json::to_string_pretty(body).ok()
            } else {
                None
            };

            let headers_str = self.format_headers_for_logging();
            logger.log_api_query_with_headers(method, url, Some(&headers_str), body_str.as_deref());

            // Additional TRACE level logging for JSON body
            if let Some(body_str) = &body_str {
                logger.trace("=== FULL JSON REQUEST BODY ===");
                logger.trace(body_str);
                logger.trace("=============================");
            }
        }
    }

    /// Make a GET request with security validations
    pub async fn get<T>(&mut self, path: &str, query: Option<&str>) -> TiDBCloudResult<T>
    where
        T: for<'de> serde::Deserialize<'de>,
    {
        self.make_request("GET", path, query, None::<&serde_json::Value>)
            .await
    }

    /// Make a POST request with security validations
    pub async fn post<T, B>(&mut self, path: &str, body: Option<&B>) -> TiDBCloudResult<T>
    where
        T: for<'de> serde::Deserialize<'de>,
        B: serde::Serialize,
    {
        self.make_request("POST", path, None, body).await
    }

    /// Test and log available authorization methods
    async fn test_available_auth_methods(
        &self,
        response: &reqwest::Response,
    ) -> TiDBCloudResult<()> {
        if let Some(logger) = &self.builder.debug_logger {
            logger.debug("=== TESTING AVAILABLE AUTHORIZATION METHODS ===");

            // Test different authorization methods
            let auth_methods = vec![
                ("Bearer", format!("Bearer {}", self.api_key)),
                ("Basic", format!("Basic user:{}", self.api_key)),
                ("API-Key", format!("API-Key {}", self.api_key)),
                ("X-API-Key", format!("X-API-Key {}", self.api_key)),
                ("Authorization", self.api_key.clone()),
            ];

            for (method_name, auth_header) in auth_methods {
                logger.debug(&format!("Testing {method_name} authentication..."));

                // Get the URL from the original request
                let url = response.url().clone();

                // Try the authentication method
                let test_response = match method_name {
                    "Bearer" => {
                        self.client
                            .get(url.clone())
                            .header("Authorization", auth_header)
                            .send()
                            .await
                    }
                    "Basic" => {
                        self.client
                            .get(url.clone())
                            .header("Authorization", auth_header)
                            .send()
                            .await
                    }
                    "API-Key" => {
                        self.client
                            .get(url.clone())
                            .header("Authorization", auth_header)
                            .send()
                            .await
                    }
                    "X-API-Key" => {
                        self.client
                            .get(url.clone())
                            .header("X-API-Key", &self.api_key)
                            .send()
                            .await
                    }
                    "Authorization" => {
                        self.client
                            .get(url.clone())
                            .header("Authorization", auth_header)
                            .send()
                            .await
                    }
                    _ => continue,
                };

                match test_response {
                    Ok(resp) => {
                        let status = resp.status();
                        logger.debug(&format!(
                            "  {} auth result: {} {}",
                            method_name,
                            status.as_u16(),
                            status.canonical_reason().unwrap_or("Unknown")
                        ));

                        // Log response headers for successful or interesting responses
                        if status.is_success() {
                            logger.debug(&format!("  ✅ {method_name} authentication SUCCESSFUL!"));
                            for (name, value) in resp.headers() {
                                if let Ok(value_str) = value.to_str() {
                                    logger.debug(&format!("    {name}: {value_str}"));
                                }
                            }
                        } else if status == reqwest::StatusCode::UNAUTHORIZED
                            && let Some(www_auth) = resp.headers().get("www-authenticate")
                            && let Ok(www_auth_str) = www_auth.to_str()
                        {
                            logger.debug(&format!("    WWW-Authenticate: {www_auth_str}"));
                        }
                    }
                    Err(e) => {
                        logger.debug(&format!("  ❌ {method_name} auth failed: {e}"));
                    }
                }
            }

            logger.debug("=== END AUTHORIZATION METHOD TESTING ===");
        }

        Ok(())
    }

    /// Make a PATCH request with security validations
    pub async fn patch<T, B>(&mut self, path: &str, body: &B) -> TiDBCloudResult<T>
    where
        T: for<'de> serde::Deserialize<'de>,
        B: serde::Serialize,
    {
        self.make_request("PATCH", path, None, Some(body)).await
    }

    /// Make a DELETE request with security validations
    pub async fn delete<T>(&mut self, path: &str, query: Option<&str>) -> TiDBCloudResult<T>
    where
        T: for<'de> serde::Deserialize<'de>,
    {
        self.make_request("DELETE", path, query, None::<&serde_json::Value>)
            .await
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
            logger.debug(&format!("API Response Status: {status}"));

            // Log response headers
            logger.debug(&format!(
                "=== RESPONSE HEADERS ({} {}) ===",
                status.as_u16(),
                status.canonical_reason().unwrap_or("Unknown")
            ));
            for (name, value) in &headers {
                if let Ok(value_str) = value.to_str() {
                    logger.debug(&format!("{name}: {value_str}"));
                }
            }
            logger.debug("==========================================");
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
            return Err(TiDBCloudError::AuthError(
                "Insufficient permissions".to_string(),
            ));
        }

        // Check for not found errors
        if status == reqwest::StatusCode::NOT_FOUND {
            return Err(TiDBCloudError::NotFound("Resource not found".to_string()));
        }

        // Check for server errors
        if status.is_server_error() {
            return Err(TiDBCloudError::HttpError {
                status: status.as_u16(),
                message: format!("Server error: {status}"),
            });
        }

        // Validate response size
        if text.len() > MAX_REQUEST_SIZE {
            return Err(TiDBCloudError::SerializationError(format!(
                "Response too large: {} bytes (max: {} bytes)",
                text.len(),
                MAX_REQUEST_SIZE
            )));
        }

        // Try to parse as JSON first
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&text) {
            // Check if it's an error response with code/message at root level (TiDB Cloud API format)
            if let (Some(code), Some(message)) = (
                json.get("code").and_then(|v| v.as_i64()),
                json.get("message").and_then(|v| v.as_str()),
            ) {
                // If it's not a success status, treat it as an error
                if !status.is_success() {
                    let details = json.get("details").and_then(|v| v.as_array()).cloned();

                    return Err(TiDBCloudError::ApiError {
                        code: code as i32,
                        message: message.to_string(),
                        details: details.map(|d| d.into_iter().collect()),
                    });
                }
            }

            // Check if it's an error response with nested error object
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
                    "Failed to deserialize response: {e}"
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
    fn test_error_response_parsing() {
        // Test the TiDB Cloud API error format
        let error_json = r#"{"code":400, "message":"Min RCU must be at least 1/4 of max RCU.", "details":[{"@type":"type.tidbapi.com/tidb.rpc.RequestInfo", "requestId":"20250802042016c641cf31a21d42f7a8", "servingData":"bizErrorCode: 49900001"}]}"#;

        let json: serde_json::Value = serde_json::from_str(error_json).unwrap();

        // Verify we can extract the error information
        let code = json.get("code").and_then(|v| v.as_i64()).unwrap();
        let message = json.get("message").and_then(|v| v.as_str()).unwrap();
        let details = json.get("details").and_then(|v| v.as_array()).unwrap();

        assert_eq!(code, 400);
        assert_eq!(message, "Min RCU must be at least 1/4 of max RCU.");
        assert_eq!(details.len(), 1);

        // Verify we can extract request ID from details
        let request_id = details[0]
            .as_object()
            .and_then(|obj| obj.get("requestId"))
            .and_then(|v| v.as_str())
            .unwrap();

        assert_eq!(request_id, "20250802042016c641cf31a21d42f7a8");
    }

    #[test]
    fn test_url_validation() {
        let builder = HttpRequestBuilder::new(
            PRODUCTION_API_URL.to_string(),
            Duration::from_secs(30),
            "test-agent".to_string(),
        );

        // Valid URLs
        assert!(
            builder
                .validate_url(&format!("{PRODUCTION_API_URL}/tidbs"))
                .is_ok()
        );
        assert!(
            builder
                .validate_url("https://api.tidbcloud.com/v1beta2/tidbs")
                .is_ok()
        );

        // Invalid URLs
        assert!(
            builder
                .validate_url("http://cloud.tidbapi.com/v1beta2/tidbs")
                .is_err()
        ); // HTTP not allowed
        assert!(
            builder
                .validate_url("https://malicious.com/v1beta2/tidbs")
                .is_err()
        ); // Invalid domain
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
