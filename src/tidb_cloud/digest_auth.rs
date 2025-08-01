use crate::tidb_cloud::error::{TiDBCloudError, TiDBCloudResult};
use std::collections::HashMap;

/// Supported digest authentication algorithms
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum Algorithm {
    #[default]
    MD5,
    // SHA256, // Future support
    // SHA512, // Future support
}

impl Algorithm {
    /// Parse algorithm from string
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_uppercase().as_str() {
            "MD5" => Some(Algorithm::MD5),
            // "SHA256" => Some(Algorithm::SHA256), // Future support
            // "SHA512" => Some(Algorithm::SHA512), // Future support
            _ => None,
        }
    }

    /// Convert algorithm to string representation
    pub fn as_str(&self) -> &'static str {
        match self {
            Algorithm::MD5 => "MD5",
            // Algorithm::SHA256 => "SHA256", // Future support
            // Algorithm::SHA512 => "SHA512", // Future support
        }
    }
}

impl std::fmt::Display for Algorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// HTTP Digest Authentication configuration (immutable)
pub struct DigestAuth {
    username: String,
    password: String,
}

/// HTTP Digest Authentication session state (mutable)
pub struct DigestSession {
    auth: DigestAuth,
    realm: Option<String>,
    nonce: Option<String>,
    qop: Option<String>,
    opaque: Option<String>,
    algorithm: Algorithm,                // Use enum instead of Option<String>
    all_params: HashMap<String, String>, // Store all parsed parameters for error messages
    nc: u32,
    cnonce: String,
}

impl DigestAuth {
    /// Create a new digest authentication configuration
    pub fn new(username: String, password: String) -> Self {
        Self { username, password }
    }

    /// Create a new session from this authentication configuration
    pub fn create_session(&self) -> DigestSession {
        DigestSession::new(self.clone())
    }

    /// Convenience method to create a session, parse challenge, and generate response
    pub fn authenticate(
        &self,
        www_authenticate: &str,
        method: &str,
        uri: &str,
    ) -> TiDBCloudResult<String> {
        let mut session = self.create_session();
        session.parse_challenge(www_authenticate).map_err(|e| {
            TiDBCloudError::AuthError(format!(
                "Failed to parse digest challenge '{www_authenticate}': {e}"
            ))
        })?;
        session
            .generate_response_and_increment(method, uri)
            .map_err(|e| {
                TiDBCloudError::AuthError(format!(
                    "Failed to generate digest response for method '{method}' and URI '{uri}': {e}"
                ))
            })
    }

    /// Calculate MD5 hash
    fn md5_hash(&self, input: &str) -> String {
        let digest = md5::compute(input.as_bytes());
        hex::encode(digest.0)
    }
}

impl Clone for DigestAuth {
    fn clone(&self) -> Self {
        Self {
            username: self.username.clone(),
            password: self.password.clone(),
        }
    }
}

impl DigestSession {
    /// Create a new digest authentication session
    pub fn new(auth: DigestAuth) -> Self {
        Self {
            auth,
            realm: None,
            nonce: None,
            qop: None,
            opaque: None,
            algorithm: Algorithm::default(),
            all_params: HashMap::new(),
            nc: 1,
            cnonce: Self::generate_cnonce(),
        }
    }

    /// Parse WWW-Authenticate header and extract challenge parameters
    pub fn parse_challenge(&mut self, www_authenticate: &str) -> TiDBCloudResult<()> {
        // Remove "Digest " prefix
        let challenge = www_authenticate
            .strip_prefix("Digest ")
            .ok_or_else(|| TiDBCloudError::AuthError(
                format!("Invalid WWW-Authenticate header format. Expected 'Digest ' prefix, got: {www_authenticate}")
            ))?;

        // Parse key-value pairs
        let mut params = HashMap::new();
        for part in challenge.split(',') {
            let part = part.trim();
            if let Some((key, value)) = part.split_once('=') {
                let key = key.trim();
                let value = value.trim_matches('"');
                params.insert(key.to_string(), value.to_string());
            }
        }

        // Store all parameters for error messages (avoid cloning by moving)
        self.all_params = params;

        // Extract required parameters using map(|s| s.to_owned()) instead of cloned()
        self.realm = self.all_params.get("realm").map(|s| s.to_owned());
        self.nonce = self.all_params.get("nonce").map(|s| s.to_owned());
        self.qop = self.all_params.get("qop").map(|s| s.to_owned());
        self.opaque = self.all_params.get("opaque").map(|s| s.to_owned());

        // Parse algorithm from string to enum
        self.algorithm = self
            .all_params
            .get("algorithm")
            .and_then(|s| Algorithm::parse(s))
            .unwrap_or_default();

        Ok(())
    }

    /// Generate Authorization header for the response (without incrementing nc)
    pub fn generate_response(&self, method: &str, uri: &str) -> TiDBCloudResult<String> {
        let realm = self.realm.as_ref()
            .ok_or_else(|| {
                let available_params = self.get_available_params();
                TiDBCloudError::AuthError(
                    format!("Missing 'realm' parameter in digest challenge. Available parameters: {available_params}. Required for generating response.")
                )
            })?;
        let nonce = self.nonce.as_ref()
            .ok_or_else(|| {
                let available_params = self.get_available_params();
                TiDBCloudError::AuthError(
                    format!("Missing 'nonce' parameter in digest challenge. Available parameters: {available_params}. Required for generating response.")
                )
            })?;

        // Generate HA1 = MD5(username:realm:password)
        let ha1 = self.auth.md5_hash(&format!(
            "{}:{}:{}",
            self.auth.username, realm, self.auth.password
        ));

        // Generate HA2 = MD5(method:uri)
        let ha2 = self.auth.md5_hash(&format!("{method}:{uri}"));

        // Generate response
        let response = if let Some(qop) = &self.qop {
            // With qop
            let nc = format!("{:08x}", self.nc);
            let response = self.auth.md5_hash(&format!(
                "{}:{}:{}:{}:{}:{}",
                ha1, nonce, nc, &self.cnonce, qop, ha2
            ));

            // Build Authorization header with optional opaque and algorithm
            let mut auth_header = format!(
                "Digest username=\"{}\", realm=\"{}\", nonce=\"{}\", uri=\"{}\", \
                qop={}, nc={}, cnonce=\"{}\", response=\"{}\"",
                Self::escape_quoted_string(&self.auth.username),
                Self::escape_quoted_string(realm),
                Self::escape_quoted_string(nonce),
                Self::escape_quoted_string(uri),
                qop,
                nc,
                Self::escape_quoted_string(&self.cnonce),
                response
            );

            // Add algorithm (always present now)
            auth_header =
                auth_header.replace("Digest ", &format!("Digest algorithm={}, ", self.algorithm));

            // Add opaque if provided
            if let Some(opaque) = &self.opaque {
                auth_header = auth_header.replace(
                    "realm=\"",
                    &format!(
                        "opaque=\"{}\", realm=\"",
                        Self::escape_quoted_string(opaque)
                    ),
                );
            }

            auth_header
        } else {
            // Without qop
            let response = self.auth.md5_hash(&format!("{ha1}:{nonce}:{ha2}"));

            // Build Authorization header with optional opaque and algorithm
            let mut auth_header = format!(
                "Digest username=\"{}\", realm=\"{}\", nonce=\"{}\", uri=\"{}\", response=\"{}\"",
                Self::escape_quoted_string(&self.auth.username),
                Self::escape_quoted_string(realm),
                Self::escape_quoted_string(nonce),
                Self::escape_quoted_string(uri),
                response
            );

            // Add algorithm (always present now)
            auth_header =
                auth_header.replace("Digest ", &format!("Digest algorithm={}, ", self.algorithm));

            // Add opaque if provided
            if let Some(opaque) = &self.opaque {
                auth_header = auth_header.replace(
                    "realm=\"",
                    &format!(
                        "opaque=\"{}\", realm=\"",
                        Self::escape_quoted_string(opaque)
                    ),
                );
            }

            auth_header
        };

        Ok(response)
    }

    /// Generate Authorization header and increment nonce counter
    pub fn generate_response_and_increment(
        &mut self,
        method: &str,
        uri: &str,
    ) -> TiDBCloudResult<String> {
        let response = self.generate_response(method, uri)?;
        self.nc += 1;
        Ok(response)
    }

    /// Reset the session state (new nonce, cnonce, nc counter)
    pub fn reset(&mut self) {
        self.realm = None;
        self.nonce = None;
        self.qop = None;
        self.opaque = None;
        self.algorithm = Algorithm::default();
        self.all_params.clear();
        self.nc = 1;
        // Generate new cnonce only when needed (for security)
        self.cnonce = Self::generate_cnonce();
    }

    /// Get the current nonce counter value
    pub fn get_nc(&self) -> u32 {
        self.nc
    }

    /// Get the current client nonce
    pub fn get_cnonce(&self) -> &str {
        &self.cnonce
    }

    /// Get a string representation of available parameters for error messages
    fn get_available_params(&self) -> String {
        if self.all_params.is_empty() {
            "none".to_string()
        } else {
            // Avoid collecting into Vec and then mapping - do it in one step
            let mut params: Vec<&str> = self.all_params.keys().map(|s| s.as_str()).collect();
            params.sort();
            params.join(", ")
        }
    }

    /// Escape a value for use in a quoted-string in Authorization header
    /// According to RFC 2617, backslashes and quotes must be escaped
    fn escape_quoted_string(value: &str) -> String {
        value
            .replace("\\", "\\\\") // Escape backslashes first
            .replace("\"", "\\\"") // Then escape quotes
    }

    /// Generate client nonce
    fn generate_cnonce() -> String {
        use rand::Rng;
        let mut rng = rand::rng();
        let bytes: [u8; 8] = rng.random();
        // hex::encode is optimized for this use case
        hex::encode(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_algorithm_enum() {
        // Test parsing from string
        assert_eq!(Algorithm::parse("MD5"), Some(Algorithm::MD5));
        assert_eq!(Algorithm::parse("md5"), Some(Algorithm::MD5));
        assert_eq!(Algorithm::parse("Md5"), Some(Algorithm::MD5));
        assert_eq!(Algorithm::parse("SHA256"), None); // Not supported yet
        assert_eq!(Algorithm::parse("invalid"), None);

        // Test string representation
        assert_eq!(Algorithm::MD5.as_str(), "MD5");

        // Test default
        assert_eq!(Algorithm::default(), Algorithm::MD5);

        // Test Display trait
        assert_eq!(format!("{}", Algorithm::MD5), "MD5");

        // Test equality
        assert_eq!(Algorithm::MD5, Algorithm::MD5);
        assert_eq!(Algorithm::MD5, Algorithm::default()); // Should be equal
    }

    #[test]
    fn test_quoted_string_escaping() {
        // Test basic escaping
        assert_eq!(DigestSession::escape_quoted_string("normal"), "normal");
        assert_eq!(
            DigestSession::escape_quoted_string("user@domain"),
            "user@domain"
        );

        // Test quote escaping
        assert_eq!(
            DigestSession::escape_quoted_string("user\"name"),
            "user\\\"name"
        );
        assert_eq!(
            DigestSession::escape_quoted_string("\"quoted\""),
            "\\\"quoted\\\""
        );

        // Test backslash escaping
        assert_eq!(
            DigestSession::escape_quoted_string("path\\to\\file"),
            "path\\\\to\\\\file"
        );
        assert_eq!(
            DigestSession::escape_quoted_string("C:\\Users\\name"),
            "C:\\\\Users\\\\name"
        );

        // Test both quotes and backslashes
        assert_eq!(
            DigestSession::escape_quoted_string("user\"name\\path"),
            "user\\\"name\\\\path"
        );
        assert_eq!(
            DigestSession::escape_quoted_string("\"C:\\Users\\name\""),
            "\\\"C:\\\\Users\\\\name\\\""
        );

        // Test edge cases
        assert_eq!(DigestSession::escape_quoted_string(""), "");
        assert_eq!(DigestSession::escape_quoted_string("\\"), "\\\\");
        assert_eq!(DigestSession::escape_quoted_string("\""), "\\\"");
        assert_eq!(DigestSession::escape_quoted_string("\\\\"), "\\\\\\\\");
        assert_eq!(DigestSession::escape_quoted_string("\"\""), "\\\"\\\"");
    }

    #[test]
    fn test_authorization_header_escaping() {
        // Test with values that need escaping
        let challenge =
            r#"Digest realm="test\"realm", nonce="test-nonce", qop="auth", algorithm=MD5"#;
        let username = "user\"name";
        let password = "testpass";
        let method = "GET";
        let uri = "C:\\Users\\path\\to\\file";

        let auth = DigestAuth::new(username.to_string(), password.to_string());
        let mut session = auth.create_session();

        // Parse challenge
        assert!(session.parse_challenge(challenge).is_ok());

        // Generate response
        let auth_header = session
            .generate_response_and_increment(method, uri)
            .unwrap();

        // Verify that quotes and backslashes are properly escaped
        assert!(auth_header.contains("username=\"user\\\"name\""));
        assert!(auth_header.contains("realm=\"test\\\\\\\"realm\"")); // realm from challenge has escaped quote, gets double-escaped
        assert!(auth_header.contains("uri=\"C:\\\\Users\\\\path\\\\to\\\\file\""));

        // Verify the header is still valid
        assert!(auth_header.starts_with("Digest algorithm=MD5"));
        assert!(auth_header.contains("qop=auth"));
        assert!(auth_header.contains("nc=00000001"));
        assert!(auth_header.contains("cnonce=\""));
        assert!(auth_header.contains("response=\""));
    }

    #[test]
    fn test_digest_auth_creation() {
        let auth = DigestAuth::new("testuser".to_string(), "testpass".to_string());
        assert_eq!(auth.username, "testuser");
        assert_eq!(auth.password, "testpass");
    }

    #[test]
    fn test_digest_session_creation() {
        let auth = DigestAuth::new("testuser".to_string(), "testpass".to_string());
        let session = auth.create_session();
        assert_eq!(session.auth.username, "testuser");
        assert_eq!(session.auth.password, "testpass");
        assert_eq!(session.nc, 1);
    }

    #[test]
    fn test_parse_challenge() {
        let auth = DigestAuth::new("testuser".to_string(), "testpass".to_string());
        let mut session = auth.create_session();
        let challenge = r#"Digest realm="test-realm", nonce="test-nonce", qop="auth""#;

        assert!(session.parse_challenge(challenge).is_ok());
        assert_eq!(session.realm, Some("test-realm".to_string()));
        assert_eq!(session.nonce, Some("test-nonce".to_string()));
        assert_eq!(session.qop, Some("auth".to_string()));
    }

    #[test]
    fn test_parse_challenge_with_opaque_and_algorithm() {
        let auth = DigestAuth::new("testuser".to_string(), "testpass".to_string());
        let mut session = auth.create_session();
        let challenge = r#"Digest realm="test-realm", nonce="test-nonce", qop="auth", opaque="test-opaque", algorithm="MD5""#;

        assert!(session.parse_challenge(challenge).is_ok());
        assert_eq!(session.realm, Some("test-realm".to_string()));
        assert_eq!(session.nonce, Some("test-nonce".to_string()));
        assert_eq!(session.qop, Some("auth".to_string()));
        assert_eq!(session.opaque, Some("test-opaque".to_string()));
        assert_eq!(session.algorithm, Algorithm::MD5);
    }

    #[test]
    fn test_generate_response_with_opaque_and_algorithm() {
        let auth = DigestAuth::new("testuser".to_string(), "testpass".to_string());
        let mut session = auth.create_session();
        let challenge = r#"Digest realm="test-realm", nonce="test-nonce", qop="auth", opaque="test-opaque", algorithm="MD5""#;

        assert!(session.parse_challenge(challenge).is_ok());
        let response = session.generate_response("GET", "/test").unwrap();

        // Check that opaque and algorithm are included in the response
        assert!(response.contains("opaque=\"test-opaque\""));
        assert!(response.contains("algorithm=MD5"));
        assert!(response.contains("username=\"testuser\""));
        assert!(response.contains("realm=\"test-realm\""));
        assert!(response.contains("nonce=\"test-nonce\""));
    }

    #[test]
    fn test_generate_response_without_opaque() {
        let auth = DigestAuth::new("testuser".to_string(), "testpass".to_string());
        let mut session = auth.create_session();
        let challenge = r#"Digest realm="tidb.cloud", domain="", nonce="test-nonce", algorithm=MD5, qop="auth", stale=false"#;

        assert!(session.parse_challenge(challenge).is_ok());
        let response = session.generate_response("GET", "/test").unwrap();

        // Check that algorithm is included but opaque is not
        assert!(response.contains("algorithm=MD5"));
        assert!(!response.contains("opaque="));
        assert!(response.contains("username=\"testuser\""));
        assert!(response.contains("realm=\"tidb.cloud\""));
        assert!(response.contains("nonce=\"test-nonce\""));
    }

    #[test]
    fn test_generate_response_and_increment() {
        let auth = DigestAuth::new("testuser".to_string(), "testpass".to_string());
        let mut session = auth.create_session();
        let challenge = r#"Digest realm="test-realm", nonce="test-nonce", qop="auth""#;

        assert!(session.parse_challenge(challenge).is_ok());
        assert_eq!(session.get_nc(), 1);

        let response1 = session
            .generate_response_and_increment("GET", "/test")
            .unwrap();
        assert_eq!(session.get_nc(), 2);

        let response2 = session
            .generate_response_and_increment("GET", "/test")
            .unwrap();
        assert_eq!(session.get_nc(), 3);

        // Responses should be different due to different nc values
        assert_ne!(response1, response2);
    }

    #[test]
    fn test_session_reset() {
        let auth = DigestAuth::new("testuser".to_string(), "testpass".to_string());
        let mut session = auth.create_session();
        let challenge = r#"Digest realm="test-realm", nonce="test-nonce", qop="auth""#;

        assert!(session.parse_challenge(challenge).is_ok());
        assert_eq!(session.get_nc(), 1);

        session
            .generate_response_and_increment("GET", "/test")
            .unwrap();
        assert_eq!(session.get_nc(), 2);

        session.reset();
        assert_eq!(session.get_nc(), 1);
        assert_eq!(session.realm, None);
        assert_eq!(session.nonce, None);
    }

    #[test]
    fn test_reusable_auth() {
        let auth = DigestAuth::new("testuser".to_string(), "testpass".to_string());

        // Create multiple sessions from the same auth
        let mut session1 = auth.create_session();
        let mut session2 = auth.create_session();

        let challenge = r#"Digest realm="test-realm", nonce="test-nonce", qop="auth""#;

        assert!(session1.parse_challenge(challenge).is_ok());
        assert!(session2.parse_challenge(challenge).is_ok());

        let response1 = session1.generate_response("GET", "/test").unwrap();
        let response2 = session2.generate_response("GET", "/test").unwrap();

        // Both sessions should generate valid responses with the same structure
        // but different cnonce values (which is correct)
        assert!(response1.contains("Digest algorithm=MD5"));
        assert!(response2.contains("Digest algorithm=MD5"));
        assert!(response1.contains("username=\"testuser\""));
        assert!(response2.contains("username=\"testuser\""));
        assert!(response1.contains("realm=\"test-realm\""));
        assert!(response2.contains("realm=\"test-realm\""));
        assert!(response1.contains("nonce=\"test-nonce\""));
        assert!(response2.contains("nonce=\"test-nonce\""));

        // The responses should be different due to different cnonce values
        assert_ne!(response1, response2);
    }

    #[test]
    fn test_md5_hash() {
        let auth = DigestAuth::new("testuser".to_string(), "testpass".to_string());
        let hash = auth.md5_hash("test");
        assert_eq!(hash, "098f6bcd4621d373cade4e832627b4f6");
    }

    #[test]
    fn test_authenticate_convenience_method() {
        let auth = DigestAuth::new("testuser".to_string(), "testpass".to_string());
        let challenge = r#"Digest realm="test-realm", nonce="test-nonce", qop="auth""#;

        let response = auth.authenticate(challenge, "GET", "/test").unwrap();

        // Check that the response is valid
        assert!(response.contains("algorithm=MD5"));
        assert!(response.contains("username=\"testuser\""));
        assert!(response.contains("realm=\"test-realm\""));
        assert!(response.contains("nonce=\"test-nonce\""));
        assert!(response.contains("qop=auth"));
        assert!(response.contains("nc=00000001"));
    }

    #[test]
    fn test_improved_error_messages() {
        let auth = DigestAuth::new("testuser".to_string(), "testpass".to_string());

        // Test invalid WWW-Authenticate header format
        let result = auth.authenticate("InvalidHeader", "GET", "/test");
        assert!(result.is_err());
        let error = result.unwrap_err().to_string();
        assert!(error.contains("Invalid WWW-Authenticate header format"));
        assert!(error.contains("InvalidHeader"));

        // Test missing realm parameter
        let result = auth.authenticate(r#"Digest nonce="test-nonce", qop="auth""#, "GET", "/test");
        assert!(result.is_err());
        let error = result.unwrap_err().to_string();
        assert!(error.contains("Missing 'realm' parameter"));
        assert!(error.contains("Available parameters: nonce, qop"));

        // Test missing nonce parameter
        let result = auth.authenticate(r#"Digest realm="test-realm", qop="auth""#, "GET", "/test");
        assert!(result.is_err());
        let error = result.unwrap_err().to_string();
        assert!(error.contains("Missing 'nonce' parameter"));
        assert!(error.contains("Available parameters: qop, realm"));

        // Test no parameters at all
        let result = auth.authenticate(r#"Digest domain="test""#, "GET", "/test");
        assert!(result.is_err());
        let error = result.unwrap_err().to_string();
        assert!(error.contains("Missing 'realm' parameter"));
        assert!(error.contains("Available parameters: domain"));
    }

    #[test]
    fn test_complete_digest_authentication_flow() {
        // Test with a realistic challenge similar to what TiDB Cloud returns
        let challenge = r#"Digest realm="tidb.cloud", domain="", nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093", algorithm=MD5, qop="auth", stale=false"#;
        let username = "testuser";
        let password = "testpass";
        let method = "GET";
        let uri = "/api/v1/clusters";

        let auth = DigestAuth::new(username.to_string(), password.to_string());
        let mut session = auth.create_session();

        // Step 1: Parse the challenge
        assert!(session.parse_challenge(challenge).is_ok());

        // Verify parsed parameters
        assert_eq!(session.realm, Some("tidb.cloud".to_string()));
        assert_eq!(
            session.nonce,
            Some("dcd98b7102dd2f0e8b11d0f600bfb0c093".to_string())
        );
        assert_eq!(session.qop, Some("auth".to_string()));
        assert_eq!(session.algorithm, Algorithm::MD5);
        assert_eq!(session.opaque, None); // Not present in this challenge

        // Step 2: Generate the response
        let auth_header = session
            .generate_response_and_increment(method, uri)
            .unwrap();

        // Step 3: Verify the Authorization header format
        assert!(auth_header.starts_with("Digest algorithm=MD5"));
        assert!(auth_header.contains(&format!("username=\"{}\"", username)));
        assert!(auth_header.contains("realm=\"tidb.cloud\""));
        assert!(auth_header.contains("nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\""));
        assert!(auth_header.contains(&format!("uri=\"{}\"", uri)));
        assert!(auth_header.contains("qop=auth"));
        assert!(auth_header.contains("nc=00000001"));
        assert!(auth_header.contains("cnonce=\""));
        assert!(auth_header.contains("response=\""));

        // Verify the header structure (all required components are present)
        let components = [
            "Digest algorithm=MD5",
            &format!("username=\"{}\"", username),
            "realm=\"tidb.cloud\"",
            "nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\"",
            &format!("uri=\"{}\"", uri),
            "qop=auth",
            "nc=00000001",
            "cnonce=\"",
            "response=\"",
        ];

        for component in &components {
            assert!(
                auth_header.contains(component),
                "Authorization header missing component: {}",
                component
            );
        }

        // Verify nonce counter was incremented
        assert_eq!(session.get_nc(), 2);

        // Step 4: Test that subsequent requests have different responses
        let auth_header2 = session
            .generate_response_and_increment(method, uri)
            .unwrap();
        assert_ne!(
            auth_header, auth_header2,
            "Subsequent responses should be different"
        );
        assert_eq!(session.get_nc(), 3);

        // Step 5: Verify the response format is consistent
        assert!(auth_header2.starts_with("Digest algorithm=MD5"));
        assert!(auth_header2.contains(&format!("username=\"{}\"", username)));
        assert!(auth_header2.contains("realm=\"tidb.cloud\""));
        assert!(auth_header2.contains("nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\""));
        assert!(auth_header2.contains(&format!("uri=\"{}\"", uri)));
        assert!(auth_header2.contains("qop=auth"));
        assert!(auth_header2.contains("nc=00000002"));
        assert!(auth_header2.contains("cnonce=\""));
        assert!(auth_header2.contains("response=\""));
    }

    #[test]
    fn test_digest_authentication_with_opaque() {
        // Test with a challenge that includes opaque parameter
        let challenge = r#"Digest realm="test-realm", nonce="test-nonce-123", qop="auth", opaque="test-opaque-456", algorithm=MD5"#;
        let username = "testuser";
        let password = "testpass";
        let method = "POST";
        let uri = "/api/data";

        let auth = DigestAuth::new(username.to_string(), password.to_string());
        let mut session = auth.create_session();

        // Step 1: Parse the challenge
        assert!(session.parse_challenge(challenge).is_ok());

        // Verify parsed parameters including opaque
        assert_eq!(session.realm, Some("test-realm".to_string()));
        assert_eq!(session.nonce, Some("test-nonce-123".to_string()));
        assert_eq!(session.qop, Some("auth".to_string()));
        assert_eq!(session.algorithm, Algorithm::MD5);
        assert_eq!(session.opaque, Some("test-opaque-456".to_string()));

        // Step 2: Generate the response
        let auth_header = session
            .generate_response_and_increment(method, uri)
            .unwrap();

        // Step 3: Verify the Authorization header includes opaque
        assert!(auth_header.starts_with("Digest algorithm=MD5"));
        assert!(auth_header.contains(&format!("username=\"{}\"", username)));
        assert!(auth_header.contains("realm=\"test-realm\""));
        assert!(auth_header.contains("nonce=\"test-nonce-123\""));
        assert!(auth_header.contains("opaque=\"test-opaque-456\""));
        assert!(auth_header.contains(&format!("uri=\"{}\"", uri)));
        assert!(auth_header.contains("qop=auth"));
        assert!(auth_header.contains("nc=00000001"));
        assert!(auth_header.contains("cnonce=\""));
        assert!(auth_header.contains("response=\""));

        // Verify the opaque parameter appears before realm (as per RFC 2617)
        let opaque_index = auth_header.find("opaque=\"test-opaque-456\"").unwrap();
        let realm_index = auth_header.find("realm=\"test-realm\"").unwrap();
        assert!(
            opaque_index < realm_index,
            "opaque should appear before realm in Authorization header"
        );
    }

    #[test]
    fn test_digest_authentication_without_qop() {
        // Test with a challenge that doesn't include qop (quality of protection)
        let challenge = r#"Digest realm="simple-realm", nonce="simple-nonce-789", algorithm=MD5"#;
        let username = "testuser";
        let password = "testpass";
        let method = "GET";
        let uri = "/simple/path";

        let auth = DigestAuth::new(username.to_string(), password.to_string());
        let mut session = auth.create_session();

        // Step 1: Parse the challenge
        assert!(session.parse_challenge(challenge).is_ok());

        // Verify parsed parameters (no qop)
        assert_eq!(session.realm, Some("simple-realm".to_string()));
        assert_eq!(session.nonce, Some("simple-nonce-789".to_string()));
        assert_eq!(session.algorithm, Algorithm::MD5);
        assert_eq!(session.qop, None);
        assert_eq!(session.opaque, None);

        // Step 2: Generate the response
        let auth_header = session
            .generate_response_and_increment(method, uri)
            .unwrap();

        // Step 3: Verify the Authorization header format (without qop-related fields)
        assert!(auth_header.starts_with("Digest algorithm=MD5"));
        assert!(auth_header.contains(&format!("username=\"{}\"", username)));
        assert!(auth_header.contains("realm=\"simple-realm\""));
        assert!(auth_header.contains("nonce=\"simple-nonce-789\""));
        assert!(auth_header.contains(&format!("uri=\"{}\"", uri)));
        assert!(auth_header.contains("response=\""));

        // Verify qop-related fields are NOT present
        assert!(!auth_header.contains("qop="));
        assert!(!auth_header.contains("nc="));
        assert!(!auth_header.contains("cnonce="));

        // Verify the response format is simpler
        let components = [
            "Digest algorithm=MD5",
            &format!("username=\"{}\"", username),
            "realm=\"simple-realm\"",
            "nonce=\"simple-nonce-789\"",
            &format!("uri=\"{}\"", uri),
            "response=\"",
        ];

        for component in &components {
            assert!(
                auth_header.contains(component),
                "Authorization header missing component: {}",
                component
            );
        }
    }

    #[test]
    fn test_digest_response_hash_calculation() {
        // Test with known values to verify MD5 hash calculation is correct
        let challenge =
            r#"Digest realm="test-realm", nonce="test-nonce", qop="auth", algorithm=MD5"#;
        let username = "testuser";
        let password = "testpass";
        let method = "GET";
        let uri = "/test";

        let auth = DigestAuth::new(username.to_string(), password.to_string());
        let mut session = auth.create_session();

        // Parse challenge
        assert!(session.parse_challenge(challenge).is_ok());

        // Generate response
        let auth_header = session
            .generate_response_and_increment(method, uri)
            .unwrap();

        // Extract the response hash from the Authorization header
        let response_start = auth_header.find("response=\"").unwrap() + 10;
        let response_end = auth_header[response_start..].find("\"").unwrap() + response_start;
        let response_hash = &auth_header[response_start..response_end];

        // Verify the response hash is a valid MD5 hash (32 hex characters)
        assert_eq!(
            response_hash.len(),
            32,
            "Response hash should be 32 characters long"
        );
        assert!(
            response_hash.chars().all(|c| c.is_ascii_hexdigit()),
            "Response hash should contain only hex characters: {}",
            response_hash
        );

        // Extract cnonce for verification
        let cnonce_start = auth_header.find("cnonce=\"").unwrap() + 8;
        let cnonce_end = auth_header[cnonce_start..].find("\"").unwrap() + cnonce_start;
        let cnonce = &auth_header[cnonce_start..cnonce_end];

        // Verify cnonce is a valid hex string
        assert!(
            cnonce.chars().all(|c| c.is_ascii_hexdigit()),
            "Cnonce should contain only hex characters: {}",
            cnonce
        );

        // Manually calculate the expected response hash to verify correctness
        // HA1 = MD5(username:realm:password)
        let ha1_input = format!("{}:{}:{}", username, "test-realm", password);
        let ha1 = auth.md5_hash(&ha1_input);

        // HA2 = MD5(method:uri)
        let ha2_input = format!("{}:{}", method, uri);
        let ha2 = auth.md5_hash(&ha2_input);

        // Response = MD5(HA1:nonce:nc:cnonce:qop:HA2)
        let response_input = format!(
            "{}:{}:{}:{}:{}:{}",
            ha1, "test-nonce", "00000001", cnonce, "auth", ha2
        );
        let expected_response = auth.md5_hash(&response_input);

        // Verify the calculated response matches the generated one
        assert_eq!(
            response_hash, expected_response,
            "Response hash calculation is incorrect. Expected: {}, Got: {}",
            expected_response, response_hash
        );

        // Verify the nonce counter was incremented
        assert_eq!(session.get_nc(), 2);
    }

    #[test]
    fn test_username_in_authorization_header() {
        // This test specifically checks that the username is correctly included in the Authorization header
        // This would have caught the bug where username was hardcoded to "tidb_cloud_user"
        let challenge = r#"Digest realm="tidb.cloud", domain="", nonce="test-nonce", algorithm=MD5, qop="auth", stale=false"#;
        let username = "02DK2LU0"; // Real username from the actual issue
        let password = "test-password";
        let method = "GET";
        let uri = "https://cloud.dev.tidbapi.com/v1beta2/tidbs";

        let auth = DigestAuth::new(username.to_string(), password.to_string());
        let mut session = auth.create_session();

        // Parse challenge
        assert!(session.parse_challenge(challenge).is_ok());

        // Generate response
        let auth_header = session
            .generate_response_and_increment(method, uri)
            .unwrap();

        // CRITICAL: Verify the username is correctly included in the Authorization header
        assert!(
            auth_header.contains(&format!("username=\"{}\"", username)),
            "Authorization header must contain the correct username. Expected: username=\"{}\", Got: {}",
            username,
            auth_header
        );

        // Verify it does NOT contain the hardcoded username that was causing the bug
        assert!(
            !auth_header.contains("username=\"tidb_cloud_user\""),
            "Authorization header should not contain hardcoded username 'tidb_cloud_user'. Got: {}",
            auth_header
        );

        // Verify other required fields are present
        assert!(auth_header.contains("realm=\"tidb.cloud\""));
        assert!(auth_header.contains("nonce=\"test-nonce\""));
        assert!(auth_header.contains("algorithm=MD5"));
        assert!(auth_header.contains("qop=auth"));
    }

    #[test]
    fn test_different_usernames_produce_different_headers() {
        // This test ensures that different usernames actually produce different Authorization headers
        // This would catch issues where the username is ignored or hardcoded
        let challenge =
            r#"Digest realm="test-realm", nonce="test-nonce", qop="auth", algorithm=MD5"#;
        let method = "GET";
        let uri = "/test";

        // Test with first username
        let username1 = "user1";
        let password1 = "pass1";
        let auth1 = DigestAuth::new(username1.to_string(), password1.to_string());
        let mut session1 = auth1.create_session();
        session1.parse_challenge(challenge).unwrap();
        let header1 = session1
            .generate_response_and_increment(method, uri)
            .unwrap();

        // Test with second username
        let username2 = "user2";
        let password2 = "pass2";
        let auth2 = DigestAuth::new(username2.to_string(), password2.to_string());
        let mut session2 = auth2.create_session();
        session2.parse_challenge(challenge).unwrap();
        let header2 = session2
            .generate_response_and_increment(method, uri)
            .unwrap();

        // Verify both headers contain their respective usernames
        assert!(
            header1.contains(&format!("username=\"{}\"", username1)),
            "Header1 should contain username1. Got: {}",
            header1
        );
        assert!(
            header2.contains(&format!("username=\"{}\"", username2)),
            "Header2 should contain username2. Got: {}",
            header2
        );

        // Verify the headers are different (they should be due to different usernames and passwords)
        assert_ne!(
            header1, header2,
            "Headers with different usernames and passwords should be different"
        );
    }

    #[test]
    fn test_real_world_username_scenario() {
        // Test with the exact scenario from the real issue
        let challenge = r#"Digest realm="tidb.cloud", domain="", nonce="98d6e4b67ffe5df8c4cde25278f526eb", algorithm=MD5, qop="auth", stale=false"#;
        let username = "<real-username>"; // Real username from the issue
        let password = "<real-password>"; // Real password from the issue
        let method = "GET";
        let uri = "https://cloud.dev.tidbapi.com/v1beta2/tidbs";

        let auth = DigestAuth::new(username.to_string(), password.to_string());
        let mut session = auth.create_session();

        // Parse challenge
        assert!(session.parse_challenge(challenge).is_ok());

        // Generate response
        let auth_header = session
            .generate_response_and_increment(method, uri)
            .unwrap();

        // Verify the username is correctly included
        assert!(
            auth_header.contains(&format!("username=\"{}\"", username)),
            "Real-world scenario: Authorization header must contain correct username. Expected: username=\"{}\", Got: {}",
            username,
            auth_header
        );

        // Verify the header format matches what we expect from the real logs
        assert!(auth_header.starts_with("Digest algorithm=MD5"));
        assert!(auth_header.contains("realm=\"tidb.cloud\""));
        assert!(auth_header.contains("nonce=\"98d6e4b67ffe5df8c4cde25278f526eb\""));
        assert!(auth_header.contains("qop=auth"));
        assert!(auth_header.contains("nc=00000001"));
        assert!(auth_header.contains("cnonce=\""));
        assert!(auth_header.contains("response=\""));
    }

    #[test]
    fn test_username_escaping_in_authorization_header() {
        // Test that usernames with special characters are properly escaped
        let challenge =
            r#"Digest realm="test-realm", nonce="test-nonce", qop="auth", algorithm=MD5"#;
        let username = "user\"with\"quotes"; // Username with quotes that need escaping
        let password = "testpass";
        let method = "GET";
        let uri = "/test";

        let auth = DigestAuth::new(username.to_string(), password.to_string());
        let mut session = auth.create_session();

        // Parse challenge
        assert!(session.parse_challenge(challenge).is_ok());

        // Generate response
        let auth_header = session
            .generate_response_and_increment(method, uri)
            .unwrap();

        // Verify the username is properly escaped in the Authorization header
        // The username should be escaped as: user\"with\"quotes -> user\\\"with\\\"quotes
        let expected_escaped = "user\\\"with\\\"quotes";
        assert!(
            auth_header.contains(&format!("username=\"{}\"", expected_escaped)),
            "Username with quotes should be properly escaped. Expected: username=\"{}\", Got: {}",
            expected_escaped,
            auth_header
        );
    }

    #[test]
    fn test_authenticate_method_preserves_username() {
        // Test that the convenience authenticate method correctly preserves the username
        let challenge = r#"Digest realm="tidb.cloud", domain="", nonce="test-nonce", algorithm=MD5, qop="auth", stale=false"#;
        let username = "02DK2LU0";
        let password = "test-password";
        let method = "GET";
        let uri = "https://cloud.dev.tidbapi.com/v1beta2/tidbs?";

        let auth = DigestAuth::new(username.to_string(), password.to_string());

        // Use the convenience method
        let auth_header = auth.authenticate(challenge, method, uri).unwrap();

        // Verify the username is correctly included
        assert!(
            auth_header.contains(&format!("username=\"{}\"", username)),
            "Authenticate method must preserve username. Expected: username=\"{}\", Got: {}",
            username,
            auth_header
        );

        // Verify it does NOT contain the hardcoded username
        assert!(
            !auth_header.contains("username=\"tidb_cloud_user\""),
            "Authenticate method should not use hardcoded username. Got: {}",
            auth_header
        );
    }

    #[test]
    fn test_password_affects_response_hash() {
        // Test that different passwords produce different response hashes
        // This verifies that the password is actually used in the Digest calculation
        let challenge =
            r#"Digest realm="test-realm", nonce="test-nonce", qop="auth", algorithm=MD5"#;
        let username = "testuser";
        let password1 = "password1";
        let password2 = "password2";
        let method = "GET";
        let uri = "/test";

        // Test with first password
        let auth1 = DigestAuth::new(username.to_string(), password1.to_string());
        let mut session1 = auth1.create_session();
        session1.parse_challenge(challenge).unwrap();
        let header1 = session1
            .generate_response_and_increment(method, uri)
            .unwrap();

        // Test with second password
        let auth2 = DigestAuth::new(username.to_string(), password2.to_string());
        let mut session2 = auth2.create_session();
        session2.parse_challenge(challenge).unwrap();
        let header2 = session2
            .generate_response_and_increment(method, uri)
            .unwrap();

        // Extract response hashes from the headers
        let response1_start = header1.find("response=\"").unwrap() + 10;
        let response1_end = header1[response1_start..].find("\"").unwrap() + response1_start;
        let response1_hash = &header1[response1_start..response1_end];

        let response2_start = header2.find("response=\"").unwrap() + 10;
        let response2_end = header2[response2_start..].find("\"").unwrap() + response2_start;
        let response2_hash = &header2[response2_start..response2_end];

        // Verify the response hashes are different (due to different passwords)
        assert_ne!(
            response1_hash, response2_hash,
            "Response hashes should be different for different passwords. Got: {} for both",
            response1_hash
        );

        // Verify both headers contain the same username
        assert!(header1.contains(&format!("username=\"{}\"", username)));
        assert!(header2.contains(&format!("username=\"{}\"", username)));
    }

    #[test]
    fn test_password_calculation_verification() {
        // Test that the password is correctly used in the HA1 calculation
        // This verifies the exact formula: HA1 = MD5(username:realm:password)
        let challenge =
            r#"Digest realm="test-realm", nonce="test-nonce", qop="auth", algorithm=MD5"#;
        let username = "testuser";
        let password = "testpass";
        let method = "GET";
        let uri = "/test";

        let auth = DigestAuth::new(username.to_string(), password.to_string());
        let mut session = auth.create_session();
        session.parse_challenge(challenge).unwrap();

        // Generate the response
        let auth_header = session
            .generate_response_and_increment(method, uri)
            .unwrap();

        // Extract the response hash
        let response_start = auth_header.find("response=\"").unwrap() + 10;
        let response_end = auth_header[response_start..].find("\"").unwrap() + response_start;
        let response_hash = &auth_header[response_start..response_end];

        // Extract cnonce for verification
        let cnonce_start = auth_header.find("cnonce=\"").unwrap() + 8;
        let cnonce_end = auth_header[cnonce_start..].find("\"").unwrap() + cnonce_start;
        let cnonce = &auth_header[cnonce_start..cnonce_end];

        // Manually calculate the expected response hash to verify password usage
        // HA1 = MD5(username:realm:password)
        let ha1_input = format!("{}:{}:{}", username, "test-realm", password);
        let ha1 = auth.md5_hash(&ha1_input);

        // HA2 = MD5(method:uri)
        let ha2_input = format!("{}:{}", method, uri);
        let ha2 = auth.md5_hash(&ha2_input);

        // Response = MD5(HA1:nonce:nc:cnonce:qop:HA2)
        let response_input = format!(
            "{}:{}:{}:{}:{}:{}",
            ha1, "test-nonce", "00000001", cnonce, "auth", ha2
        );
        let expected_response = auth.md5_hash(&response_input);

        // Verify the calculated response matches the generated one
        assert_eq!(
            response_hash, expected_response,
            "Password calculation verification failed. Expected: {}, Got: {}",
            expected_response, response_hash
        );

        // Verify that changing the password would change the result
        let wrong_auth = DigestAuth::new(username.to_string(), "wrongpass".to_string());
        let wrong_ha1_input = format!("{}:{}:{}", username, "test-realm", "wrongpass");
        let wrong_ha1 = wrong_auth.md5_hash(&wrong_ha1_input);
        let wrong_response_input = format!(
            "{}:{}:{}:{}:{}:{}",
            wrong_ha1, "test-nonce", "00000001", cnonce, "auth", ha2
        );
        let wrong_expected_response = wrong_auth.md5_hash(&wrong_response_input);

        // Verify the wrong password produces a different response
        assert_ne!(
            response_hash, wrong_expected_response,
            "Wrong password should produce different response hash"
        );
    }

    #[test]
    #[ignore]
    fn test_real_world_password_scenario() {
        // Test with the exact password from the real issue
        let challenge = r#"Digest realm="tidb.cloud", domain="", nonce="98d6e4b67ffe5df8c4cde25278f526eb", algorithm=MD5, qop="auth", stale=false"#;
        let username = "02DK2LU0";
        let password = "083aee24-28fb-49d2-81d0-546c153c9b1e"; // Real password from the issue
        let method = "GET";
        let uri = "https://cloud.dev.tidbapi.com/v1beta2/tidbs";

        let auth = DigestAuth::new(username.to_string(), password.to_string());
        let mut session = auth.create_session();
        session.parse_challenge(challenge).unwrap();

        // Generate response
        let auth_header = session
            .generate_response_and_increment(method, uri)
            .unwrap();

        // Extract the response hash
        let response_start = auth_header.find("response=\"").unwrap() + 10;
        let response_end = auth_header[response_start..].find("\"").unwrap() + response_start;
        let response_hash = &auth_header[response_start..response_end];

        // Verify the response hash is a valid MD5 hash (32 hex characters)
        assert_eq!(
            response_hash.len(),
            32,
            "Response hash should be 32 characters long"
        );
        assert!(
            response_hash.chars().all(|c| c.is_ascii_hexdigit()),
            "Response hash should contain only hex characters: {}",
            response_hash
        );

        // Manually calculate the expected response hash with the real password
        let ha1_input = format!("{}:{}:{}", username, "tidb.cloud", password);
        let ha1 = auth.md5_hash(&ha1_input);

        let ha2_input = format!("{}:{}", method, uri);
        let ha2 = auth.md5_hash(&ha2_input);

        // Extract cnonce for verification
        let cnonce_start = auth_header.find("cnonce=\"").unwrap() + 8;
        let cnonce_end = auth_header[cnonce_start..].find("\"").unwrap() + cnonce_start;
        let cnonce = &auth_header[cnonce_start..cnonce_end];

        let response_input = format!(
            "{}:{}:{}:{}:{}:{}",
            ha1, "98d6e4b67ffe5df8c4cde25278f526eb", "00000001", cnonce, "auth", ha2
        );
        let expected_response = auth.md5_hash(&response_input);

        // Verify the calculated response matches the generated one
        assert_eq!(
            response_hash, expected_response,
            "Real-world password scenario: Response hash calculation failed. Expected: {}, Got: {}",
            expected_response, response_hash
        );

        // Verify that using a wrong password would produce a different result
        let wrong_auth = DigestAuth::new(username.to_string(), "wrong-password".to_string());
        let wrong_ha1_input = format!("{}:{}:{}", username, "tidb.cloud", "wrong-password");
        let wrong_ha1 = wrong_auth.md5_hash(&wrong_ha1_input);
        let wrong_response_input = format!(
            "{}:{}:{}:{}:{}:{}",
            wrong_ha1, "98d6e4b67ffe5df8c4cde25278f526eb", "00000001", cnonce, "auth", ha2
        );
        let wrong_expected_response = wrong_auth.md5_hash(&wrong_response_input);

        assert_ne!(
            response_hash, wrong_expected_response,
            "Wrong password should produce different response hash in real-world scenario"
        );
    }

    #[test]
    fn test_password_escaping_in_calculation() {
        // Test that passwords with special characters are handled correctly in the calculation
        let challenge =
            r#"Digest realm="test-realm", nonce="test-nonce", qop="auth", algorithm=MD5"#;
        let username = "testuser";
        let password = "pass:word:with:colons"; // Password with colons that could interfere with parsing
        let method = "GET";
        let uri = "/test";

        let auth = DigestAuth::new(username.to_string(), password.to_string());
        let mut session = auth.create_session();
        session.parse_challenge(challenge).unwrap();

        // Generate response
        let auth_header = session
            .generate_response_and_increment(method, uri)
            .unwrap();

        // Extract the response hash
        let response_start = auth_header.find("response=\"").unwrap() + 10;
        let response_end = auth_header[response_start..].find("\"").unwrap() + response_start;
        let response_hash = &auth_header[response_start..response_end];

        // Manually calculate the expected response hash
        let ha1_input = format!("{}:{}:{}", username, "test-realm", password);
        let ha1 = auth.md5_hash(&ha1_input);

        let ha2_input = format!("{}:{}", method, uri);
        let ha2 = auth.md5_hash(&ha2_input);

        // Extract cnonce for verification
        let cnonce_start = auth_header.find("cnonce=\"").unwrap() + 8;
        let cnonce_end = auth_header[cnonce_start..].find("\"").unwrap() + cnonce_start;
        let cnonce = &auth_header[cnonce_start..cnonce_end];

        let response_input = format!(
            "{}:{}:{}:{}:{}:{}",
            ha1, "test-nonce", "00000001", cnonce, "auth", ha2
        );
        let expected_response = auth.md5_hash(&response_input);

        // Verify the calculated response matches the generated one
        assert_eq!(
            response_hash, expected_response,
            "Password with special characters: Response hash calculation failed. Expected: {}, Got: {}",
            expected_response, response_hash
        );
    }
}
