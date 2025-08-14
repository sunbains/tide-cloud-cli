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
#[derive(Clone)]
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
