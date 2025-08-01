

/// Query parameter builder for common operations
pub struct QueryBuilder {
    params: Vec<(String, String)>,
}

impl QueryBuilder {
    pub fn new() -> Self {
        Self { params: Vec::new() }
    }

    /// Add a validate_only parameter
    pub fn validate_only(mut self, validate: bool) -> Self {
        self.params.push(("validateOnly".to_string(), validate.to_string()));
        self
    }

    /// Add a page_token parameter
    pub fn page_token(mut self, token: Option<String>) -> Self {
        if let Some(token) = token {
            self.params.push(("pageToken".to_string(), token));
        }
        self
    }

    /// Add a page_size parameter
    pub fn page_size(mut self, size: Option<u32>) -> Self {
        if let Some(size) = size {
            self.params.push(("pageSize".to_string(), size.to_string()));
        }
        self
    }

    /// Add a custom parameter
    pub fn param(mut self, key: &str, value: &str) -> Self {
        self.params.push((key.to_string(), value.to_string()));
        self
    }

    /// Build the query string
    pub fn build(self) -> Option<String> {
        if self.params.is_empty() {
            None
        } else {
            let query = self.params
                .iter()
                .map(|(k, v)| format!("{}={}", k, v))
                .collect::<Vec<_>>()
                .join("&");
            Some(query)
        }
    }
}

impl Default for QueryBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Common operation parameters
#[derive(Debug, Clone)]
pub struct CommonParams {
    pub validate_only: Option<bool>,
    pub page_token: Option<String>,
    pub page_size: Option<u32>,
}

impl CommonParams {
    pub fn new() -> Self {
        Self {
            validate_only: None,
            page_token: None,
            page_size: None,
        }
    }

    pub fn with_validate_only(mut self, validate: bool) -> Self {
        self.validate_only = Some(validate);
        self
    }

    pub fn with_page_token(mut self, token: String) -> Self {
        self.page_token = Some(token);
        self
    }

    pub fn with_page_size(mut self, size: u32) -> Self {
        self.page_size = Some(size);
        self
    }

    /// Build query string from common parameters
    pub fn build_query(&self) -> Option<String> {
        let mut builder = QueryBuilder::new();
        
        if let Some(validate) = self.validate_only {
            builder = builder.validate_only(validate);
        }
        
        builder = builder.page_token(self.page_token.clone());
        builder = builder.page_size(self.page_size);
        
        builder.build()
    }
}

impl Default for CommonParams {
    fn default() -> Self {
        Self::new()
    }
}

/// Path builder for consistent URL construction
pub struct PathBuilder {
    segments: Vec<String>,
}

impl PathBuilder {
    pub fn new() -> Self {
        Self { segments: Vec::new() }
    }

    /// Add a path segment
    pub fn segment(mut self, segment: &str) -> Self {
        self.segments.push(segment.to_string());
        self
    }

    /// Add tidb_id segment
    pub fn tidb_id(self, tidb_id: &str) -> Self {
        self.segment("tidbs").segment(tidb_id)
    }

    /// Add backup_id segment
    pub fn backup_id(self, backup_id: &str) -> Self {
        self.segment("backups").segment(backup_id)
    }

    /// Add backup setting segment
    pub fn backup_setting(self) -> Self {
        self.segment("backupSetting")
    }

    /// Add cloud provider info segment
    pub fn cloud_provider_info(self) -> Self {
        self.segment("cloudProviderInfo")
    }

    /// Add restore status segment
    pub fn restore_status(self) -> Self {
        self.segment("restoreStatus")
    }

    /// Add reset root password segment
    pub fn reset_root_password(self) -> Self {
        self.segment("resetRootPassword")
    }

    /// Build the path
    pub fn build(self) -> String {
        format!("/{}", self.segments.join("/"))
    }
}

impl Default for PathBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Helper trait for operations that support validation
pub trait ValidateOnly {
    fn with_validate_only(self, validate: bool) -> Self;
}

/// Helper trait for operations that support pagination
pub trait Paginated {
    fn with_page_token(self, token: String) -> Self;
    fn with_page_size(self, size: u32) -> Self;
}

/// Helper trait for building operation parameters
pub trait OperationParams {
    fn build_query(&self) -> Option<String>;
}

impl OperationParams for CommonParams {
    fn build_query(&self) -> Option<String> {
        self.build_query()
    }
}

/// Helper for building operation requests with common parameters
pub struct OperationBuilder {
    path: PathBuilder,
    params: CommonParams,
}

impl OperationBuilder {
    pub fn new() -> Self {
        Self {
            path: PathBuilder::new(),
            params: CommonParams::new(),
        }
    }

    pub fn path(mut self, path: PathBuilder) -> Self {
        self.path = path;
        self
    }

    pub fn params(mut self, params: CommonParams) -> Self {
        self.params = params;
        self
    }

    pub fn validate_only(mut self, validate: bool) -> Self {
        self.params = self.params.with_validate_only(validate);
        self
    }

    pub fn page_token(mut self, token: String) -> Self {
        self.params = self.params.with_page_token(token);
        self
    }

    pub fn page_size(mut self, size: u32) -> Self {
        self.params = self.params.with_page_size(size);
        self
    }

    pub fn build(self) -> (String, Option<String>) {
        (self.path.build(), self.params.build_query())
    }
}

impl Default for OperationBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_query_builder() {
        let query = QueryBuilder::new()
            .validate_only(true)
            .page_token(Some("token123".to_string()))
            .page_size(Some(50))
            .build();

        assert_eq!(query, Some("validateOnly=true&pageToken=token123&pageSize=50".to_string()));
    }

    #[test]
    fn test_query_builder_empty() {
        let query = QueryBuilder::new().build();
        assert_eq!(query, None);
    }

    #[test]
    fn test_common_params() {
        let params = CommonParams::new()
            .with_validate_only(true)
            .with_page_token("token123".to_string())
            .with_page_size(50);

        let query = params.build_query();
        assert_eq!(query, Some("validateOnly=true&pageToken=token123&pageSize=50".to_string()));
    }

    #[test]
    fn test_path_builder() {
        let path = PathBuilder::new()
            .tidb_id("tidb123")
            .backup_setting()
            .build();

        assert_eq!(path, "/tidbs/tidb123/backupSetting");
    }

    #[test]
    fn test_operation_builder() {
        let (path, query) = OperationBuilder::new()
            .path(PathBuilder::new().tidb_id("tidb123").backup_setting())
            .validate_only(true)
            .page_token("token123".to_string())
            .build();

        assert_eq!(path, "/tidbs/tidb123/backupSetting");
        assert_eq!(query, Some("validateOnly=true&pageToken=token123".to_string()));
    }
} 