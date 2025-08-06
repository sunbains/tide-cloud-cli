use crate::dsl::error::DSLError;
use crate::dsl::syntax::DSLValue;
use std::collections::HashMap;

/// Result of executing a DSL command
#[derive(Debug)]
pub struct DSLResult {
    pub success: bool,
    pub data: Option<DSLValue>,
    pub message: Option<String>,
    pub error: Option<DSLError>,
    pub metadata: HashMap<String, DSLValue>,
}

impl DSLResult {
    pub fn success() -> Self {
        Self {
            success: true,
            data: None,
            message: None,
            error: None,
            metadata: HashMap::new(),
        }
    }

    pub fn success_with_data(data: DSLValue) -> Self {
        Self {
            success: true,
            data: Some(data),
            message: None,
            error: None,
            metadata: HashMap::new(),
        }
    }

    pub fn success_with_message(message: impl Into<String>) -> Self {
        Self {
            success: true,
            data: None,
            message: Some(message.into()),
            error: None,
            metadata: HashMap::new(),
        }
    }

    pub fn success_with_data_and_message(data: DSLValue, message: impl Into<String>) -> Self {
        Self {
            success: true,
            data: Some(data),
            message: Some(message.into()),
            error: None,
            metadata: HashMap::new(),
        }
    }

    pub fn failure(error: DSLError) -> Self {
        Self {
            success: false,
            data: None,
            message: None,
            error: Some(error),
            metadata: HashMap::new(),
        }
    }

    pub fn failure_with_message(message: impl Into<String>) -> Self {
        Self {
            success: false,
            data: None,
            message: Some(message.into()),
            error: None,
            metadata: HashMap::new(),
        }
    }

    pub fn with_metadata(mut self, key: impl Into<String>, value: DSLValue) -> Self {
        self.metadata.insert(key.into(), value);
        self
    }

    pub fn with_metadata_map(mut self, metadata: HashMap<String, DSLValue>) -> Self {
        self.metadata = metadata;
        self
    }

    pub fn get_metadata(&self, key: &str) -> Option<&DSLValue> {
        self.metadata.get(key)
    }

    pub fn is_success(&self) -> bool {
        self.success
    }

    pub fn is_failure(&self) -> bool {
        !self.success
    }

    pub fn get_data(&self) -> Option<&DSLValue> {
        self.data.as_ref()
    }

    pub fn get_message(&self) -> Option<&str> {
        self.message.as_deref()
    }

    pub fn get_error(&self) -> Option<&DSLError> {
        self.error.as_ref()
    }
}

impl From<DSLValue> for DSLResult {
    fn from(value: DSLValue) -> Self {
        DSLResult::success_with_data(value)
    }
}

impl From<DSLError> for DSLResult {
    fn from(error: DSLError) -> Self {
        DSLResult::failure(error)
    }
}

impl From<String> for DSLResult {
    fn from(message: String) -> Self {
        DSLResult::success_with_message(message)
    }
}

impl From<&str> for DSLResult {
    fn from(message: &str) -> Self {
        DSLResult::success_with_message(message)
    }
}

/// Batch execution result
#[derive(Debug)]
pub struct DSLBatchResult {
    pub results: Vec<DSLResult>,
    pub success_count: usize,
    pub failure_count: usize,
    pub total_duration: std::time::Duration,
}

impl DSLBatchResult {
    pub fn new() -> Self {
        Self {
            results: Vec::new(),
            success_count: 0,
            failure_count: 0,
            total_duration: std::time::Duration::ZERO,
        }
    }

    pub fn add_result(&mut self, result: DSLResult) {
        if result.is_success() {
            self.success_count += 1;
        } else {
            self.failure_count += 1;
        }
        self.results.push(result);
    }

    pub fn set_duration(&mut self, duration: std::time::Duration) {
        self.total_duration = duration;
    }

    pub fn is_all_success(&self) -> bool {
        self.failure_count == 0
    }

    pub fn is_all_failure(&self) -> bool {
        self.success_count == 0
    }

    pub fn get_successful_results(&self) -> Vec<&DSLResult> {
        self.results.iter().filter(|r| r.is_success()).collect()
    }

    pub fn get_failed_results(&self) -> Vec<&DSLResult> {
        self.results.iter().filter(|r| r.is_failure()).collect()
    }

    pub fn get_first_error(&self) -> Option<&DSLError> {
        self.results.iter().find_map(|r| r.get_error())
    }

    pub fn get_all_errors(&self) -> Vec<&DSLError> {
        self.results.iter().filter_map(|r| r.get_error()).collect()
    }
}

impl Default for DSLBatchResult {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dsl_result_success() {
        let result = DSLResult::success();
        assert!(result.is_success());
        assert!(!result.is_failure());
        assert!(result.get_error().is_none());
    }

    #[test]
    fn test_dsl_result_success_with_data() {
        let data = DSLValue::from("test");
        let result = DSLResult::success_with_data(data.clone());
        assert!(result.is_success());
        assert_eq!(result.get_data(), Some(&data));
    }

    #[test]
    fn test_dsl_result_success_with_message() {
        let result = DSLResult::success_with_message("Operation completed");
        assert!(result.is_success());
        assert_eq!(result.get_message(), Some("Operation completed"));
    }

    #[test]
    fn test_dsl_result_failure() {
        let error = DSLError::syntax_error(0, "Test error");
        let result = DSLResult::failure(error);
        assert!(!result.is_success());
        assert!(result.is_failure());
        assert!(result.get_error().is_some());
    }

    #[test]
    fn test_dsl_result_with_metadata() {
        let result = DSLResult::success().with_metadata("duration", DSLValue::from(100.0));

        assert_eq!(
            result.get_metadata("duration"),
            Some(&DSLValue::from(100.0))
        );
    }

    #[test]
    fn test_dsl_batch_result_new() {
        let batch = DSLBatchResult::new();
        assert_eq!(batch.success_count, 0);
        assert_eq!(batch.failure_count, 0);
        assert!(batch.results.is_empty());
    }

    #[test]
    fn test_dsl_batch_result_add_success() {
        let mut batch = DSLBatchResult::new();
        batch.add_result(DSLResult::success());

        assert_eq!(batch.success_count, 1);
        assert_eq!(batch.failure_count, 0);
        assert!(batch.is_all_success());
    }

    #[test]
    fn test_dsl_batch_result_add_failure() {
        let mut batch = DSLBatchResult::new();
        batch.add_result(DSLResult::failure(DSLError::syntax_error(0, "Test error")));

        assert_eq!(batch.success_count, 0);
        assert_eq!(batch.failure_count, 1);
        assert!(batch.is_all_failure());
    }

    #[test]
    fn test_dsl_batch_result_mixed_results() {
        let mut batch = DSLBatchResult::new();
        batch.add_result(DSLResult::success());
        batch.add_result(DSLResult::failure(DSLError::syntax_error(0, "Test error")));

        assert_eq!(batch.success_count, 1);
        assert_eq!(batch.failure_count, 1);
        assert!(!batch.is_all_success());
        assert!(!batch.is_all_failure());
    }
}
