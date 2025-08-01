use crate::dsl::error::DSLError;
use crate::dsl::syntax::DSLValue;
use std::collections::HashMap;

/// A DSL command that can be executed
#[derive(Debug, Clone)]
pub struct DSLCommand {
    pub command_type: DSLCommandType,
    pub parameters: HashMap<String, DSLValue>,
    pub context: CommandContext,
}

/// Types of DSL commands
#[derive(Debug, Clone, PartialEq)]
pub enum DSLCommandType {
    // Cluster management
    CreateCluster,
    DeleteCluster,
    ListClusters,
    GetCluster,
    UpdateCluster,
    WaitForCluster,

    // Backup management
    CreateBackup,
    ListBackups,
    DeleteBackup,
    RestoreBackup,

    // Pricing
    EstimatePrice,
    GetPricing,

    // Control flow
    If,
    Loop,
    Break,
    Continue,
    Return,

    // Variables
    SetVariable,
    GetVariable,

    // Utility
    Echo,
    Sleep,
    Exit,

    // Logging
    SetLogLevel,
}

/// Command execution context
#[derive(Debug, Clone)]
pub struct CommandContext {
    pub line: usize,
    pub column: usize,
    pub variables: HashMap<String, DSLValue>,
    pub parent_context: Option<Box<CommandContext>>,
}

impl Default for CommandContext {
    fn default() -> Self {
        Self::new()
    }
}

impl CommandContext {
    pub fn new() -> Self {
        Self {
            line: 0,
            column: 0,
            variables: HashMap::new(),
            parent_context: None,
        }
    }

    pub fn with_location(mut self, line: usize, column: usize) -> Self {
        self.line = line;
        self.column = column;
        self
    }

    pub fn with_variables(mut self, variables: HashMap<String, DSLValue>) -> Self {
        self.variables = variables;
        self
    }

    pub fn with_parent(mut self, parent: CommandContext) -> Self {
        self.parent_context = Some(Box::new(parent));
        self
    }

    pub fn get_variable(&self, name: &str) -> Option<&DSLValue> {
        self.variables.get(name).or_else(|| {
            self.parent_context
                .as_ref()
                .and_then(|parent| parent.get_variable(name))
        })
    }

    pub fn set_variable(&mut self, name: String, value: DSLValue) {
        self.variables.insert(name, value);
    }

    pub fn has_variable(&self, name: &str) -> bool {
        self.variables.contains_key(name)
            || self
                .parent_context
                .as_ref()
                .is_some_and(|parent| parent.has_variable(name))
    }
}

impl DSLCommand {
    pub fn new(command_type: DSLCommandType) -> Self {
        Self {
            command_type,
            parameters: HashMap::new(),
            context: CommandContext::new(),
        }
    }

    pub fn with_parameter(mut self, name: impl Into<String>, value: DSLValue) -> Self {
        self.parameters.insert(name.into(), value);
        self
    }

    pub fn with_parameters(mut self, parameters: HashMap<String, DSLValue>) -> Self {
        self.parameters = parameters;
        self
    }

    pub fn with_context(mut self, context: CommandContext) -> Self {
        self.context = context;
        self
    }

    pub fn get_parameter(&self, name: &str) -> Option<&DSLValue> {
        self.parameters.get(name)
    }

    pub fn get_parameter_as_string(&self, name: &str) -> Result<&str, DSLError> {
        self.parameters
            .get(name)
            .and_then(|v| v.as_string())
            .ok_or_else(|| {
                DSLError::missing_parameter(format!("{:?}", self.command_type), name.to_string())
            })
    }

    pub fn get_parameter_as_number(&self, name: &str) -> Result<f64, DSLError> {
        self.parameters
            .get(name)
            .and_then(|v| v.as_number())
            .ok_or_else(|| {
                DSLError::missing_parameter(format!("{:?}", self.command_type), name.to_string())
            })
    }

    pub fn get_parameter_as_boolean(&self, name: &str) -> Result<bool, DSLError> {
        self.parameters
            .get(name)
            .and_then(|v| v.as_boolean())
            .ok_or_else(|| {
                DSLError::missing_parameter(format!("{:?}", self.command_type), name.to_string())
            })
    }

    pub fn require_parameter(&self, name: &str) -> Result<&DSLValue, DSLError> {
        self.parameters.get(name).ok_or_else(|| {
            DSLError::missing_parameter(format!("{:?}", self.command_type), name.to_string())
        })
    }

    pub fn get_optional_parameter(&self, name: &str) -> Option<&DSLValue> {
        self.parameters.get(name)
    }
}

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

/// Command factory for creating common commands
pub struct DSLCommandFactory;

impl DSLCommandFactory {
    pub fn create_cluster(name: impl Into<String>, region: impl Into<String>) -> DSLCommand {
        DSLCommand::new(DSLCommandType::CreateCluster)
            .with_parameter("name", DSLValue::from(name.into()))
            .with_parameter("region", DSLValue::from(region.into()))
    }

    pub fn delete_cluster(name: impl Into<String>) -> DSLCommand {
        DSLCommand::new(DSLCommandType::DeleteCluster)
            .with_parameter("name", DSLValue::from(name.into()))
    }

    pub fn list_clusters() -> DSLCommand {
        DSLCommand::new(DSLCommandType::ListClusters)
    }

    pub fn get_cluster(name: impl Into<String>) -> DSLCommand {
        DSLCommand::new(DSLCommandType::GetCluster)
            .with_parameter("name", DSLValue::from(name.into()))
    }

    pub fn wait_for_cluster(name: impl Into<String>, state: impl Into<String>) -> DSLCommand {
        DSLCommand::new(DSLCommandType::WaitForCluster)
            .with_parameter("name", DSLValue::from(name.into()))
            .with_parameter("state", DSLValue::from(state.into()))
    }

    pub fn create_backup(cluster_name: impl Into<String>) -> DSLCommand {
        DSLCommand::new(DSLCommandType::CreateBackup)
            .with_parameter("cluster_name", DSLValue::from(cluster_name.into()))
    }

    pub fn list_backups(cluster_name: impl Into<String>) -> DSLCommand {
        DSLCommand::new(DSLCommandType::ListBackups)
            .with_parameter("cluster_name", DSLValue::from(cluster_name.into()))
    }

    pub fn estimate_price(
        region: impl Into<String>,
        min_rcu: impl Into<String>,
        max_rcu: impl Into<String>,
        service_plan: impl Into<String>,
    ) -> DSLCommand {
        DSLCommand::new(DSLCommandType::EstimatePrice)
            .with_parameter("region", DSLValue::from(region.into()))
            .with_parameter("min_rcu", DSLValue::from(min_rcu.into()))
            .with_parameter("max_rcu", DSLValue::from(max_rcu.into()))
            .with_parameter("service_plan", DSLValue::from(service_plan.into()))
    }

    pub fn set_variable(name: impl Into<String>, value: DSLValue) -> DSLCommand {
        DSLCommand::new(DSLCommandType::SetVariable)
            .with_parameter("name", DSLValue::from(name.into()))
            .with_parameter("value", value)
    }

    pub fn echo(message: impl Into<String>) -> DSLCommand {
        DSLCommand::new(DSLCommandType::Echo)
            .with_parameter("message", DSLValue::from(message.into()))
    }

    pub fn sleep(seconds: f64) -> DSLCommand {
        DSLCommand::new(DSLCommandType::Sleep).with_parameter("seconds", DSLValue::from(seconds))
    }

    pub fn set_log_level(level: impl Into<String>) -> DSLCommand {
        DSLCommand::new(DSLCommandType::SetLogLevel)
            .with_parameter("level", DSLValue::from(level.into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dsl_command_new() {
        let command = DSLCommand::new(DSLCommandType::CreateCluster);
        assert_eq!(command.command_type, DSLCommandType::CreateCluster);
        assert!(command.parameters.is_empty());
    }

    #[test]
    fn test_dsl_command_with_parameter() {
        let command = DSLCommand::new(DSLCommandType::CreateCluster)
            .with_parameter("name", DSLValue::from("test-cluster"));

        assert_eq!(
            command.get_parameter("name"),
            Some(&DSLValue::from("test-cluster"))
        );
    }

    #[test]
    fn test_dsl_command_get_parameter_as_string() {
        let command = DSLCommand::new(DSLCommandType::CreateCluster)
            .with_parameter("name", DSLValue::from("test-cluster"));

        assert_eq!(
            command.get_parameter_as_string("name").unwrap(),
            "test-cluster"
        );
    }

    #[test]
    fn test_dsl_command_get_parameter_as_string_error() {
        let command = DSLCommand::new(DSLCommandType::CreateCluster)
            .with_parameter("name", DSLValue::from(42));

        assert!(command.get_parameter_as_string("name").is_err());
    }

    #[test]
    fn test_dsl_command_get_parameter_as_number() {
        let command =
            DSLCommand::new(DSLCommandType::Sleep).with_parameter("seconds", DSLValue::from(5.5));

        assert_eq!(command.get_parameter_as_number("seconds").unwrap(), 5.5);
    }

    #[test]
    fn test_dsl_command_get_parameter_as_number_error() {
        let command = DSLCommand::new(DSLCommandType::Sleep)
            .with_parameter("seconds", DSLValue::from("not-a-number"));

        assert!(command.get_parameter_as_number("seconds").is_err());
    }

    #[test]
    fn test_dsl_command_require_parameter() {
        let command = DSLCommand::new(DSLCommandType::CreateCluster)
            .with_parameter("name", DSLValue::from("test-cluster"));

        assert_eq!(
            command.require_parameter("name").unwrap(),
            &DSLValue::from("test-cluster")
        );
    }

    #[test]
    fn test_dsl_command_require_parameter_missing() {
        let command = DSLCommand::new(DSLCommandType::CreateCluster);

        assert!(command.require_parameter("name").is_err());
    }

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

    #[test]
    fn test_command_context_new() {
        let context = CommandContext::new();
        assert_eq!(context.line, 0);
        assert_eq!(context.column, 0);
        assert!(context.variables.is_empty());
        assert!(context.parent_context.is_none());
    }

    #[test]
    fn test_command_context_with_location() {
        let context = CommandContext::new().with_location(10, 5);
        assert_eq!(context.line, 10);
        assert_eq!(context.column, 5);
    }

    #[test]
    fn test_command_context_variables() {
        let mut context = CommandContext::new();
        context.set_variable("test_var".to_string(), DSLValue::from("test_value"));

        assert!(context.has_variable("test_var"));
        assert_eq!(
            context.get_variable("test_var"),
            Some(&DSLValue::from("test_value"))
        );
    }

    #[test]
    fn test_dsl_command_factory_create_cluster() {
        let command = DSLCommandFactory::create_cluster("test-cluster", "aws-us-west-1");
        assert_eq!(command.command_type, DSLCommandType::CreateCluster);
        assert_eq!(
            command.get_parameter_as_string("name").unwrap(),
            "test-cluster"
        );
        assert_eq!(
            command.get_parameter_as_string("region").unwrap(),
            "aws-us-west-1"
        );
    }

    #[test]
    fn test_dsl_command_factory_delete_cluster() {
        let command = DSLCommandFactory::delete_cluster("test-cluster");
        assert_eq!(command.command_type, DSLCommandType::DeleteCluster);
        assert_eq!(
            command.get_parameter_as_string("name").unwrap(),
            "test-cluster"
        );
    }

    #[test]
    fn test_dsl_command_factory_list_clusters() {
        let command = DSLCommandFactory::list_clusters();
        assert_eq!(command.command_type, DSLCommandType::ListClusters);
        assert!(command.parameters.is_empty());
    }

    #[test]
    fn test_dsl_command_factory_echo() {
        let command = DSLCommandFactory::echo("Hello, World!");
        assert_eq!(command.command_type, DSLCommandType::Echo);
        assert_eq!(
            command.get_parameter_as_string("message").unwrap(),
            "Hello, World!"
        );
    }

    #[test]
    fn test_dsl_command_factory_sleep() {
        let command = DSLCommandFactory::sleep(5.5);
        assert_eq!(command.command_type, DSLCommandType::Sleep);
        assert_eq!(command.get_parameter_as_number("seconds").unwrap(), 5.5);
    }
}
