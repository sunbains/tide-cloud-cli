use std::fmt;
use thiserror::Error;

/// DSL-specific error types
#[derive(Error, Debug)]
pub enum DSLError {
    /// Syntax error in DSL command
    #[error("Syntax error at position {}: {}", position, message)]
    SyntaxError {
        position: usize,
        message: String,
    },

    /// Unknown command
    #[error("Unknown command: {}", command)]
    UnknownCommand {
        command: String,
    },

    /// Missing required parameter
    #[error("Missing required parameter '{}' for command '{}'", parameter, command)]
    MissingParameter {
        command: String,
        parameter: String,
    },

    /// Invalid parameter value
    #[error("Invalid value '{}' for parameter '{}': {}", value, parameter, reason)]
    InvalidParameter {
        parameter: String,
        value: String,
        reason: String,
    },

    /// Execution error from underlying TiDB Cloud client
    #[error("Execution error: {}", message)]
    ExecutionError {
        message: String,
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    /// Type mismatch error
    #[error("Type mismatch: expected {}, got {}", expected, got)]
    TypeMismatch {
        expected: String,
        got: String,
    },

    /// Variable not found
    #[error("Variable '{}' not found", name)]
    VariableNotFound {
        name: String,
    },

    /// Invalid expression
    #[error("Invalid expression: {}", expression)]
    InvalidExpression {
        expression: String,
    },

    /// Script parsing error
    #[error("Script parsing error: {}", message)]
    ScriptError {
        message: String,
        line: Option<usize>,
        column: Option<usize>,
    },

    /// Batch execution error
    #[error("Batch execution failed at command {}: {}", command_index, message)]
    BatchError {
        command_index: usize,
        message: String,
    },

    /// Timeout error
    #[error("Operation timed out after {} seconds", timeout_seconds)]
    TimeoutError {
        timeout_seconds: u64,
    },

    /// Resource not found
    #[error("Resource '{}' not found", resource)]
    ResourceNotFound {
        resource: String,
    },

    /// Permission denied
    #[error("Permission denied: {}", operation)]
    PermissionDenied {
        operation: String,
    },
}

impl DSLError {
    /// Create a syntax error
    pub fn syntax_error(position: usize, message: impl Into<String>) -> Self {
        Self::SyntaxError {
            position,
            message: message.into(),
        }
    }

    /// Create an unknown command error
    pub fn unknown_command(command: impl Into<String>) -> Self {
        Self::UnknownCommand {
            command: command.into(),
        }
    }

    /// Create a missing parameter error
    pub fn missing_parameter(command: impl Into<String>, parameter: impl Into<String>) -> Self {
        Self::MissingParameter {
            command: command.into(),
            parameter: parameter.into(),
        }
    }

    /// Create an invalid parameter error
    pub fn invalid_parameter(
        parameter: impl Into<String>,
        value: impl Into<String>,
        reason: impl Into<String>,
    ) -> Self {
        Self::InvalidParameter {
            parameter: parameter.into(),
            value: value.into(),
            reason: reason.into(),
        }
    }

    /// Create an execution error
    pub fn execution_error(message: impl Into<String>) -> Self {
        Self::ExecutionError {
            message: message.into(),
            source: None,
        }
    }

    /// Create an execution error with source
    pub fn execution_error_with_source(message: impl Into<String>, source: impl Into<String>) -> Self {
        Self::ExecutionError {
            message: message.into(),
            source: Some(Box::new(std::io::Error::new(
                std::io::ErrorKind::Other,
                source.into()
            ))),
        }
    }

    /// Create a type mismatch error
    pub fn type_mismatch(expected: impl Into<String>, got: impl Into<String>) -> Self {
        Self::TypeMismatch {
            expected: expected.into(),
            got: got.into(),
        }
    }

    /// Create a variable not found error
    pub fn variable_not_found(name: impl Into<String>) -> Self {
        Self::VariableNotFound {
            name: name.into(),
        }
    }

    /// Create an invalid expression error
    pub fn invalid_expression(expression: impl Into<String>) -> Self {
        Self::InvalidExpression {
            expression: expression.into(),
        }
    }

    /// Create a script error
    pub fn script_error(message: impl Into<String>) -> Self {
        Self::ScriptError {
            message: message.into(),
            line: None,
            column: None,
        }
    }

    /// Create a script error with line and column information
    pub fn script_error_with_location(
        message: impl Into<String>,
        line: usize,
        column: usize,
    ) -> Self {
        Self::ScriptError {
            message: message.into(),
            line: Some(line),
            column: Some(column),
        }
    }

    /// Create a batch error
    pub fn batch_error(command_index: usize, message: impl Into<String>) -> Self {
        Self::BatchError {
            command_index,
            message: message.into(),
        }
    }

    /// Create a timeout error
    pub fn timeout_error(timeout_seconds: u64) -> Self {
        Self::TimeoutError { timeout_seconds }
    }

    /// Create a resource not found error
    pub fn resource_not_found(resource: impl Into<String>) -> Self {
        Self::ResourceNotFound {
            resource: resource.into(),
        }
    }

    /// Create a permission denied error
    pub fn permission_denied(operation: impl Into<String>) -> Self {
        Self::PermissionDenied {
            operation: operation.into(),
        }
    }
}

/// Result type for DSL operations
pub type DSLResult<T> = Result<T, DSLError>;

/// Error context for better error reporting
#[derive(Debug, Clone)]
pub struct ErrorContext {
    pub line: Option<usize>,
    pub column: Option<usize>,
    pub command: Option<String>,
    pub variables: std::collections::HashMap<String, String>,
}

impl ErrorContext {
    pub fn new() -> Self {
        Self {
            line: None,
            column: None,
            command: None,
            variables: std::collections::HashMap::new(),
        }
    }

    pub fn with_line(mut self, line: usize) -> Self {
        self.line = Some(line);
        self
    }

    pub fn with_column(mut self, column: usize) -> Self {
        self.column = Some(column);
        self
    }

    pub fn with_command(mut self, command: impl Into<String>) -> Self {
        self.command = Some(command.into());
        self
    }

    pub fn with_variable(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.variables.insert(name.into(), value.into());
        self
    }
}

impl fmt::Display for ErrorContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(line) = self.line {
            write!(f, "line {}", line)?;
            if let Some(column) = self.column {
                write!(f, ", column {}", column)?;
            }
        }
        
        if let Some(command) = &self.command {
            write!(f, " in command '{}'", command)?;
        }
        
        if !self.variables.is_empty() {
            write!(f, " with variables: {:?}", self.variables)?;
        }
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    #[test]
    fn test_syntax_error() {
        let error = DSLError::syntax_error(10, "Unexpected token");
        assert_eq!(error.to_string(), "Syntax error at position 10: Unexpected token");
    }

    #[test]
    fn test_unknown_command() {
        let error = DSLError::unknown_command("INVALID_CMD");
        assert_eq!(error.to_string(), "Unknown command: INVALID_CMD");
    }

    #[test]
    fn test_missing_parameter() {
        let error = DSLError::missing_parameter("CREATE", "name");
        assert_eq!(error.to_string(), "Missing required parameter 'name' for command 'CREATE'");
    }

    #[test]
    fn test_invalid_parameter() {
        let error = DSLError::invalid_parameter("region", "invalid-region", "Not a valid region");
        assert_eq!(error.to_string(), "Invalid value 'invalid-region' for parameter 'region': Not a valid region");
    }

    #[test]
    fn test_execution_error() {
        let error = DSLError::execution_error("API call failed");
        assert_eq!(error.to_string(), "Execution error: API call failed");
    }

    #[test]
    fn test_execution_error_with_source() {
        let error = DSLError::execution_error_with_source("API call failed", "Network timeout");
        assert_eq!(error.to_string(), "Execution error: API call failed");
        assert!(error.source().is_some());
    }

    #[test]
    fn test_type_mismatch() {
        let error = DSLError::type_mismatch("String", "Number");
        assert_eq!(error.to_string(), "Type mismatch: expected String, got Number");
    }

    #[test]
    fn test_variable_not_found() {
        let error = DSLError::variable_not_found("my_var");
        assert_eq!(error.to_string(), "Variable 'my_var' not found");
    }

    #[test]
    fn test_invalid_expression() {
        let error = DSLError::invalid_expression("1 + + 2");
        assert_eq!(error.to_string(), "Invalid expression: 1 + + 2");
    }

    #[test]
    fn test_script_error() {
        let error = DSLError::script_error("Invalid script");
        assert_eq!(error.to_string(), "Script parsing error: Invalid script");
    }

    #[test]
    fn test_script_error_with_location() {
        let error = DSLError::script_error_with_location("Invalid script", 5, 10);
        assert_eq!(error.to_string(), "Script parsing error: Invalid script");
    }

    #[test]
    fn test_batch_error() {
        let error = DSLError::batch_error(3, "Command failed");
        assert_eq!(error.to_string(), "Batch execution failed at command 3: Command failed");
    }

    #[test]
    fn test_timeout_error() {
        let error = DSLError::timeout_error(30);
        assert_eq!(error.to_string(), "Operation timed out after 30 seconds");
    }

    #[test]
    fn test_resource_not_found() {
        let error = DSLError::resource_not_found("cluster-123");
        assert_eq!(error.to_string(), "Resource 'cluster-123' not found");
    }

    #[test]
    fn test_permission_denied() {
        let error = DSLError::permission_denied("DELETE CLUSTER");
        assert_eq!(error.to_string(), "Permission denied: DELETE CLUSTER");
    }

    #[test]
    fn test_error_context() {
        let context = ErrorContext::new()
            .with_line(10)
            .with_column(5)
            .with_command("CREATE CLUSTER")
            .with_variable("name", "test-cluster");

        assert_eq!(context.line, Some(10));
        assert_eq!(context.column, Some(5));
        assert_eq!(context.command, Some("CREATE CLUSTER".to_string()));
        assert_eq!(context.variables.get("name"), Some(&"test-cluster".to_string()));
    }

    #[test]
    fn test_error_context_display() {
        let context = ErrorContext::new()
            .with_line(10)
            .with_column(5)
            .with_command("CREATE CLUSTER")
            .with_variable("name", "test-cluster");

        let display = context.to_string();
        assert!(display.contains("line 10"));
        assert!(display.contains("column 5"));
        assert!(display.contains("CREATE CLUSTER"));
        assert!(display.contains("test-cluster"));
    }

    #[test]
    fn test_error_context_partial() {
        let context = ErrorContext::new()
            .with_line(10)
            .with_command("CREATE CLUSTER");

        let display = context.to_string();
        assert!(display.contains("line 10"));
        assert!(!display.contains("column"));
        assert!(display.contains("CREATE CLUSTER"));
    }
} 