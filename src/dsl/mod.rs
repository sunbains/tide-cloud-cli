//! # TiDB Cloud DSL (Domain Specific Language)
//!
//! This module provides a domain-specific language for interacting with the TiDB Cloud API.
//! The DSL allows users to write simple, declarative commands to manage TiDB clusters,
//! backups, and other resources.
//!
//! ## Features
//!
//! - **Declarative Syntax**: Write simple commands like `CREATE CLUSTER my-cluster`
//! - **Type Safety**: Compile-time validation of commands and parameters
//! - **Async Execution**: All operations are async and non-blocking
//! - **Error Handling**: Comprehensive error reporting with context
//! - **Batch Operations**: Execute multiple commands in sequence
//! - **Conditional Logic**: Support for if/else and loops
//!
//! ## Example Usage
//!
//! ```rust,no_run
//! use tidb_cli::dsl::{UnifiedParser, DSLExecutor};
//! use tidb_cli::tidb_cloud::TiDBCloudClient;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let api_key = "your-very-long-api-key-that-meets-the-minimum-length-requirement".to_string();
//!     let client = TiDBCloudClient::new(api_key)?;
//!     let mut executor = DSLExecutor::new(client);
//!     
//!     // Parse and execute a single command using AST
//!     let ast = UnifiedParser::parse("CREATE CLUSTER my-cluster IN aws-us-west-1")?;
//!     let result = executor.execute_ast(&ast).await?;
//!     
//!     // Parse and execute a script using AST
//!     let script = r#"
//!         CREATE CLUSTER test-cluster IN aws-us-west-1 WITH min_rcu=1, max_rcu=10
//!         WAIT FOR test-cluster TO BE ACTIVE
//!         CREATE BACKUP FOR test-cluster
//!     "#;
//!     let batch_result = executor.execute_ast_script(script).await?;
//!     
//!     Ok(())
//! }
//! ```

pub mod ast;
pub mod commands;
pub mod dsl_ast_parser;
pub mod error;
pub mod executor;
pub mod sql_ast_parser;
pub mod syntax;
pub mod unified_parser;

#[cfg(test)]
mod join_test;

pub use ast::{ASTNode, ASTPrinter, ASTTransformer, ASTValidator, ASTVisitor};
pub use commands::DSLResult;
pub use dsl_ast_parser::DSLASTParser;
pub use error::{DSLError, DSLResult as Result};
pub use executor::DSLExecutor;
// Old parsers removed - using new AST-based system instead
// pub use parser::DSLParser;
pub use sql_ast_parser::SQLASTParser;
// pub use sql_parser::SQLDSLParser;
pub use syntax::DSLValue;
pub use syntax::{DSLSyntaxTree, DSLToken, DSLTokenType};
pub use unified_parser::UnifiedParser;
