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
//! ```rust
//! use test_rig::dsl::{DSLParser, DSLExecutor, DSLCommand};
//! 
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let client = TiDBCloudClient::new(api_key)?;
//!     let executor = DSLExecutor::new(client);
//!     
//!     // Parse and execute a single command
//!     let command = DSLParser::parse("CREATE CLUSTER my-cluster IN aws-us-west-1")?;
//!     let result = executor.execute(command).await?;
//!     
//!     // Parse and execute a script
//!     let script = r#"
//!         CREATE CLUSTER test-cluster IN aws-us-west-1 WITH RCU 1-10
//!         WAIT FOR test-cluster TO BE ACTIVE
//!         CREATE BACKUP FOR test-cluster
//!     "#;
//!     let commands = DSLParser::parse_script(script)?;
//!     let results = executor.execute_batch(commands).await?;
//!     
//!     Ok(())
//! }
//! ```

pub mod parser;
pub mod executor;
pub mod commands;
pub mod error;
pub mod syntax;

pub use parser::DSLParser;
pub use executor::DSLExecutor;
pub use commands::{DSLCommand, DSLResult, DSLCommandFactory};
pub use syntax::DSLValue;
pub use error::{DSLError, DSLResult as Result};
pub use syntax::{DSLToken, DSLTokenType, DSLSyntaxTree}; 