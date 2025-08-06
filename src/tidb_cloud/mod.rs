//! TiDB Cloud OpenAPI Client
//!
//! This module provides a comprehensive client for interacting with the TiDB Cloud API.
//! It includes all the operations defined in the OpenAPI specification for managing
//! TiDB clusters, backups, and related resources.

pub mod client;
pub mod config;
pub mod constants;
pub mod debug_logger;
pub mod digest_auth;
pub mod error;
pub mod http_utils;
pub mod models;
pub mod operations;
pub mod query_utils;

pub use client::TiDBCloudClient;
pub use config::TiDBCloudConfig;
pub use constants::*;
pub use debug_logger::DebugLogger;
pub use error::{TiDBCloudError, TiDBCloudResult};
pub use models::*;
