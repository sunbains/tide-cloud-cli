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

// Legacy constants for backward compatibility
/// API base URL for TiDB Cloud (legacy - use PRODUCTION_API_URL instead)
pub const API_BASE_URL: &str = PRODUCTION_API_URL;

/// Default timeout for API requests (30 seconds) (legacy - use DEFAULT_TIMEOUT_SECS instead)
pub const DEFAULT_TIMEOUT: std::time::Duration =
    std::time::Duration::from_secs(DEFAULT_TIMEOUT_SECS);

/// Default user agent for API requests (legacy - use DEFAULT_USER_AGENT from constants instead)
pub const DEFAULT_USER_AGENT: &str = constants::DEFAULT_USER_AGENT;
