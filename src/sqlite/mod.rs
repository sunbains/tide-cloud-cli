//! # SQLite Integration Module
//!
//! This module provides SQLite database functionality with virtual table support
//! for direct API integration. It includes:
//! - Virtual table implementation for TiDB Cloud API
//! - Direct SQL query execution against live API data
//! - No more complex AST parsing or manual SQL building
//! - Leverages SQLite's built-in query optimization

pub mod vtable;

// Re-export virtual table functionality
pub use vtable::{VTableConfig, register_module};

/// Simple SQLite connection wrapper for virtual table usage
pub struct SQLiteConnection {
    connection: rusqlite::Connection,
}

impl SQLiteConnection {
    /// Create a new SQLite connection
    pub fn new_in_memory() -> rusqlite::Result<Self> {
        let connection = rusqlite::Connection::open_in_memory()?;
        Ok(Self { connection })
    }

    /// Create a new SQLite connection from file
    pub fn new<P: AsRef<std::path::Path>>(path: P) -> rusqlite::Result<Self> {
        let connection = rusqlite::Connection::open(path)?;
        Ok(Self { connection })
    }

    /// Get a reference to the underlying connection
    pub fn get_ref(&self) -> &rusqlite::Connection {
        &self.connection
    }

    /// Get a mutable reference to the underlying connection
    pub fn get_mut(&mut self) -> &mut rusqlite::Connection {
        &mut self.connection
    }

    /// Execute a batch of SQL statements
    pub fn execute_batch(&self, sql: &str) -> rusqlite::Result<()> {
        self.connection.execute_batch(sql)
    }

    /// Prepare a SQL statement
    pub fn prepare(&self, sql: &str) -> rusqlite::Result<rusqlite::Statement<'_>> {
        self.connection.prepare(sql)
    }
}

impl std::ops::Deref for SQLiteConnection {
    type Target = rusqlite::Connection;

    fn deref(&self) -> &Self::Target {
        &self.connection
    }
}

impl std::ops::DerefMut for SQLiteConnection {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.connection
    }
}
