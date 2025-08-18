use clap::Parser;
use colored::*;
use rustyline::DefaultEditor;
use rustyline::error::ReadlineError;
use std::env;
use std::path::PathBuf;
use std::time::Instant;
use tracing::Level;

use tidb_cli::{
    logging::{LogConfig, init_logging},
    sqlite::{SQLiteConnection, register_module, vtable},
    tidb_cloud::TiDBCloudClient,
};

/// Type alias for query results: (headers, rows)
type QueryResult = (Vec<String>, Vec<Vec<String>>);

#[derive(Parser)]
#[command(name = "tidb-cli")]
#[command(about = "TiDB Cloud CLI with SQL interface")]
#[command(long_about = None)]
struct Cli {
    /// TiDB Cloud username or API key
    #[arg(short, long)]
    username: Option<String>,

    /// TiDB Cloud password or API secret
    #[arg(short, long)]
    password: Option<String>,

    /// TiDB Cloud base URL
    #[arg(long, default_value = "https://cloud.dev.tidbapi.com/v1beta2")]
    base_url: Option<String>,

    /// Log level (trace, debug, info, warn, error)
    #[arg(long, default_value = "info")]
    log_level: String,

    /// Enable verbose logging
    #[arg(short, long)]
    verbose: bool,

    /// Enable file logging
    #[arg(long)]
    log_file: bool,

    /// Log file path
    #[arg(long)]
    log_file_path: Option<String>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    let level = match cli.log_level.to_lowercase().as_str() {
        "trace" => Level::TRACE,
        "debug" => Level::DEBUG,
        "warn" => Level::WARN,
        "error" => Level::ERROR,
        _ => Level::INFO,
    };
    let level = if cli.verbose { Level::DEBUG } else { level };

    let mut log_config = LogConfig::new().with_level(level).with_console(true);

    if cli.log_file {
        log_config = log_config.with_file(true);
        if let Some(ref file_path) = cli.log_file_path {
            log_config = log_config.with_file_path(PathBuf::from(file_path));
        }
    }

    init_logging(&log_config)?;

    let client = create_tidb_client(&cli)?;

    interactive_shell(&client)?;

    Ok(())
}

fn create_tidb_client(cli: &Cli) -> Result<TiDBCloudClient, Box<dyn std::error::Error>> {
    let username = cli
        .username
        .clone()
        .or_else(|| env::var("TIDB_USERNAME").ok())
        .ok_or(
            "Username not provided. Use --username or set TIDB_USERNAME environment variable.",
        )?;

    let password = cli.password.clone().or_else(|| env::var("TIDB_PASSWORD").ok())
        .ok_or("Password/API key not provided. Use --password or set TIDB_PASSWORD environment variable.")?;

    let base_url = cli
        .base_url
        .clone()
        .or_else(|| env::var("TIDB_BASE_URL").ok())
        .unwrap_or_else(|| "https://cloud.dev.tidbapi.com/v1beta2".to_string());

    use std::time::Duration;
    use tidb_cli::tidb_cloud::debug_logger::DebugLogger;

    let client = TiDBCloudClient::with_config_and_credentials(
        username,
        password,
        base_url,
        Duration::from_secs(30),
        DebugLogger::default(),
    )?;
    Ok(client)
}

fn fetch_fresh_data_from_api(
    conn: &mut SQLiteConnection,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("Fetching fresh data from TiDB Cloud API...");

    println!("Note: Using virtual tables for on-demand data access");

    // Create a simple config table for status
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS config (
            key TEXT PRIMARY KEY,
            value TEXT,
            raw_data TEXT
        );
        INSERT OR REPLACE INTO config (key, value, raw_data) VALUES 
        ('api_status', 'virtual_table_mode', '{"mode": "vtab", "note": "Using virtual tables for data access"}');

        -- SQLite doesn't support stored procedures, functionality moved to application layer
        "#,
    )?;

    // Register custom SQLite function for wait_for_cluster_to_become_active
    conn.create_scalar_function(
        "wait_for_cluster_to_become_active",
        1,
        rusqlite::functions::FunctionFlags::SQLITE_UTF8,
        |ctx| {
            let display_name: String = ctx.get(0)?;

            // Get a mutable connection - this is tricky within a function
            let conn_ptr = unsafe { ctx.get_connection()? };

            let mut iteration = 1;
            const MAX_ITERATIONS: i32 = 100;

            while iteration <= MAX_ITERATIONS {
                // Execute the query directly
                let mut stmt =
                    conn_ptr.prepare("SELECT state FROM tidb_clusters WHERE display_name = ?1")?;
                let mut rows = stmt.query([&display_name])?;

                if let Some(row) = rows.next()? {
                    let state: String = row.get(0)?;
                    if state.to_lowercase() != "creating" {
                        return Ok(state);
                    }
                } else {
                    return Ok("NOT_FOUND".to_string());
                }

                iteration += 1;

                // Sleep for 1 second before next check
                std::thread::sleep(std::time::Duration::from_secs(1));
            }

            // If we've reached max iterations and still creating
            Ok("CREATING".to_string())
        },
    )?;

    println!("Virtual tables ready for data access");
    println!("Custom function 'wait_for_cluster_to_become_active(display_name)' registered");
    Ok(())
}

fn wait_for_cluster_to_become_active(
    conn: &mut SQLiteConnection,
    display_name: &str,
) -> Result<Option<(String, i32)>, Box<dyn std::error::Error>> {
    let mut iteration = 1;
    const MAX_ITERATIONS: i32 = 100;
    let start_time = Instant::now();

    while iteration <= MAX_ITERATIONS {
        let mut stmt = conn.prepare("SELECT state FROM tidb_clusters WHERE display_name = ?1")?;
        let mut rows = stmt.query([display_name])?;

        if let Some(row) = rows.next()? {
            let state: String = row.get(0)?;
            if state.to_lowercase() != "creating" {
                return Ok(Some((state, iteration)));
            }
        }

        iteration += 1;
        println!(
            "Time elapsed: {:?} - Cluster '{}' still creating, sleeping...",
            start_time.elapsed(),
            display_name
        );
        std::thread::sleep(std::time::Duration::from_secs(1));
    }

    Ok(None)
}

fn populate_rowid_mappings(conn: &mut SQLiteConnection) -> Result<(), Box<dyn std::error::Error>> {
    println!("Populating rowid mappings for virtual tables...");

    // Query each virtual table to populate the rowid mappings
    // This will trigger the filter() method which populates the global mappings

    // Populate clusters mapping
    if let Ok(mut stmt) = conn.prepare("SELECT COUNT(*) FROM tidb_clusters")
        && let Ok(mut rows) = stmt.query([])
        && let Some(row) = rows.next()?
    {
        let count: i32 = row.get(0).unwrap_or(0);
        println!("✅ Initialized rowid mapping for {count} clusters");
    }

    // Populate backups mapping
    if let Ok(mut stmt) = conn.prepare("SELECT COUNT(*) FROM tidb_backups")
        && let Ok(mut rows) = stmt.query([])
        && let Some(row) = rows.next()?
    {
        let count: i32 = row.get(0).unwrap_or(0);
        println!("✅ Initialized rowid mapping for {count} backups");
    }

    // Note: Network access mappings are now handled per-cluster via tidb_<cluster_id>_network_access tables

    println!("Rowid mappings populated successfully");
    Ok(())
}

fn setup_virtual_tables_in_connection(
    conn: &mut SQLiteConnection,
) -> Result<(), Box<dyn std::error::Error>> {
    conn.execute_batch(
        r#"
        CREATE VIRTUAL TABLE IF NOT EXISTS tidb_clusters USING tidb_clusters;
        CREATE VIRTUAL TABLE IF NOT EXISTS tidb_backups USING tidb_backups;
        "#,
    )?;

    conn.execute_batch(
        r#"
        CREATE VIEW IF NOT EXISTS tidb_endpoints AS
        SELECT 
            json_extract(endpoint.value, '$.host') || ':' || json_extract(endpoint.value, '$.port') as endpoint_id,
            tidb_id,
            json_extract(endpoint.value, '$.host') as host,
            json_extract(endpoint.value, '$.port') as port,
            json_extract(endpoint.value, '$.connectionType') as connection_type,
            endpoint.value as raw_data
        FROM tidb_clusters,
        json_each(json_extract(raw_data, '$.endpoints')) as endpoint
        WHERE json_extract(endpoint.value, '$.host') IS NOT NULL
        AND json_extract(endpoint.value, '$.port') IS NOT NULL;
        "#,
    )?;

    fetch_fresh_data_from_api(conn)?;

    if let Err(e) = vtable::initialize_cluster_access_tables(conn) {
        eprintln!("Warning: Failed to initialize cluster-specific access tables: {e}");
    }

    // Populate rowid mappings for DELETE/UPDATE operations
    if let Err(e) = populate_rowid_mappings(conn) {
        eprintln!("Warning: Failed to populate rowid mappings: {e}");
    }

    Ok(())
}

fn show_virtual_tables_with_client(
    client: &TiDBCloudClient,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("{}", "Available Virtual Tables:".green());
    println!();

    let mut conn = SQLiteConnection::new_in_memory()?;
    register_module(&conn, client)?;
    setup_virtual_tables_in_connection(&mut conn)?;

    let mut stmt =
        conn.prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")?;
    let table_rows = stmt.query_map([], |row| row.get::<_, String>(0))?;

    let mut counter = 1;
    for table_result in table_rows {
        let table_name = table_result?;

        // Skip internal SQLite tables
        if table_name.starts_with("sqlite_") {
            continue;
        }

        println!("{}", format!("{counter}. {table_name}").blue());

        // Get table schema information
        match get_table_info(&conn, &table_name) {
            Ok(info) => {
                println!("   - {}", info.description);
                if !info.fields.is_empty() {
                    println!("   - Fields: {}", info.fields.join(", "));
                }
                if !info.constraints.is_empty() {
                    println!(
                        "   - Supports WHERE constraints on: {}",
                        info.constraints.join(", ")
                    );
                }
                if !info.operations.is_empty() {
                    println!("   - Operations: {}", info.operations.join(", "));
                }
            }
            Err(_) => {
                // Fallback for any table we can't get info for
                println!("   - Available for SQL queries");
            }
        }
        println!();
        counter += 1;
    }

    if let Ok(tables) = vtable::get_dynamic_cluster_tables().lock() {
        for cluster_id in tables.iter() {
            let table_name = format!("tidb_{cluster_id}_network_access");
            println!("{}", format!("{counter}. {table_name}").blue());
            println!("   - Network access configuration for cluster {cluster_id}");
            println!("   - Fields: cidr_notation, description, enabled, tidb_id, raw_data");
            println!("   - Operations: SELECT, INSERT, UPDATE, DELETE");
            println!();
            counter += 1;
        }
    }

    println!("{}", "Special Commands:".yellow());
    println!("  .reload  - Drop all tables and recreate with fresh data from API");
    println!("  .tables  - Show available tables");
    println!("  .schema  - Show table schemas");
    println!(
        "  call wait_for_cluster_to_become_active('name');  - Poll until cluster is no longer creating"
    );
    println!();
    println!("{}", "Example Queries:".yellow());
    println!("  SELECT * FROM tidb_clusters WHERE state = 'ACTIVE';");
    println!("  SELECT display_name, min_rcu, max_rcu FROM tidb_clusters;");
    println!("  SELECT * FROM tidb_backups WHERE tidb_id = 'your_cluster_id';");
    println!("  SELECT * FROM tidb_network_access WHERE tidb_id = 'your_cluster_id';");
    println!("  SELECT * FROM tidb_endpoints WHERE connection_type = 'Public';");
    println!();
    println!("{}", "Note:".red());
    println!("  - All input is passed directly to SQLite for execution");
    println!("  - True virtual tables with on-demand data access");
    println!("  - SQLite handles constraint optimization via best_index");
    println!("  - Virtual tables provide direct API integration");

    Ok(())
}

#[derive(Debug)]
struct TableInfo {
    description: String,
    fields: Vec<String>,
    constraints: Vec<String>,
    operations: Vec<String>,
}

fn display_schema_information(conn: &SQLiteConnection) -> Result<(), Box<dyn std::error::Error>> {
    println!("{}", "Table schemas:".green());
    println!();

    let mut stmt =
        conn.prepare("SELECT sql FROM sqlite_master WHERE type='table' AND sql IS NOT NULL")?;
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        let sql: String = row.get(0)?;
        println!("{sql}");
        println!();
    }

    println!("{}", "-- TiDB Virtual Tables".blue());
    display_virtual_table_schema(conn, "tidb_clusters")?;
    display_virtual_table_schema(conn, "tidb_backups")?;
    display_virtual_table_schema(conn, "tidb_network_access")?;

    // Display views
    let mut view_stmt =
        conn.prepare("SELECT sql FROM sqlite_master WHERE type='view' AND sql IS NOT NULL")?;
    let mut view_rows = view_stmt.query([])?;
    while let Some(row) = view_rows.next()? {
        let sql: String = row.get(0)?;
        println!("{sql}");
        println!();
    }

    if let Ok(tables) = vtable::get_dynamic_cluster_tables().lock() {
        for cluster_id in tables.iter() {
            let table_name = format!("tidb_{cluster_id}_access_list");
            println!("CREATE VIRTUAL TABLE {table_name} (");
            println!("    cidr_notation TEXT,");
            println!("    description TEXT");
            println!(");");
            println!();
        }
    }

    Ok(())
}

fn display_virtual_table_schema(
    conn: &SQLiteConnection,
    table_name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    // Use PRAGMA table_info to get actual column information from the virtual table
    let mut stmt = conn.prepare(&format!("PRAGMA table_info({table_name})"))?;
    let column_rows = stmt.query_map([], |row| {
        let name: String = row.get(1)?;
        let type_name: String = row.get(2)?;
        Ok((name, type_name))
    })?;

    let mut columns = Vec::new();
    for col_result in column_rows {
        let (name, type_name) = col_result?;
        columns.push(format!("    {name} {type_name}"));
    }

    if !columns.is_empty() {
        println!("CREATE VIRTUAL TABLE {table_name} (");
        for (i, column) in columns.iter().enumerate() {
            if i == columns.len() - 1 {
                println!("{column}");
            } else {
                println!("{column},");
            }
        }
        println!(");");
        println!();
    }

    Ok(())
}

fn get_table_info(
    conn: &SQLiteConnection,
    table_name: &str,
) -> Result<TableInfo, Box<dyn std::error::Error>> {
    let mut stmt = conn.prepare(&format!("PRAGMA table_info({table_name})"))?;
    let column_rows = stmt.query_map([], |row| {
        row.get::<_, String>(1) // column name is at index 1
    })?;

    let mut fields = Vec::new();
    for col_result in column_rows {
        fields.push(col_result?);
    }

    let info = match table_name {
        "tidb_clusters" => TableInfo {
            description: "Contains TiDB cluster information".to_string(),
            fields,
            constraints: vec![
                "state".to_string(),
                "region_id".to_string(),
                "cloud_provider".to_string(),
            ],
            operations: vec![
                "SELECT".to_string(),
                "INSERT".to_string(),
                "UPDATE".to_string(),
                "DELETE".to_string(),
            ],
        },
        "tidb_backups" => TableInfo {
            description: "Contains backup information for clusters".to_string(),
            fields,
            constraints: vec!["tidb_id".to_string()],
            operations: vec![
                "SELECT".to_string(),
                "INSERT".to_string(),
                "UPDATE".to_string(),
                "DELETE".to_string(),
            ],
        },
        "tidb_network_access" => TableInfo {
            description: "Contains network access settings for clusters".to_string(),
            fields,
            constraints: vec!["tidb_id".to_string()],
            operations: vec![
                "SELECT".to_string(),
                "INSERT".to_string(),
                "UPDATE".to_string(),
            ],
        },
        "config" => TableInfo {
            description: "Contains configuration and metadata".to_string(),
            fields,
            constraints: vec![],
            operations: vec!["SELECT".to_string()],
        },
        "tidb_endpoints" => TableInfo {
            description: "Contains endpoint information for clusters (materialized view)"
                .to_string(),
            fields,
            constraints: vec![],
            operations: vec!["SELECT".to_string()],
        },
        _ => {
            // For any dynamic tables or unknown tables
            TableInfo {
                description: "Available for SQL queries".to_string(),
                fields,
                constraints: vec![],
                operations: vec!["SELECT".to_string()],
            }
        }
    };

    Ok(info)
}

fn interactive_shell(client: &TiDBCloudClient) -> Result<(), Box<dyn std::error::Error>> {
    println!("{}", "TiDB Cloud SQL Shell".green());
    println!("All input is passed directly to SQLite for execution");
    println!(
        "Type 'help' for available tables, '.reload' to refresh data, 'quit' or 'exit' to exit"
    );
    println!();

    let mut rl = DefaultEditor::new()?;

    if let Err(err) = rl.load_history("tidb_cli_history.txt")
        && !matches!(err, ReadlineError::Io(ref io_err) if io_err.kind() == std::io::ErrorKind::NotFound)
    {
        eprintln!("Failed to load history: {err}");
    }

    let mut conn = SQLiteConnection::new_in_memory()?;
    register_module(&conn, client)?;

    setup_virtual_tables_in_connection(&mut conn)?;

    loop {
        let readline = rl.readline("tidb-sql> ");

        match readline {
            Ok(line) => {
                let line = line.trim();

                if line.is_empty() {
                    continue;
                }

                match line.to_lowercase().as_str() {
                    "help" | "h" => {
                        if let Err(e) = show_virtual_tables_with_client(client) {
                            println!("{}: {}", "Error".red(), e);
                        }
                    }
                    "quit" | "exit" | "q" => {
                        println!("Goodbye!");
                        break;
                    }
                    _ => {
                        if let Err(e) = execute_query(line, &mut conn) {
                            println!("{}: {}", "Error".red(), e);
                        }
                    }
                }

                if let Err(err) = rl.add_history_entry(line) {
                    eprintln!("Failed to add to history: {err}");
                }
            }
            Err(ReadlineError::Interrupted) => {
                println!("^C");
                break;
            }
            Err(ReadlineError::Eof) => {
                println!("^D");
                break;
            }
            Err(err) => {
                println!("{}: {}", "Error".red(), err);
                break;
            }
        }
    }

    if let Err(err) = rl.save_history("tidb_cli_history.txt") {
        eprintln!("Failed to save history: {err}");
    }

    Ok(())
}

fn execute_query_with_results(
    query: &str,
    conn: &mut SQLiteConnection,
) -> Result<QueryResult, Box<dyn std::error::Error>> {
    let mut stmt = conn.prepare(query)?;
    let column_count = stmt.column_count();

    let mut headers = Vec::new();
    for i in 0..column_count {
        headers.push(stmt.column_name(i).unwrap_or("unknown").to_string());
    }

    let mut rows = stmt.query([])?;
    let mut all_rows = Vec::new();
    while let Some(row) = rows.next()? {
        let values: Vec<String> = (0..column_count)
            .map(|i| row.get::<_, String>(i).unwrap_or_default())
            .collect();
        all_rows.push(values);
    }

    Ok((headers, all_rows))
}

fn display_query_results(headers: &[String], all_rows: &[Vec<String>]) {
    if headers.is_empty() {
        return;
    }

    let mut col_widths = headers.iter().map(|h| h.len()).collect::<Vec<_>>();
    for row in all_rows {
        for (i, value) in row.iter().enumerate() {
            if i < col_widths.len() {
                col_widths[i] = col_widths[i].max(value.len());
            }
        }
    }

    println!("{}", "Query Results:".green());

    let header_line = headers
        .iter()
        .enumerate()
        .map(|(i, h)| format!("{:<width$}", h, width = col_widths[i]))
        .collect::<Vec<_>>()
        .join("  ");
    println!("{header_line}");

    let separator = col_widths
        .iter()
        .map(|&width| "-".repeat(width))
        .collect::<Vec<_>>()
        .join("  ");
    println!("{separator}");

    for row in all_rows {
        let row_line = row
            .iter()
            .enumerate()
            .map(|(i, value)| format!("{:<width$}", value, width = col_widths.get(i).unwrap_or(&0)))
            .collect::<Vec<_>>()
            .join("  ");
        println!("{row_line}");
    }

    if !all_rows.is_empty() {
        println!("{}", format!("{} row(s) returned", all_rows.len()).blue());
    } else {
        println!("{}", "No rows returned".yellow());
    }
}

fn strip_comments(input: &str) -> &str {
    let input = input.trim();

    // Find the position of comment markers
    let hash_pos = input.find('#');
    let dash_pos = input.find("--");

    // Determine the earliest comment position
    let comment_pos = match (hash_pos, dash_pos) {
        (Some(h), Some(d)) => Some(h.min(d)),
        (Some(h), None) => Some(h),
        (None, Some(d)) => Some(d),
        (None, None) => None,
    };

    // If we found a comment, return everything before it (trimmed)
    if let Some(pos) = comment_pos {
        input[..pos].trim()
    } else {
        input
    }
}

fn execute_query(
    input: &str,
    conn: &mut SQLiteConnection,
) -> Result<(), Box<dyn std::error::Error>> {
    let input = strip_comments(input);

    match input.to_lowercase().as_str() {
        ".tables" => {
            let mut stmt = conn.prepare("SELECT name FROM sqlite_master WHERE type='table'")?;
            let mut rows = stmt.query([])?;

            println!("{}", "Available tables:".green());
            while let Some(row) = rows.next()? {
                let table_name: String = row.get(0)?;
                println!("  {table_name}");
            }
            return Ok(());
        }
        ".schema" => {
            display_schema_information(conn)?;
            return Ok(());
        }
        ".reload" => {
            println!(
                "{}",
                "Reloading all tables and data from TiDB Cloud API...".yellow()
            );
            if let Err(e) = reload_all_tables(conn) {
                println!("{}: Failed to reload tables: {}", "Error".red(), e);
            } else {
                println!("{}", "✅ Successfully reloaded all tables and data".green());
            }
            return Ok(());
        }
        _ => {
            if input.starts_with("call wait_for_cluster_to_become_active(") && input.ends_with(");")
            {
                let display_name = input
                    .strip_prefix("call ")
                    .unwrap()
                    .strip_suffix(");")
                    .unwrap();
                if display_name.is_empty() {
                    println!(
                        "{}: Usage: call wait_for_cluster_to_become_active(<display_name>)",
                        "Error".red()
                    );
                } else {
                    match wait_for_cluster_to_become_active(conn, display_name) {
                        Ok(Some((state, iterations))) => {
                            println!(
                                "✅ Cluster '{display_name}' is now {state} (checked {iterations} times)"
                            );
                        }
                        Ok(None) => {
                            println!(
                                "❌ Cluster '{display_name}' is still creating after maximum iterations"
                            );
                        }
                        Err(e) => {
                            println!("{}: {}", "Error".red(), e);
                        }
                    }
                }
                return Ok(());
            }

            if let Some(display_name) = parse_wait_for_cluster_to_become_active_call(input) {
                match wait_for_cluster_to_become_active(conn, &display_name) {
                    Ok(Some((state, iterations))) => {
                        println!(
                            "✅ Cluster '{display_name}' is now {state} (checked {iterations} times)"
                        );
                    }
                    Ok(None) => {
                        println!(
                            "❌ Cluster '{display_name}' did not become active within maximum iterations"
                        );
                    }
                    Err(e) => {
                        println!("{}: {}", "Error".red(), e);
                    }
                }
                return Ok(());
            }
        }
    }

    // Check if this is a DROP TABLE command on a protected access list table
    if is_protected_access_list_drop_attempt(input) {
        println!(
            "{}: Cannot drop cluster-specific access list tables manually.",
            "Error".red()
        );
        println!("These tables are managed automatically by the virtual table infrastructure.");
        println!("Access list tables are automatically created when clusters are created");
        println!("and automatically dropped when clusters are deleted.");
        return Ok(());
    }

    // Check if this is a DELETE from tidb_clusters to handle cleanup
    let is_cluster_delete = input.to_lowercase().contains("delete")
        && input.to_lowercase().contains("from")
        && input.to_lowercase().contains("tidb_clusters");

    // Get cluster IDs before deletion for cleanup
    let clusters_to_cleanup = if is_cluster_delete {
        get_clusters_to_be_deleted(input, conn).unwrap_or_default()
    } else {
        Vec::new()
    };

    let start_time = Instant::now();

    let result = execute_query_with_results(input, conn);
    let elapsed = start_time.elapsed();

    match result {
        Ok((headers, all_rows)) => {
            let is_select = !headers.is_empty();

            if is_select {
                display_query_results(&headers, &all_rows);
            }

            // Handle cluster deletion cleanup
            if is_cluster_delete && !clusters_to_cleanup.is_empty() {
                handle_cluster_deletion_cleanup(conn, &clusters_to_cleanup);
            }

            println!(
                "{}",
                format!("Elapsed: {:.3}s", elapsed.as_secs_f64()).blue()
            );
        }
        Err(e) => {
            println!("{}: {}", "Error".red(), e);
            println!(
                "{}",
                format!("Elapsed: {:.3}s", elapsed.as_secs_f64()).blue()
            );
        }
    }

    Ok(())
}

fn parse_wait_for_cluster_to_become_active_call(input: &str) -> Option<String> {
    let input = input.trim().to_lowercase();

    if !input.starts_with("call wait_for_cluster_to_become_active") {
        return None;
    }

    let after_call = input.strip_prefix("call wait_for_cluster_to_become_active")?;
    let after_call = after_call.trim();

    if !after_call.starts_with('(') || !after_call.ends_with(");") && !after_call.ends_with(')') {
        return None;
    }

    let paren_content = if after_call.ends_with(");") {
        after_call.strip_prefix('(')?.strip_suffix(");")?
    } else {
        after_call.strip_prefix('(')?.strip_suffix(')')?
    };

    let paren_content = paren_content.trim();

    if (paren_content.starts_with('\'') && paren_content.ends_with('\''))
        || (paren_content.starts_with('"') && paren_content.ends_with('"'))
    {
        let cluster_name = &paren_content[1..paren_content.len() - 1];
        if !cluster_name.is_empty() {
            return Some(cluster_name.to_string());
        }
    }

    if !paren_content.is_empty() && !paren_content.contains(' ') {
        return Some(paren_content.to_string());
    }

    None
}

fn reload_all_tables(conn: &mut SQLiteConnection) -> Result<(), Box<dyn std::error::Error>> {
    println!("🧹 Cleaning up existing tables...");
    cleanup_all_tables(conn)?;

    println!("🔄 Recreating tables and fetching fresh data...");
    setup_virtual_tables_in_connection(conn)?;

    Ok(())
}

fn cleanup_all_tables(conn: &mut SQLiteConnection) -> Result<(), Box<dyn std::error::Error>> {
    let cluster_tables = if let Ok(tables) = vtable::get_dynamic_cluster_tables().lock() {
        tables.clone()
    } else {
        std::collections::HashSet::new()
    };

    for cluster_id in cluster_tables.iter() {
        if let Err(e) = vtable::drop_cluster_access_table(conn, cluster_id) {
            eprintln!("Warning: Failed to drop access table for cluster {cluster_id}: {e}");
        }
    }

    if let Ok(mut tables) = vtable::get_dynamic_cluster_tables().lock() {
        tables.clear();
    }

    let drop_views = vec!["DROP VIEW IF EXISTS tidb_endpoints"];

    for view_sql in drop_views {
        if let Err(e) = conn.execute(view_sql, []) {
            eprintln!("Warning: Failed to drop view: {view_sql} - {e}");
        }
    }

    let drop_tables = vec![
        "DROP TABLE IF EXISTS tidb_clusters",
        "DROP TABLE IF EXISTS tidb_backups",
        "DROP TABLE IF EXISTS tidb_network_access",
        "DROP TABLE IF EXISTS config",
    ];

    for table_sql in drop_tables {
        if let Err(e) = conn.execute(table_sql, []) {
            eprintln!("Warning: Failed to drop table: {table_sql} - {e}");
        }
    }

    clear_rowid_mappings();

    println!("✅ Cleanup completed");
    Ok(())
}

fn clear_rowid_mappings() {
    vtable::clear_all_rowid_mappings();
}

fn is_protected_access_list_drop_attempt(query: &str) -> bool {
    let query_lower = query.to_lowercase();

    if !query_lower.contains("drop") || !query_lower.contains("table") {
        return false;
    }

    // Extract table name from DROP TABLE statement
    // Handle various forms: "DROP TABLE name", "DROP TABLE IF EXISTS name", etc.
    let parts: Vec<&str> = query_lower.split_whitespace().collect();
    let mut table_name = "";

    // Find the table name after DROP TABLE [IF EXISTS]
    for (i, part) in parts.iter().enumerate() {
        if *part == "table" {
            // Check if next part is "if", then skip to table name
            if i + 1 < parts.len() {
                if parts[i + 1] == "if" && i + 3 < parts.len() && parts[i + 2] == "exists" {
                    // DROP TABLE IF EXISTS table_name
                    if i + 3 < parts.len() {
                        table_name = parts[i + 3];
                    }
                } else {
                    // DROP TABLE table_name
                    table_name = parts[i + 1];
                }
                break;
            }
        }
    }

    // Check if the table name matches the pattern for cluster-specific access list tables
    // Pattern: tidb_<cluster_id>_access_list where cluster_id is not empty
    if table_name.starts_with("tidb_") && table_name.ends_with("_access_list") {
        // Extract the middle part (cluster_id) and ensure it's not empty
        let prefix_len = "tidb_".len();
        let suffix_len = "_access_list".len();
        if table_name.len() > prefix_len + suffix_len {
            let cluster_id = &table_name[prefix_len..table_name.len() - suffix_len];
            !cluster_id.is_empty() && !cluster_id.contains('_') // Cluster ID shouldn't contain underscores
        } else {
            false
        }
    } else {
        false
    }
}

/// Extract cluster IDs that will be deleted from a DELETE query
fn get_clusters_to_be_deleted(
    delete_query: &str,
    conn: &mut SQLiteConnection,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    // Convert DELETE to SELECT to preview what will be deleted
    let select_query = delete_query.to_lowercase().replace(
        "delete from tidb_clusters",
        "select tidb_id from tidb_clusters",
    );

    let mut stmt = conn.prepare(&select_query)?;
    let mut rows = stmt.query([])?;
    let mut cluster_ids = Vec::new();

    while let Some(row) = rows.next()? {
        let tidb_id: String = row.get(0)?;
        cluster_ids.push(tidb_id);
    }

    Ok(cluster_ids)
}

/// Handle cleanup of cluster-specific access list tables after cluster deletion
fn handle_cluster_deletion_cleanup(conn: &SQLiteConnection, cluster_ids: &[String]) {
    for cluster_id in cluster_ids {
        if let Err(e) = vtable::drop_cluster_access_table(conn, cluster_id) {
            eprintln!(
                "{}: Failed to drop access list table for cluster {}: {}",
                "Warning".yellow(),
                cluster_id,
                e
            );
        } else {
            println!(
                "{}: Cleaned up access list table for deleted cluster {}",
                "✅".green(),
                cluster_id
            );
        }
    }
}
