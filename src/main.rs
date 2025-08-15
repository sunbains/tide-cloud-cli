use clap::{Parser, Subcommand};
use colored::*;
use rustyline::DefaultEditor;
use rustyline::error::ReadlineError;
use std::env;
use std::path::PathBuf;
use tracing::Level;

use tidb_cli::{
    logging::{LogConfig, init_logging},
    sqlite::{SQLiteConnection, register_module},
    tidb_cloud::TiDBCloudClient,
};

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

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Execute a SQL query
    Query {
        /// SQL query to execute
        query: String,
    },
    /// Execute a SQL script from file
    Script {
        /// Path to SQL script file
        file: String,
    },
    /// Setup virtual tables
    Setup {
        /// Setup virtual tables
        tables: bool,
    },
    /// Show available virtual tables
    ShowTables,
    /// Show example queries
    Examples,
    /// Start interactive SQL shell
    Shell,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    // Initialize logging
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

    // Create TiDB Cloud client
    let client = create_tidb_client(&cli)?;

    // Handle commands
    match cli.command {
        Some(Commands::Query { query }) => {
            execute_sql_query(&query, &client)?;
        }
        Some(Commands::Script { file }) => {
            execute_sql_script(&file, &client)?;
        }
        Some(Commands::Setup { tables }) => {
            if tables {
                setup_virtual_tables(&client)?;
            }
        }
        Some(Commands::ShowTables) => {
            show_virtual_tables()?;
        }
        Some(Commands::Examples) => {
            show_examples();
        }
        Some(Commands::Shell) => {
            interactive_shell(&client)?;
        }
        None => {
            // Default to interactive shell
            interactive_shell(&client)?;
        }
    }

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

fn execute_sql_query(
    query: &str,
    client: &TiDBCloudClient,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("{}", "Executing SQL query:".green());
    println!("{query}");
    println!();

    // Create SQLite connection with virtual tables
    let mut conn = SQLiteConnection::new_in_memory()?;
    register_module(&conn, client)?;

    // Create virtual tables
    setup_virtual_tables_in_connection(&mut conn)?;

    // Execute the query
    let mut stmt = conn.prepare(query)?;
    let column_count = stmt.column_count();

    // Get column names first
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

    // Calculate column widths for alignment
    let mut col_widths = headers.iter().map(|h| h.len()).collect::<Vec<_>>();
    for row in &all_rows {
        for (i, value) in row.iter().enumerate() {
            if i < col_widths.len() {
                col_widths[i] = col_widths[i].max(value.len());
            }
        }
    }

    // Display results
    println!("{}", "Query Results:".green());
    
    // Print column headers with proper alignment
    let header_line = headers
        .iter()
        .enumerate()
        .map(|(i, h)| format!("{:<width$}", h, width = col_widths[i]))
        .collect::<Vec<_>>()
        .join("  ");
    println!("{}", header_line);

    // Print separator line
    let separator = col_widths
        .iter()
        .map(|&width| "-".repeat(width))
        .collect::<Vec<_>>()
        .join("  ");
    println!("{}", separator);

    // Print data rows with proper alignment
    for row in &all_rows {
        let row_line = row
            .iter()
            .enumerate()
            .map(|(i, value)| format!("{:<width$}", value, width = col_widths.get(i).unwrap_or(&0)))
            .collect::<Vec<_>>()
            .join("  ");
        println!("{}", row_line);
    }

    if !all_rows.is_empty() {
        println!("{}", format!("{} row(s) returned", all_rows.len()).blue());
    } else {
        println!("{}", "No rows returned".yellow());
    }

    Ok(())
}

fn execute_sql_script(
    file_path: &str,
    client: &TiDBCloudClient,
) -> Result<(), Box<dyn std::error::Error>> {
    let content = std::fs::read_to_string(file_path)?;
    println!("{}", format!("Executing SQL script: {file_path}").green());

    // Create SQLite connection with virtual tables
    let mut conn = SQLiteConnection::new_in_memory()?;
    register_module(&conn, client)?;

    // Create virtual tables
    setup_virtual_tables_in_connection(&mut conn)?;

    // Execute the script
    conn.execute_batch(&content)?;

    println!("{}", "Script executed successfully!".green());
    Ok(())
}

fn setup_virtual_tables(client: &TiDBCloudClient) -> Result<(), Box<dyn std::error::Error>> {
    println!("{}", "Setting up virtual tables...".green());

    // Create SQLite connection
    let mut conn = SQLiteConnection::new_in_memory()?;
    register_module(&conn, client)?;

    // Create virtual tables
    setup_virtual_tables_in_connection(&mut conn)?;

    println!("{}", "Virtual tables created successfully!".green());
    println!("You can now run SQL queries against TiDB Cloud data.");

    Ok(())
}

/// Parse DELETE statement to extract table name and WHERE clause
fn parse_delete_statement(
    input: &str,
) -> Result<(String, Option<String>), Box<dyn std::error::Error>> {
    let input = input.trim().to_uppercase();

    // Find the table name after DELETE FROM
    if let Some(from_pos) = input.find("FROM") {
        let after_from = &input[from_pos + 4..];
        let parts: Vec<&str> = after_from.split_whitespace().collect();

        if parts.is_empty() {
            return Err("No table name found after FROM".into());
        }

        let table_name = parts[0].to_lowercase();

        // Check if there's a WHERE clause
        if let Some(where_pos) = after_from.find("WHERE") {
            let where_clause = after_from[where_pos + 6..].trim();
            Ok((table_name, Some(where_clause.to_string())))
        } else {
            Ok((table_name, None))
        }
    } else {
        Err("No FROM clause found in DELETE statement".into())
    }
}

/// Fetch fresh data from TiDB Cloud API and populate SQLite tables
fn fetch_fresh_data_from_api(
    conn: &mut SQLiteConnection,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("Fetching fresh data from TiDB Cloud API...");

    // Note: We're now using virtual tables, so no need to manually populate data
    // The virtual tables will handle data fetching on-demand
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
        "#,
    )?;

    println!("Virtual tables ready for data access");
    Ok(())
}

/// Setup virtual tables in the given connection
fn setup_virtual_tables_in_connection(
    conn: &mut SQLiteConnection,
) -> Result<(), Box<dyn std::error::Error>> {
    // Create the virtual table instances
    conn.execute_batch(
        r#"
        CREATE VIRTUAL TABLE IF NOT EXISTS tidb_clusters USING tidb_clusters;
        CREATE VIRTUAL TABLE IF NOT EXISTS tidb_backups USING tidb_backups;
        "#,
    )?;

    // Create the public_endpoints view using the virtual table
    conn.execute_batch(
        r#"
        CREATE VIEW IF NOT EXISTS public_endpoints AS 
        SELECT 
            c.tidb_id,
            json_extract(endpoints.value, '$.type') as endpoint_type,
            json_extract(endpoints.value, '$.address') as address,
            json_extract(endpoints.value, '$.port') as port,
            json_extract(endpoints.value, '$.subnet') as subnet,
            endpoints.value as raw_data
        FROM tidb_clusters c, json_each(c.raw_data, '$.endpoints') as endpoints;
        "#,
    )?;

    // Populate with fresh data
    fetch_fresh_data_from_api(conn)?;

    Ok(())
}

fn show_virtual_tables() -> Result<(), Box<dyn std::error::Error>> {
    println!("{}", "Available Virtual Tables:".green());
    println!();
    println!("{}", "1. tidb_clusters".blue());
    println!("   - Contains TiDB cluster information");
    println!(
        "   - Fields: tidb_id, name, display_name, region_id, state, create_time, root_password, min_rcu, max_rcu, service_plan, cloud_provider, region_display_name, raw_data"
    );
    println!("   - Supports WHERE constraints on: state, region_id, cloud_provider");
    println!();
    println!("{}", "2. tidb_backups".blue());
    println!("   - Contains backup information for clusters");
    println!("   - Fields: backup_id, tidb_id, backup_name, status, size_bytes, raw_data");
    println!("   - Supports WHERE constraints on: tidb_id");
    println!();
    println!("{}", "3. config".blue());
    println!("   - Contains configuration and metadata");
    println!("   - Fields: key, value, raw_data");
    println!();
    println!("{}", "4. public_endpoints (View)".blue());
    println!("   - Materialized view of cluster endpoints");
    println!("   - Extracted from tidb_clusters.raw_data JSON field");
    println!("   - Fields: tidb_id, endpoint_type, address, port, subnet, raw_data");
    println!();
    println!("{}", "Example Queries:".yellow());
    println!("  SELECT * FROM tidb_clusters WHERE state = 'ACTIVE';");
    println!("  SELECT display_name, min_rcu, max_rcu FROM tidb_clusters;");
    println!("  SELECT * FROM tidb_backups WHERE tidb_id = 'your_cluster_id';");
    println!("  SELECT * FROM public_endpoints WHERE endpoint_type = 'TIDB';");
    println!();
    println!("{}", "Note:".red());
    println!("  - All input is passed directly to SQLite for execution");
    println!("  - True virtual tables with on-demand data access");
    println!("  - SQLite handles constraint optimization via best_index");
    println!("  - Materialized view for complex data extraction");

    Ok(())
}

fn show_examples() {
    println!("{}", "TiDB Cloud SQL Examples:".green());
    println!();
    println!("{}", "Basic Queries:".blue());
    println!("  SELECT * FROM tidb_clusters;");
    println!("  SELECT display_name, state FROM tidb_clusters WHERE state = 'ACTIVE';");
    println!("  SELECT COUNT(*) FROM tidb_clusters;");
    println!();
    println!("{}", "Backup Operations:".blue());
    println!("  SELECT * FROM tidb_backups;");
    println!("  SELECT backup_name, status FROM tidb_backups WHERE tidb_id = 'your_cluster_id';");
    println!();
    println!("{}", "Complex Queries:".blue());
    println!("  SELECT c.display_name, COUNT(b.backup_id) as backup_count");
    println!("  FROM tidb_clusters c");
    println!("  LEFT JOIN tidb_backups b ON c.tidb_id = b.tidb_id");
    println!("  WHERE c.state = 'ACTIVE';");
    println!();
    println!("{}", "Ordering and Limiting:".blue());
    println!(
        "  SELECT display_name, create_time FROM tidb_clusters ORDER BY create_time DESC LIMIT 10;"
    );
    println!("  SELECT * FROM backups ORDER BY create_time DESC LIMIT 5;");
}

fn interactive_shell(client: &TiDBCloudClient) -> Result<(), Box<dyn std::error::Error>> {
    println!("{}", "TiDB Cloud SQL Shell".green());
    println!("All input is passed directly to SQLite for execution");
    println!("Type 'quit' or 'exit' to exit the shell");
    println!();

    let mut rl = DefaultEditor::new()?;

    // Load command history
    if let Err(err) = rl.load_history("tidb_cli_history.txt") {
        // It's okay if the history file doesn't exist yet
        if !matches!(err, ReadlineError::Io(ref io_err) if io_err.kind() == std::io::ErrorKind::NotFound)
        {
            eprintln!("Failed to load history: {err}");
        }
    }

    // Create SQLite connection with virtual tables
    let mut conn = SQLiteConnection::new_in_memory()?;
    register_module(&conn, client)?;

    // Create virtual tables
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
                        if let Err(e) = show_virtual_tables() {
                            println!("{}: {}", "Error".red(), e);
                        }
                    }
                    "quit" | "exit" | "q" => {
                        println!("Goodbye!");
                        break;
                    }
                    _ => {
                        // Execute SQL query (or any other SQLite command)
                        if let Err(e) = execute_query_in_shell(line, &mut conn) {
                            println!("{}: {}", "Error".red(), e);
                        }
                    }
                }

                // Add line to history
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

    // Save command history
    if let Err(err) = rl.save_history("tidb_cli_history.txt") {
        eprintln!("Failed to save history: {err}");
    }

    Ok(())
}

fn execute_query_in_shell(
    input: &str,
    conn: &mut SQLiteConnection,
) -> Result<(), Box<dyn std::error::Error>> {
    let input = input.trim();

    // Handle special SQLite-like commands
    match input.to_lowercase().as_str() {
        ".tables" => {
            // Show available tables
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
            // Show schema for all tables
            let mut stmt = conn.prepare("SELECT sql FROM sqlite_master WHERE type='table'")?;
            let mut rows = stmt.query([])?;

            println!("{}", "Table schemas:".green());
            while let Some(row) = rows.next()? {
                let sql: String = row.get(0)?;
                println!("{sql}");
                println!();
            }
            return Ok(());
        }
        _ => {}
    }
    // Check if it's a DELETE statement
    if input.to_uppercase().starts_with("DELETE FROM") {
        match parse_delete_statement(input) {
            Ok((table_name, where_clause)) => {
                println!("{}", "Parsed DELETE statement:".green());
                println!("Table: {table_name}");
                if let Some(where_clause) = where_clause {
                    println!("WHERE: {where_clause}");
                }

                // For now, just show what would be sent to the API
                println!(
                    "{}",
                    "Note: API calls not yet implemented in synchronous mode".yellow()
                );

                // Refresh data after operation
                fetch_fresh_data_from_api(conn)?;
            }
            Err(e) => {
                println!("{}: {}", "Error parsing DELETE statement".red(), e);
            }
        }
        return Ok(());
    }

    // Execute as regular SQL query
    let mut stmt = conn.prepare(input)?;
    let column_count = stmt.column_count();

    // Get column names first
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

    // Calculate column widths for alignment
    let mut col_widths = headers.iter().map(|h| h.len()).collect::<Vec<_>>();
    for row in &all_rows {
        for (i, value) in row.iter().enumerate() {
            if i < col_widths.len() {
                col_widths[i] = col_widths[i].max(value.len());
            }
        }
    }

    // Display results
    println!("{}", "Query Results:".green());

    // Print column headers with proper alignment
    let header_line = headers
        .iter()
        .enumerate()
        .map(|(i, h)| format!("{:<width$}", h, width = col_widths[i]))
        .collect::<Vec<_>>()
        .join("  ");
    println!("{}", header_line);

    // Print separator line
    let separator = col_widths
        .iter()
        .map(|&width| "-".repeat(width))
        .collect::<Vec<_>>()
        .join("  ");
    println!("{}", separator);

    // Print data rows with proper alignment
    for row in &all_rows {
        let row_line = row
            .iter()
            .enumerate()
            .map(|(i, value)| format!("{:<width$}", value, width = col_widths.get(i).unwrap_or(&0)))
            .collect::<Vec<_>>()
            .join("  ");
        println!("{}", row_line);
    }

    if !all_rows.is_empty() {
        println!("{}", format!("{} row(s) returned", all_rows.len()).blue());
    } else {
        println!("{}", "No rows returned".yellow());
    }

    Ok(())
}
