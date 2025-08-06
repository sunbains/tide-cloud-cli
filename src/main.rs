use clap::{Parser, Subcommand};
use colored::*;
use edit::edit;
use rustyline::{DefaultEditor, error::ReadlineError};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tidb_cli::{
    dsl::{DSLExecutor, UnifiedParser},
    logging::{LogConfig, init_logging},
    tidb_cloud::{DebugLogger, TiDBCloudClient, constants::VerbosityLevel},
};

use tokio::signal;
use tracing::Level;

#[derive(Parser)]
#[command(name = "tidb-cli")]
#[command(about = "TiDB Cloud DSL Command Line Interface")]
#[command(version)]
struct Cli {
    /// TiDB Cloud username
    #[arg(short, long)]
    username: Option<String>,

    /// TiDB Cloud password/API key
    #[arg(short, long)]
    password: Option<String>,

    /// TiDB Cloud API base URL (include API version path, e.g., https://cloud.dev.tidbapi.com/v1beta2)
    #[arg(long)]
    base_url: Option<String>,

    /// Enable verbose output
    #[arg(short, long)]
    verbose: bool,

    /// Log level (trace, debug, info, warn, error)
    #[arg(long, default_value = "info")]
    log_level: String,

    /// Enable file logging
    #[arg(long)]
    log_file: bool,

    /// Log file path
    #[arg(long)]
    log_file_path: Option<String>,

    /// Timeout in seconds for operations
    #[arg(short, long, default_value = "300")]
    timeout: u64,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Execute one or more DSL commands (separated by semicolons)
    Exec {
        /// The DSL command(s) to execute
        command: String,
    },

    /// Execute a DSL script from a file
    Script {
        /// Path to the DSL script file
        file: String,
    },

    /// Validate a DSL script without executing it
    Validate {
        /// Path to the DSL script file
        file: String,
    },

    /// List all available commands
    List,

    /// Show detailed command syntax with diagrams
    ShowHelp,

    /// Show DSL syntax examples
    Examples,

    /// Edit and execute a DSL command
    Edit {
        /// The initial DSL command to edit
        command: Option<String>,

        /// Open editor with empty content
        #[arg(long)]
        empty: bool,

        /// Editor to use (default: $EDITOR or 'nano')
        #[arg(long)]
        editor: Option<String>,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    // Initialize logging system
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

    // Check if we need authentication for the command
    let needs_auth = matches!(
        cli.command,
        Some(Commands::Exec { .. }) | Some(Commands::Script { .. }) | None
    );

    let mut executor = if needs_auth {
        // Get username and password
        let username = cli
            .username
            .or_else(|| env::var("TIDB_CLOUD_USERNAME").ok())
            .unwrap_or_else(|| "tidb_cloud_user".to_string());

        let password = cli.password
            .or_else(|| env::var("TIDB_CLOUD_PASSWORD").ok())
            .or_else(|| env::var("TIDB_CLOUD_API_KEY").ok()) // Backward compatibility
            .ok_or("TIDB_CLOUD_PASSWORD or TIDB_CLOUD_API_KEY must be provided via --password or environment variable")?;

        // Create TiDB Cloud client with username and password
        let base_url = cli
            .base_url
            .unwrap_or_else(|| "https://cloud.tidbapi.com/v1beta2".to_string());
        // Use the base URL as-is, don't append API version (let the user specify the complete URL)
        let full_base_url = base_url;
        // Create DebugLogger with the same level as the tracing system
        let debug_logger = match cli.log_level.as_str() {
            "trace" => DebugLogger::new(VerbosityLevel::Trace),
            "debug" => DebugLogger::new(VerbosityLevel::Debug),
            "info" => DebugLogger::new(VerbosityLevel::Info),
            "warn" => DebugLogger::new(VerbosityLevel::Warning),
            "error" => DebugLogger::new(VerbosityLevel::Error),
            _ => DebugLogger::new(VerbosityLevel::Info),
        };

        let client = TiDBCloudClient::with_config_and_credentials(
            username,
            password,
            full_base_url,
            std::time::Duration::from_secs(cli.timeout),
            debug_logger,
        )?;

        // Create DSL executor with timeout
        let timeout = std::time::Duration::from_secs(cli.timeout);
        Some(DSLExecutor::with_timeout(client, timeout))
    } else {
        None
    };

    // Set up signal handling for Ctrl+C
    let cancellation_flag = if let Some(ref mut exec) = executor {
        exec.get_cancellation_flag()
    } else {
        Arc::new(AtomicBool::new(false))
    };

    // Spawn signal handler
    let signal_flag = Arc::clone(&cancellation_flag);
    tokio::spawn(async move {
        if let Ok(()) = signal::ctrl_c().await {
            println!("\nReceived Ctrl+C, cancelling current command...");
            signal_flag.store(true, Ordering::Relaxed);
        }
    });

    match cli.command {
        Some(Commands::Exec { command }) => {
            // Split command by semicolons to handle multiple commands
            let commands = split_commands(&command);
            execute_multiple_commands(executor.as_mut().unwrap(), &commands).await?;
        }

        Some(Commands::Script { file }) => {
            execute_script_file(executor.as_mut().unwrap(), &file).await?;
        }

        None => {
            run_interactive_mode(executor.as_mut().unwrap()).await?;
        }

        Some(Commands::Validate { file }) => {
            validate_script_file(&file)?;
        }

        Some(Commands::List) => {
            list_available_commands();
        }

        Some(Commands::ShowHelp) => {
            show_detailed_command_help();
        }

        Some(Commands::Examples) => {
            show_examples();
        }

        Some(Commands::Edit {
            command,
            empty,
            editor,
        }) => {
            execute_edit_command(
                executor.as_mut().unwrap(),
                command,
                empty,
                editor.as_deref(),
            )
            .await?;
        }
    }

    Ok(())
}

/// Split input into individual commands by semicolon
fn split_commands(input: &str) -> Vec<String> {
    input
        .split(';')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect()
}

async fn execute_multiple_commands(
    executor: &mut DSLExecutor,
    commands: &[String],
) -> Result<(), Box<dyn std::error::Error>> {
    for (i, command) in commands.iter().enumerate() {
        if commands.len() > 1 {
            println!(
                "Executing command {} of {}: {}",
                i + 1,
                commands.len(),
                command
            );
        }

        execute_single_command(executor, command).await?;
    }
    Ok(())
}

async fn execute_single_command(
    executor: &mut DSLExecutor,
    command: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    use tracing::{debug, error, info};

    info!("Executing DSL command: {}", command);
    debug!("Parsing command: {}", command);

    // Use direct AST parsing and execution
    match UnifiedParser::parse(command) {
        Ok(ast_node) => {
            debug!("Command parsed successfully to AST: {:?}", ast_node);

            match executor.execute_ast(&ast_node).await {
                Ok(result) => {
                    if result.is_success() {
                        info!("✅ Command executed successfully");
                        if let Some(message) = result.get_message() {
                            debug!("Command has message");
                            println!("{message}");
                        }
                        if let Some(data) = result.get_data() {
                            debug!("Command data: {}", data);
                            let pretty_data = executor.pretty_print_table(data);
                            println!("Data:\n{pretty_data}");
                        }
                        if let Some(duration) = result.get_metadata("duration_ms")
                            && let Some(duration_ms) = duration.as_number()
                        {
                            debug!("Command duration: {:.2}ms", duration_ms);
                            println!("Duration: {duration_ms:.2}ms");
                        }
                    } else {
                        error!("❌ Command failed");
                        if let Some(error) = result.get_error() {
                            error!("Command error: {}", error);
                            println!("Error: {error}");
                        }
                    }
                }
                Err(e) => {
                    error!("❌ Command execution failed: {}", e);
                    println!("❌ Command execution failed: {e}");
                }
            }
        }
        Err(e) => {
            error!("❌ Command parsing failed: {}", e);
            println!("❌ Command parsing failed: {e}");
        }
    }

    Ok(())
}

async fn execute_script_file(
    executor: &mut DSLExecutor,
    file_path: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    if !Path::new(file_path).exists() {
        return Err(format!("Script file '{file_path}' not found").into());
    }

    let script_content = fs::read_to_string(file_path)?;
    println!("Executing script from: {file_path}");

    match executor.execute_ast_script(&script_content).await {
        Ok(batch_result) => {
            println!("✅ Script executed successfully");
            println!(
                "Results: {} successful, {} failed",
                batch_result.success_count, batch_result.failure_count
            );
            println!("Total duration: {:?}", batch_result.total_duration);

            // Show detailed results
            for (i, result) in batch_result.results.iter().enumerate() {
                let status = if result.is_success() { "✅" } else { "❌" };
                println!("Command {}: {}", i + 1, status);

                if let Some(message) = result.get_message() {
                    println!("  Message: {message}");
                }

                if let Some(error) = result.get_error() {
                    println!("  Error: {error}");
                }
            }

            // Show variables at the end
            if !executor.get_variables().is_empty() {
                println!("\nVariables:");
                for (name, value) in executor.get_variables() {
                    println!("  {name} = {value}");
                }
            }
        }
        Err(e) => {
            println!("❌ Script execution failed: {e}");
        }
    }

    Ok(())
}

async fn run_interactive_mode(
    executor: &mut DSLExecutor,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("TiDB Cloud CLI Interactive Mode");
    println!("Type 'help' for available commands, 'exit' to quit");
    println!("Use Ctrl+R to search history, Ctrl+L to clear screen");
    println!("================================================");

    // Create rustyline editor with history
    let mut rl = DefaultEditor::new()?;

    // Set history file path
    let history_file = get_history_file_path()?;

    // Load history if file exists
    if history_file.exists()
        && let Err(e) = rl.load_history(&history_file)
    {
        tracing::warn!("Could not load history file: {}", e);
    }

    loop {
        let readline = rl.readline("tidb-dsl> ");
        match readline {
            Ok(line) => {
                let input = line.trim();
                if input.is_empty() {
                    continue;
                }

                // Add to history (rustyline does this automatically, but we can be explicit)
                if let Err(e) = rl.add_history_entry(input) {
                    tracing::warn!("Could not add to history: {}", e);
                }

                match input.to_lowercase().as_str() {
                    "exit" | "quit" => {
                        println!("Goodbye!");
                        break;
                    }
                    "help" => {
                        show_interactive_help();
                    }
                    "help commands" => {
                        show_detailed_command_help();
                    }
                    "help examples" => {
                        show_examples();
                    }
                    "variables" => {
                        show_variables(executor);
                    }
                    "clear" => {
                        executor.clear_variables();
                        println!("Variables cleared");
                    }
                    "history" => {
                        show_history(&rl);
                    }
                    "clear-history" => {
                        if let Err(e) = rl.clear_history() {
                            tracing::warn!("Could not clear history: {}", e);
                        } else {
                            println!("History cleared");
                        }
                    }
                    "edit" => {
                        if let Err(e) = execute_edit_command(executor, None, false, None).await {
                            println!("Error: {e}");
                        }
                    }
                    _ => {
                        // Reset cancellation flag before executing command
                        executor.reset_cancellation();

                        // Split input by semicolons to handle multiple commands
                        let commands = split_commands(input);

                        if let Err(e) = execute_multiple_commands(executor, &commands).await {
                            if e.to_string().contains("cancelled") {
                                println!("Command cancelled");
                            } else {
                                println!("Error: {e}");
                            }
                        }
                    }
                }
            }
            Err(ReadlineError::Interrupted) => {
                println!("^C");
                continue;
            }
            Err(ReadlineError::Eof) => {
                println!("^D");
                break;
            }
            Err(err) => {
                println!("Error: {err}");
                break;
            }
        }
    }

    // Save history
    if let Err(e) = rl.save_history(&history_file) {
        tracing::warn!("Could not save history file: {}", e);
    }

    Ok(())
}

fn validate_script_file(file_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    if !Path::new(file_path).exists() {
        return Err(format!("Script file '{file_path}' not found").into());
    }

    let script_content = fs::read_to_string(file_path)?;
    println!("Validating script: {file_path}");

    match UnifiedParser::parse_script(&script_content) {
        Ok(ast_nodes) => {
            println!("✅ Script is valid");
            println!("Found {} AST nodes:", ast_nodes.len());

            for (i, node) in ast_nodes.iter().enumerate() {
                println!("  {}. {}", i + 1, node.variant_name());
            }
        }
        Err(e) => {
            println!("❌ Script validation failed: {e}");
        }
    }

    Ok(())
}

fn list_available_commands() {
    println!("Available DSL Commands:");
    println!("=======================");
    println!();
    println!("Cluster Management:");
    println!("  CREATE CLUSTER <name> IN <region> [WITH <params>]");
    println!("  DELETE CLUSTER <name>");
    println!("  LIST CLUSTERS [WHERE <conditions>]");
    println!("  GET CLUSTER <name>");
    println!("  UPDATE CLUSTER <name> WITH <params>");
    println!("  WAIT FOR <cluster> TO BE <state> [WITH timeout=<seconds>]");
    println!();
    println!("Backup Management:");
    println!("  CREATE BACKUP FOR <cluster> [WITH description=<desc>]");
    println!("  LIST BACKUPS FOR <cluster>");
    println!("  DELETE BACKUP <backup_id> FROM <cluster>");
    println!();
    println!("Pricing:");
    println!(
        "  ESTIMATE PRICE IN <region> WITH min_rcu=<value>, max_rcu=<value>, service_plan=<plan>"
    );
    println!();
    println!("Variables:");
    println!("  SET <variable> = <value>");
    println!("  GET <variable>");
    println!();
    println!("Control Flow:");
    println!("  IF <condition> THEN <commands> [ELSE <commands>] END");
    println!("  LOOP <commands> END");
    println!("  BREAK");
    println!("  CONTINUE");
    println!("  RETURN [<value>]");
    println!();
    println!("Utility:");
    println!("  ECHO <message>");
    println!("  SLEEP <seconds>");
    println!("  EXIT");
    println!();
    println!("Examples:");
    println!(
        "  CREATE CLUSTER my-cluster IN aws-us-west-1 WITH min_rcu=1, max_rcu=10, service_plan=Starter"
    );
    println!("  WAIT FOR my-cluster TO BE ACTIVE WITH timeout=600");
    println!("  SET region = \"aws-us-west-1\"");
    println!("  ECHO \"Cluster created successfully!\"");
}

fn show_examples() {
    println!("DSL Syntax Examples:");
    println!("===================");
    println!();

    let examples = vec![
        (
            "Basic Cluster Operations",
            r#"
# Create a cluster
CREATE CLUSTER my-cluster IN aws-us-west-1 WITH min_rcu=1, max_rcu=10, service_plan=STARTER

# Wait for cluster to be active
WAIT FOR my-cluster TO BE ACTIVE WITH timeout=600

# List all clusters
LIST CLUSTERS

# Get specific cluster details
GET CLUSTER my-cluster

# Update cluster
UPDATE CLUSTER my-cluster WITH max_rcu=20

# Delete cluster
DELETE CLUSTER my-cluster"#,
        ),
        (
            "Backup Operations",
            r#"
# Create a backup
CREATE BACKUP FOR my-cluster WITH description="Daily backup"

# List backups
LIST BACKUPS FOR my-cluster

# Delete a backup
DELETE BACKUP backup-123 FROM my-cluster"#,
        ),
        (
            "Pricing",
            r#"
# Estimate price
ESTIMATE PRICE IN aws-us-west-1 WITH min_rcu=1, max_rcu=10, service_plan=STARTER"#,
        ),
        (
            "Variables and Control Flow",
            r#"
# Set variables
SET region = "aws-us-west-1"
SET cluster_name = "my-cluster"

# Use variables
CREATE CLUSTER ${cluster_name} IN ${region}

# Conditional execution
IF ${cluster_exists} THEN
    ECHO "Cluster already exists"
ELSE
    CREATE CLUSTER ${cluster_name} IN ${region}
END"#,
        ),
        (
            "Script Example",
            r#"
# Complete script example
SET region = "aws-us-west-1"
SET cluster_name = "test-cluster"

ECHO "Creating cluster ${cluster_name} in ${region}"

CREATE CLUSTER ${cluster_name} IN ${region} WITH min_rcu=1, max_rcu=10, service_plan=STARTER

WAIT FOR ${cluster_name} TO BE ACTIVE WITH timeout=600

ECHO "Cluster ${cluster_name} is now active!"

CREATE BACKUP FOR ${cluster_name} WITH description="Initial backup"

ECHO "Backup created successfully"

LIST BACKUPS FOR ${cluster_name}"#,
        ),
    ];

    for (title, example) in examples {
        println!("{title}:");
        println!("{example}");
        println!();
    }
}

fn show_detailed_command_help() {
    println!("{}", "TiDB Cloud DSL Command Reference".bold().cyan());
    println!("{}", "=================================".cyan());
    println!();

    // Cluster Management Commands
    println!("{}", "📊 CLUSTER MANAGEMENT".bold().green());
    println!("{}", "=====================".green());
    println!();

    // CREATE CLUSTER
    println!("{}", "CREATE CLUSTER".bold().yellow());
    println!(
        "{}",
        "┌─────────────────────────────────────────────────────────────────────────────────────┐"
            .dimmed()
    );
    println!(
        "{}",
        "│ CREATE CLUSTER <name> IN <region> [WITH <parameters>]                               │"
            .dimmed()
    );
    println!(
        "{}",
        "└─────────────────────────────────────────────────────────────────────────────────────┘"
            .dimmed()
    );
    println!();
    println!("{}", "Parameters:".bold());
    println!(
        "  {}  {}  {}",
        "min_rcu".cyan(),
        "=".white(),
        "Minimum RCU (1-1000)".white()
    );
    println!(
        "  {}  {}  {}",
        "max_rcu".cyan(),
        "=".white(),
        "Maximum RCU (1-1000)".white()
    );
    println!(
        "  {}  {}  {}",
        "service_plan".cyan(),
        "=".white(),
        "Starter | Essential | Premium | BYOC".white()
    );
    println!(
        "  {}  {}  {}",
        "root_password".cyan(),
        "=".white(),
        "Root password for database access".white()
    );
    println!(
        "  {}  {}  {}",
        "high_availability_type".cyan(),
        "=".white(),
        "REGIONAL | ZONAL".white()
    );
    println!(
        "  {}  {}  {}",
        "public_connection".cyan(),
        "=".white(),
        "Public connection settings object".white()
    );
    println!();
    println!("{}", "Examples:".bold());
    println!(
        "  CREATE CLUSTER my-cluster IN aws-us-west-1 WITH min_rcu=1, max_rcu=10, service_plan=Starter"
    );
    println!(
        "  CREATE CLUSTER prod-cluster IN aws-us-east-1 WITH min_rcu=100, max_rcu=1000, service_plan=Premium"
    );
    println!(
        "  CREATE CLUSTER my-cluster IN aws-us-west-1 WITH public_connection={{enabled: true, \"ipAccessList\": [{{cidrNotation: \"10.10.1.1/21\", description: \"my ip address\"}}]}}"
    );
    println!();

    // LIST CLUSTERS
    println!("{}", "LIST CLUSTERS".bold().yellow());
    println!(
        "{}",
        "┌─────────────────────────────────────────────────────────────────────────────────────┐"
            .dimmed()
    );
    println!(
        "{}",
        "│ LIST CLUSTERS [WHERE <conditions>]                                                  │"
            .dimmed()
    );
    println!(
        "{}",
        "└─────────────────────────────────────────────────────────────────────────────────────┘"
            .dimmed()
    );
    println!();
    println!("{}", "Examples:".bold());
    println!("  LIST CLUSTERS");
    println!("  LIST CLUSTERS WHERE state=ACTIVE");
    println!();

    // GET CLUSTER
    println!("{}", "GET CLUSTER".bold().yellow());
    println!(
        "{}",
        "┌─────────────────────────────────────────────────────────────────────────────────────┐"
            .dimmed()
    );
    println!(
        "{}",
        "│ GET CLUSTER <name>                                                                  │"
            .dimmed()
    );
    println!(
        "{}",
        "└─────────────────────────────────────────────────────────────────────────────────────┘"
            .dimmed()
    );
    println!();
    println!("{}", "Examples:".bold());
    println!("  GET CLUSTER my-cluster");
    println!();

    // UPDATE CLUSTER
    println!("{}", "UPDATE CLUSTER".bold().yellow());
    println!(
        "{}",
        "┌─────────────────────────────────────────────────────────────────────────────────────┐"
            .dimmed()
    );
    println!(
        "{}",
        "│ UPDATE CLUSTER <name> WITH <parameters>                                             │"
            .dimmed()
    );
    println!(
        "{}",
        "└─────────────────────────────────────────────────────────────────────────────────────┘"
            .dimmed()
    );
    println!();
    println!("{}", "Parameters:".bold());
    println!(
        "  {}  {}  {}",
        "display_name".cyan(),
        "=".white(),
        "New display name".white()
    );
    println!(
        "  {}  {}  {}",
        "min_rcu".cyan(),
        "=".white(),
        "New minimum RCU".white()
    );
    println!(
        "  {}  {}  {}",
        "max_rcu".cyan(),
        "=".white(),
        "New maximum RCU".white()
    );
    println!(
        "  {}  {}  {}",
        "root_password".cyan(),
        "=".white(),
        "New root password for database access".white()
    );
    println!(
        "  {}  {}  {}",
        "public_connection".cyan(),
        "=".white(),
        "Public connection settings object".white()
    );
    println!();
    println!("{}", "Examples:".bold());
    println!("  UPDATE CLUSTER my-cluster WITH max_rcu=20");
    println!("  UPDATE CLUSTER my-cluster WITH display_name=\"Updated Cluster\"");
    println!("  UPDATE CLUSTER my-cluster WITH root_password=\"newpassword123\"");
    println!(
        "  UPDATE CLUSTER my-cluster WITH public_connection={{enabled: true, \"ipAccessList\": [{{cidrNotation: \"10.10.1.1/21\", description: \"my ip address\"}}]}}"
    );
    println!();

    // DELETE CLUSTER
    println!("{}", "DELETE CLUSTER".bold().yellow());
    println!(
        "{}",
        "┌─────────────────────────────────────────────────────────────────────────────────────┐"
            .dimmed()
    );
    println!(
        "{}",
        "│ DELETE CLUSTER <name>                                                               │"
            .dimmed()
    );
    println!(
        "{}",
        "└─────────────────────────────────────────────────────────────────────────────────────┘"
            .dimmed()
    );
    println!();
    println!("{}", "Examples:".bold());
    println!("  DELETE CLUSTER my-cluster");
    println!();

    // WAIT FOR CLUSTER
    println!("{}", "WAIT FOR CLUSTER".bold().yellow());
    println!(
        "{}",
        "┌─────────────────────────────────────────────────────────────────────────────────────┐"
            .dimmed()
    );
    println!(
        "{}",
        "│ WAIT FOR <cluster> TO BE <state> [WITH timeout=<seconds>]                           │"
            .dimmed()
    );
    println!(
        "{}",
        "└─────────────────────────────────────────────────────────────────────────────────────┘"
            .dimmed()
    );
    println!();
    println!("{}", "States:".bold());
    println!(
        "  {}  {}",
        "ACTIVE".green(),
        "- Cluster is ready for use".white()
    );
    println!(
        "  {}  {}",
        "CREATING".yellow(),
        "- Cluster is being created".white()
    );
    println!(
        "  {}  {}",
        "DELETING".red(),
        "- Cluster is being deleted".white()
    );
    println!(
        "  {}  {}",
        "UPDATING".yellow(),
        "- Cluster is being updated".white()
    );
    println!();
    println!("{}", "Examples:".bold());
    println!("  WAIT FOR my-cluster TO BE ACTIVE");
    println!("  WAIT FOR my-cluster TO BE ACTIVE WITH timeout=600");
    println!();

    // Backup Management Commands
    println!("{}", "💾 BACKUP MANAGEMENT".bold().green());
    println!("{}", "===================".green());
    println!();

    // CREATE BACKUP
    println!("{}", "CREATE BACKUP".bold().yellow());
    println!(
        "{}",
        "┌─────────────────────────────────────────────────────────────────────────────────────┐"
            .dimmed()
    );
    println!(
        "{}",
        "│ CREATE BACKUP FOR <cluster> [WITH description=<desc>]                               │"
            .dimmed()
    );
    println!(
        "{}",
        "└─────────────────────────────────────────────────────────────────────────────────────┘"
            .dimmed()
    );
    println!();
    println!("{}", "Examples:".bold());
    println!("  CREATE BACKUP FOR my-cluster");
    println!("  CREATE BACKUP FOR my-cluster WITH description=\"Daily backup\"");
    println!();

    // LIST BACKUPS
    println!("{}", "LIST BACKUPS".bold().yellow());
    println!(
        "{}",
        "┌─────────────────────────────────────────────────────────────────────────────────────┐"
            .dimmed()
    );
    println!(
        "{}",
        "│ LIST BACKUPS FOR <cluster>                                                          │"
            .dimmed()
    );
    println!(
        "{}",
        "└─────────────────────────────────────────────────────────────────────────────────────┘"
            .dimmed()
    );
    println!();
    println!("{}", "Examples:".bold());
    println!("  LIST BACKUPS FOR my-cluster");
    println!();

    // DELETE BACKUP
    println!("{}", "DELETE BACKUP".bold().yellow());
    println!(
        "{}",
        "┌─────────────────────────────────────────────────────────────────────────────────────┐"
            .dimmed()
    );
    println!(
        "{}",
        "│ DELETE BACKUP <backup_id> FROM <cluster>                                            │"
            .dimmed()
    );
    println!(
        "{}",
        "└─────────────────────────────────────────────────────────────────────────────────────┘"
            .dimmed()
    );
    println!();
    println!("{}", "Examples:".bold());
    println!("  DELETE BACKUP backup-123 FROM my-cluster");
    println!();

    // Pricing Commands
    println!("{}", "💰 PRICING".bold().green());
    println!("{}", "==========".green());
    println!();

    // ESTIMATE PRICE
    println!("{}", "ESTIMATE PRICE".bold().yellow());
    println!(
        "{}",
        "┌─────────────────────────────────────────────────────────────────────────────────────┐"
            .dimmed()
    );
    println!(
        "{}",
        "│ ESTIMATE PRICE IN <region> WITH <parameters>                                        │"
            .dimmed()
    );
    println!(
        "{}",
        "└─────────────────────────────────────────────────────────────────────────────────────┘"
            .dimmed()
    );
    println!();
    println!("{}", "Parameters:".bold());
    println!(
        "  {}  {}  {}",
        "min_rcu".cyan(),
        "=".white(),
        "Minimum RCU (1-1000)".white()
    );
    println!(
        "  {}  {}  {}",
        "max_rcu".cyan(),
        "=".white(),
        "Maximum RCU (1-1000)".white()
    );
    println!(
        "  {}  {}  {}",
        "service_plan".cyan(),
        "=".white(),
        "STARTER | ESSENTIAL | PREMIUM | BYOC".white()
    );
    println!(
        "  {}  {}  {}",
        "row_storage_size".cyan(),
        "=".white(),
        "Row storage size in bytes".white()
    );
    println!(
        "  {}  {}  {}",
        "column_storage_size".cyan(),
        "=".white(),
        "Column storage size in bytes".white()
    );
    println!();
    println!("{}", "Examples:".bold());
    println!("  ESTIMATE PRICE IN aws-us-west-1 WITH min_rcu=1, max_rcu=10, service_plan=STARTER");
    println!(
        "  ESTIMATE PRICE IN aws-us-east-1 WITH min_rcu=100, max_rcu=1000, service_plan=PREMIUM, row_storage_size=1073741824"
    );
    println!();

    // Variable Commands
    println!("{}", "🔧 VARIABLES".bold().green());
    println!("{}", "============".green());
    println!();

    // SET VARIABLE
    println!("{}", "SET VARIABLE".bold().yellow());
    println!(
        "{}",
        "┌─────────────────────────────────────────────────────────────────────────────────────┐"
            .dimmed()
    );
    println!(
        "{}",
        "│ SET <variable> = <value>                                                            │"
            .dimmed()
    );
    println!(
        "{}",
        "└─────────────────────────────────────────────────────────────────────────────────────┘"
            .dimmed()
    );
    println!();
    println!("{}", "Examples:".bold());
    println!("  SET region = \"aws-us-west-1\"");
    println!("  SET cluster_name = \"my-cluster\"");
    println!("  SET timeout = 600");
    println!();

    // GET VARIABLE
    println!("{}", "GET VARIABLE".bold().yellow());
    println!(
        "{}",
        "┌─────────────────────────────────────────────────────────────────────────────────────┐"
            .dimmed()
    );
    println!(
        "{}",
        "│ GET <variable>                                                                      │"
            .dimmed()
    );
    println!(
        "{}",
        "└─────────────────────────────────────────────────────────────────────────────────────┘"
            .dimmed()
    );
    println!();
    println!("{}", "Examples:".bold());
    println!("  GET region");
    println!("  GET cluster_name");
    println!();

    // Control Flow Commands
    println!("{}", "🔄 CONTROL FLOW".bold().green());
    println!("{}", "==============".green());
    println!();

    // IF
    println!("{}", "IF STATEMENT".bold().yellow());
    println!(
        "{}",
        "┌─────────────────────────────────────────────────────────────────────────────────────┐"
            .dimmed()
    );
    println!(
        "{}",
        "│ IF <condition> THEN                                                                 │"
            .dimmed()
    );
    println!(
        "{}",
        "│   <commands>                                                                        │"
            .dimmed()
    );
    println!(
        "{}",
        "│ [ELSE                                                                               │"
            .dimmed()
    );
    println!(
        "{}",
        "│   <commands>]                                                                       │"
            .dimmed()
    );
    println!(
        "{}",
        "│ END                                                                                 │"
            .dimmed()
    );
    println!(
        "{}",
        "└─────────────────────────────────────────────────────────────────────────────────────┘"
            .dimmed()
    );
    println!();
    println!("{}", "Examples:".bold());
    println!("  IF ${{cluster_exists}} THEN");
    println!("    ECHO \"Cluster already exists\"");
    println!("  ELSE");
    println!("    CREATE CLUSTER ${{cluster_name}} IN ${{region}}");
    println!("  END");
    println!();

    // LOOP
    println!("{}", "LOOP".bold().yellow());
    println!(
        "{}",
        "┌─────────────────────────────────────────────────────────────────────────────────────┐"
            .dimmed()
    );
    println!(
        "{}",
        "│ LOOP                                                                                │"
            .dimmed()
    );
    println!(
        "{}",
        "│   <commands>                                                                        │"
            .dimmed()
    );
    println!(
        "{}",
        "│ END                                                                                 │"
            .dimmed()
    );
    println!(
        "{}",
        "└─────────────────────────────────────────────────────────────────────────────────────┘"
            .dimmed()
    );
    println!();
    println!("{}", "Examples:".bold());
    println!("  LOOP");
    println!("    GET CLUSTER my-cluster");
    println!("    SLEEP 30");
    println!("  END");
    println!();

    // BREAK/CONTINUE
    println!("{}", "BREAK/CONTINUE".bold().yellow());
    println!(
        "{}",
        "┌─────────────────────────────────────────────────────────────────────────────────────┐"
            .dimmed()
    );
    println!(
        "{}",
        "│ BREAK                                                                               │"
            .dimmed()
    );
    println!(
        "{}",
        "│ CONTINUE                                                                            │"
            .dimmed()
    );
    println!(
        "{}",
        "└─────────────────────────────────────────────────────────────────────────────────────┘"
            .dimmed()
    );
    println!();
    println!("{}", "Examples:".bold());
    println!("  IF ${{condition}} THEN");
    println!("    BREAK");
    println!("  END");
    println!();

    // RETURN
    println!("{}", "RETURN".bold().yellow());
    println!(
        "{}",
        "┌─────────────────────────────────────────────────────────────────────────────────────┐"
            .dimmed()
    );
    println!(
        "{}",
        "│ RETURN [<value>]                                                                    │"
            .dimmed()
    );
    println!(
        "{}",
        "└─────────────────────────────────────────────────────────────────────────────────────┘"
            .dimmed()
    );
    println!();
    println!("{}", "Examples:".bold());
    println!("  RETURN");
    println!("  RETURN \"success\"");
    println!();

    // Utility Commands
    println!("{}", "🛠️  UTILITY".bold().green());
    println!("{}", "===========".green());
    println!();

    // ECHO
    println!("{}", "ECHO".bold().yellow());
    println!(
        "{}",
        "┌─────────────────────────────────────────────────────────────────────────────────────┐"
            .dimmed()
    );
    println!(
        "{}",
        "│ ECHO <message>                                                                      │"
            .dimmed()
    );
    println!(
        "{}",
        "└─────────────────────────────────────────────────────────────────────────────────────┘"
            .dimmed()
    );
    println!();
    println!("{}", "Examples:".bold());
    println!("  ECHO \"Cluster created successfully!\"");
    println!("  ECHO \"Current region: ${{region}}\"");
    println!();

    // SLEEP
    println!("{}", "SLEEP".bold().yellow());
    println!(
        "{}",
        "┌─────────────────────────────────────────────────────────────────────────────────────┐"
            .dimmed()
    );
    println!(
        "{}",
        "│ SLEEP <seconds>                                                                     │"
            .dimmed()
    );
    println!(
        "{}",
        "└─────────────────────────────────────────────────────────────────────────────────────┘"
            .dimmed()
    );
    println!();
    println!("{}", "Examples:".bold());
    println!("  SLEEP 30");
    println!("  SLEEP 2.5");
    println!();

    // EXIT
    println!("{}", "EXIT".bold().yellow());
    println!(
        "{}",
        "┌─────────────────────────────────────────────────────────────────────────────────────┐"
            .dimmed()
    );
    println!(
        "{}",
        "│ EXIT                                                                                │"
            .dimmed()
    );
    println!(
        "{}",
        "└─────────────────────────────────────────────────────────────────────────────────────┘"
            .dimmed()
    );
    println!();
    println!("{}", "Examples:".bold());
    println!("  EXIT");
    println!();

    // Syntax Notes
    println!("{}", "📝 SYNTAX NOTES".bold().green());
    println!("{}", "==============".green());
    println!();
    println!("{}", "• Variables:".bold());
    println!("  Use ${{variable_name}} to reference variables in commands");
    println!("  Example: CREATE CLUSTER ${{cluster_name}} IN ${{region}}");
    println!();
    println!("{}", "• Strings:".bold());
    println!("  Use double quotes for strings: \"my string\"");
    println!("  Example: SET region = \"aws-us-west-1\"");
    println!();
    println!("{}", "• Numbers:".bold());
    println!("  Numbers can be integers or decimals");
    println!("  Example: SET timeout = 600, SLEEP 2.5");
    println!();
    println!("{}", "• Optional Parameters:".bold());
    println!("  Parameters in [brackets] are optional");
    println!("  Example: CREATE CLUSTER name IN region [WITH params]");
    println!();
    println!("{}", "• Comments:".bold());
    println!("  Use # for single-line comments");
    println!("  Example: # This is a comment");
    println!();

    println!(
        "{}",
        "For more examples, run: tidb-dsl examples".bold().cyan()
    );
}

fn show_interactive_help() {
    println!("Interactive Mode Commands:");
    println!("=========================");
    println!("  <dsl_command>  - Execute a DSL command");
    println!("  help           - Show this help");
    println!("  help commands  - Show detailed command syntax with diagrams");
    println!("  help examples  - Show syntax examples");
    println!("  variables      - Show current variables");
    println!("  clear          - Clear all variables");
    println!("  edit           - Open editor to compose DSL commands");
    println!("  history        - Show command history");
    println!("  clear-history  - Clear command history");
    println!("  exit/quit      - Exit interactive mode");
    println!();
    println!("Keyboard Shortcuts:");
    println!("  ↑/↓            - Navigate through command history");
    println!("  Ctrl+R         - Search command history");
    println!("  Ctrl+L         - Clear screen");
    println!("  Ctrl+C         - Cancel current command");
    println!("  Ctrl+D         - Exit (EOF)");
    println!();
    println!("DSL Command Examples:");
    println!("  LIST CLUSTERS");
    println!("  SET region = \"aws-us-west-1\"");
    println!("  ECHO \"Hello, World!\"");
    println!("  SLEEP 5");
    println!();
    println!("Multiple Commands:");
    println!("  Use semicolons (;) to separate multiple commands:");
    println!("  ECHO \"Hello\"; SET region = \"us-east-1\"; LIST CLUSTERS");
    println!("  SLEEP 2; ECHO \"Done\"; WAIT FOR my-cluster TO BE Active");
}

fn show_variables(executor: &DSLExecutor) {
    let variables = executor.get_variables();
    if variables.is_empty() {
        println!("No variables set");
    } else {
        println!("Current variables:");
        for (name, value) in variables {
            println!("  {name} = {value}");
        }
    }
}

async fn execute_edit_command(
    executor: &mut DSLExecutor,
    initial_command: Option<String>,
    empty: bool,
    editor: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    use tracing::{debug, error, info};

    // Determine initial content for the editor
    let initial_content = if empty {
        String::new()
    } else if let Some(cmd) = initial_command {
        cmd
    } else {
        // Default template
        r#"# Edit your DSL command below
# Examples:
# ECHO "Hello, World!"
# LIST CLUSTERS
# SET region = "aws-us-west-1"
# CREATE CLUSTER my-cluster IN aws-us-west-1 WITH min_rcu=1, max_rcu=10

"#
        .to_string()
    };

    info!("Opening editor for DSL command editing");
    debug!("Initial content: {}", initial_content);

    // Set editor if specified
    if let Some(editor_name) = editor {
        unsafe {
            std::env::set_var("EDITOR", editor_name);
        }
        debug!("Using specified editor: {}", editor_name);
    }

    // Open editor and get edited content
    let edited_content = match edit(initial_content) {
        Ok(content) => content,
        Err(e) => {
            error!("Failed to open editor: {}", e);
            return Err(format!("Failed to open editor: {e}").into());
        }
    };

    // Trim whitespace and check if content is empty
    let trimmed_content = edited_content.trim();
    if trimmed_content.is_empty() {
        info!("No content provided, skipping execution");
        println!("No content provided, skipping execution");
        return Ok(());
    }

    // Remove comment lines and empty lines
    let lines: Vec<&str> = trimmed_content
        .lines()
        .filter(|line| {
            let trimmed = line.trim();
            !trimmed.is_empty() && !trimmed.starts_with('#')
        })
        .collect();

    if lines.is_empty() {
        info!("No valid commands found after filtering comments");
        println!("No valid commands found after filtering comments");
        return Ok(());
    }

    // Join lines and execute
    let final_command = lines.join("\n");
    info!("Executing edited command: {}", final_command);
    println!("Executing command:");
    println!("{final_command}");
    println!();

    // Execute the command
    execute_single_command(executor, &final_command).await?;

    Ok(())
}

/// Get the history file path
fn get_history_file_path() -> Result<PathBuf, Box<dyn std::error::Error>> {
    let home_dir = env::var("HOME")
        .or_else(|_| env::var("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."));

    let history_dir = home_dir.join(".tidb_dsl");
    fs::create_dir_all(&history_dir)?;

    Ok(history_dir.join("history.txt"))
}

/// Show command history
fn show_history(rl: &DefaultEditor) {
    println!("Command History:");
    println!("================");

    // Use a simple counter to show history entries
    let mut count = 0;
    for entry in rl.history().iter() {
        count += 1;
        println!("{count:3}: {entry}");
    }

    if count == 0 {
        println!("No command history");
    } else {
        println!("Total: {count} commands");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ast_parsing_valid_sql() {
        let result = UnifiedParser::parse("select displayName from cluster");
        println!("AST Result: {result:?}");
        assert!(
            result.is_ok(),
            "AST parsing should succeed for valid SQL syntax"
        );
    }

    #[test]
    fn test_ast_parsing_with_field_validation_deferred() {
        let result = UnifiedParser::parse("select n from cluster");
        println!("AST Result: {result:?}");
        // The new AST-based architecture allows syntactically valid SQL to parse
        // Field validation is deferred to execution time
        assert!(
            result.is_ok(),
            "AST parsing should succeed for syntactically valid SQL"
        );
    }

    #[test]
    fn test_ast_parsing_echo_command() {
        let result = UnifiedParser::parse("echo \"Hello World\"");
        println!("AST Result: {result:?}");
        assert!(
            result.is_ok(),
            "AST parsing should succeed for echo commands"
        );
    }

    #[test]
    fn test_ast_parsing_select_backups() {
        let result = UnifiedParser::parse("SELECT * FROM BACKUPS");
        println!("AST Result: {result:?}");
        assert!(
            result.is_ok(),
            "AST parsing should succeed for SELECT queries"
        );

        // Verify it creates a Select AST node
        let ast = result.unwrap();
        match ast {
            tidb_cli::dsl::ast::ASTNode::Query(tidb_cli::dsl::ast::QueryNode::Select {
                ..
            }) => {
                // Success - it's a Select query
            }
            _ => panic!("Expected SELECT query to create a Select AST node"),
        }
    }
}
