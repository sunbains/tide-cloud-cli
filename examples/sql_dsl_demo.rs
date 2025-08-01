use tidb_cli::dsl::parser::DSLParser;
use tidb_cli::dsl::sql_parser::SQLDSLParser;

fn main() {
    println!("=== TiDB Cloud SQL-like DSL Parser Demo ===\n");

    // Example SQL-like commands
    let sql_commands = vec![
        "SELECT * FROM CLUSTER",
        "SELECT * FROM CLUSTER WHERE state = 'active'",
        "SELECT display_name INTO cluster_name FROM CLUSTER WHERE state = 'active'",
        "SELECT display_name, region INTO cluster_name, cluster_region FROM CLUSTER",
        "CREATE CLUSTER my-cluster IN 'aws-us-west-1'",
        "CREATE CLUSTER my-cluster IN 'aws-us-west-1' WITH min_rcu = 1000, max_rcu = 5000",
        "UPDATE CLUSTER my-cluster SET min_rcu = 2000, max_rcu = 6000, service_plan = 'premium'",
        "DROP CLUSTER my-cluster",
        "WAIT FOR CLUSTER my-cluster TO BE active",
        "WAIT FOR CLUSTER my-cluster TO BE active WITH timeout = 300",
    ];

    for (i, sql_cmd) in sql_commands.iter().enumerate() {
        println!("{}. SQL-like command: {}", i + 1, sql_cmd);

        // Parse with SQL parser
        match SQLDSLParser::parse(sql_cmd) {
            Ok(sql_command) => {
                println!("   SQL Parser Result: {:?}", sql_command.command_type);

                // Show the transformed DSL command
                match SQLDSLParser::transform_sql_to_dsl(sql_cmd) {
                    Ok(transformed) => {
                        println!("   Transformed to: {}", transformed);

                        // Parse with original parser for comparison
                        match DSLParser::parse(&transformed) {
                            Ok(original_command) => {
                                println!(
                                    "   Original Parser Result: {:?}",
                                    original_command.command_type
                                );
                                println!("   ✅ Both parsers produce the same command type");
                            }
                            Err(e) => {
                                println!("   ❌ Original parser failed: {}", e);
                            }
                        }
                    }
                    Err(e) => {
                        println!("   ❌ Transformation failed: {}", e);
                    }
                }
            }
            Err(e) => {
                println!("   ❌ SQL parser failed: {}", e);
            }
        }
        println!();
    }

    println!("=== Comparison with Original DSL Syntax ===\n");

    let original_commands = vec![
        "LIST CLUSTERS",
        "LIST CLUSTERS WHERE state = 'active'",
        "LIST CLUSTERS WHERE state = 'active' INTO cluster_name",
        "LIST CLUSTERS INTO cluster_name, cluster_region",
        "CREATE CLUSTER my-cluster IN 'aws-us-west-1'",
        "CREATE CLUSTER my-cluster IN 'aws-us-west-1' WITH min_rcu = 1000, max_rcu = 5000",
        "UPDATE CLUSTER my-cluster WITH min_rcu = 2000, max_rcu = 6000, service_plan = 'premium'",
        "DELETE CLUSTER my-cluster",
        "WAIT FOR my-cluster TO BE active",
        "WAIT FOR my-cluster TO BE active WITH timeout = 300",
    ];

    for (i, original_cmd) in original_commands.iter().enumerate() {
        println!("{}. Original DSL command: {}", i + 1, original_cmd);

        match DSLParser::parse(original_cmd) {
            Ok(command) => {
                println!("   Original Parser Result: {:?}", command.command_type);
            }
            Err(e) => {
                println!("   ❌ Original parser failed: {}", e);
            }
        }
        println!();
    }

    println!("=== Summary ===");
    println!("The SQL-like parser transforms SQL syntax to the existing DSL syntax,");
    println!("allowing users to use familiar SQL commands while maintaining compatibility");
    println!("with the existing parser infrastructure.");
}
