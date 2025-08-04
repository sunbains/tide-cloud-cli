use crate::dsl::commands::DSLCommand;
use crate::dsl::error::{DSLError, DSLResult};
use crate::dsl::parser::DSLParser;

#[cfg(test)]
use crate::dsl::commands::DSLCommandType;

/// SQL-like DSL Parser
///
/// This parser implements a SQL-like syntax for TiDB Cloud operations:
/// - SELECT * FROM CLUSTER <name|id> WHERE <condition>
/// - SELECT <field_list> FROM CLUSTER <name|id> WHERE <condition>
/// - CREATE CLUSTER <name> IN <region> WITH <options>
/// - DELETE FROM CLUSTER <name|id>
/// - UPDATE CLUSTER <name|id> SET <field> = <value>
/// - WAIT FOR CLUSTER <name|id> TO BE <state>
pub struct SQLDSLParser;

impl SQLDSLParser {
    /// Parse a SQL-like DSL command
    pub fn parse(input: &str) -> DSLResult<DSLCommand> {
        // For now, we'll use the existing parser and transform the SQL-like syntax
        // to the existing DSL syntax before parsing

        let transformed_input = Self::transform_sql_to_dsl(input)?;
        DSLParser::parse(&transformed_input)
    }

    /// Parse a script containing multiple SQL-like commands
    pub fn parse_script(input: &str) -> DSLResult<Vec<DSLCommand>> {
        let mut commands = Vec::new();
        let lines: Vec<&str> = input
            .lines()
            .map(|line| line.trim())
            .filter(|line| !line.is_empty() && !line.starts_with("--"))
            .collect();

        for (line_num, line) in lines.iter().enumerate() {
            match Self::parse(line) {
                Ok(command) => commands.push(command),
                Err(e) => {
                    return Err(DSLError::syntax_error(
                        line_num + 1,
                        format!("Failed to parse line {}: {}", line_num + 1, e),
                    ));
                }
            }
        }

        Ok(commands)
    }

    /// Transform SQL-like syntax to existing DSL syntax
    pub fn transform_sql_to_dsl(input: &str) -> DSLResult<String> {
        let input = input.trim();

        if input.to_uppercase().starts_with("SELECT") {
            Self::transform_select(input)
        } else if input.to_uppercase().starts_with("CREATE") {
            Self::transform_create(input)
        } else if input.to_uppercase().starts_with("UPDATE") {
            Self::transform_update(input)
        } else if input.to_uppercase().starts_with("DROP") {
            Self::transform_drop(input)
        } else if input.to_uppercase().starts_with("WAIT") {
            Self::transform_wait(input)
        } else {
            // For other commands, pass through as-is
            Ok(input.to_string())
        }
    }

    /// Transform SELECT command
    /// SELECT * FROM CLUSTER [name] [WHERE condition] -> LIST CLUSTERS [WHERE condition]
    /// SELECT field1, field2 FROM CLUSTER [name] [WHERE condition] -> LIST CLUSTERS [WHERE condition] or GET CLUSTER [name]
    fn transform_select(input: &str) -> DSLResult<String> {
        let parts: Vec<&str> = input.split_whitespace().collect();

        if parts.len() < 4 {
            return Err(DSLError::syntax_error(0, "Invalid SELECT syntax"));
        }

        if parts[0].to_uppercase() != "SELECT" {
            return Err(DSLError::syntax_error(0, "Expected SELECT"));
        }

        // Parse the field list (everything between SELECT and FROM, but before INTO)
        let from_pos = parts
            .iter()
            .position(|&p| p.to_uppercase() == "FROM")
            .ok_or_else(|| DSLError::syntax_error(0, "Expected FROM"))?;

        // Find INTO position if it exists (before FROM)
        let into_pos = parts[..from_pos]
            .iter()
            .position(|&p| p.to_uppercase() == "INTO");

        // Field list is between SELECT and either INTO or FROM
        let field_end_pos = into_pos.unwrap_or(from_pos);
        let field_list = &parts[1..field_end_pos];
        if field_list.is_empty() {
            return Err(DSLError::syntax_error(0, "No fields specified in SELECT"));
        }

        // Check if it's SELECT * (all fields)
        let is_select_all = field_list.len() == 1 && field_list[0] == "*";

        // If not SELECT *, validate that the requested fields exist
        if !is_select_all {
            let valid_fields = Self::get_valid_cluster_fields();
            for field in field_list {
                let field_clean = field.trim_matches(',');
                if !valid_fields.contains(&field_clean) {
                    return Err(DSLError::syntax_error(
                        0,
                        format!(
                            "Invalid field '{}' in SELECT. Valid fields are: {}",
                            field_clean,
                            valid_fields.join(", ")
                        ),
                    ));
                }
            }
        }

        // Find FROM CLUSTER position
        let from_cluster_pos = parts
            .iter()
            .enumerate()
            .find(|(_, part)| part.to_uppercase() == "FROM")
            .and_then(|(i, _)| {
                if i + 1 < parts.len() && parts[i + 1].to_uppercase() == "CLUSTER" {
                    Some(i)
                } else {
                    None
                }
            })
            .ok_or_else(|| DSLError::syntax_error(0, "Expected FROM CLUSTER"))?;

        // Check if there's a specific cluster name after FROM CLUSTER
        let has_cluster_name = from_cluster_pos + 2 < parts.len()
            && !["WHERE", "INTO"].contains(&parts[from_cluster_pos + 2].to_uppercase().as_str());

        let mut result = if has_cluster_name {
            // SELECT * FROM CLUSTER <name> -> GET CLUSTER <name>
            let cluster_name = parts[from_cluster_pos + 2];
            format!("GET CLUSTER {cluster_name}")
        } else {
            // SELECT * FROM CLUSTER -> LIST CLUSTERS
            "LIST CLUSTERS".to_string()
        };

        // Add field selection parameter if not SELECT *
        if !is_select_all {
            let fields_str = field_list
                .iter()
                .map(|f| f.trim_matches(','))
                .filter(|f| !f.is_empty())
                .collect::<Vec<_>>()
                .join(",");
            result.push_str(&format!(" WITH selected_fields = \"{fields_str}\""));
        }

        // Add WHERE clause if present (after FROM CLUSTER or cluster name)
        let where_start_pos = if has_cluster_name {
            from_cluster_pos + 3
        } else {
            from_cluster_pos + 2
        };
        if let Some(where_index) = parts[where_start_pos..]
            .iter()
            .position(|&p| p.to_uppercase() == "WHERE")
            .map(|pos| where_start_pos + pos)
        {
            let where_clause = parts[where_index..].join(" ");
            result.push_str(&format!(" {where_clause}"));
        }

        // Add INTO clause if present (before FROM CLUSTER)
        if let Some(into_index) = parts[..from_cluster_pos]
            .iter()
            .position(|&p| p.to_uppercase() == "INTO")
        {
            let into_clause = parts[into_index..from_cluster_pos].join(" ");
            result.push_str(&format!(" {into_clause}"));
        }

        Ok(result)
    }

    /// Get the list of valid fields for cluster objects
    fn get_valid_cluster_fields() -> Vec<&'static str> {
        vec![
            "name",
            "displayName",
            "regionId",
            "regionDisplayName",
            "state",
            "minRcu",
            "maxRcu",
            "servicePlan",
            "cloudProvider",
            "highAvailabilityType",
            "rootPassword",
            "annotations",
            "labels",
            "creator",
            "createTime",
            "updateTime",
            "endpoints",
            "tidbId",
        ]
    }

    /// Transform CREATE command
    /// CREATE CLUSTER name IN region [WITH options] -> CREATE CLUSTER name IN region [WITH options]
    fn transform_create(input: &str) -> DSLResult<String> {
        // CREATE syntax is already compatible, just pass through
        Ok(input.to_string())
    }

    /// Transform DROP command
    /// DROP CLUSTER name -> DELETE CLUSTER name
    /// DELETE CLUSTER name -> DELETE CLUSTER name (pass through)
    fn transform_drop(input: &str) -> DSLResult<String> {
        let parts: Vec<&str> = input.split_whitespace().collect();

        if parts.len() < 3 {
            return Err(DSLError::syntax_error(0, "Invalid DROP/DELETE syntax"));
        }

        // Check if it's DROP CLUSTER format
        if parts[0].to_uppercase() == "DROP" && parts[1].to_uppercase() == "CLUSTER" {
            let cluster_name = parts[2];
            Ok(format!("DELETE CLUSTER {cluster_name}"))
        } else if parts[0].to_uppercase() == "DELETE" && parts[1].to_uppercase() == "CLUSTER" {
            // It's already in DELETE CLUSTER format, just pass it through
            Ok(input.to_string())
        } else {
            Err(DSLError::syntax_error(
                0,
                "Expected DROP CLUSTER or DELETE CLUSTER",
            ))
        }
    }

    /// Transform UPDATE command
    /// UPDATE CLUSTER name SET field1 = value1, field2 = value2 -> UPDATE CLUSTER name WITH field1 = value1, field2 = value2
    /// UPDATE CLUSTER name WITH field1 = value1, field2 = value2 -> UPDATE CLUSTER name WITH field1 = value1, field2 = value2 (pass through)
    fn transform_update(input: &str) -> DSLResult<String> {
        let parts: Vec<&str> = input.split_whitespace().collect();

        if parts.len() < 6 {
            return Err(DSLError::syntax_error(0, "Invalid UPDATE syntax"));
        }

        if parts[0].to_uppercase() != "UPDATE" || parts[1].to_uppercase() != "CLUSTER" {
            return Err(DSLError::syntax_error(0, "Expected UPDATE CLUSTER"));
        }

        let cluster_name = parts[2];

        // Check if it's SET or WITH format
        if parts[3].to_uppercase() == "SET" {
            let mut result = format!("UPDATE CLUSTER {cluster_name} WITH");

            // Add the SET clause without the SET keyword
            let set_clause = parts[4..].join(" ");
            result.push_str(&format!(" {set_clause}"));

            Ok(result)
        } else if parts[3].to_uppercase() == "WITH" {
            // It's already in WITH format, just pass it through
            Ok(input.to_string())
        } else {
            Err(DSLError::syntax_error(0, "Expected SET or WITH"))
        }
    }

    /// Transform WAIT command
    /// WAIT FOR CLUSTER name TO BE state [WITH timeout] -> WAIT FOR name TO BE state [WITH timeout]
    /// WAIT FOR name TO BE state [WITH timeout] -> WAIT FOR name TO BE state [WITH timeout] (pass through)
    fn transform_wait(input: &str) -> DSLResult<String> {
        let parts: Vec<&str> = input.split_whitespace().collect();

        if parts.len() < 6 {
            return Err(DSLError::syntax_error(0, "Invalid WAIT syntax"));
        }

        if parts[0].to_uppercase() != "WAIT" || parts[1].to_uppercase() != "FOR" {
            return Err(DSLError::syntax_error(0, "Expected WAIT FOR"));
        }

        // Check if it's WAIT FOR CLUSTER format
        if parts.len() >= 7 && parts[2].to_uppercase() == "CLUSTER" {
            let cluster_name = parts[3];

            if parts[4].to_uppercase() != "TO" || parts[5].to_uppercase() != "BE" {
                return Err(DSLError::syntax_error(0, "Expected TO BE"));
            }

            let state = parts[6];
            let mut result = format!("WAIT FOR {cluster_name} TO BE {state}");

            // Add WITH clause if present
            if let Some(with_index) = parts.iter().position(|&p| p.to_uppercase() == "WITH") {
                let with_clause = parts[with_index..].join(" ");
                result.push_str(&format!(" {with_clause}"));
            }

            Ok(result)
        } else {
            // It's already in WAIT FOR format, just pass it through
            Ok(input.to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transform_select_all_clusters() {
        let result = SQLDSLParser::transform_select("SELECT * FROM CLUSTER");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "LIST CLUSTERS");
    }

    #[test]
    fn test_transform_select_with_where() {
        let result = SQLDSLParser::transform_select("SELECT * FROM CLUSTER WHERE state = 'active'");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "LIST CLUSTERS WHERE state = 'active'");
    }

    #[test]
    fn test_transform_select_with_into() {
        let result =
            SQLDSLParser::transform_select("SELECT displayName INTO cluster_name FROM CLUSTER");
        if let Err(e) = &result {
            println!("Error: {}", e);
        }
        assert!(result.is_ok());
        assert_eq!(
            result.unwrap(),
            "LIST CLUSTERS WITH selected_fields = \"displayName\" INTO cluster_name"
        );
    }

    #[test]
    fn test_transform_select_with_into_multiple_vars() {
        let result = SQLDSLParser::transform_select(
            "SELECT displayName, regionId INTO cluster_name, cluster_region FROM CLUSTER",
        );
        assert!(result.is_ok());
        assert_eq!(
            result.unwrap(),
            "LIST CLUSTERS WITH selected_fields = \"displayName,regionId\" INTO cluster_name, cluster_region"
        );
    }

    #[test]
    fn test_transform_select_with_where_and_into() {
        let result = SQLDSLParser::transform_select(
            "SELECT displayName INTO cluster_name FROM CLUSTER WHERE state = 'active'",
        );
        assert!(result.is_ok());
        assert_eq!(
            result.unwrap(),
            "LIST CLUSTERS WITH selected_fields = \"displayName\" WHERE state = 'active' INTO cluster_name"
        );
    }

    #[test]
    fn test_transform_select_specific_cluster() {
        let result = SQLDSLParser::transform_select("SELECT * FROM CLUSTER my-cluster");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "GET CLUSTER my-cluster");
    }

    #[test]
    fn test_transform_select_specific_cluster_with_where() {
        let result = SQLDSLParser::transform_select(
            "SELECT * FROM CLUSTER my-cluster WHERE state = 'active'",
        );
        assert!(result.is_ok());
        assert_eq!(
            result.unwrap(),
            "GET CLUSTER my-cluster WHERE state = 'active'"
        );
    }

    #[test]
    fn test_transform_select_specific_cluster_with_into() {
        let result = SQLDSLParser::transform_select(
            "SELECT displayName INTO cluster_name FROM CLUSTER my-cluster",
        );
        assert!(result.is_ok());
        assert_eq!(
            result.unwrap(),
            "GET CLUSTER my-cluster WITH selected_fields = \"displayName\" INTO cluster_name"
        );
    }

    #[test]
    fn test_transform_update() {
        let result = SQLDSLParser::transform_update(
            "UPDATE CLUSTER my-cluster SET min_rcu = 2000, max_rcu = 6000",
        );
        assert!(result.is_ok());
        assert_eq!(
            result.unwrap(),
            "UPDATE CLUSTER my-cluster WITH min_rcu = 2000, max_rcu = 6000"
        );
    }

    #[test]
    fn test_transform_update_single_field() {
        let result = SQLDSLParser::transform_update("UPDATE CLUSTER my-cluster SET min_rcu = 2000");
        assert!(result.is_ok());
        assert_eq!(
            result.unwrap(),
            "UPDATE CLUSTER my-cluster WITH min_rcu = 2000"
        );
    }

    #[test]
    fn test_transform_update_multiple_fields() {
        let result = SQLDSLParser::transform_update(
            "UPDATE CLUSTER my-cluster SET min_rcu = 2000, max_rcu = 6000, service_plan = 'premium'",
        );
        assert!(result.is_ok());
        assert_eq!(
            result.unwrap(),
            "UPDATE CLUSTER my-cluster WITH min_rcu = 2000, max_rcu = 6000, service_plan = 'premium'"
        );
    }

    #[test]
    fn test_transform_update_with() {
        let result =
            SQLDSLParser::transform_update("UPDATE CLUSTER my-cluster WITH min_rcu = 2000");
        assert!(result.is_ok());
        assert_eq!(
            result.unwrap(),
            "UPDATE CLUSTER my-cluster WITH min_rcu = 2000"
        );
    }

    #[test]
    fn test_transform_update_with_exact_command() {
        let result = SQLDSLParser::transform_update(
            "UPDATE CLUSTER SB-Test02-delete-whenever WITH root_password = 'test-tidb'",
        );
        assert!(result.is_ok());
        assert_eq!(
            result.unwrap(),
            "UPDATE CLUSTER SB-Test02-delete-whenever WITH root_password = 'test-tidb'"
        );
    }

    #[test]
    fn test_transform_drop() {
        let result = SQLDSLParser::transform_drop("DROP CLUSTER my-cluster");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "DELETE CLUSTER my-cluster");
    }

    #[test]
    fn test_transform_delete() {
        let result = SQLDSLParser::transform_drop("DELETE CLUSTER my-cluster");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "DELETE CLUSTER my-cluster");
    }

    #[test]
    fn test_transform_wait() {
        let result = SQLDSLParser::transform_wait("WAIT FOR CLUSTER my-cluster TO BE active");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "WAIT FOR my-cluster TO BE active");
    }

    #[test]
    fn test_transform_wait_direct() {
        let result = SQLDSLParser::transform_wait("WAIT FOR my-cluster TO BE active");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "WAIT FOR my-cluster TO BE active");
    }

    #[test]
    fn test_transform_wait_exact_command() {
        let result =
            SQLDSLParser::transform_wait("WAIT FOR SB-Test02-delete-whenever TO BE Active");
        assert!(result.is_ok());
        assert_eq!(
            result.unwrap(),
            "WAIT FOR SB-Test02-delete-whenever TO BE Active"
        );
    }

    #[test]
    fn test_parse_select_all_clusters() {
        let result = SQLDSLParser::parse("SELECT * FROM CLUSTER");
        assert!(result.is_ok());
        let command = result.unwrap();
        assert_eq!(command.command_type, DSLCommandType::ListClusters);
    }

    #[test]
    fn test_parse_select_with_where() {
        let result = SQLDSLParser::parse("SELECT * FROM CLUSTER WHERE state = 'active'");
        assert!(result.is_ok());
        let command = result.unwrap();
        assert_eq!(command.command_type, DSLCommandType::ListClusters);
    }

    #[test]
    fn test_parse_select_with_into() {
        let result = SQLDSLParser::parse("SELECT displayName INTO cluster_name FROM CLUSTER");
        assert!(result.is_ok());
        let command = result.unwrap();
        assert_eq!(command.command_type, DSLCommandType::ListClusters);
    }

    #[test]
    fn test_parse_select_with_where_and_into() {
        let result = SQLDSLParser::parse(
            "SELECT displayName INTO cluster_name FROM CLUSTER WHERE state = 'active'",
        );
        assert!(result.is_ok());
        let command = result.unwrap();
        assert_eq!(command.command_type, DSLCommandType::ListClusters);
    }

    #[test]
    fn test_parse_create_cluster() {
        let result = SQLDSLParser::parse("CREATE CLUSTER my-cluster IN 'aws-us-west-1'");
        assert!(result.is_ok());
        let command = result.unwrap();
        assert_eq!(command.command_type, DSLCommandType::CreateCluster);
    }

    #[test]
    fn test_parse_update_cluster() {
        let result = SQLDSLParser::parse("UPDATE CLUSTER my-cluster SET min_rcu = 2000");
        assert!(result.is_ok());
        let command = result.unwrap();
        assert_eq!(command.command_type, DSLCommandType::UpdateCluster);
    }

    #[test]
    fn test_parse_update_cluster_with() {
        let result = SQLDSLParser::parse("UPDATE CLUSTER my-cluster WITH min_rcu = 2000");
        assert!(result.is_ok());
        let command = result.unwrap();
        assert_eq!(command.command_type, DSLCommandType::UpdateCluster);
    }

    #[test]
    fn test_parse_drop_cluster() {
        let result = SQLDSLParser::parse("DROP CLUSTER my-cluster");
        assert!(result.is_ok());
        let command = result.unwrap();
        assert_eq!(command.command_type, DSLCommandType::DeleteCluster);
    }

    #[test]
    fn test_parse_delete_cluster() {
        let result = SQLDSLParser::parse("DELETE CLUSTER my-cluster");
        assert!(result.is_ok());
        let command = result.unwrap();
        assert_eq!(command.command_type, DSLCommandType::DeleteCluster);
    }

    #[test]
    fn test_parse_wait_for_cluster() {
        let result = SQLDSLParser::parse("WAIT FOR CLUSTER my-cluster TO BE active");
        assert!(result.is_ok());
        let command = result.unwrap();
        assert_eq!(command.command_type, DSLCommandType::WaitForCluster);
    }

    #[test]
    fn test_parse_wait_for_direct() {
        let result = SQLDSLParser::parse("WAIT FOR my-cluster TO BE active");
        assert!(result.is_ok());
        let command = result.unwrap();
        assert_eq!(command.command_type, DSLCommandType::WaitForCluster);
    }

    #[test]
    fn test_transform_select_invalid_field() {
        let result = SQLDSLParser::transform_select("SELECT n FROM CLUSTER");
        assert!(result.is_err());
        let error = result.unwrap_err();
        println!("Error message: {}", error);
        assert!(error.to_string().contains("Invalid field 'n'"));
        assert!(error.to_string().contains("Valid fields are:"));
    }

    #[test]
    fn test_transform_select_valid_field() {
        let result = SQLDSLParser::transform_select("SELECT displayName FROM CLUSTER");
        assert!(result.is_ok());
        assert_eq!(
            result.unwrap(),
            "LIST CLUSTERS WITH selected_fields = \"displayName\""
        );
    }

    #[test]
    fn test_transform_select_multiple_valid_fields() {
        let result = SQLDSLParser::transform_select("SELECT displayName, state FROM CLUSTER");
        assert!(result.is_ok());
        assert_eq!(
            result.unwrap(),
            "LIST CLUSTERS WITH selected_fields = \"displayName,state\""
        );
    }

    #[test]
    fn test_transform_select_with_where_and_invalid_field() {
        let result = SQLDSLParser::transform_select(
            "SELECT invalid_field FROM CLUSTER WHERE displayName = 'test'",
        );
        assert!(result.is_err());
        let error = result.unwrap_err();
        assert!(error.to_string().contains("Invalid field 'invalid_field'"));
    }

    #[test]
    fn test_transform_select_all_fields() {
        let result = SQLDSLParser::transform_select("SELECT * FROM CLUSTER");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "LIST CLUSTERS");
    }
}
