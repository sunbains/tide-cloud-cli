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
    /// SELECT field1, field2 FROM CLUSTER [name] [WHERE condition] -> LIST CLUSTERS [WHERE condition]
    fn transform_select(input: &str) -> DSLResult<String> {
        let parts: Vec<&str> = input.split_whitespace().collect();

        if parts.len() < 4 {
            return Err(DSLError::syntax_error(0, "Invalid SELECT syntax"));
        }

        if parts[0].to_uppercase() != "SELECT" {
            return Err(DSLError::syntax_error(0, "Expected SELECT"));
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

        let mut result = "LIST CLUSTERS".to_string();

        // Add WHERE clause if present (after FROM CLUSTER)
        if let Some(where_index) = parts[from_cluster_pos..]
            .iter()
            .position(|&p| p.to_uppercase() == "WHERE")
            .map(|pos| from_cluster_pos + pos)
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

    /// Transform CREATE command
    /// CREATE CLUSTER name IN region [WITH options] -> CREATE CLUSTER name IN region [WITH options]
    fn transform_create(input: &str) -> DSLResult<String> {
        // CREATE syntax is already compatible, just pass through
        Ok(input.to_string())
    }

    /// Transform DROP command
    /// DROP CLUSTER name -> DELETE CLUSTER name
    fn transform_drop(input: &str) -> DSLResult<String> {
        let parts: Vec<&str> = input.split_whitespace().collect();

        if parts.len() < 3 {
            return Err(DSLError::syntax_error(0, "Invalid DROP syntax"));
        }

        if parts[0].to_uppercase() != "DROP" || parts[1].to_uppercase() != "CLUSTER" {
            return Err(DSLError::syntax_error(0, "Expected DROP CLUSTER"));
        }

        let cluster_name = parts[2];
        Ok(format!("DELETE CLUSTER {cluster_name}"))
    }

    /// Transform UPDATE command
    /// UPDATE CLUSTER name SET field1 = value1, field2 = value2 -> UPDATE CLUSTER name WITH field1 = value1, field2 = value2
    fn transform_update(input: &str) -> DSLResult<String> {
        let parts: Vec<&str> = input.split_whitespace().collect();

        if parts.len() < 6 {
            return Err(DSLError::syntax_error(0, "Invalid UPDATE syntax"));
        }

        if parts[0].to_uppercase() != "UPDATE" || parts[1].to_uppercase() != "CLUSTER" {
            return Err(DSLError::syntax_error(0, "Expected UPDATE CLUSTER"));
        }

        let cluster_name = parts[2];

        if parts[3].to_uppercase() != "SET" {
            return Err(DSLError::syntax_error(0, "Expected SET"));
        }

        let mut result = format!("UPDATE CLUSTER {cluster_name} WITH");

        // Add the SET clause without the SET keyword
        let set_clause = parts[4..].join(" ");
        result.push_str(&format!(" {set_clause}"));

        Ok(result)
    }

    /// Transform WAIT command
    /// WAIT FOR CLUSTER name TO BE state [WITH timeout] -> WAIT FOR name TO BE state [WITH timeout]
    fn transform_wait(input: &str) -> DSLResult<String> {
        let parts: Vec<&str> = input.split_whitespace().collect();

        if parts.len() < 7 {
            return Err(DSLError::syntax_error(0, "Invalid WAIT syntax"));
        }

        if parts[0].to_uppercase() != "WAIT"
            || parts[1].to_uppercase() != "FOR"
            || parts[2].to_uppercase() != "CLUSTER"
        {
            return Err(DSLError::syntax_error(0, "Expected WAIT FOR CLUSTER"));
        }

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
            SQLDSLParser::transform_select("SELECT display_name INTO cluster_name FROM CLUSTER");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "LIST CLUSTERS INTO cluster_name");
    }

    #[test]
    fn test_transform_select_with_into_multiple_vars() {
        let result = SQLDSLParser::transform_select(
            "SELECT display_name, region INTO cluster_name, cluster_region FROM CLUSTER",
        );
        assert!(result.is_ok());
        assert_eq!(
            result.unwrap(),
            "LIST CLUSTERS INTO cluster_name, cluster_region"
        );
    }

    #[test]
    fn test_transform_select_with_where_and_into() {
        let result = SQLDSLParser::transform_select(
            "SELECT display_name INTO cluster_name FROM CLUSTER WHERE state = 'active'",
        );
        assert!(result.is_ok());
        assert_eq!(
            result.unwrap(),
            "LIST CLUSTERS WHERE state = 'active' INTO cluster_name"
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
    fn test_transform_drop() {
        let result = SQLDSLParser::transform_drop("DROP CLUSTER my-cluster");
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
        let result = SQLDSLParser::parse("SELECT display_name INTO cluster_name FROM CLUSTER");
        assert!(result.is_ok());
        let command = result.unwrap();
        assert_eq!(command.command_type, DSLCommandType::ListClusters);
    }

    #[test]
    fn test_parse_select_with_where_and_into() {
        let result = SQLDSLParser::parse(
            "SELECT display_name INTO cluster_name FROM CLUSTER WHERE state = 'active'",
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
    fn test_parse_drop_cluster() {
        let result = SQLDSLParser::parse("DROP CLUSTER my-cluster");
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
}
