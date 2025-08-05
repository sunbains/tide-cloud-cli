use crate::dsl::{
    ast::{ASTNode, CommandNode, FieldContext},
    error::{DSLError, DSLResult},
    syntax::DSLValue,
};

/// DSL to AST parser that converts DSL syntax to our AST representation
pub struct DSLASTParser;

impl DSLASTParser {
    /// Parse DSL input and convert to AST
    pub fn parse(input: &str) -> DSLResult<ASTNode> {
        let mut parser = DSLASTParser;
        parser.parse_dsl(input)
    }

    /// Parse DSL input
    fn parse_dsl(&mut self, input: &str) -> DSLResult<ASTNode> {
        let input = input.trim();

        // Simple keyword-based parsing for now
        let input_upper = input.to_uppercase();

        if input_upper.starts_with("CREATE CLUSTER") {
            self.parse_create_cluster(input)
        } else if input_upper.starts_with("DELETE CLUSTER") {
            self.parse_delete_cluster(input)
        } else if input_upper.starts_with("UPDATE CLUSTER") {
            self.parse_update_cluster(input)
        } else if input_upper.starts_with("WAIT FOR") {
            self.parse_wait_for_cluster(input)
        } else if input_upper.starts_with("CREATE BACKUP") {
            self.parse_create_backup(input)
        } else if input_upper.starts_with("LIST BACKUPS") {
            self.parse_list_backups(input)
        } else if input_upper.starts_with("DELETE BACKUP") {
            self.parse_delete_backup(input)
        } else if input_upper.starts_with("SET") {
            self.parse_set_command(input)
        } else if input_upper.starts_with("ECHO") {
            self.parse_echo(input)
        } else if input_upper.starts_with("SLEEP") {
            self.parse_sleep(input)
        } else if input_upper.starts_with("IF") {
            self.parse_if_statement(input)
        } else if input_upper.starts_with("LOOP") {
            self.parse_loop_statement(input)
        } else {
            Err(DSLError::syntax_error(
                0,
                format!("Unknown DSL command: {input}"),
            ))
        }
    }

    /// Parse CREATE CLUSTER command
    fn parse_create_cluster(&mut self, input: &str) -> DSLResult<ASTNode> {
        // Simple parsing: CREATE CLUSTER name IN region [WITH options]
        let parts: Vec<&str> = input.split_whitespace().collect();

        if parts.len() < 5 {
            return Err(DSLError::syntax_error(
                0,
                "CREATE CLUSTER requires: name IN region".to_string(),
            ));
        }

        if parts[0].to_uppercase() != "CREATE" || parts[1].to_uppercase() != "CLUSTER" {
            return Err(DSLError::syntax_error(
                0,
                "Expected CREATE CLUSTER".to_string(),
            ));
        }

        let name = parts[2].to_string();

        if parts[3].to_uppercase() != "IN" {
            return Err(DSLError::syntax_error(
                0,
                "Expected IN after cluster name".to_string(),
            ));
        }

        let region = parts[4].to_string();

        // Parse optional WITH clause
        let mut rcu_range = None;
        let mut service_plan = None;
        let mut password = None;

        if parts.len() > 5 && parts[5].to_uppercase() == "WITH" {
            let with_clause = parts[6..].join(" ");
            let options = self.parse_with_clause(&with_clause)?;

            for (key, value) in &options {
                match key.to_lowercase().as_str() {
                    "min_rcu" => {
                        if let Some(max_rcu) = options.get("max_rcu") {
                            rcu_range = Some((value.to_string(), max_rcu.to_string()));
                        }
                    }
                    "max_rcu" => {
                        if let Some(min_rcu) = options.get("min_rcu") {
                            rcu_range = Some((min_rcu.to_string(), value.to_string()));
                        }
                    }
                    "service_plan" => service_plan = Some(value.to_string()),
                    "password" => password = Some(value.to_string()),
                    _ => {}
                }
            }
        }

        Ok(ASTNode::Command(CommandNode::CreateCluster {
            name,
            region,
            rcu_range,
            service_plan,
            password,
        }))
    }

    /// Parse DELETE CLUSTER command
    fn parse_delete_cluster(&mut self, input: &str) -> DSLResult<ASTNode> {
        let parts: Vec<&str> = input.split_whitespace().collect();

        if parts.len() < 3 {
            return Err(DSLError::syntax_error(
                0,
                "DELETE CLUSTER requires a name".to_string(),
            ));
        }

        if parts[0].to_uppercase() != "DELETE" || parts[1].to_uppercase() != "CLUSTER" {
            return Err(DSLError::syntax_error(
                0,
                "Expected DELETE CLUSTER".to_string(),
            ));
        }

        let name = parts[2].to_string();

        Ok(ASTNode::Command(CommandNode::DeleteCluster { name }))
    }

    /// Parse UPDATE CLUSTER command
    fn parse_update_cluster(&mut self, input: &str) -> DSLResult<ASTNode> {
        let parts: Vec<&str> = input.split_whitespace().collect();

        if parts.len() < 4 {
            return Err(DSLError::syntax_error(
                0,
                "UPDATE CLUSTER requires: name SET field=value".to_string(),
            ));
        }

        if parts[0].to_uppercase() != "UPDATE" || parts[1].to_uppercase() != "CLUSTER" {
            return Err(DSLError::syntax_error(
                0,
                "Expected UPDATE CLUSTER".to_string(),
            ));
        }

        let name = parts[2].to_string();

        if parts[3].to_uppercase() != "SET" {
            return Err(DSLError::syntax_error(
                0,
                "Expected SET after cluster name".to_string(),
            ));
        }

        let set_clause = parts[4..].join(" ");
        let updates = self.parse_set_clause(&set_clause)?;

        Ok(ASTNode::Command(CommandNode::UpdateCluster {
            name,
            updates,
        }))
    }

    /// Parse WAIT FOR command
    fn parse_wait_for_cluster(&mut self, input: &str) -> DSLResult<ASTNode> {
        let parts: Vec<&str> = input.split_whitespace().collect();

        if parts.len() < 5 {
            return Err(DSLError::syntax_error(
                0,
                "WAIT FOR requires: cluster TO BE state".to_string(),
            ));
        }

        if parts[0].to_uppercase() != "WAIT" || parts[1].to_uppercase() != "FOR" {
            return Err(DSLError::syntax_error(0, "Expected WAIT FOR".to_string()));
        }

        let name = parts[2].to_string();

        if parts[3].to_uppercase() != "TO" || parts[4].to_uppercase() != "BE" {
            return Err(DSLError::syntax_error(
                0,
                "Expected TO BE after cluster name".to_string(),
            ));
        }

        let state = parts[5].to_string();

        Ok(ASTNode::Command(CommandNode::WaitForCluster {
            name,
            state,
            timeout: None, // Could parse optional timeout
        }))
    }

    /// Parse CREATE BACKUP command
    fn parse_create_backup(&mut self, input: &str) -> DSLResult<ASTNode> {
        let parts: Vec<&str> = input.split_whitespace().collect();

        if parts.len() < 4 {
            return Err(DSLError::syntax_error(
                0,
                "CREATE BACKUP requires: FOR cluster".to_string(),
            ));
        }

        if parts[0].to_uppercase() != "CREATE" || parts[1].to_uppercase() != "BACKUP" {
            return Err(DSLError::syntax_error(
                0,
                "Expected CREATE BACKUP".to_string(),
            ));
        }

        if parts[2].to_uppercase() != "FOR" {
            return Err(DSLError::syntax_error(
                0,
                "Expected FOR after CREATE BACKUP".to_string(),
            ));
        }

        let cluster_name = parts[3].to_string();
        let mut description = None;

        // Parse optional description
        if parts.len() > 4 && parts[4].to_uppercase() == "WITH" {
            let with_clause = parts[5..].join(" ");
            let options = self.parse_with_clause(&with_clause)?;

            if let Some(desc) = options.get("description") {
                description = Some(desc.to_string());
            }
        }

        Ok(ASTNode::Command(CommandNode::CreateBackup {
            cluster_name,
            description,
        }))
    }

    /// Parse LIST BACKUPS command
    fn parse_list_backups(&mut self, input: &str) -> DSLResult<ASTNode> {
        let parts: Vec<&str> = input.split_whitespace().collect();

        if parts.len() < 2 {
            return Err(DSLError::syntax_error(
                0,
                "LIST BACKUPS requires at least 2 words".to_string(),
            ));
        }

        if parts[0].to_uppercase() != "LIST" || parts[1].to_uppercase() != "BACKUPS" {
            return Err(DSLError::syntax_error(
                0,
                "Expected LIST BACKUPS".to_string(),
            ));
        }

        let mut cluster_name = None;
        let mut filters = Vec::new();

        // Parse optional cluster name
        if parts.len() > 2 && parts[2].to_uppercase() == "FOR" {
            if parts.len() < 4 {
                return Err(DSLError::syntax_error(
                    0,
                    "LIST BACKUPS FOR requires a cluster name".to_string(),
                ));
            }
            cluster_name = Some(parts[3].to_string());
        }

        // Parse optional WHERE clause
        let where_start = if cluster_name.is_some() { 4 } else { 2 };
        if parts.len() > where_start && parts[where_start].to_uppercase() == "WHERE" {
            let where_clause = parts[where_start + 1..].join(" ");
            let filter = self.parse_where_clause(&where_clause)?;
            filters.push(filter);
        }

        Ok(ASTNode::Command(CommandNode::ListBackups {
            cluster_name,
            filters,
        }))
    }

    /// Parse DELETE BACKUP command
    fn parse_delete_backup(&mut self, input: &str) -> DSLResult<ASTNode> {
        let parts: Vec<&str> = input.split_whitespace().collect();

        if parts.len() < 4 {
            return Err(DSLError::syntax_error(
                0,
                "DELETE BACKUP requires: FROM cluster backup_id".to_string(),
            ));
        }

        if parts[0].to_uppercase() != "DELETE" || parts[1].to_uppercase() != "BACKUP" {
            return Err(DSLError::syntax_error(
                0,
                "Expected DELETE BACKUP".to_string(),
            ));
        }

        if parts[2].to_uppercase() != "FROM" {
            return Err(DSLError::syntax_error(
                0,
                "Expected FROM after DELETE BACKUP".to_string(),
            ));
        }

        let cluster_name = parts[3].to_string();
        let backup_id = parts[4].to_string();

        Ok(ASTNode::Command(
            crate::dsl::ast::CommandNode::DeleteBackup {
                cluster_name,
                backup_id,
            },
        ))
    }

    /// Parse SET command
    fn parse_set_command(&mut self, input: &str) -> DSLResult<ASTNode> {
        let parts: Vec<&str> = input.split_whitespace().collect();

        if parts.len() < 3 {
            return Err(DSLError::syntax_error(
                0,
                "SET requires: variable = value".to_string(),
            ));
        }

        if parts[0].to_uppercase() != "SET" {
            return Err(DSLError::syntax_error(0, "Expected SET".to_string()));
        }

        let name = parts[1].to_string();

        if parts[2] != "=" {
            return Err(DSLError::syntax_error(
                0,
                "Expected = after variable name".to_string(),
            ));
        }

        let value_str = parts[3..].join(" ");
        let value = self.parse_value(&value_str)?;

        Ok(ASTNode::Utility(
            crate::dsl::ast::UtilityNode::SetVariable {
                name,
                value: Box::new(value),
            },
        ))
    }

    /// Parse ECHO command
    fn parse_echo(&mut self, input: &str) -> DSLResult<ASTNode> {
        let parts: Vec<&str> = input.split_whitespace().collect();

        if parts.len() < 2 {
            return Err(DSLError::syntax_error(
                0,
                "ECHO requires a message".to_string(),
            ));
        }

        if parts[0].to_uppercase() != "ECHO" {
            return Err(DSLError::syntax_error(0, "Expected ECHO".to_string()));
        }

        let message_str = parts[1..].join(" ");
        let message = self.parse_value(&message_str)?;

        Ok(ASTNode::Utility(crate::dsl::ast::UtilityNode::Echo {
            message: Box::new(message),
        }))
    }

    /// Parse SLEEP command
    fn parse_sleep(&mut self, input: &str) -> DSLResult<ASTNode> {
        let parts: Vec<&str> = input.split_whitespace().collect();

        if parts.len() < 2 {
            return Err(DSLError::syntax_error(
                0,
                "SLEEP requires a duration".to_string(),
            ));
        }

        if parts[0].to_uppercase() != "SLEEP" {
            return Err(DSLError::syntax_error(0, "Expected SLEEP".to_string()));
        }

        let duration_str = parts[1..].join(" ");
        let duration = self.parse_value(&duration_str)?;

        Ok(ASTNode::Utility(crate::dsl::ast::UtilityNode::Sleep {
            duration: Box::new(duration),
        }))
    }

    /// Parse IF statement
    fn parse_if_statement(&mut self, _input: &str) -> DSLResult<ASTNode> {
        // Simplified parsing for now
        Err(DSLError::syntax_error(
            0,
            "IF statements not yet implemented".to_string(),
        ))
    }

    /// Parse LOOP statement
    fn parse_loop_statement(&mut self, _input: &str) -> DSLResult<ASTNode> {
        // Simplified parsing for now
        Err(DSLError::syntax_error(
            0,
            "LOOP statements not yet implemented".to_string(),
        ))
    }

    /// Parse WITH clause
    fn parse_with_clause(
        &mut self,
        with_clause: &str,
    ) -> DSLResult<std::collections::HashMap<String, String>> {
        let mut options = std::collections::HashMap::new();

        let parts: Vec<&str> = with_clause.split(',').collect();
        for part in parts {
            let part = part.trim();
            if let Some(equal_pos) = part.find('=') {
                let key = part[..equal_pos].trim();
                let value = part[equal_pos + 1..].trim();
                options.insert(key.to_string(), value.to_string());
            }
        }

        Ok(options)
    }

    /// Parse SET clause
    fn parse_set_clause(&mut self, set_clause: &str) -> DSLResult<Vec<ASTNode>> {
        let mut updates = Vec::new();

        let parts: Vec<&str> = set_clause.split(',').collect();
        for part in parts {
            let part = part.trim();
            if let Some(equal_pos) = part.find('=') {
                let field = part[..equal_pos].trim();
                let value_str = part[equal_pos + 1..].trim();

                let field_node = ASTNode::Expression(crate::dsl::ast::ExpressionNode::Field {
                    name: field.to_string(),
                    context: None,
                    alias: None,
                });

                let value_node = self.parse_value(value_str)?;

                let update =
                    ASTNode::Expression(crate::dsl::ast::ExpressionNode::BinaryExpression {
                        left: Box::new(field_node),
                        operator: "=".to_string(),
                        right: Box::new(value_node),
                    });

                updates.push(update);
            }
        }

        Ok(updates)
    }

    /// Parse WHERE clause
    fn parse_where_clause(&mut self, where_clause: &str) -> DSLResult<ASTNode> {
        // Simple parsing for basic conditions
        let where_clause = where_clause.trim();

        // Look for basic operators
        let operators = ["=", "!=", ">", "<", ">=", "<=", "LIKE", "IN"];

        for op in &operators {
            if let Some(op_pos) = where_clause.find(op) {
                let left_str = where_clause[..op_pos].trim();
                let right_str = where_clause[op_pos + op.len()..].trim();

                let left = self.parse_field(left_str)?;
                let right = self.parse_value(right_str)?;

                return Ok(ASTNode::Expression(
                    crate::dsl::ast::ExpressionNode::BinaryExpression {
                        left: Box::new(left),
                        operator: op.to_string(),
                        right: Box::new(right),
                    },
                ));
            }
        }

        Err(DSLError::syntax_error(
            0,
            format!("Invalid WHERE clause: {where_clause}"),
        ))
    }

    /// Parse a field reference
    fn parse_field(&mut self, field_str: &str) -> DSLResult<ASTNode> {
        let field_str = field_str.trim();

        // Handle cross-context fields: CONTEXT.field
        if let Some(dot_pos) = field_str.find('.') {
            let context_str = field_str[..dot_pos].trim();
            let field_name = field_str[dot_pos + 1..].trim();

            // Parse context string to FieldContext enum
            let context = match context_str.to_uppercase().as_str() {
                "CLUSTER" => Some(FieldContext::Cluster),
                "BACKUPS" => Some(FieldContext::Backups),
                _ => None, // Invalid context
            };

            return Ok(ASTNode::Expression(
                crate::dsl::ast::ExpressionNode::Field {
                    name: field_name.to_string(),
                    context,
                    alias: None,
                },
            ));
        }

        // Regular field
        Ok(ASTNode::Expression(
            crate::dsl::ast::ExpressionNode::Field {
                name: field_str.to_string(),
                context: None,
                alias: None,
            },
        ))
    }

    /// Parse a value (literal or variable)
    fn parse_value(&mut self, value_str: &str) -> DSLResult<ASTNode> {
        let value_str = value_str.trim();

        // String literal
        if value_str.starts_with('\'') && value_str.ends_with('\'') {
            let content = &value_str[1..value_str.len() - 1];
            return Ok(ASTNode::Expression(
                crate::dsl::ast::ExpressionNode::Literal {
                    value: DSLValue::String(content.to_string()),
                },
            ));
        }

        // Number literal
        if let Ok(number) = value_str.parse::<f64>() {
            return Ok(ASTNode::Expression(
                crate::dsl::ast::ExpressionNode::Literal {
                    value: DSLValue::Number(number),
                },
            ));
        }

        // Boolean literal
        match value_str.to_lowercase().as_str() {
            "true" => Ok(ASTNode::Expression(
                crate::dsl::ast::ExpressionNode::Literal {
                    value: DSLValue::Boolean(true),
                },
            )),
            "false" => Ok(ASTNode::Expression(
                crate::dsl::ast::ExpressionNode::Literal {
                    value: DSLValue::Boolean(false),
                },
            )),
            _ => {
                // Assume it's a variable reference
                Ok(ASTNode::Expression(
                    crate::dsl::ast::ExpressionNode::Variable {
                        name: value_str.to_string(),
                    },
                ))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dsl::syntax::DSLValue;

    #[test]
    fn test_parse_create_cluster() {
        let result = DSLASTParser::parse("CREATE CLUSTER my-cluster IN aws-us-west-1");
        assert!(result.is_ok());

        if let Ok(ASTNode::Command(crate::dsl::ast::CommandNode::CreateCluster {
            name,
            region,
            rcu_range,
            service_plan,
            password,
        })) = result
        {
            assert_eq!(name, "my-cluster");
            assert_eq!(region, "aws-us-west-1");
            assert!(rcu_range.is_none());
            assert!(service_plan.is_none());
            assert!(password.is_none());
        } else {
            panic!("Expected CreateCluster node");
        }
    }

    #[test]
    fn test_parse_create_cluster_with_options() {
        let result = DSLASTParser::parse(
            "CREATE CLUSTER my-cluster IN aws-us-west-1 WITH min_rcu=1, max_rcu=10, service_plan=starter",
        );
        assert!(result.is_ok());

        if let Ok(ASTNode::Command(crate::dsl::ast::CommandNode::CreateCluster {
            name,
            region,
            rcu_range,
            service_plan,
            password,
        })) = result
        {
            assert_eq!(name, "my-cluster");
            assert_eq!(region, "aws-us-west-1");
            assert_eq!(rcu_range, Some(("1".to_string(), "10".to_string())));
            assert_eq!(service_plan, Some("starter".to_string()));
            assert!(password.is_none());
        } else {
            panic!("Expected CreateCluster node");
        }
    }

    #[test]
    fn test_parse_list_backups() {
        let result = DSLASTParser::parse("LIST BACKUPS");
        assert!(result.is_ok());

        if let Ok(ASTNode::Command(crate::dsl::ast::CommandNode::ListBackups {
            cluster_name,
            filters,
        })) = result
        {
            assert!(cluster_name.is_none());
            assert!(filters.is_empty());
        } else {
            panic!("Expected ListBackups node");
        }
    }

    #[test]
    fn test_parse_list_backups_for_cluster() {
        let result = DSLASTParser::parse("LIST BACKUPS FOR my-cluster");
        assert!(result.is_ok());

        if let Ok(ASTNode::Command(crate::dsl::ast::CommandNode::ListBackups {
            cluster_name,
            filters,
        })) = result
        {
            assert_eq!(cluster_name, Some("my-cluster".to_string()));
            assert!(filters.is_empty());
        } else {
            panic!("Expected ListBackups node");
        }
    }

    #[test]
    fn test_parse_set_variable() {
        let result = DSLASTParser::parse("SET my_var = 'test value'");
        assert!(result.is_ok());

        if let Ok(ASTNode::Utility(crate::dsl::ast::UtilityNode::SetVariable { name, value })) =
            result
        {
            assert_eq!(name, "my_var");

            if let ASTNode::Expression(crate::dsl::ast::ExpressionNode::Literal {
                value: literal_value,
            }) = &*value
            {
                assert_eq!(literal_value, &DSLValue::String("test value".to_string()));
            } else {
                panic!("Expected Literal node");
            }
        } else {
            panic!("Expected SetVariable node");
        }
    }

    #[test]
    fn test_parse_echo() {
        let result = DSLASTParser::parse("ECHO 'Hello, World!'");
        assert!(result.is_ok());

        if let Ok(ASTNode::Utility(crate::dsl::ast::UtilityNode::Echo { message })) = result {
            if let ASTNode::Expression(crate::dsl::ast::ExpressionNode::Literal {
                value: literal_value,
            }) = &*message
            {
                assert_eq!(
                    literal_value,
                    &DSLValue::String("Hello, World!".to_string())
                );
            } else {
                panic!("Expected Literal node");
            }
        } else {
            panic!("Expected Echo node");
        }
    }

    #[test]
    fn test_parse_sleep() {
        let result = DSLASTParser::parse("SLEEP 1000");
        assert!(result.is_ok());

        if let Ok(ASTNode::Utility(crate::dsl::ast::UtilityNode::Sleep { duration })) = result {
            if let ASTNode::Expression(crate::dsl::ast::ExpressionNode::Literal {
                value: literal_value,
            }) = &*duration
            {
                assert_eq!(literal_value, &DSLValue::Number(1000.0));
            } else {
                panic!("Expected Literal node");
            }
        } else {
            panic!("Expected Sleep node");
        }
    }
}
