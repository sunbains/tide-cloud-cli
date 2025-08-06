use crate::dsl::{
    ast::ASTNode,
    dsl_ast_parser::DSLASTParser,
    error::{DSLError, DSLResult},
    sql_ast_parser::SQLASTParser,
};

/// Unified parser that can handle both SQL and DSL syntax
pub struct UnifiedParser;

impl UnifiedParser {
    /// Parse input and convert to AST, automatically detecting SQL vs DSL syntax
    pub fn parse(input: &str) -> DSLResult<ASTNode> {
        let input = input.trim();

        if input.is_empty() {
            return Err(DSLError::syntax_error(0, "Empty input".to_string()));
        }

        // Detect if this is SQL syntax
        if Self::is_sql_syntax(input) {
            SQLASTParser::parse(input)
        } else {
            // Assume it's DSL syntax
            DSLASTParser::parse(input)
        }
    }

    /// Detect if the input looks like SQL syntax
    fn is_sql_syntax(input: &str) -> bool {
        let input_upper = input.to_uppercase();

        // Check for SQL keywords at the start
        input_upper.starts_with("SELECT")
            || input_upper.starts_with("INSERT")
            || (input_upper.starts_with("UPDATE") && !input_upper.starts_with("UPDATE CLUSTER"))  // Exclude DSL UPDATE CLUSTER
            || input_upper.starts_with("DELETE FROM")  // More specific - only SQL DELETE FROM, not DSL DELETE CLUSTER
            || input_upper.starts_with("CREATE TABLE")
            || input_upper.starts_with("DROP TABLE")
            || input_upper.starts_with("ALTER TABLE")
            || input_upper.starts_with("DESCRIBE TABLE")
    }

    /// Parse multiple statements (separated by semicolons)
    pub fn parse_script(input: &str) -> DSLResult<Vec<ASTNode>> {
        let statements: Vec<&str> = input
            .split(';')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .collect();

        let mut ast_nodes = Vec::new();

        for statement in statements {
            let node = Self::parse(statement)?;
            ast_nodes.push(node);
        }

        Ok(ast_nodes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dsl::ast::{CommandNode, ExpressionNode, QueryNode};

    #[test]
    fn test_detect_sql_syntax() {
        assert!(UnifiedParser::is_sql_syntax("SELECT * FROM BACKUPS"));
        assert!(UnifiedParser::is_sql_syntax("select * from backups"));
        assert!(UnifiedParser::is_sql_syntax(
            "SELECT displayName, state FROM CLUSTER"
        ));
        assert!(UnifiedParser::is_sql_syntax("DESCRIBE TABLE BACKUPS"));
        assert!(UnifiedParser::is_sql_syntax("describe table clusters"));
        assert!(!UnifiedParser::is_sql_syntax("CREATE CLUSTER my-cluster"));
        assert!(!UnifiedParser::is_sql_syntax("LIST CLUSTERS"));
    }

    #[test]
    fn test_parse_sql_select() {
        let result = UnifiedParser::parse("SELECT * FROM BACKUPS WHERE CLUSTER.displayName = '.*'");
        assert!(result.is_ok());

        if let Ok(ASTNode::Query(QueryNode::Select {
            fields,
            from,
            where_clause,
            ..
        })) = result
        {
            assert_eq!(fields.len(), 1);
            assert!(matches!(
                fields[0],
                ASTNode::Expression(ExpressionNode::Wildcard)
            ));

            // TODO: Fix dereferencing issues in test
            if let ASTNode::Query(QueryNode::Table { name, .. }) = &*from {
                assert_eq!(name, "BACKUPS");
            }

            assert!(where_clause.is_some());
        } else {
            panic!("Expected Select node");
        }
    }

    #[test]
    fn test_parse_dsl_create_cluster() {
        let result = UnifiedParser::parse("CREATE CLUSTER my-cluster IN aws-us-west-1");
        assert!(result.is_ok());

        if let Ok(ASTNode::Command(CommandNode::CreateCluster { name, region, .. })) = result {
            assert_eq!(name, "my-cluster");
            assert_eq!(region, "aws-us-west-1");
        } else {
            panic!("Expected CreateCluster node");
        }
    }

    #[test]
    fn test_parse_script() {
        let script = "CREATE CLUSTER test-cluster IN aws-us-west-1; SELECT * FROM BACKUPS";
        let result = UnifiedParser::parse_script(script);
        assert!(result.is_ok());

        if let Ok(nodes) = result {
            assert_eq!(nodes.len(), 2);

            // First node should be CreateCluster
            if let ASTNode::Command(CommandNode::CreateCluster { name, .. }) = &nodes[0] {
                assert_eq!(name, "test-cluster");
            } else {
                panic!("Expected CreateCluster node");
            }

            // Second node should be Select
            if let ASTNode::Query(QueryNode::Select { .. }) = &nodes[1] {
                // OK
            } else {
                panic!("Expected Select node");
            }
        }
    }

    #[test]
    fn test_parse_describe_table() {
        let result = UnifiedParser::parse("DESCRIBE TABLE BACKUPS");
        assert!(result.is_ok());

        if let Ok(ASTNode::Query(QueryNode::DescribeTable { table_name })) = result {
            assert_eq!(table_name, "BACKUPS");
        } else {
            panic!("Expected DescribeTable node");
        }
    }
}
