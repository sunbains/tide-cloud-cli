#[cfg(test)]
mod tests {
    use crate::dsl::{
        ast_dsl_transformer::ASTDSLTransformer, executor::DSLExecutor, sql_ast_parser::SQLASTParser,
    };
    use crate::tidb_cloud::TiDBCloudClient;

    #[tokio::test]
    async fn test_join_query_execution() {
        // Create a mock client for testing
        let client = TiDBCloudClient::new(
            "test-key-that-is-long-enough-to-pass-validation-requirements".to_string(),
        )
        .expect("Failed to create client");
        let _executor = DSLExecutor::new(client);

        // Parse the problematic query
        let query = "select * from backups where backups.tidbId = clusters.tidbid and clusters.displayName = 'SB-Test01-delete-whenever'";

        // Step 1: Test SQL parsing
        let ast_result = SQLASTParser::parse(query);
        println!("AST parsing result: {ast_result:?}");
        assert!(ast_result.is_ok());

        // Step 2: Test AST to DSL transformation
        let ast_node = ast_result.unwrap();
        let command_result = ASTDSLTransformer::transform(&ast_node);
        println!("Command transformation result: {command_result:?}");
        assert!(command_result.is_ok());

        let command = command_result.unwrap();
        println!("Generated command: {command:?}");

        // Step 3: Check that the command properly represents the join
        // The current implementation treats joins as ListBackups with a complex where clause
        // but this doesn't actually perform the join - it just tries to filter backups

        // Now it should create a proper JOIN command instead of ListBackups
        assert_eq!(format!("{:?}", command.command_type), "Join");

        // Verify JOIN parameters
        assert!(command.parameters.contains_key("left_table"));
        assert!(command.parameters.contains_key("right_table"));
        assert!(command.parameters.contains_key("on_condition"));
        assert!(command.parameters.contains_key("where_clause"));

        // Check table names
        if let Some(crate::dsl::syntax::DSLValue::String(table_str)) =
            command.parameters.get("left_table")
        {
            assert_eq!(table_str, "BACKUPS");
        }

        if let Some(crate::dsl::syntax::DSLValue::String(table_str)) =
            command.parameters.get("right_table")
        {
            assert_eq!(table_str, "CLUSTERS");
        }

        // Check ON condition
        if let Some(crate::dsl::syntax::DSLValue::String(on_str)) =
            command.parameters.get("on_condition")
        {
            println!("ON condition: {on_str}");
            assert!(on_str.contains("tidbId"));
        }

        // Check WHERE clause
        if let Some(crate::dsl::syntax::DSLValue::String(where_str)) =
            command.parameters.get("where_clause")
        {
            println!("Where clause: {where_str}");
            assert!(where_str.contains("displayName"));
            assert!(where_str.contains("SB-Test01-delete-whenever"));
        } else {
            panic!("Expected where_clause parameter");
        }
    }

    #[test]
    fn test_join_parsing_detailed() {
        let query = "select * from backups where backups.tidbId = clusters.tidbid and clusters.displayName = 'SB-Test01-delete-whenever'";
        let result = SQLASTParser::parse(query);

        assert!(result.is_ok());
        let ast = result.unwrap();

        // Print the AST structure for debugging
        println!("AST structure: {ast:#?}");

        // Verify it's a SELECT with JOIN in FROM clause
        if let crate::dsl::ast::ASTNode::Query(crate::dsl::ast::QueryNode::Select {
            from,
            where_clause,
            ..
        }) = ast
        {
            // Check that FROM clause is a JOIN
            if let crate::dsl::ast::ASTNode::Query(crate::dsl::ast::QueryNode::Join {
                left,
                right,
                on_condition,
                ..
            }) = *from
            {
                // Verify tables
                match (*left, *right) {
                    (
                        crate::dsl::ast::ASTNode::Query(crate::dsl::ast::QueryNode::Table {
                            name: left_name,
                            ..
                        }),
                        crate::dsl::ast::ASTNode::Query(crate::dsl::ast::QueryNode::Table {
                            name: right_name,
                            ..
                        }),
                    ) => {
                        assert_eq!(left_name, "BACKUPS");
                        assert_eq!(right_name, "CLUSTERS");
                    }
                    _ => panic!("Expected table nodes in JOIN"),
                }

                // Verify ON condition
                println!("ON condition: {on_condition:#?}");

                // Verify WHERE clause (should contain the displayName filter)
                if let Some(where_node) = where_clause {
                    println!("WHERE clause: {where_node:#?}");
                } else {
                    panic!("Expected WHERE clause with displayName filter");
                }
            } else {
                panic!("Expected JOIN node in FROM clause");
            }
        } else {
            panic!("Expected SELECT node");
        }
    }
}
