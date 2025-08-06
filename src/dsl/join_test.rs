#[cfg(test)]
mod tests {
    use crate::dsl::{executor::DSLExecutor, sql_ast_parser::SQLASTParser};
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

        // Step 1: Test SQL parsing to AST
        let ast_result = SQLASTParser::parse(query);
        println!("AST parsing result: {ast_result:?}");
        assert!(ast_result.is_ok());

        let ast_node = ast_result.unwrap();
        println!("Generated AST: {ast_node:?}");

        // Step 2: Test direct AST execution (note: this will attempt to call the API)
        // In a real test, we would mock the API calls, but for now we just verify the AST structure

        // Verify the AST represents a SELECT with JOIN
        if let crate::dsl::ast::ASTNode::Query(crate::dsl::ast::QueryNode::Select {
            from,
            where_clause,
            ..
        }) = &ast_node
        {
            // Check that FROM clause is a JOIN
            if let crate::dsl::ast::ASTNode::Query(crate::dsl::ast::QueryNode::Join {
                left,
                right,
                on_condition,
                ..
            }) = from.as_ref()
            {
                println!("Found JOIN in AST with left: {left:?}, right: {right:?}");
                println!("ON condition: {on_condition:?}");

                // This verifies the AST is correctly structured for JOIN execution
                assert!(matches!(
                    left.as_ref(),
                    crate::dsl::ast::ASTNode::Query(crate::dsl::ast::QueryNode::Table { .. })
                ));
                assert!(matches!(
                    right.as_ref(),
                    crate::dsl::ast::ASTNode::Query(crate::dsl::ast::QueryNode::Table { .. })
                ));

                // Verify WHERE clause exists
                assert!(where_clause.is_some());
            } else {
                panic!("Expected JOIN node in FROM clause");
            }
        } else {
            panic!("Expected SELECT node with JOIN");
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
