use tidb_cli::dsl::ast::{ASTNode, QueryNode, SortDirection};
use tidb_cli::dsl::sql_ast_parser::SQLASTParser;

#[test]
fn test_order_by_basic() {
    let sql = "SELECT * FROM CLUSTERS ORDER BY name";
    match SQLASTParser::parse(sql) {
        Ok(ASTNode::Query(QueryNode::Select { order_by, .. })) => {
            assert!(order_by.is_some());
            let order_clauses = order_by.unwrap();
            assert_eq!(order_clauses.len(), 1);
            assert_eq!(order_clauses[0].direction, SortDirection::Ascending);
        }
        _ => panic!("Failed to parse ORDER BY"),
    }
}

#[test]
fn test_order_by_desc() {
    let sql = "SELECT name, region FROM CLUSTERS ORDER BY name DESC";
    match SQLASTParser::parse(sql) {
        Ok(ASTNode::Query(QueryNode::Select { order_by, .. })) => {
            assert!(order_by.is_some());
            let order_clauses = order_by.unwrap();
            assert_eq!(order_clauses.len(), 1);
            assert_eq!(order_clauses[0].direction, SortDirection::Descending);
        }
        _ => panic!("Failed to parse ORDER BY DESC"),
    }
}

#[test]
fn test_order_by_multiple() {
    let sql = "SELECT * FROM CLUSTERS ORDER BY region ASC, name DESC";
    match SQLASTParser::parse(sql) {
        Ok(ASTNode::Query(QueryNode::Select { order_by, .. })) => {
            assert!(order_by.is_some());
            let order_clauses = order_by.unwrap();
            assert_eq!(order_clauses.len(), 2);
            assert_eq!(order_clauses[0].direction, SortDirection::Ascending);
            assert_eq!(order_clauses[1].direction, SortDirection::Descending);
        }
        _ => panic!("Failed to parse multiple ORDER BY"),
    }
}

#[test]
fn test_order_by_with_where_and_into() {
    let sql = "SELECT * FROM CLUSTERS WHERE state = 'ACTIVE' ORDER BY name DESCENDING INTO result";
    match SQLASTParser::parse(sql) {
        Ok(ASTNode::Query(QueryNode::Select {
            where_clause,
            order_by,
            into_clause,
            ..
        })) => {
            assert!(where_clause.is_some());
            assert!(order_by.is_some());
            assert!(into_clause.is_some());

            let order_clauses = order_by.unwrap();
            assert_eq!(order_clauses.len(), 1);
            assert_eq!(order_clauses[0].direction, SortDirection::Descending);
        }
        _ => panic!("Failed to parse complex SELECT with ORDER BY"),
    }
}
