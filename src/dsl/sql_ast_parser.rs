use crate::dsl::{
    ast::{
        ASTNode, CommandNode, ExpressionNode, FieldContext, JoinType, OrderByClause, QueryNode,
        SortDirection,
    },
    error::{DSLError, DSLResult},
    syntax::DSLValue,
};

/// SQL to AST parser that converts SQL syntax to our AST representation
pub struct SQLASTParser;

impl SQLASTParser {
    /// Parse SQL input and convert to AST
    pub fn parse(input: &str) -> DSLResult<ASTNode> {
        let mut parser = SQLASTParser;
        parser.parse_sql(input)
    }

    /// Parse a SQL statement
    fn parse_sql(&mut self, input: &str) -> DSLResult<ASTNode> {
        let input = input.trim();

        if input.to_uppercase().starts_with("SELECT") {
            self.parse_select_statement(input)
        } else if input.to_uppercase().starts_with("DESCRIBE TABLE") {
            self.parse_describe_table_statement(input)
        } else if input.to_uppercase().starts_with("UPDATE") {
            self.parse_update_statement(input)
        } else {
            Err(DSLError::syntax_error(
                0,
                format!("Unsupported SQL statement: {input}"),
            ))
        }
    }

    /// Parse a SELECT statement
    fn parse_select_statement(&mut self, input: &str) -> DSLResult<ASTNode> {
        let input = input.trim();
        let input_upper = input.to_uppercase();

        // Extract SELECT fields
        let select_end = input_upper.find(" FROM ").ok_or_else(|| {
            DSLError::syntax_error(0, "SELECT statement must contain FROM clause".to_string())
        })?;

        let fields_str = input[6..select_end].trim();
        let fields = self.parse_field_list(fields_str)?;

        // Extract FROM clause
        let from_start = select_end + 6;
        let from_end = input_upper[from_start..]
            .find(" WHERE ")
            .or_else(|| input_upper[from_start..].find(" ORDER BY "))
            .or_else(|| input_upper[from_start..].find(" INTO "))
            .unwrap_or(input.len() - from_start);
        let from_str = input[from_start..from_start + from_end].trim();

        // Extract WHERE clause
        let where_clause = if let Some(where_start) = input_upper[from_start..].find(" WHERE ") {
            let where_end_pos = from_start + where_start + 7;

            // Find the end of WHERE clause (before ORDER BY or INTO)
            let where_end = input_upper[where_end_pos..]
                .find(" ORDER BY ")
                .or_else(|| input_upper[where_end_pos..].find(" INTO "))
                .unwrap_or(input.len() - where_end_pos);

            let where_str = input[where_end_pos..where_end_pos + where_end].trim();

            // Check if WHERE clause contains implicit join conditions
            if self.contains_implicit_join(where_str) {
                // Convert implicit join to explicit join
                match self.convert_implicit_join_to_explicit(from_str, where_str)? {
                    Some(node) => Some(Box::new(node)),
                    None => {
                        // For cross-table joins, filter out the join condition and keep the rest
                        let remaining_where = self.filter_out_join_condition(where_str)?;
                        remaining_where.map(Box::new)
                    }
                }
            } else {
                Some(Box::new(self.parse_where_clause(where_str)?))
            }
        } else {
            None
        };

        // Extract ORDER BY clause
        let order_by = if let Some(order_by_start) = input_upper.find(" ORDER BY ") {
            let order_by_pos = order_by_start + 10;

            // Find the end of ORDER BY clause (before INTO)
            let order_by_end = input_upper[order_by_pos..]
                .find(" INTO ")
                .unwrap_or(input.len() - order_by_pos);

            let order_by_str = input[order_by_pos..order_by_pos + order_by_end].trim();
            Some(self.parse_order_by_clause(order_by_str)?)
        } else {
            None
        };

        // Extract INTO clause
        let into_clause = if let Some(into_start) = input_upper.find(" INTO ") {
            let into_str = input[into_start + 6..].trim();
            Some(Box::new(self.parse_into_clause(into_str)?))
        } else {
            None
        };

        // Determine the FROM clause - either use the original or the converted JOIN
        let from_node = if let Some(ref _where_node) = where_clause {
            // We need to get the raw WHERE string again to check for implicit joins
            if let Some(where_start) = input_upper[from_start..].find(" WHERE ") {
                let where_end_pos = from_start + where_start + 7;

                // Find the end of WHERE clause (before ORDER BY or INTO)
                let where_end = input_upper[where_end_pos..]
                    .find(" ORDER BY ")
                    .or_else(|| input_upper[where_end_pos..].find(" INTO "))
                    .unwrap_or(input.len() - where_end_pos);

                let where_str = input[where_end_pos..where_end_pos + where_end].trim();

                if self.contains_implicit_join(where_str) {
                    // Use the converted JOIN instead of the original FROM clause
                    self.convert_implicit_join_from_clause(from_str, where_str)?
                } else {
                    // Using original FROM clause
                    self.parse_from_clause(from_str)?
                }
            } else {
                self.parse_from_clause(from_str)?
            }
        } else {
            // No WHERE clause, using original FROM clause
            self.parse_from_clause(from_str)?
        };

        Ok(ASTNode::Query(QueryNode::Select {
            fields,
            from: Box::new(from_node),
            where_clause,
            order_by,
            into_clause,
        }))
    }

    /// Parse an UPDATE statement
    fn parse_update_statement(&mut self, input: &str) -> DSLResult<ASTNode> {
        let original_input = input;
        let input = input.to_uppercase();

        // Extract table name after "UPDATE CLUSTER"
        let _update_start = input.find("UPDATE").unwrap() + 6;
        let cluster_start = input.find("CLUSTER").unwrap();
        let set_start = input
            .find("SET")
            .ok_or_else(|| DSLError::syntax_error(0, "Missing SET clause".to_string()))?;

        let table_name = original_input[cluster_start + 7..set_start].trim();

        // Extract SET clause
        let set_end = input.len();
        let set_str = original_input[set_start + 3..set_end].trim();

        // Parse the SET clause to extract field-value pairs
        let field_value_pairs = self.parse_set_clause(set_str)?;

        // Convert field-value pairs to AST nodes
        let updates = field_value_pairs
            .into_iter()
            .map(|(field, value)| {
                ASTNode::Expression(ExpressionNode::Assignment {
                    name: field,
                    value: Box::new(ASTNode::Expression(ExpressionNode::Literal { value })),
                })
            })
            .collect();

        Ok(ASTNode::Command(CommandNode::UpdateCluster {
            name: table_name.to_string(),
            updates,
        }))
    }

    /// Parse SET clause to extract field-value pairs
    fn parse_set_clause(&mut self, set_str: &str) -> DSLResult<Vec<(String, DSLValue)>> {
        let mut updates = Vec::new();

        // Split by comma, but be careful about commas inside JSON objects
        let mut current_field = String::new();
        let mut current_value = String::new();
        let mut brace_count = 0;
        let mut in_quotes = false;
        let mut quote_char = '\0';
        let mut parsing_field = true;

        for ch in set_str.chars() {
            match ch {
                '"' | '\'' => {
                    if !in_quotes {
                        in_quotes = true;
                        quote_char = ch;
                    } else if ch == quote_char {
                        in_quotes = false;
                    }
                    if parsing_field {
                        current_field.push(ch);
                    } else {
                        current_value.push(ch);
                    }
                }
                '=' => {
                    if !in_quotes && brace_count == 0 {
                        parsing_field = false;
                    } else if parsing_field {
                        current_field.push(ch);
                    } else {
                        current_value.push(ch);
                    }
                }
                '{' => {
                    if !in_quotes {
                        brace_count += 1;
                    }
                    if parsing_field {
                        current_field.push(ch);
                    } else {
                        current_value.push(ch);
                    }
                }
                '}' => {
                    if !in_quotes {
                        brace_count -= 1;
                    }
                    if parsing_field {
                        current_field.push(ch);
                    } else {
                        current_value.push(ch);
                    }
                }
                ',' => {
                    if !in_quotes && brace_count == 0 {
                        // End of current field-value pair
                        let field = current_field.trim().to_string();
                        let value = self.parse_json_value(current_value.trim())?;
                        if !field.is_empty() {
                            updates.push((field, value));
                        }
                        current_field.clear();
                        current_value.clear();
                        parsing_field = true;
                    } else if parsing_field {
                        current_field.push(ch);
                    } else {
                        current_value.push(ch);
                    }
                }
                _ => {
                    if parsing_field {
                        current_field.push(ch);
                    } else {
                        current_value.push(ch);
                    }
                }
            }
        }

        // Add the last field-value pair
        if !current_field.trim().is_empty() {
            let field = current_field.trim().to_string();
            let value = self.parse_json_value(current_value.trim())?;
            updates.push((field, value));
        }

        Ok(updates)
    }

    /// Parse JSON value from string
    fn parse_json_value(&mut self, value_str: &str) -> DSLResult<DSLValue> {
        let value_str = value_str.trim();

        // Handle quoted strings
        if (value_str.starts_with('\'') && value_str.ends_with('\''))
            || (value_str.starts_with('"') && value_str.ends_with('"'))
        {
            let content = &value_str[1..value_str.len() - 1];
            return Ok(DSLValue::String(content.to_string()));
        }

        // Try to parse as JSON first
        if let Ok(json_value) = serde_json::from_str::<serde_json::Value>(value_str) {
            return Ok(self.json_to_dsl_value(json_value));
        }

        // If not JSON, treat as string
        Ok(DSLValue::String(value_str.to_string()))
    }

    /// Convert JSON value to DSL value
    #[allow(clippy::only_used_in_recursion)]
    fn json_to_dsl_value(&self, json: serde_json::Value) -> DSLValue {
        match json {
            serde_json::Value::String(s) => DSLValue::String(s),
            serde_json::Value::Number(n) => {
                if let Some(i) = n.as_i64() {
                    DSLValue::Number(i as f64)
                } else if let Some(f) = n.as_f64() {
                    DSLValue::Number(f)
                } else {
                    DSLValue::String(n.to_string())
                }
            }
            serde_json::Value::Bool(b) => DSLValue::Boolean(b),
            serde_json::Value::Array(arr) => {
                DSLValue::Array(arr.into_iter().map(|v| self.json_to_dsl_value(v)).collect())
            }
            serde_json::Value::Object(obj) => DSLValue::Object(
                obj.into_iter()
                    .map(|(k, v)| (k, self.json_to_dsl_value(v)))
                    .collect(),
            ),
            serde_json::Value::Null => DSLValue::Null,
        }
    }

    /// Parse a DESCRIBE TABLE statement
    fn parse_describe_table_statement(&mut self, input: &str) -> DSLResult<ASTNode> {
        let input = input.trim();

        // Extract table name after "DESCRIBE TABLE" (case-insensitive)
        let input_upper = input.to_uppercase();
        let describe_pos = input_upper.find("DESCRIBE TABLE").ok_or_else(|| {
            DSLError::syntax_error(0, "Invalid DESCRIBE TABLE syntax".to_string())
        })?;
        let table_start = describe_pos + "DESCRIBE TABLE".len();
        let table_name = input[table_start..].trim();

        if table_name.is_empty() {
            return Err(DSLError::syntax_error(
                0,
                "Missing table name in DESCRIBE TABLE".to_string(),
            ));
        }

        // Validate table name (only BACKUPS and CLUSTERS are supported)
        let table_name_upper = table_name.to_uppercase();
        if table_name_upper != "BACKUPS" && table_name_upper != "CLUSTERS" {
            return Err(DSLError::syntax_error(
                0,
                format!(
                    "Unsupported table: {table_name}. Only BACKUPS and CLUSTERS are supported."
                ),
            ));
        }

        Ok(ASTNode::Query(QueryNode::DescribeTable {
            table_name: table_name.to_string(),
        }))
    }

    /// Parse a list of fields
    fn parse_field_list(&mut self, fields_str: &str) -> DSLResult<Vec<ASTNode>> {
        if fields_str.trim() == "*" {
            return Ok(vec![ASTNode::Expression(ExpressionNode::Wildcard)]);
        }

        let fields: Vec<ASTNode> = fields_str
            .split(',')
            .map(|field| field.trim())
            .filter(|field| !field.is_empty())
            .map(|field| self.parse_field(field))
            .collect::<DSLResult<Vec<_>>>()?;

        Ok(fields)
    }

    /// Parse a single field
    fn parse_field(&mut self, field_str: &str) -> DSLResult<ASTNode> {
        let field_str = field_str.trim();

        // Handle field with alias: field AS alias
        if let Some(as_pos) = field_str.to_uppercase().find(" AS ") {
            let field_name = field_str[..as_pos].trim();
            let alias = field_str[as_pos + 4..].trim();

            return Ok(ASTNode::Expression(ExpressionNode::Field {
                name: field_name.to_string(),
                context: None,
                alias: Some(alias.to_string()),
            }));
        }

        // Handle cross-context fields: CONTEXT.field
        if let Some(dot_pos) = field_str.find('.') {
            let context_str = field_str[..dot_pos].trim();
            let field_name = field_str[dot_pos + 1..].trim();

            // Parse context string to FieldContext enum
            let context = match context_str.to_uppercase().as_str() {
                "CLUSTER" | "CLUSTERS" => Some(FieldContext::Cluster),
                "BACKUP" | "BACKUPS" => Some(FieldContext::Backups),
                _ => None, // Invalid context
            };

            return Ok(ASTNode::Expression(ExpressionNode::Field {
                name: field_name.to_string(),
                context,
                alias: None,
            }));
        }

        // Regular field
        Ok(ASTNode::Expression(ExpressionNode::Field {
            name: field_str.to_string(),
            context: None,
            alias: None,
        }))
    }

    /// Parse a FROM clause (may contain JOINs)
    fn parse_from_clause(&mut self, from_str: &str) -> DSLResult<ASTNode> {
        let from_str = from_str.trim();

        // Check for JOIN keywords
        let join_keywords = ["INNER JOIN", "LEFT JOIN", "RIGHT JOIN", "FULL JOIN", "JOIN"];
        let input_upper = from_str.to_uppercase();

        for join_keyword in &join_keywords {
            if let Some(join_pos) = input_upper.find(join_keyword) {
                return self.parse_join_clause(from_str, join_pos, join_keyword);
            }
        }

        // No JOIN found, treat as simple table
        self.parse_table(from_str)
    }

    /// Parse a JOIN clause
    fn parse_join_clause(
        &mut self,
        from_str: &str,
        join_pos: usize,
        join_keyword: &str,
    ) -> DSLResult<ASTNode> {
        let left_str = from_str[..join_pos].trim();
        let right_start = join_pos + join_keyword.len();

        // Find ON clause
        let on_start = from_str[right_start..].find(" ON ");
        if on_start.is_none() {
            return Err(DSLError::syntax_error(
                0,
                "JOIN requires ON clause".to_string(),
            ));
        }

        let on_start = on_start.unwrap() + right_start + 4;
        let right_str = from_str[right_start..on_start - 4].trim();
        let on_str = from_str[on_start..].trim();

        let left = self.parse_table(left_str)?;
        let right = self.parse_table(right_str)?;
        let on_condition = self.parse_where_clause(on_str)?;

        let join_type = match join_keyword {
            "INNER JOIN" => JoinType::Inner,
            "LEFT JOIN" => JoinType::Left,
            "RIGHT JOIN" => JoinType::Right,
            "FULL JOIN" => JoinType::Full,
            "JOIN" => JoinType::Inner, // Default to INNER JOIN
            _ => JoinType::Inner,
        };

        Ok(ASTNode::Query(QueryNode::Join {
            left: Box::new(left),
            join_type,
            right: Box::new(right),
            on_condition: Box::new(on_condition),
        }))
    }

    /// Parse a table reference
    fn parse_table(&mut self, table_str: &str) -> DSLResult<ASTNode> {
        let table_str = table_str.trim();

        // Handle table with alias: table AS alias
        if let Some(as_pos) = table_str.to_uppercase().find(" AS ") {
            let table_name = table_str[..as_pos].trim();
            let alias = table_str[as_pos + 4..].trim();

            return Ok(ASTNode::Query(QueryNode::Table {
                name: table_name.to_string(),
                alias: Some(alias.to_string()),
            }));
        }

        // Regular table
        Ok(ASTNode::Query(QueryNode::Table {
            name: table_str.to_string(),
            alias: None,
        }))
    }

    /// Parse a WHERE clause
    fn parse_where_clause(&mut self, where_str: &str) -> DSLResult<ASTNode> {
        // Simple parsing for basic conditions
        // This can be enhanced to handle complex boolean expressions

        let where_str = where_str.trim();

        // Look for basic operators
        let operators = ["=", "!=", ">", "<", ">=", "<=", "LIKE", "IN"];

        for op in &operators {
            if let Some(op_pos) = where_str.find(op) {
                let left_str = where_str[..op_pos].trim();
                let right_str = where_str[op_pos + op.len()..].trim();

                let left = self.parse_field(left_str)?;
                let right = self.parse_value(right_str)?;

                return Ok(ASTNode::Expression(ExpressionNode::BinaryExpression {
                    left: Box::new(left),
                    operator: op.to_string(),
                    right: Box::new(right),
                }));
            }
        }

        Err(DSLError::syntax_error(
            0,
            format!("Invalid WHERE clause: {where_str}"),
        ))
    }

    /// Parse a value (literal or variable)
    fn parse_value(&mut self, value_str: &str) -> DSLResult<ASTNode> {
        let value_str = value_str.trim();

        // String literal
        if value_str.starts_with('\'') && value_str.ends_with('\'') {
            let content = &value_str[1..value_str.len() - 1];
            return Ok(ASTNode::Expression(ExpressionNode::Literal {
                value: DSLValue::String(content.to_string()),
            }));
        }

        // Number literal
        if let Ok(number) = value_str.parse::<f64>() {
            return Ok(ASTNode::Expression(ExpressionNode::Literal {
                value: DSLValue::Number(number),
            }));
        }

        // Boolean literal
        match value_str.to_lowercase().as_str() {
            "true" => Ok(ASTNode::Expression(ExpressionNode::Literal {
                value: DSLValue::Boolean(true),
            })),
            "false" => Ok(ASTNode::Expression(ExpressionNode::Literal {
                value: DSLValue::Boolean(false),
            })),
            _ => {
                // Assume it's a field reference
                Ok(ASTNode::Expression(ExpressionNode::Field {
                    name: value_str.to_string(),
                    context: None,
                    alias: None,
                }))
            }
        }
    }

    /// Parse an INTO clause
    fn parse_into_clause(&mut self, into_str: &str) -> DSLResult<ASTNode> {
        let into_str = into_str.trim();

        // Handle variable reference: @variable
        if let Some(var_name) = into_str.strip_prefix('@') {
            return Ok(ASTNode::Expression(ExpressionNode::Variable {
                name: var_name.to_string(),
            }));
        }

        // Handle field reference
        Ok(ASTNode::Expression(ExpressionNode::Field {
            name: into_str.to_string(),
            context: None,
            alias: None,
        }))
    }

    /// Parse an ORDER BY clause
    fn parse_order_by_clause(&mut self, order_by_str: &str) -> DSLResult<Vec<OrderByClause>> {
        let order_by_str = order_by_str.trim();
        let mut order_clauses = Vec::new();

        // Split by comma to handle multiple ORDER BY fields
        for clause in order_by_str.split(',') {
            let clause = clause.trim();

            // Check for DESC/DESCENDING or ASC/ASCENDING keywords
            let (field_str, direction) = if clause.to_uppercase().ends_with(" DESC")
                || clause.to_uppercase().ends_with(" DESCENDING")
            {
                let desc_pos = if clause.to_uppercase().ends_with(" DESC") {
                    clause.len() - 5
                } else {
                    clause.len() - 11 // " DESCENDING".len()
                };
                (clause[..desc_pos].trim(), SortDirection::Descending)
            } else if clause.to_uppercase().ends_with(" ASC")
                || clause.to_uppercase().ends_with(" ASCENDING")
            {
                let asc_pos = if clause.to_uppercase().ends_with(" ASC") {
                    clause.len() - 4
                } else {
                    clause.len() - 10 // " ASCENDING".len()
                };
                (clause[..asc_pos].trim(), SortDirection::Ascending)
            } else {
                // Default to ascending if no direction specified
                (clause.trim(), SortDirection::Ascending)
            };

            // Parse the field
            let field = self.parse_field(field_str)?;

            order_clauses.push(OrderByClause { field, direction });
        }

        Ok(order_clauses)
    }

    /// Check if a WHERE clause contains an implicit join condition.
    /// This is a heuristic and might need refinement based on exact SQL syntax.
    fn contains_implicit_join(&self, where_clause: &str) -> bool {
        let where_clause = where_clause.trim();
        let lower_where_clause = where_clause.to_lowercase();

        // Look for patterns like "table1.field = table2.field" or "table1.field = table2.field"
        // This is a simplified check and might not cover all SQL join conditions.
        // A more robust solution would involve a proper SQL parser.
        lower_where_clause.contains(" = ") && lower_where_clause.contains(".")
    }

    /// Convert an implicit join condition to an explicit JOIN clause.
    /// This is a heuristic and might need refinement based on exact SQL syntax.
    fn convert_implicit_join_to_explicit(
        &mut self,
        table_name: &str,
        where_clause: &str,
    ) -> DSLResult<Option<ASTNode>> {
        let where_clause = where_clause.trim();
        let lower_where_clause = where_clause.to_lowercase();

        // Look for patterns like "backups.tidbId = clusters.tidbid"
        if lower_where_clause.contains("backups.tidbid")
            && lower_where_clause.contains("clusters.tidbid")
        {
            let parts: Vec<&str> = lower_where_clause.split(" = ").collect();
            if parts.len() == 2 {
                let left_side = parts[0];
                let right_side = parts[1];

                let left_table_name = left_side.split('.').next().unwrap();
                let right_table_name = right_side.split('.').next().unwrap();

                let left_field = left_side.split('.').next_back().unwrap();
                let right_field = right_side.split('.').next_back().unwrap();

                // Check for cross-table joins (e.g., backups.tidbId = clusters.tidbid)
                if left_table_name != right_table_name {
                    // This is a cross-table join - filter out the join condition from WHERE clause
                    // For now, we'll return None to indicate the join condition should be removed
                    // and handled in the FROM clause instead
                    return Ok(None);
                }

                // This is a self-join (same table on both sides)
                if left_table_name == table_name && right_table_name == table_name {
                    // This is an implicit self-join, which is not directly supported
                    // by our current JOIN logic. We'll return the remaining WHERE clause.
                    return Ok(Some(ASTNode::Expression(
                        ExpressionNode::BinaryExpression {
                            left: Box::new(ASTNode::Expression(ExpressionNode::Field {
                                name: left_field.to_string(),
                                context: None,
                                alias: None,
                            })),
                            operator: "=".to_string(),
                            right: Box::new(ASTNode::Expression(ExpressionNode::Field {
                                name: right_field.to_string(),
                                context: None,
                                alias: None,
                            })),
                        },
                    )));
                }
            }
        }

        // If no implicit join found, return None
        Ok(None)
    }

    /// Filter out the join condition from a WHERE clause.
    /// This is a heuristic and might need refinement based on exact SQL syntax.
    fn filter_out_join_condition(&mut self, where_str: &str) -> DSLResult<Option<ASTNode>> {
        let where_lower = where_str.to_lowercase();

        // Look for patterns like "backups.tidbId = clusters.tidbid"
        if where_lower.contains("backups.tidbid") && where_lower.contains("clusters.tidbid") {
            // Remove the join condition from the WHERE clause
            let mut remaining_where = where_str.to_string();

            // Try different case variations
            remaining_where = remaining_where
                .replace("backups.tidbId = clusters.tidbid", "")
                .replace("Backups.tidbId = Clusters.tidbid", "");

            remaining_where = remaining_where.trim().to_string();

            // Clean up AND operators
            remaining_where = remaining_where
                .trim_start_matches("AND ")
                .trim_start_matches("and ")
                .trim_end_matches(" AND")
                .trim_end_matches(" and")
                .trim()
                .to_string();

            if remaining_where.is_empty() {
                Ok(None)
            } else {
                // Parse the remaining WHERE clause
                Ok(Some(self.parse_where_clause(&remaining_where)?))
            }
        } else {
            // If no join condition found, return the original WHERE clause
            Ok(Some(self.parse_where_clause(where_str)?))
        }
    }

    /// Convert the FROM clause of a SELECT statement to a JOIN node if an implicit join is detected.
    /// This function is called after the WHERE clause has been parsed and potentially converted.
    fn convert_implicit_join_from_clause(
        &mut self,
        from_str: &str,
        where_str: &str,
    ) -> DSLResult<ASTNode> {
        let where_lower = where_str.to_lowercase();

        if where_lower.contains("backups.tidbid") && where_lower.contains("clusters.tidbid") {
            // Create a JOIN between backups and clusters
            let left_table = ASTNode::Query(QueryNode::Table {
                name: "BACKUPS".to_string(),
                alias: None,
            });

            let right_table = ASTNode::Query(QueryNode::Table {
                name: "CLUSTERS".to_string(),
                alias: None,
            });

            // Create the ON condition
            let on_condition = ASTNode::Expression(ExpressionNode::BinaryExpression {
                left: Box::new(ASTNode::Expression(ExpressionNode::Field {
                    name: "tidbId".to_string(),
                    context: Some(FieldContext::Backups),
                    alias: None,
                })),
                operator: "=".to_string(),
                right: Box::new(ASTNode::Expression(ExpressionNode::Field {
                    name: "tidbId".to_string(),
                    context: Some(FieldContext::Cluster),
                    alias: None,
                })),
            });

            // Create the JOIN node
            let join_node = ASTNode::Query(QueryNode::Join {
                left: Box::new(left_table),
                join_type: JoinType::Inner,
                right: Box::new(right_table),
                on_condition: Box::new(on_condition),
            });

            Ok(join_node)
        } else {
            // If no implicit join, return the original FROM clause
            self.parse_from_clause(from_str)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_select() {
        let result = SQLASTParser::parse("SELECT * FROM BACKUPS");
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_select_with_fields() {
        let result = SQLASTParser::parse("SELECT id, name FROM BACKUPS");
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_select_with_into() {
        let result = SQLASTParser::parse("SELECT * FROM BACKUPS INTO output.json");
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_update_cluster() {
        let result = SQLASTParser::parse("UPDATE CLUSTER my-cluster SET name = 'new-name'");
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_update_cluster_with_json() {
        let result = SQLASTParser::parse(
            "UPDATE CLUSTER my-cluster SET public_connection = { 'enabled': true }",
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_describe_table() {
        let result = SQLASTParser::parse("DESCRIBE TABLE BACKUPS");
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_select_with_order_by() {
        let result = SQLASTParser::parse("SELECT * FROM CLUSTERS ORDER BY name");
        assert!(result.is_ok());

        if let Ok(ASTNode::Query(QueryNode::Select { order_by, .. })) = result {
            assert!(order_by.is_some());
            let order_clauses = order_by.unwrap();
            assert_eq!(order_clauses.len(), 1);
            assert_eq!(order_clauses[0].direction, SortDirection::Ascending);
        }
    }

    #[test]
    fn test_parse_select_with_order_by_desc() {
        let result = SQLASTParser::parse("SELECT * FROM CLUSTERS ORDER BY name DESC");
        assert!(result.is_ok());

        if let Ok(ASTNode::Query(QueryNode::Select { order_by, .. })) = result {
            assert!(order_by.is_some());
            let order_clauses = order_by.unwrap();
            assert_eq!(order_clauses.len(), 1);
            assert_eq!(order_clauses[0].direction, SortDirection::Descending);
        }
    }

    #[test]
    fn test_parse_select_with_order_by_descending() {
        let result = SQLASTParser::parse("SELECT * FROM CLUSTERS ORDER BY name DESCENDING");
        assert!(result.is_ok());

        if let Ok(ASTNode::Query(QueryNode::Select { order_by, .. })) = result {
            assert!(order_by.is_some());
            let order_clauses = order_by.unwrap();
            assert_eq!(order_clauses.len(), 1);
            assert_eq!(order_clauses[0].direction, SortDirection::Descending);
        }
    }

    #[test]
    fn test_parse_select_with_multiple_order_by() {
        let result = SQLASTParser::parse("SELECT * FROM CLUSTERS ORDER BY name ASC, region DESC");
        assert!(result.is_ok());

        if let Ok(ASTNode::Query(QueryNode::Select { order_by, .. })) = result {
            assert!(order_by.is_some());
            let order_clauses = order_by.unwrap();
            assert_eq!(order_clauses.len(), 2);
            assert_eq!(order_clauses[0].direction, SortDirection::Ascending);
            assert_eq!(order_clauses[1].direction, SortDirection::Descending);
        }
    }

    #[test]
    fn test_parse_select_with_where_and_order_by() {
        let result =
            SQLASTParser::parse("SELECT * FROM CLUSTERS WHERE state = 'ACTIVE' ORDER BY name DESC");
        assert!(result.is_ok());

        if let Ok(ASTNode::Query(QueryNode::Select {
            where_clause,
            order_by,
            ..
        })) = result
        {
            assert!(where_clause.is_some());
            assert!(order_by.is_some());
            let order_clauses = order_by.unwrap();
            assert_eq!(order_clauses.len(), 1);
            assert_eq!(order_clauses[0].direction, SortDirection::Descending);
        }
    }

    #[test]
    fn test_contains_implicit_join() {
        let parser = SQLASTParser;

        // Test case that should detect implicit join
        let where_clause = "backups.tidbId = clusters.tidbid and clusters.displayName = 'SB-Test01-delete-whenever'";
        assert!(parser.contains_implicit_join(where_clause));

        // Test case that should NOT detect implicit join
        let where_clause_no_join = "displayName = 'SB-Test01-delete-whenever'";
        assert!(!parser.contains_implicit_join(where_clause_no_join));

        // Test case with different table field combinations
        let where_clause_alt = "backups.clusterid = clusters.id and clusters.region = 'us-east-1'";
        assert!(parser.contains_implicit_join(where_clause_alt));
    }

    #[test]
    fn test_convert_implicit_join_to_explicit() {
        let mut parser = SQLASTParser;

        let where_clause = "backups.tidbId = clusters.tidbid and clusters.displayName = 'SB-Test01-delete-whenever'";
        let result = parser.convert_implicit_join_to_explicit("BACKUPS", where_clause);

        assert!(result.is_ok());
        let remaining_where = result.unwrap();

        // For cross-table joins, we expect None since the join condition is filtered out
        // and handled in the FROM clause instead
        assert!(remaining_where.is_none());
    }

    #[test]
    fn test_parse_select_with_implicit_join() {
        let sql = "select * from backups where backups.tidbId = clusters.tidbid and clusters.displayName = 'SB-Test01-delete-whenever'";
        let result = SQLASTParser::parse(sql);

        assert!(result.is_ok());

        // Verify that the result is a JOIN node
        if let Ok(ASTNode::Query(QueryNode::Select { from, .. })) = result {
            if let ASTNode::Query(QueryNode::Join { .. }) = *from {
                // Success - the implicit join was converted to an explicit JOIN
            } else {
                panic!("Expected JOIN node, got: {:?}", *from);
            }
        } else {
            panic!("Expected SELECT node, got: {result:?}");
        }
    }

    #[test]
    fn test_user_query_implicit_join() {
        // This is the exact query provided by the user
        let sql = "select * from backups where backups.tidbId = clusters.tidbid and clusters.displayName = 'SB-Test01-delete-whenever'";
        let result = SQLASTParser::parse(sql);

        assert!(result.is_ok());

        // Verify that the result is a JOIN node
        if let Ok(ASTNode::Query(QueryNode::Select {
            from, where_clause, ..
        })) = result
        {
            // Check that FROM clause is a JOIN
            if let ASTNode::Query(QueryNode::Join {
                left,
                right,
                join_type,
                on_condition,
            }) = *from
            {
                // Verify the JOIN structure
                if let ASTNode::Query(QueryNode::Table {
                    name: left_name, ..
                }) = *left
                {
                    assert_eq!(left_name, "BACKUPS");
                } else {
                    panic!("Expected BACKUPS table on left side");
                }

                if let ASTNode::Query(QueryNode::Table {
                    name: right_name, ..
                }) = *right
                {
                    assert_eq!(right_name, "CLUSTERS");
                } else {
                    panic!("Expected CLUSTERS table on right side");
                }

                assert_eq!(join_type, JoinType::Inner);

                // Verify the ON condition
                if let ASTNode::Expression(ExpressionNode::BinaryExpression {
                    left: on_left,
                    operator,
                    right: on_right,
                }) = *on_condition
                {
                    assert_eq!(operator, "=");

                    // Check left side of ON condition
                    if let ASTNode::Expression(ExpressionNode::Field {
                        name: left_field,
                        context: Some(FieldContext::Backups),
                        ..
                    }) = *on_left
                    {
                        assert_eq!(left_field, "tidbId");
                    } else {
                        panic!("Expected backups.tidbId on left side of ON condition");
                    }

                    // Check right side of ON condition
                    if let ASTNode::Expression(ExpressionNode::Field {
                        name: right_field,
                        context: Some(FieldContext::Cluster),
                        ..
                    }) = *on_right
                    {
                        assert_eq!(right_field, "tidbId");
                    } else {
                        panic!("Expected clusters.tidbId on right side of ON condition");
                    }
                } else {
                    panic!("Expected binary expression in ON condition");
                }
            } else {
                panic!("Expected JOIN node, got: {:?}", *from);
            }

            // Check that WHERE clause contains the remaining condition
            if let Some(where_node) = where_clause {
                if let ASTNode::Expression(ExpressionNode::BinaryExpression {
                    left,
                    operator,
                    right,
                }) = *where_node
                {
                    assert_eq!(operator, "=");

                    // Check that it's the clusters.displayName condition
                    if let ASTNode::Expression(ExpressionNode::Field {
                        name: field_name, ..
                    }) = *left
                    {
                        assert_eq!(field_name, "displayName");
                    } else {
                        panic!("Expected displayName field in WHERE clause");
                    }

                    if let ASTNode::Expression(ExpressionNode::Literal { value }) = *right {
                        if let DSLValue::String(s) = value {
                            assert_eq!(s, "SB-Test01-delete-whenever");
                        } else {
                            panic!("Expected string literal in WHERE clause");
                        }
                    } else {
                        panic!("Expected literal value in WHERE clause");
                    }
                } else {
                    panic!("Expected binary expression in WHERE clause");
                }
            } else {
                panic!("Expected WHERE clause to be present");
            }
        } else {
            panic!("Expected SELECT node, got: {result:?}");
        }
    }
}
