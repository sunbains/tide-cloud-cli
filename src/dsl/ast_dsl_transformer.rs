use crate::dsl::{
    ast::{ASTNode, ASTTransformer, CommandNode, ExpressionNode, OrderByClause},
    commands::{DSLCommand, DSLCommandType},
    error::{DSLError, DSLResult},
    syntax::DSLValue,
};

/// AST to DSL command transformer
pub struct ASTDSLTransformer;

impl ASTDSLTransformer {
    /// Transform an AST node to a DSL command
    pub fn transform(node: &ASTNode) -> DSLResult<DSLCommand> {
        let mut transformer = ASTDSLTransformer;
        transformer.transform_node(node)
    }

    /// Transform an AST node to a DSL command
    fn transform_node(&mut self, node: &ASTNode) -> DSLResult<DSLCommand> {
        match node {
            ASTNode::Command(CommandNode::CreateCluster {
                name,
                region,
                rcu_range,
                service_plan,
                password,
            }) => {
                let mut command = DSLCommand::new(DSLCommandType::CreateCluster);
                command = command.with_parameter("name", DSLValue::String(name.clone()));
                command = command.with_parameter("region", DSLValue::String(region.clone()));

                if let Some((min_rcu, max_rcu)) = rcu_range {
                    command = command.with_parameter("min_rcu", DSLValue::String(min_rcu.clone()));
                    command = command.with_parameter("max_rcu", DSLValue::String(max_rcu.clone()));
                }

                if let Some(plan) = service_plan {
                    command =
                        command.with_parameter("service_plan", DSLValue::String(plan.clone()));
                }

                if let Some(pwd) = password {
                    command = command.with_parameter("password", DSLValue::String(pwd.clone()));
                }

                Ok(command)
            }

            ASTNode::Command(CommandNode::DeleteCluster { name }) => {
                let mut command = DSLCommand::new(DSLCommandType::DeleteCluster);
                command = command.with_parameter("name", DSLValue::String(name.clone()));
                Ok(command)
            }

            ASTNode::Command(CommandNode::UpdateCluster { name, updates }) => {
                let mut command = DSLCommand::new(DSLCommandType::UpdateCluster);
                command = command.with_parameter("name", DSLValue::String(name.clone()));

                // Convert updates to parameters
                for update in updates {
                    if let ASTNode::Expression(ExpressionNode::Assignment {
                        name: field_name,
                        value,
                    }) = update
                    {
                        let dsl_value = self.ast_node_to_dsl_value(value)?;
                        command = command.with_parameter(field_name.clone(), dsl_value);
                    }
                }

                Ok(command)
            }

            ASTNode::Command(crate::dsl::ast::CommandNode::WaitForCluster {
                name,
                state,
                timeout,
            }) => {
                let mut command = DSLCommand::new(DSLCommandType::WaitForCluster);
                command = command.with_parameter("name", DSLValue::String(name.clone()));
                command = command.with_parameter("state", DSLValue::String(state.clone()));

                if let Some(timeout_val) = timeout {
                    command =
                        command.with_parameter("timeout", DSLValue::Number(*timeout_val as f64));
                }

                Ok(command)
            }

            ASTNode::Command(crate::dsl::ast::CommandNode::CreateBackup {
                cluster_name,
                description,
            }) => {
                let mut command = DSLCommand::new(DSLCommandType::CreateBackup);
                command =
                    command.with_parameter("cluster_name", DSLValue::String(cluster_name.clone()));

                if let Some(desc) = description {
                    command = command.with_parameter("description", DSLValue::String(desc.clone()));
                }

                Ok(command)
            }

            ASTNode::Command(crate::dsl::ast::CommandNode::ListBackups {
                cluster_name,
                filters,
            }) => {
                let mut command = DSLCommand::new(DSLCommandType::ListBackups);

                if let Some(name) = cluster_name {
                    command =
                        command.with_parameter("cluster_name", DSLValue::String(name.clone()));
                }

                if !filters.is_empty() {
                    let filter_str = self.filters_to_string(filters)?;
                    command = command.with_parameter("filter", DSLValue::String(filter_str));
                }

                Ok(command)
            }

            ASTNode::Command(crate::dsl::ast::CommandNode::DeleteBackup {
                cluster_name,
                backup_id,
            }) => {
                let mut command = DSLCommand::new(DSLCommandType::DeleteBackup);
                command =
                    command.with_parameter("cluster_name", DSLValue::String(cluster_name.clone()));
                command = command.with_parameter("backup_id", DSLValue::String(backup_id.clone()));
                Ok(command)
            }

            ASTNode::Utility(crate::dsl::ast::UtilityNode::SetVariable { name, value }) => {
                let mut command = DSLCommand::new(DSLCommandType::SetVariable);
                command = command.with_parameter("name", DSLValue::String(name.clone()));
                let value = self.ast_node_to_dsl_value(value)?;
                command = command.with_parameter("value", value);
                Ok(command)
            }

            ASTNode::Utility(crate::dsl::ast::UtilityNode::GetVariable { name }) => {
                let mut command = DSLCommand::new(DSLCommandType::GetVariable);
                command = command.with_parameter("name", DSLValue::String(name.clone()));
                Ok(command)
            }

            ASTNode::Utility(crate::dsl::ast::UtilityNode::Echo { message }) => {
                let mut command = DSLCommand::new(DSLCommandType::Echo);
                let message_value = self.ast_node_to_dsl_value(message)?;
                command = command.with_parameter("message", message_value);
                Ok(command)
            }

            ASTNode::Utility(crate::dsl::ast::UtilityNode::Sleep { duration }) => {
                let mut command = DSLCommand::new(DSLCommandType::Sleep);
                let duration_value = self.ast_node_to_dsl_value(duration)?;
                command = command.with_parameter("duration", duration_value);
                Ok(command)
            }

            ASTNode::Query(crate::dsl::ast::QueryNode::DescribeTable { table_name }) => {
                self.transform_describe_table(table_name)
            }

            ASTNode::Query(crate::dsl::ast::QueryNode::Select {
                fields,
                from,
                where_clause,
                order_by,
                into_clause,
            }) => self.transform_select(fields, from, where_clause, order_by, into_clause),

            _ => Err(DSLError::syntax_error(
                0,
                format!("Unsupported AST node type: {}", node.node_type()),
            )),
        }
    }

    /// Convert filters to a string representation
    fn filters_to_string(&mut self, filters: &[ASTNode]) -> DSLResult<String> {
        let filter_strings: Vec<String> = filters
            .iter()
            .map(|filter| self.ast_node_to_string(filter))
            .collect::<DSLResult<Vec<_>>>()?;

        Ok(filter_strings.join(" AND "))
    }

    /// Convert fields to a string representation
    fn fields_to_string(&mut self, fields: &[ASTNode]) -> DSLResult<String> {
        let field_strings: Vec<String> = fields
            .iter()
            .map(|field| match field {
                ASTNode::Expression(crate::dsl::ast::ExpressionNode::Wildcard) => {
                    Ok("*".to_string())
                }
                ASTNode::Expression(crate::dsl::ast::ExpressionNode::Field {
                    name,
                    context,
                    alias,
                }) => {
                    let mut field_str = String::new();
                    if let Some(ctx) = context {
                        field_str.push_str(&ctx.to_string());
                        field_str.push('.');
                    }
                    field_str.push_str(name);
                    if let Some(alias_name) = alias {
                        field_str.push_str(" AS ");
                        field_str.push_str(alias_name);
                    }
                    Ok(field_str)
                }
                _ => Err(DSLError::syntax_error(
                    0,
                    format!("Invalid field in SELECT: {field:?}"),
                )),
            })
            .collect::<DSLResult<Vec<_>>>()?;

        Ok(field_strings.join(", "))
    }

    /// Convert an AST node to a string representation
    #[allow(clippy::only_used_in_recursion)]
    fn ast_node_to_string(&mut self, node: &ASTNode) -> DSLResult<String> {
        match node {
            ASTNode::Expression(crate::dsl::ast::ExpressionNode::BinaryExpression {
                left,
                operator,
                right,
            }) => {
                let left_str = self.ast_node_to_string(left)?;
                let right_str = self.ast_node_to_string(right)?;
                Ok(format!("{left_str} {operator} {right_str}"))
            }

            ASTNode::Expression(crate::dsl::ast::ExpressionNode::Field {
                name,
                context,
                alias,
            }) => {
                let mut field_str = String::new();
                if let Some(ctx) = context {
                    field_str.push_str(&ctx.to_string());
                    field_str.push('.');
                }
                field_str.push_str(name);
                if let Some(alias_name) = alias {
                    field_str.push_str(" AS ");
                    field_str.push_str(alias_name);
                }
                Ok(field_str)
            }

            ASTNode::Expression(crate::dsl::ast::ExpressionNode::Literal { value }) => {
                match value {
                    DSLValue::String(s) => Ok(format!("'{s}'")),
                    DSLValue::Number(n) => Ok(n.to_string()),
                    DSLValue::Boolean(b) => Ok(b.to_string()),
                    _ => Ok(format!("{value:?}")),
                }
            }

            ASTNode::Expression(crate::dsl::ast::ExpressionNode::Variable { name }) => {
                Ok(format!("@{name}"))
            }

            ASTNode::Expression(crate::dsl::ast::ExpressionNode::Wildcard) => Ok("*".to_string()),

            _ => Err(DSLError::syntax_error(
                0,
                format!("Cannot convert AST node to string: {node:?}"),
            )),
        }
    }

    /// Transform DESCRIBE TABLE command
    fn transform_describe_table(&mut self, table_name: &str) -> DSLResult<DSLCommand> {
        let mut command = DSLCommand::new(DSLCommandType::Echo);

        let schema_info = self.get_table_schema(table_name);
        command = command.with_parameter("message", DSLValue::String(schema_info));
        Ok(command)
    }

    /// Get schema information for a table dynamically from the schema registry
    fn get_table_schema(&self, table_name: &str) -> String {
        let schema_registry = &crate::schema::SCHEMA;

        // Map table names to object types in the schema
        let object_type = match table_name.to_uppercase().as_str() {
            "CLUSTERS" | "CLUSTER" => "Tidb",
            "BACKUPS" | "BACKUP" => "Backup",
            _ => return "Unknown table - supported tables: CLUSTERS, BACKUPS".to_string(),
        };

        // Get the object schema
        if let Some(object_schema) = schema_registry.get_object_schema(object_type) {
            self.format_table_description(table_name, object_schema)
        } else {
            format!("Table '{table_name}' not found in schema registry")
        }
    }

    /// Format table description from schema data
    fn format_table_description(
        &self,
        table_name: &str,
        schema: &crate::schema::ObjectSchema,
    ) -> String {
        let mut result = String::new();

        // Table header
        result.push_str(&format!("Table: {}\n", table_name.to_uppercase()));
        if let Some(description) = &schema.description {
            result.push_str(&format!("Description: {description}\n"));
        }
        result.push('\n');

        // Sort fields by name for consistent output
        let mut sorted_fields: Vec<_> = schema.fields.values().collect();
        sorted_fields.sort_by(|a, b| a.name.cmp(&b.name));

        // Simple column format
        result.push_str("Column Name          Type           Description\n");
        result.push_str("-----------          ----           -----------\n");

        for field in &sorted_fields {
            let column_name = &field.json_name; // Use JSON name (camelCase) for display
            let field_type = self.format_field_type(&field.field_type);
            let description = field.description.as_deref().unwrap_or("");

            result.push_str(&format!(
                "{column_name:<20} {field_type:<15} {description}\n"
            ));
        }

        result
    }

    /// Format field type for display
    #[allow(clippy::only_used_in_recursion)]
    fn format_field_type(&self, field_type: &crate::schema::FieldType) -> String {
        use crate::schema::FieldType;

        match field_type {
            FieldType::String { .. } => "VARCHAR".to_string(),
            FieldType::Integer { .. } => "BIGINT".to_string(),
            FieldType::Float { .. } => "FLOAT".to_string(),
            FieldType::Boolean { .. } => "BOOLEAN".to_string(),
            FieldType::Enum { values, .. } => {
                if values.len() <= 3 {
                    format!("ENUM({})", values.join(","))
                } else {
                    "ENUM".to_string()
                }
            }
            FieldType::Object { .. } => "JSON".to_string(),
            FieldType::Array { .. } => "ARRAY".to_string(),
            FieldType::Optional { inner_type, .. } => {
                format!("{}?", self.format_field_type(inner_type))
            }
        }
    }

    /// Transform SELECT statement
    fn transform_select(
        &mut self,
        fields: &[ASTNode],
        from: &ASTNode,
        where_clause: &Option<Box<ASTNode>>,
        order_by: &Option<Vec<OrderByClause>>,
        into_clause: &Option<Box<ASTNode>>,
    ) -> DSLResult<DSLCommand> {
        match from {
            ASTNode::Query(crate::dsl::ast::QueryNode::Table { name, .. }) => {
                let command_type = match name.to_uppercase().as_str() {
                    "BACKUP" | "BACKUPS" => DSLCommandType::ListBackups,
                    "CLUSTER" | "CLUSTERS" => DSLCommandType::ListClusters,
                    _ => return Err(DSLError::syntax_error(0, format!("Unknown table: {name}"))),
                };

                let mut command = DSLCommand::new(command_type);

                // Add fields, where clause, order by, and into clause
                self.add_select_parameters(
                    &mut command,
                    fields,
                    where_clause,
                    order_by,
                    into_clause,
                )?;
                Ok(command)
            }
            ASTNode::Query(crate::dsl::ast::QueryNode::Join {
                left,
                join_type,
                right,
                on_condition,
            }) => {
                // Handle JOIN queries properly
                let mut command = DSLCommand::new(DSLCommandType::Join);

                // Extract table names from left and right sides
                let left_table = self.extract_table_name(left)?;
                let right_table = self.extract_table_name(right)?;

                command = command.with_parameter("left_table", DSLValue::String(left_table));
                command = command.with_parameter("right_table", DSLValue::String(right_table));
                command =
                    command.with_parameter("join_type", DSLValue::String(format!("{join_type}")));
                command = command.with_parameter(
                    "on_condition",
                    DSLValue::String(self.ast_node_to_string(on_condition)?),
                );

                // Add WHERE clause if present
                if let Some(where_expr) = where_clause {
                    command = command.with_parameter(
                        "where_clause",
                        DSLValue::String(self.ast_node_to_string(where_expr)?),
                    );
                }

                self.add_select_parameters(&mut command, fields, &None, &None, into_clause)?;
                Ok(command)
            }
            _ => Err(DSLError::syntax_error(
                0,
                "SELECT FROM requires a table or join".to_string(),
            )),
        }
    }

    /// Extract table name from a table AST node
    fn extract_table_name(&mut self, node: &ASTNode) -> DSLResult<String> {
        match node {
            ASTNode::Query(crate::dsl::ast::QueryNode::Table { name, .. }) => Ok(name.clone()),
            _ => Err(DSLError::syntax_error(
                0,
                "Expected table node in JOIN".to_string(),
            )),
        }
    }

    /// Add common SELECT parameters to command
    fn add_select_parameters(
        &mut self,
        command: &mut DSLCommand,
        fields: &[ASTNode],
        where_clause: &Option<Box<ASTNode>>,
        order_by: &Option<Vec<OrderByClause>>,
        into_clause: &Option<Box<ASTNode>>,
    ) -> DSLResult<()> {
        // Add selected fields (but not for wildcard *)
        if !fields.is_empty() {
            let field_names = self.fields_to_string(fields)?;
            // Only set selected_fields if it's not a wildcard (*)
            if field_names != "*" {
                *command = command
                    .clone()
                    .with_parameter("selected_fields", DSLValue::String(field_names));
            }
        }

        // Add WHERE clause
        if let Some(where_expr) = where_clause {
            let where_str = self.ast_node_to_string(where_expr)?;
            *command = command
                .clone()
                .with_parameter("where_clause", DSLValue::String(where_str));
        }

        // Add ORDER BY clause
        if let Some(order_clauses) = order_by {
            let order_by_str = self.order_by_to_string(order_clauses)?;
            *command = command
                .clone()
                .with_parameter("order_by", DSLValue::String(order_by_str));
        }

        // Add INTO clause
        if let Some(into_expr) = into_clause {
            let into_str = self.ast_node_to_string(into_expr)?;
            *command = command
                .clone()
                .with_parameter("into_clause", DSLValue::String(into_str));
        }

        Ok(())
    }

    /// Convert ORDER BY clauses to a string representation
    fn order_by_to_string(&mut self, order_clauses: &[OrderByClause]) -> DSLResult<String> {
        let order_strings: Result<Vec<String>, DSLError> = order_clauses
            .iter()
            .map(|clause| {
                let field_str = self.ast_node_to_string(&clause.field)?;
                let direction = clause.direction.to_string();
                Ok(format!("{field_str} {direction}"))
            })
            .collect();

        match order_strings {
            Ok(strings) => Ok(strings.join(", ")),
            Err(e) => Err(e),
        }
    }

    /// Convert an AST node to a DSL value
    fn ast_node_to_dsl_value(&mut self, node: &ASTNode) -> DSLResult<DSLValue> {
        match node {
            ASTNode::Expression(crate::dsl::ast::ExpressionNode::Literal { value }) => {
                Ok(value.clone())
            }

            ASTNode::Expression(crate::dsl::ast::ExpressionNode::Variable { name }) => {
                // For variables, we'll return the variable name as a string
                // The executor will handle variable resolution
                Ok(DSLValue::String(format!("@{name}")))
            }

            ASTNode::Expression(crate::dsl::ast::ExpressionNode::BinaryExpression {
                left: _,
                operator: _,
                right: _,
            }) => {
                // For expressions, convert to string representation
                let expr_str = self.ast_node_to_string(node)?;
                Ok(DSLValue::String(expr_str))
            }

            _ => Err(DSLError::syntax_error(
                0,
                format!("Cannot convert AST node to DSL value: {node:?}"),
            )),
        }
    }
}

impl ASTTransformer for ASTDSLTransformer {
    fn transform(&mut self, node: &ASTNode) -> Result<ASTNode, String> {
        // This implementation could be used for AST-to-AST transformations
        // For now, we'll just clone the node
        Ok(node.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dsl::ast::FieldContext;
    use crate::dsl::syntax::DSLValue;

    #[test]
    fn test_transform_create_cluster() {
        let ast = ASTNode::Command(crate::dsl::ast::CommandNode::CreateCluster {
            name: "my-cluster".to_string(),
            region: "aws-us-west-1".to_string(),
            rcu_range: Some(("1".to_string(), "10".to_string())),
            service_plan: Some("starter".to_string()),
            password: None,
        });

        let result = ASTDSLTransformer::transform(&ast);
        assert!(result.is_ok());

        if let Ok(command) = result {
            assert_eq!(command.command_type, DSLCommandType::CreateCluster);
            assert_eq!(
                command.get_parameter("name").unwrap(),
                &DSLValue::String("my-cluster".to_string())
            );
            assert_eq!(
                command.get_parameter("region").unwrap(),
                &DSLValue::String("aws-us-west-1".to_string())
            );
            assert_eq!(
                command.get_parameter("min_rcu").unwrap(),
                &DSLValue::String("1".to_string())
            );
            assert_eq!(
                command.get_parameter("max_rcu").unwrap(),
                &DSLValue::String("10".to_string())
            );
            assert_eq!(
                command.get_parameter("service_plan").unwrap(),
                &DSLValue::String("starter".to_string())
            );
        }
    }

    #[test]
    fn test_transform_select_backups() {
        let ast = ASTNode::Query(crate::dsl::ast::QueryNode::Select {
            fields: vec![
                ASTNode::Expression(crate::dsl::ast::ExpressionNode::Field {
                    name: "displayName".to_string(),
                    context: None,
                    alias: None,
                }),
                ASTNode::Expression(crate::dsl::ast::ExpressionNode::Field {
                    name: "state".to_string(),
                    context: None,
                    alias: None,
                }),
            ],
            from: Box::new(ASTNode::Query(crate::dsl::ast::QueryNode::Table {
                name: "BACKUPS".to_string(),
                alias: None,
            })),
            where_clause: Some(Box::new(ASTNode::Expression(
                crate::dsl::ast::ExpressionNode::BinaryExpression {
                    left: Box::new(ASTNode::Expression(
                        crate::dsl::ast::ExpressionNode::Field {
                            name: "displayName".to_string(),
                            context: Some(FieldContext::Cluster),
                            alias: None,
                        },
                    )),
                    operator: "=".to_string(),
                    right: Box::new(ASTNode::Expression(
                        crate::dsl::ast::ExpressionNode::Literal {
                            value: DSLValue::String(".*".to_string()),
                        },
                    )),
                },
            ))),
            order_by: None,
            into_clause: Some(Box::new(ASTNode::Expression(
                crate::dsl::ast::ExpressionNode::Variable {
                    name: "result".to_string(),
                },
            ))),
        });

        let result = ASTDSLTransformer::transform(&ast);
        assert!(result.is_ok());

        if let Ok(command) = result {
            assert_eq!(command.command_type, DSLCommandType::ListBackups);
            assert_eq!(
                command.get_parameter("selected_fields").unwrap(),
                &DSLValue::String("displayName, state".to_string())
            );
            assert_eq!(
                command.get_parameter("where_clause").unwrap(),
                &DSLValue::String("CLUSTER.displayName = '.*'".to_string())
            );
            assert_eq!(
                command.get_parameter("into_clause").unwrap(),
                &DSLValue::String("@result".to_string())
            );
        }
    }

    #[test]
    fn test_transform_select_all_backups() {
        let ast = ASTNode::Query(crate::dsl::ast::QueryNode::Select {
            fields: vec![ASTNode::Expression(
                crate::dsl::ast::ExpressionNode::Field {
                    name: "*".to_string(),
                    context: None,
                    alias: None,
                },
            )],
            from: Box::new(ASTNode::Query(crate::dsl::ast::QueryNode::Table {
                name: "BACKUPS".to_string(),
                alias: None,
            })),
            where_clause: None,
            order_by: None,
            into_clause: None,
        });

        let result = ASTDSLTransformer::transform(&ast);
        assert!(result.is_ok());

        if let Ok(command) = result {
            assert_eq!(command.command_type, DSLCommandType::ListBackups);
            // For wildcard (*), selected_fields parameter should not be set
            assert!(command.get_parameter("selected_fields").is_none());
        }
    }

    #[test]
    fn test_transform_select_all_backups_with_where() {
        let ast = ASTNode::Query(crate::dsl::ast::QueryNode::Select {
            fields: vec![ASTNode::Expression(
                crate::dsl::ast::ExpressionNode::Field {
                    name: "*".to_string(),
                    context: None,
                    alias: None,
                },
            )],
            from: Box::new(ASTNode::Query(crate::dsl::ast::QueryNode::Table {
                name: "BACKUPS".to_string(),
                alias: None,
            })),
            where_clause: Some(Box::new(ASTNode::Expression(
                crate::dsl::ast::ExpressionNode::BinaryExpression {
                    left: Box::new(ASTNode::Expression(
                        crate::dsl::ast::ExpressionNode::Field {
                            name: "state".to_string(),
                            context: None,
                            alias: None,
                        },
                    )),
                    operator: "=".to_string(),
                    right: Box::new(ASTNode::Expression(
                        crate::dsl::ast::ExpressionNode::Literal {
                            value: DSLValue::String("SUCCEEDED".to_string()),
                        },
                    )),
                },
            ))),
            order_by: None,
            into_clause: None,
        });

        let result = ASTDSLTransformer::transform(&ast);
        assert!(result.is_ok());

        if let Ok(command) = result {
            assert_eq!(command.command_type, DSLCommandType::ListBackups);
            // For wildcard (*), selected_fields parameter should not be set
            assert!(command.get_parameter("selected_fields").is_none());
            assert_eq!(
                command.get_parameter("where_clause").unwrap(),
                &DSLValue::String("state = 'SUCCEEDED'".to_string())
            );
        }
    }
}
