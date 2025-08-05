use crate::dsl::syntax::DSLValue;
use std::fmt;

/// Field context for cross-context field references
#[derive(Debug, Clone, PartialEq)]
pub enum FieldContext {
    Cluster,
    Backups,
}

/// Join types for SQL JOIN operations
#[derive(Debug, Clone, PartialEq)]
pub enum JoinType {
    Inner,
    Left,
    Right,
    Full,
}

impl JoinType {
    pub fn to_string(&self) -> &'static str {
        match self {
            JoinType::Inner => "INNER JOIN",
            JoinType::Left => "LEFT JOIN",
            JoinType::Right => "RIGHT JOIN",
            JoinType::Full => "FULL JOIN",
        }
    }
}

impl fmt::Display for FieldContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FieldContext::Cluster => write!(f, "CLUSTER"),
            FieldContext::Backups => write!(f, "BACKUPS"),
        }
    }
}

impl fmt::Display for JoinType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            JoinType::Inner => write!(f, "Inner"),
            JoinType::Left => write!(f, "Left"),
            JoinType::Right => write!(f, "Right"),
            JoinType::Full => write!(f, "Full"),
        }
    }
}

/// Sort direction for ORDER BY clause
#[derive(Debug, Clone, PartialEq)]
pub enum SortDirection {
    Ascending,
    Descending,
}

impl SortDirection {
    pub fn to_string(&self) -> &'static str {
        match self {
            SortDirection::Ascending => "ASC",
            SortDirection::Descending => "DESC",
        }
    }
}

impl fmt::Display for SortDirection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SortDirection::Ascending => write!(f, "ASC"),
            SortDirection::Descending => write!(f, "DESC"),
        }
    }
}

/// Order by clause for SELECT statements
#[derive(Debug, Clone)]
pub struct OrderByClause {
    pub field: ASTNode,
    pub direction: SortDirection,
}

/// Query-related AST nodes
#[derive(Debug, Clone)]
pub enum QueryNode {
    Select {
        fields: Vec<ASTNode>,
        from: Box<ASTNode>,
        where_clause: Option<Box<ASTNode>>,
        order_by: Option<Vec<OrderByClause>>,
        into_clause: Option<Box<ASTNode>>,
    },
    DescribeTable {
        table_name: String,
    },
    Table {
        name: String,
        alias: Option<String>,
    },
    Join {
        left: Box<ASTNode>,
        join_type: JoinType,
        right: Box<ASTNode>,
        on_condition: Box<ASTNode>,
    },
}

impl fmt::Display for QueryNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            QueryNode::Select { .. } => write!(f, "Select"),
            QueryNode::DescribeTable { .. } => write!(f, "DescribeTable"),
            QueryNode::Table { .. } => write!(f, "Table"),
            QueryNode::Join { .. } => write!(f, "Join"),
        }
    }
}

/// Expression-related AST nodes
#[derive(Debug, Clone)]
pub enum ExpressionNode {
    Field {
        name: String,
        context: Option<FieldContext>, // For cross-context like CLUSTER.displayName
        alias: Option<String>,
    },
    Wildcard,
    BinaryExpression {
        left: Box<ASTNode>,
        operator: String,
        right: Box<ASTNode>,
    },
    UnaryExpression {
        operator: String,
        operand: Box<ASTNode>,
    },
    Literal {
        value: DSLValue,
    },
    Variable {
        name: String,
    },
    FunctionCall {
        name: String,
        arguments: Vec<ASTNode>,
    },
    Assignment {
        name: String,
        value: Box<ASTNode>,
    },
}

impl fmt::Display for ExpressionNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ExpressionNode::Field { .. } => write!(f, "Field"),
            ExpressionNode::Wildcard => write!(f, "Wildcard"),
            ExpressionNode::BinaryExpression { .. } => write!(f, "BinaryExpression"),
            ExpressionNode::UnaryExpression { .. } => write!(f, "UnaryExpression"),
            ExpressionNode::Literal { .. } => write!(f, "Literal"),
            ExpressionNode::Variable { .. } => write!(f, "Variable"),
            ExpressionNode::FunctionCall { .. } => write!(f, "FunctionCall"),
            ExpressionNode::Assignment { .. } => write!(f, "Assignment"),
        }
    }
}

/// Control flow AST nodes
#[derive(Debug, Clone)]
pub enum ControlFlowNode {
    IfStatement {
        condition: Box<ASTNode>,
        then_branch: Vec<ASTNode>,
        else_branch: Option<Vec<ASTNode>>,
    },
    LoopStatement {
        condition: Option<Box<ASTNode>>,
        body: Vec<ASTNode>,
    },
    BreakStatement,
    ContinueStatement,
    ReturnStatement {
        value: Option<Box<ASTNode>>,
    },
    Block {
        statements: Vec<ASTNode>,
    },
}

impl fmt::Display for ControlFlowNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ControlFlowNode::IfStatement { .. } => write!(f, "IfStatement"),
            ControlFlowNode::LoopStatement { .. } => write!(f, "LoopStatement"),
            ControlFlowNode::BreakStatement => write!(f, "BreakStatement"),
            ControlFlowNode::ContinueStatement => write!(f, "ContinueStatement"),
            ControlFlowNode::ReturnStatement { .. } => write!(f, "ReturnStatement"),
            ControlFlowNode::Block { .. } => write!(f, "Block"),
        }
    }
}

/// DSL command AST nodes
#[derive(Debug, Clone)]
pub enum CommandNode {
    CreateCluster {
        name: String,
        region: String,
        rcu_range: Option<(String, String)>,
        service_plan: Option<String>,
        password: Option<String>,
    },
    DeleteCluster {
        name: String,
    },
    UpdateCluster {
        name: String,
        updates: Vec<ASTNode>,
    },
    WaitForCluster {
        name: String,
        state: String,
        timeout: Option<u64>,
    },
    CreateBackup {
        cluster_name: String,
        description: Option<String>,
    },
    ListBackups {
        cluster_name: Option<String>,
        filters: Vec<ASTNode>,
    },
    DeleteBackup {
        cluster_name: String,
        backup_id: String,
    },
    EstimatePrice {
        region: String,
        rcu_range: (String, String),
        service_plan: String,
        storage: Option<String>,
    },
}

impl fmt::Display for CommandNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CommandNode::CreateCluster { .. } => write!(f, "CreateCluster"),
            CommandNode::DeleteCluster { .. } => write!(f, "DeleteCluster"),
            CommandNode::UpdateCluster { .. } => write!(f, "UpdateCluster"),
            CommandNode::WaitForCluster { .. } => write!(f, "WaitForCluster"),
            CommandNode::CreateBackup { .. } => write!(f, "CreateBackup"),
            CommandNode::ListBackups { .. } => write!(f, "ListBackups"),
            CommandNode::DeleteBackup { .. } => write!(f, "DeleteBackup"),
            CommandNode::EstimatePrice { .. } => write!(f, "EstimatePrice"),
        }
    }
}

/// Utility AST nodes
#[derive(Debug, Clone)]
pub enum UtilityNode {
    Echo { message: Box<ASTNode> },
    Sleep { duration: Box<ASTNode> },
    SetVariable { name: String, value: Box<ASTNode> },
    GetVariable { name: String },
    SetLogLevel { level: String },
}

impl fmt::Display for UtilityNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UtilityNode::Echo { .. } => write!(f, "Echo"),
            UtilityNode::Sleep { .. } => write!(f, "Sleep"),
            UtilityNode::SetVariable { .. } => write!(f, "SetVariable"),
            UtilityNode::GetVariable { .. } => write!(f, "GetVariable"),
            UtilityNode::SetLogLevel { .. } => write!(f, "SetLogLevel"),
        }
    }
}

/// Main AST node that can represent any type of node
#[derive(Debug, Clone)]
pub enum ASTNode {
    Query(QueryNode),
    Expression(ExpressionNode),
    ControlFlow(ControlFlowNode),
    Command(CommandNode),
    Utility(UtilityNode),
    Empty,
}

impl ASTNode {
    /// Get the type of this AST node for debugging and validation
    pub fn node_type(&self) -> &'static str {
        // Use Display trait for automatic type introspection
        match self {
            ASTNode::Query(_) => "Query",
            ASTNode::Expression(_) => "Expression",
            ASTNode::ControlFlow(_) => "ControlFlow",
            ASTNode::Command(_) => "Command",
            ASTNode::Utility(_) => "Utility",
            ASTNode::Empty => "Empty",
        }
    }

    /// Get the specific variant name of this AST node
    pub fn variant_name(&self) -> String {
        match self {
            ASTNode::Query(query_node) => query_node.to_string(),
            ASTNode::Expression(expr_node) => expr_node.to_string(),
            ASTNode::ControlFlow(control_node) => control_node.to_string(),
            ASTNode::Command(cmd_node) => cmd_node.to_string(),
            ASTNode::Utility(util_node) => util_node.to_string(),
            ASTNode::Empty => "Empty".to_string(),
        }
    }

    /// Check if this node represents a query operation
    pub fn is_query(&self) -> bool {
        matches!(self, ASTNode::Query(_))
    }

    /// Check if this node represents a command
    pub fn is_command(&self) -> bool {
        matches!(self, ASTNode::Command(_))
    }

    /// Check if this node represents an expression
    pub fn is_expression(&self) -> bool {
        matches!(self, ASTNode::Expression(_))
    }

    /// Check if this node represents control flow
    pub fn is_control_flow(&self) -> bool {
        matches!(self, ASTNode::ControlFlow(_))
    }

    /// Check if this node represents a utility operation
    pub fn is_utility(&self) -> bool {
        matches!(self, ASTNode::Utility(_))
    }
}

impl fmt::Display for ASTNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ASTNode::Query(query_node) => write!(f, "Query({query_node})"),
            ASTNode::Expression(expr_node) => write!(f, "Expression({expr_node})"),
            ASTNode::ControlFlow(control_node) => write!(f, "ControlFlow({control_node})"),
            ASTNode::Command(cmd_node) => write!(f, "Command({cmd_node})"),
            ASTNode::Utility(util_node) => write!(f, "Utility({util_node})"),
            ASTNode::Empty => write!(f, "Empty"),
        }
    }
}

/// AST visitor trait for traversing and transforming AST nodes
pub trait ASTVisitor {
    type Output;
    type Error;

    // Query nodes
    fn visit_select(
        &mut self,
        fields: &[ASTNode],
        from: &ASTNode,
        where_clause: &Option<Box<ASTNode>>,
        order_by: &Option<Vec<OrderByClause>>,
        into_clause: &Option<Box<ASTNode>>,
    ) -> Result<Self::Output, Self::Error>;
    fn visit_describe_table(&mut self, table_name: &str) -> Result<Self::Output, Self::Error>;
    fn visit_table(
        &mut self,
        name: &str,
        alias: &Option<String>,
    ) -> Result<Self::Output, Self::Error>;
    fn visit_join(
        &mut self,
        left: &ASTNode,
        join_type: &JoinType,
        right: &ASTNode,
        on_condition: &ASTNode,
    ) -> Result<Self::Output, Self::Error>;

    // Expression nodes
    fn visit_field(
        &mut self,
        name: &str,
        context: &Option<FieldContext>,
        alias: &Option<String>,
    ) -> Result<Self::Output, Self::Error>;
    fn visit_wildcard(&mut self) -> Result<Self::Output, Self::Error>;
    fn visit_binary_expression(
        &mut self,
        left: &ASTNode,
        operator: &str,
        right: &ASTNode,
    ) -> Result<Self::Output, Self::Error>;
    fn visit_unary_expression(
        &mut self,
        operator: &str,
        operand: &ASTNode,
    ) -> Result<Self::Output, Self::Error>;
    fn visit_literal(&mut self, value: &DSLValue) -> Result<Self::Output, Self::Error>;
    fn visit_variable(&mut self, name: &str) -> Result<Self::Output, Self::Error>;
    fn visit_function_call(
        &mut self,
        name: &str,
        arguments: &[ASTNode],
    ) -> Result<Self::Output, Self::Error>;
    fn visit_assignment(
        &mut self,
        name: &str,
        value: &ASTNode,
    ) -> Result<Self::Output, Self::Error>;

    // Control flow nodes
    fn visit_if_statement(
        &mut self,
        condition: &ASTNode,
        then_branch: &[ASTNode],
        else_branch: &Option<Vec<ASTNode>>,
    ) -> Result<Self::Output, Self::Error>;
    fn visit_loop_statement(
        &mut self,
        condition: &Option<Box<ASTNode>>,
        body: &[ASTNode],
    ) -> Result<Self::Output, Self::Error>;
    fn visit_break_statement(&mut self) -> Result<Self::Output, Self::Error>;
    fn visit_continue_statement(&mut self) -> Result<Self::Output, Self::Error>;
    fn visit_return_statement(
        &mut self,
        value: &Option<Box<ASTNode>>,
    ) -> Result<Self::Output, Self::Error>;
    fn visit_block(&mut self, statements: &[ASTNode]) -> Result<Self::Output, Self::Error>;

    // Command nodes
    fn visit_create_cluster(
        &mut self,
        name: &str,
        region: &str,
        rcu_range: &Option<(String, String)>,
        service_plan: &Option<String>,
        password: &Option<String>,
    ) -> Result<Self::Output, Self::Error>;
    fn visit_delete_cluster(&mut self, name: &str) -> Result<Self::Output, Self::Error>;
    fn visit_update_cluster(
        &mut self,
        name: &str,
        updates: &[ASTNode],
    ) -> Result<Self::Output, Self::Error>;
    fn visit_wait_for_cluster(
        &mut self,
        name: &str,
        state: &str,
        timeout: &Option<u64>,
    ) -> Result<Self::Output, Self::Error>;
    fn visit_create_backup(
        &mut self,
        cluster_name: &str,
        description: &Option<String>,
    ) -> Result<Self::Output, Self::Error>;
    fn visit_list_backups(
        &mut self,
        cluster_name: &Option<String>,
        filters: &[ASTNode],
    ) -> Result<Self::Output, Self::Error>;
    fn visit_delete_backup(
        &mut self,
        cluster_name: &str,
        backup_id: &str,
    ) -> Result<Self::Output, Self::Error>;
    fn visit_estimate_price(
        &mut self,
        region: &str,
        rcu_range: &(String, String),
        service_plan: &str,
        storage: &Option<String>,
    ) -> Result<Self::Output, Self::Error>;

    // Utility nodes
    fn visit_echo(&mut self, message: &ASTNode) -> Result<Self::Output, Self::Error>;
    fn visit_sleep(&mut self, duration: &ASTNode) -> Result<Self::Output, Self::Error>;
    fn visit_set_variable(
        &mut self,
        name: &str,
        value: &ASTNode,
    ) -> Result<Self::Output, Self::Error>;
    fn visit_get_variable(&mut self, name: &str) -> Result<Self::Output, Self::Error>;
    fn visit_set_log_level(&mut self, level: &str) -> Result<Self::Output, Self::Error>;

    // Special nodes
    fn visit_empty(&mut self) -> Result<Self::Output, Self::Error>;

    // Default method for unhandled cases (optional)
    fn visit_default(&mut self, node: &ASTNode) -> Result<Self::Output, Self::Error> {
        panic!("Unhandled AST node type: {}", node.variant_name())
    }
}

/// Default AST visitor implementation that provides basic traversal
pub struct DefaultASTVisitor;

impl DefaultASTVisitor {
    pub fn new() -> Self {
        Self
    }

    /// Visit an AST node and dispatch to appropriate visitor method
    pub fn visit<V: ASTVisitor>(
        &mut self,
        visitor: &mut V,
        node: &ASTNode,
    ) -> Result<V::Output, V::Error> {
        // First visit the current node
        let result = self.visit_node(visitor, node)?;

        // Then recursively visit all child nodes
        self.visit_children(visitor, node)?;

        Ok(result)
    }

    /// Visit just the current node without recursion
    pub fn visit_node<V: ASTVisitor>(
        &mut self,
        visitor: &mut V,
        node: &ASTNode,
    ) -> Result<V::Output, V::Error> {
        match node {
            ASTNode::Query(query_node) => match query_node {
                QueryNode::Select {
                    fields,
                    from,
                    where_clause,
                    order_by,
                    into_clause,
                } => visitor.visit_select(fields, from, where_clause, order_by, into_clause),
                QueryNode::DescribeTable { table_name } => visitor.visit_describe_table(table_name),
                QueryNode::Table { name, alias } => visitor.visit_table(name, alias),
                QueryNode::Join {
                    left,
                    join_type,
                    right,
                    on_condition,
                } => visitor.visit_join(left, join_type, right, on_condition),
            },
            ASTNode::Expression(expr_node) => match expr_node {
                ExpressionNode::Field {
                    name,
                    context,
                    alias,
                } => visitor.visit_field(name, context, alias),
                ExpressionNode::Wildcard => visitor.visit_wildcard(),
                ExpressionNode::BinaryExpression {
                    left,
                    operator,
                    right,
                } => visitor.visit_binary_expression(left, operator, right),
                ExpressionNode::UnaryExpression { operator, operand } => {
                    visitor.visit_unary_expression(operator, operand)
                }
                ExpressionNode::Literal { value } => visitor.visit_literal(value),
                ExpressionNode::Variable { name } => visitor.visit_variable(name),
                ExpressionNode::FunctionCall { name, arguments } => {
                    visitor.visit_function_call(name, arguments)
                }
                ExpressionNode::Assignment { name, value } => visitor.visit_assignment(name, value),
            },
            ASTNode::ControlFlow(control_node) => match control_node {
                ControlFlowNode::IfStatement {
                    condition,
                    then_branch,
                    else_branch,
                } => visitor.visit_if_statement(condition, then_branch, else_branch),
                ControlFlowNode::LoopStatement { condition, body } => {
                    visitor.visit_loop_statement(condition, body)
                }
                ControlFlowNode::BreakStatement => visitor.visit_break_statement(),
                ControlFlowNode::ContinueStatement => visitor.visit_continue_statement(),
                ControlFlowNode::ReturnStatement { value } => visitor.visit_return_statement(value),
                ControlFlowNode::Block { statements } => visitor.visit_block(statements),
            },
            ASTNode::Command(cmd_node) => match cmd_node {
                CommandNode::CreateCluster {
                    name,
                    region,
                    rcu_range,
                    service_plan,
                    password,
                } => visitor.visit_create_cluster(name, region, rcu_range, service_plan, password),
                CommandNode::DeleteCluster { name } => visitor.visit_delete_cluster(name),
                CommandNode::UpdateCluster { name, updates } => {
                    visitor.visit_update_cluster(name, updates)
                }
                CommandNode::WaitForCluster {
                    name,
                    state,
                    timeout,
                } => visitor.visit_wait_for_cluster(name, state, timeout),
                CommandNode::CreateBackup {
                    cluster_name,
                    description,
                } => visitor.visit_create_backup(cluster_name, description),
                CommandNode::ListBackups {
                    cluster_name,
                    filters,
                } => visitor.visit_list_backups(cluster_name, filters),
                CommandNode::DeleteBackup {
                    cluster_name,
                    backup_id,
                } => visitor.visit_delete_backup(cluster_name, backup_id),
                CommandNode::EstimatePrice {
                    region,
                    rcu_range,
                    service_plan,
                    storage,
                } => visitor.visit_estimate_price(region, rcu_range, service_plan, storage),
            },
            ASTNode::Utility(util_node) => match util_node {
                UtilityNode::Echo { message } => visitor.visit_echo(message),
                UtilityNode::Sleep { duration } => visitor.visit_sleep(duration),
                UtilityNode::SetVariable { name, value } => visitor.visit_set_variable(name, value),
                UtilityNode::GetVariable { name } => visitor.visit_get_variable(name),
                UtilityNode::SetLogLevel { level } => visitor.visit_set_log_level(level),
            },
            ASTNode::Empty => visitor.visit_empty(),
        }
    }

    /// Recursively visit all child nodes
    pub fn visit_children<V: ASTVisitor>(
        &mut self,
        visitor: &mut V,
        node: &ASTNode,
    ) -> Result<(), V::Error> {
        match node {
            ASTNode::Query(query_node) => match query_node {
                QueryNode::Select {
                    fields,
                    from,
                    where_clause,
                    order_by,
                    into_clause,
                } => {
                    // Visit all field nodes
                    for field in fields {
                        self.visit(visitor, field)?;
                    }
                    // Visit from clause
                    self.visit(visitor, from)?;
                    // Visit where clause if present
                    if let Some(where_node) = where_clause {
                        self.visit(visitor, where_node)?;
                    }
                    // Visit order by clauses if present
                    if let Some(order_clauses) = order_by {
                        for order_clause in order_clauses {
                            self.visit(visitor, &order_clause.field)?;
                        }
                    }
                    // Visit into clause if present
                    if let Some(into_node) = into_clause {
                        self.visit(visitor, into_node)?;
                    }
                }
                QueryNode::DescribeTable { .. } => {
                    // No children to visit
                }
                QueryNode::Table { .. } => {
                    // No children to visit
                }
                QueryNode::Join {
                    left,
                    right,
                    on_condition,
                    ..
                } => {
                    self.visit(visitor, left)?;
                    self.visit(visitor, right)?;
                    self.visit(visitor, on_condition)?;
                }
            },
            ASTNode::Expression(expr_node) => match expr_node {
                ExpressionNode::Field { .. } => {
                    // No children to visit
                }
                ExpressionNode::Wildcard => {
                    // No children to visit
                }
                ExpressionNode::BinaryExpression { left, right, .. } => {
                    self.visit(visitor, left)?;
                    self.visit(visitor, right)?;
                }
                ExpressionNode::UnaryExpression { operand, .. } => {
                    self.visit(visitor, operand)?;
                }
                ExpressionNode::Literal { .. } => {
                    // No children to visit
                }
                ExpressionNode::Variable { .. } => {
                    // No children to visit
                }
                ExpressionNode::FunctionCall { arguments, .. } => {
                    for arg in arguments {
                        self.visit(visitor, arg)?;
                    }
                }
                ExpressionNode::Assignment { value, .. } => {
                    self.visit(visitor, value)?;
                }
            },
            ASTNode::ControlFlow(control_node) => match control_node {
                ControlFlowNode::IfStatement {
                    condition,
                    then_branch,
                    else_branch,
                } => {
                    self.visit(visitor, condition)?;
                    for stmt in then_branch {
                        self.visit(visitor, stmt)?;
                    }
                    if let Some(else_branch) = else_branch {
                        for stmt in else_branch {
                            self.visit(visitor, stmt)?;
                        }
                    }
                }
                ControlFlowNode::LoopStatement { condition, body } => {
                    if let Some(condition_node) = condition {
                        self.visit(visitor, condition_node)?;
                    }
                    for stmt in body {
                        self.visit(visitor, stmt)?;
                    }
                }
                ControlFlowNode::BreakStatement | ControlFlowNode::ContinueStatement => {
                    // No children to visit
                }
                ControlFlowNode::ReturnStatement { value } => {
                    if let Some(value_node) = value {
                        self.visit(visitor, value_node)?;
                    }
                }
                ControlFlowNode::Block { statements } => {
                    for stmt in statements {
                        self.visit(visitor, stmt)?;
                    }
                }
            },
            ASTNode::Command(cmd_node) => match cmd_node {
                CommandNode::CreateCluster { .. } => {
                    // No children to visit
                }
                CommandNode::DeleteCluster { .. } => {
                    // No children to visit
                }
                CommandNode::UpdateCluster { updates, .. } => {
                    for update in updates {
                        self.visit(visitor, update)?;
                    }
                }
                CommandNode::WaitForCluster { .. } => {
                    // No children to visit
                }
                CommandNode::CreateBackup { .. } => {
                    // No children to visit
                }
                CommandNode::ListBackups { filters, .. } => {
                    for filter in filters {
                        self.visit(visitor, filter)?;
                    }
                }
                CommandNode::DeleteBackup { .. } => {
                    // No children to visit
                }
                CommandNode::EstimatePrice { .. } => {
                    // No children to visit
                }
            },
            ASTNode::Utility(util_node) => match util_node {
                UtilityNode::Echo { message } => {
                    self.visit(visitor, message)?;
                }
                UtilityNode::Sleep { duration } => {
                    self.visit(visitor, duration)?;
                }
                UtilityNode::SetVariable { value, .. } => {
                    self.visit(visitor, value)?;
                }
                UtilityNode::GetVariable { .. } => {
                    // No children to visit
                }
                UtilityNode::SetLogLevel { .. } => {
                    // No children to visit
                }
            },
            ASTNode::Empty => {
                // No children to visit
            }
        }
        Ok(())
    }
}

impl Default for DefaultASTVisitor {
    fn default() -> Self {
        Self::new()
    }
}

/// AST transformer trait for converting AST nodes
pub trait ASTTransformer {
    fn transform(&mut self, node: &ASTNode) -> Result<ASTNode, String>;
}

/// Example visitor that counts different types of AST nodes
pub struct ASTNodeCounter {
    pub select_count: usize,
    pub field_count: usize,
    pub literal_count: usize,
    pub command_count: usize,
}

impl ASTNodeCounter {
    pub fn new() -> Self {
        Self {
            select_count: 0,
            field_count: 0,
            literal_count: 0,
            command_count: 0,
        }
    }

    pub fn print_summary(&self) {
        println!("AST Node Summary:");
        println!("  Select statements: {}", self.select_count);
        println!("  Field references: {}", self.field_count);
        println!("  Literals: {}", self.literal_count);
        println!("  Commands: {}", self.command_count);
    }
}

impl Default for ASTNodeCounter {
    fn default() -> Self {
        Self::new()
    }
}

impl ASTVisitor for ASTNodeCounter {
    type Output = ();
    type Error = String;

    // Query nodes
    fn visit_select(
        &mut self,
        _fields: &[ASTNode],
        _from: &ASTNode,
        _where_clause: &Option<Box<ASTNode>>,
        _order_by: &Option<Vec<OrderByClause>>,
        _into_clause: &Option<Box<ASTNode>>,
    ) -> Result<(), String> {
        self.select_count += 1;
        Ok(())
    }
    fn visit_describe_table(&mut self, _table_name: &str) -> Result<(), String> {
        Ok(())
    }
    fn visit_table(&mut self, _name: &str, _alias: &Option<String>) -> Result<(), String> {
        Ok(())
    }
    fn visit_join(
        &mut self,
        _left: &ASTNode,
        _join_type: &JoinType,
        _right: &ASTNode,
        _on_condition: &ASTNode,
    ) -> Result<(), String> {
        Ok(())
    }

    // Expression nodes
    fn visit_field(
        &mut self,
        _name: &str,
        _context: &Option<FieldContext>,
        _alias: &Option<String>,
    ) -> Result<(), String> {
        self.field_count += 1;
        Ok(())
    }
    fn visit_wildcard(&mut self) -> Result<(), String> {
        Ok(())
    }
    fn visit_binary_expression(
        &mut self,
        _left: &ASTNode,
        _operator: &str,
        _right: &ASTNode,
    ) -> Result<(), String> {
        Ok(())
    }
    fn visit_unary_expression(
        &mut self,
        _operator: &str,
        _operand: &ASTNode,
    ) -> Result<(), String> {
        Ok(())
    }
    fn visit_literal(&mut self, _value: &DSLValue) -> Result<(), String> {
        self.literal_count += 1;
        Ok(())
    }
    fn visit_variable(&mut self, _name: &str) -> Result<(), String> {
        Ok(())
    }
    fn visit_function_call(&mut self, _name: &str, _arguments: &[ASTNode]) -> Result<(), String> {
        Ok(())
    }
    fn visit_assignment(&mut self, _name: &str, _value: &ASTNode) -> Result<(), String> {
        Ok(())
    }

    // Control flow nodes
    fn visit_if_statement(
        &mut self,
        _condition: &ASTNode,
        _then_branch: &[ASTNode],
        _else_branch: &Option<Vec<ASTNode>>,
    ) -> Result<(), String> {
        Ok(())
    }
    fn visit_loop_statement(
        &mut self,
        _condition: &Option<Box<ASTNode>>,
        _body: &[ASTNode],
    ) -> Result<(), String> {
        Ok(())
    }
    fn visit_break_statement(&mut self) -> Result<(), String> {
        Ok(())
    }
    fn visit_continue_statement(&mut self) -> Result<(), String> {
        Ok(())
    }
    fn visit_return_statement(&mut self, _value: &Option<Box<ASTNode>>) -> Result<(), String> {
        Ok(())
    }
    fn visit_block(&mut self, _statements: &[ASTNode]) -> Result<(), String> {
        Ok(())
    }

    // Command nodes
    fn visit_create_cluster(
        &mut self,
        _name: &str,
        _region: &str,
        _rcu_range: &Option<(String, String)>,
        _service_plan: &Option<String>,
        _password: &Option<String>,
    ) -> Result<(), String> {
        self.command_count += 1;
        Ok(())
    }
    fn visit_delete_cluster(&mut self, _name: &str) -> Result<(), String> {
        self.command_count += 1;
        Ok(())
    }
    fn visit_update_cluster(&mut self, _name: &str, _updates: &[ASTNode]) -> Result<(), String> {
        self.command_count += 1;
        Ok(())
    }
    fn visit_wait_for_cluster(
        &mut self,
        _name: &str,
        _state: &str,
        _timeout: &Option<u64>,
    ) -> Result<(), String> {
        self.command_count += 1;
        Ok(())
    }
    fn visit_create_backup(
        &mut self,
        _cluster_name: &str,
        _description: &Option<String>,
    ) -> Result<(), String> {
        self.command_count += 1;
        Ok(())
    }
    fn visit_list_backups(
        &mut self,
        _cluster_name: &Option<String>,
        _filters: &[ASTNode],
    ) -> Result<(), String> {
        self.command_count += 1;
        Ok(())
    }
    fn visit_delete_backup(&mut self, _cluster_name: &str, _backup_id: &str) -> Result<(), String> {
        self.command_count += 1;
        Ok(())
    }
    fn visit_estimate_price(
        &mut self,
        _region: &str,
        _rcu_range: &(String, String),
        _service_plan: &str,
        _storage: &Option<String>,
    ) -> Result<(), String> {
        self.command_count += 1;
        Ok(())
    }

    // Utility nodes
    fn visit_echo(&mut self, _message: &ASTNode) -> Result<(), String> {
        Ok(())
    }
    fn visit_sleep(&mut self, _duration: &ASTNode) -> Result<(), String> {
        Ok(())
    }
    fn visit_set_variable(&mut self, _name: &str, _value: &ASTNode) -> Result<(), String> {
        Ok(())
    }
    fn visit_get_variable(&mut self, _name: &str) -> Result<(), String> {
        Ok(())
    }
    fn visit_set_log_level(&mut self, _level: &str) -> Result<(), String> {
        Ok(())
    }

    // Special nodes
    fn visit_empty(&mut self) -> Result<(), String> {
        Ok(())
    }
}

/// AST validator trait for semantic validation
pub trait ASTValidator {
    type Error;

    fn validate(&mut self, node: &ASTNode) -> Result<(), Self::Error>;
}

/// AST printer for debugging and pretty-printing
pub struct ASTPrinter {
    indent_level: usize,
}

impl ASTPrinter {
    pub fn new() -> Self {
        Self { indent_level: 0 }
    }

    pub fn print(&mut self, node: &ASTNode) -> String {
        let mut result = String::new();
        self.print_node(node, &mut result);
        result
    }

    fn print_node(&mut self, node: &ASTNode, result: &mut String) {
        let indent = "  ".repeat(self.indent_level);

        match node {
            ASTNode::Query(query_node) => {
                result.push_str(&format!("{indent}Query\n"));
                self.indent_level += 1;

                match query_node {
                    QueryNode::Select {
                        fields,
                        from,
                        where_clause,
                        order_by,
                        into_clause,
                    } => {
                        result.push_str(&format!("{indent}Select\n"));
                        self.indent_level += 1;

                        result.push_str(&format!("{indent}fields:\n"));
                        self.indent_level += 1;
                        for field in fields {
                            self.print_node(field, result);
                        }
                        self.indent_level -= 1;

                        result.push_str(&format!("{indent}from:\n"));
                        self.indent_level += 1;
                        self.print_node(from, result);
                        self.indent_level -= 1;

                        if let Some(where_expr) = where_clause {
                            result.push_str(&format!("{indent}where:\n"));
                            self.indent_level += 1;
                            self.print_node(where_expr, result);
                            self.indent_level -= 1;
                        }

                        if let Some(order_clauses) = order_by {
                            result.push_str(&format!("{indent}order_by:\n"));
                            self.indent_level += 1;
                            for order_clause in order_clauses {
                                result.push_str(&format!(
                                    "{}field: {} {}\n",
                                    "  ".repeat(self.indent_level),
                                    order_clause.field.variant_name(),
                                    order_clause.direction
                                ));
                                self.print_node(&order_clause.field, result);
                            }
                            self.indent_level -= 1;
                        }

                        if let Some(into_expr) = into_clause {
                            result.push_str(&format!("{indent}into:\n"));
                            self.indent_level += 1;
                            self.print_node(into_expr, result);
                            self.indent_level -= 1;
                        }
                    }
                    QueryNode::DescribeTable { table_name } => {
                        result.push_str(&format!("{indent}DescribeTable({table_name})\n"));
                    }
                    QueryNode::Table { name, alias } => {
                        if let Some(alias_name) = alias {
                            result.push_str(&format!("{indent}Table({name} AS {alias_name})\n"));
                        } else {
                            result.push_str(&format!("{indent}Table({name})\n"));
                        }
                    }
                    QueryNode::Join {
                        left,
                        join_type,
                        right,
                        on_condition,
                    } => {
                        result.push_str(&format!("{}Join({})\n", indent, join_type.to_string()));
                        self.indent_level += 1;

                        result.push_str(&format!("{indent}left:\n"));
                        self.indent_level += 1;
                        self.print_node(left, result);
                        self.indent_level -= 1;

                        result.push_str(&format!("{indent}right:\n"));
                        self.indent_level += 1;
                        self.print_node(right, result);
                        self.indent_level -= 1;

                        result.push_str(&format!("{indent}on:\n"));
                        self.indent_level += 1;
                        self.print_node(on_condition, result);
                        self.indent_level -= 1;
                    }
                }
                self.indent_level -= 1;
            }
            ASTNode::Expression(expr_node) => {
                result.push_str(&format!("{indent}Expression\n"));
                self.indent_level += 1;

                match expr_node {
                    ExpressionNode::Field {
                        name,
                        context,
                        alias,
                    } => {
                        let context_str = context
                            .as_ref()
                            .map(|c| format!("{c}."))
                            .unwrap_or_default();
                        let alias_str = alias
                            .as_ref()
                            .map(|a| format!(" AS {a}"))
                            .unwrap_or_default();
                        result
                            .push_str(&format!("{indent}Field({context_str}{name}{alias_str})\n"));
                    }
                    ExpressionNode::Wildcard => {
                        result.push_str(&format!("{indent}Wildcard(*)\n"));
                    }
                    ExpressionNode::BinaryExpression {
                        left,
                        operator,
                        right,
                    } => {
                        result.push_str(&format!("{indent}BinaryExpression({operator})\n"));
                        self.indent_level += 1;
                        self.print_node(left, result);
                        self.print_node(right, result);
                        self.indent_level -= 1;
                    }
                    ExpressionNode::UnaryExpression { operator, operand } => {
                        result.push_str(&format!("{indent}UnaryExpression({operator})\n"));
                        self.indent_level += 1;
                        self.print_node(operand, result);
                        self.indent_level -= 1;
                    }
                    ExpressionNode::Literal { value } => {
                        result.push_str(&format!("{indent}Literal({value:?})\n"));
                    }
                    ExpressionNode::Variable { name } => {
                        result.push_str(&format!("{indent}Variable({name})\n"));
                    }
                    ExpressionNode::FunctionCall { name, arguments } => {
                        result.push_str(&format!("{indent}FunctionCall({name})\n"));
                        self.indent_level += 1;
                        result.push_str(&format!("{indent}arguments:\n"));
                        self.indent_level += 1;
                        for arg in arguments {
                            self.print_node(arg, result);
                        }
                        self.indent_level -= 2;
                    }
                    ExpressionNode::Assignment { name, value } => {
                        result.push_str(&format!("{indent}Assignment({name})\n"));
                        self.indent_level += 1;
                        self.print_node(value, result);
                        self.indent_level -= 1;
                    }
                }
                self.indent_level -= 1;
            }
            ASTNode::ControlFlow(control_node) => {
                result.push_str(&format!("{indent}ControlFlow\n"));
                self.indent_level += 1;

                match control_node {
                    ControlFlowNode::IfStatement {
                        condition,
                        then_branch,
                        else_branch,
                    } => {
                        result.push_str(&format!("{indent}IfStatement\n"));
                        self.indent_level += 1;
                        self.print_node(condition, result);
                        self.indent_level -= 1;
                        result.push_str(&format!("{indent}then:\n"));
                        self.indent_level += 1;
                        for stmt in then_branch {
                            self.print_node(stmt, result);
                        }
                        self.indent_level -= 1;
                        if let Some(else_branch) = else_branch {
                            result.push_str(&format!("{indent}else:\n"));
                            self.indent_level += 1;
                            for stmt in else_branch {
                                self.print_node(stmt, result);
                            }
                            self.indent_level -= 1;
                        }
                    }
                    ControlFlowNode::LoopStatement { condition, body } => {
                        result.push_str(&format!("{indent}LoopStatement\n"));
                        self.indent_level += 1;
                        if let Some(cond) = condition {
                            result.push_str(&format!("{indent}condition:\n"));
                            self.indent_level += 1;
                            self.print_node(cond, result);
                            self.indent_level -= 1;
                        }
                        result.push_str(&format!("{indent}body:\n"));
                        self.indent_level += 1;
                        for stmt in body {
                            self.print_node(stmt, result);
                        }
                        self.indent_level -= 1;
                    }
                    ControlFlowNode::BreakStatement => {
                        result.push_str(&format!("{indent}BreakStatement\n"));
                    }
                    ControlFlowNode::ContinueStatement => {
                        result.push_str(&format!("{indent}ContinueStatement\n"));
                    }
                    ControlFlowNode::ReturnStatement { value } => {
                        result.push_str(&format!("{indent}ReturnStatement\n"));
                        self.indent_level += 1;
                        if let Some(val) = value {
                            self.print_node(val, result);
                        }
                        self.indent_level -= 1;
                    }
                    ControlFlowNode::Block { statements } => {
                        result.push_str(&format!("{indent}Block\n"));
                        self.indent_level += 1;
                        for stmt in statements {
                            self.print_node(stmt, result);
                        }
                        self.indent_level -= 1;
                    }
                }
                self.indent_level -= 1;
            }
            ASTNode::Command(cmd_node) => {
                result.push_str(&format!("{indent}Command\n"));
                self.indent_level += 1;

                match cmd_node {
                    CommandNode::CreateCluster {
                        name,
                        region,
                        rcu_range,
                        service_plan,
                        password,
                    } => {
                        result.push_str(&format!("{indent}CreateCluster({name}, {region})\n"));
                        if let Some((start, end)) = rcu_range {
                            result.push_str(&format!("{indent}rcu_range: {start}-{end}\n"));
                        }
                        if let Some(plan) = service_plan {
                            result.push_str(&format!("{indent}service_plan: {plan}\n"));
                        }
                        if let Some(pass) = password {
                            result.push_str(&format!("{indent}password: {pass}\n"));
                        }
                    }
                    CommandNode::DeleteCluster { name } => {
                        result.push_str(&format!("{indent}DeleteCluster({name})\n"));
                    }
                    CommandNode::UpdateCluster { name, updates } => {
                        result.push_str(&format!("{indent}UpdateCluster({name})\n"));
                        self.indent_level += 1;
                        result.push_str(&format!("{indent}updates:\n"));
                        self.indent_level += 1;
                        for update in updates {
                            self.print_node(update, result);
                        }
                        self.indent_level -= 2;
                    }
                    CommandNode::WaitForCluster {
                        name,
                        state,
                        timeout,
                    } => {
                        result.push_str(&format!("{indent}WaitForCluster({name}, {state})\n"));
                        if let Some(t) = timeout {
                            result.push_str(&format!("{indent}timeout: {t}\n"));
                        }
                    }
                    CommandNode::CreateBackup {
                        cluster_name,
                        description,
                    } => {
                        result.push_str(&format!("{indent}CreateBackup({cluster_name})\n"));
                        if let Some(desc) = description {
                            result.push_str(&format!("{indent}description: {desc}\n"));
                        }
                    }
                    CommandNode::ListBackups {
                        cluster_name,
                        filters,
                    } => {
                        result.push_str(&format!("{indent}ListBackups\n"));
                        self.indent_level += 1;

                        if let Some(name) = cluster_name {
                            result.push_str(&format!("{indent}cluster: {name}\n"));
                        }

                        if !filters.is_empty() {
                            result.push_str(&format!("{indent}filters:\n"));
                            self.indent_level += 1;
                            for filter in filters {
                                self.print_node(filter, result);
                            }
                            self.indent_level -= 1;
                        }

                        self.indent_level -= 1;
                    }
                    CommandNode::DeleteBackup {
                        cluster_name,
                        backup_id,
                    } => {
                        result.push_str(&format!(
                            "{indent}DeleteBackup({cluster_name}, {backup_id})\n"
                        ));
                    }
                    CommandNode::EstimatePrice {
                        region,
                        rcu_range,
                        service_plan: _,
                        storage,
                    } => {
                        result
                            .push_str(&format!("{indent}EstimatePrice({region}, {rcu_range:?})\n"));
                        if let Some(s) = storage {
                            result.push_str(&format!("{indent}storage: {s}\n"));
                        }
                    }
                }
                self.indent_level -= 1;
            }
            ASTNode::Utility(util_node) => {
                result.push_str(&format!("{indent}Utility\n"));
                self.indent_level += 1;

                match util_node {
                    UtilityNode::Echo { message } => {
                        result.push_str(&format!("{indent}Echo\n"));
                        self.indent_level += 1;
                        self.print_node(message, result);
                        self.indent_level -= 1;
                    }
                    UtilityNode::Sleep { duration } => {
                        result.push_str(&format!("{indent}Sleep\n"));
                        self.indent_level += 1;
                        self.print_node(duration, result);
                        self.indent_level -= 1;
                    }
                    UtilityNode::SetVariable { name, value } => {
                        result.push_str(&format!("{indent}SetVariable({name})\n"));
                        self.indent_level += 1;
                        self.print_node(value, result);
                        self.indent_level -= 1;
                    }
                    UtilityNode::GetVariable { name } => {
                        result.push_str(&format!("{indent}GetVariable({name})\n"));
                    }
                    UtilityNode::SetLogLevel { level } => {
                        result.push_str(&format!("{indent}SetLogLevel({level})\n"));
                    }
                }
                self.indent_level -= 1;
            }
            ASTNode::Empty => {
                result.push_str(&format!("{indent}Empty\n"));
            }
        }
    }
}

impl Default for ASTPrinter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dsl::syntax::DSLValue;

    #[test]
    fn test_ast_node_type() {
        let select = ASTNode::Query(QueryNode::Select {
            fields: vec![],
            from: Box::new(ASTNode::Query(QueryNode::Table {
                name: "test".to_string(),
                alias: None,
            })),
            where_clause: None,
            order_by: None,
            into_clause: None,
        });
        assert_eq!(select.node_type(), "Query");
        assert_eq!(select.variant_name(), "Select");
        assert!(select.is_query());
        assert!(!select.is_command());
        assert!(!select.is_expression());
    }

    #[test]
    fn test_ast_printer() {
        let ast = ASTNode::Query(QueryNode::Select {
            fields: vec![ASTNode::Expression(ExpressionNode::Wildcard)],
            from: Box::new(ASTNode::Query(QueryNode::Table {
                name: "BACKUPS".to_string(),
                alias: None,
            })),
            where_clause: Some(Box::new(ASTNode::Expression(
                ExpressionNode::BinaryExpression {
                    left: Box::new(ASTNode::Expression(ExpressionNode::Field {
                        name: "displayName".to_string(),
                        context: Some(FieldContext::Cluster),
                        alias: None,
                    })),
                    operator: "=".to_string(),
                    right: Box::new(ASTNode::Expression(ExpressionNode::Literal {
                        value: DSLValue::String(".*".to_string()),
                    })),
                },
            ))),
            order_by: None,
            into_clause: None,
        });

        let mut printer = ASTPrinter::new();
        let result = printer.print(&ast);

        assert!(result.contains("Select"));
        assert!(result.contains("Wildcard(*)"));
        assert!(result.contains("Table(BACKUPS)"));
        assert!(result.contains("BinaryExpression(=)"));
        assert!(result.contains("Literal(String(\".*\"))"));
    }

    #[test]
    fn test_display_trait() {
        let select = ASTNode::Query(QueryNode::Select {
            fields: vec![],
            from: Box::new(ASTNode::Query(QueryNode::Table {
                name: "test".to_string(),
                alias: None,
            })),
            where_clause: None,
            order_by: None,
            into_clause: None,
        });

        assert_eq!(select.to_string(), "Query(Select)");

        let field = ASTNode::Expression(ExpressionNode::Field {
            name: "test_field".to_string(),
            context: None,
            alias: None,
        });

        assert_eq!(field.to_string(), "Expression(Field)");

        let empty = ASTNode::Empty;
        assert_eq!(empty.to_string(), "Empty");
    }

    #[test]
    fn test_field_context() {
        // Test FieldContext enum functionality
        let cluster_context = FieldContext::Cluster;
        let backups_context = FieldContext::Backups;

        assert_eq!(cluster_context.to_string(), "CLUSTER");
        assert_eq!(backups_context.to_string(), "BACKUPS");

        // Test Field node with context
        let field_with_context = ASTNode::Expression(ExpressionNode::Field {
            name: "displayName".to_string(),
            context: Some(FieldContext::Cluster),
            alias: None,
        });

        assert_eq!(field_with_context.to_string(), "Expression(Field)");

        // Test Field node without context
        let field_without_context = ASTNode::Expression(ExpressionNode::Field {
            name: "displayName".to_string(),
            context: None,
            alias: None,
        });

        assert_eq!(field_without_context.to_string(), "Expression(Field)");
    }

    #[test]
    fn test_comprehensive_visitor() {
        // Create a complex AST with multiple node types
        let ast = ASTNode::Query(QueryNode::Select {
            fields: vec![
                ASTNode::Expression(ExpressionNode::Field {
                    name: "displayName".to_string(),
                    context: Some(FieldContext::Cluster),
                    alias: None,
                }),
                ASTNode::Expression(ExpressionNode::Field {
                    name: "state".to_string(),
                    context: None,
                    alias: None,
                }),
            ],
            from: Box::new(ASTNode::Query(QueryNode::Table {
                name: "BACKUPS".to_string(),
                alias: None,
            })),
            where_clause: Some(Box::new(ASTNode::Expression(
                ExpressionNode::BinaryExpression {
                    left: Box::new(ASTNode::Expression(ExpressionNode::Field {
                        name: "displayName".to_string(),
                        context: None,
                        alias: None,
                    })),
                    operator: "=".to_string(),
                    right: Box::new(ASTNode::Expression(ExpressionNode::Literal {
                        value: DSLValue::String(".*".to_string()),
                    })),
                },
            ))),
            order_by: None,
            into_clause: None,
        });

        // Create visitor and traverse AST
        let mut counter = ASTNodeCounter::new();
        let mut default_visitor = DefaultASTVisitor::new();

        let result = default_visitor.visit(&mut counter, &ast);
        assert!(result.is_ok());

        // Verify counts
        assert_eq!(counter.select_count, 1);
        assert_eq!(counter.field_count, 3); // 2 in fields + 1 in where clause
        assert_eq!(counter.literal_count, 1);
        assert_eq!(counter.command_count, 0);

        // Test with a command
        let command_ast = ASTNode::Command(CommandNode::CreateCluster {
            name: "test-cluster".to_string(),
            region: "aws-us-west-1".to_string(),
            rcu_range: None,
            service_plan: None,
            password: None,
        });

        let result = default_visitor.visit(&mut counter, &command_ast);
        assert!(result.is_ok());
        assert_eq!(counter.command_count, 1);
    }
}
