use std::fmt;

/// Token types for the DSL lexer
#[derive(Debug, Clone, PartialEq)]
pub enum DSLTokenType {
    // Keywords
    Create,
    Delete,
    List,
    Get,
    Update,
    Wait,
    For,
    To,
    Be,
    In,
    With,
    Using,
    From,
    Where,
    And,
    Or,
    Not,
    If,
    Then,
    Else,
    End,
    Loop,
    While,
    Do,
    Break,
    Continue,
    Return,
    Set,
    Variable,
    LogLevel,
    Cluster,
    Clusters,
    Backup,
    Backups,
    Region,
    Regions,
    Price,
    Pricing,
    RCU,
    Storage,
    Plan,
    Service,
    Active,
    Creating,
    Deleting,
    Failed,
    Paused,
    Resuming,
    Suspending,
    Suspended,
    Starter,
    Dedicated,
    Enterprise,
    AWS,
    GCP,
    Azure,
    Seconds,
    Minutes,
    Hours,
    Days,
    True,
    False,
    Null,

    // SQL-like keywords
    Select,
    Asterisk,

    // Literals
    String(String),
    Number(f64),
    Identifier(String),
    VariableRef(String),

    // Operators
    Equals,
    NotEquals,
    LessThan,
    LessThanOrEqual,
    GreaterThan,
    GreaterThanOrEqual,
    Plus,
    Minus,
    Multiply,
    Divide,
    Modulo,
    Assign,
    PlusAssign,
    MinusAssign,
    MultiplyAssign,
    DivideAssign,

    // Delimiters
    LeftParen,
    RightParen,
    LeftBrace,
    RightBrace,
    LeftBracket,
    RightBracket,
    Comma,
    Semicolon,
    Colon,
    Dot,
    Arrow,
    Range,

    // Special
    Echo,
    Sleep,
    EOF,
    Error(String),
}

impl fmt::Display for DSLTokenType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DSLTokenType::Create => write!(f, "CREATE"),
            DSLTokenType::Delete => write!(f, "DELETE"),
            DSLTokenType::List => write!(f, "LIST"),
            DSLTokenType::Get => write!(f, "GET"),
            DSLTokenType::Update => write!(f, "UPDATE"),
            DSLTokenType::Wait => write!(f, "WAIT"),
            DSLTokenType::For => write!(f, "FOR"),
            DSLTokenType::To => write!(f, "TO"),
            DSLTokenType::Be => write!(f, "BE"),
            DSLTokenType::In => write!(f, "IN"),
            DSLTokenType::With => write!(f, "WITH"),
            DSLTokenType::Using => write!(f, "USING"),
            DSLTokenType::From => write!(f, "FROM"),
            DSLTokenType::Where => write!(f, "WHERE"),
            DSLTokenType::And => write!(f, "AND"),
            DSLTokenType::Or => write!(f, "OR"),
            DSLTokenType::Not => write!(f, "NOT"),
            DSLTokenType::If => write!(f, "IF"),
            DSLTokenType::Then => write!(f, "THEN"),
            DSLTokenType::Else => write!(f, "ELSE"),
            DSLTokenType::End => write!(f, "END"),
            DSLTokenType::Loop => write!(f, "LOOP"),
            DSLTokenType::While => write!(f, "WHILE"),
            DSLTokenType::Do => write!(f, "DO"),
            DSLTokenType::Break => write!(f, "BREAK"),
            DSLTokenType::Continue => write!(f, "CONTINUE"),
            DSLTokenType::Return => write!(f, "RETURN"),
            DSLTokenType::Set => write!(f, "SET"),
            DSLTokenType::Variable => write!(f, "VARIABLE"),
            DSLTokenType::LogLevel => write!(f, "LOG-LEVEL"),
            DSLTokenType::Cluster => write!(f, "CLUSTER"),
            DSLTokenType::Clusters => write!(f, "CLUSTERS"),
            DSLTokenType::Backup => write!(f, "BACKUP"),
            DSLTokenType::Backups => write!(f, "BACKUPS"),
            DSLTokenType::Region => write!(f, "REGION"),
            DSLTokenType::Regions => write!(f, "REGIONS"),
            DSLTokenType::Price => write!(f, "PRICE"),
            DSLTokenType::Pricing => write!(f, "PRICING"),
            DSLTokenType::RCU => write!(f, "RCU"),
            DSLTokenType::Storage => write!(f, "STORAGE"),
            DSLTokenType::Plan => write!(f, "PLAN"),
            DSLTokenType::Service => write!(f, "SERVICE"),
            DSLTokenType::Active => write!(f, "ACTIVE"),
            DSLTokenType::Creating => write!(f, "CREATING"),
            DSLTokenType::Deleting => write!(f, "DELETING"),
            DSLTokenType::Failed => write!(f, "FAILED"),
            DSLTokenType::Paused => write!(f, "PAUSED"),
            DSLTokenType::Resuming => write!(f, "RESUMING"),
            DSLTokenType::Suspending => write!(f, "SUSPENDING"),
            DSLTokenType::Suspended => write!(f, "SUSPENDED"),
            DSLTokenType::Starter => write!(f, "STARTER"),
            DSLTokenType::Dedicated => write!(f, "DEDICATED"),
            DSLTokenType::Enterprise => write!(f, "ENTERPRISE"),
            DSLTokenType::AWS => write!(f, "AWS"),
            DSLTokenType::GCP => write!(f, "GCP"),
            DSLTokenType::Azure => write!(f, "AZURE"),
            DSLTokenType::Seconds => write!(f, "SECONDS"),
            DSLTokenType::Minutes => write!(f, "MINUTES"),
            DSLTokenType::Hours => write!(f, "HOURS"),
            DSLTokenType::Days => write!(f, "DAYS"),
            DSLTokenType::True => write!(f, "TRUE"),
            DSLTokenType::False => write!(f, "FALSE"),
            DSLTokenType::Null => write!(f, "NULL"),
            DSLTokenType::Select => write!(f, "SELECT"),
            DSLTokenType::Asterisk => write!(f, "*"),
            DSLTokenType::String(s) => write!(f, "\"{s}\""),
            DSLTokenType::Number(n) => write!(f, "{n}"),
            DSLTokenType::Identifier(id) => write!(f, "{id}"),
            DSLTokenType::VariableRef(var) => write!(f, "${var}"),
            DSLTokenType::Equals => write!(f, "=="),
            DSLTokenType::NotEquals => write!(f, "!="),
            DSLTokenType::LessThan => write!(f, "<"),
            DSLTokenType::LessThanOrEqual => write!(f, "<="),
            DSLTokenType::GreaterThan => write!(f, ">"),
            DSLTokenType::GreaterThanOrEqual => write!(f, ">="),
            DSLTokenType::Plus => write!(f, "+"),
            DSLTokenType::Minus => write!(f, "-"),
            DSLTokenType::Multiply => write!(f, "*"),
            DSLTokenType::Divide => write!(f, "/"),
            DSLTokenType::Modulo => write!(f, "%"),
            DSLTokenType::Assign => write!(f, "="),
            DSLTokenType::PlusAssign => write!(f, "+="),
            DSLTokenType::MinusAssign => write!(f, "-="),
            DSLTokenType::MultiplyAssign => write!(f, "*="),
            DSLTokenType::DivideAssign => write!(f, "/="),
            DSLTokenType::LeftParen => write!(f, "("),
            DSLTokenType::RightParen => write!(f, ")"),
            DSLTokenType::LeftBrace => write!(f, "{{"),
            DSLTokenType::RightBrace => write!(f, "}}"),
            DSLTokenType::LeftBracket => write!(f, "["),
            DSLTokenType::RightBracket => write!(f, "]"),
            DSLTokenType::Comma => write!(f, ","),
            DSLTokenType::Semicolon => write!(f, ";"),
            DSLTokenType::Colon => write!(f, ":"),
            DSLTokenType::Dot => write!(f, "."),
            DSLTokenType::Arrow => write!(f, "->"),
            DSLTokenType::Range => write!(f, ".."),
            DSLTokenType::Echo => write!(f, "ECHO"),
            DSLTokenType::Sleep => write!(f, "SLEEP"),
            DSLTokenType::EOF => write!(f, "EOF"),
            DSLTokenType::Error(msg) => write!(f, "ERROR: {msg}"),
        }
    }
}

/// A token in the DSL
#[derive(Debug, Clone)]
pub struct DSLToken {
    pub token_type: DSLTokenType,
    pub lexeme: String,
    pub line: usize,
    pub column: usize,
}

impl DSLToken {
    pub fn new(
        token_type: DSLTokenType,
        lexeme: impl Into<String>,
        line: usize,
        column: usize,
    ) -> Self {
        Self {
            token_type,
            lexeme: lexeme.into(),
            line,
            column,
        }
    }

    pub fn is_keyword(&self) -> bool {
        matches!(
            self.token_type,
            DSLTokenType::Create
                | DSLTokenType::Delete
                | DSLTokenType::List
                | DSLTokenType::Get
                | DSLTokenType::Update
                | DSLTokenType::Wait
                | DSLTokenType::For
                | DSLTokenType::To
                | DSLTokenType::Be
                | DSLTokenType::In
                | DSLTokenType::With
                | DSLTokenType::Using
                | DSLTokenType::From
                | DSLTokenType::Where
                | DSLTokenType::And
                | DSLTokenType::Or
                | DSLTokenType::Not
                | DSLTokenType::If
                | DSLTokenType::Then
                | DSLTokenType::Else
                | DSLTokenType::End
                | DSLTokenType::Loop
                | DSLTokenType::While
                | DSLTokenType::Do
                | DSLTokenType::Break
                | DSLTokenType::Continue
                | DSLTokenType::Return
                | DSLTokenType::Set
                | DSLTokenType::Variable
                | DSLTokenType::LogLevel
                | DSLTokenType::Cluster
                | DSLTokenType::Clusters
                | DSLTokenType::Backup
                | DSLTokenType::Backups
                | DSLTokenType::Region
                | DSLTokenType::Regions
                | DSLTokenType::Price
                | DSLTokenType::Pricing
                | DSLTokenType::RCU
                | DSLTokenType::Storage
                | DSLTokenType::Plan
                | DSLTokenType::Service
                | DSLTokenType::Active
                | DSLTokenType::Creating
                | DSLTokenType::Deleting
                | DSLTokenType::Failed
                | DSLTokenType::Paused
                | DSLTokenType::Resuming
                | DSLTokenType::Suspending
                | DSLTokenType::Suspended
                | DSLTokenType::Starter
                | DSLTokenType::Dedicated
                | DSLTokenType::Enterprise
                | DSLTokenType::AWS
                | DSLTokenType::GCP
                | DSLTokenType::Azure
                | DSLTokenType::Seconds
                | DSLTokenType::Minutes
                | DSLTokenType::Hours
                | DSLTokenType::Days
                | DSLTokenType::True
                | DSLTokenType::False
                | DSLTokenType::Null
        )
    }

    pub fn is_literal(&self) -> bool {
        matches!(
            self.token_type,
            DSLTokenType::String(_)
                | DSLTokenType::Number(_)
                | DSLTokenType::Identifier(_)
                | DSLTokenType::VariableRef(_)
        )
    }

    pub fn is_operator(&self) -> bool {
        matches!(
            self.token_type,
            DSLTokenType::Equals
                | DSLTokenType::NotEquals
                | DSLTokenType::LessThan
                | DSLTokenType::LessThanOrEqual
                | DSLTokenType::GreaterThan
                | DSLTokenType::GreaterThanOrEqual
                | DSLTokenType::Plus
                | DSLTokenType::Minus
                | DSLTokenType::Multiply
                | DSLTokenType::Divide
                | DSLTokenType::Modulo
                | DSLTokenType::Assign
                | DSLTokenType::PlusAssign
                | DSLTokenType::MinusAssign
                | DSLTokenType::MultiplyAssign
                | DSLTokenType::DivideAssign
        )
    }

    pub fn is_delimiter(&self) -> bool {
        matches!(
            self.token_type,
            DSLTokenType::LeftParen
                | DSLTokenType::RightParen
                | DSLTokenType::LeftBrace
                | DSLTokenType::RightBrace
                | DSLTokenType::LeftBracket
                | DSLTokenType::RightBracket
                | DSLTokenType::Comma
                | DSLTokenType::Semicolon
                | DSLTokenType::Colon
                | DSLTokenType::Dot
                | DSLTokenType::Arrow
                | DSLTokenType::Range
        )
    }
}

impl fmt::Display for DSLToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} at line {}, column {}",
            self.token_type, self.line, self.column
        )
    }
}

/// Abstract syntax tree node types
#[derive(Debug, Clone)]
pub enum DSLSyntaxTree {
    // Commands
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
    ListClusters {
        filters: Vec<ClusterFilter>,
    },
    GetCluster {
        name: String,
    },
    UpdateCluster {
        name: String,
        updates: Vec<ClusterUpdate>,
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
        cluster_name: String,
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

    // Control flow
    IfStatement {
        condition: Box<DSLSyntaxTree>,
        then_branch: Vec<DSLSyntaxTree>,
        else_branch: Option<Vec<DSLSyntaxTree>>,
    },
    LoopStatement {
        condition: Option<Box<DSLSyntaxTree>>,
        body: Vec<DSLSyntaxTree>,
    },
    BreakStatement,
    ContinueStatement,
    ReturnStatement {
        value: Option<Box<DSLSyntaxTree>>,
    },

    // Variables and assignments
    VariableDeclaration {
        name: String,
        value: Box<DSLSyntaxTree>,
    },
    Assignment {
        name: String,
        value: Box<DSLSyntaxTree>,
    },

    // Expressions
    BinaryExpression {
        left: Box<DSLSyntaxTree>,
        operator: String,
        right: Box<DSLSyntaxTree>,
    },
    UnaryExpression {
        operator: String,
        operand: Box<DSLSyntaxTree>,
    },
    Literal {
        value: DSLValue,
    },
    VariableReference {
        name: String,
    },
    FunctionCall {
        name: String,
        arguments: Vec<DSLSyntaxTree>,
    },

    // Block
    Block {
        statements: Vec<DSLSyntaxTree>,
    },

    // No-op
    NoOp,
}

/// Cluster filter for list operations
#[derive(Debug, Clone)]
pub struct ClusterFilter {
    pub field: String,
    pub operator: String,
    pub value: DSLValue,
}

/// Cluster update for update operations
#[derive(Debug, Clone)]
pub struct ClusterUpdate {
    pub field: String,
    pub value: DSLValue,
}

/// DSL value types
#[derive(Debug, Clone, PartialEq)]
pub enum DSLValue {
    String(String),
    Number(f64),
    Boolean(bool),
    Null,
    Array(Vec<DSLValue>),
    Object(std::collections::HashMap<String, DSLValue>),
}

impl DSLValue {
    pub fn as_string(&self) -> Option<&str> {
        match self {
            DSLValue::String(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_number(&self) -> Option<f64> {
        match self {
            DSLValue::Number(n) => Some(*n),
            _ => None,
        }
    }

    pub fn as_boolean(&self) -> Option<bool> {
        match self {
            DSLValue::Boolean(b) => Some(*b),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&[DSLValue]> {
        match self {
            DSLValue::Array(arr) => Some(arr),
            _ => None,
        }
    }

    pub fn as_object(&self) -> Option<&std::collections::HashMap<String, DSLValue>> {
        match self {
            DSLValue::Object(obj) => Some(obj),
            _ => None,
        }
    }

    pub fn is_null(&self) -> bool {
        matches!(self, DSLValue::Null)
    }

    pub fn is_truthy(&self) -> bool {
        match self {
            DSLValue::Boolean(b) => *b,
            DSLValue::Number(n) => *n != 0.0,
            DSLValue::String(s) => !s.is_empty(),
            DSLValue::Array(arr) => !arr.is_empty(),
            DSLValue::Object(obj) => !obj.is_empty(),
            DSLValue::Null => false,
        }
    }
}

impl fmt::Display for DSLValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DSLValue::String(s) => write!(f, "\"{s}\""),
            DSLValue::Number(n) => write!(f, "{n}"),
            DSLValue::Boolean(b) => write!(f, "{b}"),
            DSLValue::Null => write!(f, "null"),
            DSLValue::Array(arr) => {
                write!(f, "[")?;
                for (i, item) in arr.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{item}")?;
                }
                write!(f, "]")
            }
            DSLValue::Object(obj) => {
                write!(f, "{{")?;
                for (i, (key, value)) in obj.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "\"{key}\": {value}")?;
                }
                write!(f, "}}")
            }
        }
    }
}

impl From<String> for DSLValue {
    fn from(s: String) -> Self {
        DSLValue::String(s)
    }
}

impl From<&str> for DSLValue {
    fn from(s: &str) -> Self {
        DSLValue::String(s.to_string())
    }
}

impl From<f64> for DSLValue {
    fn from(n: f64) -> Self {
        DSLValue::Number(n)
    }
}

impl From<i64> for DSLValue {
    fn from(n: i64) -> Self {
        DSLValue::Number(n as f64)
    }
}

impl From<bool> for DSLValue {
    fn from(b: bool) -> Self {
        DSLValue::Boolean(b)
    }
}

impl From<Vec<DSLValue>> for DSLValue {
    fn from(arr: Vec<DSLValue>) -> Self {
        DSLValue::Array(arr)
    }
}

impl From<std::collections::HashMap<String, DSLValue>> for DSLValue {
    fn from(obj: std::collections::HashMap<String, DSLValue>) -> Self {
        DSLValue::Object(obj)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dsl_value_from_string() {
        let value = DSLValue::from("test");
        assert_eq!(value.as_string(), Some("test"));
    }

    #[test]
    fn test_dsl_value_from_number() {
        let value = DSLValue::from(42.5);
        assert_eq!(value.as_number(), Some(42.5));
    }

    #[test]
    fn test_dsl_value_from_boolean() {
        let value = DSLValue::from(true);
        assert_eq!(value.as_boolean(), Some(true));
    }

    #[test]
    fn test_dsl_value_from_array() {
        let arr = vec![DSLValue::from("a"), DSLValue::from(1)];
        let value = DSLValue::from(arr);
        assert!(value.as_array().is_some());
        assert_eq!(value.as_array().unwrap().len(), 2);
    }

    #[test]
    fn test_dsl_value_from_object() {
        let mut obj = std::collections::HashMap::new();
        obj.insert("key".to_string(), DSLValue::from("value"));
        let value = DSLValue::from(obj);
        assert!(value.as_object().is_some());
    }

    #[test]
    fn test_dsl_value_truthy() {
        assert!(DSLValue::from(true).is_truthy());
        assert!(DSLValue::from(42.0).is_truthy());
        assert!(DSLValue::from("hello").is_truthy());
        assert!(DSLValue::from(vec![DSLValue::from(1)]).is_truthy());

        assert!(!DSLValue::from(false).is_truthy());
        assert!(!DSLValue::from(0.0).is_truthy());
        assert!(!DSLValue::from("").is_truthy());
        assert!(!DSLValue::from(Vec::<DSLValue>::new()).is_truthy());
        assert!(!DSLValue::Null.is_truthy());
    }

    #[test]
    fn test_dsl_value_display() {
        assert_eq!(DSLValue::from("test").to_string(), "\"test\"");
        assert_eq!(DSLValue::from(42.5).to_string(), "42.5");
        assert_eq!(DSLValue::from(true).to_string(), "true");
        assert_eq!(DSLValue::Null.to_string(), "null");

        let arr = vec![DSLValue::from("a"), DSLValue::from(1)];
        assert_eq!(DSLValue::from(arr).to_string(), "[\"a\", 1]");

        let mut obj = std::collections::HashMap::new();
        obj.insert("key".to_string(), DSLValue::from("value"));
        assert_eq!(DSLValue::from(obj).to_string(), "{\"key\": \"value\"}");
    }

    #[test]
    fn test_dsl_token_new() {
        let token = DSLToken::new(DSLTokenType::Identifier("test".to_string()), "test", 1, 5);
        assert_eq!(token.line, 1);
        assert_eq!(token.column, 5);
        assert_eq!(token.lexeme, "test");
    }

    #[test]
    fn test_dsl_token_is_keyword() {
        let token = DSLToken::new(DSLTokenType::Create, "CREATE", 1, 1);
        assert!(token.is_keyword());

        let token = DSLToken::new(DSLTokenType::Identifier("test".to_string()), "test", 1, 1);
        assert!(!token.is_keyword());
    }

    #[test]
    fn test_dsl_token_is_literal() {
        let token = DSLToken::new(DSLTokenType::String("test".to_string()), "\"test\"", 1, 1);
        assert!(token.is_literal());

        let token = DSLToken::new(DSLTokenType::Number(42.0), "42", 1, 1);
        assert!(token.is_literal());

        let token = DSLToken::new(DSLTokenType::Create, "CREATE", 1, 1);
        assert!(!token.is_literal());
    }

    #[test]
    fn test_dsl_token_is_operator() {
        let token = DSLToken::new(DSLTokenType::Equals, "=", 1, 1);
        assert!(token.is_operator());

        let token = DSLToken::new(DSLTokenType::Create, "CREATE", 1, 1);
        assert!(!token.is_operator());
    }

    #[test]
    fn test_dsl_token_is_delimiter() {
        let token = DSLToken::new(DSLTokenType::LeftParen, "(", 1, 1);
        assert!(token.is_delimiter());

        let token = DSLToken::new(DSLTokenType::Create, "CREATE", 1, 1);
        assert!(!token.is_delimiter());
    }

    #[test]
    fn test_dsl_token_display() {
        let token = DSLToken::new(DSLTokenType::Create, "CREATE", 1, 5);
        assert_eq!(token.to_string(), "CREATE at line 1, column 5");
    }

    #[test]
    fn test_dsl_token_type_display() {
        assert_eq!(DSLTokenType::Create.to_string(), "CREATE");
        assert_eq!(
            DSLTokenType::String("test".to_string()).to_string(),
            "\"test\""
        );
        assert_eq!(DSLTokenType::Number(42.0).to_string(), "42");
        assert_eq!(DSLTokenType::Equals.to_string(), "==");
        assert_eq!(DSLTokenType::LeftParen.to_string(), "(");
        assert_eq!(DSLTokenType::Echo.to_string(), "ECHO");
        assert_eq!(DSLTokenType::Sleep.to_string(), "SLEEP");
        assert_eq!(DSLTokenType::EOF.to_string(), "EOF");
        assert_eq!(
            DSLTokenType::Error("test".to_string()).to_string(),
            "ERROR: test"
        );
    }
}
