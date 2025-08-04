use crate::dsl::{
    commands::{CommandContext, DSLCommand, DSLCommandType},
    error::{DSLError, DSLResult},
    syntax::{DSLToken, DSLTokenType, DSLValue},
};

/// DSL lexer for tokenizing input
pub struct DSLLexer {
    input: Vec<char>,
    position: usize,
    line: usize,
    column: usize,
}

impl DSLLexer {
    pub fn new(input: &str) -> Self {
        Self {
            input: input.chars().collect(),
            position: 0,
            line: 1,
            column: 1,
        }
    }

    pub fn tokenize(&mut self) -> DSLResult<Vec<DSLToken>> {
        let mut tokens = Vec::new();

        while !self.is_at_end() {
            self.skip_whitespace();

            if self.is_at_end() {
                break;
            }

            let token = self.next_token()?;
            tokens.push(token);
        }

        tokens.push(DSLToken::new(DSLTokenType::EOF, "", self.line, self.column));
        Ok(tokens)
    }

    fn next_token(&mut self) -> DSLResult<DSLToken> {
        let start_column = self.column;
        let start_line = self.line;
        let c = self.advance();

        match c {
            // Single character tokens
            '(' => Ok(DSLToken::new(
                DSLTokenType::LeftParen,
                "(",
                start_line,
                start_column,
            )),
            ')' => Ok(DSLToken::new(
                DSLTokenType::RightParen,
                ")",
                start_line,
                start_column,
            )),
            '{' => Ok(DSLToken::new(
                DSLTokenType::LeftBrace,
                "{",
                start_line,
                start_column,
            )),
            '}' => Ok(DSLToken::new(
                DSLTokenType::RightBrace,
                "}",
                start_line,
                start_column,
            )),
            '[' => Ok(DSLToken::new(
                DSLTokenType::LeftBracket,
                "[",
                start_line,
                start_column,
            )),
            ']' => Ok(DSLToken::new(
                DSLTokenType::RightBracket,
                "]",
                start_line,
                start_column,
            )),
            ',' => Ok(DSLToken::new(
                DSLTokenType::Comma,
                ",",
                start_line,
                start_column,
            )),
            ';' => Ok(DSLToken::new(
                DSLTokenType::Semicolon,
                ";",
                start_line,
                start_column,
            )),
            ':' => Ok(DSLToken::new(
                DSLTokenType::Colon,
                ":",
                start_line,
                start_column,
            )),
            '.' => Ok(DSLToken::new(
                DSLTokenType::Dot,
                ".",
                start_line,
                start_column,
            )),
            '+' => Ok(DSLToken::new(
                DSLTokenType::Plus,
                "+",
                start_line,
                start_column,
            )),
            '*' => Ok(DSLToken::new(
                DSLTokenType::Multiply,
                "*",
                start_line,
                start_column,
            )),
            '%' => Ok(DSLToken::new(
                DSLTokenType::Modulo,
                "%",
                start_line,
                start_column,
            )),

            // Two character tokens
            '=' => {
                if self.match_char('=') {
                    Ok(DSLToken::new(
                        DSLTokenType::Equals,
                        "==",
                        start_line,
                        start_column,
                    ))
                } else {
                    Ok(DSLToken::new(
                        DSLTokenType::Assign,
                        "=",
                        start_line,
                        start_column,
                    ))
                }
            }
            '!' => {
                if self.match_char('=') {
                    Ok(DSLToken::new(
                        DSLTokenType::NotEquals,
                        "!=",
                        start_line,
                        start_column,
                    ))
                } else {
                    Ok(DSLToken::new(
                        DSLTokenType::Not,
                        "!",
                        start_line,
                        start_column,
                    ))
                }
            }
            '<' => {
                if self.match_char('=') {
                    Ok(DSLToken::new(
                        DSLTokenType::LessThanOrEqual,
                        "<=",
                        start_line,
                        start_column,
                    ))
                } else {
                    Ok(DSLToken::new(
                        DSLTokenType::LessThan,
                        "<",
                        start_line,
                        start_column,
                    ))
                }
            }
            '>' => {
                if self.match_char('=') {
                    Ok(DSLToken::new(
                        DSLTokenType::GreaterThanOrEqual,
                        ">=",
                        start_line,
                        start_column,
                    ))
                } else {
                    Ok(DSLToken::new(
                        DSLTokenType::GreaterThan,
                        ">",
                        start_line,
                        start_column,
                    ))
                }
            }
            '-' => {
                if self.match_char('>') {
                    Ok(DSLToken::new(
                        DSLTokenType::Arrow,
                        "->",
                        start_line,
                        start_column,
                    ))
                } else {
                    Ok(DSLToken::new(
                        DSLTokenType::Minus,
                        "-",
                        start_line,
                        start_column,
                    ))
                }
            }
            '/' => {
                if self.match_char('/') {
                    // Comment
                    while self.peek() != '\n' && !self.is_at_end() {
                        self.advance();
                    }
                    self.next_token()
                } else {
                    Ok(DSLToken::new(
                        DSLTokenType::Divide,
                        "/",
                        start_line,
                        start_column,
                    ))
                }
            }

            // Strings
            '"' => self.string(start_line, start_column),
            '\'' => self.string(start_line, start_column),

            // Numbers
            '0'..='9' => self.number(start_line, start_column),

            // Identifiers and keywords
            'a'..='z' | 'A'..='Z' | '_' => self.identifier_or_keyword(start_line, start_column),

            // Variables
            '$' => self.variable(start_line, start_column),

            // Unknown character
            _ => Err(DSLError::syntax_error(
                self.position - 1,
                format!("Unexpected character: {c}"),
            )),
        }
    }

    fn string(&mut self, start_line: usize, start_column: usize) -> DSLResult<DSLToken> {
        let mut value = String::new();
        let quote = self.previous();

        while self.peek() != quote && !self.is_at_end() {
            if self.peek() == '\n' {
                self.line += 1;
                self.column = 0;
            }
            value.push(self.advance());
        }

        if self.is_at_end() {
            return Err(DSLError::syntax_error(
                self.position,
                "Unterminated string".to_string(),
            ));
        }

        // Consume the closing quote
        self.advance();

        Ok(DSLToken::new(
            DSLTokenType::String(value),
            "",
            start_line,
            start_column,
        ))
    }

    fn number(&mut self, start_line: usize, start_column: usize) -> DSLResult<DSLToken> {
        let mut value = String::new();
        value.push(self.previous());

        while self.peek().is_ascii_digit() || self.peek() == '.' {
            value.push(self.advance());
        }

        match value.parse::<f64>() {
            Ok(num) => Ok(DSLToken::new(
                DSLTokenType::Number(num),
                &value,
                start_line,
                start_column,
            )),
            Err(_) => Err(DSLError::syntax_error(
                start_column,
                format!("Invalid number: {value}"),
            )),
        }
    }

    fn identifier_or_keyword(
        &mut self,
        start_line: usize,
        start_column: usize,
    ) -> DSLResult<DSLToken> {
        let mut value = String::new();
        value.push(self.previous());

        while self.peek().is_alphanumeric() || self.peek() == '_' || self.peek() == '-' {
            value.push(self.advance());
        }

        let token_type = self.keyword_to_token_type(&value);
        Ok(DSLToken::new(token_type, &value, start_line, start_column))
    }

    fn variable(&mut self, start_line: usize, start_column: usize) -> DSLResult<DSLToken> {
        let mut name = String::new();

        while self.peek().is_alphanumeric() || self.peek() == '_' {
            name.push(self.advance());
        }

        if name.is_empty() {
            return Err(DSLError::syntax_error(
                start_column,
                "Empty variable name".to_string(),
            ));
        }

        // Validate variable name to prevent injection attacks
        if !self.is_valid_variable_name(&name) {
            return Err(DSLError::syntax_error(
                start_column,
                format!("Invalid variable name '{name}': contains forbidden characters"),
            ));
        }

        Ok(DSLToken::new(
            DSLTokenType::VariableRef(name),
            "",
            start_line,
            start_column,
        ))
    }

    fn keyword_to_token_type(&self, keyword: &str) -> DSLTokenType {
        match keyword.to_uppercase().as_str() {
            "CREATE" => DSLTokenType::Create,
            "DELETE" => DSLTokenType::Delete,
            "LIST" => DSLTokenType::List,
            "GET" => DSLTokenType::Get,
            "UPDATE" => DSLTokenType::Update,
            "WAIT" => DSLTokenType::Wait,
            "FOR" => DSLTokenType::For,
            "TO" => DSLTokenType::To,
            "BE" => DSLTokenType::Be,
            "IN" => DSLTokenType::In,
            "WITH" => DSLTokenType::With,
            "USING" => DSLTokenType::Using,
            "FROM" => DSLTokenType::From,
            "WHERE" => DSLTokenType::Where,
            "AND" => DSLTokenType::And,
            "OR" => DSLTokenType::Or,
            "NOT" => DSLTokenType::Not,
            "IF" => DSLTokenType::If,
            "THEN" => DSLTokenType::Then,
            "ELSE" => DSLTokenType::Else,
            "END" => DSLTokenType::End,
            "LOOP" => DSLTokenType::Loop,
            "WHILE" => DSLTokenType::While,
            "DO" => DSLTokenType::Do,
            "BREAK" => DSLTokenType::Break,
            "CONTINUE" => DSLTokenType::Continue,
            "RETURN" => DSLTokenType::Return,
            "SET" => DSLTokenType::Set,
            "VARIABLE" => DSLTokenType::Variable,
            "LOG-LEVEL" => DSLTokenType::LogLevel,
            "CLUSTER" => DSLTokenType::Cluster,
            "CLUSTERS" => DSLTokenType::Clusters,
            "BACKUP" => DSLTokenType::Backup,
            "BACKUPS" => DSLTokenType::Backups,
            "REGION" => DSLTokenType::Region,
            "REGIONS" => DSLTokenType::Regions,
            "PRICE" => DSLTokenType::Price,
            "PRICING" => DSLTokenType::Pricing,
            "RCU" => DSLTokenType::RCU,
            "STORAGE" => DSLTokenType::Storage,
            "PLAN" => DSLTokenType::Plan,
            "SERVICE" => DSLTokenType::Service,
            "ACTIVE" => DSLTokenType::Active,
            "CREATING" => DSLTokenType::Creating,
            "DELETING" => DSLTokenType::Deleting,
            "FAILED" => DSLTokenType::Failed,
            "PAUSED" => DSLTokenType::Paused,
            "RESUMING" => DSLTokenType::Resuming,
            "SUSPENDING" => DSLTokenType::Suspending,
            "SUSPENDED" => DSLTokenType::Suspended,
            "STARTER" => DSLTokenType::Starter,
            "DEDICATED" => DSLTokenType::Dedicated,
            "ENTERPRISE" => DSLTokenType::Enterprise,
            "AWS" => DSLTokenType::AWS,
            "GCP" => DSLTokenType::GCP,
            "AZURE" => DSLTokenType::Azure,
            "SECONDS" => DSLTokenType::Seconds,
            "MINUTES" => DSLTokenType::Minutes,
            "HOURS" => DSLTokenType::Hours,
            "DAYS" => DSLTokenType::Days,
            "TRUE" => DSLTokenType::True,
            "FALSE" => DSLTokenType::False,
            "NULL" => DSLTokenType::Null,
            "ECHO" => DSLTokenType::Echo,
            "SLEEP" => DSLTokenType::Sleep,
            "SELECT" => DSLTokenType::Select,
            _ => DSLTokenType::Identifier(keyword.to_string()),
        }
    }

    fn advance(&mut self) -> char {
        let c = self.input[self.position];
        self.position += 1;
        if c == '\n' {
            self.line += 1;
            self.column = 1;
        } else {
            self.column += 1;
        }
        c
    }

    fn match_char(&mut self, expected: char) -> bool {
        if self.is_at_end() || self.input[self.position] != expected {
            false
        } else {
            self.position += 1;
            self.column += 1;
            true
        }
    }

    fn peek(&self) -> char {
        if self.is_at_end() {
            '\0'
        } else {
            self.input[self.position]
        }
    }

    fn previous(&self) -> char {
        self.input[self.position - 1]
    }

    fn is_at_end(&self) -> bool {
        self.position >= self.input.len()
    }

    fn skip_whitespace(&mut self) {
        while !self.is_at_end() && self.peek().is_whitespace() {
            self.advance();
        }
    }

    /// Validate variable name to prevent injection attacks
    fn is_valid_variable_name(&self, name: &str) -> bool {
        if name.is_empty() {
            return false;
        }

        // Check for shell metacharacters and other dangerous patterns
        let dangerous_chars = [
            '$', '`', '(', ')', '[', ']', '{', '}', '|', '&', ';', '<', '>', '\\', '"', '\'',
        ];
        if name.chars().any(|c| dangerous_chars.contains(&c)) {
            return false;
        }

        // Check for command injection patterns
        let dangerous_patterns = [
            "rm",
            "del",
            "format",
            "shutdown",
            "reboot",
            "kill",
            "exec",
            "system",
            "eval",
            "command",
            "shell",
            "bash",
            "cmd",
            "powershell",
        ];

        let lower_name = name.to_lowercase();
        if dangerous_patterns
            .iter()
            .any(|&pattern| lower_name.contains(pattern))
        {
            return false;
        }

        // Limit length to prevent DoS
        if name.len() > 50 {
            return false;
        }

        true
    }
}

/// DSL parser for converting tokens to commands
pub struct DSLParser {
    tokens: Vec<DSLToken>,
    current: usize,
}

impl DSLParser {
    pub fn new(tokens: Vec<DSLToken>) -> Self {
        Self { tokens, current: 0 }
    }

    pub fn parse(input: &str) -> DSLResult<DSLCommand> {
        // Validate input length to prevent DoS attacks
        if input.len() > 10000 {
            return Err(DSLError::syntax_error(
                0,
                "Input too long: maximum 10,000 characters allowed".to_string(),
            ));
        }

        let mut lexer = DSLLexer::new(input);
        let tokens = lexer.tokenize()?;
        let mut parser = DSLParser::new(tokens);
        parser.parse_command()
    }

    pub fn parse_script(input: &str) -> DSLResult<Vec<DSLCommand>> {
        let mut lexer = DSLLexer::new(input);
        let tokens = lexer.tokenize()?;
        let mut parser = DSLParser::new(tokens);
        parser.parse_script_internal()
    }

    fn parse_script_internal(&mut self) -> DSLResult<Vec<DSLCommand>> {
        let mut commands = Vec::new();

        while !self.is_at_end() {
            self.skip_semicolons();

            if self.is_at_end() {
                break;
            }

            let command = self.parse_command()?;
            commands.push(command);
        }

        Ok(commands)
    }

    fn parse_command(&mut self) -> DSLResult<DSLCommand> {
        let start_line = self.peek().line;
        let start_column = self.peek().column;

        let command = match self.peek().token_type {
            DSLTokenType::Create => self.parse_create_command()?,
            DSLTokenType::Delete => self.parse_delete_command()?,
            DSLTokenType::List => self.parse_list_command()?,
            DSLTokenType::Get => self.parse_get_command()?,
            DSLTokenType::Update => self.parse_update_command()?,
            DSLTokenType::Wait => self.parse_wait_command()?,
            DSLTokenType::Set => self.parse_set_command()?,
            DSLTokenType::If => self.parse_if_command()?,
            DSLTokenType::Loop => self.parse_loop_command()?,
            DSLTokenType::Echo => self.parse_echo_command()?,
            DSLTokenType::Sleep => self.parse_sleep_command()?,
            _ => {
                return Err(DSLError::unknown_command(self.peek().lexeme.clone()));
            }
        };

        Ok(command.with_context(CommandContext::new().with_location(start_line, start_column)))
    }

    fn parse_create_command(&mut self) -> DSLResult<DSLCommand> {
        self.consume(DSLTokenType::Create, "Expected 'CREATE'")?;

        match self.peek().token_type {
            DSLTokenType::Cluster => Ok(self.parse_create_cluster()?),
            DSLTokenType::Backup => Ok(self.parse_create_backup()?),
            _ => Err(DSLError::syntax_error(
                self.peek().column,
                "Expected 'CLUSTER' or 'BACKUP' after 'CREATE'".to_string(),
            )),
        }
    }

    fn parse_create_cluster(&mut self) -> DSLResult<DSLCommand> {
        self.consume(DSLTokenType::Cluster, "Expected 'CLUSTER'")?;

        let name = self.parse_identifier()?;

        self.consume(DSLTokenType::In, "Expected 'IN'")?;
        let region = self.parse_expression()?;

        let mut command = DSLCommand::new(DSLCommandType::CreateCluster)
            .with_parameter("name", DSLValue::from(name))
            .with_parameter("region", region);

        // Parse optional parameters
        if self.match_token(DSLTokenType::With) {
            command = self.parse_with_clause(command)?;
        }

        Ok(command)
    }

    fn parse_create_backup(&mut self) -> DSLResult<DSLCommand> {
        self.consume(DSLTokenType::Backup, "Expected 'BACKUP'")?;

        self.consume(DSLTokenType::For, "Expected 'FOR'")?;
        let cluster_name = self.parse_identifier()?;

        let mut command = DSLCommand::new(DSLCommandType::CreateBackup)
            .with_parameter("cluster_name", DSLValue::from(cluster_name));

        // Parse optional description
        if self.match_token(DSLTokenType::With) {
            command = self.parse_with_clause(command)?;
        }

        Ok(command)
    }

    fn parse_delete_command(&mut self) -> DSLResult<DSLCommand> {
        self.consume(DSLTokenType::Delete, "Expected 'DELETE'")?;

        match self.peek().token_type {
            DSLTokenType::Cluster => Ok(self.parse_delete_cluster()?),
            DSLTokenType::Backup => Ok(self.parse_delete_backup()?),
            _ => Err(DSLError::syntax_error(
                self.peek().column,
                "Expected 'CLUSTER' or 'BACKUP' after 'DELETE'".to_string(),
            )),
        }
    }

    fn parse_delete_cluster(&mut self) -> DSLResult<DSLCommand> {
        self.consume(DSLTokenType::Cluster, "Expected 'CLUSTER'")?;
        let name = self.parse_identifier()?;

        Ok(DSLCommand::new(DSLCommandType::DeleteCluster)
            .with_parameter("name", DSLValue::from(name)))
    }

    fn parse_delete_backup(&mut self) -> DSLResult<DSLCommand> {
        self.consume(DSLTokenType::Backup, "Expected 'BACKUP'")?;
        let backup_id = self.parse_identifier()?;

        self.consume(DSLTokenType::From, "Expected 'FROM'")?;
        let cluster_name = self.parse_identifier()?;

        Ok(DSLCommand::new(DSLCommandType::DeleteBackup)
            .with_parameter("backup_id", DSLValue::from(backup_id))
            .with_parameter("cluster_name", DSLValue::from(cluster_name)))
    }

    fn parse_list_command(&mut self) -> DSLResult<DSLCommand> {
        self.consume(DSLTokenType::List, "Expected 'LIST'")?;

        match self.peek().token_type {
            DSLTokenType::Clusters => Ok(self.parse_list_clusters()?),
            DSLTokenType::Backups => Ok(self.parse_list_backups()?),
            _ => Err(DSLError::syntax_error(
                self.peek().column,
                "Expected 'CLUSTERS' or 'BACKUPS' after 'LIST'".to_string(),
            )),
        }
    }

    fn parse_list_clusters(&mut self) -> DSLResult<DSLCommand> {
        self.consume(DSLTokenType::Clusters, "Expected 'CLUSTERS'")?;

        let mut command = DSLCommand::new(DSLCommandType::ListClusters);

        if self.match_token(DSLTokenType::With) {
            command = self.parse_with_clause(command)?;
        }

        if self.match_token(DSLTokenType::Where) {
            command = self.parse_where_clause(command)?;
        }

        Ok(command)
    }

    fn parse_list_backups(&mut self) -> DSLResult<DSLCommand> {
        self.consume(DSLTokenType::Backups, "Expected 'BACKUPS'")?;

        self.consume(DSLTokenType::For, "Expected 'FOR'")?;
        let cluster_name = self.parse_identifier()?;

        Ok(DSLCommand::new(DSLCommandType::ListBackups)
            .with_parameter("cluster_name", DSLValue::from(cluster_name)))
    }

    fn parse_get_command(&mut self) -> DSLResult<DSLCommand> {
        self.consume(DSLTokenType::Get, "Expected 'GET'")?;

        self.consume(DSLTokenType::Cluster, "Expected 'CLUSTER'")?;
        let name = self.parse_identifier()?;

        let mut command = DSLCommand::new(DSLCommandType::GetCluster)
            .with_parameter("name", DSLValue::from(name));

        if self.match_token(DSLTokenType::With) {
            command = self.parse_with_clause(command)?;
        }

        Ok(command)
    }

    fn parse_update_command(&mut self) -> DSLResult<DSLCommand> {
        self.consume(DSLTokenType::Update, "Expected 'UPDATE'")?;

        self.consume(DSLTokenType::Cluster, "Expected 'CLUSTER'")?;
        let name = self.parse_identifier()?;

        self.consume(DSLTokenType::With, "Expected 'WITH'")?;
        let mut command = DSLCommand::new(DSLCommandType::UpdateCluster)
            .with_parameter("name", DSLValue::from(name));

        command = self.parse_with_clause(command)?;

        Ok(command)
    }

    fn parse_wait_command(&mut self) -> DSLResult<DSLCommand> {
        self.consume(DSLTokenType::Wait, "Expected 'WAIT'")?;

        self.consume(DSLTokenType::For, "Expected 'FOR'")?;
        let name = self.parse_field_name()?;

        self.consume(DSLTokenType::To, "Expected 'TO'")?;
        self.consume(DSLTokenType::Be, "Expected 'BE'")?;
        let state = self.parse_field_name()?;

        let mut command = DSLCommand::new(DSLCommandType::WaitForCluster)
            .with_parameter("name", DSLValue::from(name))
            .with_parameter("state", DSLValue::from(state));

        // Parse optional timeout
        if self.match_token(DSLTokenType::With) {
            command = self.parse_with_clause(command)?;
        }

        Ok(command)
    }

    fn parse_set_command(&mut self) -> DSLResult<DSLCommand> {
        self.consume(DSLTokenType::Set, "Expected 'SET'")?;

        // Check if this is SET LOG-LEVEL
        if self.check(DSLTokenType::LogLevel) {
            self.consume(DSLTokenType::LogLevel, "Expected 'LOG-LEVEL'")?;
            let level = self.parse_expression()?;

            Ok(DSLCommand::new(DSLCommandType::SetLogLevel).with_parameter("level", level))
        } else {
            // Regular SET variable = value
            let name = self.parse_variable_name()?;
            self.consume(DSLTokenType::Assign, "Expected '='")?;
            let value = self.parse_expression()?;

            Ok(DSLCommand::new(DSLCommandType::SetVariable)
                .with_parameter("name", DSLValue::from(name))
                .with_parameter("value", value))
        }
    }

    /// Parse a variable name that can be any identifier or keyword
    fn parse_variable_name(&mut self) -> DSLResult<String> {
        let token = self.peek();
        let name = match &token.token_type {
            DSLTokenType::Identifier(name) => name.clone(),
            DSLTokenType::Region => "region".to_string(),
            DSLTokenType::Clusters => "clusters".to_string(),
            DSLTokenType::Backups => "backups".to_string(),
            DSLTokenType::Regions => "regions".to_string(),
            DSLTokenType::Price => "price".to_string(),
            DSLTokenType::Pricing => "pricing".to_string(),
            DSLTokenType::RCU => "rcu".to_string(),
            DSLTokenType::Storage => "storage".to_string(),
            DSLTokenType::Plan => "plan".to_string(),
            DSLTokenType::Service => "service".to_string(),
            DSLTokenType::Active => "active".to_string(),
            DSLTokenType::Creating => "creating".to_string(),
            DSLTokenType::Deleting => "deleting".to_string(),
            DSLTokenType::Failed => "failed".to_string(),
            DSLTokenType::Paused => "paused".to_string(),
            DSLTokenType::Resuming => "resuming".to_string(),
            DSLTokenType::Suspending => "suspending".to_string(),
            DSLTokenType::Suspended => "suspended".to_string(),
            DSLTokenType::Starter => "starter".to_string(),
            DSLTokenType::Dedicated => "dedicated".to_string(),
            DSLTokenType::Enterprise => "enterprise".to_string(),
            DSLTokenType::AWS => "aws".to_string(),
            DSLTokenType::GCP => "gcp".to_string(),
            DSLTokenType::Azure => "azure".to_string(),
            DSLTokenType::Seconds => "seconds".to_string(),
            DSLTokenType::Minutes => "minutes".to_string(),
            DSLTokenType::Hours => "hours".to_string(),
            DSLTokenType::Days => "days".to_string(),
            DSLTokenType::True => "true".to_string(),
            DSLTokenType::False => "false".to_string(),
            DSLTokenType::Null => "null".to_string(),
            _ => {
                return Err(DSLError::syntax_error(
                    token.column,
                    format!("Expected variable name, got {:?}", token.token_type),
                ));
            }
        };
        self.advance();
        Ok(name)
    }

    /// Parse a field name that can be any identifier or keyword (for WHERE clauses)
    fn parse_field_name(&mut self) -> DSLResult<String> {
        let token = self.peek();
        let name = match &token.token_type {
            DSLTokenType::Identifier(name) => {
                // Check if the identifier is a known state keyword (case-insensitive)
                let upper_name = name.to_uppercase();
                match upper_name.as_str() {
                    "ACTIVE" => "active".to_string(),
                    "CREATING" => "creating".to_string(),
                    "DELETING" => "deleting".to_string(),
                    "FAILED" => "failed".to_string(),
                    "PAUSED" => "paused".to_string(),
                    "RESUMING" => "resuming".to_string(),
                    "SUSPENDING" => "suspending".to_string(),
                    "SUSPENDED" => "suspended".to_string(),
                    "MAINTENANCE" => "maintenance".to_string(),
                    _ => name.clone(), // Return as-is if not a known state
                }
            }
            DSLTokenType::Cluster => "cluster".to_string(),
            DSLTokenType::Clusters => "clusters".to_string(),
            DSLTokenType::Region => "region".to_string(),
            DSLTokenType::Service => "service".to_string(),
            DSLTokenType::Plan => "plan".to_string(),
            DSLTokenType::RCU => "rcu".to_string(),
            DSLTokenType::Storage => "storage".to_string(),
            DSLTokenType::Price => "price".to_string(),
            DSLTokenType::Pricing => "pricing".to_string(),
            DSLTokenType::Active => "active".to_string(),
            DSLTokenType::Creating => "creating".to_string(),
            DSLTokenType::Deleting => "deleting".to_string(),
            DSLTokenType::Failed => "failed".to_string(),
            DSLTokenType::Paused => "paused".to_string(),
            DSLTokenType::Resuming => "resuming".to_string(),
            DSLTokenType::Suspending => "suspending".to_string(),
            DSLTokenType::Suspended => "suspended".to_string(),
            DSLTokenType::Starter => "starter".to_string(),
            DSLTokenType::Dedicated => "dedicated".to_string(),
            DSLTokenType::Enterprise => "enterprise".to_string(),
            DSLTokenType::AWS => "aws".to_string(),
            DSLTokenType::GCP => "gcp".to_string(),
            DSLTokenType::Azure => "azure".to_string(),
            DSLTokenType::Seconds => "seconds".to_string(),
            DSLTokenType::Minutes => "minutes".to_string(),
            DSLTokenType::Hours => "hours".to_string(),
            DSLTokenType::Days => "days".to_string(),
            DSLTokenType::True => "true".to_string(),
            DSLTokenType::False => "false".to_string(),
            DSLTokenType::Null => "null".to_string(),
            DSLTokenType::Echo => "echo".to_string(),
            DSLTokenType::Sleep => "sleep".to_string(),
            _ => {
                return Err(DSLError::syntax_error(
                    self.peek().column,
                    format!("Expected field name, got {:?}", self.peek().token_type),
                ));
            }
        };
        self.advance();
        Ok(name)
    }

    #[allow(unused_variables)]
    #[allow(unused_assignments)]
    fn parse_if_command(&mut self) -> DSLResult<DSLCommand> {
        self.consume(DSLTokenType::If, "Expected 'IF'")?;

        let condition = self.parse_expression()?;
        self.consume(DSLTokenType::Then, "Expected 'THEN'")?;

        let mut then_commands = Vec::new();
        while !self.is_at_end()
            && !self.match_token(DSLTokenType::Else)
            && !self.match_token(DSLTokenType::End)
        {
            then_commands.push(self.parse_command()?);
        }

        let mut else_commands = None;
        if self.match_token(DSLTokenType::Else) {
            let mut commands = Vec::new();
            while !self.is_at_end() && !self.match_token(DSLTokenType::End) {
                commands.push(self.parse_command()?);
            }
            else_commands = Some(commands);
        }

        self.consume(DSLTokenType::End, "Expected 'END'")?;

        // For now, we'll create a simple command that represents the if statement
        // In a full implementation, this would be more complex
        Ok(DSLCommand::new(DSLCommandType::If).with_parameter("condition", condition))
    }

    fn parse_loop_command(&mut self) -> DSLResult<DSLCommand> {
        self.consume(DSLTokenType::Loop, "Expected 'LOOP'")?;

        let mut commands = Vec::new();
        while !self.is_at_end() && !self.match_token(DSLTokenType::End) {
            commands.push(self.parse_command()?);
        }

        self.consume(DSLTokenType::End, "Expected 'END'")?;

        Ok(DSLCommand::new(DSLCommandType::Loop))
    }

    fn parse_echo_command(&mut self) -> DSLResult<DSLCommand> {
        self.consume(DSLTokenType::Echo, "Expected 'ECHO'")?;

        let message = self.parse_expression()?;

        Ok(DSLCommand::new(DSLCommandType::Echo).with_parameter("message", message))
    }

    fn parse_sleep_command(&mut self) -> DSLResult<DSLCommand> {
        self.consume(DSLTokenType::Sleep, "Expected 'SLEEP'")?;

        let seconds = self.parse_expression()?;

        Ok(DSLCommand::new(DSLCommandType::Sleep).with_parameter("seconds", seconds))
    }

    fn parse_with_clause(&mut self, mut command: DSLCommand) -> DSLResult<DSLCommand> {
        loop {
            let param_name = self.parse_identifier()?;
            self.consume(DSLTokenType::Assign, "Expected '='")?;
            let param_value = self.parse_expression()?;

            command = command.with_parameter(param_name, param_value);

            if !self.match_token(DSLTokenType::Comma) {
                break;
            }
        }
        Ok(command)
    }

    fn parse_where_clause(&mut self, mut command: DSLCommand) -> DSLResult<DSLCommand> {
        // Parse the entire WHERE clause as a single complex expression
        let where_expression = self.parse_where_expression()?;

        // Store the complete WHERE clause for RPN evaluation
        command = command.with_parameter("where_clause", DSLValue::from(where_expression));

        Ok(command)
    }

    fn parse_where_expression(&mut self) -> DSLResult<String> {
        let mut expression = String::new();
        let mut paren_count = 0;
        let mut last_token_column = 0;

        while !self.is_at_end() {
            let token = self.peek();
            last_token_column = token.column;

            match token.token_type {
                DSLTokenType::And | DSLTokenType::Or | DSLTokenType::Not => {
                    expression.push_str(&format!(" {} ", token.lexeme.to_uppercase()));
                    self.advance();
                }
                DSLTokenType::LeftParen => {
                    expression.push('(');
                    paren_count += 1;
                    self.advance();
                }
                DSLTokenType::RightParen => {
                    if paren_count > 0 {
                        expression.push(')');
                        paren_count -= 1;
                        self.advance();
                    } else {
                        break; // End of WHERE clause
                    }
                }
                DSLTokenType::Where => {
                    // Skip the WHERE keyword itself
                    self.advance();
                    continue;
                }
                // Add termination conditions for end of WHERE clause
                DSLTokenType::EOF | DSLTokenType::Semicolon => {
                    break; // End of WHERE clause
                }
                _ => {
                    // Handle field names, operators, and values
                    if !expression.is_empty()
                        && !expression.ends_with(' ')
                        && !expression.ends_with('(')
                    {
                        expression.push(' ');
                    }

                    match token.token_type {
                        DSLTokenType::String(ref s) => {
                            expression.push_str(&format!("\"{s}\""));
                            self.advance();
                        }
                        DSLTokenType::Number(n) => {
                            expression.push_str(&n.to_string());
                            self.advance();
                        }
                        DSLTokenType::Identifier(_) => {
                            let field = self.parse_field_name()?;
                            expression.push_str(&field);
                        }
                        DSLTokenType::Equals
                        | DSLTokenType::NotEquals
                        | DSLTokenType::LessThan
                        | DSLTokenType::LessThanOrEqual
                        | DSLTokenType::GreaterThan
                        | DSLTokenType::GreaterThanOrEqual => {
                            let operator = self.parse_operator()?;
                            expression.push_str(&operator);
                        }
                        DSLTokenType::True => {
                            expression.push_str("true");
                            self.advance();
                        }
                        DSLTokenType::False => {
                            expression.push_str("false");
                            self.advance();
                        }
                        DSLTokenType::Null => {
                            expression.push_str("null");
                            self.advance();
                        }
                        _ => {
                            // For other tokens, just add the lexeme
                            expression.push_str(&token.lexeme);
                            self.advance();
                        }
                    }
                }
            }
        }

        if paren_count != 0 {
            return Err(DSLError::syntax_error(
                last_token_column,
                "Mismatched parentheses in WHERE clause".to_string(),
            ));
        }

        Ok(expression.trim().to_string())
    }

    fn parse_expression(&mut self) -> DSLResult<DSLValue> {
        match self.peek().token_type {
            DSLTokenType::String(ref s) => {
                let s = s.clone();
                self.advance();
                // Remove quotes from string literals for comparison
                let clean_s = s.trim_matches('"');
                Ok(DSLValue::from(clean_s))
            }
            DSLTokenType::Number(n) => {
                self.advance();
                Ok(DSLValue::from(n))
            }
            DSLTokenType::True => {
                self.advance();
                Ok(DSLValue::from(true))
            }
            DSLTokenType::False => {
                self.advance();
                Ok(DSLValue::from(false))
            }
            DSLTokenType::Null => {
                self.advance();
                Ok(DSLValue::Null)
            }
            DSLTokenType::VariableRef(ref name) => {
                let name = name.clone();
                self.advance();
                Ok(DSLValue::from(format!("${name}")))
            }
            DSLTokenType::Identifier(_) => {
                let identifier = self.parse_identifier()?;
                Ok(DSLValue::from(identifier))
            }
            // Handle JSON objects and arrays
            DSLTokenType::LeftBrace => self.parse_json_object(),
            DSLTokenType::LeftBracket => self.parse_json_array(),
            // Handle state keywords
            DSLTokenType::Active => {
                self.advance();
                Ok(DSLValue::from("ACTIVE"))
            }
            DSLTokenType::Creating => {
                self.advance();
                Ok(DSLValue::from("CREATING"))
            }
            DSLTokenType::Deleting => {
                self.advance();
                Ok(DSLValue::from("DELETING"))
            }
            DSLTokenType::Failed => {
                self.advance();
                Ok(DSLValue::from("FAILED"))
            }
            DSLTokenType::Paused => {
                self.advance();
                Ok(DSLValue::from("PAUSED"))
            }
            DSLTokenType::Resuming => {
                self.advance();
                Ok(DSLValue::from("RESUMING"))
            }
            DSLTokenType::Suspending => {
                self.advance();
                Ok(DSLValue::from("SUSPENDING"))
            }
            DSLTokenType::Suspended => {
                self.advance();
                Ok(DSLValue::from("SUSPENDED"))
            }
            // Handle service plan keywords
            DSLTokenType::Starter => {
                self.advance();
                Ok(DSLValue::from("STARTER"))
            }
            DSLTokenType::Dedicated => {
                self.advance();
                Ok(DSLValue::from("DEDICATED"))
            }
            DSLTokenType::Enterprise => {
                self.advance();
                Ok(DSLValue::from("ENTERPRISE"))
            }
            _ => Err(DSLError::syntax_error(
                self.peek().column,
                format!(
                    "Unexpected token in expression: {:?}",
                    self.peek().token_type
                ),
            )),
        }
    }

    fn parse_identifier(&mut self) -> DSLResult<String> {
        match self.peek().token_type {
            DSLTokenType::Identifier(ref name) => {
                let name = name.clone();
                self.advance();
                Ok(name)
            }
            // Allow certain keywords to be used as identifiers in parameter names
            DSLTokenType::Plan => {
                self.advance();
                Ok("plan".to_string())
            }
            _ => Err(DSLError::syntax_error(
                self.peek().column,
                format!("Expected identifier, got {:?}", self.peek().token_type),
            )),
        }
    }

    fn parse_json_object(&mut self) -> DSLResult<DSLValue> {
        // Consume the opening brace
        self.consume(DSLTokenType::LeftBrace, "Expected '{' to start JSON object")?;

        let mut object = std::collections::HashMap::new();

        // Check if the object is empty
        if self.match_token(DSLTokenType::RightBrace) {
            // match_token already advances the parser
            return Ok(DSLValue::Object(object));
        }

        loop {
            // Parse the key (can be identifier or string)
            let key = match self.peek().token_type {
                DSLTokenType::String(ref s) => {
                    let s = s.clone();
                    self.advance();
                    s.trim_matches('"').to_string()
                }
                DSLTokenType::Identifier(ref name) => {
                    let name = name.clone();
                    self.advance();
                    name
                }
                _ => {
                    return Err(DSLError::syntax_error(
                        self.peek().column,
                        format!(
                            "Expected string or identifier for object key, got {:?}",
                            self.peek().token_type
                        ),
                    ));
                }
            };

            // Consume the colon
            self.consume(DSLTokenType::Colon, "Expected ':' after object key")?;

            // Parse the value
            let value = self.parse_expression()?;

            object.insert(key, value);

            // Check for comma or closing brace
            if self.match_token(DSLTokenType::Comma) {
                // match_token already advances the parser
            } else if self.match_token(DSLTokenType::RightBrace) {
                break;
            } else {
                return Err(DSLError::syntax_error(
                    self.peek().column,
                    "Expected ',' or '}' in JSON object",
                ));
            }
        }

        Ok(DSLValue::Object(object))
    }

    fn parse_json_array(&mut self) -> DSLResult<DSLValue> {
        // Consume the opening bracket
        self.consume(
            DSLTokenType::LeftBracket,
            "Expected '[' to start JSON array",
        )?;

        let mut array = Vec::new();

        // Check if the array is empty
        if self.match_token(DSLTokenType::RightBracket) {
            // match_token already advances the parser
            return Ok(DSLValue::Array(array));
        }

        loop {
            // Parse the value
            let value = self.parse_expression()?;
            array.push(value);

            // Check for comma or closing bracket
            if self.match_token(DSLTokenType::Comma) {
                // match_token already advances the parser
            } else if self.match_token(DSLTokenType::RightBracket) {
                break;
            } else {
                return Err(DSLError::syntax_error(
                    self.peek().column,
                    "Expected ',' or ']' in JSON array",
                ));
            }
        }

        Ok(DSLValue::Array(array))
    }

    fn parse_operator(&mut self) -> DSLResult<String> {
        match self.peek().token_type {
            DSLTokenType::Equals => {
                self.advance();
                Ok("==".to_string())
            }
            DSLTokenType::Assign => {
                self.advance();
                Ok("=".to_string())
            }
            DSLTokenType::NotEquals => {
                self.advance();
                Ok("!=".to_string())
            }
            DSLTokenType::LessThan => {
                self.advance();
                Ok("<".to_string())
            }
            DSLTokenType::LessThanOrEqual => {
                self.advance();
                Ok("<=".to_string())
            }
            DSLTokenType::GreaterThan => {
                self.advance();
                Ok(">".to_string())
            }
            DSLTokenType::GreaterThanOrEqual => {
                self.advance();
                Ok(">=".to_string())
            }
            _ => Err(DSLError::syntax_error(
                self.peek().column,
                format!("Expected operator, got {:?}", self.peek().token_type),
            )),
        }
    }

    fn consume(&mut self, token_type: DSLTokenType, message: &str) -> DSLResult<&DSLToken> {
        if self.check(token_type) {
            Ok(self.advance())
        } else {
            Err(DSLError::syntax_error(
                self.peek().column,
                message.to_string(),
            ))
        }
    }

    fn match_token(&mut self, token_type: DSLTokenType) -> bool {
        if self.check(token_type) {
            self.advance();
            true
        } else {
            false
        }
    }

    fn check(&self, token_type: DSLTokenType) -> bool {
        if self.is_at_end() {
            false
        } else {
            std::mem::discriminant(&self.peek().token_type) == std::mem::discriminant(&token_type)
        }
    }

    fn advance(&mut self) -> &DSLToken {
        if !self.is_at_end() {
            self.current += 1;
        }
        self.previous()
    }

    fn is_at_end(&self) -> bool {
        self.peek().token_type == DSLTokenType::EOF
    }

    fn peek(&self) -> &DSLToken {
        &self.tokens[self.current]
    }

    fn previous(&self) -> &DSLToken {
        &self.tokens[self.current - 1]
    }

    fn skip_semicolons(&mut self) {
        while self.match_token(DSLTokenType::Semicolon) {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ============================================================================
    // LEXER TESTS
    // ============================================================================

    #[test]
    fn test_lexer_new() {
        let lexer = DSLLexer::new("CREATE CLUSTER");
        assert_eq!(lexer.input.len(), 14);
        assert_eq!(lexer.position, 0);
        assert_eq!(lexer.line, 1);
        assert_eq!(lexer.column, 1);
    }

    #[test]
    fn test_lexer_tokenize_simple() {
        let mut lexer = DSLLexer::new("CREATE CLUSTER");
        let tokens = lexer.tokenize().unwrap();

        assert_eq!(tokens.len(), 3); // CREATE, CLUSTER, EOF
        assert_eq!(tokens[0].token_type, DSLTokenType::Create);
        assert_eq!(tokens[1].token_type, DSLTokenType::Cluster);
        assert_eq!(tokens[2].token_type, DSLTokenType::EOF);
    }

    #[test]
    fn test_lexer_tokenize_with_string() {
        let mut lexer = DSLLexer::new("CREATE CLUSTER \"test-cluster\"");
        let tokens = lexer.tokenize().unwrap();

        assert_eq!(tokens.len(), 4); // CREATE, CLUSTER, "test-cluster", EOF
        assert_eq!(tokens[0].token_type, DSLTokenType::Create);
        assert_eq!(tokens[1].token_type, DSLTokenType::Cluster);
        assert_eq!(
            tokens[2].token_type,
            DSLTokenType::String("test-cluster".to_string())
        );
    }

    #[test]
    fn test_lexer_tokenize_with_number() {
        let mut lexer = DSLLexer::new("SLEEP 5.5");
        let tokens = lexer.tokenize().unwrap();

        assert_eq!(tokens.len(), 3); // SLEEP, 5.5, EOF
        assert_eq!(tokens[0].token_type, DSLTokenType::Sleep);
        assert_eq!(tokens[1].token_type, DSLTokenType::Number(5.5));
    }

    #[test]
    fn test_lexer_tokenize_with_variable() {
        let mut lexer = DSLLexer::new("SET VARIABLE $my_var");
        let tokens = lexer.tokenize().unwrap();

        assert_eq!(tokens.len(), 4); // SET, VARIABLE, $my_var, EOF
        assert_eq!(tokens[0].token_type, DSLTokenType::Set);
        assert_eq!(tokens[1].token_type, DSLTokenType::Variable);
        assert_eq!(
            tokens[2].token_type,
            DSLTokenType::VariableRef("my_var".to_string())
        );
    }

    #[test]
    fn test_lexer_tokenize_with_hyphenated_identifier() {
        let mut lexer = DSLLexer::new("CREATE CLUSTER my-cluster-123");
        let tokens = lexer.tokenize().unwrap();

        assert_eq!(tokens.len(), 4); // CREATE, CLUSTER, my-cluster-123, EOF
        assert_eq!(tokens[0].token_type, DSLTokenType::Create);
        assert_eq!(tokens[1].token_type, DSLTokenType::Cluster);
        assert_eq!(
            tokens[2].token_type,
            DSLTokenType::Identifier("my-cluster-123".to_string())
        );
    }

    #[test]
    fn test_lexer_invalid_variable_name() {
        let mut lexer = DSLLexer::new("SET VARIABLE $rm");
        let result = lexer.tokenize();
        assert!(result.is_err());
    }

    #[test]
    fn test_lexer_variable_name_validation() {
        let lexer = DSLLexer::new("");

        // Valid variable names
        assert!(lexer.is_valid_variable_name("my_var"));
        assert!(lexer.is_valid_variable_name("test123"));
        assert!(lexer.is_valid_variable_name("_private"));

        // Invalid variable names
        assert!(!lexer.is_valid_variable_name(""));
        assert!(!lexer.is_valid_variable_name("rm"));
        assert!(!lexer.is_valid_variable_name("my$var"));
        assert!(!lexer.is_valid_variable_name("my;var"));
        assert!(!lexer.is_valid_variable_name(&"a".repeat(51))); // Too long
    }

    // ============================================================================
    // PARSER TESTS - CLUSTER MANAGEMENT COMMANDS (IMPLEMENTED)
    // ============================================================================

    #[test]
    fn test_parser_create_cluster_basic() {
        let result = DSLParser::parse("CREATE CLUSTER my-cluster IN \"aws-us-east-1\"");
        assert!(result.is_ok());
        let command = result.unwrap();
        assert_eq!(command.command_type, DSLCommandType::CreateCluster);
        assert_eq!(
            command.get_parameter_as_string("name").unwrap(),
            "my-cluster"
        );
        assert_eq!(
            command.get_parameter_as_string("region").unwrap(),
            "aws-us-east-1"
        );
    }

    #[test]
    fn test_parser_create_cluster_with_all_parameters() {
        let result = DSLParser::parse(
            "CREATE CLUSTER my-cluster IN \"aws-us-east-1\" WITH min_rcu=1000, max_rcu=5000, service_plan=PREMIUM, password=\"mypass123\"",
        );
        assert!(result.is_ok());
        let command = result.unwrap();
        assert_eq!(command.command_type, DSLCommandType::CreateCluster);
        assert_eq!(
            command.get_parameter_as_string("name").unwrap(),
            "my-cluster"
        );
        assert_eq!(
            command.get_parameter_as_string("region").unwrap(),
            "aws-us-east-1"
        );
        assert_eq!(command.get_parameter_as_number("min_rcu").unwrap(), 1000.0);
        assert_eq!(command.get_parameter_as_number("max_rcu").unwrap(), 5000.0);
        assert_eq!(
            command.get_parameter_as_string("service_plan").unwrap(),
            "PREMIUM"
        );
        assert_eq!(
            command.get_parameter_as_string("password").unwrap(),
            "mypass123"
        );
    }

    #[test]
    fn test_parser_create_cluster_with_numeric_rcu() {
        let result = DSLParser::parse(
            "CREATE CLUSTER my-cluster IN \"aws-us-east-1\" WITH min_rcu=5000, max_rcu=20000",
        );
        assert!(result.is_ok());
        let command = result.unwrap();
        assert_eq!(command.command_type, DSLCommandType::CreateCluster);
        assert_eq!(command.get_parameter_as_number("min_rcu").unwrap(), 5000.0);
        assert_eq!(command.get_parameter_as_number("max_rcu").unwrap(), 20000.0);
    }

    #[test]
    fn test_parser_create_cluster_with_string_rcu() {
        let result = DSLParser::parse(
            "CREATE CLUSTER my-cluster IN \"aws-us-east-1\" WITH min_rcu=\"1000\", max_rcu=\"5000\"",
        );
        assert!(result.is_ok());
        let command = result.unwrap();
        assert_eq!(command.command_type, DSLCommandType::CreateCluster);
        assert_eq!(command.get_parameter_as_string("min_rcu").unwrap(), "1000");
        assert_eq!(command.get_parameter_as_string("max_rcu").unwrap(), "5000");
    }

    #[test]
    fn test_parser_delete_cluster() {
        let result = DSLParser::parse("DELETE CLUSTER my-cluster");
        assert!(result.is_ok());
        let command = result.unwrap();
        assert_eq!(command.command_type, DSLCommandType::DeleteCluster);
        assert_eq!(
            command.get_parameter_as_string("name").unwrap(),
            "my-cluster"
        );
    }

    #[test]
    fn test_parser_list_clusters() {
        let result = DSLParser::parse("LIST CLUSTERS");
        assert!(result.is_ok());
        let command = result.unwrap();
        assert_eq!(command.command_type, DSLCommandType::ListClusters);
    }

    #[test]
    fn test_parser_get_cluster() {
        let result = DSLParser::parse("GET CLUSTER my-cluster");
        assert!(result.is_ok());
        let command = result.unwrap();
        assert_eq!(command.command_type, DSLCommandType::GetCluster);
        assert_eq!(
            command.get_parameter_as_string("name").unwrap(),
            "my-cluster"
        );
    }

    #[test]
    fn test_parser_update_cluster() {
        let result = DSLParser::parse("UPDATE CLUSTER my-cluster WITH max_rcu=10000");
        assert!(result.is_ok());
        let command = result.unwrap();
        assert_eq!(command.command_type, DSLCommandType::UpdateCluster);
        assert_eq!(
            command.get_parameter_as_string("name").unwrap(),
            "my-cluster"
        );
        assert_eq!(command.get_parameter_as_number("max_rcu").unwrap(), 10000.0);
    }

    // ============================================================================
    // PARSER TESTS - BACKUP MANAGEMENT COMMANDS (IMPLEMENTED)
    // ============================================================================

    #[test]
    fn test_parser_create_backup() {
        let result = DSLParser::parse("CREATE BACKUP FOR my-cluster");
        assert!(result.is_ok());
        let command = result.unwrap();
        assert_eq!(command.command_type, DSLCommandType::CreateBackup);
        assert_eq!(
            command.get_parameter_as_string("cluster_name").unwrap(),
            "my-cluster"
        );
    }

    #[test]
    fn test_parser_create_backup_with_description() {
        let result =
            DSLParser::parse("CREATE BACKUP FOR my-cluster WITH description=\"Daily backup\"");
        assert!(result.is_ok());
        let command = result.unwrap();
        assert_eq!(command.command_type, DSLCommandType::CreateBackup);
        assert_eq!(
            command.get_parameter_as_string("cluster_name").unwrap(),
            "my-cluster"
        );
        assert_eq!(
            command.get_parameter_as_string("description").unwrap(),
            "Daily backup"
        );
    }

    #[test]
    fn test_parser_list_backups() {
        let result = DSLParser::parse("LIST BACKUPS FOR my-cluster");
        assert!(result.is_ok());
        let command = result.unwrap();
        assert_eq!(command.command_type, DSLCommandType::ListBackups);
        assert_eq!(
            command.get_parameter_as_string("cluster_name").unwrap(),
            "my-cluster"
        );
    }

    #[test]
    fn test_parser_delete_backup() {
        let result = DSLParser::parse("DELETE BACKUP backup-123 FROM my-cluster");
        assert!(result.is_ok());
        let command = result.unwrap();
        assert_eq!(command.command_type, DSLCommandType::DeleteBackup);
        assert_eq!(
            command.get_parameter_as_string("backup_id").unwrap(),
            "backup-123"
        );
        assert_eq!(
            command.get_parameter_as_string("cluster_name").unwrap(),
            "my-cluster"
        );
    }

    // ============================================================================
    // PARSER TESTS - VARIABLE COMMANDS (IMPLEMENTED)
    // ============================================================================

    #[test]
    fn test_parser_set_variable_with_keyword_name() {
        let result = DSLParser::parse("SET region = \"aws-us-east-1\"");
        assert!(result.is_ok());
        let command = result.unwrap();
        assert_eq!(command.command_type, DSLCommandType::SetVariable);
        assert_eq!(command.get_parameter_as_string("name").unwrap(), "region");
        assert_eq!(
            command.get_parameter_as_string("value").unwrap(),
            "aws-us-east-1"
        );
    }

    #[test]
    fn test_parser_set_log_level() {
        let result = DSLParser::parse("SET LOG-LEVEL debug");
        assert!(result.is_ok());
        let command = result.unwrap();
        assert_eq!(command.command_type, DSLCommandType::SetLogLevel);
        assert_eq!(command.get_parameter_as_string("level").unwrap(), "debug");
    }

    #[test]
    fn test_parser_set_log_level_with_quotes() {
        let result = DSLParser::parse("SET LOG-LEVEL 'info'");
        assert!(result.is_ok());
        let command = result.unwrap();
        assert_eq!(command.command_type, DSLCommandType::SetLogLevel);
        assert_eq!(command.get_parameter_as_string("level").unwrap(), "info");
    }

    #[test]
    fn test_parser_wait_command_with_keyword_state() {
        let result = DSLParser::parse("WAIT FOR SB-Test01-delete-whenever TO BE Active");
        assert!(result.is_ok());
        let command = result.unwrap();
        assert_eq!(command.command_type, DSLCommandType::WaitForCluster);
        assert_eq!(
            command.get_parameter_as_string("name").unwrap(),
            "SB-Test01-delete-whenever"
        );
        assert_eq!(command.get_parameter_as_string("state").unwrap(), "active");
    }

    #[test]
    fn test_parser_wait_command_case_insensitive_states() {
        // Test different case variations - all should parse to lowercase
        let test_cases = vec![
            ("WAIT FOR cluster TO BE Active", "active"),
            ("WAIT FOR cluster TO BE active", "active"),
            ("WAIT FOR cluster TO BE ACTIVE", "active"),
        ];

        for (input, expected_state) in test_cases {
            let result = DSLParser::parse(input);
            assert!(result.is_ok(), "Failed to parse: {}", input);
            let command = result.unwrap();
            assert_eq!(command.command_type, DSLCommandType::WaitForCluster);
            assert_eq!(
                command.get_parameter_as_string("state").unwrap(),
                expected_state,
                "Failed for input: {}",
                input
            );
        }
    }

    // ============================================================================
    // PARSER TESTS - UTILITY COMMANDS (IMPLEMENTED)
    // ============================================================================

    #[test]
    fn test_parser_echo() {
        let result = DSLParser::parse("ECHO \"Hello, World!\"");
        assert!(result.is_ok());
        let command = result.unwrap();
        assert_eq!(command.command_type, DSLCommandType::Echo);
        assert_eq!(
            command.get_parameter_as_string("message").unwrap(),
            "Hello, World!"
        );
    }

    #[test]
    fn test_parser_echo_with_variable() {
        let result = DSLParser::parse("ECHO $my_var");
        assert!(result.is_ok());
        let command = result.unwrap();
        assert_eq!(command.command_type, DSLCommandType::Echo);
        assert_eq!(
            command.get_parameter_as_string("message").unwrap(),
            "$my_var"
        );
    }

    #[test]
    fn test_parser_sleep() {
        let result = DSLParser::parse("SLEEP 5.5");
        assert!(result.is_ok());
        let command = result.unwrap();
        assert_eq!(command.command_type, DSLCommandType::Sleep);
        assert_eq!(command.get_parameter_as_number("seconds").unwrap(), 5.5);
    }

    #[test]
    fn test_parser_sleep_with_units() {
        let result = DSLParser::parse("SLEEP 2 MINUTES");
        assert!(result.is_ok());
        let command = result.unwrap();
        assert_eq!(command.command_type, DSLCommandType::Sleep);
        assert_eq!(command.get_parameter_as_number("seconds").unwrap(), 2.0);
    }

    // ============================================================================
    // PARSER TESTS - EXPRESSIONS AND VALUES (IMPLEMENTED)
    // ============================================================================

    #[test]
    fn test_parser_expression_string() {
        let result = DSLParser::parse("ECHO \"test string\"");
        assert!(result.is_ok());
        let command = result.unwrap();
        assert_eq!(
            command.get_parameter_as_string("message").unwrap(),
            "test string"
        );
    }

    #[test]
    fn test_parser_expression_number() {
        let result = DSLParser::parse("SLEEP 42.5");
        assert!(result.is_ok());
        let command = result.unwrap();
        assert_eq!(command.get_parameter_as_number("seconds").unwrap(), 42.5);
    }

    #[test]
    fn test_parser_expression_variable() {
        let result = DSLParser::parse("ECHO $my_var");
        assert!(result.is_ok());
        let command = result.unwrap();
        assert_eq!(
            command.get_parameter_as_string("message").unwrap(),
            "$my_var"
        );
    }

    // ============================================================================
    // PARSER TESTS - SCRIPTS AND MULTIPLE COMMANDS (IMPLEMENTED)
    // ============================================================================

    #[test]
    fn test_parser_script_simple() {
        let script = "ECHO \"Hello\";\nSLEEP 1.0;";
        let result = DSLParser::parse_script(script);
        assert!(result.is_ok());
        let commands = result.unwrap();
        assert_eq!(commands.len(), 2);
        assert_eq!(commands[0].command_type, DSLCommandType::Echo);
        assert_eq!(commands[1].command_type, DSLCommandType::Sleep);
    }

    // ============================================================================
    // PARSER TESTS - EDGE CASES AND ERROR CONDITIONS (IMPLEMENTED)
    // ============================================================================

    #[test]
    fn test_parser_input_too_long() {
        let long_input = "CREATE CLUSTER ".repeat(1000); // Much longer than 10,000 chars
        let result = DSLParser::parse(&long_input);
        assert!(result.is_err());
    }

    #[test]
    fn test_parser_invalid_command() {
        let result = DSLParser::parse("INVALID COMMAND");
        assert!(result.is_err());
    }

    #[test]
    fn test_parser_missing_parameter() {
        let result = DSLParser::parse("CREATE CLUSTER");
        assert!(result.is_err());
    }

    #[test]
    fn test_parser_missing_required_parameter() {
        let result = DSLParser::parse("CREATE CLUSTER my-cluster");
        assert!(result.is_err()); // Missing IN clause
    }

    #[test]
    fn test_parser_invalid_syntax() {
        let result = DSLParser::parse("CREATE CLUSTER my-cluster IN");
        assert!(result.is_err()); // Missing region
    }

    // ============================================================================
    // PARSER TESTS - WHITESPACE AND FORMATTING (IMPLEMENTED)
    // ============================================================================

    #[test]
    fn test_parser_extra_whitespace() {
        let result = DSLParser::parse("  CREATE  CLUSTER  my-cluster  IN  \"aws-us-east-1\"  ");
        assert!(result.is_ok());
        let command = result.unwrap();
        assert_eq!(command.command_type, DSLCommandType::CreateCluster);
        assert_eq!(
            command.get_parameter_as_string("name").unwrap(),
            "my-cluster"
        );
        assert_eq!(
            command.get_parameter_as_string("region").unwrap(),
            "aws-us-east-1"
        );
    }

    #[test]
    fn test_parser_newlines() {
        let result = DSLParser::parse("CREATE\nCLUSTER\nmy-cluster\nIN\n\"aws-us-east-1\"");
        assert!(result.is_ok());
        let command = result.unwrap();
        assert_eq!(command.command_type, DSLCommandType::CreateCluster);
        assert_eq!(
            command.get_parameter_as_string("name").unwrap(),
            "my-cluster"
        );
        assert_eq!(
            command.get_parameter_as_string("region").unwrap(),
            "aws-us-east-1"
        );
    }

    #[test]
    fn test_parser_tabs() {
        let result = DSLParser::parse("CREATE\tCLUSTER\tmy-cluster\tIN\t\"aws-us-east-1\"");
        assert!(result.is_ok());
        let command = result.unwrap();
        assert_eq!(command.command_type, DSLCommandType::CreateCluster);
        assert_eq!(
            command.get_parameter_as_string("name").unwrap(),
            "my-cluster"
        );
        assert_eq!(
            command.get_parameter_as_string("region").unwrap(),
            "aws-us-east-1"
        );
    }

    // ============================================================================
    // PARSER TESTS - SPECIAL CHARACTERS AND ESCAPING (IMPLEMENTED)
    // ============================================================================

    #[test]
    fn test_parser_string_with_backslashes() {
        let result = DSLParser::parse("ECHO \"C:\\path\\to\\file\"");
        assert!(result.is_ok());
        let command = result.unwrap();
        assert_eq!(
            command.get_parameter_as_string("message").unwrap(),
            "C:\\path\\to\\file"
        );
    }

    #[test]
    fn test_parser_identifier_with_special_chars() {
        let result = DSLParser::parse("CREATE CLUSTER my-cluster_123 IN \"aws-us-east-1\"");
        assert!(result.is_ok());
        let command = result.unwrap();
        assert_eq!(
            command.get_parameter_as_string("name").unwrap(),
            "my-cluster_123"
        );
    }

    // ============================================================================
    // PARSER TESTS - NUMERIC VALUES AND UNITS (IMPLEMENTED)
    // ============================================================================

    #[test]
    fn test_parser_integer_values() {
        let result = DSLParser::parse("SLEEP 42");
        assert!(result.is_ok());
        let command = result.unwrap();
        assert_eq!(command.get_parameter_as_number("seconds").unwrap(), 42.0);
    }

    #[test]
    fn test_parser_float_values() {
        let result = DSLParser::parse("SLEEP 3.14159");
        assert!(result.is_ok());
        let command = result.unwrap();
        assert_eq!(command.get_parameter_as_number("seconds").unwrap(), 3.14159);
    }

    // ============================================================================
    // PARSER TESTS - COMPLEX SCENARIOS (IMPLEMENTED)
    // ============================================================================

    #[test]
    fn test_parser_complex_cluster_creation() {
        let result = DSLParser::parse(
            "CREATE CLUSTER production-cluster IN \"aws-us-west-2\" WITH min_rcu=5000, max_rcu=20000, service_plan=ENTERPRISE, password=\"SecurePass123!\"",
        );
        assert!(result.is_ok());
        let command = result.unwrap();
        assert_eq!(command.command_type, DSLCommandType::CreateCluster);
        assert_eq!(
            command.get_parameter_as_string("name").unwrap(),
            "production-cluster"
        );
        assert_eq!(
            command.get_parameter_as_string("region").unwrap(),
            "aws-us-west-2"
        );
        assert_eq!(command.get_parameter_as_number("min_rcu").unwrap(), 5000.0);
        assert_eq!(command.get_parameter_as_number("max_rcu").unwrap(), 20000.0);
        assert_eq!(
            command.get_parameter_as_string("service_plan").unwrap(),
            "ENTERPRISE"
        );
        assert_eq!(
            command.get_parameter_as_string("password").unwrap(),
            "SecurePass123!"
        );
    }

    #[test]
    fn test_parser_json_object() {
        let input = "UPDATE CLUSTER my-cluster WITH public_connection={enabled: true, \"ipAccessList\": [{cidrNotation: \"10.10.1.1/21\", description: \"my ip address\"}]}";
        let result = DSLParser::parse(input);
        if let Err(e) = &result {
            println!("Parse error: {:?}", e);
        }
        assert!(result.is_ok());
        let command = result.unwrap();
        assert_eq!(command.command_type, DSLCommandType::UpdateCluster);
        assert_eq!(
            command.get_parameter_as_string("name").unwrap(),
            "my-cluster"
        );

        let public_connection = command.get_parameter("public_connection").unwrap();
        if let DSLValue::Object(obj) = public_connection {
            assert_eq!(obj.get("enabled").and_then(|v| v.as_boolean()), Some(true));

            if let Some(DSLValue::Array(ip_list)) = obj.get("ipAccessList") {
                assert_eq!(ip_list.len(), 1);
                if let Some(DSLValue::Object(ip_obj)) = ip_list.first() {
                    assert_eq!(
                        ip_obj.get("cidrNotation").and_then(|v| v.as_string()),
                        Some("10.10.1.1/21")
                    );
                    assert_eq!(
                        ip_obj.get("description").and_then(|v| v.as_string()),
                        Some("my ip address")
                    );
                }
            }
        } else {
            panic!("Expected object for public_connection");
        }
    }

    #[test]
    fn test_parser_json_array() {
        let input = "SET my_array = [1, 2, 3, \"hello\", true]";
        let result = DSLParser::parse(input);
        assert!(result.is_ok());
        let command = result.unwrap();
        assert_eq!(command.command_type, DSLCommandType::SetVariable);

        // Check that the variable name is correct
        assert_eq!(command.get_parameter_as_string("name").unwrap(), "my_array");

        // Check that the value is an array
        let array_value = command.get_parameter("value").unwrap();
        if let DSLValue::Array(arr) = array_value {
            assert_eq!(arr.len(), 5);
            assert_eq!(arr[0].as_number(), Some(1.0));
            assert_eq!(arr[1].as_number(), Some(2.0));
            assert_eq!(arr[2].as_number(), Some(3.0));
            assert_eq!(arr[3].as_string(), Some("hello"));
            assert_eq!(arr[4].as_boolean(), Some(true));
        } else {
            panic!("Expected array for value");
        }
    }

    #[test]
    fn test_lexer_json_tokens() {
        let input = "{enabled: true, \"ipAccessList\": [{cidrNotation: \"10.10.1.1/21\", description: \"my ip address\"}]}";
        let mut lexer = DSLLexer::new(input);
        let tokens = lexer.tokenize().unwrap();

        println!("Tokens:");
        for (i, token) in tokens.iter().enumerate() {
            println!("  {}: {:?} - '{}'", i, token.token_type, token.lexeme);
        }

        // Verify we get the expected tokens
        assert_eq!(tokens[0].token_type, DSLTokenType::LeftBrace);
        assert_eq!(
            tokens[1].token_type,
            DSLTokenType::Identifier("enabled".to_string())
        );
        assert_eq!(tokens[2].token_type, DSLTokenType::Colon);
        assert_eq!(tokens[3].token_type, DSLTokenType::True);
        assert_eq!(tokens[4].token_type, DSLTokenType::Comma);
        assert_eq!(
            tokens[5].token_type,
            DSLTokenType::String("ipAccessList".to_string())
        );
        assert_eq!(tokens[6].token_type, DSLTokenType::Colon);
    }

    #[test]
    fn test_parser_json_object_simple() {
        let input = "UPDATE CLUSTER my-cluster WITH public_connection={enabled: true, \"ipAccessList\": []}";
        let mut lexer = DSLLexer::new(input);
        let tokens = lexer.tokenize().unwrap();

        println!("Full command tokens:");
        for (i, token) in tokens.iter().enumerate() {
            println!("  {}: {:?} - '{}'", i, token.token_type, token.lexeme);
        }

        let result = DSLParser::parse(input);
        if let Err(e) = &result {
            println!("Parse error: {:?}", e);
        }
        assert!(result.is_ok());
    }

    #[test]
    fn test_parser_json_object_only() {
        let input = "{enabled: true, \"ipAccessList\": []}";
        let mut lexer = DSLLexer::new(input);
        let tokens = lexer.tokenize().unwrap();

        println!("JSON object tokens:");
        for (i, token) in tokens.iter().enumerate() {
            println!("  {}: {:?} - '{}'", i, token.token_type, token.lexeme);
        }

        let mut parser = DSLParser::new(tokens);
        let result = parser.parse_json_object();
        if let Err(e) = &result {
            println!("Parse error: {:?}", e);
        }
        assert!(result.is_ok());
    }

    #[test]
    fn test_parser_json_object_simple_keys() {
        let input = "{enabled: true, ipAccessList: []}";
        let mut lexer = DSLLexer::new(input);
        let tokens = lexer.tokenize().unwrap();

        println!("Simple JSON object tokens:");
        for (i, token) in tokens.iter().enumerate() {
            println!("  {}: {:?} - '{}'", i, token.token_type, token.lexeme);
        }

        let mut parser = DSLParser::new(tokens);
        let result = parser.parse_json_object();
        if let Err(e) = &result {
            println!("Parse error: {:?}", e);
        }
        assert!(result.is_ok());
    }
}
