# SQL-like DSL Syntax for TiDB Cloud CLI

This document describes the SQL-like syntax for the TiDB Cloud CLI DSL, which provides a familiar interface for users accustomed to SQL while maintaining full compatibility with the existing DSL parser. The implementation includes a powerful Reverse Polish Notation (RPN) based condition evaluator for complex WHERE clauses.

## Overview

The SQL-like parser transforms SQL-style commands into the existing DSL syntax, allowing users to use familiar SQL patterns while leveraging the robust existing parser infrastructure. The WHERE clause evaluation uses an advanced RPN-based system that supports complex boolean expressions with proper operator precedence.

**Supported SQL-like commands:**
- `SELECT * FROM CLUSTER [WHERE condition]` - List clusters with advanced filtering
- `CREATE CLUSTER name IN region [WITH options]` - Create clusters
- `UPDATE CLUSTER name SET field = value` - Update cluster properties
- `DROP CLUSTER name` - Delete clusters
- `WAIT FOR CLUSTER name TO BE state` - Wait for cluster state changes
- `SET LOG-LEVEL level` - Change logging verbosity dynamically

## Advanced WHERE Clause Evaluation

The WHERE clause supports complex boolean expressions using a Reverse Polish Notation (RPN) based evaluator with the following capabilities:

### Supported Operators

**Logical Operators:**
- `AND` - Logical AND
- `OR` - Logical OR  
- `NOT` - Logical NOT

**Comparison Operators:**
- `=` - Equal to
- `!=` - Not equal to
- `<` - Less than
- `<=` - Less than or equal to
- `>` - Greater than
- `>=` - Greater than or equal to
- `IN` - Check if value is in a list

**Pattern Matching:**
- `*` - Wildcard pattern (e.g., `name = test*`)
- `/pattern/` - Regular expression (e.g., `name = /test.*/`)

### Operator Precedence

The RPN evaluator implements proper operator precedence (highest to lowest):

1. **Comparison operators** (`=`, `!=`, `<`, `<=`, `>`, `>=`) - precedence 4
2. **NOT** - precedence 3  
3. **AND** - precedence 2
4. **OR** - precedence 1

**Examples:**
```sql
-- AND has higher precedence than OR
SELECT * FROM CLUSTER WHERE name = test-cluster AND state = ACTIVE OR region = us-west-2
-- Equivalent to: (name = test-cluster AND state = ACTIVE) OR region = us-west-2

-- NOT has higher precedence than AND
SELECT * FROM CLUSTER WHERE NOT name = other-cluster AND state = ACTIVE
-- Equivalent to: (NOT name = other-cluster) AND state = ACTIVE

-- Parentheses override precedence
SELECT * FROM CLUSTER WHERE (name = test-cluster OR name = other-cluster) AND state = ACTIVE
-- Explicitly groups the OR expression before AND
```

### Complex WHERE Clause Examples

```sql
-- Simple conditions
SELECT * FROM CLUSTER WHERE name = test-cluster
SELECT * FROM CLUSTER WHERE state = ACTIVE
SELECT * FROM CLUSTER WHERE region = us-east-1

-- Logical operators
SELECT * FROM CLUSTER WHERE name = test-cluster AND state = ACTIVE
SELECT * FROM CLUSTER WHERE name = test-cluster OR state = FAILED
SELECT * FROM CLUSTER WHERE NOT (state = FAILED)

-- Complex expressions with parentheses
SELECT * FROM CLUSTER WHERE (name = test* OR name = prod*) AND (state = ACTIVE OR state = CREATING)
SELECT * FROM CLUSTER WHERE name = /test.*/ AND (region = us-east-1 OR region = us-west-2)

-- Pattern matching
SELECT * FROM CLUSTER WHERE name = test*          -- Wildcard pattern
SELECT * FROM CLUSTER WHERE name = /test.*/       -- Regular expression
SELECT * FROM CLUSTER WHERE name = /.*cluster/    -- Regex with anchors

-- IN operator with arrays
SELECT * FROM CLUSTER WHERE state IN ['ACTIVE', 'CREATING', 'UPDATING']
SELECT * FROM CLUSTER WHERE region IN ['us-west-1', 'us-east-1']
SELECT * FROM CLUSTER WHERE name IN ['test-cluster', 'prod-cluster']

-- Mixed conditions
SELECT * FROM CLUSTER WHERE name = test* AND (state = ACTIVE OR state = CREATING) AND NOT (state = FAILED)
```

## Supported Commands

### SELECT Commands

**Syntax:**
```sql
SELECT * FROM CLUSTER [WHERE condition]
SELECT field1, field2 FROM CLUSTER [WHERE condition]
SELECT field1, field2 INTO var1, var2 FROM CLUSTER [WHERE condition]
```

**Examples:**
```sql
-- List all clusters
SELECT * FROM CLUSTER

-- List clusters with specific fields
SELECT name, region, state FROM CLUSTER

-- List clusters with simple filter
SELECT * FROM CLUSTER WHERE state = 'active'
SELECT * FROM CLUSTER WHERE region = 'aws-us-west-1' AND state = 'active'

-- Complex filtering with RPN evaluation
SELECT * FROM CLUSTER WHERE (name = test* OR name = prod*) AND (state = ACTIVE OR state = CREATING)
SELECT * FROM CLUSTER WHERE name = /test.*/ AND NOT (state = FAILED OR state = DELETED)
SELECT * FROM CLUSTER WHERE state IN ['ACTIVE', 'CREATING'] AND region IN ['us-west-1', 'us-east-1']

-- Store cluster data in variables
SELECT display_name INTO cluster_name FROM CLUSTER WHERE state = 'active'
SELECT display_name, region INTO cluster_name, cluster_region FROM CLUSTER
```

**Transforms to:**
```dsl
LIST CLUSTERS
LIST CLUSTERS WHERE state = 'active'
LIST CLUSTERS WHERE (name = test* OR name = prod*) AND (state = ACTIVE OR state = CREATING)
LIST CLUSTERS WHERE state = 'active' INTO cluster_name
LIST CLUSTERS INTO cluster_name, cluster_region
```

**Features:**
- ✅ **Advanced filtering**: Complex boolean expressions with proper operator precedence
- ✅ **Pattern matching**: Wildcard and regex support
- ✅ **IN operator**: Check if values are in a list of options
- ✅ **Variable assignment**: Store cluster data in variables for later use
- ✅ **Multiple variables**: Assign multiple fields to multiple variables
- ✅ **Combined with WHERE**: Filter clusters and store results in variables
- ✅ **Flexible syntax**: Works with any number of field-variable pairs

**Notes:**
- The `INTO` clause stores the first matching cluster's data in the specified variables
- Variables can be used in subsequent commands using `$variable_name` syntax
- If no clusters match the WHERE condition, variables remain unchanged
- Complex WHERE clauses are evaluated using the RPN-based condition evaluator

### CREATE Commands

**Syntax:**
```sql
CREATE CLUSTER name IN region [WITH options]
```

**Examples:**
```sql
-- Create a basic cluster
CREATE CLUSTER my-cluster IN 'aws-us-west-1'

-- Create cluster with options
CREATE CLUSTER my-cluster IN 'aws-us-west-1' WITH min_rcu = 1000, max_rcu = 5000
```

**Transforms to:**
```dsl
CREATE CLUSTER my-cluster IN 'aws-us-west-1'
CREATE CLUSTER my-cluster IN 'aws-us-west-1' WITH min_rcu = 1000, max_rcu = 5000
```

**Valid Parameters:**
The `WITH` clause only accepts parameters that correspond to valid JSON attributes in the TiDB Cloud API:

- **Required:** `name`, `region`
- **Optional:** `min_rcu`, `max_rcu`, `plan` (or `service_plan`), `root_password` (or `password`), `high_availability_type`, `annotations`, `labels`, `public_connection`

**Parameter Validation:**
- Invalid parameters will result in clear error messages listing all allowed parameters
- Only parameters that map to actual API fields are accepted
- This prevents typos and ensures API compatibility

### SET LOG-LEVEL Commands

**Syntax:**
```sql
SET LOG-LEVEL level
```

**Examples:**
```sql
-- Set log level to debug for more verbose output
SET LOG-LEVEL debug

-- Set log level to trace for maximum verbosity
SET LOG-LEVEL trace

-- Set log level to info for standard output
SET LOG-LEVEL info

-- Set log level to warn for warnings and errors only
SET LOG-LEVEL warn

-- Set log level to error for errors only
SET LOG-LEVEL error
```

**Transforms to:**
```dsl
SET LOG-LEVEL debug
SET LOG-LEVEL trace
SET LOG-LEVEL info
SET LOG-LEVEL warn
SET LOG-LEVEL error
```

**Features:**
- ✅ **Dynamic changes**: Change log level during interactive sessions
- ✅ **Global state management**: Updates thread-safe global log level state
- ✅ **Validation**: Only accepts valid log levels (trace, debug, info, warn, error)
- ✅ **Case insensitive**: Works with any case (DEBUG, debug, Debug)
- ✅ **Error handling**: Clear error messages for invalid levels
- ✅ **No global dispatcher conflicts**: Avoids the "global default trace dispatcher already set" error
- ⚠️ **Limited scope**: Currently only affects custom logging functions, not existing tracing macros

**Available Log Levels:**
- **`trace`**: Most verbose - shows all log messages including internal details
- **`debug`**: Detailed debugging information - shows function calls and data flow
- **`info`**: Standard information - shows important operations and status
- **`warn`**: Warnings only - shows warnings and errors
- **`error`**: Errors only - shows only error messages

**Use Cases:**
- **Debugging**: Use `SET LOG-LEVEL debug` to see detailed API calls and responses
- **Troubleshooting**: Use `SET LOG-LEVEL trace` to see internal system details
- **Production**: Use `SET LOG-LEVEL warn` or `SET LOG-LEVEL error` for minimal output
- **Development**: Use `SET LOG-LEVEL info` for balanced information

**Notes:**
- The log level change updates the global state and provides immediate feedback
- The change is not persistent across CLI restarts
- Invalid log levels result in clear error messages
- The command provides immediate feedback on success or failure
- Uses thread-safe global state management to avoid tracing system conflicts
- **Current limitation**: Only affects custom logging functions, not existing `tracing!` macros
- **Future enhancement**: Could be extended to affect all tracing macros with a custom layer implementation

### UPDATE Commands

**Syntax:**
```sql
UPDATE CLUSTER name SET field1 = value1 [, field2 = value2]*
```

**Features:**
- ✅ **Multiple fields**: Update multiple fields in a single command
- ✅ **Comma-separated**: Fields are separated by commas
- ✅ **Mixed types**: Supports numbers, strings, and other data types
- ✅ **Flexible syntax**: Works with any number of field-value pairs

**Examples:**
```sql
-- Update single field
UPDATE CLUSTER my-cluster SET min_rcu = 2000

-- Update multiple fields (comma-separated)
UPDATE CLUSTER my-cluster SET min_rcu = 2000, max_rcu = 6000

-- Update multiple fields with different types
UPDATE CLUSTER my-cluster SET min_rcu = 2000, max_rcu = 6000, service_plan = 'premium'

-- Update with string values
UPDATE CLUSTER my-cluster SET region = 'aws-us-east-1', service_plan = 'enterprise'
```

**Transforms to:**
```dsl
UPDATE CLUSTER my-cluster WITH min_rcu = 2000
UPDATE CLUSTER my-cluster WITH min_rcu = 2000, max_rcu = 6000
UPDATE CLUSTER my-cluster WITH min_rcu = 2000, max_rcu = 6000, service_plan = 'premium'
UPDATE CLUSTER my-cluster WITH region = 'aws-us-east-1', service_plan = 'enterprise'
```

**Notes:**
- Multiple fields can be updated in a single command
- Fields are separated by commas

### DROP Commands

**Syntax:**
```sql
DROP CLUSTER name
```

**Examples:**
```sql
DROP CLUSTER my-cluster
DROP CLUSTER test-cluster-123
```

**Transforms to:**
```dsl
DELETE CLUSTER my-cluster
DELETE CLUSTER test-cluster-123
```

**Notes:**
- This is a destructive operation that permanently deletes the cluster
- Use with caution as this action cannot be undone

### WAIT Commands

**Syntax:**
```sql
WAIT FOR CLUSTER name TO BE state [WITH timeout]
```

**Examples:**
```sql
-- Wait for cluster to be active
WAIT FOR CLUSTER my-cluster TO BE active

-- Wait with timeout
WAIT FOR CLUSTER my-cluster TO BE active WITH timeout = 300
```

**Transforms to:**
```dsl
WAIT FOR my-cluster TO BE active
WAIT FOR my-cluster TO BE active WITH timeout = 300
```

## RPN-Based WHERE Clause Implementation

### How It Works

The RPN-based condition evaluator processes WHERE clauses in three stages:

#### 1. Tokenization
The WHERE clause is parsed into tokens:
- `Field` - Field names (e.g., `name`, `state`, `region`)
- `Value` - Literal values (e.g., `"test-cluster"`, `ACTIVE`)
- `Operator` - Comparison operators (e.g., `=`, `!=`, `<`)
- `And`, `Or`, `Not` - Logical operators
- `LeftParen`, `RightParen` - Parentheses for grouping

#### 2. Infix to RPN Conversion
The infix expression is converted to Reverse Polish Notation using the Shunting Yard algorithm with proper operator precedence:

**Example:**
**Infix:** `(name = test* OR name = prod*) AND (state = ACTIVE OR state = CREATING)`

**RPN:** `name test* = name prod* = OR state ACTIVE = state CREATING = OR AND`

#### 3. RPN Evaluation
The RPN expression is evaluated using a stack-based approach:
- Push operands (fields/values) onto the stack
- When an operator is encountered, pop operands, apply the operator, and push the result
- Final result is the boolean value indicating if the condition is true

### Implementation Details

#### Core Components

1. **ConditionToken Enum**
   ```rust
   enum ConditionToken {
       Field(String),
       Operator(String),
       Value(DSLValue),
       And,
       Or,
       Not,
       LeftParen,
       RightParen,
   }
   ```

2. **Infix to RPN Conversion**
   - Uses Shunting Yard algorithm
   - Handles operator precedence
   - Supports parentheses for explicit grouping

3. **RPN Evaluation**
   - Stack-based evaluation
   - Field value resolution from cluster data
   - Operator application with error handling

4. **Operator Support**
   - Comparison operators with string comparison
   - Wildcard pattern matching
   - Regular expression matching
   - Logical operators with short-circuit evaluation

#### Error Handling

The evaluator provides comprehensive error handling for:
- Unknown fields
- Invalid operators
- Mismatched parentheses
- Invalid regex patterns
- Insufficient operands

#### Backward Compatibility

The implementation maintains backward compatibility with the existing simple filter format while adding support for complex expressions.

#### Performance Considerations

- RPN evaluation is O(n) where n is the number of tokens
- Field value resolution is cached per cluster
- Regular expressions are compiled once per pattern
- Short-circuit evaluation for logical operators

## Usage

### In Code

```rust
use tidb_cli::dsl::sql_parser::SQLDSLParser;

// Parse SQL-like commands with complex WHERE clauses
let command = SQLDSLParser::parse("SELECT * FROM CLUSTER WHERE (name = test* OR name = prod*) AND state = 'active'")?;

// Parse scripts with multiple commands
let commands = SQLDSLParser::parse_script(r#"
    SELECT * FROM CLUSTER WHERE state = 'active';
    CREATE CLUSTER my-cluster IN 'aws-us-west-1' WITH min_rcu = 1000;
    WAIT FOR CLUSTER my-cluster TO BE active;
"#)?;

// Transform SQL to DSL syntax
let dsl_syntax = SQLDSLParser::transform_sql_to_dsl("SELECT * FROM CLUSTER")?;
// Returns: "LIST CLUSTERS"
```

### Command Line

The SQL-like syntax can be used directly in the CLI:

```bash
# List all clusters
tidb-dsl> SELECT * FROM CLUSTER

# List clusters with complex filtering
tidb-dsl> SELECT * FROM CLUSTER WHERE (name = test* OR name = prod*) AND (state = ACTIVE OR state = CREATING)
tidb-dsl> SELECT * FROM CLUSTER WHERE state IN ['ACTIVE', 'CREATING', 'UPDATING']

# Create a cluster
tidb-dsl> CREATE CLUSTER my-cluster IN 'aws-us-west-1' WITH min_rcu = 1000, max_rcu = 5000

# Update a cluster
tidb-dsl> UPDATE CLUSTER my-cluster SET min_rcu = 2000

# Wait for cluster state
tidb-dsl> WAIT FOR CLUSTER my-cluster TO BE active
```

## Benefits

1. **Familiarity**: Users familiar with SQL can immediately use the CLI without learning new syntax
2. **Advanced Filtering**: Complex WHERE clauses with proper operator precedence and pattern matching
3. **Compatibility**: Full compatibility with existing DSL parser and infrastructure
4. **Consistency**: Maintains the same command types and parameter handling
5. **Extensibility**: Easy to add new SQL-like commands by extending the transformation logic

## Implementation Details

The SQL-like parser works by:

1. **Transformation**: Converting SQL syntax to existing DSL syntax
2. **Parsing**: Using the existing DSL parser to parse the transformed commands
3. **RPN Evaluation**: Processing complex WHERE clauses using the RPN-based evaluator
4. **Execution**: Executing the commands using the existing DSL executor

This approach ensures:
- No changes to the core parser infrastructure
- Full compatibility with existing features
- Advanced filtering capabilities
- Easy testing and maintenance
- Consistent error handling

## Testing

The implementation includes comprehensive tests covering:
- Simple field comparisons
- Logical operators (AND, OR, NOT)
- Parentheses and operator precedence
- Pattern matching (wildcards and regex)
- Complex expressions
- Error conditions
- SQL-like syntax transformation
- RPN evaluation accuracy

## Future Enhancements

Potential future enhancements could include:

- Support for more SQL-like commands (INSERT, ALTER, etc.)
- Subqueries and complex WHERE clauses
- JOIN-like operations for cross-resource queries
- Aggregation functions (COUNT, SUM, etc.)
- ORDER BY and LIMIT clauses
- Support for arithmetic expressions
- Function calls (e.g., `LENGTH(name) > 10`)
- More data types (numbers, dates, etc.)

## Examples

### Complete Workflow with Advanced Filtering

```sql
-- 1. List existing clusters with complex filtering
SELECT * FROM CLUSTER WHERE (name = test* OR name = prod*) AND (state = ACTIVE OR state = CREATING)
SELECT * FROM CLUSTER WHERE state IN ['ACTIVE', 'CREATING', 'UPDATING'] AND region IN ['us-west-1', 'us-east-1']

-- 2. Store first active cluster's details
SELECT display_name, region INTO cluster_name, cluster_region FROM CLUSTER WHERE state = 'active'

-- 3. Create a new cluster
CREATE CLUSTER test-cluster IN 'aws-us-west-1' WITH min_rcu = 1000, max_rcu = 5000

-- 4. Wait for cluster to be ready
WAIT FOR CLUSTER test-cluster TO BE active

-- 5. Update cluster configuration (multiple fields)
UPDATE CLUSTER test-cluster SET max_rcu = 6000, min_rcu = 2000, service_plan = 'dedicated'

-- 6. Wait for update to complete
WAIT FOR CLUSTER test-cluster TO BE active

-- 7. Store updated cluster details with pattern matching
SELECT display_name, region INTO updated_name, updated_region FROM CLUSTER WHERE name = /test.*/

-- 8. Clean up when done
DROP CLUSTER test-cluster
```

### Script Example with Complex Filtering

```sql
-- cluster_management.sql
-- Create and manage a test cluster with advanced filtering

-- List clusters with complex conditions
SELECT * FROM CLUSTER WHERE (name = test* OR name = prod*) AND NOT (state = FAILED OR state = DELETED);
SELECT * FROM CLUSTER WHERE state IN ['ACTIVE', 'CREATING'] AND region IN ['us-west-1', 'us-east-1'];

-- Create cluster
CREATE CLUSTER test-cluster IN 'aws-us-west-1' WITH min_rcu = 1000, max_rcu = 5000;

-- Wait for creation
WAIT FOR CLUSTER test-cluster TO BE active;

-- List clusters to verify with pattern matching
SELECT * FROM CLUSTER WHERE name = /test.*/;

-- Store cluster details in variables
SELECT display_name, region INTO cluster_name, cluster_region FROM CLUSTER WHERE name = 'test-cluster';

-- Update configuration (multiple fields)
UPDATE CLUSTER test-cluster SET max_rcu = 6000, min_rcu = 2000, service_plan = 'dedicated';

-- Wait for update to complete
WAIT FOR CLUSTER test-cluster TO BE active;

-- Verify the update and store new details
SELECT display_name, region INTO updated_name, updated_region FROM CLUSTER WHERE name = 'test-cluster';

-- Clean up when done
DROP CLUSTER test-cluster;
```

This SQL-like syntax provides a familiar interface while maintaining all the power and flexibility of the existing TiDB Cloud CLI DSL, enhanced with advanced RPN-based WHERE clause evaluation for complex filtering scenarios. 