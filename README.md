# TiDB Cloud CLI

A command-line interface for managing TiDB Cloud resources using **SQLite Virtual Tables**. The CLI provides a seamless SQL interface that translates SQL operations directly into TiDB Cloud API calls in real-time.

## Features

- **SQLite Virtual Tables**: Native SQLite virtual table implementation with full SQL support
- **Real-time API Integration**: Direct translation of SQL queries to TiDB Cloud API calls
- **No Manual Parsing**: Leverages SQLite's built-in SQL engine for all operations
- **Full CRUD Support**: INSERT, UPDATE, DELETE operations trigger real API calls
- **Automatic Data Fetching**: Virtual tables fetch fresh data from API on-demand
- **Interactive SQL Shell**: Full-featured SQL shell with command history and auto-completion
- **Structured Logging**: Comprehensive debug logging for troubleshooting

## Architecture

The TiDB Cloud CLI uses **SQLite Virtual Tables** that implement the `rusqlite::vtab` traits:

- **`VTab`**: Defines table schema and handles table-level operations
- **`VTabCursor`**: Manages data iteration and API calls
- **`CreateVTab`**: Handles INSERT operations (creates real TiDB Cloud resources)
- **`UpdateVTab`**: Handles UPDATE operations (modifies existing resources)
- **`DeleteVTab`**: Handles DELETE operations (removes resources)

### How It Works

1. **SQL Query Execution**: User executes SQL against virtual tables
2. **Virtual Table Handlers**: SQLite calls appropriate virtual table methods
3. **API Translation**: Virtual tables translate operations to TiDB Cloud API calls
4. **Real-time Results**: Fresh data returned directly from API responses

## Installation

```bash
cargo install --path .
```

## Usage

### Interactive SQL Shell

Start the interactive shell to execute SQL queries directly:

```bash
tidb-cli --username your-username --password your-api-key --base-url https://cloud.dev.tidbapi.com/v1beta2 shell
```

### Available Virtual Tables

#### 1. `tidb_clusters`
**Schema**: Full TiDB cluster information
```sql
CREATE TABLE tidb_clusters (
    tidb_id TEXT,           -- Primary identifier
    name TEXT,              -- Resource name
    display_name TEXT,      -- Human-readable name
    region_id TEXT,         -- Cloud region
    state TEXT,             -- Cluster state
    create_time TEXT,       -- Creation timestamp
    root_password TEXT,     -- Root password
    min_rcu TEXT,          -- Minimum RCU
    max_rcu TEXT,          -- Maximum RCU
    service_plan TEXT,      -- Service tier
    cloud_provider TEXT,    -- Cloud provider
    region_display_name TEXT, -- Region description
    raw_data TEXT           -- Full JSON response
);
```

**Supported Operations**:
- ✅ **SELECT**: Query clusters with WHERE, JOIN, GROUP BY, ORDER BY
- ✅ **INSERT**: Create new clusters (triggers `create_tidb` API)
- ✅ **UPDATE**: Modify cluster properties (triggers `update_tidb` API)
- ✅ **DELETE**: Remove clusters (triggers `delete_tidb` API)

#### 2. `tidb_backups`
**Schema**: Backup information for clusters
```sql
CREATE TABLE tidb_backups (
    backup_id TEXT,         -- Primary identifier
    tidb_id TEXT,          -- Foreign key to clusters
    backup_name TEXT,       -- Backup name
    description TEXT,       -- Backup description
    status TEXT,            -- Backup status
    size_bytes TEXT,        -- Size in bytes
    raw_data TEXT           -- Full JSON response
);
```

**Supported Operations**:
- ✅ **SELECT**: Query backups with constraints
- ✅ **INSERT**: Create new backups (triggers `create_backup` API)
- ✅ **UPDATE**: Modify backup description (triggers `update_backup` API)
- ✅ **DELETE**: Remove backups (triggers `delete_backup` API)

#### 3. `tidb_public_endpoints`
**Schema**: Public endpoint information extracted from clusters
```sql
CREATE TABLE tidb_public_endpoints (
    endpoint_id TEXT,       -- Endpoint identifier
    tidb_id TEXT,          -- Foreign key to clusters
    host TEXT,              -- Host address
    port TEXT,              -- Port number
    connection_type TEXT,   -- Connection type
    raw_data TEXT           -- Full JSON response
);
```

**Supported Operations**:
- ✅ **SELECT**: Query endpoints (read-only)
- 🔒 **INSERT/UPDATE/DELETE**: Not supported (endpoints managed via clusters)

### Example Queries

#### Basic Cluster Operations
```sql
-- List all active clusters
SELECT * FROM tidb_clusters WHERE state = 'ACTIVE';

-- Get cluster details with region information
SELECT display_name, region_id, min_rcu, max_rcu 
FROM tidb_clusters 
ORDER BY create_time DESC;

-- Count clusters by service plan
SELECT service_plan, COUNT(*) as cluster_count 
FROM tidb_clusters 
GROUP BY service_plan 
ORDER BY cluster_count DESC;
```

#### Backup Management
```sql
-- List all backups with cluster information
SELECT c.display_name, b.backup_name, b.status, b.size_bytes
FROM tidb_clusters c
JOIN tidb_backups b ON c.tidb_id = b.tidb_id
WHERE b.status = 'COMPLETED';

-- Count backups per cluster
SELECT c.display_name, COUNT(b.backup_id) as backup_count
FROM tidb_clusters c
LEFT JOIN tidb_backups b ON c.tidb_id = b.tidb_id
GROUP BY c.tidb_id, c.display_name;
```

#### Endpoint Information
```sql
-- List all public endpoints
SELECT * FROM tidb_public_endpoints WHERE connection_type = 'PUBLIC';

-- Join clusters with their endpoints
SELECT c.display_name, pe.host, pe.port, pe.connection_type
FROM tidb_clusters c
JOIN tidb_public_endpoints pe ON c.tidb_id = pe.tidb_id;
```

### Data Modification Operations

#### Creating Clusters
```sql
INSERT INTO tidb_clusters (
    display_name, region_id, min_rcu, max_rcu, 
    service_plan, cloud_provider
) VALUES (
    'My New Cluster', 'aws-us-east-1', '1000', '2000', 
    'Basic', 'aws'
);
```

**Required Fields**: `display_name`, `region_id`
**Optional Fields**: `min_rcu`, `max_rcu`, `service_plan`, `cloud_provider`
**Defaults**: `min_rcu=1000`, `max_rcu=2000`, `service_plan='Basic'`, `cloud_provider='aws'`

#### Creating Backups
```sql
-- Create backup for specific cluster
INSERT INTO tidb_backups (tidb_id, description) 
VALUES ('cluster-123', 'Manual backup for testing');

-- Create backup using subquery to find cluster
INSERT INTO tidb_backups (tidb_id, description) 
VALUES (
    (SELECT tidb_id FROM tidb_clusters WHERE display_name = 'My Cluster'), 
    'Backup by display name'
);
```

#### Updating Clusters
```sql
-- Update cluster configuration
UPDATE tidb_clusters 
SET display_name = 'New Name', min_rcu = '6000', max_rcu = '12000' 
WHERE tidb_id = 'cluster-123';

-- Update only display name
UPDATE tidb_clusters 
SET display_name = 'Updated Name' 
WHERE tidb_id = 'cluster-456';

-- Update root password (triggers separate API call)
UPDATE tidb_clusters 
SET root_password = 'new-password-123' 
WHERE tidb_id = 'cluster-789';
```

#### Deleting Resources
```sql
-- Delete specific cluster
DELETE FROM tidb_clusters WHERE tidb_id = 'cluster-123';

-- Delete specific backup
DELETE FROM tidb_backups WHERE backup_id = 'backup-456';

-- Delete all backups for a cluster
DELETE FROM tidb_backups WHERE tidb_id = 'cluster-123';
```

## Command Line Parameters

### Global Options

```bash
# Authentication (Required)
--username, -u <USERNAME>           # TiDB Cloud username
--password, -p <PASSWORD>           # TiDB Cloud password/API key
--base-url <URL>                    # TiDB Cloud API base URL

# Logging and Output
--verbose, -v                       # Enable verbose output
--log-level <LEVEL>                 # Log level (trace, debug, info, warn, error)
--log-file                          # Enable file logging
--log-file-path <PATH>              # Log file path
```

### Commands

```bash
# Interactive SQL shell
shell                               # Start interactive SQL shell

# Execute SQL queries directly
query <SQL_QUERY>                   # Execute a single SQL query

# Execute SQL from file
script <FILE>                       # Execute SQL script from a file

# Show available tables and schemas
show-tables                         # List all available virtual tables
examples                            # Show SQL query examples
```

### Examples

```bash
# Start interactive SQL shell
tidb-cli --username myuser --password myapikey \
         --base-url https://cloud.dev.tidbapi.com/v1beta2 shell

# Execute single SQL query
tidb-cli --username myuser --password myapikey \
         --base-url https://cloud.dev.tidbapi.com/v1beta2 \
         query "SELECT * FROM tidb_clusters WHERE state = 'ACTIVE'"

# Verbose logging with debug level
tidb-cli --username myuser --password myapikey \
         --base-url https://cloud.dev.tidbapi.com/v1beta2 \
         --verbose \
         --log-level debug \
         shell
```

## Virtual Table Implementation Details

### Architecture Components

- **`TidbClustersTab`**: Implements `VTab`, `CreateVTab`, `UpdateVTab`, `DeleteVTab`
- **`TidbClustersCursor`**: Implements `VTabCursor` for data iteration
- **`TidbBackupsTab`**: Similar implementation for backup operations
- **`TidbPublicEndpointsTab`**: Read-only virtual table for endpoint data

### Key Methods

- **`connect()`**: Defines table schema
- **`best_index()`**: Optimizes query execution based on constraints
- **`filter()`**: Fetches data from API based on SQL constraints
- **`insert()`**: Creates resources via TiDB Cloud API
- **`update()`**: Modifies resources via TiDB Cloud API
- **`delete()`**: Removes resources via TiDB Cloud API

### Constraint Optimization

The virtual tables automatically optimize queries by:
- Analyzing WHERE clause constraints
- Applying filters at the API level when possible
- Using constraint masks for efficient query planning
- Estimating query costs for SQLite's query planner

### Error Handling

- **API Failures**: Hard errors (no fallback to sample data)
- **Authentication Errors**: Proper error propagation
- **Network Issues**: Clear error messages with context
- **Validation**: Input validation before API calls

## Development

```bash
# Build
cargo build

# Run tests
cargo test

# Run CLI
cargo run --bin tidb-cli -- shell

# Check for warnings
cargo clippy
```

## License

Apache-2.0
