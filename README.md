# TiDB Cloud CLI

A command-line interface for managing TiDB Cloud resources using SQL syntax and SQLite integration. The CLI provides a virtual table interface that maps SQL operations to TiDB Cloud API calls.

## Features

- **SQL Interface**: Full SQL support for querying and managing TiDB Cloud resources
- **Virtual Tables**: SQLite tables that automatically sync with TiDB Cloud API
- **Real-time Data**: Fresh data fetched from API on every query execution
- **API Integration**: INSERT, UPDATE, DELETE operations trigger corresponding TiDB Cloud API calls
- **Foreign Key Support**: Proper relationships between clusters, backups, and endpoints
- **Local Caching**: SQLite integration for efficient data storage and querying
- **Interactive Shell**: Full-featured SQL shell with command history

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

Once in the shell, you can:
- Type `help` to see available tables and example queries
- Use `.tables` to list all tables
- Use `.schema <table_name>` to see table structure
- Execute any SQL query directly

### Available Tables

The CLI provides the following virtual tables that automatically sync with TiDB Cloud:

#### 1. clusters
Contains TiDB cluster information with fields:
- `tidb_id`, `name`, `display_name`, `state`, `region_id`
- `root_password`, `min_rcu`, `max_rcu`, `service_plan`
- `cloud_provider`, `region_display_name`, `raw_data`

#### 2. backups
Contains backup information with fields:
- `backup_id`, `tidb_id`, `backup_name`, `status`, `size_bytes`, `raw_data`

#### 3. public_endpoints
Contains TiDB cluster endpoint information with fields:
- `endpoint_id`, `tidb_id`, `host`, `port`, `connection_type`, `raw_data`
- Linked to clusters table via foreign key (`tidb_id`)

#### 4. config
Contains configuration information with fields:
- `key`, `value`, `raw_data`

### Example Queries

#### Basic Queries
```sql
-- List all active clusters
SELECT * FROM clusters WHERE state = 'ACTIVE';

-- Get cluster details with region information
SELECT display_name, region_id FROM clusters ORDER BY create_time DESC;

-- Count backups per cluster
SELECT c.display_name, COUNT(b.backup_id) 
FROM clusters c 
LEFT JOIN backups b ON c.tidb_id = b.tidb_id 
GROUP BY c.tidb_id;
```

#### Endpoint Queries
```sql
-- List all public endpoints
SELECT * FROM public_endpoints WHERE connection_type = 'PUBLIC';

-- Join clusters with their endpoints
SELECT c.display_name, pe.host, pe.port 
FROM clusters c 
JOIN public_endpoints pe ON c.tidb_id = pe.tidb_id;
```

### Data Modification Operations

#### Creating Clusters
```sql
INSERT INTO clusters (tidb_id, name, display_name, region_id, state, create_time, root_password, min_rcu, max_rcu, service_plan, cloud_provider, region_display_name, raw_data)
VALUES (NULL, 'clusters/new-cluster', 'My New Cluster', 'aws-us-east-1', 'CREATING', NOW(), '5000', '10000', 'Premium', 'aws', 'Virginia (us-east-1)', '{}');
```

#### Creating Backups
```sql
-- Direct cluster ID
INSERT INTO backups (tidb_id, description) VALUES ('cluster-123', 'Manual backup for testing');

-- Using subquery to find cluster by display name
INSERT INTO backups (tidb_id, description) 
VALUES ((SELECT tidb_id FROM clusters WHERE display_name = 'My Cluster'), 'Backup by display name');

-- Using subquery to find cluster by name
INSERT INTO backups (tidb_id, description) 
VALUES ((SELECT tidb_id FROM clusters WHERE name = 'clusters/test-cluster'), 'Backup by cluster name');
```

#### Deleting Backups
```sql
-- Delete specific backup
DELETE FROM backups WHERE backup_id = 'backup-123';

-- Delete all backups for a cluster
DELETE FROM backups WHERE tidb_id = 'cluster-456';
```

#### Updating Clusters
```sql
-- Update cluster configuration
UPDATE clusters 
SET display_name = 'New Name', min_rcu = '6000', max_rcu = '12000' 
WHERE tidb_id = 'cluster-123';

-- Update only display name
UPDATE clusters 
SET display_name = 'Updated Name' 
WHERE tidb_id = 'cluster-456';

-- Update root password (triggers separate API call)
UPDATE clusters 
SET root_password = 'new-password-123' 
WHERE tidb_id = 'cluster-789';
```

#### Managing Endpoints
```sql
-- Create new endpoint (triggers API call to update public connection settings)
INSERT INTO public_endpoints (endpoint_id, tidb_id, host, port, connection_type, raw_data) 
VALUES ('endpoint-1', 'cluster-123', '192.168.1.100', '4000', 'PUBLIC', '{}');
```

## Command Line Parameters

### Global Options

```bash
# Authentication
--username, -u <USERNAME>           # TiDB Cloud username
--password, -p <PASSWORD>           # TiDB Cloud password/API key
--base-url <URL>                    # TiDB Cloud API base URL

# Logging and Output
--verbose, -v                       # Enable verbose output
--log-level <LEVEL>                 # Log level (trace, debug, info, warn, error)
--log-file                          # Enable file logging
--log-file-path <PATH>              # Log file path

# Operation Settings
--timeout, -t <SECONDS>             # Timeout in seconds (default: 300)
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

# Setup and configuration
setup                               # Initialize virtual tables
```

### Examples

```bash
# Start interactive SQL shell
tidb-cli --username myuser --password myapikey \
         --base-url https://cloud.dev.tbapi.com/v1beta2 shell

# Execute single SQL query
tidb-cli --username myuser --password myapikey \
         --base-url https://cloud.dev.tbapi.com/v1beta2 \
         query "SELECT * FROM clusters WHERE state = 'ACTIVE'"

# Verbose logging with debug level
tidb-cli --username myuser --password myapikey \
         --base-url https://cloud.dev.tbapi.com/v1beta2 \
         --verbose \
         --log-level debug \
         shell

# Execute SQL script from file
tidb-cli --username myuser --password myapikey \
         --base-url https://cloud.dev.tbapi.com/v1beta2 \
         script ./queries.sql

# Show available tables
tidb-cli --username myuser --password myapikey \
         --base-url https://cloud.dev.tbapi.com/v1beta2 \
         show-tables
```

## Configuration

The CLI requires TiDB Cloud authentication via command line parameters or environment variables:

```bash
# Required environment variables (alternative to command line)
export TIDB_CLOUD_USERNAME="your-username"
export TIDB_CLOUD_PASSWORD="your-api-key"
export TIDB_CLOUD_API_KEY="your-api-key"  # Backward compatibility
```


## Development

```bash
# Build
cargo build

# Run tests
cargo test

# Run CLI
cargo run
```

## Architecture

The TiDB Cloud CLI uses a **SQLite-based architecture** that provides a seamless SQL interface to TiDB Cloud data:

- **SQLite Integration**: Uses SQLite as the query engine with local tables for data caching
- **API Synchronization**: Automatically fetches fresh data from TiDB Cloud API before executing queries
- **Materialized Views**: The `public_endpoints` table is implemented as a materialized view that automatically extracts endpoint data from cluster JSON
- **Direct SQL Execution**: All SQL statements are passed directly to SQLite without Rust-side parsing
- **SQLite Triggers**: Uses SQLite triggers to handle INSERT/UPDATE/DELETE operations (currently logging only)
- **Real-time Data**: Queries always run against the latest data from the TiDB Cloud API

## API Integration Features

### Current Implementation
The CLI currently provides a SQL interface to TiDB Cloud data with the following capabilities:

- **Data Querying**: All SELECT queries are executed against fresh data from the TiDB Cloud API
- **Data Storage**: Local SQLite tables cache the latest data from the API
- **Materialized Views**: The `public_endpoints` view automatically extracts endpoint information from cluster JSON data
- **SQLite Triggers**: Basic triggers are in place for INSERT/UPDATE/DELETE operations (currently logging only)

### Future Enhancements
The architecture is designed to support full API integration through SQLite triggers:

- **INSERT INTO clusters**: Will create new TiDB clusters via `create_tidb` API
- **INSERT INTO backups**: Will create new backups via `create_backup` API  
- **DELETE FROM clusters**: Will remove clusters via `delete_tidb` API
- **DELETE FROM backups**: Will remove backups via `delete_backup` API
- **UPDATE clusters**: Will update cluster configuration via `update_tidb` API

### Data Synchronization
- All data is fetched fresh from the TiDB Cloud API on every query execution
- Local SQLite tables are automatically populated and synchronized
- The materialized view automatically reflects changes in the underlying cluster data

## License

Apache-2.0
