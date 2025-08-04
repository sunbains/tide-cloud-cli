# TiDB CLI

A standalone command-line interface for TiDB Cloud operations. This tool provides a simple, declarative syntax for managing TiDB Cloud resources.

## Features

- **Declarative Syntax**: Write simple commands like `CREATE CLUSTER my-cluster`
- **Interactive Mode**: Execute commands interactively with command history
- **Script Execution**: Run DSL scripts from files
- **Command Validation**: Validate scripts without executing them
- **Comprehensive Help**: Built-in help and examples
- **Logging**: Configurable logging levels and file output

## Installation

### Prerequisites

- Rust 1.70 or later
- TiDB Cloud account with API access

### Building from Source

```bash
git clone <repository-url>
cd tidb-cloud-cli
cargo build --release
```

The binary will be available at `target/release/tidb-dsl`.

## Usage

### Basic Commands

```bash
# Execute a single command
tidb-cli exec "CREATE CLUSTER my-cluster IN aws-us-west-1"

# Execute a script file
tidb-cli script my-script.dsl

# Interactive mode
tidb-cli interactive

# Validate a script without executing
tidb-cli validate my-script.dsl

# Show available commands
tidb-cli list-commands

# Show detailed help
tidb-cli help-commands

# Show examples
tidb-cli examples
```

### Authentication

You can provide credentials via command line arguments or environment variables:

```bash
# Command line arguments
tidb-cli --username your-username --password your-password exec "LIST CLUSTERS"

# Environment variables
export TIDB_USERNAME=your-username
export TIDB_PASSWORD=your-password
tidb-cli exec "LIST CLUSTERS"
```

## DSL Syntax

### Cluster Management

```dsl
# Create a cluster
CREATE CLUSTER my-cluster IN aws-us-west-1 WITH RCU 1-10

# List clusters
LIST CLUSTERS

# Get cluster details
GET CLUSTER my-cluster

# Update cluster
UPDATE CLUSTER my-cluster SET RCU 2-20

# Delete cluster
DELETE CLUSTER my-cluster
```

### Backup Management

```dsl
# Create backup
CREATE BACKUP FOR my-cluster

# List backups
LIST BACKUPS FOR my-cluster

# Get backup details
GET BACKUP backup-id

# Delete backup
DELETE BACKUP backup-id
```

## Examples

### Complete Cluster Setup

```dsl
# Create a cluster
CREATE CLUSTER production-cluster IN aws-us-west-1 WITH RCU 2-20

# Wait for it to be active
WAIT FOR production-cluster TO BE ACTIVE

# Create a backup
CREATE BACKUP FOR production-cluster

# List all resources
LIST CLUSTERS
LIST BACKUPS FOR production-cluster
```

## Development

### Building

```bash
# Development build
cargo build

# Release build
cargo build --release

# Run tests
cargo test

# Check for issues
cargo check
cargo clippy
```

## License

Apache 2.0 License - see LICENSE file for details.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Run the test suite
6. Submit a pull request
