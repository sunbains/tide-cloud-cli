# Basic Cluster Management Example
# This script demonstrates basic cluster operations

# Set variables for reuse
SET cluster_name = "example-cluster"
SET region = "aws-us-east-1"

# Create a cluster
CREATE CLUSTER $cluster_name IN $region WITH RCU 1-10

# Wait for the cluster to be active
WAIT FOR $cluster_name TO BE ACTIVE

# Create a backup
CREATE BACKUP FOR $cluster_name

# List backups for our cluster
LIST BACKUPS FOR $cluster_name
