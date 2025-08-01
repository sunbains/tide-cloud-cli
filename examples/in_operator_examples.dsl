-- IN Operator Examples for TiDB Cloud CLI
-- This file demonstrates how to use the IN operator in WHERE clauses

-- Basic IN operator usage
SELECT * FROM CLUSTER WHERE state IN ['ACTIVE', 'CREATING', 'UPDATING']

-- IN operator with region filtering
SELECT * FROM CLUSTER WHERE region IN ['us-west-1', 'us-east-1', 'aws-us-west-2']

-- IN operator with cluster names
SELECT * FROM CLUSTER WHERE name IN ['test-cluster', 'prod-cluster', 'dev-cluster']

-- IN operator with mixed quoted and unquoted values
SELECT * FROM CLUSTER WHERE state IN [ACTIVE, 'CREATING', "UPDATING"]

-- IN operator combined with other operators
SELECT * FROM CLUSTER WHERE state IN ['ACTIVE', 'CREATING'] AND name = test-cluster

-- IN operator with OR
SELECT * FROM CLUSTER WHERE state IN ['FAILED', 'DELETED'] OR name = test-cluster

-- IN operator with NOT
SELECT * FROM CLUSTER WHERE NOT state IN ['FAILED', 'DELETED']

-- Complex expression with multiple IN operators
SELECT * FROM CLUSTER WHERE (state IN ['ACTIVE', 'CREATING']) AND (region IN ['us-west-1', 'us-east-1'])

-- IN operator with parentheses for precedence
SELECT * FROM CLUSTER WHERE (name IN ['test-cluster', 'prod-cluster']) AND (state IN ['ACTIVE', 'CREATING'])

-- IN operator with pattern matching
SELECT * FROM CLUSTER WHERE name = test* AND state IN ['ACTIVE', 'CREATING']

-- IN operator with regex
SELECT * FROM CLUSTER WHERE name = /test.*/ AND state IN ['ACTIVE', 'CREATING']

-- Store cluster data with IN operator filtering
SELECT display_name, region INTO cluster_name, cluster_region FROM CLUSTER WHERE state IN ['ACTIVE', 'CREATING']

-- Multiple field selection with IN operator
SELECT name, state, region FROM CLUSTER WHERE state IN ['ACTIVE', 'CREATING'] AND region IN ['us-west-1', 'us-east-1'] 