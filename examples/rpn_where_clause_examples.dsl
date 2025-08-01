# RPN-Based WHERE Clause Examples
# This file demonstrates the new RPN-based condition evaluator for complex WHERE clauses

# Simple conditions
LIST CLUSTERS WHERE name = test-cluster
LIST CLUSTERS WHERE state = ACTIVE
LIST CLUSTERS WHERE region = us-east-1

# Logical operators
LIST CLUSTERS WHERE name = test-cluster AND state = ACTIVE
LIST CLUSTERS WHERE name = test-cluster OR state = FAILED
LIST CLUSTERS WHERE NOT (state = FAILED)

# Complex expressions with parentheses
LIST CLUSTERS WHERE (name = test* OR name = prod*) AND (state = ACTIVE OR state = CREATING)
LIST CLUSTERS WHERE name = /test.*/ AND (region = us-east-1 OR region = us-west-2)

# Pattern matching
LIST CLUSTERS WHERE name = test*          # Wildcard pattern
LIST CLUSTERS WHERE name = /test.*/       # Regular expression
LIST CLUSTERS WHERE name = /.*cluster/    # Regex with anchors

# Mixed conditions
LIST CLUSTERS WHERE name = test* AND (state = ACTIVE OR state = CREATING) AND NOT (state = FAILED)

# Complex nested expressions
LIST CLUSTERS WHERE (
    (name = test* OR name = prod*) AND 
    (state = ACTIVE OR state = CREATING OR state = UPDATING) AND 
    NOT (state = FAILED OR state = DELETED)
) OR (
    name = /.*-dev.*/ AND region = us-west-2
)

# Field comparisons with different operators
LIST CLUSTERS WHERE min_rcu >= 1 AND max_rcu <= 10
LIST CLUSTERS WHERE service_plan = STARTER AND cloud_provider = AWS
LIST CLUSTERS WHERE create_time > "2023-01-01" AND update_time < "2023-12-31"

# Using NOT with complex expressions
LIST CLUSTERS WHERE NOT (name = test* AND state = FAILED)
LIST CLUSTERS WHERE name = prod* AND NOT (state = DELETED OR state = FAILED)

# Multiple field comparisons
LIST CLUSTERS WHERE name = /.*prod.*/ AND region = us-east-1 AND service_plan = DEDICATED 