# RPN-Based WHERE Clause Examples
# This file demonstrates the new RPN-based condition evaluator for complex WHERE clauses
# Now using SELECT statements instead of LIST commands

# Simple conditions
SELECT * FROM BACKUPS WHERE state = ACTIVE
SELECT * FROM BACKUPS WHERE size > 1000

# Logical operators
SELECT * FROM BACKUPS WHERE state = ACTIVE AND size > 500
SELECT * FROM BACKUPS WHERE state = ACTIVE OR state = CREATING
SELECT * FROM BACKUPS WHERE NOT (state = FAILED)

# Complex expressions with parentheses
SELECT * FROM BACKUPS WHERE (size > 100 OR size < 50) AND (state = ACTIVE OR state = CREATING)
SELECT * FROM BACKUPS WHERE state = ACTIVE AND (size > 1000 OR size < 100)

# Pattern matching with backups
SELECT * FROM BACKUPS WHERE state = ACTIVE
SELECT * FROM BACKUPS WHERE size >= 500
SELECT * FROM BACKUPS WHERE createTime > "2023-01-01"

# Mixed conditions
SELECT * FROM BACKUPS WHERE state = ACTIVE AND (size > 100 OR size < 50) AND NOT (state = FAILED)

# Complex nested expressions
SELECT * FROM BACKUPS WHERE (
    (state = ACTIVE OR state = CREATING) AND 
    (size > 100 OR size < 50) AND 
    NOT (state = FAILED OR state = DELETED)
) OR (
    size > 1000 AND state = COMPLETED
)

# Field comparisons with different operators
SELECT * FROM BACKUPS WHERE size >= 100 AND size <= 1000
SELECT * FROM BACKUPS WHERE state = ACTIVE AND createTime > "2023-01-01"
SELECT * FROM BACKUPS WHERE createTime > "2023-01-01" AND createTime < "2023-12-31"

# Using NOT with complex expressions
SELECT * FROM BACKUPS WHERE NOT (state = FAILED AND size < 100)
SELECT * FROM BACKUPS WHERE state = ACTIVE AND NOT (state = DELETED OR state = FAILED)

# Multiple field comparisons
SELECT * FROM BACKUPS WHERE state = ACTIVE AND size > 500 AND createTime > "2023-01-01"