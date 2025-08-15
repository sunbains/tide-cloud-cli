# TiDB Endpoints Materialized View

The `tidb_endpoints` view provides access to endpoints from TiDB clusters extracted from the raw_data JSON.

## Schema

```sql
CREATE VIEW tidb_endpoints AS
    SELECT 
        json_extract(endpoint.value, '$.host') || ':' || json_extract(endpoint.value, '$.port') as endpoint_id,
        tidb_id,
        json_extract(endpoint.value, '$.host') as host,
        json_extract(endpoint.value, '$.port') as port,
        json_extract(endpoint.value, '$.connectionType') as connection_type,
        endpoint.value as raw_data
    FROM tidb_clusters,
    json_each(json_extract(raw_data, '$.endpoints')) as endpoint
    WHERE json_extract(endpoint.value, '$.host') IS NOT NULL
    AND json_extract(endpoint.value, '$.port') IS NOT NULL;
```

### Columns

- `endpoint_id` (TEXT): Composite key in format "host:port" extracted from JSON
- `tidb_id` (TEXT): ID of the TiDB cluster this endpoint belongs to
- `host` (TEXT): Hostname or IP address extracted from endpoint JSON
- `port` (TEXT): Port number extracted from endpoint JSON
- `connection_type` (TEXT): Connection type extracted from endpoint JSON
- `raw_data` (TEXT): Raw JSON data of the endpoint object

## Usage Examples

### List all endpoints
```sql
SELECT endpoint_id, tidb_id, host, port FROM tidb_endpoints;
```

### Get endpoints for a specific cluster
```sql
SELECT * FROM tidb_endpoints WHERE tidb_id = 'your-cluster-id';
```

### Join with clusters table
```sql
SELECT 
    pe.endpoint_id,
    pe.host,
    pe.port,
    c.display_name as cluster_name
FROM tidb_endpoints pe
JOIN tidb_clusters c ON pe.tidb_id = c.tidb_id;
```

### Count endpoints per cluster
```sql
SELECT 
    tidb_id,
    COUNT(*) as endpoint_count
FROM tidb_endpoints
GROUP BY tidb_id;
```

## Data Source

The view extracts endpoints from the `endpoints` array in the TiDB cluster `raw_data` JSON field using SQLite's JSON functions.

## Limitations

- This is a materialized view (no INSERT/UPDATE/DELETE operations)
- Data is based on tidb_clusters raw_data JSON
- Performance depends on JSON parsing and the number of clusters