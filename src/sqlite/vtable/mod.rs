//! SQLite Virtual Table implementation for TiDB Cloud API
//!
//! This module provides a proper virtual table implementation that translates
//! SQLite queries into TiDB Cloud API requests in real-time.

use crate::tidb_cloud::TiDBCloudClient;
use rusqlite::ffi;
use rusqlite::vtab::{
    Context, CreateVTab, Filters, IndexConstraintOp, IndexInfo, Inserts, UpdateVTab, Updates, VTab,
    VTabConnection, VTabCursor, VTabKind,
};
use rusqlite::{Connection, Result as SqliteResult};
use std::collections::HashMap;
use std::ffi::c_int;
use std::marker::PhantomData;
use std::sync::{Arc, Mutex, OnceLock};
use tracing::debug;

pub mod api_bridge;
use api_bridge::{BackupData, ClusterData, NetworkAccessData};

// Global mapping from rowid to tidb_id for cluster deletions
static CLUSTER_ROWID_MAP: OnceLock<Arc<Mutex<HashMap<i64, String>>>> = OnceLock::new();

fn get_cluster_rowid_map() -> &'static Arc<Mutex<HashMap<i64, String>>> {
    CLUSTER_ROWID_MAP.get_or_init(|| Arc::new(Mutex::new(HashMap::new())))
}

// Global mapping from rowid to (tidb_id, backup_id) for backup deletions
type BackupRowidMap = Arc<Mutex<HashMap<i64, (String, String)>>>;
static BACKUP_ROWID_MAP: OnceLock<BackupRowidMap> = OnceLock::new();

fn get_backup_rowid_map() -> &'static BackupRowidMap {
    BACKUP_ROWID_MAP.get_or_init(|| Arc::new(Mutex::new(HashMap::new())))
}

// Global mapping from rowid to (tidb_id, cidr_notation) for network access updates/deletes
type NetworkAccessRowidMap = Arc<Mutex<HashMap<i64, (String, String)>>>;
static NETWORK_ACCESS_ROWID_MAP: OnceLock<NetworkAccessRowidMap> = OnceLock::new();

fn get_network_access_rowid_map() -> &'static NetworkAccessRowidMap {
    NETWORK_ACCESS_ROWID_MAP.get_or_init(|| Arc::new(Mutex::new(HashMap::new())))
}

// Global registry for tracking dynamic cluster-specific tables
static DYNAMIC_CLUSTER_TABLES: OnceLock<Arc<Mutex<std::collections::HashSet<String>>>> =
    OnceLock::new();

pub fn get_dynamic_cluster_tables() -> &'static Arc<Mutex<std::collections::HashSet<String>>> {
    DYNAMIC_CLUSTER_TABLES.get_or_init(|| Arc::new(Mutex::new(std::collections::HashSet::new())))
}

/// Create a cluster-specific network access virtual table
pub fn create_cluster_access_table(conn: &Connection, cluster_id: &str) -> SqliteResult<()> {
    // Register the module for this specific cluster
    let module_name = format!("tidb_{cluster_id}_network_access");

    conn.create_module(
        module_name.as_str(),
        rusqlite::vtab::update_module::<TidbClusterNetworkAccessTab>(),
        Some(cluster_id.to_string()),
    )?;

    // Create the virtual table instance
    let table_name = format!("tidb_{cluster_id}_network_access");
    let sql = format!("CREATE VIRTUAL TABLE IF NOT EXISTS {table_name} USING {module_name}");

    conn.execute(&sql, [])?;

    // Track this table in our registry
    if let Ok(mut tables) = get_dynamic_cluster_tables().lock() {
        tables.insert(cluster_id.to_string());
    }

    debug!(
        "✅ Created cluster-specific network access table: {}",
        table_name
    );
    Ok(())
}

/// Drop a cluster-specific network access virtual table
pub fn drop_cluster_access_table(conn: &Connection, cluster_id: &str) -> SqliteResult<()> {
    let table_name = format!("tidb_{cluster_id}_network_access");

    // Drop the virtual table
    let sql = format!("DROP TABLE IF EXISTS {table_name}");
    conn.execute(&sql, [])?;

    // Remove from our registry
    if let Ok(mut tables) = get_dynamic_cluster_tables().lock() {
        tables.remove(cluster_id);
    }

    debug!(
        "✅ Dropped cluster-specific network access table: {}",
        table_name
    );
    Ok(())
}

/// Clear all rowid mappings (for reload operations)
pub fn clear_all_rowid_mappings() {
    // Clear cluster rowid mappings
    if let Ok(mut map) = get_cluster_rowid_map().lock() {
        map.clear();
    }

    // Clear backup rowid mappings
    if let Ok(mut map) = get_backup_rowid_map().lock() {
        map.clear();
    }

    // Clear network access rowid mappings
    if let Ok(mut map) = get_network_access_rowid_map().lock() {
        map.clear();
    }
}

/// Initialize cluster-specific access tables for all existing clusters
pub fn initialize_cluster_access_tables(conn: &Connection) -> SqliteResult<()> {
    debug!("🚀 Initializing cluster-specific access tables for existing clusters...");

    // Fetch all existing clusters
    match api_bridge::fetch_clusters() {
        Ok(clusters) => {
            for cluster in clusters {
                if let Err(e) = create_cluster_access_table(conn, &cluster.tidb_id) {
                    debug!(
                        "⚠️ Failed to create access table for cluster {}: {}",
                        cluster.tidb_id, e
                    );
                    // Continue with other clusters even if one fails
                }
            }

            let table_count = if let Ok(tables) = get_dynamic_cluster_tables().lock() {
                tables.len()
            } else {
                0
            };

            debug!(
                "✅ Initialized {} cluster-specific access tables",
                table_count
            );
            Ok(())
        }
        Err(e) => {
            debug!("⚠️ Failed to fetch clusters for initialization: {}", e);
            // Don't fail the entire setup if cluster fetch fails
            Ok(())
        }
    }
}

// Column constants for the clusters virtual table
const COL_TIDB_ID: c_int = 0;
const COL_NAME: c_int = 1;
const COL_DISPLAY_NAME: c_int = 2;
const COL_REGION_ID: c_int = 3;
const COL_STATE: c_int = 4;
const COL_CREATE_TIME: c_int = 5;
const COL_ROOT_PASSWORD: c_int = 6;
const COL_MIN_RCU: c_int = 7;
const COL_MAX_RCU: c_int = 8;
const COL_SERVICE_PLAN: c_int = 9;
const COL_CLOUD_PROVIDER: c_int = 10;
const COL_REGION_DISPLAY_NAME: c_int = 11;
const COL_RAW_DATA: c_int = 12;

// Column constants for the backups virtual table
const COL_BACKUP_TIDB_ID: c_int = 1;
const COL_BACKUP_DESCRIPTION: c_int = 3;

// Column constants for the network_access virtual table
const COL_NETWORK_TIDB_ID: c_int = 0;
const COL_NETWORK_ENABLED: c_int = 1;
const COL_NETWORK_CIDR_NOTATION: c_int = 2;
const COL_NETWORK_DESCRIPTION: c_int = 3;
const COL_NETWORK_RAW_DATA: c_int = 4;

// Constraint masks for best_index
const MASK_STATE: c_int = 1;
const MASK_REGION_ID: c_int = 2;
const MASK_CLOUD_PROVIDER: c_int = 4;

/// Register the TiDB Cloud virtual table module with SQLite
pub fn register_module(conn: &Connection, client: &TiDBCloudClient) -> SqliteResult<()> {
    use rusqlite::vtab::update_module;

    // Initialize the API bridge with the client - this must succeed
    api_bridge::initialize(client.clone()).map_err(|e| {
        rusqlite::Error::ModuleError(format!("Failed to initialize API bridge: {e}"))
    })?;

    // Register the clusters virtual table (supports INSERT/UPDATE/DELETE)
    conn.create_module(
        "tidb_clusters",
        update_module::<TidbClustersTab>(),
        None::<()>,
    )?;

    // Register the backups virtual table (supports INSERT/UPDATE/DELETE)
    conn.create_module(
        "tidb_backups",
        update_module::<TidbBackupsTab>(),
        None::<()>,
    )?;

    // Note: network_access is now handled per-cluster via dynamic cluster-specific tables
    // The global tidb_network_access table is removed in favor of tidb_<cluster_id>_network_access tables

    debug!("Virtual table modules registered successfully");
    debug!(
        "Available tables: tidb_clusters, tidb_backups, tidb_<cluster_id>_network_access (per cluster)"
    );
    debug!("Note: Using TiDB Cloud API integration with async-to-sync conversion.");
    Ok(())
}

/// TiDB Clusters Virtual Table
#[repr(C)]
struct TidbClustersTab {
    base: ffi::sqlite3_vtab,
}

unsafe impl<'vtab> VTab<'vtab> for TidbClustersTab {
    type Aux = ();
    type Cursor = TidbClustersCursor<'vtab>;

    fn connect(
        _db: &mut VTabConnection,
        _aux: Option<&Self::Aux>,
        _args: &[&[u8]],
    ) -> SqliteResult<(String, Self)> {
        let schema = r#"
            CREATE TABLE x(
                tidb_id TEXT,
                name TEXT,
                display_name TEXT,
                region_id TEXT,
                state TEXT,
                create_time TEXT,
                root_password TEXT,
                min_rcu TEXT,
                max_rcu TEXT,
                service_plan TEXT,
                cloud_provider TEXT,
                region_display_name TEXT,
                raw_data TEXT
            )
        "#
        .to_owned();

        Ok((
            schema,
            Self {
                base: ffi::sqlite3_vtab::default(),
            },
        ))
    }

    fn best_index(&self, info: &mut IndexInfo) -> SqliteResult<()> {
        let mut state_idx: Option<usize> = None;
        let mut region_idx: Option<usize> = None;
        let mut provider_idx: Option<usize> = None;

        // Check which constraints we can handle
        for (i, c) in info.constraints().enumerate() {
            if !c.is_usable() {
                continue;
            }
            if c.operator() != IndexConstraintOp::SQLITE_INDEX_CONSTRAINT_EQ {
                continue;
            }
            match c.column() {
                COL_STATE => state_idx = Some(i),
                COL_REGION_ID => region_idx = Some(i),
                COL_CLOUD_PROVIDER => provider_idx = Some(i),
                _ => {}
            }
        }

        // Set up constraint usage
        let mut n = 0i32;
        if let Some(j) = state_idx {
            n += 1;
            let mut u = info.constraint_usage(j);
            u.set_argv_index(n);
            u.set_omit(true);
        }
        if let Some(j) = region_idx {
            n += 1;
            let mut u = info.constraint_usage(j);
            u.set_argv_index(n);
            u.set_omit(true);
        }
        if let Some(j) = provider_idx {
            n += 1;
            let mut u = info.constraint_usage(j);
            u.set_argv_index(n);
            u.set_omit(true);
        }

        // Set constraint mask
        let mut mask: c_int = 0;
        if state_idx.is_some() {
            mask |= MASK_STATE;
        }
        if region_idx.is_some() {
            mask |= MASK_REGION_ID;
        }
        if provider_idx.is_some() {
            mask |= MASK_CLOUD_PROVIDER;
        }
        info.set_idx_num(mask);

        // Set cost estimate
        if mask != 0 {
            info.set_estimated_cost(100.0); // With constraints
        } else {
            info.set_estimated_cost(10000.0); // Full table scan
        }

        Ok(())
    }

    fn open(&'vtab mut self) -> SqliteResult<Self::Cursor> {
        Ok(TidbClustersCursor::new())
    }
}

impl CreateVTab<'_> for TidbClustersTab {
    const KIND: VTabKind = VTabKind::Default;
}

impl UpdateVTab<'_> for TidbClustersTab {
    fn insert(&mut self, args: &Inserts<'_>) -> SqliteResult<i64> {
        // SQLite virtual tables include hidden columns (rowid, etc.) in the args
        // The actual column args start at an offset. From our debug output:
        // - SQLite passes 15 args total with values at indices 4,5,9,10,11,12
        // - This suggests the args array includes the full table schema
        const ARG_OFFSET: usize = 2; // SQLite seems to add 2 hidden columns

        // Helper function to get column value using the constant + offset
        let get_column_value = |col_const: c_int| -> SqliteResult<Option<String>> {
            args.get::<Option<String>>((col_const + ARG_OFFSET as c_int) as usize)
        };

        // Extract required values with proper error handling
        let display_name = get_column_value(COL_DISPLAY_NAME)?.ok_or_else(|| {
            rusqlite::Error::InvalidColumnName("display_name is required".to_string())
        })?;

        // Use default values when not provided
        let region_id =
            get_column_value(COL_REGION_ID)?.unwrap_or_else(|| "aws-us-east-1".to_string());
        let min_rcu = get_column_value(COL_MIN_RCU)?.unwrap_or_else(|| "5000".to_string());
        let max_rcu = get_column_value(COL_MAX_RCU)?.unwrap_or_else(|| "20000".to_string());
        let service_plan =
            get_column_value(COL_SERVICE_PLAN)?.unwrap_or_else(|| "Premium".to_string());
        let cloud_provider =
            get_column_value(COL_CLOUD_PROVIDER)?.unwrap_or_else(|| "aws".to_string());

        match api_bridge::create_cluster(
            &display_name,
            &region_id,
            &min_rcu,
            &max_rcu,
            &service_plan,
            &cloud_provider,
        ) {
            Ok(tidb_id) => {
                debug!("✅ Created cluster: {display_name} with ID: {}", tidb_id);
                // Note: Dynamic table creation needs to be handled externally due to SQLite connection access limitations
                // The main application should call create_cluster_access_table() after successful cluster creation
                Ok(1) // Return a rowid for the new row
            }
            Err(e) => Err(rusqlite::Error::ModuleError(format!("Insert failed: {e}"))),
        }
    }

    fn delete(&mut self, rowid: rusqlite::types::ValueRef<'_>) -> SqliteResult<()> {
        let rowid_val = rowid.as_i64()?;

        // Look up the tidb_id using the global rowid mapping
        let rowid_map = get_cluster_rowid_map();
        let tidb_id = if let Ok(map) = rowid_map.lock() {
            map.get(&rowid_val).cloned()
        } else {
            None
        };

        match tidb_id {
            Some(tidb_id) => {
                debug!("🗑️ Deleting cluster {tidb_id} (rowid: {rowid_val})");

                match api_bridge::delete_cluster(&tidb_id) {
                    Ok(()) => {
                        debug!("✅ Successfully deleted cluster: {tidb_id}");

                        // Remove from the rowid mapping
                        if let Ok(mut map) = rowid_map.lock() {
                            map.remove(&rowid_val);
                        }

                        // Note: Dynamic table cleanup needs to be handled externally due to SQLite connection access limitations
                        // The main application should call drop_cluster_access_table() after successful cluster deletion

                        Ok(())
                    }
                    Err(e) => Err(rusqlite::Error::ModuleError(format!("Delete failed: {e}"))),
                }
            }
            None => {
                debug!("⚠️ Delete requested for rowid {rowid_val}, but no tidb_id found");
                Err(rusqlite::Error::ModuleError(format!(
                    "Cannot delete cluster: no tidb_id found for rowid {rowid_val}. Try running SELECT first to populate the mapping."
                )))
            }
        }
    }

    fn update(&mut self, args: &Updates<'_>) -> SqliteResult<()> {
        // For UPDATE operations, the first argument is the new rowid, second is old rowid
        // But for our case, we want the old rowid to look up the cluster
        // Let's extract it from the arguments - typically the rowid is at index 0
        let rowid = args.get::<i64>(0)?;

        // Look up the tidb_id using the global rowid mapping
        let rowid_map = get_cluster_rowid_map();
        let tidb_id = if let Ok(map) = rowid_map.lock() {
            map.get(&rowid).cloned()
        } else {
            None
        };

        let tidb_id = match tidb_id {
            Some(id) => id,
            None => {
                return Err(rusqlite::Error::ModuleError(format!(
                    "Cannot update cluster: no tidb_id found for rowid {rowid}. Try running SELECT first to populate the mapping."
                )));
            }
        };

        // Extract updatable column values using the argument offset pattern
        const ARG_OFFSET: usize = 2; // Same offset pattern as INSERT

        // Helper function to get optional column value
        let get_column_value = |col_const: c_int| -> SqliteResult<Option<String>> {
            args.get::<Option<String>>((col_const + ARG_OFFSET as c_int) as usize)
        };

        // Extract the updatable columns - now including root_password
        let display_name = get_column_value(COL_DISPLAY_NAME)?;
        let min_rcu = get_column_value(COL_MIN_RCU)?;
        let max_rcu = get_column_value(COL_MAX_RCU)?;
        let root_password = get_column_value(COL_ROOT_PASSWORD)?;

        // Check if at least one field is being updated
        if display_name.is_none()
            && min_rcu.is_none()
            && max_rcu.is_none()
            && root_password.is_none()
        {
            return Err(rusqlite::Error::ModuleError(
                "No updatable columns specified. Only display_name, min_rcu, max_rcu, and root_password can be updated.".to_string()
            ));
        }

        debug!("🔄 Updating cluster {tidb_id} (rowid: {rowid})");
        if let Some(ref name) = display_name {
            debug!("  display_name: {name}");
        }
        if let Some(ref min) = min_rcu {
            debug!("  min_rcu: {min}");
        }
        if let Some(ref max) = max_rcu {
            debug!("  max_rcu: {max}");
        }
        if root_password.is_some() {
            debug!("  root_password: [REDACTED]");
        }

        // Separate handling for different update types
        let has_regular_updates = display_name.is_some() || min_rcu.is_some() || max_rcu.is_some();
        let has_password_update = root_password.is_some();

        let mut update_results = Vec::new();

        // Handle regular cluster updates (display_name, min_rcu, max_rcu)
        if has_regular_updates {
            match api_bridge::update_cluster(
                &tidb_id,
                display_name.as_deref(),
                min_rcu.as_deref(),
                max_rcu.as_deref(),
            ) {
                Ok(()) => {
                    debug!("✅ Successfully updated cluster properties: {tidb_id}");
                    update_results.push("cluster properties");
                }
                Err(e) => {
                    return Err(rusqlite::Error::ModuleError(format!(
                        "Cluster update failed: {e}"
                    )));
                }
            }
        }

        // Handle root password update (separate API call)
        if has_password_update && let Some(password) = root_password {
            match api_bridge::update_cluster_root_password(&tidb_id, &password) {
                Ok(()) => {
                    debug!("✅ Successfully updated cluster root password: {tidb_id}");
                    update_results.push("root password");
                }
                Err(e) => {
                    return Err(rusqlite::Error::ModuleError(format!(
                        "Root password update failed: {e}"
                    )));
                }
            }
        }

        debug!(
            "✅ Successfully updated cluster: {}",
            update_results.join(" and ")
        );
        Ok(())
    }
}

/// TiDB Backups Virtual Table
#[repr(C)]
struct TidbBackupsTab {
    base: ffi::sqlite3_vtab,
}

unsafe impl<'vtab> VTab<'vtab> for TidbBackupsTab {
    type Aux = ();
    type Cursor = TidbBackupsCursor<'vtab>;

    fn connect(
        _db: &mut VTabConnection,
        _aux: Option<&Self::Aux>,
        _args: &[&[u8]],
    ) -> SqliteResult<(String, Self)> {
        let schema = r#"
            CREATE TABLE x(
                backup_id TEXT,
                tidb_id TEXT,
                backup_name TEXT,
                description TEXT,
                status TEXT,
                size_bytes TEXT,
                raw_data TEXT
            )
        "#
        .to_owned();

        Ok((
            schema,
            Self {
                base: ffi::sqlite3_vtab::default(),
            },
        ))
    }

    fn best_index(&self, info: &mut IndexInfo) -> SqliteResult<()> {
        let mut tidb_id_idx: Option<usize> = None;

        // Check which constraints we can handle
        for (i, c) in info.constraints().enumerate() {
            if !c.is_usable() {
                continue;
            }
            if c.operator() != IndexConstraintOp::SQLITE_INDEX_CONSTRAINT_EQ {
                continue;
            }
            if c.column() == 1 {
                // tidb_id column
                tidb_id_idx = Some(i);
            }
        }

        // Set up constraint usage
        if let Some(j) = tidb_id_idx {
            let mut u = info.constraint_usage(j);
            u.set_argv_index(1);
            u.set_omit(true);
        }

        // Set constraint mask
        let mask: c_int = if tidb_id_idx.is_some() { 1 } else { 0 };
        info.set_idx_num(mask);

        // Set cost estimate
        if mask != 0 {
            info.set_estimated_cost(50.0); // With tidb_id constraint
        } else {
            info.set_estimated_cost(5000.0); // Full table scan
        }

        Ok(())
    }

    fn open(&'vtab mut self) -> SqliteResult<Self::Cursor> {
        Ok(TidbBackupsCursor::new())
    }
}

impl CreateVTab<'_> for TidbBackupsTab {
    const KIND: VTabKind = VTabKind::Default;
}

impl UpdateVTab<'_> for TidbBackupsTab {
    fn insert(&mut self, args: &Inserts<'_>) -> SqliteResult<i64> {
        // For backups, when only description is provided (single value insert),
        // we need to handle it specially. When both tidb_id and description are provided,
        // use the normal column mapping.
        const ARG_OFFSET: usize = 2;

        let total_args = args.len();
        let provided_values = total_args - ARG_OFFSET;

        let (tidb_id, description) = if provided_values == 1 {
            // Single value provided - assume it's description, and we need a default tidb_id
            // This is a special case where user provides only description
            let _description = args.get::<Option<String>>(ARG_OFFSET)?;

            // Return error - we actually need tidb_id to create a backup
            return Err(rusqlite::Error::InvalidColumnName(
                "INSERT with single value not supported. Please provide both tidb_id and description: INSERT INTO tidb_backups (tidb_id, description) VALUES ('cluster_id', 'backup_description')".to_string(),
            ));
        } else {
            // Multiple values - use column mapping
            let get_column_value = |col_const: c_int| -> SqliteResult<Option<String>> {
                args.get::<Option<String>>((col_const + ARG_OFFSET as c_int) as usize)
            };

            let tidb_id = get_column_value(COL_BACKUP_TIDB_ID)?.ok_or_else(|| {
                rusqlite::Error::InvalidColumnName(
                    "tidb_id is required for creating backups".to_string(),
                )
            })?;
            let description = get_column_value(COL_BACKUP_DESCRIPTION)?;
            (tidb_id, description)
        };

        // Generate backup name from description or use default
        let backup_name = if let Some(ref desc) = description {
            if desc.trim().is_empty() {
                format!("Backup-{}", chrono::Utc::now().format("%Y%m%d-%H%M%S"))
            } else {
                desc.clone()
            }
        } else {
            format!("Backup-{}", chrono::Utc::now().format("%Y%m%d-%H%M%S"))
        };

        match api_bridge::create_backup(&tidb_id, &backup_name, description.as_deref()) {
            Ok(_backup_id) => {
                debug!("✅ Created backup: {backup_name} for cluster {tidb_id}");
                Ok(1) // Return a rowid for the new row
            }
            Err(e) => Err(rusqlite::Error::ModuleError(format!("Insert failed: {e}"))),
        }
    }

    fn delete(&mut self, rowid: rusqlite::types::ValueRef<'_>) -> SqliteResult<()> {
        let rowid_val = rowid.as_i64()?;

        // Look up the (tidb_id, backup_id) using the global rowid mapping
        let rowid_map = get_backup_rowid_map();
        let backup_info = if let Ok(map) = rowid_map.lock() {
            map.get(&rowid_val).cloned()
        } else {
            None
        };

        match backup_info {
            Some((tidb_id, backup_id)) => {
                debug!(
                    "🗑️ Deleting backup {backup_id} from cluster {tidb_id} (rowid: {rowid_val})"
                );

                match api_bridge::delete_backup(&tidb_id, &backup_id) {
                    Ok(()) => {
                        debug!("✅ Successfully deleted backup: {backup_id}");

                        // Remove from the rowid mapping
                        if let Ok(mut map) = rowid_map.lock() {
                            map.remove(&rowid_val);
                        }

                        Ok(())
                    }
                    Err(e) => Err(rusqlite::Error::ModuleError(format!("Delete failed: {e}"))),
                }
            }
            None => {
                debug!("⚠️ Delete requested for rowid {rowid_val}, but no backup info found");
                Err(rusqlite::Error::ModuleError(format!(
                    "Cannot delete backup: no backup info found for rowid {rowid_val}. Try running SELECT first to populate the mapping."
                )))
            }
        }
    }

    fn update(&mut self, args: &Updates<'_>) -> SqliteResult<()> {
        let rowid = args.get::<i64>(0)?;

        // Look up the backup info using the global rowid mapping
        let rowid_map = get_backup_rowid_map();
        let backup_info = if let Ok(map) = rowid_map.lock() {
            map.get(&rowid).cloned()
        } else {
            None
        };

        let (tidb_id, backup_id) = match backup_info {
            Some(info) => info,
            None => {
                return Err(rusqlite::Error::ModuleError(format!(
                    "Cannot update backup: no backup info found for rowid {rowid}. Try running SELECT first to populate the mapping."
                )));
            }
        };

        // Extract updatable column values using the argument offset pattern
        const ARG_OFFSET: usize = 2; // Same offset pattern as other operations

        // Helper function to get optional column value
        let get_column_value = |col_const: c_int| -> SqliteResult<Option<String>> {
            args.get::<Option<String>>((col_const + ARG_OFFSET as c_int) as usize)
        };

        // Only description can be updated for backups
        let description = get_column_value(COL_BACKUP_DESCRIPTION)?;

        let description = match description {
            Some(desc) => desc,
            None => {
                return Err(rusqlite::Error::ModuleError(
                    "No updatable columns specified. Only description can be updated for backups."
                        .to_string(),
                ));
            }
        };

        debug!("🔄 Updating backup {backup_id} (rowid: {rowid})");
        debug!("  description: {description}");

        match api_bridge::update_backup(&tidb_id, &backup_id, &description) {
            Ok(()) => {
                debug!("✅ Successfully updated backup: {backup_id}");
                Ok(())
            }
            Err(e) => Err(rusqlite::Error::ModuleError(format!("Update failed: {e}"))),
        }
    }
}

/// Cursor for iterating over TiDB clusters
#[repr(C)]
struct TidbClustersCursor<'vtab> {
    base: ffi::sqlite3_vtab_cursor,
    row_id: i64,
    clusters: Vec<ClusterData>,
    current_index: usize,
    _phantom: PhantomData<&'vtab TidbClustersTab>,
}

impl<'vtab> TidbClustersCursor<'vtab> {
    fn new() -> Self {
        Self {
            base: ffi::sqlite3_vtab_cursor::default(),
            row_id: 1,
            clusters: Vec::new(),
            current_index: 0,
            _phantom: PhantomData,
        }
    }

    fn fetch_clusters_from_api(&mut self, _constraints: &Filters<'_>) -> SqliteResult<()> {
        // Fetch from API - this must succeed
        let clusters = self.try_fetch_clusters_from_api()?;
        self.clusters = clusters;

        // Update the global rowid to tidb_id mapping
        let rowid_map = get_cluster_rowid_map();
        if let Ok(mut map) = rowid_map.lock() {
            map.clear(); // Clear old mappings
            for (index, cluster) in self.clusters.iter().enumerate() {
                let rowid = (index + 1) as i64; // rowid starts from 1
                map.insert(rowid, cluster.tidb_id.clone());
            }
            debug!(
                "✅ Updated rowid mapping for {} clusters",
                self.clusters.len()
            );
        }

        debug!(
            "✅ Fetched {} clusters from TiDB Cloud API",
            self.clusters.len()
        );
        self.current_index = 0;
        Ok(())
    }

    fn try_fetch_clusters_from_api(&self) -> SqliteResult<Vec<ClusterData>> {
        match api_bridge::fetch_clusters() {
            Ok(clusters) => Ok(clusters),
            Err(e) => Err(rusqlite::Error::ModuleError(e)),
        }
    }
}

/// Cursor for iterating over TiDB backups
#[repr(C)]
struct TidbBackupsCursor<'vtab> {
    base: ffi::sqlite3_vtab_cursor,
    row_id: i64,
    backups: Vec<BackupData>,
    current_index: usize,
    _phantom: PhantomData<&'vtab TidbBackupsTab>,
}

impl<'vtab> TidbBackupsCursor<'vtab> {
    fn new() -> Self {
        Self {
            base: ffi::sqlite3_vtab_cursor::default(),
            row_id: 1,
            backups: Vec::new(),
            current_index: 0,
            _phantom: PhantomData,
        }
    }

    fn fetch_backups_from_api(&mut self, _constraints: &Filters<'_>) -> SqliteResult<()> {
        // Fetch from API - this must succeed
        let backups = self.try_fetch_backups_from_api()?;
        self.backups = backups;

        // Update the global rowid to (tidb_id, backup_id) mapping
        let rowid_map = get_backup_rowid_map();
        if let Ok(mut map) = rowid_map.lock() {
            map.clear(); // Clear old mappings
            for (index, backup) in self.backups.iter().enumerate() {
                let rowid = (index + 1) as i64; // rowid starts from 1
                map.insert(rowid, (backup.tidb_id.clone(), backup.backup_id.clone()));
            }
            debug!(
                "✅ Updated backup rowid mapping for {} backups",
                self.backups.len()
            );
        }

        debug!(
            "✅ Fetched {} backups from TiDB Cloud API",
            self.backups.len()
        );
        self.current_index = 0;
        Ok(())
    }

    fn try_fetch_backups_from_api(&self) -> SqliteResult<Vec<BackupData>> {
        match api_bridge::fetch_backups() {
            Ok(backups) => Ok(backups),
            Err(e) => Err(rusqlite::Error::ModuleError(e)),
        }
    }
}

unsafe impl VTabCursor for TidbClustersCursor<'_> {
    fn filter(
        &mut self,
        _idx_num: c_int,
        _idx_str: Option<&str>,
        _args: &Filters<'_>,
    ) -> SqliteResult<()> {
        self.fetch_clusters_from_api(_args)?;
        self.row_id = 1;
        Ok(())
    }

    fn next(&mut self) -> SqliteResult<()> {
        self.current_index += 1;
        self.row_id += 1;
        Ok(())
    }

    fn eof(&self) -> bool {
        self.current_index >= self.clusters.len()
    }

    fn column(&self, ctx: &mut Context, i: c_int) -> SqliteResult<()> {
        if self.eof() {
            return Ok(());
        }

        let cluster = &self.clusters[self.current_index];
        let value = match i {
            COL_TIDB_ID => &cluster.tidb_id,
            COL_NAME => &cluster.name,
            COL_DISPLAY_NAME => &cluster.display_name,
            COL_REGION_ID => &cluster.region_id,
            COL_STATE => &cluster.state,
            COL_CREATE_TIME => &cluster.create_time,
            COL_ROOT_PASSWORD => &cluster.root_password,
            COL_MIN_RCU => &cluster.min_rcu,
            COL_MAX_RCU => &cluster.max_rcu,
            COL_SERVICE_PLAN => &cluster.service_plan,
            COL_CLOUD_PROVIDER => &cluster.cloud_provider,
            COL_REGION_DISPLAY_NAME => &cluster.region_display_name,
            COL_RAW_DATA => &cluster.raw_data,
            _ => return Ok(()),
        };

        ctx.set_result(value)?;
        Ok(())
    }

    fn rowid(&self) -> SqliteResult<i64> {
        Ok(self.row_id)
    }
}

unsafe impl VTabCursor for TidbBackupsCursor<'_> {
    fn filter(
        &mut self,
        _idx_num: c_int,
        _idx_str: Option<&str>,
        _args: &Filters<'_>,
    ) -> SqliteResult<()> {
        self.fetch_backups_from_api(_args)?;
        self.row_id = 1;
        Ok(())
    }

    fn next(&mut self) -> SqliteResult<()> {
        self.current_index += 1;
        self.row_id += 1;
        Ok(())
    }

    fn eof(&self) -> bool {
        self.current_index >= self.backups.len()
    }

    fn column(&self, ctx: &mut Context, i: c_int) -> SqliteResult<()> {
        if self.eof() {
            return Ok(());
        }

        let backup = &self.backups[self.current_index];
        let value = match i {
            0 => &backup.backup_id,
            1 => &backup.tidb_id,
            2 => &backup.backup_name,
            3 => &backup.description,
            4 => &backup.status,
            5 => &backup.size_bytes,
            6 => &backup.raw_data,
            _ => return Ok(()),
        };

        ctx.set_result(value)?;
        Ok(())
    }

    fn rowid(&self) -> SqliteResult<i64> {
        Ok(self.row_id)
    }
}

/// TiDB Network Access Virtual Table
#[repr(C)]
struct TidbNetworkAccessTab {
    base: ffi::sqlite3_vtab,
}

unsafe impl<'vtab> VTab<'vtab> for TidbNetworkAccessTab {
    type Aux = ();
    type Cursor = TidbNetworkAccessCursor<'vtab>;

    fn connect(
        _db: &mut VTabConnection,
        _aux: Option<&Self::Aux>,
        _args: &[&[u8]],
    ) -> SqliteResult<(String, Self)> {
        let schema = r#"
            CREATE TABLE x(
                tidb_id TEXT,
                enabled TEXT,
                cidr_notation TEXT,
                description TEXT,
                raw_data TEXT
            )
        "#
        .to_owned();

        Ok((
            schema,
            Self {
                base: ffi::sqlite3_vtab::default(),
            },
        ))
    }

    fn best_index(&self, info: &mut IndexInfo) -> SqliteResult<()> {
        let mut tidb_id_idx: Option<usize> = None;

        // Check which constraints we can handle
        for (i, c) in info.constraints().enumerate() {
            if !c.is_usable() {
                continue;
            }
            if c.operator() != IndexConstraintOp::SQLITE_INDEX_CONSTRAINT_EQ {
                continue;
            }
            if c.column() == COL_NETWORK_TIDB_ID {
                tidb_id_idx = Some(i);
            }
        }

        // Set up constraint usage
        if let Some(j) = tidb_id_idx {
            let mut u = info.constraint_usage(j);
            u.set_argv_index(1);
            u.set_omit(true);
        }

        // Set constraint mask
        let mask: c_int = if tidb_id_idx.is_some() { 1 } else { 0 };
        info.set_idx_num(mask);

        // Set cost estimate
        if mask != 0 {
            info.set_estimated_cost(25.0); // With tidb_id constraint
        } else {
            info.set_estimated_cost(2500.0); // Full table scan
        }

        Ok(())
    }

    fn open(&'vtab mut self) -> SqliteResult<Self::Cursor> {
        Ok(TidbNetworkAccessCursor::new())
    }
}

impl CreateVTab<'_> for TidbNetworkAccessTab {
    const KIND: VTabKind = VTabKind::Default;
}

impl UpdateVTab<'_> for TidbNetworkAccessTab {
    fn insert(&mut self, args: &Inserts<'_>) -> SqliteResult<i64> {
        // For network access, the user can specify either:
        // 4 values: tidb_id, cidr_notation, description (enabled defaults to true)
        // 5 values: tidb_id, enabled, cidr_notation, description (explicit enabled)
        const ARG_OFFSET: usize = 2; // Same offset pattern as other tables

        let total_args = args.len();
        let provided_values = total_args - ARG_OFFSET;

        // Helper function to get column value using the constant + offset
        let get_column_value = |col_const: c_int| -> SqliteResult<Option<String>> {
            args.get::<Option<String>>((col_const + ARG_OFFSET as c_int) as usize)
        };

        let (tidb_id, enabled_bool, cidr_notation, description) = if provided_values == 4 {
            // 4 values provided: tidb_id, cidr_notation, description (skip enabled, default to true)
            let tidb_id = args.get::<Option<String>>(ARG_OFFSET)?.ok_or_else(|| {
                rusqlite::Error::InvalidColumnName(
                    "tidb_id is required for adding IP to access list".to_string(),
                )
            })?;

            let cidr_notation = args.get::<Option<String>>(ARG_OFFSET + 1)?.ok_or_else(|| {
                rusqlite::Error::InvalidColumnName(
                    "cidr_notation is required for adding IP to access list".to_string(),
                )
            })?;

            let description = args.get::<Option<String>>(ARG_OFFSET + 2)?.ok_or_else(|| {
                rusqlite::Error::InvalidColumnName(
                    "description is required for adding IP to access list".to_string(),
                )
            })?;

            (tidb_id, None, cidr_notation, description) // enabled defaults to true (None)
        } else {
            // 5 values provided: use normal column mapping
            let tidb_id = get_column_value(COL_NETWORK_TIDB_ID)?.ok_or_else(|| {
                rusqlite::Error::InvalidColumnName(
                    "tidb_id is required for adding IP to access list".to_string(),
                )
            })?;

            let cidr_notation = get_column_value(COL_NETWORK_CIDR_NOTATION)?.ok_or_else(|| {
                rusqlite::Error::InvalidColumnName(
                    "cidr_notation is required for adding IP to access list".to_string(),
                )
            })?;

            let description = get_column_value(COL_NETWORK_DESCRIPTION)?.ok_or_else(|| {
                rusqlite::Error::InvalidColumnName(
                    "description is required for adding IP to access list".to_string(),
                )
            })?;

            // enabled defaults to true, but can be overridden
            let enabled = get_column_value(COL_NETWORK_ENABLED)?;
            let enabled_bool = match enabled.as_deref() {
                Some("false") | Some("0") | Some("no") | Some("off") => Some(false),
                _ => None, // Will default to true in the add_ip_to_access_list function
            };

            (tidb_id, enabled_bool, cidr_notation, description)
        };

        match api_bridge::add_ip_to_access_list(
            &tidb_id,
            &cidr_notation,
            &description,
            enabled_bool,
        ) {
            Ok(()) => {
                debug!("✅ Added IP to access list: {cidr_notation} for cluster {tidb_id}");
                Ok(1) // Return a rowid for the new row
            }
            Err(e) => Err(rusqlite::Error::ModuleError(format!("Insert failed: {e}"))),
        }
    }

    fn delete(&mut self, _rowid: rusqlite::types::ValueRef<'_>) -> SqliteResult<()> {
        Err(rusqlite::Error::ModuleError(
            "DELETE not supported on tidb_network_access. Use UPDATE to modify network access settings.".to_string(),
        ))
    }

    fn update(&mut self, args: &Updates<'_>) -> SqliteResult<()> {
        let rowid = args.get::<i64>(0)?;

        // Look up the (tidb_id, cidr_notation) using the global rowid mapping
        let rowid_map = get_network_access_rowid_map();
        let network_info = if let Ok(map) = rowid_map.lock() {
            map.get(&rowid).cloned()
        } else {
            None
        };

        let (tidb_id, _cidr) = match network_info {
            Some(info) => info,
            None => {
                return Err(rusqlite::Error::ModuleError(format!(
                    "Cannot update network access: no network info found for rowid {rowid}. Try running SELECT first to populate the mapping."
                )));
            }
        };

        // Extract updatable column values using the argument offset pattern
        const ARG_OFFSET: usize = 2; // Same offset pattern as other operations

        // Helper function to get optional column value
        let get_column_value = |col_const: c_int| -> SqliteResult<Option<String>> {
            args.get::<Option<String>>((col_const + ARG_OFFSET as c_int) as usize)
        };

        // Extract the updatable columns
        let enabled = get_column_value(COL_NETWORK_ENABLED)?;
        let cidr_notation = get_column_value(COL_NETWORK_CIDR_NOTATION)?;
        let description = get_column_value(COL_NETWORK_DESCRIPTION)?;

        // Check if at least one field is being updated
        if enabled.is_none() && cidr_notation.is_none() && description.is_none() {
            return Err(rusqlite::Error::ModuleError(
                "No updatable columns specified. Only enabled, cidr_notation, and description can be updated.".to_string()
            ));
        }

        let enabled_str = enabled.unwrap_or_else(|| "true".to_string());
        let cidr_str = cidr_notation.unwrap_or_else(String::new);
        let desc_str = description.unwrap_or_else(String::new);

        debug!("🔄 Updating network access for tidb_id {tidb_id} (rowid: {rowid})");
        debug!("  enabled: {enabled_str}");
        if !cidr_str.is_empty() {
            debug!("  cidr_notation: {cidr_str}");
        }
        if !desc_str.is_empty() {
            debug!("  description: {desc_str}");
        }

        match api_bridge::update_network_access(&tidb_id, &enabled_str, &cidr_str, &desc_str) {
            Ok(()) => {
                debug!("✅ Successfully updated network access: {tidb_id}");
                Ok(())
            }
            Err(e) => Err(rusqlite::Error::ModuleError(format!("Update failed: {e}"))),
        }
    }
}

/// Cursor for iterating over TiDB network access settings
#[repr(C)]
struct TidbNetworkAccessCursor<'vtab> {
    base: ffi::sqlite3_vtab_cursor,
    row_id: i64,
    network_access: Vec<NetworkAccessData>,
    current_index: usize,
    _phantom: PhantomData<&'vtab TidbNetworkAccessTab>,
}

impl<'vtab> TidbNetworkAccessCursor<'vtab> {
    fn new() -> Self {
        Self {
            base: ffi::sqlite3_vtab_cursor::default(),
            row_id: 1,
            network_access: Vec::new(),
            current_index: 0,
            _phantom: PhantomData,
        }
    }

    fn fetch_network_access_from_api(&mut self, _constraints: &Filters<'_>) -> SqliteResult<()> {
        // Fetch from API - this must succeed
        let network_access = self.try_fetch_network_access_from_api()?;
        self.network_access = network_access;

        // Update the global rowid to (tidb_id, cidr_notation) mapping
        let rowid_map = get_network_access_rowid_map();
        if let Ok(mut map) = rowid_map.lock() {
            map.clear(); // Clear old mappings
            for (index, access) in self.network_access.iter().enumerate() {
                let rowid = (index + 1) as i64; // rowid starts from 1
                map.insert(
                    rowid,
                    (access.tidb_id.clone(), access.cidr_notation.clone()),
                );
            }
            debug!(
                "✅ Updated network access rowid mapping for {} entries",
                self.network_access.len()
            );
        }

        debug!(
            "✅ Fetched {} network access entries from TiDB Cloud API",
            self.network_access.len()
        );
        self.current_index = 0;
        Ok(())
    }

    fn try_fetch_network_access_from_api(&self) -> SqliteResult<Vec<NetworkAccessData>> {
        match api_bridge::fetch_network_access() {
            Ok(network_access) => Ok(network_access),
            Err(e) => Err(rusqlite::Error::ModuleError(e)),
        }
    }
}

unsafe impl VTabCursor for TidbNetworkAccessCursor<'_> {
    fn filter(
        &mut self,
        _idx_num: c_int,
        _idx_str: Option<&str>,
        _args: &Filters<'_>,
    ) -> SqliteResult<()> {
        self.fetch_network_access_from_api(_args)?;
        self.row_id = 1;
        Ok(())
    }

    fn next(&mut self) -> SqliteResult<()> {
        self.current_index += 1;
        self.row_id += 1;
        Ok(())
    }

    fn eof(&self) -> bool {
        self.current_index >= self.network_access.len()
    }

    fn column(&self, ctx: &mut Context, i: c_int) -> SqliteResult<()> {
        if self.eof() {
            return Ok(());
        }

        let access = &self.network_access[self.current_index];
        let value = match i {
            COL_NETWORK_TIDB_ID => &access.tidb_id,
            COL_NETWORK_ENABLED => &access.enabled,
            COL_NETWORK_CIDR_NOTATION => &access.cidr_notation,
            COL_NETWORK_DESCRIPTION => &access.description,
            COL_NETWORK_RAW_DATA => &access.raw_data,
            _ => return Ok(()),
        };

        ctx.set_result(value)?;
        Ok(())
    }

    fn rowid(&self) -> SqliteResult<i64> {
        Ok(self.row_id)
    }
}

/// Cluster-specific Network Access Virtual Table (e.g., tidb_123_access_list)
#[repr(C)]
struct TidbClusterNetworkAccessTab {
    base: ffi::sqlite3_vtab,
    cluster_id: String,
}

unsafe impl<'vtab> VTab<'vtab> for TidbClusterNetworkAccessTab {
    type Aux = String; // cluster_id as auxiliary data
    type Cursor = TidbClusterNetworkAccessCursor<'vtab>;

    fn connect(
        _db: &mut VTabConnection,
        aux: Option<&Self::Aux>,
        _args: &[&[u8]],
    ) -> SqliteResult<(String, Self)> {
        let cluster_id = aux
            .ok_or_else(|| {
                rusqlite::Error::ModuleError(
                    "cluster_id required for cluster-specific access table".to_string(),
                )
            })?
            .clone();

        let vtab = Self {
            base: ffi::sqlite3_vtab::default(),
            cluster_id,
        };

        let schema = "CREATE TABLE x(cidr_notation TEXT UNIQUE, description TEXT, enabled TEXT, tidb_id TEXT, raw_data TEXT)";
        Ok((schema.to_string(), vtab))
    }

    fn best_index(&self, info: &mut IndexInfo) -> SqliteResult<()> {
        // Always scan all rows for this cluster
        info.set_estimated_cost(100.0);
        info.set_estimated_rows(100);
        Ok(())
    }

    fn open(&'vtab mut self) -> SqliteResult<Self::Cursor> {
        Ok(TidbClusterNetworkAccessCursor::new(self.cluster_id.clone()))
    }
}

impl CreateVTab<'_> for TidbClusterNetworkAccessTab {
    const KIND: VTabKind = VTabKind::Default;
}

impl UpdateVTab<'_> for TidbClusterNetworkAccessTab {
    fn insert(&mut self, args: &Inserts<'_>) -> SqliteResult<i64> {
        const ARG_OFFSET: usize = 2;

        // Count only non-None values after ARG_OFFSET
        let mut provided_values = 0;
        for i in ARG_OFFSET..args.len() {
            if args.get::<Option<String>>(i).unwrap_or(None).is_some() {
                provided_values += 1;
            }
        }

        let (enabled_bool, cidr_notation, description) = if provided_values == 2 {
            // 2 values for cluster-specific table: cidr_notation, description
            // With schema: cidr_notation TEXT, description TEXT, enabled TEXT, tidb_id TEXT, raw_data TEXT
            let cidr_notation = args.get::<Option<String>>(ARG_OFFSET)?.ok_or_else(|| {
                rusqlite::Error::InvalidColumnName("cidr_notation is required".to_string())
            })?;

            let description = args.get::<Option<String>>(ARG_OFFSET + 1)?.ok_or_else(|| {
                rusqlite::Error::InvalidColumnName("description is required".to_string())
            })?;

            (None, cidr_notation, description) // enabled defaults to true, other fields auto-generated
        } else if provided_values == 3 {
            // 3 values: cidr_notation, description, enabled
            let cidr_notation = args.get::<Option<String>>(ARG_OFFSET)?.ok_or_else(|| {
                rusqlite::Error::InvalidColumnName("cidr_notation is required".to_string())
            })?;

            let description = args.get::<Option<String>>(ARG_OFFSET + 1)?.ok_or_else(|| {
                rusqlite::Error::InvalidColumnName("description is required".to_string())
            })?;

            let enabled = args.get::<Option<String>>(ARG_OFFSET + 2)?;
            let enabled_bool = match enabled.as_deref() {
                Some("false") | Some("0") | Some("no") | Some("off") => Some(false),
                _ => None,
            };

            (enabled_bool, cidr_notation, description)
        } else {
            return Err(rusqlite::Error::InvalidColumnName(
                "cluster-specific access table expects 2-3 values (cidr_notation, description, [enabled])".to_string()
            ));
        };

        // Check for existing CIDR entries to prevent duplicates
        match api_bridge::fetch_network_access() {
            Ok(network_access) => {
                // Check if this CIDR already exists for this cluster
                let duplicate_exists = network_access.iter().any(|entry| {
                    entry.tidb_id == self.cluster_id && entry.cidr_notation == cidr_notation
                });

                if duplicate_exists {
                    return Err(rusqlite::Error::SqliteFailure(
                        rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_CONSTRAINT_UNIQUE),
                        Some(format!(
                            "UNIQUE constraint failed: tidb_{}_network_access.cidr_notation",
                            self.cluster_id
                        )),
                    ));
                }
            }
            Err(e) => {
                debug!("Warning: Could not check for duplicates: {}", e);
                // Continue with insert attempt - API might catch duplicate
            }
        }

        match api_bridge::add_ip_to_access_list(
            &self.cluster_id,
            &cidr_notation,
            &description,
            enabled_bool,
        ) {
            Ok(()) => {
                debug!(
                    "✅ Added IP to cluster {} access list: {}",
                    self.cluster_id, cidr_notation
                );
                Ok(1)
            }
            Err(e) => Err(rusqlite::Error::ModuleError(format!("Insert failed: {e}"))),
        }
    }

    fn delete(&mut self, rowid: rusqlite::types::ValueRef<'_>) -> SqliteResult<()> {
        let rowid_value: i64 = rowid.as_i64()?;

        // Get the network access mapping to find the CIDR to delete
        let network_map = get_network_access_rowid_map();
        if let Ok(map) = network_map.lock()
            && let Some((tidb_id, cidr_notation)) = map.get(&rowid_value)
            && tidb_id == &self.cluster_id
        {
            match api_bridge::remove_ip_from_access_list(tidb_id, cidr_notation) {
                Ok(()) => {
                    debug!(
                        "✅ Removed IP from cluster {} access list: {}",
                        self.cluster_id, cidr_notation
                    );
                    return Ok(());
                }
                Err(e) => {
                    return Err(rusqlite::Error::ModuleError(format!("Delete failed: {e}")));
                }
            }
        }

        Err(rusqlite::Error::ModuleError(
            "Could not find network access entry to delete".to_string(),
        ))
    }

    fn update(&mut self, args: &Updates<'_>) -> SqliteResult<()> {
        let rowid = args.get::<i64>(0)?;

        // Get updated values - only support updating description and enabled status
        let new_enabled = args.get::<Option<String>>(2)?; // enabled column
        let new_description = args.get::<Option<String>>(4)?; // description column

        let network_map = get_network_access_rowid_map();
        if let Ok(map) = network_map.lock()
            && let Some((tidb_id, cidr_notation)) = map.get(&rowid)
            && tidb_id == &self.cluster_id
        {
            let enabled_bool = match new_enabled.as_deref() {
                Some("false") | Some("0") | Some("no") | Some("off") => Some(false),
                Some("true") | Some("1") | Some("yes") | Some("on") => Some(true),
                _ => None,
            };

            match api_bridge::update_access_list_entry(
                tidb_id,
                cidr_notation,
                new_description.as_deref(),
                enabled_bool,
            ) {
                Ok(()) => {
                    debug!(
                        "✅ Updated access list entry for cluster {}: {}",
                        self.cluster_id, cidr_notation
                    );
                    return Ok(());
                }
                Err(e) => {
                    return Err(rusqlite::Error::ModuleError(format!("Update failed: {e}")));
                }
            }
        }

        Err(rusqlite::Error::ModuleError(
            "Could not find network access entry to update".to_string(),
        ))
    }
}

/// Cursor for cluster-specific network access virtual table
#[repr(C)]
struct TidbClusterNetworkAccessCursor<'vtab> {
    base: ffi::sqlite3_vtab_cursor,
    row_id: i64,
    network_access: Vec<NetworkAccessData>,
    current_index: usize,
    cluster_id: String,
    _phantom: PhantomData<&'vtab TidbClusterNetworkAccessTab>,
}

impl<'vtab> TidbClusterNetworkAccessCursor<'vtab> {
    fn new(cluster_id: String) -> Self {
        Self {
            base: ffi::sqlite3_vtab_cursor::default(),
            row_id: 1,
            network_access: Vec::new(),
            current_index: 0,
            cluster_id,
            _phantom: PhantomData,
        }
    }

    fn fetch_cluster_network_access(&mut self) -> SqliteResult<()> {
        match api_bridge::fetch_network_access() {
            Ok(all_access) => {
                // Filter to only include entries for this cluster
                self.network_access = all_access
                    .into_iter()
                    .filter(|access| access.tidb_id == self.cluster_id)
                    .collect();

                // Update the global rowid mapping for this cluster's entries
                let network_map = get_network_access_rowid_map();
                if let Ok(mut map) = network_map.lock() {
                    for (index, access) in self.network_access.iter().enumerate() {
                        let rowid = (index + 1) as i64;
                        map.insert(
                            rowid,
                            (access.tidb_id.clone(), access.cidr_notation.clone()),
                        );
                    }
                }

                debug!(
                    "Fetched {} network access entries for cluster {}",
                    self.network_access.len(),
                    self.cluster_id
                );
                Ok(())
            }
            Err(e) => {
                debug!(
                    "Failed to fetch network access for cluster {}: {}",
                    self.cluster_id, e
                );
                Err(rusqlite::Error::ModuleError(format!(
                    "API fetch failed: {e}"
                )))
            }
        }
    }
}

unsafe impl VTabCursor for TidbClusterNetworkAccessCursor<'_> {
    fn filter(
        &mut self,
        _idx_num: c_int,
        _idx_str: Option<&str>,
        _args: &Filters<'_>,
    ) -> SqliteResult<()> {
        self.fetch_cluster_network_access()?;
        self.row_id = 1;
        Ok(())
    }

    fn next(&mut self) -> SqliteResult<()> {
        self.current_index += 1;
        self.row_id += 1;
        Ok(())
    }

    fn eof(&self) -> bool {
        self.current_index >= self.network_access.len()
    }

    fn column(&self, ctx: &mut Context, i: c_int) -> SqliteResult<()> {
        if self.eof() {
            return Ok(());
        }

        let access = &self.network_access[self.current_index];
        let value = match i {
            0 => &access.cidr_notation, // Column 0: cidr_notation
            1 => &access.description,   // Column 1: description
            2 => &access.enabled,       // Column 2: enabled
            3 => &access.tidb_id,       // Column 3: tidb_id
            4 => &access.raw_data,      // Column 4: raw_data
            _ => return Ok(()),
        };

        ctx.set_result(value)?;
        Ok(())
    }

    fn rowid(&self) -> SqliteResult<i64> {
        Ok(self.row_id)
    }
}

/// Configuration for TiDB Cloud virtual tables
#[derive(Debug, Clone)]
pub struct VTableConfig {
    /// Base URL for the TiDB Cloud API
    pub base_url: String,
    /// API credentials (username:password or API key)
    pub credentials: String,
    /// Table type (clusters, backups, config)
    pub table_type: String,
    /// Primary key field in the JSON response
    pub primary_key: String,
    /// Page size for pagination
    pub page_size: Option<u32>,
    /// Custom headers
    pub headers: Option<std::collections::HashMap<String, String>>,
}

impl Default for VTableConfig {
    fn default() -> Self {
        Self {
            base_url: "https://cloud.dev.tidbapi.com/v1beta2".to_string(),
            credentials: String::new(),
            table_type: "clusters".to_string(),
            primary_key: "id".to_string(),
            page_size: Some(100),
            headers: None,
        }
    }
}

/// Error types for virtual table operations
#[derive(Debug, thiserror::Error)]
pub enum VTableError {
    #[error("SQLite error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    #[error("HTTP request failed: {0}")]
    HttpRequest(String),

    #[error("JSON parsing failed: {0}")]
    JsonParse(String),

    #[error("API error: {0}")]
    ApiError(String),

    #[error("Configuration error: {0}")]
    ConfigError(String),

    #[error("Unsupported operation: {0}")]
    UnsupportedOperation(String),
}

impl From<VTableError> for rusqlite::Error {
    fn from(err: VTableError) -> Self {
        rusqlite::Error::InvalidParameterName(err.to_string())
    }
}

/// Result type for virtual table operations
pub type VTableResult<T> = Result<T, VTableError>;
