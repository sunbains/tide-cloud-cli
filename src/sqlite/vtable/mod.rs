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
use api_bridge::{BackupData, ClusterData, PublicEndpointData};

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

// Global mapping from rowid to (tidb_id, endpoint_id) for public endpoint deletions
type PublicEndpointRowidMap = Arc<Mutex<HashMap<i64, (String, String)>>>;
static PUBLIC_ENDPOINT_ROWID_MAP: OnceLock<PublicEndpointRowidMap> = OnceLock::new();

fn get_public_endpoint_rowid_map() -> &'static PublicEndpointRowidMap {
    PUBLIC_ENDPOINT_ROWID_MAP.get_or_init(|| Arc::new(Mutex::new(HashMap::new())))
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

// Column constants for the public_endpoints virtual table
const COL_ENDPOINT_ID: c_int = 0;
const COL_ENDPOINT_TIDB_ID: c_int = 1;
const COL_HOST: c_int = 2;
const COL_PORT: c_int = 3;
const COL_CONNECTION_TYPE: c_int = 4;
const COL_ENDPOINT_RAW_DATA: c_int = 5;

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

    // Register the public_endpoints virtual table (read-only for now)
    conn.create_module(
        "tidb_public_endpoints",
        rusqlite::vtab::read_only_module::<TidbPublicEndpointsTab>(),
        None::<()>,
    )?;

    debug!("Virtual table modules registered successfully");
    debug!("Available tables: tidb_clusters, tidb_backups, tidb_public_endpoints");
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
            Ok(_tidb_id) => {
                debug!("✅ Created cluster: {display_name}");
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
        // For backups, the user should specify tidb_id and description
        // backup_name will be auto-generated from description or use a default
        const ARG_OFFSET: usize = 2; // Same offset pattern as clusters

        // Helper function to get column value using the constant + offset
        let get_column_value = |col_const: c_int| -> SqliteResult<Option<String>> {
            args.get::<Option<String>>((col_const + ARG_OFFSET as c_int) as usize)
        };

        // Extract required values
        let tidb_id = get_column_value(COL_BACKUP_TIDB_ID)?.ok_or_else(|| {
            rusqlite::Error::InvalidColumnName(
                "tidb_id is required for creating backups".to_string(),
            )
        })?;
        let description = get_column_value(COL_BACKUP_DESCRIPTION)?;

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

/// TiDB Public Endpoints Virtual Table
#[repr(C)]
struct TidbPublicEndpointsTab {
    base: ffi::sqlite3_vtab,
}

unsafe impl<'vtab> VTab<'vtab> for TidbPublicEndpointsTab {
    type Aux = ();
    type Cursor = TidbPublicEndpointsCursor<'vtab>;

    fn connect(
        _db: &mut VTabConnection,
        _aux: Option<&Self::Aux>,
        _args: &[&[u8]],
    ) -> SqliteResult<(String, Self)> {
        let schema = r#"
            CREATE TABLE x(
                endpoint_id TEXT PRIMARY KEY,
                tidb_id TEXT,
                host TEXT,
                port TEXT,
                connection_type TEXT,
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
        let mut endpoint_id_idx: Option<usize> = None;

        // Check which constraints we can handle
        for (i, c) in info.constraints().enumerate() {
            if !c.is_usable() {
                continue;
            }
            if c.operator() != IndexConstraintOp::SQLITE_INDEX_CONSTRAINT_EQ {
                continue;
            }
            match c.column() {
                COL_ENDPOINT_TIDB_ID => tidb_id_idx = Some(i),
                COL_ENDPOINT_ID => endpoint_id_idx = Some(i),
                _ => {}
            }
        }

        // Set up constraint usage
        let mut n = 0i32;
        if let Some(j) = tidb_id_idx {
            n += 1;
            let mut u = info.constraint_usage(j);
            u.set_argv_index(n);
            u.set_omit(true);
        }
        if let Some(j) = endpoint_id_idx {
            n += 1;
            let mut u = info.constraint_usage(j);
            u.set_argv_index(n);
            u.set_omit(true);
        }

        // Set constraint mask
        let mut mask: c_int = 0;
        if tidb_id_idx.is_some() {
            mask |= 1;
        }
        if endpoint_id_idx.is_some() {
            mask |= 2;
        }
        info.set_idx_num(mask);

        // Set cost estimate
        if mask != 0 {
            info.set_estimated_cost(50.0); // With constraints
        } else {
            info.set_estimated_cost(1000.0); // Full table scan
        }

        Ok(())
    }

    fn open(&'vtab mut self) -> SqliteResult<Self::Cursor> {
        Ok(TidbPublicEndpointsCursor::new())
    }
}

impl CreateVTab<'_> for TidbPublicEndpointsTab {
    const KIND: VTabKind = VTabKind::Default;
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

/// Cursor for iterating over TiDB public endpoints
#[repr(C)]
struct TidbPublicEndpointsCursor<'vtab> {
    base: ffi::sqlite3_vtab_cursor,
    row_id: i64,
    endpoints: Vec<PublicEndpointData>,
    current_index: usize,
    _phantom: PhantomData<&'vtab TidbPublicEndpointsTab>,
}

impl<'vtab> TidbPublicEndpointsCursor<'vtab> {
    fn new() -> Self {
        Self {
            base: ffi::sqlite3_vtab_cursor::default(),
            row_id: 1,
            endpoints: Vec::new(),
            current_index: 0,
            _phantom: PhantomData,
        }
    }

    fn fetch_endpoints_from_api(&mut self, _constraints: &Filters<'_>) -> SqliteResult<()> {
        // Fetch from API - this must succeed
        let endpoints = self.try_fetch_endpoints_from_api()?;
        self.endpoints = endpoints;

        // Update the global rowid to (tidb_id, endpoint_id) mapping
        let rowid_map = get_public_endpoint_rowid_map();
        if let Ok(mut map) = rowid_map.lock() {
            map.clear(); // Clear old mappings
            for (index, endpoint) in self.endpoints.iter().enumerate() {
                let rowid = (index + 1) as i64; // rowid starts from 1
                map.insert(
                    rowid,
                    (endpoint.tidb_id.clone(), endpoint.endpoint_id.clone()),
                );
            }
            debug!(
                "✅ Updated public endpoint rowid mapping for {} endpoints",
                self.endpoints.len()
            );
        }

        debug!(
            "✅ Fetched {} public endpoints from TiDB Cloud API",
            self.endpoints.len()
        );
        self.current_index = 0;
        Ok(())
    }

    fn try_fetch_endpoints_from_api(&self) -> SqliteResult<Vec<PublicEndpointData>> {
        match api_bridge::fetch_public_endpoints() {
            Ok(endpoints) => Ok(endpoints),
            Err(e) => Err(rusqlite::Error::ModuleError(e)),
        }
    }
}

unsafe impl VTabCursor for TidbPublicEndpointsCursor<'_> {
    fn filter(
        &mut self,
        _idx_num: c_int,
        _idx_str: Option<&str>,
        _args: &Filters<'_>,
    ) -> SqliteResult<()> {
        self.fetch_endpoints_from_api(_args)?;
        self.row_id = 1;
        Ok(())
    }

    fn next(&mut self) -> SqliteResult<()> {
        self.current_index += 1;
        self.row_id += 1;
        Ok(())
    }

    fn eof(&self) -> bool {
        self.current_index >= self.endpoints.len()
    }

    fn column(&self, ctx: &mut Context, i: c_int) -> SqliteResult<()> {
        if self.eof() {
            return Ok(());
        }

        let endpoint = &self.endpoints[self.current_index];
        let value = match i {
            COL_ENDPOINT_ID => &endpoint.endpoint_id,
            COL_ENDPOINT_TIDB_ID => &endpoint.tidb_id,
            COL_HOST => &endpoint.host,
            COL_PORT => &endpoint.port,
            COL_CONNECTION_TYPE => &endpoint.connection_type,
            COL_ENDPOINT_RAW_DATA => &endpoint.raw_data,
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
