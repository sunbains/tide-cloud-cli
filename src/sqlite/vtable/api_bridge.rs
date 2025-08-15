//! API bridge for converting async TiDB Cloud API calls to sync vtable operations

use crate::tidb_cloud::{TiDBCloudClient, models::*};
use serde_json;
use std::sync::{Arc, Mutex, OnceLock};
use tokio::runtime::Runtime;

// Global runtime for async-to-sync conversion
static RUNTIME: OnceLock<Runtime> = OnceLock::new();

// Global client storage
static CLIENT: OnceLock<Arc<Mutex<TiDBCloudClient>>> = OnceLock::new();

/// Initialize the API bridge with a TiDB client
pub fn initialize(client: TiDBCloudClient) -> Result<(), Box<dyn std::error::Error>> {
    // Initialize the tokio runtime
    let rt = Runtime::new()?;
    RUNTIME.set(rt).map_err(|_| "Runtime already initialized")?;

    // Store the client
    CLIENT
        .set(Arc::new(Mutex::new(client)))
        .map_err(|_| "Client already initialized")?;

    Ok(())
}

/// Cluster data for virtual table
#[derive(Clone)]
pub struct ClusterData {
    pub tidb_id: String,
    pub name: String,
    pub display_name: String,
    pub region_id: String,
    pub state: String,
    pub create_time: String,
    pub root_password: String,
    pub min_rcu: String,
    pub max_rcu: String,
    pub service_plan: String,
    pub cloud_provider: String,
    pub region_display_name: String,
    pub raw_data: String,
}

/// Backup data for virtual table
#[derive(Clone)]
pub struct BackupData {
    pub backup_id: String,
    pub tidb_id: String,
    pub backup_name: String,
    pub description: String,
    pub status: String,
    pub size_bytes: String,
    pub raw_data: String,
}

/// Network access data for virtual table
#[derive(Clone)]
pub struct NetworkAccessData {
    pub tidb_id: String,
    pub enabled: String,
    pub cidr_notation: String,
    pub description: String,
    pub raw_data: String,
}

/// Fetch clusters from TiDB Cloud API (sync wrapper)
pub fn fetch_clusters() -> Result<Vec<ClusterData>, String> {
    let runtime = RUNTIME.get().ok_or("Runtime not initialized")?;

    let client = CLIENT.get().ok_or("Client not initialized")?;

    let result = runtime.block_on(async {
        let mut client_clone = {
            let client_guard = client.lock().unwrap();
            client_guard.clone()
        };
        client_clone.list_all_tidbs(None).await
    });

    match result {
        Ok(tidbs) => {
            let clusters: Vec<ClusterData> = tidbs
                .into_iter()
                .map(|tidb| {
                    let raw_data = serde_json::to_string(&tidb).unwrap_or_default();
                    ClusterData {
                        tidb_id: tidb.tidb_id.unwrap_or_default(),
                        name: tidb.name.unwrap_or_default(),
                        display_name: tidb.display_name,
                        region_id: tidb.region_id,
                        state: format!("{:?}", tidb.state.unwrap_or(ClusterState::Creating)),
                        create_time: tidb.create_time.unwrap_or_default(),
                        root_password: "".to_string(), // Never expose passwords
                        min_rcu: tidb.min_rcu,
                        max_rcu: tidb.max_rcu,
                        service_plan: format!("{:?}", tidb.service_plan),
                        cloud_provider: format!(
                            "{:?}",
                            tidb.cloud_provider.unwrap_or(CloudProvider::Aws)
                        ),
                        region_display_name: tidb.region_display_name.unwrap_or_default(),
                        raw_data,
                    }
                })
                .collect();
            Ok(clusters)
        }
        Err(e) => Err(format!("API error: {e}")),
    }
}

/// Fetch backups from TiDB Cloud API (sync wrapper)
pub fn fetch_backups() -> Result<Vec<BackupData>, String> {
    let runtime = RUNTIME.get().ok_or("Runtime not initialized")?;

    let client = CLIENT.get().ok_or("Client not initialized")?;

    let result = runtime.block_on(async {
        let mut client_clone = {
            let client_guard = client.lock().unwrap();
            client_guard.clone()
        };

        // First get all clusters, then get backups for each
        let tidbs = client_clone.list_all_tidbs(None).await?;
        let mut all_backups = Vec::new();

        for tidb in tidbs {
            if let Some(tidb_id) = tidb.tidb_id {
                match client_clone.list_all_backups(&tidb_id, None).await {
                    Ok(backups) => {
                        for backup in backups {
                            let raw_data = serde_json::to_string(&backup).unwrap_or_default();
                            let backup_data = BackupData {
                                backup_id: backup.id.unwrap_or_default(),
                                tidb_id: tidb_id.clone(),
                                backup_name: backup.display_name.unwrap_or_default(),
                                description: backup.description.unwrap_or_default(),
                                status: format!(
                                    "{:?}",
                                    backup.state.unwrap_or(BackupState::Unknown)
                                ),
                                size_bytes: backup.size_bytes.unwrap_or_default(),
                                raw_data,
                            };
                            all_backups.push(backup_data);
                        }
                    }
                    Err(_e) => {
                        // Continue if we can't get backups for this cluster
                        // This could happen if the cluster doesn't support backups
                    }
                }
            }
        }

        Ok::<Vec<BackupData>, crate::tidb_cloud::error::TiDBCloudError>(all_backups)
    });

    match result {
        Ok(backups) => Ok(backups),
        Err(e) => Err(format!("API error: {e}")),
    }
}

// ============================================================================
// Cluster Management Operations
// ============================================================================

/// Create a new cluster (sync wrapper)
pub fn create_cluster(
    display_name: &str,
    region_id: &str,
    min_rcu: &str,
    max_rcu: &str,
    service_plan: &str,
    cloud_provider: &str,
) -> Result<String, String> {
    let runtime = RUNTIME.get().ok_or("Runtime not initialized")?;

    let client = CLIENT.get().ok_or("Client not initialized")?;

    // Parse service plan
    let service_plan_enum = match service_plan.to_lowercase().as_str() {
        "starter" => ServicePlan::Starter,
        "essential" => ServicePlan::Essential,
        "premium" => ServicePlan::Premium,
        "byoc" => ServicePlan::BYOC,
        _ => return Err(format!("Invalid service plan: {service_plan}")),
    };

    // Parse cloud provider
    let cloud_provider_enum = match cloud_provider.to_lowercase().as_str() {
        "aws" => CloudProvider::Aws,
        "gcp" => CloudProvider::Gcp,
        "azure" => CloudProvider::Azure,
        "alicloud" => CloudProvider::Alicloud,
        _ => return Err(format!("Invalid cloud provider: {cloud_provider}")),
    };

    let result = runtime.block_on(async {
        let mut client_clone = {
            let client_guard = client.lock().unwrap();
            client_guard.clone()
        };

        let tidb = Tidb {
            display_name: display_name.to_string(),
            region_id: region_id.to_string(),
            min_rcu: min_rcu.to_string(),
            max_rcu: max_rcu.to_string(),
            service_plan: service_plan_enum,
            cloud_provider: Some(cloud_provider_enum),
            ..Default::default()
        };

        client_clone.create_tidb(&tidb, None).await
    });

    match result {
        Ok(created_tidb) => {
            let tidb_id = created_tidb.tidb_id.unwrap_or_default();
            Ok(tidb_id)
        }
        Err(e) => Err(format!("Failed to create cluster: {e}")),
    }
}

/// Update an existing cluster (sync wrapper)
pub fn update_cluster(
    tidb_id: &str,
    display_name: Option<&str>,
    min_rcu: Option<&str>,
    max_rcu: Option<&str>,
) -> Result<(), String> {
    let runtime = RUNTIME.get().ok_or("Runtime not initialized")?;

    let client = CLIENT.get().ok_or("Client not initialized")?;

    let result = runtime.block_on(async {
        let mut client_clone = {
            let client_guard = client.lock().unwrap();
            client_guard.clone()
        };

        let update_request = UpdateTidbRequest {
            display_name: display_name.map(|s| s.to_string()),
            min_rcu: min_rcu.map(|s| s.to_string()),
            max_rcu: max_rcu.map(|s| s.to_string()),
        };

        client_clone
            .update_tidb(tidb_id, &update_request, None)
            .await
    });

    match result {
        Ok(_) => Ok(()),
        Err(e) => Err(format!("Failed to update cluster: {e}")),
    }
}

/// Update cluster root password (sync wrapper)
pub fn update_cluster_root_password(tidb_id: &str, new_password: &str) -> Result<(), String> {
    let runtime = RUNTIME.get().ok_or("Runtime not initialized")?;

    let client = CLIENT.get().ok_or("Client not initialized")?;

    let result = runtime.block_on(async {
        let mut client_clone = {
            let client_guard = client.lock().unwrap();
            client_guard.clone()
        };
        client_clone
            .update_root_password(tidb_id, new_password)
            .await
    });

    match result {
        Ok(_) => Ok(()),
        Err(e) => Err(format!("Failed to update root password: {e}")),
    }
}

/// Delete a cluster (sync wrapper)
pub fn delete_cluster(tidb_id: &str) -> Result<(), String> {
    let runtime = RUNTIME.get().ok_or("Runtime not initialized")?;

    let client = CLIENT.get().ok_or("Client not initialized")?;

    let result = runtime.block_on(async {
        let mut client_clone = {
            let client_guard = client.lock().unwrap();
            client_guard.clone()
        };
        client_clone.delete_tidb(tidb_id, None).await
    });

    match result {
        Ok(_) => Ok(()),
        Err(e) => Err(format!("Failed to delete cluster: {e}")),
    }
}

// ============================================================================
// Backup Management Operations
// ============================================================================

/// Create a new backup (sync wrapper)
pub fn create_backup(
    tidb_id: &str,
    backup_name: &str,
    description: Option<&str>,
) -> Result<String, String> {
    let runtime = RUNTIME.get().ok_or("Runtime not initialized")?;

    let client = CLIENT.get().ok_or("Client not initialized")?;

    let result = runtime.block_on(async {
        let mut client_clone = {
            let client_guard = client.lock().unwrap();
            client_guard.clone()
        };

        let backup_request = CreateBackupRequest {
            display_name: Some(backup_name.to_string()),
            description: description.map(|d| d.to_string()),
        };

        client_clone.create_backup(tidb_id, &backup_request).await
    });

    match result {
        Ok(backup) => {
            let backup_id = backup.id.unwrap_or_default();
            Ok(backup_id)
        }
        Err(e) => Err(format!("Failed to create backup: {e}")),
    }
}

/// Update a backup (sync wrapper)
pub fn update_backup(tidb_id: &str, backup_id: &str, description: &str) -> Result<(), String> {
    let runtime = RUNTIME.get().ok_or("Runtime not initialized")?;

    let client = CLIENT.get().ok_or("Client not initialized")?;

    let result = runtime.block_on(async {
        let mut client_clone = {
            let client_guard = client.lock().unwrap();
            client_guard.clone()
        };

        let update_request = crate::tidb_cloud::models::UpdateBackupRequest {
            description: Some(description.to_string()),
        };

        client_clone
            .update_backup(tidb_id, backup_id, &update_request)
            .await
    });

    match result {
        Ok(_) => Ok(()),
        Err(e) => Err(format!("Failed to update backup: {e}")),
    }
}

/// Delete a backup (sync wrapper)
pub fn delete_backup(tidb_id: &str, backup_id: &str) -> Result<(), String> {
    let runtime = RUNTIME.get().ok_or("Runtime not initialized")?;

    let client = CLIENT.get().ok_or("Client not initialized")?;

    let result = runtime.block_on(async {
        let mut client_clone = {
            let client_guard = client.lock().unwrap();
            client_guard.clone()
        };
        client_clone.delete_backup(tidb_id, backup_id).await
    });

    match result {
        Ok(_) => Ok(()),
        Err(e) => Err(format!("Failed to delete backup: {e}")),
    }
}

// ============================================================================
// Network Access Management Operations
// ============================================================================

/// Fetch network access settings from TiDB Cloud API (sync wrapper)
pub fn fetch_network_access() -> Result<Vec<NetworkAccessData>, String> {
    let runtime = RUNTIME.get().ok_or("Runtime not initialized")?;

    let client = CLIENT.get().ok_or("Client not initialized")?;

    let result = runtime.block_on(async {
        let mut client_clone = {
            let client_guard = client.lock().unwrap();
            client_guard.clone()
        };

        // First get all clusters, then get network access settings for each
        let tidbs = client_clone.list_all_tidbs(None).await?;
        let mut all_network_access = Vec::new();

        for tidb in tidbs {
            if let Some(tidb_id) = tidb.tidb_id {
                match client_clone.get_public_connection(&tidb_id).await {
                    Ok(connection) => {
                        let raw_data = serde_json::to_string(&connection).unwrap_or_default();

                        // Create a row for each IP access entry, or one row if no entries
                        if connection.ip_access_list.is_empty() {
                            let network_data = NetworkAccessData {
                                tidb_id: connection.tidb_id,
                                enabled: connection.enabled.to_string(),
                                cidr_notation: String::new(),
                                description: String::new(),
                                raw_data,
                            };
                            all_network_access.push(network_data);
                        } else {
                            for entry in connection.ip_access_list {
                                let network_data = NetworkAccessData {
                                    tidb_id: connection.tidb_id.clone(),
                                    enabled: connection.enabled.to_string(),
                                    cidr_notation: entry.cidr_notation,
                                    description: entry.description,
                                    raw_data: raw_data.clone(),
                                };
                                all_network_access.push(network_data);
                            }
                        }
                    }
                    Err(_e) => {
                        // Continue if we can't get network access for this cluster
                        // This could happen if the cluster doesn't support network access or isn't ready yet
                    }
                }
            }
        }

        Ok::<Vec<NetworkAccessData>, crate::tidb_cloud::error::TiDBCloudError>(all_network_access)
    });

    match result {
        Ok(network_access) => Ok(network_access),
        Err(e) => Err(format!("API error: {e}")),
    }
}

/// Add IP to access list (sync wrapper)
pub fn add_ip_to_access_list(
    tidb_id: &str,
    cidr_notation: &str,
    description: &str,
    enabled: Option<bool>,
) -> Result<(), String> {
    let runtime = RUNTIME.get().ok_or("Runtime not initialized")?;

    let client = CLIENT.get().ok_or("Client not initialized")?;

    let enabled_val = enabled.unwrap_or(true);

    let result = runtime.block_on(async {
        let mut client_clone = {
            let client_guard = client.lock().unwrap();
            client_guard.clone()
        };

        // Get current settings first
        let current_settings = client_clone.get_public_connection(tidb_id).await?;

        // Create new IP access list
        let mut ip_access_list = current_settings.ip_access_list;

        // Add new entry
        use crate::tidb_cloud::models::IpAccessListEntry;
        ip_access_list.push(IpAccessListEntry {
            cidr_notation: cidr_notation.to_string(),
            description: description.to_string(),
        });

        let update_request = crate::tidb_cloud::models::UpdatePublicConnectionRequest {
            enabled: enabled_val,
            ip_access_list,
        };

        client_clone
            .update_public_connection(tidb_id, &update_request)
            .await
    });

    match result {
        Ok(_) => Ok(()),
        Err(e) => Err(format!("Failed to add IP to access list: {e}")),
    }
}

/// Remove IP from access list (sync wrapper)
pub fn remove_ip_from_access_list(tidb_id: &str, cidr_notation: &str) -> Result<(), String> {
    let runtime = RUNTIME.get().ok_or("Runtime not initialized")?;

    let client = CLIENT.get().ok_or("Client not initialized")?;

    let result = runtime.block_on(async {
        let mut client_clone = {
            let client_guard = client.lock().unwrap();
            client_guard.clone()
        };

        // Get current settings first
        let current_settings = client_clone.get_public_connection(tidb_id).await?;

        // Remove the specified entry from IP access list
        let ip_access_list = current_settings
            .ip_access_list
            .into_iter()
            .filter(|entry| entry.cidr_notation != cidr_notation)
            .collect();

        let update_request = crate::tidb_cloud::models::UpdatePublicConnectionRequest {
            enabled: current_settings.enabled,
            ip_access_list,
        };

        client_clone
            .update_public_connection(tidb_id, &update_request)
            .await
    });

    match result {
        Ok(_) => Ok(()),
        Err(e) => Err(format!("Failed to remove IP from access list: {e}")),
    }
}

/// Update a specific access list entry (sync wrapper)
pub fn update_access_list_entry(
    tidb_id: &str,
    cidr_notation: &str,
    new_description: Option<&str>,
    new_enabled: Option<bool>,
) -> Result<(), String> {
    let runtime = RUNTIME.get().ok_or("Runtime not initialized")?;

    let client = CLIENT.get().ok_or("Client not initialized")?;

    let result = runtime.block_on(async {
        let mut client_clone = {
            let client_guard = client.lock().unwrap();
            client_guard.clone()
        };

        // Get current settings first
        let current_settings = client_clone.get_public_connection(tidb_id).await?;

        // Update the specified entry in IP access list
        let ip_access_list = current_settings
            .ip_access_list
            .into_iter()
            .map(|mut entry| {
                if entry.cidr_notation == cidr_notation
                    && let Some(desc) = new_description
                {
                    entry.description = desc.to_string();
                }
                // Note: enabled is a global setting, not per-entry, but we can update the global setting
                entry
            })
            .collect();

        let enabled_val = new_enabled.unwrap_or(current_settings.enabled);

        let update_request = crate::tidb_cloud::models::UpdatePublicConnectionRequest {
            enabled: enabled_val,
            ip_access_list,
        };

        client_clone
            .update_public_connection(tidb_id, &update_request)
            .await
    });

    match result {
        Ok(_) => Ok(()),
        Err(e) => Err(format!("Failed to update access list entry: {e}")),
    }
}

/// Update network access settings (sync wrapper)
pub fn update_network_access(
    tidb_id: &str,
    enabled: &str,
    cidr_notation: &str,
    description: &str,
) -> Result<(), String> {
    let runtime = RUNTIME.get().ok_or("Runtime not initialized")?;

    let client = CLIENT.get().ok_or("Client not initialized")?;

    // Parse enabled string to boolean
    let enabled_bool = match enabled.to_lowercase().as_str() {
        "true" | "1" | "yes" | "on" => true,
        "false" | "0" | "no" | "off" => false,
        _ => return Err(format!("Invalid enabled value: {enabled}. Use true/false")),
    };

    let result = runtime.block_on(async {
        let mut client_clone = {
            let client_guard = client.lock().unwrap();
            client_guard.clone()
        };

        // Get current settings first
        let current_settings = client_clone.get_public_connection(tidb_id).await?;

        // Create new IP access list
        let mut ip_access_list = current_settings.ip_access_list;

        // If we have new CIDR and description, update or add the entry
        if !cidr_notation.is_empty() {
            // Check if this CIDR already exists and update it
            let mut found = false;
            for entry in &mut ip_access_list {
                if entry.cidr_notation == cidr_notation {
                    entry.description = description.to_string();
                    found = true;
                    break;
                }
            }

            // If not found, add new entry
            if !found {
                use crate::tidb_cloud::models::IpAccessListEntry;
                ip_access_list.push(IpAccessListEntry {
                    cidr_notation: cidr_notation.to_string(),
                    description: description.to_string(),
                });
            }
        }

        let update_request = crate::tidb_cloud::models::UpdatePublicConnectionRequest {
            enabled: enabled_bool,
            ip_access_list,
        };

        client_clone
            .update_public_connection(tidb_id, &update_request)
            .await
    });

    match result {
        Ok(_) => Ok(()),
        Err(e) => Err(format!("Failed to update network access: {e}")),
    }
}
