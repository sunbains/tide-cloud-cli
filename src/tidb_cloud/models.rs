use field_names_macro::FieldNames;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ============================================================================
// Enums
// ============================================================================

/// Enum of possible states of a cluster
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ClusterState {
    Creating,
    Deleting,
    Active,
    Restoring,
    Maintenance,
    Deleted,
    Inactive,
    Upgrading,
    Importing,
    Modifying,
    Pausing,
    Paused,
    Resuming,
}

/// Service plan types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub enum ServicePlan {
    Starter,
    Essential,
    Premium,
    BYOC,
}

/// Cloud provider names
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum CloudProvider {
    #[serde(rename = "aws")]
    Aws,
    #[serde(rename = "gcp")]
    Gcp,
    #[serde(rename = "azure")]
    Azure,
    #[serde(rename = "alicloud")]
    Alicloud,
}

/// Backup state enum
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BackupState {
    Unknown,
    Pending,
    Running,
    Succeeded,
    Failed,
    Cancelled,
}

/// Backup trigger type enum
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BackupTriggerType {
    Auto,
    Manual,
}

/// Backup type enum
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BackupType {
    Snapshot,
    Copied,
}

/// Backup schedule type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BackupScheduleType {
    Daily,
    Hourly,
}

/// Restore mode enum
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RestoreMode {
    Snapshot,
    Pitr,
}

/// Restore state enum
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RestoreState {
    Unknown,
    Pending,
    Running,
    Succeeded,
    Failed,
    Cancelled,
}

/// Endpoint connection type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EndpointConnectionType {
    Public,
    PrivateEndpoint,
    VpcPeering,
}

/// High availability type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HighAvailabilityType {
    Regional,
    Zonal,
    #[serde(rename = "HIGH_AVAILABILITY_TYPE_UNSPECIFIED")]
    Unspecified,
}

/// Component type for price estimation
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ComponentType {
    RuCost,
    StorageCost,
}

// ============================================================================
// Core Models
// ============================================================================

/// TiDB cluster information
#[derive(Debug, Clone, Serialize, Deserialize, FieldNames)]
#[serde(rename_all = "camelCase")]
pub struct Tidb {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tidb_id: Option<String>,
    pub display_name: String,
    pub region_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cloud_provider: Option<CloudProvider>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region_display_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<ClusterState>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub root_password: Option<String>,
    pub min_rcu: String,
    pub max_rcu: String,
    pub service_plan: ServicePlan,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub high_availability_type: Option<HighAvailabilityType>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub annotations: Option<HashMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub labels: Option<HashMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub creator: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub create_time: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub update_time: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoints: Option<Vec<TidbEndpoint>>,
}

impl Default for Tidb {
    fn default() -> Self {
        Self {
            name: None,
            tidb_id: None,
            display_name: String::new(),
            region_id: String::new(),
            cloud_provider: None,
            region_display_name: None,
            state: None,
            root_password: None,
            min_rcu: String::new(),
            max_rcu: String::new(),
            service_plan: ServicePlan::Starter,
            high_availability_type: None,
            annotations: None,
            labels: None,
            creator: None,
            create_time: None,
            update_time: None,
            endpoints: None,
        }
    }
}

/// TiDB endpoint information
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TidbEndpoint {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connection_type: Option<EndpointConnectionType>,
}

/// Backup information
#[derive(Debug, Clone, Serialize, Deserialize, FieldNames)]
#[serde(rename_all = "camelCase")]
pub struct Backup {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tidb_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organization_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_plan: Option<ServicePlan>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub create_time: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size_bytes: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<BackupState>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub r#type: Option<BackupType>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trigger_type: Option<BackupTriggerType>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expiration_time: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backup_ts: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region_id: Option<String>,
}

/// Backup setting configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BackupSetting {
    pub tidb_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schedule_type: Option<BackupScheduleType>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schedule: Option<BackupSchedule>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retention_days: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_backup_time: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pitr_start_time: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pitr_end_time: Option<String>,
}

/// Backup schedule configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BackupSchedule {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub daily_schedule: Option<DailySchedule>,
}

/// Daily backup schedule
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DailySchedule {
    pub schedule_time: String, // Format: "hour:minute" like "16:40"
}

/// Cloud provider information
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CloudProviderInfo {
    pub tidb_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cloud_provider: Option<CloudProvider>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tidb_cloud_account_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tidb_cloud_account_external_id: Option<String>,
}

/// Component cost for price estimation
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ComponentCost {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub component_type: Option<ComponentType>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub budget_limit: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub row_storage: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub column_storage: Option<f64>,
}

// ============================================================================
// Request/Response Models
// ============================================================================

/// List TiDB clusters response
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListTidbsResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tidbs: Option<Vec<Tidb>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_size: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_page_token: Option<String>,
}

/// List backups response
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListTidbBackupsResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backups: Option<Vec<Backup>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_size: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_page_token: Option<String>,
}

/// Price estimation request
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EstimatePriceRequest {
    pub region_id: String,
    pub min_rcu: String,
    pub max_rcu: String,
    pub service_plan: ServicePlan,
    pub row_storage_size: String,
    pub column_storage_size: String,
}

/// Price estimation response
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EstimatePriceResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub costs: Option<Vec<ComponentCost>>,
}

/// Restore TiDB request
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RestoreTidbRequest {
    pub tidb: Tidb,
    pub source_tidb_id: String,
    pub restore_mode: RestoreMode,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backup_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub point_in_time: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub validate_only: Option<bool>,
}

/// Restore TiDB response
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RestoreTidbResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tidb: Option<Tidb>,
}

/// Restore status response
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RestoreStatusResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<RestoreState>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub progress: Option<i32>,
}

/// Reset root password request body
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResetRootPasswordBody {
    pub root_password: String,
}

/// Reset root password response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResetRootPasswordResponse {}

// ============================================================================
// Query Parameters
// ============================================================================

/// Query parameters for listing TiDB clusters
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ListTidbsParams {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_plan: Option<ServicePlan>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region_ids: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub page_size: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub page_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skip: Option<i32>,
}

/// Query parameters for listing backups
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ListBackupsParams {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<Vec<BackupState>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region_id: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trigger_type: Option<Vec<BackupTriggerType>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_time: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_time: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub page_size: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub page_token: Option<String>,
}

// ============================================================================
// Update Models
// ============================================================================

/// Update TiDB request body
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct UpdateTidbRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_rcu: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_rcu: Option<String>,
}

/// Create backup request body
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct CreateBackupRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// Update backup request body
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct UpdateBackupRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// Update backup setting request body
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateBackupSettingRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schedule_type: Option<BackupScheduleType>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schedule: Option<BackupSchedule>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retention_days: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_backup_time: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pitr_start_time: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pitr_end_time: Option<String>,
}

/// IP access list entry for public connection settings
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IpAccessListEntry {
    pub cidr_notation: String,
    pub description: String,
}

/// Request body for updating public connection settings
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdatePublicConnectionRequest {
    pub enabled: bool,
    pub ip_access_list: Vec<IpAccessListEntry>,
}

/// Response for public connection settings
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicConnectionResponse {
    pub name: String,
    pub tidb_id: String,
    pub enabled: bool,
    pub ip_access_list: Vec<IpAccessListEntry>,
}
