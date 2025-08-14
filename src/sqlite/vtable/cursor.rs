use super::{VTableConfig, VTableError, VTableResult};

/// Cursor for iterating over TiDB Cloud API results
pub struct TiDBCloudCursor {
    config: VTableConfig,
    // Note: HttpClient removed - now using tidb_cloud module API
    current_data: Option<serde_json::Value>,
    current_index: usize,
    all_data: Vec<serde_json::Value>,
    eof: bool,
}

impl TiDBCloudCursor {
    pub fn new(config: VTableConfig) -> VTableResult<Self> {
        Ok(Self {
            config,
            current_data: None,
            current_index: 0,
            all_data: Vec::new(),
            eof: true, // Start with EOF until data is fetched
        })
    }



    /// Build the API endpoint URL
    fn build_endpoint(&self) -> VTableResult<String> {
        let endpoint = match self.config.table_type.as_str() {
            "clusters" => format!("{}/tidbs", self.config.base_url),
            "backups" => format!("{}/backups", self.config.base_url),
            "config" => format!("{}/config", self.config.base_url),
            _ => {
                return Err(VTableError::ConfigError(format!(
                    "Unsupported table type: {}",
                    self.config.table_type
                )));
            }
        };

        Ok(endpoint)
    }

    /// Build the authorization header
    fn build_auth_header(&self) -> VTableResult<String> {
        if self.config.credentials.contains(':') {
            // username:password format
            Ok(self.config.credentials.clone())
        } else {
            // API key format
            Ok(format!("Bearer {}", self.config.credentials))
        }
    }

    /// Parse the API response based on table type
    fn parse_response(&self, response: serde_json::Value) -> VTableResult<Vec<serde_json::Value>> {
        match self.config.table_type.as_str() {
            "clusters" => {
                if let Some(tidbs) = response.get("tidbs")
                    && let Some(array) = tidbs.as_array()
                {
                    return Ok(array.clone());
                }
                Ok(vec![])
            }
            "backups" => {
                if let Some(backups) = response.get("backups")
                    && let Some(array) = backups.as_array()
                {
                    return Ok(array.clone());
                }
                Ok(vec![])
            }
            "config" => {
                // For config, we might want to flatten the response
                Ok(vec![response])
            }
            _ => Ok(vec![]),
        }
    }

    /// Extract a column value from the current row
    pub fn extract_column(&self, column_index: i32) -> VTableResult<String> {
        let current_data = self
            .current_data
            .as_ref()
            .ok_or(VTableError::UnsupportedOperation(
                "No current row".to_string(),
            ))?;

        let value = match self.config.table_type.as_str() {
            "clusters" => self.extract_cluster_column(current_data, column_index)?,
            "backups" => self.extract_backup_column(current_data, column_index)?,
            "config" => self.extract_config_column(current_data, column_index)?,
            _ => {
                return Err(VTableError::UnsupportedOperation(format!(
                    "Unsupported table type: {}",
                    self.config.table_type
                )));
            }
        };

        Ok(value)
    }

    /// Extract column values for clusters table
    fn extract_cluster_column(
        &self,
        data: &serde_json::Value,
        column_index: i32,
    ) -> VTableResult<String> {
        let value = match column_index {
            0 => data
                .get("tidb_id")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            1 => data
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            2 => data
                .get("displayName")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            3 => data
                .get("regionId")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            4 => data
                .get("regionDisplayName")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            5 => data
                .get("state")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            6 => data
                .get("rootPassword")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            7 => data
                .get("minRcu")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            8 => data
                .get("maxRcu")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            9 => data
                .get("servicePlan")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            10 => data
                .get("highAvailabilityType")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            11 => data
                .get("creator")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            12 => data
                .get("createTime")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            13 => data
                .get("updateTime")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            14 => data.to_string(),
            _ => {
                return Err(VTableError::UnsupportedOperation(format!(
                    "Invalid column index: {column_index}"
                )));
            }
        };

        Ok(value)
    }

    /// Extract column values for backups table
    fn extract_backup_column(
        &self,
        data: &serde_json::Value,
        column_index: i32,
    ) -> VTableResult<String> {
        let value = match column_index {
            0 => data
                .get("backupId")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            1 => data
                .get("tidbId")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            2 => data
                .get("backupName")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            3 => data
                .get("backupType")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            4 => data
                .get("description")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            5 => data
                .get("sizeBytes")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            6 => data
                .get("status")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            7 => data
                .get("startTime")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            8 => data
                .get("endTime")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            9 => data.to_string(),
            _ => {
                return Err(VTableError::UnsupportedOperation(format!(
                    "Invalid column index: {column_index}"
                )));
            }
        };

        Ok(value)
    }

    /// Extract column values for config table
    fn extract_config_column(
        &self,
        data: &serde_json::Value,
        column_index: i32,
    ) -> VTableResult<String> {
        let value = match column_index {
            0 => "api_info".to_string(),                     // key
            1 => "TiDB Cloud API Configuration".to_string(), // value
            2 => data.to_string(),                           // raw_data
            _ => {
                return Err(VTableError::UnsupportedOperation(format!(
                    "Invalid column index: {column_index}"
                )));
            }
        };

        Ok(value)
    }

    /// Move to next row
    pub fn advance(&mut self) -> VTableResult<()> {
        if self.current_index < self.all_data.len() {
            self.current_data = Some(self.all_data[self.current_index].clone());
            self.current_index += 1;
            self.eof = false;
        } else {
            self.eof = true;
        }
        Ok(())
    }

    /// Check if we've reached the end
    pub fn eof(&self) -> bool {
        self.eof
    }

    /// Get the current row ID
    pub fn rowid(&self) -> i64 {
        self.current_index as i64
    }
}
