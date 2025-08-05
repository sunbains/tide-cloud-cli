use crate::tidb_cloud::{
    client::TiDBCloudClient,
    error::TiDBCloudResult,
    models::*,
    query_utils::{PathBuilder, QueryBuilder},
};

impl TiDBCloudClient {
    // ============================================================================
    // TiDB Cluster Operations
    // ============================================================================

    /// List TiDB clusters
    pub async fn list_tidbs(
        &mut self,
        params: Option<&ListTidbsParams>,
    ) -> TiDBCloudResult<ListTidbsResponse> {
        let query = params.map(|p| self.build_query_string(p)).transpose()?;
        self.get("/tidbs", query.as_deref()).await
    }

    /// Create a new TiDB cluster
    pub async fn create_tidb(
        &mut self,
        tidb: &Tidb,
        validate_only: Option<bool>,
    ) -> TiDBCloudResult<Tidb> {
        let _query = if let Some(validate) = validate_only {
            QueryBuilder::new().validate_only(validate).build()
        } else {
            None
        };
        self.post("/tidbs", Some(tidb)).await
    }

    /// Get a specific TiDB cluster
    pub async fn get_tidb(&mut self, tidb_id: &str) -> TiDBCloudResult<Tidb> {
        let path = PathBuilder::new().tidb_id(tidb_id).build();
        self.get(&path, None).await
    }

    /// Update a TiDB cluster
    pub async fn update_tidb(
        &mut self,
        tidb_id: &str,
        update: &UpdateTidbRequest,
        validate_only: Option<bool>,
    ) -> TiDBCloudResult<Tidb> {
        let path = PathBuilder::new().tidb_id(tidb_id).build();
        let query = if let Some(validate) = validate_only {
            QueryBuilder::new().validate_only(validate).build()
        } else {
            None
        };

        // For PATCH requests with query parameters, we need to build the URL manually
        if let Some(query) = query {
            let url = format!("{}{}?{}", self.base_url(), path, query);
            let response = self
                .http_methods
                .client
                .patch(&url)
                .json(update)
                .send()
                .await?;
            self.http_methods.handle_response(response).await
        } else {
            self.patch(&path, update).await
        }
    }

    /// Delete a TiDB cluster
    pub async fn delete_tidb(
        &mut self,
        tidb_id: &str,
        validate_only: Option<bool>,
    ) -> TiDBCloudResult<Tidb> {
        let path = PathBuilder::new().tidb_id(tidb_id).build();
        let query = if let Some(validate) = validate_only {
            QueryBuilder::new().validate_only(validate).build()
        } else {
            None
        };
        self.delete(&path, query.as_deref()).await
    }

    /// Reset root password for a TiDB cluster
    pub async fn reset_root_password(
        &mut self,
        tidb_id: &str,
        password: &str,
    ) -> TiDBCloudResult<ResetRootPasswordResponse> {
        // Use mixed format: /tidbs/{tidb_id}:resetRootPassword
        let path = format!("/tidbs/{tidb_id}:resetRootPassword");
        let body = ResetRootPasswordBody {
            root_password: password.to_string(),
        };
        self.post(&path, Some(&body)).await
    }

    /// Update public connection settings for a TiDB cluster
    pub async fn update_public_connection(
        &mut self,
        tidb_id: &str,
        request: &UpdatePublicConnectionRequest,
    ) -> TiDBCloudResult<PublicConnectionResponse> {
        let path = PathBuilder::new()
            .tidb_id(tidb_id)
            .public_connection_setting()
            .build();
        self.patch(&path, request).await
    }

    /// Get cloud provider information for a TiDB cluster
    pub async fn get_cloud_provider_info(
        &mut self,
        tidb_id: &str,
    ) -> TiDBCloudResult<CloudProviderInfo> {
        let path = PathBuilder::new()
            .tidb_id(tidb_id)
            .cloud_provider_info()
            .build();
        self.get(&path, None).await
    }

    /// Estimate price for a TiDB cluster
    pub async fn estimate_price(
        &mut self,
        request: &EstimatePriceRequest,
    ) -> TiDBCloudResult<EstimatePriceResponse> {
        self.post("/tidbs:estimatePrice", Some(request)).await
    }

    // ============================================================================
    // Backup Operations
    // ============================================================================

    /// Get backup settings for a TiDB cluster
    pub async fn get_backup_setting(&mut self, tidb_id: &str) -> TiDBCloudResult<BackupSetting> {
        let path = PathBuilder::new().tidb_id(tidb_id).backup_setting().build();
        self.get(&path, None).await
    }

    /// Update backup settings for a TiDB cluster
    pub async fn update_backup_setting(
        &mut self,
        tidb_id: &str,
        settings: &UpdateBackupSettingRequest,
        validate_only: Option<bool>,
    ) -> TiDBCloudResult<BackupSetting> {
        let path = PathBuilder::new().tidb_id(tidb_id).backup_setting().build();
        let query = if let Some(validate) = validate_only {
            QueryBuilder::new().validate_only(validate).build()
        } else {
            None
        };

        if let Some(query) = query {
            let url = format!("{}{}?{}", self.base_url(), path, query);
            let response = self
                .http_methods
                .client
                .patch(&url)
                .json(settings)
                .send()
                .await?;
            self.http_methods.handle_response(response).await
        } else {
            self.patch(&path, settings).await
        }
    }

    /// List backups for a TiDB cluster
    pub async fn list_backups(
        &mut self,
        tidb_id: &str,
        params: Option<&ListBackupsParams>,
    ) -> TiDBCloudResult<ListTidbBackupsResponse> {
        let query = params.map(|p| self.build_query_string(p)).transpose()?;
        let path = PathBuilder::new().tidb_id(tidb_id).backups().build();
        self.get(&path, query.as_deref()).await
    }

    /// Delete a backup
    pub async fn delete_backup(&mut self, tidb_id: &str, backup_id: &str) -> TiDBCloudResult<()> {
        let path = PathBuilder::new()
            .tidb_id(tidb_id)
            .backup_id(backup_id)
            .build();
        let _response: serde_json::Value = self.delete(&path, None).await?;
        // The response is an empty object, so we just return unit
        Ok(())
    }

    // ============================================================================
    // Restore Operations
    // ============================================================================

    /// Restore a TiDB cluster from backup
    pub async fn restore_tidb(
        &mut self,
        request: &RestoreTidbRequest,
    ) -> TiDBCloudResult<RestoreTidbResponse> {
        self.post("/tidbs:restore", Some(request)).await
    }

    /// Get restore status for a TiDB cluster
    pub async fn get_restore_status(
        &mut self,
        tidb_id: &str,
    ) -> TiDBCloudResult<RestoreStatusResponse> {
        let path = PathBuilder::new().tidb_id(tidb_id).restore_status().build();
        self.get(&path, None).await
    }
}

// ============================================================================
// Convenience Methods
// ============================================================================

impl TiDBCloudClient {
    /// List all TiDB clusters with pagination
    pub async fn list_all_tidbs(
        &mut self,
        params: Option<&ListTidbsParams>,
    ) -> TiDBCloudResult<Vec<Tidb>> {
        let mut all_tidbs = Vec::new();
        let mut page_token = None;
        let mut current_params = params.cloned().unwrap_or_default();

        loop {
            current_params.page_token = page_token;
            let response = self.list_tidbs(Some(&current_params)).await?;

            if let Some(tidbs) = response.tidbs {
                all_tidbs.extend(tidbs);
            }

            page_token = response.next_page_token;
            if page_token.is_none() || page_token.as_ref().unwrap().is_empty() {
                break;
            }
        }
        Ok(all_tidbs)
    }

    /// List all backups for a TiDB cluster with pagination
    pub async fn list_all_backups(
        &mut self,
        tidb_id: &str,
        params: Option<&ListBackupsParams>,
    ) -> TiDBCloudResult<Vec<Backup>> {
        let mut all_backups = Vec::new();
        let mut page_token = None;
        let mut current_params = params.cloned().unwrap_or_default();

        loop {
            current_params.page_token = page_token;
            let response = self.list_backups(tidb_id, Some(&current_params)).await?;

            if let Some(backups) = response.backups {
                all_backups.extend(backups);
            }

            page_token = response.next_page_token;
            if page_token.is_none() || page_token.as_ref().unwrap().is_empty() {
                break;
            }
        }

        Ok(all_backups)
    }

    /// Wait for a TiDB cluster to reach a specific state
    pub async fn wait_for_tidb_state(
        &mut self,
        tidb_id: &str,
        target_state: ClusterState,
        timeout: std::time::Duration,
        check_interval: std::time::Duration,
    ) -> TiDBCloudResult<Tidb> {
        let start_time = std::time::Instant::now();

        while start_time.elapsed() < timeout {
            let tidb = self.get_tidb(tidb_id).await?;

            if let Some(state) = &tidb.state
                && state == &target_state
            {
                return Ok(tidb);
            }

            tokio::time::sleep(check_interval).await;
        }

        Err(crate::tidb_cloud::error::TiDBCloudError::TimeoutError(
            format!("TiDB cluster {tidb_id} did not reach state {target_state:?} within timeout"),
        ))
    }

    /// Wait for a TiDB cluster to be active
    pub async fn wait_for_tidb_active(&mut self, tidb_id: &str) -> TiDBCloudResult<Tidb> {
        self.wait_for_tidb_state(
            tidb_id,
            ClusterState::Active,
            std::time::Duration::from_secs(600), // 10 minutes
            std::time::Duration::from_secs(10),  // Check every 10 seconds
        )
        .await
    }

    /// Create a TiDB cluster and wait for it to be active
    pub async fn create_tidb_and_wait(&mut self, tidb: &Tidb) -> TiDBCloudResult<Tidb> {
        let created_tidb = self.create_tidb(tidb, None).await?;

        if let Some(tidb_id) = &created_tidb.tidb_id {
            self.wait_for_tidb_active(tidb_id).await
        } else {
            Ok(created_tidb)
        }
    }

    /// Delete a TiDB cluster and wait for it to be deleted
    pub async fn delete_tidb_and_wait(&mut self, tidb_id: &str) -> TiDBCloudResult<Tidb> {
        let deleted_tidb = self.delete_tidb(tidb_id, None).await?;

        // Wait for the cluster to be deleted
        self.wait_for_tidb_state(
            tidb_id,
            ClusterState::Deleted,
            std::time::Duration::from_secs(300), // 5 minutes
            std::time::Duration::from_secs(10),  // Check every 10 seconds
        )
        .await?;

        Ok(deleted_tidb)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_list_tidbs_params() {
        let client =
            TiDBCloudClient::new("test-api-key-that-is-long-enough-for-validation".to_string())
                .unwrap();

        let params = ListTidbsParams {
            service_plan: Some(ServicePlan::Starter),
            region_ids: None,
            name: Some("test-cluster".to_string()),
            page_size: Some(10),
            page_token: None,
            skip: None,
        };

        let query = client.build_query_string(&params).unwrap();
        println!("Generated query: {query}");
        assert!(query.contains("servicePlan=Starter"));
        assert!(query.contains("name=test-cluster"));
        assert!(query.contains("pageSize=10"));
    }

    #[tokio::test]
    async fn test_list_backups_params() {
        let client =
            TiDBCloudClient::new("test-api-key-that-is-long-enough-for-validation".to_string())
                .unwrap();

        let params = ListBackupsParams {
            state: None,
            region_id: None,
            trigger_type: None,
            start_time: Some("2023-01-01T00:00:00Z".to_string()),
            end_time: Some("2023-12-31T23:59:59Z".to_string()),
            page_size: Some(10),
            page_token: None,
        };

        let query = client.build_query_string(&params).unwrap();
        assert!(query.contains("startTime=2023-01-01T00%3A00%3A00Z"));
        assert!(query.contains("endTime=2023-12-31T23%3A59%3A59Z"));
        assert!(query.contains("pageSize=10"));
    }

    #[test]
    fn test_reset_root_password_url_format() {
        let tidb_id = "12345";
        let expected_path = "/tidbs/12345:resetRootPassword";
        let actual_path = format!("/tidbs/{tidb_id}:resetRootPassword");
        assert_eq!(actual_path, expected_path);
    }

    #[test]
    fn test_update_public_connection_url_format() {
        let tidb_id = "12345";
        let expected_path = "/tidbs/12345/publicConnectionSetting";
        let actual_path = PathBuilder::new()
            .tidb_id(tidb_id)
            .public_connection_setting()
            .build();
        assert_eq!(actual_path, expected_path);
    }
}
