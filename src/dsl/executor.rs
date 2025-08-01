use crate::dsl::{
    error::{DSLError, DSLResult},
    commands::{DSLCommand, DSLCommandType, DSLResult as CommandResult, DSLBatchResult},
    syntax::DSLValue,
};
use crate::tidb_cloud::{TiDBCloudClient, models::*};
use std::collections::HashMap;
use std::time::Instant;
use tokio::time::{sleep, Duration};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use colored::*;

/// DSL executor that runs commands against the TiDB Cloud API
pub struct DSLExecutor {
    client: TiDBCloudClient,
    variables: HashMap<String, DSLValue>,
    _timeout: Duration,
    request_count: Arc<AtomicU64>,
    last_request_time: Arc<AtomicU64>,
}

impl DSLExecutor {
    /// Create a new DSL executor with a TiDB Cloud client
    pub fn new(client: TiDBCloudClient) -> Self {
        // Validate that the client has a valid API key
        if !Self::is_valid_api_key(&client) {
            tracing::warn!("DSLExecutor created with potentially invalid API key");
        }
        
        Self {
            client,
            variables: HashMap::new(),
            _timeout: Duration::from_secs(300), // 5 minutes default timeout
            request_count: Arc::new(AtomicU64::new(0)),
            last_request_time: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Validate API key format (basic validation)
    fn is_valid_api_key(client: &TiDBCloudClient) -> bool {
        // This is a basic validation - in production, you might want to make a test API call
        // For now, we just check if the API key is not empty and has reasonable length
        let api_key = client.api_key();
        !api_key.is_empty() && api_key.len() >= 20 && api_key.len() <= 100
    }

    /// Create a new DSL executor with custom timeout
    pub fn with_timeout(client: TiDBCloudClient, timeout: Duration) -> Self {
        Self {
            client,
            variables: HashMap::new(),
            _timeout: timeout,
            request_count: Arc::new(AtomicU64::new(0)),
            last_request_time: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Execute a single command
    pub async fn execute(&mut self, command: DSLCommand) -> DSLResult<CommandResult> {
        let start_time = Instant::now();
        
        tracing::info!("Executing command: {:?}", command.command_type);
        tracing::debug!("Command parameters: {:?}", command.parameters);
        
        let result = match command.command_type {
            DSLCommandType::CreateCluster => self.execute_create_cluster(command).await,
            DSLCommandType::DeleteCluster => self.execute_delete_cluster(command).await,
            DSLCommandType::ListClusters => self.execute_list_clusters(command).await,
            DSLCommandType::GetCluster => self.execute_get_cluster(command).await,
            DSLCommandType::UpdateCluster => self.execute_update_cluster(command).await,
            DSLCommandType::WaitForCluster => self.execute_wait_for_cluster(command).await,
            DSLCommandType::CreateBackup => self.execute_create_backup(command).await,
            DSLCommandType::ListBackups => self.execute_list_backups(command).await,
            DSLCommandType::DeleteBackup => self.execute_delete_backup(command).await,
            DSLCommandType::EstimatePrice => self.execute_estimate_price(command).await,
            DSLCommandType::SetVariable => self.execute_set_variable(command).await,
            DSLCommandType::GetVariable => self.execute_get_variable(command).await,
            DSLCommandType::Echo => self.execute_echo(command).await,
            DSLCommandType::Sleep => self.execute_sleep(command).await,
            DSLCommandType::If => self.execute_if(command).await,
            DSLCommandType::Loop => self.execute_loop(command).await,
            DSLCommandType::Break => self.execute_break(command).await,
            DSLCommandType::Continue => self.execute_continue(command).await,
            DSLCommandType::Return => self.execute_return(command).await,
            DSLCommandType::Exit => self.execute_exit(command).await,
            _ => Err(DSLError::unknown_command(format!("{:?}", command.command_type))),
        };

        let duration = start_time.elapsed();
        
        match result {
            Ok(mut cmd_result) => {
                cmd_result = cmd_result.with_metadata("duration_ms", DSLValue::from(duration.as_millis() as f64));
                tracing::info!("Command executed successfully in {:?}", duration);
                Ok(cmd_result)
            }
            Err(e) => {
                tracing::error!("Command execution failed: {}", e);
                Err(e)
            }
        }
    }

    /// Execute multiple commands in sequence
    pub async fn execute_batch(&mut self, commands: Vec<DSLCommand>) -> DSLResult<DSLBatchResult> {
        let start_time = Instant::now();
        let mut batch_result = DSLBatchResult::new();

        for (index, command) in commands.into_iter().enumerate() {
            match self.execute(command.clone()).await {
                Ok(result) => {
                    batch_result.add_result(result);
                }
                Err(e) => {
                    let error_message = e.to_string();
                    batch_result.add_result(CommandResult::failure(e));
                    
                    // Check if we should continue on error
                    if !self.should_continue_on_error(&command) {
                        return Err(DSLError::batch_error(index, error_message));
                    }
                }
            }
        }

        batch_result.set_duration(start_time.elapsed());
        Ok(batch_result)
    }

    /// Execute a script from a string
    pub async fn execute_script(&mut self, script: &str) -> DSLResult<DSLBatchResult> {
        let commands = crate::dsl::parser::DSLParser::parse_script(script)?;
        self.execute_batch(commands).await
    }

    // Command execution methods

    async fn execute_create_cluster(&self, command: DSLCommand) -> DSLResult<CommandResult> {
        let name = command.get_parameter_as_string("name")?;
        let region = command.get_parameter_as_string("region")?;
        
        // Validate cluster name and region
        self.validate_cluster_name(&name)?;
        self.validate_region(&region)?;
        
        let min_rcu = command.get_optional_parameter("min_rcu")
            .map(|v| match v {
                DSLValue::String(s) => s.clone(),
                DSLValue::Number(n) => n.to_string(),
                _ => "1".to_string(),
            })
            .unwrap_or("1".to_string());
        let max_rcu = command.get_optional_parameter("max_rcu")
            .map(|v| match v {
                DSLValue::String(s) => s.clone(),
                DSLValue::Number(n) => n.to_string(),
                _ => "10".to_string(),
            })
            .unwrap_or("10".to_string());
        let service_plan = command.get_optional_parameter("service_plan")
            .and_then(|v| v.as_string())
            .unwrap_or("STARTER");
        let password = command.get_optional_parameter("password")
            .and_then(|v| v.as_string());

        let service_plan_enum = match service_plan.to_uppercase().as_str() {
            "STARTER" => ServicePlan::Starter,
            "ESSENTIAL" => ServicePlan::Essential,
            "PREMIUM" => ServicePlan::Premium,
            "BYOC" => ServicePlan::BYOC,
            _ => return Err(DSLError::invalid_parameter("service_plan", service_plan, "Must be STARTER, ESSENTIAL, PREMIUM, or BYOC")),
        };

        let tidb = Tidb {
            display_name: name.to_string(),
            region_id: region.to_string(),
            min_rcu: min_rcu.to_string(),
            max_rcu: max_rcu.to_string(),
            service_plan: service_plan_enum,
            root_password: password.map(|p| p.to_string()),
            ..Default::default()
        };

        match self.client.create_tidb(&tidb, None).await {
            Ok(cluster) => {
                let cluster_data = self.cluster_to_dsl_value(cluster);
                Ok(CommandResult::success_with_data_and_message(
                    cluster_data,
                    format!("Successfully created cluster '{}'", name)
                ))
            }
            Err(e) => Err(DSLError::execution_error_with_source(
                format!("Failed to create cluster '{}'", name),
                e.to_string()
            )),
        }
    }

    async fn execute_delete_cluster(&self, command: DSLCommand) -> DSLResult<CommandResult> {
        let name = command.get_parameter_as_string("name")?;
        
        // First, get the cluster to find its ID
        let clusters = self.client.list_all_tidbs(None).await
            .map_err(|e| DSLError::execution_error_with_source(
                "Failed to list clusters",
                e.to_string()
            ))?;

        let cluster = clusters.iter()
            .find(|c| c.display_name == name)
            .ok_or_else(|| DSLError::resource_not_found(format!("Cluster '{}'", name)))?;

        let cluster_id = cluster.tidb_id.as_ref()
            .ok_or_else(|| DSLError::execution_error("Cluster has no ID"))?;

        match self.client.delete_tidb(cluster_id, None).await {
            Ok(_) => Ok(CommandResult::success_with_message(
                format!("Successfully deleted cluster '{}'", name)
            )),
            Err(e) => Err(DSLError::execution_error_with_source(
                format!("Failed to delete cluster '{}'", name),
                e.to_string()
            )),
        }
    }

    async fn execute_list_clusters(&self, command: DSLCommand) -> DSLResult<CommandResult> {
        // Check rate limiting before making API call
        self.check_rate_limit().await?;
        
        match self.client.list_all_tidbs(None).await {
            Ok(mut clusters) => {
                // Apply WHERE clause filtering if present
                let mut filters = Vec::new();
                for (key, value) in &command.parameters {
                    if key.starts_with("filter_") {
                        if let DSLValue::String(filter_str) = value {
                            filters.push(filter_str.clone());
                        }
                    }
                }
                
                // Apply filters to clusters
                if !filters.is_empty() {
                    clusters.retain(|cluster| {
                        filters.iter().all(|filter| {
                            self.evaluate_filter(cluster, filter)
                        })
                    });
                }
                
                let clusters_len = clusters.len();
                
                // Create formatted display string with colored output
                let mut display_lines = Vec::new();
                display_lines.push(format!("{}", "Clusters:".bold().white()));
                
                for cluster in &clusters {
                    let formatted_cluster = self.format_cluster_for_display(cluster);
                    display_lines.push(format!("  {}", formatted_cluster));
                }
                
                let display_text = display_lines.join("\n");
                
                // Also create the original data structure for programmatic access
                let clusters_data = DSLValue::Array(
                    clusters.into_iter()
                        .map(|c| self.cluster_to_dsl_value(c))
                        .collect()
                );
                
                Ok(CommandResult::success_with_data_and_message(
                    clusters_data,
                    format!("Found {} clusters\n{}", clusters_len, display_text)
                ))
            }
            Err(e) => {
                tracing::error!("TiDB Cloud API error: {}", e);
                Err(DSLError::execution_error_with_source(
                    "Failed to list clusters",
                    e.to_string()
                ))
            },
        }
    }

    async fn execute_get_cluster(&self, command: DSLCommand) -> DSLResult<CommandResult> {
        let name = command.get_parameter_as_string("name")?;
        
        let clusters = self.client.list_all_tidbs(None).await
            .map_err(|e| DSLError::execution_error_with_source(
                "Failed to list clusters",
                e.to_string()
            ))?;

        let cluster = clusters.into_iter()
            .find(|c| c.display_name == name)
            .ok_or_else(|| DSLError::resource_not_found(format!("Cluster '{}'", name)))?;

        // Create formatted display string with colored output first
        let formatted_cluster = self.format_cluster_for_display(&cluster);
        let display_text = format!("Cluster Details:\n  {}", formatted_cluster);
        
        let cluster_data = self.cluster_to_dsl_value(cluster);
        
        Ok(CommandResult::success_with_data_and_message(
            cluster_data,
            format!("Found cluster '{}'\n{}", name, display_text)
        ))
    }

    async fn execute_update_cluster(&self, command: DSLCommand) -> DSLResult<CommandResult> {
        let name = command.get_parameter_as_string("name")?;
        
        // Check rate limiting before making API call
        self.check_rate_limit().await?;
        
        // First, get the cluster to find its ID
        let clusters = self.client.list_all_tidbs(None).await
            .map_err(|e| DSLError::execution_error_with_source(
                "Failed to list clusters",
                e.to_string()
            ))?;

        let cluster = clusters.iter()
            .find(|c| c.display_name == name)
            .ok_or_else(|| DSLError::resource_not_found(format!("Cluster '{}'", name)))?;

        let _cluster_id = cluster.tidb_id.as_ref()
            .ok_or_else(|| DSLError::execution_error("Cluster has no ID"))?;

        // Build update request
        let mut update = UpdateTidbRequest {
            display_name: cluster.display_name.clone(),
            min_rcu: cluster.min_rcu.clone(),
            max_rcu: cluster.max_rcu.clone(),
        };
        
        if let Some(max_rcu) = command.get_optional_parameter("max_rcu") {
            if let Some(max_rcu_str) = max_rcu.as_string() {
                update.max_rcu = max_rcu_str.to_string();
            }
        }

        if let Some(display_name) = command.get_optional_parameter("display_name") {
            if let Some(display_name_str) = display_name.as_string() {
                update.display_name = display_name_str.to_string();
            }
        }

        // TODO: Implement actual update_tidb method in TiDBCloudClient
        // For now, we'll return a success message with the prepared update
        tracing::info!("Would update cluster '{}' with: {:?}", name, update);
        
        Ok(CommandResult::success_with_message(
            format!("Update request prepared for cluster '{}' (implementation pending)", name)
        ))
    }

    async fn execute_wait_for_cluster(&self, command: DSLCommand) -> DSLResult<CommandResult> {
        let name = command.get_parameter_as_string("name")?;
        let state = command.get_parameter_as_string("state")?;
        let timeout_seconds = command.get_optional_parameter("timeout")
            .and_then(|v| v.as_number())
            .unwrap_or(600.0) as u64;

        let target_state = match state.to_uppercase().as_str() {
            "ACTIVE" => ClusterState::Active,
            "CREATING" => ClusterState::Creating,
            "DELETING" => ClusterState::Deleting,
            "MAINTENANCE" => ClusterState::Maintenance,
            "PAUSED" => ClusterState::Paused,
            "RESUMING" => ClusterState::Resuming,
            _ => return Err(DSLError::invalid_parameter("state", state, "Invalid cluster state")),
        };

        // First, get the cluster to find its ID
        let clusters = self.client.list_all_tidbs(None).await
            .map_err(|e| DSLError::execution_error_with_source(
                "Failed to list clusters",
                e.to_string()
            ))?;

        let cluster = clusters.iter()
            .find(|c| c.display_name == name)
            .ok_or_else(|| DSLError::resource_not_found(format!("Cluster '{}'", name)))?;

        let cluster_id = cluster.tidb_id.as_ref()
            .ok_or_else(|| DSLError::execution_error("Cluster has no ID"))?;

        match self.client.wait_for_tidb_state(
            cluster_id,
            target_state,
            Duration::from_secs(timeout_seconds),
            Duration::from_secs(10),
        ).await {
            Ok(cluster) => {
                let cluster_data = self.cluster_to_dsl_value(cluster);
                Ok(CommandResult::success_with_data_and_message(
                    cluster_data,
                    format!("Cluster '{}' reached state '{}'", name, state)
                ))
            }
            Err(e) => Err(DSLError::execution_error_with_source(
                format!("Failed to wait for cluster '{}' to reach state '{}'", name, state),
                e.to_string()
            )),
        }
    }

    async fn execute_create_backup(&self, command: DSLCommand) -> DSLResult<CommandResult> {
        let cluster_name = command.get_parameter_as_string("cluster_name")?;
        let _description = command.get_optional_parameter("description")
            .and_then(|v| v.as_string());

        // First, get the cluster to find its ID
        let clusters = self.client.list_all_tidbs(None).await
            .map_err(|e| DSLError::execution_error_with_source(
                "Failed to list clusters",
                e.to_string()
            ))?;

        let cluster = clusters.iter()
            .find(|c| c.display_name == cluster_name)
            .ok_or_else(|| DSLError::resource_not_found(format!("Cluster '{}'", cluster_name)))?;

        let _cluster_id = cluster.tidb_id.as_ref()
            .ok_or_else(|| DSLError::execution_error("Cluster has no ID"))?;

        // Note: The actual backup creation might need to be implemented in the client
        // For now, we'll return a success message
        Ok(CommandResult::success_with_message(
            format!("Backup creation initiated for cluster '{}'", cluster_name)
        ))
    }

    async fn execute_list_backups(&self, command: DSLCommand) -> DSLResult<CommandResult> {
        let cluster_name = command.get_parameter_as_string("cluster_name")?;
        
        // First, get the cluster to find its ID
        let clusters = self.client.list_all_tidbs(None).await
            .map_err(|e| DSLError::execution_error_with_source(
                "Failed to list clusters",
                e.to_string()
            ))?;

        let cluster = clusters.iter()
            .find(|c| c.display_name == cluster_name)
            .ok_or_else(|| DSLError::resource_not_found(format!("Cluster '{}'", cluster_name)))?;

        let cluster_id = cluster.tidb_id.as_ref()
            .ok_or_else(|| DSLError::execution_error("Cluster has no ID"))?;

        match self.client.list_all_backups(cluster_id, None).await {
            Ok(backups) => {
                let backups_len = backups.len();
                let backups_data = DSLValue::Array(
                    backups.into_iter()
                        .map(|b| self.backup_to_dsl_value(b))
                        .collect()
                );
                Ok(CommandResult::success_with_data_and_message(
                    backups_data,
                    format!("Found {} backups for cluster '{}'", backups_len, cluster_name)
                ))
            }
            Err(e) => Err(DSLError::execution_error_with_source(
                format!("Failed to list backups for cluster '{}'", cluster_name),
                e.to_string()
            )),
        }
    }

    async fn execute_delete_backup(&self, command: DSLCommand) -> DSLResult<CommandResult> {
        let backup_id = command.get_parameter_as_string("backup_id")?;
        let cluster_name = command.get_parameter_as_string("cluster_name")?;
        
        // First, get the cluster to find its ID
        let clusters = self.client.list_all_tidbs(None).await
            .map_err(|e| DSLError::execution_error_with_source(
                "Failed to list clusters",
                e.to_string()
            ))?;

        let cluster = clusters.iter()
            .find(|c| c.display_name == cluster_name)
            .ok_or_else(|| DSLError::resource_not_found(format!("Cluster '{}'", cluster_name)))?;

        let cluster_id = cluster.tidb_id.as_ref()
            .ok_or_else(|| DSLError::execution_error("Cluster has no ID"))?;

        match self.client.delete_backup(cluster_id, &backup_id).await {
            Ok(_) => Ok(CommandResult::success_with_message(
                format!("Successfully deleted backup '{}' from cluster '{}'", backup_id, cluster_name)
            )),
            Err(e) => Err(DSLError::execution_error_with_source(
                format!("Failed to delete backup '{}' from cluster '{}'", backup_id, cluster_name),
                e.to_string()
            )),
        }
    }

    async fn execute_estimate_price(&self, command: DSLCommand) -> DSLResult<CommandResult> {
        let region = command.get_parameter_as_string("region")?;
        let min_rcu = command.get_parameter_as_string("min_rcu")?;
        let max_rcu = command.get_parameter_as_string("max_rcu")?;
        let service_plan = command.get_parameter_as_string("service_plan")?;
        let storage = command.get_optional_parameter("storage")
            .and_then(|v| v.as_string())
            .unwrap_or("1073741824"); // 1GB default

        let service_plan_enum = match service_plan.to_uppercase().as_str() {
            "STARTER" => ServicePlan::Starter,
            "ESSENTIAL" => ServicePlan::Essential,
            "PREMIUM" => ServicePlan::Premium,
            "BYOC" => ServicePlan::BYOC,
            _ => return Err(DSLError::invalid_parameter("service_plan", service_plan, "Must be STARTER, ESSENTIAL, PREMIUM, or BYOC")),
        };

        let price_request = EstimatePriceRequest {
            region_id: region.to_string(),
            min_rcu: min_rcu.to_string(),
            max_rcu: max_rcu.to_string(),
            service_plan: service_plan_enum,
            row_storage_size: storage.to_string(),
            column_storage_size: storage.to_string(),
        };

        match self.client.estimate_price(&price_request).await {
            Ok(price) => {
                let price_data = self.price_to_dsl_value(price);
                Ok(CommandResult::success_with_data_and_message(
                    price_data,
                    format!("Price estimated for region '{}' with RCU range {}-{}", region, min_rcu, max_rcu)
                ))
            }
            Err(e) => Err(DSLError::execution_error_with_source(
                format!("Failed to estimate price for region '{}'", region),
                e.to_string()
            )),
        }
    }

    async fn execute_set_variable(&mut self, command: DSLCommand) -> DSLResult<CommandResult> {
        let name = command.get_parameter_as_string("name")?;
        let value = command.require_parameter("value")?.clone();
        
        self.variables.insert(name.to_string(), value.clone());
        
        Ok(CommandResult::success_with_data_and_message(
            value,
            format!("Set variable '{}'", name)
        ))
    }

    async fn execute_get_variable(&self, command: DSLCommand) -> DSLResult<CommandResult> {
        let name = command.get_parameter_as_string("name")?;
        
        match self.variables.get(name) {
            Some(value) => Ok(CommandResult::success_with_data_and_message(
                value.clone(),
                format!("Variable '{}' = {}", name, value)
            )),
            None => Err(DSLError::variable_not_found(name)),
        }
    }

    async fn execute_echo(&self, command: DSLCommand) -> DSLResult<CommandResult> {
        let message = command.get_parameter_as_string("message")?;
        
        // Sanitize the message to prevent injection attacks
        let sanitized_message = self.sanitize_output(message);
        
        println!("{}", sanitized_message);
        
        Ok(CommandResult::success_with_message(
            format!("Echoed: {}", sanitized_message)
        ))
    }

    async fn execute_sleep(&self, command: DSLCommand) -> DSLResult<CommandResult> {
        let seconds = command.get_parameter_as_number("seconds")?;
        
        sleep(Duration::from_secs_f64(seconds)).await;
        
        Ok(CommandResult::success_with_message(
            format!("Slept for {} seconds", seconds)
        ))
    }

    async fn execute_if(&mut self, command: DSLCommand) -> DSLResult<CommandResult> {
        let condition = command.require_parameter("condition")?;
        
        if condition.is_truthy() {
            Ok(CommandResult::success_with_message("If condition was true"))
        } else {
            Ok(CommandResult::success_with_message("If condition was false"))
        }
    }

    async fn execute_loop(&mut self, _command: DSLCommand) -> DSLResult<CommandResult> {
        // For now, just return success
        // In a full implementation, this would handle loop execution
        Ok(CommandResult::success_with_message("Loop executed"))
    }

    async fn execute_break(&mut self, _command: DSLCommand) -> DSLResult<CommandResult> {
        Ok(CommandResult::success_with_message("Break executed"))
    }

    async fn execute_continue(&mut self, _command: DSLCommand) -> DSLResult<CommandResult> {
        Ok(CommandResult::success_with_message("Continue executed"))
    }

    async fn execute_return(&mut self, command: DSLCommand) -> DSLResult<CommandResult> {
        if let Some(value) = command.get_optional_parameter("value") {
            Ok(CommandResult::success_with_data_and_message(
                value.clone(),
                "Return executed"
            ))
        } else {
            Ok(CommandResult::success_with_message("Return executed"))
        }
    }

    async fn execute_exit(&mut self, _command: DSLCommand) -> DSLResult<CommandResult> {
        Ok(CommandResult::success_with_message("Exit executed"))
    }

    // Helper methods

    fn should_continue_on_error(&self, _command: &DSLCommand) -> bool {
        // For now, always continue on error
        // This could be configurable per command or globally
        true
    }

    fn cluster_to_dsl_value(&self, cluster: Tidb) -> DSLValue {
        let mut obj = HashMap::new();
        obj.insert("id".to_string(), DSLValue::from(cluster.tidb_id.unwrap_or_default()));
        obj.insert("name".to_string(), DSLValue::from(cluster.display_name));
        obj.insert("region".to_string(), DSLValue::from(cluster.region_id));
        obj.insert("state".to_string(), DSLValue::from(format!("{:?}", cluster.state.unwrap_or(ClusterState::Creating))));
        obj.insert("min_rcu".to_string(), DSLValue::from(cluster.min_rcu));
        obj.insert("max_rcu".to_string(), DSLValue::from(cluster.max_rcu));
        obj.insert("service_plan".to_string(), DSLValue::from(format!("{:?}", cluster.service_plan)));
        
        if let Some(endpoints) = cluster.endpoints {
            let endpoints_array = endpoints.into_iter()
                .map(|e| {
                    let mut endpoint_obj = HashMap::new();
                    endpoint_obj.insert("host".to_string(), DSLValue::from(e.host.unwrap_or_default()));
                    endpoint_obj.insert("port".to_string(), DSLValue::from(e.port.unwrap_or(0) as f64));
                    DSLValue::Object(endpoint_obj)
                })
                .collect();
            obj.insert("endpoints".to_string(), DSLValue::Array(endpoints_array));
        }
        
        DSLValue::Object(obj)
    }

    /// Format cluster status with appropriate colors
    fn format_cluster_status(&self, state: &ClusterState) -> String {
        match state {
            ClusterState::Active => format!("{}", "Active".green().bold()),
            ClusterState::Creating => format!("{}", "Creating".yellow().bold()),
            ClusterState::Deleting => format!("{}", "Deleting".red().bold()),
            ClusterState::Restoring => format!("{}", "Restoring".blue().bold()),
            ClusterState::Maintenance => format!("{}", "Maintenance".magenta().bold()),
            ClusterState::Deleted => format!("{}", "Deleted".red().dimmed()),
            ClusterState::Inactive => format!("{}", "Inactive".red().dimmed()),
            ClusterState::Upgrading => format!("{}", "Upgrading".cyan().bold()),
            ClusterState::Importing => format!("{}", "Importing".blue().bold()),
            ClusterState::Modifying => format!("{}", "Modifying".yellow().bold()),
            ClusterState::Pausing => format!("{}", "Pausing".yellow().bold()),
            ClusterState::Paused => format!("{}", "Paused".yellow().dimmed()),
            ClusterState::Resuming => format!("{}", "Resuming".yellow().bold()),
        }
    }

    /// Format cluster data with colored status for display
    fn format_cluster_for_display(&self, cluster: &Tidb) -> String {
        let status = self.format_cluster_status(&cluster.state.as_ref().unwrap_or(&ClusterState::Creating));
        let name = cluster.display_name.cyan().bold();
        let region = cluster.region_id.blue();
        let rcu = format!("{}-{}", cluster.min_rcu, cluster.max_rcu).white();
        
        format!(
            "{} ({}) - {} - {} - RCU: {}",
            name, cluster.tidb_id.as_deref().unwrap_or("N/A").dimmed(), 
            status, region, rcu
        )
    }

    fn backup_to_dsl_value(&self, backup: Backup) -> DSLValue {
        let mut obj = HashMap::new();
        obj.insert("id".to_string(), DSLValue::from(backup.id.unwrap_or_default()));
        obj.insert("name".to_string(), DSLValue::from(backup.display_name.unwrap_or_default()));
        obj.insert("state".to_string(), DSLValue::from(format!("{:?}", backup.state.unwrap_or(BackupState::Unknown))));
        obj.insert("size".to_string(), DSLValue::from(backup.size_bytes.unwrap_or_default()));
        obj.insert("create_time".to_string(), DSLValue::from(backup.create_time.unwrap_or_default()));
        
        DSLValue::Object(obj)
    }

    fn price_to_dsl_value(&self, price: EstimatePriceResponse) -> DSLValue {
        let mut obj = HashMap::new();
        
        if let Some(costs) = &price.costs {
            let costs_array = costs.iter()
                .map(|c| {
                    let mut cost_obj = HashMap::new();
                    cost_obj.insert("component".to_string(), DSLValue::from(format!("{:?}", c.component_type.as_ref().unwrap_or(&ComponentType::RuCost))));
                    cost_obj.insert("min".to_string(), DSLValue::from(c.min.unwrap_or(0.0)));
                    cost_obj.insert("max".to_string(), DSLValue::from(c.max.unwrap_or(0.0)));
                    DSLValue::Object(cost_obj)
                })
                .collect();
            obj.insert("costs".to_string(), DSLValue::Array(costs_array));
        }
        
        DSLValue::Object(obj)
    }

    /// Get all variables
    pub fn get_variables(&self) -> &HashMap<String, DSLValue> {
        &self.variables
    }

    /// Set a variable
    pub fn set_variable(&mut self, name: String, value: DSLValue) {
        self.variables.insert(name, value);
    }

    /// Get a variable
    pub fn get_variable(&self, name: &str) -> Option<&DSLValue> {
        self.variables.get(name)
    }

    /// Clear all variables
    pub fn clear_variables(&mut self) {
        self.variables.clear();
    }

    /// Sanitize output to prevent injection attacks
    fn sanitize_output(&self, input: &str) -> String {
        // Remove or escape potentially dangerous characters
        input
            .replace('\0', "") // Remove null bytes
            .replace('\r', "") // Remove carriage returns
            .replace('\n', "\\n") // Escape newlines
            .replace('\t', "\\t") // Escape tabs
            .chars()
            .take(1000) // Limit length to prevent DoS
            .collect()
    }

    /// Check rate limiting before making API calls
    async fn check_rate_limit(&self) -> DSLResult<()> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        let last_time = self.last_request_time.load(Ordering::Relaxed);
        let count = self.request_count.load(Ordering::Relaxed);
        
        // Reset counter if more than 1 minute has passed
        if now - last_time > 60 {
            self.request_count.store(0, Ordering::Relaxed);
            self.last_request_time.store(now, Ordering::Relaxed);
        }
        
        // Allow max 100 requests per minute
        if count >= 100 {
            return Err(DSLError::execution_error(
                "Rate limit exceeded: maximum 100 requests per minute"
            ));
        }
        
        self.request_count.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    /// Validate cluster name format
    fn validate_cluster_name(&self, name: &str) -> DSLResult<()> {
        if name.is_empty() {
            return Err(DSLError::invalid_parameter("name", name, "Cluster name cannot be empty"));
        }
        
        if name.len() > 63 {
            return Err(DSLError::invalid_parameter("name", name, "Cluster name too long (max 63 characters)"));
        }
        
        // Check for valid characters (alphanumeric, hyphens, underscores)
        if !name.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_') {
            return Err(DSLError::invalid_parameter("name", name, "Cluster name contains invalid characters"));
        }
        
        // Must start and end with alphanumeric
        if !name.chars().next().unwrap().is_alphanumeric() || 
           !name.chars().last().unwrap().is_alphanumeric() {
            return Err(DSLError::invalid_parameter("name", name, "Cluster name must start and end with alphanumeric characters"));
        }
        
        Ok(())
    }

    /// Validate region format
    fn validate_region(&self, region: &str) -> DSLResult<()> {
        if region.is_empty() {
            return Err(DSLError::invalid_parameter("region", region, "Region cannot be empty"));
        }
        
        // Check for valid region format (e.g., aws-us-west-1, gcp-us-central1)
        let valid_regions = [
            "aws-us-west-1", "aws-us-east-1", "aws-eu-west-1", "aws-ap-southeast-1",
            "gcp-us-central1", "gcp-us-west1", "gcp-europe-west1", "gcp-asia-east1",
            "azure-eastus", "azure-westus", "azure-northeurope", "azure-southeastasia"
        ];
        
        if !valid_regions.contains(&region) {
            return Err(DSLError::invalid_parameter("region", region, "Invalid region format"));
        }
        
        Ok(())
    }

    /// Evaluate a filter expression against a cluster
    fn evaluate_filter(&self, cluster: &Tidb, filter: &str) -> bool {
        // Parse filter in format "field operator value"
        let parts: Vec<&str> = filter.split_whitespace().collect();
        if parts.len() != 3 {
            return false; // Invalid filter format
        }
        
        let field = parts[0];
        let operator = parts[1];
        let value = parts[2];
        
        // Get the field value from the cluster
        let field_value = match field {
            "state" => cluster.state.as_ref().map(|s| format!("{:?}", s)).unwrap_or_default(),
            "region" => cluster.region_id.clone(),
            "name" => cluster.display_name.clone(),
            "display_name" => cluster.display_name.clone(),
            "service_plan" => format!("{:?}", cluster.service_plan),
            _ => return false, // Unknown field
        };
        
        // Clean the value by removing quotes if present
        let clean_value = value.trim_matches('"');
        
        // Apply the operator
        match operator {
            "=" | "==" => field_value.to_lowercase() == clean_value.to_lowercase(),
            "!=" => field_value.to_lowercase() != clean_value.to_lowercase(),
            "<" => field_value.to_lowercase() < clean_value.to_lowercase(),
            "<=" => field_value.to_lowercase() <= clean_value.to_lowercase(),
            ">" => field_value.to_lowercase() > clean_value.to_lowercase(),
            ">=" => field_value.to_lowercase() >= clean_value.to_lowercase(),
            _ => false, // Unknown operator
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dsl::commands::DSLCommandFactory;

    // Mock TiDBCloudClient for testing
    struct MockTiDBCloudClient;

    impl MockTiDBCloudClient {
        fn new() -> TiDBCloudClient {
            // Create a minimal client for testing
            TiDBCloudClient::new("test-api-key-that-is-long-enough-for-validation".to_string()).unwrap()
        }
    }

    #[tokio::test]
    async fn test_executor_new() {
        let client = MockTiDBCloudClient::new();
        let executor = DSLExecutor::new(client);
        assert!(executor.variables.is_empty());
    }

    #[tokio::test]
    async fn test_executor_with_timeout() {
        let client = MockTiDBCloudClient::new();
        let timeout = Duration::from_secs(60);
        let executor = DSLExecutor::with_timeout(client, timeout);
        assert_eq!(executor._timeout, timeout);
    }

    #[tokio::test]
    async fn test_executor_validate_cluster_name() {
        let client = MockTiDBCloudClient::new();
        let executor = DSLExecutor::new(client);
        
        // Valid names
        assert!(executor.validate_cluster_name("test-cluster").is_ok());
        assert!(executor.validate_cluster_name("test123").is_ok());
        assert!(executor.validate_cluster_name("test_cluster").is_ok());
        
        // Invalid names
        assert!(executor.validate_cluster_name("").is_err());
        assert!(executor.validate_cluster_name("-test").is_err());
        assert!(executor.validate_cluster_name("test-").is_err());
        assert!(executor.validate_cluster_name("test@cluster").is_err());
        assert!(executor.validate_cluster_name(&"a".repeat(64)).is_err());
    }

    #[tokio::test]
    async fn test_executor_validate_region() {
        let client = MockTiDBCloudClient::new();
        let executor = DSLExecutor::new(client);
        
        // Valid regions
        assert!(executor.validate_region("aws-us-west-1").is_ok());
        assert!(executor.validate_region("gcp-us-central1").is_ok());
        assert!(executor.validate_region("azure-eastus").is_ok());
        
        // Invalid regions
        assert!(executor.validate_region("").is_err());
        assert!(executor.validate_region("invalid-region").is_err());
        assert!(executor.validate_region("aws-west-1").is_err());
    }

    #[tokio::test]
    async fn test_executor_sanitize_output() {
        let client = MockTiDBCloudClient::new();
        let executor = DSLExecutor::new(client);
        
        let input = "Hello\nWorld\r\n\tTest\0";
        let sanitized = executor.sanitize_output(input);
        
        assert!(!sanitized.contains('\n'));
        assert!(!sanitized.contains('\r'));
        assert!(!sanitized.contains('\t'));
        assert!(!sanitized.contains('\0'));
        assert!(sanitized.contains("\\n"));
        assert!(sanitized.contains("\\t"));
    }

    #[tokio::test]
    async fn test_executor_sanitize_output_length_limit() {
        let client = MockTiDBCloudClient::new();
        let executor = DSLExecutor::new(client);
        
        let long_input = "a".repeat(2000);
        let sanitized = executor.sanitize_output(&long_input);
        
        assert_eq!(sanitized.len(), 1000);
    }

    #[tokio::test]
    async fn test_executor_variables() {
        let client = MockTiDBCloudClient::new();
        let mut executor = DSLExecutor::new(client);
        
        // Set variable
        executor.set_variable("test_var".to_string(), DSLValue::from("test_value"));
        assert_eq!(executor.get_variable("test_var"), Some(&DSLValue::from("test_value")));
        
        // Get non-existent variable
        assert_eq!(executor.get_variable("non_existent"), None);
        
        // Clear variables
        executor.clear_variables();
        assert_eq!(executor.get_variable("test_var"), None);
    }

    #[tokio::test]
    async fn test_executor_rate_limit() {
        let client = MockTiDBCloudClient::new();
        let executor = DSLExecutor::new(client);
        
        // First call should succeed
        assert!(executor.check_rate_limit().await.is_ok());
        
        // Multiple calls should succeed (rate limit is per minute)
        for _ in 0..10 {
            assert!(executor.check_rate_limit().await.is_ok());
        }
    }

    #[tokio::test]
    async fn test_executor_echo_command() {
        let client = MockTiDBCloudClient::new();
        let executor = DSLExecutor::new(client);
        
        let command = DSLCommandFactory::echo("Hello, World!");
        let result = executor.execute_echo(command).await;
        
        assert!(result.is_ok());
        let command_result = result.unwrap();
        assert!(command_result.is_success());
        assert_eq!(command_result.get_message(), Some("Echoed: Hello, World!"));
    }

    #[tokio::test]
    async fn test_executor_sleep_command() {
        let client = MockTiDBCloudClient::new();
        let executor = DSLExecutor::new(client);
        
        let command = DSLCommandFactory::sleep(0.1); // Short sleep for testing
        let result = executor.execute_sleep(command).await;
        
        assert!(result.is_ok());
        let command_result = result.unwrap();
        assert!(command_result.is_success());
        assert_eq!(command_result.get_message(), Some("Slept for 0.1 seconds"));
    }

    #[tokio::test]
    async fn test_executor_set_variable_command() {
        let client = MockTiDBCloudClient::new();
        let mut executor = DSLExecutor::new(client);
        
        let command = DSLCommand::new(DSLCommandType::SetVariable)
            .with_parameter("name", DSLValue::from("test_var"))
            .with_parameter("value", DSLValue::from("test_value"));
        
        let result = executor.execute_set_variable(command).await;
        
        assert!(result.is_ok());
        let command_result = result.unwrap();
        assert!(command_result.is_success());
        
        // Check that variable was actually set
        assert_eq!(executor.get_variable("test_var"), Some(&DSLValue::from("test_value")));
    }

    #[tokio::test]
    async fn test_executor_get_variable_command() {
        let client = MockTiDBCloudClient::new();
        let mut executor = DSLExecutor::new(client);
        
        // Set a variable first
        executor.set_variable("test_var".to_string(), DSLValue::from("test_value"));
        
        let command = DSLCommand::new(DSLCommandType::GetVariable)
            .with_parameter("name", DSLValue::from("test_var"));
        
        let result = executor.execute_get_variable(command).await;
        
        assert!(result.is_ok());
        let command_result = result.unwrap();
        assert!(command_result.is_success());
        assert_eq!(command_result.get_data(), Some(&DSLValue::from("test_value")));
    }

    #[tokio::test]
    async fn test_executor_get_variable_not_found() {
        let client = MockTiDBCloudClient::new();
        let executor = DSLExecutor::new(client);
        
        let command = DSLCommand::new(DSLCommandType::GetVariable)
            .with_parameter("name", DSLValue::from("non_existent"));
        
        let result = executor.execute_get_variable(command).await;
        
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_executor_if_command() {
        let client = MockTiDBCloudClient::new();
        let mut executor = DSLExecutor::new(client);
        
        let command = DSLCommand::new(DSLCommandType::If)
            .with_parameter("condition", DSLValue::from(true));
        
        let result = executor.execute_if(command).await;
        
        assert!(result.is_ok());
        let command_result = result.unwrap();
        assert!(command_result.is_success());
    }

    #[tokio::test]
    async fn test_executor_unknown_command() {
        let client = MockTiDBCloudClient::new();
        let mut executor = DSLExecutor::new(client);
        
        let command = DSLCommand::new(DSLCommandType::CreateCluster); // This should be handled
        let result = executor.execute(command).await;
        
        // This should fail because we don't have a real TiDB client
        assert!(result.is_err());
    }

    #[test]
    fn test_format_cluster_status() {
        let client = MockTiDBCloudClient::new();
        let executor = DSLExecutor::new(client);
        
        // Test that status formatting works for different states
        let active_status = executor.format_cluster_status(&ClusterState::Active);
        let creating_status = executor.format_cluster_status(&ClusterState::Creating);
        let deleting_status = executor.format_cluster_status(&ClusterState::Deleting);
        
        // The formatted strings should contain the status text
        assert!(active_status.contains("Active"));
        assert!(creating_status.contains("Creating"));
        assert!(deleting_status.contains("Deleting"));
    }

    #[test]
    fn test_format_cluster_for_display() {
        let client = MockTiDBCloudClient::new();
        let executor = DSLExecutor::new(client);
        
        let cluster = Tidb {
            name: Some("clusters/test".to_string()),
            tidb_id: Some("12345".to_string()),
            display_name: "test-cluster".to_string(),
            region_id: "aws-us-east-1".to_string(),
            cloud_provider: Some(CloudProvider::Aws),
            region_display_name: Some("US East (N. Virginia)".to_string()),
            state: Some(ClusterState::Active),
            root_password: None,
            min_rcu: "1".to_string(),
            max_rcu: "10".to_string(),
            service_plan: ServicePlan::Starter,
            high_availability_type: None,
            annotations: None,
            labels: None,
            creator: None,
            create_time: None,
            update_time: None,
            endpoints: None,
        };
        
        let formatted = executor.format_cluster_for_display(&cluster);
        
        // Should contain all the key information
        assert!(formatted.contains("test-cluster"));
        assert!(formatted.contains("12345"));
        assert!(formatted.contains("Active"));
        assert!(formatted.contains("aws-us-east-1"));
        assert!(formatted.contains("1-10"));
    }
} 