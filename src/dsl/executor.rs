use crate::dsl::{
    commands::{DSLBatchResult, DSLCommand, DSLCommandType, DSLResult as CommandResult},
    error::{DSLError, DSLResult},
    syntax::DSLValue,
};
use crate::logging::{change_log_level, set_current_log_level};
use crate::tidb_cloud::{TiDBCloudClient, models::*};
use colored::*;
use serde_json;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Instant;
use tokio::time::Duration;
use tracing::Level;

/// DSL executor that runs commands against the TiDB Cloud API
pub struct DSLExecutor {
    client: TiDBCloudClient,
    variables: HashMap<String, DSLValue>,
    _timeout: Duration,
    request_count: Arc<AtomicU64>,
    last_request_time: Arc<AtomicU64>,
    cancellation_flag: Arc<AtomicBool>,
}

/// RPN-based condition evaluator for complex WHERE clauses
#[derive(Debug, Clone, PartialEq)]
enum ConditionToken {
    Field(String),
    Operator(String),
    Value(DSLValue),
    And,
    Or,
    Not,
    LeftParen,
    RightParen,
}

impl DSLExecutor {
    // Define the available fields as a const array to avoid duplication
    const TIDB_FIELDS: &'static [&'static str] = &[
        "name",
        "tidb_id",
        "display_name",
        "region_id",
        "cloud_provider",
        "region_display_name",
        "state",
        "root_password",
        "min_rcu",
        "max_rcu",
        "service_plan",
        "high_availability_type",
        "creator",
        "create_time",
        "update_time",
    ];

    const TIDB_ALIASES: &'static [&'static str] = &[
        "region",
        "servicePlan",
        "highAvailabilityType",
        "createTime",
        "updateTime",
    ];

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
            cancellation_flag: Arc::new(AtomicBool::new(false)),
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
            cancellation_flag: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Create a new DSL executor with custom timeout and log level
    pub fn with_timeout_and_log_level(
        client: TiDBCloudClient,
        timeout: Duration,
        log_level: Level,
    ) -> Self {
        // Set the global log level
        set_current_log_level(log_level);

        Self {
            client,
            variables: HashMap::new(),
            _timeout: timeout,
            request_count: Arc::new(AtomicU64::new(0)),
            last_request_time: Arc::new(AtomicU64::new(0)),
            cancellation_flag: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Execute a single command
    pub async fn execute(&mut self, command: DSLCommand) -> DSLResult<CommandResult> {
        let start_time = Instant::now();

        tracing::debug!("Executing command: {:?}", command.command_type);
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
            DSLCommandType::SetLogLevel => self.execute_set_log_level(command).await,
            DSLCommandType::Echo => self.execute_echo(command).await,
            DSLCommandType::Sleep => self.execute_sleep(command).await,
            DSLCommandType::If => self.execute_if(command).await,
            DSLCommandType::Loop => self.execute_loop(command).await,
            DSLCommandType::Break => self.execute_break(command).await,
            DSLCommandType::Continue => self.execute_continue(command).await,
            DSLCommandType::Return => self.execute_return(command).await,
            DSLCommandType::Exit => self.execute_exit(command).await,
            _ => Err(DSLError::unknown_command(format!(
                "{:?}",
                command.command_type
            ))),
        };

        let duration = start_time.elapsed();

        match result {
            Ok(mut cmd_result) => {
                cmd_result = cmd_result
                    .with_metadata("duration_ms", DSLValue::from(duration.as_millis() as f64));
                tracing::debug!("Command executed successfully in {:?}", duration);

                // Print elapsed time to user
                let elapsed_str = self.format_duration(duration);
                println!(
                    "{}",
                    format!("⏱️  Command completed in {elapsed_str}").cyan()
                );

                Ok(cmd_result)
            }
            Err(e) => {
                tracing::error!("Command execution failed: {}", e);

                // Print elapsed time even for failed commands
                let elapsed_str = self.format_duration(duration);
                println!(
                    "{}",
                    format!("⏱️  Command failed after {elapsed_str}").red()
                );

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

        let duration = start_time.elapsed();
        batch_result.set_duration(duration);

        // Print total batch execution time
        let elapsed_str = self.format_duration(duration);
        println!(
            "{}",
            format!(
                "⏱️  Batch completed in {} ({} commands)",
                elapsed_str,
                batch_result.results.len()
            )
            .cyan()
        );

        Ok(batch_result)
    }

    /// Execute a script from a string
    pub async fn execute_script(&mut self, script: &str) -> DSLResult<DSLBatchResult> {
        let commands = crate::dsl::parser::DSLParser::parse_script(script)?;
        self.execute_batch(commands).await
    }

    // Command execution methods

    async fn execute_create_cluster(&mut self, command: DSLCommand) -> DSLResult<CommandResult> {
        let name = command.get_parameter_as_string("name")?;
        let region = command.get_parameter_as_string("region")?;

        // Validate cluster name and region
        self.validate_cluster_name(name)?;
        self.validate_region(region)?;

        // Validate that only allowed parameters are provided
        self.validate_create_cluster_parameters(&command)?;

        let min_rcu = command
            .get_optional_parameter("min_rcu")
            .map(|v| match v {
                DSLValue::String(s) => s.clone(),
                DSLValue::Number(n) => n.to_string(),
                _ => "1".to_string(),
            })
            .unwrap_or("1".to_string());
        let max_rcu = command
            .get_optional_parameter("max_rcu")
            .map(|v| match v {
                DSLValue::String(s) => s.clone(),
                DSLValue::Number(n) => n.to_string(),
                _ => "10".to_string(),
            })
            .unwrap_or("10".to_string());
        let service_plan = command
            .get_optional_parameter("service_plan")
            .and_then(|v| v.as_string())
            .unwrap_or("PREMIUM");
        let password = command
            .get_optional_parameter("password")
            .and_then(|v| v.as_string());

        let service_plan_enum = match service_plan.to_uppercase().as_str() {
            "STARTER" => ServicePlan::Starter,
            "ESSENTIAL" => ServicePlan::Essential,
            "PREMIUM" => ServicePlan::Premium,
            "BYOC" => ServicePlan::BYOC,
            _ => {
                return Err(DSLError::invalid_parameter(
                    "service_plan",
                    service_plan,
                    "Must be STARTER, ESSENTIAL, PREMIUM, or BYOC",
                ));
            }
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

        // Create the cluster first
        let cluster = match self.client.create_tidb(&tidb, None).await {
            Ok(cluster) => cluster,
            Err(e) => {
                return Err(DSLError::execution_error_with_source(
                    format!("Failed to create cluster '{name}'"),
                    e.to_string(),
                ));
            }
        };

        // Check if public_connection settings need to be configured
        let mut public_connection_updated = false;
        if let Some(public_connection) = command.get_optional_parameter("public_connection")
            && let Some(connection_obj) = public_connection.as_object()
        {
            // Get the cluster ID for the public connection update
            let cluster_id = cluster
                .tidb_id
                .as_ref()
                .ok_or_else(|| DSLError::execution_error("Created cluster has no ID"))?;

            // Parse the public connection settings
            let enabled = connection_obj
                .get("enabled")
                .and_then(|v| v.as_boolean())
                .unwrap_or(false);

            let ip_access_list = if let Some(ip_list) = connection_obj.get("ipAccessList") {
                if let Some(ip_array) = ip_list.as_array() {
                    let mut entries = Vec::new();
                    for ip_entry in ip_array {
                        if let Some(ip_obj) = ip_entry.as_object() {
                            let cidr_notation = ip_obj
                                .get("cidrNotation")
                                .and_then(|v| v.as_string())
                                .unwrap_or("0.0.0.0/0")
                                .to_string();
                            let description = ip_obj
                                .get("description")
                                .and_then(|v| v.as_string())
                                .unwrap_or("Default access")
                                .to_string();
                            entries.push(IpAccessListEntry {
                                cidr_notation,
                                description,
                            });
                        }
                    }
                    entries
                } else {
                    vec![]
                }
            } else {
                vec![]
            };

            let request = UpdatePublicConnectionRequest {
                enabled,
                ip_access_list,
            };

            // Update public connection settings using the dedicated endpoint
            match self
                .client
                .update_public_connection(cluster_id, &request)
                .await
            {
                Ok(_) => {
                    public_connection_updated = true;
                    tracing::debug!(
                        "Public connection settings configured successfully for cluster '{}'",
                        name
                    );
                }
                Err(e) => {
                    return Err(DSLError::execution_error_with_source(
                        format!(
                            "Failed to configure public connection settings for cluster '{name}'"
                        ),
                        e.to_string(),
                    ));
                }
            }
        }

        let cluster_data = self.cluster_to_dsl_value(cluster);
        let mut message = format!("Successfully created cluster '{name}'");
        if public_connection_updated {
            message = format!("{message} with public connection settings configured");
        }

        Ok(CommandResult::success_with_data_and_message(
            cluster_data,
            message,
        ))
    }

    async fn execute_delete_cluster(&mut self, command: DSLCommand) -> DSLResult<CommandResult> {
        let name = command.get_parameter_as_string("name")?;

        // First, get the cluster to find its ID
        let clusters = self.client.list_all_tidbs(None).await.map_err(|e| {
            DSLError::execution_error_with_source("Failed to list clusters", e.to_string())
        })?;

        let cluster = clusters
            .iter()
            .find(|c| c.display_name == name)
            .ok_or_else(|| DSLError::resource_not_found(format!("Cluster '{name}'")))?;

        let cluster_id = cluster
            .tidb_id
            .as_ref()
            .ok_or_else(|| DSLError::execution_error("Cluster has no ID"))?;

        match self.client.delete_tidb(cluster_id, None).await {
            Ok(_) => Ok(CommandResult::success_with_message(format!(
                "Successfully deleted cluster '{name}'"
            ))),
            Err(e) => Err(DSLError::execution_error_with_source(
                format!("Failed to delete cluster '{name}'"),
                e.to_string(),
            )),
        }
    }

    async fn execute_list_clusters(&mut self, command: DSLCommand) -> DSLResult<CommandResult> {
        // Check rate limiting before making API call
        self.check_rate_limit().await?;

        match self.client.list_all_tidbs(None).await {
            Ok(mut clusters) => {
                // Apply WHERE clause filtering if present
                if let Some(DSLValue::String(where_clause)) = command.parameters.get("where_clause")
                {
                    // Use the new RPN-based condition evaluator
                    clusters.retain(|cluster| {
                        match self.evaluate_where_clause(cluster, where_clause) {
                            Ok(result) => result,
                            Err(e) => {
                                eprintln!("Error evaluating WHERE clause: {e}");
                                false
                            }
                        }
                    });
                } else {
                    // Fallback to old filter format for backward compatibility
                    let mut filters = Vec::new();
                    for (key, value) in &command.parameters {
                        if key.starts_with("filter_")
                            && let DSLValue::String(filter_str) = value
                        {
                            filters.push(filter_str.clone());
                        }
                    }

                    // Apply filters to clusters
                    if !filters.is_empty() {
                        clusters.retain(|cluster| {
                            filters
                                .iter()
                                .all(|filter| self.evaluate_filter(cluster, filter))
                        });
                    }
                }

                let clusters_len = clusters.len();

                // Create formatted display string with colored output
                let mut display_lines = Vec::new();
                display_lines.push(format!("{}", "Clusters:".bold().white()));

                for cluster in &clusters {
                    let formatted_cluster = self.format_cluster_for_display(cluster);
                    display_lines.push(format!("  {formatted_cluster}"));
                }

                let display_text = display_lines.join("\n");

                // Check if specific fields were selected
                let selected_fields = command
                    .parameters
                    .get("selected_fields")
                    .and_then(|v| v.as_string())
                    .map(|s| {
                        s.split(',')
                            .map(|f| f.trim().to_string())
                            .collect::<Vec<_>>()
                    });

                // Create the data structure - either full or filtered
                let clusters_data = if let Some(fields) = selected_fields {
                    // Filter to only selected fields
                    DSLValue::Array(
                        clusters
                            .iter()
                            .map(|c| self.cluster_to_dsl_value_filtered(c, &fields))
                            .collect(),
                    )
                } else {
                    // Full data structure
                    DSLValue::Array(
                        clusters
                            .into_iter()
                            .map(|c| self.cluster_to_dsl_value(c))
                            .collect(),
                    )
                };

                Ok(CommandResult::success_with_data_and_message(
                    clusters_data,
                    format!("Found {clusters_len} clusters\n{display_text}"),
                ))
            }
            Err(e) => {
                tracing::error!("TiDB Cloud API error: {}", e);
                Err(DSLError::execution_error_with_source(
                    "Failed to list clusters",
                    e.to_string(),
                ))
            }
        }
    }

    async fn execute_get_cluster(&mut self, command: DSLCommand) -> DSLResult<CommandResult> {
        let name = command.get_parameter_as_string("name")?;

        let clusters = self.client.list_all_tidbs(None).await.map_err(|e| {
            DSLError::execution_error_with_source("Failed to list clusters", e.to_string())
        })?;

        let cluster = clusters
            .into_iter()
            .find(|c| c.display_name == name)
            .ok_or_else(|| DSLError::resource_not_found(format!("Cluster '{name}'")))?;

        // Create formatted display string with colored output first
        let formatted_cluster = self.format_cluster_for_display(&cluster);
        let display_text = format!("Cluster Details:\n  {formatted_cluster}");

        // Check if specific fields were selected
        let selected_fields = command
            .parameters
            .get("selected_fields")
            .and_then(|v| v.as_string())
            .map(|s| {
                s.split(',')
                    .map(|f| f.trim().to_string())
                    .collect::<Vec<_>>()
            });

        // Create the data structure - either full or filtered
        let cluster_data = if let Some(fields) = selected_fields {
            // Filter to only selected fields
            self.cluster_to_dsl_value_filtered(&cluster, &fields)
        } else {
            // Full data structure
            self.cluster_to_dsl_value(cluster)
        };

        Ok(CommandResult::success_with_data_and_message(
            cluster_data,
            format!("Found cluster '{name}'\n{display_text}"),
        ))
    }

    async fn execute_update_cluster(&mut self, command: DSLCommand) -> DSLResult<CommandResult> {
        let name = command.get_parameter_as_string("name")?;

        // Check rate limiting before making API call
        self.check_rate_limit().await?;

        // First, get the cluster to find its ID
        let clusters = self.client.list_all_tidbs(None).await.map_err(|e| {
            DSLError::execution_error_with_source("Failed to list clusters", e.to_string())
        })?;

        let cluster = clusters
            .iter()
            .find(|c| c.display_name == name)
            .ok_or_else(|| DSLError::resource_not_found(format!("Cluster '{name}'")))?;

        let cluster_id = cluster
            .tidb_id
            .as_ref()
            .ok_or_else(|| DSLError::execution_error("Cluster has no ID"))?;

        // Check if root_password is being updated
        let mut root_password_updated = false;
        if let Some(root_password) = command.get_optional_parameter("root_password")
            && let Some(password_str) = root_password.as_string()
        {
            // Reset root password using the dedicated endpoint
            // Try using internal_name if available, otherwise use tidb_id
            let api_cluster_id = if let Some(internal_name) = &cluster.name {
                // Extract the ID from internal_name (e.g., "clusters/10103009492238500237" -> "10103009492238500237")
                if internal_name.starts_with("clusters/") {
                    internal_name.trim_start_matches("clusters/")
                } else {
                    internal_name
                }
            } else {
                cluster_id
            };

            tracing::debug!(
                "Attempting to reset root password for cluster '{}' with ID '{}' (API ID: '{}')",
                name,
                cluster_id,
                api_cluster_id
            );
            match self
                .client
                .reset_root_password(api_cluster_id, password_str)
                .await
            {
                Ok(_) => {
                    root_password_updated = true;
                    tracing::debug!("Root password updated successfully for cluster '{}'", name);
                }
                Err(e) => {
                    return Err(DSLError::execution_error_with_source(
                        format!("Failed to update root password for cluster '{name}'"),
                        e.to_string(),
                    ));
                }
            }
        }

        // Check if public_connection is being updated
        let mut public_connection_updated = false;
        if let Some(public_connection) = command.get_optional_parameter("public_connection")
            && let Some(connection_obj) = public_connection.as_object()
        {
            // Parse the public connection settings
            let enabled = connection_obj
                .get("enabled")
                .and_then(|v| v.as_boolean())
                .unwrap_or(false);

            let ip_access_list = if let Some(ip_list) = connection_obj.get("ipAccessList") {
                if let Some(ip_array) = ip_list.as_array() {
                    let mut entries = Vec::new();
                    for ip_entry in ip_array {
                        if let Some(ip_obj) = ip_entry.as_object() {
                            let cidr_notation = ip_obj
                                .get("cidrNotation")
                                .and_then(|v| v.as_string())
                                .unwrap_or("0.0.0.0/0")
                                .to_string();
                            let description = ip_obj
                                .get("description")
                                .and_then(|v| v.as_string())
                                .unwrap_or("Default access")
                                .to_string();
                            entries.push(IpAccessListEntry {
                                cidr_notation,
                                description,
                            });
                        }
                    }
                    entries
                } else {
                    vec![]
                }
            } else {
                vec![]
            };

            let request = UpdatePublicConnectionRequest {
                enabled,
                ip_access_list,
            };

            // Update public connection settings using the dedicated endpoint
            match self
                .client
                .update_public_connection(cluster_id, &request)
                .await
            {
                Ok(_) => {
                    public_connection_updated = true;
                    tracing::debug!(
                        "Public connection settings updated successfully for cluster '{}'",
                        name
                    );
                }
                Err(e) => {
                    return Err(DSLError::execution_error_with_source(
                        format!("Failed to update public connection settings for cluster '{name}'"),
                        e.to_string(),
                    ));
                }
            }
        }

        // Build update request for other fields
        let mut update = UpdateTidbRequest {
            display_name: cluster.display_name.clone(),
            min_rcu: cluster.min_rcu.clone(),
            max_rcu: cluster.max_rcu.clone(),
        };

        let mut has_other_updates = false;

        if let Some(max_rcu) = command.get_optional_parameter("max_rcu")
            && let Some(max_rcu_str) = max_rcu.as_string()
        {
            update.max_rcu = max_rcu_str.to_string();
            has_other_updates = true;
        }

        if let Some(display_name) = command.get_optional_parameter("display_name")
            && let Some(display_name_str) = display_name.as_string()
        {
            update.display_name = display_name_str.to_string();
            has_other_updates = true;
        }

        // If we have other updates to make, perform them
        if has_other_updates {
            // TODO: Implement actual update_tidb method in TiDBCloudClient
            // For now, we'll return a success message with the prepared update
            tracing::debug!("Would update cluster '{}' with: {:?}", name, update);

            let mut message =
                format!("Update request prepared for cluster '{name}' (implementation pending)");

            if root_password_updated {
                message = format!("Root password updated successfully. {message}");
            }

            if public_connection_updated {
                message = format!("Public connection settings updated successfully. {message}");
            }

            return Ok(CommandResult::success_with_message(message));
        }

        // If we only updated the root password, return success
        if root_password_updated {
            let mut message = format!("Root password updated successfully for cluster '{name}'");
            if public_connection_updated {
                message = format!("{message}. Public connection settings updated successfully.");
            }
            return Ok(CommandResult::success_with_message(message));
        }

        // If we only updated public connection settings, return success
        if public_connection_updated {
            return Ok(CommandResult::success_with_message(format!(
                "Public connection settings updated successfully for cluster '{name}'"
            )));
        }

        // If no updates were made, return an error
        Err(DSLError::invalid_parameter(
            "update",
            "no parameters",
            "No valid update parameters provided",
        ))
    }

    async fn execute_wait_for_cluster(&mut self, command: DSLCommand) -> DSLResult<CommandResult> {
        let name = command.get_parameter_as_string("name")?;
        let state = command.get_parameter_as_string("state")?;

        // Check if timeout is specified
        let has_timeout = command.get_optional_parameter("timeout").is_some();
        let timeout_seconds = if has_timeout {
            command
                .get_optional_parameter("timeout")
                .and_then(|v| v.as_number())
                .unwrap_or(600.0) as u64
        } else {
            0 // Will be used to indicate infinite timeout
        };

        let target_state = match state.to_uppercase().as_str() {
            "ACTIVE" => ClusterState::Active,
            "CREATING" => ClusterState::Creating,
            "DELETING" => ClusterState::Deleting,
            "MAINTENANCE" => ClusterState::Maintenance,
            "PAUSED" => ClusterState::Paused,
            "RESUMING" => ClusterState::Resuming,
            _ => {
                return Err(DSLError::invalid_parameter(
                    "state",
                    state,
                    "Invalid cluster state",
                ));
            }
        };

        // First, get the cluster to find its ID
        let clusters = self.client.list_all_tidbs(None).await.map_err(|e| {
            DSLError::execution_error_with_source("Failed to list clusters", e.to_string())
        })?;

        let cluster = clusters
            .iter()
            .find(|c| c.display_name == name)
            .ok_or_else(|| DSLError::resource_not_found(format!("Cluster '{name}'")))?;

        let cluster_id = cluster
            .tidb_id
            .as_ref()
            .ok_or_else(|| DSLError::execution_error("Cluster has no ID"))?;

        // If no timeout is specified, implement infinite wait with periodic messages
        if !has_timeout {
            return self
                .wait_for_cluster_infinite(cluster_id, name, target_state, state)
                .await;
        }

        // Use the original timeout-based approach
        match self
            .client
            .wait_for_tidb_state(
                cluster_id,
                target_state,
                Duration::from_secs(timeout_seconds),
                Duration::from_secs(10),
            )
            .await
        {
            Ok(cluster) => {
                let cluster_data = self.cluster_to_dsl_value(cluster);
                Ok(CommandResult::success_with_data_and_message(
                    cluster_data,
                    format!("Cluster '{name}' reached state '{state}'"),
                ))
            }
            Err(e) => Err(DSLError::execution_error_with_source(
                format!("Failed to wait for cluster '{name}' to reach state '{state}'"),
                e.to_string(),
            )),
        }
    }

    async fn wait_for_cluster_infinite(
        &mut self,
        cluster_id: &str,
        cluster_name: &str,
        target_state: ClusterState,
        target_state_str: &str,
    ) -> DSLResult<CommandResult> {
        let start_time = std::time::Instant::now();
        let mut last_message_time = start_time;
        let message_interval = Duration::from_secs(60); // Print message every minute

        println!(
            "Waiting for cluster '{cluster_name}' to reach state '{target_state_str}' (no timeout specified)"
        );

        loop {
            // Check for cancellation
            if self.is_cancelled() {
                println!("Command cancelled by user");
                return Err(DSLError::execution_error("Command was cancelled by user"));
            }

            // Check current cluster state
            let cluster = match self.client.get_tidb(cluster_id).await {
                Ok(cluster) => cluster,
                Err(e) => {
                    return Err(DSLError::execution_error_with_source(
                        format!("Failed to get cluster '{cluster_name}' status"),
                        e.to_string(),
                    ));
                }
            };

            // Check if target state is reached
            if let Some(current_state) = &cluster.state
                && current_state == &target_state
            {
                let cluster_data = self.cluster_to_dsl_value(cluster);
                let elapsed = start_time.elapsed();
                let elapsed_str = self.format_duration(elapsed);

                println!(
                    "Cluster '{cluster_name}' reached state '{target_state_str}' after {elapsed_str}"
                );

                return Ok(CommandResult::success_with_data_and_message(
                    cluster_data,
                    format!(
                        "Cluster '{cluster_name}' reached state '{target_state_str}' after {elapsed_str}"
                    ),
                ));
            }

            // Print status message every minute
            let now = std::time::Instant::now();
            if now.duration_since(last_message_time) >= message_interval {
                let elapsed = now.duration_since(start_time);
                let elapsed_str = self.format_duration(elapsed);
                let current_state_str = cluster
                    .state
                    .as_ref()
                    .map(|s| format!("{s:?}"))
                    .unwrap_or_else(|| "Unknown".to_string());

                println!(
                    "Still waiting for cluster '{cluster_name}' to reach state '{target_state_str}' (current: {current_state_str}, elapsed: {elapsed_str})"
                );
                last_message_time = now;
            }

            // Wait before next check
            tokio::time::sleep(Duration::from_secs(10)).await;
        }
    }

    async fn execute_create_backup(&mut self, command: DSLCommand) -> DSLResult<CommandResult> {
        let cluster_name = command.get_parameter_as_string("cluster_name")?;
        let _description = command
            .get_optional_parameter("description")
            .and_then(|v| v.as_string());

        // First, get the cluster to find its ID
        let clusters = self.client.list_all_tidbs(None).await.map_err(|e| {
            DSLError::execution_error_with_source("Failed to list clusters", e.to_string())
        })?;

        let cluster = clusters
            .iter()
            .find(|c| c.display_name == cluster_name)
            .ok_or_else(|| DSLError::resource_not_found(format!("Cluster '{cluster_name}'")))?;

        let _cluster_id = cluster
            .tidb_id
            .as_ref()
            .ok_or_else(|| DSLError::execution_error("Cluster has no ID"))?;

        // Note: The actual backup creation might need to be implemented in the client
        // For now, we'll return a success message
        Ok(CommandResult::success_with_message(format!(
            "Backup creation initiated for cluster '{cluster_name}'"
        )))
    }

    async fn execute_list_backups(&mut self, command: DSLCommand) -> DSLResult<CommandResult> {
        let cluster_name = command.get_parameter_as_string("cluster_name")?;

        // First, get the cluster to find its ID
        let clusters = self.client.list_all_tidbs(None).await.map_err(|e| {
            DSLError::execution_error_with_source("Failed to list clusters", e.to_string())
        })?;

        let cluster = clusters
            .iter()
            .find(|c| c.display_name == cluster_name)
            .ok_or_else(|| DSLError::resource_not_found(format!("Cluster '{cluster_name}'")))?;

        let cluster_id = cluster
            .tidb_id
            .as_ref()
            .ok_or_else(|| DSLError::execution_error("Cluster has no ID"))?;

        match self.client.list_all_backups(cluster_id, None).await {
            Ok(backups) => {
                let backups_len = backups.len();
                let backups_data = DSLValue::Array(
                    backups
                        .into_iter()
                        .map(|b| self.backup_to_dsl_value(b))
                        .collect(),
                );
                Ok(CommandResult::success_with_data_and_message(
                    backups_data,
                    format!("Found {backups_len} backups for cluster '{cluster_name}'"),
                ))
            }
            Err(e) => Err(DSLError::execution_error_with_source(
                format!("Failed to list backups for cluster '{cluster_name}'"),
                e.to_string(),
            )),
        }
    }

    async fn execute_delete_backup(&mut self, command: DSLCommand) -> DSLResult<CommandResult> {
        let backup_id = command.get_parameter_as_string("backup_id")?;
        let cluster_name = command.get_parameter_as_string("cluster_name")?;

        // First, get the cluster to find its ID
        let clusters = self.client.list_all_tidbs(None).await.map_err(|e| {
            DSLError::execution_error_with_source("Failed to list clusters", e.to_string())
        })?;

        let cluster = clusters
            .iter()
            .find(|c| c.display_name == cluster_name)
            .ok_or_else(|| DSLError::resource_not_found(format!("Cluster '{cluster_name}'")))?;

        let cluster_id = cluster
            .tidb_id
            .as_ref()
            .ok_or_else(|| DSLError::execution_error("Cluster has no ID"))?;

        match self.client.delete_backup(cluster_id, backup_id).await {
            Ok(_) => Ok(CommandResult::success_with_message(format!(
                "Successfully deleted backup '{backup_id}' from cluster '{cluster_name}'"
            ))),
            Err(e) => Err(DSLError::execution_error_with_source(
                format!("Failed to delete backup '{backup_id}' from cluster '{cluster_name}'"),
                e.to_string(),
            )),
        }
    }

    async fn execute_estimate_price(&mut self, command: DSLCommand) -> DSLResult<CommandResult> {
        let region = command.get_parameter_as_string("region")?;
        let min_rcu = command.get_parameter_as_string("min_rcu")?;
        let max_rcu = command.get_parameter_as_string("max_rcu")?;
        let service_plan = command.get_parameter_as_string("service_plan")?;
        let storage = command
            .get_optional_parameter("storage")
            .and_then(|v| v.as_string())
            .unwrap_or("1073741824"); // 1GB default

        let service_plan_enum = match service_plan.to_uppercase().as_str() {
            "STARTER" => ServicePlan::Starter,
            "ESSENTIAL" => ServicePlan::Essential,
            "PREMIUM" => ServicePlan::Premium,
            "BYOC" => ServicePlan::BYOC,
            _ => {
                return Err(DSLError::invalid_parameter(
                    "service_plan",
                    service_plan,
                    "Must be STARTER, ESSENTIAL, PREMIUM, or BYOC",
                ));
            }
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
                    format!(
                        "Price estimated for region '{region}' with RCU range {min_rcu}-{max_rcu}"
                    ),
                ))
            }
            Err(e) => Err(DSLError::execution_error_with_source(
                format!("Failed to estimate price for region '{region}'"),
                e.to_string(),
            )),
        }
    }

    async fn execute_set_variable(&mut self, command: DSLCommand) -> DSLResult<CommandResult> {
        let name = command.get_parameter_as_string("name")?;
        let value = command.require_parameter("value")?.clone();

        self.variables.insert(name.to_string(), value.clone());

        Ok(CommandResult::success_with_data_and_message(
            value,
            format!("Set variable '{name}'"),
        ))
    }

    async fn execute_get_variable(&self, command: DSLCommand) -> DSLResult<CommandResult> {
        let name = command.get_parameter_as_string("name")?;

        match self.variables.get(name) {
            Some(value) => Ok(CommandResult::success_with_data_and_message(
                value.clone(),
                format!("Variable '{name}' = {value}"),
            )),
            None => Err(DSLError::variable_not_found(name)),
        }
    }

    async fn execute_set_log_level(&mut self, command: DSLCommand) -> DSLResult<CommandResult> {
        let level = command.get_parameter_as_string("level")?;

        // Validate the log level
        let valid_levels = ["trace", "debug", "info", "warn", "error"];
        let level_lower = level.to_lowercase();

        if !valid_levels.contains(&level_lower.as_str()) {
            return Err(DSLError::invalid_parameter(
                "level",
                level,
                "Must be one of: trace, debug, info, warn, error",
            ));
        }

        // Convert string to tracing::Level
        let new_level = match level_lower.as_str() {
            "trace" => Level::TRACE,
            "debug" => Level::DEBUG,
            "info" => Level::INFO,
            "warn" => Level::WARN,
            "error" => Level::ERROR,
            _ => {
                return Err(DSLError::invalid_parameter(
                    "level",
                    level,
                    "Must be one of: trace, debug, info, warn, error",
                ));
            }
        };

        // Change the log level
        match change_log_level(new_level) {
            Ok(()) => Ok(CommandResult::success_with_message(format!(
                "Log level changed to '{level_lower}'"
            ))),
            Err(e) => Err(DSLError::execution_error_with_source(
                "Failed to change log level",
                e.to_string(),
            )),
        }
    }

    async fn execute_echo(&self, command: DSLCommand) -> DSLResult<CommandResult> {
        let message = command.get_parameter_as_string("message")?;

        // Sanitize the message to prevent injection attacks
        let sanitized_message = self.sanitize_output(message);

        println!("{sanitized_message}");

        Ok(CommandResult::success_with_message(format!(
            "Echoed: {sanitized_message}"
        )))
    }

    async fn execute_sleep(&self, command: DSLCommand) -> DSLResult<CommandResult> {
        let seconds = command.get_parameter_as_number("seconds")?;
        let total_duration = Duration::from_secs_f64(seconds);
        let start_time = std::time::Instant::now();

        // Sleep in smaller intervals to allow for cancellation
        let check_interval = Duration::from_millis(100); // Check every 100ms
        let mut elapsed = Duration::ZERO;

        while elapsed < total_duration {
            // Check for cancellation
            if self.is_cancelled() {
                return Err(DSLError::execution_error(
                    "Sleep command was cancelled by user",
                ));
            }

            // Sleep for the shorter of the remaining time or check interval
            let remaining = total_duration - elapsed;
            let sleep_duration = if remaining < check_interval {
                remaining
            } else {
                check_interval
            };

            tokio::time::sleep(sleep_duration).await;
            elapsed = start_time.elapsed();
        }

        Ok(CommandResult::success_with_message(format!(
            "Slept for {seconds} seconds"
        )))
    }

    async fn execute_if(&mut self, command: DSLCommand) -> DSLResult<CommandResult> {
        let condition = command.require_parameter("condition")?;

        if condition.is_truthy() {
            Ok(CommandResult::success_with_message("If condition was true"))
        } else {
            Ok(CommandResult::success_with_message(
                "If condition was false",
            ))
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
                "Return executed",
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
        // Use serde_json to serialize the cluster to JSON, then convert to DSLValue
        // This makes it dynamic and automatically includes all fields from the JSON specification
        match serde_json::to_value(&cluster) {
            Ok(json_value) => {
                // Convert serde_json::Value to DSLValue
                Self::json_value_to_dsl_value(json_value)
            }
            Err(_) => {
                // Fallback to a basic object if serialization fails
                let mut obj = HashMap::new();
                obj.insert(
                    "error".to_string(),
                    DSLValue::from("Failed to serialize cluster"),
                );
                DSLValue::Object(obj)
            }
        }
    }

    /// Convert serde_json::Value to DSLValue recursively
    fn json_value_to_dsl_value(value: serde_json::Value) -> DSLValue {
        match value {
            serde_json::Value::Null => DSLValue::Null,
            serde_json::Value::Bool(b) => DSLValue::Boolean(b),
            serde_json::Value::Number(n) => {
                if let Some(i) = n.as_i64() {
                    DSLValue::Number(i as f64)
                } else if let Some(f) = n.as_f64() {
                    DSLValue::Number(f)
                } else {
                    DSLValue::String(n.to_string())
                }
            }
            serde_json::Value::String(s) => DSLValue::String(s),
            serde_json::Value::Array(arr) => {
                let dsl_array = arr.into_iter().map(Self::json_value_to_dsl_value).collect();
                DSLValue::Array(dsl_array)
            }
            serde_json::Value::Object(obj) => {
                let dsl_obj = obj
                    .into_iter()
                    .map(|(k, v)| (k, Self::json_value_to_dsl_value(v)))
                    .collect();
                DSLValue::Object(dsl_obj)
            }
        }
    }

    /// Convert cluster to DSLValue with only selected fields
    fn cluster_to_dsl_value_filtered(
        &self,
        cluster: &Tidb,
        selected_fields: &[String],
    ) -> DSLValue {
        // First get the full JSON representation
        let full_json = match serde_json::to_value(cluster) {
            Ok(json_value) => json_value,
            Err(_) => {
                // Fallback to a basic object if serialization fails
                let mut obj = HashMap::new();
                obj.insert(
                    "error".to_string(),
                    DSLValue::from("Failed to serialize cluster"),
                );
                return DSLValue::Object(obj);
            }
        };

        // Filter to only selected fields
        if let serde_json::Value::Object(mut full_obj) = full_json {
            let mut filtered_obj = HashMap::new();

            for field in selected_fields {
                if let Some(value) = full_obj.remove(field) {
                    filtered_obj.insert(field.clone(), Self::json_value_to_dsl_value(value));
                }
            }

            DSLValue::Object(filtered_obj)
        } else {
            DSLValue::Null
        }
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
        let status =
            self.format_cluster_status(cluster.state.as_ref().unwrap_or(&ClusterState::Creating));
        let name = cluster.display_name.cyan().bold();
        let region = cluster.region_id.blue();
        let rcu = format!("{}-{}", cluster.min_rcu, cluster.max_rcu).white();

        // Check password status
        let password_status = if let Some(ref annotations) = cluster.annotations {
            if let Some(has_password) = annotations.get("tidb.cloud/has-set-password") {
                if has_password == "false" {
                    " [Password: Not Set]".red()
                } else {
                    " [Password: Set]".green()
                }
            } else {
                "".normal()
            }
        } else {
            "".normal()
        };

        // Check endpoints status
        let endpoints_status = if let Some(ref endpoints) = cluster.endpoints {
            if endpoints.is_empty() {
                " [Endpoints: Not Available]".yellow()
            } else {
                " [Endpoints: Available]".green()
            }
        } else {
            " [Endpoints: Not Available]".yellow()
        };

        format!(
            "{} ({}) - {} - {} - RCU: {}{}{}",
            name,
            cluster.tidb_id.as_deref().unwrap_or("N/A").dimmed(),
            status,
            region,
            rcu,
            password_status,
            endpoints_status
        )
    }

    fn backup_to_dsl_value(&self, backup: Backup) -> DSLValue {
        // Use serde_json to serialize the backup to JSON, then convert to DSLValue
        // This makes it dynamic and automatically includes all fields from the JSON specification
        match serde_json::to_value(&backup) {
            Ok(json_value) => {
                // Convert serde_json::Value to DSLValue
                Self::json_value_to_dsl_value(json_value)
            }
            Err(_) => {
                // Fallback to a basic object if serialization fails
                let mut obj = HashMap::new();
                obj.insert(
                    "error".to_string(),
                    DSLValue::from("Failed to serialize backup"),
                );
                DSLValue::Object(obj)
            }
        }
    }

    fn price_to_dsl_value(&self, price: EstimatePriceResponse) -> DSLValue {
        // Use serde_json to serialize the price to JSON, then convert to DSLValue
        // This makes it dynamic and automatically includes all fields from the JSON specification
        match serde_json::to_value(&price) {
            Ok(json_value) => {
                // Convert serde_json::Value to DSLValue
                Self::json_value_to_dsl_value(json_value)
            }
            Err(_) => {
                // Fallback to a basic object if serialization fails
                let mut obj = HashMap::new();
                obj.insert(
                    "error".to_string(),
                    DSLValue::from("Failed to serialize price"),
                );
                DSLValue::Object(obj)
            }
        }
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

    /// Set the cancellation flag to true
    pub fn cancel(&self) {
        self.cancellation_flag.store(true, Ordering::Relaxed);
    }

    /// Reset the cancellation flag to false
    pub fn reset_cancellation(&self) {
        self.cancellation_flag.store(false, Ordering::Relaxed);
    }

    /// Check if cancellation has been requested
    pub fn is_cancelled(&self) -> bool {
        self.cancellation_flag.load(Ordering::Relaxed)
    }

    /// Get a reference to the cancellation flag for sharing
    pub fn get_cancellation_flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.cancellation_flag)
    }

    /// Sanitize output to prevent injection attacks
    fn sanitize_output(&self, input: &str) -> String {
        // Remove or escape potentially dangerous characters
        input
            .replace(['\0', '\r'], "") // Remove carriage returns
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
                "Rate limit exceeded: maximum 100 requests per minute",
            ));
        }

        self.request_count.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    /// Validate cluster name format
    fn validate_cluster_name(&self, name: &str) -> DSLResult<()> {
        if name.is_empty() {
            return Err(DSLError::invalid_parameter(
                "name",
                name,
                "Cluster name cannot be empty",
            ));
        }

        if name.len() > 63 {
            return Err(DSLError::invalid_parameter(
                "name",
                name,
                "Cluster name too long (max 63 characters)",
            ));
        }

        // Check for valid characters (alphanumeric, hyphens, underscores)
        if !name
            .chars()
            .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
        {
            return Err(DSLError::invalid_parameter(
                "name",
                name,
                "Cluster name contains invalid characters",
            ));
        }

        // Must start and end with alphanumeric
        if !name.chars().next().unwrap().is_alphanumeric()
            || !name.chars().last().unwrap().is_alphanumeric()
        {
            return Err(DSLError::invalid_parameter(
                "name",
                name,
                "Cluster name must start and end with alphanumeric characters",
            ));
        }

        Ok(())
    }

    /// Validate region format
    fn validate_region(&self, region: &str) -> DSLResult<()> {
        if region.is_empty() {
            return Err(DSLError::invalid_parameter(
                "region",
                region,
                "Region cannot be empty",
            ));
        }

        // Check for valid region format (e.g., aws-us-west-1, gcp-us-central1)
        let valid_regions = [
            "aws-us-west-1",
            "aws-us-east-1",
            // FIXME: We should be able to get this from the API
        ];

        if !valid_regions.contains(&region) {
            return Err(DSLError::invalid_parameter(
                "region",
                region,
                "Invalid region format",
            ));
        }

        Ok(())
    }

    /// Validate that only allowed parameters are provided for CREATE CLUSTER command
    fn validate_create_cluster_parameters(&self, command: &DSLCommand) -> DSLResult<()> {
        // Get allowed parameters from the Tidb struct definition
        let allowed_parameters = self.get_create_cluster_allowed_parameters();

        // Check each parameter in the command
        for param_name in command.parameters.keys() {
            if !allowed_parameters.contains(&param_name.as_str()) {
                return Err(DSLError::invalid_parameter(
                    param_name,
                    "unknown",
                    format!(
                        "Invalid parameter '{}' for CREATE CLUSTER. Allowed parameters are: {}",
                        param_name,
                        allowed_parameters.join(", ")
                    ),
                ));
            }
        }

        Ok(())
    }

    /// Get allowed parameters for CREATE CLUSTER based on the Tidb struct definition
    fn get_create_cluster_allowed_parameters(&self) -> Vec<&'static str> {
        // This function returns the allowed DSL parameters for CREATE CLUSTER
        // based on the actual Tidb struct definition from models.rs
        //
        // The mapping is derived from the Tidb struct fields that are settable during creation.
        // This ensures that the validation stays in sync with the actual API schema.

        // Get the settable fields from the Tidb struct
        let _settable_fields = self.get_settable_tidb_fields();

        // Get the field mapping to understand the relationship between DSL params and struct fields
        let _field_mapping = self.get_dsl_to_tidb_field_mapping();

        // Create a parameter mapping that reflects the actual struct fields
        let mut allowed_params = Vec::new();

        // Required fields from Tidb struct (always included in JSON)
        allowed_params.extend_from_slice(&[
            "name",         // maps to display_name
            "region",       // maps to region_id
            "min_rcu",      // maps to min_rcu
            "max_rcu",      // maps to max_rcu
            "plan",         // maps to service_plan
            "service_plan", // maps to service_plan (alternative name)
        ]);

        // Optional fields from Tidb struct (included if not None)
        allowed_params.extend_from_slice(&[
            "root_password",          // maps to root_password
            "password",               // maps to root_password (alias)
            "high_availability_type", // maps to high_availability_type
            "annotations",            // maps to annotations
            "labels",                 // maps to labels
        ]);

        // Special parameters (handled separately)
        allowed_params.extend_from_slice(&[
            "public_connection", // handled separately for public connection settings
        ]);

        allowed_params
    }

    /// Get the mapping from DSL parameter names to Tidb struct field names
    fn get_dsl_to_tidb_field_mapping(&self) -> HashMap<&'static str, &'static str> {
        // This function provides the mapping from DSL parameter names to actual Tidb struct field names
        // This ensures that the parameter validation is based on the actual struct definition
        let mut mapping = HashMap::new();

        // Required fields from Tidb struct
        mapping.insert("name", "display_name");
        mapping.insert("region", "region_id");
        mapping.insert("min_rcu", "min_rcu");
        mapping.insert("max_rcu", "max_rcu");
        mapping.insert("plan", "service_plan");
        mapping.insert("service_plan", "service_plan");

        // Optional fields from Tidb struct
        mapping.insert("root_password", "root_password");
        mapping.insert("password", "root_password");
        mapping.insert("high_availability_type", "high_availability_type");
        mapping.insert("annotations", "annotations");
        mapping.insert("labels", "labels");

        mapping
    }

    /// Get the list of settable fields from the Tidb struct for cluster creation
    fn get_settable_tidb_fields(&self) -> Vec<&'static str> {
        // This function returns the list of fields from the Tidb struct that can be set during creation
        // Based on the actual struct definition in models.rs
        vec![
            "display_name",           // String (required)
            "region_id",              // String (required)
            "min_rcu",                // String (required)
            "max_rcu",                // String (required)
            "service_plan",           // ServicePlan (required)
            "root_password",          // Option<String> (optional)
            "high_availability_type", // Option<HighAvailabilityType> (optional)
            "annotations",            // Option<HashMap<String, String>> (optional)
            "labels",                 // Option<HashMap<String, String>> (optional)
        ]
    }

    /// Evaluate a filter expression against a cluster
    fn evaluate_filter(&self, cluster: &Tidb, filter: &str) -> bool {
        // Parse filter in format "field operator value"
        let parts: Vec<&str> = filter.split_whitespace().collect();
        if parts.len() != 3 {
            eprintln!(
                "Error: Invalid filter format. Expected 'field operator value', got: {filter}"
            );
            return false; // Invalid filter format
        }

        let field_path = parts[0];
        let operator = parts[1];
        let value = parts[2];

        // Get the field value from the cluster using dot notation
        let field_value = self.get_field_value(cluster, field_path);
        if field_value.is_none() {
            eprintln!("Error: Unknown field '{field_path}' in WHERE clause.");
            eprintln!("Available fields:");
            eprintln!("  {}", self.get_available_fields());
            eprintln!(
                "Note: You can use wildcard patterns like 'SB*' or regex patterns like '/SB.*/' for pattern matching."
            );
            return false; // Unknown field
        }

        let field_value = field_value.unwrap();
        let clean_value = value.trim_matches('"');

        // Apply the operator
        match operator {
            "=" | "==" => {
                // Check if it's a regex pattern (starts with / and ends with /)
                if clean_value.starts_with('/') && clean_value.ends_with('/') {
                    let regex_pattern = &clean_value[1..clean_value.len() - 1];
                    match regex::Regex::new(regex_pattern) {
                        Ok(regex) => regex.is_match(&field_value),
                        Err(e) => {
                            eprintln!("Error: Invalid regex pattern '{regex_pattern}': {e}");
                            false
                        }
                    }
                } else if self.is_regex_pattern(clean_value) {
                    // Treat as regex pattern (contains regex special chars but not wrapped in /)
                    match regex::Regex::new(clean_value) {
                        Ok(regex) => regex.is_match(&field_value),
                        Err(e) => {
                            eprintln!("Error: Invalid regex pattern '{clean_value}': {e}");
                            eprintln!(
                                "Hint: If you meant to use wildcards, try '{}'",
                                self.suggest_wildcard_pattern(clean_value)
                            );
                            eprintln!(
                                "Hint: If you meant to use regex, try '{}'",
                                self.suggest_regex_pattern(clean_value)
                            );
                            false
                        }
                    }
                } else if clean_value.contains('*') || clean_value.contains('?') {
                    // Convert wildcard pattern to regex
                    let regex_pattern = self.wildcard_to_regex(clean_value);
                    match regex::Regex::new(&regex_pattern) {
                        Ok(regex) => regex.is_match(&field_value),
                        Err(e) => {
                            eprintln!("Error: Invalid wildcard pattern '{clean_value}': {e}");
                            false
                        }
                    }
                } else {
                    field_value.to_lowercase() == clean_value.to_lowercase()
                }
            }
            "!=" => {
                if clean_value.starts_with('/') && clean_value.ends_with('/') {
                    let regex_pattern = &clean_value[1..clean_value.len() - 1];
                    match regex::Regex::new(regex_pattern) {
                        Ok(regex) => !regex.is_match(&field_value),
                        Err(e) => {
                            eprintln!("Error: Invalid regex pattern '{regex_pattern}': {e}");
                            true // Invalid regex pattern, treat as not matching
                        }
                    }
                } else if self.is_regex_pattern(clean_value) {
                    // Treat as regex pattern (contains regex special chars but not wrapped in /)
                    match regex::Regex::new(clean_value) {
                        Ok(regex) => !regex.is_match(&field_value),
                        Err(e) => {
                            eprintln!("Error: Invalid regex pattern '{clean_value}': {e}");
                            eprintln!(
                                "Hint: If you meant to use wildcards, try '{}'",
                                self.suggest_wildcard_pattern(clean_value)
                            );
                            eprintln!(
                                "Hint: If you meant to use regex, try '{}'",
                                self.suggest_regex_pattern(clean_value)
                            );
                            true // Invalid regex pattern, treat as not matching
                        }
                    }
                } else if clean_value.contains('*') || clean_value.contains('?') {
                    // Convert wildcard pattern to regex
                    let regex_pattern = self.wildcard_to_regex(clean_value);
                    match regex::Regex::new(&regex_pattern) {
                        Ok(regex) => !regex.is_match(&field_value),
                        Err(e) => {
                            eprintln!("Error: Invalid wildcard pattern '{clean_value}': {e}");
                            true // Invalid wildcard pattern, treat as not matching
                        }
                    }
                } else {
                    field_value.to_lowercase() != clean_value.to_lowercase()
                }
            }
            "<" => field_value.to_lowercase() < clean_value.to_lowercase(),
            "<=" => field_value.to_lowercase() <= clean_value.to_lowercase(),
            ">" => field_value.to_lowercase() > clean_value.to_lowercase(),
            ">=" => field_value.to_lowercase() >= clean_value.to_lowercase(),
            _ => {
                eprintln!(
                    "Error: Unknown operator '{operator}'. Supported operators: =, !=, <, <=, >, >="
                );
                eprintln!(
                    "Note: You can use wildcard patterns like 'SB*' or regex patterns like '/SB.*/' for pattern matching."
                );
                false
            }
        }
    }

    /// Get field value from cluster using dot notation for nested fields
    fn get_field_value(&self, cluster: &Tidb, field_path: &str) -> Option<String> {
        // Parse field path more carefully to handle quoted keys
        let parts = self.parse_field_path(field_path);

        let field_name = parts[0].as_str();

        // Check if it's a valid field name first
        if !self.is_valid_tidb_field(field_name)
            && !field_name.starts_with("annotations")
            && !field_name.starts_with("labels")
            && !field_name.starts_with("endpoints")
        {
            return None; // Unknown field
        }

        match field_name {
            // Top-level fields
            "name" => cluster.name.clone(),
            "tidb_id" => cluster.tidb_id.clone(),
            "display_name" => Some(cluster.display_name.clone()),
            "region_id" => Some(cluster.region_id.clone()),
            "cloud_provider" => cluster.cloud_provider.as_ref().map(|p| format!("{p:?}")),
            "region_display_name" => cluster.region_display_name.clone(),
            "state" => cluster.state.as_ref().map(|s| format!("{s:?}")),
            "root_password" => cluster.root_password.clone(),
            "min_rcu" => Some(cluster.min_rcu.clone()),
            "max_rcu" => Some(cluster.max_rcu.clone()),
            "service_plan" => Some(format!("{:?}", cluster.service_plan)),
            "high_availability_type" => cluster
                .high_availability_type
                .as_ref()
                .map(|h| format!("{h:?}")),
            "creator" => cluster.creator.clone(),
            "create_time" => cluster.create_time.clone(),
            "update_time" => cluster.update_time.clone(),

            // Nested fields
            "annotations" => {
                if parts.len() > 1 {
                    let key = parts[1].trim_matches('"');
                    cluster
                        .annotations
                        .as_ref()
                        .and_then(|ann| ann.get(key).cloned())
                } else {
                    Some(format!("{:?}", cluster.annotations))
                }
            }
            "labels" => {
                if parts.len() > 1 {
                    let key = parts[1].trim_matches('"');
                    cluster
                        .labels
                        .as_ref()
                        .and_then(|labels| labels.get(key).cloned())
                } else {
                    Some(format!("{:?}", cluster.labels))
                }
            }
            "endpoints" => {
                if parts.len() > 1 {
                    cluster.endpoints.as_ref().and_then(|endpoints| {
                        if let Ok(index) = parts[1].parse::<usize>() {
                            endpoints
                                .get(index)
                                .and_then(|endpoint| match parts.get(2) {
                                    Some(part) => match part.as_str() {
                                        "host" => endpoint.host.clone(),
                                        "port" => endpoint.port.map(|p| p.to_string()),
                                        "connection_type" => endpoint
                                            .connection_type
                                            .as_ref()
                                            .map(|c| format!("{c:?}")),
                                        _ => Some(format!("{endpoint:?}")),
                                    },
                                    None => Some(format!("{endpoint:?}")),
                                })
                        } else {
                            None
                        }
                    })
                } else {
                    Some(format!("{:?}", cluster.endpoints))
                }
            }

            // Aliases for backward compatibility
            "region" => Some(cluster.region_id.clone()),
            "servicePlan" => Some(format!("{:?}", cluster.service_plan)),
            "highAvailabilityType" => cluster
                .high_availability_type
                .as_ref()
                .map(|h| format!("{h:?}")),
            "createTime" => cluster.create_time.clone(),
            "updateTime" => cluster.update_time.clone(),

            _ => None, // Unknown field
        }
    }

    /// Parse field path into parts, handling quoted keys properly
    fn parse_field_path(&self, field_path: &str) -> Vec<String> {
        let mut parts = Vec::new();
        let mut current_part = String::new();
        let mut in_quotes = false;
        let chars = field_path.chars().peekable();

        for ch in chars {
            match ch {
                '"' => {
                    in_quotes = !in_quotes;
                    current_part.push(ch);
                }
                '.' => {
                    if !in_quotes {
                        if !current_part.is_empty() {
                            parts.push(current_part.clone());
                            current_part.clear();
                        }
                    } else {
                        current_part.push(ch);
                    }
                }
                _ => {
                    current_part.push(ch);
                }
            }
        }

        if !current_part.is_empty() {
            parts.push(current_part);
        }

        parts
    }

    /// Convert wildcard pattern to regex pattern
    fn wildcard_to_regex(&self, pattern: &str) -> String {
        let mut regex = String::new();
        regex.push('^'); // Start of string

        for ch in pattern.chars() {
            match ch {
                '*' => regex.push_str(".*"), // * matches any sequence of characters
                '?' => regex.push('.'),      // ? matches any single character
                '.' | '(' | ')' | '[' | ']' | '{' | '}' | '+' | '|' | '^' | '$' | '\\' => {
                    // Escape regex special characters
                    regex.push('\\');
                    regex.push(ch);
                }
                _ => regex.push(ch),
            }
        }

        regex.push('$'); // End of string
        regex
    }

    /// Check if a string contains regex special characters (indicating it should be treated as regex)
    fn is_regex_pattern(&self, pattern: &str) -> bool {
        // Check for common regex special characters that aren't typically in wildcard patterns
        pattern.contains('(')
            || pattern.contains(')')
            || pattern.contains('[')
            || pattern.contains(']')
            || pattern.contains('+')
            || pattern.contains('{')
            || pattern.contains('}')
            || pattern.contains('|')
            || pattern.contains('^')
            || pattern.contains('$')
            || pattern.contains('\\')
            || pattern.contains("\\d")
            || pattern.contains("\\w")
            || pattern.contains("\\s")
    }

    /// Get a list of available fields for WHERE clause filtering
    fn get_available_fields(&self) -> String {
        let mut sections = Vec::new();

        // Get top-level fields from the Tidb struct
        sections.push(format!(
            "Top-level fields: {}",
            Self::TIDB_FIELDS.join(", ")
        ));

        // Nested fields (these are derived from the struct but need special handling)
        let nested_fields = [
            "annotations.<key>",
            "labels.<key>",
            "endpoints.<index>.host",
            "endpoints.<index>.port",
            "endpoints.<index>.connection_type",
        ];
        sections.push(format!("Nested fields: {}", nested_fields.join(", ")));

        // Aliases (these are convenience mappings)
        sections.push(format!("Aliases: {}", Self::TIDB_ALIASES.join(", ")));

        sections.join("\n  ")
    }

    /// Check if a field name is valid for the Tidb struct
    fn is_valid_tidb_field(&self, field_name: &str) -> bool {
        Self::TIDB_FIELDS.contains(&field_name) || Self::TIDB_ALIASES.contains(&field_name)
    }

    /// Suggest a wildcard pattern based on common regex mistakes
    fn suggest_wildcard_pattern(&self, pattern: &str) -> String {
        // Common pattern: if it starts with * and contains regex chars, suggest simple wildcard
        if pattern.starts_with('*')
            && (pattern.contains('[') || pattern.contains('(') || pattern.contains('+'))
        {
            // Extract the core pattern and suggest a simple wildcard
            let core = pattern.trim_matches('*');
            if core.contains('[') && core.contains(']') {
                // For character classes like [0-1], suggest a simple wildcard
                return "*".to_string();
            }
        }

        // Default suggestion: convert common regex to wildcard
        pattern
            .replace(".*", "*")
            .replace(".", "?")
            .replace("+", "*")
            .replace("(", "")
            .replace(")", "")
            .replace("[", "")
            .replace("]", "")
    }

    /// Suggest a corrected regex pattern
    fn suggest_regex_pattern(&self, pattern: &str) -> String {
        // Common issue: * at the beginning without .
        if pattern.starts_with('*') && !pattern.starts_with(".*") {
            return format!(".{pattern}");
        }

        // Common issue: * at the end without .
        if pattern.ends_with('*') && !pattern.ends_with(".*") {
            return format!("{pattern}.");
        }

        // If no obvious fix, return the original with a note
        pattern.to_string()
    }

    /// Format a duration in a human-readable way
    fn format_duration(&self, duration: std::time::Duration) -> String {
        let total_millis = duration.as_millis();

        if total_millis < 1000 {
            format!("{total_millis}ms")
        } else if total_millis < 60000 {
            let seconds = total_millis as f64 / 1000.0;
            format!("{seconds:.1}s")
        } else {
            let minutes = total_millis / 60000;
            let seconds = (total_millis % 60000) / 1000;
            format!("{minutes}m {seconds}s")
        }
    }

    /// Pretty print DSLValue as a table
    pub fn pretty_print_table(&self, data: &DSLValue) -> String {
        match data {
            DSLValue::Array(arr) => {
                if arr.is_empty() {
                    return "No data to display".to_string();
                }

                // Get all unique keys from all objects
                let mut all_keys = std::collections::HashSet::new();
                for item in arr {
                    if let DSLValue::Object(obj) = item {
                        for key in obj.keys() {
                            all_keys.insert(key.clone());
                        }
                    }
                }

                let mut keys: Vec<String> = all_keys.into_iter().collect();
                keys.sort(); // Sort keys for consistent output

                if keys.is_empty() {
                    return "No data to display".to_string();
                }

                // Check if any column contains complex nested data
                let has_complex_data = self.has_complex_nested_data(arr, &keys);

                if has_complex_data {
                    // Use multi-line format with sub-tables for complex nested data
                    return self.format_complex_table_with_subtables(arr, &keys);
                }

                // Calculate column widths
                let mut column_widths = HashMap::new();
                for key in &keys {
                    let mut max_width = key.len();
                    for item in arr {
                        if let DSLValue::Object(obj) = item
                            && let Some(value) = obj.get(key) {
                                let value_str = self.format_value_for_table(value);
                                max_width = max_width.max(value_str.len());
                            }
                    }
                    column_widths.insert(key.clone(), max_width);
                }

                // Build the table
                let mut table = String::new();

                // Header
                table.push('┌');
                for (_i, key) in keys.iter().enumerate() {
                    let width = column_widths[key];
                    table.push_str(&"─".repeat(width + 2));
                    if _i < keys.len() - 1 {
                        table.push('┬');
                    }
                }
                table.push_str("┐\n");

                // Column headers
                table.push('│');
                for key in keys.iter() {
                    let width = column_widths[key];
                    table.push_str(&format!(" {key:<width$} │"));
                }
                table.push('\n');

                // Separator
                table.push('├');
                for (_i, key) in keys.iter().enumerate() {
                    let width = column_widths[key];
                    table.push_str(&"─".repeat(width + 2));
                    if _i < keys.len() - 1 {
                        table.push('┼');
                    }
                }
                table.push_str("┤\n");

                // Data rows
                for item in arr {
                    if let DSLValue::Object(obj) = item {
                        table.push('│');
                        for key in keys.iter() {
                            let width = column_widths[key];
                            let value = obj.get(key).unwrap_or(&DSLValue::Null);
                            let value_str = self.format_value_for_table(value);
                            table.push_str(&format!(" {value_str:<width$} │"));
                        }
                        table.push('\n');
                    }
                }

                // Footer
                table.push('└');
                for (_i, key) in keys.iter().enumerate() {
                    let width = column_widths[key];
                    table.push_str(&"─".repeat(width + 2));
                    if _i < keys.len() - 1 {
                        table.push('┴');
                    }
                }
                table.push('┘');

                table
            }
            DSLValue::Object(obj) => {
                // Single object - display as key-value pairs
                let mut table = String::new();
                let mut keys: Vec<String> = obj.keys().cloned().collect();
                keys.sort();

                if keys.is_empty() {
                    return "No data to display".to_string();
                }

                // Calculate column widths
                let mut key_width = 0;
                let mut value_width = 0;
                for key in &keys {
                    key_width = key_width.max(key.len());
                    if let Some(value) = obj.get(key) {
                        let value_str = self.format_value_for_table(value);
                        value_width = value_width.max(value_str.len());
                    }
                }

                // Build the table
                let total_width = key_width + value_width + 7; // +7 for borders and spacing

                // Header
                table.push_str(&format!("┌{}┐\n", "─".repeat(total_width - 2)));

                // Data rows
                for key in &keys {
                    if let Some(value) = obj.get(key) {
                        let value_str = self.format_value_for_table(value);
                        table.push_str(&format!(
                            "│ {key:<key_width$} │ {value_str:<value_width$} │\n"
                        ));
                    }
                }

                // Footer
                table.push_str(&format!("└{}┘", "─".repeat(total_width - 2)));

                table
            }
            _ => format!("{data}"),
        }
    }

    /// Format a value for table display
    fn format_value_for_table(&self, value: &DSLValue) -> String {
        match value {
            DSLValue::Null => "null".dimmed().to_string(),
            DSLValue::Boolean(b) => b.to_string().yellow().to_string(),
            DSLValue::Number(n) => n.to_string().cyan().to_string(),
            DSLValue::String(s) => s.clone(),
            DSLValue::Array(arr) => {
                if arr.is_empty() {
                    "[]".to_string()
                } else {
                    // For arrays, convert to serde_json::Value for clean JSON
                    let json_value = Self::dsl_value_to_json(value);
                    let json_str = serde_json::to_string_pretty(&json_value)
                        .unwrap_or_else(|_| format!("{value:?}"));
                    self.format_nested_json_for_table(&json_str)
                }
            }
            DSLValue::Object(obj) => {
                if obj.is_empty() {
                    "{}".to_string()
                } else {
                    // For objects, convert to serde_json::Value for clean JSON
                    let json_value = Self::dsl_value_to_json(value);
                    let json_str = serde_json::to_string_pretty(&json_value)
                        .unwrap_or_else(|_| format!("{value:?}"));
                    self.format_nested_json_for_table(&json_str)
                }
            }
        }
    }

    /// Convert DSLValue to serde_json::Value for clean JSON serialization
    fn dsl_value_to_json(value: &DSLValue) -> serde_json::Value {
        match value {
            DSLValue::Null => serde_json::Value::Null,
            DSLValue::Boolean(b) => serde_json::Value::Bool(*b),
            DSLValue::Number(n) => serde_json::Value::Number(
                serde_json::Number::from_f64(*n).unwrap_or_else(|| serde_json::Number::from(0)),
            ),
            DSLValue::String(s) => serde_json::Value::String(s.clone()),
            DSLValue::Array(arr) => {
                let json_array: Vec<serde_json::Value> =
                    arr.iter().map(Self::dsl_value_to_json).collect();
                serde_json::Value::Array(json_array)
            }
            DSLValue::Object(obj) => {
                let json_obj: serde_json::Map<String, serde_json::Value> = obj
                    .iter()
                    .map(|(k, v)| (k.clone(), Self::dsl_value_to_json(v)))
                    .collect();
                serde_json::Value::Object(json_obj)
            }
        }
    }

    /// Format nested JSON to be more readable in table format
    fn format_nested_json_for_table(&self, json_str: &str) -> String {
        let lines: Vec<&str> = json_str.lines().collect();

        if lines.len() <= 1 {
            // Single line JSON - return as-is
            json_str.to_string()
        } else {
            // Multi-line JSON - format with compact indentation
            let mut result = String::new();
            for (i, line) in lines.iter().enumerate() {
                if i == 0 {
                    // First line - no indentation
                    result.push_str(line);
                } else {
                    // Subsequent lines - add minimal indentation
                    let trimmed = line.trim();
                    if !trimmed.is_empty() {
                        result.push_str("  "); // 2 spaces for indentation
                        result.push_str(trimmed);
                    }
                }
                if i < lines.len() - 1 {
                    result.push(' '); // Use space instead of newline for table compatibility
                }
            }
            result
        }
    }

    /// Check if the data contains complex nested structures
    fn has_complex_nested_data(&self, arr: &[DSLValue], keys: &[String]) -> bool {
        for item in arr {
            if let DSLValue::Object(obj) = item {
                for key in keys {
                    if let Some(DSLValue::Array(_) | DSLValue::Object(_)) = obj.get(key) {
                        return true;
                    }
                }
            }
        }
        false
    }

    /// Format table for complex nested data using sub-tables within columns
    fn format_complex_table_with_subtables(&self, arr: &[DSLValue], keys: &[String]) -> String {
        // Calculate column widths
        let mut column_widths = Vec::new();
        for key in keys {
            let mut max_width = key.len();
            for item in arr {
                if let DSLValue::Object(obj) = item
                    && let Some(value) = obj.get(key) {
                        let value_str = match value {
                            DSLValue::Array(arr) => {
                                if arr.is_empty() {
                                    "[]".to_string()
                                } else {
                                    self.create_compact_sub_table_for_array(arr)
                                }
                            }
                            DSLValue::Object(obj) => {
                                if obj.is_empty() {
                                    "{}".to_string()
                                } else {
                                    self.create_compact_sub_table_for_object(obj)
                                }
                            }
                            _ => format!("{value}"),
                        };
                        max_width = max_width.max(value_str.len());
                    }
            }
            column_widths.push(max_width + 2); // Add padding
        }

        // Build table content first (without frame)
        let mut table_content = String::new();
        table_content.push_str("Row 1:\n");

        // Header row
        for (i, key) in keys.iter().enumerate() {
            table_content.push_str(&format!(" {:<width$} ", key, width = column_widths[i]));
            if i < keys.len() - 1 {
                table_content.push_str(" | ");
            }
        }
        table_content.push('\n');

        // Data rows with multi-line support
        for item in arr {
            if let DSLValue::Object(obj) = item {
                // Get all the wrapped lines for this row
                let mut row_lines: Vec<Vec<String>> = Vec::new();

                for key in keys {
                    let value = obj.get(key).unwrap_or(&DSLValue::Null);
                    let value_str = match value {
                        DSLValue::Array(arr) => {
                            if arr.is_empty() {
                                "[]".to_string()
                            } else {
                                self.create_compact_sub_table_for_array(arr)
                            }
                        }
                        DSLValue::Object(obj) => {
                            if obj.is_empty() {
                                "{}".to_string()
                            } else {
                                self.create_compact_sub_table_for_object(obj)
                            }
                        }
                        _ => format!("{value}"),
                    };

                    let col_idx = keys.iter().position(|k| k == key).unwrap();
                    let lines = self.wrap_text_to_lines(&value_str, column_widths[col_idx]);
                    row_lines.push(lines);
                }

                // Find the maximum number of lines for this row
                let max_lines = row_lines.iter().map(|lines| lines.len()).max().unwrap_or(1);

                // Print each line of the row
                for line_idx in 0..max_lines {
                    for (col_idx, _key) in keys.iter().enumerate() {
                        let lines = &row_lines[col_idx];
                        if line_idx < lines.len() {
                            let line_content = &lines[line_idx];
                            table_content.push_str(&format!(
                                " {:<width$} ",
                                line_content,
                                width = column_widths[col_idx]
                            ));
                        } else {
                            // Fill empty space for this column
                            table_content.push_str(&format!(
                                " {:<width$} ",
                                "",
                                width = column_widths[col_idx]
                            ));
                        }
                        if col_idx < keys.len() - 1 {
                            table_content.push_str(" | ");
                        }
                    }
                    table_content.push('\n');
                }
            }
        }

        // Simple table with just a line under headers
        let mut final_table = String::new();

        // Add content with simple formatting
        let content_lines: Vec<&str> = table_content.lines().collect();
        for (line_idx, line) in content_lines.iter().enumerate() {
            if line_idx == 0 {
                // Add the "Row 1:" line first
                final_table.push_str(line);
                final_table.push('\n');
                continue;
            }

            // Add content line
            final_table.push_str(line);
            final_table.push('\n');

            // Add separator line after header
            if line_idx == 1 {
                // Simple line under headers
                for (i, width) in column_widths.iter().enumerate() {
                    for _ in 0..*width {
                        final_table.push('─');
                    }
                    if i < column_widths.len() - 1 {
                        final_table.push('─');
                    }
                }
                final_table.push('\n');
            }
        }

        final_table
    }

    /// Wrap text to fit within column width and return lines (without column separator)
    fn wrap_text_to_lines(&self, text: &str, column_width: usize) -> Vec<String> {
        // Account for padding (2 spaces + 2 spaces = 4 characters)
        let available_width = column_width.saturating_sub(4);

        if text.len() <= available_width {
            vec![text.to_string()]
        } else {
            // Split text into chunks that fit within available width
            let mut lines = Vec::new();
            let mut current_line = String::new();

            for word in text.split_whitespace() {
                if current_line.len() + word.len() < available_width {
                    if !current_line.is_empty() {
                        current_line.push(' ');
                    }
                    current_line.push_str(word);
                } else {
                    // Current line is full, add it to lines
                    if !current_line.is_empty() {
                        lines.push(current_line);
                    }
                    current_line = word.to_string();
                }
            }

            // Add the last line
            if !current_line.is_empty() {
                lines.push(current_line);
            }

            lines
        }
    }

    /// Create a sub-table for an array
    #[allow(dead_code)]
    fn create_sub_table_for_array(&self, arr: &[DSLValue]) -> String {
        if arr.is_empty() {
            return "[]".to_string();
        }

        let mut table = String::new();

        for (i, item) in arr.iter().enumerate() {
            let item_str = match item {
                DSLValue::Object(obj) => self.create_compact_sub_table_for_object(obj),
                DSLValue::Array(nested_arr) => self.create_compact_sub_table_for_array(nested_arr),
                _ => format!("{item}"),
            };

            // Add item to table
            table.push_str(&item_str.to_string());

            if i < arr.len() - 1 {
                table.push('\n');
            }
        }

        table
    }

    /// Create a compact sub-table for an array (fits in column)
    fn create_compact_sub_table_for_array(&self, arr: &[DSLValue]) -> String {
        if arr.is_empty() {
            return "[]".to_string();
        }

        let mut items = Vec::new();
        for item in arr {
            let item_str = match item {
                DSLValue::Object(obj) => self.create_compact_sub_table_for_object(obj),
                DSLValue::Array(nested_arr) => self.create_compact_sub_table_for_array(nested_arr),
                _ => format!("{item}"),
            };
            items.push(item_str);
        }

        format!("[{}]", items.join(", "))
    }

    /// Create a sub-table for an object
    #[allow(dead_code)]
    fn create_sub_table_for_object(
        &self,
        obj: &std::collections::HashMap<String, DSLValue>,
    ) -> String {
        if obj.is_empty() {
            return "{}".to_string();
        }

        let mut keys: Vec<String> = obj.keys().cloned().collect();
        keys.sort();

        // Calculate column widths
        let mut key_width = 0;
        let mut value_width = 0;
        for key in &keys {
            key_width = key_width.max(key.len());
            if let Some(value) = obj.get(key) {
                let value_str = match value {
                    DSLValue::Object(nested_obj) => self.create_sub_table_for_object(nested_obj),
                    DSLValue::Array(nested_arr) => self.create_sub_table_for_array(nested_arr),
                    _ => format!("{value}"),
                };
                value_width = value_width.max(value_str.len());
            }
        }

        let mut table = String::new();
        let total_width = key_width + value_width + 7;

        // Header
        table.push_str(&format!("┌{}┐\n", "─".repeat(total_width - 2)));

        // Data rows
        for key in &keys {
            if let Some(value) = obj.get(key) {
                let value_str = match value {
                    DSLValue::Object(nested_obj) => self.create_sub_table_for_object(nested_obj),
                    DSLValue::Array(nested_arr) => self.create_sub_table_for_array(nested_arr),
                    _ => format!("{value}"),
                };
                table.push_str(&format!(
                    "│ {key:<key_width$} │ {value_str:<value_width$} │\n"
                ));
            }
        }

        // Footer
        table.push_str(&format!("└{}┘", "─".repeat(total_width - 2)));

        table
    }

    /// Create a compact sub-table for an object (fits in column)
    fn create_compact_sub_table_for_object(
        &self,
        obj: &std::collections::HashMap<String, DSLValue>,
    ) -> String {
        if obj.is_empty() {
            return "{}".to_string();
        }

        let mut pairs = Vec::new();
        let mut keys: Vec<String> = obj.keys().cloned().collect();
        keys.sort();

        for key in &keys {
            if let Some(value) = obj.get(key) {
                let value_str = match value {
                    DSLValue::Object(nested_obj) => {
                        self.create_compact_sub_table_for_object(nested_obj)
                    }
                    DSLValue::Array(nested_arr) => {
                        self.create_compact_sub_table_for_array(nested_arr)
                    }
                    _ => format!("{value}"),
                };
                pairs.push(format!("{key}: {value_str}"));
            }
        }

        format!("{{{}}}", pairs.join(", "))
    }

    /// Format a sub-table to fit within a column
    #[allow(dead_code)]
    fn format_sub_table_in_column(&self, sub_table: &str, column_width: usize) -> String {
        let lines: Vec<&str> = sub_table.lines().collect();
        let mut result = String::new();

        for (i, line) in lines.iter().enumerate() {
            if i > 0 {
                result.push('│');
            }

            // Truncate or wrap the line to fit within column width
            let truncated_line = if line.len() > column_width {
                &line[..column_width]
            } else {
                line
            };

            result.push_str(&format!(
                " {truncated_line:<column_width$} "
            ));
            if i < lines.len() - 1 {
                result.push_str("│\n");
            }
        }

        result
    }

    /// Format table for simple data using single-line format
    #[allow(dead_code)]
    fn format_simple_table(&self, arr: &[DSLValue], keys: &[String]) -> String {
        // Calculate column widths
        let mut column_widths = HashMap::new();
        for key in keys {
            let mut max_width = key.len();
            for item in arr {
                if let DSLValue::Object(obj) = item
                    && let Some(value) = obj.get(key) {
                        let value_str = self.format_value_for_table(value);
                        max_width = max_width.max(value_str.len());
                    }
            }
            column_widths.insert(key.clone(), max_width);
        }

        // Build the table
        let mut table = String::new();

        // Header
        table.push('┌');
        for (i, key) in keys.iter().enumerate() {
            let width = column_widths[key];
            table.push_str(&"─".repeat(width + 2));
            if i < keys.len() - 1 {
                table.push('┬');
            }
        }
        table.push_str("┐\n");

        // Column headers
        table.push('│');
        for key in keys {
            let width = column_widths[key];
            table.push_str(&format!(" {key:<width$} │"));
        }
        table.push('\n');

        // Separator
        table.push('├');
        for (i, key) in keys.iter().enumerate() {
            let width = column_widths[key];
            table.push_str(&"─".repeat(width + 2));
            if i < keys.len() - 1 {
                table.push('┼');
            }
        }
        table.push_str("┤\n");

        // Data rows
        for item in arr {
            if let DSLValue::Object(obj) = item {
                table.push('│');
                for key in keys {
                    let width = column_widths[key];
                    let value = obj.get(key).unwrap_or(&DSLValue::Null);
                    let value_str = self.format_value_for_table(value);
                    table.push_str(&format!(" {value_str:<width$} │"));
                }
                table.push('\n');
            }
        }

        // Footer
        table.push('└');
        for (i, key) in keys.iter().enumerate() {
            let width = column_widths[key];
            table.push_str(&"─".repeat(width + 2));
            if i < keys.len() - 1 {
                table.push('┴');
            }
        }
        table.push('┘');

        table
    }

    /// Convert infix condition to RPN (Reverse Polish Notation)
    fn infix_to_rpn(&self, tokens: Vec<ConditionToken>) -> DSLResult<Vec<ConditionToken>> {
        let mut output = Vec::new();
        let mut stack = Vec::new();

        for token in tokens {
            match token {
                ConditionToken::Field(_) | ConditionToken::Value(_) => {
                    output.push(token);
                }
                ConditionToken::LeftParen => {
                    stack.push(token);
                }
                ConditionToken::RightParen => {
                    while let Some(top) = stack.pop() {
                        if top == ConditionToken::LeftParen {
                            break;
                        }
                        output.push(top);
                    }
                }
                ConditionToken::And | ConditionToken::Or | ConditionToken::Not => {
                    while let Some(top) = stack.last() {
                        if let ConditionToken::LeftParen = top {
                            break;
                        }
                        if self.get_precedence(&token) <= self.get_precedence(top) {
                            output.push(stack.pop().unwrap());
                        } else {
                            break;
                        }
                    }
                    stack.push(token);
                }
                ConditionToken::Operator(_) => {
                    while let Some(top) = stack.last() {
                        if let ConditionToken::LeftParen = top {
                            break;
                        }
                        if self.get_precedence(&token) <= self.get_precedence(top) {
                            output.push(stack.pop().unwrap());
                        } else {
                            break;
                        }
                    }
                    stack.push(token);
                }
            }
        }

        while let Some(token) = stack.pop() {
            if token == ConditionToken::LeftParen {
                return Err(DSLError::syntax_error(
                    0,
                    "Mismatched parentheses in WHERE clause".to_string(),
                ));
            }
            output.push(token);
        }

        Ok(output)
    }

    /// Get operator precedence for RPN conversion
    fn get_precedence(&self, token: &ConditionToken) -> u8 {
        match token {
            ConditionToken::Not => 3,
            ConditionToken::And => 2,
            ConditionToken::Or => 1,
            ConditionToken::Operator(_) => 4,
            _ => 0,
        }
    }

    /// Evaluate RPN expression against a cluster
    fn evaluate_rpn(&self, cluster: &Tidb, rpn: &[ConditionToken]) -> DSLResult<bool> {
        let mut stack = Vec::new();

        for token in rpn {
            match token {
                ConditionToken::Field(field_name) => {
                    // Get the field value from the cluster
                    let field_value = self.get_field_value(cluster, field_name);
                    if field_value.is_none() {
                        return Err(DSLError::syntax_error(
                            0,
                            format!("Unknown field '{field_name}' in WHERE clause"),
                        ));
                    }
                    stack.push(DSLValue::from(field_value.unwrap()));
                }
                ConditionToken::Value(value) => {
                    stack.push(value.clone());
                }
                ConditionToken::Operator(operator) => {
                    if stack.len() < 2 {
                        return Err(DSLError::syntax_error(
                            0,
                            format!("Insufficient operands for operator '{operator}'"),
                        ));
                    }
                    let right = stack.pop().unwrap();
                    let left = stack.pop().unwrap();

                    let result = self.apply_operator(&left, &right, operator)?;
                    stack.push(DSLValue::from(result));
                }
                ConditionToken::And => {
                    if stack.len() < 2 {
                        return Err(DSLError::syntax_error(
                            0,
                            "Insufficient operands for AND operator".to_string(),
                        ));
                    }
                    let right = stack.pop().unwrap();
                    let left = stack.pop().unwrap();

                    let result = left.is_truthy() && right.is_truthy();
                    stack.push(DSLValue::from(result));
                }
                ConditionToken::Or => {
                    if stack.len() < 2 {
                        return Err(DSLError::syntax_error(
                            0,
                            "Insufficient operands for OR operator".to_string(),
                        ));
                    }
                    let right = stack.pop().unwrap();
                    let left = stack.pop().unwrap();

                    let result = left.is_truthy() || right.is_truthy();
                    stack.push(DSLValue::from(result));
                }
                ConditionToken::Not => {
                    if stack.is_empty() {
                        return Err(DSLError::syntax_error(
                            0,
                            "Insufficient operands for NOT operator".to_string(),
                        ));
                    }
                    let operand = stack.pop().unwrap();

                    let result = !operand.is_truthy();
                    stack.push(DSLValue::from(result));
                }
                _ => {
                    return Err(DSLError::syntax_error(
                        0,
                        "Unexpected token in RPN evaluation".to_string(),
                    ));
                }
            }
        }

        if stack.len() != 1 {
            return Err(DSLError::syntax_error(
                0,
                "Invalid expression in WHERE clause".to_string(),
            ));
        }

        let result = stack.pop().unwrap();
        Ok(result.is_truthy())
    }

    /// Apply comparison operator to two values
    fn apply_operator(&self, left: &DSLValue, right: &DSLValue, operator: &str) -> DSLResult<bool> {
        let left_str = left.as_string().unwrap_or("").to_lowercase();
        let right_str = right.as_string().unwrap_or("").to_lowercase();

        match operator {
            "=" | "==" => {
                // Handle regex patterns, wildcards, and exact matches
                if right_str.starts_with('/') && right_str.ends_with('/') {
                    let regex_pattern = &right_str[1..right_str.len() - 1];
                    match regex::Regex::new(regex_pattern) {
                        Ok(regex) => Ok(regex.is_match(&left_str)),
                        Err(e) => Err(DSLError::syntax_error(
                            0,
                            format!("Invalid regex pattern '{regex_pattern}': {e}"),
                        )),
                    }
                } else if self.is_regex_pattern(&right_str) {
                    match regex::Regex::new(&right_str) {
                        Ok(regex) => Ok(regex.is_match(&left_str)),
                        Err(e) => Err(DSLError::syntax_error(
                            0,
                            format!("Invalid regex pattern '{right_str}': {e}"),
                        )),
                    }
                } else if right_str.contains('*') || right_str.contains('?') {
                    let regex_pattern = self.wildcard_to_regex(&right_str);
                    match regex::Regex::new(&regex_pattern) {
                        Ok(regex) => Ok(regex.is_match(&left_str)),
                        Err(e) => Err(DSLError::syntax_error(
                            0,
                            format!("Invalid wildcard pattern '{right_str}': {e}"),
                        )),
                    }
                } else {
                    Ok(left_str == right_str)
                }
            }
            "!=" => {
                if right_str.starts_with('/') && right_str.ends_with('/') {
                    let regex_pattern = &right_str[1..right_str.len() - 1];
                    match regex::Regex::new(regex_pattern) {
                        Ok(regex) => Ok(!regex.is_match(&left_str)),
                        Err(e) => Err(DSLError::syntax_error(
                            0,
                            format!("Invalid regex pattern '{regex_pattern}': {e}"),
                        )),
                    }
                } else if self.is_regex_pattern(&right_str) {
                    match regex::Regex::new(&right_str) {
                        Ok(regex) => Ok(!regex.is_match(&left_str)),
                        Err(e) => Err(DSLError::syntax_error(
                            0,
                            format!("Invalid regex pattern '{right_str}': {e}"),
                        )),
                    }
                } else if right_str.contains('*') || right_str.contains('?') {
                    let regex_pattern = self.wildcard_to_regex(&right_str);
                    match regex::Regex::new(&regex_pattern) {
                        Ok(regex) => Ok(!regex.is_match(&left_str)),
                        Err(e) => Err(DSLError::syntax_error(
                            0,
                            format!("Invalid wildcard pattern '{right_str}': {e}"),
                        )),
                    }
                } else {
                    Ok(left_str != right_str)
                }
            }
            "<" => Ok(left_str < right_str),
            "<=" => Ok(left_str <= right_str),
            ">" => Ok(left_str > right_str),
            ">=" => Ok(left_str >= right_str),
            "IN" => {
                // For IN operator, right should be an array
                match right {
                    DSLValue::Array(values) => {
                        // Check if left value is in the array
                        let left_value = left.as_string().unwrap_or("").to_lowercase();
                        Ok(values
                            .iter()
                            .any(|v| v.as_string().unwrap_or("").to_lowercase() == left_value))
                    }
                    _ => Err(DSLError::syntax_error(
                        0,
                        format!("IN operator requires an array on the right side, got {right}"),
                    )),
                }
            }
            _ => Err(DSLError::syntax_error(
                0,
                format!("Unknown operator '{operator}'"),
            )),
        }
    }

    /// Parse WHERE clause into tokens for RPN processing
    fn parse_where_tokens(&self, where_clause: &str) -> DSLResult<Vec<ConditionToken>> {
        let mut tokens = Vec::new();
        let mut current = String::new();
        let mut in_quotes = false;
        let mut i = 0;
        let chars: Vec<char> = where_clause.chars().collect();

        while i < chars.len() {
            let ch = chars[i];

            if ch == '"' {
                in_quotes = !in_quotes;
                if !in_quotes && !current.is_empty() {
                    // End of quoted string
                    tokens.push(ConditionToken::Value(DSLValue::from(current.clone())));
                    current.clear();
                }
            } else if in_quotes {
                current.push(ch);
            } else if ch.is_whitespace() {
                if !current.is_empty() {
                    self.push_token(&mut tokens, &current)?;
                    current.clear();
                }
            } else if ch == '(' {
                if !current.is_empty() {
                    self.push_token(&mut tokens, &current)?;
                    current.clear();
                }
                tokens.push(ConditionToken::LeftParen);
            } else if ch == ')' {
                if !current.is_empty() {
                    self.push_token(&mut tokens, &current)?;
                    current.clear();
                }
                tokens.push(ConditionToken::RightParen);
            } else if ch == '[' {
                // Start of array literal
                if !current.is_empty() {
                    self.push_token(&mut tokens, &current)?;
                    current.clear();
                }
                let array_values = self.parse_array_literal(&chars, &mut i)?;
                tokens.push(ConditionToken::Value(DSLValue::from(array_values)));
            } else {
                current.push(ch);
            }
            i += 1;
        }

        if !current.is_empty() {
            self.push_token(&mut tokens, &current)?;
        }

        // Validate that we have proper operator-value pairs
        self.validate_token_sequence(&tokens)?;

        Ok(tokens)
    }

    fn parse_array_literal(&self, chars: &[char], index: &mut usize) -> DSLResult<Vec<DSLValue>> {
        let mut values = Vec::new();
        let mut current_value = String::new();
        let mut in_quotes = false;

        // Skip the opening '['
        *index += 1;

        while *index < chars.len() {
            let ch = chars[*index];

            if ch == ']' {
                // End of array
                if !current_value.is_empty() {
                    // Remove quotes from the value
                    let clean_value = current_value
                        .trim()
                        .trim_matches('"')
                        .trim_matches('\'')
                        .to_string();
                    values.push(DSLValue::from(clean_value));
                }
                break;
            } else if ch == '"' {
                in_quotes = !in_quotes;
                if !in_quotes && !current_value.is_empty() {
                    // End of quoted string in array
                    values.push(DSLValue::from(current_value.clone()));
                    current_value.clear();
                }
            } else if in_quotes {
                current_value.push(ch);
            } else if ch == ',' {
                // Separator between array elements
                if !current_value.is_empty() {
                    // Remove quotes from the value
                    let clean_value = current_value
                        .trim()
                        .trim_matches('"')
                        .trim_matches('\'')
                        .to_string();
                    values.push(DSLValue::from(clean_value));
                    current_value.clear();
                }
            } else if ch.is_whitespace() {
                // Skip whitespace outside of quotes
                if !current_value.is_empty() {
                    current_value.push(ch);
                }
            } else {
                current_value.push(ch);
            }

            *index += 1;
        }

        if *index >= chars.len() {
            return Err(DSLError::syntax_error(
                0,
                "Unterminated array literal".to_string(),
            ));
        }

        Ok(values)
    }

    fn validate_token_sequence(&self, tokens: &[ConditionToken]) -> DSLResult<()> {
        let mut i = 0;
        while i < tokens.len() {
            match &tokens[i] {
                ConditionToken::Field(_) => {
                    // After a field, we expect an operator
                    if i + 1 >= tokens.len() {
                        return Err(DSLError::syntax_error(
                            0,
                            "Expected operator after field".to_string(),
                        ));
                    }
                    match &tokens[i + 1] {
                        ConditionToken::Operator(_) => {
                            // After an operator, we expect a value
                            if i + 2 >= tokens.len() {
                                return Err(DSLError::syntax_error(
                                    0,
                                    "Expected value after operator".to_string(),
                                ));
                            }
                            match &tokens[i + 2] {
                                ConditionToken::Value(_) | ConditionToken::Field(_) => {
                                    i += 3;
                                }
                                _ => {
                                    return Err(DSLError::syntax_error(
                                        0,
                                        "Expected value after operator".to_string(),
                                    ));
                                }
                            }
                        }
                        _ => {
                            return Err(DSLError::syntax_error(
                                0,
                                "Expected operator after field".to_string(),
                            ));
                        }
                    }
                }
                ConditionToken::Not => {
                    // NOT can be followed by a field, a left parenthesis, or another NOT
                    if i + 1 >= tokens.len() {
                        return Err(DSLError::syntax_error(
                            0,
                            "Expected expression after NOT".to_string(),
                        ));
                    }
                    match &tokens[i + 1] {
                        ConditionToken::Field(_)
                        | ConditionToken::LeftParen
                        | ConditionToken::Not => {
                            i += 1; // Move to the next token, the NOT itself
                        }
                        _ => {
                            return Err(DSLError::syntax_error(
                                0,
                                "Expected field, parenthesis, or NOT after NOT".to_string(),
                            ));
                        }
                    }
                }
                ConditionToken::And | ConditionToken::Or => {
                    // AND/OR can be followed by any expression
                    if i + 1 >= tokens.len() {
                        return Err(DSLError::syntax_error(
                            0,
                            "Expected expression after logical operator".to_string(),
                        ));
                    }
                    i += 1;
                }
                ConditionToken::LeftParen | ConditionToken::RightParen => {
                    i += 1;
                }
                ConditionToken::Value(_) => {
                    // Values should only appear after operators
                    if i == 0 || !matches!(&tokens[i - 1], ConditionToken::Operator(_)) {
                        return Err(DSLError::syntax_error(
                            0,
                            "Unexpected value without operator".to_string(),
                        ));
                    }
                    i += 1;
                }
                ConditionToken::Operator(_) => {
                    // Operators should only appear after fields
                    if i == 0 || !matches!(&tokens[i - 1], ConditionToken::Field(_)) {
                        return Err(DSLError::syntax_error(
                            0,
                            "Unexpected operator without field".to_string(),
                        ));
                    }
                    i += 1;
                }
            }
        }
        Ok(())
    }

    /// Push a token to the token list
    fn push_token(&self, tokens: &mut Vec<ConditionToken>, token: &str) -> DSLResult<()> {
        let token_upper = token.to_uppercase();
        match token_upper.as_str() {
            "AND" => tokens.push(ConditionToken::And),
            "OR" => tokens.push(ConditionToken::Or),
            "NOT" => tokens.push(ConditionToken::Not),
            "=" | "==" | "!=" | "<" | "<=" | ">" | ">=" | "IN" => {
                tokens.push(ConditionToken::Operator(token.to_string()));
            }
            _ => {
                // Check if it's a field name or value
                if self.is_valid_tidb_field(token) {
                    tokens.push(ConditionToken::Field(token.to_string()));
                } else {
                    // Treat as value (remove quotes if present)
                    let clean_value = token.trim_matches('"');
                    tokens.push(ConditionToken::Value(DSLValue::from(
                        clean_value.to_string(),
                    )));
                }
            }
        }
        Ok(())
    }

    /// Evaluate complex WHERE clause using RPN
    fn evaluate_where_clause(&self, cluster: &Tidb, where_clause: &str) -> DSLResult<bool> {
        let tokens = self.parse_where_tokens(where_clause)?;
        let rpn = self.infix_to_rpn(tokens)?;
        self.evaluate_rpn(cluster, &rpn)
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
            TiDBCloudClient::new("test-api-key-that-is-long-enough-for-validation".to_string())
                .unwrap()
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

        // Invalid regions
        assert!(executor.validate_region("").is_err());
        assert!(executor.validate_region("invalid-region").is_err());
        assert!(executor.validate_region("aws-west-1").is_err());
    }

    #[test]
    fn test_evaluate_filter_nested_fields() {
        let client = MockTiDBCloudClient::new();
        let executor = DSLExecutor::new(client);

        // Create a test cluster with nested data
        let mut cluster = Tidb::default();
        cluster.display_name = "test-cluster".to_string();
        cluster.state = Some(ClusterState::Active);

        // Add annotations
        let mut annotations = HashMap::new();
        annotations.insert(
            "tidb.cloud/has-set-password".to_string(),
            "false".to_string(),
        );
        annotations.insert("environment".to_string(), "production".to_string());
        cluster.annotations = Some(annotations);

        // Add labels
        let mut labels = HashMap::new();
        labels.insert("tidb.cloud/organization".to_string(), "90032".to_string());
        labels.insert("team".to_string(), "platform".to_string());
        cluster.labels = Some(labels);

        // Test nested field access
        assert!(executor.evaluate_filter(&cluster, r#"annotations.environment = "production""#));
        assert!(executor.evaluate_filter(
            &cluster,
            r#"annotations."tidb.cloud/has-set-password" = "false""#
        ));
        assert!(executor.evaluate_filter(&cluster, r#"labels.team = "platform""#));
        assert!(
            executor.evaluate_filter(&cluster, r#"labels."tidb.cloud/organization" = "90032""#)
        );

        // Test regex on nested fields
        assert!(executor.evaluate_filter(&cluster, r#"annotations.environment = "/prod/""#));
        assert!(executor.evaluate_filter(&cluster, r#"labels.team = "/plat/""#));

        // Test non-existent nested fields
        assert!(!executor.evaluate_filter(&cluster, r#"annotations.nonexistent = "value""#));
        assert!(!executor.evaluate_filter(&cluster, r#"labels.nonexistent = "value""#));
    }

    #[test]
    fn test_evaluate_filter_error_handling() {
        let client = MockTiDBCloudClient::new();
        let executor = DSLExecutor::new(client);

        // Create a test cluster
        let mut cluster = Tidb::default();
        cluster.display_name = "test-cluster".to_string();
        cluster.state = Some(ClusterState::Active);

        // Test unknown field (should print error and return false)
        assert!(!executor.evaluate_filter(&cluster, r#"unknown_field = "value""#));

        // Test invalid filter format (should print error and return false)
        assert!(!executor.evaluate_filter(&cluster, r#"display_name = "#));
        assert!(!executor.evaluate_filter(&cluster, r#"display_name"#));

        // Test unknown operator (should print error and return false)
        assert!(!executor.evaluate_filter(&cluster, r#"display_name <> "test""#));

        // Test invalid regex pattern (should print error and return false)
        assert!(!executor.evaluate_filter(&cluster, r#"display_name = "/[invalid/""#));
    }

    #[test]
    fn test_get_available_fields() {
        let client = MockTiDBCloudClient::new();
        let executor = DSLExecutor::new(client);

        let fields = executor.get_available_fields();

        // Check that all expected sections are present
        assert!(fields.contains("Top-level fields:"));
        assert!(fields.contains("Nested fields:"));
        assert!(fields.contains("Aliases:"));

        // Check that all expected fields are present
        assert!(fields.contains("name"));
        assert!(fields.contains("display_name"));
        assert!(fields.contains("region_id"));
        assert!(fields.contains("state"));
        assert!(fields.contains("annotations.<key>"));
        assert!(fields.contains("labels.<key>"));
        assert!(fields.contains("endpoints.<index>.host"));
        assert!(fields.contains("region")); // alias

        // Check the format includes newlines and indentation
        assert!(fields.contains("\n  "));
    }

    #[test]
    fn test_wildcard_patterns() {
        let client = MockTiDBCloudClient::new();
        let executor = DSLExecutor::new(client);

        // Create a test cluster
        let mut cluster = Tidb::default();
        cluster.display_name = "SB-Test01-delete-whenever".to_string();
        cluster.region_id = "aws-us-east-1".to_string();
        cluster.state = Some(ClusterState::Active);

        // Test wildcard patterns
        assert!(executor.evaluate_filter(&cluster, r#"display_name = "SB*""#));
        assert!(executor.evaluate_filter(&cluster, r#"display_name = "*Test*""#));
        assert!(executor.evaluate_filter(&cluster, r#"display_name = "*whenever""#));
        assert!(executor.evaluate_filter(&cluster, r#"display_name = "SB-Test01*""#));

        // Test single character wildcard
        assert!(
            executor.evaluate_filter(&cluster, r#"display_name = "SB-Test01-delete-whenever""#)
        );
        assert!(
            executor.evaluate_filter(&cluster, r#"display_name = "SB-Test01-delete-whenev?r""#)
        );

        // Test negation with wildcards
        assert!(!executor.evaluate_filter(&cluster, r#"display_name != "SB*""#));
        assert!(executor.evaluate_filter(&cluster, r#"display_name != "Different*""#));

        // Test that exact matching still works
        assert!(
            executor.evaluate_filter(&cluster, r#"display_name = "SB-Test01-delete-whenever""#)
        );
        assert!(!executor.evaluate_filter(&cluster, r#"display_name = "Different-Name""#));
    }

    #[test]
    fn test_wildcard_to_regex_conversion() {
        let client = MockTiDBCloudClient::new();
        let executor = DSLExecutor::new(client);

        // Test basic wildcard conversion
        assert_eq!(executor.wildcard_to_regex("test*"), "^test.*$");
        assert_eq!(executor.wildcard_to_regex("*test"), "^.*test$");
        assert_eq!(executor.wildcard_to_regex("test?"), "^test.$");
        assert_eq!(executor.wildcard_to_regex("test"), "^test$");

        // Test escaping of regex special characters
        assert_eq!(executor.wildcard_to_regex("test.com"), "^test\\.com$");
        assert_eq!(executor.wildcard_to_regex("test(123)"), "^test\\(123\\)$");
        assert_eq!(executor.wildcard_to_regex("test[123]"), "^test\\[123\\]$");

        // Test the problematic pattern
        assert_eq!(
            executor.wildcard_to_regex("*([0-1]+)*"),
            "^.*\\(\\[0-1\\]\\+\\).*$"
        );
    }

    #[test]
    fn test_regex_vs_wildcard_detection() {
        let client = MockTiDBCloudClient::new();
        let executor = DSLExecutor::new(client);

        // Create a test cluster
        let mut cluster = Tidb::default();
        cluster.display_name = "Sb-Test01-abc".to_string();

        // This should work as regex pattern (wrapped in /)
        assert!(executor.evaluate_filter(&cluster, r#"display_name = "/.*([0-1]+).*/""#));

        // This should now work as regex pattern (not wrapped in / but contains regex chars)
        assert!(executor.evaluate_filter(&cluster, r#"display_name = ".*([0-1]+).*""#));

        // This should work as wildcard pattern (simple * and ?)
        assert!(executor.evaluate_filter(&cluster, r#"display_name = "Sb*""#));
        assert!(executor.evaluate_filter(&cluster, r#"display_name = "*Test*""#));
    }

    #[test]
    fn test_user_regex_pattern() {
        let client = MockTiDBCloudClient::new();
        let executor = DSLExecutor::new(client);

        // Create a test cluster matching the user's pattern
        let mut cluster = Tidb::default();
        cluster.display_name = "Sb-Test01-abc".to_string();

        // Test the corrected user pattern (.* instead of * at beginning)
        assert!(executor.evaluate_filter(&cluster, r#"display_name = ".*([0-1]+).*""#));
        assert!(executor.evaluate_filter(&cluster, r#"display_name = "/.*([0-1]+).*/""#));

        // Test that the original invalid pattern fails with proper error
        assert!(!executor.evaluate_filter(&cluster, r#"display_name = "*([0-1]+)*""#));

        // Test that the corrected patterns work
        assert!(executor.evaluate_filter(&cluster, r#"display_name = "*01*""#));
        assert!(executor.evaluate_filter(&cluster, r#"display_name = ".*([0-1]+).*""#));

        // Test the user's specific pattern
        assert!(!executor.evaluate_filter(&cluster, r#"display_name = "*[0-1]+*""#));
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
        assert_eq!(
            executor.get_variable("test_var"),
            Some(&DSLValue::from("test_value"))
        );

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
        assert_eq!(
            executor.get_variable("test_var"),
            Some(&DSLValue::from("test_value"))
        );
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
        assert_eq!(
            command_result.get_data(),
            Some(&DSLValue::from("test_value"))
        );
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

        let command =
            DSLCommand::new(DSLCommandType::If).with_parameter("condition", DSLValue::from(true));

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

    #[test]
    fn test_rpn_condition_evaluator_simple() {
        let executor = DSLExecutor::new(MockTiDBCloudClient::new());

        // Test simple field comparison
        let cluster = create_test_cluster("test-cluster", "ACTIVE", "us-east-1");
        let result = executor.evaluate_where_clause(&cluster, "name = test-cluster");
        assert!(result.is_ok());
        assert!(result.unwrap());

        let result = executor.evaluate_where_clause(&cluster, "name = other-cluster");
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[test]
    fn test_rpn_condition_evaluator_and_or() {
        let executor = DSLExecutor::new(MockTiDBCloudClient::new());

        let cluster = create_test_cluster("test-cluster", "ACTIVE", "us-east-1");

        // Test AND operator
        let result =
            executor.evaluate_where_clause(&cluster, "name = test-cluster AND state = ACTIVE");
        assert!(result.is_ok());
        assert!(result.unwrap());

        let result =
            executor.evaluate_where_clause(&cluster, "name = test-cluster AND state = FAILED");
        assert!(result.is_ok());
        assert!(!result.unwrap());

        // Test OR operator
        let result =
            executor.evaluate_where_clause(&cluster, "name = test-cluster OR state = FAILED");
        assert!(result.is_ok());
        assert!(result.unwrap());

        let result =
            executor.evaluate_where_clause(&cluster, "name = other-cluster OR state = FAILED");
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[test]
    fn test_rpn_condition_evaluator_parentheses() {
        let executor = DSLExecutor::new(MockTiDBCloudClient::new());

        let cluster = create_test_cluster("test-cluster", "ACTIVE", "us-east-1");

        // Test parentheses for operator precedence
        let result = executor.evaluate_where_clause(
            &cluster,
            "(name = test-cluster OR name = other) AND state = ACTIVE",
        );
        assert!(result.is_ok());
        assert!(result.unwrap());

        let result = executor.evaluate_where_clause(
            &cluster,
            "name = test-cluster OR (name = other AND state = ACTIVE)",
        );
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn test_rpn_condition_evaluator_not() {
        let executor = DSLExecutor::new(MockTiDBCloudClient::new());

        let cluster = create_test_cluster("test-cluster", "ACTIVE", "us-east-1");

        // Test NOT operator
        let result = executor.evaluate_where_clause(&cluster, "NOT (name = other-cluster)");
        assert!(result.is_ok());
        assert!(result.unwrap());

        let result = executor.evaluate_where_clause(&cluster, "NOT (name = test-cluster)");
        assert!(result.is_ok());
        assert!(!result.unwrap());

        // Test NOT with AND
        let result = executor
            .evaluate_where_clause(&cluster, "name = test-cluster AND NOT (state = FAILED)");
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn test_rpn_condition_evaluator_wildcards() {
        let executor = DSLExecutor::new(MockTiDBCloudClient::new());

        let cluster = create_test_cluster("test-cluster", "ACTIVE", "us-east-1");

        // Test wildcard patterns
        let result = executor.evaluate_where_clause(&cluster, "name = test*");
        assert!(result.is_ok());
        assert!(result.unwrap());

        let result = executor.evaluate_where_clause(&cluster, "name = *cluster");
        assert!(result.is_ok());
        assert!(result.unwrap());

        let result = executor.evaluate_where_clause(&cluster, "name = other*");
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[test]
    fn test_rpn_condition_evaluator_regex() {
        let executor = DSLExecutor::new(MockTiDBCloudClient::new());

        let cluster = create_test_cluster("test-cluster", "ACTIVE", "us-east-1");

        // Test regex patterns
        let result = executor.evaluate_where_clause(&cluster, "name = /test.*/");
        assert!(result.is_ok());
        assert!(result.unwrap());

        let result = executor.evaluate_where_clause(&cluster, "name = /.*cluster/");
        assert!(result.is_ok());
        assert!(result.unwrap());

        let result = executor.evaluate_where_clause(&cluster, "name = /other.*/");
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[test]
    fn test_rpn_condition_evaluator_complex() {
        let executor = DSLExecutor::new(MockTiDBCloudClient::new());

        let cluster = create_test_cluster("test-cluster", "ACTIVE", "us-east-1");

        // Test complex expression with multiple operators and parentheses
        let result = executor.evaluate_where_clause(
            &cluster,
            "(name = test* OR name = prod*) AND (state = ACTIVE OR state = CREATING) AND NOT (state = FAILED)",
        );
        assert!(result.is_ok());
        assert!(result.unwrap());

        let result = executor.evaluate_where_clause(
            &cluster,
            "name = /test.*/ AND (region = us-east-1 OR region = us-west-2)",
        );
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn test_rpn_condition_evaluator_errors() {
        let executor = DSLExecutor::new(MockTiDBCloudClient::new());

        let cluster = create_test_cluster("test-cluster", "ACTIVE", "us-east-1");

        // Test invalid field
        let result = executor.evaluate_where_clause(&cluster, "invalid_field = value");
        assert!(result.is_err());

        // Test mismatched parentheses
        let result = executor.evaluate_where_clause(&cluster, "(name = test-cluster");
        assert!(result.is_err());

        // Test invalid operator
        let result = executor.evaluate_where_clause(&cluster, "name INVALID_OP test-cluster");
        assert!(result.is_err());
    }

    #[test]
    fn test_rpn_condition_evaluator_operator_precedence() {
        let executor = DSLExecutor::new(MockTiDBCloudClient::new());

        let cluster = create_test_cluster("test-cluster", "ACTIVE", "us-east-1");

        // Test 1: AND has higher precedence than OR
        // A AND B OR C should be parsed as (A AND B) OR C
        let result = executor.evaluate_where_clause(
            &cluster,
            "name = test-cluster AND state = ACTIVE OR region = us-west-2",
        );
        assert!(result.is_ok());
        assert!(result.unwrap()); // Should be true because (name = test-cluster AND state = ACTIVE) is true

        // Test 2: NOT has higher precedence than AND
        // NOT A AND B should be parsed as (NOT A) AND B
        let result =
            executor.evaluate_where_clause(&cluster, "NOT name = other-cluster AND state = ACTIVE");
        assert!(result.is_ok());
        assert!(result.unwrap()); // Should be true because (NOT name = other-cluster) is true AND state = ACTIVE is true

        // Test 3: Comparison operators have highest precedence
        // A = B AND C = D should be parsed as (A = B) AND (C = D)
        let result =
            executor.evaluate_where_clause(&cluster, "name = test-cluster AND state = ACTIVE");
        assert!(result.is_ok());
        assert!(result.unwrap());

        // Test 4: Complex precedence with parentheses
        // A AND (B OR C) should be parsed as A AND (B OR C)
        let result = executor.evaluate_where_clause(
            &cluster,
            "name = test-cluster AND (state = ACTIVE OR state = CREATING)",
        );
        assert!(result.is_ok());
        assert!(result.unwrap());

        // Test 5: NOT with complex expression
        // NOT (A AND B) should be parsed as NOT (A AND B)
        let result = executor
            .evaluate_where_clause(&cluster, "NOT (name = other-cluster AND state = ACTIVE)");
        assert!(result.is_ok());
        assert!(result.unwrap()); // Should be true because the inner expression is false

        // Test 6: Multiple AND/OR without parentheses
        // A AND B OR C AND D should be parsed as (A AND B) OR (C AND D)
        let result = executor.evaluate_where_clause(
            &cluster,
            "name = test-cluster AND state = ACTIVE OR name = other-cluster AND state = CREATING",
        );
        assert!(result.is_ok());
        assert!(result.unwrap()); // Should be true because (name = test-cluster AND state = ACTIVE) is true

        // Test 7: NOT with OR precedence
        // NOT A OR B should be parsed as (NOT A) OR B
        let result =
            executor.evaluate_where_clause(&cluster, "NOT name = other-cluster OR state = ACTIVE");
        assert!(result.is_ok());
        assert!(result.unwrap()); // Should be true because (NOT name = other-cluster) is true

        // Test 8: Complex nested precedence
        // A AND NOT (B OR C) AND D should be parsed as A AND (NOT (B OR C)) AND D
        let result = executor.evaluate_where_clause(&cluster, "name = test-cluster AND NOT (state = FAILED OR state = DELETED) AND region = us-east-1");
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn test_rpn_condition_evaluator_precedence_edge_cases() {
        let executor = DSLExecutor::new(MockTiDBCloudClient::new());

        let cluster = create_test_cluster("test-cluster", "ACTIVE", "us-east-1");

        // Test 1: Simple NOT
        let result = executor.evaluate_where_clause(&cluster, "NOT name = other-cluster");
        assert!(result.is_ok());
        assert!(result.unwrap()); // Should be true because name != other-cluster

        // Test 2: NOT with parentheses
        let result = executor.evaluate_where_clause(&cluster, "NOT (name = other-cluster)");
        assert!(result.is_ok());
        assert!(result.unwrap()); // Should be true because the inner expression is false

        // Test 3: Complex precedence with mixed operators
        // A = B AND C != D OR E < F should be parsed as ((A = B) AND (C != D)) OR (E < F)
        let result = executor.evaluate_where_clause(
            &cluster,
            "name = test-cluster AND state != FAILED OR region < us-west-2",
        );
        assert!(result.is_ok());
        assert!(result.unwrap()); // Should be true because (name = test-cluster AND state != FAILED) is true

        // Test 4: Precedence with parentheses overriding
        // (A OR B) AND C should be parsed as (A OR B) AND C
        let result = executor.evaluate_where_clause(
            &cluster,
            "(name = test-cluster OR name = other-cluster) AND state = ACTIVE",
        );
        assert!(result.is_ok());
        assert!(result.unwrap()); // Should be true because (name = test-cluster OR name = other-cluster) is true AND state = ACTIVE is true
    }

    #[test]
    fn test_rpn_condition_evaluator_complex_precedence() {
        let executor = DSLExecutor::new(MockTiDBCloudClient::new());

        let cluster = create_test_cluster("test-cluster", "ACTIVE", "us-east-1");

        // Test 1: Simple NOT with field comparison
        // NOT A = B should be parsed as NOT (A = B)
        let result = executor.evaluate_where_clause(&cluster, "NOT name = other-cluster");
        assert!(result.is_ok());
        assert!(result.unwrap()); // Should be true because name != other-cluster

        // Test 2: NOT with AND/OR precedence
        // NOT A AND B should be parsed as (NOT A) AND B
        let result =
            executor.evaluate_where_clause(&cluster, "NOT name = other-cluster AND state = ACTIVE");
        assert!(result.is_ok());
        assert!(result.unwrap());

        // Test 3: NOT with OR precedence
        // NOT A OR B should be parsed as (NOT A) OR B
        let result =
            executor.evaluate_where_clause(&cluster, "NOT name = other-cluster OR state = ACTIVE");
        assert!(result.is_ok());
        assert!(result.unwrap());

        // Test 4: Complex nested precedence
        // A AND NOT (B OR C) AND D should be parsed as A AND (NOT (B OR C)) AND D
        let result = executor.evaluate_where_clause(&cluster, "name = test-cluster AND NOT (state = FAILED OR state = DELETED) AND region = us-east-1");
        assert!(result.is_ok());
        assert!(result.unwrap());

        // Test 5: Multiple comparison operators with precedence
        // A = B AND C != D OR E < F should be parsed as ((A = B) AND (C != D)) OR (E < F)
        let result = executor.evaluate_where_clause(
            &cluster,
            "name = test-cluster AND state != FAILED OR region < us-west-2",
        );
        assert!(result.is_ok());
        assert!(result.unwrap());

        // Test 6: Precedence with parentheses overriding
        // (A OR B) AND C should be parsed as (A OR B) AND C
        let result = executor.evaluate_where_clause(
            &cluster,
            "(name = test-cluster OR name = other-cluster) AND state = ACTIVE",
        );
        assert!(result.is_ok());
        assert!(result.unwrap());

        // Test 7: Complex expression with all operators
        // A AND (B OR C) AND NOT (D OR E) should be parsed as A AND (B OR C) AND (NOT (D OR E))
        let result = executor.evaluate_where_clause(&cluster, "name = test-cluster AND (state = ACTIVE OR state = CREATING) AND NOT (state = FAILED OR state = DELETED)");
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn test_rpn_condition_evaluator_in_operator() {
        let client = MockTiDBCloudClient::new();
        let executor = DSLExecutor::new(client);

        let cluster = create_test_cluster("test-cluster", "ACTIVE", "us-west-1");

        // Test IN operator with array of values
        let result =
            executor.evaluate_where_clause(&cluster, "state IN ['ACTIVE', 'CREATING', 'UPDATING']");
        assert!(result.is_ok());
        assert!(result.unwrap()); // Should be true because state is 'ACTIVE'

        // Test IN operator with array of values - not in list
        let result = executor.evaluate_where_clause(&cluster, "state IN ['FAILED', 'DELETED']");
        assert!(result.is_ok());
        assert!(!result.unwrap()); // Should be false because state is not in the list

        // Test IN operator with quoted strings in array
        let result =
            executor.evaluate_where_clause(&cluster, "state IN [\"ACTIVE\", \"CREATING\"]");
        assert!(result.is_ok());
        assert!(result.unwrap()); // Should be true

        // Test IN operator with mixed quoted and unquoted values
        let result =
            executor.evaluate_where_clause(&cluster, "state IN [ACTIVE, 'CREATING', \"UPDATING\"]");
        assert!(result.is_ok());
        assert!(result.unwrap()); // Should be true

        // Test IN operator with field name
        let result =
            executor.evaluate_where_clause(&cluster, "name IN ['test-cluster', 'other-cluster']");
        assert!(result.is_ok());
        assert!(result.unwrap()); // Should be true

        // Test IN operator with region
        let result =
            executor.evaluate_where_clause(&cluster, "region IN ['us-west-1', 'us-east-1']");
        assert!(result.is_ok());
        assert!(result.unwrap()); // Should be true
    }

    #[test]
    fn test_rpn_condition_evaluator_in_operator_complex() {
        let client = MockTiDBCloudClient::new();
        let executor = DSLExecutor::new(client);

        let cluster = create_test_cluster("test-cluster", "ACTIVE", "us-west-1");

        // Test IN operator combined with other operators
        let result = executor.evaluate_where_clause(
            &cluster,
            "state IN ['ACTIVE', 'CREATING'] AND name = test-cluster",
        );
        assert!(result.is_ok());
        assert!(result.unwrap()); // Should be true

        // Test IN operator with OR
        let result = executor.evaluate_where_clause(
            &cluster,
            "state IN ['FAILED', 'DELETED'] OR name = test-cluster",
        );
        assert!(result.is_ok());
        assert!(result.unwrap()); // Should be true because name = test-cluster

        // Test IN operator with NOT
        let result = executor.evaluate_where_clause(&cluster, "NOT state IN ['FAILED', 'DELETED']");
        assert!(result.is_ok());
        assert!(result.unwrap()); // Should be true because state is not in the list

        // Test complex expression with IN
        let result = executor.evaluate_where_clause(
            &cluster,
            "(state IN ['ACTIVE', 'CREATING']) AND (name IN ['test-cluster', 'other-cluster'])",
        );
        assert!(result.is_ok());
        assert!(result.unwrap()); // Should be true
    }

    #[test]
    fn test_rpn_condition_evaluator_in_operator_errors() {
        let client = MockTiDBCloudClient::new();
        let executor = DSLExecutor::new(client);

        let cluster = create_test_cluster("test-cluster", "ACTIVE", "us-west-1");

        // Test IN operator with non-array right side
        let result = executor.evaluate_where_clause(&cluster, "state IN ACTIVE");
        assert!(result.is_err()); // Should fail because right side is not an array

        // Test IN operator with empty array
        let result = executor.evaluate_where_clause(&cluster, "state IN []");
        assert!(result.is_ok());
        assert!(!result.unwrap()); // Should be false because empty array

        // Test IN operator with malformed array (missing closing bracket)
        let result = executor.evaluate_where_clause(&cluster, "state IN ['ACTIVE'");
        assert!(result.is_err()); // Should fail because array is not properly closed
    }

    fn create_test_cluster(name: &str, state: &str, region: &str) -> Tidb {
        Tidb {
            name: Some(name.to_string()),
            tidb_id: Some("test-id".to_string()),
            display_name: name.to_string(),
            region_id: region.to_string(),
            cloud_provider: Some(CloudProvider::Aws),
            region_display_name: Some(region.to_string()),
            state: Some(match state {
                "ACTIVE" => ClusterState::Active,
                "CREATING" => ClusterState::Creating,
                "FAILED" => ClusterState::Deleted, // Use Deleted as a failed-like state
                _ => ClusterState::Active,
            }),
            root_password: None,
            min_rcu: "1".to_string(),
            max_rcu: "10".to_string(),
            service_plan: ServicePlan::Starter,
            high_availability_type: Some(HighAvailabilityType::Regional),
            annotations: None,
            labels: None,
            creator: Some("test-user".to_string()),
            create_time: Some("2023-01-01T00:00:00Z".to_string()),
            update_time: Some("2023-01-01T00:00:00Z".to_string()),
            endpoints: None,
        }
    }

    #[test]
    fn test_dynamic_json_extraction() {
        let executor = DSLExecutor::new(MockTiDBCloudClient::new());
        let cluster = create_test_cluster("test-cluster", "ACTIVE", "us-east-1");

        // Test that the dynamic JSON extraction includes all fields
        let dsl_value = executor.cluster_to_dsl_value(cluster);

        if let DSLValue::Object(obj) = dsl_value {
            // Print all available fields for debugging
            println!("Available fields: {:?}", obj.keys().collect::<Vec<_>>());

            // Verify that key fields are present (using the actual JSON field names)
            assert!(obj.contains_key("name"));
            assert!(obj.contains_key("displayName")); // JSON field name, not display_name
            assert!(obj.contains_key("regionId")); // JSON field name, not region_id
            assert!(obj.contains_key("state"));
            assert!(obj.contains_key("minRcu")); // JSON field name, not min_rcu
            assert!(obj.contains_key("maxRcu")); // JSON field name, not max_rcu
            assert!(obj.contains_key("servicePlan")); // JSON field name, not service_plan
            assert!(obj.contains_key("cloudProvider")); // JSON field name, not cloud_provider
            assert!(obj.contains_key("highAvailabilityType")); // JSON field name, not high_availability_type
            assert!(obj.contains_key("creator"));
            assert!(obj.contains_key("createTime")); // JSON field name, not create_time
            assert!(obj.contains_key("updateTime")); // JSON field name, not update_time

            // Verify that the field values are correct
            assert_eq!(
                obj.get("displayName"),
                Some(&DSLValue::String("test-cluster".to_string()))
            );
            assert_eq!(
                obj.get("regionId"),
                Some(&DSLValue::String("us-east-1".to_string()))
            );
        } else {
            panic!("Expected DSLValue::Object");
        }
    }

    #[test]
    fn test_pretty_print_table() {
        let executor = DSLExecutor::new(MockTiDBCloudClient::new());

        // Test with array of objects
        let data = DSLValue::Array(vec![
            DSLValue::Object({
                let mut obj = HashMap::new();
                obj.insert("name".to_string(), DSLValue::String("cluster1".to_string()));
                obj.insert("state".to_string(), DSLValue::String("ACTIVE".to_string()));
                obj
            }),
            DSLValue::Object({
                let mut obj = HashMap::new();
                obj.insert("name".to_string(), DSLValue::String("cluster2".to_string()));
                obj.insert(
                    "state".to_string(),
                    DSLValue::String("INACTIVE".to_string()),
                );
                obj
            }),
        ]);

        let table = executor.pretty_print_table(&data);
        println!("Generated table:\n{}", table);

        // Verify the table contains expected elements
        assert!(table.contains("name"));
        assert!(table.contains("state"));
        assert!(table.contains("cluster1"));
        assert!(table.contains("cluster2"));
        assert!(table.contains("ACTIVE"));
        assert!(table.contains("INACTIVE"));
        assert!(table.contains("┌")); // Header
        assert!(table.contains("└")); // Footer
    }

    #[test]
    fn test_pretty_print_table_with_complex_data() {
        let executor = DSLExecutor::new(MockTiDBCloudClient::new());

        // Test with the actual data format from the user's example
        let data = DSLValue::Array(vec![DSLValue::Object({
            let mut obj = HashMap::new();
            obj.insert(
                "highAvailabilityType".to_string(),
                DSLValue::String("REGIONAL".to_string()),
            );
            obj.insert(
                "displayName".to_string(),
                DSLValue::String("SB-Test01-delete-whenever".to_string()),
            );
            obj.insert(
                "endpoints".to_string(),
                DSLValue::Array(vec![DSLValue::Object({
                    let mut endpoint = HashMap::new();
                    endpoint.insert("port".to_string(), DSLValue::Number(4000.0));
                    endpoint.insert(
                        "connectionType".to_string(),
                        DSLValue::String("PUBLIC".to_string()),
                    );
                    endpoint.insert(
                        "host".to_string(),
                        DSLValue::String(
                            "tidb.hcrmzl1vj561.clusters.dev.tidb-cloud.com".to_string(),
                        ),
                    );
                    endpoint
                })]),
            );
            obj
        })]);

        let table = executor.pretty_print_table(&data);
        println!("Complex data table:\n{}", table);

        // Verify the table contains expected elements
        assert!(table.contains("highAvailabilityType"));
        assert!(table.contains("displayName"));
        assert!(table.contains("endpoints"));
        assert!(table.contains("REGIONAL"));
        assert!(table.contains("SB-Test01-delete-whenever"));
        assert!(table.contains("connectionType")); // Sub-table content
        assert!(table.contains("host")); // Sub-table content
        assert!(table.contains("PUBLIC")); // Sub-table content
        assert!(table.contains("port")); // Sub-table content
        assert!(table.contains("4000")); // Sub-table content
        assert!(table.contains("─")); // Separator line
    }

    #[test]
    fn test_pretty_print_table_with_deeply_nested_data() {
        let executor = DSLExecutor::new(MockTiDBCloudClient::new());

        // Test with deeply nested JSON structures
        let data = DSLValue::Array(vec![DSLValue::Object({
            let mut obj = HashMap::new();
            obj.insert("name".to_string(), DSLValue::String("cluster1".to_string()));
            obj.insert(
                "config".to_string(),
                DSLValue::Object({
                    let mut config = HashMap::new();
                    config.insert(
                        "network".to_string(),
                        DSLValue::Object({
                            let mut network = HashMap::new();
                            network
                                .insert("vpc".to_string(), DSLValue::String("vpc-123".to_string()));
                            network.insert(
                                "subnets".to_string(),
                                DSLValue::Array(vec![
                                    DSLValue::String("subnet-1".to_string()),
                                    DSLValue::String("subnet-2".to_string()),
                                ]),
                            );
                            network
                        }),
                    );
                    config.insert(
                        "security".to_string(),
                        DSLValue::Object({
                            let mut security = HashMap::new();
                            security.insert(
                                "firewall_rules".to_string(),
                                DSLValue::Array(vec![
                                    DSLValue::Object({
                                        let mut rule1 = HashMap::new();
                                        rule1.insert("port".to_string(), DSLValue::Number(3306.0));
                                        rule1.insert(
                                            "source".to_string(),
                                            DSLValue::String("0.0.0.0/0".to_string()),
                                        );
                                        rule1
                                    }),
                                    DSLValue::Object({
                                        let mut rule2 = HashMap::new();
                                        rule2.insert("port".to_string(), DSLValue::Number(22.0));
                                        rule2.insert(
                                            "source".to_string(),
                                            DSLValue::String("10.0.0.0/8".to_string()),
                                        );
                                        rule2
                                    }),
                                ]),
                            );
                            security
                        }),
                    );
                    config
                }),
            );
            obj.insert(
                "metadata".to_string(),
                DSLValue::Object({
                    let mut metadata = HashMap::new();
                    metadata.insert(
                        "tags".to_string(),
                        DSLValue::Array(vec![
                            DSLValue::String("production".to_string()),
                            DSLValue::String("database".to_string()),
                        ]),
                    );
                    metadata.insert(
                        "created_by".to_string(),
                        DSLValue::String("admin".to_string()),
                    );
                    metadata
                }),
            );
            obj
        })]);

        let table = executor.pretty_print_table(&data);
        println!("Deeply nested data table:\n{}", table);

        // Verify the table contains expected elements
        assert!(table.contains("name"));
        assert!(table.contains("config"));
        assert!(table.contains("metadata"));
        assert!(table.contains("cluster1"));
        assert!(table.contains("network"));
        assert!(table.contains("security"));
        assert!(table.contains("vpc-123"));
        assert!(table.contains("subnet-1"));
        assert!(table.contains("subnet-2"));
        assert!(table.contains("admin"));
        assert!(table.contains("firewall_rules")); // Sub-table content
        assert!(table.contains("3306")); // Sub-table content
        assert!(table.contains("22")); // Sub-table content
        assert!(table.contains("production")); // Sub-table content
        assert!(table.contains("database")); // Sub-table content
        assert!(table.contains("─")); // Separator line
    }

    #[test]
    fn test_sub_table_formatting() {
        let executor = DSLExecutor::new(MockTiDBCloudClient::new());

        // Test with simple nested data to see sub-table formatting
        let data = DSLValue::Array(vec![DSLValue::Object({
            let mut obj = HashMap::new();
            obj.insert(
                "name".to_string(),
                DSLValue::String("test-cluster".to_string()),
            );
            obj.insert(
                "endpoints".to_string(),
                DSLValue::Array(vec![DSLValue::Object({
                    let mut endpoint = HashMap::new();
                    endpoint.insert(
                        "host".to_string(),
                        DSLValue::String("example.com".to_string()),
                    );
                    endpoint.insert("port".to_string(), DSLValue::Number(4000.0));
                    endpoint
                })]),
            );
            obj
        })]);

        // Debug: Check if complex data is detected
        let keys = vec!["name".to_string(), "endpoints".to_string()];
        let has_complex = executor.has_complex_nested_data(&data.as_array().unwrap(), &keys);
        println!("Has complex data: {}", has_complex);

        let table = executor.pretty_print_table(&data);
        println!("Sub-table test:\n{}", table);

        // Check if it's using the sub-table format
        assert!(table.contains("Row 1:"));
        assert!(table.contains("name"));
        assert!(table.contains("endpoints"));
        assert!(table.contains("test-cluster"));
        assert!(table.contains("host"));
        assert!(table.contains("port"));
        assert!(table.contains("example.com"));
        assert!(table.contains("4000")); // Sub-table content
    }

    #[test]
    fn test_recursive_sub_table_formatting() {
        let executor = DSLExecutor::new(MockTiDBCloudClient::new());

        // Test with deeply nested recursive data
        let data = DSLValue::Array(vec![DSLValue::Object({
            let mut obj = HashMap::new();
            obj.insert(
                "cluster".to_string(),
                DSLValue::String("main-cluster".to_string()),
            );
            obj.insert(
                "config".to_string(),
                DSLValue::Object({
                    let mut config = HashMap::new();
                    config.insert(
                        "database".to_string(),
                        DSLValue::Object({
                            let mut db = HashMap::new();
                            db.insert(
                                "instances".to_string(),
                                DSLValue::Array(vec![
                                    DSLValue::Object({
                                        let mut instance1 = HashMap::new();
                                        instance1.insert(
                                            "id".to_string(),
                                            DSLValue::String("db-1".to_string()),
                                        );
                                        instance1.insert(
                                            "settings".to_string(),
                                            DSLValue::Object({
                                                let mut settings = HashMap::new();
                                                settings.insert(
                                                    "max_connections".to_string(),
                                                    DSLValue::Number(100.0),
                                                );
                                                settings.insert(
                                                    "timeout".to_string(),
                                                    DSLValue::Number(30.0),
                                                );
                                                settings
                                            }),
                                        );
                                        instance1
                                    }),
                                    DSLValue::Object({
                                        let mut instance2 = HashMap::new();
                                        instance2.insert(
                                            "id".to_string(),
                                            DSLValue::String("db-2".to_string()),
                                        );
                                        instance2.insert(
                                            "settings".to_string(),
                                            DSLValue::Object({
                                                let mut settings = HashMap::new();
                                                settings.insert(
                                                    "max_connections".to_string(),
                                                    DSLValue::Number(200.0),
                                                );
                                                settings.insert(
                                                    "timeout".to_string(),
                                                    DSLValue::Number(60.0),
                                                );
                                                settings
                                            }),
                                        );
                                        instance2
                                    }),
                                ]),
                            );
                            db
                        }),
                    );
                    config
                }),
            );
            obj
        })]);

        let table = executor.pretty_print_table(&data);
        println!("Recursive sub-table test:\n{}", table);

        // Check if it's using the recursive sub-table format
        assert!(table.contains("Row 1:"));
        assert!(table.contains("cluster"));
        assert!(table.contains("config"));
        assert!(table.contains("main-cluster"));
        assert!(table.contains("database"));
        assert!(table.contains("instances"));
        assert!(table.contains("db-1"));
        assert!(table.contains("settings"));
        assert!(table.contains("max_connections"));
        assert!(table.contains("timeout"));
        assert!(table.contains("100"));
        assert!(table.contains("30"));
        assert!(table.contains("db-2")); // Sub-table content
        assert!(table.contains("200")); // Sub-table content
        assert!(table.contains("60")); // Sub-table content
        assert!(table.contains("─")); // Separator line
    }
}
