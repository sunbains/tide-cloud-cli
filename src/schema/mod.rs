use crate::tidb_cloud::models::{Backup, Tidb};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Trait for types that can provide field values dynamically
pub trait FieldAccessor {
    /// Get the logical type name for this object
    fn object_type(&self) -> &'static str;

    /// Get a field value by canonical field name using schema lookup
    fn get_field_value(&self, field_name: &str) -> Option<String>;

    /// Get all field values as a HashMap using schema-defined fields
    fn get_all_field_values(&self) -> HashMap<String, String>;

    /// Check if a field exists for this object type
    fn has_field(&self, field_name: &str) -> bool {
        crate::schema::SCHEMA.is_valid_field(self.object_type(), field_name)
    }

    /// Get the JSON representation of a field for API responses
    fn get_field_json_name(&self, field_name: &str) -> Option<String> {
        crate::schema::SCHEMA.get_json_name(self.object_type(), field_name)
    }
}

/// Represents a field type in the schema
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum FieldType {
    String {
        default: Option<String>,
    },
    Integer {
        default: Option<i64>,
    },
    Float {
        default: Option<f64>,
    },
    Boolean {
        default: Option<bool>,
    },
    Enum {
        values: Vec<String>,
        default: Option<String>,
    },
    Object {
        object_type: String,
        default: Option<String>, // JSON string representation
    },
    Array {
        element_type: Box<FieldType>,
        default: Option<Vec<String>>, // Array of string representations
    },
    Optional {
        inner_type: Box<FieldType>,
        default: Option<String>, // String representation of the inner type
    },
}

impl FieldType {
    /// Get the default value as a string representation
    pub fn get_default_value(&self) -> Option<String> {
        match self {
            FieldType::String { default } => default.clone(),
            FieldType::Integer { default } => default.map(|v| v.to_string()),
            FieldType::Float { default } => default.map(|v| v.to_string()),
            FieldType::Boolean { default } => default.map(|v| v.to_string()),
            FieldType::Enum { default, .. } => default.clone(),
            FieldType::Object { default, .. } => default.clone(),
            FieldType::Array { default, .. } => default.as_ref().map(|v| format!("{v:?}")),
            FieldType::Optional { default, .. } => default.clone(),
        }
    }

    /// Get enum values if this is an enum type
    pub fn get_enum_values(&self) -> Option<&Vec<String>> {
        match self {
            FieldType::Enum { values, .. } => Some(values),
            _ => None,
        }
    }

    /// Check if this is an enum type
    pub fn is_enum(&self) -> bool {
        matches!(self, FieldType::Enum { .. })
    }

    /// Get the inner type if this is an Optional type
    pub fn get_inner_type(&self) -> Option<&FieldType> {
        match self {
            FieldType::Optional { inner_type, .. } => Some(inner_type),
            _ => None,
        }
    }

    /// Get the actual type (unwrap Optional if needed)
    pub fn get_actual_type(&self) -> &FieldType {
        match self {
            FieldType::Optional { inner_type, .. } => inner_type.get_actual_type(),
            _ => self,
        }
    }
}

/// Represents a field definition in the schema
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldDefinition {
    pub name: String,
    pub json_name: String, // The name used in JSON (camelCase)
    pub field_type: FieldType,
    pub description: Option<String>,
    pub is_required: bool,
    pub is_filterable: bool,      // Can be used in WHERE clauses
    pub is_selectable: bool,      // Can be used in SELECT clauses
    pub is_settable: bool,        // Can be set during creation/update
    pub is_creatable: bool,       // Can be set during cluster creation
    pub aliases: Vec<String>,     // Alternative names for the field
    pub dsl_aliases: Vec<String>, // DSL parameter names that map to this field
}

/// Represents an object type in the schema
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectSchema {
    pub name: String,
    pub fields: HashMap<String, FieldDefinition>,
    pub description: Option<String>,
}

/// Global schema registry that acts as a data dictionary
#[derive(Debug, Clone)]
pub struct SchemaRegistry {
    objects: HashMap<String, ObjectSchema>,
}

impl SchemaRegistry {
    /// Create a new schema registry
    pub fn new() -> Self {
        let mut registry = Self {
            objects: HashMap::new(),
        };

        // Register all known object types
        registry.register_tidb_schema();
        registry.register_backup_schema();

        registry
    }

    /// Get a field definition by object type and field name
    pub fn get_field(&self, object_type: &str, field_name: &str) -> Option<&FieldDefinition> {
        self.objects.get(object_type).and_then(|schema| {
            // Try exact match first
            schema
                .fields
                .get(field_name)
                .or_else(|| {
                    // Try JSON name match
                    schema.fields.values().find(|f| f.json_name == field_name)
                })
                .or_else(|| {
                    // Try alias match
                    schema
                        .fields
                        .values()
                        .find(|f| f.aliases.contains(&field_name.to_string()))
                })
        })
    }

    /// Get all field names for an object type (including aliases)
    pub fn get_field_names(&self, object_type: &str) -> Vec<String> {
        self.objects
            .get(object_type)
            .map(|schema| {
                let mut names = Vec::new();
                for field in schema.fields.values() {
                    names.push(field.name.clone());
                    names.push(field.json_name.clone());
                    names.extend(field.aliases.clone());
                }
                names
            })
            .unwrap_or_default()
    }

    /// Get all filterable field names for an object type
    pub fn get_filterable_fields(&self, object_type: &str) -> Vec<String> {
        self.objects
            .get(object_type)
            .map(|schema| {
                schema
                    .fields
                    .values()
                    .filter(|f| f.is_filterable)
                    .flat_map(|f| {
                        let mut names = vec![f.name.clone(), f.json_name.clone()];
                        names.extend(f.aliases.clone());
                        names
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get all selectable field names for an object type
    pub fn get_selectable_fields(&self, object_type: &str) -> Vec<String> {
        self.objects
            .get(object_type)
            .map(|schema| {
                schema
                    .fields
                    .values()
                    .filter(|f| f.is_selectable)
                    .flat_map(|f| {
                        let mut names = vec![f.name.clone(), f.json_name.clone()];
                        names.extend(f.aliases.clone());
                        names
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Check if a field is valid for an object type
    pub fn is_valid_field(&self, object_type: &str, field_name: &str) -> bool {
        self.get_field(object_type, field_name).is_some()
    }

    /// Check if a field is filterable for an object type
    pub fn is_filterable_field(&self, object_type: &str, field_name: &str) -> bool {
        self.get_field(object_type, field_name)
            .map(|f| f.is_filterable)
            .unwrap_or(false)
    }

    /// Check if a field is selectable for an object type
    pub fn is_selectable_field(&self, object_type: &str, field_name: &str) -> bool {
        self.get_field(object_type, field_name)
            .map(|f| f.is_selectable)
            .unwrap_or(false)
    }

    /// Get the JSON name for a field
    pub fn get_json_name(&self, object_type: &str, field_name: &str) -> Option<String> {
        self.get_field(object_type, field_name)
            .map(|f| f.json_name.clone())
    }

    /// Get the canonical field name (snake_case) for a field
    pub fn get_canonical_name(&self, object_type: &str, field_name: &str) -> Option<String> {
        self.get_field(object_type, field_name)
            .map(|f| f.name.clone())
    }

    /// Get all creatable field names for an object type
    pub fn get_creatable_fields(&self, object_type: &str) -> Vec<String> {
        self.objects
            .get(object_type)
            .map(|schema| {
                schema
                    .fields
                    .values()
                    .filter(|f| f.is_creatable)
                    .flat_map(|f| {
                        let mut names = vec![f.name.clone(), f.json_name.clone()];
                        names.extend(f.dsl_aliases.clone());
                        names
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get all settable field names for an object type
    pub fn get_settable_fields(&self, object_type: &str) -> Vec<String> {
        self.objects
            .get(object_type)
            .map(|schema| {
                schema
                    .fields
                    .values()
                    .filter(|f| f.is_settable)
                    .flat_map(|f| {
                        let mut names = vec![f.name.clone(), f.json_name.clone()];
                        names.extend(f.dsl_aliases.clone());
                        names
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Check if a field is creatable for an object type
    pub fn is_creatable_field(&self, object_type: &str, field_name: &str) -> bool {
        self.get_field(object_type, field_name)
            .map(|f| f.is_creatable)
            .unwrap_or(false)
    }

    /// Check if a field is settable for an object type
    pub fn is_settable_field(&self, object_type: &str, field_name: &str) -> bool {
        self.get_field(object_type, field_name)
            .map(|f| f.is_settable)
            .unwrap_or(false)
    }

    /// Get the DSL parameter mapping for a field
    pub fn get_dsl_parameter_mapping(&self, object_type: &str) -> HashMap<String, String> {
        self.objects
            .get(object_type)
            .map(|schema| {
                let mut mapping = HashMap::new();
                for field in schema.fields.values() {
                    for dsl_alias in &field.dsl_aliases {
                        mapping.insert(dsl_alias.clone(), field.name.clone());
                    }
                }
                mapping
            })
            .unwrap_or_default()
    }

    /// Get the canonical field name for a DSL parameter
    pub fn get_canonical_field_for_dsl_param(
        &self,
        object_type: &str,
        dsl_param: &str,
    ) -> Option<String> {
        self.objects.get(object_type).and_then(|schema| {
            schema
                .fields
                .values()
                .find(|f| f.dsl_aliases.contains(&dsl_param.to_string()))
                .map(|f| f.name.clone())
        })
    }

    /// Get the default value for a field
    pub fn get_field_default_value(&self, object_type: &str, field_name: &str) -> Option<String> {
        self.get_field(object_type, field_name)
            .and_then(|field| field.field_type.get_default_value())
    }

    /// Get enum values for a field
    pub fn get_field_enum_values(
        &self,
        object_type: &str,
        field_name: &str,
    ) -> Option<Vec<String>> {
        self.get_field(object_type, field_name)
            .and_then(|field| field.field_type.get_enum_values())
            .cloned()
    }

    /// Check if a field is an enum type
    pub fn is_field_enum(&self, object_type: &str, field_name: &str) -> bool {
        self.get_field(object_type, field_name)
            .map(|field| field.field_type.is_enum())
            .unwrap_or(false)
    }

    /// Get object schema by name
    pub fn get_object_schema(&self, object_type: &str) -> Option<&ObjectSchema> {
        self.objects.get(object_type)
    }

    /// Convert a string value to the appropriate enum type for a field
    pub fn convert_string_to_enum_value(
        &self,
        object_type: &str,
        field_name: &str,
        value: &str,
    ) -> Option<String> {
        self.get_field(object_type, field_name).and_then(|field| {
            // Get the actual field type, unwrapping Optional if needed
            let field_type = field.field_type.get_actual_type();

            if let FieldType::Enum { values, .. } = field_type {
                // Check if the value matches any of the enum values (case-insensitive)
                values
                    .iter()
                    .find(|v| v.to_uppercase() == value.to_uppercase())
                    .cloned()
            } else {
                None
            }
        })
    }

    /// Validate if a string value is a valid enum value for a field
    pub fn is_valid_enum_value(&self, object_type: &str, field_name: &str, value: &str) -> bool {
        self.convert_string_to_enum_value(object_type, field_name, value)
            .is_some()
    }

    /// Convert string to ServicePlan enum using schema
    pub fn string_to_service_plan(
        &self,
        value: &str,
    ) -> Option<crate::tidb_cloud::models::ServicePlan> {
        use crate::tidb_cloud::models::ServicePlan;

        let normalized_value = self.convert_string_to_enum_value("Tidb", "service_plan", value)?;
        match normalized_value.to_uppercase().as_str() {
            "STARTER" => Some(ServicePlan::Starter),
            "ESSENTIAL" => Some(ServicePlan::Essential),
            "PREMIUM" => Some(ServicePlan::Premium),
            "BYOC" => Some(ServicePlan::BYOC),
            _ => None,
        }
    }

    /// Convert string to ClusterState enum using schema
    pub fn string_to_cluster_state(
        &self,
        value: &str,
    ) -> Option<crate::tidb_cloud::models::ClusterState> {
        use crate::tidb_cloud::models::ClusterState;

        let normalized_value = self.convert_string_to_enum_value("Tidb", "state", value)?;
        match normalized_value.to_uppercase().as_str() {
            "ACTIVE" => Some(ClusterState::Active),
            "CREATING" => Some(ClusterState::Creating),
            "DELETING" => Some(ClusterState::Deleting),
            "RESTORING" => Some(ClusterState::Restoring),
            "MAINTENANCE" => Some(ClusterState::Maintenance),
            "DELETED" => Some(ClusterState::Deleted),
            "INACTIVE" => Some(ClusterState::Inactive),
            "UPGRADING" => Some(ClusterState::Upgrading),
            "IMPORTING" => Some(ClusterState::Importing),
            "MODIFYING" => Some(ClusterState::Modifying),
            "PAUSING" => Some(ClusterState::Pausing),
            "PAUSED" => Some(ClusterState::Paused),
            "RESUMING" => Some(ClusterState::Resuming),
            _ => None,
        }
    }

    /// Register the Tidb object schema
    fn register_tidb_schema(&mut self) {
        let mut fields = HashMap::new();

        fields.insert(
            "name".to_string(),
            FieldDefinition {
                name: "name".to_string(),
                json_name: "name".to_string(),
                field_type: FieldType::Optional {
                    inner_type: Box::new(FieldType::String { default: None }),
                    default: None,
                },
                description: Some("Cluster name".to_string()),
                is_required: false,
                is_filterable: true,
                is_selectable: true,
                is_settable: false,
                is_creatable: false,
                aliases: vec![],
                dsl_aliases: vec![],
            },
        );

        fields.insert(
            "tidb_id".to_string(),
            FieldDefinition {
                name: "tidb_id".to_string(),
                json_name: "tidbId".to_string(),
                field_type: FieldType::Optional {
                    inner_type: Box::new(FieldType::String { default: None }),
                    default: None,
                },
                description: Some("Cluster ID".to_string()),
                is_required: false,
                is_filterable: true,
                is_selectable: true,
                is_settable: false,
                is_creatable: false,
                aliases: vec![],
                dsl_aliases: vec![],
            },
        );

        fields.insert(
            "display_name".to_string(),
            FieldDefinition {
                name: "display_name".to_string(),
                json_name: "displayName".to_string(),
                field_type: FieldType::String { default: None },
                description: Some("Display name for the cluster".to_string()),
                is_required: true,
                is_filterable: true,
                is_selectable: true,
                is_settable: true,
                is_creatable: true,
                aliases: vec![],
                dsl_aliases: vec!["name".to_string()],
            },
        );

        fields.insert(
            "region_id".to_string(),
            FieldDefinition {
                name: "region_id".to_string(),
                json_name: "regionId".to_string(),
                field_type: FieldType::String { default: None },
                description: Some("Region ID".to_string()),
                is_required: true,
                is_filterable: true,
                is_selectable: true,
                is_settable: true,
                is_creatable: true,
                aliases: vec!["region".to_string()],
                dsl_aliases: vec!["region".to_string()],
            },
        );

        fields.insert(
            "cloud_provider".to_string(),
            FieldDefinition {
                name: "cloud_provider".to_string(),
                json_name: "cloudProvider".to_string(),
                field_type: FieldType::Optional {
                    inner_type: Box::new(FieldType::Enum {
                        values: vec![
                            "aws".to_string(),
                            "gcp".to_string(),
                            "azure".to_string(),
                            "alicloud".to_string(),
                        ],
                        default: None,
                    }),
                    default: None,
                },
                description: Some("Cloud provider".to_string()),
                is_required: false,
                is_filterable: true,
                is_selectable: true,
                is_settable: false,
                is_creatable: false,
                aliases: vec![],
                dsl_aliases: vec![],
            },
        );

        fields.insert(
            "state".to_string(),
            FieldDefinition {
                name: "state".to_string(),
                json_name: "state".to_string(),
                field_type: FieldType::Optional {
                    inner_type: Box::new(FieldType::Enum {
                        values: vec![
                            "CREATING".to_string(),
                            "DELETING".to_string(),
                            "ACTIVE".to_string(),
                            "RESTORING".to_string(),
                            "MAINTENANCE".to_string(),
                            "DELETED".to_string(),
                            "INACTIVE".to_string(),
                            "UPGRADING".to_string(),
                            "IMPORTING".to_string(),
                            "MODIFYING".to_string(),
                            "PAUSING".to_string(),
                            "PAUSED".to_string(),
                            "RESUMING".to_string(),
                        ],
                        default: None,
                    }),
                    default: None,
                },
                description: Some("Cluster state".to_string()),
                is_required: false,
                is_filterable: true,
                is_selectable: true,
                is_settable: false,
                is_creatable: false,
                aliases: vec![],
                dsl_aliases: vec![],
            },
        );

        fields.insert(
            "min_rcu".to_string(),
            FieldDefinition {
                name: "min_rcu".to_string(),
                json_name: "minRcu".to_string(),
                field_type: FieldType::String {
                    default: Some("1".to_string()),
                },
                description: Some("Minimum RCU".to_string()),
                is_required: false,
                is_filterable: true,
                is_selectable: true,
                is_settable: true,
                is_creatable: true,
                aliases: vec![],
                dsl_aliases: vec!["min_rcu".to_string()],
            },
        );

        fields.insert(
            "max_rcu".to_string(),
            FieldDefinition {
                name: "max_rcu".to_string(),
                json_name: "maxRcu".to_string(),
                field_type: FieldType::String {
                    default: Some("10".to_string()),
                },
                description: Some("Maximum RCU".to_string()),
                is_required: false,
                is_filterable: true,
                is_selectable: true,
                is_settable: true,
                is_creatable: true,
                aliases: vec![],
                dsl_aliases: vec!["max_rcu".to_string()],
            },
        );

        fields.insert(
            "service_plan".to_string(),
            FieldDefinition {
                name: "service_plan".to_string(),
                json_name: "servicePlan".to_string(),
                field_type: FieldType::Enum {
                    values: vec![
                        "STARTER".to_string(),
                        "ESSENTIAL".to_string(),
                        "PREMIUM".to_string(),
                        "BYOC".to_string(),
                    ],
                    default: Some("PREMIUM".to_string()),
                },
                description: Some("Service plan".to_string()),
                is_required: true,
                is_filterable: true,
                is_selectable: true,
                is_settable: true,
                is_creatable: true,
                aliases: vec![],
                dsl_aliases: vec!["plan".to_string(), "service_plan".to_string()],
            },
        );

        fields.insert(
            "create_time".to_string(),
            FieldDefinition {
                name: "create_time".to_string(),
                json_name: "createTime".to_string(),
                field_type: FieldType::Optional {
                    inner_type: Box::new(FieldType::String { default: None }),
                    default: None,
                },
                description: Some("Creation time".to_string()),
                is_required: false,
                is_filterable: true,
                is_selectable: true,
                is_settable: false,
                is_creatable: false,
                aliases: vec![],
                dsl_aliases: vec![],
            },
        );

        fields.insert(
            "update_time".to_string(),
            FieldDefinition {
                name: "update_time".to_string(),
                json_name: "updateTime".to_string(),
                field_type: FieldType::Optional {
                    inner_type: Box::new(FieldType::String { default: None }),
                    default: None,
                },
                description: Some("Last update time".to_string()),
                is_required: false,
                is_filterable: true,
                is_selectable: true,
                is_settable: false,
                is_creatable: false,
                aliases: vec![],
                dsl_aliases: vec![],
            },
        );

        // Add more fields as needed...

        self.objects.insert(
            "Tidb".to_string(),
            ObjectSchema {
                name: "Tidb".to_string(),
                fields,
                description: Some("TiDB cluster information".to_string()),
            },
        );
    }

    /// Register the Backup object schema
    fn register_backup_schema(&mut self) {
        let mut fields = HashMap::new();

        fields.insert(
            "id".to_string(),
            FieldDefinition {
                name: "id".to_string(),
                json_name: "id".to_string(),
                field_type: FieldType::Optional {
                    inner_type: Box::new(FieldType::String { default: None }),
                    default: None,
                },
                description: Some("Backup ID".to_string()),
                is_required: false,
                is_filterable: true,
                is_selectable: true,
                is_settable: false,
                is_creatable: false,
                aliases: vec![],
                dsl_aliases: vec![],
            },
        );

        fields.insert(
            "tidb_id".to_string(),
            FieldDefinition {
                name: "tidb_id".to_string(),
                json_name: "tidbId".to_string(),
                field_type: FieldType::Optional {
                    inner_type: Box::new(FieldType::String { default: None }),
                    default: None,
                },
                description: Some("Cluster ID".to_string()),
                is_required: false,
                is_filterable: true,
                is_selectable: true,
                is_settable: false,
                is_creatable: false,
                aliases: vec![],
                dsl_aliases: vec![],
            },
        );

        fields.insert(
            "display_name".to_string(),
            FieldDefinition {
                name: "display_name".to_string(),
                json_name: "displayName".to_string(),
                field_type: FieldType::Optional {
                    inner_type: Box::new(FieldType::String { default: None }),
                    default: None,
                },
                description: Some("Backup display name".to_string()),
                is_required: false,
                is_filterable: true,
                is_selectable: true,
                is_settable: false,
                is_creatable: false,
                aliases: vec![],
                dsl_aliases: vec![],
            },
        );

        fields.insert(
            "state".to_string(),
            FieldDefinition {
                name: "state".to_string(),
                json_name: "state".to_string(),
                field_type: FieldType::Optional {
                    inner_type: Box::new(FieldType::Enum {
                        values: vec![
                            "UNKNOWN".to_string(),
                            "PENDING".to_string(),
                            "RUNNING".to_string(),
                            "SUCCEEDED".to_string(),
                            "FAILED".to_string(),
                            "CANCELLED".to_string(),
                        ],
                        default: None,
                    }),
                    default: None,
                },
                description: Some("Backup state".to_string()),
                is_required: false,
                is_filterable: true,
                is_selectable: true,
                is_settable: false,
                is_creatable: false,
                aliases: vec![],
                dsl_aliases: vec![],
            },
        );

        fields.insert(
            "type".to_string(),
            FieldDefinition {
                name: "type".to_string(),
                json_name: "type".to_string(),
                field_type: FieldType::Optional {
                    inner_type: Box::new(FieldType::Enum {
                        values: vec!["SNAPSHOT".to_string(), "COPIED".to_string()],
                        default: None,
                    }),
                    default: None,
                },
                description: Some("Backup type".to_string()),
                is_required: false,
                is_filterable: true,
                is_selectable: true,
                is_settable: false,
                is_creatable: false,
                aliases: vec![],
                dsl_aliases: vec![],
            },
        );

        fields.insert(
            "size_bytes".to_string(),
            FieldDefinition {
                name: "size_bytes".to_string(),
                json_name: "sizeBytes".to_string(),
                field_type: FieldType::Optional {
                    inner_type: Box::new(FieldType::String { default: None }),
                    default: None,
                },
                description: Some("Backup size in bytes".to_string()),
                is_required: false,
                is_filterable: true,
                is_selectable: true,
                is_settable: false,
                is_creatable: false,
                aliases: vec![],
                dsl_aliases: vec![],
            },
        );

        fields.insert(
            "create_time".to_string(),
            FieldDefinition {
                name: "create_time".to_string(),
                json_name: "createTime".to_string(),
                field_type: FieldType::Optional {
                    inner_type: Box::new(FieldType::String { default: None }),
                    default: None,
                },
                description: Some("Creation time".to_string()),
                is_required: false,
                is_filterable: true,
                is_selectable: true,
                is_settable: false,
                is_creatable: false,
                aliases: vec![],
                dsl_aliases: vec![],
            },
        );

        // Add more fields as needed...

        self.objects.insert(
            "Backup".to_string(),
            ObjectSchema {
                name: "Backup".to_string(),
                fields,
                description: Some("Backup information".to_string()),
            },
        );
    }
}

impl Default for SchemaRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Field access patterns for different object types
#[derive(Debug, Clone)]
pub struct FieldAccessRegistry {
    tidb_access_patterns: HashMap<String, TidbFieldAccess>,
    backup_access_patterns: HashMap<String, BackupFieldAccess>,
}

/// How to access a field from a Tidb struct
#[derive(Debug, Clone)]
pub enum TidbFieldAccess {
    Direct(String),    // cluster.name
    Optional(String),  // cluster.name.clone()
    Formatted(String), // format!("{:?}", cluster.service_plan)
    Nested(String),    // cluster.annotations.get(key)
    Array(String),     // cluster.endpoints.get(index)
}

/// Field accessor function type for Tidb
pub type FieldAccessorFn = fn(&Tidb) -> Option<String>;

/// Field accessor function type for Backup
pub type BackupFieldAccessorFn = fn(&Backup) -> Option<String>;

/// Nested field accessor function type
pub type NestedFieldAccessorFn = fn(&Tidb, &[String]) -> Option<String>;

/// Array field accessor function type
pub type ArrayFieldAccessorFn = fn(&Tidb, &[String]) -> Option<String>;

/// Field accessor registry for dynamic field access
#[derive(Debug, Clone)]
pub struct FieldAccessorRegistry {
    accessors: HashMap<String, FieldAccessorFn>,
    backup_accessors: HashMap<String, BackupFieldAccessorFn>,
    nested_accessors: HashMap<String, NestedFieldAccessorFn>,
    array_accessors: HashMap<String, ArrayFieldAccessorFn>,
}

/// Parameter configuration for DSL commands
#[derive(Debug, Clone)]
pub struct ParameterConfig {
    pub name: String,
    pub default_value: Option<String>,
    pub allowed_values: Option<Vec<String>>,
    pub required: bool,
    pub field_mapping: Option<String>, // Maps to struct field name
}

/// Command configuration for DSL commands
#[derive(Debug, Clone)]
pub struct CommandConfig {
    pub name: String,
    pub parameters: HashMap<String, ParameterConfig>,
}

impl FieldAccessorRegistry {
    /// Get field value using dynamic field access - NO hardcoded field names!
    pub fn get_field_value(&self, cluster: &Tidb, field_name: &str) -> Option<String> {
        self.accessors
            .get(field_name)
            .and_then(|accessor| accessor(cluster))
    }

    /// Get nested field value using dynamic field access - NO hardcoded field names!
    pub fn get_nested_field_value(
        &self,
        cluster: &Tidb,
        field_name: &str,
        parts: &[String],
    ) -> Option<String> {
        self.nested_accessors
            .get(field_name)
            .and_then(|accessor| accessor(cluster, parts))
    }

    /// Get array field value using dynamic field access - NO hardcoded field names!
    pub fn get_array_field_value(
        &self,
        cluster: &Tidb,
        field_name: &str,
        parts: &[String],
    ) -> Option<String> {
        self.array_accessors
            .get(field_name)
            .and_then(|accessor| accessor(cluster, parts))
    }

    /// Check if a field is a nested field - NO hardcoded field names!
    pub fn is_nested_field(&self, field_name: &str) -> bool {
        self.nested_accessors.contains_key(field_name)
    }

    /// Check if a field is an array field - NO hardcoded field names!
    pub fn is_array_field(&self, field_name: &str) -> bool {
        self.array_accessors.contains_key(field_name)
    }

    /// Get nested field names - NO hardcoded field names!
    pub fn get_nested_field_names(&self) -> Vec<String> {
        self.nested_accessors.keys().cloned().collect()
    }

    /// Get array field names - NO hardcoded field names!
    pub fn get_array_field_names(&self) -> Vec<String> {
        self.array_accessors.keys().cloned().collect()
    }

    /// Get Backup field value using dynamic field access - NO hardcoded field names!
    pub fn get_backup_field_value(&self, backup: &Backup, field_name: &str) -> Option<String> {
        self.backup_accessors
            .get(field_name)
            .and_then(|accessor| accessor(backup))
    }
}

/// Helper functions for command configuration
pub fn get_command_config(command_name: &str) -> Option<&'static CommandConfig> {
    crate::schema::COMMAND_CONFIG.get(command_name)
}

pub fn get_parameter_config(
    command_name: &str,
    param_name: &str,
) -> Option<&'static ParameterConfig> {
    get_command_config(command_name).and_then(|config| config.parameters.get(param_name))
}

pub fn get_parameter_default(command_name: &str, param_name: &str) -> Option<String> {
    get_parameter_config(command_name, param_name).and_then(|config| config.default_value.clone())
}

pub fn get_parameter_allowed_values(command_name: &str, param_name: &str) -> Option<Vec<String>> {
    get_parameter_config(command_name, param_name).and_then(|config| config.allowed_values.clone())
}

pub fn get_parameter_field_mapping(command_name: &str, param_name: &str) -> Option<String> {
    get_parameter_config(command_name, param_name).and_then(|config| config.field_mapping.clone())
}

/// Get nested parameter default value
pub fn get_nested_parameter_default(command_name: &str, nested_param_name: &str) -> Option<String> {
    get_parameter_config(command_name, nested_param_name)
        .and_then(|config| config.default_value.clone())
}

/// How to access a field from a Backup struct
#[derive(Debug, Clone)]
pub enum BackupFieldAccess {
    Direct(String),    // backup.id
    Optional(String),  // backup.id.clone()
    Formatted(String), // format!("{:?}", backup.state)
}

impl Default for FieldAccessRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl FieldAccessRegistry {
    pub fn new() -> Self {
        let mut tidb_patterns = HashMap::new();
        let mut backup_patterns = HashMap::new();

        // Tidb field access patterns
        tidb_patterns.insert(
            "name".to_string(),
            TidbFieldAccess::Optional("name".to_string()),
        );
        tidb_patterns.insert(
            "tidb_id".to_string(),
            TidbFieldAccess::Optional("tidb_id".to_string()),
        );
        tidb_patterns.insert(
            "display_name".to_string(),
            TidbFieldAccess::Direct("display_name".to_string()),
        );
        tidb_patterns.insert(
            "region_id".to_string(),
            TidbFieldAccess::Direct("region_id".to_string()),
        );
        tidb_patterns.insert(
            "cloud_provider".to_string(),
            TidbFieldAccess::Formatted("cloud_provider".to_string()),
        );
        tidb_patterns.insert(
            "region_display_name".to_string(),
            TidbFieldAccess::Optional("region_display_name".to_string()),
        );
        tidb_patterns.insert(
            "state".to_string(),
            TidbFieldAccess::Formatted("state".to_string()),
        );
        tidb_patterns.insert(
            "root_password".to_string(),
            TidbFieldAccess::Optional("root_password".to_string()),
        );
        tidb_patterns.insert(
            "min_rcu".to_string(),
            TidbFieldAccess::Direct("min_rcu".to_string()),
        );
        tidb_patterns.insert(
            "max_rcu".to_string(),
            TidbFieldAccess::Direct("max_rcu".to_string()),
        );
        tidb_patterns.insert(
            "service_plan".to_string(),
            TidbFieldAccess::Formatted("service_plan".to_string()),
        );
        tidb_patterns.insert(
            "high_availability_type".to_string(),
            TidbFieldAccess::Formatted("high_availability_type".to_string()),
        );
        tidb_patterns.insert(
            "creator".to_string(),
            TidbFieldAccess::Optional("creator".to_string()),
        );
        tidb_patterns.insert(
            "create_time".to_string(),
            TidbFieldAccess::Optional("create_time".to_string()),
        );
        tidb_patterns.insert(
            "update_time".to_string(),
            TidbFieldAccess::Optional("update_time".to_string()),
        );
        tidb_patterns.insert(
            "annotations".to_string(),
            TidbFieldAccess::Nested("annotations".to_string()),
        );
        tidb_patterns.insert(
            "labels".to_string(),
            TidbFieldAccess::Nested("labels".to_string()),
        );
        tidb_patterns.insert(
            "endpoints".to_string(),
            TidbFieldAccess::Array("endpoints".to_string()),
        );

        // Backup field access patterns
        backup_patterns.insert(
            "id".to_string(),
            BackupFieldAccess::Optional("id".to_string()),
        );
        backup_patterns.insert(
            "tidb_id".to_string(),
            BackupFieldAccess::Optional("tidb_id".to_string()),
        );
        backup_patterns.insert(
            "display_name".to_string(),
            BackupFieldAccess::Optional("display_name".to_string()),
        );
        backup_patterns.insert(
            "description".to_string(),
            BackupFieldAccess::Optional("description".to_string()),
        );
        backup_patterns.insert(
            "backup_ts".to_string(),
            BackupFieldAccess::Optional("backup_ts".to_string()),
        );
        backup_patterns.insert(
            "create_time".to_string(),
            BackupFieldAccess::Optional("create_time".to_string()),
        );
        backup_patterns.insert(
            "expiration_time".to_string(),
            BackupFieldAccess::Optional("expiration_time".to_string()),
        );
        backup_patterns.insert(
            "size_bytes".to_string(),
            BackupFieldAccess::Optional("size_bytes".to_string()),
        );
        backup_patterns.insert(
            "state".to_string(),
            BackupFieldAccess::Formatted("state".to_string()),
        );
        backup_patterns.insert(
            "type".to_string(),
            BackupFieldAccess::Formatted("type".to_string()),
        );
        backup_patterns.insert(
            "trigger_type".to_string(),
            BackupFieldAccess::Formatted("trigger_type".to_string()),
        );
        backup_patterns.insert(
            "organization_id".to_string(),
            BackupFieldAccess::Optional("organization_id".to_string()),
        );
        backup_patterns.insert(
            "region_id".to_string(),
            BackupFieldAccess::Optional("region_id".to_string()),
        );
        backup_patterns.insert(
            "service_plan".to_string(),
            BackupFieldAccess::Formatted("service_plan".to_string()),
        );

        Self {
            tidb_access_patterns: tidb_patterns,
            backup_access_patterns: backup_patterns,
        }
    }

    pub fn get_tidb_access_pattern(&self, field_name: &str) -> Option<&TidbFieldAccess> {
        self.tidb_access_patterns.get(field_name)
    }

    pub fn get_backup_access_pattern(&self, field_name: &str) -> Option<&BackupFieldAccess> {
        self.backup_access_patterns.get(field_name)
    }

    /// Get the canonical field name for a DSL parameter
    pub fn get_canonical_field_for_dsl_param(
        &self,
        object_type: &str,
        dsl_param: &str,
    ) -> Option<String> {
        match object_type {
            "Tidb" => {
                // Map DSL parameters to canonical field names
                match dsl_param {
                    "name" => Some("display_name".to_string()),
                    "region" => Some("region_id".to_string()),
                    "plan" | "service_plan" => Some("service_plan".to_string()),
                    _ => None,
                }
            }
            "Backup" => None,
            _ => None,
        }
    }

    /// Get the DSL parameter name for a canonical field
    pub fn get_dsl_param_for_canonical_field(
        &self,
        object_type: &str,
        canonical_field: &str,
    ) -> Option<String> {
        match object_type {
            "Tidb" => match canonical_field {
                "display_name" => Some("name".to_string()),
                "region_id" => Some("region".to_string()),
                "service_plan" => Some("plan".to_string()),
                _ => None,
            },
            "Backup" => None,
            _ => None,
        }
    }

    /// Get all DSL parameter names for an object type
    pub fn get_dsl_parameters(&self, object_type: &str) -> Vec<String> {
        match object_type {
            "Tidb" => vec![
                "name".to_string(),
                "region".to_string(),
                "plan".to_string(),
                "service_plan".to_string(),
            ],
            "Backup" => vec![],
            _ => vec![],
        }
    }
}

lazy_static::lazy_static! {
    /// Global schema instance
    pub static ref SCHEMA: SchemaRegistry = SchemaRegistry::new();

    /// Global field access registry
    pub static ref FIELD_ACCESS: FieldAccessRegistry = FieldAccessRegistry::new();

    /// Global command configuration registry
    pub static ref COMMAND_CONFIG: HashMap<String, CommandConfig> = {
        let mut configs = HashMap::new();

        // CREATE CLUSTER command configuration - NO hardcoded values!
        let mut create_cluster_params = HashMap::new();

        create_cluster_params.insert("name".to_string(), ParameterConfig {
            name: "name".to_string(),
            default_value: None,
            allowed_values: None,
            required: true,
            field_mapping: Some("display_name".to_string()),
        });

        create_cluster_params.insert("region".to_string(), ParameterConfig {
            name: "region".to_string(),
            default_value: None,
            allowed_values: None,
            required: true,
            field_mapping: Some("region_id".to_string()),
        });

        // Get defaults and enum values from schema - NO hardcoded values!
        let schema = crate::schema::SCHEMA.get_field("Tidb", "min_rcu");
        let min_rcu_default = schema.and_then(|f| f.field_type.get_default_value());
        create_cluster_params.insert("min_rcu".to_string(), ParameterConfig {
            name: "min_rcu".to_string(),
            default_value: min_rcu_default,
            allowed_values: None,
            required: false,
            field_mapping: Some("min_rcu".to_string()),
        });

        let schema = crate::schema::SCHEMA.get_field("Tidb", "max_rcu");
        let max_rcu_default = schema.and_then(|f| f.field_type.get_default_value());
        create_cluster_params.insert("max_rcu".to_string(), ParameterConfig {
            name: "max_rcu".to_string(),
            default_value: max_rcu_default,
            allowed_values: None,
            required: false,
            field_mapping: Some("max_rcu".to_string()),
        });

        let schema = crate::schema::SCHEMA.get_field("Tidb", "service_plan");
        let service_plan_default = schema.and_then(|f| f.field_type.get_default_value());
        let service_plan_values = schema.and_then(|f| f.field_type.get_enum_values()).cloned();
        create_cluster_params.insert("service_plan".to_string(), ParameterConfig {
            name: "service_plan".to_string(),
            default_value: service_plan_default,
            allowed_values: service_plan_values,
            required: false,
            field_mapping: Some("service_plan".to_string()),
        });

        create_cluster_params.insert("password".to_string(), ParameterConfig {
            name: "password".to_string(),
            default_value: None,
            allowed_values: None,
            required: false,
            field_mapping: Some("root_password".to_string()),
        });

        create_cluster_params.insert("public_connection".to_string(), ParameterConfig {
            name: "public_connection".to_string(),
            default_value: None,
            allowed_values: None,
            required: false,
            field_mapping: None, // Complex nested object
        });

        // Nested field configurations for public_connection
        create_cluster_params.insert("public_connection.enabled".to_string(), ParameterConfig {
            name: "enabled".to_string(),
            default_value: Some("false".to_string()),
            allowed_values: None,
            required: false,
            field_mapping: Some("enabled".to_string()),
        });

        create_cluster_params.insert("public_connection.ipAccessList".to_string(), ParameterConfig {
            name: "ipAccessList".to_string(),
            default_value: None,
            allowed_values: None,
            required: false,
            field_mapping: Some("ip_access_list".to_string()),
        });

        create_cluster_params.insert("public_connection.ipAccessList.cidrNotation".to_string(), ParameterConfig {
            name: "cidrNotation".to_string(),
            default_value: Some("0.0.0.0/0".to_string()),
            allowed_values: None,
            required: false,
            field_mapping: Some("cidr_notation".to_string()),
        });

        create_cluster_params.insert("public_connection.ipAccessList.description".to_string(), ParameterConfig {
            name: "description".to_string(),
            default_value: Some("Default access".to_string()),
            allowed_values: None,
            required: false,
            field_mapping: Some("description".to_string()),
        });

        configs.insert("CREATE_CLUSTER".to_string(), CommandConfig {
            name: "CREATE_CLUSTER".to_string(),
            parameters: create_cluster_params,
        });

        configs
    };

    /// Global field accessor registry for dynamic field access
    pub static ref FIELD_ACCESSORS: FieldAccessorRegistry = {
        let mut registry = FieldAccessorRegistry {
            accessors: HashMap::new(),
            backup_accessors: HashMap::new(),
            nested_accessors: HashMap::new(),
            array_accessors: HashMap::new(),
        };

        // Register field accessors - NO hardcoded field names in the executor!
        registry.accessors.insert("display_name".to_string(), |cluster| Some(cluster.display_name.clone()));
        registry.accessors.insert("region_id".to_string(), |cluster| Some(cluster.region_id.clone()));
        registry.accessors.insert("min_rcu".to_string(), |cluster| Some(cluster.min_rcu.clone()));
        registry.accessors.insert("max_rcu".to_string(), |cluster| Some(cluster.max_rcu.clone()));

        registry.accessors.insert("name".to_string(), |cluster| cluster.name.clone());
        registry.accessors.insert("tidb_id".to_string(), |cluster| cluster.tidb_id.clone());
        registry.accessors.insert("region_display_name".to_string(), |cluster| cluster.region_display_name.clone());
        registry.accessors.insert("root_password".to_string(), |cluster| cluster.root_password.clone());
        registry.accessors.insert("creator".to_string(), |cluster| cluster.creator.clone());
        registry.accessors.insert("create_time".to_string(), |cluster| cluster.create_time.clone());
        registry.accessors.insert("update_time".to_string(), |cluster| cluster.update_time.clone());

        registry.accessors.insert("cloud_provider".to_string(), |cluster| cluster.cloud_provider.as_ref().map(|p| format!("{p:?}")));
        registry.accessors.insert("state".to_string(), |cluster| cluster.state.as_ref().map(|s| format!("{s:?}")));
        registry.accessors.insert("service_plan".to_string(), |cluster| Some(format!("{:?}", cluster.service_plan)));
        registry.accessors.insert("high_availability_type".to_string(), |cluster| cluster.high_availability_type.as_ref().map(|h| format!("{h:?}")));

        // Register Backup field accessors - NO hardcoded field names!
        registry.backup_accessors.insert("id".to_string(), |backup| backup.id.clone());
        registry.backup_accessors.insert("tidb_id".to_string(), |backup| backup.tidb_id.clone());
        registry.backup_accessors.insert("display_name".to_string(), |backup| backup.display_name.clone());
        registry.backup_accessors.insert("description".to_string(), |backup| backup.description.clone());
        registry.backup_accessors.insert("backup_ts".to_string(), |backup| backup.backup_ts.clone());
        registry.backup_accessors.insert("create_time".to_string(), |backup| backup.create_time.clone());
        registry.backup_accessors.insert("expiration_time".to_string(), |backup| backup.expiration_time.clone());
        registry.backup_accessors.insert("size_bytes".to_string(), |backup| backup.size_bytes.clone());
        registry.backup_accessors.insert("organization_id".to_string(), |backup| backup.organization_id.clone());
        registry.backup_accessors.insert("region_id".to_string(), |backup| backup.region_id.clone());

        registry.backup_accessors.insert("state".to_string(), |backup| backup.state.as_ref().map(|s| format!("{s:?}")));
        registry.backup_accessors.insert("type".to_string(), |backup| backup.r#type.as_ref().map(|t| format!("{t:?}")));
        registry.backup_accessors.insert("trigger_type".to_string(), |backup| backup.trigger_type.as_ref().map(|t| format!("{t:?}")));
        registry.backup_accessors.insert("service_plan".to_string(), |backup| backup.service_plan.as_ref().map(|s| format!("{s:?}")));

        // Register nested field accessors - NO hardcoded field names!
        registry.nested_accessors.insert("annotations".to_string(), |cluster, parts| {
            if parts.len() > 1 {
                let key = parts[1].trim_matches('"');
                cluster
                    .annotations
                    .as_ref()
                    .and_then(|ann| ann.get(key).cloned())
            } else {
                Some(format!("{:?}", cluster.annotations))
            }
        });

        registry.nested_accessors.insert("labels".to_string(), |cluster, parts| {
            if parts.len() > 1 {
                let key = parts[1].trim_matches('"');
                cluster
                    .labels
                    .as_ref()
                    .and_then(|labels| labels.get(key).cloned())
            } else {
                Some(format!("{:?}", cluster.labels))
            }
        });

        // Register array field accessors - NO hardcoded field names!
        registry.array_accessors.insert("endpoints".to_string(), |cluster, parts| {
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
        });

        registry
    };
}

/// Implementation of FieldAccessor for Tidb using the global field accessor registry
impl FieldAccessor for Tidb {
    fn object_type(&self) -> &'static str {
        "Tidb"
    }

    fn get_field_value(&self, field_name: &str) -> Option<String> {
        FIELD_ACCESSORS.get_field_value(self, field_name)
    }

    fn get_all_field_values(&self) -> HashMap<String, String> {
        let mut values = HashMap::new();
        let field_names = SCHEMA.get_field_names(self.object_type());

        for field_name in field_names {
            if let Some(value) = self.get_field_value(&field_name) {
                values.insert(field_name, value);
            }
        }

        values
    }
}

/// Implementation of FieldAccessor for Backup using the global field accessor registry
impl FieldAccessor for Backup {
    fn object_type(&self) -> &'static str {
        "Backup"
    }

    fn get_field_value(&self, field_name: &str) -> Option<String> {
        FIELD_ACCESSORS.get_backup_field_value(self, field_name)
    }

    fn get_all_field_values(&self) -> HashMap<String, String> {
        let mut values = HashMap::new();
        let field_names = SCHEMA.get_field_names(self.object_type());

        for field_name in field_names {
            if let Some(value) = self.get_field_value(&field_name) {
                values.insert(field_name, value);
            }
        }

        values
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_schema_registry_creation() {
        let registry = SchemaRegistry::new();
        assert!(registry.objects.contains_key("Tidb"));
        assert!(registry.objects.contains_key("Backup"));
    }

    #[test]
    fn test_field_validation() {
        let registry = SchemaRegistry::new();

        // Test valid fields
        assert!(registry.is_valid_field("Tidb", "display_name"));
        assert!(registry.is_valid_field("Tidb", "displayName"));
        assert!(registry.is_valid_field("Tidb", "region"));

        // Test invalid fields
        assert!(!registry.is_valid_field("Tidb", "invalid_field"));
        assert!(!registry.is_valid_field("InvalidObject", "any_field"));
    }

    #[test]
    fn test_filterable_fields() {
        let registry = SchemaRegistry::new();

        assert!(registry.is_filterable_field("Tidb", "display_name"));
        assert!(registry.is_filterable_field("Backup", "state"));

        // Test that we can get all filterable fields
        let tidb_filterable = registry.get_filterable_fields("Tidb");
        assert!(!tidb_filterable.is_empty());
        assert!(tidb_filterable.contains(&"display_name".to_string()));
        assert!(tidb_filterable.contains(&"displayName".to_string()));
    }

    #[test]
    fn test_field_names() {
        let registry = SchemaRegistry::new();

        let tidb_fields = registry.get_field_names("Tidb");
        assert!(tidb_fields.contains(&"display_name".to_string()));
        assert!(tidb_fields.contains(&"displayName".to_string()));
        assert!(tidb_fields.contains(&"region".to_string())); // alias
    }
}
