use crate::{schema_json, ContractError, ContractResult};
use jsonschema::JSONSchema;
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationIssue {
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instance_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationReport {
    pub path: String,
    pub valid: bool,
    pub errors: Vec<ValidationIssue>,
}

pub fn validate_contract_file(path: &Path) -> ContractResult<ValidationReport> {
    let content = std::fs::read_to_string(path)?;
    let yaml_value: serde_yaml::Value = serde_yaml::from_str(&content)?;
    let json_value = serde_json::to_value(yaml_value)?;
    let schema_value: serde_json::Value = serde_json::from_str(schema_json())?;
    let compiled = JSONSchema::compile(&schema_value)
        .map_err(|error| ContractError::InvalidConfig(error.to_string()))?;
    let report = match compiled.validate(&json_value) {
        Ok(_) => ValidationReport {
            path: path.display().to_string(),
            valid: true,
            errors: Vec::new(),
        },
        Err(errors) => {
            let issues = errors
                .map(|error| ValidationIssue {
                    message: error.to_string(),
                    instance_path: Some(error.instance_path.to_string()),
                })
                .collect::<Vec<_>>();
            ValidationReport {
                path: path.display().to_string(),
                valid: false,
                errors: issues,
            }
        }
    };
    Ok(report)
}
