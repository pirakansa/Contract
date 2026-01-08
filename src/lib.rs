mod config;
mod contract;
mod diff;
mod init;
mod loader;
mod required_files;
mod schema;
mod validation;

pub use crate::config::{load_config_file, resolve_cli_config, CliConfig, ConfigFile};
pub use crate::contract::{Contract, RequiredFile, Severity};
pub use crate::diff::{diff_required_files, DiffEntry, DiffReport};
pub use crate::init::{init_contract_files, InitOptions, InitOutcome};
pub use crate::loader::{load_contract, LoadOptions, LoadedContract};
pub use crate::required_files::{
    check_required_files, RequiredFileCheck, RequiredFilesReport, Summary,
};
pub use crate::schema::schema_json;
pub use crate::validation::{validate_contract_file, ValidationIssue, ValidationReport};

pub type ContractResult<T> = Result<T, ContractError>;

#[derive(thiserror::Error, Debug)]
pub enum ContractError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("YAML parse error: {0}")]
    Yaml(#[from] serde_yaml::Error),
    #[error("JSON parse error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("TOML parse error: {0}")]
    Toml(#[from] toml::de::Error),
    #[error("Schema validation failed")]
    SchemaValidation { issues: Vec<ValidationIssue> },
    #[error("File already exists: {0}")]
    AlreadyExists(String),
    #[error("Profile file not found: {0}")]
    ProfileNotFound(String),
    #[error("Unsupported rule: {0}")]
    UnsupportedRule(String),
    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),
}
