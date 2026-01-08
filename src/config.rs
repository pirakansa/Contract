use crate::ContractResult;
use serde::Deserialize;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Deserialize, Default)]
pub struct ConfigFile {
    #[serde(default)]
    pub default: DefaultConfig,
    #[serde(default)]
    pub check: CheckConfig,
    #[serde(default)]
    pub github: GithubConfig,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct DefaultConfig {
    pub config: Option<PathBuf>,
    pub format: Option<String>,
    pub strict: Option<bool>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct CheckConfig {
    pub rules: Option<Vec<String>>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct GithubConfig {
    pub token: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct CliConfig {
    pub config_path: Option<PathBuf>,
    pub format: Option<String>,
    pub strict: Option<bool>,
    pub check_rules: Option<Vec<String>>,
}

pub fn load_config_file(path: &Path) -> ContractResult<Option<ConfigFile>> {
    if !path.exists() {
        return Ok(None);
    }
    let content = std::fs::read_to_string(path)?;
    let config = toml::from_str(&content)?;
    Ok(Some(config))
}

pub fn resolve_cli_config(config_file: Option<ConfigFile>) -> CliConfig {
    let mut resolved = CliConfig::default();
    if let Some(config_file) = config_file {
        resolved.config_path = config_file.default.config;
        resolved.format = config_file.default.format;
        resolved.strict = config_file.default.strict;
        resolved.check_rules = config_file.check.rules;
    }
    resolved
}
