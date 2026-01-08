use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize)]
pub struct Contract {
    pub version: String,
    #[serde(default)]
    pub profile: Option<String>,
    #[serde(default)]
    pub language: Option<String>,
    #[serde(default)]
    pub branch_protection: Option<serde_yaml::Value>,
    #[serde(default)]
    pub required_files: Vec<RequiredFile>,
    #[serde(default)]
    pub metadata: Option<serde_yaml::Value>,
}

impl Contract {
    pub fn merge_profile(&self, profile: Contract) -> Contract {
        let mut merged = self.clone();
        merged.required_files.extend(profile.required_files);
        if profile.branch_protection.is_some() {
            merged.branch_protection = profile.branch_protection;
        }
        if profile.metadata.is_some() {
            merged.metadata = profile.metadata;
        }
        merged
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RequiredFile {
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub pattern: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub alternatives: Vec<String>,
    #[serde(default)]
    pub severity: Severity,
    #[serde(default)]
    pub case_insensitive: bool,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    #[default]
    Error,
    Warning,
    Info,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Error => "error",
            Severity::Warning => "warning",
            Severity::Info => "info",
        }
    }
}
