use crate::ContractResult;
use crate::{ContractError, RequiredFile, Severity};
use serde::Serialize;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct InitOptions {
    pub output_path: PathBuf,
    pub profile: Option<String>,
    pub from_repo: bool,
    pub force: bool,
}

#[derive(Debug, Clone)]
pub struct InitOutcome {
    pub created: Vec<PathBuf>,
}

#[derive(Serialize)]
struct ContractTemplate {
    #[serde(rename = "$schema", skip_serializing_if = "Option::is_none")]
    schema: Option<String>,
    version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    profile: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    required_files: Vec<RequiredFileTemplate>,
}

#[derive(Serialize)]
struct ProfileTemplate {
    #[serde(rename = "$schema", skip_serializing_if = "Option::is_none")]
    schema: Option<String>,
    version: String,
    language: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    required_files: Vec<RequiredFileTemplate>,
}

#[derive(Serialize)]
struct RequiredFileTemplate {
    path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    severity: Option<Severity>,
}

pub fn init_contract_files(root: &Path, options: InitOptions) -> ContractResult<InitOutcome> {
    let mut created = Vec::new();
    let base_required_files = if options.from_repo {
        required_files_from_repo(root)
    } else {
        default_required_files()
    };

    let template = ContractTemplate {
        schema: Some("https://pirakansa.github.io/Contract/schemas/v1.json".to_string()),
        version: "1.0".to_string(),
        profile: options.profile.clone(),
        required_files: base_required_files,
    };

    write_yaml(&options.output_path, &template, options.force)?;
    created.push(options.output_path.clone());

    if let Some(profile) = options.profile {
        let profile_path = profile_path_for(&options.output_path, &profile);
        let profile_template = ProfileTemplate {
            schema: Some("https://pirakansa.github.io/Contract/schemas/v1.json".to_string()),
            version: "1.0".to_string(),
            language: profile.clone(),
            required_files: profile_required_files(&profile),
        };
        write_yaml(&profile_path, &profile_template, options.force)?;
        created.push(profile_path);
    }

    Ok(InitOutcome { created })
}

fn write_yaml<T: Serialize>(path: &Path, value: &T, force: bool) -> ContractResult<()> {
    if path.exists() && !force {
        return Err(ContractError::AlreadyExists(path.display().to_string()));
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let content = serde_yaml::to_string(value)?;
    std::fs::write(path, content)?;
    Ok(())
}

fn profile_path_for(base_path: &Path, profile: &str) -> PathBuf {
    let directory = base_path.parent().unwrap_or_else(|| Path::new("."));
    directory.join(format!("contract.{profile}.yml"))
}

fn default_required_files() -> Vec<RequiredFileTemplate> {
    vec![
        RequiredFileTemplate {
            path: "README.md".to_string(),
            severity: None,
        },
        RequiredFileTemplate {
            path: "LICENSE".to_string(),
            severity: None,
        },
        RequiredFileTemplate {
            path: ".gitignore".to_string(),
            severity: None,
        },
        RequiredFileTemplate {
            path: "AGENTS.md".to_string(),
            severity: Some(Severity::Info),
        },
    ]
}

fn required_files_from_repo(root: &Path) -> Vec<RequiredFileTemplate> {
    let candidates = [
        ("README.md", None),
        ("LICENSE", None),
        ("CONTRIBUTING.md", Some(Severity::Warning)),
        ("CHANGELOG.md", Some(Severity::Warning)),
        ("SECURITY.md", Some(Severity::Warning)),
        (".gitignore", None),
        ("AGENTS.md", Some(Severity::Info)),
    ];
    candidates
        .into_iter()
        .filter_map(|(path, severity)| {
            let candidate = root.join(path);
            candidate.exists().then(|| RequiredFileTemplate {
                path: path.to_string(),
                severity,
            })
        })
        .collect()
}

fn profile_required_files(profile: &str) -> Vec<RequiredFileTemplate> {
    match profile {
        "rust" => vec![
            RequiredFileTemplate {
                path: "Cargo.toml".to_string(),
                severity: None,
            },
            RequiredFileTemplate {
                path: "src/main.rs".to_string(),
                severity: Some(Severity::Warning),
            },
            RequiredFileTemplate {
                path: "rust-toolchain.toml".to_string(),
                severity: Some(Severity::Warning),
            },
        ],
        _ => Vec::new(),
    }
}

impl From<RequiredFile> for RequiredFileTemplate {
    fn from(value: RequiredFile) -> Self {
        RequiredFileTemplate {
            path: value.path.unwrap_or_default(),
            severity: if value.severity == Severity::Error {
                None
            } else {
                Some(value.severity)
            },
        }
    }
}
