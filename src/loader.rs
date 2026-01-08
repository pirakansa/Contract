use crate::{Contract, ContractError, ContractResult};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct LoadOptions {
    pub config_path: PathBuf,
    pub include_profile: bool,
}

#[derive(Debug, Clone)]
pub struct LoadedContract {
    pub base_path: PathBuf,
    pub profile_path: Option<PathBuf>,
    pub contract: Contract,
}

pub fn load_contract(options: LoadOptions) -> ContractResult<LoadedContract> {
    let base_path = options.config_path;
    let base_content = std::fs::read_to_string(&base_path)?;
    let base: Contract = serde_yaml::from_str(&base_content)?;
    if options.include_profile {
        if let Some(profile) = base.profile.clone() {
            let profile_path = profile_path_for(&base_path, &profile);
            if !profile_path.exists() {
                return Err(ContractError::ProfileNotFound(
                    profile_path.display().to_string(),
                ));
            }
            let profile_content = std::fs::read_to_string(&profile_path)?;
            let profile_contract: Contract = serde_yaml::from_str(&profile_content)?;
            let merged = base.merge_profile(profile_contract);
            return Ok(LoadedContract {
                base_path,
                profile_path: Some(profile_path),
                contract: merged,
            });
        }
    }
    Ok(LoadedContract {
        base_path,
        profile_path: None,
        contract: base,
    })
}

fn profile_path_for(base_path: &Path, profile: &str) -> PathBuf {
    let directory = base_path.parent().unwrap_or_else(|| Path::new("."));
    directory.join(format!("contract.{profile}.yml"))
}
