use anyhow::{anyhow, Context};
use contract::{
    check_branch_protection, BranchProtectionReport, CliConfig, Contract, GithubClient,
    RequiredFilesReport, Summary,
};
use std::path::{Path, PathBuf};
use std::process::Command;

pub(super) fn resolve_config_path(
    path: Option<PathBuf>,
    config: Option<PathBuf>,
    cli_config: &CliConfig,
) -> PathBuf {
    path.or(config)
        .or_else(|| cli_config.config_path.clone())
        .unwrap_or_else(|| PathBuf::from("contract.yml"))
}

pub(super) fn resolve_strict(flag: Option<bool>, config_strict: Option<bool>) -> bool {
    let mut strict = flag.or(config_strict).unwrap_or(false);
    if env_true("CONTRACT_STRICT") {
        strict = true;
    }
    strict
}

pub(super) fn report_profile_name(config_path: &Path) -> anyhow::Result<Option<String>> {
    let content = std::fs::read_to_string(config_path)?;
    let contract: serde_yaml::Value = serde_yaml::from_str(&content)?;
    if let Some(profile) = contract.get("profile") {
        Ok(profile.as_str().map(|value| value.to_string()))
    } else {
        Ok(None)
    }
}

pub(super) fn profile_path_for(config_path: &Path, profile: &str) -> PathBuf {
    config_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(format!("contract.{profile}.yml"))
}

pub(super) fn summarize_required_files(report: &Option<RequiredFilesReport>) -> Summary {
    report
        .as_ref()
        .map(|report| report.summary.clone())
        .unwrap_or_default()
}

pub(super) fn add_summary(summary: &mut Summary, other: &Summary) {
    summary.error += other.error;
    summary.warning += other.warning;
    summary.info += other.info;
}

pub(super) fn branch_protection_reports(
    contract: &Contract,
    remote: Option<&str>,
    cli_config: &CliConfig,
) -> anyhow::Result<Vec<BranchProtectionReport>> {
    let Some(branch_protection) = contract.branch_protection.as_ref() else {
        return Ok(Vec::new());
    };
    let (client, repo) = github_context(remote, cli_config)?;
    check_branch_protection(&client, &repo, branch_protection)
        .context("branch_protection の取得に失敗しました")
}

fn env_true(key: &str) -> bool {
    std::env::var(key)
        .ok()
        .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
        .unwrap_or(false)
}

fn resolve_github_token(cli_config: &CliConfig) -> Option<String> {
    std::env::var("GITHUB_TOKEN")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| cli_config.github_token.clone())
}

fn require_github_token(cli_config: &CliConfig) -> anyhow::Result<String> {
    resolve_github_token(cli_config).ok_or_else(|| {
        anyhow!("GITHUB_TOKEN または .contract.toml の github.token を設定してください")
    })
}

fn resolve_repository(remote: Option<&str>) -> anyhow::Result<String> {
    if let Some(remote) = remote {
        return normalize_repository(remote)
            .ok_or_else(|| anyhow!("invalid remote repository: {remote}"));
    }
    if let Ok(repo) = std::env::var("GITHUB_REPOSITORY") {
        if !repo.trim().is_empty() {
            return Ok(repo);
        }
    }
    let output = Command::new("git")
        .args(["config", "--get", "remote.origin.url"])
        .output()
        .context("git remote.origin.url の取得に失敗しました")?;
    if !output.status.success() {
        return Err(anyhow!("git remote.origin.url が見つかりません"));
    }
    let url = String::from_utf8_lossy(&output.stdout).trim().to_string();
    normalize_repository(&url).ok_or_else(|| anyhow!("invalid remote repository: {url}"))
}

fn github_context(
    remote: Option<&str>,
    cli_config: &CliConfig,
) -> anyhow::Result<(GithubClient, String)> {
    let repo = resolve_repository(remote).context("GitHub リポジトリの解決に失敗しました")?;
    let token = require_github_token(cli_config)?;
    Ok((GithubClient::new(Some(token)), repo))
}

fn normalize_repository(value: &str) -> Option<String> {
    let trimmed = value.trim().trim_end_matches(".git");
    if let Some(rest) = trimmed.strip_prefix("git@github.com:") {
        return take_owner_repo(rest);
    }
    if let Some(rest) = trimmed.strip_prefix("ssh://git@github.com/") {
        return take_owner_repo(rest);
    }
    if let Some(index) = trimmed.find("github.com/") {
        let rest = &trimmed[index + "github.com/".len()..];
        return take_owner_repo(rest);
    }
    take_owner_repo(trimmed)
}

fn take_owner_repo(value: &str) -> Option<String> {
    let mut parts = value.split('/');
    let owner = parts.next()?;
    let repo = parts.next()?;
    if owner.is_empty() || repo.is_empty() {
        return None;
    }
    Some(format!("{owner}/{repo}"))
}
