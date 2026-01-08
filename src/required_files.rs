use crate::{ContractError, ContractResult, RequiredFile, Severity};
use globset::{GlobBuilder, GlobSetBuilder};
use regex::RegexBuilder;
use std::collections::HashSet;
use std::path::Path;
use walkdir::WalkDir;

#[derive(Debug, Clone, serde::Serialize)]
pub struct RequiredFileCheck {
    pub path: String,
    pub exists: bool,
    pub severity: Severity,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, Default)]
pub struct Summary {
    pub error: usize,
    pub warning: usize,
    pub info: usize,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct RequiredFilesReport {
    pub checks: Vec<RequiredFileCheck>,
    pub summary: Summary,
}

pub fn check_required_files(
    root: &Path,
    required_files: &[RequiredFile],
) -> ContractResult<RequiredFilesReport> {
    let files = list_files(root)?;
    let files_lowercase = files
        .iter()
        .map(|path| path.to_lowercase())
        .collect::<HashSet<_>>();
    let mut checks = Vec::new();
    let mut summary = Summary::default();

    for required in required_files {
        let check = evaluate_required_file(required, root, &files, &files_lowercase)?;
        if !check.exists {
            match check.severity {
                Severity::Error => summary.error += 1,
                Severity::Warning => summary.warning += 1,
                Severity::Info => summary.info += 1,
            }
        }
        checks.push(check);
    }

    Ok(RequiredFilesReport { checks, summary })
}

fn evaluate_required_file(
    required: &RequiredFile,
    root: &Path,
    files: &[String],
    files_lowercase: &HashSet<String>,
) -> ContractResult<RequiredFileCheck> {
    let (label, exists) = if let Some(path) = required.path.as_ref() {
        let alternatives = required.alternatives.iter();
        let candidates = std::iter::once(path).chain(alternatives);
        let exists = candidates.clone().any(|candidate| {
            path_exists(
                candidate,
                root,
                files,
                files_lowercase,
                required.case_insensitive,
            )
        });
        (path.to_string(), exists)
    } else if let Some(pattern) = required.pattern.as_ref() {
        let exists = match_regex(pattern, files, required.case_insensitive)?;
        (pattern.to_string(), exists)
    } else {
        return Err(ContractError::InvalidConfig(
            "required_files entry must include path or pattern".to_string(),
        ));
    };

    Ok(RequiredFileCheck {
        path: label,
        exists,
        severity: required.severity,
        description: required.description.clone(),
    })
}

fn path_exists(
    candidate: &str,
    root: &Path,
    files: &[String],
    files_lowercase: &HashSet<String>,
    case_insensitive: bool,
) -> bool {
    let normalized = normalize_path(candidate);
    if looks_like_glob(&normalized) {
        return match_glob(&normalized, files, case_insensitive);
    }
    if case_insensitive {
        let target = normalized.to_lowercase();
        return files_lowercase.contains(&target);
    }
    root.join(candidate).exists()
}

fn looks_like_glob(candidate: &str) -> bool {
    candidate.contains('*') || candidate.contains('?') || candidate.contains('[')
}

fn match_glob(pattern: &str, files: &[String], case_insensitive: bool) -> bool {
    let mut builder = GlobBuilder::new(pattern);
    builder.case_insensitive(case_insensitive);
    if let Ok(glob) = builder.build() {
        let mut set_builder = GlobSetBuilder::new();
        set_builder.add(glob);
        if let Ok(glob_set) = set_builder.build() {
            return files.iter().any(|file| glob_set.is_match(file));
        }
    }
    false
}

fn normalize_path(path: &str) -> String {
    path.replace('\\', "/")
}

fn match_regex(pattern: &str, files: &[String], case_insensitive: bool) -> ContractResult<bool> {
    let regex = RegexBuilder::new(pattern)
        .case_insensitive(case_insensitive)
        .build()
        .map_err(|error| ContractError::InvalidConfig(error.to_string()))?;
    Ok(files.iter().any(|file| regex.is_match(file)))
}

fn list_files(root: &Path) -> ContractResult<Vec<String>> {
    let mut paths = Vec::new();
    for entry in WalkDir::new(root).into_iter().filter_map(Result::ok) {
        let path = entry.path();
        if path_is_ignored(path, root) {
            continue;
        }
        if entry.file_type().is_file() {
            let relative = path.strip_prefix(root).unwrap_or(path);
            let normalized = relative.to_string_lossy().replace('\\', "/");
            paths.push(normalized);
        }
    }
    Ok(paths)
}

fn path_is_ignored(path: &Path, root: &Path) -> bool {
    if let Ok(relative) = path.strip_prefix(root) {
        if let Some(component) = relative.components().next() {
            let name = component.as_os_str().to_string_lossy();
            return name == ".git" || name == "target";
        }
    }
    false
}
