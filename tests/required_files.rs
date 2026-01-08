use contract::{check_required_files, RequiredFile, Severity};
use std::fs;
use std::path::Path;

fn required_file(path: &str) -> RequiredFile {
    RequiredFile {
        path: Some(path.to_string()),
        pattern: None,
        description: None,
        alternatives: Vec::new(),
        severity: Severity::Error,
        case_insensitive: false,
    }
}

fn required_pattern(pattern: &str) -> RequiredFile {
    RequiredFile {
        path: None,
        pattern: Some(pattern.to_string()),
        description: None,
        alternatives: Vec::new(),
        severity: Severity::Error,
        case_insensitive: false,
    }
}

fn write_file(root: &Path, path: &str) {
    let full_path = root.join(path);
    if let Some(parent) = full_path.parent() {
        fs::create_dir_all(parent).expect("create parent");
    }
    fs::write(full_path, "data").expect("write file");
}

#[test]
fn alternatives_allow_existing_file() {
    let temp = tempfile::TempDir::new().expect("tempdir");
    write_file(temp.path(), "LICENSE.md");

    let mut file = required_file("LICENSE");
    file.alternatives.push("LICENSE.md".to_string());

    let report = check_required_files(temp.path(), &[file]).expect("check");
    assert!(report.checks[0].exists);
    assert_eq!(report.summary.error, 0);
}

#[test]
fn regex_pattern_matches_file() {
    let temp = tempfile::TempDir::new().expect("tempdir");
    write_file(temp.path(), "README.md");

    let report =
        check_required_files(temp.path(), &[required_pattern("^README\\.md$")]).expect("check");
    assert!(report.checks[0].exists);
}

#[test]
fn glob_pattern_matches_recursive_paths() {
    let temp = tempfile::TempDir::new().expect("tempdir");
    write_file(temp.path(), "src/lib.rs");

    let report = check_required_files(temp.path(), &[required_file("src/**/*.rs")]).expect("check");
    assert!(report.checks[0].exists);
}

#[test]
fn case_insensitive_match_works() {
    let temp = tempfile::TempDir::new().expect("tempdir");
    write_file(temp.path(), "README.md");

    let mut file = required_file("readme.md");
    file.case_insensitive = true;
    let report = check_required_files(temp.path(), &[file]).expect("check");
    assert!(report.checks[0].exists);
}

#[test]
fn summary_counts_missing_files() {
    let temp = tempfile::TempDir::new().expect("tempdir");
    let mut warning_file = required_file("MISSING.md");
    warning_file.severity = Severity::Warning;

    let report = check_required_files(temp.path(), &[warning_file]).expect("check");
    assert!(!report.checks[0].exists);
    assert_eq!(report.summary.warning, 1);
    assert_eq!(report.summary.error, 0);
}
