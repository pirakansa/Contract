use contract::{BranchProtectionReport, DiffEntry, DiffReport, RequiredFilesReport, Summary};

pub(super) fn print_validate_human(reports: &[contract::ValidationReport]) {
    let mut errors = 0;
    for report in reports {
        if report.valid {
            println!("✓ {}: Valid", report.path);
        } else {
            println!("✗ {}: Invalid", report.path);
            for issue in &report.errors {
                println!("  - {}", issue.message);
            }
            errors += report.errors.len();
        }
    }
    println!("Validated {} files, {} errors", reports.len(), errors);
}

pub(super) fn print_validate_json(reports: &[contract::ValidationReport]) -> anyhow::Result<()> {
    let output = serde_json::json!({
        "valid": reports.iter().all(|report| report.valid),
        "files": reports
    });
    println!("{}", serde_json::to_string_pretty(&output)?);
    Ok(())
}

pub(super) fn print_check_human(
    branch_reports: &[BranchProtectionReport],
    report: Option<&RequiredFilesReport>,
    summary: &Summary,
) {
    for report in branch_reports {
        println!("Branch Protection [{}]", report.target);
        if report.details.is_empty() {
            println!("  ✓ No checks configured");
            continue;
        }
        for detail in &report.details {
            if detail.passed {
                println!(
                    "  ✓ {}: {}",
                    detail.path,
                    format_check_value(&detail.expected)
                );
            } else {
                let icon = match detail.severity {
                    contract::Severity::Error => "✗",
                    contract::Severity::Warning => "⚠",
                    contract::Severity::Info => "ℹ",
                };
                println!("  {icon} {}: {}", detail.path, detail.message);
            }
        }
        println!();
    }
    if let Some(report) = report {
        println!("Required Files");
        for check in &report.checks {
            let (icon, message) = if check.exists {
                ("✓", "Found")
            } else {
                match check.severity {
                    contract::Severity::Error => ("✗", "Not found (error)"),
                    contract::Severity::Warning => ("⚠", "Not found (warning)"),
                    contract::Severity::Info => ("ℹ", "Not found (info)"),
                }
            };
            println!("  {icon} {}: {message}", check.path);
        }
    }
    println!(
        "Summary: {} error, {} warning, {} info",
        summary.error, summary.warning, summary.info
    );
}

pub(super) fn print_check_json(
    branch_reports: &[BranchProtectionReport],
    report: Option<&RequiredFilesReport>,
    summary: &Summary,
    valid: bool,
) -> anyhow::Result<()> {
    let mut results = Vec::new();
    for report in branch_reports {
        results.push(serde_json::json!({
            "rule": "branch_protection",
            "target": report.target,
            "checks": report.checks,
        }));
    }
    if let Some(report) = report {
        results.push(serde_json::json!({
            "rule": "required_files",
            "checks": report.checks,
        }));
    }
    let output = serde_json::json!({
        "valid": valid,
        "results": results,
        "summary": summary,
    });
    println!("{}", serde_json::to_string_pretty(&output)?);
    Ok(())
}

pub(super) fn print_diff_human(report: Option<&DiffReport>) {
    if let Some(report) = report {
        if report.diffs.is_empty() {
            println!("No differences found.");
            return;
        }
        let mut branch_groups: Vec<(String, Vec<&DiffEntry>)> = Vec::new();
        let mut required_diffs = Vec::new();
        for diff in &report.diffs {
            if diff.rule == "branch_protection" {
                let target = diff.target.clone().unwrap_or_else(|| "unknown".to_string());
                if let Some((_, entries)) = branch_groups.iter_mut().find(|(key, _)| key == &target)
                {
                    entries.push(diff);
                } else {
                    branch_groups.push((target, vec![diff]));
                }
            } else if diff.rule == "required_files" {
                required_diffs.push(diff);
            }
        }

        for (target, diffs) in branch_groups {
            println!("Branch Protection [{target}]");
            for diff in diffs {
                if diff.diff_type == "array_diff" {
                    println!("  {}:", diff.path);
                    if let Some(missing) = &diff.missing {
                        for value in missing {
                            println!("    + {value} (missing)");
                        }
                    }
                    if let Some(extra) = &diff.extra {
                        for value in extra {
                            println!("    - {value} (extra)");
                        }
                    }
                } else {
                    println!(
                        "  {}: expected {}, got {}",
                        diff.path,
                        format_diff_value(diff.expected.as_ref()),
                        format_diff_value(diff.actual.as_ref())
                    );
                }
            }
            println!();
        }

        if !required_diffs.is_empty() {
            println!("Required Files:");
            for diff in required_diffs {
                let severity = diff.severity.map(|value| value.as_str()).unwrap_or("error");
                println!("  + {} (missing, severity: {severity})", diff.path);
            }
        }
    } else {
        println!("No differences found.");
    }
}

pub(super) fn print_diff_json(report: Option<&DiffReport>) -> anyhow::Result<()> {
    let output = serde_json::json!({
        "diffs": report.map(|report| report.diffs.clone()).unwrap_or_default(),
    });
    println!("{}", serde_json::to_string_pretty(&output)?);
    Ok(())
}

pub(super) fn print_diff_yaml(report: Option<&DiffReport>) -> anyhow::Result<()> {
    let output = serde_yaml::to_string(
        &report
            .map(|report| report.diffs.clone())
            .unwrap_or_default(),
    )?;
    println!("{output}");
    Ok(())
}

fn format_check_value(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(text) => text.clone(),
        _ => value.to_string(),
    }
}

fn format_diff_value(value: Option<&serde_json::Value>) -> String {
    value
        .map(format_check_value)
        .unwrap_or_else(|| "-".to_string())
}
