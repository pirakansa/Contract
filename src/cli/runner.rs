use super::args::{
    CheckArgs, CheckFormat, Cli, Commands, DiffArgs, DiffFormat, InitArgs, Rule, ValidateArgs,
    ValidateFormat,
};
use super::output::{
    print_check_human, print_check_json, print_diff_human, print_diff_json, print_diff_yaml,
    print_validate_human, print_validate_json,
};
use super::util::{
    add_summary, branch_protection_reports, profile_path_for, report_profile_name,
    resolve_config_path, resolve_strict, summarize_required_files,
};
use anyhow::Context;
use contract::{
    check_required_files, diff_branch_protection, diff_required_files, init_contract_files,
    load_config_file, load_contract, resolve_cli_config, schema_json, validate_contract_file,
    CliConfig, ContractError, LoadOptions,
};
use std::path::{Path, PathBuf};

pub(super) fn run(cli: Cli) -> anyhow::Result<i32> {
    let config_file = load_config_file(Path::new(".contract.toml"))?;
    let cli_config = resolve_cli_config(config_file);
    match cli.command {
        Commands::Validate(args) => run_validate(args, &cli_config),
        Commands::Check(args) => run_check(args, &cli_config),
        Commands::Diff(args) => run_diff(args, &cli_config),
        Commands::Apply(_args) => {
            eprintln!("apply は Phase 2 で対応予定です。");
            Ok(2)
        }
        Commands::Init(args) => run_init(args),
        Commands::Schema => {
            println!("{}", schema_json());
            Ok(0)
        }
    }
}

fn run_validate(args: ValidateArgs, cli_config: &CliConfig) -> anyhow::Result<i32> {
    let config_path = resolve_config_path(args.path, args.config, cli_config);
    let format = args
        .format
        .or_else(|| cli_config.format.as_deref().and_then(parse_validate_format))
        .unwrap_or(ValidateFormat::Human);
    let mut reports = Vec::new();

    if !config_path.exists() {
        eprintln!(
            "contract ファイルが見つかりません: {}",
            config_path.display()
        );
        return Ok(2);
    }
    let report = validate_contract_file(&config_path)
        .with_context(|| format!("{config_path:?} の検証に失敗しました"))?;
    reports.push(report);

    if args.with_profile {
        let profile_name = report_profile_name(&config_path)?;
        if let Some(profile_name) = profile_name {
            let profile_path = profile_path_for(&config_path, &profile_name);
            if !profile_path.exists() {
                eprintln!("profile が見つかりません: {}", profile_path.display());
                return Ok(2);
            }
            let profile_report = validate_contract_file(&profile_path)?;
            reports.push(profile_report);
        }
    }

    let valid = reports.iter().all(|report| report.valid);
    if args.quiet && valid {
        return Ok(0);
    }

    match format {
        ValidateFormat::Human => print_validate_human(&reports),
        ValidateFormat::Json => print_validate_json(&reports)?,
    }

    Ok(if valid { 0 } else { 1 })
}

fn run_check(args: CheckArgs, cli_config: &CliConfig) -> anyhow::Result<i32> {
    let rules = parse_rules(args.rules, cli_config.check_rules.clone())?;
    if args.remote.is_some() && rules.contains(&Rule::RequiredFiles) {
        eprintln!("remote の required_files チェックは未対応です。");
        return Ok(2);
    }
    let config_path = resolve_config_path(None, args.config, cli_config);
    if !config_path.exists() {
        eprintln!(
            "contract ファイルが見つかりません: {}",
            config_path.display()
        );
        return Ok(2);
    }
    let strict = resolve_strict(args.strict, cli_config.strict);
    let format = args
        .format
        .or_else(|| cli_config.format.as_deref().and_then(parse_check_format))
        .unwrap_or(CheckFormat::Human);

    let loaded = load_contract(LoadOptions {
        config_path: config_path.clone(),
        include_profile: true,
    })?;
    let root = config_path
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));

    let branch_reports = if rules.contains(&Rule::BranchProtection) {
        branch_protection_reports(&loaded.contract, args.remote.as_deref(), cli_config)?
    } else {
        Vec::new()
    };

    let report = if rules.contains(&Rule::RequiredFiles) {
        Some(check_required_files(
            &root,
            &loaded.contract.required_files,
        )?)
    } else {
        None
    };

    let mut summary = summarize_required_files(&report);
    let branch_summary = contract::summarize_branch_protection(&branch_reports);
    add_summary(&mut summary, &branch_summary);
    let has_error = summary.error > 0 || (strict && summary.warning > 0);
    if args.quiet && summary.error == 0 && summary.warning == 0 {
        return Ok(0);
    }

    match format {
        CheckFormat::Human => print_check_human(&branch_reports, report.as_ref(), &summary),
        CheckFormat::Json => {
            print_check_json(&branch_reports, report.as_ref(), &summary, !has_error)?
        }
    }

    Ok(if has_error { 1 } else { 0 })
}

fn run_diff(args: DiffArgs, cli_config: &CliConfig) -> anyhow::Result<i32> {
    let rules = parse_rules(args.rules, cli_config.check_rules.clone())?;
    if args.remote.is_some() && rules.contains(&Rule::RequiredFiles) {
        eprintln!("remote の required_files diff は未対応です。");
        return Ok(2);
    }
    let config_path = resolve_config_path(None, args.config, cli_config);
    if !config_path.exists() {
        eprintln!(
            "contract ファイルが見つかりません: {}",
            config_path.display()
        );
        return Ok(2);
    }
    let format = args
        .format
        .or_else(|| cli_config.format.as_deref().and_then(parse_diff_format))
        .unwrap_or(DiffFormat::Human);

    let loaded = load_contract(LoadOptions {
        config_path: config_path.clone(),
        include_profile: true,
    })?;
    let root = config_path
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));

    let mut diffs = Vec::new();
    let summary = if rules.contains(&Rule::RequiredFiles) {
        let required_report = check_required_files(&root, &loaded.contract.required_files)?;
        diffs.extend(diff_required_files(&required_report.checks).diffs);
        Some(required_report.summary)
    } else {
        None
    };

    if rules.contains(&Rule::BranchProtection) {
        let branch_reports =
            branch_protection_reports(&loaded.contract, args.remote.as_deref(), cli_config)?;
        diffs.extend(diff_branch_protection(&branch_reports));
    }

    let report = contract::DiffReport { diffs, summary };

    let has_diff = !report.diffs.is_empty();
    match format {
        DiffFormat::Human => print_diff_human(Some(&report)),
        DiffFormat::Json => print_diff_json(Some(&report))?,
        DiffFormat::Yaml => print_diff_yaml(Some(&report))?,
    }

    Ok(if has_diff { 1 } else { 0 })
}

fn run_init(args: InitArgs) -> anyhow::Result<i32> {
    if args.remote.is_some() {
        eprintln!("remote からの init は未対応です。");
        return Ok(2);
    }
    let root = std::env::current_dir()?;
    match init_contract_files(
        &root,
        contract::InitOptions {
            output_path: args.output,
            profile: args.profile,
            from_repo: args.from_repo,
            force: args.force,
        },
    ) {
        Ok(outcome) => {
            for path in outcome.created {
                println!("Created: {}", path.display());
            }
            Ok(0)
        }
        Err(ContractError::AlreadyExists(path)) => {
            eprintln!("ファイルが既に存在します: {path}");
            Ok(1)
        }
        Err(error) => Err(error.into()),
    }
}

fn parse_rules(
    rules: Option<String>,
    config_rules: Option<Vec<String>>,
) -> anyhow::Result<Vec<Rule>> {
    let list = if let Some(rules) = rules {
        rules
            .split(',')
            .map(|item| item.trim().to_string())
            .collect::<Vec<_>>()
    } else if let Some(config_rules) = config_rules {
        config_rules
            .into_iter()
            .map(|item| item.trim().to_string())
            .collect::<Vec<_>>()
    } else {
        vec![
            "required_files".to_string(),
            "branch_protection".to_string(),
        ]
    };
    let mut parsed = Vec::new();
    for rule in list {
        match rule.as_str() {
            "required_files" => parsed.push(Rule::RequiredFiles),
            "branch_protection" => parsed.push(Rule::BranchProtection),
            other => {
                return Err(ContractError::InvalidConfig(format!(
                    "unknown rule: {other}"
                )))
                .context("rules の解決に失敗しました")
            }
        }
    }
    Ok(parsed)
}

fn parse_validate_format(value: &str) -> Option<ValidateFormat> {
    match value {
        "human" => Some(ValidateFormat::Human),
        "json" => Some(ValidateFormat::Json),
        _ => None,
    }
}

fn parse_check_format(value: &str) -> Option<CheckFormat> {
    match value {
        "human" => Some(CheckFormat::Human),
        "json" => Some(CheckFormat::Json),
        _ => None,
    }
}

fn parse_diff_format(value: &str) -> Option<DiffFormat> {
    match value {
        "human" => Some(DiffFormat::Human),
        "json" => Some(DiffFormat::Json),
        "yaml" => Some(DiffFormat::Yaml),
        _ => None,
    }
}
