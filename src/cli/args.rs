use clap::{ArgAction, Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "repo-contract", version, about = "Repo Contract CLI")]
pub(crate) struct Cli {
    #[command(subcommand)]
    pub(crate) command: Commands,
    #[arg(short = 'v', long = "verbose", action = ArgAction::Count)]
    pub(crate) verbose: u8,
    #[arg(long = "no-color", default_value_t = false)]
    pub(crate) no_color: bool,
}

#[derive(Subcommand)]
pub(crate) enum Commands {
    Validate(ValidateArgs),
    Check(CheckArgs),
    Diff(DiffArgs),
    Apply(ApplyArgs),
    Init(InitArgs),
    Schema,
}

#[derive(clap::Args)]
pub(crate) struct ValidateArgs {
    #[arg(value_name = "PATH")]
    pub(crate) path: Option<PathBuf>,
    #[arg(short = 'c', long = "config")]
    pub(crate) config: Option<PathBuf>,
    #[arg(short = 'p', long = "with-profile", default_value_t = false)]
    pub(crate) with_profile: bool,
    #[arg(short = 'f', long = "format")]
    pub(crate) format: Option<ValidateFormat>,
    #[arg(short = 'q', long = "quiet", default_value_t = false)]
    pub(crate) quiet: bool,
}

#[derive(clap::Args)]
pub(crate) struct CheckArgs {
    #[arg(short = 'c', long = "config")]
    pub(crate) config: Option<PathBuf>,
    #[arg(short = 'r', long = "remote")]
    pub(crate) remote: Option<String>,
    #[arg(long = "rules")]
    pub(crate) rules: Option<String>,
    #[arg(short = 'f', long = "format")]
    pub(crate) format: Option<CheckFormat>,
    #[arg(short = 's', long = "strict", action = ArgAction::SetTrue)]
    pub(crate) strict: Option<bool>,
    #[arg(short = 'q', long = "quiet", default_value_t = false)]
    pub(crate) quiet: bool,
}

#[derive(clap::Args)]
pub(crate) struct DiffArgs {
    #[arg(short = 'c', long = "config")]
    pub(crate) config: Option<PathBuf>,
    #[arg(short = 'r', long = "remote")]
    pub(crate) remote: Option<String>,
    #[arg(long = "rules")]
    pub(crate) rules: Option<String>,
    #[arg(short = 'f', long = "format")]
    pub(crate) format: Option<DiffFormat>,
}

#[derive(clap::Args)]
pub(crate) struct ApplyArgs {
    #[arg(short = 'c', long = "config")]
    pub(crate) config: Option<PathBuf>,
}

#[derive(clap::Args)]
pub(crate) struct InitArgs {
    #[arg(short = 'o', long = "output", default_value = "contract.yml")]
    pub(crate) output: PathBuf,
    #[arg(short = 'p', long = "profile")]
    pub(crate) profile: Option<String>,
    #[arg(long = "from-repo", default_value_t = false)]
    pub(crate) from_repo: bool,
    #[arg(short = 'r', long = "remote")]
    pub(crate) remote: Option<String>,
    #[arg(short = 'f', long = "force", default_value_t = false)]
    pub(crate) force: bool,
}

#[derive(Clone, Debug, ValueEnum)]
pub(crate) enum ValidateFormat {
    Human,
    Json,
}

#[derive(Clone, Debug, ValueEnum)]
pub(crate) enum CheckFormat {
    Human,
    Json,
}

#[derive(Clone, Debug, ValueEnum)]
pub(crate) enum DiffFormat {
    Human,
    Json,
    Yaml,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Rule {
    RequiredFiles,
    BranchProtection,
}
