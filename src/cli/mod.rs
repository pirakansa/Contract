mod args;
mod output;
mod runner;
mod util;

use clap::Parser;

pub fn run() -> i32 {
    let cli = args::Cli::parse();
    match runner::run(cli) {
        Ok(code) => code,
        Err(error) => {
            eprintln!("error: {error}");
            2
        }
    }
}
