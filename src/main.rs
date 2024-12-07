use cf_waf_analyzer::cli::{Cli, Commands};
use cf_waf_analyzer::error::Result;
use cf_waf_analyzer::FirewallAnalyzer;
use clap::Parser;
use std::process;

fn main() {
    let cli = Cli::parse();

    if let Err(err) = run(cli) {
        eprintln!("Error: {}", err);
        process::exit(1);
    }
}

fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Commands::Analyze { input, format } => {
            let analyzer = FirewallAnalyzer::new();
            analyzer.analyze_file(&input, format)?;
        }
    }
    Ok(())
}
