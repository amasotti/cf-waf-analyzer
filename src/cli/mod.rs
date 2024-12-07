use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    Analyze {
        /// Input file path
        input: PathBuf,

        /// Output format (text, md)
        #[arg(short, long, default_value = "text")]
        format: String,
    },
}
