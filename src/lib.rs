pub mod analyzer;
pub mod cli;
pub mod error;
pub mod model;
pub mod output;

// Constants for ruleset IDs to avoid magic strings
pub const CLOUDFLARE_RULESET_ID: &str = "efb7b8c949ac4650a09736fc376e9aee";
pub const OWASP_RULESET_ID: &str = "4814384a9e5d4991b9815dcfc25d2f1f";
pub const LEAKED_CREDS_RULESET_ID: &str = "c2e184081120413c86c3ab7e14069605";

// Re-export main types
pub use error::{Error, Result};
pub use model::{AnalysisResult, FirewallEvent};
