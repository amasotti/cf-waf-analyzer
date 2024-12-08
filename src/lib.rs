use crate::model::RulesetInfo;
use std::collections::HashMap;

pub mod analyzer;
pub mod cli;
pub mod error;
pub mod model;
pub mod output;

pub type RulesetInfoMap = HashMap<&'static str, &'static str>;

// Constants for ruleset IDs to avoid magic strings
pub const CLOUDFLARE_RULESET_ID: &str = "efb7b8c949ac4650a09736fc376e9aee";
pub const OWASP_RULESET_ID: &str = "4814384a9e5d4991b9815dcfc25d2f1f";
pub const LEAKED_CREDS_RULESET_ID: &str = "c2e184081120413c86c3ab7e14069605";

// Re-export main types
pub use analyzer::FirewallAnalyzer;
pub use error::{Error, Result};
pub use model::{AnalysisResult, FirewallEvent};

fn initialize_ruleset_mappings() -> HashMap<String, RulesetInfo> {
    [
        (
            CLOUDFLARE_RULESET_ID.to_string(),
            RulesetInfo::new("Cloudflare Rules", colored::Color::Blue),
        ),
        (
            OWASP_RULESET_ID.to_string(),
            RulesetInfo::new("OWASP Rules", colored::Color::Green),
        ),
        (
            LEAKED_CREDS_RULESET_ID.to_string(),
            RulesetInfo::new("Leaked Credentials Rules", colored::Color::Red),
        ),
    ]
    .into_iter()
    .collect()
}

pub fn initialize_rule_id_mapping() -> RulesetInfoMap {
    let mut map = HashMap::new();
    map.insert(
        "4d887b5914c64b209697214d2059fd73",
        "920300: Request Missing an Accept Header",
    );
    map.insert(
        "596955b6baec4d4ba2a3f509956b7490",
        "920420: Request content type not allowed by policy",
    );
    map.insert(
        "753c98e3a15f4a389ea0b196c91b7247",
        "932200: RCE Bypass Technique",
    );
    map.insert(
        "8ac8bc2a661e475d940980f9317f28e1",
        "911100: Method is not allowed by policy",
    );
    map.insert(
        "5e4903d6afa841c9b88b96203297003f",
        "942430: Restricted SQL Character Anomaly Detection",
    );
    map.insert(
        "6afe6795ee6a48d6a1dfe59255395a78",
        "942260: Detects basic SQL authentication bypass attempts 1/3",
    );
    map.insert(
        "ad801cbf1e434f849dd076ec44550b20",
        "920320: Missing User Agent Header",
    );
    map.insert(
        "5a6f5a57cde8428ab0668ce17cdec0c8",
        "942370: Detects classic SQL injection probings 2/3",
    );
    map.insert(
        "405028a67bf44e56b896558f6e8a82b0",
        "932115: Remote Command Execution: Windows Command Injection",
    );
    map.insert(
        "d12ad6d1bc0c42b3affe0cee682bb405",
        "942440: SQL Comment Sequence Detected",
    );
    map.insert(
        "1ba7e9fcfa5841559dc4b7a89447c501",
        "920230: Multiple URL Encoding Detected",
    );

    map
}
