use crate::error::Result;
use crate::model::RulesetInfo;
use crate::{AnalysisResult, CLOUDFLARE_RULESET_ID, LEAKED_CREDS_RULESET_ID, OWASP_RULESET_ID};
use colored::*;
use std::collections::HashMap;

trait Formatter {
    fn format_header(&self, text: &str) -> String;
    fn format_section(&self, text: &str) -> String;
    fn format_subsection(&self, text: &str, id: &str) -> String;
    fn format_item(&self, key: &str, value: i32, label: &str) -> String;
    fn format_stat(&self, key: &str, value: impl std::fmt::Display) -> String;
}

struct TextFormatter;
struct MarkdownFormatter;

impl Formatter for TextFormatter {
    fn format_header(&self, text: &str) -> String {
        format!("{}\n", text.bold())
    }

    fn format_section(&self, text: &str) -> String {
        format!("\n{}", text.bold())
    }

    fn format_subsection(&self, text: &str, id: &str) -> String {
        format!("\n=== {} ({}) ===", text, id.dimmed())
    }

    fn format_item(&self, key: &str, value: i32, label: &str) -> String {
        format!("{}: {} {}", key.cyan(), value.to_string().yellow(), label)
    }

    fn format_stat(&self, key: &str, value: impl std::fmt::Display) -> String {
        format!("{}: {}", key, value.to_string().yellow())
    }
}

impl Formatter for MarkdownFormatter {
    fn format_header(&self, text: &str) -> String {
        format!("# {}\n", text)
    }

    fn format_section(&self, text: &str) -> String {
        format!("\n## {}", text)
    }

    fn format_subsection(&self, text: &str, id: &str) -> String {
        format!("\n### {} ({})", text, id)
    }

    fn format_item(&self, key: &str, value: i32, label: &str) -> String {
        format!("- `{}`: {} {}", key, value, label)
    }

    fn format_stat(&self, key: &str, value: impl std::fmt::Display) -> String {
        format!("- {}: {}", key, value)
    }
}

pub struct OutputFormatter {
    format: String,
    console: ConsoleOutput,
}

impl OutputFormatter {
    pub fn new(format: &str) -> Self {
        Self {
            format: format.to_string(),
            console: ConsoleOutput::new(),
        }
    }

    pub fn output(&self, analysis: AnalysisResult) -> Result<()> {
        match self.format.as_str() {
            "text" | "console" => self.console.display(analysis, &TextFormatter),
            "markdown" | "md" => self.console.display(analysis, &MarkdownFormatter),
            _ => Err(crate::error::Error::InvalidInput(format!(
                "Unsupported output format: {}",
                self.format
            ))),
        }
    }
}

struct ConsoleOutput {
    ruleset_mappings: HashMap<String, RulesetInfo>,
}

impl ConsoleOutput {
    fn new() -> Self {
        Self {
            ruleset_mappings: Self::initialize_ruleset_mappings(),
        }
    }

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

    fn display(&self, analysis: AnalysisResult, formatter: &impl Formatter) -> Result<()> {
        // Header
        println!("{}", formatter.format_header("Firewall Analysis Results"));

        // Ruleset Analysis
        println!("{}", formatter.format_section("Rules grouped by Ruleset:"));
        self.print_ruleset_analysis(&analysis, formatter);

        // Endpoint Analysis
        println!(
            "{}",
            formatter.format_section("Most common target endpoints:")
        );
        self.print_sorted_items(&analysis.endpoints, "requests", 10, formatter);

        // Path Analysis
        println!("{}", formatter.format_section("Most common request paths:"));
        self.print_sorted_items(&analysis.paths, "requests", 10, formatter);

        // Summary Statistics
        println!("{}", formatter.format_section("Summary Statistics:"));
        println!(
            "{}",
            formatter.format_stat("Total events", analysis.total_events)
        );
        println!(
            "{}",
            formatter.format_stat("Unique hosts", analysis.unique_hosts)
        );

        // HTTP Methods
        println!("{}", formatter.format_section("HTTP Methods distribution:"));
        self.print_sorted_items(&analysis.http_methods, "requests", usize::MAX, formatter);

        Ok(())
    }

    fn print_ruleset_analysis(&self, analysis: &AnalysisResult, formatter: &impl Formatter) {
        for (ruleset_id, rule_counts) in &analysis.ruleset_rules {
            let ruleset_info = self.get_ruleset_info(ruleset_id);
            println!(
                "{}",
                formatter.format_subsection(&ruleset_info.name, ruleset_id)
            );
            self.print_sorted_items(rule_counts, "occurrences", usize::MAX, formatter);
        }
    }

    fn print_sorted_items(
        &self,
        items: &HashMap<String, i32>,
        label: &str,
        limit: usize,
        formatter: &impl Formatter,
    ) {
        let mut sorted_items: Vec<_> = items.iter().collect();
        sorted_items.sort_by(|a, b| b.1.cmp(a.1));

        for (item, count) in sorted_items.iter().take(limit) {
            println!("{}", formatter.format_item(item, **count, label));
        }
        println!();
    }

    fn get_ruleset_info(&self, ruleset_id: &str) -> RulesetInfo {
        self.ruleset_mappings
            .get(ruleset_id)
            .cloned()
            .unwrap_or_else(|| RulesetInfo::new("Unknown Ruleset", colored::Color::Magenta))
    }
}
