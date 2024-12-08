/// ConsoleOutput is a struct that implements the Formatter trait and is responsible for displaying
/// the analysis results in the console, independent of the output format.
///
/// The display method takes an AnalysisResult and a Formatter trait object as arguments, and
/// prints the analysis results to the console using the provided formatter.
use crate::model::RulesetInfo;
use crate::output::Formatter;
use crate::{
    initialize_rule_id_mapping, initialize_ruleset_mappings, AnalysisResult, RulesetInfoMap,
};
use std::collections::HashMap;

pub struct ConsoleOutput {
    ruleset_mappings: HashMap<String, RulesetInfo>,
    rule_id_mappings: RulesetInfoMap,
}

impl ConsoleOutput {
    pub fn new() -> Self {
        Self {
            ruleset_mappings: initialize_ruleset_mappings(),
            rule_id_mappings: initialize_rule_id_mapping(),
        }
    }

    pub fn display(
        &self,
        analysis: AnalysisResult,
        formatter: &impl Formatter,
    ) -> crate::Result<()> {
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
            self.print_sorted_rules(rule_counts, "occurrences", usize::MAX, formatter);
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

    fn print_sorted_rules(
        &self,
        items: &HashMap<String, i32>,
        label: &str,
        limit: usize,
        formatter: &impl Formatter,
    ) {
        let mut sorted_items: Vec<_> = items.iter().collect();
        sorted_items.sort_by(|a, b| b.1.cmp(a.1));

        for (item, count) in sorted_items.iter().take(limit) {
            let human_readable_name = self
                .rule_id_mappings
                .get(item.as_str())
                .unwrap_or(&"Unknown Rule Name");
            println!(
                "{}",
                formatter.format_rule(item.as_str(), **count, label, human_readable_name)
            );
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
