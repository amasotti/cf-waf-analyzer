use crate::output::Formatter;
use colored::Colorize;

pub struct TextFormatter;

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

    fn format_item(&self, key: &str, value: i32, count_label: &str) -> String {
        format!(
            "{}: {} {}",
            key.cyan(),
            value.to_string().yellow(),
            count_label
        )
    }

    fn format_rule(&self, key: &str, value: i32, count_label: &str, rule_label: &str) -> String {
        format!(
            "{}: {} {} ({})",
            key.cyan(),
            value.to_string().yellow(),
            count_label,
            rule_label
        )
    }

    fn format_stat(&self, key: &str, value: impl std::fmt::Display) -> String {
        format!("{}: {}", key, value.to_string().yellow())
    }

    fn format_code_block(&self, code: &str) -> String {
        format!("```\n{}\n```", code)
    }

    fn format_link(&self, text: &str, url: &str) -> String {
        format!("{} ({})", text, url)
    }
}
