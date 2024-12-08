use crate::output::Formatter;

pub struct MarkdownFormatter;

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

    fn format_item(&self, key: &str, value: i32, count_label: &str) -> String {
        format!("- `{}`: {} {}", key, value, count_label)
    }

    fn format_rule(&self, key: &str, value: i32, count_label: &str, rule_label: &str) -> String {
        format!("- `{}`: {} {} [{}]", key, value, count_label, rule_label)
    }

    fn format_stat(&self, key: &str, value: impl std::fmt::Display) -> String {
        format!("- {}: {}", key, value)
    }

    fn format_code_block(&self, code: &str) -> String {
        format!("```\n{}\n```", code)
    }

    fn format_link(&self, text: &str, url: &str) -> String {
        format!("[{}]({})", text, url)
    }
}
