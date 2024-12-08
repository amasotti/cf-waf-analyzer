//! This module contains the output formatters for the CLI.
//!
//! The `Formatter` trait defines the methods that a formatter must implement.
//!
//! The `console_output`, `markdown_fmt`, and `text_fmt` modules contain the implementations of
//! the `Formatter` trait.
//!
//! The `output_formatter` module contains the `OutputFormatter` struct, which is used to select
//! the output format based on the user's input.
//!
//! The `Formatter` trait is implemented for the `ConsoleOutput`, `MarkdownFormatter`, and
//! `TextFormatter` types.
//!
//! The `OutputFormatter` struct is used to select the output format based on the user's input.

mod console_output;
mod markdown_fmt;
pub mod output_formatter;
mod text_fmt;

pub trait Formatter {
    fn format_header(&self, text: &str) -> String;
    fn format_section(&self, text: &str) -> String;
    fn format_subsection(&self, text: &str, id: &str) -> String;
    /// Formats an item with a key, value, and label
    /// Example: "GET: 100 requests"
    ///
    /// # Arguments
    ///
    /// * `key` - The key of the item
    /// * `value` - The value of the item
    /// * `label` - The label of the item
    fn format_item(&self, key: &str, value: i32, count_label: &str) -> String;

    fn format_rule(&self, key: &str, value: i32, count_label: &str, rule_label: &str) -> String;

    /// Formats a statistic with a key and value
    /// Example: "Total events: 1000"
    ///
    /// # Arguments
    ///
    /// * `key` - The key of the statistic
    /// * `value` - The value of the statistic
    fn format_stat(&self, key: &str, value: impl std::fmt::Display) -> String;
    fn format_code_block(&self, code: &str) -> String;
    fn format_link(&self, text: &str, url: &str) -> String;
}
