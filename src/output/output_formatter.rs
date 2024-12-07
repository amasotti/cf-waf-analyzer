use crate::output::console_output::ConsoleOutput;
use crate::output::markdown_fmt::MarkdownFormatter;
use crate::output::text_fmt::TextFormatter;
use crate::AnalysisResult;

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

    pub fn output(&self, analysis: AnalysisResult) -> crate::Result<()> {
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
