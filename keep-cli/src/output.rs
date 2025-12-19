#![forbid(unsafe_code)]

use console::{style, Term};
use indicatif::{ProgressBar, ProgressStyle};
use std::time::Duration;

pub struct Output {
    term: Term,
}

impl Output {
    pub fn new() -> Self {
        Self {
            term: Term::stderr(),
        }
    }

    pub fn success(&self, msg: &str) {
        let _ = self
            .term
            .write_line(&format!("{} {}", style("✓").green().bold(), msg));
    }

    pub fn error(&self, msg: &str) {
        let _ = self
            .term
            .write_line(&format!("{} {}", style("✗").red().bold(), msg));
    }

    #[allow(dead_code)]
    pub fn warn(&self, msg: &str) {
        let _ = self
            .term
            .write_line(&format!("{} {}", style("!").yellow().bold(), msg));
    }

    pub fn info(&self, msg: &str) {
        let _ = self.term.write_line(msg);
    }

    pub fn header(&self, msg: &str) {
        let _ = self.term.write_line(&format!("\n{}", style(msg).bold()));
    }

    pub fn field(&self, label: &str, value: &str) {
        let _ = self
            .term
            .write_line(&format!("  {}: {}", style(label).dim(), value));
    }

    pub fn key_field(&self, label: &str, value: &str) {
        let _ = self.term.write_line(&format!(
            "  {}: {}",
            style(label).dim(),
            style(value).yellow()
        ));
    }

    pub fn newline(&self) {
        let _ = self.term.write_line("");
    }

    pub fn table_header(&self, cols: &[(&str, usize)]) {
        let header: String = cols
            .iter()
            .map(|(name, width)| format!("{:<width$}", style(*name).bold(), width = width))
            .collect::<Vec<_>>()
            .join(" ");
        let _ = self.term.write_line(&format!("\n{}", header));
        let _ = self.term.write_line(&"─".repeat(70));
    }

    pub fn table_row(&self, cols: &[(&str, usize, bool)]) {
        let row: String = cols
            .iter()
            .map(|(val, width, highlight)| {
                if *highlight {
                    format!("{:<width$}", style(*val).yellow(), width = width)
                } else {
                    format!("{:<width$}", val, width = width)
                }
            })
            .collect::<Vec<_>>()
            .join(" ");
        let _ = self.term.write_line(&row);
    }

    pub fn spinner(&self, msg: &str) -> Spinner {
        let pb = ProgressBar::new_spinner();
        pb.set_style(
            ProgressStyle::default_spinner()
                .template("{spinner:.cyan} {msg}")
                .unwrap(),
        );
        pb.set_message(msg.to_string());
        pb.enable_steady_tick(Duration::from_millis(80));
        Spinner { pb }
    }

    pub fn hidden_banner(&self) {
        let lines = [
            "╔══════════════════════════════════════════════════════════════╗",
            "║              HIDDEN VOLUME MODE                              ║",
            "╠══════════════════════════════════════════════════════════════╣",
            "║                                                              ║",
            "║  You will create TWO passwords:                             ║",
            "║                                                              ║",
            "║  1. OUTER password - Shows decoy keys                       ║",
            "║     → Use this if forced to reveal your vault               ║",
            "║                                                              ║",
            "║  2. HIDDEN password - Shows real keys                       ║",
            "║     → Never reveal this password                            ║",
            "║                                                              ║",
            "║  The hidden volume is CRYPTOGRAPHICALLY UNDETECTABLE.       ║",
            "║  An attacker cannot prove it exists.                        ║",
            "║                                                              ║",
            "╚══════════════════════════════════════════════════════════════╝",
        ];
        self.newline();
        for line in lines {
            let _ = self.term.write_line(&format!("{}", style(line).cyan()));
        }
        self.newline();
    }

    pub fn hidden_notes(&self) {
        self.header("IMPORTANT NOTES:");
        let _ = self.term.write_line(&format!(
            "  • Put {} keys in outer volume (small amounts)",
            style("DECOY").yellow()
        ));
        let _ = self.term.write_line(&format!(
            "  • Put {} keys in hidden volume",
            style("REAL").green()
        ));
        let _ = self.term.write_line(&format!(
            "  • Under duress: give {} password only",
            style("OUTER").yellow()
        ));
        let _ = self.term.write_line(&format!(
            "  • Hidden volume {} be detected",
            style("cannot").red().bold()
        ));
        self.newline();
        self.info("To access hidden volume:");
        let _ = self
            .term
            .write_line(&format!("  {}", style("keep --hidden <command>").cyan()));
    }

    pub fn init_notes(&self) {
        self.info("Next steps:");
        let _ = self.term.write_line(&format!(
            "  {} Generate a key",
            style("keep generate --name main").cyan()
        ));
        let _ = self.term.write_line(&format!(
            "  {} Import existing key",
            style("keep import --name backup").cyan()
        ));
    }

    pub fn secret_warning(&self) {
        let _ = self.term.write_line(&format!(
            "\n{}",
            style("WARNING: Never share your private key!").red().bold()
        ));
    }

    pub fn hidden_label(&self) {
        let _ = self
            .term
            .write_line(&format!("\n{}", style("[HIDDEN VOLUME]").red().bold()));
    }
}

impl Default for Output {
    fn default() -> Self {
        Self::new()
    }
}

pub struct Spinner {
    pb: ProgressBar,
}

impl Spinner {
    pub fn finish(&self) {
        self.pb.finish_and_clear();
    }

    #[allow(dead_code)]
    pub fn finish_with(&self, msg: &str) {
        self.pb.finish_with_message(msg.to_string());
    }
}
