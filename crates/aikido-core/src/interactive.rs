//! Feature #79: Interactive terminal — navigate findings with arrow keys.
//!
//! Provides a simple text-based interface for navigating findings
//! when output is connected to a TTY. Uses basic ANSI escape codes.

use crate::ast_walker::ModuleInfo;
use crate::detector::Finding;

/// Format a single finding for interactive display.
pub fn format_finding_detail(finding: &Finding, index: usize, total: usize) -> String {
    let mut out = String::new();

    out.push_str(&format!("  Finding {}/{total}\n", index + 1));
    out.push_str(&format!(
        "  [{severity}] {title}\n",
        severity = finding.severity,
        title = finding.title
    ));
    out.push_str(&format!("  Detector: {}\n", finding.detector_name));
    out.push_str(&format!("  Confidence: {}\n", finding.confidence));
    out.push_str(&format!("  Module: {}\n", finding.module));

    if let Some(ref loc) = finding.location {
        if let Some(line) = loc.line_start {
            out.push_str(&format!("  Location: {}:{}\n", loc.module_path, line));
        }
    }

    out.push_str(&format!("\n  {}\n", finding.description));

    if let Some(ref suggestion) = finding.suggestion {
        out.push_str(&format!("\n  Suggestion: {suggestion}\n"));
    }

    out
}

/// Format the interactive findings list (selected item highlighted).
pub fn format_findings_list(findings: &[Finding], selected: usize, page_size: usize) -> String {
    let mut out = String::new();

    if findings.is_empty() {
        out.push_str("  No findings to display.\n");
        return out;
    }

    let page_start = (selected / page_size) * page_size;
    let page_end = (page_start + page_size).min(findings.len());

    out.push_str(&format!(
        "  Findings ({}/{}) — Page {}/{}\n\n",
        findings.len(),
        findings.len(),
        selected / page_size + 1,
        findings.len().div_ceil(page_size)
    ));

    for (i, f) in findings.iter().enumerate().take(page_end).skip(page_start) {
        let marker = if i == selected { ">" } else { " " };
        let severity_tag = match f.severity {
            crate::detector::Severity::Critical => "CRIT",
            crate::detector::Severity::High => "HIGH",
            crate::detector::Severity::Medium => "MED ",
            crate::detector::Severity::Low => "LOW ",
            crate::detector::Severity::Info => "INFO",
        };

        out.push_str(&format!(
            "  {marker} [{severity_tag}] {title}\n",
            title = f.title
        ));
    }

    out.push_str("\n  [j/k or arrows] Navigate  [enter] View detail  [q] Quit\n");

    out
}

/// Run interactive mode. Returns the formatted output for each interaction.
/// This is a state machine that can be driven by external input.
#[derive(Debug)]
pub struct InteractiveState {
    pub selected: usize,
    pub total: usize,
    pub page_size: usize,
    pub viewing_detail: bool,
}

impl InteractiveState {
    pub fn new(total: usize) -> Self {
        Self {
            selected: 0,
            total,
            page_size: 15,
            viewing_detail: false,
        }
    }

    /// Move selection up.
    pub fn up(&mut self) {
        if self.viewing_detail {
            return;
        }
        if self.selected > 0 {
            self.selected -= 1;
        }
    }

    /// Move selection down.
    pub fn down(&mut self) {
        if self.viewing_detail {
            return;
        }
        if self.selected + 1 < self.total {
            self.selected += 1;
        }
    }

    /// Toggle detail view.
    pub fn enter(&mut self) {
        self.viewing_detail = !self.viewing_detail;
    }

    /// Render current state.
    pub fn render(&self, findings: &[Finding]) -> String {
        if self.viewing_detail && self.selected < findings.len() {
            format_finding_detail(&findings[self.selected], self.selected, self.total)
        } else {
            format_findings_list(findings, self.selected, self.page_size)
        }
    }
}

/// Get source snippet for a finding from modules.
pub fn get_finding_snippet(
    finding: &Finding,
    modules: &[ModuleInfo],
    context: usize,
) -> Option<String> {
    let loc = finding.location.as_ref()?;
    let line = loc.line_start?;

    let module = modules.iter().find(|m| m.path == loc.module_path)?;
    let source = module.source_code.as_deref()?;

    let lines: Vec<&str> = source.lines().collect();
    let start = line.saturating_sub(context + 1);
    let end = (line + context).min(lines.len());

    let mut snippet = String::new();
    for (i, src_line) in lines.iter().enumerate().take(end).skip(start) {
        let marker = if i + 1 == line { ">>>" } else { "   " };
        snippet.push_str(&format!("{marker} {:>4} | {src_line}\n", i + 1));
    }
    Some(snippet)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detector::{Confidence, Severity, SourceLocation};

    fn make_finding(title: &str, severity: Severity) -> Finding {
        Finding {
            detector_name: "test-detector".to_string(),
            severity,
            confidence: Confidence::Likely,
            title: title.to_string(),
            description: "Test description".to_string(),
            module: "test".to_string(),
            location: Some(SourceLocation::from_bytes("test.ak", 0, 10)),
            suggestion: Some("Fix it".to_string()),
            related_findings: vec![],
            semantic_group: None,

            evidence: None,
        }
    }

    #[test]
    fn test_format_findings_list_empty() {
        let list = format_findings_list(&[], 0, 10);
        assert!(list.contains("No findings"));
    }

    #[test]
    fn test_format_findings_list_highlights_selected() {
        let findings = vec![
            make_finding("First", Severity::High),
            make_finding("Second", Severity::Low),
        ];
        let list = format_findings_list(&findings, 0, 10);
        assert!(list.contains("> [HIGH] First"));
        assert!(list.contains("  [LOW ] Second"));
    }

    #[test]
    fn test_format_finding_detail() {
        let f = make_finding("Important finding", Severity::Critical);
        let detail = format_finding_detail(&f, 0, 1);
        assert!(detail.contains("Finding 1/1"));
        assert!(detail.contains("[Critical]"));
        assert!(detail.contains("Important finding"));
        assert!(detail.contains("Suggestion: Fix it"));
    }

    #[test]
    fn test_interactive_state_navigation() {
        let mut state = InteractiveState::new(5);
        assert_eq!(state.selected, 0);

        state.down();
        assert_eq!(state.selected, 1);

        state.down();
        assert_eq!(state.selected, 2);

        state.up();
        assert_eq!(state.selected, 1);

        // Can't go below 0
        state.up();
        state.up();
        assert_eq!(state.selected, 0);
    }

    #[test]
    fn test_interactive_state_bounds() {
        let mut state = InteractiveState::new(2);
        state.down();
        state.down(); // already at max
        assert_eq!(state.selected, 1);
    }

    #[test]
    fn test_interactive_state_detail_toggle() {
        let mut state = InteractiveState::new(3);
        assert!(!state.viewing_detail);
        state.enter();
        assert!(state.viewing_detail);
        state.enter();
        assert!(!state.viewing_detail);
    }

    #[test]
    fn test_interactive_render_list() {
        let findings = vec![make_finding("Test", Severity::Medium)];
        let state = InteractiveState::new(1);
        let output = state.render(&findings);
        assert!(output.contains("[MED ]"));
    }

    #[test]
    fn test_interactive_render_detail() {
        let findings = vec![make_finding("Test", Severity::Medium)];
        let mut state = InteractiveState::new(1);
        state.enter();
        let output = state.render(&findings);
        assert!(output.contains("Finding 1/1"));
    }

    #[test]
    fn test_get_snippet_with_context() {
        use crate::ast_walker::{ModuleInfo, ModuleKind};
        let modules = vec![ModuleInfo {
            name: "test".to_string(),
            path: "test.ak".to_string(),
            kind: ModuleKind::Validator,
            validators: vec![],
            data_types: vec![],
            functions: vec![],
            constants: vec![],
            type_aliases: vec![],
            test_count: 0,
            test_function_names: vec![],
            source_code: Some("line1\nline2\nline3\nline4\nline5".to_string()),
        }];
        let mut f = make_finding("Test", Severity::High);
        f.location = Some(SourceLocation {
            module_path: "test.ak".to_string(),
            byte_start: 0,
            byte_end: 10,
            line_start: Some(3),
            column_start: Some(1),
            line_end: Some(3),
            column_end: Some(5),
        });
        let snippet = get_finding_snippet(&f, &modules, 1).unwrap();
        assert!(snippet.contains(">>> "));
        assert!(snippet.contains("line3"));
    }
}
