//! Feature #85: LSP server — Language Server Protocol support for real-time analysis.
//!
//! Provides LSP-compatible data structures for reporting aikido findings
//! as editor diagnostics. The actual LSP server transport (stdio/socket) is
//! handled by the CLI binary when invoked with `--lsp`.
//!
//! This module converts aikido findings into LSP Diagnostic format.

use crate::detector::{Finding, Severity};

/// LSP Diagnostic severity levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LspSeverity {
    Error = 1,
    Warning = 2,
    Information = 3,
    Hint = 4,
}

/// An LSP-compatible diagnostic derived from an aikido finding.
#[derive(Debug, Clone)]
pub struct LspDiagnostic {
    /// URI of the file.
    pub uri: String,
    /// 0-based start line.
    pub start_line: u32,
    /// 0-based start column.
    pub start_col: u32,
    /// 0-based end line.
    pub end_line: u32,
    /// 0-based end column.
    pub end_col: u32,
    /// Diagnostic severity.
    pub severity: LspSeverity,
    /// Diagnostic message.
    pub message: String,
    /// Source identifier.
    pub source: String,
    /// Diagnostic code (detector name).
    pub code: String,
}

/// Convert aikido severity to LSP severity.
pub fn to_lsp_severity(severity: &Severity) -> LspSeverity {
    match severity {
        Severity::Critical | Severity::High => LspSeverity::Error,
        Severity::Medium => LspSeverity::Warning,
        Severity::Low => LspSeverity::Information,
        Severity::Info => LspSeverity::Hint,
    }
}

/// Convert a list of findings to LSP diagnostics.
pub fn findings_to_diagnostics(findings: &[Finding], project_root: &str) -> Vec<LspDiagnostic> {
    findings
        .iter()
        .filter_map(|f| {
            let loc = f.location.as_ref()?;
            let line_start = loc.line_start.unwrap_or(1);
            let col_start = loc.column_start.unwrap_or(1);
            let line_end = loc.line_end.unwrap_or(line_start);
            let col_end = loc.column_end.unwrap_or(col_start + 1);

            Some(LspDiagnostic {
                uri: if loc.module_path.starts_with('/') {
                    format!("file://{}", loc.module_path)
                } else {
                    format!("file://{}/{}", project_root, loc.module_path)
                },
                start_line: (line_start as u32).saturating_sub(1),
                start_col: (col_start as u32).saturating_sub(1),
                end_line: (line_end as u32).saturating_sub(1),
                end_col: (col_end as u32).saturating_sub(1),
                severity: to_lsp_severity(&f.severity),
                message: format!("[{}] {}", f.detector_name, f.description),
                source: "aikido".to_string(),
                code: f.detector_name.clone(),
            })
        })
        .collect()
}

/// Format diagnostics as LSP JSON-RPC notification (textDocument/publishDiagnostics).
pub fn format_publish_diagnostics(diagnostics: &[LspDiagnostic]) -> String {
    // Group diagnostics by URI
    let mut by_uri: std::collections::HashMap<&str, Vec<&LspDiagnostic>> =
        std::collections::HashMap::new();
    for d in diagnostics {
        by_uri.entry(&d.uri).or_default().push(d);
    }

    let mut notifications = Vec::new();
    for (uri, diags) in &by_uri {
        let diag_json: Vec<String> = diags
            .iter()
            .map(|d| {
                format!(
                    r#"{{"range":{{"start":{{"line":{},"character":{}}},"end":{{"line":{},"character":{}}}}},"severity":{},"source":"{}","code":"{}","message":"{}"}}"#,
                    d.start_line,
                    d.start_col,
                    d.end_line,
                    d.end_col,
                    d.severity as u8,
                    d.source,
                    d.code,
                    d.message.replace('\\', "\\\\").replace('"', "\\\"")
                )
            })
            .collect();

        notifications.push(format!(
            r#"{{"jsonrpc":"2.0","method":"textDocument/publishDiagnostics","params":{{"uri":"{}","diagnostics":[{}]}}}}"#,
            uri,
            diag_json.join(",")
        ));
    }

    notifications.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detector::{Confidence, SourceLocation};

    fn make_finding(detector: &str, severity: Severity, line: usize) -> Finding {
        Finding {
            detector_name: detector.to_string(),
            severity,
            confidence: Confidence::Likely,
            title: "Test".to_string(),
            description: "Test description".to_string(),
            module: "test".to_string(),
            location: Some(SourceLocation {
                module_path: "validators/pool.ak".to_string(),
                byte_start: 0,
                byte_end: 10,
                line_start: Some(line),
                column_start: Some(5),
                line_end: Some(line),
                column_end: Some(20),
            }),
            suggestion: None,
            related_findings: vec![],
            semantic_group: None,

            evidence: None,
        }
    }

    #[test]
    fn test_severity_mapping() {
        assert_eq!(to_lsp_severity(&Severity::Critical), LspSeverity::Error);
        assert_eq!(to_lsp_severity(&Severity::High), LspSeverity::Error);
        assert_eq!(to_lsp_severity(&Severity::Medium), LspSeverity::Warning);
        assert_eq!(to_lsp_severity(&Severity::Low), LspSeverity::Information);
        assert_eq!(to_lsp_severity(&Severity::Info), LspSeverity::Hint);
    }

    #[test]
    fn test_findings_to_diagnostics() {
        let findings = vec![make_finding("test-det", Severity::High, 10)];
        let diags = findings_to_diagnostics(&findings, "/project");
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].start_line, 9); // 0-based
        assert_eq!(diags[0].start_col, 4);
        assert_eq!(diags[0].severity, LspSeverity::Error);
        assert!(diags[0].uri.contains("validators/pool.ak"));
    }

    #[test]
    fn test_findings_without_location_skipped() {
        let mut f = make_finding("test", Severity::Low, 1);
        f.location = None;
        let diags = findings_to_diagnostics(&[f], "/project");
        assert!(diags.is_empty());
    }

    #[test]
    fn test_format_publish_diagnostics() {
        let findings = vec![make_finding("test-det", Severity::Medium, 5)];
        let diags = findings_to_diagnostics(&findings, "/project");
        let json = format_publish_diagnostics(&diags);
        assert!(json.contains("publishDiagnostics"));
        assert!(json.contains("validators/pool.ak"));
        assert!(json.contains("test-det"));
    }

    #[test]
    fn test_diagnostic_fields() {
        let findings = vec![make_finding("my-detector", Severity::Critical, 42)];
        let diags = findings_to_diagnostics(&findings, "/root");
        let d = &diags[0];
        assert_eq!(d.code, "my-detector");
        assert_eq!(d.source, "aikido");
        assert!(d.message.contains("Test description"));
    }

    #[test]
    fn test_absolute_module_path_not_doubled() {
        let mut f = make_finding("test", Severity::High, 1);
        f.location = Some(SourceLocation {
            module_path: "/home/user/project/validators/pool.ak".to_string(),
            byte_start: 0,
            byte_end: 10,
            line_start: Some(1),
            column_start: Some(1),
            line_end: Some(1),
            column_end: Some(10),
        });
        let diags = findings_to_diagnostics(&[f], "/home/user/project");
        assert_eq!(diags[0].uri, "file:///home/user/project/validators/pool.ak");
    }

    #[test]
    fn test_relative_module_path_joined() {
        let findings = vec![make_finding("test", Severity::High, 1)];
        let diags = findings_to_diagnostics(&findings, "/project");
        assert_eq!(diags[0].uri, "file:///project/validators/pool.ak");
    }
}
