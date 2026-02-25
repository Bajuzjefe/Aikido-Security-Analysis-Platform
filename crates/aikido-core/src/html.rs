use std::collections::HashMap;

use crate::ast_walker::ModuleInfo;
use crate::detector::{Finding, Severity};

/// CSS color for each severity level.
fn severity_color(severity: &Severity) -> &'static str {
    match severity {
        Severity::Critical => "#dc2626",
        Severity::High => "#ea580c",
        Severity::Medium => "#ca8a04",
        Severity::Low => "#2563eb",
        Severity::Info => "#6b7280",
    }
}

/// CSS class name for each severity level.
fn severity_class(severity: &Severity) -> &'static str {
    match severity {
        Severity::Critical => "severity-critical",
        Severity::High => "severity-high",
        Severity::Medium => "severity-medium",
        Severity::Low => "severity-low",
        Severity::Info => "severity-info",
    }
}

/// Label text for each severity level.
fn severity_label(severity: &Severity) -> &'static str {
    match severity {
        Severity::Critical => "CRITICAL",
        Severity::High => "HIGH",
        Severity::Medium => "MEDIUM",
        Severity::Low => "LOW",
        Severity::Info => "INFO",
    }
}

/// Numeric rank for sorting (higher = more severe).
fn severity_rank(severity: &Severity) -> u8 {
    match severity {
        Severity::Critical => 5,
        Severity::High => 4,
        Severity::Medium => 3,
        Severity::Low => 2,
        Severity::Info => 1,
    }
}

/// Escape HTML special characters.
fn escape_html(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// Generate a standalone HTML report with embedded CSS.
pub fn findings_to_html(
    findings: &[Finding],
    project_name: &str,
    project_version: &str,
    modules: &[ModuleInfo],
) -> String {
    // Build source map for snippet extraction
    let source_map: HashMap<&str, &str> = modules
        .iter()
        .filter_map(|m| m.source_code.as_deref().map(|src| (m.path.as_str(), src)))
        .collect();

    // Sort findings by severity (critical first)
    let mut sorted_findings: Vec<&Finding> = findings.iter().collect();
    sorted_findings.sort_by(|a, b| severity_rank(&b.severity).cmp(&severity_rank(&a.severity)));

    // Count by severity
    let critical = findings
        .iter()
        .filter(|f| f.severity == Severity::Critical)
        .count();
    let high = findings
        .iter()
        .filter(|f| f.severity == Severity::High)
        .count();
    let medium = findings
        .iter()
        .filter(|f| f.severity == Severity::Medium)
        .count();
    let low = findings
        .iter()
        .filter(|f| f.severity == Severity::Low)
        .count();
    let info = findings
        .iter()
        .filter(|f| f.severity == Severity::Info)
        .count();

    let mut html = String::new();

    // DOCTYPE and head
    html.push_str("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n");
    html.push_str("<meta charset=\"UTF-8\">\n");
    html.push_str("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n");
    html.push_str(&format!(
        "<title>Aikido Report - {} v{}</title>\n",
        escape_html(project_name),
        escape_html(project_version)
    ));

    // Embedded CSS
    html.push_str("<style>\n");
    html.push_str(
        r#"* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f8fafc; color: #1e293b; line-height: 1.6; padding: 2rem; }
.container { max-width: 960px; margin: 0 auto; }
h1 { font-size: 1.75rem; margin-bottom: 0.25rem; }
.subtitle { color: #64748b; margin-bottom: 2rem; }
.summary { display: flex; gap: 1rem; flex-wrap: wrap; margin-bottom: 2rem; }
.stat-card { background: #fff; border: 1px solid #e2e8f0; border-radius: 8px; padding: 1rem 1.5rem; min-width: 120px; text-align: center; }
.stat-card .count { font-size: 2rem; font-weight: 700; }
.stat-card .label { font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em; color: #64748b; }
.finding-card { background: #fff; border: 1px solid #e2e8f0; border-radius: 8px; margin-bottom: 1rem; overflow: hidden; }
.finding-header { display: flex; align-items: center; gap: 0.75rem; padding: 1rem 1.5rem; border-bottom: 1px solid #f1f5f9; }
.badge { display: inline-block; padding: 0.2rem 0.6rem; border-radius: 4px; color: #fff; font-size: 0.7rem; font-weight: 700; letter-spacing: 0.05em; }
.severity-critical .badge { background: #dc2626; }
.severity-high .badge { background: #ea580c; }
.severity-medium .badge { background: #ca8a04; }
.severity-low .badge { background: #2563eb; }
.severity-info .badge { background: #6b7280; }
.finding-title { font-weight: 600; }
.finding-body { padding: 1rem 1.5rem; }
.finding-body p { margin-bottom: 0.75rem; }
.location { font-family: 'SFMono-Regular', Consolas, monospace; font-size: 0.85rem; color: #475569; }
pre { background: #1e293b; color: #e2e8f0; padding: 1rem; border-radius: 6px; overflow-x: auto; font-size: 0.85rem; margin-bottom: 0.75rem; }
.suggestion { background: #f0fdf4; border-left: 3px solid #22c55e; padding: 0.75rem 1rem; border-radius: 0 6px 6px 0; font-size: 0.9rem; }
.no-issues { text-align: center; padding: 3rem; color: #16a34a; font-size: 1.25rem; }
@media (max-width: 640px) { body { padding: 1rem; } .summary { flex-direction: column; } .stat-card { min-width: unset; } }
"#,
    );
    html.push_str("</style>\n</head>\n<body>\n<div class=\"container\">\n");

    // Header
    html.push_str("<h1>Aikido Security Report</h1>\n");
    html.push_str(&format!(
        "<p class=\"subtitle\">{} v{}</p>\n",
        escape_html(project_name),
        escape_html(project_version)
    ));

    // Summary stats
    html.push_str("<div class=\"summary\">\n");
    let stats = [
        ("Total", findings.len(), "#1e293b"),
        ("Critical", critical, severity_color(&Severity::Critical)),
        ("High", high, severity_color(&Severity::High)),
        ("Medium", medium, severity_color(&Severity::Medium)),
        ("Low", low, severity_color(&Severity::Low)),
        ("Info", info, severity_color(&Severity::Info)),
    ];
    for (label, count, color) in &stats {
        html.push_str(&format!(
            "<div class=\"stat-card\"><div class=\"count\" style=\"color:{color}\">{count}</div><div class=\"label\">{label}</div></div>\n",
        ));
    }
    html.push_str("</div>\n");

    if findings.is_empty() {
        html.push_str("<div class=\"no-issues\">No issues found.</div>\n");
    } else {
        // Finding cards
        for finding in &sorted_findings {
            let cls = severity_class(&finding.severity);
            let sev_label = severity_label(&finding.severity);

            html.push_str(&format!("<div class=\"finding-card {cls}\">\n"));
            html.push_str("<div class=\"finding-header\">\n");
            html.push_str(&format!("<span class=\"badge\">{sev_label}</span>\n"));
            html.push_str(&format!(
                "<span class=\"finding-title\">{}</span>\n",
                escape_html(&finding.title)
            ));
            html.push_str("</div>\n");

            html.push_str("<div class=\"finding-body\">\n");
            html.push_str(&format!(
                "<p><strong>Detector:</strong> <code>{}</code></p>\n",
                escape_html(&finding.detector_name)
            ));
            html.push_str(&format!("<p>{}</p>\n", escape_html(&finding.description)));

            // Location + snippet
            if let Some(ref loc) = finding.location {
                let line_info = loc.line_start.map(|l| format!(":{l}")).unwrap_or_default();
                html.push_str(&format!(
                    "<p class=\"location\">{}{}</p>\n",
                    escape_html(&loc.module_path),
                    line_info
                ));

                if let Some(source) = source_map.get(loc.module_path.as_str()) {
                    if let Some(snippet) = loc.snippet(source, 2) {
                        html.push_str(&format!("<pre>{}</pre>\n", escape_html(&snippet)));
                    }
                }
            }

            // Suggestion
            if let Some(ref suggestion) = finding.suggestion {
                html.push_str(&format!(
                    "<div class=\"suggestion\"><strong>Suggestion:</strong> {}</div>\n",
                    escape_html(suggestion)
                ));
            }

            if !finding.related_findings.is_empty() {
                html.push_str(&format!(
                    "<div class=\"related\"><em>Also covers: {}</em></div>\n",
                    escape_html(&finding.related_findings.join(", "))
                ));
            }

            html.push_str("</div>\n</div>\n");
        }
    }

    html.push_str("</div>\n</body>\n</html>\n");

    html
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast_walker::ModuleKind;
    use crate::detector::{Confidence, SourceLocation};

    #[test]
    fn test_output_starts_with_doctype() {
        let result = findings_to_html(&[], "test", "1.0.0", &[]);
        assert!(result.starts_with("<!DOCTYPE html>"));
    }

    #[test]
    fn test_contains_correct_finding_count() {
        let findings = vec![
            Finding {
                detector_name: "det-a".to_string(),
                severity: Severity::High,
                confidence: Confidence::Definite,
                title: "Issue A".to_string(),
                description: "Desc A".to_string(),
                module: "test".to_string(),
                location: None,
                suggestion: None,
                related_findings: vec![],
                semantic_group: None,

                evidence: None,
            },
            Finding {
                detector_name: "det-b".to_string(),
                severity: Severity::Low,
                confidence: Confidence::Likely,
                title: "Issue B".to_string(),
                description: "Desc B".to_string(),
                module: "test".to_string(),
                location: None,
                suggestion: None,
                related_findings: vec![],
                semantic_group: None,

                evidence: None,
            },
        ];

        let result = findings_to_html(&findings, "proj", "0.1.0", &[]);
        // The "Total" stat card should show 2
        assert!(result.contains(">2</div>"));
        // Both findings should appear
        assert!(result.contains("Issue A"));
        assert!(result.contains("Issue B"));
    }

    #[test]
    fn test_contains_severity_color_classes() {
        let findings = vec![
            Finding {
                detector_name: "det-crit".to_string(),
                severity: Severity::Critical,
                confidence: Confidence::Definite,
                title: "Crit".to_string(),
                description: "Crit desc".to_string(),
                module: "test".to_string(),
                location: None,
                suggestion: None,
                related_findings: vec![],
                semantic_group: None,

                evidence: None,
            },
            Finding {
                detector_name: "det-med".to_string(),
                severity: Severity::Medium,
                confidence: Confidence::Likely,
                title: "Med".to_string(),
                description: "Med desc".to_string(),
                module: "test".to_string(),
                location: None,
                suggestion: None,
                related_findings: vec![],
                semantic_group: None,

                evidence: None,
            },
        ];

        let result = findings_to_html(&findings, "proj", "1.0.0", &[]);
        assert!(result.contains("severity-critical"));
        assert!(result.contains("severity-medium"));
    }

    #[test]
    fn test_html_snippet_and_suggestion() {
        let source = "fn check() {\n  if True {\n    spend()\n  }\n}";
        let modules = vec![ModuleInfo {
            name: "test".to_string(),
            path: "validators/test.ak".to_string(),
            kind: ModuleKind::Validator,
            validators: vec![],
            data_types: vec![],
            functions: vec![],
            constants: vec![],
            type_aliases: vec![],
            test_count: 0,
            test_function_names: vec![],
            source_code: Some(source.to_string()),
        }];

        let finding = Finding {
            detector_name: "test-det".to_string(),
            severity: Severity::High,
            confidence: Confidence::Definite,
            title: "Bad check".to_string(),
            description: "This check is wrong.".to_string(),
            module: "test".to_string(),
            location: Some(SourceLocation {
                module_path: "validators/test.ak".to_string(),
                byte_start: 14,
                byte_end: 28,
                line_start: Some(2),
                column_start: Some(3),
                line_end: Some(2),
                column_end: Some(14),
            }),
            suggestion: Some("Use a proper condition.".to_string()),
            related_findings: vec![],
            semantic_group: None,

            evidence: None,
        };

        let result = findings_to_html(&[finding], "proj", "1.0.0", &modules);
        assert!(result.contains("<pre>"));
        assert!(result.contains("if True"));
        assert!(result.contains("Use a proper condition."));
    }

    #[test]
    fn test_no_issues_message() {
        let result = findings_to_html(&[], "proj", "1.0.0", &[]);
        assert!(result.contains("No issues found."));
    }

    #[test]
    fn test_html_escapes_special_chars() {
        let finding = Finding {
            detector_name: "test".to_string(),
            severity: Severity::Low,
            confidence: Confidence::Possible,
            title: "Check <script> & \"quotes\"".to_string(),
            description: "Desc with <b>html</b>".to_string(),
            module: "test".to_string(),
            location: None,
            suggestion: None,
            related_findings: vec![],
            semantic_group: None,

            evidence: None,
        };

        let result = findings_to_html(&[finding], "proj", "1.0.0", &[]);
        assert!(result.contains("&lt;script&gt;"));
        assert!(result.contains("&amp;"));
        assert!(result.contains("&quot;quotes&quot;"));
        assert!(!result.contains("<script>"));
    }
}
