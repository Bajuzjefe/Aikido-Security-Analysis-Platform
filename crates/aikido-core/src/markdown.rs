use std::collections::HashMap;

use crate::ast_walker::ModuleInfo;
use crate::detector::{Finding, Severity};

/// Severity badge for GitHub-compatible markdown.
fn severity_badge(severity: &Severity) -> &'static str {
    match severity {
        Severity::Critical => "🔴 **CRITICAL**",
        Severity::High => "🟠 **HIGH**",
        Severity::Medium => "🟡 **MEDIUM**",
        Severity::Low => "🔵 **LOW**",
        Severity::Info => "⚪ **INFO**",
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

/// Generate a Markdown report suitable for GitHub PRs, wikis, and READMEs.
pub fn findings_to_markdown(
    findings: &[Finding],
    project_name: &str,
    project_version: &str,
    modules: &[ModuleInfo],
) -> String {
    let mut output = String::new();

    // Header
    output.push_str("# Aikido Security Report\n\n");
    output.push_str(&format!(
        "**Project:** {project_name} v{project_version}\n\n",
    ));

    if findings.is_empty() {
        output.push_str("No issues found.\n");
        return output;
    }

    // Summary table
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

    output.push_str("## Summary\n\n");
    output.push_str(&format!("**Total issues:** {}\n\n", findings.len()));
    output.push_str("| Severity | Count |\n");
    output.push_str("|----------|-------|\n");
    output.push_str(&format!("| 🔴 Critical | {critical} |\n"));
    output.push_str(&format!("| 🟠 High | {high} |\n"));
    output.push_str(&format!("| 🟡 Medium | {medium} |\n"));
    output.push_str(&format!("| 🔵 Low | {low} |\n"));
    output.push_str(&format!("| ⚪ Info | {info} |\n"));
    output.push('\n');

    // Build source map for snippet extraction
    let source_map: HashMap<&str, &str> = modules
        .iter()
        .filter_map(|m| m.source_code.as_deref().map(|src| (m.path.as_str(), src)))
        .collect();

    // Sort findings by severity (critical first)
    let mut sorted_findings: Vec<&Finding> = findings.iter().collect();
    sorted_findings.sort_by(|a, b| severity_rank(&b.severity).cmp(&severity_rank(&a.severity)));

    // Render each finding
    output.push_str("## Findings\n\n");

    for (i, finding) in sorted_findings.iter().enumerate() {
        output.push_str(&format!(
            "### {}. {} `{}`\n\n",
            i + 1,
            severity_badge(&finding.severity),
            finding.detector_name
        ));

        output.push_str(&format!("**{}**\n\n", finding.title));
        output.push_str(&format!("{}\n\n", finding.description));

        // Location
        if let Some(ref loc) = finding.location {
            let line_info = loc.line_start.map(|l| format!(":{l}")).unwrap_or_default();
            output.push_str(&format!(
                "**Location:** `{}{}`\n\n",
                loc.module_path, line_info
            ));

            // Code snippet
            if let Some(source) = source_map.get(loc.module_path.as_str()) {
                if let Some(snippet) = loc.snippet(source, 2) {
                    output.push_str("```aiken\n");
                    output.push_str(&snippet);
                    output.push_str("\n```\n\n");
                }
            }
        }

        // Suggestion
        if let Some(ref suggestion) = finding.suggestion {
            output.push_str(&format!("> **Suggestion:** {suggestion}\n\n"));
        }

        if !finding.related_findings.is_empty() {
            output.push_str(&format!(
                "> *Also covers: {}*\n\n",
                finding.related_findings.join(", ")
            ));
        }

        output.push_str("---\n\n");
    }

    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast_walker::ModuleKind;
    use crate::detector::{Confidence, SourceLocation};

    #[test]
    fn test_empty_findings_produces_no_issues() {
        let result = findings_to_markdown(&[], "test-project", "1.0.0", &[]);
        assert!(result.contains("# Aikido Security Report"));
        assert!(result.contains("test-project"));
        assert!(result.contains("No issues found"));
        // Should NOT contain a summary table
        assert!(!result.contains("| Severity"));
    }

    #[test]
    fn test_single_finding_renders_all_fields() {
        let source = "fn foo() {\n  let x = 42\n  True\n}";
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
            detector_name: "double-satisfaction".to_string(),
            severity: Severity::Critical,
            confidence: Confidence::Definite,
            title: "Validator vulnerable to double satisfaction".to_string(),
            description: "Multiple UTXOs can satisfy this validator simultaneously.".to_string(),
            module: "test".to_string(),
            location: Some(SourceLocation {
                module_path: "validators/test.ak".to_string(),
                byte_start: 0,
                byte_end: 10,
                line_start: Some(1),
                column_start: Some(1),
                line_end: Some(1),
                column_end: Some(10),
            }),
            suggestion: Some("Add a unique identifier check.".to_string()),
            related_findings: vec![],
            semantic_group: None,

            evidence: None,
        };

        let result = findings_to_markdown(&[finding], "my-project", "2.0.0", &modules);

        // Header
        assert!(result.contains("# Aikido Security Report"));
        assert!(result.contains("my-project v2.0.0"));

        // Summary table
        assert!(result.contains("| 🔴 Critical | 1 |"));

        // Finding section
        assert!(result.contains("**CRITICAL**"));
        assert!(result.contains("`double-satisfaction`"));
        assert!(result.contains("Validator vulnerable to double satisfaction"));
        assert!(result.contains("Multiple UTXOs"));

        // Location
        assert!(result.contains("`validators/test.ak:1`"));

        // Code snippet with aiken tag
        assert!(result.contains("```aiken"));
        assert!(result.contains("fn foo()"));

        // Suggestion
        assert!(result.contains("Add a unique identifier check."));
    }

    #[test]
    fn test_multiple_findings_sorted_by_severity() {
        let findings = vec![
            Finding {
                detector_name: "info-detector".to_string(),
                severity: Severity::Info,
                confidence: Confidence::Possible,
                title: "Info issue".to_string(),
                description: "An info-level finding.".to_string(),
                module: "test".to_string(),
                location: None,
                suggestion: None,
                related_findings: vec![],
                semantic_group: None,

                evidence: None,
            },
            Finding {
                detector_name: "critical-detector".to_string(),
                severity: Severity::Critical,
                confidence: Confidence::Definite,
                title: "Critical issue".to_string(),
                description: "A critical finding.".to_string(),
                module: "test".to_string(),
                location: None,
                suggestion: None,
                related_findings: vec![],
                semantic_group: None,

                evidence: None,
            },
            Finding {
                detector_name: "medium-detector".to_string(),
                severity: Severity::Medium,
                confidence: Confidence::Likely,
                title: "Medium issue".to_string(),
                description: "A medium finding.".to_string(),
                module: "test".to_string(),
                location: None,
                suggestion: None,
                related_findings: vec![],
                semantic_group: None,

                evidence: None,
            },
        ];

        let result = findings_to_markdown(&findings, "project", "1.0.0", &[]);

        // Critical should appear before Medium, which should appear before Info
        let critical_pos = result.find("Critical issue").unwrap();
        let medium_pos = result.find("Medium issue").unwrap();
        let info_pos = result.find("Info issue").unwrap();
        assert!(
            critical_pos < medium_pos,
            "Critical should come before Medium"
        );
        assert!(medium_pos < info_pos, "Medium should come before Info");

        // Summary counts
        assert!(result.contains("**Total issues:** 3"));
    }
}
