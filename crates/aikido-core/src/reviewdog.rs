use crate::detector::{Finding, Severity};

/// Map aikido Severity to reviewdog severity string.
fn severity_to_rdjson(severity: &Severity) -> &'static str {
    match severity {
        Severity::Critical | Severity::High => "ERROR",
        Severity::Medium => "WARNING",
        Severity::Low | Severity::Info => "INFO",
    }
}

/// Generate Reviewdog Diagnostic Format (rdjson) v0.2 output from findings.
/// If `project_root` is provided, file paths will be made relative to it.
pub fn findings_to_rdjson(findings: &[Finding], project_root: Option<&str>) -> String {
    let diagnostics: Vec<serde_json::Value> = findings
        .iter()
        .map(|f| {
            let message = if f.related_findings.is_empty() {
                format!("{}: {}", f.title, f.description)
            } else {
                format!(
                    "{}: {} (also covers: {})",
                    f.title,
                    f.description,
                    f.related_findings.join(", ")
                )
            };
            let mut diag = serde_json::json!({
                "message": message,
                "severity": severity_to_rdjson(&f.severity),
                "code": {
                    "value": f.detector_name,
                    "url": format!(
                        "https://github.com/Bajuzjefe/Aikido-Security-Analysis-Platform/blob/main/docs/detectors/{}.md",
                        f.detector_name
                    )
                }
            });

            if let Some(ref loc) = f.location {
                let path = if let Some(root) = project_root {
                    loc.module_path
                        .strip_prefix(root)
                        .unwrap_or(&loc.module_path)
                        .trim_start_matches('/')
                        .to_string()
                } else {
                    loc.module_path.clone()
                };

                let mut range = serde_json::json!({
                    "start": {
                        "line": loc.line_start.unwrap_or(1),
                        "column": loc.column_start.unwrap_or(1)
                    }
                });

                if let Some(end_line) = loc.line_end {
                    range["end"] = serde_json::json!({
                        "line": end_line,
                        "column": loc.column_end.unwrap_or(1)
                    });
                }

                diag["location"] = serde_json::json!({
                    "path": path,
                    "range": range
                });
            }

            diag
        })
        .collect();

    let output = serde_json::json!({
        "source": {
            "name": "aikido",
            "url": "https://github.com/Bajuzjefe/Aikido-Security-Analysis-Platform"
        },
        "diagnostics": diagnostics
    });

    serde_json::to_string_pretty(&output).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detector::{Confidence, SourceLocation};

    #[test]
    fn test_rdjson_empty_findings() {
        let json_str = findings_to_rdjson(&[], None);
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        assert_eq!(parsed["source"]["name"], "aikido");
        assert_eq!(
            parsed["source"]["url"],
            "https://github.com/Bajuzjefe/Aikido-Security-Analysis-Platform"
        );
        assert!(parsed["diagnostics"].as_array().unwrap().is_empty());
    }

    #[test]
    fn test_rdjson_single_finding_with_location() {
        let finding = Finding {
            detector_name: "double-satisfaction".to_string(),
            severity: Severity::Critical,
            confidence: Confidence::Definite,
            title: "Double Satisfaction".to_string(),
            description: "Validator may be satisfied multiple times".to_string(),
            module: "test".to_string(),
            location: Some(SourceLocation {
                module_path: "/home/user/project/validators/test.ak".to_string(),
                byte_start: 100,
                byte_end: 200,
                line_start: Some(10),
                column_start: Some(5),
                line_end: Some(15),
                column_end: Some(1),
            }),
            suggestion: None,
            related_findings: vec![],
            semantic_group: None,

            evidence: None,
        };

        let json_str = findings_to_rdjson(&[finding], Some("/home/user/project"));
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();

        let diag = &parsed["diagnostics"][0];
        assert_eq!(diag["severity"], "ERROR");
        assert_eq!(diag["code"]["value"], "double-satisfaction");
        assert_eq!(diag["location"]["path"], "validators/test.ak");
        assert_eq!(diag["location"]["range"]["start"]["line"], 10);
        assert_eq!(diag["location"]["range"]["start"]["column"], 5);
    }
}
