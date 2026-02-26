use crate::detector::Finding;

/// Generate CSV output from findings.
/// Format: detector,severity,confidence,title,module,file,line_start,line_end
pub fn findings_to_csv(findings: &[Finding]) -> String {
    let mut lines = Vec::with_capacity(findings.len() + 1);

    // Header
    lines.push(
        "detector,severity,confidence,title,description,module,file,line_start,line_end,related_findings"
            .to_string(),
    );

    for f in findings {
        let file = f.location.as_ref().map_or("", |l| l.module_path.as_str());
        let line_start = f
            .location
            .as_ref()
            .and_then(|l| l.line_start)
            .map_or(String::new(), |l| l.to_string());
        let line_end = f
            .location
            .as_ref()
            .and_then(|l| l.line_end)
            .map_or(String::new(), |l| l.to_string());

        // Escape CSV fields that may contain commas or quotes
        let title = csv_escape(&f.title);
        let description = csv_escape(&f.description);
        let related = if f.related_findings.is_empty() {
            String::new()
        } else {
            csv_escape(&f.related_findings.join("; "))
        };

        lines.push(format!(
            "{},{},{},{},{},{},{},{},{},{}",
            f.detector_name,
            f.severity.to_string().to_lowercase(),
            f.confidence.to_string().to_lowercase(),
            title,
            description,
            f.module,
            file,
            line_start,
            line_end,
            related
        ));
    }

    lines.join("\n")
}

/// Escape a field for CSV: wrap in quotes if it contains comma, quote, or newline.
fn csv_escape(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detector::{Confidence, Severity, SourceLocation};

    #[test]
    fn test_csv_empty_findings() {
        let csv = findings_to_csv(&[]);
        assert_eq!(
            csv,
            "detector,severity,confidence,title,description,module,file,line_start,line_end,related_findings"
        );
    }

    #[test]
    fn test_csv_single_finding() {
        let finding = Finding {
            detector_name: "double-satisfaction".to_string(),
            severity: Severity::Critical,
            confidence: Confidence::Definite,
            title: "Double Satisfaction".to_string(),
            description: "Desc".to_string(),
            module: "test/validator".to_string(),
            location: Some(SourceLocation {
                module_path: "validators/test.ak".to_string(),
                byte_start: 0,
                byte_end: 100,
                line_start: Some(10),
                column_start: Some(1),
                line_end: Some(15),
                column_end: Some(1),
            }),
            suggestion: None,
            related_findings: vec![],
            semantic_group: None,

            evidence: None,
        };

        let csv = findings_to_csv(&[finding]);
        let lines: Vec<&str> = csv.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[1].starts_with("double-satisfaction,critical,definite,"));
        assert!(lines[1].contains("validators/test.ak"));
        assert!(lines[1].contains(",10,15"));
    }

    #[test]
    fn test_csv_escapes_commas_in_title() {
        let finding = Finding {
            detector_name: "test".to_string(),
            severity: Severity::Low,
            confidence: Confidence::Possible,
            title: "Title, with comma".to_string(),
            description: "Desc".to_string(),
            module: "mod".to_string(),
            location: None,
            suggestion: None,
            related_findings: vec![],
            semantic_group: None,

            evidence: None,
        };

        let csv = findings_to_csv(&[finding]);
        assert!(csv.contains("\"Title, with comma\""));
    }

    #[test]
    fn test_csv_no_location() {
        let finding = Finding {
            detector_name: "test".to_string(),
            severity: Severity::Info,
            confidence: Confidence::Possible,
            title: "No location".to_string(),
            description: "Desc".to_string(),
            module: "mod".to_string(),
            location: None,
            suggestion: None,
            related_findings: vec![],
            semantic_group: None,

            evidence: None,
        };

        let csv = findings_to_csv(&[finding]);
        let lines: Vec<&str> = csv.lines().collect();
        assert!(lines[1].ends_with(",mod,,,,"));
        assert!(lines[1].contains(",Desc,"));
    }
}
