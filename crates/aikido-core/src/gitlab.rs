use crate::detector::{Finding, Severity};

/// Generate GitLab SAST JSON format output.
/// See: https://docs.gitlab.com/ee/ci/yaml/artifacts_reports.html#artifactsreportssast
pub fn findings_to_gitlab_sast(findings: &[Finding]) -> String {
    let vulnerabilities: Vec<serde_json::Value> = findings
        .iter()
        .map(|f| {
            let mut vuln = serde_json::json!({
                "id": finding_id(f),
                "category": "sast",
                "name": f.title,
                "message": f.description,
                "description": f.description,
                "severity": gitlab_severity(&f.severity),
                "confidence": f.confidence.to_string().to_uppercase(),
                "scanner": {
                    "id": "aikido",
                    "name": "Aikido"
                },
                "identifiers": [{
                    "type": "aikido_rule",
                    "name": f.detector_name,
                    "value": f.detector_name,
                    "url": format!(
                        "https://github.com/Bajuzjefe/aikido/blob/main/docs/detectors/{}.md",
                        f.detector_name
                    )
                }]
            });

            if let Some(ref loc) = f.location {
                vuln["location"] = serde_json::json!({
                    "file": loc.module_path,
                    "start_line": loc.line_start.unwrap_or(1),
                    "end_line": loc.line_end.unwrap_or(1)
                });
            }

            if let Some(ref suggestion) = f.suggestion {
                vuln["solution"] = serde_json::Value::String(suggestion.clone());
            }

            if !f.related_findings.is_empty() {
                vuln["related_findings"] = serde_json::json!(f.related_findings);
            }

            vuln
        })
        .collect();

    let output = serde_json::json!({
        "version": "15.0.7",
        "vulnerabilities": vulnerabilities,
        "scan": {
            "scanner": {
                "id": "aikido",
                "name": "Aikido",
                "url": "https://github.com/Bajuzjefe/aikido",
                "vendor": {
                    "name": "aikido"
                },
                "version": "0.3.0"
            },
            "type": "sast",
            "status": "success"
        }
    });

    serde_json::to_string_pretty(&output).unwrap_or_default()
}

/// Map aikido Severity to GitLab severity string.
fn gitlab_severity(severity: &Severity) -> &'static str {
    match severity {
        Severity::Critical => "Critical",
        Severity::High => "High",
        Severity::Medium => "Medium",
        Severity::Low => "Low",
        Severity::Info => "Info",
    }
}

/// Generate a stable ID for a finding based on detector + module + location.
fn finding_id(f: &Finding) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut hasher = DefaultHasher::new();
    f.detector_name.hash(&mut hasher);
    f.module.hash(&mut hasher);
    if let Some(ref loc) = f.location {
        loc.byte_start.hash(&mut hasher);
    }
    format!("{:016x}", hasher.finish())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detector::{Confidence, SourceLocation};

    #[test]
    fn test_gitlab_sast_empty() {
        let json_str = findings_to_gitlab_sast(&[]);
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        assert_eq!(parsed["version"], "15.0.7");
        assert!(parsed["vulnerabilities"].as_array().unwrap().is_empty());
        assert_eq!(parsed["scan"]["scanner"]["id"], "aikido");
        assert_eq!(parsed["scan"]["type"], "sast");
    }

    #[test]
    fn test_gitlab_sast_with_finding() {
        let finding = Finding {
            detector_name: "double-satisfaction".to_string(),
            severity: Severity::Critical,
            confidence: Confidence::Definite,
            title: "Double Satisfaction Risk".to_string(),
            description: "Validator may be satisfied multiple times".to_string(),
            module: "test".to_string(),
            location: Some(SourceLocation {
                module_path: "validators/test.ak".to_string(),
                byte_start: 100,
                byte_end: 200,
                line_start: Some(10),
                column_start: Some(5),
                line_end: Some(15),
                column_end: Some(1),
            }),
            suggestion: Some("Use own_ref to prevent double spending".to_string()),
            related_findings: vec![],
            semantic_group: None,

            evidence: None,
        };

        let json_str = findings_to_gitlab_sast(&[finding]);
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();

        let vulns = parsed["vulnerabilities"].as_array().unwrap();
        assert_eq!(vulns.len(), 1);
        assert_eq!(vulns[0]["severity"], "Critical");
        assert_eq!(vulns[0]["category"], "sast");
        assert_eq!(vulns[0]["location"]["file"], "validators/test.ak");
        assert_eq!(vulns[0]["location"]["start_line"], 10);
        assert!(vulns[0]["solution"].as_str().unwrap().contains("own_ref"));
        assert_eq!(vulns[0]["identifiers"][0]["value"], "double-satisfaction");
    }

    #[test]
    fn test_gitlab_severity_mapping() {
        assert_eq!(gitlab_severity(&Severity::Critical), "Critical");
        assert_eq!(gitlab_severity(&Severity::High), "High");
        assert_eq!(gitlab_severity(&Severity::Medium), "Medium");
        assert_eq!(gitlab_severity(&Severity::Low), "Low");
        assert_eq!(gitlab_severity(&Severity::Info), "Info");
    }

    #[test]
    fn test_finding_id_stable() {
        let f = Finding {
            detector_name: "test".to_string(),
            severity: Severity::Low,
            confidence: Confidence::Possible,
            title: "T".to_string(),
            description: "D".to_string(),
            module: "m".to_string(),
            location: None,
            suggestion: None,
            related_findings: vec![],
            semantic_group: None,

            evidence: None,
        };
        let id1 = finding_id(&f);
        let id2 = finding_id(&f);
        assert_eq!(id1, id2);
        assert_eq!(id1.len(), 16);
    }
}
