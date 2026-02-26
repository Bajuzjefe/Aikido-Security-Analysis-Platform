use std::collections::HashMap;

use serde::Serialize;

use crate::ast_walker::ModuleInfo;
use crate::detector::{all_detectors, Finding, Severity};
use crate::evidence::evidence_to_sarif_code_flow;

/// SARIF v2.1.0 output format.
/// See: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifLog {
    #[serde(rename = "$schema")]
    pub schema: String,
    pub version: String,
    pub runs: Vec<SarifRun>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifRun {
    pub tool: SarifTool,
    pub results: Vec<SarifResult>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifTool {
    pub driver: SarifDriver,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifDriver {
    pub name: String,
    pub version: String,
    pub information_uri: String,
    pub rules: Vec<SarifRule>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifRule {
    pub id: String,
    pub short_description: SarifMessage,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub help_uri: Option<String>,
    pub default_configuration: SarifDefaultConfig,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<SarifRuleProperties>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifRuleProperties {
    /// Numeric security severity (0.0-10.0) for GitHub Security tab categorization.
    #[serde(rename = "security-severity")]
    pub security_severity: String,
    /// Tags including CWE references and category.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifDefaultConfig {
    pub level: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifResult {
    pub rule_id: String,
    pub level: String,
    pub message: SarifMessage,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub locations: Vec<SarifLocation>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub related_locations: Vec<SarifRelatedLocation>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub code_flows: Vec<SarifCodeFlow>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub partial_fingerprints: Option<SarifPartialFingerprints>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<SarifResultProperties>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifResultProperties {
    /// Numeric security severity (0.0-10.0) for this specific result.
    #[serde(rename = "security-severity")]
    pub security_severity: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifPartialFingerprints {
    /// Hash of the primary location line content for stable dedup across runs.
    #[serde(rename = "primaryLocationLineHash")]
    pub primary_location_line_hash: String,
}

/// Code flow showing step-by-step execution path to a vulnerability.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifCodeFlow {
    pub thread_flows: Vec<SarifThreadFlow>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifThreadFlow {
    pub locations: Vec<SarifThreadFlowLocation>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifThreadFlowLocation {
    pub location: SarifLocation,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<SarifMessage>,
}

/// Related location linking findings to datum definitions, helper functions, etc.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifRelatedLocation {
    pub id: usize,
    pub physical_location: SarifPhysicalLocation,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<SarifMessage>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifMessage {
    pub text: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifLocation {
    pub physical_location: SarifPhysicalLocation,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifPhysicalLocation {
    pub artifact_location: SarifArtifactLocation,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region: Option<SarifRegion>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifArtifactLocation {
    pub uri: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifRegion {
    pub start_line: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_column: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_line: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_column: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snippet: Option<SarifSnippet>,
}

/// Embedded source code snippet in SARIF region.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifSnippet {
    pub text: String,
}

fn severity_to_sarif_level(severity: &Severity) -> &'static str {
    match severity {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low | Severity::Info => "note",
    }
}

/// Map severity to a numeric 0.0-10.0 security severity score.
fn severity_to_numeric(severity: &Severity) -> &'static str {
    match severity {
        Severity::Critical => "9.5",
        Severity::High => "7.5",
        Severity::Medium => "5.0",
        Severity::Low => "3.0",
        Severity::Info => "1.0",
    }
}

/// Compute a stable fingerprint hash from finding location content.
fn compute_line_hash(finding: &Finding, source_map: &HashMap<&str, &str>) -> Option<String> {
    let loc = finding.location.as_ref()?;
    let line_num = loc.line_start?;
    let source = source_map.get(loc.module_path.as_str())?;
    let line_content = source.lines().nth(line_num.saturating_sub(1))?;

    // Simple hash: detector name + file + line content
    let input = format!(
        "{}:{}:{}",
        finding.detector_name,
        loc.module_path,
        line_content.trim()
    );
    let hash = simple_hash(&input);
    Some(format!("{hash:016x}"))
}

/// Simple non-cryptographic hash for fingerprinting.
fn simple_hash(s: &str) -> u64 {
    let mut hash: u64 = 5381;
    for byte in s.bytes() {
        hash = hash.wrapping_mul(33).wrapping_add(u64::from(byte));
    }
    hash
}

/// Extract a snippet of the finding's primary location from source.
fn extract_snippet(finding: &Finding, source_map: &HashMap<&str, &str>) -> Option<String> {
    let loc = finding.location.as_ref()?;
    let line_num = loc.line_start?;
    let source = source_map.get(loc.module_path.as_str())?;
    let lines: Vec<&str> = source.lines().collect();
    let end_line = loc.line_end.unwrap_or(line_num);

    let start_idx = line_num.saturating_sub(1);
    let end_idx = end_line.min(lines.len());

    if start_idx >= lines.len() {
        return None;
    }

    let snippet_lines: Vec<&str> = lines[start_idx..end_idx].to_vec();
    Some(snippet_lines.join("\n"))
}

/// Convert a finding's evidence into SARIF codeFlows, if evidence with code flow steps is present.
fn build_code_flows_from_evidence(finding: &Finding) -> Vec<SarifCodeFlow> {
    let Some(ref evidence) = finding.evidence else {
        return vec![];
    };

    if evidence.code_flow.is_empty() {
        return vec![];
    }

    let sarif_json = evidence_to_sarif_code_flow(evidence);
    let Some(flows_array) = sarif_json.as_array() else {
        return vec![];
    };

    flows_array
        .iter()
        .filter_map(|flow| {
            let thread_flows = flow.get("threadFlows")?.as_array()?;
            let sarif_thread_flows: Vec<SarifThreadFlow> = thread_flows
                .iter()
                .filter_map(|tf| {
                    let locs = tf.get("locations")?.as_array()?;
                    let sarif_locs: Vec<SarifThreadFlowLocation> = locs
                        .iter()
                        .filter_map(|loc_entry| {
                            let phys = loc_entry.get("location")?.get("physicalLocation")?;
                            let uri = phys
                                .get("artifactLocation")?
                                .get("uri")?
                                .as_str()?
                                .to_string();

                            let region = phys.get("region").and_then(|r| {
                                let start_line = r.get("startLine")?.as_u64()? as usize;
                                Some(SarifRegion {
                                    start_line,
                                    start_column: r
                                        .get("startColumn")
                                        .and_then(|v| v.as_u64())
                                        .map(|v| v as usize),
                                    end_line: r
                                        .get("endLine")
                                        .and_then(|v| v.as_u64())
                                        .map(|v| v as usize),
                                    end_column: r
                                        .get("endColumn")
                                        .and_then(|v| v.as_u64())
                                        .map(|v| v as usize),
                                    snippet: None,
                                })
                            });

                            let message = loc_entry.get("message").and_then(|m| {
                                Some(SarifMessage {
                                    text: m.get("text")?.as_str()?.to_string(),
                                })
                            });

                            Some(SarifThreadFlowLocation {
                                location: SarifLocation {
                                    physical_location: SarifPhysicalLocation {
                                        artifact_location: SarifArtifactLocation { uri },
                                        region,
                                    },
                                },
                                message,
                            })
                        })
                        .collect();
                    Some(SarifThreadFlow {
                        locations: sarif_locs,
                    })
                })
                .collect();
            Some(SarifCodeFlow {
                thread_flows: sarif_thread_flows,
            })
        })
        .collect()
}

/// Generate SARIF JSON from findings.
/// If `project_root` is provided, file paths will be made relative to it.
/// If `modules` is provided, source code snippets and fingerprints will be included.
pub fn findings_to_sarif(
    findings: &[Finding],
    project_root: Option<&str>,
    modules: &[ModuleInfo],
) -> String {
    let detectors = all_detectors();

    // Build source map for snippets and fingerprints
    let source_map: HashMap<&str, &str> = modules
        .iter()
        .filter_map(|m| m.source_code.as_deref().map(|src| (m.path.as_str(), src)))
        .collect();

    let rules: Vec<SarifRule> = detectors
        .iter()
        .map(|d| {
            let mut tags = Vec::new();
            tags.push("security".to_string());
            tags.push(d.category().to_string());
            if let Some(cwe) = d.cwe_id() {
                tags.push(format!("external/cwe/{}", cwe.to_lowercase()));
            }

            SarifRule {
                id: d.name().to_string(),
                short_description: SarifMessage {
                    text: d.description().to_string(),
                },
                help_uri: Some(d.doc_url()),
                default_configuration: SarifDefaultConfig {
                    level: severity_to_sarif_level(&d.severity()).to_string(),
                },
                properties: Some(SarifRuleProperties {
                    security_severity: severity_to_numeric(&d.severity()).to_string(),
                    tags,
                }),
            }
        })
        .collect();

    let results: Vec<SarifResult> = findings
        .iter()
        .map(|f| {
            let (locations, snippet_region) = if let Some(ref loc) = f.location {
                let snippet = extract_snippet(f, &source_map);
                let region = loc.line_start.map(|line| SarifRegion {
                    start_line: line,
                    start_column: loc.column_start,
                    end_line: loc.line_end,
                    end_column: loc.column_end,
                    snippet: snippet.map(|text| SarifSnippet { text }),
                });

                // Make path relative if project_root is provided
                let uri = if let Some(root) = project_root {
                    loc.module_path
                        .strip_prefix(root)
                        .unwrap_or(&loc.module_path)
                        .trim_start_matches('/')
                        .to_string()
                } else {
                    loc.module_path.clone()
                };

                (
                    vec![SarifLocation {
                        physical_location: SarifPhysicalLocation {
                            artifact_location: SarifArtifactLocation { uri },
                            region,
                        },
                    }],
                    true,
                )
            } else {
                (vec![], false)
            };

            // Compute partial fingerprint for stable dedup
            let partial_fingerprints =
                compute_line_hash(f, &source_map).map(|hash| SarifPartialFingerprints {
                    primary_location_line_hash: hash,
                });

            SarifResult {
                rule_id: f.detector_name.clone(),
                level: severity_to_sarif_level(&f.severity).to_string(),
                message: SarifMessage {
                    text: if f.related_findings.is_empty() {
                        format!("{}\n{}", f.title, f.description)
                    } else {
                        format!(
                            "{}\n{}\n(also covers: {})",
                            f.title,
                            f.description,
                            f.related_findings.join(", ")
                        )
                    },
                },
                locations,
                related_locations: vec![],
                code_flows: build_code_flows_from_evidence(f),
                partial_fingerprints,
                properties: if snippet_region {
                    Some(SarifResultProperties {
                        security_severity: severity_to_numeric(&f.severity).to_string(),
                    })
                } else {
                    None
                },
            }
        })
        .collect();

    let log = SarifLog {
        schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json".to_string(),
        version: "2.1.0".to_string(),
        runs: vec![SarifRun {
            tool: SarifTool {
                driver: SarifDriver {
                    name: "aikido".to_string(),
                    version: "0.3.0".to_string(),
                    information_uri: "https://github.com/Bajuzjefe/aikido".to_string(),
                    rules,
                },
            },
            results,
        }],
    };

    serde_json::to_string_pretty(&log).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detector::{Confidence, SourceLocation};

    #[test]
    fn test_sarif_empty_findings() {
        let sarif = findings_to_sarif(&[], None, &[]);
        let parsed: serde_json::Value = serde_json::from_str(&sarif).unwrap();
        assert_eq!(parsed["version"], "2.1.0");
        assert!(parsed["runs"][0]["results"].as_array().unwrap().is_empty());
        // Rules should still list all detectors
        assert!(!parsed["runs"][0]["tool"]["driver"]["rules"]
            .as_array()
            .unwrap()
            .is_empty());
    }

    #[test]
    fn test_sarif_with_finding() {
        let finding = Finding {
            detector_name: "double-satisfaction".to_string(),
            severity: Severity::Critical,
            confidence: Confidence::Definite,
            title: "Test finding".to_string(),
            description: "Test description".to_string(),
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
            suggestion: None,
            related_findings: vec![],
            semantic_group: None,

            evidence: None,
        };

        let sarif = findings_to_sarif(&[finding], None, &[]);
        let parsed: serde_json::Value = serde_json::from_str(&sarif).unwrap();

        let result = &parsed["runs"][0]["results"][0];
        assert_eq!(result["ruleId"], "double-satisfaction");
        assert_eq!(result["level"], "error");
        assert_eq!(
            result["locations"][0]["physicalLocation"]["region"]["startLine"],
            10
        );
    }

    #[test]
    fn test_sarif_relative_paths() {
        let finding = Finding {
            detector_name: "test".to_string(),
            severity: Severity::Medium,
            confidence: Confidence::Likely,
            title: "Test".to_string(),
            description: "Desc".to_string(),
            module: "test".to_string(),
            location: Some(SourceLocation {
                module_path: "/home/user/project/validators/test.ak".to_string(),
                byte_start: 0,
                byte_end: 10,
                line_start: Some(1),
                column_start: Some(1),
                line_end: Some(1),
                column_end: Some(10),
            }),
            suggestion: None,
            related_findings: vec![],
            semantic_group: None,

            evidence: None,
        };

        let sarif = findings_to_sarif(&[finding], Some("/home/user/project"), &[]);
        let parsed: serde_json::Value = serde_json::from_str(&sarif).unwrap();
        let uri = parsed["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
            ["artifactLocation"]["uri"]
            .as_str()
            .unwrap();
        assert_eq!(uri, "validators/test.ak");
    }

    #[test]
    fn test_sarif_severity_mapping() {
        assert_eq!(severity_to_sarif_level(&Severity::Critical), "error");
        assert_eq!(severity_to_sarif_level(&Severity::High), "error");
        assert_eq!(severity_to_sarif_level(&Severity::Medium), "warning");
        assert_eq!(severity_to_sarif_level(&Severity::Low), "note");
        assert_eq!(severity_to_sarif_level(&Severity::Info), "note");
    }

    #[test]
    fn test_sarif_without_location() {
        let finding = Finding {
            detector_name: "test".to_string(),
            severity: Severity::Medium,
            confidence: Confidence::Likely,
            title: "No location".to_string(),
            description: "Desc".to_string(),
            module: "test".to_string(),
            location: None,
            suggestion: None,
            related_findings: vec![],
            semantic_group: None,

            evidence: None,
        };

        let sarif = findings_to_sarif(&[finding], None, &[]);
        let parsed: serde_json::Value = serde_json::from_str(&sarif).unwrap();
        let result = &parsed["runs"][0]["results"][0];
        // locations should be absent (empty array, skip_serializing_if)
        assert!(
            result["locations"].as_array().is_none()
                || result["locations"].as_array().unwrap().is_empty()
        );
    }

    #[test]
    fn test_sarif_rule_properties_cwe() {
        let sarif = findings_to_sarif(&[], None, &[]);
        let parsed: serde_json::Value = serde_json::from_str(&sarif).unwrap();
        let rules = parsed["runs"][0]["tool"]["driver"]["rules"]
            .as_array()
            .unwrap();

        // Find double-satisfaction rule
        let ds_rule = rules
            .iter()
            .find(|r| r["id"] == "double-satisfaction")
            .unwrap();
        let tags = ds_rule["properties"]["tags"].as_array().unwrap();
        let tag_strs: Vec<&str> = tags.iter().map(|t| t.as_str().unwrap()).collect();
        assert!(tag_strs.contains(&"security"));
        assert!(tag_strs.contains(&"authorization"));
        assert!(tag_strs.contains(&"external/cwe/cwe-362"));
    }

    #[test]
    fn test_sarif_security_severity_on_rules() {
        let sarif = findings_to_sarif(&[], None, &[]);
        let parsed: serde_json::Value = serde_json::from_str(&sarif).unwrap();
        let rules = parsed["runs"][0]["tool"]["driver"]["rules"]
            .as_array()
            .unwrap();

        // Critical detector should have 9.5
        let ds_rule = rules
            .iter()
            .find(|r| r["id"] == "double-satisfaction")
            .unwrap();
        assert_eq!(
            ds_rule["properties"]["security-severity"].as_str().unwrap(),
            "9.5"
        );

        // Medium detector should have 5.0
        let mvr_rule = rules
            .iter()
            .find(|r| r["id"] == "missing-validity-range")
            .unwrap();
        assert_eq!(
            mvr_rule["properties"]["security-severity"]
                .as_str()
                .unwrap(),
            "5.0"
        );
    }

    #[test]
    fn test_sarif_partial_fingerprints() {
        use crate::ast_walker::ModuleKind;

        let source = "line1\nline2\nline3\nline4\nline5";
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
            source_code: Some(source.to_string()),
        }];

        let finding = Finding {
            detector_name: "test-detector".to_string(),
            severity: Severity::High,
            confidence: Confidence::Likely,
            title: "Test".to_string(),
            description: "Desc".to_string(),
            module: "test".to_string(),
            location: Some(SourceLocation {
                module_path: "test.ak".to_string(),
                byte_start: 6,
                byte_end: 11,
                line_start: Some(2),
                column_start: Some(1),
                line_end: Some(2),
                column_end: Some(5),
            }),
            suggestion: None,
            related_findings: vec![],
            semantic_group: None,

            evidence: None,
        };

        let sarif = findings_to_sarif(&[finding], None, &modules);
        let parsed: serde_json::Value = serde_json::from_str(&sarif).unwrap();
        let result = &parsed["runs"][0]["results"][0];

        // Should have partial fingerprints
        assert!(result["partialFingerprints"]["primaryLocationLineHash"]
            .as_str()
            .is_some());
        let hash = result["partialFingerprints"]["primaryLocationLineHash"]
            .as_str()
            .unwrap();
        assert_eq!(hash.len(), 16); // 16 hex chars
    }

    #[test]
    fn test_sarif_snippet_text() {
        use crate::ast_walker::ModuleKind;

        let source = "fn foo() {\n  let x = 42\n  True\n}";
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
            source_code: Some(source.to_string()),
        }];

        let finding = Finding {
            detector_name: "test-detector".to_string(),
            severity: Severity::High,
            confidence: Confidence::Likely,
            title: "Test".to_string(),
            description: "Desc".to_string(),
            module: "test".to_string(),
            location: Some(SourceLocation {
                module_path: "test.ak".to_string(),
                byte_start: 0,
                byte_end: 10,
                line_start: Some(1),
                column_start: Some(1),
                line_end: Some(2),
                column_end: Some(14),
            }),
            suggestion: None,
            related_findings: vec![],
            semantic_group: None,

            evidence: None,
        };

        let sarif = findings_to_sarif(&[finding], None, &modules);
        let parsed: serde_json::Value = serde_json::from_str(&sarif).unwrap();
        let snippet = &parsed["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
            ["region"]["snippet"]["text"];
        assert!(snippet.as_str().is_some());
        assert!(snippet.as_str().unwrap().contains("fn foo()"));
    }

    #[test]
    fn test_sarif_result_security_severity() {
        let finding = Finding {
            detector_name: "test".to_string(),
            severity: Severity::High,
            confidence: Confidence::Likely,
            title: "Test".to_string(),
            description: "Desc".to_string(),
            module: "test".to_string(),
            location: Some(SourceLocation {
                module_path: "test.ak".to_string(),
                byte_start: 0,
                byte_end: 10,
                line_start: Some(1),
                column_start: Some(1),
                line_end: Some(1),
                column_end: Some(10),
            }),
            suggestion: None,
            related_findings: vec![],
            semantic_group: None,

            evidence: None,
        };

        let sarif = findings_to_sarif(&[finding], None, &[]);
        let parsed: serde_json::Value = serde_json::from_str(&sarif).unwrap();
        let result = &parsed["runs"][0]["results"][0];
        assert_eq!(
            result["properties"]["security-severity"].as_str().unwrap(),
            "7.5"
        );
    }

    #[test]
    fn test_sarif_numeric_severity_mapping() {
        assert_eq!(severity_to_numeric(&Severity::Critical), "9.5");
        assert_eq!(severity_to_numeric(&Severity::High), "7.5");
        assert_eq!(severity_to_numeric(&Severity::Medium), "5.0");
        assert_eq!(severity_to_numeric(&Severity::Low), "3.0");
        assert_eq!(severity_to_numeric(&Severity::Info), "1.0");
    }

    #[test]
    fn test_sarif_category_tags() {
        let sarif = findings_to_sarif(&[], None, &[]);
        let parsed: serde_json::Value = serde_json::from_str(&sarif).unwrap();
        let rules = parsed["runs"][0]["tool"]["driver"]["rules"]
            .as_array()
            .unwrap();

        // Verify different categories are present across rules
        let categories: Vec<&str> = rules
            .iter()
            .filter_map(|r| {
                r["properties"]["tags"]
                    .as_array()
                    .and_then(|tags| tags.get(1))
                    .and_then(|t| t.as_str())
            })
            .collect();
        assert!(categories.contains(&"authorization"));
        assert!(categories.contains(&"data-validation"));
        assert!(categories.contains(&"logic"));
        assert!(categories.contains(&"math"));
        assert!(categories.contains(&"resource"));
        assert!(categories.contains(&"configuration"));
    }

    #[test]
    fn test_simple_hash_deterministic() {
        let h1 = simple_hash("test input");
        let h2 = simple_hash("test input");
        assert_eq!(h1, h2);

        let h3 = simple_hash("different input");
        assert_ne!(h1, h3);
    }
}
