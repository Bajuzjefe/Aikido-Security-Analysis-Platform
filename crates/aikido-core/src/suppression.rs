use crate::ast_walker::ModuleInfo;
use crate::detector::Finding;

/// A suppression entry with optional reason.
#[derive(Debug, Clone)]
pub struct SuppressionInfo {
    pub detector: Option<String>, // None = suppress all
    pub reason: Option<String>,
    pub line: usize,
    pub path: String,
}

/// Filter out findings that are suppressed by `// aikido:ignore` comments.
///
/// Supports these formats:
/// - `// aikido:ignore` — suppress all findings on the next line
/// - `// aikido:ignore <detector-name>` — suppress specific detector
/// - `// aikido:ignore[<detector-name>]` — bracket syntax
/// - `// aikido:ignore[<detector-name>] reason: <text>` — with reason tracking
///
/// Must be called AFTER `resolve_finding_locations()` since it needs line numbers.
pub fn filter_suppressed(findings: Vec<Finding>, modules: &[ModuleInfo]) -> Vec<Finding> {
    let (kept, _suppressed) = filter_suppressed_with_info(findings, modules);
    kept
}

/// Filter suppressed findings and return both kept and suppression info.
pub fn filter_suppressed_with_info(
    findings: Vec<Finding>,
    modules: &[ModuleInfo],
) -> (Vec<Finding>, Vec<SuppressionInfo>) {
    // Build a map of module path → source lines
    let source_map: std::collections::HashMap<&str, Vec<&str>> = modules
        .iter()
        .filter_map(|m| {
            m.source_code
                .as_deref()
                .map(|src| (m.path.as_str(), src.lines().collect()))
        })
        .collect();

    let mut kept = Vec::new();
    let mut suppressed = Vec::new();

    for finding in findings {
        let Some(ref loc) = finding.location else {
            kept.push(finding);
            continue;
        };
        let Some(line) = loc.line_start else {
            kept.push(finding);
            continue;
        };
        let Some(lines) = source_map.get(loc.module_path.as_str()) else {
            kept.push(finding);
            continue;
        };

        // Scan preceding comment lines and the same line for suppression comments.
        // Walk upward from the line before the finding, collecting all consecutive
        // aikido:ignore comments. This handles --fix stacking multiple comments.
        let mut was_suppressed = false;

        // First check the same line (inline suppression)
        if let Some(src_line) = line.checked_sub(1).and_then(|i| lines.get(i)) {
            if let Some(sup) = parse_suppression(src_line) {
                match sup {
                    Suppression::All { reason } => {
                        suppressed.push(SuppressionInfo {
                            detector: None,
                            reason: reason.map(|s| s.to_string()),
                            line,
                            path: loc.module_path.clone(),
                        });
                        was_suppressed = true;
                    }
                    Suppression::Detector { name, reason } => {
                        if name == finding.detector_name {
                            suppressed.push(SuppressionInfo {
                                detector: Some(name.to_string()),
                                reason: reason.map(|s| s.to_string()),
                                line,
                                path: loc.module_path.clone(),
                            });
                            was_suppressed = true;
                        }
                    }
                }
            }
        }

        // Walk upward through consecutive comment lines before the finding
        if !was_suppressed {
            let mut check_idx = line.checked_sub(2); // line before (0-based)
            while let Some(idx) = check_idx {
                let Some(src_line) = lines.get(idx) else {
                    break;
                };
                // Stop if this line is not a comment (only scan consecutive comments)
                if !src_line.trim().starts_with("//") {
                    break;
                }
                if let Some(sup) = parse_suppression(src_line) {
                    match sup {
                        Suppression::All { reason } => {
                            suppressed.push(SuppressionInfo {
                                detector: None,
                                reason: reason.map(|s| s.to_string()),
                                line,
                                path: loc.module_path.clone(),
                            });
                            was_suppressed = true;
                            break;
                        }
                        Suppression::Detector { name, reason } => {
                            if name == finding.detector_name {
                                suppressed.push(SuppressionInfo {
                                    detector: Some(name.to_string()),
                                    reason: reason.map(|s| s.to_string()),
                                    line,
                                    path: loc.module_path.clone(),
                                });
                                was_suppressed = true;
                                break;
                            }
                        }
                    }
                }
                check_idx = idx.checked_sub(1);
            }
        }

        if !was_suppressed {
            kept.push(finding);
        }
    }

    (kept, suppressed)
}

enum Suppression<'a> {
    All {
        reason: Option<&'a str>,
    },
    Detector {
        name: &'a str,
        reason: Option<&'a str>,
    },
}

fn parse_suppression(line: &str) -> Option<Suppression<'_>> {
    let trimmed = line.trim();

    // Look for `// aikido:ignore` anywhere in the line
    let marker = "// aikido:ignore";
    let idx = trimmed.find(marker)?;
    let rest = &trimmed[idx + marker.len()..];

    // Bracket syntax: // aikido:ignore[detector-name] reason: text
    if let Some(bracket_rest) = rest.strip_prefix('[') {
        let close_idx = bracket_rest.find(']')?;
        let detector_name = bracket_rest[..close_idx].trim();
        let after_bracket = bracket_rest[close_idx + 1..].trim();

        let reason = after_bracket
            .strip_prefix("reason:")
            .map(|r| r.trim())
            .filter(|r| !r.is_empty());

        if detector_name.is_empty() {
            Some(Suppression::All { reason })
        } else {
            Some(Suppression::Detector {
                name: detector_name,
                reason,
            })
        }
    } else if rest.is_empty() || rest.starts_with(char::is_whitespace) {
        // Space syntax: // aikido:ignore detector-name
        let after = rest.trim();
        if after.is_empty() {
            Some(Suppression::All { reason: None })
        } else {
            // Check for reason in space syntax: // aikido:ignore detector-name reason: text
            // Split at first "reason:" if present
            if let Some(reason_idx) = after.find("reason:") {
                let detector_name = after[..reason_idx].trim();
                let reason_text = after[reason_idx + 7..].trim();
                let reason = if reason_text.is_empty() {
                    None
                } else {
                    Some(reason_text)
                };
                if detector_name.is_empty() {
                    Some(Suppression::All { reason })
                } else {
                    Some(Suppression::Detector {
                        name: detector_name,
                        reason,
                    })
                }
            } else {
                Some(Suppression::Detector {
                    name: after,
                    reason: None,
                })
            }
        }
    } else {
        None // Not a valid suppression (e.g., "// aikido:ignored")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detector::{Confidence, Severity, SourceLocation};

    fn make_finding(detector: &str, path: &str, line: usize) -> Finding {
        Finding {
            detector_name: detector.to_string(),
            severity: Severity::High,
            confidence: Confidence::Likely,
            title: "Test finding".to_string(),
            description: "Test".to_string(),
            module: "test".to_string(),
            location: Some(SourceLocation {
                module_path: path.to_string(),
                byte_start: 0,
                byte_end: 0,
                line_start: Some(line),
                column_start: Some(1),
                line_end: Some(line),
                column_end: Some(1),
            }),
            suggestion: None,
            related_findings: vec![],
            semantic_group: None,

            evidence: None,
        }
    }

    fn make_module(path: &str, source: &str) -> ModuleInfo {
        ModuleInfo {
            name: "test".to_string(),
            path: path.to_string(),
            kind: crate::ast_walker::ModuleKind::Validator,
            validators: vec![],
            data_types: vec![],
            functions: vec![],
            constants: vec![],
            type_aliases: vec![],
            test_count: 0,
            test_function_names: vec![],
            source_code: Some(source.to_string()),
        }
    }

    #[test]
    fn test_suppress_all_on_line_before() {
        let source = "// aikido:ignore\nlet x = 42";
        let modules = vec![make_module("test.ak", source)];
        let findings = vec![make_finding("any-detector", "test.ak", 2)];

        let result = filter_suppressed(findings, &modules);
        assert!(result.is_empty());
    }

    #[test]
    fn test_suppress_specific_detector() {
        let source = "// aikido:ignore double-satisfaction\nlet x = 42";
        let modules = vec![make_module("test.ak", source)];

        let f1 = make_finding("double-satisfaction", "test.ak", 2);
        let f2 = make_finding("missing-signature-check", "test.ak", 2);
        let findings = vec![f1, f2];

        let result = filter_suppressed(findings, &modules);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].detector_name, "missing-signature-check");
    }

    #[test]
    fn test_no_suppression_without_comment() {
        let source = "let x = 42\nlet y = 43";
        let modules = vec![make_module("test.ak", source)];
        let findings = vec![make_finding("any-detector", "test.ak", 2)];

        let result = filter_suppressed(findings, &modules);
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn test_no_location_keeps_finding() {
        let modules = vec![make_module("test.ak", "// aikido:ignore\nfoo")];
        let finding = Finding {
            detector_name: "test".to_string(),
            severity: Severity::High,
            confidence: Confidence::Likely,
            title: "Test".to_string(),
            description: "Test".to_string(),
            module: "test".to_string(),
            location: None,
            suggestion: None,
            related_findings: vec![],
            semantic_group: None,

            evidence: None,
        };

        let result = filter_suppressed(vec![finding], &modules);
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn test_parse_suppression_variants() {
        assert!(parse_suppression("  // aikido:ignore").is_some());
        assert!(parse_suppression("  // aikido:ignore double-satisfaction").is_some());
        assert!(parse_suppression("// not a suppression").is_none());
        assert!(parse_suppression("// aikido:ignored").is_none());
    }

    #[test]
    fn test_bracket_syntax() {
        let source = "// aikido:ignore[double-satisfaction]\nlet x = 42";
        let modules = vec![make_module("test.ak", source)];

        let f1 = make_finding("double-satisfaction", "test.ak", 2);
        let f2 = make_finding("missing-signature-check", "test.ak", 2);
        let findings = vec![f1, f2];

        let result = filter_suppressed(findings, &modules);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].detector_name, "missing-signature-check");
    }

    #[test]
    fn test_bracket_syntax_with_reason() {
        let source =
            "// aikido:ignore[double-satisfaction] reason: own_ref checked in helper\nlet x = 42";
        let modules = vec![make_module("test.ak", source)];

        let findings = vec![make_finding("double-satisfaction", "test.ak", 2)];
        let (kept, suppressed) = filter_suppressed_with_info(findings, &modules);

        assert!(kept.is_empty());
        assert_eq!(suppressed.len(), 1);
        assert_eq!(
            suppressed[0].detector.as_deref(),
            Some("double-satisfaction")
        );
        assert_eq!(
            suppressed[0].reason.as_deref(),
            Some("own_ref checked in helper")
        );
    }

    #[test]
    fn test_bracket_empty_suppresses_all() {
        let source = "// aikido:ignore[]\nlet x = 42";
        let modules = vec![make_module("test.ak", source)];
        let findings = vec![make_finding("any-detector", "test.ak", 2)];

        let result = filter_suppressed(findings, &modules);
        assert!(result.is_empty());
    }

    #[test]
    fn test_space_syntax_with_reason() {
        let source = "// aikido:ignore double-satisfaction reason: checked elsewhere\nlet x = 42";
        let modules = vec![make_module("test.ak", source)];
        let findings = vec![make_finding("double-satisfaction", "test.ak", 2)];

        let (kept, suppressed) = filter_suppressed_with_info(findings, &modules);
        assert!(kept.is_empty());
        assert_eq!(suppressed.len(), 1);
        assert_eq!(suppressed[0].reason.as_deref(), Some("checked elsewhere"));
    }

    #[test]
    fn test_suppression_info_captures_location() {
        let source = "// aikido:ignore[missing-signature-check]\nfn foo() { True }";
        let modules = vec![make_module("test.ak", source)];
        let findings = vec![make_finding("missing-signature-check", "test.ak", 2)];

        let (kept, suppressed) = filter_suppressed_with_info(findings, &modules);
        assert!(kept.is_empty());
        assert_eq!(suppressed.len(), 1);
        assert_eq!(suppressed[0].line, 2);
        assert_eq!(suppressed[0].path, "test.ak");
    }

    #[test]
    fn test_stacked_suppression_comments() {
        // When --fix inserts multiple suppression comments for same line,
        // all should be effective (not just the one immediately before)
        let source = "// aikido:ignore[double-satisfaction]\n// aikido:ignore[missing-signature-check]\nlet x = 42";
        let modules = vec![make_module("test.ak", source)];

        let f1 = make_finding("double-satisfaction", "test.ak", 3);
        let f2 = make_finding("missing-signature-check", "test.ak", 3);
        let findings = vec![f1, f2];

        let result = filter_suppressed(findings, &modules);
        assert!(
            result.is_empty(),
            "Both stacked suppression comments should be effective, but {} findings remained",
            result.len()
        );
    }

    #[test]
    fn test_stacked_suppression_stops_at_non_comment() {
        // Suppression scanning stops at non-comment lines
        let source =
            "// aikido:ignore[double-satisfaction]\nlet y = 1\n// aikido:ignore[missing-signature-check]\nlet x = 42";
        let modules = vec![make_module("test.ak", source)];

        let f1 = make_finding("double-satisfaction", "test.ak", 4);
        let findings = vec![f1];

        let result = filter_suppressed(findings, &modules);
        assert_eq!(
            result.len(),
            1,
            "Suppression should not cross non-comment lines"
        );
    }
}
