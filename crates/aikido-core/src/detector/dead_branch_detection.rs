use crate::ast_walker::{ModuleInfo, ModuleKind};
use crate::detector::{Confidence, Detector, Finding, Severity, SourceLocation};

/// Detects unreachable or dead branches in validators.
///
/// Branches that always error (fail) with no path to success, or
/// when branches that duplicate other branches, indicate code issues.
pub struct DeadBranchDetection;

impl Detector for DeadBranchDetection {
    fn name(&self) -> &str {
        "dead-branch-detection"
    }

    fn description(&self) -> &str {
        "Identifies unreachable or always-failing branches"
    }

    fn severity(&self) -> Severity {
        Severity::Info
    }

    fn long_description(&self) -> &str {
        "Detects branches in when expressions that always fail/error, indicating \
        unreachable code or intentionally disabled functionality. While these may \
        be intentional (defense in depth), they can also indicate logic errors \
        or incomplete implementation."
    }

    fn cwe_id(&self) -> Option<&str> {
        Some("CWE-561")
    }

    fn category(&self) -> &str {
        "logic"
    }

    fn detect(&self, modules: &[ModuleInfo]) -> Vec<Finding> {
        let mut findings = Vec::new();

        for module in modules {
            if module.kind != ModuleKind::Validator {
                continue;
            }

            for validator in &module.validators {
                for handler in &validator.handlers {
                    let signals = &handler.body_signals;
                    let total_branches = signals.when_branches.len();

                    if total_branches < 2 {
                        continue;
                    }

                    let error_branches: Vec<_> = signals
                        .when_branches
                        .iter()
                        .filter(|b| b.body_is_error && !b.is_catchall)
                        .collect();

                    // If most non-catchall branches error, the remaining ones are suspicious
                    let non_catchall = signals
                        .when_branches
                        .iter()
                        .filter(|b| !b.is_catchall)
                        .count();

                    if !error_branches.is_empty()
                        && error_branches.len() == non_catchall.saturating_sub(1)
                    {
                        // All but one branch errors — this is normal (only one valid path)
                        continue;
                    }

                    // Flag individual error branches that aren't catchalls
                    for branch in &error_branches {
                        findings.push(Finding {
                            detector_name: self.name().to_string(),
                            severity: self.severity(),
                            confidence: Confidence::Possible,
                            title: format!(
                                "Branch '{}' always fails in {}.{}",
                                branch.pattern_text, validator.name, handler.name
                            ),
                            description: format!(
                                "The when branch matching '{}' in {}.{} always results in \
                                an error/fail. This may be intentional (disabled action) or \
                                indicate incomplete implementation.",
                                branch.pattern_text, validator.name, handler.name
                            ),
                            module: module.name.clone(),
                            location: handler
                                .location
                                .map(|(s, e)| SourceLocation::from_bytes(&module.path, s, e)),
                            suggestion: Some(
                                "If this action is intentionally disabled, consider removing \
                                it from the redeemer type to make the intent clear."
                                    .to_string(),
                            ),
                            related_findings: vec![],
                            semantic_group: None,

                            evidence: None,
                        });
                    }
                }
            }
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast_walker::*;
    use crate::body_analysis::{BodySignals, WhenBranchInfo};

    #[test]
    fn test_detects_error_branch() {
        let mut signals = BodySignals::default();
        signals.when_branches.push(WhenBranchInfo {
            pattern_text: "Update".to_string(),
            is_catchall: false,
            body_is_literal_true: false,
            body_is_error: false,
        });
        signals.when_branches.push(WhenBranchInfo {
            pattern_text: "Close".to_string(),
            is_catchall: false,
            body_is_literal_true: false,
            body_is_error: false,
        });
        signals.when_branches.push(WhenBranchInfo {
            pattern_text: "Disabled".to_string(),
            is_catchall: false,
            body_is_literal_true: false,
            body_is_error: true,
        });

        let modules = vec![ModuleInfo {
            name: "test/v".to_string(),
            path: "v.ak".to_string(),
            kind: ModuleKind::Validator,
            validators: vec![ValidatorInfo {
                name: "pool".to_string(),
                params: vec![],
                handlers: vec![HandlerInfo {
                    name: "spend".to_string(),
                    params: vec![],
                    return_type: "Bool".to_string(),
                    location: None,
                    body_signals: signals,
                }],
                summary: None,
            }],
            data_types: vec![],
            functions: vec![],
            constants: vec![],
            type_aliases: vec![],
            test_count: 0,
            source_code: None,
            test_function_names: vec![],
        }];

        let findings = DeadBranchDetection.detect(&modules);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].title.contains("Disabled"));
    }

    #[test]
    fn test_no_finding_for_single_branch() {
        let mut signals = BodySignals::default();
        signals.when_branches.push(WhenBranchInfo {
            pattern_text: "Update".to_string(),
            is_catchall: false,
            body_is_literal_true: false,
            body_is_error: false,
        });

        let modules = vec![ModuleInfo {
            name: "test/v".to_string(),
            path: "v.ak".to_string(),
            kind: ModuleKind::Validator,
            validators: vec![ValidatorInfo {
                name: "pool".to_string(),
                params: vec![],
                handlers: vec![HandlerInfo {
                    name: "spend".to_string(),
                    params: vec![],
                    return_type: "Bool".to_string(),
                    location: None,
                    body_signals: signals,
                }],
                summary: None,
            }],
            data_types: vec![],
            functions: vec![],
            constants: vec![],
            type_aliases: vec![],
            test_count: 0,
            source_code: None,
            test_function_names: vec![],
        }];

        let findings = DeadBranchDetection.detect(&modules);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_no_finding_when_all_but_one_error() {
        // Pattern: one valid path + rest error = normal defensive pattern
        let mut signals = BodySignals::default();
        signals.when_branches.push(WhenBranchInfo {
            pattern_text: "Update".to_string(),
            is_catchall: false,
            body_is_literal_true: false,
            body_is_error: false,
        });
        signals.when_branches.push(WhenBranchInfo {
            pattern_text: "Close".to_string(),
            is_catchall: false,
            body_is_literal_true: false,
            body_is_error: true,
        });

        let modules = vec![ModuleInfo {
            name: "test/v".to_string(),
            path: "v.ak".to_string(),
            kind: ModuleKind::Validator,
            validators: vec![ValidatorInfo {
                name: "pool".to_string(),
                params: vec![],
                handlers: vec![HandlerInfo {
                    name: "spend".to_string(),
                    params: vec![],
                    return_type: "Bool".to_string(),
                    location: None,
                    body_signals: signals,
                }],
                summary: None,
            }],
            data_types: vec![],
            functions: vec![],
            constants: vec![],
            type_aliases: vec![],
            test_count: 0,
            source_code: None,
            test_function_names: vec![],
        }];

        let findings = DeadBranchDetection.detect(&modules);
        assert!(findings.is_empty());
    }
}
