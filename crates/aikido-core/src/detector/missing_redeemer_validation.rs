use crate::ast_walker::{ModuleInfo, ModuleKind};
use crate::delegation::build_delegation_set;
use crate::detector::{Confidence, Detector, Finding, Severity, SourceLocation};

pub struct MissingRedeemerValidation;

impl Detector for MissingRedeemerValidation {
    fn name(&self) -> &str {
        "missing-redeemer-validation"
    }

    fn description(&self) -> &str {
        "Detects catch-all redeemer patterns that trivially return True"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn long_description(&self) -> &str {
        "Redeemer validation ensures each action variant is handled with appropriate logic. \
        A catch-all pattern that returns True (e.g., `_ -> True`) bypasses all validation, \
        allowing any redeemer to succeed. Even named branches returning True without logic \
        indicate missing validation.\n\n\
        Example (vulnerable):\n  when redeemer is {\n    Close -> True\n    _ -> True\n  }\n\n\
        Fix: Add meaningful validation logic for each redeemer variant."
    }

    fn cwe_id(&self) -> Option<&str> {
        Some("CWE-20")
    }

    fn category(&self) -> &str {
        "data-validation"
    }

    fn detect(&self, modules: &[ModuleInfo]) -> Vec<Finding> {
        let mut findings = Vec::new();
        let delegation_set = build_delegation_set(modules);

        for module in modules {
            if module.kind != ModuleKind::Validator {
                continue;
            }

            for validator in &module.validators {
                for handler in &validator.handlers {
                    let is_delegating = delegation_set.contains(&(
                        module.name.clone(),
                        validator.name.clone(),
                        handler.name.clone(),
                    ));

                    // Check if handler has pre-branch authorization guards.
                    // When `multisig.satisfied(...)` runs before the when statement,
                    // branches that return True are guarded by that check and not
                    // truly unvalidated. We only check for multisig/satisfied calls
                    // (not extra_signatories) because signatories can be checked
                    // inside a specific branch rather than as a pre-branch guard.
                    let signals = &handler.body_signals;
                    let has_pre_branch_auth = signals
                        .function_calls
                        .iter()
                        .any(|c| c.contains("multisig") || c.contains("satisfied"));

                    for branch in &handler.body_signals.when_branches {
                        if branch.is_catchall && branch.body_is_literal_true {
                            // Catch-all True is always suspicious, even with pre-branch auth
                            findings.push(Finding {
                                detector_name: self.name().to_string(),
                                severity: Severity::High,
                                confidence: Confidence::Definite,
                                title: format!(
                                    "Catch-all redeemer returns True in {}.{}",
                                    validator.name, handler.name
                                ),
                                description: format!(
                                    "Pattern '{}' catches all redeemer variants and trivially returns True, bypassing validation.",
                                    branch.pattern_text
                                ),
                                module: module.name.clone(),
                                location: handler.location.map(|(s, e)| {
                                    SourceLocation::from_bytes(&module.path, s, e)
                                }),
                                suggestion: Some(
                                    "Validate each redeemer variant explicitly with meaningful logic."
                                        .to_string(),
                                ),
                                related_findings: vec![],
                                semantic_group: None,

                                evidence: None,
                            });
                        } else if !branch.is_catchall
                            && branch.body_is_literal_true
                            && !has_pre_branch_auth
                            && !is_delegating
                        {
                            // Named branch True without pre-branch authorization is suspicious.
                            // But if there are signatory/multisig checks before the when,
                            // the branch is guarded and not truly unvalidated.
                            findings.push(Finding {
                                detector_name: self.name().to_string(),
                                severity: Severity::Medium,
                                confidence: Confidence::Likely,
                                title: format!(
                                    "Redeemer branch trivially returns True in {}.{}",
                                    validator.name, handler.name
                                ),
                                description: format!(
                                    "Pattern '{}' returns True without validation logic.",
                                    branch.pattern_text
                                ),
                                module: module.name.clone(),
                                location: handler
                                    .location
                                    .map(|(s, e)| SourceLocation::from_bytes(&module.path, s, e)),
                                suggestion: Some(
                                    "Add validation logic for this redeemer action.".to_string(),
                                ),
                                related_findings: vec![],
                                semantic_group: None,

                                evidence: None,
                            });
                        }
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
    use crate::ast_walker::{HandlerInfo, ValidatorInfo};
    use crate::body_analysis::{BodySignals, WhenBranchInfo};

    fn make_validator_module(handlers: Vec<HandlerInfo>) -> Vec<ModuleInfo> {
        vec![ModuleInfo {
            name: "test/validator".to_string(),
            path: "test.ak".to_string(),
            kind: ModuleKind::Validator,
            validators: vec![ValidatorInfo {
                name: "test_validator".to_string(),
                params: vec![],
                handlers,
                summary: None,
            }],
            data_types: vec![],
            functions: vec![],
            constants: vec![],
            type_aliases: vec![],
            test_count: 0,
            source_code: None,
            test_function_names: vec![],
        }]
    }

    #[test]
    fn test_detects_catchall_true() {
        let handler = HandlerInfo {
            name: "spend".to_string(),
            params: vec![],
            return_type: "Bool".to_string(),
            location: None,
            body_signals: BodySignals {
                when_branches: vec![WhenBranchInfo {
                    pattern_text: "_".to_string(),
                    is_catchall: true,
                    body_is_literal_true: true,
                    body_is_error: false,
                }],
                ..Default::default()
            },
        };

        let modules = make_validator_module(vec![handler]);
        let detector = MissingRedeemerValidation;
        let findings = detector.detect(&modules);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
        assert!(findings[0].title.contains("Catch-all"));
    }

    #[test]
    fn test_detects_named_branch_true() {
        let handler = HandlerInfo {
            name: "spend".to_string(),
            params: vec![],
            return_type: "Bool".to_string(),
            location: None,
            body_signals: BodySignals {
                when_branches: vec![WhenBranchInfo {
                    pattern_text: "Close".to_string(),
                    is_catchall: false,
                    body_is_literal_true: true,
                    body_is_error: false,
                }],
                ..Default::default()
            },
        };

        let modules = make_validator_module(vec![handler]);
        let detector = MissingRedeemerValidation;
        let findings = detector.detect(&modules);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Medium);
    }

    #[test]
    fn test_no_false_positive_on_proper_validation() {
        let handler = HandlerInfo {
            name: "spend".to_string(),
            params: vec![],
            return_type: "Bool".to_string(),
            location: None,
            body_signals: BodySignals {
                when_branches: vec![WhenBranchInfo {
                    pattern_text: "Close".to_string(),
                    is_catchall: false,
                    body_is_literal_true: false,
                    body_is_error: false,
                }],
                ..Default::default()
            },
        };

        let modules = make_validator_module(vec![handler]);
        let detector = MissingRedeemerValidation;
        let findings = detector.detect(&modules);

        assert!(findings.is_empty());
    }

    #[test]
    fn test_no_finding_named_branch_with_pre_branch_auth() {
        // Named branch True with pre-branch multisig auth should be suppressed
        let mut fns = std::collections::HashSet::new();
        fns.insert("multisig.satisfied".to_string());
        let handler = HandlerInfo {
            name: "else".to_string(),
            params: vec![],
            return_type: "Bool".to_string(),
            location: None,
            body_signals: BodySignals {
                when_branches: vec![WhenBranchInfo {
                    pattern_text: "Publishing(..)".to_string(),
                    is_catchall: false,
                    body_is_literal_true: true,
                    body_is_error: false,
                }],
                function_calls: fns,
                ..Default::default()
            },
        };

        let modules = make_validator_module(vec![handler]);
        let detector = MissingRedeemerValidation;
        let findings = detector.detect(&modules);
        assert!(
            findings.is_empty(),
            "named branch True with pre-branch auth should be suppressed"
        );
    }

    #[test]
    fn test_catchall_still_flagged_with_pre_branch_auth() {
        // Catch-all True should still be flagged even with pre-branch auth
        let mut fns = std::collections::HashSet::new();
        fns.insert("multisig.satisfied".to_string());
        let handler = HandlerInfo {
            name: "else".to_string(),
            params: vec![],
            return_type: "Bool".to_string(),
            location: None,
            body_signals: BodySignals {
                when_branches: vec![WhenBranchInfo {
                    pattern_text: "_".to_string(),
                    is_catchall: true,
                    body_is_literal_true: true,
                    body_is_error: false,
                }],
                function_calls: fns,
                ..Default::default()
            },
        };

        let modules = make_validator_module(vec![handler]);
        let detector = MissingRedeemerValidation;
        let findings = detector.detect(&modules);
        assert_eq!(findings.len(), 1, "catch-all True always flagged");
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn test_skips_lib_modules() {
        let modules = vec![ModuleInfo {
            name: "test/types".to_string(),
            path: "types.ak".to_string(),
            kind: ModuleKind::Lib,
            validators: vec![],
            data_types: vec![],
            functions: vec![],
            constants: vec![],
            type_aliases: vec![],
            test_count: 0,
            source_code: None,
            test_function_names: vec![],
        }];

        let detector = MissingRedeemerValidation;
        let findings = detector.detect(&modules);
        assert!(findings.is_empty());
    }
}
