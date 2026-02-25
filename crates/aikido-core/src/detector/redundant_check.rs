use crate::ast_walker::{ModuleInfo, ModuleKind};
use crate::detector::{Confidence, Detector, Finding, Severity, SourceLocation};

pub struct RedundantCheck;

impl Detector for RedundantCheck {
    fn name(&self) -> &str {
        "redundant-check"
    }

    fn description(&self) -> &str {
        "Detects redeemer branches with trivially true conditions"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn long_description(&self) -> &str {
        "A redeemer branch that unconditionally returns `True` without any validation \
        is likely missing checks. This pattern makes the branch a no-op from a security \
        perspective, allowing anyone to use that redeemer action without constraints.\n\n\
        Fix: Add appropriate validation logic or remove the branch."
    }

    fn cwe_id(&self) -> Option<&str> {
        Some("CWE-570")
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
                    for branch in &handler.body_signals.when_branches {
                        if branch.is_catchall {
                            continue;
                        }

                        if branch.body_is_literal_true {
                            findings.push(Finding {
                                detector_name: self.name().to_string(),
                                severity: self.severity(),
                                confidence: Confidence::Likely,
                                title: format!(
                                    "Trivially true branch '{}' in {}.{}",
                                    branch.pattern_text, validator.name, handler.name
                                ),
                                description: format!(
                                    "Branch '{}' unconditionally returns True without \
                                    any validation. This effectively allows unrestricted \
                                    use of this redeemer action.",
                                    branch.pattern_text
                                ),
                                module: module.name.clone(),
                                location: handler
                                    .location
                                    .map(|(s, e)| SourceLocation::from_bytes(&module.path, s, e)),
                                suggestion: Some(
                                    "Add validation logic or remove the branch if it should not be allowed."
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
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast_walker::*;
    use crate::body_analysis::{BodySignals, WhenBranchInfo};

    fn make_module(branches: Vec<WhenBranchInfo>) -> Vec<ModuleInfo> {
        vec![ModuleInfo {
            name: "test/validator".to_string(),
            path: "validator.ak".to_string(),
            kind: ModuleKind::Validator,
            validators: vec![ValidatorInfo {
                name: "v".to_string(),
                params: vec![],
                handlers: vec![HandlerInfo {
                    name: "spend".to_string(),
                    params: vec![],
                    return_type: "Bool".to_string(),
                    location: None,
                    body_signals: BodySignals {
                        when_branches: branches,
                        ..Default::default()
                    },
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
        }]
    }

    #[test]
    fn test_detects_true_branch() {
        let modules = make_module(vec![WhenBranchInfo {
            pattern_text: "Deposit".to_string(),
            is_catchall: false,
            body_is_literal_true: true,
            body_is_error: false,
        }]);
        assert_eq!(RedundantCheck.detect(&modules).len(), 1);
    }

    #[test]
    fn test_no_finding_for_normal_branch() {
        let modules = make_module(vec![WhenBranchInfo {
            pattern_text: "Withdraw".to_string(),
            is_catchall: false,
            body_is_literal_true: false,
            body_is_error: false,
        }]);
        assert!(RedundantCheck.detect(&modules).is_empty());
    }

    #[test]
    fn test_skips_catchall_true() {
        let modules = make_module(vec![WhenBranchInfo {
            pattern_text: "_".to_string(),
            is_catchall: true,
            body_is_literal_true: true,
            body_is_error: false,
        }]);
        assert!(RedundantCheck.detect(&modules).is_empty());
    }
}
