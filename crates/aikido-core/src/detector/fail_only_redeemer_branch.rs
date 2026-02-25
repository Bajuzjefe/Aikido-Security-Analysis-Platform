use crate::ast_walker::{ModuleInfo, ModuleKind};
use crate::detector::{Confidence, Detector, Finding, Severity, SourceLocation};

pub struct FailOnlyRedeemerBranch;

impl Detector for FailOnlyRedeemerBranch {
    fn name(&self) -> &str {
        "fail-only-redeemer-branch"
    }

    fn description(&self) -> &str {
        "Detects redeemer when/match branches that always fail"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn long_description(&self) -> &str {
        "A redeemer branch that always calls `fail` or returns `False` is dead code. \
        This may indicate an incomplete implementation, a logic error, or a placeholder \
        that was never replaced with real validation logic. While not a direct vulnerability, \
        dead branches add confusion and may mask missing functionality.\n\n\
        Example:\n  when redeemer is {\n    \
        Close -> verify_close(datum, self)\n    \
        Update -> fail  // Dead branch - always fails\n  }\n\n\
        Fix: Implement the branch or remove it:\n  when redeemer is {\n    \
        Close -> verify_close(datum, self)\n    \
        Update -> verify_update(datum, redeemer, self)\n  }"
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
                    for branch in &handler.body_signals.when_branches {
                        // Skip catch-all branches that fail — that's a common "deny by default" pattern
                        if branch.is_catchall {
                            continue;
                        }

                        // Skip branches matching well-known Cardano type constructors
                        // that aren't redeemer actions (e.g., from `when credential is`)
                        if is_known_non_redeemer_constructor(&branch.pattern_text) {
                            continue;
                        }

                        if branch.body_is_error {
                            findings.push(Finding {
                                detector_name: self.name().to_string(),
                                severity: self.severity(),
                                confidence: Confidence::Likely,
                                title: format!(
                                    "Fail-only redeemer branch '{}' in {}.{}",
                                    branch.pattern_text, validator.name, handler.name
                                ),
                                description: format!(
                                    "Redeemer branch '{}' always fails. This is dead code \
                                    that may indicate incomplete implementation.",
                                    branch.pattern_text
                                ),
                                module: module.name.clone(),
                                location: handler.location.map(|(s, e)| {
                                    SourceLocation::from_bytes(&module.path, s, e)
                                }),
                                suggestion: Some(
                                    "Implement the branch logic or remove the unused redeemer variant."
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

/// Cardano type constructors that appear in `when` branches but aren't redeemer actions.
/// Pattern matching on these is normal control flow, not a dead redeemer branch.
const NON_REDEEMER_CONSTRUCTORS: &[&str] = &[
    "Script",
    "VerificationKey",
    "Inline",
    "DatumHash",
    "NoDatum",
    "Some",
    "None",
    "True",
    "False",
    "Finite",
    "PositiveInfinity",
    "NegativeInfinity",
];

fn is_known_non_redeemer_constructor(pattern: &str) -> bool {
    // Match the first word (constructor name before any fields)
    let first_word = pattern.split_whitespace().next().unwrap_or(pattern);
    // Also handle tuple patterns like "Script(hash)"
    let constructor = first_word.split('(').next().unwrap_or(first_word);
    NON_REDEEMER_CONSTRUCTORS.contains(&constructor)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast_walker::*;
    use crate::body_analysis::{BodySignals, WhenBranchInfo};

    fn make_handler_with_branches(branches: Vec<WhenBranchInfo>) -> Vec<ModuleInfo> {
        vec![ModuleInfo {
            name: "test/validator".to_string(),
            path: "validator.ak".to_string(),
            kind: ModuleKind::Validator,
            validators: vec![ValidatorInfo {
                name: "test_validator".to_string(),
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
    fn test_detects_fail_branch() {
        let branches = vec![
            WhenBranchInfo {
                pattern_text: "Close".to_string(),
                is_catchall: false,
                body_is_literal_true: false,
                body_is_error: false,
            },
            WhenBranchInfo {
                pattern_text: "Update".to_string(),
                is_catchall: false,
                body_is_literal_true: false,
                body_is_error: true,
            },
        ];

        let modules = make_handler_with_branches(branches);
        let findings = FailOnlyRedeemerBranch.detect(&modules);

        assert_eq!(findings.len(), 1);
        assert!(findings[0].title.contains("Update"));
    }

    #[test]
    fn test_skips_catchall_fail() {
        // A catch-all that fails is a valid "deny by default" pattern
        let branches = vec![
            WhenBranchInfo {
                pattern_text: "Close".to_string(),
                is_catchall: false,
                body_is_literal_true: false,
                body_is_error: false,
            },
            WhenBranchInfo {
                pattern_text: "_".to_string(),
                is_catchall: true,
                body_is_literal_true: false,
                body_is_error: true,
            },
        ];

        let modules = make_handler_with_branches(branches);
        let findings = FailOnlyRedeemerBranch.detect(&modules);

        assert!(findings.is_empty());
    }

    #[test]
    fn test_no_finding_for_working_branches() {
        let branches = vec![WhenBranchInfo {
            pattern_text: "Close".to_string(),
            is_catchall: false,
            body_is_literal_true: false,
            body_is_error: false,
        }];

        let modules = make_handler_with_branches(branches);
        let findings = FailOnlyRedeemerBranch.detect(&modules);

        assert!(findings.is_empty());
    }
}
