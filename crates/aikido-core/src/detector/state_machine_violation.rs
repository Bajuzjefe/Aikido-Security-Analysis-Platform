use crate::ast_walker::ModuleInfo;
use crate::delegation::build_delegation_set;
use crate::detector::{Confidence, Detector, Finding, Severity};
use crate::state_machine::{extract_state_machines, StateMachineIssueType};

/// Detects state machine violations: unhandled actions, always-succeeds branches, etc.
pub struct StateMachineViolation;

impl Detector for StateMachineViolation {
    fn name(&self) -> &str {
        "state-machine-violation"
    }

    fn description(&self) -> &str {
        "Detects state machine issues in redeemer handling"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn long_description(&self) -> &str {
        "Analyzes validator redeemer handling as a state machine. Detects: \
        unhandled redeemer actions, actions that always succeed without validation, \
        terminal actions without token burns, and catchall branches accepting unknown actions."
    }

    fn cwe_id(&self) -> Option<&str> {
        Some("CWE-754")
    }

    fn category(&self) -> &str {
        "logic"
    }

    fn detect(&self, modules: &[ModuleInfo]) -> Vec<Finding> {
        let mut findings = Vec::new();
        let delegation_set = build_delegation_set(modules);
        let machines = extract_state_machines(modules);

        for sm in &machines {
            // Skip state machines extracted from delegating handlers
            if delegation_set.contains(&(
                sm.module.clone(),
                sm.validator.clone(),
                sm.handler.clone(),
            )) {
                continue;
            }

            for issue in &sm.issues {
                let (severity, confidence) = match issue.issue_type {
                    StateMachineIssueType::UnhandledAction => (Severity::High, Confidence::Likely),
                    StateMachineIssueType::AlwaysSucceeds => (Severity::High, Confidence::Definite),
                    StateMachineIssueType::CatchallAcceptsUnknown => {
                        (Severity::High, Confidence::Likely)
                    }
                    StateMachineIssueType::TerminalWithoutBurn => {
                        (Severity::Medium, Confidence::Possible)
                    }
                    StateMachineIssueType::NonTerminalWithoutOutput => {
                        (Severity::Medium, Confidence::Possible)
                    }
                    _ => (Severity::Medium, Confidence::Possible),
                };

                findings.push(Finding {
                    detector_name: self.name().to_string(),
                    severity,
                    confidence,
                    title: format!(
                        "State machine issue: {} in {}.{}",
                        issue.action, sm.validator, sm.handler
                    ),
                    description: issue.description.clone(),
                    module: sm.module.clone(),
                    location: None,
                    suggestion: Some(match issue.issue_type {
                        StateMachineIssueType::UnhandledAction => {
                            format!("Add a when branch for the '{}' action.", issue.action)
                        }
                        StateMachineIssueType::AlwaysSucceeds => {
                            format!("Add validation logic to the '{}' branch.", issue.action)
                        }
                        StateMachineIssueType::CatchallAcceptsUnknown => {
                            "Replace catchall True with fail to reject unknown actions.".to_string()
                        }
                        StateMachineIssueType::TerminalWithoutBurn => {
                            "Access the mint field and verify tokens are burned.".to_string()
                        }
                        _ => "Review the state machine logic.".to_string(),
                    }),
                    related_findings: vec![],
                    semantic_group: Some("state-machine".to_string()),

                    evidence: None,
                });
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
    fn test_detects_always_succeeds() {
        let mut signals = BodySignals::default();
        signals.when_branches.push(WhenBranchInfo {
            pattern_text: "Update".to_string(),
            is_catchall: false,
            body_is_literal_true: true,
            body_is_error: false,
        });
        signals.when_branches.push(WhenBranchInfo {
            pattern_text: "Close".to_string(),
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
                    params: vec![
                        ParamInfo {
                            name: "datum".to_string(),
                            type_name: "D".to_string(),
                        },
                        ParamInfo {
                            name: "redeemer".to_string(),
                            type_name: "R".to_string(),
                        },
                    ],
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
        let findings = StateMachineViolation.detect(&modules);
        assert!(
            findings.iter().any(|f| f.title.contains("Update")),
            "should deterministically detect always-succeeds Update action"
        );
    }

    #[test]
    fn test_no_finding_without_when_branches() {
        let signals = BodySignals::default();
        let modules = vec![ModuleInfo {
            name: "test/v".to_string(),
            path: "v.ak".to_string(),
            kind: ModuleKind::Validator,
            validators: vec![ValidatorInfo {
                name: "pool".to_string(),
                params: vec![],
                handlers: vec![HandlerInfo {
                    name: "spend".to_string(),
                    params: vec![
                        ParamInfo {
                            name: "datum".to_string(),
                            type_name: "D".to_string(),
                        },
                        ParamInfo {
                            name: "redeemer".to_string(),
                            type_name: "R".to_string(),
                        },
                    ],
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
        let findings = StateMachineViolation.detect(&modules);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_detects_catchall_accepts_unknown() {
        let mut signals = BodySignals::default();
        signals.when_branches.push(WhenBranchInfo {
            pattern_text: "Update".to_string(),
            is_catchall: false,
            body_is_literal_true: false,
            body_is_error: false,
        });
        signals.when_branches.push(WhenBranchInfo {
            pattern_text: "_".to_string(),
            is_catchall: true,
            body_is_literal_true: true,
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
                    params: vec![
                        ParamInfo {
                            name: "datum".to_string(),
                            type_name: "D".to_string(),
                        },
                        ParamInfo {
                            name: "redeemer".to_string(),
                            type_name: "R".to_string(),
                        },
                    ],
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

        let findings = StateMachineViolation.detect(&modules);
        assert!(
            findings
                .iter()
                .any(|f| f.description.contains("Catchall branch accepts unknown")),
            "should flag catchall-accepts-unknown state machine issue"
        );
    }
}
