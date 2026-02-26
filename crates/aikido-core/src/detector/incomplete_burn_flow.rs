use crate::ast_walker::{ModuleInfo, ModuleKind};
use crate::detector::{Confidence, Detector, Finding, Severity, SourceLocation};
use crate::token_lifecycle::TokenLifecycleGraph;

/// Detects destructive operations without corresponding token burns.
pub struct IncompleteBurnFlow;

impl Detector for IncompleteBurnFlow {
    fn name(&self) -> &str {
        "incomplete-burn-flow"
    }

    fn description(&self) -> &str {
        "Detects destructive operations missing token burns across validators"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn long_description(&self) -> &str {
        "When a spend handler performs a terminal/destructive action (close, cancel, liquidate) \
        that consumes tokens from inputs but no validator in the project checks the mint field \
        for burning, the tokens remain in circulation. This creates ghost tokens that can be \
        used to forge identities or bypass authentication."
    }

    fn cwe_id(&self) -> Option<&str> {
        Some("CWE-404")
    }

    fn category(&self) -> &str {
        "logic"
    }

    fn detect(&self, modules: &[ModuleInfo]) -> Vec<Finding> {
        let mut findings = Vec::new();
        let lifecycle_graph = TokenLifecycleGraph::build(modules);

        for module in modules {
            if module.kind != ModuleKind::Validator {
                continue;
            }
            for validator in &module.validators {
                for handler in &validator.handlers {
                    if handler.name != "spend" {
                        continue;
                    }
                    let signals = &handler.body_signals;

                    // Look for terminal actions in when branches
                    let has_terminal = signals.when_branches.iter().any(|b| {
                        let lower = b.pattern_text.to_lowercase();
                        [
                            "close",
                            "cancel",
                            "liquidate",
                            "redeem",
                            "settle",
                            "destroy",
                            "burn",
                            "exit",
                        ]
                        .iter()
                        .any(|p| lower.contains(p))
                    });

                    // Uses tokens (quantity_of on inputs)
                    let uses_tokens = signals.tx_field_accesses.contains("inputs")
                        && signals
                            .function_calls
                            .iter()
                            .any(|c| c.contains("quantity_of"));

                    if has_terminal
                        && uses_tokens
                        && !signals.tx_field_accesses.contains("mint")
                        && !lifecycle_graph.has_burn_path(&module.name, &validator.name)
                    {
                        findings.push(Finding {
                            detector_name: self.name().to_string(),
                            severity: self.severity(),
                            confidence: Confidence::Likely,
                            title: format!(
                                "Terminal action without burn in {}.{}",
                                validator.name, handler.name
                            ),
                            description: format!(
                                "Handler {}.{} has terminal actions consuming tokens but doesn't \
                                access the mint field. Lifecycle analysis found no use->burn \
                                path for validator '{}'.",
                                validator.name, handler.name, validator.name
                            ),
                            module: module.name.clone(),
                            location: handler
                                .location
                                .map(|(s, e)| SourceLocation::from_bytes(&module.path, s, e)),
                            suggestion: Some(
                                "Add or wire a burn path (mint handler or coordinated burn \
                                validation) so destructive operations cannot leave ghost tokens."
                                    .to_string(),
                            ),
                            related_findings: vec![],
                            semantic_group: Some("cross-validator".to_string()),

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
    fn test_detects_missing_burn() {
        let mut signals = BodySignals::default();
        signals.tx_field_accesses.insert("inputs".to_string());
        signals
            .function_calls
            .insert("assets.quantity_of".to_string());
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
        let findings = IncompleteBurnFlow.detect(&modules);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn test_finding_with_uncoordinated_mint_handler() {
        let mut signals = BodySignals::default();
        signals.tx_field_accesses.insert("inputs".to_string());
        signals
            .function_calls
            .insert("assets.quantity_of".to_string());
        signals.when_branches.push(WhenBranchInfo {
            pattern_text: "Close".to_string(),
            is_catchall: false,
            body_is_literal_true: false,
            body_is_error: false,
        });

        let modules = vec![
            ModuleInfo {
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
            },
            ModuleInfo {
                name: "test/mint".to_string(),
                path: "mint.ak".to_string(),
                kind: ModuleKind::Validator,
                validators: vec![ValidatorInfo {
                    name: "token".to_string(),
                    params: vec![],
                    handlers: vec![HandlerInfo {
                        name: "mint".to_string(),
                        params: vec![],
                        return_type: "Bool".to_string(),
                        location: None,
                        body_signals: BodySignals {
                            tx_field_accesses: ["mint"].iter().map(|s| s.to_string()).collect(),
                            function_calls: ["value.negate"]
                                .iter()
                                .map(|s| s.to_string())
                                .collect(),
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
            },
        ];
        let findings = IncompleteBurnFlow.detect(&modules);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn test_no_finding_without_terminal_action() {
        let mut signals = BodySignals::default();
        signals.tx_field_accesses.insert("inputs".to_string());
        signals
            .function_calls
            .insert("assets.quantity_of".to_string());
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
        let findings = IncompleteBurnFlow.detect(&modules);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_no_finding_with_coordinated_local_burn_path() {
        let mut spend_signals = BodySignals::default();
        spend_signals.tx_field_accesses.insert("inputs".to_string());
        spend_signals
            .function_calls
            .insert("assets.quantity_of".to_string());
        spend_signals.when_branches.push(WhenBranchInfo {
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
                handlers: vec![
                    HandlerInfo {
                        name: "spend".to_string(),
                        params: vec![],
                        return_type: "Bool".to_string(),
                        location: None,
                        body_signals: spend_signals,
                    },
                    HandlerInfo {
                        name: "mint".to_string(),
                        params: vec![],
                        return_type: "Bool".to_string(),
                        location: None,
                        body_signals: BodySignals {
                            tx_field_accesses: ["mint"].iter().map(|s| s.to_string()).collect(),
                            function_calls: ["value.from_minted_value", "value.negate"]
                                .iter()
                                .map(|s| s.to_string())
                                .collect(),
                            ..Default::default()
                        },
                    },
                ],
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

        let findings = IncompleteBurnFlow.detect(&modules);
        assert!(
            findings.is_empty(),
            "coordinated local burn path should suppress incomplete-burn-flow finding"
        );
    }
}
