use crate::ast_walker::ModuleInfo;
use crate::delegation::detect_delegation_patterns;
use crate::detector::{Confidence, Detector, Finding, Severity};
use crate::transaction_analysis::{infer_transaction_templates, ParticipantRole};
use crate::validator_graph::{ValidatorGraph, ValidatorRelation};

/// Detects delegation where the delegated handler may be missing checks.
pub struct CrossValidatorGap;

impl Detector for CrossValidatorGap {
    fn name(&self) -> &str {
        "cross-validator-gap"
    }

    fn description(&self) -> &str {
        "Detects potential gaps in delegated validation"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn long_description(&self) -> &str {
        "When a spend handler delegates validation via the withdraw-zero pattern, \
        the delegated withdrawal handler must perform all necessary security checks. \
        This detector flags cases where the delegating handler skips checks AND \
        no corresponding withdrawal handler is found in the project."
    }

    fn cwe_id(&self) -> Option<&str> {
        Some("CWE-862")
    }

    fn category(&self) -> &str {
        "authorization"
    }

    fn detect(&self, modules: &[ModuleInfo]) -> Vec<Finding> {
        let mut findings = Vec::new();
        let delegations = detect_delegation_patterns(modules);
        let validator_graph = ValidatorGraph::build(modules);
        let templates = infer_transaction_templates(modules);

        for delegation in &delegations {
            let has_graph_delegate = validator_graph
                .relations_of(&delegation.module_name, &delegation.validator_name)
                .iter()
                .any(|(_, relation)| matches!(relation, ValidatorRelation::WithdrawDelegation));

            let has_withdraw_template = templates.iter().any(|template| {
                template.source_module == delegation.module_name
                    && template.source_validator == delegation.validator_name
                    && template.source_handler == delegation.handler_name
                    && template
                        .participants
                        .iter()
                        .any(|p| p.role == ParticipantRole::Withdrawal)
            });

            if !(has_graph_delegate && has_withdraw_template) {
                findings.push(Finding {
                    detector_name: self.name().to_string(),
                    severity: self.severity(),
                    confidence: Confidence::Likely,
                    title: format!(
                        "Delegation without visible delegate in {}.{}",
                        delegation.validator_name, delegation.handler_name
                    ),
                    description: format!(
                        "Handler {}.{} delegates validation via withdraw-zero pattern \
                        but graph/template context cannot prove a valid delegated withdrawal path. \
                        The delegated security checks may be missing.",
                        delegation.validator_name, delegation.handler_name,
                    ),
                    module: delegation.module_name.clone(),
                    location: None,
                    suggestion: Some(
                        "Ensure cross-validator context contains a concrete withdrawal delegate \
                        (validator graph edge + transaction template participant) and that \
                        delegated checks are implemented there."
                            .to_string(),
                    ),
                    related_findings: vec![],
                    semantic_group: Some("cross-validator".to_string()),

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
    use crate::body_analysis::BodySignals;

    #[test]
    fn test_no_finding_when_delegate_exists() {
        let modules = vec![
            ModuleInfo {
                name: "test/pool".to_string(),
                path: "pool.ak".to_string(),
                kind: ModuleKind::Validator,
                validators: vec![ValidatorInfo {
                    name: "pool".to_string(),
                    params: vec![],
                    handlers: vec![HandlerInfo {
                        name: "spend".to_string(),
                        params: vec![],
                        return_type: "Bool".to_string(),
                        location: None,
                        body_signals: BodySignals {
                            tx_field_accesses: ["withdrawals"]
                                .iter()
                                .map(|s| s.to_string())
                                .collect(),
                            function_calls: ["dict.has_key"]
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
            ModuleInfo {
                name: "test/staking".to_string(),
                path: "staking.ak".to_string(),
                kind: ModuleKind::Validator,
                validators: vec![ValidatorInfo {
                    name: "staking".to_string(),
                    params: vec![],
                    handlers: vec![HandlerInfo {
                        name: "withdraw".to_string(),
                        params: vec![],
                        return_type: "Bool".to_string(),
                        location: None,
                        body_signals: BodySignals::default(),
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
        let findings = CrossValidatorGap.detect(&modules);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_no_finding_without_delegation() {
        let modules = vec![ModuleInfo {
            name: "test/pool".to_string(),
            path: "pool.ak".to_string(),
            kind: ModuleKind::Validator,
            validators: vec![ValidatorInfo {
                name: "pool".to_string(),
                params: vec![],
                handlers: vec![HandlerInfo {
                    name: "spend".to_string(),
                    params: vec![],
                    return_type: "Bool".to_string(),
                    location: None,
                    body_signals: BodySignals {
                        tx_field_accesses: ["outputs", "extra_signatories"]
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
        }];
        let findings = CrossValidatorGap.detect(&modules);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_finding_when_delegation_has_no_delegate_context() {
        let modules = vec![ModuleInfo {
            name: "test/pool".to_string(),
            path: "pool.ak".to_string(),
            kind: ModuleKind::Validator,
            validators: vec![ValidatorInfo {
                name: "pool".to_string(),
                params: vec![],
                handlers: vec![HandlerInfo {
                    name: "spend".to_string(),
                    params: vec![],
                    return_type: "Bool".to_string(),
                    location: None,
                    body_signals: BodySignals {
                        tx_field_accesses: ["withdrawals"].iter().map(|s| s.to_string()).collect(),
                        function_calls: ["dict.has_key"].iter().map(|s| s.to_string()).collect(),
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
        }];

        let findings = CrossValidatorGap.detect(&modules);
        assert_eq!(
            findings.len(),
            1,
            "delegation without delegate should be flagged"
        );
        assert_eq!(findings[0].detector_name, "cross-validator-gap");
        assert_eq!(
            findings[0].semantic_group.as_deref(),
            Some("cross-validator")
        );
    }
}
