use crate::ast_walker::{ModuleInfo, ModuleKind};
use crate::delegation::build_delegation_set;
use crate::detector::{Confidence, Detector, Finding, Severity, SourceLocation};
use crate::transaction_analysis::{infer_transaction_templates, ParticipantRole};
use crate::validator_graph::{ValidatorGraph, ValidatorRelation};

/// Detects spend handlers producing continuing UTxOs without proper coordination.
pub struct UncoordinatedStateTransfer;

impl Detector for UncoordinatedStateTransfer {
    fn name(&self) -> &str {
        "uncoordinated-state-transfer"
    }

    fn description(&self) -> &str {
        "Detects uncoordinated state transfers between validators"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn long_description(&self) -> &str {
        "When a spend handler produces continuing outputs AND accesses mint or withdrawals, \
        it's coordinating with other validators. But if it only checks existence (has_key) \
        without verifying the coordinated validator's state, the coordination may be incomplete."
    }

    fn cwe_id(&self) -> Option<&str> {
        Some("CWE-345")
    }

    fn category(&self) -> &str {
        "logic"
    }

    fn detect(&self, modules: &[ModuleInfo]) -> Vec<Finding> {
        let mut findings = Vec::new();
        let delegation_set = build_delegation_set(modules);
        let validator_graph = ValidatorGraph::build(modules);
        let templates = infer_transaction_templates(modules);

        for module in modules {
            if module.kind != ModuleKind::Validator {
                continue;
            }
            for validator in &module.validators {
                for handler in &validator.handlers {
                    if handler.name != "spend" {
                        continue;
                    }
                    if delegation_set.contains(&(
                        module.name.clone(),
                        validator.name.clone(),
                        handler.name.clone(),
                    )) {
                        continue;
                    }

                    let signals = &handler.body_signals;
                    let produces_output = signals.tx_field_accesses.contains("outputs");
                    let accesses_mint = signals.tx_field_accesses.contains("mint");
                    let has_graph_mint_coordination = validator_graph
                        .relations_of(&module.name, &validator.name)
                        .iter()
                        .any(|(_, relation)| {
                            matches!(relation, ValidatorRelation::MintCoordination)
                        });
                    let has_template_mint_participant = templates.iter().any(|template| {
                        template.source_module == module.name
                            && template.source_validator == validator.name
                            && template.source_handler == handler.name
                            && template
                                .participants
                                .iter()
                                .any(|p| p.role == ParticipantRole::MintBurn)
                    });

                    if !has_graph_mint_coordination && !has_template_mint_participant {
                        continue;
                    }

                    if produces_output && accesses_mint {
                        // Check if mint access is just existence check
                        let only_existence = signals
                            .function_calls
                            .iter()
                            .any(|c| c.contains("has_key") || c.contains("list.has"))
                            && !signals.function_calls.iter().any(|c| {
                                c.contains("quantity_of")
                                    || c.contains("assets.match")
                                    || c.contains("tokens")
                                    || c.contains("flatten")
                            });

                        if only_existence {
                            findings.push(Finding {
                                detector_name: self.name().to_string(),
                                severity: self.severity(),
                                confidence: Confidence::Possible,
                                title: format!(
                                    "Incomplete mint coordination in {}.{}",
                                    validator.name, handler.name
                                ),
                                description: format!(
                                    "Handler {}.{} produces continuing outputs and checks mint \
                                    existence but doesn't verify mint quantities or policy details.",
                                    validator.name, handler.name
                                ),
                                module: module.name.clone(),
                                location: handler
                                    .location
                                    .map(|(s, e)| SourceLocation::from_bytes(&module.path, s, e)),
                                suggestion: Some(
                                    "Verify minted token quantities match expected amounts \
                                    using quantity_of or assets.match."
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
    fn test_detects_existence_only_mint_check() {
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
                    body_signals: BodySignals {
                        tx_field_accesses: ["outputs", "mint"]
                            .iter()
                            .map(|s| s.to_string())
                            .collect(),
                        function_calls: ["list.has"].iter().map(|s| s.to_string()).collect(),
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
        let findings = UncoordinatedStateTransfer.detect(&modules);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn test_no_finding_with_quantity_of() {
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
                    body_signals: BodySignals {
                        tx_field_accesses: ["outputs", "mint"]
                            .iter()
                            .map(|s| s.to_string())
                            .collect(),
                        function_calls: ["list.has", "assets.quantity_of"]
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
        let findings = UncoordinatedStateTransfer.detect(&modules);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_no_finding_on_non_spend() {
        let modules = vec![ModuleInfo {
            name: "test/v".to_string(),
            path: "v.ak".to_string(),
            kind: ModuleKind::Validator,
            validators: vec![ValidatorInfo {
                name: "pool".to_string(),
                params: vec![],
                handlers: vec![HandlerInfo {
                    name: "mint".to_string(),
                    params: vec![],
                    return_type: "Bool".to_string(),
                    location: None,
                    body_signals: BodySignals {
                        tx_field_accesses: ["outputs", "mint"]
                            .iter()
                            .map(|s| s.to_string())
                            .collect(),
                        function_calls: ["list.has"].iter().map(|s| s.to_string()).collect(),
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
        let findings = UncoordinatedStateTransfer.detect(&modules);
        assert!(findings.is_empty());
    }
}
