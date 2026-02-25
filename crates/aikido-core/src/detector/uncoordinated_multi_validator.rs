use crate::ast_walker::{ModuleInfo, ModuleKind};
use crate::detector::{Confidence, Detector, Finding, Severity, SourceLocation};
use crate::transaction_analysis::{infer_transaction_templates, ParticipantRole};
use crate::validator_graph::{ValidatorGraph, ValidatorRelation};

/// Detects multi-handler validators where the spend handler manages state
/// but doesn't verify the transaction's mint field.
///
/// In DEX pools and lending protocols, a validator typically has both spend
/// and mint handlers. The spend handler manages pool state (deposits,
/// withdrawals, swaps), while the mint handler controls LP/receipt tokens.
/// If the spend handler doesn't verify what's being minted, an attacker
/// can manipulate token supply independently of state changes.
pub struct UncoordinatedMultiValidator;

impl Detector for UncoordinatedMultiValidator {
    fn name(&self) -> &str {
        "uncoordinated-multi-validator"
    }

    fn description(&self) -> &str {
        "Detects multi-handler validators where spend doesn't verify minting"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn long_description(&self) -> &str {
        "When a validator has both spend and mint handlers (multi-validator pattern), the \
        spend handler typically manages protocol state while the mint handler controls token \
        supply. If the spend handler doesn't access the transaction's `mint` field, minting \
        operations are uncoordinated with state changes.\n\n\
        This enables attacks where an attacker:\n\
        - Mints LP tokens without depositing (DEX)\n\
        - Mints receipt tokens without locking collateral (lending)\n\
        - Burns tokens without triggering proper withdrawal logic\n\n\
        Example (vulnerable):\n  validator my_pool {\n    spend(datum, redeemer, own_ref, self) {\n      \
        // Manages pool state but ignores self.mint!\n    }\n    \
        mint(redeemer, self) { ... }\n  }\n\n\
        Fix: Verify mint in spend:\n  let minted = value.from_minted_value(self.mint)\n  \
        // Verify minted amount matches expected LP tokens"
    }

    fn cwe_id(&self) -> Option<&str> {
        Some("CWE-345")
    }

    fn category(&self) -> &str {
        "logic"
    }

    fn detect(&self, modules: &[ModuleInfo]) -> Vec<Finding> {
        let mut findings = Vec::new();
        let validator_graph = ValidatorGraph::build(modules);
        let templates = infer_transaction_templates(modules);

        for module in modules {
            if module.kind != ModuleKind::Validator {
                continue;
            }

            for validator in &module.validators {
                let has_colocated_mint_spend = validator_graph
                    .relations_of(&module.name, &validator.name)
                    .iter()
                    .any(|(_, relation)| matches!(relation, ValidatorRelation::ColocatedMintSpend));
                if !has_colocated_mint_spend {
                    continue;
                }

                for handler in &validator.handlers {
                    if handler.name != "spend" {
                        continue;
                    }

                    let signals = &handler.body_signals;

                    // Spend handler must produce outputs (continuing UTXO / state management)
                    if !signals.tx_field_accesses.contains("outputs") {
                        continue;
                    }

                    let has_template_context = templates.iter().any(|template| {
                        template.source_module == module.name
                            && template.source_validator == validator.name
                            && template.source_handler == handler.name
                            && template
                                .participants
                                .iter()
                                .any(|p| p.role == ParticipantRole::SpendScript)
                    });
                    if !has_template_context {
                        continue;
                    }

                    // Check if spend handler verifies the mint field
                    let checks_mint = signals.tx_field_accesses.contains("mint");

                    if !checks_mint {
                        findings.push(Finding {
                            detector_name: self.name().to_string(),
                            severity: self.severity(),
                            confidence: Confidence::Likely,
                            title: format!(
                                "Multi-validator '{}' spend handler doesn't verify minting",
                                validator.name
                            ),
                            description: format!(
                                "Validator '{}' has both spend and mint handlers, but the spend \
                                handler manages state (produces outputs) without checking the \
                                `mint` field. Token minting/burning is uncoordinated with state \
                                changes, potentially allowing supply manipulation.",
                                validator.name
                            ),
                            module: module.name.clone(),
                            location: handler
                                .location
                                .map(|(s, e)| SourceLocation::from_bytes(&module.path, s, e)),
                            suggestion: Some(
                                "In the spend handler, verify minting with \
                                `value.from_minted_value(self.mint)` and check that minted \
                                quantities match the expected state transition."
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
    use crate::body_analysis::BodySignals;
    use std::collections::HashSet;

    fn make_multi_validator(
        spend_tx_accesses: HashSet<String>,
        has_mint_handler: bool,
    ) -> Vec<ModuleInfo> {
        let mut handlers = vec![HandlerInfo {
            name: "spend".to_string(),
            params: vec![],
            return_type: "Bool".to_string(),
            location: None,
            body_signals: BodySignals {
                tx_field_accesses: spend_tx_accesses,
                ..Default::default()
            },
        }];
        if has_mint_handler {
            handlers.push(HandlerInfo {
                name: "mint".to_string(),
                params: vec![],
                return_type: "Bool".to_string(),
                location: None,
                body_signals: BodySignals::default(),
            });
        }

        vec![ModuleInfo {
            name: "test/validator".to_string(),
            path: "validator.ak".to_string(),
            kind: ModuleKind::Validator,
            validators: vec![ValidatorInfo {
                name: "pool".to_string(),
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
    fn test_detects_uncoordinated_spend_mint() {
        let mut tx = HashSet::new();
        tx.insert("outputs".to_string());
        // No "mint" access

        let modules = make_multi_validator(tx, true);
        let findings = UncoordinatedMultiValidator.detect(&modules);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn test_no_finding_when_spend_checks_mint() {
        let mut tx = HashSet::new();
        tx.insert("outputs".to_string());
        tx.insert("mint".to_string());

        let modules = make_multi_validator(tx, true);
        let findings = UncoordinatedMultiValidator.detect(&modules);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_no_finding_without_mint_handler() {
        let mut tx = HashSet::new();
        tx.insert("outputs".to_string());

        let modules = make_multi_validator(tx, false);
        let findings = UncoordinatedMultiValidator.detect(&modules);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_no_finding_without_outputs() {
        let modules = make_multi_validator(HashSet::new(), true);
        let findings = UncoordinatedMultiValidator.detect(&modules);
        assert!(findings.is_empty());
    }
}
