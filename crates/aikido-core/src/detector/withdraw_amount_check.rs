use crate::ast_walker::{ModuleInfo, ModuleKind};
use crate::cardano_model::validates_withdrawal_amount;
use crate::delegation::build_delegation_set;
use crate::detector::{Confidence, Detector, Finding, Severity, SourceLocation};

/// Detects withdrawal used for auth but only existence checked, not amount.
pub struct WithdrawAmountCheck;

impl Detector for WithdrawAmountCheck {
    fn name(&self) -> &str {
        "withdraw-amount-check"
    }

    fn description(&self) -> &str {
        "Detects withdrawal auth that only checks existence, not amount"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn long_description(&self) -> &str {
        "The Cardano ledger allows any staking script to be invoked with a 0 withdrawal. \
        If a validator only checks that a withdrawal exists (via has_key) but doesn't verify \
        the withdrawal amount, the delegation check provides no security guarantee."
    }

    fn cwe_id(&self) -> Option<&str> {
        Some("CWE-345")
    }

    fn category(&self) -> &str {
        "authorization"
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
                    if delegation_set.contains(&(
                        module.name.clone(),
                        validator.name.clone(),
                        handler.name.clone(),
                    )) {
                        continue;
                    }

                    // A withdraw handler being invoked IS the validation mechanism
                    // in Plutus V3 delegation pattern — checking the withdrawal amount
                    // inside the delegation target is redundant.
                    if handler.name == "withdraw" {
                        continue;
                    }

                    let signals = &handler.body_signals;
                    if !signals.tx_field_accesses.contains("withdrawals") {
                        continue;
                    }

                    // Only checks existence
                    let has_existence_check = signals
                        .function_calls
                        .iter()
                        .any(|c| c.contains("has_key") || c.contains("list.has"));
                    // Canonical Cardano semantic check from cardano_model.
                    let checks_amount = validates_withdrawal_amount(handler);

                    if has_existence_check && !checks_amount {
                        findings.push(Finding {
                            detector_name: self.name().to_string(),
                            severity: self.severity(),
                            confidence: Confidence::Possible,
                            title: format!(
                                "Withdrawal existence-only check in {}.{}",
                                validator.name, handler.name
                            ),
                            description: format!(
                                "Handler {}.{} checks withdrawal existence but not the amount. \
                                An attacker can invoke the staking script with a 0-amount withdrawal.",
                                validator.name, handler.name
                            ),
                            module: module.name.clone(),
                            location: handler
                                .location
                                .map(|(s, e)| SourceLocation::from_bytes(&module.path, s, e)),
                            suggestion: Some(
                                "Verify the withdrawal amount is > 0 or matches an expected value."
                                    .to_string(),
                            ),
                            related_findings: vec![],
                            semantic_group: Some("cardano-semantics".to_string()),

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

    #[test]
    fn test_detects_existence_only() {
        // Handler accesses withdrawals AND outputs (so it's not a pure delegation
        // handler — it does its own output validation), but only checks withdrawal
        // existence without verifying the amount.
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
                        tx_field_accesses: ["withdrawals", "outputs"]
                            .iter()
                            .map(|s| s.to_string())
                            .collect(),
                        function_calls: ["dict.has_key"].iter().map(|s| s.to_string()).collect(),
                        all_record_labels: ["datum"].iter().map(|s| s.to_string()).collect(),
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
        let findings = WithdrawAmountCheck.detect(&modules);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn test_no_finding_with_amount_check() {
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
                        tx_field_accesses: ["withdrawals"].iter().map(|s| s.to_string()).collect(),
                        function_calls: ["dict.has_key", "pairs.get_first"]
                            .iter()
                            .map(|s| s.to_string())
                            .collect(),
                        guarded_vars: ["withdrawal_amount"]
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
        let findings = WithdrawAmountCheck.detect(&modules);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_no_finding_without_withdrawals() {
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
                        tx_field_accesses: ["outputs"].iter().map(|s| s.to_string()).collect(),
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
        let findings = WithdrawAmountCheck.detect(&modules);
        assert!(findings.is_empty());
    }
}
