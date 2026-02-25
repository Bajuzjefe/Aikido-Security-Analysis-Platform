use crate::ast_walker::{ModuleInfo, ModuleKind};
use crate::detector::{Confidence, Detector, Finding, Severity, SourceLocation};

/// Detects handlers that produce outputs to script addresses without constraining staking credentials.
pub struct InsufficientStakingControl;

impl Detector for InsufficientStakingControl {
    fn name(&self) -> &str {
        "insufficient-staking-control"
    }

    fn description(&self) -> &str {
        "Detects handlers that produce outputs without constraining the staking credential"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn long_description(&self) -> &str {
        "When a validator sends outputs to a script address, the staking credential of that \
        address should be constrained. If not, an attacker can redirect staking rewards to their \
        own staking key by providing a script address with their staking credential but the \
        validator's payment credential.\n\n\
        Example (vulnerable):\n  spend(datum, redeemer, own_ref, self) {\n    \
        list.any(self.outputs, fn(o) {\n      o.address.payment_credential == own_credential\n      \
        // Missing: stake_credential not checked!\n    })\n  }\n\n\
        Fix: Also check the staking credential:\n  o.address.payment_credential == own_credential\n  \
        && o.address.stake_credential == expected_stake"
    }

    fn cwe_id(&self) -> Option<&str> {
        Some("CWE-863")
    }

    fn category(&self) -> &str {
        "authorization"
    }

    fn detect(&self, modules: &[ModuleInfo]) -> Vec<Finding> {
        let mut findings = Vec::new();

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

                    // Handler accesses outputs and address (sending to a script)
                    let accesses_outputs = signals.tx_field_accesses.contains("outputs");
                    let accesses_address = signals.all_record_labels.contains("address")
                        || signals.all_record_labels.contains("payment_credential");
                    let checks_staking = signals.all_record_labels.contains("stake_credential");

                    if accesses_outputs && accesses_address && !checks_staking {
                        // Check if a companion stake handler constrains delegation.
                        // If so, staking rewards may already be protected.
                        let has_stake_handler = validator.handlers.iter().any(|h| {
                            h.name == "stake"
                                && (h.body_signals.all_record_labels.contains("credential")
                                    || h.body_signals
                                        .all_record_labels
                                        .contains("stake_credential")
                                    || h.body_signals
                                        .tx_field_accesses
                                        .contains("extra_signatories"))
                        });

                        // Companion stake handler with credential checks = lower risk
                        if has_stake_handler {
                            continue;
                        }

                        // Suppress when handler delegates all logic to a withdrawal script.
                        // The withdrawal handler validates outputs independently.
                        if signals.tx_field_accesses.contains("withdrawals")
                            && signals
                                .function_calls
                                .iter()
                                .any(|c| c.contains("has_key") || c.contains("is_withdrawal"))
                        {
                            continue;
                        }

                        // Suppress when the handler compares full addresses (not just
                        // payment_credential). A full address equality check like
                        // `output.address == own_address` implicitly validates the
                        // stake_credential as well. We detect this by checking if
                        // "address" is in record labels but "payment_credential" is NOT,
                        // which indicates direct address comparison rather than field-by-field.
                        let uses_full_address_comparison =
                            signals.all_record_labels.contains("address")
                                && !signals.all_record_labels.contains("payment_credential");
                        if uses_full_address_comparison {
                            continue;
                        }

                        // Suppress when a called helper function performs full address
                        // comparison. Cross-function tracing: if handler calls func X
                        // and X's body_signals show address comparison (address label
                        // present without payment_credential), the check is delegated.
                        // Use exact function name matching to avoid substring false matches.
                        let helper_checks_full_address = module.functions.iter().any(|f| {
                            if let Some(ref fsignals) = f.body_signals {
                                let handler_calls_this = signals
                                    .function_calls
                                    .iter()
                                    .any(|c| c == &f.name || c.ends_with(&format!(".{}", f.name)));
                                handler_calls_this
                                    && fsignals.all_record_labels.contains("address")
                                    && !fsignals.all_record_labels.contains("payment_credential")
                            } else {
                                false
                            }
                        });
                        if helper_checks_full_address {
                            continue;
                        }

                        findings.push(Finding {
                            detector_name: self.name().to_string(),
                            severity: self.severity(),
                            confidence: Confidence::Possible,
                            title: format!(
                                "Handler {}.{} doesn't constrain staking credential on outputs",
                                validator.name, handler.name
                            ),
                            description:
                                "Outputs check the payment credential but not the staking credential. \
                                An attacker can provide an address with their staking key to steal \
                                staking rewards."
                                    .to_string(),
                            module: module.name.clone(),
                            location: handler
                                .location
                                .map(|(s, e)| SourceLocation::from_bytes(&module.path, s, e)),
                            suggestion: Some(
                                "Also verify `output.address.stake_credential` matches the expected value."
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

    fn make_handler(
        tx_accesses: HashSet<String>,
        record_labels: HashSet<String>,
    ) -> Vec<ModuleInfo> {
        vec![ModuleInfo {
            name: "test/validator".to_string(),
            path: "validator.ak".to_string(),
            kind: ModuleKind::Validator,
            validators: vec![ValidatorInfo {
                name: "test".to_string(),
                params: vec![],
                handlers: vec![HandlerInfo {
                    name: "spend".to_string(),
                    params: vec![],
                    return_type: "Bool".to_string(),
                    location: None,
                    body_signals: BodySignals {
                        tx_field_accesses: tx_accesses,
                        all_record_labels: record_labels,
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
    fn test_detects_missing_staking_control() {
        let mut tx = HashSet::new();
        tx.insert("outputs".to_string());
        let mut labels = HashSet::new();
        labels.insert("address".to_string());
        labels.insert("payment_credential".to_string());
        // No stake_credential

        let modules = make_handler(tx, labels);
        let findings = InsufficientStakingControl.detect(&modules);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Medium);
    }

    #[test]
    fn test_no_finding_when_stake_checked() {
        let mut tx = HashSet::new();
        tx.insert("outputs".to_string());
        let mut labels = HashSet::new();
        labels.insert("address".to_string());
        labels.insert("payment_credential".to_string());
        labels.insert("stake_credential".to_string());

        let modules = make_handler(tx, labels);
        let findings = InsufficientStakingControl.detect(&modules);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_no_finding_with_companion_stake_handler() {
        let mut tx = HashSet::new();
        tx.insert("outputs".to_string());
        let mut labels = HashSet::new();
        labels.insert("address".to_string());
        labels.insert("payment_credential".to_string());

        // Companion stake handler checks credentials
        let mut stake_labels = HashSet::new();
        stake_labels.insert("credential".to_string());

        let modules = vec![ModuleInfo {
            name: "test/validator".to_string(),
            path: "validator.ak".to_string(),
            kind: ModuleKind::Validator,
            validators: vec![ValidatorInfo {
                name: "test".to_string(),
                params: vec![],
                handlers: vec![
                    HandlerInfo {
                        name: "spend".to_string(),
                        params: vec![],
                        return_type: "Bool".to_string(),
                        location: None,
                        body_signals: BodySignals {
                            tx_field_accesses: tx,
                            all_record_labels: labels,
                            ..Default::default()
                        },
                    },
                    HandlerInfo {
                        name: "stake".to_string(),
                        params: vec![],
                        return_type: "Bool".to_string(),
                        location: None,
                        body_signals: BodySignals {
                            all_record_labels: stake_labels,
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

        let findings = InsufficientStakingControl.detect(&modules);
        assert!(
            findings.is_empty(),
            "Companion stake handler should suppress finding"
        );
    }

    #[test]
    fn test_no_finding_without_outputs() {
        let tx = HashSet::new();
        let mut labels = HashSet::new();
        labels.insert("address".to_string());

        let modules = make_handler(tx, labels);
        let findings = InsufficientStakingControl.detect(&modules);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_no_finding_with_withdrawal_delegation() {
        let mut tx = HashSet::new();
        tx.insert("outputs".to_string());
        tx.insert("withdrawals".to_string());
        let mut labels = HashSet::new();
        labels.insert("address".to_string());
        labels.insert("payment_credential".to_string());
        let mut fns = HashSet::new();
        fns.insert("pairs.has_key".to_string());

        let modules = vec![ModuleInfo {
            name: "test/validator".to_string(),
            path: "validator.ak".to_string(),
            kind: ModuleKind::Validator,
            validators: vec![ValidatorInfo {
                name: "test".to_string(),
                params: vec![],
                handlers: vec![HandlerInfo {
                    name: "spend".to_string(),
                    params: vec![],
                    return_type: "Bool".to_string(),
                    location: None,
                    body_signals: BodySignals {
                        tx_field_accesses: tx,
                        all_record_labels: labels,
                        function_calls: fns,
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

        let findings = InsufficientStakingControl.detect(&modules);
        assert!(
            findings.is_empty(),
            "withdrawal delegation should suppress staking finding"
        );
    }

    #[test]
    fn test_no_finding_with_full_address_comparison() {
        // When handler uses "address" label but NOT "payment_credential",
        // it's doing full address comparison which includes stake_credential.
        let mut tx = HashSet::new();
        tx.insert("outputs".to_string());
        let mut labels = HashSet::new();
        labels.insert("address".to_string());
        // Notably absent: "payment_credential" — indicates full address comparison

        let modules = make_handler(tx, labels);
        let findings = InsufficientStakingControl.detect(&modules);
        assert!(
            findings.is_empty(),
            "full address comparison should suppress staking finding"
        );
    }

    #[test]
    fn test_no_finding_with_helper_full_address_check() {
        // Handler calls a helper function that performs full address comparison.
        let mut tx = HashSet::new();
        tx.insert("outputs".to_string());
        let mut labels = HashSet::new();
        labels.insert("address".to_string());
        labels.insert("payment_credential".to_string());
        let mut fns = HashSet::new();
        fns.insert("utils.check_output".to_string());

        // Helper function body signals: uses "address" without "payment_credential"
        let mut helper_labels = HashSet::new();
        helper_labels.insert("address".to_string());
        let helper_signals = BodySignals {
            all_record_labels: helper_labels,
            ..Default::default()
        };

        let modules = vec![ModuleInfo {
            name: "test/validator".to_string(),
            path: "validator.ak".to_string(),
            kind: ModuleKind::Validator,
            validators: vec![ValidatorInfo {
                name: "test".to_string(),
                params: vec![],
                handlers: vec![HandlerInfo {
                    name: "spend".to_string(),
                    params: vec![],
                    return_type: "Bool".to_string(),
                    location: None,
                    body_signals: BodySignals {
                        tx_field_accesses: tx,
                        all_record_labels: labels,
                        function_calls: fns,
                        ..Default::default()
                    },
                }],
                summary: None,
            }],
            data_types: vec![],
            functions: vec![crate::ast_walker::FunctionInfo {
                name: "check_output".to_string(),
                public: true,
                params: vec![],
                return_type: "Bool".to_string(),
                body_signals: Some(helper_signals),
            }],
            constants: vec![],
            type_aliases: vec![],
            test_count: 0,
            source_code: None,
            test_function_names: vec![],
        }];

        let findings = InsufficientStakingControl.detect(&modules);
        assert!(
            findings.is_empty(),
            "helper function with full address check should suppress finding"
        );
    }

    #[test]
    fn test_finding_with_helper_that_only_checks_payment() {
        // Handler calls a helper that also only checks payment_credential — should still fire.
        let mut tx = HashSet::new();
        tx.insert("outputs".to_string());
        let mut labels = HashSet::new();
        labels.insert("address".to_string());
        labels.insert("payment_credential".to_string());
        let mut fns = HashSet::new();
        fns.insert("utils.check_output".to_string());

        // Helper also accesses payment_credential (not full address comparison)
        let mut helper_labels = HashSet::new();
        helper_labels.insert("address".to_string());
        helper_labels.insert("payment_credential".to_string());
        let helper_signals = BodySignals {
            all_record_labels: helper_labels,
            ..Default::default()
        };

        let modules = vec![ModuleInfo {
            name: "test/validator".to_string(),
            path: "validator.ak".to_string(),
            kind: ModuleKind::Validator,
            validators: vec![ValidatorInfo {
                name: "test".to_string(),
                params: vec![],
                handlers: vec![HandlerInfo {
                    name: "spend".to_string(),
                    params: vec![],
                    return_type: "Bool".to_string(),
                    location: None,
                    body_signals: BodySignals {
                        tx_field_accesses: tx,
                        all_record_labels: labels,
                        function_calls: fns,
                        ..Default::default()
                    },
                }],
                summary: None,
            }],
            data_types: vec![],
            functions: vec![crate::ast_walker::FunctionInfo {
                name: "check_output".to_string(),
                public: true,
                params: vec![],
                return_type: "Bool".to_string(),
                body_signals: Some(helper_signals),
            }],
            constants: vec![],
            type_aliases: vec![],
            test_count: 0,
            source_code: None,
            test_function_names: vec![],
        }];

        let findings = InsufficientStakingControl.detect(&modules);
        assert_eq!(
            findings.len(),
            1,
            "helper with only payment_credential check should NOT suppress"
        );
    }
}
