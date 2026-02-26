use crate::ast_walker::{ModuleInfo, ModuleKind};
use crate::detector::{Confidence, Detector, Finding, Severity, SourceLocation};

/// Detects handlers that use withdrawal-based authorization without verifying amounts.
///
/// The "withdraw zero trick" is a well-known Cardano vulnerability where an attacker
/// triggers a staking validator by including a zero-amount withdrawal in the transaction.
/// If a validator checks only for the *existence* of a withdrawal (not the amount),
/// an attacker can satisfy the check for free.
pub struct WithdrawZeroTrick;

impl Detector for WithdrawZeroTrick {
    fn name(&self) -> &str {
        "withdraw-zero-trick"
    }

    fn description(&self) -> &str {
        "Detects handlers using withdrawal-based auth without verifying withdrawal amounts"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn long_description(&self) -> &str {
        "The 'withdraw zero trick' exploits validators that check for the existence of a \
        withdrawal in the transaction without verifying the withdrawal amount. On Cardano, \
        anyone can include a zero-amount withdrawal from any staking script address. If a \
        spend or mint validator uses withdrawal existence as an authorization mechanism \
        (common pattern), an attacker can satisfy this check by adding a 0 ADA withdrawal.\n\n\
        Similarly, a `withdraw` handler that doesn't verify the withdrawal amount can be \
        triggered with a zero withdrawal, potentially enabling unintended state changes.\n\n\
        Example (vulnerable):\n  spend(datum, redeemer, own_ref, self) {\n    \
        // Only checks withdrawal exists, not amount!\n    \
        dict.has_key(self.withdrawals, staking_credential)\n  }\n\n\
        Fix: Also verify the amount:\n  spend(datum, redeemer, own_ref, self) {\n    \
        expect Some(amount) = dict.get(self.withdrawals, staking_credential)\n    \
        amount > 0\n  }"
    }

    fn cwe_id(&self) -> Option<&str> {
        Some("CWE-345")
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
                    let signals = &handler.body_signals;

                    // Handler must access the withdrawals field
                    let accesses_withdrawals = signals.tx_field_accesses.contains("withdrawals");
                    if !accesses_withdrawals {
                        continue;
                    }

                    // Check if the handler verifies withdrawal amounts.
                    // Good patterns: dict.get (returns amount), comparing with 0,
                    // using the withdrawal value in arithmetic.
                    // Bad patterns: dict.has_key (only checks existence),
                    // dict.keys (only enumerates keys).
                    let verifies_amount = signals.function_calls.iter().any(|c| {
                        c.contains("dict.get")
                            || c.contains("dict.foldl")
                            || c.contains("dict.foldr")
                            || c.contains("dict.values")
                            || c.contains("dict.to_pairs")
                            || c.contains("lovelace_of")
                            || c.contains("from_lovelace")
                    }) || signals.has_division
                        || signals.has_subtraction
                        || signals.has_multiplication;

                    if !verifies_amount {
                        let (confidence, desc) = if handler.name == "withdraw" {
                            (
                                Confidence::Likely,
                                format!(
                                    "Withdraw handler {}.{} accesses withdrawals but doesn't \
                                    verify the withdrawal amount. An attacker can trigger this \
                                    handler with a zero-amount withdrawal.",
                                    validator.name, handler.name
                                ),
                            )
                        } else {
                            (
                                Confidence::Likely,
                                format!(
                                    "Handler {}.{} uses withdrawal-based authorization but only \
                                    checks for withdrawal existence (e.g., dict.has_key), not the \
                                    amount. An attacker can satisfy this check with a zero withdrawal.",
                                    validator.name, handler.name
                                ),
                            )
                        };

                        findings.push(Finding {
                            detector_name: self.name().to_string(),
                            severity: self.severity(),
                            confidence,
                            title: format!(
                                "Potential withdraw-zero trick in {}.{}",
                                validator.name, handler.name
                            ),
                            description: desc,
                            module: module.name.clone(),
                            location: handler
                                .location
                                .map(|(s, e)| SourceLocation::from_bytes(&module.path, s, e)),
                            suggestion: Some(
                                "Use `dict.get` to retrieve the withdrawal amount and verify \
                                it is greater than zero: `expect Some(amount) = \
                                dict.get(self.withdrawals, key)` then `amount > 0`."
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
        handler_name: &str,
        tx_accesses: HashSet<String>,
        function_calls: HashSet<String>,
        has_division: bool,
    ) -> Vec<ModuleInfo> {
        vec![ModuleInfo {
            name: "test/validator".to_string(),
            path: "validator.ak".to_string(),
            kind: ModuleKind::Validator,
            validators: vec![ValidatorInfo {
                name: "test".to_string(),
                params: vec![],
                handlers: vec![HandlerInfo {
                    name: handler_name.to_string(),
                    params: vec![],
                    return_type: "Bool".to_string(),
                    location: None,
                    body_signals: BodySignals {
                        tx_field_accesses: tx_accesses,
                        function_calls,
                        has_division,
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
    fn test_detects_withdraw_zero_in_spend() {
        let mut tx = HashSet::new();
        tx.insert("withdrawals".to_string());
        let mut fns = HashSet::new();
        fns.insert("dict.has_key".to_string()); // Only checks existence!

        let modules = make_handler("spend", tx, fns, false);
        let findings = WithdrawZeroTrick.detect(&modules);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
        assert!(findings[0].title.contains("withdraw-zero trick"));
    }

    #[test]
    fn test_detects_withdraw_zero_in_withdraw_handler() {
        let mut tx = HashSet::new();
        tx.insert("withdrawals".to_string());

        let modules = make_handler("withdraw", tx, HashSet::new(), false);
        let findings = WithdrawZeroTrick.detect(&modules);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].confidence, Confidence::Likely);
    }

    #[test]
    fn test_no_finding_with_dict_get() {
        let mut tx = HashSet::new();
        tx.insert("withdrawals".to_string());
        let mut fns = HashSet::new();
        fns.insert("dict.get".to_string()); // Retrieves the amount

        let modules = make_handler("spend", tx, fns, false);
        let findings = WithdrawZeroTrick.detect(&modules);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_no_finding_with_amount_arithmetic() {
        let mut tx = HashSet::new();
        tx.insert("withdrawals".to_string());

        let modules = make_handler("spend", tx, HashSet::new(), true);
        let findings = WithdrawZeroTrick.detect(&modules);
        assert!(findings.is_empty(), "Division implies amount processing");
    }

    #[test]
    fn test_no_finding_without_withdrawals() {
        let mut tx = HashSet::new();
        tx.insert("outputs".to_string());

        let modules = make_handler("spend", tx, HashSet::new(), false);
        let findings = WithdrawZeroTrick.detect(&modules);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_no_finding_with_dict_foldl() {
        let mut tx = HashSet::new();
        tx.insert("withdrawals".to_string());
        let mut fns = HashSet::new();
        fns.insert("dict.foldl".to_string());

        let modules = make_handler("spend", tx, fns, false);
        let findings = WithdrawZeroTrick.detect(&modules);
        assert!(findings.is_empty());
    }
}
