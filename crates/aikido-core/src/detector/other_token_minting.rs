use crate::ast_walker::{ModuleInfo, ModuleKind};
use crate::detector::{Confidence, Detector, Finding, Severity, SourceLocation};

/// Detects minting policies that validate their own tokens but don't restrict
/// other policies from minting in the same transaction.
///
/// This is the "Other Token Name" / "Other Redeemer" vulnerability documented by
/// MLabs. An attacker can submit a transaction that mints tokens under the
/// legitimate policy AND simultaneously mints arbitrary tokens under their own
/// policy. If the validator only checks its own tokens, the attacker's tokens
/// are included for free.
pub struct OtherTokenMinting;

impl Detector for OtherTokenMinting {
    fn name(&self) -> &str {
        "other-token-minting"
    }

    fn description(&self) -> &str {
        "Detects minting policies that don't restrict other policies from minting in the same tx"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn long_description(&self) -> &str {
        "When a minting policy validates only its own tokens (using `quantity_of` or filtering \
        by own policy ID), it doesn't prevent other policies from also minting in the same \
        transaction. An attacker can piggyback their own minting alongside a legitimate mint \
        operation.\n\n\
        To prevent this, the mint handler should enumerate ALL minted tokens (using \
        `value.from_minted_value` + `value.flatten`) and verify that only expected tokens \
        are present, OR verify the total number of minting policies is exactly 1.\n\n\
        Example (vulnerable):\n  mint(redeemer, self) {\n    \
        let minted = value.from_minted_value(self.mint)\n    \
        value.quantity_of(minted, own_policy, token_name) == 1\n    \
        // Doesn't check if OTHER policies also minted!\n  }\n\n\
        Fix: Verify total minting:\n  mint(redeemer, self) {\n    \
        let minted = value.from_minted_value(self.mint)\n    \
        expect [(policy, name, qty)] = value.flatten(minted)\n    \
        policy == own_policy && name == token_name && qty == 1\n  }"
    }

    fn cwe_id(&self) -> Option<&str> {
        Some("CWE-20")
    }

    fn category(&self) -> &str {
        "data-validation"
    }

    fn detect(&self, modules: &[ModuleInfo]) -> Vec<Finding> {
        let mut findings = Vec::new();

        for module in modules {
            if module.kind != ModuleKind::Validator {
                continue;
            }

            for validator in &module.validators {
                for handler in &validator.handlers {
                    if handler.name != "mint" {
                        continue;
                    }

                    let signals = &handler.body_signals;

                    // Handler must access the mint field
                    let accesses_mint = signals.tx_field_accesses.contains("mint");
                    if !accesses_mint {
                        continue;
                    }

                    // Check if handler validates specific tokens (quantity_of pattern)
                    // without enumerating all minted tokens
                    let uses_specific_check = signals
                        .function_calls
                        .iter()
                        .any(|c| c.contains("quantity_of") || c.contains("tokens"));

                    // Check if handler enumerates all minted tokens (safe pattern)
                    let enumerates_all = signals.function_calls.iter().any(|c| {
                        c.contains("flatten")
                            || c.contains("policies")
                            || c.contains("to_dict")
                            || c.contains("to_pairs")
                            || c.contains("dict.keys")
                            || c.contains("dict.size")
                            || c.contains("list.length")
                    });

                    // Pattern: uses specific token check (quantity_of) but doesn't
                    // enumerate all tokens. This means it only validates its own
                    // tokens but ignores others.
                    if uses_specific_check && !enumerates_all {
                        // Note: On Cardano, each minting policy is isolated to its own
                        // policy ID. Other policies minting in the same TX cannot mint
                        // tokens under THIS policy's ID. The risk is limited to the
                        // attacker minting worthless tokens under their own policy.
                        findings.push(Finding {
                            detector_name: self.name().to_string(),
                            severity: self.severity(),
                            confidence: Confidence::Possible,
                            title: format!(
                                "Minting policy '{}' doesn't restrict other policies from minting",
                                validator.name
                            ),
                            description: format!(
                                "Mint handler in '{}' validates specific token quantities \
                                (e.g., quantity_of) but doesn't enumerate all minted tokens. \
                                An attacker can piggyback their own minting in the same \
                                transaction alongside the legitimate mint. Note: Cardano policy \
                                isolation means other policies cannot mint under this policy's ID, \
                                limiting the practical impact.",
                                validator.name
                            ),
                            module: module.name.clone(),
                            location: handler
                                .location
                                .map(|(s, e)| SourceLocation::from_bytes(&module.path, s, e)),
                            suggestion: Some(
                                "Use `value.flatten(value.from_minted_value(self.mint))` to \
                                destructure ALL minted tokens and verify the list contains \
                                only expected entries, or check `list.length(value.policies(minted)) == 1`."
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

    fn make_mint_handler(
        tx_accesses: HashSet<String>,
        function_calls: HashSet<String>,
    ) -> Vec<ModuleInfo> {
        vec![ModuleInfo {
            name: "test/validator".to_string(),
            path: "validator.ak".to_string(),
            kind: ModuleKind::Validator,
            validators: vec![ValidatorInfo {
                name: "test_policy".to_string(),
                params: vec![],
                handlers: vec![HandlerInfo {
                    name: "mint".to_string(),
                    params: vec![],
                    return_type: "Bool".to_string(),
                    location: None,
                    body_signals: BodySignals {
                        tx_field_accesses: tx_accesses,
                        function_calls,
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
    fn test_detects_quantity_of_without_flatten() {
        let mut tx = HashSet::new();
        tx.insert("mint".to_string());
        let mut fns = HashSet::new();
        fns.insert("value.from_minted_value".to_string());
        fns.insert("value.quantity_of".to_string());

        let modules = make_mint_handler(tx, fns);
        let findings = OtherTokenMinting.detect(&modules);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
        assert_eq!(findings[0].confidence, Confidence::Possible);
        assert!(findings[0].title.contains("doesn't restrict"));
        assert!(findings[0].description.contains("policy isolation"));
    }

    #[test]
    fn test_no_finding_with_flatten() {
        let mut tx = HashSet::new();
        tx.insert("mint".to_string());
        let mut fns = HashSet::new();
        fns.insert("value.from_minted_value".to_string());
        fns.insert("value.quantity_of".to_string());
        fns.insert("value.flatten".to_string());

        let modules = make_mint_handler(tx, fns);
        let findings = OtherTokenMinting.detect(&modules);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_no_finding_with_policies_check() {
        let mut tx = HashSet::new();
        tx.insert("mint".to_string());
        let mut fns = HashSet::new();
        fns.insert("value.quantity_of".to_string());
        fns.insert("value.policies".to_string());

        let modules = make_mint_handler(tx, fns);
        let findings = OtherTokenMinting.detect(&modules);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_no_finding_without_specific_check() {
        let mut tx = HashSet::new();
        tx.insert("mint".to_string());
        let mut fns = HashSet::new();
        // Only flatten, no quantity_of — handler enumerates everything (safe)
        fns.insert("value.flatten".to_string());

        let modules = make_mint_handler(tx, fns);
        let findings = OtherTokenMinting.detect(&modules);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_no_finding_without_mint_access() {
        let modules = make_mint_handler(HashSet::new(), HashSet::new());
        let findings = OtherTokenMinting.detect(&modules);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_no_finding_on_spend_handler() {
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
        }];
        let findings = OtherTokenMinting.detect(&modules);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_no_finding_with_dict_keys() {
        let mut tx = HashSet::new();
        tx.insert("mint".to_string());
        let mut fns = HashSet::new();
        fns.insert("value.tokens".to_string());
        fns.insert("dict.keys".to_string());

        let modules = make_mint_handler(tx, fns);
        let findings = OtherTokenMinting.detect(&modules);
        assert!(findings.is_empty());
    }
}
