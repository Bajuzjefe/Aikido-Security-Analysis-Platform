use crate::ast_walker::{ModuleInfo, ModuleKind};
use crate::detector::{Confidence, Detector, Finding, Severity, SourceLocation};

/// Detects minting policies that check authorization but not token names.
pub struct TokenNameNotValidated;

impl Detector for TokenNameNotValidated {
    fn name(&self) -> &str {
        "token-name-not-validated"
    }

    fn description(&self) -> &str {
        "Detects minting policies that check authorization but don't validate token names"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn long_description(&self) -> &str {
        "A minting policy that checks authorization (via extra_signatories or inputs) but \
        doesn't validate which specific token names are being minted allows an authorized \
        party to mint arbitrary tokens under the policy. The mint handler should validate \
        both authorization AND the specific tokens being minted.\n\n\
        Example (vulnerable):\n  mint(redeemer, self) {\n    \
        list.has(self.extra_signatories, admin_key)\n    \
        // Authorized, but what tokens are being minted?\n  }\n\n\
        Fix: Also validate token names:\n  mint(redeemer, self) {\n    \
        let minted = value.from_minted_value(self.mint)\n    \
        expect [(_, name, qty)] = value.flatten(minted)\n    \
        name == expected_name && qty == 1\n    \
        && list.has(self.extra_signatories, admin_key)\n  }"
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

                    // Has authorization check
                    let has_auth = signals.tx_field_accesses.contains("extra_signatories")
                        || signals.tx_field_accesses.contains("inputs");

                    // Accesses mint field (has some minting awareness)
                    let accesses_mint = signals.tx_field_accesses.contains("mint");

                    // Does it validate token names? Look for value.flatten, value.tokens,
                    // or pattern destructuring indicators
                    let validates_names = signals.function_calls.iter().any(|c| {
                        c.contains("flatten")
                            || c.contains("tokens")
                            || c.contains("from_minted_value")
                            || c.contains("quantity_of")
                    }) || signals.all_record_labels.contains("asset_name")
                        || signals.all_record_labels.contains("token_name");

                    // Check for singleton minting policy patterns:
                    // 1. Validator name suggests singleton (settings, config, etc.)
                    // 2. Handler consumes a boot UTXO (checks inputs for uniqueness)
                    let validator_lower = validator.name.to_lowercase();
                    let is_singleton_policy = [
                        "settings", "config", "protocol", "boot", "genesis", "oracle", "treasury",
                        "factory", "registry",
                    ]
                    .iter()
                    .any(|pat| validator_lower.contains(pat));

                    // Only flag if: has auth check, but no token name validation
                    // (if no mint access at all, missing-minting-policy-check catches it)
                    // Skip singleton policies — they mint exactly 1 token by construction
                    if has_auth && accesses_mint && !validates_names && !is_singleton_policy {
                        findings.push(Finding {
                            detector_name: self.name().to_string(),
                            severity: self.severity(),
                            confidence: Confidence::Likely,
                            title: format!(
                                "Minting policy {} checks authorization but not token names",
                                validator.name
                            ),
                            description:
                                "Mint handler verifies authorization but doesn't validate \
                                which token names are being minted. An authorized party could \
                                mint tokens with arbitrary names under this policy."
                                    .to_string(),
                            module: module.name.clone(),
                            location: handler
                                .location
                                .map(|(s, e)| SourceLocation::from_bytes(&module.path, s, e)),
                            suggestion: Some(
                                "Use `value.from_minted_value(self.mint)` and verify specific token names."
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
        record_labels: HashSet<String>,
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
    fn test_detects_auth_without_name_validation() {
        let mut tx = HashSet::new();
        tx.insert("extra_signatories".to_string());
        tx.insert("mint".to_string());
        // No token name validation functions

        let modules = make_mint_handler(tx, HashSet::new(), HashSet::new());
        let findings = TokenNameNotValidated.detect(&modules);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn test_no_finding_when_names_validated() {
        let mut tx = HashSet::new();
        tx.insert("extra_signatories".to_string());
        tx.insert("mint".to_string());
        let mut fns = HashSet::new();
        fns.insert("value.from_minted_value".to_string());
        fns.insert("value.flatten".to_string());

        let modules = make_mint_handler(tx, fns, HashSet::new());
        let findings = TokenNameNotValidated.detect(&modules);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_no_finding_without_auth() {
        let mut tx = HashSet::new();
        tx.insert("mint".to_string());
        // No auth check → missing-minting-policy-check or unrestricted-minting handles this

        let modules = make_mint_handler(tx, HashSet::new(), HashSet::new());
        let findings = TokenNameNotValidated.detect(&modules);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_no_finding_for_singleton_settings_policy() {
        // Singleton policies (settings, config, etc.) don't need token name validation
        let mut tx = HashSet::new();
        tx.insert("extra_signatories".to_string());
        tx.insert("mint".to_string());

        let mut modules = make_mint_handler(tx, HashSet::new(), HashSet::new());
        modules[0].validators[0].name = "settings".to_string();
        let findings = TokenNameNotValidated.detect(&modules);
        assert!(
            findings.is_empty(),
            "singleton settings policy should be skipped"
        );
    }

    #[test]
    fn test_no_finding_for_singleton_oracle_policy() {
        let mut tx = HashSet::new();
        tx.insert("extra_signatories".to_string());
        tx.insert("mint".to_string());

        let mut modules = make_mint_handler(tx, HashSet::new(), HashSet::new());
        modules[0].validators[0].name = "oracle".to_string();
        let findings = TokenNameNotValidated.detect(&modules);
        assert!(
            findings.is_empty(),
            "singleton oracle policy should be skipped"
        );
    }

    #[test]
    fn test_still_detects_non_singleton_policy() {
        // A "rewards" or "token" policy should still be flagged
        let mut tx = HashSet::new();
        tx.insert("extra_signatories".to_string());
        tx.insert("mint".to_string());

        let mut modules = make_mint_handler(tx, HashSet::new(), HashSet::new());
        modules[0].validators[0].name = "rewards_token".to_string();
        let findings = TokenNameNotValidated.detect(&modules);
        assert_eq!(
            findings.len(),
            1,
            "non-singleton policy should still be flagged"
        );
    }

    #[test]
    fn test_no_finding_on_spend() {
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
        let findings = TokenNameNotValidated.detect(&modules);
        assert!(findings.is_empty());
    }
}
