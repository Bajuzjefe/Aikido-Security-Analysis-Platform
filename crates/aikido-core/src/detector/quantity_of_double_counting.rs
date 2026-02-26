use crate::ast_walker::{ModuleInfo, ModuleKind};
use crate::delegation::build_delegation_set;
use crate::detector::{Confidence, Detector, Finding, Severity, SourceLocation};

/// Detects multiple `quantity_of` calls that may allow double-counting of assets.
pub struct QuantityOfDoubleCounting;

impl Detector for QuantityOfDoubleCounting {
    fn name(&self) -> &str {
        "quantity-of-double-counting"
    }

    fn description(&self) -> &str {
        "Detects multiple quantity_of calls on the same Value that may allow asset overlap exploitation"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn long_description(&self) -> &str {
        "When a validator calls `value.quantity_of` multiple times to check different assets \
        in the same Value, an attacker can satisfy multiple checks with a single asset if the \
        checks don't verify mutual exclusivity. For example, if a validator checks for 100 \
        TokenA AND 100 TokenB using separate quantity_of calls, an attacker could provide a \
        single asset that satisfies both checks if the asset names overlap or if the same \
        policy ID is used.\n\n\
        Example (vulnerable):\n  let has_enough_a = value.quantity_of(v, policy, token_a) >= 100\n  \
        let has_enough_b = value.quantity_of(v, policy, token_b) >= 100\n  \
        // Both could be satisfied by the same tokens!\n\n\
        Fix: Use `value.tokens` to iterate and verify exact quantities, or check that \
        the total value matches expectations with `value.without_lovelace`."
    }

    fn cwe_id(&self) -> Option<&str> {
        Some("CWE-682")
    }

    fn category(&self) -> &str {
        "math"
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

                    // Use actual call count (not HashSet cardinality) to detect
                    // multiple independent quantity_of checks on the same Value.
                    let quantity_of_count = handler.body_signals.quantity_of_call_count;

                    // Also count tokens/policies calls that suggest multi-asset checks
                    let has_tokens_call = handler
                        .body_signals
                        .function_calls
                        .iter()
                        .any(|c| c.contains("tokens") || c.contains("policies"));

                    // Only flag if there are multiple quantity_of calls without
                    // corresponding tokens/policies iteration (which would be safe)
                    if quantity_of_count >= 2 && !has_tokens_call {
                        // If all quantity_of calls check distinct (policy, asset) pairs,
                        // double-counting is unlikely — downgrade to Info
                        let all_distinct =
                            handler.body_signals.quantity_of_asset_pairs.len() == quantity_of_count;
                        let (severity, confidence) = if all_distinct {
                            (Severity::Info, Confidence::Possible)
                        } else {
                            (self.severity(), Confidence::Possible)
                        };

                        findings.push(Finding {
                            detector_name: self.name().to_string(),
                            severity,
                            confidence,
                            title: format!(
                                "Multiple quantity_of calls in {}.{} may allow double-counting",
                                validator.name, handler.name
                            ),
                            description: format!(
                                "Handler {}.{} calls `quantity_of` {} times to check asset \
                                quantities. Without verifying mutual exclusivity, an attacker \
                                may satisfy multiple checks with overlapping assets.",
                                validator.name, handler.name, quantity_of_count
                            ),
                            module: module.name.clone(),
                            location: handler
                                .location
                                .map(|(s, e)| SourceLocation::from_bytes(&module.path, s, e)),
                            suggestion: Some(
                                "Use `value.tokens` or `value.without_lovelace` for exact value \
                                matching instead of multiple independent quantity_of checks."
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

    fn make_handler_with_count(
        function_calls: HashSet<String>,
        quantity_of_call_count: usize,
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
                        function_calls,
                        quantity_of_call_count,
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
    fn test_detects_multiple_quantity_of() {
        let mut calls = HashSet::new();
        calls.insert("quantity_of".to_string());

        // 3 calls to quantity_of — realistic for collateral validators
        let modules = make_handler_with_count(calls, 3);
        let findings = QuantityOfDoubleCounting.detect(&modules);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn test_no_finding_with_single_quantity_of() {
        let mut calls = HashSet::new();
        calls.insert("quantity_of".to_string());

        let modules = make_handler_with_count(calls, 1);
        let findings = QuantityOfDoubleCounting.detect(&modules);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_no_finding_when_tokens_used() {
        let mut calls = HashSet::new();
        calls.insert("quantity_of".to_string());
        calls.insert("value.tokens".to_string());

        // Even with 3 calls, tokens/policies iteration suppresses
        let modules = make_handler_with_count(calls, 3);
        let findings = QuantityOfDoubleCounting.detect(&modules);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_no_finding_without_quantity_of() {
        let modules = make_handler_with_count(HashSet::new(), 0);
        let findings = QuantityOfDoubleCounting.detect(&modules);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_detects_at_threshold_of_two() {
        let mut calls = HashSet::new();
        calls.insert("quantity_of".to_string());

        // Exactly 2 calls — minimum threshold
        let modules = make_handler_with_count(calls, 2);
        let findings = QuantityOfDoubleCounting.detect(&modules);
        assert_eq!(findings.len(), 1);
    }
}
