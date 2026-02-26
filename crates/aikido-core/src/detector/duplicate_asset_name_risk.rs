use crate::ast_walker::{ModuleInfo, ModuleKind};
use crate::detector::{Confidence, Detector, Finding, Severity, SourceLocation};

/// Detects minting policies that mint tokens without ensuring unique asset names.
///
/// If a mint handler creates tokens without checking the minted quantity against
/// existing tokens (e.g., verifying no token with that name already exists),
/// an attacker could mint duplicates. This is especially dangerous for NFTs
/// where uniqueness is a core guarantee.
pub struct DuplicateAssetNameRisk;

impl Detector for DuplicateAssetNameRisk {
    fn name(&self) -> &str {
        "duplicate-asset-name-risk"
    }

    fn description(&self) -> &str {
        "Detects minting policies that don't verify token name uniqueness"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn long_description(&self) -> &str {
        "When a minting policy creates tokens but doesn't verify the exact minted quantity \
        is 1 (for NFTs) or check against existing supply, duplicate tokens can be minted. \
        The mint handler should verify the exact quantity being minted and ideally check \
        that the asset doesn't already exist.\n\n\
        A safe mint handler typically uses `value.from_minted_value(self.mint)` and then \
        destructures to verify exactly `[(policy, name, 1)]` for NFT minting, or uses \
        `quantity_of` with a specific expected quantity.\n\n\
        Example (vulnerable):\n  mint(redeemer, self) {\n    \
        value.quantity_of(minted, policy, name) > 0\n    \
        // Allows minting 1, 2, 100... tokens!\n  }\n\n\
        Fix: Check exact quantity:\n  expect [(_, _, 1)] = value.flatten(minted)"
    }

    fn cwe_id(&self) -> Option<&str> {
        Some("CWE-682")
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

                    // Must access the mint field
                    if !signals.tx_field_accesses.contains("mint") {
                        continue;
                    }

                    // Check if handler validates exact quantities
                    let validates_exact_quantity = signals.function_calls.iter().any(|c| {
                        c.contains("flatten") || c.contains("to_pairs") || c.contains("to_dict")
                    }) || signals.has_fold_counting_pattern;

                    // Check if handler uses equality checks on quantity
                    // (quantity_of returns Int, comparing with == 1 is safe)
                    // If they use flatten + expect pattern, that's exact validation
                    // If they only use quantity_of with > 0 or similar, that's weak
                    let uses_quantity_of = signals
                        .function_calls
                        .iter()
                        .any(|c| c.contains("quantity_of"));

                    // Flag: uses quantity_of but no flatten/destructuring (can't verify exact count)
                    if uses_quantity_of && !validates_exact_quantity {
                        findings.push(Finding {
                            detector_name: self.name().to_string(),
                            severity: self.severity(),
                            confidence: Confidence::Possible,
                            title: format!(
                                "Minting policy '{}' may allow duplicate token names",
                                validator.name
                            ),
                            description: format!(
                                "Mint handler in '{}' uses quantity_of to check minted tokens \
                                but doesn't destructure the full mint value. Without checking \
                                the exact quantity (e.g., == 1), the handler may allow minting \
                                more tokens than intended.",
                                validator.name
                            ),
                            module: module.name.clone(),
                            location: handler
                                .location
                                .map(|(s, e)| SourceLocation::from_bytes(&module.path, s, e)),
                            suggestion: Some(
                                "Use `expect [(_, _, 1)] = value.flatten(minted)` to verify \
                                exactly one token is minted, or check \
                                `value.quantity_of(minted, policy, name) == 1`."
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
        fns.insert("value.quantity_of".to_string());

        let modules = make_mint_handler(tx, fns);
        let findings = DuplicateAssetNameRisk.detect(&modules);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Medium);
    }

    #[test]
    fn test_no_finding_with_flatten() {
        let mut tx = HashSet::new();
        tx.insert("mint".to_string());
        let mut fns = HashSet::new();
        fns.insert("value.quantity_of".to_string());
        fns.insert("value.flatten".to_string());

        let modules = make_mint_handler(tx, fns);
        let findings = DuplicateAssetNameRisk.detect(&modules);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_no_finding_without_quantity_of() {
        let mut tx = HashSet::new();
        tx.insert("mint".to_string());
        let mut fns = HashSet::new();
        fns.insert("value.from_minted_value".to_string());

        let modules = make_mint_handler(tx, fns);
        let findings = DuplicateAssetNameRisk.detect(&modules);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_no_finding_without_mint_access() {
        let modules = make_mint_handler(HashSet::new(), HashSet::new());
        let findings = DuplicateAssetNameRisk.detect(&modules);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_no_finding_with_foldl_counting_pattern() {
        let mut tx = HashSet::new();
        tx.insert("mint".to_string());
        let mut fns = HashSet::new();
        fns.insert("value.quantity_of".to_string());

        let mut modules = make_mint_handler(tx, fns);
        // Simulate fold-counting pattern (dict.foldl counting tokens)
        modules[0].validators[0].handlers[0]
            .body_signals
            .has_fold_counting_pattern = true;
        let findings = DuplicateAssetNameRisk.detect(&modules);
        assert!(
            findings.is_empty(),
            "foldl counting pattern should suppress duplicate-asset-name finding"
        );
    }

    #[test]
    fn test_still_detects_without_fold_pattern() {
        let mut tx = HashSet::new();
        tx.insert("mint".to_string());
        let mut fns = HashSet::new();
        fns.insert("value.quantity_of".to_string());

        let mut modules = make_mint_handler(tx, fns);
        modules[0].validators[0].handlers[0]
            .body_signals
            .has_fold_counting_pattern = false;
        let findings = DuplicateAssetNameRisk.detect(&modules);
        assert_eq!(
            findings.len(),
            1,
            "without fold pattern, should still detect"
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
        let findings = DuplicateAssetNameRisk.detect(&modules);
        assert!(findings.is_empty());
    }
}
