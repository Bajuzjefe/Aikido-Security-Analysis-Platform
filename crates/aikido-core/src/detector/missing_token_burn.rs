use crate::ast_walker::{ModuleInfo, ModuleKind};
use crate::detector::{Confidence, Detector, Finding, Severity, SourceLocation};

/// Detects minting policies that handle minting but have no burn path.
pub struct MissingTokenBurn;

impl Detector for MissingTokenBurn {
    fn name(&self) -> &str {
        "missing-token-burn"
    }

    fn description(&self) -> &str {
        "Detects minting policies with no burn (negative quantity) handling"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn long_description(&self) -> &str {
        "A minting policy should handle both minting (positive quantities) and burning \
        (negative quantities). If the mint handler has no path for negative quantities, \
        tokens can never be burned, which may be a protocol design flaw. Some protocols \
        require burning tokens to reclaim collateral, close positions, or settle contracts. \
        Without a burn path, these tokens are permanently locked.\n\n\
        Example (vulnerable):\n  mint(redeemer, self) {\n    when redeemer is {\n      \
        Mint -> { // only handles minting }\n    }\n    // No Burn redeemer variant!\n  }\n\n\
        Fix: Handle both mint and burn:\n  mint(redeemer, self) {\n    when redeemer is {\n      \
        Mint -> { /* validate minting */ }\n      Burn -> { /* validate burning */ }\n    }\n  }"
    }

    fn cwe_id(&self) -> Option<&str> {
        Some("CWE-754")
    }

    fn category(&self) -> &str {
        "logic"
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

                    // Skip when mint handler delegates to a withdrawal script.
                    if signals.tx_field_accesses.contains("withdrawals")
                        && signals
                            .function_calls
                            .iter()
                            .any(|c| c.contains("has_key") || c.contains("is_withdrawal"))
                    {
                        continue;
                    }

                    // Skip one-shot minting patterns. One-shot NFTs/auth tokens are
                    // minted once and never burned by design. Indicators:
                    // - Single/no when branches (no Burn variant)
                    // - Exact mint validation (flatten, tokens+to_pairs, quantity_of)
                    // Note: Parameterized validators alone are NOT sufficient — many
                    // multi-phase protocols (perpetuals, DeFi) have params but still
                    // need burn paths.
                    let has_exact_mint_check = signals
                        .function_calls
                        .iter()
                        .any(|c| c.contains("flatten") || c.contains("to_pairs"))
                        && signals.function_calls.iter().any(|c| {
                            c.contains("quantity_of")
                                || c.contains("tokens")
                                || c.contains("from_asset")
                        });
                    let is_one_shot = signals.when_branches.len() <= 1 && has_exact_mint_check;
                    if is_one_shot {
                        continue;
                    }

                    // Check if the handler has any awareness of burning/negative quantities
                    let handles_burn = signals.when_branches.iter().any(|b| {
                        let p = b.pattern_text.to_lowercase();
                        p.contains("burn") || p.contains("destroy") || p.contains("redeem")
                    }) || signals.function_calls.iter().any(|c| {
                        let cl = c.to_lowercase();
                        cl.contains("burn") || cl.contains("negate") || cl.contains("negative")
                    }) || signals.var_references.iter().any(|v| {
                        let vl = v.to_lowercase();
                        vl.contains("burn") || vl.contains("destroy")
                    }) || signals.all_record_labels.iter().any(|l| {
                        let ll = l.to_lowercase();
                        ll.contains("burn") || ll.contains("destroy")
                    });

                    // Skip if the handler has no meaningful logic (caught by other detectors)
                    let has_logic = !signals.function_calls.is_empty()
                        || !signals.when_branches.is_empty()
                        || !signals.tx_field_accesses.is_empty();

                    if has_logic && !handles_burn {
                        findings.push(Finding {
                            detector_name: self.name().to_string(),
                            severity: self.severity(),
                            confidence: Confidence::Possible,
                            title: format!(
                                "Minting policy '{}' has no burn path",
                                validator.name
                            ),
                            description: format!(
                                "Mint handler for '{}' handles minting but has no code path \
                                for burning tokens (negative quantities). Tokens minted under \
                                this policy can never be burned.",
                                validator.name
                            ),
                            module: module.name.clone(),
                            location: handler
                                .location
                                .map(|(s, e)| SourceLocation::from_bytes(&module.path, s, e)),
                            suggestion: Some(
                                "Add a Burn redeemer variant or check for negative mint quantities \
                                with appropriate authorization."
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
    use crate::body_analysis::{BodySignals, WhenBranchInfo};
    use std::collections::HashSet;

    fn make_mint_handler(
        when_branches: Vec<WhenBranchInfo>,
        function_calls: HashSet<String>,
        var_refs: HashSet<String>,
        tx_accesses: HashSet<String>,
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
                        when_branches,
                        function_calls,
                        var_references: var_refs,
                        tx_field_accesses: tx_accesses,
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
    fn test_detects_missing_burn() {
        let branches = vec![WhenBranchInfo {
            pattern_text: "Mint".to_string(),
            is_catchall: false,
            body_is_literal_true: false,
            body_is_error: false,
        }];
        let mut tx = HashSet::new();
        tx.insert("mint".to_string());

        let modules = make_mint_handler(branches, HashSet::new(), HashSet::new(), tx);
        let findings = MissingTokenBurn.detect(&modules);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].title.contains("no burn path"));
    }

    #[test]
    fn test_no_finding_with_burn_branch() {
        let branches = vec![
            WhenBranchInfo {
                pattern_text: "Mint".to_string(),
                is_catchall: false,
                body_is_literal_true: false,
                body_is_error: false,
            },
            WhenBranchInfo {
                pattern_text: "Burn".to_string(),
                is_catchall: false,
                body_is_literal_true: false,
                body_is_error: false,
            },
        ];
        let mut tx = HashSet::new();
        tx.insert("mint".to_string());

        let modules = make_mint_handler(branches, HashSet::new(), HashSet::new(), tx);
        let findings = MissingTokenBurn.detect(&modules);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_no_finding_with_negate_call() {
        let mut fns = HashSet::new();
        fns.insert("value.negate".to_string());
        let mut tx = HashSet::new();
        tx.insert("mint".to_string());

        let modules = make_mint_handler(vec![], fns, HashSet::new(), tx);
        let findings = MissingTokenBurn.detect(&modules);
        assert!(findings.is_empty());
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

        let findings = MissingTokenBurn.detect(&modules);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_no_finding_for_empty_handler() {
        // Handler with no logic at all — caught by empty-handler-body detector
        let modules = make_mint_handler(vec![], HashSet::new(), HashSet::new(), HashSet::new());
        let findings = MissingTokenBurn.detect(&modules);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_no_finding_with_withdrawal_delegation() {
        let mut tx = HashSet::new();
        tx.insert("withdrawals".to_string());
        tx.insert("mint".to_string());
        let mut calls = HashSet::new();
        calls.insert("pairs.has_key".to_string());

        let modules = make_mint_handler(vec![], calls, HashSet::new(), tx);
        let findings = MissingTokenBurn.detect(&modules);
        assert!(findings.is_empty(), "withdrawal delegation should suppress");
    }

    #[test]
    fn test_no_finding_for_one_shot_mint() {
        // One-shot minting: single branch + flatten + quantity_of = exact token check
        let branches = vec![WhenBranchInfo {
            pattern_text: "Mint".to_string(),
            is_catchall: false,
            body_is_literal_true: false,
            body_is_error: false,
        }];
        let mut calls = HashSet::new();
        calls.insert("assets.flatten".to_string());
        calls.insert("assets.quantity_of".to_string());
        let mut tx = HashSet::new();
        tx.insert("mint".to_string());

        let modules = make_mint_handler(branches, calls, HashSet::new(), tx);
        let findings = MissingTokenBurn.detect(&modules);
        assert!(
            findings.is_empty(),
            "one-shot mint with flatten + quantity_of should suppress"
        );
    }
}
