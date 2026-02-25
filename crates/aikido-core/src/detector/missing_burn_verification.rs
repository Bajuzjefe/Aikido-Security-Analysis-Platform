use crate::ast_walker::{ModuleInfo, ModuleKind};
use crate::body_analysis::WhenBranchInfo;
use crate::detector::{Confidence, Detector, Finding, Severity, SourceLocation};

/// Destructive action names commonly found in DeFi handler names or redeemer branches.
const DESTRUCTIVE_PATTERNS: &[&str] = &[
    "liquidat",
    "close",
    "cancel",
    "withdraw",
    "redeem",
    "settle",
    "burn",
    "destroy",
    "remove",
    "exit",
    "terminate",
    "expire",
    "claim",
];

/// Check if a handler name or its redeemer branches indicate a destructive flow.
fn is_destructive_handler(handler_name: &str, when_branches: &[WhenBranchInfo]) -> bool {
    let lower_name = handler_name.to_lowercase();
    if DESTRUCTIVE_PATTERNS.iter().any(|p| lower_name.contains(p)) {
        return true;
    }
    when_branches.iter().any(|b| {
        let lower = b.pattern_text.to_lowercase();
        DESTRUCTIVE_PATTERNS.iter().any(|p| lower.contains(p))
    })
}

/// Detects spend handlers that reduce value (withdrawals, redemptions) without
/// verifying corresponding token burns in the mint field.
///
/// In DeFi protocols, withdrawing value from a pool typically requires burning
/// LP tokens or receipt tokens. If the spend handler doesn't check the mint
/// field during value reduction, tokens remain in circulation without backing.
pub struct MissingBurnVerification;

impl Detector for MissingBurnVerification {
    fn name(&self) -> &str {
        "missing-burn-verification"
    }

    fn description(&self) -> &str {
        "Detects value reduction in spend handlers without verifying token burns"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn long_description(&self) -> &str {
        "When a spend handler processes a withdrawal or value reduction (indicated by \
        subtraction operations and output production), it should verify that corresponding \
        tokens are burned in the same transaction. Without checking the `mint` field:\n\
        - LP tokens aren't burned during pool withdrawals (value backed by nothing)\n\
        - Receipt tokens aren't burned during redemptions (double-spend risk)\n\
        - Debt tokens aren't burned during loan repayments (phantom debt)\n\n\
        Example (vulnerable):\n  spend(datum, Withdraw, own_ref, self) {\n    \
        let new_reserve = datum.reserve - withdrawal_amount\n    \
        // Doesn't check self.mint for LP token burn!\n  }\n\n\
        Fix: Verify burn:\n  let burned = value.from_minted_value(self.mint)\n  \
        expect value.quantity_of(burned, lp_policy, lp_name) < 0"
    }

    fn cwe_id(&self) -> Option<&str> {
        Some("CWE-682")
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
                    if handler.name != "spend" {
                        continue;
                    }

                    let signals = &handler.body_signals;

                    // Must produce outputs (continuing UTXO)
                    if !signals.tx_field_accesses.contains("outputs") {
                        continue;
                    }

                    // Must NOT check mint field (no burn verification)
                    if signals.tx_field_accesses.contains("mint") {
                        continue;
                    }

                    // Must have either:
                    // 1. Subtraction (value reduction), OR
                    // 2. Token consumption via quantity_of on inputs in destructive flows
                    let has_value_reduction = signals.has_subtraction;

                    let has_token_consumption = signals.quantity_of_call_count > 0
                        && signals.tx_field_accesses.contains("inputs")
                        && is_destructive_handler(&handler.name, &signals.when_branches);

                    if !has_value_reduction && !has_token_consumption {
                        continue;
                    }

                    // Only flag if the validator also has a mint handler
                    // (if no mint handler, there are no protocol tokens to burn)
                    let has_mint_handler = validator.handlers.iter().any(|h| h.name == "mint");

                    if !has_mint_handler {
                        continue;
                    }

                    findings.push(Finding {
                        detector_name: self.name().to_string(),
                        severity: self.severity(),
                        confidence: Confidence::Possible,
                        title: format!(
                            "Value reduction in {}.{} without burn verification",
                            validator.name, handler.name
                        ),
                        description: format!(
                            "Handler {}.{} performs value subtraction and produces continuing \
                            outputs but doesn't check the `mint` field. The validator has a \
                            mint handler, so protocol tokens exist — withdrawals should verify \
                            corresponding tokens are burned.",
                            validator.name, handler.name
                        ),
                        module: module.name.clone(),
                        location: handler
                            .location
                            .map(|(s, e)| SourceLocation::from_bytes(&module.path, s, e)),
                        suggestion: Some(
                            "Verify token burns during withdrawals: \
                            `let burned = value.from_minted_value(self.mint)` then check \
                            `value.quantity_of(burned, policy, name) < 0`."
                                .to_string(),
                        ),
                        related_findings: vec![],
                        semantic_group: None,

                        evidence: None,
                    });
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
        spend_tx: HashSet<String>,
        has_subtraction: bool,
        has_mint_handler: bool,
    ) -> Vec<ModuleInfo> {
        let mut handlers = vec![HandlerInfo {
            name: "spend".to_string(),
            params: vec![],
            return_type: "Bool".to_string(),
            location: None,
            body_signals: BodySignals {
                tx_field_accesses: spend_tx,
                has_subtraction,
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
    fn test_detects_missing_burn() {
        let mut tx = HashSet::new();
        tx.insert("outputs".to_string());

        let modules = make_multi_validator(tx, true, true);
        let findings = MissingBurnVerification.detect(&modules);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn test_no_finding_when_mint_checked() {
        let mut tx = HashSet::new();
        tx.insert("outputs".to_string());
        tx.insert("mint".to_string());

        let modules = make_multi_validator(tx, true, true);
        let findings = MissingBurnVerification.detect(&modules);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_no_finding_without_subtraction() {
        let mut tx = HashSet::new();
        tx.insert("outputs".to_string());

        let modules = make_multi_validator(tx, false, true);
        let findings = MissingBurnVerification.detect(&modules);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_no_finding_without_mint_handler() {
        let mut tx = HashSet::new();
        tx.insert("outputs".to_string());

        let modules = make_multi_validator(tx, true, false);
        let findings = MissingBurnVerification.detect(&modules);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_no_finding_without_outputs() {
        let modules = make_multi_validator(HashSet::new(), true, true);
        let findings = MissingBurnVerification.detect(&modules);
        assert!(findings.is_empty());
    }
}
