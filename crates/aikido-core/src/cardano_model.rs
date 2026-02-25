//! Cardano ledger rules and semantic model (Phase 4).
//!
//! Encodes Cardano-specific behavior that detectors use for reasoning:
//! Value multi-asset semantics, withdrawal guarantees, minting policy rules, etc.

use crate::ast_walker::HandlerInfo;

/// Cardano ledger rules that affect validator security.
pub struct LedgerRules;

impl LedgerRules {
    /// Value multi-asset comparison: `>=` on Value only checks lovelace.
    /// For proper multi-asset comparison, use `assets.match` with `==`.
    pub const VALUE_GEQ_ONLY_CHECKS_LOVELACE: &str = "value-geq-lovelace-only";

    /// Any staking script can be invoked with a 0-withdrawal amount.
    /// This means checking `withdrawals` for key existence is NOT sufficient
    /// for authentication — the withdrawal amount must also be verified.
    pub const WITHDRAW_ZERO_INVOCATION: &str = "withdraw-zero-invocation";

    /// Every minted token's policy is automatically executed by the ledger.
    /// A spend handler coordinating with a minting policy gets automatic
    /// policy execution without needing to check the policy explicitly.
    pub const MINTING_POLICY_AUTO_EXECUTION: &str = "minting-policy-auto-execution";

    /// Min-UTxO ledger rule: every UTxO must contain at least ~1 ADA.
    /// This is enforced by the ledger, not by validators.
    pub const MIN_UTXO_LEDGER_ENFORCED: &str = "min-utxo-ledger";

    /// Reference scripts are stored in UTxOs and don't need to be included
    /// in the transaction witness set. This can be exploited if the validator
    /// doesn't check for reference script injection.
    pub const REFERENCE_SCRIPT_SEMANTICS: &str = "reference-script-semantics";
}

/// Check if a handler uses Value comparison patterns that respect multi-asset semantics.
pub fn uses_safe_value_comparison(handler: &HandlerInfo) -> bool {
    let signals = &handler.body_signals;

    // Unsafe: assets.match used with non-equality comparator (>=, >, etc.)
    if signals.has_unsafe_match_comparison {
        return false;
    }

    // Safe: assets.match with equality comparator
    let has_assets_match = signals
        .function_calls
        .iter()
        .any(|c| c.contains("assets.match"));

    // Safe: quantity_of for specific asset checks
    let has_quantity_of = signals
        .function_calls
        .iter()
        .any(|c| c.contains("quantity_of"));

    // Safe: value.to_pairs for full enumeration
    let has_full_enum = signals
        .function_calls
        .iter()
        .any(|c| c.contains("value.to_pairs") || c.contains("flatten_with"));

    // Unsafe: lovelace_of without multi-asset checks
    let uses_lovelace_only = signals
        .function_calls
        .iter()
        .any(|c| c.contains("lovelace_of"))
        && !has_quantity_of
        && !has_assets_match
        && !has_full_enum;

    !uses_lovelace_only
        && (has_assets_match
            || has_quantity_of
            || has_full_enum
            || !signals
                .function_calls
                .iter()
                .any(|c| c.contains("lovelace_of")))
}

/// Quantity-only extraction without full Value semantics.
pub fn uses_partial_value_extraction(handler: &HandlerInfo) -> bool {
    let signals = &handler.body_signals;
    let has_quantity_of = signals
        .function_calls
        .iter()
        .any(|c| c.contains("quantity_of"));
    let has_full_value_check = signals.function_calls.iter().any(|c| {
        c.contains("assets.match")
            || c.contains("value.to_pairs")
            || c.contains("flatten_with")
            || c.contains("assets.tokens")
            || c.contains("assets.policies")
    });
    has_quantity_of && !has_full_value_check
}

/// Check if a handler properly validates withdrawal amounts (not just existence).
pub fn validates_withdrawal_amount(handler: &HandlerInfo) -> bool {
    let signals = &handler.body_signals;

    if !signals.tx_field_accesses.contains("withdrawals") {
        return false;
    }

    // Must do more than just has_key — should access the amount
    let checks_amount = signals.function_calls.iter().any(|c| {
        c.contains("dict.get") || c.contains("pairs.get_first") || c.contains("pairs.get_all")
    }) && (signals.has_subtraction
        || signals
            .guarded_vars
            .iter()
            .any(|v| v.contains("withdrawal") || v.contains("amount")));

    checks_amount
}

/// Check if a handler uses a token for identity verification without
/// checking the minting policy.
pub fn uses_token_as_identity(handler: &HandlerInfo) -> bool {
    let signals = &handler.body_signals;

    // Checks for specific token (quantity_of) in inputs
    let checks_token_in_inputs = signals.tx_field_accesses.contains("inputs")
        && signals
            .function_calls
            .iter()
            .any(|c| c.contains("quantity_of"));

    // But doesn't check the minting policy
    let checks_policy = signals.tx_field_accesses.contains("mint")
        || signals
            .function_calls
            .iter()
            .any(|c| c.contains("minting_policy"));

    checks_token_in_inputs && !checks_policy
}

/// Analyze a handler for Cardano-specific semantic issues.
pub fn analyze_cardano_semantics(handler: &HandlerInfo) -> Vec<CardanoSemanticIssue> {
    let mut issues = Vec::new();

    if !uses_safe_value_comparison(handler) {
        issues.push(CardanoSemanticIssue {
            rule: LedgerRules::VALUE_GEQ_ONLY_CHECKS_LOVELACE.to_string(),
            description: "Value comparison may not properly handle multi-asset values".to_string(),
        });
    }

    if handler
        .body_signals
        .tx_field_accesses
        .contains("withdrawals")
        && !validates_withdrawal_amount(handler)
    {
        issues.push(CardanoSemanticIssue {
            rule: LedgerRules::WITHDRAW_ZERO_INVOCATION.to_string(),
            description: "Withdrawal existence checked but amount not validated".to_string(),
        });
    }

    if uses_token_as_identity(handler) {
        issues.push(CardanoSemanticIssue {
            rule: LedgerRules::MINTING_POLICY_AUTO_EXECUTION.to_string(),
            description: "Token used for identity without minting policy verification".to_string(),
        });
    }

    issues
}

/// A Cardano semantic issue detected in a handler.
#[derive(Debug, Clone)]
pub struct CardanoSemanticIssue {
    pub rule: String,
    pub description: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::body_analysis::BodySignals;

    fn make_handler(fn_calls: &[&str], tx_accesses: &[&str]) -> HandlerInfo {
        HandlerInfo {
            name: "spend".to_string(),
            params: vec![],
            return_type: "Bool".to_string(),
            location: None,
            body_signals: BodySignals {
                function_calls: fn_calls.iter().map(|s| s.to_string()).collect(),
                tx_field_accesses: tx_accesses.iter().map(|s| s.to_string()).collect(),
                ..Default::default()
            },
        }
    }

    #[test]
    fn test_safe_value_comparison_with_assets_match() {
        let handler = make_handler(&["assets.match"], &["outputs"]);
        assert!(uses_safe_value_comparison(&handler));
    }

    #[test]
    fn test_unsafe_lovelace_only() {
        let handler = make_handler(&["value.lovelace_of"], &["outputs"]);
        assert!(!uses_safe_value_comparison(&handler));
    }

    #[test]
    fn test_safe_with_quantity_of() {
        let handler = make_handler(&["value.lovelace_of", "assets.quantity_of"], &["outputs"]);
        assert!(uses_safe_value_comparison(&handler));
    }

    #[test]
    fn test_unsafe_with_inequality_match() {
        let mut signals = BodySignals::default();
        signals.tx_field_accesses.insert("outputs".to_string());
        signals.function_calls.insert("assets.match".to_string());
        signals.has_unsafe_match_comparison = true;
        let handler = HandlerInfo {
            name: "spend".to_string(),
            params: vec![],
            return_type: "Bool".to_string(),
            location: None,
            body_signals: signals,
        };
        assert!(!uses_safe_value_comparison(&handler));
    }

    #[test]
    fn test_withdrawal_amount_validation() {
        let mut signals = BodySignals::default();
        signals.tx_field_accesses.insert("withdrawals".to_string());
        signals.function_calls.insert("dict.get".to_string());
        signals.has_subtraction = true;
        let handler = HandlerInfo {
            name: "spend".to_string(),
            params: vec![],
            return_type: "Bool".to_string(),
            location: None,
            body_signals: signals,
        };
        assert!(validates_withdrawal_amount(&handler));
    }

    #[test]
    fn test_withdrawal_only_existence_check() {
        let mut signals = BodySignals::default();
        signals.tx_field_accesses.insert("withdrawals".to_string());
        signals.function_calls.insert("dict.has_key".to_string());
        let handler = HandlerInfo {
            name: "spend".to_string(),
            params: vec![],
            return_type: "Bool".to_string(),
            location: None,
            body_signals: signals,
        };
        assert!(!validates_withdrawal_amount(&handler));
    }

    #[test]
    fn test_token_as_identity() {
        let handler = make_handler(&["assets.quantity_of"], &["inputs"]);
        assert!(uses_token_as_identity(&handler));
    }

    #[test]
    fn test_token_with_policy_check() {
        let handler = make_handler(&["assets.quantity_of"], &["inputs", "mint"]);
        assert!(!uses_token_as_identity(&handler));
    }
}
