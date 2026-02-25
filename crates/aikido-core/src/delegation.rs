//! Delegation pattern recognition for Cardano validators.
//!
//! Many Cardano DeFi protocols use a **withdraw-zero delegation** pattern:
//! a spend handler delegates validation to a staking/withdrawal handler by
//! checking `withdrawals` (via `dict.has_key` or `pairs.has_key`) but does NOT
//! itself validate `outputs`, `inputs`, or `extra_signatories`. The actual
//! security checks happen in the delegated withdrawal handler.
//!
//! Without recognizing this pattern, aikido flags the delegating handler for
//! missing checks that are actually performed by the delegate — causing
//! massive false positives on protocols like Strike Finance perpetuals.

use crate::ast_walker::{HandlerInfo, ModuleInfo, ModuleKind, ValidatorInfo};

/// Information about a detected delegation relationship.
#[derive(Debug, Clone)]
pub struct DelegationInfo {
    /// Module containing the delegating validator.
    pub module_name: String,
    /// Validator name.
    pub validator_name: String,
    /// Handler name (e.g., "spend").
    pub handler_name: String,
    /// The type of delegation detected.
    pub delegation_type: DelegationType,
}

/// The kind of delegation pattern detected.
#[derive(Debug, Clone, PartialEq)]
pub enum DelegationType {
    /// Handler accesses `withdrawals` and delegates to a staking handler.
    WithdrawZero,
    /// Handler accesses `mint` to coordinate with a minting policy.
    MintCoordination,
}

/// Detect all delegation patterns across all modules.
///
/// Returns a list of `DelegationInfo` for each handler that delegates
/// its validation to another handler/validator.
pub fn detect_delegation_patterns(modules: &[ModuleInfo]) -> Vec<DelegationInfo> {
    let mut delegations = Vec::new();

    for module in modules {
        if module.kind != ModuleKind::Validator {
            continue;
        }

        for validator in &module.validators {
            for handler in &validator.handlers {
                if let Some(dtype) = detect_handler_delegation(handler) {
                    delegations.push(DelegationInfo {
                        module_name: module.name.clone(),
                        validator_name: validator.name.clone(),
                        handler_name: handler.name.clone(),
                        delegation_type: dtype,
                    });
                }
            }
        }
    }

    delegations
}

/// Check if a single handler is a delegating handler.
///
/// A handler is "delegating" when it accesses `withdrawals` (the delegation
/// mechanism) but does NOT itself perform core validation:
/// - Does NOT iterate/check `outputs` (no output validation)
/// - Does NOT check `extra_signatories` (no signature validation)
///
/// This means the handler is relying on a withdrawal/staking handler to
/// perform those checks.
fn detect_handler_delegation(handler: &HandlerInfo) -> Option<DelegationType> {
    let signals = &handler.body_signals;

    // Check for withdraw-zero delegation pattern:
    // Handler accesses withdrawals (the delegation trigger) but doesn't
    // do its own output/signature validation.
    let accesses_withdrawals = signals.tx_field_accesses.contains("withdrawals")
        || signals.function_calls.iter().any(|c| {
            // dict.has_key or pairs.has_key on withdrawals
            (c.contains("has_key") || c.contains("pairs.get_first"))
                && signals.tx_field_accesses.contains("withdrawals")
        });

    if accesses_withdrawals {
        // The handler accesses withdrawals — now check if it delegates
        // (doesn't do its own core validation).
        let has_output_helper_validation = signals.function_calls.iter().any(|c| {
            c.contains("get_address_outputs")
                || c.contains("find_output")
                || c.contains("own_output")
                || c.contains("continuing_output")
                || c.contains("script_output")
        });
        let does_own_output_validation = (signals.tx_field_accesses.contains("outputs")
            && (signals.all_record_labels.contains("datum")
                || signals.all_record_labels.contains("address")
                || signals.all_record_labels.contains("value")
                || signals.var_references.iter().any(|v| {
                    v == "InlineDatum"
                        || v == "ScriptCredential"
                        || v == "VerificationKeyCredential"
                })))
            || has_output_helper_validation;

        let has_sig_helper_validation = signals.function_calls.iter().any(|c| {
            c.contains("is_signer")
                || c.contains("check_signatory")
                || c.contains("signed_by")
                || c.contains("authorized_by")
        });
        let does_own_sig_validation = (signals.tx_field_accesses.contains("extra_signatories")
            && signals
                .function_calls
                .iter()
                .any(|c| c.contains("list.has") || c.contains("list.any")))
            || has_sig_helper_validation;

        // If the handler doesn't validate outputs or signatures itself,
        // it's delegating to the withdrawal handler
        if !does_own_output_validation && !does_own_sig_validation {
            return Some(DelegationType::WithdrawZero);
        }
    }

    None
}

/// Check if a specific handler in a specific validator is delegating.
///
/// Convenience function for detectors to quickly check delegation status.
pub fn is_delegating_handler(
    handler: &HandlerInfo,
    _validator: &ValidatorInfo,
    _modules: &[ModuleInfo],
) -> bool {
    detect_handler_delegation(handler).is_some()
}

/// Build a set of (module_name, validator_name, handler_name) tuples
/// for all delegating handlers. Useful for O(1) lookups in detectors.
pub fn build_delegation_set(
    modules: &[ModuleInfo],
) -> std::collections::HashSet<(String, String, String)> {
    detect_delegation_patterns(modules)
        .into_iter()
        .map(|d| (d.module_name, d.validator_name, d.handler_name))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast_walker::*;
    use crate::body_analysis::BodySignals;

    fn make_handler_signals(
        tx_accesses: &[&str],
        fn_calls: &[&str],
        record_labels: &[&str],
        var_refs: &[&str],
    ) -> BodySignals {
        BodySignals {
            tx_field_accesses: tx_accesses.iter().map(|s| s.to_string()).collect(),
            function_calls: fn_calls.iter().map(|s| s.to_string()).collect(),
            all_record_labels: record_labels.iter().map(|s| s.to_string()).collect(),
            var_references: var_refs.iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        }
    }

    fn make_module(handlers: Vec<(&str, BodySignals)>) -> Vec<ModuleInfo> {
        let handler_infos: Vec<HandlerInfo> = handlers
            .into_iter()
            .map(|(name, signals)| HandlerInfo {
                name: name.to_string(),
                params: vec![],
                return_type: "Bool".to_string(),
                location: None,
                body_signals: signals,
            })
            .collect();

        vec![ModuleInfo {
            name: "test/validator".to_string(),
            path: "validator.ak".to_string(),
            kind: ModuleKind::Validator,
            validators: vec![ValidatorInfo {
                name: "test".to_string(),
                params: vec![],
                handlers: handler_infos,
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
    fn test_detects_withdraw_zero_delegation() {
        // Handler accesses withdrawals but doesn't validate outputs or signatures
        let signals = make_handler_signals(&["withdrawals", "inputs"], &["dict.has_key"], &[], &[]);
        let modules = make_module(vec![("spend", signals)]);
        let delegations = detect_delegation_patterns(&modules);

        assert_eq!(delegations.len(), 1);
        assert_eq!(delegations[0].delegation_type, DelegationType::WithdrawZero);
    }

    #[test]
    fn test_no_delegation_when_outputs_validated() {
        // Handler accesses withdrawals AND validates outputs — not pure delegation
        let signals = make_handler_signals(
            &["withdrawals", "outputs"],
            &["dict.has_key", "list.any"],
            &["datum", "address"],
            &["InlineDatum"],
        );
        let modules = make_module(vec![("spend", signals)]);
        let delegations = detect_delegation_patterns(&modules);

        assert!(
            delegations.is_empty(),
            "handler that validates outputs is not delegating"
        );
    }

    #[test]
    fn test_no_delegation_when_signatures_checked() {
        // Handler accesses withdrawals AND checks signatures — not pure delegation
        let signals = make_handler_signals(
            &["withdrawals", "extra_signatories"],
            &["dict.has_key", "list.has"],
            &[],
            &[],
        );
        let modules = make_module(vec![("spend", signals)]);
        let delegations = detect_delegation_patterns(&modules);

        assert!(
            delegations.is_empty(),
            "handler that checks signatures is not delegating"
        );
    }

    #[test]
    fn test_no_delegation_with_output_helper_call() {
        // Output validation can be delegated into utility/helper functions.
        // This should not be classified as pure withdraw-zero delegation.
        let signals = make_handler_signals(
            &["withdrawals"],
            &["dict.has_key", "utils.get_address_outputs"],
            &[],
            &[],
        );
        let modules = make_module(vec![("spend", signals)]);
        let delegations = detect_delegation_patterns(&modules);

        assert!(
            delegations.is_empty(),
            "output helper calls imply own output validation"
        );
    }

    #[test]
    fn test_no_delegation_without_withdrawals() {
        // Handler without withdrawals access is not using delegation
        let signals = make_handler_signals(&["outputs", "inputs"], &["list.any"], &[], &[]);
        let modules = make_module(vec![("spend", signals)]);
        let delegations = detect_delegation_patterns(&modules);

        assert!(delegations.is_empty());
    }

    #[test]
    fn test_skips_lib_modules() {
        let modules = vec![ModuleInfo {
            name: "test/utils".to_string(),
            path: "utils.ak".to_string(),
            kind: ModuleKind::Lib,
            validators: vec![],
            data_types: vec![],
            functions: vec![],
            constants: vec![],
            type_aliases: vec![],
            test_count: 0,
            source_code: None,
            test_function_names: vec![],
        }];

        let delegations = detect_delegation_patterns(&modules);
        assert!(delegations.is_empty());
    }

    #[test]
    fn test_build_delegation_set() {
        let signals = make_handler_signals(&["withdrawals", "inputs"], &["dict.has_key"], &[], &[]);
        let modules = make_module(vec![("spend", signals)]);
        let set = build_delegation_set(&modules);

        assert!(set.contains(&(
            "test/validator".to_string(),
            "test".to_string(),
            "spend".to_string()
        )));
    }

    #[test]
    fn test_is_delegating_handler_true() {
        let signals = make_handler_signals(&["withdrawals"], &["dict.has_key"], &[], &[]);
        let handler = HandlerInfo {
            name: "spend".to_string(),
            params: vec![],
            return_type: "Bool".to_string(),
            location: None,
            body_signals: signals,
        };
        let validator = ValidatorInfo {
            name: "test".to_string(),
            params: vec![],
            handlers: vec![handler.clone()],
            summary: None,
        };

        assert!(is_delegating_handler(&handler, &validator, &[]));
    }

    #[test]
    fn test_is_delegating_handler_false() {
        let signals = make_handler_signals(&["outputs", "inputs"], &["list.any"], &["datum"], &[]);
        let handler = HandlerInfo {
            name: "spend".to_string(),
            params: vec![],
            return_type: "Bool".to_string(),
            location: None,
            body_signals: signals,
        };
        let validator = ValidatorInfo {
            name: "test".to_string(),
            params: vec![],
            handlers: vec![handler.clone()],
            summary: None,
        };

        assert!(!is_delegating_handler(&handler, &validator, &[]));
    }

    #[test]
    fn test_delegation_with_outputs_but_value_check() {
        // Handler accesses withdrawals AND outputs with value check —
        // checking output value IS output validation, so NOT delegating
        let signals = make_handler_signals(
            &["withdrawals", "outputs"],
            &["dict.has_key"],
            &["value"],
            &[],
        );
        let modules = make_module(vec![("spend", signals)]);
        let delegations = detect_delegation_patterns(&modules);

        assert!(
            delegations.is_empty(),
            "checking output value IS output validation — not delegating"
        );
    }

    #[test]
    fn test_delegation_with_outputs_but_no_validation_labels() {
        // Handler accesses withdrawals AND outputs, but no datum/address/value labels —
        // outputs access alone without any validation labels still counts as delegating
        let signals = make_handler_signals(
            &["withdrawals", "outputs"],
            &["dict.has_key"],
            &[], // no validation labels at all
            &[],
        );
        let modules = make_module(vec![("spend", signals)]);
        let delegations = detect_delegation_patterns(&modules);

        assert_eq!(
            delegations.len(),
            1,
            "accessing outputs without any validation labels is still delegating"
        );
    }
}
