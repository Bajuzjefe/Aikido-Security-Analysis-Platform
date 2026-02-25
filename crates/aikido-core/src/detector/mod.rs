pub mod trait_def;
pub use trait_def::*;

pub mod arbitrary_datum_in_output;
pub mod cheap_spam_vulnerability;
pub mod cross_validator_gap;
pub mod datum_field_bounds;
pub mod dead_branch_detection;
pub mod dead_code_path;
pub mod division_by_zero_risk;
pub mod double_satisfaction;
pub mod duplicate_asset_name_risk;
pub mod empty_handler_body;
pub mod excessive_validator_params;
pub mod fail_only_redeemer_branch;
pub mod fee_calculation_unchecked;
pub mod hardcoded_addresses;
pub mod identity_token_forgery;
pub mod incomplete_burn_flow;
pub mod incomplete_value_extraction;
pub mod insufficient_staking_control;
pub mod integer_underflow_risk;
pub mod invariant_violation;
pub mod magic_numbers;
pub mod missing_datum_field_validation;
pub mod missing_datum_in_script_output;
pub mod missing_input_credential_check;
pub mod missing_min_ada_check;
pub mod missing_minting_policy_check;
pub mod missing_redeemer_validation;
pub mod missing_signature_check;
pub mod missing_state_update;
pub mod missing_token_burn;
pub mod missing_utxo_authentication;
pub mod missing_validity_range;
pub mod multi_asset_comparison_bypass;
pub mod non_exhaustive_redeemer;
pub mod oracle_freshness_not_checked;
pub mod other_token_minting;
pub mod output_address_not_validated;
pub mod path_sensitive_guard_check;
pub mod precise_taint_to_sink;
pub mod quantity_of_double_counting;
pub mod redundant_check;
pub mod reference_script_injection;
pub mod rounding_error_risk;
pub mod shadowed_variable;
pub mod state_machine_violation;
pub mod state_transition_integrity;
pub mod token_name_not_validated;
pub mod unbounded_datum_size;
pub mod unbounded_list_iteration;
pub mod unbounded_value_size;
pub mod unconstrained_recursion;
pub mod uncoordinated_multi_validator;
pub mod uncoordinated_state_transfer;
pub mod unrestricted_minting;
pub mod unsafe_datum_deconstruction;
pub mod unsafe_list_head;
pub mod unsafe_match_comparison;
pub mod unsafe_partial_pattern;
pub mod unsafe_redeemer_arithmetic;
pub mod unused_import;
pub mod unused_library_module;
pub mod unused_validator_parameter;
pub mod utxo_contention_risk;
pub mod value_not_preserved;
pub mod value_preservation_gap;
pub mod withdraw_amount_check;
pub mod withdraw_zero_trick;

pub mod datum_tampering_risk;
pub mod missing_burn_verification;
pub mod missing_protocol_token;
pub mod oracle_manipulation_risk;
pub mod output_count_validation;
pub mod tautological_comparison;
pub mod unbounded_protocol_operations;
pub mod value_comparison_semantics;

use crate::ast_walker::ModuleInfo;

use arbitrary_datum_in_output::ArbitraryDatumInOutput;
use cheap_spam_vulnerability::CheapSpamVulnerability;
use cross_validator_gap::CrossValidatorGap;
use datum_field_bounds::DatumFieldBounds;
use dead_branch_detection::DeadBranchDetection;
use dead_code_path::DeadCodePath;
use division_by_zero_risk::DivisionByZeroRisk;
use double_satisfaction::DoubleSatisfaction;
use duplicate_asset_name_risk::DuplicateAssetNameRisk;
use empty_handler_body::EmptyHandlerBody;
use excessive_validator_params::ExcessiveValidatorParams;
use fail_only_redeemer_branch::FailOnlyRedeemerBranch;
use fee_calculation_unchecked::FeeCalculationUnchecked;
use hardcoded_addresses::HardcodedAddresses;
use identity_token_forgery::IdentityTokenForgery;
use incomplete_burn_flow::IncompleteBurnFlow;
use incomplete_value_extraction::IncompleteValueExtraction;
use insufficient_staking_control::InsufficientStakingControl;
use integer_underflow_risk::IntegerUnderflowRisk;
use invariant_violation::InvariantViolation;
use magic_numbers::MagicNumbers;
use missing_datum_field_validation::MissingDatumFieldValidation;
use missing_datum_in_script_output::MissingDatumInScriptOutput;
use missing_input_credential_check::MissingInputCredentialCheck;
use missing_min_ada_check::MissingMinAdaCheck;
use missing_minting_policy_check::MissingMintingPolicyCheck;
use missing_redeemer_validation::MissingRedeemerValidation;
use missing_signature_check::MissingSignatureCheck;
use missing_state_update::MissingStateUpdate;
use missing_token_burn::MissingTokenBurn;
use missing_utxo_authentication::MissingUtxoAuthentication;
use missing_validity_range::MissingValidityRange;
use multi_asset_comparison_bypass::MultiAssetComparisonBypass;
use non_exhaustive_redeemer::NonExhaustiveRedeemer;
use oracle_freshness_not_checked::OracleFreshnessNotChecked;
use other_token_minting::OtherTokenMinting;
use output_address_not_validated::OutputAddressNotValidated;
use path_sensitive_guard_check::PathSensitiveGuardCheck;
use precise_taint_to_sink::PreciseTaintToSink;
use quantity_of_double_counting::QuantityOfDoubleCounting;
use redundant_check::RedundantCheck;
use reference_script_injection::ReferenceScriptInjection;
use rounding_error_risk::RoundingErrorRisk;
use shadowed_variable::ShadowedVariable;
use state_machine_violation::StateMachineViolation;
use state_transition_integrity::StateTransitionIntegrity;
use token_name_not_validated::TokenNameNotValidated;
use unbounded_datum_size::UnboundedDatumSize;
use unbounded_list_iteration::UnboundedListIteration;
use unbounded_value_size::UnboundedValueSize;
use unconstrained_recursion::UnconstrainedRecursion;
use uncoordinated_multi_validator::UncoordinatedMultiValidator;
use uncoordinated_state_transfer::UncoordinatedStateTransfer;
use unrestricted_minting::UnrestrictedMinting;
use unsafe_datum_deconstruction::UnsafeDatumDeconstruction;
use unsafe_list_head::UnsafeListHead;
use unsafe_match_comparison::UnsafeMatchComparison;
use unsafe_partial_pattern::UnsafePartialPattern;
use unsafe_redeemer_arithmetic::UnsafeRedeemerArithmetic;
use unused_import::UnusedImport;
use unused_library_module::UnusedLibraryModule;
use unused_validator_parameter::UnusedValidatorParameter;
use utxo_contention_risk::UtxoContentionRisk;
use value_not_preserved::ValueNotPreserved;
use value_preservation_gap::ValuePreservationGap;
use withdraw_amount_check::WithdrawAmountCheck;
use withdraw_zero_trick::WithdrawZeroTrick;

use datum_tampering_risk::DatumTamperingRisk;
use missing_burn_verification::MissingBurnVerification;
use missing_protocol_token::MissingProtocolToken;
use oracle_manipulation_risk::OracleManipulationRisk;
use output_count_validation::OutputCountValidation;
use tautological_comparison::TautologicalComparison;
use unbounded_protocol_operations::UnboundedProtocolOperations;
use value_comparison_semantics::ValueComparisonSemantics;

/// Returns all registered detectors.
pub fn all_detectors() -> Vec<Box<dyn Detector>> {
    vec![
        Box::new(DoubleSatisfaction),
        Box::new(MissingRedeemerValidation),
        Box::new(MissingValidityRange),
        Box::new(MissingSignatureCheck),
        Box::new(UnsafeDatumDeconstruction),
        Box::new(UnboundedListIteration),
        Box::new(HardcodedAddresses),
        Box::new(MissingMintingPolicyCheck),
        Box::new(MissingUtxoAuthentication),
        Box::new(UnrestrictedMinting),
        Box::new(UnusedValidatorParameter),
        Box::new(FailOnlyRedeemerBranch),
        Box::new(MissingDatumInScriptOutput),
        Box::new(ArbitraryDatumInOutput),
        Box::new(InsufficientStakingControl),
        Box::new(UnboundedDatumSize),
        Box::new(DivisionByZeroRisk),
        Box::new(NonExhaustiveRedeemer),
        Box::new(UnsafeListHead),
        Box::new(TokenNameNotValidated),
        Box::new(ValueNotPreserved),
        Box::new(UnboundedValueSize),
        Box::new(OracleFreshnessNotChecked),
        Box::new(MissingMinAdaCheck),
        Box::new(DeadCodePath),
        Box::new(RedundantCheck),
        Box::new(ShadowedVariable),
        Box::new(MagicNumbers),
        Box::new(ExcessiveValidatorParams),
        Box::new(UnusedImport),
        Box::new(UnsafePartialPattern),
        Box::new(UnconstrainedRecursion),
        Box::new(EmptyHandlerBody),
        Box::new(UtxoContentionRisk),
        Box::new(CheapSpamVulnerability),
        Box::new(UnsafeMatchComparison),
        Box::new(IntegerUnderflowRisk),
        Box::new(QuantityOfDoubleCounting),
        Box::new(OutputAddressNotValidated),
        Box::new(MissingDatumFieldValidation),
        Box::new(ReferenceScriptInjection),
        Box::new(MissingTokenBurn),
        Box::new(StateTransitionIntegrity),
        Box::new(MissingStateUpdate),
        Box::new(WithdrawZeroTrick),
        Box::new(OtherTokenMinting),
        Box::new(RoundingErrorRisk),
        Box::new(MissingInputCredentialCheck),
        Box::new(UnsafeRedeemerArithmetic),
        Box::new(DuplicateAssetNameRisk),
        Box::new(ValuePreservationGap),
        Box::new(FeeCalculationUnchecked),
        Box::new(UncoordinatedMultiValidator),
        Box::new(DatumTamperingRisk),
        Box::new(MissingBurnVerification),
        Box::new(OracleManipulationRisk),
        Box::new(MissingProtocolToken),
        Box::new(UnboundedProtocolOperations),
        Box::new(UnusedLibraryModule),
        Box::new(ValueComparisonSemantics),
        Box::new(OutputCountValidation),
        Box::new(TautologicalComparison),
        // Phase 2: IR-based detectors
        Box::new(PathSensitiveGuardCheck),
        Box::new(PreciseTaintToSink),
        Box::new(DeadBranchDetection),
        // Phase 3: Cross-validator detectors
        Box::new(CrossValidatorGap),
        Box::new(UncoordinatedStateTransfer),
        Box::new(IncompleteBurnFlow),
        // Phase 4: Cardano semantics detectors
        Box::new(MultiAssetComparisonBypass),
        Box::new(IncompleteValueExtraction),
        Box::new(IdentityTokenForgery),
        Box::new(WithdrawAmountCheck),
        // Phase 5: State machine / invariant detectors
        Box::new(StateMachineViolation),
        Box::new(InvariantViolation),
        Box::new(DatumFieldBounds),
    ]
}

const STABLE_DETECTORS: &[&str] = &[
    "double-satisfaction",
    "missing-redeemer-validation",
    "missing-signature-check",
    "missing-minting-policy-check",
    "missing-utxo-authentication",
    "unrestricted-minting",
    "unsafe-datum-deconstruction",
    "missing-validity-range",
    "state-transition-integrity",
    "withdraw-zero-trick",
    "withdraw-amount-check",
    "value-not-preserved",
    "missing-token-burn",
    "missing-state-update",
];

const EXPERIMENTAL_DETECTORS: &[&str] = &[
    "path-sensitive-guard-check",
    "precise-taint-to-sink",
    "cross-validator-gap",
    "uncoordinated-state-transfer",
    "uncoordinated-multi-validator",
    "incomplete-burn-flow",
    "state-machine-violation",
    "invariant-violation",
    "datum-field-bounds",
    "multi-asset-comparison-bypass",
    "incomplete-value-extraction",
    "identity-token-forgery",
];

/// Reliability tier for detector quality policy and release gating.
pub fn detector_reliability_tier(detector_name: &str) -> DetectorReliabilityTier {
    if STABLE_DETECTORS.contains(&detector_name) {
        DetectorReliabilityTier::Stable
    } else if EXPERIMENTAL_DETECTORS.contains(&detector_name) {
        DetectorReliabilityTier::Experimental
    } else {
        DetectorReliabilityTier::Beta
    }
}

/// Run all detectors against the given modules and return sorted findings.
pub fn run_detectors(modules: &[ModuleInfo]) -> Vec<Finding> {
    let detectors = all_detectors();
    let mut findings: Vec<Finding> = detectors.iter().flat_map(|d| d.detect(modules)).collect();

    // Resolve byte offsets → line:column using source code
    resolve_finding_locations(&mut findings, modules);

    // Sort by severity (Critical first)
    findings.sort_by(|a, b| severity_order(&b.severity).cmp(&severity_order(&a.severity)));

    // Deduplicate findings with the same root cause
    dedup_findings(&mut findings);

    // Consolidate overlapping detectors on the same handler
    consolidate_findings(&mut findings);

    findings
}

/// Deduplicate findings that share the same root cause.
/// Two findings are considered duplicates if they come from the same detector,
/// in the same module, at the same byte offset.
pub fn dedup_findings(findings: &mut Vec<Finding>) {
    let mut seen = std::collections::HashSet::new();
    findings.retain(|f| {
        let byte = f.location.as_ref().map_or(0, |l| l.byte_start);
        let key = format!("{}:{}:{}", f.detector_name, f.module, byte);
        seen.insert(key)
    });
}

/// Consolidation rules: when a higher-severity detector fires on the same module+handler
/// as a lower-severity one, the lower one is absorbed (suppressed) and its detector name
/// is added to the survivor's `related_findings`.
const CONSOLIDATION_RULES: &[(&str, &str)] = &[
    // (suppressed, survivor): suppressed is absorbed when survivor fires on same module
    // Note: fee-calculation-unchecked and integer-underflow-risk are distinct concerns
    // (fee manipulation vs underflow) and should NOT be consolidated.
    ("arbitrary-datum-in-output", "state-transition-integrity"),
    (
        "missing-datum-in-script-output",
        "state-transition-integrity",
    ),
    // withdraw-amount-check is a stricter variant of withdraw-zero-trick and
    // often fires on the same root cause. Keep the higher-severity survivor.
    ("withdraw-amount-check", "withdraw-zero-trick"),
];

/// Consolidate overlapping detectors that fire on the same module.
/// Suppressed findings are removed and their names are added to the survivor's `related_findings`.
pub fn consolidate_findings(findings: &mut Vec<Finding>) {
    // Build set of (module, detector) pairs for quick lookup
    let active: std::collections::HashSet<(String, String)> = findings
        .iter()
        .map(|f| (f.module.clone(), f.detector_name.clone()))
        .collect();

    // Identify which findings to suppress
    let mut suppress_indices = std::collections::HashSet::new();
    let mut absorb_map: std::collections::HashMap<(String, String), Vec<String>> =
        std::collections::HashMap::new();

    for (i, finding) in findings.iter().enumerate() {
        for &(suppressed, survivor) in CONSOLIDATION_RULES {
            if finding.detector_name == suppressed
                && active.contains(&(finding.module.clone(), survivor.to_string()))
            {
                suppress_indices.insert(i);
                absorb_map
                    .entry((finding.module.clone(), survivor.to_string()))
                    .or_default()
                    .push(suppressed.to_string());
            }
        }
    }

    // Add absorbed detector names to survivors
    for finding in findings.iter_mut() {
        let key = (finding.module.clone(), finding.detector_name.clone());
        if let Some(absorbed) = absorb_map.get(&key) {
            finding.related_findings.extend(absorbed.iter().cloned());
        }
    }

    // Remove suppressed findings (iterate in reverse to preserve indices)
    let mut indices: Vec<usize> = suppress_indices.into_iter().collect();
    indices.sort_unstable_by(|a, b| b.cmp(a));
    for i in indices {
        findings.remove(i);
    }
}

/// Resolve byte offsets in finding locations to line:column using module source code.
pub fn resolve_finding_locations(findings: &mut [Finding], modules: &[ModuleInfo]) {
    // Build a map of module path → source code
    let source_map: std::collections::HashMap<&str, &str> = modules
        .iter()
        .filter_map(|m| m.source_code.as_deref().map(|src| (m.path.as_str(), src)))
        .collect();

    for finding in findings.iter_mut() {
        if let Some(ref mut loc) = finding.location {
            if let Some(source) = source_map.get(loc.module_path.as_str()) {
                loc.resolve(source);
            }
        }
    }
}

// severity_order() is imported from trait_def via `pub use trait_def::*`

// --- Shared detector utilities ---

/// Extract the base type name, stripping module prefixes and Option<...> wrapping.
/// e.g., "Option<sentaku/contracts/datum.PositionDatum>" -> "PositionDatum"
pub(crate) fn type_base_name(type_name: &str) -> &str {
    let inner = type_name
        .strip_prefix("Option<")
        .and_then(|s| s.strip_suffix('>'))
        .unwrap_or(type_name);
    inner.rsplit('.').next().unwrap_or(inner)
}

/// Check if a field label matches any of the given patterns using word-boundary
/// matching on `_`-delimited segments. Prevents "ownership" from matching "owner".
///
/// Matches when the pattern appears as:
/// - The entire label: "owner" matches "owner"
/// - A `_`-delimited prefix: "owner_key" matches "owner"
/// - A `_`-delimited suffix: "position_owner" matches "owner"
/// - A `_`-delimited infix: "my_owner_key" matches "owner"
/// - Multi-word patterns: "expires_at" matches "position_expires_at"
pub(crate) fn matches_field_pattern(label: &str, patterns: &[&str]) -> bool {
    let lower = label.to_lowercase();
    patterns.iter().any(|&pattern| {
        lower == pattern
            || lower.starts_with(&format!("{pattern}_"))
            || lower.ends_with(&format!("_{pattern}"))
            || lower.contains(&format!("_{pattern}_"))
    })
}

/// Patterns indicating outputs go to script addresses (not PKH wallets).
const SCRIPT_ADDRESS_INDICATORS: &[&str] = &[
    "ScriptCredential",
    "Script",
    "script_credential",
    "pay_to_script",
    "script_hash",
    "validator_hash",
];

/// PKH (wallet) address indicators — positive evidence that outputs target wallets.
const PKH_ADDRESS_INDICATORS: &[&str] = &[
    "VerificationKeyCredential",
    "VerificationKey",
    "pay_to_pkh",
    "has_output_to_pkh",
    "output_to_pkh",
    "pkh_address",
    "wallet_address",
    "credential.VerificationKey",
];

/// Check if a handler's signals indicate that outputs go to PKH (wallet) addresses only.
///
/// Returns true only when there is POSITIVE evidence of PKH/wallet outputs
/// (e.g., `VerificationKeyCredential` referenced). The absence of script references
/// alone is NOT sufficient — a vulnerable validator might simply omit address checks,
/// and that omission itself is part of the vulnerability.
pub(crate) fn outputs_go_to_pkh_only(signals: &crate::body_analysis::BodySignals) -> bool {
    // Must access outputs for this check to be meaningful
    if !signals.tx_field_accesses.contains("outputs") {
        return false;
    }

    // Require POSITIVE evidence of PKH output patterns
    let has_pkh_ref = signals
        .var_references
        .iter()
        .any(|v| PKH_ADDRESS_INDICATORS.iter().any(|ind| v.contains(ind)))
        || signals
            .function_calls
            .iter()
            .any(|c| PKH_ADDRESS_INDICATORS.iter().any(|ind| c.contains(ind)));

    // Also suppress if script address IS referenced — this means the handler
    // already deals with script outputs (not purely PKH). Only return true
    // when PKH is referenced WITHOUT script addresses.
    let has_script_ref = signals
        .var_references
        .iter()
        .any(|v| SCRIPT_ADDRESS_INDICATORS.iter().any(|ind| v.contains(ind)))
        || signals
            .function_calls
            .iter()
            .any(|c| SCRIPT_ADDRESS_INDICATORS.iter().any(|ind| c.contains(ind)));

    has_pkh_ref && !has_script_ref
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_type_base_name() {
        assert_eq!(type_base_name("PositionDatum"), "PositionDatum");
        assert_eq!(type_base_name("datum.PositionDatum"), "PositionDatum");
        assert_eq!(type_base_name("a.b.c"), "c");
        assert_eq!(
            type_base_name("Option<sentaku/contracts/datum.PositionDatum>"),
            "PositionDatum"
        );
        assert_eq!(type_base_name("Option<Datum>"), "Datum");
    }

    #[test]
    fn test_matches_field_pattern_exact() {
        assert!(matches_field_pattern("owner", &["owner"]));
        assert!(matches_field_pattern("deadline", &["deadline"]));
    }

    #[test]
    fn test_matches_field_pattern_prefix() {
        assert!(matches_field_pattern("owner_key", &["owner"]));
        assert!(matches_field_pattern("deadline_ms", &["deadline"]));
    }

    #[test]
    fn test_matches_field_pattern_suffix() {
        assert!(matches_field_pattern("position_owner", &["owner"]));
        assert!(matches_field_pattern("my_deadline", &["deadline"]));
    }

    #[test]
    fn test_matches_field_pattern_infix() {
        assert!(matches_field_pattern("my_owner_key", &["owner"]));
    }

    #[test]
    fn test_matches_field_pattern_no_partial_match() {
        assert!(!matches_field_pattern("ownership", &["owner"]));
        assert!(!matches_field_pattern("coowner", &["owner"]));
        assert!(!matches_field_pattern("deadlines", &["deadline"]));
        assert!(!matches_field_pattern("mydeadline", &["deadline"]));
    }

    #[test]
    fn test_matches_field_pattern_multiword() {
        assert!(matches_field_pattern("expires_at", &["expires_at"]));
        assert!(matches_field_pattern(
            "position_expires_at",
            &["expires_at"]
        ));
        assert!(!matches_field_pattern("expires_atomic", &["expires_at"]));
    }

    #[test]
    fn test_matches_field_pattern_case_insensitive() {
        assert!(matches_field_pattern("Owner", &["owner"]));
        assert!(matches_field_pattern("DEADLINE", &["deadline"]));
    }

    #[test]
    fn test_dedup_removes_duplicate_findings() {
        use crate::detector::Confidence;

        let f1 = Finding {
            detector_name: "test-detector".to_string(),
            severity: Severity::High,
            confidence: Confidence::Likely,
            title: "Finding 1".to_string(),
            description: "Desc".to_string(),
            module: "mod_a".to_string(),
            location: Some(crate::detector::SourceLocation::from_bytes(
                "test.ak", 100, 200,
            )),
            suggestion: None,
            related_findings: vec![],
            semantic_group: None,

            evidence: None,
        };
        let f2 = Finding {
            detector_name: "test-detector".to_string(),
            severity: Severity::High,
            confidence: Confidence::Likely,
            title: "Finding 1 duplicate".to_string(),
            description: "Desc".to_string(),
            module: "mod_a".to_string(),
            location: Some(crate::detector::SourceLocation::from_bytes(
                "test.ak", 100, 200,
            )),
            suggestion: None,
            related_findings: vec![],
            semantic_group: None,

            evidence: None,
        };
        let f3 = Finding {
            detector_name: "other-detector".to_string(),
            severity: Severity::Medium,
            confidence: Confidence::Possible,
            title: "Different finding".to_string(),
            description: "Desc".to_string(),
            module: "mod_a".to_string(),
            location: Some(crate::detector::SourceLocation::from_bytes(
                "test.ak", 100, 200,
            )),
            suggestion: None,
            related_findings: vec![],
            semantic_group: None,

            evidence: None,
        };

        let mut findings = vec![f1, f2, f3];
        dedup_findings(&mut findings);
        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].detector_name, "test-detector");
        assert_eq!(findings[1].detector_name, "other-detector");
    }

    fn make_finding(detector: &str, module: &str) -> Finding {
        Finding {
            detector_name: detector.to_string(),
            severity: Severity::High,
            confidence: Confidence::Likely,
            title: format!("{detector} finding"),
            description: "test".to_string(),
            module: module.to_string(),
            location: None,
            suggestion: None,
            related_findings: vec![],
            semantic_group: None,

            evidence: None,
        }
    }

    #[test]
    fn test_fee_calc_not_absorbed_by_underflow() {
        // fee-calculation-unchecked and integer-underflow-risk are distinct concerns
        let mut findings = vec![
            make_finding("integer-underflow-risk", "mod_a"),
            make_finding("fee-calculation-unchecked", "mod_a"),
        ];
        consolidate_findings(&mut findings);
        assert_eq!(
            findings.len(),
            2,
            "fee-calc and underflow are distinct — should not be consolidated"
        );
    }

    #[test]
    fn test_consolidate_datum_detectors_absorbed_by_state_transition() {
        let mut findings = vec![
            make_finding("state-transition-integrity", "mod_a"),
            make_finding("arbitrary-datum-in-output", "mod_a"),
            make_finding("missing-datum-in-script-output", "mod_a"),
        ];
        consolidate_findings(&mut findings);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].detector_name, "state-transition-integrity");
        assert!(findings[0]
            .related_findings
            .contains(&"arbitrary-datum-in-output".to_string()));
        assert!(findings[0]
            .related_findings
            .contains(&"missing-datum-in-script-output".to_string()));
    }

    #[test]
    fn test_consolidate_different_modules_not_absorbed() {
        let mut findings = vec![
            make_finding("integer-underflow-risk", "mod_a"),
            make_finding("fee-calculation-unchecked", "mod_b"),
        ];
        consolidate_findings(&mut findings);
        assert_eq!(
            findings.len(),
            2,
            "different modules should not be consolidated"
        );
    }

    #[test]
    fn test_consolidate_standalone_not_suppressed() {
        let mut findings = vec![
            make_finding("fee-calculation-unchecked", "mod_a"),
            make_finding("other-detector", "mod_a"),
        ];
        consolidate_findings(&mut findings);
        assert_eq!(
            findings.len(),
            2,
            "standalone findings should not be suppressed"
        );
    }

    #[test]
    fn test_reliability_tier_known_stable_detector() {
        assert_eq!(
            detector_reliability_tier("double-satisfaction"),
            DetectorReliabilityTier::Stable
        );
    }

    #[test]
    fn test_reliability_tier_known_experimental_detector() {
        assert_eq!(
            detector_reliability_tier("cross-validator-gap"),
            DetectorReliabilityTier::Experimental
        );
    }

    #[test]
    fn test_reliability_tier_default_beta() {
        assert_eq!(
            detector_reliability_tier("magic-numbers"),
            DetectorReliabilityTier::Beta
        );
    }
}
