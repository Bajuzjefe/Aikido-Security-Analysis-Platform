//! Dual-pattern compliance/violation architecture.
//!
//! Traditional static analyzers only look for **violations** — patterns that
//! indicate a vulnerability. This module adds the complementary side:
//! **compliance** — patterns that indicate a security property IS correctly
//! enforced. By cross-referencing both, we can:
//!
//! 1. Confirm violations (no compliance evidence found)
//! 2. Suppress false positives (compliance evidence contradicts the finding)
//! 3. Reduce confidence (partial compliance evidence)
//!
//! This is especially valuable for Cardano validators where security patterns
//! (signature checks, UTXO authentication, datum continuity) have well-known
//! idioms that can be positively identified.

use std::collections::HashMap;

use serde::Serialize;

use crate::ast_walker::{DataTypeInfo, ModuleInfo, ModuleKind};
use crate::body_analysis::BodySignals;
use crate::detector::{matches_field_pattern, Confidence, Finding};

// ---------------------------------------------------------------------------
// Core types
// ---------------------------------------------------------------------------

/// A compliance pattern — evidence that a security property IS enforced.
#[derive(Debug, Clone, Serialize)]
pub struct ComplianceEvidence {
    /// The security property being verified.
    pub property: SecurityProperty,
    /// Module where the compliance was observed.
    pub module: String,
    /// Handler where the compliance was observed.
    pub handler: String,
    /// Description of how compliance is achieved.
    pub description: String,
    /// Confidence in the compliance finding (0.0 to 1.0).
    pub confidence: f64,
}

/// Security properties that can be checked for compliance.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub enum SecurityProperty {
    SignatureVerification,
    MintAuthorization,
    UtxoAuthentication,
    OutputAddressValidation,
    DatumIntegrity,
    ValuePreservation,
    TimeConstraint,
    BurnAuthorization,
    RedeemerValidation,
    StateTransitionCheck,
}

impl std::fmt::Display for SecurityProperty {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SecurityProperty::SignatureVerification => write!(f, "signature-verification"),
            SecurityProperty::MintAuthorization => write!(f, "mint-authorization"),
            SecurityProperty::UtxoAuthentication => write!(f, "utxo-authentication"),
            SecurityProperty::OutputAddressValidation => write!(f, "output-address-validation"),
            SecurityProperty::DatumIntegrity => write!(f, "datum-integrity"),
            SecurityProperty::ValuePreservation => write!(f, "value-preservation"),
            SecurityProperty::TimeConstraint => write!(f, "time-constraint"),
            SecurityProperty::BurnAuthorization => write!(f, "burn-authorization"),
            SecurityProperty::RedeemerValidation => write!(f, "redeemer-validation"),
            SecurityProperty::StateTransitionCheck => write!(f, "state-transition-check"),
        }
    }
}

/// Result of dual-pattern analysis on a finding.
#[derive(Debug, Clone)]
pub enum DualPatternResult {
    /// Violation confirmed — no compliance evidence found.
    ViolationConfirmed(Finding),
    /// Violation suppressed — compliance evidence found.
    ComplianceSuppressed {
        original_finding: Finding,
        compliance: ComplianceEvidence,
    },
    /// Reduced confidence — partial compliance evidence.
    ReducedConfidence {
        finding: Finding,
        partial_compliance: ComplianceEvidence,
        original_confidence: Confidence,
    },
}

impl DualPatternResult {
    /// Returns `true` if this result is a confirmed violation.
    pub fn is_violation(&self) -> bool {
        matches!(self, DualPatternResult::ViolationConfirmed(_))
    }

    /// Returns `true` if this result was suppressed by compliance evidence.
    pub fn is_suppressed(&self) -> bool {
        matches!(self, DualPatternResult::ComplianceSuppressed { .. })
    }

    /// Extract the finding, regardless of result type.
    pub fn finding(&self) -> &Finding {
        match self {
            DualPatternResult::ViolationConfirmed(f) => f,
            DualPatternResult::ComplianceSuppressed {
                original_finding, ..
            } => original_finding,
            DualPatternResult::ReducedConfidence { finding, .. } => finding,
        }
    }

    /// Consume the result and return the finding.
    pub fn into_finding(self) -> Finding {
        match self {
            DualPatternResult::ViolationConfirmed(f) => f,
            DualPatternResult::ComplianceSuppressed {
                original_finding, ..
            } => original_finding,
            DualPatternResult::ReducedConfidence { finding, .. } => finding,
        }
    }
}

// ---------------------------------------------------------------------------
// Compliance checker trait
// ---------------------------------------------------------------------------

/// Trait for checking compliance patterns.
///
/// Each implementation checks for a specific security property's correct
/// enforcement in validator handler bodies. When positive evidence is found,
/// the checker returns `ComplianceEvidence` describing how the property is
/// enforced.
pub trait ComplianceChecker: Send + Sync {
    /// The security property this checker verifies.
    fn property(&self) -> SecurityProperty;

    /// Check if a specific handler demonstrates compliance with this property.
    ///
    /// Returns `Some(ComplianceEvidence)` when the handler shows positive evidence
    /// that the security property is enforced, `None` otherwise.
    fn check_compliance(
        &self,
        modules: &[ModuleInfo],
        module_name: &str,
        handler_name: &str,
    ) -> Option<ComplianceEvidence>;
}

// ---------------------------------------------------------------------------
// Compliance checker implementations
// ---------------------------------------------------------------------------

/// Authority-like field patterns (same as in missing-signature-check detector).
const AUTHORITY_FIELD_PATTERNS: &[&str] = &[
    "owner",
    "beneficiary",
    "admin",
    "authority",
    "operator",
    "creator",
];

/// Checks for `extra_signatories` usage with authority-related datum fields.
///
/// Compliance is established when:
/// 1. The datum type has authority-like ByteArray fields (owner, admin, etc.)
/// 2. The handler accesses `extra_signatories` from the transaction
/// 3. The handler references authority field names in its body
pub struct SignatureComplianceChecker;

impl ComplianceChecker for SignatureComplianceChecker {
    fn property(&self) -> SecurityProperty {
        SecurityProperty::SignatureVerification
    }

    fn check_compliance(
        &self,
        modules: &[ModuleInfo],
        module_name: &str,
        handler_name: &str,
    ) -> Option<ComplianceEvidence> {
        let (signals, _module) = find_handler_signals(modules, module_name, handler_name)?;

        // Must access extra_signatories
        if !signals.tx_field_accesses.contains("extra_signatories") {
            return None;
        }

        // Collect authority fields from datum types across all modules
        let authority_fields = collect_authority_fields(modules);
        if authority_fields.is_empty() {
            // No authority fields defined, but signatories are checked — partial compliance
            return Some(ComplianceEvidence {
                property: self.property(),
                module: module_name.to_string(),
                handler: handler_name.to_string(),
                description: "Handler checks extra_signatories but no authority datum fields found"
                    .to_string(),
                confidence: 0.5,
            });
        }

        // Check if handler references authority field names (datum field access)
        let references_authority = authority_fields.iter().any(|(_, fields)| {
            fields.iter().any(|field| {
                signals.datum_field_accesses.contains(field)
                    || signals.var_references.contains(field)
                    || signals.all_record_labels.iter().any(|l| l.contains(field))
            })
        });

        let (description, confidence) = if references_authority {
            (
                "Handler verifies extra_signatories against authority datum fields".to_string(),
                0.9,
            )
        } else {
            (
                "Handler checks extra_signatories (authority field correlation not confirmed)"
                    .to_string(),
                0.6,
            )
        };

        Some(ComplianceEvidence {
            property: self.property(),
            module: module_name.to_string(),
            handler: handler_name.to_string(),
            description,
            confidence,
        })
    }
}

/// Checks for proper authorization in mint handlers.
///
/// Compliance is established when a mint handler:
/// 1. Checks `extra_signatories` (signature authorization), OR
/// 2. Checks `inputs` (UTXO-based authorization), OR
/// 3. Checks `mint` field (self-referential minting policy check)
pub struct MintAuthorizationChecker;

impl ComplianceChecker for MintAuthorizationChecker {
    fn property(&self) -> SecurityProperty {
        SecurityProperty::MintAuthorization
    }

    fn check_compliance(
        &self,
        modules: &[ModuleInfo],
        module_name: &str,
        handler_name: &str,
    ) -> Option<ComplianceEvidence> {
        // Only relevant for mint handlers
        if handler_name != "mint" {
            return None;
        }

        let (signals, _module) = find_handler_signals(modules, module_name, handler_name)?;

        let checks_signatories = signals.tx_field_accesses.contains("extra_signatories");
        let checks_inputs = signals.tx_field_accesses.contains("inputs");
        let checks_mint = signals.tx_field_accesses.contains("mint");
        let checks_ref_inputs = signals.tx_field_accesses.contains("reference_inputs");

        let mut mechanisms = Vec::new();
        if checks_signatories {
            mechanisms.push("signature verification");
        }
        if checks_inputs {
            mechanisms.push("input UTXO consumption");
        }
        if checks_mint {
            mechanisms.push("minting policy self-check");
        }
        if checks_ref_inputs {
            mechanisms.push("reference input verification");
        }

        if mechanisms.is_empty() {
            return None;
        }

        let confidence = match mechanisms.len() {
            1 => 0.7,
            2 => 0.85,
            _ => 0.95,
        };

        Some(ComplianceEvidence {
            property: self.property(),
            module: module_name.to_string(),
            handler: handler_name.to_string(),
            description: format!("Mint handler uses authorization: {}", mechanisms.join(", ")),
            confidence,
        })
    }
}

/// Checks for `own_ref` usage and input authentication.
///
/// Compliance is established when:
/// 1. The handler uses `own_ref` (OutputReference parameter), AND
/// 2. The handler accesses `inputs` to authenticate its own UTXO
pub struct UtxoAuthChecker;

impl ComplianceChecker for UtxoAuthChecker {
    fn property(&self) -> SecurityProperty {
        SecurityProperty::UtxoAuthentication
    }

    fn check_compliance(
        &self,
        modules: &[ModuleInfo],
        module_name: &str,
        handler_name: &str,
    ) -> Option<ComplianceEvidence> {
        let (signals, _module) = find_handler_signals(modules, module_name, handler_name)?;

        let uses_own_ref = signals.uses_own_ref;
        let checks_inputs = signals.tx_field_accesses.contains("inputs");
        let enforces_single_input = signals.enforces_single_input;

        if !uses_own_ref && !enforces_single_input {
            return None;
        }

        let (description, confidence) = if uses_own_ref && checks_inputs {
            (
                "Handler authenticates own UTXO via own_ref + inputs check".to_string(),
                0.9,
            )
        } else if enforces_single_input {
            (
                "Handler enforces single-input constraint (prevents double satisfaction)"
                    .to_string(),
                0.85,
            )
        } else if uses_own_ref {
            (
                "Handler references own_ref but may not fully authenticate inputs".to_string(),
                0.6,
            )
        } else {
            return None;
        };

        Some(ComplianceEvidence {
            property: self.property(),
            module: module_name.to_string(),
            handler: handler_name.to_string(),
            description,
            confidence,
        })
    }
}

/// Checks for address validation in output construction.
///
/// Compliance is established when:
/// 1. The handler accesses `outputs`
/// 2. The handler checks `address`, `payment_credential`, or `ScriptCredential`
pub struct OutputAddressChecker;

impl ComplianceChecker for OutputAddressChecker {
    fn property(&self) -> SecurityProperty {
        SecurityProperty::OutputAddressValidation
    }

    fn check_compliance(
        &self,
        modules: &[ModuleInfo],
        module_name: &str,
        handler_name: &str,
    ) -> Option<ComplianceEvidence> {
        let (signals, _module) = find_handler_signals(modules, module_name, handler_name)?;

        // Must access outputs
        if !signals.tx_field_accesses.contains("outputs") {
            return None;
        }

        let checks_address = signals
            .all_record_labels
            .iter()
            .any(|l| l == "address" || l == "payment_credential");

        let checks_script_credential = signals
            .var_references
            .iter()
            .any(|v| v.contains("ScriptCredential") || v.contains("VerificationKeyCredential"));

        let checks_via_function = signals.function_calls.iter().any(|c| {
            c.contains("payment_credential")
                || c.contains("address")
                || c.contains("script_hash")
                || c.contains("ScriptCredential")
        });

        if !checks_address && !checks_script_credential && !checks_via_function {
            return None;
        }

        let mut evidence = Vec::new();
        if checks_address {
            evidence.push("address/payment_credential field access");
        }
        if checks_script_credential {
            evidence.push("credential type verification");
        }
        if checks_via_function {
            evidence.push("address validation function call");
        }

        let confidence = match evidence.len() {
            1 => 0.7,
            2 => 0.85,
            _ => 0.95,
        };

        Some(ComplianceEvidence {
            property: self.property(),
            module: module_name.to_string(),
            handler: handler_name.to_string(),
            description: format!("Output address validated via: {}", evidence.join(", ")),
            confidence,
        })
    }
}

/// Checks for datum continuity assertion patterns.
///
/// Compliance is established when:
/// 1. The handler has a datum continuity assertion (`input_datum == output_datum`), OR
/// 2. The handler uses record update syntax (preserving unmodified fields), OR
/// 3. The handler checks individual datum fields between input and output
pub struct DatumIntegrityChecker;

impl ComplianceChecker for DatumIntegrityChecker {
    fn property(&self) -> SecurityProperty {
        SecurityProperty::DatumIntegrity
    }

    fn check_compliance(
        &self,
        modules: &[ModuleInfo],
        module_name: &str,
        handler_name: &str,
    ) -> Option<ComplianceEvidence> {
        let (signals, _module) = find_handler_signals(modules, module_name, handler_name)?;

        if signals.has_datum_continuity_assertion {
            return Some(ComplianceEvidence {
                property: self.property(),
                module: module_name.to_string(),
                handler: handler_name.to_string(),
                description: "Handler asserts full datum continuity (input == output datum)"
                    .to_string(),
                confidence: 0.95,
            });
        }

        if signals.has_record_update {
            return Some(ComplianceEvidence {
                property: self.property(),
                module: module_name.to_string(),
                handler: handler_name.to_string(),
                description:
                    "Handler uses record update syntax (preserves unmodified datum fields)"
                        .to_string(),
                confidence: 0.85,
            });
        }

        if !signals.datum_equality_checks.is_empty() {
            let field_count = signals.datum_equality_checks.len();
            let confidence = if field_count >= 3 { 0.8 } else { 0.6 };

            return Some(ComplianceEvidence {
                property: self.property(),
                module: module_name.to_string(),
                handler: handler_name.to_string(),
                description: format!(
                    "Handler checks {} datum field(s) for equality between input and output",
                    field_count
                ),
                confidence,
            });
        }

        None
    }
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

/// Find the BodySignals for a specific handler in a specific module.
fn find_handler_signals<'a>(
    modules: &'a [ModuleInfo],
    module_name: &str,
    handler_name: &str,
) -> Option<(&'a BodySignals, &'a ModuleInfo)> {
    for module in modules {
        if module.name != module_name {
            continue;
        }
        for validator in &module.validators {
            for handler in &validator.handlers {
                if handler.name == handler_name {
                    return Some((&handler.body_signals, module));
                }
            }
        }
    }
    None
}

/// Collect authority-like fields from all datum types across modules.
fn collect_authority_fields(modules: &[ModuleInfo]) -> Vec<(String, Vec<String>)> {
    modules
        .iter()
        .flat_map(|m| &m.data_types)
        .filter_map(|dt| {
            let fields: Vec<String> = find_authority_fields_in_type(dt);
            if fields.is_empty() {
                None
            } else {
                Some((dt.name.clone(), fields))
            }
        })
        .collect()
}

/// Find authority-like ByteArray fields in a data type.
fn find_authority_fields_in_type(dt: &DataTypeInfo) -> Vec<String> {
    dt.constructors
        .iter()
        .flat_map(|c| &c.fields)
        .filter(|f| {
            if let Some(label) = &f.label {
                matches_field_pattern(label, AUTHORITY_FIELD_PATTERNS) && f.type_name == "ByteArray"
            } else {
                false
            }
        })
        .filter_map(|f| f.label.clone())
        .collect()
}

/// Extract the handler name from a finding's title.
///
/// Many detectors encode the handler location in the title as
/// `"... in validator_name.handler_name"`. We extract the handler name
/// from this pattern and also check the finding's module to locate signals.
fn extract_handler_from_finding(finding: &Finding, modules: &[ModuleInfo]) -> Option<String> {
    // Strategy 1: Parse from title "... in validator.handler"
    if let Some(pos) = finding.title.rfind(" in ") {
        let suffix = &finding.title[pos + 4..];
        if let Some(dot_pos) = suffix.rfind('.') {
            let handler_name = &suffix[dot_pos + 1..];
            // Verify this handler exists in the module
            if handler_exists(modules, &finding.module, handler_name) {
                return Some(handler_name.to_string());
            }
        }
        // Maybe the suffix is just the handler name
        let trimmed = suffix.trim();
        if handler_exists(modules, &finding.module, trimmed) {
            return Some(trimmed.to_string());
        }
    }

    // Strategy 2: For module-level findings, check all handlers
    // Return the first handler in the module (detectors typically fire per-handler)
    for module in modules {
        if module.name == finding.module {
            for validator in &module.validators {
                if let Some(handler) = validator.handlers.first() {
                    return Some(handler.name.clone());
                }
            }
        }
    }

    None
}

/// Check if a handler with the given name exists in a module.
fn handler_exists(modules: &[ModuleInfo], module_name: &str, handler_name: &str) -> bool {
    modules.iter().any(|m| {
        m.name == module_name
            && m.validators
                .iter()
                .any(|v| v.handlers.iter().any(|h| h.name == handler_name))
    })
}

// ---------------------------------------------------------------------------
// Detector-to-property mapping
// ---------------------------------------------------------------------------

/// Map detector names to their corresponding security properties.
fn detector_to_property(detector_name: &str) -> Option<SecurityProperty> {
    match detector_name {
        "missing-signature-check" => Some(SecurityProperty::SignatureVerification),
        "unrestricted-minting" | "missing-minting-policy-check" | "other-token-minting" => {
            Some(SecurityProperty::MintAuthorization)
        }
        "missing-utxo-authentication" | "double-satisfaction" => {
            Some(SecurityProperty::UtxoAuthentication)
        }
        "output-address-not-validated" => Some(SecurityProperty::OutputAddressValidation),
        "state-transition-integrity"
        | "arbitrary-datum-in-output"
        | "missing-datum-in-script-output"
        | "datum-tampering-risk"
        | "missing-datum-field-validation" => Some(SecurityProperty::DatumIntegrity),
        "value-not-preserved" | "value-preservation-gap" => {
            Some(SecurityProperty::ValuePreservation)
        }
        "missing-validity-range" | "oracle-freshness-not-checked" => {
            Some(SecurityProperty::TimeConstraint)
        }
        "missing-token-burn" | "incomplete-burn-flow" | "missing-burn-verification" => {
            Some(SecurityProperty::BurnAuthorization)
        }
        "missing-redeemer-validation" | "non-exhaustive-redeemer" => {
            Some(SecurityProperty::RedeemerValidation)
        }
        "missing-state-update" | "state-machine-violation" => {
            Some(SecurityProperty::StateTransitionCheck)
        }
        _ => None,
    }
}

/// Get all registered compliance checkers.
fn all_compliance_checkers() -> Vec<Box<dyn ComplianceChecker>> {
    vec![
        Box::new(SignatureComplianceChecker),
        Box::new(MintAuthorizationChecker),
        Box::new(UtxoAuthChecker),
        Box::new(OutputAddressChecker),
        Box::new(DatumIntegrityChecker),
    ]
}

// ---------------------------------------------------------------------------
// Main public API
// ---------------------------------------------------------------------------

/// Apply dual-pattern analysis to a set of findings.
///
/// For each finding, this function:
/// 1. Maps the detector to a security property
/// 2. Runs the corresponding compliance checker
/// 3. Returns a `DualPatternResult` indicating whether the violation is
///    confirmed, suppressed, or has reduced confidence
///
/// Findings whose detectors don't map to any security property are
/// passed through as `ViolationConfirmed`.
pub fn apply_dual_pattern_analysis(
    findings: Vec<Finding>,
    modules: &[ModuleInfo],
) -> Vec<DualPatternResult> {
    let checkers = all_compliance_checkers();

    // Build lookup: SecurityProperty -> ComplianceChecker
    let checker_map: HashMap<SecurityProperty, &dyn ComplianceChecker> = checkers
        .iter()
        .map(|c| (c.property(), c.as_ref()))
        .collect();

    findings
        .into_iter()
        .map(|finding| {
            let property = match detector_to_property(&finding.detector_name) {
                Some(p) => p,
                None => return DualPatternResult::ViolationConfirmed(finding),
            };

            let checker = match checker_map.get(&property) {
                Some(c) => c,
                None => return DualPatternResult::ViolationConfirmed(finding),
            };

            // Extract handler name from the finding
            let handler_name = match extract_handler_from_finding(&finding, modules) {
                Some(h) => h,
                None => return DualPatternResult::ViolationConfirmed(finding),
            };

            match checker.check_compliance(modules, &finding.module, &handler_name) {
                Some(compliance) if compliance.confidence >= 0.8 => {
                    DualPatternResult::ComplianceSuppressed {
                        original_finding: finding,
                        compliance,
                    }
                }
                Some(partial_compliance) => {
                    let original_confidence = finding.confidence.clone();
                    let mut downgraded = finding;
                    // Reduce confidence: Definite -> Likely, Likely -> Possible
                    downgraded.confidence = match downgraded.confidence {
                        Confidence::Definite => Confidence::Likely,
                        Confidence::Likely => Confidence::Possible,
                        Confidence::Possible => Confidence::Possible,
                    };
                    DualPatternResult::ReducedConfidence {
                        finding: downgraded,
                        partial_compliance,
                        original_confidence,
                    }
                }
                None => DualPatternResult::ViolationConfirmed(finding),
            }
        })
        .collect()
}

/// Filter findings using dual-pattern analysis, returning only confirmed violations.
///
/// This is a convenience function that applies dual-pattern analysis and returns
/// only the findings that are either:
/// - Confirmed violations (no compliance evidence)
/// - Reduced confidence (partial compliance, but still reported)
///
/// Fully suppressed findings (high-confidence compliance) are removed.
pub fn filter_with_compliance(findings: Vec<Finding>, modules: &[ModuleInfo]) -> Vec<Finding> {
    apply_dual_pattern_analysis(findings, modules)
        .into_iter()
        .filter_map(|result| match result {
            DualPatternResult::ViolationConfirmed(f) => Some(f),
            DualPatternResult::ReducedConfidence { finding, .. } => Some(finding),
            DualPatternResult::ComplianceSuppressed { .. } => None,
        })
        .collect()
}

/// Collect all compliance evidence across all modules and handlers.
///
/// This provides a positive security posture view — showing what IS
/// correctly implemented, independent of any violation findings.
pub fn collect_all_compliance(modules: &[ModuleInfo]) -> Vec<ComplianceEvidence> {
    let checkers = all_compliance_checkers();
    let mut evidence = Vec::new();

    for module in modules {
        if module.kind != ModuleKind::Validator {
            continue;
        }
        for validator in &module.validators {
            for handler in &validator.handlers {
                for checker in &checkers {
                    if let Some(e) = checker.check_compliance(modules, &module.name, &handler.name)
                    {
                        evidence.push(e);
                    }
                }
            }
        }
    }

    evidence
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast_walker::*;
    use crate::body_analysis::BodySignals;
    use crate::detector::Severity;
    use std::collections::HashSet;

    // --- Test helpers ---

    fn make_validator_module(
        module_name: &str,
        validator_name: &str,
        handler_name: &str,
        signals: BodySignals,
    ) -> ModuleInfo {
        ModuleInfo {
            name: module_name.to_string(),
            path: format!("{module_name}.ak"),
            kind: ModuleKind::Validator,
            validators: vec![ValidatorInfo {
                name: validator_name.to_string(),
                params: vec![],
                handlers: vec![HandlerInfo {
                    name: handler_name.to_string(),
                    params: vec![ParamInfo {
                        name: "datum".to_string(),
                        type_name: "TestDatum".to_string(),
                    }],
                    return_type: "Bool".to_string(),
                    location: None,
                    body_signals: signals,
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
        }
    }

    fn make_lib_module_with_types(data_types: Vec<DataTypeInfo>) -> ModuleInfo {
        ModuleInfo {
            name: "test/types".to_string(),
            path: "types.ak".to_string(),
            kind: ModuleKind::Lib,
            validators: vec![],
            data_types,
            functions: vec![],
            constants: vec![],
            type_aliases: vec![],
            test_count: 0,
            source_code: None,
            test_function_names: vec![],
        }
    }

    fn make_datum_type_with_fields(fields: Vec<(&str, &str)>) -> DataTypeInfo {
        DataTypeInfo {
            name: "TestDatum".to_string(),
            public: true,
            constructors: vec![ConstructorInfo {
                name: "TestDatum".to_string(),
                fields: fields
                    .into_iter()
                    .map(|(name, typ)| FieldInfo {
                        label: Some(name.to_string()),
                        type_name: typ.to_string(),
                    })
                    .collect(),
            }],
        }
    }

    fn make_finding(detector: &str, module: &str, handler: &str) -> Finding {
        Finding {
            detector_name: detector.to_string(),
            severity: Severity::High,
            confidence: Confidence::Likely,
            title: format!("{detector} finding in test_validator.{handler}"),
            description: "test finding".to_string(),
            module: module.to_string(),
            location: None,
            suggestion: None,
            related_findings: vec![],
            semantic_group: None,
            evidence: None,
        }
    }

    // --- SecurityProperty Display tests ---

    #[test]
    fn test_security_property_display() {
        assert_eq!(
            SecurityProperty::SignatureVerification.to_string(),
            "signature-verification"
        );
        assert_eq!(
            SecurityProperty::MintAuthorization.to_string(),
            "mint-authorization"
        );
        assert_eq!(
            SecurityProperty::UtxoAuthentication.to_string(),
            "utxo-authentication"
        );
        assert_eq!(
            SecurityProperty::OutputAddressValidation.to_string(),
            "output-address-validation"
        );
        assert_eq!(
            SecurityProperty::DatumIntegrity.to_string(),
            "datum-integrity"
        );
        assert_eq!(
            SecurityProperty::ValuePreservation.to_string(),
            "value-preservation"
        );
        assert_eq!(
            SecurityProperty::TimeConstraint.to_string(),
            "time-constraint"
        );
        assert_eq!(
            SecurityProperty::BurnAuthorization.to_string(),
            "burn-authorization"
        );
        assert_eq!(
            SecurityProperty::RedeemerValidation.to_string(),
            "redeemer-validation"
        );
        assert_eq!(
            SecurityProperty::StateTransitionCheck.to_string(),
            "state-transition-check"
        );
    }

    // --- DualPatternResult tests ---

    #[test]
    fn test_dual_pattern_result_is_violation() {
        let finding = make_finding("test-detector", "mod_a", "spend");
        let result = DualPatternResult::ViolationConfirmed(finding);
        assert!(result.is_violation());
        assert!(!result.is_suppressed());
    }

    #[test]
    fn test_dual_pattern_result_is_suppressed() {
        let finding = make_finding("test-detector", "mod_a", "spend");
        let result = DualPatternResult::ComplianceSuppressed {
            original_finding: finding,
            compliance: ComplianceEvidence {
                property: SecurityProperty::SignatureVerification,
                module: "mod_a".to_string(),
                handler: "spend".to_string(),
                description: "test".to_string(),
                confidence: 0.9,
            },
        };
        assert!(result.is_suppressed());
        assert!(!result.is_violation());
    }

    #[test]
    fn test_dual_pattern_result_finding_access() {
        let finding = make_finding("test-detector", "mod_a", "spend");
        let expected_title = finding.title.clone();

        let result = DualPatternResult::ViolationConfirmed(finding);
        assert_eq!(result.finding().title, expected_title);
    }

    #[test]
    fn test_dual_pattern_result_into_finding() {
        let finding = make_finding("test-detector", "mod_a", "spend");
        let expected_title = finding.title.clone();

        let result = DualPatternResult::ViolationConfirmed(finding);
        let extracted = result.into_finding();
        assert_eq!(extracted.title, expected_title);
    }

    // --- SignatureComplianceChecker tests ---

    #[test]
    fn test_signature_compliance_with_signatories_and_authority_fields() {
        let mut tx_accesses = HashSet::new();
        tx_accesses.insert("extra_signatories".to_string());

        let mut datum_accesses = HashSet::new();
        datum_accesses.insert("owner".to_string());

        let signals = BodySignals {
            tx_field_accesses: tx_accesses,
            datum_field_accesses: datum_accesses,
            ..Default::default()
        };

        let validator_module =
            make_validator_module("test/validator", "my_validator", "spend", signals);
        let type_module = make_lib_module_with_types(vec![make_datum_type_with_fields(vec![
            ("owner", "ByteArray"),
            ("amount", "Int"),
        ])]);

        let modules = vec![type_module, validator_module];
        let checker = SignatureComplianceChecker;
        let evidence = checker.check_compliance(&modules, "test/validator", "spend");

        assert!(evidence.is_some());
        let e = evidence.unwrap();
        assert_eq!(e.property, SecurityProperty::SignatureVerification);
        assert!(e.confidence >= 0.8);
        assert!(e.description.contains("authority datum fields"));
    }

    #[test]
    fn test_signature_compliance_without_signatories() {
        let signals = BodySignals::default();
        let modules = vec![make_validator_module(
            "test/validator",
            "my_validator",
            "spend",
            signals,
        )];

        let checker = SignatureComplianceChecker;
        let evidence = checker.check_compliance(&modules, "test/validator", "spend");
        assert!(evidence.is_none());
    }

    #[test]
    fn test_signature_compliance_signatories_no_authority_fields() {
        let mut tx_accesses = HashSet::new();
        tx_accesses.insert("extra_signatories".to_string());

        let signals = BodySignals {
            tx_field_accesses: tx_accesses,
            ..Default::default()
        };

        let modules = vec![make_validator_module(
            "test/validator",
            "my_validator",
            "spend",
            signals,
        )];

        let checker = SignatureComplianceChecker;
        let evidence = checker.check_compliance(&modules, "test/validator", "spend");

        // Should return evidence with lower confidence (no authority fields in project)
        assert!(evidence.is_some());
        let e = evidence.unwrap();
        assert!(e.confidence < 0.8);
    }

    // --- MintAuthorizationChecker tests ---

    #[test]
    fn test_mint_authorization_with_signatories() {
        let mut tx_accesses = HashSet::new();
        tx_accesses.insert("extra_signatories".to_string());

        let signals = BodySignals {
            tx_field_accesses: tx_accesses,
            ..Default::default()
        };

        let modules = vec![make_validator_module(
            "test/validator",
            "my_validator",
            "mint",
            signals,
        )];

        let checker = MintAuthorizationChecker;
        let evidence = checker.check_compliance(&modules, "test/validator", "mint");

        assert!(evidence.is_some());
        let e = evidence.unwrap();
        assert_eq!(e.property, SecurityProperty::MintAuthorization);
        assert!(e.description.contains("signature verification"));
    }

    #[test]
    fn test_mint_authorization_with_multiple_mechanisms() {
        let mut tx_accesses = HashSet::new();
        tx_accesses.insert("extra_signatories".to_string());
        tx_accesses.insert("inputs".to_string());
        tx_accesses.insert("mint".to_string());

        let signals = BodySignals {
            tx_field_accesses: tx_accesses,
            ..Default::default()
        };

        let modules = vec![make_validator_module(
            "test/validator",
            "my_validator",
            "mint",
            signals,
        )];

        let checker = MintAuthorizationChecker;
        let evidence = checker.check_compliance(&modules, "test/validator", "mint");

        assert!(evidence.is_some());
        let e = evidence.unwrap();
        assert!(e.confidence >= 0.9);
    }

    #[test]
    fn test_mint_authorization_not_applicable_to_spend() {
        let mut tx_accesses = HashSet::new();
        tx_accesses.insert("extra_signatories".to_string());

        let signals = BodySignals {
            tx_field_accesses: tx_accesses,
            ..Default::default()
        };

        let modules = vec![make_validator_module(
            "test/validator",
            "my_validator",
            "spend",
            signals,
        )];

        let checker = MintAuthorizationChecker;
        let evidence = checker.check_compliance(&modules, "test/validator", "spend");
        assert!(evidence.is_none());
    }

    #[test]
    fn test_mint_authorization_no_checks() {
        let signals = BodySignals::default();
        let modules = vec![make_validator_module(
            "test/validator",
            "my_validator",
            "mint",
            signals,
        )];

        let checker = MintAuthorizationChecker;
        let evidence = checker.check_compliance(&modules, "test/validator", "mint");
        assert!(evidence.is_none());
    }

    // --- UtxoAuthChecker tests ---

    #[test]
    fn test_utxo_auth_with_own_ref_and_inputs() {
        let mut tx_accesses = HashSet::new();
        tx_accesses.insert("inputs".to_string());

        let signals = BodySignals {
            uses_own_ref: true,
            tx_field_accesses: tx_accesses,
            ..Default::default()
        };

        let modules = vec![make_validator_module(
            "test/validator",
            "my_validator",
            "spend",
            signals,
        )];

        let checker = UtxoAuthChecker;
        let evidence = checker.check_compliance(&modules, "test/validator", "spend");

        assert!(evidence.is_some());
        let e = evidence.unwrap();
        assert_eq!(e.property, SecurityProperty::UtxoAuthentication);
        assert!(e.confidence >= 0.8);
        assert!(e.description.contains("own_ref"));
    }

    #[test]
    fn test_utxo_auth_with_single_input_enforcement() {
        let signals = BodySignals {
            enforces_single_input: true,
            ..Default::default()
        };

        let modules = vec![make_validator_module(
            "test/validator",
            "my_validator",
            "spend",
            signals,
        )];

        let checker = UtxoAuthChecker;
        let evidence = checker.check_compliance(&modules, "test/validator", "spend");

        assert!(evidence.is_some());
        let e = evidence.unwrap();
        assert!(e.confidence >= 0.8);
        assert!(e.description.contains("single-input"));
    }

    #[test]
    fn test_utxo_auth_own_ref_without_inputs() {
        let signals = BodySignals {
            uses_own_ref: true,
            ..Default::default()
        };

        let modules = vec![make_validator_module(
            "test/validator",
            "my_validator",
            "spend",
            signals,
        )];

        let checker = UtxoAuthChecker;
        let evidence = checker.check_compliance(&modules, "test/validator", "spend");

        assert!(evidence.is_some());
        let e = evidence.unwrap();
        // Lower confidence — own_ref without inputs check
        assert!(e.confidence < 0.8);
    }

    #[test]
    fn test_utxo_auth_no_own_ref_or_single_input() {
        let signals = BodySignals::default();
        let modules = vec![make_validator_module(
            "test/validator",
            "my_validator",
            "spend",
            signals,
        )];

        let checker = UtxoAuthChecker;
        let evidence = checker.check_compliance(&modules, "test/validator", "spend");
        assert!(evidence.is_none());
    }

    // --- OutputAddressChecker tests ---

    #[test]
    fn test_output_address_with_payment_credential_check() {
        let mut tx_accesses = HashSet::new();
        tx_accesses.insert("outputs".to_string());

        let mut record_labels = HashSet::new();
        record_labels.insert("payment_credential".to_string());

        let signals = BodySignals {
            tx_field_accesses: tx_accesses,
            all_record_labels: record_labels,
            ..Default::default()
        };

        let modules = vec![make_validator_module(
            "test/validator",
            "my_validator",
            "spend",
            signals,
        )];

        let checker = OutputAddressChecker;
        let evidence = checker.check_compliance(&modules, "test/validator", "spend");

        assert!(evidence.is_some());
        let e = evidence.unwrap();
        assert_eq!(e.property, SecurityProperty::OutputAddressValidation);
        assert!(e.description.contains("address/payment_credential"));
    }

    #[test]
    fn test_output_address_with_script_credential_reference() {
        let mut tx_accesses = HashSet::new();
        tx_accesses.insert("outputs".to_string());

        let mut var_refs = HashSet::new();
        var_refs.insert("ScriptCredential".to_string());

        let signals = BodySignals {
            tx_field_accesses: tx_accesses,
            var_references: var_refs,
            ..Default::default()
        };

        let modules = vec![make_validator_module(
            "test/validator",
            "my_validator",
            "spend",
            signals,
        )];

        let checker = OutputAddressChecker;
        let evidence = checker.check_compliance(&modules, "test/validator", "spend");

        assert!(evidence.is_some());
        let e = evidence.unwrap();
        assert!(e.description.contains("credential type verification"));
    }

    #[test]
    fn test_output_address_without_outputs_access() {
        let signals = BodySignals::default();
        let modules = vec![make_validator_module(
            "test/validator",
            "my_validator",
            "spend",
            signals,
        )];

        let checker = OutputAddressChecker;
        let evidence = checker.check_compliance(&modules, "test/validator", "spend");
        assert!(evidence.is_none());
    }

    #[test]
    fn test_output_address_outputs_without_validation() {
        let mut tx_accesses = HashSet::new();
        tx_accesses.insert("outputs".to_string());

        let signals = BodySignals {
            tx_field_accesses: tx_accesses,
            ..Default::default()
        };

        let modules = vec![make_validator_module(
            "test/validator",
            "my_validator",
            "spend",
            signals,
        )];

        let checker = OutputAddressChecker;
        let evidence = checker.check_compliance(&modules, "test/validator", "spend");
        assert!(evidence.is_none());
    }

    // --- DatumIntegrityChecker tests ---

    #[test]
    fn test_datum_integrity_with_continuity_assertion() {
        let signals = BodySignals {
            has_datum_continuity_assertion: true,
            ..Default::default()
        };

        let modules = vec![make_validator_module(
            "test/validator",
            "my_validator",
            "spend",
            signals,
        )];

        let checker = DatumIntegrityChecker;
        let evidence = checker.check_compliance(&modules, "test/validator", "spend");

        assert!(evidence.is_some());
        let e = evidence.unwrap();
        assert_eq!(e.property, SecurityProperty::DatumIntegrity);
        assert!(e.confidence >= 0.9);
        assert!(e.description.contains("full datum continuity"));
    }

    #[test]
    fn test_datum_integrity_with_record_update() {
        let signals = BodySignals {
            has_record_update: true,
            ..Default::default()
        };

        let modules = vec![make_validator_module(
            "test/validator",
            "my_validator",
            "spend",
            signals,
        )];

        let checker = DatumIntegrityChecker;
        let evidence = checker.check_compliance(&modules, "test/validator", "spend");

        assert!(evidence.is_some());
        let e = evidence.unwrap();
        assert!(e.confidence >= 0.8);
        assert!(e.description.contains("record update syntax"));
    }

    #[test]
    fn test_datum_integrity_with_field_equality_checks() {
        let mut datum_eq = HashSet::new();
        datum_eq.insert("owner".to_string());
        datum_eq.insert("policy_id".to_string());
        datum_eq.insert("asset_name".to_string());

        let signals = BodySignals {
            datum_equality_checks: datum_eq,
            ..Default::default()
        };

        let modules = vec![make_validator_module(
            "test/validator",
            "my_validator",
            "spend",
            signals,
        )];

        let checker = DatumIntegrityChecker;
        let evidence = checker.check_compliance(&modules, "test/validator", "spend");

        assert!(evidence.is_some());
        let e = evidence.unwrap();
        assert!(e.confidence >= 0.7);
        assert!(e.description.contains("3 datum field(s)"));
    }

    #[test]
    fn test_datum_integrity_with_few_field_checks() {
        let mut datum_eq = HashSet::new();
        datum_eq.insert("owner".to_string());

        let signals = BodySignals {
            datum_equality_checks: datum_eq,
            ..Default::default()
        };

        let modules = vec![make_validator_module(
            "test/validator",
            "my_validator",
            "spend",
            signals,
        )];

        let checker = DatumIntegrityChecker;
        let evidence = checker.check_compliance(&modules, "test/validator", "spend");

        assert!(evidence.is_some());
        let e = evidence.unwrap();
        assert!(e.confidence < 0.8);
        assert!(e.description.contains("1 datum field(s)"));
    }

    #[test]
    fn test_datum_integrity_no_evidence() {
        let signals = BodySignals::default();
        let modules = vec![make_validator_module(
            "test/validator",
            "my_validator",
            "spend",
            signals,
        )];

        let checker = DatumIntegrityChecker;
        let evidence = checker.check_compliance(&modules, "test/validator", "spend");
        assert!(evidence.is_none());
    }

    // --- detector_to_property mapping tests ---

    #[test]
    fn test_detector_to_property_signature() {
        assert_eq!(
            detector_to_property("missing-signature-check"),
            Some(SecurityProperty::SignatureVerification)
        );
    }

    #[test]
    fn test_detector_to_property_mint() {
        assert_eq!(
            detector_to_property("unrestricted-minting"),
            Some(SecurityProperty::MintAuthorization)
        );
        assert_eq!(
            detector_to_property("missing-minting-policy-check"),
            Some(SecurityProperty::MintAuthorization)
        );
        assert_eq!(
            detector_to_property("other-token-minting"),
            Some(SecurityProperty::MintAuthorization)
        );
    }

    #[test]
    fn test_detector_to_property_utxo() {
        assert_eq!(
            detector_to_property("missing-utxo-authentication"),
            Some(SecurityProperty::UtxoAuthentication)
        );
        assert_eq!(
            detector_to_property("double-satisfaction"),
            Some(SecurityProperty::UtxoAuthentication)
        );
    }

    #[test]
    fn test_detector_to_property_output_address() {
        assert_eq!(
            detector_to_property("output-address-not-validated"),
            Some(SecurityProperty::OutputAddressValidation)
        );
    }

    #[test]
    fn test_detector_to_property_datum() {
        assert_eq!(
            detector_to_property("state-transition-integrity"),
            Some(SecurityProperty::DatumIntegrity)
        );
        assert_eq!(
            detector_to_property("arbitrary-datum-in-output"),
            Some(SecurityProperty::DatumIntegrity)
        );
        assert_eq!(
            detector_to_property("datum-tampering-risk"),
            Some(SecurityProperty::DatumIntegrity)
        );
    }

    #[test]
    fn test_detector_to_property_value() {
        assert_eq!(
            detector_to_property("value-not-preserved"),
            Some(SecurityProperty::ValuePreservation)
        );
        assert_eq!(
            detector_to_property("value-preservation-gap"),
            Some(SecurityProperty::ValuePreservation)
        );
    }

    #[test]
    fn test_detector_to_property_time() {
        assert_eq!(
            detector_to_property("missing-validity-range"),
            Some(SecurityProperty::TimeConstraint)
        );
        assert_eq!(
            detector_to_property("oracle-freshness-not-checked"),
            Some(SecurityProperty::TimeConstraint)
        );
    }

    #[test]
    fn test_detector_to_property_burn() {
        assert_eq!(
            detector_to_property("missing-token-burn"),
            Some(SecurityProperty::BurnAuthorization)
        );
        assert_eq!(
            detector_to_property("incomplete-burn-flow"),
            Some(SecurityProperty::BurnAuthorization)
        );
    }

    #[test]
    fn test_detector_to_property_redeemer() {
        assert_eq!(
            detector_to_property("missing-redeemer-validation"),
            Some(SecurityProperty::RedeemerValidation)
        );
        assert_eq!(
            detector_to_property("non-exhaustive-redeemer"),
            Some(SecurityProperty::RedeemerValidation)
        );
    }

    #[test]
    fn test_detector_to_property_state() {
        assert_eq!(
            detector_to_property("missing-state-update"),
            Some(SecurityProperty::StateTransitionCheck)
        );
        assert_eq!(
            detector_to_property("state-machine-violation"),
            Some(SecurityProperty::StateTransitionCheck)
        );
    }

    #[test]
    fn test_detector_to_property_unknown() {
        assert_eq!(detector_to_property("unknown-detector"), None);
        assert_eq!(detector_to_property("magic-numbers"), None);
    }

    // --- apply_dual_pattern_analysis integration tests ---

    #[test]
    fn test_dual_analysis_confirms_violation_when_no_compliance() {
        let signals = BodySignals::default();
        let modules = vec![make_validator_module(
            "test/validator",
            "my_validator",
            "spend",
            signals,
        )];

        let finding = make_finding("missing-signature-check", "test/validator", "spend");
        let results = apply_dual_pattern_analysis(vec![finding], &modules);

        assert_eq!(results.len(), 1);
        assert!(results[0].is_violation());
    }

    #[test]
    fn test_dual_analysis_suppresses_with_high_compliance() {
        let mut tx_accesses = HashSet::new();
        tx_accesses.insert("extra_signatories".to_string());

        let mut datum_accesses = HashSet::new();
        datum_accesses.insert("owner".to_string());

        let signals = BodySignals {
            tx_field_accesses: tx_accesses,
            datum_field_accesses: datum_accesses,
            ..Default::default()
        };

        let validator_module =
            make_validator_module("test/validator", "my_validator", "spend", signals);
        let type_module = make_lib_module_with_types(vec![make_datum_type_with_fields(vec![(
            "owner",
            "ByteArray",
        )])]);

        let modules = vec![type_module, validator_module];
        let finding = make_finding("missing-signature-check", "test/validator", "spend");
        let results = apply_dual_pattern_analysis(vec![finding], &modules);

        assert_eq!(results.len(), 1);
        assert!(results[0].is_suppressed());
    }

    #[test]
    fn test_dual_analysis_reduces_confidence_with_partial_compliance() {
        let mut tx_accesses = HashSet::new();
        tx_accesses.insert("extra_signatories".to_string());

        let signals = BodySignals {
            tx_field_accesses: tx_accesses,
            ..Default::default()
        };

        // No authority fields defined — partial compliance (confidence < 0.8)
        let modules = vec![make_validator_module(
            "test/validator",
            "my_validator",
            "spend",
            signals,
        )];

        let finding = make_finding("missing-signature-check", "test/validator", "spend");
        let results = apply_dual_pattern_analysis(vec![finding], &modules);

        assert_eq!(results.len(), 1);
        match &results[0] {
            DualPatternResult::ReducedConfidence {
                finding,
                original_confidence,
                ..
            } => {
                assert_eq!(*original_confidence, Confidence::Likely);
                assert_eq!(finding.confidence, Confidence::Possible);
            }
            other => panic!("Expected ReducedConfidence, got {:?}", other.is_violation()),
        }
    }

    #[test]
    fn test_dual_analysis_passes_unmapped_detectors_through() {
        let signals = BodySignals::default();
        let modules = vec![make_validator_module(
            "test/validator",
            "my_validator",
            "spend",
            signals,
        )];

        let finding = make_finding("magic-numbers", "test/validator", "spend");
        let results = apply_dual_pattern_analysis(vec![finding], &modules);

        assert_eq!(results.len(), 1);
        assert!(results[0].is_violation());
    }

    #[test]
    fn test_dual_analysis_multiple_findings() {
        let mut tx_accesses = HashSet::new();
        tx_accesses.insert("extra_signatories".to_string());
        tx_accesses.insert("inputs".to_string());

        let signals = BodySignals {
            tx_field_accesses: tx_accesses,
            uses_own_ref: true,
            ..Default::default()
        };

        let modules = vec![make_validator_module(
            "test/validator",
            "my_validator",
            "spend",
            signals,
        )];

        let findings = vec![
            make_finding("missing-signature-check", "test/validator", "spend"),
            make_finding("double-satisfaction", "test/validator", "spend"),
            make_finding("magic-numbers", "test/validator", "spend"),
        ];

        let results = apply_dual_pattern_analysis(findings, &modules);
        assert_eq!(results.len(), 3);

        // magic-numbers has no property mapping — confirmed violation
        assert!(results[2].is_violation());
    }

    // --- filter_with_compliance tests ---

    #[test]
    fn test_filter_removes_suppressed_findings() {
        let mut tx_accesses = HashSet::new();
        tx_accesses.insert("extra_signatories".to_string());

        let mut datum_accesses = HashSet::new();
        datum_accesses.insert("owner".to_string());

        let signals = BodySignals {
            tx_field_accesses: tx_accesses,
            datum_field_accesses: datum_accesses,
            ..Default::default()
        };

        let validator_module =
            make_validator_module("test/validator", "my_validator", "spend", signals);
        let type_module = make_lib_module_with_types(vec![make_datum_type_with_fields(vec![(
            "owner",
            "ByteArray",
        )])]);

        let modules = vec![type_module, validator_module];

        let findings = vec![
            make_finding("missing-signature-check", "test/validator", "spend"),
            make_finding("magic-numbers", "test/validator", "spend"),
        ];

        let filtered = filter_with_compliance(findings, &modules);

        // missing-signature-check should be suppressed, magic-numbers kept
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].detector_name, "magic-numbers");
    }

    #[test]
    fn test_filter_keeps_reduced_confidence_findings() {
        let mut tx_accesses = HashSet::new();
        tx_accesses.insert("extra_signatories".to_string());

        let signals = BodySignals {
            tx_field_accesses: tx_accesses,
            ..Default::default()
        };

        let modules = vec![make_validator_module(
            "test/validator",
            "my_validator",
            "spend",
            signals,
        )];

        let findings = vec![make_finding(
            "missing-signature-check",
            "test/validator",
            "spend",
        )];

        let filtered = filter_with_compliance(findings, &modules);

        // Partial compliance — kept but with reduced confidence
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].confidence, Confidence::Possible);
    }

    // --- collect_all_compliance tests ---

    #[test]
    fn test_collect_all_compliance_multiple_properties() {
        let mut tx_accesses = HashSet::new();
        tx_accesses.insert("extra_signatories".to_string());
        tx_accesses.insert("inputs".to_string());
        tx_accesses.insert("outputs".to_string());

        let mut record_labels = HashSet::new();
        record_labels.insert("payment_credential".to_string());

        let signals = BodySignals {
            tx_field_accesses: tx_accesses,
            uses_own_ref: true,
            all_record_labels: record_labels,
            has_datum_continuity_assertion: true,
            ..Default::default()
        };

        let modules = vec![make_validator_module(
            "test/validator",
            "my_validator",
            "spend",
            signals,
        )];

        let evidence = collect_all_compliance(&modules);

        // Should find multiple compliance properties
        let properties: HashSet<SecurityProperty> =
            evidence.iter().map(|e| e.property.clone()).collect();
        assert!(properties.contains(&SecurityProperty::UtxoAuthentication));
        assert!(properties.contains(&SecurityProperty::OutputAddressValidation));
        assert!(properties.contains(&SecurityProperty::DatumIntegrity));
    }

    #[test]
    fn test_collect_all_compliance_skips_lib_modules() {
        let signals = BodySignals {
            has_datum_continuity_assertion: true,
            ..Default::default()
        };

        // Create a lib module (not validator) — should be skipped
        let mut module = make_validator_module("test/lib", "my_validator", "spend", signals);
        module.kind = ModuleKind::Lib;

        let evidence = collect_all_compliance(&[module]);
        assert!(evidence.is_empty());
    }

    // --- all_compliance_checkers tests ---

    #[test]
    fn test_all_checkers_have_unique_properties() {
        let checkers = all_compliance_checkers();
        let mut properties = HashSet::new();
        for checker in &checkers {
            assert!(
                properties.insert(checker.property()),
                "Duplicate property: {:?}",
                checker.property()
            );
        }
        assert_eq!(checkers.len(), 5);
    }

    // --- Helper function tests ---

    #[test]
    fn test_find_handler_signals_found() {
        let signals = BodySignals {
            uses_own_ref: true,
            ..Default::default()
        };
        let modules = vec![make_validator_module(
            "test/validator",
            "my_validator",
            "spend",
            signals,
        )];

        let result = find_handler_signals(&modules, "test/validator", "spend");
        assert!(result.is_some());
        assert!(result.unwrap().0.uses_own_ref);
    }

    #[test]
    fn test_find_handler_signals_not_found() {
        let modules = vec![make_validator_module(
            "test/validator",
            "my_validator",
            "spend",
            BodySignals::default(),
        )];

        assert!(find_handler_signals(&modules, "test/validator", "mint").is_none());
        assert!(find_handler_signals(&modules, "other/module", "spend").is_none());
    }

    #[test]
    fn test_extract_handler_from_finding_dot_notation() {
        let modules = vec![make_validator_module(
            "test/validator",
            "my_validator",
            "spend",
            BodySignals::default(),
        )];

        let finding = make_finding("test", "test/validator", "spend");
        let handler = extract_handler_from_finding(&finding, &modules);
        assert_eq!(handler, Some("spend".to_string()));
    }

    #[test]
    fn test_extract_handler_from_finding_fallback() {
        let modules = vec![make_validator_module(
            "test/validator",
            "my_validator",
            "spend",
            BodySignals::default(),
        )];

        // Finding without standard title pattern — falls back to first handler
        let mut finding = make_finding("test", "test/validator", "spend");
        finding.title = "some random title without handler info".to_string();
        let handler = extract_handler_from_finding(&finding, &modules);
        assert_eq!(handler, Some("spend".to_string()));
    }

    #[test]
    fn test_handler_exists_true() {
        let modules = vec![make_validator_module(
            "test/validator",
            "my_validator",
            "spend",
            BodySignals::default(),
        )];
        assert!(handler_exists(&modules, "test/validator", "spend"));
    }

    #[test]
    fn test_handler_exists_false() {
        let modules = vec![make_validator_module(
            "test/validator",
            "my_validator",
            "spend",
            BodySignals::default(),
        )];
        assert!(!handler_exists(&modules, "test/validator", "mint"));
        assert!(!handler_exists(&modules, "other/module", "spend"));
    }

    #[test]
    fn test_collect_authority_fields_found() {
        let type_module = make_lib_module_with_types(vec![make_datum_type_with_fields(vec![
            ("owner", "ByteArray"),
            ("admin", "ByteArray"),
            ("amount", "Int"),
        ])]);
        let fields = collect_authority_fields(&[type_module]);
        assert_eq!(fields.len(), 1);
        assert!(fields[0].1.contains(&"owner".to_string()));
        assert!(fields[0].1.contains(&"admin".to_string()));
    }

    #[test]
    fn test_collect_authority_fields_empty() {
        let type_module = make_lib_module_with_types(vec![make_datum_type_with_fields(vec![
            ("amount", "Int"),
            ("token", "ByteArray"),
        ])]);
        let fields = collect_authority_fields(&[type_module]);
        assert!(fields.is_empty());
    }

    // --- Confidence downgrade tests ---

    #[test]
    fn test_confidence_downgrade_definite_to_likely() {
        let mut tx_accesses = HashSet::new();
        tx_accesses.insert("extra_signatories".to_string());

        let signals = BodySignals {
            tx_field_accesses: tx_accesses,
            ..Default::default()
        };

        let modules = vec![make_validator_module(
            "test/validator",
            "my_validator",
            "spend",
            signals,
        )];

        let mut finding = make_finding("missing-signature-check", "test/validator", "spend");
        finding.confidence = Confidence::Definite;

        let results = apply_dual_pattern_analysis(vec![finding], &modules);
        assert_eq!(results.len(), 1);

        match &results[0] {
            DualPatternResult::ReducedConfidence { finding, .. } => {
                assert_eq!(finding.confidence, Confidence::Likely);
            }
            _ => panic!("Expected ReducedConfidence"),
        }
    }

    #[test]
    fn test_confidence_downgrade_possible_stays_possible() {
        let mut tx_accesses = HashSet::new();
        tx_accesses.insert("extra_signatories".to_string());

        let signals = BodySignals {
            tx_field_accesses: tx_accesses,
            ..Default::default()
        };

        let modules = vec![make_validator_module(
            "test/validator",
            "my_validator",
            "spend",
            signals,
        )];

        let mut finding = make_finding("missing-signature-check", "test/validator", "spend");
        finding.confidence = Confidence::Possible;

        let results = apply_dual_pattern_analysis(vec![finding], &modules);

        match &results[0] {
            DualPatternResult::ReducedConfidence { finding, .. } => {
                assert_eq!(finding.confidence, Confidence::Possible);
            }
            _ => panic!("Expected ReducedConfidence"),
        }
    }

    // --- Edge case tests ---

    #[test]
    fn test_dual_analysis_empty_findings() {
        let modules = vec![make_validator_module(
            "test/validator",
            "my_validator",
            "spend",
            BodySignals::default(),
        )];

        let results = apply_dual_pattern_analysis(vec![], &modules);
        assert!(results.is_empty());
    }

    #[test]
    fn test_dual_analysis_empty_modules() {
        let finding = make_finding("missing-signature-check", "test/validator", "spend");
        let results = apply_dual_pattern_analysis(vec![finding], &[]);

        // Cannot find handler — falls through as confirmed violation
        assert_eq!(results.len(), 1);
        assert!(results[0].is_violation());
    }

    #[test]
    fn test_dual_analysis_module_mismatch() {
        let signals = BodySignals::default();
        let modules = vec![make_validator_module(
            "other/module",
            "my_validator",
            "spend",
            signals,
        )];

        let finding = make_finding("missing-signature-check", "test/validator", "spend");
        let results = apply_dual_pattern_analysis(vec![finding], &modules);

        // Module mismatch — no handler found, confirmed violation
        assert_eq!(results.len(), 1);
        assert!(results[0].is_violation());
    }

    // --- Mint authorization dual-pattern tests ---

    #[test]
    fn test_dual_analysis_suppresses_unrestricted_minting_when_authorized() {
        let mut tx_accesses = HashSet::new();
        tx_accesses.insert("extra_signatories".to_string());
        tx_accesses.insert("inputs".to_string());

        let signals = BodySignals {
            tx_field_accesses: tx_accesses,
            ..Default::default()
        };

        let modules = vec![make_validator_module(
            "test/validator",
            "my_validator",
            "mint",
            signals,
        )];

        let finding = make_finding("unrestricted-minting", "test/validator", "mint");
        let results = apply_dual_pattern_analysis(vec![finding], &modules);

        assert_eq!(results.len(), 1);
        assert!(results[0].is_suppressed());
    }

    // --- Output address dual-pattern tests ---

    #[test]
    fn test_dual_analysis_suppresses_output_address_when_validated() {
        let mut tx_accesses = HashSet::new();
        tx_accesses.insert("outputs".to_string());

        let mut record_labels = HashSet::new();
        record_labels.insert("address".to_string());
        record_labels.insert("payment_credential".to_string());

        let mut var_refs = HashSet::new();
        var_refs.insert("ScriptCredential".to_string());

        let signals = BodySignals {
            tx_field_accesses: tx_accesses,
            all_record_labels: record_labels,
            var_references: var_refs,
            ..Default::default()
        };

        let modules = vec![make_validator_module(
            "test/validator",
            "my_validator",
            "spend",
            signals,
        )];

        let finding = make_finding("output-address-not-validated", "test/validator", "spend");
        let results = apply_dual_pattern_analysis(vec![finding], &modules);

        assert_eq!(results.len(), 1);
        assert!(results[0].is_suppressed());
    }

    // --- Datum integrity dual-pattern tests ---

    #[test]
    fn test_dual_analysis_suppresses_datum_tampering_when_continuity_asserted() {
        let signals = BodySignals {
            has_datum_continuity_assertion: true,
            ..Default::default()
        };

        let modules = vec![make_validator_module(
            "test/validator",
            "my_validator",
            "spend",
            signals,
        )];

        let finding = make_finding("datum-tampering-risk", "test/validator", "spend");
        let results = apply_dual_pattern_analysis(vec![finding], &modules);

        assert_eq!(results.len(), 1);
        assert!(results[0].is_suppressed());
    }
}
