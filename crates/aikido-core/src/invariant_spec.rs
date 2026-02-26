//! Invariant specification language for protocol-level property checking.
//!
//! Allows protocol authors to declare high-level security invariants in
//! `.aikido-invariants.toml` files. These invariants are verified against the
//! analyzed AST signals from `ast_walker::ModuleInfo`, producing violations
//! that can be converted to standard `Finding`s for unified reporting.
//!
//! # Example
//!
//! ```toml
//! [protocol]
//! name = "My DEX"
//! version = "1.0.0"
//!
//! [[invariant]]
//! name = "admin-only-withdraw"
//! severity = "critical"
//! category = "access_control"
//! validators = ["treasury"]
//! [invariant.check]
//! type = "requires_signatory"
//! datum_field = "admin_pkh"
//! ```

use std::fmt;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::ast_walker::ModuleInfo;
use crate::detector::{Confidence, Finding, Severity};

// ---------------------------------------------------------------------------
// Specification types (parsed from .aikido-invariants.toml)
// ---------------------------------------------------------------------------

/// Root of an invariant specification file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvariantSpec {
    pub protocol: ProtocolInfo,
    #[serde(default, rename = "invariant")]
    pub invariants: Vec<InvariantDef>,
}

/// Metadata about the protocol being analyzed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolInfo {
    pub name: String,
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
}

/// A single invariant definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvariantDef {
    pub name: String,
    pub severity: InvariantSeverity,
    #[serde(default)]
    pub description: Option<String>,
    pub category: InvariantCategory,
    /// Which validators this invariant applies to (empty = all validators).
    #[serde(default)]
    pub validators: Vec<String>,
    pub check: InvariantCheck,
}

/// Severity levels for invariant violations (mirrors `detector::Severity`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum InvariantSeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl fmt::Display for InvariantSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InvariantSeverity::Critical => write!(f, "critical"),
            InvariantSeverity::High => write!(f, "high"),
            InvariantSeverity::Medium => write!(f, "medium"),
            InvariantSeverity::Low => write!(f, "low"),
            InvariantSeverity::Info => write!(f, "info"),
        }
    }
}

impl From<&InvariantSeverity> for Severity {
    fn from(s: &InvariantSeverity) -> Self {
        match s {
            InvariantSeverity::Critical => Severity::Critical,
            InvariantSeverity::High => Severity::High,
            InvariantSeverity::Medium => Severity::Medium,
            InvariantSeverity::Low => Severity::Low,
            InvariantSeverity::Info => Severity::Info,
        }
    }
}

/// Categories for grouping related invariants.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum InvariantCategory {
    ValueConservation,
    AccessControl,
    StateTransition,
    TokenIntegrity,
    Temporal,
    Economic,
    Custom,
}

impl fmt::Display for InvariantCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InvariantCategory::ValueConservation => write!(f, "value_conservation"),
            InvariantCategory::AccessControl => write!(f, "access_control"),
            InvariantCategory::StateTransition => write!(f, "state_transition"),
            InvariantCategory::TokenIntegrity => write!(f, "token_integrity"),
            InvariantCategory::Temporal => write!(f, "temporal"),
            InvariantCategory::Economic => write!(f, "economic"),
            InvariantCategory::Custom => write!(f, "custom"),
        }
    }
}

/// Invariant check definitions — what to verify against the analyzed AST.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum InvariantCheck {
    /// Requires a specific function call or pattern in validators.
    RequiresCall {
        function: String,
        #[serde(default)]
        in_handler: Option<String>,
    },
    /// Requires checking a specific transaction field.
    RequiresFieldCheck {
        field: String,
        #[serde(default)]
        operation: Option<String>,
    },
    /// Requires a signatory check (extra_signatories access).
    RequiresSignatory {
        #[serde(default)]
        datum_field: Option<String>,
    },
    /// Requires value preservation between inputs and outputs.
    ValuePreservation {
        #[serde(default)]
        tolerance: Option<String>,
    },
    /// Requires datum continuity (input datum relates to output datum).
    DatumContinuity {
        #[serde(default)]
        fields: Vec<String>,
    },
    /// Requires a specific token in transaction.
    RequiresToken {
        #[serde(default)]
        policy_field: Option<String>,
        #[serde(default)]
        token_name: Option<String>,
    },
    /// Requires validity range check.
    RequiresValidityRange {
        #[serde(default)]
        check_start: bool,
        #[serde(default)]
        check_end: bool,
    },
    /// Custom expression (future: will be parsed into AST).
    Expression { expr: String },
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors that can occur when loading or validating invariant specifications.
#[derive(Debug)]
pub enum InvariantError {
    IoError(std::io::Error),
    ParseError(String),
    ValidationError(String),
}

impl fmt::Display for InvariantError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InvariantError::IoError(e) => write!(f, "I/O error: {e}"),
            InvariantError::ParseError(msg) => write!(f, "parse error: {msg}"),
            InvariantError::ValidationError(msg) => write!(f, "validation error: {msg}"),
        }
    }
}

impl std::error::Error for InvariantError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            InvariantError::IoError(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for InvariantError {
    fn from(e: std::io::Error) -> Self {
        InvariantError::IoError(e)
    }
}

// ---------------------------------------------------------------------------
// Violation type
// ---------------------------------------------------------------------------

/// An invariant violation finding — produced when a declared invariant is not
/// satisfied by the analyzed code.
#[derive(Debug, Clone, Serialize)]
pub struct InvariantViolation {
    pub invariant_name: String,
    pub category: InvariantCategory,
    pub severity: Severity,
    pub module: String,
    pub handler: String,
    pub description: String,
    pub expected: String,
    pub observed: String,
}

// ---------------------------------------------------------------------------
// Loading
// ---------------------------------------------------------------------------

/// Load an invariant spec from a TOML file.
///
/// Returns `InvariantError::IoError` if the file cannot be read, or
/// `InvariantError::ParseError` if the TOML is malformed.
pub fn load_invariant_spec(path: &Path) -> Result<InvariantSpec, InvariantError> {
    let content = std::fs::read_to_string(path)?;
    let spec: InvariantSpec =
        toml::from_str(&content).map_err(|e| InvariantError::ParseError(e.to_string()))?;
    validate_spec(&spec)?;
    Ok(spec)
}

/// Validate an invariant spec for internal consistency.
fn validate_spec(spec: &InvariantSpec) -> Result<(), InvariantError> {
    if spec.protocol.name.is_empty() {
        return Err(InvariantError::ValidationError(
            "protocol.name must not be empty".to_string(),
        ));
    }
    for inv in &spec.invariants {
        if inv.name.is_empty() {
            return Err(InvariantError::ValidationError(
                "invariant name must not be empty".to_string(),
            ));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Verification engine
// ---------------------------------------------------------------------------

/// Verify all invariants in a spec against analyzed modules.
///
/// Iterates over each invariant definition and checks whether the relevant
/// validator handlers satisfy the declared check. Returns a violation for
/// every handler that fails to satisfy its invariant.
pub fn verify_invariants(spec: &InvariantSpec, modules: &[ModuleInfo]) -> Vec<InvariantViolation> {
    let mut violations = Vec::new();

    for inv in &spec.invariants {
        for module in modules {
            for validator in &module.validators {
                // If the invariant scopes to specific validators, skip non-matching ones.
                if !inv.validators.is_empty()
                    && !inv
                        .validators
                        .iter()
                        .any(|v| validator_name_matches(&validator.name, v))
                {
                    continue;
                }

                for handler in &validator.handlers {
                    if let Some(violation) = check_invariant(inv, module, &validator.name, handler)
                    {
                        violations.push(violation);
                    }
                }
            }
        }
    }

    violations
}

/// Check whether a single handler satisfies a single invariant.
/// Returns `Some(violation)` if the invariant is NOT satisfied.
fn check_invariant(
    inv: &InvariantDef,
    module: &ModuleInfo,
    validator_name: &str,
    handler: &crate::ast_walker::HandlerInfo,
) -> Option<InvariantViolation> {
    let signals = &handler.body_signals;

    match &inv.check {
        InvariantCheck::RequiresCall {
            function,
            in_handler,
        } => {
            // If scoped to a specific handler, skip others.
            if let Some(target) = in_handler {
                if handler.name != *target {
                    return None;
                }
            }
            if !signals.function_calls.contains(function.as_str()) {
                return Some(make_violation(
                    inv,
                    module,
                    validator_name,
                    handler,
                    &format!("Call to `{function}` present"),
                    &format!(
                        "No call to `{function}` found in function_calls: {{{}}}",
                        signals
                            .function_calls
                            .iter()
                            .cloned()
                            .collect::<Vec<_>>()
                            .join(", ")
                    ),
                ));
            }
            None
        }

        InvariantCheck::RequiresFieldCheck { field, operation } => {
            if !signals.tx_field_accesses.contains(field.as_str()) {
                let op_msg = operation
                    .as_deref()
                    .map(|op| format!(" with operation `{op}`"))
                    .unwrap_or_default();
                return Some(make_violation(
                    inv,
                    module,
                    validator_name,
                    handler,
                    &format!("Transaction field `{field}` checked{op_msg}"),
                    &format!(
                        "Field `{field}` not accessed; tx fields: {{{}}}",
                        signals
                            .tx_field_accesses
                            .iter()
                            .cloned()
                            .collect::<Vec<_>>()
                            .join(", ")
                    ),
                ));
            }
            None
        }

        InvariantCheck::RequiresSignatory { datum_field } => {
            let has_sig_access = signals.tx_field_accesses.contains("extra_signatories");

            if !has_sig_access {
                let field_msg = datum_field
                    .as_deref()
                    .map(|f| format!(" (expected from datum field `{f}`)"))
                    .unwrap_or_default();
                return Some(make_violation(
                    inv,
                    module,
                    validator_name,
                    handler,
                    &format!("Signatory check present{field_msg}"),
                    "No `extra_signatories` access found in transaction field accesses",
                ));
            }

            // If a specific datum field is expected, check it is accessed.
            if let Some(field) = datum_field {
                if !signals.datum_field_accesses.contains(field.as_str())
                    && !signals.var_references.contains(field.as_str())
                    && !signals.all_record_labels.contains(field.as_str())
                {
                    return Some(make_violation(
                        inv,
                        module,
                        validator_name,
                        handler,
                        &format!("Datum field `{field}` used in signatory check"),
                        &format!(
                            "Field `{field}` not found in datum accesses or variable references"
                        ),
                    ));
                }
            }
            None
        }

        InvariantCheck::ValuePreservation { tolerance } => {
            let has_value_access = signals.tx_field_accesses.contains("outputs")
                && signals.tx_field_accesses.contains("inputs");
            let has_value_call = signals.function_calls.iter().any(|c| {
                c.contains("value") || c.contains("lovelace") || c.contains("quantity_of")
            });

            if !has_value_access || !has_value_call {
                let tol_msg = tolerance
                    .as_deref()
                    .map(|t| format!(" (tolerance: {t})"))
                    .unwrap_or_default();
                return Some(make_violation(
                    inv,
                    module,
                    validator_name,
                    handler,
                    &format!("Value preservation check (inputs vs outputs){tol_msg}"),
                    "Handler does not access both inputs and outputs with value comparison calls",
                ));
            }
            None
        }

        InvariantCheck::DatumContinuity { fields } => {
            if !signals.has_datum_continuity_assertion && signals.datum_equality_checks.is_empty() {
                return Some(make_violation(
                    inv,
                    module,
                    validator_name,
                    handler,
                    "Datum continuity between input and output",
                    "No datum continuity assertion or field equality checks found",
                ));
            }

            // If specific fields are required, verify they are checked.
            for field in fields {
                if !signals.datum_equality_checks.contains(field.as_str()) {
                    return Some(make_violation(
                        inv,
                        module,
                        validator_name,
                        handler,
                        &format!("Datum field `{field}` preserved across state transition"),
                        &format!(
                            "Field `{field}` not found in datum equality checks: {{{}}}",
                            signals
                                .datum_equality_checks
                                .iter()
                                .cloned()
                                .collect::<Vec<_>>()
                                .join(", ")
                        ),
                    ));
                }
            }
            None
        }

        InvariantCheck::RequiresToken {
            policy_field,
            token_name,
        } => {
            let has_token_call = signals.function_calls.iter().any(|c| {
                c.contains("quantity_of") || c.contains("has_token") || c.contains("tokens")
            });

            if !has_token_call {
                let mut detail_parts = Vec::new();
                if let Some(pf) = policy_field {
                    detail_parts.push(format!("policy from `{pf}`"));
                }
                if let Some(tn) = token_name {
                    detail_parts.push(format!("token name `{tn}`"));
                }
                let detail = if detail_parts.is_empty() {
                    String::new()
                } else {
                    format!(" ({})", detail_parts.join(", "))
                };
                return Some(make_violation(
                    inv,
                    module,
                    validator_name,
                    handler,
                    &format!("Token check present{detail}"),
                    "No token-related function calls (quantity_of, has_token, tokens) found",
                ));
            }
            None
        }

        InvariantCheck::RequiresValidityRange {
            check_start,
            check_end,
        } => {
            let has_range = signals.tx_field_accesses.contains("validity_range");

            if !has_range {
                let mut parts = Vec::new();
                if *check_start {
                    parts.push("start");
                }
                if *check_end {
                    parts.push("end");
                }
                let bound_msg = if parts.is_empty() {
                    String::new()
                } else {
                    format!(" (bounds: {})", parts.join(", "))
                };
                return Some(make_violation(
                    inv,
                    module,
                    validator_name,
                    handler,
                    &format!("Validity range check{bound_msg}"),
                    "No `validity_range` access found in transaction field accesses",
                ));
            }
            None
        }

        InvariantCheck::Expression { expr } => {
            // Expression-based checks are not yet implemented. Emit a warning
            // violation so users know the check was skipped.
            Some(make_violation(
                inv,
                module,
                validator_name,
                handler,
                &format!("Expression evaluated: `{expr}`"),
                "Expression-based invariant checks are not yet implemented",
            ))
        }
    }
}

/// Helper to construct an `InvariantViolation`.
fn make_violation(
    inv: &InvariantDef,
    module: &ModuleInfo,
    validator_name: &str,
    handler: &crate::ast_walker::HandlerInfo,
    expected: &str,
    observed: &str,
) -> InvariantViolation {
    let description = inv
        .description
        .clone()
        .unwrap_or_else(|| format!("Invariant `{}` violated", inv.name));

    InvariantViolation {
        invariant_name: inv.name.clone(),
        category: inv.category.clone(),
        severity: Severity::from(&inv.severity),
        module: module.name.clone(),
        handler: format!("{}.{}", validator_name, handler.name),
        description,
        expected: expected.to_string(),
        observed: observed.to_string(),
    }
}

/// Check if a validator name matches a pattern.
/// Matches when the pattern equals the full name, or the last segment after `/`.
fn validator_name_matches(validator_name: &str, pattern: &str) -> bool {
    validator_name == pattern
        || validator_name
            .rsplit('/')
            .next()
            .is_some_and(|last| last == pattern)
}

// ---------------------------------------------------------------------------
// Conversion to Findings
// ---------------------------------------------------------------------------

/// Convert invariant violations to standard `Finding`s for unified output.
pub fn violations_to_findings(violations: &[InvariantViolation]) -> Vec<Finding> {
    violations
        .iter()
        .map(|v| Finding {
            detector_name: format!("invariant-spec:{}", v.invariant_name),
            severity: v.severity.clone(),
            confidence: Confidence::Definite,
            title: format!("Invariant `{}` violated in {}", v.invariant_name, v.handler),
            description: format!(
                "{}\n\nExpected: {}\nObserved: {}",
                v.description, v.expected, v.observed
            ),
            module: v.module.clone(),
            location: None,
            suggestion: Some(format!(
                "Ensure the `{}` invariant ({}) is satisfied in handler `{}`",
                v.invariant_name, v.category, v.handler
            )),
            related_findings: vec![],
            semantic_group: Some(format!("invariant-spec:{}", v.category)),
            evidence: None,
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Report formatting
// ---------------------------------------------------------------------------

/// Format an invariant verification report as human-readable text.
pub fn format_invariant_report(violations: &[InvariantViolation], spec: &InvariantSpec) -> String {
    let mut out = String::new();

    // Header
    out.push_str(&format!(
        "Invariant Verification Report: {}{}\n",
        spec.protocol.name,
        spec.protocol
            .version
            .as_deref()
            .map(|v| format!(" v{v}"))
            .unwrap_or_default()
    ));
    out.push_str(&"=".repeat(60));
    out.push('\n');

    if let Some(desc) = &spec.protocol.description {
        out.push_str(&format!("Protocol: {desc}\n"));
    }

    out.push_str(&format!("Invariants defined: {}\n", spec.invariants.len()));
    out.push_str(&format!("Violations found: {}\n", violations.len()));
    out.push('\n');

    if violations.is_empty() {
        out.push_str("All invariants satisfied.\n");
        return out;
    }

    // Group violations by category
    let mut by_category: std::collections::BTreeMap<String, Vec<&InvariantViolation>> =
        std::collections::BTreeMap::new();
    for v in violations {
        by_category
            .entry(v.category.to_string())
            .or_default()
            .push(v);
    }

    for (category, cat_violations) in &by_category {
        out.push_str(&format!("[{category}]\n"));
        out.push_str(&"-".repeat(40));
        out.push('\n');

        for v in cat_violations {
            out.push_str(&format!(
                "  {} [{}] {}\n",
                severity_marker(&v.severity),
                v.invariant_name,
                v.description
            ));
            out.push_str(&format!("    Handler: {}\n", v.handler));
            out.push_str(&format!("    Expected: {}\n", v.expected));
            out.push_str(&format!("    Observed: {}\n", v.observed));
            out.push('\n');
        }
    }

    out
}

/// Produce a severity marker for terminal display.
fn severity_marker(severity: &Severity) -> &'static str {
    match severity {
        Severity::Critical => "[CRITICAL]",
        Severity::High => "[HIGH]",
        Severity::Medium => "[MEDIUM]",
        Severity::Low => "[LOW]",
        Severity::Info => "[INFO]",
    }
}

// ---------------------------------------------------------------------------
// Sample spec generation
// ---------------------------------------------------------------------------

/// Generate a well-commented sample `.aikido-invariants.toml` for a project.
pub fn generate_sample_spec(protocol_name: &str) -> String {
    format!(
        r##"# Aikido Invariant Specification
# ================================
# Define protocol-level security invariants that your smart contract must satisfy.
# Aikido will verify these against the analyzed code and report violations.
#
# Place this file as `.aikido-invariants.toml` in your project root.

[protocol]
name = "{protocol_name}"
# version = "1.0.0"
# description = "Brief description of the protocol"


# ============================================================================
# VALUE CONSERVATION
# ============================================================================
# Ensures that value (ADA, tokens) is preserved across transactions.
# Prevents value leakage or creation bugs.

# [[invariant]]
# name = "value-preserved-in-swap"
# severity = "critical"
# description = "Total input value must equal total output value (minus fees)"
# category = "value_conservation"
# validators = ["swap"]
# [invariant.check]
# type = "value_preservation"
# tolerance = "fees_only"


# ============================================================================
# ACCESS CONTROL
# ============================================================================
# Ensures that sensitive operations are gated by proper authorization checks.

# [[invariant]]
# name = "admin-only-config-update"
# severity = "critical"
# description = "Config updates must be signed by the admin key"
# category = "access_control"
# validators = ["config"]
# [invariant.check]
# type = "requires_signatory"
# datum_field = "admin_pkh"

# [[invariant]]
# name = "owner-authorized-withdrawal"
# severity = "high"
# description = "Withdrawals must be authorized by the position owner"
# category = "access_control"
# validators = ["treasury"]
# [invariant.check]
# type = "requires_signatory"
# datum_field = "owner"


# ============================================================================
# STATE TRANSITION
# ============================================================================
# Ensures that state transitions preserve required datum fields and follow
# the expected state machine.

# [[invariant]]
# name = "datum-continuity-on-update"
# severity = "high"
# description = "Immutable datum fields must be preserved across state transitions"
# category = "state_transition"
# validators = ["position"]
# [invariant.check]
# type = "datum_continuity"
# fields = ["owner", "policy_id", "created_at"]


# ============================================================================
# TOKEN INTEGRITY
# ============================================================================
# Ensures that token operations are properly validated.

# [[invariant]]
# name = "protocol-token-present"
# severity = "high"
# description = "Protocol auth token must be verified in every spend"
# category = "token_integrity"
# validators = []
# [invariant.check]
# type = "requires_token"
# policy_field = "policy_id"
# token_name = "auth"


# ============================================================================
# TEMPORAL
# ============================================================================
# Ensures that time-sensitive operations check the validity range.

# [[invariant]]
# name = "deadline-enforced"
# severity = "medium"
# description = "Operations with deadlines must check the transaction validity range"
# category = "temporal"
# validators = ["position"]
# [invariant.check]
# type = "requires_validity_range"
# check_start = false
# check_end = true


# ============================================================================
# ECONOMIC
# ============================================================================
# Ensures economic correctness of the protocol mechanics.

# [[invariant]]
# name = "fee-calculation-verified"
# severity = "medium"
# description = "Protocol fee must be calculated and checked in swap handlers"
# category = "economic"
# validators = ["swap"]
# [invariant.check]
# type = "requires_call"
# function = "calculate_fee"
# in_handler = "spend"


# ============================================================================
# CUSTOM
# ============================================================================
# Protocol-specific invariants using custom expressions (future feature).

# [[invariant]]
# name = "min-output-check"
# severity = "low"
# description = "Outputs must meet minimum ADA threshold"
# category = "custom"
# [invariant.check]
# type = "requires_field_check"
# field = "outputs"
# operation = "min_ada_check"
"##
    )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast_walker::{HandlerInfo, ModuleKind, ParamInfo, ValidatorInfo};
    use crate::body_analysis::BodySignals;

    /// Build a minimal `ModuleInfo` with one validator and one handler,
    /// using the given body signals.
    fn make_module(
        name: &str,
        validator_name: &str,
        handler_name: &str,
        signals: BodySignals,
    ) -> ModuleInfo {
        ModuleInfo {
            name: name.to_string(),
            path: format!("validators/{name}.ak"),
            kind: ModuleKind::Validator,
            validators: vec![ValidatorInfo {
                name: validator_name.to_string(),
                params: vec![],
                handlers: vec![HandlerInfo {
                    name: handler_name.to_string(),
                    params: vec![ParamInfo {
                        name: "datum".to_string(),
                        type_name: "Datum".to_string(),
                    }],
                    return_type: "Bool".to_string(),
                    location: Some((0, 100)),
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

    // -----------------------------------------------------------------------
    // TOML parsing tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_minimal_spec() {
        let toml_str = r#"
            [protocol]
            name = "TestProtocol"

            [[invariant]]
            name = "sig-check"
            severity = "high"
            category = "access_control"
            [invariant.check]
            type = "requires_signatory"
        "#;

        let spec: InvariantSpec = toml::from_str(toml_str).unwrap();
        assert_eq!(spec.protocol.name, "TestProtocol");
        assert!(spec.protocol.version.is_none());
        assert_eq!(spec.invariants.len(), 1);
        assert_eq!(spec.invariants[0].name, "sig-check");
        assert_eq!(spec.invariants[0].severity, InvariantSeverity::High);
        assert_eq!(
            spec.invariants[0].category,
            InvariantCategory::AccessControl
        );
        assert!(matches!(
            spec.invariants[0].check,
            InvariantCheck::RequiresSignatory { .. }
        ));
    }

    #[test]
    fn test_parse_full_spec() {
        let toml_str = r#"
            [protocol]
            name = "MyDEX"
            version = "2.0.0"
            description = "Decentralized exchange protocol"

            [[invariant]]
            name = "value-preserved"
            severity = "critical"
            description = "Value must be conserved in swaps"
            category = "value_conservation"
            validators = ["swap", "liquidity"]
            [invariant.check]
            type = "value_preservation"
            tolerance = "fees_only"

            [[invariant]]
            name = "admin-auth"
            severity = "high"
            category = "access_control"
            validators = ["config"]
            [invariant.check]
            type = "requires_signatory"
            datum_field = "admin_pkh"

            [[invariant]]
            name = "deadline-check"
            severity = "medium"
            category = "temporal"
            [invariant.check]
            type = "requires_validity_range"
            check_start = false
            check_end = true

            [[invariant]]
            name = "datum-preserved"
            severity = "high"
            category = "state_transition"
            [invariant.check]
            type = "datum_continuity"
            fields = ["owner", "policy_id"]

            [[invariant]]
            name = "call-check"
            severity = "medium"
            category = "economic"
            [invariant.check]
            type = "requires_call"
            function = "calculate_fee"
            in_handler = "spend"

            [[invariant]]
            name = "field-check"
            severity = "low"
            category = "custom"
            [invariant.check]
            type = "requires_field_check"
            field = "outputs"
            operation = "min_ada"

            [[invariant]]
            name = "token-check"
            severity = "high"
            category = "token_integrity"
            [invariant.check]
            type = "requires_token"
            policy_field = "policy_id"
            token_name = "auth"

            [[invariant]]
            name = "custom-expr"
            severity = "info"
            category = "custom"
            [invariant.check]
            type = "expression"
            expr = "inputs.value >= outputs.value"
        "#;

        let spec: InvariantSpec = toml::from_str(toml_str).unwrap();
        assert_eq!(spec.protocol.name, "MyDEX");
        assert_eq!(spec.protocol.version.as_deref(), Some("2.0.0"));
        assert_eq!(spec.invariants.len(), 8);

        // Check all check types parsed correctly.
        assert!(matches!(
            spec.invariants[0].check,
            InvariantCheck::ValuePreservation { .. }
        ));
        assert!(matches!(
            spec.invariants[1].check,
            InvariantCheck::RequiresSignatory { .. }
        ));
        assert!(matches!(
            spec.invariants[2].check,
            InvariantCheck::RequiresValidityRange { .. }
        ));
        assert!(matches!(
            spec.invariants[3].check,
            InvariantCheck::DatumContinuity { .. }
        ));
        assert!(matches!(
            spec.invariants[4].check,
            InvariantCheck::RequiresCall { .. }
        ));
        assert!(matches!(
            spec.invariants[5].check,
            InvariantCheck::RequiresFieldCheck { .. }
        ));
        assert!(matches!(
            spec.invariants[6].check,
            InvariantCheck::RequiresToken { .. }
        ));
        assert!(matches!(
            spec.invariants[7].check,
            InvariantCheck::Expression { .. }
        ));
    }

    #[test]
    fn test_parse_empty_invariants() {
        let toml_str = r#"
            [protocol]
            name = "Empty"
        "#;

        let spec: InvariantSpec = toml::from_str(toml_str).unwrap();
        assert_eq!(spec.invariants.len(), 0);
    }

    #[test]
    fn test_parse_invalid_toml() {
        let bad = "not valid toml [[[";
        let result: Result<InvariantSpec, _> = toml::from_str(bad);
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // Severity / category display
    // -----------------------------------------------------------------------

    #[test]
    fn test_severity_display() {
        assert_eq!(InvariantSeverity::Critical.to_string(), "critical");
        assert_eq!(InvariantSeverity::High.to_string(), "high");
        assert_eq!(InvariantSeverity::Medium.to_string(), "medium");
        assert_eq!(InvariantSeverity::Low.to_string(), "low");
        assert_eq!(InvariantSeverity::Info.to_string(), "info");
    }

    #[test]
    fn test_severity_conversion() {
        assert_eq!(
            Severity::from(&InvariantSeverity::Critical),
            Severity::Critical
        );
        assert_eq!(Severity::from(&InvariantSeverity::High), Severity::High);
        assert_eq!(Severity::from(&InvariantSeverity::Medium), Severity::Medium);
        assert_eq!(Severity::from(&InvariantSeverity::Low), Severity::Low);
        assert_eq!(Severity::from(&InvariantSeverity::Info), Severity::Info);
    }

    #[test]
    fn test_category_display() {
        assert_eq!(
            InvariantCategory::ValueConservation.to_string(),
            "value_conservation"
        );
        assert_eq!(
            InvariantCategory::AccessControl.to_string(),
            "access_control"
        );
        assert_eq!(
            InvariantCategory::StateTransition.to_string(),
            "state_transition"
        );
        assert_eq!(
            InvariantCategory::TokenIntegrity.to_string(),
            "token_integrity"
        );
        assert_eq!(InvariantCategory::Temporal.to_string(), "temporal");
        assert_eq!(InvariantCategory::Economic.to_string(), "economic");
        assert_eq!(InvariantCategory::Custom.to_string(), "custom");
    }

    // -----------------------------------------------------------------------
    // Verification: RequiresSignatory
    // -----------------------------------------------------------------------

    #[test]
    fn test_verify_requires_signatory_pass() {
        let mut signals = BodySignals::default();
        signals
            .tx_field_accesses
            .insert("extra_signatories".to_string());

        let module = make_module("treasury", "treasury", "spend", signals);

        let spec: InvariantSpec = toml::from_str(
            r#"
            [protocol]
            name = "Test"
            [[invariant]]
            name = "sig-check"
            severity = "high"
            category = "access_control"
            [invariant.check]
            type = "requires_signatory"
        "#,
        )
        .unwrap();

        let violations = verify_invariants(&spec, &[module]);
        assert!(
            violations.is_empty(),
            "Expected no violations, got: {violations:?}"
        );
    }

    #[test]
    fn test_verify_requires_signatory_fail() {
        let signals = BodySignals::default(); // no extra_signatories access
        let module = make_module("treasury", "treasury", "spend", signals);

        let spec: InvariantSpec = toml::from_str(
            r#"
            [protocol]
            name = "Test"
            [[invariant]]
            name = "sig-check"
            severity = "critical"
            category = "access_control"
            [invariant.check]
            type = "requires_signatory"
        "#,
        )
        .unwrap();

        let violations = verify_invariants(&spec, &[module]);
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].invariant_name, "sig-check");
        assert_eq!(violations[0].severity, Severity::Critical);
        assert!(violations[0].observed.contains("extra_signatories"));
    }

    #[test]
    fn test_verify_requires_signatory_with_datum_field_pass() {
        let mut signals = BodySignals::default();
        signals
            .tx_field_accesses
            .insert("extra_signatories".to_string());
        signals.datum_field_accesses.insert("admin_pkh".to_string());

        let module = make_module("config", "config", "spend", signals);

        let spec: InvariantSpec = toml::from_str(
            r#"
            [protocol]
            name = "Test"
            [[invariant]]
            name = "admin-auth"
            severity = "critical"
            category = "access_control"
            [invariant.check]
            type = "requires_signatory"
            datum_field = "admin_pkh"
        "#,
        )
        .unwrap();

        let violations = verify_invariants(&spec, &[module]);
        assert!(violations.is_empty());
    }

    #[test]
    fn test_verify_requires_signatory_with_datum_field_fail() {
        let mut signals = BodySignals::default();
        signals
            .tx_field_accesses
            .insert("extra_signatories".to_string());
        // admin_pkh NOT in datum_field_accesses

        let module = make_module("config", "config", "spend", signals);

        let spec: InvariantSpec = toml::from_str(
            r#"
            [protocol]
            name = "Test"
            [[invariant]]
            name = "admin-auth"
            severity = "critical"
            category = "access_control"
            [invariant.check]
            type = "requires_signatory"
            datum_field = "admin_pkh"
        "#,
        )
        .unwrap();

        let violations = verify_invariants(&spec, &[module]);
        assert_eq!(violations.len(), 1);
        assert!(violations[0].expected.contains("admin_pkh"));
    }

    // -----------------------------------------------------------------------
    // Verification: RequiresFieldCheck
    // -----------------------------------------------------------------------

    #[test]
    fn test_verify_requires_field_check_pass() {
        let mut signals = BodySignals::default();
        signals.tx_field_accesses.insert("outputs".to_string());

        let module = make_module("validator", "validator", "spend", signals);

        let spec: InvariantSpec = toml::from_str(
            r#"
            [protocol]
            name = "Test"
            [[invariant]]
            name = "output-check"
            severity = "low"
            category = "custom"
            [invariant.check]
            type = "requires_field_check"
            field = "outputs"
        "#,
        )
        .unwrap();

        let violations = verify_invariants(&spec, &[module]);
        assert!(violations.is_empty());
    }

    #[test]
    fn test_verify_requires_field_check_fail() {
        let signals = BodySignals::default(); // no tx_field_accesses
        let module = make_module("validator", "validator", "spend", signals);

        let spec: InvariantSpec = toml::from_str(
            r#"
            [protocol]
            name = "Test"
            [[invariant]]
            name = "output-check"
            severity = "medium"
            category = "custom"
            [invariant.check]
            type = "requires_field_check"
            field = "outputs"
            operation = "min_ada_check"
        "#,
        )
        .unwrap();

        let violations = verify_invariants(&spec, &[module]);
        assert_eq!(violations.len(), 1);
        assert!(violations[0].expected.contains("outputs"));
        assert!(violations[0].expected.contains("min_ada_check"));
    }

    // -----------------------------------------------------------------------
    // Verification: RequiresCall
    // -----------------------------------------------------------------------

    #[test]
    fn test_verify_requires_call_pass() {
        let mut signals = BodySignals::default();
        signals.function_calls.insert("calculate_fee".to_string());

        let module = make_module("swap", "swap", "spend", signals);

        let spec: InvariantSpec = toml::from_str(
            r#"
            [protocol]
            name = "Test"
            [[invariant]]
            name = "fee-calc"
            severity = "medium"
            category = "economic"
            [invariant.check]
            type = "requires_call"
            function = "calculate_fee"
            in_handler = "spend"
        "#,
        )
        .unwrap();

        let violations = verify_invariants(&spec, &[module]);
        assert!(violations.is_empty());
    }

    #[test]
    fn test_verify_requires_call_fail() {
        let signals = BodySignals::default();
        let module = make_module("swap", "swap", "spend", signals);

        let spec: InvariantSpec = toml::from_str(
            r#"
            [protocol]
            name = "Test"
            [[invariant]]
            name = "fee-calc"
            severity = "medium"
            category = "economic"
            [invariant.check]
            type = "requires_call"
            function = "calculate_fee"
            in_handler = "spend"
        "#,
        )
        .unwrap();

        let violations = verify_invariants(&spec, &[module]);
        assert_eq!(violations.len(), 1);
        assert!(violations[0].expected.contains("calculate_fee"));
    }

    #[test]
    fn test_verify_requires_call_wrong_handler_skipped() {
        let signals = BodySignals::default();
        // Handler is "mint" but invariant targets "spend"
        let module = make_module("swap", "swap", "mint", signals);

        let spec: InvariantSpec = toml::from_str(
            r#"
            [protocol]
            name = "Test"
            [[invariant]]
            name = "fee-calc"
            severity = "medium"
            category = "economic"
            [invariant.check]
            type = "requires_call"
            function = "calculate_fee"
            in_handler = "spend"
        "#,
        )
        .unwrap();

        let violations = verify_invariants(&spec, &[module]);
        assert!(violations.is_empty(), "Should skip non-matching handler");
    }

    // -----------------------------------------------------------------------
    // Verification: ValuePreservation
    // -----------------------------------------------------------------------

    #[test]
    fn test_verify_value_preservation_pass() {
        let mut signals = BodySignals::default();
        signals.tx_field_accesses.insert("inputs".to_string());
        signals.tx_field_accesses.insert("outputs".to_string());
        signals.function_calls.insert("quantity_of".to_string());

        let module = make_module("swap", "swap", "spend", signals);

        let spec: InvariantSpec = toml::from_str(
            r#"
            [protocol]
            name = "Test"
            [[invariant]]
            name = "value-check"
            severity = "critical"
            category = "value_conservation"
            [invariant.check]
            type = "value_preservation"
        "#,
        )
        .unwrap();

        let violations = verify_invariants(&spec, &[module]);
        assert!(violations.is_empty());
    }

    #[test]
    fn test_verify_value_preservation_fail() {
        let mut signals = BodySignals::default();
        signals.tx_field_accesses.insert("outputs".to_string());
        // Missing "inputs" access

        let module = make_module("swap", "swap", "spend", signals);

        let spec: InvariantSpec = toml::from_str(
            r#"
            [protocol]
            name = "Test"
            [[invariant]]
            name = "value-check"
            severity = "critical"
            category = "value_conservation"
            [invariant.check]
            type = "value_preservation"
        "#,
        )
        .unwrap();

        let violations = verify_invariants(&spec, &[module]);
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].severity, Severity::Critical);
    }

    // -----------------------------------------------------------------------
    // Verification: DatumContinuity
    // -----------------------------------------------------------------------

    #[test]
    fn test_verify_datum_continuity_pass_assertion() {
        let signals = BodySignals {
            has_datum_continuity_assertion: true,
            ..Default::default()
        };

        let module = make_module("position", "position", "spend", signals);

        let spec: InvariantSpec = toml::from_str(
            r#"
            [protocol]
            name = "Test"
            [[invariant]]
            name = "datum-cont"
            severity = "high"
            category = "state_transition"
            [invariant.check]
            type = "datum_continuity"
        "#,
        )
        .unwrap();

        let violations = verify_invariants(&spec, &[module]);
        assert!(violations.is_empty());
    }

    #[test]
    fn test_verify_datum_continuity_pass_field_checks() {
        let mut signals = BodySignals::default();
        signals.datum_equality_checks.insert("owner".to_string());
        signals
            .datum_equality_checks
            .insert("policy_id".to_string());

        let module = make_module("position", "position", "spend", signals);

        let spec: InvariantSpec = toml::from_str(
            r#"
            [protocol]
            name = "Test"
            [[invariant]]
            name = "datum-cont"
            severity = "high"
            category = "state_transition"
            [invariant.check]
            type = "datum_continuity"
            fields = ["owner", "policy_id"]
        "#,
        )
        .unwrap();

        let violations = verify_invariants(&spec, &[module]);
        assert!(violations.is_empty());
    }

    #[test]
    fn test_verify_datum_continuity_fail_missing_field() {
        let mut signals = BodySignals::default();
        signals.datum_equality_checks.insert("owner".to_string());
        // Missing "policy_id"

        let module = make_module("position", "position", "spend", signals);

        let spec: InvariantSpec = toml::from_str(
            r#"
            [protocol]
            name = "Test"
            [[invariant]]
            name = "datum-cont"
            severity = "high"
            category = "state_transition"
            [invariant.check]
            type = "datum_continuity"
            fields = ["owner", "policy_id"]
        "#,
        )
        .unwrap();

        let violations = verify_invariants(&spec, &[module]);
        assert_eq!(violations.len(), 1);
        assert!(violations[0].expected.contains("policy_id"));
    }

    #[test]
    fn test_verify_datum_continuity_fail_none() {
        let signals = BodySignals::default();
        let module = make_module("position", "position", "spend", signals);

        let spec: InvariantSpec = toml::from_str(
            r#"
            [protocol]
            name = "Test"
            [[invariant]]
            name = "datum-cont"
            severity = "high"
            category = "state_transition"
            [invariant.check]
            type = "datum_continuity"
        "#,
        )
        .unwrap();

        let violations = verify_invariants(&spec, &[module]);
        assert_eq!(violations.len(), 1);
    }

    // -----------------------------------------------------------------------
    // Verification: RequiresToken
    // -----------------------------------------------------------------------

    #[test]
    fn test_verify_requires_token_pass() {
        let mut signals = BodySignals::default();
        signals.function_calls.insert("quantity_of".to_string());

        let module = make_module("vault", "vault", "spend", signals);

        let spec: InvariantSpec = toml::from_str(
            r#"
            [protocol]
            name = "Test"
            [[invariant]]
            name = "token-check"
            severity = "high"
            category = "token_integrity"
            [invariant.check]
            type = "requires_token"
            policy_field = "policy_id"
        "#,
        )
        .unwrap();

        let violations = verify_invariants(&spec, &[module]);
        assert!(violations.is_empty());
    }

    #[test]
    fn test_verify_requires_token_fail() {
        let signals = BodySignals::default();
        let module = make_module("vault", "vault", "spend", signals);

        let spec: InvariantSpec = toml::from_str(
            r#"
            [protocol]
            name = "Test"
            [[invariant]]
            name = "token-check"
            severity = "high"
            category = "token_integrity"
            [invariant.check]
            type = "requires_token"
            policy_field = "policy_id"
            token_name = "auth"
        "#,
        )
        .unwrap();

        let violations = verify_invariants(&spec, &[module]);
        assert_eq!(violations.len(), 1);
        assert!(violations[0].expected.contains("policy_id"));
        assert!(violations[0].expected.contains("auth"));
    }

    // -----------------------------------------------------------------------
    // Verification: RequiresValidityRange
    // -----------------------------------------------------------------------

    #[test]
    fn test_verify_requires_validity_range_pass() {
        let mut signals = BodySignals::default();
        signals
            .tx_field_accesses
            .insert("validity_range".to_string());

        let module = make_module("position", "position", "spend", signals);

        let spec: InvariantSpec = toml::from_str(
            r#"
            [protocol]
            name = "Test"
            [[invariant]]
            name = "time-check"
            severity = "medium"
            category = "temporal"
            [invariant.check]
            type = "requires_validity_range"
            check_end = true
        "#,
        )
        .unwrap();

        let violations = verify_invariants(&spec, &[module]);
        assert!(violations.is_empty());
    }

    #[test]
    fn test_verify_requires_validity_range_fail() {
        let signals = BodySignals::default();
        let module = make_module("position", "position", "spend", signals);

        let spec: InvariantSpec = toml::from_str(
            r#"
            [protocol]
            name = "Test"
            [[invariant]]
            name = "time-check"
            severity = "medium"
            category = "temporal"
            [invariant.check]
            type = "requires_validity_range"
            check_start = true
            check_end = true
        "#,
        )
        .unwrap();

        let violations = verify_invariants(&spec, &[module]);
        assert_eq!(violations.len(), 1);
        assert!(violations[0].expected.contains("start"));
        assert!(violations[0].expected.contains("end"));
    }

    // -----------------------------------------------------------------------
    // Verification: Expression (unimplemented — always produces violation)
    // -----------------------------------------------------------------------

    #[test]
    fn test_verify_expression_always_violations() {
        let signals = BodySignals::default();
        let module = make_module("swap", "swap", "spend", signals);

        let spec: InvariantSpec = toml::from_str(
            r#"
            [protocol]
            name = "Test"
            [[invariant]]
            name = "custom-expr"
            severity = "info"
            category = "custom"
            [invariant.check]
            type = "expression"
            expr = "inputs.value >= outputs.value"
        "#,
        )
        .unwrap();

        let violations = verify_invariants(&spec, &[module]);
        assert_eq!(violations.len(), 1);
        assert!(violations[0].observed.contains("not yet implemented"));
    }

    // -----------------------------------------------------------------------
    // Validator scoping
    // -----------------------------------------------------------------------

    #[test]
    fn test_verify_validator_scoping() {
        let mut signals = BodySignals::default();
        signals
            .tx_field_accesses
            .insert("extra_signatories".to_string());

        // "treasury" validator satisfies the check, "swap" does not.
        let treasury = make_module("treasury", "treasury", "spend", signals);
        let swap = make_module("swap", "swap", "spend", BodySignals::default());

        let spec: InvariantSpec = toml::from_str(
            r#"
            [protocol]
            name = "Test"
            [[invariant]]
            name = "treasury-sig"
            severity = "critical"
            category = "access_control"
            validators = ["treasury"]
            [invariant.check]
            type = "requires_signatory"
        "#,
        )
        .unwrap();

        let violations = verify_invariants(&spec, &[treasury, swap]);
        // Only treasury is in scope, and it passes.
        assert!(violations.is_empty());
    }

    #[test]
    fn test_verify_all_validators_when_empty_scope() {
        let module_a = make_module("a", "alpha", "spend", BodySignals::default());
        let module_b = make_module("b", "beta", "spend", BodySignals::default());

        let spec: InvariantSpec = toml::from_str(
            r#"
            [protocol]
            name = "Test"
            [[invariant]]
            name = "global-sig"
            severity = "high"
            category = "access_control"
            [invariant.check]
            type = "requires_signatory"
        "#,
        )
        .unwrap();

        let violations = verify_invariants(&spec, &[module_a, module_b]);
        // Both validators should be checked (and both fail).
        assert_eq!(violations.len(), 2);
    }

    // -----------------------------------------------------------------------
    // Validator name matching
    // -----------------------------------------------------------------------

    #[test]
    fn test_validator_name_matches() {
        assert!(validator_name_matches("treasury", "treasury"));
        assert!(validator_name_matches("validators/treasury", "treasury"));
        assert!(!validator_name_matches("treasury", "swap"));
        assert!(!validator_name_matches("my_treasury", "treasury"));
    }

    // -----------------------------------------------------------------------
    // violations_to_findings conversion
    // -----------------------------------------------------------------------

    #[test]
    fn test_violations_to_findings() {
        let violations = vec![
            InvariantViolation {
                invariant_name: "sig-check".to_string(),
                category: InvariantCategory::AccessControl,
                severity: Severity::Critical,
                module: "treasury".to_string(),
                handler: "treasury.spend".to_string(),
                description: "Missing signatory check".to_string(),
                expected: "Signatory check present".to_string(),
                observed: "No extra_signatories access".to_string(),
            },
            InvariantViolation {
                invariant_name: "time-check".to_string(),
                category: InvariantCategory::Temporal,
                severity: Severity::Medium,
                module: "position".to_string(),
                handler: "position.spend".to_string(),
                description: "Missing validity range".to_string(),
                expected: "Validity range checked".to_string(),
                observed: "No validity_range access".to_string(),
            },
        ];

        let findings = violations_to_findings(&violations);
        assert_eq!(findings.len(), 2);

        assert_eq!(findings[0].detector_name, "invariant-spec:sig-check");
        assert_eq!(findings[0].severity, Severity::Critical);
        assert_eq!(findings[0].confidence, Confidence::Definite);
        assert!(findings[0].title.contains("sig-check"));
        assert!(findings[0].title.contains("treasury.spend"));
        assert!(findings[0].description.contains("Expected:"));
        assert!(findings[0].description.contains("Observed:"));
        assert_eq!(
            findings[0].semantic_group.as_deref(),
            Some("invariant-spec:access_control")
        );

        assert_eq!(findings[1].detector_name, "invariant-spec:time-check");
        assert_eq!(findings[1].severity, Severity::Medium);
    }

    #[test]
    fn test_violations_to_findings_empty() {
        let findings = violations_to_findings(&[]);
        assert!(findings.is_empty());
    }

    // -----------------------------------------------------------------------
    // Report formatting
    // -----------------------------------------------------------------------

    #[test]
    fn test_format_report_no_violations() {
        let spec: InvariantSpec = toml::from_str(
            r#"
            [protocol]
            name = "TestProto"
            version = "1.0"
        "#,
        )
        .unwrap();

        let report = format_invariant_report(&[], &spec);
        assert!(report.contains("TestProto"));
        assert!(report.contains("v1.0"));
        assert!(report.contains("Invariants defined: 0"));
        assert!(report.contains("Violations found: 0"));
        assert!(report.contains("All invariants satisfied"));
    }

    #[test]
    fn test_format_report_with_violations() {
        let spec: InvariantSpec = toml::from_str(
            r#"
            [protocol]
            name = "TestProto"
            description = "A test protocol"
            [[invariant]]
            name = "sig-check"
            severity = "critical"
            category = "access_control"
            [invariant.check]
            type = "requires_signatory"
        "#,
        )
        .unwrap();

        let violations = vec![InvariantViolation {
            invariant_name: "sig-check".to_string(),
            category: InvariantCategory::AccessControl,
            severity: Severity::Critical,
            module: "treasury".to_string(),
            handler: "treasury.spend".to_string(),
            description: "Missing signatory check".to_string(),
            expected: "Signatory check present".to_string(),
            observed: "No extra_signatories access".to_string(),
        }];

        let report = format_invariant_report(&violations, &spec);
        assert!(report.contains("TestProto"));
        assert!(report.contains("A test protocol"));
        assert!(report.contains("Violations found: 1"));
        assert!(report.contains("[access_control]"));
        assert!(report.contains("[CRITICAL]"));
        assert!(report.contains("sig-check"));
        assert!(report.contains("treasury.spend"));
    }

    // -----------------------------------------------------------------------
    // Sample spec generation
    // -----------------------------------------------------------------------

    #[test]
    fn test_generate_sample_spec() {
        let sample = generate_sample_spec("MyProtocol");
        assert!(sample.contains("MyProtocol"));
        assert!(sample.contains("[protocol]"));
        assert!(sample.contains("value_conservation"));
        assert!(sample.contains("access_control"));
        assert!(sample.contains("state_transition"));
        assert!(sample.contains("token_integrity"));
        assert!(sample.contains("temporal"));
        assert!(sample.contains("economic"));
        assert!(sample.contains("custom"));
        assert!(sample.contains("requires_signatory"));
        assert!(sample.contains("requires_validity_range"));
        assert!(sample.contains("datum_continuity"));
        assert!(sample.contains("requires_call"));
        assert!(sample.contains("requires_field_check"));
        assert!(sample.contains("requires_token"));
        assert!(sample.contains("value_preservation"));
    }

    // -----------------------------------------------------------------------
    // Error type
    // -----------------------------------------------------------------------

    #[test]
    fn test_error_display() {
        let io_err = InvariantError::IoError(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "file not found",
        ));
        assert!(io_err.to_string().contains("I/O error"));

        let parse_err = InvariantError::ParseError("bad toml".to_string());
        assert!(parse_err.to_string().contains("parse error: bad toml"));

        let val_err = InvariantError::ValidationError("empty name".to_string());
        assert!(val_err.to_string().contains("validation error: empty name"));
    }

    #[test]
    fn test_validation_empty_protocol_name() {
        let spec = InvariantSpec {
            protocol: ProtocolInfo {
                name: String::new(),
                version: None,
                description: None,
            },
            invariants: vec![],
        };
        let result = validate_spec(&spec);
        assert!(result.is_err());
    }

    #[test]
    fn test_validation_empty_invariant_name() {
        let spec = InvariantSpec {
            protocol: ProtocolInfo {
                name: "Test".to_string(),
                version: None,
                description: None,
            },
            invariants: vec![InvariantDef {
                name: String::new(),
                severity: InvariantSeverity::High,
                description: None,
                category: InvariantCategory::Custom,
                validators: vec![],
                check: InvariantCheck::Expression {
                    expr: "true".to_string(),
                },
            }],
        };
        let result = validate_spec(&spec);
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // Load from file (uses tempfile)
    // -----------------------------------------------------------------------

    #[test]
    fn test_load_invariant_spec_from_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".aikido-invariants.toml");
        std::fs::write(
            &path,
            r#"
            [protocol]
            name = "FileTest"
            version = "0.1.0"
            [[invariant]]
            name = "test-inv"
            severity = "low"
            category = "custom"
            [invariant.check]
            type = "requires_field_check"
            field = "mint"
        "#,
        )
        .unwrap();

        let spec = load_invariant_spec(&path).unwrap();
        assert_eq!(spec.protocol.name, "FileTest");
        assert_eq!(spec.invariants.len(), 1);
    }

    #[test]
    fn test_load_invariant_spec_missing_file() {
        let result = load_invariant_spec(Path::new("/nonexistent/.aikido-invariants.toml"));
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), InvariantError::IoError(_)));
    }

    #[test]
    fn test_load_invariant_spec_invalid_toml() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.toml");
        std::fs::write(&path, "this is not valid toml [[[").unwrap();

        let result = load_invariant_spec(&path);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), InvariantError::ParseError(_)));
    }
}
