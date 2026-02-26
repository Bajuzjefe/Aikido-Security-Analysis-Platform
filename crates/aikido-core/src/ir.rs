//! Intermediate Representation types for Aikido analysis.
//!
//! Provides typed IR used by dataflow analysis and IR-based detectors.
//! Simpler than aiken-lang's TypedExpr — designed for analysis, not compilation.

use std::collections::{HashMap, HashSet};

/// Unique variable identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct VarId(pub u32);

/// Taint source — where potentially attacker-controlled data enters.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TaintSource {
    /// Redeemer parameter (fully attacker-controlled).
    Redeemer,
    /// A specific datum field (partially trusted — on-chain state).
    DatumField(String),
    /// Transaction field access (e.g., validity_range — partially trusted).
    TransactionField(String),
    /// External input (function parameter from caller).
    ExternalInput(String),
}

/// Taint label indicating the trust level of data.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TaintLabel {
    /// Fully attacker-controlled (redeemer, user-supplied data).
    AttackerControlled,
    /// On-chain data, can be manipulated in some contexts.
    PartiallyTrusted,
    /// Has passed through a guard/validation check.
    Sanitized,
    /// Clean — from trusted source (e.g., own script address).
    Clean,
}

impl TaintLabel {
    /// Whether this taint level is concerning (needs attention).
    pub fn is_tainted(&self) -> bool {
        matches!(
            self,
            TaintLabel::AttackerControlled | TaintLabel::PartiallyTrusted
        )
    }
}

/// A sensitive sink — an operation where tainted data could cause harm.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TaintSink {
    /// Division operation (tainted divisor → division by zero).
    Division,
    /// Output address (tainted address → funds sent to attacker).
    OutputAddress,
    /// Output value/amount (tainted amount → value manipulation).
    OutputValue,
    /// Arithmetic operation (tainted operand → calculation manipulation).
    Arithmetic,
    /// Comparison/guard (tainted comparison → bypassed check).
    Comparison,
    /// Datum field in output (tainted datum → state corruption).
    OutputDatum,
}

/// A tracked taint flow from source to sink.
#[derive(Debug, Clone)]
pub struct TaintFlow {
    /// Where the tainted data originated.
    pub source: TaintSource,
    /// Current taint level.
    pub label: TaintLabel,
    /// Where the tainted data reaches.
    pub sink: TaintSink,
    /// Chain of variable names showing the flow path.
    pub variable_chain: Vec<String>,
    /// Whether the data was sanitized (passed through a guard) before reaching the sink.
    pub is_sanitized: bool,
    /// The sanitizing condition, if any.
    pub sanitizer: Option<String>,
}

/// Results of taint analysis on a handler.
#[derive(Debug, Clone, Default)]
pub struct TaintResults {
    /// All detected taint flows.
    pub flows: Vec<TaintFlow>,
    /// Variables that have been sanitized (passed through guards).
    pub sanitized_vars: HashSet<String>,
    /// Variables with their current taint labels.
    pub var_taint: HashMap<String, TaintLabel>,
    /// Unsanitized flows reaching sensitive sinks (the actual findings).
    pub unsanitized_sink_flows: Vec<TaintFlow>,
    /// Dead variables (defined but never used).
    pub dead_vars: HashSet<String>,
    /// Number of distinct execution paths analyzed.
    pub paths_analyzed: usize,
    /// Variables that are guarded on some paths but not others.
    pub partially_guarded_vars: HashSet<String>,
}

impl TaintResults {
    /// Check if a variable is tainted (attacker-controlled or partially trusted).
    pub fn is_tainted(&self, var: &str) -> bool {
        self.var_taint
            .get(var)
            .is_some_and(|label| label.is_tainted())
    }

    /// Check if a variable has been sanitized.
    pub fn is_sanitized(&self, var: &str) -> bool {
        self.sanitized_vars.contains(var)
    }

    /// Get unsanitized flows to a specific sink type.
    pub fn unsanitized_to_sink(&self, sink: &TaintSink) -> Vec<&TaintFlow> {
        self.unsanitized_sink_flows
            .iter()
            .filter(|f| &f.sink == sink)
            .collect()
    }
}

/// Cardano-specific IR types for semantic analysis.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CardanoType {
    /// ADA value (lovelace).
    Lovelace,
    /// Multi-asset Value.
    Value,
    /// Address (payment + stake credential).
    Address,
    /// Datum (inline or hash).
    Datum(String),
    /// PolicyId (minting policy).
    PolicyId,
    /// OutputReference.
    OutputReference,
    /// Integer (generic).
    Int,
    /// ByteArray.
    ByteArray,
    /// Bool.
    Bool,
    /// List of some type.
    List(Box<CardanoType>),
    /// Option of some type.
    Option(Box<CardanoType>),
    /// Unknown / unresolved type.
    Unknown,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_taint_labels() {
        assert!(TaintLabel::AttackerControlled.is_tainted());
        assert!(TaintLabel::PartiallyTrusted.is_tainted());
        assert!(!TaintLabel::Sanitized.is_tainted());
        assert!(!TaintLabel::Clean.is_tainted());
    }

    #[test]
    fn test_taint_results_queries() {
        let mut results = TaintResults::default();
        results.var_taint.insert(
            "redeemer_amount".to_string(),
            TaintLabel::AttackerControlled,
        );
        results
            .var_taint
            .insert("datum_owner".to_string(), TaintLabel::PartiallyTrusted);
        results.sanitized_vars.insert("checked_amount".to_string());

        assert!(results.is_tainted("redeemer_amount"));
        assert!(results.is_tainted("datum_owner"));
        assert!(!results.is_tainted("checked_amount"));
        assert!(results.is_sanitized("checked_amount"));
    }

    #[test]
    fn test_unsanitized_to_sink() {
        let mut results = TaintResults::default();
        results.unsanitized_sink_flows.push(TaintFlow {
            source: TaintSource::Redeemer,
            label: TaintLabel::AttackerControlled,
            sink: TaintSink::Division,
            variable_chain: vec!["redeemer_x".to_string(), "divisor".to_string()],
            is_sanitized: false,
            sanitizer: None,
        });
        results.unsanitized_sink_flows.push(TaintFlow {
            source: TaintSource::Redeemer,
            label: TaintLabel::AttackerControlled,
            sink: TaintSink::OutputAddress,
            variable_chain: vec!["redeemer_addr".to_string()],
            is_sanitized: false,
            sanitizer: None,
        });

        assert_eq!(results.unsanitized_to_sink(&TaintSink::Division).len(), 1);
        assert_eq!(
            results.unsanitized_to_sink(&TaintSink::OutputAddress).len(),
            1
        );
        assert_eq!(results.unsanitized_to_sink(&TaintSink::Arithmetic).len(), 0);
    }
}
