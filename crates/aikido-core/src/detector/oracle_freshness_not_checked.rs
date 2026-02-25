use crate::ast_walker::{ModuleInfo, ModuleKind};
use crate::detector::{Confidence, Detector, Finding, Severity, SourceLocation};

/// Detects usage of oracle/reference data without verifying recency.
pub struct OracleFreshnessNotChecked;

/// Patterns that suggest oracle or external data usage
const ORACLE_PATTERNS: &[&str] = &["oracle", "price", "feed", "rate", "exchange", "quote"];

impl Detector for OracleFreshnessNotChecked {
    fn name(&self) -> &str {
        "oracle-freshness-not-checked"
    }

    fn description(&self) -> &str {
        "Detects use of oracle data without verifying recency (timestamp/slot check)"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn long_description(&self) -> &str {
        "When using oracle data (prices, exchange rates, external state) from reference \
        inputs, the validator should verify that the data is recent by comparing a timestamp \
        or slot number in the oracle datum against the transaction's validity range. Stale \
        oracle data can be exploited for price manipulation attacks.\n\n\
        Example (vulnerable):\n  spend(datum, redeemer, own_ref, self) {\n    \
        let oracle_datum = get_oracle_datum(self.reference_inputs)\n    \
        let price = oracle_datum.price\n    // Missing: no freshness check!\n    \
        process_trade(price)\n  }\n\n\
        Fix: Verify oracle freshness:\n  spend(datum, redeemer, own_ref, self) {\n    \
        let oracle_datum = get_oracle_datum(self.reference_inputs)\n    \
        expect oracle_datum.last_updated >= get_lower_bound(self.validity_range)\n    \
        process_trade(oracle_datum.price)\n  }"
    }

    fn cwe_id(&self) -> Option<&str> {
        Some("CWE-613")
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
                    let signals = &handler.body_signals;

                    // Must use reference inputs (oracle data source)
                    let uses_ref_inputs = signals.tx_field_accesses.contains("reference_inputs");
                    if !uses_ref_inputs {
                        continue;
                    }

                    // Check if oracle-like patterns appear in record labels or function calls
                    let has_oracle_pattern = signals.all_record_labels.iter().any(|label| {
                        let lower = label.to_lowercase();
                        ORACLE_PATTERNS.iter().any(|p| lower.contains(p))
                    }) || signals.function_calls.iter().any(|call| {
                        let lower = call.to_lowercase();
                        ORACLE_PATTERNS.iter().any(|p| lower.contains(p))
                    }) || signals.var_references.iter().any(|var| {
                        let lower = var.to_lowercase();
                        ORACLE_PATTERNS.iter().any(|p| lower.contains(p))
                    });

                    if !has_oracle_pattern {
                        continue;
                    }

                    // Check if freshness/recency is verified
                    let checks_freshness =
                        // Validity range check (time-based freshness)
                        signals.tx_field_accesses.contains("validity_range")
                        // Timestamp/slot-related patterns in record labels
                        || signals.all_record_labels.iter().any(|label| {
                            let lower = label.to_lowercase();
                            lower.contains("timestamp")
                                || lower.contains("last_updated")
                                || lower.contains("updated_at")
                                || lower.contains("valid_until")
                                || lower.contains("expires")
                                || lower.contains("slot")
                                || lower.contains("epoch")
                                || lower.contains("freshness")
                        })
                        // Time-related function calls
                        || signals.function_calls.iter().any(|c| {
                            c.contains("interval")
                                || c.contains("time")
                                || c.contains("slot")
                                || c.contains("posix")
                        });

                    if !checks_freshness {
                        findings.push(Finding {
                            detector_name: self.name().to_string(),
                            severity: self.severity(),
                            confidence: Confidence::Possible,
                            title: format!(
                                "Handler {}.{} uses oracle data without freshness check",
                                validator.name, handler.name
                            ),
                            description:
                                "Handler accesses oracle data from reference inputs but doesn't \
                                verify the data's recency by checking a timestamp against the \
                                transaction's validity range. Stale oracle data can enable \
                                price manipulation attacks."
                                    .to_string(),
                            module: module.name.clone(),
                            location: handler
                                .location
                                .map(|(s, e)| SourceLocation::from_bytes(&module.path, s, e)),
                            suggestion: Some(
                                "Verify oracle freshness: check that the oracle datum's timestamp \
                                or last_updated field is within the transaction's validity range."
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

    fn make_handler(
        tx_accesses: HashSet<String>,
        record_labels: HashSet<String>,
        function_calls: HashSet<String>,
        var_refs: HashSet<String>,
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
                        tx_field_accesses: tx_accesses,
                        all_record_labels: record_labels,
                        function_calls,
                        var_references: var_refs,
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
    fn test_detects_oracle_without_freshness() {
        let mut tx = HashSet::new();
        tx.insert("reference_inputs".to_string());
        let mut labels = HashSet::new();
        labels.insert("price".to_string());
        // No validity_range or timestamp check

        let modules = make_handler(tx, labels, HashSet::new(), HashSet::new());
        let findings = OracleFreshnessNotChecked.detect(&modules);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].title.contains("freshness"));
    }

    #[test]
    fn test_no_finding_with_validity_range_check() {
        let mut tx = HashSet::new();
        tx.insert("reference_inputs".to_string());
        tx.insert("validity_range".to_string());
        let mut labels = HashSet::new();
        labels.insert("price".to_string());

        let modules = make_handler(tx, labels, HashSet::new(), HashSet::new());
        let findings = OracleFreshnessNotChecked.detect(&modules);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_no_finding_with_timestamp_field() {
        let mut tx = HashSet::new();
        tx.insert("reference_inputs".to_string());
        let mut labels = HashSet::new();
        labels.insert("price".to_string());
        labels.insert("last_updated".to_string());

        let modules = make_handler(tx, labels, HashSet::new(), HashSet::new());
        let findings = OracleFreshnessNotChecked.detect(&modules);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_no_finding_without_reference_inputs() {
        let mut labels = HashSet::new();
        labels.insert("price".to_string());
        let modules = make_handler(HashSet::new(), labels, HashSet::new(), HashSet::new());
        let findings = OracleFreshnessNotChecked.detect(&modules);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_no_finding_without_oracle_pattern() {
        let mut tx = HashSet::new();
        tx.insert("reference_inputs".to_string());
        // No oracle-related labels
        let modules = make_handler(tx, HashSet::new(), HashSet::new(), HashSet::new());
        let findings = OracleFreshnessNotChecked.detect(&modules);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_detects_via_var_reference() {
        let mut tx = HashSet::new();
        tx.insert("reference_inputs".to_string());
        let mut vars = HashSet::new();
        vars.insert("oracle_datum".to_string());

        let modules = make_handler(tx, HashSet::new(), HashSet::new(), vars);
        let findings = OracleFreshnessNotChecked.detect(&modules);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn test_no_finding_with_interval_function() {
        let mut tx = HashSet::new();
        tx.insert("reference_inputs".to_string());
        let mut labels = HashSet::new();
        labels.insert("oracle".to_string());
        let mut fns = HashSet::new();
        fns.insert("interval.is_entirely_after".to_string());

        let modules = make_handler(tx, labels, fns, HashSet::new());
        let findings = OracleFreshnessNotChecked.detect(&modules);
        assert!(findings.is_empty());
    }
}
