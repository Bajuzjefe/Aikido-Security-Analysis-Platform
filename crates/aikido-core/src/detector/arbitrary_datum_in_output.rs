use crate::ast_walker::{ModuleInfo, ModuleKind};
use crate::detector::{
    outputs_go_to_pkh_only, Confidence, Detector, Finding, Severity, SourceLocation,
};

/// Detects handlers that write outputs with datum but never validate datum content.
pub struct ArbitraryDatumInOutput;

impl Detector for ArbitraryDatumInOutput {
    fn name(&self) -> &str {
        "arbitrary-datum-in-output"
    }

    fn description(&self) -> &str {
        "Detects handlers that produce outputs with datum but don't validate datum correctness"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn long_description(&self) -> &str {
        "When a handler creates continuing outputs (e.g., sending funds back to the script), \
        the datum attached to those outputs must be validated. If the datum is not checked \
        against expected values, an attacker can lock funds with an arbitrary datum, potentially \
        making them unspendable or manipulating contract state.\n\n\
        Example (vulnerable):\n  spend(datum, redeemer, own_ref, self) {\n    \
        list.any(self.outputs, fn(o) {\n      o.address == own_address && o.value >= min_value\n      \
        // datum not validated!\n    })\n  }\n\n\
        Fix: Validate the output datum:\n  list.any(self.outputs, fn(o) {\n    \
        o.address == own_address && o.value >= min_value\n    \
        && o.datum == InlineDatum(expected_datum)\n  })"
    }

    fn cwe_id(&self) -> Option<&str> {
        Some("CWE-20")
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
                    if handler.name != "spend" {
                        continue;
                    }

                    let signals = &handler.body_signals;

                    // Datum validation is only relevant for script outputs, not wallet (PKH) outputs
                    if outputs_go_to_pkh_only(signals) {
                        continue;
                    }

                    // Suppress when datum continuity is already asserted
                    if signals.has_datum_continuity_assertion {
                        continue;
                    }

                    // Handler accesses outputs but never accesses datum on those outputs
                    let accesses_outputs = signals.tx_field_accesses.contains("outputs");
                    let accesses_datum = signals.all_record_labels.contains("datum");

                    // Also check for InlineDatum or DatumHash in function calls/var refs
                    let validates_datum = accesses_datum
                        || signals.var_references.contains("InlineDatum")
                        || signals.var_references.contains("DatumHash")
                        || signals.var_references.contains("NoDatum");

                    if accesses_outputs && !validates_datum {
                        findings.push(Finding {
                            detector_name: self.name().to_string(),
                            severity: self.severity(),
                            confidence: Confidence::Possible,
                            title: format!(
                                "Handler {}.{} writes outputs without validating datum",
                                validator.name, handler.name
                            ),
                            description:
                                "Outputs are produced but the datum content is never checked. \
                                An attacker could attach an arbitrary datum, corrupting state or \
                                locking funds permanently."
                                    .to_string(),
                            module: module.name.clone(),
                            location: handler
                                .location
                                .map(|(s, e)| SourceLocation::from_bytes(&module.path, s, e)),
                            suggestion: Some(
                                "Validate output datum with `o.datum == InlineDatum(expected)` to ensure state integrity."
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

    fn make_spend_handler(
        tx_accesses: HashSet<String>,
        record_labels: HashSet<String>,
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
    fn test_detects_arbitrary_datum() {
        let mut tx = HashSet::new();
        tx.insert("outputs".to_string());
        let labels = HashSet::new(); // no datum label
        let modules = make_spend_handler(tx, labels, HashSet::new());
        let findings = ArbitraryDatumInOutput.detect(&modules);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn test_no_finding_when_datum_checked() {
        let mut tx = HashSet::new();
        tx.insert("outputs".to_string());
        let mut labels = HashSet::new();
        labels.insert("datum".to_string());
        let modules = make_spend_handler(tx, labels, HashSet::new());
        let findings = ArbitraryDatumInOutput.detect(&modules);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_no_finding_when_inline_datum_used() {
        let mut tx = HashSet::new();
        tx.insert("outputs".to_string());
        let mut vars = HashSet::new();
        vars.insert("InlineDatum".to_string());
        let modules = make_spend_handler(tx, HashSet::new(), vars);
        let findings = ArbitraryDatumInOutput.detect(&modules);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_no_finding_without_outputs() {
        let tx = HashSet::new(); // no outputs access
        let modules = make_spend_handler(tx, HashSet::new(), HashSet::new());
        let findings = ArbitraryDatumInOutput.detect(&modules);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_no_finding_when_outputs_to_pkh() {
        let mut tx = HashSet::new();
        tx.insert("outputs".to_string());
        let mut vars = HashSet::new();
        vars.insert("VerificationKeyCredential".to_string());
        let modules = make_spend_handler(tx, HashSet::new(), vars);
        let findings = ArbitraryDatumInOutput.detect(&modules);
        assert!(
            findings.is_empty(),
            "Should suppress when outputs go to PKH only"
        );
    }
}
