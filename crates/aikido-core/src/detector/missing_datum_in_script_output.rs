use crate::ast_walker::{ModuleInfo, ModuleKind};
use crate::detector::{
    outputs_go_to_pkh_only, Confidence, Detector, Finding, Severity, SourceLocation,
};

pub struct MissingDatumInScriptOutput;

impl Detector for MissingDatumInScriptOutput {
    fn name(&self) -> &str {
        "missing-datum-in-script-output"
    }

    fn description(&self) -> &str {
        "Detects handlers that produce outputs without verifying datum attachment"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn long_description(&self) -> &str {
        "Sending value to a script address without attaching a datum makes those funds \
        permanently unspendable. A spend handler that constructs or validates continuing \
        outputs should verify that each output to a script address includes a datum.\n\n\
        Example (vulnerable):\n  spend(datum, redeemer, own_ref, self) {\n    \
        list.any(self.outputs, fn(o) {\n      \
        o.address == own_address && o.value >= min_value\n      \
        // Missing: no datum check!\n    })\n  }\n\n\
        Fix: Verify datum is present:\n  spend(datum, redeemer, own_ref, self) {\n    \
        list.any(self.outputs, fn(o) {\n      \
        o.address == own_address && o.value >= min_value\n      \
        && o.datum == InlineDatum(expected_datum)\n    })\n  }"
    }

    fn cwe_id(&self) -> Option<&str> {
        Some("CWE-404")
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
                    // Must access outputs
                    let accesses_outputs =
                        handler.body_signals.tx_field_accesses.contains("outputs");
                    if !accesses_outputs {
                        continue;
                    }

                    // Datum attachment is only relevant for script outputs, not wallet (PKH) outputs
                    if outputs_go_to_pkh_only(&handler.body_signals) {
                        continue;
                    }

                    // Check if datum is referenced anywhere in the body
                    let references_datum = handler.body_signals.all_record_labels.contains("datum");

                    // Check if Cardano datum constructors appear in var refs/function calls
                    // Only suppress on specific constructors, not loose "datum" substring
                    // (which matches input parameter names like "datum_opt")
                    let references_datum_type = handler
                        .body_signals
                        .var_references
                        .iter()
                        .any(|v| v == "InlineDatum" || v == "DatumHash" || v == "NoDatum")
                        || handler
                            .body_signals
                            .function_calls
                            .iter()
                            .any(|f| f.contains("InlineDatum") || f.contains("DatumHash"));

                    if !references_datum && !references_datum_type {
                        findings.push(Finding {
                            detector_name: self.name().to_string(),
                            severity: self.severity(),
                            confidence: Confidence::Possible,
                            title: format!(
                                "Outputs without datum verification in {}.{}",
                                validator.name, handler.name
                            ),
                            description: "Handler accesses transaction outputs but never checks \
                                the datum field. Outputs to script addresses without datum \
                                make funds permanently unspendable."
                                .to_string(),
                            module: module.name.clone(),
                            location: handler
                                .location
                                .map(|(s, e)| SourceLocation::from_bytes(&module.path, s, e)),
                            suggestion: Some(
                                "Verify that continuing outputs include the expected datum \
                                (e.g., `o.datum == InlineDatum(...)`)."
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
        var_refs: HashSet<String>,
    ) -> Vec<ModuleInfo> {
        vec![ModuleInfo {
            name: "test/validator".to_string(),
            path: "validator.ak".to_string(),
            kind: ModuleKind::Validator,
            validators: vec![ValidatorInfo {
                name: "test_validator".to_string(),
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
    fn test_detects_missing_datum_in_output() {
        let mut tx_accesses = HashSet::new();
        tx_accesses.insert("outputs".to_string());

        let modules = make_handler(tx_accesses, HashSet::new(), HashSet::new());
        let findings = MissingDatumInScriptOutput.detect(&modules);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn test_no_finding_when_datum_accessed() {
        let mut tx_accesses = HashSet::new();
        tx_accesses.insert("outputs".to_string());
        let mut labels = HashSet::new();
        labels.insert("datum".to_string());

        let modules = make_handler(tx_accesses, labels, HashSet::new());
        let findings = MissingDatumInScriptOutput.detect(&modules);

        assert!(findings.is_empty());
    }

    #[test]
    fn test_no_finding_when_datum_type_referenced() {
        let mut tx_accesses = HashSet::new();
        tx_accesses.insert("outputs".to_string());
        let mut refs = HashSet::new();
        refs.insert("InlineDatum".to_string());

        let modules = make_handler(tx_accesses, HashSet::new(), refs);
        let findings = MissingDatumInScriptOutput.detect(&modules);

        assert!(findings.is_empty());
    }

    #[test]
    fn test_no_finding_without_outputs() {
        let mut tx_accesses = HashSet::new();
        tx_accesses.insert("inputs".to_string());

        let modules = make_handler(tx_accesses, HashSet::new(), HashSet::new());
        let findings = MissingDatumInScriptOutput.detect(&modules);

        assert!(findings.is_empty());
    }

    #[test]
    fn test_no_finding_when_outputs_to_pkh() {
        let mut tx_accesses = HashSet::new();
        tx_accesses.insert("outputs".to_string());
        let mut vars = HashSet::new();
        vars.insert("VerificationKeyCredential".to_string());

        let modules = make_handler(tx_accesses, HashSet::new(), vars);
        let findings = MissingDatumInScriptOutput.detect(&modules);

        assert!(
            findings.is_empty(),
            "Should suppress when outputs go to PKH only"
        );
    }
}
