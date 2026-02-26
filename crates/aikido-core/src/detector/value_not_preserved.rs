use crate::ast_walker::{ModuleInfo, ModuleKind};
use crate::detector::{Confidence, Detector, Finding, Severity, SourceLocation};

/// Detects spend handlers that produce outputs without verifying value preservation.
pub struct ValueNotPreserved;

impl Detector for ValueNotPreserved {
    fn name(&self) -> &str {
        "value-not-preserved"
    }

    fn description(&self) -> &str {
        "Detects spend handlers that don't verify output value covers input value"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn long_description(&self) -> &str {
        "A spend handler that sends continuing outputs back to the script should verify \
        that the output value is sufficient (typically >= the input value, minus any intended \
        withdrawal). Without this check, an attacker could drain funds by creating outputs \
        with less value than the input.\n\n\
        Example (vulnerable):\n  spend(datum, redeemer, own_ref, self) {\n    \
        list.any(self.outputs, fn(o) {\n      o.address == own_address\n      \
        // Missing: value check!\n    })\n  }\n\n\
        Fix: Verify value preservation:\n  list.any(self.outputs, fn(o) {\n    \
        o.address == own_address && value.lovelace_of(o.value) >= expected\n  })"
    }

    fn cwe_id(&self) -> Option<&str> {
        Some("CWE-682")
    }

    fn category(&self) -> &str {
        "math"
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

                    // Handler produces outputs (continuing UTXO pattern)
                    let accesses_outputs = signals.tx_field_accesses.contains("outputs");
                    if !accesses_outputs {
                        continue;
                    }

                    // Check if value is verified in outputs.
                    // Note: stdlib v2 renamed `value` module to `assets`, so we check
                    // both naming conventions.
                    let checks_value = signals.all_record_labels.contains("value")
                        || signals.function_calls.iter().any(|c| {
                            c.contains("lovelace_of")
                                || c.contains("value.merge")
                                || c.contains("value.add")
                                || c.contains("value.from_lovelace")
                                || c.contains("value.negate")
                                // stdlib v2 assets module (replaces value in Aiken v1.1+)
                                || c.contains("assets.merge")
                                || c.contains("assets.add")
                                || c.contains("assets.from_lovelace")
                                || c.contains("assets.negate")
                                || c.contains("assets.from_asset")
                                || c.contains("assets.without_lovelace")
                                || c.contains("assets.quantity_of")
                                || c.contains("assets.to_dict")
                                // Generic value comparison patterns
                                || c.contains("quantity_of")
                                || c.contains("from_asset")
                                || c.contains("without_lovelace")
                        });

                    if !checks_value {
                        findings.push(Finding {
                            detector_name: self.name().to_string(),
                            severity: self.severity(),
                            confidence: Confidence::Possible,
                            title: format!(
                                "Handler {}.{} produces outputs without value verification",
                                validator.name, handler.name
                            ),
                            description:
                                "Spend handler creates continuing outputs but never checks \
                                the output value. An attacker could drain funds by creating \
                                outputs with less value than expected."
                                    .to_string(),
                            module: module.name.clone(),
                            location: handler
                                .location
                                .map(|(s, e)| SourceLocation::from_bytes(&module.path, s, e)),
                            suggestion: Some(
                                "Verify output value with `value.lovelace_of(o.value) >= expected` or similar."
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
        function_calls: HashSet<String>,
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
    fn test_detects_missing_value_check() {
        let mut tx = HashSet::new();
        tx.insert("outputs".to_string());
        let mut labels = HashSet::new();
        labels.insert("address".to_string());
        // No "value" label

        let modules = make_spend_handler(tx, labels, HashSet::new());
        let findings = ValueNotPreserved.detect(&modules);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn test_no_finding_when_value_checked() {
        let mut tx = HashSet::new();
        tx.insert("outputs".to_string());
        let mut labels = HashSet::new();
        labels.insert("address".to_string());
        labels.insert("value".to_string());

        let modules = make_spend_handler(tx, labels, HashSet::new());
        let findings = ValueNotPreserved.detect(&modules);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_no_finding_with_value_function() {
        let mut tx = HashSet::new();
        tx.insert("outputs".to_string());
        let mut fns = HashSet::new();
        fns.insert("value.lovelace_of".to_string());

        let modules = make_spend_handler(tx, HashSet::new(), fns);
        let findings = ValueNotPreserved.detect(&modules);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_no_finding_with_assets_module_functions() {
        // stdlib v2 uses `assets` module instead of `value`
        let mut tx = HashSet::new();
        tx.insert("outputs".to_string());
        let mut fns = HashSet::new();
        fns.insert("assets.merge".to_string());

        let modules = make_spend_handler(tx, HashSet::new(), fns);
        let findings = ValueNotPreserved.detect(&modules);
        assert!(findings.is_empty(), "assets.merge should suppress finding");
    }

    #[test]
    fn test_no_finding_with_quantity_of() {
        let mut tx = HashSet::new();
        tx.insert("outputs".to_string());
        let mut fns = HashSet::new();
        fns.insert("assets.quantity_of".to_string());

        let modules = make_spend_handler(tx, HashSet::new(), fns);
        let findings = ValueNotPreserved.detect(&modules);
        assert!(
            findings.is_empty(),
            "assets.quantity_of should suppress finding"
        );
    }

    #[test]
    fn test_no_finding_with_from_asset() {
        let mut tx = HashSet::new();
        tx.insert("outputs".to_string());
        let mut fns = HashSet::new();
        fns.insert("from_asset".to_string());

        let modules = make_spend_handler(tx, HashSet::new(), fns);
        let findings = ValueNotPreserved.detect(&modules);
        assert!(findings.is_empty(), "from_asset should suppress finding");
    }

    #[test]
    fn test_no_finding_without_outputs() {
        let modules = make_spend_handler(HashSet::new(), HashSet::new(), HashSet::new());
        let findings = ValueNotPreserved.detect(&modules);
        assert!(findings.is_empty());
    }
}
