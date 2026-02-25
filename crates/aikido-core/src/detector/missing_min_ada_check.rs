use crate::ast_walker::{ModuleInfo, ModuleKind};
use crate::detector::{Confidence, Detector, Finding, Severity, SourceLocation};

/// Detects script outputs without minimum ADA (lovelace) verification.
pub struct MissingMinAdaCheck;

impl Detector for MissingMinAdaCheck {
    fn name(&self) -> &str {
        "missing-min-ada-check"
    }

    fn description(&self) -> &str {
        "Detects script outputs without ensuring minimum ADA requirement"
    }

    fn severity(&self) -> Severity {
        Severity::Info
    }

    fn long_description(&self) -> &str {
        "Cardano requires every UTXO to contain a minimum amount of ADA (approximately 1-2 ADA \
        depending on datum/token size). Script outputs that don't verify this minimum can fail \
        at transaction submission, causing unexpected failures. The Cardano ledger enforces this \
        as a protocol rule, so outputs below the minimum will be rejected.\n\n\
        Example (vulnerable):\n  let output = Output {\n    address: script_address,\n    \
        value: value.from_asset(policy, name, quantity),\n    // Only native tokens, no ADA check!\n    \
        datum: InlineDatum(new_datum),\n    reference_script: None,\n  }\n\n\
        Fix: Ensure minimum ADA:\n  let output = Output {\n    address: script_address,\n    \
        value: value.from_lovelace(2_000_000)\n      |> value.add(policy, name, quantity),\n    \
        datum: InlineDatum(new_datum),\n    reference_script: None,\n  }"
    }

    fn cwe_id(&self) -> Option<&str> {
        Some("CWE-754")
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
                    let signals = &handler.body_signals;

                    // Handler must access outputs
                    let accesses_outputs = signals.tx_field_accesses.contains("outputs");
                    if !accesses_outputs {
                        continue;
                    }

                    // Output construction guard: only fire if handler actually constructs
                    // outputs (has address AND value/lovelace in record labels). If handler
                    // just reads outputs for validation, skip.
                    let constructs_outputs = signals.all_record_labels.contains("address")
                        && (signals.all_record_labels.contains("value")
                            || signals.all_record_labels.contains("lovelace"));
                    if !constructs_outputs {
                        continue;
                    }

                    // Check if lovelace/ADA amount is verified or set
                    let checks_min_ada = signals.function_calls.iter().any(|c| {
                        c.contains("lovelace_of")
                            || c.contains("from_lovelace")
                            || c.contains("ada_lovelace")
                            || c.contains("min_ada")
                            || c.contains("min_lovelace")
                            || c.contains("minimum_ada")
                            || c.contains("value_geq")
                            || c.contains("value_greater")
                            || c.contains("merge")
                            || c.contains("from_asset")
                    }) || signals.all_record_labels.iter().any(|label| {
                        let lower = label.to_lowercase();
                        lower.contains("lovelace") || lower.contains("ada") || lower == "min_value"
                    }) || signals.var_references.iter().any(|var| {
                        let lower = var.to_lowercase();
                        lower.contains("min_ada")
                            || lower.contains("min_lovelace")
                            || lower.contains("minimum")
                    });

                    if !checks_min_ada {
                        findings.push(Finding {
                            detector_name: self.name().to_string(),
                            severity: self.severity(),
                            confidence: Confidence::Possible,
                            title: format!(
                                "Handler {}.{} produces outputs without minimum ADA check",
                                validator.name, handler.name
                            ),
                            description:
                                "Handler creates outputs but doesn't verify the minimum ADA \
                                (lovelace) requirement. Cardano requires every UTXO to contain \
                                a minimum amount of ADA. Note: The Cardano ledger enforces this \
                                as a protocol rule — transactions with outputs below the minimum \
                                are rejected at submission time, so this is not exploitable but \
                                may cause unexpected transaction failures."
                                    .to_string(),
                            module: module.name.clone(),
                            location: handler
                                .location
                                .map(|(s, e)| SourceLocation::from_bytes(&module.path, s, e)),
                            suggestion: Some(
                                "Ensure outputs include sufficient ADA using `value.from_lovelace(2_000_000)` \
                                or check with `value.lovelace_of(output.value) >= min_required`."
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
    fn test_detects_missing_min_ada() {
        let mut tx = HashSet::new();
        tx.insert("outputs".to_string());
        let mut labels = HashSet::new();
        labels.insert("address".to_string());
        labels.insert("value".to_string());
        // No lovelace/ADA checks

        let modules = make_handler(tx, labels, HashSet::new(), HashSet::new());
        let findings = MissingMinAdaCheck.detect(&modules);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].title.contains("minimum ADA"));
    }

    #[test]
    fn test_no_finding_with_lovelace_of() {
        let mut tx = HashSet::new();
        tx.insert("outputs".to_string());
        let mut labels = HashSet::new();
        labels.insert("address".to_string());
        labels.insert("value".to_string());
        let mut fns = HashSet::new();
        fns.insert("value.lovelace_of".to_string());

        let modules = make_handler(tx, labels, fns, HashSet::new());
        let findings = MissingMinAdaCheck.detect(&modules);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_no_finding_with_from_lovelace() {
        let mut tx = HashSet::new();
        tx.insert("outputs".to_string());
        let mut labels = HashSet::new();
        labels.insert("address".to_string());
        labels.insert("value".to_string());
        let mut fns = HashSet::new();
        fns.insert("value.from_lovelace".to_string());

        let modules = make_handler(tx, labels, fns, HashSet::new());
        let findings = MissingMinAdaCheck.detect(&modules);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_no_finding_with_min_ada_var() {
        let mut tx = HashSet::new();
        tx.insert("outputs".to_string());
        let mut labels = HashSet::new();
        labels.insert("address".to_string());
        labels.insert("value".to_string());
        let mut vars = HashSet::new();
        vars.insert("min_ada".to_string());

        let modules = make_handler(tx, labels, HashSet::new(), vars);
        let findings = MissingMinAdaCheck.detect(&modules);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_no_finding_without_outputs() {
        let modules = make_handler(
            HashSet::new(),
            HashSet::new(),
            HashSet::new(),
            HashSet::new(),
        );
        let findings = MissingMinAdaCheck.detect(&modules);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_no_finding_without_output_construction() {
        // Handler accesses outputs but doesn't construct them (no address+value labels)
        let mut tx = HashSet::new();
        tx.insert("outputs".to_string());

        let modules = make_handler(tx, HashSet::new(), HashSet::new(), HashSet::new());
        let findings = MissingMinAdaCheck.detect(&modules);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_no_finding_with_value_geq() {
        let mut tx = HashSet::new();
        tx.insert("outputs".to_string());
        let mut labels = HashSet::new();
        labels.insert("address".to_string());
        labels.insert("value".to_string());
        let mut fns = HashSet::new();
        fns.insert("value.value_geq".to_string());

        let modules = make_handler(tx, labels, fns, HashSet::new());
        let findings = MissingMinAdaCheck.detect(&modules);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_no_finding_with_merge() {
        let mut tx = HashSet::new();
        tx.insert("outputs".to_string());
        let mut labels = HashSet::new();
        labels.insert("address".to_string());
        labels.insert("value".to_string());
        let mut fns = HashSet::new();
        fns.insert("value.merge".to_string());

        let modules = make_handler(tx, labels, fns, HashSet::new());
        let findings = MissingMinAdaCheck.detect(&modules);
        assert!(findings.is_empty());
    }
}
