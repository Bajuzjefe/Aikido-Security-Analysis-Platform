use crate::ast_walker::{ModuleInfo, ModuleKind};
use crate::detector::{
    outputs_go_to_pkh_only, Confidence, Detector, Finding, Severity, SourceLocation,
};

/// Detects handlers that produce outputs without constraining the reference_script field.
pub struct ReferenceScriptInjection;

impl Detector for ReferenceScriptInjection {
    fn name(&self) -> &str {
        "reference-script-injection"
    }

    fn description(&self) -> &str {
        "Detects outputs that don't constrain reference_script, allowing script injection"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn long_description(&self) -> &str {
        "When a validator produces continuing outputs but doesn't verify the \
        `reference_script` field is None (or a specific expected value), an attacker \
        can attach a large reference script to the UTXO. This increases the UTXO's \
        minimum ADA requirement significantly, potentially making it unspendable or \
        creating a denial-of-service condition.\n\n\
        Example (vulnerable):\n  list.any(self.outputs, fn(o) {\n    \
        o.address == script_address &&\n    o.value == expected_value\n    \
        // Missing: o.reference_script == None!\n  })\n\n\
        Fix: Constrain reference_script:\n  list.any(self.outputs, fn(o) {\n    \
        o.address == script_address &&\n    o.value == expected_value &&\n    \
        o.reference_script == None\n  })"
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
                    let signals = &handler.body_signals;

                    // Only fire for spend handlers — mint handlers produce new UTXOs,
                    // not continuing existing ones. The injection attack vector only
                    // applies to spend handlers with continuing outputs.
                    if handler.name != "spend" {
                        continue;
                    }

                    // Handler must access outputs (continuing UTXO pattern)
                    if !signals.tx_field_accesses.contains("outputs") {
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

                    // Suppress when outputs go to PKH addresses (wallet payouts).
                    // Reference script injection only matters for script-locked UTXOs
                    // that will be consumed by validators. Wallet owners can always
                    // spend their UTXOs regardless of attached reference scripts.
                    if outputs_go_to_pkh_only(signals) {
                        continue;
                    }

                    // Suppress when handler delegates to a withdrawal script.
                    if signals.tx_field_accesses.contains("withdrawals")
                        && signals
                            .function_calls
                            .iter()
                            .any(|c| c.contains("has_key") || c.contains("is_withdrawal"))
                    {
                        continue;
                    }

                    // Suppress when a flatten+length exact count check is present.
                    // Pattern: `list.length(flatten(output.value)) == N` constrains
                    // the UTXO size, limiting the damage from reference script injection.
                    let has_flatten = signals.function_calls.iter().any(|c| c.contains("flatten"));
                    let has_list_length = signals
                        .function_calls
                        .iter()
                        .any(|c| c.contains("list.length") || c.contains("length"));
                    if has_flatten && has_list_length {
                        continue;
                    }

                    // Check if reference_script is constrained
                    let constrains_ref_script = signals
                        .all_record_labels
                        .iter()
                        .any(|l| l == "reference_script")
                        || signals
                            .function_calls
                            .iter()
                            .any(|c| c.contains("reference_script"))
                        || signals
                            .var_references
                            .iter()
                            .any(|v| v.contains("reference_script"));

                    if !constrains_ref_script {
                        findings.push(Finding {
                            detector_name: self.name().to_string(),
                            severity: self.severity(),
                            confidence: Confidence::Possible,
                            title: format!(
                                "Handler {}.{} doesn't constrain reference_script on outputs",
                                validator.name, handler.name
                            ),
                            description: format!(
                                "Handler {}.{} produces outputs but never checks the \
                                `reference_script` field. An attacker can attach a large \
                                reference script to the UTXO, increasing minimum ADA and \
                                potentially making it unspendable.",
                                validator.name, handler.name
                            ),
                            module: module.name.clone(),
                            location: handler
                                .location
                                .map(|(s, e)| SourceLocation::from_bytes(&module.path, s, e)),
                            suggestion: Some(
                                "Add `o.reference_script == None` to output validation."
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

    fn make_handler_with_name(
        handler_name: &str,
        tx_accesses: HashSet<String>,
        record_labels: HashSet<String>,
    ) -> Vec<ModuleInfo> {
        vec![ModuleInfo {
            name: "test/validator".to_string(),
            path: "validator.ak".to_string(),
            kind: ModuleKind::Validator,
            validators: vec![ValidatorInfo {
                name: "test".to_string(),
                params: vec![],
                handlers: vec![HandlerInfo {
                    name: handler_name.to_string(),
                    params: vec![],
                    return_type: "Bool".to_string(),
                    location: None,
                    body_signals: BodySignals {
                        tx_field_accesses: tx_accesses,
                        all_record_labels: record_labels,
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

    fn make_handler(
        tx_accesses: HashSet<String>,
        record_labels: HashSet<String>,
    ) -> Vec<ModuleInfo> {
        make_handler_with_name("spend", tx_accesses, record_labels)
    }

    #[test]
    fn test_detects_missing_reference_script_check() {
        let mut tx = HashSet::new();
        tx.insert("outputs".to_string());
        let mut labels = HashSet::new();
        labels.insert("address".to_string());
        labels.insert("value".to_string());

        // Must include script address ref so PKH check doesn't suppress
        let modules = vec![ModuleInfo {
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
                        tx_field_accesses: tx,
                        all_record_labels: labels,
                        var_references: {
                            let mut v = HashSet::new();
                            v.insert("ScriptCredential".to_string());
                            v
                        },
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
        }];

        let findings = ReferenceScriptInjection.detect(&modules);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].title.contains("reference_script"));
    }

    #[test]
    fn test_no_finding_with_reference_script_check() {
        let mut tx = HashSet::new();
        tx.insert("outputs".to_string());
        let mut labels = HashSet::new();
        labels.insert("address".to_string());
        labels.insert("value".to_string());
        labels.insert("reference_script".to_string());

        let modules = make_handler(tx, labels);
        let findings = ReferenceScriptInjection.detect(&modules);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_no_finding_without_outputs() {
        let modules = make_handler(HashSet::new(), HashSet::new());
        let findings = ReferenceScriptInjection.detect(&modules);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_no_finding_for_mint_handler() {
        // Mint handlers produce new UTXOs, not continuing ones — skip them
        let mut tx = HashSet::new();
        tx.insert("outputs".to_string());
        let mut labels = HashSet::new();
        labels.insert("address".to_string());
        labels.insert("value".to_string());

        let modules = make_handler_with_name("mint", tx, labels);
        let findings = ReferenceScriptInjection.detect(&modules);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_no_finding_without_output_construction() {
        // Handler reads outputs but doesn't construct them (no address+value labels)
        let mut tx = HashSet::new();
        tx.insert("outputs".to_string());
        let labels = HashSet::new(); // no address/value labels

        let modules = make_handler(tx, labels);
        let findings = ReferenceScriptInjection.detect(&modules);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_no_finding_when_outputs_to_pkh() {
        // Outputs go to PKH addresses — no ref script injection risk
        let mut tx = HashSet::new();
        tx.insert("outputs".to_string());
        let mut labels = HashSet::new();
        labels.insert("address".to_string());
        labels.insert("value".to_string());
        let mut var_refs = HashSet::new();
        var_refs.insert("VerificationKeyCredential".to_string());

        let modules = vec![ModuleInfo {
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
                        tx_field_accesses: tx,
                        all_record_labels: labels,
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
        }];

        let findings = ReferenceScriptInjection.detect(&modules);
        assert!(
            findings.is_empty(),
            "PKH-only outputs should suppress ref script finding"
        );
    }

    #[test]
    fn test_no_finding_with_withdrawal_delegation() {
        let mut tx = HashSet::new();
        tx.insert("outputs".to_string());
        tx.insert("withdrawals".to_string());
        let mut labels = HashSet::new();
        labels.insert("address".to_string());
        labels.insert("value".to_string());

        let modules = vec![ModuleInfo {
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
                        tx_field_accesses: tx,
                        all_record_labels: labels,
                        function_calls: {
                            let mut fns = HashSet::new();
                            fns.insert("pairs.has_key".to_string());
                            fns
                        },
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
        }];

        let findings = ReferenceScriptInjection.detect(&modules);
        assert!(
            findings.is_empty(),
            "withdrawal delegation should suppress ref script finding"
        );
    }

    #[test]
    fn test_no_finding_with_flatten_length_constraint() {
        let mut tx = HashSet::new();
        tx.insert("outputs".to_string());
        let mut labels = HashSet::new();
        labels.insert("address".to_string());
        labels.insert("value".to_string());
        let mut fns = HashSet::new();
        fns.insert("assets.flatten".to_string());
        fns.insert("list.length".to_string());

        let modules = vec![ModuleInfo {
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
                        tx_field_accesses: tx,
                        all_record_labels: labels,
                        function_calls: fns,
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
        }];

        let findings = ReferenceScriptInjection.detect(&modules);
        assert!(
            findings.is_empty(),
            "flatten+length constraint should suppress ref script finding"
        );
    }
}
