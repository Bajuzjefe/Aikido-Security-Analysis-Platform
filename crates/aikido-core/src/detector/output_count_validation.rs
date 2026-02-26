use crate::ast_walker::{ModuleInfo, ModuleKind};
use crate::delegation::build_delegation_set;
use crate::detector::{Confidence, Detector, Finding, Severity, SourceLocation};

/// Detects spend handlers that produce continuing outputs to script addresses
/// without checking the output count.
///
/// Without an output count check (e.g., `list.length(script_outputs) == 1`),
/// an attacker can include extra outputs in the transaction, potentially
/// splitting the script UTXO into multiple pieces with duplicated state.
pub struct OutputCountValidation;

impl Detector for OutputCountValidation {
    fn name(&self) -> &str {
        "output-count-validation"
    }

    fn description(&self) -> &str {
        "Detects spend handlers producing script outputs without checking output count"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn long_description(&self) -> &str {
        "When a spend handler produces continuing outputs to a script address, it should \
        verify exactly how many outputs are created. Without an output count check, an \
        attacker can create extra script outputs in the same transaction, effectively \
        duplicating the contract state.\n\n\
        Example (vulnerable):\n  spend(datum, redeemer, own_ref, self) {\n    \
        list.any(self.outputs, fn(o) {\n      \
        o.address == own_address && o.value >= min_value\n    })\n    \
        // No check on HOW MANY outputs go to the script!\n  }\n\n\
        Fix: Check output count:\n  let script_outputs = list.filter(self.outputs, fn(o) {\n    \
        o.address.payment_credential == ScriptCredential(own_hash)\n  })\n  \
        expect list.length(script_outputs) == 1"
    }

    fn cwe_id(&self) -> Option<&str> {
        Some("CWE-697")
    }

    fn category(&self) -> &str {
        "logic"
    }

    fn detect(&self, modules: &[ModuleInfo]) -> Vec<Finding> {
        let mut findings = Vec::new();
        let delegation_set = build_delegation_set(modules);

        for module in modules {
            if module.kind != ModuleKind::Validator {
                continue;
            }

            for validator in &module.validators {
                for handler in &validator.handlers {
                    if handler.name != "spend" {
                        continue;
                    }

                    // Skip delegating handlers
                    if delegation_set.contains(&(
                        module.name.clone(),
                        validator.name.clone(),
                        handler.name.clone(),
                    )) {
                        continue;
                    }

                    let signals = &handler.body_signals;

                    // Must access outputs
                    if !signals.tx_field_accesses.contains("outputs") {
                        continue;
                    }

                    // Must produce continuing outputs to script addresses
                    // (evidence: ScriptCredential or script_hash in references)
                    let produces_script_outputs = signals.var_references.iter().any(|v| {
                        v == "ScriptCredential"
                            || v.contains("script_hash")
                            || v.contains("script_credential")
                    }) || signals
                        .function_calls
                        .iter()
                        .any(|c| c.contains("ScriptCredential") || c.contains("script_hash"));

                    if !produces_script_outputs {
                        continue;
                    }

                    // Check if output count is validated
                    let checks_count = signals
                        .function_calls
                        .iter()
                        .any(|c| c.contains("list.length") || c.contains("list.count"))
                        || signals.enforces_single_input; // single_input pattern implies count awareness

                    if !checks_count {
                        findings.push(Finding {
                            detector_name: self.name().to_string(),
                            severity: self.severity(),
                            confidence: Confidence::Possible,
                            title: format!(
                                "No output count check in {}.{}",
                                validator.name, handler.name
                            ),
                            description: format!(
                                "Handler {}.{} produces continuing outputs to a script \
                                address but doesn't verify the output count. An attacker \
                                could create extra script outputs, duplicating contract state.",
                                validator.name, handler.name
                            ),
                            module: module.name.clone(),
                            location: handler
                                .location
                                .map(|(s, e)| SourceLocation::from_bytes(&module.path, s, e)),
                            suggestion: Some(
                                "Check that exactly one output goes to the script address: \
                                `expect list.length(script_outputs) == 1`."
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

    fn make_spend(tx_accesses: &[&str], fn_calls: &[&str], var_refs: &[&str]) -> Vec<ModuleInfo> {
        vec![ModuleInfo {
            name: "test/validator".to_string(),
            path: "validator.ak".to_string(),
            kind: ModuleKind::Validator,
            validators: vec![ValidatorInfo {
                name: "pool".to_string(),
                params: vec![],
                handlers: vec![HandlerInfo {
                    name: "spend".to_string(),
                    params: vec![],
                    return_type: "Bool".to_string(),
                    location: None,
                    body_signals: BodySignals {
                        tx_field_accesses: tx_accesses.iter().map(|s| s.to_string()).collect(),
                        function_calls: fn_calls.iter().map(|s| s.to_string()).collect(),
                        var_references: var_refs.iter().map(|s| s.to_string()).collect(),
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
    fn test_detects_missing_output_count() {
        let modules = make_spend(&["outputs"], &["list.any"], &["ScriptCredential"]);
        let findings = OutputCountValidation.detect(&modules);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].title.contains("output count"));
    }

    #[test]
    fn test_no_finding_with_length_check() {
        let modules = make_spend(
            &["outputs"],
            &["list.any", "list.length"],
            &["ScriptCredential"],
        );
        let findings = OutputCountValidation.detect(&modules);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_no_finding_without_script_outputs() {
        // Outputs but no script address reference
        let modules = make_spend(&["outputs"], &["list.any"], &["VerificationKeyCredential"]);
        let findings = OutputCountValidation.detect(&modules);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_no_finding_without_outputs() {
        let modules = make_spend(&["inputs"], &["list.any"], &["ScriptCredential"]);
        let findings = OutputCountValidation.detect(&modules);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_no_finding_on_non_spend() {
        let modules = vec![ModuleInfo {
            name: "test/validator".to_string(),
            path: "validator.ak".to_string(),
            kind: ModuleKind::Validator,
            validators: vec![ValidatorInfo {
                name: "pool".to_string(),
                params: vec![],
                handlers: vec![HandlerInfo {
                    name: "mint".to_string(),
                    params: vec![],
                    return_type: "Bool".to_string(),
                    location: None,
                    body_signals: BodySignals {
                        tx_field_accesses: ["outputs"].iter().map(|s| s.to_string()).collect(),
                        var_references: ["ScriptCredential"]
                            .iter()
                            .map(|s| s.to_string())
                            .collect(),
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
        let findings = OutputCountValidation.detect(&modules);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_no_finding_with_count_check() {
        let modules = make_spend(
            &["outputs"],
            &["list.any", "list.count"],
            &["ScriptCredential"],
        );
        let findings = OutputCountValidation.detect(&modules);
        assert!(findings.is_empty());
    }
}
