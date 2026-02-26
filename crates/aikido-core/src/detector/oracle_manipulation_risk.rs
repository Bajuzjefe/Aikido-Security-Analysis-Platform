use crate::ast_walker::{ModuleInfo, ModuleKind};
use crate::detector::{Confidence, Detector, Finding, Severity, SourceLocation};

/// Detects handlers that use reference inputs for oracle data without verifying
/// the input's payment credential (ScriptCredential/address match).
///
/// While `missing-utxo-authentication` checks for ANY auth (signers/mint),
/// this detector specifically flags when reference_inputs are used with
/// value/token checks but without address credential verification — the
/// standard oracle authentication pattern.
pub struct OracleManipulationRisk;

impl Detector for OracleManipulationRisk {
    fn name(&self) -> &str {
        "oracle-manipulation-risk"
    }

    fn description(&self) -> &str {
        "Detects reference input usage without payment credential verification"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn long_description(&self) -> &str {
        "When a handler reads oracle data from reference inputs, it should verify \
        the input's payment credential (address) to ensure the data comes from a \
        trusted oracle script. Checking only for an auth token (NFT) without also \
        verifying the credential allows an attacker to create a fake UTXO carrying \
        the same token at a different address with manipulated data.\n\n\
        Example (vulnerable):\n  spend(datum, redeemer, own_ref, self) {\n    \
        let oracle = list.find(self.reference_inputs, fn(i) {\n      \
        value.quantity_of(i.output.value, oracle_policy, \"\") > 0\n    })\n    \
        oracle.output.datum.price  // no address check!\n  }\n\n\
        Fix: Also verify the credential:\n  \
        expect ScriptCredential(hash) = oracle.output.address.payment_credential\n  \
        expect hash == expected_oracle_script_hash"
    }

    fn cwe_id(&self) -> Option<&str> {
        Some("CWE-345")
    }

    fn category(&self) -> &str {
        "oracle"
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

                    // Must use reference_inputs
                    if !signals.tx_field_accesses.contains("reference_inputs") {
                        continue;
                    }

                    // Must do value/token inspection (quantity_of, tokens, etc.)
                    let does_value_check = signals.function_calls.iter().any(|c| {
                        c.contains("quantity_of")
                            || c.contains("tokens")
                            || c.contains("from_asset")
                    });

                    if !does_value_check {
                        continue;
                    }

                    // Must NOT verify payment credential
                    let checks_credential = signals
                        .function_calls
                        .iter()
                        .any(|c| c.contains("payment_credential") || c.contains("credential"))
                        || signals.all_record_labels.contains("payment_credential")
                        || signals.var_references.contains("ScriptCredential");

                    if checks_credential {
                        continue;
                    }

                    findings.push(Finding {
                        detector_name: self.name().to_string(),
                        severity: self.severity(),
                        confidence: Confidence::Possible,
                        title: format!(
                            "Oracle reference input in {}.{} without credential verification",
                            validator.name, handler.name
                        ),
                        description: format!(
                            "Handler {}.{} reads reference inputs and checks token values \
                            but doesn't verify the payment credential. An attacker could \
                            provide a fake UTXO with manipulated oracle data.",
                            validator.name, handler.name
                        ),
                        module: module.name.clone(),
                        location: handler
                            .location
                            .map(|(s, e)| SourceLocation::from_bytes(&module.path, s, e)),
                        suggestion: Some(
                            "Verify the reference input's payment credential: \
                            `expect ScriptCredential(hash) = input.output.address.payment_credential` \
                            and check `hash == expected_script_hash`."
                                .to_string(),
                        ),
                        related_findings: vec![],
                        semantic_group: None,

                        evidence: None,
                    });
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
        func_calls: HashSet<String>,
        record_labels: HashSet<String>,
        var_refs: HashSet<String>,
    ) -> Vec<ModuleInfo> {
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
                        tx_field_accesses: tx_accesses,
                        function_calls: func_calls,
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
    fn test_detects_oracle_without_credential() {
        let mut tx = HashSet::new();
        tx.insert("reference_inputs".to_string());
        let mut calls = HashSet::new();
        calls.insert("value.quantity_of".to_string());

        let modules = make_handler(tx, calls, HashSet::new(), HashSet::new());
        let findings = OracleManipulationRisk.detect(&modules);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn test_no_finding_with_credential_check() {
        let mut tx = HashSet::new();
        tx.insert("reference_inputs".to_string());
        let mut calls = HashSet::new();
        calls.insert("value.quantity_of".to_string());
        let mut labels = HashSet::new();
        labels.insert("payment_credential".to_string());

        let modules = make_handler(tx, calls, labels, HashSet::new());
        let findings = OracleManipulationRisk.detect(&modules);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_no_finding_with_script_credential_var() {
        let mut tx = HashSet::new();
        tx.insert("reference_inputs".to_string());
        let mut calls = HashSet::new();
        calls.insert("value.quantity_of".to_string());
        let mut vars = HashSet::new();
        vars.insert("ScriptCredential".to_string());

        let modules = make_handler(tx, calls, HashSet::new(), vars);
        let findings = OracleManipulationRisk.detect(&modules);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_no_finding_without_reference_inputs() {
        let mut tx = HashSet::new();
        tx.insert("outputs".to_string());
        let mut calls = HashSet::new();
        calls.insert("value.quantity_of".to_string());

        let modules = make_handler(tx, calls, HashSet::new(), HashSet::new());
        let findings = OracleManipulationRisk.detect(&modules);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_no_finding_without_value_check() {
        let mut tx = HashSet::new();
        tx.insert("reference_inputs".to_string());

        let modules = make_handler(tx, HashSet::new(), HashSet::new(), HashSet::new());
        let findings = OracleManipulationRisk.detect(&modules);
        assert!(findings.is_empty());
    }
}
