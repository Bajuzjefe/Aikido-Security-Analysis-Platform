use crate::ast_walker::{ModuleInfo, ModuleKind};
use crate::delegation::build_delegation_set;
use crate::detector::{Confidence, Detector, Finding, Severity, SourceLocation};

/// Detects handlers that produce outputs without validating the destination address.
pub struct OutputAddressNotValidated;

impl Detector for OutputAddressNotValidated {
    fn name(&self) -> &str {
        "output-address-not-validated"
    }

    fn description(&self) -> &str {
        "Detects handlers that produce outputs without verifying the destination address"
    }

    fn severity(&self) -> Severity {
        Severity::Critical
    }

    fn long_description(&self) -> &str {
        "When a handler creates or iterates transaction outputs but never checks the output \
        address (payment_credential), an attacker could redirect funds to an arbitrary \
        address. This is especially dangerous in mint handlers where newly minted tokens \
        could be sent anywhere, and in spend handlers where continuing UTXOs must go back \
        to the correct script address.\n\n\
        Example (vulnerable):\n  mint(redeemer, self) {\n    \
        list.any(self.outputs, fn(o) {\n      value.quantity_of(o.value, policy, name) == 1\n      \
        // Missing: o.address == expected_address!\n    })\n  }\n\n\
        Fix: Verify address:\n  list.any(self.outputs, fn(o) {\n    \
        o.address.payment_credential == ScriptCredential(own_hash) &&\n    \
        value.quantity_of(o.value, policy, name) == 1\n  })"
    }

    fn cwe_id(&self) -> Option<&str> {
        Some("CWE-284")
    }

    fn category(&self) -> &str {
        "authorization"
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
                    // Suppress on delegating handlers — address validation happens in delegate
                    if delegation_set.contains(&(
                        module.name.clone(),
                        validator.name.clone(),
                        handler.name.clone(),
                    )) {
                        continue;
                    }

                    let signals = &handler.body_signals;

                    // Handler must access outputs
                    let accesses_outputs = signals.tx_field_accesses.contains("outputs");
                    if !accesses_outputs {
                        continue;
                    }

                    // Check if address/payment_credential is validated
                    let validates_address = signals
                        .all_record_labels
                        .iter()
                        .any(|l| l == "address" || l == "payment_credential")
                        || signals.function_calls.iter().any(|c| {
                            c.contains("payment_credential")
                                || c.contains("address")
                                || c.contains("script_hash")
                                || c.contains("ScriptCredential")
                                || c.contains("VerificationKeyCredential")
                        })
                        || signals.var_references.iter().any(|v| {
                            v.contains("address")
                                || v.contains("script_hash")
                                || v == "ScriptCredential"
                                || v == "VerificationKeyCredential"
                        });

                    if !validates_address {
                        // Higher confidence for mint handlers (tokens go to unchecked address)
                        let confidence = if handler.name == "mint" {
                            Confidence::Likely
                        } else {
                            Confidence::Possible
                        };

                        findings.push(Finding {
                            detector_name: self.name().to_string(),
                            severity: self.severity(),
                            confidence,
                            title: format!(
                                "Handler {}.{} produces outputs without address validation",
                                validator.name, handler.name
                            ),
                            description: format!(
                                "Handler {}.{} iterates transaction outputs but never checks \
                                the output address or payment_credential. An attacker could \
                                redirect funds or minted tokens to an arbitrary address.",
                                validator.name, handler.name
                            ),
                            module: module.name.clone(),
                            location: handler
                                .location
                                .map(|(s, e)| SourceLocation::from_bytes(&module.path, s, e)),
                            suggestion: Some(
                                "Verify output address with `o.address.payment_credential == \
                                ScriptCredential(own_hash)` or compare against expected address."
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
        handler_name: &str,
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
                    name: handler_name.to_string(),
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
    fn test_detects_missing_address_check_mint() {
        let mut tx = HashSet::new();
        tx.insert("outputs".to_string());
        let mut labels = HashSet::new();
        labels.insert("value".to_string());

        let modules = make_handler("mint", tx, labels, HashSet::new(), HashSet::new());
        let findings = OutputAddressNotValidated.detect(&modules);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical);
        assert_eq!(findings[0].confidence, Confidence::Likely);
    }

    #[test]
    fn test_detects_missing_address_check_spend() {
        let mut tx = HashSet::new();
        tx.insert("outputs".to_string());

        let modules = make_handler("spend", tx, HashSet::new(), HashSet::new(), HashSet::new());
        let findings = OutputAddressNotValidated.detect(&modules);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].confidence, Confidence::Possible);
    }

    #[test]
    fn test_no_finding_with_address_label() {
        let mut tx = HashSet::new();
        tx.insert("outputs".to_string());
        let mut labels = HashSet::new();
        labels.insert("address".to_string());

        let modules = make_handler("mint", tx, labels, HashSet::new(), HashSet::new());
        let findings = OutputAddressNotValidated.detect(&modules);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_no_finding_with_payment_credential_call() {
        let mut tx = HashSet::new();
        tx.insert("outputs".to_string());
        let mut fns = HashSet::new();
        fns.insert("payment_credential".to_string());

        let modules = make_handler("mint", tx, HashSet::new(), fns, HashSet::new());
        let findings = OutputAddressNotValidated.detect(&modules);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_no_finding_with_script_credential_var() {
        let mut tx = HashSet::new();
        tx.insert("outputs".to_string());
        let mut vars = HashSet::new();
        vars.insert("ScriptCredential".to_string());

        let modules = make_handler("mint", tx, HashSet::new(), HashSet::new(), vars);
        let findings = OutputAddressNotValidated.detect(&modules);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_no_finding_without_outputs() {
        let modules = make_handler(
            "mint",
            HashSet::new(),
            HashSet::new(),
            HashSet::new(),
            HashSet::new(),
        );
        let findings = OutputAddressNotValidated.detect(&modules);
        assert!(findings.is_empty());
    }
}
