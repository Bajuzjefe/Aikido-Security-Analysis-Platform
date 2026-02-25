use crate::ast_walker::{ModuleInfo, ModuleKind};
use crate::detector::{Confidence, Detector, Finding, Severity, SourceLocation};

/// Detects handlers that iterate transaction inputs without verifying
/// credential types (script vs pubkey).
///
/// This is the "Trust No UTxO" vulnerability pattern documented by Vacuumlabs.
/// When a validator searches for specific tokens in transaction inputs but
/// doesn't verify the input comes from a script address, an attacker could
/// satisfy the check using a pubkey-owned UTxO containing the same token.
pub struct MissingInputCredentialCheck;

impl Detector for MissingInputCredentialCheck {
    fn name(&self) -> &str {
        "missing-input-credential-check"
    }

    fn description(&self) -> &str {
        "Detects handlers that search inputs by token/value without verifying credential type"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn long_description(&self) -> &str {
        "When a handler searches transaction inputs for a specific token or value \
        (using list iteration on tx.inputs), it should verify that the input comes from \
        the expected script address — not just any address containing the right token.\n\n\
        A pubkey address can hold the same token as a script address. If a validator \
        only checks for token presence without verifying the credential type is \
        ScriptCredential, an attacker can satisfy the check with their own UTxO.\n\n\
        Exception: if the handler uses its own OutputReference (own_ref) to identify the \
        specific input, credential checking is unnecessary since own_ref is unique.\n\n\
        Example (vulnerable):\n  list.any(self.inputs, fn(input) {\n    \
        value.quantity_of(input.output.value, policy, name) > 0\n    \
        // Doesn't verify: input.output.address.payment_credential!\n  })\n\n\
        Fix: Also check credential:\n  list.any(self.inputs, fn(input) {\n    \
        input.output.address.payment_credential == ScriptCredential(hash) &&\n    \
        value.quantity_of(input.output.value, policy, name) > 0\n  })"
    }

    fn cwe_id(&self) -> Option<&str> {
        Some("CWE-345")
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

                    // Handler must iterate inputs
                    let iterates_inputs = signals.tx_list_iterations.contains("inputs");
                    if !iterates_inputs {
                        continue;
                    }

                    // If handler uses own_ref, it identifies its specific input
                    // (no need for credential check)
                    if signals.uses_own_ref {
                        continue;
                    }

                    // Check if handler does value/token checks on inputs
                    let checks_value_on_inputs = signals.function_calls.iter().any(|c| {
                        c.contains("quantity_of")
                            || c.contains("lovelace_of")
                            || c.contains("tokens")
                            || c.contains("policies")
                    }) || signals.all_record_labels.contains("value");

                    if !checks_value_on_inputs {
                        continue;
                    }

                    // Check if handler verifies credential types
                    let checks_credential = signals
                        .all_record_labels
                        .iter()
                        .any(|l| l == "payment_credential" || l == "stake_credential")
                        || signals
                            .var_references
                            .iter()
                            .any(|v| v == "ScriptCredential" || v == "VerificationKeyCredential")
                        || signals.function_calls.iter().any(|c| {
                            c.contains("payment_credential")
                                || c.contains("ScriptCredential")
                                || c.contains("credential")
                        });

                    if !checks_credential {
                        findings.push(Finding {
                            detector_name: self.name().to_string(),
                            severity: self.severity(),
                            confidence: Confidence::Possible,
                            title: format!(
                                "Input search without credential check in {}.{}",
                                validator.name, handler.name
                            ),
                            description: format!(
                                "Handler {}.{} iterates transaction inputs and checks \
                                token/value content but doesn't verify the input credential \
                                type (ScriptCredential vs VerificationKeyCredential). An \
                                attacker could satisfy the check using a pubkey-owned UTxO.",
                                validator.name, handler.name
                            ),
                            module: module.name.clone(),
                            location: handler
                                .location
                                .map(|(s, e)| SourceLocation::from_bytes(&module.path, s, e)),
                            suggestion: Some(
                                "Verify the input comes from the expected script: \
                                `input.output.address.payment_credential == \
                                ScriptCredential(expected_hash)`."
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
        tx_list_iterations: HashSet<String>,
        function_calls: HashSet<String>,
        record_labels: HashSet<String>,
        var_refs: HashSet<String>,
        uses_own_ref: bool,
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
                        tx_list_iterations,
                        function_calls,
                        all_record_labels: record_labels,
                        var_references: var_refs,
                        uses_own_ref,
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
    fn test_detects_input_search_without_credential() {
        let mut tx = HashSet::new();
        tx.insert("inputs".to_string());
        let mut iters = HashSet::new();
        iters.insert("inputs".to_string());
        let mut fns = HashSet::new();
        fns.insert("value.quantity_of".to_string());
        let mut labels = HashSet::new();
        labels.insert("value".to_string());

        let modules = make_handler(tx, iters, fns, labels, HashSet::new(), false);
        let findings = MissingInputCredentialCheck.detect(&modules);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Medium);
    }

    #[test]
    fn test_no_finding_with_credential_check() {
        let mut tx = HashSet::new();
        tx.insert("inputs".to_string());
        let mut iters = HashSet::new();
        iters.insert("inputs".to_string());
        let mut fns = HashSet::new();
        fns.insert("value.quantity_of".to_string());
        let mut labels = HashSet::new();
        labels.insert("value".to_string());
        labels.insert("payment_credential".to_string());

        let modules = make_handler(tx, iters, fns, labels, HashSet::new(), false);
        let findings = MissingInputCredentialCheck.detect(&modules);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_no_finding_with_own_ref() {
        let mut tx = HashSet::new();
        tx.insert("inputs".to_string());
        let mut iters = HashSet::new();
        iters.insert("inputs".to_string());
        let mut fns = HashSet::new();
        fns.insert("value.quantity_of".to_string());

        let modules = make_handler(tx, iters, fns, HashSet::new(), HashSet::new(), true);
        let findings = MissingInputCredentialCheck.detect(&modules);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_no_finding_with_script_credential_var() {
        let mut tx = HashSet::new();
        tx.insert("inputs".to_string());
        let mut iters = HashSet::new();
        iters.insert("inputs".to_string());
        let mut fns = HashSet::new();
        fns.insert("value.quantity_of".to_string());
        let mut vars = HashSet::new();
        vars.insert("ScriptCredential".to_string());

        let modules = make_handler(tx, iters, fns, HashSet::new(), vars, false);
        let findings = MissingInputCredentialCheck.detect(&modules);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_no_finding_without_value_check() {
        let mut tx = HashSet::new();
        tx.insert("inputs".to_string());
        let mut iters = HashSet::new();
        iters.insert("inputs".to_string());

        let modules = make_handler(
            tx,
            iters,
            HashSet::new(),
            HashSet::new(),
            HashSet::new(),
            false,
        );
        let findings = MissingInputCredentialCheck.detect(&modules);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_no_finding_without_input_iteration() {
        let mut tx = HashSet::new();
        tx.insert("inputs".to_string());
        // No iteration on inputs
        let modules = make_handler(
            tx,
            HashSet::new(),
            HashSet::new(),
            HashSet::new(),
            HashSet::new(),
            false,
        );
        let findings = MissingInputCredentialCheck.detect(&modules);
        assert!(findings.is_empty());
    }
}
