use crate::ast_walker::{ModuleInfo, ModuleKind};
use crate::delegation::build_delegation_set;
use crate::detector::{Confidence, Detector, Finding, Severity, SourceLocation};

pub struct MissingUtxoAuthentication;

impl Detector for MissingUtxoAuthentication {
    fn name(&self) -> &str {
        "missing-utxo-authentication"
    }

    fn description(&self) -> &str {
        "Detects handlers that use reference inputs without authenticating them"
    }

    fn severity(&self) -> Severity {
        Severity::Critical
    }

    fn long_description(&self) -> &str {
        "When a validator reads data from reference inputs, it must authenticate those inputs \
        to prevent an attacker from providing fake reference data. Without authentication, \
        an attacker can create a UTXO with attacker-controlled data at any address and \
        include it as a reference input.\n\n\
        Example (vulnerable):\n  spend(datum, redeemer, own_ref, self) {\n    \
        let oracle = list.head(self.reference_inputs)\n    \
        oracle.output.datum.price  // trusts unverified data!\n  }\n\n\
        Fix: Verify the reference input carries an auth token:\n  spend(datum, redeemer, own_ref, self) {\n    \
        let oracle = list.find(self.reference_inputs, fn(i) {\n      \
        value.quantity_of(i.output.value, oracle_policy, \"\") > 0\n    })\n    ...\n  }"
    }

    fn cwe_id(&self) -> Option<&str> {
        Some("CWE-345")
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
                    // Suppress on delegating handlers — auth happens in delegate
                    if delegation_set.contains(&(
                        module.name.clone(),
                        validator.name.clone(),
                        handler.name.clone(),
                    )) {
                        continue;
                    }

                    let uses_ref_inputs = handler
                        .body_signals
                        .tx_field_accesses
                        .contains("reference_inputs");

                    if !uses_ref_inputs {
                        continue;
                    }

                    // Check for authentication patterns
                    let checks_signatories = handler
                        .body_signals
                        .tx_field_accesses
                        .contains("extra_signatories");
                    let checks_mint = handler.body_signals.tx_field_accesses.contains("mint");

                    // If reference_inputs used without any auth pattern
                    if !checks_signatories && !checks_mint {
                        findings.push(Finding {
                            detector_name: self.name().to_string(),
                            severity: self.severity(),
                            confidence: Confidence::Likely,
                            title: format!(
                                "Unauthenticated reference inputs in {}.{}",
                                validator.name, handler.name
                            ),
                            description:
                                "Handler reads reference inputs without verifying their \
                                authenticity via signatories or minting policy checks. \
                                An attacker could provide fake reference data."
                                    .to_string(),
                            module: module.name.clone(),
                            location: handler.location.map(|(s, e)| {
                                SourceLocation::from_bytes(&module.path, s, e)
                            }),
                            suggestion: Some(
                                "Authenticate reference inputs by checking for an auth token (NFT/policy) \
                                or verifying a signer."
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

    fn make_handler_with_accesses(accesses: HashSet<String>) -> Vec<ModuleInfo> {
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
                        tx_field_accesses: accesses,
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
    fn test_detects_unauthenticated_ref_inputs() {
        let mut accesses = HashSet::new();
        accesses.insert("reference_inputs".to_string());

        let modules = make_handler_with_accesses(accesses);
        let findings = MissingUtxoAuthentication.detect(&modules);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical);
    }

    #[test]
    fn test_no_finding_when_signatories_checked() {
        let mut accesses = HashSet::new();
        accesses.insert("reference_inputs".to_string());
        accesses.insert("extra_signatories".to_string());

        let modules = make_handler_with_accesses(accesses);
        let findings = MissingUtxoAuthentication.detect(&modules);

        assert!(findings.is_empty());
    }

    #[test]
    fn test_no_finding_when_mint_checked() {
        let mut accesses = HashSet::new();
        accesses.insert("reference_inputs".to_string());
        accesses.insert("mint".to_string());

        let modules = make_handler_with_accesses(accesses);
        let findings = MissingUtxoAuthentication.detect(&modules);

        assert!(findings.is_empty());
    }

    #[test]
    fn test_no_finding_without_ref_inputs() {
        let mut accesses = HashSet::new();
        accesses.insert("outputs".to_string());

        let modules = make_handler_with_accesses(accesses);
        let findings = MissingUtxoAuthentication.detect(&modules);

        assert!(findings.is_empty());
    }
}
