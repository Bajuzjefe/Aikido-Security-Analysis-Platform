use crate::ast_walker::{ModuleInfo, ModuleKind};
use crate::detector::{Confidence, Detector, Finding, Severity, SourceLocation};

pub struct UnrestrictedMinting;

impl Detector for UnrestrictedMinting {
    fn name(&self) -> &str {
        "unrestricted-minting"
    }

    fn description(&self) -> &str {
        "Detects minting policies with no authorization check"
    }

    fn severity(&self) -> Severity {
        Severity::Critical
    }

    fn long_description(&self) -> &str {
        "A minting policy that performs no authorization check allows anyone to mint tokens. \
        Mint handlers should verify that the transaction is authorized, typically by checking \
        `extra_signatories` for a required signer or verifying a specific input UTXO is consumed.\n\n\
        Example (vulnerable):\n  mint(_redeemer, _self) {\n    True\n  }\n\n\
        Fix: Add authorization:\n  mint(redeemer, self) {\n    \
        list.has(self.extra_signatories, admin_pkh)\n  }"
    }

    fn cwe_id(&self) -> Option<&str> {
        Some("CWE-862")
    }

    fn category(&self) -> &str {
        "authorization"
    }

    fn detect(&self, modules: &[ModuleInfo]) -> Vec<Finding> {
        let mut findings = Vec::new();

        for module in modules {
            if module.kind != ModuleKind::Validator {
                continue;
            }

            for validator in &module.validators {
                for handler in &validator.handlers {
                    if handler.name != "mint" {
                        continue;
                    }

                    let checks_signatories = handler
                        .body_signals
                        .tx_field_accesses
                        .contains("extra_signatories");
                    let checks_inputs = handler.body_signals.tx_field_accesses.contains("inputs");
                    let checks_mint = handler.body_signals.tx_field_accesses.contains("mint");
                    let checks_ref_inputs = handler
                        .body_signals
                        .tx_field_accesses
                        .contains("reference_inputs");
                    // No meaningful security checks at all
                    // Note: withdrawals access is NOT an authorization check — the
                    // withdraw-zero-trick detector handles insufficient withdrawal checks
                    if !checks_signatories && !checks_inputs && !checks_mint && !checks_ref_inputs {
                        // Check if a companion spend handler in the same validator has auth checks.
                        // Multi-validator pattern: spend handler enforces auth, mint handler defers.
                        let companion_has_auth = validator.handlers.iter().any(|h| {
                            h.name == "spend"
                                && (h
                                    .body_signals
                                    .tx_field_accesses
                                    .contains("extra_signatories")
                                    || h.body_signals.tx_field_accesses.contains("inputs"))
                        });

                        let confidence = if companion_has_auth {
                            Confidence::Possible
                        } else {
                            Confidence::Definite
                        };

                        let desc = if companion_has_auth {
                            "Mint handler has no direct authorization checks. A companion spend \
                            handler has auth checks — verify that minting is always paired with \
                            an authorized spend."
                                .to_string()
                        } else {
                            "Mint handler has no authorization checks (no signatories, inputs, \
                            mint, or reference input validation). Anyone can mint tokens."
                                .to_string()
                        };

                        findings.push(Finding {
                            detector_name: self.name().to_string(),
                            severity: self.severity(),
                            confidence,
                            title: format!(
                                "Unrestricted minting policy {}",
                                validator.name
                            ),
                            description: desc,
                            module: module.name.clone(),
                            location: handler.location.map(|(s, e)| {
                                SourceLocation::from_bytes(&module.path, s, e)
                            }),
                            suggestion: Some(
                                "Add authorization: check `self.extra_signatories` for an admin key, \
                                or verify a specific input UTXO is consumed."
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

    fn make_mint_handler(tx_accesses: HashSet<String>) -> Vec<ModuleInfo> {
        vec![ModuleInfo {
            name: "test/validator".to_string(),
            path: "validator.ak".to_string(),
            kind: ModuleKind::Validator,
            validators: vec![ValidatorInfo {
                name: "test_policy".to_string(),
                params: vec![],
                handlers: vec![HandlerInfo {
                    name: "mint".to_string(),
                    params: vec![
                        ParamInfo {
                            name: "redeemer".to_string(),
                            type_name: "Redeemer".to_string(),
                        },
                        ParamInfo {
                            name: "self".to_string(),
                            type_name: "Transaction".to_string(),
                        },
                    ],
                    return_type: "Bool".to_string(),
                    location: None,
                    body_signals: BodySignals {
                        tx_field_accesses: tx_accesses,
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
    fn test_detects_unrestricted_mint() {
        let modules = make_mint_handler(HashSet::new());
        let findings = UnrestrictedMinting.detect(&modules);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical);
        assert_eq!(findings[0].confidence, Confidence::Definite);
    }

    #[test]
    fn test_no_finding_with_signatories() {
        let mut accesses = HashSet::new();
        accesses.insert("extra_signatories".to_string());

        let modules = make_mint_handler(accesses);
        let findings = UnrestrictedMinting.detect(&modules);

        assert!(findings.is_empty());
    }

    #[test]
    fn test_no_finding_with_inputs_check() {
        let mut accesses = HashSet::new();
        accesses.insert("inputs".to_string());

        let modules = make_mint_handler(accesses);
        let findings = UnrestrictedMinting.detect(&modules);

        assert!(findings.is_empty());
    }

    #[test]
    fn test_no_finding_with_mint_check() {
        let mut accesses = HashSet::new();
        accesses.insert("mint".to_string());

        let modules = make_mint_handler(accesses);
        let findings = UnrestrictedMinting.detect(&modules);

        assert!(findings.is_empty());
    }

    #[test]
    fn test_finding_with_withdrawals_only() {
        // Withdrawals access is NOT an authorization check
        let mut accesses = HashSet::new();
        accesses.insert("withdrawals".to_string());

        let modules = make_mint_handler(accesses);
        let findings = UnrestrictedMinting.detect(&modules);

        assert_eq!(
            findings.len(),
            1,
            "Withdrawals alone should not suppress finding"
        );
    }
}
