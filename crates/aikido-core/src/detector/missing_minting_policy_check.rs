use crate::ast_walker::{ModuleInfo, ModuleKind};
use crate::detector::{Confidence, Detector, Finding, Severity, SourceLocation};

pub struct MissingMintingPolicyCheck;

impl Detector for MissingMintingPolicyCheck {
    fn name(&self) -> &str {
        "missing-minting-policy-check"
    }

    fn description(&self) -> &str {
        "Detects mint handlers that don't validate which token names are being minted"
    }

    fn severity(&self) -> Severity {
        Severity::Critical
    }

    fn long_description(&self) -> &str {
        "A minting policy that doesn't validate token names allows an attacker to mint \
        arbitrary tokens under the policy. The mint handler should check the `mint` field \
        of the transaction to verify that only expected token names and quantities are minted.\n\n\
        Example (vulnerable):\n  mint(redeemer, self) {\n    \
        list.has(self.extra_signatories, admin_key)\n  }\n\n\
        Fix: Validate the mint field:\n  mint(redeemer, self) {\n    \
        let minted = value.from_minted_value(self.mint)\n    \
        expect [(_, token_name, qty)] = value.flatten(minted)\n    \
        token_name == expected_name && qty == 1\n  }"
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

                    let accesses_mint = handler.body_signals.tx_field_accesses.contains("mint");

                    if !accesses_mint {
                        // Mint handler that never reads the mint field at all
                        findings.push(Finding {
                            detector_name: self.name().to_string(),
                            severity: self.severity(),
                            confidence: Confidence::Definite,
                            title: format!(
                                "Minting policy {} doesn't validate minted tokens",
                                validator.name
                            ),
                            description:
                                "Mint handler never accesses the transaction's mint field. \
                                An attacker could mint arbitrary token names under this policy."
                                    .to_string(),
                            module: module.name.clone(),
                            location: handler.location.map(|(s, e)| {
                                SourceLocation::from_bytes(&module.path, s, e)
                            }),
                            suggestion: Some(
                                "Check `self.mint` (or `transaction.mint`) to validate token names and quantities."
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
    fn test_detects_missing_mint_check() {
        let mut accesses = HashSet::new();
        accesses.insert("extra_signatories".to_string());
        // No "mint" access

        let modules = make_mint_handler(accesses);
        let findings = MissingMintingPolicyCheck.detect(&modules);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical);
        assert!(findings[0].title.contains("doesn't validate"));
    }

    #[test]
    fn test_no_finding_when_mint_accessed() {
        let mut accesses = HashSet::new();
        accesses.insert("mint".to_string());
        accesses.insert("extra_signatories".to_string());

        let modules = make_mint_handler(accesses);
        let findings = MissingMintingPolicyCheck.detect(&modules);

        assert!(findings.is_empty());
    }

    #[test]
    fn test_skips_spend_handlers() {
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
                    body_signals: BodySignals::default(),
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

        let findings = MissingMintingPolicyCheck.detect(&modules);
        assert!(findings.is_empty());
    }
}
