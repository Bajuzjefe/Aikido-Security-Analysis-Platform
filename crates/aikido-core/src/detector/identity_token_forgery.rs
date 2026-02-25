use crate::ast_walker::{ModuleInfo, ModuleKind};
use crate::cardano_model::uses_token_as_identity;
use crate::detector::{Confidence, Detector, Finding, Severity, SourceLocation};

/// Detects tokens used as identity proof without minting policy verification.
pub struct IdentityTokenForgery;

impl Detector for IdentityTokenForgery {
    fn name(&self) -> &str {
        "identity-token-forgery"
    }

    fn description(&self) -> &str {
        "Detects tokens used for identity without minting policy verification"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn long_description(&self) -> &str {
        "When a validator uses a token (via quantity_of) in inputs to verify identity \
        or authorization, the minting policy must be verified to ensure the token is \
        legitimate. Without checking the minting policy, an attacker can create a \
        token with the same name under a different policy."
    }

    fn cwe_id(&self) -> Option<&str> {
        Some("CWE-290")
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
                    let signals = &handler.body_signals;

                    let checks_token_without_policy = uses_token_as_identity(handler);

                    // Only flag if token is used for auth-like purpose
                    let is_auth_check = signals.guarded_vars.iter().any(|v| {
                        v.contains("token") || v.contains("nft") || v.contains("quantity")
                    }) || (signals
                        .function_calls
                        .iter()
                        .any(|c| c.contains("quantity_of"))
                        && (!signals.guarded_vars.is_empty() || signals.has_subtraction));

                    if checks_token_without_policy && is_auth_check {
                        findings.push(Finding {
                            detector_name: self.name().to_string(),
                            severity: self.severity(),
                            confidence: Confidence::Possible,
                            title: format!(
                                "Token identity without policy check in {}.{}",
                                validator.name, handler.name
                            ),
                            description: format!(
                                "Handler {}.{} uses quantity_of on inputs for identity/auth \
                                but doesn't verify the minting policy. An attacker could forge \
                                the token under a different policy.",
                                validator.name, handler.name
                            ),
                            module: module.name.clone(),
                            location: handler
                                .location
                                .map(|(s, e)| SourceLocation::from_bytes(&module.path, s, e)),
                            suggestion: Some(
                                "Verify the token's policy ID matches the expected minting policy."
                                    .to_string(),
                            ),
                            related_findings: vec![],
                            semantic_group: Some("cardano-semantics".to_string()),

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

    #[test]
    fn test_detects_token_without_policy() {
        let mut signals = BodySignals::default();
        signals.tx_field_accesses.insert("inputs".to_string());
        signals
            .function_calls
            .insert("assets.quantity_of".to_string());
        signals.guarded_vars.insert("token_quantity".to_string());
        signals.has_subtraction = true;

        let modules = vec![ModuleInfo {
            name: "test/v".to_string(),
            path: "v.ak".to_string(),
            kind: ModuleKind::Validator,
            validators: vec![ValidatorInfo {
                name: "pool".to_string(),
                params: vec![],
                handlers: vec![HandlerInfo {
                    name: "spend".to_string(),
                    params: vec![],
                    return_type: "Bool".to_string(),
                    location: None,
                    body_signals: signals,
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
        let findings = IdentityTokenForgery.detect(&modules);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn test_no_finding_with_policy_check() {
        let mut signals = BodySignals::default();
        signals.tx_field_accesses.insert("inputs".to_string());
        signals.tx_field_accesses.insert("mint".to_string());
        signals
            .function_calls
            .insert("assets.quantity_of".to_string());
        signals.guarded_vars.insert("token_quantity".to_string());

        let modules = vec![ModuleInfo {
            name: "test/v".to_string(),
            path: "v.ak".to_string(),
            kind: ModuleKind::Validator,
            validators: vec![ValidatorInfo {
                name: "pool".to_string(),
                params: vec![],
                handlers: vec![HandlerInfo {
                    name: "spend".to_string(),
                    params: vec![],
                    return_type: "Bool".to_string(),
                    location: None,
                    body_signals: signals,
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
        let findings = IdentityTokenForgery.detect(&modules);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_no_finding_without_auth_use() {
        let mut signals = BodySignals::default();
        signals.tx_field_accesses.insert("inputs".to_string());
        signals
            .function_calls
            .insert("assets.quantity_of".to_string());
        // No guarded_vars, no subtraction — not an auth check

        let modules = vec![ModuleInfo {
            name: "test/v".to_string(),
            path: "v.ak".to_string(),
            kind: ModuleKind::Validator,
            validators: vec![ValidatorInfo {
                name: "pool".to_string(),
                params: vec![],
                handlers: vec![HandlerInfo {
                    name: "spend".to_string(),
                    params: vec![],
                    return_type: "Bool".to_string(),
                    location: None,
                    body_signals: signals,
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
        let findings = IdentityTokenForgery.detect(&modules);
        assert!(findings.is_empty());
    }
}
