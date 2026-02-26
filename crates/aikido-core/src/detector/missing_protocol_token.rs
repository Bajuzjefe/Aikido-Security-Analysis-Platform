use crate::ast_walker::{ModuleInfo, ModuleKind};
use crate::detector::{Confidence, Detector, Finding, Severity, SourceLocation};

/// Detects spend handlers that produce continuing outputs without verifying
/// a protocol/state token in the output value.
///
/// In Cardano DeFi, continuing outputs (UTXOs sent back to the same script)
/// should carry a state token (NFT or protocol token) to authenticate the
/// UTXO. Without a state token check, an attacker can create fake UTXOs
/// at the script address with arbitrary data.
pub struct MissingProtocolToken;

impl Detector for MissingProtocolToken {
    fn name(&self) -> &str {
        "missing-protocol-token"
    }

    fn description(&self) -> &str {
        "Detects continuing outputs without state token verification"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn long_description(&self) -> &str {
        "When a spend handler produces continuing outputs (UTXOs returned to the script), \
        it should verify the output carries a protocol/state token. This token authenticates \
        the UTXO and prevents confusion with attacker-created UTXOs at the same address.\n\n\
        Without state token verification:\n\
        - Attacker can create fake UTXOs at the script address with bogus data\n\
        - The validator may accept stale or manipulated state\n\
        - Protocol invariants can be violated\n\n\
        Example (vulnerable):\n  spend(datum, redeemer, own_ref, self) {\n    \
        // Sends output back to script but doesn't check for state NFT\n    \
        expect some_output.value >= min_value\n  }\n\n\
        Fix: Verify state token:\n  \
        expect value.quantity_of(output.value, state_policy, state_name) == 1"
    }

    fn cwe_id(&self) -> Option<&str> {
        Some("CWE-345")
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
                    if handler.name != "spend" {
                        continue;
                    }

                    let signals = &handler.body_signals;

                    // Must produce continuing outputs
                    if !signals.tx_field_accesses.contains("outputs") {
                        continue;
                    }

                    // Must use own_ref (identifying own script address)
                    if !signals.uses_own_ref {
                        continue;
                    }

                    // Check for token/value verification in outputs
                    let checks_token = signals.function_calls.iter().any(|c| {
                        c.contains("quantity_of")
                            || c.contains("tokens")
                            || c.contains("from_asset")
                            || c.contains("policies")
                    });

                    // Also OK if mint is checked (minting verifies token presence)
                    let checks_mint = signals.tx_field_accesses.contains("mint");

                    if !checks_token && !checks_mint {
                        findings.push(Finding {
                            detector_name: self.name().to_string(),
                            severity: self.severity(),
                            confidence: Confidence::Possible,
                            title: format!(
                                "Continuing output in {}.{} without state token verification",
                                validator.name, handler.name
                            ),
                            description: format!(
                                "Handler {}.{} produces continuing outputs and uses own_ref \
                                but doesn't verify a protocol/state token in the output. \
                                Without token verification, fake UTXOs at the script address \
                                could be accepted.",
                                validator.name, handler.name
                            ),
                            module: module.name.clone(),
                            location: handler
                                .location
                                .map(|(s, e)| SourceLocation::from_bytes(&module.path, s, e)),
                            suggestion: Some(
                                "Verify the continuing output carries a state token: \
                                `expect value.quantity_of(output.value, state_policy, name) == 1`."
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
        func_calls: HashSet<String>,
        uses_own_ref: bool,
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
    fn test_detects_missing_state_token() {
        let mut tx = HashSet::new();
        tx.insert("outputs".to_string());

        let modules = make_handler(tx, HashSet::new(), true);
        let findings = MissingProtocolToken.detect(&modules);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Medium);
    }

    #[test]
    fn test_no_finding_with_quantity_of() {
        let mut tx = HashSet::new();
        tx.insert("outputs".to_string());
        let mut calls = HashSet::new();
        calls.insert("value.quantity_of".to_string());

        let modules = make_handler(tx, calls, true);
        let findings = MissingProtocolToken.detect(&modules);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_no_finding_with_mint_check() {
        let mut tx = HashSet::new();
        tx.insert("outputs".to_string());
        tx.insert("mint".to_string());

        let modules = make_handler(tx, HashSet::new(), true);
        let findings = MissingProtocolToken.detect(&modules);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_no_finding_without_own_ref() {
        let mut tx = HashSet::new();
        tx.insert("outputs".to_string());

        let modules = make_handler(tx, HashSet::new(), false);
        let findings = MissingProtocolToken.detect(&modules);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_no_finding_without_outputs() {
        let modules = make_handler(HashSet::new(), HashSet::new(), true);
        let findings = MissingProtocolToken.detect(&modules);
        assert!(findings.is_empty());
    }
}
