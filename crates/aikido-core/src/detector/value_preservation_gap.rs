use crate::ast_walker::{ModuleInfo, ModuleKind};
use crate::detector::{Confidence, Detector, Finding, Severity, SourceLocation};

/// Detects spend handlers that check output value via lovelace only,
/// potentially ignoring native asset preservation.
///
/// Cardano UTxOs can contain ADA + native assets. A spend handler that only
/// verifies lovelace amount (via `lovelace_of`) without checking native assets
/// allows an attacker to drain native tokens while preserving ADA.
pub struct ValuePreservationGap;

impl Detector for ValuePreservationGap {
    fn name(&self) -> &str {
        "value-preservation-gap"
    }

    fn description(&self) -> &str {
        "Detects spend handlers that check lovelace but not native asset preservation"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn long_description(&self) -> &str {
        "When a spend handler verifies the output value using only `lovelace_of` (ADA check), \
        it ignores native assets in the UTXO. An attacker could construct a transaction that \
        preserves the ADA amount but strips or reduces native tokens from the continuing output.\n\n\
        Safe patterns include:\n\
        - Comparing full Values with `value.merge`, `value.negate`, or equality\n\
        - Using `value.without_lovelace` to check native assets separately\n\
        - Using `value.flatten` to enumerate and verify all assets\n\n\
        Example (vulnerable):\n  list.any(self.outputs, fn(o) {\n    \
        o.address == own_address &&\n    \
        value.lovelace_of(o.value) >= expected_ada\n    \
        // Native tokens not checked!\n  })\n\n\
        Fix: Check full value:\n  value.merge(o.value, value.negate(expected_value)) == value.zero()"
    }

    fn cwe_id(&self) -> Option<&str> {
        Some("CWE-682")
    }

    fn category(&self) -> &str {
        "math"
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

                    // Must produce outputs (continuing UTXO pattern)
                    if !signals.tx_field_accesses.contains("outputs") {
                        continue;
                    }

                    // Check if handler uses lovelace-only checking
                    let uses_lovelace_only = signals
                        .function_calls
                        .iter()
                        .any(|c| c.contains("lovelace_of") || c.contains("from_lovelace"));

                    if !uses_lovelace_only {
                        continue;
                    }

                    // Check if handler ALSO verifies native assets
                    let checks_native_assets = signals.function_calls.iter().any(|c| {
                        c.contains("without_lovelace")
                            || c.contains("value.merge")
                            || c.contains("value.negate")
                            || c.contains("value.flatten")
                            || c.contains("value.add")
                            || c.contains("value.zero")
                            || c.contains("value.to_dict")
                            || c.contains("value.tokens")
                            || c.contains("value.policies")
                            || c.contains("quantity_of")
                    });

                    if !checks_native_assets {
                        findings.push(Finding {
                            detector_name: self.name().to_string(),
                            severity: self.severity(),
                            confidence: Confidence::Likely,
                            title: format!(
                                "Value check in {}.{} covers lovelace but not native assets",
                                validator.name, handler.name
                            ),
                            description: format!(
                                "Handler {}.{} produces outputs and checks lovelace amounts \
                                (via lovelace_of/from_lovelace) but doesn't verify native \
                                asset preservation. An attacker could drain native tokens \
                                while keeping ADA intact.",
                                validator.name, handler.name
                            ),
                            module: module.name.clone(),
                            location: handler
                                .location
                                .map(|(s, e)| SourceLocation::from_bytes(&module.path, s, e)),
                            suggestion: Some(
                                "Compare full Values using `value.merge(output, value.negate(expected))` \
                                or check native assets with `value.without_lovelace` and `value.tokens`."
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

    fn make_spend(
        tx_accesses: HashSet<String>,
        function_calls: HashSet<String>,
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
                        function_calls,
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
    fn test_detects_lovelace_only_check() {
        let mut tx = HashSet::new();
        tx.insert("outputs".to_string());
        let mut fns = HashSet::new();
        fns.insert("value.lovelace_of".to_string());

        let modules = make_spend(tx, fns);
        let findings = ValuePreservationGap.detect(&modules);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn test_no_finding_with_merge() {
        let mut tx = HashSet::new();
        tx.insert("outputs".to_string());
        let mut fns = HashSet::new();
        fns.insert("value.lovelace_of".to_string());
        fns.insert("value.merge".to_string());

        let modules = make_spend(tx, fns);
        let findings = ValuePreservationGap.detect(&modules);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_no_finding_with_quantity_of() {
        let mut tx = HashSet::new();
        tx.insert("outputs".to_string());
        let mut fns = HashSet::new();
        fns.insert("value.lovelace_of".to_string());
        fns.insert("value.quantity_of".to_string());

        let modules = make_spend(tx, fns);
        let findings = ValuePreservationGap.detect(&modules);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_no_finding_without_lovelace_check() {
        let mut tx = HashSet::new();
        tx.insert("outputs".to_string());
        let mut fns = HashSet::new();
        fns.insert("value.merge".to_string());

        let modules = make_spend(tx, fns);
        let findings = ValuePreservationGap.detect(&modules);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_no_finding_without_outputs() {
        let mut fns = HashSet::new();
        fns.insert("value.lovelace_of".to_string());

        let modules = make_spend(HashSet::new(), fns);
        let findings = ValuePreservationGap.detect(&modules);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_no_finding_on_mint_handler() {
        let modules = vec![ModuleInfo {
            name: "test/validator".to_string(),
            path: "validator.ak".to_string(),
            kind: ModuleKind::Validator,
            validators: vec![ValidatorInfo {
                name: "test".to_string(),
                params: vec![],
                handlers: vec![HandlerInfo {
                    name: "mint".to_string(),
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
        let findings = ValuePreservationGap.detect(&modules);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_no_finding_with_without_lovelace() {
        let mut tx = HashSet::new();
        tx.insert("outputs".to_string());
        let mut fns = HashSet::new();
        fns.insert("value.lovelace_of".to_string());
        fns.insert("value.without_lovelace".to_string());

        let modules = make_spend(tx, fns);
        let findings = ValuePreservationGap.detect(&modules);
        assert!(findings.is_empty());
    }
}
