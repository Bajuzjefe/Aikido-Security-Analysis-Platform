use crate::ast_walker::{ModuleInfo, ModuleKind};
use crate::cardano_model::uses_safe_value_comparison;
use crate::detector::{Confidence, Detector, Finding, Severity, SourceLocation};
use crate::stdlib_model::has_safe_multi_asset_handling;

/// Detects Value compared with >= or assets.match with non-equality.
pub struct MultiAssetComparisonBypass;

impl Detector for MultiAssetComparisonBypass {
    fn name(&self) -> &str {
        "multi-asset-comparison-bypass"
    }

    fn description(&self) -> &str {
        "Detects Value comparison that can be bypassed with extra assets"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn long_description(&self) -> &str {
        "Cardano Values are multi-asset containers. Using >= comparison or \
        assets.match with inequality comparators only verifies listed assets \
        meet minimums. Extra unexpected assets are silently accepted, enabling \
        an attacker to inject tokens or drain value."
    }

    fn cwe_id(&self) -> Option<&str> {
        Some("CWE-697")
    }

    fn category(&self) -> &str {
        "logic"
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
                    let has_value_context = signals.tx_field_accesses.contains("outputs")
                        || signals.tx_field_accesses.contains("inputs");
                    if !has_value_context {
                        continue;
                    }

                    // Check for unsafe match comparison with value operations
                    if signals.has_unsafe_match_comparison
                        && !uses_safe_value_comparison(handler)
                        && !has_safe_multi_asset_handling(&signals.function_calls)
                    {
                        findings.push(Finding {
                            detector_name: self.name().to_string(),
                            severity: self.severity(),
                            confidence: Confidence::Likely,
                            title: format!(
                                "Multi-asset comparison bypass possible in {}.{}",
                                validator.name, handler.name
                            ),
                            description: format!(
                                "Handler {}.{} uses assets.match with inequality comparator. \
                                An attacker can inject extra assets not covered by the comparison.",
                                validator.name, handler.name
                            ),
                            module: module.name.clone(),
                            location: handler
                                .location
                                .map(|(s, e)| SourceLocation::from_bytes(&module.path, s, e)),
                            suggestion: Some(
                                "Use == comparator in assets.match for exact Value matching."
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
    fn test_detects_unsafe_match() {
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
                    body_signals: BodySignals {
                        tx_field_accesses: ["outputs"].iter().map(|s| s.to_string()).collect(),
                        has_unsafe_match_comparison: true,
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
        let findings = MultiAssetComparisonBypass.detect(&modules);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn test_no_finding_without_value_context() {
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
                    body_signals: BodySignals {
                        has_unsafe_match_comparison: true,
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
        let findings = MultiAssetComparisonBypass.detect(&modules);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_no_finding_with_safe_handling() {
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
                    body_signals: BodySignals {
                        tx_field_accesses: ["outputs"].iter().map(|s| s.to_string()).collect(),
                        function_calls: ["assets.tokens"].iter().map(|s| s.to_string()).collect(),
                        has_unsafe_match_comparison: true,
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
        let findings = MultiAssetComparisonBypass.detect(&modules);
        assert!(findings.is_empty());
    }
}
