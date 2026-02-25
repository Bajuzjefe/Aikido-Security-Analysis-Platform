use crate::ast_walker::{ModuleInfo, ModuleKind};
use crate::detector::{Confidence, Detector, Finding, Severity, SourceLocation};

pub struct UnsafeMatchComparison;

impl Detector for UnsafeMatchComparison {
    fn name(&self) -> &str {
        "unsafe-match-comparison"
    }

    fn description(&self) -> &str {
        "Detects unsafe use of match(..., >=) for Cardano Value comparison"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn long_description(&self) -> &str {
        "The Aiken `match` function with `>=` operator for comparing multi-asset Values can \
        hide critical issues. When asset quantities change (e.g., lending operations), `match(actual, expected, >=)` \
        only checks that Lovelace is sufficient, ignoring that native token amounts may have decreased. \
        This can allow over-lending, double-counting, or protocol insolvency.\n\n\
        Example (vulnerable):\n  expect True == match(output_pool_utxo.value, expected_pool_output.value, >=)\n\n\
        Fix: Use explicit per-asset quantity checks or `value.without_lovelace` for exact token matching."
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
                    // Check for match calls with unsafe inequality operators (>=, >, <=, <).
                    // The body_analysis extracts this from the AST: match(val, expected, >=)
                    // where the third arg is a Fn with BinOp inequality body.
                    let has_unsafe_match = handler.body_signals.has_unsafe_match_comparison;

                    // Fallback: also detect match calls without operator info
                    // (e.g., via cross-module propagation where only function_calls are merged)
                    let uses_match_no_operator =
                        !has_unsafe_match
                            && handler.body_signals.function_calls.iter().any(|c| {
                                c == "match" || c.ends_with(".match") || c == "assets.match"
                            });

                    if !has_unsafe_match && !uses_match_no_operator {
                        continue;
                    }

                    let confidence = if has_unsafe_match {
                        Confidence::Likely
                    } else {
                        // match call exists but no AST operator info — lower confidence
                        Confidence::Possible
                    };

                    findings.push(Finding {
                        detector_name: self.name().to_string(),
                        severity: self.severity(),
                        confidence,
                        title: format!(
                            "Unsafe match(..., >=) value comparison in {}.{}",
                            validator.name, handler.name
                        ),
                        description: format!(
                            "Handler {}.{} uses `match` for Value comparison. The `>=` operator \
                            only verifies Lovelace sufficiency and may miss native token imbalances, \
                            allowing over-lending or protocol insolvency.",
                            validator.name, handler.name
                        ),
                        module: module.name.clone(),
                        location: handler.location.map(|(s, e)| {
                            SourceLocation::from_bytes(&module.path, s, e)
                        }),
                        suggestion: Some(
                            "Replace `match(..., >=)` with explicit per-asset quantity checks. \
                            Use `value.without_lovelace` for exact token matching or check individual \
                            asset quantities directly."
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

    #[test]
    fn test_detects_match_comparison() {
        let mut calls = HashSet::new();
        calls.insert("match".to_string());
        let mut tx_accesses = HashSet::new();
        tx_accesses.insert("outputs".to_string());

        let modules = vec![ModuleInfo {
            name: "test/validator".to_string(),
            path: "validator.ak".to_string(),
            kind: ModuleKind::Validator,
            validators: vec![ValidatorInfo {
                name: "test_v".to_string(),
                params: vec![],
                handlers: vec![HandlerInfo {
                    name: "spend".to_string(),
                    params: vec![],
                    return_type: "Bool".to_string(),
                    location: None,
                    body_signals: BodySignals {
                        function_calls: calls,
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
        }];

        let findings = UnsafeMatchComparison.detect(&modules);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
        // function_calls-only path (no AST operator info) → Possible confidence
        assert_eq!(findings[0].confidence, Confidence::Possible);
    }

    #[test]
    fn test_detects_unsafe_match_via_ast_signal() {
        let mut tx_accesses = HashSet::new();
        tx_accesses.insert("outputs".to_string());

        let modules = vec![ModuleInfo {
            name: "test/validator".to_string(),
            path: "validator.ak".to_string(),
            kind: ModuleKind::Validator,
            validators: vec![ValidatorInfo {
                name: "test_v".to_string(),
                params: vec![],
                handlers: vec![HandlerInfo {
                    name: "spend".to_string(),
                    params: vec![],
                    return_type: "Bool".to_string(),
                    location: None,
                    body_signals: BodySignals {
                        has_unsafe_match_comparison: true,
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
        }];

        let findings = UnsafeMatchComparison.detect(&modules);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
        // AST-detected match(>=) → Likely confidence
        assert_eq!(findings[0].confidence, Confidence::Likely);
    }

    #[test]
    fn test_ast_signal_without_outputs_still_likely() {
        let modules = vec![ModuleInfo {
            name: "test/validator".to_string(),
            path: "validator.ak".to_string(),
            kind: ModuleKind::Validator,
            validators: vec![ValidatorInfo {
                name: "test_v".to_string(),
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

        let findings = UnsafeMatchComparison.detect(&modules);
        assert_eq!(findings.len(), 1);
        // AST signal alone is sufficient for Likely
        assert_eq!(findings[0].confidence, Confidence::Likely);
    }

    #[test]
    fn test_no_finding_without_match() {
        let modules = vec![ModuleInfo {
            name: "test/validator".to_string(),
            path: "validator.ak".to_string(),
            kind: ModuleKind::Validator,
            validators: vec![ValidatorInfo {
                name: "test_v".to_string(),
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

        let findings = UnsafeMatchComparison.detect(&modules);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_detects_assets_match() {
        let mut calls = HashSet::new();
        calls.insert("assets.match".to_string());

        let modules = vec![ModuleInfo {
            name: "test/validator".to_string(),
            path: "validator.ak".to_string(),
            kind: ModuleKind::Validator,
            validators: vec![ValidatorInfo {
                name: "test_v".to_string(),
                params: vec![],
                handlers: vec![HandlerInfo {
                    name: "spend".to_string(),
                    params: vec![],
                    return_type: "Bool".to_string(),
                    location: None,
                    body_signals: BodySignals {
                        function_calls: calls,
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

        let findings = UnsafeMatchComparison.detect(&modules);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].confidence, Confidence::Possible);
    }
}
