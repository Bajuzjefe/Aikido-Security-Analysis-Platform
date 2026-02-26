use crate::ast_walker::{ModuleInfo, ModuleKind};
use crate::detector::{Confidence, Detector, Finding, Severity, SourceLocation};

/// Detects potential conservation law violations (value not conserved).
pub struct InvariantViolation;

impl Detector for InvariantViolation {
    fn name(&self) -> &str {
        "invariant-violation"
    }

    fn description(&self) -> &str {
        "Detects potential value conservation violations"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn long_description(&self) -> &str {
        "Checks for handlers that manipulate values (arithmetic on amounts) without \
        verifying conservation: sum(inputs) == sum(outputs) + fees. When value arithmetic \
        is present but no equality check ties input and output values, the conservation \
        invariant may be violated."
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

                    // Must do value arithmetic AND produce outputs
                    let does_value_arithmetic = (signals.has_subtraction
                        || signals.has_multiplication)
                        && signals.function_calls.iter().any(|c| {
                            c.contains("lovelace_of")
                                || c.contains("value.merge")
                                || c.contains("value.negate")
                                || c.contains("quantity_of")
                        });
                    let produces_output = signals.tx_field_accesses.contains("outputs");

                    if !does_value_arithmetic || !produces_output {
                        continue;
                    }

                    // Check for conservation verification
                    let has_conservation = signals
                        .function_calls
                        .iter()
                        .any(|c| c.contains("assets.match") || c.contains("value.to_pairs"))
                        || signals.guarded_vars.iter().any(|v| {
                            v.contains("total") || v.contains("sum") || v.contains("balance")
                        });

                    if !has_conservation {
                        findings.push(Finding {
                            detector_name: self.name().to_string(),
                            severity: self.severity(),
                            confidence: Confidence::Possible,
                            title: format!(
                                "Value conservation not verified in {}.{}",
                                validator.name, handler.name
                            ),
                            description: format!(
                                "Handler {}.{} performs value arithmetic and produces outputs \
                                but doesn't appear to verify that total value is conserved.",
                                validator.name, handler.name
                            ),
                            module: module.name.clone(),
                            location: handler
                                .location
                                .map(|(s, e)| SourceLocation::from_bytes(&module.path, s, e)),
                            suggestion: Some(
                                "Add a check that sum(output_values) == sum(input_values) - fees."
                                    .to_string(),
                            ),
                            related_findings: vec![],
                            semantic_group: Some("invariant".to_string()),

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
    fn test_detects_missing_conservation() {
        let mut signals = BodySignals::default();
        signals.tx_field_accesses.insert("outputs".to_string());
        signals.has_subtraction = true;
        signals
            .function_calls
            .insert("value.lovelace_of".to_string());

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
        let findings = InvariantViolation.detect(&modules);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn test_no_finding_with_conservation_check() {
        let mut signals = BodySignals::default();
        signals.tx_field_accesses.insert("outputs".to_string());
        signals.has_subtraction = true;
        signals
            .function_calls
            .insert("value.lovelace_of".to_string());
        signals.function_calls.insert("assets.match".to_string());

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
        let findings = InvariantViolation.detect(&modules);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_no_finding_on_non_spend() {
        let mut signals = BodySignals::default();
        signals.tx_field_accesses.insert("outputs".to_string());
        signals.has_subtraction = true;
        signals
            .function_calls
            .insert("value.lovelace_of".to_string());

        let modules = vec![ModuleInfo {
            name: "test/v".to_string(),
            path: "v.ak".to_string(),
            kind: ModuleKind::Validator,
            validators: vec![ValidatorInfo {
                name: "pool".to_string(),
                params: vec![],
                handlers: vec![HandlerInfo {
                    name: "mint".to_string(),
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
        let findings = InvariantViolation.detect(&modules);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_no_finding_without_value_arithmetic() {
        let mut signals = BodySignals::default();
        signals.tx_field_accesses.insert("outputs".to_string());
        // No subtraction or multiplication

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
        let findings = InvariantViolation.detect(&modules);
        assert!(findings.is_empty());
    }
}
