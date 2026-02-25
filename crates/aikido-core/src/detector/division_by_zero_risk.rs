use crate::ast_walker::{ModuleInfo, ModuleKind};
use crate::detector::{Confidence, Detector, Finding, Severity, SourceLocation};

/// Detects division/modulo operations where the denominator could be zero.
pub struct DivisionByZeroRisk;

impl Detector for DivisionByZeroRisk {
    fn name(&self) -> &str {
        "division-by-zero-risk"
    }

    fn description(&self) -> &str {
        "Detects division/modulo operations where the denominator could be attacker-controlled"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn long_description(&self) -> &str {
        "Division by zero in Plutus causes the validator to fail, which could be exploited \
        to deny legitimate transactions. When the denominator comes from redeemer or datum \
        input (attacker-controlled data), there's a risk of division by zero.\n\n\
        Example (vulnerable):\n  spend(datum, redeemer, own_ref, self) {\n    \
        let payout = total_value / redeemer.shares\n    // redeemer.shares could be 0!\n  }\n\n\
        Fix: Guard against zero:\n  expect redeemer.shares > 0\n  let payout = total_value / redeemer.shares"
    }

    fn cwe_id(&self) -> Option<&str> {
        Some("CWE-369")
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
                    if !handler.body_signals.has_division {
                        continue;
                    }

                    // Only suppress when the divisor itself is guarded.
                    // If we know the divisor variable, check if it's in guarded_vars.
                    // If we don't know divisor names, fall back to unguarded.
                    if !handler.body_signals.division_divisors.is_empty() {
                        let all_divisors_guarded = handler
                            .body_signals
                            .division_divisors
                            .iter()
                            .all(|d| handler.body_signals.guarded_vars.contains(d));
                        if all_divisors_guarded {
                            continue;
                        }
                    } else if !handler.body_signals.guarded_vars.is_empty() {
                        // No divisor names tracked (e.g., complex expression) but
                        // guards exist — fall back to suppressing (conservative).
                        continue;
                    }

                    findings.push(Finding {
                        detector_name: self.name().to_string(),
                        severity: self.severity(),
                        confidence: Confidence::Possible,
                        title: format!(
                            "Handler {}.{} contains division that may fail on zero",
                            validator.name, handler.name
                        ),
                        description:
                            "Division or modulo operation detected. If the denominator is \
                            derived from redeemer or datum input, an attacker could cause \
                            division by zero, failing the transaction."
                                .to_string(),
                        module: module.name.clone(),
                        location: handler
                            .location
                            .map(|(s, e)| SourceLocation::from_bytes(&module.path, s, e)),
                        suggestion: Some(
                            "Guard division with `expect denominator > 0` before the operation."
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

    fn make_handler(has_division: bool) -> Vec<ModuleInfo> {
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
                        has_division,
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
    fn test_detects_division() {
        let modules = make_handler(true);
        let findings = DivisionByZeroRisk.detect(&modules);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn test_no_finding_without_division() {
        let modules = make_handler(false);
        let findings = DivisionByZeroRisk.detect(&modules);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_no_finding_when_divisor_guarded() {
        let mut guarded = std::collections::HashSet::new();
        guarded.insert("denominator".to_string());
        let mut divisors = std::collections::HashSet::new();
        divisors.insert("denominator".to_string());

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
                    body_signals: BodySignals {
                        has_division: true,
                        guarded_vars: guarded,
                        division_divisors: divisors,
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

        let findings = DivisionByZeroRisk.detect(&modules);
        assert!(
            findings.is_empty(),
            "guarded divisor should suppress division-by-zero finding"
        );
    }

    #[test]
    fn test_finding_when_divisor_not_guarded() {
        // Guards exist for unrelated variable, but divisor is NOT guarded
        let mut guarded = std::collections::HashSet::new();
        guarded.insert("other_var".to_string());
        let mut divisors = std::collections::HashSet::new();
        divisors.insert("price".to_string());

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
                    body_signals: BodySignals {
                        has_division: true,
                        guarded_vars: guarded,
                        division_divisors: divisors,
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

        let findings = DivisionByZeroRisk.detect(&modules);
        assert_eq!(
            findings.len(),
            1,
            "unguarded divisor should still produce a finding"
        );
    }
}
