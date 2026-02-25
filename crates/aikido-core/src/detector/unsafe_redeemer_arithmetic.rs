use crate::ast_walker::{ModuleInfo, ModuleKind};
use crate::detector::{Confidence, Detector, Finding, Severity, SourceLocation};

/// Detects handlers that use redeemer-derived values in division or multiplication
/// without proper validation.
///
/// The redeemer is fully attacker-controlled. Using it directly as a divisor risks
/// division-by-zero. Using it as a multiplier risks integer overflow or precision
/// manipulation. This detector fires when both conditions are met: redeemer taint
/// exists AND division/multiplication is present.
pub struct UnsafeRedeemerArithmetic;

impl Detector for UnsafeRedeemerArithmetic {
    fn name(&self) -> &str {
        "unsafe-redeemer-arithmetic"
    }

    fn description(&self) -> &str {
        "Detects division or multiplication with attacker-controlled redeemer values"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn long_description(&self) -> &str {
        "When a handler uses redeemer-derived values directly in arithmetic operations \
        (division, multiplication, modulo), the attacker controls the operands. This enables:\n\
        - Division by zero (redeemer value = 0 as divisor)\n\
        - Precision manipulation (tiny/huge multipliers to skew calculations)\n\
        - Integer overflow in multiplication results\n\n\
        The redeemer is submitted by the transaction builder and is entirely untrusted. \
        Any arithmetic involving redeemer values should validate the operand first.\n\n\
        Example (vulnerable):\n  spend(datum, redeemer, own_ref, self) {\n    \
        let payout = datum.total_value / redeemer.num_shares\n    \
        // redeemer.num_shares could be 0!\n  }\n\n\
        Fix: Validate first:\n  expect redeemer.num_shares > 0"
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
                    let signals = &handler.body_signals;

                    // Must have redeemer-tainted variables
                    if signals.redeemer_tainted_vars.is_empty() {
                        continue;
                    }

                    // Must have division or multiplication
                    let has_risky_arithmetic = signals.has_division || signals.has_multiplication;

                    if !has_risky_arithmetic {
                        continue;
                    }

                    // Suppress when guards correlate with tainted/divisor variables.
                    // Check: redeemer tainted vars or division divisors are guarded.
                    let taint_guarded = signals
                        .redeemer_tainted_vars
                        .iter()
                        .any(|v| signals.guarded_vars.contains(v));
                    let divisor_guarded = !signals.division_divisors.is_empty()
                        && signals
                            .division_divisors
                            .iter()
                            .all(|d| signals.guarded_vars.contains(d));
                    if taint_guarded || divisor_guarded {
                        continue;
                    }

                    let ops = match (signals.has_division, signals.has_multiplication) {
                        (true, true) => "division and multiplication",
                        (true, false) => "division",
                        (false, true) => "multiplication",
                        _ => unreachable!(),
                    };

                    findings.push(Finding {
                        detector_name: self.name().to_string(),
                        severity: self.severity(),
                        confidence: Confidence::Likely,
                        title: format!(
                            "Redeemer-tainted arithmetic in {}.{}",
                            validator.name, handler.name
                        ),
                        description: format!(
                            "Handler {}.{} uses {ops} with redeemer-derived variables \
                            (tainted: [{}]). The redeemer is attacker-controlled — using it \
                            directly in arithmetic risks division-by-zero, overflow, or \
                            precision manipulation.",
                            validator.name,
                            handler.name,
                            signals
                                .redeemer_tainted_vars
                                .iter()
                                .take(5)
                                .cloned()
                                .collect::<Vec<_>>()
                                .join(", ")
                        ),
                        module: module.name.clone(),
                        location: handler
                            .location
                            .map(|(s, e)| SourceLocation::from_bytes(&module.path, s, e)),
                        suggestion: Some(
                            "Validate redeemer values before arithmetic: \
                            `expect redeemer.value > 0` or use datum-sourced values instead."
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

    fn make_handler(
        tainted: HashSet<String>,
        has_division: bool,
        has_multiplication: bool,
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
                        redeemer_tainted_vars: tainted,
                        has_division,
                        has_multiplication,
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
    fn test_detects_tainted_division() {
        let mut tainted = HashSet::new();
        tainted.insert("redeemer".to_string());
        let modules = make_handler(tainted, true, false);
        let findings = UnsafeRedeemerArithmetic.detect(&modules);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
        assert!(findings[0].description.contains("division"));
    }

    #[test]
    fn test_detects_tainted_multiplication() {
        let mut tainted = HashSet::new();
        tainted.insert("action".to_string());
        let modules = make_handler(tainted, false, true);
        let findings = UnsafeRedeemerArithmetic.detect(&modules);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].description.contains("multiplication"));
    }

    #[test]
    fn test_detects_tainted_both() {
        let mut tainted = HashSet::new();
        tainted.insert("redeemer".to_string());
        let modules = make_handler(tainted, true, true);
        let findings = UnsafeRedeemerArithmetic.detect(&modules);
        assert_eq!(findings.len(), 1);
        assert!(findings[0]
            .description
            .contains("division and multiplication"));
    }

    #[test]
    fn test_no_finding_without_taint() {
        let modules = make_handler(HashSet::new(), true, true);
        let findings = UnsafeRedeemerArithmetic.detect(&modules);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_no_finding_without_arithmetic() {
        let mut tainted = HashSet::new();
        tainted.insert("redeemer".to_string());
        let modules = make_handler(tainted, false, false);
        let findings = UnsafeRedeemerArithmetic.detect(&modules);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_no_finding_when_tainted_var_guarded() {
        let mut tainted = HashSet::new();
        tainted.insert("price".to_string());

        let mut guarded = HashSet::new();
        guarded.insert("price".to_string()); // tainted var is guarded

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
                        redeemer_tainted_vars: tainted,
                        has_division: true,
                        guarded_vars: guarded,
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

        let findings = UnsafeRedeemerArithmetic.detect(&modules);
        assert!(
            findings.is_empty(),
            "guarded tainted var should suppress finding"
        );
    }
}
