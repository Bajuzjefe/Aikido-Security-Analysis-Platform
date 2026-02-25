use aiken_lang::ast::BinOp;

use crate::ast_walker::{ModuleInfo, ModuleKind};
use crate::detector::{Confidence, Detector, Finding, Severity, SourceLocation};

/// Detects integer subtraction that may underflow (go negative) without a guard.
pub struct IntegerUnderflowRisk;

impl Detector for IntegerUnderflowRisk {
    fn name(&self) -> &str {
        "integer-underflow-risk"
    }

    fn description(&self) -> &str {
        "Detects integer subtraction that may produce negative values without a guard"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn long_description(&self) -> &str {
        "Integer subtraction can produce negative values which, when used as \
        token quantities or lovelace amounts, cause unexpected behavior. If the subtrahend \
        (value being subtracted) comes from redeemer or datum input, an attacker could \
        manipulate it to produce a negative result.\n\n\
        Note: Aiken uses arbitrary-precision integers (BigInt) that do not overflow or \
        underflow in the traditional sense. Negative results are valid values. The risk is \
        when a negative result is used where a positive value is expected (e.g., token \
        quantities, lovelace amounts).\n\n\
        Example (vulnerable):\n  let remaining = collateral_value - total_loss\n  \
        // If total_loss > collateral_value, remaining is negative!\n\n\
        Fix: Guard against underflow:\n  expect total_loss <= collateral_value\n  \
        let remaining = collateral_value - total_loss"
    }

    fn cwe_id(&self) -> Option<&str> {
        Some("CWE-191")
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
                    if !handler.body_signals.has_subtraction {
                        continue;
                    }

                    let signals = &handler.body_signals;

                    // Suppress when guards are present (expect x >= y, expect a > 0)
                    // and subtraction is NOT redeemer-tainted. This covers AMM/DeFi
                    // patterns where datum-derived arithmetic is guarded.
                    let has_guards = !signals.guarded_vars.is_empty();
                    let is_tainted = !signals.redeemer_tainted_vars.is_empty();

                    if has_guards && !is_tainted {
                        // Datum-only arithmetic with guards — safe pattern
                        continue;
                    }

                    // Phase 1.1: Correlated guard suppression via GuardedOperations.
                    // Pattern: `expect a >= b + constant` (or a >= b) before `a - b`.
                    // Only suppress when the guard's variable ALSO appears in the
                    // subtraction operands — this prevents unrelated guards from
                    // suppressing unrelated subtractions.
                    let has_correlated_guard = signals.guarded_operations.iter().any(|g| {
                        matches!(
                            g.guard_op,
                            BinOp::GtEqInt | BinOp::GtInt | BinOp::LtEqInt | BinOp::LtInt
                        ) && signals.subtraction_operands.contains(&g.guarded_var)
                    });

                    if has_correlated_guard {
                        continue;
                    }

                    // Higher confidence if subtraction involves redeemer-tainted values
                    let confidence = if is_tainted {
                        Confidence::Likely
                    } else {
                        Confidence::Possible
                    };

                    findings.push(Finding {
                        detector_name: self.name().to_string(),
                        severity: self.severity(),
                        confidence,
                        title: format!(
                            "Handler {}.{} contains integer subtraction that may underflow",
                            validator.name, handler.name
                        ),
                        description: format!(
                            "Handler {}.{} uses integer subtraction. If the subtrahend is \
                            derived from user input (redeemer/datum), the result could go \
                            negative, causing unexpected behavior in value calculations.",
                            validator.name, handler.name
                        ),
                        module: module.name.clone(),
                        location: handler
                            .location
                            .map(|(s, e)| SourceLocation::from_bytes(&module.path, s, e)),
                        suggestion: Some(
                            "Guard subtraction with `expect b <= a` before computing `a - b`, \
                            or use saturating arithmetic patterns."
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

    fn make_handler(has_subtraction: bool, tainted_vars: HashSet<String>) -> Vec<ModuleInfo> {
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
                        has_subtraction,
                        redeemer_tainted_vars: tainted_vars,
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
    fn test_detects_subtraction() {
        let modules = make_handler(true, HashSet::new());
        let findings = IntegerUnderflowRisk.detect(&modules);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Medium);
        assert_eq!(findings[0].confidence, Confidence::Possible);
    }

    #[test]
    fn test_no_finding_without_subtraction() {
        let modules = make_handler(false, HashSet::new());
        let findings = IntegerUnderflowRisk.detect(&modules);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_no_finding_when_guarded_and_no_taint() {
        // Datum-derived subtraction with guard (e.g., expect a >= b; a - b)
        let mut modules = make_handler(true, HashSet::new());
        modules[0].validators[0].handlers[0]
            .body_signals
            .guarded_vars
            .insert("amount".to_string());
        let findings = IntegerUnderflowRisk.detect(&modules);
        assert!(
            findings.is_empty(),
            "guarded datum-only subtraction should be suppressed"
        );
    }

    #[test]
    fn test_still_flags_when_guarded_but_tainted() {
        // Redeemer-tainted subtraction should still flag even with guards
        let mut tainted = HashSet::new();
        tainted.insert("redeemer".to_string());
        let mut modules = make_handler(true, tainted);
        modules[0].validators[0].handlers[0]
            .body_signals
            .guarded_vars
            .insert("amount".to_string());
        let findings = IntegerUnderflowRisk.detect(&modules);
        assert_eq!(
            findings.len(),
            1,
            "redeemer-tainted subtraction should still flag"
        );
    }

    #[test]
    fn test_higher_confidence_with_tainted_vars() {
        let mut tainted = HashSet::new();
        tainted.insert("redeemer".to_string());
        let modules = make_handler(true, tainted);
        let findings = IntegerUnderflowRisk.detect(&modules);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].confidence, Confidence::Likely);
    }

    #[test]
    fn test_no_finding_with_correlated_guard_operation() {
        // Pattern: `expect a >= b + 2` before `a - b` — safe, suppress
        use crate::body_analysis::GuardedOperation;
        use aiken_lang::ast::BinOp;

        let mut modules = make_handler(true, HashSet::new());
        let signals = &mut modules[0].validators[0].handlers[0].body_signals;
        signals.guarded_vars.insert("a".to_string());
        signals.guarded_vars.insert("b".to_string());
        signals.subtraction_operands.insert("a".to_string());
        signals.subtraction_operands.insert("b".to_string());
        signals.guarded_operations.push(GuardedOperation {
            guarded_var: "a".to_string(),
            guard_op: BinOp::GtEqInt,
            compared_to: Some("b".to_string()),
        });
        let findings = IntegerUnderflowRisk.detect(&modules);
        assert!(
            findings.is_empty(),
            "correlated guard operation should suppress finding"
        );
    }

    #[test]
    fn test_guard_with_complex_rhs_suppresses_when_operands_correlate() {
        // Pattern: `expect treasury >= b + c` before `treasury - amount`
        // Guard has complex RHS (compared_to: None) but guarded_var is in subtraction_operands
        use crate::body_analysis::GuardedOperation;
        use aiken_lang::ast::BinOp;

        let mut modules = make_handler(true, HashSet::new());
        let signals = &mut modules[0].validators[0].handlers[0].body_signals;
        signals.subtraction_operands.insert("treasury".to_string());
        signals.subtraction_operands.insert("amount".to_string());
        signals.guarded_operations.push(GuardedOperation {
            guarded_var: "treasury".to_string(),
            guard_op: BinOp::GtEqInt,
            compared_to: None, // complex RHS like `b + c`
        });
        let findings = IntegerUnderflowRisk.detect(&modules);
        assert!(
            findings.is_empty(),
            "guard with complex RHS should suppress when guarded_var is a subtraction operand"
        );
    }

    #[test]
    fn test_guard_does_not_suppress_when_unrelated() {
        // Pattern: guard on `order_count >= min_orders` but subtraction is `collateral - fee`
        // The guard is on a different variable than the subtraction operands → no suppression
        use crate::body_analysis::GuardedOperation;
        use aiken_lang::ast::BinOp;

        let mut modules = make_handler(true, HashSet::new());
        let signals = &mut modules[0].validators[0].handlers[0].body_signals;
        signals
            .subtraction_operands
            .insert("collateral".to_string());
        signals.subtraction_operands.insert("fee".to_string());
        signals.guarded_operations.push(GuardedOperation {
            guarded_var: "order_count".to_string(), // unrelated to subtraction
            guard_op: BinOp::GtEqInt,
            compared_to: Some("min_orders".to_string()),
        });
        let findings = IntegerUnderflowRisk.detect(&modules);
        assert_eq!(
            findings.len(),
            1,
            "unrelated guard should NOT suppress subtraction finding"
        );
    }

    #[test]
    fn test_correlated_guard_suppresses_even_when_tainted() {
        // Correlated guard + redeemer taint = suppressed, because the guard
        // (e.g., expect a >= b) prevents underflow when the guard correlates
        // with the subtraction operands.
        use crate::body_analysis::GuardedOperation;
        use aiken_lang::ast::BinOp;

        let mut tainted = HashSet::new();
        tainted.insert("redeemer".to_string());
        let mut modules = make_handler(true, tainted);
        let signals = &mut modules[0].validators[0].handlers[0].body_signals;
        signals.subtraction_operands.insert("a".to_string());
        signals.subtraction_operands.insert("b".to_string());
        signals.guarded_operations.push(GuardedOperation {
            guarded_var: "a".to_string(),
            guard_op: BinOp::GtEqInt,
            compared_to: Some("b".to_string()),
        });
        let findings = IntegerUnderflowRisk.detect(&modules);
        assert!(
            findings.is_empty(),
            "correlated guard should suppress even with tainted operands"
        );
    }

    #[test]
    fn test_tainted_arithmetic_fires_with_uncorrelated_guard() {
        // Redeemer-tainted subtraction with a guard on an unrelated variable
        // should still fire — the guard doesn't protect the subtraction.
        use crate::body_analysis::GuardedOperation;
        use aiken_lang::ast::BinOp;

        let mut tainted = HashSet::new();
        tainted.insert("redeemer".to_string());
        let mut modules = make_handler(true, tainted);
        let signals = &mut modules[0].validators[0].handlers[0].body_signals;
        signals.guarded_vars.insert("count".to_string());
        signals
            .subtraction_operands
            .insert("collateral".to_string());
        signals.subtraction_operands.insert("fee".to_string());
        signals.guarded_operations.push(GuardedOperation {
            guarded_var: "count".to_string(),
            guard_op: BinOp::GtEqInt,
            compared_to: Some("min_count".to_string()),
        });
        let findings = IntegerUnderflowRisk.detect(&modules);
        assert_eq!(
            findings.len(),
            1,
            "tainted subtraction with unrelated guard should still fire"
        );
    }
}
