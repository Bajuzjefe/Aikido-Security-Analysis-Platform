use crate::ast_walker::{ModuleInfo, ModuleKind};
use crate::detector::{Confidence, Detector, Finding, Severity, SourceLocation};

/// Detects handlers with both integer division and multiplication, which
/// risks precision loss due to truncation.
///
/// In Cardano smart contracts, all arithmetic is integer-based. Division
/// truncates (rounds toward zero), so `(a / b) * c` can lose significant
/// value compared to `(a * c) / b`. This is a common source of rounding
/// errors in DeFi protocols handling token swaps, LP calculations, and
/// fee computations.
pub struct RoundingErrorRisk;

impl Detector for RoundingErrorRisk {
    fn name(&self) -> &str {
        "rounding-error-risk"
    }

    fn description(&self) -> &str {
        "Detects handlers with integer division and multiplication that risk precision loss"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn long_description(&self) -> &str {
        "Integer division in Aiken truncates toward zero. When a handler performs both \
        division and multiplication, the order of operations matters critically:\n\
        - `(a / b) * c` loses precision (truncation then scaling)\n\
        - `(a * c) / b` preserves precision (scaling then truncation)\n\n\
        DeFi protocols (DEXs, lending, perpetuals) are especially vulnerable since even \
        small rounding errors in swap rates, LP token calculations, or interest \
        accumulation can be exploited across many transactions.\n\n\
        Example (vulnerable):\n  let share = total_value / total_shares\n  \
        let payout = share * user_shares  // Lost precision!\n\n\
        Fix: Multiply first:\n  let payout = total_value * user_shares / total_shares"
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

                    // Must have both division and multiplication
                    if !signals.has_division || !signals.has_multiplication {
                        continue;
                    }

                    // Suppress when handler delegates all logic to a withdrawal script.
                    // The withdrawal handler performs its own arithmetic validation.
                    if signals.tx_field_accesses.contains("withdrawals")
                        && signals
                            .function_calls
                            .iter()
                            .any(|c| c.contains("has_key") || c.contains("is_withdrawal"))
                    {
                        continue;
                    }

                    findings.push(Finding {
                        detector_name: self.name().to_string(),
                        severity: self.severity(),
                        confidence: Confidence::Possible,
                        title: format!(
                            "Potential rounding error in {}.{}",
                            validator.name, handler.name
                        ),
                        description: format!(
                            "Handler {}.{} contains both integer division and multiplication. \
                            Integer division truncates, so `(a / b) * c` loses precision \
                            compared to `(a * c) / b`. Verify the order of operations \
                            preserves maximum precision.",
                            validator.name, handler.name
                        ),
                        module: module.name.clone(),
                        location: handler
                            .location
                            .map(|(s, e)| SourceLocation::from_bytes(&module.path, s, e)),
                        suggestion: Some(
                            "Reorder operations to multiply before dividing: \
                            `a * c / b` instead of `a / b * c`. For complex formulas, \
                            consider using a common denominator approach."
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

    fn make_handler(has_division: bool, has_multiplication: bool) -> Vec<ModuleInfo> {
        make_handler_with_signals(has_division, has_multiplication, BodySignals::default())
    }

    fn make_handler_with_signals(
        has_division: bool,
        has_multiplication: bool,
        mut extra_signals: BodySignals,
    ) -> Vec<ModuleInfo> {
        extra_signals.has_division = has_division;
        extra_signals.has_multiplication = has_multiplication;
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
                    body_signals: extra_signals,
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
    fn test_detects_div_and_mult() {
        let modules = make_handler(true, true);
        let findings = RoundingErrorRisk.detect(&modules);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Medium);
        assert!(findings[0].title.contains("rounding error"));
    }

    #[test]
    fn test_no_finding_division_only() {
        let modules = make_handler(true, false);
        let findings = RoundingErrorRisk.detect(&modules);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_no_finding_multiplication_only() {
        let modules = make_handler(false, true);
        let findings = RoundingErrorRisk.detect(&modules);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_no_finding_neither() {
        let modules = make_handler(false, false);
        let findings = RoundingErrorRisk.detect(&modules);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_no_finding_with_withdrawal_delegation() {
        let mut signals = BodySignals::default();
        signals.tx_field_accesses.insert("withdrawals".to_string());
        signals.function_calls.insert("pairs.has_key".to_string());
        let modules = make_handler_with_signals(true, true, signals);
        let findings = RoundingErrorRisk.detect(&modules);
        assert!(
            findings.is_empty(),
            "withdrawal delegation should suppress rounding error finding"
        );
    }

    #[test]
    fn test_no_finding_on_lib_module() {
        let modules = vec![ModuleInfo {
            name: "test/lib".to_string(),
            path: "lib.ak".to_string(),
            kind: ModuleKind::Lib,
            validators: vec![],
            data_types: vec![],
            functions: vec![],
            constants: vec![],
            type_aliases: vec![],
            test_count: 0,
            source_code: None,
            test_function_names: vec![],
        }];
        let findings = RoundingErrorRisk.detect(&modules);
        assert!(findings.is_empty());
    }
}
