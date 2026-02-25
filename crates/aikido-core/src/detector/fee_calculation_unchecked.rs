use crate::ast_walker::{ModuleInfo, ModuleKind};
use crate::detector::{Confidence, Detector, Finding, Severity, SourceLocation};

/// Detects handlers that perform subtraction (fee/deduction calculations)
/// with redeemer-tainted values without proper bounds checking.
///
/// Fee calculations commonly involve subtracting a fee amount from a total.
/// If the fee amount comes from the redeemer (attacker-controlled), the attacker
/// can set an arbitrarily large fee, potentially draining the UTXO.
pub struct FeeCalculationUnchecked;

impl Detector for FeeCalculationUnchecked {
    fn name(&self) -> &str {
        "fee-calculation-unchecked"
    }

    fn description(&self) -> &str {
        "Detects fee/deduction calculations using attacker-controlled redeemer values"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn long_description(&self) -> &str {
        "When a handler subtracts a value derived from the redeemer (e.g., a fee amount, \
        withdrawal amount, or deduction), the attacker controls the subtrahend. Without \
        proper bounds checking:\n\
        - Setting fee = total_value drains everything\n\
        - Setting fee > total_value causes underflow (Aiken integers can go negative)\n\
        - Setting fee = 0 bypasses fee collection\n\n\
        The redeemer should not be the source of truth for fee amounts. Use datum fields, \
        protocol parameters, or formula-based calculations instead.\n\n\
        Example (vulnerable):\n  let payout = datum.total - redeemer.fee_amount\n  \
        // Attacker sets fee_amount = total, drains everything!\n\n\
        Fix: Use protocol-defined fees:\n  let fee = datum.total * protocol_fee_rate / 10000"
    }

    fn cwe_id(&self) -> Option<&str> {
        Some("CWE-20")
    }

    fn category(&self) -> &str {
        "data-validation"
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

                    // Must have subtraction AND redeemer-tainted vars
                    if !signals.has_subtraction || signals.redeemer_tainted_vars.is_empty() {
                        continue;
                    }

                    // Also must access outputs (continuing UTXO / payout pattern)
                    // This filters out validators that just do math but don't produce outputs
                    if !signals.tx_field_accesses.contains("outputs") {
                        continue;
                    }

                    // Suppress when redeemer-tainted vars have corresponding guards.
                    // If a tainted variable is compared/validated before use in
                    // subtraction, the developer has verified the value.
                    let taint_guarded = signals
                        .redeemer_tainted_vars
                        .iter()
                        .any(|v| signals.guarded_vars.contains(v));
                    // Also suppress when subtraction operands are guarded
                    let subtraction_guarded = !signals.subtraction_operands.is_empty()
                        && signals
                            .subtraction_operands
                            .iter()
                            .any(|v| signals.guarded_vars.contains(v));
                    if taint_guarded || subtraction_guarded {
                        continue;
                    }

                    findings.push(Finding {
                        detector_name: self.name().to_string(),
                        severity: self.severity(),
                        confidence: Confidence::Possible,
                        title: format!(
                            "Potential unchecked fee calculation in {}.{}",
                            validator.name, handler.name
                        ),
                        description: format!(
                            "Handler {}.{} performs subtraction with redeemer-derived values \
                            and produces outputs. If the subtracted amount (fee, deduction) \
                            comes from the redeemer, an attacker can manipulate it to drain \
                            funds or bypass fee collection.",
                            validator.name, handler.name
                        ),
                        module: module.name.clone(),
                        location: handler
                            .location
                            .map(|(s, e)| SourceLocation::from_bytes(&module.path, s, e)),
                        suggestion: Some(
                            "Derive fee amounts from datum fields or protocol parameters, \
                            not from the redeemer. If redeemer-based, validate bounds: \
                            `expect redeemer.fee >= min_fee && redeemer.fee <= max_fee`."
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
        has_subtraction: bool,
        tx_accesses: HashSet<String>,
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
                        has_subtraction,
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
        }]
    }

    #[test]
    fn test_detects_tainted_subtraction_with_outputs() {
        let mut tainted = HashSet::new();
        tainted.insert("redeemer".to_string());
        let mut tx = HashSet::new();
        tx.insert("outputs".to_string());

        let modules = make_handler(tainted, true, tx);
        let findings = FeeCalculationUnchecked.detect(&modules);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Medium);
    }

    #[test]
    fn test_no_finding_without_outputs() {
        let mut tainted = HashSet::new();
        tainted.insert("redeemer".to_string());

        let modules = make_handler(tainted, true, HashSet::new());
        let findings = FeeCalculationUnchecked.detect(&modules);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_no_finding_without_subtraction() {
        let mut tainted = HashSet::new();
        tainted.insert("redeemer".to_string());
        let mut tx = HashSet::new();
        tx.insert("outputs".to_string());

        let modules = make_handler(tainted, false, tx);
        let findings = FeeCalculationUnchecked.detect(&modules);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_no_finding_without_taint() {
        let mut tx = HashSet::new();
        tx.insert("outputs".to_string());

        let modules = make_handler(HashSet::new(), true, tx);
        let findings = FeeCalculationUnchecked.detect(&modules);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_no_finding_when_tainted_var_guarded() {
        let mut tainted = HashSet::new();
        tainted.insert("payout_lovelace".to_string());
        let mut tx = HashSet::new();
        tx.insert("outputs".to_string());
        let mut guarded = HashSet::new();
        guarded.insert("payout_lovelace".to_string());

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
                        has_subtraction: true,
                        tx_field_accesses: tx,
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

        let findings = FeeCalculationUnchecked.detect(&modules);
        assert!(
            findings.is_empty(),
            "guarded tainted var should suppress fee-calculation finding"
        );
    }

    #[test]
    fn test_no_finding_when_subtraction_operand_guarded() {
        let mut tainted = HashSet::new();
        tainted.insert("redeemer".to_string());
        let mut tx = HashSet::new();
        tx.insert("outputs".to_string());
        let mut sub_operands = HashSet::new();
        sub_operands.insert("gross".to_string());
        sub_operands.insert("fee".to_string());
        let mut guarded = HashSet::new();
        guarded.insert("gross".to_string()); // subtraction operand is guarded

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
                        has_subtraction: true,
                        tx_field_accesses: tx,
                        subtraction_operands: sub_operands,
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

        let findings = FeeCalculationUnchecked.detect(&modules);
        assert!(
            findings.is_empty(),
            "guarded subtraction operand should suppress fee-calculation finding"
        );
    }
}
