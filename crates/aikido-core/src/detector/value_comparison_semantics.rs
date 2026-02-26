use crate::ast_walker::{ModuleInfo, ModuleKind};
use crate::cardano_model::uses_safe_value_comparison;
use crate::detector::{Confidence, Detector, Finding, Severity, SourceLocation};

/// Detects unsafe Value comparison patterns in Cardano validators.
///
/// Cardano Values are multi-asset containers. Common pitfalls:
/// 1. Using `lovelace_of()` to compare Values (ignores native tokens)
/// 2. Using `value.merge()` + direct BinOp comparison (bypasses multi-asset semantics)
/// 3. Using `assets.match` with `>=` comparator (only checks existing assets, misses extras)
pub struct ValueComparisonSemantics;

impl Detector for ValueComparisonSemantics {
    fn name(&self) -> &str {
        "value-comparison-semantics"
    }

    fn description(&self) -> &str {
        "Detects unsafe multi-asset Value comparison patterns"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn long_description(&self) -> &str {
        "Cardano Values contain ADA (lovelace) plus any number of native assets. \
        Using `lovelace_of()` to compare entire Values ignores native token quantities, \
        allowing an attacker to drain native assets. Similarly, using `>=` with \
        `assets.match` only verifies listed assets meet minimums but doesn't catch \
        extra unexpected assets being injected.\n\n\
        Example (vulnerable):\n  \
        // Only checks ADA, ignores native tokens:\n  \
        value.lovelace_of(output.value) >= value.lovelace_of(input.value)\n\n\
        Fix: Use proper multi-asset comparison:\n  \
        assets.match(output.value, expected_value, fn(_, a, b) { a == b })"
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

                    // Must access outputs or inputs (value comparison context)
                    let has_value_context = signals.tx_field_accesses.contains("outputs")
                        || signals.tx_field_accesses.contains("inputs");

                    if !has_value_context {
                        continue;
                    }
                    let has_safe_semantics = uses_safe_value_comparison(handler);

                    // Pattern 1: lovelace_of used for value comparison
                    // When lovelace_of is called AND subtraction/comparison exists,
                    // the handler may be ignoring native tokens
                    let uses_lovelace_of = signals
                        .function_calls
                        .iter()
                        .any(|c| c.contains("lovelace_of"));

                    let has_value_comparison = signals.has_subtraction
                        || signals.has_division
                        || signals
                            .function_calls
                            .iter()
                            .any(|c| c.contains("value.merge") || c.contains("value.negate"));

                    // Only flag if lovelace_of is used WITHOUT proper multi-asset checks
                    if uses_lovelace_of && has_value_comparison && !has_safe_semantics {
                        findings.push(Finding {
                            detector_name: self.name().to_string(),
                            severity: self.severity(),
                            confidence: Confidence::Possible,
                            title: format!(
                                "Value compared via lovelace_of in {}.{} (ignores native tokens)",
                                validator.name, handler.name
                            ),
                            description: format!(
                                "Handler {}.{} uses `lovelace_of()` for Value comparison \
                                but doesn't check native token quantities. An attacker \
                                could drain native assets while maintaining ADA amounts.",
                                validator.name, handler.name
                            ),
                            module: module.name.clone(),
                            location: handler
                                .location
                                .map(|(s, e)| SourceLocation::from_bytes(&module.path, s, e)),
                            suggestion: Some(
                                "Use `assets.match(output.value, expected, fn(_, a, b) { a == b })` \
                                or check each asset with `quantity_of` for proper multi-asset comparison."
                                    .to_string(),
                            ),
                            related_findings: vec![],
                            semantic_group: None,

                            evidence: None,
                        });
                    }

                    // Pattern 2: unsafe match comparison already tracked by
                    // has_unsafe_match_comparison — but we add context about multi-asset
                    // (this complements the existing unsafe-match-comparison detector)
                    if signals.has_unsafe_match_comparison
                        && has_value_comparison
                        && !has_safe_semantics
                    {
                        findings.push(Finding {
                            detector_name: self.name().to_string(),
                            severity: Severity::Medium,
                            confidence: Confidence::Possible,
                            title: format!(
                                "Inequality match comparator on Value in {}.{} may miss assets",
                                validator.name, handler.name
                            ),
                            description: format!(
                                "Handler {}.{} uses `assets.match` with an inequality comparator \
                                (>=, >) alongside value arithmetic. This only checks that listed \
                                assets meet minimums — extra unexpected assets in the output are \
                                silently accepted.",
                                validator.name, handler.name
                            ),
                            module: module.name.clone(),
                            location: handler
                                .location
                                .map(|(s, e)| SourceLocation::from_bytes(&module.path, s, e)),
                            suggestion: Some(
                                "Use `==` comparator in `assets.match` for exact Value matching, \
                                or explicitly check that no unexpected assets are present."
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

    fn make_handler(
        tx_accesses: &[&str],
        fn_calls: &[&str],
        has_subtraction: bool,
        has_unsafe_match: bool,
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
                        tx_field_accesses: tx_accesses.iter().map(|s| s.to_string()).collect(),
                        function_calls: fn_calls.iter().map(|s| s.to_string()).collect(),
                        has_subtraction,
                        has_unsafe_match_comparison: has_unsafe_match,
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
    fn test_detects_lovelace_only_comparison() {
        let modules = make_handler(
            &["outputs"],
            &["value.lovelace_of"],
            true,  // has subtraction (value arithmetic)
            false, // no unsafe match
        );
        let findings = ValueComparisonSemantics.detect(&modules);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].title.contains("lovelace_of"));
    }

    #[test]
    fn test_no_finding_with_quantity_of() {
        // lovelace_of used BUT also quantity_of — multi-asset properly checked
        let modules = make_handler(
            &["outputs"],
            &["value.lovelace_of", "assets.quantity_of"],
            true,
            false,
        );
        let findings = ValueComparisonSemantics.detect(&modules);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_no_finding_with_assets_match() {
        // lovelace_of used BUT also assets.match — multi-asset properly checked
        let modules = make_handler(
            &["outputs"],
            &["value.lovelace_of", "assets.match"],
            true,
            false,
        );
        let findings = ValueComparisonSemantics.detect(&modules);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_detects_unsafe_match_with_value_arithmetic() {
        let modules = make_handler(
            &["outputs"],
            &["value.merge"],
            true, // subtraction
            true, // unsafe match >=
        );
        let findings = ValueComparisonSemantics.detect(&modules);
        // Should have the inequality match finding
        assert!(
            findings.iter().any(|f| f.title.contains("Inequality")),
            "should flag unsafe match with value arithmetic"
        );
    }

    #[test]
    fn test_no_finding_without_value_context() {
        // No outputs/inputs access — no value comparison context
        let modules = make_handler(&["extra_signatories"], &["value.lovelace_of"], true, false);
        let findings = ValueComparisonSemantics.detect(&modules);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_no_finding_lovelace_of_without_arithmetic() {
        // lovelace_of but no subtraction/division — just reading, not comparing
        let modules = make_handler(&["outputs"], &["value.lovelace_of"], false, false);
        let findings = ValueComparisonSemantics.detect(&modules);
        assert!(findings.is_empty());
    }
}
