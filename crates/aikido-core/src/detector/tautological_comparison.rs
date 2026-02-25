use crate::ast_walker::{ModuleInfo, ModuleKind};
use crate::detector::{Confidence, Detector, Finding, Severity, SourceLocation};

/// Detects tautological comparisons where a value is compared to itself.
pub struct TautologicalComparison;

impl Detector for TautologicalComparison {
    fn name(&self) -> &str {
        "tautological-comparison"
    }

    fn description(&self) -> &str {
        "Detects comparisons where a value is compared to itself (always true)"
    }

    fn severity(&self) -> Severity {
        Severity::Critical
    }

    fn long_description(&self) -> &str {
        "A tautological comparison occurs when the same expression appears on both sides \
        of an equality check (e.g., `datum.field == datum.field`). This always evaluates \
        to True and indicates a copy-paste bug — the developer likely intended to compare \
        two different values. In a validator, this means the intended check is silently \
        bypassed, potentially allowing unauthorized actions.\n\n\
        Example (vulnerable):\n  expect datum.mint_policy_id == datum.mint_policy_id\n  \
        // Always True! Should be: datum.mint_policy_id == expected_policy_id\n\n\
        Fix: Compare against the correct variable or parameter."
    }

    fn cwe_id(&self) -> Option<&str> {
        Some("CWE-571")
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
                    for tautology in &handler.body_signals.tautological_comparisons {
                        findings.push(Finding {
                            detector_name: self.name().to_string(),
                            severity: self.severity(),
                            confidence: Confidence::Definite,
                            title: format!(
                                "Tautological comparison in {}.{}: {}",
                                validator.name, handler.name, tautology
                            ),
                            description: format!(
                                "Handler {}.{} compares `{}` — this is always True \
                                and likely a copy-paste bug. The intended validation \
                                is silently bypassed.",
                                validator.name, handler.name, tautology
                            ),
                            module: module.name.clone(),
                            location: handler
                                .location
                                .map(|(s, e)| SourceLocation::from_bytes(&module.path, s, e)),
                            suggestion: Some(
                                "Replace one side of the comparison with the intended variable \
                                or parameter."
                                    .to_string(),
                            ),
                            related_findings: vec![],
                            semantic_group: Some("logic".to_string()),

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

    fn make_module_with_tautologies(tautologies: Vec<String>) -> Vec<ModuleInfo> {
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
                        tautological_comparisons: tautologies,
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
    fn test_detects_tautological_comparison() {
        let modules = make_module_with_tautologies(vec![
            "datum.mint_policy_id == datum.mint_policy_id".to_string(),
        ]);
        let findings = TautologicalComparison.detect(&modules);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical);
        assert_eq!(findings[0].confidence, Confidence::Definite);
        assert!(findings[0].title.contains("Tautological"));
    }

    #[test]
    fn test_no_finding_without_tautology() {
        let modules = make_module_with_tautologies(vec![]);
        let findings = TautologicalComparison.detect(&modules);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_multiple_tautologies() {
        let modules = make_module_with_tautologies(vec![
            "datum.a == datum.a".to_string(),
            "datum.b == datum.b".to_string(),
        ]);
        let findings = TautologicalComparison.detect(&modules);
        assert_eq!(findings.len(), 2);
    }

    #[test]
    fn test_skips_lib_modules() {
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
        let findings = TautologicalComparison.detect(&modules);
        assert!(findings.is_empty());
    }
}
