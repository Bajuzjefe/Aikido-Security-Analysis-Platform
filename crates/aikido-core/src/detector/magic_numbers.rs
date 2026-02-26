use crate::ast_walker::{ModuleInfo, ModuleKind};
use crate::detector::{Confidence, Detector, Finding, Severity, SourceLocation};

pub struct MagicNumbers;

/// Common numeric values that are NOT magic numbers.
const SAFE_VALUES: &[&str] = &[
    "0", "1", "2", "-1", "True", "False", "1000000", // 1 ADA in lovelace
];

impl Detector for MagicNumbers {
    fn name(&self) -> &str {
        "magic-numbers"
    }

    fn description(&self) -> &str {
        "Detects unexplained numeric literals in validator logic"
    }

    fn severity(&self) -> Severity {
        Severity::Info
    }

    fn long_description(&self) -> &str {
        "Numeric literals embedded directly in validator logic without named constants \
        make code harder to understand and maintain. Constants like deadline offsets, \
        fee amounts, or threshold values should be extracted to named constants or \
        validator parameters.\n\n\
        Fix: Extract numeric literals to named constants or validator parameters."
    }

    fn cwe_id(&self) -> Option<&str> {
        Some("CWE-547")
    }

    fn category(&self) -> &str {
        "configuration"
    }

    fn detect(&self, modules: &[ModuleInfo]) -> Vec<Finding> {
        let mut findings = Vec::new();

        for module in modules {
            if module.kind != ModuleKind::Validator {
                continue;
            }

            for validator in &module.validators {
                for handler in &validator.handlers {
                    // Check for large numeric literals in var_references
                    // In our signal model, numeric literals appear as var_references
                    // when they're significant values used in comparisons
                    let suspicious_numbers: Vec<&str> = handler
                        .body_signals
                        .var_references
                        .iter()
                        .filter(|v| is_magic_number(v))
                        .map(|v| v.as_str())
                        .collect();

                    for num in &suspicious_numbers {
                        findings.push(Finding {
                            detector_name: self.name().to_string(),
                            severity: self.severity(),
                            confidence: Confidence::Possible,
                            title: format!(
                                "Magic number '{}' in {}.{}",
                                num, validator.name, handler.name
                            ),
                            description: format!(
                                "Numeric literal '{num}' used directly in handler logic. \
                                Consider extracting to a named constant for clarity.",
                            ),
                            module: module.name.clone(),
                            location: handler
                                .location
                                .map(|(s, e)| SourceLocation::from_bytes(&module.path, s, e)),
                            suggestion: Some(
                                "Extract the numeric literal to a named constant or \
                                validator parameter."
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

fn is_magic_number(s: &str) -> bool {
    if SAFE_VALUES.contains(&s) {
        return false;
    }
    // Must be a pure numeric literal (possibly negative)
    let stripped = s.strip_prefix('-').unwrap_or(s);
    if !stripped.chars().all(|c| c.is_ascii_digit()) {
        return false;
    }
    // Must be a significant value (> 2 or negative)
    if let Ok(n) = s.parse::<i64>() {
        n.abs() > 2 && n != 1_000_000
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast_walker::*;
    use crate::body_analysis::BodySignals;
    use std::collections::HashSet;

    fn make_module(var_refs: HashSet<String>) -> Vec<ModuleInfo> {
        vec![ModuleInfo {
            name: "test/validator".to_string(),
            path: "validator.ak".to_string(),
            kind: ModuleKind::Validator,
            validators: vec![ValidatorInfo {
                name: "v".to_string(),
                params: vec![],
                handlers: vec![HandlerInfo {
                    name: "spend".to_string(),
                    params: vec![],
                    return_type: "Bool".to_string(),
                    location: None,
                    body_signals: BodySignals {
                        var_references: var_refs,
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
    fn test_detects_magic_number() {
        let mut refs = HashSet::new();
        refs.insert("86400".to_string());
        let modules = make_module(refs);
        assert_eq!(MagicNumbers.detect(&modules).len(), 1);
    }

    #[test]
    fn test_ignores_small_numbers() {
        let mut refs = HashSet::new();
        refs.insert("0".to_string());
        refs.insert("1".to_string());
        refs.insert("2".to_string());
        let modules = make_module(refs);
        assert!(MagicNumbers.detect(&modules).is_empty());
    }

    #[test]
    fn test_ignores_non_numeric() {
        let mut refs = HashSet::new();
        refs.insert("datum".to_string());
        refs.insert("tx".to_string());
        let modules = make_module(refs);
        assert!(MagicNumbers.detect(&modules).is_empty());
    }
}
