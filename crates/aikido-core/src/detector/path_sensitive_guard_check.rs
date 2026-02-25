use crate::ast_walker::{ModuleInfo, ModuleKind};
use crate::dataflow::analyze_handler_taint;
use crate::detector::{Confidence, Detector, Finding, Severity, SourceLocation};

/// Detects variables guarded on some execution paths but not others.
///
/// When a redeemer-derived variable is checked in one when branch but used
/// unchecked in another, an attacker can exploit the unchecked path.
pub struct PathSensitiveGuardCheck;

impl Detector for PathSensitiveGuardCheck {
    fn name(&self) -> &str {
        "path-sensitive-guard-check"
    }

    fn description(&self) -> &str {
        "Detects variables guarded on some paths but not others"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn long_description(&self) -> &str {
        "When a redeemer-derived variable is validated in one branch of a when expression \
        but used without validation in another branch, an attacker can craft a redeemer that \
        takes the unguarded path. This detector uses taint analysis to identify variables that \
        are partially guarded across different execution paths."
    }

    fn cwe_id(&self) -> Option<&str> {
        Some("CWE-807")
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
                    let taint = analyze_handler_taint(handler);

                    for var in &taint.partially_guarded_vars {
                        if taint.is_tainted(var) && !taint.is_sanitized(var) {
                            findings.push(Finding {
                                detector_name: self.name().to_string(),
                                severity: self.severity(),
                                confidence: Confidence::Possible,
                                title: format!(
                                    "Variable '{}' guarded on some paths but not all in {}.{}",
                                    var, validator.name, handler.name
                                ),
                                description: format!(
                                    "The redeemer-derived variable '{}' is checked in some when \
                                    branches of {}.{} but not in others. An attacker could \
                                    craft a redeemer that takes the unguarded path.",
                                    var, validator.name, handler.name
                                ),
                                module: module.name.clone(),
                                location: handler
                                    .location
                                    .map(|(s, e)| SourceLocation::from_bytes(&module.path, s, e)),
                                suggestion: Some(format!(
                                    "Ensure '{}' is validated on all execution paths, \
                                    or add a guard at the beginning of the handler.",
                                    var
                                )),
                                related_findings: vec![],
                                semantic_group: Some("taint-analysis".to_string()),

                                evidence: None,
                            });
                        }
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
    use crate::body_analysis::{BodySignals, WhenBranchInfo};

    #[test]
    fn test_no_finding_when_guarded() {
        let mut signals = BodySignals::default();
        signals.redeemer_tainted_vars.insert("amount".to_string());
        signals.guarded_vars.insert("amount".to_string());
        signals.when_branches.push(WhenBranchInfo {
            pattern_text: "Update".to_string(),
            is_catchall: false,
            body_is_literal_true: false,
            body_is_error: false,
        });

        let modules = vec![ModuleInfo {
            name: "test/v".to_string(),
            path: "v.ak".to_string(),
            kind: ModuleKind::Validator,
            validators: vec![ValidatorInfo {
                name: "pool".to_string(),
                params: vec![],
                handlers: vec![HandlerInfo {
                    name: "spend".to_string(),
                    params: vec![
                        ParamInfo {
                            name: "datum".to_string(),
                            type_name: "D".to_string(),
                        },
                        ParamInfo {
                            name: "redeemer".to_string(),
                            type_name: "R".to_string(),
                        },
                    ],
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

        let findings = PathSensitiveGuardCheck.detect(&modules);
        // The variable is both guarded and tainted — sanitized by guard, so no finding
        assert!(findings.is_empty());
    }

    #[test]
    fn test_no_finding_on_library_module() {
        let modules = vec![ModuleInfo {
            name: "lib/utils".to_string(),
            path: "utils.ak".to_string(),
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

        let findings = PathSensitiveGuardCheck.detect(&modules);
        assert!(findings.is_empty());
    }
}
