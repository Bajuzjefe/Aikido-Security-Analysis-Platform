use crate::ast_walker::{ModuleInfo, ModuleKind};
use crate::detector::{Confidence, Detector, Finding, Severity, SourceLocation};

/// Detects when/match on redeemer that doesn't cover all constructors.
pub struct NonExhaustiveRedeemer;

impl Detector for NonExhaustiveRedeemer {
    fn name(&self) -> &str {
        "non-exhaustive-redeemer"
    }

    fn description(&self) -> &str {
        "Detects redeemer pattern matches that may not cover all constructors"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn long_description(&self) -> &str {
        "When a handler uses `when` on the redeemer, all constructors of the redeemer type \
        should be explicitly handled. A catch-all `_` branch that returns True or does nothing \
        useful may indicate missing redeemer validation. This detector flags handlers where the \
        redeemer has a named type with constructors but the when branches don't cover them all \
        and fall through to a catch-all.\n\n\
        Example (vulnerable):\n  spend(datum, redeemer, own_ref, self) {\n    \
        when redeemer is {\n      Withdraw -> check_withdraw()\n      \
        _ -> True  // Missing: Update, Close, etc.\n    }\n  }\n\n\
        Fix: Handle all redeemer constructors explicitly."
    }

    fn cwe_id(&self) -> Option<&str> {
        Some("CWE-478")
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

            // Collect redeemer type definitions from this module and lib modules
            for validator in &module.validators {
                for handler in &validator.handlers {
                    let signals = &handler.body_signals;

                    // Need at least some when branches
                    if signals.when_branches.is_empty() {
                        continue;
                    }

                    // Check for catch-all that returns True (already caught by missing-redeemer-validation)
                    // This detector looks for named branches + catch-all where named branches
                    // don't cover the type's constructors
                    let has_catchall = signals.when_branches.iter().any(|b| b.is_catchall);
                    let named_branches: Vec<&str> = signals
                        .when_branches
                        .iter()
                        .filter(|b| !b.is_catchall)
                        .map(|b| b.pattern_text.as_str())
                        .collect();

                    if !has_catchall || named_branches.is_empty() {
                        continue;
                    }

                    // Look for redeemer param to find its type
                    let redeemer_param = handler.params.iter().find(|p| {
                        let lower = p.name.to_lowercase();
                        lower == "redeemer" || lower.contains("action") || lower.contains("rdmr")
                    });

                    if let Some(param) = redeemer_param {
                        let redeemer_type = crate::detector::type_base_name(&param.type_name);

                        // Find the type's constructors across all modules
                        let constructor_count = find_constructor_count(modules, redeemer_type);

                        if constructor_count > 0 && named_branches.len() < constructor_count {
                            findings.push(Finding {
                                detector_name: self.name().to_string(),
                                severity: self.severity(),
                                confidence: Confidence::Likely,
                                title: format!(
                                    "Handler {}.{} doesn't cover all {} redeemer constructors ({}/{})",
                                    validator.name,
                                    handler.name,
                                    redeemer_type,
                                    named_branches.len(),
                                    constructor_count
                                ),
                                description: format!(
                                    "Redeemer type '{}' has {} constructors but only {} are explicitly \
                                    handled. The remaining constructors fall through to a catch-all branch.",
                                    redeemer_type,
                                    constructor_count,
                                    named_branches.len()
                                ),
                                module: module.name.clone(),
                                location: handler
                                    .location
                                    .map(|(s, e)| SourceLocation::from_bytes(&module.path, s, e)),
                                suggestion: Some(
                                    "Handle all redeemer constructors explicitly instead of using a catch-all."
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
        }

        findings
    }
}

fn find_constructor_count(modules: &[ModuleInfo], type_name: &str) -> usize {
    for module in modules {
        for dt in &module.data_types {
            if dt.name == type_name {
                return dt.constructors.len();
            }
        }
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast_walker::*;
    use crate::body_analysis::{BodySignals, WhenBranchInfo};

    fn make_modules(
        branches: Vec<WhenBranchInfo>,
        redeemer_type: &str,
        constructors: Vec<ConstructorInfo>,
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
                    params: vec![
                        ParamInfo {
                            name: "datum".to_string(),
                            type_name: "Datum".to_string(),
                        },
                        ParamInfo {
                            name: "redeemer".to_string(),
                            type_name: redeemer_type.to_string(),
                        },
                    ],
                    return_type: "Bool".to_string(),
                    location: None,
                    body_signals: BodySignals {
                        when_branches: branches,
                        ..Default::default()
                    },
                }],
                summary: None,
            }],
            data_types: vec![DataTypeInfo {
                name: redeemer_type.to_string(),
                public: true,
                constructors,
            }],
            functions: vec![],
            constants: vec![],
            type_aliases: vec![],
            test_count: 0,
            source_code: None,
            test_function_names: vec![],
        }]
    }

    #[test]
    fn test_detects_non_exhaustive() {
        let branches = vec![
            WhenBranchInfo {
                pattern_text: "Withdraw".to_string(),
                is_catchall: false,
                body_is_literal_true: false,
                body_is_error: false,
            },
            WhenBranchInfo {
                pattern_text: "_".to_string(),
                is_catchall: true,
                body_is_literal_true: true,
                body_is_error: false,
            },
        ];
        let constructors = vec![
            ConstructorInfo {
                name: "Withdraw".to_string(),
                fields: vec![],
            },
            ConstructorInfo {
                name: "Update".to_string(),
                fields: vec![],
            },
            ConstructorInfo {
                name: "Close".to_string(),
                fields: vec![],
            },
        ];
        let modules = make_modules(branches, "Action", constructors);
        let findings = NonExhaustiveRedeemer.detect(&modules);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].title.contains("1/3"));
    }

    #[test]
    fn test_no_finding_when_all_covered() {
        let branches = vec![
            WhenBranchInfo {
                pattern_text: "Withdraw".to_string(),
                is_catchall: false,
                body_is_literal_true: false,
                body_is_error: false,
            },
            WhenBranchInfo {
                pattern_text: "Update".to_string(),
                is_catchall: false,
                body_is_literal_true: false,
                body_is_error: false,
            },
            WhenBranchInfo {
                pattern_text: "_".to_string(),
                is_catchall: true,
                body_is_literal_true: false,
                body_is_error: true,
            },
        ];
        let constructors = vec![
            ConstructorInfo {
                name: "Withdraw".to_string(),
                fields: vec![],
            },
            ConstructorInfo {
                name: "Update".to_string(),
                fields: vec![],
            },
        ];
        let modules = make_modules(branches, "Action", constructors);
        let findings = NonExhaustiveRedeemer.detect(&modules);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_no_finding_without_catchall() {
        let branches = vec![WhenBranchInfo {
            pattern_text: "Withdraw".to_string(),
            is_catchall: false,
            body_is_literal_true: false,
            body_is_error: false,
        }];
        let constructors = vec![
            ConstructorInfo {
                name: "Withdraw".to_string(),
                fields: vec![],
            },
            ConstructorInfo {
                name: "Update".to_string(),
                fields: vec![],
            },
        ];
        let modules = make_modules(branches, "Action", constructors);
        let findings = NonExhaustiveRedeemer.detect(&modules);
        // No catchall → Aiken compiler likely handles it, not our concern
        assert!(findings.is_empty());
    }
}
