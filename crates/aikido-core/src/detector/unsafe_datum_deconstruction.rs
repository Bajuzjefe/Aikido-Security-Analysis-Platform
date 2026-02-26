use crate::ast_walker::{ModuleInfo, ModuleKind};
use crate::detector::{Confidence, Detector, Finding, Severity, SourceLocation};

pub struct UnsafeDatumDeconstruction;

impl Detector for UnsafeDatumDeconstruction {
    fn name(&self) -> &str {
        "unsafe-datum-deconstruction"
    }

    fn description(&self) -> &str {
        "Detects spend handlers with Option<T> datum that never use `expect Some(x) = datum`"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn long_description(&self) -> &str {
        "In Plutus V3, spend handler datums are `Option<T>`. If a handler receives an \
        `Option<T>` datum but never safely deconstructs it with `expect Some(datum) = datum_opt`, \
        accessing the datum directly may cause a runtime error if the UTXO has no inline datum.\n\n\
        Example (vulnerable):\n  spend(datum_opt: Option<Datum>, ..) {\n    \
        // datum_opt used without expect Some\n  }\n\n\
        Fix: `expect Some(datum) = datum_opt` at the start of the handler."
    }

    fn cwe_id(&self) -> Option<&str> {
        Some("CWE-252")
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
                    if handler.name != "spend" {
                        continue;
                    }

                    // First param is the datum — check if it's Option<T>
                    let Some(datum_param) = handler.params.first() else {
                        continue;
                    };

                    if !datum_param.type_name.starts_with("Option<") {
                        continue;
                    }

                    // Check if the handler ever does `expect Some(x) = datum_var`
                    let datum_name = &datum_param.name;
                    if datum_name.starts_with('_') {
                        // Explicitly discarded — not a concern
                        continue;
                    }

                    // Direct deconstruction: `expect Some(x) = datum_name`
                    let direct_expect = handler.body_signals.expect_some_vars.contains(datum_name);

                    if !direct_expect {
                        findings.push(Finding {
                            detector_name: self.name().to_string(),
                            severity: self.severity(),
                            confidence: Confidence::Likely,
                            title: format!(
                                "Unsafe Option datum deconstruction in {}.{}",
                                validator.name, handler.name
                            ),
                            description: format!(
                                "Datum parameter '{datum_name}' is Option<T> but handler never uses `expect Some(..) = {datum_name}`. \
                                Accessing the datum without safe deconstruction may cause runtime errors.",
                            ),
                            module: module.name.clone(),
                            location: handler.location.map(|(s, e)| {
                                SourceLocation::from_bytes(&module.path, s, e)
                            }),
                            suggestion: Some(
                                "Use `expect Some(datum) = datum_opt` to safely deconstruct the Optional datum."
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
    use std::collections::HashSet;

    fn make_spend_module(
        datum_type: &str,
        datum_name: &str,
        expect_some_vars: HashSet<String>,
    ) -> Vec<ModuleInfo> {
        vec![ModuleInfo {
            name: "test/validator".to_string(),
            path: "validator.ak".to_string(),
            kind: ModuleKind::Validator,
            validators: vec![ValidatorInfo {
                name: "test_validator".to_string(),
                params: vec![],
                handlers: vec![HandlerInfo {
                    name: "spend".to_string(),
                    params: vec![
                        ParamInfo {
                            name: datum_name.to_string(),
                            type_name: datum_type.to_string(),
                        },
                        ParamInfo {
                            name: "redeemer".to_string(),
                            type_name: "Redeemer".to_string(),
                        },
                        ParamInfo {
                            name: "own_ref".to_string(),
                            type_name: "OutputReference".to_string(),
                        },
                        ParamInfo {
                            name: "self".to_string(),
                            type_name: "Transaction".to_string(),
                        },
                    ],
                    return_type: "Bool".to_string(),
                    location: Some((100, 200)),
                    body_signals: BodySignals {
                        expect_some_vars,
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
    fn test_detects_unsafe_option_datum() {
        let modules = make_spend_module("Option<Datum>", "datum_opt", HashSet::new());
        let findings = UnsafeDatumDeconstruction.detect(&modules);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
        assert!(findings[0].title.contains("Unsafe Option datum"));
    }

    #[test]
    fn test_no_finding_when_expect_some_used() {
        let mut vars = HashSet::new();
        vars.insert("datum_opt".to_string());
        let modules = make_spend_module("Option<Datum>", "datum_opt", vars);
        let findings = UnsafeDatumDeconstruction.detect(&modules);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_no_finding_for_non_option_datum() {
        let modules = make_spend_module("PositionDatum", "datum", HashSet::new());
        let findings = UnsafeDatumDeconstruction.detect(&modules);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_no_finding_when_datum_discarded() {
        let modules = make_spend_module("Option<Datum>", "_datum", HashSet::new());
        let findings = UnsafeDatumDeconstruction.detect(&modules);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_finding_when_only_indirect_expect() {
        // Indirect expect (helper does expect Some on a different var name) should NOT suppress.
        // Only direct expect on the exact datum param name suppresses.
        let mut expect_vars = HashSet::new();
        expect_vars.insert("maybe_datum".to_string()); // from merged helper — different name

        let mut modules = make_spend_module("Option<Datum>", "datum_opt", expect_vars);
        modules[0].validators[0].handlers[0]
            .body_signals
            .var_references
            .insert("datum_opt".to_string());

        let findings = UnsafeDatumDeconstruction.detect(&modules);
        assert_eq!(
            findings.len(),
            1,
            "Indirect expect on different var name should not suppress finding"
        );
    }

    #[test]
    fn test_skips_non_spend_handlers() {
        let modules = vec![ModuleInfo {
            name: "test/validator".to_string(),
            path: "validator.ak".to_string(),
            kind: ModuleKind::Validator,
            validators: vec![ValidatorInfo {
                name: "test_validator".to_string(),
                params: vec![],
                handlers: vec![HandlerInfo {
                    name: "mint".to_string(),
                    params: vec![
                        ParamInfo {
                            name: "redeemer".to_string(),
                            type_name: "Option<Redeemer>".to_string(),
                        },
                        ParamInfo {
                            name: "self".to_string(),
                            type_name: "Transaction".to_string(),
                        },
                    ],
                    return_type: "Bool".to_string(),
                    location: None,
                    body_signals: BodySignals::default(),
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

        let findings = UnsafeDatumDeconstruction.detect(&modules);
        assert!(findings.is_empty());
    }
}
