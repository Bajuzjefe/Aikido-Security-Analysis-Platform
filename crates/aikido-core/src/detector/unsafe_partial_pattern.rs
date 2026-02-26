use crate::ast_walker::{ModuleInfo, ModuleKind};
use crate::detector::{Confidence, Detector, Finding, Severity, SourceLocation};

pub struct UnsafePartialPattern;

impl Detector for UnsafePartialPattern {
    fn name(&self) -> &str {
        "unsafe-partial-pattern"
    }

    fn description(&self) -> &str {
        "Detects expect patterns on non-Option types that may fail at runtime"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn long_description(&self) -> &str {
        "Using `expect` to destructure values can crash at runtime if the pattern \
        doesn't match. While `expect Some(x) = option_val` is necessary for Option types, \
        using `expect` on other types (like list destructuring or constructor matching) \
        is risky if the value doesn't always match the expected pattern.\n\n\
        This detector checks for `expect_some_vars` usage on non-Option parameters.\n\n\
        Fix: Use `when` pattern matching instead of `expect` for non-Option types."
    }

    fn cwe_id(&self) -> Option<&str> {
        Some("CWE-252")
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
                    // Look for expect_some_vars that reference non-datum parameters
                    // (datum expect Some is handled by unsafe-datum-deconstruction)
                    let datum_param = handler.params.first().map(|p| p.name.as_str());

                    for expect_var in &handler.body_signals.expect_some_vars {
                        // Skip the datum parameter — that's covered by unsafe-datum-deconstruction
                        if datum_param == Some(expect_var.as_str()) {
                            continue;
                        }

                        // Check if this variable is a redeemer-tainted value
                        if handler
                            .body_signals
                            .redeemer_tainted_vars
                            .contains(expect_var)
                        {
                            findings.push(Finding {
                                detector_name: self.name().to_string(),
                                severity: self.severity(),
                                confidence: Confidence::Possible,
                                title: format!(
                                    "Unsafe expect on redeemer-derived '{}' in {}.{}",
                                    expect_var, validator.name, handler.name
                                ),
                                description: format!(
                                    "Variable '{expect_var}' is derived from the redeemer and used in \
                                    an expect pattern. If the redeemer value doesn't match, \
                                    the transaction will fail at runtime.",
                                ),
                                module: module.name.clone(),
                                location: handler
                                    .location
                                    .map(|(s, e)| SourceLocation::from_bytes(&module.path, s, e)),
                                suggestion: Some(
                                    "Use `when` pattern matching instead of `expect` \
                                    for redeemer-derived values."
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast_walker::*;
    use crate::body_analysis::BodySignals;
    use std::collections::HashSet;

    fn make_module(
        expect_some_vars: HashSet<String>,
        redeemer_tainted: HashSet<String>,
    ) -> Vec<ModuleInfo> {
        vec![ModuleInfo {
            name: "test/validator".to_string(),
            path: "validator.ak".to_string(),
            kind: ModuleKind::Validator,
            validators: vec![ValidatorInfo {
                name: "v".to_string(),
                params: vec![],
                handlers: vec![HandlerInfo {
                    name: "spend".to_string(),
                    params: vec![ParamInfo {
                        name: "datum".to_string(),
                        type_name: "Option<MyDatum>".to_string(),
                    }],
                    return_type: "Bool".to_string(),
                    location: None,
                    body_signals: BodySignals {
                        expect_some_vars,
                        redeemer_tainted_vars: redeemer_tainted,
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
    fn test_detects_unsafe_expect_on_tainted() {
        let mut expect = HashSet::new();
        expect.insert("action_data".to_string());
        let mut tainted = HashSet::new();
        tainted.insert("action_data".to_string());
        let modules = make_module(expect, tainted);
        assert_eq!(UnsafePartialPattern.detect(&modules).len(), 1);
    }

    #[test]
    fn test_no_finding_on_datum() {
        let mut expect = HashSet::new();
        expect.insert("datum".to_string());
        let modules = make_module(expect, HashSet::new());
        assert!(UnsafePartialPattern.detect(&modules).is_empty());
    }

    #[test]
    fn test_no_finding_without_taint() {
        let mut expect = HashSet::new();
        expect.insert("some_var".to_string());
        let modules = make_module(expect, HashSet::new());
        assert!(UnsafePartialPattern.detect(&modules).is_empty());
    }
}
