use crate::ast_walker::{ModuleInfo, ModuleKind};
use crate::detector::{Confidence, Detector, Finding, Severity, SourceLocation};

pub struct UnusedImport;

impl Detector for UnusedImport {
    fn name(&self) -> &str {
        "unused-import"
    }

    fn description(&self) -> &str {
        "Detects validators with no function calls to imported modules"
    }

    fn severity(&self) -> Severity {
        Severity::Info
    }

    fn long_description(&self) -> &str {
        "Validator handlers that don't call any library functions may have unused imports. \
        While not a security issue, unused imports add clutter and may indicate \
        incomplete implementations where expected checks were never added.\n\n\
        Fix: Remove unused imports or add the missing validation logic."
    }

    fn cwe_id(&self) -> Option<&str> {
        None
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
                    // If a handler has no function calls at all, it's suspicious
                    // (most real validators call stdlib functions)
                    if handler.body_signals.function_calls.is_empty()
                        && !handler.body_signals.var_references.is_empty()
                    {
                        findings.push(Finding {
                            detector_name: self.name().to_string(),
                            severity: self.severity(),
                            confidence: Confidence::Possible,
                            title: format!(
                                "No function calls in {}.{} — possible unused imports",
                                validator.name, handler.name
                            ),
                            description: format!(
                                "Handler '{}.{}' references variables but calls no functions. \
                                Most validators use stdlib functions (list.has, interval checks, etc). \
                                This may indicate unused imports or missing validation logic.",
                                validator.name, handler.name
                            ),
                            module: module.name.clone(),
                            location: handler
                                .location
                                .map(|(s, e)| SourceLocation::from_bytes(&module.path, s, e)),
                            suggestion: Some(
                                "Review imports and add the expected validation logic."
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

    fn make_module(
        function_calls: HashSet<String>,
        var_references: HashSet<String>,
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
                    params: vec![],
                    return_type: "Bool".to_string(),
                    location: None,
                    body_signals: BodySignals {
                        function_calls,
                        var_references,
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
    fn test_detects_no_function_calls() {
        let mut vars = HashSet::new();
        vars.insert("datum".to_string());
        let modules = make_module(HashSet::new(), vars);
        assert_eq!(UnusedImport.detect(&modules).len(), 1);
    }

    #[test]
    fn test_no_finding_with_function_calls() {
        let mut calls = HashSet::new();
        calls.insert("list.has".to_string());
        let mut vars = HashSet::new();
        vars.insert("datum".to_string());
        let modules = make_module(calls, vars);
        assert!(UnusedImport.detect(&modules).is_empty());
    }

    #[test]
    fn test_no_finding_empty_body() {
        let modules = make_module(HashSet::new(), HashSet::new());
        assert!(UnusedImport.detect(&modules).is_empty());
    }
}
