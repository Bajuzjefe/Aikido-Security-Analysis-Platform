use crate::ast_walker::{ModuleInfo, ModuleKind};
use crate::detector::{Confidence, Detector, Finding, Severity, SourceLocation};

pub struct EmptyHandlerBody;

impl Detector for EmptyHandlerBody {
    fn name(&self) -> &str {
        "empty-handler-body"
    }

    fn description(&self) -> &str {
        "Detects handlers with no meaningful logic"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn long_description(&self) -> &str {
        "A handler that has no function calls, no variable references, no when branches, \
        and no tx field accesses is essentially empty — it either trivially succeeds or \
        fails without performing any validation. This is a strong indicator of a missing \
        implementation or a placeholder.\n\n\
        Fix: Add appropriate validation logic to the handler."
    }

    fn cwe_id(&self) -> Option<&str> {
        Some("CWE-561")
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
                    // Skip fallback handlers (else handlers are expected to be simple)
                    if handler.name == "else" {
                        continue;
                    }

                    let signals = &handler.body_signals;
                    let is_empty = signals.function_calls.is_empty()
                        && signals.var_references.is_empty()
                        && signals.when_branches.is_empty()
                        && signals.tx_field_accesses.is_empty()
                        && !signals.uses_own_ref;

                    if is_empty {
                        findings.push(Finding {
                            detector_name: self.name().to_string(),
                            severity: self.severity(),
                            confidence: Confidence::Likely,
                            title: format!(
                                "Empty handler body in {}.{}",
                                validator.name, handler.name
                            ),
                            description: format!(
                                "Handler '{}.{}' has no function calls, variable references, \
                                pattern matches, or tx field accesses. It trivially succeeds \
                                or fails without any validation.",
                                validator.name, handler.name
                            ),
                            module: module.name.clone(),
                            location: handler
                                .location
                                .map(|(s, e)| SourceLocation::from_bytes(&module.path, s, e)),
                            suggestion: Some(
                                "Add validation logic or remove the handler if unused.".to_string(),
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

    fn make_module(signals: BodySignals) -> Vec<ModuleInfo> {
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
        }]
    }

    #[test]
    fn test_detects_empty_handler() {
        let modules = make_module(BodySignals::default());
        assert_eq!(EmptyHandlerBody.detect(&modules).len(), 1);
    }

    #[test]
    fn test_no_finding_with_function_calls() {
        let mut calls = HashSet::new();
        calls.insert("list.has".to_string());
        let modules = make_module(BodySignals {
            function_calls: calls,
            ..Default::default()
        });
        assert!(EmptyHandlerBody.detect(&modules).is_empty());
    }

    #[test]
    fn test_no_finding_with_var_references() {
        let mut vars = HashSet::new();
        vars.insert("datum".to_string());
        let modules = make_module(BodySignals {
            var_references: vars,
            ..Default::default()
        });
        assert!(EmptyHandlerBody.detect(&modules).is_empty());
    }
}
