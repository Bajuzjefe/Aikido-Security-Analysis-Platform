use crate::ast_walker::{ModuleInfo, ModuleKind};
use crate::detector::{Confidence, Detector, Finding, Severity, SourceLocation};

pub struct UnboundedListIteration;

impl Detector for UnboundedListIteration {
    fn name(&self) -> &str {
        "unbounded-list-iteration"
    }

    fn description(&self) -> &str {
        "Detects direct iteration over raw transaction list fields (outputs, inputs, etc.)"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn long_description(&self) -> &str {
        "Directly iterating transaction fields like outputs, inputs, or reference_inputs with \
        list.any/map/filter can lead to excessive execution costs. A malicious transaction can \
        include many UTXOs to inflate the iteration cost, potentially exceeding the execution \
        budget.\n\n\
        Example:\n  list.any(self.outputs, fn(o) { ... })\n\n\
        Mitigation: Consider whether the iteration is bounded by other constraints, or use \
        early termination strategies."
    }

    fn cwe_id(&self) -> Option<&str> {
        Some("CWE-400")
    }

    fn category(&self) -> &str {
        "resource"
    }

    fn detect(&self, modules: &[ModuleInfo]) -> Vec<Finding> {
        let mut findings = Vec::new();

        for module in modules {
            if module.kind != ModuleKind::Validator {
                continue;
            }

            for validator in &module.validators {
                for handler in &validator.handlers {
                    if handler.body_signals.tx_list_iterations.is_empty() {
                        continue;
                    }

                    let fields: Vec<&str> = handler
                        .body_signals
                        .tx_list_iterations
                        .iter()
                        .map(|s| s.as_str())
                        .collect();

                    findings.push(Finding {
                        detector_name: self.name().to_string(),
                        severity: self.severity(),
                        confidence: Confidence::Possible,
                        title: format!(
                            "Unbounded list iteration in {}.{}",
                            validator.name, handler.name
                        ),
                        description: format!(
                            "Handler directly iterates transaction field(s) [{}] which can have unbounded length. \
                            This may lead to excessive execution costs on transactions with many UTXOs.",
                            fields.join(", ")
                        ),
                        module: module.name.clone(),
                        location: handler.location.map(|(s, e)| {
                            SourceLocation::from_bytes(&module.path, s, e)
                        }),
                        suggestion: Some(
                            "Consider filtering or limiting iteration, or validate expected list bounds."
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

    fn make_validator_module(tx_list_iterations: HashSet<String>) -> Vec<ModuleInfo> {
        vec![ModuleInfo {
            name: "test/validator".to_string(),
            path: "validator.ak".to_string(),
            kind: ModuleKind::Validator,
            validators: vec![ValidatorInfo {
                name: "test_validator".to_string(),
                params: vec![],
                handlers: vec![HandlerInfo {
                    name: "spend".to_string(),
                    params: vec![ParamInfo {
                        name: "self".to_string(),
                        type_name: "Transaction".to_string(),
                    }],
                    return_type: "Bool".to_string(),
                    location: Some((50, 150)),
                    body_signals: BodySignals {
                        tx_list_iterations,
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
    fn test_detects_unbounded_iteration() {
        let mut iters = HashSet::new();
        iters.insert("outputs".to_string());
        let modules = make_validator_module(iters);
        let findings = UnboundedListIteration.detect(&modules);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Medium);
        assert!(findings[0].description.contains("outputs"));
    }

    #[test]
    fn test_detects_multiple_fields() {
        let mut iters = HashSet::new();
        iters.insert("outputs".to_string());
        iters.insert("inputs".to_string());
        let modules = make_validator_module(iters);
        let findings = UnboundedListIteration.detect(&modules);
        assert_eq!(findings.len(), 1);
        // Description should mention both fields
        let desc = &findings[0].description;
        assert!(desc.contains("outputs") || desc.contains("inputs"));
    }

    #[test]
    fn test_no_finding_when_no_iteration() {
        let modules = make_validator_module(HashSet::new());
        let findings = UnboundedListIteration.detect(&modules);
        assert!(findings.is_empty());
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
        let findings = UnboundedListIteration.detect(&modules);
        assert!(findings.is_empty());
    }
}
