use crate::ast_walker::{ModuleInfo, ModuleKind};
use crate::detector::{Confidence, Detector, Finding, Severity, SourceLocation};

/// Detects use of list.head() or list.at() without length check.
pub struct UnsafeListHead;

impl Detector for UnsafeListHead {
    fn name(&self) -> &str {
        "unsafe-list-head"
    }

    fn description(&self) -> &str {
        "Detects use of list.head() or list.at() which crash on empty lists"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn long_description(&self) -> &str {
        "Functions like `list.head()` and `list.at()` crash at runtime when called on an \
        empty list or with an out-of-bounds index. In a validator, this causes the transaction \
        to fail. If the list comes from transaction data (e.g., inputs, outputs), an attacker \
        might craft a transaction that triggers this crash.\n\n\
        Example (vulnerable):\n  let first_output = list.head(self.outputs)\n  \
        // Crashes if outputs is empty!\n\n\
        Fix: Use pattern matching or check length first:\n  \
        expect [first_output, ..] = self.outputs"
    }

    fn cwe_id(&self) -> Option<&str> {
        Some("CWE-129")
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
                    let calls = &handler.body_signals.unsafe_list_access_calls;
                    if calls.is_empty() {
                        continue;
                    }

                    // Check if there's a length/is_empty guard
                    let has_guard = handler.body_signals.function_calls.contains("list.length")
                        || handler
                            .body_signals
                            .function_calls
                            .contains("list.is_empty")
                        || handler
                            .body_signals
                            .function_calls
                            .contains("builtin.length_of_list");

                    if has_guard {
                        continue;
                    }

                    let call_names: Vec<&str> = calls.iter().map(|s| s.as_str()).collect();
                    findings.push(Finding {
                        detector_name: self.name().to_string(),
                        severity: self.severity(),
                        confidence: Confidence::Likely,
                        title: format!(
                            "Handler {}.{} uses {} without length guard",
                            validator.name,
                            handler.name,
                            call_names.join(", ")
                        ),
                        description: format!(
                            "Calls to {} can crash at runtime on empty lists or out-of-bounds \
                            indices. No length check was detected.",
                            call_names.join(", ")
                        ),
                        module: module.name.clone(),
                        location: handler
                            .location
                            .map(|(s, e)| SourceLocation::from_bytes(&module.path, s, e)),
                        suggestion: Some(
                            "Use pattern matching (`expect [first, ..] = list`) or check list length before access."
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

    fn make_handler(unsafe_calls: Vec<String>, function_calls: HashSet<String>) -> Vec<ModuleInfo> {
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
                        unsafe_list_access_calls: unsafe_calls,
                        function_calls,
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
    fn test_detects_unsafe_list_head() {
        let modules = make_handler(vec!["list.head".to_string()], HashSet::new());
        let findings = UnsafeListHead.detect(&modules);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].title.contains("list.head"));
    }

    #[test]
    fn test_no_finding_with_length_guard() {
        let mut fns = HashSet::new();
        fns.insert("list.length".to_string());
        let modules = make_handler(vec!["list.head".to_string()], fns);
        let findings = UnsafeListHead.detect(&modules);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_no_finding_without_unsafe_calls() {
        let modules = make_handler(vec![], HashSet::new());
        let findings = UnsafeListHead.detect(&modules);
        assert!(findings.is_empty());
    }
}
