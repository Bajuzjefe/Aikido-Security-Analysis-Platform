use crate::ast_walker::{ModuleInfo, ModuleKind};
use crate::detector::{Confidence, Detector, Finding, Severity, SourceLocation};

pub struct UnconstrainedRecursion;

impl Detector for UnconstrainedRecursion {
    fn name(&self) -> &str {
        "unconstrained-recursion"
    }

    fn description(&self) -> &str {
        "Detects handlers calling themselves without clear termination"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn long_description(&self) -> &str {
        "A handler or function that calls itself (directly recursive) without clear \
        base case indicators may loop indefinitely, consuming all available execution \
        budget. On Cardano, this results in a failed transaction and lost fees.\n\n\
        Fix: Ensure recursive functions have clear base cases and bounded depth."
    }

    fn cwe_id(&self) -> Option<&str> {
        Some("CWE-674")
    }

    fn category(&self) -> &str {
        "resource"
    }

    fn detect(&self, modules: &[ModuleInfo]) -> Vec<Finding> {
        let mut findings = Vec::new();

        for module in modules {
            // Skip stdlib modules — their recursive functions are well-tested
            if module.name.starts_with("aiken/")
                || module.name.starts_with("aiken_")
                || module.name.starts_with("cardano/")
            {
                continue;
            }

            // Check library functions for self-recursive calls
            for func in &module.functions {
                if let Some(ref signals) = func.body_signals {
                    // Check if function calls itself
                    if signals.function_calls.contains(&func.name)
                        || signals
                            .function_calls
                            .contains(&format!("{}.{}", module.name, func.name))
                    {
                        // Check for base case indicators:
                        // 1. when/match branches with termination patterns:
                        //    - literal True or fail/error body
                        //    - empty-list pattern `[]` (base case for list recursion)
                        //    - zero/None patterns (base case for countdown/option recursion)
                        // 2. comparison guards (if/else with >= / <= conditions)
                        // 3. expect destructure (expect [h, ..rest] = list or
                        //    expect Some(x) = y) — fails on empty, acting as base case
                        let has_when_base = !signals.when_branches.is_empty()
                            && signals.when_branches.iter().any(|b| {
                                b.body_is_literal_true
                                    || b.body_is_error
                                    // Empty-list or zero patterns are classic base cases
                                    // even if their body returns a value (e.g., `[] -> -1`)
                                    || b.pattern_text == "[]"
                                    || b.pattern_text == "0"
                                    || b.pattern_text == "None"
                                    || b.pattern_text == "Nil"
                            });
                        let has_guard_base = !signals.guarded_vars.is_empty();

                        // List traversal functions that destructure with expect [x, ..rest]
                        // have an implicit base case (crash on empty list = termination).
                        // Also: functions using expect Some(x) have implicit base case.
                        let has_expect_destructure = !signals.expect_some_vars.is_empty()
                            || signals.has_expect_list_destructure;

                        let has_base_case =
                            has_when_base || has_guard_base || has_expect_destructure;

                        if !has_base_case {
                            findings.push(Finding {
                                detector_name: self.name().to_string(),
                                severity: self.severity(),
                                confidence: Confidence::Possible,
                                title: format!(
                                    "Potentially unconstrained recursion in function '{}'",
                                    func.name
                                ),
                                description: format!(
                                    "Function '{}' calls itself but has no obvious base case \
                                    (no when/match with True or fail branches). This may cause \
                                    unbounded recursion.",
                                    func.name
                                ),
                                module: module.name.clone(),
                                location: None,
                                suggestion: Some(
                                    "Add a clear base case or use iterative constructs."
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

            // Also check validator handlers for self-references
            if module.kind != ModuleKind::Validator {
                continue;
            }

            for validator in &module.validators {
                for handler in &validator.handlers {
                    let full_name = format!("{}.{}", validator.name, handler.name);
                    if handler.body_signals.function_calls.contains(&handler.name)
                        || handler.body_signals.function_calls.contains(&full_name)
                    {
                        findings.push(Finding {
                            detector_name: self.name().to_string(),
                            severity: self.severity(),
                            confidence: Confidence::Possible,
                            title: format!(
                                "Handler {}.{} appears to call itself recursively",
                                validator.name, handler.name
                            ),
                            description: "Recursive handler calls are unusual and may \
                                indicate a logic error."
                                .to_string(),
                            module: module.name.clone(),
                            location: handler
                                .location
                                .map(|(s, e)| SourceLocation::from_bytes(&module.path, s, e)),
                            suggestion: Some(
                                "Review whether the recursive call is intentional.".to_string(),
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

    fn make_func_module(
        func_name: &str,
        calls: HashSet<String>,
        branches: Vec<crate::body_analysis::WhenBranchInfo>,
    ) -> Vec<ModuleInfo> {
        vec![ModuleInfo {
            name: "test/lib".to_string(),
            path: "lib.ak".to_string(),
            kind: ModuleKind::Lib,
            validators: vec![],
            data_types: vec![],
            functions: vec![FunctionInfo {
                name: func_name.to_string(),
                public: true,
                params: vec![],
                return_type: "Int".to_string(),
                body_signals: Some(BodySignals {
                    function_calls: calls,
                    when_branches: branches,
                    ..Default::default()
                }),
            }],
            constants: vec![],
            type_aliases: vec![],
            test_count: 0,
            source_code: None,
            test_function_names: vec![],
        }]
    }

    #[test]
    fn test_detects_self_recursive_no_base() {
        let mut calls = HashSet::new();
        calls.insert("my_func".to_string());
        let modules = make_func_module("my_func", calls, vec![]);
        assert_eq!(UnconstrainedRecursion.detect(&modules).len(), 1);
    }

    #[test]
    fn test_no_finding_with_base_case() {
        let mut calls = HashSet::new();
        calls.insert("my_func".to_string());
        let modules = make_func_module(
            "my_func",
            calls,
            vec![crate::body_analysis::WhenBranchInfo {
                pattern_text: "[]".to_string(),
                is_catchall: false,
                body_is_literal_true: true,
                body_is_error: false,
            }],
        );
        assert!(UnconstrainedRecursion.detect(&modules).is_empty());
    }

    #[test]
    fn test_no_finding_with_empty_list_base_case() {
        // when list is { [] -> -1, [h, ..rest] -> recurse(rest) }
        let mut calls = HashSet::new();
        calls.insert("count_orders".to_string());
        let modules = make_func_module(
            "count_orders",
            calls,
            vec![
                crate::body_analysis::WhenBranchInfo {
                    pattern_text: "[]".to_string(),
                    is_catchall: false,
                    body_is_literal_true: false,
                    body_is_error: false,
                },
                crate::body_analysis::WhenBranchInfo {
                    pattern_text: "[input, ..rest]".to_string(),
                    is_catchall: false,
                    body_is_literal_true: false,
                    body_is_error: false,
                },
            ],
        );
        assert!(
            UnconstrainedRecursion.detect(&modules).is_empty(),
            "[] base case should suppress finding"
        );
    }

    #[test]
    fn test_no_finding_with_expect_some_destructure() {
        // Functions using expect Some(x) = y have implicit base case
        let mut calls = HashSet::new();
        calls.insert("find_item".to_string());
        let mut modules = make_func_module("find_item", calls, vec![]);
        // Add expect_some_vars to signals
        modules[0].functions[0]
            .body_signals
            .as_mut()
            .unwrap()
            .expect_some_vars
            .insert("datum".to_string());
        assert!(
            UnconstrainedRecursion.detect(&modules).is_empty(),
            "expect Some destructure should suppress finding"
        );
    }

    #[test]
    fn test_no_finding_with_guard_vars() {
        // Functions with if idx >= N { ... } have guarded_vars
        let mut calls = HashSet::new();
        calls.insert("fast_index".to_string());
        let mut modules = make_func_module("fast_index", calls, vec![]);
        modules[0].functions[0]
            .body_signals
            .as_mut()
            .unwrap()
            .guarded_vars
            .insert("idx".to_string());
        assert!(
            UnconstrainedRecursion.detect(&modules).is_empty(),
            "guarded_vars should suppress finding"
        );
    }

    #[test]
    fn test_no_finding_with_expect_list_destructure() {
        // Functions using expect [h, ..rest] = list have implicit base case
        let mut calls = HashSet::new();
        calls.insert("do_index".to_string());
        let mut modules = make_func_module("do_index", calls, vec![]);
        modules[0].functions[0]
            .body_signals
            .as_mut()
            .unwrap()
            .has_expect_list_destructure = true;
        assert!(
            UnconstrainedRecursion.detect(&modules).is_empty(),
            "expect list destructure should suppress finding"
        );
    }

    #[test]
    fn test_no_finding_no_self_call() {
        let mut calls = HashSet::new();
        calls.insert("other_func".to_string());
        let modules = make_func_module("my_func", calls, vec![]);
        assert!(UnconstrainedRecursion.detect(&modules).is_empty());
    }
}
