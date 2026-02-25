use std::collections::HashSet;

use crate::ast_walker::{ModuleInfo, ModuleKind};
use crate::detector::{Confidence, Detector, Finding, Severity, SourceLocation};

/// Check if `word` appears in `text` as a whole word (not as a substring of
/// another identifier). Characters adjacent to the match must be non-alphanumeric
/// and not underscore to count as a word boundary.
fn contains_as_word(text: &str, word: &str) -> bool {
    for (i, _) in text.match_indices(word) {
        let before_ok = if i > 0 {
            let ch = text.as_bytes()[i - 1];
            !ch.is_ascii_alphanumeric() && ch != b'_'
        } else {
            true
        };
        let after_idx = i + word.len();
        let after_ok = if after_idx < text.len() {
            let ch = text.as_bytes()[after_idx];
            !ch.is_ascii_alphanumeric() && ch != b'_'
        } else {
            true
        };
        if before_ok && after_ok {
            return true;
        }
    }
    false
}

pub struct ShadowedVariable;

impl Detector for ShadowedVariable {
    fn name(&self) -> &str {
        "shadowed-variable"
    }

    fn description(&self) -> &str {
        "Detects handler parameters shadowed by when/match pattern bindings"
    }

    fn severity(&self) -> Severity {
        Severity::Info
    }

    fn long_description(&self) -> &str {
        "When a when/match pattern binding uses the same name as a handler parameter, \
        the parameter is shadowed within that branch. This can lead to confusion and bugs \
        where the developer intends to reference the outer parameter but accidentally \
        uses the pattern-bound value.\n\n\
        Fix: Use distinct names for pattern bindings."
    }

    fn cwe_id(&self) -> Option<&str> {
        Some("CWE-1078")
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
                    let param_names: HashSet<&str> = handler
                        .params
                        .iter()
                        .filter(|p| !p.name.starts_with('_'))
                        .map(|p| p.name.as_str())
                        .collect();

                    if param_names.is_empty() {
                        continue;
                    }

                    // Check when branch pattern texts for parameter names
                    for branch in &handler.body_signals.when_branches {
                        for param_name in &param_names {
                            // Pattern text might contain the param name as a binding
                            // e.g., "Close { datum }" would shadow the datum parameter.
                            // Use word boundary matching to avoid false positives from
                            // short param names like 'r' matching inside 'CreatePool'.
                            if contains_as_word(&branch.pattern_text, param_name)
                                && !branch.is_catchall
                                && branch.pattern_text != *param_name
                            {
                                findings.push(Finding {
                                    detector_name: self.name().to_string(),
                                    severity: self.severity(),
                                    confidence: Confidence::Possible,
                                    title: format!(
                                        "Parameter '{}' may be shadowed in branch '{}' of {}.{}",
                                        param_name,
                                        branch.pattern_text,
                                        validator.name,
                                        handler.name
                                    ),
                                    description: format!(
                                        "Pattern '{}' may shadow handler parameter '{}'. \
                                        This can cause confusion about which value is being used.",
                                        branch.pattern_text, param_name
                                    ),
                                    module: module.name.clone(),
                                    location: handler.location.map(|(s, e)| {
                                        SourceLocation::from_bytes(&module.path, s, e)
                                    }),
                                    suggestion: Some(format!(
                                        "Use a different name for the pattern binding to avoid \
                                        shadowing '{param_name}'."
                                    )),
                                    related_findings: vec![],
                                    semantic_group: None,

                                    evidence: None,
                                });
                            }
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

    fn make_module(params: Vec<ParamInfo>, branches: Vec<WhenBranchInfo>) -> Vec<ModuleInfo> {
        vec![ModuleInfo {
            name: "test/validator".to_string(),
            path: "validator.ak".to_string(),
            kind: ModuleKind::Validator,
            validators: vec![ValidatorInfo {
                name: "v".to_string(),
                params: vec![],
                handlers: vec![HandlerInfo {
                    name: "spend".to_string(),
                    params,
                    return_type: "Bool".to_string(),
                    location: None,
                    body_signals: BodySignals {
                        when_branches: branches,
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
    fn test_detects_shadowed_param() {
        let modules = make_module(
            vec![ParamInfo {
                name: "datum".to_string(),
                type_name: "MyDatum".to_string(),
            }],
            vec![WhenBranchInfo {
                pattern_text: "Close { datum }".to_string(),
                is_catchall: false,
                body_is_literal_true: false,
                body_is_error: false,
            }],
        );
        assert_eq!(ShadowedVariable.detect(&modules).len(), 1);
    }

    #[test]
    fn test_no_finding_different_names() {
        let modules = make_module(
            vec![ParamInfo {
                name: "datum".to_string(),
                type_name: "MyDatum".to_string(),
            }],
            vec![WhenBranchInfo {
                pattern_text: "Close { value }".to_string(),
                is_catchall: false,
                body_is_literal_true: false,
                body_is_error: false,
            }],
        );
        assert!(ShadowedVariable.detect(&modules).is_empty());
    }

    #[test]
    fn test_skips_discarded_params() {
        let modules = make_module(
            vec![ParamInfo {
                name: "_datum".to_string(),
                type_name: "MyDatum".to_string(),
            }],
            vec![WhenBranchInfo {
                pattern_text: "Close { _datum }".to_string(),
                is_catchall: false,
                body_is_literal_true: false,
                body_is_error: false,
            }],
        );
        assert!(ShadowedVariable.detect(&modules).is_empty());
    }

    #[test]
    fn test_no_false_positive_short_param_in_constructor() {
        // Param "r" should NOT match inside "CreatePool" — word boundary check
        let modules = make_module(
            vec![ParamInfo {
                name: "r".to_string(),
                type_name: "Redeemer".to_string(),
            }],
            vec![WhenBranchInfo {
                pattern_text: "CreatePool".to_string(),
                is_catchall: false,
                body_is_literal_true: false,
                body_is_error: false,
            }],
        );
        assert!(
            ShadowedVariable.detect(&modules).is_empty(),
            "short param 'r' inside 'CreatePool' should not trigger shadowing"
        );
    }

    #[test]
    fn test_word_boundary_helper() {
        assert!(contains_as_word("Close { datum }", "datum"));
        assert!(contains_as_word("datum", "datum"));
        assert!(!contains_as_word("CreatePool", "r"));
        assert!(!contains_as_word("BurnPool", "r"));
        assert!(contains_as_word("Close { r }", "r"));
        assert!(contains_as_word("Close(r)", "r"));
        assert!(!contains_as_word("ordered", "r"));
    }
}
