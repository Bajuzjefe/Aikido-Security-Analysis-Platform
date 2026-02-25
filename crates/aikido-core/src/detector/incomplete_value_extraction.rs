use crate::ast_walker::{ModuleInfo, ModuleKind};
use crate::cardano_model::uses_partial_value_extraction;
use crate::delegation::build_delegation_set;
use crate::detector::{Confidence, Detector, Finding, Severity, SourceLocation};

/// Detects quantity_of used to validate Value but other assets unchecked.
pub struct IncompleteValueExtraction;

impl Detector for IncompleteValueExtraction {
    fn name(&self) -> &str {
        "incomplete-value-extraction"
    }

    fn description(&self) -> &str {
        "Detects partial Value checks via quantity_of that miss other assets"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn long_description(&self) -> &str {
        "Using quantity_of extracts a single asset's quantity from a Value, \
        ignoring all other assets. When used as the sole validation on an output \
        Value, other native assets are not checked and can be drained."
    }

    fn cwe_id(&self) -> Option<&str> {
        Some("CWE-697")
    }

    fn category(&self) -> &str {
        "logic"
    }

    fn detect(&self, modules: &[ModuleInfo]) -> Vec<Finding> {
        let mut findings = Vec::new();
        let delegation_set = build_delegation_set(modules);
        for module in modules {
            if module.kind != ModuleKind::Validator {
                continue;
            }
            for validator in &module.validators {
                for handler in &validator.handlers {
                    if delegation_set.contains(&(
                        module.name.clone(),
                        validator.name.clone(),
                        handler.name.clone(),
                    )) {
                        continue;
                    }
                    let signals = &handler.body_signals;
                    if !signals.tx_field_accesses.contains("outputs") {
                        continue;
                    }

                    let has_partial_extraction = uses_partial_value_extraction(handler);

                    if has_partial_extraction {
                        findings.push(Finding {
                            detector_name: self.name().to_string(),
                            severity: self.severity(),
                            confidence: Confidence::Possible,
                            title: format!(
                                "Incomplete Value check via quantity_of in {}.{}",
                                validator.name, handler.name
                            ),
                            description: format!(
                                "Handler {}.{} uses quantity_of to check specific asset \
                                quantities but doesn't validate the full Value. Other native \
                                assets may be drained.",
                                validator.name, handler.name
                            ),
                            module: module.name.clone(),
                            location: handler
                                .location
                                .map(|(s, e)| SourceLocation::from_bytes(&module.path, s, e)),
                            suggestion: Some(
                                "Complement quantity_of checks with assets.match for full \
                                Value validation."
                                    .to_string(),
                            ),
                            related_findings: vec![],
                            semantic_group: Some("cardano-semantics".to_string()),

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

    #[test]
    fn test_detects_quantity_of_only() {
        let modules = vec![ModuleInfo {
            name: "test/v".to_string(),
            path: "v.ak".to_string(),
            kind: ModuleKind::Validator,
            validators: vec![ValidatorInfo {
                name: "pool".to_string(),
                params: vec![],
                handlers: vec![HandlerInfo {
                    name: "spend".to_string(),
                    params: vec![],
                    return_type: "Bool".to_string(),
                    location: None,
                    body_signals: BodySignals {
                        tx_field_accesses: ["outputs"].iter().map(|s| s.to_string()).collect(),
                        function_calls: ["assets.quantity_of"]
                            .iter()
                            .map(|s| s.to_string())
                            .collect(),
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
        }];
        let findings = IncompleteValueExtraction.detect(&modules);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn test_no_finding_with_assets_match() {
        let modules = vec![ModuleInfo {
            name: "test/v".to_string(),
            path: "v.ak".to_string(),
            kind: ModuleKind::Validator,
            validators: vec![ValidatorInfo {
                name: "pool".to_string(),
                params: vec![],
                handlers: vec![HandlerInfo {
                    name: "spend".to_string(),
                    params: vec![],
                    return_type: "Bool".to_string(),
                    location: None,
                    body_signals: BodySignals {
                        tx_field_accesses: ["outputs"].iter().map(|s| s.to_string()).collect(),
                        function_calls: ["assets.quantity_of", "assets.match"]
                            .iter()
                            .map(|s| s.to_string())
                            .collect(),
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
        }];
        let findings = IncompleteValueExtraction.detect(&modules);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_no_finding_without_outputs() {
        let modules = vec![ModuleInfo {
            name: "test/v".to_string(),
            path: "v.ak".to_string(),
            kind: ModuleKind::Validator,
            validators: vec![ValidatorInfo {
                name: "pool".to_string(),
                params: vec![],
                handlers: vec![HandlerInfo {
                    name: "spend".to_string(),
                    params: vec![],
                    return_type: "Bool".to_string(),
                    location: None,
                    body_signals: BodySignals {
                        tx_field_accesses: ["inputs"].iter().map(|s| s.to_string()).collect(),
                        function_calls: ["assets.quantity_of"]
                            .iter()
                            .map(|s| s.to_string())
                            .collect(),
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
        }];
        let findings = IncompleteValueExtraction.detect(&modules);
        assert!(findings.is_empty());
    }
}
