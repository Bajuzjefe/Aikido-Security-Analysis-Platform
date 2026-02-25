use crate::ast_walker::{ModuleInfo, ModuleKind};
use crate::detector::{Confidence, Detector, Finding, Severity};

pub struct UnusedValidatorParameter;

impl Detector for UnusedValidatorParameter {
    fn name(&self) -> &str {
        "unused-validator-parameter"
    }

    fn description(&self) -> &str {
        "Detects validator parameters that are never referenced in any handler"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn long_description(&self) -> &str {
        "Validator parameters (deployment-time configuration) that are never referenced \
        in any handler indicate dead configuration or missing validation logic. These \
        parameters are baked into the compiled script address, so unused params waste \
        script size and may indicate an incomplete implementation.\n\n\
        Example (vulnerable):\n  validator(oracle_pkh: ByteArray) {\n    \
        spend(datum, redeemer, own_ref, self) {\n      \
        // oracle_pkh is never used!\n      True\n    }\n  }\n\n\
        Fix: Use the parameter or remove it:\n  validator(oracle_pkh: ByteArray) {\n    \
        spend(datum, redeemer, own_ref, self) {\n      \
        let oracle = find_oracle(self.reference_inputs, oracle_pkh)\n      ...\n    }\n  }"
    }

    fn cwe_id(&self) -> Option<&str> {
        Some("CWE-561")
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
                if validator.params.is_empty() {
                    continue;
                }

                for param in &validator.params {
                    // Skip explicitly discarded params
                    if param.name.starts_with('_') {
                        continue;
                    }

                    // Check if this param is referenced in any handler's body
                    let used_in_any_handler = validator
                        .handlers
                        .iter()
                        .any(|h| h.body_signals.var_references.contains(&param.name));

                    // Also check functions in the same module (param may be captured
                    // via closure in a helper function called from the handler)
                    let used_in_module_fns = module.functions.iter().any(|f| {
                        f.body_signals
                            .as_ref()
                            .is_some_and(|bs| bs.var_references.contains(&param.name))
                    });

                    if !used_in_any_handler && !used_in_module_fns {
                        findings.push(Finding {
                            detector_name: self.name().to_string(),
                            severity: self.severity(),
                            confidence: Confidence::Likely,
                            title: format!(
                                "Unused validator parameter '{}' in {}",
                                param.name, validator.name
                            ),
                            description: format!(
                                "Validator parameter '{}' (type: {}) is never referenced in any handler. \
                                This may indicate dead configuration or missing validation logic.",
                                param.name, param.type_name
                            ),
                            module: module.name.clone(),
                            location: None,
                            suggestion: Some(format!(
                                "Use '{}' in handler logic or prefix with _ to mark as intentionally unused.",
                                param.name
                            )),
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

    fn make_validator_with_param(
        param_name: &str,
        var_references: HashSet<String>,
    ) -> Vec<ModuleInfo> {
        vec![ModuleInfo {
            name: "test/validator".to_string(),
            path: "validator.ak".to_string(),
            kind: ModuleKind::Validator,
            validators: vec![ValidatorInfo {
                name: "test_validator".to_string(),
                params: vec![ParamInfo {
                    name: param_name.to_string(),
                    type_name: "ByteArray".to_string(),
                }],
                handlers: vec![HandlerInfo {
                    name: "spend".to_string(),
                    params: vec![],
                    return_type: "Bool".to_string(),
                    location: None,
                    body_signals: BodySignals {
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
    fn test_detects_unused_param() {
        let modules = make_validator_with_param("oracle_pkh", HashSet::new());
        let findings = UnusedValidatorParameter.detect(&modules);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Medium);
        assert!(findings[0].title.contains("oracle_pkh"));
    }

    #[test]
    fn test_no_finding_when_param_used() {
        let mut refs = HashSet::new();
        refs.insert("oracle_pkh".to_string());

        let modules = make_validator_with_param("oracle_pkh", refs);
        let findings = UnusedValidatorParameter.detect(&modules);

        assert!(findings.is_empty());
    }

    #[test]
    fn test_skips_discarded_params() {
        let modules = make_validator_with_param("_unused", HashSet::new());
        let findings = UnusedValidatorParameter.detect(&modules);

        assert!(findings.is_empty());
    }

    #[test]
    fn test_no_finding_without_params() {
        let modules = vec![ModuleInfo {
            name: "test/validator".to_string(),
            path: "validator.ak".to_string(),
            kind: ModuleKind::Validator,
            validators: vec![ValidatorInfo {
                name: "test".to_string(),
                params: vec![],
                handlers: vec![],
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

        let findings = UnusedValidatorParameter.detect(&modules);
        assert!(findings.is_empty());
    }
}
