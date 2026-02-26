use crate::ast_walker::{ModuleInfo, ModuleKind};
use crate::detector::{Confidence, Detector, Finding, Severity, SourceLocation};

pub struct ExcessiveValidatorParams;

const MAX_RECOMMENDED_PARAMS: usize = 4;

impl Detector for ExcessiveValidatorParams {
    fn name(&self) -> &str {
        "excessive-validator-params"
    }

    fn description(&self) -> &str {
        "Detects validators with too many parameters"
    }

    fn severity(&self) -> Severity {
        Severity::Info
    }

    fn long_description(&self) -> &str {
        "Validators with many parameters increase deployment complexity and are more \
        error-prone. Each parameter must be provided at deployment time and increases \
        the script size. Consider grouping related parameters into a datum or using \
        reference scripts.\n\n\
        Threshold: More than 4 validator parameters triggers this warning.\n\n\
        Fix: Group related parameters into a configuration datum or reduce parameter count."
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
                if validator.params.len() > MAX_RECOMMENDED_PARAMS {
                    let param_names: Vec<&str> =
                        validator.params.iter().map(|p| p.name.as_str()).collect();

                    let location = validator
                        .handlers
                        .first()
                        .and_then(|h| h.location)
                        .map(|(s, e)| SourceLocation::from_bytes(&module.path, s, e));

                    findings.push(Finding {
                        detector_name: self.name().to_string(),
                        severity: self.severity(),
                        confidence: Confidence::Possible,
                        title: format!(
                            "Validator '{}' has {} parameters (max recommended: {})",
                            validator.name,
                            validator.params.len(),
                            MAX_RECOMMENDED_PARAMS
                        ),
                        description: format!(
                            "Parameters: {}. Consider grouping related parameters.",
                            param_names.join(", ")
                        ),
                        module: module.name.clone(),
                        location,
                        suggestion: Some(
                            "Group related parameters into a configuration datum \
                            or reference script."
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

    fn make_module(params: Vec<ParamInfo>) -> Vec<ModuleInfo> {
        vec![ModuleInfo {
            name: "test/validator".to_string(),
            path: "validator.ak".to_string(),
            kind: ModuleKind::Validator,
            validators: vec![ValidatorInfo {
                name: "v".to_string(),
                params,
                handlers: vec![HandlerInfo {
                    name: "spend".to_string(),
                    params: vec![],
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
        }]
    }

    fn param(name: &str) -> ParamInfo {
        ParamInfo {
            name: name.to_string(),
            type_name: "ByteArray".to_string(),
        }
    }

    #[test]
    fn test_detects_excessive_params() {
        let modules = make_module(vec![
            param("a"),
            param("b"),
            param("c"),
            param("d"),
            param("e"),
        ]);
        assert_eq!(ExcessiveValidatorParams.detect(&modules).len(), 1);
    }

    #[test]
    fn test_no_finding_under_threshold() {
        let modules = make_module(vec![param("a"), param("b")]);
        assert!(ExcessiveValidatorParams.detect(&modules).is_empty());
    }

    #[test]
    fn test_no_finding_at_threshold() {
        let modules = make_module(vec![param("a"), param("b"), param("c"), param("d")]);
        assert!(ExcessiveValidatorParams.detect(&modules).is_empty());
    }
}
