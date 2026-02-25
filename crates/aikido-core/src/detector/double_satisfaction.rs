use crate::ast_walker::{ModuleInfo, ModuleKind};
use crate::delegation::build_delegation_set;
use crate::detector::{Confidence, Detector, Finding, Severity, SourceLocation};

pub struct DoubleSatisfaction;

impl Detector for DoubleSatisfaction {
    fn name(&self) -> &str {
        "double-satisfaction"
    }

    fn description(&self) -> &str {
        "Detects spend handlers that iterate outputs without referencing their own OutputReference"
    }

    fn severity(&self) -> Severity {
        Severity::Critical
    }

    fn long_description(&self) -> &str {
        "A double satisfaction attack occurs when a single transaction spends multiple script UTXOs, \
        and one output satisfies the spending conditions for all of them. If a spend handler iterates \
        transaction outputs looking for a matching payment but never checks its own OutputReference, \
        an attacker can batch multiple script inputs and use one output to satisfy all of them.\n\n\
        Example (vulnerable):\n  spend(datum, redeemer, _own_ref, self) {\n    \
        list.any(self.outputs, fn(o) { o.value >= datum.amount })\n  }\n\n\
        Fix: Use own_ref to correlate the specific input being spent:\n  spend(datum, redeemer, own_ref, self) {\n    \
        let own_input = transaction.find_input(self.inputs, own_ref)\n    ...\n  }"
    }

    fn cwe_id(&self) -> Option<&str> {
        Some("CWE-362")
    }

    fn category(&self) -> &str {
        "authorization"
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

                    // Only applies to spend handlers
                    if handler.name != "spend" {
                        continue;
                    }

                    // Must have at least 3 params (datum, redeemer, own_ref, self)
                    if handler.params.len() < 3 {
                        continue;
                    }

                    let accesses_outputs =
                        handler.body_signals.tx_field_accesses.contains("outputs");

                    // Check if own_ref param is explicitly discarded (starts with _)
                    let own_ref_discarded = handler.params[2].name.starts_with('_');

                    // Flag if outputs are accessed but own_ref is not used
                    if accesses_outputs && (own_ref_discarded || !handler.body_signals.uses_own_ref)
                    {
                        let confidence = if handler.body_signals.enforces_single_input {
                            Confidence::Possible // Still report, lower confidence
                        } else if own_ref_discarded {
                            Confidence::Definite
                        } else {
                            Confidence::Likely
                        };
                        findings.push(Finding {
                            detector_name: self.name().to_string(),
                            severity: self.severity(),
                            confidence,
                            title: format!(
                                "Potential double satisfaction in {}.{}",
                                validator.name, handler.name
                            ),
                            description: format!(
                                "Handler iterates transaction outputs but never references its own OutputReference (param '{}'). \
                                An attacker could satisfy multiple script inputs with a single output.",
                                handler.params[2].name
                            ),
                            module: module.name.clone(),
                            location: handler.location.map(|(s, e)| {
                                SourceLocation::from_bytes(&module.path, s, e)
                            }),
                            suggestion: Some(
                                "Use the OutputReference parameter to correlate outputs to this specific input."
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

    fn make_spend_handler(
        own_ref_name: &str,
        tx_accesses: HashSet<String>,
        uses_own_ref: bool,
    ) -> Vec<ModuleInfo> {
        vec![ModuleInfo {
            name: "test/validator".to_string(),
            path: "validator.ak".to_string(),
            kind: ModuleKind::Validator,
            validators: vec![ValidatorInfo {
                name: "test_validator".to_string(),
                params: vec![],
                handlers: vec![HandlerInfo {
                    name: "spend".to_string(),
                    params: vec![
                        ParamInfo {
                            name: "datum".to_string(),
                            type_name: "Datum".to_string(),
                        },
                        ParamInfo {
                            name: "redeemer".to_string(),
                            type_name: "Redeemer".to_string(),
                        },
                        ParamInfo {
                            name: own_ref_name.to_string(),
                            type_name: "OutputReference".to_string(),
                        },
                        ParamInfo {
                            name: "self".to_string(),
                            type_name: "Transaction".to_string(),
                        },
                    ],
                    return_type: "Bool".to_string(),
                    location: None,
                    body_signals: BodySignals {
                        tx_field_accesses: tx_accesses,
                        uses_own_ref,
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
    fn test_detects_double_satisfaction() {
        let mut accesses = HashSet::new();
        accesses.insert("outputs".to_string());

        let modules = make_spend_handler("_own_ref", accesses, false);

        let detector = DoubleSatisfaction;
        let findings = detector.detect(&modules);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical);
        assert!(findings[0].title.contains("double satisfaction"));
    }

    #[test]
    fn test_no_finding_when_own_ref_used() {
        let mut accesses = HashSet::new();
        accesses.insert("outputs".to_string());

        let modules = make_spend_handler("own_ref", accesses, true);

        let detector = DoubleSatisfaction;
        let findings = detector.detect(&modules);

        assert!(findings.is_empty());
    }

    #[test]
    fn test_no_finding_when_outputs_not_accessed() {
        let modules = make_spend_handler("_own_ref", HashSet::new(), false);

        let detector = DoubleSatisfaction;
        let findings = detector.detect(&modules);

        assert!(findings.is_empty());
    }

    #[test]
    fn test_downgraded_confidence_with_single_input_constraint() {
        let mut accesses = HashSet::new();
        accesses.insert("outputs".to_string());

        let modules = vec![ModuleInfo {
            name: "test/validator".to_string(),
            path: "validator.ak".to_string(),
            kind: ModuleKind::Validator,
            validators: vec![ValidatorInfo {
                name: "test_validator".to_string(),
                params: vec![],
                handlers: vec![HandlerInfo {
                    name: "spend".to_string(),
                    params: vec![
                        ParamInfo {
                            name: "datum".to_string(),
                            type_name: "Datum".to_string(),
                        },
                        ParamInfo {
                            name: "redeemer".to_string(),
                            type_name: "Redeemer".to_string(),
                        },
                        ParamInfo {
                            name: "_own_ref".to_string(),
                            type_name: "OutputReference".to_string(),
                        },
                        ParamInfo {
                            name: "self".to_string(),
                            type_name: "Transaction".to_string(),
                        },
                    ],
                    return_type: "Bool".to_string(),
                    location: None,
                    body_signals: BodySignals {
                        tx_field_accesses: accesses,
                        uses_own_ref: false,
                        enforces_single_input: true,
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

        let detector = DoubleSatisfaction;
        let findings = detector.detect(&modules);

        assert_eq!(
            findings.len(),
            1,
            "Single-input constraint should downgrade, not suppress"
        );
        assert_eq!(findings[0].confidence, Confidence::Possible);
    }

    #[test]
    fn test_skips_non_spend_handlers() {
        let mut accesses = HashSet::new();
        accesses.insert("outputs".to_string());

        let modules = vec![ModuleInfo {
            name: "test/validator".to_string(),
            path: "validator.ak".to_string(),
            kind: ModuleKind::Validator,
            validators: vec![ValidatorInfo {
                name: "test_validator".to_string(),
                params: vec![],
                handlers: vec![HandlerInfo {
                    name: "mint".to_string(),
                    params: vec![
                        ParamInfo {
                            name: "redeemer".to_string(),
                            type_name: "Redeemer".to_string(),
                        },
                        ParamInfo {
                            name: "self".to_string(),
                            type_name: "Transaction".to_string(),
                        },
                    ],
                    return_type: "Bool".to_string(),
                    location: None,
                    body_signals: BodySignals {
                        tx_field_accesses: accesses,
                        uses_own_ref: false,
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

        let detector = DoubleSatisfaction;
        let findings = detector.detect(&modules);

        assert!(findings.is_empty());
    }
}
