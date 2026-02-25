use crate::ast_walker::{ModuleInfo, ModuleKind};
use crate::detector::{Confidence, Detector, Finding, Severity, SourceLocation};

/// Detects datum fields that can take invalid values (no bounds checking).
pub struct DatumFieldBounds;

impl Detector for DatumFieldBounds {
    fn name(&self) -> &str {
        "datum-field-bounds"
    }

    fn description(&self) -> &str {
        "Detects datum fields without bounds validation"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn long_description(&self) -> &str {
        "When a validator accepts datum fields (especially numeric ones like leverage, \
        amount, price) in output datums without validating their bounds, an attacker \
        can set these fields to extreme values (0, negative, overflow) that break \
        the contract's invariants on subsequent interactions."
    }

    fn cwe_id(&self) -> Option<&str> {
        Some("CWE-129")
    }

    fn category(&self) -> &str {
        "data-validation"
    }

    fn detect(&self, modules: &[ModuleInfo]) -> Vec<Finding> {
        let mut findings = Vec::new();
        for module in modules {
            if module.kind != ModuleKind::Validator {
                continue;
            }
            for validator in &module.validators {
                for handler in &validator.handlers {
                    if handler.name != "spend" {
                        continue;
                    }
                    let signals = &handler.body_signals;

                    // Must produce output with datum
                    if !signals.tx_field_accesses.contains("outputs") {
                        continue;
                    }
                    let has_datum_output =
                        signals.all_record_labels.contains("datum") || signals.has_record_update;
                    if !has_datum_output {
                        continue;
                    }

                    // Check if datum fields are bounds-checked
                    let datum_fields_checked = !signals.datum_field_accesses.is_empty()
                        && signals.datum_field_accesses.iter().any(|f| {
                            signals.guarded_vars.contains(f)
                                || signals
                                    .guarded_operations
                                    .iter()
                                    .any(|g| g.guarded_var == *f)
                        });

                    // If datum fields are accessed but not bounds-checked in output
                    if !signals.datum_field_accesses.is_empty()
                        && !datum_fields_checked
                        && signals.has_record_update
                    {
                        let fields: Vec<_> = signals.datum_field_accesses.iter().cloned().collect();
                        findings.push(Finding {
                            detector_name: self.name().to_string(),
                            severity: self.severity(),
                            confidence: Confidence::Possible,
                            title: format!(
                                "Datum field bounds not checked in {}.{}",
                                validator.name, handler.name
                            ),
                            description: format!(
                                "Handler {}.{} updates datum fields via record update but \
                                doesn't validate field bounds. Fields: {:?}",
                                validator.name, handler.name, fields
                            ),
                            module: module.name.clone(),
                            location: handler
                                .location
                                .map(|(s, e)| SourceLocation::from_bytes(&module.path, s, e)),
                            suggestion: Some(
                                "Add bounds checks (expect field > 0, expect field <= max) \
                                before writing to output datum."
                                    .to_string(),
                            ),
                            related_findings: vec![],
                            semantic_group: Some("invariant".to_string()),

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
    fn test_detects_unchecked_datum_update() {
        let mut signals = BodySignals::default();
        signals.tx_field_accesses.insert("outputs".to_string());
        signals.has_record_update = true;
        signals.all_record_labels.insert("datum".to_string());
        signals.datum_field_accesses.insert("leverage".to_string());

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
        }];
        let findings = DatumFieldBounds.detect(&modules);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn test_no_finding_with_guarded_field() {
        let mut signals = BodySignals::default();
        signals.tx_field_accesses.insert("outputs".to_string());
        signals.has_record_update = true;
        signals.all_record_labels.insert("datum".to_string());
        signals.datum_field_accesses.insert("leverage".to_string());
        signals.guarded_vars.insert("leverage".to_string());

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
        }];
        let findings = DatumFieldBounds.detect(&modules);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_no_finding_without_record_update() {
        let mut signals = BodySignals::default();
        signals.tx_field_accesses.insert("outputs".to_string());
        signals.all_record_labels.insert("datum".to_string());
        signals.datum_field_accesses.insert("leverage".to_string());
        // has_record_update = false

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
        }];
        let findings = DatumFieldBounds.detect(&modules);
        assert!(findings.is_empty());
    }
}
