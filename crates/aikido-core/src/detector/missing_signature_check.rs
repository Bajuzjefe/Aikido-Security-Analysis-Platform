use crate::ast_walker::{DataTypeInfo, ModuleInfo, ModuleKind};
use crate::delegation::build_delegation_set;
use crate::detector::{
    matches_field_pattern, type_base_name, Confidence, Detector, Finding, Severity, SourceLocation,
};

const AUTHORITY_FIELD_PATTERNS: &[&str] = &[
    "owner",
    "beneficiary",
    "admin",
    "authority",
    "operator",
    "creator",
];

pub struct MissingSignatureCheck;

impl MissingSignatureCheck {
    /// Find authority-like fields in a data type (ByteArray fields with authority-related names).
    fn find_authority_fields(dt: &DataTypeInfo) -> Vec<String> {
        dt.constructors
            .iter()
            .flat_map(|c| &c.fields)
            .filter(|f| {
                if let Some(label) = &f.label {
                    matches_field_pattern(label, AUTHORITY_FIELD_PATTERNS)
                        && f.type_name == "ByteArray"
                } else {
                    false
                }
            })
            .filter_map(|f| f.label.clone())
            .collect()
    }
}

impl Detector for MissingSignatureCheck {
    fn name(&self) -> &str {
        "missing-signature-check"
    }

    fn description(&self) -> &str {
        "Detects handlers with authority-like datum fields that never check extra_signatories"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn long_description(&self) -> &str {
        "Authority fields (owner, admin, operator, etc.) as ByteArray in datum types typically \
        represent public key hashes that should be verified against transaction signatories. \
        If a handler uses datum with such fields but never checks transaction.extra_signatories, \
        the authority constraint may be unenforced.\n\n\
        Example (vulnerable):\n  spend(datum, .., self) {\n    \
        // datum.owner is never verified\n    datum.amount > 0\n  }\n\n\
        Fix: Verify `list.has(self.extra_signatories, datum.owner)`."
    }

    fn cwe_id(&self) -> Option<&str> {
        Some("CWE-862")
    }

    fn category(&self) -> &str {
        "authorization"
    }

    fn detect(&self, modules: &[ModuleInfo]) -> Vec<Finding> {
        let mut findings = Vec::new();
        let delegation_set = build_delegation_set(modules);

        // Collect all authority-like fields from all data types
        let all_authority_fields: Vec<(String, Vec<String>)> = modules
            .iter()
            .flat_map(|m| &m.data_types)
            .filter_map(|dt| {
                let fields = Self::find_authority_fields(dt);
                if fields.is_empty() {
                    None
                } else {
                    Some((dt.name.clone(), fields))
                }
            })
            .collect();

        if all_authority_fields.is_empty() {
            return findings;
        }

        for module in modules {
            if module.kind != ModuleKind::Validator {
                continue;
            }

            for validator in &module.validators {
                for handler in &validator.handlers {
                    // Suppress on delegating handlers — signature check happens in delegate
                    if delegation_set.contains(&(
                        module.name.clone(),
                        validator.name.clone(),
                        handler.name.clone(),
                    )) {
                        continue;
                    }
                    let datum_type_name = handler
                        .params
                        .first()
                        .map(|p| type_base_name(&p.type_name).to_string());

                    let relevant_fields: Vec<&str> = all_authority_fields
                        .iter()
                        .filter(|(type_name, _)| {
                            datum_type_name.as_deref().is_some_and(|dt| dt == type_name)
                        })
                        .flat_map(|(_, fields)| fields.iter().map(|s| s.as_str()))
                        .collect();

                    if relevant_fields.is_empty() {
                        continue;
                    }

                    if !handler
                        .body_signals
                        .tx_field_accesses
                        .contains("extra_signatories")
                    {
                        findings.push(Finding {
                            detector_name: self.name().to_string(),
                            severity: self.severity(),
                            confidence: Confidence::Likely,
                            title: format!(
                                "Authority field but no signature check in {}.{}",
                                validator.name, handler.name
                            ),
                            description: format!(
                                "Datum field(s) [{}] resemble authority keys (ByteArray) but handler never checks transaction.extra_signatories.",
                                relevant_fields.join(", ")
                            ),
                            module: module.name.clone(),
                            location: handler.location.map(|(s, e)| {
                                SourceLocation::from_bytes(&module.path, s, e)
                            }),
                            suggestion: Some(
                                "Verify the authority key appears in transaction.extra_signatories."
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

    fn make_test_modules(
        datum_fields: Vec<(&str, &str)>,
        tx_accesses: HashSet<String>,
    ) -> Vec<ModuleInfo> {
        let fields = datum_fields
            .into_iter()
            .map(|(name, type_name)| FieldInfo {
                label: Some(name.to_string()),
                type_name: type_name.to_string(),
            })
            .collect();

        vec![
            ModuleInfo {
                name: "test/types".to_string(),
                path: "types.ak".to_string(),
                kind: ModuleKind::Lib,
                validators: vec![],
                data_types: vec![DataTypeInfo {
                    name: "TestDatum".to_string(),
                    public: true,
                    constructors: vec![ConstructorInfo {
                        name: "TestDatum".to_string(),
                        fields,
                    }],
                }],
                functions: vec![],
                constants: vec![],
                type_aliases: vec![],
                test_count: 0,
                source_code: None,
                test_function_names: vec![],
            },
            ModuleInfo {
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
                                type_name: "TestDatum".to_string(),
                            },
                            ParamInfo {
                                name: "redeemer".to_string(),
                                type_name: "Redeemer".to_string(),
                            },
                            ParamInfo {
                                name: "own_ref".to_string(),
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
            },
        ]
    }

    #[test]
    fn test_detects_missing_signature_check() {
        let modules = make_test_modules(
            vec![("owner", "ByteArray"), ("amount", "Int")],
            HashSet::new(),
        );

        let detector = MissingSignatureCheck;
        let findings = detector.detect(&modules);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
        assert!(findings[0].description.contains("owner"));
    }

    #[test]
    fn test_no_finding_when_extra_signatories_checked() {
        let mut accesses = HashSet::new();
        accesses.insert("extra_signatories".to_string());

        let modules = make_test_modules(vec![("owner", "ByteArray"), ("amount", "Int")], accesses);

        let detector = MissingSignatureCheck;
        let findings = detector.detect(&modules);

        assert!(findings.is_empty());
    }

    #[test]
    fn test_no_finding_without_authority_fields() {
        let modules = make_test_modules(
            vec![("amount", "Int"), ("token", "ByteArray")],
            HashSet::new(),
        );

        let detector = MissingSignatureCheck;
        let findings = detector.detect(&modules);

        assert!(findings.is_empty());
    }

    #[test]
    fn test_only_matches_bytearray_type() {
        // "owner" field that's Int, not ByteArray — should NOT trigger
        let modules = make_test_modules(vec![("owner", "Int"), ("amount", "Int")], HashSet::new());

        let detector = MissingSignatureCheck;
        let findings = detector.detect(&modules);

        assert!(findings.is_empty());
    }

    #[test]
    fn test_no_false_positive_on_similar_names() {
        // "ownership" should NOT match "owner" with word-boundary matching
        let modules = make_test_modules(
            vec![("ownership", "ByteArray"), ("coowner", "ByteArray")],
            HashSet::new(),
        );

        let detector = MissingSignatureCheck;
        let findings = detector.detect(&modules);

        assert!(findings.is_empty());
    }
}
