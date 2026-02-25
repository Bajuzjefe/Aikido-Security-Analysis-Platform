use crate::ast_walker::{ModuleInfo, ModuleKind};
use crate::detector::{Confidence, Detector, Finding, Severity, SourceLocation};

/// Detects spend handlers that accept a datum but don't validate critical fields.
pub struct MissingDatumFieldValidation;

/// Fields that are typically user-controlled and should be validated in the handler.
/// If a datum type has these fields but the handler never accesses them, the handler
/// likely trusts the datum contents blindly.
const CRITICAL_DATUM_FIELDS: &[&str] = &[
    "deadline",
    "expiry",
    "expires_at",
    "lock_until",
    "amount",
    "price",
    "strike_price",
    "premium",
    "collateral",
    "margin",
    "min_amount",
    "max_amount",
    "target_price",
    "rate",
    "ratio",
    "leverage",
    "multiplier",
    "quantity",
    "threshold",
    "limit",
];

impl Detector for MissingDatumFieldValidation {
    fn name(&self) -> &str {
        "missing-datum-field-validation"
    }

    fn description(&self) -> &str {
        "Detects spend handlers that accept datum with financial fields but never validate them"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn long_description(&self) -> &str {
        "When a datum contains fields representing financial constraints (deadlines, amounts, \
        prices, collateral), the spend handler should validate these values. If the handler \
        never accesses critical datum fields, it may be blindly trusting user-supplied datum \
        data without verification, allowing manipulation of financial terms.\n\n\
        Example (vulnerable):\n  type LoanDatum {\n    borrower: VerificationKeyHash,\n    \
        collateral: Int,  // never checked!\n    deadline: Int,  // never checked!\n  }\n  \
        spend(datum, redeemer, _ref, self) {\n    // Only checks borrower, ignores collateral \
        and deadline\n  }\n\n\
        Fix: Validate all financial fields:\n  expect datum.collateral >= min_collateral\n  \
        expect datum.deadline > get_current_time(self.validity_range)"
    }

    fn cwe_id(&self) -> Option<&str> {
        Some("CWE-20")
    }

    fn category(&self) -> &str {
        "data-validation"
    }

    fn detect(&self, modules: &[ModuleInfo]) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Collect data types from all modules (lib and validator) for cross-module lookup
        let all_data_types: Vec<_> = modules.iter().flat_map(|m| m.data_types.iter()).collect();

        for module in modules {
            if module.kind != ModuleKind::Validator {
                continue;
            }

            for validator in &module.validators {
                for handler in &validator.handlers {
                    if handler.name != "spend" {
                        continue;
                    }

                    // Get the datum type name
                    let datum_param = match handler.params.first() {
                        Some(p) => p,
                        None => continue,
                    };

                    let datum_type_name = crate::detector::type_base_name(&datum_param.type_name);

                    // Find datum type definition
                    let datum_type = all_data_types.iter().find(|dt| dt.name == datum_type_name);
                    let datum_type = match datum_type {
                        Some(dt) => dt,
                        None => continue,
                    };

                    // Get fields from the first constructor
                    let fields = match datum_type.constructors.first() {
                        Some(c) => &c.fields,
                        None => continue,
                    };

                    // Suppress when datum continuity is already asserted
                    // (the handler explicitly preserves datum state through equality or record update)
                    if handler.body_signals.has_datum_continuity_assertion {
                        continue;
                    }

                    // Find critical fields in the datum
                    let critical_fields: Vec<&str> = fields
                        .iter()
                        .filter_map(|f| {
                            f.label.as_deref().and_then(|label| {
                                let lower = label.to_lowercase();
                                if CRITICAL_DATUM_FIELDS.iter().any(|&pattern| {
                                    lower == pattern
                                        || lower.starts_with(&format!("{pattern}_"))
                                        || lower.ends_with(&format!("_{pattern}"))
                                        || lower.contains(&format!("_{pattern}_"))
                                }) {
                                    Some(label)
                                } else {
                                    None
                                }
                            })
                        })
                        .collect();

                    if critical_fields.is_empty() {
                        continue;
                    }

                    // Check which datum fields are actually accessed in the handler.
                    // Primary: direct datum field accesses (datum.field).
                    // Fallback: var_references — if the field name appears as a variable,
                    // the handler likely reads it through destructuring or helper functions
                    // (e.g., `let stake = datum.stake_lovelace` or passing datum to a
                    // helper that accesses the field).
                    let accessed = &handler.body_signals.datum_field_accesses;
                    let var_refs = &handler.body_signals.var_references;

                    let unvalidated: Vec<&&str> = critical_fields
                        .iter()
                        .filter(|&&field| !accessed.contains(field) && !var_refs.contains(field))
                        .collect();

                    if !unvalidated.is_empty() {
                        let field_list: Vec<String> =
                            unvalidated.iter().map(|f| format!("'{f}'")).collect();
                        findings.push(Finding {
                            detector_name: self.name().to_string(),
                            severity: self.severity(),
                            confidence: Confidence::Possible,
                            title: format!(
                                "Datum fields {} not validated in {}.{}",
                                field_list.join(", "),
                                validator.name,
                                handler.name
                            ),
                            description: format!(
                                "Handler {}.{} accepts datum type '{}' with financial fields {} \
                                but never accesses them. These fields may be manipulated by an \
                                attacker if not validated.",
                                validator.name,
                                handler.name,
                                datum_type_name,
                                field_list.join(", ")
                            ),
                            module: module.name.clone(),
                            location: handler
                                .location
                                .map(|(s, e)| SourceLocation::from_bytes(&module.path, s, e)),
                            suggestion: Some(format!(
                                "Validate datum fields: {}",
                                unvalidated
                                    .iter()
                                    .map(|f| format!("`expect datum.{f} > 0`"))
                                    .collect::<Vec<_>>()
                                    .join(", ")
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

    fn make_modules(
        datum_fields: Vec<FieldInfo>,
        datum_accesses: HashSet<String>,
    ) -> Vec<ModuleInfo> {
        vec![ModuleInfo {
            name: "test/validator".to_string(),
            path: "validator.ak".to_string(),
            kind: ModuleKind::Validator,
            validators: vec![ValidatorInfo {
                name: "test".to_string(),
                params: vec![],
                handlers: vec![HandlerInfo {
                    name: "spend".to_string(),
                    params: vec![ParamInfo {
                        name: "datum".to_string(),
                        type_name: "LoanDatum".to_string(),
                    }],
                    return_type: "Bool".to_string(),
                    location: None,
                    body_signals: BodySignals {
                        datum_field_accesses: datum_accesses,
                        ..Default::default()
                    },
                }],
                summary: None,
            }],
            data_types: vec![DataTypeInfo {
                name: "LoanDatum".to_string(),
                public: true,
                constructors: vec![ConstructorInfo {
                    name: "LoanDatum".to_string(),
                    fields: datum_fields,
                }],
            }],
            functions: vec![],
            constants: vec![],
            type_aliases: vec![],
            test_count: 0,
            source_code: None,
            test_function_names: vec![],
        }]
    }

    #[test]
    fn test_detects_unvalidated_financial_fields() {
        let fields = vec![
            FieldInfo {
                label: Some("owner".to_string()),
                type_name: "VerificationKeyHash".to_string(),
            },
            FieldInfo {
                label: Some("deadline".to_string()),
                type_name: "Int".to_string(),
            },
            FieldInfo {
                label: Some("collateral".to_string()),
                type_name: "Int".to_string(),
            },
        ];
        let mut accesses = HashSet::new();
        accesses.insert("owner".to_string());
        // deadline and collateral not accessed

        let modules = make_modules(fields, accesses);
        let findings = MissingDatumFieldValidation.detect(&modules);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].title.contains("deadline"));
        assert!(findings[0].title.contains("collateral"));
    }

    #[test]
    fn test_no_finding_when_all_fields_accessed() {
        let fields = vec![
            FieldInfo {
                label: Some("deadline".to_string()),
                type_name: "Int".to_string(),
            },
            FieldInfo {
                label: Some("amount".to_string()),
                type_name: "Int".to_string(),
            },
        ];
        let mut accesses = HashSet::new();
        accesses.insert("deadline".to_string());
        accesses.insert("amount".to_string());

        let modules = make_modules(fields, accesses);
        let findings = MissingDatumFieldValidation.detect(&modules);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_no_finding_with_no_financial_fields() {
        let fields = vec![
            FieldInfo {
                label: Some("owner".to_string()),
                type_name: "VerificationKeyHash".to_string(),
            },
            FieldInfo {
                label: Some("name".to_string()),
                type_name: "ByteArray".to_string(),
            },
        ];

        let modules = make_modules(fields, HashSet::new());
        let findings = MissingDatumFieldValidation.detect(&modules);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_no_finding_when_field_in_var_references() {
        // Field accessed via helper function — appears in var_references but not
        // datum_field_accesses (e.g., datum passed to settlement.compute_payout
        // which reads stake_lovelace internally)
        let fields = vec![
            FieldInfo {
                label: Some("owner".to_string()),
                type_name: "VerificationKeyHash".to_string(),
            },
            FieldInfo {
                label: Some("collateral".to_string()),
                type_name: "Int".to_string(),
            },
        ];
        let mut accesses = HashSet::new();
        accesses.insert("owner".to_string());
        // collateral NOT in datum_field_accesses...

        let mut var_refs = HashSet::new();
        var_refs.insert("collateral".to_string()); // ...but IS in var_references

        let modules = vec![ModuleInfo {
            name: "test/validator".to_string(),
            path: "validator.ak".to_string(),
            kind: ModuleKind::Validator,
            validators: vec![ValidatorInfo {
                name: "test".to_string(),
                params: vec![],
                handlers: vec![HandlerInfo {
                    name: "spend".to_string(),
                    params: vec![ParamInfo {
                        name: "datum".to_string(),
                        type_name: "LoanDatum".to_string(),
                    }],
                    return_type: "Bool".to_string(),
                    location: None,
                    body_signals: BodySignals {
                        datum_field_accesses: accesses,
                        var_references: var_refs,
                        ..Default::default()
                    },
                }],
                summary: None,
            }],
            data_types: vec![DataTypeInfo {
                name: "LoanDatum".to_string(),
                public: true,
                constructors: vec![ConstructorInfo {
                    name: "LoanDatum".to_string(),
                    fields,
                }],
            }],
            functions: vec![],
            constants: vec![],
            type_aliases: vec![],
            test_count: 0,
            source_code: None,
            test_function_names: vec![],
        }];

        let findings = MissingDatumFieldValidation.detect(&modules);
        assert!(
            findings.is_empty(),
            "field in var_references should suppress missing-datum-field finding"
        );
    }

    #[test]
    fn test_no_finding_on_mint_handler() {
        let modules = vec![ModuleInfo {
            name: "test/validator".to_string(),
            path: "validator.ak".to_string(),
            kind: ModuleKind::Validator,
            validators: vec![ValidatorInfo {
                name: "test".to_string(),
                params: vec![],
                handlers: vec![HandlerInfo {
                    name: "mint".to_string(),
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
        }];

        let findings = MissingDatumFieldValidation.detect(&modules);
        assert!(findings.is_empty());
    }
}
