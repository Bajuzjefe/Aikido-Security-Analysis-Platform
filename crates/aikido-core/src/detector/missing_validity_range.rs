use crate::ast_walker::{DataTypeInfo, ModuleInfo, ModuleKind};
use crate::detector::{
    matches_field_pattern, type_base_name, Confidence, Detector, Finding, Severity, SourceLocation,
};

const TIME_FIELD_PATTERNS: &[&str] = &[
    "deadline",
    "expiry",
    "lock_until",
    "valid_until",
    "valid_before",
    "valid_after",
    "expires_at",
    "opened_at",
    "created_at",
    "timestamp",
];

/// Suffix patterns for time-related field names (e.g., `entered_position_time`).
const TIME_FIELD_SUFFIXES: &[&str] = &["_time", "_timestamp", "_at"];

pub struct MissingValidityRange;

impl MissingValidityRange {
    /// Find time-like fields in a data type (Int fields with time-related names or POSIXTime type).
    fn find_time_fields(dt: &DataTypeInfo) -> Vec<String> {
        dt.constructors
            .iter()
            .flat_map(|c| &c.fields)
            .filter(|f| {
                if let Some(label) = &f.label {
                    let is_int_type = f.type_name == "Int";
                    let is_posix_type = f.type_name.contains("POSIX");
                    if !is_int_type && !is_posix_type {
                        return false;
                    }
                    // Check explicit patterns (deadline, expiry, etc.)
                    if matches_field_pattern(label, TIME_FIELD_PATTERNS) {
                        return true;
                    }
                    // Check suffix patterns (entered_position_time, created_at, etc.)
                    let lower = label.to_lowercase();
                    TIME_FIELD_SUFFIXES.iter().any(|s| lower.ends_with(s))
                } else {
                    false
                }
            })
            .filter_map(|f| f.label.clone())
            .collect()
    }
}

impl Detector for MissingValidityRange {
    fn name(&self) -> &str {
        "missing-validity-range"
    }

    fn description(&self) -> &str {
        "Detects handlers with time-like datum fields that never check validity_range"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn long_description(&self) -> &str {
        "Time-sensitive datum fields (deadline, expires_at, etc.) indicate temporal constraints \
        that should be enforced via transaction.validity_range. Without this check, a transaction \
        can be submitted at any time, potentially allowing actions before or after the intended \
        window.\n\n\
        Example (vulnerable):\n  spend(datum, .., self) {\n    \
        // datum.deadline exists but validity_range never checked\n    True\n  }\n\n\
        Fix: Check `self.validity_range` against the datum's time fields."
    }

    fn cwe_id(&self) -> Option<&str> {
        Some("CWE-613")
    }

    fn category(&self) -> &str {
        "logic"
    }

    fn detect(&self, modules: &[ModuleInfo]) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Collect all time-like fields from all data types across all modules
        let all_time_fields: Vec<(String, Vec<String>)> = modules
            .iter()
            .flat_map(|m| &m.data_types)
            .filter_map(|dt| {
                let fields = Self::find_time_fields(dt);
                if fields.is_empty() {
                    None
                } else {
                    Some((dt.name.clone(), fields))
                }
            })
            .collect();

        if all_time_fields.is_empty() {
            return findings;
        }

        for module in modules {
            if module.kind != ModuleKind::Validator {
                continue;
            }

            for validator in &module.validators {
                for handler in &validator.handlers {
                    let datum_type_name = handler
                        .params
                        .first()
                        .map(|p| type_base_name(&p.type_name).to_string());

                    let mut relevant_time_fields: Vec<&str> = all_time_fields
                        .iter()
                        .filter(|(type_name, _)| {
                            datum_type_name.as_deref().is_some_and(|dt| dt == type_name)
                        })
                        .flat_map(|(_, fields)| fields.iter().map(|s| s.as_str()))
                        .collect();

                    // Fallback: if the handler's direct datum type doesn't have time fields,
                    // check if the handler body references any time-like variable names.
                    // This catches nested datum types (e.g., OrderDatum containing PositionDatum
                    // with entered_position_time — the handler destructures the nested type).
                    if relevant_time_fields.is_empty() {
                        let body_time_refs: Vec<&str> = all_time_fields
                            .iter()
                            .flat_map(|(_, fields)| fields.iter())
                            .filter(|field| {
                                handler.body_signals.var_references.contains(field.as_str())
                            })
                            .map(|s| s.as_str())
                            .collect();
                        if !body_time_refs.is_empty() {
                            relevant_time_fields = body_time_refs;
                        }
                    }

                    if relevant_time_fields.is_empty() {
                        continue;
                    }

                    if !handler
                        .body_signals
                        .tx_field_accesses
                        .contains("validity_range")
                    {
                        findings.push(Finding {
                            detector_name: self.name().to_string(),
                            severity: self.severity(),
                            confidence: Confidence::Likely,
                            title: format!(
                                "Time-sensitive datum but no validity_range check in {}.{}",
                                validator.name, handler.name
                            ),
                            description: format!(
                                "Datum field(s) [{}] suggest time-sensitive logic but handler never accesses transaction.validity_range.",
                                relevant_time_fields.join(", ")
                            ),
                            module: module.name.clone(),
                            location: handler.location.map(|(s, e)| {
                                SourceLocation::from_bytes(&module.path, s, e)
                            }),
                            suggestion: Some(
                                "Check validity_range against the time field(s) to enforce temporal constraints."
                                    .to_string(),
                            ),
                            related_findings: vec![],
                            semantic_group: None,

                            evidence: None,
                        });
                    }

                    // Additional check: if validity_range IS accessed but only lower bound is used
                    // (not upper bound), flag potential time manipulation
                    if handler
                        .body_signals
                        .tx_field_accesses
                        .contains("validity_range")
                    {
                        let uses_lower =
                            handler.body_signals.function_calls.iter().any(|c| {
                                c.contains("lower_bound") || c.contains("get_lower_bound")
                            });
                        let uses_upper = handler.body_signals.function_calls.iter().any(|c| {
                            c.contains("upper_bound")
                                || c.contains("get_upper_bound")
                                || c.contains("is_entirely_before")
                                || c.contains("is_entirely_after")
                        });

                        // Recognize oracle-based time verification as an upper-bound
                        // equivalent. When a handler verifies Ed25519 signatures
                        // (oracle pattern) AND has time-related guards, the oracle's
                        // freshness check constrains the time window similarly to
                        // a validity_range upper bound.
                        let has_oracle_time_verification =
                            handler.body_signals.function_calls.iter().any(|c| {
                                c.contains("verify_ed25519_signature")
                                    || c.contains("ed25519.verify")
                                    || c.contains("verify_signature")
                                    || c.contains("verify_attestation")
                                    || c.contains("verify_oracle")
                            }) && !handler.body_signals.guarded_vars.is_empty();

                        if uses_lower && !uses_upper && !has_oracle_time_verification {
                            findings.push(Finding {
                                detector_name: self.name().to_string(),
                                severity: Severity::High,
                                confidence: Confidence::Likely,
                                title: format!(
                                    "Lower bound time manipulation risk in {}.{}",
                                    validator.name, handler.name
                                ),
                                description: format!(
                                    "Handler uses get_lower_bound for time-sensitive logic with field(s) [{}] \
                                    but never checks the upper bound. An attacker can set the lower bound \
                                    arbitrarily far in the past, manipulating time-based calculations \
                                    (interest accrual, fee computation, deadline checks).",
                                    relevant_time_fields.join(", ")
                                ),
                                module: module.name.clone(),
                                location: handler.location.map(|(s, e)| {
                                    SourceLocation::from_bytes(&module.path, s, e)
                                }),
                                suggestion: Some(
                                    "Use get_upper_bound instead of get_lower_bound for time-sensitive \
                                    calculations. The upper bound cannot be set arbitrarily into the past."
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
    fn test_detects_missing_validity_range() {
        let modules = make_test_modules(
            vec![("deadline", "Int"), ("owner", "ByteArray")],
            HashSet::new(),
        );
        let findings = MissingValidityRange.detect(&modules);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Medium);
        assert!(findings[0].description.contains("deadline"));
    }

    #[test]
    fn test_no_finding_when_validity_range_checked() {
        let mut accesses = HashSet::new();
        accesses.insert("validity_range".to_string());
        let modules =
            make_test_modules(vec![("deadline", "Int"), ("owner", "ByteArray")], accesses);
        let findings = MissingValidityRange.detect(&modules);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_no_finding_without_time_fields() {
        let modules = make_test_modules(
            vec![("owner", "ByteArray"), ("amount", "Int")],
            HashSet::new(),
        );
        let findings = MissingValidityRange.detect(&modules);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_no_false_positive_on_similar_names() {
        // "deadlines" should NOT match "deadline" with word-boundary matching
        let modules = make_test_modules(
            vec![("deadlines", "Int"), ("created", "Int")],
            HashSet::new(),
        );
        let findings = MissingValidityRange.detect(&modules);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_detects_lower_bound_only() {
        let mut accesses = HashSet::new();
        accesses.insert("validity_range".to_string());
        let mut calls = HashSet::new();
        calls.insert("get_lower_bound".to_string());

        let modules = vec![
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
                        fields: vec![FieldInfo {
                            label: Some("deadline".to_string()),
                            type_name: "Int".to_string(),
                        }],
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
                                name: "self".to_string(),
                                type_name: "Transaction".to_string(),
                            },
                        ],
                        return_type: "Bool".to_string(),
                        location: None,
                        body_signals: BodySignals {
                            tx_field_accesses: accesses,
                            function_calls: calls,
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
        ];

        let findings = MissingValidityRange.detect(&modules);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
        assert!(findings[0].title.contains("Lower bound"));
    }

    #[test]
    fn test_no_finding_with_upper_bound() {
        let mut accesses = HashSet::new();
        accesses.insert("validity_range".to_string());
        let mut calls = HashSet::new();
        calls.insert("get_lower_bound".to_string());
        calls.insert("get_upper_bound".to_string());

        let modules = vec![
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
                        fields: vec![FieldInfo {
                            label: Some("deadline".to_string()),
                            type_name: "Int".to_string(),
                        }],
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
                                name: "self".to_string(),
                                type_name: "Transaction".to_string(),
                            },
                        ],
                        return_type: "Bool".to_string(),
                        location: None,
                        body_signals: BodySignals {
                            tx_field_accesses: accesses,
                            function_calls: calls,
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
        ];

        let findings = MissingValidityRange.detect(&modules);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_no_finding_with_oracle_time_verification() {
        // Handler uses lower_bound but also verifies Ed25519 oracle signatures
        // with time guards — oracle freshness serves as upper bound equivalent
        let mut accesses = HashSet::new();
        accesses.insert("validity_range".to_string());
        let mut calls = HashSet::new();
        calls.insert("get_lower_bound".to_string());
        calls.insert("verify_ed25519_signature".to_string());
        let mut guarded = HashSet::new();
        guarded.insert("observed_at".to_string());

        let modules = vec![
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
                        fields: vec![FieldInfo {
                            label: Some("expires_at".to_string()),
                            type_name: "Int".to_string(),
                        }],
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
                                name: "self".to_string(),
                                type_name: "Transaction".to_string(),
                            },
                        ],
                        return_type: "Bool".to_string(),
                        location: None,
                        body_signals: BodySignals {
                            tx_field_accesses: accesses,
                            function_calls: calls,
                            guarded_vars: guarded,
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
        ];

        let findings = MissingValidityRange.detect(&modules);
        assert!(
            findings.is_empty(),
            "oracle time verification should suppress lower-bound-only finding"
        );
    }

    #[test]
    fn test_detects_nested_time_field_via_var_reference() {
        // Simulates: OrderDatum doesn't have time fields, but the handler
        // destructures a nested PositionDatum with entered_position_time.
        // The handler body references the variable "entered_position_time"
        // and uses get_lower_bound without upper bound.
        let mut accesses = HashSet::new();
        accesses.insert("validity_range".to_string());
        let mut calls = HashSet::new();
        calls.insert("get_lower_bound".to_string());
        let mut var_refs = HashSet::new();
        var_refs.insert("entered_position_time".to_string());

        let modules = vec![
            // Types module with PositionDatum (has time field)
            ModuleInfo {
                name: "test/types".to_string(),
                path: "types.ak".to_string(),
                kind: ModuleKind::Lib,
                validators: vec![],
                data_types: vec![DataTypeInfo {
                    name: "PositionDatum".to_string(),
                    public: true,
                    constructors: vec![ConstructorInfo {
                        name: "PositionDatum".to_string(),
                        fields: vec![FieldInfo {
                            label: Some("entered_position_time".to_string()),
                            type_name: "Int".to_string(),
                        }],
                    }],
                }],
                functions: vec![],
                constants: vec![],
                type_aliases: vec![],
                test_count: 0,
                source_code: None,
                test_function_names: vec![],
            },
            // Validator with handler that takes OrderDatum (no time fields)
            // but body references entered_position_time via nested destructuring
            ModuleInfo {
                name: "test/validator".to_string(),
                path: "validator.ak".to_string(),
                kind: ModuleKind::Validator,
                validators: vec![ValidatorInfo {
                    name: "orders".to_string(),
                    params: vec![],
                    handlers: vec![HandlerInfo {
                        name: "spend".to_string(),
                        params: vec![
                            ParamInfo {
                                name: "datum".to_string(),
                                type_name: "OrderDatum".to_string(),
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
                            function_calls: calls,
                            var_references: var_refs,
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
        ];

        let findings = MissingValidityRange.detect(&modules);
        assert_eq!(
            findings.len(),
            1,
            "should detect lower-bound-only via nested time field"
        );
        assert_eq!(findings[0].severity, Severity::High);
        assert!(findings[0].title.contains("Lower bound"));
    }
}
