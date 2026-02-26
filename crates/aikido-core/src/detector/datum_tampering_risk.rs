use crate::ast_walker::{ModuleInfo, ModuleKind};
use crate::detector::{type_base_name, Confidence, Detector, Finding, Severity, SourceLocation};

/// Detects spend handlers that produce continuing outputs but only validate
/// a subset of the datum fields, leaving unchecked fields vulnerable to tampering.
///
/// When a continuing UTXO is created, the output datum should be fully validated.
/// If only some fields are checked (e.g., owner, amount) but others are not
/// (e.g., interest_rate, fee_multiplier), an attacker can modify the unchecked
/// fields to gain an advantage.
pub struct DatumTamperingRisk;

impl Detector for DatumTamperingRisk {
    fn name(&self) -> &str {
        "datum-tampering-risk"
    }

    fn description(&self) -> &str {
        "Detects continuing outputs where only some datum fields are validated"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn long_description(&self) -> &str {
        "When a spend handler produces continuing outputs (sends a UTXO back to the same \
        script), the output datum should be fully validated. If the handler only accesses \
        some datum fields but the datum type has additional fields, an attacker could modify \
        the unchecked fields in the continuing output.\n\n\
        For example, if a handler checks `datum.owner` and `datum.amount` but ignores \
        `datum.fee_rate`, an attacker could set `fee_rate` to zero in the output datum.\n\n\
        Example (vulnerable):\n  spend(datum, redeemer, own_ref, self) {\n    \
        expect o.datum == InlineDatum(MyDatum { owner: datum.owner, amount: new_amount, \
        fee_rate: ??? })  // fee_rate unchecked!\n  }\n\n\
        Fix: Validate all datum fields or use record update syntax with explicit field \
        checks: `MyDatum { ..datum, amount: new_amount }`"
    }

    fn cwe_id(&self) -> Option<&str> {
        Some("CWE-20")
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

                    // Must produce continuing outputs
                    if !signals.tx_field_accesses.contains("outputs") {
                        continue;
                    }

                    // Skip when handler delegates to a withdrawal script.
                    if signals.tx_field_accesses.contains("withdrawals")
                        && signals
                            .function_calls
                            .iter()
                            .any(|c| c.contains("has_key") || c.contains("is_withdrawal"))
                    {
                        continue;
                    }

                    // Must access some datum fields (partial validation)
                    if signals.datum_field_accesses.is_empty() {
                        continue;
                    }

                    // Suppress when handler constructs full datum for comparison.
                    // Pattern: `InlineDatum(MyDatum { ... }) == output.datum`
                    // If the handler references InlineDatum AND the datum type constructor,
                    // it's building a full datum for equality check.
                    let uses_inline_datum = signals
                        .var_references
                        .iter()
                        .any(|v| v == "InlineDatum" || v == "DatumHash");
                    let uses_datum_constructor = signals
                        .function_calls
                        .iter()
                        .any(|f| f.contains("InlineDatum") || f.contains("DatumHash"));
                    if uses_inline_datum || uses_datum_constructor {
                        continue;
                    }

                    // Suppress when handler uses record update syntax
                    // (`MyDatum { ..datum, field: val }`) — this preserves all
                    // fields not explicitly overridden, preventing tampering.
                    if signals.has_record_update {
                        continue;
                    }

                    // Find the datum type and count total fields
                    let datum_type_name = handler
                        .params
                        .first()
                        .map(|p| type_base_name(&p.type_name).to_string());

                    if let Some(ref dt_name) = datum_type_name {
                        let total_fields = count_datum_fields(modules, dt_name);

                        // Only flag if there are unchecked fields
                        // (at least 2 fields not accessed, and at least 3 total)
                        let accessed = signals.datum_field_accesses.len();
                        if total_fields >= 3 && accessed > 0 && accessed < total_fields - 1 {
                            let unchecked = total_fields - accessed;
                            findings.push(Finding {
                                detector_name: self.name().to_string(),
                                severity: self.severity(),
                                confidence: Confidence::Possible,
                                title: format!(
                                    "Partial datum validation in {}.{} ({accessed}/{total_fields} fields checked)",
                                    validator.name, handler.name
                                ),
                                description: format!(
                                    "Handler {}.{} produces continuing outputs and accesses \
                                    {accessed} of {total_fields} datum fields. The {unchecked} \
                                    unchecked fields could be tampered with in the output datum.",
                                    validator.name, handler.name
                                ),
                                module: module.name.clone(),
                                location: handler
                                    .location
                                    .map(|(s, e)| SourceLocation::from_bytes(&module.path, s, e)),
                                suggestion: Some(
                                    "Validate all datum fields in the continuing output, or use \
                                    record update syntax with explicit checks for each field."
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

/// Count the total number of labeled fields in a datum type across all modules.
fn count_datum_fields(modules: &[ModuleInfo], type_name: &str) -> usize {
    for module in modules {
        for dt in &module.data_types {
            if dt.name == type_name {
                return dt
                    .constructors
                    .first()
                    .map_or(0, |c| c.fields.iter().filter(|f| f.label.is_some()).count());
            }
        }
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast_walker::*;
    use crate::body_analysis::BodySignals;
    use std::collections::HashSet;

    fn make_modules(
        datum_fields: Vec<(&str, &str)>,
        tx_accesses: HashSet<String>,
        datum_accesses: HashSet<String>,
    ) -> Vec<ModuleInfo> {
        let fields = datum_fields
            .into_iter()
            .map(|(name, typ)| FieldInfo {
                label: Some(name.to_string()),
                type_name: typ.to_string(),
            })
            .collect();

        vec![
            ModuleInfo {
                name: "test/types".to_string(),
                path: "types.ak".to_string(),
                kind: ModuleKind::Lib,
                validators: vec![],
                data_types: vec![DataTypeInfo {
                    name: "PoolDatum".to_string(),
                    public: true,
                    constructors: vec![ConstructorInfo {
                        name: "PoolDatum".to_string(),
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
                    name: "pool".to_string(),
                    params: vec![],
                    handlers: vec![HandlerInfo {
                        name: "spend".to_string(),
                        params: vec![ParamInfo {
                            name: "datum".to_string(),
                            type_name: "PoolDatum".to_string(),
                        }],
                        return_type: "Bool".to_string(),
                        location: None,
                        body_signals: BodySignals {
                            tx_field_accesses: tx_accesses,
                            datum_field_accesses: datum_accesses,
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
    fn test_detects_partial_datum_validation() {
        let mut tx = HashSet::new();
        tx.insert("outputs".to_string());
        let mut datum = HashSet::new();
        datum.insert("owner".to_string());
        // Only 1 of 4 fields accessed

        let modules = make_modules(
            vec![
                ("owner", "ByteArray"),
                ("amount", "Int"),
                ("fee_rate", "Int"),
                ("deadline", "Int"),
            ],
            tx,
            datum,
        );
        let findings = DatumTamperingRisk.detect(&modules);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].title.contains("1/4"));
    }

    #[test]
    fn test_no_finding_when_most_fields_accessed() {
        let mut tx = HashSet::new();
        tx.insert("outputs".to_string());
        let mut datum = HashSet::new();
        datum.insert("owner".to_string());
        datum.insert("amount".to_string());
        datum.insert("fee_rate".to_string());
        // 3 of 4 fields — only 1 unchecked, below threshold

        let modules = make_modules(
            vec![
                ("owner", "ByteArray"),
                ("amount", "Int"),
                ("fee_rate", "Int"),
                ("deadline", "Int"),
            ],
            tx,
            datum,
        );
        let findings = DatumTamperingRisk.detect(&modules);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_no_finding_without_outputs() {
        let mut datum = HashSet::new();
        datum.insert("owner".to_string());

        let modules = make_modules(
            vec![("owner", "ByteArray"), ("amount", "Int"), ("fee", "Int")],
            HashSet::new(),
            datum,
        );
        let findings = DatumTamperingRisk.detect(&modules);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_no_finding_with_empty_datum_accesses() {
        let mut tx = HashSet::new();
        tx.insert("outputs".to_string());

        let modules = make_modules(
            vec![("owner", "ByteArray"), ("amount", "Int"), ("fee", "Int")],
            tx,
            HashSet::new(),
        );
        let findings = DatumTamperingRisk.detect(&modules);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_no_finding_with_small_datum() {
        let mut tx = HashSet::new();
        tx.insert("outputs".to_string());
        let mut datum = HashSet::new();
        datum.insert("owner".to_string());

        let modules = make_modules(vec![("owner", "ByteArray"), ("amount", "Int")], tx, datum);
        let findings = DatumTamperingRisk.detect(&modules);
        assert!(findings.is_empty(), "2-field datum should not trigger");
    }

    #[test]
    fn test_no_finding_with_withdrawal_delegation() {
        let mut tx = HashSet::new();
        tx.insert("outputs".to_string());
        tx.insert("withdrawals".to_string());
        let mut datum = HashSet::new();
        datum.insert("owner".to_string());

        let mut modules = make_modules(
            vec![
                ("owner", "ByteArray"),
                ("amount", "Int"),
                ("fee_rate", "Int"),
                ("deadline", "Int"),
            ],
            tx,
            datum,
        );
        // Add has_key function call to spend handler
        modules[1].validators[0].handlers[0]
            .body_signals
            .function_calls
            .insert("pairs.has_key".to_string());

        let findings = DatumTamperingRisk.detect(&modules);
        assert!(
            findings.is_empty(),
            "withdrawal delegation should suppress datum tampering"
        );
    }

    #[test]
    fn test_no_finding_with_inline_datum_comparison() {
        let mut tx = HashSet::new();
        tx.insert("outputs".to_string());
        let mut datum = HashSet::new();
        datum.insert("owner".to_string());
        // Only 1 of 4 accessed — would normally trigger

        let mut modules = make_modules(
            vec![
                ("owner", "ByteArray"),
                ("amount", "Int"),
                ("fee_rate", "Int"),
                ("deadline", "Int"),
            ],
            tx,
            datum,
        );
        // Handler references InlineDatum — building datum for equality check
        modules[1].validators[0].handlers[0]
            .body_signals
            .var_references
            .insert("InlineDatum".to_string());

        let findings = DatumTamperingRisk.detect(&modules);
        assert!(
            findings.is_empty(),
            "InlineDatum reference should suppress — handler constructs datum for comparison"
        );
    }

    #[test]
    fn test_no_finding_with_record_update_syntax() {
        let mut tx = HashSet::new();
        tx.insert("outputs".to_string());
        let mut datum = HashSet::new();
        datum.insert("owner".to_string());
        // Only 1 of 4 accessed — would normally trigger

        let mut modules = make_modules(
            vec![
                ("owner", "ByteArray"),
                ("amount", "Int"),
                ("fee_rate", "Int"),
                ("deadline", "Int"),
            ],
            tx,
            datum,
        );
        // Handler uses record update syntax: MyDatum { ..datum, amount: new_amount }
        modules[1].validators[0].handlers[0]
            .body_signals
            .has_record_update = true;

        let findings = DatumTamperingRisk.detect(&modules);
        assert!(
            findings.is_empty(),
            "record update syntax should suppress — preserves all unmodified fields"
        );
    }
}
