use crate::ast_walker::{ModuleInfo, ModuleKind};
use crate::detector::{Confidence, Detector, Finding, Severity, SourceLocation};

/// Detects spend handlers that modify value but don't update the datum state.
pub struct MissingStateUpdate;

impl Detector for MissingStateUpdate {
    fn name(&self) -> &str {
        "missing-state-update"
    }

    fn description(&self) -> &str {
        "Detects spend handlers that produce continuing outputs without datum state updates"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn long_description(&self) -> &str {
        "When a spend handler produces continuing outputs (sends value back to the same \
        script address), the output datum should typically be updated to reflect the new \
        state. If the handler accesses both the input datum and outputs but never references \
        output datum construction, the continuing UTXO may carry stale state that doesn't \
        match its value.\n\n\
        Example (vulnerable):\n  spend(datum, redeemer, _ref, self) {\n    \
        list.any(self.outputs, fn(o) {\n      o.address == own_address &&\n      \
        value.lovelace_of(o.value) >= datum.balance + amount\n      \
        // datum not updated — output carries old datum.balance!\n    })\n  }\n\n\
        Fix: Update datum in output:\n  let new_datum = MyDatum { ..datum, balance: datum.balance + amount }\n  \
        expect InlineDatum(out_datum) = output.datum\n  out_datum == new_datum"
    }

    fn cwe_id(&self) -> Option<&str> {
        Some("CWE-669")
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
                    if handler.name != "spend" {
                        continue;
                    }

                    let signals = &handler.body_signals;

                    // Must access datum fields (actually reads the datum)
                    if signals.datum_field_accesses.is_empty() {
                        continue;
                    }

                    // Must produce continuing outputs
                    if !signals.tx_field_accesses.contains("outputs") {
                        continue;
                    }

                    // Suppress for burn/reclaim patterns. When a handler checks that
                    // zero tokens of its own policy exist on outputs (e.g.,
                    // `quantity_of(output.value, own_policy, ...) == 0`), it's
                    // intentionally destroying the UTXO, not updating it.
                    let is_burn_reclaim = signals
                        .function_calls
                        .iter()
                        .any(|c| c.contains("quantity_of") || c.contains("tokens"))
                        && signals
                            .function_calls
                            .iter()
                            .any(|c| c.contains("multisig") || c.contains("satisfied"));

                    if is_burn_reclaim {
                        continue;
                    }

                    // Suppress when handler delegates all logic to a withdrawal script.
                    if signals.tx_field_accesses.contains("withdrawals")
                        && signals
                            .function_calls
                            .iter()
                            .any(|c| c.contains("has_key") || c.contains("is_withdrawal"))
                    {
                        continue;
                    }

                    // Check if datum is referenced in output construction
                    let updates_datum = signals.all_record_labels.contains("datum")
                        || signals.function_calls.iter().any(|c| {
                            c.contains("InlineDatum")
                                || c.contains("inline_datum")
                                || c.contains("DatumHash")
                                || c.contains("RecordUpdate")
                        })
                        || signals
                            .var_references
                            .iter()
                            .any(|v| v == "InlineDatum" || v == "DatumHash" || v == "NoDatum");

                    if !updates_datum {
                        findings.push(Finding {
                            detector_name: self.name().to_string(),
                            severity: self.severity(),
                            confidence: Confidence::Possible,
                            title: format!(
                                "Handler {}.{} reads datum but doesn't update it in outputs",
                                validator.name, handler.name
                            ),
                            description: format!(
                                "Handler {}.{} reads datum fields ({}) and produces continuing \
                                outputs but doesn't appear to construct or verify the output datum. \
                                The output UTXO may carry stale state.",
                                validator.name,
                                handler.name,
                                signals
                                    .datum_field_accesses
                                    .iter()
                                    .cloned()
                                    .collect::<Vec<_>>()
                                    .join(", ")
                            ),
                            module: module.name.clone(),
                            location: handler
                                .location
                                .map(|(s, e)| SourceLocation::from_bytes(&module.path, s, e)),
                            suggestion: Some(
                                "Construct an updated datum and verify it with \
                                `expect InlineDatum(new_datum) = output.datum`."
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

    fn make_modules(
        datum_accesses: HashSet<String>,
        tx_accesses: HashSet<String>,
        record_labels: HashSet<String>,
        var_refs: HashSet<String>,
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
                        type_name: "MyDatum".to_string(),
                    }],
                    return_type: "Bool".to_string(),
                    location: None,
                    body_signals: BodySignals {
                        datum_field_accesses: datum_accesses,
                        tx_field_accesses: tx_accesses,
                        all_record_labels: record_labels,
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
        }]
    }

    #[test]
    fn test_detects_missing_state_update() {
        let mut datum = HashSet::new();
        datum.insert("balance".to_string());
        let mut tx = HashSet::new();
        tx.insert("outputs".to_string());

        let modules = make_modules(datum, tx, HashSet::new(), HashSet::new());
        let findings = MissingStateUpdate.detect(&modules);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].title.contains("doesn't update"));
    }

    #[test]
    fn test_no_finding_when_datum_updated() {
        let mut datum = HashSet::new();
        datum.insert("balance".to_string());
        let mut tx = HashSet::new();
        tx.insert("outputs".to_string());
        let mut labels = HashSet::new();
        labels.insert("datum".to_string());

        let modules = make_modules(datum, tx, labels, HashSet::new());
        let findings = MissingStateUpdate.detect(&modules);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_no_finding_with_inline_datum() {
        let mut datum = HashSet::new();
        datum.insert("balance".to_string());
        let mut tx = HashSet::new();
        tx.insert("outputs".to_string());
        let mut vars = HashSet::new();
        vars.insert("InlineDatum".to_string());

        let modules = make_modules(datum, tx, HashSet::new(), vars);
        let findings = MissingStateUpdate.detect(&modules);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_no_finding_without_datum_reads() {
        let mut tx = HashSet::new();
        tx.insert("outputs".to_string());

        let modules = make_modules(HashSet::new(), tx, HashSet::new(), HashSet::new());
        let findings = MissingStateUpdate.detect(&modules);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_no_finding_without_outputs() {
        let mut datum = HashSet::new();
        datum.insert("balance".to_string());

        let modules = make_modules(datum, HashSet::new(), HashSet::new(), HashSet::new());
        let findings = MissingStateUpdate.detect(&modules);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_no_finding_with_burn_reclaim_pattern() {
        // Handler checks quantity_of + multisig.satisfied = burn/reclaim pattern
        let mut datum = HashSet::new();
        datum.insert("owner".to_string());
        let mut tx = HashSet::new();
        tx.insert("outputs".to_string());
        let mut fns = HashSet::new();
        fns.insert("quantity_of".to_string());
        fns.insert("multisig.satisfied".to_string());

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
                        type_name: "MyDatum".to_string(),
                    }],
                    return_type: "Bool".to_string(),
                    location: None,
                    body_signals: BodySignals {
                        datum_field_accesses: datum,
                        tx_field_accesses: tx,
                        function_calls: fns,
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
        let findings = MissingStateUpdate.detect(&modules);
        assert!(
            findings.is_empty(),
            "burn/reclaim pattern should suppress missing state update"
        );
    }

    #[test]
    fn test_no_finding_with_withdrawal_delegation() {
        let mut datum = HashSet::new();
        datum.insert("balance".to_string());
        let mut tx = HashSet::new();
        tx.insert("outputs".to_string());
        tx.insert("withdrawals".to_string());
        let mut fns = HashSet::new();
        fns.insert("pairs.has_key".to_string());

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
                        type_name: "MyDatum".to_string(),
                    }],
                    return_type: "Bool".to_string(),
                    location: None,
                    body_signals: BodySignals {
                        datum_field_accesses: datum,
                        tx_field_accesses: tx,
                        function_calls: fns,
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
        let findings = MissingStateUpdate.detect(&modules);
        assert!(
            findings.is_empty(),
            "withdrawal delegation should suppress missing state update"
        );
    }
}
