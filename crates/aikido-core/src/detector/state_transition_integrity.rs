use crate::ast_walker::{ModuleInfo, ModuleKind};
use crate::delegation::build_delegation_set;
use crate::detector::{
    outputs_go_to_pkh_only, Confidence, Detector, Finding, Severity, SourceLocation,
};

/// Detects validators with multiple redeemer actions but no datum state verification.
pub struct StateTransitionIntegrity;

impl Detector for StateTransitionIntegrity {
    fn name(&self) -> &str {
        "state-transition-integrity"
    }

    fn description(&self) -> &str {
        "Detects spend handlers with multiple redeemer actions but no output datum verification"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn long_description(&self) -> &str {
        "When a spend handler has multiple redeemer actions (e.g., Deposit, Withdraw, Update), \
        each action should verify the output datum correctly reflects the state change. Without \
        datum verification on outputs, an attacker could perform a valid action but produce an \
        output with a manipulated datum, effectively corrupting the protocol state.\n\n\
        Example (vulnerable):\n  spend(datum, redeemer, _ref, self) {\n    when redeemer is {\n      \
        Deposit(amount) -> {\n        // Checks value but not output datum!\n        \
        value.lovelace_of(output.value) >= datum.balance + amount\n      }\n    }\n  }\n\n\
        Fix: Verify output datum:\n  Deposit(amount) -> {\n    expect InlineDatum(new_datum) = output.datum\n    \
        new_datum.balance == datum.balance + amount &&\n    value.lovelace_of(output.value) >= new_datum.balance\n  }"
    }

    fn cwe_id(&self) -> Option<&str> {
        Some("CWE-345")
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
                    if handler.name != "spend" {
                        continue;
                    }

                    // Suppress on delegating handlers — state validation happens in delegate
                    if delegation_set.contains(&(
                        module.name.clone(),
                        validator.name.clone(),
                        handler.name.clone(),
                    )) {
                        continue;
                    }

                    let signals = &handler.body_signals;

                    // Must have multiple redeemer actions (>= 2 non-catchall when branches)
                    let action_branches: Vec<_> = signals
                        .when_branches
                        .iter()
                        .filter(|b| !b.is_catchall && !b.body_is_error)
                        .collect();

                    if action_branches.len() < 2 {
                        continue;
                    }

                    // Must produce continuing outputs
                    if !signals.tx_field_accesses.contains("outputs") {
                        continue;
                    }

                    // Suppress when outputs go to PKH addresses (wallet payouts).
                    // PKH outputs have no continuing script state to corrupt —
                    // there's no script-locked UTXO whose datum needs verification.
                    if outputs_go_to_pkh_only(signals) {
                        continue;
                    }

                    // Suppress when datum continuity is already asserted
                    // (record update or explicit equality checks between input/output datums)
                    if signals.has_datum_continuity_assertion {
                        continue;
                    }

                    // Check if output datum is verified
                    let verifies_datum = signals.all_record_labels.contains("datum")
                        || signals.function_calls.iter().any(|c| {
                            c.contains("InlineDatum")
                                || c.contains("inline_datum")
                                || c.contains("DatumHash")
                                || c.contains("datum_hash")
                        })
                        || signals
                            .var_references
                            .iter()
                            .any(|v| v == "InlineDatum" || v == "DatumHash" || v == "NoDatum");

                    if !verifies_datum {
                        let actions: Vec<&str> = action_branches
                            .iter()
                            .map(|b| b.pattern_text.as_str())
                            .collect();

                        findings.push(Finding {
                            detector_name: self.name().to_string(),
                            severity: self.severity(),
                            confidence: Confidence::Likely,
                            title: format!(
                                "State transition in {}.{} doesn't verify output datum",
                                validator.name, handler.name
                            ),
                            description: format!(
                                "Handler {}.{} has {} redeemer actions ({}) and produces \
                                continuing outputs but never verifies the output datum. \
                                An attacker could submit a valid action but with a \
                                manipulated datum, corrupting protocol state.",
                                validator.name,
                                handler.name,
                                action_branches.len(),
                                actions.join(", ")
                            ),
                            module: module.name.clone(),
                            location: handler
                                .location
                                .map(|(s, e)| SourceLocation::from_bytes(&module.path, s, e)),
                            suggestion: Some(
                                "For each redeemer action, verify the output datum with \
                                `expect InlineDatum(new_datum) = output.datum` and validate \
                                all datum fields reflect the expected state change."
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
    use crate::body_analysis::{BodySignals, WhenBranchInfo};
    use std::collections::HashSet;

    fn make_modules(
        when_branches: Vec<WhenBranchInfo>,
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
                    params: vec![],
                    return_type: "Bool".to_string(),
                    location: None,
                    body_signals: BodySignals {
                        when_branches,
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
    fn test_detects_missing_datum_verification() {
        let branches = vec![
            WhenBranchInfo {
                pattern_text: "Deposit".to_string(),
                is_catchall: false,
                body_is_literal_true: false,
                body_is_error: false,
            },
            WhenBranchInfo {
                pattern_text: "Withdraw".to_string(),
                is_catchall: false,
                body_is_literal_true: false,
                body_is_error: false,
            },
        ];
        let mut tx = HashSet::new();
        tx.insert("outputs".to_string());
        // No datum label or InlineDatum reference
        // Must include script address ref so PKH check doesn't suppress
        let mut var_refs = HashSet::new();
        var_refs.insert("ScriptCredential".to_string());

        let modules = make_modules(branches, tx, HashSet::new(), var_refs);
        let findings = StateTransitionIntegrity.detect(&modules);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].title.contains("doesn't verify output datum"));
        assert_eq!(findings[0].confidence, Confidence::Likely);
    }

    #[test]
    fn test_no_finding_when_datum_checked() {
        let branches = vec![
            WhenBranchInfo {
                pattern_text: "Deposit".to_string(),
                is_catchall: false,
                body_is_literal_true: false,
                body_is_error: false,
            },
            WhenBranchInfo {
                pattern_text: "Withdraw".to_string(),
                is_catchall: false,
                body_is_literal_true: false,
                body_is_error: false,
            },
        ];
        let mut tx = HashSet::new();
        tx.insert("outputs".to_string());
        let mut labels = HashSet::new();
        labels.insert("datum".to_string());

        let modules = make_modules(branches, tx, labels, HashSet::new());
        let findings = StateTransitionIntegrity.detect(&modules);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_no_finding_when_inline_datum_used() {
        let branches = vec![
            WhenBranchInfo {
                pattern_text: "Deposit".to_string(),
                is_catchall: false,
                body_is_literal_true: false,
                body_is_error: false,
            },
            WhenBranchInfo {
                pattern_text: "Withdraw".to_string(),
                is_catchall: false,
                body_is_literal_true: false,
                body_is_error: false,
            },
        ];
        let mut tx = HashSet::new();
        tx.insert("outputs".to_string());
        let mut vars = HashSet::new();
        vars.insert("InlineDatum".to_string());

        let modules = make_modules(branches, tx, HashSet::new(), vars);
        let findings = StateTransitionIntegrity.detect(&modules);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_no_finding_single_action() {
        let branches = vec![WhenBranchInfo {
            pattern_text: "Execute".to_string(),
            is_catchall: false,
            body_is_literal_true: false,
            body_is_error: false,
        }];
        let mut tx = HashSet::new();
        tx.insert("outputs".to_string());

        let modules = make_modules(branches, tx, HashSet::new(), HashSet::new());
        let findings = StateTransitionIntegrity.detect(&modules);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_no_finding_when_outputs_to_pkh() {
        // Outputs go to PKH addresses (wallet payouts) — no continuing script state
        let branches = vec![
            WhenBranchInfo {
                pattern_text: "Settle".to_string(),
                is_catchall: false,
                body_is_literal_true: false,
                body_is_error: false,
            },
            WhenBranchInfo {
                pattern_text: "Reclaim".to_string(),
                is_catchall: false,
                body_is_literal_true: false,
                body_is_error: false,
            },
        ];
        let mut tx = HashSet::new();
        tx.insert("outputs".to_string());
        // No ScriptCredential references → outputs go to PKH only
        let mut var_refs = HashSet::new();
        var_refs.insert("VerificationKeyCredential".to_string());

        let modules = make_modules(branches, tx, HashSet::new(), var_refs);
        let findings = StateTransitionIntegrity.detect(&modules);
        assert!(
            findings.is_empty(),
            "PKH-only outputs should suppress state-transition finding"
        );
    }

    #[test]
    fn test_still_fires_when_outputs_to_script() {
        // Outputs go to script addresses — state transition matters
        let branches = vec![
            WhenBranchInfo {
                pattern_text: "Deposit".to_string(),
                is_catchall: false,
                body_is_literal_true: false,
                body_is_error: false,
            },
            WhenBranchInfo {
                pattern_text: "Withdraw".to_string(),
                is_catchall: false,
                body_is_literal_true: false,
                body_is_error: false,
            },
        ];
        let mut tx = HashSet::new();
        tx.insert("outputs".to_string());
        let mut var_refs = HashSet::new();
        var_refs.insert("ScriptCredential".to_string());

        let modules = make_modules(branches, tx, HashSet::new(), var_refs);
        let findings = StateTransitionIntegrity.detect(&modules);
        assert_eq!(
            findings.len(),
            1,
            "script address outputs should still fire state-transition"
        );
    }

    #[test]
    fn test_no_finding_without_outputs() {
        let branches = vec![
            WhenBranchInfo {
                pattern_text: "A".to_string(),
                is_catchall: false,
                body_is_literal_true: false,
                body_is_error: false,
            },
            WhenBranchInfo {
                pattern_text: "B".to_string(),
                is_catchall: false,
                body_is_literal_true: false,
                body_is_error: false,
            },
        ];

        let modules = make_modules(branches, HashSet::new(), HashSet::new(), HashSet::new());
        let findings = StateTransitionIntegrity.detect(&modules);
        assert!(findings.is_empty());
    }
}
