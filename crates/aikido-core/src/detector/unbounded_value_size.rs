use crate::ast_walker::{ModuleInfo, ModuleKind};
use crate::detector::{Confidence, Detector, Finding, Severity, SourceLocation};

/// Detects script outputs that don't constrain native asset count (token dust attack vector).
pub struct UnboundedValueSize;

impl Detector for UnboundedValueSize {
    fn name(&self) -> &str {
        "unbounded-value-size"
    }

    fn description(&self) -> &str {
        "Detects outputs that don't constrain the number of native assets in the Value"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn long_description(&self) -> &str {
        "When a script creates continuing outputs (sending value back to the script address), \
        it should constrain the number of native assets (token policies) in the output value. \
        Without this check, an attacker can add many small native assets ('token dust') to the \
        UTXO, bloating its size and increasing the cost to spend it — potentially making it \
        unspendable if processing exceeds the Plutus execution budget.\n\n\
        Example (vulnerable):\n  spend(datum, redeemer, own_ref, self) {\n    \
        list.any(self.outputs, fn(o) {\n      o.address == own_address &&\n      \
        value.lovelace_of(o.value) >= expected\n      // Missing: no check on native asset count!\n    \
        })\n  }\n\n\
        Fix: Constrain the output value's native asset policies:\n  \
        list.any(self.outputs, fn(o) {\n    o.address == own_address &&\n    \
        value.lovelace_of(o.value) >= expected &&\n    \
        list.length(value.policies(o.value)) <= max_policies\n  })"
    }

    fn cwe_id(&self) -> Option<&str> {
        Some("CWE-400")
    }

    fn category(&self) -> &str {
        "resource"
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

                    // Handler must produce continuing outputs
                    let accesses_outputs = signals.tx_field_accesses.contains("outputs");
                    if !accesses_outputs {
                        continue;
                    }

                    // Check if value is accessed (basic prerequisite — must at least check value)
                    // Note: stdlib v2 renamed `value` module to `assets`
                    let checks_value = signals.all_record_labels.contains("value")
                        || signals.function_calls.iter().any(|c| {
                            c.contains("lovelace_of")
                                || c.contains("value.merge")
                                || c.contains("value.from_lovelace")
                                || c.contains("assets.merge")
                                || c.contains("assets.from_lovelace")
                                || c.contains("assets.add")
                        });

                    if !checks_value {
                        // value-not-preserved detector already covers this case
                        continue;
                    }

                    // Check if native asset count is constrained.
                    // Strong constraints fully prevent dust (suppress finding):
                    let has_strong_constraint =
                        signals.function_calls.iter().any(|c| {
                            c.contains("policies")
                                || c.contains("tokens")
                                || c.contains("without_lovelace")
                                || c.contains("from_asset")
                                || c.contains("to_dict")
                                || c.contains("asset_count")
                        }) || signals.all_record_labels.contains("policies");

                    if has_strong_constraint {
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

                    // Suppress on admin-signed handlers. When a handler requires
                    // a specific signature (extra_signatories check), token dust
                    // is not an external attack vector — the admin controls inputs.
                    if signals.requires_signature {
                        continue;
                    }

                    // Weak constraints (flatten, quantity_of) check individual assets
                    // or total counts but don't prevent arbitrary policy injection.
                    let has_flatten = signals.function_calls.iter().any(|c| c.contains("flatten"));
                    let has_quantity_of = signals
                        .function_calls
                        .iter()
                        .any(|c| c.contains("quantity_of"));
                    let has_list_length = signals
                        .function_calls
                        .iter()
                        .any(|c| c.contains("list.length") || c.contains("length"));

                    // flatten + list.length together = exact asset count check (strong).
                    // Pattern: `list.length(flatten(output.value)) == N`
                    // This prevents dust injection by constraining the total number
                    // of (policy, name, quantity) triples.
                    if has_flatten && has_list_length {
                        continue;
                    }

                    let has_weak_constraint = has_flatten || has_quantity_of;

                    if !has_weak_constraint {
                        findings.push(Finding {
                            detector_name: self.name().to_string(),
                            severity: self.severity(),
                            confidence: Confidence::Possible,
                            title: format!(
                                "Handler {}.{} doesn't constrain native asset count in outputs",
                                validator.name, handler.name
                            ),
                            description:
                                "Spend handler creates continuing outputs and checks value \
                                but doesn't constrain the number of native asset policies. \
                                An attacker can add token dust to bloat the UTXO size, \
                                potentially making it unspendable."
                                    .to_string(),
                            module: module.name.clone(),
                            location: handler
                                .location
                                .map(|(s, e)| SourceLocation::from_bytes(&module.path, s, e)),
                            suggestion: Some(
                                "Check `list.length(value.policies(o.value)) <= max_policies` or \
                                use `value.without_lovelace` to verify exact token content."
                                    .to_string(),
                            ),
                            related_findings: vec![],
                            semantic_group: None,

                            evidence: None,
                        });
                    } else {
                        // Weak constraint present — still flag but note the partial mitigation
                        findings.push(Finding {
                            detector_name: self.name().to_string(),
                            severity: self.severity(),
                            confidence: Confidence::Possible,
                            title: format!(
                                "Weak native asset constraint in {}.{} — token dust risk",
                                validator.name, handler.name
                            ),
                            description:
                                "Spend handler checks individual asset quantities (quantity_of) \
                                or total asset count (flatten) but doesn't constrain the set of \
                                allowed policies. An attacker can inject additional native asset \
                                policies as dust, bloating the UTXO."
                                    .to_string(),
                            module: module.name.clone(),
                            location: handler
                                .location
                                .map(|(s, e)| SourceLocation::from_bytes(&module.path, s, e)),
                            suggestion: Some(
                                "Use `list.length(value.policies(o.value)) <= max_policies` or \
                                `value.without_lovelace` for exact token matching instead of \
                                individual quantity checks."
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
        tx_accesses: HashSet<String>,
        record_labels: HashSet<String>,
        function_calls: HashSet<String>,
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
                        tx_field_accesses: tx_accesses,
                        all_record_labels: record_labels,
                        function_calls,
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
    fn test_detects_unbounded_value() {
        let mut tx = HashSet::new();
        tx.insert("outputs".to_string());
        let mut labels = HashSet::new();
        labels.insert("address".to_string());
        labels.insert("value".to_string());
        // Has value check but no asset constraint

        let modules = make_spend_handler(tx, labels, HashSet::new());
        let findings = UnboundedValueSize.detect(&modules);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].title.contains("native asset count"));
    }

    #[test]
    fn test_no_finding_when_policies_checked() {
        let mut tx = HashSet::new();
        tx.insert("outputs".to_string());
        let mut labels = HashSet::new();
        labels.insert("value".to_string());
        let mut fns = HashSet::new();
        fns.insert("value.policies".to_string());

        let modules = make_spend_handler(tx, labels, fns);
        let findings = UnboundedValueSize.detect(&modules);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_weak_finding_when_quantity_of_used() {
        // quantity_of is a weak constraint — checks one asset but doesn't prevent dust
        let mut tx = HashSet::new();
        tx.insert("outputs".to_string());
        let mut labels = HashSet::new();
        labels.insert("value".to_string());
        let mut fns = HashSet::new();
        fns.insert("value.quantity_of".to_string());

        let modules = make_spend_handler(tx, labels, fns);
        let findings = UnboundedValueSize.detect(&modules);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].title.contains("Weak native asset constraint"));
    }

    #[test]
    fn test_weak_finding_when_flatten_used() {
        // flatten is a weak constraint — counts total items but doesn't constrain policies
        let mut tx = HashSet::new();
        tx.insert("outputs".to_string());
        let mut labels = HashSet::new();
        labels.insert("value".to_string());
        let mut fns = HashSet::new();
        fns.insert("assets.flatten".to_string());

        let modules = make_spend_handler(tx, labels, fns);
        let findings = UnboundedValueSize.detect(&modules);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].title.contains("Weak native asset constraint"));
    }

    #[test]
    fn test_no_finding_without_outputs() {
        let modules = make_spend_handler(HashSet::new(), HashSet::new(), HashSet::new());
        let findings = UnboundedValueSize.detect(&modules);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_no_finding_without_value_check() {
        // If value isn't checked at all, value-not-preserved covers it
        let mut tx = HashSet::new();
        tx.insert("outputs".to_string());
        let modules = make_spend_handler(tx, HashSet::new(), HashSet::new());
        let findings = UnboundedValueSize.detect(&modules);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_no_finding_with_flatten_and_length() {
        // flatten + list.length together = exact asset count check (strong)
        let mut tx = HashSet::new();
        tx.insert("outputs".to_string());
        let mut labels = HashSet::new();
        labels.insert("value".to_string());
        let mut fns = HashSet::new();
        fns.insert("assets.flatten".to_string());
        fns.insert("list.length".to_string());

        let modules = make_spend_handler(tx, labels, fns);
        let findings = UnboundedValueSize.detect(&modules);
        assert!(
            findings.is_empty(),
            "flatten + list.length should suppress as strong constraint"
        );
    }

    #[test]
    fn test_no_finding_with_withdrawal_delegation() {
        let mut tx = HashSet::new();
        tx.insert("outputs".to_string());
        tx.insert("withdrawals".to_string());
        let mut labels = HashSet::new();
        labels.insert("value".to_string());
        let mut fns = HashSet::new();
        fns.insert("pairs.has_key".to_string());

        let modules = make_spend_handler(tx, labels, fns);
        let findings = UnboundedValueSize.detect(&modules);
        assert!(
            findings.is_empty(),
            "withdrawal delegation should suppress value size finding"
        );
    }

    #[test]
    fn test_no_finding_with_admin_signature() {
        // Admin-signed handlers are not vulnerable to external token dust attacks
        let mut tx = HashSet::new();
        tx.insert("outputs".to_string());
        let mut labels = HashSet::new();
        labels.insert("value".to_string());

        let modules = vec![ModuleInfo {
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
                        tx_field_accesses: tx,
                        all_record_labels: labels,
                        requires_signature: true,
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

        let findings = UnboundedValueSize.detect(&modules);
        assert!(
            findings.is_empty(),
            "admin-signed handler should suppress token dust finding"
        );
    }

    #[test]
    fn test_finding_without_admin_signature() {
        // Non-admin handler without asset constraint should still fire
        let mut tx = HashSet::new();
        tx.insert("outputs".to_string());
        let mut labels = HashSet::new();
        labels.insert("value".to_string());

        let modules = vec![ModuleInfo {
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
                        tx_field_accesses: tx,
                        all_record_labels: labels,
                        requires_signature: false,
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

        let findings = UnboundedValueSize.detect(&modules);
        assert_eq!(
            findings.len(),
            1,
            "non-admin handler should still report token dust finding"
        );
    }
}
