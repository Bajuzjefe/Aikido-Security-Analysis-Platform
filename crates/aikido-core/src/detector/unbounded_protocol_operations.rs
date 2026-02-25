use crate::ast_walker::{ModuleInfo, ModuleKind};
use crate::detector::{Confidence, Detector, Finding, Severity, SourceLocation};

/// Detects handlers that iterate over both inputs AND outputs, creating
/// O(n*m) complexity risk that can lead to transaction budget exhaustion.
///
/// When a handler iterates both tx.inputs and tx.outputs (or their variants),
/// the resulting cross-product loop can be extremely expensive. An attacker
/// can pad the transaction with extra inputs/outputs to blow up execution cost
/// and cause legitimate transactions to fail with budget exceeded errors.
pub struct UnboundedProtocolOperations;

impl Detector for UnboundedProtocolOperations {
    fn name(&self) -> &str {
        "unbounded-protocol-operations"
    }

    fn description(&self) -> &str {
        "Detects handlers iterating both inputs and outputs (O(n*m) risk)"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn long_description(&self) -> &str {
        "When a handler iterates over both transaction inputs and outputs, the \
        combined iteration creates O(n*m) complexity. An attacker can pad a transaction \
        with many extra inputs and outputs to exhaust the execution budget, causing \
        legitimate transactions to fail.\n\n\
        This is especially dangerous when the handler uses nested iteration \
        (list.filter over inputs inside list.map over outputs).\n\n\
        Example (vulnerable):\n  spend(datum, redeemer, own_ref, self) {\n    \
        let my_inputs = list.filter(self.inputs, fn(i) { ... })\n    \
        let my_outputs = list.filter(self.outputs, fn(o) { ... })\n    \
        // Both lists attacker-controlled in size!\n  }\n\n\
        Fix: Use indexed access or fold with early termination, and constrain \
        input/output counts with `expect list.length(inputs) <= max_inputs`."
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
                    let signals = &handler.body_signals;

                    // Check if handler iterates both inputs and outputs
                    let iterates_inputs = signals.tx_list_iterations.contains("inputs");
                    let iterates_outputs = signals.tx_list_iterations.contains("outputs");

                    if !iterates_inputs || !iterates_outputs {
                        continue;
                    }

                    // Check for length bounds (mitigation)
                    let has_length_check = signals
                        .function_calls
                        .iter()
                        .any(|c| c.contains("list.length") || c.contains("length"));

                    if has_length_check {
                        continue;
                    }

                    findings.push(Finding {
                        detector_name: self.name().to_string(),
                        severity: self.severity(),
                        confidence: Confidence::Possible,
                        title: format!(
                            "Unbounded dual iteration in {}.{}",
                            validator.name, handler.name
                        ),
                        description: format!(
                            "Handler {}.{} iterates over both transaction inputs and outputs \
                            without length bounds. This creates O(n*m) complexity that an \
                            attacker can exploit by padding the transaction with extra \
                            inputs/outputs to exhaust the execution budget.",
                            validator.name, handler.name
                        ),
                        module: module.name.clone(),
                        location: handler
                            .location
                            .map(|(s, e)| SourceLocation::from_bytes(&module.path, s, e)),
                        suggestion: Some(
                            "Add length bounds on inputs/outputs: \
                            `expect list.length(self.inputs) <= max_inputs` or use \
                            indexed access instead of iteration."
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
    use std::collections::HashSet;

    fn make_handler(
        tx_list_iterations: HashSet<String>,
        func_calls: HashSet<String>,
    ) -> Vec<ModuleInfo> {
        vec![ModuleInfo {
            name: "test/validator".to_string(),
            path: "validator.ak".to_string(),
            kind: ModuleKind::Validator,
            validators: vec![ValidatorInfo {
                name: "pool".to_string(),
                params: vec![],
                handlers: vec![HandlerInfo {
                    name: "spend".to_string(),
                    params: vec![],
                    return_type: "Bool".to_string(),
                    location: None,
                    body_signals: BodySignals {
                        tx_list_iterations,
                        function_calls: func_calls,
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
    fn test_detects_dual_iteration() {
        let mut iters = HashSet::new();
        iters.insert("inputs".to_string());
        iters.insert("outputs".to_string());

        let modules = make_handler(iters, HashSet::new());
        let findings = UnboundedProtocolOperations.detect(&modules);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Medium);
    }

    #[test]
    fn test_no_finding_with_length_check() {
        let mut iters = HashSet::new();
        iters.insert("inputs".to_string());
        iters.insert("outputs".to_string());
        let mut calls = HashSet::new();
        calls.insert("list.length".to_string());

        let modules = make_handler(iters, calls);
        let findings = UnboundedProtocolOperations.detect(&modules);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_no_finding_with_only_inputs() {
        let mut iters = HashSet::new();
        iters.insert("inputs".to_string());

        let modules = make_handler(iters, HashSet::new());
        let findings = UnboundedProtocolOperations.detect(&modules);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_no_finding_with_only_outputs() {
        let mut iters = HashSet::new();
        iters.insert("outputs".to_string());

        let modules = make_handler(iters, HashSet::new());
        let findings = UnboundedProtocolOperations.detect(&modules);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_no_finding_with_no_iterations() {
        let modules = make_handler(HashSet::new(), HashSet::new());
        let findings = UnboundedProtocolOperations.detect(&modules);
        assert!(findings.is_empty());
    }
}
