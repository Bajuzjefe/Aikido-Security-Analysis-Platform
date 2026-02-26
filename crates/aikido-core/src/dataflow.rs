//! Dataflow and taint analysis for Aikido.
//!
//! Performs taint analysis on handler body signals to track how attacker-controlled
//! data (redeemer) flows through the program and whether it's properly sanitized
//! before reaching sensitive operations (division, output address, arithmetic).
//!
//! This is a practical improvement over the flat `redeemer_tainted_vars: HashSet`
//! approach — it tracks taint labels, sanitization, and flow paths.

use std::collections::{HashMap, HashSet};

use crate::ast_walker::{HandlerInfo, ModuleInfo, ModuleKind};
use crate::body_analysis::BodySignals;
use crate::ir::{TaintFlow, TaintLabel, TaintResults, TaintSink, TaintSource};

/// Run taint analysis on a handler's body signals and parameters.
///
/// Initializes taint from redeemer/datum parameters, propagates through
/// the signal information, checks guards, and reports unsanitized flows
/// to sensitive sinks.
pub fn analyze_handler_taint(handler: &HandlerInfo) -> TaintResults {
    let signals = &handler.body_signals;
    let mut results = TaintResults::default();

    // Step 1: Initialize taint sources from parameters
    initialize_taint_sources(handler, &mut results);

    // Step 2: Propagate taint through variable assignments
    propagate_taint(signals, &mut results);

    // Step 3: Check sanitization (guards that validate tainted variables)
    check_sanitization(signals, &mut results);

    // Step 4: Detect taint reaching sensitive sinks
    detect_sink_flows(signals, &mut results);

    // Step 5: Identify partially guarded variables
    identify_partial_guards(signals, &mut results);

    results
}

/// Run taint analysis across all handlers in all validator modules.
pub fn analyze_all_modules(
    modules: &[ModuleInfo],
) -> HashMap<(String, String, String), TaintResults> {
    let mut all_results = HashMap::new();

    for module in modules {
        if module.kind != ModuleKind::Validator {
            continue;
        }

        for validator in &module.validators {
            for handler in &validator.handlers {
                let results = analyze_handler_taint(handler);
                all_results.insert(
                    (
                        module.name.clone(),
                        validator.name.clone(),
                        handler.name.clone(),
                    ),
                    results,
                );
            }
        }
    }

    all_results
}

/// Initialize taint sources from handler parameters.
fn initialize_taint_sources(handler: &HandlerInfo, results: &mut TaintResults) {
    let params = &handler.params;
    let signals = &handler.body_signals;

    // For spend handlers: param[0] = datum, param[1] = redeemer, param[2] = own_ref, param[3] = tx
    // For mint handlers: param[0] = redeemer, param[last] = tx
    if handler.name == "spend" {
        if params.len() >= 2 {
            // Redeemer is fully attacker-controlled
            let redeemer = &params[1];
            results
                .var_taint
                .insert(redeemer.name.clone(), TaintLabel::AttackerControlled);
            // Mark all redeemer-derived variables
            for var in &signals.redeemer_tainted_vars {
                results
                    .var_taint
                    .insert(var.clone(), TaintLabel::AttackerControlled);
            }
        }
        if !params.is_empty() {
            // Datum is partially trusted (on-chain state)
            let datum = &params[0];
            results
                .var_taint
                .insert(datum.name.clone(), TaintLabel::PartiallyTrusted);
            // Datum field accesses inherit partial trust
            for field in &signals.datum_field_accesses {
                results
                    .var_taint
                    .insert(field.clone(), TaintLabel::PartiallyTrusted);
            }
        }
    } else if (handler.name == "mint" || handler.name == "withdraw") && !params.is_empty() {
        // First param is redeemer for non-spend handlers
        let redeemer = &params[0];
        results
            .var_taint
            .insert(redeemer.name.clone(), TaintLabel::AttackerControlled);
        for var in &signals.redeemer_tainted_vars {
            results
                .var_taint
                .insert(var.clone(), TaintLabel::AttackerControlled);
        }
    }
}

/// Propagate taint through tracked variable references.
fn propagate_taint(signals: &BodySignals, results: &mut TaintResults) {
    // Iterate over redeemer-tainted variables and mark any derived variables
    let tainted: HashSet<String> = signals.redeemer_tainted_vars.clone();

    // Variables that appear in expect_some_vars after tainted assignment
    for var in &signals.expect_some_vars {
        if tainted.iter().any(|t| var.contains(t)) {
            results
                .var_taint
                .insert(var.clone(), TaintLabel::AttackerControlled);
        }
    }

    // Subtraction operands derived from tainted vars
    for operand in &signals.subtraction_operands {
        if tainted.contains(operand) || results.var_taint.contains_key(operand) {
            results
                .var_taint
                .insert(format!("{operand}_result"), TaintLabel::AttackerControlled);
        }
    }
}

/// Check which tainted variables pass through guards (sanitization).
fn check_sanitization(signals: &BodySignals, results: &mut TaintResults) {
    // Variables in guarded_vars have been compared/checked
    for var in &signals.guarded_vars {
        if results.var_taint.contains_key(var) {
            results.sanitized_vars.insert(var.clone());
        }
    }

    // Structured guards provide more detail
    for guard in &signals.guarded_operations {
        if results.var_taint.contains_key(&guard.guarded_var) {
            results.sanitized_vars.insert(guard.guarded_var.clone());
        }
    }

    // Variables that go through expect (pattern match) are partially sanitized
    for var in &signals.expect_some_vars {
        if results.var_taint.contains_key(var) {
            results.sanitized_vars.insert(var.clone());
        }
    }
}

/// Detect tainted data reaching sensitive sinks.
fn detect_sink_flows(signals: &BodySignals, results: &mut TaintResults) {
    let tainted_vars: HashSet<&String> = results
        .var_taint
        .iter()
        .filter(|(_, label)| label.is_tainted())
        .map(|(name, _)| name)
        .collect();

    // Sink 1: Division with tainted divisor
    if signals.has_division {
        for divisor in &signals.division_divisors {
            if tainted_vars.contains(divisor) && !results.sanitized_vars.contains(divisor) {
                results.unsanitized_sink_flows.push(TaintFlow {
                    source: TaintSource::Redeemer,
                    label: TaintLabel::AttackerControlled,
                    sink: TaintSink::Division,
                    variable_chain: vec![divisor.clone()],
                    is_sanitized: false,
                    sanitizer: None,
                });
            }
        }
    }

    // Sink 2: Subtraction with tainted operands (integer underflow)
    if signals.has_subtraction {
        for operand in &signals.subtraction_operands {
            if tainted_vars.contains(operand) && !results.sanitized_vars.contains(operand) {
                results.unsanitized_sink_flows.push(TaintFlow {
                    source: TaintSource::Redeemer,
                    label: TaintLabel::AttackerControlled,
                    sink: TaintSink::Arithmetic,
                    variable_chain: vec![operand.clone()],
                    is_sanitized: false,
                    sanitizer: None,
                });
            }
        }
    }

    // Sink 3: Tainted variables used without guard (general)
    for var in &tainted_vars {
        if !results.sanitized_vars.contains(*var) {
            // Check if this variable reaches any known sink pattern
            let reaches_output = signals.tx_field_accesses.contains("outputs")
                && signals.var_references.contains(*var);
            if reaches_output {
                results.flows.push(TaintFlow {
                    source: TaintSource::Redeemer,
                    label: TaintLabel::AttackerControlled,
                    sink: TaintSink::OutputValue,
                    variable_chain: vec![(*var).clone()],
                    is_sanitized: false,
                    sanitizer: None,
                });
            }
        }
    }

    results.paths_analyzed = 1; // Flat analysis = 1 path
}

/// Identify variables that are guarded on some execution paths but not others.
fn identify_partial_guards(signals: &BodySignals, results: &mut TaintResults) {
    // Variables that appear in both guarded_vars and redeemer_tainted_vars
    // but also appear in when branches where they might not be guarded
    for var in &signals.redeemer_tainted_vars {
        let is_guarded_somewhere = signals.guarded_vars.contains(var);
        let appears_in_branches = signals
            .when_branches
            .iter()
            .any(|b| !b.is_catchall && !b.body_is_error);

        if is_guarded_somewhere && appears_in_branches {
            results.partially_guarded_vars.insert(var.clone());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast_walker::ParamInfo;
    use crate::body_analysis::BodySignals;

    fn make_spend_handler(
        redeemer_name: &str,
        datum_name: &str,
        signals: BodySignals,
    ) -> HandlerInfo {
        HandlerInfo {
            name: "spend".to_string(),
            params: vec![
                ParamInfo {
                    name: datum_name.to_string(),
                    type_name: "PositionDatum".to_string(),
                },
                ParamInfo {
                    name: redeemer_name.to_string(),
                    type_name: "PositionRedeemer".to_string(),
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
            body_signals: signals,
        }
    }

    #[test]
    fn test_redeemer_taint_initialization() {
        let mut signals = BodySignals::default();
        signals
            .redeemer_tainted_vars
            .insert("redeemer_amount".to_string());

        let handler = make_spend_handler("redeemer", "datum", signals);
        let results = analyze_handler_taint(&handler);

        assert!(results.is_tainted("redeemer"));
        assert!(results.is_tainted("redeemer_amount"));
        // Datum is PartiallyTrusted (on-chain state), not AttackerControlled
        assert!(results.is_tainted("datum"));
        assert_eq!(
            results.var_taint.get("datum"),
            Some(&TaintLabel::PartiallyTrusted)
        );
        assert_eq!(
            results.var_taint.get("redeemer"),
            Some(&TaintLabel::AttackerControlled)
        );
    }

    #[test]
    fn test_datum_partial_trust() {
        let mut signals = BodySignals::default();
        signals
            .datum_field_accesses
            .insert("stake_lovelace".to_string());

        let handler = make_spend_handler("redeemer", "datum", signals);
        let results = analyze_handler_taint(&handler);

        assert!(results.is_tainted("datum"));
        assert!(results.is_tainted("stake_lovelace"));
    }

    #[test]
    fn test_guarded_variable_sanitized() {
        let mut signals = BodySignals::default();
        signals.redeemer_tainted_vars.insert("amount".to_string());
        signals.guarded_vars.insert("amount".to_string());

        let handler = make_spend_handler("redeemer", "datum", signals);
        let results = analyze_handler_taint(&handler);

        assert!(results.is_sanitized("amount"));
    }

    #[test]
    fn test_unsanitized_division_detected() {
        let mut signals = BodySignals::default();
        signals.redeemer_tainted_vars.insert("divisor".to_string());
        signals.has_division = true;
        signals.division_divisors.insert("divisor".to_string());

        let handler = make_spend_handler("redeemer", "datum", signals);
        let results = analyze_handler_taint(&handler);

        assert!(!results.unsanitized_sink_flows.is_empty());
        assert_eq!(results.unsanitized_sink_flows[0].sink, TaintSink::Division);
    }

    #[test]
    fn test_sanitized_division_not_reported() {
        let mut signals = BodySignals::default();
        signals.redeemer_tainted_vars.insert("divisor".to_string());
        signals.has_division = true;
        signals.division_divisors.insert("divisor".to_string());
        signals.guarded_vars.insert("divisor".to_string()); // guarded!

        let handler = make_spend_handler("redeemer", "datum", signals);
        let results = analyze_handler_taint(&handler);

        assert!(
            results.unsanitized_sink_flows.is_empty(),
            "guarded divisor should not be flagged"
        );
    }

    #[test]
    fn test_partial_guard_detection() {
        let mut signals = BodySignals::default();
        signals.redeemer_tainted_vars.insert("amount".to_string());
        signals.guarded_vars.insert("amount".to_string());
        signals
            .when_branches
            .push(crate::body_analysis::WhenBranchInfo {
                pattern_text: "Update".to_string(),
                is_catchall: false,
                body_is_literal_true: false,
                body_is_error: false,
            });

        let handler = make_spend_handler("redeemer", "datum", signals);
        let results = analyze_handler_taint(&handler);

        assert!(results.partially_guarded_vars.contains("amount"));
    }
}
