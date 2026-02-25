//! State machine extraction from redeemer patterns (Phase 5).
//!
//! Auto-extracts state machines from validator code by analyzing:
//! 1. Redeemer type constructors (each = a transition/action)
//! 2. When branch patterns (preconditions per action)
//! 3. Output datum construction (postconditions per action)
//!
//! Checks for completeness: all redeemer actions handled, no orphan states,
//! all transitions have valid pre/post conditions.

use crate::ast_walker::{DataTypeInfo, HandlerInfo, ModuleInfo, ModuleKind, ValidatorInfo};
use crate::body_analysis::WhenBranchInfo;

/// A state machine extracted from a validator.
#[derive(Debug, Clone)]
pub struct StateMachine {
    /// Module name.
    pub module: String,
    /// Validator name.
    pub validator: String,
    /// Handler name.
    pub handler: String,
    /// The redeemer type name.
    pub redeemer_type: String,
    /// All possible actions (redeemer constructors).
    pub actions: Vec<Action>,
    /// Detected state transitions.
    pub transitions: Vec<Transition>,
    /// Issues found in the state machine.
    pub issues: Vec<StateMachineIssue>,
}

/// An action (redeemer constructor).
#[derive(Debug, Clone)]
pub struct Action {
    pub name: String,
    pub fields: Vec<String>,
    pub has_handler: bool,
}

/// A state transition.
#[derive(Debug, Clone)]
pub struct Transition {
    pub action: String,
    pub preconditions: Vec<String>,
    pub postconditions: Vec<String>,
    pub produces_output: bool,
    pub is_terminal: bool,
}

/// An issue with the state machine.
#[derive(Debug, Clone)]
pub struct StateMachineIssue {
    pub issue_type: StateMachineIssueType,
    pub action: String,
    pub description: String,
}

/// Types of state machine issues.
#[derive(Debug, Clone, PartialEq)]
pub enum StateMachineIssueType {
    /// Redeemer action has no handler/branch.
    UnhandledAction,
    /// Action handler always succeeds (literal True).
    AlwaysSucceeds,
    /// Action handler always fails.
    AlwaysFails,
    /// Terminal action (close/cancel/liquidate) doesn't burn tokens.
    TerminalWithoutBurn,
    /// Non-terminal action doesn't produce continuing output.
    NonTerminalWithoutOutput,
    /// Action doesn't validate state preconditions.
    MissingPrecondition,
    /// Catchall branch accepts unknown actions.
    CatchallAcceptsUnknown,
}

/// Extract state machines from all validator modules.
pub fn extract_state_machines(modules: &[ModuleInfo]) -> Vec<StateMachine> {
    let mut machines = Vec::new();

    for module in modules {
        if module.kind != ModuleKind::Validator {
            continue;
        }

        for validator in &module.validators {
            for handler in &validator.handlers {
                if let Some(sm) = extract_handler_state_machine(module, validator, handler) {
                    machines.push(sm);
                }
            }
        }
    }

    machines
}

/// Extract a state machine from a single handler.
fn extract_handler_state_machine(
    module: &ModuleInfo,
    validator: &ValidatorInfo,
    handler: &HandlerInfo,
) -> Option<StateMachine> {
    let signals = &handler.body_signals;

    // Need when branches (pattern matching on redeemer) to extract state machine
    if signals.when_branches.is_empty() {
        return None;
    }

    // Find the redeemer type from handler params
    let redeemer_type = find_redeemer_type(handler)?;

    // Find the DataType definition for the redeemer
    let redeemer_dt = find_data_type(module, &redeemer_type);

    // Build actions from either the DataType constructors or the when branch patterns
    let actions = build_actions(&redeemer_dt, &signals.when_branches);

    if actions.is_empty() {
        return None;
    }

    // Analyze each branch for pre/postconditions
    let transitions = build_transitions(&actions, handler);

    // Check for issues
    let issues =
        check_state_machine_issues(&actions, &transitions, &signals.when_branches, handler);

    Some(StateMachine {
        module: module.name.clone(),
        validator: validator.name.clone(),
        handler: handler.name.clone(),
        redeemer_type,
        actions,
        transitions,
        issues,
    })
}

fn find_redeemer_type(handler: &HandlerInfo) -> Option<String> {
    let redeemer_idx = if handler.name == "spend" { 1 } else { 0 };
    handler
        .params
        .get(redeemer_idx)
        .map(|p| p.type_name.clone())
}

fn find_data_type<'a>(module: &'a ModuleInfo, type_name: &str) -> Option<&'a DataTypeInfo> {
    // Check this module first, then search all modules data types
    module.data_types.iter().find(|dt| dt.name == type_name)
}

fn build_actions(redeemer_dt: &Option<&DataTypeInfo>, branches: &[WhenBranchInfo]) -> Vec<Action> {
    let mut actions = Vec::new();

    if let Some(dt) = redeemer_dt {
        // Use the DataType constructors
        for constructor in &dt.constructors {
            let has_handler = branches
                .iter()
                .any(|b| b.pattern_text.contains(&constructor.name));
            actions.push(Action {
                name: constructor.name.clone(),
                fields: constructor
                    .fields
                    .iter()
                    .filter_map(|f| f.label.clone())
                    .collect(),
                has_handler,
            });
        }
    } else {
        // Infer from branch patterns
        for branch in branches {
            if !branch.is_catchall {
                actions.push(Action {
                    name: branch.pattern_text.clone(),
                    fields: vec![],
                    has_handler: true,
                });
            }
        }
    }

    actions
}

fn build_transitions(actions: &[Action], handler: &HandlerInfo) -> Vec<Transition> {
    let signals = &handler.body_signals;
    let mut transitions = Vec::new();

    for action in actions {
        if !action.has_handler {
            continue;
        }

        let is_terminal = is_terminal_action(&action.name);
        let produces_output = (signals.tx_field_accesses.contains("outputs")
            || has_output_extraction_call(handler))
            && !is_terminal;

        let mut preconditions = Vec::new();
        let mut postconditions = Vec::new();

        // Check if datum fields are validated (preconditions)
        for field in &signals.datum_field_accesses {
            preconditions.push(format!("datum.{field} validated"));
        }

        // Check if output datum is constructed (postconditions)
        if signals.has_record_update {
            postconditions.push("datum updated via record update".to_string());
        }
        if signals.has_datum_continuity_assertion {
            postconditions.push("datum continuity asserted".to_string());
        }

        transitions.push(Transition {
            action: action.name.clone(),
            preconditions,
            postconditions,
            produces_output,
            is_terminal,
        });
    }

    transitions
}

const TERMINAL_PATTERNS: &[&str] = &[
    "close",
    "cancel",
    "liquidate",
    "redeem",
    "settle",
    "destroy",
    "burn",
    "remove",
    "exit",
    "terminate",
    "expire",
    "withdraw",
];

fn is_terminal_action(name: &str) -> bool {
    let lower = name.to_lowercase();
    TERMINAL_PATTERNS.iter().any(|p| lower.contains(p))
}

fn has_output_extraction_call(handler: &HandlerInfo) -> bool {
    handler.body_signals.function_calls.iter().any(|call| {
        call.contains("get_address_outputs")
            || call.contains("find_output")
            || call.contains("own_output")
            || call.contains("continuing_output")
            || call.contains("script_output")
    })
}

fn check_state_machine_issues(
    actions: &[Action],
    transitions: &[Transition],
    branches: &[WhenBranchInfo],
    handler: &HandlerInfo,
) -> Vec<StateMachineIssue> {
    let mut issues = Vec::new();

    // Check for unhandled actions
    for action in actions {
        if !action.has_handler {
            issues.push(StateMachineIssue {
                issue_type: StateMachineIssueType::UnhandledAction,
                action: action.name.clone(),
                description: format!(
                    "Redeemer action '{}' has no matching when branch",
                    action.name
                ),
            });
        }
    }

    // Check for always-succeeds branches
    for branch in branches {
        if !branch.is_catchall && branch.body_is_literal_true {
            issues.push(StateMachineIssue {
                issue_type: StateMachineIssueType::AlwaysSucceeds,
                action: branch.pattern_text.clone(),
                description: format!(
                    "Action '{}' always succeeds without validation",
                    branch.pattern_text
                ),
            });
        }
    }

    // Check for catchall that accepts unknown actions
    let has_catchall_true = branches
        .iter()
        .any(|b| b.is_catchall && b.body_is_literal_true);
    if has_catchall_true {
        issues.push(StateMachineIssue {
            issue_type: StateMachineIssueType::CatchallAcceptsUnknown,
            action: "_".to_string(),
            description: "Catchall branch accepts unknown redeemer actions".to_string(),
        });
    }

    // Check terminal actions for burn
    for transition in transitions {
        if transition.is_terminal && !handler.body_signals.tx_field_accesses.contains("mint") {
            issues.push(StateMachineIssue {
                issue_type: StateMachineIssueType::TerminalWithoutBurn,
                action: transition.action.clone(),
                description: format!(
                    "Terminal action '{}' doesn't access mint field (may need token burn)",
                    transition.action
                ),
            });
        }
    }

    // Check non-terminal actions produce output
    for transition in transitions {
        if !transition.is_terminal
            && !transition.produces_output
            && !handler.body_signals.tx_field_accesses.contains("outputs")
            && !has_output_extraction_call(handler)
        {
            issues.push(StateMachineIssue {
                issue_type: StateMachineIssueType::NonTerminalWithoutOutput,
                action: transition.action.clone(),
                description: format!(
                    "Non-terminal action '{}' doesn't produce continuing output",
                    transition.action
                ),
            });
        }
    }

    issues
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast_walker::*;
    use crate::body_analysis::BodySignals;

    #[test]
    fn test_extract_from_branches() {
        let mut signals = BodySignals::default();
        signals.when_branches.push(WhenBranchInfo {
            pattern_text: "Update".to_string(),
            is_catchall: false,
            body_is_literal_true: false,
            body_is_error: false,
        });
        signals.when_branches.push(WhenBranchInfo {
            pattern_text: "Close".to_string(),
            is_catchall: false,
            body_is_literal_true: false,
            body_is_error: false,
        });
        signals.tx_field_accesses.insert("outputs".to_string());

        let module = ModuleInfo {
            name: "test/pool".to_string(),
            path: "pool.ak".to_string(),
            kind: ModuleKind::Validator,
            validators: vec![ValidatorInfo {
                name: "pool".to_string(),
                params: vec![],
                handlers: vec![HandlerInfo {
                    name: "spend".to_string(),
                    params: vec![
                        ParamInfo {
                            name: "datum".to_string(),
                            type_name: "PoolDatum".to_string(),
                        },
                        ParamInfo {
                            name: "redeemer".to_string(),
                            type_name: "PoolRedeemer".to_string(),
                        },
                    ],
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
        };

        let machines = extract_state_machines(&[module]);
        assert_eq!(machines.len(), 1);
        assert_eq!(machines[0].actions.len(), 2);
        assert_eq!(machines[0].actions[0].name, "Update");
        assert_eq!(machines[0].actions[1].name, "Close");
    }

    #[test]
    fn test_terminal_action_detection() {
        assert!(is_terminal_action("Close"));
        assert!(is_terminal_action("Liquidate"));
        assert!(is_terminal_action("cancel_position"));
        assert!(!is_terminal_action("Update"));
        assert!(!is_terminal_action("Deposit"));
    }

    #[test]
    fn test_catchall_issue() {
        let mut signals = BodySignals::default();
        signals.when_branches.push(WhenBranchInfo {
            pattern_text: "Update".to_string(),
            is_catchall: false,
            body_is_literal_true: false,
            body_is_error: false,
        });
        signals.when_branches.push(WhenBranchInfo {
            pattern_text: "_".to_string(),
            is_catchall: true,
            body_is_literal_true: true,
            body_is_error: false,
        });

        let module = ModuleInfo {
            name: "test/pool".to_string(),
            path: "pool.ak".to_string(),
            kind: ModuleKind::Validator,
            validators: vec![ValidatorInfo {
                name: "pool".to_string(),
                params: vec![],
                handlers: vec![HandlerInfo {
                    name: "spend".to_string(),
                    params: vec![
                        ParamInfo {
                            name: "datum".to_string(),
                            type_name: "D".to_string(),
                        },
                        ParamInfo {
                            name: "redeemer".to_string(),
                            type_name: "R".to_string(),
                        },
                    ],
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
        };

        let machines = extract_state_machines(&[module]);
        assert!(!machines.is_empty());
        assert!(machines[0]
            .issues
            .iter()
            .any(|i| i.issue_type == StateMachineIssueType::CatchallAcceptsUnknown));
    }

    #[test]
    fn test_helper_output_call_counts_as_output_production() {
        let mut signals = BodySignals::default();
        signals.when_branches.push(WhenBranchInfo {
            pattern_text: "Update".to_string(),
            is_catchall: false,
            body_is_literal_true: false,
            body_is_error: false,
        });
        signals
            .function_calls
            .insert("utils.get_address_outputs".to_string());

        let module = ModuleInfo {
            name: "test/pool".to_string(),
            path: "pool.ak".to_string(),
            kind: ModuleKind::Validator,
            validators: vec![ValidatorInfo {
                name: "pool".to_string(),
                params: vec![],
                handlers: vec![HandlerInfo {
                    name: "spend".to_string(),
                    params: vec![
                        ParamInfo {
                            name: "datum".to_string(),
                            type_name: "D".to_string(),
                        },
                        ParamInfo {
                            name: "redeemer".to_string(),
                            type_name: "R".to_string(),
                        },
                    ],
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
        };

        let machines = extract_state_machines(&[module]);
        assert_eq!(machines.len(), 1);
        assert!(
            !machines[0]
                .issues
                .iter()
                .any(|i| i.issue_type == StateMachineIssueType::NonTerminalWithoutOutput),
            "helper output extraction should avoid NonTerminalWithoutOutput FP"
        );
    }
}
