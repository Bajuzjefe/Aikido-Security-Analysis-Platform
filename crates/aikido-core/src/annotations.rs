//! Aikido annotation parsing for specification language (Phase 5).
//!
//! Parses `@aikido:` annotations from Aiken source code comments:
//! - `@aikido:invariant value_conserved(input_value, output_value)`
//! - `@aikido:state_machine Forward { Created -> Accepted -> Deposited -> Exercised }`
//! - `@aikido:time_locked exercise_date`
//! - `@aikido:requires_burn position_token`
//! - `@aikido:conservation total_lended + pool_available == pool_total`

use std::collections::HashMap;

/// All annotations found in a module's source code.
#[derive(Debug, Clone, Default)]
pub struct ModuleAnnotations {
    pub invariants: Vec<Invariant>,
    pub state_machines: Vec<StateMachineSpec>,
    pub time_locks: Vec<TimeLock>,
    pub required_burns: Vec<RequiredBurn>,
    pub conservation_laws: Vec<ConservationLaw>,
}

/// An invariant specification.
#[derive(Debug, Clone)]
pub struct Invariant {
    pub name: String,
    pub params: Vec<String>,
    pub line: usize,
}

/// A state machine specification.
#[derive(Debug, Clone)]
pub struct StateMachineSpec {
    pub name: String,
    pub states: Vec<String>,
    pub transitions: Vec<(String, String)>,
    pub line: usize,
}

/// A time lock specification.
#[derive(Debug, Clone)]
pub struct TimeLock {
    pub field: String,
    pub line: usize,
}

/// A required burn specification.
#[derive(Debug, Clone)]
pub struct RequiredBurn {
    pub token: String,
    pub line: usize,
}

/// A conservation law specification.
#[derive(Debug, Clone)]
pub struct ConservationLaw {
    pub expression: String,
    pub line: usize,
}

/// Parse annotations from source code.
pub fn parse_annotations(source: &str) -> ModuleAnnotations {
    let mut annotations = ModuleAnnotations::default();

    for (line_num, line) in source.lines().enumerate() {
        let trimmed = line.trim();

        // Look for @aikido: annotations in comments
        let annotation = if trimmed.starts_with("///") {
            trimmed.strip_prefix("///").unwrap_or("").trim()
        } else if trimmed.starts_with("//") {
            trimmed.strip_prefix("//").unwrap_or("").trim()
        } else {
            continue;
        };

        if !annotation.starts_with("@aikido:") {
            continue;
        }

        let content = annotation.strip_prefix("@aikido:").unwrap_or("").trim();

        if let Some(rest) = content.strip_prefix("invariant") {
            if let Some(inv) = parse_invariant(rest.trim(), line_num + 1) {
                annotations.invariants.push(inv);
            }
        } else if let Some(rest) = content.strip_prefix("state_machine") {
            if let Some(sm) = parse_state_machine(rest.trim(), line_num + 1) {
                annotations.state_machines.push(sm);
            }
        } else if let Some(rest) = content.strip_prefix("time_locked") {
            annotations.time_locks.push(TimeLock {
                field: rest.trim().to_string(),
                line: line_num + 1,
            });
        } else if let Some(rest) = content.strip_prefix("requires_burn") {
            annotations.required_burns.push(RequiredBurn {
                token: rest.trim().to_string(),
                line: line_num + 1,
            });
        } else if let Some(rest) = content.strip_prefix("conservation") {
            annotations.conservation_laws.push(ConservationLaw {
                expression: rest.trim().to_string(),
                line: line_num + 1,
            });
        }
    }

    annotations
}

fn parse_invariant(text: &str, line: usize) -> Option<Invariant> {
    // Format: name(param1, param2)
    let open = text.find('(')?;
    let close = text.find(')')?;
    let name = text[..open].trim().to_string();
    let params: Vec<String> = text[open + 1..close]
        .split(',')
        .map(|p| p.trim().to_string())
        .filter(|p| !p.is_empty())
        .collect();

    Some(Invariant { name, params, line })
}

fn parse_state_machine(text: &str, line: usize) -> Option<StateMachineSpec> {
    // Format: Name { State1 -> State2 -> State3 }
    let brace_open = text.find('{')?;
    let brace_close = text.find('}')?;
    let name = text[..brace_open].trim().to_string();
    let body = text[brace_open + 1..brace_close].trim();

    let states: Vec<String> = body
        .split("->")
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    let mut transitions = Vec::new();
    for i in 0..states.len().saturating_sub(1) {
        transitions.push((states[i].clone(), states[i + 1].clone()));
    }

    Some(StateMachineSpec {
        name,
        states,
        transitions,
        line,
    })
}

/// Parse annotations from all modules that have source code.
pub fn parse_all_annotations(
    modules: &[crate::ast_walker::ModuleInfo],
) -> HashMap<String, ModuleAnnotations> {
    let mut all = HashMap::new();

    for module in modules {
        if let Some(ref source) = module.source_code {
            let annotations = parse_annotations(source);
            if !annotations.invariants.is_empty()
                || !annotations.state_machines.is_empty()
                || !annotations.time_locks.is_empty()
                || !annotations.required_burns.is_empty()
                || !annotations.conservation_laws.is_empty()
            {
                all.insert(module.name.clone(), annotations);
            }
        }
    }

    all
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_invariant() {
        let source = r#"
/// @aikido:invariant value_conserved(input_value, output_value)
fn validate() -> Bool {
"#;
        let annotations = parse_annotations(source);
        assert_eq!(annotations.invariants.len(), 1);
        assert_eq!(annotations.invariants[0].name, "value_conserved");
        assert_eq!(
            annotations.invariants[0].params,
            vec!["input_value", "output_value"]
        );
    }

    #[test]
    fn test_parse_state_machine() {
        let source = r#"
/// @aikido:state_machine Forward { Created -> Accepted -> Deposited -> Exercised }
"#;
        let annotations = parse_annotations(source);
        assert_eq!(annotations.state_machines.len(), 1);
        assert_eq!(annotations.state_machines[0].name, "Forward");
        assert_eq!(annotations.state_machines[0].states.len(), 4);
        assert_eq!(annotations.state_machines[0].transitions.len(), 3);
    }

    #[test]
    fn test_parse_time_locked() {
        let source = "// @aikido:time_locked exercise_date\n";
        let annotations = parse_annotations(source);
        assert_eq!(annotations.time_locks.len(), 1);
        assert_eq!(annotations.time_locks[0].field, "exercise_date");
    }

    #[test]
    fn test_parse_requires_burn() {
        let source = "/// @aikido:requires_burn position_token\n";
        let annotations = parse_annotations(source);
        assert_eq!(annotations.required_burns.len(), 1);
        assert_eq!(annotations.required_burns[0].token, "position_token");
    }

    #[test]
    fn test_parse_conservation() {
        let source = "/// @aikido:conservation total_lended + pool_available == pool_total\n";
        let annotations = parse_annotations(source);
        assert_eq!(annotations.conservation_laws.len(), 1);
        assert!(annotations.conservation_laws[0]
            .expression
            .contains("pool_total"));
    }

    #[test]
    fn test_no_annotations() {
        let source = "fn validate() -> Bool { True }";
        let annotations = parse_annotations(source);
        assert!(annotations.invariants.is_empty());
        assert!(annotations.state_machines.is_empty());
    }

    #[test]
    fn test_multiple_annotations() {
        let source = r#"
/// @aikido:invariant value_conserved(input, output)
/// @aikido:requires_burn position_token
/// @aikido:state_machine Pool { Active -> Closing -> Closed }
fn validate() -> Bool { True }
"#;
        let annotations = parse_annotations(source);
        assert_eq!(annotations.invariants.len(), 1);
        assert_eq!(annotations.required_burns.len(), 1);
        assert_eq!(annotations.state_machines.len(), 1);
    }
}
