//! Feature #73: Symbolic execution — explore execution paths with symbolic values.
//! Feature #74: Constraint propagation — track numeric ranges through branches.
//!
//! This module provides lightweight symbolic analysis for Aiken validators.
//! It tracks symbolic values through when/match branches and propagates
//! constraints to detect impossible conditions and unreachable paths.

use std::collections::HashMap;

/// A symbolic value representing a constraint on a variable.
#[derive(Debug, Clone, PartialEq)]
pub enum SymbolicValue {
    /// Unconstrained — any value is possible.
    Any,
    /// Constrained to a specific constructor (from when/match).
    Constructor(String),
    /// Constrained to a numeric range.
    Range { min: Option<i64>, max: Option<i64> },
    /// Known to be True or False.
    Boolean(bool),
}

impl SymbolicValue {
    /// Check if this value is impossible (empty range).
    pub fn is_impossible(&self) -> bool {
        match self {
            SymbolicValue::Range {
                min: Some(lo),
                max: Some(hi),
            } => lo > hi,
            _ => false,
        }
    }

    /// Narrow this value with an equality constraint.
    pub fn narrow_eq(&self, constructor: &str) -> SymbolicValue {
        match self {
            SymbolicValue::Any => SymbolicValue::Constructor(constructor.to_string()),
            SymbolicValue::Constructor(c) if c == constructor => self.clone(),
            SymbolicValue::Constructor(_) => SymbolicValue::Range {
                min: Some(1),
                max: Some(0),
            }, // impossible
            _ => self.clone(),
        }
    }

    /// Narrow with a less-than constraint.
    pub fn narrow_lt(&self, bound: i64) -> SymbolicValue {
        match self {
            SymbolicValue::Any => SymbolicValue::Range {
                min: None,
                max: Some(bound - 1),
            },
            SymbolicValue::Range { min, max } => SymbolicValue::Range {
                min: *min,
                max: Some(max.map_or(bound - 1, |m| m.min(bound - 1))),
            },
            _ => self.clone(),
        }
    }

    /// Narrow with a greater-than constraint.
    pub fn narrow_gt(&self, bound: i64) -> SymbolicValue {
        match self {
            SymbolicValue::Any => SymbolicValue::Range {
                min: Some(bound + 1),
                max: None,
            },
            SymbolicValue::Range { min, max } => SymbolicValue::Range {
                min: Some(min.map_or(bound + 1, |m| m.max(bound + 1))),
                max: *max,
            },
            _ => self.clone(),
        }
    }
}

/// Symbolic execution context tracking variable constraints per path.
#[derive(Debug, Clone, Default)]
pub struct SymbolicContext {
    /// Variable name → current symbolic value.
    pub bindings: HashMap<String, SymbolicValue>,
    /// Paths explored so far.
    pub path_count: usize,
    /// Impossible paths detected.
    pub impossible_paths: Vec<String>,
}

impl SymbolicContext {
    pub fn new() -> Self {
        Self::default()
    }

    /// Bind a variable to a symbolic value.
    pub fn bind(&mut self, name: &str, value: SymbolicValue) {
        self.bindings.insert(name.to_string(), value);
    }

    /// Get the current symbolic value for a variable.
    pub fn get(&self, name: &str) -> &SymbolicValue {
        self.bindings.get(name).unwrap_or(&SymbolicValue::Any)
    }

    /// Record an explored path.
    pub fn explore_path(&mut self, branch_desc: &str) {
        self.path_count += 1;
        // Check if any binding is impossible
        for (var, val) in &self.bindings {
            if val.is_impossible() {
                self.impossible_paths
                    .push(format!("{branch_desc}: {var} has impossible constraints"));
            }
        }
    }

    /// Fork context for a branch — returns a clone for the branch path.
    pub fn fork(&self) -> Self {
        Self {
            bindings: self.bindings.clone(),
            path_count: self.path_count,
            impossible_paths: Vec::new(),
        }
    }
}

/// Analyze when/match branches symbolically to find impossible paths.
/// Takes branch patterns and returns which branches are potentially unreachable.
pub fn analyze_branches_symbolically(
    subject_var: &str,
    branches: &[(String, bool)], // (pattern_text, is_catchall)
) -> Vec<String> {
    let mut impossible = Vec::new();
    let mut ctx = SymbolicContext::new();
    ctx.bind(subject_var, SymbolicValue::Any);

    let mut seen_constructors = Vec::new();

    for (pattern, is_catchall) in branches {
        if *is_catchall {
            // Catchall after all constructors covered = dead code
            if !seen_constructors.is_empty() {
                // This is valid — catchall handles remaining cases
            }
            continue;
        }

        // Check if this constructor was already matched
        if seen_constructors.contains(pattern) {
            impossible.push(format!(
                "Branch '{pattern}' is unreachable — already matched above"
            ));
        }

        seen_constructors.push(pattern.clone());
    }

    impossible
}

/// Propagate numeric constraints through a series of comparisons.
/// Returns the final range for the variable.
pub fn propagate_constraints(
    constraints: &[(String, i64)], // ("lt"|"gt"|"eq", value)
) -> SymbolicValue {
    let mut value = SymbolicValue::Any;

    for (op, bound) in constraints {
        value = match op.as_str() {
            "lt" => value.narrow_lt(*bound),
            "gt" => value.narrow_gt(*bound),
            "eq" => SymbolicValue::Range {
                min: Some(*bound),
                max: Some(*bound),
            },
            _ => value,
        };
    }

    value
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_symbolic_value_any() {
        let v = SymbolicValue::Any;
        assert!(!v.is_impossible());
    }

    #[test]
    fn test_symbolic_value_impossible_range() {
        let v = SymbolicValue::Range {
            min: Some(10),
            max: Some(5),
        };
        assert!(v.is_impossible());
    }

    #[test]
    fn test_symbolic_value_valid_range() {
        let v = SymbolicValue::Range {
            min: Some(1),
            max: Some(10),
        };
        assert!(!v.is_impossible());
    }

    #[test]
    fn test_narrow_eq_from_any() {
        let v = SymbolicValue::Any.narrow_eq("Foo");
        assert_eq!(v, SymbolicValue::Constructor("Foo".to_string()));
    }

    #[test]
    fn test_narrow_eq_contradicts() {
        let v = SymbolicValue::Constructor("Foo".to_string()).narrow_eq("Bar");
        assert!(v.is_impossible());
    }

    #[test]
    fn test_narrow_lt() {
        let v = SymbolicValue::Any.narrow_lt(10);
        assert_eq!(
            v,
            SymbolicValue::Range {
                min: None,
                max: Some(9)
            }
        );
    }

    #[test]
    fn test_narrow_gt() {
        let v = SymbolicValue::Any.narrow_gt(0);
        assert_eq!(
            v,
            SymbolicValue::Range {
                min: Some(1),
                max: None
            }
        );
    }

    #[test]
    fn test_constraint_propagation_possible() {
        let result = propagate_constraints(&[("gt".to_string(), 0), ("lt".to_string(), 100)]);
        assert!(!result.is_impossible());
        assert_eq!(
            result,
            SymbolicValue::Range {
                min: Some(1),
                max: Some(99)
            }
        );
    }

    #[test]
    fn test_constraint_propagation_impossible() {
        let result = propagate_constraints(&[("gt".to_string(), 100), ("lt".to_string(), 50)]);
        assert!(result.is_impossible());
    }

    #[test]
    fn test_symbolic_context_fork() {
        let mut ctx = SymbolicContext::new();
        ctx.bind("x", SymbolicValue::Any);
        let mut forked = ctx.fork();
        forked.bind("x", SymbolicValue::Boolean(true));
        assert_eq!(*ctx.get("x"), SymbolicValue::Any);
        assert_eq!(*forked.get("x"), SymbolicValue::Boolean(true));
    }

    #[test]
    fn test_analyze_branches_duplicate_pattern() {
        let branches = vec![
            ("Foo".to_string(), false),
            ("Bar".to_string(), false),
            ("Foo".to_string(), false), // duplicate
        ];
        let impossible = analyze_branches_symbolically("x", &branches);
        assert_eq!(impossible.len(), 1);
        assert!(impossible[0].contains("unreachable"));
    }

    #[test]
    fn test_analyze_branches_no_duplicates() {
        let branches = vec![
            ("Foo".to_string(), false),
            ("Bar".to_string(), false),
            ("_".to_string(), true),
        ];
        let impossible = analyze_branches_symbolically("x", &branches);
        assert!(impossible.is_empty());
    }
}
