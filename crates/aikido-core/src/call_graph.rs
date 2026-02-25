//! Feature #34: Call graph construction.
//!
//! Builds a directed call graph from [`ModuleInfo`] data extracted during AST
//! walking. The graph edges are derived from `body_signals.function_calls`
//! stored on both validator handlers and library functions.

use std::collections::{HashMap, HashSet};

use crate::ast_walker::ModuleInfo;

/// A directed call graph over all analysed modules.
///
/// Each node is a function/handler name (string). Edges go from caller to
/// callee. Module-qualified calls (`list.has`) and bare local calls (`check`)
/// are both represented as-is; callers of builtins from the standard library
/// will appear in `edges` but will not be keys themselves unless they appear as
/// callers too.
#[derive(Debug, Clone, Default)]
pub struct CallGraph {
    /// Adjacency list: caller name → set of callee names.
    pub edges: HashMap<String, HashSet<String>>,
    /// All known function / handler names (nodes that appear as callers).
    pub nodes: HashSet<String>,
}

impl CallGraph {
    /// Construct a call graph from a slice of [`ModuleInfo`] values.
    pub fn from_modules(modules: &[ModuleInfo]) -> Self {
        let mut graph = CallGraph::default();

        for module in modules {
            // Validator handlers
            for validator in &module.validators {
                for handler in &validator.handlers {
                    let caller = format!("{}::{}", validator.name, handler.name);
                    graph.nodes.insert(caller.clone());
                    let callees = graph.edges.entry(caller).or_default();
                    for callee in &handler.body_signals.function_calls {
                        callees.insert(callee.clone());
                    }
                }
            }

            // Library / helper functions
            for func in &module.functions {
                graph.nodes.insert(func.name.clone());
                if let Some(signals) = &func.body_signals {
                    let callees = graph.edges.entry(func.name.clone()).or_default();
                    for callee in &signals.function_calls {
                        callees.insert(callee.clone());
                    }
                } else {
                    // Ensure the node appears in edges (with an empty callee set)
                    graph.edges.entry(func.name.clone()).or_default();
                }
            }
        }

        graph
    }

    /// Return all callers of the given function name.
    ///
    /// A caller is any node whose callee set contains `name`.
    pub fn callers_of<'a>(&'a self, name: &str) -> Vec<&'a str> {
        self.edges
            .iter()
            .filter_map(|(caller, callees)| {
                if callees.contains(name) {
                    Some(caller.as_str())
                } else {
                    None
                }
            })
            .collect()
    }

    /// Return the set of callees for the given caller name, if it exists.
    pub fn callees_of(&self, name: &str) -> Option<&HashSet<String>> {
        self.edges.get(name)
    }

    /// Return function names that are NOT reachable from any of the given
    /// entry-point names via the call graph.
    ///
    /// Uses a BFS / DFS traversal starting from each entry point and returns
    /// all nodes not visited.  Only nodes that appear in `self.nodes` are
    /// considered; callee names that do not appear in `nodes` (e.g. stdlib
    /// builtins) are ignored.
    pub fn unreachable_from<'a>(&'a self, entry_points: &[&str]) -> Vec<&'a str> {
        let mut visited: HashSet<&str> = HashSet::new();
        let mut stack: Vec<&str> = entry_points.to_vec();

        while let Some(current) = stack.pop() {
            if visited.contains(current) {
                continue;
            }
            visited.insert(current);
            if let Some(callees) = self.edges.get(current) {
                for callee in callees {
                    // Only traverse nodes we know about (skip stdlib / external)
                    if self.nodes.contains(callee.as_str()) && !visited.contains(callee.as_str()) {
                        stack.push(callee.as_str());
                    }
                }
            }
        }

        self.nodes
            .iter()
            .filter(|node| !visited.contains(node.as_str()))
            .map(|s| s.as_str())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast_walker::{FunctionInfo, ModuleInfo, ModuleKind, ParamInfo, ValidatorInfo};
    use crate::body_analysis::BodySignals;

    fn make_module_with_functions(name: &str, functions: Vec<(&str, Vec<&str>)>) -> ModuleInfo {
        let funcs: Vec<FunctionInfo> = functions
            .into_iter()
            .map(|(fn_name, callees)| {
                let mut signals = BodySignals::default();
                for callee in callees {
                    signals.function_calls.insert(callee.to_string());
                }
                FunctionInfo {
                    name: fn_name.to_string(),
                    public: true,
                    params: vec![],
                    return_type: "Bool".to_string(),
                    body_signals: Some(signals),
                }
            })
            .collect();

        ModuleInfo {
            name: name.to_string(),
            path: format!("{name}.ak"),
            kind: ModuleKind::Lib,
            validators: vec![],
            data_types: vec![],
            functions: funcs,
            constants: vec![],
            type_aliases: vec![],
            test_count: 0,
            source_code: None,
            test_function_names: vec![],
        }
    }

    fn make_module_with_validator(
        module_name: &str,
        validator_name: &str,
        handler_name: &str,
        callees: Vec<&str>,
    ) -> ModuleInfo {
        let mut signals = BodySignals::default();
        for callee in callees {
            signals.function_calls.insert(callee.to_string());
        }

        let handler = crate::ast_walker::HandlerInfo {
            name: handler_name.to_string(),
            params: vec![],
            return_type: "Bool".to_string(),
            location: None,
            body_signals: signals,
        };

        let validator = ValidatorInfo {
            name: validator_name.to_string(),
            params: vec![],
            handlers: vec![handler],
            summary: None,
        };

        ModuleInfo {
            name: module_name.to_string(),
            path: format!("{module_name}.ak"),
            kind: ModuleKind::Validator,
            validators: vec![validator],
            data_types: vec![],
            functions: vec![],
            constants: vec![],
            type_aliases: vec![],
            test_count: 0,
            source_code: None,
            test_function_names: vec![],
        }
    }

    #[test]
    fn test_call_graph_empty() {
        let graph = CallGraph::from_modules(&[]);
        assert!(graph.edges.is_empty());
        assert!(graph.nodes.is_empty());
    }

    #[test]
    fn test_call_graph_single_function_no_calls() {
        let module = make_module_with_functions("lib", vec![("foo", vec![])]);
        let graph = CallGraph::from_modules(&[module]);
        assert!(graph.nodes.contains("foo"));
        assert!(graph
            .callees_of("foo")
            .map(|s| s.is_empty())
            .unwrap_or(true));
    }

    #[test]
    fn test_call_graph_function_calls() {
        let module = make_module_with_functions(
            "lib",
            vec![
                ("foo", vec!["bar", "list.has"]),
                ("bar", vec!["baz"]),
                ("baz", vec![]),
            ],
        );
        let graph = CallGraph::from_modules(&[module]);

        assert!(graph.nodes.contains("foo"));
        assert!(graph.nodes.contains("bar"));
        assert!(graph.nodes.contains("baz"));

        let foo_callees = graph.callees_of("foo").expect("foo should have callees");
        assert!(foo_callees.contains("bar"));
        assert!(foo_callees.contains("list.has"));

        let bar_callees = graph.callees_of("bar").expect("bar should have callees");
        assert!(bar_callees.contains("baz"));
    }

    #[test]
    fn test_callers_of() {
        let module = make_module_with_functions(
            "lib",
            vec![
                ("foo", vec!["helper"]),
                ("bar", vec!["helper"]),
                ("helper", vec![]),
            ],
        );
        let graph = CallGraph::from_modules(&[module]);

        let mut callers = graph.callers_of("helper");
        callers.sort_unstable();
        assert_eq!(callers.len(), 2);
        assert!(callers.contains(&"foo"));
        assert!(callers.contains(&"bar"));
    }

    #[test]
    fn test_callers_of_unknown() {
        let module = make_module_with_functions("lib", vec![("foo", vec![])]);
        let graph = CallGraph::from_modules(&[module]);
        assert!(graph.callers_of("nonexistent").is_empty());
    }

    #[test]
    fn test_unreachable_from_all_reachable() {
        let module = make_module_with_functions(
            "lib",
            vec![("entry", vec!["a"]), ("a", vec!["b"]), ("b", vec![])],
        );
        let graph = CallGraph::from_modules(&[module]);
        let unreachable = graph.unreachable_from(&["entry"]);
        assert!(
            unreachable.is_empty(),
            "expected no unreachable nodes, got: {unreachable:?}"
        );
    }

    #[test]
    fn test_unreachable_from_with_dead_code() {
        let module = make_module_with_functions(
            "lib",
            vec![
                ("entry", vec!["a"]),
                ("a", vec![]),
                ("dead", vec![]), // not called from entry
            ],
        );
        let graph = CallGraph::from_modules(&[module]);
        let unreachable = graph.unreachable_from(&["entry"]);
        assert_eq!(unreachable, vec!["dead"]);
    }

    #[test]
    fn test_validator_handler_appears_as_node() {
        let module = make_module_with_validator("contract", "my_validator", "spend", vec!["check"]);
        let graph = CallGraph::from_modules(&[module]);

        let node = "my_validator::spend";
        assert!(
            graph.nodes.contains(node),
            "expected node '{node}' in graph"
        );

        let callees = graph.callees_of(node).expect("should have callees");
        assert!(callees.contains("check"));
    }

    #[test]
    fn test_callees_of_none_for_unknown() {
        let graph = CallGraph::default();
        assert!(graph.callees_of("unknown").is_none());
    }

    #[test]
    fn test_call_graph_from_multiple_modules() {
        let mod1 = make_module_with_functions("mod1", vec![("alpha", vec!["beta"])]);
        let mod2 = make_module_with_functions("mod2", vec![("beta", vec![])]);
        let graph = CallGraph::from_modules(&[mod1, mod2]);

        assert!(graph.nodes.contains("alpha"));
        assert!(graph.nodes.contains("beta"));

        let callers = graph.callers_of("beta");
        assert!(callers.contains(&"alpha"));
    }

    #[test]
    fn test_function_with_no_body_signals() {
        // FunctionInfo with body_signals: None — should still appear as a node
        let func = FunctionInfo {
            name: "no_tx_param".to_string(),
            public: false,
            params: vec![ParamInfo {
                name: "x".to_string(),
                type_name: "Int".to_string(),
            }],
            return_type: "Int".to_string(),
            body_signals: None,
        };
        let module = ModuleInfo {
            name: "lib".to_string(),
            path: "lib.ak".to_string(),
            kind: ModuleKind::Lib,
            validators: vec![],
            data_types: vec![],
            functions: vec![func],
            constants: vec![],
            type_aliases: vec![],
            test_count: 0,
            source_code: None,
            test_function_names: vec![],
        };
        let graph = CallGraph::from_modules(&[module]);
        assert!(graph.nodes.contains("no_tx_param"));
        assert!(graph
            .callees_of("no_tx_param")
            .map(|s| s.is_empty())
            .unwrap_or(true));
    }
}
