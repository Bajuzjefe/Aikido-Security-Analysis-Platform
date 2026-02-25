//! Feature #75: Cross-module analysis — analyze interactions between lib modules and validators.
//! Feature #76: Type-level analysis — use type information for stronger guarantees.
//!
//! This module provides cross-module and type-level analysis capabilities:
//! - Tracks which library functions are used by which validators
//! - Identifies unused library exports
//! - Detects type boundary violations (opaque types accessed unsafely)
//! - Maps data flow between modules

use std::collections::{HashMap, HashSet};

use crate::ast_walker::{ModuleInfo, ModuleKind};

/// Cross-module dependency information.
#[derive(Debug, Clone, Default)]
pub struct ModuleDependencyGraph {
    /// Module name → set of modules it depends on (via function calls).
    pub dependencies: HashMap<String, HashSet<String>>,
    /// Module name → set of functions exported (public functions).
    pub exports: HashMap<String, HashSet<String>>,
    /// Module name → set of functions imported (called from other modules).
    pub imports: HashMap<String, HashSet<String>>,
}

impl ModuleDependencyGraph {
    /// Build dependency graph from module info.
    pub fn from_modules(modules: &[ModuleInfo]) -> Self {
        let mut graph = Self::default();

        // Collect all public functions per module
        for module in modules {
            let exports: HashSet<String> = module
                .functions
                .iter()
                .filter(|f| f.public)
                .map(|f| f.name.clone())
                .collect();
            graph.exports.insert(module.name.clone(), exports);
        }

        // Analyze function calls to build dependencies
        for module in modules {
            let mut deps = HashSet::new();
            let mut used_imports = HashSet::new();

            // Check validator handlers
            for validator in &module.validators {
                for handler in &validator.handlers {
                    for call in &handler.body_signals.function_calls {
                        if let Some((mod_name, _func_name)) = call.split_once('.') {
                            // Find which module this belongs to
                            for other in modules {
                                let short = other.name.rsplit('/').next().unwrap_or(&other.name);
                                if short == mod_name || other.name == mod_name {
                                    deps.insert(other.name.clone());
                                    used_imports.insert(call.clone());
                                }
                            }
                        }
                    }
                }
            }

            // Check library functions
            for func in &module.functions {
                if let Some(ref signals) = func.body_signals {
                    for call in &signals.function_calls {
                        if let Some((mod_name, _)) = call.split_once('.') {
                            for other in modules {
                                let short = other.name.rsplit('/').next().unwrap_or(&other.name);
                                if short == mod_name || other.name == mod_name {
                                    deps.insert(other.name.clone());
                                    used_imports.insert(call.clone());
                                }
                            }
                        }
                    }
                }
            }

            graph.dependencies.insert(module.name.clone(), deps);
            graph.imports.insert(module.name.clone(), used_imports);
        }

        graph
    }

    /// Find library modules that are never used by any validator.
    pub fn unused_modules(&self, modules: &[ModuleInfo]) -> Vec<String> {
        let validator_deps: HashSet<&String> = modules
            .iter()
            .filter(|m| m.kind == ModuleKind::Validator)
            .flat_map(|m| {
                self.dependencies
                    .get(&m.name)
                    .map(|d| d.iter().collect::<Vec<_>>())
                    .unwrap_or_default()
            })
            .collect();

        modules
            .iter()
            .filter(|m| m.kind == ModuleKind::Lib && !validator_deps.contains(&m.name))
            .map(|m| m.name.clone())
            .collect()
    }

    /// Get the transitive dependencies of a module.
    pub fn transitive_deps(&self, module_name: &str) -> HashSet<String> {
        let mut visited = HashSet::new();
        let mut stack = vec![module_name.to_string()];

        while let Some(current) = stack.pop() {
            if !visited.insert(current.clone()) {
                continue;
            }
            if let Some(deps) = self.dependencies.get(&current) {
                for dep in deps {
                    if !visited.contains(dep) {
                        stack.push(dep.clone());
                    }
                }
            }
        }

        visited.remove(module_name);
        visited
    }
}

/// Type-level analysis results.
#[derive(Debug, Clone, Default)]
pub struct TypeAnalysis {
    /// Opaque types and which modules define them.
    pub opaque_types: HashMap<String, String>,
    /// Type usage violations: accessing opaque type internals from outside.
    pub violations: Vec<TypeViolation>,
}

/// A type-level violation.
#[derive(Debug, Clone)]
pub struct TypeViolation {
    pub type_name: String,
    pub defined_in: String,
    pub accessed_in: String,
    pub description: String,
}

impl TypeAnalysis {
    /// Analyze type boundaries across modules.
    pub fn from_modules(modules: &[ModuleInfo]) -> Self {
        let mut analysis = Self::default();

        // Collect opaque type definitions
        for module in modules {
            for dt in &module.data_types {
                // In Aiken, types can be opaque (private constructors)
                // We detect this by checking if the type is not public or has limited visibility
                if !dt.public {
                    analysis
                        .opaque_types
                        .insert(dt.name.clone(), module.name.clone());
                }
            }
        }

        // Check for violations: accessing fields of opaque types from other modules
        for module in modules {
            for validator in &module.validators {
                for handler in &validator.handlers {
                    for label in &handler.body_signals.all_record_labels {
                        // Check if any opaque type has a field matching this label
                        for other_module in modules {
                            if other_module.name == module.name {
                                continue;
                            }
                            for dt in &other_module.data_types {
                                if !analysis.opaque_types.contains_key(&dt.name) {
                                    continue;
                                }
                                let has_field = dt.constructors.iter().any(|c| {
                                    c.fields
                                        .iter()
                                        .any(|f| f.label.as_deref() == Some(label.as_str()))
                                });
                                if has_field {
                                    analysis.violations.push(TypeViolation {
                                        type_name: dt.name.clone(),
                                        defined_in: other_module.name.clone(),
                                        accessed_in: module.name.clone(),
                                        description: format!(
                                            "Field '{}' of opaque type '{}' accessed from '{}'",
                                            label, dt.name, module.name
                                        ),
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }

        analysis
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast_walker::*;
    use crate::body_analysis::BodySignals;

    fn make_lib_module(name: &str, funcs: Vec<(&str, bool)>) -> ModuleInfo {
        ModuleInfo {
            name: name.to_string(),
            path: format!("{name}.ak"),
            kind: ModuleKind::Lib,
            validators: vec![],
            data_types: vec![],
            functions: funcs
                .into_iter()
                .map(|(n, public)| FunctionInfo {
                    name: n.to_string(),
                    public,
                    params: vec![],
                    return_type: "Bool".to_string(),
                    body_signals: None,
                })
                .collect(),
            constants: vec![],
            type_aliases: vec![],
            test_count: 0,
            source_code: None,
            test_function_names: vec![],
        }
    }

    fn make_validator_module(name: &str, calls: HashSet<String>) -> ModuleInfo {
        ModuleInfo {
            name: name.to_string(),
            path: format!("{name}.ak"),
            kind: ModuleKind::Validator,
            validators: vec![ValidatorInfo {
                name: "v".to_string(),
                params: vec![],
                handlers: vec![HandlerInfo {
                    name: "spend".to_string(),
                    params: vec![],
                    return_type: "Bool".to_string(),
                    location: None,
                    body_signals: BodySignals {
                        function_calls: calls,
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
        }
    }

    #[test]
    fn test_build_dependency_graph() {
        let lib = make_lib_module("utils", vec![("helper", true)]);
        let mut calls = HashSet::new();
        calls.insert("utils.helper".to_string());
        let validator = make_validator_module("validator", calls);

        let graph = ModuleDependencyGraph::from_modules(&[lib, validator]);
        assert!(graph
            .dependencies
            .get("validator")
            .unwrap()
            .contains("utils"));
    }

    #[test]
    fn test_unused_modules() {
        let lib1 = make_lib_module("used_lib", vec![("helper", true)]);
        let lib2 = make_lib_module("unused_lib", vec![("other", true)]);
        let mut calls = HashSet::new();
        calls.insert("used_lib.helper".to_string());
        let validator = make_validator_module("validator", calls);

        let all_modules = vec![lib1, lib2, validator];
        let graph = ModuleDependencyGraph::from_modules(&all_modules);
        let unused = graph.unused_modules(&all_modules);
        assert!(unused.contains(&"unused_lib".to_string()));
    }

    #[test]
    fn test_transitive_deps() {
        let mut deps = HashMap::new();
        let mut a_deps = HashSet::new();
        a_deps.insert("b".to_string());
        deps.insert("a".to_string(), a_deps);

        let mut b_deps = HashSet::new();
        b_deps.insert("c".to_string());
        deps.insert("b".to_string(), b_deps);

        deps.insert("c".to_string(), HashSet::new());

        let graph = ModuleDependencyGraph {
            dependencies: deps,
            exports: HashMap::new(),
            imports: HashMap::new(),
        };

        let trans = graph.transitive_deps("a");
        assert!(trans.contains("b"));
        assert!(trans.contains("c"));
        assert!(!trans.contains("a"));
    }

    #[test]
    fn test_type_analysis_no_violations() {
        let modules = vec![make_lib_module("lib", vec![])];
        let analysis = TypeAnalysis::from_modules(&modules);
        assert!(analysis.violations.is_empty());
    }

    #[test]
    fn test_opaque_type_detection() {
        let module = ModuleInfo {
            name: "types".to_string(),
            path: "types.ak".to_string(),
            kind: ModuleKind::Lib,
            validators: vec![],
            data_types: vec![DataTypeInfo {
                name: "Secret".to_string(),
                public: false, // opaque
                constructors: vec![ConstructorInfo {
                    name: "Secret".to_string(),
                    fields: vec![FieldInfo {
                        label: Some("inner".to_string()),
                        type_name: "ByteArray".to_string(),
                    }],
                }],
            }],
            functions: vec![],
            constants: vec![],
            type_aliases: vec![],
            test_count: 0,
            source_code: None,
            test_function_names: vec![],
        };

        let analysis = TypeAnalysis::from_modules(&[module]);
        assert!(analysis.opaque_types.contains_key("Secret"));
    }
}
