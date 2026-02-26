use crate::ast_walker::{ModuleInfo, ModuleKind};
use crate::call_graph::CallGraph;
use crate::cross_module::ModuleDependencyGraph;
use crate::detector::{Confidence, Detector, Finding, Severity};

pub struct UnusedLibraryModule;

impl Detector for UnusedLibraryModule {
    fn name(&self) -> &str {
        "unused-library-module"
    }

    fn description(&self) -> &str {
        "Detects library modules not used by any validator"
    }

    fn severity(&self) -> Severity {
        Severity::Info
    }

    fn long_description(&self) -> &str {
        "A library module whose functions are not transitively reachable from any \
        validator module may be dead code. Type-only modules (no functions) are \
        excluded since Aiken imports types implicitly.\n\n\
        Fix: Remove the unused module or add a validator dependency."
    }

    fn cwe_id(&self) -> Option<&str> {
        Some("CWE-561")
    }

    fn category(&self) -> &str {
        "code-quality"
    }

    fn detect(&self, modules: &[ModuleInfo]) -> Vec<Finding> {
        let mut findings = Vec::new();
        let graph = ModuleDependencyGraph::from_modules(modules);

        // Collect the transitive dependency closure of all validator modules
        let mut validator_transitive_deps = std::collections::HashSet::new();
        for module in modules {
            if module.kind == ModuleKind::Validator {
                let deps = graph.transitive_deps(&module.name);
                validator_transitive_deps.extend(deps);
                // Also include the validator module itself
                validator_transitive_deps.insert(module.name.clone());
            }
        }

        // Fallback: use call graph reachability to catch cases where module
        // dependencies are resolved through unqualified function calls
        // (e.g., `use calculation/swap.{do_swap}` then calling `do_swap()`)
        // that the module-level dependency graph misses.
        let call_graph = CallGraph::from_modules(modules);
        let entry_points: Vec<&str> = call_graph
            .nodes
            .iter()
            .filter(|n| n.contains("::"))
            .map(|s| s.as_str())
            .collect();

        let unreachable_fns: std::collections::HashSet<&str> = if !entry_points.is_empty() {
            call_graph
                .unreachable_from(&entry_points)
                .into_iter()
                .collect()
        } else {
            std::collections::HashSet::new()
        };

        // Build set of all called bare names (handles qualified call mismatches)
        let mut called_bare_names: std::collections::HashSet<&str> =
            std::collections::HashSet::new();
        for callees in call_graph.edges.values() {
            for callee in callees {
                if let Some(dot_pos) = callee.rfind('.') {
                    called_bare_names.insert(&callee[dot_pos + 1..]);
                }
                called_bare_names.insert(callee.as_str());
            }
        }

        for module in modules {
            if module.kind != ModuleKind::Lib {
                continue;
            }

            // Skip type-only modules (no functions defined)
            if module.functions.is_empty() {
                continue;
            }

            // Skip stdlib and well-known Aiken library modules
            if module.name.starts_with("aiken/")
                || module.name.starts_with("aiken_")
                || module.name.starts_with("cardano/")
            {
                continue;
            }

            // Skip test modules — test helpers are expected to be
            // unreachable from validators
            if module.name.starts_with("tests/") || module.name.starts_with("test/") {
                continue;
            }

            // Primary check: module in transitive deps
            if validator_transitive_deps.contains(&module.name) {
                continue;
            }

            // Fallback: any function in this module is reachable via call graph
            let has_reachable_function = module.functions.iter().any(|f| {
                let in_graph = call_graph.nodes.contains(&f.name)
                    || called_bare_names.contains(f.name.as_str());
                in_graph && !unreachable_fns.contains(f.name.as_str())
            });

            if has_reachable_function {
                continue;
            }

            findings.push(Finding {
                detector_name: self.name().to_string(),
                severity: self.severity(),
                confidence: Confidence::Possible,
                title: format!("Unused library module '{}'", module.name),
                description: format!(
                    "Library module '{}' defines {} function(s) but is not used \
                    by any validator module (directly or transitively).",
                    module.name,
                    module.functions.len()
                ),
                module: module.name.clone(),
                location: None,
                suggestion: Some(
                    "Remove the unused module or verify it is imported \
                    through a pattern not captured by static analysis."
                        .to_string(),
                ),
                related_findings: vec![],
                semantic_group: None,

                evidence: None,
            });
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast_walker::*;
    use crate::body_analysis::BodySignals;

    fn make_lib(name: &str, funcs: Vec<&str>) -> ModuleInfo {
        ModuleInfo {
            name: name.to_string(),
            path: format!("{name}.ak"),
            kind: ModuleKind::Lib,
            validators: vec![],
            data_types: vec![],
            functions: funcs
                .into_iter()
                .map(|n| FunctionInfo {
                    name: n.to_string(),
                    public: true,
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

    fn make_type_only_lib(name: &str) -> ModuleInfo {
        ModuleInfo {
            name: name.to_string(),
            path: format!("{name}.ak"),
            kind: ModuleKind::Lib,
            validators: vec![],
            data_types: vec![DataTypeInfo {
                name: "MyType".to_string(),
                public: true,
                constructors: vec![],
            }],
            functions: vec![],
            constants: vec![],
            type_aliases: vec![],
            test_count: 0,
            source_code: None,
            test_function_names: vec![],
        }
    }

    fn make_validator(name: &str, calls: Vec<&str>) -> ModuleInfo {
        let mut signals = BodySignals::default();
        for call in calls {
            signals.function_calls.insert(call.to_string());
        }
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
        }
    }

    #[test]
    fn test_unused_lib_detected() {
        let modules = vec![
            make_lib("lib/unused", vec!["helper"]),
            make_validator("validators/v", vec![]),
        ];
        let findings = UnusedLibraryModule.detect(&modules);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].title.contains("lib/unused"));
    }

    #[test]
    fn test_used_lib_not_flagged() {
        let modules = vec![
            make_lib("lib/used", vec!["helper"]),
            make_validator("validators/v", vec!["used.helper"]),
        ];
        let findings = UnusedLibraryModule.detect(&modules);
        assert!(
            findings.is_empty(),
            "used lib should not be flagged, got: {findings:?}"
        );
    }

    #[test]
    fn test_type_only_module_not_flagged() {
        let modules = vec![
            make_type_only_lib("lib/types"),
            make_validator("validators/v", vec![]),
        ];
        let findings = UnusedLibraryModule.detect(&modules);
        assert!(
            findings.is_empty(),
            "type-only module should not be flagged"
        );
    }

    #[test]
    fn test_transitively_used_lib_not_flagged() {
        // validator -> lib/a.helper -> (lib/b should be transitively used)
        let mut lib_b = make_lib("lib/b", vec!["deep_helper"]);
        // Make lib/a depend on lib/b
        let mut lib_a = make_lib("lib/a", vec!["helper"]);
        // lib/a's function calls lib/b
        if let Some(ref mut signals) = lib_a.functions[0].body_signals {
            signals.function_calls.insert("b.deep_helper".to_string());
        } else {
            let mut signals = BodySignals::default();
            signals.function_calls.insert("b.deep_helper".to_string());
            lib_a.functions[0].body_signals = Some(signals);
        }
        // Ensure lib_b has body_signals so the dependency graph can process it
        lib_b.functions[0].body_signals = Some(BodySignals::default());

        let modules = vec![
            lib_a,
            lib_b,
            make_validator("validators/v", vec!["a.helper"]),
        ];
        let findings = UnusedLibraryModule.detect(&modules);
        assert!(
            findings.is_empty(),
            "transitively used lib should not be flagged, got: {findings:?}"
        );
    }
}
