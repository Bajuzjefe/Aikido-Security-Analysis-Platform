//! Token lifecycle graph across spend/mint/withdraw handlers.
//!
//! Models whether a validator family has a complete mint -> use -> burn lifecycle.

use std::collections::HashSet;

use crate::ast_walker::{ModuleInfo, ModuleKind};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LifecycleStage {
    Mint,
    Use,
    Burn,
    Withdraw,
}

#[derive(Debug, Clone)]
pub struct LifecycleEdge {
    pub module: String,
    pub validator: String,
    pub from: LifecycleStage,
    pub to: LifecycleStage,
}

#[derive(Debug, Default)]
pub struct TokenLifecycleGraph {
    edges: Vec<LifecycleEdge>,
    burn_validators: HashSet<(String, String)>,
}

impl TokenLifecycleGraph {
    pub fn build(modules: &[ModuleInfo]) -> Self {
        let mut graph = Self::default();

        for module in modules {
            if module.kind != ModuleKind::Validator {
                continue;
            }

            for validator in &module.validators {
                let mut has_mint = false;
                let mut has_use = false;
                let mut has_withdraw = false;
                let mut has_burn = false;

                for handler in &validator.handlers {
                    let signals = &handler.body_signals;

                    if handler.name == "mint" {
                        has_mint = true;
                    }

                    if signals.tx_field_accesses.contains("withdrawals")
                        || handler.name == "withdraw"
                    {
                        has_withdraw = true;
                    }

                    let uses_tokens = signals.tx_field_accesses.contains("inputs")
                        && signals
                            .function_calls
                            .iter()
                            .any(|c| c.contains("quantity_of"));
                    if uses_tokens {
                        has_use = true;
                    }

                    let burn_evidence = signals.tx_field_accesses.contains("mint")
                        && signals.function_calls.iter().any(|c| {
                            c.contains("negate")
                                || c.contains("burn")
                                || c.contains("from_minted_value")
                                || c.contains("quantity_of")
                        });
                    if burn_evidence {
                        has_burn = true;
                    }
                }

                let key = (module.name.clone(), validator.name.clone());
                if has_burn {
                    graph.burn_validators.insert(key.clone());
                }

                if has_mint && has_use {
                    graph.edges.push(LifecycleEdge {
                        module: module.name.clone(),
                        validator: validator.name.clone(),
                        from: LifecycleStage::Mint,
                        to: LifecycleStage::Use,
                    });
                }

                if has_use && has_burn {
                    graph.edges.push(LifecycleEdge {
                        module: module.name.clone(),
                        validator: validator.name.clone(),
                        from: LifecycleStage::Use,
                        to: LifecycleStage::Burn,
                    });
                }

                if has_use && has_withdraw {
                    graph.edges.push(LifecycleEdge {
                        module: module.name.clone(),
                        validator: validator.name.clone(),
                        from: LifecycleStage::Use,
                        to: LifecycleStage::Withdraw,
                    });
                }
            }
        }

        graph
    }

    pub fn has_burn_path(&self, module: &str, validator: &str) -> bool {
        self.burn_validators
            .contains(&(module.to_string(), validator.to_string()))
            || self.edges.iter().any(|edge| {
                edge.module == module
                    && edge.validator == validator
                    && edge.from == LifecycleStage::Use
                    && edge.to == LifecycleStage::Burn
            })
    }

    pub fn has_any_burn_path(&self) -> bool {
        !self.burn_validators.is_empty()
            || self
                .edges
                .iter()
                .any(|edge| edge.from == LifecycleStage::Use && edge.to == LifecycleStage::Burn)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast_walker::*;
    use crate::body_analysis::BodySignals;

    #[test]
    fn test_detects_use_to_burn_path() {
        let modules = vec![ModuleInfo {
            name: "test/v".to_string(),
            path: "v.ak".to_string(),
            kind: ModuleKind::Validator,
            validators: vec![ValidatorInfo {
                name: "pool".to_string(),
                params: vec![],
                handlers: vec![
                    HandlerInfo {
                        name: "spend".to_string(),
                        params: vec![],
                        return_type: "Bool".to_string(),
                        location: None,
                        body_signals: BodySignals {
                            tx_field_accesses: ["inputs"].iter().map(|s| s.to_string()).collect(),
                            function_calls: ["assets.quantity_of"]
                                .iter()
                                .map(|s| s.to_string())
                                .collect(),
                            ..Default::default()
                        },
                    },
                    HandlerInfo {
                        name: "mint".to_string(),
                        params: vec![],
                        return_type: "Bool".to_string(),
                        location: None,
                        body_signals: BodySignals {
                            tx_field_accesses: ["mint"].iter().map(|s| s.to_string()).collect(),
                            function_calls: ["value.from_minted_value", "value.negate"]
                                .iter()
                                .map(|s| s.to_string())
                                .collect(),
                            ..Default::default()
                        },
                    },
                ],
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

        let graph = TokenLifecycleGraph::build(&modules);
        assert!(graph.has_burn_path("test/v", "pool"));
        assert!(graph.has_any_burn_path());
    }

    #[test]
    fn test_no_burn_path_without_burn_evidence() {
        let modules = vec![ModuleInfo {
            name: "test/v".to_string(),
            path: "v.ak".to_string(),
            kind: ModuleKind::Validator,
            validators: vec![ValidatorInfo {
                name: "pool".to_string(),
                params: vec![],
                handlers: vec![
                    HandlerInfo {
                        name: "spend".to_string(),
                        params: vec![],
                        return_type: "Bool".to_string(),
                        location: None,
                        body_signals: BodySignals {
                            tx_field_accesses: ["inputs"].iter().map(|s| s.to_string()).collect(),
                            function_calls: ["assets.quantity_of"]
                                .iter()
                                .map(|s| s.to_string())
                                .collect(),
                            ..Default::default()
                        },
                    },
                    HandlerInfo {
                        name: "mint".to_string(),
                        params: vec![],
                        return_type: "Bool".to_string(),
                        location: None,
                        body_signals: BodySignals {
                            tx_field_accesses: ["mint"].iter().map(|s| s.to_string()).collect(),
                            function_calls: ["dict.get"].iter().map(|s| s.to_string()).collect(),
                            ..Default::default()
                        },
                    },
                ],
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

        let graph = TokenLifecycleGraph::build(&modules);
        assert!(
            !graph.has_burn_path("test/v", "pool"),
            "mint handler without negate/burn evidence should not count as burn path"
        );
        assert!(!graph.has_any_burn_path());
    }
}
