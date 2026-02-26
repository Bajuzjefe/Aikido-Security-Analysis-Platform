//! Validator dependency graph for cross-validator analysis (Phase 3).
//!
//! Builds a graph of relationships between validators in a project,
//! enabling detection of coordination gaps, missing delegation checks,
//! and uncoordinated state transfers.

use std::collections::{HashMap, HashSet};

use petgraph::graph::{DiGraph, NodeIndex};

use crate::ast_walker::{ModuleInfo, ModuleKind};
use crate::delegation::detect_delegation_patterns;

/// The kind of relationship between two validators.
#[derive(Debug, Clone, PartialEq)]
pub enum ValidatorRelation {
    /// Spend handler delegates to a withdrawal/staking handler.
    WithdrawDelegation,
    /// Spend and mint handlers in the same validator.
    ColocatedMintSpend,
    /// Spend handler accesses `mint` field to coordinate with a minting policy.
    MintCoordination,
    /// Two validators share a datum type (same DataType name used).
    SharedDatumType { datum_type: String },
    /// Validator references another's token via parameter (ByteArray param).
    TokenReference { param_name: String },
}

/// A node in the validator dependency graph.
#[derive(Debug, Clone)]
pub struct ValidatorNode {
    pub module_name: String,
    pub validator_name: String,
    pub handler_names: Vec<String>,
    pub tx_accesses: HashSet<String>,
    pub has_spend: bool,
    pub has_mint: bool,
}

/// The validator dependency graph.
#[derive(Debug, Default)]
pub struct ValidatorGraph {
    pub graph: DiGraph<ValidatorNode, ValidatorRelation>,
    pub node_index: HashMap<(String, String), NodeIndex>,
}

impl ValidatorGraph {
    /// Build the validator dependency graph from analyzed modules.
    pub fn build(modules: &[ModuleInfo]) -> Self {
        let mut vg = Self::default();

        // Step 1: Add all validators as nodes
        for module in modules {
            if module.kind != ModuleKind::Validator {
                continue;
            }

            for validator in &module.validators {
                let handler_names: Vec<String> =
                    validator.handlers.iter().map(|h| h.name.clone()).collect();
                let tx_accesses: HashSet<String> = validator
                    .handlers
                    .iter()
                    .flat_map(|h| h.body_signals.tx_field_accesses.iter().cloned())
                    .collect();

                let node = ValidatorNode {
                    module_name: module.name.clone(),
                    validator_name: validator.name.clone(),
                    handler_names: handler_names.clone(),
                    tx_accesses: tx_accesses.clone(),
                    has_spend: handler_names.iter().any(|n| n == "spend"),
                    has_mint: handler_names.iter().any(|n| n == "mint"),
                };
                let idx = vg.graph.add_node(node);
                vg.node_index
                    .insert((module.name.clone(), validator.name.clone()), idx);
            }
        }

        // Step 2: Detect relationships

        // 2a: Colocated mint+spend
        for module in modules {
            if module.kind != ModuleKind::Validator {
                continue;
            }
            for validator in &module.validators {
                let has_spend = validator.handlers.iter().any(|h| h.name == "spend");
                let has_mint = validator.handlers.iter().any(|h| h.name == "mint");
                if has_spend && has_mint {
                    if let Some(&idx) = vg
                        .node_index
                        .get(&(module.name.clone(), validator.name.clone()))
                    {
                        vg.graph
                            .add_edge(idx, idx, ValidatorRelation::ColocatedMintSpend);
                    }
                }
            }
        }

        // 2b: Withdraw delegation
        let delegations = detect_delegation_patterns(modules);
        for delegation in &delegations {
            if let Some(&delegator_idx) = vg.node_index.get(&(
                delegation.module_name.clone(),
                delegation.validator_name.clone(),
            )) {
                // Find potential delegates (validators with withdraw/staking handlers)
                for module in modules {
                    if module.kind != ModuleKind::Validator {
                        continue;
                    }
                    for validator in &module.validators {
                        let has_withdraw = validator
                            .handlers
                            .iter()
                            .any(|h| h.name == "withdraw" || h.name == "else");
                        if has_withdraw {
                            if let Some(&delegate_idx) = vg
                                .node_index
                                .get(&(module.name.clone(), validator.name.clone()))
                            {
                                if delegator_idx != delegate_idx {
                                    vg.graph.add_edge(
                                        delegator_idx,
                                        delegate_idx,
                                        ValidatorRelation::WithdrawDelegation,
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }

        // 2c: Mint coordination (spend handler accesses `mint` field)
        for module in modules {
            if module.kind != ModuleKind::Validator {
                continue;
            }
            for validator in &module.validators {
                for handler in &validator.handlers {
                    if handler.name == "spend"
                        && handler.body_signals.tx_field_accesses.contains("mint")
                    {
                        if let Some(&spend_idx) = vg
                            .node_index
                            .get(&(module.name.clone(), validator.name.clone()))
                        {
                            // Find validators with mint handlers
                            for m2 in modules {
                                if m2.kind != ModuleKind::Validator {
                                    continue;
                                }
                                for v2 in &m2.validators {
                                    let has_mint = v2.handlers.iter().any(|h| h.name == "mint");
                                    if has_mint {
                                        if let Some(&mint_idx) =
                                            vg.node_index.get(&(m2.name.clone(), v2.name.clone()))
                                        {
                                            if spend_idx != mint_idx {
                                                vg.graph.add_edge(
                                                    spend_idx,
                                                    mint_idx,
                                                    ValidatorRelation::MintCoordination,
                                                );
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // 2d: Shared datum types
        let mut datum_types: HashMap<String, Vec<(String, String)>> = HashMap::new();
        for module in modules {
            for dt in &module.data_types {
                datum_types
                    .entry(dt.name.clone())
                    .or_default()
                    .push((module.name.clone(), String::new()));
            }
            for validator in &module.validators {
                for handler in &validator.handlers {
                    for param in &handler.params {
                        if !param.type_name.contains("Transaction")
                            && !param.type_name.contains("OutputReference")
                            && !param.type_name.contains("Bool")
                            && !param.type_name.contains("Int")
                            && !param.type_name.contains("ByteArray")
                        {
                            datum_types
                                .entry(param.type_name.clone())
                                .or_default()
                                .push((module.name.clone(), validator.name.clone()));
                        }
                    }
                }
            }
        }

        // Link validators that share datum types
        for (type_name, users) in &datum_types {
            let validators: Vec<_> = users.iter().filter(|(_, v)| !v.is_empty()).collect();
            for i in 0..validators.len() {
                for j in (i + 1)..validators.len() {
                    let key_i = (validators[i].0.clone(), validators[i].1.clone());
                    let key_j = (validators[j].0.clone(), validators[j].1.clone());
                    if let (Some(&idx_i), Some(&idx_j)) =
                        (vg.node_index.get(&key_i), vg.node_index.get(&key_j))
                    {
                        if idx_i != idx_j {
                            vg.graph.add_edge(
                                idx_i,
                                idx_j,
                                ValidatorRelation::SharedDatumType {
                                    datum_type: type_name.clone(),
                                },
                            );
                        }
                    }
                }
            }
        }

        vg
    }

    /// Get all validators that a given validator delegates to.
    pub fn delegates_to(&self, module: &str, validator: &str) -> Vec<&ValidatorNode> {
        let key = (module.to_string(), validator.to_string());
        if let Some(&idx) = self.node_index.get(&key) {
            self.graph
                .neighbors_directed(idx, petgraph::Direction::Outgoing)
                .filter(|&n| {
                    self.graph
                        .find_edge(idx, n)
                        .and_then(|e| self.graph.edge_weight(e))
                        .is_some_and(|w| matches!(w, ValidatorRelation::WithdrawDelegation))
                })
                .filter_map(|n| self.graph.node_weight(n))
                .collect()
        } else {
            vec![]
        }
    }

    /// Get all relationships for a validator.
    pub fn relations_of(
        &self,
        module: &str,
        validator: &str,
    ) -> Vec<(&ValidatorNode, &ValidatorRelation)> {
        let key = (module.to_string(), validator.to_string());
        if let Some(&idx) = self.node_index.get(&key) {
            self.graph
                .neighbors_directed(idx, petgraph::Direction::Outgoing)
                .filter_map(|n| {
                    let edge = self.graph.find_edge(idx, n)?;
                    let relation = self.graph.edge_weight(edge)?;
                    let node = self.graph.node_weight(n)?;
                    Some((node, relation))
                })
                .collect()
        } else {
            vec![]
        }
    }

    /// Count total validators.
    pub fn validator_count(&self) -> usize {
        self.graph.node_count()
    }

    /// Count total relationships.
    pub fn relation_count(&self) -> usize {
        self.graph.edge_count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast_walker::*;
    use crate::body_analysis::BodySignals;

    fn make_module(name: &str, validators: Vec<ValidatorInfo>) -> ModuleInfo {
        ModuleInfo {
            name: name.to_string(),
            path: format!("{name}.ak"),
            kind: ModuleKind::Validator,
            validators,
            data_types: vec![],
            functions: vec![],
            constants: vec![],
            type_aliases: vec![],
            test_count: 0,
            source_code: None,
            test_function_names: vec![],
        }
    }

    fn make_validator(name: &str, handlers: Vec<HandlerInfo>) -> ValidatorInfo {
        ValidatorInfo {
            name: name.to_string(),
            params: vec![],
            handlers,
            summary: None,
        }
    }

    fn make_handler(name: &str, tx_accesses: &[&str]) -> HandlerInfo {
        HandlerInfo {
            name: name.to_string(),
            params: vec![],
            return_type: "Bool".to_string(),
            location: None,
            body_signals: BodySignals {
                tx_field_accesses: tx_accesses.iter().map(|s| s.to_string()).collect(),
                ..Default::default()
            },
        }
    }

    #[test]
    fn test_colocated_mint_spend() {
        let modules = vec![make_module(
            "test/pool",
            vec![make_validator(
                "pool",
                vec![
                    make_handler("spend", &["outputs"]),
                    make_handler("mint", &["mint"]),
                ],
            )],
        )];

        let vg = ValidatorGraph::build(&modules);
        assert_eq!(vg.validator_count(), 1);
        assert!(vg.relation_count() >= 1);
    }

    #[test]
    fn test_mint_coordination() {
        let modules = vec![
            make_module(
                "test/pool",
                vec![make_validator(
                    "pool",
                    vec![make_handler("spend", &["outputs", "mint"])],
                )],
            ),
            make_module(
                "test/token",
                vec![make_validator(
                    "token",
                    vec![make_handler("mint", &["mint"])],
                )],
            ),
        ];

        let vg = ValidatorGraph::build(&modules);
        assert_eq!(vg.validator_count(), 2);
        // pool→token mint coordination
        let relations = vg.relations_of("test/pool", "pool");
        assert!(
            relations
                .iter()
                .any(|(_, r)| matches!(r, ValidatorRelation::MintCoordination)),
            "should detect mint coordination"
        );
    }

    #[test]
    fn test_empty_modules() {
        let vg = ValidatorGraph::build(&[]);
        assert_eq!(vg.validator_count(), 0);
        assert_eq!(vg.relation_count(), 0);
    }
}
