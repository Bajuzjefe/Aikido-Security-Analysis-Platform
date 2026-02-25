//! Control Flow Graph construction from Aiken TypedExpr.
//!
//! Builds a simplified CFG that tracks branching paths through when/if expressions.
//! Used for path-sensitive analysis: detecting which variables are guarded on which
//! paths and identifying dead branches.

use std::collections::HashMap;

use petgraph::graph::{DiGraph, NodeIndex};

/// A control flow graph for a single handler or function body.
#[derive(Debug, Clone, Default)]
pub struct CfgGraph {
    /// The directed graph of basic blocks.
    pub graph: DiGraph<BasicBlock, CfgEdge>,
    /// Entry block index.
    pub entry: Option<NodeIndex>,
    /// All variable definitions (name → defining block + statement index).
    pub var_defs: HashMap<String, (NodeIndex, usize)>,
}

/// A basic block: a sequence of statements with a single terminator.
#[derive(Debug, Clone)]
pub struct BasicBlock {
    pub id: usize,
    pub stmts: Vec<CfgStmt>,
    pub terminator: Terminator,
}

/// Edge label in the CFG.
#[derive(Debug, Clone)]
pub enum CfgEdge {
    /// Unconditional flow.
    Unconditional,
    /// True branch of an if/when condition.
    TrueBranch,
    /// False/else branch.
    FalseBranch,
    /// Pattern match arm with pattern description.
    PatternArm(String),
    /// Error/fail edge.
    ErrorEdge,
}

/// A statement within a basic block.
#[derive(Debug, Clone)]
pub enum CfgStmt {
    /// Variable assignment: `let name = expr` or `expect pattern = expr`.
    Assign {
        target: String,
        source: CfgExpr,
        is_expect: bool,
    },
    /// Function call (may have side effects).
    Call { function: String, args: Vec<String> },
    /// Guard/assertion: a condition that must hold.
    Guard {
        var: String,
        op: GuardOp,
        compared_to: Option<String>,
    },
    /// Record field access tracked for analysis.
    FieldAccess {
        target: String,
        record: String,
        field: String,
    },
}

/// Simplified expression representation.
#[derive(Debug, Clone)]
pub enum CfgExpr {
    Var(String),
    Literal(String),
    FieldAccess {
        record: String,
        field: String,
    },
    BinOp {
        op: String,
        left: String,
        right: String,
    },
    Call {
        function: String,
        args: Vec<String>,
    },
    RecordUpdate {
        base: String,
        fields: Vec<(String, String)>,
    },
}

/// Guard comparison operators.
#[derive(Debug, Clone, PartialEq)]
pub enum GuardOp {
    Eq,
    NotEq,
    Gt,
    GtEq,
    Lt,
    LtEq,
}

/// Block terminator — how control leaves this block.
#[derive(Debug, Clone)]
pub enum Terminator {
    /// Unconditional jump to next block.
    Goto,
    /// Conditional branch (if expression).
    Branch { condition: String },
    /// Pattern match (when expression).
    Switch { subject: String, arm_count: usize },
    /// Return from function/handler.
    Return,
    /// Error/fail terminator — unreachable after this.
    Error,
    /// Not yet assigned (during construction).
    Pending,
}

impl Default for BasicBlock {
    fn default() -> Self {
        Self {
            id: 0,
            stmts: Vec::new(),
            terminator: Terminator::Pending,
        }
    }
}

impl CfgGraph {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a new basic block and return its node index.
    pub fn add_block(&mut self, block: BasicBlock) -> NodeIndex {
        self.graph.add_node(block)
    }

    /// Add an edge between two blocks.
    pub fn add_edge(&mut self, from: NodeIndex, to: NodeIndex, edge: CfgEdge) {
        self.graph.add_edge(from, to, edge);
    }

    /// Get the number of basic blocks.
    pub fn block_count(&self) -> usize {
        self.graph.node_count()
    }

    /// Get the number of edges.
    pub fn edge_count(&self) -> usize {
        self.graph.edge_count()
    }

    /// Check if a block is reachable from the entry.
    pub fn is_reachable(&self, target: NodeIndex) -> bool {
        if let Some(entry) = self.entry {
            petgraph::algo::has_path_connecting(&self.graph, entry, target, None)
        } else {
            false
        }
    }

    /// Get all paths from entry to a given block (for path-sensitive analysis).
    /// Returns conditions encountered along each path.
    pub fn paths_to(&self, target: NodeIndex) -> Vec<Vec<PathCondition>> {
        let mut paths = Vec::new();
        if let Some(entry) = self.entry {
            let mut current_path = Vec::new();
            self.dfs_paths(
                entry,
                target,
                &mut current_path,
                &mut paths,
                &mut Vec::new(),
            );
        }
        paths
    }

    fn dfs_paths(
        &self,
        current: NodeIndex,
        target: NodeIndex,
        current_path: &mut Vec<PathCondition>,
        all_paths: &mut Vec<Vec<PathCondition>>,
        visited: &mut Vec<NodeIndex>,
    ) {
        if visited.contains(&current) {
            return; // Avoid cycles
        }
        visited.push(current);

        if current == target {
            all_paths.push(current_path.clone());
            visited.pop();
            return;
        }

        // Follow all outgoing edges
        let neighbors: Vec<_> = self
            .graph
            .neighbors_directed(current, petgraph::Direction::Outgoing)
            .collect();
        for neighbor in neighbors {
            // Find the edge to get the condition
            if let Some(edge) = self.graph.find_edge(current, neighbor) {
                let edge_label = &self.graph[edge];
                let condition = match edge_label {
                    CfgEdge::TrueBranch => {
                        if let Some(block) = self.graph.node_weight(current) {
                            if let Terminator::Branch { condition } = &block.terminator {
                                Some(PathCondition::True(condition.clone()))
                            } else {
                                None
                            }
                        } else {
                            None
                        }
                    }
                    CfgEdge::FalseBranch => {
                        if let Some(block) = self.graph.node_weight(current) {
                            if let Terminator::Branch { condition } = &block.terminator {
                                Some(PathCondition::False(condition.clone()))
                            } else {
                                None
                            }
                        } else {
                            None
                        }
                    }
                    CfgEdge::PatternArm(pattern) => Some(PathCondition::Pattern(pattern.clone())),
                    CfgEdge::ErrorEdge => Some(PathCondition::Error),
                    CfgEdge::Unconditional => None,
                };
                if let Some(ref cond) = condition {
                    current_path.push(cond.clone());
                }
                self.dfs_paths(neighbor, target, current_path, all_paths, visited);
                if condition.is_some() {
                    current_path.pop();
                }
            }
        }

        visited.pop();
    }

    /// Find all blocks that end in Error terminator (dead ends / fail paths).
    pub fn error_blocks(&self) -> Vec<NodeIndex> {
        self.graph
            .node_indices()
            .filter(|&idx| matches!(self.graph[idx].terminator, Terminator::Error))
            .collect()
    }

    /// Find unreachable blocks (not reachable from entry).
    pub fn unreachable_blocks(&self) -> Vec<NodeIndex> {
        self.graph
            .node_indices()
            .filter(|&idx| !self.is_reachable(idx))
            .collect()
    }
}

/// A condition encountered along a path in the CFG.
#[derive(Debug, Clone)]
pub enum PathCondition {
    /// Condition was true on this path.
    True(String),
    /// Condition was false on this path.
    False(String),
    /// Matched a specific pattern.
    Pattern(String),
    /// Path went through error/fail.
    Error,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_cfg() {
        let cfg = CfgGraph::new();
        assert_eq!(cfg.block_count(), 0);
        assert_eq!(cfg.edge_count(), 0);
    }

    #[test]
    fn test_linear_cfg() {
        let mut cfg = CfgGraph::new();
        let b0 = cfg.add_block(BasicBlock {
            id: 0,
            stmts: vec![],
            terminator: Terminator::Goto,
        });
        let b1 = cfg.add_block(BasicBlock {
            id: 1,
            stmts: vec![],
            terminator: Terminator::Return,
        });
        cfg.entry = Some(b0);
        cfg.add_edge(b0, b1, CfgEdge::Unconditional);

        assert_eq!(cfg.block_count(), 2);
        assert!(cfg.is_reachable(b1));
    }

    #[test]
    fn test_branch_cfg() {
        let mut cfg = CfgGraph::new();
        let entry = cfg.add_block(BasicBlock {
            id: 0,
            stmts: vec![],
            terminator: Terminator::Branch {
                condition: "x > 0".to_string(),
            },
        });
        let true_block = cfg.add_block(BasicBlock {
            id: 1,
            stmts: vec![],
            terminator: Terminator::Return,
        });
        let false_block = cfg.add_block(BasicBlock {
            id: 2,
            stmts: vec![],
            terminator: Terminator::Error,
        });
        cfg.entry = Some(entry);
        cfg.add_edge(entry, true_block, CfgEdge::TrueBranch);
        cfg.add_edge(entry, false_block, CfgEdge::FalseBranch);

        assert!(cfg.is_reachable(true_block));
        assert!(cfg.is_reachable(false_block));
        assert_eq!(cfg.error_blocks().len(), 1);
    }

    #[test]
    fn test_unreachable_blocks() {
        let mut cfg = CfgGraph::new();
        let b0 = cfg.add_block(BasicBlock {
            id: 0,
            stmts: vec![],
            terminator: Terminator::Return,
        });
        let _b1 = cfg.add_block(BasicBlock {
            id: 1,
            stmts: vec![],
            terminator: Terminator::Return,
        });
        cfg.entry = Some(b0);
        // b1 is unreachable — no edge to it

        assert_eq!(cfg.unreachable_blocks().len(), 1);
    }

    #[test]
    fn test_paths_to() {
        let mut cfg = CfgGraph::new();
        let entry = cfg.add_block(BasicBlock {
            id: 0,
            stmts: vec![],
            terminator: Terminator::Branch {
                condition: "is_valid".to_string(),
            },
        });
        let true_block = cfg.add_block(BasicBlock {
            id: 1,
            stmts: vec![],
            terminator: Terminator::Goto,
        });
        let false_block = cfg.add_block(BasicBlock {
            id: 2,
            stmts: vec![],
            terminator: Terminator::Goto,
        });
        let merge = cfg.add_block(BasicBlock {
            id: 3,
            stmts: vec![],
            terminator: Terminator::Return,
        });
        cfg.entry = Some(entry);
        cfg.add_edge(entry, true_block, CfgEdge::TrueBranch);
        cfg.add_edge(entry, false_block, CfgEdge::FalseBranch);
        cfg.add_edge(true_block, merge, CfgEdge::Unconditional);
        cfg.add_edge(false_block, merge, CfgEdge::Unconditional);

        let paths = cfg.paths_to(merge);
        assert_eq!(paths.len(), 2, "should have 2 paths to merge block");
    }
}
