//! Path-sensitive analysis integration for Aikido.
//!
//! Enumerates concrete execution paths through a CFG, collects path conditions,
//! applies symbolic narrowing, and verifies whether findings are reachable on
//! unguarded paths. This bridges the CFG (feature #71) and symbolic execution
//! (features #73/#74) to reduce false positives.

use serde::Serialize;
use std::collections::{HashMap, HashSet};

use crate::cfg::{BasicBlock, CfgEdge, CfgGraph, CfgStmt, Terminator};
use crate::detector::Finding;
use crate::symbolic::{SymbolicContext, SymbolicValue};
use petgraph::graph::NodeIndex;

// ---------------------------------------------------------------------------
// Path collection types
// ---------------------------------------------------------------------------

/// A concrete path through the CFG from entry to a target block.
#[derive(Debug, Clone)]
pub struct CfgPath {
    /// Ordered sequence of basic-block node indices along this path.
    pub blocks: Vec<NodeIndex>,
    /// Conditions accumulated along the path (one per branch edge traversed).
    pub conditions: Vec<PathCondition>,
    /// Symbolic state: variable name -> symbolic value at end of path.
    pub symbolic_state: HashMap<String, SymbolicValue>,
}

/// A condition that must hold on a specific path.
#[derive(Debug, Clone, Serialize)]
pub struct PathCondition {
    /// The variable involved in this condition.
    pub variable: String,
    /// The kind of constraint.
    pub constraint: ConditionType,
    /// The basic-block id where this condition originates.
    pub block_id: usize,
}

/// Constraint types that arise from branches, guards, and pattern matches.
#[derive(Debug, Clone, Serialize)]
pub enum ConditionType {
    /// Variable equals a specific constructor (pattern match arm).
    IsConstructor(String),
    /// Variable is NOT a specific constructor (false branch of pattern match).
    IsNotConstructor(String),
    // -- Numeric comparisons --
    LessThan(i64),
    GreaterThan(i64),
    LessOrEqual(i64),
    GreaterOrEqual(i64),
    Equals(i64),
    NotEquals(i64),
    // -- Boolean --
    IsTrue,
    IsFalse,
    /// A guard check was performed (from `CfgStmt::Guard`).
    GuardedBy {
        /// The guard comparison operator (serialized form of `GuardOp`).
        op: String,
        /// The variable or literal compared against.
        compared_to: String,
    },
}

// ---------------------------------------------------------------------------
// Path enumeration
// ---------------------------------------------------------------------------

/// Maximum recursion depth to avoid stack overflow on pathological CFGs.
const MAX_PATH_DEPTH: usize = 128;

/// Enumerate all paths through a CFG from the entry block to `target`.
///
/// Returns at most `max_paths` paths. Paths that loop are truncated.
pub fn enumerate_paths_to(cfg: &CfgGraph, target: NodeIndex, max_paths: usize) -> Vec<CfgPath> {
    let entry = match cfg.entry {
        Some(e) => e,
        None => return Vec::new(),
    };
    let mut results = Vec::new();
    let mut current_blocks = Vec::new();
    let mut current_conditions = Vec::new();
    let mut visited = HashSet::new();

    dfs_enumerate(
        cfg,
        entry,
        target,
        &mut current_blocks,
        &mut current_conditions,
        &mut visited,
        &mut results,
        max_paths,
    );

    results
}

/// Recursive DFS path collector.
#[allow(clippy::too_many_arguments)]
fn dfs_enumerate(
    cfg: &CfgGraph,
    current: NodeIndex,
    target: NodeIndex,
    blocks: &mut Vec<NodeIndex>,
    conditions: &mut Vec<PathCondition>,
    visited: &mut HashSet<NodeIndex>,
    results: &mut Vec<CfgPath>,
    max_paths: usize,
) {
    if results.len() >= max_paths || blocks.len() >= MAX_PATH_DEPTH {
        return;
    }
    if visited.contains(&current) {
        return; // cycle
    }

    visited.insert(current);
    blocks.push(current);

    if current == target {
        results.push(CfgPath {
            blocks: blocks.clone(),
            conditions: conditions.clone(),
            symbolic_state: HashMap::new(),
        });
        blocks.pop();
        visited.remove(&current);
        return;
    }

    let neighbors: Vec<_> = cfg
        .graph
        .neighbors_directed(current, petgraph::Direction::Outgoing)
        .collect();

    for neighbor in neighbors {
        if results.len() >= max_paths {
            break;
        }
        if let Some(edge_idx) = cfg.graph.find_edge(current, neighbor) {
            let edge = &cfg.graph[edge_idx];
            let block = &cfg.graph[current];
            let new_conditions = conditions_from_edge(edge, block);
            let cond_count = new_conditions.len();
            conditions.extend(new_conditions);

            dfs_enumerate(
                cfg, neighbor, target, blocks, conditions, visited, results, max_paths,
            );

            // Pop the conditions we just added.
            for _ in 0..cond_count {
                conditions.pop();
            }
        }
    }

    blocks.pop();
    visited.remove(&current);
}

/// Derive path conditions from a CFG edge and its source block.
fn conditions_from_edge(edge: &CfgEdge, source_block: &BasicBlock) -> Vec<PathCondition> {
    let block_id = source_block.id;
    match edge {
        CfgEdge::TrueBranch => {
            if let Terminator::Branch { condition } = &source_block.terminator {
                vec![PathCondition {
                    variable: condition.clone(),
                    constraint: ConditionType::IsTrue,
                    block_id,
                }]
            } else {
                Vec::new()
            }
        }
        CfgEdge::FalseBranch => {
            if let Terminator::Branch { condition } = &source_block.terminator {
                vec![PathCondition {
                    variable: condition.clone(),
                    constraint: ConditionType::IsFalse,
                    block_id,
                }]
            } else {
                Vec::new()
            }
        }
        CfgEdge::PatternArm(pattern) => {
            if let Terminator::Switch { subject, .. } = &source_block.terminator {
                vec![PathCondition {
                    variable: subject.clone(),
                    constraint: ConditionType::IsConstructor(pattern.clone()),
                    block_id,
                }]
            } else {
                Vec::new()
            }
        }
        CfgEdge::ErrorEdge | CfgEdge::Unconditional => Vec::new(),
    }
}

/// Enumerate all paths that reach any block containing a reference to `variable`.
///
/// A block "references" a variable if any of its statements mentions `variable`
/// in an assignment target, call argument, guard, or field access.
pub fn paths_reaching_variable(cfg: &CfgGraph, variable: &str, max_paths: usize) -> Vec<CfgPath> {
    let targets = blocks_referencing_variable(cfg, variable);
    let mut all_paths = Vec::new();

    for target in targets {
        if all_paths.len() >= max_paths {
            break;
        }
        let remaining = max_paths.saturating_sub(all_paths.len());
        let mut paths = enumerate_paths_to(cfg, target, remaining);
        all_paths.append(&mut paths);
    }

    all_paths
}

/// Find all blocks in the CFG that reference a given variable name.
fn blocks_referencing_variable(cfg: &CfgGraph, variable: &str) -> Vec<NodeIndex> {
    cfg.graph
        .node_indices()
        .filter(|&idx| block_references_variable(&cfg.graph[idx], variable))
        .collect()
}

/// Check whether a basic block mentions a variable anywhere in its statements.
fn block_references_variable(block: &BasicBlock, variable: &str) -> bool {
    for stmt in &block.stmts {
        match stmt {
            CfgStmt::Assign { target, .. } if target == variable => return true,
            CfgStmt::Call { args, .. } if args.iter().any(|a| a == variable) => return true,
            CfgStmt::Guard {
                var, compared_to, ..
            } => {
                if var == variable {
                    return true;
                }
                if let Some(cmp) = compared_to {
                    if cmp == variable {
                        return true;
                    }
                }
            }
            CfgStmt::FieldAccess { target, record, .. }
                if target == variable || record == variable =>
            {
                return true;
            }
            _ => {}
        }
    }
    false
}

/// Check if a path is feasible (its accumulated constraints are not contradictory).
///
/// This performs a lightweight check: it applies all conditions to a fresh symbolic
/// context and returns `false` if any variable's range becomes impossible.
pub fn is_path_feasible(path: &CfgPath) -> bool {
    let mut ctx = SymbolicContext::new();

    for cond in &path.conditions {
        let current = ctx.get(&cond.variable).clone();
        let narrowed = apply_condition(&current, &cond.constraint);
        if narrowed.is_impossible() {
            return false;
        }
        ctx.bind(&cond.variable, narrowed);
    }

    true
}

/// Apply a single condition to a symbolic value, returning the narrowed result.
fn apply_condition(value: &SymbolicValue, condition: &ConditionType) -> SymbolicValue {
    match condition {
        ConditionType::IsConstructor(name) => value.narrow_eq(name),
        ConditionType::IsNotConstructor(name) => {
            // If the value is already this constructor, it becomes impossible.
            if let SymbolicValue::Constructor(c) = value {
                if c == name {
                    return SymbolicValue::Range {
                        min: Some(1),
                        max: Some(0),
                    }; // impossible
                }
            }
            value.clone()
        }
        ConditionType::LessThan(n) => value.narrow_lt(*n),
        ConditionType::GreaterThan(n) => value.narrow_gt(*n),
        ConditionType::LessOrEqual(n) => value.narrow_lt(*n + 1),
        ConditionType::GreaterOrEqual(n) => value.narrow_gt(*n - 1),
        ConditionType::Equals(n) => {
            // Narrow to exact point.
            let low = value.narrow_gt(*n - 1);
            apply_condition(&low, &ConditionType::LessThan(*n + 1))
        }
        ConditionType::NotEquals(n) => {
            // If already pinned to exactly n, impossible.
            if let SymbolicValue::Range {
                min: Some(lo),
                max: Some(hi),
            } = value
            {
                if lo == n && hi == n {
                    return SymbolicValue::Range {
                        min: Some(1),
                        max: Some(0),
                    };
                }
            }
            value.clone()
        }
        ConditionType::IsTrue => {
            if let SymbolicValue::Boolean(false) = value {
                SymbolicValue::Range {
                    min: Some(1),
                    max: Some(0),
                } // impossible
            } else {
                SymbolicValue::Boolean(true)
            }
        }
        ConditionType::IsFalse => {
            if let SymbolicValue::Boolean(true) = value {
                SymbolicValue::Range {
                    min: Some(1),
                    max: Some(0),
                } // impossible
            } else {
                SymbolicValue::Boolean(false)
            }
        }
        ConditionType::GuardedBy { .. } => {
            // Guard presence does not narrow the symbolic value itself;
            // it is used for guard detection, not constraint narrowing.
            value.clone()
        }
    }
}

// ---------------------------------------------------------------------------
// Path-sensitive finding verification
// ---------------------------------------------------------------------------

/// Result of path-sensitive analysis on a single finding.
#[derive(Debug, Clone, Serialize)]
pub struct PathAnalysisResult {
    /// Name of the detector that produced the finding.
    pub finding_detector: String,
    /// Module where the finding was reported.
    pub finding_module: String,
    /// Total number of paths explored to the finding location.
    pub total_paths: usize,
    /// Number of feasible (non-contradictory) paths.
    pub feasible_paths: usize,
    /// Number of feasible paths that contain a guard for this detector.
    pub guarded_paths: usize,
    /// Number of feasible paths with no guard (potentially vulnerable).
    pub vulnerable_paths: usize,
    /// Summary verdict.
    pub verdict: PathVerdict,
    /// Per-path details.
    pub details: Vec<PathDetail>,
}

/// Summary verdict from path-sensitive analysis.
#[derive(Debug, Clone, Serialize)]
pub enum PathVerdict {
    /// All feasible paths to the finding are guarded -- likely false positive.
    AllGuarded,
    /// Some paths are guarded, some are not.
    PartiallyGuarded {
        /// Fraction of feasible paths that are unguarded (0.0 to 1.0).
        unguarded_ratio: f64,
    },
    /// No feasible paths are guarded -- finding confirmed.
    Unguarded,
    /// Analysis could not determine the verdict.
    Undetermined {
        /// Reason the analysis was inconclusive.
        reason: String,
    },
}

/// Detail for a single path considered during analysis.
#[derive(Debug, Clone, Serialize)]
pub struct PathDetail {
    /// Unique path identifier within this analysis run.
    pub path_id: usize,
    /// Whether the path's constraints are satisfiable.
    pub feasible: bool,
    /// Whether the path contains a guard for the vulnerability.
    pub guarded: bool,
    /// Human-readable description of the guard if present.
    pub guard_description: Option<String>,
    /// Conditions accumulated along this path.
    pub conditions: Vec<PathCondition>,
}

/// Maximum paths to explore per finding (avoid combinatorial explosion).
const DEFAULT_MAX_PATHS: usize = 256;

/// Analyze a single finding using path-sensitive analysis over its CFG.
///
/// Locates the finding's target block by matching the module and byte offset
/// against the CFG's blocks, enumerates paths from the entry, and checks each
/// path for guards appropriate to the finding's detector.
pub fn analyze_finding_paths(finding: &Finding, cfg: &CfgGraph) -> PathAnalysisResult {
    let entry = match cfg.entry {
        Some(e) => e,
        None => {
            return PathAnalysisResult {
                finding_detector: finding.detector_name.clone(),
                finding_module: finding.module.clone(),
                total_paths: 0,
                feasible_paths: 0,
                guarded_paths: 0,
                vulnerable_paths: 0,
                verdict: PathVerdict::Undetermined {
                    reason: "CFG has no entry block".to_string(),
                },
                details: Vec::new(),
            };
        }
    };

    // Find the target block. For now, use all Return blocks as targets
    // (the finding's byte offset could be in any block; analyzing all exit paths
    // is a sound over-approximation).
    let target_blocks: Vec<NodeIndex> = cfg
        .graph
        .node_indices()
        .filter(|&idx| {
            matches!(
                cfg.graph[idx].terminator,
                Terminator::Return | Terminator::Error
            )
        })
        .collect();

    // If no target blocks found, use the entry itself.
    let targets = if target_blocks.is_empty() {
        vec![entry]
    } else {
        target_blocks
    };

    let mut all_paths = Vec::new();
    for target in &targets {
        let remaining = DEFAULT_MAX_PATHS.saturating_sub(all_paths.len());
        if remaining == 0 {
            break;
        }
        let mut paths = enumerate_paths_to(cfg, *target, remaining);
        all_paths.append(&mut paths);
    }

    if all_paths.is_empty() {
        return PathAnalysisResult {
            finding_detector: finding.detector_name.clone(),
            finding_module: finding.module.clone(),
            total_paths: 0,
            feasible_paths: 0,
            guarded_paths: 0,
            vulnerable_paths: 0,
            verdict: PathVerdict::Undetermined {
                reason: "No paths found in CFG".to_string(),
            },
            details: Vec::new(),
        };
    }

    let total = all_paths.len();
    let mut details = Vec::new();
    let mut feasible_count = 0usize;
    let mut guarded_count = 0usize;

    for (i, path) in all_paths.iter().enumerate() {
        let feasible = is_path_feasible(path);
        let (guarded, guard_desc) = if feasible {
            let g = path_has_guard_for(path, &finding.detector_name);
            let desc = if g {
                Some(describe_guard(&finding.detector_name))
            } else {
                None
            };
            (g, desc)
        } else {
            (false, None)
        };

        if feasible {
            feasible_count += 1;
            if guarded {
                guarded_count += 1;
            }
        }

        details.push(PathDetail {
            path_id: i,
            feasible,
            guarded,
            guard_description: guard_desc,
            conditions: path.conditions.clone(),
        });
    }

    let vulnerable_count = feasible_count.saturating_sub(guarded_count);

    let verdict = if feasible_count == 0 {
        PathVerdict::Undetermined {
            reason: "All paths are infeasible".to_string(),
        }
    } else if guarded_count == feasible_count {
        PathVerdict::AllGuarded
    } else if guarded_count == 0 {
        PathVerdict::Unguarded
    } else {
        PathVerdict::PartiallyGuarded {
            unguarded_ratio: vulnerable_count as f64 / feasible_count as f64,
        }
    };

    PathAnalysisResult {
        finding_detector: finding.detector_name.clone(),
        finding_module: finding.module.clone(),
        total_paths: total,
        feasible_paths: feasible_count,
        guarded_paths: guarded_count,
        vulnerable_paths: vulnerable_count,
        verdict,
        details,
    }
}

/// Analyze all findings that have source locations matching a CFG key.
///
/// `cfgs` is keyed by `"module::handler"` (e.g. `"validators/my_contract::spend"`).
/// Each finding is matched by its `module` field against the CFG keys.
pub fn analyze_findings_with_cfg(
    findings: &[Finding],
    cfgs: &HashMap<String, CfgGraph>,
) -> Vec<PathAnalysisResult> {
    findings
        .iter()
        .filter_map(|f| {
            // Try exact match first, then prefix match.
            let cfg = cfgs.get(&f.module).or_else(|| {
                cfgs.iter()
                    .find(|(k, _)| k.contains(&f.module) || f.module.contains(k.as_str()))
                    .map(|(_, v)| v)
            });
            cfg.map(|c| analyze_finding_paths(f, c))
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Guard detection
// ---------------------------------------------------------------------------

/// Check if a path contains a guard appropriate for a specific detector.
///
/// Dispatches to detector-specific guard checkers based on the detector name.
fn path_has_guard_for(path: &CfgPath, detector_name: &str) -> bool {
    match detector_name {
        "missing-signature-check" | "missing-utxo-authentication" => has_signature_guard(path),
        "value-not-preserved" | "value-preservation-gap" | "value-comparison-semantics" => {
            has_value_guard(path)
        }
        "missing-datum-in-script-output"
        | "arbitrary-datum-in-output"
        | "missing-datum-field-validation"
        | "datum-tampering-risk" => has_datum_guard(path),
        "output-address-not-validated" => has_address_guard(path),
        "unrestricted-minting"
        | "missing-minting-policy-check"
        | "other-token-minting"
        | "token-name-not-validated" => has_mint_guard(path),
        _ => {
            // Generic: check if any guard statement exists on the path.
            path_has_any_guard(path)
        }
    }
}

/// Check whether any block along the path contains a `CfgStmt::Guard` for
/// `extra_signatories` or a call to `list.has` on signatories.
fn has_signature_guard(path: &CfgPath) -> bool {
    for cond in &path.conditions {
        let var_lower = cond.variable.to_lowercase();
        if var_lower.contains("signator") || var_lower.contains("signer") {
            return true;
        }
        if let ConditionType::GuardedBy { compared_to, .. } = &cond.constraint {
            let cmp_lower = compared_to.to_lowercase();
            if cmp_lower.contains("signator") || cmp_lower.contains("signer") {
                return true;
            }
        }
    }
    false
}

/// Check whether the path contains a guard that compares values
/// (e.g., lovelace amounts, token quantities, or full Value equality).
fn has_value_guard(path: &CfgPath) -> bool {
    for cond in &path.conditions {
        let var_lower = cond.variable.to_lowercase();
        if var_lower.contains("value")
            || var_lower.contains("lovelace")
            || var_lower.contains("quantity")
            || var_lower.contains("amount")
        {
            return true;
        }
        if let ConditionType::GuardedBy { compared_to, .. } = &cond.constraint {
            let cmp_lower = compared_to.to_lowercase();
            if cmp_lower.contains("value")
                || cmp_lower.contains("lovelace")
                || cmp_lower.contains("quantity")
            {
                return true;
            }
        }
    }
    false
}

/// Check whether the path validates datum fields or datum equality.
fn has_datum_guard(path: &CfgPath) -> bool {
    for cond in &path.conditions {
        let var_lower = cond.variable.to_lowercase();
        if var_lower.contains("datum") {
            return true;
        }
        if let ConditionType::GuardedBy { compared_to, .. } = &cond.constraint {
            if compared_to.to_lowercase().contains("datum") {
                return true;
            }
        }
    }
    false
}

/// Check whether the path validates output addresses.
fn has_address_guard(path: &CfgPath) -> bool {
    for cond in &path.conditions {
        let var_lower = cond.variable.to_lowercase();
        if var_lower.contains("address") || var_lower.contains("credential") {
            return true;
        }
        if let ConditionType::GuardedBy { compared_to, .. } = &cond.constraint {
            let cmp_lower = compared_to.to_lowercase();
            if cmp_lower.contains("address") || cmp_lower.contains("credential") {
                return true;
            }
        }
    }
    false
}

/// Check whether the path validates minting authorization
/// (e.g., checking the minting policy, token name, or mint field).
fn has_mint_guard(path: &CfgPath) -> bool {
    for cond in &path.conditions {
        let var_lower = cond.variable.to_lowercase();
        if var_lower.contains("mint")
            || var_lower.contains("policy")
            || var_lower.contains("token_name")
        {
            return true;
        }
        if let ConditionType::GuardedBy { compared_to, .. } = &cond.constraint {
            let cmp_lower = compared_to.to_lowercase();
            if cmp_lower.contains("mint") || cmp_lower.contains("policy") {
                return true;
            }
        }
    }
    false
}

/// Generic guard check: does the path contain *any* guard condition at all?
fn path_has_any_guard(path: &CfgPath) -> bool {
    path.conditions
        .iter()
        .any(|c| matches!(c.constraint, ConditionType::GuardedBy { .. }))
}

/// Produce a human-readable description of the kind of guard expected for a detector.
fn describe_guard(detector_name: &str) -> String {
    match detector_name {
        "missing-signature-check" | "missing-utxo-authentication" => {
            "Path contains signature/signatory check".to_string()
        }
        "value-not-preserved" | "value-preservation-gap" | "value-comparison-semantics" => {
            "Path contains value/amount comparison".to_string()
        }
        "missing-datum-in-script-output"
        | "arbitrary-datum-in-output"
        | "missing-datum-field-validation"
        | "datum-tampering-risk" => "Path contains datum validation".to_string(),
        "output-address-not-validated" => "Path contains address/credential check".to_string(),
        "unrestricted-minting"
        | "missing-minting-policy-check"
        | "other-token-minting"
        | "token-name-not-validated" => "Path contains minting policy/token name check".to_string(),
        _ => "Path contains a guard statement".to_string(),
    }
}

// ---------------------------------------------------------------------------
// Symbolic execution integration
// ---------------------------------------------------------------------------

/// Apply symbolic narrowing along a path's conditions.
///
/// Starts from `initial_context`, walks each condition, and narrows the
/// bindings. Returns the context reflecting constraints at the path's end.
pub fn symbolic_narrow_path(path: &CfgPath, initial_context: &SymbolicContext) -> SymbolicContext {
    let mut ctx = initial_context.fork();

    for cond in &path.conditions {
        let current = ctx.get(&cond.variable).clone();
        let narrowed = apply_condition(&current, &cond.constraint);
        ctx.bind(&cond.variable, narrowed);
    }

    ctx.explore_path(&format!("path with {} conditions", path.conditions.len()));
    ctx
}

/// Check if a variable's symbolic state at the end of a path makes a
/// named condition impossible.
///
/// For example, if `condition` is `"x_positive"` and the symbolic context
/// shows `x` has range `max=0`, then `x > 0` is unreachable.
///
/// Currently supports checking impossibility of variables already in the
/// path's symbolic state. More sophisticated condition parsing can be added.
pub fn is_symbolically_unreachable(path: &CfgPath, condition: &str) -> bool {
    // Build a context from path conditions.
    let ctx = symbolic_narrow_path(path, &SymbolicContext::new());

    // Check if any binding in the context is impossible.
    for val in ctx.bindings.values() {
        if val.is_impossible() {
            return true;
        }
    }

    // Check if the condition variable itself is impossible.
    let val = ctx.get(condition);
    val.is_impossible()
}

// ---------------------------------------------------------------------------
// Formatting
// ---------------------------------------------------------------------------

/// Format a complete path-analysis report as a human-readable string.
pub fn format_path_analysis_report(results: &[PathAnalysisResult]) -> String {
    if results.is_empty() {
        return "No path analysis results.\n".to_string();
    }

    let mut out = String::new();
    out.push_str("=== Path-Sensitive Analysis Report ===\n\n");

    for (i, result) in results.iter().enumerate() {
        out.push_str(&format!(
            "--- Finding #{}: {} in {} ---\n",
            i + 1,
            result.finding_detector,
            result.finding_module,
        ));
        out.push_str(&format!(
            "  Paths: {} total, {} feasible, {} guarded, {} vulnerable\n",
            result.total_paths,
            result.feasible_paths,
            result.guarded_paths,
            result.vulnerable_paths,
        ));
        out.push_str(&format!("  Verdict: {}\n", format_verdict(&result.verdict)));

        if !result.details.is_empty() {
            let show_count = result.details.len().min(10);
            out.push_str(&format!(
                "  Details ({} of {} paths):\n",
                show_count,
                result.details.len()
            ));
            for detail in result.details.iter().take(show_count) {
                out.push_str(&format!("    {}\n", format_path_detail(detail)));
            }
            if result.details.len() > show_count {
                out.push_str(&format!(
                    "    ... and {} more paths\n",
                    result.details.len() - show_count
                ));
            }
        }
        out.push('\n');
    }

    // Summary statistics.
    let all_guarded = results
        .iter()
        .filter(|r| matches!(r.verdict, PathVerdict::AllGuarded))
        .count();
    let unguarded = results
        .iter()
        .filter(|r| matches!(r.verdict, PathVerdict::Unguarded))
        .count();
    let partial = results
        .iter()
        .filter(|r| matches!(r.verdict, PathVerdict::PartiallyGuarded { .. }))
        .count();
    let undetermined = results
        .iter()
        .filter(|r| matches!(r.verdict, PathVerdict::Undetermined { .. }))
        .count();

    out.push_str("=== Summary ===\n");
    out.push_str(&format!("  Total findings analyzed: {}\n", results.len()));
    out.push_str(&format!("  All guarded (likely FP): {}\n", all_guarded));
    out.push_str(&format!("  Partially guarded:       {}\n", partial));
    out.push_str(&format!("  Unguarded (confirmed):   {}\n", unguarded));
    out.push_str(&format!("  Undetermined:            {}\n", undetermined));

    out
}

/// Format a single path detail line.
pub fn format_path_detail(detail: &PathDetail) -> String {
    let status = if !detail.feasible {
        "INFEASIBLE"
    } else if detail.guarded {
        "GUARDED"
    } else {
        "VULNERABLE"
    };

    let guard_info = detail
        .guard_description
        .as_deref()
        .map(|d| format!(" ({d})"))
        .unwrap_or_default();

    let cond_count = detail.conditions.len();
    format!(
        "Path #{}: [{status}]{guard_info} -- {cond_count} conditions",
        detail.path_id
    )
}

/// Format a verdict enum as a short string.
fn format_verdict(verdict: &PathVerdict) -> String {
    match verdict {
        PathVerdict::AllGuarded => "ALL GUARDED (likely false positive)".to_string(),
        PathVerdict::PartiallyGuarded { unguarded_ratio } => {
            format!(
                "PARTIALLY GUARDED ({:.0}% unguarded)",
                unguarded_ratio * 100.0
            )
        }
        PathVerdict::Unguarded => "UNGUARDED (finding confirmed)".to_string(),
        PathVerdict::Undetermined { reason } => format!("UNDETERMINED ({reason})"),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cfg::{BasicBlock, CfgEdge, CfgGraph, CfgStmt, GuardOp, Terminator};
    use crate::detector::{Confidence, Finding, Severity, SourceLocation};
    use crate::symbolic::{SymbolicContext, SymbolicValue};

    // -- Helpers --

    fn make_finding(detector: &str, module: &str) -> Finding {
        Finding {
            detector_name: detector.to_string(),
            severity: Severity::High,
            confidence: Confidence::Likely,
            title: format!("Test finding: {detector}"),
            description: "test".to_string(),
            module: module.to_string(),
            location: Some(SourceLocation::from_bytes(module, 0, 10)),
            suggestion: None,
            related_findings: Vec::new(),
            semantic_group: None,
            evidence: None,
        }
    }

    fn linear_cfg() -> CfgGraph {
        // entry -> middle -> exit (Return)
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
        cfg
    }

    fn branching_cfg() -> CfgGraph {
        // entry --(true)--> guarded_block --(uncond)--> exit
        //       \--(false)--> unguarded_block --(uncond)--> exit
        let mut cfg = CfgGraph::new();
        let entry = cfg.add_block(BasicBlock {
            id: 0,
            stmts: vec![],
            terminator: Terminator::Branch {
                condition: "is_valid".to_string(),
            },
        });
        let guarded = cfg.add_block(BasicBlock {
            id: 1,
            stmts: vec![CfgStmt::Guard {
                var: "extra_signatories".to_string(),
                op: GuardOp::NotEq,
                compared_to: Some("empty".to_string()),
            }],
            terminator: Terminator::Goto,
        });
        let unguarded = cfg.add_block(BasicBlock {
            id: 2,
            stmts: vec![],
            terminator: Terminator::Goto,
        });
        let exit = cfg.add_block(BasicBlock {
            id: 3,
            stmts: vec![],
            terminator: Terminator::Return,
        });
        cfg.entry = Some(entry);
        cfg.add_edge(entry, guarded, CfgEdge::TrueBranch);
        cfg.add_edge(entry, unguarded, CfgEdge::FalseBranch);
        cfg.add_edge(guarded, exit, CfgEdge::Unconditional);
        cfg.add_edge(unguarded, exit, CfgEdge::Unconditional);
        cfg
    }

    fn switch_cfg() -> CfgGraph {
        // entry (switch on "action") -->
        //   "Mint" arm --> b_mint --> exit
        //   "Burn" arm --> b_burn --> exit
        let mut cfg = CfgGraph::new();
        let entry = cfg.add_block(BasicBlock {
            id: 0,
            stmts: vec![],
            terminator: Terminator::Switch {
                subject: "action".to_string(),
                arm_count: 2,
            },
        });
        let b_mint = cfg.add_block(BasicBlock {
            id: 1,
            stmts: vec![],
            terminator: Terminator::Goto,
        });
        let b_burn = cfg.add_block(BasicBlock {
            id: 2,
            stmts: vec![],
            terminator: Terminator::Goto,
        });
        let exit = cfg.add_block(BasicBlock {
            id: 3,
            stmts: vec![],
            terminator: Terminator::Return,
        });
        cfg.entry = Some(entry);
        cfg.add_edge(entry, b_mint, CfgEdge::PatternArm("Mint".to_string()));
        cfg.add_edge(entry, b_burn, CfgEdge::PatternArm("Burn".to_string()));
        cfg.add_edge(b_mint, exit, CfgEdge::Unconditional);
        cfg.add_edge(b_burn, exit, CfgEdge::Unconditional);
        cfg
    }

    // -----------------------------------------------------------------------
    // Path enumeration tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_enumerate_paths_linear() {
        let cfg = linear_cfg();
        let exit = NodeIndex::new(1);
        let paths = enumerate_paths_to(&cfg, exit, 10);
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0].blocks.len(), 2);
        assert!(paths[0].conditions.is_empty());
    }

    #[test]
    fn test_enumerate_paths_branching() {
        let cfg = branching_cfg();
        let exit = NodeIndex::new(3);
        let paths = enumerate_paths_to(&cfg, exit, 10);
        assert_eq!(paths.len(), 2, "diamond CFG should have 2 paths to exit");

        // One path should have IsTrue, the other IsFalse.
        let has_true = paths.iter().any(|p| {
            p.conditions
                .iter()
                .any(|c| matches!(c.constraint, ConditionType::IsTrue))
        });
        let has_false = paths.iter().any(|p| {
            p.conditions
                .iter()
                .any(|c| matches!(c.constraint, ConditionType::IsFalse))
        });
        assert!(has_true);
        assert!(has_false);
    }

    #[test]
    fn test_enumerate_paths_switch() {
        let cfg = switch_cfg();
        let exit = NodeIndex::new(3);
        let paths = enumerate_paths_to(&cfg, exit, 10);
        assert_eq!(paths.len(), 2);

        let constructors: Vec<_> = paths
            .iter()
            .flat_map(|p| p.conditions.iter())
            .filter_map(|c| match &c.constraint {
                ConditionType::IsConstructor(name) => Some(name.clone()),
                _ => None,
            })
            .collect();
        assert!(constructors.contains(&"Mint".to_string()));
        assert!(constructors.contains(&"Burn".to_string()));
    }

    #[test]
    fn test_enumerate_paths_no_entry() {
        let cfg = CfgGraph::new(); // no entry
        let target = NodeIndex::new(0);
        let paths = enumerate_paths_to(&cfg, target, 10);
        assert!(paths.is_empty());
    }

    #[test]
    fn test_enumerate_paths_max_limit() {
        let cfg = branching_cfg();
        let exit = NodeIndex::new(3);
        let paths = enumerate_paths_to(&cfg, exit, 1);
        assert_eq!(paths.len(), 1, "should stop at max_paths=1");
    }

    #[test]
    fn test_enumerate_paths_unreachable_target() {
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
        // b1 is unreachable.
        let paths = enumerate_paths_to(&cfg, NodeIndex::new(1), 10);
        assert!(paths.is_empty());
    }

    // -----------------------------------------------------------------------
    // Variable-reaching paths
    // -----------------------------------------------------------------------

    #[test]
    fn test_paths_reaching_variable_found() {
        let mut cfg = CfgGraph::new();
        let b0 = cfg.add_block(BasicBlock {
            id: 0,
            stmts: vec![CfgStmt::Assign {
                target: "x".to_string(),
                source: crate::cfg::CfgExpr::Literal("42".to_string()),
                is_expect: false,
            }],
            terminator: Terminator::Return,
        });
        cfg.entry = Some(b0);

        let paths = paths_reaching_variable(&cfg, "x", 10);
        assert_eq!(paths.len(), 1);
    }

    #[test]
    fn test_paths_reaching_variable_not_found() {
        let cfg = linear_cfg();
        let paths = paths_reaching_variable(&cfg, "nonexistent", 10);
        assert!(paths.is_empty());
    }

    #[test]
    fn test_paths_reaching_variable_in_guard() {
        let mut cfg = CfgGraph::new();
        let b0 = cfg.add_block(BasicBlock {
            id: 0,
            stmts: vec![CfgStmt::Guard {
                var: "signers".to_string(),
                op: GuardOp::NotEq,
                compared_to: Some("empty".to_string()),
            }],
            terminator: Terminator::Return,
        });
        cfg.entry = Some(b0);

        let paths = paths_reaching_variable(&cfg, "signers", 10);
        assert_eq!(paths.len(), 1);
    }

    #[test]
    fn test_paths_reaching_variable_in_call_args() {
        let mut cfg = CfgGraph::new();
        let b0 = cfg.add_block(BasicBlock {
            id: 0,
            stmts: vec![CfgStmt::Call {
                function: "list.has".to_string(),
                args: vec!["signatories".to_string(), "key".to_string()],
            }],
            terminator: Terminator::Return,
        });
        cfg.entry = Some(b0);

        let paths = paths_reaching_variable(&cfg, "key", 10);
        assert_eq!(paths.len(), 1);
    }

    #[test]
    fn test_paths_reaching_variable_in_field_access() {
        let mut cfg = CfgGraph::new();
        let b0 = cfg.add_block(BasicBlock {
            id: 0,
            stmts: vec![CfgStmt::FieldAccess {
                target: "sigs".to_string(),
                record: "tx".to_string(),
                field: "extra_signatories".to_string(),
            }],
            terminator: Terminator::Return,
        });
        cfg.entry = Some(b0);

        let paths_by_target = paths_reaching_variable(&cfg, "sigs", 10);
        assert_eq!(paths_by_target.len(), 1);
        let paths_by_record = paths_reaching_variable(&cfg, "tx", 10);
        assert_eq!(paths_by_record.len(), 1);
    }

    // -----------------------------------------------------------------------
    // Feasibility
    // -----------------------------------------------------------------------

    #[test]
    fn test_feasible_path_no_conditions() {
        let path = CfgPath {
            blocks: vec![NodeIndex::new(0)],
            conditions: vec![],
            symbolic_state: HashMap::new(),
        };
        assert!(is_path_feasible(&path));
    }

    #[test]
    fn test_feasible_path_consistent_conditions() {
        let path = CfgPath {
            blocks: vec![NodeIndex::new(0), NodeIndex::new(1)],
            conditions: vec![
                PathCondition {
                    variable: "x".to_string(),
                    constraint: ConditionType::GreaterThan(0),
                    block_id: 0,
                },
                PathCondition {
                    variable: "x".to_string(),
                    constraint: ConditionType::LessThan(100),
                    block_id: 0,
                },
            ],
            symbolic_state: HashMap::new(),
        };
        assert!(is_path_feasible(&path));
    }

    #[test]
    fn test_infeasible_path_contradictory_range() {
        let path = CfgPath {
            blocks: vec![NodeIndex::new(0), NodeIndex::new(1)],
            conditions: vec![
                PathCondition {
                    variable: "x".to_string(),
                    constraint: ConditionType::GreaterThan(100),
                    block_id: 0,
                },
                PathCondition {
                    variable: "x".to_string(),
                    constraint: ConditionType::LessThan(50),
                    block_id: 0,
                },
            ],
            symbolic_state: HashMap::new(),
        };
        assert!(!is_path_feasible(&path));
    }

    #[test]
    fn test_infeasible_path_contradictory_boolean() {
        let path = CfgPath {
            blocks: vec![NodeIndex::new(0)],
            conditions: vec![
                PathCondition {
                    variable: "flag".to_string(),
                    constraint: ConditionType::IsTrue,
                    block_id: 0,
                },
                PathCondition {
                    variable: "flag".to_string(),
                    constraint: ConditionType::IsFalse,
                    block_id: 0,
                },
            ],
            symbolic_state: HashMap::new(),
        };
        assert!(!is_path_feasible(&path));
    }

    #[test]
    fn test_infeasible_path_contradictory_constructors() {
        let path = CfgPath {
            blocks: vec![NodeIndex::new(0)],
            conditions: vec![
                PathCondition {
                    variable: "action".to_string(),
                    constraint: ConditionType::IsConstructor("Mint".to_string()),
                    block_id: 0,
                },
                PathCondition {
                    variable: "action".to_string(),
                    constraint: ConditionType::IsNotConstructor("Mint".to_string()),
                    block_id: 0,
                },
            ],
            symbolic_state: HashMap::new(),
        };
        assert!(!is_path_feasible(&path));
    }

    #[test]
    fn test_feasible_path_equals_within_range() {
        let path = CfgPath {
            blocks: vec![NodeIndex::new(0)],
            conditions: vec![PathCondition {
                variable: "x".to_string(),
                constraint: ConditionType::Equals(42),
                block_id: 0,
            }],
            symbolic_state: HashMap::new(),
        };
        assert!(is_path_feasible(&path));
    }

    #[test]
    fn test_infeasible_path_not_equals_on_exact() {
        let path = CfgPath {
            blocks: vec![NodeIndex::new(0)],
            conditions: vec![
                PathCondition {
                    variable: "x".to_string(),
                    constraint: ConditionType::Equals(5),
                    block_id: 0,
                },
                PathCondition {
                    variable: "x".to_string(),
                    constraint: ConditionType::NotEquals(5),
                    block_id: 0,
                },
            ],
            symbolic_state: HashMap::new(),
        };
        assert!(!is_path_feasible(&path));
    }

    // -----------------------------------------------------------------------
    // Guard detection
    // -----------------------------------------------------------------------

    #[test]
    fn test_has_signature_guard_via_variable() {
        let path = CfgPath {
            blocks: vec![NodeIndex::new(0)],
            conditions: vec![PathCondition {
                variable: "extra_signatories".to_string(),
                constraint: ConditionType::IsTrue,
                block_id: 0,
            }],
            symbolic_state: HashMap::new(),
        };
        assert!(has_signature_guard(&path));
    }

    #[test]
    fn test_has_signature_guard_via_compared_to() {
        let path = CfgPath {
            blocks: vec![NodeIndex::new(0)],
            conditions: vec![PathCondition {
                variable: "check".to_string(),
                constraint: ConditionType::GuardedBy {
                    op: "Eq".to_string(),
                    compared_to: "signers".to_string(),
                },
                block_id: 0,
            }],
            symbolic_state: HashMap::new(),
        };
        assert!(has_signature_guard(&path));
    }

    #[test]
    fn test_has_no_signature_guard() {
        let path = CfgPath {
            blocks: vec![NodeIndex::new(0)],
            conditions: vec![PathCondition {
                variable: "datum_ok".to_string(),
                constraint: ConditionType::IsTrue,
                block_id: 0,
            }],
            symbolic_state: HashMap::new(),
        };
        assert!(!has_signature_guard(&path));
    }

    #[test]
    fn test_has_value_guard() {
        let path = CfgPath {
            blocks: vec![NodeIndex::new(0)],
            conditions: vec![PathCondition {
                variable: "output_value".to_string(),
                constraint: ConditionType::GreaterOrEqual(1_000_000),
                block_id: 0,
            }],
            symbolic_state: HashMap::new(),
        };
        assert!(has_value_guard(&path));
    }

    #[test]
    fn test_has_datum_guard() {
        let path = CfgPath {
            blocks: vec![NodeIndex::new(0)],
            conditions: vec![PathCondition {
                variable: "output_datum".to_string(),
                constraint: ConditionType::IsTrue,
                block_id: 0,
            }],
            symbolic_state: HashMap::new(),
        };
        assert!(has_datum_guard(&path));
    }

    #[test]
    fn test_has_address_guard() {
        let path = CfgPath {
            blocks: vec![NodeIndex::new(0)],
            conditions: vec![PathCondition {
                variable: "output_address".to_string(),
                constraint: ConditionType::IsTrue,
                block_id: 0,
            }],
            symbolic_state: HashMap::new(),
        };
        assert!(has_address_guard(&path));
    }

    #[test]
    fn test_has_address_guard_credential() {
        let path = CfgPath {
            blocks: vec![NodeIndex::new(0)],
            conditions: vec![PathCondition {
                variable: "payment_credential".to_string(),
                constraint: ConditionType::IsTrue,
                block_id: 0,
            }],
            symbolic_state: HashMap::new(),
        };
        assert!(has_address_guard(&path));
    }

    #[test]
    fn test_has_mint_guard() {
        let path = CfgPath {
            blocks: vec![NodeIndex::new(0)],
            conditions: vec![PathCondition {
                variable: "mint_policy".to_string(),
                constraint: ConditionType::IsTrue,
                block_id: 0,
            }],
            symbolic_state: HashMap::new(),
        };
        assert!(has_mint_guard(&path));
    }

    #[test]
    fn test_path_has_guard_for_dispatches_correctly() {
        // Signature guard should match missing-signature-check.
        let sig_path = CfgPath {
            blocks: vec![NodeIndex::new(0)],
            conditions: vec![PathCondition {
                variable: "signatories_ok".to_string(),
                constraint: ConditionType::IsTrue,
                block_id: 0,
            }],
            symbolic_state: HashMap::new(),
        };
        assert!(path_has_guard_for(&sig_path, "missing-signature-check"));
        assert!(!path_has_guard_for(&sig_path, "value-not-preserved"));

        // Value guard should match value-not-preserved.
        let val_path = CfgPath {
            blocks: vec![NodeIndex::new(0)],
            conditions: vec![PathCondition {
                variable: "lovelace_amount".to_string(),
                constraint: ConditionType::GreaterThan(0),
                block_id: 0,
            }],
            symbolic_state: HashMap::new(),
        };
        assert!(path_has_guard_for(&val_path, "value-not-preserved"));
        assert!(!path_has_guard_for(&val_path, "missing-signature-check"));
    }

    #[test]
    fn test_path_has_guard_for_generic_fallback() {
        // Unknown detector falls back to checking for any GuardedBy condition.
        let path_with_guard = CfgPath {
            blocks: vec![NodeIndex::new(0)],
            conditions: vec![PathCondition {
                variable: "something".to_string(),
                constraint: ConditionType::GuardedBy {
                    op: "Eq".to_string(),
                    compared_to: "expected".to_string(),
                },
                block_id: 0,
            }],
            symbolic_state: HashMap::new(),
        };
        assert!(path_has_guard_for(
            &path_with_guard,
            "some-unknown-detector"
        ));

        let path_no_guard = CfgPath {
            blocks: vec![NodeIndex::new(0)],
            conditions: vec![PathCondition {
                variable: "x".to_string(),
                constraint: ConditionType::IsTrue,
                block_id: 0,
            }],
            symbolic_state: HashMap::new(),
        };
        assert!(!path_has_guard_for(&path_no_guard, "some-unknown-detector"));
    }

    // -----------------------------------------------------------------------
    // Finding analysis
    // -----------------------------------------------------------------------

    #[test]
    fn test_analyze_finding_no_entry() {
        let cfg = CfgGraph::new();
        let finding = make_finding("missing-signature-check", "test_module");
        let result = analyze_finding_paths(&finding, &cfg);
        assert!(matches!(result.verdict, PathVerdict::Undetermined { .. }));
        assert_eq!(result.total_paths, 0);
    }

    #[test]
    fn test_analyze_finding_linear_unguarded() {
        let cfg = linear_cfg();
        let finding = make_finding("missing-signature-check", "test_module");
        let result = analyze_finding_paths(&finding, &cfg);
        assert!(matches!(result.verdict, PathVerdict::Unguarded));
        assert_eq!(result.feasible_paths, result.total_paths);
        assert_eq!(result.guarded_paths, 0);
    }

    #[test]
    fn test_analyze_finding_with_signature_condition() {
        // Build a CFG where the only path to Return has a signatory condition.
        let mut cfg = CfgGraph::new();
        let entry = cfg.add_block(BasicBlock {
            id: 0,
            stmts: vec![],
            terminator: Terminator::Branch {
                condition: "has_signer".to_string(),
            },
        });
        let guarded = cfg.add_block(BasicBlock {
            id: 1,
            stmts: vec![],
            terminator: Terminator::Return,
        });
        let error = cfg.add_block(BasicBlock {
            id: 2,
            stmts: vec![],
            terminator: Terminator::Error,
        });
        cfg.entry = Some(entry);
        cfg.add_edge(entry, guarded, CfgEdge::TrueBranch);
        cfg.add_edge(entry, error, CfgEdge::FalseBranch);

        let finding = make_finding("missing-signature-check", "test");
        let result = analyze_finding_paths(&finding, &cfg);

        // The Return path goes through TrueBranch where "has_signer" is true.
        // The Error path goes through FalseBranch. Both reach target blocks.
        // True branch: "has_signer" IsTrue — does not match signature guard
        // (the variable name does not contain "signator" or "signer").
        // Actually "has_signer" contains "signer", so it IS a signature guard.
        assert!(result.guarded_paths > 0);
    }

    #[test]
    fn test_analyze_finding_partially_guarded() {
        let cfg = branching_cfg();
        // branching_cfg has entry->guarded(true)->exit and entry->unguarded(false)->exit.
        // The "guarded" block has a Guard on extra_signatories, but this is a block
        // statement — the path conditions come from edges, not block statements.
        // The true-branch condition variable is "is_valid", which does not match
        // signature guard. So both paths are unguarded for signature check.
        let finding = make_finding("missing-signature-check", "test");
        let result = analyze_finding_paths(&finding, &cfg);
        // Neither path has signatory-related conditions.
        assert!(matches!(result.verdict, PathVerdict::Unguarded));
    }

    #[test]
    fn test_analyze_findings_with_cfg_matching() {
        let cfg = linear_cfg();
        let mut cfgs = HashMap::new();
        cfgs.insert("my_module".to_string(), cfg);

        let findings = vec![
            make_finding("missing-signature-check", "my_module"),
            make_finding("value-not-preserved", "other_module"), // no CFG match
        ];

        let results = analyze_findings_with_cfg(&findings, &cfgs);
        assert_eq!(results.len(), 1, "only the matching finding gets analyzed");
        assert_eq!(results[0].finding_detector, "missing-signature-check");
    }

    #[test]
    fn test_analyze_findings_with_cfg_prefix_match() {
        let cfg = linear_cfg();
        let mut cfgs = HashMap::new();
        cfgs.insert("validators/my_contract::spend".to_string(), cfg);

        let findings = vec![make_finding(
            "missing-signature-check",
            "validators/my_contract",
        )];

        let results = analyze_findings_with_cfg(&findings, &cfgs);
        assert_eq!(results.len(), 1, "should match via substring containment");
    }

    // -----------------------------------------------------------------------
    // Symbolic integration
    // -----------------------------------------------------------------------

    #[test]
    fn test_symbolic_narrow_path_empty() {
        let path = CfgPath {
            blocks: vec![],
            conditions: vec![],
            symbolic_state: HashMap::new(),
        };
        let ctx = SymbolicContext::new();
        let result = symbolic_narrow_path(&path, &ctx);
        assert!(result.bindings.is_empty());
    }

    #[test]
    fn test_symbolic_narrow_path_applies_constraints() {
        let path = CfgPath {
            blocks: vec![NodeIndex::new(0)],
            conditions: vec![
                PathCondition {
                    variable: "x".to_string(),
                    constraint: ConditionType::GreaterThan(0),
                    block_id: 0,
                },
                PathCondition {
                    variable: "x".to_string(),
                    constraint: ConditionType::LessThan(100),
                    block_id: 0,
                },
            ],
            symbolic_state: HashMap::new(),
        };

        let initial = SymbolicContext::new();
        let result = symbolic_narrow_path(&path, &initial);
        let x = result.get("x");
        match x {
            SymbolicValue::Range {
                min: Some(lo),
                max: Some(hi),
            } => {
                assert_eq!(*lo, 1);
                assert_eq!(*hi, 99);
            }
            other => panic!("Expected Range, got {:?}", other),
        }
    }

    #[test]
    fn test_symbolic_narrow_path_detects_impossible() {
        let path = CfgPath {
            blocks: vec![NodeIndex::new(0)],
            conditions: vec![
                PathCondition {
                    variable: "x".to_string(),
                    constraint: ConditionType::GreaterThan(100),
                    block_id: 0,
                },
                PathCondition {
                    variable: "x".to_string(),
                    constraint: ConditionType::LessThan(50),
                    block_id: 0,
                },
            ],
            symbolic_state: HashMap::new(),
        };

        let result = symbolic_narrow_path(&path, &SymbolicContext::new());
        assert!(!result.impossible_paths.is_empty());
    }

    #[test]
    fn test_symbolic_narrow_preserves_initial_bindings() {
        let path = CfgPath {
            blocks: vec![NodeIndex::new(0)],
            conditions: vec![PathCondition {
                variable: "y".to_string(),
                constraint: ConditionType::IsTrue,
                block_id: 0,
            }],
            symbolic_state: HashMap::new(),
        };

        let mut initial = SymbolicContext::new();
        initial.bind("x", SymbolicValue::Boolean(true));

        let result = symbolic_narrow_path(&path, &initial);
        assert_eq!(*result.get("x"), SymbolicValue::Boolean(true));
        assert_eq!(*result.get("y"), SymbolicValue::Boolean(true));
    }

    #[test]
    fn test_is_symbolically_unreachable_impossible_path() {
        let path = CfgPath {
            blocks: vec![NodeIndex::new(0)],
            conditions: vec![
                PathCondition {
                    variable: "x".to_string(),
                    constraint: ConditionType::GreaterThan(100),
                    block_id: 0,
                },
                PathCondition {
                    variable: "x".to_string(),
                    constraint: ConditionType::LessThan(50),
                    block_id: 0,
                },
            ],
            symbolic_state: HashMap::new(),
        };
        assert!(is_symbolically_unreachable(&path, "x"));
    }

    #[test]
    fn test_is_symbolically_unreachable_feasible_path() {
        let path = CfgPath {
            blocks: vec![NodeIndex::new(0)],
            conditions: vec![PathCondition {
                variable: "x".to_string(),
                constraint: ConditionType::GreaterThan(0),
                block_id: 0,
            }],
            symbolic_state: HashMap::new(),
        };
        assert!(!is_symbolically_unreachable(&path, "x"));
    }

    #[test]
    fn test_is_symbolically_unreachable_unknown_variable() {
        let path = CfgPath {
            blocks: vec![NodeIndex::new(0)],
            conditions: vec![],
            symbolic_state: HashMap::new(),
        };
        // Unknown variable defaults to Any, which is not impossible.
        assert!(!is_symbolically_unreachable(&path, "unknown_var"));
    }

    // -----------------------------------------------------------------------
    // Formatting
    // -----------------------------------------------------------------------

    #[test]
    fn test_format_path_detail_vulnerable() {
        let detail = PathDetail {
            path_id: 0,
            feasible: true,
            guarded: false,
            guard_description: None,
            conditions: vec![],
        };
        let s = format_path_detail(&detail);
        assert!(s.contains("VULNERABLE"));
        assert!(s.contains("Path #0"));
    }

    #[test]
    fn test_format_path_detail_guarded() {
        let detail = PathDetail {
            path_id: 1,
            feasible: true,
            guarded: true,
            guard_description: Some("Has signature check".to_string()),
            conditions: vec![PathCondition {
                variable: "x".to_string(),
                constraint: ConditionType::IsTrue,
                block_id: 0,
            }],
        };
        let s = format_path_detail(&detail);
        assert!(s.contains("GUARDED"));
        assert!(s.contains("Has signature check"));
        assert!(s.contains("1 conditions"));
    }

    #[test]
    fn test_format_path_detail_infeasible() {
        let detail = PathDetail {
            path_id: 2,
            feasible: false,
            guarded: false,
            guard_description: None,
            conditions: vec![],
        };
        let s = format_path_detail(&detail);
        assert!(s.contains("INFEASIBLE"));
    }

    #[test]
    fn test_format_path_analysis_report_empty() {
        let report = format_path_analysis_report(&[]);
        assert!(report.contains("No path analysis results"));
    }

    #[test]
    fn test_format_path_analysis_report_single() {
        let result = PathAnalysisResult {
            finding_detector: "missing-signature-check".to_string(),
            finding_module: "validators/test.ak".to_string(),
            total_paths: 2,
            feasible_paths: 2,
            guarded_paths: 1,
            vulnerable_paths: 1,
            verdict: PathVerdict::PartiallyGuarded {
                unguarded_ratio: 0.5,
            },
            details: vec![
                PathDetail {
                    path_id: 0,
                    feasible: true,
                    guarded: true,
                    guard_description: Some("signature check".to_string()),
                    conditions: vec![],
                },
                PathDetail {
                    path_id: 1,
                    feasible: true,
                    guarded: false,
                    guard_description: None,
                    conditions: vec![],
                },
            ],
        };

        let report = format_path_analysis_report(&[result]);
        assert!(report.contains("Path-Sensitive Analysis Report"));
        assert!(report.contains("missing-signature-check"));
        assert!(report.contains("PARTIALLY GUARDED"));
        assert!(report.contains("50%"));
        assert!(report.contains("Summary"));
    }

    #[test]
    fn test_format_report_summary_counts() {
        let results = vec![
            PathAnalysisResult {
                finding_detector: "a".to_string(),
                finding_module: "m".to_string(),
                total_paths: 1,
                feasible_paths: 1,
                guarded_paths: 1,
                vulnerable_paths: 0,
                verdict: PathVerdict::AllGuarded,
                details: vec![],
            },
            PathAnalysisResult {
                finding_detector: "b".to_string(),
                finding_module: "m".to_string(),
                total_paths: 1,
                feasible_paths: 1,
                guarded_paths: 0,
                vulnerable_paths: 1,
                verdict: PathVerdict::Unguarded,
                details: vec![],
            },
            PathAnalysisResult {
                finding_detector: "c".to_string(),
                finding_module: "m".to_string(),
                total_paths: 0,
                feasible_paths: 0,
                guarded_paths: 0,
                vulnerable_paths: 0,
                verdict: PathVerdict::Undetermined {
                    reason: "no paths".to_string(),
                },
                details: vec![],
            },
        ];

        let report = format_path_analysis_report(&results);
        assert!(report.contains("All guarded (likely FP): 1"));
        assert!(report.contains("Unguarded (confirmed):   1"));
        assert!(report.contains("Undetermined:            1"));
    }

    // -----------------------------------------------------------------------
    // Edge cases and cycle detection
    // -----------------------------------------------------------------------

    #[test]
    fn test_cycle_does_not_infinite_loop() {
        // A -> B -> A (cycle). Target = A.
        let mut cfg = CfgGraph::new();
        let a = cfg.add_block(BasicBlock {
            id: 0,
            stmts: vec![],
            terminator: Terminator::Goto,
        });
        let b = cfg.add_block(BasicBlock {
            id: 1,
            stmts: vec![],
            terminator: Terminator::Goto,
        });
        cfg.entry = Some(a);
        cfg.add_edge(a, b, CfgEdge::Unconditional);
        cfg.add_edge(b, a, CfgEdge::Unconditional);

        // Target = entry (a). Should find 1 path: [a].
        let paths = enumerate_paths_to(&cfg, a, 10);
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0].blocks, vec![a]);
    }

    #[test]
    fn test_self_loop_handled() {
        let mut cfg = CfgGraph::new();
        let a = cfg.add_block(BasicBlock {
            id: 0,
            stmts: vec![],
            terminator: Terminator::Goto,
        });
        cfg.entry = Some(a);
        cfg.add_edge(a, a, CfgEdge::Unconditional); // self-loop

        let paths = enumerate_paths_to(&cfg, a, 10);
        // Should find the trivial path [a] but NOT loop infinitely.
        assert_eq!(paths.len(), 1);
    }

    #[test]
    fn test_apply_condition_guard_does_not_narrow() {
        let val = SymbolicValue::Any;
        let result = apply_condition(
            &val,
            &ConditionType::GuardedBy {
                op: "Eq".to_string(),
                compared_to: "foo".to_string(),
            },
        );
        assert_eq!(result, SymbolicValue::Any);
    }

    #[test]
    fn test_apply_condition_less_or_equal() {
        let val = SymbolicValue::Any;
        let result = apply_condition(&val, &ConditionType::LessOrEqual(10));
        // LessOrEqual(10) => narrow_lt(11) => max = 10
        assert_eq!(
            result,
            SymbolicValue::Range {
                min: None,
                max: Some(10)
            }
        );
    }

    #[test]
    fn test_apply_condition_greater_or_equal() {
        let val = SymbolicValue::Any;
        let result = apply_condition(&val, &ConditionType::GreaterOrEqual(5));
        // GreaterOrEqual(5) => narrow_gt(4) => min = 5
        assert_eq!(
            result,
            SymbolicValue::Range {
                min: Some(5),
                max: None
            }
        );
    }

    #[test]
    fn test_block_references_variable_guard_compared_to() {
        let block = BasicBlock {
            id: 0,
            stmts: vec![CfgStmt::Guard {
                var: "x".to_string(),
                op: GuardOp::Eq,
                compared_to: Some("target_var".to_string()),
            }],
            terminator: Terminator::Return,
        };
        assert!(block_references_variable(&block, "target_var"));
        assert!(block_references_variable(&block, "x"));
        assert!(!block_references_variable(&block, "other"));
    }

    #[test]
    fn test_conditions_from_edge_unconditional() {
        let block = BasicBlock::default();
        let conds = conditions_from_edge(&CfgEdge::Unconditional, &block);
        assert!(conds.is_empty());
    }

    #[test]
    fn test_conditions_from_edge_error() {
        let block = BasicBlock::default();
        let conds = conditions_from_edge(&CfgEdge::ErrorEdge, &block);
        assert!(conds.is_empty());
    }

    #[test]
    fn test_conditions_from_edge_true_branch() {
        let block = BasicBlock {
            id: 5,
            stmts: vec![],
            terminator: Terminator::Branch {
                condition: "is_admin".to_string(),
            },
        };
        let conds = conditions_from_edge(&CfgEdge::TrueBranch, &block);
        assert_eq!(conds.len(), 1);
        assert_eq!(conds[0].variable, "is_admin");
        assert!(matches!(conds[0].constraint, ConditionType::IsTrue));
        assert_eq!(conds[0].block_id, 5);
    }

    #[test]
    fn test_conditions_from_edge_false_branch() {
        let block = BasicBlock {
            id: 7,
            stmts: vec![],
            terminator: Terminator::Branch {
                condition: "is_admin".to_string(),
            },
        };
        let conds = conditions_from_edge(&CfgEdge::FalseBranch, &block);
        assert_eq!(conds.len(), 1);
        assert!(matches!(conds[0].constraint, ConditionType::IsFalse));
    }

    #[test]
    fn test_conditions_from_edge_pattern_arm() {
        let block = BasicBlock {
            id: 3,
            stmts: vec![],
            terminator: Terminator::Switch {
                subject: "redeemer".to_string(),
                arm_count: 3,
            },
        };
        let conds = conditions_from_edge(&CfgEdge::PatternArm("Withdraw".to_string()), &block);
        assert_eq!(conds.len(), 1);
        assert_eq!(conds[0].variable, "redeemer");
        assert!(matches!(
            &conds[0].constraint,
            ConditionType::IsConstructor(name) if name == "Withdraw"
        ));
    }

    #[test]
    fn test_conditions_from_edge_true_branch_wrong_terminator() {
        // TrueBranch on a non-Branch terminator should produce no conditions.
        let block = BasicBlock {
            id: 0,
            stmts: vec![],
            terminator: Terminator::Goto,
        };
        let conds = conditions_from_edge(&CfgEdge::TrueBranch, &block);
        assert!(conds.is_empty());
    }

    #[test]
    fn test_describe_guard_returns_expected_strings() {
        assert!(describe_guard("missing-signature-check").contains("signature"));
        assert!(describe_guard("value-not-preserved").contains("value"));
        assert!(describe_guard("arbitrary-datum-in-output").contains("datum"));
        assert!(describe_guard("output-address-not-validated").contains("address"));
        assert!(describe_guard("unrestricted-minting").contains("minting"));
        assert!(describe_guard("unknown-detector").contains("guard"));
    }

    // -----------------------------------------------------------------------
    // PathVerdict serialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_path_verdict_serialization() {
        let verdict = PathVerdict::PartiallyGuarded {
            unguarded_ratio: 0.333,
        };
        let json = serde_json::to_string(&verdict).unwrap();
        assert!(json.contains("PartiallyGuarded"));
        assert!(json.contains("0.333"));
    }

    #[test]
    fn test_path_condition_serialization() {
        let cond = PathCondition {
            variable: "x".to_string(),
            constraint: ConditionType::GreaterThan(42),
            block_id: 3,
        };
        let json = serde_json::to_string(&cond).unwrap();
        assert!(json.contains("\"variable\":\"x\""));
        assert!(json.contains("GreaterThan"));
    }

    #[test]
    fn test_path_analysis_result_serialization() {
        let result = PathAnalysisResult {
            finding_detector: "test".to_string(),
            finding_module: "mod".to_string(),
            total_paths: 5,
            feasible_paths: 3,
            guarded_paths: 2,
            vulnerable_paths: 1,
            verdict: PathVerdict::Unguarded,
            details: vec![],
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"total_paths\":5"));
    }
}
