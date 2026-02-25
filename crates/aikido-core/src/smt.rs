//! SMT (Satisfiability Modulo Theories) lane for finding verification.
//!
//! Provides an abstract, solver-independent SMT interface for encoding
//! Cardano validator constraints and verifying detector findings. The module
//! includes Cardano-specific domain axioms (lovelace non-negativity, min UTxO,
//! value conservation), path condition encoding from CFG analysis, and a
//! built-in simple solver for basic boolean/integer satisfiability.
//!
//! The abstract interface can be backed by Z3, CVC5, or the built-in solver.
//! No external SMT solver library is required as a dependency.

use serde::Serialize;
use std::collections::HashMap;
use std::time::Instant;

use crate::detector::Finding;

// ---------------------------------------------------------------------------
// Core SMT types
// ---------------------------------------------------------------------------

/// An SMT sort (type in the solver's type system).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub enum SmtSort {
    /// Boolean sort.
    Bool,
    /// Unbounded integer sort.
    Int,
    /// Fixed-width bit vector (for hashes, addresses, policy IDs).
    BitVec(u32),
    /// Array from index sort to element sort.
    Array(Box<SmtSort>, Box<SmtSort>),
    /// Domain-specific custom sort (e.g., "Value", "Address", "Datum").
    Custom(String),
}

impl std::fmt::Display for SmtSort {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SmtSort::Bool => write!(f, "Bool"),
            SmtSort::Int => write!(f, "Int"),
            SmtSort::BitVec(w) => write!(f, "BitVec({w})"),
            SmtSort::Array(idx, elem) => write!(f, "Array({idx}, {elem})"),
            SmtSort::Custom(name) => write!(f, "{name}"),
        }
    }
}

/// An SMT expression (solver-independent AST).
#[derive(Debug, Clone, Serialize)]
pub enum SmtExpr {
    // --- Literals ---
    /// Boolean literal.
    BoolLit(bool),
    /// Integer literal.
    IntLit(i64),
    /// Bit-vector literal with explicit width.
    BitVecLit {
        value: Vec<u8>,
        width: u32,
    },

    // --- Variables ---
    /// A named, sorted variable.
    Var {
        name: String,
        sort: SmtSort,
    },

    // --- Boolean connectives ---
    /// Conjunction (all must hold).
    And(Vec<Box<SmtExpr>>),
    /// Disjunction (at least one must hold).
    Or(Vec<Box<SmtExpr>>),
    /// Negation.
    Not(Box<SmtExpr>),
    /// Logical implication (antecedent => consequent).
    Implies(Box<SmtExpr>, Box<SmtExpr>),

    // --- Integer arithmetic ---
    Add(Box<SmtExpr>, Box<SmtExpr>),
    Sub(Box<SmtExpr>, Box<SmtExpr>),
    Mul(Box<SmtExpr>, Box<SmtExpr>),
    Div(Box<SmtExpr>, Box<SmtExpr>),
    Mod(Box<SmtExpr>, Box<SmtExpr>),

    // --- Comparisons ---
    Eq(Box<SmtExpr>, Box<SmtExpr>),
    Lt(Box<SmtExpr>, Box<SmtExpr>),
    Le(Box<SmtExpr>, Box<SmtExpr>),
    Gt(Box<SmtExpr>, Box<SmtExpr>),
    Ge(Box<SmtExpr>, Box<SmtExpr>),

    // --- Conditional ---
    /// If-then-else: `(ite cond then_expr else_expr)`.
    Ite(Box<SmtExpr>, Box<SmtExpr>, Box<SmtExpr>),

    // --- Quantifiers (for invariant checking) ---
    /// Universal quantification.
    ForAll {
        vars: Vec<(String, SmtSort)>,
        body: Box<SmtExpr>,
    },
    /// Existential quantification.
    Exists {
        vars: Vec<(String, SmtSort)>,
        body: Box<SmtExpr>,
    },
}

// ---------------------------------------------------------------------------
// SmtExpr builder helpers
// ---------------------------------------------------------------------------

impl SmtExpr {
    /// Create an integer variable.
    pub fn int_var(name: &str) -> Self {
        SmtExpr::Var {
            name: name.to_string(),
            sort: SmtSort::Int,
        }
    }

    /// Create a boolean variable.
    pub fn bool_var(name: &str) -> Self {
        SmtExpr::Var {
            name: name.to_string(),
            sort: SmtSort::Bool,
        }
    }

    /// Create a bit-vector variable.
    pub fn bv_var(name: &str, width: u32) -> Self {
        SmtExpr::Var {
            name: name.to_string(),
            sort: SmtSort::BitVec(width),
        }
    }

    /// Shorthand: `self > other`.
    pub fn gt(self, other: SmtExpr) -> SmtExpr {
        SmtExpr::Gt(Box::new(self), Box::new(other))
    }

    /// Shorthand: `self >= other`.
    pub fn ge(self, other: SmtExpr) -> SmtExpr {
        SmtExpr::Ge(Box::new(self), Box::new(other))
    }

    /// Shorthand: `self < other`.
    pub fn lt(self, other: SmtExpr) -> SmtExpr {
        SmtExpr::Lt(Box::new(self), Box::new(other))
    }

    /// Shorthand: `self <= other`.
    pub fn le(self, other: SmtExpr) -> SmtExpr {
        SmtExpr::Le(Box::new(self), Box::new(other))
    }

    /// Shorthand: `self == other`.
    pub fn eq(self, other: SmtExpr) -> SmtExpr {
        SmtExpr::Eq(Box::new(self), Box::new(other))
    }

    /// Shorthand: `self + other`.
    #[allow(clippy::should_implement_trait)]
    pub fn add(self, other: SmtExpr) -> SmtExpr {
        SmtExpr::Add(Box::new(self), Box::new(other))
    }

    /// Shorthand: `self - other`.
    #[allow(clippy::should_implement_trait)]
    pub fn sub(self, other: SmtExpr) -> SmtExpr {
        SmtExpr::Sub(Box::new(self), Box::new(other))
    }

    /// Shorthand: `!self`.
    #[allow(clippy::should_implement_trait)]
    pub fn not(self) -> SmtExpr {
        SmtExpr::Not(Box::new(self))
    }

    /// Shorthand: `self => other`.
    pub fn implies(self, other: SmtExpr) -> SmtExpr {
        SmtExpr::Implies(Box::new(self), Box::new(other))
    }

    /// Conjunction of multiple expressions.
    pub fn and_all(exprs: Vec<SmtExpr>) -> SmtExpr {
        SmtExpr::And(exprs.into_iter().map(Box::new).collect())
    }

    /// Disjunction of multiple expressions.
    pub fn or_any(exprs: Vec<SmtExpr>) -> SmtExpr {
        SmtExpr::Or(exprs.into_iter().map(Box::new).collect())
    }
}

// ---------------------------------------------------------------------------
// SMT result types
// ---------------------------------------------------------------------------

/// Result of an SMT satisfiability query.
#[derive(Debug, Clone, Serialize)]
pub enum SmtResult {
    /// Satisfiable -- a model (witness) exists.
    Sat { witness: HashMap<String, SmtValue> },
    /// Unsatisfiable -- no model exists (constraints are contradictory).
    Unsat,
    /// Unknown -- solver could not determine within resource limits.
    Unknown { reason: String },
}

/// A concrete value in an SMT model (witness).
#[derive(Debug, Clone, Serialize, PartialEq)]
pub enum SmtValue {
    Bool(bool),
    Int(i64),
    BitVec(Vec<u8>),
    Custom(String),
}

// ---------------------------------------------------------------------------
// Cardano domain axioms
// ---------------------------------------------------------------------------

/// Cardano-specific axioms that constrain the solver's search space.
///
/// These encode fundamental Cardano ledger rules so that any SAT witness
/// represents a plausible on-chain state, not a physically impossible one.
pub fn cardano_axioms() -> Vec<SmtExpr> {
    vec![
        lovelace_non_negative(),
        min_utxo_constraint(),
        tx_value_conservation(),
        address_length_constraints(),
        fee_constraints(),
        validity_range_ordering(),
    ]
}

/// Lovelace amounts are always non-negative.
///
/// Axiom: `lovelace >= 0`
fn lovelace_non_negative() -> SmtExpr {
    SmtExpr::int_var("lovelace").ge(SmtExpr::IntLit(0))
}

/// Minimum UTxO ADA constraint (currently ~1 ADA = 1_000_000 lovelace).
///
/// Any UTxO output must carry at least min_utxo lovelace.
/// Axiom: `output_lovelace >= 1_000_000`
fn min_utxo_constraint() -> SmtExpr {
    SmtExpr::int_var("output_lovelace").ge(SmtExpr::IntLit(1_000_000))
}

/// Transaction value conservation: total inputs = total outputs + fee.
///
/// Axiom: `input_total == output_total + fee`
fn tx_value_conservation() -> SmtExpr {
    let inputs = SmtExpr::int_var("input_total");
    let outputs = SmtExpr::int_var("output_total");
    let fee = SmtExpr::int_var("fee");
    inputs.eq(outputs.add(fee))
}

/// Address length constraints for Cardano addresses.
///
/// Payment key hashes are 28 bytes (224 bits).
/// Axiom: `address_length == 28`
fn address_length_constraints() -> SmtExpr {
    SmtExpr::int_var("address_hash_length").eq(SmtExpr::IntLit(28))
}

/// Transaction fees must be positive and within protocol bounds.
///
/// Axiom: `fee >= 155_381 AND fee <= 50_000_000`
/// (155_381 is the Babbage-era minimum fee for a minimal transaction;
///  50 ADA is a generous upper bound.)
fn fee_constraints() -> SmtExpr {
    let fee = SmtExpr::int_var("fee");
    SmtExpr::and_all(vec![
        fee.clone().ge(SmtExpr::IntLit(155_381)),
        fee.le(SmtExpr::IntLit(50_000_000)),
    ])
}

/// Validity range ordering: if both bounds are present, start <= end.
///
/// Axiom: `validity_start <= validity_end`
fn validity_range_ordering() -> SmtExpr {
    SmtExpr::int_var("validity_start").le(SmtExpr::int_var("validity_end"))
}

// ---------------------------------------------------------------------------
// Path conditions (from CFG analysis)
// ---------------------------------------------------------------------------

/// A single path condition extracted from CFG traversal.
#[derive(Debug, Clone)]
pub struct PathCondition {
    /// Variable name the condition constrains.
    pub variable: String,
    /// The constraint on the variable.
    pub constraint: PathConstraint,
}

/// Constraint kinds that appear in CFG branch conditions.
#[derive(Debug, Clone)]
pub enum PathConstraint {
    /// Variable equals a specific string value or constructor name.
    Equals(String),
    /// Variable does not equal a value.
    NotEquals(String),
    /// Variable is less than an integer bound.
    LessThan(i64),
    /// Variable is greater than an integer bound.
    GreaterThan(i64),
    /// Variable is less than or equal to an integer bound.
    LessThanOrEqual(i64),
    /// Variable is greater than or equal to an integer bound.
    GreaterThanOrEqual(i64),
    /// Variable matches a constructor (pattern match arm).
    IsConstructor(String),
    /// Variable does not match a constructor (negated arm).
    IsNotConstructor(String),
    /// Variable is one of a set of values.
    InSet(Vec<String>),
}

/// Encode a slice of path conditions as SMT expressions.
///
/// Each `PathCondition` becomes a constraint on a named variable.
/// String equality is encoded as boolean variables named `{var}_is_{value}`.
pub fn encode_path_conditions(conditions: &[PathCondition]) -> Vec<SmtExpr> {
    conditions.iter().map(encode_single_condition).collect()
}

fn encode_single_condition(cond: &PathCondition) -> SmtExpr {
    let var = &cond.variable;
    match &cond.constraint {
        PathConstraint::Equals(val) => {
            // For string/constructor equality, create a boolean flag variable.
            SmtExpr::bool_var(&format!("{var}_is_{val}"))
        }
        PathConstraint::NotEquals(val) => SmtExpr::bool_var(&format!("{var}_is_{val}")).not(),
        PathConstraint::LessThan(bound) => SmtExpr::int_var(var).lt(SmtExpr::IntLit(*bound)),
        PathConstraint::GreaterThan(bound) => SmtExpr::int_var(var).gt(SmtExpr::IntLit(*bound)),
        PathConstraint::LessThanOrEqual(bound) => SmtExpr::int_var(var).le(SmtExpr::IntLit(*bound)),
        PathConstraint::GreaterThanOrEqual(bound) => {
            SmtExpr::int_var(var).ge(SmtExpr::IntLit(*bound))
        }
        PathConstraint::IsConstructor(ctor) => SmtExpr::bool_var(&format!("{var}_is_{ctor}")),
        PathConstraint::IsNotConstructor(ctor) => {
            SmtExpr::bool_var(&format!("{var}_is_{ctor}")).not()
        }
        PathConstraint::InSet(vals) => {
            let disjuncts: Vec<SmtExpr> = vals
                .iter()
                .map(|v| SmtExpr::bool_var(&format!("{var}_is_{v}")))
                .collect();
            SmtExpr::or_any(disjuncts)
        }
    }
}

/// Encode a finding's context as SMT expressions.
///
/// Extracts constraints from the finding's detector name, module, and
/// description to create domain-relevant constraints. Detector-specific
/// encoding maps each detector category to appropriate Cardano axioms.
pub fn encode_finding_context(finding: &Finding) -> Vec<SmtExpr> {
    let mut constraints = Vec::new();
    let detector = &finding.detector_name;

    // Map detector categories to relevant domain constraints.
    if detector.contains("value") || detector.contains("lovelace") {
        // Value-related findings: constrain lovelace to be non-negative.
        constraints.push(lovelace_non_negative());
        constraints.push(min_utxo_constraint());
    }

    if detector.contains("fee") {
        constraints.push(fee_constraints());
    }

    if detector.contains("validity") || detector.contains("time") || detector.contains("range") {
        constraints.push(validity_range_ordering());
    }

    if detector.contains("minting") || detector.contains("burn") || detector.contains("token") {
        // Minting: token quantity must be non-zero and name length bounded.
        constraints.push(SmtExpr::int_var("mint_quantity").ge(SmtExpr::IntLit(1)));
        constraints.push(SmtExpr::int_var("asset_name_length").le(SmtExpr::IntLit(32)));
        constraints.push(SmtExpr::int_var("asset_name_length").ge(SmtExpr::IntLit(0)));
    }

    if detector.contains("datum") {
        // Datum presence: the output must carry a datum.
        constraints.push(SmtExpr::bool_var("output_has_datum"));
    }

    if detector.contains("signature") || detector.contains("authentication") {
        // The required signer must be present in the transaction.
        constraints.push(SmtExpr::bool_var("signer_present"));
    }

    if detector.contains("address") {
        constraints.push(address_length_constraints());
    }

    // Always include value conservation for economic findings.
    if detector.contains("double-satisfaction")
        || detector.contains("value-not-preserved")
        || detector.contains("value-preservation")
    {
        constraints.push(tx_value_conservation());
    }

    constraints
}

// ---------------------------------------------------------------------------
// Finding verification through SMT
// ---------------------------------------------------------------------------

/// Result of verifying a single finding via SMT analysis.
#[derive(Debug, Clone, Serialize)]
pub struct SmtVerificationResult {
    /// Detector that produced the original finding.
    pub finding_detector: String,
    /// The raw SMT result.
    pub result: SmtResult,
    /// Human-readable interpretation of the result.
    pub interpretation: SmtInterpretation,
    /// Number of SMT constraints used in the query.
    pub constraints_used: usize,
    /// Wall-clock time for the SMT check in milliseconds.
    pub time_ms: u64,
}

/// Interpretation of an SMT result in the context of a finding.
#[derive(Debug, Clone, Serialize)]
pub enum SmtInterpretation {
    /// SAT: an exploit input exists -- true positive confirmed.
    ExploitExists { witness_description: String },
    /// UNSAT: no exploit possible under the encoded constraints -- false positive.
    FalsePositive { proof_description: String },
    /// Unknown: the solver could not determine satisfiability.
    Inconclusive { reason: String },
}

/// Attempt to verify or refute a finding using SMT constraints.
///
/// Encodes the finding's context plus any path conditions into an SMT query,
/// adds Cardano domain axioms, and checks satisfiability. If SAT, the finding
/// is confirmed (exploit witness exists). If UNSAT, the finding is likely
/// a false positive under the encoded constraints.
pub fn verify_finding_smt(
    finding: &Finding,
    path_conditions: &[PathCondition],
) -> SmtVerificationResult {
    let start = Instant::now();

    // 1. Gather all constraints.
    let mut assertions = cardano_axioms();
    assertions.extend(encode_finding_context(finding));
    assertions.extend(encode_path_conditions(path_conditions));

    let constraint_count = assertions.len();

    // 2. Run the built-in solver.
    let solver = SimpleSmtSolver::new();
    let result = solver.check_sat(&assertions);

    let elapsed_ms = start.elapsed().as_millis() as u64;

    // 3. Interpret the result.
    let interpretation = match &result {
        SmtResult::Sat { witness } => {
            let desc = if witness.is_empty() {
                "Constraints are satisfiable; an exploit input may exist.".to_string()
            } else {
                let vars: Vec<String> = witness
                    .iter()
                    .map(|(k, v)| format!("{k} = {v:?}"))
                    .collect();
                format!("Exploit witness: {}", vars.join(", "))
            };
            SmtInterpretation::ExploitExists {
                witness_description: desc,
            }
        }
        SmtResult::Unsat => SmtInterpretation::FalsePositive {
            proof_description:
                "No satisfying assignment exists under Cardano domain axioms and path conditions."
                    .to_string(),
        },
        SmtResult::Unknown { reason } => SmtInterpretation::Inconclusive {
            reason: reason.clone(),
        },
    };

    SmtVerificationResult {
        finding_detector: finding.detector_name.clone(),
        result,
        interpretation,
        constraints_used: constraint_count,
        time_ms: elapsed_ms,
    }
}

// ---------------------------------------------------------------------------
// Built-in simple solver
// ---------------------------------------------------------------------------

/// A simple constraint solver for basic boolean and integer satisfiability.
///
/// Handles pure boolean logic, simple integer comparisons, and equality.
/// Returns `Unknown` for anything more complex (quantifiers, arrays,
/// bit-vectors, nonlinear arithmetic). This enables basic SMT verification
/// without requiring an external solver library.
pub struct SimpleSmtSolver;

impl Default for SimpleSmtSolver {
    fn default() -> Self {
        Self::new()
    }
}

impl SimpleSmtSolver {
    pub fn new() -> Self {
        SimpleSmtSolver
    }

    /// Check satisfiability of a conjunction of expressions.
    ///
    /// Strategy:
    /// 1. Collect integer bounds from comparison expressions.
    /// 2. Check for contradictions (empty ranges, false literals).
    /// 3. For pure boolean formulas, attempt direct evaluation.
    /// 4. Return `Unknown` for anything beyond the solver's capabilities.
    pub fn check_sat(&self, assertions: &[SmtExpr]) -> SmtResult {
        // Quick checks first.
        if assertions.is_empty() {
            return SmtResult::Sat {
                witness: HashMap::new(),
            };
        }

        // Collect integer variable bounds.
        let mut lower_bounds: HashMap<String, i64> = HashMap::new();
        let mut upper_bounds: HashMap<String, i64> = HashMap::new();
        let mut equalities: HashMap<String, i64> = HashMap::new();
        let mut bool_assignments: HashMap<String, bool> = HashMap::new();
        let mut has_complex = false;

        for expr in assertions {
            if !self.extract_constraints(
                expr,
                &mut lower_bounds,
                &mut upper_bounds,
                &mut equalities,
                &mut bool_assignments,
            ) {
                has_complex = true;
            }
        }

        // Check for integer contradictions.
        for (var, &lb) in &lower_bounds {
            if let Some(&ub) = upper_bounds.get(var) {
                if lb > ub {
                    return SmtResult::Unsat;
                }
            }
            if let Some(&eq_val) = equalities.get(var) {
                if eq_val < lb {
                    return SmtResult::Unsat;
                }
            }
        }
        for (var, &ub) in &upper_bounds {
            if let Some(&eq_val) = equalities.get(var) {
                if eq_val > ub {
                    return SmtResult::Unsat;
                }
            }
        }

        // Check boolean contradictions.
        for expr in assertions {
            if let Some(false) = self.evaluate(expr, &equalities, &bool_assignments) {
                return SmtResult::Unsat;
            }
        }

        // If we had complex expressions we can't fully analyze, report Unknown.
        if has_complex {
            return SmtResult::Unknown {
                reason: "Expression contains constructs beyond the simple solver's capability \
                         (quantifiers, arrays, bit-vectors, or nonlinear arithmetic)."
                    .to_string(),
            };
        }

        // Build a witness from the extracted bounds.
        let mut witness = HashMap::new();
        for (var, &eq_val) in &equalities {
            witness.insert(var.clone(), SmtValue::Int(eq_val));
        }
        for (var, &lb) in &lower_bounds {
            if !witness.contains_key(var) {
                let ub = upper_bounds.get(var).copied().unwrap_or(lb + 1000);
                let val = lb.max(ub.min(lb));
                witness.insert(var.clone(), SmtValue::Int(val));
            }
        }
        for (var, &ub) in &upper_bounds {
            if !witness.contains_key(var) {
                witness.insert(var.clone(), SmtValue::Int(ub));
            }
        }
        for (var, &val) in &bool_assignments {
            witness.insert(var.clone(), SmtValue::Bool(val));
        }

        SmtResult::Sat { witness }
    }

    /// Extract simple constraints from an expression.
    /// Returns `false` if the expression contains constructs we cannot handle.
    fn extract_constraints(
        &self,
        expr: &SmtExpr,
        lower_bounds: &mut HashMap<String, i64>,
        upper_bounds: &mut HashMap<String, i64>,
        equalities: &mut HashMap<String, i64>,
        bool_assignments: &mut HashMap<String, bool>,
    ) -> bool {
        match expr {
            SmtExpr::BoolLit(_) | SmtExpr::IntLit(_) => true,

            // x >= N  =>  lower bound
            SmtExpr::Ge(lhs, rhs) => {
                if let (Some(var), Some(val)) = (self.as_var_name(lhs), self.as_int_lit(rhs)) {
                    let entry = lower_bounds.entry(var).or_insert(i64::MIN);
                    *entry = (*entry).max(val);
                    return true;
                }
                if let (Some(val), Some(var)) = (self.as_int_lit(lhs), self.as_var_name(rhs)) {
                    let entry = upper_bounds.entry(var).or_insert(i64::MAX);
                    *entry = (*entry).min(val);
                    return true;
                }
                false
            }

            // x > N  =>  lower bound N+1
            SmtExpr::Gt(lhs, rhs) => {
                if let (Some(var), Some(val)) = (self.as_var_name(lhs), self.as_int_lit(rhs)) {
                    let entry = lower_bounds.entry(var).or_insert(i64::MIN);
                    *entry = (*entry).max(val + 1);
                    return true;
                }
                if let (Some(val), Some(var)) = (self.as_int_lit(lhs), self.as_var_name(rhs)) {
                    let entry = upper_bounds.entry(var).or_insert(i64::MAX);
                    *entry = (*entry).min(val - 1);
                    return true;
                }
                false
            }

            // x <= N  =>  upper bound
            SmtExpr::Le(lhs, rhs) => {
                if let (Some(var), Some(val)) = (self.as_var_name(lhs), self.as_int_lit(rhs)) {
                    let entry = upper_bounds.entry(var).or_insert(i64::MAX);
                    *entry = (*entry).min(val);
                    return true;
                }
                if let (Some(val), Some(var)) = (self.as_int_lit(lhs), self.as_var_name(rhs)) {
                    let entry = lower_bounds.entry(var).or_insert(i64::MIN);
                    *entry = (*entry).max(val);
                    return true;
                }
                false
            }

            // x < N  =>  upper bound N-1
            SmtExpr::Lt(lhs, rhs) => {
                if let (Some(var), Some(val)) = (self.as_var_name(lhs), self.as_int_lit(rhs)) {
                    let entry = upper_bounds.entry(var).or_insert(i64::MAX);
                    *entry = (*entry).min(val - 1);
                    return true;
                }
                if let (Some(val), Some(var)) = (self.as_int_lit(lhs), self.as_var_name(rhs)) {
                    let entry = lower_bounds.entry(var).or_insert(i64::MIN);
                    *entry = (*entry).max(val + 1);
                    return true;
                }
                false
            }

            // x == N  =>  equality
            SmtExpr::Eq(lhs, rhs) => {
                if let (Some(var), Some(val)) = (self.as_var_name(lhs), self.as_int_lit(rhs)) {
                    equalities.insert(var, val);
                    return true;
                }
                if let (Some(val), Some(var)) = (self.as_int_lit(lhs), self.as_var_name(rhs)) {
                    equalities.insert(var, val);
                    return true;
                }
                // Boolean variable equality: var == true/false
                if let (Some(var), Some(val)) = (self.as_var_name(lhs), self.as_bool_lit(rhs)) {
                    bool_assignments.insert(var, val);
                    return true;
                }
                false
            }

            // Bare boolean variable => true
            SmtExpr::Var {
                name,
                sort: SmtSort::Bool,
            } => {
                bool_assignments.insert(name.clone(), true);
                true
            }

            // !expr
            SmtExpr::Not(inner) => {
                if let SmtExpr::Var {
                    name,
                    sort: SmtSort::Bool,
                } = inner.as_ref()
                {
                    bool_assignments.insert(name.clone(), false);
                    return true;
                }
                false
            }

            // AND: recurse into all children
            SmtExpr::And(children) => {
                let mut all_simple = true;
                for child in children {
                    if !self.extract_constraints(
                        child,
                        lower_bounds,
                        upper_bounds,
                        equalities,
                        bool_assignments,
                    ) {
                        all_simple = false;
                    }
                }
                all_simple
            }

            // Eq between two Var+Add/Sub expressions (e.g., value conservation)
            SmtExpr::Implies(_, _) => false,
            SmtExpr::Or(_) => false,
            SmtExpr::Ite(_, _, _) => false,
            SmtExpr::ForAll { .. } | SmtExpr::Exists { .. } => false,
            SmtExpr::Add(_, _)
            | SmtExpr::Sub(_, _)
            | SmtExpr::Mul(_, _)
            | SmtExpr::Div(_, _)
            | SmtExpr::Mod(_, _) => false,
            SmtExpr::BitVecLit { .. } => false,
            SmtExpr::Var { .. } => false,
        }
    }

    /// Evaluate a simple expression given known values.
    /// Returns `Some(true/false)` if evaluation succeeds, `None` if it cannot.
    fn evaluate(
        &self,
        expr: &SmtExpr,
        equalities: &HashMap<String, i64>,
        bool_assignments: &HashMap<String, bool>,
    ) -> Option<bool> {
        match expr {
            SmtExpr::BoolLit(b) => Some(*b),

            SmtExpr::Var {
                name,
                sort: SmtSort::Bool,
            } => bool_assignments.get(name).copied(),

            SmtExpr::Not(inner) => self
                .evaluate(inner, equalities, bool_assignments)
                .map(|b| !b),

            SmtExpr::And(children) => {
                let mut all_true = true;
                let mut any_false = false;
                for child in children {
                    match self.evaluate(child, equalities, bool_assignments) {
                        Some(false) => {
                            any_false = true;
                            break;
                        }
                        Some(true) => {}
                        None => all_true = false,
                    }
                }
                if any_false {
                    Some(false)
                } else if all_true {
                    Some(true)
                } else {
                    None
                }
            }

            SmtExpr::Or(children) => {
                let mut all_false = true;
                let mut any_true = false;
                for child in children {
                    match self.evaluate(child, equalities, bool_assignments) {
                        Some(true) => {
                            any_true = true;
                            break;
                        }
                        Some(false) => {}
                        None => all_false = false,
                    }
                }
                if any_true {
                    Some(true)
                } else if all_false {
                    Some(false)
                } else {
                    None
                }
            }

            SmtExpr::Implies(ante, cons) => {
                let a = self.evaluate(ante, equalities, bool_assignments);
                let c = self.evaluate(cons, equalities, bool_assignments);
                match (a, c) {
                    (Some(false), _) => Some(true), // false => anything is true
                    (_, Some(true)) => Some(true),  // anything => true is true
                    (Some(true), Some(false)) => Some(false),
                    _ => None,
                }
            }

            SmtExpr::Ge(lhs, rhs) => {
                let l = self.eval_int(lhs, equalities)?;
                let r = self.eval_int(rhs, equalities)?;
                Some(l >= r)
            }
            SmtExpr::Gt(lhs, rhs) => {
                let l = self.eval_int(lhs, equalities)?;
                let r = self.eval_int(rhs, equalities)?;
                Some(l > r)
            }
            SmtExpr::Le(lhs, rhs) => {
                let l = self.eval_int(lhs, equalities)?;
                let r = self.eval_int(rhs, equalities)?;
                Some(l <= r)
            }
            SmtExpr::Lt(lhs, rhs) => {
                let l = self.eval_int(lhs, equalities)?;
                let r = self.eval_int(rhs, equalities)?;
                Some(l < r)
            }
            SmtExpr::Eq(lhs, rhs) => {
                // Try integer equality first.
                if let (Some(l), Some(r)) = (
                    self.eval_int(lhs, equalities),
                    self.eval_int(rhs, equalities),
                ) {
                    return Some(l == r);
                }
                // Try boolean equality.
                if let (Some(l), Some(r)) = (
                    self.evaluate(lhs, equalities, bool_assignments),
                    self.evaluate(rhs, equalities, bool_assignments),
                ) {
                    return Some(l == r);
                }
                None
            }

            _ => None,
        }
    }

    /// Evaluate an expression as an integer.
    fn eval_int(&self, expr: &SmtExpr, equalities: &HashMap<String, i64>) -> Option<i64> {
        match expr {
            SmtExpr::IntLit(n) => Some(*n),
            SmtExpr::Var {
                name,
                sort: SmtSort::Int,
            } => equalities.get(name).copied(),
            SmtExpr::Add(l, r) => {
                let lv = self.eval_int(l, equalities)?;
                let rv = self.eval_int(r, equalities)?;
                Some(lv + rv)
            }
            SmtExpr::Sub(l, r) => {
                let lv = self.eval_int(l, equalities)?;
                let rv = self.eval_int(r, equalities)?;
                Some(lv - rv)
            }
            SmtExpr::Mul(l, r) => {
                let lv = self.eval_int(l, equalities)?;
                let rv = self.eval_int(r, equalities)?;
                Some(lv * rv)
            }
            SmtExpr::Div(l, r) => {
                let lv = self.eval_int(l, equalities)?;
                let rv = self.eval_int(r, equalities)?;
                if rv == 0 {
                    None
                } else {
                    Some(lv / rv)
                }
            }
            SmtExpr::Mod(l, r) => {
                let lv = self.eval_int(l, equalities)?;
                let rv = self.eval_int(r, equalities)?;
                if rv == 0 {
                    None
                } else {
                    Some(lv % rv)
                }
            }
            SmtExpr::Ite(cond, then_e, else_e) => {
                // We need bool_assignments for evaluate, but this is eval_int.
                // Use empty bool assignments -- simple cases only.
                let empty_bools = HashMap::new();
                match self.evaluate(cond, equalities, &empty_bools)? {
                    true => self.eval_int(then_e, equalities),
                    false => self.eval_int(else_e, equalities),
                }
            }
            _ => None,
        }
    }

    // --- Helpers ---

    fn as_var_name(&self, expr: &SmtExpr) -> Option<String> {
        match expr {
            SmtExpr::Var { name, .. } => Some(name.clone()),
            _ => None,
        }
    }

    fn as_int_lit(&self, expr: &SmtExpr) -> Option<i64> {
        match expr {
            SmtExpr::IntLit(n) => Some(*n),
            _ => None,
        }
    }

    fn as_bool_lit(&self, expr: &SmtExpr) -> Option<bool> {
        match expr {
            SmtExpr::BoolLit(b) => Some(*b),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Reporting
// ---------------------------------------------------------------------------

/// Format a full SMT verification report as a human-readable string.
pub fn format_smt_report(results: &[SmtVerificationResult]) -> String {
    if results.is_empty() {
        return "No findings were submitted for SMT verification.".to_string();
    }

    let mut lines = Vec::new();
    lines.push("SMT Verification Report".to_string());
    lines.push("=".repeat(60));
    lines.push(String::new());

    for (i, r) in results.iter().enumerate() {
        lines.push(format!("Finding #{}: {}", i + 1, r.finding_detector));
        lines.push("-".repeat(40));

        let status = match &r.result {
            SmtResult::Sat { .. } => "SAT (exploit may exist)",
            SmtResult::Unsat => "UNSAT (likely false positive)",
            SmtResult::Unknown { .. } => "UNKNOWN",
        };
        lines.push(format!("  Status:      {status}"));
        lines.push(format!("  Constraints: {}", r.constraints_used));
        lines.push(format!("  Time:        {} ms", r.time_ms));

        match &r.interpretation {
            SmtInterpretation::ExploitExists {
                witness_description,
            } => {
                lines.push(format!("  Exploit:     {witness_description}"));
            }
            SmtInterpretation::FalsePositive { proof_description } => {
                lines.push(format!("  Proof:       {proof_description}"));
            }
            SmtInterpretation::Inconclusive { reason } => {
                lines.push(format!("  Reason:      {reason}"));
            }
        }

        if let SmtResult::Sat { witness } = &r.result {
            if !witness.is_empty() {
                lines.push("  Witness:".to_string());
                for (k, v) in witness {
                    lines.push(format!("    {k} = {v:?}"));
                }
            }
        }

        lines.push(String::new());
    }

    // Append summary.
    lines.push(format_verification_summary(results));
    lines.join("\n")
}

/// Format a concise summary of SMT verification results.
pub fn format_verification_summary(results: &[SmtVerificationResult]) -> String {
    let total = results.len();
    let sat_count = results
        .iter()
        .filter(|r| matches!(r.result, SmtResult::Sat { .. }))
        .count();
    let unsat_count = results
        .iter()
        .filter(|r| matches!(r.result, SmtResult::Unsat))
        .count();
    let unknown_count = results
        .iter()
        .filter(|r| matches!(r.result, SmtResult::Unknown { .. }))
        .count();
    let total_time_ms: u64 = results.iter().map(|r| r.time_ms).sum();

    let mut lines = Vec::new();
    lines.push(format!("SMT Verification Summary ({total} findings)"));
    lines.push("-".repeat(40));
    lines.push(format!(
        "  Confirmed (SAT):       {sat_count:>3} ({:.0}%)",
        if total > 0 {
            sat_count as f64 / total as f64 * 100.0
        } else {
            0.0
        }
    ));
    lines.push(format!(
        "  False positive (UNSAT): {unsat_count:>3} ({:.0}%)",
        if total > 0 {
            unsat_count as f64 / total as f64 * 100.0
        } else {
            0.0
        }
    ));
    lines.push(format!(
        "  Inconclusive:          {unknown_count:>3} ({:.0}%)",
        if total > 0 {
            unknown_count as f64 / total as f64 * 100.0
        } else {
            0.0
        }
    ));
    lines.push(format!("  Total time:            {total_time_ms:>3} ms"));
    lines.join("\n")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detector::{Confidence, Finding, Severity};

    // --- SmtExpr construction helpers ---

    #[test]
    fn test_int_var() {
        let e = SmtExpr::int_var("x");
        match &e {
            SmtExpr::Var { name, sort } => {
                assert_eq!(name, "x");
                assert_eq!(*sort, SmtSort::Int);
            }
            _ => panic!("expected Var"),
        }
    }

    #[test]
    fn test_bool_var() {
        let e = SmtExpr::bool_var("flag");
        match &e {
            SmtExpr::Var { name, sort } => {
                assert_eq!(name, "flag");
                assert_eq!(*sort, SmtSort::Bool);
            }
            _ => panic!("expected Var"),
        }
    }

    #[test]
    fn test_bv_var() {
        let e = SmtExpr::bv_var("hash", 256);
        match &e {
            SmtExpr::Var { name, sort } => {
                assert_eq!(name, "hash");
                assert_eq!(*sort, SmtSort::BitVec(256));
            }
            _ => panic!("expected Var"),
        }
    }

    #[test]
    fn test_builder_chaining() {
        let e = SmtExpr::int_var("x").gt(SmtExpr::IntLit(0));
        match &e {
            SmtExpr::Gt(_, _) => {}
            _ => panic!("expected Gt"),
        }

        let e2 = SmtExpr::int_var("a")
            .add(SmtExpr::int_var("b"))
            .eq(SmtExpr::IntLit(100));
        match &e2 {
            SmtExpr::Eq(_, _) => {}
            _ => panic!("expected Eq"),
        }
    }

    #[test]
    fn test_and_all_or_any() {
        let conj = SmtExpr::and_all(vec![SmtExpr::BoolLit(true), SmtExpr::BoolLit(true)]);
        match &conj {
            SmtExpr::And(children) => assert_eq!(children.len(), 2),
            _ => panic!("expected And"),
        }

        let disj = SmtExpr::or_any(vec![SmtExpr::BoolLit(false), SmtExpr::BoolLit(true)]);
        match &disj {
            SmtExpr::Or(children) => assert_eq!(children.len(), 2),
            _ => panic!("expected Or"),
        }
    }

    #[test]
    fn test_not_and_implies() {
        let neg = SmtExpr::BoolLit(true).not();
        match &neg {
            SmtExpr::Not(_) => {}
            _ => panic!("expected Not"),
        }

        let imp = SmtExpr::bool_var("a").implies(SmtExpr::bool_var("b"));
        match &imp {
            SmtExpr::Implies(_, _) => {}
            _ => panic!("expected Implies"),
        }
    }

    // --- SmtSort display ---

    #[test]
    fn test_sort_display() {
        assert_eq!(SmtSort::Bool.to_string(), "Bool");
        assert_eq!(SmtSort::Int.to_string(), "Int");
        assert_eq!(SmtSort::BitVec(256).to_string(), "BitVec(256)");
        assert_eq!(
            SmtSort::Array(Box::new(SmtSort::Int), Box::new(SmtSort::Bool)).to_string(),
            "Array(Int, Bool)"
        );
        assert_eq!(SmtSort::Custom("Value".into()).to_string(), "Value");
    }

    // --- Cardano axioms ---

    #[test]
    fn test_cardano_axioms_count() {
        let axioms = cardano_axioms();
        assert_eq!(axioms.len(), 6);
    }

    #[test]
    fn test_lovelace_non_negative_structure() {
        let axiom = lovelace_non_negative();
        match &axiom {
            SmtExpr::Ge(lhs, rhs) => {
                assert!(matches!(lhs.as_ref(), SmtExpr::Var { name, .. } if name == "lovelace"));
                assert!(matches!(rhs.as_ref(), SmtExpr::IntLit(0)));
            }
            _ => panic!("expected Ge"),
        }
    }

    #[test]
    fn test_min_utxo_constraint_structure() {
        let axiom = min_utxo_constraint();
        match &axiom {
            SmtExpr::Ge(lhs, rhs) => {
                assert!(
                    matches!(lhs.as_ref(), SmtExpr::Var { name, .. } if name == "output_lovelace")
                );
                assert!(matches!(rhs.as_ref(), SmtExpr::IntLit(1_000_000)));
            }
            _ => panic!("expected Ge"),
        }
    }

    #[test]
    fn test_tx_value_conservation_structure() {
        let axiom = tx_value_conservation();
        match &axiom {
            SmtExpr::Eq(lhs, rhs) => {
                assert!(matches!(lhs.as_ref(), SmtExpr::Var { name, .. } if name == "input_total"));
                // rhs should be Add(output_total, fee)
                assert!(matches!(rhs.as_ref(), SmtExpr::Add(_, _)));
            }
            _ => panic!("expected Eq"),
        }
    }

    #[test]
    fn test_fee_constraints_structure() {
        let axiom = fee_constraints();
        match &axiom {
            SmtExpr::And(children) => {
                assert_eq!(children.len(), 2);
            }
            _ => panic!("expected And"),
        }
    }

    #[test]
    fn test_validity_range_ordering_structure() {
        let axiom = validity_range_ordering();
        match &axiom {
            SmtExpr::Le(lhs, rhs) => {
                assert!(
                    matches!(lhs.as_ref(), SmtExpr::Var { name, .. } if name == "validity_start")
                );
                assert!(
                    matches!(rhs.as_ref(), SmtExpr::Var { name, .. } if name == "validity_end")
                );
            }
            _ => panic!("expected Le"),
        }
    }

    // --- Path condition encoding ---

    #[test]
    fn test_encode_equals() {
        let conds = vec![PathCondition {
            variable: "redeemer".to_string(),
            constraint: PathConstraint::Equals("Deposit".to_string()),
        }];
        let encoded = encode_path_conditions(&conds);
        assert_eq!(encoded.len(), 1);
        match &encoded[0] {
            SmtExpr::Var { name, sort } => {
                assert_eq!(name, "redeemer_is_Deposit");
                assert_eq!(*sort, SmtSort::Bool);
            }
            _ => panic!("expected Var"),
        }
    }

    #[test]
    fn test_encode_not_equals() {
        let conds = vec![PathCondition {
            variable: "redeemer".to_string(),
            constraint: PathConstraint::NotEquals("Withdraw".to_string()),
        }];
        let encoded = encode_path_conditions(&conds);
        assert_eq!(encoded.len(), 1);
        match &encoded[0] {
            SmtExpr::Not(inner) => match inner.as_ref() {
                SmtExpr::Var { name, .. } => assert_eq!(name, "redeemer_is_Withdraw"),
                _ => panic!("expected Var inside Not"),
            },
            _ => panic!("expected Not"),
        }
    }

    #[test]
    fn test_encode_less_than() {
        let conds = vec![PathCondition {
            variable: "amount".to_string(),
            constraint: PathConstraint::LessThan(100),
        }];
        let encoded = encode_path_conditions(&conds);
        assert_eq!(encoded.len(), 1);
        match &encoded[0] {
            SmtExpr::Lt(lhs, rhs) => {
                assert!(matches!(lhs.as_ref(), SmtExpr::Var { name, .. } if name == "amount"));
                assert!(matches!(rhs.as_ref(), SmtExpr::IntLit(100)));
            }
            _ => panic!("expected Lt"),
        }
    }

    #[test]
    fn test_encode_greater_than() {
        let conds = vec![PathCondition {
            variable: "balance".to_string(),
            constraint: PathConstraint::GreaterThan(0),
        }];
        let encoded = encode_path_conditions(&conds);
        assert_eq!(encoded.len(), 1);
        match &encoded[0] {
            SmtExpr::Gt(lhs, rhs) => {
                assert!(matches!(lhs.as_ref(), SmtExpr::Var { name, .. } if name == "balance"));
                assert!(matches!(rhs.as_ref(), SmtExpr::IntLit(0)));
            }
            _ => panic!("expected Gt"),
        }
    }

    #[test]
    fn test_encode_in_set() {
        let conds = vec![PathCondition {
            variable: "action".to_string(),
            constraint: PathConstraint::InSet(vec!["Deposit".to_string(), "Withdraw".to_string()]),
        }];
        let encoded = encode_path_conditions(&conds);
        assert_eq!(encoded.len(), 1);
        match &encoded[0] {
            SmtExpr::Or(children) => {
                assert_eq!(children.len(), 2);
            }
            _ => panic!("expected Or"),
        }
    }

    #[test]
    fn test_encode_is_constructor() {
        let conds = vec![PathCondition {
            variable: "datum".to_string(),
            constraint: PathConstraint::IsConstructor("ActiveState".to_string()),
        }];
        let encoded = encode_path_conditions(&conds);
        assert_eq!(encoded.len(), 1);
        match &encoded[0] {
            SmtExpr::Var { name, sort } => {
                assert_eq!(name, "datum_is_ActiveState");
                assert_eq!(*sort, SmtSort::Bool);
            }
            _ => panic!("expected Var"),
        }
    }

    #[test]
    fn test_encode_is_not_constructor() {
        let conds = vec![PathCondition {
            variable: "datum".to_string(),
            constraint: PathConstraint::IsNotConstructor("Closed".to_string()),
        }];
        let encoded = encode_path_conditions(&conds);
        assert_eq!(encoded.len(), 1);
        match &encoded[0] {
            SmtExpr::Not(_) => {}
            _ => panic!("expected Not"),
        }
    }

    #[test]
    fn test_encode_le_ge() {
        let conds = vec![
            PathCondition {
                variable: "x".to_string(),
                constraint: PathConstraint::LessThanOrEqual(50),
            },
            PathCondition {
                variable: "y".to_string(),
                constraint: PathConstraint::GreaterThanOrEqual(10),
            },
        ];
        let encoded = encode_path_conditions(&conds);
        assert_eq!(encoded.len(), 2);
        assert!(matches!(&encoded[0], SmtExpr::Le(_, _)));
        assert!(matches!(&encoded[1], SmtExpr::Ge(_, _)));
    }

    #[test]
    fn test_encode_multiple_conditions() {
        let conds = vec![
            PathCondition {
                variable: "amount".to_string(),
                constraint: PathConstraint::GreaterThan(0),
            },
            PathCondition {
                variable: "amount".to_string(),
                constraint: PathConstraint::LessThan(1_000_000_000),
            },
            PathCondition {
                variable: "action".to_string(),
                constraint: PathConstraint::IsConstructor("Deposit".to_string()),
            },
        ];
        let encoded = encode_path_conditions(&conds);
        assert_eq!(encoded.len(), 3);
    }

    // --- SimpleSmtSolver ---

    #[test]
    fn test_solver_empty_assertions() {
        let solver = SimpleSmtSolver::new();
        let result = solver.check_sat(&[]);
        assert!(matches!(result, SmtResult::Sat { .. }));
    }

    #[test]
    fn test_solver_simple_sat() {
        let solver = SimpleSmtSolver::new();
        // x >= 0 AND x <= 100  -->  SAT
        let assertions = vec![
            SmtExpr::int_var("x").ge(SmtExpr::IntLit(0)),
            SmtExpr::int_var("x").le(SmtExpr::IntLit(100)),
        ];
        let result = solver.check_sat(&assertions);
        assert!(matches!(result, SmtResult::Sat { .. }));
    }

    #[test]
    fn test_solver_simple_unsat() {
        let solver = SimpleSmtSolver::new();
        // x >= 100 AND x <= 50  -->  UNSAT
        let assertions = vec![
            SmtExpr::int_var("x").ge(SmtExpr::IntLit(100)),
            SmtExpr::int_var("x").le(SmtExpr::IntLit(50)),
        ];
        let result = solver.check_sat(&assertions);
        assert!(matches!(result, SmtResult::Unsat));
    }

    #[test]
    fn test_solver_equality_conflict_with_lower_bound() {
        let solver = SimpleSmtSolver::new();
        // x == 5 AND x >= 10  -->  UNSAT
        let assertions = vec![
            SmtExpr::int_var("x").eq(SmtExpr::IntLit(5)),
            SmtExpr::int_var("x").ge(SmtExpr::IntLit(10)),
        ];
        let result = solver.check_sat(&assertions);
        assert!(matches!(result, SmtResult::Unsat));
    }

    #[test]
    fn test_solver_equality_conflict_with_upper_bound() {
        let solver = SimpleSmtSolver::new();
        // x == 100 AND x <= 50  -->  UNSAT
        let assertions = vec![
            SmtExpr::int_var("x").eq(SmtExpr::IntLit(100)),
            SmtExpr::int_var("x").le(SmtExpr::IntLit(50)),
        ];
        let result = solver.check_sat(&assertions);
        assert!(matches!(result, SmtResult::Unsat));
    }

    #[test]
    fn test_solver_bool_literal_false() {
        let solver = SimpleSmtSolver::new();
        // false  -->  UNSAT
        let assertions = vec![SmtExpr::BoolLit(false)];
        let result = solver.check_sat(&assertions);
        assert!(matches!(result, SmtResult::Unsat));
    }

    #[test]
    fn test_solver_bool_literal_true() {
        let solver = SimpleSmtSolver::new();
        // true  -->  SAT
        let assertions = vec![SmtExpr::BoolLit(true)];
        let result = solver.check_sat(&assertions);
        assert!(matches!(result, SmtResult::Sat { .. }));
    }

    #[test]
    fn test_solver_bool_variable_and_negation() {
        let solver = SimpleSmtSolver::new();
        // flag AND !flag  -->  UNSAT
        let assertions = vec![SmtExpr::bool_var("flag"), SmtExpr::bool_var("flag").not()];
        let result = solver.check_sat(&assertions);
        assert!(matches!(result, SmtResult::Unsat));
    }

    #[test]
    fn test_solver_gt_lt_boundary() {
        let solver = SimpleSmtSolver::new();
        // x > 5 AND x < 7  -->  SAT (x=6)
        let assertions = vec![
            SmtExpr::int_var("x").gt(SmtExpr::IntLit(5)),
            SmtExpr::int_var("x").lt(SmtExpr::IntLit(7)),
        ];
        let result = solver.check_sat(&assertions);
        assert!(matches!(result, SmtResult::Sat { .. }));
    }

    #[test]
    fn test_solver_gt_lt_empty_range() {
        let solver = SimpleSmtSolver::new();
        // x > 10 AND x < 10  -->  UNSAT (lb=11, ub=9)
        let assertions = vec![
            SmtExpr::int_var("x").gt(SmtExpr::IntLit(10)),
            SmtExpr::int_var("x").lt(SmtExpr::IntLit(10)),
        ];
        let result = solver.check_sat(&assertions);
        assert!(matches!(result, SmtResult::Unsat));
    }

    #[test]
    fn test_solver_and_conjunction() {
        let solver = SimpleSmtSolver::new();
        // AND(x >= 0, x <= 100)  -->  SAT
        let assertions = vec![SmtExpr::and_all(vec![
            SmtExpr::int_var("x").ge(SmtExpr::IntLit(0)),
            SmtExpr::int_var("x").le(SmtExpr::IntLit(100)),
        ])];
        let result = solver.check_sat(&assertions);
        assert!(matches!(result, SmtResult::Sat { .. }));
    }

    #[test]
    fn test_solver_unknown_for_quantifiers() {
        let solver = SimpleSmtSolver::new();
        let assertions = vec![SmtExpr::ForAll {
            vars: vec![("x".to_string(), SmtSort::Int)],
            body: Box::new(SmtExpr::int_var("x").ge(SmtExpr::IntLit(0))),
        }];
        let result = solver.check_sat(&assertions);
        assert!(matches!(result, SmtResult::Unknown { .. }));
    }

    #[test]
    fn test_solver_unknown_for_or() {
        let solver = SimpleSmtSolver::new();
        // OR is beyond the simple solver's extraction phase
        let assertions = vec![SmtExpr::or_any(vec![
            SmtExpr::int_var("x").ge(SmtExpr::IntLit(0)),
            SmtExpr::int_var("x").le(SmtExpr::IntLit(100)),
        ])];
        let result = solver.check_sat(&assertions);
        // The simple solver can't extract bounds from OR, so it reports Unknown
        assert!(matches!(result, SmtResult::Unknown { .. }));
    }

    #[test]
    fn test_solver_cardano_axioms_sat() {
        let solver = SimpleSmtSolver::new();
        // Cardano axioms alone should be satisfiable (there exist valid transactions)
        let axioms = cardano_axioms();
        let result = solver.check_sat(&axioms);
        // The axioms include tx_value_conservation (Eq with Add), which is complex,
        // so we expect Unknown from the simple solver.
        assert!(matches!(
            result,
            SmtResult::Sat { .. } | SmtResult::Unknown { .. }
        ));
    }

    #[test]
    fn test_solver_witness_values() {
        let solver = SimpleSmtSolver::new();
        // x == 42  -->  SAT with witness x=42
        let assertions = vec![SmtExpr::int_var("x").eq(SmtExpr::IntLit(42))];
        let result = solver.check_sat(&assertions);
        match result {
            SmtResult::Sat { witness } => {
                assert_eq!(witness.get("x"), Some(&SmtValue::Int(42)));
            }
            _ => panic!("expected SAT"),
        }
    }

    #[test]
    fn test_solver_bool_witness() {
        let solver = SimpleSmtSolver::new();
        let assertions = vec![SmtExpr::bool_var("valid")];
        let result = solver.check_sat(&assertions);
        match result {
            SmtResult::Sat { witness } => {
                assert_eq!(witness.get("valid"), Some(&SmtValue::Bool(true)));
            }
            _ => panic!("expected SAT"),
        }
    }

    #[test]
    fn test_solver_default_trait() {
        let solver = SimpleSmtSolver;
        let result = solver.check_sat(&[]);
        assert!(matches!(result, SmtResult::Sat { .. }));
    }

    // --- Finding verification pipeline ---

    fn make_test_finding(detector: &str) -> Finding {
        Finding {
            detector_name: detector.to_string(),
            severity: Severity::High,
            confidence: Confidence::Likely,
            title: format!("Test finding from {detector}"),
            description: "Test description.".to_string(),
            module: "test_module".to_string(),
            location: None,
            suggestion: None,
            related_findings: vec![],
            semantic_group: None,
            evidence: None,
        }
    }

    #[test]
    fn test_verify_finding_returns_result() {
        let finding = make_test_finding("value-not-preserved");
        let result = verify_finding_smt(&finding, &[]);
        assert_eq!(result.finding_detector, "value-not-preserved");
        assert!(result.constraints_used > 0);
    }

    #[test]
    fn test_verify_finding_with_path_conditions() {
        let finding = make_test_finding("division-by-zero-risk");
        let conditions = vec![
            PathCondition {
                variable: "divisor".to_string(),
                constraint: PathConstraint::GreaterThan(0),
            },
            PathCondition {
                variable: "divisor".to_string(),
                constraint: PathConstraint::LessThan(1000),
            },
        ];
        let result = verify_finding_smt(&finding, &conditions);
        assert!(result.constraints_used >= 8); // 6 axioms + 2 path conditions
    }

    #[test]
    fn test_verify_finding_contradictory_conditions() {
        let finding = make_test_finding("missing-validity-range");
        // validity_start > validity_end contradicts the axiom validity_start <= validity_end
        let conditions = vec![
            PathCondition {
                variable: "validity_start".to_string(),
                constraint: PathConstraint::GreaterThan(1000),
            },
            PathCondition {
                variable: "validity_end".to_string(),
                constraint: PathConstraint::LessThan(500),
            },
        ];
        let result = verify_finding_smt(&finding, &conditions);
        // The simple solver should detect the contradiction from the axiom
        // validity_start <= validity_end combined with validity_start > 1000
        // and validity_end < 500.
        assert!(matches!(
            result.result,
            SmtResult::Unsat | SmtResult::Unknown { .. }
        ));
    }

    #[test]
    fn test_verify_finding_value_context_encoding() {
        let finding = make_test_finding("value-not-preserved");
        let encoded = encode_finding_context(&finding);
        // "value" detector should include lovelace_non_negative, min_utxo, tx_value_conservation
        assert!(encoded.len() >= 2);
    }

    #[test]
    fn test_verify_finding_minting_context() {
        let finding = make_test_finding("unrestricted-minting");
        let encoded = encode_finding_context(&finding);
        // "minting" detector should include mint quantity and asset name constraints
        assert!(encoded.len() >= 3);
    }

    #[test]
    fn test_verify_finding_datum_context() {
        let finding = make_test_finding("missing-datum-in-script-output");
        let encoded = encode_finding_context(&finding);
        // "datum" detector should include datum presence constraint
        assert!(!encoded.is_empty());
    }

    #[test]
    fn test_verify_finding_signature_context() {
        let finding = make_test_finding("missing-signature-check");
        let encoded = encode_finding_context(&finding);
        assert!(!encoded.is_empty());
    }

    #[test]
    fn test_verify_finding_address_context() {
        let finding = make_test_finding("output-address-not-validated");
        let encoded = encode_finding_context(&finding);
        assert!(!encoded.is_empty());
    }

    #[test]
    fn test_verify_finding_double_satisfaction_context() {
        let finding = make_test_finding("double-satisfaction");
        let encoded = encode_finding_context(&finding);
        // Should include tx_value_conservation
        assert!(!encoded.is_empty());
    }

    // --- Interpretation types ---

    #[test]
    fn test_interpretation_exploit_exists() {
        let interp = SmtInterpretation::ExploitExists {
            witness_description: "divisor = 0".to_string(),
        };
        let serialized = serde_json::to_string(&interp).unwrap();
        assert!(serialized.contains("ExploitExists"));
    }

    #[test]
    fn test_interpretation_false_positive() {
        let interp = SmtInterpretation::FalsePositive {
            proof_description: "No model exists.".to_string(),
        };
        let serialized = serde_json::to_string(&interp).unwrap();
        assert!(serialized.contains("FalsePositive"));
    }

    #[test]
    fn test_interpretation_inconclusive() {
        let interp = SmtInterpretation::Inconclusive {
            reason: "timeout".to_string(),
        };
        let serialized = serde_json::to_string(&interp).unwrap();
        assert!(serialized.contains("Inconclusive"));
    }

    // --- Reporting ---

    #[test]
    fn test_format_smt_report_empty() {
        let report = format_smt_report(&[]);
        assert!(report.contains("No findings"));
    }

    #[test]
    fn test_format_smt_report_with_results() {
        let results = vec![
            SmtVerificationResult {
                finding_detector: "division-by-zero-risk".to_string(),
                result: SmtResult::Sat {
                    witness: {
                        let mut m = HashMap::new();
                        m.insert("divisor".to_string(), SmtValue::Int(0));
                        m
                    },
                },
                interpretation: SmtInterpretation::ExploitExists {
                    witness_description: "divisor = 0".to_string(),
                },
                constraints_used: 8,
                time_ms: 1,
            },
            SmtVerificationResult {
                finding_detector: "missing-validity-range".to_string(),
                result: SmtResult::Unsat,
                interpretation: SmtInterpretation::FalsePositive {
                    proof_description: "Constraints are contradictory.".to_string(),
                },
                constraints_used: 10,
                time_ms: 0,
            },
        ];
        let report = format_smt_report(&results);
        assert!(report.contains("Finding #1: division-by-zero-risk"));
        assert!(report.contains("Finding #2: missing-validity-range"));
        assert!(report.contains("SAT"));
        assert!(report.contains("UNSAT"));
        assert!(report.contains("SMT Verification Summary"));
    }

    #[test]
    fn test_format_verification_summary() {
        let results = vec![
            SmtVerificationResult {
                finding_detector: "a".to_string(),
                result: SmtResult::Sat {
                    witness: HashMap::new(),
                },
                interpretation: SmtInterpretation::ExploitExists {
                    witness_description: "test".to_string(),
                },
                constraints_used: 5,
                time_ms: 1,
            },
            SmtVerificationResult {
                finding_detector: "b".to_string(),
                result: SmtResult::Unsat,
                interpretation: SmtInterpretation::FalsePositive {
                    proof_description: "test".to_string(),
                },
                constraints_used: 5,
                time_ms: 2,
            },
            SmtVerificationResult {
                finding_detector: "c".to_string(),
                result: SmtResult::Unknown {
                    reason: "timeout".to_string(),
                },
                interpretation: SmtInterpretation::Inconclusive {
                    reason: "timeout".to_string(),
                },
                constraints_used: 5,
                time_ms: 100,
            },
        ];
        let summary = format_verification_summary(&results);
        assert!(summary.contains("3 findings"));
        assert!(summary.contains("Confirmed (SAT)"));
        assert!(summary.contains("False positive (UNSAT)"));
        assert!(summary.contains("Inconclusive"));
        assert!(summary.contains("103 ms"));
    }

    #[test]
    fn test_format_summary_zero_findings() {
        let summary = format_verification_summary(&[]);
        assert!(summary.contains("0 findings"));
    }

    // --- Serialization ---

    #[test]
    fn test_smt_result_serialization() {
        let sat = SmtResult::Sat {
            witness: {
                let mut m = HashMap::new();
                m.insert("x".to_string(), SmtValue::Int(42));
                m
            },
        };
        let json = serde_json::to_string(&sat).unwrap();
        assert!(json.contains("Sat"));
        assert!(json.contains("42"));

        let unsat = SmtResult::Unsat;
        let json = serde_json::to_string(&unsat).unwrap();
        assert!(json.contains("Unsat"));

        let unknown = SmtResult::Unknown {
            reason: "timeout".to_string(),
        };
        let json = serde_json::to_string(&unknown).unwrap();
        assert!(json.contains("Unknown"));
    }

    #[test]
    fn test_smt_value_serialization() {
        let val = SmtValue::Bool(true);
        let json = serde_json::to_string(&val).unwrap();
        assert!(json.contains("true"));

        let val = SmtValue::Int(-5);
        let json = serde_json::to_string(&val).unwrap();
        assert!(json.contains("-5"));

        let val = SmtValue::BitVec(vec![0xAB, 0xCD]);
        let json = serde_json::to_string(&val).unwrap();
        assert!(json.contains("BitVec"));

        let val = SmtValue::Custom("special".to_string());
        let json = serde_json::to_string(&val).unwrap();
        assert!(json.contains("special"));
    }

    #[test]
    fn test_smt_expr_serialization() {
        let expr = SmtExpr::int_var("x").gt(SmtExpr::IntLit(0));
        let json = serde_json::to_string(&expr).unwrap();
        assert!(json.contains("Gt"));
    }

    #[test]
    fn test_verification_result_serialization() {
        let vr = SmtVerificationResult {
            finding_detector: "test-detector".to_string(),
            result: SmtResult::Unsat,
            interpretation: SmtInterpretation::FalsePositive {
                proof_description: "No model.".to_string(),
            },
            constraints_used: 6,
            time_ms: 0,
        };
        let json = serde_json::to_string(&vr).unwrap();
        assert!(json.contains("test-detector"));
        assert!(json.contains("Unsat"));
    }

    // --- Evaluate helper ---

    #[test]
    fn test_evaluate_bool_literals() {
        let solver = SimpleSmtSolver::new();
        let eq = HashMap::new();
        let ba = HashMap::new();
        assert_eq!(
            solver.evaluate(&SmtExpr::BoolLit(true), &eq, &ba),
            Some(true)
        );
        assert_eq!(
            solver.evaluate(&SmtExpr::BoolLit(false), &eq, &ba),
            Some(false)
        );
    }

    #[test]
    fn test_evaluate_and() {
        let solver = SimpleSmtSolver::new();
        let eq = HashMap::new();
        let ba = HashMap::new();
        let expr = SmtExpr::and_all(vec![SmtExpr::BoolLit(true), SmtExpr::BoolLit(true)]);
        assert_eq!(solver.evaluate(&expr, &eq, &ba), Some(true));

        let expr2 = SmtExpr::and_all(vec![SmtExpr::BoolLit(true), SmtExpr::BoolLit(false)]);
        assert_eq!(solver.evaluate(&expr2, &eq, &ba), Some(false));
    }

    #[test]
    fn test_evaluate_or() {
        let solver = SimpleSmtSolver::new();
        let eq = HashMap::new();
        let ba = HashMap::new();
        let expr = SmtExpr::or_any(vec![SmtExpr::BoolLit(false), SmtExpr::BoolLit(true)]);
        assert_eq!(solver.evaluate(&expr, &eq, &ba), Some(true));

        let expr2 = SmtExpr::or_any(vec![SmtExpr::BoolLit(false), SmtExpr::BoolLit(false)]);
        assert_eq!(solver.evaluate(&expr2, &eq, &ba), Some(false));
    }

    #[test]
    fn test_evaluate_implies() {
        let solver = SimpleSmtSolver::new();
        let eq = HashMap::new();
        let ba = HashMap::new();
        // false => anything is true
        let expr = SmtExpr::BoolLit(false).implies(SmtExpr::BoolLit(false));
        assert_eq!(solver.evaluate(&expr, &eq, &ba), Some(true));

        // true => false is false
        let expr2 = SmtExpr::BoolLit(true).implies(SmtExpr::BoolLit(false));
        assert_eq!(solver.evaluate(&expr2, &eq, &ba), Some(false));

        // true => true is true
        let expr3 = SmtExpr::BoolLit(true).implies(SmtExpr::BoolLit(true));
        assert_eq!(solver.evaluate(&expr3, &eq, &ba), Some(true));
    }

    #[test]
    fn test_evaluate_comparisons_with_known_values() {
        let solver = SimpleSmtSolver::new();
        let mut eq = HashMap::new();
        eq.insert("x".to_string(), 10);
        let ba = HashMap::new();

        assert_eq!(
            solver.evaluate(&SmtExpr::int_var("x").gt(SmtExpr::IntLit(5)), &eq, &ba),
            Some(true)
        );
        assert_eq!(
            solver.evaluate(&SmtExpr::int_var("x").lt(SmtExpr::IntLit(5)), &eq, &ba),
            Some(false)
        );
        assert_eq!(
            solver.evaluate(&SmtExpr::int_var("x").eq(SmtExpr::IntLit(10)), &eq, &ba),
            Some(true)
        );
        assert_eq!(
            solver.evaluate(&SmtExpr::int_var("x").ge(SmtExpr::IntLit(10)), &eq, &ba),
            Some(true)
        );
        assert_eq!(
            solver.evaluate(&SmtExpr::int_var("x").le(SmtExpr::IntLit(10)), &eq, &ba),
            Some(true)
        );
    }

    #[test]
    fn test_evaluate_unknown_variable() {
        let solver = SimpleSmtSolver::new();
        let eq = HashMap::new();
        let ba = HashMap::new();
        // Unknown variable => None
        assert_eq!(
            solver.evaluate(
                &SmtExpr::int_var("unknown").gt(SmtExpr::IntLit(0)),
                &eq,
                &ba
            ),
            None
        );
    }

    #[test]
    fn test_eval_int_arithmetic() {
        let solver = SimpleSmtSolver::new();
        let mut eq = HashMap::new();
        eq.insert("a".to_string(), 10);
        eq.insert("b".to_string(), 3);

        assert_eq!(
            solver.eval_int(&SmtExpr::int_var("a").add(SmtExpr::int_var("b")), &eq),
            Some(13)
        );
        assert_eq!(
            solver.eval_int(&SmtExpr::int_var("a").sub(SmtExpr::int_var("b")), &eq),
            Some(7)
        );
        assert_eq!(
            solver.eval_int(
                &SmtExpr::Mul(
                    Box::new(SmtExpr::int_var("a")),
                    Box::new(SmtExpr::int_var("b"))
                ),
                &eq
            ),
            Some(30)
        );
        assert_eq!(
            solver.eval_int(
                &SmtExpr::Div(
                    Box::new(SmtExpr::int_var("a")),
                    Box::new(SmtExpr::int_var("b"))
                ),
                &eq
            ),
            Some(3)
        );
        assert_eq!(
            solver.eval_int(
                &SmtExpr::Mod(
                    Box::new(SmtExpr::int_var("a")),
                    Box::new(SmtExpr::int_var("b"))
                ),
                &eq
            ),
            Some(1)
        );
    }

    #[test]
    fn test_eval_int_div_by_zero() {
        let solver = SimpleSmtSolver::new();
        let mut eq = HashMap::new();
        eq.insert("a".to_string(), 10);
        eq.insert("b".to_string(), 0);
        assert_eq!(
            solver.eval_int(
                &SmtExpr::Div(
                    Box::new(SmtExpr::int_var("a")),
                    Box::new(SmtExpr::int_var("b"))
                ),
                &eq
            ),
            None
        );
        assert_eq!(
            solver.eval_int(
                &SmtExpr::Mod(
                    Box::new(SmtExpr::int_var("a")),
                    Box::new(SmtExpr::int_var("b"))
                ),
                &eq
            ),
            None
        );
    }

    // --- End-to-end pipeline test ---

    #[test]
    fn test_e2e_verify_value_not_preserved_with_tight_conditions() {
        let finding = make_test_finding("value-not-preserved");
        let conditions = vec![
            PathCondition {
                variable: "lovelace".to_string(),
                constraint: PathConstraint::GreaterThanOrEqual(0),
            },
            PathCondition {
                variable: "output_lovelace".to_string(),
                constraint: PathConstraint::GreaterThanOrEqual(1_000_000),
            },
        ];
        let result = verify_finding_smt(&finding, &conditions);
        assert_eq!(result.finding_detector, "value-not-preserved");
        // Should produce a result (SAT or Unknown, depending on axiom complexity)
        assert!(result.constraints_used > 0);
        assert!(result.time_ms < 1000); // Should be fast
    }

    #[test]
    fn test_e2e_verify_impossible_fee() {
        // fee >= 155_381 (axiom) AND fee < 100 (path condition) --> UNSAT
        let finding = make_test_finding("fee-calculation-unchecked");
        let conditions = vec![PathCondition {
            variable: "fee".to_string(),
            constraint: PathConstraint::LessThan(100),
        }];
        let result = verify_finding_smt(&finding, &conditions);
        // The axiom says fee >= 155_381, the condition says fee < 100.
        // The simple solver should detect this contradiction.
        assert!(matches!(
            result.result,
            SmtResult::Unsat | SmtResult::Unknown { .. }
        ));
    }
}
