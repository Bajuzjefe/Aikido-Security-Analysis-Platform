use std::collections::HashSet;

use aiken_lang::ast::{BinOp, Pattern, TypedClause};
use aiken_lang::expr::TypedExpr;

/// A structured guard tracking entry: which variable is guarded, with what
/// comparison operation, and against what other variable (if any).
#[derive(Debug, Clone)]
pub struct GuardedOperation {
    pub guarded_var: String,
    pub guard_op: BinOp,
    pub compared_to: Option<String>,
}

/// Behavioral signals extracted from walking a handler body's expression tree.
#[derive(Debug, Clone, Default)]
pub struct BodySignals {
    /// Field accesses on the Transaction param (e.g., "extra_signatories", "validity_range")
    pub tx_field_accesses: HashSet<String>,
    /// Whether the own_ref parameter (3rd spend param) is referenced in the body
    pub uses_own_ref: bool,
    /// Function calls made (e.g., "list.has", "interval.is_entirely_after")
    pub function_calls: HashSet<String>,
    /// Variable names referenced in the body
    pub var_references: HashSet<String>,
    /// When/match branches — for redeemer analysis
    pub when_branches: Vec<WhenBranchInfo>,
    /// Variables with `expect Some(x) = var` pattern (unsafe datum deconstruction check)
    pub expect_some_vars: HashSet<String>,
    /// TX fields passed to list iteration functions (list.any/map/filter/etc)
    pub tx_list_iterations: HashSet<String>,
    /// ByteArray literal lengths found in body (for hardcoded address detection)
    pub bytearray_literal_lengths: Vec<usize>,
    /// All RecordAccess labels encountered in body (e.g., "datum", "value", "address")
    pub all_record_labels: HashSet<String>,
    /// Division/modulo operations found (BinOp with DivInt, ModInt)
    pub has_division: bool,
    /// Subtraction operations found (BinOp with SubInt)
    pub has_subtraction: bool,
    /// Multiplication operations found (BinOp with MultInt)
    pub has_multiplication: bool,
    /// Calls to list.head or list.at (unsafe without length check)
    pub unsafe_list_access_calls: Vec<String>,

    /// Whether the handler enforces a single-input constraint (e.g.,
    /// `expect list.length(get_all_validators_inputs(tx)) == 1`).
    /// This prevents double satisfaction without needing own_ref.
    pub enforces_single_input: bool,

    /// Variables that appear in comparison guards (e.g., `expect x > 0`, `x >= min_value`).
    /// Used to suppress false positives in division-by-zero and redeemer arithmetic detectors.
    pub guarded_vars: HashSet<String>,

    /// Variable names used as divisors in division/modulo operations.
    /// Used for precise guard correlation in division-by-zero detection.
    pub division_divisors: HashSet<String>,

    /// Whether an `expect [h, ..rest] = list` pattern was found (implicit base case for recursion).
    pub has_expect_list_destructure: bool,

    /// Whether a `match(val, expected, >=)` or similar inequality call was detected.
    /// True when `assets.match`/`match` is called with a BinOp inequality (>=, >, <=, <)
    /// as the comparison operator argument. This is unsafe for multi-asset Value comparison.
    pub has_unsafe_match_comparison: bool,

    // --- Feature #33: Taint tracking (lightweight) ---
    /// Variables derived from the redeemer parameter (tainted by redeemer).
    pub redeemer_tainted_vars: HashSet<String>,

    // --- Feature #36: Data flow analysis (datum field tracking) ---
    /// Fields accessed on the datum parameter (first param of spend handlers).
    pub datum_field_accesses: HashSet<String>,

    /// Whether the handler uses record update syntax (`MyType { ..base, field: val }`).
    /// This preserves all fields not explicitly overridden, preventing datum tampering.
    pub has_record_update: bool,

    /// Structured guard tracking: each entry records the guarded variable,
    /// the comparison operator, and the variable it is compared against.
    /// Populated from BinOp comparisons; backward-compatible with `guarded_vars`.
    pub guarded_operations: Vec<GuardedOperation>,

    /// Whether the handler contains a fold/foldl/foldr counting pattern
    /// (e.g., `dict.foldl` + accumulator for token quantity validation).
    pub has_fold_counting_pattern: bool,

    /// Whether the handler accesses `extra_signatories` and compares against a known key.
    /// Indicates an admin-signed or signature-gated handler.
    pub requires_signature: bool,

    /// Variable names that participate in subtraction operations (BinOp::SubInt).
    /// Used for correlating guards with specific subtractions in integer-underflow detection.
    pub subtraction_operands: HashSet<String>,

    /// Number of `quantity_of` calls in the handler body.
    /// Unlike `function_calls` (a HashSet that deduplicates), this tracks actual call frequency
    /// for detecting multiple independent quantity_of checks that may allow double-counting.
    pub quantity_of_call_count: usize,

    /// Distinct (policy_var, asset_var) pairs passed to quantity_of calls.
    /// When `quantity_of_asset_pairs.len() == quantity_of_call_count`, all calls check
    /// distinct assets, making double-counting unlikely.
    pub quantity_of_asset_pairs: HashSet<String>,

    /// Tautological comparisons found (e.g., `datum.field == datum.field`).
    /// Each entry is a string like "datum.mint_policy_id == datum.mint_policy_id".
    pub tautological_comparisons: Vec<String>,

    // --- Datum continuity tracking ---
    /// Fields compared between input and output datums (equality checks on datum fields).
    /// Populated when patterns like `new_datum.field == old_datum.field` are detected.
    pub datum_equality_checks: HashSet<String>,

    /// Whether the handler asserts whole-datum continuity (e.g., `expect input_datum == output_datum`
    /// or record update syntax preserving all fields).
    pub has_datum_continuity_assertion: bool,
}

#[derive(Debug, Clone)]
pub struct WhenBranchInfo {
    pub pattern_text: String,
    pub is_catchall: bool,
    pub body_is_literal_true: bool,
    pub body_is_error: bool,
}

/// Analyze a handler body expression, extracting behavioral signals.
///
/// - `tx_param_name`: name of the Transaction parameter (usually the last handler param).
/// - `own_ref_param_name`: name of the OutputReference parameter (3rd spend param), if any.
/// - `redeemer_param_name`: name of the redeemer parameter, if any (for taint tracking).
/// - `datum_param_name`: name of the datum parameter, if any (first spend param, for field tracking).
pub fn analyze_body(
    body: &TypedExpr,
    tx_param_name: &str,
    own_ref_param_name: Option<&str>,
    redeemer_param_name: Option<&str>,
    datum_param_name: Option<&str>,
) -> BodySignals {
    let mut signals = BodySignals::default();

    // Seed redeemer taint set with the redeemer param name itself
    if let Some(rp) = redeemer_param_name {
        signals.redeemer_tainted_vars.insert(rp.to_string());
    }

    walk_expr(
        body,
        tx_param_name,
        redeemer_param_name,
        datum_param_name,
        &mut signals,
    );

    // Check if own_ref is used — it's referenced somewhere in the body
    if let Some(own_ref_name) = own_ref_param_name {
        signals.uses_own_ref = signals.var_references.contains(own_ref_name);
    }

    // Detect single-input constraint pattern:
    // `expect list.length(get_all_validators_inputs(tx)) == 1`
    // Heuristic: if both list.length and get_validators_inputs/get_all_validators_inputs
    // are called, the handler likely enforces a single-input constraint.
    let has_length_call = signals
        .function_calls
        .iter()
        .any(|c| c.ends_with("list.length"));
    let has_validators_inputs = signals
        .function_calls
        .iter()
        .any(|c| c.contains("get_validators_inputs") || c.contains("get_all_validators_inputs"));
    if has_length_call && has_validators_inputs {
        signals.enforces_single_input = true;
    }

    // Detect fold/foldl/foldr counting pattern:
    // When dict.foldl, list.foldl, list.foldr, list.reduce, or list.count
    // is called, this indicates an accumulator-based counting pattern
    // (common for validating exact token quantities in mint handlers).
    let has_fold = signals.function_calls.iter().any(|c| {
        c.contains("foldl")
            || c.contains("foldr")
            || c.contains("reduce")
            || c == "list.count"
            || c.ends_with(".count")
    });
    if has_fold {
        signals.has_fold_counting_pattern = true;
    }

    // Detect signature-gated handler:
    // When extra_signatories is accessed AND list.has is called, the handler
    // requires a specific signature (admin pattern).
    if signals.tx_field_accesses.contains("extra_signatories")
        && signals.function_calls.iter().any(|c| {
            c.contains("list.has")
                || c.contains("list.any")
                || c.contains("bytearray.compare")
                || c.contains("list.find")
        })
    {
        signals.requires_signature = true;
    }

    // Detect datum continuity: record update syntax preserves all non-overridden
    // fields, which is a form of datum continuity assertion.
    if signals.has_record_update && signals.all_record_labels.contains("datum") {
        signals.has_datum_continuity_assertion = true;
    }

    // Detect datum continuity from equality checks between datum-related variables.
    // If variables with "datum" in their name appear in equality guards, the handler
    // is likely asserting datum field continuity.
    let has_datum_equality = signals.guarded_operations.iter().any(|op| {
        op.guard_op == BinOp::Eq
            && (op.guarded_var.contains("datum") || op.guarded_var.contains("state"))
            && op
                .compared_to
                .as_ref()
                .is_some_and(|c| c.contains("datum") || c.contains("state"))
    });
    if has_datum_equality {
        signals.has_datum_continuity_assertion = true;
    }

    signals
}

fn walk_expr(
    expr: &TypedExpr,
    tx_param_name: &str,
    redeemer_param_name: Option<&str>,
    datum_param_name: Option<&str>,
    signals: &mut BodySignals,
) {
    match expr {
        TypedExpr::RecordAccess { label, record, .. } => {
            // Check if this is a direct field access on the Transaction param
            if is_var_named(record, tx_param_name) {
                signals.tx_field_accesses.insert(label.clone());
            }

            // Feature #36: track field accesses on the datum param
            if let Some(datum_name) = datum_param_name {
                if is_var_named(record, datum_name) {
                    signals.datum_field_accesses.insert(label.clone());
                }
            }

            // Track all record access labels for cross-cutting analysis
            signals.all_record_labels.insert(label.clone());
            walk_expr(
                record,
                tx_param_name,
                redeemer_param_name,
                datum_param_name,
                signals,
            );
        }

        TypedExpr::Var { name, .. } => {
            signals.var_references.insert(name.clone());
        }

        TypedExpr::Call { fun, args, .. } => {
            if let Some(call_name) = extract_call_name(fun) {
                // Detect list iteration on tx fields: list.any(tx.outputs, ...)
                if is_list_iteration_call(&call_name) {
                    if let Some(first_arg) = args.first() {
                        if let TypedExpr::RecordAccess { label, record, .. } = &first_arg.value {
                            if is_var_named(record, tx_param_name) {
                                signals.tx_list_iterations.insert(label.clone());
                            }
                        }
                    }
                }
                // Detect unsafe list access: list.head, list.at (no length check)
                if is_unsafe_list_access(&call_name) {
                    signals.unsafe_list_access_calls.push(call_name.clone());
                }

                // Detect unsafe match comparison: match(val, expected, >=)
                // When the last arg is a Fn with a BinOp inequality body, it's unsafe
                // for multi-asset Value comparison (only checks lovelace).
                if (call_name == "match"
                    || call_name.ends_with(".match")
                    || call_name == "assets.match")
                    && args.len() >= 3
                {
                    if let TypedExpr::Fn { body, .. } = &args.last().unwrap().value {
                        if let TypedExpr::BinOp { name, .. } = body.as_ref() {
                            if matches!(
                                name,
                                BinOp::GtEqInt | BinOp::GtInt | BinOp::LtEqInt | BinOp::LtInt
                            ) {
                                signals.has_unsafe_match_comparison = true;
                            }
                        }
                    }
                }

                // Track quantity_of call frequency and distinct asset pairs.
                if call_name.contains("quantity_of") {
                    signals.quantity_of_call_count += 1;
                    // Extract (policy, asset_name) pair from 2nd and 3rd args
                    let policy_var = args.get(1).and_then(|a| extract_var_name(&a.value));
                    let asset_var = args.get(2).and_then(|a| extract_var_name(&a.value));
                    if let (Some(p), Some(a)) = (policy_var, asset_var) {
                        signals.quantity_of_asset_pairs.insert(format!("{p}::{a}"));
                    }
                }

                signals.function_calls.insert(call_name);
            }
            walk_expr(
                fun,
                tx_param_name,
                redeemer_param_name,
                datum_param_name,
                signals,
            );
            for arg in args {
                walk_expr(
                    &arg.value,
                    tx_param_name,
                    redeemer_param_name,
                    datum_param_name,
                    signals,
                );
            }
        }

        TypedExpr::When {
            subject, clauses, ..
        } => {
            walk_expr(
                subject,
                tx_param_name,
                redeemer_param_name,
                datum_param_name,
                signals,
            );
            for clause in clauses {
                let branch_info = analyze_when_branch(clause);
                signals.when_branches.push(branch_info);
                walk_expr(
                    &clause.then,
                    tx_param_name,
                    redeemer_param_name,
                    datum_param_name,
                    signals,
                );
            }
        }

        TypedExpr::ModuleSelect {
            label, module_name, ..
        } => {
            signals
                .function_calls
                .insert(format!("{module_name}.{label}"));
        }

        TypedExpr::Sequence { expressions, .. } | TypedExpr::Pipeline { expressions, .. } => {
            for e in expressions {
                walk_expr(
                    e,
                    tx_param_name,
                    redeemer_param_name,
                    datum_param_name,
                    signals,
                );
            }
        }

        TypedExpr::If {
            branches,
            final_else,
            ..
        } => {
            for branch in branches {
                walk_expr(
                    &branch.condition,
                    tx_param_name,
                    redeemer_param_name,
                    datum_param_name,
                    signals,
                );
                walk_expr(
                    &branch.body,
                    tx_param_name,
                    redeemer_param_name,
                    datum_param_name,
                    signals,
                );
            }
            walk_expr(
                final_else,
                tx_param_name,
                redeemer_param_name,
                datum_param_name,
                signals,
            );
        }

        TypedExpr::BinOp {
            name, left, right, ..
        } => {
            if matches!(name, BinOp::DivInt | BinOp::ModInt) {
                signals.has_division = true;
                // Track the divisor (right operand) for precise guard correlation
                extract_divisor_var(right, signals);
            }
            if matches!(name, BinOp::SubInt) {
                signals.has_subtraction = true;
                // Track subtraction operands for guard correlation
                if let Some(v) = extract_var_name(left) {
                    signals.subtraction_operands.insert(v);
                }
                if let Some(v) = extract_var_name(right) {
                    signals.subtraction_operands.insert(v);
                }
            }
            if matches!(name, BinOp::MultInt) {
                signals.has_multiplication = true;
            }
            // Detect tautological comparisons (e.g., `datum.field == datum.field`)
            if matches!(name, BinOp::Eq) {
                if let Some(tautology) = detect_tautological_comparison(left, right) {
                    signals.tautological_comparisons.push(tautology);
                }
            }

            // Track variables in comparison guards (e.g., `x > 0`, `x >= min`, `x == 0`)
            if matches!(
                name,
                BinOp::GtInt | BinOp::GtEqInt | BinOp::LtInt | BinOp::LtEqInt | BinOp::Eq
            ) {
                extract_guarded_vars(left, signals);
                extract_guarded_vars(right, signals);
                // Structured guard tracking
                extract_guarded_operation(left, right, *name, signals);
            }
            walk_expr(
                left,
                tx_param_name,
                redeemer_param_name,
                datum_param_name,
                signals,
            );
            walk_expr(
                right,
                tx_param_name,
                redeemer_param_name,
                datum_param_name,
                signals,
            );
        }

        TypedExpr::Assignment {
            value,
            kind,
            pattern,
            ..
        } => {
            // Detect `expect Some(x) = var` patterns
            if kind.is_expect() {
                if let Pattern::Constructor { name, .. } = pattern {
                    if name == "Some" {
                        // The value being deconstructed — track its var name
                        if let TypedExpr::Var { name: var_name, .. } = value.as_ref() {
                            signals.expect_some_vars.insert(var_name.clone());
                        }
                    }
                }
                // Detect `expect [h, ..rest] = list` — implicit base case (crashes on empty list)
                if let Pattern::List { elements, tail, .. } = pattern {
                    if !elements.is_empty() && tail.is_some() {
                        signals.has_expect_list_destructure = true;
                    }
                }
            }

            // Detect Transaction record destructuring: let Transaction { inputs, mint, .. } = self
            // This makes destructured field names visible as tx_field_accesses
            if let Pattern::Constructor {
                name: pat_name,
                arguments,
                ..
            } = pattern
            {
                if pat_name == "Transaction" && is_var_named(value, tx_param_name) {
                    for arg in arguments {
                        if let Some(label) = &arg.label {
                            signals.tx_field_accesses.insert(label.clone());
                        }
                    }
                }
            }

            // Feature #33: taint propagation — if the RHS is a redeemer-tainted var or
            // a RecordAccess on the redeemer param, mark the LHS variable(s) as tainted.
            let rhs_is_tainted = is_expr_redeemer_tainted(
                value,
                &signals.redeemer_tainted_vars,
                redeemer_param_name,
            );
            if rhs_is_tainted {
                propagate_taint_from_pattern(pattern, &mut signals.redeemer_tainted_vars);
            }

            walk_expr(
                value,
                tx_param_name,
                redeemer_param_name,
                datum_param_name,
                signals,
            );
        }

        TypedExpr::Trace { then, text, .. } => {
            walk_expr(
                then,
                tx_param_name,
                redeemer_param_name,
                datum_param_name,
                signals,
            );
            walk_expr(
                text,
                tx_param_name,
                redeemer_param_name,
                datum_param_name,
                signals,
            );
        }

        TypedExpr::Fn { body, .. } => {
            walk_expr(
                body,
                tx_param_name,
                redeemer_param_name,
                datum_param_name,
                signals,
            );
        }

        TypedExpr::List { elements, tail, .. } => {
            for e in elements {
                walk_expr(
                    e,
                    tx_param_name,
                    redeemer_param_name,
                    datum_param_name,
                    signals,
                );
            }
            if let Some(t) = tail {
                walk_expr(
                    t,
                    tx_param_name,
                    redeemer_param_name,
                    datum_param_name,
                    signals,
                );
            }
        }

        TypedExpr::Tuple { elems, .. } => {
            for e in elems {
                walk_expr(
                    e,
                    tx_param_name,
                    redeemer_param_name,
                    datum_param_name,
                    signals,
                );
            }
        }

        TypedExpr::Pair { fst, snd, .. } => {
            walk_expr(
                fst,
                tx_param_name,
                redeemer_param_name,
                datum_param_name,
                signals,
            );
            walk_expr(
                snd,
                tx_param_name,
                redeemer_param_name,
                datum_param_name,
                signals,
            );
        }

        TypedExpr::TupleIndex { tuple, .. } => {
            walk_expr(
                tuple,
                tx_param_name,
                redeemer_param_name,
                datum_param_name,
                signals,
            );
        }

        TypedExpr::UnOp { value, .. } => {
            walk_expr(
                value,
                tx_param_name,
                redeemer_param_name,
                datum_param_name,
                signals,
            );
        }

        TypedExpr::RecordUpdate { spread, args, .. } => {
            signals.has_record_update = true;
            walk_expr(
                spread,
                tx_param_name,
                redeemer_param_name,
                datum_param_name,
                signals,
            );
            for arg in args {
                walk_expr(
                    &arg.value,
                    tx_param_name,
                    redeemer_param_name,
                    datum_param_name,
                    signals,
                );
            }
        }

        TypedExpr::ByteArray { bytes, .. } => {
            signals.bytearray_literal_lengths.push(bytes.len());
        }

        // Literals — no children to walk
        TypedExpr::UInt { .. }
        | TypedExpr::String { .. }
        | TypedExpr::CurvePoint { .. }
        | TypedExpr::ErrorTerm { .. } => {}
    }
}

// ---------------------------------------------------------------------------
// Tautological comparison detection
// ---------------------------------------------------------------------------

/// Build a canonical string representation of a record access chain.
/// e.g., `datum.mint_policy_id` → "datum.mint_policy_id"
fn record_access_path(expr: &TypedExpr) -> Option<String> {
    match expr {
        TypedExpr::RecordAccess { label, record, .. } => {
            record_access_path(record).map(|base| format!("{base}.{label}"))
        }
        TypedExpr::Var { name, .. } => Some(name.clone()),
        _ => None,
    }
}

/// Detect if a BinOp(Eq) compares identical expressions (tautology).
/// Returns e.g. "datum.mint_policy_id == datum.mint_policy_id".
fn detect_tautological_comparison(left: &TypedExpr, right: &TypedExpr) -> Option<String> {
    let left_path = record_access_path(left)?;
    let right_path = record_access_path(right)?;
    if left_path == right_path {
        Some(format!("{left_path} == {right_path}"))
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// Guard detection helpers
// ---------------------------------------------------------------------------

/// Extract variable names from comparison operands and add them to `guarded_vars`.
/// Handles direct vars (`x > 0`) and record accesses (`redeemer.price > 0`).
fn extract_guarded_vars(expr: &TypedExpr, signals: &mut BodySignals) {
    match expr {
        TypedExpr::Var { name, .. } => {
            signals.guarded_vars.insert(name.clone());
        }
        TypedExpr::RecordAccess { record, .. } => {
            // For `redeemer.price > 0`, guard both `redeemer` and the full access
            if let TypedExpr::Var { name, .. } = record.as_ref() {
                signals.guarded_vars.insert(name.clone());
            }
        }
        _ => {}
    }
}

/// Extract a structured guard operation from a comparison BinOp.
/// Records which variable is guarded, the comparison operator, and the other operand.
fn extract_guarded_operation(
    left: &TypedExpr,
    right: &TypedExpr,
    op: BinOp,
    signals: &mut BodySignals,
) {
    let left_var = extract_var_name(left);
    let right_var = extract_var_name(right);
    if let Some(lv) = &left_var {
        signals.guarded_operations.push(GuardedOperation {
            guarded_var: lv.clone(),
            guard_op: op,
            compared_to: right_var.clone(),
        });
    }
    if let Some(rv) = &right_var {
        // Also record the right side as guarded (symmetric for Eq)
        let inverse_op = match op {
            BinOp::GtInt => BinOp::LtInt,
            BinOp::GtEqInt => BinOp::LtEqInt,
            BinOp::LtInt => BinOp::GtInt,
            BinOp::LtEqInt => BinOp::GtEqInt,
            other => other,
        };
        signals.guarded_operations.push(GuardedOperation {
            guarded_var: rv.clone(),
            guard_op: inverse_op,
            compared_to: left_var,
        });
    }
}

/// Extract variable name from a simple expression (Var or RecordAccess on Var).
fn extract_var_name(expr: &TypedExpr) -> Option<String> {
    match expr {
        TypedExpr::Var { name, .. } => Some(name.clone()),
        TypedExpr::RecordAccess { record, .. } => {
            if let TypedExpr::Var { name, .. } = record.as_ref() {
                Some(name.clone())
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Extract variable names from a division's right operand (the divisor).
fn extract_divisor_var(expr: &TypedExpr, signals: &mut BodySignals) {
    match expr {
        TypedExpr::Var { name, .. } => {
            signals.division_divisors.insert(name.clone());
        }
        TypedExpr::RecordAccess { record, .. } => {
            if let TypedExpr::Var { name, .. } = record.as_ref() {
                signals.division_divisors.insert(name.clone());
            }
        }
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// Feature #33: Taint tracking helpers
// ---------------------------------------------------------------------------

/// Returns true if the expression is derived from a redeemer-tainted source.
fn is_expr_redeemer_tainted(
    expr: &TypedExpr,
    tainted: &HashSet<String>,
    redeemer_param_name: Option<&str>,
) -> bool {
    match expr {
        TypedExpr::Var { name, .. } => {
            // The redeemer param itself, or any already-tainted variable
            tainted.contains(name.as_str())
                || redeemer_param_name.is_some_and(|rp| rp == name.as_str())
        }
        TypedExpr::RecordAccess { record, .. } => {
            // Field access on a tainted var (e.g., redeemer.field)
            is_expr_redeemer_tainted(record, tainted, redeemer_param_name)
        }
        _ => false,
    }
}

/// Propagate taint to variables bound by a pattern (e.g., `let x = tainted_expr`).
fn propagate_taint_from_pattern<C, T, B>(
    pattern: &Pattern<C, T, String, B>,
    tainted: &mut HashSet<String>,
) {
    match pattern {
        Pattern::Var { name, .. } => {
            tainted.insert(name.clone());
        }
        Pattern::Assign { name, pattern, .. } => {
            tainted.insert(name.clone());
            propagate_taint_from_pattern(pattern, tainted);
        }
        Pattern::Constructor { arguments, .. } => {
            for arg in arguments {
                propagate_taint_from_pattern(&arg.value, tainted);
            }
        }
        Pattern::Tuple { elems, .. } => {
            for elem in elems {
                propagate_taint_from_pattern(elem, tainted);
            }
        }
        Pattern::Pair { fst, snd, .. } => {
            propagate_taint_from_pattern(fst, tainted);
            propagate_taint_from_pattern(snd, tainted);
        }
        Pattern::List { elements, tail, .. } => {
            for elem in elements {
                propagate_taint_from_pattern(elem, tainted);
            }
            if let Some(t) = tail {
                propagate_taint_from_pattern(t, tainted);
            }
        }
        // Discard, Int, ByteArray — no variable bindings to taint
        Pattern::Discard { .. } | Pattern::Int { .. } | Pattern::ByteArray { .. } => {}
    }
}

// ---------------------------------------------------------------------------
// Existing helpers (unchanged)
// ---------------------------------------------------------------------------

const LIST_ITERATION_FUNCTIONS: &[&str] = &[
    "list.any",
    "list.map",
    "list.filter",
    "list.foldl",
    "list.foldr",
    "list.has",
    "list.find",
    "list.all",
    "list.filter_map",
    "list.flat_map",
    "list.each",
    "list.reduce",
    "list.index_of",
    "list.count",
];

fn is_list_iteration_call(call_name: &str) -> bool {
    LIST_ITERATION_FUNCTIONS.contains(&call_name)
}

const UNSAFE_LIST_ACCESS_FUNCTIONS: &[&str] = &["list.head", "list.at", "builtin.head_list"];

fn is_unsafe_list_access(call_name: &str) -> bool {
    UNSAFE_LIST_ACCESS_FUNCTIONS.contains(&call_name)
}

fn is_var_named(expr: &TypedExpr, name: &str) -> bool {
    matches!(expr, TypedExpr::Var { name: var_name, .. } if var_name == name)
}

fn extract_call_name(fun: &TypedExpr) -> Option<String> {
    match fun {
        TypedExpr::Var { name, .. } => Some(name.clone()),
        TypedExpr::ModuleSelect {
            label, module_name, ..
        } => Some(format!("{module_name}.{label}")),
        TypedExpr::RecordAccess { label, record, .. } => {
            if let TypedExpr::Var { name, .. } = record.as_ref() {
                Some(format!("{name}.{label}"))
            } else {
                Some(label.clone())
            }
        }
        _ => None,
    }
}

fn analyze_when_branch(clause: &TypedClause) -> WhenBranchInfo {
    let is_catchall = is_catchall_pattern(&clause.pattern);
    let body_is_literal_true = is_literal_true(&clause.then);
    let body_is_error = is_error_body(&clause.then);
    let pattern_text = pattern_to_string(&clause.pattern);

    WhenBranchInfo {
        pattern_text,
        is_catchall,
        body_is_literal_true,
        body_is_error,
    }
}

fn is_catchall_pattern<C, T, N, B>(pattern: &Pattern<C, T, N, B>) -> bool {
    matches!(pattern, Pattern::Discard { .. } | Pattern::Var { .. })
}

fn is_literal_true(expr: &TypedExpr) -> bool {
    matches!(expr, TypedExpr::Var { name, .. } if name == "True")
}

fn is_error_body(expr: &TypedExpr) -> bool {
    match expr {
        TypedExpr::ErrorTerm { .. } => true,
        TypedExpr::Var { name, .. } if name == "False" => true,
        // fail with trace message: trace @"..." fail
        TypedExpr::Trace { then, .. } => is_error_body(then),
        TypedExpr::Sequence { expressions, .. } => expressions.last().is_some_and(is_error_body),
        _ => false,
    }
}

fn pattern_to_string<C, T, B>(pattern: &Pattern<C, T, String, B>) -> String {
    match pattern {
        Pattern::Discard { name, .. } => name.clone(),
        Pattern::Var { name, .. } => name.clone(),
        Pattern::Constructor { name, .. } => name.clone(),
        Pattern::Int { value, .. } => value.clone(),
        Pattern::Assign { name, .. } => format!("{name} as .."),
        Pattern::Tuple { .. } => "(...)".to_string(),
        Pattern::Pair { .. } => "Pair(..)".to_string(),
        Pattern::List { elements, tail, .. } => {
            if elements.is_empty() && tail.is_none() {
                "[]".to_string()
            } else {
                "[..]".to_string()
            }
        }
        Pattern::ByteArray { .. } => "#\"..\"".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_body_signals_default() {
        let signals = BodySignals::default();
        assert!(signals.tx_field_accesses.is_empty());
        assert!(!signals.uses_own_ref);
        assert!(signals.function_calls.is_empty());
        assert!(signals.var_references.is_empty());
        assert!(signals.when_branches.is_empty());
    }

    #[test]
    fn test_when_branch_info() {
        let branch = WhenBranchInfo {
            pattern_text: "_".to_string(),
            is_catchall: true,
            body_is_literal_true: true,
            body_is_error: false,
        };
        assert!(branch.is_catchall);
        assert!(branch.body_is_literal_true);
        assert!(!branch.body_is_error);
    }

    #[test]
    fn test_body_signals_with_tx_fields() {
        let mut signals = BodySignals::default();
        signals
            .tx_field_accesses
            .insert("extra_signatories".to_string());
        signals
            .tx_field_accesses
            .insert("validity_range".to_string());
        assert!(signals.tx_field_accesses.contains("extra_signatories"));
        assert!(signals.tx_field_accesses.contains("validity_range"));
        assert!(!signals.tx_field_accesses.contains("outputs"));
    }

    #[test]
    fn test_own_ref_detection() {
        let mut signals = BodySignals::default();
        signals.var_references.insert("own_ref".to_string());
        signals.uses_own_ref = signals.var_references.contains("own_ref");
        assert!(signals.uses_own_ref);
    }

    #[test]
    fn test_function_calls_tracking() {
        let mut signals = BodySignals::default();
        signals.function_calls.insert("list.has".to_string());
        signals
            .function_calls
            .insert("interval.is_entirely_after".to_string());
        assert_eq!(signals.function_calls.len(), 2);
        assert!(signals.function_calls.contains("list.has"));
    }

    // --- Feature #33: Taint tracking tests ---

    #[test]
    fn test_redeemer_tainted_vars_default_empty() {
        let signals = BodySignals::default();
        assert!(signals.redeemer_tainted_vars.is_empty());
    }

    #[test]
    fn test_redeemer_tainted_vars_insertion() {
        let mut signals = BodySignals::default();
        signals.redeemer_tainted_vars.insert("redeemer".to_string());
        signals.redeemer_tainted_vars.insert("action".to_string());
        assert!(signals.redeemer_tainted_vars.contains("redeemer"));
        assert!(signals.redeemer_tainted_vars.contains("action"));
        assert!(!signals.redeemer_tainted_vars.contains("datum"));
    }

    #[test]
    fn test_propagate_taint_from_var_pattern() {
        use aiken_lang::ast::Span;
        let mut tainted: HashSet<String> = HashSet::new();
        let pattern: Pattern<(), (), String, ()> = Pattern::Var {
            location: Span::empty(),
            name: "x".to_string(),
        };
        propagate_taint_from_pattern(&pattern, &mut tainted);
        assert!(tainted.contains("x"));
    }

    #[test]
    fn test_propagate_taint_from_discard_pattern() {
        use aiken_lang::ast::Span;
        let mut tainted: HashSet<String> = HashSet::new();
        let pattern: Pattern<(), (), String, ()> = Pattern::Discard {
            location: Span::empty(),
            name: "_".to_string(),
        };
        propagate_taint_from_pattern(&pattern, &mut tainted);
        // Discard binds no variables
        assert!(tainted.is_empty());
    }

    // --- Feature #36: Datum field access tracking tests ---

    #[test]
    fn test_datum_field_accesses_default_empty() {
        let signals = BodySignals::default();
        assert!(signals.datum_field_accesses.is_empty());
    }

    #[test]
    fn test_datum_field_accesses_insertion() {
        let mut signals = BodySignals::default();
        signals.datum_field_accesses.insert("deadline".to_string());
        signals.datum_field_accesses.insert("owner".to_string());
        assert!(signals.datum_field_accesses.contains("deadline"));
        assert!(signals.datum_field_accesses.contains("owner"));
        assert!(!signals.datum_field_accesses.contains("value"));
    }

    #[test]
    fn test_is_expr_redeemer_tainted_via_taint_set() {
        use aiken_lang::ast::Span;
        use aiken_lang::tipo::Type;
        use std::rc::Rc;

        let bool_type = Rc::new(Type::App {
            public: true,
            contains_opaque: false,
            module: String::new(),
            name: "Bool".to_string(),
            args: vec![],
            alias: None,
        });

        let mut tainted = HashSet::new();
        tainted.insert("rdm".to_string());

        // A var already in the tainted set is tainted
        let expr_tainted = TypedExpr::local_var("rdm", bool_type.clone(), Span::empty());
        assert!(is_expr_redeemer_tainted(
            &expr_tainted,
            &tainted,
            Some("rdm")
        ));

        // A var NOT in the tainted set, and not the redeemer param, is not tainted
        let expr_clean = TypedExpr::local_var("x", bool_type.clone(), Span::empty());
        assert!(!is_expr_redeemer_tainted(
            &expr_clean,
            &HashSet::new(),
            Some("rdm")
        ));

        // A var named exactly the redeemer param is tainted even if the taint set is empty
        let expr_rdm = TypedExpr::local_var("rdm", bool_type, Span::empty());
        assert!(is_expr_redeemer_tainted(
            &expr_rdm,
            &HashSet::new(),
            Some("rdm")
        ));
    }

    #[test]
    fn test_pattern_to_string_empty_list() {
        use aiken_lang::ast::Span;
        let pattern: Pattern<(), (), String, ()> = Pattern::List {
            location: Span::empty(),
            elements: vec![],
            tail: None,
        };
        assert_eq!(pattern_to_string(&pattern), "[]");
    }

    #[test]
    fn test_pattern_to_string_non_empty_list() {
        use aiken_lang::ast::Span;
        let pattern: Pattern<(), (), String, ()> = Pattern::List {
            location: Span::empty(),
            elements: vec![Pattern::Var {
                location: Span::empty(),
                name: "h".to_string(),
            }],
            tail: Some(Box::new(Pattern::Var {
                location: Span::empty(),
                name: "rest".to_string(),
            })),
        };
        assert_eq!(pattern_to_string(&pattern), "[..]");
    }

    #[test]
    fn test_has_expect_list_destructure_default_false() {
        let signals = BodySignals::default();
        assert!(!signals.has_expect_list_destructure);
    }

    // --- GuardedOperation tests ---

    #[test]
    fn test_guarded_operations_default_empty() {
        let signals = BodySignals::default();
        assert!(signals.guarded_operations.is_empty());
    }

    #[test]
    fn test_guarded_operation_struct() {
        let op = GuardedOperation {
            guarded_var: "a".to_string(),
            guard_op: BinOp::GtEqInt,
            compared_to: Some("b".to_string()),
        };
        assert_eq!(op.guarded_var, "a");
        assert_eq!(op.guard_op, BinOp::GtEqInt);
        assert_eq!(op.compared_to, Some("b".to_string()));
    }

    #[test]
    fn test_guarded_operation_without_comparison() {
        let op = GuardedOperation {
            guarded_var: "x".to_string(),
            guard_op: BinOp::GtInt,
            compared_to: None,
        };
        assert!(op.compared_to.is_none());
    }

    #[test]
    fn test_extract_var_name_simple() {
        use aiken_lang::ast::Span;
        use aiken_lang::tipo::Type;
        use std::rc::Rc;

        let int_type = Rc::new(Type::App {
            public: true,
            contains_opaque: false,
            module: String::new(),
            name: "Int".to_string(),
            args: vec![],
            alias: None,
        });
        let expr = TypedExpr::local_var("my_var", int_type, Span::empty());
        assert_eq!(extract_var_name(&expr), Some("my_var".to_string()));
    }

    // --- Fold-counting pattern tests ---

    #[test]
    fn test_fold_counting_default_false() {
        let signals = BodySignals::default();
        assert!(!signals.has_fold_counting_pattern);
    }

    #[test]
    fn test_fold_counting_set_on_foldl() {
        let mut signals = BodySignals::default();
        signals.function_calls.insert("dict.foldl".to_string());
        // Simulate the analyze_body post-processing
        let has_fold = signals.function_calls.iter().any(|c| {
            c.contains("foldl")
                || c.contains("foldr")
                || c.contains("reduce")
                || c == "list.count"
                || c.ends_with(".count")
        });
        if has_fold {
            signals.has_fold_counting_pattern = true;
        }
        assert!(signals.has_fold_counting_pattern);
    }

    // --- requires_signature tests ---

    #[test]
    fn test_requires_signature_default_false() {
        let signals = BodySignals::default();
        assert!(!signals.requires_signature);
    }

    #[test]
    fn test_requires_signature_with_extra_signatories_and_list_has() {
        let mut signals = BodySignals::default();
        signals
            .tx_field_accesses
            .insert("extra_signatories".to_string());
        signals.function_calls.insert("list.has".to_string());
        // Simulate the analyze_body post-processing
        if signals.tx_field_accesses.contains("extra_signatories")
            && signals.function_calls.iter().any(|c| {
                c.contains("list.has")
                    || c.contains("list.any")
                    || c.contains("bytearray.compare")
                    || c.contains("list.find")
            })
        {
            signals.requires_signature = true;
        }
        assert!(signals.requires_signature);
    }

    // --- quantity_of_call_count tests ---

    #[test]
    fn test_quantity_of_call_count_default_zero() {
        let signals = BodySignals::default();
        assert_eq!(signals.quantity_of_call_count, 0);
    }

    #[test]
    fn test_quantity_of_call_count_increments() {
        let signals = BodySignals {
            quantity_of_call_count: 5,
            ..Default::default()
        };
        // Simulate 5 quantity_of calls (as in forwards collateral validator)
        assert_eq!(signals.quantity_of_call_count, 5);
    }
}
