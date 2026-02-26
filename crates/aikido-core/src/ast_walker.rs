use std::collections::HashSet;
use std::rc::Rc;

use aiken_lang::ast::{
    ArgName, DataType, Definition, RecordConstructor, RecordConstructorArg, TypeAlias, TypedArg,
};
use aiken_lang::expr::TypedExpr;
use aiken_lang::tipo::{Type, TypeVar};
use aiken_project::module::CheckedModule;

use crate::body_analysis::{analyze_body, BodySignals};

// Concrete typed aliases for the generic AST types
type TypedValidator = aiken_lang::ast::Validator<Rc<Type>, TypedArg, TypedExpr>;
type TypedFunction = aiken_lang::ast::Function<Rc<Type>, TypedExpr, TypedArg>;
type TypedModuleConstant = aiken_lang::ast::ModuleConstant<TypedExpr>;

#[derive(Debug, Clone)]
pub struct ModuleInfo {
    pub name: String,
    pub path: String,
    pub kind: ModuleKind,
    pub validators: Vec<ValidatorInfo>,
    pub data_types: Vec<DataTypeInfo>,
    pub functions: Vec<FunctionInfo>,
    pub constants: Vec<ConstantInfo>,
    pub type_aliases: Vec<TypeAliasInfo>,
    pub test_count: usize,
    pub source_code: Option<String>,
    /// Names of test functions defined in this module (from `Definition::Test`).
    /// Used by dead-code-path detector to avoid flagging test helpers as unreachable.
    pub test_function_names: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ModuleKind {
    Lib,
    Validator,
}

// ---------------------------------------------------------------------------
// Feature #2: Cross-handler analysis — ValidatorSignals summary
// ---------------------------------------------------------------------------

/// Aggregated signals across all handlers in a single validator.
/// Enables cross-handler correlation: e.g., if spend and mint handlers in the
/// same validator share a vulnerability pattern.
#[derive(Debug, Clone, Default)]
pub struct ValidatorSignals {
    /// Names of all handlers (e.g., ["spend", "mint"])
    pub handler_names: Vec<String>,
    /// Union of all tx field accesses across every handler
    pub combined_tx_accesses: HashSet<String>,
    /// True if at least one handler is named "spend"
    pub has_spend: bool,
    /// True if at least one handler is named "mint"
    pub has_mint: bool,
}

#[derive(Debug, Clone)]
pub struct ValidatorInfo {
    pub name: String,
    pub params: Vec<ParamInfo>,
    pub handlers: Vec<HandlerInfo>,
    /// Feature #2: cross-handler signal summary (populated after body analysis).
    pub summary: Option<ValidatorSignals>,
}

#[derive(Debug, Clone)]
pub struct HandlerInfo {
    pub name: String,
    pub params: Vec<ParamInfo>,
    pub return_type: String,
    pub location: Option<(usize, usize)>,
    pub body_signals: BodySignals,
}

#[derive(Debug, Clone)]
pub struct ParamInfo {
    pub name: String,
    pub type_name: String,
}

#[derive(Debug, Clone)]
pub struct DataTypeInfo {
    pub name: String,
    pub public: bool,
    pub constructors: Vec<ConstructorInfo>,
}

#[derive(Debug, Clone)]
pub struct ConstructorInfo {
    pub name: String,
    pub fields: Vec<FieldInfo>,
}

#[derive(Debug, Clone)]
pub struct FieldInfo {
    pub label: Option<String>,
    pub type_name: String,
}

#[derive(Debug, Clone)]
pub struct FunctionInfo {
    pub name: String,
    pub public: bool,
    pub params: Vec<ParamInfo>,
    pub return_type: String,
    /// Body signals extracted from the function body (for interprocedural analysis).
    pub body_signals: Option<BodySignals>,
}

#[derive(Debug, Clone)]
pub struct ConstantInfo {
    pub name: String,
    pub public: bool,
}

#[derive(Debug, Clone)]
pub struct TypeAliasInfo {
    pub name: String,
    pub public: bool,
}

fn generic_id_to_name(id: u64) -> String {
    // Map numeric generic IDs to lowercase letter names: a, b, c, ...
    let idx = (id % 26) as u8;
    let letter = (b'a' + idx) as char;
    letter.to_string()
}

pub fn type_to_string(typ: &Rc<Type>) -> String {
    match typ.as_ref() {
        Type::App {
            name,
            args,
            module,
            alias,
            ..
        } => {
            // If there's a type alias, prefer its name for readability
            if let Some(alias_ann) = alias {
                let alias_name = if let Some(ref m) = alias_ann.module {
                    format!("{m}.{}", alias_ann.alias)
                } else {
                    alias_ann.alias.clone()
                };
                return alias_name;
            }

            let base = if module.is_empty() {
                name.clone()
            } else {
                format!("{module}.{name}")
            };

            if args.is_empty() {
                base
            } else {
                let arg_strs: Vec<String> = args.iter().map(type_to_string).collect();
                format!("{base}<{}>", arg_strs.join(", "))
            }
        }
        Type::Fn { args, ret, .. } => {
            let arg_strs: Vec<String> = args.iter().map(type_to_string).collect();
            let ret_str = type_to_string(ret);
            format!("fn({}) -> {ret_str}", arg_strs.join(", "))
        }
        Type::Var { tipo, .. } => {
            let var = tipo.borrow();
            match &*var {
                TypeVar::Link { tipo } => type_to_string(tipo),
                TypeVar::Generic { id } => generic_id_to_name(*id),
                TypeVar::Unbound { id } => format!("?{id}"),
            }
        }
        Type::Tuple { elems, .. } => {
            let elem_strs: Vec<String> = elems.iter().map(type_to_string).collect();
            format!("({})", elem_strs.join(", "))
        }
        Type::Pair { fst, snd, .. } => {
            format!("Pair<{}, {}>", type_to_string(fst), type_to_string(snd))
        }
    }
}

fn extract_arg_name(arg_name: &ArgName) -> String {
    match arg_name {
        ArgName::Named { name, .. } => name.clone(),
        ArgName::Discarded { name, .. } => format!("_{name}"),
    }
}

fn extract_param(arg: &TypedArg) -> ParamInfo {
    ParamInfo {
        name: extract_arg_name(&arg.arg_name),
        type_name: type_to_string(&arg.tipo),
    }
}

fn extract_validator(v: &TypedValidator) -> ValidatorInfo {
    let params: Vec<ParamInfo> = v.params.iter().map(extract_param).collect();

    let mut handlers: Vec<HandlerInfo> = v
        .handlers
        .iter()
        .map(|h| {
            let handler_params: Vec<ParamInfo> = h.arguments.iter().map(extract_param).collect();

            // The last param is the Transaction param (usually named "self")
            let tx_param_name = handler_params
                .last()
                .map(|p| p.name.as_str())
                .unwrap_or("self");

            // For spend handlers: params are (datum, redeemer, own_ref, tx)
            // Indices: 0 = datum, 1 = redeemer, 2 = own_ref, 3 = tx (last)
            let own_ref_param_name = if h.name == "spend" && handler_params.len() >= 3 {
                let name = &handler_params[2].name;
                // If prefixed with _, it's explicitly discarded — not used
                if name.starts_with('_') {
                    None
                } else {
                    Some(name.as_str())
                }
            } else {
                None
            };

            // Feature #33: redeemer param (index 1 for spend; index 0 for mint/other with 2+ params)
            let redeemer_param_name: Option<&str> =
                if h.name == "spend" && handler_params.len() >= 2 {
                    Some(handler_params[1].name.as_str())
                } else if h.name != "spend" && handler_params.len() >= 2 {
                    // For mint/withdraw/etc: first param is redeemer, last is tx
                    Some(handler_params[0].name.as_str())
                } else {
                    None
                };

            // Feature #36: datum param (index 0 for spend)
            let datum_param_name: Option<&str> = if h.name == "spend" && !handler_params.is_empty()
            {
                Some(handler_params[0].name.as_str())
            } else {
                None
            };

            let body_signals = analyze_body(
                &h.body,
                tx_param_name,
                own_ref_param_name,
                redeemer_param_name,
                datum_param_name,
            );

            HandlerInfo {
                name: h.name.clone(),
                params: handler_params,
                return_type: type_to_string(&h.return_type),
                location: Some((h.location.start, h.location.end)),
                body_signals,
            }
        })
        .collect();

    // Also extract the fallback (else) handler if it contains real logic.
    // Aiken validators always have a fallback, but the default is just `fail`.
    // Validators like SundaeSwap's `manage` put ALL logic in the else handler.
    {
        let fb = &v.fallback;
        let fb_params: Vec<ParamInfo> = fb.arguments.iter().map(extract_param).collect();
        let has_real_logic = !fb_params.is_empty() && !fb_params[0].name.starts_with('_');

        if has_real_logic {
            // The else handler's single param is ScriptContext — treat as tx param
            let tx_param_name = fb_params.first().map(|p| p.name.as_str()).unwrap_or("ctx");

            let body_signals = analyze_body(
                &fb.body,
                tx_param_name,
                None, // no own_ref in else handler
                None, // no redeemer in else handler
                None, // no datum in else handler
            );

            handlers.push(HandlerInfo {
                name: "else".to_string(),
                params: fb_params,
                return_type: type_to_string(&fb.return_type),
                location: Some((fb.location.start, fb.location.end)),
                body_signals,
            });
        }
    }

    ValidatorInfo {
        name: v.name.clone(),
        params,
        handlers,
        summary: None, // populated later by cross_handler_analysis()
    }
}

fn extract_data_type(dt: &DataType<Rc<Type>>) -> DataTypeInfo {
    let constructors: Vec<ConstructorInfo> = dt
        .constructors
        .iter()
        .map(|c: &RecordConstructor<Rc<Type>>| {
            let fields: Vec<FieldInfo> = c
                .arguments
                .iter()
                .map(|a: &RecordConstructorArg<Rc<Type>>| FieldInfo {
                    label: a.label.clone(),
                    type_name: type_to_string(&a.tipo),
                })
                .collect();
            ConstructorInfo {
                name: c.name.clone(),
                fields,
            }
        })
        .collect();

    DataTypeInfo {
        name: dt.name.clone(),
        public: dt.public,
        constructors,
    }
}

fn extract_function(f: &TypedFunction) -> FunctionInfo {
    let params: Vec<ParamInfo> = f.arguments.iter().map(extract_param).collect();

    // For interprocedural analysis: find a Transaction-typed param and analyze the body
    let tx_param_name = params
        .iter()
        .find(|p| p.type_name.contains("Transaction"))
        .map(|p| p.name.as_str())
        .unwrap_or("");

    // Always analyze body — even without a Transaction param, we capture function_calls,
    // expect_some_vars, when_branches, etc. for interprocedural analysis.
    let body_signals = Some(analyze_body(&f.body, tx_param_name, None, None, None));

    FunctionInfo {
        name: f.name.clone(),
        public: f.public,
        params,
        return_type: type_to_string(&f.return_type),
        body_signals,
    }
}

fn extract_module_constant(c: &TypedModuleConstant) -> ConstantInfo {
    ConstantInfo {
        name: c.name.clone(),
        public: c.public,
    }
}

fn extract_type_alias(ta: &TypeAlias<Rc<Type>>) -> TypeAliasInfo {
    TypeAliasInfo {
        name: ta.alias.clone(),
        public: ta.public,
    }
}

pub fn extract_module_info(module: &CheckedModule) -> ModuleInfo {
    let mut validators = Vec::new();
    let mut data_types = Vec::new();
    let mut functions = Vec::new();
    let mut constants = Vec::new();
    let mut type_aliases = Vec::new();
    let mut test_count = 0usize;
    let mut test_function_names = Vec::new();

    for def in module.ast.definitions() {
        match def {
            Definition::Validator(v) => validators.push(extract_validator(v)),
            Definition::DataType(dt) => data_types.push(extract_data_type(dt)),
            Definition::Fn(f) => functions.push(extract_function(f)),
            Definition::ModuleConstant(c) => constants.push(extract_module_constant(c)),
            Definition::TypeAlias(ta) => type_aliases.push(extract_type_alias(ta)),
            Definition::Test(t) => {
                test_count += 1;
                test_function_names.push(t.name.clone());
            }
            Definition::Benchmark(_) => {}
            Definition::Use(_) => {}
        }
    }

    let kind = if module.kind.is_validator() {
        ModuleKind::Validator
    } else {
        ModuleKind::Lib
    };

    // Read source code for line-number resolution in findings
    let source_code = std::fs::read_to_string(&module.input_path).ok();

    // Interprocedural analysis: merge function body signals into handler signals.
    // If a handler calls a local function that accesses tx fields, merge those signals.
    merge_function_signals(&functions, &mut validators);

    // Re-evaluate derived signals that depend on merged function_calls.
    // The single-input constraint (enforces_single_input) may only be detectable
    // after helper function calls are merged into the handler's function_calls.
    recompute_derived_signals(&mut validators);

    // Feature #2: Cross-handler analysis — build ValidatorSignals summary per validator.
    cross_handler_analysis(&mut validators);

    ModuleInfo {
        name: module.name.clone(),
        path: module.input_path.display().to_string(),
        kind,
        validators,
        data_types,
        functions,
        constants,
        type_aliases,
        test_count,
        source_code,
        test_function_names,
    }
}

/// Merge body signals from called functions into handler signals (transitive, fixed-point).
///
/// Unlike the previous 1-level merge, this first resolves function→function chains
/// (max 5 rounds) so that if handler calls `check_value` which calls `validate_amount`,
/// `validate_amount`'s signals propagate through `check_value` into the handler.
fn merge_function_signals(functions: &[FunctionInfo], validators: &mut [ValidatorInfo]) {
    // Build map of function name → owned BodySignals (mutable for transitive resolution)
    let mut fn_signals: std::collections::HashMap<String, BodySignals> = functions
        .iter()
        .filter_map(|f| f.body_signals.as_ref().map(|s| (f.name.clone(), s.clone())))
        .collect();

    if fn_signals.is_empty() {
        return;
    }

    // Phase 1: Resolve function→function chains via fixed-point iteration.
    // If function A calls function B, merge B's signals into A.
    // Repeat until no changes (max 5 rounds to avoid infinite loops).
    for _round in 0..5 {
        let mut any_changed = false;

        // Collect all function names to iterate without borrow conflicts
        let fn_names: Vec<String> = fn_signals.keys().cloned().collect();

        for fn_name in &fn_names {
            let callee_names: Vec<String> = {
                let signals = &fn_signals[fn_name];
                signals
                    .function_calls
                    .iter()
                    .filter(|c| !c.contains('.')) // Only local (unqualified) calls
                    .filter(|c| c.as_str() != fn_name.as_str()) // No self-recursion
                    .cloned()
                    .collect()
            };

            for callee in &callee_names {
                if let Some(callee_signals) = fn_signals.get(callee).cloned() {
                    let target = fn_signals.get_mut(fn_name).unwrap();
                    if merge_signals_into(target, &callee_signals) {
                        any_changed = true;
                    }
                }
            }
        }

        if !any_changed {
            break;
        }
    }

    // Phase 2: Merge resolved function signals into handler signals.
    for validator in validators.iter_mut() {
        for handler in &mut validator.handlers {
            let calls: Vec<String> = handler
                .body_signals
                .function_calls
                .iter()
                .cloned()
                .collect();

            for call in &calls {
                // Local function calls have no module prefix (just the name)
                // Module-qualified calls like "list.has" won't match local functions
                if let Some(fn_sigs) = fn_signals.get(call.as_str()) {
                    merge_signals_into(&mut handler.body_signals, fn_sigs);
                }
            }
        }
    }
}

/// Re-evaluate derived signals after interprocedural merge.
///
/// Some signals (like `enforces_single_input`) depend on the full set of function_calls,
/// which is only complete after merging helper function signals. This function re-checks
/// patterns that couldn't be detected in the initial `analyze_body` pass.
fn recompute_derived_signals(validators: &mut [ValidatorInfo]) {
    for validator in validators.iter_mut() {
        for handler in &mut validator.handlers {
            if handler.body_signals.enforces_single_input {
                continue; // Already detected
            }
            let has_length_call = handler
                .body_signals
                .function_calls
                .iter()
                .any(|c| c.ends_with("list.length"));
            let has_validators_inputs = handler.body_signals.function_calls.iter().any(|c| {
                c.contains("get_validators_inputs") || c.contains("get_all_validators_inputs")
            });
            if has_length_call && has_validators_inputs {
                handler.body_signals.enforces_single_input = true;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Cross-module transitive signal merging
// ---------------------------------------------------------------------------

/// Merge all relevant fields from `source` into `target`. Returns true if anything new was added.
fn merge_signals_into(target: &mut BodySignals, source: &BodySignals) -> bool {
    let mut changed = false;

    for v in &source.tx_field_accesses {
        if target.tx_field_accesses.insert(v.clone()) {
            changed = true;
        }
    }
    for v in &source.expect_some_vars {
        if target.expect_some_vars.insert(v.clone()) {
            changed = true;
        }
    }
    for v in &source.tx_list_iterations {
        if target.tx_list_iterations.insert(v.clone()) {
            changed = true;
        }
    }
    for v in &source.all_record_labels {
        if target.all_record_labels.insert(v.clone()) {
            changed = true;
        }
    }
    let before = target.unsafe_list_access_calls.len();
    target
        .unsafe_list_access_calls
        .extend(source.unsafe_list_access_calls.iter().cloned());
    if target.unsafe_list_access_calls.len() != before {
        changed = true;
    }
    for v in &source.redeemer_tainted_vars {
        if target.redeemer_tainted_vars.insert(v.clone()) {
            changed = true;
        }
    }
    for v in &source.datum_field_accesses {
        if target.datum_field_accesses.insert(v.clone()) {
            changed = true;
        }
    }
    // Merge function_calls so transitive chains propagate
    for v in &source.function_calls {
        if target.function_calls.insert(v.clone()) {
            changed = true;
        }
    }
    if source.uses_own_ref && !target.uses_own_ref {
        target.uses_own_ref = true;
        changed = true;
    }
    if source.has_division && !target.has_division {
        target.has_division = true;
        changed = true;
    }
    if source.has_subtraction && !target.has_subtraction {
        target.has_subtraction = true;
        changed = true;
    }
    if source.enforces_single_input && !target.enforces_single_input {
        target.enforces_single_input = true;
        changed = true;
    }
    for v in &source.guarded_vars {
        if target.guarded_vars.insert(v.clone()) {
            changed = true;
        }
    }
    for v in &source.division_divisors {
        if target.division_divisors.insert(v.clone()) {
            changed = true;
        }
    }
    // Propagate signals that represent call-chain capabilities
    // (NOT context-local signals like when_branches, has_multiplication,
    // bytearray_literal_lengths)
    for v in &source.var_references {
        if target.var_references.insert(v.clone()) {
            changed = true;
        }
    }
    if source.has_expect_list_destructure && !target.has_expect_list_destructure {
        target.has_expect_list_destructure = true;
        changed = true;
    }
    if source.has_unsafe_match_comparison && !target.has_unsafe_match_comparison {
        target.has_unsafe_match_comparison = true;
        changed = true;
    }
    // Accumulate quantity_of call count from called functions
    if source.quantity_of_call_count > 0 {
        target.quantity_of_call_count += source.quantity_of_call_count;
        changed = true;
    }
    // Propagate quantity_of asset pairs
    for v in &source.quantity_of_asset_pairs {
        if target.quantity_of_asset_pairs.insert(v.clone()) {
            changed = true;
        }
    }
    // Propagate tautological comparisons
    if !source.tautological_comparisons.is_empty() {
        let before = target.tautological_comparisons.len();
        target
            .tautological_comparisons
            .extend(source.tautological_comparisons.iter().cloned());
        if target.tautological_comparisons.len() != before {
            changed = true;
        }
    }
    // Datum continuity tracking
    for v in &source.datum_equality_checks {
        if target.datum_equality_checks.insert(v.clone()) {
            changed = true;
        }
    }
    if source.has_datum_continuity_assertion && !target.has_datum_continuity_assertion {
        target.has_datum_continuity_assertion = true;
        changed = true;
    }

    changed
}

/// A deferred merge action to avoid borrow conflicts when iterating modules.
struct MergeAction {
    module_idx: usize,
    validator_idx: usize,
    handler_idx: usize,
    source_signals: BodySignals,
}

/// Build a global function map: key → cloned BodySignals.
/// Keys are both "short_module.fn_name" and "full/path.fn_name" for flexible lookup.
fn build_global_function_map(
    modules: &[ModuleInfo],
) -> std::collections::HashMap<String, BodySignals> {
    let mut map = std::collections::HashMap::new();

    for module in modules {
        let short_module = module.name.rsplit('/').next().unwrap_or(&module.name);

        for func in &module.functions {
            if let Some(ref signals) = func.body_signals {
                // Index by "short_module.fn_name"
                let short_key = format!("{short_module}.{}", func.name);
                map.entry(short_key).or_insert_with(|| signals.clone());

                // Index by "full/path.fn_name"
                let full_key = format!("{}.{}", module.name, func.name);
                map.entry(full_key).or_insert_with(|| signals.clone());

                // Also index by bare function name for unqualified cross-module calls
                // (some Aiken modules import and call without qualifier)
                map.entry(func.name.clone())
                    .or_insert_with(|| signals.clone());
            }
        }
    }

    map
}

/// Resolve a qualified function call (e.g. "utils.get_upper_bound") against the global map.
/// Returns the matching key if found.
fn resolve_call<'a>(
    call: &str,
    global_map: &'a std::collections::HashMap<String, BodySignals>,
) -> Option<&'a BodySignals> {
    // Direct lookup first (handles "short_module.fn_name" and "full/path.fn_name")
    if let Some(signals) = global_map.get(call) {
        return Some(signals);
    }

    // For calls like "module.func", try matching just the last segment of module name
    if let Some(dot_pos) = call.rfind('.') {
        let func_name = &call[dot_pos + 1..];
        let mod_part = &call[..dot_pos];

        // Try all keys that end with ".func_name" where the module part matches
        for (key, signals) in global_map {
            if let Some(key_dot) = key.rfind('.') {
                let key_func = &key[key_dot + 1..];
                let key_mod = &key[..key_dot];
                if key_func == func_name {
                    let key_short = key_mod.rsplit('/').next().unwrap_or(key_mod);
                    if key_short == mod_part || key_mod == mod_part {
                        return Some(signals);
                    }
                }
            }
        }

        // Last resort: look up just the bare function name
        if let Some(signals) = global_map.get(func_name) {
            return Some(signals);
        }
    }

    None
}

/// Collect merge actions for cross-module qualified calls without holding mutable borrows.
fn collect_cross_module_merges(
    modules: &[ModuleInfo],
    global_map: &std::collections::HashMap<String, BodySignals>,
) -> Vec<MergeAction> {
    let mut actions = Vec::new();

    // Skip stdlib modules — they don't contain security-relevant signals
    let skip_prefixes = ["aiken/", "aiken_"];

    for (mi, module) in modules.iter().enumerate() {
        for (vi, validator) in module.validators.iter().enumerate() {
            for (hi, handler) in validator.handlers.iter().enumerate() {
                let calls: Vec<String> = handler
                    .body_signals
                    .function_calls
                    .iter()
                    .cloned()
                    .collect();

                for call in &calls {
                    // Only resolve qualified calls (containing '.')
                    if !call.contains('.') {
                        continue;
                    }
                    // Skip stdlib calls
                    if skip_prefixes.iter().any(|p| call.starts_with(p)) {
                        continue;
                    }
                    // Skip common stdlib module prefixes
                    if let Some(mod_part) = call.split('.').next() {
                        if matches!(
                            mod_part,
                            "list"
                                | "dict"
                                | "bytearray"
                                | "int"
                                | "string"
                                | "option"
                                | "math"
                                | "interval"
                                | "transaction"
                                | "value"
                                | "pairs"
                                | "builtin"
                        ) {
                            continue;
                        }
                    }

                    if let Some(source_signals) = resolve_call(call, global_map) {
                        actions.push(MergeAction {
                            module_idx: mi,
                            validator_idx: vi,
                            handler_idx: hi,
                            source_signals: source_signals.clone(),
                        });
                    }
                }
            }
        }
    }

    actions
}

/// Cross-module transitive signal merging.
///
/// After all modules are extracted (with intra-module merging already done),
/// this resolves qualified function calls (e.g. `utils.get_upper_bound`) across
/// module boundaries and merges their signals into handler bodies.
///
/// Uses fixed-point iteration (max 5 rounds) to handle transitive call chains.
pub fn merge_cross_module_signals(modules: &mut [ModuleInfo]) {
    let global_map = build_global_function_map(modules);

    if global_map.is_empty() {
        return;
    }

    // Fixed-point iteration for transitive chains
    for _round in 0..5 {
        let actions = collect_cross_module_merges(modules, &global_map);

        if actions.is_empty() {
            break;
        }

        let mut any_changed = false;
        for action in actions {
            let handler = &mut modules[action.module_idx].validators[action.validator_idx].handlers
                [action.handler_idx];
            if merge_signals_into(&mut handler.body_signals, &action.source_signals) {
                any_changed = true;
            }
        }

        if !any_changed {
            break;
        }
    }

    // Re-evaluate derived signals and cross-handler analysis after cross-module merge
    for module in modules.iter_mut() {
        recompute_derived_signals(&mut module.validators);
        cross_handler_analysis(&mut module.validators);
    }
}

// ---------------------------------------------------------------------------
// Feature #2: Cross-handler analysis
// ---------------------------------------------------------------------------

/// Build a `ValidatorSignals` summary for each validator by correlating signals
/// across all of its handlers.  This lets detectors ask cross-handler questions
/// such as "does this validator have both spend and mint handlers?" or "which tx
/// fields are accessed by any handler?".
fn cross_handler_analysis(validators: &mut [ValidatorInfo]) {
    for validator in validators.iter_mut() {
        let mut summary = ValidatorSignals::default();

        for handler in &validator.handlers {
            summary.handler_names.push(handler.name.clone());
            summary
                .combined_tx_accesses
                .extend(handler.body_signals.tx_field_accesses.iter().cloned());

            if handler.name == "spend" {
                summary.has_spend = true;
            }
            if handler.name == "mint" {
                summary.has_mint = true;
            }
        }

        validator.summary = Some(summary);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_type_to_string_app_simple() {
        let t = Rc::new(Type::App {
            public: true,
            contains_opaque: false,
            module: String::new(),
            name: "Int".to_string(),
            args: vec![],
            alias: None,
        });
        assert_eq!(type_to_string(&t), "Int");
    }

    #[test]
    fn test_type_to_string_app_with_module() {
        let inner = Rc::new(Type::App {
            public: true,
            contains_opaque: false,
            module: String::new(),
            name: "Int".to_string(),
            args: vec![],
            alias: None,
        });
        let t = Rc::new(Type::App {
            public: true,
            contains_opaque: false,
            module: String::new(),
            name: "List".to_string(),
            args: vec![inner],
            alias: None,
        });
        assert_eq!(type_to_string(&t), "List<Int>");
    }

    #[test]
    fn test_type_to_string_tuple() {
        let int_type = Rc::new(Type::App {
            public: true,
            contains_opaque: false,
            module: String::new(),
            name: "Int".to_string(),
            args: vec![],
            alias: None,
        });
        let t = Rc::new(Type::Tuple {
            elems: vec![int_type.clone(), int_type],
            alias: None,
        });
        assert_eq!(type_to_string(&t), "(Int, Int)");
    }

    #[test]
    fn test_type_to_string_fn() {
        let int_type = Rc::new(Type::App {
            public: true,
            contains_opaque: false,
            module: String::new(),
            name: "Int".to_string(),
            args: vec![],
            alias: None,
        });
        let bool_type = Rc::new(Type::App {
            public: true,
            contains_opaque: false,
            module: String::new(),
            name: "Bool".to_string(),
            args: vec![],
            alias: None,
        });
        let t = Rc::new(Type::Fn {
            args: vec![int_type],
            ret: bool_type,
            alias: None,
        });
        assert_eq!(type_to_string(&t), "fn(Int) -> Bool");
    }

    // --- Feature #2: ValidatorSignals tests ---

    #[test]
    fn test_validator_signals_default() {
        let vs = ValidatorSignals::default();
        assert!(vs.handler_names.is_empty());
        assert!(vs.combined_tx_accesses.is_empty());
        assert!(!vs.has_spend);
        assert!(!vs.has_mint);
    }

    #[test]
    fn test_validator_signals_has_spend_and_mint() {
        let mut vs = ValidatorSignals::default();
        vs.handler_names.push("spend".to_string());
        vs.handler_names.push("mint".to_string());
        vs.has_spend = true;
        vs.has_mint = true;
        assert!(vs.has_spend);
        assert!(vs.has_mint);
        assert_eq!(vs.handler_names.len(), 2);
    }

    #[test]
    fn test_validator_signals_combined_tx_accesses() {
        let mut vs = ValidatorSignals::default();
        vs.combined_tx_accesses
            .insert("extra_signatories".to_string());
        vs.combined_tx_accesses.insert("outputs".to_string());
        assert_eq!(vs.combined_tx_accesses.len(), 2);
        assert!(vs.combined_tx_accesses.contains("extra_signatories"));
    }

    #[test]
    fn test_cross_handler_analysis_populates_summary() {
        // Build a minimal ValidatorInfo with two handlers
        let spend_signals = {
            let mut s = BodySignals::default();
            s.tx_field_accesses.insert("extra_signatories".to_string());
            s
        };
        let mint_signals = {
            let mut s = BodySignals::default();
            s.tx_field_accesses.insert("outputs".to_string());
            s
        };

        let mut validators = vec![ValidatorInfo {
            name: "my_validator".to_string(),
            params: vec![],
            handlers: vec![
                HandlerInfo {
                    name: "spend".to_string(),
                    params: vec![],
                    return_type: "Bool".to_string(),
                    location: None,
                    body_signals: spend_signals,
                },
                HandlerInfo {
                    name: "mint".to_string(),
                    params: vec![],
                    return_type: "Bool".to_string(),
                    location: None,
                    body_signals: mint_signals,
                },
            ],
            summary: None,
        }];

        cross_handler_analysis(&mut validators);

        let summary = validators[0]
            .summary
            .as_ref()
            .expect("summary should be set");
        assert!(summary.has_spend);
        assert!(summary.has_mint);
        assert_eq!(summary.handler_names.len(), 2);
        assert!(summary.combined_tx_accesses.contains("extra_signatories"));
        assert!(summary.combined_tx_accesses.contains("outputs"));
    }

    #[test]
    fn test_cross_handler_analysis_spend_only() {
        let spend_signals = BodySignals::default();
        let mut validators = vec![ValidatorInfo {
            name: "spend_only".to_string(),
            params: vec![],
            handlers: vec![HandlerInfo {
                name: "spend".to_string(),
                params: vec![],
                return_type: "Bool".to_string(),
                location: None,
                body_signals: spend_signals,
            }],
            summary: None,
        }];

        cross_handler_analysis(&mut validators);

        let summary = validators[0]
            .summary
            .as_ref()
            .expect("summary should be set");
        assert!(summary.has_spend);
        assert!(!summary.has_mint);
    }

    #[test]
    fn test_validator_info_summary_initially_none() {
        // Before cross_handler_analysis, summary is None
        let v = ValidatorInfo {
            name: "test".to_string(),
            params: vec![],
            handlers: vec![],
            summary: None,
        };
        assert!(v.summary.is_none());
    }

    // --- Cross-module signal merging tests ---

    /// Helper to build a minimal ModuleInfo with one validator handler and optional lib functions.
    fn make_test_module(
        name: &str,
        handler_calls: Vec<&str>,
        handler_tx_accesses: Vec<&str>,
        functions: Vec<(&str, Vec<&str>, Vec<&str>)>, // (fn_name, tx_accesses, calls)
    ) -> ModuleInfo {
        let mut handler_signals = BodySignals::default();
        for call in handler_calls {
            handler_signals.function_calls.insert(call.to_string());
        }
        for acc in handler_tx_accesses {
            handler_signals.tx_field_accesses.insert(acc.to_string());
        }

        let funcs: Vec<FunctionInfo> = functions
            .into_iter()
            .map(|(fn_name, tx_accesses, calls)| {
                let mut signals = BodySignals::default();
                for acc in tx_accesses {
                    signals.tx_field_accesses.insert(acc.to_string());
                }
                for call in calls {
                    signals.function_calls.insert(call.to_string());
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
            kind: ModuleKind::Validator,
            validators: vec![ValidatorInfo {
                name: "test_validator".to_string(),
                params: vec![],
                handlers: vec![HandlerInfo {
                    name: "spend".to_string(),
                    params: vec![],
                    return_type: "Bool".to_string(),
                    location: None,
                    body_signals: handler_signals,
                }],
                summary: None,
            }],
            data_types: vec![],
            functions: funcs,
            constants: vec![],
            type_aliases: vec![],
            test_count: 0,
            source_code: None,
            test_function_names: vec![],
        }
    }

    /// Helper for lib-only module (no validators).
    fn make_lib_module(name: &str, functions: Vec<(&str, Vec<&str>, Vec<&str>)>) -> ModuleInfo {
        let funcs: Vec<FunctionInfo> = functions
            .into_iter()
            .map(|(fn_name, tx_accesses, calls)| {
                let mut signals = BodySignals::default();
                for acc in tx_accesses {
                    signals.tx_field_accesses.insert(acc.to_string());
                }
                for call in calls {
                    signals.function_calls.insert(call.to_string());
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

    #[test]
    fn test_cross_module_qualified_call_resolution() {
        // Validator calls "utils.check_signer" which accesses extra_signatories
        let mut modules = vec![
            make_test_module(
                "project/validators/my_validator",
                vec!["utils.check_signer"],
                vec![],
                vec![],
            ),
            make_lib_module(
                "project/lib/utils",
                vec![("check_signer", vec!["extra_signatories"], vec![])],
            ),
        ];

        merge_cross_module_signals(&mut modules);

        let handler = &modules[0].validators[0].handlers[0];
        assert!(
            handler
                .body_signals
                .tx_field_accesses
                .contains("extra_signatories"),
            "cross-module call should merge tx_field_accesses"
        );
    }

    #[test]
    fn test_cross_module_transitive_chain() {
        // handler -> utils.wrapper -> helpers.check_validity -> tx.validity_range
        let mut modules = vec![
            make_test_module(
                "project/validators/v",
                vec!["utils.wrapper"],
                vec![],
                vec![],
            ),
            make_lib_module(
                "project/lib/utils",
                vec![("wrapper", vec![], vec!["helpers.check_validity"])],
            ),
            make_lib_module(
                "project/lib/helpers",
                vec![("check_validity", vec!["validity_range"], vec![])],
            ),
        ];

        merge_cross_module_signals(&mut modules);

        let handler = &modules[0].validators[0].handlers[0];
        // The transitive chain should bring validity_range into the handler
        // Note: transitive resolution happens through function_calls merging
        // On round 1: handler gets utils.wrapper's signals (including helpers.check_validity call)
        // On round 2: handler gets helpers.check_validity's signals (including validity_range)
        assert!(
            handler
                .body_signals
                .tx_field_accesses
                .contains("validity_range"),
            "transitive chain should propagate tx_field_accesses"
        );
    }

    #[test]
    fn test_cross_module_terminates_with_no_functions() {
        // Empty modules — should not panic or loop
        let mut modules = vec![make_test_module(
            "project/validators/empty",
            vec![],
            vec![],
            vec![],
        )];

        merge_cross_module_signals(&mut modules);
        // Just verify it doesn't panic
        assert!(modules[0].validators[0].handlers[0]
            .body_signals
            .tx_field_accesses
            .is_empty());
    }

    #[test]
    fn test_cross_module_stdlib_calls_ignored() {
        // Stdlib calls like "list.has" should not be resolved
        let mut modules = vec![
            make_test_module(
                "project/validators/v",
                vec!["list.has", "dict.get"],
                vec![],
                vec![],
            ),
            // Even if there's a module named "list", stdlib prefix skips it
        ];

        merge_cross_module_signals(&mut modules);

        let handler = &modules[0].validators[0].handlers[0];
        // No tx accesses should be added from stdlib calls
        assert!(handler.body_signals.tx_field_accesses.is_empty());
    }

    #[test]
    fn test_cross_module_non_transaction_function_signals() {
        // A function without Transaction param should still have body_signals
        // (Change 1 ensures this), and cross-module merge should use them
        let mut modules = vec![
            make_test_module(
                "project/validators/v",
                vec!["helpers.validate_datum"],
                vec![],
                vec![],
            ),
            make_lib_module(
                "project/lib/helpers",
                vec![("validate_datum", vec![], vec![])],
            ),
        ];

        // Give the helper function some expect_some_vars (non-tx signal)
        modules[1].functions[0]
            .body_signals
            .as_mut()
            .unwrap()
            .expect_some_vars
            .insert("datum_field".to_string());

        // Rebuild global map and merge
        merge_cross_module_signals(&mut modules);

        let handler = &modules[0].validators[0].handlers[0];
        assert!(
            handler
                .body_signals
                .expect_some_vars
                .contains("datum_field"),
            "non-tx signals from helper functions should be merged"
        );
    }
}
