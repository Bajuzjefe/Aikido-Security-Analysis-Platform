use std::path::Path;

use uplc::ast::{DeBruijn, Program, Term};

/// Plutus V3 protocol limits (Chang hard fork).
pub const MAX_CPU_BUDGET: u64 = 14_000_000_000; // 14 billion ExUnits CPU steps
pub const MAX_MEM_BUDGET: u64 = 10_000_000; // 10 million ExUnits memory
pub const MAX_SCRIPT_SIZE: usize = 16_384; // 16 KB compiled script

/// Metrics extracted from UPLC compiled code.
#[derive(Debug, Clone, Default)]
pub struct UplcMetrics {
    pub term_count: usize,
    pub lambda_count: usize,
    pub apply_count: usize,
    pub builtin_count: usize,
    pub force_count: usize,
    pub delay_count: usize,
    pub constant_count: usize,
    pub error_count: usize,
    pub builtins_used: Vec<String>,
    pub max_depth: usize,
}

/// Estimated execution budget for a validator.
#[derive(Debug, Clone)]
pub struct BudgetEstimate {
    pub cpu_estimate: u64,
    pub mem_estimate: u64,
    pub cpu_pct: f64,
    pub mem_pct: f64,
}

impl BudgetEstimate {
    /// Estimate budget from UPLC metrics using heuristic weights.
    pub fn from_metrics(metrics: &UplcMetrics) -> Self {
        // Heuristic weights based on typical Plutus CEK machine costs.
        // These are rough estimates — actual costs depend on specific builtins and data sizes.
        let cpu_estimate = (metrics.apply_count as u64) * 23_000
            + (metrics.lambda_count as u64) * 23_000
            + (metrics.builtin_count as u64) * 150_000
            + (metrics.force_count as u64) * 23_000
            + (metrics.delay_count as u64) * 23_000
            + (metrics.constant_count as u64) * 23_000
            + (metrics.term_count as u64) * 1_000;

        let mem_estimate = (metrics.apply_count as u64) * 100
            + (metrics.lambda_count as u64) * 100
            + (metrics.constant_count as u64) * 200
            + (metrics.term_count as u64) * 32;

        let cpu_pct = (cpu_estimate as f64 / MAX_CPU_BUDGET as f64) * 100.0;
        let mem_pct = (mem_estimate as f64 / MAX_MEM_BUDGET as f64) * 100.0;

        Self {
            cpu_estimate,
            mem_estimate,
            cpu_pct,
            mem_pct,
        }
    }
}

/// Budget warnings for a validator.
#[derive(Debug, Clone)]
pub struct BudgetWarning {
    pub validator_title: String,
    pub message: String,
    pub severity: BudgetWarningSeverity,
}

#[derive(Debug, Clone, PartialEq)]
pub enum BudgetWarningSeverity {
    Info,
    Warning,
    Error,
}

/// Check budget thresholds and script size limits.
/// Returns warnings for validators that exceed configurable thresholds.
pub fn check_budget_thresholds(
    validators: &[BlueprintValidatorMetrics],
    cpu_warn_pct: f64,
    mem_warn_pct: f64,
) -> Vec<BudgetWarning> {
    let mut warnings = Vec::new();

    for v in validators {
        // #57: Script size limit check
        if v.compiled_size > MAX_SCRIPT_SIZE {
            warnings.push(BudgetWarning {
                validator_title: v.title.clone(),
                message: format!(
                    "Script size {} bytes exceeds {} byte limit",
                    v.compiled_size, MAX_SCRIPT_SIZE
                ),
                severity: BudgetWarningSeverity::Error,
            });
        } else if v.compiled_size > MAX_SCRIPT_SIZE * 80 / 100 {
            warnings.push(BudgetWarning {
                validator_title: v.title.clone(),
                message: format!(
                    "Script size {} bytes is {:.0}% of {} byte limit",
                    v.compiled_size,
                    (v.compiled_size as f64 / MAX_SCRIPT_SIZE as f64) * 100.0,
                    MAX_SCRIPT_SIZE
                ),
                severity: BudgetWarningSeverity::Warning,
            });
        }

        // #55/#56: CPU/memory budget estimation and threshold warning
        if let Some(ref metrics) = v.metrics {
            let budget = BudgetEstimate::from_metrics(metrics);

            if budget.cpu_pct > cpu_warn_pct {
                let severity = if budget.cpu_pct > 90.0 {
                    BudgetWarningSeverity::Error
                } else {
                    BudgetWarningSeverity::Warning
                };
                warnings.push(BudgetWarning {
                    validator_title: v.title.clone(),
                    message: format!(
                        "Estimated CPU budget {:.1}% of max ({} / {})",
                        budget.cpu_pct, budget.cpu_estimate, MAX_CPU_BUDGET
                    ),
                    severity,
                });
            }

            if budget.mem_pct > mem_warn_pct {
                let severity = if budget.mem_pct > 90.0 {
                    BudgetWarningSeverity::Error
                } else {
                    BudgetWarningSeverity::Warning
                };
                warnings.push(BudgetWarning {
                    validator_title: v.title.clone(),
                    message: format!(
                        "Estimated memory budget {:.1}% of max ({} / {})",
                        budget.mem_pct, budget.mem_estimate, MAX_MEM_BUDGET
                    ),
                    severity,
                });
            }
        }
    }

    warnings
}

/// Analyze compiled code from a hex string (from plutus.json `compiledCode`).
pub fn analyze_compiled_code(hex: &str) -> Option<UplcMetrics> {
    let program = Program::<DeBruijn>::from_hex(hex, &mut Vec::new(), &mut Vec::new()).ok()?;
    let mut metrics = UplcMetrics::default();
    walk_term(&program.term, 0, &mut metrics);
    // Deduplicate builtins
    metrics.builtins_used.sort();
    metrics.builtins_used.dedup();
    Some(metrics)
}

fn walk_term(term: &Term<DeBruijn>, depth: usize, metrics: &mut UplcMetrics) {
    metrics.term_count += 1;
    if depth > metrics.max_depth {
        metrics.max_depth = depth;
    }

    match term {
        Term::Lambda { body, .. } => {
            metrics.lambda_count += 1;
            walk_term(body.as_ref(), depth + 1, metrics);
        }
        Term::Apply { function, argument } => {
            metrics.apply_count += 1;
            walk_term(function.as_ref(), depth + 1, metrics);
            walk_term(argument.as_ref(), depth + 1, metrics);
        }
        Term::Builtin(builtin) => {
            metrics.builtin_count += 1;
            metrics.builtins_used.push(format!("{builtin:?}"));
        }
        Term::Force(inner) => {
            metrics.force_count += 1;
            walk_term(inner.as_ref(), depth + 1, metrics);
        }
        Term::Delay(inner) => {
            metrics.delay_count += 1;
            walk_term(inner.as_ref(), depth + 1, metrics);
        }
        Term::Constant(_) => {
            metrics.constant_count += 1;
        }
        Term::Error => {
            metrics.error_count += 1;
        }
        Term::Var(_) => {}
        Term::Case { constr, branches } => {
            walk_term(constr.as_ref(), depth + 1, metrics);
            for branch in branches {
                walk_term(branch, depth + 1, metrics);
            }
        }
        Term::Constr { fields, .. } => {
            for field in fields {
                walk_term(field, depth + 1, metrics);
            }
        }
    }
}

/// Blueprint validator info with UPLC metrics.
pub struct BlueprintValidatorMetrics {
    pub title: String,
    pub compiled_size: usize,
    pub metrics: Option<UplcMetrics>,
}

/// Read plutus.json and analyze all validators' compiled code.
pub fn analyze_blueprint(project_root: &Path) -> Vec<BlueprintValidatorMetrics> {
    let blueprint_path = project_root.join("plutus.json");
    let Ok(content) = std::fs::read_to_string(&blueprint_path) else {
        return vec![];
    };

    let Ok(json) = serde_json::from_str::<serde_json::Value>(&content) else {
        return vec![];
    };

    let Some(validators) = json.get("validators").and_then(|v| v.as_array()) else {
        return vec![];
    };

    validators
        .iter()
        .filter_map(|v| {
            let title = v.get("title")?.as_str()?.to_string();
            let compiled_code = v.get("compiledCode").and_then(|c| c.as_str()).unwrap_or("");
            let compiled_size = compiled_code.len() / 2;
            let metrics = if compiled_code.is_empty() {
                None
            } else {
                analyze_compiled_code(compiled_code)
            };
            Some(BlueprintValidatorMetrics {
                title,
                compiled_size,
                metrics,
            })
        })
        .collect()
}

/// Format UPLC metrics for display.
pub fn format_uplc_metrics(metrics: &UplcMetrics) -> String {
    let budget = BudgetEstimate::from_metrics(metrics);
    let mut parts = vec![
        format!("terms: {}", metrics.term_count),
        format!("lambdas: {}", metrics.lambda_count),
        format!("applies: {}", metrics.apply_count),
        format!("builtins: {}", metrics.builtin_count),
        format!("max depth: {}", metrics.max_depth),
    ];
    if !metrics.builtins_used.is_empty() {
        parts.push(format!("unique builtins: {}", metrics.builtins_used.len()));
    }
    parts.push(format!(
        "est. CPU: {:.1}% | est. MEM: {:.1}%",
        budget.cpu_pct, budget.mem_pct
    ));
    parts.join(" | ")
}

/// Format budget warnings for display.
pub fn format_budget_warnings(warnings: &[BudgetWarning]) -> String {
    if warnings.is_empty() {
        return String::new();
    }

    let mut output = Vec::new();
    output.push("BUDGET WARNINGS".to_string());
    for w in warnings {
        let level = match w.severity {
            BudgetWarningSeverity::Error => "ERROR",
            BudgetWarningSeverity::Warning => "WARN",
            BudgetWarningSeverity::Info => "INFO",
        };
        output.push(format!(
            "  [{}] {}: {}",
            level, w.validator_title, w.message
        ));
    }
    output.join("\n")
}

// ---------------------------------------------------------------------------
// Feature #95: Builtin cost breakdown — show estimated cost per builtin function
// ---------------------------------------------------------------------------

/// Cost breakdown per builtin function.
#[derive(Debug, Clone)]
pub struct BuiltinCostBreakdown {
    pub builtin_name: String,
    pub count: usize,
    pub estimated_cpu: u64,
    pub percentage_of_total: f64,
}

/// Generate per-builtin cost breakdown from metrics.
pub fn builtin_cost_breakdown(metrics: &UplcMetrics) -> Vec<BuiltinCostBreakdown> {
    let total_cpu = BudgetEstimate::from_metrics(metrics).cpu_estimate;
    if total_cpu == 0 {
        return vec![];
    }

    // Count occurrences of each builtin
    let mut counts: HashMap<String, usize> = HashMap::new();
    for b in &metrics.builtins_used {
        *counts.entry(b.clone()).or_insert(0) += 1;
    }

    // Estimate cost per builtin (150k CPU per invocation as heuristic)
    let cpu_per_builtin: u64 = 150_000;
    let mut breakdown: Vec<BuiltinCostBreakdown> = counts
        .into_iter()
        .map(|(name, count)| {
            let estimated_cpu = count as u64 * cpu_per_builtin;
            BuiltinCostBreakdown {
                builtin_name: name,
                count,
                estimated_cpu,
                percentage_of_total: (estimated_cpu as f64 / total_cpu as f64) * 100.0,
            }
        })
        .collect();

    breakdown.sort_by(|a, b| b.estimated_cpu.cmp(&a.estimated_cpu));
    breakdown
}

/// Format builtin cost breakdown for display.
pub fn format_builtin_breakdown(breakdown: &[BuiltinCostBreakdown]) -> String {
    if breakdown.is_empty() {
        return "No builtins used.".to_string();
    }
    let mut lines = vec!["BUILTIN COST BREAKDOWN".to_string()];
    for b in breakdown {
        lines.push(format!(
            "  {:<30} x{:<4} est. CPU: {:>10} ({:.1}%)",
            b.builtin_name, b.count, b.estimated_cpu, b.percentage_of_total
        ));
    }
    lines.join("\n")
}

// ---------------------------------------------------------------------------
// Feature #96: Historical tracking — track compiled size across git commits
// ---------------------------------------------------------------------------

/// Historical snapshot of compiled sizes.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SizeSnapshot {
    pub commit: String,
    pub timestamp: String,
    pub validators: Vec<ValidatorSize>,
}

/// Size info for a single validator.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ValidatorSize {
    pub title: String,
    pub compiled_size: usize,
    pub term_count: Option<usize>,
}

/// Record current compiled sizes as a snapshot.
pub fn create_size_snapshot(
    validators: &[BlueprintValidatorMetrics],
    commit: &str,
) -> SizeSnapshot {
    SizeSnapshot {
        commit: commit.to_string(),
        timestamp: chrono_stub_now(),
        validators: validators
            .iter()
            .map(|v| ValidatorSize {
                title: v.title.clone(),
                compiled_size: v.compiled_size,
                term_count: v.metrics.as_ref().map(|m| m.term_count),
            })
            .collect(),
    }
}

/// Simple timestamp stub (avoids chrono dependency).
fn chrono_stub_now() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    format!("{secs}")
}

/// Compare two size snapshots and report regressions.
pub fn compare_snapshots(old: &SizeSnapshot, new: &SizeSnapshot) -> Vec<SizeRegression> {
    let mut regressions = Vec::new();

    for new_v in &new.validators {
        if let Some(old_v) = old.validators.iter().find(|v| v.title == new_v.title) {
            let size_diff = new_v.compiled_size as i64 - old_v.compiled_size as i64;
            let pct_change = if old_v.compiled_size > 0 {
                (size_diff as f64 / old_v.compiled_size as f64) * 100.0
            } else {
                0.0
            };

            if pct_change.abs() > 5.0 {
                regressions.push(SizeRegression {
                    validator_title: new_v.title.clone(),
                    old_size: old_v.compiled_size,
                    new_size: new_v.compiled_size,
                    change_bytes: size_diff,
                    change_pct: pct_change,
                });
            }
        }
    }

    regressions
}

/// Size regression between two snapshots.
#[derive(Debug, Clone)]
pub struct SizeRegression {
    pub validator_title: String,
    pub old_size: usize,
    pub new_size: usize,
    pub change_bytes: i64,
    pub change_pct: f64,
}

// ---------------------------------------------------------------------------
// Feature #97: UPLC optimization hints — suggest UPLC patterns that could be more efficient
// ---------------------------------------------------------------------------

/// Optimization hint for UPLC code.
#[derive(Debug, Clone)]
pub struct OptimizationHint {
    pub category: String,
    pub message: String,
    pub priority: HintPriority,
}

#[derive(Debug, Clone, PartialEq)]
pub enum HintPriority {
    Low,
    Medium,
    High,
}

/// Analyze UPLC metrics and suggest optimizations.
pub fn suggest_optimizations(metrics: &UplcMetrics) -> Vec<OptimizationHint> {
    let mut hints = Vec::new();

    // High error count suggests unneeded error terms
    if metrics.error_count > 10 {
        hints.push(OptimizationHint {
            category: "dead-code".to_string(),
            message: format!(
                "{} error terms found — consider removing unreachable error branches",
                metrics.error_count
            ),
            priority: HintPriority::Low,
        });
    }

    // Very deep nesting suggests possible optimization via let-bindings
    if metrics.max_depth > 100 {
        hints.push(OptimizationHint {
            category: "nesting".to_string(),
            message: format!(
                "Max nesting depth {} — consider flattening with let-bindings or helper functions",
                metrics.max_depth
            ),
            priority: HintPriority::Medium,
        });
    }

    // High force/delay ratio suggests unnecessary thunking
    if metrics.force_count > metrics.delay_count * 3 && metrics.delay_count > 5 {
        hints.push(OptimizationHint {
            category: "thunking".to_string(),
            message: format!(
                "Force/delay ratio is {}/{} — some delays may be immediately forced",
                metrics.force_count, metrics.delay_count
            ),
            priority: HintPriority::Low,
        });
    }

    // High constant count relative to terms suggests possible sharing
    if metrics.constant_count > metrics.term_count / 3 && metrics.constant_count > 50 {
        hints.push(OptimizationHint {
            category: "sharing".to_string(),
            message: format!(
                "{} constants in {} terms — look for duplicate constants that could be shared via let",
                metrics.constant_count, metrics.term_count
            ),
            priority: HintPriority::Medium,
        });
    }

    // Large script with many builtins
    let budget = BudgetEstimate::from_metrics(metrics);
    if budget.cpu_pct > 30.0 {
        hints.push(OptimizationHint {
            category: "budget".to_string(),
            message: format!(
                "Estimated CPU usage {:.1}% — consider optimizing hot paths",
                budget.cpu_pct
            ),
            priority: HintPriority::High,
        });
    }

    hints
}

// ---------------------------------------------------------------------------
// Feature #98: Dead code in UPLC — detect unreachable terms in compiled output
// ---------------------------------------------------------------------------

/// UPLC dead code analysis result.
#[derive(Debug, Clone)]
pub struct UplcDeadCode {
    pub unreachable_error_terms: usize,
    pub unused_lambda_depth: usize,
    pub total_terms: usize,
    pub estimated_dead_pct: f64,
}

/// Analyze UPLC for potential dead code.
pub fn detect_uplc_dead_code(hex: &str) -> Option<UplcDeadCode> {
    let program = Program::<DeBruijn>::from_hex(hex, &mut Vec::new(), &mut Vec::new()).ok()?;
    let mut unreachable_errors = 0;
    let mut total = 0;
    let mut max_unused_depth = 0;
    count_dead_code(
        &program.term,
        0,
        &mut unreachable_errors,
        &mut total,
        &mut max_unused_depth,
    );

    let estimated_dead_pct = if total > 0 {
        (unreachable_errors as f64 / total as f64) * 100.0
    } else {
        0.0
    };

    Some(UplcDeadCode {
        unreachable_error_terms: unreachable_errors,
        unused_lambda_depth: max_unused_depth,
        total_terms: total,
        estimated_dead_pct,
    })
}

fn count_dead_code(
    term: &Term<DeBruijn>,
    depth: usize,
    errors: &mut usize,
    total: &mut usize,
    max_depth: &mut usize,
) {
    *total += 1;
    match term {
        Term::Error => {
            *errors += 1;
            if depth > *max_depth {
                *max_depth = depth;
            }
        }
        Term::Lambda { body, .. } => {
            count_dead_code(body, depth + 1, errors, total, max_depth);
        }
        Term::Apply { function, argument } => {
            count_dead_code(function, depth + 1, errors, total, max_depth);
            count_dead_code(argument, depth + 1, errors, total, max_depth);
        }
        Term::Force(inner) | Term::Delay(inner) => {
            count_dead_code(inner, depth + 1, errors, total, max_depth);
        }
        Term::Case { constr, branches } => {
            count_dead_code(constr, depth + 1, errors, total, max_depth);
            for b in branches {
                count_dead_code(b, depth + 1, errors, total, max_depth);
            }
        }
        Term::Constr { fields, .. } => {
            for f in fields {
                count_dead_code(f, depth + 1, errors, total, max_depth);
            }
        }
        Term::Constant(_) | Term::Var(_) | Term::Builtin(_) => {}
    }
}

// ---------------------------------------------------------------------------
// Feature #99: UPLC diff — compare compiled output between versions
// ---------------------------------------------------------------------------

/// Diff between two UPLC compiled outputs.
#[derive(Debug, Clone)]
pub struct UplcDiff {
    pub old_metrics: UplcMetrics,
    pub new_metrics: UplcMetrics,
    pub term_count_diff: i64,
    pub lambda_diff: i64,
    pub builtin_diff: i64,
    pub depth_diff: i64,
    pub new_builtins: Vec<String>,
    pub removed_builtins: Vec<String>,
}

/// Compare two UPLC compiled codes and produce a diff.
pub fn diff_compiled_code(old_hex: &str, new_hex: &str) -> Option<UplcDiff> {
    let old_metrics = analyze_compiled_code(old_hex)?;
    let new_metrics = analyze_compiled_code(new_hex)?;

    let old_builtins: HashSet<&String> = old_metrics.builtins_used.iter().collect();
    let new_builtins: HashSet<&String> = new_metrics.builtins_used.iter().collect();

    let added: Vec<String> = new_builtins
        .difference(&old_builtins)
        .map(|s| s.to_string())
        .collect();
    let removed: Vec<String> = old_builtins
        .difference(&new_builtins)
        .map(|s| s.to_string())
        .collect();

    Some(UplcDiff {
        term_count_diff: new_metrics.term_count as i64 - old_metrics.term_count as i64,
        lambda_diff: new_metrics.lambda_count as i64 - old_metrics.lambda_count as i64,
        builtin_diff: new_metrics.builtin_count as i64 - old_metrics.builtin_count as i64,
        depth_diff: new_metrics.max_depth as i64 - old_metrics.max_depth as i64,
        new_builtins: added,
        removed_builtins: removed,
        old_metrics,
        new_metrics,
    })
}

/// Format a UPLC diff for display.
pub fn format_uplc_diff(diff: &UplcDiff) -> String {
    let mut lines = vec!["UPLC DIFF".to_string()];
    lines.push(format!(
        "  Terms:    {} → {} ({:+})",
        diff.old_metrics.term_count, diff.new_metrics.term_count, diff.term_count_diff
    ));
    lines.push(format!(
        "  Lambdas:  {} → {} ({:+})",
        diff.old_metrics.lambda_count, diff.new_metrics.lambda_count, diff.lambda_diff
    ));
    lines.push(format!(
        "  Builtins: {} → {} ({:+})",
        diff.old_metrics.builtin_count, diff.new_metrics.builtin_count, diff.builtin_diff
    ));
    lines.push(format!(
        "  Depth:    {} → {} ({:+})",
        diff.old_metrics.max_depth, diff.new_metrics.max_depth, diff.depth_diff
    ));

    if !diff.new_builtins.is_empty() {
        lines.push(format!("  New builtins: {}", diff.new_builtins.join(", ")));
    }
    if !diff.removed_builtins.is_empty() {
        lines.push(format!(
            "  Removed builtins: {}",
            diff.removed_builtins.join(", ")
        ));
    }

    lines.join("\n")
}

use std::collections::{HashMap, HashSet};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_default() {
        let m = UplcMetrics::default();
        assert_eq!(m.term_count, 0);
        assert_eq!(m.max_depth, 0);
        assert!(m.builtins_used.is_empty());
    }

    #[test]
    fn test_analyze_invalid_hex() {
        assert!(analyze_compiled_code("not-hex").is_none());
        assert!(analyze_compiled_code("").is_none());
    }

    #[test]
    fn test_format_metrics() {
        let m = UplcMetrics {
            term_count: 100,
            lambda_count: 20,
            apply_count: 40,
            builtin_count: 10,
            force_count: 5,
            delay_count: 3,
            constant_count: 15,
            error_count: 2,
            builtins_used: vec!["AddInteger".to_string(), "EqualsInteger".to_string()],
            max_depth: 25,
        };
        let formatted = format_uplc_metrics(&m);
        assert!(formatted.contains("terms: 100"));
        assert!(formatted.contains("max depth: 25"));
        assert!(formatted.contains("unique builtins: 2"));
        assert!(formatted.contains("est. CPU:"));
        assert!(formatted.contains("est. MEM:"));
    }

    #[test]
    fn test_analyze_blueprint_nonexistent() {
        let result = analyze_blueprint(Path::new("/nonexistent"));
        assert!(result.is_empty());
    }

    #[test]
    fn test_budget_estimate_from_metrics() {
        let m = UplcMetrics {
            term_count: 1000,
            lambda_count: 200,
            apply_count: 400,
            builtin_count: 100,
            force_count: 50,
            delay_count: 30,
            constant_count: 150,
            error_count: 5,
            builtins_used: vec![],
            max_depth: 30,
        };
        let budget = BudgetEstimate::from_metrics(&m);
        assert!(budget.cpu_estimate > 0);
        assert!(budget.mem_estimate > 0);
        assert!(budget.cpu_pct > 0.0);
        assert!(budget.mem_pct > 0.0);
        assert!(budget.cpu_pct < 100.0); // Shouldn't exceed 100% for reasonable metrics
    }

    #[test]
    fn test_budget_estimate_zero_metrics() {
        let m = UplcMetrics::default();
        let budget = BudgetEstimate::from_metrics(&m);
        assert_eq!(budget.cpu_estimate, 0);
        assert_eq!(budget.mem_estimate, 0);
        assert_eq!(budget.cpu_pct, 0.0);
        assert_eq!(budget.mem_pct, 0.0);
    }

    #[test]
    fn test_script_size_limit_warning() {
        let validators = vec![BlueprintValidatorMetrics {
            title: "test_validator".to_string(),
            compiled_size: 20_000, // > 16KB
            metrics: None,
        }];
        let warnings = check_budget_thresholds(&validators, 50.0, 50.0);
        assert_eq!(warnings.len(), 1);
        assert_eq!(warnings[0].severity, BudgetWarningSeverity::Error);
        assert!(warnings[0].message.contains("exceeds"));
    }

    #[test]
    fn test_script_size_approaching_limit() {
        let validators = vec![BlueprintValidatorMetrics {
            title: "test_validator".to_string(),
            compiled_size: 14_000, // > 80% of 16KB
            metrics: None,
        }];
        let warnings = check_budget_thresholds(&validators, 50.0, 50.0);
        assert_eq!(warnings.len(), 1);
        assert_eq!(warnings[0].severity, BudgetWarningSeverity::Warning);
    }

    #[test]
    fn test_no_warnings_for_small_script() {
        let validators = vec![BlueprintValidatorMetrics {
            title: "test_validator".to_string(),
            compiled_size: 5_000,
            metrics: Some(UplcMetrics::default()),
        }];
        let warnings = check_budget_thresholds(&validators, 50.0, 50.0);
        assert!(warnings.is_empty());
    }

    #[test]
    fn test_format_budget_warnings() {
        let warnings = vec![BudgetWarning {
            validator_title: "test".to_string(),
            message: "Size too large".to_string(),
            severity: BudgetWarningSeverity::Error,
        }];
        let formatted = format_budget_warnings(&warnings);
        assert!(formatted.contains("BUDGET WARNINGS"));
        assert!(formatted.contains("[ERROR]"));
        assert!(formatted.contains("Size too large"));
    }

    #[test]
    fn test_format_empty_warnings() {
        let formatted = format_budget_warnings(&[]);
        assert!(formatted.is_empty());
    }

    // --- Feature #95: Builtin cost breakdown tests ---

    #[test]
    fn test_builtin_breakdown_empty() {
        let m = UplcMetrics::default();
        let breakdown = builtin_cost_breakdown(&m);
        assert!(breakdown.is_empty());
    }

    #[test]
    fn test_builtin_breakdown_with_builtins() {
        let m = UplcMetrics {
            term_count: 100,
            lambda_count: 10,
            apply_count: 20,
            builtin_count: 5,
            builtins_used: vec![
                "AddInteger".to_string(),
                "AddInteger".to_string(),
                "EqualsInteger".to_string(),
            ],
            ..Default::default()
        };
        let breakdown = builtin_cost_breakdown(&m);
        assert!(!breakdown.is_empty());
        // AddInteger should have count 2
        let add = breakdown.iter().find(|b| b.builtin_name == "AddInteger");
        assert!(add.is_some());
        assert_eq!(add.unwrap().count, 2);
    }

    #[test]
    fn test_format_builtin_breakdown() {
        let breakdown = vec![BuiltinCostBreakdown {
            builtin_name: "AddInteger".to_string(),
            count: 5,
            estimated_cpu: 750_000,
            percentage_of_total: 25.0,
        }];
        let formatted = format_builtin_breakdown(&breakdown);
        assert!(formatted.contains("BUILTIN COST BREAKDOWN"));
        assert!(formatted.contains("AddInteger"));
    }

    // --- Feature #96: Historical tracking tests ---

    #[test]
    fn test_create_size_snapshot() {
        let validators = vec![BlueprintValidatorMetrics {
            title: "test".to_string(),
            compiled_size: 5000,
            metrics: Some(UplcMetrics {
                term_count: 200,
                ..Default::default()
            }),
        }];
        let snap = create_size_snapshot(&validators, "abc123");
        assert_eq!(snap.commit, "abc123");
        assert_eq!(snap.validators.len(), 1);
        assert_eq!(snap.validators[0].compiled_size, 5000);
        assert_eq!(snap.validators[0].term_count, Some(200));
    }

    #[test]
    fn test_compare_snapshots_no_regression() {
        let old = SizeSnapshot {
            commit: "a".to_string(),
            timestamp: "0".to_string(),
            validators: vec![ValidatorSize {
                title: "v".to_string(),
                compiled_size: 5000,
                term_count: None,
            }],
        };
        let new = SizeSnapshot {
            commit: "b".to_string(),
            timestamp: "1".to_string(),
            validators: vec![ValidatorSize {
                title: "v".to_string(),
                compiled_size: 5100, // <5% change
                term_count: None,
            }],
        };
        let regressions = compare_snapshots(&old, &new);
        assert!(regressions.is_empty());
    }

    #[test]
    fn test_compare_snapshots_with_regression() {
        let old = SizeSnapshot {
            commit: "a".to_string(),
            timestamp: "0".to_string(),
            validators: vec![ValidatorSize {
                title: "v".to_string(),
                compiled_size: 5000,
                term_count: None,
            }],
        };
        let new = SizeSnapshot {
            commit: "b".to_string(),
            timestamp: "1".to_string(),
            validators: vec![ValidatorSize {
                title: "v".to_string(),
                compiled_size: 6000, // 20% increase
                term_count: None,
            }],
        };
        let regressions = compare_snapshots(&old, &new);
        assert_eq!(regressions.len(), 1);
        assert!(regressions[0].change_pct > 15.0);
    }

    // --- Feature #97: Optimization hints tests ---

    #[test]
    fn test_no_hints_for_simple_script() {
        let m = UplcMetrics {
            term_count: 50,
            ..Default::default()
        };
        let hints = suggest_optimizations(&m);
        assert!(hints.is_empty());
    }

    #[test]
    fn test_hints_for_high_error_count() {
        let m = UplcMetrics {
            term_count: 100,
            error_count: 15,
            ..Default::default()
        };
        let hints = suggest_optimizations(&m);
        assert!(hints.iter().any(|h| h.category == "dead-code"));
    }

    #[test]
    fn test_hints_for_deep_nesting() {
        let m = UplcMetrics {
            term_count: 200,
            max_depth: 150,
            ..Default::default()
        };
        let hints = suggest_optimizations(&m);
        assert!(hints.iter().any(|h| h.category == "nesting"));
    }

    // --- Feature #98: Dead code detection tests ---

    #[test]
    fn test_dead_code_invalid_hex() {
        assert!(detect_uplc_dead_code("invalid").is_none());
    }

    // --- Feature #99: UPLC diff tests ---

    #[test]
    fn test_format_uplc_diff() {
        let diff = UplcDiff {
            old_metrics: UplcMetrics {
                term_count: 100,
                lambda_count: 20,
                builtin_count: 10,
                max_depth: 25,
                ..Default::default()
            },
            new_metrics: UplcMetrics {
                term_count: 120,
                lambda_count: 25,
                builtin_count: 12,
                max_depth: 28,
                ..Default::default()
            },
            term_count_diff: 20,
            lambda_diff: 5,
            builtin_diff: 2,
            depth_diff: 3,
            new_builtins: vec!["NewBuiltin".to_string()],
            removed_builtins: vec![],
        };
        let formatted = format_uplc_diff(&diff);
        assert!(formatted.contains("UPLC DIFF"));
        assert!(formatted.contains("+20"));
        assert!(formatted.contains("NewBuiltin"));
    }
}
