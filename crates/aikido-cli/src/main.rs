use std::path::PathBuf;
use std::process;
use std::time::{Duration, SystemTime};

use clap::Parser;
use colored::Colorize;

use aikido_core::lsp::{findings_to_diagnostics, format_publish_diagnostics};
use aikido_core::pdf::findings_to_pdf;
use aikido_core::tx_simulation::enrich_findings_with_uplc_simulation_with_context_builder;
use aikido_core::{
    all_detectors, analyze_blueprint, check_budget_thresholds, cwc_for_detector, dashboard_to_json,
    detector_reliability_tier, evaluate_accuracy, filter_suppressed, findings_to_csv,
    findings_to_gitlab_sast, findings_to_html, findings_to_markdown, findings_to_rdjson,
    findings_to_sarif, format_benchmark_summary, format_budget_warnings, format_dashboard,
    format_finding_summary, format_findings, format_report, format_uplc_metrics,
    load_expectations_from_toml, load_invariant_spec, load_plugins, parse_severity,
    run_benchmark_manifest, run_detectors_with_config, severity_order, verify_invariants,
    violations_to_findings, AikenProject, AikidoConfig, Baseline, CallGraph, Finding,
};

const FINDINGS_JSON_SCHEMA_VERSION: &str = "aikido.findings.v1";

#[derive(Parser)]
#[command(name = "aikido")]
#[command(version = "0.3.0")]
#[command(about = "Static analysis tool for Aiken smart contracts")]
struct Cli {
    /// Path to the Aiken project directory
    #[arg(default_value = ".")]
    project_path: PathBuf,

    /// Show detailed output (function signatures, constants, UPLC metrics)
    #[arg(short, long)]
    verbose: bool,

    /// Output format
    #[arg(long, default_value = "text", value_parser = ["text", "json", "sarif", "markdown", "html", "rdjson", "csv", "gitlab-sast", "pdf"])]
    format: String,

    /// Skip vulnerability detection
    #[arg(long)]
    no_detectors: bool,

    /// Minimum severity to report (info, low, medium, high, critical)
    #[arg(long, default_value = "info")]
    min_severity: String,

    /// Quiet mode — only output findings, no progress messages
    #[arg(short, long)]
    quiet: bool,

    /// Minimum severity that triggers non-zero exit code (default: high)
    #[arg(long, default_value = "high")]
    fail_on: String,

    /// List all available detector rules
    #[arg(long)]
    list_rules: bool,

    /// Show detailed explanation of a detector rule
    #[arg(long)]
    explain: Option<String>,

    /// Accept all current findings as baseline (creates .aikido-baseline.json)
    #[arg(long)]
    accept_baseline: bool,

    /// Only report findings in files changed since this git ref (e.g., main, abc123)
    #[arg(long)]
    diff: Option<String>,

    /// Watch for file changes and re-run analysis
    #[arg(long)]
    watch: bool,

    /// Generate a default .aikido.toml config file and exit
    #[arg(long)]
    init: bool,

    /// Clone and analyze a remote git repository
    #[arg(long)]
    git: Option<String>,

    /// Generate .aikido.toml pre-configured to suppress all current findings
    #[arg(long)]
    generate_config: bool,

    /// Path to .aikido.toml config file (default: auto-detect in project directory)
    #[arg(long)]
    config: Option<PathBuf>,

    /// Output findings as LSP JSON-RPC diagnostics (for editor integration)
    #[arg(long)]
    lsp: bool,

    /// Launch interactive terminal navigator for findings
    #[arg(long)]
    interactive: bool,

    /// Insert suppression comments for all current findings (or a specific detector)
    #[arg(long)]
    fix: Option<Option<String>>,

    /// Reject projects using stdlib v1.x (default: warn and attempt compilation)
    #[arg(long)]
    strict_stdlib: bool,

    /// Print the function call graph and exit
    #[arg(long)]
    call_graph: bool,

    /// Evaluate detector accuracy against .aikido-accuracy.toml expectations and exit
    #[arg(long)]
    accuracy: bool,

    /// Run benchmark manifest (multi-project accuracy/quality summary) and exit
    #[arg(long)]
    benchmark_manifest: Option<PathBuf>,

    /// Fail benchmark mode if configured quality gates are violated
    #[arg(long)]
    benchmark_enforce_gates: bool,

    /// Disable full-stack orchestration lanes and run static detectors only.
    #[arg(long)]
    static_only: bool,
}

// parse_severity() and severity_order() imported from aikido_core

// severity_rank is an alias for severity_order — using severity_order directly

fn findings_to_json(
    findings: &[Finding],
    project_name: &str,
    project_version: &str,
    lane_status: serde_json::Value,
) -> String {
    let findings_json: Vec<serde_json::Value> = findings
        .iter()
        .map(|f| {
            serde_json::json!({
                "detector": f.detector_name,
                "reliability_tier": detector_reliability_tier(&f.detector_name).to_string(),
                "severity": f.severity.to_string().to_lowercase(),
                "confidence": f.confidence.to_string(),
                "title": f.title,
                "description": f.description,
                "module": f.module,
                "cwc": cwc_for_detector(&f.detector_name).map(|entry| serde_json::json!({
                    "id": entry.id,
                    "name": entry.name,
                    "severity": entry.severity.to_string(),
                })),
                "location": f.location.as_ref().map(|loc| serde_json::json!({
                    "path": loc.module_path,
                    "byte_start": loc.byte_start,
                    "byte_end": loc.byte_end,
                    "line_start": loc.line_start,
                    "column_start": loc.column_start,
                    "line_end": loc.line_end,
                    "column_end": loc.column_end,
                })),
                "suggestion": f.suggestion,
                "related_findings": f.related_findings,
                "semantic_group": f.semantic_group,
                "evidence": f.evidence,
            })
        })
        .collect();

    let output = serde_json::json!({
        "schema_version": FINDINGS_JSON_SCHEMA_VERSION,
        "project": project_name,
        "version": project_version,
        "analysis_lanes": lane_status,
        "findings": findings_json,
        "total": findings.len(),
    });

    serde_json::to_string_pretty(&output).unwrap_or_default()
}

fn build_lane_status(
    aikido_config: &AikidoConfig,
    no_detectors: bool,
    simulation_corroborated_findings: usize,
) -> serde_json::Value {
    serde_json::json!({
        "detectors": {
            "enabled": !no_detectors,
            "count": all_detectors().len(),
            "runtime_integrated": true
        },
        "compliance": {
            "enabled": aikido_config.analysis.dual_pattern,
            "runtime_integrated": true
        },
        "smt": {
            "enabled": aikido_config.analysis.smt,
            "runtime_integrated": true,
            "backend": "simple-solver"
        },
        "simulation": {
            "enabled": aikido_config.analysis.simulation,
            "runtime_integrated": true,
            "context_builder_command_configured": aikido_config.analysis.simulation_context_builder_command.is_some(),
            "corroborated_findings": simulation_corroborated_findings
        },
        "path_cfg_ssa_symbolic": {
            "enabled": false,
            "runtime_integrated": false,
            "status": "not_integrated",
            "note": "Modules exist and are tested, but are not yet invoked in the standard runtime detector pipeline."
        }
    })
}

fn main() {
    let cli = Cli::parse();

    // --list-rules: print all detectors and exit
    if cli.list_rules {
        let detectors = all_detectors();
        println!("Available detectors ({}):\n", detectors.len());
        for d in &detectors {
            let cwe = d.cwe_id().unwrap_or("-");
            println!(
                "  {:<40} [{:<8}] {:<18} {:<12} {:<10} {}",
                d.name(),
                d.severity().to_string(),
                d.category(),
                detector_reliability_tier(d.name()).to_string(),
                cwe,
                d.description()
            );
            println!("  {:<40} {}", "", d.doc_url().dimmed());
        }
        process::exit(0);
    }

    // --explain <rule>: show detailed explanation and exit
    if let Some(ref rule) = cli.explain {
        let detectors = all_detectors();
        if let Some(d) = detectors.iter().find(|d| d.name() == rule) {
            println!("{}", d.name());
            println!("Severity: {}", d.severity());
            println!("Category: {}", d.category());
            if let Some(cwe) = d.cwe_id() {
                println!("CWE: {cwe}");
            }
            println!("Docs: {}", d.doc_url());
            println!();
            println!("{}", d.long_description());
        } else {
            eprintln!(
                "{}: unknown rule '{}'. Use --list-rules to see all available detectors.",
                "error".red().bold(),
                rule
            );
            process::exit(1);
        }
        process::exit(0);
    }

    // --benchmark-manifest: run multi-project benchmark and exit
    if let Some(ref manifest_path) = cli.benchmark_manifest {
        match run_benchmark_manifest(manifest_path) {
            Ok(summary) => {
                if cli.format == "json" {
                    println!("{}", aikido_core::benchmark_summary_to_json(&summary));
                } else {
                    println!("{}", format_benchmark_summary(&summary));
                }
                if cli.benchmark_enforce_gates && !summary.gate_evaluation.passed {
                    process::exit(1);
                }
                process::exit(0);
            }
            Err(e) => {
                eprintln!("{}: {e}", "error".red().bold());
                process::exit(1);
            }
        }
    }

    let min_severity = match parse_severity(&cli.min_severity) {
        Some(s) => s,
        None => {
            eprintln!(
                "{}: invalid severity '{}'. Use: info, low, medium, high, critical",
                "error".red().bold(),
                cli.min_severity
            );
            process::exit(1);
        }
    };

    // Validate --fail-on early (before compilation)
    let fail_on_severity = match parse_severity(&cli.fail_on) {
        Some(s) => s,
        None => {
            eprintln!(
                "{}: invalid --fail-on severity '{}'. Use: info, low, medium, high, critical",
                "error".red().bold(),
                cli.fail_on
            );
            process::exit(1);
        }
    };

    let project_path = if cli.project_path.is_absolute() {
        cli.project_path.clone()
    } else {
        std::env::current_dir()
            .expect("Failed to get current directory")
            .join(&cli.project_path)
    };

    // --init: generate default .aikido.toml and exit
    if cli.init {
        let config_path = project_path.join(".aikido.toml");
        if config_path.exists() {
            eprintln!(
                "{}: .aikido.toml already exists at {}",
                "error".red().bold(),
                config_path.display()
            );
            process::exit(1);
        }

        let detectors = all_detectors();
        let mut content = String::new();
        content.push_str("# Aikido Configuration\n");
        content.push_str("# See: https://github.com/Bajuzjefe/Aikido-Security-Analysis-Platform\n");
        content.push('\n');
        content.push_str("[detectors]\n");
        content.push_str("# Uncomment to disable specific detectors:\n");
        content.push_str("# disable = [\"hardcoded-addresses\"]\n");
        content.push('\n');
        content.push_str("# Uncomment to override severity levels:\n");
        content.push_str("# [detectors.severity_override]\n");
        content.push_str("# missing-validity-range = \"high\"\n");
        content.push('\n');
        content.push_str("[plugins]\n");
        content.push_str("# Optional subprocess plugin commands (JSON protocol):\n");
        content.push_str("# commands = [\"./plugins/my_plugin --format aikido-json\"]\n");
        content.push_str("# Legacy dynamic plugins are disabled in ABI v2.\n");
        content.push_str("\n[analysis]\n");
        content.push_str("# Optional external simulation context-builder command:\n");
        content.push_str(
            "# simulation_context_builder_command = \"node /path/to/simulation-context-builder\"\n",
        );
        content.push('\n');
        content.push_str("# Available detectors:\n");
        for d in &detectors {
            let cwe = d.cwe_id().unwrap_or("-");
            content.push_str(&format!(
                "# - {} ({}) [{}] {}\n",
                d.name(),
                d.severity(),
                cwe,
                d.category()
            ));
        }

        if let Err(e) = std::fs::write(&config_path, &content) {
            eprintln!("{}: failed to write config: {e}", "error".red().bold());
            process::exit(1);
        }

        eprintln!(
            "{} Created .aikido.toml at {}",
            "\u{2714}".green().bold(),
            config_path.display()
        );
        process::exit(0);
    }

    // --git: clone remote repository to temp dir
    let _temp_dir_guard: Option<TempDirGuard>;
    let project_path = if let Some(ref git_url) = cli.git {
        if !cli.quiet {
            eprintln!("{} Cloning {}...", "[1/4]".cyan().bold(), git_url);
        }

        let hash = simple_hash(git_url);
        let temp_path = std::env::temp_dir().join(format!("aikido-remote-{hash:016x}"));

        // Clean up any previous clone
        let _ = std::fs::remove_dir_all(&temp_path);

        let output = std::process::Command::new("git")
            .args([
                "clone",
                "--depth",
                "1",
                git_url,
                &temp_path.to_string_lossy(),
            ])
            .output();

        match output {
            Ok(out) if out.status.success() => {
                _temp_dir_guard = Some(TempDirGuard(temp_path.clone()));
                temp_path
            }
            Ok(out) => {
                eprintln!(
                    "{}: git clone failed: {}",
                    "error".red().bold(),
                    String::from_utf8_lossy(&out.stderr).trim()
                );
                process::exit(1);
            }
            Err(e) => {
                eprintln!("{}: failed to run git: {e}", "error".red().bold());
                process::exit(1);
            }
        }
    } else {
        _temp_dir_guard = None;
        project_path
    };

    if !cli.quiet {
        eprintln!("{} {}", "Analyzing:".cyan().bold(), project_path.display());
    }

    let project = match AikenProject::new(project_path.clone()) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{}: {e}", "error".red().bold());
            process::exit(1);
        }
    };

    let config = match project.config() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{}: {e}", "error".red().bold());
            process::exit(1);
        }
    };

    if !cli.quiet {
        eprintln!(
            "{} {} v{}",
            "Project:".cyan().bold(),
            config.name,
            config.version
        );
        let step_base = if cli.git.is_some() { 2 } else { 1 };
        let total_steps = step_base + 2;
        eprintln!(
            "{} Compiling...",
            format!("[{step_base}/{total_steps}]").cyan().bold()
        );
    }

    let modules = match project.compile_with_options(cli.strict_stdlib) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("{}: {e}", "error".red().bold());
            process::exit(1);
        }
    };

    if !cli.quiet {
        eprintln!(
            "{} {} modules analyzed",
            "\u{2714}".green().bold(),
            modules.len()
        );
    }

    // --call-graph: print function call graph and exit
    if cli.call_graph {
        let graph = CallGraph::from_modules(&modules);
        println!("Call Graph ({} nodes)", graph.nodes.len());
        println!("{}", "=".repeat(60));
        let mut sorted_callers: Vec<&String> = graph.edges.keys().collect();
        sorted_callers.sort();
        for caller in sorted_callers {
            if let Some(callees) = graph.edges.get(caller.as_str()) {
                if callees.is_empty() {
                    continue;
                }
                let mut sorted_callees: Vec<&String> = callees.iter().collect();
                sorted_callees.sort();
                println!(
                    "  {} -> {}",
                    caller,
                    sorted_callees
                        .iter()
                        .map(|s| s.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                );
            }
        }
        process::exit(0);
    }

    // Load aikido config (from --config path or auto-detect in project dir)
    let mut aikido_config = if let Some(ref config_path) = cli.config {
        AikidoConfig::load_from_file(config_path)
    } else {
        AikidoConfig::load(&project_path)
    };

    if !cli.static_only {
        aikido_config.analysis.dual_pattern = true;
        aikido_config.analysis.smt = true;
        aikido_config.analysis.simulation = true;
    }

    // Validate config and print warnings
    let config_warnings = aikido_config.validate();
    for warning in &config_warnings {
        eprintln!("{}: {warning}", "warning".yellow().bold());
    }

    // Run detectors
    let findings: Vec<Finding> = if cli.no_detectors {
        vec![]
    } else {
        if !cli.quiet {
            let step_base = if cli.git.is_some() { 3 } else { 2 };
            let total_steps = step_base + 1;
            let detector_count = all_detectors().len();
            eprintln!(
                "{} Running {} detectors...",
                format!("[{step_base}/{total_steps}]").cyan().bold(),
                detector_count
            );
        }
        let all_findings = if aikido_config.plugins.paths.is_empty()
            && aikido_config.plugins.commands.is_empty()
        {
            run_detectors_with_config(&modules, &aikido_config)
        } else {
            let plugin_bundle = match load_plugins(&aikido_config.plugins, &project_path) {
                Ok(bundle) => bundle,
                Err(errors) => {
                    for error in errors {
                        eprintln!("{}: {error}", "error".red().bold());
                    }
                    process::exit(1);
                }
            };
            if !cli.quiet {
                let detector_count = plugin_bundle.findings.len();
                eprintln!(
                    "{} Loaded {} plugin finding{} from {} plugin{}",
                    "\u{2714}".green().bold(),
                    detector_count,
                    if detector_count == 1 { "" } else { "s" },
                    plugin_bundle.plugin_count(),
                    if plugin_bundle.plugin_count() == 1 {
                        ""
                    } else {
                        "s"
                    }
                );
            }
            let mut findings = run_detectors_with_config(&modules, &aikido_config);
            findings.extend(plugin_bundle.findings);
            findings
        };

        // Apply suppression comments
        let unsuppressed = filter_suppressed(all_findings, &modules);

        // Apply baseline filtering
        let baseline = Baseline::load(&project_path);
        let after_baseline = baseline.filter_baselined(unsuppressed);

        // Filter by minimum severity
        let min_rank = severity_order(&min_severity);
        after_baseline
            .into_iter()
            .filter(|f| severity_order(&f.severity) >= min_rank)
            .collect()
    };

    // --diff: filter findings to only changed files
    let mut findings: Vec<Finding> = findings;
    let mut simulation_corroborated_findings = 0usize;

    if !cli.no_detectors {
        let invariant_spec_path = project_path.join(".aikido-invariants.toml");
        if invariant_spec_path.exists() {
            match load_invariant_spec(&invariant_spec_path) {
                Ok(spec) => {
                    let violations = verify_invariants(&spec, &modules);
                    if !violations.is_empty() && !cli.quiet {
                        eprintln!(
                            "{} {} invariant violation{} detected",
                            "Invariants:".cyan().bold(),
                            violations.len(),
                            if violations.len() == 1 { "" } else { "s" }
                        );
                    }
                    let mut inv_findings = violations_to_findings(&violations);
                    findings.append(&mut inv_findings);
                }
                Err(e) => {
                    eprintln!(
                        "{}: failed to load {}: {e}",
                        "warning".yellow().bold(),
                        invariant_spec_path.display()
                    );
                }
            }
        }

        if aikido_config.analysis.simulation {
            let enriched = enrich_findings_with_uplc_simulation_with_context_builder(
                &mut findings,
                &project_path,
                aikido_config
                    .analysis
                    .simulation_context_builder_command
                    .as_deref(),
            );
            simulation_corroborated_findings = enriched;
            if enriched > 0 && !cli.quiet {
                eprintln!(
                    "{} {} finding{} corroborated with UPLC execution",
                    "Simulation:".cyan().bold(),
                    enriched,
                    if enriched == 1 { "" } else { "s" }
                );
            }
        }
    }

    findings = if let Some(ref git_ref) = cli.diff {
        let output = std::process::Command::new("git")
            .args(["diff", "--name-only", git_ref])
            .current_dir(&project_path)
            .output();

        match output {
            Ok(out) if out.status.success() => {
                let changed_files: Vec<String> = String::from_utf8_lossy(&out.stdout)
                    .lines()
                    .map(|l| l.to_string())
                    .collect();

                if !cli.quiet {
                    eprintln!(
                        "{} {} changed files since {}",
                        "Diff:".cyan().bold(),
                        changed_files.len(),
                        git_ref
                    );
                }

                findings
                    .into_iter()
                    .filter(|f| {
                        f.location.as_ref().is_some_and(|loc| {
                            changed_files.iter().any(|cf| loc.module_path.ends_with(cf))
                        })
                    })
                    .collect()
            }
            Ok(out) => {
                eprintln!(
                    "{}: git diff failed: {}",
                    "warning".yellow().bold(),
                    String::from_utf8_lossy(&out.stderr).trim()
                );
                findings
            }
            Err(e) => {
                eprintln!("{}: failed to run git: {e}", "warning".yellow().bold());
                findings
            }
        }
    } else {
        findings
    };

    // --accuracy: evaluate detector accuracy against expectations and exit
    if cli.accuracy {
        let accuracy_path = project_path.join(".aikido-accuracy.toml");
        match load_expectations_from_toml(&accuracy_path) {
            Ok(expectation) => {
                let dashboard = evaluate_accuracy(&[(&expectation, &findings)]);
                if dashboard.evaluated_cases == 0 {
                    eprintln!(
                        "{}: no labeled detector cases found in {}",
                        "error".red().bold(),
                        accuracy_path.display()
                    );
                    eprintln!(
                        "Add labels using `expected`/`unexpected` (legacy) or `[[labels]]` with classification TP/FP/INFO/BUSINESS_LOGIC/UNREVIEWED."
                    );
                    process::exit(1);
                }

                if dashboard.unlabeled_triggered_cases > 0 && !cli.quiet {
                    eprintln!(
                        "{}: {} triggered detector case{} not labeled in accuracy file",
                        "warning".yellow().bold(),
                        dashboard.unlabeled_triggered_cases,
                        if dashboard.unlabeled_triggered_cases == 1 {
                            ""
                        } else {
                            "s"
                        }
                    );
                }

                if cli.format == "json" {
                    println!("{}", dashboard_to_json(&dashboard));
                } else {
                    println!("{}", format_dashboard(&dashboard));
                }
                process::exit(0);
            }
            Err(e) => {
                eprintln!("{}: {e}", "error".red().bold());
                eprintln!(
                    "\nCreate {} with format:\n  expected = [\"detector-a\", ...]\n  unexpected = [\"detector-b\", ...]\n  [[labels]]\n  detector = \"detector-c\"\n  classification = \"TP\"\n  rationale = \"why\"\n  audit_id = \"AUD-1\"\n  source = \"external-audit\"",
                    accuracy_path.display()
                );
                process::exit(1);
            }
        }
    }

    // --generate-config: create .aikido.toml that suppresses all current findings
    if cli.generate_config {
        let triggered_detectors: std::collections::BTreeSet<&str> =
            findings.iter().map(|f| f.detector_name.as_str()).collect();

        let config_path = project_path.join(".aikido.toml");
        let mut content = String::new();
        content.push_str("# Aikido Configuration — auto-generated from current findings\n");
        content
            .push_str("# See: https://github.com/Bajuzjefe/Aikido-Security-Analysis-Platform\n\n");
        content.push_str("[detectors]\n");
        if triggered_detectors.is_empty() {
            content.push_str("# No findings detected — all detectors remain enabled.\n");
            content.push_str("# disable = []\n");
        } else {
            content.push_str("# The following detectors produced findings in this project.\n");
            content.push_str("# Uncomment the disable line to suppress them:\n");
            let names: Vec<&str> = triggered_detectors.into_iter().collect();
            content.push_str(&format!(
                "# disable = [{}]\n",
                names
                    .iter()
                    .map(|n| format!("\"{n}\""))
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        content.push('\n');
        content.push_str("# Severity overrides:\n");
        content.push_str("# [detectors.severity_override]\n");
        content.push_str("# missing-validity-range = \"high\"\n");
        content.push('\n');
        content.push_str("# Config inheritance:\n");
        content.push_str("# extends = \"aikido-strict\"\n");
        content.push('\n');
        content.push_str("# Per-file overrides:\n");
        content.push_str("# [[files]]\n");
        content.push_str("# pattern = \"validators/*.ak\"\n");
        content.push_str("# disable = [\"magic-numbers\"]\n");

        if let Err(e) = std::fs::write(&config_path, &content) {
            eprintln!("{}: failed to write config: {e}", "error".red().bold());
            process::exit(1);
        }

        eprintln!(
            "{} Generated .aikido.toml at {}",
            "\u{2714}".green().bold(),
            config_path.display()
        );
        process::exit(0);
    }

    // --accept-baseline: save current findings as baseline and exit
    if cli.accept_baseline {
        let baseline = Baseline::from_findings(&findings);
        match baseline.save(&project_path) {
            Ok(()) => {
                eprintln!(
                    "{} Saved {} findings to .aikido-baseline.json",
                    "\u{2714}".green().bold(),
                    findings.len()
                );
            }
            Err(e) => {
                eprintln!("{}: {e}", "error".red().bold());
                process::exit(1);
            }
        }
        process::exit(0);
    }

    // --fix: insert suppression comments for findings
    if let Some(ref fix_opt) = cli.fix {
        let filter_detector = fix_opt.as_deref();
        let target_findings: Vec<&Finding> = findings
            .iter()
            .filter(|f| {
                f.location.is_some() && filter_detector.is_none_or(|d| f.detector_name == d)
            })
            .collect();

        if target_findings.is_empty() {
            eprintln!(
                "{} No findings with source locations to fix.",
                "info".cyan().bold()
            );
            process::exit(0);
        }

        // Group findings by file path, sort by line descending (insert bottom-up)
        let mut by_file: std::collections::HashMap<&str, Vec<&Finding>> =
            std::collections::HashMap::new();
        for f in &target_findings {
            if let Some(ref loc) = f.location {
                by_file.entry(&loc.module_path).or_default().push(f);
            }
        }

        let mut fixed_count = 0usize;
        for (path, mut file_findings) in by_file {
            let full_path = project_path.join(path);
            let source = match std::fs::read_to_string(&full_path) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("{}: cannot read {path}: {e}", "warning".yellow().bold());
                    continue;
                }
            };

            let mut lines: Vec<String> = source.lines().map(|l| l.to_string()).collect();

            // Sort by line number descending so insertions don't shift later indices
            file_findings.sort_by(|a, b| {
                let la = a.location.as_ref().and_then(|l| l.line_start).unwrap_or(0);
                let lb = b.location.as_ref().and_then(|l| l.line_start).unwrap_or(0);
                lb.cmp(&la)
            });

            for f in &file_findings {
                if let Some(ref loc) = f.location {
                    let line_idx = loc.line_start.unwrap_or(1).saturating_sub(1);
                    // Determine indentation from the target line
                    let indent = if line_idx < lines.len() {
                        let target = &lines[line_idx];
                        let trimmed = target.trim_start();
                        &target[..target.len() - trimmed.len()]
                    } else {
                        ""
                    };
                    let comment = format!("{indent}// aikido:ignore[{}]", f.detector_name);
                    lines.insert(line_idx, comment);
                    fixed_count += 1;
                }
            }

            let new_source = lines.join("\n");
            // Preserve trailing newline if original had one
            let new_source = if source.ends_with('\n') && !new_source.ends_with('\n') {
                new_source + "\n"
            } else {
                new_source
            };

            if let Err(e) = std::fs::write(&full_path, &new_source) {
                eprintln!("{}: cannot write {path}: {e}", "error".red().bold());
            }
        }

        eprintln!(
            "{} Inserted {} suppression comments across {} findings.",
            "\u{2714}".green().bold(),
            fixed_count,
            target_findings.len()
        );
        process::exit(0);
    }

    // --lsp: output LSP JSON-RPC diagnostics and exit
    if cli.lsp {
        let root = project_path.to_str().unwrap_or(".");
        let diagnostics = findings_to_diagnostics(&findings, root);
        println!("{}", format_publish_diagnostics(&diagnostics));
        let exit_code = if findings.is_empty() { 0 } else { 2 };
        process::exit(exit_code);
    }

    // --interactive: launch terminal navigator
    if cli.interactive {
        use aikido_core::interactive::InteractiveState;
        use std::io::{IsTerminal, Read};

        if !std::io::stdin().is_terminal() {
            eprintln!(
                "{}: --interactive requires a terminal (TTY). Pipe to a file or use --format instead.",
                "error".red().bold()
            );
            process::exit(1);
        }

        if findings.is_empty() {
            eprintln!("{} No findings to navigate.", "\u{2714}".green().bold());
            process::exit(0);
        }

        let mut state = InteractiveState::new(findings.len());
        // Set terminal to raw mode for single-char input
        let _ = std::process::Command::new("stty")
            .args(["-echo", "cbreak"])
            .status();

        loop {
            // Clear screen and render
            print!("\x1b[2J\x1b[H");
            print!("{}", state.render(&findings));

            // Read single byte
            let mut buf = [0u8; 3];
            let n = std::io::stdin().read(&mut buf).unwrap_or(0);
            if n == 0 {
                break;
            }

            match buf[0] {
                b'q' | 3 => break,              // q or Ctrl-C
                b'j' | b'J' => state.down(),    // j = down
                b'k' | b'K' => state.up(),      // k = up
                b'\n' | b'\r' => state.enter(), // enter = toggle detail
                27 if n >= 3 && buf[1] == b'[' => {
                    // arrow keys
                    match buf[2] {
                        b'A' => state.up(),   // up arrow
                        b'B' => state.down(), // down arrow
                        _ => {}
                    }
                }
                _ => {}
            }
        }

        // Restore terminal
        let _ = std::process::Command::new("stty")
            .args(["echo", "-cbreak"])
            .status();
        println!();
        process::exit(0);
    }

    match cli.format.as_str() {
        "json" => {
            let lane_status = build_lane_status(
                &aikido_config,
                cli.no_detectors,
                simulation_corroborated_findings,
            );
            println!(
                "{}",
                findings_to_json(&findings, &config.name, &config.version, lane_status)
            );
        }
        "sarif" => {
            let root = project_path.to_str().map(|s| s.trim_end_matches('/'));
            println!("{}", findings_to_sarif(&findings, root, &modules));
        }
        "markdown" => {
            println!(
                "{}",
                findings_to_markdown(&findings, &config.name, &config.version, &modules)
            );
        }
        "html" => {
            println!(
                "{}",
                findings_to_html(&findings, &config.name, &config.version, &modules)
            );
        }
        "rdjson" => {
            let root = project_path.to_str().map(|s| s.trim_end_matches('/'));
            println!("{}", findings_to_rdjson(&findings, root));
        }
        "csv" => {
            println!("{}", findings_to_csv(&findings));
        }
        "gitlab-sast" => {
            println!("{}", findings_to_gitlab_sast(&findings));
        }
        "pdf" => {
            let pdf_bytes = findings_to_pdf(&findings, &config.name, &config.version, &modules);
            use std::io::Write;
            std::io::stdout()
                .write_all(&pdf_bytes)
                .expect("failed to write PDF");
        }
        _ => {
            // Text format
            let report = format_report(
                &modules,
                &config.name,
                &config.version,
                &project_path,
                cli.verbose,
            );
            println!("{report}");

            // UPLC metrics and budget warnings
            {
                let blueprint_metrics = analyze_blueprint(&project_path);

                if cli.verbose && !blueprint_metrics.is_empty() {
                    println!("\nUPLC METRICS");
                    for bv in &blueprint_metrics {
                        println!("  {}: {} bytes", bv.title, bv.compiled_size);
                        if let Some(ref m) = bv.metrics {
                            println!("    {}", format_uplc_metrics(m));
                        }
                    }
                }

                // Budget warnings (shown even without --verbose)
                let budget_warnings = check_budget_thresholds(&blueprint_metrics, 50.0, 50.0);
                if !budget_warnings.is_empty() {
                    eprintln!("\n{}", format_budget_warnings(&budget_warnings));
                }
            }

            if !cli.no_detectors {
                if findings.is_empty() {
                    if !cli.quiet {
                        eprintln!("{} No issues found.", "\u{2714}".green().bold());
                    }
                } else {
                    if !cli.quiet {
                        eprintln!(
                            "{} {} issue{} found: {}",
                            "\u{26a0}".yellow().bold(),
                            findings.len(),
                            if findings.len() == 1 { "" } else { "s" },
                            format_finding_summary(&findings)
                        );
                    }
                    let findings_report = format_findings(&findings, &modules);
                    println!("{findings_report}");
                }
            }
        }
    }

    // --fail-on: exit with non-zero status if findings at or above threshold
    let fail_on_rank = severity_order(&fail_on_severity);
    let should_fail = findings
        .iter()
        .any(|f| severity_order(&f.severity) >= fail_on_rank);

    if !cli.watch && should_fail {
        process::exit(2);
    }

    // --watch: polling loop for .ak file changes
    if cli.watch {
        let mut last_check = SystemTime::now();

        loop {
            eprintln!("{}", "Watching for changes...".dimmed());
            std::thread::sleep(Duration::from_secs(2));

            // Check if any .ak file has been modified since last check
            let changed = has_ak_files_changed(&project_path, last_check);
            if !changed {
                continue;
            }

            last_check = SystemTime::now();
            eprintln!("\n{}", "Changes detected, re-analyzing...".cyan().bold());

            // Re-compile and re-run analysis
            let project = match AikenProject::new(project_path.clone()) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("{}: {e}", "error".red().bold());
                    continue;
                }
            };

            let _config = match project.config() {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("{}: {e}", "error".red().bold());
                    continue;
                }
            };

            let modules = match project.compile_with_options(cli.strict_stdlib) {
                Ok(m) => m,
                Err(e) => {
                    eprintln!("{}: {e}", "error".red().bold());
                    continue;
                }
            };

            let mut aikido_config = if let Some(ref config_path) = cli.config {
                AikidoConfig::load_from_file(config_path)
            } else {
                AikidoConfig::load(&project_path)
            };
            if !cli.static_only {
                aikido_config.analysis.dual_pattern = true;
                aikido_config.analysis.smt = true;
                aikido_config.analysis.simulation = true;
            }
            let mut findings: Vec<Finding> = if cli.no_detectors {
                vec![]
            } else {
                let all_findings = if aikido_config.plugins.paths.is_empty()
                    && aikido_config.plugins.commands.is_empty()
                {
                    run_detectors_with_config(&modules, &aikido_config)
                } else {
                    let plugin_bundle = match load_plugins(&aikido_config.plugins, &project_path) {
                        Ok(bundle) => bundle,
                        Err(errors) => {
                            for error in errors {
                                eprintln!("{}: {error}", "error".red().bold());
                            }
                            continue;
                        }
                    };
                    if !cli.quiet {
                        let detector_count = plugin_bundle.findings.len();
                        eprintln!(
                            "{} Loaded {} plugin finding{} from {} plugin{}",
                            "\u{2714}".green().bold(),
                            detector_count,
                            if detector_count == 1 { "" } else { "s" },
                            plugin_bundle.plugin_count(),
                            if plugin_bundle.plugin_count() == 1 {
                                ""
                            } else {
                                "s"
                            }
                        );
                    }
                    let mut findings = run_detectors_with_config(&modules, &aikido_config);
                    findings.extend(plugin_bundle.findings);
                    findings
                };
                let unsuppressed = filter_suppressed(all_findings, &modules);
                let baseline = Baseline::load(&project_path);
                let after_baseline = baseline.filter_baselined(unsuppressed);
                let min_rank = severity_order(&min_severity);
                after_baseline
                    .into_iter()
                    .filter(|f| severity_order(&f.severity) >= min_rank)
                    .collect()
            };

            if !cli.no_detectors && aikido_config.analysis.simulation {
                let _ = enrich_findings_with_uplc_simulation_with_context_builder(
                    &mut findings,
                    &project_path,
                    aikido_config
                        .analysis
                        .simulation_context_builder_command
                        .as_deref(),
                );
            }

            if findings.is_empty() {
                eprintln!("{} No issues found.", "\u{2714}".green().bold());
            } else {
                eprintln!(
                    "{} {} issue{} found: {}",
                    "\u{26a0}".yellow().bold(),
                    findings.len(),
                    if findings.len() == 1 { "" } else { "s" },
                    format_finding_summary(&findings)
                );
                let findings_report = format_findings(&findings, &modules);
                println!("{findings_report}");
            }
        }
    }
}

/// Guard that removes a temp directory when dropped.
struct TempDirGuard(std::path::PathBuf);

impl Drop for TempDirGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Simple hash for a string (FNV-1a inspired).
fn simple_hash(s: &str) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325;
    for b in s.bytes() {
        hash ^= b as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

/// Check if any `.ak` file under the given path has been modified since `since`.
fn has_ak_files_changed(dir: &std::path::Path, since: SystemTime) -> bool {
    fn walk_dir(dir: &std::path::Path, since: SystemTime) -> bool {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return false;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                if walk_dir(&path, since) {
                    return true;
                }
            } else if path.extension().is_some_and(|ext| ext == "ak") {
                if let Ok(metadata) = std::fs::metadata(&path) {
                    if let Ok(modified) = metadata.modified() {
                        if modified > since {
                            return true;
                        }
                    }
                }
            }
        }
        false
    }
    walk_dir(dir, since)
}
