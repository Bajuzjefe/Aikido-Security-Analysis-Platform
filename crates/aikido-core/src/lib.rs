pub mod accuracy;
pub mod ast_walker;
pub mod baseline;
pub mod benchmark;
pub mod body_analysis;
pub mod call_graph;
pub mod compliance;
pub mod config;
pub mod cross_module;
pub mod csv;
pub mod cwc;
pub mod delegation;
pub mod detector;
pub mod evidence;
pub mod gitlab;
pub mod html;
pub mod interactive;
pub mod invariant_spec;
pub mod lsp;
pub mod markdown;
pub mod path_analysis;
pub mod pdf;
pub mod plugin;
pub mod project;
pub mod report;
pub mod reviewdog;
pub mod sarif;
pub mod scorecard;
pub mod smt;
pub mod ssa;
pub mod suppression;
pub mod symbolic;
pub mod tx_simulation;
pub mod uplc_analysis;

pub mod fuzz_lane;

pub mod annotations;
pub mod cardano_model;
pub mod cfg;
pub mod dataflow;
pub mod ir;
pub mod protocol_patterns;
pub mod state_machine;
pub mod stdlib_model;
pub mod token_lifecycle;
pub mod transaction_analysis;
pub mod validator_graph;

pub use accuracy::{
    dashboard_to_json, evaluate_accuracy, format_dashboard, load_expectations_from_toml,
    validate_expectation_v2, AccuracyDashboard, AuditMapping, FindingLabel, FixtureExpectation,
    LabelClassification,
};
pub use ast_walker::{merge_cross_module_signals, ModuleInfo, ValidatorSignals};
pub use baseline::Baseline;
pub use benchmark::{
    benchmark_summary_to_json, evaluate_quality_gates, format_benchmark_summary,
    run_benchmark_manifest, BenchmarkFixture, BenchmarkManifest, BenchmarkQualityGates,
    BenchmarkSummary, BenchmarkTotals, DetectorAccuracyRow, DetectorFindingStats, GateEvaluation,
    BENCHMARK_SCHEMA_VERSION,
};
pub use call_graph::CallGraph;
pub use compliance::{
    apply_dual_pattern_analysis, collect_all_compliance, filter_with_compliance, ComplianceChecker,
    ComplianceEvidence, DualPatternResult, SecurityProperty,
};
pub use config::{
    run_detectors_with_config, run_detectors_with_config_and_detectors, AikidoConfig,
};
pub use csv::findings_to_csv;
pub use cwc::{all_cwc_entries, cwc_for_detector, format_cwc_registry, CwcEntry};
pub use detector::{
    all_detectors, detector_reliability_tier, parse_severity, run_detectors, severity_order,
    Confidence, DetectorReliabilityTier, Finding, Severity, SourceLocation,
};
pub use evidence::{
    compute_effective_confidence, evidence_path_verified, evidence_pattern_match,
    evidence_to_sarif_code_flow, format_evidence, CodeFlowKind, CodeFlowStep, Evidence,
    EvidenceLevel,
};
pub use gitlab::findings_to_gitlab_sast;
pub use html::findings_to_html;
pub use invariant_spec::{
    format_invariant_report, generate_sample_spec, load_invariant_spec, verify_invariants,
    violations_to_findings, InvariantCategory, InvariantCheck, InvariantDef, InvariantError,
    InvariantSeverity, InvariantSpec, InvariantViolation, ProtocolInfo,
};
pub use markdown::findings_to_markdown;
pub use plugin::{
    load_plugins, LoadedPlugin, PluginBundle, PluginConfig, PluginError, AIKIDO_PLUGIN_API_VERSION,
};
pub use project::{AikenProject, AikidoError};
pub use protocol_patterns::{
    analyze_authority_flows, analyze_token_flows, builtin_protocol_patterns,
    detect_protocol_pattern, format_protocol_report, score_protocol_patterns, AuthorityFlow,
    InvariantCheckType, ProtocolCategory, ProtocolInvariant, ProtocolPattern, TokenFlow,
    TokenFlowType, ValidatorRole,
};
pub use report::{format_finding_summary, format_findings, format_report};
pub use reviewdog::findings_to_rdjson;
pub use sarif::findings_to_sarif;
pub use scorecard::{
    check_demotion, check_promotion, criteria_for_tier, evaluate_all_scorecards,
    evaluate_quality_gate, evaluate_scorecard, format_scorecard_report, format_scorecard_summary,
    DetectorScorecard, QualityGateResult, TierCriteria, BETA_CRITERIA, EXPERIMENTAL_CRITERIA,
    STABLE_CRITERIA,
};
pub use suppression::{filter_suppressed, filter_suppressed_with_info, SuppressionInfo};
pub use token_lifecycle::TokenLifecycleGraph;
pub use uplc_analysis::{
    analyze_blueprint, check_budget_thresholds, format_budget_warnings, format_uplc_metrics,
};
