//! Deterministic benchmark runner and quality-gate evaluation.
//!
//! This module executes Aikido across a manifest of fixture projects,
//! evaluates detector accuracy against per-fixture expectation files, and
//! emits a stable machine-readable summary for CI regression checks.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::accuracy::{
    evaluate_accuracy, load_expectations_from_toml, validate_expectation_v2, FixtureExpectation,
};
use crate::config::{run_detectors_with_config, AikidoConfig};
use crate::detector::Finding;
use crate::project::AikenProject;
use crate::suppression::filter_suppressed;

pub const BENCHMARK_SCHEMA_VERSION: &str = "aikido.benchmark.v1";

fn default_accuracy_file() -> String {
    ".aikido-accuracy.toml".to_string()
}

#[derive(Debug, Clone, Deserialize)]
pub struct BenchmarkManifest {
    pub fixtures: Vec<BenchmarkFixture>,
    #[serde(default)]
    pub quality_gates: BenchmarkQualityGates,
}

impl BenchmarkManifest {
    pub fn load(path: &Path) -> Result<Self, String> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        let manifest: Self = toml::from_str(&content)
            .map_err(|e| format!("invalid benchmark manifest {}: {e}", path.display()))?;
        if manifest.fixtures.is_empty() {
            return Err("benchmark manifest has no fixtures".to_string());
        }
        Ok(manifest)
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct BenchmarkFixture {
    pub name: String,
    pub project: String,
    #[serde(default = "default_accuracy_file")]
    pub accuracy: String,
    #[serde(default)]
    pub config: Option<String>,
    #[serde(default)]
    pub strict_stdlib: bool,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct BenchmarkQualityGates {
    pub min_true_positives: Option<usize>,
    pub min_precision: Option<f64>,
    pub max_false_positive_rate: Option<f64>,
    pub min_annotation_coverage: Option<f64>,
    pub min_reviewed_coverage: Option<f64>,
    pub max_unlabeled_triggered_cases: Option<usize>,
    pub max_unreviewed_triggered_cases: Option<usize>,
    pub max_unreviewed_labeled_cases: Option<usize>,
    pub max_unreviewed_rate: Option<f64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BenchmarkSummary {
    pub schema_version: String,
    pub manifest_path: String,
    pub fixture_results: Vec<FixtureBenchmarkResult>,
    pub detector_accuracy: Vec<DetectorAccuracyRow>,
    pub detector_finding_stats: Vec<DetectorFindingStats>,
    pub totals: BenchmarkTotals,
    pub quality_gates: BenchmarkQualityGates,
    pub gate_evaluation: GateEvaluation,
}

#[derive(Debug, Clone, Serialize)]
pub struct FixtureBenchmarkResult {
    pub name: String,
    pub project_path: String,
    pub finding_count: usize,
    pub severity_counts: BTreeMap<String, usize>,
    pub confidence_counts: BTreeMap<String, usize>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DetectorAccuracyRow {
    pub detector: String,
    pub tp: usize,
    pub fp: usize,
    pub fn_count: usize,
    pub tn: usize,
    pub precision: Option<f64>,
    pub recall: Option<f64>,
    pub f1: Option<f64>,
    pub evaluated_cases: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct DetectorFindingStats {
    pub detector: String,
    pub findings: usize,
    pub by_severity: BTreeMap<String, usize>,
    pub by_confidence: BTreeMap<String, usize>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BenchmarkTotals {
    pub fixture_count: usize,
    pub detector_count: usize,
    pub finding_count: usize,
    pub true_positives: usize,
    pub false_positives: usize,
    pub false_negatives: usize,
    pub evaluated_cases: usize,
    pub reviewed_cases: usize,
    pub unreviewed_cases: usize,
    pub info_cases: usize,
    pub business_logic_cases: usize,
    pub skipped_cases: usize,
    pub unlabeled_triggered_cases: usize,
    pub unreviewed_triggered_cases: usize,
    pub precision: Option<f64>,
    pub recall: Option<f64>,
    pub false_positive_rate: Option<f64>,
    pub annotation_coverage: Option<f64>,
    pub reviewed_coverage: Option<f64>,
    pub unreviewed_rate: Option<f64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct GateEvaluation {
    pub passed: bool,
    pub violations: Vec<String>,
}

struct LoadedFixture {
    summary: FixtureBenchmarkResult,
    expectation: FixtureExpectation,
    findings: Vec<Finding>,
}

pub fn run_benchmark_manifest(manifest_path: &Path) -> Result<BenchmarkSummary, String> {
    let manifest = BenchmarkManifest::load(manifest_path)?;
    let base_dir = manifest_path
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));

    let mut loaded = Vec::new();
    for fixture in &manifest.fixtures {
        let project_path = resolve_from_base(&base_dir, &fixture.project);
        let accuracy_path = resolve_fixture_path(&project_path, &fixture.accuracy);
        let config_path = fixture
            .config
            .as_ref()
            .map(|c| resolve_fixture_path(&project_path, c));

        let project = AikenProject::new(project_path.clone())
            .map_err(|e| format!("fixture '{}': {e}", fixture.name))?;
        let modules = project
            .compile_with_options(fixture.strict_stdlib)
            .map_err(|e| format!("fixture '{}': {e}", fixture.name))?;

        let aikido_config = if let Some(path) = config_path {
            AikidoConfig::load_from_file(&path)
        } else {
            AikidoConfig::load(&project_path)
        };

        let findings = filter_suppressed(
            run_detectors_with_config(&modules, &aikido_config),
            &modules,
        );
        let expectation = load_expectations_from_toml(&accuracy_path).map_err(|e| {
            format!(
                "fixture '{}': failed loading expectations at {}: {e}",
                fixture.name,
                accuracy_path.display()
            )
        })?;
        let schema_errors = validate_expectation_v2(&expectation);
        if !schema_errors.is_empty() {
            return Err(format!(
                "fixture '{}': expectation schema v2 validation failed at {}: {}",
                fixture.name,
                accuracy_path.display(),
                schema_errors.join("; ")
            ));
        }

        let summary = FixtureBenchmarkResult {
            name: fixture.name.clone(),
            project_path: project_path.to_string_lossy().to_string(),
            finding_count: findings.len(),
            severity_counts: count_by_severity(&findings),
            confidence_counts: count_by_confidence(&findings),
        };

        loaded.push(LoadedFixture {
            summary,
            expectation,
            findings,
        });
    }

    loaded.sort_by(|a, b| a.summary.name.cmp(&b.summary.name));

    let fixture_refs: Vec<(&FixtureExpectation, &[Finding])> = loaded
        .iter()
        .map(|f| (&f.expectation, f.findings.as_slice()))
        .collect();
    let dashboard = evaluate_accuracy(&fixture_refs);

    let mut detector_accuracy = Vec::new();
    for (name, metrics) in sorted_accuracy_rows(&dashboard.metrics) {
        if metrics.true_positives
            + metrics.false_positives
            + metrics.false_negatives
            + metrics.true_negatives
            == 0
        {
            continue;
        }
        detector_accuracy.push(DetectorAccuracyRow {
            detector: name.clone(),
            tp: metrics.true_positives,
            fp: metrics.false_positives,
            fn_count: metrics.false_negatives,
            tn: metrics.true_negatives,
            precision: metrics.precision(),
            recall: metrics.recall(),
            f1: metrics.f1(),
            evaluated_cases: metrics.total_cases(),
        });
    }

    let detector_finding_stats = aggregate_finding_stats(&loaded);

    let finding_count = loaded.iter().map(|f| f.findings.len()).sum::<usize>();
    let true_positives = dashboard
        .metrics
        .values()
        .map(|m| m.true_positives)
        .sum::<usize>();
    let false_positives = dashboard
        .metrics
        .values()
        .map(|m| m.false_positives)
        .sum::<usize>();
    let false_negatives = dashboard
        .metrics
        .values()
        .map(|m| m.false_negatives)
        .sum::<usize>();

    let totals = BenchmarkTotals {
        fixture_count: loaded.len(),
        detector_count: dashboard.detector_count,
        finding_count,
        true_positives,
        false_positives,
        false_negatives,
        evaluated_cases: dashboard.evaluated_cases,
        reviewed_cases: dashboard.reviewed_cases,
        unreviewed_cases: dashboard.unreviewed_cases,
        info_cases: dashboard.info_cases,
        business_logic_cases: dashboard.business_logic_cases,
        skipped_cases: dashboard.skipped_cases,
        unlabeled_triggered_cases: dashboard.unlabeled_triggered_cases,
        unreviewed_triggered_cases: dashboard.unreviewed_triggered_cases,
        precision: ratio(true_positives, true_positives + false_positives),
        recall: ratio(true_positives, true_positives + false_negatives),
        false_positive_rate: ratio(false_positives, true_positives + false_positives),
        annotation_coverage: dashboard.annotation_coverage(),
        reviewed_coverage: dashboard.reviewed_coverage(),
        unreviewed_rate: dashboard.unreviewed_rate(),
    };

    let gate_evaluation = evaluate_quality_gates(&totals, &manifest.quality_gates);

    Ok(BenchmarkSummary {
        schema_version: BENCHMARK_SCHEMA_VERSION.to_string(),
        manifest_path: manifest_path.to_string_lossy().to_string(),
        fixture_results: loaded.into_iter().map(|f| f.summary).collect(),
        detector_accuracy,
        detector_finding_stats,
        totals,
        quality_gates: manifest.quality_gates,
        gate_evaluation,
    })
}

pub fn evaluate_quality_gates(
    totals: &BenchmarkTotals,
    gates: &BenchmarkQualityGates,
) -> GateEvaluation {
    let mut violations = Vec::new();

    if let Some(min_tp) = gates.min_true_positives {
        if totals.true_positives < min_tp {
            violations.push(format!(
                "true positives {} below minimum {}",
                totals.true_positives, min_tp
            ));
        }
    }

    if let Some(min_precision) = gates.min_precision {
        match totals.precision {
            Some(p) if p < min_precision => violations.push(format!(
                "precision {:.3} below minimum {:.3}",
                p, min_precision
            )),
            None => violations.push("precision is undefined (no TP/FP cases)".to_string()),
            _ => {}
        }
    }

    if let Some(max_fp_rate) = gates.max_false_positive_rate {
        match totals.false_positive_rate {
            Some(r) if r > max_fp_rate => violations.push(format!(
                "false positive rate {:.3} above maximum {:.3}",
                r, max_fp_rate
            )),
            None => {
                violations.push("false positive rate is undefined (no TP/FP cases)".to_string())
            }
            _ => {}
        }
    }

    if let Some(min_cov) = gates.min_annotation_coverage {
        match totals.annotation_coverage {
            Some(c) if c < min_cov => violations.push(format!(
                "annotation coverage {:.3} below minimum {:.3}",
                c, min_cov
            )),
            None => violations.push("annotation coverage is undefined".to_string()),
            _ => {}
        }
    }

    if let Some(min_cov) = gates.min_reviewed_coverage {
        match totals.reviewed_coverage {
            Some(c) if c < min_cov => violations.push(format!(
                "reviewed coverage {:.3} below minimum {:.3}",
                c, min_cov
            )),
            None => violations.push("reviewed coverage is undefined".to_string()),
            _ => {}
        }
    }

    if let Some(max_unlabeled) = gates.max_unlabeled_triggered_cases {
        if totals.unlabeled_triggered_cases > max_unlabeled {
            violations.push(format!(
                "unlabeled triggered cases {} above maximum {}",
                totals.unlabeled_triggered_cases, max_unlabeled
            ));
        }
    }

    if let Some(max_unreviewed_triggered) = gates.max_unreviewed_triggered_cases {
        if totals.unreviewed_triggered_cases > max_unreviewed_triggered {
            violations.push(format!(
                "unreviewed triggered cases {} above maximum {}",
                totals.unreviewed_triggered_cases, max_unreviewed_triggered
            ));
        }
    }

    if let Some(max_unreviewed) = gates.max_unreviewed_labeled_cases {
        if totals.unreviewed_cases > max_unreviewed {
            violations.push(format!(
                "unreviewed labeled cases {} above maximum {}",
                totals.unreviewed_cases, max_unreviewed
            ));
        }
    }

    if let Some(max_rate) = gates.max_unreviewed_rate {
        match totals.unreviewed_rate {
            Some(r) if r > max_rate => violations.push(format!(
                "unreviewed rate {:.3} above maximum {:.3}",
                r, max_rate
            )),
            None => violations.push("unreviewed rate is undefined".to_string()),
            _ => {}
        }
    }

    GateEvaluation {
        passed: violations.is_empty(),
        violations,
    }
}

pub fn benchmark_summary_to_json(summary: &BenchmarkSummary) -> String {
    serde_json::to_string_pretty(summary).unwrap_or_else(|_| "{}".to_string())
}

pub fn format_benchmark_summary(summary: &BenchmarkSummary) -> String {
    let mut lines = Vec::new();
    lines.push("Aikido Benchmark Summary".to_string());
    lines.push("=".repeat(80));
    lines.push(format!("Manifest: {}", summary.manifest_path));
    lines.push(format!(
        "Fixtures: {}  Findings: {}",
        summary.totals.fixture_count, summary.totals.finding_count
    ));
    lines.push(format!(
        "TP: {}  FP: {}  FN: {}",
        summary.totals.true_positives,
        summary.totals.false_positives,
        summary.totals.false_negatives
    ));
    lines.push(format!(
        "Precision: {}  Recall: {}  FP rate: {}",
        format_ratio(summary.totals.precision),
        format_ratio(summary.totals.recall),
        format_ratio(summary.totals.false_positive_rate)
    ));
    lines.push(format!(
        "Annotation coverage: {}  Unlabeled triggered: {}",
        format_ratio(summary.totals.annotation_coverage),
        summary.totals.unlabeled_triggered_cases
    ));
    lines.push(format!(
        "Reviewed coverage: {}  UNREVIEWED labels: {}  UNREVIEWED triggered: {}",
        format_ratio(summary.totals.reviewed_coverage),
        summary.totals.unreviewed_cases,
        summary.totals.unreviewed_triggered_cases
    ));
    lines.push(format!(
        "UNREVIEWED rate: {}  INFO labels: {}  BUSINESS_LOGIC labels: {}",
        format_ratio(summary.totals.unreviewed_rate),
        summary.totals.info_cases,
        summary.totals.business_logic_cases
    ));
    lines.push("-".repeat(80));
    lines.push("Fixture results:".to_string());
    for fixture in &summary.fixture_results {
        lines.push(format!(
            "  - {}: {} findings ({})",
            fixture.name,
            fixture.finding_count,
            format_count_map(&fixture.severity_counts)
        ));
    }
    lines.push("-".repeat(80));
    lines.push(format!(
        "Quality gates: {}",
        if summary.gate_evaluation.passed {
            "PASS"
        } else {
            "FAIL"
        }
    ));
    if !summary.gate_evaluation.violations.is_empty() {
        for v in &summary.gate_evaluation.violations {
            lines.push(format!("  - {}", v));
        }
    }
    lines.join("\n")
}

fn resolve_from_base(base: &Path, raw: &str) -> PathBuf {
    let path = PathBuf::from(raw);
    if path.is_absolute() {
        path
    } else {
        base.join(path)
    }
}

fn resolve_fixture_path(project: &Path, raw: &str) -> PathBuf {
    let path = PathBuf::from(raw);
    if path.is_absolute() {
        path
    } else {
        project.join(path)
    }
}

fn sorted_accuracy_rows(
    metrics: &HashMap<String, crate::accuracy::DetectorMetrics>,
) -> Vec<(&String, &crate::accuracy::DetectorMetrics)> {
    let mut rows: Vec<_> = metrics.iter().collect();
    rows.sort_by_key(|(name, _)| *name);
    rows
}

fn aggregate_finding_stats(fixtures: &[LoadedFixture]) -> Vec<DetectorFindingStats> {
    let mut map: BTreeMap<String, DetectorFindingStats> = BTreeMap::new();

    for fixture in fixtures {
        for finding in &fixture.findings {
            let entry =
                map.entry(finding.detector_name.clone())
                    .or_insert_with(|| DetectorFindingStats {
                        detector: finding.detector_name.clone(),
                        findings: 0,
                        by_severity: BTreeMap::new(),
                        by_confidence: BTreeMap::new(),
                    });

            entry.findings += 1;
            *entry
                .by_severity
                .entry(finding.severity.to_string().to_lowercase())
                .or_insert(0) += 1;
            *entry
                .by_confidence
                .entry(finding.confidence.to_string().to_lowercase())
                .or_insert(0) += 1;
        }
    }

    map.into_values().collect()
}

fn count_by_severity(findings: &[Finding]) -> BTreeMap<String, usize> {
    let mut map = BTreeMap::new();
    for finding in findings {
        *map.entry(finding.severity.to_string().to_lowercase())
            .or_insert(0) += 1;
    }
    map
}

fn count_by_confidence(findings: &[Finding]) -> BTreeMap<String, usize> {
    let mut map = BTreeMap::new();
    for finding in findings {
        *map.entry(finding.confidence.to_string().to_lowercase())
            .or_insert(0) += 1;
    }
    map
}

fn ratio(num: usize, denom: usize) -> Option<f64> {
    if denom == 0 {
        None
    } else {
        Some(num as f64 / denom as f64)
    }
}

fn format_ratio(r: Option<f64>) -> String {
    r.map(|v| format!("{:.1}%", v * 100.0))
        .unwrap_or_else(|| "N/A".to_string())
}

fn format_count_map(map: &BTreeMap<String, usize>) -> String {
    map.iter()
        .map(|(k, v)| format!("{k}:{v}"))
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_manifest_defaults_accuracy_file() {
        let dir = tempfile::tempdir().unwrap();
        let manifest_path = dir.path().join("benchmark.toml");
        std::fs::write(
            &manifest_path,
            r#"
[[fixtures]]
name = "fixture-a"
project = "fixtures/a"
"#,
        )
        .unwrap();

        let manifest = BenchmarkManifest::load(&manifest_path).unwrap();
        assert_eq!(manifest.fixtures.len(), 1);
        assert_eq!(manifest.fixtures[0].accuracy, ".aikido-accuracy.toml");
    }

    #[test]
    fn test_evaluate_quality_gates_pass() {
        let totals = BenchmarkTotals {
            fixture_count: 1,
            detector_count: 75,
            finding_count: 5,
            true_positives: 4,
            false_positives: 1,
            false_negatives: 1,
            evaluated_cases: 10,
            reviewed_cases: 8,
            unreviewed_cases: 1,
            info_cases: 1,
            business_logic_cases: 0,
            skipped_cases: 0,
            unlabeled_triggered_cases: 0,
            unreviewed_triggered_cases: 0,
            precision: Some(0.8),
            recall: Some(0.8),
            false_positive_rate: Some(0.2),
            annotation_coverage: Some(0.8),
            reviewed_coverage: Some(0.7),
            unreviewed_rate: Some(0.1),
        };
        let gates = BenchmarkQualityGates {
            min_true_positives: Some(3),
            min_precision: Some(0.7),
            max_false_positive_rate: Some(0.3),
            min_annotation_coverage: Some(0.5),
            min_reviewed_coverage: Some(0.6),
            max_unlabeled_triggered_cases: Some(2),
            max_unreviewed_triggered_cases: Some(1),
            max_unreviewed_labeled_cases: Some(2),
            max_unreviewed_rate: Some(0.2),
        };

        let eval = evaluate_quality_gates(&totals, &gates);
        assert!(eval.passed);
        assert!(eval.violations.is_empty());
    }

    #[test]
    fn test_evaluate_quality_gates_failures() {
        let totals = BenchmarkTotals {
            fixture_count: 1,
            detector_count: 75,
            finding_count: 5,
            true_positives: 1,
            false_positives: 3,
            false_negatives: 5,
            evaluated_cases: 10,
            reviewed_cases: 2,
            unreviewed_cases: 4,
            info_cases: 0,
            business_logic_cases: 0,
            skipped_cases: 100,
            unlabeled_triggered_cases: 9,
            unreviewed_triggered_cases: 5,
            precision: Some(0.25),
            recall: Some(0.166),
            false_positive_rate: Some(0.75),
            annotation_coverage: Some(0.09),
            reviewed_coverage: Some(0.02),
            unreviewed_rate: Some(0.666),
        };
        let gates = BenchmarkQualityGates {
            min_true_positives: Some(2),
            min_precision: Some(0.5),
            max_false_positive_rate: Some(0.4),
            min_annotation_coverage: Some(0.1),
            min_reviewed_coverage: Some(0.1),
            max_unlabeled_triggered_cases: Some(4),
            max_unreviewed_triggered_cases: Some(2),
            max_unreviewed_labeled_cases: Some(1),
            max_unreviewed_rate: Some(0.2),
        };

        let eval = evaluate_quality_gates(&totals, &gates);
        assert!(!eval.passed);
        assert_eq!(eval.violations.len(), 9);
    }
}
