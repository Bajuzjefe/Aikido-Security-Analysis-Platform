//! Feature #105: Detector accuracy dashboard — track precision/recall per detector across test fixtures.
//!
//! Provides a framework for measuring detector accuracy by comparing actual findings
//! against annotated expectations (true positives, false negatives, false positives).

use crate::detector::{all_detectors, Finding};
use std::collections::{HashMap, HashSet};
use std::path::Path;

/// Annotation for a fixture: which detectors SHOULD fire and which SHOULD NOT.
#[derive(Debug, Clone)]
pub struct FixtureExpectation {
    /// Name of the fixture/project.
    pub fixture_name: String,
    /// Detectors that MUST fire (true positives expected).
    pub expected_detectors: HashSet<String>,
    /// Detectors that MUST NOT fire (known true negatives).
    pub unexpected_detectors: HashSet<String>,
    /// Per-detector label schema v2 records.
    pub labels: HashMap<String, FindingLabel>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LabelClassification {
    Tp,
    Fp,
    Info,
    BusinessLogic,
    Unreviewed,
}

#[derive(Debug, Clone)]
pub struct FindingLabel {
    pub detector: String,
    pub classification: LabelClassification,
    pub rationale: Option<String>,
    pub audit_mapping: Option<AuditMapping>,
}

#[derive(Debug, Clone)]
pub struct AuditMapping {
    pub audit_id: String,
    pub source: Option<String>,
}

impl LabelClassification {
    fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_uppercase().as_str() {
            "TP" => Some(Self::Tp),
            "FP" => Some(Self::Fp),
            "INFO" => Some(Self::Info),
            "BUSINESS_LOGIC" => Some(Self::BusinessLogic),
            "UNREVIEWED" => Some(Self::Unreviewed),
            _ => None,
        }
    }
}

impl FixtureExpectation {
    pub fn new(name: &str) -> Self {
        Self {
            fixture_name: name.to_string(),
            expected_detectors: HashSet::new(),
            unexpected_detectors: HashSet::new(),
            labels: HashMap::new(),
        }
    }

    pub fn expect(mut self, detector: &str) -> Self {
        self.expected_detectors.insert(detector.to_string());
        self.labels
            .entry(detector.to_string())
            .or_insert_with(|| FindingLabel {
                detector: detector.to_string(),
                classification: LabelClassification::Tp,
                rationale: None,
                audit_mapping: None,
            });
        self
    }

    pub fn reject(mut self, detector: &str) -> Self {
        self.unexpected_detectors.insert(detector.to_string());
        self.labels
            .entry(detector.to_string())
            .or_insert_with(|| FindingLabel {
                detector: detector.to_string(),
                classification: LabelClassification::Fp,
                rationale: None,
                audit_mapping: None,
            });
        self
    }

    pub fn add_label(
        &mut self,
        detector: &str,
        classification: LabelClassification,
        rationale: Option<String>,
        audit_mapping: Option<AuditMapping>,
    ) {
        if classification == LabelClassification::Tp {
            self.expected_detectors.insert(detector.to_string());
        } else if classification == LabelClassification::Fp {
            self.unexpected_detectors.insert(detector.to_string());
        }

        self.labels.insert(
            detector.to_string(),
            FindingLabel {
                detector: detector.to_string(),
                classification,
                rationale,
                audit_mapping,
            },
        );
    }

    fn classification_for(&self, detector: &str) -> Option<LabelClassification> {
        if let Some(label) = self.labels.get(detector) {
            return Some(label.classification.clone());
        }
        if self.expected_detectors.contains(detector) {
            return Some(LabelClassification::Tp);
        }
        if self.unexpected_detectors.contains(detector) {
            return Some(LabelClassification::Fp);
        }
        None
    }

    pub fn labeled_count(&self) -> usize {
        self.labels.len()
    }
}

/// Per-detector accuracy metrics.
#[derive(Debug, Clone, Default)]
pub struct DetectorMetrics {
    /// Number of fixtures where detector correctly fired (true positive).
    pub true_positives: usize,
    /// Number of fixtures where detector incorrectly fired (false positive).
    pub false_positives: usize,
    /// Number of fixtures where detector should have fired but didn't (false negative).
    pub false_negatives: usize,
    /// Number of fixtures where detector correctly didn't fire (true negative).
    pub true_negatives: usize,
}

impl DetectorMetrics {
    /// Precision = TP / (TP + FP). Returns None if no positive predictions.
    pub fn precision(&self) -> Option<f64> {
        let denom = self.true_positives + self.false_positives;
        if denom == 0 {
            None
        } else {
            Some(self.true_positives as f64 / denom as f64)
        }
    }

    /// Recall = TP / (TP + FN). Returns None if no expected positives.
    pub fn recall(&self) -> Option<f64> {
        let denom = self.true_positives + self.false_negatives;
        if denom == 0 {
            None
        } else {
            Some(self.true_positives as f64 / denom as f64)
        }
    }

    /// F1 score = 2 * precision * recall / (precision + recall).
    pub fn f1(&self) -> Option<f64> {
        let p = self.precision()?;
        let r = self.recall()?;
        if p + r == 0.0 {
            Some(0.0)
        } else {
            Some(2.0 * p * r / (p + r))
        }
    }

    /// Total test cases this detector was evaluated against.
    pub fn total_cases(&self) -> usize {
        self.true_positives + self.false_positives + self.false_negatives + self.true_negatives
    }
}

/// Aggregate accuracy dashboard across all detectors and fixtures.
#[derive(Debug, Clone)]
pub struct AccuracyDashboard {
    pub metrics: HashMap<String, DetectorMetrics>,
    /// Number of fixtures included in this dashboard.
    pub fixture_count: usize,
    /// Number of detectors considered per fixture.
    pub detector_count: usize,
    /// Number of detector/fixture pairs with explicit annotations.
    pub evaluated_cases: usize,
    /// Number of detector/fixture pairs with non-UNREVIEWED labels.
    pub reviewed_cases: usize,
    /// Number of detector/fixture pairs labeled as UNREVIEWED.
    pub unreviewed_cases: usize,
    /// Number of detector/fixture pairs labeled as INFO.
    pub info_cases: usize,
    /// Number of detector/fixture pairs labeled as BUSINESS_LOGIC.
    pub business_logic_cases: usize,
    /// Number of detector/fixture pairs skipped due to missing annotations.
    pub skipped_cases: usize,
    /// Number of skipped detector/fixture pairs where the detector still fired.
    /// These are "silent blind spots" in the benchmark.
    pub unlabeled_triggered_cases: usize,
    /// Number of UNREVIEWED-labeled detector/fixture pairs where detector fired.
    pub unreviewed_triggered_cases: usize,
}

impl AccuracyDashboard {
    /// Total detector/fixture pairs in this dashboard.
    pub fn total_cases(&self) -> usize {
        self.fixture_count * self.detector_count
    }

    pub fn labeled_cases(&self) -> usize {
        self.reviewed_cases + self.unreviewed_cases
    }

    /// How much of the total surface has explicit labels (v1 or v2).
    pub fn annotation_coverage(&self) -> Option<f64> {
        let total = self.total_cases();
        if total == 0 {
            None
        } else {
            Some(self.labeled_cases() as f64 / total as f64)
        }
    }

    /// Coverage excluding UNREVIEWED labels.
    pub fn reviewed_coverage(&self) -> Option<f64> {
        let total = self.total_cases();
        if total == 0 {
            None
        } else {
            Some(self.reviewed_cases as f64 / total as f64)
        }
    }

    /// Fraction of labeled cases still marked as UNREVIEWED.
    pub fn unreviewed_rate(&self) -> Option<f64> {
        let labeled = self.labeled_cases();
        if labeled == 0 {
            None
        } else {
            Some(self.unreviewed_cases as f64 / labeled as f64)
        }
    }
}

/// Evaluate detector accuracy against fixture expectations.
///
/// For each fixture, compares the actual findings against the expectation
/// to classify each detector result as TP, FP, FN, or TN.
pub fn evaluate_accuracy(
    fixture_results: &[(&FixtureExpectation, &[Finding])],
) -> AccuracyDashboard {
    let all_detector_names: Vec<String> = all_detectors()
        .iter()
        .map(|d| d.name().to_string())
        .collect();
    let fixture_count = fixture_results.len();
    let detector_count = all_detector_names.len();
    let mut metrics: HashMap<String, DetectorMetrics> = HashMap::new();
    let mut evaluated_cases = 0;
    let mut reviewed_cases = 0;
    let mut unreviewed_cases = 0;
    let mut info_cases = 0;
    let mut business_logic_cases = 0;
    let mut skipped_cases = 0;
    let mut unlabeled_triggered_cases = 0;
    let mut unreviewed_triggered_cases = 0;

    for name in &all_detector_names {
        metrics.entry(name.clone()).or_default();
    }

    for (expectation, findings) in fixture_results {
        let triggered: HashSet<String> = findings.iter().map(|f| f.detector_name.clone()).collect();

        for detector_name in &all_detector_names {
            let m = metrics.entry(detector_name.clone()).or_default();
            let did_fire = triggered.contains(detector_name);
            match expectation.classification_for(detector_name) {
                Some(LabelClassification::Tp) => {
                    reviewed_cases += 1;
                    evaluated_cases += 1;
                    if did_fire {
                        m.true_positives += 1;
                    } else {
                        m.false_negatives += 1;
                    }
                }
                Some(LabelClassification::Fp) => {
                    reviewed_cases += 1;
                    evaluated_cases += 1;
                    if did_fire {
                        m.false_positives += 1;
                    } else {
                        m.true_negatives += 1;
                    }
                }
                Some(LabelClassification::Info) => {
                    reviewed_cases += 1;
                    info_cases += 1;
                }
                Some(LabelClassification::BusinessLogic) => {
                    reviewed_cases += 1;
                    business_logic_cases += 1;
                }
                Some(LabelClassification::Unreviewed) => {
                    unreviewed_cases += 1;
                    if did_fire {
                        unreviewed_triggered_cases += 1;
                    }
                }
                None => {
                    skipped_cases += 1;
                    if did_fire {
                        unlabeled_triggered_cases += 1;
                    }
                }
            }
        }
    }

    AccuracyDashboard {
        metrics,
        fixture_count,
        detector_count,
        evaluated_cases,
        reviewed_cases,
        unreviewed_cases,
        info_cases,
        business_logic_cases,
        skipped_cases,
        unlabeled_triggered_cases,
        unreviewed_triggered_cases,
    }
}

/// Format the accuracy dashboard as a human-readable table.
pub fn format_dashboard(dashboard: &AccuracyDashboard) -> String {
    let mut lines = Vec::new();
    lines.push("Detector Accuracy Dashboard".to_string());
    lines.push("=".repeat(80));
    lines.push(format!(
        "{:<40} {:>4} {:>4} {:>4} {:>4} {:>8} {:>8}",
        "Detector", "TP", "FP", "FN", "TN", "Prec.", "Recall"
    ));
    lines.push("-".repeat(80));

    let mut sorted_detectors: Vec<_> = dashboard.metrics.iter().collect();
    sorted_detectors.sort_by_key(|(name, _)| (*name).clone());

    for (name, m) in &sorted_detectors {
        // Skip detectors with no test cases
        if m.total_cases() == 0 {
            continue;
        }

        let prec = m
            .precision()
            .map(|p| format!("{:.0}%", p * 100.0))
            .unwrap_or_else(|| "N/A".to_string());
        let recall = m
            .recall()
            .map(|r| format!("{:.0}%", r * 100.0))
            .unwrap_or_else(|| "N/A".to_string());

        lines.push(format!(
            "{:<40} {:>4} {:>4} {:>4} {:>4} {:>8} {:>8}",
            name,
            m.true_positives,
            m.false_positives,
            m.false_negatives,
            m.true_negatives,
            prec,
            recall
        ));
    }

    lines.push("-".repeat(80));

    // Summary
    let total_tp: usize = dashboard.metrics.values().map(|m| m.true_positives).sum();
    let total_fp: usize = dashboard.metrics.values().map(|m| m.false_positives).sum();
    let total_fn: usize = dashboard.metrics.values().map(|m| m.false_negatives).sum();

    let overall_prec = if total_tp + total_fp > 0 {
        format!(
            "{:.0}%",
            total_tp as f64 / (total_tp + total_fp) as f64 * 100.0
        )
    } else {
        "N/A".to_string()
    };
    let overall_recall = if total_tp + total_fn > 0 {
        format!(
            "{:.0}%",
            total_tp as f64 / (total_tp + total_fn) as f64 * 100.0
        )
    } else {
        "N/A".to_string()
    };

    lines.push(format!(
        "Overall: {total_tp} TP, {total_fp} FP, {total_fn} FN — Precision: {overall_prec}, Recall: {overall_recall}",
    ));
    let coverage = dashboard
        .annotation_coverage()
        .map(|c| format!("{:.1}%", c * 100.0))
        .unwrap_or_else(|| "N/A".to_string());
    let reviewed_coverage = dashboard
        .reviewed_coverage()
        .map(|c| format!("{:.1}%", c * 100.0))
        .unwrap_or_else(|| "N/A".to_string());
    let unreviewed_rate = dashboard
        .unreviewed_rate()
        .map(|r| format!("{:.1}%", r * 100.0))
        .unwrap_or_else(|| "N/A".to_string());
    lines.push(format!(
        "Label coverage: {} / {} ({coverage})",
        dashboard.labeled_cases(),
        dashboard.total_cases()
    ));
    lines.push(format!(
        "Reviewed coverage: {} / {} ({reviewed_coverage})",
        dashboard.reviewed_cases,
        dashboard.total_cases()
    ));
    lines.push(format!(
        "UNREVIEWED labels: {} (rate: {unreviewed_rate})",
        dashboard.unreviewed_cases
    ));
    lines.push(format!(
        "INFO labels: {}  BUSINESS_LOGIC labels: {}",
        dashboard.info_cases, dashboard.business_logic_cases
    ));
    lines.push(format!(
        "Unlabeled triggered cases: {}",
        dashboard.unlabeled_triggered_cases
    ));
    lines.push(format!(
        "UNREVIEWED triggered cases: {}",
        dashboard.unreviewed_triggered_cases
    ));

    lines.join("\n")
}

/// Format the dashboard as JSON for programmatic consumption.
pub fn dashboard_to_json(dashboard: &AccuracyDashboard) -> String {
    let mut entries: Vec<String> = Vec::new();

    let mut sorted_detectors: Vec<_> = dashboard.metrics.iter().collect();
    sorted_detectors.sort_by_key(|(name, _)| (*name).clone());

    for (name, m) in &sorted_detectors {
        if m.total_cases() == 0 {
            continue;
        }
        let prec = m
            .precision()
            .map(|p| format!("{p:.4}"))
            .unwrap_or_else(|| "null".to_string());
        let recall = m
            .recall()
            .map(|r| format!("{r:.4}"))
            .unwrap_or_else(|| "null".to_string());
        let f1 = m
            .f1()
            .map(|f| format!("{f:.4}"))
            .unwrap_or_else(|| "null".to_string());

        entries.push(format!(
            r#"    {{"detector":"{}","tp":{},"fp":{},"fn":{},"tn":{},"precision":{},"recall":{},"f1":{}}}"#,
            name, m.true_positives, m.false_positives, m.false_negatives, m.true_negatives,
            prec, recall, f1
        ));
    }

    let coverage = dashboard
        .annotation_coverage()
        .map(|c| format!("{c:.4}"))
        .unwrap_or_else(|| "null".to_string());
    let reviewed_coverage = dashboard
        .reviewed_coverage()
        .map(|c| format!("{c:.4}"))
        .unwrap_or_else(|| "null".to_string());
    let unreviewed_rate = dashboard
        .unreviewed_rate()
        .map(|c| format!("{c:.4}"))
        .unwrap_or_else(|| "null".to_string());
    format!(
        "{{\n  \"fixture_count\":{},\n  \"detector_count\":{},\n  \"total_cases\":{},\n  \"evaluated_cases\":{},\n  \"reviewed_cases\":{},\n  \"unreviewed_cases\":{},\n  \"info_cases\":{},\n  \"business_logic_cases\":{},\n  \"skipped_cases\":{},\n  \"unlabeled_triggered_cases\":{},\n  \"unreviewed_triggered_cases\":{},\n  \"annotation_coverage\":{},\n  \"reviewed_coverage\":{},\n  \"unreviewed_rate\":{},\n  \"detectors\":[\n{}\n  ]\n}}",
        dashboard.fixture_count,
        dashboard.detector_count,
        dashboard.total_cases(),
        dashboard.evaluated_cases,
        dashboard.reviewed_cases,
        dashboard.unreviewed_cases,
        dashboard.info_cases,
        dashboard.business_logic_cases,
        dashboard.skipped_cases,
        dashboard.unlabeled_triggered_cases,
        dashboard.unreviewed_triggered_cases,
        coverage,
        reviewed_coverage,
        unreviewed_rate,
        entries.join(",\n")
    )
}

/// Load fixture expectations from a TOML file.
///
/// Supported TOML formats:
/// ```toml
/// expected = ["detector-a", "detector-b"]
/// unexpected = ["detector-c"]
///
/// [[labels]]
/// detector = "detector-d"
/// classification = "TP" # TP|FP|INFO|BUSINESS_LOGIC|UNREVIEWED
/// rationale = "matches external audit finding"
/// audit_id = "AUD-12"
/// source = "company-audit-2026"
/// ```
pub fn load_expectations_from_toml(path: &Path) -> Result<FixtureExpectation, String> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;

    let file: ExpectationFile =
        toml::from_str(&content).map_err(|e| format!("invalid TOML in {}: {e}", path.display()))?;

    let fixture_name = path
        .parent()
        .and_then(|p| p.file_name())
        .and_then(|n| n.to_str())
        .unwrap_or("unknown")
        .to_string();

    let mut expectation = FixtureExpectation::new(&fixture_name);

    for detector in file.expected.unwrap_or_default() {
        expectation.expected_detectors.insert(detector.clone());
        expectation
            .labels
            .entry(detector.clone())
            .or_insert_with(|| FindingLabel {
                detector,
                classification: LabelClassification::Tp,
                rationale: None,
                audit_mapping: None,
            });
    }

    for detector in file.unexpected.unwrap_or_default() {
        expectation.unexpected_detectors.insert(detector.clone());
        expectation
            .labels
            .entry(detector.clone())
            .or_insert_with(|| FindingLabel {
                detector,
                classification: LabelClassification::Fp,
                rationale: None,
                audit_mapping: None,
            });
    }

    for label in file.labels.unwrap_or_default() {
        let Some(classification) = LabelClassification::parse(&label.classification) else {
            return Err(format!(
                "invalid label classification '{}' in {} (detector '{}')",
                label.classification,
                path.display(),
                label.detector
            ));
        };

        let audit_mapping = label.audit_id.map(|audit_id| AuditMapping {
            audit_id,
            source: label.source,
        });

        expectation.add_label(
            &label.detector,
            classification,
            label.rationale,
            audit_mapping,
        );
    }

    Ok(expectation)
}

#[derive(Debug, serde::Deserialize)]
struct ExpectationFile {
    expected: Option<Vec<String>>,
    unexpected: Option<Vec<String>>,
    labels: Option<Vec<ExpectationLabel>>,
}

#[derive(Debug, serde::Deserialize)]
struct ExpectationLabel {
    detector: String,
    classification: String,
    rationale: Option<String>,
    audit_id: Option<String>,
    source: Option<String>,
}

pub fn validate_expectation_v2(expectation: &FixtureExpectation) -> Vec<String> {
    let mut errors = Vec::new();

    for (detector, label) in &expectation.labels {
        if label.rationale.is_none()
            && matches!(
                label.classification,
                LabelClassification::Tp
                    | LabelClassification::Fp
                    | LabelClassification::BusinessLogic
            )
        {
            errors.push(format!(
                "label for detector '{}' should include rationale in schema v2",
                detector
            ));
        }
    }

    for (detector, label) in &expectation.labels {
        if matches!(
            label.classification,
            LabelClassification::Tp | LabelClassification::Fp | LabelClassification::BusinessLogic
        ) && label.audit_mapping.is_none()
        {
            errors.push(format!(
                "label for detector '{}' should include audit mapping (audit_id/source) in schema v2",
                detector
            ));
        }
    }

    errors
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detector::{Confidence, Severity, SourceLocation};

    fn make_finding(detector: &str) -> Finding {
        Finding {
            detector_name: detector.to_string(),
            severity: Severity::High,
            confidence: Confidence::Likely,
            title: "Test".to_string(),
            description: "Test".to_string(),
            module: "test".to_string(),
            location: Some(SourceLocation::from_bytes("test.ak", 0, 10)),
            suggestion: None,
            related_findings: vec![],
            semantic_group: None,

            evidence: None,
        }
    }

    #[test]
    fn test_true_positive() {
        let exp = FixtureExpectation::new("test").expect("double-satisfaction");
        let findings = vec![make_finding("double-satisfaction")];
        let dashboard = evaluate_accuracy(&[(&exp, &findings)]);
        let m = &dashboard.metrics["double-satisfaction"];
        assert_eq!(m.true_positives, 1);
        assert_eq!(m.false_negatives, 0);
    }

    #[test]
    fn test_false_negative() {
        let exp = FixtureExpectation::new("test").expect("double-satisfaction");
        let findings: Vec<Finding> = vec![];
        let dashboard = evaluate_accuracy(&[(&exp, &findings)]);
        let m = &dashboard.metrics["double-satisfaction"];
        assert_eq!(m.true_positives, 0);
        assert_eq!(m.false_negatives, 1);
    }

    #[test]
    fn test_false_positive() {
        let exp = FixtureExpectation::new("test").reject("double-satisfaction");
        let findings = vec![make_finding("double-satisfaction")];
        let dashboard = evaluate_accuracy(&[(&exp, &findings)]);
        let m = &dashboard.metrics["double-satisfaction"];
        assert_eq!(m.false_positives, 1);
        assert_eq!(m.true_negatives, 0);
    }

    #[test]
    fn test_true_negative() {
        let exp = FixtureExpectation::new("test").reject("double-satisfaction");
        let findings: Vec<Finding> = vec![];
        let dashboard = evaluate_accuracy(&[(&exp, &findings)]);
        let m = &dashboard.metrics["double-satisfaction"];
        assert_eq!(m.false_positives, 0);
        assert_eq!(m.true_negatives, 1);
    }

    #[test]
    fn test_precision_recall() {
        let m = DetectorMetrics {
            true_positives: 8,
            false_positives: 2,
            false_negatives: 1,
            true_negatives: 5,
        };

        let prec = m.precision().unwrap();
        assert!((prec - 0.8).abs() < 0.001);

        let recall = m.recall().unwrap();
        assert!((recall - 0.8889).abs() < 0.001);

        let f1 = m.f1().unwrap();
        assert!(f1 > 0.8 && f1 < 0.9);
    }

    #[test]
    fn test_precision_no_positives() {
        let m = DetectorMetrics::default();
        assert!(m.precision().is_none());
        assert!(m.recall().is_none());
        assert!(m.f1().is_none());
    }

    #[test]
    fn test_format_dashboard_not_empty() {
        let exp = FixtureExpectation::new("test")
            .expect("double-satisfaction")
            .reject("missing-signature-check");
        let findings = vec![make_finding("double-satisfaction")];
        let dashboard = evaluate_accuracy(&[(&exp, &findings)]);
        let output = format_dashboard(&dashboard);
        assert!(output.contains("Detector Accuracy Dashboard"));
        assert!(output.contains("double-satisfaction"));
        assert!(output.contains("100%"));
    }

    #[test]
    fn test_dashboard_json_valid() {
        let exp = FixtureExpectation::new("test").expect("double-satisfaction");
        let findings = vec![make_finding("double-satisfaction")];
        let dashboard = evaluate_accuracy(&[(&exp, &findings)]);
        let json = dashboard_to_json(&dashboard);
        assert!(json.contains("\"fixture_count\":1"));
        assert!(json.contains("\"evaluated_cases\":1"));
        assert!(json.contains("\"detector\":\"double-satisfaction\""));
        assert!(json.contains("\"tp\":1"));
    }

    #[test]
    fn test_multiple_fixtures() {
        let exp1 = FixtureExpectation::new("fixture-a")
            .expect("double-satisfaction")
            .expect("missing-signature-check");
        let exp2 = FixtureExpectation::new("fixture-b")
            .expect("double-satisfaction")
            .reject("missing-signature-check");

        let findings1 = vec![
            make_finding("double-satisfaction"),
            make_finding("missing-signature-check"),
        ];
        let findings2 = vec![make_finding("double-satisfaction")];

        let dashboard = evaluate_accuracy(&[(&exp1, &findings1), (&exp2, &findings2)]);

        let ds = &dashboard.metrics["double-satisfaction"];
        assert_eq!(ds.true_positives, 2); // Fired correctly in both

        let ms = &dashboard.metrics["missing-signature-check"];
        assert_eq!(ms.true_positives, 1); // Fired correctly in fixture-a
        assert_eq!(ms.true_negatives, 1); // Correctly absent in fixture-b
    }

    #[test]
    fn test_fixture_expectation_builder() {
        let exp = FixtureExpectation::new("test")
            .expect("a")
            .expect("b")
            .reject("c");
        assert_eq!(exp.fixture_name, "test");
        assert_eq!(exp.expected_detectors.len(), 2);
        assert_eq!(exp.unexpected_detectors.len(), 1);
        assert_eq!(exp.labeled_count(), 3);
    }

    #[test]
    fn test_load_expectations_from_toml() {
        let dir = std::env::temp_dir().join("aikido-accuracy-test");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join(".aikido-accuracy.toml");
        std::fs::write(
            &path,
            r#"
expected = ["double-satisfaction", "missing-signature-check"]
unexpected = ["dead-code-path"]
"#,
        )
        .unwrap();

        let exp = load_expectations_from_toml(&path).unwrap();
        assert_eq!(exp.expected_detectors.len(), 2);
        assert!(exp.expected_detectors.contains("double-satisfaction"));
        assert!(exp.expected_detectors.contains("missing-signature-check"));
        assert_eq!(exp.unexpected_detectors.len(), 1);
        assert!(exp.unexpected_detectors.contains("dead-code-path"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_load_expectations_from_toml_missing_file() {
        let path = std::path::PathBuf::from("/nonexistent/.aikido-accuracy.toml");
        assert!(load_expectations_from_toml(&path).is_err());
    }

    #[test]
    fn test_annotation_coverage_and_unlabeled_triggered() {
        let exp = FixtureExpectation::new("fixture-a")
            .expect("double-satisfaction")
            .reject("missing-signature-check");
        let findings = vec![
            make_finding("double-satisfaction"),
            make_finding("unbounded-list-iteration"),
        ];

        let dashboard = evaluate_accuracy(&[(&exp, &findings)]);
        assert_eq!(dashboard.fixture_count, 1);
        assert!(dashboard.detector_count >= 2);
        assert_eq!(dashboard.evaluated_cases, 2);
        assert_eq!(dashboard.unlabeled_triggered_cases, 1);
        assert!(dashboard.skipped_cases > 0);
        assert!(dashboard.annotation_coverage().is_some());

        let rendered = format_dashboard(&dashboard);
        assert!(rendered.contains("Label coverage"));
        assert!(rendered.contains("Unlabeled triggered cases"));
    }

    #[test]
    fn test_load_expectations_v2_labels() {
        let dir = std::env::temp_dir().join("aikido-accuracy-test-v2");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join(".aikido-accuracy.toml");
        std::fs::write(
            &path,
            r#"
[[labels]]
detector = "double-satisfaction"
classification = "TP"
rationale = "matches audited finding"
audit_id = "AUD-1"
source = "strike-v1"

[[labels]]
detector = "magic-numbers"
classification = "UNREVIEWED"
"#,
        )
        .unwrap();

        let exp = load_expectations_from_toml(&path).unwrap();
        assert_eq!(exp.labeled_count(), 2);
        assert_eq!(
            exp.classification_for("double-satisfaction"),
            Some(LabelClassification::Tp)
        );
        assert_eq!(
            exp.classification_for("magic-numbers"),
            Some(LabelClassification::Unreviewed)
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
