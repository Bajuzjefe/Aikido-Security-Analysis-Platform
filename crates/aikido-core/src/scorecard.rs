//! Detector Scorecard system — data-driven tier promotion/demotion for detectors.
//!
//! Evaluates each detector against accuracy data and tier criteria to determine
//! whether it should be promoted (e.g., Experimental -> Beta -> Stable) or demoted,
//! and produces formatted reports for CI quality gates.

use serde::{Deserialize, Serialize};

use crate::accuracy::AccuracyDashboard;
use crate::cwc::cwc_for_detector;
use crate::detector::{all_detectors, detector_reliability_tier, DetectorReliabilityTier};

// ---------------------------------------------------------------------------
// Tier criteria constants
// ---------------------------------------------------------------------------

/// Criteria a detector must meet to qualify for a given tier.
#[derive(Debug, Clone)]
pub struct TierCriteria {
    pub min_true_positives: usize,
    pub max_fp_rate: f64,
    pub min_fixtures: usize,
    pub requires_path_sensitivity: bool,
    pub requires_smt: bool,
    pub requires_simulation: bool,
    pub requires_cwc: bool,
}

/// Criteria for the Experimental tier.
pub const EXPERIMENTAL_CRITERIA: TierCriteria = TierCriteria {
    min_true_positives: 5,
    max_fp_rate: 0.40,
    min_fixtures: 1,
    requires_path_sensitivity: false,
    requires_smt: false,
    requires_simulation: false,
    requires_cwc: false,
};

/// Criteria for the Beta tier.
pub const BETA_CRITERIA: TierCriteria = TierCriteria {
    min_true_positives: 20,
    max_fp_rate: 0.20,
    min_fixtures: 3,
    requires_path_sensitivity: false,
    requires_smt: false,
    requires_simulation: false,
    requires_cwc: false,
};

/// Criteria for the Stable tier.
pub const STABLE_CRITERIA: TierCriteria = TierCriteria {
    min_true_positives: 50,
    max_fp_rate: 0.05,
    min_fixtures: 5,
    requires_path_sensitivity: true,
    requires_smt: true,
    requires_simulation: false,
    requires_cwc: true,
};

/// Returns the `TierCriteria` for a given tier.
pub fn criteria_for_tier(tier: DetectorReliabilityTier) -> &'static TierCriteria {
    match tier {
        DetectorReliabilityTier::Experimental => &EXPERIMENTAL_CRITERIA,
        DetectorReliabilityTier::Beta => &BETA_CRITERIA,
        DetectorReliabilityTier::Stable => &STABLE_CRITERIA,
    }
}

// ---------------------------------------------------------------------------
// Scorecard types
// ---------------------------------------------------------------------------

/// Per-detector evaluation scorecard.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectorScorecard {
    pub detector_name: String,
    pub current_tier: DetectorReliabilityTier,
    pub recommended_tier: DetectorReliabilityTier,
    pub true_positives: usize,
    pub false_positives: usize,
    pub total_findings: usize,
    pub fp_rate: f64,
    pub fixture_coverage: usize,
    pub has_path_sensitivity: bool,
    pub has_smt_integration: bool,
    pub has_simulation_test: bool,
    pub has_cwc_mapping: bool,
    pub promotion_eligible: bool,
    pub demotion_risk: bool,
    pub notes: Vec<String>,
}

/// Result of evaluating a quality gate against a set of scorecards.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QualityGateResult {
    pub passed: bool,
    pub violations: Vec<String>,
    pub summary: String,
}

// ---------------------------------------------------------------------------
// Tier ordering helpers
// ---------------------------------------------------------------------------

/// Numeric ordering: Experimental(0) < Beta(1) < Stable(2).
fn tier_ord(tier: DetectorReliabilityTier) -> u8 {
    match tier {
        DetectorReliabilityTier::Experimental => 0,
        DetectorReliabilityTier::Beta => 1,
        DetectorReliabilityTier::Stable => 2,
    }
}

/// Returns the next tier up from the given tier, if any.
fn next_tier(tier: DetectorReliabilityTier) -> Option<DetectorReliabilityTier> {
    match tier {
        DetectorReliabilityTier::Experimental => Some(DetectorReliabilityTier::Beta),
        DetectorReliabilityTier::Beta => Some(DetectorReliabilityTier::Stable),
        DetectorReliabilityTier::Stable => None,
    }
}

/// Returns the previous tier down from the given tier, if any.
#[allow(dead_code)]
fn prev_tier(tier: DetectorReliabilityTier) -> Option<DetectorReliabilityTier> {
    match tier {
        DetectorReliabilityTier::Experimental => None,
        DetectorReliabilityTier::Beta => Some(DetectorReliabilityTier::Experimental),
        DetectorReliabilityTier::Stable => Some(DetectorReliabilityTier::Beta),
    }
}

// ---------------------------------------------------------------------------
// Scorecard evaluation
// ---------------------------------------------------------------------------

/// Check whether a detector meets the quantitative criteria for a given tier.
#[allow(clippy::too_many_arguments)]
fn meets_criteria(
    criteria: &TierCriteria,
    tp: usize,
    fp_rate: f64,
    fixture_coverage: usize,
    has_path_sensitivity: bool,
    has_smt: bool,
    _has_simulation: bool,
    has_cwc: bool,
) -> bool {
    if tp < criteria.min_true_positives {
        return false;
    }
    if fp_rate > criteria.max_fp_rate {
        return false;
    }
    if fixture_coverage < criteria.min_fixtures {
        return false;
    }
    if criteria.requires_path_sensitivity && !has_path_sensitivity {
        return false;
    }
    if criteria.requires_smt && !has_smt {
        return false;
    }
    if criteria.requires_simulation && !_has_simulation {
        return false;
    }
    if criteria.requires_cwc && !has_cwc {
        return false;
    }
    true
}

/// Compute the highest tier a detector qualifies for based on its metrics.
fn compute_recommended_tier(
    tp: usize,
    fp_rate: f64,
    fixture_coverage: usize,
    has_path_sensitivity: bool,
    has_smt: bool,
    has_simulation: bool,
    has_cwc: bool,
) -> DetectorReliabilityTier {
    // Try from highest to lowest.
    if meets_criteria(
        &STABLE_CRITERIA,
        tp,
        fp_rate,
        fixture_coverage,
        has_path_sensitivity,
        has_smt,
        has_simulation,
        has_cwc,
    ) {
        return DetectorReliabilityTier::Stable;
    }
    if meets_criteria(
        &BETA_CRITERIA,
        tp,
        fp_rate,
        fixture_coverage,
        has_path_sensitivity,
        has_smt,
        has_simulation,
        has_cwc,
    ) {
        return DetectorReliabilityTier::Beta;
    }
    DetectorReliabilityTier::Experimental
}

/// Evaluate a single detector's scorecard from accuracy dashboard data.
///
/// The `accuracy_data` dashboard provides per-detector `DetectorMetrics` (TP, FP, FN, TN)
/// aggregated across fixture runs. Feature flags (path sensitivity, SMT, simulation, CWC)
/// are derived from the detector's trait implementation where possible.
pub fn evaluate_scorecard(
    detector_name: &str,
    accuracy_data: &AccuracyDashboard,
) -> DetectorScorecard {
    let current_tier = detector_reliability_tier(detector_name);

    // Pull metrics from the dashboard (default to empty if missing).
    let metrics = accuracy_data
        .metrics
        .get(detector_name)
        .cloned()
        .unwrap_or_default();

    let tp = metrics.true_positives;
    let fp = metrics.false_positives;
    let total = tp + fp;
    let fp_rate = if total > 0 {
        fp as f64 / total as f64
    } else {
        0.0
    };

    // fixture_coverage: count how many fixtures this detector was actually evaluated
    // against. We approximate this as total_cases (TP+FP+FN+TN).
    let fixture_coverage = metrics.total_cases();

    // Determine feature flags from detector trait implementations.
    let has_cwc = cwc_for_detector(detector_name).is_some();
    let has_path_sensitivity = is_path_sensitive_detector(detector_name);
    let has_smt = is_smt_backed_detector(detector_name);
    let has_simulation = is_simulation_backed_detector(detector_name);

    let recommended = compute_recommended_tier(
        tp,
        fp_rate,
        fixture_coverage,
        has_path_sensitivity,
        has_smt,
        has_simulation,
        has_cwc,
    );

    let promotion_eligible = tier_ord(recommended) > tier_ord(current_tier);
    let demotion_risk = tier_ord(recommended) < tier_ord(current_tier);

    // Build notes.
    let mut notes = Vec::new();
    if promotion_eligible {
        notes.push(format!(
            "Eligible for promotion: {} -> {}",
            current_tier, recommended
        ));
    }
    if demotion_risk {
        notes.push(format!(
            "Demotion risk: {} -> {} (does not meet current tier criteria)",
            current_tier, recommended
        ));
    }
    if total == 0 {
        notes.push("No evaluated findings — insufficient data for tier assessment".to_string());
    }
    if !has_cwc && current_tier == DetectorReliabilityTier::Stable {
        notes.push("Missing CWE mapping — required for Stable tier".to_string());
    }

    DetectorScorecard {
        detector_name: detector_name.to_string(),
        current_tier,
        recommended_tier: recommended,
        true_positives: tp,
        false_positives: fp,
        total_findings: total,
        fp_rate,
        fixture_coverage,
        has_path_sensitivity,
        has_smt_integration: has_smt,
        has_simulation_test: has_simulation,
        has_cwc_mapping: has_cwc,
        promotion_eligible,
        demotion_risk,
        notes,
    }
}

/// Evaluate scorecards for every registered detector.
pub fn evaluate_all_scorecards(accuracy_data: &AccuracyDashboard) -> Vec<DetectorScorecard> {
    let detectors = all_detectors();
    detectors
        .iter()
        .map(|d| evaluate_scorecard(d.name(), accuracy_data))
        .collect()
}

fn is_path_sensitive_detector(detector_name: &str) -> bool {
    matches!(
        detector_name,
        "path-sensitive-guard-check"
            | "precise-taint-to-sink"
            | "state-machine-violation"
            | "invariant-violation"
            | "output-count-validation"
    )
}

fn is_smt_backed_detector(detector_name: &str) -> bool {
    matches!(
        detector_name,
        "double-satisfaction"
            | "missing-signature-check"
            | "missing-validity-range"
            | "missing-redeemer-validation"
            | "missing-datum-in-script-output"
            | "unrestricted-minting"
            | "value-not-preserved"
    )
}

fn is_simulation_backed_detector(detector_name: &str) -> bool {
    matches!(
        detector_name,
        "missing-signature-check"
            | "unrestricted-minting"
            | "double-satisfaction"
            | "missing-redeemer-validation"
            | "missing-validity-range"
            | "missing-datum-in-script-output"
    )
}

// ---------------------------------------------------------------------------
// Promotion / Demotion checks
// ---------------------------------------------------------------------------

/// Check if a detector should be promoted. Returns the next tier if eligible.
pub fn check_promotion(scorecard: &DetectorScorecard) -> Option<DetectorReliabilityTier> {
    if !scorecard.promotion_eligible {
        return None;
    }
    next_tier(scorecard.current_tier)
}

/// Check if a detector should be demoted (i.e., it no longer meets its current tier criteria).
pub fn check_demotion(scorecard: &DetectorScorecard) -> bool {
    scorecard.demotion_risk
}

// ---------------------------------------------------------------------------
// Quality gate
// ---------------------------------------------------------------------------

/// Evaluate a quality gate: all detectors at or above `min_tier` must meet
/// the criteria for their current tier. Returns a `QualityGateResult`.
pub fn evaluate_quality_gate(
    scorecards: &[DetectorScorecard],
    min_tier: DetectorReliabilityTier,
) -> QualityGateResult {
    let mut violations = Vec::new();

    for sc in scorecards {
        // Only gate detectors at or above the minimum tier.
        if tier_ord(sc.current_tier) < tier_ord(min_tier) {
            continue;
        }
        if sc.demotion_risk {
            violations.push(format!(
                "{}: current tier {} but only qualifies for {} (TP={}, FP rate={:.0}%, fixtures={})",
                sc.detector_name,
                sc.current_tier,
                sc.recommended_tier,
                sc.true_positives,
                sc.fp_rate * 100.0,
                sc.fixture_coverage,
            ));
        }
    }

    let passed = violations.is_empty();
    let gated_count = scorecards
        .iter()
        .filter(|sc| tier_ord(sc.current_tier) >= tier_ord(min_tier))
        .count();
    let summary = if passed {
        format!(
            "Quality gate PASSED: all {} detectors at tier >= {} meet their criteria",
            gated_count, min_tier
        )
    } else {
        format!(
            "Quality gate FAILED: {} of {} detectors at tier >= {} have violations",
            violations.len(),
            gated_count,
            min_tier
        )
    };

    QualityGateResult {
        passed,
        violations,
        summary,
    }
}

// ---------------------------------------------------------------------------
// Report formatting
// ---------------------------------------------------------------------------

/// Format a detailed scorecard report for all detectors.
pub fn format_scorecard_report(scorecards: &[DetectorScorecard]) -> String {
    let mut lines = Vec::new();
    lines.push("Detector Scorecard Report".to_string());
    lines.push("=".repeat(100));
    lines.push(format!(
        "{:<40} {:>8} {:>4} {:>4} {:>7} {:>5} {:>10} {:>12}",
        "Detector", "Tier", "TP", "FP", "FP%", "Fix.", "Recommend", "Status"
    ));
    lines.push("-".repeat(100));

    let mut sorted: Vec<&DetectorScorecard> = scorecards.iter().collect();
    sorted.sort_by(|a, b| {
        tier_ord(b.current_tier)
            .cmp(&tier_ord(a.current_tier))
            .then(a.detector_name.cmp(&b.detector_name))
    });

    for sc in &sorted {
        let fp_pct = if sc.total_findings > 0 {
            format!("{:.0}%", sc.fp_rate * 100.0)
        } else {
            "N/A".to_string()
        };

        let status = if sc.promotion_eligible {
            "PROMOTE"
        } else if sc.demotion_risk {
            "DEMOTE"
        } else {
            "OK"
        };

        lines.push(format!(
            "{:<40} {:>8} {:>4} {:>4} {:>7} {:>5} {:>10} {:>12}",
            sc.detector_name,
            sc.current_tier,
            sc.true_positives,
            sc.false_positives,
            fp_pct,
            sc.fixture_coverage,
            sc.recommended_tier,
            status,
        ));
    }

    lines.push("-".repeat(100));

    // Summary counts
    let promote_count = sorted.iter().filter(|sc| sc.promotion_eligible).count();
    let demote_count = sorted.iter().filter(|sc| sc.demotion_risk).count();
    let ok_count = sorted.len() - promote_count - demote_count;
    let stable_count = sorted
        .iter()
        .filter(|sc| sc.current_tier == DetectorReliabilityTier::Stable)
        .count();
    let beta_count = sorted
        .iter()
        .filter(|sc| sc.current_tier == DetectorReliabilityTier::Beta)
        .count();
    let experimental_count = sorted
        .iter()
        .filter(|sc| sc.current_tier == DetectorReliabilityTier::Experimental)
        .count();

    lines.push(format!(
        "Tiers: {} stable, {} beta, {} experimental",
        stable_count, beta_count, experimental_count
    ));
    lines.push(format!(
        "Actions: {} promotions, {} demotions, {} unchanged",
        promote_count, demote_count, ok_count
    ));

    // Feature coverage
    let path_sens_count = sorted.iter().filter(|sc| sc.has_path_sensitivity).count();
    let smt_count = sorted.iter().filter(|sc| sc.has_smt_integration).count();
    let sim_count = sorted.iter().filter(|sc| sc.has_simulation_test).count();
    let cwc_count = sorted.iter().filter(|sc| sc.has_cwc_mapping).count();
    lines.push(format!(
        "Features: {} path-sensitive, {} SMT, {} simulation, {} CWE-mapped",
        path_sens_count, smt_count, sim_count, cwc_count
    ));

    // Promotion details
    if promote_count > 0 {
        lines.push(String::new());
        lines.push("Promotion candidates:".to_string());
        for sc in sorted.iter().filter(|sc| sc.promotion_eligible) {
            lines.push(format!(
                "  {} : {} -> {}",
                sc.detector_name, sc.current_tier, sc.recommended_tier
            ));
        }
    }

    // Demotion details
    if demote_count > 0 {
        lines.push(String::new());
        lines.push("Demotion risks:".to_string());
        for sc in sorted.iter().filter(|sc| sc.demotion_risk) {
            lines.push(format!(
                "  {} : {} -> {} ({})",
                sc.detector_name,
                sc.current_tier,
                sc.recommended_tier,
                sc.notes.join("; ")
            ));
        }
    }

    lines.join("\n")
}

/// Format a one-line summary of scorecard evaluation.
pub fn format_scorecard_summary(scorecards: &[DetectorScorecard]) -> String {
    let total = scorecards.len();
    let promote_count = scorecards.iter().filter(|sc| sc.promotion_eligible).count();
    let demote_count = scorecards.iter().filter(|sc| sc.demotion_risk).count();
    let stable_count = scorecards
        .iter()
        .filter(|sc| sc.current_tier == DetectorReliabilityTier::Stable)
        .count();
    let beta_count = scorecards
        .iter()
        .filter(|sc| sc.current_tier == DetectorReliabilityTier::Beta)
        .count();
    let exp_count = scorecards
        .iter()
        .filter(|sc| sc.current_tier == DetectorReliabilityTier::Experimental)
        .count();

    format!(
        "Scorecard: {total} detectors ({stable_count} stable, {beta_count} beta, {exp_count} experimental) \
         | {promote_count} promotions, {demote_count} demotions"
    )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accuracy::DetectorMetrics;
    use std::collections::HashMap;

    /// Helper to build an AccuracyDashboard with custom per-detector metrics.
    fn make_dashboard(entries: &[(&str, DetectorMetrics)]) -> AccuracyDashboard {
        let mut metrics = HashMap::new();
        for (name, m) in entries {
            metrics.insert(name.to_string(), m.clone());
        }
        AccuracyDashboard {
            metrics,
            fixture_count: 5,
            detector_count: entries.len(),
            evaluated_cases: entries.len(),
            reviewed_cases: entries.len(),
            unreviewed_cases: 0,
            info_cases: 0,
            business_logic_cases: 0,
            skipped_cases: 0,
            unlabeled_triggered_cases: 0,
            unreviewed_triggered_cases: 0,
        }
    }

    fn metrics(tp: usize, fp: usize, fn_: usize, tn: usize) -> DetectorMetrics {
        DetectorMetrics {
            true_positives: tp,
            false_positives: fp,
            false_negatives: fn_,
            true_negatives: tn,
        }
    }

    // -----------------------------------------------------------------------
    // TierCriteria constants
    // -----------------------------------------------------------------------

    #[test]
    #[allow(clippy::assertions_on_constants)]
    fn test_experimental_criteria_values() {
        assert_eq!(EXPERIMENTAL_CRITERIA.min_true_positives, 5);
        assert!((EXPERIMENTAL_CRITERIA.max_fp_rate - 0.40).abs() < f64::EPSILON);
        assert_eq!(EXPERIMENTAL_CRITERIA.min_fixtures, 1);
        assert!(!EXPERIMENTAL_CRITERIA.requires_path_sensitivity);
        assert!(!EXPERIMENTAL_CRITERIA.requires_smt);
        assert!(!EXPERIMENTAL_CRITERIA.requires_cwc);
    }

    #[test]
    #[allow(clippy::assertions_on_constants)]
    fn test_beta_criteria_values() {
        assert_eq!(BETA_CRITERIA.min_true_positives, 20);
        assert!((BETA_CRITERIA.max_fp_rate - 0.20).abs() < f64::EPSILON);
        assert_eq!(BETA_CRITERIA.min_fixtures, 3);
        assert!(!BETA_CRITERIA.requires_path_sensitivity);
        assert!(!BETA_CRITERIA.requires_smt);
        assert!(!BETA_CRITERIA.requires_cwc);
    }

    #[test]
    #[allow(clippy::assertions_on_constants)]
    fn test_stable_criteria_values() {
        assert_eq!(STABLE_CRITERIA.min_true_positives, 50);
        assert!((STABLE_CRITERIA.max_fp_rate - 0.05).abs() < f64::EPSILON);
        assert_eq!(STABLE_CRITERIA.min_fixtures, 5);
        assert!(STABLE_CRITERIA.requires_path_sensitivity);
        assert!(STABLE_CRITERIA.requires_smt);
        assert!(STABLE_CRITERIA.requires_cwc);
    }

    #[test]
    fn test_criteria_for_tier() {
        let exp = criteria_for_tier(DetectorReliabilityTier::Experimental);
        assert_eq!(exp.min_true_positives, 5);
        let beta = criteria_for_tier(DetectorReliabilityTier::Beta);
        assert_eq!(beta.min_true_positives, 20);
        let stable = criteria_for_tier(DetectorReliabilityTier::Stable);
        assert_eq!(stable.min_true_positives, 50);
    }

    // -----------------------------------------------------------------------
    // meets_criteria
    // -----------------------------------------------------------------------

    #[test]
    fn test_meets_experimental_criteria() {
        assert!(meets_criteria(
            &EXPERIMENTAL_CRITERIA,
            5,
            0.30,
            1,
            false,
            false,
            false,
            false
        ));
    }

    #[test]
    fn test_fails_experimental_too_few_tp() {
        assert!(!meets_criteria(
            &EXPERIMENTAL_CRITERIA,
            4,
            0.30,
            1,
            false,
            false,
            false,
            false
        ));
    }

    #[test]
    fn test_fails_experimental_fp_rate_too_high() {
        assert!(!meets_criteria(
            &EXPERIMENTAL_CRITERIA,
            5,
            0.50,
            1,
            false,
            false,
            false,
            false
        ));
    }

    #[test]
    fn test_meets_beta_criteria() {
        assert!(meets_criteria(
            &BETA_CRITERIA,
            20,
            0.15,
            3,
            false,
            false,
            false,
            false
        ));
    }

    #[test]
    fn test_fails_beta_not_enough_fixtures() {
        assert!(!meets_criteria(
            &BETA_CRITERIA,
            20,
            0.15,
            2,
            false,
            false,
            false,
            false
        ));
    }

    #[test]
    fn test_meets_stable_criteria() {
        assert!(meets_criteria(
            &STABLE_CRITERIA,
            50,
            0.04,
            5,
            true,
            true,
            false,
            true
        ));
    }

    #[test]
    fn test_fails_stable_missing_path_sensitivity() {
        assert!(!meets_criteria(
            &STABLE_CRITERIA,
            50,
            0.04,
            5,
            false,
            true,
            false,
            true
        ));
    }

    #[test]
    fn test_fails_stable_missing_smt() {
        assert!(!meets_criteria(
            &STABLE_CRITERIA,
            50,
            0.04,
            5,
            true,
            false,
            false,
            true
        ));
    }

    #[test]
    fn test_fails_stable_missing_cwc() {
        assert!(!meets_criteria(
            &STABLE_CRITERIA,
            50,
            0.04,
            5,
            true,
            true,
            false,
            false
        ));
    }

    // -----------------------------------------------------------------------
    // compute_recommended_tier
    // -----------------------------------------------------------------------

    #[test]
    fn test_recommended_tier_stable() {
        let tier = compute_recommended_tier(60, 0.03, 6, true, true, false, true);
        assert_eq!(tier, DetectorReliabilityTier::Stable);
    }

    #[test]
    fn test_recommended_tier_beta() {
        let tier = compute_recommended_tier(25, 0.10, 4, false, false, false, false);
        assert_eq!(tier, DetectorReliabilityTier::Beta);
    }

    #[test]
    fn test_recommended_tier_experimental() {
        let tier = compute_recommended_tier(3, 0.10, 1, false, false, false, false);
        assert_eq!(tier, DetectorReliabilityTier::Experimental);
    }

    #[test]
    fn test_recommended_tier_high_fp_caps_to_experimental() {
        // Even with many TPs, an FP rate > 40% keeps detector at Experimental.
        let tier = compute_recommended_tier(100, 0.50, 10, true, true, false, true);
        assert_eq!(tier, DetectorReliabilityTier::Experimental);
    }

    // -----------------------------------------------------------------------
    // tier helpers
    // -----------------------------------------------------------------------

    #[test]
    fn test_tier_ord() {
        assert!(
            tier_ord(DetectorReliabilityTier::Experimental)
                < tier_ord(DetectorReliabilityTier::Beta)
        );
        assert!(
            tier_ord(DetectorReliabilityTier::Beta) < tier_ord(DetectorReliabilityTier::Stable)
        );
    }

    #[test]
    fn test_next_tier() {
        assert_eq!(
            next_tier(DetectorReliabilityTier::Experimental),
            Some(DetectorReliabilityTier::Beta)
        );
        assert_eq!(
            next_tier(DetectorReliabilityTier::Beta),
            Some(DetectorReliabilityTier::Stable)
        );
        assert_eq!(next_tier(DetectorReliabilityTier::Stable), None);
    }

    #[test]
    fn test_prev_tier() {
        assert_eq!(prev_tier(DetectorReliabilityTier::Experimental), None);
        assert_eq!(
            prev_tier(DetectorReliabilityTier::Beta),
            Some(DetectorReliabilityTier::Experimental)
        );
        assert_eq!(
            prev_tier(DetectorReliabilityTier::Stable),
            Some(DetectorReliabilityTier::Beta)
        );
    }

    // -----------------------------------------------------------------------
    // evaluate_scorecard
    // -----------------------------------------------------------------------

    #[test]
    fn test_evaluate_scorecard_with_data() {
        let dashboard = make_dashboard(&[("double-satisfaction", metrics(10, 1, 0, 5))]);
        let sc = evaluate_scorecard("double-satisfaction", &dashboard);
        assert_eq!(sc.detector_name, "double-satisfaction");
        assert_eq!(sc.current_tier, DetectorReliabilityTier::Stable);
        assert_eq!(sc.true_positives, 10);
        assert_eq!(sc.false_positives, 1);
        assert_eq!(sc.total_findings, 11);
        assert!((sc.fp_rate - 1.0 / 11.0).abs() < 0.01);
        assert_eq!(sc.fixture_coverage, 16); // 10+1+0+5
    }

    #[test]
    fn test_evaluate_scorecard_missing_detector() {
        // Detector not in the dashboard -> defaults to zero metrics.
        let dashboard = make_dashboard(&[]);
        let sc = evaluate_scorecard("nonexistent-detector", &dashboard);
        assert_eq!(sc.true_positives, 0);
        assert_eq!(sc.false_positives, 0);
        assert_eq!(sc.total_findings, 0);
        assert!((sc.fp_rate - 0.0).abs() < f64::EPSILON);
        assert!(!sc.promotion_eligible);
    }

    #[test]
    fn test_evaluate_scorecard_zero_findings_note() {
        let dashboard = make_dashboard(&[("double-satisfaction", metrics(0, 0, 0, 0))]);
        let sc = evaluate_scorecard("double-satisfaction", &dashboard);
        assert!(sc.notes.iter().any(|n| n.contains("insufficient data")));
    }

    #[test]
    fn test_evaluate_scorecard_promotion_eligible() {
        // Experimental detector with enough TPs to qualify for Beta.
        let dashboard = make_dashboard(&[("cross-validator-gap", metrics(25, 3, 2, 10))]);
        let sc = evaluate_scorecard("cross-validator-gap", &dashboard);
        assert_eq!(sc.current_tier, DetectorReliabilityTier::Experimental);
        assert_eq!(sc.recommended_tier, DetectorReliabilityTier::Beta);
        assert!(sc.promotion_eligible);
        assert!(!sc.demotion_risk);
        assert!(sc.notes.iter().any(|n| n.contains("promotion")));
    }

    #[test]
    fn test_evaluate_scorecard_demotion_risk() {
        // Stable detector with very few TPs — doesn't meet Stable or Beta criteria.
        let dashboard = make_dashboard(&[("double-satisfaction", metrics(2, 1, 0, 0))]);
        let sc = evaluate_scorecard("double-satisfaction", &dashboard);
        assert_eq!(sc.current_tier, DetectorReliabilityTier::Stable);
        assert!(sc.demotion_risk);
        assert!(!sc.promotion_eligible);
        assert!(sc.notes.iter().any(|n| n.contains("Demotion risk")));
    }

    // -----------------------------------------------------------------------
    // evaluate_all_scorecards
    // -----------------------------------------------------------------------

    #[test]
    fn test_evaluate_all_scorecards_covers_all_detectors() {
        let dashboard = make_dashboard(&[]);
        let scorecards = evaluate_all_scorecards(&dashboard);
        let detector_count = all_detectors().len();
        assert_eq!(scorecards.len(), detector_count);
    }

    // -----------------------------------------------------------------------
    // check_promotion / check_demotion
    // -----------------------------------------------------------------------

    #[test]
    fn test_check_promotion_returns_next_tier() {
        let sc = DetectorScorecard {
            detector_name: "test".to_string(),
            current_tier: DetectorReliabilityTier::Experimental,
            recommended_tier: DetectorReliabilityTier::Beta,
            true_positives: 25,
            false_positives: 3,
            total_findings: 28,
            fp_rate: 3.0 / 28.0,
            fixture_coverage: 5,
            has_path_sensitivity: false,
            has_smt_integration: false,
            has_simulation_test: false,
            has_cwc_mapping: false,
            promotion_eligible: true,
            demotion_risk: false,
            notes: vec![],
        };
        assert_eq!(check_promotion(&sc), Some(DetectorReliabilityTier::Beta));
    }

    #[test]
    fn test_check_promotion_returns_none_when_not_eligible() {
        let sc = DetectorScorecard {
            detector_name: "test".to_string(),
            current_tier: DetectorReliabilityTier::Beta,
            recommended_tier: DetectorReliabilityTier::Beta,
            true_positives: 20,
            false_positives: 3,
            total_findings: 23,
            fp_rate: 3.0 / 23.0,
            fixture_coverage: 4,
            has_path_sensitivity: false,
            has_smt_integration: false,
            has_simulation_test: false,
            has_cwc_mapping: false,
            promotion_eligible: false,
            demotion_risk: false,
            notes: vec![],
        };
        assert_eq!(check_promotion(&sc), None);
    }

    #[test]
    fn test_check_demotion_true_when_risk() {
        let sc = DetectorScorecard {
            detector_name: "test".to_string(),
            current_tier: DetectorReliabilityTier::Stable,
            recommended_tier: DetectorReliabilityTier::Experimental,
            true_positives: 2,
            false_positives: 1,
            total_findings: 3,
            fp_rate: 1.0 / 3.0,
            fixture_coverage: 3,
            has_path_sensitivity: false,
            has_smt_integration: false,
            has_simulation_test: false,
            has_cwc_mapping: false,
            promotion_eligible: false,
            demotion_risk: true,
            notes: vec![],
        };
        assert!(check_demotion(&sc));
    }

    #[test]
    fn test_check_demotion_false_when_ok() {
        let sc = DetectorScorecard {
            detector_name: "test".to_string(),
            current_tier: DetectorReliabilityTier::Beta,
            recommended_tier: DetectorReliabilityTier::Beta,
            true_positives: 20,
            false_positives: 2,
            total_findings: 22,
            fp_rate: 2.0 / 22.0,
            fixture_coverage: 4,
            has_path_sensitivity: false,
            has_smt_integration: false,
            has_simulation_test: false,
            has_cwc_mapping: false,
            promotion_eligible: false,
            demotion_risk: false,
            notes: vec![],
        };
        assert!(!check_demotion(&sc));
    }

    // -----------------------------------------------------------------------
    // evaluate_quality_gate
    // -----------------------------------------------------------------------

    #[test]
    fn test_quality_gate_passes_when_all_ok() {
        let scorecards = vec![
            DetectorScorecard {
                detector_name: "det-a".to_string(),
                current_tier: DetectorReliabilityTier::Beta,
                recommended_tier: DetectorReliabilityTier::Beta,
                true_positives: 20,
                false_positives: 2,
                total_findings: 22,
                fp_rate: 2.0 / 22.0,
                fixture_coverage: 4,
                has_path_sensitivity: false,
                has_smt_integration: false,
                has_simulation_test: false,
                has_cwc_mapping: false,
                promotion_eligible: false,
                demotion_risk: false,
                notes: vec![],
            },
            DetectorScorecard {
                detector_name: "det-b".to_string(),
                current_tier: DetectorReliabilityTier::Stable,
                recommended_tier: DetectorReliabilityTier::Stable,
                true_positives: 60,
                false_positives: 2,
                total_findings: 62,
                fp_rate: 2.0 / 62.0,
                fixture_coverage: 6,
                has_path_sensitivity: true,
                has_smt_integration: true,
                has_simulation_test: false,
                has_cwc_mapping: true,
                promotion_eligible: false,
                demotion_risk: false,
                notes: vec![],
            },
        ];
        let result = evaluate_quality_gate(&scorecards, DetectorReliabilityTier::Beta);
        assert!(result.passed);
        assert!(result.violations.is_empty());
        assert!(result.summary.contains("PASSED"));
    }

    #[test]
    fn test_quality_gate_fails_on_demotion_risk() {
        let scorecards = vec![DetectorScorecard {
            detector_name: "bad-detector".to_string(),
            current_tier: DetectorReliabilityTier::Stable,
            recommended_tier: DetectorReliabilityTier::Experimental,
            true_positives: 2,
            false_positives: 5,
            total_findings: 7,
            fp_rate: 5.0 / 7.0,
            fixture_coverage: 7,
            has_path_sensitivity: false,
            has_smt_integration: false,
            has_simulation_test: false,
            has_cwc_mapping: false,
            promotion_eligible: false,
            demotion_risk: true,
            notes: vec![],
        }];
        let result = evaluate_quality_gate(&scorecards, DetectorReliabilityTier::Beta);
        assert!(!result.passed);
        assert_eq!(result.violations.len(), 1);
        assert!(result.violations[0].contains("bad-detector"));
        assert!(result.summary.contains("FAILED"));
    }

    #[test]
    fn test_quality_gate_ignores_below_min_tier() {
        // Experimental detector with demotion risk, but gate only checks Beta+.
        let scorecards = vec![DetectorScorecard {
            detector_name: "exp-detector".to_string(),
            current_tier: DetectorReliabilityTier::Experimental,
            recommended_tier: DetectorReliabilityTier::Experimental,
            true_positives: 1,
            false_positives: 5,
            total_findings: 6,
            fp_rate: 5.0 / 6.0,
            fixture_coverage: 6,
            has_path_sensitivity: false,
            has_smt_integration: false,
            has_simulation_test: false,
            has_cwc_mapping: false,
            promotion_eligible: false,
            demotion_risk: true,
            notes: vec![],
        }];
        let result = evaluate_quality_gate(&scorecards, DetectorReliabilityTier::Beta);
        assert!(result.passed);
    }

    #[test]
    fn test_quality_gate_empty_scorecards() {
        let result = evaluate_quality_gate(&[], DetectorReliabilityTier::Experimental);
        assert!(result.passed);
        assert!(result.summary.contains("PASSED"));
    }

    // -----------------------------------------------------------------------
    // format_scorecard_report
    // -----------------------------------------------------------------------

    #[test]
    fn test_format_report_contains_header() {
        let scorecards = vec![DetectorScorecard {
            detector_name: "test-det".to_string(),
            current_tier: DetectorReliabilityTier::Beta,
            recommended_tier: DetectorReliabilityTier::Beta,
            true_positives: 20,
            false_positives: 2,
            total_findings: 22,
            fp_rate: 2.0 / 22.0,
            fixture_coverage: 4,
            has_path_sensitivity: false,
            has_smt_integration: false,
            has_simulation_test: false,
            has_cwc_mapping: false,
            promotion_eligible: false,
            demotion_risk: false,
            notes: vec![],
        }];
        let report = format_scorecard_report(&scorecards);
        assert!(report.contains("Detector Scorecard Report"));
        assert!(report.contains("test-det"));
        assert!(report.contains("beta"));
        assert!(report.contains("OK"));
    }

    #[test]
    fn test_format_report_shows_promotions() {
        let scorecards = vec![DetectorScorecard {
            detector_name: "promotable".to_string(),
            current_tier: DetectorReliabilityTier::Experimental,
            recommended_tier: DetectorReliabilityTier::Beta,
            true_positives: 25,
            false_positives: 3,
            total_findings: 28,
            fp_rate: 3.0 / 28.0,
            fixture_coverage: 5,
            has_path_sensitivity: false,
            has_smt_integration: false,
            has_simulation_test: false,
            has_cwc_mapping: false,
            promotion_eligible: true,
            demotion_risk: false,
            notes: vec![],
        }];
        let report = format_scorecard_report(&scorecards);
        assert!(report.contains("PROMOTE"));
        assert!(report.contains("Promotion candidates"));
        assert!(report.contains("promotable"));
    }

    #[test]
    fn test_format_report_shows_demotions() {
        let scorecards = vec![DetectorScorecard {
            detector_name: "declining".to_string(),
            current_tier: DetectorReliabilityTier::Stable,
            recommended_tier: DetectorReliabilityTier::Experimental,
            true_positives: 2,
            false_positives: 5,
            total_findings: 7,
            fp_rate: 5.0 / 7.0,
            fixture_coverage: 7,
            has_path_sensitivity: false,
            has_smt_integration: false,
            has_simulation_test: false,
            has_cwc_mapping: false,
            promotion_eligible: false,
            demotion_risk: true,
            notes: vec!["Demotion risk: stable -> experimental".to_string()],
        }];
        let report = format_scorecard_report(&scorecards);
        assert!(report.contains("DEMOTE"));
        assert!(report.contains("Demotion risks"));
        assert!(report.contains("declining"));
    }

    // -----------------------------------------------------------------------
    // format_scorecard_summary
    // -----------------------------------------------------------------------

    #[test]
    fn test_format_summary_includes_counts() {
        let scorecards = vec![
            DetectorScorecard {
                detector_name: "s1".to_string(),
                current_tier: DetectorReliabilityTier::Stable,
                recommended_tier: DetectorReliabilityTier::Stable,
                true_positives: 50,
                false_positives: 1,
                total_findings: 51,
                fp_rate: 1.0 / 51.0,
                fixture_coverage: 6,
                has_path_sensitivity: true,
                has_smt_integration: true,
                has_simulation_test: false,
                has_cwc_mapping: true,
                promotion_eligible: false,
                demotion_risk: false,
                notes: vec![],
            },
            DetectorScorecard {
                detector_name: "b1".to_string(),
                current_tier: DetectorReliabilityTier::Beta,
                recommended_tier: DetectorReliabilityTier::Beta,
                true_positives: 20,
                false_positives: 2,
                total_findings: 22,
                fp_rate: 2.0 / 22.0,
                fixture_coverage: 4,
                has_path_sensitivity: false,
                has_smt_integration: false,
                has_simulation_test: false,
                has_cwc_mapping: false,
                promotion_eligible: false,
                demotion_risk: false,
                notes: vec![],
            },
            DetectorScorecard {
                detector_name: "e1".to_string(),
                current_tier: DetectorReliabilityTier::Experimental,
                recommended_tier: DetectorReliabilityTier::Beta,
                true_positives: 25,
                false_positives: 3,
                total_findings: 28,
                fp_rate: 3.0 / 28.0,
                fixture_coverage: 5,
                has_path_sensitivity: false,
                has_smt_integration: false,
                has_simulation_test: false,
                has_cwc_mapping: false,
                promotion_eligible: true,
                demotion_risk: false,
                notes: vec![],
            },
        ];
        let summary = format_scorecard_summary(&scorecards);
        assert!(summary.contains("3 detectors"));
        assert!(summary.contains("1 stable"));
        assert!(summary.contains("1 beta"));
        assert!(summary.contains("1 experimental"));
        assert!(summary.contains("1 promotions"));
        assert!(summary.contains("0 demotions"));
    }

    // -----------------------------------------------------------------------
    // Serialization round-trip
    // -----------------------------------------------------------------------

    #[test]
    fn test_scorecard_serialization_roundtrip() {
        let sc = DetectorScorecard {
            detector_name: "test-det".to_string(),
            current_tier: DetectorReliabilityTier::Beta,
            recommended_tier: DetectorReliabilityTier::Stable,
            true_positives: 55,
            false_positives: 2,
            total_findings: 57,
            fp_rate: 2.0 / 57.0,
            fixture_coverage: 6,
            has_path_sensitivity: true,
            has_smt_integration: true,
            has_simulation_test: false,
            has_cwc_mapping: true,
            promotion_eligible: true,
            demotion_risk: false,
            notes: vec!["note1".to_string()],
        };
        let json = serde_json::to_string(&sc).unwrap();
        let restored: DetectorScorecard = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.detector_name, "test-det");
        assert_eq!(restored.current_tier, DetectorReliabilityTier::Beta);
        assert_eq!(restored.recommended_tier, DetectorReliabilityTier::Stable);
        assert_eq!(restored.true_positives, 55);
        assert!(restored.promotion_eligible);
        assert!(!restored.demotion_risk);
    }

    #[test]
    fn test_quality_gate_result_serialization() {
        let result = QualityGateResult {
            passed: false,
            violations: vec!["violation1".to_string()],
            summary: "FAILED".to_string(),
        };
        let json = serde_json::to_string(&result).unwrap();
        let restored: QualityGateResult = serde_json::from_str(&json).unwrap();
        assert!(!restored.passed);
        assert_eq!(restored.violations.len(), 1);
    }

    // -----------------------------------------------------------------------
    // Edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn test_fp_rate_zero_when_no_findings() {
        let dashboard = make_dashboard(&[("test-det", metrics(0, 0, 0, 0))]);
        let sc = evaluate_scorecard("test-det", &dashboard);
        assert!((sc.fp_rate - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_fp_rate_100_percent() {
        let dashboard = make_dashboard(&[("test-det", metrics(0, 10, 0, 0))]);
        let sc = evaluate_scorecard("test-det", &dashboard);
        assert!((sc.fp_rate - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_fp_rate_zero_with_only_tp() {
        let dashboard = make_dashboard(&[("test-det", metrics(10, 0, 0, 0))]);
        let sc = evaluate_scorecard("test-det", &dashboard);
        assert!((sc.fp_rate - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_quality_gate_multiple_violations() {
        let scorecards = vec![
            DetectorScorecard {
                detector_name: "bad-1".to_string(),
                current_tier: DetectorReliabilityTier::Stable,
                recommended_tier: DetectorReliabilityTier::Experimental,
                true_positives: 2,
                false_positives: 5,
                total_findings: 7,
                fp_rate: 5.0 / 7.0,
                fixture_coverage: 7,
                has_path_sensitivity: false,
                has_smt_integration: false,
                has_simulation_test: false,
                has_cwc_mapping: false,
                promotion_eligible: false,
                demotion_risk: true,
                notes: vec![],
            },
            DetectorScorecard {
                detector_name: "bad-2".to_string(),
                current_tier: DetectorReliabilityTier::Beta,
                recommended_tier: DetectorReliabilityTier::Experimental,
                true_positives: 3,
                false_positives: 4,
                total_findings: 7,
                fp_rate: 4.0 / 7.0,
                fixture_coverage: 7,
                has_path_sensitivity: false,
                has_smt_integration: false,
                has_simulation_test: false,
                has_cwc_mapping: false,
                promotion_eligible: false,
                demotion_risk: true,
                notes: vec![],
            },
        ];
        let result = evaluate_quality_gate(&scorecards, DetectorReliabilityTier::Experimental);
        assert!(!result.passed);
        assert_eq!(result.violations.len(), 2);
        assert!(result.summary.contains("2 of 2"));
    }
}
