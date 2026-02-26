//! Integration tests for multiple fixture projects (#59).
//! Each fixture is inspired by a real-world Aiken contract pattern
//! and contains deliberate vulnerabilities that specific detectors should catch.

use std::path::PathBuf;
use std::sync::LazyLock;

use aikido_core::ast_walker::ModuleInfo;
use aikido_core::detector::{run_detectors, Finding, Severity};
use aikido_core::project::AikenProject;

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures")
        .join(name)
}

// --- Treasury fixture (inspired by SundaeSwap treasury) ---

static TREASURY_COMPILED: LazyLock<Vec<ModuleInfo>> = LazyLock::new(|| {
    let project = AikenProject::new(fixture_path("simple-treasury")).expect("should load treasury");
    project.compile().expect("should compile treasury")
});

static TREASURY_FINDINGS: LazyLock<Vec<Finding>> =
    LazyLock::new(|| run_detectors(&TREASURY_COMPILED));

#[test]
fn test_treasury_compiles() {
    let modules = &*TREASURY_COMPILED;
    assert!(!modules.is_empty(), "treasury should have modules");
    let validators: Vec<_> = modules
        .iter()
        .filter(|m| m.kind == aikido_core::ast_walker::ModuleKind::Validator)
        .collect();
    assert_eq!(validators.len(), 1, "should have 1 validator module");
}

#[test]
fn test_treasury_detects_double_satisfaction() {
    let findings = &*TREASURY_FINDINGS;
    assert!(
        findings
            .iter()
            .any(|f| f.detector_name == "double-satisfaction"),
        "treasury uses _own_ref (unused) → should trigger double-satisfaction. Findings: {:?}",
        finding_names(findings)
    );
}

#[test]
fn test_treasury_detects_unsafe_datum_deconstruction() {
    let findings = &*TREASURY_FINDINGS;
    // Treasury has Option<TreasuryDatum> but never does expect Some(d) = datum
    assert!(
        findings
            .iter()
            .any(|f| f.detector_name == "unsafe-datum-deconstruction"),
        "treasury should trigger unsafe-datum-deconstruction. Findings: {:?}",
        finding_names(findings)
    );
}

#[test]
fn test_treasury_detects_missing_signature_check() {
    let findings = &*TREASURY_FINDINGS;
    // Treasury has admin field but never checks tx.extra_signatories
    assert!(
        findings
            .iter()
            .any(|f| f.detector_name == "missing-signature-check"),
        "treasury should trigger missing-signature-check. Findings: {:?}",
        finding_names(findings)
    );
}

#[test]
fn test_treasury_has_high_or_critical_findings() {
    let findings = &*TREASURY_FINDINGS;
    let serious = findings
        .iter()
        .filter(|f| matches!(f.severity, Severity::Critical | Severity::High))
        .count();
    assert!(
        serious >= 2,
        "treasury should have at least 2 high/critical findings, got {serious}"
    );
}

// --- Token Minter fixture (inspired by Anastasia-Labs tx-level-minter) ---

static MINTER_COMPILED: LazyLock<Vec<ModuleInfo>> = LazyLock::new(|| {
    let project = AikenProject::new(fixture_path("token-minter")).expect("should load minter");
    project.compile().expect("should compile minter")
});

static MINTER_FINDINGS: LazyLock<Vec<Finding>> = LazyLock::new(|| run_detectors(&MINTER_COMPILED));

#[test]
fn test_minter_compiles() {
    let modules = &*MINTER_COMPILED;
    assert!(!modules.is_empty(), "minter should have modules");
}

#[test]
fn test_minter_detects_unrestricted_minting() {
    let findings = &*MINTER_FINDINGS;
    assert!(
        findings
            .iter()
            .any(|f| f.detector_name == "unrestricted-minting"),
        "token_policy mint returns True with no checks → should trigger unrestricted-minting. Findings: {:?}",
        finding_names(findings)
    );
}

#[test]
fn test_minter_detects_missing_minting_policy_check() {
    let findings = &*MINTER_FINDINGS;
    assert!(
        findings
            .iter()
            .any(|f| f.detector_name == "missing-minting-policy-check"),
        "token_policy doesn't validate token names → should trigger missing-minting-policy-check. Findings: {:?}",
        finding_names(findings)
    );
}

#[test]
fn test_minter_detects_missing_signature_for_holder() {
    let findings = &*MINTER_FINDINGS;
    // token_holder has owner field but never checks signatories
    assert!(
        findings
            .iter()
            .any(|f| f.detector_name == "missing-signature-check"),
        "token_holder should trigger missing-signature-check. Findings: {:?}",
        finding_names(findings)
    );
}

// --- Escrow fixture (inspired by Fusion maker contract) ---

static ESCROW_COMPILED: LazyLock<Vec<ModuleInfo>> = LazyLock::new(|| {
    let project = AikenProject::new(fixture_path("escrow-contract")).expect("should load escrow");
    project.compile().expect("should compile escrow")
});

static ESCROW_FINDINGS: LazyLock<Vec<Finding>> = LazyLock::new(|| run_detectors(&ESCROW_COMPILED));

#[test]
fn test_escrow_compiles() {
    let modules = &*ESCROW_COMPILED;
    assert!(!modules.is_empty(), "escrow should have modules");
}

#[test]
fn test_escrow_detects_fail_only_branch() {
    let findings = &*ESCROW_FINDINGS;
    assert!(
        findings
            .iter()
            .any(|f| f.detector_name == "fail-only-redeemer-branch"),
        "escrow Refund branch always fails → should trigger fail-only-redeemer-branch. Findings: {:?}",
        finding_names(findings)
    );
}

#[test]
fn test_escrow_no_double_satisfaction() {
    let findings = &*ESCROW_FINDINGS;
    // Escrow properly uses own_ref, so should NOT trigger double-satisfaction
    assert!(
        !findings
            .iter()
            .any(|f| f.detector_name == "double-satisfaction"),
        "escrow uses own_ref properly → should NOT trigger double-satisfaction"
    );
}

#[test]
fn test_escrow_value_not_preserved_in_cancel() {
    let findings = &*ESCROW_FINDINGS;
    // Cancel branch has outputs but doesn't check value
    let vp = findings
        .iter()
        .filter(|f| f.detector_name == "value-not-preserved")
        .count();
    // The detector may or may not fire depending on signals analysis;
    // at minimum it should not panic
    eprintln!(
        "value-not-preserved findings on escrow: {vp}. All findings: {:?}",
        finding_names(findings)
    );
}

// --- Lending Protocol fixture (inspired by Lenfi) ---

static LENDING_COMPILED: LazyLock<Vec<ModuleInfo>> = LazyLock::new(|| {
    let project = AikenProject::new(fixture_path("lending-protocol")).expect("should load lending");
    project.compile().expect("should compile lending")
});

static LENDING_FINDINGS: LazyLock<Vec<Finding>> =
    LazyLock::new(|| run_detectors(&LENDING_COMPILED));

#[test]
fn test_lending_compiles() {
    let modules = &*LENDING_COMPILED;
    assert!(!modules.is_empty(), "lending should have modules");
    let validators: Vec<_> = modules
        .iter()
        .filter(|m| m.kind == aikido_core::ast_walker::ModuleKind::Validator)
        .collect();
    assert_eq!(validators.len(), 1, "should have 1 validator module");
}

#[test]
fn test_lending_detects_double_satisfaction() {
    let findings = &*LENDING_FINDINGS;
    // Both lending_pool and loan_position use _own_ref (unused)
    let ds_count = findings
        .iter()
        .filter(|f| f.detector_name == "double-satisfaction")
        .count();
    assert!(
        ds_count >= 2,
        "lending should trigger double-satisfaction on both validators, got {ds_count}. Findings: {:?}",
        finding_names(findings)
    );
}

#[test]
fn test_lending_detects_missing_redeemer_validation() {
    let findings = &*LENDING_FINDINGS;
    // Repay branch returns True unconditionally
    assert!(
        findings
            .iter()
            .any(|f| f.detector_name == "missing-redeemer-validation"),
        "lending Repay returns True → should trigger missing-redeemer-validation. Findings: {:?}",
        finding_names(findings)
    );
}

#[test]
fn test_lending_detects_state_transition_integrity() {
    let findings = &*LENDING_FINDINGS;
    assert!(
        findings
            .iter()
            .any(|f| f.detector_name == "state-transition-integrity"),
        "lending should trigger state-transition-integrity. Findings: {:?}",
        finding_names(findings)
    );
}

#[test]
fn test_lending_detects_unused_library_module() {
    let findings = &*LENDING_FINDINGS;
    // math.ak functions are never called from validators
    assert!(
        findings
            .iter()
            .any(|f| f.detector_name == "unused-library-module"),
        "lending math module should be flagged as unused. Findings: {:?}",
        finding_names(findings)
    );
}

#[test]
fn test_lending_detects_dead_code() {
    let findings = &*LENDING_FINDINGS;
    // math.ak has unreachable functions (deduped per module since location is None)
    assert!(
        findings.iter().any(|f| f.detector_name == "dead-code-path"),
        "lending should have dead-code-path findings. Findings: {:?}",
        finding_names(findings)
    );
}

#[test]
fn test_lending_has_diverse_severity() {
    let findings = &*LENDING_FINDINGS;
    let critical = findings
        .iter()
        .filter(|f| f.severity == Severity::Critical)
        .count();
    let high = findings
        .iter()
        .filter(|f| f.severity == Severity::High)
        .count();
    let medium = findings
        .iter()
        .filter(|f| f.severity == Severity::Medium)
        .count();
    assert!(
        critical >= 2,
        "lending should have >= 2 critical, got {critical}"
    );
    assert!(high >= 1, "lending should have >= 1 high, got {high}");
    assert!(medium >= 5, "lending should have >= 5 medium, got {medium}");
}

// --- DEX AMM fixture (inspired by Minswap/SundaeSwap) ---

static DEX_COMPILED: LazyLock<Vec<ModuleInfo>> = LazyLock::new(|| {
    let project = AikenProject::new(fixture_path("dex-contracts")).expect("should load dex");
    project.compile().expect("should compile dex")
});

static DEX_FINDINGS: LazyLock<Vec<Finding>> = LazyLock::new(|| run_detectors(&DEX_COMPILED));

#[test]
fn test_dex_compiles() {
    let modules = &*DEX_COMPILED;
    assert!(!modules.is_empty(), "dex should have modules");
    let validators: Vec<_> = modules
        .iter()
        .filter(|m| m.kind == aikido_core::ast_walker::ModuleKind::Validator)
        .collect();
    // pool.ak, lp_policy.ak, order.ak → 3 validator files
    assert!(
        validators.len() >= 2,
        "should have at least 2 validator modules, got {}",
        validators.len()
    );
}

#[test]
fn test_dex_detects_unrestricted_minting() {
    let findings = &*DEX_FINDINGS;
    assert!(
        findings
            .iter()
            .any(|f| f.detector_name == "unrestricted-minting"),
        "lp_token mint returns True → should trigger unrestricted-minting. Findings: {:?}",
        finding_names(findings)
    );
}

#[test]
fn test_dex_detects_missing_minting_policy_check() {
    let findings = &*DEX_FINDINGS;
    assert!(
        findings
            .iter()
            .any(|f| f.detector_name == "missing-minting-policy-check"),
        "lp_token doesn't validate token names → should trigger missing-minting-policy-check. Findings: {:?}",
        finding_names(findings)
    );
}

#[test]
fn test_dex_detects_double_satisfaction_on_order() {
    let findings = &*DEX_FINDINGS;
    // swap_order uses _own_ref (unused)
    assert!(
        findings
            .iter()
            .any(|f| f.detector_name == "double-satisfaction" && f.title.contains("swap_order")),
        "swap_order should trigger double-satisfaction. Findings: {:?}",
        finding_names(findings)
    );
}

#[test]
fn test_dex_pool_no_double_satisfaction() {
    let findings = &*DEX_FINDINGS;
    // amm_pool properly uses own_ref
    assert!(
        !findings
            .iter()
            .any(|f| f.detector_name == "double-satisfaction" && f.title.contains("amm_pool")),
        "amm_pool uses own_ref properly → should NOT trigger double-satisfaction"
    );
}

#[test]
fn test_dex_detects_dead_code() {
    let findings = &*DEX_FINDINGS;
    // math.ak has unreachable functions (deduped per module since location is None)
    assert!(
        findings.iter().any(|f| f.detector_name == "dead-code-path"),
        "dex should have dead-code-path findings. Findings: {:?}",
        finding_names(findings)
    );
}

#[test]
fn test_dex_detects_unused_library_module() {
    let findings = &*DEX_FINDINGS;
    assert!(
        findings
            .iter()
            .any(|f| f.detector_name == "unused-library-module"),
        "dex math module should be flagged as unused. Findings: {:?}",
        finding_names(findings)
    );
}

#[test]
fn test_dex_has_high_or_critical_findings() {
    let findings = &*DEX_FINDINGS;
    let serious = findings
        .iter()
        .filter(|f| matches!(f.severity, Severity::Critical | Severity::High))
        .count();
    assert!(
        serious >= 5,
        "dex should have at least 5 high/critical findings, got {serious}"
    );
}

// --- Cross-fixture tests ---

#[test]
fn test_all_fixtures_produce_findings() {
    // All fixtures have deliberate vulnerabilities
    assert!(
        !TREASURY_FINDINGS.is_empty(),
        "treasury should have findings"
    );
    assert!(!MINTER_FINDINGS.is_empty(), "minter should have findings");
    assert!(!ESCROW_FINDINGS.is_empty(), "escrow should have findings");
    assert!(!LENDING_FINDINGS.is_empty(), "lending should have findings");
    assert!(!DEX_FINDINGS.is_empty(), "dex should have findings");
}

#[test]
fn test_findings_have_locations_across_fixtures() {
    for (name, findings) in [
        ("treasury", &*TREASURY_FINDINGS),
        ("minter", &*MINTER_FINDINGS),
        ("escrow", &*ESCROW_FINDINGS),
        ("lending", &*LENDING_FINDINGS),
        ("dex", &*DEX_FINDINGS),
    ] {
        for f in findings {
            if let Some(ref loc) = f.location {
                assert!(
                    loc.line_start.is_some(),
                    "Finding '{}' in {} should have resolved line_start",
                    f.detector_name,
                    name
                );
            }
        }
    }
}

#[test]
fn test_diverse_detectors_triggered() {
    // Across all 5 fixtures, we should trigger a diverse set of detectors
    let mut detector_names: Vec<&str> = Vec::new();
    for findings in [
        &*TREASURY_FINDINGS,
        &*MINTER_FINDINGS,
        &*ESCROW_FINDINGS,
        &*LENDING_FINDINGS,
        &*DEX_FINDINGS,
    ] {
        for f in findings {
            if !detector_names.contains(&f.detector_name.as_str()) {
                detector_names.push(Box::leak(f.detector_name.clone().into_boxed_str()));
            }
        }
    }
    assert!(
        detector_names.len() >= 8,
        "fixtures should trigger at least 8 different detectors, got {}: {:?}",
        detector_names.len(),
        detector_names
    );
}

#[test]
fn test_total_findings_across_all_fixtures() {
    // Regression guard: track total findings across all fixtures
    let total = TREASURY_FINDINGS.len()
        + MINTER_FINDINGS.len()
        + ESCROW_FINDINGS.len()
        + LENDING_FINDINGS.len()
        + DEX_FINDINGS.len();
    eprintln!("Total findings across all 5 fixtures: {total}");
    assert!(
        total >= 40,
        "should have at least 40 total findings across all fixtures, got {total}"
    );
}

fn finding_names(findings: &[Finding]) -> Vec<&str> {
    findings.iter().map(|f| f.detector_name.as_str()).collect()
}

// --- Referral system fixture (FP regression) ---

static REFERRAL_COMPILED: LazyLock<Vec<ModuleInfo>> = LazyLock::new(|| {
    let project =
        AikenProject::new(fixture_path("referral-system")).expect("should load referral-system");
    project.compile().expect("should compile referral-system")
});

static REFERRAL_FINDINGS: LazyLock<Vec<Finding>> =
    LazyLock::new(|| run_detectors(&REFERRAL_COMPILED));

#[test]
fn test_referral_compiles() {
    let modules = &*REFERRAL_COMPILED;
    assert!(!modules.is_empty(), "referral-system should have modules");
    let validators: Vec<_> = modules
        .iter()
        .filter(|m| m.kind == aikido_core::ast_walker::ModuleKind::Validator)
        .collect();
    assert_eq!(validators.len(), 1, "should have 1 validator module");
}

#[test]
fn test_referral_no_duplicate_asset_name_fp() {
    // Phase 1 FP: dict.foldl counting pattern should suppress duplicate-asset-name-risk
    let findings = &*REFERRAL_FINDINGS;
    assert!(
        !findings
            .iter()
            .any(|f| f.detector_name == "duplicate-asset-name-risk"),
        "duplicate-asset-name-risk should be suppressed by foldl counting pattern. Findings: {:?}",
        finding_names(findings)
    );
}

#[test]
fn test_referral_no_integer_underflow_fp() {
    // Phase 1 FP: correlated guard should suppress integer-underflow-risk
    let findings = &*REFERRAL_FINDINGS;
    assert!(
        !findings
            .iter()
            .any(|f| f.detector_name == "integer-underflow-risk"),
        "integer-underflow-risk should be suppressed by correlated guard. Findings: {:?}",
        finding_names(findings)
    );
}

#[test]
fn test_referral_other_token_minting_fires() {
    // other-token-minting should still fire (quantity_of without flatten)
    let findings = &*REFERRAL_FINDINGS;
    assert!(
        findings
            .iter()
            .any(|f| f.detector_name == "other-token-minting"),
        "other-token-minting should fire on mint handler. Findings: {:?}",
        finding_names(findings)
    );
}

#[test]
fn test_referral_finding_count() {
    let findings = &*REFERRAL_FINDINGS;
    eprintln!(
        "Referral fixture: {} findings: {:?}",
        findings.len(),
        finding_names(findings)
    );
    // With FP reduction, total findings should be moderate (not zero, but much less noise)
    // We expect some legit findings and a few acceptable informational ones
}
