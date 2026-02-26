use std::path::PathBuf;
use std::sync::LazyLock;

use aikido_core::ast_walker::{ModuleInfo, ModuleKind};
use aikido_core::config::AikidoConfig;
use aikido_core::detector::{all_detectors, run_detectors};
use aikido_core::project::{AikenProject, ProjectConfig};
use aikido_core::report::format_findings;
use aikido_core::sarif::findings_to_sarif;
use aikido_core::suppression::filter_suppressed;
use aikido_core::uplc_analysis;

fn fixtures_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/sentaku-contracts")
}

/// Compile the Sentaku project once and share across all tests.
static COMPILED: LazyLock<(ProjectConfig, Vec<ModuleInfo>)> = LazyLock::new(|| {
    let project = AikenProject::new(fixtures_path()).expect("should load project");
    let config = project.config().expect("should read config");
    let modules = project.compile().expect("should compile");
    (config, modules)
});

#[test]
fn test_load_sentaku_project() {
    let (config, _) = &*COMPILED;
    assert_eq!(config.name, "sentaku/contracts");
    assert_eq!(config.version, "0.1.0");
}

#[test]
fn test_compile_sentaku_finds_validator() {
    let (_, modules) = &*COMPILED;

    let validator_modules: Vec<_> = modules
        .iter()
        .filter(|m| m.kind == ModuleKind::Validator)
        .collect();

    assert_eq!(
        validator_modules.len(),
        1,
        "expected exactly 1 validator module"
    );
    let vm = validator_modules[0];

    assert_eq!(vm.validators.len(), 1, "expected 1 validator");
    let v = &vm.validators[0];
    assert_eq!(v.name, "position");
    assert_eq!(v.params.len(), 2, "position validator has 2 params");
    assert_eq!(v.params[0].name, "oracle_pkh");
    assert_eq!(v.params[1].name, "operator_pkh");
}

#[test]
fn test_compile_sentaku_data_types() {
    let (_, modules) = &*COMPILED;

    let types_module = modules
        .iter()
        .find(|m| m.name == "sentaku/contracts/types")
        .expect("should find types module");

    let type_names: Vec<&str> = types_module
        .data_types
        .iter()
        .map(|dt| dt.name.as_str())
        .collect();

    assert!(type_names.contains(&"Symbol"), "should have Symbol type");
    assert!(
        type_names.contains(&"Direction"),
        "should have Direction type"
    );
    assert!(
        type_names.contains(&"Duration"),
        "should have Duration type"
    );
    assert!(
        type_names.contains(&"PositionResult"),
        "should have PositionResult type"
    );

    let symbol = types_module
        .data_types
        .iter()
        .find(|dt| dt.name == "Symbol")
        .unwrap();
    let constructor_names: Vec<&str> = symbol
        .constructors
        .iter()
        .map(|c| c.name.as_str())
        .collect();
    assert_eq!(constructor_names, vec!["BTC", "ETH", "SOL", "ADA", "SNEK"]);
}

#[test]
fn test_compile_sentaku_test_count() {
    let (_, modules) = &*COMPILED;

    let total_tests: usize = modules
        .iter()
        .filter(|m| m.name.starts_with("sentaku/"))
        .map(|m| m.test_count)
        .sum();

    assert!(
        total_tests >= 24,
        "expected at least 24 tests, got {total_tests}"
    );
}

#[test]
fn test_compile_sentaku_datum_fields() {
    let (_, modules) = &*COMPILED;

    let datum_module = modules
        .iter()
        .find(|m| m.name == "sentaku/contracts/datum")
        .expect("should find datum module");

    assert_eq!(datum_module.data_types.len(), 1);
    let datum = &datum_module.data_types[0];
    assert_eq!(datum.name, "PositionDatum");
    assert_eq!(datum.constructors.len(), 1);

    let fields = &datum.constructors[0].fields;
    let field_labels: Vec<Option<&str>> = fields.iter().map(|f| f.label.as_deref()).collect();

    assert!(field_labels.contains(&Some("position_id")));
    assert!(field_labels.contains(&Some("owner")));
    assert!(field_labels.contains(&Some("symbol")));
    assert!(field_labels.contains(&Some("stake_lovelace")));
    assert!(field_labels.contains(&Some("entry_price")));
}

#[test]
fn test_report_generation() {
    let (config, modules) = &*COMPILED;

    let report = aikido_core::report::format_report(
        modules,
        &config.name,
        &config.version,
        &fixtures_path(),
        false,
    );

    assert!(report.contains("AIKIDO v0.2.0"));
    assert!(report.contains("sentaku/contracts"));
    assert!(report.contains("VALIDATOR: position"));
    assert!(report.contains("Parameters: oracle_pkh"));
    assert!(report.contains("Compiled Size:"));
    assert!(report.contains("SUMMARY"));
}

#[test]
fn test_detectors_run_on_sentaku() {
    let (_, modules) = &*COMPILED;

    let findings = run_detectors(modules);

    // Sentaku should trigger some findings — at minimum detectors run without panicking
    eprintln!("Sentaku findings: {}", findings.len());
    for f in &findings {
        eprintln!("  [{:?}] {} — {}", f.severity, f.detector_name, f.title);
    }
}

#[test]
fn test_body_signals_populated_for_sentaku() {
    let (_, modules) = &*COMPILED;

    let validator_module = modules
        .iter()
        .find(|m| m.kind == ModuleKind::Validator)
        .expect("should find validator module");

    let validator = &validator_module.validators[0];
    assert_eq!(validator.name, "position");

    let spend_handler = validator
        .handlers
        .iter()
        .find(|h| h.name == "spend")
        .expect("should have spend handler");

    let signals = &spend_handler.body_signals;
    eprintln!("TX field accesses: {:?}", signals.tx_field_accesses);
    eprintln!("Function calls: {:?}", signals.function_calls);
    eprintln!("Uses own_ref: {}", signals.uses_own_ref);
    eprintln!("When branches: {}", signals.when_branches.len());

    assert!(
        !signals.var_references.is_empty(),
        "spend handler body should reference variables"
    );

    // Spend handler should have a location
    assert!(
        spend_handler.location.is_some(),
        "spend handler should have source location"
    );
}

#[test]
fn test_findings_report_format() {
    let (_, modules) = &*COMPILED;

    let findings = run_detectors(modules);
    let report = format_findings(&findings, modules);

    if !findings.is_empty() {
        assert!(report.contains("FINDINGS"));
        assert!(
            report.contains("CRITICAL")
                || report.contains("HIGH")
                || report.contains("MEDIUM")
                || report.contains("LOW")
                || report.contains("INFO")
        );
    }
}

// --- Phase 3 integration tests ---

#[test]
fn test_findings_have_resolved_locations() {
    let (_, modules) = &*COMPILED;
    let findings = run_detectors(modules);

    // Findings with locations should have resolved line numbers
    for f in &findings {
        if let Some(ref loc) = f.location {
            assert!(
                loc.line_start.is_some(),
                "Finding '{}' should have resolved line_start",
                f.detector_name
            );
        }
    }
}

#[test]
fn test_sarif_output_valid_json() {
    let (_, modules) = &*COMPILED;
    let findings = run_detectors(modules);
    let sarif = findings_to_sarif(&findings, None, modules);

    let parsed: serde_json::Value =
        serde_json::from_str(&sarif).expect("SARIF should be valid JSON");
    assert_eq!(parsed["version"], "2.1.0");
    assert!(parsed["runs"].is_array());
    assert!(parsed["runs"][0]["tool"]["driver"]["rules"].is_array());
    // Should have all detector rules
    assert_eq!(
        parsed["runs"][0]["tool"]["driver"]["rules"]
            .as_array()
            .unwrap()
            .len(),
        75
    );
}

#[test]
fn test_config_with_disabled_detector() {
    let (_, modules) = &*COMPILED;

    let config: AikidoConfig = toml::from_str(
        r#"
[detectors]
disable = ["missing-signature-check"]
"#,
    )
    .unwrap();

    let findings = aikido_core::config::run_detectors_with_config(modules, &config);
    assert!(
        !findings
            .iter()
            .any(|f| f.detector_name == "missing-signature-check"),
        "disabled detector should not produce findings"
    );
}

#[test]
fn test_suppression_filters_findings() {
    let (_, modules) = &*COMPILED;
    let findings = run_detectors(modules);
    let original_count = findings.len();

    // filter_suppressed with no suppression comments should keep all findings
    let after = filter_suppressed(findings, modules);
    assert_eq!(
        after.len(),
        original_count,
        "without suppression comments, all findings should remain"
    );
}

#[test]
fn test_uplc_analysis_on_sentaku_blueprint() {
    let blueprint_metrics = uplc_analysis::analyze_blueprint(&fixtures_path());
    assert!(
        !blueprint_metrics.is_empty(),
        "should find validators in plutus.json"
    );

    for bv in &blueprint_metrics {
        assert!(bv.compiled_size > 0, "compiled size should be > 0");
        if let Some(ref m) = bv.metrics {
            assert!(m.term_count > 0, "should have UPLC terms");
            assert!(m.lambda_count > 0, "should have lambdas");
            assert!(m.apply_count > 0, "should have applies");
            assert!(m.max_depth > 0, "should have depth > 0");
            eprintln!(
                "UPLC {} — {}",
                bv.title,
                uplc_analysis::format_uplc_metrics(m)
            );
        }
    }
}

#[test]
fn test_source_code_populated() {
    let (_, modules) = &*COMPILED;

    let validator_module = modules
        .iter()
        .find(|m| m.kind == ModuleKind::Validator)
        .expect("should find validator module");

    assert!(
        validator_module.source_code.is_some(),
        "validator module should have source code loaded"
    );
}

#[test]
fn test_all_detectors_registered() {
    let detectors = aikido_core::detector::all_detectors();
    assert_eq!(detectors.len(), 75, "should have 75 registered detectors");
}

// --- False-positive regression tests (#58) ---

#[test]
fn test_no_false_positive_double_satisfaction_without_outputs() {
    // Sentaku's spend handler that uses own_ref should NOT trigger double satisfaction
    let (_, modules) = &*COMPILED;
    let findings = run_detectors(modules);

    for f in &findings {
        if f.detector_name == "double-satisfaction" {
            // If it fires, own_ref should actually be unused
            assert!(
                f.description.contains("_own_ref") || f.description.contains("own_ref"),
                "double-satisfaction should only fire when own_ref is unused"
            );
        }
    }
}

#[test]
fn test_no_false_positive_unrestricted_minting_on_spend() {
    // unrestricted-minting should ONLY fire on mint handlers, never on spend
    let (_, modules) = &*COMPILED;
    let findings = run_detectors(modules);

    for f in &findings {
        if f.detector_name == "unrestricted-minting" {
            assert!(
                !f.title.contains("spend"),
                "unrestricted-minting should not fire on spend handlers"
            );
        }
    }
}

#[test]
fn test_interprocedural_analysis_reduces_false_positives() {
    // After interprocedural analysis, functions that access tx fields
    // via helper functions should be detected
    let (_, modules) = &*COMPILED;

    let validator_module = modules
        .iter()
        .find(|m| m.kind == ModuleKind::Validator)
        .expect("should find validator module");

    // Check that function body signals are propagated to handlers
    for validator in &validator_module.validators {
        for handler in &validator.handlers {
            if handler.name == "spend" {
                // After merge, the handler should have signals from called functions
                // This is a structural test - the merge happened in extract_module_info
                assert!(
                    !handler.body_signals.function_calls.is_empty(),
                    "spend handler should have function calls tracked"
                );
            }
        }
    }
}

#[test]
fn test_confidence_on_sentaku_findings() {
    // All findings should have confidence set
    let (_, modules) = &*COMPILED;
    let findings = run_detectors(modules);

    for f in &findings {
        // Confidence should be one of the valid values
        let conf_str = f.confidence.to_string();
        assert!(
            conf_str == "definite" || conf_str == "likely" || conf_str == "possible",
            "Finding '{}' has unexpected confidence: {}",
            f.detector_name,
            conf_str
        );
    }
}

// --- Snapshot tests (#60) ---

#[test]
fn test_snapshot_detector_list() {
    let detectors = all_detectors();
    let list: Vec<String> = detectors
        .iter()
        .map(|d| format!("{:<40} [{:<8}] {}", d.name(), d.severity(), d.description()))
        .collect();
    insta::assert_yaml_snapshot!("detector_list", list);
}

#[test]
fn test_snapshot_sarif_structure() {
    let (_, modules) = &*COMPILED;
    let findings = run_detectors(modules);
    let sarif_str = findings_to_sarif(&findings, Some("/project"), modules);
    let sarif: serde_json::Value = serde_json::from_str(&sarif_str).expect("valid SARIF JSON");

    // Snapshot the tool driver section (rules are stable)
    let rules = &sarif["runs"][0]["tool"]["driver"]["rules"];
    let rule_ids: Vec<&str> = rules
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["id"].as_str().unwrap())
        .collect();
    insta::assert_yaml_snapshot!("sarif_rule_ids", rule_ids);
}

#[test]
fn test_snapshot_finding_summary() {
    let (_, modules) = &*COMPILED;
    let findings = run_detectors(modules);
    let summary = aikido_core::report::format_finding_summary(&findings);
    // Verify format: summary should contain severity counts.
    // Cross-module interprocedural analysis merges signals from helper functions
    // into handlers, enabling more detectors to fire accurately (e.g., cheap-spam,
    // unbounded-datum-size, utxo-contention-risk).
    assert!(
        summary.contains("1 critical"),
        "expected 1 critical in: {summary}"
    );
    let high_count = extract_severity_count(&summary, "high");
    assert!(
        (2..=7).contains(&high_count),
        "expected 2-7 high findings, got {high_count} in: {summary}"
    );
    // Parse medium count — range accounts for cross-module signal propagation and FP reduction
    let medium_count = extract_severity_count(&summary, "medium");
    assert!(
        (3..=9).contains(&medium_count),
        "expected 3-9 medium findings, got {medium_count} in: {summary}"
    );
    // reference-script-injection downgraded from Medium to Low in v0.2.0
    let low_count = extract_severity_count(&summary, "low");
    assert!(
        (0..=2).contains(&low_count),
        "expected 0-2 low findings, got {low_count} in: {summary}"
    );
    // missing-min-ada-check downgraded from Low to Info in v0.2.0
    let info_count = extract_severity_count(&summary, "info");
    assert!(
        (0..=2).contains(&info_count),
        "expected 0-2 info findings, got {info_count} in: {summary}"
    );
}

/// Extract the numeric count before a severity label in a summary string.
/// e.g. "1 critical, 2 high, 3 medium" → extract_severity_count(s, "medium") = 3
fn extract_severity_count(summary: &str, severity: &str) -> u32 {
    for part in summary.split(',') {
        let trimmed = part.trim();
        if trimmed.ends_with(severity) {
            return trimmed
                .trim_end_matches(severity)
                .trim()
                .parse()
                .unwrap_or(0);
        }
    }
    0
}

// --- Baseline tests ---

#[test]
fn test_baseline_filters_known_findings() {
    use aikido_core::baseline::Baseline;

    let (_, modules) = &*COMPILED;
    let findings = run_detectors(modules);

    if findings.is_empty() {
        return; // Nothing to test
    }

    // Create baseline from current findings
    let baseline = Baseline::from_findings(&findings);

    // Same findings should be fully filtered
    let same_findings = run_detectors(modules);
    let filtered = baseline.filter_baselined(same_findings);
    assert!(
        filtered.is_empty(),
        "Baselined findings should be fully filtered, got {} remaining",
        filtered.len()
    );
}
