//! Property-based tests (#100) using proptest.
//! Generate random ModuleInfo structures and verify detectors never panic.

use proptest::prelude::*;
use std::collections::HashSet;

use aikido_core::ast_walker::{
    ConstructorInfo, DataTypeInfo, FieldInfo, HandlerInfo, ModuleInfo, ModuleKind, ParamInfo,
    ValidatorInfo,
};
use aikido_core::body_analysis::{BodySignals, WhenBranchInfo};
use aikido_core::detector::run_detectors;

// --- Strategies for generating random AST structures ---

fn arb_string() -> impl Strategy<Value = String> {
    prop::collection::vec(prop::char::range('a', 'z'), 1..20)
        .prop_map(|chars| chars.into_iter().collect())
}

fn arb_module_name() -> impl Strategy<Value = String> {
    arb_string().prop_map(|s| format!("test/{s}"))
}

fn arb_type_name() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("Int".to_string()),
        Just("Bool".to_string()),
        Just("ByteArray".to_string()),
        Just("List<Int>".to_string()),
        Just("Option<ByteArray>".to_string()),
        Just("Data".to_string()),
        arb_string(),
    ]
}

fn arb_param() -> impl Strategy<Value = ParamInfo> {
    (arb_string(), arb_type_name()).prop_map(|(name, type_name)| ParamInfo { name, type_name })
}

fn arb_when_branch() -> impl Strategy<Value = WhenBranchInfo> {
    (any::<bool>(), any::<bool>(), any::<bool>(), arb_string()).prop_map(
        |(is_catchall, body_is_literal_true, body_is_error, pattern_text)| WhenBranchInfo {
            pattern_text,
            is_catchall,
            body_is_literal_true,
            body_is_error,
        },
    )
}

fn arb_hash_set(max_items: usize) -> impl Strategy<Value = HashSet<String>> {
    prop::collection::vec(arb_string(), 0..max_items).prop_map(|v| v.into_iter().collect())
}

fn arb_body_signals() -> impl Strategy<Value = BodySignals> {
    // Split into two groups to stay within proptest's 12-element tuple limit
    let group1 = (
        arb_hash_set(5),                                // tx_field_accesses
        any::<bool>(),                                  // uses_own_ref
        arb_hash_set(5),                                // function_calls
        arb_hash_set(5),                                // var_references
        prop::collection::vec(arb_when_branch(), 0..4), // when_branches
        arb_hash_set(3),                                // expect_some_vars
        arb_hash_set(3),                                // tx_list_iterations
    );

    let group2 = (
        prop::collection::vec(0..100usize, 0..5), // bytearray_literal_lengths
        arb_hash_set(5),                          // all_record_labels
        any::<bool>(),                            // has_division
        prop::collection::vec(arb_string(), 0..3), // unsafe_list_access_calls
        arb_hash_set(3),                          // redeemer_tainted_vars
        arb_hash_set(3),                          // datum_field_accesses
    );

    (group1, group2).prop_map(
        |(
            (
                tx_field_accesses,
                uses_own_ref,
                function_calls,
                var_references,
                when_branches,
                expect_some_vars,
                tx_list_iterations,
            ),
            (
                bytearray_literal_lengths,
                all_record_labels,
                has_division,
                unsafe_list_access_calls,
                redeemer_tainted_vars,
                datum_field_accesses,
            ),
        )| {
            BodySignals {
                tx_field_accesses,
                uses_own_ref,
                function_calls,
                var_references,
                when_branches,
                expect_some_vars,
                tx_list_iterations,
                bytearray_literal_lengths,
                all_record_labels,
                has_division,
                unsafe_list_access_calls,
                redeemer_tainted_vars,
                has_subtraction: false,
                has_multiplication: false,
                has_expect_list_destructure: false,
                has_unsafe_match_comparison: false,
                datum_field_accesses,
                enforces_single_input: false,
                has_record_update: false,
                guarded_vars: HashSet::new(),
                division_divisors: HashSet::new(),
                guarded_operations: vec![],
                has_fold_counting_pattern: false,
                requires_signature: false,
                subtraction_operands: HashSet::new(),
                quantity_of_call_count: 0,
                quantity_of_asset_pairs: HashSet::new(),
                tautological_comparisons: vec![],
                datum_equality_checks: HashSet::new(),
                has_datum_continuity_assertion: false,
            }
        },
    )
}

fn arb_handler() -> impl Strategy<Value = HandlerInfo> {
    (
        prop_oneof![
            Just("spend".to_string()),
            Just("mint".to_string()),
            Just("withdraw".to_string()),
            arb_string(),
        ],
        prop::collection::vec(arb_param(), 0..5),
        arb_type_name(),
        arb_body_signals(),
        prop::option::of((0..1000usize, 0..1000usize)),
    )
        .prop_map(
            |(name, params, return_type, body_signals, location)| HandlerInfo {
                name,
                params,
                return_type,
                body_signals,
                location,
            },
        )
}

fn arb_field() -> impl Strategy<Value = FieldInfo> {
    (prop::option::of(arb_string()), arb_type_name())
        .prop_map(|(label, type_name)| FieldInfo { label, type_name })
}

fn arb_constructor() -> impl Strategy<Value = ConstructorInfo> {
    (arb_string(), prop::collection::vec(arb_field(), 0..6))
        .prop_map(|(name, fields)| ConstructorInfo { name, fields })
}

fn arb_data_type() -> impl Strategy<Value = DataTypeInfo> {
    (
        arb_string(),
        any::<bool>(),
        prop::collection::vec(arb_constructor(), 1..4),
    )
        .prop_map(|(name, public, constructors)| DataTypeInfo {
            name,
            public,
            constructors,
        })
}

fn arb_validator() -> impl Strategy<Value = ValidatorInfo> {
    (
        arb_string(),
        prop::collection::vec(arb_param(), 0..3),
        prop::collection::vec(arb_handler(), 1..4),
    )
        .prop_map(|(name, params, handlers)| ValidatorInfo {
            name,
            params,
            handlers,
            summary: None,
        })
}

fn arb_module_kind() -> impl Strategy<Value = ModuleKind> {
    prop_oneof![Just(ModuleKind::Validator), Just(ModuleKind::Lib),]
}

fn arb_module() -> impl Strategy<Value = ModuleInfo> {
    (
        arb_module_name(),
        arb_module_kind(),
        prop::collection::vec(arb_validator(), 0..3),
        prop::collection::vec(arb_data_type(), 0..3),
        0..10usize,
    )
        .prop_map(|(name, kind, validators, data_types, test_count)| {
            let path = format!("{name}.ak");
            ModuleInfo {
                name,
                path,
                kind,
                validators,
                data_types,
                functions: vec![],
                constants: vec![],
                type_aliases: vec![],
                test_count,
                source_code: None,
                test_function_names: vec![],
            }
        })
}

fn arb_modules() -> impl Strategy<Value = Vec<ModuleInfo>> {
    prop::collection::vec(arb_module(), 1..5)
}

// --- Property tests ---

proptest! {
    #![proptest_config(ProptestConfig::with_cases(200))]

    #[test]
    fn detectors_never_panic(modules in arb_modules()) {
        // The primary property: detectors must never panic on any input
        let _findings = run_detectors(&modules);
    }

    #[test]
    fn findings_have_valid_severity(modules in arb_modules()) {
        let findings = run_detectors(&modules);
        for f in &findings {
            let _ = f.severity.to_string();
            let _ = f.confidence.to_string();
        }
    }

    #[test]
    fn findings_have_nonempty_names(modules in arb_modules()) {
        let findings = run_detectors(&modules);
        for f in &findings {
            prop_assert!(!f.detector_name.is_empty(), "detector_name must not be empty");
            prop_assert!(!f.title.is_empty(), "title must not be empty");
            prop_assert!(!f.description.is_empty(), "description must not be empty");
        }
    }

    #[test]
    fn empty_modules_produce_no_findings(modules in prop::collection::vec(
        arb_module_name().prop_map(|name| {
            let path = format!("{name}.ak");
            ModuleInfo {
                name,
                path,
                kind: ModuleKind::Lib,
                validators: vec![],
                data_types: vec![],
                functions: vec![],
                constants: vec![],
                type_aliases: vec![],
                test_count: 0,
                source_code: None,
                test_function_names: vec![],
            }
        }),
        1..5,
    )) {
        let findings = run_detectors(&modules);
        prop_assert!(findings.is_empty(), "empty modules should produce no findings, got: {}", findings.len());
    }

    #[test]
    fn sarif_output_is_valid_json(modules in arb_modules()) {
        let findings = run_detectors(&modules);
        let sarif = aikido_core::sarif::findings_to_sarif(&findings, None, &modules);
        let parsed: serde_json::Value = serde_json::from_str(&sarif)
            .expect("SARIF should always be valid JSON");
        prop_assert_eq!(parsed["version"].as_str().unwrap(), "2.1.0");
    }

    #[test]
    fn markdown_output_doesnt_panic(modules in arb_modules()) {
        let findings = run_detectors(&modules);
        let _ = aikido_core::markdown::findings_to_markdown(&findings, "test", "0.1.0", &modules);
    }

    #[test]
    fn html_output_doesnt_panic(modules in arb_modules()) {
        let findings = run_detectors(&modules);
        let _ = aikido_core::html::findings_to_html(&findings, "test", "0.1.0", &modules);
    }

    #[test]
    fn rdjson_output_doesnt_panic(modules in arb_modules()) {
        let findings = run_detectors(&modules);
        let _ = aikido_core::reviewdog::findings_to_rdjson(&findings, None);
    }

    #[test]
    fn config_disable_removes_detector_findings(modules in arb_modules()) {
        let all_findings = run_detectors(&modules);
        if !all_findings.is_empty() {
            let detector_to_disable = &all_findings[0].detector_name;
            let config: aikido_core::config::AikidoConfig = toml::from_str(
                &format!("[detectors]\ndisable = [\"{detector_to_disable}\"]")
            ).unwrap();
            let filtered = aikido_core::config::run_detectors_with_config(&modules, &config);
            // The disabled detector should not appear in results
            prop_assert!(
                !filtered.iter().any(|f| f.detector_name == *detector_to_disable),
                "disabled detector '{}' should not produce findings",
                detector_to_disable
            );
        }
    }

    #[test]
    fn baseline_filters_consistently(modules in arb_modules()) {
        let findings = run_detectors(&modules);
        let baseline = aikido_core::baseline::Baseline::from_findings(&findings);
        let same = run_detectors(&modules);
        let filtered = baseline.filter_baselined(same);
        prop_assert!(filtered.is_empty(), "baselined findings should be fully filtered");
    }

    #[test]
    fn suppression_with_no_comments_preserves_all(modules in arb_modules()) {
        let findings = run_detectors(&modules);
        let count_before = findings.len();
        let after = aikido_core::suppression::filter_suppressed(findings, &modules);
        prop_assert_eq!(after.len(), count_before, "no suppression comments → all findings kept");
    }
}
