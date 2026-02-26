//! Benchmark suite (#102) for aikido analysis engine.
//! Measures performance of key operations across different input sizes.

use std::collections::HashSet;
use std::path::PathBuf;

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};

use aikido_core::ast_walker::{
    ConstructorInfo, DataTypeInfo, FieldInfo, HandlerInfo, ModuleInfo, ModuleKind, ParamInfo,
    ValidatorInfo,
};
use aikido_core::body_analysis::{BodySignals, WhenBranchInfo};
use aikido_core::detector::{all_detectors, run_detectors};

fn fixtures_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures")
        .join(name)
}

/// Generate synthetic modules with `n` validators, each with `h` handlers.
fn generate_modules(
    num_modules: usize,
    validators_per: usize,
    handlers_per: usize,
) -> Vec<ModuleInfo> {
    (0..num_modules)
        .map(|mi| {
            let validators = (0..validators_per)
                .map(|vi| {
                    let handlers = (0..handlers_per)
                        .map(|hi| {
                            let name = if hi == 0 {
                                "spend".to_string()
                            } else {
                                format!("handler_{hi}")
                            };

                            let mut tx_field_accesses = HashSet::new();
                            tx_field_accesses.insert("outputs".to_string());
                            tx_field_accesses.insert("inputs".to_string());

                            let mut function_calls = HashSet::new();
                            function_calls.insert("list.any".to_string());

                            let mut var_references = HashSet::new();
                            var_references.insert("datum".to_string());
                            var_references.insert("tx".to_string());

                            HandlerInfo {
                                name,
                                params: vec![
                                    ParamInfo {
                                        name: "datum".to_string(),
                                        type_name: "Option<MyDatum>".to_string(),
                                    },
                                    ParamInfo {
                                        name: "redeemer".to_string(),
                                        type_name: "MyRedeemer".to_string(),
                                    },
                                    ParamInfo {
                                        name: "own_ref".to_string(),
                                        type_name: "OutputReference".to_string(),
                                    },
                                    ParamInfo {
                                        name: "tx".to_string(),
                                        type_name: "Transaction".to_string(),
                                    },
                                ],
                                return_type: "Bool".to_string(),
                                body_signals: BodySignals {
                                    tx_field_accesses,
                                    uses_own_ref: hi % 2 == 0,
                                    function_calls,
                                    var_references,
                                    when_branches: vec![
                                        WhenBranchInfo {
                                            pattern_text: "ActionA".to_string(),
                                            is_catchall: false,
                                            body_is_literal_true: false,
                                            body_is_error: false,
                                        },
                                        WhenBranchInfo {
                                            pattern_text: "ActionB".to_string(),
                                            is_catchall: false,
                                            body_is_literal_true: false,
                                            body_is_error: false,
                                        },
                                    ],
                                    ..BodySignals::default()
                                },
                                location: Some((100 + hi * 50, 200 + hi * 50)),
                            }
                        })
                        .collect();

                    ValidatorInfo {
                        name: format!("validator_{vi}"),
                        params: vec![],
                        handlers,
                        summary: None,
                    }
                })
                .collect();

            let data_types = vec![DataTypeInfo {
                name: "MyDatum".to_string(),
                public: true,
                constructors: vec![ConstructorInfo {
                    name: "MyDatum".to_string(),
                    fields: vec![
                        FieldInfo {
                            label: Some("owner".to_string()),
                            type_name: "ByteArray".to_string(),
                        },
                        FieldInfo {
                            label: Some("deadline".to_string()),
                            type_name: "Int".to_string(),
                        },
                    ],
                }],
            }];

            ModuleInfo {
                name: format!("test/module_{mi}"),
                path: format!("validators/module_{mi}.ak"),
                kind: ModuleKind::Validator,
                validators,
                data_types,
                functions: vec![],
                constants: vec![],
                type_aliases: vec![],
                test_count: 0,
                test_function_names: vec![],
                source_code: None,
            }
        })
        .collect()
}

fn bench_detector_registration(c: &mut Criterion) {
    c.bench_function("all_detectors_registration", |b| {
        b.iter(|| {
            let detectors = all_detectors();
            black_box(detectors.len());
        });
    });
}

fn bench_run_detectors_synthetic(c: &mut Criterion) {
    let mut group = c.benchmark_group("run_detectors_synthetic");

    for &(modules, validators, handlers) in &[
        (1, 1, 1),  // Small: 1 module, 1 validator, 1 handler
        (1, 1, 4),  // Single validator, 4 handlers
        (3, 2, 2),  // Medium: 3 modules, 2 validators each, 2 handlers
        (10, 3, 3), // Large: 10 modules, 3 validators, 3 handlers
        (20, 5, 4), // Very large: 20 modules, 5 validators, 4 handlers
    ] {
        let label = format!("{modules}m_{validators}v_{handlers}h");
        let input = generate_modules(modules, validators, handlers);
        group.bench_with_input(
            BenchmarkId::new("detectors", &label),
            &input,
            |b, modules| {
                b.iter(|| {
                    let findings = run_detectors(black_box(modules));
                    black_box(findings.len());
                });
            },
        );
    }

    group.finish();
}

fn bench_sarif_output(c: &mut Criterion) {
    let modules = generate_modules(5, 3, 3);
    let findings = run_detectors(&modules);

    c.bench_function("sarif_output", |b| {
        b.iter(|| {
            let sarif = aikido_core::sarif::findings_to_sarif(
                black_box(&findings),
                Some("/project"),
                black_box(&modules),
            );
            black_box(sarif.len());
        });
    });
}

fn bench_html_output(c: &mut Criterion) {
    let modules = generate_modules(5, 3, 3);
    let findings = run_detectors(&modules);

    c.bench_function("html_output", |b| {
        b.iter(|| {
            let html = aikido_core::html::findings_to_html(
                black_box(&findings),
                "test-project",
                "0.1.0",
                black_box(&modules),
            );
            black_box(html.len());
        });
    });
}

fn bench_markdown_output(c: &mut Criterion) {
    let modules = generate_modules(5, 3, 3);
    let findings = run_detectors(&modules);

    c.bench_function("markdown_output", |b| {
        b.iter(|| {
            let md = aikido_core::markdown::findings_to_markdown(
                black_box(&findings),
                "test-project",
                "0.1.0",
                black_box(&modules),
            );
            black_box(md.len());
        });
    });
}

fn bench_baseline(c: &mut Criterion) {
    let modules = generate_modules(10, 3, 3);
    let findings = run_detectors(&modules);
    let baseline = aikido_core::baseline::Baseline::from_findings(&findings);

    c.bench_function("baseline_filter", |b| {
        b.iter(|| {
            let new_findings = run_detectors(black_box(&modules));
            let filtered = baseline.filter_baselined(new_findings);
            black_box(filtered.len());
        });
    });
}

fn bench_suppression(c: &mut Criterion) {
    let modules = generate_modules(5, 3, 3);
    let findings = run_detectors(&modules);

    c.bench_function("suppression_filter", |b| {
        b.iter(|| {
            let f = findings.clone();
            let after = aikido_core::suppression::filter_suppressed(f, black_box(&modules));
            black_box(after.len());
        });
    });
}

fn bench_uplc_analysis(c: &mut Criterion) {
    let sentaku_path = fixtures_path("sentaku-contracts");
    if sentaku_path.join("plutus.json").exists() {
        c.bench_function("uplc_analyze_blueprint", |b| {
            b.iter(|| {
                let metrics =
                    aikido_core::uplc_analysis::analyze_blueprint(black_box(&sentaku_path));
                black_box(metrics.len());
            });
        });
    }
}

criterion_group!(
    benches,
    bench_detector_registration,
    bench_run_detectors_synthetic,
    bench_sarif_output,
    bench_html_output,
    bench_markdown_output,
    bench_baseline,
    bench_suppression,
    bench_uplc_analysis,
);
criterion_main!(benches);
