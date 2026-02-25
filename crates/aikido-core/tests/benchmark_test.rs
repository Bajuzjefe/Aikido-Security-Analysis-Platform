use std::path::PathBuf;

use aikido_core::run_benchmark_manifest;

fn project_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

#[test]
fn test_run_benchmark_manifest_on_referral_fixture() {
    let root = project_root();
    let fixture = root.join("fixtures/referral-system");
    let manifest_path = root.join("target/benchmark-test-manifest.toml");

    let fixture_path = fixture.to_string_lossy().replace('\\', "/");
    let manifest_content = format!(
        r#"
[[fixtures]]
name = "referral-system"
project = "{fixture_path}"
accuracy = ".aikido-accuracy.toml"
"#
    );
    std::fs::write(&manifest_path, manifest_content).expect("should write temp benchmark manifest");

    let summary = run_benchmark_manifest(&manifest_path).expect("benchmark run should succeed");
    assert_eq!(summary.totals.fixture_count, 1);
    assert_eq!(summary.fixture_results.len(), 1);
    assert!(summary.totals.finding_count > 0);
    assert!(summary.totals.evaluated_cases > 0);

    let _ = std::fs::remove_file(&manifest_path);
}
