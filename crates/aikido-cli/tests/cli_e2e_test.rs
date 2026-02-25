use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn project_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn fixtures_path() -> PathBuf {
    project_root().join("fixtures/sentaku-contracts")
}

fn benchmark_manifest_path() -> PathBuf {
    project_root().join("benchmarks/local-fixtures.toml")
}

fn aikido_bin() -> PathBuf {
    // The binary is built to target/debug/aikido
    project_root().join("target/debug/aikido")
}

/// Ensure the binary is built before running tests.
fn ensure_built() {
    let output = Command::new("cargo")
        .args(["build", "--bin", "aikido"])
        .current_dir(project_root())
        .output()
        .expect("failed to build aikido");
    assert!(
        output.status.success(),
        "failed to build aikido binary\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn unique_temp_path(stem: &str, ext: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock should be monotonic")
        .as_nanos();
    std::env::temp_dir().join(format!("aikido-cli-{stem}-{nanos}.{ext}"))
}

#[test]
fn test_cli_version_flag() {
    ensure_built();
    let output = Command::new(aikido_bin())
        .arg("--version")
        .output()
        .expect("failed to run aikido --version");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("aikido"), "should contain 'aikido'");
    assert!(stdout.contains("0.3.0"), "should contain version");
    assert!(output.status.success());
}

#[test]
fn test_cli_list_rules() {
    ensure_built();
    let output = Command::new(aikido_bin())
        .arg("--list-rules")
        .output()
        .expect("failed to run aikido --list-rules");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("double-satisfaction"));
    assert!(stdout.contains("missing-signature-check"));
    assert!(stdout.contains("unrestricted-minting"));
    assert!(stdout.contains("75"), "should show 75 detectors");
    assert!(output.status.success());
}

#[test]
fn test_cli_explain_rule() {
    ensure_built();
    let output = Command::new(aikido_bin())
        .args(["--explain", "double-satisfaction"])
        .output()
        .expect("failed to run aikido --explain");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("double-satisfaction"));
    assert!(stdout.contains("Critical"));
    assert!(stdout.contains("OutputReference"));
    assert!(output.status.success());
}

#[test]
fn test_cli_explain_unknown_rule() {
    ensure_built();
    let output = Command::new(aikido_bin())
        .args(["--explain", "nonexistent-rule"])
        .output()
        .expect("failed to run aikido --explain");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("unknown rule"));
}

#[test]
fn test_cli_text_output_on_sentaku() {
    ensure_built();
    let output = Command::new(aikido_bin())
        .args([
            fixtures_path().to_str().unwrap(),
            "--quiet",
            "--fail-on",
            "critical",
        ])
        .output()
        .expect("failed to run aikido on sentaku");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("AIKIDO") || stdout.contains("FINDINGS") || stdout.contains("SUMMARY"),
        "should produce text output"
    );
    assert!(
        output.status.code() == Some(0) || output.status.code() == Some(2),
        "text run should exit with 0 or 2, got {:?}",
        output.status.code()
    );
}

#[test]
fn test_cli_json_output() {
    ensure_built();
    let output = Command::new(aikido_bin())
        .args([
            fixtures_path().to_str().unwrap(),
            "--format",
            "json",
            "--quiet",
            "--fail-on",
            "critical",
        ])
        .output()
        .expect("failed to run aikido --format json");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).expect("should be valid JSON");
    assert_eq!(parsed["schema_version"], "aikido.findings.v1");
    assert!(parsed["project"].is_string());
    assert!(parsed["findings"].is_array());
    assert!(parsed["total"].is_number());
    assert!(parsed["analysis_lanes"].is_object());
    assert_eq!(
        parsed["analysis_lanes"]["detectors"]["runtime_integrated"],
        serde_json::json!(true)
    );
    assert_eq!(
        parsed["analysis_lanes"]["simulation"]["runtime_integrated"],
        serde_json::json!(true)
    );
    assert_eq!(
        parsed["analysis_lanes"]["path_cfg_ssa_symbolic"]["runtime_integrated"],
        serde_json::json!(false)
    );
    assert_eq!(
        parsed["analysis_lanes"]["path_cfg_ssa_symbolic"]["status"],
        serde_json::json!("not_integrated")
    );
    if let Some(first) = parsed["findings"].as_array().and_then(|a| a.first()) {
        assert!(first["reliability_tier"].is_string());
    }
    assert!(
        output.status.code() == Some(0) || output.status.code() == Some(2),
        "json run should exit with 0 or 2, got {:?}",
        output.status.code()
    );
}

#[test]
fn test_cli_sarif_output() {
    ensure_built();
    let output = Command::new(aikido_bin())
        .args([
            fixtures_path().to_str().unwrap(),
            "--format",
            "sarif",
            "--quiet",
            "--fail-on",
            "critical",
        ])
        .output()
        .expect("failed to run aikido --format sarif");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("should be valid SARIF JSON");
    assert_eq!(parsed["version"], "2.1.0");
    assert!(parsed["runs"][0]["tool"]["driver"]["rules"].is_array());
    assert!(
        output.status.code() == Some(0) || output.status.code() == Some(2),
        "sarif run should exit with 0 or 2, got {:?}",
        output.status.code()
    );
}

#[test]
fn test_cli_fail_on_flag() {
    ensure_built();

    // With --fail-on critical, medium-only findings should exit 0
    let output = Command::new(aikido_bin())
        .args([
            fixtures_path().to_str().unwrap(),
            "--quiet",
            "--fail-on",
            "critical",
            "--min-severity",
            "medium",
        ])
        .output()
        .expect("failed to run aikido --fail-on");

    // Exit code depends on whether critical findings exist
    // We just verify it runs without error
    assert!(
        output.status.code() == Some(0) || output.status.code() == Some(2),
        "should exit with 0 or 2, got {:?}",
        output.status.code()
    );
}

#[test]
fn test_cli_invalid_severity() {
    ensure_built();
    let output = Command::new(aikido_bin())
        .args([
            fixtures_path().to_str().unwrap(),
            "--min-severity",
            "invalid",
        ])
        .output()
        .expect("failed to run aikido");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("invalid severity"));
}

#[test]
fn test_cli_nonexistent_project() {
    ensure_built();
    let output = Command::new(aikido_bin())
        .arg("/nonexistent/path")
        .output()
        .expect("failed to run aikido");

    assert!(!output.status.success());
}

#[test]
fn test_cli_benchmark_manifest_json_output() {
    ensure_built();
    let output = Command::new(aikido_bin())
        .args([
            "--benchmark-manifest",
            benchmark_manifest_path().to_str().unwrap(),
            "--format",
            "json",
            "--benchmark-enforce-gates",
        ])
        .output()
        .expect("failed to run aikido --benchmark-manifest");

    assert!(
        output.status.success(),
        "benchmark run should pass gates. stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("benchmark output should be valid JSON");
    assert_eq!(parsed["schema_version"], "aikido.benchmark.v1");
    assert!(parsed["fixture_results"].is_array());
    assert!(parsed["totals"]["finding_count"].is_number());
    assert!(parsed["gate_evaluation"]["passed"].is_boolean());
}

#[test]
fn test_cli_plugin_load_failure_is_fatal() {
    ensure_built();
    let config_path = unique_temp_path("plugin-config", "toml");
    let missing_plugin = "definitely_missing_plugin_command_for_test_1234567890";
    let content = format!(
        r#"[plugins]
commands = ["{missing_plugin}"]
"#
    );
    std::fs::write(&config_path, content).expect("write config");

    let output = Command::new(aikido_bin())
        .args([
            fixtures_path().to_str().unwrap(),
            "--config",
            config_path.to_str().unwrap(),
            "--quiet",
        ])
        .output()
        .expect("failed to run aikido with plugin config");

    let _ = std::fs::remove_file(&config_path);

    assert!(
        !output.status.success(),
        "plugin load failure must fail run, got status {:?}",
        output.status.code()
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("plugin execution failed")
            || stderr.contains("plugin launch failed")
            || stderr.contains("not found"),
        "stderr should report plugin process failure, got: {stderr}"
    );
}
