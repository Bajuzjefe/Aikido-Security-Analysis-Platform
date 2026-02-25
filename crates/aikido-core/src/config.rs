use std::collections::HashMap;
use std::path::Path;

use serde::Deserialize;

use crate::ast_walker::ModuleInfo;
use crate::compliance::filter_with_compliance;
use crate::detector::{
    all_detectors, consolidate_findings, dedup_findings, parse_severity, resolve_finding_locations,
    severity_order, Detector, Finding, Severity,
};
use crate::evidence::{compute_effective_confidence, Evidence, EvidenceLevel};
use crate::plugin::PluginConfig;
use crate::smt::{verify_finding_smt, PathCondition, SmtInterpretation};
use crate::tx_simulation::{generate_exploit_scenario, ExpectedResult};

/// Per-file configuration overrides.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct FileOverride {
    /// Glob pattern matching module paths (e.g., "validators/*.ak").
    pub pattern: String,
    /// Detectors to disable for matching files.
    #[serde(default)]
    pub disable: Vec<String>,
    /// Severity overrides for matching files.
    #[serde(default)]
    pub severity_override: HashMap<String, String>,
}

/// Configuration loaded from `.aikido.toml`.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct AikidoConfig {
    /// Extend from a base config: "aikido-strict", "aikido-lenient", or a file path.
    #[serde(default)]
    pub extends: Option<String>,

    #[serde(default)]
    pub detectors: DetectorConfig,

    /// Runtime plugin detector configuration.
    #[serde(default)]
    pub plugins: PluginConfig,

    /// Per-file configuration overrides.
    #[serde(default)]
    pub files: Vec<FileOverride>,

    /// Full-stack analysis lane toggles.
    #[serde(default)]
    pub analysis: AnalysisConfig,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct DetectorConfig {
    /// Detector names to disable entirely.
    #[serde(default)]
    pub disable: Vec<String>,

    /// Override severity for specific detectors.
    #[serde(default)]
    pub severity_override: HashMap<String, String>,

    /// Custom field name patterns that indicate authority/ownership fields.
    #[serde(default)]
    pub authority_patterns: Vec<String>,

    /// Custom field name patterns that indicate time/deadline fields.
    #[serde(default)]
    pub time_patterns: Vec<String>,

    /// Preset severity profile: "strict", "default", or "lenient".
    #[serde(default)]
    pub severity_profile: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AnalysisConfig {
    /// Enable dual-pattern compliance suppression/reduction.
    #[serde(default)]
    pub dual_pattern: bool,
    /// Enable SMT verification on high/critical findings.
    #[serde(default)]
    pub smt: bool,
    /// Enable exploit-scenario generation lane.
    #[serde(default)]
    pub simulation: bool,
    /// Optional external context-builder command for simulation.
    ///
    /// The command receives `AIKIDO_SIM_CONTEXT_REQUEST` JSON and must return
    /// JSON on stdout with shape:
    /// `{ "context": <SimPlutusData-compatible value> }`.
    #[serde(default)]
    pub simulation_context_builder_command: Option<String>,
}

impl Default for AnalysisConfig {
    fn default() -> Self {
        Self {
            dual_pattern: false,
            smt: false,
            simulation: false,
            simulation_context_builder_command: None,
        }
    }
}

impl AikidoConfig {
    /// Load config from `.aikido.toml` in the given directory. Returns default if file not found.
    pub fn load(project_root: &Path) -> Self {
        let config_path = project_root.join(".aikido.toml");
        Self::load_from_path(&config_path, project_root)
    }

    /// Load config from a specific file path. Returns default if file not found.
    pub fn load_from_file(config_file: &Path) -> Self {
        let project_root = config_file.parent().unwrap_or(Path::new("."));
        Self::load_from_path(config_file, project_root)
    }

    fn load_from_path(config_path: &Path, project_root: &Path) -> Self {
        let Ok(content) = std::fs::read_to_string(config_path) else {
            return Self::default();
        };

        let mut config: Self = toml::from_str(&content).unwrap_or_default();

        // Apply extends (config inheritance)
        if let Some(ref extends) = config.extends.clone() {
            let base = match extends.as_str() {
                "aikido-strict" => Self::strict_preset(),
                "aikido-lenient" => Self::lenient_preset(),
                path => {
                    let base_path = project_root.join(path);
                    if let Ok(base_content) = std::fs::read_to_string(&base_path) {
                        toml::from_str(&base_content).unwrap_or_default()
                    } else {
                        Self::default()
                    }
                }
            };
            config = config.merge_over(base);
        }

        config
    }

    /// Create a strict preset: all detectors enabled, severity escalated.
    fn strict_preset() -> Self {
        let mut severity_override = HashMap::new();
        severity_override.insert("missing-validity-range".to_string(), "high".to_string());
        severity_override.insert("unused-validator-parameter".to_string(), "high".to_string());
        severity_override.insert(
            "fail-only-redeemer-branch".to_string(),
            "medium".to_string(),
        );
        severity_override.insert("hardcoded-addresses".to_string(), "high".to_string());
        severity_override.insert("magic-numbers".to_string(), "medium".to_string());
        severity_override.insert("missing-min-ada-check".to_string(), "medium".to_string());
        Self {
            extends: None,
            detectors: DetectorConfig {
                disable: vec![],
                severity_override,
                severity_profile: Some("strict".to_string()),
                ..Default::default()
            },
            plugins: PluginConfig::default(),
            files: vec![],
            analysis: AnalysisConfig::default(),
        }
    }

    /// Create a lenient preset: noisy detectors disabled.
    fn lenient_preset() -> Self {
        Self {
            extends: None,
            detectors: DetectorConfig {
                disable: vec![
                    "hardcoded-addresses".to_string(),
                    "unused-validator-parameter".to_string(),
                    "fail-only-redeemer-branch".to_string(),
                    "magic-numbers".to_string(),
                    "empty-handler-body".to_string(),
                ],
                severity_profile: Some("lenient".to_string()),
                ..Default::default()
            },
            plugins: PluginConfig::default(),
            files: vec![],
            analysis: AnalysisConfig::default(),
        }
    }

    /// Merge self (overlay) over a base config. Self's values take precedence.
    fn merge_over(mut self, base: Self) -> Self {
        // Merge disable lists (union)
        for d in base.detectors.disable {
            if !self.detectors.disable.contains(&d) {
                self.detectors.disable.push(d);
            }
        }
        // Base severity overrides, then overlay's overrides take precedence
        for (k, v) in base.detectors.severity_override {
            self.detectors.severity_override.entry(k).or_insert(v);
        }
        // Base patterns merged
        for p in base.detectors.authority_patterns {
            if !self.detectors.authority_patterns.contains(&p) {
                self.detectors.authority_patterns.push(p);
            }
        }
        for p in base.detectors.time_patterns {
            if !self.detectors.time_patterns.contains(&p) {
                self.detectors.time_patterns.push(p);
            }
        }
        // Profile: overlay wins if set
        if self.detectors.severity_profile.is_none() {
            self.detectors.severity_profile = base.detectors.severity_profile;
        }
        // File overrides: concatenate
        self.files.extend(base.files);
        // Plugin paths: overlay wins if set, else inherit base.
        if self.plugins.paths.is_empty() {
            self.plugins = base.plugins;
        }
        // Keep overlay analysis settings as authoritative.
        self
    }

    /// Detectors disabled by the "lenient" profile.
    /// Must match the disable list in `lenient_preset()`.
    const LENIENT_DISABLED: &'static [&'static str] = &[
        "hardcoded-addresses",
        "unused-validator-parameter",
        "fail-only-redeemer-branch",
        "magic-numbers",
        "empty-handler-body",
    ];

    /// Check if a detector is disabled (by profile or explicit disable list).
    pub fn is_disabled(&self, detector_name: &str) -> bool {
        // Check profile-based disabling first
        if let Some(ref profile) = self.detectors.severity_profile {
            if profile == "lenient" && Self::LENIENT_DISABLED.contains(&detector_name) {
                return true;
            }
        }

        // Then check explicit disable list
        self.detectors.disable.contains(&detector_name.to_string())
    }

    /// Get severity override for a detector, if any.
    pub fn severity_override(&self, detector_name: &str) -> Option<Severity> {
        self.detectors
            .severity_override
            .get(detector_name)
            .and_then(|s| parse_severity(s))
    }

    /// Get custom authority/ownership field patterns from config.
    pub fn authority_patterns(&self) -> Vec<&str> {
        self.detectors
            .authority_patterns
            .iter()
            .map(|s| s.as_str())
            .collect()
    }

    /// Get custom time/deadline field patterns from config.
    pub fn time_patterns(&self) -> Vec<&str> {
        self.detectors
            .time_patterns
            .iter()
            .map(|s| s.as_str())
            .collect()
    }

    /// Check if a detector is disabled for a specific module path (considering file overrides).
    pub fn is_disabled_for_module(&self, detector_name: &str, module_path: &str) -> bool {
        if self.is_disabled(detector_name) {
            return true;
        }
        // Check file overrides
        for file_override in &self.files {
            if glob_matches(&file_override.pattern, module_path)
                && file_override.disable.contains(&detector_name.to_string())
            {
                return true;
            }
        }
        false
    }

    /// Get severity override for a detector in a specific module (considering file overrides).
    pub fn severity_override_for_module(
        &self,
        detector_name: &str,
        module_path: &str,
    ) -> Option<Severity> {
        // File overrides take precedence
        for file_override in &self.files {
            if glob_matches(&file_override.pattern, module_path) {
                if let Some(sev_str) = file_override.severity_override.get(detector_name) {
                    if let Some(sev) = parse_severity(sev_str) {
                        return Some(sev);
                    }
                }
            }
        }
        // Fall back to global override
        self.severity_override(detector_name)
    }

    /// Validate config against known detectors. Returns a list of warning messages.
    pub fn validate(&self) -> Vec<String> {
        let detectors = all_detectors();
        let valid_names: Vec<&str> = detectors.iter().map(|d| d.name()).collect();
        let mut warnings = Vec::new();

        // Check severity profile
        if let Some(ref profile) = self.detectors.severity_profile {
            if !["strict", "default", "lenient"].contains(&profile.as_str()) {
                warnings.push(format!(
                    "unknown severity_profile '{profile}' (use: strict, default, lenient)",
                ));
            }
        }

        // Check disabled detector names
        for name in &self.detectors.disable {
            if !valid_names.contains(&name.as_str()) {
                warnings.push(format!("unknown detector '{name}' in disable list"));
            }
        }

        // Check severity override keys and values
        for (name, severity_str) in &self.detectors.severity_override {
            if !valid_names.contains(&name.as_str()) {
                warnings.push(format!("unknown detector '{name}' in severity_override"));
            }
            if parse_severity(severity_str).is_none() {
                warnings.push(format!(
                    "invalid severity '{severity_str}' for detector '{name}' in severity_override (use: info, low, medium, high, critical)",
                ));
            }
        }

        for path in &self.plugins.paths {
            if path.trim().is_empty() {
                warnings.push("empty plugin path in [plugins].paths".to_string());
            } else {
                warnings.push(format!(
                    "legacy dynamic plugin path '{path}' configured; use [plugins].commands (ABI v2)"
                ));
            }
        }

        for cmd in &self.plugins.commands {
            if cmd.trim().is_empty() {
                warnings.push("empty plugin command in [plugins].commands".to_string());
            }
        }

        warnings
    }
}

/// Simple glob matching for file patterns. Supports `*` (any non-/ chars) and `**` (any path).
fn glob_matches(pattern: &str, path: &str) -> bool {
    let parts: Vec<&str> = pattern.split("**/").collect();
    if parts.len() == 1 {
        // No ** — simple wildcard matching
        simple_wildcard_match(pattern, path)
    } else {
        // Has ** — match prefix before ** and suffix after **
        let prefix = parts[0].trim_end_matches('/');
        let suffix = parts.last().unwrap().trim_start_matches('/');

        if !prefix.is_empty()
            && !simple_wildcard_match(prefix, &path[..path.len().min(prefix.len())])
        {
            return false;
        }
        if suffix.is_empty() {
            return true;
        }
        // Check if any suffix of path matches the suffix pattern
        for i in 0..path.len() {
            if simple_wildcard_match(suffix, &path[i..]) {
                return true;
            }
        }
        false
    }
}

fn simple_wildcard_match(pattern: &str, text: &str) -> bool {
    let mut p_star = None;
    let mut t_star = None;
    let mut pi = 0;
    let mut ti = 0;
    let p_bytes: Vec<char> = pattern.chars().collect();
    let t_bytes: Vec<char> = text.chars().collect();

    while ti < t_bytes.len() {
        if pi < p_bytes.len() && (p_bytes[pi] == '?' || p_bytes[pi] == t_bytes[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p_bytes.len() && p_bytes[pi] == '*' {
            p_star = Some(pi);
            t_star = Some(ti);
            pi += 1;
        } else if let Some(ps) = p_star {
            pi = ps + 1;
            let ts = t_star.unwrap() + 1;
            t_star = Some(ts);
            ti = ts;
        } else {
            return false;
        }
    }

    while pi < p_bytes.len() && p_bytes[pi] == '*' {
        pi += 1;
    }

    pi == p_bytes.len()
}

// parse_severity() imported from crate::detector::trait_def

/// Run detectors with config (disabling and severity overrides applied).
pub fn run_detectors_with_config(modules: &[ModuleInfo], config: &AikidoConfig) -> Vec<Finding> {
    let no_extra: &[Box<dyn Detector>] = &[];
    run_detectors_with_config_and_detectors(modules, config, no_extra)
}

/// Run detectors with config and additional runtime detectors (e.g., plugins).
pub fn run_detectors_with_config_and_detectors(
    modules: &[ModuleInfo],
    config: &AikidoConfig,
    additional_detectors: &[Box<dyn Detector>],
) -> Vec<Finding> {
    let builtins = all_detectors();
    let detector_iter = builtins.iter().chain(additional_detectors.iter());
    let mut findings: Vec<Finding> = detector_iter
        .filter(|d| !config.is_disabled(d.name()))
        .flat_map(|d| d.detect(modules))
        .collect();

    // Apply per-file overrides: filter out findings disabled for specific files
    if !config.files.is_empty() {
        findings.retain(|f| {
            let module_path = f
                .location
                .as_ref()
                .map(|l| l.module_path.as_str())
                .unwrap_or("");
            !config.is_disabled_for_module(&f.detector_name, module_path)
        });
    }

    // Apply severity overrides (per-file overrides take precedence)
    for finding in &mut findings {
        let module_path = finding
            .location
            .as_ref()
            .map(|l| l.module_path.as_str())
            .unwrap_or("");
        if let Some(override_sev) =
            config.severity_override_for_module(&finding.detector_name, module_path)
        {
            finding.severity = override_sev;
        }
    }

    // Resolve byte offsets → line:column
    resolve_finding_locations(&mut findings, modules);

    // Sort by severity (Critical first)
    findings.sort_by(|a, b| severity_order(&b.severity).cmp(&severity_order(&a.severity)));

    // Deduplicate findings with the same root cause
    dedup_findings(&mut findings);

    // Consolidate overlapping detectors on the same handler
    consolidate_findings(&mut findings);

    if config.analysis.dual_pattern {
        findings = filter_with_compliance(findings, modules);
    }

    if config.analysis.smt {
        enrich_with_smt(&mut findings);
    }

    if config.analysis.simulation {
        enrich_with_simulation_scenarios(&mut findings);
    }

    findings
}

fn enrich_with_smt(findings: &mut [Finding]) {
    let empty_conditions: Vec<PathCondition> = Vec::new();
    for finding in findings.iter_mut() {
        let sev = severity_order(&finding.severity);
        if sev < severity_order(&Severity::High) {
            continue;
        }
        let verification = verify_finding_smt(finding, &empty_conditions);
        let smt_evidence = match verification.interpretation {
            SmtInterpretation::ExploitExists {
                witness_description,
            } => Evidence {
                level: EvidenceLevel::SmtProven,
                method: "smt-simple-solver".to_string(),
                details: Some(witness_description),
                code_flow: vec![],
                witness: Some(serde_json::json!({
                    "constraints_used": verification.constraints_used,
                    "time_ms": verification.time_ms,
                    "result": "sat",
                })),
                confidence_boost: 0.6,
            },
            SmtInterpretation::FalsePositive { proof_description } => Evidence {
                level: EvidenceLevel::PathVerified,
                method: "smt-simple-solver".to_string(),
                details: Some(format!("SMT refuted exploitability: {proof_description}")),
                code_flow: vec![],
                witness: Some(serde_json::json!({
                    "constraints_used": verification.constraints_used,
                    "time_ms": verification.time_ms,
                    "result": "unsat",
                })),
                confidence_boost: 0.0,
            },
            SmtInterpretation::Inconclusive { reason } => Evidence {
                level: EvidenceLevel::PatternMatch,
                method: "smt-simple-solver".to_string(),
                details: Some(format!("SMT inconclusive: {reason}")),
                code_flow: vec![],
                witness: Some(serde_json::json!({
                    "constraints_used": verification.constraints_used,
                    "time_ms": verification.time_ms,
                    "result": "unknown",
                })),
                confidence_boost: 0.0,
            },
        };

        let merged = merge_evidence(finding.evidence.clone(), smt_evidence);
        finding.confidence = compute_effective_confidence(&finding.confidence, &merged);
        finding.evidence = Some(merged);
    }
}

fn enrich_with_simulation_scenarios(findings: &mut [Finding]) {
    for finding in findings.iter_mut() {
        let Some(scenario) = generate_exploit_scenario(finding) else {
            continue;
        };

        let expectation = match scenario.expected_result {
            ExpectedResult::ValidatorAccepts => "validator-accepts",
            ExpectedResult::ValidatorRejects => "validator-rejects",
            ExpectedResult::Unknown => "unknown",
        };

        let evidence = Evidence {
            level: EvidenceLevel::PathVerified,
            method: "tx-scenario-generation".to_string(),
            details: Some("Exploit scenario generated for runtime simulation".to_string()),
            code_flow: vec![],
            witness: Some(serde_json::json!({
                "detector": scenario.finding_detector,
                "expected_result": expectation,
                "attack_steps": scenario.attack_steps.len(),
                "has_simulated_tx": scenario.simulated_tx.is_some(),
            })),
            confidence_boost: 0.3,
        };

        let merged = merge_evidence(finding.evidence.clone(), evidence);
        finding.confidence = compute_effective_confidence(&finding.confidence, &merged);
        finding.evidence = Some(merged);
    }
}

fn merge_evidence(existing: Option<Evidence>, incoming: Evidence) -> Evidence {
    match existing {
        None => incoming,
        Some(prev) => {
            let merged_level = if prev.level == incoming.level {
                incoming.level.clone()
            } else {
                EvidenceLevel::Corroborated
            };

            let merged_method = format!("{},{}", prev.method, incoming.method);
            let merged_details = match (prev.details, incoming.details) {
                (Some(a), Some(b)) => Some(format!("{a}; {b}")),
                (Some(a), None) => Some(a),
                (None, Some(b)) => Some(b),
                (None, None) => None,
            };

            let mut code_flow = prev.code_flow;
            code_flow.extend(incoming.code_flow);

            let merged_witness = Some(match (prev.witness, incoming.witness) {
                (Some(a), Some(b)) => serde_json::json!({ "lane_1": a, "lane_2": b }),
                (Some(a), None) => a,
                (None, Some(b)) => b,
                (None, None) => serde_json::json!({}),
            });

            let merged_boost = prev
                .confidence_boost
                .max(incoming.confidence_boost)
                .max(1.0);

            Evidence {
                level: merged_level,
                method: merged_method,
                details: merged_details,
                code_flow,
                witness: merged_witness,
                confidence_boost: merged_boost,
            }
        }
    }
}

// severity_order() imported from crate::detector::trait_def

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = AikidoConfig::default();
        assert!(config.detectors.disable.is_empty());
        assert!(config.detectors.severity_override.is_empty());
        assert!(!config.is_disabled("double-satisfaction"));
    }

    #[test]
    fn test_parse_config_toml() {
        let toml_str = r#"
[detectors]
disable = ["hardcoded-addresses"]

[detectors.severity_override]
missing-validity-range = "high"
"#;
        let config: AikidoConfig = toml::from_str(toml_str).unwrap();
        assert!(config.is_disabled("hardcoded-addresses"));
        assert!(!config.is_disabled("double-satisfaction"));
        assert_eq!(
            config.severity_override("missing-validity-range"),
            Some(Severity::High)
        );
        assert_eq!(config.severity_override("double-satisfaction"), None);
    }

    #[test]
    fn test_load_nonexistent_returns_default() {
        let config = AikidoConfig::load(Path::new("/nonexistent/path"));
        assert!(config.detectors.disable.is_empty());
    }

    #[test]
    fn test_custom_field_patterns() {
        let toml_str = r#"
[detectors]
authority_patterns = ["admin", "governor"]
time_patterns = ["expiry", "lock_until"]
"#;
        let config: AikidoConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.authority_patterns(), vec!["admin", "governor"]);
        assert_eq!(config.time_patterns(), vec!["expiry", "lock_until"]);
    }

    #[test]
    fn test_custom_field_patterns_default_empty() {
        let config = AikidoConfig::default();
        assert!(config.authority_patterns().is_empty());
        assert!(config.time_patterns().is_empty());
    }

    #[test]
    fn test_validate_unknown_detector_in_disable() {
        let toml_str = r#"
[detectors]
disable = ["nonexistent-detector"]
"#;
        let config: AikidoConfig = toml::from_str(toml_str).unwrap();
        let warnings = config.validate();
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("nonexistent-detector"));
        assert!(warnings[0].contains("disable"));
    }

    #[test]
    fn test_validate_unknown_detector_in_severity_override() {
        let toml_str = r#"
[detectors]
[detectors.severity_override]
fake-detector = "high"
"#;
        let config: AikidoConfig = toml::from_str(toml_str).unwrap();
        let warnings = config.validate();
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("fake-detector"));
        assert!(warnings[0].contains("severity_override"));
    }

    #[test]
    fn test_validate_invalid_severity_value() {
        let toml_str = r#"
[detectors]
[detectors.severity_override]
double-satisfaction = "super-critical"
"#;
        let config: AikidoConfig = toml::from_str(toml_str).unwrap();
        let warnings = config.validate();
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("super-critical"));
        assert!(warnings[0].contains("invalid severity"));
    }

    #[test]
    fn test_validate_valid_config_no_warnings() {
        let toml_str = r#"
[detectors]
disable = ["hardcoded-addresses"]

[detectors.severity_override]
missing-validity-range = "high"
"#;
        let config: AikidoConfig = toml::from_str(toml_str).unwrap();
        let warnings = config.validate();
        assert!(warnings.is_empty());
    }

    #[test]
    fn test_profile_strict_enables_all() {
        let toml_str = r#"
[detectors]
severity_profile = "strict"
"#;
        let config: AikidoConfig = toml::from_str(toml_str).unwrap();
        assert!(!config.is_disabled("hardcoded-addresses"));
        assert!(!config.is_disabled("unused-validator-parameter"));
        assert!(!config.is_disabled("fail-only-redeemer-branch"));
        assert!(!config.is_disabled("double-satisfaction"));
    }

    #[test]
    fn test_profile_default_enables_all() {
        let toml_str = r#"
[detectors]
severity_profile = "default"
"#;
        let config: AikidoConfig = toml::from_str(toml_str).unwrap();
        assert!(!config.is_disabled("hardcoded-addresses"));
        assert!(!config.is_disabled("double-satisfaction"));
    }

    #[test]
    fn test_profile_lenient_disables_noisy() {
        let toml_str = r#"
[detectors]
severity_profile = "lenient"
"#;
        let config: AikidoConfig = toml::from_str(toml_str).unwrap();
        // All 5 LENIENT_DISABLED detectors should be disabled
        assert!(config.is_disabled("hardcoded-addresses"));
        assert!(config.is_disabled("unused-validator-parameter"));
        assert!(config.is_disabled("fail-only-redeemer-branch"));
        assert!(config.is_disabled("magic-numbers"));
        assert!(config.is_disabled("empty-handler-body"));
        // Other detectors remain enabled
        assert!(!config.is_disabled("double-satisfaction"));
        assert!(!config.is_disabled("missing-validity-range"));
    }

    #[test]
    fn test_validate_unknown_profile() {
        let toml_str = r#"
[detectors]
severity_profile = "paranoid"
"#;
        let config: AikidoConfig = toml::from_str(toml_str).unwrap();
        let warnings = config.validate();
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("paranoid"));
        assert!(warnings[0].contains("severity_profile"));
    }

    #[test]
    fn test_severity_override_case_insensitive() {
        let toml_str = r#"
[detectors]
[detectors.severity_override]
test-detector = "Critical"
"#;
        let config: AikidoConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(
            config.severity_override("test-detector"),
            Some(Severity::Critical)
        );
    }

    #[test]
    fn test_extends_strict_preset() {
        let toml_str = r#"
extends = "aikido-strict"
"#;
        let config: AikidoConfig = toml::from_str(toml_str).unwrap();
        let merged = config.merge_over(AikidoConfig::strict_preset());
        assert!(merged.detectors.disable.is_empty());
        assert!(merged
            .detectors
            .severity_override
            .contains_key("missing-validity-range"));
    }

    #[test]
    fn test_extends_lenient_preset() {
        let toml_str = r#"
extends = "aikido-lenient"
"#;
        let config: AikidoConfig = toml::from_str(toml_str).unwrap();
        let merged = config.merge_over(AikidoConfig::lenient_preset());
        assert!(merged
            .detectors
            .disable
            .contains(&"hardcoded-addresses".to_string()));
        assert!(merged
            .detectors
            .disable
            .contains(&"magic-numbers".to_string()));
    }

    #[test]
    fn test_extends_overlay_takes_precedence() {
        let base = AikidoConfig {
            detectors: DetectorConfig {
                severity_override: {
                    let mut m = HashMap::new();
                    m.insert("double-satisfaction".to_string(), "medium".to_string());
                    m
                },
                ..Default::default()
            },
            ..Default::default()
        };
        let overlay = AikidoConfig {
            detectors: DetectorConfig {
                severity_override: {
                    let mut m = HashMap::new();
                    m.insert("double-satisfaction".to_string(), "critical".to_string());
                    m
                },
                ..Default::default()
            },
            ..Default::default()
        };
        let merged = overlay.merge_over(base);
        assert_eq!(
            merged
                .detectors
                .severity_override
                .get("double-satisfaction"),
            Some(&"critical".to_string())
        );
    }

    #[test]
    fn test_file_override_disables_detector() {
        let toml_str = r#"
[[files]]
pattern = "validators/*.ak"
disable = ["magic-numbers"]
"#;
        let config: AikidoConfig = toml::from_str(toml_str).unwrap();
        assert!(config.is_disabled_for_module("magic-numbers", "validators/pool.ak"));
        assert!(!config.is_disabled_for_module("magic-numbers", "lib/utils.ak"));
    }

    #[test]
    fn test_file_override_severity() {
        let toml_str = r#"
[[files]]
pattern = "validators/*.ak"
[files.severity_override]
missing-validity-range = "critical"
"#;
        let config: AikidoConfig =
            toml::from_str(toml_str).expect("file override TOML should parse");
        assert_eq!(
            config.severity_override_for_module("missing-validity-range", "validators/pool.ak"),
            Some(Severity::Critical)
        );
        // Non-matching path falls back to global
        assert_eq!(
            config.severity_override_for_module("missing-validity-range", "lib/utils.ak"),
            None
        );
    }

    #[test]
    fn test_file_override_non_matching_no_effect() {
        let config = AikidoConfig {
            files: vec![FileOverride {
                pattern: "test/*.ak".to_string(),
                disable: vec!["double-satisfaction".to_string()],
                severity_override: HashMap::new(),
            }],
            ..Default::default()
        };
        assert!(!config.is_disabled_for_module("double-satisfaction", "validators/pool.ak"));
    }

    #[test]
    fn test_glob_matches_basic() {
        assert!(simple_wildcard_match("*.ak", "pool.ak"));
        assert!(!simple_wildcard_match("*.ak", "pool.rs"));
        assert!(simple_wildcard_match("validators/*", "validators/pool.ak"));
        assert!(!simple_wildcard_match("validators/*", "lib/pool.ak"));
    }
}
