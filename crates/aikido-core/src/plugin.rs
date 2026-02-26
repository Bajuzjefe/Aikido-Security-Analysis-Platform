//! Runtime execution for external detector plugins.
//!
//! Plugins run as subprocesses and communicate over JSON via
//! `AIKIDO_PLUGIN_REQUEST` (environment variable) and stdout.
//! This avoids unsafe ABI coupling across dynamic Rust libraries.

use std::path::Path;
use std::process::{Command, Stdio};

use serde::{Deserialize, Serialize};

use crate::detector::{parse_severity, Confidence, Finding, Severity, SourceLocation};

/// Current plugin protocol version.
pub const AIKIDO_PLUGIN_API_VERSION: u32 = 2;
const PLUGIN_SCHEMA_V1: &str = "aikido-plugin-v1";

/// Plugin configuration from `.aikido.toml`.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct PluginConfig {
    /// Legacy dynamic-library plugin paths (unsupported in ABI v2).
    #[serde(default)]
    pub paths: Vec<String>,
    /// Commands to execute as plugins.
    #[serde(default)]
    pub commands: Vec<String>,
    /// Legacy opt-in for ABI v1 dynamic plugins (ignored in ABI v2).
    #[serde(default)]
    pub allow_unsafe_abi: bool,
}

/// Metadata about a loaded plugin.
#[derive(Debug, Clone)]
pub struct LoadedPlugin {
    /// Name reported by plugin response (or fallback command).
    pub name: String,
    /// Command executed for this plugin.
    pub path: String,
    /// Number of findings returned by this plugin.
    pub detector_count: usize,
}

/// Loaded plugin bundle.
#[derive(Debug)]
pub struct PluginBundle {
    pub findings: Vec<Finding>,
    pub loaded_plugins: Vec<LoadedPlugin>,
}

impl PluginBundle {
    pub fn is_empty(&self) -> bool {
        self.loaded_plugins.is_empty()
    }

    pub fn plugin_count(&self) -> usize {
        self.loaded_plugins.len()
    }
}

/// Error type for plugin loading.
#[derive(Debug, Clone)]
pub enum PluginError {
    /// Deprecated dynamic library plugin path was configured.
    DynamicAbiUnsupported { path: String },
    /// Plugin command could not be started.
    LaunchFailed { path: String, message: String },
    /// Plugin command exited unsuccessfully.
    ExecutionFailed {
        path: String,
        status: i32,
        stderr: String,
    },
    /// Plugin stdout could not be parsed as JSON.
    InvalidOutput { path: String, message: String },
}

impl std::fmt::Display for PluginError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PluginError::DynamicAbiUnsupported { path } => write!(
                f,
                "dynamic plugin ABI is unsupported in v2; remove [plugins].paths entry: {path}"
            ),
            PluginError::LaunchFailed { path, message } => {
                write!(f, "plugin launch failed ({path}): {message}")
            }
            PluginError::ExecutionFailed {
                path,
                status,
                stderr,
            } => write!(
                f,
                "plugin execution failed ({path}) exit={status}: {}",
                stderr.trim()
            ),
            PluginError::InvalidOutput { path, message } => {
                write!(f, "plugin output invalid ({path}): {message}")
            }
        }
    }
}

#[derive(Debug, Serialize)]
struct PluginRequest {
    schema_version: &'static str,
    aikido_plugin_api_version: u32,
    project_root: String,
}

#[derive(Debug, Deserialize)]
struct PluginResponse {
    schema_version: String,
    plugin_name: Option<String>,
    #[serde(default)]
    findings: Vec<WireFinding>,
}

#[derive(Debug, Deserialize)]
struct WireFinding {
    detector: String,
    severity: String,
    title: String,
    description: String,
    module: String,
    #[serde(default)]
    confidence: Option<String>,
    #[serde(default)]
    suggestion: Option<String>,
    #[serde(default)]
    location: Option<WireLocation>,
}

#[derive(Debug, Deserialize)]
struct WireLocation {
    path: String,
    byte_start: usize,
    byte_end: usize,
}

/// Load and execute all configured plugins.
///
/// In protocol v2, plugins are external commands.
pub fn load_plugins(
    config: &PluginConfig,
    project_root: &Path,
) -> Result<PluginBundle, Vec<PluginError>> {
    let mut errors = Vec::new();

    if !config.paths.is_empty() {
        for path in &config.paths {
            errors.push(PluginError::DynamicAbiUnsupported { path: path.clone() });
        }
    }

    let mut findings = Vec::new();
    let mut loaded_plugins = Vec::new();

    for command in &config.commands {
        match run_plugin_command(command, project_root) {
            Ok((plugin_name, mut plugin_findings)) => {
                let count = plugin_findings.len();
                findings.append(&mut plugin_findings);
                loaded_plugins.push(LoadedPlugin {
                    name: plugin_name,
                    path: command.clone(),
                    detector_count: count,
                });
            }
            Err(err) => errors.push(err),
        }
    }

    if errors.is_empty() {
        Ok(PluginBundle {
            findings,
            loaded_plugins,
        })
    } else {
        Err(errors)
    }
}

fn run_plugin_command(
    command: &str,
    project_root: &Path,
) -> Result<(String, Vec<Finding>), PluginError> {
    let request = PluginRequest {
        schema_version: PLUGIN_SCHEMA_V1,
        aikido_plugin_api_version: AIKIDO_PLUGIN_API_VERSION,
        project_root: project_root.to_string_lossy().into_owned(),
    };

    let req_json = serde_json::to_string(&request).map_err(|e| PluginError::InvalidOutput {
        path: command.to_string(),
        message: format!("failed to encode request: {e}"),
    })?;

    let output = Command::new("sh")
        .arg("-lc")
        .arg(command)
        .env("AIKIDO_PLUGIN_REQUEST", &req_json)
        .current_dir(project_root)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| PluginError::LaunchFailed {
            path: command.to_string(),
            message: e.to_string(),
        })?
        .wait_with_output()
        .map_err(|e| PluginError::LaunchFailed {
            path: command.to_string(),
            message: e.to_string(),
        })?;

    if !output.status.success() {
        return Err(PluginError::ExecutionFailed {
            path: command.to_string(),
            status: output.status.code().unwrap_or(-1),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        });
    }

    let response: PluginResponse =
        serde_json::from_slice(&output.stdout).map_err(|e| PluginError::InvalidOutput {
            path: command.to_string(),
            message: format!("stdout is not valid plugin JSON: {e}"),
        })?;

    if response.schema_version != PLUGIN_SCHEMA_V1 {
        return Err(PluginError::InvalidOutput {
            path: command.to_string(),
            message: format!(
                "unsupported schema_version '{}' expected '{}'",
                response.schema_version, PLUGIN_SCHEMA_V1
            ),
        });
    }

    let findings = response
        .findings
        .into_iter()
        .map(wire_finding_to_core)
        .collect();

    let name = response.plugin_name.unwrap_or_else(|| command.to_string());

    Ok((name, findings))
}

fn wire_finding_to_core(w: WireFinding) -> Finding {
    let severity = parse_severity(&w.severity).unwrap_or(Severity::Medium);
    let confidence = parse_confidence(w.confidence.as_deref());

    Finding {
        detector_name: w.detector,
        severity,
        confidence,
        title: w.title,
        description: w.description,
        module: w.module,
        location: w
            .location
            .map(|loc| SourceLocation::from_bytes(&loc.path, loc.byte_start, loc.byte_end)),
        suggestion: w.suggestion,
        related_findings: vec![],
        semantic_group: None,
        evidence: None,
    }
}

fn parse_confidence(raw: Option<&str>) -> Confidence {
    match raw.map(|v| v.to_ascii_lowercase()) {
        Some(v) if v == "definite" => Confidence::Definite,
        Some(v) if v == "likely" => Confidence::Likely,
        _ => Confidence::Possible,
    }
}

/// Resolve plugin command strings.
pub fn resolve_plugin_paths(config: &PluginConfig, _project_root: &Path) -> Vec<String> {
    config.commands.clone()
}

/// Get the platform-specific legacy plugin file extension.
pub fn plugin_extension() -> &'static str {
    if cfg!(target_os = "macos") {
        "dylib"
    } else if cfg!(target_os = "windows") {
        "dll"
    } else {
        "so"
    }
}

/// Discover plugin commands and validate they are non-empty.
pub fn discover_plugins(config: &PluginConfig) -> Vec<Result<String, PluginError>> {
    config
        .commands
        .iter()
        .map(|cmd| {
            if cmd.trim().is_empty() {
                Err(PluginError::InvalidOutput {
                    path: "<empty-command>".to_string(),
                    message: "empty command in [plugins].commands".to_string(),
                })
            } else {
                Ok(cmd.clone())
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn test_discover_plugins_empty() {
        let config = PluginConfig::default();
        let results = discover_plugins(&config);
        assert!(results.is_empty());
    }

    #[test]
    fn test_discover_plugins_non_empty_command() {
        let config = PluginConfig {
            commands: vec!["echo test".to_string()],
            ..Default::default()
        };
        let results = discover_plugins(&config);
        assert_eq!(results.len(), 1);
        assert!(results[0].is_ok());
    }

    #[test]
    fn test_discover_plugins_empty_command_reports_error() {
        let config = PluginConfig {
            commands: vec!["   ".to_string()],
            ..Default::default()
        };
        let results = discover_plugins(&config);
        assert_eq!(results.len(), 1);
        assert!(results[0].is_err());
    }

    #[test]
    fn test_load_plugins_rejects_legacy_dynamic_paths() {
        let config = PluginConfig {
            paths: vec!["./legacy_plugin.so".to_string()],
            ..Default::default()
        };

        let err =
            load_plugins(&config, Path::new(".")).expect_err("dynamic paths should be rejected");
        assert_eq!(err.len(), 1);
        assert!(matches!(err[0], PluginError::DynamicAbiUnsupported { .. }));
    }

    #[test]
    fn test_load_plugins_runs_json_command() {
        let config = PluginConfig {
            commands: vec![
                "printf '%s' '{\"schema_version\":\"aikido-plugin-v1\",\"plugin_name\":\"demo\",\"findings\":[{\"detector\":\"external-detector\",\"severity\":\"high\",\"confidence\":\"likely\",\"title\":\"External finding\",\"description\":\"From plugin\",\"module\":\"validators/test.ak\",\"location\":{\"path\":\"validators/test.ak\",\"byte_start\":1,\"byte_end\":5}}]}'".to_string(),
            ],
            ..Default::default()
        };

        let bundle = load_plugins(&config, Path::new("."))
            .expect("plugin command should return valid findings");
        assert_eq!(bundle.plugin_count(), 1);
        assert_eq!(bundle.findings.len(), 1);
        assert_eq!(bundle.findings[0].detector_name, "external-detector");
        assert_eq!(bundle.findings[0].confidence, Confidence::Likely);
    }

    #[test]
    fn test_load_plugins_invalid_json_output() {
        let config = PluginConfig {
            commands: vec!["printf '%s' 'not-json'".to_string()],
            ..Default::default()
        };

        let errors = load_plugins(&config, Path::new(".")).expect_err("invalid output must error");
        assert_eq!(errors.len(), 1);
        assert!(matches!(errors[0], PluginError::InvalidOutput { .. }));
    }

    #[test]
    fn test_plugin_extension() {
        let ext = plugin_extension();
        assert!(matches!(ext, "so" | "dylib" | "dll"));
    }
}
