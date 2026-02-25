use std::path::Path;

use colored::Colorize;

use crate::ast_walker::{DataTypeInfo, ModuleInfo, ModuleKind, ValidatorInfo};
use crate::detector::{Finding, Severity};

pub struct BlueprintValidator {
    pub title: String,
    pub compiled_size: usize,
}

pub fn read_blueprint(project_root: &Path) -> Vec<BlueprintValidator> {
    let blueprint_path = project_root.join("plutus.json");
    let Ok(content) = std::fs::read_to_string(&blueprint_path) else {
        return vec![];
    };

    let Ok(json) = serde_json::from_str::<serde_json::Value>(&content) else {
        return vec![];
    };

    let Some(validators) = json.get("validators").and_then(|v| v.as_array()) else {
        return vec![];
    };

    validators
        .iter()
        .filter_map(|v| {
            let title = v.get("title")?.as_str()?.to_string();
            let compiled_code = v.get("compiledCode").and_then(|c| c.as_str()).unwrap_or("");
            let compiled_size = compiled_code.len() / 2; // hex to bytes
            Some(BlueprintValidator {
                title,
                compiled_size,
            })
        })
        .collect()
}

fn format_separator() -> String {
    "\u{2501}".repeat(50)
}

fn format_data_type(dt: &DataTypeInfo) -> String {
    if dt.constructors.len() == 1 && !dt.constructors[0].fields.is_empty() {
        // Record-style: show fields
        let fields: Vec<String> = dt.constructors[0]
            .fields
            .iter()
            .map(|f| {
                if let Some(label) = &f.label {
                    format!("{label}: {}", f.type_name)
                } else {
                    f.type_name.clone()
                }
            })
            .collect();
        format!("{} {{ {} }}", dt.name, fields.join(", "))
    } else if dt.constructors.iter().all(|c| c.fields.is_empty()) {
        // Enum-style: show variants
        let variants: Vec<String> = dt.constructors.iter().map(|c| c.name.clone()).collect();
        format!("{} {{ {} }}", dt.name, variants.join(" | "))
    } else {
        // Mixed: show constructor names with field counts
        let variants: Vec<String> = dt
            .constructors
            .iter()
            .map(|c| {
                if c.fields.is_empty() {
                    c.name.clone()
                } else {
                    format!("{}({})", c.name, c.fields.len())
                }
            })
            .collect();
        format!("{} {{ {} }}", dt.name, variants.join(" | "))
    }
}

fn format_validator(v: &ValidatorInfo, blueprint_validators: &[BlueprintValidator]) -> String {
    let mut lines = Vec::new();

    if !v.params.is_empty() {
        let params: Vec<String> = v
            .params
            .iter()
            .map(|p| format!("{}: {}", p.name, p.type_name))
            .collect();
        lines.push(format!("    Parameters: {}", params.join(", ")));
    }

    for handler in &v.handlers {
        let params: Vec<String> = handler
            .params
            .iter()
            .map(|p| format!("{}: {}", p.name, p.type_name))
            .collect();
        lines.push(format!(
            "    Handler: {}({})",
            handler.name,
            params.join(", ")
        ));
    }

    // Aiken validators always have a fallback handler
    lines.push("    Handler: else (fallback)".to_string());

    // Match against blueprint for compiled size
    for bv in blueprint_validators {
        if bv.title.starts_with(&v.name) || bv.title.contains(&v.name) {
            lines.push(format!("    Compiled Size: {} bytes", bv.compiled_size));
            break;
        }
    }

    lines.join("\n")
}

pub fn format_report(
    modules: &[ModuleInfo],
    project_name: &str,
    project_version: &str,
    project_root: &Path,
    verbose: bool,
) -> String {
    let sep = format_separator();
    let blueprint_validators = read_blueprint(project_root);

    let mut output = Vec::new();

    output.push(sep.clone());
    output.push("  AIKIDO v0.3.0  Static Analysis Report".to_string());
    output.push(format!("  Project: {project_name} v{project_version}"));
    output.push(sep.clone());
    output.push(String::new());

    // Filter out stdlib modules and env/config modules
    let project_modules: Vec<&ModuleInfo> = modules
        .iter()
        .filter(|m| !m.name.starts_with("aiken/") && !m.name.starts_with("aiken_"))
        .collect();

    // Print modules
    for module in &project_modules {
        let kind_label = match module.kind {
            ModuleKind::Validator => "VALIDATOR MODULE",
            ModuleKind::Lib => "MODULE",
        };
        output.push(format!("{kind_label}: {}", module.name));

        if !module.data_types.is_empty() {
            let dt_strs: Vec<String> = module.data_types.iter().map(format_data_type).collect();
            for dt_str in &dt_strs {
                output.push(format!("  Data Type: {dt_str}"));
            }
        }

        if !module.functions.is_empty() && verbose {
            for f in &module.functions {
                let vis = if f.public { "pub " } else { "" };
                let params: Vec<String> = f
                    .params
                    .iter()
                    .map(|p| format!("{}: {}", p.name, p.type_name))
                    .collect();
                output.push(format!(
                    "  Function: {vis}{}({}) -> {}",
                    f.name,
                    params.join(", "),
                    f.return_type,
                ));
            }
        } else if !module.functions.is_empty() {
            let pub_count = module.functions.iter().filter(|f| f.public).count();
            let priv_count = module.functions.len() - pub_count;
            let mut parts = Vec::new();
            if pub_count > 0 {
                parts.push(format!("{pub_count} public"));
            }
            if priv_count > 0 {
                parts.push(format!("{priv_count} private"));
            }
            output.push(format!("  Functions: {}", parts.join(", ")));
        }

        if !module.constants.is_empty() && verbose {
            for c in &module.constants {
                let vis = if c.public { "pub " } else { "" };
                output.push(format!("  Constant: {vis}{}", c.name));
            }
        }

        if !module.type_aliases.is_empty() && verbose {
            for ta in &module.type_aliases {
                output.push(format!("  Type Alias: {}", ta.name));
            }
        }

        for v in &module.validators {
            output.push(format!("  VALIDATOR: {}", v.name));
            output.push(format_validator(v, &blueprint_validators));
        }

        if module.test_count > 0 {
            output.push(format!("  Tests: {}", module.test_count));
        }

        output.push(String::new());
    }

    // Summary
    let total_validators: usize = project_modules.iter().map(|m| m.validators.len()).sum();
    let total_data_types: usize = project_modules.iter().map(|m| m.data_types.len()).sum();
    let total_functions: usize = project_modules.iter().map(|m| m.functions.len()).sum();
    let total_tests: usize = project_modules.iter().map(|m| m.test_count).sum();
    let total_constants: usize = project_modules.iter().map(|m| m.constants.len()).sum();

    output.push("SUMMARY".to_string());
    output.push(format!(
        "  Modules: {} | Validators: {} | Data Types: {} | Functions: {} | Constants: {} | Tests: {}",
        project_modules.len(),
        total_validators,
        total_data_types,
        total_functions,
        total_constants,
        total_tests,
    ));
    output.push(sep);

    output.join("\n")
}

/// Format vulnerability findings into a report section.
/// If `modules` is provided, source code snippets will be included.
pub fn format_findings(findings: &[Finding], modules: &[ModuleInfo]) -> String {
    if findings.is_empty() {
        return String::new();
    }

    // Build source map for snippet extraction
    let source_map: std::collections::HashMap<&str, &str> = modules
        .iter()
        .filter_map(|m| m.source_code.as_deref().map(|src| (m.path.as_str(), src)))
        .collect();

    let sep = format_separator();
    let mut output = Vec::new();

    output.push(String::new());
    output.push(sep.clone());
    output.push(format!(
        "  FINDINGS ({} issue{} found)",
        findings.len(),
        if findings.len() == 1 { "" } else { "s" }
    ));
    output.push(sep.clone());
    output.push(String::new());

    for finding in findings {
        let severity_tag = match finding.severity {
            Severity::Critical => "CRITICAL".red().bold().to_string(),
            Severity::High => "HIGH".red().to_string(),
            Severity::Medium => "MEDIUM".yellow().to_string(),
            Severity::Low => "LOW".blue().to_string(),
            Severity::Info => "INFO".dimmed().to_string(),
        };

        let confidence_tag = format!(" ({})", finding.confidence);

        let loc_str = finding
            .location
            .as_ref()
            .and_then(|loc| {
                loc.line_start
                    .map(|line| format!(" \u{2014} {}:{}", loc.module_path, line))
            })
            .unwrap_or_default();

        output.push(format!(
            "  [{severity_tag}]{confidence_tag} {} \u{2014} {}{loc_str}",
            finding.detector_name, finding.title
        ));
        output.push(format!("    {}", finding.description));

        // Source code snippet
        if let Some(ref loc) = finding.location {
            if let Some(source) = source_map.get(loc.module_path.as_str()) {
                if let Some(snippet) = loc.snippet(source, 2) {
                    output.push(String::new());
                    for line in snippet.lines() {
                        output.push(format!("    {line}"));
                    }
                }
            }
        }

        if let Some(suggestion) = &finding.suggestion {
            output.push(String::new());
            output.push(format!("    Suggestion: {suggestion}"));
        }

        if !finding.related_findings.is_empty() {
            output.push(format!(
                "    (also covers: {})",
                finding.related_findings.join(", ")
            ));
        }

        output.push(String::new());
    }

    // Summary statistics
    output.push(format!("  {}", format_finding_summary(findings)));
    output.push(String::new());
    output.push(sep);

    output.join("\n")
}

/// Format a one-line summary of finding counts by severity.
pub fn format_finding_summary(findings: &[Finding]) -> String {
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
    let low = findings
        .iter()
        .filter(|f| f.severity == Severity::Low)
        .count();
    let info = findings
        .iter()
        .filter(|f| f.severity == Severity::Info)
        .count();
    let mut parts = Vec::new();
    if critical > 0 {
        parts.push(format!("{}", format!("{critical} critical").red().bold()));
    } else {
        parts.push(format!("{critical} critical"));
    }
    if high > 0 {
        parts.push(format!("{}", format!("{high} high").red()));
    } else {
        parts.push(format!("{high} high"));
    }
    if medium > 0 {
        parts.push(format!("{}", format!("{medium} medium").yellow()));
    } else {
        parts.push(format!("{medium} medium"));
    }
    if low > 0 {
        parts.push(format!("{}", format!("{low} low").blue()));
    } else {
        parts.push(format!("{low} low"));
    }
    if info > 0 {
        parts.push(format!("{}", format!("{info} info").dimmed()));
    } else {
        parts.push(format!("{info} info"));
    }
    parts.join(", ")
}
