use serde::Serialize;

use crate::ast_walker::ModuleInfo;
use crate::evidence::Evidence;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Info => write!(f, "Info"),
            Severity::Low => write!(f, "Low"),
            Severity::Medium => write!(f, "Medium"),
            Severity::High => write!(f, "High"),
            Severity::Critical => write!(f, "Critical"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum Confidence {
    /// The finding is almost certainly a real issue.
    Definite,
    /// The finding is likely a real issue based on heuristic patterns.
    Likely,
    /// The finding is possible but may be a false positive.
    Possible,
}

impl std::fmt::Display for Confidence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Confidence::Definite => write!(f, "definite"),
            Confidence::Likely => write!(f, "likely"),
            Confidence::Possible => write!(f, "possible"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, serde::Deserialize)]
pub enum DetectorReliabilityTier {
    Stable,
    Beta,
    Experimental,
}

impl std::fmt::Display for DetectorReliabilityTier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DetectorReliabilityTier::Stable => write!(f, "stable"),
            DetectorReliabilityTier::Beta => write!(f, "beta"),
            DetectorReliabilityTier::Experimental => write!(f, "experimental"),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct SourceLocation {
    pub module_path: String,
    pub byte_start: usize,
    pub byte_end: usize,
    pub line_start: Option<usize>,
    pub column_start: Option<usize>,
    pub line_end: Option<usize>,
    pub column_end: Option<usize>,
}

impl SourceLocation {
    /// Create a SourceLocation from byte offsets (line/column resolved later).
    pub fn from_bytes(module_path: &str, byte_start: usize, byte_end: usize) -> Self {
        Self {
            module_path: module_path.to_string(),
            byte_start,
            byte_end,
            line_start: None,
            column_start: None,
            line_end: None,
            column_end: None,
        }
    }

    /// Resolve line/column from source code.
    pub fn resolve(&mut self, source: &str) {
        let (line_start, col_start) = byte_offset_to_line_col(source, self.byte_start);
        let (line_end, col_end) = byte_offset_to_line_col(source, self.byte_end);
        self.line_start = Some(line_start);
        self.column_start = Some(col_start);
        self.line_end = Some(line_end);
        self.column_end = Some(col_end);
    }

    /// Extract a code snippet around the finding location.
    /// Returns lines with line numbers, marking the finding lines with '>'.
    pub fn snippet(&self, source: &str, context_lines: usize) -> Option<String> {
        let finding_start = self.line_start?;
        let finding_end = self.line_end.unwrap_or(finding_start);
        let lines: Vec<&str> = source.lines().collect();
        if lines.is_empty() || finding_start == 0 {
            return None;
        }
        let start_idx = finding_start.saturating_sub(1 + context_lines);
        let end_idx = (finding_end + context_lines).min(lines.len());

        let mut result = Vec::new();
        for (i, line) in lines.iter().enumerate().take(end_idx).skip(start_idx) {
            let line_num = i + 1;
            let is_finding = line_num >= finding_start && line_num <= finding_end;
            let marker = if is_finding { ">" } else { " " };
            result.push(format!("{marker} {line_num:4} | {line}"));
        }
        Some(result.join("\n"))
    }

    /// Make the module_path relative to a project root.
    pub fn make_relative(&mut self, project_root: &str) {
        if let Some(rel) = self.module_path.strip_prefix(project_root) {
            self.module_path = rel.trim_start_matches('/').to_string();
        }
    }
}

/// Convert a byte offset to 1-based (line, column).
fn byte_offset_to_line_col(source: &str, offset: usize) -> (usize, usize) {
    let offset = offset.min(source.len());
    let mut line = 1;
    let mut col = 1;
    for (i, ch) in source.char_indices() {
        if i >= offset {
            break;
        }
        if ch == '\n' {
            line += 1;
            col = 1;
        } else {
            col += 1;
        }
    }
    (line, col)
}

#[derive(Debug, Clone)]
pub struct Finding {
    pub detector_name: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub title: String,
    pub description: String,
    pub module: String,
    pub location: Option<SourceLocation>,
    pub suggestion: Option<String>,
    /// Detector names whose findings were absorbed by this one during consolidation.
    pub related_findings: Vec<String>,
    /// Semantic group for cross-detector consolidation (e.g., "datum-integrity").
    pub semantic_group: Option<String>,
    /// Evidence supporting this finding (proof of exploitability).
    pub evidence: Option<Evidence>,
}

pub trait Detector: Send + Sync {
    fn name(&self) -> &str;
    fn description(&self) -> &str;
    fn severity(&self) -> Severity;
    fn detect(&self, modules: &[ModuleInfo]) -> Vec<Finding>;

    /// Detailed explanation of the vulnerability pattern, including examples and remediation.
    fn long_description(&self) -> &str {
        self.description()
    }

    /// CWE (Common Weakness Enumeration) identifier for this detector, if applicable.
    /// Format: "CWE-NNN"
    fn cwe_id(&self) -> Option<&str> {
        None
    }

    /// Category grouping for this detector.
    /// One of: authorization, data-validation, logic, math, resource, configuration
    fn category(&self) -> &str {
        "general"
    }

    /// URL to the documentation page for this detector.
    fn doc_url(&self) -> String {
        format!(
            "https://github.com/Bajuzjefe/aikido/blob/main/docs/detectors/{}.md",
            self.name()
        )
    }
}

/// Numeric ordering for severity levels (Critical=5, Info=1).
/// Used for sorting findings by severity.
pub fn severity_order(s: &Severity) -> u8 {
    match s {
        Severity::Critical => 5,
        Severity::High => 4,
        Severity::Medium => 3,
        Severity::Low => 2,
        Severity::Info => 1,
    }
}

/// Parse a severity string into a `Severity` enum value.
pub fn parse_severity(s: &str) -> Option<Severity> {
    match s.to_lowercase().as_str() {
        "info" => Some(Severity::Info),
        "low" => Some(Severity::Low),
        "medium" => Some(Severity::Medium),
        "high" => Some(Severity::High),
        "critical" => Some(Severity::Critical),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_byte_offset_to_line_col() {
        let src = "line1\nline2\nline3";
        assert_eq!(byte_offset_to_line_col(src, 0), (1, 1));
        assert_eq!(byte_offset_to_line_col(src, 5), (1, 6)); // newline char
        assert_eq!(byte_offset_to_line_col(src, 6), (2, 1)); // start of line2
        assert_eq!(byte_offset_to_line_col(src, 12), (3, 1));
    }

    #[test]
    fn test_source_location_resolve() {
        let src = "fn foo() {\n  True\n}";
        let mut loc = SourceLocation::from_bytes("test.ak", 0, 19);
        loc.resolve(src);
        assert_eq!(loc.line_start, Some(1));
        assert_eq!(loc.column_start, Some(1));
        assert_eq!(loc.line_end, Some(3));
    }

    #[test]
    fn test_snippet_extraction() {
        let src = "line1\nline2\nline3\nline4\nline5\nline6\nline7";
        let mut loc = SourceLocation::from_bytes("test.ak", 12, 17); // line3
        loc.resolve(src);
        let snippet = loc.snippet(src, 1).unwrap();
        assert!(snippet.contains("> "));
        assert!(snippet.contains("line3"));
        assert!(snippet.contains("line2")); // context before
        assert!(snippet.contains("line4")); // context after
    }

    #[test]
    fn test_make_relative() {
        let mut loc = SourceLocation::from_bytes("/home/user/project/validators/test.ak", 0, 10);
        loc.make_relative("/home/user/project");
        assert_eq!(loc.module_path, "validators/test.ak");
    }

    #[test]
    fn test_confidence_display() {
        assert_eq!(Confidence::Definite.to_string(), "definite");
        assert_eq!(Confidence::Likely.to_string(), "likely");
        assert_eq!(Confidence::Possible.to_string(), "possible");
    }
}
