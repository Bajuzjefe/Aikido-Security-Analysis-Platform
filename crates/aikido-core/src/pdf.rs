//! Feature #77: PDF audit report — generate a professional audit-style PDF.
//!
//! Generates a minimal valid PDF file containing:
//! - Executive summary
//! - Methodology description
//! - Findings sorted by severity
//! - Recommendations
//!
//! Uses raw PDF structure (no external deps) for a text-only PDF.
//! Supports multi-page output with automatic word wrapping.

use crate::ast_walker::ModuleInfo;
use crate::detector::{Finding, Severity};

/// Max characters per line for Courier 9pt with 72pt margins on letter page.
/// Page width 612pt - 72pt left - 50pt right = 490pt usable. Courier 9pt ≈ 5.4pt/char.
const MAX_LINE_CHARS: usize = 90;

/// Top of text area (y coordinate).
const PAGE_TOP: i32 = 740;
/// Bottom margin — start new page below this.
const PAGE_BOTTOM: i32 = 60;
/// Line height in points.
const LINE_HEIGHT: i32 = 11;

/// Generate a PDF audit report as raw bytes.
pub fn findings_to_pdf(
    findings: &[Finding],
    project_name: &str,
    project_version: &str,
    modules: &[ModuleInfo],
) -> Vec<u8> {
    let content = build_audit_text(findings, project_name, project_version, modules);
    text_to_pdf(&content)
}

/// Build the audit report text content.
fn build_audit_text(
    findings: &[Finding],
    project_name: &str,
    project_version: &str,
    modules: &[ModuleInfo],
) -> String {
    let mut out = String::new();

    // Title
    out.push_str("AIKIDO SECURITY AUDIT REPORT\n");
    out.push_str("============================\n\n");
    out.push_str(&format!("Project: {project_name} v{project_version}\n"));
    out.push_str(&format!("Date: {}\n", chrono_date()));
    out.push_str("Tool: aikido v0.3.0\n\n");

    // Executive Summary
    out.push_str("1. EXECUTIVE SUMMARY\n");
    out.push_str("--------------------\n\n");

    let (critical, high, medium, low, info) = count_by_severity(findings);
    let validator_count = modules
        .iter()
        .filter(|m| m.kind == crate::ast_walker::ModuleKind::Validator)
        .count();
    let lib_count = modules.len() - validator_count;

    out.push_str(&format!(
        "This automated security audit analyzed {total} modules ({vc} validators, \
         {lc} libraries) of the {project_name} project.\n\n",
        total = modules.len(),
        vc = validator_count,
        lc = lib_count,
    ));
    out.push_str("Findings summary:\n");
    out.push_str(&format!("  Critical: {critical}\n"));
    out.push_str(&format!("  High:     {high}\n"));
    out.push_str(&format!("  Medium:   {medium}\n"));
    out.push_str(&format!("  Low:      {low}\n"));
    out.push_str(&format!("  Info:     {info}\n"));
    out.push_str(&format!("  Total:    {}\n\n", findings.len()));

    // Methodology
    out.push_str("2. METHODOLOGY\n");
    out.push_str("--------------\n\n");
    out.push_str("Analysis performed using aikido, a static analysis tool for Aiken\n");
    out.push_str("smart contracts. The tool examines:\n");
    out.push_str("  - Typed AST patterns for known vulnerability classes\n");
    out.push_str("  - Handler body signals (field accesses, function calls, taint)\n");
    out.push_str("  - Cross-module dependency analysis\n");
    out.push_str("  - UPLC compiled code metrics\n\n");
    out.push_str("Each finding includes severity, confidence, and remediation guidance.\n\n");

    // Findings
    out.push_str("3. FINDINGS\n");
    out.push_str("-----------\n\n");

    if findings.is_empty() {
        out.push_str("No issues were detected.\n\n");
    } else {
        for (i, f) in findings.iter().enumerate() {
            out.push_str(&format!(
                "Finding #{}: [{}] {}\n",
                i + 1,
                f.severity,
                f.title
            ));
            out.push_str(&format!("  Detector: {}\n", f.detector_name));
            out.push_str(&format!("  Module: {}\n", f.module));
            if let Some(ref loc) = f.location {
                if let Some(line) = loc.line_start {
                    // Use relative path: strip everything up to "validators/" or "lib/"
                    let path = make_relative_path(&loc.module_path);
                    out.push_str(&format!("  Location: {path}:{line}\n"));
                }
            }
            out.push_str(&format!("  Description: {}\n", f.description));
            if let Some(ref suggestion) = f.suggestion {
                out.push_str(&format!("  Recommendation: {suggestion}\n"));
            }
            if !f.related_findings.is_empty() {
                out.push_str(&format!(
                    "  (Also covers: {})\n",
                    f.related_findings.join(", ")
                ));
            }
            out.push('\n');
        }
    }

    // Recommendations
    out.push_str("4. RECOMMENDATIONS\n");
    out.push_str("------------------\n\n");

    if critical > 0 || high > 0 {
        out.push_str("CRITICAL/HIGH severity findings should be addressed before\n");
        out.push_str("deployment. Review each finding and apply the suggested fix.\n\n");
    }
    if medium > 0 {
        out.push_str("MEDIUM severity findings indicate potential issues that should\n");
        out.push_str("be evaluated in the context of the project's threat model.\n\n");
    }
    if findings.is_empty() {
        out.push_str("No automated findings were detected. This does not guarantee\n");
        out.push_str("the absence of vulnerabilities. Manual review is recommended\n");
        out.push_str("for production contracts.\n\n");
    }

    out.push_str("---\n");
    out.push_str("Generated by aikido\n");
    out.push_str("https://github.com/Bajuzjefe/aikido\n");

    out
}

/// Strip absolute path to show only from "validators/" or "lib/" onward.
fn make_relative_path(path: &str) -> &str {
    if let Some(idx) = path.find("validators/") {
        return &path[idx..];
    }
    if let Some(idx) = path.find("lib/") {
        return &path[idx..];
    }
    // Fallback: just the filename
    path.rsplit('/').next().unwrap_or(path)
}

fn count_by_severity(findings: &[Finding]) -> (usize, usize, usize, usize, usize) {
    let mut c = (0, 0, 0, 0, 0);
    for f in findings {
        match f.severity {
            Severity::Critical => c.0 += 1,
            Severity::High => c.1 += 1,
            Severity::Medium => c.2 += 1,
            Severity::Low => c.3 += 1,
            Severity::Info => c.4 += 1,
        }
    }
    c
}

fn chrono_date() -> String {
    let now = std::time::SystemTime::now();
    let since_epoch = now
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let mut days = (since_epoch.as_secs() / 86400) as i64;

    // Civil date from day count (algorithm from Howard Hinnant)
    days += 719468; // shift epoch from 1970-01-01 to 0000-03-01
    let era = days.div_euclid(146097);
    let doe = days.rem_euclid(146097); // day of era [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y}-{m:02}-{d:02}")
}

/// Word-wrap a single line to fit within MAX_LINE_CHARS.
fn wrap_line(line: &str) -> Vec<String> {
    if line.len() <= MAX_LINE_CHARS {
        return vec![line.to_string()];
    }

    // Detect leading whitespace for continuation indent
    let indent_len = line.len() - line.trim_start().len();
    let continuation_indent = if indent_len > 0 {
        " ".repeat(indent_len.min(8) + 2)
    } else {
        "  ".to_string()
    };

    let mut lines = Vec::new();
    let mut current = String::new();
    let mut is_first = true;

    for word in line.split(' ') {
        let test_len = if current.is_empty() {
            word.len()
        } else {
            current.len() + 1 + word.len()
        };

        if test_len > MAX_LINE_CHARS && !current.is_empty() {
            lines.push(current);
            current = if is_first {
                is_first = false;
                format!("{continuation_indent}{word}")
            } else {
                format!("{continuation_indent}{word}")
            };
        } else if current.is_empty() {
            current = word.to_string();
        } else {
            current.push(' ');
            current.push_str(word);
        }
    }
    if !current.is_empty() {
        lines.push(current);
    }

    if lines.is_empty() {
        vec![line.to_string()]
    } else {
        lines
    }
}

/// Convert plain text to a multi-page PDF with word wrapping.
fn text_to_pdf(text: &str) -> Vec<u8> {
    // Escape PDF special chars
    let escaped = text
        .replace('\\', "\\\\")
        .replace('(', "\\(")
        .replace(')', "\\)");

    // Word-wrap and split into pages
    let mut pages_lines: Vec<Vec<String>> = Vec::new();
    let mut current_page: Vec<String> = Vec::new();
    let mut y = PAGE_TOP;

    for raw_line in escaped.lines() {
        let wrapped = wrap_line(raw_line);
        for wl in wrapped {
            if y < PAGE_BOTTOM {
                // Start a new page
                pages_lines.push(std::mem::take(&mut current_page));
                y = PAGE_TOP;
            }
            current_page.push(wl);
            y -= LINE_HEIGHT;
        }
    }
    if !current_page.is_empty() {
        pages_lines.push(current_page);
    }
    if pages_lines.is_empty() {
        pages_lines.push(Vec::new());
    }

    let num_pages = pages_lines.len();

    // Build content streams for each page
    let mut content_streams: Vec<String> = Vec::new();
    for page_lines in &pages_lines {
        let mut ops = String::new();
        ops.push_str(&format!(
            "BT\n/F1 9 Tf\n72 {PAGE_TOP} Td\n{LINE_HEIGHT} TL\n"
        ));
        for line in page_lines {
            ops.push_str(&format!("({line}) Tj T*\n"));
        }
        ops.push_str("ET\n");
        content_streams.push(ops);
    }

    // Build PDF structure
    // Objects layout:
    //   1: Catalog
    //   2: Pages
    //   3: Font
    //   4..4+N-1: Page objects (one per page)
    //   4+N..4+2N-1: Content stream objects (one per page)

    let font_obj = 3;
    let first_page_obj = 4;
    let first_content_obj = first_page_obj + num_pages;

    let mut pdf = Vec::new();
    let mut offsets: Vec<usize> = Vec::new();

    // Header
    pdf.extend_from_slice(b"%PDF-1.4\n");

    // Object 1: Catalog
    offsets.push(pdf.len());
    pdf.extend_from_slice(b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n");

    // Object 2: Pages — list all page kids
    offsets.push(pdf.len());
    let kids: Vec<String> = (0..num_pages)
        .map(|i| format!("{} 0 R", first_page_obj + i))
        .collect();
    let kids_str = kids.join(" ");
    pdf.extend_from_slice(
        format!("2 0 obj\n<< /Type /Pages /Kids [{kids_str}] /Count {num_pages} >>\nendobj\n")
            .as_bytes(),
    );

    // Object 3: Font
    offsets.push(pdf.len());
    pdf.extend_from_slice(
        b"3 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>\nendobj\n",
    );

    // Page objects
    for i in 0..num_pages {
        offsets.push(pdf.len());
        let page_num = first_page_obj + i;
        let content_num = first_content_obj + i;
        pdf.extend_from_slice(
            format!(
                "{page_num} 0 obj\n\
                 << /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] \
                 /Contents {content_num} 0 R \
                 /Resources << /Font << /F1 {font_obj} 0 R >> >> >>\n\
                 endobj\n"
            )
            .as_bytes(),
        );
    }

    // Content stream objects
    for (i, stream) in content_streams.iter().enumerate() {
        offsets.push(pdf.len());
        let obj_num = first_content_obj + i;
        let len = stream.len();
        pdf.extend_from_slice(
            format!("{obj_num} 0 obj\n<< /Length {len} >>\nstream\n{stream}endstream\nendobj\n")
                .as_bytes(),
        );
    }

    // Xref table
    let xref_offset = pdf.len();
    let total_objects = offsets.len() + 1; // +1 for object 0
    pdf.extend_from_slice(b"xref\n");
    pdf.extend_from_slice(format!("0 {total_objects}\n").as_bytes());
    pdf.extend_from_slice(b"0000000000 65535 f \n");
    for offset in &offsets {
        pdf.extend_from_slice(format!("{offset:010} 00000 n \n").as_bytes());
    }

    // Trailer
    pdf.extend_from_slice(
        format!(
            "trailer\n<< /Size {total_objects} /Root 1 0 R >>\nstartxref\n{xref_offset}\n%%EOF\n"
        )
        .as_bytes(),
    );

    pdf
}

/// Get the audit report as plain text (for non-PDF use).
pub fn findings_to_audit_text(
    findings: &[Finding],
    project_name: &str,
    project_version: &str,
    modules: &[ModuleInfo],
) -> String {
    build_audit_text(findings, project_name, project_version, modules)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detector::{Confidence, SourceLocation};

    fn make_finding(name: &str, severity: Severity) -> Finding {
        Finding {
            detector_name: name.to_string(),
            severity,
            confidence: Confidence::Likely,
            title: format!("Test finding: {name}"),
            description: "Test description".to_string(),
            module: "test/validator".to_string(),
            location: Some(SourceLocation {
                module_path: "validator.ak".to_string(),
                byte_start: 0,
                byte_end: 10,
                line_start: Some(5),
                column_start: Some(1),
                line_end: Some(5),
                column_end: Some(10),
            }),
            suggestion: Some("Fix it".to_string()),
            related_findings: vec![],
            semantic_group: None,

            evidence: None,
        }
    }

    #[test]
    fn test_pdf_starts_with_header() {
        let pdf = findings_to_pdf(&[], "test", "1.0", &[]);
        assert!(pdf.starts_with(b"%PDF-1.4"));
    }

    #[test]
    fn test_pdf_ends_with_eof() {
        let pdf = findings_to_pdf(&[], "test", "1.0", &[]);
        let s = String::from_utf8_lossy(&pdf);
        assert!(s.ends_with("%%EOF\n"));
    }

    #[test]
    fn test_audit_text_contains_project_name() {
        let text = findings_to_audit_text(&[], "myproject", "2.0", &[]);
        assert!(text.contains("myproject v2.0"));
    }

    #[test]
    fn test_audit_text_contains_findings() {
        let findings = vec![
            make_finding("test-det", Severity::High),
            make_finding("other-det", Severity::Low),
        ];
        let text = findings_to_audit_text(&findings, "proj", "1.0", &[]);
        assert!(text.contains("Finding #1"));
        assert!(text.contains("Finding #2"));
        assert!(text.contains("[High]"));
        assert!(text.contains("[Low]"));
    }

    #[test]
    fn test_audit_text_no_findings() {
        let text = findings_to_audit_text(&[], "proj", "1.0", &[]);
        assert!(text.contains("No issues were detected"));
    }

    #[test]
    fn test_severity_counts() {
        let findings = vec![
            make_finding("a", Severity::Critical),
            make_finding("b", Severity::High),
            make_finding("c", Severity::High),
            make_finding("d", Severity::Medium),
        ];
        let (c, h, m, l, i) = count_by_severity(&findings);
        assert_eq!((c, h, m, l, i), (1, 2, 1, 0, 0));
    }

    #[test]
    fn test_wrap_line_short() {
        let lines = wrap_line("short line");
        assert_eq!(lines, vec!["short line"]);
    }

    #[test]
    fn test_wrap_line_long() {
        let long = "word ".repeat(25); // ~125 chars
        let lines = wrap_line(long.trim());
        assert!(lines.len() >= 2);
        for l in &lines {
            assert!(l.len() <= MAX_LINE_CHARS + 10); // some slack for last word
        }
    }

    #[test]
    fn test_make_relative_path_validators() {
        assert_eq!(
            make_relative_path("/foo/bar/fixtures/sentaku/validators/position.ak"),
            "validators/position.ak"
        );
    }

    #[test]
    fn test_make_relative_path_lib() {
        assert_eq!(
            make_relative_path("/foo/bar/lib/mymodule/types.ak"),
            "lib/mymodule/types.ak"
        );
    }

    #[test]
    fn test_make_relative_path_fallback() {
        assert_eq!(make_relative_path("just_a_file.ak"), "just_a_file.ak");
    }

    #[test]
    fn test_multipage_pdf() {
        // Create enough findings to force multiple pages
        let findings: Vec<Finding> = (0..20)
            .map(|i| make_finding(&format!("det-{i}"), Severity::Medium))
            .collect();
        let pdf = findings_to_pdf(&findings, "big-project", "1.0", &[]);
        let s = String::from_utf8_lossy(&pdf);
        assert!(s.starts_with("%PDF-1.4"));
        assert!(s.contains("/Count "));
        // Should have more than 1 page
        let count_pos = s.find("/Count ").unwrap();
        let count_char = s[count_pos + 7..count_pos + 8].to_string();
        let count: usize = count_char.parse().unwrap_or(1);
        assert!(count >= 2, "Expected multi-page PDF, got {count} pages");
    }
}
