# PDF

PDF audit report for formal security deliverables. Generates a multi-page PDF document structured as a professional audit report, suitable for client delivery, compliance documentation, and archival.

```bash
aikido /path/to/project --format pdf > audit-report.pdf
```

**Important:** The PDF format writes binary data to stdout. Always redirect to a file.

## Report structure

The generated PDF follows a formal audit report structure:

### 1. Title section

- Report title: "AIKIDO SECURITY AUDIT REPORT"
- Project name and version
- Generation date (automatically computed)
- Tool version

### 2. Executive summary

A high-level overview including:

- Number of modules analyzed (validators and libraries)
- Finding counts broken down by severity (Critical, High, Medium, Low, Info)
- Total finding count

### 3. Methodology

Description of the analysis techniques used:

- Typed AST pattern matching for known vulnerability classes
- Handler body signal extraction (field accesses, function calls, taint tracking)
- Cross-module dependency analysis
- UPLC compiled code metrics

### 4. Findings

Each finding is listed with:

- Sequential number and severity level
- Detector name
- Module name
- File location and line number (relative paths)
- Description
- Recommendation (when available)

### 5. Recommendations

Contextual recommendations based on the severity distribution:

- Critical/High findings: "Should be addressed before deployment"
- Medium findings: "Should be evaluated in the context of the project's threat model"
- No findings: "No automated findings detected. Manual review is recommended for production contracts."

### 6. Footer

Tool attribution and project URL.

## Example usage

### Generate and open

```bash
aikido . --format pdf > audit.pdf
open audit.pdf            # macOS
xdg-open audit.pdf        # Linux
```

### CI artifact

```yaml
- name: Generate PDF audit report
  run: aikido . --format pdf --quiet > audit-report.pdf 2>/dev/null || true

- name: Upload audit report
  uses: actions/upload-artifact@v4
  with:
    name: audit-report
    path: audit-report.pdf
```

### Combine with severity filter

Generate a report showing only Medium and above:

```bash
aikido . --format pdf --min-severity medium > audit-report.pdf
```

## Technical details

- **Format:** PDF 1.4
- **Font:** Courier (monospace, built-in Type 1 font -- no font embedding needed)
- **Font size:** 9pt
- **Page size:** US Letter (612 x 792 points)
- **Margins:** 72pt left, 50pt right, 52pt top/bottom
- **Line wrapping:** Automatic word wrapping at 90 characters per line with continuation indent
- **Multi-page:** Automatic page breaks with consistent header layout
- **Dependencies:** None -- the PDF is generated from raw PDF structure without external libraries

The PDF is text-only (no images, charts, or tables). For a richer visual report, consider using `--format html` and printing to PDF from a browser.
