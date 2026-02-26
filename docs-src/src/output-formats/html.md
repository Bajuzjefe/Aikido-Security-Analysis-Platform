# HTML

Standalone HTML report with embedded CSS. Opens in any browser with no external dependencies. Good for sharing findings with stakeholders who do not use the terminal or GitHub.

```bash
aikido /path/to/project --format html > report.html
```

## Features

- **Self-contained** -- All styles are embedded inline. The HTML file has no external CSS, JavaScript, or image dependencies. Share it as a single file attachment.
- **Responsive layout** -- The report adapts to desktop and mobile viewports using CSS media queries.
- **Visual severity cards** -- Findings are rendered as cards with color-coded severity badges (red for Critical, orange for High, yellow for Medium, blue for Low, gray for Info).
- **Summary dashboard** -- A row of stat cards at the top shows total findings and counts per severity level, each colored to match its severity.
- **Code snippets** -- Source code is rendered in a dark-themed `<pre>` block with monospace font when available.
- **HTML-safe** -- All user-facing content (titles, descriptions, code) is escaped to prevent XSS. Special characters (`<`, `>`, `&`, `"`) are converted to HTML entities.

## Example usage

### Generate and open

```bash
aikido . --format html > report.html
open report.html          # macOS
xdg-open report.html      # Linux
```

### Email or Slack

The generated HTML file is typically 5--20 KB depending on the number of findings. It can be attached to emails, uploaded to Slack, or hosted on any static file server.

### CI artifact

Save the HTML report as a CI artifact for download after each pipeline run:

```yaml
# GitHub Actions
- name: Generate HTML report
  run: aikido . --format html --quiet > aikido-report.html 2>/dev/null || true

- name: Upload report
  uses: actions/upload-artifact@v4
  with:
    name: aikido-report
    path: aikido-report.html
```

## Report structure

The HTML report contains:

1. **Header** -- "Aikido Security Report" with project name and version
2. **Summary cards** -- One card per severity level plus a "Total" card, each displaying a large count number colored by severity
3. **Finding cards** -- One card per finding, sorted by severity (Critical first), containing:
   - Severity badge (colored pill)
   - Finding title
   - Detector name as inline code
   - Description text
   - File path and line number (monospace)
   - Source code snippet in a dark `<pre>` block (when available)
   - Suggestion in a green-bordered callout box (when available)

When no findings are detected, the report displays a "No issues found." message.

## Styling

The embedded CSS uses a system font stack (`-apple-system, BlinkMacSystemFont, Segoe UI, Roboto`) with a light gray background. Severity colors follow a consistent palette:

| Severity | Color | Hex |
|----------|-------|-----|
| Critical | Red | `#dc2626` |
| High | Orange | `#ea580c` |
| Medium | Yellow | `#ca8a04` |
| Low | Blue | `#2563eb` |
| Info | Gray | `#6b7280` |

The report renders well when printed to paper or saved as PDF from the browser's print dialog.
