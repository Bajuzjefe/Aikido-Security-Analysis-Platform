# Output Formats

Aikido supports 9 output formats, selected with the `--format` flag. The default is `text`, which produces colored terminal output suitable for interactive development. All other formats write to stdout and can be redirected to a file.

```bash
# Default: colored terminal output
aikido /path/to/project

# Explicit format selection
aikido /path/to/project --format json

# Redirect to file
aikido /path/to/project --format sarif > results.sarif
aikido /path/to/project --format html > report.html
aikido /path/to/project --format pdf > audit.pdf
```

## Format reference

| Format | Flag | Primary use case | Machine-readable |
|--------|------|------------------|:----------------:|
| [Terminal (Text)](text.md) | `--format text` | Interactive development, local review | No |
| [JSON](json.md) | `--format json` | Scripting, custom tooling, dashboards | Yes |
| [SARIF](sarif.md) | `--format sarif` | GitHub Code Scanning, VS Code SARIF Viewer | Yes |
| [Markdown](markdown.md) | `--format markdown` | PR comments, wikis, documentation | No |
| [HTML](html.md) | `--format html` | Standalone reports for sharing via browser | No |
| [PDF](pdf.md) | `--format pdf` | Formal audit deliverables, client reports | No |
| [CSV](csv.md) | `--format csv` | Spreadsheets, data analysis, bulk processing | Yes |
| [GitLab SAST](gitlab-sast.md) | `--format gitlab-sast` | GitLab Security Dashboard | Yes |
| [reviewdog (rdjson)](reviewdog.md) | `--format rdjson` | PR annotations via reviewdog | Yes |

## Combining with other flags

Output format can be combined with any other Aikido flag. Common combinations:

```bash
# Filter by severity before outputting
aikido . --format json --min-severity medium

# Only findings in changed files
aikido . --format sarif --diff main

# Quiet mode suppresses progress messages on stderr
aikido . --format json --quiet

# Fail CI if findings exceed threshold (exit code 2)
aikido . --format sarif --fail-on high
```

## Choosing a format

**During development** -- Use the default `text` format. It provides colored severity badges, source code context with line numbers, and actionable suggestions directly in your terminal.

**In GitHub Actions** -- Use `sarif` with the `github/codeql-action/upload-sarif@v3` action to surface findings in the GitHub Security tab with inline code annotations. Aikido's official GitHub Action does this automatically.

**In GitLab CI** -- Use `gitlab-sast` and declare the output as a SAST artifact. Findings appear in the GitLab Security Dashboard.

**For PR review** -- Use `markdown` to post findings as PR comments, or `rdjson` with reviewdog for inline annotations.

**For sharing with non-developers** -- Use `html` for a self-contained report that opens in any browser, or `pdf` for formal audit deliverables.

**For data processing** -- Use `json` for scripting and custom tooling, or `csv` for spreadsheet import.

## Exit codes

The `--format` flag does not affect exit codes. Aikido always returns:

| Exit code | Meaning |
|-----------|---------|
| `0` | No findings above the `--fail-on` threshold |
| `1` | Error (compilation failure, invalid config, etc.) |
| `2` | Findings at or above the `--fail-on` threshold |

The default `--fail-on` threshold is `high`, meaning any High or Critical finding triggers exit code 2.
