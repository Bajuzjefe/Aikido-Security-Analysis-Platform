# SARIF

[SARIF](https://sarifweb.azurewebsites.net/) (Static Analysis Results Interchange Format) v2.1.0 output for GitHub Code Scanning, VS Code SARIF Viewer, and other SARIF-compatible tools.

```bash
aikido /path/to/project --format sarif
aikido /path/to/project --format sarif > results.sarif
```

## Why SARIF

SARIF is the standard interchange format for static analysis results. When uploaded to GitHub Code Scanning, findings appear as inline annotations in pull requests and in the repository's Security tab. This gives your team one-click access to every Aikido finding with file, line, severity, and remediation guidance -- without leaving GitHub.

## GitHub Actions integration

The fastest way to use SARIF with GitHub is through Aikido's official GitHub Action, which handles SARIF generation and upload automatically:

```yaml
name: Security
on: [push, pull_request]

jobs:
  aikido:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
    steps:
      - uses: actions/checkout@v4
      - uses: Bajuzjefe/aikido@v1
        with:
          project-path: "."
          fail-on: high
          upload-sarif: "true"
```

### Manual SARIF upload

If you prefer to generate and upload SARIF yourself:

```yaml
name: Security
on: [push, pull_request]

jobs:
  aikido:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
    steps:
      - uses: actions/checkout@v4

      - name: Install Aikido
        run: cargo install --git https://github.com/Bajuzjefe/aikido aikido-cli

      - name: Run analysis
        run: aikido . --format sarif > results.sarif
        continue-on-error: true

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
          category: aikido
```

**Important:** The `security-events: write` permission is required for SARIF upload. The `continue-on-error: true` on the analysis step ensures the SARIF file is uploaded even when Aikido exits with code 2 (findings above threshold).

## SARIF structure

Aikido generates a compliant SARIF v2.1.0 log with the following structure:

```json
{
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "aikido",
          "version": "0.1.0",
          "informationUri": "https://github.com/Bajuzjefe/aikido",
          "rules": [
            {
              "id": "double-satisfaction",
              "shortDescription": {
                "text": "Detects validators vulnerable to double satisfaction attacks"
              },
              "helpUri": "https://github.com/Bajuzjefe/aikido/blob/main/docs/detectors/double-satisfaction.md",
              "defaultConfiguration": {
                "level": "error"
              },
              "properties": {
                "security-severity": "9.5",
                "tags": ["security", "authorization", "external/cwe/cwe-362"]
              }
            }
          ]
        }
      },
      "results": [
        {
          "ruleId": "double-satisfaction",
          "level": "error",
          "message": {
            "text": "Validator vulnerable to double satisfaction\nMultiple UTXOs can be spent without unique identification."
          },
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": {
                  "uri": "validators/pool.ak"
                },
                "region": {
                  "startLine": 42,
                  "startColumn": 5,
                  "endLine": 55,
                  "endColumn": 6,
                  "snippet": {
                    "text": "when redeemer is {"
                  }
                }
              }
            }
          ],
          "partialFingerprints": {
            "primaryLocationLineHash": "a1b2c3d4e5f67890"
          },
          "properties": {
            "security-severity": "7.5"
          }
        }
      ]
    }
  ]
}
```

## SARIF features

### Rule definitions

All 58 detectors are registered as SARIF rules in the `tool.driver.rules` array, even when no findings are produced. Each rule includes:

- **id** -- Detector name (e.g., `"double-satisfaction"`)
- **shortDescription** -- One-line detector description
- **helpUri** -- Link to detailed detector documentation
- **defaultConfiguration.level** -- SARIF level: `"error"` (Critical/High), `"warning"` (Medium), `"note"` (Low/Info)
- **properties.security-severity** -- Numeric score (0.0--10.0) used by GitHub to categorize findings in the Security tab
- **properties.tags** -- Includes `"security"`, the detector category, and CWE references (e.g., `"external/cwe/cwe-362"`)

### Severity mapping

| Aikido severity | SARIF level | Security severity score |
|-----------------|-------------|:-----------------------:|
| Critical | `error` | 9.5 |
| High | `error` | 7.5 |
| Medium | `warning` | 5.0 |
| Low | `note` | 3.0 |
| Info | `note` | 1.0 |

### Source snippets

When source code is available, SARIF results include embedded code snippets in the `region.snippet.text` field. This allows SARIF viewers to display the relevant code without needing access to the source files.

### Partial fingerprints

Each result includes a `partialFingerprints.primaryLocationLineHash` computed from the detector name, file path, and source line content. This enables stable deduplication across runs -- GitHub Code Scanning uses this to track whether a finding is new, existing, or fixed.

### Relative paths

File paths in SARIF output are relative to the project root. Aikido automatically strips the absolute project path prefix when generating the `artifactLocation.uri` field.

## VS Code integration

Install the [SARIF Viewer](https://marketplace.visualstudio.com/items?itemName=MS-SarifVSCode.sarif-viewer) extension, then open the `.sarif` file in VS Code. Findings are shown as inline annotations in the editor.
