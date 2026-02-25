# JSON

Machine-readable JSON output suitable for scripting, custom tooling, and integration with dashboards.

```bash
aikido /path/to/project --format json
aikido /path/to/project --format json > results.json
```

## Structure

The JSON output is a single object with the following shape:

```json
{
  "project": "my-dex",
  "version": "1.0.0",
  "findings": [
    {
      "detector": "double-satisfaction",
      "severity": "critical",
      "title": "Validator vulnerable to double satisfaction",
      "description": "Multiple UTXOs at this script address can be spent in a single transaction without the validator distinguishing which UTXO is being authorized.",
      "module": "my_dex/pool",
      "location": {
        "path": "validators/pool.ak",
        "byte_start": 1024,
        "byte_end": 1280,
        "line_start": 42,
        "column_start": 5,
        "line_end": 55,
        "column_end": 6
      },
      "suggestion": "Reference the validator's own input via the output reference parameter to ensure each UTXO is uniquely identified."
    },
    {
      "detector": "missing-validity-range",
      "severity": "medium",
      "title": "No validity range check",
      "description": "The validator does not check transaction validity range.",
      "module": "my_dex/pool",
      "location": {
        "path": "validators/pool.ak",
        "byte_start": 800,
        "byte_end": 900,
        "line_start": 41,
        "column_start": 3,
        "line_end": 41,
        "column_end": 50
      },
      "suggestion": "Use validity_range to enforce time constraints."
    }
  ],
  "total": 2
}
```

## Fields

### Top-level

| Field | Type | Description |
|-------|------|-------------|
| `project` | string | Project name from `aiken.toml` |
| `version` | string | Project version from `aiken.toml` |
| `findings` | array | Array of finding objects |
| `total` | integer | Total number of findings |

### Finding object

| Field | Type | Description |
|-------|------|-------------|
| `detector` | string | Detector rule ID (e.g., `"double-satisfaction"`) |
| `severity` | string | One of: `"critical"`, `"high"`, `"medium"`, `"low"`, `"info"` |
| `title` | string | Short human-readable title |
| `description` | string | Detailed explanation of the issue |
| `module` | string | Aiken module path (e.g., `"my_dex/pool"`) |
| `location` | object or null | Source location, or `null` if not available |
| `suggestion` | string or null | Remediation guidance, or `null` |

### Location object

| Field | Type | Description |
|-------|------|-------------|
| `path` | string | File path relative to project root |
| `byte_start` | integer | Start byte offset in the source file |
| `byte_end` | integer | End byte offset in the source file |
| `line_start` | integer | Start line number (1-based) |
| `column_start` | integer | Start column number (1-based) |
| `line_end` | integer | End line number (1-based) |
| `column_end` | integer | End column number (1-based) |

## Examples

### Count findings by severity with jq

```bash
aikido . --format json | jq '.findings | group_by(.severity) | map({severity: .[0].severity, count: length})'
```

### Extract only critical and high findings

```bash
aikido . --format json | jq '.findings | map(select(.severity == "critical" or .severity == "high"))'
```

### List affected files

```bash
aikido . --format json | jq '[.findings[].location.path] | unique'
```

### Check if any critical findings exist (for CI)

```bash
CRITICAL=$(aikido . --format json --quiet | jq '.findings | map(select(.severity == "critical")) | length')
if [ "$CRITICAL" -gt 0 ]; then
  echo "Found $CRITICAL critical findings"
  exit 1
fi
```

## Notes

- The output is pretty-printed by default (indented with 2 spaces).
- Findings with no source location have `"location": null`.
- Findings with no remediation have `"suggestion": null`.
- Severity values are always lowercase strings.
- The `total` field always equals the length of the `findings` array.
