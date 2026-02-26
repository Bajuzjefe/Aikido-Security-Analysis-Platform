# CSV

Comma-separated values output for spreadsheet import, data analysis, and bulk processing.

```bash
aikido /path/to/project --format csv
aikido /path/to/project --format csv > findings.csv
```

## Format

The CSV output includes a header row followed by one row per finding:

```csv
detector,severity,confidence,title,description,module,file,line_start,line_end
double-satisfaction,critical,definite,Validator vulnerable to double satisfaction,Multiple UTXOs can be spent without unique identification,my_dex/pool,validators/pool.ak,42,55
missing-validity-range,medium,likely,No validity range check,The validator does not check transaction validity range,my_dex/pool,validators/pool.ak,41,41
unused-import,info,definite,Unused import detected,Import is not referenced in module,my_dex/helpers,lib/my_dex/helpers.ak,3,3
```

## Columns

| Column | Description | Example |
|--------|-------------|---------|
| `detector` | Detector rule ID | `double-satisfaction` |
| `severity` | Severity level (lowercase) | `critical`, `high`, `medium`, `low`, `info` |
| `confidence` | Confidence level (lowercase) | `definite`, `likely`, `possible` |
| `title` | Short title of the finding | `Validator vulnerable to double satisfaction` |
| `description` | Detailed description | `Multiple UTXOs can be spent...` |
| `module` | Aiken module path | `my_dex/pool` |
| `file` | Source file path | `validators/pool.ak` |
| `line_start` | Start line number (1-based) | `42` |
| `line_end` | End line number (1-based) | `55` |

## Escaping

Fields containing commas, double quotes, or newlines are wrapped in double quotes with internal quotes escaped by doubling (`""` for a literal `"`). This follows standard CSV escaping rules (RFC 4180).

## Empty fields

- Findings without a source location have empty `file`, `line_start`, and `line_end` fields.
- All findings have `detector`, `severity`, `confidence`, `title`, `description`, and `module` populated.

## Examples

### Open in a spreadsheet

```bash
aikido . --format csv > findings.csv
open findings.csv         # Opens in default spreadsheet app
```

### Filter with command-line tools

```bash
# Count findings per severity
aikido . --format csv | tail -n +2 | cut -d, -f2 | sort | uniq -c

# Extract only critical findings
aikido . --format csv | head -1 && aikido . --format csv | grep ',critical,'

# Get unique affected files
aikido . --format csv | tail -n +2 | cut -d, -f7 | sort -u
```

### Import into Python

```python
import csv
import sys

with open("findings.csv") as f:
    reader = csv.DictReader(f)
    critical = [r for r in reader if r["severity"] == "critical"]
    print(f"Critical findings: {len(critical)}")
```

## Notes

- The header row is always present, even when there are no findings.
- Severity and confidence values are always lowercase.
- Line numbers are 1-based. An empty line number means the finding has no associated source location.
