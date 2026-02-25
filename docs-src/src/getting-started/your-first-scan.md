# Your First Scan

This walkthrough takes you through a complete Aikido scan, explaining every part of the output so you know exactly what you are looking at and how to act on it.

## Running the scan

Start by pointing Aikido at an Aiken project directory (the directory that contains `aiken.toml`):

```bash
aikido /path/to/my-treasury
```

## Phase 1: Compilation

Aikido first loads and compiles your Aiken project. You will see progress output on stderr:

```
Analyzing: /home/dev/my-treasury
Project: my-treasury v0.1.0
[1/3] Compiling...
✔ 3 modules analyzed
```

Aikido uses the Aiken compiler internally. It reads your `aiken.toml`, resolves dependencies, and compiles all modules into a typed AST (Abstract Syntax Tree). If your project does not compile under Aiken, Aikido will report the compilation error and exit.

The first time you compile a project, Aiken downloads the standard library. This requires network access. Subsequent runs use the cached stdlib.

## Phase 2: Detection

Next, Aikido runs all 58 security detectors against the compiled modules:

```
[2/3] Running 58 detectors...
```

Each detector walks the typed AST looking for specific vulnerability patterns. Detectors operate at multiple levels:

- **Single-handler analysis** -- checks within a single validator handler (e.g., is the redeemer validated?)
- **Cross-handler analysis** -- correlates signals across all handlers within a validator (e.g., does any handler coordinate with others?)
- **Cross-module analysis** -- follows function calls into library modules to check if a security property is satisfied in a helper function
- **Taint tracking** -- traces data flow from untrusted sources (redeemer fields, datum fields) to sensitive operations (arithmetic, output construction)

## Phase 3: Results

### The report header

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  AIKIDO v0.3.0  Static Analysis Report
  Project: my-treasury v0.1.0
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

The header shows the Aikido version and your project name and version (from `aiken.toml`). This is followed by a structural summary of your project: modules, validators, data types, and function counts.

### Module summary

```
VALIDATOR MODULE: treasury
  Data Type: TreasuryDatum { owner: VerificationKeyHash, amount: Int }
  Data Type: TreasuryRedeemer { Withdraw | Deposit }
  VALIDATOR: treasury
    Handler: spend(datum: Option<TreasuryDatum>, redeemer: TreasuryRedeemer)
    Handler: else (fallback)
  Functions: 1 public, 2 private

MODULE: utils
  Functions: 3 public
```

This section shows what Aikido found in your project. Validator modules contain `validator` blocks. Library modules contain shared functions. Data types are shown with their fields or variants. This helps you verify that Aikido is seeing the same project structure you expect.

### Individual findings

Each finding is a self-contained report:

```
  [CRITICAL] (definite) double-satisfaction — Handler treasury.spend iterates
    outputs without own OutputReference — validators/treasury.ak:23

    Spend handler accesses tx.outputs but never uses __own_ref to identify
    its own input. An attacker can satisfy multiple script inputs with a
    single output, draining funds.

       21 |
       22 | validator treasury {
    >  23 |   spend(
    >  24 |     datum: Option<TreasuryDatum>,
    >  25 |     redeemer: TreasuryRedeemer,
       26 |     _own_ref,
       27 |     self,

    Suggestion: Use the OutputReference parameter to correlate outputs
    to this specific input.
```

Let's break down each component:

#### Severity level

The tag in square brackets indicates how dangerous the finding is:

| Severity | Meaning | Action |
|----------|---------|--------|
| **CRITICAL** | Direct fund loss or complete bypass of authorization. Exploitable in most cases. | Fix before deployment. Do not proceed to mainnet with unresolved critical findings. |
| **HIGH** | Significant security weakness. May be exploitable depending on contract logic and transaction context. | Fix before deployment. Acceptable only if you have a documented reason why it does not apply. |
| **MEDIUM** | Potential issue that could lead to denial of service, unexpected behavior, or edge-case exploits. | Review and address. Some medium findings may be acceptable design trade-offs. |
| **LOW** | Code quality issue or minor concern that is unlikely to be directly exploitable. | Address when convenient. These improve code maintainability and auditability. |
| **INFO** | Informational observation. Style, naming, or structural suggestion. | Optional. Useful for clean codebases but not security-critical. |

#### Confidence rating

The parenthesized word after the severity indicates how certain Aikido is that this is a real issue:

| Confidence | Meaning |
|------------|---------|
| **definite** | The pattern is unambiguous. The vulnerability exists unless there is external mitigation not visible in the Aiken code. Very low false positive rate. |
| **likely** | The heuristic strongly suggests a real issue, but there are scenarios where the code might be correct (e.g., the check happens in an external module Aikido cannot see). |
| **possible** | The pattern matches, but the context is ambiguous. Review the finding manually to determine whether it applies to your specific case. |

#### Detector name

The short identifier (e.g., `double-satisfaction`) names the specific rule that triggered. You can use this to:

- Get a detailed explanation: `aikido --explain double-satisfaction`
- Suppress the finding if it is a false positive: add `// aikido:ignore[double-satisfaction]` above the line
- Disable the detector project-wide in `.aikido.toml`

#### Location

The file path and line number where the issue was detected:

```
validators/treasury.ak:23
```

Paths are relative to your project root. Line numbers point to the start of the problematic code span.

#### Description

A plain-language explanation of what the issue is and why it matters. Descriptions are written to be understandable without deep Cardano knowledge, but they reference Cardano-specific concepts (UTXOs, redeemers, validators) where relevant.

#### Source snippet

A code snippet showing the relevant lines with the finding lines marked with `>`:

```
       22 | validator treasury {
    >  23 |   spend(
    >  24 |     datum: Option<TreasuryDatum>,
    >  25 |     redeemer: TreasuryRedeemer,
```

Two lines of context are shown above and below the finding. Line numbers match your source file.

#### Suggestion

A concrete recommendation for how to fix the issue:

```
Suggestion: Use the OutputReference parameter to correlate outputs
to this specific input.
```

Suggestions are specific to the detector and the code pattern found. They point you toward the fix without being prescriptive about implementation details.

### Finding summary

At the bottom of the report, a one-line summary counts findings by severity:

```
  1 critical, 2 high, 3 medium, 0 low, 1 info
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

## Exit codes

Aikido uses exit codes to communicate results to scripts and CI pipelines:

| Code | Meaning |
|------|---------|
| `0` | Analysis completed. No findings at or above the `--fail-on` threshold (default: high). |
| `1` | Error -- could not compile the project, invalid arguments, or other failure. |
| `2` | Analysis completed but findings at or above the `--fail-on` threshold were found. |

The default threshold is `high`, meaning Aikido exits with code 2 if any high or critical findings exist. Change this with `--fail-on`:

```bash
# Fail on any finding (including info)
aikido /path/to/project --fail-on info

# Only fail on critical
aikido /path/to/project --fail-on critical
```

## Filtering output

### By severity

Show only medium-and-above findings:

```bash
aikido /path/to/project --min-severity medium
```

### By changed files (diff mode)

Report findings only in files changed since a git ref:

```bash
aikido /path/to/project --diff main
```

This is useful in pull request checks where you only want to see new issues, not pre-existing ones.

### With a baseline

Accept all current findings as a baseline, then only report new ones going forward:

```bash
# First run: save current state
aikido /path/to/project --accept-baseline

# Later runs: only new findings are reported
aikido /path/to/project
```

The baseline is stored in `.aikido-baseline.json` in your project root.

## Handling false positives

If a finding is a false positive -- the code is correct but the pattern matches -- you have several options:

**Inline suppression** -- Add a comment above the flagged line:

```aiken
// aikido:ignore[double-satisfaction] -- own_ref checked in separate helper
spend(datum, redeemer, own_ref, self) {
```

**Config-level suppression** -- Disable a detector for specific files in `.aikido.toml`:

```toml
[[files]]
pattern = "validators/treasury.ak"
disable = ["double-satisfaction"]
```

**Auto-insert suppressions** -- Let Aikido add the comments for you:

```bash
aikido /path/to/project --fix
```

## Trying other output formats

The default colored terminal output is designed for development. For CI, reporting, or tooling integration, use `--format`:

```bash
aikido /path/to/project --format json          # Machine-readable JSON
aikido /path/to/project --format sarif         # GitHub Code Scanning
aikido /path/to/project --format markdown      # Markdown report
aikido /path/to/project --format html          # Standalone HTML page
aikido /path/to/project --format pdf           # PDF audit report
aikido /path/to/project --format csv           # Spreadsheet export
aikido /path/to/project --format gitlab-sast   # GitLab SAST
aikido /path/to/project --format rdjson        # reviewdog annotations
```

## Next steps

- [.aikido.toml Reference](../configuration/aikido-toml.md) -- Fine-tune detector behavior per project
- [Detectors Overview](../detectors/overview.md) -- Browse all 58 detectors with vulnerable and safe examples
- [GitHub Actions](../ci-cd/github-actions.md) -- Set up automated security scanning in your CI pipeline
