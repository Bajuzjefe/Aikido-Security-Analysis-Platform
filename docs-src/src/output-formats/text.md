# Terminal (Text)

The default output format. Produces colored, human-readable output designed for interactive terminal use during development.

```bash
# These are equivalent
aikido /path/to/project
aikido /path/to/project --format text
```

## What it includes

The text format outputs several sections:

1. **Project header** -- Project name, version, and module summary
2. **Module listing** -- Validators, data types, functions, and test counts per module
3. **UPLC metrics** -- Compiled code sizes and budget usage (with `--verbose`)
4. **Findings** -- Each finding with severity badge, detector name, description, source context, and suggestion

## Example output

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  AIKIDO v0.2.0  Static Analysis Report
  Project: my-dex v1.0.0
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

VALIDATOR MODULE: my_dex/pool
  Data Type: PoolDatum { token_a: AssetClass, token_b: AssetClass, lp_total: Int }
  Data Type: PoolRedeemer { Swap | AddLiquidity | RemoveLiquidity }
  Functions: 3 public, 2 private
  VALIDATOR: pool
    Handler: pool.spend(datum: PoolDatum, redeemer: PoolRedeemer)
    Handler: else (fallback)
    Compiled Size: 4821 bytes

SUMMARY
  Modules: 3 | Validators: 1 | Data Types: 4 | Functions: 12 | Constants: 2 | Tests: 8
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  FINDINGS (3 issues found)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  [CRITICAL] (definite) double-satisfaction — Validator vulnerable to double satisfaction — validators/pool.ak:42
    Multiple UTXOs at this script address can be spent in a single transaction
    without the validator distinguishing which UTXO is being authorized.

       40 | validator pool {
       41 |   spend(datum: PoolDatum, redeemer: PoolRedeemer, _self: OutputReference, tx: Transaction) {
    >> 42 |     when redeemer is {
       43 |       Swap -> handle_swap(datum, tx)
       44 |       AddLiquidity -> handle_add(datum, tx)

    Suggestion: Reference the validator's own input via the output reference parameter
    to ensure each UTXO is uniquely identified.

  [HIGH] (likely) value-not-preserved — Token value may not be preserved — validators/pool.ak:58
    The validator does not verify that the total value locked at the script
    address is maintained after the transaction.

    Suggestion: Compare input value with continuing output value to ensure
    no tokens are drained.

  [MEDIUM] (likely) missing-validity-range — No validity range check — validators/pool.ak:41
    The validator does not check transaction validity range, which may allow
    replay or time-dependent attacks.

    Suggestion: Use validity_range to enforce time constraints on the transaction.

  3 critical, 0 high, 1 medium, 0 low, 0 info

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

## Severity badges

Each finding is prefixed with a colored severity badge:

| Severity | Color | Badge |
|----------|-------|-------|
| Critical | Red, bold | `[CRITICAL]` |
| High | Red | `[HIGH]` |
| Medium | Yellow | `[MEDIUM]` |
| Low | Blue | `[LOW]` |
| Info | Gray | `[INFO]` |

The confidence level appears in parentheses after the badge: `(definite)`, `(likely)`, or `(possible)`.

## Source context

When source code is available, findings include a snippet with surrounding lines. The offending line is marked with `>>` and line numbers are shown on the left margin.

## Progress messages

Progress messages are written to stderr, not stdout. This means piping the output to a file captures only the report:

```bash
# Progress messages visible in terminal, report saved to file
aikido . > report.txt
```

Use `--quiet` to suppress progress messages entirely:

```bash
aikido . --quiet
```

## Verbose mode

The `--verbose` flag adds function signatures, constants, type aliases, and UPLC budget metrics to the report:

```bash
aikido . --verbose
```
