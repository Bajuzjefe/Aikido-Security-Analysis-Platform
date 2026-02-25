# Quick Start

Three steps from zero to your first security scan.

## Step 1: Install

Pick the method that suits you (see [Installation](installation.md) for full details):

```bash
# Homebrew (recommended for macOS/Linux)
brew install Bajuzjefe/tap/aikido

# Or Cargo (Rust >= 1.88.0)
cargo install --git https://github.com/Bajuzjefe/aikido aikido-cli

# Or npx (no install needed)
npx aikido-aiken /path/to/project
```

## Step 2: Run

Point Aikido at any Aiken project directory -- the one containing your `aiken.toml`:

```bash
aikido /path/to/your-aiken-project
```

Aikido will:
1. Load and compile your Aiken project
2. Run all 58 security detectors against the typed AST
3. Print findings to the terminal with source context

No configuration files are needed. No flags are required. Aikido auto-detects your project structure from `aiken.toml`.

## Step 3: Read the results

Aikido prints a structured report. Here is what a typical run looks like:

```
Analyzing: /home/dev/my-dex
Project: my-dex v0.1.0
[1/3] Compiling...
✔ 4 modules analyzed
[2/3] Running 58 detectors...
⚠ 3 issues found: 1 critical, 1 high, 1 medium

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  FINDINGS (3 issues found)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  [CRITICAL] (definite) double-satisfaction - Handler swap.spend iterates
    outputs without own OutputReference - validators/swap.ak:15

    Spend handler accesses tx.outputs but never uses __own_ref to
    identify its own input. An attacker can satisfy multiple script
    inputs with a single output, draining funds.

       13 | validator swap {
    >  14 |   spend(datum: Option<SwapDatum>, redeemer: SwapAction,
    >  15 |         _own_ref, self) {
    >  16 |     list.any(self.outputs, fn(o) { o.value >= datum.amount })

    Suggestion: Use the OutputReference parameter to correlate outputs
    to this specific input.

  [HIGH] (likely) value-not-preserved - Handler pool.spend does not
    verify output value - validators/pool.ak:42
    ...

  [MEDIUM] (possible) unbounded-list-iteration - Direct iteration over
    self.inputs - lib/helpers.ak:8
    ...

  1 critical, 1 high, 1 medium, 0 low, 0 info
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

Each finding includes:
- **Severity** -- Critical, High, Medium, Low, or Info
- **Confidence** -- definite, likely, or possible
- **Detector name** -- The rule that triggered (e.g., `double-satisfaction`)
- **Location** -- File path and line number
- **Description** -- What the issue is and why it matters
- **Source snippet** -- The relevant code with the problem lines highlighted
- **Suggestion** -- How to fix it

## What to do next

**Fix critical and high findings first.** These represent real attack vectors that could lead to fund loss.

**Investigate medium findings.** Many are genuine issues, but some may be intentional design choices (Aikido reports them so you can make a conscious decision).

**Low and info findings** are code quality observations. Address them when convenient.

**Get more detail on a specific detector:**

```bash
aikido --explain double-satisfaction
```

**Export results for CI or reporting:**

```bash
# JSON for scripts
aikido /path/to/project --format json

# SARIF for GitHub Code Scanning
aikido /path/to/project --format sarif > results.sarif

# Markdown for pull request comments
aikido /path/to/project --format markdown
```

**Gate your CI pipeline on severity thresholds:**

```bash
# Exit with code 2 if any high or critical findings exist
aikido /path/to/project --fail-on high
```

## Next steps

- [Your First Scan](your-first-scan.md) -- A detailed walkthrough of every part of the output
- [.aikido.toml Reference](../configuration/aikido-toml.md) -- Customize which detectors run and how
- [Detectors Overview](../detectors/overview.md) -- Browse all 58 detectors with examples
