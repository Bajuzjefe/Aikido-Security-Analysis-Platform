# GitHub Actions

Aikido integrates with GitHub Actions to run security analysis on every push and pull request, upload findings to GitHub Code Scanning, and gate merges on severity thresholds.

## Quick start workflow

Create `.github/workflows/aikido.yml` in your Aiken project:

```yaml
name: Aikido Security Analysis

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

permissions:
  security-events: write

jobs:
  aikido:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Install Rust
        uses: dtolnay/rust-toolchain@stable

      - name: Cache cargo
        uses: actions/cache@v4
        with:
          path: |
            ~/.cargo/registry
            ~/.cargo/git
          key: ${{ runner.os }}-aikido-${{ hashFiles('**/Cargo.lock') }}

      - name: Install Aikido
        run: cargo install aikido-cli

      - name: Run analysis (text)
        run: aikido . --fail-on high || true

      - name: Run analysis (SARIF)
        run: aikido . --format sarif > aikido-results.sarif || true

      - name: Upload to GitHub Code Scanning
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: aikido-results.sarif
          category: aikido

      - name: Gate on severity
        run: aikido . --fail-on high --quiet
```

This workflow does three things:

1. **Text output** -- prints human-readable findings in the Actions log so developers can see results directly. The `|| true` prevents the workflow from stopping before SARIF upload.
2. **SARIF upload** -- generates SARIF output and uploads it to GitHub Code Scanning. Findings appear in the Security tab and as annotations on pull request diffs.
3. **Gate on severity** -- runs a final check with `--fail-on high` to fail the workflow if any high or critical findings exist. The `--quiet` flag suppresses progress messages since the detailed output was already printed.

## CI gating with `--fail-on`

The `--fail-on` flag sets the minimum severity that causes a non-zero exit code:

```yaml
# Fail on critical only (lenient)
- run: aikido . --fail-on critical --quiet

# Fail on high or critical (recommended)
- run: aikido . --fail-on high --quiet

# Fail on medium and above (strict)
- run: aikido . --fail-on medium --quiet

# Fail on any finding
- run: aikido . --fail-on info --quiet
```

The exit codes are:

| Code | Meaning |
|------|---------|
| `0` | No findings at or above the threshold |
| `1` | Findings at or above the threshold |
| `2` | Compilation error (invalid Aiken project) |
| `3` | Configuration error (bad `.aikido.toml` or invalid flags) |

## Diff-only mode for pull requests

Use `--diff` to report only findings in files changed by the PR, reducing noise on large projects:

```yaml
- name: Run analysis (changed files only)
  if: github.event_name == 'pull_request'
  run: |
    aikido . --diff origin/${{ github.base_ref }} \
      --format sarif > aikido-results.sarif || true
```

This runs `git diff --name-only` against the base branch and filters findings to only those files.

## Using the reusable workflow

Aikido ships a reusable workflow at `.github/workflows/aikido.yml` in the Aikido repository. You can call it from any Aiken project without duplicating the workflow definition:

```yaml
name: Security

on:
  push:
    branches: [main]
  pull_request:

jobs:
  aikido:
    uses: Bajuzjefe/Aikido-Security-Analysis-Platform/.github/workflows/aikido.yml@main
    permissions:
      security-events: write
    with:
      project-path: "."
      fail-on: "high"
      min-severity: "info"
```

The reusable workflow accepts three inputs:

| Input | Default | Description |
|-------|---------|-------------|
| `project-path` | `"."` | Path to the Aiken project directory |
| `fail-on` | `"high"` | Minimum severity that triggers failure |
| `min-severity` | `"info"` | Minimum severity to include in output |

## Using the Docker image

If you prefer not to compile from source in CI, use the pre-built Docker image:

```yaml
- name: Run Aikido
  run: |
    docker run --rm \
      -v ${{ github.workspace }}:/project \
      ghcr.io/bajuzjefe/aikido:0.3.1 \
      /project --format sarif > aikido-results.sarif || true
```

This avoids the Rust toolchain installation and cargo cache steps entirely.

## Full example with baseline

For projects with existing findings you want to accept as a baseline, combine `--accept-baseline` (run once locally) with the CI workflow:

```yaml
- name: Run analysis
  run: |
    aikido . --format sarif > aikido-results.sarif || true

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: aikido-results.sarif
    category: aikido

- name: Gate (new findings only)
  run: aikido . --fail-on high --quiet
```

The baseline file (`.aikido-baseline.json`) is committed to the repository. On each CI run, Aikido automatically loads it and excludes baselined findings from both the output and the exit code check.
