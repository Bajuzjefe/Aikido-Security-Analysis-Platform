# aikido-aiken

Security analysis platform for [Aiken](https://aiken-lang.org/) smart contracts on Cardano.

75 detectors, SMT verification, transaction simulation, compliance analysis, protocol pattern detection, and grammar-aware fuzzing. Built in Rust.

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/Bajuzjefe/Aikido-Security-Analysis-Platform/blob/main/LICENSE)
[![npm version](https://img.shields.io/npm/v/aikido-aiken.svg)](https://www.npmjs.com/package/aikido-aiken)

## Install

```bash
npm install -g aikido-aiken
```

Or run directly with npx:

```bash
npx aikido-aiken /path/to/your-aiken-project
```

## Usage

```bash
# Scan an Aiken project
aikido-aiken /path/to/project

# JSON output
aikido-aiken /path/to/project --format json

# SARIF output (for GitHub Code Scanning)
aikido-aiken /path/to/project --format sarif

# Filter by severity
aikido-aiken /path/to/project --min-severity medium

# Fail CI on high+ findings
aikido-aiken /path/to/project --fail-on high
```

## Example Output

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  AIKIDO v0.3.1  Static Analysis Report
  Project: my-project v0.1.0
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  [CRITICAL] double-satisfaction
    validators/treasury.ak:23
    Spend handler accesses tx.outputs without own OutputReference.
    An attacker can satisfy multiple script inputs with a single output.

  [HIGH] missing-signature-check
    validators/treasury.ak:45
    No signer verification found in handler.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Summary: 2 findings (1 critical, 1 high)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

## How It Works

This package is a thin wrapper that downloads the pre-built Aikido binary for your platform during `npm install`. Supported platforms:

| OS | x64 | ARM64 |
|----|-----|-------|
| macOS | Yes | Yes |
| Linux | Yes | Yes |
| Windows | Yes | - |

If no pre-built binary is available, install from source:

```bash
cargo install --git https://github.com/Bajuzjefe/Aikido-Security-Analysis-Platform aikido-cli
```

## Other Installation Methods

```bash
# Homebrew (macOS/Linux)
brew install Bajuzjefe/tap/aikido

# Docker
docker run --rm -v $(pwd):/project ghcr.io/bajuzjefe/aikido:0.3.1 /project

# GitHub Action
- uses: Bajuzjefe/Aikido-Security-Analysis-Platform@v0.3.1
```

## Output Formats

`text` `json` `sarif` `markdown` `html` `pdf` `csv` `gitlab-sast` `rdjson`

## Links

- [GitHub](https://github.com/Bajuzjefe/Aikido-Security-Analysis-Platform)
- [75 Detectors](https://github.com/Bajuzjefe/Aikido-Security-Analysis-Platform#detectors)
- [Configuration](https://github.com/Bajuzjefe/Aikido-Security-Analysis-Platform#configuration)
- [CI/CD Integration](https://github.com/Bajuzjefe/Aikido-Security-Analysis-Platform#github-actions)

## License

MIT
