# Introduction

Aikido is a static security analyzer for [Aiken](https://aiken-lang.org/) smart contracts on Cardano. It finds vulnerabilities in your validators before they reach mainnet -- where contracts are immutable and bugs mean lost funds with no recourse.

Point Aikido at any Aiken project and it compiles your code, walks the typed AST, runs 58 security detectors with cross-module interprocedural analysis, and reports findings with source locations, severity ratings, confidence scores, CWE classifications, and actionable remediation guidance. The whole process takes seconds, not weeks.

## Why Aikido exists

Cardano smart contracts (validators) are deployed on-chain as compiled Plutus scripts. Once a script is referenced in a live UTXO, there is no upgrade mechanism -- the code is final. A missed authorization check, an unvalidated output address, or a double satisfaction vulnerability can drain every UTXO held at that script address. Manual security audits catch these issues, but they are expensive, slow, and hard to schedule during active development.

Aikido automates the detection of vulnerability classes that appear repeatedly in published audit reports from firms like MLabs, Vacuumlabs, and Anastasia Labs. It is not a replacement for manual audits, but it catches the most common and most dangerous patterns instantly, on every commit, as part of your normal development workflow.

## Key features

**58 security detectors** -- Covering critical vulnerabilities (double satisfaction, unrestricted minting, missing UTXO authentication), high-severity logic errors (value not preserved, division by zero, integer underflow), medium-severity resource issues (unbounded iteration, datum size limits, UTXO contention), and code quality checks (dead code, shadowed variables, magic numbers). Every detector is mapped to a CWE identifier and includes a detailed explanation with vulnerable and safe code examples.

**Cross-module interprocedural analysis** -- Aikido does not just pattern-match within a single file. It resolves qualified function calls across module boundaries, traces data flow from untrusted redeemer fields through helper functions, and correlates signals across all handlers within a multi-purpose validator. This dramatically reduces false positives compared to a simple AST grep.

**9 output formats** -- Colored terminal output for development, JSON for scripting, SARIF for GitHub Code Scanning, Markdown and HTML for reports, PDF for formal audit deliverables, CSV for spreadsheets, GitLab SAST for GitLab pipelines, and reviewdog (rdjson) for pull request annotations.

**Zero configuration required** -- Run `aikido /path/to/project` and get results immediately. No setup files, no database, no network calls (beyond the initial Aiken stdlib download). When you need customization, an `.aikido.toml` config file supports disabling detectors, overriding severity levels, per-file rules, config inheritance, and strict/lenient presets.

**CI/CD integration** -- First-class support for GitHub Actions (SARIF upload to Code Scanning), GitLab CI (SAST format), Docker containers, and diff-only mode that reports findings only in changed files. The `--fail-on` flag lets you gate merges on severity thresholds.

**Confidence scoring** -- Every finding is rated as `definite`, `likely`, or `possible`, so you can prioritize your review and filter out lower-confidence results when needed.

**Ecosystem validated** -- Tested against 10 real-world Aiken projects including SundaeSwap, Anastasia Labs, Strike Finance, and Seedelf. 176 findings across those projects with zero crashes and an 81% true positive rate.

## Who is Aikido for

- **Aiken developers** who want fast feedback on security issues during development
- **Security auditors** who need an automated first pass before manual review
- **Protocol teams** preparing for mainnet deployment and wanting to minimize audit scope
- **CI/CD pipelines** that need to gate deployments on security thresholds

## What Aikido is not

Aikido is a static analyzer, not a formal verifier. It does not prove correctness -- it finds common vulnerability patterns through AST analysis, taint tracking, and symbolic execution. Some findings may be false positives (the tool reports confidence levels to help you triage), and some vulnerabilities may require domain-specific knowledge that no automated tool can provide. Use Aikido alongside manual review and testing, not as a sole gatekeeper.

## Next steps

- [Installation](getting-started/installation.md) -- Get Aikido running in under a minute
- [Quick Start](getting-started/quick-start.md) -- Three steps from zero to your first scan
- [Your First Scan](getting-started/your-first-scan.md) -- Understand every part of the output
