# Detectors Overview

Aikido ships with **58 security detectors** organized into four severity levels. Every detector is derived from real vulnerabilities found in published Cardano smart contract audits.

## Severity Levels

| Level | Count | Description |
|-------|-------|-------------|
| **Critical** | 5 | Exploitable vulnerabilities that lead to direct fund loss |
| **High** | 19 | Serious vulnerabilities that can be exploited under specific conditions |
| **Medium** | 24 | Potential vulnerabilities or unsafe patterns that increase attack surface |
| **Low / Info** | 10 | Code quality issues, potential design concerns, best practice violations |

## How Detectors Work

Each detector:

1. **Walks the typed AST** — Aikido compiles your Aiken project and traverses the fully typed abstract syntax tree
2. **Extracts signals** — Identifies patterns like handler types, datum access, value operations, signature checks
3. **Performs cross-module analysis** — Follows function calls across module boundaries to reduce false positives
4. **Applies taint tracking** — Traces data flow from untrusted sources (redeemer, datum) to critical operations
5. **Scores confidence** — Rates each finding as `definite`, `likely`, or `possible`
6. **Maps to CWE** — Links findings to standardized Common Weakness Enumeration identifiers

## Confidence Levels

- **definite** — The vulnerability pattern is unambiguous and exploitable
- **likely** — The pattern strongly suggests a vulnerability, but context may provide mitigation
- **possible** — The pattern is suspicious and warrants manual review

## Listing Detectors

```bash
# Show all 58 detectors with severity and description
aikido --list-rules

# Get detailed explanation with examples for a specific detector
aikido --explain double-satisfaction
```

## Configuring Detectors

Detectors can be configured via `.aikido.toml`:

```toml
[detectors]
# Disable specific detectors
disable = ["magic-numbers", "unused-import"]

# Override severity levels
[detectors.severity_override]
unbounded-datum-size = "low"
```

Detectors can also be suppressed inline:

```rust
// aikido:ignore[double-satisfaction] -- false positive: own_ref checked in helper
```

See [Configuration](../configuration/aikido-toml.md) for full details.

## All 58 Detectors

### Critical (5)

| Detector | CWE | Description |
|----------|-----|-------------|
| [double-satisfaction](critical/double-satisfaction.md) | CWE-362 | Spend handler iterates outputs without referencing own input |
| [missing-minting-policy-check](critical/missing-minting-policy-check.md) | CWE-862 | Mint handler doesn't validate which token names are minted |
| [missing-utxo-authentication](critical/missing-utxo-authentication.md) | CWE-345 | Reference inputs used without authentication |
| [unrestricted-minting](critical/unrestricted-minting.md) | CWE-862 | Minting policy with no authorization check at all |
| [output-address-not-validated](critical/output-address-not-validated.md) | CWE-284 | Outputs sent to unchecked addresses |

### High (19)

| Detector | CWE | Description |
|----------|-----|-------------|
| [missing-redeemer-validation](high/missing-redeemer-validation.md) | CWE-20 | Catch-all redeemer pattern trivially returns True |
| [missing-signature-check](high/missing-signature-check.md) | CWE-862 | Authority datum fields with no extra_signatories check |
| [unsafe-datum-deconstruction](high/unsafe-datum-deconstruction.md) | CWE-252 | Option datum not safely deconstructed |
| [missing-datum-in-script-output](high/missing-datum-in-script-output.md) | CWE-404 | Script output without datum attachment |
| [arbitrary-datum-in-output](high/arbitrary-datum-in-output.md) | CWE-20 | Outputs produced without validating datum correctness |
| [division-by-zero-risk](high/division-by-zero-risk.md) | CWE-369 | Division with attacker-controlled denominator |
| [token-name-not-validated](high/token-name-not-validated.md) | CWE-20 | Mint policy checks auth but not token names |
| [value-not-preserved](high/value-not-preserved.md) | CWE-682 | Spend handler doesn't verify output value >= input value |
| [unsafe-match-comparison](high/unsafe-match-comparison.md) | CWE-697 | Value compared with match instead of structural equality |
| [integer-underflow-risk](high/integer-underflow-risk.md) | CWE-191 | Subtraction on redeemer-controlled values |
| [quantity-of-double-counting](high/quantity-of-double-counting.md) | CWE-682 | Token quantity checked without isolating input vs output |
| [state-transition-integrity](high/state-transition-integrity.md) | CWE-345 | Redeemer actions without datum transition validation |
| [withdraw-zero-trick](high/withdraw-zero-trick.md) | CWE-345 | Withdraw handler exploitable with zero-value withdrawal |
| [other-token-minting](high/other-token-minting.md) | CWE-20 | Mint policy allows minting beyond intended scope |
| [unsafe-redeemer-arithmetic](high/unsafe-redeemer-arithmetic.md) | CWE-682 | Arithmetic on redeemer-tainted values without bounds |
| [value-preservation-gap](high/value-preservation-gap.md) | CWE-682 | Lovelace checked but native assets not preserved |
| [uncoordinated-multi-validator](high/uncoordinated-multi-validator.md) | CWE-362 | Multi-handler validator without coordination |
| [missing-burn-verification](high/missing-burn-verification.md) | CWE-862 | Token burning without proper verification |
| [oracle-manipulation-risk](high/oracle-manipulation-risk.md) | CWE-345 | Oracle data used without manipulation safeguards |

### Medium (24)

| Detector | CWE | Description |
|----------|-----|-------------|
| [missing-validity-range](medium/missing-validity-range.md) | CWE-613 | Time-sensitive datum without validity_range check |
| [insufficient-staking-control](medium/insufficient-staking-control.md) | CWE-863 | Outputs don't constrain staking credential |
| [unbounded-list-iteration](medium/unbounded-list-iteration.md) | CWE-400 | Direct iteration over raw transaction list fields |
| [unbounded-datum-size](medium/unbounded-datum-size.md) | CWE-400 | Datum fields with unbounded types |
| [unbounded-value-size](medium/unbounded-value-size.md) | CWE-400 | Outputs don't constrain native asset count |
| [oracle-freshness-not-checked](medium/oracle-freshness-not-checked.md) | CWE-613 | Oracle data used without recency verification |
| [non-exhaustive-redeemer](medium/non-exhaustive-redeemer.md) | CWE-478 | Redeemer match doesn't cover all constructors |
| [unsafe-list-head](medium/unsafe-list-head.md) | CWE-129 | list.head() / list.at() without length guard |
| [hardcoded-addresses](medium/hardcoded-addresses.md) | CWE-798 | ByteArray literals matching Cardano address lengths |
| [unsafe-partial-pattern](medium/unsafe-partial-pattern.md) | CWE-252 | Expect pattern on non-Option type that may fail |
| [unconstrained-recursion](medium/unconstrained-recursion.md) | CWE-674 | Self-recursive handler without clear termination |
| [empty-handler-body](medium/empty-handler-body.md) | CWE-561 | Handler with no meaningful logic |
| [utxo-contention-risk](medium/utxo-contention-risk.md) | CWE-400 | Single global UTXO contention pattern |
| [cheap-spam-vulnerability](medium/cheap-spam-vulnerability.md) | CWE-770 | Validator vulnerable to cheap UTXO spam |
| [missing-datum-field-validation](medium/missing-datum-field-validation.md) | CWE-20 | Datum fields accepted but never validated |
| [missing-token-burn](medium/missing-token-burn.md) | CWE-754 | Minting policy with no burn handling |
| [missing-state-update](medium/missing-state-update.md) | CWE-669 | State machine without datum update |
| [rounding-error-risk](medium/rounding-error-risk.md) | CWE-682 | Integer division on financial values |
| [missing-input-credential-check](medium/missing-input-credential-check.md) | CWE-345 | Input iteration without credential check |
| [duplicate-asset-name-risk](medium/duplicate-asset-name-risk.md) | CWE-682 | Minting without unique asset name enforcement |
| [fee-calculation-unchecked](medium/fee-calculation-unchecked.md) | CWE-20 | Fee or protocol payment without validation |
| [datum-tampering-risk](medium/datum-tampering-risk.md) | CWE-20 | Datum passed through without field-level validation |
| [missing-protocol-token](medium/missing-protocol-token.md) | CWE-345 | State transition without protocol token verification |
| [unbounded-protocol-operations](medium/unbounded-protocol-operations.md) | CWE-400 | Both input and output lists iterated without bounds |

### Low / Info (10)

| Detector | Severity | Description |
|----------|----------|-------------|
| [reference-script-injection](low/reference-script-injection.md) | Low | Outputs don't constrain reference_script field |
| [unused-validator-parameter](low/unused-validator-parameter.md) | Low | Validator parameter never referenced |
| [fail-only-redeemer-branch](low/fail-only-redeemer-branch.md) | Low | Redeemer branch that always fails |
| [missing-min-ada-check](low/missing-min-ada-check.md) | Info | Script output without minimum ADA check |
| [dead-code-path](low/dead-code-path.md) | Low | Unreachable code paths |
| [redundant-check](low/redundant-check.md) | Low | Trivially true conditions |
| [shadowed-variable](low/shadowed-variable.md) | Info | Handler parameter shadowed by pattern binding |
| [magic-numbers](low/magic-numbers.md) | Info | Unexplained numeric literals |
| [excessive-validator-params](low/excessive-validator-params.md) | Info | Too many validator parameters |
| [unused-import](low/unused-import.md) | Info | Imported module with no function calls |
