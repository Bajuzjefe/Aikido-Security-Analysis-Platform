# Medium Severity Detectors

Medium severity detectors identify potential vulnerabilities and unsafe patterns that increase the attack surface. While not always directly exploitable, these patterns often indicate missing safety checks that could be combined with other weaknesses.

| Detector | CWE | Description |
|----------|-----|-------------|
| [missing-validity-range](missing-validity-range.md) | CWE-613 | Time-sensitive datum without validity_range check |
| [insufficient-staking-control](insufficient-staking-control.md) | CWE-863 | Outputs don't constrain staking credential |
| [unbounded-list-iteration](unbounded-list-iteration.md) | CWE-400 | Direct iteration over raw transaction list fields |
| [unbounded-datum-size](unbounded-datum-size.md) | CWE-400 | Datum fields with unbounded types |
| [unbounded-value-size](unbounded-value-size.md) | CWE-400 | Outputs don't constrain native asset count |
| [oracle-freshness-not-checked](oracle-freshness-not-checked.md) | CWE-613 | Oracle data used without recency verification |
| [non-exhaustive-redeemer](non-exhaustive-redeemer.md) | CWE-478 | Redeemer match doesn't cover all constructors |
| [unsafe-list-head](unsafe-list-head.md) | CWE-129 | list.head() / list.at() without length guard |
| [hardcoded-addresses](hardcoded-addresses.md) | CWE-798 | ByteArray literals matching Cardano address lengths |
| [unsafe-partial-pattern](unsafe-partial-pattern.md) | CWE-252 | Expect pattern on non-Option type that may fail |
| [unconstrained-recursion](unconstrained-recursion.md) | CWE-674 | Self-recursive handler without clear termination |
| [empty-handler-body](empty-handler-body.md) | CWE-561 | Handler with no meaningful logic |
| [utxo-contention-risk](utxo-contention-risk.md) | CWE-400 | Single global UTXO contention pattern |
| [cheap-spam-vulnerability](cheap-spam-vulnerability.md) | CWE-770 | Validator vulnerable to cheap UTXO spam |
| [missing-datum-field-validation](missing-datum-field-validation.md) | CWE-20 | Datum fields accepted but never validated |
| [missing-token-burn](missing-token-burn.md) | CWE-754 | Minting policy with no burn handling |
| [missing-state-update](missing-state-update.md) | CWE-669 | State machine without datum update |
| [rounding-error-risk](rounding-error-risk.md) | CWE-682 | Integer division on financial values |
| [missing-input-credential-check](missing-input-credential-check.md) | CWE-345 | Input iteration without credential check |
| [duplicate-asset-name-risk](duplicate-asset-name-risk.md) | CWE-682 | Minting without unique asset name enforcement |
| [fee-calculation-unchecked](fee-calculation-unchecked.md) | CWE-20 | Fee or protocol payment without validation |
| [datum-tampering-risk](datum-tampering-risk.md) | CWE-20 | Datum passed through without field-level validation |
| [missing-protocol-token](missing-protocol-token.md) | CWE-345 | State transition without protocol token verification |
| [unbounded-protocol-operations](unbounded-protocol-operations.md) | CWE-400 | Both input and output lists iterated without bounds |
