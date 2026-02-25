# High Severity Detectors

High severity detectors identify serious vulnerabilities that can be exploited under specific conditions, potentially leading to fund loss, unauthorized access, or protocol corruption.

| Detector | CWE | Description |
|----------|-----|-------------|
| [missing-redeemer-validation](missing-redeemer-validation.md) | CWE-20 | Catch-all redeemer pattern trivially returns True |
| [missing-signature-check](missing-signature-check.md) | CWE-862 | Authority datum fields with no extra_signatories check |
| [unsafe-datum-deconstruction](unsafe-datum-deconstruction.md) | CWE-252 | Option datum not safely deconstructed |
| [missing-datum-in-script-output](missing-datum-in-script-output.md) | CWE-404 | Script output without datum attachment |
| [arbitrary-datum-in-output](arbitrary-datum-in-output.md) | CWE-20 | Outputs produced without validating datum correctness |
| [division-by-zero-risk](division-by-zero-risk.md) | CWE-369 | Division with attacker-controlled denominator |
| [token-name-not-validated](token-name-not-validated.md) | CWE-20 | Mint policy checks auth but not token names |
| [value-not-preserved](value-not-preserved.md) | CWE-682 | Spend handler doesn't verify output value >= input value |
| [unsafe-match-comparison](unsafe-match-comparison.md) | CWE-697 | Value compared with match instead of structural equality |
| [integer-underflow-risk](integer-underflow-risk.md) | CWE-191 | Subtraction on redeemer-controlled values |
| [quantity-of-double-counting](quantity-of-double-counting.md) | CWE-682 | Token quantity checked without isolating input vs output |
| [state-transition-integrity](state-transition-integrity.md) | CWE-345 | Redeemer actions without datum transition validation |
| [withdraw-zero-trick](withdraw-zero-trick.md) | CWE-345 | Withdraw handler exploitable with zero-value withdrawal |
| [other-token-minting](other-token-minting.md) | CWE-20 | Mint policy allows minting beyond intended scope |
| [unsafe-redeemer-arithmetic](unsafe-redeemer-arithmetic.md) | CWE-682 | Arithmetic on redeemer-tainted values without bounds |
| [value-preservation-gap](value-preservation-gap.md) | CWE-682 | Lovelace checked but native assets not preserved |
| [uncoordinated-multi-validator](uncoordinated-multi-validator.md) | CWE-362 | Multi-handler validator without coordination |
| [missing-burn-verification](missing-burn-verification.md) | CWE-862 | Token burning without proper verification |
| [oracle-manipulation-risk](oracle-manipulation-risk.md) | CWE-345 | Oracle data used without manipulation safeguards |
