# tautological-comparison

**Severity:** Critical | **Confidence:** definite | **CWE:** [CWE-571](https://cwe.mitre.org/data/definitions/571.html)

## What it detects

Comparisons where a value is compared to itself, making the expression always evaluate to `True`. This typically indicates a copy-paste bug where the developer intended to compare two different values.

## Why it matters

A tautological comparison silently bypasses the intended validation. In a validator, this means a security check is effectively disabled while appearing correct at a glance. Because the comparison always succeeds, any transaction that reaches this check will pass regardless of the actual data.

**Real-world impact:** A lending protocol's liquidation validator checks that the oracle price is below the threshold: `datum.oracle_price == datum.oracle_price` instead of `datum.oracle_price == redeemer.oracle_price`. Every liquidation attempt succeeds regardless of the actual oracle price, allowing an attacker to liquidate healthy positions and drain collateral.

## Example: Vulnerable Code

```aiken
validator escrow {
  spend(datum: EscrowDatum, redeemer: ClaimRedeemer, _own_ref: OutputReference, self: Transaction) {
    // BUG: comparing datum.beneficiary to itself (always True)
    let valid_claim =
      datum.beneficiary == datum.beneficiary
        && redeemer.amount <= datum.max_claimable

    valid_claim
  }
}
```

## Example: Safe Code

```aiken
validator escrow {
  spend(datum: EscrowDatum, redeemer: ClaimRedeemer, _own_ref: OutputReference, self: Transaction) {
    // SAFE: comparing different sources
    let signer = list.at(self.extra_signatories, 0)
    let valid_claim =
      datum.beneficiary == signer
        && redeemer.amount <= datum.max_claimable

    valid_claim
  }
}
```

## Detection Logic

Aikido flags this pattern when:

1. **Both sides of `==` resolve to the same expression** - same variable path on left and right.
2. **The comparison is in a validator body** - not in a test or library helper.
3. **Confidence is Definite** - a self-comparison is always a bug; there is no legitimate reason to compare a value to itself in a validator.

## False Positives

- **Intentional identity checks in generic code:** Extremely rare in validators. If genuinely intended, suppress with `// aikido:ignore[tautological-comparison]`.

## Related Detectors

- [redundant-check](../low/redundant-check.md) - Detects checks that are logically redundant but not necessarily tautological.
- [dead-code-path](../low/dead-code-path.md) - Tautological conditions can create unreachable branches.
