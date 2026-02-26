# uncoordinated-state-transfer

**Severity:** Medium | **Confidence:** possible | **CWE:** [CWE-345](https://cwe.mitre.org/data/definitions/345.html)

## What it detects

Spend handlers that produce continuing outputs and coordinate with other validators (via mint or withdrawals) but only check for the existence of the coordination without verifying the coordinated validator's state.

## Why it matters

Multi-validator protocols require coordination: a spend handler may check that a minting policy was invoked or a staking script was withdrawn. But if the handler only checks `has_key(self.mint, policy)` without verifying what was minted (or how much), the coordination is incomplete and can be exploited.

**Real-world impact:** A DEX pool handler checks that the LP minting policy is invoked during a swap but never verifies the minted amount. An attacker triggers the minting policy (minting 0 LP tokens) to satisfy the existence check while manipulating the pool's reserves.

## Example: Vulnerable Code

```aiken
validator pool {
  spend(datum: PoolDatum, _redeemer: Data, own_ref: OutputReference, self: Transaction) {
    // VULNERABLE: checks that minting occurred but not what was minted
    let mint_invoked =
      value.from_minted_value(self.mint)
        |> value.policies
        |> list.has(datum.lp_policy)

    mint_invoked && validate_outputs(datum, self)
  }
}
```

## Example: Safe Code

```aiken
validator pool {
  spend(datum: PoolDatum, _redeemer: Data, own_ref: OutputReference, self: Transaction) {
    let minted = value.from_minted_value(self.mint)

    // SAFE: verify the exact minted quantity
    let lp_minted = value.quantity_of(minted, datum.lp_policy, "LP")
    expect lp_minted == expected_lp_amount(datum, self)

    validate_outputs(datum, self)
  }
}
```

## Detection Logic

Aikido flags this pattern when:

1. **A spend handler produces continuing outputs** - indicating state management.
2. **The handler accesses `self.mint` or `self.withdrawals`** - indicating multi-validator coordination.
3. **Only existence is checked** - `has_key`, `policies`, or `list.has` without quantity/amount verification.

## False Positives

- **Mint policy handles validation:** If the minting policy itself enforces the correct quantities, the spend handler may not need to recheck. Suppress with `// aikido:ignore[uncoordinated-state-transfer]`.
- **Withdrawal for routing only:** If the withdrawal carries data via redeemer rather than serving as authorization.

## Related Detectors

- [uncoordinated-multi-validator](../high/uncoordinated-multi-validator.md) - Broader multi-validator issues.
- [cross-validator-gap](../high/cross-validator-gap.md) - Delegation without proper checks.
- [withdraw-amount-check](withdraw-amount-check.md) - Similar pattern for withdrawal amounts.
