# division-by-zero-risk

**Severity:** High | **Confidence:** likely | **CWE:** [CWE-369](https://cwe.mitre.org/data/definitions/369.html)

## What it detects

Division or modulo operations in validator handlers where the denominator could be zero, especially when the denominator is derived from attacker-controlled input (redeemer or datum fields). Division by zero in Plutus causes the validator to abort, which can be exploited to block legitimate transactions.

## Why it matters

In Plutus (and Aiken), integer division by zero causes the validator to immediately fail with an error. While this prevents the transaction from succeeding, it creates a denial-of-service vector: an attacker can craft inputs that cause division by zero, preventing legitimate operations.

**Real-world impact:** A DEX validator calculates the swap output using `input_amount * reserve_out / reserve_in`. If `reserve_in` reaches zero (through a sequence of swaps that drain one side of the pool), all subsequent swap transactions fail with a division-by-zero error. The pool becomes permanently unusable, locking all remaining funds. Even the pool creator cannot withdraw because the withdraw handler also uses this calculation.

In more subtle cases, the denominator comes directly from the redeemer. An attacker submits a transaction with `shares: 0` in the redeemer, causing the validator to fail. If this failure cascades (e.g., in a batching protocol where one failed validation blocks an entire batch), the attacker can repeatedly disrupt the protocol at minimal cost.

## Example: Vulnerable Code

```aiken
type WithdrawRedeemer {
  shares: Int,
  recipient: ByteArray,
}

validator liquidity_pool {
  spend(datum: PoolDatum, redeemer: WithdrawRedeemer, own_ref: OutputReference, self: Transaction) {
    expect Some(own_input) = transaction.find_input(self.transaction.inputs, own_ref)
    let total_value = value.lovelace_of(own_input.output.value)

    // VULNERABLE: redeemer.shares could be 0
    let per_share_value = total_value / redeemer.shares
    let withdrawal_amount = per_share_value * redeemer.shares

    validate_withdrawal(withdrawal_amount, datum, self.transaction)
  }
}
```

## Example: Safe Code

```aiken
type WithdrawRedeemer {
  shares: Int,
  recipient: ByteArray,
}

validator liquidity_pool {
  spend(datum: PoolDatum, redeemer: WithdrawRedeemer, own_ref: OutputReference, self: Transaction) {
    expect Some(own_input) = transaction.find_input(self.transaction.inputs, own_ref)
    let total_value = value.lovelace_of(own_input.output.value)

    // SAFE: guard against zero denominator before division
    expect redeemer.shares > 0
    expect datum.total_shares > 0

    let per_share_value = total_value * redeemer.shares / datum.total_shares
    validate_withdrawal(per_share_value, datum, self.transaction)
  }
}
```

## Detection Logic

Aikido flags this pattern when:

1. **Handler is in a validator module** -- library functions are not checked.
2. **The `has_division` body signal is true** -- the handler body contains a `/` (division) or `%` (modulo) operation.

The confidence is **possible** in the general case because the denominator may be a known constant or otherwise guaranteed non-zero. If combined with redeemer-tainted variables (tracked by the `redeemer_tainted_vars` signal), the risk is higher.

## False Positives

- **Constant denominators:** Division by a literal constant (e.g., `amount / 100`) can never be zero. Aikido currently does not distinguish constant from variable denominators. Suppress with `// aikido:ignore[division-by-zero-risk]`.
- **Guarded divisions:** If the handler checks the denominator before dividing (e.g., `expect shares > 0` followed by `total / shares`), the division is safe. Aikido does not yet perform path-sensitive analysis to verify that guards dominate the division.
- **Library function divisions:** Division inside standard library functions (e.g., `math.sqrt`) has internal guards. If the body signal triggers from such a call, it may be a false positive.

## Related Detectors

- [integer-underflow-risk](integer-underflow-risk.md) -- A related arithmetic hazard: subtraction producing negative values.
- [unsafe-redeemer-arithmetic](unsafe-redeemer-arithmetic.md) -- Broader category: arithmetic on redeemer-tainted values without bounds checking.
- [rounding-error-risk](../medium/rounding-error-risk.md) -- Even when division does not fail, integer truncation can cause incorrect financial calculations.
