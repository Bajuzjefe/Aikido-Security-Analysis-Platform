# integer-underflow-risk

**Severity:** High | **Confidence:** likely | **CWE:** [CWE-191](https://cwe.mitre.org/data/definitions/191.html)

## What it detects

Integer subtraction in validator handlers where the result could go negative, especially when the subtrahend (value being subtracted) comes from attacker-controlled input such as redeemer or datum fields. Plutus integers are arbitrary-precision and can represent negative values, which -- when used as token quantities, lovelace amounts, or loop bounds -- cause unexpected and exploitable behavior.

## Why it matters

Unlike Solidity (where unsigned integers revert on underflow), Aiken/Plutus integers are signed and arbitrary-precision. Subtraction that produces a negative number does not cause an error -- it silently produces a negative value. When this negative value is used in subsequent calculations (e.g., computing a payout, adjusting pool reserves, or determining token quantities), the result is mathematically incorrect and often exploitable.

**Real-world impact:** A collateralized lending protocol computes `remaining_collateral = collateral_value - total_loss`. The `total_loss` comes from the redeemer (attacker-controlled). If `total_loss > collateral_value`, `remaining_collateral` becomes negative. This negative value is then added to the pool's reserves, effectively *increasing* them in the validator's view while the actual value decreased. The attacker can repeat this to inflate the pool's accounting arbitrarily, eventually withdrawing the inflated balance.

In another scenario, a reward calculator uses `staked_amount - withdrawal_amount`. If the withdrawal exceeds the stake (because the redeemer specifies an inflated withdrawal), the result underflows and the validator computes nonsensical reward amounts.

## Example: Vulnerable Code

```aiken
type ClaimRedeemer {
  claim_amount: Int,
  recipient: ByteArray,
}

validator reward_vault {
  spend(datum: VaultDatum, redeemer: ClaimRedeemer, own_ref: OutputReference, self: Transaction) {
    expect Some(own_input) = transaction.find_input(self.transaction.inputs, own_ref)
    let current_balance = value.lovelace_of(own_input.output.value)

    // VULNERABLE: redeemer.claim_amount could exceed current_balance
    let remaining = current_balance - redeemer.claim_amount
    // remaining could be negative! But the code continues...

    let new_datum = VaultDatum { ..datum, balance: remaining }

    list.any(
      self.transaction.outputs,
      fn(output) {
        output.address == own_input.output.address
          && value.lovelace_of(output.value) >= remaining
          // A negative remaining means ANY output satisfies this!
          && output.datum == InlineDatum(new_datum)
      },
    )
  }
}
```

## Example: Safe Code

```aiken
type ClaimRedeemer {
  claim_amount: Int,
  recipient: ByteArray,
}

validator reward_vault {
  spend(datum: VaultDatum, redeemer: ClaimRedeemer, own_ref: OutputReference, self: Transaction) {
    expect Some(own_input) = transaction.find_input(self.transaction.inputs, own_ref)
    let current_balance = value.lovelace_of(own_input.output.value)

    // SAFE: guard against underflow before subtraction
    expect redeemer.claim_amount > 0
    expect redeemer.claim_amount <= current_balance

    let remaining = current_balance - redeemer.claim_amount

    // Now remaining is guaranteed non-negative
    let new_datum = VaultDatum { ..datum, balance: remaining }

    list.any(
      self.transaction.outputs,
      fn(output) {
        output.address == own_input.output.address
          && value.lovelace_of(output.value) >= remaining
          && output.datum == InlineDatum(new_datum)
      },
    )
  }
}
```

## Detection Logic

Aikido flags this pattern when:

1. **Handler is in a validator module**.
2. **The `has_subtraction` body signal is true** -- the handler contains a `-` (subtraction) operation.
3. **Confidence adjustment:** If the `redeemer_tainted_vars` set is non-empty (the handler has variables derived from redeemer input), confidence is **likely** because the subtrahend may be attacker-controlled. Otherwise, confidence is **possible**.

## False Positives

- **Guarded subtractions:** If the handler explicitly checks `b <= a` before computing `a - b`, the subtraction is safe. Aikido does not yet perform path-sensitive analysis to verify that guards dominate the subtraction. Suppress with `// aikido:ignore[integer-underflow-risk]`.
- **Constant subtractions:** Subtracting a known constant (e.g., `amount - 2_000_000` for minimum ADA) cannot underflow in normal operation (the UTXO would not exist with less than the constant). These are false positives.
- **Value-level subtraction:** Using `value.negate` and `value.merge` for multi-asset arithmetic may trigger this detector even though the Cardano ledger enforces non-negative output values.
- **Time arithmetic:** Subtracting timestamps or slot numbers (e.g., `current_slot - start_slot`) where the order is guaranteed by the protocol.

## Related Detectors

- [division-by-zero-risk](division-by-zero-risk.md) -- Another arithmetic hazard: division by attacker-controlled denominators.
- [unsafe-redeemer-arithmetic](unsafe-redeemer-arithmetic.md) -- The broader category: any arithmetic on redeemer-tainted values without bounds checking.
- [rounding-error-risk](../medium/rounding-error-risk.md) -- Integer division truncation, a different but related arithmetic concern.
- [value-not-preserved](value-not-preserved.md) -- Negative values from underflow can cause value preservation checks to silently pass.
