# fee-calculation-unchecked

**Severity:** Medium | **Confidence:** possible | **CWE:** [CWE-20](https://cwe.mitre.org/data/definitions/20.html)

## What it detects

Identifies handlers that perform subtraction with redeemer-derived (attacker-controlled) values and produce outputs, suggesting a fee or deduction calculation that could be manipulated.

## Why it matters

When a handler computes payouts by subtracting a fee or deduction from a total, and the deduction amount comes from the redeemer, the attacker controls the subtraction:

- **Fee = total**: Attacker sets the fee equal to the total value, draining the entire UTXO
- **Fee > total**: Subtraction goes negative (Aiken integers allow this), producing invalid value calculations
- **Fee = 0**: Attacker bypasses fee collection entirely
- **Precision exploitation**: Combined with rounding errors, manipulated fee amounts extract maximum value

The redeemer is fully attacker-controlled and should never be the sole source of truth for protocol fees.

## Example: Vulnerable Code

```aiken
validator escrow {
  spend(datum: EscrowDatum, redeemer: ClaimRedeemer, _ref: OutputReference, self: Transaction) {
    // Redeemer provides the fee amount -- attacker-controlled!
    let payout = datum.locked_amount - redeemer.fee_amount
    let fee = redeemer.fee_amount

    list.any(self.outputs, fn(output) {
      output.address == datum.beneficiary_address &&
      value.lovelace_of(output.value) >= payout
    })
    // Attacker sets fee_amount = locked_amount, gets everything as "fee"
  }
}
```

## Example: Safe Code

```aiken
validator escrow {
  spend(datum: EscrowDatum, _redeemer: Void, _ref: OutputReference, self: Transaction) {
    // Fee derived from protocol-defined rate, NOT from redeemer
    let fee = datum.locked_amount * protocol_fee_rate / 10000
    let payout = datum.locked_amount - fee

    expect fee >= 0 && fee <= datum.locked_amount  // Bounds check

    list.any(self.outputs, fn(output) {
      output.address == datum.beneficiary_address &&
      value.lovelace_of(output.value) >= payout
    }) && list.any(self.outputs, fn(output) {
      output.address == protocol_treasury &&
      value.lovelace_of(output.value) >= fee
    })
  }
}
```

## Detection Logic

1. Checks handlers that have subtraction operations (`has_subtraction` signal) and redeemer-tainted variables.
2. Requires the handler to also produce outputs (accesses `outputs` in tx fields), indicating a payout or continuing UTXO pattern.
3. Flags handlers where all three conditions are met: subtraction, redeemer taint, and output production.

## False Positives

- **Redeemer as hint, not source of truth**: If the redeemer provides an index or hint that the validator cross-checks against datum or protocol parameters, the subtraction may be safe.
- **Validated redeemer values**: If the handler bounds-checks the redeemer value before using it in subtraction (e.g., `expect redeemer.fee >= min_fee && redeemer.fee <= max_fee`).
- **Non-financial subtraction**: Arithmetic used for non-value calculations (e.g., computing list indices).

Suppress with:
```aiken
// aikido:ignore[fee-calculation-unchecked] -- redeemer fee validated against protocol bounds
```

## Related Detectors

- [unsafe-redeemer-arithmetic](../high/unsafe-redeemer-arithmetic.md) -- Arithmetic on redeemer-tainted values without bounds
- [integer-underflow-risk](../high/integer-underflow-risk.md) -- Subtraction on redeemer-controlled values
- [rounding-error-risk](rounding-error-risk.md) -- Integer division precision loss
