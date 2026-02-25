# invariant-violation

**Severity:** High | **Confidence:** possible | **CWE:** [CWE-682](https://cwe.mitre.org/data/definitions/682.html)

## What it detects

Handlers that perform arithmetic on value amounts without verifying the conservation invariant: `sum(inputs) == sum(outputs) + fees`. When value arithmetic is present but no equality check ties input and output values, the conservation invariant may be violated.

## Why it matters

Value conservation is a core property of any protocol that moves funds. If a handler computes new amounts (splits, fees, rewards) but never asserts that the total is preserved, rounding errors or malicious inputs can silently create or destroy value.

**Real-world impact:** A DEX swap handler calculates output amounts using a constant-product formula but never asserts that `input_value == output_a + output_b + fee`. An attacker crafts a swap where rounding works in their favor on every trade, slowly draining the liquidity pool.

## Example: Vulnerable Code

```aiken
validator dex {
  spend(datum: PoolDatum, redeemer: SwapRedeemer, own_ref: OutputReference, self: Transaction) {
    let input_amount = redeemer.amount
    let fee = input_amount * datum.fee_rate / 10000
    let output_amount = input_amount - fee

    // VULNERABLE: calculates amounts but never checks conservation
    let has_output =
      list.any(self.outputs, fn(o) {
        o.address == redeemer.recipient
      })

    has_output
  }
}
```

## Example: Safe Code

```aiken
validator dex {
  spend(datum: PoolDatum, redeemer: SwapRedeemer, own_ref: OutputReference, self: Transaction) {
    expect Some(own_input) = transaction.find_input(self.inputs, own_ref)
    let input_value = value.lovelace_of(own_input.output.value)

    let fee = input_value * datum.fee_rate / 10000
    let output_amount = input_value - fee

    // SAFE: verify conservation explicitly
    let total_outputs = get_output_value(self.outputs, redeemer.recipient)
    let pool_continuing = get_output_value(self.outputs, own_input.output.address)

    total_outputs + pool_continuing + fee == input_value
  }
}
```

## Detection Logic

Aikido flags this pattern when:

1. **Handler performs arithmetic on amounts** - addition, subtraction, multiplication, or division on value-related variables.
2. **No equality assertion ties inputs to outputs** - the handler never checks that computed values balance.
3. **The handler is a spend handler** with continuing output patterns.

## False Positives

- **External conservation checks:** If conservation is enforced by a coordinating minting policy or withdrawal validator, the spend handler may intentionally skip the check. Suppress with `// aikido:ignore[invariant-violation]`.
- **Non-value arithmetic:** Arithmetic on counters, indices, or timestamps that are unrelated to token values.

## Related Detectors

- [value-not-preserved](value-not-preserved.md) - Detects missing value checks on continuing outputs (complementary).
- [value-preservation-gap](value-preservation-gap.md) - Detects ADA-only checks that miss native assets.
- [fee-calculation-unchecked](../medium/fee-calculation-unchecked.md) - Detects fee computations without bounds validation.
