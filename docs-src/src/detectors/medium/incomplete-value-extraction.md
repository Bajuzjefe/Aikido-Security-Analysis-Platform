# incomplete-value-extraction

**Severity:** Medium | **Confidence:** possible | **CWE:** [CWE-697](https://cwe.mitre.org/data/definitions/697.html)

## What it detects

Value checks that use `quantity_of` to extract a single asset's quantity, ignoring all other assets in the Value. When used as the sole validation on an output Value, other native assets are not checked and can be drained.

## Why it matters

`quantity_of(value, policy, name)` returns the quantity of one specific asset. If this is the only check on an output's value, an attacker can construct a transaction that preserves the checked asset but removes or adds all other assets.

**Real-world impact:** A liquidity pool validator checks that the continuing output has at least the expected amount of Token A using `quantity_of`. An attacker creates the output with the correct Token A quantity but drains all Token B from the pool. The validator approves because it only checked one asset.

## Example: Vulnerable Code

```aiken
validator pool {
  spend(datum: PoolDatum, _redeemer: Data, own_ref: OutputReference, self: Transaction) {
    expect Some(own_input) = transaction.find_input(self.inputs, own_ref)

    // VULNERABLE: only checks one asset, others can be drained
    list.any(self.outputs, fn(o) {
      o.address == own_input.output.address
        && value.quantity_of(o.value, datum.token_a_policy, datum.token_a_name)
            >= value.quantity_of(own_input.output.value, datum.token_a_policy, datum.token_a_name)
    })
  }
}
```

## Example: Safe Code

```aiken
validator pool {
  spend(datum: PoolDatum, _redeemer: Data, own_ref: OutputReference, self: Transaction) {
    expect Some(own_input) = transaction.find_input(self.inputs, own_ref)

    // SAFE: compare entire value
    list.any(self.outputs, fn(o) {
      o.address == own_input.output.address
        && o.value == own_input.output.value
    })
  }
}
```

## Detection Logic

Aikido flags this pattern when:

1. **`quantity_of` is the sole value check** on a continuing output.
2. **The input UTXO could contain multiple assets** - not a known ADA-only context.
3. **No full Value comparison** (`==`, `value.merge`, or comprehensive asset enumeration) supplements the check.

## False Positives

- **Single-asset protocols:** If the UTXO is guaranteed to only contain ADA and one token, `quantity_of` may be sufficient. Suppress with `// aikido:ignore[incomplete-value-extraction]`.
- **Multiple `quantity_of` calls:** If every asset is individually checked via separate `quantity_of` calls, the coverage may be complete.

## Related Detectors

- [value-comparison-semantics](../high/value-comparison-semantics.md) - Broader unsafe Value comparison patterns.
- [multi-asset-comparison-bypass](../high/multi-asset-comparison-bypass.md) - `>=` comparison allowing extra assets.
- [value-not-preserved](../high/value-not-preserved.md) - No value check at all.
