# multi-asset-comparison-bypass

**Severity:** High | **Confidence:** likely | **CWE:** [CWE-697](https://cwe.mitre.org/data/definitions/697.html)

## What it detects

Value comparisons using `>=` or `assets.match` with inequality comparators that only verify listed assets meet minimums. Extra unexpected assets are silently accepted, enabling an attacker to inject tokens or manipulate the value.

## Why it matters

Cardano Values are multi-asset containers. A `>=` comparison checks that every asset in the right-hand side exists in the left-hand side with at least that quantity, but it does not check for extra assets. An attacker can inject additional tokens into an output that passes the `>=` check, polluting the UTXO or exploiting downstream logic.

**Real-world impact:** A vault validator checks `output.value >= required_value` where `required_value` contains only ADA. An attacker creates the continuing output with the correct ADA amount plus a spam token. On the next interaction, the extra token causes the value comparison to behave differently, enabling extraction of the spam token plus ADA.

## Example: Vulnerable Code

```aiken
validator vault {
  spend(datum: VaultDatum, _redeemer: Data, own_ref: OutputReference, self: Transaction) {
    expect Some(own_input) = transaction.find_input(self.inputs, own_ref)
    let required = own_input.output.value

    // VULNERABLE: >= allows extra assets in the output
    list.any(self.outputs, fn(o) {
      o.address == own_input.output.address
        && value.geq(o.value, required)
    })
  }
}
```

## Example: Safe Code

```aiken
validator vault {
  spend(datum: VaultDatum, _redeemer: Data, own_ref: OutputReference, self: Transaction) {
    expect Some(own_input) = transaction.find_input(self.inputs, own_ref)

    // SAFE: exact equality prevents extra assets
    list.any(self.outputs, fn(o) {
      o.address == own_input.output.address
        && o.value == own_input.output.value
    })
  }
}
```

## Detection Logic

Aikido flags this pattern when:

1. **A `>=` or `geq` comparison is used on Values** in a continuing output check.
2. **The comparison is the sole value validation** - no additional checks filter unexpected assets.
3. **The context is a spend handler** with continuing UTXO patterns.

## False Positives

- **Intentional value accumulation:** Some protocols (e.g., donation contracts) intentionally accept extra tokens. Suppress with `// aikido:ignore[multi-asset-comparison-bypass]`.
- **Downstream filtering:** If a subsequent handler or minting policy rejects unexpected assets, the `>=` may be acceptable.

## Related Detectors

- [value-comparison-semantics](value-comparison-semantics.md) - Broader: detects multiple unsafe Value comparison patterns.
- [incomplete-value-extraction](../medium/incomplete-value-extraction.md) - Using `quantity_of` to check only one asset.
- [value-not-preserved](value-not-preserved.md) - Missing value checks entirely.
