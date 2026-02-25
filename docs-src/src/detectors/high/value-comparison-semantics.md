# value-comparison-semantics

**Severity:** High | **Confidence:** possible | **CWE:** [CWE-697](https://cwe.mitre.org/data/definitions/697.html)

## What it detects

Unsafe multi-asset Value comparison patterns. Two primary patterns:

1. **Lovelace-only comparison:** Using `lovelace_of()` to compare entire Values, ignoring native token quantities.
2. **Partial match:** Using `>=` with `assets.match` to verify listed assets meet minimums without catching extra injected assets.

## Why it matters

Cardano Values contain ADA (lovelace) plus any number of native assets. Comparing only the lovelace component means an attacker can drain all native assets while keeping the ADA balance unchanged. Similarly, partial matching with `>=` allows asset injection.

**Real-world impact:** A staking pool checks value preservation using `lovelace_of(output.value) >= lovelace_of(input.value)`. An attacker constructs a transaction that preserves the ADA but removes all reward tokens from the pool UTXO. The validator approves because the lovelace check passes.

## Example: Vulnerable Code

```aiken
validator pool {
  spend(datum: PoolDatum, _redeemer: Data, own_ref: OutputReference, self: Transaction) {
    expect Some(own_input) = transaction.find_input(self.inputs, own_ref)
    let input_lovelace = value.lovelace_of(own_input.output.value)

    // VULNERABLE: only checks ADA, native assets can be drained
    list.any(self.outputs, fn(o) {
      o.address == own_input.output.address
        && value.lovelace_of(o.value) >= input_lovelace
    })
  }
}
```

## Example: Safe Code

```aiken
validator pool {
  spend(datum: PoolDatum, _redeemer: Data, own_ref: OutputReference, self: Transaction) {
    expect Some(own_input) = transaction.find_input(self.inputs, own_ref)

    // SAFE: compare entire Value including all native assets
    list.any(self.outputs, fn(o) {
      o.address == own_input.output.address
        && o.value == own_input.output.value
    })
  }
}
```

## Detection Logic

Aikido flags this pattern when:

1. **Pattern 1 (High):** `lovelace_of()` is the sole mechanism for comparing input and output values in a continuing UTXO check.
2. **Pattern 2 (Medium):** `>=` or `assets.match` with inequality is used as the sole value validation on multi-asset Values.
3. **The handler is a spend handler** with continuing output patterns.

## False Positives

- **ADA-only protocols:** If the protocol genuinely only handles ADA (no native assets), lovelace comparison is sufficient. Suppress with `// aikido:ignore[value-comparison-semantics]`.
- **Intentional partial checks:** Some protocols only need to preserve specific assets and allow others to change.

## Related Detectors

- [multi-asset-comparison-bypass](multi-asset-comparison-bypass.md) - Focused specifically on `>=` bypass.
- [value-preservation-gap](value-preservation-gap.md) - ADA checked but native assets not preserved.
- [incomplete-value-extraction](../medium/incomplete-value-extraction.md) - `quantity_of` checks only one asset.
