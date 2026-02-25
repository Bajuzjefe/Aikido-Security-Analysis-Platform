# missing-min-ada-check

**Severity:** Low
**Confidence:** Possible

## Description

Cardano requires every UTXO to contain a minimum amount of ADA (approximately 1-2 ADA depending on datum and token size). Script outputs that don't verify this minimum can fail at transaction submission, causing unexpected failures. The Cardano ledger enforces this as a protocol rule, so outputs below the minimum will be rejected.

## Vulnerable Example

```aiken
validator {
  spend(datum, redeemer, own_ref, self) {
    let own_address = get_own_address(self.inputs, own_ref)
    // Output only carries native tokens -- no ADA check!
    list.any(self.outputs, fn(o) {
      o.address == own_address
        && value.quantity_of(o.value, datum.policy_id, datum.asset_name) >= 1
        && o.datum == InlineDatum(new_datum)
    })
  }
}
```

The output may contain only native tokens without sufficient ADA, causing the transaction to be rejected by the Cardano ledger at submission time.

## Safe Example

```aiken
validator {
  spend(datum, redeemer, own_ref, self) {
    let own_address = get_own_address(self.inputs, own_ref)
    // Ensure the output carries at least 2 ADA alongside native tokens
    list.any(self.outputs, fn(o) {
      o.address == own_address
        && value.lovelace_of(o.value) >= 2_000_000
        && value.quantity_of(o.value, datum.policy_id, datum.asset_name) >= 1
        && o.datum == InlineDatum(new_datum)
    })
  }
}
```

## Remediation

1. Always include a minimum ADA check on continuing outputs using `value.lovelace_of(output.value) >= min_required`.
2. When constructing output values, start with `value.from_lovelace(2_000_000)` and add native tokens on top.
3. The exact minimum depends on the output's datum and token bundle size. A safe default is 2 ADA.

## References

- [CWE-754: Improper Check for Unusual or Exceptional Conditions](https://cwe.mitre.org/data/definitions/754.html)
