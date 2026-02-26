# value-not-preserved

**Severity:** High
**Confidence:** Possible

## Description

A spend handler that sends continuing outputs back to the script should verify that the output value is sufficient (typically >= the input value, minus any intended withdrawal). Without this check, an attacker could drain funds by creating outputs with less value than the input.

This detector flags spend handlers that access `outputs` (indicating a continuing UTXO pattern) but never check the `value` field or call value-related functions like `lovelace_of`, `value.merge`, or `value.from_lovelace`.

## Vulnerable Example

```aiken
validator {
  spend(datum, redeemer, own_ref, self) {
    let own_address = find_own_address(self.inputs, own_ref)
    // Checks that a continuing output exists at the right address
    // but NEVER checks its value!
    list.any(self.outputs, fn(o) {
      o.address == own_address &&
      o.datum == InlineDatum(datum)
    })
  }
}
```

An attacker spends the script UTXO holding 1000 ADA and creates a continuing output with only the minimum ADA (~1.5 ADA), pocketing the difference.

## Safe Example

```aiken
validator {
  spend(datum, redeemer, own_ref, self) {
    let own_address = find_own_address(self.inputs, own_ref)
    let own_input = find_input(self.inputs, own_ref)
    list.any(self.outputs, fn(o) {
      o.address == own_address &&
      o.datum == InlineDatum(datum) &&
      // Verify value is preserved
      value.lovelace_of(o.value) >= value.lovelace_of(own_input.output.value)
    })
  }
}
```

## Remediation

1. Always verify the output value in continuing UTXO patterns using `value.lovelace_of()` or direct value comparison
2. Compare the continuing output value against the input value to ensure funds are not drained
3. If partial withdrawals are allowed, verify the output value equals the input value minus the authorized withdrawal amount
4. For validators holding native assets, check both ADA and token quantities using `value.quantity_of()` or `value.without_lovelace()`

## References

- [CWE-682: Incorrect Calculation](https://cwe.mitre.org/data/definitions/682.html)
