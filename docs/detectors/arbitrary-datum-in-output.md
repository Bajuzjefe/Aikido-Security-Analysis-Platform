# arbitrary-datum-in-output

**Severity:** High
**Confidence:** Possible

## Description

When a handler creates continuing outputs (e.g., sending funds back to the script), the datum attached to those outputs must be validated. If the datum is not checked against expected values, an attacker can lock funds with an arbitrary datum, potentially making them unspendable or manipulating contract state.

## Vulnerable Example

```aiken
validator {
  spend(datum, redeemer, own_ref, self) {
    let own_address = get_own_address(self.inputs, own_ref)
    let min_value = datum.locked_amount
    // Checks output exists at the right address with enough value,
    // but never validates what datum is attached to that output!
    list.any(self.outputs, fn(o) {
      o.address == own_address && value.lovelace_of(o.value) >= min_value
    })
  }
}
```

An attacker can attach an arbitrary datum to the continuing output, corrupting the contract state or permanently locking funds by making them unspendable by any future redeemer.

## Safe Example

```aiken
validator {
  spend(datum, redeemer, own_ref, self) {
    let own_address = get_own_address(self.inputs, own_ref)
    let min_value = datum.locked_amount
    let expected_datum = Datum { ..datum, counter: datum.counter + 1 }
    // Validates both the value AND the datum on the continuing output
    list.any(self.outputs, fn(o) {
      o.address == own_address
        && value.lovelace_of(o.value) >= min_value
        && o.datum == InlineDatum(expected_datum)
    })
  }
}
```

## Remediation

1. Always validate the datum attached to continuing outputs using `o.datum == InlineDatum(expected)`.
2. Construct the expected datum explicitly from the current state and verify it matches.
3. If using `DatumHash`, ensure the hash corresponds to the correct datum content.

## References

- [CWE-20: Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)
