# missing-datum-in-script-output

**Severity:** High
**Confidence:** Possible

## Description

Detects handlers that access transaction outputs but never check the `datum` field. Outputs sent to script addresses without a datum make funds permanently unspendable — the script can never validate a spending transaction because there's no datum to read.

## Vulnerable Example

```aiken
validator {
  spend(datum, redeemer, own_ref, self) {
    list.any(self.outputs, fn(o) {
      o.address == own_address && o.value >= min_value
      // Missing: no datum check!
    })
  }
}
```

## Safe Example

```aiken
validator {
  spend(datum, redeemer, own_ref, self) {
    list.any(self.outputs, fn(o) {
      o.address == own_address
      && o.value >= min_value
      && o.datum == InlineDatum(expected_datum)
    })
  }
}
```

## Remediation

1. Check `output.datum` for continuing outputs to script addresses
2. Use `InlineDatum(...)` or `DatumHash(...)` to verify datum content
3. Ensure the datum matches expected state transitions

## References

- [MLabs: Missing datum](https://library.mlabs.city/common-plutus-security-vulnerabilities)
