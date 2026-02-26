# missing-signature-check

**Severity:** High
**Confidence:** Likely

## Description

Detects validators with authority/owner fields in the datum that never check `extra_signatories`. If a datum has a field like `owner: ByteArray` but the handler never verifies the transaction is signed by that key, anyone can spend the UTXO.

## Vulnerable Example

```aiken
type Datum {
  owner: ByteArray,
  amount: Int,
}

validator {
  spend(datum, _redeemer, _own_ref, self) {
    // Checks amount but never verifies owner signed!
    list.any(self.outputs, fn(o) { o.value >= datum.amount })
  }
}
```

## Safe Example

```aiken
validator {
  spend(datum, _redeemer, _own_ref, self) {
    list.has(self.extra_signatories, datum.owner)
  }
}
```

## Remediation

1. Use `list.has(self.extra_signatories, datum.owner)` to verify the owner signed
2. Alternatively, check for a specific auth token in inputs

## References

- [MLabs: Missing signature check](https://library.mlabs.city/common-plutus-security-vulnerabilities#missing-signature-check)
