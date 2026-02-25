# unrestricted-minting

**Severity:** Critical
**Confidence:** Definite

## Description

Detects minting policies with no authorization checks at all. A mint handler that doesn't check `extra_signatories`, `inputs`, `mint`, or `reference_inputs` allows anyone to mint tokens freely.

## Vulnerable Example

```aiken
validator {
  mint(_redeemer, _self) {
    True
  }
}
```

## Safe Example

```aiken
validator(admin_pkh: ByteArray) {
  mint(_redeemer, self) {
    list.has(self.extra_signatories, admin_pkh)
  }
}
```

## Remediation

1. Add signer check: `list.has(self.extra_signatories, admin_pkh)`
2. Or add UTXO check: verify a specific input is consumed
3. Or add one-shot pattern: check own policy ID in inputs

## References

- [Plutonomicon: Unrestricted minting](https://github.com/ArdanaLabs/Plutonomicon)
