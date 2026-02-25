# hardcoded-addresses

**Severity:** Medium
**Confidence:** Possible

## Description

Detects ByteArray literals of suspicious lengths (28, 29, or 57 bytes) in handler bodies. These sizes correspond to Cardano key hashes (28 bytes), key hash + network tag (29 bytes), and full address payloads (57 bytes). Hardcoded addresses make scripts inflexible and can indicate that test addresses were accidentally left in production code.

## Vulnerable Example

```aiken
validator {
  spend(_datum, _redeemer, _own_ref, self) {
    // Hardcoded address — can't change without redeploying
    let admin = #"a1b2c3..."  // 28-byte key hash
    list.has(self.extra_signatories, admin)
  }
}
```

## Safe Example

```aiken
validator(admin_pkh: ByteArray) {
  spend(_datum, _redeemer, _own_ref, self) {
    // Parameterized — configurable at deployment
    list.has(self.extra_signatories, admin_pkh)
  }
}
```

## Remediation

1. Use validator parameters for addresses and key hashes
2. This allows the same script to be deployed with different configurations
3. Reduces risk of test addresses in production

## References

- [Aiken Validator Parameters](https://aiken-lang.org/language-tour/validators#parameters)
