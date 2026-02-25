# unused-validator-parameter

**Severity:** Medium
**Confidence:** Likely

## Description

Detects validator parameters (deployment-time configuration) that are never referenced in any handler. Unused parameters waste script size, increase deployment costs, and may indicate missing validation logic.

## Vulnerable Example

```aiken
validator(oracle_pkh: ByteArray) {
  spend(datum, redeemer, own_ref, self) {
    // oracle_pkh is never used!
    list.has(self.extra_signatories, datum.owner)
  }
}
```

## Safe Example

```aiken
validator(oracle_pkh: ByteArray) {
  spend(datum, redeemer, own_ref, self) {
    let oracle = find_oracle(self.reference_inputs, oracle_pkh)
    verify_oracle_data(oracle, datum)
  }
}
```

## Remediation

1. Use the parameter in handler logic
2. Or remove it if it's truly unnecessary
3. Or prefix with `_` to mark as intentionally unused

## References

- [Aiken Validator Parameters](https://aiken-lang.org/language-tour/validators#parameters)
