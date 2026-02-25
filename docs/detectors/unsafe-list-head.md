# unsafe-list-head

**Severity:** Medium
**Confidence:** Likely

## Description

Functions like `list.head()` and `list.at()` crash at runtime when called on an empty list or with an out-of-bounds index. In a validator, this causes the transaction to fail. If the list comes from transaction data (e.g., inputs, outputs), an attacker might craft a transaction that triggers this crash.

## Vulnerable Example

```aiken
validator {
  spend(datum, redeemer, own_ref, self) {
    // Crashes if the transaction has no outputs!
    let first_output = list.head(self.outputs)
    first_output.address == datum.expected_address
  }
}
```

An attacker can submit a transaction with an empty outputs list (or one that doesn't match the expected structure), causing the validator to crash with a runtime error instead of returning `False`.

## Safe Example

```aiken
validator {
  spend(datum, redeemer, own_ref, self) {
    // Pattern matching safely handles the empty list case
    expect [first_output, ..] = self.outputs
    first_output.address == datum.expected_address
  }
}
```

Alternatively, guard with a length check:

```aiken
validator {
  spend(datum, redeemer, own_ref, self) {
    list.length(self.outputs) > 0 && {
      let first_output = list.head(self.outputs)
      first_output.address == datum.expected_address
    }
  }
}
```

## Remediation

1. Replace `list.head()` with pattern matching: `expect [first, ..] = the_list`
2. Replace `list.at(n)` with pattern matching or use `list.length()` to verify bounds first
3. Use `list.find()` or `list.filter()` which return `Option` types instead of crashing
4. When the list comes from transaction data, always assume it could be empty

## References

- [CWE-129: Improper Validation of Array Index](https://cwe.mitre.org/data/definitions/129.html)
