# unbounded-list-iteration

**Severity:** Medium
**Confidence:** Possible

## Description

Detects handlers that iterate over raw transaction lists (outputs, inputs, etc.) using functions like `list.any`, `list.map`, `list.filter`. While often necessary, unbounded iteration over transaction lists can lead to excessive execution costs if an attacker creates a transaction with many inputs/outputs.

## Vulnerable Example

```aiken
validator {
  spend(datum, _redeemer, _own_ref, self) {
    // Iterates ALL outputs — cost grows with transaction size
    list.any(self.outputs, fn(o) {
      o.address == datum.target && o.value >= datum.amount
    })
  }
}
```

## Safer Example

```aiken
validator {
  spend(datum, redeemer, own_ref, self) {
    // Use redeemer to specify the output index
    let output = list.at(self.outputs, redeemer.output_index)
    output.address == datum.target && output.value >= datum.amount
  }
}
```

## Remediation

1. Use redeemer fields to specify indices instead of searching
2. Filter lists early to reduce iteration scope
3. Consider execution budget implications

## References

- [MLabs: Unbounded protocol datum](https://library.mlabs.city/common-plutus-security-vulnerabilities)
- [Vacuumlabs: Transaction size attacks](https://vacuumlabs.com/blog/technology/cardano-smart-contract-audit-guide)
