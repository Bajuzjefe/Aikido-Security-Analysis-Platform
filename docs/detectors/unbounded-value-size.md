# unbounded-value-size

**Severity:** Medium
**Confidence:** Possible

## Description

When a script creates continuing outputs (sending value back to the script address), it should constrain the number of native assets (token policies) in the output value. Without this check, an attacker can add many small native assets ("token dust") to the UTXO, bloating its size and increasing the cost to spend it -- potentially making it unspendable if processing exceeds the Plutus execution budget.

## Vulnerable Example

```aiken
validator {
  spend(datum, redeemer, own_ref, self) {
    let own_address = find_own_address(self.inputs, own_ref)
    list.any(self.outputs, fn(o) {
      o.address == own_address &&
      value.lovelace_of(o.value) >= datum.min_amount
      // Missing: no constraint on native asset count!
      // Attacker can add hundreds of junk tokens to this output
    })
  }
}
```

An attacker includes the script UTXO as an input and creates the continuing output with hundreds of native asset policies attached. The next person who tries to spend this UTXO will exceed the execution budget iterating over all those assets.

## Safe Example

```aiken
validator {
  spend(datum, redeemer, own_ref, self) {
    let own_address = find_own_address(self.inputs, own_ref)
    list.any(self.outputs, fn(o) {
      o.address == own_address &&
      value.lovelace_of(o.value) >= datum.min_amount &&
      // Constrain the number of token policies in the output
      list.length(value.policies(o.value)) <= 2
    })
  }
}
```

## Remediation

1. Check the number of native asset policies in continuing outputs using `value.policies()` and enforce an upper bound
2. Alternatively, use `value.without_lovelace()` to inspect the exact token content and verify it matches expectations
3. Use `value.quantity_of()` to check for specific expected tokens rather than accepting arbitrary value

## References

- [CWE-400: Uncontrolled Resource Consumption](https://cwe.mitre.org/data/definitions/400.html)
