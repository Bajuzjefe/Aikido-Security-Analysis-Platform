# double-satisfaction

**Severity:** Critical
**Confidence:** Definite (own_ref discarded) / Likely (own_ref unused)

## Description

Detects spend handlers that iterate transaction outputs without referencing their own `OutputReference`. This enables a double satisfaction attack where a single transaction spends multiple script UTXOs, and one output satisfies the spending conditions for all of them.

## Vulnerable Example

```aiken
validator {
  spend(datum, redeemer, _own_ref, self) {
    // Checks if ANY output pays enough — but doesn't correlate
    // to THIS specific input being spent
    list.any(self.outputs, fn(o) { o.value >= datum.amount })
  }
}
```

An attacker batches N script inputs and provides one output that satisfies all N validators.

## Safe Example

```aiken
validator {
  spend(datum, redeemer, own_ref, self) {
    let own_input = transaction.find_input(self.inputs, own_ref)
    // Now correlate the output to this specific input
    let continuing_output = find_output_for(self.outputs, own_input)
    continuing_output.value >= datum.amount
  }
}
```

## Remediation

1. Use the `own_ref` (OutputReference) parameter to identify the specific input being spent
2. Find the corresponding continuing output using `own_ref`
3. Validate the output against the specific input, not against all outputs globally

## References

- [Cardano Double Satisfaction Attack](https://github.com/nicholasfrom/cardano-vulnerabilities#double-satisfaction)
- [Plutonomicon Double Satisfaction](https://github.com/ArdanaLabs/Plutonomicon#double-satisfaction)
