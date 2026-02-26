# output-count-validation

**Severity:** Medium | **Confidence:** possible | **CWE:** [CWE-697](https://cwe.mitre.org/data/definitions/697.html)

## What it detects

Spend handlers that produce continuing outputs to a script address without verifying how many outputs are created. Without an output count check, an attacker can create extra script outputs in the same transaction, effectively duplicating the contract state.

## Why it matters

Many validators use `list.any(self.outputs, ...)` to verify that at least one valid continuing output exists. The problem is that `list.any` returns `True` as soon as one match is found, ignoring additional matches. An attacker can include multiple valid outputs in a single transaction, each carrying a copy of the state, potentially doubling their claim.

**Real-world impact:** A staking pool validator checks that `any` output goes to the script with the correct datum. An attacker creates two valid continuing outputs, each with the full staked amount in the datum. On the next interaction, the attacker unstakes from both, withdrawing twice the original deposit.

## Example: Vulnerable Code

```aiken
validator pool {
  spend(datum: PoolDatum, _redeemer: Data, own_ref: OutputReference, self: Transaction) {
    expect Some(own_input) = transaction.find_input(self.inputs, own_ref)

    // VULNERABLE: checks that at least one valid output exists
    // but doesn't verify ONLY one exists
    list.any(self.outputs, fn(o) {
      o.address == own_input.output.address
        && o.value == own_input.output.value
    })
  }
}
```

## Example: Safe Code

```aiken
validator pool {
  spend(datum: PoolDatum, _redeemer: Data, own_ref: OutputReference, self: Transaction) {
    expect Some(own_input) = transaction.find_input(self.inputs, own_ref)
    let own_hash = when own_input.output.address.payment_credential is {
      ScriptCredential(hash) -> hash
      _ -> fail
    }

    // SAFE: filter and count script outputs
    let script_outputs =
      list.filter(self.outputs, fn(o) {
        o.address.payment_credential == ScriptCredential(own_hash)
      })

    expect list.length(script_outputs) == 1
    expect Some(continuing) = list.head(script_outputs)
    continuing.value == own_input.output.value
  }
}
```

## Detection Logic

Aikido flags this pattern when:

1. **A spend handler produces continuing outputs** - outputs going to the same script address.
2. **`list.any` or equivalent is used** to check for valid outputs.
3. **No output count check is present** - no `list.length`, `list.filter` + count, or explicit uniqueness assertion.

## False Positives

- **Single-UTXO protocols:** If the protocol uses identity tokens to ensure uniqueness, output count checks may be redundant. Suppress with `// aikido:ignore[output-count-validation]`.
- **Multi-output designs:** Some protocols intentionally create multiple outputs (e.g., batch processing). In these cases, the count is expected to vary.

## Related Detectors

- [double-satisfaction](../critical/double-satisfaction.md) - Related: multiple inputs can share validation.
- [state-transition-integrity](../high/state-transition-integrity.md) - State transitions should produce exactly the expected outputs.
- [value-not-preserved](../high/value-not-preserved.md) - Value should be preserved per output.
