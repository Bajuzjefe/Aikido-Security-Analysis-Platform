# double-satisfaction

**Severity:** Critical | **Confidence:** definite | **CWE:** [CWE-362](https://cwe.mitre.org/data/definitions/362.html)

## What it detects

Spend handlers that iterate transaction outputs without referencing their own `OutputReference`. When a validator checks outputs (e.g., looking for a continuing UTXO with sufficient value) but never correlates those checks to the specific input being spent, multiple script inputs can be "satisfied" by a single output.

## Why it matters

A double satisfaction attack is one of the most dangerous vulnerabilities in Cardano smart contracts. In a single transaction, an attacker can spend multiple UTXOs locked at the same script address. If the validator only checks that *some* output meets a condition (like carrying enough ADA) but does not tie that output to the specific input being validated, one output satisfies the condition for all inputs simultaneously.

**Real-world impact:** An attacker holding two UTXOs at a lending protocol -- each worth 1,000 ADA -- constructs a transaction spending both. The validator for each input sees an output of 1,000 ADA going back to the script and approves. But there is only one such output. The attacker pockets 1,000 ADA. At scale, this drains the entire protocol TVL.

This attack has been found in multiple Cardano DeFi audits and is considered the signature Cardano-specific vulnerability.

## Example: Vulnerable Code

```aiken
validator treasury {
  spend(datum: TreasuryDatum, _redeemer: Redeemer, _own_ref, self: Transaction) {
    // VULNERABLE: iterates outputs but never uses own_ref
    // A single output can satisfy this check for multiple inputs
    list.any(
      self.transaction.outputs,
      fn(output) {
        output.address == datum.script_address
          && value.lovelace_of(output.value) >= datum.locked_amount
      },
    )
  }
}
```

## Example: Safe Code

```aiken
use cardano/transaction.{find_input}

validator treasury {
  spend(datum: TreasuryDatum, _redeemer: Redeemer, own_ref: OutputReference, self: Transaction) {
    // SAFE: uses own_ref to identify the specific input being spent
    expect Some(own_input) = find_input(self.transaction.inputs, own_ref)
    let own_value = own_input.output.value

    // Now correlate: the continuing output must carry at least our value
    list.any(
      self.transaction.outputs,
      fn(output) {
        output.address == own_input.output.address
          && value.lovelace_of(output.value) >= value.lovelace_of(own_value)
      },
    )
  }
}
```

## Detection Logic

Aikido flags this pattern when all of the following are true:

1. **Handler type is `spend`** -- only spend handlers receive an `OutputReference` parameter.
2. **Handler accesses `transaction.outputs`** -- indicates it iterates or inspects outputs.
3. **The third parameter (`own_ref`) is either discarded (prefixed with `_`) or never referenced in the body** -- the `uses_own_ref` body signal is false.

When `own_ref` is explicitly discarded (e.g., `_own_ref`), confidence is **definite**. When the parameter exists but is simply never used in the handler body, confidence is **likely**.

## False Positives

This detector may fire incorrectly in these scenarios:

- **Withdrawal-only validators:** If the spend handler only permits full withdrawal (no continuing output), double satisfaction is not exploitable because the attacker cannot save on outputs. Suppress with `// aikido:ignore[double-satisfaction]`.
- **Single-use UTXOs:** Validators that enforce a one-shot pattern (e.g., consuming an NFT) where only one UTXO can ever exist at the script address.
- **Cross-module correlation:** The `own_ref` may be passed to a helper function in another module. Aikido's cross-module analysis tracks this, but deeply nested helper chains may occasionally be missed.

## Related Detectors

- [value-not-preserved](../high/value-not-preserved.md) -- Checks that output value covers input value, complementary to this detector.
- [output-address-not-validated](output-address-not-validated.md) -- Ensures output addresses are checked; often co-occurs with double satisfaction.
- [uncoordinated-multi-validator](../high/uncoordinated-multi-validator.md) -- Multi-handler validators without coordination face similar batch-exploit risks.
