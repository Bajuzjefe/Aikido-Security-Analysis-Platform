# unbounded-protocol-operations

**Severity:** Medium | **Confidence:** possible | **CWE:** [CWE-400](https://cwe.mitre.org/data/definitions/400.html)

## What it detects

Identifies handlers that iterate over both transaction inputs and outputs without length bounds, creating O(n*m) complexity risk.

## Why it matters

When a handler iterates over both `self.inputs` and `self.outputs`, the combined iteration creates quadratic complexity. An attacker can exploit this by padding the transaction with extra inputs and outputs:

- **Budget exhaustion**: With 50 inputs and 50 outputs, the validator performs ~2,500 operations. With 100 of each, it is 10,000 operations. This rapidly exceeds the Plutus execution budget.
- **Griefing attack**: An attacker can include many small pubkey inputs and extra outputs to force the validator to iterate more, causing legitimate transactions to fail.
- **Nested iteration amplification**: If the handler uses nested list operations (e.g., `list.filter` over inputs inside `list.map` over outputs), the complexity is truly O(n*m).

Even linear iteration over one list is risky (see `unbounded-list-iteration`), but dual iteration is significantly worse.

## Example: Vulnerable Code

```aiken
validator batch_processor {
  spend(datum: BatchDatum, _redeemer: Void, own_ref: OutputReference, self: Transaction) {
    // Filter inputs and outputs separately -- O(n) + O(m)
    let script_inputs = list.filter(self.inputs, fn(input) {
      input.output.address == datum.script_address
    })
    let script_outputs = list.filter(self.outputs, fn(output) {
      output.address == datum.script_address
    })

    // Now cross-reference them -- O(n*m) total!
    list.all(script_inputs, fn(input) {
      list.any(script_outputs, fn(output) {
        value.lovelace_of(output.value) >= value.lovelace_of(input.output.value)
      })
    })
  }
}
```

## Example: Safe Code

```aiken
validator batch_processor {
  spend(datum: BatchDatum, _redeemer: Void, own_ref: OutputReference, self: Transaction) {
    // Bound the input and output counts first
    expect list.length(self.inputs) <= 10
    expect list.length(self.outputs) <= 10

    let script_inputs = list.filter(self.inputs, fn(input) {
      input.output.address == datum.script_address
    })
    let script_outputs = list.filter(self.outputs, fn(output) {
      output.address == datum.script_address
    })

    list.all(script_inputs, fn(input) {
      list.any(script_outputs, fn(output) {
        value.lovelace_of(output.value) >= value.lovelace_of(input.output.value)
      })
    })
  }
}
```

Or use indexed access to avoid iteration entirely:

```aiken
// Redeemer provides indices -- O(1) access
expect input = list.at(self.inputs, redeemer.input_index)
expect output = list.at(self.outputs, redeemer.output_index)
value.lovelace_of(output.value) >= value.lovelace_of(input.output.value)
```

## Detection Logic

1. Checks handler body signals for `tx_list_iterations` containing both "inputs" and "outputs".
2. Looks for mitigating `list.length` or `length` calls that could bound the iteration.
3. If both lists are iterated and no length bounds are detected, emits a finding.

## False Positives

- **Off-chain bounded transactions**: If the protocol's transaction builder guarantees small input/output counts, the on-chain validator is still technically vulnerable to crafted transactions but unlikely to be exploited.
- **Early termination**: `list.any` stops on first match, so worst-case complexity may not be reached in practice.
- **Length bounds elsewhere**: If length checks are done in a helper function called before the iteration.

Suppress with:
```aiken
// aikido:ignore[unbounded-protocol-operations] -- max 3 inputs and 3 outputs by protocol design
```

## Related Detectors

- [unbounded-list-iteration](unbounded-list-iteration.md) -- Single list iteration without bounds
- [cheap-spam-vulnerability](cheap-spam-vulnerability.md) -- No minimum deposit requirements
- [utxo-contention-risk](utxo-contention-risk.md) -- Single global UTXO throughput bottleneck
