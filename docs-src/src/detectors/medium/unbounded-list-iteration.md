# unbounded-list-iteration

**Severity:** Medium | **Confidence:** possible | **CWE:** [CWE-400](https://cwe.mitre.org/data/definitions/400.html)

## What it detects

Identifies handlers that directly iterate over raw transaction list fields such as `outputs`, `inputs`, or `reference_inputs` using functions like `list.any`, `list.filter`, `list.map`, or `list.foldl`.

## Why it matters

Transaction list fields are attacker-controlled in size. A malicious user can pad a transaction with many extra UTXOs to inflate iteration cost:

- **`inputs`**: An attacker can add many pubkey inputs they control
- **`outputs`**: Extra outputs can be added to any transaction
- **`reference_inputs`**: Reference inputs are free (no spending required)

If a validator iterates these lists with `O(n)` operations, the execution budget can be exhausted, causing legitimate transactions to fail. This is a denial-of-service vector against the protocol.

## Example: Vulnerable Code

```aiken
validator dex {
  spend(datum: PoolDatum, _redeemer: Void, own_ref: OutputReference, self: Transaction) {
    // Iterates ALL outputs -- attacker can pad with hundreds of extra outputs
    list.any(self.outputs, fn(output) {
      output.address == datum.pool_address &&
      value.lovelace_of(output.value) >= datum.min_liquidity
    })
  }
}
```

## Example: Safe Code

```aiken
validator dex {
  spend(datum: PoolDatum, _redeemer: Void, own_ref: OutputReference, self: Transaction) {
    // Constrain the number of outputs first
    expect list.length(self.outputs) <= 5
    list.any(self.outputs, fn(output) {
      output.address == datum.pool_address &&
      value.lovelace_of(output.value) >= datum.min_liquidity
    })
  }
}
```

Alternatively, use indexed access when you know exactly which output to check:

```aiken
// Use the redeemer to specify the output index
expect [_, pool_output, ..] = self.outputs
pool_output.address == datum.pool_address
```

## Detection Logic

1. Walks validator handler bodies and tracks which transaction list fields are iterated (via `tx_list_iterations` signal).
2. Reports any handler that iterates `outputs`, `inputs`, or `reference_inputs` directly.
3. Reports all iterated fields in a single finding per handler.

## False Positives

- **Small, bounded protocols**: Simple validators where transactions naturally have few inputs/outputs (e.g., 1-in-1-out escrows) may not need bounds checking in practice.
- **Early termination**: `list.any` terminates on first match, which limits worst-case cost if the target is typically found early. This is still flagged because the worst case remains unbounded.
- **Off-chain constraints**: If the transaction builder limits input/output count, the on-chain validator is still technically vulnerable to a crafted transaction.

Suppress with:
```aiken
// aikido:ignore[unbounded-list-iteration] -- protocol limits to 3 outputs via off-chain builder
```

## Related Detectors

- [unbounded-protocol-operations](unbounded-protocol-operations.md) -- O(n*m) dual iteration on inputs AND outputs
- [cheap-spam-vulnerability](cheap-spam-vulnerability.md) -- No minimum value requirements enabling spam
