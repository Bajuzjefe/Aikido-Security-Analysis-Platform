# unsafe-list-head

**Severity:** Medium | **Confidence:** likely | **CWE:** [CWE-129](https://cwe.mitre.org/data/definitions/129.html)

## What it detects

Identifies calls to `list.head()` or `list.at()` in validator handlers without a preceding length check or `list.is_empty` guard.

## Why it matters

In Aiken, `list.head()` and `list.at()` crash at runtime when called on an empty list or with an out-of-bounds index. In a validator context, this causes the entire transaction to fail with a Plutus evaluation error, and the user loses their transaction fee.

If the list comes from transaction data (inputs, outputs, reference inputs), an attacker can craft a transaction where the list is empty or shorter than expected, triggering the crash:

- **Griefing attack**: Force legitimate transactions to fail by manipulating transaction structure
- **Denial of service**: If a protocol requires specific UTXOs that don't exist, the validator crashes instead of returning a clear error

## Example: Vulnerable Code

```aiken
validator pool {
  spend(datum: PoolDatum, _redeemer: Void, _ref: OutputReference, self: Transaction) {
    // Crashes if outputs is empty!
    let first_output = list.head(self.outputs)
    first_output.address == datum.pool_address
  }
}
```

## Example: Safe Code

```aiken
validator pool {
  spend(datum: PoolDatum, _redeemer: Void, _ref: OutputReference, self: Transaction) {
    // Safe: pattern matching handles empty case
    expect [first_output, ..] = self.outputs
    first_output.address == datum.pool_address
  }
}
```

Or with an explicit length guard:

```aiken
validator pool {
  spend(datum: PoolDatum, _redeemer: Void, _ref: OutputReference, self: Transaction) {
    expect list.length(self.outputs) >= 1
    let first_output = list.head(self.outputs)
    first_output.address == datum.pool_address
  }
}
```

## Detection Logic

1. Tracks calls to `list.head`, `list.at`, and similar partial functions via the `unsafe_list_access_calls` body signal.
2. Checks for the presence of guard functions: `list.length`, `list.is_empty`, or `builtin.length_of_list`.
3. If unsafe access calls exist without any guard, emits a finding listing the specific calls.

## False Positives

- **Guaranteed non-empty lists**: If a prior `expect` pattern or protocol invariant guarantees the list is non-empty, the `list.head` call is safe.
- **Pattern matching in `expect`**: Aiken's `expect [head, ..] = list` is itself a partial pattern, but it is clearer about failure semantics and is not flagged by this detector.
- **Guard in helper function**: If the length check is in a different function called before `list.head`, Aikido may not trace the control flow.

## Related Detectors

- [unsafe-partial-pattern](unsafe-partial-pattern.md) -- Expect patterns on non-Option types
- [unbounded-list-iteration](unbounded-list-iteration.md) -- Iterating unbounded transaction lists
