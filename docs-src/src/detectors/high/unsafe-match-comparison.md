# unsafe-match-comparison

**Severity:** High | **Confidence:** likely | **CWE:** [CWE-697](https://cwe.mitre.org/data/definitions/697.html)

## What it detects

Validators that use the `match` function (or `assets.match`) with a `>=` comparator for Cardano multi-asset `Value` comparison. This pattern only verifies that lovelace is sufficient while silently ignoring changes in native token quantities, creating an exploitable gap in value verification.

## Why it matters

Cardano's `Value` type is a multi-asset container holding lovelace and any number of native tokens. When comparing two `Value` instances, using `match(actual, expected, >=)` checks that `actual` has at least as much lovelace as `expected`, but does not guarantee that native token quantities are equal or sufficient. An attacker can exploit this by reducing native token quantities while keeping lovelace at or above the threshold.

**Real-world impact:** A lending protocol uses `match(output_value, expected_value, >=)` to verify that the pool UTXO's continuing output preserves value. An attacker borrows tokens from the pool, constructs a repayment transaction that adds extra lovelace to compensate for the missing tokens, and the `match` comparison passes. The pool's lovelace is inflated but its actual token reserves are depleted. The protocol becomes insolvent when other users try to redeem tokens that no longer exist in the pool.

This vulnerability was identified in real Cardano DeFi audits and is particularly dangerous because the `match` function *appears* to do the right thing -- developers assume it performs a full structural comparison when it actually only checks one dimension of a multi-dimensional value.

## Example: Vulnerable Code

```aiken
validator lending_pool {
  spend(datum: PoolDatum, redeemer: Action, own_ref: OutputReference, self: Transaction) {
    expect Some(own_input) = transaction.find_input(self.transaction.inputs, own_ref)
    let own_address = own_input.output.address

    let expected_output_value = calculate_expected_value(datum, redeemer)

    expect Some(continuing_output) =
      list.find(self.transaction.outputs, fn(o) { o.address == own_address })

    // VULNERABLE: match with >= only checks lovelace, ignores native asset changes
    expect True == match(continuing_output.value, expected_output_value, >=)

    True
  }
}
```

## Example: Safe Code

```aiken
use cardano/assets.{quantity_of, without_lovelace}

validator lending_pool {
  spend(datum: PoolDatum, redeemer: Action, own_ref: OutputReference, self: Transaction) {
    expect Some(own_input) = transaction.find_input(self.transaction.inputs, own_ref)
    let own_address = own_input.output.address

    let expected_output_value = calculate_expected_value(datum, redeemer)

    expect Some(continuing_output) =
      list.find(self.transaction.outputs, fn(o) { o.address == own_address })

    // SAFE: check lovelace separately
    expect
      value.lovelace_of(continuing_output.value)
        >= value.lovelace_of(expected_output_value)

    // SAFE: verify native tokens exactly (no more, no less)
    expect without_lovelace(continuing_output.value) == without_lovelace(expected_output_value)

    True
  }
}
```

Alternatively, check individual token quantities:

```aiken
    // SAFE: explicit per-asset verification
    expect
      quantity_of(continuing_output.value, pool_token_policy, pool_token_name)
        >= quantity_of(expected_output_value, pool_token_policy, pool_token_name)
    expect
      quantity_of(continuing_output.value, lp_token_policy, lp_token_name)
        == quantity_of(expected_output_value, lp_token_policy, lp_token_name)
```

## Detection Logic

Aikido flags this pattern when:

1. **Handler is in a validator module**.
2. **Function calls include `match`, `assets.match`, or any call ending with `.match`** -- detected via the `function_calls` body signal.
3. **Confidence adjustment:** If the handler also accesses `transaction.outputs` or iterates outputs (via `tx_list_iterations`), the confidence is **likely** (the `match` is being used for output value comparison). Otherwise, confidence is **possible**.

## False Positives

- **Lovelace-only validators:** If the validator only deals with ADA (no native tokens), `match(..., >=)` is equivalent to a simple lovelace comparison and is safe. Suppress with `// aikido:ignore[unsafe-match-comparison]`.
- **Custom `match` functions:** If the codebase defines its own function named `match` that performs full structural comparison, Aikido will incorrectly flag it. Aikido looks for the function name, not its implementation.
- **Match used for non-Value types:** If `match` is used for comparing non-Value types (e.g., custom records), the finding is a false positive.
- **Match with equality operator:** If the code uses `match(actual, expected, ==)` instead of `>=`, the comparison is exact. Aikido currently does not distinguish operators in the `match` call.

## Related Detectors

- [value-not-preserved](value-not-preserved.md) -- The simpler case: value is never checked at all.
- [value-preservation-gap](value-preservation-gap.md) -- Detects the pattern where lovelace is checked but native assets are explicitly not preserved.
- [quantity-of-double-counting](quantity-of-double-counting.md) -- Another token quantity verification issue: counting tokens without isolating inputs from outputs.
