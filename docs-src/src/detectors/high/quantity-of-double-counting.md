# quantity-of-double-counting

**Severity:** High | **Confidence:** possible | **CWE:** [CWE-682](https://cwe.mitre.org/data/definitions/682.html) -- Incorrect Calculation

## What it detects

Finds validators that call `quantity_of` multiple times on the same `Value` to check different assets, without verifying that the checks are mutually exclusive. When separate `quantity_of` calls inspect the same underlying value, an attacker can craft a transaction where a single asset satisfies multiple independent checks simultaneously.

## Why it matters

Cardano validators frequently need to verify that a UTXO contains sufficient quantities of multiple tokens. A common but dangerous pattern is to make separate `quantity_of` calls for each required token. If the validator does not confirm that each check targets a distinct asset, an attacker can exploit asset overlap:

- **DEX liquidity checks**: A pool requires 100 TokenA and 100 TokenB. An attacker provides a single asset that the validator counts toward both requirements, depositing far less than expected.
- **Multi-collateral vaults**: A lending protocol checks for collateral in two assets. Overlapping counts let the attacker under-collateralize a position.
- **Reward distribution**: A staking contract checks that a user holds governance tokens AND LP tokens. If both checks hit the same policy ID with manipulated token names, the attacker claims rewards without holding the required tokens.

The root cause is that `quantity_of` is a point query -- it returns the quantity for one specific (policy, name) pair and says nothing about what else is in the value. Multiple point queries on the same value give no guarantee of mutual exclusivity.

## Example: Vulnerable Code

```aiken
use cardano/transaction.{Transaction, OutputReference}
use cardano/value

type PoolDatum {
  min_token_a: Int,
  min_token_b: Int,
  policy: ByteArray,
  token_a_name: ByteArray,
  token_b_name: ByteArray,
}

validator multi_asset_pool {
  spend(
    datum: Option<PoolDatum>,
    _redeemer: Data,
    _own_ref: OutputReference,
    self: Transaction,
  ) {
    expect Some(d) = datum
    let output = list.head(self.outputs)

    // BUG: Two independent quantity_of calls on the same Value.
    // If token_a_name and token_b_name resolve to the same asset,
    // or if the attacker can influence which assets are present,
    // a single deposit satisfies both checks.
    let has_enough_a =
      value.quantity_of(output.value, d.policy, d.token_a_name) >= d.min_token_a
    let has_enough_b =
      value.quantity_of(output.value, d.policy, d.token_b_name) >= d.min_token_b

    has_enough_a && has_enough_b
  }
}
```

## Example: Safe Code

```aiken
use cardano/transaction.{Transaction, OutputReference}
use cardano/value

type PoolDatum {
  min_token_a: Int,
  min_token_b: Int,
  policy: ByteArray,
  token_a_name: ByteArray,
  token_b_name: ByteArray,
}

validator multi_asset_pool {
  spend(
    datum: Option<PoolDatum>,
    _redeemer: Data,
    _own_ref: OutputReference,
    self: Transaction,
  ) {
    expect Some(d) = datum
    let output = list.head(self.outputs)

    // SAFE: Flatten the entire value and verify exact contents.
    // This ensures every asset is accounted for exactly once.
    let assets = value.flatten(value.without_lovelace(output.value))

    // Verify the output contains precisely the expected assets
    expect [(p1, n1, q1), (p2, n2, q2)] = assets
    p1 == d.policy && n1 == d.token_a_name && q1 >= d.min_token_a &&
    p2 == d.policy && n2 == d.token_b_name && q2 >= d.min_token_b
  }
}
```

Alternatively, use `value.tokens` to iterate over all tokens under a policy and check each one individually:

```aiken
// SAFE: Enumerate tokens under the policy and verify each
let token_map = value.tokens(output.value, d.policy)
expect Some(qty_a) = dict.get(token_map, d.token_a_name)
expect Some(qty_b) = dict.get(token_map, d.token_b_name)
qty_a >= d.min_token_a && qty_b >= d.min_token_b
```

## Detection Logic

Aikido flags a handler when **all** of the following are true:

1. The module is a validator (not a library).
2. The handler's body contains **two or more** calls matching `quantity_of`.
3. The handler does **not** also call `tokens`, `policies`, `flatten`, or similar enumeration functions that would indicate whole-value inspection.

The detector operates at the function-call signal level, scanning the handler's extracted `function_calls` set for `quantity_of` occurrences and checking for the presence of safe enumeration patterns.

## False Positives

Suppress this finding when:

- **Token names are compile-time constants**: If both `quantity_of` calls use hardcoded, provably distinct `(policy, name)` pairs that cannot overlap at runtime.
- **Separate source values**: The two `quantity_of` calls operate on different `Value` objects (e.g., one on the input, one on the output) rather than the same value.
- **Upstream validation**: A helper function called earlier in the handler already verifies mutual exclusivity of assets via enumeration.

```aiken
// aikido:ignore[quantity-of-double-counting] -- token names are distinct constants
```

## Related Detectors

- [value-not-preserved](value-not-preserved.md) -- Checks whether output value matches input value at all.
- [value-preservation-gap](value-preservation-gap.md) -- Detects lovelace-only checks that ignore native assets.
- [double-satisfaction](../critical/double-satisfaction.md) -- A related pattern where outputs are not tied to specific inputs.
