# unbounded-value-size

**Severity:** Medium | **Confidence:** possible | **CWE:** [CWE-400](https://cwe.mitre.org/data/definitions/400.html)

## What it detects

Identifies spend handlers that produce continuing outputs and check value (e.g., via `lovelace_of`) but do not constrain the number of native asset policies in the output.

## Why it matters

On Cardano, a UTXO's value can contain any number of native asset policies. An attacker can add many small native assets ("token dust") to a continuing output, which:

- **Bloats the UTXO size**, increasing the minimum ADA required
- **Increases deserialization cost** when the UTXO is later spent
- **Can make the UTXO unspendable** if processing the value exceeds the Plutus execution budget

This attack is cheap -- the attacker only needs to mint worthless tokens under their own policy and include them in the transaction output.

## Example: Vulnerable Code

```aiken
validator vault {
  spend(datum: VaultDatum, _redeemer: Void, own_ref: OutputReference, self: Transaction) {
    let own_address = get_own_address(self.inputs, own_ref)
    list.any(self.outputs, fn(output) {
      output.address == own_address &&
      value.lovelace_of(output.value) >= datum.locked_amount
      // No check on native asset count -- attacker can add token dust!
    })
  }
}
```

## Example: Safe Code

```aiken
use cardano/assets.{policies}

validator vault {
  spend(datum: VaultDatum, _redeemer: Void, own_ref: OutputReference, self: Transaction) {
    let own_address = get_own_address(self.inputs, own_ref)
    list.any(self.outputs, fn(output) {
      output.address == own_address &&
      value.lovelace_of(output.value) >= datum.locked_amount &&
      // Constrain native assets to only the expected policy
      list.length(policies(output.value)) <= 2  // ADA + state token
    })
  }
}
```

Or verify exact value content:

```aiken
let expected_value = value.from_lovelace(datum.locked_amount)
  |> value.add(state_policy, state_name, 1)
value.without_lovelace(output.value) == value.without_lovelace(expected_value)
```

## Detection Logic

1. Checks spend handlers that access `outputs` (continuing output pattern).
2. Verifies the handler checks value (via `lovelace_of`, `value.merge`, etc.).
3. Flags handlers that do not constrain native assets via `policies`, `tokens`, `flatten`, `without_lovelace`, `from_asset`, `quantity_of`, `to_dict`, or `asset_count`.
4. Skips handlers that do not check value at all (covered by `value-not-preserved`).

## False Positives

- **Token-gated protocols**: If the protocol uses `quantity_of` to check a specific token, Aikido considers this sufficient asset constraint and will not flag.
- **No continuing outputs**: If outputs go to user addresses (not back to the script), token dust is the user's problem.
- **Value equality checks**: If the handler uses full value equality (`output.value == expected_value`), this implicitly constrains assets.

## Related Detectors

- [value-not-preserved](../high/value-not-preserved.md) -- Output value not checked at all
- [unbounded-datum-size](unbounded-datum-size.md) -- Unbounded datum fields
- [cheap-spam-vulnerability](cheap-spam-vulnerability.md) -- No minimum deposit requirements
