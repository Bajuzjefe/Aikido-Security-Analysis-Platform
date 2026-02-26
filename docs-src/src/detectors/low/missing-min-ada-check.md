# missing-min-ada-check

**Severity:** Info | **CWE:** CWE-754 (Improper Check for Unusual or Exceptional Conditions)

## What it detects

Validator handlers that construct outputs (continuing UTXOs) without verifying that those outputs meet the Cardano minimum ADA (lovelace) requirement.

## Why it matters

The Cardano ledger enforces a protocol-level rule: every UTXO must contain a minimum amount of ADA. This minimum is not a fixed value -- it scales with the size of the UTXO's datum, native assets, and reference script. Typical minimums range from approximately 1 to 5 ADA depending on the output's complexity.

If a validator constructs an output that falls below this minimum, the entire transaction will be rejected by the ledger at submission time. This creates several problems:

- **Stuck UTXOs**: If the validator logic computes an output value that does not include enough ADA, the UTXO at the script address becomes unspendable because no valid transaction can be constructed from it.
- **Failed user transactions**: Users who interact with the contract will see their transactions fail with a cryptic "minimum UTXO value not met" error, degrading the user experience.
- **Native token lockup**: When outputs carry only native tokens without sufficient ADA, those tokens can become permanently locked.

This is an informational finding because the ledger itself prevents the invalid transaction from going on-chain, so funds are not at direct risk. However, it can cause significant operational issues.

## Example: Flagged Code

```aiken
validator token_vault {
  spend(datum: Option<VaultDatum>, _redeemer: VaultRedeemer, own_ref: OutputReference, self: Transaction) {
    expect Some(d) = datum
    let own_input = utils.find_input(self.inputs, own_ref)
    let script_address = own_input.output.address

    // Construct output with only the protocol token -- no ADA!
    let expected_output =
      Output {
        address: script_address,
        value: value.from_asset(d.policy_id, d.asset_name, 1),
        datum: InlineDatum(d),
        reference_script: None,
      }

    list.has(self.outputs, expected_output)
  }
}
```

## Example: Improved Code

```aiken
validator token_vault {
  spend(datum: Option<VaultDatum>, _redeemer: VaultRedeemer, own_ref: OutputReference, self: Transaction) {
    expect Some(d) = datum
    let own_input = utils.find_input(self.inputs, own_ref)
    let script_address = own_input.output.address

    // Include minimum ADA alongside the protocol token
    let expected_value =
      value.from_lovelace(2_000_000)
        |> value.add(d.policy_id, d.asset_name, 1)

    let expected_output =
      Output {
        address: script_address,
        value: expected_value,
        datum: InlineDatum(d),
        reference_script: None,
      }

    list.has(self.outputs, expected_output)
  }
}
```

Alternatively, verify the output meets a minimum ADA threshold:

```aiken
// Check that the continuing output carries sufficient ADA
let output_ada = value.lovelace_of(continuing_output.value)
expect output_ada >= min_ada_required
```

## Detection Logic

Aikido identifies this pattern through the following steps:

1. **Scope**: Examines all handlers in validator modules.
2. **Output construction check**: Verifies the handler accesses `transaction.outputs` AND uses both `address` and `value`/`lovelace` record labels, indicating output construction or validation.
3. **ADA check scan**: Searches for evidence of ADA/lovelace handling in three places:
   - **Function calls**: `lovelace_of`, `from_lovelace`, `ada_lovelace`, `min_ada`, `min_lovelace`, `minimum_ada`, `value_geq`, `value_greater`, `merge`, `from_asset`.
   - **Record labels**: Any label containing `lovelace`, `ada`, or `min_value` (case-insensitive).
   - **Variable references**: Any variable containing `min_ada`, `min_lovelace`, or `minimum` (case-insensitive).
4. **Confidence**: Rated as `possible` because the heuristic-based approach may miss some ADA checks performed through indirect means.

## False Positives

This detector may produce false positives when:

- The minimum ADA is ensured through `value.merge` with the input value, preserving the input's ADA. The detector recognizes `merge` as an ADA-related operation in v0.2.0+, but older versions may miss it.
- The ADA amount is computed in a separate helper module and passed as a variable whose name does not contain recognizable ADA-related terms.
- The validator deliberately does not constrain the exact output value (e.g., it only checks that the output goes to the right address) and relies on the off-chain transaction builder to include sufficient ADA.
- The validator uses `from_asset` to build a value that is later merged with lovelace in a way the detector cannot trace.

Suppress with:

```aiken
// aikido:ignore[missing-min-ada-check] -- ADA preserved via value.merge with input
```

## Related Detectors

- [value-not-preserved](../high/value-not-preserved.md) -- Output value not verified against input value
- [value-preservation-gap](../high/value-preservation-gap.md) -- Lovelace checked but native assets not preserved
- [reference-script-injection](reference-script-injection.md) -- Unconstrained reference_script inflates minimum ADA
