# reference-script-injection

**Severity:** Low | **CWE:** CWE-20 (Improper Input Validation)

## What it detects

Spend handlers that produce continuing outputs without constraining the `reference_script` field on those outputs. When this field is left unchecked, an attacker can attach an arbitrarily large reference script to the UTXO.

## Why it matters

Every Cardano UTXO has a minimum ADA requirement that scales with the size of its data, including any attached reference script. If an attacker can inject a large reference script into a continuing output, the minimum ADA locked in that UTXO increases dramatically. This can create a denial-of-service condition where the UTXO becomes economically unviable to spend, or it can drain ADA from the contract by forcing higher deposits than expected.

The attack is subtle because `reference_script` is an optional field on `Output` that many developers simply forget to constrain. The Cardano ledger does not prevent attaching a reference script to any UTXO -- that responsibility falls entirely on the validator.

## Example: Flagged Code

```aiken
validator my_protocol {
  spend(datum: Option<MyDatum>, _redeemer: MyRedeemer, own_ref: OutputReference, self: Transaction) {
    expect Some(d) = datum
    let own_input = utils.find_input(self.inputs, own_ref)
    let script_address = own_input.output.address

    // Verify a continuing output exists with correct address and value
    list.any(
      self.outputs,
      fn(output) {
        output.address == script_address &&
        output.value == expected_value(d) &&
        output.datum == InlineDatum(new_datum(d))
        // BUG: reference_script is not constrained!
        // Attacker can attach a huge script here.
      },
    )
  }
}
```

## Example: Improved Code

```aiken
validator my_protocol {
  spend(datum: Option<MyDatum>, _redeemer: MyRedeemer, own_ref: OutputReference, self: Transaction) {
    expect Some(d) = datum
    let own_input = utils.find_input(self.inputs, own_ref)
    let script_address = own_input.output.address

    // Verify continuing output with ALL fields constrained
    list.any(
      self.outputs,
      fn(output) {
        output.address == script_address &&
        output.value == expected_value(d) &&
        output.datum == InlineDatum(new_datum(d)) &&
        output.reference_script == None
      },
    )
  }
}
```

## Detection Logic

Aikido identifies this pattern through the following steps:

1. **Scope**: Only examines `spend` handlers in validator modules. Mint handlers produce new UTXOs, not continuing ones, so they are excluded.
2. **Output construction check**: Verifies the handler accesses `transaction.outputs` AND uses both `address` and `value` (or `lovelace`) record labels, indicating it constructs or validates continuing outputs.
3. **Constraint check**: Scans record labels, function calls, and variable references for any mention of `reference_script`. If none is found, the detector fires.
4. **Confidence**: Rated as `possible` because the handler may delegate the check to a helper function in another module that Aikido cannot trace in all cases.

## False Positives

This detector may produce false positives when:

- The `reference_script` check is performed in a cross-module helper function that the detector cannot trace.
- The protocol intentionally allows reference scripts on its UTXOs (e.g., a reference script registry).
- The handler reads outputs for validation purposes (e.g., counting them) but does not actually produce continuing outputs. The output construction heuristic (address + value labels) usually filters this out, but edge cases exist.

Suppress with:

```aiken
// aikido:ignore[reference-script-injection] -- ref script check in utils.validate_output
```

## Related Detectors

- [missing-datum-in-script-output](../high/missing-datum-in-script-output.md) -- Outputs missing datum attachment
- [arbitrary-datum-in-output](../high/arbitrary-datum-in-output.md) -- Output datum not validated
- [output-address-not-validated](../critical/output-address-not-validated.md) -- Output address not checked
- [insufficient-staking-control](../medium/insufficient-staking-control.md) -- Staking credential not constrained on outputs
