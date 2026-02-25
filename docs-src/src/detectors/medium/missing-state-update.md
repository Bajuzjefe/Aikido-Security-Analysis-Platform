# missing-state-update

**Severity:** Medium | **Confidence:** possible | **CWE:** [CWE-669](https://cwe.mitre.org/data/definitions/669.html)

## What it detects

Identifies spend handlers that read datum fields, produce continuing outputs, but do not appear to construct or verify the output datum -- meaning the continuing UTXO may carry stale state.

## Why it matters

In Cardano state machine patterns, a spend handler consumes a UTXO and recreates it with updated state in the datum. If the handler reads datum fields and sends value back to the script address but does not update the datum:

- **Stale state**: The continuing UTXO carries the old datum, so the state does not reflect the action performed.
- **Replay attacks**: The same state can be "spent" repeatedly since the datum never changes.
- **Accounting errors**: Financial fields (balances, counters) do not update, leading to incorrect protocol state.
- **Double claims**: A user could claim rewards multiple times if the "claimed" flag never gets set.

## Example: Vulnerable Code

```aiken
validator vault {
  spend(datum: VaultDatum, redeemer: DepositAction, own_ref: OutputReference, self: Transaction) {
    let own_address = get_own_address(self.inputs, own_ref)
    let deposit_amount = redeemer.amount

    // Reads datum.balance and produces continuing output
    list.any(self.outputs, fn(output) {
      output.address == own_address &&
      value.lovelace_of(output.value) >= datum.balance + deposit_amount
      // BUT: output datum is never checked! datum.balance stays the same.
    })
  }
}
```

## Example: Safe Code

```aiken
validator vault {
  spend(datum: VaultDatum, redeemer: DepositAction, own_ref: OutputReference, self: Transaction) {
    let own_address = get_own_address(self.inputs, own_ref)
    let deposit_amount = redeemer.amount
    let new_balance = datum.balance + deposit_amount

    // Construct updated datum and verify it in the output
    let expected_datum = VaultDatum { ..datum, balance: new_balance }
    list.any(self.outputs, fn(output) {
      output.address == own_address &&
      value.lovelace_of(output.value) >= new_balance &&
      output.datum == InlineDatum(expected_datum)
    })
  }
}
```

## Detection Logic

1. Checks spend handlers that access datum fields (`datum_field_accesses` is non-empty) and produce outputs (`outputs` in `tx_field_accesses`).
2. Looks for datum update indicators: record labels containing "datum", function calls involving `InlineDatum`, `inline_datum`, `DatumHash`, or `RecordUpdate`, or variable references to `InlineDatum`, `DatumHash`, or `NoDatum`.
3. Flags handlers that read the datum and produce outputs but show no datum construction activity.

## False Positives

- **Terminal spend**: If the handler consumes the UTXO without recreating it (e.g., a "close" action that sends all funds to the owner), there is no continuing output and no datum to update.
- **Datum validated in helper**: If datum construction happens in a cross-module helper function.
- **Unchanged datum**: If the action intentionally does not change the datum (e.g., a "read" action), the existing datum is reused correctly.

Suppress with:
```aiken
// aikido:ignore[missing-state-update] -- terminal spend, no continuing output
```

## Related Detectors

- [datum-tampering-risk](datum-tampering-risk.md) -- Only partial datum validation on continuing outputs
- [state-transition-integrity](../high/state-transition-integrity.md) -- Redeemer actions without datum transition validation
- [arbitrary-datum-in-output](../high/arbitrary-datum-in-output.md) -- Output datum not validated
