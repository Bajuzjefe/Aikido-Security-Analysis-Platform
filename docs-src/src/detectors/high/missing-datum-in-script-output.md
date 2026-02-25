# missing-datum-in-script-output

**Severity:** High | **Confidence:** likely | **CWE:** [CWE-404](https://cwe.mitre.org/data/definitions/404.html)

## What it detects

Handlers that iterate transaction outputs (continuing UTXO pattern) without ever checking the `datum` field on those outputs. Sending value to a script address without attaching a datum makes those funds permanently unspendable, because the script will have no datum to validate against when someone tries to spend the UTXO.

## Why it matters

On Cardano, a UTXO at a script address *must* have a datum for the script to process it. If a transaction creates an output at a script address without a datum (or with the wrong datum type), those funds are permanently locked -- no transaction can ever spend them because the validator cannot execute without datum input.

**Real-world impact:** A treasury contract's spend handler validates that a continuing UTXO is created with sufficient value at the script address. But it never checks that the output has a datum. A user submits a legitimate transaction, but due to a frontend bug or transaction builder error, the continuing output is created without a datum. The treasury funds are now permanently locked. Even the admin cannot recover them because no spend transaction can be constructed without a datum for the validator to parse. At $100M+ TVL, this represents catastrophic fund loss.

This is especially insidious because it is often not an *attack* but an *accident* -- a missing datum in the continuing output turns a routine transaction into permanent fund loss.

## Example: Vulnerable Code

```aiken
validator treasury {
  spend(datum: TreasuryDatum, redeemer: Withdrawal, own_ref: OutputReference, self: Transaction) {
    expect Some(own_input) = transaction.find_input(self.transaction.inputs, own_ref)
    let own_address = own_input.output.address

    // VULNERABLE: checks address and value but not datum
    list.any(
      self.transaction.outputs,
      fn(output) {
        output.address == own_address
          && value.lovelace_of(output.value)
            >= value.lovelace_of(own_input.output.value) - redeemer.amount
      },
    )
  }
}
```

## Example: Safe Code

```aiken
validator treasury {
  spend(datum: TreasuryDatum, redeemer: Withdrawal, own_ref: OutputReference, self: Transaction) {
    expect Some(own_input) = transaction.find_input(self.transaction.inputs, own_ref)
    let own_address = own_input.output.address

    // Compute expected continuing datum
    let expected_datum = TreasuryDatum {
      ..datum,
      total_withdrawn: datum.total_withdrawn + redeemer.amount,
    }

    // SAFE: verifies address, value, AND datum
    list.any(
      self.transaction.outputs,
      fn(output) {
        output.address == own_address
          && value.lovelace_of(output.value)
            >= value.lovelace_of(own_input.output.value) - redeemer.amount
          && output.datum == InlineDatum(expected_datum)
      },
    )
  }
}
```

## Detection Logic

Aikido flags this pattern when:

1. **Handler accesses `transaction.outputs`** -- indicating it iterates or inspects outputs.
2. **No datum reference in the handler body:**
   - The `all_record_labels` set does not contain `"datum"`.
   - No variable references or function calls contain `"Datum"`, `"datum"`, `"InlineDatum"`, `"DatumHash"`, or similar datum-related identifiers.

The confidence is **possible** because the handler may check outputs for purposes other than continuing UTXOs (e.g., verifying a fee payment to a wallet address, where datum is not needed).

## False Positives

- **Non-continuing outputs:** If the handler checks outputs only to verify payments to regular wallet addresses (not script addresses), datum is not required. Suppress with `// aikido:ignore[missing-datum-in-script-output]`.
- **Burn-only patterns:** If the handler validates that the UTXO is being consumed without continuation (e.g., closing a position), outputs do not need datum checks.
- **Datum checked in helper functions:** If datum validation is performed in a called function from another module, Aikido may not trace it. Cross-module analysis covers many but not all cases.
- **NoDatum intentional pattern:** Some advanced patterns intentionally create outputs with `NoDatum` at script addresses that accept datum-less UTXOs (e.g., always-succeeding scripts). This is rare and usually a code smell itself.

## Related Detectors

- [arbitrary-datum-in-output](arbitrary-datum-in-output.md) -- The next level up: datum is present but its *content* is not validated, allowing state corruption.
- [unsafe-datum-deconstruction](unsafe-datum-deconstruction.md) -- Receiving side: when the datum is `Option<T>` and the handler does not safely handle `None`.
- [output-address-not-validated](../critical/output-address-not-validated.md) -- Often co-occurs: if the address is not checked, the datum check is also likely missing.
- [value-not-preserved](value-not-preserved.md) -- Another property of continuing outputs that should be verified alongside datum.
