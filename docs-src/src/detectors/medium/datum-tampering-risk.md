# datum-tampering-risk

**Severity:** Medium | **Confidence:** possible | **CWE:** [CWE-20](https://cwe.mitre.org/data/definitions/20.html)

## What it detects

Identifies spend handlers that produce continuing outputs and access some datum fields but not all, leaving unchecked fields vulnerable to modification by an attacker in the output datum.

## Why it matters

When a spend handler creates a continuing output (UTXO sent back to the same script), the output datum should be fully validated. If only a subset of fields is checked:

- **Silent tampering**: An attacker modifies unchecked fields in the output datum (e.g., changing `fee_rate` from 5% to 0%, or `admin` from the protocol owner to themselves).
- **State corruption**: Unchecked fields like `interest_rate`, `collateral_ratio`, or `oracle_address` can be silently replaced.
- **Privilege escalation**: An attacker could replace an `owner` or `admin` field if it is not part of the validation.

The attacker controls the output datum -- the validator must verify every field they care about.

## Example: Vulnerable Code

```aiken
type LoanDatum {
  borrower: VerificationKeyHash,
  amount: Int,
  interest_rate: Int,    // Not validated!
  collateral_ratio: Int, // Not validated!
  oracle_address: Address,  // Not validated!
}

validator lending {
  spend(datum: LoanDatum, _redeemer: Void, own_ref: OutputReference, self: Transaction) {
    // Only checks borrower and amount -- 3 fields are unchecked!
    list.any(self.outputs, fn(output) {
      output.address == get_own_address(self.inputs, own_ref) &&
      expect InlineDatum(new_datum): LoanDatum = output.datum
      new_datum.borrower == datum.borrower &&
      new_datum.amount == datum.amount + deposit
    })
    // Attacker sets interest_rate = 0, collateral_ratio = 0, oracle = fake!
  }
}
```

## Example: Safe Code

```aiken
validator lending {
  spend(datum: LoanDatum, _redeemer: Void, own_ref: OutputReference, self: Transaction) {
    let expected_datum = LoanDatum {
      ..datum,               // Preserve all existing fields
      amount: datum.amount + deposit,  // Only update what changes
    }
    list.any(self.outputs, fn(output) {
      output.address == get_own_address(self.inputs, own_ref) &&
      output.datum == InlineDatum(expected_datum)
    })
  }
}
```

Using `..datum` (record update syntax) ensures all unchanged fields are preserved exactly.

## Detection Logic

1. Examines spend handlers that produce continuing outputs (access `outputs`) and read datum fields.
2. Counts total fields in the datum type definition across all modules.
3. Compares total fields against the number of accessed datum fields.
4. Flags handlers where the datum type has 3+ fields and 2+ fields are unchecked (accessed fewer than `total - 1`).

## False Positives

- **Full datum equality check**: If the handler compares the entire output datum against an expected value (`output.datum == expected`), all fields are implicitly validated.
- **Record update syntax**: Using `MyDatum { ..datum, field: new_value }` preserves all unchanged fields.
- **Terminal spend**: If the handler does not produce continuing outputs (e.g., a "close" action), datum tampering is not a concern.
- **Few fields accessed but all checked in output**: The detector counts field reads, not field writes. If fields are set in the output without being read first, they may still be correctly validated.

Suppress with:
```aiken
// aikido:ignore[datum-tampering-risk] -- full datum equality checked via record update
```

## Related Detectors

- [missing-datum-field-validation](missing-datum-field-validation.md) -- Datum fields never validated at all
- [missing-state-update](missing-state-update.md) -- No datum update in continuing output
- [arbitrary-datum-in-output](../high/arbitrary-datum-in-output.md) -- Output datum not validated
