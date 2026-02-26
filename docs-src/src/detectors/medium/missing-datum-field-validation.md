# missing-datum-field-validation

**Severity:** Medium | **Confidence:** possible | **CWE:** [CWE-20](https://cwe.mitre.org/data/definitions/20.html)

## What it detects

Identifies spend handlers where the datum type contains financial or constraint fields (such as `deadline`, `amount`, `price`, `collateral`, `rate`, `threshold`) that are never accessed in the handler body.

## Why it matters

Datum data on Cardano is user-supplied -- anyone can create a UTXO at a script address with arbitrary datum content. If a validator accepts datum fields representing financial constraints but never validates them:

- **Manipulated terms**: An attacker creates a UTXO with `collateral: 0` or `deadline: 9999999999999` to bypass intended constraints.
- **Protocol exploitation**: Unvalidated `price` or `rate` fields allow the attacker to set favorable trading terms.
- **Bypassed limits**: Fields like `max_amount` or `threshold` that are never checked provide no actual protection.

## Example: Vulnerable Code

```aiken
type LoanDatum {
  borrower: VerificationKeyHash,
  collateral: Int,     // Never checked!
  deadline: Int,       // Never checked!
  interest_rate: Int,  // Never checked!
}

validator lending {
  spend(datum: LoanDatum, _redeemer: Void, _ref: OutputReference, self: Transaction) {
    // Only verifies borrower, ignores all financial fields
    list.has(self.extra_signatories, datum.borrower)
  }
}
```

## Example: Safe Code

```aiken
validator lending {
  spend(datum: LoanDatum, redeemer: LoanAction, _ref: OutputReference, self: Transaction) {
    // Validate ALL financial fields
    expect datum.collateral >= min_collateral
    expect datum.deadline > 0

    let current_time = get_upper_bound(self.validity_range)
    expect datum.deadline > current_time

    expect datum.interest_rate >= 0 && datum.interest_rate <= max_rate

    list.has(self.extra_signatories, datum.borrower)
  }
}
```

## Detection Logic

1. For each spend handler, identifies the datum type and looks up its field definitions across all modules.
2. Searches for critical field names: `deadline`, `expiry`, `amount`, `price`, `strike_price`, `premium`, `collateral`, `margin`, `min_amount`, `max_amount`, `target_price`, `rate`, `ratio`, `leverage`, `multiplier`, `quantity`, `threshold`, `limit`.
3. Compares against `datum_field_accesses` in the handler's body signals.
4. Reports fields that exist in the datum type but are never accessed by the handler.

## False Positives

- **Read-only datum fields**: Some fields are set at UTXO creation and consumed by off-chain code rather than the validator.
- **Cross-module validation**: If datum fields are validated in a helper function called from the handler, Aikido may not detect the access if cross-module analysis does not trace it.
- **Informational fields**: Fields like `description` or `name` that are not financial constraints.

Suppress with:
```aiken
// aikido:ignore[missing-datum-field-validation] -- deadline validated in helper module
```

## Related Detectors

- [missing-validity-range](missing-validity-range.md) -- Time fields without validity range check
- [datum-tampering-risk](datum-tampering-risk.md) -- Partial datum validation on continuing outputs
- [arbitrary-datum-in-output](../high/arbitrary-datum-in-output.md) -- Output datum not validated
