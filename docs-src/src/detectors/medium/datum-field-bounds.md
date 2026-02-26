# datum-field-bounds

**Severity:** Medium | **Confidence:** possible | **CWE:** [CWE-129](https://cwe.mitre.org/data/definitions/129.html)

## What it detects

Datum fields in continuing outputs that are accepted without bounds validation. When a validator produces an output with a datum containing numeric fields (leverage, amount, price, rate) without validating their range, an attacker can set extreme values that break invariants on subsequent interactions.

## Why it matters

Output datums define the contract state for future interactions. If a handler writes a datum with unchecked numeric fields, an attacker can inject values like 0, negative numbers, or extremely large integers that cause division by zero, integer overflow, or logic violations in subsequent transactions.

**Real-world impact:** A lending protocol accepts a new loan with `datum.leverage` written from the redeemer without bounds checking. An attacker creates a loan with `leverage = 0`, which causes a division-by-zero crash when another user tries to liquidate it, effectively making the loan immune to liquidation.

## Example: Vulnerable Code

```aiken
validator lending {
  spend(datum: LoanDatum, redeemer: CreateLoan, own_ref: OutputReference, self: Transaction) {
    // VULNERABLE: writes redeemer values to output datum without bounds
    let new_datum = LoanDatum {
      borrower: redeemer.borrower,
      collateral_ratio: redeemer.collateral_ratio,  // could be 0
      interest_rate: redeemer.interest_rate,          // could be negative
      amount: redeemer.amount,
    }

    list.any(self.outputs, fn(o) {
      o.address == script_address && o.datum == InlineDatum(new_datum)
    })
  }
}
```

## Example: Safe Code

```aiken
validator lending {
  spend(datum: LoanDatum, redeemer: CreateLoan, own_ref: OutputReference, self: Transaction) {
    // SAFE: validate all numeric fields
    expect redeemer.collateral_ratio >= 150  // minimum 150%
    expect redeemer.collateral_ratio <= 1000 // maximum 1000%
    expect redeemer.interest_rate > 0
    expect redeemer.interest_rate <= 5000    // max 50% APR in basis points
    expect redeemer.amount > 0

    let new_datum = LoanDatum {
      borrower: redeemer.borrower,
      collateral_ratio: redeemer.collateral_ratio,
      interest_rate: redeemer.interest_rate,
      amount: redeemer.amount,
    }

    list.any(self.outputs, fn(o) {
      o.address == script_address && o.datum == InlineDatum(new_datum)
    })
  }
}
```

## Detection Logic

Aikido flags this pattern when:

1. **A handler produces a continuing output with a datum** containing numeric fields.
2. **Datum field values come from the redeemer** (attacker-controlled).
3. **No bounds validation** (`> 0`, `<= max`, range checks) is performed on the fields before they are written to the output datum.

## False Positives

- **Bounded by type:** If the field type inherently constrains the range (e.g., a small enum), bounds checks may be unnecessary.
- **Validation in datum constructor:** If bounds checking happens in a separate validation function called before datum construction, Aikido may miss the connection.

## Related Detectors

- [missing-datum-field-validation](missing-datum-field-validation.md) - Broader datum field validation issues.
- [precise-taint-to-sink](../high/precise-taint-to-sink.md) - Taint from redeemer to sensitive operations.
- [unsafe-redeemer-arithmetic](../high/unsafe-redeemer-arithmetic.md) - Redeemer values used in arithmetic without validation.
