# rounding-error-risk

**Severity:** Medium | **Confidence:** possible | **CWE:** [CWE-682](https://cwe.mitre.org/data/definitions/682.html)

## What it detects

Identifies validator handlers that contain both integer division and integer multiplication operations, which creates a risk of precision loss due to truncation order.

## Why it matters

Aiken uses arbitrary-precision integers with truncating division (rounds toward zero). When a handler performs both division and multiplication, the order of operations critically affects precision:

- `(a / b) * c` -- **loses precision**: division truncates first, then multiplication amplifies the error.
- `(a * c) / b` -- **preserves precision**: multiplication preserves the full value before the single truncation.

In DeFi protocols, even small rounding errors compound across many transactions:

- **DEX swap rates**: A 1-lovelace rounding error per swap can be exploited thousands of times.
- **LP token calculations**: Incorrect share calculations let attackers extract more value than deposited.
- **Interest accrual**: Rounding errors in interest calculations benefit either borrowers or lenders unfairly.
- **Fee extraction**: An attacker can structure transactions to consistently round fees in their favor.

## Example: Vulnerable Code

```aiken
validator liquidity_pool {
  spend(datum: PoolDatum, redeemer: SwapRedeemer, _ref: OutputReference, self: Transaction) {
    // Division first -- precision lost!
    let price_per_unit = datum.reserve_b / datum.reserve_a
    let output_amount = price_per_unit * redeemer.input_amount

    // If reserve_b=1000, reserve_a=3: price=333 instead of 333.33...
    // For input_amount=3: output=999 instead of 1000
    expect output_amount >= redeemer.min_output
  }
}
```

## Example: Safe Code

```aiken
validator liquidity_pool {
  spend(datum: PoolDatum, redeemer: SwapRedeemer, _ref: OutputReference, self: Transaction) {
    // Multiply first, divide last -- preserves precision
    let output_amount = datum.reserve_b * redeemer.input_amount / datum.reserve_a

    // For same values: (1000 * 3) / 3 = 1000 -- exact!
    expect output_amount >= redeemer.min_output
  }
}
```

For complex formulas, use a common denominator approach:

```aiken
// Instead of: fee_rate / 100 * amount
// Use: amount * fee_rate / 100
let fee = amount * fee_rate / fee_denominator
```

## Detection Logic

1. Checks handler body signals for `has_division` and `has_multiplication` flags.
2. If both are present, emits a finding advising review of operation ordering.
3. Only checks validator handlers (not library functions).

## False Positives

- **Correct ordering**: If the handler already multiplies before dividing, the finding is a false positive. Aikido does not yet track operation order.
- **Non-financial arithmetic**: Division and multiplication used for non-financial logic (e.g., computing a list index) where rounding is acceptable.
- **Constant denominators**: Division by known constants (e.g., `/ 100` for percentages) where precision loss is negligible.

Suppress with:
```aiken
// aikido:ignore[rounding-error-risk] -- multiply-first ordering verified
```

## Related Detectors

- [division-by-zero-risk](../high/division-by-zero-risk.md) -- Division with attacker-controlled denominator
- [integer-underflow-risk](../high/integer-underflow-risk.md) -- Subtraction on redeemer-controlled values
- [unsafe-redeemer-arithmetic](../high/unsafe-redeemer-arithmetic.md) -- Arithmetic on redeemer-tainted values
