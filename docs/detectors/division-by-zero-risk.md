# division-by-zero-risk

**Severity:** High
**Confidence:** Possible

## Description

Division by zero in Plutus causes the validator to fail, which could be exploited to deny legitimate transactions. When the denominator comes from redeemer or datum input (attacker-controlled data), there is a risk of intentional division by zero causing a denial-of-service condition.

## Vulnerable Example

```aiken
validator {
  spend(datum, redeemer, own_ref, self) {
    let total_value = value.lovelace_of(get_own_input(self, own_ref).value)
    // redeemer.shares could be 0, causing the validator to crash!
    let payout = total_value / redeemer.shares
    check_output_value(self.outputs, payout)
  }
}
```

If an attacker submits a redeemer with `shares = 0`, the division crashes the validator, preventing the transaction from succeeding. This can be used to grief other users or lock funds.

## Safe Example

```aiken
validator {
  spend(datum, redeemer, own_ref, self) {
    let total_value = value.lovelace_of(get_own_input(self, own_ref).value)
    // Guard against zero before dividing
    expect redeemer.shares > 0
    let payout = total_value / redeemer.shares
    check_output_value(self.outputs, payout)
  }
}
```

## Remediation

1. Guard every division and modulo operation with `expect denominator > 0` before performing the operation.
2. If the denominator comes from datum or redeemer input, treat it as untrusted and validate it explicitly.
3. Consider using safe division helpers that return an `Option` type instead of crashing.

## References

- [CWE-369: Divide By Zero](https://cwe.mitre.org/data/definitions/369.html)
