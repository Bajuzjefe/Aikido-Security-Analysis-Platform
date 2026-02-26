# magic-numbers

**Severity:** Info
**Confidence:** Possible

## Description

Numeric literals embedded directly in validator logic without named constants make code harder to understand and maintain. Constants like deadline offsets, fee amounts, or threshold values should be extracted to named constants or validator parameters for clarity and easier auditing.

## Vulnerable Example

```aiken
validator {
  spend(datum, redeemer, own_ref, self) {
    let deadline = datum.created_at + 86400000
    let fee = total_amount * 25 / 10000
    let min_participants = 3
    deadline_ok && fee_ok && participants >= min_participants
  }
}
```

The values `86400000`, `25`, and `10000` are unexplained. An auditor must guess their meaning: is `86400000` milliseconds (1 day)? Is `25 / 10000` a 0.25% fee?

## Safe Example

```aiken
const one_day_ms: Int = 86_400_000

const fee_basis_points: Int = 25

const basis_point_denominator: Int = 10_000

const min_participants: Int = 3

validator {
  spend(datum, redeemer, own_ref, self) {
    let deadline = datum.created_at + one_day_ms
    let fee = total_amount * fee_basis_points / basis_point_denominator
    deadline_ok && fee_ok && participants >= min_participants
  }
}
```

## Remediation

1. Extract numeric literals to named constants at the module level with descriptive names.
2. For values that may change across deployments, use validator parameters instead of constants.
3. Common safe values that do not trigger this detector: `0`, `1`, `2`, `-1`, `True`, `False`, and `1000000` (1 ADA in lovelace).

## References

- [CWE-547: Use of Hard-coded, Security-relevant Constants](https://cwe.mitre.org/data/definitions/547.html)
