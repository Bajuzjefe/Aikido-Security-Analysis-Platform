# missing-validity-range

**Severity:** Medium
**Confidence:** Likely

## Description

Detects validators with time-related datum fields (deadline, expiry, etc.) that never check `validity_range`. Without validity range checks, time-sensitive logic like deadlines cannot be enforced on-chain.

## Vulnerable Example

```aiken
type Datum {
  deadline: Int,
  owner: ByteArray,
}

validator {
  spend(datum, _redeemer, _own_ref, self) {
    // Has a deadline field but never checks validity_range!
    list.has(self.extra_signatories, datum.owner)
  }
}
```

## Safe Example

```aiken
validator {
  spend(datum, _redeemer, _own_ref, self) {
    let valid = interval.is_entirely_before(self.validity_range, datum.deadline)
    valid && list.has(self.extra_signatories, datum.owner)
  }
}
```

## Remediation

1. Access `self.validity_range` to enforce time constraints
2. Use `interval.is_entirely_before` or `interval.is_entirely_after` for deadline checks

## References

- [MLabs: Time-related vulnerabilities](https://library.mlabs.city/common-plutus-security-vulnerabilities)
