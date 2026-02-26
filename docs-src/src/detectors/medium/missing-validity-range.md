# missing-validity-range

**Severity:** Medium | **Confidence:** likely | **CWE:** [CWE-613](https://cwe.mitre.org/data/definitions/613.html)

## What it detects

Identifies spend handlers that have time-sensitive datum fields (such as `deadline`, `expiry`, `lock_until`, or `valid_until`) but never check `transaction.validity_range`. Also flags handlers that only check the lower bound of the validity range (susceptible to time manipulation).

## Why it matters

Time-sensitive logic in a Cardano validator must be enforced through the transaction's validity range. Without this check, a transaction can be submitted at any time, allowing an attacker to:

- **Claim funds before a deadline expires** by submitting a transaction early
- **Bypass time-locked withdrawals** by ignoring temporal constraints
- **Exploit stale deadlines** on abandoned UTXOs that should have been reclaimed

If only the lower bound is checked (via `get_lower_bound`), an attacker can set it arbitrarily far in the past, manipulating interest accrual, fee computation, or deadline comparisons.

## Example: Vulnerable Code

```aiken
type EscrowDatum {
  beneficiary: VerificationKeyHash,
  deadline: Int,
  amount: Int,
}

validator escrow {
  spend(datum: EscrowDatum, _redeemer: Void, _own_ref: OutputReference, self: Transaction) {
    // Checks beneficiary signature but never checks deadline against time
    list.has(self.extra_signatories, datum.beneficiary)
  }
}
```

The `deadline` field exists in the datum but is never enforced. Anyone with the beneficiary key can claim at any time, defeating the purpose of the deadline.

## Example: Safe Code

```aiken
use cardano/transaction.{ValidityRange}
use aiken/interval

validator escrow {
  spend(datum: EscrowDatum, _redeemer: Void, _own_ref: OutputReference, self: Transaction) {
    // Enforce that the transaction happens after the deadline
    let after_deadline = interval.is_entirely_after(self.validity_range, datum.deadline)
    after_deadline && list.has(self.extra_signatories, datum.beneficiary)
  }
}
```

## Detection Logic

1. Scans all datum type definitions for fields with time-related names (`deadline`, `expiry`, `lock_until`, `valid_until`, `valid_before`, `valid_after`, `expires_at`, `opened_at`, `created_at`) of type `Int`.
2. For each spend handler whose datum type contains time fields, checks whether `validity_range` appears in the handler's transaction field accesses.
3. If `validity_range` is accessed but only `get_lower_bound` is used (without `get_upper_bound`, `is_entirely_before`, or `is_entirely_after`), a separate **high-severity** finding is emitted for lower-bound time manipulation risk.

## False Positives

- **Display-only time fields**: If a datum stores a timestamp for informational purposes (e.g., `created_at` for a record) without temporal enforcement requirements, suppress with:
  ```aiken
  // aikido:ignore[missing-validity-range] -- created_at is metadata only
  ```
- **Time validation in helper modules**: If validity range is checked in a cross-module helper function, Aikido's cross-module analysis should detect it. If not, suppress and document.
- **Field name coincidence**: Fields like `valid_until` on non-temporal types may trigger falsely.

## Related Detectors

- [oracle-freshness-not-checked](oracle-freshness-not-checked.md) -- Oracle data staleness (also time-dependent)
- [missing-datum-field-validation](missing-datum-field-validation.md) -- Datum fields accepted but never validated
