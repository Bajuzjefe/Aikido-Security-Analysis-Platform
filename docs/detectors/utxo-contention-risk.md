# utxo-contention-risk

**Severity:** Medium
**Confidence:** Possible

## Description

When a validator uses a single shared UTXO (global state) that multiple users must spend and recreate, contention arises: only one transaction can succeed per block. This limits throughput to approximately 1 transaction per 20 seconds and causes most user transactions to fail with "UTxO already spent" errors.

This detector identifies datums that lack user-identifying fields (such as `owner`, `beneficiary`, `credential`, or unique IDs), which suggests a single global state UTXO pattern rather than a per-user UTXO pattern.

## Vulnerable Example

```aiken
type PoolState {
  total_locked: Int,
  reward_rate: Int,
  last_update: Int,
}

validator {
  spend(datum: PoolState, redeemer, own_ref, self) {
    // Every user who interacts with this pool must spend
    // the same single UTXO — only one succeeds per block
    let new_total = datum.total_locked + redeemer.amount
    let output = find_continuing_output(self.outputs, own_ref)
    expect out_datum: PoolState = output.datum
    out_datum.total_locked == new_total
  }
}
```

If 10 users submit transactions in the same block, 9 will fail because they all reference the same UTXO input.

## Safe Example

```aiken
type UserPosition {
  owner: VerificationKeyHash,
  amount_locked: Int,
  lock_until: Int,
}

validator {
  spend(datum: UserPosition, redeemer, own_ref, self) {
    // Each user has their own UTXO at the script address
    // No contention — parallel transactions succeed
    list.has(self.extra_signatories, datum.owner) &&
    check_withdrawal(datum, redeemer, self)
  }
}
```

## Remediation

1. Use a per-user UTXO pattern where each user has their own UTXO at the script address, identified by an `owner` field in the datum
2. If global state is necessary, use a batching/aggregation approach where a batcher combines multiple user requests into a single transaction
3. Consider off-chain state with on-chain settlement for high-throughput use cases
4. Add user-identifying fields (`owner`, `beneficiary`, `credential`) to the datum type

## References

- [CWE-400: Uncontrolled Resource Consumption](https://cwe.mitre.org/data/definitions/400.html)
- [Cardano eUTXO Concurrency Patterns](https://docs.cardano.org/smart-contracts/plutus/concurrency/)
