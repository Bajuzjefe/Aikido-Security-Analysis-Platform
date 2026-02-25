# withdraw-zero-trick

**Severity:** High | **Confidence:** likely | **CWE:** [CWE-345](https://cwe.mitre.org/data/definitions/345.html) -- Insufficient Verification of Data Authenticity

## What it detects

Finds validators that use withdrawal-based authorization but only check whether a withdrawal **exists** in the transaction, without verifying the withdrawal **amount**. On Cardano, anyone can include a zero-ADA withdrawal from any staking script address, meaning a simple existence check provides no real authorization.

## Why it matters

The "withdraw zero trick" is a well-known Cardano attack vector. The pattern arises from a popular design where a spend or mint validator delegates authorization to a staking validator by checking for a withdrawal from that staking script in the transaction. The idea is that only the staking script's owner can withdraw from it, so the presence of a withdrawal proves authorization.

However, Cardano allows **zero-amount withdrawals** from any staking script. This means:

- **Unauthorized spending**: An attacker includes a `0 ADA` withdrawal from the staking script in their transaction. The spend validator sees the withdrawal exists and approves the spend. The staking validator runs but receives `0`, which may pass trivially. The attacker drains the UTXO.
- **Free minting**: A mint policy checks for a withdrawal from a governance staking script. The attacker adds a zero withdrawal, bypassing governance entirely.
- **Staking validator bypass**: A withdraw handler itself does not check the amount, so it succeeds on zero-amount withdrawals and can be triggered freely.

This attack has been documented in multiple Cardano audit reports and is considered a standard part of the Cardano threat model.

## Example: Vulnerable Code

```aiken
use cardano/transaction.{Transaction, OutputReference}
use aiken/primitive/bytearray

type SpendDatum {
  owner_staking_cred: ByteArray,
}

validator guarded_vault {
  spend(
    datum: Option<SpendDatum>,
    _redeemer: Data,
    _own_ref: OutputReference,
    self: Transaction,
  ) {
    expect Some(d) = datum

    // BUG: Only checks that a withdrawal EXISTS for the staking credential.
    // An attacker can include a zero-amount withdrawal to satisfy this check.
    dict.has_key(self.withdrawals, d.owner_staking_cred)
  }
}
```

## Example: Safe Code

```aiken
use cardano/transaction.{Transaction, OutputReference}
use aiken/primitive/bytearray

type SpendDatum {
  owner_staking_cred: ByteArray,
}

validator guarded_vault {
  spend(
    datum: Option<SpendDatum>,
    _redeemer: Data,
    _own_ref: OutputReference,
    self: Transaction,
  ) {
    expect Some(d) = datum

    // SAFE: Retrieve the withdrawal amount and verify it is non-zero.
    // A zero withdrawal can be submitted by anyone and proves nothing.
    expect Some(amount) = dict.get(self.withdrawals, d.owner_staking_cred)
    amount > 0
  }
}
```

For staking validators, ensure the handler itself validates the amount:

```aiken
validator auth_staking {
  withdraw(_redeemer: Data, self: Transaction) {
    // SAFE: Verify withdrawal amount is meaningful
    expect Some(amount) = dict.get(self.withdrawals, own_credential)
    amount > 0 &&
    // ... additional authorization logic
    list.has(self.extra_signatories, owner_pkh)
  }
}
```

## Detection Logic

Aikido flags a handler when **all** of the following are true:

1. The module is a validator.
2. The handler accesses the `withdrawals` field from the transaction context.
3. The handler does **not** use patterns that retrieve the withdrawal amount:
   - No `dict.get` (which returns the amount as `Option<Int>`)
   - No `dict.foldl`, `dict.foldr`, `dict.values`, `dict.to_pairs` (which iterate over amounts)
   - No `lovelace_of` or `from_lovelace` calls
   - No arithmetic operations (division, subtraction, multiplication) that would process the amount

The combination of withdrawal access without amount retrieval strongly indicates an existence-only check (e.g., `dict.has_key`, `dict.keys`).

For `withdraw` handlers, the confidence is set to `likely` since the handler itself should verify its own withdrawal amount. For `spend` and `mint` handlers, the confidence is also `likely` since withdrawal-based auth without amount verification is a documented exploit pattern.

## False Positives

Suppress this finding when:

- **Zero withdrawal is intentional**: The protocol design explicitly uses zero withdrawals as a signaling mechanism and the staking validator has its own independent authorization (e.g., checking `extra_signatories`).
- **Amount checked in a helper function**: The withdrawal amount is validated in a separate module function that Aikido cannot trace.
- **Staking validator enforces amount**: The corresponding staking validator (not the spend validator) enforces `amount > 0`, making the zero trick impossible. However, this relies on the staking validator being correct -- defense in depth recommends checking in both places.

```aiken
// aikido:ignore[withdraw-zero-trick] -- staking validator enforces amount > 0
```

## Related Detectors

- [missing-signature-check](missing-signature-check.md) -- Missing authorization via `extra_signatories`.
- [missing-redeemer-validation](missing-redeemer-validation.md) -- Catch-all redeemer that trivially succeeds.
- [missing-utxo-authentication](../critical/missing-utxo-authentication.md) -- Reference inputs used without any authentication.
