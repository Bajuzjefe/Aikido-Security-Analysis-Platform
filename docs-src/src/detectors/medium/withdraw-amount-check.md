# withdraw-amount-check

**Severity:** Medium | **Confidence:** possible | **CWE:** [CWE-345](https://cwe.mitre.org/data/definitions/345.html)

## What it detects

Withdrawal authorization that only checks for the existence of a withdrawal entry (via `has_key`) without verifying the withdrawal amount. The Cardano ledger allows any staking script to be invoked with a 0-amount withdrawal, making existence-only checks ineffective as authorization.

## Why it matters

The withdraw-zero pattern is a common delegation technique where a spend handler delegates its validation by checking that a specific staking script was invoked. If the handler only checks `has_key(self.withdrawals, credential)` without verifying the amount, the check is trivially satisfied by a zero-amount withdrawal, providing no security guarantee.

**Real-world impact:** A validator uses `dict.has_key(self.withdrawals, stake_cred)` to verify that the staking script approved the transaction. An attacker includes a zero-amount withdrawal for the staking credential. The Cardano ledger allows this regardless of the staking script's logic, bypassing the intended authorization.

## Example: Vulnerable Code

```aiken
validator pool {
  spend(_datum: Data, _redeemer: Data, _own_ref: OutputReference, self: Transaction) {
    // VULNERABLE: only checks existence, not amount
    dict.has_key(self.withdrawals, Inline(ScriptCredential(staking_hash)))
  }
}
```

## Example: Safe Code

```aiken
validator pool {
  spend(_datum: Data, _redeemer: Data, _own_ref: OutputReference, self: Transaction) {
    // SAFE: verify the withdrawal amount is non-zero
    when dict.get(self.withdrawals, Inline(ScriptCredential(staking_hash))) is {
      Some(amount) -> amount > 0
      None -> False
    }
  }
}
```

## Detection Logic

Aikido flags this pattern when:

1. **`dict.has_key` is called on `self.withdrawals`** or an equivalent existence check.
2. **The withdrawal amount is never compared** - no `> 0`, `== expected`, or other amount validation.
3. **The check appears to serve as authorization** for a spend handler.

## False Positives

- **Non-zero enforced by staking script:** If the staking script itself rejects zero-amount withdrawals, the spend handler's existence check may be sufficient. However, relying on external enforcement is fragile.
- **Withdrawal used only for routing:** If the withdrawal is used to pass data (via redeemer) rather than for authorization, the amount is irrelevant.

## Related Detectors

- [withdraw-zero-trick](../high/withdraw-zero-trick.md) - Detects the withdraw-zero pattern itself.
- [cross-validator-gap](../high/cross-validator-gap.md) - Detects gaps in delegated validation.
- [missing-signature-check](../high/missing-signature-check.md) - Alternative authorization mechanism.
