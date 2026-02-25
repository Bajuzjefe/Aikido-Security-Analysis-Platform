# identity-token-forgery

**Severity:** High | **Confidence:** possible | **CWE:** [CWE-290](https://cwe.mitre.org/data/definitions/290.html)

## What it detects

Tokens used for identity or authorization (checked via `quantity_of` on inputs) without verifying the minting policy. Without a policy check, an attacker can mint a token with the same name under a different policy and pass the identity check.

## Why it matters

On Cardano, a token is uniquely identified by its policy ID and asset name. Checking only the asset name (e.g., "admin_token") without verifying the policy ID means any token with that name satisfies the check, regardless of who minted it.

**Real-world impact:** A treasury validator checks for an "admin" token in the transaction inputs using `quantity_of(input.value, any_policy, "admin") > 0`. An attacker mints their own "admin" token under a policy they control, includes it in the transaction, and gains full admin access to the treasury.

## Example: Vulnerable Code

```aiken
validator treasury {
  spend(datum: TreasuryDatum, _redeemer: Data, _own_ref: OutputReference, self: Transaction) {
    // VULNERABLE: checks token name but not policy
    let has_admin_token =
      list.any(self.inputs, fn(input) {
        value.quantity_of(input.output.value, some_policy, "admin") > 0
      })

    has_admin_token
  }
}
```

## Example: Safe Code

```aiken
validator treasury {
  spend(datum: TreasuryDatum, _redeemer: Data, _own_ref: OutputReference, self: Transaction) {
    // SAFE: checks specific policy ID
    let has_admin_token =
      list.any(self.inputs, fn(input) {
        value.quantity_of(input.output.value, datum.admin_policy_id, "admin") > 0
      })

    // ALSO verify the policy cannot be freely minted
    let no_extra_minting =
      value.quantity_of(value.from_minted_value(self.mint), datum.admin_policy_id, "admin") == 0

    has_admin_token && no_extra_minting
  }
}
```

## Detection Logic

Aikido flags this pattern when:

1. **`quantity_of` is called on transaction inputs** to check for a token.
2. **The minting policy is not verified** elsewhere in the handler (no `self.mint` check for the same policy).
3. **The token appears to serve an authorization role** based on naming patterns or usage context.

## False Positives

- **Hardcoded trusted policy:** If the policy ID is a compile-time constant known to be secure, the check may be sufficient. The detector may still flag if it cannot resolve the constant.
- **One-shot minting policies:** If the token was minted under a one-shot policy (UTXO-locked), forgery is impossible. Suppress with `// aikido:ignore[identity-token-forgery]`.

## Related Detectors

- [missing-minting-policy-check](../critical/missing-minting-policy-check.md) - Broader: detects any minting without policy verification.
- [token-name-not-validated](token-name-not-validated.md) - Complementary: token name should also be checked.
- [missing-burn-verification](missing-burn-verification.md) - Identity tokens should be burned when no longer needed.
