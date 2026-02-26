# missing-minting-policy-check

**Severity:** Critical | **Confidence:** definite | **CWE:** [CWE-862](https://cwe.mitre.org/data/definitions/862.html)

## What it detects

Mint handlers that never access the `transaction.mint` field. A minting policy that does not inspect what is actually being minted under its own policy ID allows an attacker to mint arbitrary token names and quantities, even if other authorization checks (like signature verification) are in place.

## Why it matters

Every minting policy on Cardano controls a unique policy ID. When a minting transaction executes, the policy's mint handler is invoked -- but the handler must explicitly check the `mint` field to know *what* tokens are being minted. Without this check, authorization alone is meaningless: a valid signer could mint governance tokens, liquidity pool tokens, or any other asset name under the policy.

**Real-world impact:** A DeFi protocol uses an admin-signed minting policy for its pool tokens. The mint handler verifies the admin signature but never checks which tokens are minted. A compromised admin key (or an insider) mints 1 billion governance tokens, diluting all existing holders and seizing protocol control. Alternatively, an attacker could mint tokens with names that collide with other protocol tokens, confusing frontends and users.

## Example: Vulnerable Code

```aiken
validator token_policy {
  mint(_redeemer: Data, self: Transaction) {
    // VULNERABLE: checks authorization but never inspects what is being minted
    let admin_key = #"abcdef0123456789abcdef0123456789abcdef0123456789abcdef01"
    list.has(self.transaction.extra_signatories, admin_key)
  }
}
```

## Example: Safe Code

```aiken
use cardano/assets.{from_asset, quantity_of}
use cardano/transaction.{Transaction}

validator token_policy {
  mint(_redeemer: Data, self: Transaction) {
    let admin_key = #"abcdef0123456789abcdef0123456789abcdef0123456789abcdef01"

    // Verify authorization
    expect list.has(self.transaction.extra_signatories, admin_key)

    // SAFE: validate exactly what is being minted
    let own_policy = self.transaction.mint
    let expected_name = "PoolToken"
    expect quantity_of(own_policy, self.policy_id, expected_name) == 1

    // Ensure nothing else is minted under this policy
    let total_minted = assets.tokens(own_policy, self.policy_id)
    dict.size(total_minted) == 1
  }
}
```

## Detection Logic

Aikido flags this pattern when:

1. **Handler type is `mint`** -- only minting policies are checked.
2. **Handler never accesses the `mint` field** on the transaction -- the `tx_field_accesses` set does not contain `"mint"`.

The confidence is always **definite** because a mint handler that never reads the mint field cannot possibly validate what is being minted.

## False Positives

This detector has a very low false positive rate. Potential cases include:

- **One-shot minting policies with time locks:** If the policy uses a `before` slot constraint so it can only ever be used once (and the slot has passed), the lack of mint field validation is moot. However, best practice is still to validate the mint field.
- **Burn-only invocations:** A policy may be invoked to burn tokens, where the handler intentionally does not check the mint field because it only verifies burn conditions. In practice, even burn handlers should validate the mint field to prevent minting during a burn transaction.

## Related Detectors

- [unrestricted-minting](unrestricted-minting.md) -- Catches policies with no authorization at all (no signatories, no inputs check). This detector is complementary: it catches policies that *have* authorization but skip token validation.
- [token-name-not-validated](../high/token-name-not-validated.md) -- A more nuanced variant: the handler accesses the mint field but does not validate specific token names.
- [other-token-minting](../high/other-token-minting.md) -- Detects when a policy allows minting beyond its intended scope.
