# unrestricted-minting

**Severity:** Critical | **Confidence:** definite | **CWE:** [CWE-862](https://cwe.mitre.org/data/definitions/862.html)

## What it detects

Minting policies that contain no authorization check whatsoever. The mint handler does not verify signatories, does not check transaction inputs, does not inspect the mint field, and does not examine reference inputs. In the most extreme case, the handler simply returns `True`.

## Why it matters

An unrestricted minting policy allows anyone to mint unlimited quantities of any token under the policy ID. This means any user on the Cardano network can create tokens that appear to be official protocol tokens, governance tokens, or receipt tokens, destroying the trust model of the entire protocol.

**Real-world impact:** A DeFi protocol deploys a minting policy for its LP (liquidity pool) tokens. During development, the mint handler was a placeholder that always returns `True`. After deployment to mainnet, an attacker discovers this, mints billions of LP tokens, and redeems them against the protocol's reserves, draining every pool. The protocol's TVL goes to zero in a single transaction.

This is not a theoretical attack -- unrestricted minting policies have been found in production Cardano contracts during security audits. Even when caught before exploitation, the fix requires migrating the entire protocol to a new policy ID.

## Example: Vulnerable Code

```aiken
validator lp_token_policy {
  mint(_redeemer: Data, _self: Transaction) {
    // VULNERABLE: no authorization, no validation, anyone can mint
    True
  }
}
```

Another common vulnerable pattern uses parameters but never checks them:

```aiken
validator reward_policy(admin_pkh: ByteArray) {
  mint(_redeemer: Data, _self: Transaction) {
    // VULNERABLE: admin_pkh is a parameter but is never verified
    // The handler ignores all transaction context
    True
  }
}
```

## Example: Safe Code

```aiken
validator lp_token_policy(pool_script_hash: ByteArray) {
  mint(_redeemer: Data, self: Transaction) {
    // SAFE: minting is gated by consuming a UTXO at the pool script
    let pool_input_exists =
      list.any(
        self.transaction.inputs,
        fn(input) {
          when input.output.address.payment_credential is {
            ScriptCredential(hash) -> hash == pool_script_hash
            _ -> False
          }
        },
      )

    // Also validate what is being minted
    expect pool_input_exists

    let minted = self.transaction.mint
    let own_tokens = assets.tokens(minted, self.policy_id)
    dict.size(own_tokens) == 1
  }
}
```

## Detection Logic

Aikido flags this pattern when all of the following are true for a `mint` handler:

1. **No `extra_signatories` access** -- no signature-based authorization.
2. **No `inputs` access** -- no UTXO-consumption-based authorization.
3. **No `mint` access** -- no self-validation of what is being minted.
4. **No `reference_inputs` access** -- no reference-input-based authorization.

When none of these security-relevant transaction fields are accessed, the handler effectively performs no meaningful checks.

**Companion handler awareness:** If a companion `spend` handler exists in the same validator and *does* have authorization checks (signatories or inputs), the confidence is downgraded to **possible** -- this indicates a multi-validator pattern where the spend handler is intended to enforce authorization. However, the finding is still reported because the mint handler alone is unrestricted.

## False Positives

- **Multi-validator coordination:** In the "forwarding mint" pattern, a mint handler intentionally defers all authorization to a companion spend handler in the same validator. The spend handler ensures that minting only happens alongside an authorized spend. Aikido detects this pattern and reduces confidence to **possible**, but the finding is still reported as a warning.
- **One-shot policies with external time locks:** A policy may be unrestricted but deployed with an external time-lock native script wrapper that prevents minting after a certain slot. Aikido analyzes only the Aiken source, not the deployment wrapper.
- **Test / prototype validators:** During development, placeholder mint handlers that return `True` are common. These should be flagged before deployment.

## Related Detectors

- [missing-minting-policy-check](missing-minting-policy-check.md) -- Catches policies that have some authorization but do not validate the mint field. This detector catches the more severe case: no checks at all.
- [token-name-not-validated](../high/token-name-not-validated.md) -- Even with authorization and mint access, the specific token names may not be validated.
- [missing-burn-verification](../high/missing-burn-verification.md) -- Related: a policy that allows unrestricted burning can also cause protocol damage.
