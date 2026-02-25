# token-name-not-validated

**Severity:** High | **Confidence:** likely | **CWE:** [CWE-20](https://cwe.mitre.org/data/definitions/20.html)

## What it detects

Minting policies that check authorization (signatories or input consumption) and access the `mint` field, but do not validate which specific token names are being minted. The handler knows *something* is being minted and verifies *who* is minting, but does not constrain *what* tokens are produced.

## Why it matters

A minting policy's primary responsibility is controlling which tokens can exist under its policy ID. Even with proper authorization, failing to validate token names allows an authorized party (or an attacker who compromises the auth mechanism) to mint tokens with arbitrary names. This can create confusion, enable spoofing attacks, or break protocol assumptions.

**Real-world impact:** A DeFi protocol uses a minting policy for its liquidity pool tokens. The policy checks the admin signature and verifies the mint field is non-empty, but never checks the specific token name. An authorized admin (or a compromised admin key) mints tokens named "GovernanceToken" under the LP token policy ID. These fake governance tokens are indistinguishable on-chain from real ones. The attacker uses them to vote on governance proposals, redirecting the protocol treasury to their own address.

This is distinct from `unrestricted-minting` (no auth at all) and `missing-minting-policy-check` (no mint field access). This detector catches the subtle middle ground: partial validation that creates a false sense of security.

## Example: Vulnerable Code

```aiken
validator pool_token_policy(pool_hash: ByteArray) {
  mint(_redeemer: Data, self: Transaction) {
    // Checks authorization
    let pool_input_consumed =
      list.any(
        self.transaction.inputs,
        fn(input) {
          when input.output.address.payment_credential is {
            ScriptCredential(hash) -> hash == pool_hash
            _ -> False
          }
        },
      )

    // Accesses mint field but only checks it's non-empty
    let something_minted = self.transaction.mint != assets.zero()

    // VULNERABLE: what token names are being minted? Completely unchecked!
    pool_input_consumed && something_minted
  }
}
```

## Example: Safe Code

```aiken
use cardano/assets.{tokens, quantity_of}

validator pool_token_policy(pool_hash: ByteArray) {
  mint(redeemer: MintAction, self: Transaction) {
    let pool_input_consumed =
      list.any(
        self.transaction.inputs,
        fn(input) {
          when input.output.address.payment_credential is {
            ScriptCredential(hash) -> hash == pool_hash
            _ -> False
          }
        },
      )

    expect pool_input_consumed

    // SAFE: validate the specific token name and quantity
    let own_minted = tokens(self.transaction.mint, self.policy_id)
    expect dict.size(own_minted) == 1

    let expected_name = redeemer.pool_token_name
    expect quantity_of(self.transaction.mint, self.policy_id, expected_name) == redeemer.quantity
    expect redeemer.quantity > 0

    True
  }
}
```

## Detection Logic

Aikido flags this pattern when all of the following are true:

1. **Handler type is `mint`**.
2. **Handler has authorization checks** -- accesses `extra_signatories` or `inputs` (distinguishing from `unrestricted-minting`).
3. **Handler accesses the `mint` field** (distinguishing from `missing-minting-policy-check`).
4. **Handler does not validate specific token names** -- no function calls containing `flatten`, `tokens`, `from_minted_value`, or `quantity_of`, and no record label accesses for `asset_name` or `token_name`.

The confidence is **likely** because the handler may use alternative validation patterns that Aikido does not recognize.

## False Positives

- **Custom validation functions:** If token name validation is done through a project-specific helper function (e.g., `validate_mint_output(...)`) that internally calls `tokens()` or `quantity_of()`, Aikido may not trace through it. Suppress with `// aikido:ignore[token-name-not-validated]`.
- **Pattern destructuring:** Aiken's pattern matching (e.g., `expect [(_, name, qty)] = ...`) validates token names implicitly through the structure. Aikido looks for this pattern but may miss complex destructuring.
- **Single-use policies:** If the policy is designed to be used exactly once (e.g., a one-shot NFT mint), token name validation may be less critical because the policy cannot be reused.

## Related Detectors

- [missing-minting-policy-check](../critical/missing-minting-policy-check.md) -- The more severe case where the mint field is never even accessed.
- [unrestricted-minting](../critical/unrestricted-minting.md) -- The most severe case: no authorization checks at all.
- [other-token-minting](other-token-minting.md) -- Detects when a policy allows minting beyond its intended scope, a related concern.
- [duplicate-asset-name-risk](../medium/duplicate-asset-name-risk.md) -- Minting without unique asset name enforcement.
