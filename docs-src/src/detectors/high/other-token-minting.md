# other-token-minting

**Severity:** High | **Confidence:** likely | **CWE:** [CWE-20](https://cwe.mitre.org/data/definitions/20.html) -- Improper Input Validation

## What it detects

Finds minting policies that validate their own tokens (using `quantity_of` or similar point checks) but do not restrict other policies from minting tokens in the same transaction. An attacker can piggyback their own minting alongside a legitimate mint operation.

## Why it matters

On Cardano, a single transaction can invoke multiple minting policies. Each minting policy receives the full transaction context but is only required to validate its own logic. If a minting policy checks only that the correct quantity of its own token was minted -- without verifying that **no other tokens** were minted -- an attacker can exploit this gap.

This is known as the "Other Token Name" or "Other Redeemer" vulnerability, documented by MLabs and found in multiple production audits:

- **NFT minting**: A policy verifies that exactly 1 NFT is minted under its policy ID. The attacker includes a second minting policy in the same transaction that mints 1,000,000 counterfeit tokens. The legitimate policy passes because its own token checks out.
- **Governance tokens**: A DAO minting policy checks that tokens are minted proportional to a deposit. The attacker adds a second policy minting arbitrary governance tokens, diluting voting power.
- **Receipt tokens**: A lending protocol mints receipt tokens proportional to deposits. The attacker piggybacks a second mint of receipt tokens via their own policy, creating unbacked receipts that can be redeemed later.

The fundamental issue is that `quantity_of` is a point query: it answers "how many of MY token were minted?" but not "was ANYTHING ELSE also minted?"

## Example: Vulnerable Code

```aiken
use cardano/transaction.{Transaction}
use cardano/value

type MintAction {
  MintToken
  BurnToken
}

validator nft_policy {
  mint(redeemer: MintAction, self: Transaction) {
    let own_policy = self.id

    when redeemer is {
      MintToken -> {
        let minted = value.from_minted_value(self.mint)

        // BUG: Only checks that exactly 1 of OUR token was minted.
        // Doesn't prevent OTHER policies from also minting tokens
        // in the same transaction!
        value.quantity_of(minted, own_policy, "MyNFT") == 1 &&
        list.has(self.extra_signatories, admin_pkh)
      }
      BurnToken -> {
        let minted = value.from_minted_value(self.mint)
        value.quantity_of(minted, own_policy, "MyNFT") == -1
      }
    }
  }
}
```

## Example: Safe Code

```aiken
use cardano/transaction.{Transaction}
use cardano/value

type MintAction {
  MintToken
  BurnToken
}

validator nft_policy {
  mint(redeemer: MintAction, self: Transaction) {
    let own_policy = self.id
    let minted = value.from_minted_value(self.mint)

    when redeemer is {
      MintToken -> {
        // SAFE: Flatten ALL minted tokens and verify the list contains
        // exactly one entry -- our token. No other minting is possible.
        let all_minted = value.flatten(minted)
        expect [(policy, name, qty)] = all_minted

        policy == own_policy &&
        name == "MyNFT" &&
        qty == 1 &&
        list.has(self.extra_signatories, admin_pkh)
      }
      BurnToken -> {
        let all_minted = value.flatten(minted)
        expect [(policy, name, qty)] = all_minted

        policy == own_policy &&
        name == "MyNFT" &&
        qty == -1
      }
    }
  }
}
```

An alternative approach verifies the number of minting policies:

```aiken
// SAFE: Verify only one policy is minting in this transaction
let minted = value.from_minted_value(self.mint)
let policy_count = list.length(value.policies(minted))
expect policy_count == 1

// Now safe to check our specific token
value.quantity_of(minted, own_policy, "MyNFT") == 1
```

## Detection Logic

Aikido flags a handler when **all** of the following are true:

1. The module is a validator and the handler is a `mint` handler.
2. The handler accesses the `mint` field from the transaction context.
3. The handler uses **specific token checks** -- calls containing `quantity_of` or `tokens` -- indicating it validates individual token quantities.
4. The handler does **not** enumerate all minted tokens -- no calls to `flatten`, `policies`, `to_dict`, `to_pairs`, `dict.keys`, `dict.size`, or `list.length`.

The combination of point-query validation (step 3) without enumeration (step 4) indicates that the policy validates its own tokens but is blind to what other policies mint.

## False Positives

Suppress this finding when:

- **Burning only**: The policy exclusively handles burns (negative quantities). Other policies minting alongside a burn is typically not a concern.
- **Protocol-level coordination**: A separate spend validator in the same transaction already verifies the complete mint field. The minting policy delegates enumeration to the spend handler.
- **Intentional multi-mint**: The protocol is explicitly designed to allow multiple policies to mint in the same transaction (e.g., a batch minting orchestrator).

```aiken
// aikido:ignore[other-token-minting] -- spend handler verifies complete mint field
```

## Related Detectors

- [missing-minting-policy-check](../critical/missing-minting-policy-check.md) -- Mint handler that does not validate token names at all.
- [unrestricted-minting](../critical/unrestricted-minting.md) -- Minting policy with no authorization check whatsoever.
- [token-name-not-validated](token-name-not-validated.md) -- Mint policy checks authorization but not which token names are minted.
