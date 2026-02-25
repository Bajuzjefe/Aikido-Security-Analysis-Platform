# missing-token-burn

**Severity:** Medium | **Confidence:** possible | **CWE:** [CWE-754](https://cwe.mitre.org/data/definitions/754.html)

## What it detects

Identifies minting policies that handle token creation but have no code path for burning tokens (negative mint quantities).

## Why it matters

On Cardano, burning tokens requires the minting policy to authorize negative quantities. If a minting policy only handles minting (positive quantities) and has no burn path:

- **Permanent token supply**: Tokens can never be destroyed, which may break protocol mechanics that require burning (e.g., redeeming vouchers, closing positions, settling contracts).
- **Locked collateral**: If burning a token is required to reclaim locked collateral, the collateral becomes permanently locked.
- **State bloat**: Unused tokens accumulate in the UTXO set indefinitely.
- **Design oversight**: Missing burn logic often indicates an incomplete implementation.

## Example: Vulnerable Code

```aiken
type MintAction {
  Mint
  // No Burn variant!
}

validator nft_policy {
  mint(redeemer: MintAction, self: Transaction) {
    when redeemer is {
      Mint -> {
        let minted = value.from_minted_value(self.mint)
        expect [(_, _, 1)] = value.flatten(minted)
        list.has(self.extra_signatories, admin)
      }
    }
  }
}
```

## Example: Safe Code

```aiken
type MintAction {
  Mint
  Burn
}

validator nft_policy {
  mint(redeemer: MintAction, self: Transaction) {
    when redeemer is {
      Mint -> {
        let minted = value.from_minted_value(self.mint)
        expect [(_, _, 1)] = value.flatten(minted)
        list.has(self.extra_signatories, admin)
      }
      Burn -> {
        let minted = value.from_minted_value(self.mint)
        expect [(_, _, qty)] = value.flatten(minted)
        // Quantity must be negative for burning
        qty < 0 && list.has(self.extra_signatories, admin)
      }
    }
  }
}
```

## Detection Logic

1. Examines mint handlers that have meaningful logic (function calls, when branches, or tx field accesses).
2. Searches for burn-related indicators: `when` branch patterns containing "burn", "destroy", or "redeem"; function calls containing "burn", "negate", or "negative"; variable references or record labels containing "burn" or "destroy".
3. Flags mint handlers with logic but no burn-related indicators.
4. Skips empty handlers (caught by `empty-handler-body`).

## False Positives

- **One-shot minting policies**: Policies that are intentionally single-use (e.g., time-locked NFT minting) may not need a burn path if the policy becomes unexecutable after the time lock expires.
- **Burn handled via catch-all**: If burning is handled by a catch-all branch or generic negative-quantity check without burn-specific naming.
- **Separate burn policy**: Some protocols use a different policy for burning than minting.

Suppress with:
```aiken
// aikido:ignore[missing-token-burn] -- one-shot policy, time-locked and expires
```

## Related Detectors

- [missing-burn-verification](../high/missing-burn-verification.md) -- Token burning without proper verification
- [missing-minting-policy-check](../critical/missing-minting-policy-check.md) -- Mint handler not validating token names
- [unrestricted-minting](../critical/unrestricted-minting.md) -- No authorization check on minting
