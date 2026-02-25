# duplicate-asset-name-risk

**Severity:** Medium | **Confidence:** possible | **CWE:** [CWE-682](https://cwe.mitre.org/data/definitions/682.html)

## What it detects

Identifies minting policies that use `quantity_of` to check minted token quantities but do not destructure the full mint value (via `flatten`, `to_pairs`, or `to_dict`), which could allow minting more tokens than intended.

## Why it matters

A minting policy that only checks `quantity_of(minted, policy, name) > 0` allows minting any quantity (1, 100, or 1 million tokens). This is critical for:

- **NFT uniqueness**: An NFT policy must ensure exactly 1 token is minted. If `> 0` is checked instead of `== 1`, duplicates can be created.
- **Additional token names**: Without destructuring the full mint value, the attacker can mint additional tokens under the same policy with different names.
- **Supply manipulation**: Fungible tokens minted with unchecked quantities can have their supply inflated.

## Example: Vulnerable Code

```aiken
validator nft_policy {
  mint(_redeemer: Void, self: Transaction) {
    let minted = value.from_minted_value(self.mint)
    // Only checks quantity > 0 -- allows minting 100 copies!
    value.quantity_of(minted, own_policy, token_name) > 0 &&
    list.has(self.extra_signatories, admin)
  }
}
```

## Example: Safe Code

```aiken
validator nft_policy {
  mint(_redeemer: Void, self: Transaction) {
    let minted = value.from_minted_value(self.mint)
    // Destructure to verify EXACTLY one token minted, no extra names
    expect [(_, _, 1)] = value.flatten(minted)
    list.has(self.extra_signatories, admin)
  }
}
```

Or for policies that mint specific named tokens:

```aiken
validator token_policy {
  mint(redeemer: MintAction, self: Transaction) {
    let minted = value.from_minted_value(self.mint)
    let pairs = value.to_pairs(minted)
    // Verify exact quantities for each token name
    expect [(policy, name, qty)] = pairs
    policy == own_policy && name == expected_name && qty == 1
  }
}
```

## Detection Logic

1. Examines mint handlers that access the `mint` transaction field.
2. Checks if the handler uses `quantity_of` (partial quantity check) without also using `flatten`, `to_pairs`, or `to_dict` (full destructuring).
3. Full destructuring allows the handler to verify exact quantities and ensure no extra tokens are minted.
4. Flags handlers that only use `quantity_of` without full value destructuring.

## False Positives

- **Fungible token policies**: For fungible tokens, minting arbitrary quantities may be intentional (controlled by other authorization checks).
- **Quantity equality check**: If `quantity_of` is compared with `==` (exact match) rather than `>`, the quantity is constrained even without destructuring.
- **Multi-step validation**: If the handler checks `quantity_of` for each expected token name individually, covering all cases.

Suppress with:
```aiken
// aikido:ignore[duplicate-asset-name-risk] -- fungible token, quantity controlled by auth check
```

## Related Detectors

- [missing-minting-policy-check](../critical/missing-minting-policy-check.md) -- Mint handler not validating token names
- [unrestricted-minting](../critical/unrestricted-minting.md) -- No authorization on minting
- [other-token-minting](../high/other-token-minting.md) -- Policy allows minting beyond intended scope
