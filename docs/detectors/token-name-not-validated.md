# token-name-not-validated

**Severity:** High
**Confidence:** Likely

## Description

A minting policy that checks authorization (via `extra_signatories` or inputs) but doesn't validate which specific token names are being minted allows an authorized party to mint arbitrary tokens under the policy. The mint handler should validate both authorization AND the specific tokens being minted.

## Vulnerable Example

```aiken
validator {
  mint(redeemer, self) {
    // Checks authorization, but not WHICH tokens are minted
    let admin_key = #"abcd1234..."
    list.has(self.extra_signatories, admin_key)
  }
}
```

An authorized signer can mint tokens with any name and any quantity under this policy. For NFT policies, this means unlimited NFTs with arbitrary names. For fungible tokens, this means uncontrolled inflation of any token name.

## Safe Example

```aiken
validator {
  mint(redeemer, self) {
    let admin_key = #"abcd1234..."
    let minted = value.from_minted_value(self.mint)
    // Validate exactly which token is being minted
    expect [(_, name, qty)] = value.flatten(minted)
    name == "MyToken" && qty == 1
      && list.has(self.extra_signatories, admin_key)
  }
}
```

## Remediation

1. Use `value.from_minted_value(self.mint)` to extract the minted assets
2. Use `value.flatten()` or `value.tokens()` to inspect individual token names and quantities
3. Validate that only the expected token names are present with the expected quantities
4. For NFT policies, ensure `qty == 1` and the name matches the expected value

## References

- [CWE-20: Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)
