# missing-minting-policy-check

**Severity:** Critical
**Confidence:** Definite

## Description

Detects mint handlers that don't access the transaction's `mint` field. Without checking what tokens are being minted, an attacker can mint arbitrary token names under the policy, potentially creating counterfeit tokens.

## Vulnerable Example

```aiken
validator {
  mint(redeemer, self) {
    // Only checks authorization, not WHAT is minted
    list.has(self.extra_signatories, admin_key)
  }
}
```

An attacker who obtains the admin signature can mint unlimited tokens with any name.

## Safe Example

```aiken
validator {
  mint(redeemer, self) {
    let minted = value.from_minted_value(self.mint)
    expect [(_, token_name, qty)] = value.flatten(minted)
    token_name == expected_name && qty == 1
    && list.has(self.extra_signatories, admin_key)
  }
}
```

## Remediation

1. Always access `self.mint` in mint handlers
2. Validate token names and quantities
3. Ensure only expected tokens can be minted

## References

- [MLabs: Minting policy validation](https://library.mlabs.city/common-plutus-security-vulnerabilities)
