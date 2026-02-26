# missing-utxo-authentication

**Severity:** Critical
**Confidence:** Likely

## Description

Detects handlers that use `reference_inputs` without authenticating them via signatories or minting policy checks. An attacker can create a UTXO with fake data at any address and include it as a reference input. Without authentication, the validator trusts this attacker-controlled data.

## Vulnerable Example

```aiken
validator {
  spend(datum, redeemer, own_ref, self) {
    let oracle = list.head(self.reference_inputs)
    // Trusts unverified reference data!
    oracle.output.datum.price > datum.min_price
  }
}
```

## Safe Example

```aiken
validator {
  spend(datum, redeemer, own_ref, self) {
    let oracle = list.find(self.reference_inputs, fn(i) {
      // Verify the oracle carries an auth NFT
      value.quantity_of(i.output.value, oracle_policy_id, "") > 0
    })
    expect Some(verified_oracle) = oracle
    verified_oracle.output.datum.price > datum.min_price
  }
}
```

## Remediation

1. Check for an authentication token (NFT) in reference input values
2. Or verify a required signer controls the reference input
3. Never trust reference input data without verification

## References

- [MLabs: UTxO authentication](https://library.mlabs.city/common-plutus-security-vulnerabilities#utxo-authentication)
