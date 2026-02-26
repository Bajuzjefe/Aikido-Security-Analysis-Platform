# insufficient-staking-control

**Severity:** Medium | **Confidence:** possible | **CWE:** [CWE-863](https://cwe.mitre.org/data/definitions/863.html)

## What it detects

Identifies spend handlers that produce outputs to a script address, verify the payment credential, but do not constrain the staking credential on those outputs.

## Why it matters

On Cardano, every address has two components: a payment credential and an optional staking credential. When a validator sends funds back to its own script address and only checks the payment credential, an attacker can substitute their own staking credential. This redirects all staking rewards from the script's locked value to the attacker's stake key.

For high-TVL protocols, staking rewards on locked ADA can be significant (4-5% annually). An attacker can silently siphon these rewards without ever touching the locked funds.

## Example: Vulnerable Code

```aiken
validator pool {
  spend(datum: PoolDatum, _redeemer: Void, own_ref: OutputReference, self: Transaction) {
    let own_address = get_own_address(self.inputs, own_ref)
    list.any(self.outputs, fn(output) {
      // Only checks payment credential -- staking credential is ignored!
      output.address.payment_credential == own_address.payment_credential &&
      value.lovelace_of(output.value) >= datum.locked_amount
    })
  }
}
```

## Example: Safe Code

```aiken
validator pool {
  spend(datum: PoolDatum, _redeemer: Void, own_ref: OutputReference, self: Transaction) {
    let own_address = get_own_address(self.inputs, own_ref)
    list.any(self.outputs, fn(output) {
      // Checks BOTH payment and staking credentials
      output.address.payment_credential == own_address.payment_credential &&
      output.address.stake_credential == own_address.stake_credential &&
      value.lovelace_of(output.value) >= datum.locked_amount
    })
  }
}
```

## Detection Logic

1. Examines spend handlers that access `outputs` and `address` or `payment_credential` record labels.
2. Flags handlers that never access `stake_credential`.
3. Suppresses the finding if a companion `stake` handler exists on the same validator that checks credentials or `extra_signatories`, since the stake handler can independently protect delegation.

## False Positives

- **Companion stake handler**: If the validator has a dedicated stake handler that controls delegation, staking rewards are already protected. Aikido automatically suppresses this case.
- **Non-continuing outputs**: If outputs are sent to a user's address (not back to the script), staking credential control is the user's responsibility.
- **Intentional staking flexibility**: Some protocols intentionally allow the staking credential to vary (e.g., liquid staking). Suppress with:
  ```aiken
  // aikido:ignore[insufficient-staking-control] -- staking credential intentionally flexible
  ```

## Related Detectors

- [output-address-not-validated](../critical/output-address-not-validated.md) -- Outputs sent to completely unchecked addresses
- [value-not-preserved](../high/value-not-preserved.md) -- Output value not verified
