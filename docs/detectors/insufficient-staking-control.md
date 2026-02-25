# insufficient-staking-control

**Severity:** Medium
**Confidence:** Possible

## Description

When a validator sends outputs to a script address, the staking credential of that address should be constrained. If not, an attacker can redirect staking rewards to their own staking key by providing a script address with their staking credential but the validator's payment credential. This is known as a staking credential hijack.

## Vulnerable Example

```aiken
validator {
  spend(datum, redeemer, own_ref, self) {
    let own_input = transaction.find_input(self.inputs, own_ref)
    let own_credential = own_input.output.address.payment_credential
    // Only checks payment_credential -- attacker can substitute
    // their own staking credential to steal staking rewards
    list.any(self.outputs, fn(o) {
      o.address.payment_credential == own_credential
        && value.lovelace_of(o.value) >= datum.min_value
    })
  }
}
```

The attacker constructs an output address with the validator's payment credential but their own staking credential, redirecting all staking rewards to their wallet.

## Safe Example

```aiken
validator {
  spend(datum, redeemer, own_ref, self) {
    let own_input = transaction.find_input(self.inputs, own_ref)
    let own_address = own_input.output.address
    // Checks BOTH payment and staking credentials
    list.any(self.outputs, fn(o) {
      o.address.payment_credential == own_address.payment_credential
        && o.address.stake_credential == own_address.stake_credential
        && value.lovelace_of(o.value) >= datum.min_value
    })
  }
}
```

## Remediation

1. Verify `output.address.stake_credential` matches the expected staking credential when checking continuing outputs.
2. Alternatively, compare the full `output.address` against the expected address instead of just the payment credential.
3. Consider adding a companion `stake` handler that explicitly controls delegation behavior.

## References

- [CWE-863: Incorrect Authorization](https://cwe.mitre.org/data/definitions/863.html)
