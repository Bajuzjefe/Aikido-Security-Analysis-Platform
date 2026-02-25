# output-address-not-validated

**Severity:** Critical | **Confidence:** definite | **CWE:** [CWE-284](https://cwe.mitre.org/data/definitions/284.html)

## What it detects

Handlers that iterate or inspect transaction outputs without validating the destination address (`payment_credential`). When a validator checks outputs for value, datum, or token presence but never verifies *where* those outputs are going, an attacker can redirect funds or minted tokens to an arbitrary address.

## Why it matters

Every Cardano transaction output has an address that determines who can spend it. If a validator only checks that an output contains sufficient value or specific tokens but never verifies the address, the attacker controls where funds go. This is particularly devastating in two scenarios:

1. **Spend handlers with continuing UTXOs:** The validator expects funds to return to the script address, but the attacker sends them to a personal wallet.
2. **Mint handlers with token distribution:** The validator mints tokens and expects them to go to a specific recipient, but the attacker redirects them.

**Real-world impact:** A staking protocol's spend handler verifies that the continuing output contains at least the staked amount plus rewards. But it never checks the output address. An attacker constructs a transaction that "continues" the UTXO to their own wallet address instead of the script. The validator sees the value is preserved and approves -- but the funds are now in the attacker's wallet, no longer locked at the script. The entire staking pool can be drained one UTXO at a time.

## Example: Vulnerable Code

```aiken
validator staking_pool {
  spend(datum: StakeDatum, _redeemer: Data, own_ref: OutputReference, self: Transaction) {
    expect Some(own_input) = transaction.find_input(self.transaction.inputs, own_ref)
    let input_value = own_input.output.value

    // VULNERABLE: checks value but not the output address
    list.any(
      self.transaction.outputs,
      fn(output) {
        value.lovelace_of(output.value) >= value.lovelace_of(input_value)
        // Missing: output.address == own_input.output.address
      },
    )
  }
}
```

## Example: Safe Code

```aiken
validator staking_pool {
  spend(datum: StakeDatum, _redeemer: Data, own_ref: OutputReference, self: Transaction) {
    expect Some(own_input) = transaction.find_input(self.transaction.inputs, own_ref)
    let own_address = own_input.output.address
    let input_value = own_input.output.value

    // SAFE: verifies both address and value
    list.any(
      self.transaction.outputs,
      fn(output) {
        output.address.payment_credential == own_address.payment_credential
          && value.lovelace_of(output.value) >= value.lovelace_of(input_value)
      },
    )
  }
}
```

For mint handlers, validate the destination of minted tokens:

```aiken
validator nft_minter {
  mint(redeemer: MintAction, self: Transaction) {
    expect list.has(self.transaction.extra_signatories, redeemer.admin_key)

    // SAFE: verify minted token goes to the intended recipient
    list.any(
      self.transaction.outputs,
      fn(output) {
        output.address == redeemer.recipient_address
          && assets.quantity_of(output.value, self.policy_id, redeemer.token_name) == 1
      },
    )
  }
}
```

## Detection Logic

Aikido flags this pattern when:

1. **Handler accesses `transaction.outputs`** -- it iterates or inspects outputs.
2. **No address validation signals are present** in the handler body:
   - No record label access for `"address"` or `"payment_credential"`.
   - No function calls containing `"payment_credential"`, `"address"`, `"script_hash"`, `"ScriptCredential"`, or `"VerificationKeyCredential"`.
   - No variable references to `"ScriptCredential"`, `"VerificationKeyCredential"`, or address-related identifiers.

**Confidence levels:**
- **likely** for `mint` handlers (tokens being sent to unverified addresses is high-impact).
- **possible** for `spend` handlers (there may be legitimate patterns where address checking is unnecessary).

## False Positives

- **Fee or tip outputs:** If a handler validates a fee payment to a known address stored in the datum, but the address check happens in a helper function that Aikido does not trace, a false positive can occur. Suppress with `// aikido:ignore[output-address-not-validated]`.
- **Burn-only spend handlers:** If the handler only permits burning/destroying the UTXO (no continuing output), address validation on outputs is irrelevant.
- **Global state validators:** Some validators check all outputs collectively (total value across all outputs) rather than individual output addresses. This is a design pattern that may be intentional, though it carries its own risks.
- **Cross-module address checks:** The address validation may occur in a helper function imported from another module. Aikido's cross-module analysis covers many of these cases, but deeply nested calls may be missed.

## Related Detectors

- [double-satisfaction](double-satisfaction.md) -- Often co-occurs: if the output address is unchecked, double satisfaction is also likely.
- [value-not-preserved](../high/value-not-preserved.md) -- Checks that output value is sufficient; complementary to address validation.
- [arbitrary-datum-in-output](../high/arbitrary-datum-in-output.md) -- Similarly, outputs may have unchecked datum content alongside unchecked addresses.
- [insufficient-staking-control](../medium/insufficient-staking-control.md) -- Even with correct payment credential, the staking credential on the output may be unvalidated.
