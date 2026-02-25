# missing-protocol-token

**Severity:** Medium | **Confidence:** possible | **CWE:** [CWE-345](https://cwe.mitre.org/data/definitions/345.html)

## What it detects

Identifies spend handlers that produce continuing outputs and use `own_ref` to identify the script address, but do not verify a protocol/state token (NFT) in the output value.

## Why it matters

On Cardano, anyone can create a UTXO at any script address with arbitrary datum content. Without a state token to authenticate UTXOs:

- **Fake UTXO injection**: An attacker creates a UTXO at the script address with a malicious datum. If the validator does not require a state token, it cannot distinguish the fake UTXO from a legitimate one.
- **State confusion**: The validator may process an attacker-created UTXO as if it were valid protocol state.
- **Double-spending illusion**: An attacker creates fake "pool" UTXOs to trick other users into interacting with bogus state.

A protocol/state token (usually an NFT) is minted when the protocol UTXO is created and must be carried through every state transition, authenticating the UTXO at each step.

## Example: Vulnerable Code

```aiken
validator pool {
  spend(datum: PoolDatum, _redeemer: Void, own_ref: OutputReference, self: Transaction) {
    let own_address = get_own_address(self.inputs, own_ref)

    // Checks address and value, but no state token!
    list.any(self.outputs, fn(output) {
      output.address == own_address &&
      value.lovelace_of(output.value) >= datum.min_liquidity
    })
  }
}
```

## Example: Safe Code

```aiken
validator pool(state_policy: PolicyId, state_name: AssetName) {
  spend(datum: PoolDatum, _redeemer: Void, own_ref: OutputReference, self: Transaction) {
    let own_address = get_own_address(self.inputs, own_ref)

    list.any(self.outputs, fn(output) {
      output.address == own_address &&
      value.lovelace_of(output.value) >= datum.min_liquidity &&
      // Verify the state token is present in the output
      value.quantity_of(output.value, state_policy, state_name) == 1
    })
  }
}
```

## Detection Logic

1. Examines spend handlers that access `outputs` (continuing output pattern) and use `own_ref` (script address identification).
2. Checks for token verification via function calls: `quantity_of`, `tokens`, `from_asset`, or `policies`.
3. Also considers `mint` field access as sufficient (if mint is checked, token presence is verified through minting).
4. Flags handlers that produce continuing outputs with `own_ref` but perform no token verification.

## False Positives

- **Simple lock/unlock validators**: Validators without continuing state (e.g., one-shot escrows) do not need state tokens.
- **Token checked in helper module**: If token verification happens in a cross-module utility function.
- **Value equality check**: If the handler verifies exact output value including native assets, the state token is implicitly checked.
- **Token present in input check**: If the handler verifies the state token in the input (not the output), the output could still be missing it.

Suppress with:
```aiken
// aikido:ignore[missing-protocol-token] -- simple escrow, no continuing state
```

## Related Detectors

- [missing-utxo-authentication](../critical/missing-utxo-authentication.md) -- Reference inputs used without authentication
- [missing-input-credential-check](missing-input-credential-check.md) -- Inputs searched without credential check
- [double-satisfaction](../critical/double-satisfaction.md) -- Outputs not tied to specific input
