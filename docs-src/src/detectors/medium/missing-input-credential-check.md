# missing-input-credential-check

**Severity:** Medium | **Confidence:** possible | **CWE:** [CWE-345](https://cwe.mitre.org/data/definitions/345.html)

## What it detects

Identifies handlers that iterate over transaction inputs searching for specific tokens or values without verifying the input's credential type (script vs. pubkey). This is the "Trust No UTxO" vulnerability pattern.

## Why it matters

On Cardano, both script addresses and pubkey addresses can hold the same native tokens. When a validator searches inputs for a specific token (e.g., an oracle token, protocol NFT, or governance token) without checking the credential type:

- **Fake input injection**: An attacker creates a pubkey UTXO containing the same token and includes it in the transaction. The validator finds the token but reads data from the attacker's fake UTXO instead of the authentic script UTXO.
- **Oracle spoofing**: An attacker mints a token with the same policy and name, holds it at their pubkey address, and the validator trusts their fake "oracle" data.
- **Authentication bypass**: Protocol tokens that should only exist at script addresses are found at attacker-controlled addresses.

The `own_ref` (OutputReference) uniquely identifies a specific input, so handlers that use it are excluded.

## Example: Vulnerable Code

```aiken
validator dex {
  spend(datum: PoolDatum, _redeemer: Void, _ref: OutputReference, self: Transaction) {
    // Finds ANY input with the oracle token -- could be attacker's pubkey UTXO!
    list.any(self.inputs, fn(input) {
      value.quantity_of(input.output.value, oracle_policy, oracle_name) > 0
    })
  }
}
```

## Example: Safe Code

```aiken
use cardano/address.{ScriptCredential}

validator dex {
  spend(datum: PoolDatum, _redeemer: Void, _ref: OutputReference, self: Transaction) {
    list.any(self.inputs, fn(input) {
      // Verify the input comes from a script address
      input.output.address.payment_credential == ScriptCredential(oracle_script_hash) &&
      value.quantity_of(input.output.value, oracle_policy, oracle_name) > 0
    })
  }
}
```

## Detection Logic

1. Checks if the handler iterates over `inputs` (via `tx_list_iterations`).
2. Skips handlers that use `own_ref` (which uniquely identifies the input).
3. Checks for value/token operations on inputs: calls to `quantity_of`, `lovelace_of`, `tokens`, `policies`, or access to `value` record labels.
4. Verifies the handler checks credential types: `payment_credential`, `stake_credential`, `ScriptCredential`, `VerificationKeyCredential`, or related function calls.
5. Flags handlers that search inputs by token/value without credential verification.

## False Positives

- **Protocol-controlled tokens**: If the token's minting policy guarantees it can only exist at specific script addresses, the credential check is technically redundant (but still best practice).
- **Own-script inputs only**: If the handler only processes inputs from its own script address (verified via own_ref), credential checking is unnecessary.
- **Reference inputs**: This detector checks `inputs`, not `reference_inputs`. Oracle data from reference inputs is covered by `oracle-freshness-not-checked` and `missing-utxo-authentication`.

Suppress with:
```aiken
// aikido:ignore[missing-input-credential-check] -- token can only exist at script address
```

## Related Detectors

- [missing-utxo-authentication](../critical/missing-utxo-authentication.md) -- Reference inputs used without authentication
- [oracle-manipulation-risk](../high/oracle-manipulation-risk.md) -- Oracle data without manipulation safeguards
- [oracle-freshness-not-checked](oracle-freshness-not-checked.md) -- Oracle data without freshness verification
