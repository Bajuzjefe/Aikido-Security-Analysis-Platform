# arbitrary-datum-in-output

**Severity:** High | **Confidence:** likely | **CWE:** [CWE-20](https://cwe.mitre.org/data/definitions/20.html)

## What it detects

Spend handlers that produce continuing outputs (iterate `transaction.outputs`) without validating the datum content attached to those outputs. Even when a datum exists on the output, if its content is not checked against expected values, an attacker can inject arbitrary state into the contract.

## Why it matters

Cardano smart contracts use datum as on-chain state. When a spend handler creates a continuing UTXO (sending value back to the script address), the datum on that output becomes the new state of the contract. If the validator does not verify that this datum matches the expected state transition, an attacker can write arbitrary values, corrupting the protocol's state machine.

**Real-world impact:** A lending protocol tracks loan positions in datum. The spend handler verifies that the continuing output has sufficient collateral value but never checks the datum. An attacker constructs a transaction that sets the loan's `interest_rate` to zero and `principal` to 1 lovelace in the continuing datum. The validator approves because the value check passes. The attacker now has a nearly-free loan backed by the protocol's collateral. By repeating this across all loans, the attacker can drain the protocol's entire lending pool.

## Example: Vulnerable Code

```aiken
type PoolState {
  total_liquidity: Int,
  fee_rate: Int,
  admin: ByteArray,
}

validator liquidity_pool {
  spend(datum: PoolState, redeemer: SwapAction, own_ref: OutputReference, self: Transaction) {
    expect Some(own_input) = transaction.find_input(self.transaction.inputs, own_ref)
    let own_address = own_input.output.address

    // VULNERABLE: checks address and value but NOT the datum content
    list.any(
      self.transaction.outputs,
      fn(output) {
        output.address == own_address
          && value.lovelace_of(output.value) >= calculate_expected_output(datum, redeemer)
      },
    )
  }
}
```

## Example: Safe Code

```aiken
type PoolState {
  total_liquidity: Int,
  fee_rate: Int,
  admin: ByteArray,
}

validator liquidity_pool {
  spend(datum: PoolState, redeemer: SwapAction, own_ref: OutputReference, self: Transaction) {
    expect Some(own_input) = transaction.find_input(self.transaction.inputs, own_ref)
    let own_address = own_input.output.address

    // Compute the expected new state
    let expected_output_value = calculate_expected_output(datum, redeemer)
    let expected_datum = PoolState {
      ..datum,
      total_liquidity: datum.total_liquidity + redeemer.input_amount - redeemer.output_amount,
    }

    // SAFE: validates address, value, AND datum content
    list.any(
      self.transaction.outputs,
      fn(output) {
        output.address == own_address
          && value.lovelace_of(output.value) >= expected_output_value
          && output.datum == InlineDatum(expected_datum)
      },
    )
  }
}
```

## Detection Logic

Aikido flags this pattern when all of the following are true:

1. **Handler type is `spend`** -- only spend handlers are checked (they create continuing UTXOs).
2. **Handler accesses `transaction.outputs`** -- it iterates or inspects outputs.
3. **No datum validation signals** are present in the handler body:
   - No record label `"datum"` is accessed.
   - No variable references to `"InlineDatum"`, `"DatumHash"`, or `"NoDatum"`.

The confidence is **possible** because the handler may access outputs for purposes other than continuing UTXOs, and some validators use structural patterns that Aikido may not fully trace.

## False Positives

- **Non-continuing output checks:** If the handler only inspects outputs to verify payments to regular wallet addresses (where datum is not relevant), this is a false positive. Suppress with `// aikido:ignore[arbitrary-datum-in-output]`.
- **Datum validation in helpers:** If datum validation is delegated to a helper function, Aikido's cross-module analysis will attempt to trace it but may miss deeply nested calls.
- **Withdrawal-only patterns:** Handlers that only allow full withdrawal (no continuing UTXO) do not need datum validation on outputs.
- **Single-action validators:** Validators with only one possible state (no state transitions) may legitimately skip datum validation if the datum never changes.

## Related Detectors

- [missing-datum-in-script-output](missing-datum-in-script-output.md) -- The simpler case: datum is entirely absent, not just unvalidated.
- [datum-tampering-risk](../medium/datum-tampering-risk.md) -- A medium-severity variant that catches datum passed through without field-level validation.
- [state-transition-integrity](state-transition-integrity.md) -- Validates that redeemer actions produce correct datum transitions.
- [output-address-not-validated](../critical/output-address-not-validated.md) -- Often co-occurs: unchecked datum alongside unchecked address.
