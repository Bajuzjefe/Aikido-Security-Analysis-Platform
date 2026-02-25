# value-not-preserved

**Severity:** High | **Confidence:** likely | **CWE:** [CWE-682](https://cwe.mitre.org/data/definitions/682.html)

## What it detects

Spend handlers that iterate transaction outputs (continuing UTXO pattern) without verifying that the output value is sufficient. When a validator produces a continuing output but never checks the `value` field or calls value-related functions, an attacker can create outputs with less value than the input, effectively draining the contract.

## Why it matters

Value preservation is the most fundamental property of a continuing UTXO. When a spend handler creates an output that goes back to the script address, the value of that output must be at least as much as the input value (minus any intended withdrawal or fee). Without this check, an attacker can "continue" the script UTXO with a near-zero value, pocketing the difference.

**Real-world impact:** A staking protocol's spend handler checks that the continuing output has the correct address and datum, but never verifies the value. An attacker constructs a transaction that spends a 100,000 ADA UTXO at the script and creates a continuing output with just 2 ADA (minimum UTXO requirement) at the same script address with the same datum. The validator approves because the address and datum match. The attacker walks away with 99,998 ADA. By repeating this for every UTXO at the script, the attacker drains the entire protocol.

## Example: Vulnerable Code

```aiken
type StakeDatum {
  staker: ByteArray,
  staked_at: Int,
  reward_rate: Int,
}

validator staking_pool {
  spend(datum: StakeDatum, _redeemer: Data, own_ref: OutputReference, self: Transaction) {
    expect Some(own_input) = transaction.find_input(self.transaction.inputs, own_ref)
    let own_address = own_input.output.address

    // VULNERABLE: checks address and datum but NOT value
    list.any(
      self.transaction.outputs,
      fn(output) {
        output.address == own_address
          && output.datum == InlineDatum(datum)
      },
    )
  }
}
```

## Example: Safe Code

```aiken
type StakeDatum {
  staker: ByteArray,
  staked_at: Int,
  reward_rate: Int,
}

validator staking_pool {
  spend(datum: StakeDatum, redeemer: ClaimRewards, own_ref: OutputReference, self: Transaction) {
    expect Some(own_input) = transaction.find_input(self.transaction.inputs, own_ref)
    let own_address = own_input.output.address
    let input_lovelace = value.lovelace_of(own_input.output.value)

    // Calculate expected minimum continuing value
    let reward_amount = calculate_rewards(datum, self.transaction.validity_range)
    let expected_continuing_value = input_lovelace - reward_amount

    // SAFE: verifies address, value, AND datum
    list.any(
      self.transaction.outputs,
      fn(output) {
        output.address == own_address
          && value.lovelace_of(output.value) >= expected_continuing_value
          && output.datum == InlineDatum(datum)
      },
    )
  }
}
```

## Detection Logic

Aikido flags this pattern when:

1. **Handler type is `spend`** -- only spend handlers are checked.
2. **Handler accesses `transaction.outputs`** -- indicating a continuing UTXO pattern.
3. **No value verification signals** in the handler body:
   - No record label `"value"` is accessed on outputs.
   - No function calls to `lovelace_of`, `value.merge`, `value.add`, `value.from_lovelace`, or `value.negate`.

The confidence is **possible** because the handler may access outputs for purposes other than creating continuing UTXOs. Not every output iteration implies a continuing UTXO pattern.

## False Positives

- **Withdrawal-only handlers:** If the handler only allows full withdrawal (consuming the UTXO entirely, no continuing output), value preservation is not applicable. Suppress with `// aikido:ignore[value-not-preserved]`.
- **Value checked in helpers:** If value verification is performed in a helper function from another module, Aikido's cross-module analysis will attempt to trace it. Deep call chains may be missed.
- **Token-based value:** Some protocols track value through native tokens rather than ADA. If the handler checks token quantities instead of lovelace, the detector may fire because it looks for value-specific function calls.
- **Output iteration for non-continuing purposes:** If outputs are iterated only to verify fee payments or reward distributions (not continuing UTXOs), value preservation is irrelevant.

## Related Detectors

- [value-preservation-gap](value-preservation-gap.md) -- The next level: lovelace is checked but native assets are not preserved.
- [unsafe-match-comparison](unsafe-match-comparison.md) -- A specific pattern where `match(..., >=)` gives false confidence in value checks.
- [double-satisfaction](../critical/double-satisfaction.md) -- Often co-occurs: if value is not individually verified per input, double satisfaction is also possible.
- [output-address-not-validated](../critical/output-address-not-validated.md) -- Complementary: address and value should both be checked on continuing outputs.
