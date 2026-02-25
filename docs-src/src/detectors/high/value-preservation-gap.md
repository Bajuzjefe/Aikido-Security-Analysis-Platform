# value-preservation-gap

**Severity:** High | **Confidence:** likely | **CWE:** [CWE-682](https://cwe.mitre.org/data/definitions/682.html) -- Incorrect Calculation

## What it detects

Finds spend handlers that verify lovelace (ADA) preservation in continuing outputs but do not check native asset preservation. On Cardano, UTXOs can hold ADA alongside arbitrary native tokens. A validator that only compares lovelace amounts allows an attacker to drain native tokens from the UTXO while keeping the ADA intact.

## Why it matters

Cardano UTXOs carry a multi-asset `Value` consisting of lovelace plus zero or more native tokens. Many validators need to ensure that the continuing output preserves the full value of the spent input. A common mistake is to check only the lovelace component using `value.lovelace_of`:

- **DEX pool draining**: A liquidity pool holds 10,000 ADA + 50,000 TokenA. The validator checks that the output contains at least 10,000 ADA. The attacker constructs a transaction that preserves 10,000 ADA but removes all 50,000 TokenA.
- **Treasury theft**: A multi-sig treasury holds ADA + governance tokens. The spend handler checks lovelace preservation. An attacker (with valid signatures for a "routine" operation) strips the governance tokens, seizing voting power.
- **Staking contract value leak**: A staking contract locks user deposits as ADA + reward tokens. The withdrawal handler checks lovelace but not reward tokens. An attacker withdraws reward tokens for free.

The root cause is that `value.lovelace_of` returns only the ADA component and discards all native asset information. Any comparison using only this function is blind to native token manipulation.

## Example: Vulnerable Code

```aiken
use cardano/transaction.{Transaction, OutputReference}
use cardano/value

type VaultDatum {
  owner: ByteArray,
  expected_ada: Int,
}

validator token_vault {
  spend(
    datum: Option<VaultDatum>,
    _redeemer: Data,
    own_ref: OutputReference,
    self: Transaction,
  ) {
    expect Some(d) = datum

    // Find the continuing output back to the script
    expect Some(output) =
      list.find(self.outputs, fn(o) {
        o.address == own_ref.output_reference
      })

    // BUG: Only checks ADA preservation.
    // Native tokens in the UTXO are completely ignored!
    // An attacker can strip all native tokens while passing this check.
    value.lovelace_of(output.value) >= d.expected_ada &&
    list.has(self.extra_signatories, d.owner)
  }
}
```

## Example: Safe Code

```aiken
use cardano/transaction.{Transaction, OutputReference, Input}
use cardano/value

type VaultDatum {
  owner: ByteArray,
}

validator token_vault {
  spend(
    datum: Option<VaultDatum>,
    _redeemer: Data,
    own_ref: OutputReference,
    self: Transaction,
  ) {
    expect Some(d) = datum

    // Find the input being spent
    expect Some(own_input) =
      list.find(self.inputs, fn(i: Input) {
        i.output_reference == own_ref
      })

    // Find the continuing output back to the script
    expect Some(output) =
      list.find(self.outputs, fn(o) {
        o.address == own_input.output.address
      })

    // SAFE: Compare the full Value, not just lovelace.
    // value.merge with value.negate computes the difference.
    // If the result is value.zero(), the values are identical.
    let diff = value.merge(output.value, value.negate(own_input.output.value))

    diff == value.zero() &&
    list.has(self.extra_signatories, d.owner)
  }
}
```

Alternative safe patterns:

```aiken
// Pattern 1: Check native assets separately
let output_native = value.without_lovelace(output.value)
let input_native = value.without_lovelace(own_input.output.value)
output_native == input_native &&
value.lovelace_of(output.value) >= value.lovelace_of(own_input.output.value)

// Pattern 2: Enumerate and verify all assets
let output_assets = value.flatten(output.value)
let input_assets = value.flatten(own_input.output.value)
// Compare asset lists

// Pattern 3: Check specific native tokens explicitly
value.lovelace_of(output.value) >= expected_ada &&
value.quantity_of(output.value, token_policy, token_name) >= expected_tokens
```

## Detection Logic

Aikido flags a handler when **all** of the following are true:

1. The module is a validator and the handler is a `spend` handler.
2. The handler accesses `outputs` from the transaction context (indicating it produces continuing UTXOs).
3. The handler calls `lovelace_of` or `from_lovelace` (indicating lovelace-level value checking).
4. The handler does **not** also call any native-asset-aware function: `without_lovelace`, `value.merge`, `value.negate`, `value.flatten`, `value.add`, `value.zero`, `value.to_dict`, `value.tokens`, `value.policies`, or `quantity_of`.

The absence of native-asset functions (step 4) alongside lovelace-specific functions (step 3) indicates that only the ADA component is validated.

## False Positives

Suppress this finding when:

- **ADA-only UTXO**: The validator is designed to hold only ADA (no native tokens). In this case, `lovelace_of` is sufficient.
- **Token check in helper module**: A cross-module helper function verifies native assets, but Aikido cannot trace the call.
- **Minting policy ensures no extra tokens**: The protocol's minting policy guarantees that the UTXO never contains unexpected native tokens.
- **Output address forces min-UTXO rules**: The protocol design ensures native tokens cannot be present at the script address.

```aiken
// aikido:ignore[value-preservation-gap] -- UTXO only holds ADA by design
```

## Related Detectors

- [value-not-preserved](value-not-preserved.md) -- Spend handler does not verify output value at all.
- [quantity-of-double-counting](quantity-of-double-counting.md) -- Multiple `quantity_of` calls that may double-count assets.
- [missing-datum-in-script-output](missing-datum-in-script-output.md) -- Continuing outputs missing datum attachment.
