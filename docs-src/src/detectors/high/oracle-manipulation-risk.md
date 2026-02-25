# oracle-manipulation-risk

**Severity:** High | **Confidence:** possible | **CWE:** [CWE-345](https://cwe.mitre.org/data/definitions/345.html) -- Insufficient Verification of Data Authenticity

## What it detects

Finds handlers that read data from reference inputs and verify an authentication token (via `quantity_of` or similar) but do not check the reference input's payment credential. Without credential verification, an attacker can create a fake UTXO at a different address carrying a copy of the authentication token, with entirely fabricated oracle data.

## Why it matters

Cardano validators use reference inputs (CIP-31) to read oracle data without consuming the oracle UTXO. The standard authentication pattern is to verify that the reference input carries a specific NFT (oracle auth token). However, NFT-only authentication has a critical gap:

- **Token duplication via minting policy exploit**: If the oracle NFT's minting policy has any vulnerability, the attacker mints a second copy. They place it at their own address with a manipulated datum, then provide this fake UTXO as the reference input.
- **Same-policy token confusion**: If the oracle operator's minting policy allows multiple token names, the attacker may find or create another UTXO under the same policy at a different address.
- **Token forwarding**: In some protocol designs, the oracle token may temporarily exist at an address controlled by the attacker (e.g., during a multi-step protocol interaction).

The defense is to verify not just the token, but the **payment credential** of the reference input's address. This ensures the data comes from the expected oracle script, regardless of what tokens it carries.

This vulnerability is distinct from [missing-utxo-authentication](../critical/missing-utxo-authentication.md), which catches reference inputs with **no authentication at all**. This detector fires when there IS token-based authentication, but the address/credential is not verified -- a more subtle but equally exploitable gap.

## Example: Vulnerable Code

```aiken
use cardano/transaction.{Transaction, OutputReference, Input}
use cardano/value

type PriceDatum {
  price: Int,
  timestamp: Int,
}

type LoanDatum {
  collateral_amount: Int,
  oracle_policy: ByteArray,
  oracle_token_name: ByteArray,
}

validator lending_protocol {
  spend(
    datum: Option<LoanDatum>,
    _redeemer: Data,
    _own_ref: OutputReference,
    self: Transaction,
  ) {
    expect Some(d) = datum

    // Find the oracle reference input by checking for the auth token
    expect Some(oracle_input) =
      list.find(self.reference_inputs, fn(ref_input: Input) {
        value.quantity_of(
          ref_input.output.value,
          d.oracle_policy,
          d.oracle_token_name,
        ) > 0
      })

    // BUG: Reads the oracle datum but never checks the ADDRESS
    // of the reference input. An attacker can provide a fake UTXO
    // at their own address carrying a copy of the auth token
    // with a manipulated price.
    expect InlineDatum(raw) = oracle_input.output.datum
    expect oracle: PriceDatum = raw

    let collateral_value = d.collateral_amount * oracle.price
    collateral_value >= minimum_collateral
  }
}
```

## Example: Safe Code

```aiken
use cardano/transaction.{Transaction, OutputReference, Input, InlineDatum}
use cardano/address.{Script as ScriptCredential}
use cardano/value

type PriceDatum {
  price: Int,
  timestamp: Int,
}

type LoanDatum {
  collateral_amount: Int,
  oracle_policy: ByteArray,
  oracle_token_name: ByteArray,
  oracle_script_hash: ByteArray,
}

validator lending_protocol {
  spend(
    datum: Option<LoanDatum>,
    _redeemer: Data,
    _own_ref: OutputReference,
    self: Transaction,
  ) {
    expect Some(d) = datum

    expect Some(oracle_input) =
      list.find(self.reference_inputs, fn(ref_input: Input) {
        value.quantity_of(
          ref_input.output.value,
          d.oracle_policy,
          d.oracle_token_name,
        ) > 0
      })

    // SAFE: Verify the oracle input comes from the expected script address.
    // This prevents fake UTXOs at attacker-controlled addresses.
    expect ScriptCredential(script_hash) =
      oracle_input.output.address.payment_credential
    expect script_hash == d.oracle_script_hash

    // Now safe to read the oracle datum
    expect InlineDatum(raw) = oracle_input.output.datum
    expect oracle: PriceDatum = raw

    let collateral_value = d.collateral_amount * oracle.price
    collateral_value >= minimum_collateral
  }
}
```

For additional defense, verify oracle freshness as well:

```aiken
// SAFE: Verify credential AND freshness
expect ScriptCredential(hash) = oracle_input.output.address.payment_credential
expect hash == expected_oracle_hash

expect InlineDatum(raw) = oracle_input.output.datum
expect oracle: PriceDatum = raw

// Check that the oracle data is recent (within validity range)
let current_time = self.validity_range.lower_bound
expect oracle.timestamp + max_oracle_age >= current_time
```

## Detection Logic

Aikido flags a handler when **all** of the following are true:

1. The module is a validator.
2. The handler accesses `reference_inputs` from the transaction context.
3. The handler performs **value/token inspection** on the reference input -- calls containing `quantity_of`, `tokens`, or `from_asset` -- indicating it uses token-based authentication.
4. The handler does **not** verify the payment credential:
   - No function calls containing `payment_credential` or `credential`
   - No record label access to `payment_credential`
   - No variable reference to `ScriptCredential`

The pattern of token-based authentication (step 3) without credential verification (step 4) indicates that the oracle input's address is not validated, leaving a manipulation vector.

## False Positives

Suppress this finding when:

- **Token is provably unique**: The oracle NFT's minting policy is a one-shot policy (parameterized by a UTXO reference) that can mint exactly one token. In this case, there cannot be a second copy of the token at a different address. However, relying solely on token uniqueness is fragile -- credential checks provide defense in depth.
- **Address checked in helper module**: A cross-module helper function verifies the credential, but Aikido cannot trace the call across module boundaries.
- **Reference input is not an oracle**: The reference input is used for purposes other than reading external data (e.g., reading the validator's own state from a separate UTXO), where the address is implicitly trusted.
- **Credential checked via address comparison**: The handler compares the entire `address` struct rather than extracting `payment_credential` specifically. This is equivalent but uses a different code pattern.

```aiken
// aikido:ignore[oracle-manipulation-risk] -- oracle NFT is one-shot, unique by construction
```

## Related Detectors

- [missing-utxo-authentication](../critical/missing-utxo-authentication.md) -- Reference inputs with no authentication at all (more severe).
- [oracle-freshness-not-checked](../medium/oracle-freshness-not-checked.md) -- Oracle data used without verifying recency.
- [missing-validity-range](../medium/missing-validity-range.md) -- Time-sensitive operations without validity range checks.
