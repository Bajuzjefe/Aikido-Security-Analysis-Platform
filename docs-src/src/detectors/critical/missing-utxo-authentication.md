# missing-utxo-authentication

**Severity:** Critical | **Confidence:** definite | **CWE:** [CWE-345](https://cwe.mitre.org/data/definitions/345.html)

## What it detects

Handlers that read data from reference inputs (`transaction.reference_inputs`) without authenticating those inputs. Reference inputs are read-only UTXOs included in a transaction for data access. Since anyone can create a UTXO at any address with arbitrary datum, a handler that trusts reference input data without verification is vulnerable to data injection.

## Why it matters

Reference inputs (CIP-31) are a powerful Cardano feature: they allow validators to read on-chain data without consuming UTXOs. However, this power comes with a critical caveat -- anyone can create a UTXO that *looks like* an oracle feed, price datum, or configuration store. If a validator reads a reference input and trusts its datum without verifying it carries an authentication token (NFT) or comes from a specific credential, an attacker can forge the data.

**Real-world impact:** A lending protocol reads an oracle price feed from a reference input. The oracle is expected to be a UTXO holding a specific NFT. But the validator never checks for the NFT -- it just reads the first reference input. An attacker creates a UTXO with a fake price datum (setting the collateral asset price to near-zero), includes it as a reference input, and liquidates healthy positions at a fraction of their real value. The attacker extracts millions in under-collateralized loans.

## Example: Vulnerable Code

```aiken
use cardano/transaction.{Transaction, Input}

type OracleData {
  price: Int,
  timestamp: Int,
}

validator lending_pool {
  spend(datum: PoolDatum, redeemer: Action, own_ref: OutputReference, self: Transaction) {
    // VULNERABLE: trusts the first reference input without authentication
    expect [oracle_input, ..] = self.transaction.reference_inputs
    expect oracle_datum: OracleData = oracle_input.output.datum

    let current_price = oracle_datum.price
    // Uses attacker-controlled price for liquidation logic...
    current_price * datum.collateral_amount >= datum.loan_amount * 150 / 100
  }
}
```

## Example: Safe Code

```aiken
use cardano/transaction.{Transaction, Input}
use cardano/assets.{quantity_of}

type OracleData {
  price: Int,
  timestamp: Int,
}

validator lending_pool {
  spend(datum: PoolDatum, redeemer: Action, own_ref: OutputReference, self: Transaction) {
    let oracle_nft_policy = datum.oracle_policy_id

    // SAFE: authenticate the reference input by verifying it holds the oracle NFT
    expect Some(oracle_input) =
      list.find(
        self.transaction.reference_inputs,
        fn(input) {
          quantity_of(input.output.value, oracle_nft_policy, "OracleFeed") > 0
        },
      )

    expect oracle_datum: OracleData = oracle_input.output.datum
    let current_price = oracle_datum.price

    current_price * datum.collateral_amount >= datum.loan_amount * 150 / 100
  }
}
```

## Detection Logic

Aikido flags this pattern when:

1. **Handler accesses `reference_inputs`** on the transaction -- the `tx_field_accesses` set contains `"reference_inputs"`.
2. **No authentication pattern is present** -- the handler does not access `extra_signatories` (signer-based auth) and does not access the `mint` field (token-gated auth via minting policy).

The confidence is **likely** because while the heuristic strongly indicates missing authentication, there could be other authentication patterns (e.g., checking a specific address or credential) that Aikido does not yet track as auth signals.

## False Positives

- **Address-based authentication:** If the validator checks that the reference input comes from a specific known address (e.g., hardcoded script hash), this is a form of authentication that Aikido may not recognize. Suppress with `// aikido:ignore[missing-utxo-authentication] -- address check in helper`.
- **Protocol-owned reference inputs:** Some protocols create immutable reference UTXOs at their own script address. If the validator checks the reference input's address matches its own, this is sufficient authentication but may not be detected as such.
- **Governance read patterns:** Reading governance parameters from a well-known UTXO where the datum is validated structurally (not just trusted) may be safe without token authentication, though token-gating is still best practice.

## Related Detectors

- [oracle-manipulation-risk](../high/oracle-manipulation-risk.md) -- Detects oracle data used without manipulation safeguards, a higher-level concern that overlaps with authentication.
- [oracle-freshness-not-checked](../medium/oracle-freshness-not-checked.md) -- Even authenticated oracle data can be stale; this detector checks for recency validation.
- [missing-input-credential-check](../medium/missing-input-credential-check.md) -- Similar pattern for regular inputs: iterating without credential verification.
