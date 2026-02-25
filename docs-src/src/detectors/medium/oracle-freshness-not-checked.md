# oracle-freshness-not-checked

**Severity:** Medium | **Confidence:** possible | **CWE:** [CWE-613](https://cwe.mitre.org/data/definitions/613.html)

## What it detects

Identifies handlers that use oracle data from reference inputs (detected by oracle-related naming patterns like `oracle`, `price`, `feed`, `rate`, `exchange`, `quote`) without verifying the data's freshness through a timestamp or validity range check.

## Why it matters

Oracle data represents external state (prices, exchange rates, etc.) that changes over time. If a validator uses oracle data without checking its recency:

- **Stale price exploit**: An attacker can submit a transaction referencing an old oracle UTXO with a favorable price, profiting from the discrepancy with the current market price.
- **Arbitrage attacks**: In DEX/lending protocols, stale prices enable risk-free arbitrage at the protocol's expense.
- **Liquidation manipulation**: Stale oracle data can prevent valid liquidations or trigger invalid ones.

On Cardano, reference inputs allow reading UTXO data without spending it. An attacker can reference any existing oracle UTXO, including outdated ones.

## Example: Vulnerable Code

```aiken
validator dex {
  spend(datum: PoolDatum, redeemer: SwapRedeemer, _ref: OutputReference, self: Transaction) {
    // Reads oracle price from reference input
    let oracle_input = list.find(self.reference_inputs, fn(ref) {
      value.quantity_of(ref.output.value, oracle_policy, oracle_name) == 1
    })
    expect Some(oracle) = oracle_input
    expect oracle_datum: OracleDatum = oracle.output.datum
    let price = oracle_datum.price
    // Uses price directly -- no freshness check!
    validate_swap(datum, redeemer, price)
  }
}
```

## Example: Safe Code

```aiken
use aiken/interval

validator dex {
  spend(datum: PoolDatum, redeemer: SwapRedeemer, _ref: OutputReference, self: Transaction) {
    let oracle_input = list.find(self.reference_inputs, fn(ref) {
      value.quantity_of(ref.output.value, oracle_policy, oracle_name) == 1
    })
    expect Some(oracle) = oracle_input
    expect oracle_datum: OracleDatum = oracle.output.datum

    // Verify oracle data is fresh (updated within the validity window)
    let tx_time = interval.get_upper_bound(self.validity_range)
    expect oracle_datum.last_updated + max_staleness >= tx_time

    validate_swap(datum, redeemer, oracle_datum.price)
  }
}
```

## Detection Logic

1. Checks if the handler accesses `reference_inputs` (oracle data source).
2. Searches for oracle-related patterns in record labels, function calls, and variable references (`oracle`, `price`, `feed`, `rate`, `exchange`, `quote`).
3. Verifies freshness checking by looking for: `validity_range` access, timestamp-related labels (`timestamp`, `last_updated`, `updated_at`, `valid_until`, `expires`, `slot`, `epoch`, `freshness`), or time-related function calls (`interval`, `time`, `slot`, `posix`).
4. Flags handlers that use oracle data without any freshness indicator.

## False Positives

- **Immutable oracle data**: If the oracle datum contains configuration data that never changes (e.g., protocol parameters), freshness is not relevant.
- **Oracle freshness enforced by oracle contract**: If the oracle's own validator ensures it can only be updated within a time window, consumer validators may rely on this guarantee.
- **Generic reference inputs**: If `reference_inputs` are used for non-oracle purposes but a variable happens to contain "rate" or "price" in its name.

Suppress with:
```aiken
// aikido:ignore[oracle-freshness-not-checked] -- oracle contract enforces 5-minute update window
```

## Related Detectors

- [missing-validity-range](missing-validity-range.md) -- Time-sensitive datum without validity range check
- [oracle-manipulation-risk](../high/oracle-manipulation-risk.md) -- Oracle data used without manipulation safeguards
- [missing-utxo-authentication](../critical/missing-utxo-authentication.md) -- Reference inputs used without authentication
