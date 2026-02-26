# oracle-freshness-not-checked

**Severity:** Medium
**Confidence:** Possible

## Description

When using oracle data (prices, exchange rates, external state) from reference inputs, the validator should verify that the data is recent by comparing a timestamp or slot number in the oracle datum against the transaction's validity range. Stale oracle data can be exploited for price manipulation attacks, where an attacker uses an outdated price to execute a trade at a favorable but no-longer-accurate rate.

## Vulnerable Example

```aiken
validator {
  spend(datum, redeemer, own_ref, self) {
    // Read oracle data from reference inputs
    let oracle_input = list.find(self.reference_inputs, fn(i) {
      i.output.address == datum.oracle_address
    })
    let oracle_datum: OracleDatum = parse_datum(oracle_input)
    let price = oracle_datum.price
    // Uses the price without checking if it's still current!
    // Could be hours or days old
    let required_payment = redeemer.quantity * price
    check_payment(self.outputs, required_payment)
  }
}
```

An attacker waits for the oracle price to become stale, then submits a transaction using the outdated reference input to exploit the price difference.

## Safe Example

```aiken
validator {
  spend(datum, redeemer, own_ref, self) {
    let oracle_input = list.find(self.reference_inputs, fn(i) {
      i.output.address == datum.oracle_address
    })
    let oracle_datum: OracleDatum = parse_datum(oracle_input)
    // Verify oracle freshness: last_updated must be within validity range
    let tx_lower_bound = get_lower_bound(self.validity_range)
    expect oracle_datum.last_updated >= tx_lower_bound - datum.max_oracle_age
    let price = oracle_datum.price
    let required_payment = redeemer.quantity * price
    check_payment(self.outputs, required_payment)
  }
}
```

## Remediation

1. Include a `last_updated` or `timestamp` field in the oracle datum.
2. Compare the oracle's timestamp against the transaction's `validity_range` to ensure recency.
3. Define a maximum acceptable oracle age (e.g., 5 minutes) and reject transactions that use data older than that threshold.
4. Use `interval.is_entirely_after` or similar functions from the Aiken standard library to verify time-based constraints.

## References

- [CWE-613: Insufficient Session Expiration](https://cwe.mitre.org/data/definitions/613.html)
