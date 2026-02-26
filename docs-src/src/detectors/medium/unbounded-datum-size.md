# unbounded-datum-size

**Severity:** Medium | **Confidence:** possible | **CWE:** [CWE-400](https://cwe.mitre.org/data/definitions/400.html)

## What it detects

Identifies datum types used in spend handlers that contain fields with unbounded types: `List<T>`, `ByteArray` (when not a known fixed-size type), or `Dict<K, V>`.

## Why it matters

Datum deserialization and processing consumes Plutus execution budget proportional to the datum's size. If a datum contains unbounded collections, an attacker can create a UTXO with a bloated datum that:

- **Exceeds the execution budget** when the validator tries to process it, making the UTXO permanently unspendable
- **Increases minimum UTXO value** (Cardano requires more ADA for larger datums), locking excess funds
- **Causes out-of-memory failures** during deserialization

This is especially dangerous for continuing outputs where the datum accumulates data over time.

## Example: Vulnerable Code

```aiken
type AuctionDatum {
  seller: VerificationKeyHash,
  bids: List<Bid>,           // Grows unboundedly with each bid!
  history: List<ByteArray>,  // Accumulates indefinitely!
}

type Bid {
  bidder: VerificationKeyHash,
  amount: Int,
}
```

After enough bids, processing this datum exceeds the execution budget and the auction UTXO becomes unspendable.

## Example: Safe Code

```aiken
type AuctionDatum {
  seller: VerificationKeyHash,
  highest_bid: Option<Bid>,   // Only track the highest bid
  bid_count: Int,             // Track count separately
}

// Or enforce bounds in the validator:
validator auction {
  spend(datum: AuctionDatum, _redeemer: Void, _ref: OutputReference, self: Transaction) {
    expect list.length(datum.bids) <= 50
    // ... rest of validation
  }
}
```

## Detection Logic

1. For each spend handler, identifies the datum type from the first parameter.
2. Searches for the datum type definition across all modules (including lib modules).
3. Flags fields whose type contains `List<`, `ByteArray`, or `Dict<`.
4. Skips `ByteArray` fields with names or types indicating fixed-size Cardano primitives (e.g., `policy_id`, `script_hash`, `key_hash`, `PolicyId`, `VerificationKeyHash`, `Hash<...>`).

## False Positives

- **Fixed-size ByteArray fields**: Fields named `policy_id`, `script_hash`, `pub_key`, etc. are automatically excluded since they are always 28 or 32 bytes on Cardano.
- **Bounded by validator logic**: If the validator enforces a maximum length on the list (e.g., `expect list.length(datum.items) <= 10`), the finding can be suppressed.
- **Short-lived UTXOs**: If the datum is consumed in the same transaction it is created, bloating is not a practical concern.

Suppress with:
```aiken
// aikido:ignore[unbounded-datum-size] -- list bounded to 10 items by validator logic
```

## Related Detectors

- [unbounded-value-size](unbounded-value-size.md) -- Unbounded native asset count in output values
- [unbounded-list-iteration](unbounded-list-iteration.md) -- Direct iteration over transaction lists
- [cheap-spam-vulnerability](cheap-spam-vulnerability.md) -- Cheap UTXO creation without deposit requirements
