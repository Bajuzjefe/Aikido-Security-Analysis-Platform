# utxo-contention-risk

**Severity:** Medium | **Confidence:** possible | **CWE:** [CWE-400](https://cwe.mitre.org/data/definitions/400.html)

## What it detects

Identifies validators whose datum types have no user-identifying fields (such as `owner`, `beneficiary`, `id`, or `Credential`-typed fields), suggesting a single global UTXO pattern that causes transaction contention.

## Why it matters

On Cardano, each UTXO can only be spent by one transaction per block. If a protocol uses a single shared UTXO (global state) that every user must interact with:

- **Throughput is limited to ~1 transaction per 20-second block**
- **Most user transactions fail** with "UTxO already spent" errors when two transactions try to spend the same UTXO in the same block
- **User experience degrades** as the protocol scales, with increasing failure rates
- **MEV-like contention** emerges where users compete to be included first

This pattern works for admin-only operations but fails for multi-user protocols.

## Example: Vulnerable Code

```aiken
type AuctionState {
  current_bid: Int,
  bid_count: Int,
  end_slot: Int,
}

// All bidders must spend the same UTXO -- only one bid per block!
validator auction {
  spend(datum: AuctionState, redeemer: BidAction, _ref: OutputReference, self: Transaction) { ... }
  mint(_redeemer: Void, _self: Transaction) { ... }
}
```

## Example: Safe Code

```aiken
type BidDatum {
  bidder: VerificationKeyHash,   // Per-user field
  auction_id: ByteArray,
  bid_amount: Int,
}

// Each bidder has their own UTXO -- parallel bids supported
validator auction {
  spend(datum: BidDatum, redeemer: BidAction, _ref: OutputReference, self: Transaction) { ... }
  mint(_redeemer: Void, _self: Transaction) { ... }
}
```

## Detection Logic

1. Examines multi-handler validators (2+ handlers) with a spend handler that uses a structured datum type.
2. Skips primitive datum types (`Void`, `Data`, `Int`, `ByteArray`) and single-handler validators.
3. Skips datum types whose names match singleton patterns (`Settings`, `Config`, `Parameters`, `Protocol`, `Global`, `Pool`, `Registry`, `Factory`).
4. Looks up the datum type definition and checks all fields for user-identifying names (`owner`, `beneficiary`, `creator`, `user`, `sender`, `recipient`, `address`, `pkh`, `credential`, `position_id`, `order_id`, `seller`, `buyer`, `borrower`, `lender`, etc.) or types (`Credential`, `VerificationKeyHash`, `VerificationKey`, `Address`).
5. Also resolves one level of nested custom types (e.g., a `Config` field that contains an `owner`).
6. Flags validators where no user-identifying field is found.

## False Positives

- **Intentional singletons**: Protocols that intentionally use a global state UTXO (e.g., a liquidity pool with batched operations). Aikido skips datum types with singleton-related names, but custom names may still trigger.
- **Admin-only contracts**: Validators where only an admin interacts (low contention by design).
- **Batching protocols**: Some protocols aggregate multiple user requests into a single transaction, avoiding contention.

Suppress with:
```aiken
// aikido:ignore[utxo-contention-risk] -- intentional global pool with off-chain batching
```

## Related Detectors

- [unbounded-protocol-operations](unbounded-protocol-operations.md) -- O(n*m) iteration complexity
- [cheap-spam-vulnerability](cheap-spam-vulnerability.md) -- Cheap UTXO spam at script address
