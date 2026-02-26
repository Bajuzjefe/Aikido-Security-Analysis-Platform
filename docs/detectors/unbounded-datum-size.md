# unbounded-datum-size

**Severity:** Medium
**Confidence:** Possible

## Description

Datum types that contain unbounded collections (`List`, `ByteArray`, `Dict`) can grow arbitrarily large. Processing large datums consumes excessive CPU/memory budget, potentially making the UTXO unspendable if the cost exceeds Plutus execution limits.

Known fixed-size types (e.g., `PolicyId`, `VerificationKeyHash`, `Credential`) are excluded since they have constant size on Cardano (28 or 32 bytes).

## Vulnerable Example

```aiken
type PoolDatum {
  owners: List<ByteArray>,
  history: List<Action>,
  metadata: ByteArray,
}

validator {
  spend(datum: PoolDatum, redeemer, own_ref, self) {
    // If `owners` or `history` grows very large, this UTXO
    // may become too expensive to spend
    list.has(datum.owners, signer)
  }
}
```

An attacker (or normal usage over time) can grow these lists until spending the UTXO exceeds the Plutus execution budget, permanently locking the funds.

## Safe Example

```aiken
type PoolDatum {
  owner: VerificationKeyHash,
  last_action: Action,
  metadata_hash: ByteArray,
}

validator {
  spend(datum: PoolDatum, redeemer, own_ref, self) {
    // Fixed-size datum fields — spending cost is constant
    list.has(self.extra_signatories, datum.owner)
  }
}
```

## Remediation

1. Replace unbounded `List` fields with fixed-size alternatives where possible (e.g., a single `owner` instead of `List<owner>`)
2. Store large data off-chain and reference it by hash in the datum
3. If lists are necessary, enforce maximum size limits in the validator logic before processing
4. Use `Dict` sparingly and only with known upper bounds on the number of entries

## References

- [CWE-400: Uncontrolled Resource Consumption](https://cwe.mitre.org/data/definitions/400.html)
