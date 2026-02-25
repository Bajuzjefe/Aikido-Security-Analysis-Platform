# missing-signature-check

**Severity:** High | **Confidence:** likely | **CWE:** [CWE-862](https://cwe.mitre.org/data/definitions/862.html)

## What it detects

Validators with datum types containing authority-like `ByteArray` fields (named `owner`, `admin`, `operator`, `beneficiary`, `authority`, or `creator`) where the handler never checks `transaction.extra_signatories`. This indicates that an authority constraint exists in the data model but is never enforced at runtime.

## Why it matters

When a datum contains a field like `owner: ByteArray`, it almost always represents a public key hash that should authorize certain operations. If the validator never verifies this key hash against the transaction's signatories, anyone can perform operations that should require the owner's signature.

**Real-world impact:** An escrow contract stores `beneficiary: ByteArray` in its datum, representing who should receive the escrowed funds upon completion. The spend handler checks that a completion condition is met but never verifies that the transaction is signed by the beneficiary. An attacker watches the blockchain, sees the completion condition become true, and submits a transaction claiming the escrow funds to their own address -- because the beneficiary's signature is never required.

In DeFi protocols, missing signature checks on admin fields can allow unauthorized parameter changes, emergency withdrawals, or protocol upgrades.

## Example: Vulnerable Code

```aiken
type EscrowDatum {
  owner: ByteArray,
  beneficiary: ByteArray,
  unlock_time: Int,
  amount: Int,
}

validator escrow {
  spend(datum: EscrowDatum, _redeemer: Data, _own_ref: OutputReference, self: Transaction) {
    // VULNERABLE: datum has owner and beneficiary fields but neither is verified
    let valid_time =
      interval.is_after(self.transaction.validity_range, datum.unlock_time)
    let sufficient_output =
      list.any(
        self.transaction.outputs,
        fn(o) { value.lovelace_of(o.value) >= datum.amount },
      )

    valid_time && sufficient_output
  }
}
```

## Example: Safe Code

```aiken
type EscrowDatum {
  owner: ByteArray,
  beneficiary: ByteArray,
  unlock_time: Int,
  amount: Int,
}

validator escrow {
  spend(datum: EscrowDatum, redeemer: Action, own_ref: OutputReference, self: Transaction) {
    when redeemer is {
      Claim -> {
        // SAFE: verify the beneficiary signed the transaction
        expect list.has(self.transaction.extra_signatories, datum.beneficiary)

        let valid_time =
          interval.is_after(self.transaction.validity_range, datum.unlock_time)
        let sufficient_output =
          list.any(
            self.transaction.outputs,
            fn(o) { value.lovelace_of(o.value) >= datum.amount },
          )

        valid_time && sufficient_output
      }
      Cancel -> {
        // SAFE: only the owner can cancel
        list.has(self.transaction.extra_signatories, datum.owner)
      }
    }
  }
}
```

## Detection Logic

Aikido performs cross-module analysis for this detector:

1. **Scan all data types** across all modules for authority-like fields: fields named `owner`, `beneficiary`, `admin`, `authority`, `operator`, or `creator` with type `ByteArray`. Word-boundary matching is used to avoid false matches on names like `ownership` or `coowner`.
2. **For each validator handler**, check if the first parameter (datum) has a type matching one of these data types.
3. **If authority fields are found** in the datum type but the handler never accesses `extra_signatories` on the transaction, a **High/likely** finding is emitted.

The confidence is **likely** (not definite) because there are legitimate patterns where signature verification is intentionally omitted for certain actions.

## False Positives

- **Datum fields used for non-auth purposes:** A `ByteArray` field named `owner` might represent a token name or hash rather than a public key hash. Context matters -- if the field is not used for authorization, suppress with `// aikido:ignore[missing-signature-check]`.
- **Multi-validator delegation:** Authorization may be enforced by a companion validator (e.g., a mint handler verifies the signer, and the spend handler trusts the presence of a freshly minted token). This is a valid pattern but should be documented.
- **Signature check in helper functions:** If `extra_signatories` is checked in a helper function called from another module, Aikido's cross-module analysis will attempt to trace it. If it cannot, a false positive may occur.
- **Token-gated authorization:** Some protocols use NFT ownership instead of signatures for authorization. The `owner` field might be a policy ID rather than a public key hash.

## Related Detectors

- [missing-redeemer-validation](missing-redeemer-validation.md) -- Even with signature checks, redeemer branches that return `True` bypass them.
- [missing-minting-policy-check](../critical/missing-minting-policy-check.md) -- Minting policies that lack authorization; signature checks are a common authorization mechanism.
- [unrestricted-minting](../critical/unrestricted-minting.md) -- The minting equivalent of missing signature verification.
