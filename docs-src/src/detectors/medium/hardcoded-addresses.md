# hardcoded-addresses

**Severity:** Medium | **Confidence:** possible | **CWE:** [CWE-798](https://cwe.mitre.org/data/definitions/798.html)

## What it detects

Identifies ByteArray literals in validator handler bodies whose lengths match Cardano address components: 28 bytes (key hash), 29 bytes (key hash + network tag), or 57 bytes (full address payload).

## Why it matters

Hardcoded addresses or key hashes in validators create several risks:

- **Testnet addresses in production**: A developer might hardcode a testnet key hash during development and forget to change it before deploying to mainnet.
- **Inflexible contracts**: Hardcoded addresses cannot be updated without redeploying the entire validator, which changes the script hash and breaks all existing UTXOs.
- **Centralization risk**: A hardcoded admin key hash cannot be rotated if the key is compromised.
- **Deployment errors**: Copy-pasting addresses across environments is error-prone.

These values should be validator parameters, allowing different deployments with different addresses.

## Example: Vulnerable Code

```aiken
validator treasury {
  spend(_datum: Void, _redeemer: Void, _ref: OutputReference, self: Transaction) {
    // Hardcoded admin key hash (28 bytes)
    let admin_hash = #"a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4"
    list.has(self.extra_signatories, admin_hash)
  }
}
```

## Example: Safe Code

```aiken
validator treasury(admin_hash: VerificationKeyHash) {
  spend(_datum: Void, _redeemer: Void, _ref: OutputReference, self: Transaction) {
    // Admin hash passed as validator parameter
    list.has(self.extra_signatories, admin_hash)
  }
}
```

## Detection Logic

1. Collects all ByteArray literal lengths from handler bodies via the `bytearray_literal_lengths` body signal.
2. Flags literals of 28 bytes (key hash), 29 bytes (key hash + network tag), or 57 bytes (full address payload).
3. Describes the likely meaning of each size in the finding.

## False Positives

- **Non-address ByteArrays**: A 28-byte ByteArray could be a cryptographic hash, IPFS CID prefix, or other data that coincidentally matches a key hash length.
- **Module constants**: ByteArrays defined as module-level constants (not inline in handler bodies) serve a similar purpose to parameters and may be intentional.
- **Well-known protocol addresses**: Some protocols intentionally hardcode addresses of canonical contracts (e.g., a DEX router address that never changes).

Suppress with:
```aiken
// aikido:ignore[hardcoded-addresses] -- well-known DEX router hash, never changes
```

## Related Detectors

- [unused-validator-parameter](../low/unused-validator-parameter.md) -- Validator parameters that are never used
- [excessive-validator-params](../low/excessive-validator-params.md) -- Too many validator parameters
