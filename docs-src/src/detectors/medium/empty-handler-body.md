# empty-handler-body

**Severity:** Medium | **Confidence:** likely | **CWE:** [CWE-561](https://cwe.mitre.org/data/definitions/561.html)

## What it detects

Identifies validator handlers that have no meaningful logic -- no function calls, no variable references, no `when` branches, no transaction field accesses, and no `own_ref` usage.

## Why it matters

An empty handler body means the validator either trivially succeeds or trivially fails without performing any validation. This is a critical vulnerability:

- **Always-succeeds**: If the handler returns `True` with no checks, anyone can spend the UTXO, drain funds, or perform unauthorized actions.
- **Always-fails**: If the handler returns `False` with no checks, funds at the script address are permanently locked.
- **Placeholder code**: Empty handlers often indicate incomplete implementations that were accidentally deployed.

## Example: Vulnerable Code

```aiken
validator treasury {
  spend(_datum: Void, _redeemer: Void, _ref: OutputReference, _self: Transaction) {
    // No validation at all -- anyone can spend!
    True
  }
}
```

## Example: Safe Code

```aiken
validator treasury(admin: VerificationKeyHash) {
  spend(_datum: Void, _redeemer: Void, _ref: OutputReference, self: Transaction) {
    // At minimum, require admin signature
    list.has(self.extra_signatories, admin)
  }
}
```

## Detection Logic

1. For each validator handler (excluding `else` fallback handlers), checks all body signal categories:
   - `function_calls` is empty
   - `var_references` is empty
   - `when_branches` is empty
   - `tx_field_accesses` is empty
   - `uses_own_ref` is false
2. If all categories are empty, the handler has no meaningful logic.
3. Skips `else` handlers since they are expected to be simple fallback branches.

## False Positives

- **Intentional always-fail handlers**: Some validators intentionally have handlers that always fail (e.g., a mint-only validator with a spend handler that always rejects). In this case, the handler should explicitly call `fail` rather than being empty.
- **Delegating handlers**: If a handler delegates all logic to another validator via the withdraw-zero trick, it may appear empty. Suppress if this pattern is intentional.

Suppress with:
```aiken
// aikido:ignore[empty-handler-body] -- spend handler intentionally always fails
```

## Related Detectors

- [missing-redeemer-validation](../high/missing-redeemer-validation.md) -- Catch-all redeemer that trivially returns True
- [unrestricted-minting](../critical/unrestricted-minting.md) -- Minting policy with no authorization
