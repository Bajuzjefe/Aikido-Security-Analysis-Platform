# cross-validator-gap

**Severity:** High | **Confidence:** likely | **CWE:** [CWE-862](https://cwe.mitre.org/data/definitions/862.html)

## What it detects

Spend handlers that delegate validation to a withdrawal handler via the withdraw-zero pattern, where the delegated handler is missing or performs insufficient security checks.

## Why it matters

The withdraw-zero delegation pattern is common in Cardano protocols: a spend handler skips its own checks and instead requires that a specific staking script is invoked (with a zero-amount withdrawal). If the delegated withdrawal handler does not exist or lacks critical checks, the delegation creates a security gap where the spend handler's UTXO can be spent without proper authorization.

**Real-world impact:** A multi-validator protocol delegates all spend validation to a central "router" withdrawal handler. The router handler checks the redeemer type but forgets to verify signatures. An attacker can spend any UTXO at the script address by including a zero-withdrawal of the router script in their transaction.

## Example: Vulnerable Code

```aiken
// Spend handler delegates to withdrawal
validator pool {
  spend(_datum: Data, _redeemer: Data, _own_ref: OutputReference, self: Transaction) {
    // Delegates all validation to the staking script
    dict.has_key(self.withdrawals, Inline(ScriptCredential(staking_hash)))
  }
}

// But the withdrawal handler is missing or too permissive
validator pool {
  withdraw(_redeemer: Data, self: Transaction) {
    // VULNERABLE: always succeeds
    True
  }
}
```

## Example: Safe Code

```aiken
validator pool {
  spend(_datum: Data, _redeemer: Data, _own_ref: OutputReference, self: Transaction) {
    dict.has_key(self.withdrawals, Inline(ScriptCredential(staking_hash)))
  }
}

validator pool {
  withdraw(redeemer: RouterRedeemer, self: Transaction) {
    // SAFE: withdrawal handler performs full validation
    let is_signed = list.has(self.extra_signatories, redeemer.admin_pkh)
    let outputs_valid = validate_outputs(self.outputs, redeemer)
    let value_preserved = check_value_conservation(self)

    is_signed && outputs_valid && value_preserved
  }
}
```

## Detection Logic

Aikido flags this pattern when:

1. **A spend handler uses the withdraw-zero pattern** - checks `dict.has_key(self.withdrawals, ...)`.
2. **The delegating handler skips its own security checks** - no signature, value, or datum verification.
3. **The target withdrawal handler is missing or always succeeds** - no corresponding withdrawal handler found, or it has no meaningful checks.

## False Positives

- **External validators:** If the withdrawal handler is in a separate project or imported as a reference script, Aikido cannot analyze it. Suppress with `// aikido:ignore[cross-validator-gap]`.
- **Intentional minimal spend:** Some designs intentionally keep spend handlers thin when the withdrawal handler is comprehensive.

## Related Detectors

- [withdraw-zero-trick](withdraw-zero-trick.md) - Detects the withdraw-zero pattern itself.
- [withdraw-amount-check](../medium/withdraw-amount-check.md) - Detects withdrawal auth that only checks existence, not amount.
- [uncoordinated-multi-validator](uncoordinated-multi-validator.md) - Broader multi-validator coordination issues.
