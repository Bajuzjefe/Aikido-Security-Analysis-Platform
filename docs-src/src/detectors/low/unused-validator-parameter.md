# unused-validator-parameter

**Severity:** Low | **CWE:** CWE-561 (Dead Code)

## What it detects

Validator parameters (deployment-time configuration values) that are never referenced in any handler body or module-level function. These are values baked into the compiled script at deployment but never actually used by the on-chain logic.

## Why it matters

Validator parameters in Aiken are fixed at deployment time and become part of the compiled script hash, which determines the script address. An unused parameter has several implications:

- **Missing validation**: The parameter was likely intended to be used in a check (e.g., an oracle public key hash, an admin address, or a protocol token policy ID). Forgetting to use it means the intended authorization or validation logic is absent.
- **Wasted script size**: Each parameter increases the compiled UPLC script size, which increases transaction fees for every interaction with the contract.
- **Design confusion**: Future auditors and maintainers will wonder why a parameter exists if it serves no purpose, making the codebase harder to reason about.

## Example: Flagged Code

```aiken
validator my_escrow(oracle_pkh: ByteArray, admin_pkh: ByteArray) {
  spend(datum: Option<EscrowDatum>, redeemer: EscrowRedeemer, own_ref: OutputReference, self: Transaction) {
    expect Some(d) = datum
    // admin_pkh is checked, but oracle_pkh is never used!
    let signed_by_admin =
      list.has(self.extra_signatories, admin_pkh)

    when redeemer is {
      Release -> signed_by_admin && verify_release(d, self)
      Cancel -> signed_by_admin
    }
  }
}
```

## Example: Improved Code

```aiken
validator my_escrow(oracle_pkh: ByteArray, admin_pkh: ByteArray) {
  spend(datum: Option<EscrowDatum>, redeemer: EscrowRedeemer, own_ref: OutputReference, self: Transaction) {
    expect Some(d) = datum
    let signed_by_admin =
      list.has(self.extra_signatories, admin_pkh)

    // Use oracle_pkh to authenticate the oracle reference input
    let oracle_input =
      list.find(
        self.reference_inputs,
        fn(input) {
          input.output.address.payment_credential == ScriptCredential(oracle_pkh)
        },
      )

    when redeemer is {
      Release -> signed_by_admin && verify_release(d, self, oracle_input)
      Cancel -> signed_by_admin
    }
  }
}
```

If the parameter is genuinely unnecessary, remove it or prefix with underscore:

```aiken
// Option A: Remove the parameter entirely
validator my_escrow(admin_pkh: ByteArray) { ... }

// Option B: Mark as intentionally unused
validator my_escrow(_oracle_pkh: ByteArray, admin_pkh: ByteArray) { ... }
```

## Detection Logic

Aikido identifies this pattern through the following steps:

1. **Scope**: Only examines validator modules with at least one validator parameter.
2. **Skip discarded params**: Parameters prefixed with `_` are treated as intentionally unused and skipped.
3. **Reference search**: For each parameter, Aikido scans variable references across all handler bodies in the same validator.
4. **Module function check**: Also scans module-level functions for references to the parameter name, since parameters can be captured by helper functions in the same module.
5. **Confidence**: Rated as `likely` because the parameter name search is straightforward and rarely produces false matches.

## False Positives

This detector may produce false positives when:

- The parameter is used in a helper function defined in a separate module (cross-module closure capture). Aikido checks same-module functions but cannot trace across all module boundaries.
- The parameter name happens to be very short (e.g., `a`) and collides with a local variable name, causing the detector to think it is used when it is not (false negative), or vice versa.

Suppress with:

```aiken
// aikido:ignore[unused-validator-parameter] -- oracle_pkh used in imported helper
```

## Related Detectors

- [excessive-validator-params](excessive-validator-params.md) -- Too many validator parameters
- [dead-code-path](dead-code-path.md) -- Unreachable code paths in handlers
- [missing-signature-check](../high/missing-signature-check.md) -- Authority datum fields without signature verification
