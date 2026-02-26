# fail-only-redeemer-branch

**Severity:** Low | **CWE:** CWE-561 (Dead Code)

## What it detects

Redeemer `when`/`match` branches that unconditionally call `fail` or `error`, making them impossible to execute successfully. These branches exist in the type definition but serve no functional purpose in the validator.

## Why it matters

A redeemer variant that always fails is dead code. While it does not directly create a vulnerability (the transaction would simply be rejected), it raises several concerns:

- **Incomplete implementation**: The branch was likely a placeholder during development that was never filled in with real logic. The intended functionality may be missing entirely.
- **Misleading API surface**: Off-chain code and documentation may reference this redeemer action, leading users or integrators to believe it is functional when it will always fail.
- **Wasted script size**: The branch adds to the compiled UPLC script size without contributing any functionality, increasing transaction costs for all other actions.
- **Audit confusion**: Reviewers must determine whether the fail is intentional or a bug, wasting audit time.

Note: Catch-all branches (`_ -> fail`) are excluded from this detector because "deny by default" is a well-established security pattern.

## Example: Flagged Code

```aiken
type MarketRedeemer {
  Settle
  Dispute
  Cancel
}

validator market {
  spend(datum: Option<MarketDatum>, redeemer: MarketRedeemer, own_ref: OutputReference, self: Transaction) {
    expect Some(d) = datum
    when redeemer is {
      Settle -> verify_settlement(d, self)
      Dispute -> fail @"Not implemented yet"  // Dead branch!
      Cancel -> verify_cancellation(d, self)
    }
  }
}
```

## Example: Improved Code

```aiken
// Option A: Implement the branch
validator market {
  spend(datum: Option<MarketDatum>, redeemer: MarketRedeemer, own_ref: OutputReference, self: Transaction) {
    expect Some(d) = datum
    when redeemer is {
      Settle -> verify_settlement(d, self)
      Dispute -> verify_dispute(d, self)
      Cancel -> verify_cancellation(d, self)
    }
  }
}

// Option B: Remove the unused variant from the type
type MarketRedeemer {
  Settle
  Cancel
}
```

## Detection Logic

Aikido identifies this pattern through the following steps:

1. **Scope**: Only examines validator handler bodies in validator modules.
2. **Branch extraction**: During AST walking, Aikido records each `when`/`match` branch with its pattern text, whether it is a catch-all, and whether its body unconditionally calls `fail` or `error`.
3. **Catch-all exclusion**: Branches marked as catch-all (`_`, `..`) are skipped because failing on unknown redeemers is a valid security practice.
4. **Non-redeemer exclusion**: Branches matching well-known Cardano type constructors (e.g., `Script`, `VerificationKey`, `Some`, `None`, `True`, `False`, `Inline`, `DatumHash`, `NoDatum`, `Finite`, `PositiveInfinity`, `NegativeInfinity`) are skipped, since these appear in normal control flow matching on credentials, datums, and intervals -- not redeemer actions.
5. **Confidence**: Rated as `likely` because the body analysis clearly identifies `fail`/`error` calls.

## False Positives

This detector may produce false positives when:

- The `fail` branch is intentionally disabled as a temporary measure during a phased rollout (e.g., "enable Dispute in v2").
- The `when` expression is matching on something other than the redeemer (e.g., a datum field or an option type) and the constructor name does not appear in the built-in exclusion list.
- The branch calls `fail` conditionally through a helper function that always returns `False` in the current configuration -- the detector sees `fail` at the body level but the actual control flow is more nuanced.

Suppress with:

```aiken
// aikido:ignore[fail-only-redeemer-branch] -- Dispute disabled until v2 upgrade
```

## Related Detectors

- [dead-code-path](dead-code-path.md) -- All named branches fail (broader dead code pattern)
- [redundant-check](redundant-check.md) -- Branches that always return True (opposite problem)
- [non-exhaustive-redeemer](../medium/non-exhaustive-redeemer.md) -- Redeemer match missing constructors
- [missing-redeemer-validation](../high/missing-redeemer-validation.md) -- Catch-all redeemer trivially returns True
